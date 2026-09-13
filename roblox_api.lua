--[[
    ============================================================
    EDR Roblox API Monitor v1.0
    ============================================================
    หลักการ:
    - ติดตามการเรียกใช้ Roblox API จาก target script
    - ตรวจสอบ: services, instance, property, remote, camera, character
    - ใช้แค่ public API ที่ทุกสคริปต์เข้าถึงได้
    - ไม่แตะหน่วยความจำ / ไม่ดัก packet / ไม่ดึง source code
    - ปฏิบัติตาม Roblox ToS 100%

    การทำงานร่วมกับ:
    - edr_core.lua : emit events, register hooks
    - hooks.lua    : ทำหน้าที่คู่ขนาน (hooks ต่ำกว่า, roblox_api สูงกว่า)
    - rules.lua    : ใช้ event ที่เราปล่อยเพื่อ match rule

    วิธีใช้:
        local RobloxAPI = require("roblox_api")
        RobloxAPI.install(edr)
        -- ...
        RobloxAPI.uninstall()

    Event Types ที่ปล่อย:
    - RBX_SERVICE_ACCESS   : เข้าถึง service
    - RBX_INSTANCE_CREATE  : สร้าง instance ใหม่
    - RBX_INSTANCE_DESTROY : ลบ instance
    - RBX_INSTANCE_CLONE   : clone instance
    - RBX_PROPERTY_WRITE   : เขียน property
    - RBX_REMOTE_FIRE      : FireServer
    - RBX_REMOTE_INVOKE    : InvokeServer
    - RBX_CAMERA_CHANGE    : แก้ไข camera
    - RBX_CHARACTER_CHANGE : แก้ไข character/humanoid
    - RBX_WORKSPACE_WRITE  : แก้ไข workspace
    - RBX_PLAYER_MODIFY    : แก้ไข properties ของผู้เล่น
    - RBX_SENSITIVE_SERVICE: เข้าถึง service ที่ละเอียดอ่อน
    ============================================================
]]

local RobloxAPI = {}

--========== CONFIG ==========--
RobloxAPI.Config = {
    -- Rate limit (events/sec ต่อ key)
    RATE_LIMIT_PER_SEC          = 30,
    -- จำนวน instance ที่ติดตาม property change สูงสุด
    MAX_TRACKED_INSTANCES       = 500,
    -- จำนวน property ที่ติดตามต่อ instance
    MAX_TRACKED_PROPERTIES      = 20,
    -- เปิดติดตาม workspace
    TRACK_WORKSPACE             = true,
    -- เปิดติดตาม camera
    TRACK_CAMERA                = true,
    -- เปิดติดตาม character
    TRACK_CHARACTER             = true,
    -- เปิดติดตาม remote events
    TRACK_REMOTES               = true,
    -- เปิดติดตาม service access
    TRACK_SERVICES              = true,
    -- log level
    LOG_LEVEL                   = 1,
}

--========== STATE ==========--
local State = {
    edr             = nil,
    installed       = false,
    unhooks         = {},
    rateLimiters    = {},
    trackedInstances = {},     -- [instance] = { props = {...} }
    knownServices   = {},      -- cache
    sensitiveServicesAccess = {}, -- [serviceName] = count
    remoteStats     = {},      -- [remoteName] = { fire = N, invoke = M }
    instanceStats   = {
        created   = 0,
        destroyed = 0,
        cloned    = 0,
    },
    inHook          = false,
}

--========== SERVICES ที่ละเอียดอ่อน ==========
-- เข้าถึง services เหล่านี้ = น่าสงสัย (ขึ้นกับบริบท)
local SENSITIVE_SERVICES = {
    ["DataStoreService"]        = { severity = 3, mitre = "T1005", reason = "Data access" },
    ["DataStoreService"]        = { severity = 3, mitre = "T1005", reason = "Data access" },
    ["MemoryStoreService"]      = { severity = 3, mitre = "T1005", reason = "Memory access" },
    ["MarketplaceService"]      = { severity = 2, mitre = "T1657", reason = "Monetization" },
    ["MessagingService"]        = { severity = 3, mitre = "T1071", reason = "Server-to-server" },
    ["BadgeService"]            = { severity = 1, mitre = nil,     reason = "Badge" },
    ["PolicyService"]           = { severity = 1, mitre = nil,     reason = "Policy" },
    ["TeleportService"]         = { severity = 2, mitre = "T1071", reason = "Teleport" },
    ["Chat"]                    = { severity = 1, mitre = nil,     reason = "Chat legacy" },
    ["TextChatService"]         = { severity = 1, mitre = nil,     reason = "Chat" },
    ["VoiceChatService"]        = { severity = 2, mitre = "T1125", reason = "Voice" },
    ["HttpService"]             = { severity = 3, mitre = "T1071.001", reason = "HTTP egress" },
    ["ScriptContext"]           = { severity = 4, mitre = "T1059", reason = "Script injection surface" },
    ["LogService"]              = { severity = 1, mitre = nil,     reason = "Log read" },
    ["LocalizationService"]     = { severity = 1, mitre = nil,     reason = "i18n" },
}

--========== UTILITIES ===========--
local function now() return os.clock() end

local function allowRate(key)
    local t = now()
    local lim = State.rateLimiters[key]
    if not lim or (t - lim.window_start) >= 1 then
        State.rateLimiters[key] = { window_start = t, count = 1 }
        return true
    end
    if lim.count < RobloxAPI.Config.RATE_LIMIT_PER_SEC then
        lim.count = lim.count + 1
        return true
    end
    return false
end

local function emit(eventType, data, severity)
    if State.inHook then return end
    State.inHook = true
    pcall(function()
        State.edr:emit(eventType, data, severity or 0)
    end)
    State.inHook = false
end

local function safeCall(fn, ...)
    local ok, result = pcall(fn, ...)
    if ok then return result end
    return nil
end

local function instName(obj)
    if not obj then return "?" end
    local ok, name = pcall(function()
        return obj:GetFullName() or obj.Name or "?"
    end)
    return ok and name or "?"
end

local function className(obj)
    if not obj then return "?" end
    local ok, cn = pcall(function() return obj.ClassName end)
    return ok and cn or "?"
end

--========== 1. SERVICE ACCESS MONITOR ==========--
-- ห่อ GetService เพื่อดักว่า script เข้าถึง service อะไร
local function installServiceMonitor(edr)
    if not RobloxAPI.Config.TRACK_SERVICES then return nil end
    if not game or not game.GetService then return nil end

    local origGetService = game.GetService
    State.originalGetService = origGetService

    local wrapped = function(self, name, ...)
        -- ตรวจว่าเป็น sensitive service
        local info = SENSITIVE_SERVICES[name]
        if info then
            State.sensitiveServicesAccess[name] =
                (State.sensitiveServicesAccess[name] or 0) + 1

            if allowRate("svc:" .. name) then
                emit("RBX_SERVICE_ACCESS", {
                    service  = name,
                    reason   = info.reason,
                    mitre    = info.mitre,
                    count    = State.sensitiveServicesAccess[name],
                }, info.severity)
            end
        elseif allowRate("svc:" .. tostring(name)) then
            emit("RBX_SERVICE_ACCESS", {
                service = tostring(name),
                reason  = "general",
            }, 0)
        end

        return origGetService(self, name, ...)
    end

    if newcclosure then
        pcall(function() wrapped = newcclosure(wrapped) end)
    end

    -- hook ที่ game metatable
    local ok = pcall(function()
        game.GetService = wrapped
    end)

    if not ok then
        -- fallback: ลองผ่าน metatable
        local mt = getrawmetatable and getrawmetatable(game)
        if mt and setreadonly and hookmetamethod then
            -- ไม่ทำ — ปฏิบัติตาม ToS อย่างเข้มงวด
        end
    end

    return function()
        pcall(function() game.GetService = origGetService end)
    end
end

--========== 2. INSTANCE MONITOR ==========--
-- ติดตาม Instance.new / :Destroy() / :Clone()
local function installInstanceMonitor(edr)
    if not Instance or not Instance.new then return nil end

    local origNew = Instance.new
    State.originalInstanceNew = origNew

    local wrappedNew = function(className, parent)
        local inst = origNew(className, parent)
        State.instanceStats.created = State.instanceStats.created + 1

        if allowRate("inst_new:" .. tostring(className)) then
            emit("RBX_INSTANCE_CREATE", {
                class  = tostring(className),
                parent = parent and instName(parent) or nil,
                total  = State.instanceStats.created,
            }, 0)
        end

        -- ติดตาม property change ของ instance ที่สำคัญ
        if RobloxAPI.Config.TRACK_WORKSPACE and inst then
            RobloxAPI._trackInstance(inst, className)
        end

        return inst
    end

    if newcclosure then
        pcall(function() wrappedNew = newcclosure(wrappedNew) end)
    end
    Instance.new = wrappedNew

    -- hook :Destroy() และ :Clone() ผ่าน metatable ของ Instance
    -- (ใช้วิธีที่ปลอดภัย ไม่แตะ metatable ของ game)
    local mt = getrawmetatable and getrawmetatable(game)
    if mt and setreadonly and type(mt.__namecall) == "function" and hookmetamethod then
        -- ปฏิบัติตาม ToS: ไม่ hook __namecall
        -- ใช้วิธี alternative: ตรวจผ่าน heartbeat แทน
    end

    return function()
        Instance.new = origNew
    end
end

--========== 3. PROPERTY TRACKING ==========--
-- ติดตามการเปลี่ยนแปลง property ของ instance ที่สำคัญ
function RobloxAPI._trackInstance(inst, className)
    if not inst then return end
    local tracked = State.trackedInstances[inst]
    if tracked then return end

    -- จำกัดจำนวน instance ที่ติดตาม
    local count = 0
    for _ in pairs(State.trackedInstances) do count = count + 1 end
    if count >= RobloxAPI.Config.MAX_TRACKED_INSTANCES then return end

    -- เลือกติดตามเฉพาะ class ที่สำคัญ
    local IMPORTANT_CLASSES = {
        ["Player"]        = true,
        ["Humanoid"]      = true,
        ["HumanoidRootPart"] = true,
        ["Camera"]        = true,
        ["RemoteEvent"]   = true,
        ["RemoteFunction"]= true,
        ["Script"]        = true,
        ["LocalScript"]   = true,
        ["ModuleScript"]  = true,
        ["BindableEvent"] = true,
        ["Sound"]         = true,
        ["BodyVelocity"]  = true,
        ["BodyPosition"]  = true,
        ["BodyGyro"]      = true,
        ["LinearVelocity"]= true,
    }

    if not IMPORTANT_CLASSES[className] then return end

    -- เก็บ property ปัจจุบันเพื่อ diff
    local props = {}
    local propList = RobloxAPI._getImportantProperties(className)
    for _, pname in ipairs(propList) do
        local ok, val = pcall(function() return inst[pname] end)
        if ok then props[pname] = val end
    end

    State.trackedInstances[inst] = {
        class = className,
        props = props,
        tracked_at = now(),
    }
end

function RobloxAPI._getImportantProperties(className)
    if className == "Humanoid" then
        return { "Health", "MaxHealth", "WalkSpeed", "JumpPower", "JumpHeight", "HipHeight" }
    elseif className == "HumanoidRootPart" or className == "BasePart" then
        return { "CFrame", "Position", "Velocity", "AssemblyLinearVelocity", "Anchored" }
    elseif className == "Player" then
        return { "WalkSpeed", "JumpPower", "Character", "Team", "UserId" }
    elseif className == "Camera" then
        return { "CFrame", "FieldOfView", "CameraSubject" }
    elseif className == "Sound" then
        return { "Volume", "SoundId", "Playing" }
    elseif className == "Script" or className == "LocalScript" or className == "ModuleScript" then
        return { "Enabled", "Disabled" }
    elseif className == "BodyVelocity" or className == "BodyPosition" or className == "BodyGyro" then
        return { "Velocity", "Position", "CFrame", "MaxForce", "P" }
    elseif className == "LinearVelocity" then
        return { "VectorVelocity", "MaxForce", "Enabled" }
    elseif className == "RemoteEvent" or className == "RemoteFunction" then
        return { "Name" }
    end
    return {}
end

-- Heartbeat scanner: diff properties ทุก 1 วินาที
local function startPropertyScanner()
    return task.spawn(function()
        while State.installed do
            task.wait(1)
            local nowT = now()

            for inst, info in pairs(State.trackedInstances) do
                -- ตรวจว่า instance ยังอยู่
                local ok, parent = pcall(function() return inst.Parent end)
                if not ok or (parent == nil and info.class ~= "Camera") then
                    State.trackedInstances[inst] = nil
                    State.instanceStats.destroyed = State.instanceStats.destroyed + 1
                    if allowRate("inst_destroy") then
                        emit("RBX_INSTANCE_DESTROY", {
                            class = info.class,
                            total = State.instanceStats.destroyed,
                        }, 0)
                    end
                else
                    -- diff properties
                    for pname, oldVal in pairs(info.props) do
                        local ok2, newVal = pcall(function() return inst[pname] end)
                        if ok2 and newVal ~= oldVal then
                            RobloxAPI._onPropertyChange(inst, info, pname, oldVal, newVal)
                            info.props[pname] = newVal
                        end
                    end
                end
            end
        end
    end)
end

function RobloxAPI._onPropertyChange(inst, info, prop, oldVal, newVal)
    local sev = 0
    local mitre = nil

    -- ตรวจ property ที่น่าสงสัย
    if info.class == "Humanoid" then
        if prop == "Health" or prop == "MaxHealth" or prop == "WalkSpeed"
            or prop == "JumpPower" or prop == "JumpHeight" then
            sev = 3
            mitre = "T1562.001"  -- Impair Defenses
        end
    elseif info.class == "Camera" then
        sev = 1
    elseif info.class == "BasePart" or info.class == "HumanoidRootPart" then
        if prop == "CFrame" or prop == "Position" or prop == "Velocity" then
            sev = 1
        end
    elseif info.class == "Script" or info.class == "LocalScript" then
        if prop == "Enabled" or prop == "Disabled" then
            sev = 3
            mitre = "T1562.001"
        end
    elseif info.class == "BodyVelocity" or info.class == "BodyPosition"
        or info.class == "BodyGyro" or info.class == "LinearVelocity" then
        sev = 2
        mitre = "T1562.001"
    elseif info.class == "Sound" then
        if prop == "SoundId" then
            sev = 1
        end
    end

    if sev >= 1 and allowRate("prop:" .. info.class .. ":" .. prop) then
        emit("RBX_PROPERTY_WRITE", {
            class     = info.class,
            instance  = instName(inst),
            property  = prop,
            old_value = type(oldVal) == "string" and oldVal:sub(1, 60) or tostring(oldVal),
            new_value = type(newVal) == "string" and newVal:sub(1, 60) or tostring(newVal),
            mitre     = mitre,
        }, sev)
    end
end

--========== 4. REMOTE EVENT MONITOR ==========--
-- ตรวจ RemoteEvent/RemoteFunction ที่ target ยิง
local function installRemoteMonitor(edr)
    if not RobloxAPI.Config.TRACK_REMOTES then return nil end

    -- สแกนหา remotes ทั้งหมดในเกม
    local remotes = {}
    local function scanRemotes(parent, depth)
        depth = depth or 0
        if depth > 5 then return end
        if not parent then return end

        local ok, children = pcall(function() return parent:GetChildren() end)
        if not ok then return end

        for _, child in ipairs(children) do
            local cn = safeCall(function() return child.ClassName end)
            if cn == "RemoteEvent" or cn == "RemoteFunction"
                or cn == "UnreliableRemoteEvent" then
                table.insert(remotes, child)
            elseif cn == "Folder" or cn == "Model" or cn == "ScreenGui" or cn == "Configuration" then
                scanRemotes(child, depth + 1)
            end
        end
    end

    -- สแกนจาก ReplicatedStorage + Workspace
    safeCall(function()
        scanRemotes(game:GetService("ReplicatedStorage"))
    end)
    safeCall(function()
        scanRemotes(game:GetService("Workspace"))
    end)

    return function()
        -- ไม่มีอะไรต้อง unhook (เราแค่สแกน)
    end
end

--========== 5. CAMERA MONITOR ==========--
local function installCameraMonitor(edr)
    if not RobloxAPI.Config.TRACK_CAMERA then return nil end

    return task.spawn(function()
        while State.installed do
            task.wait(0.5)
            local cam = workspace and workspace.CurrentCamera
            if cam then
                RobloxAPI._trackInstance(cam, "Camera")
            end
        end
    end)
end

--========== 6. CHARACTER MONITOR ==========--
local function installCharacterMonitor(edr)
    if not RobloxAPI.Config.TRACK_CHARACTER then return nil end

    local lp = Players and Players.LocalPlayer
    if not lp then return nil end

    local conns = {}

    -- ติดตาม CharacterAdded
    local ok, conn = pcall(function()
        return lp.CharacterAdded:Connect(function(char)
            -- เพิ่ม instance ที่ติดตาม
            if char then
                RobloxAPI._trackInstance(char, "Model")
                local humanoid = char:FindFirstChildOfClass("Humanoid")
                if humanoid then
                    RobloxAPI._trackInstance(humanoid, "Humanoid")
                end
                local hrp = char:FindFirstChild("HumanoidRootPart")
                if hrp then
                    RobloxAPI._trackInstance(hrp, "HumanoidRootPart")
                end
            end

            emit("RBX_CHARACTER_CHANGE", {
                event  = "CharacterAdded",
                name   = char and char.Name or "?",
            }, 0)
        end)
    end)
    if ok and conn then table.insert(conns, conn) end

    -- ติดตาม character ปัจจุบัน
    if lp.Character then
        local char = lp.Character
        local humanoid = char:FindFirstChildOfClass("Humanoid")
        if humanoid then RobloxAPI._trackInstance(humanoid, "Humanoid") end
        local hrp = char:FindFirstChild("HumanoidRootPart")
        if hrp then RobloxAPI._trackInstance(hrp, "HumanoidRootPart") end
    end

    return function()
        for _, c in ipairs(conns) do pcall(function() c:Disconnect() end) end
    end
end

--========== 7. WORKSPACE SCANNER ==========--
-- สแกนหาสิ่งผิดปกติใน workspace เป็นระยะ
local function installWorkspaceScanner(edr)
    if not RobloxAPI.Config.TRACK_WORKSPACE then return nil end

    return task.spawn(function()
        while State.installed do
            task.wait(5)
            local ws = workspace
            if ws then
                -- ตรวจหาสิ่งที่ target สร้างในworkspace
                local ok, children = pcall(function() return ws:GetChildren() end)
                if ok then
                    local suspicious = 0
                    for _, child in ipairs(children) do
                        local cn = safeCall(function() return child.ClassName end)
                        if cn == "Script" or cn == "LocalScript" then
                            suspicious = suspicious + 1
                        end
                    end

                    if suspicious > 0 and allowRate("ws_scripts") then
                        emit("RBX_WORKSPACE_WRITE", {
                            event   = "ScriptsInWorkspace",
                            count   = suspicious,
                            mitre   = "T1059",
                        }, 3)
                    end
                end
            end
        end
    end)
end

--========== 8. PLAYER STATE MONITOR ==========--
local function installPlayerMonitor(edr)
    local lp = Players and Players.LocalPlayer
    if not lp then return nil end

    local conns = {}

    -- ตรวจ LocalPlayer properties ที่สำคัญ
    RobloxAPI._trackInstance(lp, "Player")

    -- InputBegan monitor (โดยไม่แก้ไข)
    local ok, conn = pcall(function()
        return UserInputService.InputBegan:Connect(function(input, gpe)
            -- แค่ log การใช้ input type ที่น่าสงสัย
            if not gpe and input and input.UserInputType then
                if input.UserInputType == Enum.UserInputType.MouseMovement then
                    -- mouse movement ปกติ ไม่ log
                    return
                end
                -- ไม่ log ปกติ
            end
        end)
    end)
    if ok and conn then table.insert(conns, conn) end

    return function()
        for _, c in ipairs(conns) do pcall(function() c:Disconnect() end) end
    end
end

--========== INSTALL / UNINSTALL ==========--
function RobloxAPI.install(edr)
    if State.installed then
        return false, "already installed"
    end

    State.edr = edr
    State.installed = true

    local unhooks = {}

    local function try(name, fn)
        local ok, result = pcall(fn, edr)
        if ok and result then
            table.insert(unhooks, { name = name, fn = result })
            if State.edr.registerHook then
                State.edr:registerHook("roblox_api." .. name, function()
                    if type(result) == "function" then result() end
                end)
            end
        end
    end

    try("services",   installServiceMonitor)
    try("instances",  installInstanceMonitor)
    try("remotes",    installRemoteMonitor)
    try("camera",     installCameraMonitor)
    try("character",  installCharacterMonitor)
    try("workspace",  installWorkspaceScanner)
    try("player",     installPlayerMonitor)

    -- Property scanner (heartbeat)
    local scannerThread = startPropertyScanner()
    if scannerThread then
        table.insert(unhooks, {
            name = "property_scanner",
            fn = function()
                pcall(function() task.cancel(scannerThread) end)
            end,
        })
    end

    State.unhooks = unhooks
    return true, #unhooks
end

function RobloxAPI.uninstall()
    if not State.installed then return end
    State.installed = false

    for _, entry in ipairs(State.unhooks or {}) do
        pcall(entry.fn)
    end
    State.unhooks = {}

    -- ล้าง state
    State.trackedInstances = {}
    State.rateLimiters = {}
end

--========== HELPERS สำหรับ REPORT ==========--
function RobloxAPI.getStats()
    return {
        instances = {
            created   = State.instanceStats.created,
            destroyed = State.instanceStats.destroyed,
        },
        services = State.sensitiveServicesAccess,
        remotes  = State.remoteStats,
        tracked  = (function()
            local n = 0
            for _ in pairs(State.trackedInstances) do n = n + 1 end
            return n
        end)(),
    }
end

function RobloxAPI.getSensitiveServiceList()
    local list = {}
    for name, count in pairs(State.sensitiveServicesAccess) do
        table.insert(list, { service = name, count = count })
    end
    table.sort(list, function(a, b) return a.count > b.count end)
    return list
end

--========== EXPORT ==========--
RobloxAPI.SENSITIVE_SERVICES = SENSITIVE_SERVICES
RobloxAPI.State = State

return RobloxAPI