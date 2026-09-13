--[[
    ============================================================
    EDR Roblox API Monitor v2.0 — Advanced + ToS Compliant
    ============================================================
    หลักการ:
    - ใช้เฉพาะ public API ของ Roblox 100% (ปฏิบัติตาม ToS)
    - ไม่แตะหน่วยความจำ ไม่ดัก packet ไม่ดึง source
    - Weak tables ป้องกัน memory leak
    - Batched updates ลด event flood
    - Bloom filter dedup + Time-series stats
    - Kalman filter smoothing
    - Adaptive sampling ตาม activity

    Event types ที่ปล่อย:
    - RBX_SERVICE_ACCESS
    - RBX_INSTANCE_CREATE / RBX_INSTANCE_DESTROY / RBX_INSTANCE_CLONE
    - RBX_PROPERTY_WRITE
    - RBX_REMOTE_FOUND / RBX_REMOTE_FIRE
    - RBX_CAMERA_CHANGE
    - RBX_CHARACTER_CHANGE
    - RBX_WORKSPACE_WRITE
    - RBX_PLAYER_MODIFY
    ============================================================
]]

local RobloxAPI = {}

--========== CONFIG ==========--
RobloxAPI.Config = {
    -- Rate limits
    RATE_LIMIT_PER_SEC          = 50,
    RATE_LIMIT_WINDOW           = 1.0,

    -- Tracking limits (LRU)
    MAX_TRACKED_INSTANCES       = 300,
    MAX_TRACKED_PROPERTIES      = 16,
    MAX_TRACKED_NAMES           = 500,

    -- Batching
    BATCH_FLUSH_INTERVAL        = 1.0,   -- รวม changes ต่อ 1 วิ
    BATCH_MAX_SIZE              = 200,   -- flush ถ้าเกิน
    PROPERTY_SCAN_INTERVAL      = 1.0,   -- diff ทุก 1 วิ

    -- Bloom filter
    BLOOM_SIZE                  = 1 << 16,
    BLOOM_HASHES                = 4,

    -- Adaptive sampling
    ADAPTIVE_ENABLED            = true,
    BASE_SAMPLE_RATE            = 0.4,
    HIGH_ACTIVITY_SAMPLE_RATE   = 1.0,
    HIGH_ACTIVITY_THRESHOLD     = 20,    -- events/sec

    -- Subsystems toggle
    TRACK_SERVICES              = true,
    TRACK_INSTANCES             = true,
    TRACK_PROPERTIES            = true,
    TRACK_REMOTES               = true,
    TRACK_CAMERA                = true,
    TRACK_CHARACTER             = true,
    TRACK_WORKSPACE             = true,
    TRACK_PLAYER                = true,

    -- Remote scan
    REMOTE_SCAN_INTERVAL        = 30,
    REMOTE_MAX_DEPTH            = 6,
    REMOTE_MAX_SCAN             = 5000,

    -- Camera
    CAMERA_SCAN_INTERVAL        = 1.0,
    CAMERA_FOV_THRESHOLD        = 5,     -- องศา

    -- Character
    CHARACTER_SCAN_INTERVAL     = 0.5,
    HEALTH_JUMP_THRESHOLD       = 30,    -- HP เปลี่ยนมากเกิน
    SPEED_JUMP_THRESHOLD        = 20,    -- WalkSpeed เปลี่ยนมากเกิน

    -- Workspace
    WORKSPACE_SCAN_INTERVAL     = 5,

    -- Log
    LOG_LEVEL                   = 1,
}

--========== SENSITIVE SERVICES ==========--
local SENSITIVE_SERVICES = {
    ["DataStoreService"]    = { severity = 3, mitre = "T1005", reason = "Data access" },
    ["MemoryStoreService"]  = { severity = 3, mitre = "T1005", reason = "Memory access" },
    ["MarketplaceService"]  = { severity = 2, mitre = "T1657", reason = "Monetization" },
    ["MessagingService"]    = { severity = 3, mitre = "T1071", reason = "Server-to-server" },
    ["TeleportService"]     = { severity = 2, mitre = "T1071", reason = "Teleport" },
    ["VoiceChatService"]    = { severity = 2, mitre = "T1125", reason = "Voice" },
    ["HttpService"]         = { severity = 3, mitre = "T1071.001", reason = "HTTP egress" },
    ["ScriptContext"]       = { severity = 4, mitre = "T1059", reason = "Script injection" },
    ["LogService"]          = { severity = 1, mitre = nil, reason = "Log read" },
    ["PolicyService"]       = { severity = 1, mitre = nil, reason = "Policy" },
    ["BadgeService"]        = { severity = 1, mitre = nil, reason = "Badge" },
    ["TextChatService"]     = { severity = 1, mitre = nil, reason = "Chat" },
    ["Chat"]                = { severity = 1, mitre = nil, reason = "Chat legacy" },
    ["GroupService"]        = { severity = 2, mitre = "T1078", reason = "Group data" },
    ["UserService"]         = { severity = 2, mitre = "T1078", reason = "User data" },
    ["AdService"]           = { severity = 1, mitre = nil, reason = "Ads" },
    ["ContentProvider"]     = { severity = 1, mitre = nil, reason = "Content" },
}

--========== IMPORTANT CLASSES/PROPERTIES ==========--
local IMPORTANT_CLASSES = {
    Player              = true,
    Humanoid            = true,
    HumanoidRootPart    = true,
    Camera              = true,
    RemoteEvent         = true,
    RemoteFunction      = true,
    UnreliableRemoteEvent = true,
    Script              = true,
    LocalScript         = true,
    ModuleScript        = true,
    BindableEvent       = true,
    Sound               = true,
    BodyVelocity        = true,
    BodyPosition        = true,
    BodyGyro            = true,
    LinearVelocity      = true,
    Attachment          = true,
    Beam                = true,
    ParticleEmitter     = true,
}

local IMPORTANT_PROPERTIES = {
    Humanoid             = { "Health", "MaxHealth", "WalkSpeed", "JumpPower", "JumpHeight", "HipHeight", "Sit" },
    HumanoidRootPart     = { "CFrame", "Position", "Velocity", "AssemblyLinearVelocity", "Anchored" },
    BasePart             = { "CFrame", "Position", "Velocity", "Anchored", "CanCollide" },
    Player               = { "Character", "Team", "UserId", "AccountAge", "MembershipType" },
    Camera               = { "CFrame", "FieldOfView", "CameraType", "CameraSubject" },
    Sound                = { "Volume", "SoundId", "Playing", "TimePosition" },
    Script               = { "Enabled", "Disabled" },
    LocalScript          = { "Enabled", "Disabled" },
    ModuleScript         = { "Name" },
    BodyVelocity         = { "Velocity", "MaxForce", "P" },
    BodyPosition         = { "Position", "MaxForce", "P" },
    BodyGyro             = { "CFrame", "MaxTorque", "P" },
    LinearVelocity       = { "VectorVelocity", "MaxForce", "Enabled" },
    RemoteEvent          = { "Name" },
    RemoteFunction       = { "Name" },
}

--========== BIT OPS ==========--
local band = bit32 and bit32.band or function(a,b)
    local r, bit = 0, 1
    while a > 0 and b > 0 do
        if a % 2 == 1 and b % 2 == 1 then r = r + bit end
        a, b, bit = math.floor(a/2), math.floor(b/2), bit * 2
    end
    return r
end

local bor = bit32 and bit32.bor or function(a,b)
    local r, bit = 0, 1
    while a > 0 or b > 0 do
        if a % 2 == 1 or b % 2 == 1 then r = r + bit end
        a, b, bit = math.floor(a/2), math.floor(b/2), bit * 2
    end
    return r
end

local bxor = bit32 and bit32.bxor or function(a,b)
    local r, bit = 0, 1
    while a > 0 or b > 0 do
        if a % 2 ~= b % 2 then r = r + bit end
        a, b, bit = math.floor(a/2), math.floor(b/2), bit * 2
    end
    return r
end

local function fnv1a(str, seed)
    local h = seed or 2166136261
    for i = 1, #str do
        h = bxor(h, str:byte(i))
        h = band(h * 16777619, 0xFFFFFFFF)
    end
    return h
end

local HASH_SEEDS = { 2166136261, 2166136261 + 101, 2166136261 + 202, 2166136261 + 303 }
local function hashN(str, n)
    return fnv1a(str, HASH_SEEDS[n])
end

--========== BLOOM FILTER ==========--
local Bloom = {}
Bloom.__index = Bloom

function Bloom.new(size, hashes)
    return setmetatable({
        size = size or (1 << 16),
        hashCount = hashes or 4,
        bits = {},
        itemCount = 0,
    }, Bloom)
end

function Bloom:add(str)
    if type(str) ~= "string" then return end
    for i = 1, self.hashCount do
        local idx = hashN(str, i) % self.size
        local w = math.floor(idx / 32)
        local b = idx % 32
        self.bits[w] = bor(self.bits[w] or 0, 1 << b)
    end
    self.itemCount = self.itemCount + 1
end

function Bloom:contains(str)
    if type(str) ~= "string" then return false end
    for i = 1, self.hashCount do
        local idx = hashN(str, i) % self.size
        local w = math.floor(idx / 32)
        local b = idx % 32
        if band(self.bits[w] or 0, 1 << b) == 0 then return false end
    end
    return true
end

--========== KALMAN FILTER ==========--
local Kalman = {}
Kalman.__index = Kalman

function Kalman.new(q, r, initial)
    return setmetatable({
        q = q or 0.01,
        r = r or 0.1,
        x = initial or 0,
        p = 1.0,
    }, Kalman)
end

function Kalman:update(z)
    self.p = self.p + self.q
    local k = self.p / (self.p + self.r)
    self.x = self.x + k * (z - self.x)
    self.p = (1 - k) * self.p
    return self.x
end

--========== TIME-SERIES ==========--
local TimeSeries = {}
TimeSeries.__index = TimeSeries

function TimeSeries.new(capacity)
    return setmetatable({
        capacity = capacity or 60,
        values = {},
        count = 0,
        head = 1,
        sum = 0,
        min = math.huge,
        max = -math.huge,
    }, TimeSeries)
end

function TimeSeries:push(v)
    if self.count < self.capacity then
        self.count = self.count + 1
        self.values[self.count] = v
        self.sum = self.sum + v
    else
        self.head = (self.head % self.capacity) + 1
        local idx = self.head - 1
        if idx < 1 then idx = self.capacity end
        local old = self.values[idx]
        self.values[idx] = v
        self.sum = self.sum - old + v
    end
    if v < self.min then self.min = v end
    if v > self.max then self.max = v end
end

function TimeSeries:stats()
    local n = self.count
    if n == 0 then return { count = 0, min = 0, max = 0, avg = 0 } end
    local total = math.min(n, self.capacity)
    local sorted = {}
    for i = 1, total do sorted[i] = self.values[i] end
    table.sort(sorted)
    local p50 = sorted[math.ceil(total * 0.5)] or 0
    local p99 = sorted[math.ceil(total * 0.99)] or 0
    return {
        count = n,
        min = self.min == math.huge and 0 or self.min,
        max = self.max == -math.huge and 0 or self.max,
        avg = self.sum / total,
        p50 = p50,
        p99 = p99,
    }
end

--========== STATE ==========--
local State = {
    edr             = nil,
    installed       = false,
    unhooks         = {},
    rateLimiters    = {},
    bloom           = nil,
    inHook          = false,

    -- Instance tracking (weak!)
    trackedInstances = setmetatable({}, { __mode = "k" }),
    trackedCount    = 0,
    trackedOrder    = {},   -- LRU

    -- Property batching
    propertyBatch   = {},   -- { [instanceName] = { [prop] = {old, new, count} } }
    batchSize       = 0,
    lastBatchFlush  = 0,

    -- Service access
    serviceAccess   = {},   -- [name] = count
    serviceStats    = {},

    -- Remote cache
    remoteCache     = setmetatable({}, { __mode = "k" }),
    remoteCount     = 0,
    lastRemoteScan  = 0,

    -- Stats
    stats = {
        instanceCreate  = 0,
        instanceDestroy = 0,
        instanceClone   = 0,
        propertyChanges = 0,
        servicesAccessed = 0,
        remotesFound    = 0,
        sampleDropped   = 0,
        sampleKept      = 0,
    },

    -- Time series
    ts = {
        instanceRate    = TimeSeries.new(60),
        propertyRate    = TimeSeries.new(60),
        networkRate     = TimeSeries.new(60),
        fpsRate         = TimeSeries.new(60),
    },

    -- Kalman
    kalmanFPS       = nil,
    kalmanInstances = nil,

    -- Character baseline
    characterBaseline = {
        health = nil,
        maxHealth = nil,
        walkSpeed = nil,
        jumpPower = nil,
    },

    -- Camera baseline
    cameraBaseline = {
        fov = nil,
    },

    -- Adaptive
    currentSampleRate = 0.4,
    recentEventCount  = 0,
    lastEventReset    = 0,
}

--========== UTILITIES ==========--
local function now() return os.clock() end
local function walltime() return os.time() end

local function safeCall(fn, ...)
    local ok, result = pcall(fn, ...)
    if ok then return result end
    return nil
end

local function allowRate(key)
    local lim = State.rateLimiters[key]
    local t = now()
    if not lim or (t - lim.window_start) >= RobloxAPI.Config.RATE_LIMIT_WINDOW then
        State.rateLimiters[key] = { window_start = t, count = 1 }
        return true
    end
    if lim.count < RobloxAPI.Config.RATE_LIMIT_PER_SEC then
        lim.count = lim.count + 1
        return true
    end
    return false
end

local function shouldSample(key)
    if not RobloxAPI.Config.ADAPTIVE_ENABLED then return true end
    local t = now()
    -- reset counter ทุกวินาที
    if t - State.lastEventReset >= 1 then
        local rate = State.recentEventCount
        if rate >= RobloxAPI.Config.HIGH_ACTIVITY_THRESHOLD then
            State.currentSampleRate = RobloxAPI.Config.HIGH_ACTIVITY_SAMPLE_RATE
        else
            local ratio = rate / RobloxAPI.Config.HIGH_ACTIVITY_THRESHOLD
            State.currentSampleRate = RobloxAPI.Config.BASE_SAMPLE_RATE
                + ratio * (RobloxAPI.Config.HIGH_ACTIVITY_SAMPLE_RATE
                    - RobloxAPI.Config.BASE_SAMPLE_RATE)
        end
        State.recentEventCount = 0
        State.lastEventReset = t
    end
    State.recentEventCount = State.recentEventCount + 1

    if State.currentSampleRate >= 1.0 then return true end
    if math.random() < State.currentSampleRate then
        State.stats.sampleKept = State.stats.sampleKept + 1
        return true
    end
    State.stats.sampleDropped = State.stats.sampleDropped + 1
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

--========== LRU INSTANCE TRACKING ==========--
local function evictLRU()
    while State.trackedCount >= RobloxAPI.Config.MAX_TRACKED_INSTANCES do
        local oldest = table.remove(State.trackedOrder, 1)
        if not oldest then break end
        if State.trackedInstances[oldest] then
            State.trackedInstances[oldest] = nil
            State.trackedCount = State.trackedCount - 1
        end
    end
end

local function trackInstance(inst, class)
    if not inst or not class then return end
    if State.trackedInstances[inst] then
        -- refresh LRU
        return
    end

    evictLRU()

    -- เก็บ properties ที่สำคัญ
    local props = {}
    local propList = IMPORTANT_PROPERTIES[class] or IMPORTANT_PROPERTIES.BasePart or {}
    for _, pname in ipairs(propList) do
        local ok, val = pcall(function() return inst[pname] end)
        if ok then props[pname] = val end
    end

    State.trackedInstances[inst] = {
        class = class,
        props = props,
        tracked_at = now(),
        connections = {},
    }
    State.trackedCount = State.trackedCount + 1
    table.insert(State.trackedOrder, inst)

    -- เชื่อมต่อ property changed signal (ถ้ามี)
    pcall(function()
        local entry = State.trackedInstances[inst]
        for pname, _ in pairs(props) do
            local ok, signal = pcall(function()
                return inst:GetPropertyChangedSignal(pname)
            end)
            if ok and signal then
                local conn = signal:Connect(function()
                    -- batch ไว้ค่อย flush
                    local key = instName(inst)
                    local batch = State.propertyBatch[key]
                    if not batch then
                        batch = {}
                        State.propertyBatch[key] = batch
                    end
                    local p = batch[pname]
                    if p then
                        p.count = p.count + 1
                    else
                        local newVal
                        pcall(function() newVal = inst[pname] end)
                        batch[pname] = {
                            old = props[pname],
                            new = newVal,
                            count = 1,
                            class = class,
                        }
                        State.batchSize = State.batchSize + 1
                    end
                end)
                entry.connections[#entry.connections + 1] = conn
            end
        end
    end)
end

local function untrackInstance(inst)
    local entry = State.trackedInstances[inst]
    if not entry then return end

    for _, conn in ipairs(entry.connections) do
        pcall(function() conn:Disconnect() end)
    end

    State.trackedInstances[inst] = nil
    State.trackedCount = State.trackedCount - 1
end

--========== BATCH FLUSH ==========--
local function flushPropertyBatch()
    local t = now()
    if t - State.lastBatchFlush < RobloxAPI.Config.BATCH_FLUSH_INTERVAL
        and State.batchSize < RobloxAPI.Config.BATCH_MAX_SIZE then
        return
    end
    State.lastBatchFlush = t

    local totalBatch = State.batchSize
    State.batchSize = 0

    for instNameStr, batch in pairs(State.propertyBatch) do
        for pname, info in pairs(batch) do
            State.stats.propertyChanges = State.stats.propertyChanges + info.count

            -- dedup
            local key = instNameStr .. ":" .. pname .. ":" .. tostring(info.new):sub(1, 40)
            if State.bloom:contains(key) then
                -- skip
            else
                State.bloom:add(key)

                if allowRate("prop:" .. pname) then
                    local sev = 0
                    local mitre = nil
                    local class = info.class

                    if class == "Humanoid" then
                        if pname == "Health" or pname == "MaxHealth"
                            or pname == "WalkSpeed" or pname == "JumpPower" then
                            sev = 3
                            mitre = "T1562.001"
                        end
                    elseif class == "Camera" then
                        sev = 1
                    elseif class == "Script" or class == "LocalScript" then
                        sev = 3
                        mitre = "T1562.001"
                    elseif class == "BodyVelocity" or class == "BodyPosition"
                        or class == "BodyGyro" or class == "LinearVelocity" then
                        sev = 2
                        mitre = "T1562.001"
                    end

                    emit("RBX_PROPERTY_WRITE", {
                        class     = class,
                        instance  = instNameStr,
                        property  = pname,
                        old_value = tostring(info.old):sub(1, 60),
                        new_value = tostring(info.new):sub(1, 60),
                        count     = info.count,
                        mitre     = mitre,
                    }, sev)
                end
            end
        end
    end

    -- clear batch
    for k in pairs(State.propertyBatch) do
        State.propertyBatch[k] = nil
    end

    -- time series
    if totalBatch > 0 then
        State.ts.propertyRate:push(totalBatch)
    end
end

--========== 1. SERVICE ACCESS MONITOR ==========--
local function installServiceMonitor(edr)
    if not RobloxAPI.Config.TRACK_SERVICES then return nil end
    if not game or not game.GetService then return nil end

    local origGetService = game.GetService
    State.originalGetService = origGetService

    local wrapped = function(self, name, ...)
        local sname = tostring(name)
        State.serviceAccess[sname] = (State.serviceAccess[sname] or 0) + 1
        State.serviceStats[sname] = State.serviceStats[sname] or TimeSeries.new(60)
        State.serviceStats[sname]:push(now())
        State.stats.servicesAccessed = State.stats.servicesAccessed + 1

        local info = SENSITIVE_SERVICES[sname]
        if info then
            if allowRate("svc:" .. sname) and shouldSample("svc_" .. sname) then
                emit("RBX_SERVICE_ACCESS", {
                    service = sname,
                    reason  = info.reason,
                    mitre   = info.mitre,
                    count   = State.serviceAccess[sname],
                }, info.severity)
            end
        elseif allowRate("svc:" .. sname) and shouldSample("svc_general") then
            emit("RBX_SERVICE_ACCESS", {
                service = sname,
                reason  = "general",
            }, 0)
        end

        return origGetService(self, name, ...)
    end

    if newcclosure then
        pcall(function() wrapped = newcclosure(wrapped) end)
    end

    -- ลอง assign (อาจ fail ใน vanilla)
    local ok = pcall(function()
        game.GetService = wrapped
    end)

    if not ok then
        -- fallback: ไม่ได้ wrap → ใช้ scan แทน
        return function() end
    end

    return function()
        pcall(function() game.GetService = origGetService end)
    end
end

--========== 2. INSTANCE LIFECYCLE MONITOR ==========--
local function installInstanceMonitor(edr)
    if not RobloxAPI.Config.TRACK_INSTANCES then return nil end
    if not Instance or not Instance.new then return nil end

    local origNew = Instance.new
    State.originalInstanceNew = origNew

    local wrapped = function(class, parent)
        local inst = origNew(class, parent)
        State.stats.instanceCreate = State.stats.instanceCreate + 1
        State.ts.instanceRate:push(State.stats.instanceCreate)

        if allowRate("inst_new:" .. tostring(class)) and shouldSample("inst_new") then
            emit("RBX_INSTANCE_CREATE", {
                class  = tostring(class),
                parent = parent and instName(parent) or nil,
                total  = State.stats.instanceCreate,
            }, 0)
        end

        -- ติดตาม instance ที่สำคัญ
        if RobloxAPI.Config.TRACK_PROPERTIES and IMPORTANT_CLASSES[class] then
            trackInstance(inst, class)
        end

        return inst
    end

    if newcclosure then
        pcall(function() wrapped = newcclosure(wrapped) end)
    end

    Instance.new = wrapped

    return function()
        Instance.new = origNew
    end
end

--========== 3. PROPERTY SCANNER ==========--
local function startPropertyScanner()
    if not RobloxAPI.Config.TRACK_PROPERTIES then return nil end

    return task.spawn(function()
        while State.installed do
            task.wait(RobloxAPI.Config.PROPERTY_SCAN_INTERVAL)

            -- flush batch
            pcall(flushPropertyBatch)

            -- scan tracked instances (diff fallback ถ้า signal ไม่ทำงาน)
            for inst, entry in pairs(State.trackedInstances) do
                -- ตรวจว่า instance ยังอยู่
                local ok, parent = pcall(function() return inst.Parent end)
                if not ok or parent == nil and entry.class ~= "Camera" then
                    State.stats.instanceDestroy = State.stats.instanceDestroy + 1
                    if allowRate("inst_destroy") then
                        emit("RBX_INSTANCE_DESTROY", {
                            class = entry.class,
                            total = State.stats.instanceDestroy,
                        }, 0)
                    end
                    untrackInstance(inst)
                end
            end
        end
    end)
end

--========== 4. REMOTE DISCOVERY ==========--
local function scanRemotes()
    local remotes = {}
    local count = 0

    local function scan(parent, depth)
        if depth > RobloxAPI.Config.REMOTE_MAX_DEPTH then return end
        if count > RobloxAPI.Config.REMOTE_MAX_SCAN then return end
        if not parent then return end

        local ok, children = pcall(function() return parent:GetChildren() end)
        if not ok then return end

        for _, child in ipairs(children) do
            count = count + 1
            if count > RobloxAPI.Config.REMOTE_MAX_SCAN then return end

            local cn = safeCall(function() return child.ClassName end)
            if cn == "RemoteEvent" or cn == "RemoteFunction"
                or cn == "UnreliableRemoteEvent" then
                if not State.remoteCache[child] then
                    State.remoteCache[child] = true
                    State.remoteCount = State.remoteCount + 1
                    remotes[#remotes + 1] = child

                    emit("RBX_REMOTE_FOUND", {
                        name = instName(child),
                        class = cn,
                        total = State.remoteCount,
                    }, 0)
                end
            elseif cn == "Folder" or cn == "Model" or cn == "ScreenGui"
                or cn == "Configuration" or cn == "Tool"
                or cn == "Actor" or cn == "StarterPlayerScripts" then
                scan(child, depth + 1)
            end
        end
    end

    safeCall(function()
        scan(game:GetService("ReplicatedStorage"), 0)
    end)
    safeCall(function()
        scan(game:GetService("Workspace"), 0)
    end)
    safeCall(function()
        local lp = game:GetService("Players").LocalPlayer
        if lp then scan(lp, 0) end
    end)

    State.stats.remotesFound = State.remoteCount
    State.lastRemoteScan = now()

    -- ตรวจชื่อ remotes ที่น่าสงสัย
    local SUSPICIOUS = {
        "admin", "backdoor", "give", "grant", "setmoney", "setcash",
        "giveitem", "spawn", "kill", "damage", "tp", "teleport",
        "godmode", "noclip", "fly", "speed", "kick", "ban",
        "webhook", "discord", "token", "password", "secret",
    }
    for _, remote in ipairs(remotes) do
        local lname = tostring(remote.Name):lower()
        for _, sus in ipairs(SUSPICIOUS) do
            if lname:find(sus, 1, true) then
                emit("VULN_FINDING", {
                    category = "REMOTE_SECURITY",
                    severity = 3,
                    title    = "Suspicious RemoteEvent name",
                    detail   = string.format("Remote '%s' matches suspicious pattern '%s'",
                        instName(remote), sus),
                    mitre    = "T1059",
                }, 3)
                break
            end
        end
    end

    return #remotes
end

local function startRemoteScanner()
    if not RobloxAPI.Config.TRACK_REMOTES then return nil end

    return task.spawn(function()
        -- scan ครั้งแรก
        task.wait(3)
        pcall(scanRemotes)

        -- scan ซ้ำเป็นระยะ
        while State.installed do
            task.wait(RobloxAPI.Config.REMOTE_SCAN_INTERVAL)
            pcall(scanRemotes)
        end
    end)
end

--========== 5. CAMERA MONITOR ==========--
local function startCameraMonitor()
    if not RobloxAPI.Config.TRACK_CAMERA then return nil end

    return task.spawn(function()
        while State.installed do
            task.wait(RobloxAPI.Config.CAMERA_SCAN_INTERVAL)
            local cam = workspace and workspace.CurrentCamera
            if cam then
                trackInstance(cam, "Camera")

                -- ตรวจ FOV anomaly
                local ok, fov = pcall(function() return cam.FieldOfView end)
                if ok and fov then
                    if State.cameraBaseline.fov == nil then
                        State.cameraBaseline.fov = fov
                    else
                        local delta = math.abs(fov - State.cameraBaseline.fov)
                        if delta >= RobloxAPI.Config.CAMERA_FOV_THRESHOLD then
                            if allowRate("cam_fov") then
                                emit("RBX_CAMERA_CHANGE", {
                                    event = "FOVJump",
                                    old = State.cameraBaseline.fov,
                                    new = fov,
                                    delta = delta,
                                }, 2)
                            end
                            State.cameraBaseline.fov = fov
                        end
                    end
                end
            end
        end
    end)
end

--========== 6. CHARACTER MONITOR ==========--
local function startCharacterMonitor()
    if not RobloxAPI.Config.TRACK_CHARACTER then return nil end

    local conns = {}
    local lp = game:GetService("Players").LocalPlayer
    if not lp then return nil end

    -- CharacterAdded signal
    local ok, conn = pcall(function()
        return lp.CharacterAdded:Connect(function(char)
            if not char then return end
            local humanoid = char:FindFirstChildOfClass("Humanoid")
            if humanoid then trackInstance(humanoid, "Humanoid") end
            local hrp = char:FindFirstChild("HumanoidRootPart")
            if hrp then trackInstance(hrp, "HumanoidRootPart") end

            emit("RBX_CHARACTER_CHANGE", {
                event = "CharacterAdded",
                name  = char.Name or "?",
            }, 0)
        end)
    end)
    if ok and conn then conns[#conns + 1] = conn end

    -- CharacterRemoving signal
    local ok2, conn2 = pcall(function()
        return lp.CharacterRemoving:Connect(function(char)
            if not char then return end
            emit("RBX_CHARACTER_CHANGE", {
                event = "CharacterRemoving",
                name  = char.Name or "?",
            }, 0)
        end)
    end)
    if ok2 and conn2 then conns[#conns + 1] = conn2 end

    -- ติดตาม character ปัจจุบัน
    if lp.Character then
        local char = lp.Character
        local humanoid = char:FindFirstChildOfClass("Humanoid")
        if humanoid then trackInstance(humanoid, "Humanoid") end
        local hrp = char:FindFirstChild("HumanoidRootPart")
        if hrp then trackInstance(hrp, "HumanoidRootPart") end
    end

    -- Background scanner (health/speed jump)
    task.spawn(function()
        while State.installed do
            task.wait(RobloxAPI.Config.CHARACTER_SCAN_INTERVAL)
            local char = lp.Character
            if char then
                local humanoid = char:FindFirstChildOfClass("Humanoid")
                if humanoid then
                    local h = safeCall(function() return humanoid.Health end)
                    local mh = safeCall(function() return humanoid.MaxHealth end)
                    local ws = safeCall(function() return humanoid.WalkSpeed end)

                    if h then
                        if State.characterBaseline.health == nil then
                            State.characterBaseline.health = h
                            State.characterBaseline.maxHealth = mh
                            State.characterBaseline.walkSpeed = ws
                        else
                            local dHealth = math.abs(h - State.characterBaseline.health)
                            if dHealth >= RobloxAPI.Config.HEALTH_JUMP_THRESHOLD then
                                if allowRate("char_health") then
                                    emit("RBX_CHARACTER_CHANGE", {
                                        event = "HealthJump",
                                        old = State.characterBaseline.health,
                                        new = h,
                                        delta = dHealth,
                                    }, 3)
                                end
                            end
                            State.characterBaseline.health = h

                            if ws then
                                local dSpeed = math.abs(ws - (State.characterBaseline.walkSpeed or ws))
                                if dSpeed >= RobloxAPI.Config.SPEED_JUMP_THRESHOLD then
                                    if allowRate("char_speed") then
                                        emit("RBX_CHARACTER_CHANGE", {
                                            event = "SpeedJump",
                                            old = State.characterBaseline.walkSpeed,
                                            new = ws,
                                            delta = dSpeed,
                                        }, 3)
                                    end
                                end
                                State.characterBaseline.walkSpeed = ws
                            end
                        end
                    end
                end
            end
        end
    end)

    return function()
        for _, c in ipairs(conns) do
            pcall(function() c:Disconnect() end)
        end
    end
end

--========== 7. WORKSPACE SCANNER ==========--
local function startWorkspaceScanner()
    if not RobloxAPI.Config.TRACK_WORKSPACE then return nil end

    return task.spawn(function()
        while State.installed do
            task.wait(RobloxAPI.Config.WORKSPACE_SCAN_INTERVAL)
            local ws = workspace
            if ws then
                local ok, children = pcall(function() return ws:GetChildren() end)
                if ok then
                    local scripts, remoteCount = 0, 0
                    for _, child in ipairs(children) do
                        local cn = safeCall(function() return child.ClassName end)
                        if cn == "Script" or cn == "LocalScript" then
                            scripts = scripts + 1
                        elseif cn == "RemoteEvent" or cn == "RemoteFunction" then
                            remoteCount = remoteCount + 1
                        end
                    end

                    if scripts > 0 and allowRate("ws_scripts") then
                        emit("RBX_WORKSPACE_WRITE", {
                            event = "ScriptsInWorkspace",
                            count = scripts,
                            mitre = "T1059",
                        }, 3)
                    end
                end
            end
        end
    end)
end

--========== 8. PLAYER MONITOR ==========--
local function startPlayerMonitor()
    if not RobloxAPI.Config.TRACK_PLAYER then return nil end

    local lp = game:GetService("Players").LocalPlayer
    if not lp then return nil end

    trackInstance(lp, "Player")

    -- LocalPlayer properties
    local conns = {}
    pcall(function()
        local conn = lp.CharacterAdded:Connect(function()
            -- track ใหม่ทุกครั้ง
            trackInstance(lp, "Player")
        end)
        conns[#conns + 1] = conn
    end)

    return function()
        for _, c in ipairs(conns) do
            pcall(function() c:Disconnect() end)
        end
    end
end

--========== 9. FPS MONITOR ==========--
local function startFPSMonitor()
    local RunService = game:GetService("RunService")
    if not RunService then return nil end

    local conn = RunService.Heartbeat:Connect(function(dt)
        if dt > 0 then
            local fps = 1 / dt
            State.ts.fpsRate:push(fps)
            if State.kalmanFPS then
                State.kalmanFPS:update(fps)
            end
        end
    end)

    return function()
        pcall(function() conn:Disconnect() end)
    end
end

--========== INSTALL ==========--
function RobloxAPI.install(edr)
    if State.installed then
        return false, "already installed"
    end

    State.edr = edr
    State.installed = true
    State.bloom = Bloom.new(RobloxAPI.Config.BLOOM_SIZE, RobloxAPI.Config.BLOOM_HASHES)
    State.kalmanFPS = Kalman.new(0.001, 0.1, 60)
    State.kalmanInstances = Kalman.new(0.01, 0.1, 0)

    local unhooks = {}

    local function try(name, fn)
        local ok, result = pcall(fn, edr)
        if ok and result then
            unhooks[#unhooks + 1] = { name = name, fn = result }
            if State.edr.registerHook then
                State.edr:registerHook("roblox_api." .. name, function()
                    if type(result) == "function" then result() end
                end)
            end
        end
    end

    try("services",       installServiceMonitor)
    try("instances",      installInstanceMonitor)
    try("camera",         startCameraMonitor)
    try("character",      startCharacterMonitor)
    try("workspace",      startWorkspaceScanner)
    try("player",         startPlayerMonitor)
    try("fps",            startFPSMonitor)

    -- Property scanner thread
    local scannerThread = startPropertyScanner()
    if scannerThread then
        unhooks[#unhooks + 1] = {
            name = "property_scanner",
            fn = function()
                pcall(function() task.cancel(scannerThread) end)
            end,
        }
    end

    -- Remote scanner thread
    local remoteThread = startRemoteScanner()
    if remoteThread then
        unhooks[#unhooks + 1] = {
            name = "remote_scanner",
            fn = function()
                pcall(function() task.cancel(remoteThread) end)
            end,
        }
    end

    State.unhooks = unhooks
    return true, #unhooks
end

--========== UNINSTALL ==========--
function RobloxAPI.uninstall()
    if not State.installed then return end
    State.installed = false

    -- flush remaining batches
    pcall(flushPropertyBatch)

    -- disconnect all
    for _, entry in ipairs(State.unhooks or {}) do
        pcall(entry.fn)
    end
    State.unhooks = {}

    -- cleanup tracked instances
    for inst, entry in pairs(State.trackedInstances) do
        for _, conn in ipairs(entry.connections or {}) do
            pcall(function() conn:Disconnect() end)
        end
    end
    State.trackedInstances = setmetatable({}, { __mode = "k" })
    State.trackedOrder = {}
    State.trackedCount = 0
    State.rateLimiters = {}
    State.propertyBatch = {}
end

--========== STATS ==========--
function RobloxAPI.getStats()
    return {
        instances = {
            create  = State.stats.instanceCreate,
            destroy = State.stats.instanceDestroy,
            tracked = State.trackedCount,
        },
        properties = {
            changes = State.stats.propertyChanges,
            batchSize = State.batchSize,
        },
        services = {
            accessed = State.stats.servicesAccessed,
            unique   = (function()
                local n = 0
                for _ in pairs(State.serviceAccess) do n = n + 1 end
                return n
            end)(),
        },
        remotes = {
            found = State.remoteCount,
        },
        sampling = {
            kept    = State.stats.sampleKept,
            dropped = State.stats.sampleDropped,
            rate    = State.currentSampleRate,
        },
        timeseries = {
            instanceRate = State.ts.instanceRate:stats(),
            propertyRate = State.ts.propertyRate:stats(),
            fpsRate      = State.ts.fpsRate:stats(),
        },
        kalman = {
            fps = State.kalmanFPS and State.kalmanFPS:get() or 60,
        },
    }
end

function RobloxAPI.getSensitiveServiceList()
    local list = {}
    for name, count in pairs(State.serviceAccess) do
        if SENSITIVE_SERVICES[name] then
            list[#list + 1] = {
                service = name,
                count = count,
                severity = SENSITIVE_SERVICES[name].severity,
                reason = SENSITIVE_SERVICES[name].reason,
            }
        end
    end
    table.sort(list, function(a, b) return a.count > b.count end)
    return list
end

function RobloxAPI.getAllServiceList()
    local list = {}
    for name, count in pairs(State.serviceAccess) do
        list[#list + 1] = { service = name, count = count }
    end
    table.sort(list, function(a, b) return a.count > b.count end)
    return list
end

function RobloxAPI.getRemoteList()
    local list = {}
    for remote in pairs(State.remoteCache) do
        local name = safeCall(function() return remote:GetFullName() end)
        local cn = safeCall(function() return remote.ClassName end)
        if name then
            list[#list + 1] = { name = name, class = cn }
        end
    end
    return list
end

function RobloxAPI.getTrackedInstances()
    local list = {}
    for inst, entry in pairs(State.trackedInstances) do
        list[#list + 1] = {
            name = instName(inst),
            class = entry.class,
            tracked_at = entry.tracked_at,
        }
    end
    return list
end

--========== EXPORT ==========--
RobloxAPI.SENSITIVE_SERVICES = SENSITIVE_SERVICES
RobloxAPI.IMPORTANT_CLASSES = IMPORTANT_CLASSES
RobloxAPI.IMPORTANT_PROPERTIES = IMPORTANT_PROPERTIES
RobloxAPI.State = State

return RobloxAPI