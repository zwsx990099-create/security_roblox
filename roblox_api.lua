--[[
    ============================================================
    EDR Roblox API Monitor v3.0 — Version-Aware
    ============================================================
    NEW in v3.0:
    - MODULE_VERSION = "3.0.0"
    - setPerformanceMode(mode) — light/balanced/paranoid
    - Structured JSON logging
    - Self-integrity check
    - Buffer caps
    - Consistent pcall + degrade
    - Mode-aware tracking

    Compliance:
    - ใช้เฉพาะ public API ของ Roblox (ToS compliant)
    - ไม่แตะหน่วยความจำ / ไม่ดัก packet / ไม่ดึง source
    - Weak tables ป้องกัน memory leak
    - Batched property updates
    ============================================================
]]

local RobloxAPI = {}

--========== VERSION ==========--
RobloxAPI._VERSION = "3.0.0"
RobloxAPI.MODULE_VERSION = "3.0.0"
RobloxAPI.VERSION = "3.0.0"

--========== CONFIG ==========--
RobloxAPI.Config = {
    RATE_LIMIT_PER_SEC          = 50,
    RATE_LIMIT_WINDOW           = 1.0,
    MAX_TRACKED_INSTANCES       = 300,
    MAX_TRACKED_PROPERTIES      = 16,
    MAX_TRACKED_NAMES           = 500,
    BATCH_FLUSH_INTERVAL        = 1.0,
    BATCH_MAX_SIZE              = 200,
    PROPERTY_SCAN_INTERVAL      = 1.0,
    BLOOM_SIZE                  = 1 << 16,
    BLOOM_HASHES                = 4,
    ADAPTIVE_ENABLED            = true,
    BASE_SAMPLE_RATE            = 0.4,
    HIGH_ACTIVITY_SAMPLE_RATE   = 1.0,
    HIGH_ACTIVITY_THRESHOLD     = 20,
    TRACK_SERVICES              = true,
    TRACK_INSTANCES             = true,
    TRACK_PROPERTIES            = true,
    TRACK_REMOTES               = true,
    TRACK_CAMERA                = true,
    TRACK_CHARACTER             = true,
    TRACK_WORKSPACE             = true,
    TRACK_PLAYER                = true,
    REMOTE_SCAN_INTERVAL        = 30,
    REMOTE_MAX_DEPTH            = 6,
    REMOTE_MAX_SCAN             = 5000,
    CAMERA_SCAN_INTERVAL        = 1.0,
    CAMERA_FOV_THRESHOLD        = 5,
    CHARACTER_SCAN_INTERVAL     = 0.5,
    HEALTH_JUMP_THRESHOLD       = 30,
    SPEED_JUMP_THRESHOLD        = 20,
    WORKSPACE_SCAN_INTERVAL     = 5,
    LOG_LEVEL                   = 1,
    LOG_STRUCTURED              = false,

    -- v3.0
    SELF_INTEGRITY              = true,
    INTEGRITY_INTERVAL          = 30,
    MAX_PROPERTY_CHANGES        = 10000,
    MAX_SERVICE_ACCESSES        = 5000,
    PERFORMANCE_MODE            = "balanced",
}

--========== MODE PROFILES ==========--
local MODE_PROFILES = {
    light = {
        MAX_TRACKED_INSTANCES       = 80,
        MAX_TRACKED_PROPERTIES      = 8,
        BATCH_FLUSH_INTERVAL        = 2.0,
        PROPERTY_SCAN_INTERVAL      = 2.0,
        REMOTE_SCAN_INTERVAL        = 60,
        REMOTE_MAX_SCAN             = 1000,
        CAMERA_SCAN_INTERVAL        = 3.0,
        CHARACTER_SCAN_INTERVAL     = 2.0,
        WORKSPACE_SCAN_INTERVAL     = 15,
        TRACK_REMOTES               = true,
        TRACK_CAMERA                = true,
        TRACK_CHARACTER             = true,
        TRACK_WORKSPACE             = false,
        TRACK_PLAYER                = false,
        BASE_SAMPLE_RATE            = 0.2,
        HIGH_ACTIVITY_SAMPLE_RATE   = 0.6,
        BLOOM_SIZE                  = 1 << 14,
    },
    balanced = {
        MAX_TRACKED_INSTANCES       = 300,
        MAX_TRACKED_PROPERTIES      = 16,
        BATCH_FLUSH_INTERVAL        = 1.0,
        PROPERTY_SCAN_INTERVAL      = 1.0,
        REMOTE_SCAN_INTERVAL        = 30,
        REMOTE_MAX_SCAN             = 5000,
        CAMERA_SCAN_INTERVAL        = 1.0,
        CHARACTER_SCAN_INTERVAL     = 0.5,
        WORKSPACE_SCAN_INTERVAL     = 5,
        TRACK_REMOTES               = true,
        TRACK_CAMERA                = true,
        TRACK_CHARACTER             = true,
        TRACK_WORKSPACE             = true,
        TRACK_PLAYER                = true,
        BASE_SAMPLE_RATE            = 0.4,
        HIGH_ACTIVITY_SAMPLE_RATE   = 1.0,
        BLOOM_SIZE                  = 1 << 16,
    },
    paranoid = {
        MAX_TRACKED_INSTANCES       = 1000,
        MAX_TRACKED_PROPERTIES      = 32,
        BATCH_FLUSH_INTERVAL        = 0.5,
        PROPERTY_SCAN_INTERVAL      = 0.5,
        REMOTE_SCAN_INTERVAL        = 10,
        REMOTE_MAX_SCAN             = 20000,
        CAMERA_SCAN_INTERVAL        = 0.5,
        CHARACTER_SCAN_INTERVAL     = 0.25,
        WORKSPACE_SCAN_INTERVAL     = 2,
        TRACK_REMOTES               = true,
        TRACK_CAMERA                = true,
        TRACK_CHARACTER             = true,
        TRACK_WORKSPACE             = true,
        TRACK_PLAYER                = true,
        BASE_SAMPLE_RATE            = 0.8,
        HIGH_ACTIVITY_SAMPLE_RATE   = 1.0,
        BLOOM_SIZE                  = 1 << 20,
    },
}

function RobloxAPI.setPerformanceMode(mode)
    if not mode or not MODE_PROFILES[mode] then
        return false, "unknown mode: " .. tostring(mode)
    end
    local profile = MODE_PROFILES[mode]
    for k, v in pairs(profile) do
        RobloxAPI.Config[k] = v
    end
    RobloxAPI.Config.PERFORMANCE_MODE = mode
    RobloxAPI._log(1, "perf", "mode applied: " .. mode, profile)
    return true
end

function RobloxAPI.getPerformanceMode()
    return RobloxAPI.Config.PERFORMANCE_MODE
end

function RobloxAPI.getVersion()
    return RobloxAPI._VERSION
end

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

--========== IMPORTANT CLASSES ==========--
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
local function hashN(str, n) return fnv1a(str, HASH_SEEDS[n]) end

--========== LOGGING ==========--
local function jsonEscape(s)
    s = tostring(s or "")
    s = s:gsub("\\", "\\\\"):gsub("\"", "\\\"")
        :gsub("\n", "\\n"):gsub("\r", "\\r"):gsub("\t", "\\t")
    return s
end

local function jsonEncode(t)
    if type(t) ~= "table" then
        if type(t) == "string" then return '"' .. jsonEscape(t) .. '"'
        elseif type(t) == "number" or type(t) == "boolean" then return tostring(t)
        else return "null" end
    end
    local isArray = #t > 0
    local parts = {}
    if isArray then
        for i = 1, #t do parts[#parts + 1] = jsonEncode(t[i]) end
        return "[" .. table.concat(parts, ",") .. "]"
    else
        for k, v in pairs(t) do
            parts[#parts + 1] = '"' .. jsonEscape(k) .. '":' .. jsonEncode(v)
        end
        return "{" .. table.concat(parts, ",") .. "}"
    end
end

function RobloxAPI._log(level, module, event, data)
    if level > RobloxAPI.Config.LOG_LEVEL then return end
    if RobloxAPI.Config.LOG_STRUCTURED then
        local entry = {
            ts = os.time(), level = level,
            module = "rbxapi." .. tostring(module),
            event = event,
        }
        if data then entry.data = data end
        print("[EDR] " .. jsonEncode(entry))
    else
        print(string.format("[RBXAPI][%s] %s", tostring(module), tostring(event)))
    end
end

local log = RobloxAPI._log

--========== BLOOM ==========--
local Bloom = {}
Bloom.__index = Bloom

function Bloom.new(size, hashes)
    return setmetatable({
        size = size or (1 << 16),
        hashCount = hashes or 4,
        bits = {}, itemCount = 0,
    }, Bloom)
end

function Bloom:add(str)
    if type(str) ~= "string" then return end
    for i = 1, self.hashCount do
        local idx = hashN(str, i) % self.size
        local w = math.floor(idx / 32)
        self.bits[w] = bor(self.bits[w] or 0, 1 << (idx % 32))
    end
    self.itemCount = self.itemCount + 1
end

function Bloom:contains(str)
    if type(str) ~= "string" then return false end
    for i = 1, self.hashCount do
        local idx = hashN(str, i) % self.size
        local w = math.floor(idx / 32)
        if band(self.bits[w] or 0, 1 << (idx % 32)) == 0 then return false end
    end
    return true
end

--========== KALMAN ==========--
local Kalman = {}
Kalman.__index = Kalman

function Kalman.new(q, r, initial)
    return setmetatable({
        q = q or 0.01, r = r or 0.1, x = initial or 0, p = 1.0,
    }, Kalman)
end

function Kalman:update(z)
    self.p = self.p + self.q
    local k = self.p / (self.p + self.r)
    self.x = self.x + k * (z - self.x)
    self.p = (1 - k) * self.p
    return self.x
end

function Kalman:get() return self.x end

--========== TIME SERIES ==========--
local TimeSeries = {}
TimeSeries.__index = TimeSeries

function TimeSeries.new(capacity)
    return setmetatable({
        capacity = capacity or 60,
        values = {}, count = 0, head = 1,
        sum = 0, min = math.huge, max = -math.huge,
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
    return {
        count = n,
        min = self.min == math.huge and 0 or self.min,
        max = self.max == -math.huge and 0 or self.max,
        avg = self.sum / total,
        p50 = sorted[math.ceil(total * 0.5)] or 0,
        p99 = sorted[math.ceil(total * 0.99)] or 0,
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

    trackedInstances = setmetatable({}, { __mode = "k" }),
    trackedCount    = 0,
    trackedOrder    = {},

    propertyBatch   = {},
    batchSize       = 0,
    lastBatchFlush  = 0,
    batchDropped    = 0,

    serviceAccess   = {},
    serviceStats    = {},
    serviceDropped  = 0,

    remoteCache     = setmetatable({}, { __mode = "k" }),
    remoteCount     = 0,
    lastRemoteScan  = 0,

    stats = {
        instanceCreate  = 0,
        instanceDestroy = 0,
        propertyChanges = 0,
        servicesAccessed = 0,
        remotesFound    = 0,
        sampleDropped   = 0,
        sampleKept      = 0,
    },

    ts = {
        instanceRate    = TimeSeries.new(60),
        propertyRate    = TimeSeries.new(60),
        networkRate     = TimeSeries.new(60),
        fpsRate         = TimeSeries.new(60),
    },

    kalmanFPS       = nil,
    kalmanInstances = nil,

    characterBaseline = { health = nil, maxHealth = nil, walkSpeed = nil, jumpPower = nil },
    cameraBaseline = { fov = nil },

    currentSampleRate = 0.4,
    recentEventCount  = 0,
    lastEventReset    = 0,

    integrityThread   = nil,
    integrityViolations = 0,
}

--========== UTILITIES ==========--
local function now() return os.clock() end

local function safeCall(fn, ...)
    local ok, r = pcall(fn, ...)
    if ok then return r end
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
    if State.trackedInstances[inst] then return end
    evictLRU()

    local props = {}
    local propList = IMPORTANT_PROPERTIES[class] or IMPORTANT_PROPERTIES.BasePart or {}
    local limit = RobloxAPI.Config.MAX_TRACKED_PROPERTIES
    local count = 0
    for _, pname in ipairs(propList) do
        if count >= limit then break end
        local ok, val = pcall(function() return inst[pname] end)
        if ok then props[pname] = val; count = count + 1 end
    end

    State.trackedInstances[inst] = {
        class = class, props = props,
        tracked_at = now(), connections = {},
    }
    State.trackedCount = State.trackedCount + 1
    table.insert(State.trackedOrder, inst)

    pcall(function()
        local entry = State.trackedInstances[inst]
        if not entry then return end
        for pname, _ in pairs(props) do
            local ok, signal = pcall(function()
                return inst:GetPropertyChangedSignal(pname)
            end)
            if ok and signal then
                local conn = signal:Connect(function()
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
                            old = props[pname], new = newVal,
                            count = 1, class = class,
                        }
                        State.batchSize = State.batchSize + 1
                        if State.batchSize > RobloxAPI.Config.MAX_PROPERTY_CHANGES then
                            State.batchDropped = State.batchDropped + 1
                        end
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
            local key = instNameStr .. ":" .. pname .. ":" .. tostring(info.new):sub(1, 40)
            if not State.bloom:contains(key) then
                State.bloom:add(key)
                if allowRate("prop:" .. pname) then
                    local sev = 0
                    local mitre = nil
                    local class = info.class
                    if class == "Humanoid" then
                        if pname == "Health" or pname == "MaxHealth"
                            or pname == "WalkSpeed" or pname == "JumpPower" then
                            sev = 3; mitre = "T1562.001"
                        end
                    elseif class == "Camera" then
                        sev = 1
                    elseif class == "Script" or class == "LocalScript" then
                        sev = 3; mitre = "T1562.001"
                    elseif class == "BodyVelocity" or class == "BodyPosition"
                        or class == "BodyGyro" or class == "LinearVelocity" then
                        sev = 2; mitre = "T1562.001"
                    end
                    emit("RBX_PROPERTY_WRITE", {
                        class = class, instance = instNameStr,
                        property = pname,
                        old_value = tostring(info.old):sub(1, 60),
                        new_value = tostring(info.new):sub(1, 60),
                        count = info.count, mitre = mitre,
                    }, sev)
                end
            end
        end
    end
    for k in pairs(State.propertyBatch) do State.propertyBatch[k] = nil end
    if totalBatch > 0 then State.ts.propertyRate:push(totalBatch) end
end

--========== 1. SERVICE MONITOR ==========--
local function installServiceMonitor(edr)
    if not RobloxAPI.Config.TRACK_SERVICES then return nil end
    if not game or not game.GetService then return nil end

    local orig = game.GetService
    State.originalGetService = orig

    local wrapped = function(self, name, ...)
        local sname = tostring(name)
        if State.stats.servicesAccessed >= RobloxAPI.Config.MAX_SERVICE_ACCESSES then
            State.serviceDropped = State.serviceDropped + 1
        else
            State.serviceAccess[sname] = (State.serviceAccess[sname] or 0) + 1
            State.serviceStats[sname] = State.serviceStats[sname] or TimeSeries.new(60)
            State.serviceStats[sname]:push(now())
            State.stats.servicesAccessed = State.stats.servicesAccessed + 1
        end

        local info = SENSITIVE_SERVICES[sname]
        if info then
            if allowRate("svc:" .. sname) and shouldSample("svc_" .. sname) then
                emit("RBX_SERVICE_ACCESS", {
                    service = sname, reason = info.reason, mitre = info.mitre,
                    count = State.serviceAccess[sname] or 0,
                }, info.severity)
            end
        elseif allowRate("svc:" .. sname) and shouldSample("svc_general") then
            emit("RBX_SERVICE_ACCESS", { service = sname, reason = "general" }, 0)
        end
        return orig(self, name, ...)
    end

    if newcclosure then pcall(function() wrapped = newcclosure(wrapped) end) end

    local ok = pcall(function() game.GetService = wrapped end)
    if not ok then return function() end end

    return function()
        pcall(function() game.GetService = orig end)
    end
end

--========== 2. INSTANCE LIFECYCLE ==========--
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
                class = tostring(class),
                parent = parent and instName(parent) or nil,
                total = State.stats.instanceCreate,
            }, 0)
        end
        if RobloxAPI.Config.TRACK_PROPERTIES and IMPORTANT_CLASSES[class] then
            trackInstance(inst, class)
        end
        return inst
    end

    if newcclosure then pcall(function() wrapped = newcclosure(wrapped) end) end
    Instance.new = wrapped

    return function() Instance.new = origNew end
end

--========== 3. PROPERTY SCANNER ==========--
local function startPropertyScanner()
    if not RobloxAPI.Config.TRACK_PROPERTIES then return nil end
    return task.spawn(function()
        while State.installed do
            task.wait(RobloxAPI.Config.PROPERTY_SCAN_INTERVAL)
            pcall(flushPropertyBatch)
            for inst, entry in pairs(State.trackedInstances) do
                local ok, parent = pcall(function() return inst.Parent end)
                if not ok or (parent == nil and entry.class ~= "Camera") then
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
                        name = instName(child), class = cn,
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

    safeCall(function() scan(game:GetService("ReplicatedStorage"), 0) end)
    safeCall(function() scan(game:GetService("Workspace"), 0) end)
    safeCall(function()
        local lp = game:GetService("Players").LocalPlayer
        if lp then scan(lp, 0) end
    end)

    State.stats.remotesFound = State.remoteCount
    State.lastRemoteScan = now()

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
                    category = "REMOTE_SECURITY", severity = 3,
                    title = "Suspicious RemoteEvent name",
                    detail = string.format("Remote '%s' matches suspicious pattern '%s'",
                        instName(remote), sus),
                    mitre = "T1059",
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
        task.wait(3)
        pcall(scanRemotes)
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
                                    new = fov, delta = delta,
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

    pcall(function()
        local conn = lp.CharacterAdded:Connect(function(char)
            if not char then return end
            local humanoid = char:FindFirstChildOfClass("Humanoid")
            if humanoid then trackInstance(humanoid, "Humanoid") end
            local hrp = char:FindFirstChild("HumanoidRootPart")
            if hrp then trackInstance(hrp, "HumanoidRootPart") end
            emit("RBX_CHARACTER_CHANGE", {
                event = "CharacterAdded", name = char.Name or "?",
            }, 0)
        end)
        conns[#conns + 1] = conn
    end)

    pcall(function()
        local conn = lp.CharacterRemoving:Connect(function(char)
            if not char then return end
            emit("RBX_CHARACTER_CHANGE", {
                event = "CharacterRemoving", name = char.Name or "?",
            }, 0)
        end)
        conns[#conns + 1] = conn
    end)

    if lp.Character then
        local char = lp.Character
        local humanoid = char:FindFirstChildOfClass("Humanoid")
        if humanoid then trackInstance(humanoid, "Humanoid") end
        local hrp = char:FindFirstChild("HumanoidRootPart")
        if hrp then trackInstance(hrp, "HumanoidRootPart") end
    end

    task.spawn(function()
        while State.installed do
            task.wait(RobloxAPI.Config.CHARACTER_SCAN_INTERVAL)
            local char = lp.Character
            if char then
                local humanoid = char:FindFirstChildOfClass("Humanoid")
                if humanoid then
                    local h = safeCall(function() return humanoid.Health end)
                    local ws = safeCall(function() return humanoid.WalkSpeed end)
                    if h then
                        if State.characterBaseline.health == nil then
                            State.characterBaseline.health = h
                            State.characterBaseline.walkSpeed = ws
                        else
                            local dHealth = math.abs(h - State.characterBaseline.health)
                            if dHealth >= RobloxAPI.Config.HEALTH_JUMP_THRESHOLD then
                                if allowRate("char_health") then
                                    emit("RBX_CHARACTER_CHANGE", {
                                        event = "HealthJump",
                                        old = State.characterBaseline.health,
                                        new = h, delta = dHealth,
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
                                            new = ws, delta = dSpeed,
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
        for _, c in ipairs(conns) do pcall(function() c:Disconnect() end) end
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
                    local scripts = 0
                    for _, child in ipairs(children) do
                        local cn = safeCall(function() return child.ClassName end)
                        if cn == "Script" or cn == "LocalScript" then
                            scripts = scripts + 1
                        end
                    end
                    if scripts > 0 and allowRate("ws_scripts") then
                        emit("RBX_WORKSPACE_WRITE", {
                            event = "ScriptsInWorkspace",
                            count = scripts, mitre = "T1059",
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
    return function() end
end

--========== 9. FPS MONITOR ==========--
local function startFPSMonitor()
    local RunService = game:GetService("RunService")
    if not RunService then return nil end
    local conn = RunService.Heartbeat:Connect(function(dt)
        if dt > 0 then
            local fps = 1 / dt
            State.ts.fpsRate:push(fps)
            if State.kalmanFPS then State.kalmanFPS:update(fps) end
        end
    end)
    return function() pcall(function() conn:Disconnect() end) end
end

--========== SELF INTEGRITY ==========--
local function startSelfIntegrity()
    if not RobloxAPI.Config.SELF_INTEGRITY then return end
    if State.integrityThread then return end

    local watched = {
        { name = "pcall", fn = pcall },
        { name = "type", fn = type },
        { name = "setmetatable", fn = setmetatable },
    }
    local baseline = {}
    for _, w in ipairs(watched) do baseline[w.name] = tostring(w.fn) end

    State.integrityThread = task.spawn(function()
        while State.installed do
            task.wait(RobloxAPI.Config.INTEGRITY_INTERVAL)
            for _, w in ipairs(watched) do
                local cur = tostring(w.fn)
                if cur ~= baseline[w.name] then
                    State.integrityViolations = State.integrityViolations + 1
                    emit("ANOMALY", {
                        metric = "rbxapi_integrity_violation",
                        fn = w.name,
                    }, 4)
                    baseline[w.name] = cur
                end
            end
        end
    end)
end

--========== INSTALL ==========--
function RobloxAPI.install(edr)
    if State.installed then return false, "already installed" end
    State.edr = edr
    State.installed = true
    State.bloom = Bloom.new(RobloxAPI.Config.BLOOM_SIZE, RobloxAPI.Config.BLOOM_HASHES)
    State.kalmanFPS = Kalman.new(0.001, 0.1, 60)

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

    try("services", installServiceMonitor)
    try("instances", installInstanceMonitor)
    try("camera", startCameraMonitor)
    try("character", startCharacterMonitor)
    try("workspace", startWorkspaceScanner)
    try("player", startPlayerMonitor)
    try("fps", startFPSMonitor)

    local scannerThread = startPropertyScanner()
    if scannerThread then
        unhooks[#unhooks + 1] = {
            name = "property_scanner",
            fn = function() pcall(function() task.cancel(scannerThread) end) end,
        }
    end

    local remoteThread = startRemoteScanner()
    if remoteThread then
        unhooks[#unhooks + 1] = {
            name = "remote_scanner",
            fn = function() pcall(function() task.cancel(remoteThread) end) end,
        }
    end

    State.unhooks = unhooks
    startSelfIntegrity()

    log(1, "install", "installed",
        { count = #unhooks, mode = RobloxAPI.Config.PERFORMANCE_MODE })
    return true, #unhooks
end

--========== UNINSTALL ==========--
function RobloxAPI.uninstall()
    if not State.installed then return end
    State.installed = false
    pcall(flushPropertyBatch)
    for _, entry in ipairs(State.unhooks or {}) do
        pcall(entry.fn)
    end
    State.unhooks = {}
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
    if State.integrityThread then
        pcall(function() task.cancel(State.integrityThread) end)
        State.integrityThread = nil
    end
    log(1, "uninstall", "removed")
end

--========== QUERIES ==========--
function RobloxAPI.getStats()
    return {
        version = RobloxAPI._VERSION,
        mode = RobloxAPI.Config.PERFORMANCE_MODE,
        instances = {
            create = State.stats.instanceCreate,
            destroy = State.stats.instanceDestroy,
            tracked = State.trackedCount,
        },
        properties = {
            changes = State.stats.propertyChanges,
            batchSize = State.batchSize,
            dropped = State.batchDropped,
        },
        services = {
            accessed = State.stats.servicesAccessed,
            dropped = State.serviceDropped,
            unique = (function()
                local n = 0
                for _ in pairs(State.serviceAccess) do n = n + 1 end
                return n
            end)(),
        },
        remotes = { found = State.remoteCount },
        sampling = {
            kept = State.stats.sampleKept,
            dropped = State.stats.sampleDropped,
            rate = State.currentSampleRate,
        },
        timeseries = {
            instanceRate = State.ts.instanceRate:stats(),
            propertyRate = State.ts.propertyRate:stats(),
            fpsRate = State.ts.fpsRate:stats(),
        },
        kalman = {
            fps = State.kalmanFPS and State.kalmanFPS:get() or 60,
        },
        integrityViolations = State.integrityViolations,
    }
end

function RobloxAPI.getSensitiveServiceList()
    local list = {}
    for name, count in pairs(State.serviceAccess) do
        if SENSITIVE_SERVICES[name] then
            list[#list + 1] = {
                service = name, count = count,
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
            name = instName(inst), class = entry.class,
            tracked_at = entry.tracked_at,
        }
    end
    return list
end

--========== EXPORT ==========--
RobloxAPI.SENSITIVE_SERVICES = SENSITIVE_SERVICES
RobloxAPI.IMPORTANT_CLASSES = IMPORTANT_CLASSES
RobloxAPI.IMPORTANT_PROPERTIES = IMPORTANT_PROPERTIES
RobloxAPI.MODE_PROFILES = MODE_PROFILES
RobloxAPI.State = State
RobloxAPI.Bloom = Bloom
RobloxAPI.Kalman = Kalman

return RobloxAPI