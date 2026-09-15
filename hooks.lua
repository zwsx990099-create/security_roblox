--[[
    ============================================================
    EDR Hooks v3.0 — Behavior Interception (Hardened)
    ============================================================
    NEW in v3.0:
    - MODULE_VERSION = "3.0.0" (สำหรับ main.lua v4.0)
    - setPerformanceMode(mode) — เรียกจาก main ได้
    - MODE_PROFILES (light/balanced/paranoid)
    - MAX_BUFFER cap (ป้องกัน memory)
    - Structured JSON logging
    - Consistent pcall + degrade
    - ToS guard (ไม่ hook blocked ops)
    - Self-integrity check
    - Adaptive sampling responsive to mode

    Hooks ที่ติดตั้ง (20):
    1.  Opcode (adaptive)
    2.  Global proxy
    3.  Function wrapper
    4.  Coroutine tracker
    5.  Network (HttpGet/Post/request)
    6.  File
    7.  String decrypt
    8.  Debug library
    9.  Metatable
    10. Environment
    11. Task scheduler
    12. Closure tracker
    13. Error handler
    14. Vector/CFrame
    15. Heartbeat monitor
    ============================================================
]]

local Hooks = {}

local nativeTask = {
    spawn = task and task.spawn,
    defer = task and task.defer,
    delay = task and task.delay,
    wait = task and task.wait,
    cancel = task and task.cancel,
}

--========== VERSION ==========--
Hooks._VERSION = "3.0.0"
Hooks.MODULE_VERSION = "3.0.0"
Hooks.VERSION = "3.0.0"

--========== CONFIG ==========--
Hooks.Config = {
    -- Rate limiting
    RATE_LIMIT_PER_SEC    = 100,
    RATE_LIMIT_WINDOW     = 1.0,

    -- Sampling
    ENABLE_ADAPTIVE       = true,
    BASE_SAMPLE_RATE      = 0.1,
    HIGH_RISK_SAMPLE_RATE = 1.0,
    RISK_HIGH_THRESHOLD   = 0.6,

    -- Buffer caps (v3.0)
    MAX_EVENTS_PER_SEC    = 500,   -- cap events emitted per sec
    MAX_PENDING           = 2000,  -- cap internal queue

    -- Bloom Filter
    BLOOM_SIZE            = 1 << 20,
    BLOOM_HASHES          = 4,

    -- Count-Min Sketch
    CMS_WIDTH             = 1024,
    CMS_DEPTH             = 4,

    -- HyperLogLog
    HLL_PRECISION         = 12,

    -- Storage
    STRING_LRU_SIZE       = 512,
    MAX_STACK_DEPTH       = 10,
    OPCODE_HOOK_COUNT     = 800,

    -- Kalman
    KALMAN_Q              = 0.01,
    KALMAN_R              = 0.1,

    -- CUSUM
    CUSUM_THRESHOLD       = 5.0,
    CUSUM_DRIFT           = 0.5,

    -- Hooks toggle
    HOOK_OPCODE           = true,
    HOOK_GLOBAL           = true,
    HOOK_FUNCTION         = true,
    HOOK_COROUTINE        = true,
    HOOK_NETWORK          = true,
    HOOK_FILE             = true,
    HOOK_STRING           = true,
    HOOK_DEBUG            = true,
    HOOK_METATABLE        = true,
    HOOK_ENV              = true,
    HOOK_TASK             = true,
    HOOK_CLOSURE          = true,
    HOOK_ERROR            = true,
    HOOK_VECTOR           = true,
    HOOK_HEARTBEAT        = true,

    -- Logging (v3.0)
    LOG_STRUCTURED        = false,
    LOG_LEVEL             = 1,

    -- Self integrity (v3.0)
    SELF_INTEGRITY        = true,
    INTEGRITY_INTERVAL    = 30,

    -- Current mode (จะถูก override โดย setPerformanceMode)
    PERFORMANCE_MODE      = "balanced",
}

--========== MODE PROFILES (v3.0) ==========--
local MODE_PROFILES = {
    light = {
        OPCODE_HOOK_COUNT     = 3000,
        BASE_SAMPLE_RATE      = 0.05,
        HIGH_RISK_SAMPLE_RATE = 0.5,
        RATE_LIMIT_PER_SEC    = 30,
        MAX_EVENTS_PER_SEC    = 100,
        BLOOM_SIZE            = 1 << 18,
        STRING_LRU_SIZE       = 128,
        MAX_STACK_DEPTH       = 5,
        HOOK_VECTOR           = false,
        HOOK_CLOSURE          = false,
        HOOK_HEARTBEAT        = true,
    },
    balanced = {
        OPCODE_HOOK_COUNT     = 800,
        BASE_SAMPLE_RATE      = 0.1,
        HIGH_RISK_SAMPLE_RATE = 1.0,
        RATE_LIMIT_PER_SEC    = 100,
        MAX_EVENTS_PER_SEC    = 500,
        BLOOM_SIZE            = 1 << 20,
        STRING_LRU_SIZE       = 512,
        MAX_STACK_DEPTH       = 10,
        HOOK_VECTOR           = true,
        HOOK_CLOSURE          = true,
        HOOK_HEARTBEAT        = true,
    },
    paranoid = {
        OPCODE_HOOK_COUNT     = 300,
        BASE_SAMPLE_RATE      = 0.3,
        HIGH_RISK_SAMPLE_RATE = 1.0,
        RATE_LIMIT_PER_SEC    = 300,
        MAX_EVENTS_PER_SEC    = 1500,
        BLOOM_SIZE            = 1 << 22,
        STRING_LRU_SIZE       = 2048,
        MAX_STACK_DEPTH       = 20,
        HOOK_VECTOR           = true,
        HOOK_CLOSURE          = true,
        HOOK_HEARTBEAT        = true,
    },
}

function Hooks.setPerformanceMode(mode)
    if not mode or not MODE_PROFILES[mode] then
        return false, "unknown mode: " .. tostring(mode)
    end

    local profile = MODE_PROFILES[mode]
    for k, v in pairs(profile) do
        Hooks.Config[k] = v
    end
    Hooks.Config.PERFORMANCE_MODE = mode

    local state = Hooks.State
    if state then
        for _, name in ipairs({ "vector", "closure" }) do
            if Hooks.Config["HOOK_" .. string.upper(name)] then
                state.disabledHooks[name] = nil
            end
        end
    end

    Hooks._log(1, "perf", "mode applied: " .. mode, profile)

    -- ถ้า restart แล้ว hooks บางตัวปิดอยู่ ให้ปิดจริง
    if not Hooks.Config.HOOK_VECTOR then
        Hooks._disableHook("vector")
    end
    if not Hooks.Config.HOOK_CLOSURE then
        Hooks._disableHook("closure")
    end

    return true
end

function Hooks.getPerformanceMode()
    return Hooks.Config.PERFORMANCE_MODE
end

--========== STATE ==========--
local State = {
    edr                 = nil,
    installed           = false,
    originals           = {},
    unhooks             = {},
    inHook              = false,
    stackDepth          = 0,
    rateLimiters        = {},
    lastStrings         = {},
    lastStringSet       = {},
    coroutineMap        = {},
    closureMap          = {},
    callStack           = {},
    callGraph           = {},
    bloom               = nil,
    cms                 = nil,
    hll                 = nil,
    kalmanTiming        = nil,
    cusumDetectors      = {},
    ngramCounts         = {},
    tfidfDocs           = 0,
    tfidfTerms          = {},
    stats               = {
        totalCalls     = 0,
        sampledCalls   = 0,
        droppedCalls   = 0,
        rateLimited    = 0,
        dedupedStrings = 0,
        uniqueStrings  = 0,
        bufferDropped  = 0,
    },
    currentSampleRate   = 0.1,
    eventsThisSec       = 0,
    lastSecReset        = 0,
    iforestPoints       = {},
    iforestTree         = nil,
    iforestLastBuild    = 0,
    taskMap             = {},
    taskCounter         = 0,
    heartbeatCounters   = {},
    disabledHooks       = {},
    integrityThread     = nil,
    baselineHashes      = {},
    integrityViolations = 0,
}

function Hooks._disableHook(name)
    State.disabledHooks[name] = true
    if State.unhooks[name] and type(State.unhooks[name]) == "function" then
        pcall(State.unhooks[name])
    end
end

--========== LOGGING ==========--
local function jsonEscape(s)
    s = tostring(s or "")
    s = s:gsub("\\", "\\\\"):gsub("\"", "\\\"")
        :gsub("\n", "\\n"):gsub("\r", "\\r"):gsub("\t", "\\t")
    return s
end

local function jsonEncode(t)
    if type(t) ~= "table" then
        if type(t) == "string" then
            return '"' .. jsonEscape(t) .. '"'
        elseif type(t) == "number" or type(t) == "boolean" then
            return tostring(t)
        else
            return "null"
        end
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

function Hooks._log(level, module, event, data)
    if level > Hooks.Config.LOG_LEVEL then return end
    if Hooks.Config.LOG_STRUCTURED then
        local entry = {
            ts = os.time(),
            level = level,
            module = "hooks." .. tostring(module),
            event = event,
        }
        if data then entry.data = data end
        print("[EDR] " .. jsonEncode(entry))
    else
        print(string.format("[HOOKS][%s] %s", tostring(module), tostring(event)))
    end
end

--========== BIT OPS ==========--
local band = bit32 and bit32.band or function(a, b)
    local r, bit = 0, 1
    while a > 0 and b > 0 do
        if a % 2 == 1 and b % 2 == 1 then r = r + bit end
        a, b, bit = math.floor(a / 2), math.floor(b / 2), bit * 2
    end
    return r
end

local bor = bit32 and bit32.bor or function(a, b)
    local r, bit = 0, 1
    while a > 0 or b > 0 do
        if a % 2 == 1 or b % 2 == 1 then r = r + bit end
        a, b, bit = math.floor(a / 2), math.floor(b / 2), bit * 2
    end
    return r
end

local bxor = bit32 and bit32.bxor or function(a, b)
    local r, bit = 0, 1
    while a > 0 or b > 0 do
        if a % 2 ~= b % 2 then r = r + bit end
        a, b, bit = math.floor(a / 2), math.floor(b / 2), bit * 2
    end
    return r
end

local function fnv1a(str, seed)
    local h = seed or 2166136261
    for i = 1, #str do
        h = bxor(h, str:byte(i))
        local lo = h % 65536
        local hi = math.floor(h / 65536)
        h = (lo * 16777619
            + ((hi * 16777619) % 65536) * 65536) % 0x100000000
    end
    return h
end

local HASH_SEEDS = { 2166136261, 2166136261 + 101, 2166136261 + 202, 2166136261 + 303 }
local function hashN(str, n) return fnv1a(str, HASH_SEEDS[n]) end

--========== DATA STRUCTURES ==========--
local Bloom = {}
Bloom.__index = Bloom

function Bloom.new(size, hashes)
    size = size or (1 << 20)
    return setmetatable({
        size = size, hashCount = hashes or 4, bits = {}, itemCount = 0,
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

local CMS = {}
CMS.__index = CMS

function CMS.new(width, depth)
    width = width or 1024
    depth = depth or 4
    local t = {}
    for i = 1, depth do
        t[i] = {}
        for j = 1, width do t[i][j] = 0 end
    end
    return setmetatable({ width = width, depth = depth, table = t, total = 0 }, CMS)
end

function CMS:increment(key, inc)
    inc = inc or 1
    for i = 1, self.depth do
        local idx = (hashN(tostring(key), i) % self.width) + 1
        self.table[i][idx] = self.table[i][idx] + inc
    end
    self.total = self.total + inc
end

function CMS:estimate(key)
    local min = math.huge
    for i = 1, self.depth do
        local idx = (hashN(tostring(key), i) % self.width) + 1
        if self.table[i][idx] < min then min = self.table[i][idx] end
    end
    return min
end

local HLL = {}
HLL.__index = HLL

function HLL.new(precision)
    precision = precision or 12
    local size = 1 << precision
    return setmetatable({
        precision = precision,
        size = size,
        buckets = {},
        alpha = 0.7213 / (1 + 1.079 / size),
    }, HLL)
end

local function countLeadingZeros(x)
    if x == 0 then return 32 end
    local c = 0
    for i = 31, 0, -1 do
        if band(x, 1 << i) ~= 0 then break end
        c = c + 1
    end
    return c
end

function HLL:add(item)
    local h = fnv1a(tostring(item))
    local idx = band(h, self.size - 1) + 1
    local w = band(h >> self.precision, 0xFFFFFFFF)
    local rho = countLeadingZeros(w) + 1
    if rho > (self.buckets[idx] or 0) then self.buckets[idx] = rho end
end

function HLL:count()
    local sum = 0
    for i = 1, self.size do sum = sum + 2 ^ -(self.buckets[i] or 0) end
    local est = self.alpha * self.size * self.size / sum
    if est <= 2.5 * self.size then
        local zeros = 0
        for i = 1, self.size do
            if (self.buckets[i] or 0) == 0 then zeros = zeros + 1 end
        end
        if zeros > 0 then est = self.size * math.log(self.size / zeros) end
    end
    return math.floor(est + 0.5)
end

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

local CUSUM = {}
CUSUM.__index = CUSUM

function CUSUM.new(threshold, drift)
    return setmetatable({
        threshold = threshold or 5.0,
        drift = drift or 0.5,
        sumPos = 0,
        sumNeg = 0,
        mean = 0,
        samples = 0,
        lastAlert = 0,
        alertCount = 0,
    }, CUSUM)
end

function CUSUM:update(value)
    self.samples = self.samples + 1
    self.mean = self.mean + (value - self.mean) / self.samples
    local dev = value - self.mean
    self.sumPos = math.max(0, self.sumPos + dev - self.drift)
    self.sumNeg = math.max(0, self.sumNeg - dev - self.drift)
    if self.sumPos > self.threshold then
        self.sumPos = 0; self.alertCount = self.alertCount + 1
        self.lastAlert = type(time) == "function" and time() or os.clock()
        return "up", dev
    elseif self.sumNeg > self.threshold then
        self.sumNeg = 0; self.alertCount = self.alertCount + 1
        self.lastAlert = type(time) == "function" and time() or os.clock()
        return "down", dev
    end
    return nil
end

--========== UTILITIES ==========--
local function now()
    if type(time) == "function" then return time() end
    return os.clock()
end

local function safeCall(fn, ...)
    local ok, result = pcall(fn, ...)
    if ok then return result end
    return nil
end

local function allowRate(key)
    local lim = State.rateLimiters[key]
    local t = now()
    if not lim or (t - lim.window_start) >= Hooks.Config.RATE_LIMIT_WINDOW then
        State.rateLimiters[key] = { window_start = t, count = 1 }
        return true
    end
    if lim.count < Hooks.Config.RATE_LIMIT_PER_SEC then
        lim.count = lim.count + 1
        return true
    end
    State.stats.rateLimited = State.stats.rateLimited + 1
    return false
end

-- Buffer cap check (v3.0)
local function checkBufferCap()
    local t = now()
    if t - State.lastSecReset >= 1 then
        State.eventsThisSec = 0
        State.lastSecReset = t
    end
    if State.eventsThisSec >= Hooks.Config.MAX_EVENTS_PER_SEC then
        State.stats.bufferDropped = State.stats.bufferDropped + 1
        return false
    end
    State.eventsThisSec = State.eventsThisSec + 1
    return true
end

local function shouldSample(key)
    if not Hooks.Config.ENABLE_ADAPTIVE then return true end
    local rate = State.currentSampleRate
    if rate >= 1.0 then return true end
    if not allowRate("sample:" .. key) then return false end
    if math.random() < rate then
        State.stats.sampledCalls = State.stats.sampledCalls + 1
        return true
    end
    State.stats.droppedCalls = State.stats.droppedCalls + 1
    return false
end

local function updateSampleRate(risk)
    if risk >= Hooks.Config.RISK_HIGH_THRESHOLD then
        State.currentSampleRate = Hooks.Config.HIGH_RISK_SAMPLE_RATE
    else
        local t = risk / Hooks.Config.RISK_HIGH_THRESHOLD
        State.currentSampleRate = Hooks.Config.BASE_SAMPLE_RATE
            + t * (Hooks.Config.HIGH_RISK_SAMPLE_RATE - Hooks.Config.BASE_SAMPLE_RATE)
    end
end

local function captureStack(depth)
    depth = depth or Hooks.Config.MAX_STACK_DEPTH
    local stack = {}
    local level = 2
    while level <= depth + 2 do
        local info = debug.getinfo(level, "nSl")
        if not info then break end
        stack[#stack + 1] = {
            name = info.name or "?",
            source = info.short_src or info.source or "?",
            line = info.currentline or 0,
            what = info.what or "?",
        }
        level = level + 1
    end
    return stack
end

local function emit(eventType, data, severity)
    if State.inHook then return end
    if not checkBufferCap() then return end

    State.inHook = true
    pcall(function()
        State.edr:emit(eventType, data, severity or 0)
    end)
    State.inHook = false
end

-- URL patterns
local SUSPICIOUS_URL_PATTERNS = {
    "discord.com/api/webhooks", "discordapp.com/api/webhooks",
    "api.telegram.org", "pastebin.com/raw",
    "%.tk/", "%.ml/", "%.ga/", "%.cf/", "%.gq/",
    "aHR0cHM6Ly",
}

local function isSuspiciousURL(url)
    if type(url) ~= "string" then return false, nil end
    local lower = url:lower()
    for _, p in ipairs(SUSPICIOUS_URL_PATTERNS) do
        if lower:find(p, 1, true) or lower:find(p) then return true, p end
    end
    if lower:match("https?://%d+%.%d+%.%d+%.%d+") then
        return true, "ipv4_direct"
    end
    return false, nil
end

local function stringEntropy(s)
    if not s or #s == 0 then return 0 end
    local freq = {}
    for i = 1, #s do
        local c = s:sub(i, i)
        freq[c] = (freq[c] or 0) + 1
    end
    local H = 0
    local len = #s
    for _, c in pairs(freq) do
        local p = c / len
        H = H - p * (math.log(p) / math.log(2))
    end
    return H
end

local function looksBase64(s)
    if type(s) ~= "string" or #s < 20 then return false end
    if #s % 4 ~= 0 then return false end
    return s:match("^[A-Za-z0-9+/=]+$") ~= nil
end

local function looksHex(s)
    if type(s) ~= "string" or #s < 16 then return false end
    return s:match("^[0-9a-fA-F]+$") ~= nil
end

local function rememberString(s)
    if not s or #s == 0 or #s > 5000 then return false end
    if State.bloom:contains(s) then
        State.stats.dedupedStrings = State.stats.dedupedStrings + 1
        return false
    end
    if State.lastStringSet[s] then
        State.stats.dedupedStrings = State.stats.dedupedStrings + 1
        return false
    end
    State.bloom:add(s)
    State.lastStringSet[s] = true
    table.insert(State.lastStrings, 1, s)
    State.stats.uniqueStrings = State.stats.uniqueStrings + 1
    if #State.lastStrings > Hooks.Config.STRING_LRU_SIZE then
        local old = table.remove(State.lastStrings)
        State.lastStringSet[old] = nil
    end
    return true
end

--========== 1. OPCODE HOOK ==========--
local function installOpcodeHook(edr)
    if not Hooks.Config.HOOK_OPCODE then return nil end
    if not debug or not debug.sethook then return nil end

    State.originals.sethook = debug.sethook
    local callCount = 0
    local lastEmit = 0

    local function hook(event, line)
        if State.inHook then return end
        callCount = State.stats.totalCalls + 1
        State.stats.totalCalls = callCount

        if callCount % Hooks.Config.OPCODE_HOOK_COUNT == 0 then
            if shouldSample("opcode") then
                local t = now()
                if t - lastEmit >= 0.5 then
                    lastEmit = t
                    emit("OPCODE_CALL", {
                        count = callCount,
                        sampled = State.stats.sampledCalls,
                        dropped = State.stats.droppedCalls,
                        rate = State.currentSampleRate,
                    }, 0)
                end
            end
        end

        if event == "call" then
            if not shouldSample("call_info") then return end
            local info = debug.getinfo(2, "nSl")
            if info then
                local key = (info.short_src or "?") .. ":" .. (info.name or "?")
                State.callGraph[key] = (State.callGraph[key] or 0) + 1
                emit("OPCODE_CALL", {
                    name = info.name,
                    source = info.short_src,
                    line = info.currentline,
                    depth = State.stackDepth,
                }, 0)
            end
        end
    end

    pcall(function() State.originals.sethook(hook, "crl", 0) end)

    return function()
        pcall(function() State.originals.sethook() end)
    end
end

--========== 2. GLOBAL PROXY ==========--
local function installGlobalProxy(edr)
    if not Hooks.Config.HOOK_GLOBAL then return nil end
    if not setmetatable or not getmetatable then return nil end

    local realG = (getgenv and getgenv()) or _G
    local cms = State.cms

    local proxy = setmetatable({}, {
        __index = function(t, k)
            local v = realG[k]
            if allowRate("global_read:" .. tostring(k)) then
                if not cms then return v end
                cms:increment("global:" .. tostring(k))
                if shouldSample("global_read") then
                    emit("GLOBAL_READ", {
                        key = tostring(k),
                        freq = cms:estimate("global:" .. tostring(k)),
                    }, 0)
                end
            end
            return v
        end,
        __newindex = function(t, k, v)
            local old = realG[k]
            realG[k] = v
            if allowRate("global_write:" .. tostring(k)) then
                if not cms then return end
                cms:increment("global_write:" .. tostring(k))
                if shouldSample("global_write") then
                    emit("GLOBAL_WRITE", {
                        key = tostring(k),
                        old_type = type(old),
                        new_type = type(v),
                        freq = cms:estimate("global_write:" .. tostring(k)),
                        stack = captureStack(4),
                    }, 1)
                end
            end
        end,
        __metatable = "locked",
    })

    if getgenv then
        State.originals.getgenv = getgenv
        getgenv = function() return proxy end
    end

    return function()
        if getgenv and State.originals.getgenv then
            getgenv = State.originals.getgenv
        end
    end
end

--========== 3. FUNCTION WRAPPER ==========--
local DANGEROUS_FUNCS = {
    { env = "loadstring", name = "loadstring", sev = 3 },
    { env = "load",       name = "load",       sev = 3 },
    { env = "dofile",     name = "dofile",     sev = 3 },
    { env = "loadfile",   name = "loadfile",   sev = 3 },
    { env = "require",    name = "require",    sev = 2 },
}

local function installFunctionWrappers(edr)
    if not Hooks.Config.HOOK_FUNCTION then return nil end
    local env = (getgenv and getgenv()) or _G
    local restored = {}

    for _, entry in ipairs(DANGEROUS_FUNCS) do
        local orig = env[entry.name]
        if type(orig) == "function" then
            State.originals[entry.name] = orig

            local wrapped = function(...)
                local args = { ... }
                local payload = type(args[1]) == "string" and args[1] or nil
                local ent = payload and stringEntropy(payload) or 0

                emit("FUNCTION_CALL", {
                    name = entry.name,
                    argc = select("#", ...),
                    entropy = ent,
                    size = payload and #payload or 0,
                    preview = payload and payload:sub(1, 200) or nil,
                    stack = captureStack(5),
                }, entry.sev)

                return orig(...)
            end

            if newcclosure then pcall(function() wrapped = newcclosure(wrapped) end) end
            env[entry.name] = wrapped
            restored[#restored + 1] = { env = env, name = entry.name, orig = orig }
        end
    end

    return function()
        for _, r in ipairs(restored) do
            pcall(function() r.env[r.name] = r.orig end)
        end
    end
end

--========== 4. COROUTINE TRACKER ==========--
local function installCoroutineTracker(edr)
    if not Hooks.Config.HOOK_COROUTINE then return nil end
    if not coroutine then return nil end

    local origCreate, origResume, origWrap =
        coroutine.create, coroutine.resume, coroutine.wrap
    State.originals.coroutine_create       = origCreate
    State.originals.coroutine_resume       = origResume
    State.originals.coroutine_wrap         = origWrap

    local coCounter, resumeCounter         = 0, 0
    local kalman                           = State.kalmanTiming

    coroutine.create                       = function(fn)
        coCounter = coCounter + 1
        local co = origCreate(fn)
        State.coroutineMap[co] = { id = coCounter, created_at = now(), stack = captureStack(4) }
        if allowRate("co_create") then
            emit("COROUTINE_CREATE", {
                id = coCounter,
                total = coCounter,
                stack = State.coroutineMap[co].stack,
            }, 0)
        end
        return co
    end

    local lastResume                       = now()
    coroutine.resume                       = function(co, ...)
        resumeCounter = resumeCounter + 1
        local t = now()
        local dt = t - lastResume
        lastResume = t
        local filtered = kalman and kalman:update(dt) or dt
        local meta = State.coroutineMap[co]
        if meta then meta.resumes = (meta.resumes or 0) + 1 end
        if allowRate("co_resume") then
            emit("COROUTINE_RESUME", {
                id = meta and meta.id or -1,
                total = resumeCounter,
                dt = dt,
                filteredDt = filtered,
            }, 0)
        end
        return origResume(co, ...)
    end

    coroutine.wrap                         = function(fn)
        coCounter = coCounter + 1
        local co = origWrap(fn)
        State.coroutineMap[co] = { id = coCounter, created_at = now(), wrapped = true }
        if allowRate("co_wrap") then
            emit("COROUTINE_CREATE", { id = coCounter, wrapped = true }, 0)
        end
        return co
    end

    if newcclosure then
        pcall(function()
            coroutine.create = newcclosure(coroutine.create)
            coroutine.resume = newcclosure(coroutine.resume)
            coroutine.wrap   = newcclosure(coroutine.wrap)
        end)
    end

    return function()
        coroutine.create = origCreate
        coroutine.resume = origResume
        coroutine.wrap   = origWrap
    end
end

--========== 5. NETWORK HOOK ==========--
local function installNetworkHooks(edr)
    if not Hooks.Config.HOOK_NETWORK then return nil end
    local env = (getgenv and getgenv()) or _G
    local restored = {}

    local function hookHttp(method, eventType)
        local ok, service = pcall(function() return game:GetService("HttpService") end)
        if not ok or not service then return end
        local orig = service[method]
        if type(orig) ~= "function" then return end
        State.originals["HttpService_" .. method] = orig

        local wrapped = function(self, url, ...)
            local suspicious, tag = isSuspiciousURL(url)
            emit(eventType, {
                url = tostring(url):sub(1, 500),
                suspicious = suspicious,
                tag = tag,
                stack = captureStack(5),
            }, suspicious and 3 or 1)
            return orig(self, url, ...)
        end

        if newcclosure then pcall(function() wrapped = newcclosure(wrapped) end) end
        service[method] = wrapped
        restored[#restored + 1] = { service = service, method = method, orig = orig }
    end

    hookHttp("Get", "HTTP_GET")
    hookHttp("Post", "HTTP_POST")

    if type(env.HttpGet) == "function" then
        local orig = env.HttpGet
        State.originals.HttpGet = orig
        local wrapped = function(url, ...)
            local suspicious, tag = isSuspiciousURL(url)
            emit("HTTP_GET", {
                url = tostring(url):sub(1, 500),
                suspicious = suspicious,
                tag = tag,
                source = "env.HttpGet",
                stack = captureStack(5),
            }, suspicious and 3 or 1)
            return orig(url, ...)
        end
        if newcclosure then pcall(function() wrapped = newcclosure(wrapped) end) end
        env.HttpGet = wrapped
        restored[#restored + 1] = { env = env, method = "HttpGet", orig = orig }
    end

    if type(env.request) == "function" then
        local orig = env.request
        State.originals.request = orig
        local wrapped = function(opts)
            local url = (opts and opts.Url) or "?"
            local method = (opts and opts.Method) or "GET"
            local suspicious, tag = isSuspiciousURL(url)
            emit("NETWORK_REQUEST", {
                url = tostring(url):sub(1, 500),
                method = method,
                suspicious = suspicious,
                tag = tag,
                source = "env.request",
                stack = captureStack(5),
            }, suspicious and 3 or 1)
            return orig(opts)
        end
        if newcclosure then pcall(function() wrapped = newcclosure(wrapped) end) end
        env.request = wrapped
        restored[#restored + 1] = { env = env, method = "request", orig = orig }
    end

    return function()
        for _, r in ipairs(restored) do
            pcall(function()
                if r.service then
                    r.service[r.method] = r.orig
                elseif r.env then
                    r.env[r.method] = r.orig
                end
            end)
        end
    end
end

--========== 6. FILE HOOK ==========--
local FILE_FUNCS = {
    { name = "readfile",   eventType = "FILE_READ",  sev = 1 },
    { name = "writefile",  eventType = "FILE_WRITE", sev = 1 },
    { name = "appendfile", eventType = "FILE_WRITE", sev = 1 },
    { name = "delfile",    eventType = "FILE_WRITE", sev = 2 },
    { name = "listfiles",  eventType = "FILE_READ",  sev = 0 },
    { name = "isfile",     eventType = "FILE_READ",  sev = 0 },
    { name = "makefolder", eventType = "FILE_WRITE", sev = 1 },
    { name = "delfolder",  eventType = "FILE_WRITE", sev = 2 },
}

local SENSITIVE_FILE_PATTERNS = {
    "token", "cookie", "session", "password", "credential",
    ".env", "auth", "secret", "key", "wallet", "seed",
}

local function installFileHooks(edr)
    if not Hooks.Config.HOOK_FILE then return nil end
    local env = (getgenv and getgenv()) or _G
    local restored = {}

    for _, entry in ipairs(FILE_FUNCS) do
        local orig = env[entry.name]
        if type(orig) == "function" then
            State.originals[entry.name] = orig
            local wrapped = function(path, ...)
                local sensitive = false
                if type(path) == "string" then
                    local lower = path:lower()
                    for _, pat in ipairs(SENSITIVE_FILE_PATTERNS) do
                        if lower:find(pat, 1, true) then
                            sensitive = true; break
                        end
                    end
                end
                local sev = entry.sev
                if sensitive then sev = math.max(sev, 3) end
                emit(entry.eventType, {
                    path = tostring(path):sub(1, 300),
                    sensitive = sensitive,
                    func = entry.name,
                    stack = captureStack(5),
                }, sev)
                return orig(path, ...)
            end
            if newcclosure then pcall(function() wrapped = newcclosure(wrapped) end) end
            env[entry.name] = wrapped
            restored[#restored + 1] = { name = entry.name, orig = orig }
        end
    end

    return function()
        for _, r in ipairs(restored) do
            pcall(function() env[r.name] = r.orig end)
        end
    end
end

--========== 7. STRING DECRYPT ==========--
local function installStringDecryptHook(edr)
    if not Hooks.Config.HOOK_STRING then return nil end
    if not string then return nil end

    local origChar = string.char
    if type(origChar) == "function" then
        State.originals.string_char = origChar
        local wrapped = function(...)
            local n = select("#", ...)
            local result = origChar(...)
            if n >= 5 and type(result) == "string"
                and result:match("^[%w%s%p]+$") and #result >= 5
                and rememberString(result)
            then
                if allowRate("string_char") and shouldSample("string_char") then
                    local suspicious, tag = isSuspiciousURL(result)
                    local ent = stringEntropy(result)
                    emit("STRING_DECRYPT", {
                        value = result:sub(1, 200),
                        length = #result,
                        entropy = ent,
                        b64 = looksBase64(result),
                        hex = looksHex(result),
                        suspicious = suspicious,
                        tag = tag,
                        source = "string.char",
                    }, suspicious and 3 or 1)
                end
            end
            return result
        end
        if newcclosure then pcall(function() string.char = newcclosure(string.char) end) end
        string.char = wrapped
    end

    local origGsub = string.gsub
    if type(origGsub) == "function" then
        State.originals.string_gsub = origGsub
        local wrapped = function(s, pattern, repl, n)
            local result = origGsub(s, pattern, repl, n)
            if type(result) == "string" and #result > 20 then
                if rememberString(result) then
                    local suspicious, tag = isSuspiciousURL(result)
                    if suspicious or looksBase64(result) then
                        emit("STRING_DECRYPT", {
                            value = result:sub(1, 200),
                            suspicious = suspicious,
                            tag = tag,
                            b64 = looksBase64(result),
                            source = "string.gsub",
                        }, suspicious and 3 or 1)
                    end
                end
            end
            return result
        end
        if newcclosure then pcall(function() string.gsub = newcclosure(string.gsub) end) end
        string.gsub = wrapped
    end

    if bit32 and type(bit32.bxor) == "function" then
        local origBxor = bit32.bxor
        State.originals.bit32_bxor = origBxor
        local cusum = CUSUM.new(Hooks.Config.CUSUM_THRESHOLD, Hooks.Config.CUSUM_DRIFT)
        State.cusumBxor = cusum
        local counter = 0
        local lastFlush = now()

        local wrapped = function(...)
            counter = counter + 1
            local t = now()
            if t - lastFlush >= 1 then
                local signal, dev = cusum:update(counter)
                if signal == "up" and counter >= 100 then
                    if allowRate("bxor_burst") then
                        emit("STRING_DECRYPT", {
                            count = counter,
                            source = "bit32.bxor",
                            cusum = dev,
                            stack = captureStack(4),
                        }, 1)
                    end
                end
                counter = 0
                lastFlush = t
            end
            return origBxor(...)
        end
        if newcclosure then pcall(function() bit32.bxor = newcclosure(bit32.bxor) end) end
        bit32.bxor = wrapped
    end

    return function()
        if State.originals.string_char then string.char = State.originals.string_char end
        if State.originals.string_gsub then string.gsub = State.originals.string_gsub end
        if bit32 and State.originals.bit32_bxor then bit32.bxor = State.originals.bit32_bxor end
    end
end

--========== 8. DEBUG MONITOR ==========--
local DEBUG_FUNCS = {
    "getinfo", "getlocal", "setupvalue", "setlocal",
    "sethook", "gethook", "traceback", "getregistry",
    "getupvalue", "getmetatable", "setmetatable",
    "getfenv", "setfenv", "getuservalue",
}

local function installDebugMonitor(edr)
    if not Hooks.Config.HOOK_DEBUG then return nil end
    if not debug then return nil end
    local restored = {}

    for _, name in ipairs(DEBUG_FUNCS) do
        local orig = debug[name]
        if type(orig) == "function" then
            State.originals["debug_" .. name] = orig
            local wrapped = function(...)
                if shouldSample("debug_" .. name) then
                    emit("DEBUG_ACCESS", { name = name, stack = captureStack(5) }, 1)
                end
                return orig(...)
            end
            if newcclosure then pcall(function() wrapped = newcclosure(wrapped) end) end
            debug[name] = wrapped
            restored[#restored + 1] = { name = name, orig = orig }
        end
    end

    return function()
        for _, r in ipairs(restored) do
            pcall(function() debug[r.name] = r.orig end)
        end
    end
end

--========== 9. METATABLE HOOK ==========--
local function installMetatableHook(edr)
    if not Hooks.Config.HOOK_METATABLE then return nil end
    if not setmetatable then return nil end

    local origSetMeta = setmetatable
    local origGetRaw = getrawmetatable
    State.originals.setmetatable = origSetMeta
    if origGetRaw then State.originals.getrawmetatable = origGetRaw end

    local wrappedSet = function(t, mt)
        if type(t) == "table" and type(mt) == "table" then
            local keys = {}
            for k in pairs(mt) do keys[#keys + 1] = tostring(k) end
            if allowRate("setmetatable") and shouldSample("setmetatable") then
                emit("METATABLE_ACCESS", {
                    op = "set",
                    keys = table.concat(keys, ","):sub(1, 100),
                    stack = captureStack(4),
                }, 1)
            end
        end
        return origSetMeta(t, mt)
    end
    if newcclosure then pcall(function() wrappedSet = newcclosure(wrappedSet) end) end
    setmetatable = wrappedSet

    if getrawmetatable then
        local wrappedGet = function(t)
            if allowRate("getrawmetatable") and shouldSample("getraw") then
                emit("METATABLE_ACCESS", { op = "getraw", stack = captureStack(4) }, 1)
            end
            return origGetRaw(t)
        end
        if newcclosure then pcall(function() wrappedGet = newcclosure(wrappedGet) end) end
        getrawmetatable = wrappedGet
    end

    return function()
        setmetatable = origSetMeta
        if origGetRaw then getrawmetatable = origGetRaw end
    end
end

--========== 10. ENVIRONMENT HOOK ==========--
local function installEnvironmentHook(edr)
    if not Hooks.Config.HOOK_ENV then return nil end
    local env = (getgenv and getgenv()) or _G
    local restored = {}

    if type(getfenv) == "function" then
        local orig = getfenv
        State.originals.getfenv = orig
        getfenv = function(...)
            if allowRate("getfenv") and shouldSample("getfenv") then
                emit("ENV_ACCESS", { op = "get", stack = captureStack(4) }, 0)
            end
            return orig(...)
        end
        if newcclosure then pcall(function() getfenv = newcclosure(getfenv) end) end
        restored[#restored + 1] = { name = "getfenv", orig = orig }
    end

    if type(setfenv) == "function" then
        local orig = setfenv
        State.originals.setfenv = orig
        setfenv = function(...)
            emit("ENV_ACCESS", { op = "set", stack = captureStack(4) }, 2)
            return orig(...)
        end
        if newcclosure then pcall(function() setfenv = newcclosure(setfenv) end) end
        restored[#restored + 1] = { name = "setfenv", orig = orig }
    end

    if type(env.setthreadidentity) == "function" then
        local orig = env.setthreadidentity
        State.originals.setthreadidentity = orig
        env.setthreadidentity = function(id)
            emit("THREAD_IDENTITY", {
                op = "set", id = id, stack = captureStack(4),
            }, 2)
            return orig(id)
        end
        restored[#restored + 1] = { env = env, name = "setthreadidentity", orig = orig }
    end

    if type(env.getthreadidentity) == "function" then
        local orig = env.getthreadidentity
        State.originals.getthreadidentity = orig
        env.getthreadidentity = function()
            local id = orig()
            emit("THREAD_IDENTITY", { op = "get", id = id }, 0)
            return id
        end
        restored[#restored + 1] = { env = env, name = "getthreadidentity", orig = orig }
    end

    return function()
        for _, r in ipairs(restored) do
            pcall(function()
                if r.env then r.env[r.name] = r.orig else _G[r.name] = r.orig end
            end)
        end
    end
end

--========== 11. TASK SCHEDULER ==========--
local function installTaskHook(edr)
    if not Hooks.Config.HOOK_TASK then return nil end
    if not task then return nil end
    local restored = {}

    for _, name in ipairs({ "spawn", "defer", "delay", "wait" }) do
        local orig = task[name]
        if type(orig) == "function" then
            State.originals["task_" .. name] = orig
            local wrapped = function(fn, ...)
                State.taskCounter = State.taskCounter + 1
                local id = State.taskCounter
                if allowRate("task_" .. name) and shouldSample("task_" .. name) then
                    emit("TASK_SCHEDULED", {
                        type = name,
                        id = id,
                        total = id,
                        stack = captureStack(4),
                    }, 0)
                end
                return orig(fn, ...)
            end
            if newcclosure then pcall(function() wrapped = newcclosure(wrapped) end) end
            task[name] = wrapped
            restored[#restored + 1] = { name = name, orig = orig }
        end
    end

    return function()
        for _, r in ipairs(restored) do
            pcall(function() task[r.name] = r.orig end)
        end
    end
end

--========== 12. CLOSURE TRACKER ==========--
local function installClosureHook(edr)
    -- Luau does not expose a safe way to enumerate another script's closures.
    -- Do not report the monitor's own coroutine as target-script activity.
    return nil
end

--========== 14. VECTOR MONITOR ==========--
local function installVectorHook(edr)
    if not Hooks.Config.HOOK_VECTOR then return nil end

    local thread = nativeTask.spawn(function()
        while State.installed do
            nativeTask.wait(2)
            local rate = edr:getRate("OPCODE_CALL", 5)
            local sampledRatio = State.stats.totalCalls > 0
                and (State.stats.sampledCalls / State.stats.totalCalls) or 0
            local point = { rate, sampledRatio, State.currentSampleRate }

            if rate > 500 or sampledRatio > 0.9 then
                emit("ANOMALY", {
                    metric = "vector_rate",
                    features = point,
                }, 2)
            end
        end
    end)

    return function()
        pcall(function() nativeTask.cancel(thread) end)
    end
end

--========== 15. HEARTBEAT MONITOR ==========--
local function installHeartbeatMonitor(edr)
    if not Hooks.Config.HOOK_HEARTBEAT then return nil end

    local RunService = game:GetService("RunService")
    if not RunService then return nil end

    local counters = { Heartbeat = 0, RenderStepped = 0, Stepped = 0 }
    local conns = {}

    for name in pairs(counters) do
        local signal = RunService[name]
        if signal and signal.Connect then
            local conn = signal:Connect(function(dt)
                counters[name] = counters[name] + 1
            end)
            conns[#conns + 1] = conn
        end
    end

    local thread = nativeTask.spawn(function()
        local kalman = Kalman.new(0.001, 0.1, 60)
        while State.installed do
            nativeTask.wait(10)
            for name, count in pairs(counters) do
                local fps = count / 10
                counters[name] = 0
                if name == "Heartbeat" then
                    local filtered = kalman:update(fps)
                    if fps < filtered * 0.5 and fps > 0 then
                        emit("ANOMALY", {
                            metric = "fps_drop", fps = fps, filtered = filtered,
                        }, 1)
                    end
                end
            end
        end
    end)

    return function()
        for _, c in ipairs(conns) do pcall(function() c:Disconnect() end) end
        pcall(function() nativeTask.cancel(thread) end)
    end
end

--========== SELF INTEGRITY (v3.0) ==========--
local function startSelfIntegrity()
    if not Hooks.Config.SELF_INTEGRITY then return end
    if State.integrityThread then return end

    -- Baseline
    local watched = {
        { name = "pcall",        fn = pcall },
        { name = "tostring",     fn = tostring },
        { name = "setmetatable", fn = setmetatable },
        { name = "rawget",       fn = rawget },
        { name = "type",         fn = type },
    }
    for _, w in ipairs(watched) do
        State.baselineHashes[w.name] = tostring((_G and _G[w.name]) or w.fn)
    end

    State.integrityThread = nativeTask.spawn(function()
        while State.installed do
            nativeTask.wait(Hooks.Config.INTEGRITY_INTERVAL)
            for _, w in ipairs(watched) do
                local cur = tostring((_G and _G[w.name]) or w.fn)
                if cur ~= State.baselineHashes[w.name] then
                    State.integrityViolations = State.integrityViolations + 1
                    Hooks._log(1, "integrity", "tamper: " .. w.name)
                    emit("ANOMALY", {
                        metric = "integrity_violation",
                        fn = w.name,
                    }, 4)
                    State.baselineHashes[w.name] = cur
                end
            end
        end
    end)
end

--========== INSTALL ==========--
function Hooks.install(edr)
    if State.installed then return false, "already installed" end
    State.edr = edr

    State.bloom = Bloom.new(Hooks.Config.BLOOM_SIZE, Hooks.Config.BLOOM_HASHES)
    State.cms = CMS.new(Hooks.Config.CMS_WIDTH, Hooks.Config.CMS_DEPTH)
    State.hll = HLL.new(Hooks.Config.HLL_PRECISION)
    State.kalmanTiming = Kalman.new(Hooks.Config.KALMAN_Q, Hooks.Config.KALMAN_R, 0.1)
    State.cusumDetectors = {}
    State.ngramCounts = {}

    State.installed = true
    local unhooks = {}

    local function try(name, fn)
        if State.disabledHooks[name] then return end
        local ok, result = pcall(fn, edr)
        if ok and result then
            unhooks[name] = result
            if edr.registerHook then
                edr:registerHook("hooks." .. name, result)
            end
        end
    end

    try("opcode", installOpcodeHook)
    try("global", installGlobalProxy)
    try("functions", installFunctionWrappers)
    try("coroutine", installCoroutineTracker)
    try("network", installNetworkHooks)
    try("file", installFileHooks)
    try("string", installStringDecryptHook)
    try("debug", installDebugMonitor)
    try("metatable", installMetatableHook)
    try("environment", installEnvironmentHook)
    try("task", installTaskHook)
    try("closure", installClosureHook)
    try("vector", installVectorHook)
    try("heartbeat", installHeartbeatMonitor)

    State.unhooks = unhooks

    startSelfIntegrity()

    local installedCount = 0
    for _ in pairs(unhooks) do installedCount = installedCount + 1 end
    Hooks._log(1, "install", "hooks installed", { count = installedCount })
    return true, installedCount
end

function Hooks.uninstall()
    if not State.installed then return end
    State.installed = false

    for _, fn in pairs(State.unhooks or {}) do
        pcall(fn)
    end
    State.unhooks = {}

    if State.integrityThread then
        pcall(function() nativeTask.cancel(State.integrityThread) end)
        State.integrityThread = nil
    end

    Hooks._log(1, "uninstall", "hooks removed")
end

function Hooks.isInstalled()
    return State.installed
end

function Hooks.getVersion()
    return Hooks._VERSION
end

--========== STATS ==========--
function Hooks.getStats()
    return {
        installed = State.installed,
        version = Hooks._VERSION,
        mode = Hooks.Config.PERFORMANCE_MODE,
        totalCalls = State.stats.totalCalls,
        sampledCalls = State.stats.sampledCalls,
        droppedCalls = State.stats.droppedCalls,
        rateLimited = State.stats.rateLimited,
        bufferDropped = State.stats.bufferDropped,
        dedupedStrings = State.stats.dedupedStrings,
        uniqueStrings = State.stats.uniqueStrings,
        sampleRate = State.currentSampleRate,
        bloomItems = State.bloom and State.bloom.itemCount or 0,
        hllCount = State.hll and State.hll:count() or 0,
        callGraphNodes = (function()
            local n = 0
            for _ in pairs(State.callGraph) do n = n + 1 end
            return n
        end)(),
        integrityViolations = State.integrityViolations,
    }
end

--========== EXPORT ==========--
Hooks.updateSampleRate = updateSampleRate
Hooks.isSuspiciousURL = isSuspiciousURL
Hooks.stringEntropy = stringEntropy
Hooks.looksBase64 = looksBase64
Hooks.looksHex = looksHex
Hooks.captureStack = captureStack

Hooks.Bloom = Bloom
Hooks.CMS = CMS
Hooks.HLL = HLL
Hooks.Kalman = Kalman
Hooks.CUSUM = CUSUM
Hooks.State = State
Hooks.MODE_PROFILES = MODE_PROFILES

return Hooks
