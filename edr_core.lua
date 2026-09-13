--[[
    ============================================================
    EDR Core v3.0 — Advanced Detection Kernel (Version-Aware)
    ============================================================
    NEW in v3.0:
    - MODULE_VERSION = "3.0.0"
    - setPerformanceMode(mode) — light/balanced/paranoid
    - Buffer caps enforcement
    - Structured JSON logging
    - Self-integrity check
    - Consistent pcall + degrade
    - Stats aggregation
    - Mode-aware engines

    Features (จาก v2.0):
    - Event pooling (GC pressure ต่ำ)
    - Power-of-2 RingBuffer
    - Time-Series Aggregator (P50/P90/P99, EMA)
    - Markov Chain Detector
    - Sliding Entropy Tracker
    - Taint Tracker (sensitive → sink)
    - Bayesian Risk Engine
    - Advanced Pattern Matcher
    - Alert Dedup + Priority Queue
    - Adaptive Thresholds
    ============================================================
]]

local EDR = {}

--========== VERSION ==========--
EDR._VERSION = "3.0.0"
EDR.MODULE_VERSION = "3.0.0"
EDR.VERSION = "3.0.0"

--========== CONFIG ==========--
EDR.Config = {
    -- Ring buffer
    MAX_EVENTS              = 262144,
    DROPPED_SAMPLE_LIMIT    = 100,
    -- Time
    WINDOW_SEC              = 30,
    WATCHDOG_INTERVAL       = 3,
    CORRELATION_INTERVAL    = 5,
    STATS_INTERVAL          = 2,
    -- Detection engines
    ENABLE_CORRELATION      = true,
    ENABLE_MARKOV           = true,
    ENABLE_TAINT            = true,
    ENABLE_BAYESIAN         = true,
    ENABLE_ENTROPY          = true,
    ENABLE_ANOMALY          = true,
    ENABLE_TIMESERIES       = true,
    -- Learning
    BASELINE_DURATION       = 30,
    ADAPTIVE_THRESHOLDS     = true,
    -- Integrity
    SELF_INTEGRITY          = true,
    INTEGRITY_INTERVAL      = 10,
    -- Logging
    LOG_LEVEL               = 1,
    LOG_STRUCTURED          = false,
    -- Dedup
    ALERT_DEDUP_WINDOW      = 30,
    ALERT_DEDUP_MAX         = 500,
    -- Priority
    MAX_ALERTS              = 5000,
    MAX_EVENT_BUFFER        = 200000,
    -- v3.0
    PERFORMANCE_MODE        = "balanced",
    MAX_EMIT_RATE_PER_SEC   = 1000,
    BUFFER_SAMPLE_INTERVAL  = 5,
}

--========== MODE PROFILES (v3.0) ==========--
local MODE_PROFILES = {
    light = {
        MAX_EVENTS              = 65536,
        MAX_EVENT_BUFFER        = 50000,
        WINDOW_SEC              = 20,
        WATCHDOG_INTERVAL       = 6,
        ENABLE_MARKOV           = false,
        ENABLE_TAINT            = false,
        ENABLE_BAYESIAN         = true,
        ENABLE_ENTROPY          = false,
        ENABLE_ANOMALY          = true,
        ENABLE_TIMESERIES       = false,
        ENABLE_CORRELATION      = true,
        MAX_EMIT_RATE_PER_SEC   = 200,
        INTEGRITY_INTERVAL      = 60,
    },
    balanced = {
        MAX_EVENTS              = 262144,
        MAX_EVENT_BUFFER        = 200000,
        WINDOW_SEC              = 30,
        WATCHDOG_INTERVAL       = 3,
        ENABLE_MARKOV           = true,
        ENABLE_TAINT            = true,
        ENABLE_BAYESIAN         = true,
        ENABLE_ENTROPY          = true,
        ENABLE_ANOMALY          = true,
        ENABLE_TIMESERIES       = true,
        ENABLE_CORRELATION      = true,
        MAX_EMIT_RATE_PER_SEC   = 1000,
        INTEGRITY_INTERVAL      = 10,
    },
    paranoid = {
        MAX_EVENTS              = 1048576,
        MAX_EVENT_BUFFER        = 500000,
        WINDOW_SEC              = 45,
        WATCHDOG_INTERVAL       = 2,
        ENABLE_MARKOV           = true,
        ENABLE_TAINT            = true,
        ENABLE_BAYESIAN         = true,
        ENABLE_ENTROPY          = true,
        ENABLE_ANOMALY          = true,
        ENABLE_TIMESERIES       = true,
        ENABLE_CORRELATION      = true,
        MAX_EMIT_RATE_PER_SEC   = 5000,
        INTEGRITY_INTERVAL      = 5,
    },
}

function EDR.setPerformanceMode(mode)
    if not mode or not MODE_PROFILES[mode] then
        return false, "unknown mode: " .. tostring(mode)
    end
    local profile = MODE_PROFILES[mode]
    for k, v in pairs(profile) do
        EDR.Config[k] = v
    end
    EDR.Config.PERFORMANCE_MODE = mode

    -- Apply to active instance
    if EDR._instance then
        EDR._instance:_applyMode(mode)
    end

    EDR._log(1, "perf", "mode applied: " .. mode, profile)
    return true
end

function EDR.getPerformanceMode()
    return EDR.Config.PERFORMANCE_MODE
end

function EDR.getVersion()
    return EDR._VERSION
end

--========== EVENT TYPES ==========--
EDR.EventType = {
    OPCODE_CALL        = "OPCODE_CALL",
    OPCODE_RET         = "OPCODE_RET",
    OPCODE_LINE        = "OPCODE_LINE",
    FUNCTION_CALL      = "FUNCTION_CALL",
    FUNCTION_REDEFINE  = "FUNCTION_REDEFINE",
    GLOBAL_READ        = "GLOBAL_READ",
    GLOBAL_WRITE       = "GLOBAL_WRITE",
    ENV_ACCESS         = "ENV_ACCESS",
    METATABLE_ACCESS   = "METATABLE_ACCESS",
    STRING_DECRYPT     = "STRING_DECRYPT",
    STRING_ENCODE      = "STRING_ENCODE",
    COROUTINE_CREATE   = "COROUTINE_CREATE",
    COROUTINE_RESUME   = "COROUTINE_RESUME",
    FILE_READ          = "FILE_READ",
    FILE_WRITE         = "FILE_WRITE",
    NETWORK_REQUEST    = "NETWORK_REQUEST",
    NETWORK_RESPONSE   = "NETWORK_RESPONSE",
    HTTP_GET           = "HTTP_GET",
    HTTP_POST          = "HTTP_POST",
    DEBUG_ACCESS       = "DEBUG_ACCESS",
    THREAD_IDENTITY    = "THREAD_IDENTITY",
    SUSPICIOUS_API     = "SUSPICIOUS_API",
    ANOMALY            = "ANOMALY",
    HEARTBEAT          = "HEARTBEAT",
    ALERT              = "ALERT",
    TASK_SCHEDULED     = "TASK_SCHEDULED",
    TAINT_FLOW         = "TAINT_FLOW",
    RBX_SERVICE_ACCESS   = "RBX_SERVICE_ACCESS",
    RBX_INSTANCE_CREATE  = "RBX_INSTANCE_CREATE",
    RBX_INSTANCE_DESTROY = "RBX_INSTANCE_DESTROY",
    RBX_PROPERTY_WRITE   = "RBX_PROPERTY_WRITE",
    RBX_REMOTE_FIRE      = "RBX_REMOTE_FIRE",
    RBX_REMOTE_FOUND     = "RBX_REMOTE_FOUND",
    RBX_CHARACTER_CHANGE = "RBX_CHARACTER_CHANGE",
    RBX_WORKSPACE_WRITE  = "RBX_WORKSPACE_WRITE",
    VULN_FINDING         = "VULN_FINDING",
    VULN_SCAN_COMPLETE   = "VULN_SCAN_COMPLETE",
}

EDR.Severity = {
    INFO = 0, LOW = 1, MEDIUM = 2, HIGH = 3, CRITICAL = 4,
}

--========== LOGGING (v3.0) ==========--
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

function EDR._log(level, module, event, data)
    if level > EDR.Config.LOG_LEVEL then return end
    if EDR.Config.LOG_STRUCTURED then
        local entry = {
            ts = os.time(), level = level,
            module = "core." .. tostring(module),
            event = event,
        }
        if data then entry.data = data end
        print("[EDR] " .. jsonEncode(entry))
    else
        print(string.format("[CORE][%s] %s", tostring(module), tostring(event)))
    end
end

--========== POWER-OF-2 HELPERS ==========--
local function nextPow2(n)
    local p = 1
    while p < n do p = p * 2 end
    return p
end

local function log2(n)
    local r = 0
    while n > 1 do n = n / 2; r = r + 1 end
    return r
end

--========== EVENT POOL ==========--
local EventPool = {}
EventPool.__index = EventPool

function EventPool.new(maxPool)
    return setmetatable({
        pool = {}, maxPool = maxPool or 2000,
        active = 0, reused = 0, created = 0,
    }, EventPool)
end

function EventPool:acquire()
    local n = #self.pool
    if n > 0 then
        local ev = self.pool[n]
        self.pool[n] = nil
        self.reused = self.reused + 1
        return ev
    end
    self.created = self.created + 1
    return {}
end

function EventPool:release(ev)
    if not ev then return end
    ev.type, ev.data, ev.severity = nil, nil, nil
    ev.t, ev.wall, ev.seq, ev.phase = nil, nil, nil, nil
    ev.fp = nil
    if #self.pool < self.maxPool then
        table.insert(self.pool, ev)
    end
end

function EventPool:stats()
    return {
        active = self.active, pooled = #self.pool,
        reused = self.reused, created = self.created,
    }
end

--========== RING BUFFER ==========--
local RingBuffer = {}
RingBuffer.__index = RingBuffer

function RingBuffer.new(size)
    local p2 = nextPow2(size)
    return setmetatable({
        size = p2, mask = p2 - 1, bits = log2(p2),
        data = {}, head = 0, tail = 0, count = 0,
        dropped = 0, overwritten = 0,
    }, RingBuffer)
end

function RingBuffer:push(item)
    local tail = self.tail + 1
    local idx = tail % self.size
    if self.count >= self.size then
        self.head = (self.head + 1) % self.size
        self.dropped = self.dropped + 1
        self.overwritten = self.overwritten + 1
    else
        self.count = self.count + 1
    end
    self.data[idx] = item
    self.tail = tail
end

function RingBuffer:iter()
    local i = self.head
    local n = 0
    local data = self.data
    local size = self.size
    local count = self.count
    return function()
        if n >= count then return nil end
        local item = data[i]
        i = (i + 1) % size
        n = n + 1
        return item
    end
end

function RingBuffer:snapshot(limit)
    local out = {}
    local n = 0
    for item in self:iter() do
        n = n + 1
        out[n] = item
        if limit and n >= limit then break end
    end
    return out
end

function RingBuffer:recent(windowSec, nowClock)
    nowClock = nowClock or os.clock()
    local cutoff = nowClock - windowSec
    local out = {}
    local n = 0
    for item in self:iter() do
        if item.t and item.t >= cutoff then
            n = n + 1
            out[n] = item
        end
    end
    return out
end

function RingBuffer:clear()
    self.data = {}
    self.head, self.tail, self.count = 0, 0, 0
    self.dropped, self.overwritten = 0, 0
end

--========== EVENT BUS ==========--
local EventBus = {}
EventBus.__index = EventBus

function EventBus.new()
    return setmetatable({
        subscribers = {}, global = {}, stats = {}, maxGlobal = 10,
    }, EventBus)
end

function EventBus:subscribe(eventType, callback, filter)
    if not self.subscribers[eventType] then
        self.subscribers[eventType] = {}
    end
    table.insert(self.subscribers[eventType], {
        fn = callback, filter = filter or nil,
    })
end

function EventBus:subscribeAll(callback)
    if #self.global < self.maxGlobal then
        table.insert(self.global, callback)
    end
end

function EventBus:publish(event)
    self.stats[event.type] = (self.stats[event.type] or 0) + 1
    local globals = self.global
    for i = 1, #globals do
        pcall(globals[i], event)
    end
    local subs = self.subscribers[event.type]
    if subs then
        for i = 1, #subs do
            local sub = subs[i]
            if not sub.filter or sub.filter(event) then
                pcall(sub.fn, event)
            end
        end
    end
end

--========== STATS ==========--
local Stats = {}

function Stats.mean(t, n)
    n = n or #t
    if n == 0 then return 0 end
    local s = 0
    for i = 1, n do s = s + t[i] end
    return s / n
end

function Stats.stdev(t, n)
    n = n or #t
    if n < 2 then return 0 end
    local m = Stats.mean(t, n)
    local s = 0
    for i = 1, n do
        local d = t[i] - m
        s = s + d * d
    end
    return math.sqrt(s / (n - 1))
end

function Stats.median(t, n)
    n = n or #t
    if n == 0 then return 0 end
    local sorted = {}
    for i = 1, n do sorted[i] = t[i] end
    table.sort(sorted)
    if n % 2 == 1 then return sorted[(n + 1) // 2]
    else return (sorted[n // 2] + sorted[n // 2 + 1]) / 2 end
end

function Stats.percentile(t, p, n)
    n = n or #t
    if n == 0 then return 0 end
    local sorted = {}
    for i = 1, n do sorted[i] = t[i] end
    table.sort(sorted)
    local idx = math.ceil(p * n)
    if idx < 1 then idx = 1 end
    if idx > n then idx = n end
    return sorted[idx]
end

function Stats.mad(t, n)
    n = n or #t
    if n == 0 then return 0 end
    local m = Stats.median(t, n)
    local dev = {}
    for i = 1, n do dev[i] = math.abs(t[i] - m) end
    return Stats.median(dev, n)
end

function Stats.zscore(v, mean, sd)
    if sd == 0 then return 0 end
    return (v - mean) / sd
end

function Stats.modifiedZscore(v, med, mad)
    if mad == 0 then return 0 end
    return 0.6745 * (v - med) / mad
end

function Stats.ewma(values, alpha, n)
    n = n or #values
    alpha = alpha or 0.3
    if n == 0 then return 0 end
    local s = values[1]
    for i = 2, n do
        s = alpha * values[i] + (1 - alpha) * s
    end
    return s
end

function Stats.entropy(s)
    if type(s) ~= "string" or #s == 0 then return 0 end
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

function Stats.ksStatistic(t1, t2)
    if #t1 == 0 or #t2 == 0 then return 0 end
    local s1, s2 = {}, {}
    for i = 1, #t1 do s1[i] = t1[i] end
    for i = 1, #t2 do s2[i] = t2[i] end
    table.sort(s1)
    table.sort(s2)
    local i, j = 1, 1
    local maxDiff = 0
    local n1, n2 = #s1, #s2
    while i <= n1 and j <= n2 do
        local cdf1 = (i - 1) / n1
        local cdf2 = (j - 1) / n2
        local d = math.abs(cdf1 - cdf2)
        if d > maxDiff then maxDiff = d end
        if s1[i] < s2[j] then i = i + 1
        elseif s1[i] > s2[j] then j = j + 1
        else i = i + 1; j = j + 1 end
    end
    return maxDiff
end

function Stats.chiSquare(observed, expected)
    if #observed ~= #expected then return 0 end
    local chi = 0
    for i = 1, #observed do
        if expected[i] > 0 then
            local d = observed[i] - expected[i]
            chi = chi + (d * d) / expected[i]
        end
    end
    return chi
end

--========== TIME SERIES ==========--
local TimeSeries = {}
TimeSeries.__index = TimeSeries

function TimeSeries.new(name, opts)
    opts = opts or {}
    return setmetatable({
        name = name,
        capacity = opts.capacity or 120,
        values = {}, timestamps = {},
        count = 0, head = 1,
        sum = 0, min = math.huge, max = -math.huge,
        ema = 0, emaAlpha = opts.emaAlpha or 0.2,
        lastUpdate = 0,
    }, TimeSeries)
end

function TimeSeries:push(value, t)
    t = t or os.clock()
    if self.count < self.capacity then
        self.count = self.count + 1
        self.values[self.count] = value
        self.timestamps[self.count] = t
    else
        self.head = (self.head % self.capacity) + 1
        local idx = self.head - 1
        if idx < 1 then idx = self.capacity end
        local old = self.values[idx]
        self.values[idx] = value
        self.timestamps[idx] = t
        self.sum = self.sum - old + value
    end
    if self.count <= self.capacity then self.sum = self.sum + value end
    if value < self.min then self.min = value end
    if value > self.max then self.max = value end
    if self.count == 1 then self.ema = value
    else self.ema = self.emaAlpha * value + (1 - self.emaAlpha) * self.ema end
    self.lastUpdate = t
end

function TimeSeries:snapshot()
    return {
        name = self.name, count = self.count,
        min = self.min == math.huge and 0 or self.min,
        max = self.max == -math.huge and 0 or self.max,
        sum = self.sum,
        avg = self.count > 0 and (self.sum / math.min(self.count, self.capacity)) or 0,
        ema = self.ema,
        p50 = self:percentile(0.50),
        p90 = self:percentile(0.90),
        p99 = self:percentile(0.99),
    }
end

function TimeSeries:percentile(p)
    local n = self.count
    if n == 0 then return 0 end
    local total = math.min(n, self.capacity)
    local sorted = {}
    local start = self.head
    for i = 0, total - 1 do
        local idx = start + i
        if idx > self.capacity then idx = idx - self.capacity end
        sorted[i + 1] = self.values[idx]
    end
    table.sort(sorted)
    local pos = math.ceil(p * total)
    if pos < 1 then pos = 1 end
    if pos > total then pos = total end
    return sorted[pos]
end

--========== TIME SERIES STORE ==========--
local TimeSeriesStore = {}
TimeSeriesStore.__index = TimeSeriesStore

function TimeSeriesStore.new()
    local self = setmetatable({ series = {}, enabled = true }, TimeSeriesStore)
    for _, name in ipairs({
        "event_rate", "global_write_rate", "network_rate",
        "decrypt_rate", "coroutine_rate", "file_read_rate",
        "debug_rate", "function_call_rate", "rbx_property_write_rate",
        "vuln_finding_rate", "alert_rate",
    }) do
        self.series[name] = TimeSeries.new(name, { capacity = 120 })
    end
    return self
end

function TimeSeriesStore:get(name)
    local s = self.series[name]
    if not s then
        s = TimeSeries.new(name)
        self.series[name] = s
    end
    return s
end

function TimeSeriesStore:push(name, value, t)
    if not self.enabled then return end
    self:get(name):push(value, t)
end

function TimeSeriesStore:snapshot()
    local out = {}
    for name, s in pairs(self.series) do
        out[name] = s:snapshot()
    end
    return out
end

--========== MARKOV DETECTOR ==========--
local MarkovDetector = {}
MarkovDetector.__index = MarkovDetector

function MarkovDetector.new(opts)
    opts = opts or {}
    return setmetatable({
        transitions = {}, totals = {}, lastEvent = nil,
        windowSize = opts.windowSize or 200,
        recent = {}, recentCount = 0, recentHead = 0,
        anomalyCount = 0,
        threshold = opts.threshold or 0.001,
        minSamples = opts.minSamples or 30,
    }, MarkovDetector)
end

function MarkovDetector:record(eventType)
    local from = self.lastEvent
    if from then
        if not self.transitions[from] then
            self.transitions[from] = {}
            self.totals[from] = 0
        end
        local t = self.transitions[from]
        t[eventType] = (t[eventType] or 0) + 1
        self.totals[from] = self.totals[from] + 1
    end
    self.lastEvent = eventType
    self.recentHead = (self.recentHead % self.windowSize) + 1
    self.recent[self.recentHead] = eventType
    if self.recentCount < self.windowSize then
        self.recentCount = self.recentCount + 1
    end
end

function MarkovDetector:check(from, to)
    if not from then return false, 0 end
    local total = self.totals[from] or 0
    if total < self.minSamples then return false, 0 end
    local t = self.transitions[from]
    if not t then return true, 0 end
    local count = t[to] or 0
    local prob = count / total
    if prob < self.threshold and count == 0 then
        self.anomalyCount = self.anomalyCount + 1
        return true, prob
    end
    return false, prob
end

function MarkovDetector:stats()
    local states, transitions = 0, 0
    for _, t in pairs(self.transitions) do
        states = states + 1
        for _ in pairs(t) do transitions = transitions + 1 end
    end
    return {
        states = states, transitions = transitions, anomalies = self.anomalyCount,
    }
end

--========== ENTROPY TRACKER ==========--
local EntropyTracker = {}
EntropyTracker.__index = EntropyTracker

function EntropyTracker.new(opts)
    opts = opts or {}
    return setmetatable({
        window = {}, windowSize = opts.windowSize or 50,
        count = 0, head = 1,
        threshold = opts.threshold or 6.5,
        anomalyCount = 0, baselineEnt = 0, baselineSamples = 0,
    }, EntropyTracker)
end

function EntropyTracker:push(value)
    if type(value) ~= "string" or #value < 8 then return false, 0 end
    local e = Stats.entropy(value)
    if self.count < self.windowSize then
        self.count = self.count + 1
        self.window[self.count] = e
    else
        self.head = (self.head % self.windowSize) + 1
        self.window[self.head] = e
    end
    if e < self.threshold then
        self.baselineSamples = self.baselineSamples + 1
        self.baselineEnt = self.baselineEnt
            + (e - self.baselineEnt) / self.baselineSamples
    end
    if e > self.threshold then
        self.anomalyCount = self.anomalyCount + 1
        return true, e
    end
    return false, e
end

function EntropyTracker:stats()
    return {
        baseline = self.baselineEnt, samples = self.baselineSamples,
        anomalies = self.anomalyCount,
    }
end

--========== TAINT TRACKER ==========--
local TaintTracker = {}
TaintTracker.__index = TaintTracker

local SENSITIVE_KEYS = {
    ["token"] = true, ["cookie"] = true, ["password"] = true,
    ["secret"] = true, ["apikey"] = true, ["api_key"] = true,
    ["auth"] = true, ["credential"] = true, ["session"] = true,
    ["private"] = true, ["wallet"] = true, ["seed"] = true,
}

local SINKS = {
    HTTP_POST = true, HTTP_GET = true, FILE_WRITE = true,
    NETWORK_REQUEST = true,
}

function TaintTracker.new(opts)
    opts = opts or {}
    return setmetatable({
        activeTaints = {}, nextId = 0,
        window = opts.window or 30, maxActive = opts.maxActive or 100,
        flows = {}, flowCount = 0,
    }, TaintTracker)
end

local function isSensitiveEvent(event)
    if event.type == "FILE_READ" then
        local path = tostring(event.data and event.data.path or ""):lower()
        for k in pairs(SENSITIVE_KEYS) do
            if path:find(k, 1, true) then return true, k end
        end
    elseif event.type == "GLOBAL_READ" then
        local key = tostring(event.data and event.data.key or ""):lower()
        for k in pairs(SENSITIVE_KEYS) do
            if key:find(k, 1, true) then return true, k end
        end
    end
    return false, nil
end

function TaintTracker:observe(event)
    if event.type == "FILE_READ" or event.type == "GLOBAL_READ" then
        local isSens, key = isSensitiveEvent(event)
        if isSens then
            self.nextId = self.nextId + 1
            local count = 0
            for _ in pairs(self.activeTaints) do count = count + 1 end
            if count < self.maxActive then
                self.activeTaints[self.nextId] = {
                    source = event.type, key = key, t = event.t,
                }
            end
        end
    end
    if SINKS[event.type] then
        local t = event.t
        local window = self.window
        for id, taint in pairs(self.activeTaints) do
            if (t - taint.t) <= window then
                self.activeTaints[id] = nil
                self.flowCount = self.flowCount + 1
                self.flows[#self.flows + 1] = {
                    id = id, source = taint.source, sink = event.type,
                    key = taint.key, delta = t - taint.t,
                }
                return true, {
                    source = taint.source, sink = event.type,
                    key = taint.key, delta = t - taint.t,
                }
            else
                self.activeTaints[id] = nil
            end
        end
    end
    if event.seq and event.seq % 500 == 0 then
        local t = event.t
        for id, taint in pairs(self.activeTaints) do
            if (t - taint.t) > self.window then
                self.activeTaints[id] = nil
            end
        end
    end
    return false
end

function TaintTracker:stats()
    local active = 0
    for _ in pairs(self.activeTaints) do active = active + 1 end
    return { active = active, flows = self.flowCount }
end

--========== PATTERN MATCHER ==========--
local PatternMatcher = {}

local function matchEventCond(cond, e)
    if cond.type and e.type ~= cond.type then return false end
    if cond.severity_min and (e.severity or 0) < cond.severity_min then return false end
    if cond.filter and not cond.filter(e) then return false end
    return true
end

local function evalCondition(cond, events, ctx)
    if cond.type or cond.filter then
        for _, e in ipairs(events) do
            if matchEventCond(cond, e) then return true, { event = e } end
        end
        return false
    end
    if cond.seq then
        local steps = cond.seq
        local within = cond.within or 30
        local stepIdx = 1
        local start = nil
        for _, e in ipairs(events) do
            local expected = steps[stepIdx]
            if expected and matchEventCond(expected, e) then
                if stepIdx == 1 then start = e.t end
                stepIdx = stepIdx + 1
                if stepIdx > #steps then
                    if (e.t - start) <= within then
                        return true, { elapsed = e.t - start }
                    end
                    stepIdx = 1
                    start = nil
                end
            end
        end
        return false
    end
    if cond.count then
        local c = cond.count
        local within = c.within or 10
        local now = ctx.now
        local n = 0
        for _, e in ipairs(events) do
            if (now - e.t) <= within then
                if (not c.type or e.type == c.type)
                    and (not c.filter or c.filter(e)) then
                    n = n + 1
                end
            end
        end
        return n >= (c.value or 1), { count = n }
    end
    if cond.rate then
        local r = cond.rate
        local window = r.window or 3
        local now = ctx.now
        local n = 0
        for _, e in ipairs(events) do
            if (now - e.t) <= window then
                if (not r.type or e.type == r.type)
                    and (not r.filter or r.filter(e)) then
                    n = n + 1
                end
            end
        end
        local rate = n / window
        return rate >= (r.value or 1), { rate = rate }
    end
    if cond.entropy then
        for _, e in ipairs(events) do
            local v = e.data and e.data.value
            if type(v) == "string" and #v >= 8 then
                local h = Stats.entropy(v)
                if h >= (cond.entropy.value or 6.5) then
                    return true, { entropy = h, sample = v:sub(1, 40) }
                end
            end
        end
        return false
    end
    if cond.all then
        local metas = {}
        for _, c in ipairs(cond.all) do
            local ok, m = evalCondition(c, events, ctx)
            if not ok then return false end
            table.insert(metas, m)
        end
        return true, { all = metas }
    end
    if cond.any then
        for _, c in ipairs(cond.any) do
            local ok, m = evalCondition(c, events, ctx)
            if ok then return true, m end
        end
        return false
    end
    if cond.not_ then
        local ok = evalCondition(cond.not_, events, ctx)
        return not ok
    end
    return false
end

PatternMatcher.eval = evalCondition
PatternMatcher.matchEvent = matchEventCond

--========== BAYESIAN RISK ==========--
local BayesianRisk = {}
BayesianRisk.__index = BayesianRisk

local LR_TABLE = {
    credential_file_access = 8.0,
    network_after_file = 6.0,
    high_entropy_string = 5.0,
    loader_chain = 12.0,
    anticheat_bypass = 15.0,
    taint_flow = 10.0,
    markov_anomaly = 4.0,
    rate_anomaly = 3.0,
    entropy_anomaly = 3.5,
    persistent_global = 4.5,
    debug_abuse = 5.0,
    thread_escalation = 7.0,
    remote_suspicious = 5.5,
    vuln_critical = 6.0,
}

function BayesianRisk.new(opts)
    opts = opts or {}
    return setmetatable({
        prior = opts.prior or 0.02,
        posterior = opts.prior or 0.02,
        signals = {},
        history = {},
        decay = opts.decay or 0.15,
        min = 0.001, max = 0.999,
        updateCount = 0,
    }, BayesianRisk)
end

function BayesianRisk:addSignal(name, active)
    if active then self.signals[name] = true
    else self.signals[name] = nil end
end

function BayesianRisk:update()
    local base = self.posterior + (self.prior - self.posterior) * self.decay
    base = math.max(self.min, math.min(self.max, base))
    local odds = base / (1 - base)
    local signalCount = 0
    for sig in pairs(self.signals) do
        local lr = LR_TABLE[sig] or 1.0
        odds = odds * lr
        signalCount = signalCount + 1
    end
    local newPosterior = odds / (1 + odds)
    newPosterior = math.max(self.min, math.min(self.max, newPosterior))
    self.posterior = newPosterior
    self.updateCount = self.updateCount + 1
    table.insert(self.history, {
        t = os.clock(), posterior = newPosterior, signals = signalCount,
    })
    if #self.history > 200 then table.remove(self.history, 1) end
    return self.posterior
end

function BayesianRisk:get() return self.posterior end

function BayesianRisk:stats()
    local n = 0
    for _ in pairs(self.signals) do n = n + 1 end
    return {
        posterior = self.posterior, prior = self.prior,
        signals = n, updates = self.updateCount,
    }
end

--========== ALERT DEDUP ==========--
local AlertDedup = {}
AlertDedup.__index = AlertDedup

function AlertDedup.new(opts)
    opts = opts or {}
    return setmetatable({
        seen = {}, order = {},
        window = opts.window or 30, max = opts.max or 500,
        deduped = 0,
    }, AlertDedup)
end

local function fingerprint(alert)
    local parts = {
        tostring(alert.rule or ""),
        tostring(alert.message or ""):sub(1, 80),
    }
    return table.concat(parts, "|")
end

function AlertDedup:check(alert)
    local fp = fingerprint(alert)
    local t = os.clock()
    local entry = self.seen[fp]
    if entry then
        if (t - entry.last) <= self.window then
            entry.count = entry.count + 1
            entry.last = t
            self.deduped = self.deduped + 1
            return true, entry.count
        end
        entry.count = 1
        entry.first = t
        entry.last = t
        return false
    end
    self.seen[fp] = { count = 1, first = t, last = t }
    table.insert(self.order, fp)
    if #self.order > self.max then
        local old = table.remove(self.order, 1)
        self.seen[old] = nil
    end
    return false
end

function AlertDedup:stats()
    return { tracked = #self.order, deduped = self.deduped }
end

--========== SESSION ==========--
local Session = {}
Session.__index = Session

function Session.new()
    local s = setmetatable({
        id = tostring(os.time()) .. "-" .. tostring(math.random(100000, 999999)),
        start_time = os.clock(), start_os_time = os.time(),
        events_processed = 0, alerts = 0,
        phase = "INIT", phase_changed = os.clock(),
        fingerprint = nil,
    }, Session)
    s.fingerprint = s:_computeFingerprint()
    return s
end

function Session:_computeFingerprint()
    local parts = {
        _VERSION or "unknown",
        tostring(jit and jit.version or "no-jit"),
        tostring(rawget(_G, "identifyexecutor") and "exec" or "vanilla"),
        tostring(rawget(_G, "getgenv") and "genv" or "no-genv"),
    }
    return table.concat(parts, "|")
end

function Session:advancePhase(newPhase)
    local old = self.phase
    self.phase = newPhase
    self.phase_changed = os.clock()
    return old, newPhase
end

function Session:elapsed() return os.clock() - self.start_time end

--========== ANOMALY DETECTOR ==========--
local Anomaly = {}
Anomaly.__index = Anomaly

function Anomaly.new(windowSize)
    return setmetatable({
        window = {}, windowSize = windowSize or 30,
        threshold = 3.5,
    }, Anomaly)
end

function Anomaly:push(value)
    table.insert(self.window, value)
    if #self.window > self.windowSize then table.remove(self.window, 1) end
end

function Anomaly:isAnomaly(value)
    if #self.window < 5 then return false, 0 end
    local med = Stats.median(self.window)
    local mad = Stats.mad(self.window)
    local mz = Stats.modifiedZscore(value, med, mad)
    return math.abs(mz) > self.threshold, mz
end

--========== MAIN OBJECT ==========--
function EDR.new()
    local self = setmetatable({}, { __index = EDR })

    self.bus = EventBus.new()
    self.buffer = RingBuffer.new(EDR.Config.MAX_EVENTS)
    self.session = Session.new()
    self.eventPool = EventPool.new(3000)
    self.timeseries = TimeSeriesStore.new()
    self.timeseries.enabled = EDR.Config.ENABLE_TIMESERIES
    self.markov = EDR.Config.ENABLE_MARKOV and MarkovDetector.new() or nil
    self.entropy = EDR.Config.ENABLE_ENTROPY and EntropyTracker.new() or nil
    self.taint = EDR.Config.ENABLE_TAINT and TaintTracker.new() or nil
    self.risk = EDR.Config.ENABLE_BAYESIAN and BayesianRisk.new() or nil
    self.dedup = AlertDedup.new()
    self.alerts = {}
    self.alertsById = {}
    self.alertQueue = {}
    self.hookRegistry = {}
    self.onAlert = nil
    self.watchdog = false
    self.counters = {}
    self.baselineStart = os.clock()
    self.baselineActive = true
    self.emitRateThisSec = 0
    self.lastEmitReset = os.clock()
    self.emitDropped = 0
    self.integrityThread = nil
    self.integrityViolations = 0
    self.patterns = {}
    self.mode = EDR.Config.PERFORMANCE_MODE

    EDR._installDefaultPatterns(self)

    return self
end

function EDR:_applyMode(mode)
    self.mode = mode
    self.timeseries.enabled = EDR.Config.ENABLE_TIMESERIES
    if not EDR.Config.ENABLE_MARKOV then self.markov = nil end
    if not EDR.Config.ENABLE_TAINT then self.taint = nil end
    if not EDR.Config.ENABLE_ENTROPY then self.entropy = nil end
    EDR._log(1, "perf", "instance mode applied: " .. mode)
end

--========== LOG ==========--
function EDR:log(level, msg)
    EDR._log(level, "inst", msg)
end

--========== EMIT ==========--
function EDR:_checkEmitRate()
    local t = os.clock()
    if t - self.lastEmitReset >= 1 then
        self.emitRateThisSec = 0
        self.lastEmitReset = t
    end
    if self.emitRateThisSec >= EDR.Config.MAX_EMIT_RATE_PER_SEC then
        self.emitDropped = self.emitDropped + 1
        return false
    end
    self.emitRateThisSec = self.emitRateThisSec + 1
    return true
end

function EDR:emit(eventType, data, severity)
    if not self:_checkEmitRate() then return nil end

    local t = os.clock()
    local tFloor = math.floor(t)

    local event = self.eventPool:acquire()
    event.type = eventType
    event.data = data or {}
    event.severity = severity or 0
    event.t = t
    event.wall = os.time()
    event.seq = self.session.events_processed + 1
    event.phase = self.session.phase

    -- Enforce buffer cap by overwriting oldest (handled by RingBuffer)
    self.buffer:push(event)
    self.session.events_processed = event.seq

    -- Counters
    local key = eventType .. ":" .. tFloor
    self.counters[key] = (self.counters[key] or 0) + 1
    if event.seq % 2000 == 0 then self:_cleanupCounters() end

    -- Time series
    local metricName = EDR._metricsForEvent(eventType)
    if metricName and self.timeseries.enabled then
        self.timeseries:push(metricName, self:getRate(eventType, 3), t)
    end

    -- Markov
    if self.markov then
        local from = self.markov.lastEvent
        self.markov:record(eventType)
        if from then
            local isAnom = self.markov:check(from, eventType)
            if isAnom and self.risk then
                self.risk:addSignal("markov_anomaly", true)
            end
        end
    end

    -- Entropy
    if self.entropy and eventType == "STRING_DECRYPT" then
        local v = data and data.value
        if type(v) == "string" then
            local isAnom = self.entropy:push(v)
            if isAnom and self.risk then
                self.risk:addSignal("entropy_anomaly", true)
            end
        end
    end

    -- Taint
    if self.taint then
        local taintFlow, meta = self.taint:observe(event)
        if taintFlow and self.risk then
            self.risk:addSignal("taint_flow", true)
            self:raiseAlert({
                rule = "TAINT_FLOW", severity = 3,
                message = string.format("Data flow: %s (%s) → %s (Δt=%.1fs)",
                    meta.source, meta.key or "?", meta.sink, meta.delta),
                meta = meta,
            })
        end
    end

    -- Sensitive tracking
    if self.risk then
        if eventType == "FILE_READ" then
            local p = tostring(data and data.path or ""):lower()
            for _, k in ipairs({"token", "cookie", "password", "secret", ".env"}) do
                if p:find(k, 1, true) then
                    self.risk:addSignal("credential_file_access", true)
                    break
                end
            end
        elseif eventType == "DEBUG_ACCESS" then
            self.risk:addSignal("debug_abuse", true)
        elseif eventType == "THREAD_IDENTITY" then
            self.risk:addSignal("thread_escalation", true)
        elseif eventType == "GLOBAL_WRITE" then
            if self:getRate("GLOBAL_WRITE", 3) > 30 then
                self.risk:addSignal("persistent_global", true)
            end
        end
    end

    self.bus:publish(event)
    return event
end

local METRIC_MAP = {
    GLOBAL_WRITE = "global_write_rate",
    NETWORK_REQUEST = "network_rate",
    HTTP_GET = "network_rate",
    HTTP_POST = "network_rate",
    STRING_DECRYPT = "decrypt_rate",
    COROUTINE_CREATE = "coroutine_rate",
    FILE_READ = "file_read_rate",
    DEBUG_ACCESS = "debug_rate",
    FUNCTION_CALL = "function_call_rate",
    RBX_PROPERTY_WRITE = "rbx_property_write_rate",
    VULN_FINDING = "vuln_finding_rate",
    ALERT = "alert_rate",
}

function EDR._metricsForEvent(eventType)
    return METRIC_MAP[eventType]
end

function EDR:_cleanupCounters()
    local nowFloor = math.floor(os.clock())
    for k in pairs(self.counters) do
        local t = tonumber(k:match(":(%d+)$"))
        if t and (nowFloor - t) > 60 then self.counters[k] = nil end
    end
end

function EDR:getRate(eventType, window)
    window = window or 5
    local nowFloor = math.floor(os.clock())
    local total = 0
    for i = 0, window - 1 do
        total = total + (self.counters[eventType .. ":" .. (nowFloor - i)] or 0)
    end
    return total / window
end

--========== ALERT ===========--
function EDR:raiseAlert(alert)
    alert.t = alert.t or os.clock()
    alert.session_id = self.session.id
    alert.severity = alert.severity or 0

    local isDup, count = self.dedup:check(alert)
    if isDup then
        local fp = tostring(alert.rule or "") .. "|" .. tostring(alert.message or ""):sub(1, 80)
        local existing = self.alertsById[fp]
        if existing then
            existing.dedup_count = count
            existing.last_seen = alert.t
        end
        return false
    end

    alert.priority = (alert.severity or 0) * 100 + (alert.score or 0) * 50

    table.insert(self.alerts, alert)
    self.session.alerts = self.session.alerts + 1
    local fp = tostring(alert.rule or "") .. "|" .. tostring(alert.message or ""):sub(1, 80)
    self.alertsById[fp] = alert

    if #self.alerts > EDR.Config.MAX_ALERTS then
        local removed = table.remove(self.alerts, 1)
        if removed then
            local rfp = tostring(removed.rule or "") .. "|" .. tostring(removed.message or ""):sub(1, 80)
            if self.alertsById[rfp] == removed then self.alertsById[rfp] = nil end
        end
    end

    table.insert(self.alertQueue, alert)
    table.sort(self.alertQueue, function(a, b)
        return (a.priority or 0) > (b.priority or 0)
    end)
    if #self.alertQueue > 100 then table.remove(self.alertQueue) end

    if self.onAlert then
        pcall(self.onAlert, alert)
    end
    return true
end

--========== HOOK REGISTRY ==========--
function EDR:registerHook(name, unhookFn)
    self.hookRegistry[name] = unhookFn
end

function EDR:unhookAll()
    for name, fn in pairs(self.hookRegistry) do
        pcall(fn)
    end
    self.hookRegistry = {}
end

--========== WATCHDOG ==========--
function EDR:startWatchdog()
    if self.watchdog then return end
    self.watchdog = true
    local session = self.session

    task.spawn(function()
        local corrCounter = 0
        local integrityCounter = 0

        while self.watchdog do
            task.wait(EDR.Config.WATCHDOG_INTERVAL)

            if self.baselineActive then
                if (os.clock() - self.baselineStart) >= EDR.Config.BASELINE_DURATION then
                    self.baselineActive = false
                    session:advancePhase("MONITOR")
                    self:log(1, "Baseline complete — entering MONITOR phase")
                end
            end

            self:emit("HEARTBEAT", {
                uptime = session:elapsed(),
                events = session.events_processed,
                alerts = session.alerts,
                dropped = self.buffer.dropped,
                emitDropped = self.emitDropped,
                phase = session.phase,
            })

            if self.timeseries.enabled then
                self.timeseries:push("event_rate", self:getRate("*", 5), os.clock())
            end

            corrCounter = corrCounter + 1
            if EDR.Config.ENABLE_CORRELATION and corrCounter >= 1 then
                corrCounter = 0
                pcall(function() self:scanPatterns() end)
            end

            if self.risk and not self.baselineActive then
                pcall(function() self.risk:update() end)
            end

            if EDR.Config.SELF_INTEGRITY then
                integrityCounter = integrityCounter + 1
                if integrityCounter >= 2 then
                    integrityCounter = 0
                    pcall(function() self:_checkIntegrity() end)
                end
            end
        end
    end)
end

function EDR:stopWatchdog()
    self.watchdog = false
end

--========== CORRELATION ===========--
function EDR:scanPatterns()
    local now = os.clock()
    local recent = self.buffer:recent(EDR.Config.WINDOW_SEC, now)
    if #recent == 0 then return end

    local ctx = { now = now }

    for _, pat in ipairs(self.patterns or {}) do
        local ok, meta = PatternMatcher.eval(pat.condition, recent, ctx)
        if ok then
            pat._lastHit = pat._lastHit or 0
            if (now - pat._lastHit) >= (pat.cooldown or 30) then
                pat._lastHit = now
                self:raiseAlert({
                    rule = pat.id,
                    severity = pat.severity or 2,
                    message = pat.message or pat.id,
                    meta = meta,
                    mitre = pat.mitre,
                })
                if self.risk and pat.riskSignal then
                    self.risk:addSignal(pat.riskSignal, true)
                end
            end
        end
    end
end

--========== INTEGRITY ===========--
function EDR:_checkIntegrity()
    local checks = {
        { name = "pcall", fn = pcall },
        { name = "tostring", fn = tostring },
        { name = "setmetatable", fn = setmetatable },
        { name = "rawget", fn = rawget },
        { name = "math.floor", fn = math.floor },
    }
    for _, c in ipairs(checks) do
        if type(c.fn) ~= "function" then
            self.integrityViolations = self.integrityViolations + 1
            self:raiseAlert({
                rule = "SELF_INTEGRITY",
                severity = 3,
                message = "Function tampered: " .. c.name,
            })
        end
    end
end

--========== DEFAULT PATTERNS ===========--
function EDR._installDefaultPatterns(edr)
    local patterns = {}

    table.insert(patterns, {
        id = "CRED_EXFIL", severity = 4,
        message = "Credential exfiltration chain",
        mitre = "T1552", cooldown = 30,
        riskSignal = "credential_file_access",
        condition = { seq = {
            { type = "FILE_READ", filter = function(e)
                local p = tostring(e.data and e.data.path or ""):lower()
                return p:find("token") or p:find("cookie") or p:find(".env")
                    or p:find("password") or p:find("credential")
            end },
            { type = "STRING_ENCODE" },
            { type = "HTTP_POST" },
        }, within = 20 },
    })

    table.insert(patterns, {
        id = "REMOTE_LOADER", severity = 3,
        message = "HttpGet → loadstring chain",
        mitre = "T1620", cooldown = 20,
        riskSignal = "loader_chain",
        condition = { seq = {
            { type = "HTTP_GET" },
            { type = "FUNCTION_CALL", filter = function(e)
                return e.data and e.data.name == "loadstring"
            end },
        }, within = 10 },
    })

    table.insert(patterns, {
        id = "ANTI_DEBUG", severity = 3,
        message = "Anti-debug pattern", mitre = "T1622",
        cooldown = 30, riskSignal = "debug_abuse",
        condition = { all = {
            { type = "DEBUG_ACCESS", filter = function(e)
                local n = e.data and e.data.name or ""
                return n == "getinfo" or n == "sethook"
            end },
            { count = { type = "DEBUG_ACCESS", value = 5, within = 5 } },
        } },
    })

    table.insert(patterns, {
        id = "DECRYPT_BURST", severity = 2,
        message = "Massive XOR decryption burst (Luraph-style)",
        mitre = "T1140", cooldown = 20,
        riskSignal = "high_entropy_string",
        condition = { rate = { type = "STRING_DECRYPT", value = 100, window = 3 } },
    })

    table.insert(patterns, {
        id = "GLOBAL_POLLUTION", severity = 2,
        message = "Excessive global write (hook installation?)",
        mitre = "T1055", cooldown = 30,
        riskSignal = "persistent_global",
        condition = { count = { type = "GLOBAL_WRITE", value = 50, within = 10 } },
    })

    table.insert(patterns, {
        id = "C2_PATTERN", severity = 3,
        message = "C2 pattern: encrypt burst → network",
        mitre = "T1071", cooldown = 25,
        condition = { seq = {
            { type = "STRING_DECRYPT" },
            { type = "NETWORK_REQUEST" },
            { type = "STRING_DECRYPT" },
        }, within = 5 },
    })

    table.insert(patterns, {
        id = "THREAD_ESCALATION", severity = 4,
        message = "Thread identity escalation with debug abuse",
        mitre = "T1055", cooldown = 30,
        riskSignal = "thread_escalation",
        condition = { all = {
            { type = "THREAD_IDENTITY" },
            { count = { type = "DEBUG_ACCESS", value = 3, within = 10 } },
        } },
    })

    table.insert(patterns, {
        id = "SUSPICIOUS_REMOTE", severity = 3,
        message = "Suspicious remote event firing",
        mitre = "T1059", cooldown = 15,
        riskSignal = "remote_suspicious",
        condition = { count = { type = "RBX_REMOTE_FIRE", value = 20, within = 5 } },
    })

    table.insert(patterns, {
        id = "PROPERTY_TAMPER", severity = 3,
        message = "Character/camera property manipulation",
        mitre = "T1562.001", cooldown = 20,
        condition = { count = { type = "RBX_PROPERTY_WRITE", value = 15, within = 5,
            filter = function(e)
                local d = e.data or {}
                return d.class == "Humanoid" or d.class == "Camera"
            end } },
    })

    table.insert(patterns, {
        id = "ENCRYPTED_C2", severity = 4,
        message = "High-entropy string followed by network (encrypted exfil?)",
        mitre = "T1041", cooldown = 20,
        condition = { seq = {
            { type = "STRING_DECRYPT", filter = function(e)
                local v = e.data and e.data.value
                return type(v) == "string" and #v > 30 and Stats.entropy(v) > 6.5
            end },
            { type = "HTTP_POST" },
        }, within = 8 },
    })

    table.insert(patterns, {
        id = "ENV_MANIPULATION", severity = 3,
        message = "Environment manipulation burst",
        mitre = "T1055", cooldown = 25,
        condition = { count = { type = "ENV_ACCESS", value = 10, within = 5 } },
    })

    table.insert(patterns, {
        id = "METATABLE_ABUSE", severity = 2,
        message = "Metatable tampering detected",
        mitre = "T1055", cooldown = 20,
        condition = { count = { type = "METATABLE_ACCESS", value = 15, within = 5 } },
    })

    table.insert(patterns, {
        id = "CRITICAL_VULN", severity = 4,
        message = "Critical vulnerability detected",
        mitre = "T1190", cooldown = 60,
        riskSignal = "vuln_critical",
        condition = { type = "VULN_FINDING", filter = function(e)
            return (e.severity or 0) >= 4
        end },
    })

    table.insert(patterns, {
        id = "ANOMALY_CLUSTER", severity = 3,
        message = "Cluster of statistical anomalies",
        mitre = "T1499", cooldown = 30,
        riskSignal = "rate_anomaly",
        condition = { count = { type = "ANOMALY", value = 3, within = 10 } },
    })

    table.insert(patterns, {
        id = "DATASTORE_EGRESS", severity = 4,
        message = "DataStore access followed by HTTP egress",
        mitre = "T1567", cooldown = 30,
        condition = { seq = {
            { type = "RBX_SERVICE_ACCESS", filter = function(e)
                local s = e.data and e.data.service or ""
                return s == "DataStoreService" or s == "MemoryStoreService"
            end },
            { type = "NETWORK_REQUEST" },
        }, within = 15 },
    })

    edr.patterns = patterns
end

--========== SUMMARY ===========--
function EDR:summary()
    local s = self.session
    return {
        session_id = s.id,
        fingerprint = s.fingerprint,
        elapsed = s:elapsed(),
        phase = s.phase,
        mode = self.mode,
        version = EDR._VERSION,
        events = s.events_processed,
        alerts = #self.alerts,
        dropped = self.buffer.dropped,
        emitDropped = self.emitDropped,
        pool = self.eventPool:stats(),
        dedup = self.dedup:stats(),
        taint = self.taint and self.taint:stats() or nil,
        markov = self.markov and self.markov:stats() or nil,
        entropy = self.entropy and self.entropy:stats() or nil,
        risk = self.risk and self.risk:stats() or nil,
        timeseries = self.timeseries.enabled and self.timeseries:snapshot() or nil,
        by_severity = self:_countBySeverity(),
        by_type = self.bus.stats,
        integrityViolations = self.integrityViolations,
    }
end

function EDR:_countBySeverity()
    local out = { [0]=0, [1]=0, [2]=0, [3]=0, [4]=0 }
    for _, a in ipairs(self.alerts) do
        local s = a.severity or 0
        out[s] = (out[s] or 0) + 1
    end
    return out
end

--========== EXPORT ==========--
EDR.RingBuffer = RingBuffer
EDR.EventBus = EventBus
EDR.Session = Session
EDR.Stats = Stats
EDR.TimeSeries = TimeSeries
EDR.TimeSeriesStore = TimeSeriesStore
EDR.MarkovDetector = MarkovDetector
EDR.EntropyTracker = EntropyTracker
EDR.TaintTracker = TaintTracker
EDR.PatternMatcher = PatternMatcher
EDR.BayesianRisk = BayesianRisk
EDR.AlertDedup = AlertDedup
EDR.EventPool = EventPool
EDR.Anomaly = Anomaly
EDR.MODE_PROFILES = MODE_PROFILES

EDR._instance = nil

function EDR.get()
    if not EDR._instance then
        EDR._instance = EDR.new()
    end
    return EDR._instance
end

function EDR.reset()
    if EDR._instance then
        EDR._instance:stopWatchdog()
    end
    EDR._instance = nil
end

return EDR