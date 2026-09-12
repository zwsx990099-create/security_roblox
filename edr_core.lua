--[[
    ============================================================
    EDR Core v1.0 — Event Bus + Correlation Engine
    ============================================================
    หลักการ:
    - เป็น "แกนกลาง" ที่ทุก module เสียบเข้ามา
    - รับ event จาก hooks → เก็บ → correlate → แจ้ง rule engine
    - ออกแบบตามหลัก Windows 11 EDR:
        * Kernel Callback  → opcode hook
        * ETW             → event bus
        * WFP             → network monitor
        * Registry Filter → global table monitor
        * AMSI            → string decrypt scanner
    ============================================================
]]

local EDR = {}

--========== CONFIG ==========--
EDR.Config = {
    -- ขนาด ring buffer ของ event (ปรับตาม RAM)
    MAX_EVENTS         = 500000,
    -- หน้าต่างเวลาสำหรับ correlation (วินาที)
    WINDOW_SEC         = 30,
    -- ความถี่ watchdog (วินาที)
    WATCHDOG_INTERVAL  = 5,
    -- เปิด/ปิด correlation engine
    ENABLE_CORRELATION = true,
    -- ระดับ log: 0=quiet, 1=normal, 2=verbose, 3=debug
    LOG_LEVEL          = 1,
    -- เก็บ snapshot ของ environment ก่อนรัน
    SNAPSHOT_ENV       = true,
    -- ตรวจ self-integrity (กัน hook ตัวเองถูกถอด)
    SELF_INTEGRITY     = true,
}

--========== EVENT TYPES ==========--
EDR.EventType = {
    OPCODE_CALL        = "OPCODE_CALL",
    OPCODE_RET         = "OPCODE_RET",
    OPCODE_LINE        = "OPCODE_LINE",
    GLOBAL_READ        = "GLOBAL_READ",
    GLOBAL_WRITE       = "GLOBAL_WRITE",
    FUNCTION_CALL      = "FUNCTION_CALL",       -- เรียกฟังก์ชันสำคัญ
    FUNCTION_REDEFINE  = "FUNCTION_REDEFINE",   -- เขียนทับฟังก์ชัน
    COROUTINE_CREATE   = "COROUTINE_CREATE",
    COROUTINE_RESUME   = "COROUTINE_RESUME",
    FILE_READ          = "FILE_READ",
    FILE_WRITE         = "FILE_WRITE",
    NETWORK_REQUEST    = "NETWORK_REQUEST",
    NETWORK_RESPONSE   = "NETWORK_RESPONSE",
    STRING_DECRYPT     = "STRING_DECRYPT",
    STRING_ENCODE      = "STRING_ENCODE",
    HTTP_GET           = "HTTP_GET",
    HTTP_POST          = "HTTP_POST",
    ENV_ACCESS         = "ENV_ACCESS",
    METATABLE_ACCESS   = "METATABLE_ACCESS",
    DEBUG_ACCESS       = "DEBUG_ACCESS",        -- ตรวจ debug library
    THREAD_IDENTITY    = "THREAD_IDENTITY",
    SUSPICIOUS_API     = "SUSPICIOUS_API",
    ANOMALY            = "ANOMALY",
    HEARTBEAT          = "HEARTBEAT",
    ALERT              = "ALERT",
}

--========== SEVERITY ==========--
EDR.Severity = {
    INFO     = 0,
    LOW      = 1,
    MEDIUM   = 2,
    HIGH     = 3,
    CRITICAL = 4,
}

--========== RING BUFFER ==========--
-- ใช้ fixed-size + circular index (ประหยัด memory, O(1) insert/read)
local RingBuffer = {}
RingBuffer.__index = RingBuffer

function RingBuffer.new(size)
    return setmetatable({
        size   = size,
        data   = {},
        head   = 0,
        tail   = 0,
        count  = 0,
        dropped = 0,  -- event ที่หายไปเพราะ buffer เต็ม
    }, RingBuffer)
end

function RingBuffer:push(item)
    self.tail = (self.tail % self.size) + 1
    if self.count == self.size then
        self.head = (self.head % self.size) + 1
        self.dropped = self.dropped + 1
    else
        self.count = self.count + 1
    end
    self.data[self.tail] = item
end

function RingBuffer:iter()
    local i = self.head
    local n = 0
    return function()
        if n >= self.count then return nil end
        i = (i % self.size) + 1
        n = n + 1
        return self.data[i]
    end
end

function RingBuffer:snapshot()
    local out = {}
    for item in self:iter() do
        table.insert(out, item)
    end
    return out
end

function RingBuffer:clear()
    self.data = {}
    self.head, self.tail, self.count, self.dropped = 0, 0, 0, 0
end

--========== EVENT BUS ==========--
-- Pub/Sub แบบ multi-subscriber + filter
local EventBus = {}
EventBus.__index = EventBus

function EventBus.new()
    return setmetatable({
        subscribers = {},  -- [type] = { {fn, filter}, ... }
        global      = {},  -- ฟังก์ชันที่ subscribe ทุก event
        stats       = {},  -- นับ event ต่อ type
    }, EventBus)
end

function EventBus:subscribe(eventType, callback, filter)
    if not self.subscribers[eventType] then
        self.subscribers[eventType] = {}
    end
    table.insert(self.subscribers[eventType], {
        fn = callback,
        filter = filter or function() return true end,
    })
end

function EventBus:subscribeAll(callback)
    table.insert(self.global, callback)
end

function EventBus:publish(event)
    -- นับสถิติ
    self.stats[event.type] = (self.stats[event.type] or 0) + 1

    -- แจ้ง global subscribers
    for _, sub in ipairs(self.global) do
        pcall(sub, event)
    end

    -- แจ้ง type-specific subscribers
    local subs = self.subscribers[event.type]
    if subs then
        for _, sub in ipairs(subs) do
            if sub.filter(event) then
                pcall(sub.fn, event)
            end
        end
    end
end

--========== SESSION ==========--
-- จัดการ session ทั้งหมด + metadata
local Session = {}
Session.__index = Session

function Session.new()
    local s = setmetatable({
        id              = tostring(os.time()) .. "-" .. tostring(math.random(100000, 999999)),
        start_time      = os.clock(),
        start_os_time   = os.time(),
        events_processed = 0,
        alerts          = {},
        baseline        = nil,
        phase           = "INIT",  -- INIT → BASELINE → MONITOR → REPORT
        phase_changed   = os.clock(),
        environment     = {},
        fingerprint     = nil,
    }, Session)
    s.fingerprint = s:_computeFingerprint()
    return s
end

function Session:_computeFingerprint()
    -- สร้าง fingerprint ของ environment เพื่อเทียบ baseline
    -- ใช้ค่าเหล่านี้: _VERSION, jit presence, executor name, mobile/desktop
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

function Session:addAlert(alert)
    table.insert(self.alerts, alert)
end

function Session:elapsed()
    return os.clock() - self.start_time
end

--========== CORRELATION ENGINE ==========--
-- ตรวจ sequence ของ event ที่น่าสงสัยภายในหน้าต่างเวลา
-- เหมือน Sigma rules แต่ทำงานแบบ real-time
local Correlator = {}
Correlator.__index = Correlator

function Correlator.new(bus, buffer)
    return setmetatable({
        bus        = bus,
        buffer     = buffer,
        patterns   = {},   -- list ของ pattern ที่ต้อง match
        window     = EDR.Config.WINDOW_SEC,
        hits       = {},   -- pattern_id → count
    }, Correlator)
end

-- เพิ่ม pattern (sequence detection)
-- pattern = {
--   id = "UNIQUE_ID",
--   severity = "HIGH",
--   steps = { {type="A"}, {type="B"}, {type="C"} },  -- ต้องเจอตามลำดับ
--   within = 10,  -- วินาที
--   onMatch = function(events) end,
-- }
function Correlator:addPattern(pattern)
    table.insert(self.patterns, pattern)
end

-- ตรวจ pattern ด้วย sliding window
function Correlator:scan()
    local now = os.clock()
    local events = self.buffer:snapshot()

    -- กรองเฉพาะ event ในหน้าต่างเวลา
    local recent = {}
    for _, e in ipairs(events) do
        if (now - e.t) <= self.window then
            table.insert(recent, e)
        end
    end

    -- ตรวจ pattern ทุกตัว
    for _, pat in ipairs(self.patterns) do
        self:_checkPattern(pat, recent, now)
    end
end

function Correlator:_checkPattern(pat, events, now)
    local steps = pat.steps
    local stepIdx = 1
    local matchStart = nil
    local matched = {}

    for _, e in ipairs(events) do
        local expected = steps[stepIdx]
        if expected and self:_matchStep(expected, e) then
            if stepIdx == 1 then matchStart = e.t end
            table.insert(matched, e)
            stepIdx = stepIdx + 1
            if stepIdx > #steps then
                -- ครบทุก step
                local elapsed = e.t - matchStart
                if elapsed <= (pat.within or self.window) then
                    self.hits[pat.id] = (self.hits[pat.id] or 0) + 1
                    if pat.onMatch then
                        pcall(pat.onMatch, matched, elapsed)
                    end
                end
                -- reset เพื่อหา match รอบใหม่
                stepIdx = 1
                matched = {}
                matchStart = nil
            end
        end
    end
end

function Correlator:_matchStep(expected, event)
    if expected.type and event.type ~= expected.type then return false end
    if expected.filter and not expected.filter(event) then return false end
    return true
end

--========== STATISTICAL ANALYSIS ==========--
-- คำนวณสถิติพื้นฐานสำหรับ anomaly detection
local Stats = {}

function Stats.mean(t)
    if #t == 0 then return 0 end
    local s = 0
    for _, v in ipairs(t) do s = s + v end
    return s / #t
end

function Stats.stdev(t)
    if #t < 2 then return 0 end
    local m = Stats.mean(t)
    local s = 0
    for _, v in ipairs(t) do s = s + (v - m) ^ 2 end
    return math.sqrt(s / (#t - 1))
end

function Stats.median(t)
    if #t == 0 then return 0 end
    local sorted = {}
    for i, v in ipairs(t) do sorted[i] = v end
    table.sort(sorted)
    local n = #sorted
    if n % 2 == 1 then return sorted[(n + 1) / 2]
    else return (sorted[n/2] + sorted[n/2 + 1]) / 2 end
end

function Stats.percentile(t, p)
    if #t == 0 then return 0 end
    local sorted = {}
    for i, v in ipairs(t) do sorted[i] = v end
    table.sort(sorted)
    local idx = math.ceil(p * #sorted)
    if idx < 1 then idx = 1 end
    if idx > #sorted then idx = #sorted end
    return sorted[idx]
end

-- Z-score สำหรับ anomaly detection
function Stats.zscore(value, mean, stddev)
    if stddev == 0 then return 0 end
    return (value - mean) / stddev
end

-- Modified Z-score (ใช้ median + MAD) — ทนทานต่อ outlier
function Stats.modifiedZscore(value, median, mad)
    if mad == 0 then return 0 end
    return 0.6745 * (value - median) / mad
end

-- MAD (Median Absolute Deviation)
function Stats.mad(t)
    if #t == 0 then return 0 end
    local m = Stats.median(t)
    local deviations = {}
    for _, v in ipairs(t) do
        table.insert(deviations, math.abs(v - m))
    end
    return Stats.median(deviations)
end

-- Exponentially Weighted Moving Average
function Stats.ewma(values, alpha)
    alpha = alpha or 0.3
    if #values == 0 then return 0 end
    local s = values[1]
    for i = 2, #values do
        s = alpha * values[i] + (1 - alpha) * s
    end
    return s
end

--========== ANOMALY DETECTOR ==========--
-- ใช้ MAD-based detection (ทนต่อ outlier)
local Anomaly = {}
Anomaly.__index = Anomaly

function Anomaly.new(windowSize)
    return setmetatable({
        window     = {},
        windowSize = windowSize or 30,
        threshold  = 3.5,   -- modified z-score threshold
    }, Anomaly)
end

function Anomaly:push(value)
    table.insert(self.window, value)
    if #self.window > self.windowSize then
        table.remove(self.window, 1)
    end
end

function Anomaly:isAnomaly(value)
    if #self.window < 5 then return false, 0 end
    local med = Stats.median(self.window)
    local mad = Stats.mad(self.window)
    local mz  = Stats.modifiedZscore(value, med, mad)
    return math.abs(mz) > self.threshold, mz
end

--========== CORRELATION PATTERNS (Default) ==========--
local function installDefaultPatterns(correlator, session, edr)
    -- Pattern 1: Credential Stealer (อ่านไฟล์ → encrypt → HTTP POST)
    correlator:addPattern({
        id       = "CREDENTIAL_EXFIL",
        severity = EDR.Severity.CRITICAL,
        within   = 15,
        steps = {
            { type = EDR.EventType.FILE_READ, filter = function(e)
                local d = tostring(e.data or ""):lower()
                return d:find("token") or d:find("cookie") or d:find(".env")
                    or d:find("password") or d:find("credential")
            end },
            { type = EDR.EventType.STRING_ENCODE },
            { type = EDR.EventType.HTTP_POST },
        },
        onMatch = function(events, elapsed)
            edr:raiseAlert({
                rule = "CREDENTIAL_EXFIL",
                severity = EDR.Severity.CRITICAL,
                message = "ตรวจพบรูปแบบ Credential Stealer (อ่านไฟล์ลับ → encode → POST)",
                evidence = events,
                elapsed = elapsed,
            })
        end,
    })

    -- Pattern 2: Remote Loader (HttpGet → loadstring → execute)
    correlator:addPattern({
        id       = "REMOTE_LOADER",
        severity = EDR.Severity.HIGH,
        within   = 10,
        steps = {
            { type = EDR.EventType.HTTP_GET },
            { type = EDR.EventType.FUNCTION_CALL, filter = function(e)
                return e.data and e.data.name == "loadstring"
            end },
        },
        onMatch = function(events, elapsed)
            edr:raiseAlert({
                rule = "REMOTE_LOADER",
                severity = EDR.Severity.HIGH,
                message = "ตรวจพบ Remote Loader (HttpGet → loadstring)",
                evidence = events,
                elapsed = elapsed,
            })
        end,
    })

    -- Pattern 3: Anti-Debug Probe
    correlator:addPattern({
        id       = "ANTI_DEBUG",
        severity = EDR.Severity.HIGH,
        within   = 5,
        steps = {
            { type = EDR.EventType.DEBUG_ACCESS, filter = function(e)
                return e.data and (e.data.name == "getinfo" or e.data.name == "sethook")
            end },
            { type = EDR.EventType.SUSPICIOUS_API },
        },
        onMatch = function(events, elapsed)
            edr:raiseAlert({
                rule = "ANTI_DEBUG",
                severity = EDR.Severity.HIGH,
                message = "ตรวจพบ Anti-Debug (debug.getinfo/sethook + API แปลก)",
                evidence = events,
                elapsed = elapsed,
            })
        end,
    })

    -- Pattern 4: Data Encrypt Burst (bxor/char จำนวนมากผิดปกติ)
    correlator:addPattern({
        id       = "ENCRYPT_BURST",
        severity = EDR.Severity.MEDIUM,
        within   = 3,
        steps = {
            { type = EDR.EventType.STRING_DECRYPT, filter = function(e)
                return (e.data and e.data.count or 0) > 500
            end },
            { type = EDR.EventType.NETWORK_REQUEST },
        },
        onMatch = function(events, elapsed)
            edr:raiseAlert({
                rule = "ENCRYPT_BURST",
                severity = EDR.Severity.MEDIUM,
                message = "ตรวจพบการ decrypt จำนวนมากตามด้วย network call",
                evidence = events,
                elapsed = elapsed,
            })
        end,
    })

    -- Pattern 5: Global Pollution (เขียน global ผิดปกติ)
    correlator:addPattern({
        id       = "GLOBAL_POLLUTION",
        severity = EDR.Severity.MEDIUM,
        within   = 10,
        steps = {
            { type = EDR.EventType.GLOBAL_WRITE, filter = function(e)
                return (e.data and e.data.count or 0) > 50
            end },
            { type = EDR.EventType.SUSPICIOUS_API },
        },
        onMatch = function(events, elapsed)
            edr:raiseAlert({
                rule = "GLOBAL_POLLUTION",
                severity = EDR.Severity.MEDIUM,
                message = "ตรวจพบการเขียน global ผิดปกติ (อาจเป็น hook installation)",
                evidence = events,
                elapsed = elapsed,
            })
        end,
    })
end

--========== EDR MAIN OBJECT ==========--
function EDR.new()
    local self = setmetatable({}, { __index = EDR })

    self.bus        = EventBus.new()
    self.buffer     = RingBuffer.new(EDR.Config.MAX_EVENTS)
    self.session    = Session.new()
    self.correlator = Correlator.new(self.bus, self.buffer)

    -- anomaly detectors ต่อ metric
    self.anomalies = {
        global_write_rate = Anomaly.new(30),
        network_rate      = Anomaly.new(30),
        decrypt_rate      = Anomaly.new(30),
        coroutine_rate    = Anomaly.new(30),
        file_read_rate    = Anomaly.new(30),
    }

    -- ตัวนับต่อ type ในหน้าต่างเวลา
    self.counters = {}
    -- alerts สะสม
    self.alerts   = {}
    -- callbacks
    self.onAlert  = nil
    -- watchdog
    self.watchdog = nil
    -- hook registry (ให้ module อื่นลงทะเบียน unhook)
    self.hookRegistry = {}

    installDefaultPatterns(self.correlator, self.session, self)

    return self
end

--========== LOGGING ==========--
function EDR:log(level, msg)
    if level > EDR.Config.LOG_LEVEL then return end
    local prefix = "[EDR][" .. self.session.phase .. "]"
    print(prefix .. " " .. tostring(msg))
end

--========== EVENT EMISSION ==========--
function EDR:emit(eventType, data, severity)
    local event = {
        type     = eventType,
        data     = data or {},
        severity = severity or EDR.Severity.INFO,
        t        = os.clock(),
        wall     = os.time(),
        seq      = self.session.events_processed + 1,
        phase    = self.session.phase,
    }

    -- push ลง ring buffer
    self.buffer:push(event)
    self.session.events_processed = event.seq

    -- นับต่อ type ในหน้าต่างเวลา
    self:_updateCounters(eventType)

    -- publish ผ่าน bus
    self.bus:publish(event)

    -- ตรวจ anomaly rate
    self:_checkRateAnomalies(eventType)

    return event
end

function EDR:_updateCounters(type)
    local key = type .. ":" .. math.floor(os.clock())
    self.counters[key] = (self.counters[key] or 0) + 1
    -- cleanup เก่า
    if self.session.events_processed % 1000 == 0 then
        self:_cleanupCounters()
    end
end

function EDR:_cleanupCounters()
    local now = math.floor(os.clock())
    for k in pairs(self.counters) do
        local t = tonumber(k:match(":(%d+)$"))
        if t and (now - t) > 60 then
            self.counters[k] = nil
        end
    end
end

function EDR:getRate(type, window)
    window = window or 5
    local now = math.floor(os.clock())
    local total = 0
    for i = 0, window - 1 do
        total = total + (self.counters[type .. ":" .. (now - i)] or 0)
    end
    return total / window
end

function EDR:_checkRateAnomalies(type)
    local rate = self:getRate(type, 3)
    local detector

    if type == EDR.EventType.GLOBAL_WRITE then detector = self.anomalies.global_write_rate
    elseif type == EDR.EventType.NETWORK_REQUEST then detector = self.anomalies.network_rate
    elseif type == EDR.EventType.STRING_DECRYPT then detector = self.anomalies.decrypt_rate
    elseif type == EDR.EventType.COROUTINE_CREATE then detector = self.anomalies.coroutine_rate
    elseif type == EDR.EventType.FILE_READ then detector = self.anomalies.file_read_rate
    end

    if detector then
        local isAnom, mz = detector:isAnomaly(rate)
        detector:push(rate)
        if isAnom then
            self:emit(EDR.EventType.ANOMALY, {
                metric = type,
                rate   = rate,
                zscore = mz,
            }, EDR.Severity.MEDIUM)
        end
    end
end

--========== ALERT ==========--
function EDR:raiseAlert(alert)
    alert.t = os.clock()
    alert.session_id = self.session.id
    table.insert(self.alerts, alert)
    self.session:addAlert(alert)

    -- เรียก callback ภายนอก (ให้ report/gui module จัดการ)
    if self.onAlert then
        pcall(self.onAlert, alert)
    end

    self:log(1, string.format("[ALERT/%s] %s", alert.rule or "?", alert.message or ""))
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

    -- ใช้ coroutine เป็น background loop (ไม่บล็อก main thread)
    local co = coroutine.create(function()
        while self.watchdog do
            coroutine.yield(EDR.Config.WATCHDOG_INTERVAL)
            self:emit(EDR.EventType.HEARTBEAT, {
                uptime    = self.session:elapsed(),
                events    = self.session.events_processed,
                alerts    = #self.alerts,
                dropped   = self.buffer.dropped,
            })

            if EDR.Config.ENABLE_CORRELATION then
                self.correlator:scan()
            end

            if EDR.Config.SELF_INTEGRITY then
                self:_checkIntegrity()
            end
        end
    end)

    -- ขับเคลื่อน coroutine ด้วย task.wait ถ้ามี, ถ้าไม่มีใช้ manual tick
    if task and task.spawn then
        task.spawn(function()
            while self.watchdog do
                local ok, waitTime = coroutine.resume(co)
                if not ok then break end
                task.wait(waitTime or EDR.Config.WATCHDOG_INTERVAL)
            end
        end)
    else
        -- fallback: manual tick (ผู้ใช้ต้องเรียก edr:tick() เอง)
        self._watchdogCo = co
    end
end

function EDR:tick()
    if self._watchdogCo then
        local ok, waitTime = coroutine.resume(self._watchdogCo)
        return waitTime
    end
end

function EDR:stopWatchdog()
    self.watchdog = false
end

--========== INTEGRITY CHECK ==========--
function EDR:_checkIntegrity()
    -- ตรวจว่าฟังก์ชันสำคัญยังเป็นตัวเดิม (ไม่ถูก hook ทับ)
    local checks = {
        { name = "pcall",      fn = pcall },
        { name = "tostring",   fn = tostring },
        { name = "setmetatable", fn = setmetatable },
    }
    for _, c in ipairs(checks) do
        if type(c.fn) ~= "function" then
            self:raiseAlert({
                rule = "SELF_INTEGRITY",
                severity = EDR.Severity.HIGH,
                message = "ตรวจพบการแก้ไขฟังก์ชันหลัก: " .. c.name,
            })
        end
    end
end

--========== REPORT ==========--
function EDR:summary()
    local s = self.session
    return {
        session_id    = s.id,
        fingerprint   = s.fingerprint,
        elapsed       = s:elapsed(),
        events        = s.events_processed,
        dropped       = self.buffer.dropped,
        alerts        = #self.alerts,
        by_severity   = self:_countBySeverity(),
        by_type       = self.bus.stats,
        phase         = s.phase,
    }
end

function EDR:_countBySeverity()
    local out = { INFO=0, LOW=0, MEDIUM=0, HIGH=0, CRITICAL=0 }
    for _, a in ipairs(self.alerts) do
        local sev = a.severity or 0
        if sev == 0 then out.INFO = out.INFO + 1
        elseif sev == 1 then out.LOW = out.LOW + 1
        elseif sev == 2 then out.MEDIUM = out.MEDIUM + 1
        elseif sev == 3 then out.HIGH = out.HIGH + 1
        elseif sev == 4 then out.CRITICAL = out.CRITICAL + 1 end
    end
    return out
end

--========== EXPORT ==========--
EDR.RingBuffer = RingBuffer
EDR.EventBus   = EventBus
EDR.Session    = Session
EDR.Correlator = Correlator
EDR.Stats      = Stats
EDR.Anomaly    = Anomaly

-- singleton instance
EDR._instance = nil

function EDR.get()
    if not EDR._instance then
        EDR._instance = EDR.new()
    end
    return EDR._instance
end

return EDR