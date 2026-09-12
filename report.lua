--[[
    ============================================================
    EDR Report v1.0 — Forensics + Timeline + IOC + Export
    ============================================================
    หลักการ:
    - IOC Extractor: ดึง indicator จาก events ทั้งหมด
    - Forensic Timeline: เรียง event ตามเวลา + correlate
    - Environment Diff: เปรียบเทียบ snapshot ก่อน/หลัง
    - Risk Curve: เก็บ risk score evolution
    - Executive Summary: สรุปแบบมนุษย์อ่าน
    - Export: JSON / Markdown / HTML (self-contained)
    - GUI: timeline view + IOC table + risk graph

    ใช้ร่วมกับ:
    - edr_core.lua : event buffer + alert
    - hooks.lua    : source ของ event
    - rules.lua    : alerts + risk score
    ============================================================
]]

local Report = {}

--========== CONFIG ==========--
Report.Config = {
    -- จำนวน event สูงสุดที่จะประมวลผลใน report (ป้องกัน memory)
    MAX_EVENTS_IN_REPORT = 50000,
    -- จำนวน timeline entry สูงสุด
    MAX_TIMELINE_ENTRIES = 500,
    -- จำนวน IOC สูงสุดต่อชนิด
    MAX_IOC_PER_TYPE     = 200,
    -- ความถี่ที่เก็บ risk sample (วินาที)
    RISK_SAMPLE_INTERVAL = 2,
    -- GUI mode: "compact" หรือ "full"
    GUI_MODE             = "full",
    -- เปิดการเก็บ environment snapshot
    ENABLE_ENV_SNAPSHOT  = true,
    -- เปิด deduplication ของ alert
    ENABLE_ALERT_DEDUP   = true,
    -- log level
    LOG_LEVEL            = 1,
}

--========== UTILITIES ==========--

local function now() return os.clock() end
local function walltime() return os.time() end

-- FNV-1a hash (32-bit) — ใช้ dedup + fingerprint
local function fnv1a(str)
    local hash = 2166136261
    for i = 1, #str do
        hash = bit32 and bit32.bxor(hash, str:byte(i)) or (hash ~ str:byte(i))
        if bit32 then
            hash = bit32.band(hash * 16777619, 0xFFFFFFFF)
        else
            hash = (hash * 16777619) % 4294967296
        end
    end
    return string.format("%08x", hash)
end

-- DJB2 hash (fallback ถ้าไม่มี bit32)
local function djb2(str)
    local hash = 5381
    for i = 1, #str do
        hash = ((hash * 33) + str:byte(i)) % 4294967296
    end
    return string.format("%08x", hash)
end

local function hash(str)
    if bit32 then return fnv1a(str) else return djb2(str) end
end

-- format เวลา
local function fmtDuration(sec)
    if sec < 60 then return string.format("%.1fs", sec) end
    if sec < 3600 then return string.format("%dm%ds", math.floor(sec/60), math.floor(sec%60)) end
    return string.format("%dh%dm", math.floor(sec/3600), math.floor((sec%3600)/60))
end

local function fmtTimestamp(t)
    return os.date("%Y-%m-%d %H:%M:%S", t)
end

local function fmtRelative(t, base)
    local d = t - base
    if d < 0 then d = 0 end
    return "+" .. fmtDuration(d)
end

-- pad string
local function padRight(s, n)
    s = tostring(s or "")
    if #s >= n then return s:sub(1, n) end
    return s .. string.rep(" ", n - #s)
end

local function padLeft(s, n)
    s = tostring(s or "")
    if #s >= n then return s:sub(1, n) end
    return string.rep(" ", n - #s) .. s
end

--========== SEVERITY LABELS ==========--
local SEVERITY_LABEL = {
    [0] = "INFO",
    [1] = "LOW",
    [2] = "MED",
    [3] = "HIGH",
    [4] = "CRIT",
}

local SEVERITY_ICON = {
    [0] = "·",
    [1] = "○",
    [2] = "◐",
    [3] = "●",
    [4] = "◆",
}

--========== IOC EXTRACTOR ==========--
-- ดึง indicator ทุกชนิดจาก event stream
local IOCExtractor = {}
IOCExtractor.__index = IOCExtractor

-- regex patterns
local PATTERNS = {
    url          = "https?://[%w%p]+",
    ipv4         = "%f[%d]%d+%.%d+%.%d+%.%d+%f[%D]",
    ipv6         = "%x%x?%x?%x?:%x%x?%x?%x?:%x%x?%x?%x?:%x%x?%x?%x?:%x%x?%x?%x?:%x%x?%x?%x?",
    domain       = "%f[%w][%w%-]+%.[%w%-]+%.[%a]+%f[%D]",
    md5          = "%f[%x]%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%f[%X]",
    sha1         = "%f[%x]%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%f[%X]",
    sha256       = "%f[%x]%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%f[%X]",
    btc_wallet   = "%f[%w][13][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9]%f[%W]",
    discord_tok  = "[%w%-_]+%.[%w%-_]+%.[%w%-_]+",
    telegram_bot = "%d+:AA[%w%-_]+",
    email        = "[%w%._%-]+@[%w%.%-]+%.[%a]+",
    file_path    = "[%a]:\\[%w%._\\%-]+",
    unix_path    = "/[%w%._%-/]+",
    base64_long  = "%f[%w][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/=]+%f[%W]",
}

-- whitelist: domain ที่ไม่นับเป็น IOC
local DOMAIN_WHITELIST = {
    ["roblox.com"]      = true,
    ["robloxlabs.com"]  = true,
    ["rbxcdn.com"]      = true,
    ["rbx.com"]         = true,
    ["luau.org"]        = true,
    ["github.com"]      = true,
    ["githubusercontent.com"] = true,
}

local function isWhitelisted(domain)
    for w in pairs(DOMAIN_WHITELIST) do
        if domain == w or domain:sub(-#w - 1) == "." .. w then
            return true
        end
    end
    return false
end

-- กรอง private IP
local function isPrivateIP(ip)
    local a, b = ip:match("^(%d+)%.(%d+)%.")
    a, b = tonumber(a), tonumber(b)
    if not a then return false end
    if a == 10 then return true end
    if a == 172 and b and b >= 16 and b <= 31 then return true end
    if a == 192 and b == 168 then return true end
    if a == 127 then return true end
    if a == 0 then return true end
    return false
end

function IOCExtractor.new()
    return setmetatable({
        indicators = {},   -- [type] = { [value] = {count, first_seen, last_seen, contexts} }
        total      = 0,
        by_type    = {},
    }, IOCExtractor)
end

function IOCExtractor:add(iocType, value, context)
    if not value or #value == 0 or #value > 500 then return end

    local bucket = self.indicators[iocType]
    if not bucket then
        bucket = {}
        self.indicators[iocType] = bucket
    end

    local entry = bucket[value]
    local t = now()
    if entry then
        entry.count = entry.count + 1
        entry.last_seen = t
        if context and #entry.contexts < 3 then
            table.insert(entry.contexts, context)
        end
    else
        -- จำกัดจำนวนต่อชนิด
        local n = 0
        for _ in pairs(bucket) do n = n + 1 end
        if n >= Report.Config.MAX_IOC_PER_TYPE then return end

        bucket[value] = {
            value      = value,
            count      = 1,
            first_seen = t,
            last_seen  = t,
            contexts   = context and { context } or {},
        }
        self.total = self.total + 1
        self.by_type[iocType] = (self.by_type[iocType] or 0) + 1
    end
end

-- สแกน string หา IOC ทุกชนิด
function IOCExtractor:scanString(s, context)
    if type(s) ~= "string" or #s < 4 or #s > 10000 then return end

    -- URL
    for url in s:gmatch(PATTERNS.url) do
        self:add("url", url, context)
    end

    -- IPv4
    for ip in s:gmatch(PATTERNS.ipv4) do
        if not isPrivateIP(ip) then
            self:add("ipv4", ip, context)
        end
    end

    -- Domain
    for d in s:gmatch(PATTERNS.domain) do
        if not isWhitelisted(d) and #d > 4 and #d < 100 then
            self:add("domain", d, context)
        end
    end

    -- Hash
    for h in s:gmatch(PATTERNS.sha256) do self:add("sha256", h, context) end
    for h in s:gmatch(PATTERNS.sha1) do
        if #h == 40 then self:add("sha1", h, context) end
    end
    for h in s:gmatch(PATTERNS.md5) do
        if #h == 32 then self:add("md5", h, context) end
    end

    -- Discord token
    for tok in s:gmatch(PATTERNS.discord_tok) do
        if #tok > 50 and #tok < 100 and tok:find("%.") then
            local parts = 0
            for _ in tok:gmatch("%.") do parts = parts + 1 end
            if parts == 2 then self:add("discord_token", tok, context) end
        end
    end

    -- Telegram bot
    for tok in s:gmatch(PATTERNS.telegram_bot) do
        self:add("telegram_bot", tok, context)
    end

    -- Email
    for e in s:gmatch(PATTERNS.email) do
        if #e < 100 then self:add("email", e, context) end
    end

    -- Windows path
    for p in s:gmatch(PATTERNS.file_path) do
        self:add("win_path", p, context)
    end
end

function IOCExtractor:scanEvents(events)
    for _, e in ipairs(events) do
        if e.data then
            local ctx = e.type .. " @" .. string.format("%.2f", e.t)
            -- สแกนทุก string field ใน data
            for k, v in pairs(e.data) do
                if type(v) == "string" then
                    self:scanString(v, ctx)
                end
            end
        end
    end
end

function IOCExtractor:getAll()
    local out = {}
    for iocType, bucket in pairs(self.indicators) do
        for _, entry in pairs(bucket) do
            table.insert(out, {
                type       = iocType,
                value      = entry.value,
                count      = entry.count,
                first_seen = entry.first_seen,
                last_seen  = entry.last_seen,
                contexts   = entry.contexts,
            })
        end
    end
    -- เรียงตาม count มากสุด
    table.sort(out, function(a, b)
        if a.count == b.count then return a.type < b.type end
        return a.count > b.count
    end)
    return out
end

function IOCExtractor:summary()
    return self.by_type
end

--========== RISK CURVE TRACKER ==========--
local RiskCurve = {}
RiskCurve.__index = RiskCurve

function RiskCurve.new()
    return setmetatable({
        samples    = {},    -- { {t, risk, alerts, events}, ... }
        lastSample = 0,
    }, RiskCurve)
end

function RiskCurve:sample(risk, alerts, events)
    local t = now()
    if t - self.lastSample < Report.Config.RISK_SAMPLE_INTERVAL then return end
    self.lastSample = t
    table.insert(self.samples, {
        t      = t,
        risk   = risk,
        alerts = alerts,
        events = events,
    })
    -- จำกัดจำนวน sample
    if #self.samples > 500 then
        table.remove(self.samples, 1)
    end
end

function RiskCurve:renderASCII(width, height)
    width  = width  or 60
    height = height or 8
    if #self.samples < 2 then return "(insufficient data)" end

    -- downsample
    local cols = {}
    local step = math.max(1, math.floor(#self.samples / width))
    for i = 1, #self.samples, step do
        table.insert(cols, self.samples[i])
    end

    -- สร้าง grid
    local grid = {}
    for y = 1, height do
        grid[y] = {}
        for x = 1, #cols do grid[y][x] = " " end
    end

    -- วาด
    local maxRisk = 1.0
    for _, s in ipairs(cols) do
        local x = 1
        for i, cs in ipairs(cols) do
            if cs == s then x = i; break end
        end
    end

    for i, s in ipairs(cols) do
        local y = math.floor((1 - s.risk) * (height - 1)) + 1
        y = math.max(1, math.min(height, y))
        grid[y][i] = "*"
    end

    -- รวม
    local lines = {}
    for y = 1, height do
        local riskLevel = string.format("%4.0f%%", (1 - (y-1)/(height-1)) * 100)
        table.insert(lines, riskLevel .. " │ " .. table.concat(grid[y]))
    end
    table.insert(lines, "     └" .. string.rep("─", #cols))

    return table.concat(lines, "\n")
end

--========== ENVIRONMENT SNAPSHOT ==========--
local EnvSnapshot = {}

function EnvSnapshot.capture()
    local snap = {
        time    = walltime(),
        globals = {},
        funcs   = {},
        metas   = {},
    }

    local env = getgenv and getgenv() or _G
    local count = 0
    for k, v in pairs(env) do
        count = count + 1
        if count > 2000 then break end

        snap.globals[k] = type(v)
        if type(v) == "function" then
            local info = debug and debug.getinfo and debug.getinfo(v, "S")
            snap.funcs[k] = {
                source = info and info.short_src or "?",
                hash   = hash(tostring(v)),
            }
        end
    end

    return snap
end

function EnvSnapshot.diff(before, after)
    local added, removed, changed = {}, {}, {}

    for k, t in pairs(after.globals) do
        if before.globals[k] == nil then
            table.insert(added, { key = k, type = t })
        elseif before.globals[k] ~= t then
            table.insert(changed, { key = k, from = before.globals[k], to = t })
        end
    end

    for k, t in pairs(before.globals) do
        if after.globals[k] == nil then
            table.insert(removed, { key = k, type = t })
        end
    end

    -- ตรวจฟังก์ชันที่ถูก redefine
    local redefined = {}
    for k, info in pairs(after.funcs) do
        if before.funcs[k] and before.funcs[k].hash ~= info.hash then
            table.insert(redefined, {
                key    = k,
                before = before.funcs[k].source,
                after  = info.source,
            })
        end
    end

    return {
        added      = added,
        removed    = removed,
        changed    = changed,
        redefined  = redefined,
        total_added   = #added,
        total_removed = #removed,
        total_changed = #changed,
        total_redefined = #redefined,
    }
end

--========== TIMELINE BUILDER ==========--
local Timeline = {}
Timeline.__index = Timeline

function Timeline.new()
    return setmetatable({
        entries = {},
        by_type = {},
    }, Timeline)
end

-- ระดับความสำคัญของแต่ละ event type ต่อ timeline
local TIMELINE_PRIORITY = {
    ALERT              = 100,
    SUSPICIOUS_API     = 90,
    HTTP_POST          = 85,
    HTTP_GET           = 80,
    NETWORK_REQUEST    = 75,
    FILE_WRITE         = 70,
    FILE_READ          = 65,
    FUNCTION_CALL      = 60,
    FUNCTION_REDEFINE  = 60,
    THREAD_IDENTITY    = 55,
    DEBUG_ACCESS       = 50,
    ENV_ACCESS         = 45,
    METATABLE_ACCESS   = 40,
    GLOBAL_WRITE       = 35,
    STRING_DECRYPT     = 30,
    STRING_ENCODE      = 25,
    COROUTINE_CREATE   = 20,
    COROUTINE_RESUME   = 15,
    OPCODE_CALL        = 5,
    HEARTBEAT          = 1,
}

function Timeline:add(event, priority)
    priority = priority or TIMELINE_PRIORITY[event.type] or 10
    table.insert(self.entries, {
        t        = event.t,
        wall     = event.wall,
        type     = event.type,
        severity = event.severity or 0,
        data     = event.data,
        priority = priority,
    })
end

function Timeline:build(events, alerts)
    self.entries = {}

    -- เพิ่ม events
    for _, e in ipairs(events) do
        self:add(e)
    end

    -- เพิ่ม alerts (priority สูงสุด)
    for _, a in ipairs(alerts) do
        table.insert(self.entries, {
            t        = a.t,
            wall     = a.wall or walltime(),
            type     = "ALERT",
            severity = a.severity or 3,
            data     = { rule = a.rule, message = a.message, score = a.score },
            priority = 100,
        })
    end

    -- เรียงตามเวลา
    table.sort(self.entries, function(a, b) return a.t < b.t end)

    -- ตัดให้อยู่ในขอบเขต
    if #self.entries > Report.Config.MAX_TIMELINE_ENTRIES then
        -- เก็บ priority สูงสุด
        local sorted = {}
        for i, e in ipairs(self.entries) do sorted[i] = e end
        table.sort(sorted, function(a, b) return a.priority > b.priority end)
        local keep = {}
        for i = 1, Report.Config.MAX_TIMELINE_ENTRIES do
            keep[sorted[i]] = true
        end
        local filtered = {}
        for _, e in ipairs(self.entries) do
            if keep[e] then table.insert(filtered, e) end
        end
        self.entries = filtered
    end

    return self.entries
end

function Timeline:renderASCII(opts)
    opts = opts or {}
    local lines = {}
    local t0 = self.entries[1] and self.entries[1].t or 0

    for _, e in ipairs(self.entries) do
        local icon = SEVERITY_ICON[e.severity] or "·"
        local sevLabel = SEVERITY_LABEL[e.severity] or "?"
        local rel = fmtRelative(e.t, t0)
        local dtype = padRight(e.type, 18)

        local detail = ""
        if e.type == "ALERT" then
            detail = (e.data.rule or "") .. " — " .. (e.data.message or ""):sub(1, 50)
        elseif e.data then
            if e.data.url then detail = e.data.url:sub(1, 60)
            elseif e.data.path then detail = e.data.path:sub(1, 60)
            elseif e.data.key then detail = "global:" .. e.data.key
            elseif e.data.name then detail = e.data.name
            elseif e.data.value then detail = tostring(e.data.value):sub(1, 60)
            elseif e.data.count then detail = "x" .. tostring(e.data.count)
            end
        end

        table.insert(lines, string.format("%s %s [%s] %s %s",
            icon, padLeft(rel, 10), padLeft(sevLabel, 4), dtype, detail))
    end

    return table.concat(lines, "\n")
end

--========== ALERT DEDUP ==========--
local function dedupAlerts(alerts)
    if not Report.Config.ENABLE_ALERT_DEDUP then return alerts end

    local seen = {}
    local out = {}
    for _, a in ipairs(alerts) do
        local key = (a.rule or "?") .. ":" .. tostring(a.message or ""):sub(1, 50)
        if not seen[key] then
            seen[key] = a
            table.insert(out, a)
        else
            -- merge count
            seen[key].count = (seen[key].count or 1) + 1
        end
    end
    return out
end

--========== EXECUTIVE SUMMARY ==========--
local function buildExecutiveSummary(report)
    local lines = {}
    local s = report.session
    local stats = report.stats

    -- Header
    table.insert(lines, "# Executive Summary")
    table.insert(lines, "")
    table.insert(lines, string.format("**Session ID:** `%s`", s.id))
    table.insert(lines, string.format("**Fingerprint:** `%s`", s.fingerprint or "N/A"))
    table.insert(lines, string.format("**Duration:** %s", fmtDuration(s.elapsed)))
    table.insert(lines, string.format("**Events Processed:** %d", s.events))
    table.insert(lines, string.format("**Alerts:** %d (unique: %d)", stats.total_alerts, stats.unique_alerts))
    table.insert(lines, "")

    -- Verdict
    local risk = report.risk.overall
    local verdict
    if risk >= 0.85 then verdict = "🔴 **MALICIOUS** — Strong evidence of malicious behavior"
    elseif risk >= 0.65 then verdict = "🟠 **SUSPICIOUS** — Multiple indicators of concern"
    elseif risk >= 0.35 then verdict = "🟡 **POTENTIALLY UNWANTED** — Some suspicious signals"
    elseif risk >= 0.15 then verdict = "🟢 **LOW RISK** — Minor signals detected"
    else verdict = "⚪ **CLEAN** — No significant threats detected"
    end

    table.insert(lines, "## Verdict")
    table.insert(lines, "")
    table.insert(lines, verdict)
    table.insert(lines, "")
    table.insert(lines, string.format("**Risk Score:** %.1f%% (probabilistic aggregate)", risk * 100))
    table.insert(lines, "")

    -- Top rules matched
    if #report.alerts > 0 then
        table.insert(lines, "## Top Triggered Rules")
        table.insert(lines, "")
        local sorted = {}
        for _, a in ipairs(report.alerts) do sorted[#sorted+1] = a end
        table.sort(sorted, function(x, y) return (x.score or 0) > (y.score or 0) end)
        for i = 1, math.min(10, #sorted) do
            local a = sorted[i]
            table.insert(lines, string.format("%d. **%s** (score: %.2f, severity: %s)",
                i, a.rule or "?", a.score or 0, SEVERITY_LABEL[a.severity or 0]))
            if a.message then
                table.insert(lines, string.format("   - %s", a.message))
            end
        end
        table.insert(lines, "")
    end

    -- IOC summary
    if report.ioc and next(report.ioc.by_type) then
        table.insert(lines, "## Indicators of Compromise")
        table.insert(lines, "")
        for t, count in pairs(report.ioc.by_type) do
            table.insert(lines, string.format("- **%s:** %d unique", t, count))
        end
        table.insert(lines, "")
    end

    -- Environment changes
    if report.envdiff then
        local d = report.envdiff
        table.insert(lines, "## Environment Changes")
        table.insert(lines, "")
        table.insert(lines, string.format("- Globals added: %d", d.total_added))
        table.insert(lines, string.format("- Globals removed: %d", d.total_removed))
        table.insert(lines, string.format("- Functions redefined: %d", d.total_redefined))
        table.insert(lines, "")
    end

    return table.concat(lines, "\n")
end

--========== EXPORTERS ==========--
local Exporter = {}

function Exporter.toMarkdown(report)
    local lines = {}
    table.insert(lines, buildExecutiveSummary(report))
    table.insert(lines, "")
    table.insert(lines, "---")
    table.insert(lines, "")

    -- Timeline
    table.insert(lines, "## Forensic Timeline")
    table.insert(lines, "")
    table.insert(lines, "```")
    table.insert(lines, report.timeline:renderASCII())
    table.insert(lines, "```")
    table.insert(lines, "")

    -- Risk curve
    table.insert(lines, "## Risk Evolution")
    table.insert(lines, "")
    table.insert(lines, "```")
    table.insert(lines, report.risk_curve:renderASCII(60, 8))
    table.insert(lines, "```")
    table.insert(lines, "")

    -- IOC table
    table.insert(lines, "## IOCs (Top 50)")
    table.insert(lines, "")
    table.insert(lines, "| Type | Value | Count |")
    table.insert(lines, "|------|-------|-------|")
    local iocs = report.ioc:getAll()
    for i = 1, math.min(50, #iocs) do
        local ioc = iocs[i]
        local v = ioc.value:gsub("|", "\\|"):sub(1, 80)
        table.insert(lines, string.format("| %s | `%s` | %d |", ioc.type, v, ioc.count))
    end
    table.insert(lines, "")

    -- Env diff
    if report.envdiff then
        table.insert(lines, "## Environment Modifications")
        table.insert(lines, "")
        local d = report.envdiff
        if #d.redefined > 0 then
            table.insert(lines, "### Redefined Functions")
            for _, r in ipairs(d.redefined) do
                table.insert(lines, string.format("- `%s` (%s → %s)", r.key, r.before, r.after))
            end
        end
        if #d.added > 0 then
            table.insert(lines, "### Added Globals (top 30)")
            for i = 1, math.min(30, #d.added) do
                table.insert(lines, string.format("- `%s` (%s)", d.added[i].key, d.added[i].type))
            end
        end
        table.insert(lines, "")
    end

    return table.concat(lines, "\n")
end

function Exporter.toJSON(report)
    local function esc(s)
        s = tostring(s or "")
        s = s:gsub("\\", "\\\\"):gsub("\"", "\\\""):gsub("\n", "\\n"):gsub("\r", "\\r"):gsub("\t", "\\t")
        return s
    end

    local function encodeTable(t, indent)
        indent = indent or 0
        local pad = string.rep("  ", indent)
        local lines = {}
        local isArray = #t > 0
        if isArray then
            table.insert(lines, "[")
            for i, v in ipairs(t) do
                local val = type(v) == "table" and encodeTable(v, indent + 1) or
                    (type(v) == "string" and ("\"" .. esc(v) .. "\"") or tostring(v))
                table.insert(lines, pad .. "  " .. val .. (i < #t and "," or ""))
            end
            table.insert(lines, pad .. "]")
        else
            table.insert(lines, "{")
            local keys = {}
            for k in pairs(t) do table.insert(keys, k) end
            for i, k in ipairs(keys) do
                local v = t[k]
                local val = type(v) == "table" and encodeTable(v, indent + 1) or
                    (type(v) == "string" and ("\"" .. esc(v) .. "\"") or tostring(v))
                table.insert(lines, pad .. "  \"" .. esc(k) .. "\": " .. val .. (i < #keys and "," or ""))
            end
            table.insert(lines, pad .. "}")
        end
        return table.concat(lines, "\n")
    end

    local out = {
        session = {
            id          = report.session.id,
            fingerprint = report.session.fingerprint,
            elapsed     = report.session.elapsed,
            events      = report.session.events,
        },
        risk   = report.risk,
        stats  = report.stats,
        alerts = {},
        ioc    = {},
        timeline = {},
    }

    for _, a in ipairs(report.alerts) do
        table.insert(out.alerts, {
            rule     = a.rule,
            severity = a.severity,
            score    = a.score,
            message  = a.message,
            time     = a.t,
        })
    end

    for t, list in pairs(report.ioc.indicators) do
        out.ioc[t] = {}
        for _, ioc in pairs(list) do
            table.insert(out.ioc[t], { value = ioc.value, count = ioc.count })
        end
    end

    for _, e in ipairs(report.timeline.entries) do
        table.insert(out.timeline, {
            t        = e.t,
            type     = e.type,
            severity = e.severity,
        })
    end

    return encodeTable(out, 0)
end

function Exporter.toHTML(report)
    local md = Exporter.toMarkdown(report)
    -- แปลง markdown เบาๆ เป็น HTML
    local html = {}
    table.insert(html, "<!DOCTYPE html><html><head><meta charset='utf-8'>")
    table.insert(html, "<title>EDR Report — " .. report.session.id .. "</title>")
    table.insert(html, "<style>")
    table.insert(html, "body{font-family:system-ui,monospace;background:#0d1117;color:#c9d1d9;padding:20px;max-width:1000px;margin:auto}")
    table.insert(html, "h1{color:#58a6ff;border-bottom:2px solid #30363d;padding-bottom:8px}")
    table.insert(html, "h2{color:#79c0ff;margin-top:30px}")
    table.insert(html, "h3{color:#a5d6ff}")
    table.insert(html, "pre{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px;overflow:auto;font-size:12px}")
    table.insert(html, "code{background:#161b22;padding:2px 6px;border-radius:3px;font-size:12px}")
    table.insert(html, "table{border-collapse:collapse;width:100%}")
    table.insert(html, "td,th{border:1px solid #30363d;padding:6px 10px;text-align:left;font-size:12px}")
    table.insert(html, "th{background:#161b22}")
    table.insert(html, ".critical{color:#f85149}.high{color:#ff7b72}.medium{color:#d29922}.low{color:#7ee787}")
    table.insert(html, "</style></head><body><pre>")
    table.insert(html, md:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;"))
    table.insert(html, "</pre></body></html>")
    return table.concat(html, "\n")
end

--========== REPORT OBJECT ==========--
local ReportObj = {}
ReportObj.__index = ReportObj

function Report.new(edr, rules)
    return setmetatable({
        edr         = edr,
        rules       = rules,
        session     = edr.session,
        ioc         = IOCExtractor.new(),
        risk_curve  = RiskCurve.new(),
        timeline    = Timeline.new(),
        alerts      = {},
        env_before  = nil,
        env_after   = nil,
        envdiff     = nil,
        stats       = {
            total_alerts  = 0,
            unique_alerts = 0,
        },
        risk        = {
            overall    = 0,
            peak       = 0,
            first_high = nil,
        },
        generated   = nil,
    }, ReportObj)
end

function ReportObj:captureBefore()
    if Report.Config.ENABLE_ENV_SNAPSHOT then
        self.env_before = EnvSnapshot.capture()
    end
end

function ReportObj:captureAfter()
    if Report.Config.ENABLE_ENV_SNAPSHOT then
        self.env_after = EnvSnapshot.capture()
        if self.env_before then
            self.envdiff = EnvSnapshot.diff(self.env_before, self.env_after)
        end
    end
end

function ReportObj:update()
    local edr = self.edr

    -- IOC scan จาก event ใหม่ (ใช้ buffer snapshot)
    local events = edr.buffer:snapshot()
    self.ioc:scanEvents(events)

    -- อัปเดต alerts
    self.alerts = edr.alerts
    self.stats.total_alerts = #self.alerts
    self.stats.unique_alerts = #dedupAlerts(self.alerts)

    -- คำนวณ risk
    local risk, _ = Rules.computeSessionRisk(self.alerts)
    self.risk.overall = risk
    if risk > self.risk.peak then self.risk.peak = risk end
    if not self.risk.first_high and risk >= 0.65 then
        self.risk.first_high = now()
    end

    -- sample risk curve
    self.risk_curve:sample(risk, #self.alerts, edr.session.events_processed)
end

function ReportObj:finalize()
    self:captureAfter()
    self:update()

    -- สร้าง timeline
    local events = self.edr.buffer:snapshot()
    self.timeline:build(events, self.alerts)

    self.generated = walltime()
    return self
end

function ReportObj:exportMarkdown() return Exporter.toMarkdown(self) end
function ReportObj:exportJSON()     return Exporter.toJSON(self) end
function ReportObj:exportHTML()     return Exporter.toHTML(self) end

function ReportObj:saveToFile(path, format)
    format = format or "markdown"
    local content
    if format == "json" then content = self:exportJSON()
    elseif format == "html" then content = self:exportHTML()
    else content = self:exportMarkdown() end

    -- ใช้ writefile ถ้ามี
    local env = getgenv and getgenv() or _G
    if type(env.writefile) == "function" then
        local ok, err = pcall(env.writefile, path, content)
        return ok, err
    end
    return false, "writefile not available"
end

--========== GUI ==========--
local function buildGUI(report)
    local parentGui
    local CoreGui = game:GetService("CoreGui")
    local ok, cg = pcall(function() return CoreGui end)
    if ok and cg then parentGui = cg
    else parentGui = game:GetService("Players").LocalPlayer:WaitForChild("PlayerGui") end

    local gui = Instance.new("ScreenGui")
    gui.Name = "EDR_Report_" .. tostring(math.random(1000, 9999))
    gui.ResetOnSpawn = false
    gui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
    gui.Parent = parentGui

    -- Main frame
    local main = Instance.new("Frame")
    main.Size = UDim2.new(0, 720, 0, 520)
    main.Position = UDim2.new(0.5, -360, 0.5, -260)
    main.BackgroundColor3 = Color3.fromRGB(13, 17, 23)
    main.BorderSizePixel = 0
    main.Active = true
    main.Draggable = true
    main.Parent = gui
    Instance.new("UICorner", main).CornerRadius = UDim.new(0, 12)

    local stroke = Instance.new("UIStroke", main)
    stroke.Color = Color3.fromRGB(48, 54, 61)
    stroke.Thickness = 1.5

    -- Title bar
    local title = Instance.new("TextLabel")
    title.Size = UDim2.new(1, 0, 0, 36)
    title.BackgroundColor3 = Color3.fromRGB(22, 27, 34)
    title.BorderSizePixel = 0
    title.Text = "  EDR Report — " .. report.session.id
    title.TextColor3 = Color3.fromRGB(88, 166, 255)
    title.Font = Enum.Font.GothamBold
    title.TextSize = 14
    title.TextXAlignment = Enum.TextXAlignment.Left
    title.Parent = main
    Instance.new("UICorner", title).CornerRadius = UDim.new(0, 12)

    -- Close
    local close = Instance.new("TextButton")
    close.Size = UDim2.new(0, 30, 0, 26)
    close.Position = UDim2.new(1, -34, 0, 5)
    close.BackgroundColor3 = Color3.fromRGB(180, 50, 50)
    close.BorderSizePixel = 0
    close.Text = "X"
    close.TextColor3 = Color3.fromRGB(255, 255, 255)
    close.Font = Enum.Font.GothamBold
    close.TextSize = 12
    close.Parent = title
    Instance.new("UICorner", close).CornerRadius = UDim.new(0, 6)
    close.MouseButton1Click:Connect(function() gui:Destroy() end)

    -- Risk banner
    local riskBanner = Instance.new("Frame")
    riskBanner.Size = UDim2.new(1, -24, 0, 60)
    riskBanner.Position = UDim2.new(0, 12, 0, 46)
    riskBanner.BackgroundColor3 = Color3.fromRGB(22, 27, 34)
    riskBanner.BorderSizePixel = 0
    riskBanner.Parent = main
    Instance.new("UICorner", riskBanner).CornerRadius = UDim.new(0, 8)

    local riskLabel = Instance.new("TextLabel")
    riskLabel.Size = UDim2.new(1, -20, 0, 26)
    riskLabel.Position = UDim2.new(0, 10, 0, 6)
    riskLabel.BackgroundTransparency = 1
    riskLabel.Text = "Risk Score"
    riskLabel.TextColor3 = Color3.fromRGB(201, 209, 217)
    riskLabel.Font = Enum.Font.Gotham
    riskLabel.TextSize = 12
    riskLabel.TextXAlignment = Enum.TextXAlignment.Left
    riskLabel.Parent = riskBanner

    local riskValue = Instance.new("TextLabel")
    riskValue.Size = UDim2.new(1, -20, 0, 24)
    riskValue.Position = UDim2.new(0, 10, 0, 28)
    riskValue.BackgroundTransparency = 1
    riskValue.Text = string.format("%.1f%%", report.risk.overall * 100)
    riskValue.Font = Enum.Font.GothamBold
    riskValue.TextSize = 20
    riskValue.TextXAlignment = Enum.TextXAlignment.Left
    riskValue.Parent = riskBanner

    if report.risk.overall >= 0.85 then
        riskValue.TextColor3 = Color3.fromRGB(248, 81, 73)
    elseif report.risk.overall >= 0.65 then
        riskValue.TextColor3 = Color3.fromRGB(255, 123, 114)
    elseif report.risk.overall >= 0.35 then
        riskValue.TextColor3 = Color3.fromRGB(210, 153, 34)
    else
        riskValue.TextColor3 = Color3.fromRGB(126, 231, 135)
    end

    -- Tab buttons
    local tabBar = Instance.new("Frame")
    tabBar.Size = UDim2.new(1, -24, 0, 30)
    tabBar.Position = UDim2.new(0, 12, 0, 114)
    tabBar.BackgroundColor3 = Color3.fromRGB(22, 27, 34)
    tabBar.BorderSizePixel = 0
    tabBar.Parent = main
    Instance.new("UICorner", tabBar).CornerRadius = UDim.new(0, 6)
    local tabLayout = Instance.new("UIListLayout", tabBar)
    tabLayout.FillDirection = Enum.FillDirection.Horizontal
    tabLayout.Padding = UDim.new(0, 4)

    -- Content area
    local content = Instance.new("ScrollingFrame")
    content.Size = UDim2.new(1, -24, 1, -160)
    content.Position = UDim2.new(0, 12, 0, 150)
    content.BackgroundColor3 = Color3.fromRGB(22, 27, 34)
    content.BorderSizePixel = 0
    content.ScrollBarThickness = 8
    content.CanvasSize = UDim2.new(0, 0, 0, 0)
    content.AutomaticCanvasSize = Enum.AutomaticSize.Y
    content.Parent = main
    Instance.new("UICorner", content).CornerRadius = UDim.new(0, 8)

    local contentLayout = Instance.new("UIListLayout", content)
    contentLayout.Padding = UDim.new(0, 4)
    contentLayout.SortOrder = Enum.SortOrder.LayoutOrder

    local contentPad = Instance.new("UIPadding", content)
    contentPad.PaddingTop = UDim.new(0, 8)
    contentPad.PaddingLeft = UDim.new(0, 10)
    contentPad.PaddingRight = UDim.new(0, 10)
    contentPad.PaddingBottom = UDim.new(0, 8)

    -- ตัวช่วยสร้าง label
    local function makeLabel(text, color, size, bold)
        local lbl = Instance.new("TextLabel")
        lbl.Size = UDim2.new(1, 0, 0, size or 18)
        lbl.BackgroundTransparency = 1
        lbl.Text = text
        lbl.TextColor3 = color or Color3.fromRGB(201, 209, 217)
        lbl.Font = bold and Enum.Font.GothamBold or Enum.Font.Code
        lbl.TextSize = 12
        lbl.TextXAlignment = Enum.TextXAlignment.Left
        lbl.TextWrapped = true
        lbl.TextYAlignment = Enum.TextYAlignment.Top
        lbl.Parent = content
        return lbl
    end

    -- เนื้อหาแต่ละ tab
    local tabs = {}
    local currentTab = nil

    local function clearContent()
        for _, child in ipairs(content:GetChildren()) do
            if child:IsA("TextLabel") or child:IsA("Frame") then
                child:Destroy()
            end
        end
    end

    local function renderSummary()
        clearContent()
        makeLabel("SESSION SUMMARY", Color3.fromRGB(88, 166, 255), 20, true)
        makeLabel("")
        makeLabel("Session ID:    " .. report.session.id)
        makeLabel("Fingerprint:   " .. (report.session.fingerprint or "?"))
        makeLabel("Duration:      " .. fmtDuration(report.session.elapsed))
        makeLabel("Events:        " .. tostring(report.session.events))
        makeLabel("Alerts:        " .. tostring(report.stats.total_alerts) ..
            " (" .. report.stats.unique_alerts .. " unique)")
        makeLabel("Peak Risk:     " .. string.format("%.1f%%", report.risk.peak * 100))
        makeLabel("")
        makeLabel("TOP TRIGGERED RULES", Color3.fromRGB(88, 166, 255), 20, true)
        makeLabel("")
        local sorted = {}
        for _, a in ipairs(report.alerts) do table.insert(sorted, a) end
        table.sort(sorted, function(x, y) return (x.score or 0) > (y.score or 0) end)
        for i = 1, math.min(10, #sorted) do
            local a = sorted[i]
            local sevName = SEVERITY_LABEL[a.severity or 0]
            makeLabel(string.format("%d. [%s] %s (%.2f)",
                i, sevName, a.rule or "?", a.score or 0))
        end
    end

    local function renderTimeline()
        clearContent()
        makeLabel("FORENSIC TIMELINE", Color3.fromRGB(88, 166, 255), 20, true)
        makeLabel("")
        local txt = report.timeline:renderASCII()
        for line in txt:gmatch("[^\n]+") do
            makeLabel(line, Color3.fromRGB(201, 209, 217), 14)
        end
    end

    local function renderIOC()
        clearContent()
        makeLabel("INDICATORS OF COMPROMISE", Color3.fromRGB(88, 166, 255), 20, true)
        makeLabel("")
        local iocs = report.ioc:getAll()
        for i = 1, math.min(100, #iocs) do
            local ioc = iocs[i]
            local color = Color3.fromRGB(201, 209, 217)
            if ioc.type == "url" or ioc.type == "ipv4" then
                color = Color3.fromRGB(255, 123, 114)
            elseif ioc.type == "discord_token" or ioc.type == "telegram_bot" then
                color = Color3.fromRGB(248, 81, 73)
            end
            makeLabel(string.format("[%s] %s  (×%d)", ioc.type, ioc.value:sub(1, 80), ioc.count), color, 14)
        end
    end

    local function renderRiskCurve()
        clearContent()
        makeLabel("RISK EVOLUTION", Color3.fromRGB(88, 166, 255), 20, true)
        makeLabel("")
        local graph = report.risk_curve:renderASCII(70, 10)
        for line in graph:gmatch("[^\n]+") do
            makeLabel(line, Color3.fromRGB(126, 231, 135), 14)
        end
    end

    local function renderEnv()
        clearContent()
        makeLabel("ENVIRONMENT MODIFICATIONS", Color3.fromRGB(88, 166, 255), 20, true)
        makeLabel("")
        if not report.envdiff then
            makeLabel("(no snapshot available)")
            return
        end
        local d = report.envdiff
        makeLabel(string.format("Added globals:      %d", d.total_added))
        makeLabel(string.format("Removed globals:    %d", d.total_removed))
        makeLabel(string.format("Changed types:      %d", d.total_changed))
        makeLabel(string.format("Redefined funcs:    %d", d.total_redefined))
        makeLabel("")
        makeLabel("REDEFINED FUNCTIONS", Color3.fromRGB(248, 81, 73), 16, true)
        for i = 1, math.min(20, #d.redefined) do
            local r = d.redefined[i]
            makeLabel(string.format("  • %s (%s → %s)", r.key, r.before, r.after))
        end
        makeLabel("")
        makeLabel("ADDED GLOBALS (top 20)", Color3.fromRGB(210, 153, 34), 16, true)
        for i = 1, math.min(20, #d.added) do
            local a = d.added[i]
            makeLabel(string.format("  • %s (%s)", a.key, a.type))
        end
    end

    -- สร้าง tab buttons
    local function makeTab(label, renderFn)
        local btn = Instance.new("TextButton")
        btn.Size = UDim2.new(0, 100, 1, 0)
        btn.BackgroundColor3 = Color3.fromRGB(33, 38, 45)
        btn.BorderSizePixel = 0
        btn.Text = label
        btn.TextColor3 = Color3.fromRGB(201, 209, 217)
        btn.Font = Enum.Font.Gotham
        btn.TextSize = 12
        btn.Parent = tabBar
        Instance.new("UICorner", btn).CornerRadius = UDim.new(0, 6)

        btn.MouseButton1Click:Connect(function()
            for _, b in ipairs(tabs) do
                b.btn.BackgroundColor3 = Color3.fromRGB(33, 38, 45)
            end
            btn.BackgroundColor3 = Color3.fromRGB(48, 54, 61)
            renderFn()
        end)
        table.insert(tabs, { btn = btn, render = renderFn })
        return btn
    end

    makeTab("Summary", renderSummary)
    makeTab("Timeline", renderTimeline)
    makeTab("IOC", renderIOC)
    makeTab("Risk", renderRiskCurve)
    makeTab("Env", renderEnv)

    -- เลือก tab แรก
    if tabs[1] then
        tabs[1].btn.BackgroundColor3 = Color3.fromRGB(48, 54, 61)
        tabs[1].render()
    end

    return gui
end

function ReportObj:show()
    return buildGUI(self)
end

--========== EXPORT ==========--
Report.IOCExtractor = IOCExtractor
Report.RiskCurve    = RiskCurve
Report.Timeline     = Timeline
Report.EnvSnapshot  = EnvSnapshot
Report.Exporter     = Exporter
Report.SEVERITY_LABEL = SEVERITY_LABEL
Report.SEVERITY_ICON  = SEVERITY_ICON
Report.fmtDuration  = fmtDuration
Report.hash         = hash

return Report