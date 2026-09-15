--[[
    ============================================================
    EDR Report v3.0 — Version-Aware Forensics Engine
    ============================================================
    ปรับปรุงจาก v1.0:
    - STIX 2.1, MITRE Navigator, SARIF, MISP, CSV, IOC TXT
    - Attack Chain Reconstruction
    - Bayesian IOC Confidence
    - Deep Environment Diff (function signatures)
    - Kalman-smoothed Risk Curve + prediction
    - Timeline clustering
    - Executive summary generator
    - Forensic Evidence Chain (hash all)
    - Bloomberg-filter IOC dedup
    - IOC enrichment (reputation)

    ใช้ร่วมกับ:
    - edr_core.lua : events, alerts, timeseries, risk
    - rules.lua    : alerts + mitre + category
    - hooks.lua    : source of events
    - ui.lua       : consume report
    - main.lua     : lifecycle
    ============================================================
]]

local Report = {}

Report._VERSION = "3.0.0"
Report.MODULE_VERSION = "3.0.0"
Report.VERSION = "3.0.0"

--========== CONFIG ==========--
Report.Config = {
    -- Data limits
    MAX_EVENTS_IN_REPORT    = 50000,
    MAX_TIMELINE_ENTRIES    = 500,
    MAX_IOC_PER_TYPE        = 500,
    MAX_IOC_TOTAL           = 5000,
    MAX_CHAIN_STAGES        = 20,
    MAX_FINDINGS            = 1000,
    -- Risk sampling
    RISK_SAMPLE_INTERVAL    = 2,
    RISK_PREDICTION_WINDOW  = 30,
    -- Environment
    ENABLE_ENV_SNAPSHOT     = true,
    ENV_SNAPSHOT_DEPTH      = 3,
    -- Dedup
    ENABLE_IOC_BLOOM        = true,
    IOC_BLOOM_SIZE          = 1 << 18,
    IOC_BLOOM_HASHES        = 4,
    -- Analysis
    ENABLE_CHAIN_RECON      = true,
    ENABLE_CLUSTERING       = true,
    CLUSTER_GAP_SEC         = 3,
    -- GUI
    GUI_MODE                = "full",
    -- Export
    ENABLE_FORENSIC_HASH    = true,
    FORENSIC_HASH_ALGO      = "sha256",
    SELF_INTEGRITY          = true,
    -- Log
    LOG_LEVEL               = 1,
    LOG_STRUCTURED          = false,

    PERFORMANCE_MODE        = "balanced",
}

local MODE_PROFILES = {
    light = {
        MAX_EVENTS_IN_REPORT = 10000, MAX_TIMELINE_ENTRIES = 100,
        MAX_IOC_PER_TYPE = 100, MAX_IOC_TOTAL = 500,
        MAX_FINDINGS = 200, RISK_SAMPLE_INTERVAL = 5,
        IOC_BLOOM_SIZE = 1 << 16, ENABLE_CHAIN_RECON = false,
        ENABLE_CLUSTERING = false,
    },
    balanced = {
        MAX_EVENTS_IN_REPORT = 50000, MAX_TIMELINE_ENTRIES = 500,
        MAX_IOC_PER_TYPE = 500, MAX_IOC_TOTAL = 5000,
        MAX_FINDINGS = 1000, RISK_SAMPLE_INTERVAL = 2,
        IOC_BLOOM_SIZE = 1 << 18, ENABLE_CHAIN_RECON = true,
        ENABLE_CLUSTERING = true,
    },
    paranoid = {
        MAX_EVENTS_IN_REPORT = 200000, MAX_TIMELINE_ENTRIES = 2000,
        MAX_IOC_PER_TYPE = 2000, MAX_IOC_TOTAL = 20000,
        MAX_FINDINGS = 5000, RISK_SAMPLE_INTERVAL = 1,
        IOC_BLOOM_SIZE = 1 << 22, ENABLE_CHAIN_RECON = true,
        ENABLE_CLUSTERING = true,
    },
}

function Report.setPerformanceMode(mode)
    local profile = MODE_PROFILES[mode]
    if not profile then return false, "unknown mode: " .. tostring(mode) end
    for key, value in pairs(profile) do Report.Config[key] = value end
    Report.Config.PERFORMANCE_MODE = mode
    if Report._log then Report._log(1, "perf", "mode applied: " .. mode, profile) end
    return true
end

function Report.getPerformanceMode() return Report.Config.PERFORMANCE_MODE end
function Report.getVersion() return Report._VERSION end

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
        local lo = h % 65536
        local hi = math.floor(h / 65536)
        h = (lo * 16777619
            + ((hi * 16777619) % 65536) * 65536) % 0x100000000
    end
    return h
end

local function hash(str)
    return string.format("%08x", fnv1a(str))
end

local function chain_hash(str)
    local h1 = fnv1a(str, 2166136261)
    local h2 = fnv1a(str, 2166136261 + 101)
    local h3 = fnv1a(str, 2166136261 + 202)
    local h4 = fnv1a(str, 2166136261 + 303)
    local h5 = fnv1a(str, 2166136261 + 404)
    return string.format("%08x%08x%08x%08x%08x", h1, h2, h3, h4, h5)
end

local bit32lib = bit32 or bit

local function bitRShift(a, n)
    if bit32lib and bit32lib.rshift then return bit32lib.rshift(a, n) end
    return math.floor(a / 2 ^ n) % 0x100000000
end

local function bitRRotate(a, n)
    if bit32lib and bit32lib.rrotate then return bit32lib.rrotate(a, n) end
    n = n % 32
    if n == 0 then return a % 0x100000000 end
    return bor((a * 2 ^ n) % 0x100000000,
        math.floor(a / 2 ^ (32 - n)))
end

local function sha256_pure(s)
    local rshift, rrot = bitRShift, bitRRotate
    local K = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,
        0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,
        0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,
        0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,
        0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,
        0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    }
    local H = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 }
    local bits = #s * 8
    s = s .. "\128"
    while #s % 64 ~= 56 do s = s .. "\0" end
    s = s .. string.char(
        band(rshift(bits, 56), 0xff), band(rshift(bits, 48), 0xff),
        band(rshift(bits, 40), 0xff), band(rshift(bits, 32), 0xff),
        band(rshift(bits, 24), 0xff), band(rshift(bits, 16), 0xff),
        band(rshift(bits, 8), 0xff), band(bits, 0xff))

    for chunk = 1, #s, 64 do
        local w = {}
        for j = 0, 15 do
            local p = chunk + j * 4
            w[j] = s:byte(p) * 0x1000000 + s:byte(p + 1) * 0x10000
                + s:byte(p + 2) * 0x100 + s:byte(p + 3)
        end
        for j = 16, 63 do
            local a = w[j - 15]
            local b = w[j - 2]
            local s0 = bxor(bxor(rrot(a, 7), rrot(a, 18)), rshift(a, 3))
            local s1 = bxor(bxor(rrot(b, 17), rrot(b, 19)), rshift(b, 10))
            w[j] = (w[j - 16] + s0 + w[j - 7] + s1) % 0x100000000
        end
        local a,b,c,d,e,f,g,h = H[1],H[2],H[3],H[4],H[5],H[6],H[7],H[8]
        for j = 0, 63 do
            local s1 = bxor(bxor(rrot(e, 6), rrot(e, 11)), rrot(e, 25))
            local ch = bxor(band(e, f), band(bxor(0xffffffff, e), g))
            local t1 = (h + s1 + ch + K[j + 1] + w[j]) % 0x100000000
            local s0 = bxor(bxor(rrot(a, 2), rrot(a, 13)), rrot(a, 22))
            local maj = bxor(band(a, b), bxor(band(a, c), band(b, c)))
            local t2 = (s0 + maj) % 0x100000000
            h,g,f,e,d,c,b,a = g,f,e,(d+t1)%0x100000000,c,b,a,(t1+t2)%0x100000000
        end
        H[1] = (H[1] + a) % 0x100000000
        H[2] = (H[2] + b) % 0x100000000
        H[3] = (H[3] + c) % 0x100000000
        H[4] = (H[4] + d) % 0x100000000
        H[5] = (H[5] + e) % 0x100000000
        H[6] = (H[6] + f) % 0x100000000
        H[7] = (H[7] + g) % 0x100000000
        H[8] = (H[8] + h) % 0x100000000
    end
    local out = {}
    for i = 1, 8 do out[i] = string.format("%08x", H[i]) end
    return table.concat(out)
end

local function sha256(s)
    if crypt and type(crypt) == "table" and type(crypt.hash) == "function" then
        local ok, result = pcall(crypt.hash, s, "sha256")
        if ok and type(result) == "string" and #result == 64 then return result end
    end
    if type(hash) == "function" then
        local ok, result = pcall(hash, s)
        if ok and type(result) == "string" and #result == 64 then return result end
    end
    return sha256_pure(s)
end

Report.sha256 = sha256
Report.hash32 = hash

--========== UTILITIES ==========--
local function now()
    if type(time) == "function" then return time() end
    return os.clock()
end
local function walltime() return os.time() end

local function fmtDuration(sec)
    sec = math.floor(sec or 0)
    if sec < 0 then sec = 0 end
    if sec < 60 then return sec .. "s" end
    if sec < 3600 then return math.floor(sec/60) .. "m" .. (sec%60) .. "s" end
    return math.floor(sec/3600) .. "h" .. math.floor((sec%3600)/60) .. "m"
end

local function fmtISO(t)
    return os.date("!%Y-%m-%dT%H:%M:%SZ", t or os.time())
end

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

local function truncate(s, n)
    s = tostring(s or "")
    if #s <= n then return s end
    return s:sub(1, n - 3) .. "..."
end

--========== BLOOM FILTER ==========--
local Bloom = {}
Bloom.__index = Bloom

function Bloom.new(size, hashes)
    return setmetatable({
        size = size or (1 << 18),
        hashCount = hashes or 4,
        bits = {},
        itemCount = 0,
    }, Bloom)
end

function Bloom:add(str)
    if type(str) ~= "string" then return end
    for i = 1, self.hashCount do
        local idx = fnv1a(str, 2166136261 + (i-1) * 101) % self.size
        local w = math.floor(idx / 32)
        local b = idx % 32
        self.bits[w] = bor(self.bits[w] or 0, 1 << b)
    end
    self.itemCount = self.itemCount + 1
end

function Bloom:contains(str)
    if type(str) ~= "string" then return false end
    for i = 1, self.hashCount do
        local idx = fnv1a(str, 2166136261 + (i-1) * 101) % self.size
        local w = math.floor(idx / 32)
        local b = idx % 32
        if band(self.bits[w] or 0, 1 << b) == 0 then return false end
    end
    return true
end

--========== STATS ==========--
local Stats = {}

function Stats.mean(t)
    if #t == 0 then return 0 end
    local s = 0
    for i = 1, #t do s = s + t[i] end
    return s / #t
end

function Stats.stdev(t)
    local n = #t
    if n < 2 then return 0 end
    local m = Stats.mean(t)
    local s = 0
    for i = 1, n do
        local d = t[i] - m
        s = s + d * d
    end
    return math.sqrt(s / (n - 1))
end

function Stats.median(t)
    local n = #t
    if n == 0 then return 0 end
    local sorted = {}
    for i = 1, n do sorted[i] = t[i] end
    table.sort(sorted)
    if n % 2 == 1 then return sorted[(n+1)//2]
    else return (sorted[n//2] + sorted[n//2 + 1]) / 2 end
end

function Stats.percentile(t, p)
    local n = #t
    if n == 0 then return 0 end
    local sorted = {}
    for i = 1, n do sorted[i] = t[i] end
    table.sort(sorted)
    local pos = math.ceil(p * n)
    if pos < 1 then pos = 1 end
    if pos > n then pos = n end
    return sorted[pos]
end

-- Simple Kalman filter (1D)
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

--========== SEVERITY ==========--
local SEV_LABEL = { [0]="INFO", [1]="LOW", [2]="MED", [3]="HIGH", [4]="CRIT" }
local SEV_ICON  = { [0]="·",    [1]="○",   [2]="◐",   [3]="●",    [4]="◆" }

--========== IOC EXTRACTOR v2.0 ==========--
local IOCExtractor = {}
IOCExtractor.__index = IOCExtractor

-- IOC patterns
local IOC_PATTERNS = {
    url = "https?://[%w%p]+",
    ipv4 = "%f[%d]%d+%.%d+%.%d+%.%d+%f[%D]",
    domain = "%f[%w][%w%-]+%.[%w%-]+%.[%a]+%f[%D]",
    md5 = "%f[%x]%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%f[%X]",
    sha256 = "%f[%x]%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%f[%X]",
    email = "[%w%._%-]+@[%w%.%-]+%.[%a]+",
    discord_token = "[%w%-_]+%.[%w%-_]+%.[%w%-_]+",
    telegram_bot = "%d+:AA[%w%-_]+",
    btc = "%f[%w][13][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9]%f[%W]",
    win_path = "[%a]:\\[%w%._\\%-]+",
    unix_path = "/[%w%._%-/]+",
    api_key = "AIza[%w%-_]+",
    aws_key = "AKIA[%w]+",
}

-- Whitelist
local DOMAIN_WHITELIST = {
    ["roblox.com"] = true, ["robloxlabs.com"] = true,
    ["rbxcdn.com"] = true, ["rbx.com"] = true,
    ["luau.org"] = true, ["github.com"] = true,
    ["githubusercontent.com"] = true, ["googleapis.com"] = true,
}

local function isWhitelisted(d)
    for w in pairs(DOMAIN_WHITELIST) do
        if d == w or d:sub(-#w - 1) == "." .. w then return true end
    end
    return false
end

local function isPrivateIP(ip)
    local a, b = ip:match("^(%d+)%.(%d+)%.")
    a, b = tonumber(a), tonumber(b)
    if not a then return false end
    if a == 10 then return true end
    if a == 172 and b and b >= 16 and b <= 31 then return true end
    if a == 192 and b == 168 then return true end
    if a == 127 or a == 0 then return true end
    return false
end

-- IOC types ที่อันตราย
local IOC_RISK = {
    url = 0.5, ipv4 = 0.6, domain = 0.3,
    md5 = 0.4, sha256 = 0.5, email = 0.2,
    discord_token = 0.95, telegram_bot = 0.9,
    btc = 0.85, api_key = 0.9, aws_key = 0.9,
    win_path = 0.1, unix_path = 0.1,
}

function IOCExtractor.new()
    return setmetatable({
        indicators = {},
        bloom = Bloom.new(Report.Config.IOC_BLOOM_SIZE, Report.Config.IOC_BLOOM_HASHES),
        total = 0,
        by_type = {},
        bufferDropped = 0,
    }, IOCExtractor)
end

function IOCExtractor:add(iocType, value, context, severityHint)
    if not value or #value == 0 or #value > 500 then return end

    -- Bloom check
    local key = iocType .. ":" .. value
    if self.bloom:contains(key) then
        self:reinforce(key)
        return
    end
    self.bloom:add(key)

    if self.total >= Report.Config.MAX_IOC_TOTAL then
        self.bufferDropped = self.bufferDropped + 1
        return
    end
    if (self.by_type[iocType] or 0) >= Report.Config.MAX_IOC_PER_TYPE then
        self.bufferDropped = self.bufferDropped + 1
        return
    end

    local risk = IOC_RISK[iocType] or 0.3
    local t = now()

    self.indicators[key] = {
        type = iocType,
        value = value,
        count = 1,
        first_seen = t,
        last_seen = t,
        contexts = context and { context } or {},
        risk = risk,
        confidence = 0.5,     -- Bayesian อัปเดตได้
        severity_hint = severityHint or 0,
    }
    self.total = self.total + 1
    self.by_type[iocType] = (self.by_type[iocType] or 0) + 1
end

function IOCExtractor:reinforce(key)
    local e = self.indicators[key]
    if not e then return end
    e.count = e.count + 1
    e.last_seen = now()
    -- Bayesian: ถ้าเจอซ้ำ → confidence สูงขึ้น
    local newConf = e.confidence + (1 - e.confidence) * 0.3
    e.confidence = math.min(newConf, 0.99)
end

function IOCExtractor:scanString(s, context, severityHint)
    if type(s) ~= "string" or #s < 4 or #s > 10000 then return end

    for url in s:gmatch(IOC_PATTERNS.url) do
        self:add("url", url, context, severityHint)
    end

    for ip in s:gmatch(IOC_PATTERNS.ipv4) do
        if not isPrivateIP(ip) then
            self:add("ipv4", ip, context, severityHint)
        end
    end

    for d in s:gmatch(IOC_PATTERNS.domain) do
        if not isWhitelisted(d) and #d > 4 and #d < 100 then
            self:add("domain", d, context, severityHint)
        end
    end

    for h in s:gmatch(IOC_PATTERNS.sha256) do
        if #h == 64 then self:add("sha256", h, context, severityHint) end
    end

    for h in s:gmatch(IOC_PATTERNS.md5) do
        if #h == 32 then self:add("md5", h, context, severityHint) end
    end

    for tok in s:gmatch(IOC_PATTERNS.discord_token) do
        if #tok > 50 and #tok < 100 then
            local parts = 0
            for _ in tok:gmatch("%.") do parts = parts + 1 end
            if parts == 2 then self:add("discord_token", tok, context, severityHint) end
        end
    end

    for tok in s:gmatch(IOC_PATTERNS.telegram_bot) do
        self:add("telegram_bot", tok, context, severityHint)
    end

    for e in s:gmatch(IOC_PATTERNS.email) do
        if #e < 100 then self:add("email", e, context, severityHint) end
    end

    for k in s:gmatch(IOC_PATTERNS.api_key) do
        self:add("api_key", k, context, severityHint)
    end

    for k in s:gmatch(IOC_PATTERNS.aws_key) do
        self:add("aws_key", k, context, severityHint)
    end

    for p in s:gmatch(IOC_PATTERNS.win_path) do
        self:add("win_path", p, context, severityHint)
    end
end

function IOCExtractor:scanEvents(events)
    for i = 1, #events do
        local e = events[i]
        if e.data then
            local ctx = e.type .. " @" .. string.format("%.2f", e.t)
            local sevHint = e.severity or 0
            for k, v in pairs(e.data) do
                if type(v) == "string" then
                    self:scanString(v, ctx, sevHint)
                end
            end
        end
    end
end

function IOCExtractor:getAll()
    local out = {}
    for _, entry in pairs(self.indicators) do
        out[#out + 1] = entry
    end
    -- เรียงตาม count + risk + confidence
    table.sort(out, function(a, b)
        local scoreA = a.count * 0.3 + a.risk * 0.4 + a.confidence * 0.3
        local scoreB = b.count * 0.3 + b.risk * 0.4 + b.confidence * 0.3
        return scoreA > scoreB
    end)
    return out
end

function IOCExtractor:getByType(iocType)
    local out = {}
    for _, entry in pairs(self.indicators) do
        if entry.type == iocType then out[#out + 1] = entry end
    end
    return out
end

function IOCExtractor:getTopN(n)
    local all = self:getAll()
    local out = {}
    for i = 1, math.min(n or 10, #all) do out[i] = all[i] end
    return out
end

function IOCExtractor:summary()
    return {
        total = self.total,
        by_type = self.by_type,
        bloom_items = self.bloom.itemCount,
        bufferDropped = self.bufferDropped,
    }
end

--========== ATTACK CHAIN RECONSTRUCTION ==========--
-- จับ kill chain stages จาก alerts
local ATTACK_STAGES = {
    { id = "recon",       name = "Reconnaissance",       tactics = {"T1595", "T1592"} },
    { id = "weaponize",   name = "Weaponization",        tactics = {"T1587"} },
    { id = "delivery",    name = "Delivery",             tactics = {"T1071.001", "T1583.001", "T1567"} },
    { id = "exploit",     name = "Exploitation",         tactics = {"T1190", "T1203"} },
    { id = "install",     name = "Installation",         tactics = {"T1543", "T1055", "T1620"} },
    { id = "c2",          name = "Command & Control",    tactics = {"T1071", "T1071.001", "T1573"} },
    { id = "collection",  name = "Collection",           tactics = {"T1005", "T1115", "T1113", "T1056", "T1056.001"} },
    { id = "exfil",       name = "Exfiltration",         tactics = {"T1041", "T1567", "T1020"} },
    { id = "impact",      name = "Impact",               tactics = {"T1496", "T1485", "T1486"} },
}

local ChainReconstruction = {}
ChainReconstruction.__index = ChainReconstruction

function ChainReconstruction.new()
    return setmetatable({
        stages = {},
        observed_tactics = {},
    }, ChainReconstruction)
end

function ChainReconstruction:analyze(alerts)
    -- reset
    self.stages = {}
    for _, s in ipairs(ATTACK_STAGES) do
        self.stages[s.id] = {
            id = s.id,
            name = s.name,
            tactics = s.tactics,
            hits = {},
            count = 0,
        }
    end

    for _, a in ipairs(alerts) do
        local mitre = a.mitre
        if mitre then
            for _, s in ipairs(ATTACK_STAGES) do
                for _, t in ipairs(s.tactics) do
                    if mitre == t or mitre:find("^" .. t:gsub("%.", "%%.")) then
                        local stage = self.stages[s.id]
                        stage.count = stage.count + 1
                        stage.hits[#stage.hits + 1] = a
                        self.observed_tactics[mitre] = true
                        break
                    end
                end
            end
        end
    end
end

function ChainReconstruction:getActiveStages()
    local out = {}
    for _, s in ipairs(ATTACK_STAGES) do
        local stage = self.stages[s.id]
        if stage and stage.count > 0 then
            out[#out + 1] = stage
        end
    end
    -- เรียงตามลำดับ kill chain
    return out
end

function ChainReconstruction:getCompletion()
    -- สัดส่วนของ stage ที่ปรากฏ
    local active = 0
    for _, s in ipairs(ATTACK_STAGES) do
        if self.stages[s.id].count > 0 then active = active + 1 end
    end
    return active / #ATTACK_STAGES
end

function ChainReconstruction:getSeverity()
    local completion = self:getCompletion()
    -- ถ้ามี exfil หรือ impact → critical
    if self.stages.exfil.count > 0 or self.stages.impact.count > 0 then
        return 4
    end
    if self.stages.c2.count > 0 or self.stages.collection.count > 0 then
        return 3
    end
    if self.stages.install.count > 0 or self.stages.exploit.count > 0 then
        return 3
    end
    if self.stages.delivery.count > 0 then
        return 2
    end
    return 1
end

--========== TIMELINE v2.0 ==========--
local Timeline = {}
Timeline.__index = Timeline

-- Priority per event type
local TIMELINE_PRIORITY = {
    ALERT              = 100,
    VULN_FINDING       = 95,
    TAINT_FLOW         = 92,
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
    RBX_PROPERTY_WRITE = 38,
    RBX_REMOTE_FIRE    = 36,
    GLOBAL_WRITE       = 35,
    STRING_DECRYPT     = 30,
    STRING_ENCODE      = 25,
    COROUTINE_CREATE   = 20,
    TASK_SCHEDULED     = 18,
    COROUTINE_RESUME   = 15,
    OPCODE_CALL        = 5,
    HEARTBEAT          = 1,
}

function Timeline.new()
    return setmetatable({
        entries = {},
        clusters = {},
    }, Timeline)
end

function Timeline:build(events, alerts)
    local entries = {}

    -- Events
    for i = 1, #events do
        local e = events[i]
        entries[#entries + 1] = {
            t = e.t,
            wall = e.wall,
            type = e.type,
            severity = e.severity or 0,
            data = e.data,
            priority = TIMELINE_PRIORITY[e.type] or 10,
        }
    end

    -- Alerts
    for i = 1, #alerts do
        local a = alerts[i]
        entries[#entries + 1] = {
            t = a.t,
            wall = a.wall or walltime(),
            type = "ALERT",
            severity = a.severity or 3,
            data = {
                rule = a.rule,
                message = a.message,
                score = a.score,
                mitre = a.mitre,
                category = a.category,
            },
            priority = 100,
        }
    end

    -- Sort by time
    table.sort(entries, function(a, b) return a.t < b.t end)

    -- Trim
    if #entries > Report.Config.MAX_TIMELINE_ENTRIES then
        table.sort(entries, function(a, b)
            if a.priority ~= b.priority then return a.priority > b.priority end
            return a.t < b.t
        end)
        for i = #entries, Report.Config.MAX_TIMELINE_ENTRIES + 1, -1 do
            entries[i] = nil
        end
        table.sort(entries, function(a, b) return a.t < b.t end)
    end

    self.entries = entries

    if Report.Config.ENABLE_CLUSTERING then
        self:_cluster()
    end

    return entries
end

function Timeline:_cluster()
    local clusters = {}
    if #self.entries == 0 then
        self.clusters = clusters
        return
    end

    local cur = { entries = { self.entries[1] },
                  start = self.entries[1].t,
                  end_ = self.entries[1].t,
                  severity = self.entries[1].severity or 0,
                  count = 1 }

    for i = 2, #self.entries do
        local e = self.entries[i]
        if (e.t - cur.end_) <= Report.Config.CLUSTER_GAP_SEC then
            cur.entries[#cur.entries + 1] = e
            cur.end_ = e.t
            cur.count = cur.count + 1
            if (e.severity or 0) > cur.severity then cur.severity = e.severity end
        else
            clusters[#clusters + 1] = cur
            cur = { entries = { e }, start = e.t, end_ = e.t,
                    severity = e.severity or 0, count = 1 }
        end
    end
    clusters[#clusters + 1] = cur
    self.clusters = clusters
end

function Timeline:renderASCII(opts)
    opts = opts or {}
    local lines = {}
    local t0 = self.entries[1] and self.entries[1].t or 0

    for i = 1, #self.entries do
        local e = self.entries[i]
        local icon = SEV_ICON[e.severity] or "·"
        local sevLabel = SEV_LABEL[e.severity] or "?"
        local rel = "+" .. fmtDuration(e.t - t0)
        local dtype = padRight(e.type, 18)

        local detail = ""
        if e.type == "ALERT" and e.data then
            detail = (e.data.rule or "") .. " — " .. truncate(e.data.message or "", 40)
        elseif e.data then
            if e.data.url then detail = truncate(e.data.url, 50)
            elseif e.data.path then detail = truncate(e.data.path, 50)
            elseif e.data.key then detail = "global:" .. e.data.key
            elseif e.data.name then detail = e.data.name
            elseif e.data.value then detail = truncate(tostring(e.data.value), 50)
            elseif e.data.count then detail = "x" .. tostring(e.data.count)
            elseif e.data.service then detail = "svc:" .. e.data.service
            end
        end

        lines[#lines + 1] = string.format("%s %s [%s] %s %s",
            icon, padLeft(rel, 8), padLeft(sevLabel, 4), dtype, detail)
    end

    return table.concat(lines, "\n")
end

--========== ENV SNAPSHOT v2.0 ==========--
local EnvSnapshot = {}

function EnvSnapshot.capture(opts)
    opts = opts or {}
    local maxGlobals = opts.maxGlobals or 3000
    local maxUpvalues = opts.maxUpvalues or 5
    local maxFunctions = opts.maxFunctions or 500
    local snap = {
        time = walltime(),
        globals = {},
        funcs = {},
        signatures = {},
    }

    local env = (getgenv and getgenv()) or _G
    local count, functionCount = 0, 0

    for k, v in pairs(env) do
        count = count + 1
        if count > maxGlobals then break end

        local tk = type(v)
        snap.globals[k] = tk

        if tk == "function" and functionCount < maxFunctions then
            functionCount = functionCount + 1
            local info = debug and debug.getinfo and debug.getinfo(v, "Su")
            local functionHash = hash(tostring(v))
            snap.funcs[k] = {
                source = (info and info.short_src) or "?",
                linedefined = (info and info.linedefined) or 0,
                hash = functionHash,
            }

            -- นับ upvalues (signature)
            local upvals = 0
            if debug and debug.getupvalue then
                for i = 1, maxUpvalues do
                    local name = debug.getupvalue(v, i)
                    if not name then break end
                    upvals = upvals + 1
                end
            end
            snap.signatures[k] = { upvalues = upvals, hash = functionHash }
        end
    end

    return snap
end

function EnvSnapshot.diff(before, after)
    local added, removed, changed, redefined = {}, {}, {}, {}

    for k, t in pairs(after.globals) do
        local bt = before.globals[k]
        if bt == nil then
            added[#added + 1] = { key = k, type = t }
        elseif bt ~= t then
            changed[#changed + 1] = { key = k, from = bt, to = t }
        end
    end

    for k, t in pairs(before.globals) do
        if after.globals[k] == nil then
            removed[#removed + 1] = { key = k, type = t }
        end
    end

    for k, info in pairs(after.funcs) do
        local b = before.funcs[k]
        if b and b.hash ~= info.hash then
            local sigChange = false
            local beforeSig = before.signatures[k]
            local afterSig = after.signatures[k]
            if beforeSig and afterSig then
                if beforeSig.upvalues ~= afterSig.upvalues then
                    sigChange = true
                end
            end

            redefined[#redefined + 1] = {
                key = k,
                before = b.source,
                after = info.source,
                signature_changed = sigChange,
                upvalues_before = beforeSig and beforeSig.upvalues or 0,
                upvalues_after = afterSig and afterSig.upvalues or 0,
            }
        end
    end

    -- Sort redefined by severity (signature change)
    table.sort(redefined, function(a, b)
        if a.signature_changed ~= b.signature_changed then
            return a.signature_changed
        end
        return a.key < b.key
    end)

    return {
        added = added,
        removed = removed,
        changed = changed,
        redefined = redefined,
        total_added = #added,
        total_removed = #removed,
        total_changed = #changed,
        total_redefined = #redefined,
    }
end

--========== RISK CURVE v2.0 ==========--
local RiskCurve = {}
RiskCurve.__index = RiskCurve

function RiskCurve.new()
    return setmetatable({
        samples = {},
        lastSample = 0,
        kalman = Kalman.new(0.005, 0.05, 0),
        prediction = 0,
    }, RiskCurve)
end

function RiskCurve:sample(risk, alerts, events)
    local t = now()
    if t - self.lastSample < Report.Config.RISK_SAMPLE_INTERVAL then return end
    self.lastSample = t

    local filtered = self.kalman:update(risk)

    self.samples[#self.samples + 1] = {
        t = t,
        risk = risk,
        filtered = filtered,
        alerts = alerts,
        events = events,
    }
    if #self.samples > 500 then
        table.remove(self.samples, 1)
    end

    -- Simple prediction: linear extrapolation
    if #self.samples >= 5 then
        local n = #self.samples
        local recent = {}
        for i = n - 4, n do recent[#recent + 1] = self.samples[i].filtered end
        local slope = (recent[#recent] - recent[1]) / (#recent - 1)
        self.prediction = filtered + slope * Report.Config.RISK_PREDICTION_WINDOW
        if self.prediction > 1 then self.prediction = 1 end
        if self.prediction < 0 then self.prediction = 0 end
    end
end

function RiskCurve:renderASCII(width, height)
    width = width or 60
    height = height or 8
    if #self.samples < 2 then return "(insufficient data)" end

    local cols = {}
    local step = math.max(1, math.floor(#self.samples / width))
    for i = 1, #self.samples, step do
        cols[#cols + 1] = self.samples[i]
    end

    local grid = {}
    for y = 1, height do
        grid[y] = {}
        for x = 1, #cols do grid[y][x] = " " end
    end

    for i, s in ipairs(cols) do
        local y = math.floor((1 - s.filtered) * (height - 1)) + 1
        y = math.max(1, math.min(height, y))
        grid[y][i] = "*"
    end

    local lines = {}
    for y = 1, height do
        local label = string.format("%4.0f%%", (1 - (y-1)/(height-1)) * 100)
        lines[#lines + 1] = label .. " │ " .. table.concat(grid[y])
    end
    lines[#lines + 1] = "     └" .. string.rep("─", #cols)

    return table.concat(lines, "\n")
end

--========== EXECUTIVE SUMMARY ==========--
local function buildExecutiveSummary(report)
    local lines = {}
    local s = report.session
    local stats = report.stats

    lines[#lines + 1] = "# Executive Summary"
    lines[#lines + 1] = ""
    lines[#lines + 1] = string.format("**Session ID:** `%s`", s.id or "?")
    lines[#lines + 1] = string.format("**Fingerprint:** `%s`", s.fingerprint or "N/A")
    lines[#lines + 1] = string.format("**Generated:** %s", fmtISO())
    lines[#lines + 1] = string.format("**Duration:** %s", fmtDuration(s.elapsed or 0))
    lines[#lines + 1] = string.format("**Events Processed:** %d", s.events or 0)
    lines[#lines + 1] = string.format("**Alerts:** %d (unique: %d)", stats.total_alerts, stats.unique_alerts)
    lines[#lines + 1] = ""

    -- Verdict
    local risk = report.risk.overall or 0
    local verdict
    if risk >= 0.85 then verdict = "🔴 **MALICIOUS** — Strong evidence of malicious behavior"
    elseif risk >= 0.65 then verdict = "🟠 **SUSPICIOUS** — Multiple indicators of concern"
    elseif risk >= 0.35 then verdict = "🟡 **POTENTIALLY UNWANTED** — Some suspicious signals"
    elseif risk >= 0.15 then verdict = "🟢 **LOW RISK** — Minor signals detected"
    else verdict = "⚪ **CLEAN** — No significant threats detected"
    end

    lines[#lines + 1] = "## Verdict"
    lines[#lines + 1] = ""
    lines[#lines + 1] = verdict
    lines[#lines + 1] = ""
    lines[#lines + 1] = string.format("**Risk Score:** %.1f%% (probabilistic aggregate)", risk * 100)
    if report.risk_curve and report.risk_curve.prediction > 0 then
        lines[#lines + 1] = string.format("**Predicted (30s):** %.1f%%",
            report.risk_curve.prediction * 100)
    end
    lines[#lines + 1] = ""

    -- Attack chain
    if report.chain then
        local chain = report.chain
        local active = chain:getActiveStages()
        if #active > 0 then
            lines[#lines + 1] = "## Attack Chain Coverage"
            lines[#lines + 1] = ""
            for _, stage in ipairs(active) do
                lines[#lines + 1] = string.format("- **%s** — %d indicator(s)",
                    stage.name, stage.count)
            end
            lines[#lines + 1] = ""
            lines[#lines + 1] = string.format("**Completion:** %.0f%% of kill chain",
                chain:getCompletion() * 100)
            lines[#lines + 1] = ""
        end
    end

    -- Top rules
    if #report.alerts > 0 then
        lines[#lines + 1] = "## Top Triggered Rules"
        lines[#lines + 1] = ""
        local sorted = {}
        for i = 1, #report.alerts do sorted[i] = report.alerts[i] end
        table.sort(sorted, function(a, b) return (a.score or 0) > (b.score or 0) end)
        for i = 1, math.min(10, #sorted) do
            local a = sorted[i]
            lines[#lines + 1] = string.format("%d. **%s** (score: %.2f, %s)",
                i, a.rule or "?", a.score or 0, SEV_LABEL[a.severity or 0])
            if a.message then
                lines[#lines + 1] = string.format("   - %s", truncate(a.message, 120))
            end
        end
        lines[#lines + 1] = ""
    end

    -- IOC summary
    if report.ioc and next(report.ioc.by_type) then
        lines[#lines + 1] = "## Indicators of Compromise"
        lines[#lines + 1] = ""
        for t, count in pairs(report.ioc.by_type) do
            lines[#lines + 1] = string.format("- **%s:** %d unique", t, count)
        end
        lines[#lines + 1] = ""
    end

    -- Env changes
    if report.envdiff then
        local d = report.envdiff
        lines[#lines + 1] = "## Environment Changes"
        lines[#lines + 1] = ""
        lines[#lines + 1] = string.format("- Globals added: %d", d.total_added)
        lines[#lines + 1] = string.format("- Globals removed: %d", d.total_removed)
        lines[#lines + 1] = string.format("- Functions redefined: %d", d.total_redefined)

        if #d.redefined > 0 then
            local sigChanged = 0
            for _, r in ipairs(d.redefined) do
                if r.signature_changed then sigChanged = sigChanged + 1 end
            end
            lines[#lines + 1] = string.format("- Functions with signature change: %d", sigChanged)
        end
        lines[#lines + 1] = ""
    end

    return table.concat(lines, "\n")
end

--========== EXPORTERS ==========--
local Exporter = {}

-- Markdown
function Exporter.toMarkdown(report)
    local lines = {}
    lines[#lines + 1] = buildExecutiveSummary(report)
    lines[#lines + 1] = ""
    lines[#lines + 1] = "---"
    lines[#lines + 1] = ""

    -- Timeline
    lines[#lines + 1] = "## Forensic Timeline"
    lines[#lines + 1] = ""
    lines[#lines + 1] = "```"
    lines[#lines + 1] = report.timeline:renderASCII()
    lines[#lines + 1] = "```"
    lines[#lines + 1] = ""

    -- Risk curve
    lines[#lines + 1] = "## Risk Evolution"
    lines[#lines + 1] = ""
    lines[#lines + 1] = "```"
    lines[#lines + 1] = report.risk_curve:renderASCII(60, 8)
    lines[#lines + 1] = "```"
    lines[#lines + 1] = ""

    -- IOC table
    lines[#lines + 1] = "## IOCs (Top 50)"
    lines[#lines + 1] = ""
    lines[#lines + 1] = "| Type | Value | Count | Risk | Confidence |"
    lines[#lines + 1] = "|------|-------|-------|------|------------|"
    local iocs = report.ioc:getAll()
    for i = 1, math.min(50, #iocs) do
        local ioc = iocs[i]
        local v = ioc.value:gsub("|", "\\|")
        lines[#lines + 1] = string.format("| %s | `%s` | %d | %.2f | %.2f |",
            ioc.type, truncate(v, 60), ioc.count, ioc.risk, ioc.confidence)
    end
    lines[#lines + 1] = ""

    -- Env diff
    if report.envdiff then
        local d = report.envdiff
        lines[#lines + 1] = "## Environment Modifications"
        lines[#lines + 1] = ""
        if #d.redefined > 0 then
            lines[#lines + 1] = "### Redefined Functions"
            for i, r in ipairs(d.redefined) do
                if i > 30 then break end
                local sig = r.signature_changed and " ⚠️ SIGNATURE" or ""
                lines[#lines + 1] = string.format("- `%s` (%s → %s)%s",
                    r.key, truncate(r.before, 40), truncate(r.after, 40), sig)
            end
            lines[#lines + 1] = ""
        end
        if #d.added > 0 then
            lines[#lines + 1] = "### Added Globals (top 30)"
            for i = 1, math.min(30, #d.added) do
                lines[#lines + 1] = string.format("- `%s` (%s)", d.added[i].key, d.added[i].type)
            end
        end
        lines[#lines + 1] = ""
    end

    -- Attack chain detail
    if report.chain then
        local active = report.chain:getActiveStages()
        if #active > 0 then
            lines[#lines + 1] = "## Attack Chain Detail"
            lines[#lines + 1] = ""
            for _, stage in ipairs(active) do
                lines[#lines + 1] = string.format("### %s (%d)", stage.name, stage.count)
                for i, h in ipairs(stage.hits) do
                    if i > 5 then break end
                    lines[#lines + 1] = string.format("- `%s` (%.2f)", h.rule or "?", h.score or 0)
                end
                lines[#lines + 1] = ""
            end
        end
    end

    return table.concat(lines, "\n")
end

-- JSON
function Exporter.toJSON(report)
    local function esc(s)
        s = tostring(s or "")
        s = s:gsub("\\", "\\\\"):gsub("\"", "\\\""):gsub("\n", "\\n")
            :gsub("\r", "\\r"):gsub("\t", "\\t")
        return s
    end

    local function encode(v, indent)
        indent = indent or 0
        local pad = string.rep("  ", indent)
        local t = type(v)
        if t == "nil" then return "null"
        elseif t == "boolean" then return tostring(v)
        elseif t == "number" then return tostring(v)
        elseif t == "string" then return '"' .. esc(v) .. '"'
        elseif t == "table" then
            local isArray = #v > 0
            local parts = {}
            if isArray then
                for i = 1, #v do
                    parts[#parts + 1] = string.rep("  ", indent + 1) .. encode(v[i], indent + 1)
                end
                return "[\n" .. table.concat(parts, ",\n") .. "\n" .. pad .. "]"
            else
                local keys = {}
                for k in pairs(v) do keys[#keys + 1] = tostring(k) end
                table.sort(keys)
                for i, k in ipairs(keys) do
                    parts[#parts + 1] = string.rep("  ", indent + 1)
                        .. '"' .. esc(k) .. '": ' .. encode(v[k], indent + 1)
                end
                return "{\n" .. table.concat(parts, ",\n") .. "\n" .. pad .. "}"
            end
        end
        return "null"
    end

    local out = {
        metadata = {
            version = "2.0.0",
            generated = fmtISO(),
            generator = "EDR Report v2.0",
        },
        session = {
            id = report.session.id,
            fingerprint = report.session.fingerprint,
            elapsed = report.session.elapsed,
            events = report.session.events,
        },
        risk = {
            overall = report.risk.overall,
            peak = report.risk.peak,
            prediction = report.risk_curve and report.risk_curve.prediction or 0,
        },
        stats = report.stats,
        alerts = {},
        ioc = {},
        timeline_summary = {},
        chain = {},
        env_diff = {},
    }

    for i = 1, #report.alerts do
        local a = report.alerts[i]
        out.alerts[#out.alerts + 1] = {
            rule = a.rule,
            severity = a.severity,
            score = a.score,
            message = a.message,
            mitre = a.mitre,
            category = a.category,
            time = a.t,
        }
    end

    local all = report.ioc:getAll()
    for i = 1, math.min(200, #all) do
        local ioc = all[i]
        out.ioc[#out.ioc + 1] = {
            type = ioc.type,
            value = ioc.value,
            count = ioc.count,
            risk = ioc.risk,
            confidence = ioc.confidence,
        }
    end

    for i, e in ipairs(report.timeline.entries) do
        if i > 200 then break end
        out.timeline_summary[#out.timeline_summary + 1] = {
            t = e.t,
            type = e.type,
            severity = e.severity,
        }
    end

    if report.chain then
        for _, s in ipairs(report.chain:getActiveStages()) do
            out.chain[#out.chain + 1] = {
                id = s.id,
                name = s.name,
                count = s.count,
            }
        end
    end

    if report.envdiff then
        out.env_diff.total_added = report.envdiff.total_added
        out.env_diff.total_removed = report.envdiff.total_removed
        out.env_diff.total_redefined = report.envdiff.total_redefined
    end

    return encode(out, 0)
end

-- STIX 2.1
function Exporter.toSTIX(report)
    local objects = {}
    local s = report.session

    -- Identity (source)
    objects[#objects + 1] = {
        type = "identity",
        spec_version = "2.1",
        id = "identity--edr-" .. s.id,
        created = fmtISO(),
        modified = fmtISO(),
        name = "EDR Lua Analyzer",
        identity_class = "system",
    }

    -- Report object
    objects[#objects + 1] = {
        type = "report",
        spec_version = "2.1",
        id = "report--" .. s.id,
        created = fmtISO(),
        modified = fmtISO(),
        name = "EDR Session Report " .. s.id,
        description = "Behavioral analysis of Lua script",
        published = fmtISO(),
        report_types = { "threat-report" },
    }

    -- Indicators
    local all = report.ioc:getAll()
    for i = 1, math.min(500, #all) do
        local ioc = all[i]
        local pattern
        if ioc.type == "url" then
            pattern = "[url:value = '" .. ioc.value:gsub("'", "\\'") .. "']"
        elseif ioc.type == "ipv4" then
            pattern = "[ipv4-addr:value = '" .. ioc.value .. "']"
        elseif ioc.type == "domain" then
            pattern = "[domain-name:value = '" .. ioc.value .. "']"
        elseif ioc.type == "md5" then
            pattern = "[file:hashes.MD5 = '" .. ioc.value .. "']"
        elseif ioc.type == "sha256" then
            pattern = "[file:hashes.'SHA-256' = '" .. ioc.value .. "']"
        elseif ioc.type == "email" then
            pattern = "[email-addr:value = '" .. ioc.value .. "']"
        else
            pattern = "[" .. ioc.type .. ":value = '" .. ioc.value:gsub("'", "\\'") .. "']"
        end

        objects[#objects + 1] = {
            type = "indicator",
            spec_version = "2.1",
            id = "indicator--" .. hash(ioc.type .. ioc.value),
            created = fmtISO(),
            modified = fmtISO(),
            pattern = pattern,
            pattern_type = "stix",
            valid_from = fmtISO(),
            confidence = math.floor(ioc.confidence * 100),
            labels = { ioc.type },
        }
    end

    -- Attack Patterns from alerts
    local seenTechniques = {}
    for i = 1, #report.alerts do
        local a = report.alerts[i]
        if a.mitre and not seenTechniques[a.mitre] then
            seenTechniques[a.mitre] = true
            objects[#objects + 1] = {
                type = "attack-pattern",
                spec_version = "2.1",
                id = "attack-pattern--" .. a.mitre,
                created = fmtISO(),
                modified = fmtISO(),
                name = a.mitre,
                external_references = {
                    {
                        source_name = "mitre-attack",
                        external_id = a.mitre,
                    },
                },
            }
        end
    end

    -- Bundle
    local bundle = {
        type = "bundle",
        id = "bundle--" .. s.id,
        objects = objects,
    }

    -- Encode
    local function esc(s)
        return tostring(s or ""):gsub("\\", "\\\\"):gsub("\"", "\\\"")
            :gsub("\n", "\\n"):gsub("\r", "\\r"):gsub("\t", "\\t")
    end
    local function encode(v, indent)
        indent = indent or 0
        local pad = string.rep("  ", indent)
        local t = type(v)
        if t == "nil" then return "null"
        elseif t == "boolean" or t == "number" then return tostring(v)
        elseif t == "string" then return '"' .. esc(v) .. '"'
        elseif t == "table" then
            local isArray = #v > 0
            local parts = {}
            if isArray then
                for i = 1, #v do
                    parts[#parts + 1] = string.rep("  ", indent + 1) .. encode(v[i], indent + 1)
                end
                return "[\n" .. table.concat(parts, ",\n") .. "\n" .. pad .. "]"
            else
                local keys = {}
                for k in pairs(v) do keys[#keys + 1] = tostring(k) end
                table.sort(keys)
                for i, k in ipairs(keys) do
                    parts[#parts + 1] = string.rep("  ", indent + 1)
                        .. '"' .. esc(k) .. '": ' .. encode(v[k], indent + 1)
                end
                return "{\n" .. table.concat(parts, ",\n") .. "\n" .. pad .. "}"
            end
        end
        return "null"
    end

    return encode(bundle, 0)
end

-- MITRE ATT&CK Navigator
function Exporter.toMITRENavigator(report)
    local techniqueCounts = {}
    for i = 1, #report.alerts do
        local a = report.alerts[i]
        if a.mitre then
            techniqueCounts[a.mitre] = (techniqueCounts[a.mitre] or 0) + 1
        end
    end

    local techniques = {}
    for t, count in pairs(techniqueCounts) do
        local score = math.min(count * 20, 100)
        techniques[#techniques + 1] = {
            techniqueID = t,
            score = score,
            color = score >= 80 and "#ff0000" or score >= 50 and "#ff8800" or "#ffff00",
            comment = string.format("%d alert(s)", count),
            enabled = true,
        }
    end

    local layer = {
        name = "EDR Session " .. (report.session.id or "?"),
        versions = { attack = "14", navigator = "4.9.1", layer = "4.5" },
        domain = "enterprise-attack",
        description = "Auto-generated from EDR Lua v2.0",
        filters = { platforms = { "Windows", "Linux", "macOS" } },
        sorting = 0,
        layout = { layout = "side", aggregateFunction = "average", showID = true, showName = true },
        hideDisabled = false,
        techniques = techniques,
        gradient = {
            colors = { "#ffffff", "#ff6666", "#ff0000" },
            minValue = 0,
            maxValue = 100,
        },
        legendItems = {},
        metadata = {},
        links = {},
        showTacticRowBackground = false,
        tacticRowBackground = "#dddddd",
        selectTechniquesAcrossTactics = true,
    }

    local function esc(s)
        return tostring(s or ""):gsub("\\", "\\\\"):gsub("\"", "\\\""):gsub("\n", "\\n")
    end
    local function encode(v, indent)
        indent = indent or 0
        local pad = string.rep("  ", indent)
        local t = type(v)
        if t == "nil" then return "null"
        elseif t == "boolean" then return tostring(v)
        elseif t == "number" then
            if v == math.floor(v) then return tostring(math.floor(v))
            else return tostring(v) end
        elseif t == "string" then return '"' .. esc(v) .. '"'
        elseif t == "table" then
            local isArray = #v > 0
            if isArray then
                local parts = {}
                for i = 1, #v do
                    parts[#parts + 1] = string.rep("  ", indent + 1) .. encode(v[i], indent + 1)
                end
                return "[\n" .. table.concat(parts, ",\n") .. "\n" .. pad .. "]"
            else
                local keys = {}
                for k in pairs(v) do keys[#keys + 1] = tostring(k) end
                local parts = {}
                for i, k in ipairs(keys) do
                    parts[#parts + 1] = string.rep("  ", indent + 1)
                        .. '"' .. esc(k) .. '": ' .. encode(v[k], indent + 1)
                end
                return "{\n" .. table.concat(parts, ",\n") .. "\n" .. pad .. "}"
            end
        end
        return "null"
    end

    return encode(layer, 0)
end

-- CSV (IOC list)
function Exporter.toCSV(report)
    local lines = { "type,value,count,risk,confidence,first_seen,last_seen" }
    local all = report.ioc:getAll()
    for i = 1, #all do
        local ioc = all[i]
        local v = ioc.value:gsub(",", ";")
        lines[#lines + 1] = string.format("%s,%s,%d,%.2f,%.2f,%s,%s",
            ioc.type, v, ioc.count, ioc.risk, ioc.confidence,
            fmtISO(ioc.first_seen and os.time() or nil),
            fmtISO(ioc.last_seen and os.time() or nil))
    end
    return table.concat(lines, "\n")
end

-- SARIF (Static Analysis Results Interchange Format)
function Exporter.toSARIF(report)
    local results = {}
    for i = 1, #report.alerts do
        local a = report.alerts[i]
        local sev = a.severity or 0
        local level = sev >= 4 and "error" or sev >= 3 and "warning" or "note"
        results[#results + 1] = {
            ruleId = a.rule or "unknown",
            level = level,
            message = { text = a.message or "" },
            properties = {
                score = a.score or 0,
                mitre = a.mitre,
                category = a.category,
                severity = sev,
            },
        }
    end

    local sarif = {
        version = "2.1.0",
        ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json",
        runs = {
            {
                tool = {
                    driver = {
                        name = "EDR Lua",
                        version = "2.0.0",
                        informationUri = "https://example.com/edr-lua",
                        rules = {},
                    },
                },
                results = results,
            },
        },
    }

    -- Add rule definitions
    local seenRules = {}
    for i = 1, #report.alerts do
        local a = report.alerts[i]
        if a.rule and not seenRules[a.rule] then
            seenRules[a.rule] = true
            sarif.runs[1].tool.driver.rules[#sarif.runs[1].tool.driver.rules + 1] = {
                id = a.rule,
                name = a.rule,
                shortDescription = { text = a.rule },
                fullDescription = { text = a.message or "" },
                properties = { mitre = a.mitre },
            }
        end
    end

    local function esc(s)
        return tostring(s or ""):gsub("\\", "\\\\"):gsub("\"", "\\\""):gsub("\n", "\\n")
    end
    local function encode(v, indent)
        indent = indent or 0
        local pad = string.rep("  ", indent)
        local t = type(v)
        if t == "nil" then return "null"
        elseif t == "boolean" or t == "number" then return tostring(v)
        elseif t == "string" then return '"' .. esc(v) .. '"'
        elseif t == "table" then
            local isArray = #v > 0
            if isArray then
                local parts = {}
                for i = 1, #v do
                    parts[#parts + 1] = string.rep("  ", indent + 1) .. encode(v[i], indent + 1)
                end
                return "[\n" .. table.concat(parts, ",\n") .. "\n" .. pad .. "]"
            else
                local keys = {}
                for k in pairs(v) do keys[#keys + 1] = tostring(k) end
                table.sort(keys)
                local parts = {}
                for i, k in ipairs(keys) do
                    parts[#parts + 1] = string.rep("  ", indent + 1)
                        .. '"' .. esc(k) .. '": ' .. encode(v[k], indent + 1)
                end
                return "{\n" .. table.concat(parts, ",\n") .. "\n" .. pad .. "}"
            end
        end
        return "null"
    end

    return encode(sarif, 0)
end

-- IOC TXT (simple list)
function Exporter.toIOCTXT(report)
    local lines = {}
    lines[#lines + 1] = "# EDR IOC List — " .. fmtISO()
    lines[#lines + 1] = "# Session: " .. (report.session.id or "?")
    lines[#lines + 1] = ""

    local byType = {}
    for _, ioc in pairs(report.ioc.indicators) do
        byType[ioc.type] = byType[ioc.type] or {}
        byType[ioc.type][#byType[ioc.type] + 1] = ioc
    end

    for type, list in pairs(byType) do
        lines[#lines + 1] = "[" .. type .. "]"
        for _, ioc in ipairs(list) do
            lines[#lines + 1] = ioc.value
        end
        lines[#lines + 1] = ""
    end

    return table.concat(lines, "\n")
end

-- HTML
function Exporter.toHTML(report)
    local md = Exporter.toMarkdown(report)
    local html = {}
    html[#html + 1] = "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    html[#html + 1] = "<title>EDR Report — " .. (report.session.id or "?") .. "</title>"
    html[#html + 1] = "<style>"
    html[#html + 1] = "body{font-family:system-ui,monospace;background:#0d1117;color:#c9d1d9;padding:20px;max-width:1000px;margin:auto;line-height:1.6}"
    html[#html + 1] = "h1{color:#58a6ff;border-bottom:2px solid #30363d;padding-bottom:8px}"
    html[#html + 1] = "h2{color:#79c0ff;margin-top:30px;border-bottom:1px solid #21262d;padding-bottom:4px}"
    html[#html + 1] = "h3{color:#a5d6ff}"
    html[#html + 1] = "pre{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px;overflow:auto;font-size:12px}"
    html[#html + 1] = "code{background:#161b22;padding:2px 6px;border-radius:3px;font-size:12px;color:#ff7b72}"
    html[#html + 1] = "strong{color:#f0f6fc}"
    html[#html + 1] = "</style></head><body><pre>"
    html[#html + 1] = md:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;")
    html[#html + 1] = "</pre></body></html>"
    return table.concat(html, "\n")
end

--========== MAIN REPORT OBJECT ==========--
local ReportObj = {}
ReportObj.__index = ReportObj

function Report.new(edr, rules)
    return setmetatable({
        edr        = edr,
        rules      = rules,
        session    = edr and edr.session or { id = "?", elapsed = 0, events = 0 },
        ioc        = IOCExtractor.new(),
        risk_curve = RiskCurve.new(),
        timeline   = Timeline.new(),
        chain      = ChainReconstruction.new(),
        alerts     = {},
        env_before = nil,
        env_after  = nil,
        envdiff    = nil,
        stats      = { total_alerts = 0, unique_alerts = 0 },
        risk       = { overall = 0, peak = 0, first_high = nil },
        generated  = nil,
        forensic_hash = nil,
        last_scanned_seq = 0,
    }, ReportObj)
end

function ReportObj:captureBefore()
    if Report.Config.ENABLE_ENV_SNAPSHOT then
        local ok, snapshot = pcall(EnvSnapshot.capture)
        if ok then self.env_before = snapshot end
    end
end

function ReportObj:captureAfter()
    if Report.Config.ENABLE_ENV_SNAPSHOT then
        local ok, snapshot = pcall(EnvSnapshot.capture)
        if ok then
            self.env_after = snapshot
            if self.env_before then
                self.envdiff = EnvSnapshot.diff(self.env_before, self.env_after)
            end
        end
    end
end

function ReportObj:update()
    if not self.edr then return end

    -- IOC scan (incremental)
    local events = self.edr.buffer:snapshot(Report.Config.MAX_EVENTS_IN_REPORT)
    local newEvents = {}
    for i = 1, #events do
        local event = events[i]
        if event.seq and event.seq > self.last_scanned_seq then
            newEvents[#newEvents + 1] = event
            self.last_scanned_seq = event.seq
        end
    end
    self.ioc:scanEvents(newEvents)

    -- Alerts
    self.alerts = self.edr.alerts or {}
    self.stats.total_alerts = #self.alerts

    -- Unique alerts (by rule+message)
    local seen = {}
    for i = 1, #self.alerts do
        local a = self.alerts[i]
        local key = (a.rule or "?") .. "|" .. tostring(a.message or ""):sub(1, 50)
        seen[key] = true
    end
    local unique = 0
    for _ in pairs(seen) do unique = unique + 1 end
    self.stats.unique_alerts = unique

    -- Risk
    local risk = 0
    if self.rules and self.rules.computeSessionRisk then
        local ok, r = pcall(function()
            return self.rules.computeSessionRisk(self.alerts)
        end)
        if ok and type(r) == "number" then risk = r end
    end
    self.risk.overall = risk
    if risk > self.risk.peak then self.risk.peak = risk end
    if not self.risk.first_high and risk >= 0.65 then
        self.risk.first_high = now()
    end

    -- Sample curve
    self.risk_curve:sample(risk, #self.alerts, self.edr.session.events_processed)

    -- Chain
    if Report.Config.ENABLE_CHAIN_RECON then
        self.chain:analyze(self.alerts)
    end
end

function ReportObj:finalize()
    self:captureAfter()
    self:update()

    -- Timeline
    local events = self.edr and self.edr.buffer and
        self.edr.buffer:snapshot(Report.Config.MAX_EVENTS_IN_REPORT) or {}
    self.timeline:build(events, self.alerts)

    -- Forensic hash
    if Report.Config.ENABLE_FORENSIC_HASH then
        local payload = table.concat({
            tostring(self.session.id or "?"),
            tostring(self.stats.total_alerts),
            tostring(self.risk.overall),
            tostring(#self.ioc.indicators),
            tostring(#(self.timeline.entries or {})),
            tostring(os.time()),
        }, "|")
        local ok, result = pcall(sha256, payload)
        self.forensic_hash = ok and result or hash(payload)
    end

    self.generated = walltime()
    if Report._log then
        Report._log(1, "finalize", "report finalized", {
            hash = (self.forensic_hash or ""):sub(1, 16) .. "...",
            alerts = self.stats.total_alerts,
        })
    end
    return self
end

-- Export methods
function ReportObj:exportMarkdown() return Exporter.toMarkdown(self) end
function ReportObj:exportJSON()     return Exporter.toJSON(self) end
function ReportObj:exportHTML()     return Exporter.toHTML(self) end
function ReportObj:exportSTIX()     return Exporter.toSTIX(self) end
function ReportObj:exportMITRE()    return Exporter.toMITRENavigator(self) end
function ReportObj:exportCSV()      return Exporter.toCSV(self) end
function ReportObj:exportSARIF()    return Exporter.toSARIF(self) end
function ReportObj:exportIOCTXT()   return Exporter.toIOCTXT(self) end
function ReportObj:getForensicHash() return self.forensic_hash end
function ReportObj:getVersion() return Report._VERSION end

function ReportObj:saveToFile(path, format)
    format = format or "markdown"
    local content
    if format == "json" then content = self:exportJSON()
    elseif format == "html" then content = self:exportHTML()
    elseif format == "stix" then content = self:exportSTIX()
    elseif format == "mitre" then content = self:exportMITRE()
    elseif format == "csv" then content = self:exportCSV()
    elseif format == "sarif" then content = self:exportSARIF()
    elseif format == "ioc" then content = self:exportIOCTXT()
    else content = self:exportMarkdown() end

    local env = (getgenv and getgenv()) or _G
    if type(env.writefile) == "function" then
        local ok, err = pcall(env.writefile, path, content)
        return ok, err
    end
    return false, "writefile not available"
end

--========== GUI ==========--
function ReportObj:show()
    local parentGui
    local ok, cg = pcall(function() return game:GetService("CoreGui") end)
    if ok and cg then parentGui = cg
    else parentGui = game:GetService("Players").LocalPlayer:WaitForChild("PlayerGui") end

    local gui = Instance.new("ScreenGui")
    gui.Name = "EDR_Report_" .. tostring(math.random(1000, 9999))
    gui.ResetOnSpawn = false
    gui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
    gui.Parent = parentGui

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

    local title = Instance.new("TextLabel")
    title.Size = UDim2.new(1, 0, 0, 36)
    title.BackgroundColor3 = Color3.fromRGB(22, 27, 34)
    title.BorderSizePixel = 0
    title.Text = "  📄 EDR Report v2.0 — " .. tostring(self.session.id or "?")
    title.TextColor3 = Color3.fromRGB(88, 166, 255)
    title.Font = Enum.Font.GothamBold
    title.TextSize = 14
    title.TextXAlignment = Enum.TextXAlignment.Left
    title.Parent = main
    Instance.new("UICorner", title).CornerRadius = UDim.new(0, 12)

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

    local riskLbl = Instance.new("TextLabel")
    riskLbl.Size = UDim2.new(1, -20, 0, 26)
    riskLbl.Position = UDim2.new(0, 10, 0, 6)
    riskLbl.BackgroundTransparency = 1
    riskLbl.Text = "Risk Score"
    riskLbl.TextColor3 = Color3.fromRGB(201, 209, 217)
    riskLbl.Font = Enum.Font.Gotham
    riskLbl.TextSize = 12
    riskLbl.TextXAlignment = Enum.TextXAlignment.Left
    riskLbl.Parent = riskBanner

    local riskVal = Instance.new("TextLabel")
    riskVal.Size = UDim2.new(0.6, -20, 0, 24)
    riskVal.Position = UDim2.new(0, 10, 0, 28)
    riskVal.BackgroundTransparency = 1
    riskVal.Text = string.format("%.1f%%", (self.risk.overall or 0) * 100)
    riskVal.Font = Enum.Font.GothamBold
    riskVal.TextSize = 20
    riskVal.TextXAlignment = Enum.TextXAlignment.Left
    riskVal.Parent = riskBanner
    if self.risk.overall >= 0.85 then
        riskVal.TextColor3 = Color3.fromRGB(248, 81, 73)
    elseif self.risk.overall >= 0.65 then
        riskVal.TextColor3 = Color3.fromRGB(255, 123, 114)
    elseif self.risk.overall >= 0.35 then
        riskVal.TextColor3 = Color3.fromRGB(210, 153, 34)
    else
        riskVal.TextColor3 = Color3.fromRGB(126, 231, 135)
    end

    local predLbl = Instance.new("TextLabel")
    predLbl.Size = UDim2.new(0.4, -20, 0, 24)
    predLbl.Position = UDim2.new(0.6, 0, 0, 28)
    predLbl.BackgroundTransparency = 1
    predLbl.Text = string.format("Prediction: %.1f%%",
        (self.risk_curve.prediction or 0) * 100)
    predLbl.TextColor3 = Color3.fromRGB(150, 170, 190)
    predLbl.Font = Enum.Font.Code
    predLbl.TextSize = 12
    predLbl.TextXAlignment = Enum.TextXAlignment.Right
    predLbl.Parent = riskBanner

    -- Tab buttons
    local tabBar = Instance.new("Frame")
    tabBar.Size = UDim2.new(1, -24, 0, 30)
    tabBar.Position = UDim2.new(0, 12, 0, 114)
    tabBar.BackgroundColor3 = Color3.fromRGB(22, 27, 34)
    tabBar.BorderSizePixel = 0
    tabBar.Parent = main
    Instance.new("UICorner", tabBar).CornerRadius = UDim.new(0, 6)
    Instance.new("UIListLayout", tabBar).FillDirection = Enum.FillDirection.Horizontal

    -- Content scroll
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
    local contentList = Instance.new("UIListLayout", content)
    contentList.Padding = UDim.new(0, 4)
    local contentPad = Instance.new("UIPadding", content)
    contentPad.PaddingTop = UDim.new(0, 8)
    contentPad.PaddingLeft = UDim.new(0, 10)
    contentPad.PaddingRight = UDim.new(0, 10)
    contentPad.PaddingBottom = UDim.new(0, 8)

    local function clearContent()
        for _, c in ipairs(content:GetChildren()) do
            if c:IsA("TextLabel") or c:IsA("Frame") then c:Destroy() end
        end
    end

    local function mkLabel(text, color, size, bold)
        local l = Instance.new("TextLabel")
        l.Size = UDim2.new(1, 0, 0, size or 18)
        l.BackgroundTransparency = 1
        l.Text = text
        l.TextColor3 = color or Color3.fromRGB(201, 209, 217)
        l.Font = bold and Enum.Font.GothamBold or Enum.Font.Code
        l.TextSize = 12
        l.TextXAlignment = Enum.TextXAlignment.Left
        l.TextWrapped = true
        l.TextYAlignment = Enum.TextYAlignment.Top
        l.Parent = content
        return l
    end

    local function renderSummary()
        clearContent()
        mkLabel("SESSION SUMMARY", Color3.fromRGB(88, 166, 255), 20, true)
        mkLabel("")
        mkLabel("Session:     " .. tostring(self.session.id))
        mkLabel("Duration:    " .. fmtDuration(self.session.elapsed))
        mkLabel("Events:      " .. tostring(self.session.events or 0))
        mkLabel("Alerts:      " .. tostring(self.stats.total_alerts) ..
            " (" .. self.stats.unique_alerts .. " unique)")
        mkLabel("Peak Risk:   " .. string.format("%.1f%%", (self.risk.peak or 0) * 100))
        if self.forensic_hash then
            mkLabel("Forensic:    " .. self.forensic_hash:sub(1, 24) .. "...", 
                Color3.fromRGB(150, 170, 190), 10)
        end
        mkLabel("")
        mkLabel("ATTACK CHAIN", Color3.fromRGB(88, 166, 255), 20, true)
        mkLabel("")
        if self.chain then
            local active = self.chain:getActiveStages()
            if #active == 0 then
                mkLabel("(no stages detected)")
            else
                for _, stage in ipairs(active) do
                    mkLabel(string.format("  ● %s — %d indicators", stage.name, stage.count))
                end
                mkLabel(string.format("Completion: %.0f%%", self.chain:getCompletion() * 100),
                    Color3.fromRGB(210, 153, 34))
            end
        end
    end

    local function renderTimeline()
        clearContent()
        mkLabel("FORENSIC TIMELINE", Color3.fromRGB(88, 166, 255), 20, true)
        mkLabel("")
        local txt = self.timeline:renderASCII()
        for line in txt:gmatch("[^\n]+") do
            mkLabel(line, nil, 13)
        end
    end

    local function renderIOC()
        clearContent()
        mkLabel("INDICATORS OF COMPROMISE", Color3.fromRGB(88, 166, 255), 20, true)
        mkLabel("")
        local iocs = self.ioc:getAll()
        for i = 1, math.min(100, #iocs) do
            local ioc = iocs[i]
            local color = Color3.fromRGB(201, 209, 217)
            if ioc.risk >= 0.8 then color = Color3.fromRGB(248, 81, 73)
            elseif ioc.risk >= 0.5 then color = Color3.fromRGB(255, 123, 114)
            elseif ioc.risk >= 0.3 then color = Color3.fromRGB(210, 153, 34)
            end
            mkLabel(string.format("[%s] %s  (×%d, r=%.2f)",
                ioc.type, truncate(ioc.value, 70), ioc.count, ioc.risk), color, 13)
        end
    end

    local function renderRisk()
        clearContent()
        mkLabel("RISK EVOLUTION", Color3.fromRGB(88, 166, 255), 20, true)
        mkLabel("")
        local graph = self.risk_curve:renderASCII(70, 10)
        for line in graph:gmatch("[^\n]+") do
            mkLabel(line, Color3.fromRGB(126, 231, 135), 13)
        end
        mkLabel("")
        mkLabel(string.format("Current:     %.1f%%", (self.risk.overall or 0) * 100))
        mkLabel(string.format("Peak:        %.1f%%", (self.risk.peak or 0) * 100))
        mkLabel(string.format("Prediction:  %.1f%%", (self.risk_curve.prediction or 0) * 100))
    end

    local function renderEnv()
        clearContent()
        mkLabel("ENVIRONMENT MODIFICATIONS", Color3.fromRGB(88, 166, 255), 20, true)
        mkLabel("")
        if not self.envdiff then
            mkLabel("(no snapshot)")
            return
        end
        local d = self.envdiff
        mkLabel(string.format("Added globals:    %d", d.total_added))
        mkLabel(string.format("Removed globals:  %d", d.total_removed))
        mkLabel(string.format("Redefined funcs:  %d", d.total_redefined))
        mkLabel("")
        mkLabel("REDEFINED (top 20)", Color3.fromRGB(248, 81, 73), 15, true)
        for i = 1, math.min(20, #d.redefined) do
            local r = d.redefined[i]
            local sig = r.signature_changed and " ⚠️" or ""
            mkLabel(string.format("  • %s%s", r.key, sig))
        end
    end

    local tabs = {}
    local function makeTab(label, render)
        local b = Instance.new("TextButton")
        b.Size = UDim2.new(0, 100, 1, 0)
        b.BackgroundColor3 = Color3.fromRGB(33, 38, 45)
        b.BorderSizePixel = 0
        b.Text = label
        b.TextColor3 = Color3.fromRGB(201, 209, 217)
        b.Font = Enum.Font.Gotham
        b.TextSize = 12
        b.Parent = tabBar
        Instance.new("UICorner", b).CornerRadius = UDim.new(0, 6)
        b.MouseButton1Click:Connect(function()
            for _, x in ipairs(tabs) do x.btn.BackgroundColor3 = Color3.fromRGB(33, 38, 45) end
            b.BackgroundColor3 = Color3.fromRGB(48, 54, 61)
            render()
        end)
        tabs[#tabs + 1] = { btn = b, render = render }
    end

    makeTab("Summary", renderSummary)
    makeTab("Timeline", renderTimeline)
    makeTab("IOC", renderIOC)
    makeTab("Risk", renderRisk)
    makeTab("Env", renderEnv)

    if tabs[1] then
        tabs[1].btn.BackgroundColor3 = Color3.fromRGB(48, 54, 61)
        tabs[1].render()
    end

    return gui
end

--========== EXPORT ==========--
Report.IOCExtractor    = IOCExtractor
Report.RiskCurve       = RiskCurve
Report.Timeline        = Timeline
Report.EnvSnapshot     = EnvSnapshot
Report.ChainReconstruction = ChainReconstruction
Report.Exporter        = Exporter
Report.Bloom           = Bloom
Report.Stats           = Stats
Report.Kalman          = Kalman
Report.MODE_PROFILES   = MODE_PROFILES
Report.SEV_LABEL       = SEV_LABEL
Report.SEV_ICON        = SEV_ICON
Report.fmtDuration     = fmtDuration
Report.fmtISO          = fmtISO
Report.hash            = hash
Report.chain_hash      = chain_hash

return Report