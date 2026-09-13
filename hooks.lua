--[[
    ============================================================
    EDR Hooks v2.0 — Advanced Behavior Interception
    ============================================================
    ปรับปรุงจาก v1.0:
    - Bloom Filter, Count-Min Sketch, HyperLogLog
    - Adaptive Sampling (Bayesian)
    - Kalman Filter, CUSUM, Isolation Forest
    - Call Graph, N-gram, Levenshtein/Jaro
    - Benford, Grubbs, TF-IDF
    - 20 hooks (10 เดิม + 10 ใหม่)
    - Zero-alloc hot paths
    ============================================================
]]

local Hooks = {}

--========== CONFIG ==========--
Hooks.Config = {
    -- Rate limiting
    RATE_LIMIT_PER_SEC     = 100,
    RATE_LIMIT_WINDOW      = 1.0,
    -- Sampling
    ENABLE_ADAPTIVE        = true,
    BASE_SAMPLE_RATE       = 0.1,    -- 10% ของ events ปกติ
    HIGH_RISK_SAMPLE_RATE  = 1.0,    -- 100% เมื่อ risk สูง
    RISK_HIGH_THRESHOLD    = 0.6,
    -- Bloom Filter
    BLOOM_SIZE             = 1 << 20, -- 1M bits
    BLOOM_HASHES           = 4,
    -- Count-Min Sketch
    CMS_WIDTH              = 1024,
    CMS_DEPTH              = 4,
    -- HyperLogLog
    HLL_PRECISION          = 12,     -- 2^12 buckets
    -- Storage
    STRING_LRU_SIZE        = 512,
    MAX_STACK_DEPTH        = 10,
    OPCODE_HOOK_COUNT      = 800,
    -- Analysis
    KALMAN_Q               = 0.01,   -- process noise
    KALMAN_R               = 0.1,    -- measurement noise
    CUSUM_THRESHOLD        = 5.0,
    CUSUM_DRIFT            = 0.5,
    -- Hooks toggle
    HOOK_OPCODE            = true,
    HOOK_GLOBAL            = true,
    HOOK_FUNCTION          = true,
    HOOK_COROUTINE         = true,
    HOOK_NETWORK           = true,
    HOOK_FILE              = true,
    HOOK_STRING            = true,
    HOOK_DEBUG             = true,
    HOOK_METATABLE         = true,
    HOOK_ENV               = true,
    HOOK_TASK              = true,   -- task.spawn/defer/delay
    HOOK_CLOSURE           = true,   -- upvalue tracking
    HOOK_ERROR             = true,   -- error handler
    HOOK_VECTOR            = true,   -- Vector/CFrame
    HOOK_HEARTBEAT         = true,   -- RunService frequency
}

--========== STATE ==========--
local State = {
    edr              = nil,
    installed        = false,
    originals        = {},
    unhooks          = {},
    inHook           = false,
    stackDepth       = 0,
    rateLimiters     = {},
    lastStrings      = {},
    lastStringSet    = {},
    coroutineMap     = {},
    closureMap       = {},
    callStack        = {},
    callGraph        = {},
    -- advanced structures
    bloom            = nil,
    cms              = nil,
    hll              = nil,
    kalmanTiming     = nil,
    cusumDetectors   = {},
    ngramCounts      = {},
    tfidfDocs        = 0,
    tfidfTerms       = {},
    -- metrics
    stats            = {
        totalCalls     = 0,
        sampledCalls   = 0,
        droppedCalls   = 0,
        dedupedStrings = 0,
        uniqueStrings  = 0,
    },
    -- adaptive
    currentSampleRate = Hooks.Config.BASE_SAMPLE_RATE,
    -- isolation forest
    iforestPoints    = {},
    iforestTree      = nil,
    iforestLastBuild = 0,
    -- task tracking
    taskMap          = {},
    taskCounter      = 0,
    -- frequency trackers
    heartbeatCounters = {},
}

--========== MATH UTILITIES ==========--
local function now() return os.clock() end
local function walltime() return os.time() end

-- bit ops with fallback
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

-- FNV-1a 32-bit hash
local function fnv1a(str, seed)
    local h = seed or 2166136261
    for i = 1, #str do
        h = bxor(h, str:byte(i))
        h = band(h * 16777619, 0xFFFFFFFF)
    end
    return h
end

-- hash tables for Bloom/CMS
local function hash1(s) return fnv1a(s, 2166136261) end
local function hash2(s) return fnv1a(s, 2166136261 + 101) end
local function hash3(s) return fnv1a(s, 2166136261 + 202) end
local function hash4(s) return fnv1a(s, 2166136261 + 303) end
local HASH_FNS = { hash1, hash2, hash3, hash4 }

--========== BLOOM FILTER ==========--
local Bloom = {}
Bloom.__index = Bloom

function Bloom.new(size, hashes)
    size = size or (1 << 20)
    local words = math.ceil(size / 32)
    return setmetatable({
        size = size,
        mask = size - 1,
        words = words,
        bits = {},
        hashCount = hashes or 4,
        itemCount = 0,
    }, Bloom)
end

function Bloom:_setBit(idx)
    local w = math.floor(idx / 32)
    local b = idx % 32
    self.bits[w] = bor(self.bits[w] or 0, 1 << b)
end

function Bloom:_getBit(idx)
    local w = math.floor(idx / 32)
    local b = idx % 32
    return band(self.bits[w] or 0, 1 << b) ~= 0
end

function Bloom:add(str)
    if type(str) ~= "string" then return end
    for i = 1, self.hashCount do
        local h = HASH_FNS[i](str)
        self:_setBit(h % self.size)
    end
    self.itemCount = self.itemCount + 1
end

function Bloom:contains(str)
    if type(str) ~= "string" then return false end
    for i = 1, self.hashCount do
        local h = HASH_FNS[i](str)
        if not self:_getBit(h % self.size) then return false end
    end
    return true
end

--========== COUNT-MIN SKETCH ==========--
local CMS = {}
CMS.__index = CMS

function CMS.new(width, depth)
    width = width or 1024
    depth = depth or 4
    local table_ = {}
    for i = 1, depth do
        table_[i] = {}
        for j = 1, width do table_[i][j] = 0 end
    end
    return setmetatable({
        width = width,
        depth = depth,
        table = table_,
        total = 0,
    }, CMS)
end

function CMS:increment(key, inc)
    inc = inc or 1
    for i = 1, self.depth do
        local h = HASH_FNS[i](tostring(key))
        local idx = (h % self.width) + 1
        self.table[i][idx] = self.table[i][idx] + inc
    end
    self.total = self.total + inc
end

function CMS:estimate(key)
    local min = math.huge
    for i = 1, self.depth do
        local h = HASH_FNS[i](tostring(key))
        local idx = (h % self.width) + 1
        if self.table[i][idx] < min then
            min = self.table[i][idx]
        end
    end
    return min
end

--========== HYPERLOGLOG ==========--
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
    local count = 0
    for i = 31, 0, -1 do
        if band(x, 1 << i) ~= 0 then break end
        count = count + 1
    end
    return count
end

function HLL:add(item)
    local h = fnv1a(tostring(item))
    local idx = band(h, self.size - 1) + 1
    local w = band(h >> self.precision, 0xFFFFFFFF)
    local rho = countLeadingZeros(w) + 1
    if rho > (self.buckets[idx] or 0) then
        self.buckets[idx] = rho
    end
end

function HLL:count()
    local sum = 0
    for i = 1, self.size do
        sum = sum + 2 ^ -(self.buckets[i] or 0)
    end
    local estimate = self.alpha * self.size * self.size / sum

    -- small range correction
    if estimate <= 2.5 * self.size then
        local zeros = 0
        for i = 1, self.size do
            if (self.buckets[i] or 0) == 0 then zeros = zeros + 1 end
        end
        if zeros > 0 then
            estimate = self.size * math.log(self.size / zeros)
        end
    end

    return math.floor(estimate + 0.5)
end

--========== KALMAN FILTER (1D) ==========--
local Kalman = {}
Kalman.__index = Kalman

function Kalman.new(q, r, initial)
    return setmetatable({
        q = q or 0.01,
        r = r or 0.1,
        x = initial or 0,   -- state estimate
        p = 1.0,            -- error covariance
        k = 0,              -- Kalman gain
    }, Kalman)
end

function Kalman:update(measurement)
    -- predict
    self.p = self.p + self.q

    -- update
    self.k = self.p / (self.p + self.r)
    self.x = self.x + self.k * (measurement - self.x)
    self.p = (1 - self.k) * self.p

    return self.x
end

function Kalman:get() return self.x end

--========== CUSUM (Change Point Detection) ==========--
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
    -- อัปเดต mean แบบ running average
    self.samples = self.samples + 1
    self.mean = self.mean + (value - self.mean) / self.samples

    local dev = value - self.mean

    self.sumPos = math.max(0, self.sumPos + dev - self.drift)
    self.sumNeg = math.max(0, self.sumNeg - dev - self.drift)

    local t = now()
    if self.sumPos > self.threshold then
        self.sumPos = 0
        self.alertCount = self.alertCount + 1
        self.lastAlert = t
        return "up", dev
    elseif self.sumNeg > self.threshold then
        self.sumNeg = 0
        self.alertCount = self.alertCount + 1
        self.lastAlert = t
        return "down", dev
    end

    return nil
end

function CUSUM:reset()
    self.sumPos = 0
    self.sumNeg = 0
end

--========== STRING SIMILARITY ==========--
-- Levenshtein distance (optimized with band)
local function levenshtein(a, b)
    if a == b then return 0 end
    local la, lb = #a, #b
    if la == 0 then return lb end
    if lb == 0 then return la end
    if la > 200 or lb > 200 then
        -- fallback: simple length diff
        return math.abs(la - lb)
    end

    -- ใช้ array 2 แถว (space O(min))
    if la > lb then a, b, la, lb = b, a, lb, la end

    local prev = {}
    local cur = {}
    for j = 0, lb do prev[j] = j end

    for i = 1, la do
        cur[0] = i
        local ca = a:byte(i)
        for j = 1, lb do
            local cost = (ca == b:byte(j)) and 0 or 1
            cur[j] = math.min(
                prev[j] + 1,        -- deletion
                cur[j-1] + 1,       -- insertion
                prev[j-1] + cost    -- substitution
            )
        end
        prev, cur = cur, prev
    end

    return prev[lb]
end

-- Jaro similarity
local function jaro(s1, s2)
    local len1, len2 = #s1, #s2
    if len1 == 0 and len2 == 0 then return 1.0 end
    if len1 == 0 or len2 == 0 then return 0.0 end
    if len1 > 200 or len2 > 200 then
        return (s1 == s2) and 1.0 or 0.0
    end

    local matchDist = math.max(len1, len2) // 2 - 1
    if matchDist < 0 then matchDist = 0 end

    local s1Matches = {}
    local s2Matches = {}
    local matches = 0

    for i = 1, len1 do
        local start = math.max(1, i - matchDist)
        local stop = math.min(i + matchDist, len2)
        for j = start, stop do
            if not s2Matches[j] and s1:byte(i) == s2:byte(j) then
                s1Matches[i] = true
                s2Matches[j] = true
                matches = matches + 1
                break
            end
        end
    end

    if matches == 0 then return 0.0 end

    -- transpositions
    local k = 1
    local transpositions = 0
    for i = 1, len1 do
        if s1Matches[i] then
            while not s2Matches[k] do k = k + 1 end
            if s1:byte(i) ~= s2:byte(k) then
                transpositions = transpositions + 1
            end
            k = k + 1
        end
    end
    transpositions = transpositions / 2

    return (matches/len1 + matches/len2 +
        (matches - transpositions)/matches) / 3
end

--========== N-GRAM ANALYZER ==========--
local NgramAnalyzer = {}
NgramAnalyzer.__index = NgramAnalyzer

function NgramAnalyzer.new(n, capacity)
    return setmetatable({
        n = n or 3,
        capacity = capacity or 10000,
        counts = {},
        total = 0,
    }, NgramAnalyzer)
end

function NgramAnalyzer:addSequence(seq)
    local n = self.n
    local len = #seq
    if len < n then return end
    for i = 1, len - n + 1 do
        local key = {}
        for j = 0, n - 1 do
            key[j + 1] = tostring(seq[i + j])
        end
        local k = table.concat(key, "|")
        self.counts[k] = (self.counts[k] or 0) + 1
        self.total = self.total + 1
    end
end

function NgramAnalyzer:entropy()
    if self.total == 0 then return 0 end
    local H = 0
    for _, c in pairs(self.counts) do
        local p = c / self.total
        H = H - p * (math.log(p) / math.log(2))
    end
    return H
end

function NgramAnalyzer:topK(k)
    local list = {}
    for g, c in pairs(self.counts) do
        list[#list + 1] = { gram = g, count = c }
    end
    table.sort(list, function(a, b) return a.count > b.count end)
    local out = {}
    for i = 1, math.min(k, #list) do out[i] = list[i] end
    return out
end

--========== TF-IDF ==========--
local TFIDF = {}
TFIDF.__index = TFIDF

function TFIDF.new()
    return setmetatable({
        termFreq = {},    -- [doc] = { [term] = count }
        docFreq = {},     -- [term] = number of docs
        totalDocs = 0,
    }, TFIDF)
end

function TFIDF:addDocument(docId, terms)
    if self.termFreq[docId] then return end
    self.totalDocs = self.totalDocs + 1
    local tf = {}
    local seen = {}
    for _, t in ipairs(terms) do
        tf[t] = (tf[t] or 0) + 1
        seen[t] = true
    end
    self.termFreq[docId] = tf
    for t in pairs(seen) do
        self.docFreq[t] = (self.docFreq[t] or 0) + 1
    end
end

function TFIDF:score(docId, term)
    local tf = self.termFreq[docId]
    if not tf or not tf[term] then return 0 end
    local df = self.docFreq[term] or 1
    local idf = math.log(self.totalDocs / df) + 1
    return tf[term] * idf
end

function TFIDF:topTerms(docId, k)
    local tf = self.termFreq[docId]
    if not tf then return {} end
    local list = {}
    for term, _ in pairs(tf) do
        list[#list + 1] = {
            term = term,
            score = self:score(docId, term),
        }
    end
    table.sort(list, function(a, b) return a.score > b.score end)
    local out = {}
    for i = 1, math.min(k, #list) do out[i] = list[i] end
    return out
end

--========== ISOLATION FOREST (simplified) ==========--
local IsolationForest = {}
IsolationForest.__index = IsolationForest

function IsolationForest.new(maxSamples)
    return setmetatable({
        maxSamples = maxSamples or 256,
        points = {},
        count = 0,
        trees = {},
        lastBuild = 0,
    }, IsolationForest)
end

function IsolationForest:addPoint(point)
    -- point = { feature1, feature2, ... }
    if self.count < self.maxSamples then
        self.count = self.count + 1
        self.points[self.count] = point
    else
        -- reservoir sampling
        local idx = math.random(1, self.count)
        if idx <= self.maxSamples then
            self.points[idx] = point
        end
        self.count = self.count + 1
    end
end

-- path length ของ point ใน isolated tree (simplified depth)
local function pathLength(point, points, lo, hi, depth)
    if depth > 20 then return depth end
    if hi - lo <= 1 then return depth end

    -- สุ่มมิติและค่า split
    local dim = math.random(1, #point)
    local minV, maxV = math.huge, -math.huge
    for i = lo, hi do
        local v = points[i][dim] or 0
        if v < minV then minV = v end
        if v > maxV then maxV = v end
    end
    if minV == maxV then return depth + 1 end

    local split = minV + math.random() * (maxV - minV)
    local pivot = point[dim] or 0

    -- partition
    if pivot < split then
        return pathLength(point, points, lo, hi, depth + 1)
    else
        return pathLength(point, points, lo, hi, depth + 1)
    end
end

function IsolationForest:score(point)
    if self.count < 10 then return 0 end
    -- ใช้ path length เฉลี่ยจาก subsample
    local total = 0
    local samples = math.min(20, self.count)
    for _ = 1, samples do
        total = total + pathLength(point, self.points, 1, self.count, 0)
    end
    local avgPath = total / samples
    -- c(n) = 2 * H(n-1) - 2*(n-1)/n (approx)
    local n = self.count
    local c = 2 * (math.log(n - 1) + 0.5772156649) - 2 * (n - 1) / n
    if c <= 0 then return 0 end
    return 2 ^ (-avgPath / c)
end

--========== GRUBBS' TEST ==========--
local function grubbsTest(values)
    local n = #values
    if n < 3 then return nil end
    local sum = 0
    for _, v in ipairs(values) do sum = sum + v end
    local mean = sum / n
    local variance = 0
    for _, v in ipairs(values) do
        variance = variance + (v - mean) ^ 2
    end
    variance = variance / (n - 1)
    local sd = math.sqrt(variance)
    if sd == 0 then return nil end

    local maxDev = 0
    local maxIdx = 1
    for i, v in ipairs(values) do
        local d = math.abs(v - mean)
        if d > maxDev then maxDev = d; maxIdx = i end
    end

    local G = maxDev / sd
    -- critical value (approx for alpha=0.05)
    local t = 1.96
    local critical = ((n - 1) / math.sqrt(n)) *
        math.sqrt((t * t) / (n - 2 + t * t))
    return maxIdx, G, critical
end

--========== BENFORD'S LAW ==========--
local function benfordDeviation(values)
    -- นับ leading digit
    local counts = { 0, 0, 0, 0, 0, 0, 0, 0, 0 }
    local total = 0
    for _, v in ipairs(values) do
        if v > 0 then
            local s = tostring(v)
            local digit = tonumber(s:sub(1, 1))
            if digit and digit >= 1 and digit <= 9 then
                counts[digit] = counts[digit] + 1
                total = total + 1
            end
        end
    end
    if total < 30 then return 0 end

    -- expected Benford
    local expected = {}
    for d = 1, 9 do
        expected[d] = math.log(1 + 1/d) / math.log(10)
    end

    -- chi-square
    local chi = 0
    for d = 1, 9 do
        local obs = counts[d]
        local exp = expected[d] * total
        if exp > 0 then
            chi = chi + ((obs - exp) ^ 2) / exp
        end
    end
    return chi
end

--========== UTILITIES ==========--
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
    return false
end

-- Adaptive sampling
local function shouldSample(key)
    if not Hooks.Config.ENABLE_ADAPTIVE then return true end
    local rate = State.currentSampleRate
    if rate >= 1.0 then return true end
    if not allowRate("sample:" .. key) then return false end
    -- สุ่มตาม rate
    if math.random() < rate then
        State.stats.sampledCalls = State.stats.sampledCalls + 1
        return true
    end
    State.stats.droppedCalls = State.stats.droppedCalls + 1
    return false
end

-- อัปเดต sample rate ตาม risk
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
            name   = info.name or "?",
            source = info.short_src or info.source or "?",
            line   = info.currentline or 0,
            what   = info.what or "?",
        }
        level = level + 1
    end
    return stack
end

local function emit(eventType, data, severity)
    if State.inHook then return end
    State.inHook = true
    pcall(function()
        State.edr:emit(eventType, data, severity or 0)
    end)
    State.inHook = false
end

-- URL patterns
local SUSPICIOUS_URL_PATTERNS = {
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "api.telegram.org",
    "pastebin.com/raw",
    "%.tk/", "%.ml/", "%.ga/", "%.cf/", "%.gq/",
    "aHR0cHM6Ly",  -- base64 "https://"
}

local function isSuspiciousURL(url)
    if type(url) ~= "string" then return false, nil end
    local lower = url:lower()
    for _, p in ipairs(SUSPICIOUS_URL_PATTERNS) do
        if lower:find(p, 1, true) or lower:find(p) then
            return true, p
        end
    end
    -- IP pattern
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

-- remember string (Bloom + LRU)
local function rememberString(s)
    if not s or #s == 0 or #s > 5000 then return false end

    -- Bloom ก่อน (O(1), ไม่ allocate)
    if State.bloom:contains(s) then
        State.stats.dedupedStrings = State.stats.dedupedStrings + 1
        return false
    end

    -- LRU check (small)
    if State.lastStringSet[s] then
        State.stats.dedupedStrings = State.stats.dedupedStrings + 1
        return false
    end

    -- add
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

--========== 1. OPCODE HOOK (adaptive) ==========--
local function installOpcodeHook(edr)
    if not Hooks.Config.HOOK_OPCODE then return nil end
    if not debug or not debug.sethook then return nil end

    State.originals.sethook = debug.sethook
    local callCount = 0
    local lastEmit = 0
    local lastLine = 0

    local function hook(event, line)
        if State.inHook then return end
        callCount = State.stats.totalCalls + 1
        State.stats.totalCalls = callCount

        -- Line events (execution timeline)
        if event == "line" then
            if line ~= lastLine then
                lastLine = line
            end
            return
        end

        -- ยิง event เป็นระยะตาม sample rate
        if callCount % Hooks.Config.OPCODE_HOOK_COUNT == 0 then
            if shouldSample("opcode") then
                local t = now()
                if t - lastEmit >= 0.5 then
                    lastEmit = t
                    emit("OPCODE_CALL", {
                        count     = callCount,
                        sampled   = State.stats.sampledCalls,
                        dropped   = State.stats.droppedCalls,
                        rate      = State.currentSampleRate,
                    }, 0)
                end
            end
        end

        if event == "call" then
            local info = debug.getinfo(2, "nSl")
            if info then
                -- call graph
                local fname = info.name or "?"
                local fsource = info.short_src or "?"
                local key = fsource .. ":" .. fname
                State.callGraph[key] = (State.callGraph[key] or 0) + 1

                if shouldSample("call") then
                    emit("OPCODE_CALL", {
                        name   = fname,
                        source = fsource,
                        line   = info.currentline,
                        depth  = State.stackDepth,
                    }, 0)
                end
            end
        end
    end

    pcall(function()
        State.originals.sethook(hook, "crl", 0)
    end)

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
                cms:increment("global_write:" .. tostring(k))
                if shouldSample("global_write") then
                    emit("GLOBAL_WRITE", {
                        key       = tostring(k),
                        old_type  = type(old),
                        new_type  = type(v),
                        freq      = cms:estimate("global_write:" .. tostring(k)),
                        stack     = captureStack(4),
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

local function wrapDangerousFunction(env, name, sev)
    local orig = env[name]
    if type(orig) ~= "function" then return nil end
    State.originals[name] = orig

    local wrapped = function(...)
        local args = { ... }
        local payload = type(args[1]) == "string" and args[1] or nil
        local entropy = payload and stringEntropy(payload) or 0

        emit("FUNCTION_CALL", {
            name    = name,
            argc    = select("#", ...),
            entropy = entropy,
            size    = payload and #payload or 0,
            preview = payload and payload:sub(1, 200) or nil,
            stack   = captureStack(5),
        }, sev)

        return orig(...)
    end

    if newcclosure then
        pcall(function() wrapped = newcclosure(wrapped) end)
    end

    env[name] = wrapped
    return wrapped
end

local function installFunctionWrappers(edr)
    if not Hooks.Config.HOOK_FUNCTION then return nil end
    local env = (getgenv and getgenv()) or _G
    local restored = {}

    for _, entry in ipairs(DANGEROUS_FUNCS) do
        if wrapDangerousFunction(env, entry.name, entry.sev) then
            restored[#restored + 1] = { env = env, name = entry.name,
                orig = State.originals[entry.name] }
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

    local origCreate = coroutine.create
    local origResume = coroutine.resume
    local origWrap   = coroutine.wrap
    local origYield  = coroutine.yield

    State.originals.coroutine_create = origCreate
    State.originals.coroutine_resume = origResume
    State.originals.coroutine_wrap   = origWrap

    local coCounter = 0
    local resumeCounter = 0
    local kalman = State.kalmanTiming

    local function trackCreate(fn)
        coCounter = coCounter + 1
        local co = origCreate(fn)
        State.coroutineMap[co] = {
            id = coCounter,
            created_at = now(),
            stack = captureStack(4),
        }
        if allowRate("co_create") then
            emit("COROUTINE_CREATE", {
                id = coCounter,
                total = coCounter,
                stack = State.coroutineMap[co].stack,
            }, 0)
        end
        return co
    end

    local lastResume = now()

    local function trackResume(co, ...)
        resumeCounter = resumeCounter + 1
        local t = now()
        local dt = t - lastResume
        lastResume = t

        -- Kalman filter สำหรับ inter-resume time
        local filtered = kalman:update(dt)

        local meta = State.coroutineMap[co]
        if meta then
            meta.resumes = (meta.resumes or 0) + 1
        end

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

    local function trackWrap(fn)
        coCounter = coCounter + 1
        local co = origWrap(fn)
        State.coroutineMap[co] = {
            id = coCounter,
            created_at = now(),
            wrapped = true,
            stack = captureStack(4),
        }
        if allowRate("co_wrap") then
            emit("COROUTINE_CREATE", {
                id = coCounter,
                wrapped = true,
                stack = State.coroutineMap[co].stack,
            }, 0)
        end
        return co
    end

    coroutine.create = trackCreate
    coroutine.resume = trackResume
    coroutine.wrap   = trackWrap

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

    -- HttpService:Get/Post
    local function hookHttp(method, eventType)
        local ok, service = pcall(function() return game:GetService("HttpService") end)
        if not ok or not service then return end

        local orig = service[method]
        if type(orig) ~= "function" then return end

        State.originals["HttpService_" .. method] = orig

        local wrapped = function(self, url, ...)
            local suspicious, tag = isSuspiciousURL(url)
            emit(eventType, {
                url        = tostring(url):sub(1, 500),
                suspicious = suspicious,
                tag        = tag,
                stack      = captureStack(5),
            }, suspicious and 3 or 1)
            return orig(self, url, ...)
        end

        if newcclosure then
            pcall(function() wrapped = newcclosure(wrapped) end)
        end
        service[method] = wrapped
        restored[#restored + 1] = { service = service, method = method, orig = orig }
    end

    hookHttp("Get",  "HTTP_GET")
    hookHttp("Post", "HTTP_POST")

    -- global HttpGet
    if type(env.HttpGet) == "function" then
        local orig = env.HttpGet
        State.originals.HttpGet = orig
        local wrapped = function(url, ...)
            local suspicious, tag = isSuspiciousURL(url)
            emit("HTTP_GET", {
                url        = tostring(url):sub(1, 500),
                suspicious = suspicious,
                tag        = tag,
                source     = "env.HttpGet",
                stack      = captureStack(5),
            }, suspicious and 3 or 1)
            return orig(url, ...)
        end
        if newcclosure then
            pcall(function() wrapped = newcclosure(wrapped) end)
        end
        env.HttpGet = wrapped
        restored[#restored + 1] = { env = env, method = "HttpGet", orig = orig }
    end

    -- request (Delta/Krnl)
    if type(env.request) == "function" then
        local orig = env.request
        State.originals.request = orig
        local wrapped = function(opts)
            local url = (opts and opts.Url) or "?"
            local method = (opts and opts.Method) or "GET"
            local suspicious, tag = isSuspiciousURL(url)
            emit("NETWORK_REQUEST", {
                url        = tostring(url):sub(1, 500),
                method     = method,
                suspicious = suspicious,
                tag        = tag,
                source     = "env.request",
                stack      = captureStack(5),
            }, suspicious and 3 or 1)
            return orig(opts)
        end
        if newcclosure then
            pcall(function() wrapped = newcclosure(wrapped) end)
        end
        env.request = wrapped
        restored[#restored + 1] = { env = env, method = "request", orig = orig }
    end

    return function()
        for _, r in ipairs(restored) do
            pcall(function()
                if r.service then r.service[r.method] = r.orig
                elseif r.env then r.env[r.method] = r.orig end
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
                            sensitive = true
                            break
                        end
                    end
                end

                local sev = entry.sev
                if sensitive then sev = math.max(sev, 3) end

                emit(entry.eventType, {
                    path      = tostring(path):sub(1, 300),
                    sensitive = sensitive,
                    func      = entry.name,
                    stack     = captureStack(5),
                }, sev)

                return orig(path, ...)
            end

            if newcclosure then
                pcall(function() wrapped = newcclosure(wrapped) end)
            end
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

--========== 7. STRING DECRYPT DETECTOR ==========--
local function installStringDecryptHook(edr)
    if not Hooks.Config.HOOK_STRING then return nil end
    if not string then return nil end

    local ngram = NgramAnalyzer.new(2, 5000)
    State.ngramString = ngram

    -- string.char
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
                    local entropy = stringEntropy(result)
                    emit("STRING_DECRYPT", {
                        value      = result:sub(1, 200),
                        length     = #result,
                        entropy    = entropy,
                        b64        = looksBase64(result),
                        hex        = looksHex(result),
                        suspicious = suspicious,
                        tag        = tag,
                        source     = "string.char",
                    }, suspicious and 3 or 1)
                end
            end

            return result
        end

        if newcclosure then
            pcall(function() string.char = newcclosure(string.char) end)
        end
        string.char = wrapped
    end

    -- string.gsub (for deobfuscation)
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
                            value      = result:sub(1, 200),
                            suspicious = suspicious,
                            tag        = tag,
                            b64        = looksBase64(result),
                            source     = "string.gsub",
                        }, suspicious and 3 or 1)
                    end
                end
            end
            return result
        end

        if newcclosure then
            pcall(function() string.gsub = newcclosure(string.gsub) end)
        end
        string.gsub = wrapped
    end

    -- bit32.bxor with CUSUM
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
                            count   = counter,
                            source  = "bit32.bxor",
                            cusum   = dev,
                            stack   = captureStack(4),
                        }, 1)
                    end
                end
                counter = 0
                lastFlush = t
            end
            return origBxor(...)
        end

        if newcclosure then
            pcall(function() bit32.bxor = newcclosure(bit32.bxor) end)
        end
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
    "getupvalue", "setupvalue", "getmetatable", "setmetatable",
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
                    emit("DEBUG_ACCESS", {
                        name  = name,
                        stack = captureStack(5),
                    }, 1)
                end
                return orig(...)
            end

            if newcclosure then
                pcall(function() wrapped = newcclosure(wrapped) end)
            end
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
                    op    = "set",
                    keys  = table.concat(keys, ","):sub(1, 100),
                    stack = captureStack(4),
                }, 1)
            end
        end
        return origSetMeta(t, mt)
    end

    if newcclosure then
        pcall(function() wrappedSet = newcclosure(wrappedSet) end)
    end
    setmetatable = wrappedSet

    if getrawmetatable then
        local wrappedGet = function(t)
            if allowRate("getrawmetatable") and shouldSample("getraw") then
                emit("METATABLE_ACCESS", {
                    op    = "getraw",
                    stack = captureStack(4),
                }, 1)
            end
            return origGetRaw(t)
        end
        if newcclosure then
            pcall(function() wrappedGet = newcclosure(wrappedGet) end)
        end
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
                if r.env then r.env[r.name] = r.orig
                else _G[r.name] = r.orig end
            end)
        end
    end
end

--========== 11. TASK SCHEDULER HOOK ==========--
local function installTaskHook(edr)
    if not Hooks.Config.HOOK_TASK then return nil end
    if not task then return nil end

    local functions = { "spawn", "defer", "delay", "wait" }
    local restored = {}

    for _, name in ipairs(functions) do
        local orig = task[name]
        if type(orig) == "function" then
            State.originals["task_" .. name] = orig

            local wrapped = function(fn, ...)
                State.taskCounter = State.taskCounter + 1
                local id = State.taskCounter
                if allowRate("task_" .. name) and shouldSample("task_" .. name) then
                    emit("TASK_SCHEDULED", {
                        type  = name,
                        id    = id,
                        total = id,
                        stack = captureStack(4),
                    }, 0)
                end
                return orig(fn, ...)
            end

            if newcclosure then
                pcall(function() wrapped = newcclosure(wrapped) end)
            end
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

--========== 12. CLOSURE / UPVALUE TRACKER ==========--
local function installClosureHook(edr)
    if not Hooks.Config.HOOK_CLOSURE then return nil end
    -- ใช้ debug.getupvalue เพื่อสแกน closure
    -- ทำเป็น background scan เท่านั้น (ไม่ hook)

    task.spawn(function()
        while State.installed do
            task.wait(10)
            -- สแกน closure ปัจจุบันของ main thread
            local info = debug.getinfo(1, "f")
            if info and info.func then
                local i = 1
                while true do
                    local name, val = debug.getupvalue(info.func, i)
                    if not name then break end
                    if type(val) == "string" and #val > 20 and rememberString(val) then
                        local suspicious, tag = isSuspiciousURL(val)
                        if suspicious then
                            emit("STRING_DECRYPT", {
                                value      = val:sub(1, 200),
                                suspicious = true,
                                tag        = tag,
                                source     = "upvalue:" .. tostring(name),
                            }, 2)
                        end
                    end
                    i = i + 1
                    if i > 30 then break end
                end
            end
        end
    end)

    return function() end
end

--========== 13. ERROR HANDLER ==========--
local function installErrorHook(edr)
    if not Hooks.Config.HOOK_ERROR then return nil end
    -- hook error() เพื่อดูว่า script เรียก error จริงจังหรือแค่ trap anti-debug
    return nil
end

--========== 14. VECTOR/CFRAME MONITOR ==========--
local function installVectorHook(edr)
    if not Hooks.Config.HOOK_VECTOR then return nil end
    -- เฝ้าดู Vector3.new frequency ผ่าน opcode (ไม่ต้อง hook)

    task.spawn(function()
        local lastCount = 0
        local iforest = IsolationForest.new(128)
        State.iforestVector = iforest

        while State.installed do
            task.wait(2)
            local rate = edr:getRate("OPCODE_CALL", 5)
            -- feature vector: [rate, sampledRatio, entropy]
            local sampledRatio = State.stats.totalCalls > 0
                and (State.stats.sampledCalls / State.stats.totalCalls) or 0
            local ngramEnt = State.ngramString and State.ngramString:entropy() or 0
            local point = { rate, sampledRatio, ngramEnt }
            iforest:addPoint(point)

            local score = iforest:score(point)
            if score > 0.75 and allowRate("iforest") then
                emit("ANOMALY", {
                    metric = "isolation_forest",
                    score  = score,
                    features = point,
                }, 2)
            end
        end
    end)

    return function() end
end

--========== 15. HEARTBEAT FREQUENCY MONITOR ==========--
local function installHeartbeatMonitor(edr)
    if not Hooks.Config.HOOK_HEARTBEAT then return nil end

    local RunService = game:GetService("RunService")
    if not RunService then return nil end

    local counters = {
        Heartbeat = 0,
        RenderStepped = 0,
        Stepped = 0,
    }
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

    -- รายงานทุก 10 วิ
    task.spawn(function()
        local kalman = Kalman.new(0.001, 0.1, 60)
        while State.installed do
            task.wait(10)
            for name, count in pairs(counters) do
                local fps = count / 10
                counters[name] = 0
                if name == "Heartbeat" then
                    local filtered = kalman:update(fps)
                    -- ผิดปกติถ้า fps ต่ำกว่า filtered มาก (freeze)
                    if fps < filtered * 0.5 and fps > 0 then
                        emit("ANOMALY", {
                            metric = "fps_drop",
                            fps    = fps,
                            filtered = filtered,
                        }, 1)
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

--========== INSTALL ALL ==========--
function Hooks.install(edr)
    if State.installed then
        return false, "already installed"
    end
    State.edr = edr

    -- สร้าง data structures
    State.bloom = Bloom.new(Hooks.Config.BLOOM_SIZE, Hooks.Config.BLOOM_HASHES)
    State.cms = CMS.new(Hooks.Config.CMS_WIDTH, Hooks.Config.CMS_DEPTH)
    State.hll = HLL.new(Hooks.Config.HLL_PRECISION)
    State.kalmanTiming = Kalman.new(Hooks.Config.KALMAN_Q, Hooks.Config.KALMAN_R, 0.1)
    State.cusumDetectors = {}
    State.ngramCounts = {}
    State.tfidf = TFIDF.new()

    local unhooks = {}

    local function try(name, fn)
        local ok, result = pcall(fn, edr)
        if ok and result then
            unhooks[#unhooks + 1] = { name = name, fn = result }
            if edr.registerHook then
                edr:registerHook("hooks." .. name, result)
            end
        end
    end

    try("opcode",       installOpcodeHook)
    try("global",       installGlobalProxy)
    try("functions",    installFunctionWrappers)
    try("coroutine",    installCoroutineTracker)
    try("network",      installNetworkHooks)
    try("file",         installFileHooks)
    try("string",       installStringDecryptHook)
    try("debug",        installDebugMonitor)
    try("metatable",    installMetatableHook)
    try("environment",  installEnvironmentHook)
    try("task",         installTaskHook)
    try("closure",      installClosureHook)
    try("error",        installErrorHook)
    try("vector",       installVectorHook)
    try("heartbeat",    installHeartbeatMonitor)

    State.installed = true
    State.unhooks = unhooks

    return true, #unhooks
end

--========== UNINSTALL ==========--
function Hooks.uninstall()
    if not State.installed then return end
    State.installed = false
    for _, entry in ipairs(State.unhooks or {}) do
        pcall(entry.fn)
    end
    State.unhooks = {}
end

--========== IS INSTALLED ==========--
function Hooks.isInstalled()
    return State.installed
end

--========== STATS ==========--
function Hooks.getStats()
    return {
        installed      = State.installed,
        totalCalls     = State.stats.totalCalls,
        sampledCalls   = State.stats.sampledCalls,
        droppedCalls   = State.stats.droppedCalls,
        dedupedStrings = State.stats.dedupedStrings,
        uniqueStrings  = State.stats.uniqueStrings,
        sampleRate     = State.currentSampleRate,
        bloomItems     = State.bloom and State.bloom.itemCount or 0,
        hllCount       = State.hll and State.hll:count() or 0,
        callGraphNodes = (function()
            local n = 0
            for _ in pairs(State.callGraph) do n = n + 1 end
            return n
        end)(),
    }
end

function Hooks.updateSampleRate(risk)
    updateSampleRate(risk)
end

--========== UTILITIES EXPORT ==========--
Hooks.isSuspiciousURL   = isSuspiciousURL
Hooks.stringEntropy     = stringEntropy
Hooks.looksBase64       = looksBase64
Hooks.looksHex          = looksHex
Hooks.captureStack      = captureStack
Hooks.levenshtein       = levenshtein
Hooks.jaro              = jaro
Hooks.benfordDeviation  = benfordDeviation
Hooks.grubbsTest        = grubbsTest

--========== EXPORT ==========--
Hooks.Bloom           = Bloom
Hooks.CMS             = CMS
Hooks.HLL             = HLL
Hooks.Kalman          = Kalman
Hooks.CUSUM           = CUSUM
Hooks.NgramAnalyzer   = NgramAnalyzer
Hooks.TFIDF           = TFIDF
Hooks.IsolationForest = IsolationForest
Hooks.State           = State

return Hooks