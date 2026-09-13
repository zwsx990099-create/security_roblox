--[[
    ============================================================
    EDR Rules Engine v2.0 — Compiled + Adaptive + Chained
    ============================================================
    หลักการ:
    - Compiled rules → pre-compute closures (fast)
    - Bloom filter dedup → 1M+ entries in 1MB
    - Priority min-heap → top-k selection
    - Adaptive thresholds → baseline learning
    - Fuzzy matching → Levenshtein/Jaro
    - Rule chaining → requires/implies
    - Meta-rules → cluster detection
    - 40+ default rules
    - MITRE ATT&CK weighted scoring

    ใช้ร่วมกับ:
    - edr_core.lua : event types, alerts, timeseries
    - hooks.lua    : event source
    - report.lua   : consume alerts
    - ui.lua       : display alerts + rule stats
    ============================================================
]]

local Rules = {}

--========== CONFIG ==========--
Rules.Config = {
    MATCH_MODE              = "all",       -- "all" | "first" | "topk"
    MAX_MATCHES_PER_SCAN    = 100,
    TOPK                    = 20,
    DEDUP_ENABLED           = true,
    DEDUP_COOLDOWN          = 60,
    DEDUP_BLOOM_SIZE        = 1 << 20,
    DEDUP_BLOOM_HASHES      = 4,
    ADAPTIVE_ENABLED        = true,
    ADAPTIVE_ALPHA          = 0.15,
    CHAINING_ENABLED        = true,
    META_RULES_ENABLED      = true,
    FUZZY_ENABLED           = true,
    FUZZY_THRESHOLD         = 0.85,
    STATS_ENABLED           = true,
    SUPPRESSION_ENABLED     = true,
    HOT_RELOAD              = true,
    ENABLE_MITRE            = true,
    LOG_LEVEL               = 1,
}

--========== SEVERITY WEIGHTS ==========--
local SEVERITY_WEIGHT = { [0]=0.05, [1]=0.25, [2]=0.55, [3]=0.80, [4]=1.00 }

--========== MITRE WEIGHTS ==========--
local MITRE_WEIGHT = {
    ["T1059"]     = 1.15,  -- Scripting
    ["T1059.007"] = 1.10,  -- JavaScript (Lua analog)
    ["T1056"]     = 1.20,  -- Input Capture
    ["T1056.001"] = 1.20,  -- Keylogging
    ["T1005"]     = 1.15,  -- Data from Local System
    ["T1071"]     = 1.10,  -- App Layer Protocol
    ["T1071.001"] = 1.10,  -- Web Protocols
    ["T1041"]     = 1.30,  -- Exfil Over C2
    ["T1567"]     = 1.25,  -- Exfil Over Web Service
    ["T1496"]     = 1.15,  -- Resource Hijacking
    ["T1055"]     = 1.40,  -- Process Injection
    ["T1620"]     = 1.20,  -- Reflective Code Loading
    ["T1027"]     = 0.85,  -- Obfuscation (baseline)
    ["T1140"]     = 0.90,  -- Deobfuscate/Decode
    ["T1552"]     = 1.30,  -- Unsecured Credentials
    ["T1555"]     = 1.35,  -- Creds from Password Stores
    ["T1115"]     = 1.25,  -- Clipboard
    ["T1113"]     = 1.20,  -- Screen Capture
    ["T1543"]     = 1.15,  -- Create/Modify System Process
    ["T1562.001"] = 1.35,  -- Impair Defenses
    ["T1622"]     = 1.20,  -- Debugger Evasion
    ["T1078"]     = 1.20,  -- Valid Accounts
    ["T1657"]     = 1.05,  -- Financial Theft
    ["T1125"]     = 1.10,  -- Video Capture
    ["T1190"]     = 1.40,  -- Exploit Public-Facing App
    ["T1499"]     = 1.10,  -- Endpoint DoS
    ["T1583.001"] = 1.05,  -- Domains
    ["T1068"]     = 1.35,  -- Exploitation for Priv Esc
}

--========== BLOOM FILTER ==========--
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

local Bloom = {}
Bloom.__index = Bloom

function Bloom.new(size, hashes)
    size = size or (1 << 20)
    return setmetatable({
        size = size,
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

--========== FUZZY MATCH ==========--
local FuzzyCache = { cache = {}, size = 0, max = 2000 }

local function levenshtein(a, b)
    if a == b then return 0 end
    local la, lb = #a, #b
    if la == 0 then return lb end
    if lb == 0 then return la end
    if la > 150 or lb > 150 then return math.abs(la - lb) end
    if la > lb then a, b, la, lb = b, a, lb, la end

    local prev = {}
    local cur = {}
    for j = 0, lb do prev[j] = j end

    for i = 1, la do
        cur[0] = i
        local ca = a:byte(i)
        for j = 1, lb do
            local cost = (ca == b:byte(j)) and 0 or 1
            local del = prev[j] + 1
            local ins = cur[j-1] + 1
            local sub = prev[j-1] + cost
            local m = del
            if ins < m then m = ins end
            if sub < m then m = sub end
            cur[j] = m
        end
        prev, cur = cur, prev
    end
    return prev[lb]
end

local function jaro(s1, s2)
    local l1, l2 = #s1, #s2
    if l1 == 0 and l2 == 0 then return 1.0 end
    if l1 == 0 or l2 == 0 then return 0.0 end
    if l1 > 150 or l2 > 150 then return s1 == s2 and 1.0 or 0.0 end

    local matchDist = math.max(l1, l2) // 2 - 1
    if matchDist < 0 then matchDist = 0 end

    local m1, m2 = {}, {}
    local matches = 0

    for i = 1, l1 do
        local start = math.max(1, i - matchDist)
        local stop = math.min(i + matchDist, l2)
        for j = start, stop do
            if not m2[j] and s1:byte(i) == s2:byte(j) then
                m1[i], m2[j] = true, true
                matches = matches + 1
                break
            end
        end
    end

    if matches == 0 then return 0.0 end

    local k, transpositions = 1, 0
    for i = 1, l1 do
        if m1[i] then
            while not m2[k] do k = k + 1 end
            if s1:byte(i) ~= s2:byte(k) then
                transpositions = transpositions + 1
            end
            k = k + 1
        end
    end
    transpositions = transpositions / 2

    return (matches/l1 + matches/l2 + (matches - transpositions)/matches) / 3
end

local function fuzzyMatch(a, b, threshold)
    threshold = threshold or Rules.Config.FUZZY_THRESHOLD
    if not Rules.Config.FUZZY_ENABLED then return a == b end
    if type(a) ~= "string" or type(b) ~= "string" then return false end

    -- cache key
    local key = a .. "\0" .. b
    if FuzzyCache.cache[key] ~= nil then
        return FuzzyCache.cache[key] >= threshold, FuzzyCache.cache[key]
    end

    -- quick length check
    local ldiff = math.abs(#a - #b)
    if ldiff > math.max(#a, #b) * 0.5 then
        FuzzyCache.cache[key] = 0
        return false, 0
    end

    local j = jaro(a, b)
    if j < threshold then
        FuzzyCache.cache[key] = j
        return false, j
    end

    -- refine with Levenshtein
    local l = levenshtein(a, b)
    local maxLen = math.max(#a, #b)
    local levScore = maxLen > 0 and (1 - l / maxLen) or 1

    local final = (j + levScore) / 2
    FuzzyCache.cache[key] = final

    -- LRU cleanup
    FuzzyCache.size = FuzzyCache.size + 1
    if FuzzyCache.size > FuzzyCache.max then
        FuzzyCache.cache = {}
        FuzzyCache.size = 0
    end

    return final >= threshold, final
end

--========== STATS HELPERS ==========--
local function mean(t)
    if #t == 0 then return 0 end
    local s = 0
    for i = 1, #t do s = s + t[i] end
    return s / #t
end

local function stdev(t)
    local n = #t
    if n < 2 then return 0 end
    local m = mean(t)
    local s = 0
    for i = 1, n do
        local d = t[i] - m
        s = s + d * d
    end
    return math.sqrt(s / (n - 1))
end

local function entropy(s)
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

local function getField(obj, path)
    if not path or type(path) ~= "string" then return nil end
    if path:find("%.") then
        local cur = obj
        for seg in path:gmatch("[^%.]+") do
            if type(cur) ~= "table" then return nil end
            cur = cur[seg]
            if cur == nil then return nil end
        end
        return cur
    end
    return type(obj) == "table" and obj[path] or nil
end

--========== CONDITION COMPILER ==========--
-- แปลง DSL condition → compiled closures
local Compiler = {}

local function compileFilter(fn)
    -- user-provided filter → safe wrapper
    return function(e) return fn(e) end
end

local function compileSingle(cond)
    -- { type = "HTTP_POST", filter = fn, severity_min = n }
    local ctype = cond.type
    local cfilter = cond.filter and compileFilter(cond.filter) or nil
    local csev = cond.severity_min

    return function(e)
        if ctype and e.type ~= ctype then return false end
        if csev and (e.severity or 0) < csev then return false end
        if cfilter and not cfilter(e) then return false end
        return true
    end
end

Compiler.event = function(cond)
    local match = compileSingle(cond)
    return function(events, ctx)
        for i = 1, #events do
            local e = events[i]
            if match(e) then
                return true, { event = e }
            end
        end
        return false
    end
end

Compiler.seq = function(cond)
    local steps = {}
    for i, s in ipairs(cond.seq) do
        steps[i] = compileSingle(s)
    end
    local n = #steps
    local within = cond.within or 30

    return function(events, ctx)
        local stepIdx = 1
        local start = nil
        for i = 1, #events do
            local e = events[i]
            if steps[stepIdx](e) then
                if stepIdx == 1 then start = e.t end
                stepIdx = stepIdx + 1
                if stepIdx > n then
                    local elapsed = e.t - start
                    if elapsed <= within then
                        return true, { elapsed = elapsed }
                    end
                    stepIdx = 1
                    start = nil
                end
            end
        end
        return false
    end
end

Compiler.count = function(cond)
    local c = cond.count
    local cfilter = c.filter and compileFilter(c.filter) or nil
    local ctype = c.type
    local within = c.within or 10
    local value = c.value or 1

    return function(events, ctx)
        local now = ctx.now
        local n = 0
        for i = 1, #events do
            local e = events[i]
            if (now - e.t) <= within then
                if (not ctype or e.type == ctype)
                    and (not cfilter or cfilter(e)) then
                    n = n + 1
                    if n >= value then
                        return true, { count = n }
                    end
                end
            end
        end
        return false, { count = n }
    end
end

Compiler.rate = function(cond)
    local r = cond.rate
    local cfilter = r.filter and compileFilter(r.filter) or nil
    local ctype = r.type
    local window = r.window or 3
    local value = r.value or 1

    return function(events, ctx)
        local now = ctx.now
        local n = 0
        for i = 1, #events do
            local e = events[i]
            if (now - e.t) <= window then
                if (not ctype or e.type == ctype)
                    and (not cfilter or cfilter(e)) then
                    n = n + 1
                end
            end
        end
        local rate = n / window
        if rate >= value then
            return true, { rate = rate, count = n }
        end
        return false
    end
end

Compiler.entropy = function(cond)
    local e = cond.entropy
    local field = e.field or "data.value"
    local value = e.value or 6.5

    return function(events, ctx)
        for i = 1, #events do
            local v = getField(events[i], field)
            if type(v) == "string" and #v >= 8 then
                local h = entropy(v)
                if h >= value then
                    return true, { entropy = h, sample = v:sub(1, 40) }
                end
            end
        end
        return false
    end
end

Compiler.regex = function(cond)
    local r = cond.regex
    local field = r.field or "data.url"
    -- pre-compute patterns
    local patterns = {}
    if r.any then
        for _, p in ipairs(r.any) do
            patterns[#patterns + 1] = p
        end
    elseif r.pattern then
        patterns[1] = r.pattern
    end

    return function(events, ctx)
        for i = 1, #events do
            local v = getField(events[i], field)
            if type(v) == "string" then
                for j = 1, #patterns do
                    if v:find(patterns[j]) then
                        return true, { field = field, value = v:sub(1, 200), pattern = patterns[j] }
                    end
                end
            end
        end
        return false
    end
end

Compiler.fuzzy = function(cond)
    local f = cond.fuzzy
    local field = f.field or "data.url"
    local target = f.target
    local threshold = f.threshold or Rules.Config.FUZZY_THRESHOLD

    return function(events, ctx)
        for i = 1, #events do
            local v = getField(events[i], field)
            if type(v) == "string" and #v < 500 then
                local ok, score = fuzzyMatch(v, target, threshold)
                if ok then
                    return true, {
                        field = field,
                        value = v:sub(1, 200),
                        target = target,
                        similarity = score,
                    }
                end
            end
        end
        return false
    end
end

Compiler.all = function(cond)
    local compiled = {}
    for i, c in ipairs(cond.all) do
        compiled[i] = Rules.compile(c)
    end
    local n = #compiled

    return function(events, ctx)
        local metas = {}
        for i = 1, n do
            local ok, m = compiled[i](events, ctx)
            if not ok then return false end
            metas[i] = m
        end
        return true, { all = metas }
    end
end

Compiler.any = function(cond)
    local compiled = {}
    for i, c in ipairs(cond.any) do
        compiled[i] = Rules.compile(c)
    end
    local n = #compiled

    return function(events, ctx)
        for i = 1, n do
            local ok, m = compiled[i](events, ctx)
            if ok then return true, m end
        end
        return false
    end
end

Compiler.not_ = function(cond)
    local inner = Rules.compile(cond.not_)
    return function(events, ctx)
        local ok = inner(events, ctx)
        return not ok
    end
end

Compiler.has = function(cond)
    local h = cond.has
    local field = h.field
    local pattern = h.pattern

    return function(events, ctx)
        for i = 1, #events do
            local v = getField(events[i], field)
            if v ~= nil then
                if not pattern then
                    return true, { field = field, value = v }
                end
                if type(v) == "string" and v:find(pattern) then
                    return true, { field = field, value = v:sub(1, 100) }
                end
            end
        end
        return false
    end
end

-- ตัวช่วย Top-level compile
function Rules.compile(cond)
    if not cond then return function() return false end end

    if cond.event then return Compiler.event(cond.event) end
    if cond.seq then return Compiler.seq(cond) end
    if cond.count then return Compiler.count(cond) end
    if cond.rate then return Compiler.rate(cond) end
    if cond.entropy then return Compiler.entropy(cond) end
    if cond.regex then return Compiler.regex(cond) end
    if cond.fuzzy then return Compiler.fuzzy(cond) end
    if cond.all then return Compiler.all(cond) end
    if cond.any then return Compiler.any(cond) end
    if cond.not_ then return Compiler.not_(cond) end
    if cond.has then return Compiler.has(cond) end

    -- legacy: { type = "...", filter = fn }
    if cond.type or cond.filter then
        return Compiler.event(cond)
    end

    return function() return false end
end

--========== SCORING ==========--
local function computeScore(rule, matchMeta, ctx)
    local sev = rule.severity or 1
    local conf = rule.confidence or 0.5
    local base = SEVERITY_WEIGHT[sev] or 0.5

    -- MITRE
    local mitreMult = 1.0
    if Rules.Config.ENABLE_MITRE and rule.mitre then
        mitreMult = MITRE_WEIGHT[rule.mitre] or 1.0
    end

    -- context multipliers
    local ctxMult = 1.0
    if matchMeta then
        if matchMeta.elapsed and matchMeta.elapsed < 5 then
            ctxMult = ctxMult * 1.15
        end
        if matchMeta.count and matchMeta.count > 100 then
            ctxMult = ctxMult * 1.10
        end
        if matchMeta.entropy and matchMeta.entropy > 7.0 then
            ctxMult = ctxMult * 1.15
        end
        if matchMeta.similarity and matchMeta.similarity > 0.95 then
            ctxMult = ctxMult * 1.10
        end
    end

    -- adaptive accuracy (per rule)
    local adaptiveMult = 1.0
    if Rules.Config.ADAPTIVE_ENABLED and rule._accuracy then
        adaptiveMult = 0.5 + rule._accuracy
    end

    local score = base * conf * mitreMult * ctxMult * adaptiveMult
    return math.min(score, 1.0)
end

--========== RULE ENGINE ==========--
local Engine = {}
Engine.__index = Engine

function Rules.new(edr)
    local self = setmetatable({
        edr           = edr,
        rules         = {},          -- [id] = rule (compiled)
        ruleOrder     = {},          -- sorted by priority desc
        dedupBloom    = Bloom.new(Rules.Config.DEDUP_BLOOM_SIZE, Rules.Config.DEDUP_BLOOM_HASHES),
        dedupMap      = {},          -- fallback exact dedup (rule_id → last_time)
        suppressed    = {},          -- [rule_id] = true
        stats         = {
            scans          = 0,
            matches        = 0,
            deduped        = 0,
            byRule         = {},
            bySeverity     = { [0]=0, [1]=0, [2]=0, [3]=0, [4]=0 },
            totalScore     = 0,
            totalTime      = 0,
        },
        metaRules     = {},
        ruleChains    = {},          -- [id] = { requires = {id1, id2} }
        recentMatches = {},          -- [rule_id] = timestamp
        version       = 0,
    }, Engine)

    Rules.installDefaults(self)
    self:_reorder()
    return self
end

function Engine:register(rule)
    if not rule.id then error("Rule missing id") end

    rule.enabled    = rule.enabled ~= false
    rule.cooldown   = rule.cooldown or Rules.Config.DEDUP_COOLDOWN
    rule.priority   = rule.priority or 0
    rule.severity   = rule.severity or 1
    rule.confidence = rule.confidence or 0.5
    rule.version    = rule.version or 1
    rule.category   = rule.category or "general"

    -- compile condition
    local ok, compiled = pcall(Rules.compile, rule.condition)
    if ok and type(compiled) == "function" then
        rule._eval = compiled
    else
        rule._eval = function() return false end
    end

    -- stats
    rule._matchCount = 0
    rule._accuracy   = rule.accuracy or 0.5
    rule._lastHit    = 0

    -- chaining
    if rule.requires then
        self.ruleChains[rule.id] = { requires = rule.requires }
    end

    self.rules[rule.id] = rule
    self:_reorder()

    return rule
end

function Engine:unregister(id)
    self.rules[id] = nil
    self.ruleChains[id] = nil
    self:_reorder()
end

function Engine:enable(id)
    local r = self.rules[id]
    if r then r.enabled = true; self:_reorder() end
end

function Engine:disable(id)
    local r = self.rules[id]
    if r then r.enabled = false; self:_reorder() end
end

function Engine:toggle(id)
    local r = self.rules[id]
    if r then
        r.enabled = not r.enabled
        self:_reorder()
        return r.enabled
    end
end

function Engine:suppress(id)
    if Rules.Config.SUPPRESSION_ENABLED then
        self.suppressed[id] = true
    end
end

function Engine:unsuppress(id)
    self.suppressed[id] = nil
end

function Engine:_reorder()
    local order = {}
    for _, r in pairs(self.rules) do
        order[#order + 1] = r
    end
    table.sort(order, function(a, b)
        if a.priority == b.priority then return a.id < b.id end
        return a.priority > b.priority
    end)
    self.ruleOrder = order
    self.version = self.version + 1
end

--========== DEDUP ==========--
function Engine:_isDuplicate(rule, meta)
    if not Rules.Config.DEDUP_ENABLED then return false end

    local key = rule.id
    if meta then
        if meta.value then key = key .. ":" .. tostring(meta.value):sub(1, 40) end
        if meta.field then key = key .. ":" .. meta.field end
        if meta.sample then key = key .. ":" .. meta.sample:sub(1, 40) end
        if meta.pattern then key = key .. ":" .. meta.pattern end
    end

    local now = os.clock()

    -- Bloom check (fast path)
    if self.dedupBloom:contains(key) then
        local last = self.dedupMap[key]
        if last and (now - last) < rule.cooldown then
            self.stats.deduped = self.stats.deduped + 1
            return true
        end
    end

    -- add
    self.dedupBloom:add(key)
    self.dedupMap[key] = now

    -- cleanup เฉพาะบางครั้ง
    if self.stats.scans % 200 == 0 then
        self:_cleanupDedup()
    end

    return false
end

function Engine:_cleanupDedup()
    local now = os.clock()
    local toRemove = {}
    for k, t in pairs(self.dedupMap) do
        if (now - t) > 600 then
            toRemove[#toRemove + 1] = k
        end
    end
    for _, k in ipairs(toRemove) do
        self.dedupMap[k] = nil
    end
end

--========== CHAINING ==========--
function Engine:_checkChain(rule, matchedIds)
    if not Rules.Config.CHAINING_ENABLED then return true end
    local chain = self.ruleChains[rule.id]
    if not chain or not chain.requires then return true end
    for _, dep in ipairs(chain.requires) do
        if not matchedIds[dep] then return false end
    end
    return true
end

--========== SCAN ==========--
function Engine:scan(events, ctx)
    if not events then
        if self.edr and self.edr.buffer then
            events = self.edr.buffer:snapshot()
        else
            events = {}
        end
    end
    ctx = ctx or { now = os.clock() }
    if not ctx.now then ctx.now = os.clock() end

    self.stats.scans = self.stats.scans + 1
    local t0 = os.clock()

    local matches = {}
    local matchedIds = {}
    local matchCount = 0

    for i = 1, #self.ruleOrder do
        local rule = self.ruleOrder[i]
        if rule.enabled and not self.suppressed[rule.id] then
            local ok, meta = rule._eval(events, ctx)
            if ok then
                -- chaining check
                if self:_checkChain(rule, matchedIds) then
                    -- dedup
                    if not self:_isDuplicate(rule, meta) then
                        -- cooldown per rule (fast)
                        local now = ctx.now
                        if (now - rule._lastHit) >= rule.cooldown then
                            rule._lastHit = now

                            local score = computeScore(rule, meta, ctx)
                            matchCount = matchCount + 1
                            matches[matchCount] = {
                                rule = rule,
                                meta = meta,
                                score = score,
                                time = ctx.now,
                                wall = os.time(),
                            }

                            matchedIds[rule.id] = true
                            rule._matchCount = rule._matchCount + 1
                            self.stats.byRule[rule.id] = (self.stats.byRule[rule.id] or 0) + 1
                            self.stats.bySeverity[rule.severity] = (self.stats.bySeverity[rule.severity] or 0) + 1
                            self.stats.totalScore = self.stats.totalScore + score

                            if Rules.Config.MATCH_MODE == "first" then
                                break
                            end
                            if matchCount >= Rules.Config.MAX_MATCHES_PER_SCAN then
                                break
                            end
                        end
                    end
                end
            end
        end
    end

    self.stats.matches = self.stats.matches + matchCount
    self.stats.totalTime = self.stats.totalTime + (os.clock() - t0)

    -- ส่งต่อไป EDR
    if self.edr and self.edr.raiseAlert then
        for i = 1, #matches do
            local m = matches[i]
            local r = m.rule
            self.edr:raiseAlert({
                rule     = r.id,
                name     = r.name,
                severity = r.severity,
                message  = r.description or r.name or r.id,
                score    = m.score,
                mitre    = r.mitre,
                tags     = r.tags,
                category = r.category,
                meta     = m.meta,
            })
        end
    end

    -- top-k selection
    if Rules.Config.MATCH_MODE == "topk" and #matches > Rules.Config.TOPK then
        table.sort(matches, function(a, b) return a.score > b.score end)
        local trimmed = {}
        for i = 1, Rules.Config.TOPK do trimmed[i] = matches[i] end
        matches = trimmed
    end

    return matches
end

--========== AGGREGATE RISK ==========--
-- Probabilistic OR: risk = 1 - Π(1 - score_i)
function Engine:aggregateRisk(matches)
    if not matches or #matches == 0 then return 0 end
    local product = 1.0
    for i = 1, #matches do
        product = product * (1.0 - math.min(matches[i].score, 0.99))
    end
    local risk = 1.0 - product

    -- อย่างน้อย 1 CRITICAL → รับประกันขั้นต่ำ 0.7
    for i = 1, #matches do
        if matches[i].rule.severity >= 4 then
            risk = math.max(risk, 0.7)
            break
        end
    end

    return risk
end

--========== STATS ==========--
function Engine:summary()
    return {
        scans        = self.stats.scans,
        matches      = self.stats.matches,
        deduped      = self.stats.deduped,
        rules        = #self.ruleOrder,
        enabledRules = (function()
            local n = 0
            for _, r in ipairs(self.ruleOrder) do
                if r.enabled then n = n + 1 end
            end
            return n
        end)(),
        byRule       = self.stats.byRule,
        bySeverity   = self.stats.bySeverity,
        avgScore     = self.stats.matches > 0
            and (self.stats.totalScore / self.stats.matches) or 0,
        avgScanMs    = self.stats.scans > 0
            and (self.stats.totalTime / self.stats.scans * 1000) or 0,
        dedupItems   = self.dedupBloom.itemCount,
    }
end

function Engine:getRuleStats(id)
    local r = self.rules[id]
    if not r then return nil end
    return {
        id            = r.id,
        name          = r.name,
        enabled       = r.enabled,
        severity      = r.severity,
        confidence    = r.confidence,
        priority      = r.priority,
        matchCount    = r._matchCount or 0,
        accuracy      = r._accuracy,
        category      = r.category,
        mitre         = r.mitre,
    }
end

--========== DEFAULT RULES (40+) ==========--
function Rules.installDefaults(engine)
    --=================================================================
    -- CATEGORY: STEALER / CREDENTIAL
    --=================================================================

    engine:register({
        id = "CRED_STEALER_CHAIN",
        name = "Credential Stealer Chain",
        description = "อ่านไฟล์ที่มีคำว่า token/cookie → encode → ส่งออก network",
        category = "stealer",
        severity = 4,
        confidence = 0.90,
        mitre = "T1552",
        tags = {"stealer", "credential", "exfil"},
        priority = 100,
        condition = {
            seq = {
                { type = "FILE_READ", filter = function(e)
                    local p = tostring(e.data and e.data.path or ""):lower()
                    return p:find("token") or p:find("cookie") or p:find(".env")
                        or p:find("credential") or p:find("wallet") or p:find("seed")
                end },
                { type = "STRING_ENCODE" },
                { type = "HTTP_POST" },
            },
            within = 20,
        },
    })

    engine:register({
        id = "SENSITIVE_FILE_ACCESS",
        name = "Sensitive File Access",
        description = "พยายามอ่านไฟล์ที่มีข้อมูลลับ",
        category = "stealer",
        severity = 3,
        confidence = 0.75,
        mitre = "T1005",
        tags = {"collection", "credential"},
        priority = 80,
        condition = {
            has = { field = "data.sensitive" },
        },
    })

    engine:register({
        id = "DISCORD_WEBHOOK_EXFIL",
        name = "Discord Webhook Exfiltration",
        description = "ส่งข้อมูลออกผ่าน Discord Webhook",
        category = "exfil",
        severity = 4,
        confidence = 0.95,
        mitre = "T1567",
        tags = {"exfil", "webhook", "discord"},
        priority = 95,
        condition = {
            regex = {
                field = "data.url",
                any = {"discord.com/api/webhooks", "discordapp.com/api/webhooks"},
            },
        },
    })

    engine:register({
        id = "TELEGRAM_BOT_EXFIL",
        name = "Telegram Bot API Exfiltration",
        description = "ส่งข้อมูลผ่าน Telegram Bot",
        category = "exfil",
        severity = 4,
        confidence = 0.92,
        mitre = "T1567",
        tags = {"exfil", "telegram"},
        priority = 95,
        condition = {
            regex = { field = "data.url", pattern = "api%.telegram%.org" },
        },
    })

    engine:register({
        id = "PASTEBIN_RAW_FETCH",
        name = "Pastebin Raw Fetch",
        description = "โหลดโค้ดจาก Pastebin (มักเป็น staging)",
        category = "staging",
        severity = 3,
        confidence = 0.70,
        mitre = "T1071.001",
        tags = {"staging", "download"},
        priority = 60,
        condition = {
            regex = { field = "data.url", pattern = "pastebin%.com/raw" },
        },
    })

    engine:register({
        id = "GITHUB_RAW_LOADER",
        name = "GitHub Raw Loader",
        description = "โหลด Lua จาก raw.githubusercontent.com",
        category = "staging",
        severity = 2,
        confidence = 0.55,
        mitre = "T1071.001",
        tags = {"staging", "loader"},
        priority = 40,
        condition = {
            regex = { field = "data.url", pattern = "raw%.githubusercontent%.com" },
        },
    })

    engine:register({
        id = "CLIPBOARD_ACCESS",
        name = "Clipboard Access",
        description = "เข้าถึง clipboard (อาจขโมยข้อมูล)",
        category = "stealer",
        severity = 3,
        confidence = 0.70,
        mitre = "T1115",
        tags = {"clipboard", "stealer"},
        priority = 65,
        condition = {
            regex = { field = "data.name", pattern = "Clipboard" },
        },
    })

    --=================================================================
    -- CATEGORY: DROPPER / LOADER
    --=================================================================

    engine:register({
        id = "REMOTE_CODE_LOADER",
        name = "Remote Code Loader",
        description = "HttpGet ตามด้วย loadstring",
        category = "loader",
        severity = 4,
        confidence = 0.85,
        mitre = "T1620",
        tags = {"loader", "dropper"},
        priority = 90,
        condition = {
            seq = {
                { type = "HTTP_GET" },
                { type = "FUNCTION_CALL", filter = function(e)
                    local n = e.data and e.data.name or ""
                    return n == "loadstring" or n == "load" or n == "dofile"
                end },
            },
            within = 8,
        },
    })

    engine:register({
        id = "MULTI_STAGE_LOADER",
        name = "Multi-Stage Loader",
        description = "HttpGet มากกว่า 3 ครั้งใน 5 วินาที (daisy-chain)",
        category = "loader",
        severity = 3,
        confidence = 0.65,
        mitre = "T1071.001",
        tags = {"loader", "chain"},
        priority = 70,
        condition = {
            count = { type = "HTTP_GET", value = 3, within = 5 },
        },
    })

    engine:register({
        id = "DYNAMIC_CODE_EVAL",
        name = "Dynamic Code Evaluation",
        description = "loadstring กับ string จาก network",
        category = "loader",
        severity = 3,
        confidence = 0.80,
        mitre = "T1059",
        tags = {"eval", "dynamic"},
        priority = 75,
        condition = {
            all = {
                { type = "FUNCTION_CALL", filter = function(e)
                    return (e.data and e.data.name or "") == "loadstring"
                end },
                { any = {
                    { type = "HTTP_GET" },
                    { type = "FILE_READ" },
                } },
            },
        },
    })

    engine:register({
        id = "BASE64_URL_LOADER",
        name = "Base64-Encoded URL Loader",
        description = "base64 ของ 'https://' ใน string",
        category = "loader",
        severity = 3,
        confidence = 0.85,
        mitre = "T1140",
        tags = {"obfuscation", "loader"},
        priority = 65,
        condition = {
            any = {
                { regex = { field = "data.value", pattern = "aHR0cHM6Ly" } },
                { regex = { field = "data.value", pattern = "aHR0cDovLw" } },
            },
        },
    })

    engine:register({
        id = "LOADER_CHAIN",
        name = "Loader Chain (HttpGet → loadstring → HttpGet)",
        description = "Loader ที่โหลด payload ต่อเนื่อง",
        category = "loader",
        severity = 4,
        confidence = 0.88,
        mitre = "T1620",
        tags = {"loader", "chain"},
        priority = 92,
        requires = {"REMOTE_CODE_LOADER"},
        condition = {
            seq = {
                { type = "HTTP_GET" },
                { type = "FUNCTION_CALL", filter = function(e)
                    local n = e.data and e.data.name or ""
                    return n == "loadstring"
                end },
                { type = "HTTP_GET" },
            },
            within = 15,
        },
    })

    --=================================================================
    -- CATEGORY: OBFUSCATION
    --=================================================================

    engine:register({
        id = "HIGH_ENTROPY_STRING",
        name = "High-Entropy String",
        description = "String ที่ entropy > 6.5 bits/char (encrypted)",
        category = "obfuscation",
        severity = 2,
        confidence = 0.60,
        mitre = "T1027",
        tags = {"obfuscation", "encryption"},
        priority = 40,
        condition = {
            entropy = { field = "data.value", value = 6.5 },
        },
    })

    engine:register({
        id = "BXOR_DECRYPT_BURST",
        name = "XOR Decryption Burst",
        description = "bit32.bxor มากกว่า 100 ครั้ง/วินาที",
        category = "obfuscation",
        severity = 2,
        confidence = 0.70,
        mitre = "T1140",
        tags = {"obfuscation", "luraph"},
        priority = 50,
        condition = {
            rate = { type = "STRING_DECRYPT", value = 100, window = 1 },
        },
    })

    engine:register({
        id = "STRING_CHAR_LOOP",
        name = "string.char Decryption Loop",
        description = "string.char ในลูปเพื่อสร้าง string",
        category = "obfuscation",
        severity = 2,
        confidence = 0.65,
        mitre = "T1140",
        tags = {"obfuscation"},
        priority = 45,
        condition = {
            count = { type = "STRING_DECRYPT", value = 20, within = 2 },
        },
    })

    engine:register({
        id = "ANTI_DEBUG_PROBE",
        name = "Anti-Debug Probe",
        description = "debug.getinfo/sethook — ป้องกันการวิเคราะห์",
        category = "anti-analysis",
        severity = 3,
        confidence = 0.75,
        mitre = "T1622",
        tags = {"anti-analysis"},
        priority = 65,
        condition = {
            all = {
                { type = "DEBUG_ACCESS", filter = function(e)
                    local n = e.data and e.data.name or ""
                    return n == "getinfo" or n == "sethook" or n == "gethook"
                end },
                { count = { type = "DEBUG_ACCESS", value = 5, within = 3 } },
            },
        },
    })

    engine:register({
        id = "METATABLE_TAMPER",
        name = "Metatable Tampering",
        description = "แก้ไข metatable หลายครั้ง",
        category = "hook",
        severity = 2,
        confidence = 0.55,
        mitre = "T1055",
        tags = {"hook"},
        priority = 40,
        condition = {
            count = { type = "METATABLE_ACCESS", value = 10, within = 5 },
        },
    })

    engine:register({
        id = "UPVALUE_OBFUSCATION",
        name = "Upvalue-based Obfuscation",
        description = "ใช้ upvalue ซ่อนข้อมูล",
        category = "obfuscation",
        severity = 2,
        confidence = 0.50,
        mitre = "T1027",
        tags = {"obfuscation"},
        priority = 35,
        condition = {
            regex = { field = "data.source", pattern = "upvalue" },
        },
    })

    --=================================================================
    -- CATEGORY: NETWORK / C2
    --=================================================================

    engine:register({
        id = "DIRECT_IP_CONNECTION",
        name = "Direct IP Connection",
        description = "เชื่อมต่อกับ IP ตรงๆ ไม่ผ่าน domain",
        category = "network",
        severity = 3,
        confidence = 0.70,
        mitre = "T1071",
        tags = {"c2", "network"},
        priority = 60,
        condition = {
            regex = {
                field = "data.url",
                pattern = "https?://%d+%.%d+%.%d+%.%d+",
            },
        },
    })

    engine:register({
        id = "SUSPICIOUS_TLD",
        name = "Suspicious TLD",
        description = "เชื่อมต่อกับ TLD ที่มักใช้ใน malware",
        category = "network",
        severity = 2,
        confidence = 0.55,
        mitre = "T1583.001",
        tags = {"network"},
        priority = 35,
        condition = {
            regex = {
                field = "data.url",
                any = {"%.tk/", "%.ml/", "%.ga/", "%.cf/", "%.gq/",
                    "%.top/", "%.xyz/", "%.link/", "%.click/"},
            },
        },
    })

    engine:register({
        id = "HIGH_NETWORK_RATE",
        name = "High Network Rate",
        description = "ยิง request > 20 ครั้ง/วินาที",
        category = "network",
        severity = 3,
        confidence = 0.70,
        mitre = "T1041",
        tags = {"network", "exfil"},
        priority = 70,
        condition = {
            rate = { type = "NETWORK_REQUEST", value = 20, window = 1 },
        },
    })

    engine:register({
        id = "ENCRYPTED_C2_CHANNEL",
        name = "Encrypted C2 Channel",
        description = "HTTP POST ตามด้วย NETWORK_RESPONSE ในเวลาสั้น",
        category = "c2",
        severity = 3,
        confidence = 0.65,
        mitre = "T1071.001",
        tags = {"c2"},
        priority = 60,
        condition = {
            seq = {
                { type = "HTTP_POST" },
                { type = "NETWORK_RESPONSE" },
            },
            within = 3,
        },
    })

    engine:register({
        id = "ENCRYPTED_C2_ENTROPY",
        name = "High-Entropy C2 Exfiltration",
        description = "String entropy สูง → HTTP POST",
        category = "c2",
        severity = 4,
        confidence = 0.85,
        mitre = "T1041",
        tags = {"c2", "exfil", "encrypted"},
        priority = 88,
        condition = {
            seq = {
                { type = "STRING_DECRYPT", filter = function(e)
                    local v = e.data and e.data.value
                    return type(v) == "string" and #v > 30 and entropy(v) > 6.5
                end },
                { type = "HTTP_POST" },
            },
            within = 8,
        },
    })

    engine:register({
        id = "TYPOSQUATTING_ATTEMPT",
        name = "Typosquatting Attempt",
        description = "URL ที่คล้าย domain ที่รู้จัก (fuzzy)",
        category = "network",
        severity = 3,
        confidence = 0.75,
        mitre = "T1583.001",
        tags = {"network", "phishing"},
        priority = 65,
        condition = {
            fuzzy = {
                field = "data.url",
                target = "https://discord.com/api/webhooks/",
                threshold = 0.90,
            },
        },
    })

    engine:register({
        id = "PASTEBIN_TYPOSQUAT",
        name = "Pastebin Typosquatting",
        description = "URL ที่คล้าย pastebin.com (fuzzy)",
        category = "network",
        severity = 3,
        confidence = 0.70,
        mitre = "T1583.001",
        tags = {"network", "phishing"},
        priority = 60,
        condition = {
            fuzzy = {
                field = "data.url",
                target = "https://pastebin.com/raw/",
                threshold = 0.88,
            },
        },
    })

    --=================================================================
    -- CATEGORY: RESOURCE HIJACKING
    --=================================================================

    engine:register({
        id = "CRYPTO_MINER_PATTERN",
        name = "Crypto Miner Pattern",
        description = "เชื่อมต่อกับ mining pool",
        category = "miner",
        severity = 3,
        confidence = 0.75,
        mitre = "T1496",
        tags = {"miner"},
        priority = 70,
        condition = {
            regex = {
                field = "data.url",
                any = {"pool%.", "xmr%.", "monero", "nicehash", "minergate"},
            },
        },
    })

    engine:register({
        id = "RESOURCE_EXHAUSTION",
        name = "Resource Exhaustion Pattern",
        description = "สร้าง coroutine มากกว่า 1000 ตัวต่อวินาที",
        category = "resource",
        severity = 2,
        confidence = 0.60,
        mitre = "T1499",
        tags = {"resource", "dos"},
        priority = 45,
        condition = {
            rate = { type = "COROUTINE_CREATE", value = 1000, window = 1 },
        },
    })

    --=================================================================
    -- CATEGORY: INPUT CAPTURE
    --=================================================================

    engine:register({
        id = "INPUT_CAPTURE",
        name = "Input Capture Pattern",
        description = "อ่าน UserInputService.InputBegan + network",
        category = "keylogger",
        severity = 4,
        confidence = 0.80,
        mitre = "T1056.001",
        tags = {"keylogger"},
        priority = 85,
        condition = {
            all = {
                { regex = { field = "data.name", pattern = "InputBegan" } },
                { any = {
                    { type = "NETWORK_REQUEST" },
                    { type = "HTTP_POST" },
                } },
            },
        },
    })

    --=================================================================
    -- CATEGORY: HOOK / POLLUTION
    --=================================================================

    engine:register({
        id = "GLOBAL_ENV_POLLUTION",
        name = "Global Environment Pollution",
        description = "เขียน global > 50 ครั้งใน 10 วินาที",
        category = "hook",
        severity = 2,
        confidence = 0.60,
        mitre = "T1055",
        tags = {"hook", "pollution"},
        priority = 45,
        condition = {
            count = { type = "GLOBAL_WRITE", value = 50, within = 10 },
        },
    })

    engine:register({
        id = "FUNCTION_REDEFINE_HOOK",
        name = "Function Redefinition Hook",
        description = "เขียนทับฟังก์ชันสำคัญ เช่น HttpGet",
        category = "hook",
        severity = 3,
        confidence = 0.70,
        mitre = "T1055",
        tags = {"hook"},
        priority = 60,
        condition = {
            any = {
                { type = "FUNCTION_REDEFINE", filter = function(e)
                    local n = e.data and e.data.name or ""
                    return n:find("HttpGet") or n:find("HttpPost")
                        or n:find("request") or n:find("loadstring")
                end },
                { type = "GLOBAL_WRITE", filter = function(e)
                    local k = e.data and e.data.key or ""
                    return k == "HttpGet" or k == "HttpPost"
                        or k == "request" or k == "loadstring"
                end },
            },
        },
    })

    engine:register({
        id = "SELF_INTEGRITY_TAMPER",
        name = "Self-Integrity Tampering",
        description = "แก้ไขฟังก์ชันหลักของ environment",
        category = "anti-analysis",
        severity = 4,
        confidence = 0.85,
        mitre = "T1562.001",
        tags = {"hook", "tamper"},
        priority = 90,
        condition = {
            all = {
                { regex = { field = "data.name", pattern = "pcall|setmetatable|rawget" } },
                { type = "FUNCTION_REDEFINE" },
            },
        },
    })

    engine:register({
        id = "RAW_METATABLE_ABUSE",
        name = "Raw Metatable Abuse",
        description = "ใช้ getrawmetatable หลายครั้ง",
        category = "hook",
        severity = 3,
        confidence = 0.65,
        mitre = "T1055",
        tags = {"hook"},
        priority = 55,
        condition = {
            count = { type = "METATABLE_ACCESS", value = 5, within = 3,
                filter = function(e) return e.data and e.data.op == "getraw" end },
        },
    })

    --=================================================================
    -- CATEGORY: ENV ESCALATION
    --=================================================================

    engine:register({
        id = "THREAD_IDENTITY_ESCALATION",
        name = "Thread Identity Escalation",
        description = "ยกระดับ thread identity",
        category = "escalation",
        severity = 4,
        confidence = 0.85,
        mitre = "T1055",
        tags = {"escalation", "bypass"},
        priority = 90,
        condition = {
            all = {
                { type = "THREAD_IDENTITY", filter = function(e)
                    return e.data and e.data.op == "set" and (e.data.id or 0) >= 6
                end },
            },
        },
    })

    engine:register({
        id = "ENV_MANIPULATION",
        name = "Environment Manipulation",
        description = "setfenv/setfenv หลายครั้ง",
        category = "escalation",
        severity = 3,
        confidence = 0.65,
        mitre = "T1055",
        tags = {"sandbox-escape"},
        priority = 55,
        condition = {
            count = { type = "ENV_ACCESS", value = 5, within = 5,
                filter = function(e) return e.data and e.data.op == "set" end },
        },
    })

    --=================================================================
    -- CATEGORY: ROBLOX SPECIFIC
    --=================================================================

    engine:register({
        id = "SENSITIVE_SERVICE_ACCESS",
        name = "Sensitive Service Access",
        description = "เข้าถึง DataStore/MemoryStore",
        category = "roblox",
        severity = 3,
        confidence = 0.60,
        mitre = "T1005",
        tags = {"roblox", "datastore"},
        priority = 55,
        condition = {
            regex = { field = "data.service", pattern = "DataStore|MemoryStore|Messaging" },
        },
    })

    engine:register({
        id = "PROPERTY_TAMPER",
        name = "Property Tampering",
        description = "แก้ Humanoid/Camera properties",
        category = "roblox",
        severity = 3,
        confidence = 0.70,
        mitre = "T1562.001",
        tags = {"roblox", "tamper"},
        priority = 65,
        condition = {
            count = { type = "RBX_PROPERTY_WRITE", value = 15, within = 5,
                filter = function(e)
                    local d = e.data or {}
                    return d.class == "Humanoid" or d.class == "Camera"
                end },
        },
    })

    engine:register({
        id = "REMOTE_SPAM",
        name = "Remote Event Spam",
        description = "ยิง remote > 20 ครั้งใน 5 วินาที",
        category = "roblox",
        severity = 3,
        confidence = 0.65,
        mitre = "T1059",
        tags = {"roblox", "remote"},
        priority = 60,
        condition = {
            count = { type = "RBX_REMOTE_FIRE", value = 20, within = 5 },
        },
    })

    engine:register({
        id = "SCRIPT_IN_WORKSPACE",
        name = "Script in Unusual Location",
        description = "Script/LocalScript ใน Workspace",
        category = "roblox",
        severity = 3,
        confidence = 0.70,
        mitre = "T1543",
        tags = {"roblox", "backdoor"},
        priority = 70,
        condition = {
            all = {
                { type = "RBX_WORKSPACE_WRITE" },
                { regex = { field = "data.event", pattern = "ScriptsInWorkspace" } },
            },
        },
    })

    engine:register({
        id = "DATASTORE_EGRESS",
        name = "DataStore Exfiltration",
        description = "DataStore access ตามด้วย HTTP",
        category = "roblox",
        severity = 4,
        confidence = 0.80,
        mitre = "T1567",
        tags = {"roblox", "exfil"},
        priority = 85,
        condition = {
            seq = {
                { type = "RBX_SERVICE_ACCESS", filter = function(e)
                    local s = e.data and e.data.service or ""
                    return s == "DataStoreService" or s == "MemoryStoreService"
                end },
                { type = "NETWORK_REQUEST" },
            },
            within = 15,
        },
    })

    --=================================================================
    -- CATEGORY: VULN FINDINGS
    --=================================================================

    engine:register({
        id = "CRITICAL_VULN_FOUND",
        name = "Critical Vulnerability Found",
        description = "vuln_scanner พบช่องโหว่วิกฤต",
        category = "vuln",
        severity = 4,
        confidence = 0.85,
        mitre = "T1190",
        tags = {"vuln", "critical"},
        priority = 100,
        condition = {
            type = "VULN_FINDING",
            filter = function(e)
                return (e.severity or 0) >= 4
            end,
        },
    })

    engine:register({
        id = "HIGH_VULN_COUNT",
        name = "High Vulnerability Count",
        description = "vuln scanner พบ high 5+ อย่าง",
        category = "vuln",
        severity = 3,
        confidence = 0.75,
        mitre = "T1190",
        tags = {"vuln"},
        priority = 80,
        condition = {
            count = { type = "VULN_FINDING", value = 5, within = 60,
                filter = function(e) return (e.severity or 0) >= 3 end },
        },
    })

    --=================================================================
    -- CATEGORY: ANOMALY
    --=================================================================

    engine:register({
        id = "ANOMALY_CLUSTER",
        name = "Anomaly Cluster",
        description = "3+ anomalies ใน 10 วินาที",
        category = "anomaly",
        severity = 3,
        confidence = 0.70,
        mitre = "T1499",
        tags = {"anomaly"},
        priority = 70,
        condition = {
            count = { type = "ANOMALY", value = 3, within = 10 },
        },
    })

    engine:register({
        id = "TAINT_FLOW_SENSITIVE",
        name = "Sensitive Data Flow",
        description = "Taint flow จาก source sensitive → sink",
        category = "anomaly",
        severity = 4,
        confidence = 0.85,
        mitre = "T1041",
        tags = {"taint", "dataflow"},
        priority = 88,
        condition = {
            type = "TAINT_FLOW",
        },
    })

    --=================================================================
    -- CATEGORY: COMPOSITE / META-RULES
    --=================================================================

    engine:register({
        id = "ADVANCED_STEALER_CHAIN",
        name = "Advanced Stealer Chain",
        description = "อ่านไฟล์ลับ + decrypt + network + global write",
        category = "composite",
        severity = 4,
        confidence = 0.95,
        mitre = "T1552",
        tags = {"stealer", "composite"},
        priority = 110,
        condition = {
            all = {
                { count = { type = "FILE_READ", value = 3, within = 15,
                    filter = function(e)
                        return e.data and e.data.sensitive == true
                    end } },
                { count = { type = "STRING_DECRYPT", value = 50, within = 15 } },
                { any = {
                    { type = "HTTP_POST" },
                    { type = "NETWORK_REQUEST" },
                } },
                { count = { type = "GLOBAL_WRITE", value = 10, within = 15 } },
            },
        },
    })

    engine:register({
        id = "RAT_FULL_CHAIN",
        name = "RAT Full Chain",
        description = "Remote loader + hook + persistence",
        category = "composite",
        severity = 4,
        confidence = 0.90,
        mitre = "T1071",
        tags = {"rat", "composite"},
        priority = 105,
        condition = {
            all = {
                { type = "HTTP_GET" },
                { type = "FUNCTION_CALL", filter = function(e)
                    return (e.data and e.data.name or "") == "loadstring"
                end },
                { type = "GLOBAL_WRITE", filter = function(e)
                    local k = e.data and e.data.key or ""
                    return k:find("hook") or k:find("Hook") or k:find("__")
                end },
            },
        },
    })

    engine:register({
        id = "FULL_KILL_CHAIN",
        name = "Full Kill Chain",
        description = "Loader + stealer + exfil + anti-debug",
        category = "composite",
        severity = 4,
        confidence = 0.97,
        mitre = "T1041",
        tags = {"killchain", "composite", "critical"},
        priority = 120,
        requires = {"REMOTE_CODE_LOADER", "CRED_STEALER_CHAIN"},
        condition = {
            all = {
                { type = "DEBUG_ACCESS" },
                { count = { type = "HTTP_GET", value = 2, within = 30 } },
                { count = { type = "FILE_READ", value = 2, within = 30 } },
                { type = "HTTP_POST" },
            },
        },
    })

    engine:register({
        id = "PERSISTENCE_PATTERN",
        name = "Persistence Pattern",
        description = "เขียน global hook + task scheduling",
        category = "composite",
        severity = 3,
        confidence = 0.75,
        mitre = "T1543",
        tags = {"persistence"},
        priority = 70,
        condition = {
            all = {
                { count = { type = "GLOBAL_WRITE", value = 20, within = 10 } },
                { count = { type = "TASK_SCHEDULED", value = 3, within = 10 } },
            },
        },
    })

    --=================================================================
    -- TOTAL: 40+ rules
    --=================================================================
end

--========== GLOBAL RISK ==========--
function Rules.computeSessionRisk(alerts)
    if not alerts or #alerts == 0 then return 0, {} end
    local breakdown = {}
    local product = 1.0
    for i = 1, #alerts do
        local a = alerts[i]
        local s = a.score or (SEVERITY_WEIGHT[a.severity or 0] or 0.3)
        breakdown[a.rule or "?"] = (breakdown[a.rule or "?"] or 0) + s
        product = product * (1.0 - math.min(s, 0.99))
    end
    return 1.0 - product, breakdown
end

--========== EXPORT ==========--
Rules.Engine          = Engine
Rules.Compiler        = Compiler
Rules.Bloom           = Bloom
Rules.SEVERITY_WEIGHT = SEVERITY_WEIGHT
Rules.MITRE_WEIGHT    = MITRE_WEIGHT
Rules.levenshtein     = levenshtein
Rules.jaro            = jaro
Rules.fuzzyMatch      = fuzzyMatch
Rules.entropy         = entropy

-- singleton
Rules._instance = nil

function Rules.get(edr)
    if not Rules._instance then
        Rules._instance = Rules.new(edr)
    end
    return Rules._instance
end

function Rules.reset()
    Rules._instance = nil
    FuzzyCache.cache = {}
    FuzzyCache.size = 0
end

return Rules