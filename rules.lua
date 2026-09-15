--[[
    ============================================================
    EDR Rules Engine v3.0 — Compiled + Adaptive + Version-Aware
    ============================================================
    NEW in v3.0:
    - MODULE_VERSION = "3.0.0"
    - setPerformanceMode(mode) — light/balanced/paranoid
    - Rules.testRule(id, events) — unit test hook
    - Rules.validateRule(rule) — pre-register validation
    - Buffer caps (MAX_MATCHES_PER_SCAN, TOPK)
    - Self-integrity check (rule definitions)
    - Structured JSON logging
    - Hot-reload API
    - Consistent pcall
    - Stats aggregation

    ใช้ร่วมกับ:
    - edr_core.lua v2.0 : events, alerts, timeseries
    - hooks.lua v3.0    : event source
    - report.lua v3.0   : consume alerts
    - ui.lua v3.0       : display alerts + rule stats
    - main.lua v4.0     : lifecycle + perf mode
    ============================================================
]]

local Rules = {}

local function clock()
    if type(time) == "function" then return time() end
    return os.clock()
end

--========== VERSION ==========--
Rules._VERSION = "3.0.0"
Rules.MODULE_VERSION = "3.0.0"
Rules.VERSION = "3.0.0"

--========== CONFIG ==========--
Rules.Config = {
    MATCH_MODE              = "all",
    MAX_MATCHES_PER_SCAN    = 100,
    TOPK                    = 20,
    DEDUP_ENABLED           = true,
    DEDUP_COOLDOWN          = 60,
    CHAIN_WINDOW            = 300,
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
    LOG_STRUCTURED          = false,

    -- v3.0
    SELF_INTEGRITY          = true,
    INTEGRITY_INTERVAL      = 60,
    MAX_RULES               = 200,
    MAX_DEDUP_ENTRIES       = 5000,
    PERFORMANCE_MODE        = "balanced",
}

--========== MODE PROFILES (v3.0) ==========--
local MODE_PROFILES = {
    light = {
        MAX_MATCHES_PER_SCAN    = 30,
        TOPK                    = 10,
        DEDUP_COOLDOWN          = 120,
        FUZZY_ENABLED           = false,
        CHAINING_ENABLED        = true,
        META_RULES_ENABLED      = false,
        ADAPTIVE_ENABLED        = true,
        DEDUP_BLOOM_SIZE        = 1 << 18,
    },
    balanced = {
        MAX_MATCHES_PER_SCAN    = 100,
        TOPK                    = 20,
        DEDUP_COOLDOWN          = 60,
        FUZZY_ENABLED           = true,
        CHAINING_ENABLED        = true,
        META_RULES_ENABLED      = true,
        ADAPTIVE_ENABLED        = true,
        DEDUP_BLOOM_SIZE        = 1 << 20,
    },
    paranoid = {
        MAX_MATCHES_PER_SCAN    = 200,
        TOPK                    = 50,
        DEDUP_COOLDOWN          = 30,
        FUZZY_ENABLED           = true,
        CHAINING_ENABLED        = true,
        META_RULES_ENABLED      = true,
        ADAPTIVE_ENABLED        = true,
        DEDUP_BLOOM_SIZE        = 1 << 22,
    },
}

--========== SEVERITY WEIGHTS ==========--
local SEVERITY_WEIGHT = { [0]=0.05, [1]=0.25, [2]=0.55, [3]=0.80, [4]=1.00 }

--========== MITRE WEIGHTS ==========--
local MITRE_WEIGHT = {
    ["T1059"]     = 1.15, ["T1059.007"] = 1.10,
    ["T1056"]     = 1.20, ["T1056.001"] = 1.20,
    ["T1005"]     = 1.15, ["T1071"]     = 1.10,
    ["T1071.001"] = 1.10, ["T1041"]     = 1.30,
    ["T1567"]     = 1.25, ["T1496"]     = 1.15,
    ["T1055"]     = 1.40, ["T1620"]     = 1.20,
    ["T1027"]     = 0.85, ["T1140"]     = 0.90,
    ["T1552"]     = 1.30, ["T1555"]     = 1.35,
    ["T1115"]     = 1.25, ["T1113"]     = 1.20,
    ["T1543"]     = 1.15, ["T1562.001"] = 1.35,
    ["T1622"]     = 1.20, ["T1078"]     = 1.20,
    ["T1657"]     = 1.05, ["T1125"]     = 1.10,
    ["T1190"]     = 1.40, ["T1499"]     = 1.10,
    ["T1583.001"] = 1.05, ["T1068"]     = 1.35,
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
        local lo = h % 65536
        local hi = math.floor(h / 65536)
        h = (lo * 16777619
            + ((hi * 16777619) % 65536) * 65536) % 0x100000000
    end
    return h
end

local HASH_SEEDS = { 2166136261, 2166136261 + 101, 2166136261 + 202, 2166136261 + 303 }
local function hashN(str, n) return fnv1a(str, HASH_SEEDS[n]) end

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

local function log(level, module, event, data)
    if level > Rules.Config.LOG_LEVEL then return end
    if Rules.Config.LOG_STRUCTURED then
        local entry = {
            ts = os.time(), level = level,
            module = "rules." .. tostring(module),
            event = event,
        }
        if data then entry.data = data end
        print("[EDR] " .. jsonEncode(entry))
    else
        print(string.format("[RULES][%s] %s", tostring(module), tostring(event)))
    end
end

--========== MODE SETTER (v3.0) ==========--
function Rules.setPerformanceMode(mode)
    if not mode or not MODE_PROFILES[mode] then
        return false, "unknown mode: " .. tostring(mode)
    end
    local profile = MODE_PROFILES[mode]
    for k, v in pairs(profile) do
        Rules.Config[k] = v
    end
    Rules.Config.PERFORMANCE_MODE = mode
    log(1, "perf", "mode applied: " .. mode, profile)
    return true
end

function Rules.getPerformanceMode()
    return Rules.Config.PERFORMANCE_MODE
end

--========== BLOOM FILTER ==========--
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

function Bloom:reset()
    self.bits = {}
    self.itemCount = 0
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
    local prev, cur = {}, {}
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
    local k, t = 1, 0
    for i = 1, l1 do
        if m1[i] then
            while not m2[k] do k = k + 1 end
            if s1:byte(i) ~= s2:byte(k) then t = t + 1 end
            k = k + 1
        end
    end
    t = t / 2
    return (matches/l1 + matches/l2 + (matches - t)/matches) / 3
end

local function fuzzyMatch(a, b, threshold)
    if not Rules.Config.FUZZY_ENABLED then return a == b end
    threshold = threshold or Rules.Config.FUZZY_THRESHOLD
    if type(a) ~= "string" or type(b) ~= "string" then return false end
    local key = a .. "\0" .. b
    if FuzzyCache.cache[key] ~= nil then
        return FuzzyCache.cache[key] >= threshold, FuzzyCache.cache[key]
    end
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
    local l = levenshtein(a, b)
    local maxLen = math.max(#a, #b)
    local levScore = maxLen > 0 and (1 - l / maxLen) or 1
    local final = (j + levScore) / 2
    FuzzyCache.cache[key] = final
    FuzzyCache.size = FuzzyCache.size + 1
    if FuzzyCache.size > FuzzyCache.max then
        FuzzyCache.cache = {}
        FuzzyCache.size = 0
    end
    return final >= threshold, final
end

--========== HELPERS ==========--
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
local Compiler = {}

local function compileFilter(fn)
    return function(e) return fn(e) end
end

local function compileSingle(cond)
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
            if match(e) then return true, { event = e } end
        end
        return false
    end
end

Compiler.seq = function(cond)
    local steps = {}
    for i, s in ipairs(cond.seq) do steps[i] = compileSingle(s) end
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
                    if n >= value then return true, { count = n } end
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
        if rate >= value then return true, { rate = rate, count = n } end
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
                if h >= value then return true, { entropy = h, sample = v:sub(1, 40) } end
            end
        end
        return false
    end
end

Compiler.regex = function(cond)
    local r = cond.regex
    local field = r.field or "data.url"
    local patterns = {}
    if r.any then
        for _, p in ipairs(r.any) do patterns[#patterns + 1] = p end
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
        if not Rules.Config.FUZZY_ENABLED then return false end
        for i = 1, #events do
            local v = getField(events[i], field)
            if type(v) == "string" and #v < 500 then
                local ok, score = fuzzyMatch(v, target, threshold)
                if ok then
                    return true, {
                        field = field, value = v:sub(1, 200),
                        target = target, similarity = score,
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
                if not pattern then return true, { field = field, value = v } end
                if type(v) == "string" and v:find(pattern) then
                    return true, { field = field, value = v:sub(1, 100) }
                end
            end
        end
        return false
    end
end

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
    if cond.type or cond.filter then return Compiler.event(cond) end
    return function() return false end
end

--========== RULE VALIDATION (v3.0) ==========--
function Rules.validateRule(rule)
    local errors = {}

    if type(rule) ~= "table" then
        return false, { "rule must be a table" }
    end
    if not rule.id or type(rule.id) ~= "string" or #rule.id == 0 then
        errors[#errors + 1] = "missing or invalid 'id'"
    end
    if rule.severity and (type(rule.severity) ~= "number"
        or rule.severity < 0 or rule.severity > 4) then
        errors[#errors + 1] = "severity must be 0-4"
    end
    if rule.confidence and (type(rule.confidence) ~= "number"
        or rule.confidence < 0 or rule.confidence > 1) then
        errors[#errors + 1] = "confidence must be 0-1"
    end
    if not rule.condition then
        errors[#errors + 1] = "missing 'condition'"
    end

    -- Check condition has known type
    if rule.condition then
        local known = false
        for _, key in ipairs({"event","seq","count","rate","entropy",
            "regex","fuzzy","all","any","not_","has","type","filter"}) do
            if rule.condition[key] ~= nil then known = true; break end
        end
        if not known then
            errors[#errors + 1] = "condition has no recognized type"
        end
    end

    return #errors == 0, errors
end

--========== SCORING ==========--
local function computeScore(rule, matchMeta)
    local sev = rule.severity or 1
    local conf = rule.confidence or 0.5
    local base = SEVERITY_WEIGHT[sev] or 0.5

    local mitreMult = 1.0
    if Rules.Config.ENABLE_MITRE and rule.mitre then
        mitreMult = MITRE_WEIGHT[rule.mitre] or 1.0
    end

    local ctxMult = 1.0
    if matchMeta then
        if matchMeta.elapsed and matchMeta.elapsed < 5 then ctxMult = ctxMult * 1.15 end
        if matchMeta.count and matchMeta.count > 100 then ctxMult = ctxMult * 1.10 end
        if matchMeta.entropy and matchMeta.entropy > 7.0 then ctxMult = ctxMult * 1.15 end
        if matchMeta.similarity and matchMeta.similarity > 0.95 then ctxMult = ctxMult * 1.10 end
    end

    local adaptiveMult = 1.0
    if Rules.Config.ADAPTIVE_ENABLED and rule._accuracy then
        adaptiveMult = 0.5 + rule._accuracy
    end

    return math.min(base * conf * mitreMult * ctxMult * adaptiveMult, 1.0)
end

--========== RULE ENGINE ==========--
local Engine = {}
Engine.__index = Engine

function Rules.new(edr)
    local self = setmetatable({
        edr         = edr,
        rules       = {},
        ruleOrder   = {},
        dedupBloom  = Bloom.new(Rules.Config.DEDUP_BLOOM_SIZE, Rules.Config.DEDUP_BLOOM_HASHES),
        dedupMap    = {},
        suppressed  = {},
        stats       = {
            scans        = 0,
            matches      = 0,
            deduped      = 0,
            bufferDropped = 0,
            byRule       = {},
            bySeverity   = { [0]=0, [1]=0, [2]=0, [3]=0, [4]=0 },
            totalScore   = 0,
            totalTime    = 0,
        },
        metaRules   = {},
        ruleChains  = {},
        recentMatches = {},
        version     = 0,
        integrityThread = nil,
        integrityStopped = false,
        baselineRules = {},
        integrityViolations = 0,
        mode        = Rules.Config.PERFORMANCE_MODE,
    }, Engine)

    Rules.installDefaults(self)
    self:_reorder()
    self:_startIntegrity()

    return self
end

function Engine:register(rule)
    -- v3.0: validate before register
    local valid, errors = Rules.validateRule(rule)
    if not valid then
        log(2, "register", "invalid rule: " .. tostring(rule and rule.id),
            { errors = errors })
        return nil, errors
    end

    if rule.enabled ~= false then rule.enabled = true end
    rule.cooldown   = rule.cooldown or Rules.Config.DEDUP_COOLDOWN
    rule.priority   = rule.priority or 0
    rule.severity   = rule.severity or 1
    rule.confidence = rule.confidence or 0.5
    rule.version    = rule.version or 1
    rule.category   = rule.category or "general"

    local ok, compiled = pcall(Rules.compile, rule.condition)
    if ok and type(compiled) == "function" then
        rule._eval = compiled
    else
        rule._eval = function() return false end
        log(2, "register", "compile failed for " .. rule.id, { err = tostring(compiled) })
    end

    rule._matchCount = 0
    rule._accuracy   = rule.accuracy or 0.5
    rule._lastHit    = 0
    rule._definitionHash = tostring(rule.id) .. ":" .. tostring(rule.condition and "has" or "none")

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
    for _, r in pairs(self.rules) do order[#order + 1] = r end
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
    local t = clock()
    if self.dedupBloom:contains(key) then
        local last = self.dedupMap[key]
        if last and (t - last) < rule.cooldown then
            self.stats.deduped = self.stats.deduped + 1
            return true
        end
    end
    self.dedupBloom:add(key)
    self.dedupMap[key] = t
    if self.stats.scans % 200 == 0 then self:_cleanupDedup() end
    return false
end

function Engine:_cleanupDedup()
    local t = clock()
    local toRemove = {}
    for k, ts in pairs(self.dedupMap) do
        if (t - ts) > 600 then toRemove[#toRemove + 1] = k end
    end
    for _, k in ipairs(toRemove) do self.dedupMap[k] = nil end
    -- cap and periodically reset the probabilistic filter before saturation.
    local dedupCount = 0
    for _ in pairs(self.dedupMap) do dedupCount = dedupCount + 1 end
    if dedupCount > Rules.Config.MAX_DEDUP_ENTRIES then
        self.dedupMap = {}
        self.dedupBloom:reset()
    elseif self.dedupBloom.itemCount > Rules.Config.DEDUP_BLOOM_SIZE * 0.7 then
        self.dedupBloom:reset()
    end
end

--========== CHAINING ==========--
function Engine:_checkChain(rule, matchedIds)
    if not Rules.Config.CHAINING_ENABLED then return true end
    local chain = self.ruleChains[rule.id]
    if not chain or not chain.requires then return true end
    for _, dep in ipairs(chain.requires) do
        local recent = self.recentMatches[dep]
        if not matchedIds[dep]
            and (not recent or (clock() - recent) > Rules.Config.CHAIN_WINDOW) then
            return false
        end
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
    ctx = ctx or { now = clock() }
    if not ctx.now then ctx.now = clock() end

    self.stats.scans = self.stats.scans + 1
    local t0 = clock()

    for id, hitTime in pairs(self.recentMatches) do
        if (ctx.now - hitTime) > Rules.Config.CHAIN_WINDOW then
            self.recentMatches[id] = nil
        end
    end

    local matches = {}
    local matchedIds = {}
    local matchCount = 0
    local maxMatches = Rules.Config.MAX_MATCHES_PER_SCAN

    for i = 1, #self.ruleOrder do
        local rule = self.ruleOrder[i]
        if rule.enabled and not self.suppressed[rule.id] then
            local ok, meta = rule._eval(events, ctx)
            if ok then
                if self:_checkChain(rule, matchedIds) then
                    if not self:_isDuplicate(rule, meta) then
                        local n = ctx.now
                        rule._lastHit = n
                        self.recentMatches[rule.id] = n
                        local score = computeScore(rule, meta)
                        matchCount = matchCount + 1
                        matches[matchCount] = {
                            rule = rule, meta = meta, score = score,
                            time = ctx.now, wall = os.time(),
                        }
                        matchedIds[rule.id] = true
                        rule._matchCount = rule._matchCount + 1
                        self.stats.byRule[rule.id] = (self.stats.byRule[rule.id] or 0) + 1
                        self.stats.bySeverity[rule.severity] = (self.stats.bySeverity[rule.severity] or 0) + 1
                        self.stats.totalScore = self.stats.totalScore + score
                        if Rules.Config.MATCH_MODE == "first" then break end
                        if matchCount >= maxMatches then
                            self.stats.bufferDropped = self.stats.bufferDropped + 1
                            break
                        end
                    end
                end
            end
        end
    end

    self.stats.matches = self.stats.matches + matchCount
    self.stats.totalTime = self.stats.totalTime + (clock() - t0)

    -- Forward to EDR
    if self.edr and self.edr.raiseAlert then
        for i = 1, #matches do
            local m = matches[i]
            local r = m.rule
            pcall(function()
                self.edr:raiseAlert({
                    rule = r.id, name = r.name, severity = r.severity,
                    message = r.description or r.name or r.id,
                    score = m.score, mitre = r.mitre, tags = r.tags,
                    category = r.category, meta = m.meta,
                })
            end)
        end
    end

    -- top-k
    if Rules.Config.MATCH_MODE == "topk" and #matches > Rules.Config.TOPK then
        table.sort(matches, function(a, b) return a.score > b.score end)
        local trimmed = {}
        for i = 1, Rules.Config.TOPK do trimmed[i] = matches[i] end
        matches = trimmed
    end

    return matches
end

--========== AGGREGATE RISK ==========--
function Engine:aggregateRisk(matches)
    if not matches or #matches == 0 then return 0 end
    local product = 1.0
    for i = 1, #matches do
        product = product * (1.0 - math.min(matches[i].score, 0.99))
    end
    local risk = 1.0 - product
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
        scans = self.stats.scans,
        matches = self.stats.matches,
        deduped = self.stats.deduped,
        bufferDropped = self.stats.bufferDropped,
        rules = #self.ruleOrder,
        enabledRules = (function()
            local n = 0
            for _, r in ipairs(self.ruleOrder) do
                if r.enabled then n = n + 1 end
            end
            return n
        end)(),
        byRule = self.stats.byRule,
        bySeverity = self.stats.bySeverity,
        avgScore = self.stats.matches > 0
            and (self.stats.totalScore / self.stats.matches) or 0,
        avgScanMs = self.stats.scans > 0
            and (self.stats.totalTime / self.stats.scans * 1000) or 0,
        dedupItems = self.dedupBloom.itemCount,
        version = self.version,
        mode = self.mode,
        integrityViolations = self.integrityViolations,
    }
end

function Engine:getRuleStats(id)
    local r = self.rules[id]
    if not r then return nil end
    return {
        id = r.id, name = r.name, enabled = r.enabled,
        severity = r.severity, confidence = r.confidence,
        priority = r.priority, matchCount = r._matchCount or 0,
        accuracy = r._accuracy, category = r.category, mitre = r.mitre,
    }
end

--========== TEST API (v3.0) ==========--
-- Unit test: รัน rule เฉพาะกับ events ที่กำหนด
function Engine:testRule(id, events, ctx)
    local r = self.rules[id]
    if not r then return false, "rule not found: " .. tostring(id) end
    if not r._eval then return false, "rule has no eval function" end

    ctx = ctx or { now = clock() }

    local ok, matched, meta = pcall(function()
        return r._eval(events, ctx)
    end)

    if not ok then
        return false, "eval error: " .. tostring(matched)
    end

    return matched, meta or {}
end

-- ทดสอบ rule กับ mock events
function Engine:testRuleWithMock(id, mockEvents)
    return self:testRule(id, mockEvents, { now = clock() })
end

-- Validate ทุก rule ใน engine
function Engine:validateAll()
    local results = {}
    for _, r in ipairs(self.ruleOrder) do
        local valid, errs = Rules.validateRule(r)
        results[r.id] = { valid = valid, errors = errs }
    end
    return results
end

--========== SELF INTEGRITY (v3.0) ==========--
function Engine:_startIntegrity()
    if not Rules.Config.SELF_INTEGRITY then return end

    -- Snapshot rule IDs + priorities
    for _, r in ipairs(self.ruleOrder) do
        self.baselineRules[r.id] = {
            severity = r.severity,
            priority = r.priority,
            enabled = r.enabled,
        }
    end

    self.integrityThread = task.spawn(function()
        while not self.integrityStopped do
            task.wait(Rules.Config.INTEGRITY_INTERVAL)
            for _, r in ipairs(self.ruleOrder) do
                local base = self.baselineRules[r.id]
                if base then
                    if base.severity ~= r.severity
                        or base.priority ~= r.priority then
                        self.integrityViolations = self.integrityViolations + 1
                        log(1, "integrity", "rule tampered: " .. r.id,
                            { baseline = base, current = {
                                severity = r.severity, priority = r.priority,
                            } })
                        if self.edr then
                            pcall(function()
                                self.edr:emit("ANOMALY", {
                                    metric = "rule_integrity_violation",
                                    rule = r.id,
                                }, 4)
                            end)
                        end
                        -- Revert
                        r.severity = base.severity
                        r.priority = base.priority
                    end
                end
            end
        end
    end)
end

function Engine:destroy()
    self.integrityStopped = true
    if self.integrityThread then
        pcall(function() task.cancel(self.integrityThread) end)
        self.integrityThread = nil
    end
end

--========== HOT RELOAD (v3.0) ==========--
function Engine:reloadRule(rule)
    if not rule or not rule.id then return false, "invalid rule" end
    if self.rules[rule.id] then
        self:unregister(rule.id)
    end
    return self:register(rule)
end

function Engine:getRule(id)
    return self.rules[id]
end

function Engine:getAllRules()
    local out = {}
    for _, r in ipairs(self.ruleOrder) do
        out[#out + 1] = {
            id = r.id, name = r.name, severity = r.severity,
            priority = r.priority, enabled = r.enabled,
            category = r.category, mitre = r.mitre,
            matchCount = r._matchCount or 0,
        }
    end
    return out
end

--========== DEFAULT RULES ==========--
function Rules.installDefaults(engine)
    -- กลุ่ม STEALER / CREDENTIAL
    engine:register({
        id = "CRED_STEALER_CHAIN",
        name = "Credential Stealer Chain",
        description = "อ่านไฟล์ที่มี token/cookie → encode → POST",
        category = "stealer", severity = 4, confidence = 0.90,
        mitre = "T1552", tags = {"stealer","credential","exfil"}, priority = 100,
        condition = { seq = {
            { type = "FILE_READ", filter = function(e)
                local p = tostring(e.data and e.data.path or ""):lower()
                return p:find("token") or p:find("cookie") or p:find(".env")
                    or p:find("credential") or p:find("wallet") or p:find("seed")
            end },
            { type = "STRING_ENCODE" },
            { type = "HTTP_POST" },
        }, within = 20 },
    })

    engine:register({
        id = "SENSITIVE_FILE_ACCESS",
        name = "Sensitive File Access",
        description = "อ่านไฟล์ที่มีข้อมูลลับ",
        category = "stealer", severity = 3, confidence = 0.75,
        mitre = "T1005", tags = {"collection","credential"}, priority = 80,
        condition = { has = { field = "data.sensitive" } },
    })

    engine:register({
        id = "DISCORD_WEBHOOK_EXFIL",
        name = "Discord Webhook Exfiltration",
        description = "ส่งข้อมูลออกผ่าน Discord Webhook",
        category = "exfil", severity = 4, confidence = 0.95,
        mitre = "T1567", tags = {"exfil","webhook","discord"}, priority = 95,
        condition = { regex = { field = "data.url",
            any = {"discord.com/api/webhooks","discordapp.com/api/webhooks"} } },
    })

    engine:register({
        id = "TELEGRAM_BOT_EXFIL",
        name = "Telegram Bot Exfiltration",
        description = "ส่งข้อมูลผ่าน Telegram Bot",
        category = "exfil", severity = 4, confidence = 0.92,
        mitre = "T1567", tags = {"exfil","telegram"}, priority = 95,
        condition = { regex = { field = "data.url", pattern = "api%.telegram%.org" } },
    })

    engine:register({
        id = "PASTEBIN_RAW_FETCH",
        name = "Pastebin Raw Fetch",
        description = "โหลดโค้ดจาก Pastebin",
        category = "staging", severity = 3, confidence = 0.70,
        mitre = "T1071.001", tags = {"staging","download"}, priority = 60,
        condition = { regex = { field = "data.url", pattern = "pastebin%.com/raw" } },
    })

    engine:register({
        id = "GITHUB_RAW_LOADER",
        name = "GitHub Raw Loader",
        description = "โหลด Lua จาก raw.githubusercontent.com",
        category = "staging", severity = 2, confidence = 0.55,
        mitre = "T1071.001", tags = {"staging","loader"}, priority = 40,
        condition = { regex = { field = "data.url", pattern = "raw%.githubusercontent%.com" } },
    })

    engine:register({
        id = "CLIPBOARD_ACCESS",
        name = "Clipboard Access",
        description = "เข้าถึง clipboard",
        category = "stealer", severity = 3, confidence = 0.70,
        mitre = "T1115", tags = {"clipboard","stealer"}, priority = 65,
        condition = { regex = { field = "data.name", pattern = "Clipboard" } },
    })

    -- กลุ่ม DROPPER / LOADER
    engine:register({
        id = "REMOTE_CODE_LOADER",
        name = "Remote Code Loader",
        description = "HttpGet → loadstring",
        category = "loader", severity = 4, confidence = 0.85,
        mitre = "T1620", tags = {"loader","dropper"}, priority = 90,
        condition = { seq = {
            { type = "HTTP_GET" },
            { type = "FUNCTION_CALL", filter = function(e)
                local n = e.data and e.data.name or ""
                return n == "loadstring" or n == "load" or n == "dofile"
            end },
        }, within = 8 },
    })

    engine:register({
        id = "MULTI_STAGE_LOADER",
        name = "Multi-Stage Loader",
        description = "HttpGet 3+ ครั้งใน 5 วินาที",
        category = "loader", severity = 3, confidence = 0.65,
        mitre = "T1071.001", tags = {"loader","chain"}, priority = 70,
        condition = { count = { type = "HTTP_GET", value = 3, within = 5 } },
    })

    engine:register({
        id = "DYNAMIC_CODE_EVAL",
        name = "Dynamic Code Evaluation",
        description = "loadstring กับ string จาก network",
        category = "loader", severity = 3, confidence = 0.80,
        mitre = "T1059", tags = {"eval","dynamic"}, priority = 75,
        condition = { all = {
            { type = "FUNCTION_CALL", filter = function(e)
                return (e.data and e.data.name or "") == "loadstring"
            end },
            { any = { { type = "HTTP_GET" }, { type = "FILE_READ" } } },
        } },
    })

    engine:register({
        id = "BASE64_URL_LOADER",
        name = "Base64 URL Loader",
        description = "base64 ของ 'https://'",
        category = "loader", severity = 3, confidence = 0.85,
        mitre = "T1140", tags = {"obfuscation","loader"}, priority = 65,
        condition = { any = {
            { regex = { field = "data.value", pattern = "aHR0cHM6Ly" } },
            { regex = { field = "data.value", pattern = "aHR0cDovLw" } },
        } },
    })

    engine:register({
        id = "LOADER_CHAIN",
        name = "Loader Chain",
        description = "HttpGet → loadstring → HttpGet",
        category = "loader", severity = 4, confidence = 0.88,
        mitre = "T1620", tags = {"loader","chain"}, priority = 92,
        requires = {"REMOTE_CODE_LOADER"},
        condition = { seq = {
            { type = "HTTP_GET" },
            { type = "FUNCTION_CALL", filter = function(e)
                return (e.data and e.data.name or "") == "loadstring"
            end },
            { type = "HTTP_GET" },
        }, within = 15 },
    })

    -- กลุ่ม OBFUSCATION
    engine:register({
        id = "HIGH_ENTROPY_STRING",
        name = "High-Entropy String",
        description = "entropy > 6.5 bits/char",
        category = "obfuscation", severity = 2, confidence = 0.60,
        mitre = "T1027", tags = {"obfuscation","encryption"}, priority = 40,
        condition = { entropy = { field = "data.value", value = 6.5 } },
    })

    engine:register({
        id = "BXOR_DECRYPT_BURST",
        name = "XOR Decryption Burst",
        description = "bit32.bxor > 100/s",
        category = "obfuscation", severity = 2, confidence = 0.70,
        mitre = "T1140", tags = {"obfuscation","luraph"}, priority = 50,
        condition = { rate = { type = "STRING_DECRYPT", value = 100, window = 1 } },
    })

    engine:register({
        id = "STRING_CHAR_LOOP",
        name = "string.char Decryption Loop",
        description = "string.char ในลูป",
        category = "obfuscation", severity = 2, confidence = 0.65,
        mitre = "T1140", tags = {"obfuscation"}, priority = 45,
        condition = { count = { type = "STRING_DECRYPT", value = 20, within = 2 } },
    })

    engine:register({
        id = "ANTI_DEBUG_PROBE",
        name = "Anti-Debug Probe",
        description = "debug.getinfo/sethook",
        category = "anti-analysis", severity = 3, confidence = 0.75,
        mitre = "T1622", tags = {"anti-analysis"}, priority = 65,
        condition = { all = {
            { type = "DEBUG_ACCESS", filter = function(e)
                local n = e.data and e.data.name or ""
                return n == "getinfo" or n == "sethook" or n == "gethook"
            end },
            { count = { type = "DEBUG_ACCESS", value = 5, within = 3 } },
        } },
    })

    engine:register({
        id = "METATABLE_TAMPER",
        name = "Metatable Tampering",
        description = "แก้ metatable หลายครั้ง",
        category = "hook", severity = 2, confidence = 0.55,
        mitre = "T1055", tags = {"hook"}, priority = 40,
        condition = { count = { type = "METATABLE_ACCESS", value = 10, within = 5 } },
    })

    engine:register({
        id = "UPVALUE_OBFUSCATION",
        name = "Upvalue Obfuscation",
        description = "ใช้ upvalue ซ่อนข้อมูล",
        category = "obfuscation", severity = 2, confidence = 0.50,
        mitre = "T1027", tags = {"obfuscation"}, priority = 35,
        condition = { regex = { field = "data.source", pattern = "upvalue" } },
    })

    -- กลุ่ม NETWORK / C2
    engine:register({
        id = "DIRECT_IP_CONNECTION",
        name = "Direct IP Connection",
        description = "เชื่อมต่อ IP ตรง",
        category = "network", severity = 3, confidence = 0.70,
        mitre = "T1071", tags = {"c2","network"}, priority = 60,
        condition = { regex = { field = "data.url",
            pattern = "https?://%d+%.%d+%.%d+%.%d+" } },
    })

    engine:register({
        id = "SUSPICIOUS_TLD",
        name = "Suspicious TLD",
        description = "TLD ที่มักใช้ใน malware",
        category = "network", severity = 2, confidence = 0.55,
        mitre = "T1583.001", tags = {"network"}, priority = 35,
        condition = { regex = { field = "data.url",
            any = {"%.tk/","%.ml/","%.ga/","%.cf/","%.gq/",
                "%.top/","%.xyz/","%.link/","%.click/"} } },
    })

    engine:register({
        id = "HIGH_NETWORK_RATE",
        name = "High Network Rate",
        description = "request > 20/s",
        category = "network", severity = 3, confidence = 0.70,
        mitre = "T1041", tags = {"network","exfil"}, priority = 70,
        condition = { rate = { type = "NETWORK_REQUEST", value = 20, window = 1 } },
    })

    engine:register({
        id = "ENCRYPTED_C2_CHANNEL",
        name = "Encrypted C2 Channel",
        description = "HTTP POST → NETWORK_RESPONSE",
        category = "c2", severity = 3, confidence = 0.65,
        mitre = "T1071.001", tags = {"c2"}, priority = 60,
        condition = { seq = {
            { type = "HTTP_POST" },
            { type = "NETWORK_RESPONSE" },
        }, within = 3 },
    })

    engine:register({
        id = "ENCRYPTED_C2_ENTROPY",
        name = "Encrypted C2 Exfil",
        description = "high entropy → POST",
        category = "c2", severity = 4, confidence = 0.85,
        mitre = "T1041", tags = {"c2","exfil","encrypted"}, priority = 88,
        condition = { seq = {
            { type = "STRING_DECRYPT", filter = function(e)
                local v = e.data and e.data.value
                return type(v) == "string" and #v > 30 and entropy(v) > 6.5
            end },
            { type = "HTTP_POST" },
        }, within = 8 },
    })

    engine:register({
        id = "TYPOSQUATTING_ATTEMPT",
        name = "Typosquatting Attempt",
        description = "URL คล้าย discord webhook",
        category = "network", severity = 3, confidence = 0.75,
        mitre = "T1583.001", tags = {"network","phishing"}, priority = 65,
        condition = { fuzzy = { field = "data.url",
            target = "https://discord.com/api/webhooks/", threshold = 0.90 } },
    })

    engine:register({
        id = "PASTEBIN_TYPOSQUAT",
        name = "Pastebin Typosquat",
        description = "URL คล้าย pastebin.com",
        category = "network", severity = 3, confidence = 0.70,
        mitre = "T1583.001", tags = {"network","phishing"}, priority = 60,
        condition = { fuzzy = { field = "data.url",
            target = "https://pastebin.com/raw/", threshold = 0.88 } },
    })

    -- กลุ่ม RESOURCE HIJACKING
    engine:register({
        id = "CRYPTO_MINER_PATTERN",
        name = "Crypto Miner Pattern",
        description = "เชื่อมต่อ mining pool",
        category = "miner", severity = 3, confidence = 0.75,
        mitre = "T1496", tags = {"miner"}, priority = 70,
        condition = { regex = { field = "data.url",
            any = {"pool%.","xmr%.","monero","nicehash","minergate"} } },
    })

    engine:register({
        id = "RESOURCE_EXHAUSTION",
        name = "Resource Exhaustion",
        description = "coroutine > 1000/s",
        category = "resource", severity = 2, confidence = 0.60,
        mitre = "T1499", tags = {"resource","dos"}, priority = 45,
        condition = { rate = { type = "COROUTINE_CREATE", value = 1000, window = 1 } },
    })

    -- กลุ่ม INPUT CAPTURE
    engine:register({
        id = "INPUT_CAPTURE",
        name = "Input Capture",
        description = "InputBegan + network",
        category = "keylogger", severity = 4, confidence = 0.80,
        mitre = "T1056.001", tags = {"keylogger"}, priority = 85,
        condition = { all = {
            { regex = { field = "data.name", pattern = "InputBegan" } },
            { any = { { type = "NETWORK_REQUEST" }, { type = "HTTP_POST" } } },
        } },
    })

    -- กลุ่ม HOOK / POLLUTION
    engine:register({
        id = "GLOBAL_ENV_POLLUTION",
        name = "Global Env Pollution",
        description = "global write > 50/10s",
        category = "hook", severity = 2, confidence = 0.60,
        mitre = "T1055", tags = {"hook","pollution"}, priority = 45,
        condition = { count = { type = "GLOBAL_WRITE", value = 50, within = 10 } },
    })

    engine:register({
        id = "FUNCTION_REDEFINE_HOOK",
        name = "Function Redefine Hook",
        description = "เขียนทับ HttpGet/loadstring",
        category = "hook", severity = 3, confidence = 0.70,
        mitre = "T1055", tags = {"hook"}, priority = 60,
        condition = { any = {
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
        } },
    })

    engine:register({
        id = "SELF_INTEGRITY_TAMPER",
        name = "Self-Integrity Tamper",
        description = "แก้ฟังก์ชันหลักของ environment",
        category = "anti-analysis", severity = 4, confidence = 0.85,
        mitre = "T1562.001", tags = {"hook","tamper"}, priority = 90,
        condition = { all = {
            { regex = { field = "data.name",
                pattern = "pcall|setmetatable|rawget|tostring|type" } },
            { type = "FUNCTION_REDEFINE" },
        } },
    })

    engine:register({
        id = "RAW_METATABLE_ABUSE",
        name = "Raw Metatable Abuse",
        description = "getrawmetatable หลายครั้ง",
        category = "hook", severity = 3, confidence = 0.65,
        mitre = "T1055", tags = {"hook"}, priority = 55,
        condition = { count = { type = "METATABLE_ACCESS", value = 5, within = 3,
            filter = function(e) return e.data and e.data.op == "getraw" end } },
    })

    -- กลุ่ม ENV ESCALATION
    engine:register({
        id = "THREAD_IDENTITY_ESCALATION",
        name = "Thread Identity Escalation",
        description = "ยกระดับ identity",
        category = "escalation", severity = 4, confidence = 0.85,
        mitre = "T1055", tags = {"escalation","bypass"}, priority = 90,
        condition = { all = {
            { type = "THREAD_IDENTITY", filter = function(e)
                return e.data and e.data.op == "set" and (e.data.id or 0) >= 6
            end },
        } },
    })

    engine:register({
        id = "ENV_MANIPULATION",
        name = "Environment Manipulation",
        description = "setfenv หลายครั้ง",
        category = "escalation", severity = 3, confidence = 0.65,
        mitre = "T1055", tags = {"sandbox-escape"}, priority = 55,
        condition = { count = { type = "ENV_ACCESS", value = 5, within = 5,
            filter = function(e) return e.data and e.data.op == "set" end } },
    })

    -- กลุ่ม ROBLOX
    engine:register({
        id = "SENSITIVE_SERVICE_ACCESS",
        name = "Sensitive Service Access",
        description = "DataStore/MemoryStore",
        category = "roblox", severity = 3, confidence = 0.60,
        mitre = "T1005", tags = {"roblox","datastore"}, priority = 55,
        condition = { regex = { field = "data.service",
            pattern = "DataStore|MemoryStore|Messaging" } },
    })

    engine:register({
        id = "PROPERTY_TAMPER",
        name = "Property Tampering",
        description = "แก้ Humanoid/Camera",
        category = "roblox", severity = 3, confidence = 0.70,
        mitre = "T1562.001", tags = {"roblox","tamper"}, priority = 65,
        condition = { count = { type = "RBX_PROPERTY_WRITE", value = 15, within = 5,
            filter = function(e)
                local d = e.data or {}
                return d.class == "Humanoid" or d.class == "Camera"
            end } },
    })

    engine:register({
        id = "REMOTE_SPAM",
        name = "Remote Event Spam",
        description = "remote > 20/5s",
        category = "roblox", severity = 3, confidence = 0.65,
        mitre = "T1059", tags = {"roblox","remote"}, priority = 60,
        condition = { count = { type = "RBX_REMOTE_FIRE", value = 20, within = 5 } },
    })

    engine:register({
        id = "SCRIPT_IN_WORKSPACE",
        name = "Script in Workspace",
        description = "Script/LocalScript ใน Workspace",
        category = "roblox", severity = 3, confidence = 0.70,
        mitre = "T1543", tags = {"roblox","backdoor"}, priority = 70,
        condition = { all = {
            { type = "RBX_WORKSPACE_WRITE" },
            { regex = { field = "data.event", pattern = "ScriptsInWorkspace" } },
        } },
    })

    engine:register({
        id = "DATASTORE_EGRESS",
        name = "DataStore Exfiltration",
        description = "DataStore → HTTP",
        category = "roblox", severity = 4, confidence = 0.80,
        mitre = "T1567", tags = {"roblox","exfil"}, priority = 85,
        condition = { seq = {
            { type = "RBX_SERVICE_ACCESS", filter = function(e)
                local s = e.data and e.data.service or ""
                return s == "DataStoreService" or s == "MemoryStoreService"
            end },
            { type = "NETWORK_REQUEST" },
        }, within = 15 },
    })

    -- กลุ่ม VULN
    engine:register({
        id = "CRITICAL_VULN_FOUND",
        name = "Critical Vulnerability Found",
        description = "vuln_scanner พบช่องโหว่วิกฤต",
        category = "vuln", severity = 4, confidence = 0.85,
        mitre = "T1190", tags = {"vuln","critical"}, priority = 100,
        condition = { type = "VULN_FINDING",
            filter = function(e) return (e.severity or 0) >= 4 end },
    })

    engine:register({
        id = "HIGH_VULN_COUNT",
        name = "High Vulnerability Count",
        description = "vuln scanner พบ high 5+",
        category = "vuln", severity = 3, confidence = 0.75,
        mitre = "T1190", tags = {"vuln"}, priority = 80,
        condition = { count = { type = "VULN_FINDING", value = 5, within = 60,
            filter = function(e) return (e.severity or 0) >= 3 end } },
    })

    -- กลุ่ม ANOMALY
    engine:register({
        id = "ANOMALY_CLUSTER",
        name = "Anomaly Cluster",
        description = "3+ anomalies ใน 10s",
        category = "anomaly", severity = 3, confidence = 0.70,
        mitre = "T1499", tags = {"anomaly"}, priority = 70,
        condition = { count = { type = "ANOMALY", value = 3, within = 10 } },
    })

    engine:register({
        id = "TAINT_FLOW_SENSITIVE",
        name = "Sensitive Data Flow",
        description = "taint flow sensitive → sink",
        category = "anomaly", severity = 4, confidence = 0.85,
        mitre = "T1041", tags = {"taint","dataflow"}, priority = 88,
        condition = { type = "TAINT_FLOW" },
    })

    -- COMPOSITE
    engine:register({
        id = "ADVANCED_STEALER_CHAIN",
        name = "Advanced Stealer Chain",
        description = "file + decrypt + network + global",
        category = "composite", severity = 4, confidence = 0.95,
        mitre = "T1552", tags = {"stealer","composite"}, priority = 110,
        condition = { all = {
            { count = { type = "FILE_READ", value = 3, within = 15,
                filter = function(e) return e.data and e.data.sensitive == true end } },
            { count = { type = "STRING_DECRYPT", value = 50, within = 15 } },
            { any = { { type = "HTTP_POST" }, { type = "NETWORK_REQUEST" } } },
            { count = { type = "GLOBAL_WRITE", value = 10, within = 15 } },
        } },
    })

    engine:register({
        id = "RAT_FULL_CHAIN",
        name = "RAT Full Chain",
        description = "loader + hook + persistence",
        category = "composite", severity = 4, confidence = 0.90,
        mitre = "T1071", tags = {"rat","composite"}, priority = 105,
        condition = { all = {
            { type = "HTTP_GET" },
            { type = "FUNCTION_CALL", filter = function(e)
                return (e.data and e.data.name or "") == "loadstring"
            end },
            { type = "GLOBAL_WRITE", filter = function(e)
                local k = e.data and e.data.key or ""
                return k:find("hook") or k:find("Hook") or k:find("__")
            end },
        } },
    })

    engine:register({
        id = "FULL_KILL_CHAIN",
        name = "Full Kill Chain",
        description = "loader + stealer + exfil + anti-debug",
        category = "composite", severity = 4, confidence = 0.97,
        mitre = "T1041", tags = {"killchain","composite","critical"},
        priority = 120,
        requires = {"REMOTE_CODE_LOADER", "CRED_STEALER_CHAIN"},
        condition = { all = {
            { type = "DEBUG_ACCESS" },
            { count = { type = "HTTP_GET", value = 2, within = 30 } },
            { count = { type = "FILE_READ", value = 2, within = 30 } },
            { type = "HTTP_POST" },
        } },
    })

    engine:register({
        id = "PERSISTENCE_PATTERN",
        name = "Persistence Pattern",
        description = "global hook + task schedule",
        category = "composite", severity = 3, confidence = 0.75,
        mitre = "T1543", tags = {"persistence"}, priority = 70,
        condition = { all = {
            { count = { type = "GLOBAL_WRITE", value = 20, within = 10 } },
            { count = { type = "TASK_SCHEDULED", value = 3, within = 10 } },
        } },
    })
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
Rules.Engine = Engine
Rules.Compiler = Compiler
Rules.Bloom = Bloom
Rules.SEVERITY_WEIGHT = SEVERITY_WEIGHT
Rules.MITRE_WEIGHT = MITRE_WEIGHT
Rules.MODE_PROFILES = MODE_PROFILES
Rules.levenshtein = levenshtein
Rules.jaro = jaro
Rules.fuzzyMatch = fuzzyMatch
Rules.entropy = entropy

function Rules.getVersion()
    return Rules._VERSION
end

-- singleton
Rules._instance = nil

function Rules.get(edr)
    if not Rules._instance then
        Rules._instance = Rules.new(edr)
    end
    return Rules._instance
end

function Rules.reset()
    if Rules._instance then Rules._instance:destroy() end
    Rules._instance = nil
    FuzzyCache.cache = {}
    FuzzyCache.size = 0
end

return Rules