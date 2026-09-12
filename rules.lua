--[[
    ============================================================
    EDR Rules Engine v1.0 — YARA-style DSL + Weighted Scoring
    ============================================================
    หลักการ:
    - Rule เป็น declarative table เข้าใจง่าย
    - Composite conditions: AND/OR/NOT/SEQ/COUNT/RATE/ENTROPY/REGEX
    - Weighted risk score ตาม severity + confidence + MITRE
    - Cooldown + dedup กัน alert spam
    - MITRE ATT&CK mapping
    - Hot-reload + enable/disable rule ตอนรัน
    - Rule priority + first-match / all-match mode

    ใช้ร่วมกับ:
    - edr_core.lua : ใช้ EventType, Severity, Stats, Correlator
    - hooks.lua    : เป็น source ของ event
    ============================================================
]]

local Rules = {}

--========== CONFIG ==========--
Rules.Config = {
    -- โหมดการ match: "all" = match ทุก rule, "first" = match rule แรกแล้วหยุด
    MATCH_MODE        = "all",
    -- คะแนน risk สูงสุด (ใช้ normalize)
    MAX_RISK_SCORE    = 100,
    -- จำนวน rule ที่ match ได้สูงสุดต่อ scan cycle (กัน performance)
    MAX_MATCHES_PER_SCAN = 50,
    -- เปิด dedup (rule_id + key ไม่ซ้ำภายใน cooldown)
    ENABLE_DEDUP      = true,
    -- default cooldown (วินาที)
    DEFAULT_COOLDOWN  = 60,
    -- เปิดการเชื่อม MITRE
    ENABLE_MITRE      = true,
    -- log level
    LOG_LEVEL         = 1,
}

--========== SEVERITY WEIGHTS ==========--
-- น้ำหนักของแต่ละ severity ต่อคะแนน risk
local SEVERITY_WEIGHT = {
    [0] = 0.05,   -- INFO
    [1] = 0.25,   -- LOW
    [2] = 0.55,   -- MEDIUM
    [3] = 0.80,   -- HIGH
    [4] = 1.00,   -- CRITICAL
}

--========== MITRE ATT&CK IMPACT ==========--
-- น้ำหนักเพิ่มเติมตาม tactic ของ MITRE
local MITRE_WEIGHT = {
    ["T1059"] = 1.15,  -- Command and Scripting Interpreter
    ["T1059.007"] = 1.10, -- JavaScript (Lua analog)
    ["T1056"] = 1.20,  -- Input Capture (keylogger)
    ["T1005"] = 1.15,  -- Data from Local System
    ["T1071"] = 1.10,  -- Application Layer Protocol
    ["T1071.001"] = 1.10, -- Web Protocols
    ["T1041"] = 1.30,  -- Exfiltration Over C2
    ["T1567"] = 1.25,  -- Exfiltration Over Web Service
    ["T1496"] = 1.15,  -- Resource Hijacking (miner)
    ["T1055"] = 1.40,  -- Process Injection
    ["T1620"] = 1.20,  -- Reflective Code Loading
    ["T1027"] = 0.85,  -- Obfuscated Files (baseline, ต่ำเพราะเจอบ่อย)
    ["T1140"] = 0.90,  -- Deobfuscate/Decode
    ["T1552"] = 1.30,  -- Unsecured Credentials
    ["T1555"] = 1.35,  -- Credentials from Password Stores
    ["T1115"] = 1.25,  -- Clipboard Data
    ["T1113"] = 1.20,  -- Screen Capture
    ["T1056.001"] = 1.20, -- Keylogging
}

--========== CONDITION EVALUATORS ==========--
-- แต่ละ condition type จะมี eval function

local Evaluators = {}

-- 1. Simple event match: { type = "HTTP_POST" }
Evaluators.event = function(cond, event)
    if cond.type_name and event.type ~= cond.type_name then return false end
    if cond.filter and not cond.filter(event) then return false end
    if cond.severity_min and (event.severity or 0) < cond.severity_min then return false end
    return true
end

-- 2. Sequence: { seq = { {type="A"}, {type="B"} }, within = 10 }
Evaluators.seq = function(cond, events, ctx)
    local steps = cond.seq
    local within = cond.within or 30
    local stepIdx = 1
    local matchStart = nil

    for _, e in ipairs(events) do
        local expected = steps[stepIdx]
        if expected then
            local matched = true
            if expected.type_name and e.type ~= expected.type_name then
                matched = false
            elseif expected.filter and not expected.filter(e) then
                matched = false
            end

            if matched then
                if stepIdx == 1 then matchStart = e.t end
                stepIdx = stepIdx + 1
                if stepIdx > #steps then
                    local elapsed = e.t - matchStart
                    if elapsed <= within then
                        return true, { elapsed = elapsed }
                    end
                    -- reset
                    stepIdx = 1
                    matchStart = nil
                end
            end
        end
    end
    return false
end

-- 3. Count threshold: { count = { event = "X", op = ">=", value = 10, within = 5 } }
Evaluators.count = function(cond, events, ctx)
    local c = cond.count
    local within = c.within or 10
    local now = ctx.now or os.clock()
    local n = 0
    for _, e in ipairs(events) do
        if (now - e.t) <= within then
            if not c.event or e.type == c.event then
                if not c.filter or c.filter(e) then
                    n = n + 1
                end
            end
        end
    end
    return _compare(n, c.op or ">=", c.value), { count = n }
end

-- 4. Rate: { rate = { event = "X", op = ">", value = 100 } }  events/sec
Evaluators.rate = function(cond, events, ctx)
    local r = cond.rate
    local window = r.window or 1
    local now = ctx.now or os.clock()
    local n = 0
    for _, e in ipairs(events) do
        if (now - e.t) <= window then
            if not r.event or e.type == r.event then n = n + 1 end
        end
    end
    local rate = n / window
    return _compare(rate, r.op or ">", r.value), { rate = rate, count = n }
end

-- 5. Entropy check: { entropy = { field = "value", op = ">", value = 6.5 } }
Evaluators.entropy = function(cond, events, ctx)
    local e = cond.entropy
    for _, ev in ipairs(events) do
        local v = _getField(ev, e.field or "data.value")
        if type(v) == "string" and #v >= 8 then
            local H = _entropy(v)
            if _compare(H, e.op or ">", e.value or 6.0) then
                return true, { entropy = H, sample = v:sub(1, 60) }
            end
        end
    end
    return false
end

-- 6. Regex match: { regex = { field = "data.url", pattern = "webhook" } }
Evaluators.regex = function(cond, events, ctx)
    local r = cond.regex
    for _, ev in ipairs(events) do
        local v = _getField(ev, r.field or "data.url")
        if type(v) == "string" then
            if r.any then
                for _, p in ipairs(r.any) do
                    if v:find(p) then return true, { field = r.field, value = v:sub(1, 200), pattern = p } end
                end
            elseif r.pattern and v:find(r.pattern) then
                return true, { field = r.field, value = v:sub(1, 200), pattern = r.pattern }
            end
        end
    end
    return false
end

-- 7. AND: { all = { cond1, cond2, ... } }
Evaluators.all = function(cond, events, ctx)
    local results = {}
    for _, c in ipairs(cond.all) do
        local ok, meta = _evalCondition(c, events, ctx)
        if not ok then return false end
        table.insert(results, meta)
    end
    return true, { all = results }
end

-- 8. OR: { any = { cond1, cond2, ... } }
Evaluators.any = function(cond, events, ctx)
    for _, c in ipairs(cond.any) do
        local ok, meta = _evalCondition(c, events, ctx)
        if ok then return true, { any = meta } end
    end
    return false
end

-- 9. NOT: { not_ = cond }
Evaluators.not_ = function(cond, events, ctx)
    local ok = _evalCondition(cond.not_, events, ctx)
    return not ok
end

-- 10. Field presence: { has = { field = "data.url", pattern = "..." } }
Evaluators.has = function(cond, events, ctx)
    local h = cond.has
    for _, ev in ipairs(events) do
        local v = _getField(ev, h.field)
        if v ~= nil then
            if not h.pattern or (type(v) == "string" and v:find(h.pattern)) then
                return true, { field = h.field, value = v }
            end
        end
    end
    return false
end

--========== INTERNAL HELPERS ==========--

function _compare(a, op, b)
    if op == ">=" then return a >= b
    elseif op == "<=" then return a <= b
    elseif op == ">" then return a > b
    elseif op == "<" then return a < b
    elseif op == "==" then return a == b
    elseif op == "~=" then return a ~= b
    else return false end
end

function _getField(obj, path)
    if not path then return nil end
    local cur = obj
    for seg in path:gmatch("[^%.]+") do
        if type(cur) ~= "table" then return nil end
        cur = cur[seg]
        if cur == nil then return nil end
    end
    return cur
end

function _entropy(s)
    if type(s) ~= "string" or #s == 0 then return 0 end
    local freq = {}
    for i = 1, #s do
        local c = s:sub(i, i)
        freq[c] = (freq[c] or 0) + 1
    end
    local H = 0
    for _, n in pairs(freq) do
        local p = n / #s
        H = H - p * (math.log(p) / math.log(2))
    end
    return H
end

function _evalCondition(cond, events, ctx)
    -- หา type ของ condition
    local evalType = nil
    for _, key in ipairs({"event","seq","count","rate","entropy","regex","all","any","not_","has"}) do
        if cond[key] ~= nil or (key == "event" and cond.type_name) then
            evalType = key
            break
        end
    end
    if not evalType then return false end
    local fn = Evaluators[evalType]
    if not fn then return false end
    return fn(cond, events, ctx)
end

--========== RULE SCORING ==========--
local function computeScore(rule, matchMeta)
    local sev    = rule.severity or 1
    local conf   = rule.confidence or 0.5
    local base   = SEVERITY_WEIGHT[sev] or 0.5

    -- MITRE impact
    local mitreMult = 1.0
    if Rules.Config.ENABLE_MITRE and rule.mitre then
        mitreMult = MITRE_WEIGHT[rule.mitre] or 1.0
    end

    -- Match bonus ตาม context
    local ctxMult = 1.0
    if matchMeta then
        if matchMeta.elapsed and matchMeta.elapsed < 5 then
            ctxMult = ctxMult * 1.15  -- เร็ว = น่าสงสัย
        end
        if matchMeta.count and matchMeta.count > 100 then
            ctxMult = ctxMult * 1.10
        end
        if matchMeta.entropy and matchMeta.entropy > 7.0 then
            ctxMult = ctxMult * 1.15
        end
    end

    local score = base * conf * mitreMult * ctxMult
    return math.min(score, 1.0)
end

--========== RULE DEDUP ==========--
local function makeDedupKey(rule, matchMeta)
    -- key = rule.id + first meaningful field
    local parts = { rule.id }
    if matchMeta then
        if matchMeta.value then table.insert(parts, tostring(matchMeta.value):sub(1, 40)) end
        if matchMeta.field then table.insert(parts, matchMeta.field) end
        if matchMeta.sample then table.insert(parts, matchMeta.sample:sub(1, 40)) end
    end
    return table.concat(parts, ":")
end

--========== RULES ENGINE ==========--
local Engine = {}
Engine.__index = Engine

function Rules.new(edr)
    local self = setmetatable({
        edr          = edr,
        rules        = {},        -- [id] = rule
        ruleOrder    = {},        -- sorted by priority
        dedupMap     = {},        -- [key] = timestamp
        stats        = {
            scans       = 0,
            matches     = 0,
            by_rule     = {},
            by_severity = { [0]=0, [1]=0, [2]=0, [3]=0, [4]=0 },
            total_score = 0,
        },
    }, Engine)

    -- install default rules
    Rules.installDefaults(self)

    return self
end

--========== RULE REGISTRATION ==========--
function Engine:register(rule)
    if not rule.id then
        error("Rule must have an 'id' field")
    end
    rule.enabled  = rule.enabled ~= false
    rule.cooldown = rule.cooldown or Rules.Config.DEFAULT_COOLDOWN
    rule.priority = rule.priority or 0
    rule.severity = rule.severity or 1
    rule.confidence = rule.confidence or 0.5

    self.rules[rule.id] = rule
    self:_reorder()
    return rule
end

function Engine:unregister(id)
    self.rules[id] = nil
    self:_reorder()
end

function Engine:enable(id)
    if self.rules[id] then self.rules[id].enabled = true end
end

function Engine:disable(id)
    if self.rules[id] then self.rules[id].enabled = false end
end

function Engine:_reorder()
    self.ruleOrder = {}
    for _, r in pairs(self.rules) do
        table.insert(self.ruleOrder, r)
    end
    -- เรียง priority สูงก่อน
    table.sort(self.ruleOrder, function(a, b)
        if a.priority == b.priority then return a.id < b.id end
        return a.priority > b.priority
    end)
end

--========== DEDUP CHECK ==========--
function Engine:_isDuplicate(key, cooldown)
    if not Rules.Config.ENABLE_DEDUP then return false end
    local t = os.clock()
    local last = self.dedupMap[key]
    if last and (t - last) < cooldown then
        return true
    end
    self.dedupMap[key] = t
    return false
end

function Engine:_cleanupDedup()
    -- ลบ entry เก่าทุก 100 scans
    if self.stats.scans % 100 ~= 0 then return end
    local t = os.clock()
    for k, ts in pairs(self.dedupMap) do
        if (t - ts) > 600 then
            self.dedupMap[k] = nil
        end
    end
end

--========== SCAN ==========--
function Engine:scan(events, ctx)
    if not events then
        events = self.edr and self.edr.buffer and self.edr.buffer:snapshot() or {}
    end
    if not ctx then
        ctx = { now = os.clock() }
    end

    self.stats.scans = self.stats.scans + 1
    local matches = {}

    for _, rule in ipairs(self.ruleOrder) do
        if rule.enabled then
            local ok, meta = _evalCondition(rule.condition, events, ctx)
            if ok then
                -- dedup
                local key = makeDedupKey(rule, meta)
                if not self:_isDuplicate(key, rule.cooldown) then
                    local score = computeScore(rule, meta)
                    local match = {
                        rule     = rule,
                        meta     = meta,
                        score    = score,
                        time     = ctx.now or os.clock(),
                        wall     = os.time(),
                    }
                    table.insert(matches, match)

                    self.stats.matches = self.stats.matches + 1
                    self.stats.by_rule[rule.id] = (self.stats.by_rule[rule.id] or 0) + 1
                    self.stats.by_severity[rule.severity] = (self.stats.by_severity[rule.severity] or 0) + 1
                    self.stats.total_score = self.stats.total_score + score

                    -- แจ้ง EDR
                    if self.edr and self.edr.raiseAlert then
                        self.edr:raiseAlert({
                            rule     = rule.id,
                            name     = rule.name,
                            severity = rule.severity,
                            message  = rule.description or rule.name,
                            score    = score,
                            mitre    = rule.mitre,
                            tags     = rule.tags,
                            meta     = meta,
                        })
                    end

                    if Rules.Config.MATCH_MODE == "first" then break end
                    if #matches >= Rules.Config.MAX_MATCHES_PER_SCAN then break end
                end
            end
        end
    end

    self:_cleanupDedup()
    return matches
end

--========== SCORING ==========--
function Engine:aggregateRisk(matches)
    -- รวมคะแนนแบบ probabilistic OR: risk = 1 - Π(1 - score_i)
    local product = 1.0
    for _, m in ipairs(matches) do
        product = product * (1.0 - m.score)
    end
    local risk = 1.0 - product

    -- ถ้ามี CRITICAL อย่างน้อย 1 ตัว → รับประกันขั้นต่ำ 0.7
    for _, m in ipairs(matches) do
        if m.rule.severity >= 4 then
            risk = math.max(risk, 0.7)
            break
        end
    end

    return risk
end

--========== STATS ==========--
function Engine:summary()
    return {
        scans       = self.stats.scans,
        matches     = self.stats.matches,
        by_rule     = self.stats.by_rule,
        by_severity = self.stats.by_severity,
        avg_score   = self.stats.matches > 0
            and (self.stats.total_score / self.stats.matches) or 0,
        rule_count  = #self.ruleOrder,
    }
end

--========== DEFAULT RULES ==========--
-- Rule Library: 25 rules จากงานวิจัย malware families ทั่วไป
function Rules.installDefaults(engine)

    --========= CREDENTIAL / STEALER ==========

    engine:register({
        id       = "CRED_STEALER_CHAIN",
        name     = "Credential Stealer Chain",
        description = "อ่านไฟล์ที่ชื่อมี token/cookie → encode → ส่งออก network",
        severity = 4,
        confidence = 0.90,
        mitre    = "T1552",
        tags     = {"stealer", "credential", "exfil"},
        priority = 100,
        condition = {
            seq = {
                { type_name = "FILE_READ", filter = function(e)
                    local p = tostring(e.data and e.data.path or ""):lower()
                    return p:find("token") or p:find("cookie") or p:find(".env")
                        or p:find("credential") or p:find("wallet") or p:find("seed")
                end },
                { type_name = "STRING_ENCODE" },
                { type_name = "HTTP_POST" },
            },
            within = 20,
        },
    })

    engine:register({
        id       = "SENSITIVE_FILE_ACCESS",
        name     = "Sensitive File Access",
        description = "พยายามอ่านไฟล์ที่มีข้อมูลลับ",
        severity = 3,
        confidence = 0.75,
        mitre    = "T1005",
        tags     = {"collection", "credential"},
        priority = 80,
        condition = {
            has = { field = "data.sensitive" },
        },
    })

    engine:register({
        id       = "DISCORD_WEBHOOK_EXFIL",
        name     = "Discord Webhook Exfiltration",
        description = "ส่งข้อมูลออกผ่าน Discord Webhook",
        severity = 4,
        confidence = 0.95,
        mitre    = "T1567",
        tags     = {"exfil", "webhook"},
        priority = 95,
        condition = {
            regex = {
                field = "data.url",
                any   = {"discord.com/api/webhooks", "discordapp.com/api/webhooks"},
            },
        },
    })

    engine:register({
        id       = "TELEGRAM_BOT_EXFIL",
        name     = "Telegram Bot API Exfiltration",
        description = "ส่งข้อมูลผ่าน Telegram Bot",
        severity = 4,
        confidence = 0.92,
        mitre    = "T1567",
        tags     = {"exfil", "telegram"},
        priority = 95,
        condition = {
            regex = { field = "data.url", pattern = "api%.telegram%.org" },
        },
    })

    engine:register({
        id       = "PASTEBIN_RAW_FETCH",
        name     = "Pastebin Raw Fetch",
        description = "โหลดโค้ดจาก Pastebin (มักเป็น staging)",
        severity = 3,
        confidence = 0.70,
        mitre    = "T1071.001",
        tags     = {"staging", "download"},
        priority = 60,
        condition = {
            regex = { field = "data.url", pattern = "pastebin%.com/raw" },
        },
    })

    --========= DROPPER / LOADER ==========

    engine:register({
        id       = "REMOTE_CODE_LOADER",
        name     = "Remote Code Loader",
        description = "HttpGet ตามด้วย loadstring (classic loader)",
        severity = 4,
        confidence = 0.85,
        mitre    = "T1620",
        tags     = {"loader", "dropper"},
        priority = 90,
        condition = {
            seq = {
                { type_name = "HTTP_GET" },
                { type_name = "FUNCTION_CALL", filter = function(e)
                    local n = e.data and e.data.name or ""
                    return n == "loadstring" or n == "load" or n == "dofile"
                end },
            },
            within = 8,
        },
    })

    engine:register({
        id       = "MULTI_STAGE_LOADER",
        name     = "Multi-Stage Loader",
        description = "HttpGet มากกว่า 3 ครั้งใน 5 วินาที (daisy-chain)",
        severity = 3,
        confidence = 0.65,
        mitre    = "T1071.001",
        tags     = {"loader", "chain"},
        priority = 70,
        condition = {
            count = { event = "HTTP_GET", op = ">=", value = 3, within = 5 },
        },
    })

    engine:register({
        id       = "DYNAMIC_CODE_EVAL",
        name     = "Dynamic Code Evaluation",
        description = "เรียก loadstring/load กับ string จาก network",
        severity = 3,
        confidence = 0.80,
        mitre    = "T1059",
        tags     = {"eval", "dynamic"},
        priority = 75,
        condition = {
            all = {
                { type_name = "FUNCTION_CALL", filter = function(e)
                    return (e.data and e.data.name or "") == "loadstring"
                end },
                { any = {
                    { type_name = "HTTP_GET" },
                    { type_name = "FILE_READ" },
                } },
            },
        },
    })

    engine:register({
        id       = "BASE64_URL_LOADER",
        name     = "Base64-Encoded URL Loader",
        description = "ตรวจพบ base64 ของ 'https://' ในสตริงที่ decrypt",
        severity = 3,
        confidence = 0.85,
        mitre    = "T1140",
        tags     = {"obfuscation", "loader"},
        priority = 65,
        condition = {
            any = {
                { regex = { field = "data.value", pattern = "aHR0cHM6Ly" } },
                { regex = { field = "data.value", pattern = "aHR0cDovLw" } },
            },
        },
    })

    --========= OBFUSCATION ==========

    engine:register({
        id       = "HIGH_ENTROPY_STRING",
        name     = "High-Entropy String (Encrypted Payload)",
        description = "สตริงที่ entropy สูงกว่า 6.5 bits/char — น่าจะ encrypt",
        severity = 2,
        confidence = 0.60,
        mitre    = "T1027",
        tags     = {"obfuscation", "encryption"},
        priority = 40,
        condition = {
            entropy = { field = "data.value", op = ">", value = 6.5 },
        },
    })

    engine:register({
        id       = "BXOR_DECRYPT_BURST",
        name     = "XOR Decryption Burst",
        description = "bit32.bxor ถูกเรียกมากกว่า 500 ครั้ง/วินาที (Luraph-style)",
        severity = 2,
        confidence = 0.70,
        mitre    = "T1140",
        tags     = {"obfuscation", "luraph"},
        priority = 50,
        condition = {
            rate = { event = "STRING_DECRYPT", op = ">", value = 500, window = 1 },
        },
    })

    engine:register({
        id       = "STRING_CHAR_LOOP",
        name     = "string.char Decryption Loop",
        description = "string.char ถูกใช้ในลูปเพื่อสร้างสตริงทีละตัว",
        severity = 2,
        confidence = 0.65,
        mitre    = "T1140",
        tags     = {"obfuscation"},
        priority = 45,
        condition = {
            count = { event = "STRING_DECRYPT", op = ">=", value = 20, within = 2 },
        },
    })

    engine:register({
        id       = "ANTI_DEBUG_PROBE",
        name     = "Anti-Debug Probe",
        description = "ตรวจพบการใช้ debug.getinfo/sethook — อาจเป็นการป้องกันการวิเคราะห์",
        severity = 3,
        confidence = 0.75,
        mitre    = "T1622",
        tags     = {"anti-analysis"},
        priority = 65,
        condition = {
            all = {
                { type_name = "DEBUG_ACCESS", filter = function(e)
                    local n = e.data and e.data.name or ""
                    return n == "getinfo" or n == "sethook" or n == "gethook"
                end },
                { count = { event = "DEBUG_ACCESS", op = ">=", value = 5, within = 3 } },
            },
        },
    })

    engine:register({
        id       = "METATABLE_TAMPER",
        name     = "Metatable Tampering",
        description = "แก้ไข metatable ของ table สำคัญ (อาจเป็น hook)",
        severity = 2,
        confidence = 0.55,
        mitre    = "T1055",
        tags     = {"hook"},
        priority = 40,
        condition = {
            count = { event = "METATABLE_ACCESS", op = ">=", value = 10, within = 5 },
        },
    })

    --========= NETWORK / C2 ==========

    engine:register({
        id       = "DIRECT_IP_CONNECTION",
        name     = "Direct IP Connection",
        description = "เชื่อมต่อกับ IP ตรงๆ ไม่ผ่าน domain",
        severity = 3,
        confidence = 0.70,
        mitre    = "T1071",
        tags     = {"c2", "network"},
        priority = 60,
        condition = {
            regex = {
                field = "data.url",
                pattern = "https?://%d+%.%d+%.%d+%.%d+",
            },
        },
    })

    engine:register({
        id       = "SUSPICIOUS_TLD",
        name     = "Suspicious TLD",
        description = "เชื่อมต่อกับโดเมนใน TLD ที่มักใช้ใน malware",
        severity = 2,
        confidence = 0.55,
        mitre    = "T1583.001",
        tags     = {"network"},
        priority = 35,
        condition = {
            regex = {
                field = "data.url",
                any   = {"%.tk/", "%.ml/", "%.ga/", "%.cf/", "%.gq/", "%.top/", "%.xyz/"},
            },
        },
    })

    engine:register({
        id       = "HIGH_NETWORK_RATE",
        name     = "High Network Request Rate",
        description = "ยิง request มากกว่า 20 ครั้ง/วินาที (อาจเป็น DDoS/exfil)",
        severity = 3,
        confidence = 0.70,
        mitre    = "T1041",
        tags     = {"network", "exfil"},
        priority = 70,
        condition = {
            rate = { event = "NETWORK_REQUEST", op = ">", value = 20, window = 1 },
        },
    })

    engine:register({
        id       = "ENCRYPTED_C2_CHANNEL",
        name     = "Encrypted C2 Channel",
        description = "HTTP POST ตามด้วยการตอบกลับทันทีในเวลาสั้น (C2 handshake)",
        severity = 3,
        confidence = 0.65,
        mitre    = "T1071.001",
        tags     = {"c2"},
        priority = 60,
        condition = {
            seq = {
                { type_name = "HTTP_POST" },
                { type_name = "NETWORK_RESPONSE" },
            },
            within = 3,
        },
    })

    --========= RESOURCE HIJACKING ==========

    engine:register({
        id       = "CRYPTO_MINER_PATTERN",
        name     = "Crypto Miner Pattern",
        description = "เชื่อมต่อกับ pool ที่รู้จัก + ใช้ CPU สูง",
        severity = 3,
        confidence = 0.75,
        mitre    = "T1496",
        tags     = {"miner"},
        priority = 70,
        condition = {
            regex = {
                field = "data.url",
                any   = {"pool%.", "xmr%.", "monero", "nicehash", "minergate"},
            },
        },
    })

    --========= KEYLOGGER / INPUT CAPTURE ==========

    engine:register({
        id       = "INPUT_CAPTURE",
        name     = "Input Capture Pattern",
        description = "อ่าน UserInputService.InputBegan มากกว่าปกติ",
        severity = 4,
        confidence = 0.80,
        mitre    = "T1056.001",
        tags     = {"keylogger"},
        priority = 85,
        condition = {
            all = {
                { type_name = "FUNCTION_REDEFINE", filter = function(e)
                    local n = e.data and e.data.name or ""
                    return n:find("InputBegan") or n:find("InputChanged")
                end },
                { any = {
                    { type_name = "NETWORK_REQUEST" },
                    { type_name = "HTTP_POST" },
                } },
            },
        },
    })

    --========= GLOBAL POLLUTION ==========

    engine:register({
        id       = "GLOBAL_ENV_POLLUTION",
        name     = "Global Environment Pollution",
        description = "เขียน global มากกว่า 50 ครั้งใน 10 วินาที (อาจเป็น hook installation)",
        severity = 2,
        confidence = 0.60,
        mitre    = "T1055",
        tags     = {"hook", "pollution"},
        priority = 45,
        condition = {
            count = { event = "GLOBAL_WRITE", op = ">=", value = 50, within = 10 },
        },
    })

    engine:register({
        id       = "FUNCTION_REDEFINE_HOOK",
        name     = "Function Redefinition Hook",
        description = "เขียนทับฟังก์ชันที่สำคัญ เช่น HttpGet",
        severity = 3,
        confidence = 0.70,
        mitre    = "T1055",
        tags     = {"hook"},
        priority = 60,
        condition = {
            any = {
                { type_name = "FUNCTION_REDEFINE", filter = function(e)
                    local n = e.data and e.data.name or ""
                    return n:find("HttpGet") or n:find("HttpPost") or n:find("request")
                end },
                { type_name = "GLOBAL_WRITE", filter = function(e)
                    local k = e.data and e.data.key or ""
                    return k == "HttpGet" or k == "HttpPost" or k == "request"
                end },
            },
        },
    })

    --========= ENVIRONMENT ESCALATION ==========

    engine:register({
        id       = "THREAD_IDENTITY_ESCALATION",
        name     = "Thread Identity Escalation",
        description = "พยายามยกระดับ identity ของ thread (มักเป็นเทคนิคบายพาส)",
        severity = 4,
        confidence = 0.85,
        mitre    = "T1055",
        tags     = {"escalation", "bypass"},
        priority = 90,
        condition = {
            all = {
                { type_name = "THREAD_IDENTITY", filter = function(e)
                    return e.data and e.data.op == "set" and (e.data.id or 0) >= 6
                end },
            },
        },
    })

    engine:register({
        id       = "ENV_MANIPULATION",
        name     = "Environment Manipulation",
        description = "ใช้ setfenv/setfenv เพื่อแยก environment",
        severity = 3,
        confidence = 0.65,
        mitre    = "T1055",
        tags     = {"sandbox-escape"},
        priority = 55,
        condition = {
            count = { event = "ENV_ACCESS", op = ">=", value = 5, within = 5,
                filter = function(e) return e.data and e.data.op == "set" end },
        },
    })

    --========= COROUTINE ANOMALY ==========

    engine:register({
        id       = "COROUTINE_FLOOD",
        name     = "Coroutine Flood",
        description = "สร้าง coroutine มากกว่า 100 ตัว/วินาที (VM dispatch loop)",
        severity = 1,
        confidence = 0.40,
        mitre    = "T1059",
        tags     = {"vm", "obfuscation"},
        priority = 25,
        condition = {
            rate = { event = "COROUTINE_CREATE", op = ">", value = 100, window = 1 },
        },
    })

    engine:register({
        id       = "NESTED_COROUTINE",
        name     = "Nested Coroutine Chain",
        description = "coroutine ที่ resume coroutine อื่นในลึก (VM ซ้อน VM)",
        severity = 2,
        confidence = 0.55,
        mitre    = "T1027",
        tags     = {"vm", "luraph"},
        priority = 40,
        condition = {
            rate = { event = "COROUTINE_RESUME", op = ">", value = 500, window = 1 },
        },
    })

    --========= COMBINED HIGH-RISK ==========

    engine:register({
        id       = "ADVANCED_STEALER_CHAIN",
        name     = "Advanced Stealer Chain (Composite)",
        description = "รวม 4 สัญญาณ: อ่านไฟล์ลับ + decrypt + network + global write",
        severity = 4,
        confidence = 0.95,
        mitre    = "T1552",
        tags     = {"stealer", "composite"},
        priority = 110,
        condition = {
            all = {
                { count = { event = "FILE_READ", op = ">=", value = 3, within = 15,
                    filter = function(e)
                        return e.data and e.data.sensitive == true
                    end } },
                { count = { event = "STRING_DECRYPT", op = ">=", value = 50, within = 15 } },
                { any = {
                    { type_name = "HTTP_POST" },
                    { type_name = "NETWORK_REQUEST" },
                } },
                { count = { event = "GLOBAL_WRITE", op = ">=", value = 10, within = 15 } },
            },
        },
    })

    engine:register({
        id       = "RAT_FULL_CHAIN",
        name     = "RAT Full Chain",
        description = "Remote loader + hook + persistence signal",
        severity = 4,
        confidence = 0.90,
        mitre    = "T1071",
        tags     = {"rat", "composite"},
        priority = 105,
        condition = {
            all = {
                { type_name = "HTTP_GET" },
                { type_name = "FUNCTION_CALL", filter = function(e)
                    return (e.data and e.data.name or "") == "loadstring"
                end },
                { type_name = "GLOBAL_WRITE", filter = function(e)
                    local k = e.data and e.data.key or ""
                    return k:find("hook") or k:find("Hook") or k:find("__")
                end },
            },
        },
    })

end

--========== GLOBAL RISK ==========--
-- ฟังก์ชันคำนวณ risk รวมจากทุก alert ใน session
function Rules.computeSessionRisk(alerts)
    if not alerts or #alerts == 0 then return 0, {} end
    local breakdown = {}
    local product = 1.0
    for _, a in ipairs(alerts) do
        local s = a.score or (SEVERITY_WEIGHT[a.severity or 0] or 0.3)
        breakdown[a.rule or "?"] = (breakdown[a.rule or "?"] or 0) + s
        product = product * (1.0 - math.min(s, 0.99))
    end
    return 1.0 - product, breakdown
end

--========== EXPORT ==========--
Rules.Engine    = Engine
Rules.Evaluators = Evaluators
Rules.SEVERITY_WEIGHT = SEVERITY_WEIGHT
Rules.MITRE_WEIGHT = MITRE_WEIGHT
Rules._evalCondition = _evalCondition
Rules._entropy = _entropy

-- singleton
Rules._instance = nil

function Rules.get(edr)
    if not Rules._instance then
        Rules._instance = Rules.new(edr)
    end
    return Rules._instance
end

return Rules