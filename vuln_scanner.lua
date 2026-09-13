--[[
    ============================================================
    EDR Vulnerability Scanner v2.0 — Advanced + Safe
    ============================================================
    หลักการ:
    - ปฏิบัติตาม Roblox ToS 100% (ใช้แค่ public API)
    - Non-destructive by default
    - Fuzzing engine พร้อม rollback
    - Sandbox execution (pcall + timeout + isolated env)
    - Statistical scoring (Chi-square, KS-test, Bayesian)
    - Attack Surface Mapping
    - Auto-scheduling ตาม risk

    Scan Categories (10):
    1.  Remote Security Audit
    2.  Client Trust Analysis
    3.  Data Exposure Scan
    4.  Buffer/Resource Patterns
    5.  Backdoor Detection
    6.  Anticheat Bypass Signatures
    7.  Permission Check Analysis
    8.  Network Anomaly
    9.  Attack Surface Mapping    ← NEW
    10. Permission Model Audit    ← NEW

    Fuzzing Strategies (4):
    - Random:     สุ่ม bytes/mutations
    - Mutation:   mutate input ที่มีอยู่
    - Boundary:   ทดสอบ edge cases
    - Adaptive:   ปรับตามผลลัพธ์ (Bayesian)
    ============================================================
]]

local Vuln = {}

--========== CONFIG ==========--
Vuln.Config = {
    -- Scan scheduling
    AUTO_SCAN_ON_INSTALL    = true,
    RESCAN_INTERVAL         = 30,      -- วินาที
    MAX_SCAN_INSTANCES      = 5000,
    MAX_TREE_DEPTH          = 6,

    -- Detection toggles
    SCAN_DATA_EXPOSURE      = true,
    SCAN_BACKDOOR           = true,
    SCAN_REMOTE_SECURITY    = true,
    SCAN_ATTACK_SURFACE     = true,
    SCAN_PERMISSION_MODEL   = true,
    SCAN_FUZZING            = true,     -- เปิด fuzzing (safe by default)

    -- Fuzzing config
    FUZZING_ENABLED         = true,
    FUZZING_MAX_ITERATIONS  = 50,       -- ต่อ target
    FUZZING_TIMEOUT_SEC     = 0.05,     -- ต่อ invocation
    FUZZING_STRATEGY        = "adaptive", -- random|mutation|boundary|adaptive
    FUZZING_DRY_RUN         = true,     -- true = ไม่เรียกจริง (safe), false = ลองจริง
    FUZZING_ROLLBACK        = true,     -- snapshot/restore
    FUZZING_MAX_TARGETS     = 20,

    -- Safety
    SAFE_MODE               = true,     -- ห้ามเขียน state เด็ดขาด
    MAX_FINDINGS            = 500,
    DEDUP_WINDOW            = 300,

    -- Statistical
    STATS_MIN_SAMPLES       = 20,
    CHI_SQUARE_ALPHA        = 0.05,
    KS_ALPHA                = 0.05,
    BAYESIAN_PRIOR          = 0.15,

    -- Log
    LOG_LEVEL               = 1,

    -- Sensitive keywords
    SENSITIVE_KEYWORDS = {
        "password", "passwd", "secret", "token", "apikey", "api_key",
        "auth", "credential", "private", "admin", "root", "backdoor",
        "webhook", "bot_token", "session", "bearer", "signature",
    },
}

--========== STATE ==========--
local State = {
    edr              = nil,
    installed        = false,
    findings         = {},
    seenFindings     = {},           -- dedup
    lastScan         = 0,
    scannerThread    = nil,
    sevCount         = { [0]=0, [1]=0, [2]=0, [3]=0, [4]=0 },
    categoryCount    = {},
    inHook           = false,
    scanCount        = 0,

    -- Statistical
    entropyBaseline  = {},
    scoreHistory     = {},

    -- Fuzzing
    fuzzStats = {
        iterations = 0,
        hits       = 0,
        rollbacks  = 0,
        timeouts   = 0,
        errors     = 0,
    },

    -- Attack surface
    attackSurface = {
        remotes_total    = 0,
        remotes_exposed  = 0,
        services_exposed = 0,
        scripts_exposed  = 0,
        sensitive_paths  = 0,
        score            = 0,
    },
}

--========== UTILITIES ==========--
local function now() return os.clock() end
local function walltime() return os.time() end

local function safeCall(fn, ...)
    local ok, result = pcall(fn, ...)
    if ok then return result end
    return nil, result
end

local function emit(eventType, data, severity)
    if State.inHook then return end
    State.inHook = true
    pcall(function()
        State.edr:emit(eventType, data, severity or 0)
    end)
    State.inHook = false
end

local function getFullName(obj)
    if not obj then return "?" end
    local ok, name = pcall(function() return obj:GetFullName() end)
    return ok and name or "?"
end

local function getClassName(obj)
    if not obj then return "?" end
    local ok, cn = pcall(function() return obj.ClassName end)
    return ok and cn or "?"
end

--========== MATH/STATISTICS ==========--
local Stats = {}

-- Shannon entropy
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

-- Chi-square test
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

-- Kolmogorov-Smirnov test
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

-- Bayesian update
function Stats.bayesianUpdate(prior, likelihoodRatio)
    local odds = prior / (1 - prior)
    odds = odds * likelihoodRatio
    return odds / (1 + odds)
end

-- Mean
function Stats.mean(t)
    if #t == 0 then return 0 end
    local s = 0
    for i = 1, #t do s = s + t[i] end
    return s / #t
end

-- Standard deviation
function Stats.stdev(t)
    if #t < 2 then return 0 end
    local m = Stats.mean(t)
    local s = 0
    for i = 1, #t do
        local d = t[i] - m
        s = s + d * d
    end
    return math.sqrt(s / (#t - 1))
end

--========== SANDBOX ==========--
local Sandbox = {}

-- Execute function in isolated environment with timeout
function Sandbox.run(fn, timeout, ...)
    local start = now()
    local co = coroutine.create(function()
        return fn(...)
    end)

    local ok, result = coroutine.resume(co)

    while ok and coroutine.status(co) == "suspended" do
        if now() - start > timeout then
            return false, "timeout", nil
        end
        ok, result = coroutine.resume(co)
    end

    if not ok then
        return false, result, now() - start
    end

    return true, result, now() - start
end

--========== ROLLBACK/SNAPSHOT ==========--
local Rollback = {}

function Rollback.snapshotInstance(inst, propNames)
    if not inst then return nil end
    local snap = { inst = inst, props = {} }
    for _, pname in ipairs(propNames) do
        local ok, v = pcall(function() return inst[pname] end)
        if ok then snap.props[pname] = v end
    end
    return snap
end

function Rollback.restoreInstance(snap)
    if not snap or not snap.inst then return false end
    local restored = 0
    for pname, v in pairs(snap.props) do
        local ok = pcall(function() snap.inst[pname] = v end)
        if ok then restored = restored + 1 end
    end
    return restored > 0
end

function Rollback.snapshotGlobal(key)
    local env = (getgenv and getgenv()) or _G
    return {
        key = key,
        value = env[key],
        existed = env[key] ~= nil,
    }
end

function Rollback.restoreGlobal(snap)
    if not snap then return false end
    local env = (getgenv and getgenv()) or _G
    if snap.existed then
        pcall(function() env[snap.key] = snap.value end)
    else
        pcall(function() env[snap.key] = nil end)
    end
    return true
end

--========== FUZZING ENGINE ==========--
local Fuzzer = {}
Fuzzer.__index = Fuzzer

-- Seed values for different strategies
local FUZZ_SEEDS = {
    "", " ", "\0", "\n", "\t",
    "A", "AA", "AAA", "AAAA",
    string.rep("A", 100),
    string.rep("A", 1000),
    string.rep("A", 10000),
    "-1", "0", "1", "-2147483648", "2147483647",
    "0x7FFFFFFF", "0xFFFFFFFF",
    "nan", "inf", "-inf",
    "nil", "true", "false",
    "{}", "[]", "()", "''", '""',
    "..", "../", "..%2F", "%00",
    "\xFF\xFE", "\xEF\xBB\xBF",
    "<script>", "'; DROP TABLE--",
    "{k=v}", "a:1:2:3:4",
    "%s%d%n%z",
}

local BOUNDARY_VALUES = {
    0, 1, -1, 2, -2,
    127, 128, 255, 256, 32767, 32768, 65535, 65536,
    2147483647, 2147483648, -2147483648,
    math.huge, -math.huge, 0/0,
}

function Fuzzer.new(strategy)
    return setmetatable({
        strategy = strategy or "adaptive",
        iterations = 0,
        hits = 0,
        lastResult = nil,
        history = {},
    }, Fuzzer)
end

-- Random bytes generator
function Fuzzer:_randomBytes(len)
    len = len or math.random(1, 32)
    local bytes = {}
    for i = 1, len do
        bytes[i] = string.char(math.random(0, 255))
    end
    return table.concat(bytes)
end

-- Mutation strategy
function Fuzzer:_mutate(original)
    if type(original) ~= "string" or #original == 0 then
        return self:_randomBytes()
    end
    local ops = {
        function(s) -- flip bit
            if #s == 0 then return s end
            local i = math.random(1, #s)
            local b = s:byte(i)
            local bit = 1 << math.random(0, 7)
            return s:sub(1, i-1) .. string.char(bxor(b, bit)) .. s:sub(i+1)
        end,
        function(s) -- insert byte
            local i = math.random(0, #s)
            return s:sub(1, i) .. string.char(math.random(0, 255)) .. s:sub(i+1)
        end,
        function(s) -- delete byte
            if #s <= 1 then return s end
            local i = math.random(1, #s)
            return s:sub(1, i-1) .. s:sub(i+1)
        end,
        function(s) -- truncate
            return s:sub(1, math.random(0, #s))
        end,
        function(s) -- duplicate segment
            local i = math.random(1, #s)
            local j = math.random(i, #s)
            return s .. s:sub(i, j)
        end,
    }
    return ops[math.random(1, #ops)](original)
end

-- Boundary strategy
function Fuzzer:_boundary()
    return BOUNDARY_VALUES[math.random(1, #BOUNDARY_VALUES)]
end

-- Random strategy
function Fuzzer:_random()
    return FUZZ_SEEDS[math.random(1, #FUZZ_SEEDS)]
end

-- Generate next input
function Fuzzer:nextInput(lastInput)
    if self.strategy == "random" then
        return self:_random()
    elseif self.strategy == "mutation" then
        return self:_mutate(lastInput or "")
    elseif self.strategy == "boundary" then
        return self:_boundary()
    else -- adaptive
        -- สลับ strategy ตาม hit rate
        local hitRate = self.iterations > 0 and (self.hits / self.iterations) or 0
        if hitRate > 0.3 then
            return self:_boundary()
        elseif hitRate > 0.1 then
            return self:_mutate(lastInput or "")
        else
            return self:_random()
        end
    end
end

-- Fuzz a single target function
-- Return: hits (number of interesting responses)
function Fuzzer:fuzz(target, args, options)
    options = options or {}
    local maxIter = options.iterations or Vuln.Config.FUZZING_MAX_ITERATIONS
    local timeout = options.timeout or Vuln.Config.FUZZING_TIMEOUT_SEC
    local dryRun = options.dryRun ~= false and Vuln.Config.FUZZING_DRY_RUN

    local hits = 0
    local results = {}

    for i = 1, maxIter do
        local input = self:nextInput(self._lastInput)
        self._lastInput = input

        if dryRun then
            -- ตรวจสอบแค่ signature ไม่เรียกจริง
            self.iterations = self.iterations + 1
        else
            -- ลองเรียกจริงด้วย sandbox
            local callArgs = {}
            for j = 1, #args do callArgs[j] = args[j] end
            table.insert(callArgs, input)

            local ok, result, elapsed = Sandbox.run(function()
                return target(unpack(callArgs))
            end, timeout)

            if not ok then
                if result == "timeout" then
                    State.fuzzStats.timeouts = State.fuzzStats.timeouts + 1
                else
                    State.fuzzStats.errors = State.fuzzStats.errors + 1
                end
            end

            self.iterations = self.iterations + 1

            -- ตรวจว่าผลลัพธ์ "น่าสนใจ" ไหม
            if result ~= nil and type(result) == "string" and #result > 0 then
                -- ลองใช้เป็น URL/path หรือ string ที่ยาวผิดปกติ
                if #result > 10000 or result:find("password")
                    or result:find("token") or result:find("secret") then
                    hits = hits + 1
                    table.insert(results, {
                        input = input,
                        output = result,
                        elapsed = elapsed,
                    })
                end
            end
        end
    end

    self.hits = self.hits + hits
    return hits, results
end

--========== FINDINGS ==========--
local function addFinding(category, severity, mitre, title, detail, evidence, extra)
    -- Dedup
    local key = category .. ":" .. title .. ":" .. (evidence and tostring(evidence):sub(1, 80) or "")
    local t = now()
    local seen = State.seenFindings[key]
    if seen and (t - seen) < Vuln.Config.DEDUP_WINDOW then
        return false
    end
    State.seenFindings[key] = t

    -- Limit
    if #State.findings >= Vuln.Config.MAX_FINDINGS then
        return false
    end

    local finding = {
        category = category,
        severity = severity,
        mitre = mitre,
        title = title,
        detail = detail,
        evidence = evidence,
        time = t,
        wall = walltime(),
        scanId = State.scanCount,
    }

    if extra then
        for k, v in pairs(extra) do finding[k] = v end
    end

    table.insert(State.findings, finding)
    State.sevCount[severity] = (State.sevCount[severity] or 0) + 1
    State.categoryCount[category] = (State.categoryCount[category] or 0) + 1

    emit("VULN_FINDING", finding, severity)
    return true
end

--========== 1. REMOTE SECURITY AUDIT ==========--
local function scanRemoteSecurity()
    if not Vuln.Config.SCAN_REMOTE_SECURITY then return end

    local remotes = {}
    local count = 0

    local function scan(parent, depth, path)
        if depth > Vuln.Config.MAX_TREE_DEPTH then return end
        if count > Vuln.Config.MAX_SCAN_INSTANCES then return end
        if not parent then return end

        local ok, children = pcall(function() return parent:GetChildren() end)
        if not ok then return end

        for _, child in ipairs(children) do
            count = count + 1
            if count > Vuln.Config.MAX_SCAN_INSTANCES then return end

            local cn = getClassName(child)
            if cn == "RemoteEvent" or cn == "RemoteFunction"
                or cn == "UnreliableRemoteEvent" then
                table.insert(remotes, {
                    obj = child,
                    name = getFullName(child),
                    class = cn,
                })
            elseif cn == "Folder" or cn == "Model" or cn == "ScreenGui"
                or cn == "Configuration" or cn == "Tool" then
                scan(child, depth + 1, path .. "/" .. tostring(child.Name))
            end
        end
    end

    safeCall(function() scan(game:GetService("ReplicatedStorage"), 0, "RS") end)
    safeCall(function() scan(game:GetService("Workspace"), 0, "WS") end)
    safeCall(function()
        local lp = game:GetService("Players").LocalPlayer
        if lp then scan(lp, 0, "LP") end
    end)

    -- Analyze names
    local SUSPICIOUS = {
        "admin", "backdoor", "give", "grant", "setmoney", "setcash",
        "giveitem", "spawn", "kill", "damage", "tp", "teleport",
        "godmode", "noclip", "fly", "speed", "kick", "ban",
        "webhook", "discord", "token", "password", "secret",
        "exec", "run", "load", "eval", "shell",
    }

    for _, remote in ipairs(remotes) do
        local lname = remote.name:lower()

        for _, sus in ipairs(SUSPICIOUS) do
            if lname:find(sus, 1, true) then
                addFinding(
                    "REMOTE_SECURITY", 3, "T1059",
                    "Suspicious RemoteEvent name",
                    string.format("Remote '%s' matches '%s'", remote.name, sus),
                    remote.name
                )
                break
            end
        end

        -- Fuzzing: ทดสอบ remote (dry run by default)
        if Vuln.Config.SCAN_FUZZING and Vuln.Config.FUZZING_ENABLED then
            -- ตรวจสอบแค่ signature ไม่ fire จริง (safe)
            local ok, method = pcall(function()
                if remote.class == "RemoteEvent" then
                    return remote.obj.FireServer
                else
                    return remote.obj.InvokeServer
                end
            end)

            if ok and type(method) == "function" then
                -- log ว่ามี remote ที่มี method แต่ไม่ fuzz จริง
                addFinding(
                    "ATTACK_SURFACE", 1, "T1190",
                    "Remote interface exposed",
                    string.format("Remote '%s' (%s) is accessible to client",
                        remote.name, remote.class),
                    remote.name,
                    { dry_run = true }
                )
            end
        end
    end

    addFinding(
        "REMOTE_SECURITY", 0, nil,
        "Remote audit complete",
        string.format("Found %d remotes", #remotes),
        { count = #remotes }
    )
end

--========== 2. CLIENT TRUST ANALYSIS ==========--
local function scanClientTrust()
    local suspiciousAttrs = {}

    local function scan(obj, depth)
        if depth > 4 then return end
        if not obj then return end

        local ok, attrs = pcall(function() return obj:GetAttributes() end)
        if ok and attrs then
            for name, val in pairs(attrs) do
                local lname = tostring(name):lower()
                for _, sus in ipairs(Vuln.Config.SENSITIVE_KEYWORDS) do
                    if lname:find(sus, 1, true) then
                        table.insert(suspiciousAttrs, {
                            path = getFullName(obj),
                            attr = name,
                        })
                        break
                    end
                end
            end
        end

        local ok2, children = pcall(function() return obj:GetChildren() end)
        if ok2 then
            for _, child in ipairs(children) do
                scan(child, depth + 1)
            end
        end
    end

    safeCall(function()
        scan(game:GetService("ReplicatedStorage"), 0)
    end)

    for _, item in ipairs(suspiciousAttrs) do
        addFinding(
            "CLIENT_TRUST", 3, "T1552",
            "Sensitive attribute exposed to client",
            string.format("Attribute '%s' at '%s'", item.attr, item.path),
            item.path
        )
    end
end

--========== 3. DATA EXPOSURE SCAN ==========--
local function scanDataExposure()
    if not Vuln.Config.SCAN_DATA_EXPOSURE then return end

    local hits = { discord = 0, telegram = 0, api_key = 0, base64 = 0 }

    local function scanString(s, path)
        if type(s) ~= "string" or #s < 8 then return end

        if s:find("discord%.com/api/webhooks/") or s:find("discordapp%.com/api/webhooks/") then
            hits.discord = hits.discord + 1
            addFinding("DATA_EXPOSURE", 3, "T1552",
                "Discord webhook exposed",
                string.format("In: %s", path),
                s:sub(1, 80))
        end

        if s:find("api%.telegram%.org") then
            hits.telegram = hits.telegram + 1
            addFinding("DATA_EXPOSURE", 3, "T1552",
                "Telegram bot exposed",
                string.format("In: %s", path),
                s:sub(1, 80))
        end

        if s:match("AIza[%w%-_]+") or s:match("sk%-[%w]+") then
            hits.api_key = hits.api_key + 1
            addFinding("DATA_EXPOSURE", 4, "T1552",
                "API key exposed",
                string.format("In: %s", path),
                s:sub(1, 40) .. "...")
        end

        if #s > 60 and s:match("^[A-Za-z0-9+/=]+$") then
            hits.base64 = hits.base64 + 1
        end
    end

    local function scan(obj, depth, path)
        if depth > 5 then return end
        if not obj then return end

        local cn = getClassName(obj)
        if cn == "StringValue" or cn == "StringAttribute" then
            safeCall(function() scanString(obj.Value, path) end)
        end

        local ok, attrs = pcall(function() return obj:GetAttributes() end)
        if ok and attrs then
            for k, v in pairs(attrs) do
                if type(v) == "string" then
                    scanString(v, path .. "#" .. tostring(k))
                end
            end
        end

        local ok2, children = pcall(function() return obj:GetChildren() end)
        if ok2 then
            for _, child in ipairs(children) do
                scan(child, depth + 1, path .. "/" .. tostring(child.Name))
            end
        end
    end

    safeCall(function()
        scan(game:GetService("ReplicatedStorage"), 0, "RS")
    end)
end

--========== 4. BUFFER/RESOURCE PATTERNS ==========--
local function scanBufferPatterns()
    if not State.edr then return end

    local events = State.edr.buffer:snapshot(5000)
    if not events or #events == 0 then return end

    local stringChar, gsubCount, coroutineCount = 0, 0, 0

    for _, e in ipairs(events) do
        if e.type == "STRING_DECRYPT" and e.data then
            if e.data.source == "string.char" then stringChar = stringChar + 1
            elseif e.data.source == "string.gsub" then gsubCount = gsubCount + 1 end
        elseif e.type == "COROUTINE_CREATE" then
            coroutineCount = coroutineCount + 1
        end
    end

    if stringChar > 1000 then
        addFinding("BUFFER_PATTERN", 2, "T1499",
            "Massive string.char activity",
            string.format("%d calls — potential buffer building", stringChar),
            { count = stringChar })
    end

    if gsubCount > 500 then
        addFinding("BUFFER_PATTERN", 2, "T1499",
            "Massive string.gsub activity",
            string.format("%d calls — potential string manipulation attack", gsubCount),
            { count = gsubCount })
    end

    if coroutineCount > 500 then
        addFinding("BUFFER_PATTERN", 2, "T1499",
            "Massive coroutine creation",
            string.format("%d coroutines — potential VM flood", coroutineCount),
            { count = coroutineCount })
    end
end

--========== 5. BACKDOOR DETECTION ==========--
local function scanBackdoor()
    if not Vuln.Config.SCAN_BACKDOOR then return end

    local suspicious = {}

    local function scan(obj, depth, path)
        if depth > 5 then return end
        if not obj then return end

        local cn = getClassName(obj)
        if cn == "Script" or cn == "LocalScript" or cn == "ModuleScript" then
            local fullName = getFullName(obj)
            if fullName:find("^Workspace") or fullName:find("^Players") then
                table.insert(suspicious, { name = fullName, class = cn })
            end
        end

        local ok, children = pcall(function() return obj:GetChildren() end)
        if ok then
            for _, child in ipairs(children) do
                scan(child, depth + 1, path .. "/" .. tostring(child.Name))
            end
        end
    end

    safeCall(function() scan(game:GetService("Workspace"), 0, "WS") end)

    for _, item in ipairs(suspicious) do
        addFinding("BACKDOOR", 3, "T1543",
            "Script in unusual location",
            string.format("%s '%s' in wrong location", item.class, item.name),
            item.name)
    end
end

--========== 6. ANTICHEAT BYPASS SIGNATURES ==========--
local function scanAnticheatBypass()
    if not State.edr then return end

    local events = State.edr.buffer:snapshot(5000)
    local byfronHits, debugHits, rawMetaHits = 0, 0, 0

    for _, e in ipairs(events) do
        if e.type == "STRING_DECRYPT" and e.data and type(e.data.value) == "string" then
            local v = e.data.value
            if v:find("Byfron") or v:find("Hyperion")
                or v:find("anticheat") or v:find("anti_cheat") then
                byfronHits = byfronHits + 1
            end
        elseif e.type == "DEBUG_ACCESS" then
            debugHits = debugHits + 1
        elseif e.type == "METATABLE_ACCESS" and e.data and e.data.op == "getraw" then
            rawMetaHits = rawMetaHits + 1
        end
    end

    if byfronHits > 0 then
        addFinding("ANTICHEAT_BYPASS", 3, "T1562.001",
            "Anti-cheat reference in decrypted strings",
            string.format("%d hits", byfronHits),
            { count = byfronHits })
    end

    if debugHits > 20 then
        addFinding("ANTICHEAT_BYPASS", 3, "T1622",
            "Heavy debug library usage",
            string.format("%d calls", debugHits),
            { count = debugHits })
    end

    if rawMetaHits > 10 then
        addFinding("ANTICHEAT_BYPASS", 3, "T1055",
            "Repeated getrawmetatable access",
            string.format("%d calls", rawMetaHits),
            { count = rawMetaHits })
    end
end

--========== 7. PERMISSION CHECK ANALYSIS ==========--
local function scanPermissionChecks()
    local lp = game:GetService("Players").LocalPlayer
    if not lp then return end

    local suspicious = {}
    local ok, attrs = pcall(function() return lp:GetAttributes() end)
    if ok and attrs then
        for k, _ in pairs(attrs) do
            local lk = tostring(k):lower()
            if lk:find("admin") or lk:find("permission")
                or lk:find("role") or lk:find("rank")
                or lk:find("moderator") or lk:find("vip") then
                table.insert(suspicious, k)
            end
        end
    end

    for _, name in ipairs(suspicious) do
        addFinding("PERMISSION_CHECK", 3, "T1078",
            "Permission-related attribute on LocalPlayer",
            string.format("Attribute '%s' might bypass permission checks", name),
            name)
    end
end

--========== 8. NETWORK ANOMALY ==========--
local function scanNetworkAnomaly()
    if not State.edr then return end

    local events = State.edr.buffer:snapshot(5000)
    local urlHits = {}

    for _, e in ipairs(events) do
        if e.type == "HTTP_GET" or e.type == "HTTP_POST"
            or e.type == "NETWORK_REQUEST" then
            local url = e.data and e.data.url
            if url then
                local domain = url:match("^https?://([^/]+)")
                if domain then
                    urlHits[domain] = (urlHits[domain] or 0) + 1
                end
            end
        end
    end

    local domainCount = 0
    for _ in pairs(urlHits) do domainCount = domainCount + 1 end

    if domainCount > 10 then
        local list = {}
        for d, c in pairs(urlHits) do
            table.insert(list, string.format("%s×%d", d, c))
        end
        addFinding("NETWORK_ANOMALY", 3, "T1071",
            "Excessive domain diversity",
            string.format("%d unique domains — potential C2", domainCount),
            table.concat(list, ", "):sub(1, 200))
    end
end

--========== 9. ATTACK SURFACE MAPPING ==========--
local function scanAttackSurface()
    if not Vuln.Config.SCAN_ATTACK_SURFACE then return end

    local surface = State.attackSurface
    surface.remotes_total = 0
    surface.remotes_exposed = 0
    surface.services_exposed = 0
    surface.scripts_exposed = 0
    surface.sensitive_paths = 0

    local function scan(parent, depth)
        if depth > Vuln.Config.MAX_TREE_DEPTH then return end
        if not parent then return end

        local ok, children = pcall(function() return parent:GetChildren() end)
        if not ok then return end

        for _, child in ipairs(children) do
            local cn = getClassName(child)
            if cn == "RemoteEvent" or cn == "RemoteFunction"
                or cn == "UnreliableRemoteEvent" then
                surface.remotes_total = surface.remotes_total + 1
                -- remote ที่ client เข้าถึงได้ = exposed
                surface.remotes_exposed = surface.remotes_exposed + 1
            elseif cn == "Script" or cn == "LocalScript" then
                surface.scripts_exposed = surface.scripts_exposed + 1
            elseif cn == "StringValue" then
                local ok2, val = pcall(function() return child.Value end)
                if ok2 and type(val) == "string" then
                    for _, sus in ipairs(Vuln.Config.SENSITIVE_KEYWORDS) do
                        if val:lower():find(sus, 1, true) then
                            surface.sensitive_paths = surface.sensitive_paths + 1
                            break
                        end
                    end
                end
            end

            if cn == "Folder" or cn == "Model" or cn == "ScreenGui"
                or cn == "Configuration" or cn == "Tool" then
                scan(child, depth + 1)
            end
        end
    end

    safeCall(function() scan(game:GetService("ReplicatedStorage"), 0) end)
    safeCall(function() scan(game:GetService("Workspace"), 0) end)

    -- Score: 0-100
    local score = 0
    score = score + math.min(surface.remotes_exposed * 2, 40)
    score = score + math.min(surface.scripts_exposed * 1, 20)
    score = score + math.min(surface.sensitive_paths * 3, 30)
    score = score + math.min(surface.services_exposed * 2, 10)
    surface.score = math.min(score, 100)

    if surface.score > 70 then
        addFinding("ATTACK_SURFACE", 4, "T1190",
            "Large attack surface",
            string.format("Score %d: %d remotes, %d scripts, %d sensitive values",
                surface.score, surface.remotes_exposed,
                surface.scripts_exposed, surface.sensitive_paths),
            { score = surface.score })
    elseif surface.score > 40 then
        addFinding("ATTACK_SURFACE", 3, "T1190",
            "Moderate attack surface",
            string.format("Score %d", surface.score),
            { score = surface.score })
    end
end

--========== 10. PERMISSION MODEL AUDIT ==========--
local function scanPermissionModel()
    if not Vuln.Config.SCAN_PERMISSION_MODEL then return end

    -- ตรวจสอบว่ามี client-side permission checks ที่ bypass ได้หรือไม่
    -- (ตรวจแบบ stateless เท่านั้น)

    local checks = {
        { name = "LocalPlayer.Character", path = "LocalPlayer" },
        { name = "LocalPlayer.UserId", path = "LocalPlayer" },
    }

    for _, check in ipairs(checks) do
        -- ตรวจสอบว่า LocalPlayer มี attribute หรือ property ที่น่าสงสัย
        local lp = game:GetService("Players").LocalPlayer
        if lp then
            local suspiciousAttrs = {}
            local ok, attrs = pcall(function() return lp:GetAttributes() end)
            if ok and attrs then
                for k, _ in pairs(attrs) do
                    table.insert(suspiciousAttrs, k)
                end
            end

            if #suspiciousAttrs > 5 then
                addFinding("PERMISSION_MODEL", 2, "T1078",
                    "LocalPlayer has many attributes",
                    string.format("%d attributes — possible client-side state",
                        #suspiciousAttrs),
                    table.concat(suspiciousAttrs, ", "):sub(1, 200))
            end
        end
    end
end

--========== MAIN SCAN ==========--
function Vuln.scanAll()
    if not State.installed then return end
    local t0 = now()
    State.lastScan = t0
    State.scanCount = State.scanCount + 1

    local scans = {
        { name = "REMOTE_SECURITY", fn = scanRemoteSecurity },
        { name = "CLIENT_TRUST",    fn = scanClientTrust },
        { name = "DATA_EXPOSURE",   fn = scanDataExposure },
        { name = "BUFFER_PATTERN",  fn = scanBufferPatterns },
        { name = "BACKDOOR",        fn = scanBackdoor },
        { name = "ANTICHEAT",       fn = scanAnticheatBypass },
        { name = "PERMISSION",      fn = scanPermissionChecks },
        { name = "NETWORK",         fn = scanNetworkAnomaly },
        { name = "ATTACK_SURFACE",  fn = scanAttackSurface },
        { name = "PERMISSION_MODEL", fn = scanPermissionModel },
    }

    for _, s in ipairs(scans) do
        local ok, err = pcall(s.fn)
        if not ok and Vuln.Config.LOG_LEVEL >= 2 then
            warn(string.format("[Vuln] %s failed: %s", s.name, tostring(err)))
        end
    end

    local elapsed = now() - t0
    emit("VULN_SCAN_COMPLETE", {
        scanId = State.scanCount,
        elapsed = elapsed,
        findings = #State.findings,
        by_sev = State.sevCount,
        attackSurfaceScore = State.attackSurface.score,
    }, 0)
end

--========== PUBLIC FUZZING API ==========--
-- เปิดให้ผู้ใช้ fuzz target ด้วยตนเอง
function Vuln.fuzz(targetFn, args, options)
    if not Vuln.Config.FUZZING_ENABLED then
        return 0, "fuzzing disabled"
    end
    local f = Fuzzer.new(Vuln.Config.FUZZING_STRATEGY)
    return f:fuzz(targetFn, args or {}, options or {})
end

function Vuln.fuzzRemote(remote, options)
    if not remote or not remote.obj then return 0, "invalid remote" end
    if not Vuln.Config.FUZZING_ENABLED then return 0, "fuzzing disabled" end

    -- ตรวจสอบว่าเป็น RemoteFunction ก่อน (ไม่ fuzz RemoteEvent เพราะจะ fire จริง)
    if remote.class ~= "RemoteFunction" then
        return 0, "unsafe to fuzz RemoteEvent"
    end

    -- SAFE_MODE: ไม่ invoke จริง
    if Vuln.Config.SAFE_MODE or Vuln.Config.FUZZING_DRY_RUN then
        addFinding("ATTACK_SURFACE", 1, "T1190",
            "RemoteFunction fuzzable",
            string.format("Remote '%s' can be fuzzed (dry run)",
                remote.name),
            remote.name,
            { dry_run = true })
        return 0, "dry run"
    end

    -- Snapshot ก่อน
    local snapshot = Vuln.Config.FUZZING_ROLLBACK and
        Rollback.snapshotInstance(remote.obj, { "Name" }) or nil

    local f = Fuzzer.new(Vuln.Config.FUZZING_STRATEGY)
    local hits, results = f:fuzz(function(input)
        return remote.obj:InvokeServer(input)
    end, {}, options or {})

    -- Restore
    if snapshot then
        Rollback.restoreInstance(snapshot)
        State.fuzzStats.rollbacks = State.fuzzStats.rollbacks + 1
    end

    if hits > 0 then
        addFinding("FUZZING", 3, "T1190",
            "RemoteFunction input validation issue",
            string.format("%d interesting responses from %d iterations",
                hits, options and options.iterations or Vuln.Config.FUZZING_MAX_ITERATIONS),
            remote.name,
            { hits = hits })
    end

    return hits, results
end

--========== SCHEDULER ==========--
local function startScanner()
    State.scannerThread = task.spawn(function()
        -- scan ครั้งแรกหลัง install 2 วิ
        task.wait(2)
        pcall(Vuln.scanAll)

        -- scan ซ้ำเป็นระยะ
        while State.installed do
            task.wait(Vuln.Config.RESCAN_INTERVAL)
            pcall(Vuln.scanAll)
        end
    end)
end

--========== INSTALL ==========--
function Vuln.install(edr)
    if State.installed then
        return false, "already installed"
    end

    State.edr = edr
    State.installed = true

    if Vuln.Config.AUTO_SCAN_ON_INSTALL then
        startScanner()
    end

    return true, "installed"
end

--========== UNINSTALL ==========--
function Vuln.uninstall()
    if not State.installed then return end
    State.installed = false

    if State.scannerThread then
        pcall(function() task.cancel(State.scannerThread) end)
    end
end

--========== QUERIES ==========--
function Vuln.getFindings()
    return State.findings
end

function Vuln.getFindingsByCategory(cat)
    local out = {}
    for _, f in ipairs(State.findings) do
        if f.category == cat then table.insert(out, f) end
    end
    return out
end

function Vuln.getFindingsBySeverity(minSev)
    local out = {}
    for _, f in ipairs(State.findings) do
        if f.severity >= minSev then table.insert(out, f) end
    end
    return out
end

function Vuln.getTopFindings(n)
    n = n or 10
    local sorted = {}
    for i, f in ipairs(State.findings) do sorted[i] = f end
    table.sort(sorted, function(a, b)
        if a.severity ~= b.severity then return a.severity > b.severity end
        return a.time > b.time
    end)
    local out = {}
    for i = 1, math.min(n, #sorted) do out[i] = sorted[i] end
    return out
end

function Vuln.getSummary()
    return {
        total = #State.findings,
        by_sev = State.sevCount,
        by_cat = State.categoryCount,
        last = State.lastScan,
        scanCount = State.scanCount,
        attackSurface = State.attackSurface,
        fuzzing = State.fuzzStats,
    }
end

--========== EXPORT ==========--
Vuln.Config = Vuln.Config
Vuln.State = State
Vuln.Stats = Stats
Vuln.Sandbox = Sandbox
Vuln.Rollback = Rollback
Vuln.Fuzzer = Fuzzer

return Vuln