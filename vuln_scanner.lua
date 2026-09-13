--[[
    ============================================================
    EDR Vulnerability Scanner v1.0
    ============================================================
    หลักการ:
    - สแกนช่องโหว่ระดับวิกฤตใน client-side ของเกม
    - ตรวจสอบ buffer/resource patterns (ไม่แตะหน่วยความจำ)
    - ตรวจสอบ remote security, client trust, data exposure
    - ตรวจสอบ backdoor patterns, anticheat bypass signatures
    - ใช้แค่ public API — ปฏิบัติตาม Roblox ToS 100%

    การทำงานร่วมกับ:
    - edr_core.lua : emit findings
    - roblox_api.lua : ใช้ข้อมูลที่ monitor เก็บไว้
    - rules.lua : rule เหล่านี้ทำงานคู่ขนาน
    - report.lua : findings จะถูกรวมใน report

    วิธีใช้:
        local Vuln = require("vuln_scanner")
        Vuln.install(edr)
        Vuln.scanAll()  -- scan ครั้งแรก
        -- ...
        Vuln.uninstall()

    หมวดหมู่ที่สแกน:
    1. Remote Security Audit       — remotes ไม่มี validation
    2. Client Trust Analysis       — เกมเชื่อ client มากเกินไป
    3. Data Exposure Scan          — ข้อมูลละเอียดอ่อนใน ReplicatedStorage
    4. Buffer/Resource Patterns    — string concat, table grows, recursion
    5. Backdoor Detection          — scripts ที่น่าสงสัยใน workspace
    6. Anticheat Bypass Signatures — pattern ของ bypass
    7. Permission Check Analysis   — ตรวจ missing checks
    8. Network Anomaly             — packet size / rate patterns
    ============================================================
]]

local Vuln = {}

--========== CONFIG ==========--
Vuln.Config = {
    -- สแกนครั้งแรกหลัง install
    AUTO_SCAN_ON_INSTALL    = true,
    -- สแกนซ้ำทุกกี่วินาที
    RESCAN_INTERVAL         = 30,
    -- จำนวน instance สูงสุดที่จะสแกนใน round เดียว
    MAX_SCAN_INSTANCES      = 5000,
    -- ความลึกสูงสุดในการ walk tree
    MAX_TREE_DEPTH          = 6,
    -- เปิดตรวจ data exposure
    SCAN_DATA_EXPOSURE      = true,
    -- เปิดตรวจ backdoor
    SCAN_BACKDOOR           = true,
    -- เปิดตรวจ remote security
    SCAN_REMOTE_SECURITY    = true,
    -- log level
    LOG_LEVEL               = 1,
    -- ชื่อ property/attribute ที่ถือว่า sensitive
    SENSITIVE_KEYWORDS      = {
        "password", "passwd", "secret", "token", "apikey", "api_key",
        "auth", "credential", "private", "admin", "root", "backdoor",
        "webhook", "bot_token", "session",
    },
}

--========== STATE ==========--
local State = {
    edr              = nil,
    installed        = false,
    findings         = {},          -- list ของ finding
    lastScan         = 0,
    scannerThread    = nil,
    sevCount         = { [0]=0, [1]=0, [2]=0, [3]=0, [4]=0 },
    categoryCount    = {},
    inHook           = false,
    seenFindings     = {},          -- dedup
}

--========== UTILITIES ===========--
local function now() return os.clock() end

local function emit(eventType, data, severity)
    if State.inHook then return end
    State.inHook = true
    pcall(function()
        State.edr:emit(eventType, data, severity or 0)
    end)
    State.inHook = false
end

local function safeCall(fn, ...)
    local ok, result = pcall(fn, ...)
    if ok then return result end
    return nil
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

--========== FINDING ==========--
local function addFinding(category, severity, mitre, title, detail, evidence)
    -- dedup
    local key = category .. ":" .. title .. ":" .. (evidence and tostring(evidence):sub(1, 80) or "")
    if State.seenFindings[key] then return false end
    State.seenFindings[key] = now()

    local finding = {
        category  = category,
        severity  = severity,
        mitre     = mitre,
        title     = title,
        detail    = detail,
        evidence  = evidence,
        time      = now(),
    }
    table.insert(State.findings, finding)
    State.sevCount[severity] = (State.sevCount[severity] or 0) + 1
    State.categoryCount[category] = (State.categoryCount[category] or 0) + 1

    emit("VULN_FINDING", finding, severity)
    return true
end

--========== 1. REMOTE SECURITY AUDIT ==========--
-- ตรวจ RemoteEvent/RemoteFunction ที่เข้าถึงได้จาก client
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
                    obj  = child,
                    name = getFullName(child),
                    class = cn,
                })
            elseif cn == "Folder" or cn == "Model" or cn == "ScreenGui"
                or cn == "Configuration" or cn == "Tool" then
                scan(child, depth + 1, path .. "/" .. tostring(child.Name))
            end
        end
    end

    -- สแกน ReplicatedStorage + Workspace + Players.LocalPlayer
    safeCall(function()
        scan(game:GetService("ReplicatedStorage"), 0, "ReplicatedStorage")
    end)
    safeCall(function()
        scan(game:GetService("Workspace"), 0, "Workspace")
    end)
    safeCall(function()
        local lp = game:GetService("Players").LocalPlayer
        if lp then scan(lp, 0, "LocalPlayer") end
    end)

    -- วิเคราะห์ชื่อ remotes ที่น่าสงสัย
    local SUSPICIOUS_NAMES = {
        "admin", "backdoor", "give", "grant", "setmoney", "setcash",
        "giveitem", "spawn", "kill", "damage", "tp", "teleport",
        "godmode", "noclip", "fly", "speed", "kick", "ban",
        "webhook", "discord", "token", "password", "secret",
    }

    for _, remote in ipairs(remotes) do
        local lname = remote.name:lower()

        for _, sus in ipairs(SUSPICIOUS_NAMES) do
            if lname:find(sus, 1, true) then
                addFinding(
                    "REMOTE_SECURITY",
                    3,
                    "T1059",
                    "Suspicious RemoteEvent name",
                    string.format("Remote '%s' มีชื่อที่บ่งบอกถึงสิทธิ์ระดับสูง", remote.name),
                    remote.name
                )
                break
            end
        end
    end

    addFinding(
        "REMOTE_SECURITY",
        0,
        nil,
        "Remote audit complete",
        string.format("พบ remotes ทั้งหมด %d ตัว", #remotes),
        { count = #remotes }
    )
end

--========== 2. CLIENT TRUST ANALYSIS ==========--
-- ตรวจ instance ที่มี attribute/property ที่ client เขียนได้
local function scanClientTrust()
    local suspiciousAttrs = {}

    local function scan(obj, depth)
        if depth > 4 then return end
        if not obj then return end

        -- ตรวจ attribute
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

        -- walk children
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
            "CLIENT_TRUST",
            3,
            "T1552",
            "Sensitive attribute exposed to client",
            string.format("Attribute '%s' ที่ '%s' ดูเหมือนเก็บข้อมูลละเอียดอ่อน",
                item.attr, item.path),
            item.path
        )
    end
end

--========== 3. DATA EXPOSURE SCAN ==========--
-- สแกนหาข้อมูลละเอียดอ่อนใน ReplicatedStorage
local function scanDataExposure()
    if not Vuln.Config.SCAN_DATA_EXPOSURE then return end

    local pattern_hits = {
        discord_webhook = 0,
        telegram_bot    = 0,
        api_key         = 0,
        base64_long     = 0,
        suspicious_url  = 0,
    }

    local function scanString(s, path)
        if type(s) ~= "string" or #s < 8 then return end

        if s:find("discord%.com/api/webhooks/") or s:find("discordapp%.com/api/webhooks/") then
            pattern_hits.discord_webhook = pattern_hits.discord_webhook + 1
            addFinding(
                "DATA_EXPOSURE",
                3,
                "T1552",
                "Discord webhook URL exposed",
                string.format("พบ webhook ใน: %s", path),
                s:sub(1, 80)
            )
        end

        if s:find("api%.telegram%.org") then
            pattern_hits.telegram_bot = pattern_hits.telegram_bot + 1
            addFinding(
                "DATA_EXPOSURE",
                3,
                "T1552",
                "Telegram bot endpoint exposed",
                string.format("พบ Telegram bot ใน: %s", path),
                s:sub(1, 80)
            )
        end

        if s:match("AIza[%w%-_]+") or s:match("sk%-[%w]+") then
            pattern_hits.api_key = pattern_hits.api_key + 1
            addFinding(
                "DATA_EXPOSURE",
                4,
                "T1552",
                "API key exposed in plain text",
                string.format("พบ API key ใน: %s", path),
                s:sub(1, 40) .. "..."
            )
        end

        if #s > 60 and s:match("^[A-Za-z0-9+/=]+$") then
            pattern_hits.base64_long = pattern_hits.base64_long + 1
        end
    end

    local function scan(obj, depth, path)
        if depth > 5 then return end
        if not obj then return end

        -- ตรวจ StringValue
        local cn = getClassName(obj)
        if cn == "StringValue" or cn == "StringAttribute" then
            safeCall(function() scanString(obj.Value, path) end)
        end

        -- ตรวจ attribute
        local ok, attrs = pcall(function() return obj:GetAttributes() end)
        if ok and attrs then
            for k, v in pairs(attrs) do
                if type(v) == "string" then
                    scanString(v, path .. "#" .. tostring(k))
                end
            end
        end

        -- walk
        local ok2, children = pcall(function() return obj:GetChildren() end)
        if ok2 then
            for _, child in ipairs(children) do
                scan(child, depth + 1, path .. "/" .. tostring(child.Name))
            end
        end
    end

    safeCall(function()
        scan(game:GetService("ReplicatedStorage"), 0, "ReplicatedStorage")
    end)
end

--========== 4. BUFFER/RESOURCE PATTERNS ==========--
-- ตรวจ pattern ที่อาจนำไปสู่ resource exhaustion
-- (ไม่แตะหน่วยความจำ — ใช้แค่การสังเกต behavior)
local function scanBufferPatterns()
    local edr = State.edr
    if not edr then return end

    -- ใช้ event buffer เป็น source
    local events = edr.buffer:snapshot()
    if not events or #events == 0 then return end

    -- ตรวจ string.char ที่ส่ง args จำนวนมากผิดปกติ
    local stringCharBurst = 0
    local gsubBurst = 0
    local coroutineBurst = 0

    for _, e in ipairs(events) do
        if e.type == "STRING_DECRYPT" then
            if e.data and e.data.source == "string.char" then
                stringCharBurst = stringCharBurst + 1
            elseif e.data and e.data.source == "string.gsub" then
                gsubBurst = gsubBurst + 1
            end
        elseif e.type == "COROUTINE_CREATE" then
            coroutineBurst = coroutineBurst + 1
        end
    end

    -- Pattern: string.char 1000+ ครั้ง → buffer building
    if stringCharBurst > 1000 then
        addFinding(
            "BUFFER_PATTERN",
            2,
            "T1499",
            "Massive string.char activity",
            string.format("string.char ถูกเรียก %d ครั้ง — อาจเป็น buffer building หรือ payload decoding",
                stringCharBurst),
            { count = stringCharBurst }
        )
    end

    -- Pattern: gsub 500+ ครั้ง → regex or string manipulation attack
    if gsubBurst > 500 then
        addFinding(
            "BUFFER_PATTERN",
            2,
            "T1499",
            "Massive string.gsub activity",
            string.format("string.gsub ถูกเรียก %d ครั้ง — อาจเป็น string manipulation attack",
                gsubBurst),
            { count = gsubBurst }
        )
    end

    -- Pattern: coroutine 500+ → VM flood
    if coroutineBurst > 500 then
        addFinding(
            "BUFFER_PATTERN",
            2,
            "T1499",
            "Massive coroutine creation",
            string.format("สร้าง coroutine %d ตัว — อาจเป็น VM flood",
                coroutineBurst),
            { count = coroutineBurst }
        )
    end
end

--========== 5. BACKDOOR DETECTION ==========--
-- ตรวจ Script/LocalScript ที่อยู่ผิดที่
local function scanBackdoor()
    if not Vuln.Config.SCAN_BACKDOOR then return end

    local suspicious = {}

    local function scan(obj, depth, path)
        if depth > 5 then return end
        if not obj then return end

        local cn = getClassName(obj)
        if cn == "Script" or cn == "LocalScript" or cn == "ModuleScript" then
            -- Script ใน Workspace หรือใน LocalPlayer = น่าสงสัย (ปกติอยู่ ServerScriptService)
            local fullName = getFullName(obj)
            if fullName:find("^Workspace") or fullName:find("^Players") then
                table.insert(suspicious, {
                    name = fullName,
                    class = cn,
                })
            end
        end

        local ok, children = pcall(function() return obj:GetChildren() end)
        if ok then
            for _, child in ipairs(children) do
                scan(child, depth + 1, path .. "/" .. tostring(child.Name))
            end
        end
    end

    -- สแกน Workspace
    safeCall(function()
        scan(game:GetService("Workspace"), 0, "Workspace")
    end)

    for _, item in ipairs(suspicious) do
        addFinding(
            "BACKDOOR",
            3,
            "T1543",
            "Script in unusual location",
            string.format("%s '%s' อยู่ในตำแหน่งที่ผิดปกติ (ปกติ scripts ต้องอยู่ใน ServerScriptService)",
                item.class, item.name),
            item.name
        )
    end
end

--========== 6. ANTICHEAT BYPASS SIGNATURES ==========--
-- ตรวจ pattern ของการบายพาส anti-cheat
local function scanAnticheatBypass()
    local edr = State.edr
    if not edr then return end

    -- ตรวจ event stream หา pattern
    local events = edr.buffer:snapshot()

    local byorPattern = 0
    local debugPattern = 0
    local namecallPattern = 0

    for _, e in ipairs(events) do
        if e.type == "STRING_DECRYPT" then
            local val = e.data and e.data.value
            if type(val) == "string" then
                if val:find("Byfron") or val:find("Hyperion")
                    or val:find("anticheat") or val:find("anti_cheat") then
                    byorPattern = byorPattern + 1
                end
            end
        elseif e.type == "DEBUG_ACCESS" then
            debugPattern = debugPattern + 1
        elseif e.type == "METATABLE_ACCESS" then
            local op = e.data and e.data.op
            if op == "getraw" then
                namecallPattern = namecallPattern + 1
            end
        end
    end

    if byorPattern > 0 then
        addFinding(
            "ANTICHEAT_BYPASS",
            3,
            "T1562.001",
            "Anti-cheat reference in decrypted strings",
            string.format("พบคำที่อ้างถึง Byfron/Hyperion/anticheat %d ครั้ง — อาจเป็น bypass technique",
                byorPattern),
            { count = byorPattern }
        )
    end

    if debugPattern > 20 then
        addFinding(
            "ANTICHEAT_BYPASS",
            3,
            "T1622",
            "Heavy debug library usage",
            string.format("ใช้ debug library %d ครั้ง — อาจเป็น introspection สำหรับ bypass",
                debugPattern),
            { count = debugPattern }
        )
    end

    if namecallPattern > 10 then
        addFinding(
            "ANTICHEAT_BYPASS",
            3,
            "T1055",
            "Repeated getrawmetatable access",
            string.format("เรียก getrawmetatable %d ครั้ง — อาจพยายาม hook namecall",
                namecallPattern),
            { count = namecallPattern }
        )
    end
end

--========== 7. PERMISSION CHECK ANALYSIS ==========--
-- ตรวจกลไกที่ client สามารถแก้ได้เพื่อบายพาส permission
local function scanPermissionChecks()
    local lp = Players and Players.LocalPlayer
    if not lp then return end

    -- ตรวจ LocalPlayer properties ที่สามารถใช้บายพาส
    local suspiciousProps = {}

    -- Attributes
    local ok, attrs = pcall(function() return lp:GetAttributes() end)
    if ok and attrs then
        for k, v in pairs(attrs) do
            local lk = tostring(k):lower()
            if lk:find("admin") or lk:find("permission")
                or lk:find("role") or lk:find("rank")
                or lk:find("moderator") or lk:find("vip") then
                table.insert(suspiciousProps, k)
            end
        end
    end

    for _, name in ipairs(suspiciousProps) do
        addFinding(
            "PERMISSION_CHECK",
            3,
            "T1078",
            "Permission-related attribute on LocalPlayer",
            string.format("LocalPlayer มี attribute '%s' ที่อาจใช้บายพาสการตรวจสิทธิ์", name),
            name
        )
    end
end

--========== 8. NETWORK ANOMALY ==========--
-- ตรวจ pattern ของ network ที่ผิดปกติ
local function scanNetworkAnomaly()
    local edr = State.edr
    if not edr then return end

    local events = edr.buffer:snapshot()

    local urlHits = {}
    for _, e in ipairs(events) do
        if e.type == "HTTP_GET" or e.type == "HTTP_POST"
            or e.type == "NETWORK_REQUEST" then
            local url = e.data and e.data.url
            if url then
                -- นับโดเมน
                local domain = url:match("^https?://([^/]+)")
                if domain then
                    urlHits[domain] = (urlHits[domain] or 0) + 1
                end
            end
        end
    end

    -- ถ้ามีมากกว่า 10 โดเมนใน 30 วินาที
    local domainCount = 0
    for _ in pairs(urlHits) do domainCount = domainCount + 1 end

    if domainCount > 10 then
        local list = {}
        for d, c in pairs(urlHits) do
            table.insert(list, string.format("%s×%d", d, c))
        end
        addFinding(
            "NETWORK_ANOMALY",
            3,
            "T1071",
            "Excessive domain diversity",
            string.format("ติดต่อ %d โดเมนที่ต่างกันในระยะเวลาสั้น — อาจเป็น C2 หรือ exfil",
                domainCount),
            table.concat(list, ", "):sub(1, 200)
        )
    end
end

--========== MAIN SCAN FUNCTION ==========--
function Vuln.scanAll()
    if not State.installed then return end
    local t0 = now()
    State.lastScan = t0

    pcall(scanRemoteSecurity)
    pcall(scanClientTrust)
    pcall(scanDataExposure)
    pcall(scanBufferPatterns)
    pcall(scanBackdoor)
    pcall(scanAnticheatBypass)
    pcall(scanPermissionChecks)
    pcall(scanNetworkAnomaly)

    local elapsed = now() - t0
    emit("VULN_SCAN_COMPLETE", {
        elapsed  = elapsed,
        findings = #State.findings,
        by_sev   = State.sevCount,
    }, 0)
end

--========== INSTALL / UNINSTALL ==========--
function Vuln.install(edr)
    if State.installed then
        return false, "already installed"
    end

    State.edr = edr
    State.installed = true

    -- Scan ครั้งแรก
    if Vuln.Config.AUTO_SCAN_ON_INSTALL then
        task.spawn(function()
            task.wait(2)
            pcall(Vuln.scanAll)
        end)
    end

    -- Rescan loop
    State.scannerThread = task.spawn(function()
        while State.installed do
            task.wait(Vuln.Config.RESCAN_INTERVAL)
            pcall(Vuln.scanAll)
        end
    end)

    return true, "installed"
end

function Vuln.uninstall()
    if not State.installed then return end
    State.installed = false
    if State.scannerThread then
        pcall(function() task.cancel(State.scannerThread) end)
    end
end

--========== HELPERS ==========--
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

function Vuln.getSummary()
    return {
        total    = #State.findings,
        by_sev   = State.sevCount,
        by_cat   = State.categoryCount,
        last     = State.lastScan,
    }
end

function Vuln.getTopFindings(n)
    n = n or 10
    local sorted = {}
    for _, f in ipairs(State.findings) do table.insert(sorted, f) end
    table.sort(sorted, function(a, b) return a.severity > b.severity end)
    local out = {}
    for i = 1, math.min(n, #sorted) do
        table.insert(out, sorted[i])
    end
    return out
end

--========== EXPORT ==========--
Vuln.Config   = Vuln.Config
Vuln.State    = State

return Vuln