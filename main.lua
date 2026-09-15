--[[
    ============================================================
    EDR Main v4.0 — Security-Hardened Integration Orchestrator
    ============================================================
    NEW in v4.0:
    - SHA-256 hash verification (TOFU mode)
    - Multi-URL fallback (GitHub → jsDelivr → githack)
    - Per-module version checking
    - Performance modes: LIGHT / BALANCED / PARANOID
    - Auto device tier detection
    - Structured JSON logging
    - Self-integrity verification
    - Consistent pcall everywhere
    - Client-side limitation disclaimer

    SECURITY NOTICE:
    - ระบบนี้เป็น client-side behavioral monitor เท่านั้น
    - ไม่ใช่ anti-cheat และไม่สามารถป้องกัน server-side exploit
    - ใช้เพื่อการศึกษาเท่านั้น (Roblox ToS ระบุชัด)
    ============================================================
]]

local Main             = {}

Main.VERSION           = "4.0.0"
Main.BUILD             = "2025-09-15"

--========== CONFIG ==========--
Main.Config            = {
    -- === Security ===
    HASH_VERIFICATION        = true,  -- เปิด SHA-256 check
    TOFU_MODE                = true,  -- Trust On First Use (ถ้าไม่รู้ hash)
    TOFU_STORE               = "edr_trust.json",
    ALLOW_UNVERIFIED         = false, -- ถ้า hash ไม่ตรง → ปฏิเสธการโหลด
    VERSION_CHECK            = true,
    MIN_MODULE_VERSION       = "2.0.0",
    SELF_INTEGRITY           = true,
    SELF_INTEGRITY_INTERVAL  = 30,

    -- === URLs (multi-fallback) ===
    MODULE_BASES             = {
        "https://raw.githubusercontent.com/zwsx990099-create/security_roblox/main/",
        "https://cdn.jsdelivr.net/gh/zwsx990099-create/security_roblox@main/",
        "https://raw.githack.com/zwsx990099-create/security_roblox/main/",
    },
    UI_MODULE_URLS           = {
        "https://raw.githubusercontent.com/zwsx990099-create/security_roblox/main/ui.lua",
        "https://cdn.jsdelivr.net/gh/zwsx990099-create/security_roblox@main/ui.lua",
        "https://raw.githack.com/zwsx990099-create/security_roblox/main/ui.lua",
    },
    USE_LOCAL                = true,
    ALLOW_REMOTE_FALLBACK    = true,
    URL_TIMEOUT              = 10,

    -- === Performance Mode ===
    -- "auto" | "light" | "balanced" | "paranoid"
    PERFORMANCE_MODE         = "auto",
    AUTO_DETECT_TIER         = true,

    -- === Monitor ===
    MONITOR_INTERVAL         = 3,
    ADAPTIVE_INTERVAL        = true,
    MIN_INTERVAL             = 1,
    MAX_INTERVAL             = 15,
    ADAPTIVE_ALPHA           = 0.2,

    -- === Kill Switch ===
    KILL_SWITCH_ENABLED      = true,
    KILL_THRESHOLD           = 0.90,
    WARN_THRESHOLD           = 0.65,

    -- === Recovery ===
    RECOVERY_ENABLED         = true,
    RECOVERY_INTERVAL        = 15,
    RECOVERY_MAX_RETRIES     = 5,
    RECOVERY_BACKOFF_BASE    = 30,

    -- === Circuit Breaker ===
    CIRCUIT_BREAKER_ENABLED  = true,
    CIRCUIT_FAIL_THRESHOLD   = 3,
    CIRCUIT_TIMEOUT          = 120,
    CIRCUIT_HALF_OPEN_MAX    = 1,

    -- === Health ===
    HEALTH_CHECK_INTERVAL    = 10,
    HEALTH_SCORE_DECAY       = 5,

    -- === ToS Compliance (ห้ามแก้) ===
    TOS_POLICY_ENABLED       = true,
    TOS_BLOCK_FIRE_REMOTE    = true,
    TOS_BLOCK_INVOKE_REMOTE  = false, -- อนุญาต dry-run
    TOS_BLOCK_MEMORY_READ    = true,
    TOS_BLOCK_METATABLE_HOOK = true,
    TOS_BLOCK_SOURCE_DUMP    = true,
    TOS_BLOCK_BYFRON_BYPASS  = true,
    TOS_AUDIT_ENABLED        = true,
    TOS_MAX_AUDIT_ENTRIES    = 500,

    -- === Anti-Ban ===
    ANTIBAN_ENABLED          = true,
    ANTIBAN_SESSION_ROTATE   = 3600,
    ANTIBAN_BEHAVIOR_NORM    = true,
    ANTIBAN_MAX_EVENTS_SEC   = 200,
    ANTIBAN_MAX_NETWORK_SEC  = 5,
    ANTIBAN_NOTIFICATION     = true,

    -- === Buffer Cap ===
    MAX_EVENT_BUFFER         = 200000, -- cap ring buffer
    MAX_ALERTS               = 5000,

    -- === Report ===
    AUTO_REPORT              = true,
    AUTO_REPORT_FORMAT       = "markdown",
    AUTO_SAVE_REPORT         = true,

    -- === Persistence ===
    SAVE_STATE               = true,
    STATE_FILE               = "edr_state.json",

    -- === UI ===
    GUI_ENABLED              = true,
    PREFER_UI_MODULE         = true,
    NOTIFY_ON_ALERT          = true,
    NOTIFY_SEVERITY_MIN      = 3,

    -- === Logging ===
    LOG_LEVEL                = 1,
    LOG_TO_FILE              = false,
    LOG_FILE                 = "edr_log.txt",
    LOG_STRUCTURED           = true, -- JSON logs
}

--========== MODULE REGISTRY ==========--
-- hash: "" = skip check, "sha256:xxxx" = verify, "TOFU" = first-use mode
Main.MODULE_REGISTRY   = {
    {
        key = "EDR",
        file = "edr_core.lua",
        required = true,
        version = "2.0.0",
        min_version = "2.0.0",
        hash = "TOFU",
        deps = {},
        priority = 100,
        description = "Event bus + detection kernel",
    },
    {
        key = "Hooks",
        file = "hooks.lua",
        required = true,
        version = "2.0.0",
        min_version = "2.0.0",
        hash = "TOFU",
        deps = { "EDR" },
        priority = 90,
        description = "Behavior hooks",
    },
    {
        key = "Rules",
        file = "rules.lua",
        required = true,
        version = "2.0.0",
        min_version = "2.0.0",
        hash = "TOFU",
        deps = { "EDR" },
        priority = 80,
        description = "Rule engine",
    },
    {
        key = "Report",
        file = "report.lua",
        required = true,
        version = "3.0.0",
        min_version = "2.0.0",
        hash = "TOFU",
        deps = { "EDR", "Rules" },
        priority = 70,
        description = "Report generator",
    },
    {
        key = "RobloxAPI",
        file = "roblox_api.lua",
        required = false,
        version = "2.0.0",
        min_version = "2.0.0",
        hash = "TOFU",
        deps = { "EDR" },
        priority = 60,
        description = "Roblox API monitor",
    },
    {
        key = "Vuln",
        file = "vuln_scanner.lua",
        required = false,
        version = "2.0.0",
        min_version = "2.0.0",
        hash = "TOFU",
        deps = { "EDR" },
        priority = 55,
        description = "Vulnerability scanner",
    },
    {
        key = "UI",
        file = "ui.lua",
        required = false,
        version = "3.0.0",
        min_version = "2.0.0",
        hash = "TOFU",
        deps = { "EDR", "Rules", "Report" },
        priority = 50,
        description = "Mobile UI",
    },
}

--========== SERVICES ==========--
local Players          = game:GetService("Players")
local CoreGui          = game:GetService("CoreGui")
local StarterGui       = game:GetService("StarterGui")
local UserInputService = game:GetService("UserInputService")
local RunService       = game:GetService("RunService")

local localPlayer      = Players.LocalPlayer

--========== STATE ==========--
Main.State             = {
    booted               = false,
    running              = false,
    paused               = false,
    killed               = false,
    recovered            = 0,
    start_time           = nil,
    last_tick            = nil,
    tick_count           = 0,
    modules              = {},
    module_health        = {},
    monitor_co           = nil,
    monitor_thread       = nil,
    recovery_thread      = nil,
    antiban_thread       = nil,
    integrity_thread     = nil,
    gui                  = nil,
    dashboard            = nil,
    command_log          = {},
    fatal_error          = nil,
    error_log            = {},
    audit_log            = {},
    _warned_high         = false,
    session_start        = 0,
    session_id           = nil,
    health_score         = 100,
    adaptive_interval    = 3,
    last_activity        = 0,
    -- v4.0 new
    device_tier          = "unknown", -- "low" | "mid" | "high"
    performance_mode     = "balanced",
    trust_store          = {},
    verified_modules     = {},
    integrity_violations = 0,
}

--========== UTILITIES ==========--
local function now()
    if type(time) == "function" then return time() end
    return os.clock()
end
local function walltime() return os.time() end

local function versionLess(a, b)
    local left, right = {}, {}
    for part in tostring(a):gmatch("%d+") do left[#left + 1] = tonumber(part) end
    for part in tostring(b):gmatch("%d+") do right[#right + 1] = tonumber(part) end
    local count = math.max(#left, #right)
    for i = 1, count do
        local x, y = left[i] or 0, right[i] or 0
        if x ~= y then return x < y end
    end
    return false
end

local function safeCall(fn, ...)
    local ok, result = pcall(fn, ...)
    if ok then return result end
    return nil, result
end

--========== STRUCTURED LOGGER ==========--
local function jsonEscape(s)
    s = tostring(s or "")
    s = s:gsub("\\", "\\\\"):gsub("\"", "\\\"")
        :gsub("\n", "\\n"):gsub("\r", "\\r"):gsub("\t", "\\t")
    return s
end

local function jsonEncode(t)
    if type(t) ~= "table" then
        if type(t) == "string" then
            return '"' .. jsonEscape(t) .. '"'
        elseif type(t) == "number" or type(t) == "boolean" then
            return tostring(t)
        else
            return "null"
        end
    end
    local isArray = #t > 0
    local parts = {}
    if isArray then
        for i = 1, #t do
            parts[#parts + 1] = jsonEncode(t[i])
        end
        return "[" .. table.concat(parts, ",") .. "]"
    else
        for k, v in pairs(t) do
            parts[#parts + 1] = '"' .. jsonEscape(k) .. '":' .. jsonEncode(v)
        end
        return "{" .. table.concat(parts, ",") .. "}"
    end
end

local function log(level, module, event, data)
    if level > Main.Config.LOG_LEVEL then return end

    if Main.Config.LOG_STRUCTURED then
        local entry = {
            ts = os.time(),
            level = level,
            module = module or "main",
            event = event or "log",
        }
        if data then entry.data = data end
        print("[EDR] " .. jsonEncode(entry))
    else
        print(string.format("[EDR][%s] %s", tostring(module), tostring(event)))
    end

    if Main.Config.LOG_TO_FILE and writefile then
        pcall(function()
            local existing = ""
            if isfile and isfile(Main.Config.LOG_FILE) then
                existing = readfile(Main.Config.LOG_FILE) or ""
            end
            writefile(Main.Config.LOG_FILE,
                existing .. os.date("%Y-%m-%d %H:%M:%S ") .. jsonEncode({
                    ts = os.time(), level = level, module = module, event = event, data = data,
                }) .. "\n")
        end)
    end
end

--========== SHA-256 (pure Lua fallback) ==========--
local bit32lib = bit32 or bit

local function bitBand(a, b)
    if bit32lib then return bit32lib.band(a, b) end
    local result, place = 0, 1
    while a > 0 and b > 0 do
        if a % 2 == 1 and b % 2 == 1 then result = result + place end
        a, b, place = math.floor(a / 2), math.floor(b / 2), place * 2
    end
    return result
end

local function bitBor(a, b)
    if bit32lib then return bit32lib.bor(a, b) end
    local result, place = 0, 1
    while a > 0 or b > 0 do
        if a % 2 == 1 or b % 2 == 1 then result = result + place end
        a, b, place = math.floor(a / 2), math.floor(b / 2), place * 2
    end
    return result
end

local function bitXor(a, b)
    if bit32lib then return bit32lib.bxor(a, b) end
    local result, place = 0, 1
    while a > 0 or b > 0 do
        if a % 2 ~= b % 2 then result = result + place end
        a, b, place = math.floor(a / 2), math.floor(b / 2), place * 2
    end
    return result
end

local function bitRShift(a, n)
    if bit32lib then return bit32lib.rshift(a, n) end
    return math.floor(a / 2 ^ n) % 0x100000000
end

local function bitRRotate(a, n)
    if bit32lib then return bit32lib.rrotate(a, n) end
    n = n % 32
    if n == 0 then return a % 0x100000000 end
    local left = (a * 2 ^ n) % 0x100000000
    local right = math.floor(a / 2 ^ (32 - n))
    return bitBor(left, right)
end

local function sha256_pure(s)
    local band, bxor, bor, rrot = bitBand, bitXor, bitBor, bitRRotate
    local rshift = bitRShift

    local K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    }
    local H = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }

    local len = #s
    local bits = len * 8
    s = s .. "\128"
    while (#s % 64) ~= 56 do s = s .. "\0" end
    s = s .. string.char(
        band(rshift(bits, 56), 0xFF), band(rshift(bits, 48), 0xFF),
        band(rshift(bits, 40), 0xFF), band(rshift(bits, 32), 0xFF),
        band(rshift(bits, 24), 0xFF), band(rshift(bits, 16), 0xFF),
        band(rshift(bits, 8), 0xFF), band(bits, 0xFF))

    for chunk = 1, #s, 64 do
        local w = {}
        for j = 0, 15 do
            local b1, b2, b3, b4 = s:byte(chunk + j * 4),
                s:byte(chunk + j * 4 + 1), s:byte(chunk + j * 4 + 2), s:byte(chunk + j * 4 + 3)
            w[j] = b1 * 0x1000000 + b2 * 0x10000 + b3 * 0x100 + b4
        end
        for j = 16, 63 do
            local s0 = bxor(bxor(rrot(w[j - 15], 7), rrot(w[j - 15], 18)),
                rshift(w[j - 15], 3))
            local s1 = bxor(bxor(rrot(w[j - 2], 17), rrot(w[j - 2], 19)),
                rshift(w[j - 2], 10))
            w[j] = (w[j - 16] + s0 + w[j - 7] + s1) % 0x100000000
        end
        local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
        for j = 0, 63 do
            local S1 = bxor(bxor(rrot(e, 6), rrot(e, 11)), rrot(e, 25))
            local ch = bxor(band(e, f), band(bxor(0xFFFFFFFF, e), g))
            local t1 = (h + S1 + ch + K[j + 1] + w[j]) % 0x100000000
            local S0 = bxor(bxor(rrot(a, 2), rrot(a, 13)), rrot(a, 22))
            local mj = bxor(band(a, b), bxor(band(a, c), band(b, c)))
            local t2 = (S0 + mj) % 0x100000000
            h, g, f, e, d, c, b, a = g, f, e, (d + t1) % 0x100000000, c, b, a, (t1 + t2) % 0x100000000
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
    -- 1. ลองใช้ native crypto ก่อน
    if crypt and type(crypt) == "table" and crypt.hash then
        local ok, result = pcall(crypt.hash, s, "sha256")
        if ok and type(result) == "string" and #result == 64 then return result end
    end
    -- 2. ลองใช้ hash()
    if type(hash) == "function" then
        local ok, result = pcall(hash, s)
        if ok and type(result) == "string" and #result == 64 then return result end
    end
    -- 3. fallback pure Lua
    return sha256_pure(s)
end

--========== TRUST STORE (TOFU) ==========--
local TrustStore = {}

function TrustStore.load()
    if not Main.Config.TOFU_MODE then return end
    if not readfile or not isfile then return end
    pcall(function()
        if isfile(Main.Config.TOFU_STORE) then
            local raw = readfile(Main.Config.TOFU_STORE)
            local decoded = game:GetService("HttpService"):JSONDecode(raw)
            Main.State.trust_store = decoded or {}
        end
    end)
end

function TrustStore.save()
    if not Main.Config.TOFU_MODE then return end
    if not writefile then return end
    pcall(function()
        writefile(Main.Config.TOFU_STORE,
            game:GetService("HttpService"):JSONEncode(Main.State.trust_store))
    end)
end

function TrustStore.verify(moduleKey, content)
    local actualHash = sha256(content)

    -- mode: ทั่วไป (มี hash กำหนดไว้)
    local registryEntry
    for _, e in ipairs(Main.MODULE_REGISTRY) do
        if e.key == moduleKey then
            registryEntry = e; break
        end
    end

    if registryEntry and registryEntry.hash
        and registryEntry.hash:sub(1, 7) == "sha256:" then
        local expected = registryEntry.hash:sub(8)
        if actualHash ~= expected then
            return false,
                "hash mismatch: expected " .. expected:sub(1, 16) .. "... got " .. actualHash:sub(1, 16) .. "..."
        end
        return true, actualHash
    end

    -- mode: TOFU
    if Main.Config.TOFU_MODE then
        local stored = Main.State.trust_store[moduleKey]
        if not stored then
            -- ครั้งแรก → trust + บันทึก
            Main.State.trust_store[moduleKey] = actualHash
            TrustStore.save()
            log(1, "trust", "TOFU captured hash for " .. moduleKey,
                { hash = actualHash:sub(1, 16) .. "..." })
            return true, actualHash
        end
        if stored ~= actualHash then
            return false,
                "TOFU hash changed: expected " .. stored:sub(1, 16) .. "... got " .. actualHash:sub(1, 16) .. "..."
        end
        return true, actualHash
    end

    -- ไม่มี hash, ไม่มี TOFU → ผ่าน (แต่ log warning)
    log(2, "trust", "unverified module " .. moduleKey)
    return true, actualHash
end

--========== URL FALLBACK RESOLVER ==========--
local function fetchWithFallback(filename, baseUrls)
    baseUrls = baseUrls or Main.Config.MODULE_BASES
    local errors = {}

    for i, base in ipairs(baseUrls) do
        local url = base .. filename
        local ok, content = pcall(function()
            if game and type(game.HttpGet) == "function" then
                return game:HttpGet(url)
            end
            local http = game:GetService("HttpService")
            return http:GetAsync(url, false)
        end)
        if ok and content and #content >= 100 then
            log(1, "fetch", "loaded from source " .. i,
                { url = url:sub(1, 100), size = #content })
            return content, url
        else
            errors[#errors + 1] = "source " .. i .. ": " .. tostring(content):sub(1, 60)
        end
    end

    return nil, table.concat(errors, " | ")
end

local function loadLocalModule(filename)
    if type(readfile) == "function" then
        local ok, content = pcall(readfile, filename)
        if ok and type(content) == "string" and #content >= 100 then
            return content, "local:" .. filename
        end
    end
    return nil, "local file access is unavailable"
end

--========== DEVICE TIER DETECTOR ==========--
local function detectDeviceTier()
    if not Main.Config.AUTO_DETECT_TIER then return "mid" end

    -- ใช้หลาย signals
    local isMobile = UserInputService.TouchEnabled and not UserInputService.KeyboardEnabled
    local memory = 0
    if type(gethui) == "function" then
        -- บาง executor มี memory info
    end
    pcall(function()
        if stats and stats.GetTotalMemoryUsageMb then
            memory = stats.GetTotalMemoryUsageMb()
        end
    end)

    -- Physics FPS
    local fps = 60
    pcall(function()
        fps = workspace:GetRealPhysicsFPS()
    end)

    -- ประเมิน
    if isMobile and fps < 30 then return "low" end
    if isMobile and fps < 50 then return "mid" end
    if memory > 2000 then return "low" end
    if fps < 30 then return "low" end
    if fps < 50 then return "mid" end
    return "high"
end

--========== PERFORMANCE MODE APPLIER ==========--
local function applyPerformanceMode()
    local mode = Main.Config.PERFORMANCE_MODE
    local tier = Main.State.device_tier

    -- Auto-select
    if mode == "auto" then
        if tier == "low" then
            mode = "light"
        elseif tier == "high" then
            mode = "balanced" -- ยังไม่ paranoid โดยอัตโนมัติ
        else
            mode = "balanced"
        end
    end

    Main.State.performance_mode = mode

    local modules = Main.State.modules or {}
    for _, key in ipairs({ "EDR", "Hooks", "Rules", "RobloxAPI", "Vuln", "UI" }) do
        local module = modules[key]
        if module and type(module.setPerformanceMode) == "function" then
            local callOK, applied, err = pcall(module.setPerformanceMode, mode)
            if not callOK or not applied then
                log(2, "perf", "failed to apply mode to " .. key,
                    { error = err or applied })
            end
        end
    end

    if mode == "light" then
        Main.Config.MONITOR_INTERVAL = 6
        Main.Config.MIN_INTERVAL = 3
        Main.Config.MAX_INTERVAL = 20
        Main.Config.NOTIFY_SEVERITY_MIN = 4
    elseif mode == "paranoid" then
        Main.Config.MONITOR_INTERVAL = 1
        Main.Config.MIN_INTERVAL = 0.5
        Main.Config.MAX_INTERVAL = 5
        Main.Config.NOTIFY_SEVERITY_MIN = 2
    else -- balanced
        Main.Config.MONITOR_INTERVAL = 3
        Main.Config.MIN_INTERVAL = 1
        Main.Config.MAX_INTERVAL = 15
        Main.Config.NOTIFY_SEVERITY_MIN = 3
    end

    log(1, "perf", "performance mode applied",
        { mode = mode, tier = tier })
end

--========== NOTIFY ==========--
local function notify(title, text, duration)
    if not Main.Config.NOTIFY_ON_ALERT then return end
    pcall(function()
        StarterGui:SetCore("SendNotification", {
            Title = title, Text = text, Duration = duration or 5,
        })
    end)
end

local function getParentGui()
    if type(gethui) == "function" then
        local ok, hui = pcall(gethui)
        if ok and hui then return hui end
    end
    local ok, cg = pcall(function() return CoreGui end)
    if ok and cg then return cg end
    return localPlayer:WaitForChild("PlayerGui")
end

--========== ToS COMPLIANCE LAYER ==========--
local ToS = {}

ToS.BLOCKED_OPERATIONS = {
    "fire_remote", "write_memory", "read_memory", "dump_source",
    "hook_game_metatable", "bypass_byfron", "elevate_identity",
    "inject_code", "modify_script",
}

function ToS.checkOperation(operation, details)
    if not Main.Config.TOS_POLICY_ENABLED then return true end
    for _, blocked in ipairs(ToS.BLOCKED_OPERATIONS) do
        if operation == blocked then
            table.insert(Main.State.audit_log, {
                t = now(), operation = operation, details = details, action = "BLOCKED",
            })
            log(1, "tos", "BLOCKED operation: " .. operation, details)
            if Main.Config.ANTIBAN_NOTIFICATION then
                notify("🚫 ToS BLOCK", "Blocked: " .. operation, 5)
            end
            return false
        end
    end
    table.insert(Main.State.audit_log, {
        t = now(), operation = operation, details = details, action = "ALLOWED",
    })
    if #Main.State.audit_log > Main.Config.TOS_MAX_AUDIT_ENTRIES then
        table.remove(Main.State.audit_log, 1)
    end
    return true
end

function ToS.getAuditSummary()
    local blocked, allowed = 0, 0
    for _, e in ipairs(Main.State.audit_log) do
        if e.action == "BLOCKED" then blocked = blocked + 1 else allowed = allowed + 1 end
    end
    return { total = #Main.State.audit_log, blocked = blocked, allowed = allowed }
end

--========== HEALTH MONITOR ==========--
local Health = {}

function Health.init(name)
    Main.State.module_health[name] = {
        status = "unknown",
        last_ok = nil,
        last_err = nil,
        err_count = 0,
        retry_count = 0,
        next_retry = nil,
        installed = false,
        response_time = 0,
        version = "?",
    }
end

function Health.markOK(name, responseTime)
    local h = Main.State.module_health[name]
    if not h then
        Health.init(name); h = Main.State.module_health[name]
    end
    h.status = "healthy"
    h.last_ok = now()
    if responseTime then h.response_time = responseTime end
    Main.State.health_score = math.min(Main.State.health_score + 1, 100)
end

function Health.markError(name, errMsg)
    local h = Main.State.module_health[name]
    if not h then
        Health.init(name); h = Main.State.module_health[name]
    end
    h.status = "error"
    h.last_err = tostring(errMsg):sub(1, 200)
    h.last_err_time = now()
    h.err_count = h.err_count + 1
    Main.State.health_score = math.max(
        Main.State.health_score - Main.Config.HEALTH_SCORE_DECAY, 0)
    table.insert(Main.State.error_log, {
        t = now(), module = name, message = tostring(errMsg):sub(1, 300),
    })
    if #Main.State.error_log > 200 then table.remove(Main.State.error_log, 1) end
    log(1, "health", "error in " .. name, { err = tostring(errMsg):sub(1, 100) })
end

function Health.canRetry(name)
    local h = Main.State.module_health[name]
    if not h then return true end
    if h.retry_count >= Main.Config.RECOVERY_MAX_RETRIES then return false end
    if h.next_retry and now() < h.next_retry then return false end
    return true
end

function Health.scheduleRetry(name)
    local h = Main.State.module_health[name]
    if not h then return end
    h.retry_count = h.retry_count + 1
    h.next_retry = now() + Main.Config.RECOVERY_BACKOFF_BASE * (2 ^ (h.retry_count - 1))
end

function Health.getScore()
    local score = 100
    local totalErrors = 0
    for _, h in pairs(Main.State.module_health) do
        totalErrors = totalErrors + (h.err_count or 0)
    end
    score = score - math.min(totalErrors * 2, 40)
    local audit = ToS.getAuditSummary()
    score = score - math.min(audit.blocked * 5, 30)
    score = score - math.min(Main.State.integrity_violations * 10, 20)
    local healthy, total = 0, 0
    for _, h in pairs(Main.State.module_health) do
        total = total + 1
        if h.status == "healthy" then healthy = healthy + 1 end
    end
    if total > 0 then score = score * (healthy / total) end
    return math.max(0, math.min(100, score))
end

function Health.getReport()
    local r = {}
    for name, h in pairs(Main.State.module_health) do
        r[#r + 1] = {
            name = name,
            status = h.status,
            err_count = h.err_count,
            retry_count = h.retry_count,
            installed = h.installed,
            version = h.version,
        }
    end
    table.sort(r, function(a, b) return a.name < b.name end)
    return r
end

--========== CIRCUIT BREAKER ==========--
local Circuit = {}

function Circuit.init(name)
    Circuit[name] = {
        state = "closed",
        fail_count = 0,
        success_count = 0,
        opened_at = 0,
        attempts = 0,
    }
end

function Circuit.canCall(name)
    local c = Circuit[name]
    if not c then
        Circuit.init(name); c = Circuit[name]
    end
    if c.state == "closed" then return true end
    if c.state == "open" then
        if now() - c.opened_at >= Main.Config.CIRCUIT_TIMEOUT then
            c.state = "half-open"; c.attempts = 0; return true
        end
        return false
    end
    if c.state == "half-open" then
        if c.attempts < Main.Config.CIRCUIT_HALF_OPEN_MAX then
            c.attempts = c.attempts + 1; return true
        end
        return false
    end
    return true
end

function Circuit.onSuccess(name)
    local c = Circuit[name]; if not c then
        Circuit.init(name); c = Circuit[name]
    end
    c.fail_count = 0
    if c.state == "half-open" then c.state = "closed" end
end

function Circuit.onFail(name)
    local c = Circuit[name]; if not c then
        Circuit.init(name); c = Circuit[name]
    end
    c.fail_count = c.fail_count + 1
    if c.fail_count >= Main.Config.CIRCUIT_FAIL_THRESHOLD then
        c.state = "open"; c.opened_at = now()
        log(1, "circuit", "OPEN " .. name)
    end
end

--========== BOOTSTRAP ==========--
function Main.bootstrap()
    if Main.State.booted then return true end

    log(1, "boot", "starting bootstrap", {
        mode = Main.Config.PERFORMANCE_MODE,
        tier = Main.State.device_tier,
    })

    -- โหลด trust store
    TrustStore.load()

    -- Sort modules by priority
    local sorted = {}
    for i, e in ipairs(Main.MODULE_REGISTRY) do sorted[i] = e end
    table.sort(sorted, function(a, b) return a.priority > b.priority end)

    local modules = {}
    local missing_required = {}

    for _, entry in ipairs(sorted) do
        Health.init(entry.key)
        Circuit.init(entry.key)

        -- ตรวจ dependency
        local depsOK = true
        for _, dep in ipairs(entry.deps or {}) do
            if not modules[dep] then
                depsOK = false
                log(1, "boot", entry.key .. " missing dep " .. dep)
                break
            end
        end

        if not depsOK then
            if entry.required then
                table.insert(missing_required, entry.key)
            end
        else
            local loaded = false
            local lastErr = nil

            for attempt = 1, 3 do
                local t0 = now()
                local ok, result = pcall(function()
                    -- 1. Load local source first, then use remote fallback if enabled.
                    local content, url
                    if Main.Config.USE_LOCAL then
                        content, url = loadLocalModule(entry.file)
                    end
                    if not content and Main.Config.ALLOW_REMOTE_FALLBACK then
                        content, url = fetchWithFallback(entry.file)
                    end
                    if not content then
                        error("module source unavailable: " .. tostring(url))
                    end

                    -- 2. Verify hash
                    if Main.Config.HASH_VERIFICATION then
                        local verified, hashOrErr = TrustStore.verify(entry.key, content)
                        if not verified then
                            if not Main.Config.ALLOW_UNVERIFIED then
                                error("hash verification failed: " .. tostring(hashOrErr))
                            else
                                log(1, "trust", "unverified load allowed for " .. entry.key)
                            end
                        end
                        if verified then
                            Main.State.verified_modules[entry.key] = hashOrErr
                        end
                    end

                    -- 3. Load
                    local fn, err
                    if type(content) == "function" then
                        fn = content
                    else
                        local loader = loadstring or load
                        if type(loader) ~= "function" then
                            error("no Lua loader available")
                        end
                        fn, err = loader(content, "@" .. tostring(url))
                        if not fn then error("module load failed: " .. tostring(err)) end
                    end
                    local mod = fn()

                    -- 4. Version check
                    if Main.Config.VERSION_CHECK then
                        local modVer = mod._VERSION or mod.VERSION or mod.MODULE_VERSION
                        if modVer then
                            if versionLess(modVer,
                                    entry.min_version or Main.Config.MIN_MODULE_VERSION) then
                                error(string.format(
                                    "version %s < minimum %s", modVer, entry.min_version))
                            end
                            local h = Main.State.module_health[entry.key]
                            if h then h.version = modVer end
                        end
                    end

                    return mod
                end)
                local dt = now() - t0

                if ok and result then
                    modules[entry.key] = result
                    Health.markOK(entry.key, dt)
                    Circuit.onSuccess(entry.key)
                    loaded = true
                    break
                else
                    lastErr = result
                    Circuit.onFail(entry.key)
                    if attempt < 3 then task.wait(2) end
                end
            end

            if not loaded then
                Health.markError(entry.key, lastErr or "load failed")
                if entry.required then
                    table.insert(missing_required, entry.key)
                end
                log(1, "boot", "FAILED " .. entry.key .. ": " .. tostring(lastErr))
            end
        end
    end

    if #missing_required > 0 then
        return false, "required modules missing: " .. table.concat(missing_required, ", ")
    end

    Main.State.modules = modules
    Main.State.booted = true
    return true
end

--========== INSTANCE SETUP ==========--
function Main.ensureInstances()
    local M = Main.State.modules
    if not Main.State.edr and M.EDR then
        Main.State.edr = M.EDR.get()
    end
    if not Main.State.rules and M.Rules and Main.State.edr then
        Main.State.rules = M.Rules.new(Main.State.edr)
        -- Rules owns the canonical rule definitions; avoid duplicate alerts
        -- from the kernel's legacy pattern matcher.
        Main.State.edr.patterns = {}
    end
    if not Main.State.report and M.Report and Main.State.edr and Main.State.rules then
        Main.State.report = M.Report.new(Main.State.edr, Main.State.rules)
    end
    return Main.State.edr, Main.State.rules, Main.State.report
end

--========== SUBSYSTEM ==========--
function Main.installSubsystem(key)
    local module = Main.State.modules[key]
    if not module then return false, "not loaded" end
    if type(module.install) ~= "function" then
        return false, "install function is missing"
    end

    if not ToS.checkOperation("install_hook", { module = key }) then
        return false, "ToS blocked"
    end
    if not Circuit.canCall(key) then return false, "circuit open" end

    local ok, result = pcall(module.install, Main.State.edr)

    if ok and result ~= false then
        local h = Main.State.module_health[key]
        if h then h.installed = true end
        Health.markOK(key)
        Circuit.onSuccess(key)
        return true
    else
        local err = ok and "module install returned false" or result
        Health.markError(key, err)
        Circuit.onFail(key)
        return false, err
    end
end

function Main.uninstallSubsystem(key)
    local module = Main.State.modules[key]
    if not module or type(module.uninstall) ~= "function" then return false end
    local ok = pcall(module.uninstall)
    local h = Main.State.module_health[key]
    if h then h.installed = false end
    return ok
end

--========== RECOVERY ==========--
local function recoveryTick()
    if not Main.State.running then return end
    local M = Main.State.modules
    local t = now()
    local repairs = 0

    -- Hooks
    if M.Hooks and M.Hooks.isInstalled and Main.State.module_health.Hooks.installed then
        if not M.Hooks.isInstalled() then
            log(1, "recovery", "reinstalling hooks")
            if Circuit.canCall("Hooks") then
                local ok, installed = pcall(M.Hooks.install, Main.State.edr)
                if ok and installed ~= false then
                    Health.markOK("Hooks")
                    Circuit.onSuccess("Hooks")
                else
                    Circuit.onFail("Hooks")
                end
                repairs = repairs + 1
            end
        end
    end

    -- Monitor loop
    if Main.State.running and not Main.State.paused then
        if t - (Main.State.last_tick or 0) > 30 then
            log(1, "recovery", "restarting monitor loop")
            Main.State.monitor_thread = nil
            pcall(Main.startMonitorLoop)
            repairs = repairs + 1
        end
    end

    -- Dashboard
    if Main.State.dashboard then
        local d = Main.State.dashboard
        if d then
            local dashboardGui = d["gui"]
            if not dashboardGui or not dashboardGui.Parent then
                log(1, "recovery", "rebuilding dashboard")
                Main.State.dashboard = nil
                Main.State.gui = nil
                pcall(Main.buildDashboard)
                repairs = repairs + 1
            end
        end
    end

    -- EDR watchdog
    if Main.State.edr and not Main.State.edr.watchdog then
        pcall(function() Main.State.edr:startWatchdog() end)
        repairs = repairs + 1
    end

    -- Anti-ban rotation
    if Main.Config.ANTIBAN_ENABLED then
        if t - Main.State.session_start >= Main.Config.ANTIBAN_SESSION_ROTATE then
            Main.State.session_start = t
            Main.State.session_id = tostring(os.time()) .. "-" ..
                tostring(math.random(100000, 999999))
            log(1, "antiban", "rotated session", { id = Main.State.session_id })
            repairs = repairs + 1
        end
    end

    if repairs > 0 then
        Main.State.recovered = Main.State.recovered + repairs
    end
end

function Main.startRecoveryUnit()
    if not Main.Config.RECOVERY_ENABLED then return end
    if Main.State.recovery_thread then return end
    Main.State.recovery_thread = task.spawn(function()
        while Main.State.running do
            task.wait(Main.Config.RECOVERY_INTERVAL)
            pcall(recoveryTick)
        end
    end)
end

--========== SELF INTEGRITY ==========--
local function startSelfIntegrity()
    if not Main.Config.SELF_INTEGRITY then return end
    if Main.State.integrity_thread then return end

    Main.State.integrity_thread = task.spawn(function()
        -- เก็บ hash ของฟังก์ชันสำคัญ
        local watched = {
            { name = "pcall",        fn = pcall },
            { name = "tostring",     fn = tostring },
            { name = "setmetatable", fn = setmetatable },
            { name = "rawget",       fn = rawget },
        }
        local baseline = {}
        for _, w in ipairs(watched) do
            baseline[w.name] = tostring((_G and _G[w.name]) or w.fn)
        end

        while Main.State.running do
            task.wait(Main.Config.SELF_INTEGRITY_INTERVAL)
            for _, w in ipairs(watched) do
                local cur = tostring((_G and _G[w.name]) or w.fn)
                if cur ~= baseline[w.name] then
                    Main.State.integrity_violations =
                        Main.State.integrity_violations + 1
                    log(1, "integrity", "tamper detected: " .. w.name)
                    if Main.State.edr then
                        Main.State.edr:raiseAlert({
                            rule = "SELF_INTEGRITY",
                            severity = 4,
                            message = "Function tampered: " .. w.name,
                        })
                    end
                    baseline[w.name] = cur
                end
            end
        end
    end)
end

--========== START/STOP ==========--
function Main.start()
    if not Main.State.booted then
        local ok, err = Main.bootstrap()
        if not ok then
            notify("❌ EDR", "Bootstrap failed: " .. tostring(err), 10)
            return false
        end
    end
    if Main.State.running then return true end

    Main.ensureInstances()
    local M = Main.State.modules
    if not Main.State.edr then return false, "EDR instance unavailable" end

    Main.State.session_id = tostring(os.time()) .. "-" ..
        tostring(math.random(100000, 999999))
    Main.State.session_start = now()

    Main.State.edr.onAlert = Main.onAlert

    -- Apply performance mode ก่อน install
    applyPerformanceMode()

    if Main.State.report and Main.State.report.captureBefore then
        pcall(function() Main.State.report:captureBefore() end)
    end

    for _, key in ipairs({ "Hooks", "RobloxAPI", "Vuln" }) do
        if M[key] then
            local installed, err = Main.installSubsystem(key)
            if not installed then
                log(1, "main", "subsystem failed: " .. key, { err = tostring(err) })
                if key == "Hooks" then
                    for _, cleanupKey in ipairs({ "Hooks", "RobloxAPI", "Vuln" }) do
                        pcall(function() Main.uninstallSubsystem(cleanupKey) end)
                    end
                    notify("❌ EDR", "Required subsystem failed: " .. tostring(err), 10)
                    return false
                end
            end
        end
    end

    pcall(function() Main.State.edr:startWatchdog() end)

    Main.State.running = true
    Main.State.paused = false
    Main.State.killed = false
    Main.State.start_time = now()
    Main.State.last_tick = now()
    Main.State.tick_count = 0
    Main.State._warned_high = false

    Main.startMonitorLoop()
    Main.startRecoveryUnit()
    startSelfIntegrity()

    log(1, "main", "STARTED",
        { mode = Main.State.performance_mode, tier = Main.State.device_tier })
    notify("🛡️ EDR v" .. Main.VERSION,
        "Mode: " .. Main.State.performance_mode .. " | Tier: " .. Main.State.device_tier, 5)

    local refreshDashboard = Main.State.dashboard
        and Main.State.dashboard["forceRefresh"]
    if type(refreshDashboard) == "function" then
        pcall(refreshDashboard, Main.State.dashboard)
    end
    return true
end

function Main.stop(reason)
    if not Main.State.running and not Main.State.booted then return false end
    local wasRunning = Main.State.running
    Main.State.running = false

    for _, key in ipairs({ "Hooks", "RobloxAPI", "Vuln" }) do
        pcall(function() Main.uninstallSubsystem(key) end)
    end

    if Main.State.edr then
        pcall(function() Main.State.edr:stopWatchdog() end)
    end

    if wasRunning and Main.State.report and Main.Config.AUTO_REPORT then
        pcall(function()
            Main.State.report:finalize()
            Main.saveReport()
        end)
    end

    if wasRunning then
        log(1, "main", "STOPPED", { reason = tostring(reason) })
        notify("🛡️ EDR", "Stopped: " .. tostring(reason or "user"), 5)
    end
    return wasRunning
end

function Main.pause()
    Main.State.paused = true
    log(1, "main", "PAUSED")
end

function Main.resume()
    Main.State.paused = false
    log(1, "main", "RESUMED")
end

--========== KILL ==========--
function Main.kill(reason)
    if Main.State.killed then return end
    Main.State.killed = true
    Main.State.running = false

    log(1, "main", "KILL", { reason = tostring(reason) })

    Main.showKillOverlay(reason)

    for _, key in ipairs({ "Hooks", "RobloxAPI", "Vuln" }) do
        pcall(function() Main.uninstallSubsystem(key) end)
    end
    if Main.State.edr then
        pcall(function() Main.State.edr:stopWatchdog() end)
    end
    if Main.State.report then
        pcall(function()
            Main.State.report:finalize()
            Main.saveReport()
        end)
    end

    notify("🔴 EDR KILLED", tostring(reason), 10)
end

function Main.showKillOverlay(reason)
    local gui = Instance.new("ScreenGui")
    gui.Name = "EDR_Kill_" .. tostring(math.random(1000, 9999))
    gui.ResetOnSpawn = false
    gui.DisplayOrder = 9999
    gui.Parent = getParentGui()

    local frame = Instance.new("Frame")
    frame.Size = UDim2.new(0, 460, 0, 210)
    frame.Position = UDim2.new(0.5, -230, 0.5, -105)
    frame.BackgroundColor3 = Color3.fromRGB(30, 10, 10)
    frame.BorderSizePixel = 0
    frame.Parent = gui
    Instance.new("UICorner", frame).CornerRadius = UDim.new(0, 14)
    local stroke = Instance.new("UIStroke", frame)
    stroke.Color = Color3.fromRGB(220, 60, 60)
    stroke.Thickness = 3

    local title = Instance.new("TextLabel")
    title.Size = UDim2.new(1, -30, 0, 34)
    title.Position = UDim2.new(0, 15, 0, 12)
    title.BackgroundTransparency = 1
    title.Text = "🛑  EDR KILL SWITCH"
    title.TextColor3 = Color3.fromRGB(248, 81, 73)
    title.Font = Enum.Font.GothamBold
    title.TextSize = 20
    title.TextXAlignment = Enum.TextXAlignment.Left
    title.Parent = frame

    local msg = Instance.new("TextLabel")
    msg.Size = UDim2.new(1, -30, 0, 100)
    msg.Position = UDim2.new(0, 15, 0, 52)
    msg.BackgroundTransparency = 1
    msg.Text = tostring(reason or "High risk detected")
    msg.TextColor3 = Color3.fromRGB(220, 200, 200)
    msg.Font = Enum.Font.Gotham
    msg.TextSize = 14
    msg.TextWrapped = true
    msg.TextXAlignment = Enum.TextXAlignment.Left
    msg.TextYAlignment = Enum.TextYAlignment.Top
    msg.Parent = frame

    local close = Instance.new("TextButton")
    close.Size = UDim2.new(1, -30, 0, 40)
    close.Position = UDim2.new(0, 15, 1, -55)
    close.BackgroundColor3 = Color3.fromRGB(80, 30, 30)
    close.BorderSizePixel = 0
    close.Text = "Close"
    close.TextColor3 = Color3.fromRGB(255, 255, 255)
    close.Font = Enum.Font.GothamBold
    close.TextSize = 14
    close.Parent = frame
    Instance.new("UICorner", close).CornerRadius = UDim.new(0, 8)
    close.MouseButton1Click:Connect(function() gui:Destroy() end)
end

--========== MONITOR ==========--
function Main.startMonitorLoop()
    if Main.State.monitor_thread then return end
    local co = coroutine.create(function()
        while Main.State.running do
            local interval = Main.Config.MONITOR_INTERVAL
            if Main.Config.ADAPTIVE_INTERVAL and Main.State.edr then
                local ok, rate = pcall(function()
                    return Main.State.edr:getRate("NETWORK_REQUEST", 5)
                end)
                if ok and rate then
                    if rate > 20 then
                        interval = Main.Config.MIN_INTERVAL
                    elseif rate < 1 then
                        interval = Main.Config.MAX_INTERVAL
                    end
                end
            end
            local alpha = Main.Config.ADAPTIVE_ALPHA
            Main.State.adaptive_interval = alpha * interval +
                (1 - alpha) * (Main.State.adaptive_interval or interval)
            coroutine.yield(Main.State.adaptive_interval)
            if not Main.State.paused and not Main.State.killed then
                pcall(Main.tick)
            end
        end
    end)
    Main.State.monitor_co = co
    Main.State.monitor_thread = task.spawn(function()
        while Main.State.running do
            local ok, waitTime = coroutine.resume(co)
            if not ok then
                Health.markError("MonitorLoop", waitTime); break
            end
            task.wait(waitTime or Main.Config.MONITOR_INTERVAL)
        end
        Main.State.monitor_thread = nil
    end)
end

function Main.tick()
    Main.State.tick_count = Main.State.tick_count + 1
    Main.State.last_tick = now()
    Main.State.last_activity = now()

    local M = Main.State.modules

    if Main.State.rules then
        local ok, err = pcall(function() Main.State.rules:scan() end)
        if not ok then Health.markError("Rules", err) else Health.markOK("Rules") end
    end
    if Main.State.report then
        local ok, err = pcall(function() Main.State.report:update() end)
        if not ok then Health.markError("Report", err) else Health.markOK("Report") end
    end

    local risk = 0
    if M.Rules and Main.State.edr then
        local ok, r = pcall(function()
            return M.Rules.computeSessionRisk(Main.State.edr.alerts)
        end)
        if ok and type(r) == "number" then risk = r end
    end

    if Main.Config.KILL_SWITCH_ENABLED then
        if risk >= Main.Config.KILL_THRESHOLD then
            Main.kill(string.format("Risk %.1f%% >= %.1f%%",
                risk * 100, Main.Config.KILL_THRESHOLD * 100))
        elseif risk >= Main.Config.WARN_THRESHOLD and not Main.State._warned_high then
            Main.State._warned_high = true
            notify("⚠️ EDR", string.format("High risk: %.1f%%", risk * 100), 6)
        end
    end

    if Main.State.gui and Main.State.gui.update then
        pcall(Main.State.gui.update)
    end
end

function Main.onAlert(alert)
    table.insert(Main.State.command_log, { t = now(), alert = alert })
    if #Main.State.command_log > 500 then table.remove(Main.State.command_log, 1) end

    local sev = alert.severity or 0
    if sev >= (Main.Config.NOTIFY_SEVERITY_MIN or 3) then
        notify(string.format("%s %s",
                sev >= 4 and "🔴" or "🟠", alert.rule or "ALERT"),
            tostring(alert.message or ""):sub(1, 120), 5)
    end
end

--========== REPORT ==========--
function Main.saveReport()
    if not Main.Config.AUTO_SAVE_REPORT then return false, "auto-save disabled" end
    if not Main.State.report then return false, "report unavailable" end
    local path = "edr_report_" .. os.date("%Y%m%d_%H%M%S") .. "." ..
        (Main.Config.AUTO_REPORT_FORMAT == "json" and "json"
            or Main.Config.AUTO_REPORT_FORMAT == "html" and "html" or "md")
    local ok, saved, err = pcall(function()
        return Main.State.report:saveToFile(path, Main.Config.AUTO_REPORT_FORMAT)
    end)
    if ok and saved then
        log(1, "report", "saved", { path = path })
        notify("📄 EDR Report", "Saved: " .. path, 6)
        return true, path
    else
        local message = ok and (err or "write failed") or saved
        log(1, "report", "save failed", { err = tostring(message) })
        return false, message
    end
end

function Main.saveState()
    if not Main.Config.SAVE_STATE or not writefile then return end
    pcall(function()
        writefile(Main.Config.STATE_FILE,
            game:GetService("HttpService"):JSONEncode({
                version = Main.VERSION,
                session_id = Main.State.session_id,
                saved_at = os.time(),
                health_score = Health.getScore(),
                verified = Main.State.verified_modules,
                mode = Main.State.performance_mode,
            }))
    end)
end

--========== COMMANDS ==========--
local COMMANDS = {}
local function cmd(name, fn) COMMANDS[name] = fn end

cmd("help", function()
    return [[
Commands:
  /help /start /stop /pause /resume /kill
  /status /health /score /errors /recover
  /risk /alerts /ioc /vulns /rbxstats /timeline /summary
  /audit /policy
  /mode light|balanced|paranoid    -- เปลี่ยน performance mode
  /version /clear /ui /min /report
]]
end)

cmd("status", function()
    local s = Main.State
    return string.format(
        "v%s | mode=%s tier=%s\nRunning: %s | Paused: %s | Killed: %s\nRecovered: %d | Health: %d/100\nUptime: %.1fs | Ticks: %d\nEvents: %d | Alerts: %d | Errors: %d",
        Main.VERSION, s.performance_mode, s.device_tier,
        tostring(s.running), tostring(s.paused), tostring(s.killed),
        s.recovered, Health.getScore(),
        s.start_time and (now() - s.start_time) or 0,
        s.tick_count,
        s.edr and s.edr.session.events_processed or 0,
        s.edr and #(s.edr.alerts or {}) or 0,
        #s.error_log)
end)

cmd("health", function()
    local lines = { "HEALTH (score=" .. Health.getScore() .. "/100)" }
    for _, r in ipairs(Health.getReport()) do
        local icon = r.status == "healthy" and "✓"
            or r.status == "error" and "✗" or "?"
        lines[#lines + 1] = string.format("%s %-12s v%-6s err=%d retry=%d",
            icon, r.name, r.version, r.err_count, r.retry_count)
    end
    return table.concat(lines, "\n")
end)

cmd("score", function() return "Health: " .. Health.getScore() .. "/100" end)
cmd("recover", function()
    pcall(recoveryTick)
    return "Recovery triggered. Total: " .. Main.State.recovered
end)
cmd("errors", function()
    local out = {}
    local s = math.max(1, #Main.State.error_log - 10)
    for i = s, #Main.State.error_log do
        local e = Main.State.error_log[i]
        out[#out + 1] = string.format("[%.1fs] %s: %s", e.t, e.module,
            tostring(e.message):sub(1, 70))
    end
    return #out > 0 and table.concat(out, "\n") or "No errors"
end)

cmd("audit", function()
    local s = ToS.getAuditSummary()
    return string.format("Allowed: %d | Blocked: %d | Total: %d",
        s.allowed, s.blocked, s.total)
end)

cmd("policy", function()
    return [[
BLOCKED (ToS):
  ❌ fire_remote, write_memory, read_memory
  ❌ dump_source, hook_game_metatable
  ❌ bypass_byfron, elevate_identity
  ❌ inject_code, modify_script

ALLOWED:
  ✅ read_service, read_instance, read_property
  ✅ scan_children, scan_attributes
  ✅ monitor_signal, emit_event, install_hook
  ✅ scan_vulnerability, generate_report
  ✅ dry_run_fuzz
]]
end)

cmd("start", function()
    local ok, err = Main.start()
    return ok and "Started" or ("Start failed: " .. tostring(err or "unknown error"))
end)
cmd("stop", function()
    return Main.stop("cmd") and "Stopped" or "Already stopped"
end)
cmd("pause", function()
    if not Main.State.running then return "Not running" end
    Main.pause()
    return "Paused"
end)
cmd("resume", function()
    if not Main.State.running then return "Not running" end
    Main.resume()
    return "Resumed"
end)
cmd("kill", function()
    Main.kill("cmd"); return "Killed"
end)

cmd("mode", function(arg)
    arg = tostring(arg or ""):lower()
    if arg == "light" or arg == "balanced" or arg == "paranoid" then
        Main.Config.PERFORMANCE_MODE = arg
        applyPerformanceMode()
        return "Mode: " .. arg
    end
    return "Usage: /mode light|balanced|paranoid"
end)

cmd("risk", function()
    if not Main.State.rules or not Main.State.edr then return "No data" end
    local r = Main.State.rules.computeSessionRisk(Main.State.edr.alerts)
    return string.format("Risk: %.2f%%", r * 100)
end)

cmd("alerts", function()
    local a = Main.State.edr and Main.State.edr.alerts or {}
    local out = {}
    local s = math.max(1, #a - 10)
    for i = s, #a do
        out[#out + 1] = string.format("[%s] %s (%.2f)",
            a[i].rule or "?", tostring(a[i].message or ""):sub(1, 70), a[i].score or 0)
    end
    return #out > 0 and table.concat(out, "\n") or "No alerts"
end)

cmd("version", function() return "EDR Main v" .. Main.VERSION .. " (" .. Main.BUILD .. ")" end)
cmd("clear", function()
    Main.State.command_log = {}; return "Cleared"
end)
cmd("report", function()
    Main.saveReport(); return "Saved"
end)
cmd("ui", function()
    local d = Main.State.dashboard
    if not d then return "No dashboard" end
    if d.minimized then
        d:maximize(); return "Shown"
    else
        d:minimize(); return "Hidden"
    end
end)
cmd("min", function()
    local d = Main.State.dashboard
    if d and d.minimize then d:minimize() end
    return "Minimized"
end)

function Main.executeCommand(input)
    input = tostring(input or ""):gsub("^%s+", ""):gsub("%s+$", "")
    if input == "" then return end
    local cmdLine = input:gsub("^/", "")
    local c, args = cmdLine:match("^(%S+)%s*(.*)$")
    c = c and c:lower()
    if not c then return end
    local fn = COMMANDS[c]
    if not fn then return "Unknown: " .. tostring(c) .. " (try /help)" end
    local ok, result = pcall(fn, args)
    if not ok then return "Error: " .. tostring(result) end
    return result
end

--========== FALLBACK GUI ==========--
function Main.buildGUI()
    if not Main.Config.GUI_ENABLED then return end
    if Main.State.gui and Main.State.gui.screen then return end

    local gui = Instance.new("ScreenGui")
    gui.Name = "EDR_Main_" .. tostring(math.random(1000, 9999))
    gui.ResetOnSpawn = false
    gui.Parent = getParentGui()

    local main = Instance.new("Frame")
    main.Size = UDim2.new(0, 520, 0, 580)
    main.Position = UDim2.new(0, 20, 0.5, -290)
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
    title.Size = UDim2.new(1, 0, 0, 38)
    title.BackgroundColor3 = Color3.fromRGB(22, 27, 34)
    title.BorderSizePixel = 0
    title.Text = "  🛡️  EDR v" .. Main.VERSION .. " (fallback)"
    title.TextColor3 = Color3.fromRGB(88, 166, 255)
    title.Font = Enum.Font.GothamBold
    title.TextSize = 14
    title.TextXAlignment = Enum.TextXAlignment.Left
    title.Parent = main
    Instance.new("UICorner", title).CornerRadius = UDim.new(0, 12)

    local close = Instance.new("TextButton")
    close.Size = UDim2.new(0, 30, 0, 26)
    close.Position = UDim2.new(1, -34, 0, 6)
    close.BackgroundColor3 = Color3.fromRGB(180, 50, 50)
    close.BorderSizePixel = 0
    close.Text = "X"
    close.TextColor3 = Color3.fromRGB(255, 255, 255)
    close.Font = Enum.Font.GothamBold
    close.TextSize = 12
    close.Parent = title
    Instance.new("UICorner", close).CornerRadius = UDim.new(0, 6)
    close.MouseButton1Click:Connect(function() gui.Enabled = false end)

    local statusLbl = Instance.new("TextLabel")
    statusLbl.Size = UDim2.new(1, -20, 0, 20)
    statusLbl.Position = UDim2.new(0, 10, 0, 46)
    statusLbl.BackgroundTransparency = 1
    statusLbl.Text = "⚪ STOPPED"
    statusLbl.TextColor3 = Color3.fromRGB(200, 90, 90)
    statusLbl.Font = Enum.Font.GothamBold
    statusLbl.TextSize = 13
    statusLbl.TextXAlignment = Enum.TextXAlignment.Left
    statusLbl.Parent = main

    local infoLbl = Instance.new("TextLabel")
    infoLbl.Size = UDim2.new(1, -20, 0, 60)
    infoLbl.Position = UDim2.new(0, 10, 0, 70)
    infoLbl.BackgroundTransparency = 1
    infoLbl.Text = "Health: 100/100 | Recovered: 0"
    infoLbl.TextColor3 = Color3.fromRGB(150, 170, 190)
    infoLbl.Font = Enum.Font.Code
    infoLbl.TextSize = 11
    infoLbl.TextXAlignment = Enum.TextXAlignment.Left
    infoLbl.TextYAlignment = Enum.TextYAlignment.Top
    infoLbl.Parent = main

    local console = Instance.new("ScrollingFrame")
    console.Size = UDim2.new(1, -20, 1, -200)
    console.Position = UDim2.new(0, 10, 0, 140)
    console.BackgroundColor3 = Color3.fromRGB(6, 8, 12)
    console.BorderSizePixel = 0
    console.ScrollBarThickness = 6
    console.CanvasSize = UDim2.new(0, 0, 0, 0)
    console.AutomaticCanvasSize = Enum.AutomaticSize.Y
    console.Parent = main
    Instance.new("UICorner", console).CornerRadius = UDim.new(0, 8)
    local list = Instance.new("UIListLayout", console)
    list.Padding = UDim.new(0, 2)

    local cmdBox = Instance.new("TextBox")
    cmdBox.Size = UDim2.new(1, -20, 0, 30)
    cmdBox.Position = UDim2.new(0, 10, 1, -40)
    cmdBox.BackgroundColor3 = Color3.fromRGB(22, 27, 34)
    cmdBox.BorderSizePixel = 0
    cmdBox.PlaceholderText = "Command (e.g. /help)"
    cmdBox.Text = ""
    cmdBox.TextColor3 = Color3.fromRGB(220, 230, 240)
    cmdBox.PlaceholderColor3 = Color3.fromRGB(100, 110, 120)
    cmdBox.Font = Enum.Font.Code
    cmdBox.TextSize = 12
    cmdBox.ClearTextOnFocus = false
    cmdBox.Parent = main
    Instance.new("UICorner", cmdBox).CornerRadius = UDim.new(0, 6)

    local function appendConsole(text, color)
        local lbl = Instance.new("TextLabel")
        lbl.Size = UDim2.new(1, -4, 0, 14)
        lbl.BackgroundTransparency = 1
        lbl.Text = tostring(text)
        lbl.TextColor3 = color or Color3.fromRGB(180, 200, 220)
        lbl.Font = Enum.Font.Code
        lbl.TextSize = 11
        lbl.TextXAlignment = Enum.TextXAlignment.Left
        lbl.Parent = console
    end

    cmdBox.FocusLost:Connect(function(enter)
        if not enter then return end
        local t = cmdBox.Text
        cmdBox.Text = ""
        if t == "" then return end
        appendConsole("› " .. t, Color3.fromRGB(88, 166, 255))
        local res = Main.executeCommand(t)
        if res and res ~= "" then
            for line in tostring(res):gmatch("[^\n]+") do
                appendConsole(line, Color3.fromRGB(180, 220, 180))
            end
        end
    end)

    local function update()
        if not gui.Parent then return end
        local st, col
        if Main.State.killed then
            st, col = "🔴 KILLED", Color3.fromRGB(248, 81, 73)
        elseif Main.State.paused then
            st, col = "🟡 PAUSED", Color3.fromRGB(210, 153, 34)
        elseif Main.State.running then
            st, col = "🟢 RUNNING", Color3.fromRGB(126, 231, 135)
        else
            st, col = "⚪ STOPPED", Color3.fromRGB(200, 90, 90)
        end
        statusLbl.Text = st
        statusLbl.TextColor3 = col
        infoLbl.Text = string.format(
            "Health: %d/100 | Mode: %s | Tier: %s\nRecovered: %d | Integrity: %d",
            Health.getScore(), Main.State.performance_mode, Main.State.device_tier,
            Main.State.recovered, Main.State.integrity_violations)
    end

    Main.State.gui = { screen = gui, update = update }

    appendConsole("EDR v" .. Main.VERSION .. " fallback ready", Color3.fromRGB(88, 166, 255))
    appendConsole("Type /help", Color3.fromRGB(150, 170, 190))

    task.spawn(function()
        while gui.Parent do
            task.wait(1)
            pcall(update)
        end
    end)
end

--========== DASHBOARD ==========--
function Main.buildDashboard()
    local UI = Main.State.modules.UI
    if not UI then return false, "no UI" end
    Main.ensureInstances()
    local d, err = nil, nil
    local ok, callErr = pcall(function()
        d = UI.new(Main.State.edr, Main.State.rules, Main.State.report, Main)
    end)
    if not ok then err = callErr end
    if not d then return false, tostring(err or "failed") end
    Main.State.dashboard = d
    if d.attachToEDR then pcall(function() d:attachToEDR() end) end
    if d.show then pcall(function() d:show() end) end
    Main.State.gui = {
        screen = d.gui,
        update = function()
            if d.update then pcall(function() d:update() end) end
        end,
    }
    return true
end

--========== INIT ==========--
function Main.init()
    log(1, "main", "INIT v" .. Main.VERSION)

    -- Disclaimer
    log(1, "main", "DISCLAIMER: client-side behavioral monitor only. " ..
        "Not an anti-cheat. For educational use only.")

    -- Detect device tier
    Main.State.device_tier = detectDeviceTier()
    log(1, "main", "device tier detected", { tier = Main.State.device_tier })

    -- Bootstrap
    local ok, err = Main.bootstrap()
    if not ok then
        log(1, "main", "bootstrap failed: " .. tostring(err))
        notify("❌ EDR", "Bootstrap failed: " .. tostring(err), 10)
        return false
    end

    Main.ensureInstances()

    -- Load UI
    local uiOK = false
    if Main.State.modules.UI then
        local s = Main.buildDashboard()
        if s then uiOK = true end
    end
    if not uiOK then Main.buildGUI() end

    -- Save state loop
    if Main.Config.SAVE_STATE and task and task.spawn then
        task.spawn(function()
            while true do
                task.wait(60)
                pcall(Main.saveState)
            end
        end)
    end

    log(1, "main", "initialized", { ui = uiOK and "ui.lua" or "fallback" })
    notify("🛡️ EDR v" .. Main.VERSION,
        "Tier: " .. Main.State.device_tier, 5)

    return true
end

-- Auto-init when the host provides Roblox's scheduler.
if task and type(task.spawn) == "function" then
    task.spawn(function()
        if type(task.wait) == "function" then task.wait(0.1) end
        local ok, err = pcall(Main.init)
        if not ok then
            Main.State.fatal_error = tostring(err)
            log(1, "main", "init crashed", { err = Main.State.fatal_error })
        end
    end)
end

--========== EXPORT ==========--
Main.log = log
Main.notify = notify
Main.executeCommand = Main.executeCommand
Main.Health = Health
Main.ToS = ToS
Main.Circuit = Circuit
Main.TrustStore = TrustStore
Main.sha256 = sha256

if getgenv then
    pcall(function() getgenv().EDRMain = Main end)
end
_G.EDRMain = Main

return Main
