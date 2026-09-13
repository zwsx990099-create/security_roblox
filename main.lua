--[[
    ============================================================
    EDR Main v3.0 — ToS-Compliant Integration Orchestrator
    ============================================================
    หลักการ:
    - Integration Layer สำหรับ 7 modules
    - ToS Compliance Layer (hard-coded policy)
    - Anti-Ban Protection (session rotation, behavior normalizer)
    - Module Dependency Graph + Ordered Loading
    - Advanced Recovery + Circuit Breaker
    - Adaptive Performance Scaling
    - Health Scoring (0-100)

    POLICY (ห้ามละเมิดเด็ดขาด):
    1. ไม่แตะหน่วยความจำเกม
    2. ไม่ดัก packet
    3. ไม่ดึง script source
    4. ไม่ hook metatable ของ game
    5. ไม่ fire remote โดยไม่ได้รับอนุญาต
    6. ไม่ใช้ Byfron bypass
    7. ไม่ทำพฤติกรรม bot-like ที่ผิดธรรมชาติ
    8. Audit ทุก action ที่ sensitive

    วิธีใช้:
    1. loadstring main.lua
    2. UI จะเด้งขึ้นอัตโนมัติ
    3. กด START → รันสคริปต์เป้าหมาย

    คำเตือน: เพื่อการศึกษาเท่านั้น
    ============================================================
]]

--========== BOOTSTRAP ==========--
local Main = {}

Main.VERSION = "3.0.0"
Main.BUILD   = "2025-09-14"

--========== CONFIG ==========--
Main.Config = {
    -- === URLs ===
    MODULE_BASE   = "https://raw.githubusercontent.com/zwsx990099-create/security_roblox/main/",
    UI_MODULE_URL = "https://raw.githubusercontent.com/zwsx990099-create/security_roblox/main/ui.lua",
    USE_LOCAL               = false,

    -- === Bootstrap ===
    BOOTSTRAP_RETRIES       = 3,
    BOOTSTRAP_RETRY_DELAY   = 2,
    BOOTSTRAP_PARALLEL      = false,   -- เปิด parallel load (อาจ block)
    MODULE_TIMEOUT          = 30,      -- วินาที ต่อ module

    -- === Monitor ===
    MONITOR_INTERVAL        = 3,
    ADAPTIVE_INTERVAL       = true,
    MIN_INTERVAL            = 1,
    MAX_INTERVAL            = 15,
    ADAPTIVE_ALPHA          = 0.2,     -- EMA smoothing

    -- === Kill Switch ===
    KILL_SWITCH_ENABLED     = true,
    KILL_THRESHOLD          = 0.90,
    WARN_THRESHOLD          = 0.65,

    -- === Recovery ===
    RECOVERY_ENABLED        = true,
    RECOVERY_INTERVAL       = 15,
    RECOVERY_MAX_RETRIES    = 5,
    RECOVERY_BACKOFF_BASE   = 30,

    -- === Circuit Breaker ===
    CIRCUIT_BREAKER_ENABLED = true,
    CIRCUIT_FAIL_THRESHOLD  = 3,
    CIRCUIT_TIMEOUT         = 120,
    CIRCUIT_HALF_OPEN_MAX   = 1,

    -- === Health ===
    HEALTH_CHECK_INTERVAL   = 10,
    HEALTH_MAX_ERRORS       = 50,
    HEALTH_STALE_THRESHOLD  = 60,
    HEALTH_SCORE_DECAY      = 5,       -- คะแนนลดต่อ error

    -- === ToS Compliance (สำคัญมาก!) ===
    TOS_POLICY_ENABLED      = true,
    TOS_BLOCK_FIRE_REMOTE   = true,
    TOS_BLOCK_INVOKE_REMOTE = false,   -- อนุญาต (dry-run ได้)
    TOS_BLOCK_MEMORY_READ   = true,
    TOS_BLOCK_METATABLE_HOOK = true,
    TOS_BLOCK_SOURCE_DUMP   = true,
    TOS_BLOCK_BYFRON_BYPASS = true,
    TOS_AUDIT_ENABLED       = true,
    TOS_MAX_AUDIT_ENTRIES   = 500,

    -- === Anti-Ban ===
    ANTIBAN_ENABLED         = true,
    ANTIBAN_SESSION_ROTATE  = 3600,     -- หมุน session ทุก 1 ชม.
    ANTIBAN_BEHAVIOR_NORM   = true,
    ANTIBAN_MAX_EVENTS_SEC  = 200,      -- จำกัด event rate
    ANTIBAN_MAX_NETWORK_SEC = 5,        -- จำกัด network rate
    ANTIBAN_NOTIFICATION    = true,

    -- === Report ===
    AUTO_REPORT             = true,
    AUTO_REPORT_FORMAT      = "markdown",
    AUTO_SAVE_REPORT        = true,

    -- === Persistence ===
    SAVE_STATE              = true,
    STATE_FILE              = "edr_state.json",

    -- === UI ===
    GUI_ENABLED             = true,
    PREFER_UI_MODULE        = true,
    NOTIFY_ON_ALERT         = true,
    NOTIFY_SEVERITY_MIN     = 3,

    -- === Logging ===
    LOG_LEVEL               = 1,
    LOG_TO_FILE             = false,
    LOG_FILE                = "edr_log.txt",
}

--========== SERVICES ==========--
local Players          = game:GetService("Players")
local CoreGui          = game:GetService("CoreGui")
local StarterGui       = game:GetService("StarterGui")
local UserInputService = game:GetService("UserInputService")
local RunService       = game:GetService("RunService")

local localPlayer = Players.LocalPlayer

--========== STATE ==========--
Main.State = {
    booted            = false,
    running           = false,
    paused            = false,
    killed            = false,
    recovered         = 0,
    start_time        = nil,
    last_tick         = nil,
    tick_count        = 0,
    modules           = {},
    module_versions   = {},
    module_health     = {},
    dependency_graph  = {},
    monitor_co        = nil,
    monitor_thread    = nil,
    recovery_thread   = nil,
    health_thread     = nil,
    antiban_thread    = nil,
    gui               = nil,
    dashboard         = nil,
    command_log       = {},
    fatal_error       = nil,
    error_log         = {},
    _warned_high      = false,
    session_start     = 0,
    session_id        = nil,
    audit_log         = {},
    stats_cache       = {},
    health_score      = 100,
    adaptive_interval = 3,
    last_activity     = 0,
}

--========== MODULE REGISTRY ==========--
local MODULE_REGISTRY = {
    {
        key         = "EDR",
        file        = "edr_core.lua",
        required    = true,
        description = "Event bus + detection kernel",
        deps        = {},
        priority    = 100,
    },
    {
        key         = "Hooks",
        file        = "hooks.lua",
        required    = true,
        description = "Behavior hooks",
        deps        = { "EDR" },
        priority    = 90,
    },
    {
        key         = "Rules",
        file        = "rules.lua",
        required    = true,
        description = "Rule engine",
        deps        = { "EDR" },
        priority    = 80,
    },
    {
        key         = "Report",
        file        = "report.lua",
        required    = true,
        description = "Report generator",
        deps        = { "EDR", "Rules" },
        priority = 70,
    },
    {
        key         = "RobloxAPI",
        file        = "roblox_api.lua",
        required    = false,
        description = "Roblox API monitor",
        deps        = { "EDR" },
        priority    = 60,
    },
    {
        key         = "Vuln",
        file        = "vuln_scanner.lua",
        required    = false,
        description = "Vulnerability scanner",
        deps        = { "EDR" },
        priority    = 55,
    },
    {
        key         = "UI",
        file        = "ui.lua",
        required    = false,
        description = "Mobile UI",
        deps        = { "EDR", "Rules", "Report" },
        priority    = 50,
    },
}

--========== UTILITIES ==========--
local function log(level, msg)
    if level > Main.Config.LOG_LEVEL then return end
    local prefix = "[EDR-MAIN]"
    print(prefix .. " " .. tostring(msg))
    if Main.Config.LOG_TO_FILE and writefile then
        pcall(function()
            local existing = ""
            if isfile and isfile(Main.Config.LOG_FILE) then
                existing = readfile(Main.Config.LOG_FILE) or ""
            end
            writefile(Main.Config.LOG_FILE,
                existing .. os.date("%Y-%m-%d %H:%M:%S ") .. prefix .. " " .. tostring(msg) .. "\n")
        end)
    end
end

local function notify(title, text, duration)
    if not Main.Config.NOTIFY_ON_ALERT then return end
    pcall(function()
        StarterGui:SetCore("SendNotification", {
            Title = title, Text = text, Duration = duration or 5,
        })
    end)
end

local function getParentGui()
    local ok, cg = pcall(function() return CoreGui end)
    if ok and cg then return cg end
    return localPlayer:WaitForChild("PlayerGui")
end

local function safeRequire(url, name)
    log(1, "Loading module: " .. name)
    local ok, result = pcall(function()
        local src = game:HttpGet(url)
        if not src or #src < 100 then
            error("empty or short source: " .. tostring(#src or 0))
        end
        local fn, err = loadstring(src)
        if not fn then error("loadstring failed: " .. tostring(err)) end
        return fn()
    end)
    if not ok then
        log(1, "Module " .. name .. " failed: " .. tostring(result))
        return nil, result
    end
    log(1, "Module " .. name .. " loaded")
    return result
end

local function now() return os.clock() end

--========== ToS COMPLIANCE LAYER ==========--
-- Policy ที่ห้ามละเมิดเด็ดขาด
local ToS = {}

-- Whitelist ของ operations ที่อนุญาต
ToS.ALLOWED_OPERATIONS = {
    "read_service",
    "read_instance",
    "read_property",
    "scan_children",
    "scan_attributes",
    "monitor_signal",
    "emit_event",
    "install_hook",
    "scan_vulnerability",
    "generate_report",
    "dry_run_fuzz",
}

-- Blacklist ของ operations ที่ห้าม (จะ throw error ถ้าเรียก)
ToS.BLOCKED_OPERATIONS = {
    "fire_remote",
    "write_memory",
    "read_memory",
    "dump_source",
    "hook_game_metatable",
    "bypass_byfron",
    "elevate_identity",
    "inject_code",
    "modify_script",
}

function ToS.audit(operation, details)
    if not Main.Config.TOS_AUDIT_ENABLED then return true end

    -- ตรวจสอบ
    for _, blocked in ipairs(ToS.BLOCKED_OPERATIONS) do
        if operation == blocked then
            local entry = {
                t = now(),
                operation = operation,
                details = details,
                action = "BLOCKED",
                reason = "ToS policy violation",
            }
            table.insert(Main.State.audit_log, entry)
            log(1, "ToS BLOCK: " .. operation)

            if Main.Config.ANTIBAN_NOTIFICATION then
                notify("🚫 ToS BLOCK", "Blocked: " .. operation, 5)
            end
            return false
        end
    end

    -- อนุญาต
    local entry = {
        t = now(),
        operation = operation,
        details = details,
        action = "ALLOWED",
    }
    table.insert(Main.State.audit_log, entry)

    if #Main.State.audit_log > Main.Config.TOS_MAX_AUDIT_ENTRIES then
        table.remove(Main.State.audit_log, 1)
    end

    return true
end

function ToS.checkOperation(operation, details)
    return ToS.audit(operation, details)
end

function ToS.getAuditSummary()
    local blocked, allowed = 0, 0
    for _, e in ipairs(Main.State.audit_log) do
        if e.action == "BLOCKED" then blocked = blocked + 1
        else allowed = allowed + 1 end
    end
    return {
        total = #Main.State.audit_log,
        blocked = blocked,
        allowed = allowed,
        recent = (function()
            local out = {}
            local start = math.max(1, #Main.State.audit_log - 20)
            for i = start, #Main.State.audit_log do
                out[#out + 1] = Main.State.audit_log[i]
            end
            return out
        end)(),
    }
end

--========== ANTI-BAN PROTECTION ==========--
local AntiBan = {}

function AntiBan.startSession()
    Main.State.session_id = tostring(os.time()) .. "-" .. tostring(math.random(100000, 999999))
    Main.State.session_start = now()
    log(1, "Session started: " .. Main.State.session_id)
end

function AntiBan.rotateSession()
    if not Main.Config.ANTIBAN_ENABLED then return end

    log(1, "Rotating session (anti-ban)")

    -- Save state
    if Main.Config.SAVE_STATE then
        pcall(Main.saveState)
    end

    -- Reset internal counters (แต่ไม่ reset modules)
    Main.State.stats_cache = {}
    Main.State.audit_log = {}

    -- New session id
    Main.State.session_id = tostring(os.time()) .. "-" .. tostring(math.random(100000, 999999))
    Main.State.session_start = now()

    if Main.Config.ANTIBAN_NOTIFICATION then
        notify("🔄 Session Rotated", "New session ID: " .. Main.State.session_id:sub(1, 16), 3)
    end
end

function AntiBan.behaviorNormalize()
    if not Main.Config.ANTIBAN_BEHAVIOR_NORM then return end

    -- ตรวจสอบ event rate
    if not Main.State.edr then return end

    local rate = Main.State.edr:getRate("NETWORK_REQUEST", 5)
    if rate > Main.Config.ANTIBAN_MAX_NETWORK_SEC then
        log(1, string.format("Behavior: network rate %.1f/s exceeds limit", rate))
        -- ไม่ block แต่แจ้ง
    end

    local totalRate = 0
    for _, ts in pairs(Main.State.edr.timeseries.series) do
        totalRate = totalRate + ts.ema
    end

    if totalRate > Main.Config.ANTIBAN_MAX_EVENTS_SEC then
        log(1, string.format("Behavior: total event rate %.1f/s exceeds limit", totalRate))
    end
end

--========== HEALTH MONITOR ==========--
local Health = {}

function Health.init(name)
    Main.State.module_health[name] = {
        status = "unknown",
        last_ok = nil,
        last_err = nil,
        last_err_time = nil,
        err_count = 0,
        retry_count = 0,
        next_retry = nil,
        installed = false,
        response_time = 0,
    }
end

function Health.markOK(name, responseTime)
    local h = Main.State.module_health[name]
    if not h then Health.init(name); h = Main.State.module_health[name] end
    h.status = "healthy"
    h.last_ok = now()
    h.response_time = responseTime or h.response_time
    -- เพิ่ม health score
    Main.State.health_score = math.min(Main.State.health_score + 1, 100)
end

function Health.markError(name, errMsg)
    local h = Main.State.module_health[name]
    if not h then Health.init(name); h = Main.State.module_health[name] end
    h.status = "error"
    h.last_err = tostring(errMsg):sub(1, 200)
    h.last_err_time = now()
    h.err_count = h.err_count + 1
    -- ลด health score
    Main.State.health_score = math.max(Main.State.health_score - Main.Config.HEALTH_SCORE_DECAY, 0)

    table.insert(Main.State.error_log, {
        t = now(), module = name, message = tostring(errMsg):sub(1, 300),
    })
    if #Main.State.error_log > 200 then
        table.remove(Main.State.error_log, 1)
    end
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
    local backoff = Main.Config.RECOVERY_BACKOFF_BASE * (2 ^ (h.retry_count - 1))
    h.next_retry = now() + backoff
end

function Health.getScore()
    -- คำนวณ health score จาก multiple factors
    local score = 100

    -- ลดตาม errors
    local totalErrors = 0
    for _, h in pairs(Main.State.module_health) do
        totalErrors = totalErrors + (h.err_count or 0)
    end
    score = score - math.min(totalErrors * 2, 40)

    -- ลดตาม audit blocks
    local auditSummary = ToS.getAuditSummary()
    score = score - math.min(auditSummary.blocked * 5, 30)

    -- เพิ่มถ้าทุก module healthy
    local healthyCount = 0
    local totalModules = 0
    for _, h in pairs(Main.State.module_health) do
        totalModules = totalModules + 1
        if h.status == "healthy" then healthyCount = healthyCount + 1 end
    end
    if totalModules > 0 then
        score = score * (healthyCount / totalModules)
    end

    return math.max(0, math.min(100, score))
end

function Health.getReport()
    local report = {}
    for name, h in pairs(Main.State.module_health) do
        report[#report + 1] = {
            name = name,
            status = h.status,
            err_count = h.err_count,
            retry_count = h.retry_count,
            last_ok = h.last_ok,
            last_err = h.last_err,
            installed = h.installed,
        }
    end
    table.sort(report, function(a, b) return a.name < b.name end)
    return report
end

--========== CIRCUIT BREAKER ==========--
local Circuit = {}

function Circuit.init(name)
    Circuit[name] = {
        state = "closed",       -- closed | open | half-open
        fail_count = 0,
        success_count = 0,
        opened_at = 0,
        attempts = 0,
    }
end

function Circuit.canCall(name)
    local c = Circuit[name]
    if not c then Circuit.init(name); c = Circuit[name] end

    if c.state == "closed" then return true end

    if c.state == "open" then
        if now() - c.opened_at >= Main.Config.CIRCUIT_TIMEOUT then
            c.state = "half-open"
            c.attempts = 0
            return true
        end
        return false
    end

    if c.state == "half-open" then
        if c.attempts < Main.Config.CIRCUIT_HALF_OPEN_MAX then
            c.attempts = c.attempts + 1
            return true
        end
        return false
    end

    return true
end

function Circuit.onSuccess(name)
    local c = Circuit[name]
    if not c then Circuit.init(name); c = Circuit[name] end
    c.fail_count = 0
    if c.state == "half-open" then
        c.state = "closed"
    end
end

function Circuit.onFail(name)
    local c = Circuit[name]
    if not c then Circuit.init(name); c = Circuit[name] end
    c.fail_count = c.fail_count + 1
    if c.fail_count >= Main.Config.CIRCUIT_FAIL_THRESHOLD then
        c.state = "open"
        c.opened_at = now()
        log(1, string.format("Circuit breaker OPEN: %s", name))
    end
end

--========== BOOTSTRAP ==========--
function Main.bootstrap()
    if Main.State.booted then return true end

    local base = Main.Config.MODULE_BASE
    if Main.Config.USE_LOCAL then base = "" end

    local modules = {}
    local missing_required = {}

    -- Sort modules by priority (สูงก่อน)
    local sortedRegistry = {}
    for i, entry in ipairs(MODULE_REGISTRY) do
        sortedRegistry[i] = entry
    end
    table.sort(sortedRegistry, function(a, b) return a.priority > b.priority end)

    -- โหลดตามลำดับ priority
    for _, entry in ipairs(sortedRegistry) do
        Health.init(entry.key)
        Circuit.init(entry.key)

        -- ตรวจ dependency
        local depOK = true
        for _, dep in ipairs(entry.deps or {}) do
            if not modules[dep] then
                depOK = false
                log(1, string.format("%s: missing dependency %s", entry.key, dep))
                break
            end
        end

        if not depOK then
            if entry.required then
                table.insert(missing_required, entry.key)
            end
            goto continue
        end

        local loaded = false
        local lastErr = nil

        for attempt = 1, Main.Config.BOOTSTRAP_RETRIES do
            local t0 = now()
            local ok, result = pcall(function()
                return safeRequire(base .. entry.file, entry.key)
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
                if attempt < Main.Config.BOOTSTRAP_RETRIES then
                    task.wait(Main.Config.BOOTSTRAP_RETRY_DELAY)
                end
            end
        end

        if not loaded then
            Health.markError(entry.key, lastErr or "load failed")
            if entry.required then
                table.insert(missing_required, entry.key)
            end
            log(1, string.format("Module %s NOT loaded (%s)", entry.key, entry.description))
        end

        ::continue::
    end

    if #missing_required > 0 then
        return false, "Required modules missing: " .. table.concat(missing_required, ", ")
    end

    Main.State.modules = modules
    Main.State.booted = true
    return true
end

--========== INSTANCES ==========--
function Main.ensureInstances()
    local M = Main.State.modules

    if not Main.State.edr and M.EDR then
        Main.State.edr = M.EDR.get()
    end
    if not Main.State.rules and M.Rules and Main.State.edr then
        Main.State.rules = M.Rules.new(Main.State.edr)
    end
    if not Main.State.report and M.Report and Main.State.edr and Main.State.rules then
        Main.State.report = M.Report.new(Main.State.edr, Main.State.rules)
    end

    return Main.State.edr, Main.State.rules, Main.State.report
end

--========== SUBSYSTEM MANAGEMENT ==========--
function Main.installSubsystem(key)
    local M = Main.State.modules
    local module = M[key]
    if not module then return false, "module not loaded" end

    local edr = Main.State.edr
    if not edr then return false, "edr not available" end

    -- ToS audit
    if not ToS.checkOperation("install_hook", { module = key }) then
        return false, "ToS policy blocked"
    end

    if not Circuit.canCall(key) then
        return false, "circuit breaker open"
    end

    local ok, err = pcall(function()
        if module.install then
            module.install(edr)
        end
    end)

    if ok then
        local h = Main.State.module_health[key]
        if h then h.installed = true end
        Health.markOK(key)
        Circuit.onSuccess(key)
        return true
    else
        Health.markError(key, err)
        Circuit.onFail(key)
        return false, err
    end
end

function Main.uninstallSubsystem(key)
    local module = Main.State.modules[key]
    if not module or not module.uninstall then return end
    pcall(function() module.uninstall() end)
    local h = Main.State.module_health[key]
    if h then h.installed = false end
end

--========== RECOVERY UNIT v3 ==========--
local function recoveryUnitTick()
    if not Main.State.running then return end
    local M = Main.State.modules
    local t = now()
    local repairs = 0

    -- 1. Hooks ถูกถอดไหม
    if M.Hooks and M.Hooks.isInstalled then
        local h = Main.State.module_health.Hooks
        if h and h.installed then
            local stillInstalled = M.Hooks.isInstalled()
            if not stillInstalled then
                log(1, "Recovery: Hooks removed, reinstalling...")
                if Circuit.canCall("Hooks") then
                    local ok = pcall(function() M.Hooks.install(Main.State.edr) end)
                    if ok then
                        Health.markOK("Hooks")
                        Circuit.onSuccess("Hooks")
                        repairs = repairs + 1
                    else
                        Circuit.onFail("Hooks")
                    end
                end
            end
        end
    end

    -- 2. Monitor loop ยังไหวไหม
    if Main.State.running and not Main.State.paused then
        local lastTick = Main.State.last_tick or 0
        if t - lastTick > 30 then
            log(1, "Recovery: Monitor loop appears stuck, restarting...")
            Main.State.monitor_thread = nil
            pcall(Main.startMonitorLoop)
            repairs = repairs + 1
        end
    end

    -- 3. Dashboard ยังอยู่ไหม
    if Main.Config.PREFER_UI_MODULE and Main.State.dashboard then
        local d = Main.State.dashboard
        if not d.gui or not d.gui.Parent then
            log(1, "Recovery: Dashboard destroyed, rebuilding...")
            Main.State.dashboard = nil
            Main.State.gui = nil
            pcall(Main.buildDashboard)
            repairs = repairs + 1
        end
    end

    -- 4. EDR watchdog
    if Main.State.edr and Main.State.running then
        if not Main.State.edr.watchdog then
            log(1, "Recovery: EDR watchdog stopped, restarting...")
            pcall(function() Main.State.edr:startWatchdog() end)
            repairs = repairs + 1
        end
    end

    -- 5. UI update loop
    if Main.State.dashboard and Main.State.dashboard._updateThread == nil then
        log(1, "Recovery: UI update loop stopped, restarting...")
        pcall(function() Main.State.dashboard:startUpdateLoop() end)
        repairs = repairs + 1
    end

    -- 6. Rules engine
    if M.Rules and Main.State.rules then
        local h = Main.State.module_health.Rules
        if h and h.status == "error" and Health.canRetry("Rules") then
            log(1, "Recovery: Rules engine in error state, retrying...")
            local ok = pcall(function() M.Rules.new(Main.State.edr) end)
            if ok then
                Health.markOK("Rules")
                repairs = repairs + 1
            else
                Health.scheduleRetry("Rules")
            end
        end
    end

    -- 7. Anti-Ban session rotation
    if Main.Config.ANTIBAN_ENABLED then
        if t - Main.State.session_start >= Main.Config.ANTIBAN_SESSION_ROTATE then
            AntiBan.rotateSession()
            repairs = repairs + 1
        end
    end

    -- 8. Behavior normalization
    if Main.Config.ANTIBAN_BEHAVIOR_NORM then
        AntiBan.behaviorNormalize()
    end

    if repairs > 0 then
        Main.State.recovered = Main.State.recovered + repairs
        log(1, string.format("Recovery Unit: %d repairs (total: %d)",
            repairs, Main.State.recovered))
    end
end

function Main.startRecoveryUnit()
    if not Main.Config.RECOVERY_ENABLED then return end
    if Main.State.recovery_thread then return end

    Main.State.recovery_thread = task.spawn(function()
        while Main.State.running do
            task.wait(Main.Config.RECOVERY_INTERVAL)
            local ok, err = pcall(recoveryUnitTick)
            if not ok then
                Health.markError("RecoveryUnit", err)
            end
        end
    end)

    log(1, "Recovery Unit started")
end

--========== START / STOP ==========--
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

    if not Main.State.edr then
        notify("❌ EDR", "EDR core not available", 8)
        return false
    end

    -- Anti-Ban session start
    AntiBan.startSession()

    -- Alert callback
    Main.State.edr.onAlert = function(alert)
        Main.onAlert(alert)
    end

    -- Capture before
    if Main.State.report and Main.State.report.captureBefore then
        pcall(function() Main.State.report:captureBefore() end)
    end

    -- Install subsystems (ตามลำดับ)
    for _, key in ipairs({ "Hooks", "RobloxAPI", "Vuln" }) do
        if M[key] then
            Main.installSubsystem(key)
        end
    end

    -- EDR watchdog
    pcall(function() Main.State.edr:startWatchdog() end)

    -- Reset state
    Main.State.running = true
    Main.State.paused = false
    Main.State.killed = false
    Main.State.start_time = now()
    Main.State.last_tick = now()
    Main.State.tick_count = 0
    Main.State._warned_high = false

    -- Start threads
    Main.startMonitorLoop()
    Main.startRecoveryUnit()

    log(1, "EDR STARTED")
    notify("🛡️ EDR v" .. Main.VERSION, "เริ่มเฝ้าระวังแล้ว", 5)

    if Main.State.dashboard and Main.State.dashboard.forceRefresh then
        pcall(function() Main.State.dashboard:forceRefresh() end)
    end

    return true
end

function Main.stop(reason)
    if not Main.State.running then return end

    Main.State.running = false

    -- Uninstall subsystems
    for _, key in ipairs({ "Hooks", "RobloxAPI", "Vuln" }) do
        pcall(function() Main.uninstallSubsystem(key) end)
    end

    if Main.State.edr then
        pcall(function() Main.State.edr:stopWatchdog() end)
    end

    if Main.State.report and Main.Config.AUTO_REPORT then
        pcall(function()
            Main.State.report:finalize()
            Main.saveReport()
        end)
    end

    log(1, "EDR STOPPED: " .. tostring(reason or "user"))
    notify("🛡️ EDR", "หยุดเฝ้าระวัง", 5)

    if Main.State.dashboard and Main.State.dashboard.forceRefresh then
        pcall(function() Main.State.dashboard:forceRefresh() end)
    end
end

function Main.pause()
    Main.State.paused = true
    log(1, "EDR PAUSED")
end

function Main.resume()
    Main.State.paused = false
    log(1, "EDR RESUMED")
end

--========== KILL SWITCH ==========--
function Main.kill(reason)
    if Main.State.killed then return end
    Main.State.killed = true
    Main.State.running = false

    log(1, "KILL SWITCH: " .. tostring(reason))

    Main.showKillOverlay(reason)

    local M = Main.State.modules
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

    if Main.State.dashboard and Main.State.dashboard.forceRefresh then
        pcall(function() Main.State.dashboard:forceRefresh() end)
    end
end

function Main.showKillOverlay(reason)
    local parentGui = getParentGui()
    local gui = Instance.new("ScreenGui")
    gui.Name = "EDR_KillOverlay_" .. tostring(math.random(1000, 9999))
    gui.ResetOnSpawn = false
    gui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
    gui.DisplayOrder = 9999
    gui.Parent = parentGui

    local frame = Instance.new("Frame")
    frame.Size = UDim2.new(0, 480, 0, 220)
    frame.Position = UDim2.new(0.5, -240, 0.5, -110)
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
    msg.Text = tostring(reason or "ระบบตรวจพบความเสี่ยงสูง")
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
    close.Text = "ปิดข้อความนี้"
    close.TextColor3 = Color3.fromRGB(255, 255, 255)
    close.Font = Enum.Font.GothamBold
    close.TextSize = 14
    close.Parent = frame
    Instance.new("UICorner", close).CornerRadius = UDim.new(0, 8)
    close.MouseButton1Click:Connect(function() gui:Destroy() end)
end

--========== MONITOR LOOP ==========--
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

            -- EMA smoothing
            local alpha = Main.Config.ADAPTIVE_ALPHA
            Main.State.adaptive_interval =
                alpha * interval + (1 - alpha) * (Main.State.adaptive_interval or interval)

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
                Health.markError("MonitorLoop", waitTime)
                break
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

    -- 1. Rules scan
    if Main.State.rules then
        local ok, err = pcall(function() Main.State.rules:scan() end)
        if not ok then Health.markError("Rules", err)
        else Health.markOK("Rules") end
    end

    -- 2. Report update
    if Main.State.report then
        local ok, err = pcall(function() Main.State.report:update() end)
        if not ok then Health.markError("Report", err)
        else Health.markOK("Report") end
    end

    -- 3. Compute risk
    local risk = 0
    if M.Rules and Main.State.edr then
        local ok, r = pcall(function()
            return M.Rules.computeSessionRisk(Main.State.edr.alerts)
        end)
        if ok and type(r) == "number" then risk = r end
    end

    -- 4. Kill switch
    if Main.Config.KILL_SWITCH_ENABLED then
        if risk >= Main.Config.KILL_THRESHOLD then
            Main.kill(string.format(
                "Risk %.1f%% exceeded %.1f%%",
                risk * 100, Main.Config.KILL_THRESHOLD * 100))
        elseif risk >= Main.Config.WARN_THRESHOLD and not Main.State._warned_high then
            Main.State._warned_high = true
            notify("⚠️ EDR", string.format("ความเสี่ยงสูง: %.1f%%", risk * 100), 6)
        end
    end

    -- 5. GUI update
    if Main.State.gui and Main.State.gui.update then
        pcall(Main.State.gui.update)
    end
end

--========== ALERT HANDLER ==========--
function Main.onAlert(alert)
    table.insert(Main.State.command_log, {
        t = now(), alert = alert,
    })
    if #Main.State.command_log > 500 then
        table.remove(Main.State.command_log, 1)
    end

    local sev = alert.severity or 0
    if sev >= (Main.Config.NOTIFY_SEVERITY_MIN or 3) then
        notify(
            string.format("%s %s", sev >= 4 and "🔴" or "🟠", alert.rule or "ALERT"),
            tostring(alert.message or ""):sub(1, 120),
            5
        )
    end
end

--========== SAVE REPORT ==========--
function Main.saveReport()
    if not Main.Config.AUTO_SAVE_REPORT then return end
    if not Main.State.report then return end

    local path = "edr_report_" .. os.date("%Y%m%d_%H%M%S") .. "." ..
        (Main.Config.AUTO_REPORT_FORMAT == "json" and "json"
         or Main.Config.AUTO_REPORT_FORMAT == "html" and "html"
         or "md")

    local ok, err = pcall(function()
        return Main.State.report:saveToFile(path, Main.Config.AUTO_REPORT_FORMAT)
    end)
    if ok then
        log(1, "Report saved: " .. path)
        notify("📄 EDR Report", "บันทึก: " .. path, 6)
    else
        log(1, "Report save failed: " .. tostring(err))
    end
end

--========== STATE PERSISTENCE ==========--
function Main.saveState()
    if not Main.Config.SAVE_STATE then return end
    if not writefile then return end

    local state = {
        version = Main.VERSION,
        session_id = Main.State.session_id,
        saved_at = os.time(),
        health_score = Health.getScore(),
        stats = Main.State.edr and Main.State.edr:summary() or {},
        health = Health.getReport(),
        recovered = Main.State.recovered,
        audit = ToS.getAuditSummary(),
    }
    pcall(function()
        writefile(Main.Config.STATE_FILE, game:GetService("HttpService"):JSONEncode(state))
    end)
end

function Main.loadState()
    if not Main.Config.SAVE_STATE then return end
    if not readfile or not isfile then return end
    pcall(function()
        if isfile(Main.Config.STATE_FILE) then
            local raw = readfile(Main.Config.STATE_FILE)
            local state = game:GetService("HttpService"):JSONDecode(raw)
            log(1, "State loaded: v" .. tostring(state.version or "?"))
        end
    end)
end

--========== COMMANDS ==========--
local COMMANDS = {}

COMMANDS.help = function()
    return [[
คำสั่งทั้งหมด:
  === ควบคุม ===
  /help            คำสั่งทั้งหมด
  /start           เริ่ม
  /stop            หยุด
  /pause           พัก
  /resume          ต่อ
  /kill            บังคับ kill switch
  /version         เวอร์ชัน

  === สถานะ ===
  /status          สถานะรวม
  /health          สุขภาพทุก module
  /score           health score
  /errors          error ล่าสุด
  /recover         บังคับซ่อม

  === ข้อมูล ===
  /risk            ความเสี่ยงปัจจุบัน
  /alerts          alerts ล่าสุด
  /ioc             IOC
  /vulns           ช่องโหว่
  /rbxstats        สถิติ Roblox API
  /timeline        timeline
  /summary         สรุป session

  === ToS ===
  /audit           log การตรวจสอบ
  /policy          นโยบายปัจจุบัน

  === อื่นๆ ===
  /report          สร้าง report
  /ui              ซ่อน/แสดง UI
  /min             ย่อ UI
  /clear           ล้าง log
]]
end

COMMANDS.status = function()
    local s = Main.State
    return string.format(
        "Version:    %s\nRunning:    %s\nPaused:     %s\nKilled:     %s\nRecovered:  %d\nUptime:     %.1fs\nTicks:      %d\nEvents:     %d\nAlerts:     %d\nErrors:     %d\nHealth:     %d/100",
        Main.VERSION,
        tostring(s.running), tostring(s.paused), tostring(s.killed),
        s.recovered,
        s.start_time and (now() - s.start_time) or 0,
        s.tick_count,
        s.edr and s.edr.session.events_processed or 0,
        s.edr and #(s.edr.alerts or {}) or 0,
        #s.error_log,
        Health.getScore()
    )
end

COMMANDS.health = function()
    local report = Health.getReport()
    local lines = { "MODULE HEALTH (score=" .. Health.getScore() .. "/100)" }
    for _, r in ipairs(report) do
        local icon = r.status == "healthy" and "✓"
            or r.status == "error" and "✗" or "?"
        lines[#lines + 1] = string.format("%s %-12s %-8s err=%-3d retry=%-2d installed=%s",
            icon, r.name, r.status, r.err_count or 0, r.retry_count or 0,
            tostring(r.installed))
    end
    return table.concat(lines, "\n")
end

COMMANDS.score = function()
    return string.format("Health Score: %d/100", Health.getScore())
end

COMMANDS.audit = function()
    local summary = ToS.getAuditSummary()
    local lines = {
        string.format("Total:   %d", summary.total),
        string.format("Allowed: %d", summary.allowed),
        string.format("Blocked: %d", summary.blocked),
        "",
        "Recent (last 10):",
    }
    local start = math.max(1, #Main.State.audit_log - 10)
    for i = start, #Main.State.audit_log do
        local e = Main.State.audit_log[i]
        local icon = e.action == "BLOCKED" and "🚫" or "✓"
        lines[#lines + 1] = string.format("%s [%.1fs] %s", icon, e.t, e.operation)
    end
    return table.concat(lines, "\n")
end

COMMANDS.policy = function()
    return [[
นโยบาย ToS Compliance (ห้ามละเมิด):
  ❌ fire_remote         (ห้าม fire RemoteEvent)
  ❌ write_memory        (ห้ามเขียน memory)
  ❌ read_memory         (ห้ามอ่าน memory)
  ❌ dump_source         (ห้ามดึง source code)
  ❌ hook_game_metatable (ห้าม hook metatable ของ game)
  ❌ bypass_byfron       (ห้าม bypass anticheat)
  ❌ elevate_identity    (ห้ามยกระดับ thread identity)
  ❌ inject_code         (ห้าม inject code)
  ❌ modify_script       (ห้ามแก้ไข script)

  ✅ read_service        (อ่าน service)
  ✅ read_instance       (อ่าน instance)
  ✅ read_property       (อ่าน property)
  ✅ scan_children       (สำรวจ children)
  ✅ scan_attributes     (สำรวจ attributes)
  ✅ monitor_signal      (ติดตาม signal)
  ✅ emit_event          (emit event ภายใน)
  ✅ install_hook        (ติดตั้ง hook ผ่าน API ปกติ)
  ✅ scan_vulnerability  (สแกนช่องโหว่)
  ✅ generate_report     (สร้าง report)
  ✅ dry_run_fuzz        (fuzz แบบ dry run)
]]
end

COMMANDS.errors = function()
    local lines = {}
    local start = math.max(1, #Main.State.error_log - 10)
    for i = start, #Main.State.error_log do
        local e = Main.State.error_log[i]
        lines[#lines + 1] = string.format("[%.1fs] %s: %s",
            e.t, e.module, e.message:sub(1, 80))
    end
    return #lines > 0 and table.concat(lines, "\n") or "No errors"
end

COMMANDS.recover = function()
    log(1, "Manual recovery")
    local ok, err = pcall(recoveryUnitTick)
    if ok then
        return string.format("Recovery done (total: %d)", Main.State.recovered)
    else
        return "Recovery error: " .. tostring(err)
    end
end

COMMANDS.start  = function() Main.start(); return "Started" end
COMMANDS.stop   = function() Main.stop("command"); return "Stopped" end
COMMANDS.pause  = function() Main.pause(); return "Paused" end
COMMANDS.resume = function() Main.resume(); return "Resumed" end

COMMANDS.risk = function()
    local M = Main.State.modules
    if not M.Rules or not Main.State.edr then return "No data" end
    local risk = M.Rules.computeSessionRisk(Main.State.edr.alerts)
    return string.format("Current risk: %.2f%%", risk * 100)
end

COMMANDS.alerts = function()
    local alerts = Main.State.edr and Main.State.edr.alerts or {}
    local lines = {}
    local start = math.max(1, #alerts - 10)
    for i = start, #alerts do
        local a = alerts[i]
        lines[#lines + 1] = string.format("[%s] %s (%.2f)",
            a.rule or "?", tostring(a.message or ""):sub(1, 80), a.score or 0)
    end
    return #lines > 0 and table.concat(lines, "\n") or "No alerts"
end

COMMANDS.ioc = function()
    if not Main.State.report then return "No report" end
    local iocs = Main.State.report.ioc:getAll()
    local lines = {}
    for i = 1, math.min(20, #iocs) do
        local ioc = iocs[i]
        lines[#lines + 1] = string.format("[%s] %s (×%d)",
            ioc.type, ioc.value:sub(1, 60), ioc.count)
    end
    return #lines > 0 and table.concat(lines, "\n") or "No IOC"
end

COMMANDS.vulns = function()
    local M = Main.State.modules
    if not M.Vuln or not M.Vuln.getSummary then return "Vuln scanner not ready" end
    local sum = M.Vuln.getSummary()
    local lines = {
        string.format("Total: %d", sum.total),
        string.format("Critical: %d", sum.by_sev[4] or 0),
        string.format("High: %d", sum.by_sev[3] or 0),
        string.format("Medium: %d", sum.by_sev[2] or 0),
        string.format("Attack Surface Score: %d/100", sum.attackSurface and sum.attackSurface.score or 0),
    }
    local top = M.Vuln.getTopFindings(5)
    for i, f in ipairs(top) do
        lines[#lines + 1] = string.format("%d. [%s] %s", i, f.category, f.title)
    end
    return table.concat(lines, "\n")
end

COMMANDS.rbxstats = function()
    local M = Main.State.modules
    if not M.RobloxAPI or not M.RobloxAPI.getStats then return "Roblox API not ready" end
    local s = M.RobloxAPI.getStats()
    local lines = {
        string.format("Instances: created=%d destroyed=%d tracked=%d",
            s.instances.create, s.instances.destroy, s.instances.tracked),
        string.format("Properties: changes=%d", s.properties.changes),
        string.format("Services: accessed=%d", s.services.accessed),
        string.format("Remotes: found=%d", s.remotes.found),
        string.format("Sampling: rate=%.2f kept=%d dropped=%d",
            s.sampling.rate, s.sampling.kept, s.sampling.dropped),
    }
    return table.concat(lines, "\n")
end

COMMANDS.timeline = function()
    if not Main.State.report then return "No report" end
    return Main.State.report.timeline:renderASCII()
end

COMMANDS.report = function()
    Main.saveReport()
    return "Report generated"
end

COMMANDS.summary = function()
    if not Main.State.edr then return "No data" end
    local s = Main.State.edr:summary()
    return string.format(
        "Session: %s\nElapsed: %.1fs\nEvents:  %d\nAlerts:  %d\nDropped: %d\nRecovered: %d\nHealth: %d/100",
        s.session_id, s.elapsed, s.events, s.alerts, s.dropped,
        Main.State.recovered, Health.getScore())
end

COMMANDS.ui = function()
    return Main.toggleUI()
end

COMMANDS.min = function()
    return Main.minimizeUI()
end

COMMANDS.kill = function()
    Main.kill("Manual kill")
    return "Killed"
end

COMMANDS.version = function()
    return string.format("EDR Main v%s (build %s)", Main.VERSION, Main.BUILD)
end

COMMANDS.clear = function()
    Main.State.command_log = {}
    return "Cleared"
end

function Main.executeCommand(input)
    input = tostring(input or ""):gsub("^%s+", ""):gsub("%s+$", "")
    if input == "" then return end

    local cmdLine = input:gsub("^/", "")
    local cmd, args = cmdLine:match("^(%S+)%s*(.*)$")
    cmd = cmd and cmd:lower()
    if not cmd then return end

    local fn = COMMANDS[cmd]
    if not fn then
        return "ไม่รู้จัก: " .. tostring(cmd) .. " (ลอง /help)"
    end

    local ok, result = pcall(fn, args)
    if not ok then
        return "Error: " .. tostring(result)
    end
    return result
end

--========== UI TOGGLE ==========--
function Main.toggleUI()
    local d = Main.State.dashboard
    if not d then return "No dashboard" end
    if d.minimized then
        if d.maximize then d:maximize() end
        return "UI: shown"
    else
        if d.minimize then d:minimize() end
        return "UI: hidden"
    end
end

function Main.minimizeUI()
    local d = Main.State.dashboard
    if not d then return "No dashboard" end
    if d.minimize then d:minimize() end
    return "UI: minimized"
end

--========== BUILD DASHBOARD ==========--
function Main.buildDashboard()
    local UI = Main.State.modules.UI
    if not UI then return false, "UI module not loaded" end

    Main.ensureInstances()

    local dashboard
    local ok, err = pcall(function()
        dashboard = UI.new(
            Main.State.edr,
            Main.State.rules,
            Main.State.report,
            Main
        )
    end)

    if not ok or not dashboard then
        return false, tostring(err)
    end

    Main.State.dashboard = dashboard

    if dashboard.attachToEDR then
        pcall(function() dashboard:attachToEDR() end)
    end

    if dashboard.show then
        pcall(function() dashboard:show() end)
    end

    Main.State.gui = {
        screen = dashboard.gui,
        update = function()
            if dashboard.update then pcall(function() dashboard:update() end) end
        end,
    }

    return true
end

--========== FALLBACK GUI ==========--
function Main.buildGUI()
    if not Main.Config.GUI_ENABLED then return end
    if Main.State.gui and Main.State.gui.screen then return end

    local parentGui = getParentGui()
    local gui = Instance.new("ScreenGui")
    gui.Name = "EDR_Main_" .. tostring(math.random(1000, 9999))
    gui.ResetOnSpawn = false
    gui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
    gui.Parent = parentGui

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
    title.Text = "  🛡️  EDR v" .. Main.VERSION .. " (Fallback)"
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
    list.SortOrder = Enum.SortOrder.LayoutOrder

    local cmdBox = Instance.new("TextBox")
    cmdBox.Size = UDim2.new(1, -20, 0, 30)
    cmdBox.Position = UDim2.new(0, 10, 1, -40)
    cmdBox.BackgroundColor3 = Color3.fromRGB(22, 27, 34)
    cmdBox.BorderSizePixel = 0
    cmdBox.PlaceholderText = "พิมพ์คำสั่ง (เช่น /help)"
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
        lbl.LayoutOrder = #console:GetChildren()
    end

    cmdBox.FocusLost:Connect(function(enter)
        if not enter then return end
        local text = cmdBox.Text
        cmdBox.Text = ""
        if text == "" then return end
        appendConsole("› " .. text, Color3.fromRGB(88, 166, 255))
        local result = Main.executeCommand(text)
        if result and result ~= "" then
            for line in tostring(result):gmatch("[^\n]+") do
                appendConsole(line, Color3.fromRGB(180, 220, 180))
            end
        end
    end)

    local function update()
        if not gui.Parent then return end
        local stateText, stateColor
        if Main.State.killed then
            stateText, stateColor = "🔴 KILLED", Color3.fromRGB(248, 81, 73)
        elseif Main.State.paused then
            stateText, stateColor = "🟡 PAUSED", Color3.fromRGB(210, 153, 34)
        elseif Main.State.running then
            stateText, stateColor = "🟢 RUNNING", Color3.fromRGB(126, 231, 135)
        else
            stateText, stateColor = "⚪ STOPPED", Color3.fromRGB(200, 90, 90)
        end
        statusLbl.Text = stateText
        statusLbl.TextColor3 = stateColor
        infoLbl.Text = string.format(
            "Health: %d/100 | Recovered: %d | Events: %d",
            Health.getScore(), Main.State.recovered,
            Main.State.edr and Main.State.edr.session.events_processed or 0)
    end

    Main.State.gui = { screen = gui, update = update, appendConsole = appendConsole }

    appendConsole("EDR Fallback v" .. Main.VERSION, Color3.fromRGB(88, 166, 255))
    appendConsole("พิมพ์ /help", Color3.fromRGB(150, 170, 190))

    task.spawn(function()
        while gui.Parent do
            task.wait(1)
            pcall(update)
        end
    end)
end

--========== ENTRY POINT ==========--
function Main.init()
    log(1, "Initializing EDR Main v" .. Main.VERSION)

    Main.loadState()

    local ok, err = Main.bootstrap()
    if not ok then
        log(1, "Bootstrap failed: " .. tostring(err))
        notify("❌ EDR", "โหลด modules ไม่สำเร็จ", 10)
        return false
    end

    Main.ensureInstances()

    -- Load UI
    local uiOK = false
    if Main.State.modules.UI then
        local success, dashErr = Main.buildDashboard()
        if success then
            uiOK = true
        else
            log(1, "Dashboard failed: " .. tostring(dashErr))
            Main.State.dashboard = nil
            Main.State.gui = nil
        end
    end

    if not uiOK then
        log(1, "Using fallback GUI")
        Main.buildGUI()
    end

    -- Save state loop
    if Main.Config.SAVE_STATE and task and task.spawn then
        task.spawn(function()
            while true do
                task.wait(60)
                pcall(Main.saveState)
            end
        end)
    end

    log(1, "Initialized (UI=" .. (uiOK and "ui.lua" or "fallback") .. ")")
    notify("🛡️ EDR v" .. Main.VERSION, "ToS-Compliant Mode", 5)

    return true
end

-- Auto-init
task.spawn(function()
    task.wait(0.1)
    pcall(Main.init)
end)

--========== EXPORT ==========--
Main.log            = log
Main.notify         = notify
Main.executeCommand = Main.executeCommand
Main.toggleUI       = Main.toggleUI
Main.minimizeUI     = Main.minimizeUI
Main.Health         = Health
Main.ToS            = ToS
Main.AntiBan        = AntiBan
Main.Circuit        = Circuit

if getgenv then
    pcall(function() getgenv().EDRMain = Main end)
end
_G.EDRMain = Main

return Main
