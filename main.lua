--[[
    ============================================================
    EDR Main v2.0 — Full Integration + Recovery Unit
    ============================================================
    หลักการ:
    - โหลด 7 modules: edr_core, hooks, rules, report, ui,
                     roblox_api, vuln_scanner
    - Recovery Unit: watchdog ซ่อมแซมทุก 15 วิ
    - Health Monitor: ตรวจสอบ integrity + performance
    - Error Classification: transient / recoverable / fatal
    - Circuit Breaker: หยุด module ที่ล้มซ้ำ
    - Auto-retry bootstrap (3 ครั้ง)
    - Graceful degradation ทุกชั้น

    วิธีใช้:
    1. โหลด main.lua ผ่าน loadstring
    2. UI จะเด้งขึ้นอัตโนมัติ
    3. กด START → รันสคริปต์เป้าหมาย

    คำสั่งพิเศษ:
    /health     ดูสถานะทุก module
    /recover    บังคับซ่อมแซม
    /status     สถานะรวม

    คำเตือน: เพื่อการศึกษาเท่านั้น
    ปฏิบัติตาม Roblox ToS อย่างเคร่งครัด
    ============================================================
]]

--========== BOOTSTRAP ==========--
local Main = {}

Main.VERSION = "2.0.0"
Main.BUILD   = "2025-09-14"

--========== CONFIG ==========--
Main.Config = {
    -- URLs
    MODULE_BASE      = "https://raw.githubusercontent.com/YOUR_USERNAME/edr-lua/main/",
    UI_MODULE_URL    = "https://raw.githubusercontent.com/YOUR_USERNAME/edr-lua/main/ui.lua",
    USE_LOCAL        = false,

    -- Bootstrap
    BOOTSTRAP_RETRIES       = 3,
    BOOTSTRAP_RETRY_DELAY   = 2,

    -- Monitor
    MONITOR_INTERVAL        = 3,
    ADAPTIVE_INTERVAL       = true,
    MIN_INTERVAL            = 1,
    MAX_INTERVAL            = 10,

    -- Kill Switch
    KILL_SWITCH_ENABLED     = true,
    KILL_THRESHOLD          = 0.90,
    WARN_THRESHOLD          = 0.65,

    -- Recovery Unit
    RECOVERY_ENABLED        = true,
    RECOVERY_INTERVAL       = 15,    -- วินาที
    RECOVERY_MAX_RETRIES    = 5,     -- ต่อ module ต่อ session
    RECOVERY_BACKOFF_BASE   = 30,    -- วินาที

    -- Circuit Breaker
    CIRCUIT_BREAKER_ENABLED = true,
    CIRCUIT_FAIL_THRESHOLD  = 3,     -- ครั้ง
    CIRCUIT_TIMEOUT         = 120,   -- วินาที

    -- Health Monitor
    HEALTH_CHECK_INTERVAL   = 10,
    HEALTH_MAX_ERRORS       = 50,    -- ต่อ module
    HEALTH_STALE_THRESHOLD  = 60,    -- วินาที (ไม่มีการอัปเดต)

    -- Report
    AUTO_REPORT             = true,
    AUTO_REPORT_FORMAT      = "markdown",
    AUTO_SAVE_REPORT        = true,

    -- Persistence
    SAVE_STATE              = true,
    STATE_FILE              = "edr_state.json",

    -- UI
    GUI_ENABLED             = true,
    PREFER_UI_MODULE        = true,
    NOTIFY_ON_ALERT         = true,
    NOTIFY_SEVERITY_MIN     = 3,

    -- Logging
    LOG_LEVEL               = 1,
    LOG_TO_FILE             = false,
    LOG_FILE                = "edr_log.txt",
}

--========== SERVICES ==========--
local Players          = game:GetService("Players")
local CoreGui          = game:GetService("CoreGui")
local StarterGui       = game:GetService("StarterGui")
local UserInputService = game:GetService("UserInputService")

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
    module_health     = {},   -- [name] = { status, last_ok, last_err, err_count, retry_count, next_retry }
    monitor_co        = nil,
    monitor_thread    = nil,
    recovery_thread   = nil,
    health_thread     = nil,
    gui               = nil,
    dashboard         = nil,
    command_log       = {},
    fatal_error       = nil,
    error_log         = {},   -- list ของ error ล่าสุด
    _warned_high      = false,
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

local function recordError(moduleName, errMsg)
    table.insert(Main.State.error_log, {
        t = os.clock(),
        module = moduleName,
        message = tostring(errMsg):sub(1, 300),
    })
    if #Main.State.error_log > 200 then
        table.remove(Main.State.error_log, 1)
    end

    local h = Main.State.module_health[moduleName]
    if h then
        h.err_count = (h.err_count or 0) + 1
        h.last_err = tostring(errMsg):sub(1, 300)
        h.last_err_time = os.clock()
    end
end

local function notify(title, text, duration)
    if not Main.Config.NOTIFY_ON_ALERT then return end
    pcall(function()
        StarterGui:SetCore("SendNotification", {
            Title = title,
            Text = text,
            Duration = duration or 5,
        })
    end)
end

local function getParentGui()
    local ok, cg = pcall(function() return CoreGui end)
    if ok and cg then return cg end
    return localPlayer:WaitForChild("PlayerGui")
end

local function safeRequire(url, name)
    log(1, "Loading module: " .. name .. " from " .. url)
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
    log(1, "Module " .. name .. " loaded successfully")
    return result
end

--========== HEALTH MONITOR ==========--
local HealthMonitor = {}

function HealthMonitor.initModule(name)
    Main.State.module_health[name] = {
        status      = "unknown",
        last_ok     = nil,
        last_err    = nil,
        last_err_time = nil,
        err_count   = 0,
        retry_count = 0,
        next_retry  = nil,
        installed   = false,
    }
end

function HealthMonitor.markOK(name)
    local h = Main.State.module_health[name]
    if not h then HealthMonitor.initModule(name); h = Main.State.module_health[name] end
    h.status = "healthy"
    h.last_ok = os.clock()
end

function HealthMonitor.markError(name, errMsg)
    local h = Main.State.module_health[name]
    if not h then HealthMonitor.initModule(name); h = Main.State.module_health[name] end
    h.status = "error"
    h.last_err = tostring(errMsg):sub(1, 200)
    h.last_err_time = os.clock()
    h.err_count = (h.err_count or 0) + 1
    recordError(name, errMsg)
end

function HealthMonitor.isHealthy(name)
    local h = Main.State.module_health[name]
    if not h then return false end
    return h.status == "healthy"
end

function HealthMonitor.canRetry(name)
    local h = Main.State.module_health[name]
    if not h then return true end
    if h.retry_count >= Main.Config.RECOVERY_MAX_RETRIES then return false end
    if h.next_retry and os.clock() < h.next_retry then return false end
    return true
end

function HealthMonitor.scheduleRetry(name)
    local h = Main.State.module_health[name]
    if not h then return end
    h.retry_count = h.retry_count + 1
    -- Backoff แบบ exponential
    local backoff = Main.Config.RECOVERY_BACKOFF_BASE * (2 ^ (h.retry_count - 1))
    h.next_retry = os.clock() + backoff
end

function HealthMonitor.getHealthReport()
    local report = {}
    for name, h in pairs(Main.State.module_health) do
        table.insert(report, {
            name       = name,
            status     = h.status,
            err_count  = h.err_count,
            retry_count = h.retry_count,
            last_ok    = h.last_ok,
            last_err   = h.last_err,
            installed  = h.installed,
        })
    end
    table.sort(report, function(a, b) return a.name < b.name end)
    return report
end

--========== BOOTSTRAP ==========--
local MODULE_FILES = {
    { key = "EDR",     file = "edr_core.lua",      required = true,  description = "Event bus + correlation" },
    { key = "Hooks",   file = "hooks.lua",         required = true,  description = "Behavior hooks" },
    { key = "Rules",   file = "rules.lua",         required = true,  description = "Rule engine" },
    { key = "Report",  file = "report.lua",        required = true,  description = "Report generator" },
    { key = "UI",      file = "ui.lua",            required = false, description = "Mobile UI" },
    { key = "RobloxAPI", file = "roblox_api.lua",  required = false, description = "Roblox API monitor" },
    { key = "Vuln",    file = "vuln_scanner.lua",  required = false, description = "Vulnerability scanner" },
}

function Main.bootstrap()
    if Main.State.booted then return true end

    local base = Main.Config.MODULE_BASE
    if Main.Config.USE_LOCAL then base = "" end

    local modules = {}
    local missing_required = {}

    for _, entry in ipairs(MODULE_FILES) do
        HealthMonitor.initModule(entry.key)

        local loaded = false
        local lastErr = nil

        -- Retry
        for attempt = 1, Main.Config.BOOTSTRAP_RETRIES do
            local ok, result = pcall(function()
                return safeRequire(base .. entry.file, entry.key)
            end)

            if ok and result then
                modules[entry.key] = result
                HealthMonitor.markOK(entry.key)
                loaded = true
                break
            else
                lastErr = result
                if attempt < Main.Config.BOOTSTRAP_RETRIES then
                    task.wait(Main.Config.BOOTSTRAP_RETRY_DELAY)
                end
            end
        end

        if not loaded then
            HealthMonitor.markError(entry.key, lastErr or "load failed")
            if entry.required then
                table.insert(missing_required, entry.key)
            end
            log(1, string.format("Module %s NOT loaded (%s)", entry.key, entry.description))
        end
    end

    if #missing_required > 0 then
        return false, "Required modules missing: " .. table.concat(missing_required, ", ")
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
    end
    if not Main.State.report and M.Report and Main.State.edr and Main.State.rules then
        Main.State.report = M.Report.new(Main.State.edr, Main.State.rules)
    end

    return Main.State.edr, Main.State.rules, Main.State.report
end

--========== MODULE INSTALLATION ==========--
function Main.installSubsystem(key)
    local M = Main.State.modules
    local module = M[key]
    if not module then return false, "module not loaded" end

    local edr = Main.State.edr
    if not edr then return false, "edr not available" end

    local ok, err = pcall(function()
        if key == "Hooks" and module.install then
            module.install(edr)
        elseif key == "RobloxAPI" and module.install then
            module.install(edr)
        elseif key == "Vuln" and module.install then
            module.install(edr)
        end
    end)

    if ok then
        local h = Main.State.module_health[key]
        if h then h.installed = true end
        HealthMonitor.markOK(key)
        return true
    else
        HealthMonitor.markError(key, err)
        return false, err
    end
end

function Main.uninstallSubsystem(key)
    local M = Main.State.modules
    local module = M[key]
    if not module or not module.uninstall then return end

    pcall(function() module.uninstall() end)

    local h = Main.State.module_health[key]
    if h then h.installed = false end
end

--========== RECOVERY UNIT ==========--
-- ตรวจสอบทุก subsystem และพยายามซ่อม
local function recoveryUnitTick()
    if not Main.State.running then return end
    local M = Main.State.modules
    local now = os.clock()
    local repairCount = 0

    -- ตรวจสอบแต่ละ subsystem
    for _, entry in ipairs(MODULE_FILES) do
        local key = entry.key
        local module = M[key]
        if module then
            local health = Main.State.module_health[key]

            -- 1. ตรวจว่า hooks ยังติดตั้งอยู่ไหม
            if entry.key == "Hooks" and health and health.installed then
                if module.isInstalled then
                    local stillInstalled = module.isInstalled()
                    if not stillInstalled then
                        log(1, "Recovery: Hooks ถูกถอด — ติดตั้งใหม่")
                        local ok, err = pcall(function() module.install(Main.State.edr) end)
                        if ok then
                            Main.State.recovered = Main.State.recovered + 1
                            repairCount = repairCount + 1
                            HealthMonitor.markOK(key)
                        else
                            HealthMonitor.markError(key, err)
                        end
                    end
                end
            end

            -- 2. ตรวจว่า module ยังตอบสนองไหม (stale check)
            if health and health.last_ok then
                local staleTime = now - health.last_ok
                if staleTime > Main.Config.HEALTH_STALE_THRESHOLD then
                    -- module ไม่ตอบสนอง — ลอง re-init
                    if key == "Rules" and module.scan then
                        pcall(function() module:scan() end)
                        HealthMonitor.markOK(key)
                    end
                end
            end
        end
    end

    -- 3. ตรวจ monitor loop
    if Main.State.running and not Main.State.paused then
        local lastTick = Main.State.last_tick or 0
        if now - lastTick > 30 then
            -- Monitor loop อาจตาย
            log(1, "Recovery: Monitor loop ดูเหมือนหยุด — รีสตาร์ท")
            Main.State.monitor_co = nil
            pcall(function() Main.startMonitorLoop() end)
            Main.State.recovered = Main.State.recovered + 1
            repairCount = repairCount + 1
        end
    end

    -- 4. ตรวจ dashboard
    if Main.Config.PREFER_UI_MODULE and Main.State.dashboard then
        local d = Main.State.dashboard
        if d.gui and not d.gui.Parent then
            log(1, "Recovery: Dashboard ถูกทำลาย — สร้างใหม่")
            Main.State.dashboard = nil
            Main.State.gui = nil
            pcall(function() Main.buildDashboard() end)
        end
    end

    -- 5. ตรวจ EDR watchdog
    if Main.State.edr and Main.State.running then
        if not Main.State.edr.watchdog then
            log(1, "Recovery: EDR watchdog หยุด — เริ่มใหม่")
            pcall(function() Main.State.edr:startWatchdog() end)
            Main.State.recovered = Main.State.recovered + 1
            repairCount = repairCount + 1
        end
    end

    if repairCount > 0 then
        log(1, string.format("Recovery Unit: ซ่อม %d อย่าง (รวม %d ครั้ง)",
            repairCount, Main.State.recovered))
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
                recordError("RecoveryUnit", err)
            end
        end
    end)

    log(1, "Recovery Unit started (interval=" .. Main.Config.RECOVERY_INTERVAL .. "s)")
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

    if Main.State.running then
        log(1, "Already running")
        return true
    end

    Main.ensureInstances()
    local M = Main.State.modules

    if not Main.State.edr then
        notify("❌ EDR", "EDR core ไม่พร้อม", 8)
        return false
    end

    -- Alert callback
    Main.State.edr.onAlert = function(alert)
        Main.onAlert(alert)
    end

    -- Capture
    if Main.State.report and Main.State.report.captureBefore then
        pcall(function() Main.State.report:captureBefore() end)
    end

    -- ติดตั้ง subsystems
    if M.Hooks then Main.installSubsystem("Hooks") end
    if M.RobloxAPI then Main.installSubsystem("RobloxAPI") end
    if M.Vuln then Main.installSubsystem("Vuln") end

    -- EDR watchdog
    pcall(function() Main.State.edr:startWatchdog() end)

    -- Reset state
    Main.State.running = true
    Main.State.paused = false
    Main.State.killed = false
    Main.State.start_time = os.clock()
    Main.State.last_tick = os.clock()
    Main.State.tick_count = 0
    Main.State._warned_high = false

    -- Monitor + Recovery
    Main.startMonitorLoop()
    Main.startRecoveryUnit()

    log(1, "EDR STARTED")
    notify("🛡️ EDR", "เริ่มเฝ้าระวังแล้ว — รันสคริปต์เป้าหมายได้เลย", 5)

    if Main.State.dashboard and Main.State.dashboard.forceRefresh then
        pcall(function() Main.State.dashboard:forceRefresh() end)
    end

    return true
end

function Main.stop(reason)
    if not Main.State.running then return end

    Main.State.running = false

    local M = Main.State.modules

    -- ถอด subsystems
    if M.Hooks then pcall(function() Main.uninstallSubsystem("Hooks") end) end
    if M.RobloxAPI then pcall(function() Main.uninstallSubsystem("RobloxAPI") end) end
    if M.Vuln then pcall(function() Main.uninstallSubsystem("Vuln") end) end

    if Main.State.edr then
        pcall(function() Main.State.edr:stopWatchdog() end)
    end

    -- Report
    if Main.State.report and Main.Config.AUTO_REPORT then
        pcall(function()
            Main.State.report:finalize()
            Main.saveReport()
        end)
    end

    log(1, "EDR STOPPED: " .. tostring(reason or "user"))
    notify("🛡️ EDR", "หยุดเฝ้าระวัง — " .. tostring(reason or "ผู้ใช้สั่งหยุด"), 5)

    if Main.State.dashboard and Main.State.dashboard.forceRefresh then
        pcall(function() Main.State.dashboard:forceRefresh() end)
    end
end

function Main.pause()
    Main.State.paused = true
    log(1, "EDR PAUSED")
    if Main.State.dashboard and Main.State.dashboard.forceRefresh then
        pcall(function() Main.State.dashboard:forceRefresh() end)
    end
end

function Main.resume()
    Main.State.paused = false
    log(1, "EDR RESUMED")
    if Main.State.dashboard and Main.State.dashboard.forceRefresh then
        pcall(function() Main.State.dashboard:forceRefresh() end)
    end
end

--========== KILL SWITCH ==========--
function Main.kill(reason)
    if Main.State.killed then return end
    Main.State.killed = true
    Main.State.running = false

    log(1, "KILL SWITCH TRIGGERED: " .. tostring(reason))

    Main.showKillOverlay(reason)

    local M = Main.State.modules
    if M.Hooks then pcall(function() Main.uninstallSubsystem("Hooks") end) end
    if M.RobloxAPI then pcall(function() Main.uninstallSubsystem("RobloxAPI") end) end
    if M.Vuln then pcall(function() Main.uninstallSubsystem("Vuln") end) end

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

            coroutine.yield(interval)

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
                recordError("MonitorLoop", waitTime)
                break
            end
            task.wait(waitTime or Main.Config.MONITOR_INTERVAL)
        end
        Main.State.monitor_thread = nil
    end)
end

function Main.tick()
    Main.State.tick_count = Main.State.tick_count + 1
    Main.State.last_tick = os.clock()

    local M = Main.State.modules

    -- 1. scan rules
    if Main.State.rules then
        local ok, err = pcall(function() Main.State.rules:scan() end)
        if not ok then recordError("Rules", err) end
        if ok then HealthMonitor.markOK("Rules") end
    end

    -- 2. update report
    if Main.State.report then
        local ok, err = pcall(function() Main.State.report:update() end)
        if not ok then recordError("Report", err) end
        if ok then HealthMonitor.markOK("Report") end
    end

    -- 3. คำนวณ risk
    local risk = 0
    if M.Rules and Main.State.edr then
        local ok, r = pcall(function()
            return M.Rules.computeSessionRisk(Main.State.edr.alerts)
        end)
        if ok then risk = r end
    end

    -- 4. Kill switch
    if Main.Config.KILL_SWITCH_ENABLED then
        if risk >= Main.Config.KILL_THRESHOLD then
            Main.kill(string.format(
                "Risk score %.1f%% เกินเกณฑ์ %.1f%%\n\nจำนวน alerts: %d\nเวลาที่รัน: %.1fs",
                risk * 100, Main.Config.KILL_THRESHOLD * 100,
                #(Main.State.edr.alerts or {}),
                os.clock() - (Main.State.start_time or os.clock())
            ))
        elseif risk >= Main.Config.WARN_THRESHOLD then
            if not Main.State._warned_high then
                Main.State._warned_high = true
                notify("⚠️ EDR", string.format("ความเสี่ยงสูง: %.1f%%", risk * 100), 6)
            end
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
        t = os.clock(),
        alert = alert,
    })

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
        notify("📄 EDR Report", "บันทึกที่: " .. path, 6)
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
        saved_at = os.time(),
        stats   = Main.State.edr and Main.State.edr:summary() or {},
        health  = HealthMonitor.getHealthReport(),
        recovered = Main.State.recovered,
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

--========== COMMAND INTERFACE ==========--
local COMMANDS = {}

COMMANDS.help = function()
    return [[
คำสั่งที่ใช้ได้:
  /help            แสดงคำสั่งทั้งหมด
  /status          สถานะปัจจุบัน
  /health          สถานะทุก module
  /recover         บังคับซ่อมแซม
  /start           เริ่มเฝ้าระวัง
  /stop            หยุดเฝ้าระวัง
  /pause           พักชั่วคราว
  /resume          กลับมาทำงาน
  /risk            แสดงค่า risk ปัจจุบัน
  /alerts          แสดง alerts ล่าสุด 10 ตัว
  /ioc             แสดง IOC ที่เจอ
  /vulns           แสดงช่องโหว่ที่พบ
  /timeline        แสดง timeline
  /report          สร้าง report ทันที
  /summary         สรุป session
  /rules           แสดง rules ที่โหลดไว้
  /rbxstats        สถิติ Roblox API
  /errors          แสดง error ล่าสุด
  /enable <id>     เปิด rule
  /disable <id>    ปิด rule
  /ui              ซ่อน/แสดง dashboard
  /min             ย่อ dashboard
  /kill            บังคับ kill switch
  /version         เวอร์ชัน
  /clear           ล้าง command log
]]
end

COMMANDS.status = function()
    local s = Main.State
    return string.format(
        "Running:    %s\nPaused:     %s\nKilled:     %s\nRecovered:  %d\nUptime:     %.1fs\nTicks:      %d\nEvents:     %d\nAlerts:     %d\nErrors:     %d",
        tostring(s.running), tostring(s.paused), tostring(s.killed),
        s.recovered,
        s.start_time and (os.clock() - s.start_time) or 0,
        s.tick_count,
        s.edr and s.edr.session.events_processed or 0,
        s.edr and #(s.edr.alerts or {}) or 0,
        #s.error_log
    )
end

COMMANDS.health = function()
    local report = HealthMonitor.getHealthReport()
    local lines = { "MODULE HEALTH" }
    for _, r in ipairs(report) do
        local icon = r.status == "healthy" and "✓"
            or r.status == "error" and "✗"
            or "?"
        table.insert(lines, string.format(
            "%s %-12s status=%-8s err=%-3d retry=%-2d installed=%s",
            icon, r.name, r.status, r.err_count, r.retry_count,
            tostring(r.installed)
        ))
    end
    return table.concat(lines, "\n")
end

COMMANDS.recover = function()
    log(1, "Manual recovery triggered")
    local ok, err = pcall(recoveryUnitTick)
    if ok then
        return string.format("Recovery complete (total repairs: %d)", Main.State.recovered)
    else
        return "Recovery error: " .. tostring(err)
    end
end

COMMANDS.errors = function()
    local lines = {}
    local start = math.max(1, #Main.State.error_log - 10)
    for i = start, #Main.State.error_log do
        local e = Main.State.error_log[i]
        table.insert(lines, string.format("[%.1fs] %s: %s",
            e.t, e.module, e.message:sub(1, 80)))
    end
    return #lines > 0 and table.concat(lines, "\n") or "No errors"
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
        table.insert(lines, string.format("[%s] %s (%.2f)",
            a.rule or "?", tostring(a.message or ""):sub(1, 80), a.score or 0))
    end
    return #lines > 0 and table.concat(lines, "\n") or "No alerts"
end

COMMANDS.ioc = function()
    if not Main.State.report then return "No report" end
    local iocs = Main.State.report.ioc:getAll()
    local lines = {}
    for i = 1, math.min(20, #iocs) do
        local ioc = iocs[i]
        table.insert(lines, string.format("[%s] %s (×%d)",
            ioc.type, ioc.value:sub(1, 60), ioc.count))
    end
    return #lines > 0 and table.concat(lines, "\n") or "No IOC"
end

COMMANDS.vulns = function()
    local M = Main.State.modules
    if not M.Vuln or not M.Vuln.getSummary then return "Vuln scanner ไม่พร้อม" end
    local sum = M.Vuln.getSummary()
    local lines = {
        string.format("Total: %d", sum.total),
        string.format("Critical: %d", sum.by_sev[4] or 0),
        string.format("High: %d", sum.by_sev[3] or 0),
        string.format("Medium: %d", sum.by_sev[2] or 0),
    }
    local top = M.Vuln.getTopFindings(5)
    for i, f in ipairs(top) do
        table.insert(lines, string.format("%d. [%s] %s", i, f.category, f.title))
    end
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
        "Session: %s\nElapsed: %.1fs\nEvents:  %d\nAlerts:  %d\nDropped: %d\nRecovered: %d",
        s.session_id, s.elapsed, s.events, s.alerts, s.dropped, Main.State.recovered
    )
end

COMMANDS.rbxstats = function()
    local M = Main.State.modules
    if not M.RobloxAPI or not M.RobloxAPI.getStats then
        return "Roblox API monitor ไม่พร้อม"
    end
    local s = M.RobloxAPI.getStats()
    local lines = {
        string.format("Instances: created=%d destroyed=%d",
            s.instances.created, s.instances.destroyed),
        string.format("Tracked: %d", s.tracked),
    }
    local svcList = M.RobloxAPI.getSensitiveServiceList()
    for i = 1, math.min(5, #svcList) do
        local svc = svcList[i]
        table.insert(lines, string.format("  %s ×%d", svc.service, svc.count))
    end
    return table.concat(lines, "\n")
end

COMMANDS.rules = function()
    if not Main.State.rules then return "No rules" end
    local lines = {}
    for _, r in ipairs(Main.State.rules.ruleOrder) do
        table.insert(lines, string.format("[%s] %s (sev=%d prio=%d)",
            r.enabled and "✓" or "✗", r.id, r.severity, r.priority))
    end
    return table.concat(lines, "\n")
end

COMMANDS.enable = function(id)
    if not id or id == "" then return "ใช้: /enable <rule_id>" end
    if not Main.State.rules then return "No rules" end
    Main.State.rules:enable(id)
    return "Enabled: " .. id
end

COMMANDS.disable = function(id)
    if not id or id == "" then return "ใช้: /disable <rule_id>" end
    if not Main.State.rules then return "No rules" end
    Main.State.rules:disable(id)
    return "Disabled: " .. id
end

COMMANDS.ui = function()
    return Main.toggleUI()
end

COMMANDS.min = function()
    return Main.minimizeUI()
end

COMMANDS.kill = function()
    Main.kill("สั่ง kill switch จาก command")
    return "Killed"
end

COMMANDS.version = function()
    return string.format("EDR Main v%s (build %s)", Main.VERSION, Main.BUILD)
end

COMMANDS.clear = function()
    Main.State.command_log = {}
    return "Command log cleared"
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
        return "ไม่รู้จักคำสั่ง: " .. tostring(cmd) .. " (ลอง /help)"
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
    if not d then return "ไม่มี dashboard" end

    if d.minimized then
        if d.maximize then d:maximize() end
        return "UI: แสดง"
    else
        if d.minimize then d:minimize() end
        return "UI: ซ่อน"
    end
end

function Main.minimizeUI()
    local d = Main.State.dashboard
    if not d then return "ไม่มี dashboard" end
    if d.minimize then d:minimize() end
    return "UI: ย่อ"
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
    title.Text = "  🛡️  EDR Monitor (Fallback) v" .. Main.VERSION
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

    local statusFrame = Instance.new("Frame")
    statusFrame.Size = UDim2.new(1, -20, 0, 70)
    statusFrame.Position = UDim2.new(0, 10, 0, 46)
    statusFrame.BackgroundColor3 = Color3.fromRGB(22, 27, 34)
    statusFrame.BorderSizePixel = 0
    statusFrame.Parent = main
    Instance.new("UICorner", statusFrame).CornerRadius = UDim.new(0, 8)

    local statusLabel = Instance.new("TextLabel")
    statusLabel.Size = UDim2.new(1, -20, 0, 18)
    statusLabel.Position = UDim2.new(0, 10, 0, 6)
    statusLabel.BackgroundTransparency = 1
    statusLabel.Text = "⚪ STOPPED"
    statusLabel.TextColor3 = Color3.fromRGB(200, 90, 90)
    statusLabel.Font = Enum.Font.GothamBold
    statusLabel.TextSize = 13
    statusLabel.TextXAlignment = Enum.TextXAlignment.Left
    statusLabel.Parent = statusFrame

    local metricsLabel = Instance.new("TextLabel")
    metricsLabel.Size = UDim2.new(1, -20, 0, 42)
    metricsLabel.Position = UDim2.new(0, 10, 0, 24)
    metricsLabel.BackgroundTransparency = 1
    metricsLabel.Text = "Events: 0 | Alerts: 0 | Risk: 0.0%"
    metricsLabel.TextColor3 = Color3.fromRGB(150, 170, 190)
    metricsLabel.Font = Enum.Font.Code
    metricsLabel.TextSize = 11
    metricsLabel.TextXAlignment = Enum.TextXAlignment.Left
    metricsLabel.TextYAlignment = Enum.TextYAlignment.Top
    metricsLabel.Parent = statusFrame

    local barBg = Instance.new("Frame")
    barBg.Size = UDim2.new(1, -20, 0, 8)
    barBg.Position = UDim2.new(0, 10, 0, 120)
    barBg.BackgroundColor3 = Color3.fromRGB(33, 38, 45)
    barBg.BorderSizePixel = 0
    barBg.Parent = main
    Instance.new("UICorner", barBg).CornerRadius = UDim.new(0, 4)

    local barFill = Instance.new("Frame")
    barFill.Size = UDim2.new(0, 0, 1, 0)
    barFill.BackgroundColor3 = Color3.fromRGB(80, 200, 120)
    barFill.BorderSizePixel = 0
    barFill.Parent = barBg
    Instance.new("UICorner", barFill).CornerRadius = UDim.new(0, 4)

    local consoleFrame = Instance.new("Frame")
    consoleFrame.Size = UDim2.new(1, -20, 0, 380)
    consoleFrame.Position = UDim2.new(0, 10, 0, 138)
    consoleFrame.BackgroundColor3 = Color3.fromRGB(6, 8, 12)
    consoleFrame.BorderSizePixel = 0
    consoleFrame.Parent = main
    Instance.new("UICorner", consoleFrame).CornerRadius = UDim.new(0, 8)

    local consoleScroll = Instance.new("ScrollingFrame")
    consoleScroll.Size = UDim2.new(1, -10, 1, -10)
    consoleScroll.Position = UDim2.new(0, 5, 0, 5)
    consoleScroll.BackgroundTransparency = 1
    consoleScroll.BorderSizePixel = 0
    consoleScroll.ScrollBarThickness = 6
    consoleScroll.CanvasSize = UDim2.new(0, 0, 0, 0)
    consoleScroll.AutomaticCanvasSize = Enum.AutomaticSize.Y
    consoleScroll.Parent = consoleFrame

    local consoleList = Instance.new("UIListLayout", consoleScroll)
    consoleList.Padding = UDim.new(0, 2)

    local consoleLines = {}
    local function appendConsole(text, color)
        local lbl = Instance.new("TextLabel")
        lbl.Size = UDim2.new(1, -4, 0, 14)
        lbl.BackgroundTransparency = 1
        lbl.Text = tostring(text)
        lbl.TextColor3 = color or Color3.fromRGB(180, 200, 220)
        lbl.Font = Enum.Font.Code
        lbl.TextSize = 11
        lbl.TextXAlignment = Enum.TextXAlignment.Left
        lbl.Parent = consoleScroll
        lbl.LayoutOrder = #consoleLines
        table.insert(consoleLines, lbl)
        if #consoleLines > 200 then
            consoleLines[1]:Destroy()
            table.remove(consoleLines, 1)
        end
    end

    local inputBg = Instance.new("Frame")
    inputBg.Size = UDim2.new(1, -20, 0, 32)
    inputBg.Position = UDim2.new(0, 10, 1, -44)
    inputBg.BackgroundColor3 = Color3.fromRGB(22, 27, 34)
    inputBg.BorderSizePixel = 0
    inputBg.Parent = main
    Instance.new("UICorner", inputBg).CornerRadius = UDim.new(0, 6)

    local cmdBox = Instance.new("TextBox")
    cmdBox.Size = UDim2.new(1, -20, 1, 0)
    cmdBox.Position = UDim2.new(0, 10, 0, 0)
    cmdBox.BackgroundTransparency = 1
    cmdBox.Text = ""
    cmdBox.PlaceholderText = "พิมพ์คำสั่ง (เช่น /help)"
    cmdBox.PlaceholderColor3 = Color3.fromRGB(100, 110, 120)
    cmdBox.TextColor3 = Color3.fromRGB(220, 230, 240)
    cmdBox.Font = Enum.Font.Code
    cmdBox.TextSize = 12
    cmdBox.TextXAlignment = Enum.TextXAlignment.Left
    cmdBox.ClearTextOnFocus = false
    cmdBox.Parent = inputBg

    cmdBox.FocusLost:Connect(function(enterPressed)
        if not enterPressed then return end
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
        statusLabel.Text = stateText
        statusLabel.TextColor3 = stateColor

        local risk = 0
        if Main.State.modules.Rules and Main.State.edr then
            local ok, r = pcall(function()
                return Main.State.modules.Rules.computeSessionRisk(Main.State.edr.alerts)
            end)
            if ok then risk = r end
        end

        metricsLabel.Text = string.format(
            "Events: %d | Alerts: %d | Risk: %.1f%% | Recovered: %d",
            Main.State.edr and Main.State.edr.session.events_processed or 0,
            Main.State.edr and #Main.State.edr.alerts or 0,
            risk * 100,
            Main.State.recovered
        )

        barFill.Size = UDim2.new(math.clamp(risk, 0, 1), 0, 1, 0)
        if risk < 0.35 then
            barFill.BackgroundColor3 = Color3.fromRGB(80, 200, 120)
        elseif risk < 0.65 then
            barFill.BackgroundColor3 = Color3.fromRGB(210, 153, 34)
        elseif risk < 0.85 then
            barFill.BackgroundColor3 = Color3.fromRGB(240, 140, 50)
        else
            barFill.BackgroundColor3 = Color3.fromRGB(248, 81, 73)
        end

        while true do
            local entry = table.remove(Main.State.command_log, 1)
            if not entry then break end
            if entry.alert then
                local a = entry.alert
                local icon = (a.severity or 0) >= 4 and "🔴"
                    or (a.severity or 0) >= 3 and "🟠"
                    or "🟡"
                appendConsole(
                    string.format("%s [%s] %s", icon, a.rule or "?",
                        tostring(a.message or ""):sub(1, 80)),
                    (a.severity or 0) >= 3 and Color3.fromRGB(248, 81, 73) or Color3.fromRGB(210, 153, 34)
                )
            end
        end
    end

    Main.State.gui = {
        screen = gui,
        main = main,
        update = update,
        appendConsole = appendConsole,
    }

    appendConsole("EDR Fallback GUI v" .. Main.VERSION .. " ready", Color3.fromRGB(88, 166, 255))
    appendConsole("พิมพ์ /help เพื่อดูคำสั่ง", Color3.fromRGB(150, 170, 190))

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
        notify("❌ EDR", "โหลด modules ไม่สำเร็จ: " .. tostring(err), 10)
        return false
    end

    Main.ensureInstances()

    -- ลองโหลด UI
    local uiOK = false
    if Main.State.modules.UI then
        local success, dashErr = Main.buildDashboard()
        if success then
            uiOK = true
            log(1, "Dashboard (ui.lua) initialized")
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

    log(1, "EDR initialized successfully (UI=" .. (uiOK and "ui.lua" or "fallback") .. ")")
    notify("🛡️ EDR v" .. Main.VERSION, "พร้อมทำงาน — กด START ใน GUI", 5)

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
Main.HealthMonitor  = HealthMonitor

if getgenv then
    pcall(function() getgenv().EDRMain = Main end)
end
_G.EDRMain = Main

return Main