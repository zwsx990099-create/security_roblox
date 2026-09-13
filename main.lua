--[[
    ============================================================
    EDR Main v1.1 — Integration Layer + Orchestrator (UI-Ready)
    ============================================================
    หลักการ:
    - รวม edr_core + hooks + rules + report + ui เป็นระบบเดียว
    - Bootstrapper ที่ crash-safe + fallback
    - Kill Switch + Adaptive Monitor Loop
    - Master GUI (ui.lua) + fallback GUI (buildGUI)
    - Auto-report + State persistence

    การเปลี่ยนแปลงจาก v1.0:
    - เพิ่ม UI_MODULE_URL + loadUI()
    - Main.init() โหลด ui.lua แทน buildGUI เป็นหลัก
    - แยก onAlert เป็น 2 channel
    - Main.tick() เรียก dashboard:update() โดยตรง
    - เพิ่มคำสั่ง /ui

    วิธีใช้:
    1. โหลด main.lua ผ่าน loadstring
    2. UI จะเด้งขึ้นอัตโนมัติ
    3. กด START → รันสคริปต์เป้าหมาย

    คำเตือน: เพื่อการศึกษาเท่านั้น
    ============================================================
]]

--========== BOOTSTRAP ==========--
local Main = {}

-- Metadata
Main.VERSION = "1.1.0"
Main.BUILD   = "2025-09-14"

-- Config ก่อนโหลด modules
Main.Config = {
    -- URLs ของ modules (แก้ให้ชี้ไปที่ repo ของคุณ)
    MODULE_BASE   = "https://raw.githubusercontent.com/YOUR_USERNAME/edr-lua/main/",
    -- URL ของ UI module (ไฟล์ ui.lua)
    UI_MODULE_URL = "https://raw.githubusercontent.com/YOUR_USERNAME/edr-lua/main/ui.lua",
    -- หรือใช้ local ถ้ามี
    USE_LOCAL     = false,

    -- การตั้งค่า monitor
    MONITOR_INTERVAL      = 3,     -- วินาที
    ADAPTIVE_INTERVAL     = true,  -- ปรับตาม load
    MIN_INTERVAL          = 1,
    MAX_INTERVAL          = 10,

    -- Kill switch
    KILL_SWITCH_ENABLED   = true,
    KILL_THRESHOLD        = 0.90,  -- risk เกิน 90% → ตัด
    WARN_THRESHOLD        = 0.65,

    -- Report
    AUTO_REPORT           = true,
    AUTO_REPORT_FORMAT    = "markdown",  -- markdown|json|html
    AUTO_SAVE_REPORT      = true,

    -- Persistence
    SAVE_STATE            = true,
    STATE_FILE            = "edr_state.json",

    -- Anti-AFK integration
    ANTI_AFK_INTEGRATION  = false,

    -- UI
    GUI_ENABLED           = true,      -- เปิด UI ทั้งหมด
    PREFER_UI_MODULE      = true,      -- ใช้ ui.lua ถ้ามี (fallback buildGUI ถ้าไม่มี)
    NOTIFY_ON_ALERT       = true,
    NOTIFY_SEVERITY_MIN   = 3,         -- แจ้งเตือนเฉพาะ severity >= นี้

    -- Logging
    LOG_LEVEL             = 1,   -- 0=quiet, 1=normal, 2=verbose
    LOG_TO_FILE           = false,
    LOG_FILE              = "edr_log.txt",
}

--========== SERVICES ==========--
local Players          = game:GetService("Players")
local CoreGui          = game:GetService("CoreGui")
local StarterGui       = game:GetService("StarterGui")
local UserInputService = game:GetService("UserInputService")

local localPlayer = Players.LocalPlayer

--========== STATE ==========--
Main.State = {
    booted       = false,
    running      = false,
    paused       = false,
    killed       = false,
    start_time   = nil,
    last_tick    = nil,
    tick_count   = 0,
    modules      = {},   -- reference ของ modules ที่โหลด
    monitor_co   = nil,
    gui          = nil,  -- { screen, update, ... } สำหรับ tick() เรียก
    dashboard    = nil,  -- reference ของ UI dashboard instance
    command_log  = {},
    fatal_error  = nil,
    _warned_high = false,
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

--========== BOOTSTRAP MODULES ==========--
function Main.bootstrap()
    if Main.State.booted then return true end

    local base = Main.Config.MODULE_BASE
    if Main.Config.USE_LOCAL then
        base = ""
    end

    local modules = {}

    -- 4 core modules
    local ok1, EDR = pcall(function()
        return safeRequire(base .. "edr_core.lua", "edr_core")
    end)
    if ok1 and EDR then modules.EDR = EDR end

    local ok2, Hooks = pcall(function()
        return safeRequire(base .. "hooks.lua", "hooks")
    end)
    if ok2 and Hooks then modules.Hooks = Hooks end

    local ok3, Rules = pcall(function()
        return safeRequire(base .. "rules.lua", "rules")
    end)
    if ok3 and Rules then modules.Rules = Rules end

    local ok4, Report = pcall(function()
        return safeRequire(base .. "report.lua", "report")
    end)
    if ok4 and Report then modules.Report = Report end

    -- ตรวจว่ามีครบไหม
    local missing = {}
    for _, name in ipairs({"EDR", "Hooks", "Rules", "Report"}) do
        if not modules[name] then table.insert(missing, name) end
    end

    if #missing > 0 then
        log(1, "Missing modules: " .. table.concat(missing, ", "))
        if not modules.EDR then
            return false, "EDR core module is required"
        end
    end

    Main.State.modules = modules
    Main.State.booted = true
    return true
end

--========== LOAD UI MODULE ==========--
function Main.loadUI()
    if not Main.Config.PREFER_UI_MODULE then
        return nil, "PREFER_UI_MODULE = false"
    end

    local url = Main.Config.UI_MODULE_URL
    if not url or url == "" then
        return nil, "UI_MODULE_URL ไม่ได้ตั้งค่า"
    end

    local UI, err = safeRequire(url, "ui")
    if not UI then
        return nil, err or "unknown error"
    end

    -- ตรวจว่า UI module มี API ที่ต้องการ
    if type(UI.new) ~= "function" then
        return nil, "UI module ไม่มีฟังก์ชัน .new()"
    end

    Main.State.modules.UI = UI
    return UI
end

--========== INSTANCE SETUP ==========--
-- สร้าง edr / rules / report ถ้ายังไม่มี
function Main.ensureInstances()
    local M = Main.State.modules

    if not Main.State.edr then
        Main.State.edr = M.EDR.get()
    end
    if not Main.State.rules then
        Main.State.rules = M.Rules.new(Main.State.edr)
    end
    if not Main.State.report then
        Main.State.report = M.Report.new(Main.State.edr, Main.State.rules)
    end

    return Main.State.edr, Main.State.rules, Main.State.report
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

    -- Alert callback → 2 channels (notify + dashboard log)
    Main.State.edr.onAlert = function(alert)
        Main.onAlert(alert)
    end

    -- Capture ก่อนรัน
    if Main.State.report.captureBefore then
        Main.State.report:captureBefore()
    end

    -- ติดตั้ง hooks
    if M.Hooks then
        local ok, count = M.Hooks.install(Main.State.edr)
        log(1, "Hooks installed: " .. tostring(ok) .. " (" .. tostring(count) .. ")")
    end

    -- เริ่ม watchdog ของ EDR
    Main.State.edr:startWatchdog()

    -- Reset state
    Main.State.running = true
    Main.State.paused = false
    Main.State.killed = false
    Main.State.start_time = os.clock()
    Main.State.last_tick = os.clock()
    Main.State.tick_count = 0
    Main.State._warned_high = false

    Main.startMonitorLoop()

    log(1, "EDR STARTED")
    notify("🛡️ EDR", "เริ่มเฝ้าระวังแล้ว — รันสคริปต์เป้าหมายได้เลย", 5)

    -- กระตุ้น dashboard ให้ refresh
    if Main.State.dashboard then
        pcall(function() Main.State.dashboard:forceRefresh() end)
    end

    return true
end

function Main.stop(reason)
    if not Main.State.running then return end

    Main.State.running = false

    local M = Main.State.modules

    if M.Hooks then
        pcall(function() M.Hooks.uninstall() end)
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
    notify("🛡️ EDR", "หยุดเฝ้าระวัง — " .. tostring(reason or "ผู้ใช้สั่งหยุด"), 5)

    if Main.State.dashboard then
        pcall(function() Main.State.dashboard:forceRefresh() end)
    end
end

function Main.pause()
    Main.State.paused = true
    log(1, "EDR PAUSED")
    if Main.State.dashboard then
        pcall(function() Main.State.dashboard:forceRefresh() end)
    end
end

function Main.resume()
    Main.State.paused = false
    log(1, "EDR RESUMED")
    if Main.State.dashboard then
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
    if M.Hooks then pcall(function() M.Hooks.uninstall() end) end
    if Main.State.edr then pcall(function() Main.State.edr:stopWatchdog() end) end

    if Main.State.report then
        pcall(function()
            Main.State.report:finalize()
            Main.saveReport()
        end)
    end

    notify("🔴 EDR KILLED", tostring(reason), 10)

    if Main.State.dashboard then
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
    if Main.State.monitor_co then return end

    local co = coroutine.create(function()
        while Main.State.running do
            local interval = Main.Config.MONITOR_INTERVAL

            if Main.Config.ADAPTIVE_INTERVAL and Main.State.edr then
                local rate = Main.State.edr:getRate("NETWORK_REQUEST", 5)
                if rate > 20 then
                    interval = Main.Config.MIN_INTERVAL
                elseif rate < 1 then
                    interval = Main.Config.MAX_INTERVAL
                end
            end

            coroutine.yield(interval)

            if not Main.State.paused and not Main.State.killed then
                Main.tick()
            end
        end
    end)

    Main.State.monitor_co = co

    if task and task.spawn then
        task.spawn(function()
            while Main.State.running do
                local ok, waitTime = coroutine.resume(co)
                if not ok then
                    log(1, "Monitor loop crashed: " .. tostring(waitTime))
                    break
                end
                task.wait(waitTime or Main.Config.MONITOR_INTERVAL)
            end
        end)
    end
end

function Main.tick()
    Main.State.tick_count = Main.State.tick_count + 1
    Main.State.last_tick = os.clock()

    local M = Main.State.modules

    -- 1. scan rules
    if Main.State.rules then
        pcall(function() Main.State.rules:scan() end)
    end

    -- 2. update report
    if Main.State.report then
        pcall(function() Main.State.report:update() end)
    end

    -- 3. คำนวณ risk
    local risk = 0
    if M.Rules and Main.State.edr then
        local ok, r = pcall(function()
            return M.Rules.computeSessionRisk(Main.State.edr.alerts)
        end)
        if ok then risk = r end
    end

    -- 4. Kill switch check
    if Main.Config.KILL_SWITCH_ENABLED then
        if risk >= Main.Config.KILL_THRESHOLD then
            Main.kill(string.format(
                "Risk score %.1f%% เกินเกณฑ์ %.1f%%\n\nจำนวน alerts: %d\nเวลาที่รัน: %.1fs",
                risk * 100, Main.Config.KILL_THRESHOLD * 100,
                #Main.State.edr.alerts,
                os.clock() - Main.State.start_time
            ))
        elseif risk >= Main.Config.WARN_THRESHOLD then
            if not Main.State._warned_high then
                Main.State._warned_high = true
                notify("⚠️ EDR", string.format("ความเสี่ยงสูง: %.1f%%", risk * 100), 6)
            end
        end
    end

    -- 5. อัปเดต GUI (dashboard ถ้ามี, หรือ buildGUI fallback)
    if Main.State.gui and Main.State.gui.update then
        pcall(Main.State.gui.update)
    end
end

--========== ALERT HANDLER ==========--
function Main.onAlert(alert)
    -- Channel 1: queue สำหรับ GUI เดิม (fallback)
    table.insert(Main.State.command_log, {
        t = os.clock(),
        alert = alert,
    })

    -- Channel 2: แจ้งเตือน (ตาม severity)
    local sev = alert.severity or 0
    if sev >= (Main.Config.NOTIFY_SEVERITY_MIN or 3) then
        notify(
            string.format("%s %s", sev >= 4 and "🔴" or "🟠", alert.rule or "ALERT"),
            tostring(alert.message or ""):sub(1, 120),
            5
        )
    end
    -- Channel 3: dashboard log ถูกจัดการใน ui.lua ผ่าน attachToEDR()
end

--========== SAVE REPORT ==========--
function Main.saveReport()
    if not Main.Config.AUTO_SAVE_REPORT then return end
    if not Main.State.report then return end

    local path = "edr_report_" .. os.date("%Y%m%d_%H%M%S") .. "." ..
        (Main.Config.AUTO_REPORT_FORMAT == "json" and "json"
         or Main.Config.AUTO_REPORT_FORMAT == "html" and "html"
         or "md")

    local ok, err = Main.State.report:saveToFile(path, Main.Config.AUTO_REPORT_FORMAT)
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
        config  = Main.Config,
        saved_at = os.time(),
        stats   = Main.State.edr and Main.State.edr:summary() or {},
    }
    pcall(function()
        writefile(Main.Config.STATE_FILE, game:GetService("HttpService"):JSONEncode(state))
    end)
end

function Main.loadState()
    if not Main.Config.SAVE_STATE then return end
    if not readfile or not isfile then return end

    local ok = pcall(function()
        if isfile(Main.Config.STATE_FILE) then
            local raw = readfile(Main.Config.STATE_FILE)
            local state = game:GetService("HttpService"):JSONDecode(raw)
            log(1, "State loaded from previous session")
        end
    end)
    return ok
end

--========== COMMAND INTERFACE ==========--
local COMMANDS = {}

COMMANDS.help = function()
    return [[
คำสั่งที่ใช้ได้:
  /help            แสดงคำสั่งทั้งหมด
  /status          สถานะปัจจุบัน
  /start           เริ่มเฝ้าระวัง
  /stop            หยุดเฝ้าระวัง
  /pause           พักชั่วคราว
  /resume          กลับมาทำงาน
  /risk            แสดงค่า risk ปัจจุบัน
  /alerts          แสดง alerts ล่าสุด 10 ตัว
  /ioc             แสดง IOC ที่เจอ
  /timeline        แสดง timeline
  /report          สร้าง report ทันที
  /export md|json|html
  /summary         สรุป session
  /rules           แสดง rules ที่โหลดไว้
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
        "Running:  %s\nPaused:   %s\nKilled:   %s\nUptime:   %.1fs\nTicks:    %d\nEvents:   %d\nAlerts:   %d",
        tostring(s.running), tostring(s.paused), tostring(s.killed),
        s.start_time and (os.clock() - s.start_time) or 0,
        s.tick_count,
        s.edr and s.edr.session.events_processed or 0,
        s.edr and #s.edr.alerts or 0
    )
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
        "Session: %s\nElapsed: %.1fs\nEvents:  %d\nAlerts:  %d\nDropped: %d",
        s.session_id, s.elapsed, s.events, s.alerts, s.dropped
    )
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

--========== UI TOGGLE HELPERS ==========--
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

--========== FALLBACK GUI (กรณี ui.lua ล้มเหลว) ==========--
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

    -- Console
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

    -- Command input
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

    -- Update
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
            "Events: %d | Alerts: %d | Risk: %.1f%% | Uptime: %.0fs",
            Main.State.edr and Main.State.edr.session.events_processed or 0,
            Main.State.edr and #Main.State.edr.alerts or 0,
            risk * 100,
            Main.State.start_time and (os.clock() - Main.State.start_time) or 0
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

        -- Drain log
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

--========== BUILD DASHBOARD (ui.lua) ==========--
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

    -- ผูก alert handler
    if dashboard.attachToEDR then
        pcall(function() dashboard:attachToEDR() end)
    end

    -- แสดง dashboard
    if dashboard.show then
        pcall(function() dashboard:show() end)
    end

    -- ตั้ง Main.State.gui ให้ชี้ไปที่ dashboard
    Main.State.gui = {
        screen = dashboard.gui,
        update = function() 
            if dashboard.update then dashboard:update() end
        end,
    }

    return true
end

--========== ENTRY POINT ==========--
function Main.init()
    log(1, "Initializing EDR Main v" .. Main.VERSION)

    -- โหลด state
    Main.loadState()

    -- Bootstrap 4 core modules
    local ok, err = Main.bootstrap()
    if not ok then
        log(1, "Bootstrap failed: " .. tostring(err))
        notify("❌ EDR", "โหลด modules ไม่สำเร็จ: " .. tostring(err), 10)
        return false
    end

    -- สร้าง instances ก่อน (ให้ dashboard ใช้ได้)
    Main.ensureInstances()

    -- ลองโหลด ui.lua
    local UI, uiErr = Main.loadUI()
    local uiOK = false

    if UI then
        local success, dashErr = Main.buildDashboard()
        if success then
            uiOK = true
            log(1, "Dashboard (ui.lua) initialized")
        else
            log(1, "Dashboard build failed: " .. tostring(dashErr))
            -- ล้าง State.dashboard ที่อาจค้างอยู่
            Main.State.dashboard = nil
            Main.State.gui = nil
        end
    else
        log(1, "UI module skipped: " .. tostring(uiErr))
    end

    -- Fallback: ถ้า ui.lua ล้มเหลว → ใช้ buildGUI()
    if not uiOK then
        log(1, "Falling back to buildGUI()")
        Main.buildGUI()
    end

    -- Save state เป็นระยะ
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

-- global access
if getgenv then
    pcall(function() getgenv().EDRMain = Main end)
end
_G.EDRMain = Main

return Main