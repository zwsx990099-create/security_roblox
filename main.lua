--[[
    ============================================================
    EDR Main v1.0 — Integration Layer + Orchestrator
    ============================================================
    หลักการ:
    - รวม edr_core + hooks + rules + report เป็นระบบเดียว
    - Bootstrapper ที่ crash-safe + fallback
    - Kill Switch + Adaptive Monitor Loop
    - Config Wizard + Master GUI + Command Console
    - Auto-report + State persistence
    - เชื่อมกับ Anti-AFK ได้ (optional)

    วิธีใช้:
    1. โหลด main.lua ผ่าน loadstring
    2. GUI จะเด้งขึ้น → กด START
    3. รันสคริปต์เป้าหมาย
    4. ดู real-time alerts + report เมื่อจบ

    คำเตือน: เพื่อการศึกษาเท่านั้น
    ============================================================
]]

--========== BOOTSTRAP ==========--
local Main = {}

-- Metadata
Main.VERSION = "1.0.0"
Main.BUILD   = "2025-09-13"

-- Config ก่อนโหลด modules
Main.Config = {
    -- URLs ของ modules (แก้ให้ชี้ไปที่ repo ของคุณ)
    MODULE_BASE = "https://raw.githubusercontent.com/YOUR_USERNAME/edr-lua/main/",
    -- หรือใช้ local ถ้ามี
    USE_LOCAL   = false,

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
    GUI_ENABLED           = true,
    NOTIFY_ON_ALERT       = true,

    -- Logging
    LOG_LEVEL             = 1,   -- 0=quiet, 1=normal, 2=verbose
    LOG_TO_FILE           = false,
    LOG_FILE              = "edr_log.txt",
}

--========== SERVICES ==========--
local Players      = game:GetService("Players")
local CoreGui      = game:GetService("CoreGui")
local StarterGui   = game:GetService("StarterGui")
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
    gui          = nil,
    command_log  = {},
    fatal_error  = nil,
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
        -- ถ้าอยากใช้ local ผ่าน loadstring ปกติ
        base = ""
    end

    -- โหลดทีละ module + fallback
    local modules = {}

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
        -- ยัง boot ได้ถ้าขาดแค่บางตัว
        if not modules.EDR then
            return false, "EDR core module is required"
        end
    end

    Main.State.modules = modules
    Main.State.booted = true
    return true
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

    local M = Main.State.modules

    -- สร้าง instances
    if not Main.State.edr then
        Main.State.edr = M.EDR.get()
    end
    if not Main.State.rules then
        Main.State.rules = M.Rules.new(Main.State.edr)
    end
    if not Main.State.report then
        Main.State.report = M.Report.new(Main.State.edr, Main.State.rules)
    end

    -- Alert callback → GUI + notify
    Main.State.edr.onAlert = function(alert)
        Main.onAlert(alert)
    end

    -- Capture ก่อนรัน
    Main.State.report:captureBefore()

    -- ติดตั้ง hooks
    if M.Hooks then
        local ok, count = M.Hooks.install(Main.State.edr)
        log(1, "Hooks installed: " .. tostring(ok) .. " (" .. tostring(count) .. ")")
    end

    -- เริ่ม watchdog ของ EDR
    Main.State.edr:startWatchdog()

    -- เริ่ม monitor loop
    Main.State.running = true
    Main.State.paused = false
    Main.State.killed = false
    Main.State.start_time = os.clock()
    Main.State.last_tick = os.clock()
    Main.State.tick_count = 0

    Main.startMonitorLoop()

    log(1, "EDR STARTED")
    notify("🛡️ EDR", "เริ่มเฝ้าระวังแล้ว — รันสคริปต์เป้าหมายได้เลย", 5)

    return true
end

function Main.stop(reason)
    if not Main.State.running then return end

    Main.State.running = false

    local M = Main.State.modules

    -- ถอด hooks
    if M.Hooks then
        pcall(function() M.Hooks.uninstall() end)
    end

    -- หยุด watchdog
    if Main.State.edr then
        Main.State.edr:stopWatchdog()
    end

    -- Finalize report
    if Main.State.report and Main.Config.AUTO_REPORT then
        Main.State.report:finalize()
        Main.saveReport()
    end

    log(1, "EDR STOPPED: " .. tostring(reason or "user"))
    notify("🛡️ EDR", "หยุดเฝ้าระวัง — " .. tostring(reason or "ผู้ใช้สั่งหยุด"), 5)
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

    log(1, "KILL SWITCH TRIGGERED: " .. tostring(reason))

    -- แสดง overlay เตือน
    Main.showKillOverlay(reason)

    -- หยุดทุกอย่าง
    local M = Main.State.modules
    if M.Hooks then pcall(function() M.Hooks.uninstall() end) end
    if Main.State.edr then pcall(function() Main.State.edr:stopWatchdog() end) end

    -- Finalize + save report ทันที
    if Main.State.report then
        pcall(function()
            Main.State.report:finalize()
            Main.saveReport()
        end)
    end

    notify("🔴 EDR KILLED", tostring(reason), 10)
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

            -- Adaptive interval
            if Main.Config.ADAPTIVE_INTERVAL then
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

    -- ขับเคลื่อนด้วย task ถ้ามี
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
    local matches = {}
    if Main.State.rules then
        local ok, result = pcall(function() return Main.State.rules:scan() end)
        if ok then matches = result end
    end

    -- 2. update report
    if Main.State.report then
        pcall(function() Main.State.report:update() end)
    end

    -- 3. คำนวณ risk
    local risk = 0
    if M.Rules then
        risk = M.Rules.computeSessionRisk(Main.State.edr.alerts)
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
            -- แจ้งเตือนครั้งเดียวต่อ threshold
            if not Main.State._warned_high then
                Main.State._warned_high = true
                notify("⚠️ EDR", string.format("ความเสี่ยงสูง: %.1f%%", risk * 100), 6)
            end
        end
    end

    -- 5. อัปเดต GUI
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

    -- แจ้งเตือนเฉพาะ HIGH+ ขึ้นไป
    if alert.severity and alert.severity >= 3 then
        notify(
            string.format("%s %s", alert.severity >= 4 and "🔴" or "🟠", alert.rule or "ALERT"),
            tostring(alert.message or ""):sub(1, 120),
            5
        )
    end
end

--========== SAVE REPORT ==========--
function Main.saveReport()
    if not Main.Config.AUTO_SAVE_REPORT then return end
    if not Main.State.report then return end

    local M = Main.State.modules
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

COMMANDS.start = function() Main.start(); return "Started" end
COMMANDS.stop  = function() Main.stop("command"); return "Stopped" end
COMMANDS.pause = function() Main.pause(); return "Paused" end
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

COMMANDS.version = function()
    return string.format("EDR Main v%s (build %s)", Main.VERSION, Main.BUILD)
end

COMMANDS.kill = function()
    Main.kill("สั่ง kill switch จาก command")
    return "Killed"
end

COMMANDS.clear = function()
    Main.State.command_log = {}
    return "Command log cleared"
end

function Main.executeCommand(input)
    input = tostring(input or ""):gsub("^%s+", ""):gsub("%s+$", "")
    if input == "" then return end

    -- strip leading "/"
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

--========== MASTER GUI ==========--
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

    -- Title
    local title = Instance.new("TextLabel")
    title.Size = UDim2.new(1, 0, 0, 38)
    title.BackgroundColor3 = Color3.fromRGB(22, 27, 34)
    title.BorderSizePixel = 0
    title.Text = "  🛡️  EDR Monitor — Anti-Threat Suite v" .. Main.VERSION
    title.TextColor3 = Color3.fromRGB(88, 166, 255)
    title.Font = Enum.Font.GothamBold
    title.TextSize = 14
    title.TextXAlignment = Enum.TextXAlignment.Left
    title.Parent = main
    Instance.new("UICorner", title).CornerRadius = UDim.new(0, 12)

    -- Close button
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
    close.MouseButton1Click:Connect(function()
        gui.Enabled = false
    end)

    -- Status bar
    local statusFrame = Instance.new("Frame")
    statusFrame.Size = UDim2.new(1, -20, 0, 70)
    statusFrame.Position = UDim2.new(0, 10, 0, 46)
    statusFrame.BackgroundColor3 = Color3.fromRGB(22, 27, 34)
    statusFrame.BorderSizePixel = 0
    statusFrame.Parent = main
    Instance.new("UICorner", statusFrame).CornerRadius = UDim.new(0, 8)

    local statusLabel = Instance.new("TextLabel")
    statusLabel.Name = "StatusLabel"
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
    metricsLabel.Name = "MetricsLabel"
    metricsLabel.Size = UDim2.new(1, -20, 0, 42)
    metricsLabel.Position = UDim2.new(0, 10, 0, 24)
    metricsLabel.BackgroundTransparency = 1
    metricsLabel.Text = "Events: 0 | Alerts: 0 | Risk: 0.0% | Uptime: 0s"
    metricsLabel.TextColor3 = Color3.fromRGB(150, 170, 190)
    metricsLabel.Font = Enum.Font.Code
    metricsLabel.TextSize = 11
    metricsLabel.TextXAlignment = Enum.TextXAlignment.Left
    metricsLabel.TextYAlignment = Enum.TextYAlignment.Top
    metricsLabel.Parent = statusFrame

    -- Risk bar
    local barBg = Instance.new("Frame")
    barBg.Size = UDim2.new(1, -20, 0, 8)
    barBg.Position = UDim2.new(0, 10, 0, 120)
    barBg.BackgroundColor3 = Color3.fromRGB(33, 38, 45)
    barBg.BorderSizePixel = 0
    barBg.Parent = main
    Instance.new("UICorner", barBg).CornerRadius = UDim.new(0, 4)

    local barFill = Instance.new("Frame")
    barFill.Name = "RiskBarFill"
    barFill.Size = UDim2.new(0, 0, 1, 0)
    barFill.BackgroundColor3 = Color3.fromRGB(80, 200, 120)
    barFill.BorderSizePixel = 0
    barFill.Parent = barBg
    Instance.new("UICorner", barFill).CornerRadius = UDim.new(0, 4)

    -- Control buttons
    local btnFrame = Instance.new("Frame")
    btnFrame.Size = UDim2.new(1, -20, 0, 40)
    btnFrame.Position = UDim2.new(0, 10, 0, 138)
    btnFrame.BackgroundTransparency = 1
    btnFrame.Parent = main

    local layout = Instance.new("UIListLayout", btnFrame)
    layout.FillDirection = Enum.FillDirection.Horizontal
    layout.Padding = UDim.new(0, 6)

    local function makeButton(text, color, width, onClick)
        local b = Instance.new("TextButton")
        b.Size = UDim2.new(0, width, 1, 0)
        b.BackgroundColor3 = color
        b.BorderSizePixel = 0
        b.Text = text
        b.TextColor3 = Color3.fromRGB(255, 255, 255)
        b.Font = Enum.Font.GothamBold
        b.TextSize = 12
        b.Parent = btnFrame
        Instance.new("UICorner", b).CornerRadius = UDim.new(0, 6)
        b.MouseButton1Click:Connect(onClick)
        return b
    end

    makeButton("START", Color3.fromRGB(50, 180, 80), 90, function() Main.start() end)
    makeButton("STOP",  Color3.fromRGB(180, 50, 50), 90, function() Main.stop("gui") end)
    makeButton("PAUSE", Color3.fromRGB(200, 150, 50), 90, function()
        if Main.State.paused then Main.resume() else Main.pause() end
    end)
    makeButton("REPORT", Color3.fromRGB(80, 100, 180), 100, function()
        Main.saveReport()
    end)
    makeButton("VIEW",  Color3.fromRGB(120, 80, 180), 80, function()
        if Main.State.report then
            pcall(function() Main.State.report:show() end)
        end
    end)

    -- Console output (ScrollingFrame)
    local consoleFrame = Instance.new("Frame")
    consoleFrame.Size = UDim2.new(1, -20, 0, 180)
    consoleFrame.Position = UDim2.new(0, 10, 0, 186)
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
    consoleList.SortOrder = Enum.SortOrder.LayoutOrder

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
    inputBg.Position = UDim2.new(0, 10, 1, -80)
    inputBg.BackgroundColor3 = Color3.fromRGB(22, 27, 34)
    inputBg.BorderSizePixel = 0
    inputBg.Parent = main
    Instance.new("UICorner", inputBg).CornerRadius = UDim.new(0, 6)

    local prompt = Instance.new("TextLabel")
    prompt.Size = UDim2.new(0, 24, 1, 0)
    prompt.BackgroundTransparency = 1
    prompt.Text = "  ›"
    prompt.TextColor3 = Color3.fromRGB(88, 166, 255)
    prompt.Font = Enum.Font.Code
    prompt.TextSize = 14
    prompt.TextXAlignment = Enum.TextXAlignment.Left
    prompt.Parent = inputBg

    local cmdBox = Instance.new("TextBox")
    cmdBox.Size = UDim2.new(1, -34, 1, 0)
    cmdBox.Position = UDim2.new(0, 30, 0, 0)
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

    -- ปุ่ม minimize
    local minimize = Instance.new("TextButton")
    minimize.Size = UDim2.new(0, 24, 0, 24)
    minimize.Position = UDim2.new(1, -64, 0, 7)
    minimize.BackgroundColor3 = Color3.fromRGB(60, 70, 80)
    minimize.BorderSizePixel = 0
    minimize.Text = "—"
    minimize.TextColor3 = Color3.fromRGB(255, 255, 255)
    minimize.Font = Enum.Font.GothamBold
    minimize.TextSize = 14
    minimize.Parent = title
    Instance.new("UICorner", minimize).CornerRadius = UDim.new(0, 6)

    local minimized = false
    local oldSize = main.Size
    minimize.MouseButton1Click:Connect(function()
        minimized = not minimized
        if minimized then
            oldSize = main.Size
            main.Size = UDim2.new(0, 520, 0, 38)
            statusFrame.Visible = false
            barBg.Visible = false
            btnFrame.Visible = false
            consoleFrame.Visible = false
            inputBg.Visible = false
            minimize.Text = "+"
        else
            main.Size = oldSize
            statusFrame.Visible = true
            barBg.Visible = true
            btnFrame.Visible = true
            consoleFrame.Visible = true
            inputBg.Visible = true
            minimize.Text = "—"
        end
    end)

    -- Update function
    local function update()
        if not gui.Parent then return end

        -- Status
        local stateText = "⚪ STOPPED"
        local stateColor = Color3.fromRGB(200, 90, 90)

        if Main.State.killed then
            stateText = "🔴 KILLED"
            stateColor = Color3.fromRGB(248, 81, 73)
        elseif Main.State.paused then
            stateText = "🟡 PAUSED"
            stateColor = Color3.fromRGB(210, 153, 34)
        elseif Main.State.running then
            stateText = "🟢 RUNNING"
            stateColor = Color3.fromRGB(126, 231, 135)
        end
        statusLabel.Text = stateText
        statusLabel.TextColor3 = stateColor

        -- Metrics
        local risk = 0
        if Main.State.modules.Rules and Main.State.edr then
            local ok, r = pcall(function()
                return Main.State.modules.Rules.computeSessionRisk(Main.State.edr.alerts)
            end)
            if ok then risk = r end
        end

        metricsLabel.Text = string.format(
            "Events: %d | Alerts: %d | Risk: %.1f%% | Uptime: %s | Ticks: %d",
            Main.State.edr and Main.State.edr.session.events_processed or 0,
            Main.State.edr and #Main.State.edr.alerts or 0,
            risk * 100,
            Main.State.start_time and (string.format("%.0fs", os.clock() - Main.State.start_time)) or "0s",
            Main.State.tick_count
        )

        -- Risk bar
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

        -- Drain alert queue เข้า console
        while true do
            local entry = table.remove(Main.State.command_log, 1)
            if not entry then break end
            if entry.alert then
                local a = entry.alert
                local icon = (a.severity or 0) >= 4 and "🔴"
                    or (a.severity or 0) >= 3 and "🟠"
                    or "🟡"
                appendConsole(
                    string.format("%s [%s] %s", icon, a.rule or "?", tostring(a.message or ""):sub(1, 80)),
                    (a.severity or 0) >= 3 and Color3.fromRGB(248, 81, 73) or Color3.fromRGB(210, 153, 34)
                )
            end
        end
    end

    -- Expose
    Main.State.gui = {
        screen = gui,
        main = main,
        update = update,
        appendConsole = appendConsole,
    }

    -- Initial
    appendConsole("EDR Monitor v" .. Main.VERSION .. " ready", Color3.fromRGB(88, 166, 255))
    appendConsole("พิมพ์ /help เพื่อดูคำสั่งทั้งหมด", Color3.fromRGB(150, 170, 190))

    -- Update loop
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

    -- โหลด state
    Main.loadState()

    -- Bootstrap modules
    local ok, err = Main.bootstrap()
    if not ok then
        log(1, "Bootstrap failed: " .. tostring(err))
        notify("❌ EDR", "โหลด modules ไม่สำเร็จ: " .. tostring(err), 10)
        return false
    end

    -- สร้าง GUI
    Main.buildGUI()

    -- Save state เป็นระยะ
    if Main.Config.SAVE_STATE and task and task.spawn then
        task.spawn(function()
            while true do
                task.wait(60)
                pcall(Main.saveState)
            end
        end)
    end

    log(1, "EDR initialized successfully")
    notify("🛡️ EDR v" .. Main.VERSION, "พร้อมทำงาน — กด START ใน GUI", 5)

    return true
end

-- Auto-init
task.spawn(function()
    task.wait(0.1)
    pcall(Main.init)
end)

--========== EXPORT ==========--
Main.log = log
Main.notify = notify
Main.executeCommand = Main.executeCommand

-- global access
if getgenv then
    pcall(function() getgenv().EDRMain = Main end)
end
_G.EDRMain = Main

return Main