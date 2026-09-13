--[[
    ============================================================
    EDR UI v1.0 — Mobile-First Dashboard
    ============================================================
    ออกแบบสำหรับมือถือโดยเฉพาะ:
    - Bottom sheet + tab navigation
    - Responsive ตาม orientation
    - ปุ่มขนาด >= 44px (touch standard)
    - Live update ทุก 1 วินาที
    - Minimize เป็น floating bubble
    - สีของ risk แสดงผลชัดเจน

    วิธีใช้:
        local UI = require("ui")
        local dashboard = UI.new(edr, rules, report)
        dashboard:show()
        dashboard:update()   -- เรียกในลูป

    ใช้ร่วมกับ main.lua ได้ทันที
    ============================================================
]]

local UI = {}

--========== CONFIG ==========--
UI.Config = {
    -- ขนาดและระยะ
    WIDTH_SCALE          = 0.96,   -- ใช้ 96% ของความกว้างจอ
    HEIGHT_SCALE_PORT    = 0.85,   -- portrait: 85% ของความสูง
    HEIGHT_SCALE_LAND    = 0.92,   -- landscape: 92%
    TOP_MARGIN           = 30,     -- px
    BOTTOM_MARGIN        = 60,     -- px (เว้นที่ให้ปุ่ม Roblox)
    CORNER_RADIUS        = 14,
    PADDING              = 12,

    -- Touch targets
    MIN_TOUCH_HEIGHT     = 44,
    MIN_TOUCH_WIDTH      = 44,

    -- การอัปเดต
    UPDATE_INTERVAL      = 1.0,
    MAX_LOG_LINES        = 100,

    -- เปิด minimize mode
    ENABLE_MINIMIZE      = true,
    -- เริ่มต้นเป็น minimized หรือไม่
    START_MINIMIZED      = false,

    -- สี (ตาม GitHub Dark)
    COLOR_BG             = Color3.fromRGB(13, 17, 23),
    COLOR_PANEL          = Color3.fromRGB(22, 27, 34),
    COLOR_BORDER         = Color3.fromRGB(48, 54, 61),
    COLOR_TEXT           = Color3.fromRGB(201, 209, 217),
    COLOR_TEXT_DIM       = Color3.fromRGB(139, 148, 158),
    COLOR_ACCENT         = Color3.fromRGB(88, 166, 255),
    COLOR_SUCCESS        = Color3.fromRGB(126, 231, 135),
    COLOR_WARN           = Color3.fromRGB(210, 153, 34),
    COLOR_DANGER         = Color3.fromRGB(248, 81, 73),
    COLOR_ORANGE         = Color3.fromRGB(240, 140, 50),
}

--========== SEVERITY COLORS ==========--
local SEV_COLOR = {
    [0] = Color3.fromRGB(139, 148, 158),  -- INFO - gray
    [1] = Color3.fromRGB(126, 231, 135),  -- LOW - green
    [2] = Color3.fromRGB(210, 153, 34),   -- MED - yellow
    [3] = Color3.fromRGB(240, 140, 50),   -- HIGH - orange
    [4] = Color3.fromRGB(248, 81, 73),    -- CRIT - red
}

local SEV_LABEL = { [0]="INFO", [1]="LOW", [2]="MED", [3]="HIGH", [4]="CRIT" }
local SEV_ICON  = { [0]="·",    [1]="○",   [2]="◐",   [3]="●",    [4]="◆" }

--========== UTILITIES ==========--
local function isPortrait()
    local cam = workspace.CurrentCamera
    if not cam then return true end
    local vp = cam.ViewportSize
    return vp.Y >= vp.X
end

local function getViewport()
    local cam = workspace.CurrentCamera
    if cam then return cam.ViewportSize end
    return Vector2.new(1080, 1920)
end

local function fmtDuration(sec)
    sec = math.floor(sec or 0)
    if sec < 60 then return sec .. "s" end
    if sec < 3600 then return math.floor(sec/60) .. "m" .. (sec%60) .. "s" end
    return math.floor(sec/3600) .. "h" .. math.floor((sec%3600)/60) .. "m"
end

local function getParentGui()
    local CoreGui = game:GetService("CoreGui")
    local ok, cg = pcall(function() return CoreGui end)
    if ok and cg then return cg end
    return game:GetService("Players").LocalPlayer:WaitForChild("PlayerGui")
end

local function new(className, props, children)
    local inst = Instance.new(className)
    if props then
        for k, v in pairs(props) do
            if k ~= "Parent" then inst[k] = v end
        end
    end
    if children then
        for _, c in ipairs(children) do c.Parent = inst end
    end
    if props and props.Parent then inst.Parent = props.Parent end
    return inst
end

--========== MAIN OBJECT ==========--
local Dashboard = {}
Dashboard.__index = Dashboard

function UI.new(edr, rules, report, main)
    local self = setmetatable({
        edr        = edr,
        rules      = rules,
        report     = report,
        main       = main,
        gui        = nil,
        root       = nil,
        minimized  = UI.Config.START_MINIMIZED,
        currentTab = "summary",
        tabs       = {},
        content    = {},
        logLines   = {},
        lastUpdate = 0,
        lastPortrait = isPortrait(),
    }, Dashboard)
    return self
end

--========== BUILD MAIN LAYOUT ==========--
function Dashboard:_buildRoot()
    local parentGui = getParentGui()
    local vp = getViewport()

    local gui = new("ScreenGui", {
        Name = "EDR_UI_" .. tostring(math.random(1000, 9999)),
        ResetOnSpawn = false,
        ZIndexBehavior = Enum.ZIndexBehavior.Sibling,
        DisplayOrder = 100,
        Parent = parentGui,
    })
    self.gui = gui

    -- === FLOATING BUBBLE (minimized state) ===
    local bubble = new("TextButton", {
        Name = "Bubble",
        Size = UDim2.new(0, 60, 0, 60),
        Position = UDim2.new(1, -75, 0, 100),
        BackgroundColor3 = UI.Config.COLOR_ACCENT,
        BorderSizePixel = 0,
        Text = "🛡️",
        TextColor3 = Color3.fromRGB(255, 255, 255),
        TextSize = 26,
        Font = Enum.Font.GothamBold,
        Visible = false,
        Active = true,
        Draggable = true,
        Parent = gui,
    })
    new("UICorner", { CornerRadius = UDim.new(0, 30), Parent = bubble })
    local bubbleStroke = new("UIStroke", {
        Color = UI.Config.COLOR_DANGER,
        Thickness = 2,
        Parent = bubble,
    })
    new("UIGradient", {
        Color = ColorSequence.new({
            ColorSequenceKeypoint.new(0, UI.Config.COLOR_ACCENT),
            ColorSequenceKeypoint.new(1, Color3.fromRGB(126, 231, 135)),
        }),
        Parent = bubble,
    })
    self.bubble = bubble
    self.bubbleStroke = bubbleStroke

    -- === MAIN SHEET (expanded state) ===
    local root = new("Frame", {
        Name = "Root",
        BackgroundColor3 = UI.Config.COLOR_BG,
        BorderSizePixel = 0,
        Active = true,
        Draggable = true,
        Visible = true,
        Parent = gui,
    })
    new("UICorner", { CornerRadius = UDim.new(0, UI.Config.CORNER_RADIUS), Parent = root })
    new("UIStroke", {
        Color = UI.Config.COLOR_BORDER,
        Thickness = 1.5,
        Parent = root,
    })
    self.root = root

    -- ปุ่มย่อ (มุมขวาบน)
    local minimizeBtn = new("TextButton", {
        Name = "MinimizeBtn",
        Size = UDim2.new(0, 32, 0, 32),
        Position = UDim2.new(1, -40, 0, 6),
        BackgroundColor3 = UI.Config.COLOR_PANEL,
        BorderSizePixel = 0,
        Text = "—",
        TextColor3 = UI.Config.COLOR_TEXT,
        TextSize = 18,
        Font = Enum.Font.GothamBold,
        ZIndex = 5,
        Parent = root,
    })
    new("UICorner", { CornerRadius = UDim.new(0, 8), Parent = minimizeBtn })
    minimizeBtn.MouseButton1Click:Connect(function() self:minimize() end)

    -- ปุ่มปิด (มุมซ้ายบนของ header)
    local closeBtn = new("TextButton", {
        Name = "CloseBtn",
        Size = UDim2.new(0, 32, 0, 32),
        Position = UDim2.new(1, -78, 0, 6),
        BackgroundColor3 = UI.Config.COLOR_DANGER,
        BorderSizePixel = 0,
        Text = "✕",
        TextColor3 = Color3.fromRGB(255, 255, 255),
        TextSize = 14,
        Font = Enum.Font.GothamBold,
        ZIndex = 5,
        Parent = root,
    })
    new("UICorner", { CornerRadius = UDim.new(0, 8), Parent = closeBtn })
    closeBtn.MouseButton1Click:Connect(function() self:destroy() end)

    -- === HEADER (fixed) ===
    local header = new("Frame", {
        Name = "Header",
        Size = UDim2.new(1, -80, 0, 44),
        Position = UDim2.new(0, 12, 0, 4),
        BackgroundTransparency = 1,
        Parent = root,
    })

    local titleLbl = new("TextLabel", {
        Size = UDim2.new(1, 0, 0, 22),
        BackgroundTransparency = 1,
        Text = "🛡️  EDR Monitor",
        TextColor3 = UI.Config.COLOR_ACCENT,
        TextSize = 15,
        Font = Enum.Font.GothamBold,
        TextXAlignment = Enum.TextXAlignment.Left,
        Parent = header,
    })

    local statusLbl = new("TextLabel", {
        Name = "StatusLbl",
        Size = UDim2.new(1, 0, 0, 18),
        Position = UDim2.new(0, 0, 0, 22),
        BackgroundTransparency = 1,
        Text = "⚪ STOPPED",
        TextColor3 = UI.Config.COLOR_TEXT_DIM,
        TextSize = 11,
        Font = Enum.Font.Code,
        TextXAlignment = Enum.TextXAlignment.Left,
        Parent = header,
    })
    self.statusLbl = statusLbl

    -- === RISK BAR ===
    local riskFrame = new("Frame", {
        Name = "RiskFrame",
        Size = UDim2.new(1, -24, 0, 30),
        Position = UDim2.new(0, 12, 0, 52),
        BackgroundColor3 = UI.Config.COLOR_PANEL,
        BorderSizePixel = 0,
        Parent = root,
    })
    new("UICorner", { CornerRadius = UDim.new(0, 8), Parent = riskFrame })

    local barBg = new("Frame", {
        Name = "BarBg",
        Size = UDim2.new(1, -16, 0, 8),
        Position = UDim2.new(0, 8, 0, 18),
        BackgroundColor3 = Color3.fromRGB(33, 38, 45),
        BorderSizePixel = 0,
        Parent = riskFrame,
    })
    new("UICorner", { CornerRadius = UDim.new(0, 4), Parent = barBg })

    local barFill = new("Frame", {
        Name = "BarFill",
        Size = UDim2.new(0, 0, 1, 0),
        BackgroundColor3 = UI.Config.COLOR_SUCCESS,
        BorderSizePixel = 0,
        Parent = barBg,
    })
    new("UICorner", { CornerRadius = UDim.new(0, 4), Parent = barFill })
    self.barFill = barFill

    local riskLbl = new("TextLabel", {
        Name = "RiskLbl",
        Size = UDim2.new(1, -16, 0, 16),
        Position = UDim2.new(0, 8, 0, 2),
        BackgroundTransparency = 1,
        Text = "Risk: 0.0%   |   Events: 0   |   Alerts: 0",
        TextColor3 = UI.Config.COLOR_TEXT_DIM,
        TextSize = 10,
        Font = Enum.Font.Code,
        TextXAlignment = Enum.TextXAlignment.Left,
        Parent = riskFrame,
    })
    self.riskLbl = riskLbl

    -- === TAB BAR (horizontal scroll) ===
    local tabBarFrame = new("Frame", {
        Name = "TabBar",
        Size = UDim2.new(1, -24, 0, 40),
        Position = UDim2.new(0, 12, 0, 86),
        BackgroundTransparency = 1,
        Parent = root,
    })

    local tabScroll = new("ScrollingFrame", {
        Size = UDim2.new(1, 0, 1, 0),
        BackgroundTransparency = 1,
        BorderSizePixel = 0,
        ScrollBarThickness = 0,
        ScrollingDirection = Enum.ScrollingDirection.X,
        CanvasSize = UDim2.new(0, 0, 0, 0),
        AutomaticCanvasSize = Enum.AutomaticSize.X,
        Parent = tabBarFrame,
    })
    local tabList = new("UIListLayout", {
        FillDirection = Enum.FillDirection.Horizontal,
        Padding = UDim.new(0, 6),
        VerticalAlignment = Enum.VerticalAlignment.Center,
        Parent = tabScroll,
    })
    self.tabScroll = tabScroll

    -- สร้าง tabs
    local TABS = {
        { id = "summary",  label = "Summary" },
        { id = "alerts",   label = "Alerts" },
        { id = "timeline", label = "Timeline" },
        { id = "ioc",      label = "IOC" },
        { id = "risk",     label = "Risk" },
        { id = "rules",    label = "Rules" },
        { id = "env",      label = "Env" },
        { id = "log",      label = "Log" },
    }

    for _, tabInfo in ipairs(TABS) do
        local tabBtn = new("TextButton", {
            Name = "Tab_" .. tabInfo.id,
            Size = UDim2.new(0, 78, 0, 34),
            BackgroundColor3 = UI.Config.COLOR_PANEL,
            BorderSizePixel = 0,
            Text = tabInfo.label,
            TextColor3 = UI.Config.COLOR_TEXT_DIM,
            TextSize = 11,
            Font = Enum.Font.GothamSemibold,
            Parent = tabScroll,
        })
        new("UICorner", { CornerRadius = UDim.new(0, 8), Parent = tabBtn })
        new("UIPadding", {
            PaddingLeft = UDim.new(0, 8),
            PaddingRight = UDim.new(0, 8),
            Parent = tabBtn,
        })

        tabBtn.MouseButton1Click:Connect(function()
            self:switchTab(tabInfo.id)
        end)

        self.tabs[tabInfo.id] = tabBtn
    end

    -- === CONTENT AREA (scrolling) ===
    local contentFrame = new("Frame", {
        Name = "ContentFrame",
        Size = UDim2.new(1, -24, 1, -140),
        Position = UDim2.new(0, 12, 0, 132),
        BackgroundColor3 = UI.Config.COLOR_PANEL,
        BorderSizePixel = 0,
        Parent = root,
    })
    new("UICorner", { CornerRadius = UDim.new(0, 10), Parent = contentFrame })
    self.contentFrame = contentFrame

    local contentScroll = new("ScrollingFrame", {
        Name = "ContentScroll",
        Size = UDim2.new(1, -12, 1, -12),
        Position = UDim2.new(0, 6, 0, 6),
        BackgroundTransparency = 1,
        BorderSizePixel = 0,
        ScrollBarThickness = 5,
        ScrollBarImageColor3 = UI.Config.COLOR_BORDER,
        CanvasSize = UDim2.new(0, 0, 0, 0),
        AutomaticCanvasSize = Enum.AutomaticSize.Y,
        Parent = contentFrame,
    })
    local contentList = new("UIListLayout", {
        Padding = UDim.new(0, 4),
        SortOrder = Enum.SortOrder.LayoutOrder,
        Parent = contentScroll,
    })
    self.contentScroll = contentScroll
    self.contentList = contentList

    -- === BOTTOM ACTION BAR ===
    local actionBar = new("Frame", {
        Name = "ActionBar",
        Size = UDim2.new(1, -24, 0, 44),
        Position = UDim2.new(0, 12, 1, -52),
        BackgroundTransparency = 1,
        Parent = root,
    })
    local actionList = new("UIListLayout", {
        FillDirection = Enum.FillDirection.Horizontal,
        Padding = UDim.new(0, 6),
        VerticalAlignment = Enum.VerticalAlignment.Center,
        HorizontalAlignment = Enum.HorizontalAlignment.Center,
        Parent = actionBar,
    })

    local function makeActionBtn(label, color, cb)
        local b = new("TextButton", {
            Size = UDim2.new(0, 0, 1, 0),
            BackgroundColor3 = color,
            BorderSizePixel = 0,
            Text = label,
            TextColor3 = Color3.fromRGB(255, 255, 255),
            TextSize = 12,
            Font = Enum.Font.GothamBold,
            Parent = actionBar,
            AutomaticSize = Enum.AutomaticSize.X,
        })
        new("UICorner", { CornerRadius = UDim.new(0, 8), Parent = b })
        new("UIPadding", {
            PaddingLeft = UDim.new(0, 14),
            PaddingRight = UDim.new(0, 14),
            Parent = b,
        })
        b.MouseButton1Click:Connect(cb)
        return b
    end

    -- START/STOP toggle
    self.startBtn = makeActionBtn("▶ START", UI.Config.COLOR_SUCCESS, function()
        self:onStartStop()
    end)

    makeActionBtn("📄 Export", UI.Config.COLOR_ACCENT, function()
        if self.main and self.main.saveReport then self.main.saveReport() end
    end)

    makeActionBtn("🔄 Refresh", UI.Config.COLOR_PANEL, function()
        self:forceRefresh()
    end)

    -- Minimize handler
    bubble.MouseButton1Click:Connect(function() self:maximize() end)

    -- Initial
    self:applyLayout()
    self:switchTab("summary")
end

--========== LAYOUT MANAGEMENT ==========--
function Dashboard:applyLayout()
    local vp = getViewport()
    local portrait = vp.Y >= vp.X
    self.lastPortrait = portrait

    local width = vp.X * UI.Config.WIDTH_SCALE
    local heightScale = portrait and UI.Config.HEIGHT_SCALE_PORT or UI.Config.HEIGHT_SCALE_LAND
    local height = vp.Y * heightScale

    -- กำหนดขนาดสูงสุดบน tablet/desktop
    if width > 480 then width = 480 end
    if height > 720 then height = 720 end

    -- Position: portrait = กลางล่าง, landscape = มุมขวา
    local xPos, yPos
    if portrait then
        xPos = (vp.X - width) / 2
        yPos = vp.Y - height - UI.Config.BOTTOM_MARGIN
    else
        xPos = vp.X - width - 20
        yPos = (vp.Y - height) / 2
    end

    if self.root then
        self.root.Size = UDim2.new(0, width, 0, height)
        self.root.Position = UDim2.new(0, xPos, 0, yPos)
    end
end

function Dashboard:handleViewportChange()
    local isPort = isPortrait()
    if isPort ~= self.lastPortrait then
        self:applyLayout()
    end
end

--========== SHOW / HIDE ==========--
function Dashboard:show()
    if not self.gui then
        self:_buildRoot()
    end
    if self.minimized then
        self:minimize()
    else
        self:maximize()
    end
    self:startUpdateLoop()
end

function Dashboard:minimize()
    self.minimized = true
    if self.root then self.root.Visible = false end
    if self.bubble then self.bubble.Visible = true end
end

function Dashboard:maximize()
    self.minimized = false
    if self.root then self.root.Visible = true end
    if self.bubble then self.bubble.Visible = false end
    self:applyLayout()
end

function Dashboard:destroy()
    if self.gui then
        self.gui:Destroy()
        self.gui = nil
    end
end

--========== TAB SWITCHING ==========--
function Dashboard:switchTab(tabId)
    self.currentTab = tabId

    -- Highlight tab ที่เลือก
    for id, btn in pairs(self.tabs) do
        if id == tabId then
            btn.BackgroundColor3 = UI.Config.COLOR_ACCENT
            btn.TextColor3 = Color3.fromRGB(255, 255, 255)
        else
            btn.BackgroundColor3 = UI.Config.COLOR_PANEL
            btn.TextColor3 = UI.Config.COLOR_TEXT_DIM
        end
    end

    self:renderContent()
end

--========== CONTENT RENDERING ==========--
function Dashboard:_clearContent()
    for _, child in ipairs(self.contentScroll:GetChildren()) do
        if not child:IsA("UIListLayout") then
            child:Destroy()
        end
    end
    self.content = {}
end

function Dashboard:_addLine(text, color, opts)
    opts = opts or {}
    local lbl = new("TextLabel", {
        Size = UDim2.new(1, -4, 0, opts.height or 16),
        BackgroundTransparency = 1,
        Text = tostring(text),
        TextColor3 = color or UI.Config.COLOR_TEXT,
        TextSize = opts.size or 11,
        Font = opts.bold and Enum.Font.GothamBold or Enum.Font.Code,
        TextXAlignment = Enum.TextXAlignment.Left,
        TextYAlignment = Enum.TextYAlignment.Top,
        TextWrapped = opts.wrap ~= false,
        LayoutOrder = #self.content,
        Parent = self.contentScroll,
    })
    table.insert(self.content, lbl)
    return lbl
end

function Dashboard:_addSectionHeader(text)
    local lbl = self:_addLine(text, UI.Config.COLOR_ACCENT, {
        size = 12, bold = true, height = 20,
    })
    return lbl
end

function Dashboard:_addSpacer(h)
    local s = new("Frame", {
        Size = UDim2.new(1, 0, 0, h or 6),
        BackgroundTransparency = 1,
        LayoutOrder = #self.content,
        Parent = self.contentScroll,
    })
    table.insert(self.content, s)
end

function Dashboard:renderContent()
    self:_clearContent()

    local tab = self.currentTab
    if tab == "summary"  then self:_renderSummary()
    elseif tab == "alerts"   then self:_renderAlerts()
    elseif tab == "timeline" then self:_renderTimeline()
    elseif tab == "ioc"      then self:_renderIOC()
    elseif tab == "risk"     then self:_renderRisk()
    elseif tab == "rules"    then self:_renderRules()
    elseif tab == "env"      then self:_renderEnv()
    elseif tab == "log"      then self:_renderLog()
    end
end

--========== RENDER: SUMMARY ==========--
function Dashboard:_renderSummary()
    if not self.edr then
        self:_addLine("No EDR instance", UI.Config.COLOR_TEXT_DIM)
        return
    end

    local s = self.edr.session
    self:_addSectionHeader("SESSION")
    self:_addLine("ID:          " .. tostring(s.id))
    self:_addLine("Duration:    " .. fmtDuration(s:elapsed()))
    self:_addLine("Events:      " .. tostring(s.events_processed))
    self:_addLine("Alerts:      " .. tostring(#self.edr.alerts))
    self:_addLine("Dropped:     " .. tostring(self.edr.buffer.dropped))

    self:_addSpacer(4)
    self:_addSectionHeader("TOP RULES TRIGGERED")

    local alerts = self.edr.alerts or {}
    local byRule = {}
    for _, a in ipairs(alerts) do
        local r = a.rule or "?"
        byRule[r] = (byRule[r] or 0) + 1
    end
    local sorted = {}
    for r, c in pairs(byRule) do table.insert(sorted, { rule = r, count = c }) end
    table.sort(sorted, function(a, b) return a.count > b.count end)

    if #sorted == 0 then
        self:_addLine("(no rules triggered yet)", UI.Config.COLOR_TEXT_DIM)
    else
        for i = 1, math.min(8, #sorted) do
            local item = sorted[i]
            local color = item.count >= 3 and UI.Config.COLOR_DANGER or
                          item.count >= 1 and UI.Config.COLOR_WARN or
                          UI.Config.COLOR_TEXT
            self:_addLine(string.format("%d. %s  ×%d", i, item.rule, item.count), color)
        end
    end

    self:_addSpacer(4)
    self:_addSectionHeader("CURRENT RISK")
    local risk = 0
    if self.rules and self.rules.computeSessionRisk and self.edr then
        local ok, r = pcall(function()
            return self.rules.computeSessionRisk(self.edr.alerts)
        end)
        if ok then risk = r end
    end
    local riskColor = risk >= 0.85 and UI.Config.COLOR_DANGER or
                      risk >= 0.65 and UI.Config.COLOR_ORANGE or
                      risk >= 0.35 and UI.Config.COLOR_WARN or
                      UI.Config.COLOR_SUCCESS
    self:_addLine(string.format("%.1f%%", risk * 100), riskColor, { size = 22, bold = true, height = 30 })
end

--========== RENDER: ALERTS ==========--
function Dashboard:_renderAlerts()
    local alerts = self.edr and self.edr.alerts or {}
    self:_addSectionHeader("ALERTS (" .. #alerts .. ")")
    self:_addSpacer(2)

    if #alerts == 0 then
        self:_addLine("(no alerts)", UI.Config.COLOR_TEXT_DIM)
        return
    end

    local start = math.max(1, #alerts - 50)
    for i = #alerts, start, -1 do
        local a = alerts[i]
        local sev = a.severity or 0
        local color = SEV_COLOR[sev] or UI.Config.COLOR_TEXT
        local icon = SEV_ICON[sev] or "·"
        local label = SEV_LABEL[sev] or "?"

        -- Alert header
        self:_addLine(string.format("%s [%s] %s", icon, label, a.rule or "?"),
            color, { size = 11, bold = true })

        -- Alert message
        if a.message then
            self:_addLine("  " .. tostring(a.message):sub(1, 100),
                UI.Config.COLOR_TEXT_DIM, { size = 10 })
        end

        -- Score
        if a.score then
            self:_addLine(string.format("  score: %.2f | mitre: %s",
                a.score, a.mitre or "-"),
                UI.Config.COLOR_TEXT_DIM, { size = 10 })
        end

        self:_addSpacer(3)
    end
end

--========== RENDER: TIMELINE ==========--
function Dashboard:_renderTimeline()
    self:_addSectionHeader("FORENSIC TIMELINE")

    if not self.report or not self.report.timeline then
        self:_addLine("(no timeline data)", UI.Config.COLOR_TEXT_DIM)
        return
    end

    local entries = self.report.timeline.entries
    if #entries == 0 then
        self:_addLine("(no events)", UI.Config.COLOR_TEXT_DIM)
        return
    end

    local t0 = entries[1].t or 0
    local maxShow = 80
    local start = math.max(1, #entries - maxShow)

    for i = start, #entries do
        local e = entries[i]
        local icon = SEV_ICON[e.severity or 0] or "·"
        local color = SEV_COLOR[e.severity or 0] or UI.Config.COLOR_TEXT
        local rel = string.format("+%.1fs", (e.t or 0) - t0)

        local detail = ""
        if e.data then
            if e.data.url then detail = tostring(e.data.url):sub(1, 40)
            elseif e.data.path then detail = tostring(e.data.path):sub(1, 40)
            elseif e.data.key then detail = tostring(e.data.key)
            elseif e.data.name then detail = tostring(e.data.name)
            elseif e.data.rule then detail = tostring(e.data.rule)
            end
        end

        self:_addLine(string.format("%s %s  %-18s %s",
            icon, rel, tostring(e.type):sub(1, 18), detail), color, { size = 10 })
    end
end

--========== RENDER: IOC ==========--
function Dashboard:_renderIOC()
    self:_addSectionHeader("INDICATORS OF COMPROMISE")

    if not self.report or not self.report.ioc then
        self:_addLine("(no IOC data)", UI.Config.COLOR_TEXT_DIM)
        return
    end

    local iocs = self.report.ioc:getAll()
    if #iocs == 0 then
        self:_addLine("(no IOCs found)", UI.Config.COLOR_TEXT_DIM)
        return
    end

    for i = 1, math.min(100, #iocs) do
        local ioc = iocs[i]
        local color = UI.Config.COLOR_TEXT
        if ioc.type == "url" or ioc.type == "ipv4" then
            color = UI.Config.COLOR_ORANGE
        elseif ioc.type == "discord_token" or ioc.type == "telegram_bot" then
            color = UI.Config.COLOR_DANGER
        elseif ioc.type == "domain" then
            color = UI.Config.COLOR_WARN
        end

        self:_addLine(string.format("[%s] ×%d", ioc.type, ioc.count), color,
            { size = 10, bold = true })
        self:_addLine("  " .. tostring(ioc.value):sub(1, 80),
            UI.Config.COLOR_TEXT_DIM, { size = 10 })
    end
end

--========== RENDER: RISK ==========--
function Dashboard:_renderRisk()
    self:_addSectionHeader("RISK EVOLUTION")

    if not self.report or not self.report.risk_curve then
        self:_addLine("(no risk data)", UI.Config.COLOR_TEXT_DIM)
        return
    end

    local graph = self.report.risk_curve:renderASCII(48, 8)
    for line in graph:gmatch("[^\n]+") do
        self:_addLine(line, UI.Config.COLOR_SUCCESS, { size = 10 })
    end

    self:_addSpacer(6)
    self:_addSectionHeader("STATISTICS")

    local stats = self.report.stats or {}
    self:_addLine("Total alerts:    " .. tostring(stats.total_alerts or 0))
    self:_addLine("Unique alerts:   " .. tostring(stats.unique_alerts or 0))
    self:_addLine("Peak risk:       " .. string.format("%.1f%%", (self.report.risk and self.report.risk.peak or 0) * 100))
    self:_addLine("Current risk:    " .. string.format("%.1f%%", (self.report.risk and self.report.risk.overall or 0) * 100))
end

--========== RENDER: RULES ==========--
function Dashboard:_renderRules()
    self:_addSectionHeader("LOADED RULES")

    if not self.rules or not self.rules.ruleOrder then
        self:_addLine("(no rules engine)", UI.Config.COLOR_TEXT_DIM)
        return
    end

    for _, r in ipairs(self.rules.ruleOrder) do
        local color = SEV_COLOR[r.severity or 0] or UI.Config.COLOR_TEXT
        local icon = r.enabled and "✓" or "✗"
        self:_addLine(string.format("%s [%s] %s", icon, SEV_LABEL[r.severity or 0] or "?", r.id),
            color, { size = 10, bold = true })

        -- Toggle button
        local toggleBtn = new("TextButton", {
            Size = UDim2.new(0, 68, 0, 22),
            Position = UDim2.new(1, -74, 0, 0),
            BackgroundColor3 = r.enabled and UI.Config.COLOR_SUCCESS or UI.Config.COLOR_BORDER,
            BorderSizePixel = 0,
            Text = r.enabled and "ENABLED" or "DISABLED",
            TextColor3 = Color3.fromRGB(255, 255, 255),
            TextSize = 9,
            Font = Enum.Font.GothamBold,
            ZIndex = 2,
            Parent = self.contentScroll,
        })
        new("UICorner", { CornerRadius = UDim.new(0, 4), Parent = toggleBtn })
        -- Position ให้ตรงกับ rule label ด้านบน
        local topPos = 0
        for _, c in ipairs(self.contentScroll:GetChildren()) do
            if c:IsA("TextLabel") or c:IsA("Frame") then
                topPos = topPos + c.Size.Y.Offset + self.contentList.Padding.Offset
            end
        end
        toggleBtn.Position = UDim2.new(1, -74, 0, topPos - 24)
        toggleBtn.LayoutOrder = -1

        local isEnabled = r.enabled
        toggleBtn.MouseButton1Click:Connect(function()
            if isEnabled then
                self.rules:disable(r.id)
            else
                self.rules:enable(r.id)
            end
            self:renderContent()
        end)

        if r.mitre then
            self:_addLine("  " .. tostring(r.mitre), UI.Config.COLOR_TEXT_DIM, { size = 10 })
        end
        self:_addSpacer(2)
    end
end

--========== RENDER: ENV ==========--
function Dashboard:_renderEnv()
    self:_addSectionHeader("ENVIRONMENT DIFF")

    if not self.report or not self.report.envdiff then
        self:_addLine("(no env snapshot)", UI.Config.COLOR_TEXT_DIM)
        return
    end

    local d = self.report.envdiff
    self:_addLine(string.format("Added globals:    %d", d.total_added))
    self:_addLine(string.format("Removed globals:  %d", d.total_removed))
    self:_addLine(string.format("Changed types:    %d", d.total_changed))
    self:_addLine(string.format("Redefined funcs:  %d", d.total_redefined))

    if #d.redefined > 0 then
        self:_addSpacer(4)
        self:_addSectionHeader("REDEFINED FUNCTIONS")
        for i = 1, math.min(20, #d.redefined) do
            local r = d.redefined[i]
            self:_addLine("  ● " .. r.key, UI.Config.COLOR_DANGER, { size = 10, bold = true })
            self:_addLine(string.format("    %s → %s", r.before, r.after),
                UI.Config.COLOR_TEXT_DIM, { size = 9 })
        end
    end

    if #d.added > 0 then
        self:_addSpacer(4)
        self:_addSectionHeader("ADDED GLOBALS")
        for i = 1, math.min(30, #d.added) do
            local a = d.added[i]
            self:_addLine(string.format("  + %s (%s)", a.key, a.type),
                UI.Config.COLOR_WARN, { size = 10 })
        end
    end
end

--========== RENDER: LOG ==========--
function Dashboard:_renderLog()
    self:_addSectionHeader("EVENT LOG")

    if #self.logLines == 0 then
        self:_addLine("(waiting for events...)", UI.Config.COLOR_TEXT_DIM)
        return
    end

    for i = #self.logLines, math.max(1, #self.logLines - UI.Config.MAX_LOG_LINES), -1 do
        local entry = self.logLines[i]
        self:_addLine(entry.text, entry.color, { size = 10 })
    end
end

--========== UPDATE LOOP ==========--
function Dashboard:startUpdateLoop()
    if self._updateCo then return end

    self._updateCo = task.spawn(function()
        while self.gui and self.gui.Parent do
            task.wait(UI.Config.UPDATE_INTERVAL)
            pcall(function() self:update() end)
        end
    end)
end

function Dashboard:update()
    if not self.gui or not self.gui.Parent then return end

    -- ตรวจ orientation เปลี่ยน
    self:handleViewportChange()

    -- อัปเดต status label
    local statusText, statusColor
    if self.main and self.main.State then
        if self.main.State.killed then
            statusText = "🔴 KILLED"
            statusColor = UI.Config.COLOR_DANGER
        elseif self.main.State.paused then
            statusText = "🟡 PAUSED"
            statusColor = UI.Config.COLOR_WARN
        elseif self.main.State.running then
            statusText = "🟢 RUNNING"
            statusColor = UI.Config.COLOR_SUCCESS
        else
            statusText = "⚪ STOPPED"
            statusColor = UI.Config.COLOR_TEXT_DIM
        end

        -- Update start/stop button
        if self.startBtn then
            if self.main.State.running then
                self.startBtn.Text = "■ STOP"
                self.startBtn.BackgroundColor3 = UI.Config.COLOR_DANGER
            else
                self.startBtn.Text = "▶ START"
                self.startBtn.BackgroundColor3 = UI.Config.COLOR_SUCCESS
            end
        end
    else
        statusText = "⚪ IDLE"
        statusColor = UI.Config.COLOR_TEXT_DIM
    end

    if self.statusLbl then
        self.statusLbl.Text = statusText
        self.statusLbl.TextColor3 = statusColor
    end

    -- อัปเดต risk bar + metrics
    local risk = 0
    if self.rules and self.rules.computeSessionRisk and self.edr then
        local ok, r = pcall(function()
            return self.rules.computeSessionRisk(self.edr.alerts)
        end)
        if ok then risk = r end
    end

    if self.barFill then
        self.barFill.Size = UDim2.new(math.clamp(risk, 0, 1), 0, 1, 0)
        if risk < 0.35 then
            self.barFill.BackgroundColor3 = UI.Config.COLOR_SUCCESS
        elseif risk < 0.65 then
            self.barFill.BackgroundColor3 = UI.Config.COLOR_WARN
        elseif risk < 0.85 then
            self.barFill.BackgroundColor3 = UI.Config.COLOR_ORANGE
        else
            self.barFill.BackgroundColor3 = UI.Config.COLOR_DANGER
        end
    end

    if self.riskLbl and self.edr then
        self.riskLbl.Text = string.format(
            "Risk: %.1f%%  |  Events: %d  |  Alerts: %d",
            risk * 100,
            self.edr.session.events_processed,
            #self.edr.alerts
        )
    end

    -- Update bubble glow ตาม risk
    if self.bubbleStroke then
        if risk >= 0.85 then
            self.bubbleStroke.Color = UI.Config.COLOR_DANGER
            self.bubbleStroke.Thickness = 3
        elseif risk >= 0.5 then
            self.bubbleStroke.Color = UI.Config.COLOR_WARN
            self.bubbleStroke.Thickness = 2
        else
            self.bubbleStroke.Color = UI.Config.COLOR_SUCCESS
            self.bubbleStroke.Thickness = 1
        end
    end

    -- Live-render content ถ้าเป็น tab ที่ dynamic
    if self.currentTab == "alerts" or self.currentTab == "log" or self.currentTab == "timeline" then
        -- throttle การ re-render: ทุก 2 วินาที
        if not self._lastDynamicRender or (os.clock() - self._lastDynamicRender) >= 2 then
            self._lastDynamicRender = os.clock()
            self:renderContent()
        end
    end
end

function Dashboard:forceRefresh()
    self:renderContent()
end

--========== START/STOP HANDLER ==========--
function Dashboard:onStartStop()
    if not self.main then
        -- ถ้าไม่มี main ให้ emit แค่ log
        self:_pushLog("ไม่พบ main.lua — ต้อง integrate", UI.Config.COLOR_WARN)
        return
    end

    if self.main.State and self.main.State.running then
        if self.main.stop then self.main.stop("ui_button") end
    else
        if self.main.start then self.main.start() end
    end

    task.wait(0.3)
    self:forceRefresh()
end

--========== LOG PUSH ==========--
function Dashboard:_pushLog(text, color)
    table.insert(self.logLines, {
        t = os.clock(),
        text = "› " .. tostring(text),
        color = color or UI.Config.COLOR_TEXT_DIM,
    })
    if #self.logLines > UI.Config.MAX_LOG_LINES * 2 then
        table.remove(self.logLines, 1)
    end
end

--========== HOOK ALERT ==========--
function Dashboard:attachToEDR()
    if not self.edr then return end

    local oldOnAlert = self.edr.onAlert
    self.edr.onAlert = function(alert)
        if oldOnAlert then pcall(oldOnAlert, alert) end
        local sev = alert.severity or 0
        local icon = SEV_ICON[sev] or "·"
        self:_pushLog(string.format("%s [%s] %s",
            icon, alert.rule or "?", tostring(alert.message or ""):sub(1, 60)),
            SEV_COLOR[sev] or UI.Config.COLOR_TEXT)
    end
end

--========== EXPORT ==========--
UI.Dashboard = Dashboard
UI.SEVERITY_COLORS = SEV_COLOR
UI.SEVERITY_LABELS = SEV_LABEL

return UI