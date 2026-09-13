--[[
    ============================================================
    EDR UI v3.0 — Mobile-First Full Dashboard
    ============================================================
    ปรับปรุงจาก v2.0:
    - 12 tabs (เพิ่ม ToS)
    - Health Score visualization
    - Circuit Breaker status
    - Anti-Ban countdown
    - Module grid view
    - Adaptive refresh + throttle
    - Zero-crash rendering

    Tabs:
      1.  summary  — session + health + risk
      2.  alerts   — live alerts
      3.  vulns    — vulnerabilities
      4.  api      — Roblox API stats
      5.  health   — modules + circuit breaker
      6.  tos      — compliance + audit + policy
      7.  timeline — forensic timeline
      8.  ioc      — indicators of compromise
      9.  risk     — risk curve + prediction
      10. rules    — rule list + toggle
      11. env      — environment diff
      12. log      — event log

    วิธีใช้:
        local UI = require("ui")
        local d = UI.new(edr, rules, report, main)
        d:show()
    ============================================================
]]

local UI = {}

--========== CONFIG ==========--
UI.Config = {
    -- Layout
    WIDTH_SCALE          = 0.96,
    HEIGHT_SCALE_PORT    = 0.85,
    HEIGHT_SCALE_LAND    = 0.92,
    TOP_MARGIN           = 60,
    BOTTOM_MARGIN        = 60,
    CORNER_RADIUS        = 14,
    MAX_WIDTH            = 480,
    MAX_HEIGHT           = 720,

    -- Update
    UPDATE_INTERVAL      = 1.0,
    RENDER_THROTTLE      = 1.5,
    MAX_LOG_LINES        = 200,

    -- Colors (GitHub Dark)
    BG                   = Color3.fromRGB(13, 17, 23),
    PANEL                = Color3.fromRGB(22, 27, 34),
    PANEL_ALT            = Color3.fromRGB(28, 33, 40),
    BORDER               = Color3.fromRGB(48, 54, 61),
    TEXT                 = Color3.fromRGB(201, 209, 217),
    TEXT_DIM             = Color3.fromRGB(139, 148, 158),
    TEXT_BRIGHT          = Color3.fromRGB(240, 246, 252),
    ACCENT               = Color3.fromRGB(88, 166, 255),
    SUCCESS              = Color3.fromRGB(126, 231, 135),
    WARN                 = Color3.fromRGB(210, 153, 34),
    ORANGE               = Color3.fromRGB(240, 140, 50),
    DANGER               = Color3.fromRGB(248, 81, 73),
    PURPLE               = Color3.fromRGB(188, 140, 255),
    PINK                 = Color3.fromRGB(255, 121, 198),
    CYAN                 = Color3.fromRGB(121, 192, 255),
}

--========== SEVERITY ==========--
local SEV_COLOR = {
    [0] = Color3.fromRGB(139, 148, 158),
    [1] = Color3.fromRGB(126, 231, 135),
    [2] = Color3.fromRGB(210, 153, 34),
    [3] = Color3.fromRGB(240, 140, 50),
    [4] = Color3.fromRGB(248, 81, 73),
}
local SEV_LABEL = { [0]="INFO", [1]="LOW", [2]="MED", [3]="HIGH", [4]="CRIT" }
local SEV_ICON  = { [0]="·",    [1]="○",   [2]="◐",   [3]="●",    [4]="◆" }

--========== HELPERS ==========--
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
    if sec < 0 then sec = 0 end
    if sec < 60 then return sec .. "s" end
    if sec < 3600 then return math.floor(sec/60) .. "m" .. (sec%60) .. "s" end
    return math.floor(sec/3600) .. "h" .. math.floor((sec%3600)/60) .. "m"
end

local function fmtNum(n)
    n = tonumber(n) or 0
    if n >= 1e9 then return string.format("%.1fB", n/1e9) end
    if n >= 1e6 then return string.format("%.1fM", n/1e6) end
    if n >= 1e3 then return string.format("%.1fK", n/1e3) end
    return tostring(math.floor(n))
end

local function getParentGui()
    local CoreGui = game:GetService("CoreGui")
    local ok, cg = pcall(function() return CoreGui end)
    if ok and cg then return cg end
    return game:GetService("Players").LocalPlayer:WaitForChild("PlayerGui")
end

local function mk(className, props, children)
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

local function safe(fn, ...)
    local ok, result = pcall(fn, ...)
    if ok then return result end
    return nil
end

-- Health score color
local function healthColor(score)
    if score >= 90 then return UI.Config.SUCCESS
    elseif score >= 70 then return UI.Config.CYAN
    elseif score >= 50 then return UI.Config.WARN
    elseif score >= 30 then return UI.Config.ORANGE
    else return UI.Config.DANGER end
end

-- Risk color
local function riskColor(risk)
    if risk >= 0.85 then return UI.Config.DANGER
    elseif risk >= 0.65 then return UI.Config.ORANGE
    elseif risk >= 0.35 then return UI.Config.WARN
    else return UI.Config.SUCCESS end
end

--========== DASHBOARD ==========--
local Dashboard = {}
Dashboard.__index = Dashboard

function UI.new(edr, rules, report, main)
    local self = setmetatable({
        edr          = edr,
        rules        = rules,
        report       = report,
        main         = main,
        gui          = nil,
        root         = nil,
        bubble       = nil,
        bubbleStroke = nil,
        minimized    = false,
        currentTab   = "summary",
        tabs         = {},
        content      = {},
        logLines     = {},
        cmdHistory   = {},
        historyIdx   = 0,
        lastUpdate   = 0,
        lastRender   = 0,
        lastPortrait = isPortrait(),
        _updateThread = nil,
        _destroyed   = false,
        _stats       = {
            risk = 0,
            events = 0,
            alerts = 0,
            vulnCount = 0,
            health = 100,
            recovered = 0,
        },
    }, Dashboard)
    return self
end

--========== BUILD ROOT ==========--
function Dashboard:_buildRoot()
    if self._destroyed or self.gui then return end

    local parentGui = getParentGui()

    local gui = mk("ScreenGui", {
        Name = "EDR_UI_" .. tostring(math.random(100000, 999999)),
        ResetOnSpawn = false,
        ZIndexBehavior = Enum.ZIndexBehavior.Sibling,
        DisplayOrder = 100,
        Parent = parentGui,
    })
    self.gui = gui

    --===== Bubble =====--
    local bubble = mk("TextButton", {
        Name = "Bubble",
        Size = UDim2.new(0, 60, 0, 60),
        Position = UDim2.new(1, -75, 0, 100),
        BackgroundColor3 = UI.Config.ACCENT,
        BorderSizePixel = 0,
        Text = "🛡",
        TextColor3 = Color3.fromRGB(255, 255, 255),
        TextSize = 26,
        Font = Enum.Font.GothamBold,
        Visible = false,
        Active = true,
        Draggable = true,
        Parent = gui,
    })
    mk("UICorner", { CornerRadius = UDim.new(0, 30), Parent = bubble })
    local bStroke = mk("UIStroke", {
        Color = UI.Config.SUCCESS,
        Thickness = 2,
        Parent = bubble,
    })
    mk("UIGradient", {
        Color = ColorSequence.new({
            ColorSequenceKeypoint.new(0, UI.Config.ACCENT),
            ColorSequenceKeypoint.new(1, Color3.fromRGB(126, 231, 135)),
        }),
        Parent = bubble,
    })
    self.bubble = bubble
    self.bubbleStroke = bStroke

    --===== Root Sheet =====--
    local root = mk("Frame", {
        Name = "Root",
        BackgroundColor3 = UI.Config.BG,
        BorderSizePixel = 0,
        Active = true,
        ClipsDescendants = true,
        Parent = gui,
    })
    mk("UICorner", { CornerRadius = UDim.new(0, UI.Config.CORNER_RADIUS), Parent = root })
    mk("UIStroke", { Color = UI.Config.BORDER, Thickness = 1.5, Parent = root })
    self.root = root

    --===== Header =====--
    local header = mk("Frame", {
        Name = "Header",
        Size = UDim2.new(1, -90, 0, 48),
        Position = UDim2.new(0, 12, 0, 4),
        BackgroundTransparency = 1,
        Parent = root,
    })

    mk("TextLabel", {
        Size = UDim2.new(1, 0, 0, 22),
        BackgroundTransparency = 1,
        Text = "🛡  EDR Monitor",
        TextColor3 = UI.Config.ACCENT,
        TextSize = 15,
        Font = Enum.Font.GothamBold,
        TextXAlignment = Enum.TextXAlignment.Left,
        Parent = header,
    })

    local statusLbl = mk("TextLabel", {
        Name = "StatusLbl",
        Size = UDim2.new(1, 0, 0, 20),
        Position = UDim2.new(0, 0, 0, 24),
        BackgroundTransparency = 1,
        Text = "⚪ STOPPED",
        TextColor3 = UI.Config.TEXT_DIM,
        TextSize = 11,
        Font = Enum.Font.Code,
        TextXAlignment = Enum.TextXAlignment.Left,
        Parent = header,
    })
    self.statusLbl = statusLbl

    --===== Close =====--
    local close = mk("TextButton", {
        Size = UDim2.new(0, 34, 0, 34),
        Position = UDim2.new(1, -78, 0, 8),
        BackgroundColor3 = UI.Config.DANGER,
        BorderSizePixel = 0,
        Text = "✕",
        TextColor3 = Color3.fromRGB(255, 255, 255),
        TextSize = 14,
        Font = Enum.Font.GothamBold,
        ZIndex = 5,
        Parent = root,
    })
    mk("UICorner", { CornerRadius = UDim.new(0, 8), Parent = close })
    close.MouseButton1Click:Connect(function() safe(function() self:destroy() end) end)

    --===== Minimize =====--
    local minBtn = mk("TextButton", {
        Size = UDim2.new(0, 34, 0, 34),
        Position = UDim2.new(1, -40, 0, 8),
        BackgroundColor3 = UI.Config.PANEL,
        BorderSizePixel = 0,
        Text = "—",
        TextColor3 = UI.Config.TEXT,
        TextSize = 18,
        Font = Enum.Font.GothamBold,
        ZIndex = 5,
        Parent = root,
    })
    mk("UICorner", { CornerRadius = UDim.new(0, 8), Parent = minBtn })
    minBtn.MouseButton1Click:Connect(function() safe(function() self:minimize() end) end)

    --===== Risk + Health bars =====--
    local statFrame = mk("Frame", {
        Size = UDim2.new(1, -24, 0, 46),
        Position = UDim2.new(0, 12, 0, 56),
        BackgroundColor3 = UI.Config.PANEL,
        BorderSizePixel = 0,
        Parent = root,
    })
    mk("UICorner", { CornerRadius = UDim.new(0, 8), Parent = statFrame })

    -- Risk bar
    local riskLbl = mk("TextLabel", {
        Size = UDim2.new(0.5, -8, 0, 14),
        Position = UDim2.new(0, 8, 0, 3),
        BackgroundTransparency = 1,
        Text = "Risk: 0.0%",
        TextColor3 = UI.Config.TEXT_DIM,
        TextSize = 10,
        Font = Enum.Font.Code,
        TextXAlignment = Enum.TextXAlignment.Left,
        Parent = statFrame,
    })
    self.riskLbl = riskLbl

    local riskBg = mk("Frame", {
        Size = UDim2.new(0.5, -8, 0, 6),
        Position = UDim2.new(0, 8, 0, 18),
        BackgroundColor3 = Color3.fromRGB(33, 38, 45),
        BorderSizePixel = 0,
        Parent = statFrame,
    })
    mk("UICorner", { CornerRadius = UDim.new(0, 3), Parent = riskBg })
    local riskFill = mk("Frame", {
        Size = UDim2.new(0, 0, 1, 0),
        BackgroundColor3 = UI.Config.SUCCESS,
        BorderSizePixel = 0,
        Parent = riskBg,
    })
    mk("UICorner", { CornerRadius = UDim.new(0, 3), Parent = riskFill })
    self.riskFill = riskFill

    -- Health bar
    local healthLbl = mk("TextLabel", {
        Size = UDim2.new(0.5, -8, 0, 14),
        Position = UDim2.new(0.5, 0, 0, 3),
        BackgroundTransparency = 1,
        Text = "Health: 100/100",
        TextColor3 = UI.Config.TEXT_DIM,
        TextSize = 10,
        Font = Enum.Font.Code,
        TextXAlignment = Enum.TextXAlignment.Left,
        Parent = statFrame,
    })
    self.healthLbl = healthLbl

    local healthBg = mk("Frame", {
        Size = UDim2.new(0.5, -8, 0, 6),
        Position = UDim2.new(0.5, 0, 0, 18),
        BackgroundColor3 = Color3.fromRGB(33, 38, 45),
        BorderSizePixel = 0,
        Parent = statFrame,
    })
    mk("UICorner", { CornerRadius = UDim.new(0, 3), Parent = healthBg })
    local healthFill = mk("Frame", {
        Size = UDim2.new(1, 0, 1, 0),
        BackgroundColor3 = UI.Config.SUCCESS,
        BorderSizePixel = 0,
        Parent = healthBg,
    })
    mk("UICorner", { CornerRadius = UDim.new(0, 3), Parent = healthFill })
    self.healthFill = healthFill

    -- Stats row
    local statsLbl = mk("TextLabel", {
        Size = UDim2.new(1, -16, 0, 14),
        Position = UDim2.new(0, 8, 0, 28),
        BackgroundTransparency = 1,
        Text = "Events: 0  |  Alerts: 0  |  Vulns: 0",
        TextColor3 = UI.Config.TEXT_DIM,
        TextSize = 10,
        Font = Enum.Font.Code,
        TextXAlignment = Enum.TextXAlignment.Left,
        Parent = statFrame,
    })
    self.statsLbl = statsLbl

    --===== Tab Bar =====--
    local tabBarFrame = mk("Frame", {
        Size = UDim2.new(1, -24, 0, 40),
        Position = UDim2.new(0, 12, 0, 108),
        BackgroundTransparency = 1,
        Parent = root,
    })

    local tabScroll = mk("ScrollingFrame", {
        Size = UDim2.new(1, 0, 1, 0),
        BackgroundTransparency = 1,
        BorderSizePixel = 0,
        ScrollBarThickness = 0,
        ScrollingDirection = Enum.ScrollingDirection.X,
        CanvasSize = UDim2.new(0, 0, 0, 0),
        AutomaticCanvasSize = Enum.AutomaticSize.X,
        Parent = tabBarFrame,
    })
    mk("UIListLayout", {
        FillDirection = Enum.FillDirection.Horizontal,
        Padding = UDim.new(0, 6),
        VerticalAlignment = Enum.VerticalAlignment.Center,
        Parent = tabScroll,
    })
    self.tabScroll = tabScroll

    local TABS = {
        { id = "summary",  label = "Summary" },
        { id = "alerts",   label = "Alerts" },
        { id = "vulns",    label = "Vulns" },
        { id = "api",      label = "API" },
        { id = "health",   label = "Health" },
        { id = "tos",      label = "ToS" },
        { id = "timeline", label = "Timeline" },
        { id = "ioc",      label = "IOC" },
        { id = "risk",     label = "Risk" },
        { id = "rules",    label = "Rules" },
        { id = "env",      label = "Env" },
        { id = "log",      label = "Log" },
    }

    for _, tabInfo in ipairs(TABS) do
        local tabBtn = mk("TextButton", {
            Name = "Tab_" .. tabInfo.id,
            Size = UDim2.new(0, 78, 0, 32),
            BackgroundColor3 = UI.Config.PANEL,
            BorderSizePixel = 0,
            Text = tabInfo.label,
            TextColor3 = UI.Config.TEXT_DIM,
            TextSize = 11,
            Font = Enum.Font.GothamSemibold,
            Parent = tabScroll,
        })
        mk("UICorner", { CornerRadius = UDim.new(0, 8), Parent = tabBtn })

        tabBtn.MouseButton1Click:Connect(function()
            safe(function() self:switchTab(tabInfo.id) end)
        end)

        self.tabs[tabInfo.id] = tabBtn
    end

    --===== Content =====--
    local contentFrame = mk("Frame", {
        Size = UDim2.new(1, -24, 1, -220),
        Position = UDim2.new(0, 12, 0, 154),
        BackgroundColor3 = UI.Config.PANEL,
        BorderSizePixel = 0,
        Parent = root,
    })
    mk("UICorner", { CornerRadius = UDim.new(0, 10), Parent = contentFrame })
    self.contentFrame = contentFrame

    local contentScroll = mk("ScrollingFrame", {
        Size = UDim2.new(1, -12, 1, -12),
        Position = UDim2.new(0, 6, 0, 6),
        BackgroundTransparency = 1,
        BorderSizePixel = 0,
        ScrollBarThickness = 5,
        ScrollBarImageColor3 = UI.Config.BORDER,
        CanvasSize = UDim2.new(0, 0, 0, 0),
        AutomaticCanvasSize = Enum.AutomaticSize.Y,
        Parent = contentFrame,
    })
    mk("UIListLayout", {
        Padding = UDim.new(0, 4),
        SortOrder = Enum.SortOrder.LayoutOrder,
        Parent = contentScroll,
    })
    mk("UIPadding", {
        PaddingTop = UDim.new(0, 6),
        PaddingLeft = UDim.new(0, 6),
        PaddingRight = UDim.new(0, 6),
        PaddingBottom = UDim.new(0, 6),
        Parent = contentScroll,
    })
    self.contentScroll = contentScroll

    --===== Command Input =====--
    local inputBg = mk("Frame", {
        Size = UDim2.new(1, -24, 0, 38),
        Position = UDim2.new(0, 12, 1, -104),
        BackgroundColor3 = UI.Config.PANEL,
        BorderSizePixel = 0,
        Parent = root,
    })
    mk("UICorner", { CornerRadius = UDim.new(0, 8), Parent = inputBg })
    mk("UIStroke", { Color = UI.Config.BORDER, Thickness = 1, Parent = inputBg })

    mk("TextLabel", {
        Size = UDim2.new(0, 26, 1, 0),
        BackgroundTransparency = 1,
        Text = " ›",
        TextColor3 = UI.Config.ACCENT,
        TextSize = 14,
        Font = Enum.Font.Code,
        TextXAlignment = Enum.TextXAlignment.Left,
        Parent = inputBg,
    })

    local cmdBox = mk("TextBox", {
        Size = UDim2.new(1, -34, 1, 0),
        Position = UDim2.new(0, 30, 0, 0),
        BackgroundTransparency = 1,
        Text = "",
        PlaceholderText = "พิมพ์คำสั่ง (เช่น /help)",
        PlaceholderColor3 = Color3.fromRGB(100, 110, 120),
        TextColor3 = Color3.fromRGB(220, 230, 240),
        Font = Enum.Font.Code,
        TextSize = 12,
        TextXAlignment = Enum.TextXAlignment.Left,
        ClearTextOnFocus = false,
        Parent = inputBg,
    })
    self.cmdBox = cmdBox

    cmdBox.FocusLost:Connect(function(enter)
        if not enter then return end
        local text = cmdBox.Text
        cmdBox.Text = ""
        if text == "" then return end
        table.insert(self.cmdHistory, 1, text)
        if #self.cmdHistory > 30 then table.remove(self.cmdHistory) end
        self.historyIdx = 0

        self:_pushLog("› " .. text, UI.Config.ACCENT)
        local result = safe(function()
            if self.main and self.main.executeCommand then
                return self.main.executeCommand(text)
            end
            return "Main not available"
        end)
        if result and result ~= "" then
            for line in tostring(result):gmatch("[^\n]+") do
                self:_pushLog(line, UI.Config.SUCCESS)
            end
        end
        self:forceRefresh()
    end)

    --===== Action Bar =====--
    local actionBar = mk("Frame", {
        Size = UDim2.new(1, -24, 0, 42),
        Position = UDim2.new(0, 12, 1, -56),
        BackgroundTransparency = 1,
        Parent = root,
    })
    mk("UIListLayout", {
        FillDirection = Enum.FillDirection.Horizontal,
        Padding = UDim.new(0, 6),
        VerticalAlignment = Enum.VerticalAlignment.Center,
        HorizontalAlignment = Enum.HorizontalAlignment.Center,
        Parent = actionBar,
    })

    local function makeBtn(label, color, cb)
        local b = mk("TextButton", {
            Size = UDim2.new(0, 0, 1, 0),
            BackgroundColor3 = color,
            BorderSizePixel = 0,
            Text = label,
            TextColor3 = Color3.fromRGB(255, 255, 255),
            TextSize = 12,
            Font = Enum.Font.GothamBold,
            AutomaticSize = Enum.AutomaticSize.X,
            Parent = actionBar,
        })
        mk("UICorner", { CornerRadius = UDim.new(0, 8), Parent = b })
        mk("UIPadding", {
            PaddingLeft = UDim.new(0, 14),
            PaddingRight = UDim.new(0, 14),
            Parent = b,
        })
        b.MouseButton1Click:Connect(function() safe(cb) end)
        return b
    end

    self.startBtn = makeBtn("▶ START", UI.Config.SUCCESS, function()
        self:onStartStop()
    end)
    makeBtn("📄 Export", UI.Config.ACCENT, function()
        if self.main and self.main.saveReport then self.main.saveReport() end
    end)
    makeBtn("🔄 Refresh", UI.Config.PANEL, function()
        self:forceRefresh()
    end)

    bubble.MouseButton1Click:Connect(function() safe(function() self:maximize() end) end)

    self:applyLayout()
    self:switchTab("summary")
end

--========== LAYOUT ==========--
function Dashboard:applyLayout()
    if not self.root or self._destroyed then return end
    local vp = getViewport()
    local portrait = vp.Y >= vp.X
    self.lastPortrait = portrait

    local width = vp.X * UI.Config.WIDTH_SCALE
    local heightScale = portrait and UI.Config.HEIGHT_SCALE_PORT or UI.Config.HEIGHT_SCALE_LAND
    local height = vp.Y * heightScale

    if width > UI.Config.MAX_WIDTH then width = UI.Config.MAX_WIDTH end
    if height > UI.Config.MAX_HEIGHT then height = UI.Config.MAX_HEIGHT end

    local xPos, yPos
    if portrait then
        xPos = (vp.X - width) / 2
        yPos = vp.Y - height - UI.Config.BOTTOM_MARGIN
        if yPos < UI.Config.TOP_MARGIN then yPos = UI.Config.TOP_MARGIN end
    else
        xPos = vp.X - width - 20
        yPos = (vp.Y - height) / 2
    end

    safe(function()
        self.root.Size = UDim2.new(0, width, 0, height)
        self.root.Position = UDim2.new(0, xPos, 0, yPos)
    end)
end

function Dashboard:handleViewportChange()
    if isPortrait() ~= self.lastPortrait then
        self:applyLayout()
    end
end

--========== SHOW/MIN/MAX ==========--
function Dashboard:show()
    if self._destroyed then return end
    if not self.gui then self:_buildRoot() end
    if self.minimized then self:minimize() else self:maximize() end
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
    self._destroyed = true
    if self._updateThread then
        safe(function() task.cancel(self._updateThread) end)
    end
    if self.gui then
        self.gui:Destroy()
        self.gui = nil
    end
end

--========== TAB SWITCH ==========--
function Dashboard:switchTab(tabId)
    self.currentTab = tabId
    for id, btn in pairs(self.tabs) do
        if id == tabId then
            btn.BackgroundColor3 = UI.Config.ACCENT
            btn.TextColor3 = Color3.fromRGB(255, 255, 255)
        else
            btn.BackgroundColor3 = UI.Config.PANEL
            btn.TextColor3 = UI.Config.TEXT_DIM
        end
    end
    self:renderContent()
end

--========== CONTENT HELPERS ==========--
function Dashboard:_clearContent()
    if not self.contentScroll then return end
    for _, child in ipairs(self.contentScroll:GetChildren()) do
        if not child:IsA("UIListLayout") and not child:IsA("UIPadding") then
            child:Destroy()
        end
    end
    self.content = {}
end

function Dashboard:_addLine(text, color, opts)
    opts = opts or {}
    if not self.contentScroll then return nil end
    local lbl = mk("TextLabel", {
        Size = UDim2.new(1, 0, 0, opts.height or 16),
        BackgroundTransparency = 1,
        Text = tostring(text or ""),
        TextColor3 = color or UI.Config.TEXT,
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

function Dashboard:_addHeader(text)
    return self:_addLine(text, UI.Config.ACCENT, { size = 12, bold = true, height = 22 })
end

function Dashboard:_addSpacer(h)
    if not self.contentScroll then return end
    local s = mk("Frame", {
        Size = UDim2.new(1, 0, 0, h or 6),
        BackgroundTransparency = 1,
        LayoutOrder = #self.content,
        Parent = self.contentScroll,
    })
    table.insert(self.content, s)
end

function Dashboard:_addSeparator()
    if not self.contentScroll then return end
    local s = mk("Frame", {
        Size = UDim2.new(1, 0, 0, 1),
        BackgroundColor3 = UI.Config.BORDER,
        BorderSizePixel = 0,
        LayoutOrder = #self.content,
        Parent = self.contentScroll,
    })
    table.insert(self.content, s)
end

--========== RENDER DISPATCH ==========--
function Dashboard:renderContent()
    if self._destroyed or not self.contentScroll then return end
    self:_clearContent()

    local tab = self.currentTab
    local renderFn = self["_render" .. tab:gsub("^%l", string.upper)]
    if type(renderFn) == "function" then
        local ok, err = pcall(renderFn, self)
        if not ok then
            self:_addLine("Render error: " .. tostring(err):sub(1, 100), UI.Config.DANGER)
        end
    else
        self:_addLine("Tab not implemented: " .. tostring(tab), UI.Config.TEXT_DIM)
    end
end

--========== RENDER: SUMMARY ==========--
function Dashboard:_renderSummary()
    if not self.edr then
        self:_addLine("EDR not available", UI.Config.TEXT_DIM)
        return
    end

    local s = self.edr.session
    if not s then
        self:_addLine("Session not available", UI.Config.TEXT_DIM)
        return
    end

    self:_addHeader("SESSION")
    self:_addLine("ID:        " .. tostring(s.id or "?"))
    self:_addLine("Duration:  " .. fmtDuration(s:elapsed and s:elapsed() or 0))
    self:_addLine("Events:    " .. fmtNum(s.events_processed or 0))
    self:_addLine("Alerts:    " .. fmtNum(#(self.edr.alerts or {})))
    self:_addLine("Dropped:   " .. fmtNum(self.edr.buffer and self.edr.buffer.dropped or 0))

    if self.main and self.main.State then
        local st = self.main.State
        self:_addLine("Recovered: " .. fmtNum(st.recovered or 0))
        self:_addLine("Errors:    " .. fmtNum(#(st.error_log or {})))
        self:_addLine("Session ID: " .. tostring(st.session_id or "?"):sub(1, 16))
    end

    -- Health
    self:_addSpacer(4)
    self:_addHeader("HEALTH")
    local healthScore = 100
    if self.main and self.main.Health and self.main.Health.getScore then
        healthScore = self.main.Health.getScore()
    end
    self:_addLine(string.format("Score: %d/100", healthScore), healthColor(healthScore), {
        size = 20, bold = true, height = 26,
    })

    -- Top rules
    self:_addSpacer(4)
    self:_addHeader("TOP RULES TRIGGERED")
    local alerts = self.edr.alerts or {}
    local byRule = {}
    for _, a in ipairs(alerts) do
        if a and a.rule then
            byRule[a.rule] = (byRule[a.rule] or 0) + 1
        end
    end
    local sorted = {}
    for r, c in pairs(byRule) do table.insert(sorted, { rule = r, count = c }) end
    table.sort(sorted, function(a, b) return a.count > b.count end)

    if #sorted == 0 then
        self:_addLine("(no rules triggered)", UI.Config.TEXT_DIM)
    else
        for i = 1, math.min(8, #sorted) do
            local item = sorted[i]
            local color = item.count >= 3 and UI.Config.DANGER
                or item.count >= 1 and UI.Config.WARN
                or UI.Config.TEXT
            self:_addLine(string.format("%d. %s  ×%d", i, item.rule, item.count), color)
        end
    end

    -- Current risk
    self:_addSpacer(4)
    self:_addHeader("CURRENT RISK")
    local risk = self:_computeRisk()
    self:_addLine(string.format("%.1f%%", risk * 100), riskColor(risk), {
        size = 26, bold = true, height = 34,
    })

    -- Prediction
    if self.report and self.report.risk_curve and self.report.risk_curve.prediction then
        local pred = self.report.risk_curve.prediction
        self:_addLine(string.format("Predicted (30s): %.1f%%", pred * 100),
            UI.Config.TEXT_DIM, { size = 10 })
    end

    -- ToS
    if self.main and self.main.ToS then
        self:_addSpacer(4)
        self:_addHeader("TOS COMPLIANCE")
        local summary = safe(function() return self.main.ToS.getAuditSummary() end)
        if summary then
            self:_addLine(string.format("Allowed: %d  |  Blocked: %d",
                summary.allowed, summary.blocked),
                summary.blocked > 0 and UI.Config.DANGER or UI.Config.SUCCESS)
        end
    end
end

--========== RENDER: ALERTS ==========--
function Dashboard:_renderAlerts()
    local alerts = (self.edr and self.edr.alerts) or {}
    self:_addHeader("ALERTS (" .. #alerts .. ")")
    self:_addSpacer(2)

    if #alerts == 0 then
        self:_addLine("(no alerts)", UI.Config.TEXT_DIM)
        return
    end

    local start = math.max(1, #alerts - 40)
    for i = #alerts, start, -1 do
        local a = alerts[i]
        if a then
            local sev = a.severity or 0
            local color = SEV_COLOR[sev] or UI.Config.TEXT
            local icon = SEV_ICON[sev] or "·"
            local label = SEV_LABEL[sev] or "?"

            self:_addLine(string.format("%s [%s] %s", icon, label, a.rule or "?"),
                color, { size = 11, bold = true })

            if a.message then
                self:_addLine("  " .. tostring(a.message):sub(1, 100),
                    UI.Config.TEXT_DIM, { size = 10 })
            end

            if a.score then
                local meta = string.format("  score: %.2f", a.score)
                if a.mitre then meta = meta .. " | " .. a.mitre end
                if a.category then meta = meta .. " | " .. a.category end
                self:_addLine(meta, UI.Config.TEXT_DIM, { size = 10 })
            end

            self:_addSpacer(3)
        end
    end
end

--========== RENDER: VULNS ==========--
function Dashboard:_renderVulns()
    local M = self.main and self.main.State and self.main.State.modules
    if not M or not M.Vuln then
        self:_addLine("Vuln Scanner not loaded", UI.Config.TEXT_DIM)
        return
    end

    local sum = safe(function() return M.Vuln.getSummary() end)
    if not sum then
        self:_addLine("Cannot fetch vuln summary", UI.Config.TEXT_DIM)
        return
    end

    self:_addHeader("VULNERABILITY FINDINGS")
    self:_addLine(string.format("Total: %d  |  Critical: %d  |  High: %d  |  Med: %d",
        sum.total or 0,
        (sum.by_sev and sum.by_sev[4]) or 0,
        (sum.by_sev and sum.by_sev[3]) or 0,
        (sum.by_sev and sum.by_sev[2]) or 0
    ), UI.Config.TEXT_BRIGHT, { bold = true })

    -- Attack surface
    if sum.attackSurface then
        local as = sum.attackSurface
        self:_addSpacer(4)
        self:_addHeader("ATTACK SURFACE")
        self:_addLine(string.format("Score: %d/100", as.score or 0),
            as.score >= 70 and UI.Config.DANGER
                or as.score >= 40 and UI.Config.WARN
                or UI.Config.SUCCESS, { size = 14, bold = true })
        self:_addLine(string.format("  Remotes: %d  |  Scripts: %d  |  Sensitive: %d",
            as.remotes_exposed or 0, as.scripts_exposed or 0, as.sensitive_paths or 0),
            UI.Config.TEXT_DIM, { size = 10 })
    end

    -- Fuzzing stats
    if sum.fuzzing then
        local fz = sum.fuzzing
        self:_addSpacer(4)
        self:_addHeader("FUZZING")
        self:_addLine(string.format("Iterations: %d  |  Hits: %d  |  Rollbacks: %d",
            fz.iterations or 0, fz.hits or 0, fz.rollbacks or 0),
            UI.Config.TEXT_DIM, { size = 10 })
        self:_addLine(string.format("  Timeouts: %d  |  Errors: %d",
            fz.timeouts or 0, fz.errors or 0),
            UI.Config.TEXT_DIM, { size = 10 })
    end

    -- Categories
    if sum.by_cat and next(sum.by_cat) then
        self:_addSpacer(4)
        self:_addHeader("BY CATEGORY")
        for cat, count in pairs(sum.by_cat) do
            self:_addLine(string.format("  • %s  ×%d", tostring(cat), count), UI.Config.TEXT)
        end
    end

    -- Top findings
    local top = safe(function() return M.Vuln.getTopFindings(30) end) or {}
    if #top == 0 then
        self:_addSpacer(4)
        self:_addLine("(no findings yet)", UI.Config.SUCCESS)
        return
    end

    self:_addSpacer(4)
    self:_addHeader("TOP FINDINGS (" .. #top .. ")")
    for i, f in ipairs(top) do
        local sev = f.severity or 0
        local color = SEV_COLOR[sev] or UI.Config.TEXT
        local icon = SEV_ICON[sev] or "·"

        self:_addLine(string.format("%s [%s] %s", icon, SEV_LABEL[sev] or "?",
            tostring(f.title or "?")), color, { size = 11, bold = true })

        if f.detail then
            self:_addLine("  " .. tostring(f.detail):sub(1, 120),
                UI.Config.TEXT_DIM, { size = 10 })
        end

        if f.category then
            local meta = "  cat: " .. tostring(f.category)
            if f.mitre then meta = meta .. " | " .. tostring(f.mitre) end
            self:_addLine(meta, UI.Config.TEXT_DIM, { size = 9 })
        end

        self:_addSpacer(3)
    end
end

--========== RENDER: API ==========--
function Dashboard:_renderApi()
    local M = self.main and self.main.State and self.main.State.modules
    if not M or not M.RobloxAPI then
        self:_addLine("Roblox API Monitor not loaded", UI.Config.TEXT_DIM)
        return
    end

    local s = safe(function() return M.RobloxAPI.getStats() end)
    if not s then
        self:_addLine("Cannot fetch API stats", UI.Config.TEXT_DIM)
        return
    end

    self:_addHeader("INSTANCE STATS")
    self:_addLine(string.format("Created:   %s", fmtNum(s.instances and s.instances.create or 0)))
    self:_addLine(string.format("Destroyed: %s", fmtNum(s.instances and s.instances.destroy or 0)))
    self:_addLine(string.format("Tracked:   %s", fmtNum(s.instances and s.instances.tracked or 0)))

    self:_addSpacer(4)
    self:_addHeader("PROPERTIES")
    self:_addLine(string.format("Changes: %s", fmtNum(s.properties and s.properties.changes or 0)))
    self:_addLine(string.format("Batch:   %s", fmtNum(s.properties and s.properties.batchSize or 0)))

    self:_addSpacer(4)
    self:_addHeader("SAMPLING")
    if s.sampling then
        self:_addLine(string.format("Rate:    %.0f%%", (s.sampling.rate or 0) * 100))
        self:_addLine(string.format("Kept:    %s", fmtNum(s.sampling.kept or 0)))
        self:_addLine(string.format("Dropped: %s", fmtNum(s.sampling.dropped or 0)))
    end

    self:_addSpacer(4)
    self:_addHeader("SENSITIVE SERVICES")
    local svcList = safe(function() return M.RobloxAPI.getSensitiveServiceList() end) or {}
    if #svcList == 0 then
        self:_addLine("(none accessed)", UI.Config.TEXT_DIM)
    else
        for i, svc in ipairs(svcList) do
            if i > 15 then break end
            local color = UI.Config.TEXT
            if svc.count >= 10 then color = UI.Config.DANGER
            elseif svc.count >= 3 then color = UI.Config.WARN end
            self:_addLine(string.format("  %-28s ×%d", tostring(svc.service), svc.count), color)
        end
    end

    self:_addSpacer(4)
    self:_addHeader("PLACE INFO")
    self:_addLine("Player:   " .. tostring(safe(function()
        return game:GetService("Players").LocalPlayer.Name
    end) or "?"))
    self:_addLine("Place ID: " .. tostring(safe(function() return game.PlaceId end) or "?"))
    self:_addLine("Job ID:   " .. tostring(safe(function() return game.JobId end) or "?"):sub(1, 20))
end

--========== RENDER: HEALTH ==========--
function Dashboard:_renderHealth()
    local M = self.main and self.main.State and self.main.State.modules
    if not M then
        self:_addLine("Main not loaded", UI.Config.TEXT_DIM)
        return
    end

    local healthScore = 100
    if self.main.Health and self.main.Health.getScore then
        healthScore = self.main.Health.getScore()
    end

    self:_addHeader("HEALTH SCORE")
    self:_addLine(string.format("%d / 100", healthScore), healthColor(healthScore), {
        size = 32, bold = true, height = 42,
    })

    -- Module health
    self:_addSpacer(4)
    self:_addHeader("MODULE HEALTH")

    local report = safe(function()
        return self.main.Health.getReport()
    end)

    if not report then
        self:_addLine("(no report)", UI.Config.TEXT_DIM)
    else
        for _, h in ipairs(report) do
            local icon = "?"
            local color = UI.Config.TEXT_DIM
            if h.status == "healthy" then
                icon = "✓"; color = UI.Config.SUCCESS
            elseif h.status == "error" then
                icon = "✗"; color = UI.Config.DANGER
            end
            self:_addLine(string.format("%s %-12s  err=%d  retry=%d",
                icon, tostring(h.name or "?"), h.err_count or 0, h.retry_count or 0),
                color, { size = 11 })
        end
    end

    -- Circuit Breaker
    if self.main.Circuit then
        self:_addSpacer(4)
        self:_addHeader("CIRCUIT BREAKER")
        for name, c in pairs(self.main.Circuit) do
            if type(c) == "table" then
                local color = c.state == "closed" and UI.Config.SUCCESS
                    or c.state == "half-open" and UI.Config.WARN
                    or UI.Config.DANGER
                self:_addLine(string.format("  %-12s [%s]  fails=%d",
                    tostring(name), tostring(c.state or "?"), c.fail_count or 0), color,
                    { size = 11 })
            end
        end
    end

    -- Recovery
    self:_addSpacer(4)
    self:_addHeader("RECOVERY")
    local st = self.main.State
    if st then
        self:_addLine("Total recovered: " .. fmtNum(st.recovered or 0), UI.Config.SUCCESS)
        self:_addLine("Interval: " .. tostring(
            self.main.Config and self.main.Config.RECOVERY_INTERVAL or "?") .. "s")
    end

    -- Recent errors
    self:_addSpacer(4)
    self:_addHeader("RECENT ERRORS")
    local errors = st and st.error_log or {}
    if #errors == 0 then
        self:_addLine("(no errors)", UI.Config.SUCCESS)
    else
        local start = math.max(1, #errors - 10)
        for i = start, #errors do
            local e = errors[i]
            if e then
                self:_addLine(string.format("[%.1fs] %s: %s",
                    e.t or 0, tostring(e.module or "?"),
                    tostring(e.message or ""):sub(1, 60)),
                    UI.Config.WARN, { size = 10 })
            end
        end
    end
end

--========== RENDER: TOS ==========--
function Dashboard:_renderTos()
    local main = self.main
    if not main or not main.ToS then
        self:_addLine("ToS module not available", UI.Config.TEXT_DIM)
        return
    end

    self:_addHeader("TOS COMPLIANCE")
    local summary = safe(function() return main.ToS.getAuditSummary() end)

    if not summary then
        self:_addLine("(no audit data)", UI.Config.TEXT_DIM)
        return
    end

    self:_addLine(string.format("Total operations:  %d", summary.total), UI.Config.TEXT)
    self:_addLine(string.format("Allowed:           %d", summary.allowed), UI.Config.SUCCESS)
    self:_addLine(string.format("Blocked:           %d", summary.blocked),
        summary.blocked > 0 and UI.Config.DANGER or UI.Config.TEXT_DIM)

    -- Recent audit
    self:_addSpacer(4)
    self:_addHeader("RECENT AUDIT (last 20)")
    if #main.State.audit_log == 0 then
        self:_addLine("(no audit entries)", UI.Config.TEXT_DIM)
    else
        local start = math.max(1, #main.State.audit_log - 20)
        for i = start, #main.State.audit_log do
            local e = main.State.audit_log[i]
            if e then
                local icon = e.action == "BLOCKED" and "🚫" or "✓"
                local color = e.action == "BLOCKED" and UI.Config.DANGER or UI.Config.SUCCESS
                self:_addLine(string.format("%s [%.1fs] %s", icon, e.t, tostring(e.operation)),
                    color, { size = 10 })
            end
        end
    end

    -- Anti-Ban
    self:_addSpacer(4)
    self:_addHeader("ANTI-BAN STATUS")
    if main.Config and main.Config.ANTIBAN_ENABLED then
        self:_addLine("Status: ENABLED", UI.Config.SUCCESS, { bold = true })

        if main.State.session_start then
            local elapsed = os.clock() - main.State.session_start
            local rotate = main.Config.ANTIBAN_SESSION_ROTATE or 3600
            local remaining = math.max(0, rotate - elapsed)
            self:_addLine(string.format("Session age:    %s", fmtDuration(elapsed)),
                UI.Config.TEXT_DIM, { size = 10 })
            self:_addLine(string.format("Next rotation:  %s", fmtDuration(remaining)),
                remaining < 300 and UI.Config.WARN or UI.Config.TEXT_DIM, { size = 10 })
        end

        self:_addLine(string.format("Behavior norm:  %s",
            tostring(main.Config.ANTIBAN_BEHAVIOR_NORM)), UI.Config.TEXT_DIM, { size = 10 })
        self:_addLine(string.format("Max events/sec: %d",
            main.Config.ANTIBAN_MAX_EVENTS_SEC or 0), UI.Config.TEXT_DIM, { size = 10 })
        self:_addLine(string.format("Max network/s:  %d",
            main.Config.ANTIBAN_MAX_NETWORK_SEC or 0), UI.Config.TEXT_DIM, { size = 10 })
    else
        self:_addLine("Status: DISABLED", UI.Config.WARN)
    end

    -- Policy
    self:_addSpacer(4)
    self:_addHeader("POLICY")
    self:_addLine("Blocked operations:", UI.Config.DANGER, { bold = true })
    for _, op in ipairs({
        "fire_remote", "write_memory", "read_memory", "dump_source",
        "hook_game_metatable", "bypass_byfron", "elevate_identity",
        "inject_code", "modify_script",
    }) do
        self:_addLine("  ❌ " .. op, UI.Config.DANGER, { size = 10 })
    end

    self:_addLine("", UI.Config.TEXT)
    self:_addLine("Allowed operations:", UI.Config.SUCCESS, { bold = true })
    for _, op in ipairs({
        "read_service", "read_instance", "read_property",
        "scan_children", "scan_attributes", "monitor_signal",
        "emit_event", "install_hook", "scan_vulnerability",
        "generate_report", "dry_run_fuzz",
    }) do
        self:_addLine("  ✅ " .. op, UI.Config.SUCCESS, { size = 10 })
    end
end

--========== RENDER: TIMELINE ==========--
function Dashboard:_renderTimeline()
    self:_addHeader("FORENSIC TIMELINE")

    if not self.report or not self.report.timeline then
        self:_addLine("(no timeline data)", UI.Config.TEXT_DIM)
        return
    end

    local entries = self.report.timeline.entries or {}
    if #entries == 0 then
        self:_addLine("(no events)", UI.Config.TEXT_DIM)
        return
    end

    local t0 = entries[1].t or 0
    local maxShow = 60
    local start = math.max(1, #entries - maxShow)

    for i = start, #entries do
        local e = entries[i]
        if e then
            local icon = SEV_ICON[e.severity or 0] or "·"
            local color = SEV_COLOR[e.severity or 0] or UI.Config.TEXT
            local rel = string.format("+%.1fs", (e.t or 0) - t0)

            local detail = ""
            if e.data then
                if e.data.url then detail = tostring(e.data.url):sub(1, 35)
                elseif e.data.path then detail = tostring(e.data.path):sub(1, 35)
                elseif e.data.key then detail = tostring(e.data.key)
                elseif e.data.name then detail = tostring(e.data.name)
                elseif e.data.rule then detail = tostring(e.data.rule)
                elseif e.data.value then detail = tostring(e.data.value):sub(1, 35)
                end
            end

            self:_addLine(string.format("%s %s %-16s %s",
                icon, rel, tostring(e.type or "?"):sub(1, 16), detail),
                color, { size = 10 })
        end
    end
end

--========== RENDER: IOC ==========--
function Dashboard:_renderIOC()
    self:_addHeader("INDICATORS OF COMPROMISE")

    if not self.report or not self.report.ioc then
        self:_addLine("(no IOC data)", UI.Config.TEXT_DIM)
        return
    end

    local iocs = safe(function() return self.report.ioc:getAll() end) or {}
    if #iocs == 0 then
        self:_addLine("(no IOCs found)", UI.Config.TEXT_DIM)
        return
    end

    -- Summary
    local typeCounts = {}
    for _, ioc in ipairs(iocs) do
        typeCounts[ioc.type] = (typeCounts[ioc.type] or 0) + 1
    end
    self:_addLine("Summary by type:", UI.Config.TEXT_BRIGHT, { bold = true })
    for t, c in pairs(typeCounts) do
        self:_addLine(string.format("  %-16s %d", tostring(t), c), UI.Config.TEXT_DIM, { size = 10 })
    end
    self:_addSpacer(4)

    for i = 1, math.min(80, #iocs) do
        local ioc = iocs[i]
        local color = UI.Config.TEXT
        if ioc.risk and ioc.risk >= 0.8 then color = UI.Config.DANGER
        elseif ioc.risk and ioc.risk >= 0.5 then color = UI.Config.ORANGE
        elseif ioc.type == "url" or ioc.type == "ipv4" then color = UI.Config.ORANGE
        elseif ioc.type == "md5" or ioc.type == "sha256" then color = UI.Config.PURPLE
        end

        local conf = ioc.confidence and string.format(" c=%.2f", ioc.confidence) or ""
        self:_addLine(string.format("[%s] ×%d%s", tostring(ioc.type), ioc.count or 0, conf),
            color, { size = 10, bold = true })
        self:_addLine("  " .. tostring(ioc.value or ""):sub(1, 90),
            UI.Config.TEXT_DIM, { size = 10 })
    end
end

--========== RENDER: RISK ==========--
function Dashboard:_renderRisk()
    self:_addHeader("RISK EVOLUTION")

    if not self.report or not self.report.risk_curve then
        self:_addLine("(no risk data)", UI.Config.TEXT_DIM)
        return
    end

    local graph = safe(function()
        return self.report.risk_curve:renderASCII(46, 8)
    end)
    if graph then
        for line in graph:gmatch("[^\n]+") do
            self:_addLine(line, UI.Config.SUCCESS, { size = 10 })
        end
    end

    self:_addSpacer(4)
    self:_addHeader("STATISTICS")

    local stats = self.report.stats or {}
    self:_addLine("Total alerts:    " .. tostring(stats.total_alerts or 0))
    self:_addLine("Unique alerts:   " .. tostring(stats.unique_alerts or 0))
    self:_addLine("Peak risk:       " .. string.format("%.1f%%",
        (self.report.risk and self.report.risk.peak or 0) * 100))
    self:_addLine("Current risk:    " .. string.format("%.1f%%", self:_computeRisk() * 100))
    if self.report.risk_curve.prediction then
        self:_addLine("Prediction:      " .. string.format("%.1f%%",
            self.report.risk_curve.prediction * 100),
            UI.Config.WARN)
    end

    self:_addSpacer(4)
    self:_addHeader("THRESHOLDS")
    if self.main and self.main.Config then
        self:_addLine("Warn:     " .. string.format("%.0f%%",
            (self.main.Config.WARN_THRESHOLD or 0) * 100))
        self:_addLine("Kill:     " .. string.format("%.0f%%",
            (self.main.Config.KILL_THRESHOLD or 0) * 100))
        self:_addLine("Enabled:  " .. tostring(self.main.Config.KILL_SWITCH_ENABLED))
    end
end

--========== RENDER: RULES ===========--
function Dashboard:_renderRules()
    if not self.rules or not self.rules.ruleOrder then
        self:_addLine("Rules engine not ready", UI.Config.TEXT_DIM)
        return
    end

    self:_addHeader("RULES (" .. #self.rules.ruleOrder .. ")")
    self:_addLine("แตะปุ่มเพื่อเปิด/ปิดแต่ละ rule", UI.Config.TEXT_DIM, { size = 10 })
    self:_addSpacer(4)

    for _, r in ipairs(self.rules.ruleOrder) do
        local color = SEV_COLOR[r.severity or 0] or UI.Config.TEXT
        local icon = r.enabled and "✓" or "✗"

        local row = mk("Frame", {
            Size = UDim2.new(1, 0, 0, 38),
            BackgroundColor3 = UI.Config.PANEL_ALT,
            BorderSizePixel = 0,
            LayoutOrder = #self.content,
            Parent = self.contentScroll,
        })
        mk("UICorner", { CornerRadius = UDim.new(0, 6), Parent = row })
        table.insert(self.content, row)

        mk("TextLabel", {
            Size = UDim2.new(1, -80, 1, 0),
            Position = UDim2.new(0, 8, 0, 0),
            BackgroundTransparency = 1,
            Text = string.format("%s [%s] %s", icon, SEV_LABEL[r.severity or 0] or "?", r.id or "?"),
            TextColor3 = color,
            TextSize = 11,
            Font = Enum.Font.GothamBold,
            TextXAlignment = Enum.TextXAlignment.Left,
            TextTruncate = Enum.TextTruncate.AtEnd,
            Parent = row,
        })

        local toggleBtn = mk("TextButton", {
            Size = UDim2.new(0, 66, 0, 26),
            Position = UDim2.new(1, -74, 0, 6),
            BackgroundColor3 = r.enabled and UI.Config.SUCCESS or UI.Config.BORDER,
            BorderSizePixel = 0,
            Text = r.enabled and "ON" or "OFF",
            TextColor3 = Color3.fromRGB(255, 255, 255),
            TextSize = 10,
            Font = Enum.Font.GothamBold,
            Parent = row,
        })
        mk("UICorner", { CornerRadius = UDim.new(0, 6), Parent = toggleBtn })

        local ruleId = r.id
        local isEnabled = r.enabled
        toggleBtn.MouseButton1Click:Connect(function()
            safe(function()
                if isEnabled then
                    self.rules:disable(ruleId)
                else
                    self.rules:enable(ruleId)
                end
                self:renderContent()
            end)
        end)
    end
end

--========== RENDER: ENV ==========--
function Dashboard:_renderEnv()
    self:_addHeader("ENVIRONMENT DIFF")

    if not self.report or not self.report.envdiff then
        self:_addLine("(no env snapshot)", UI.Config.TEXT_DIM)
        return
    end

    local d = self.report.envdiff
    self:_addLine(string.format("Added globals:    %d", d.total_added or 0))
    self:_addLine(string.format("Removed globals:  %d", d.total_removed or 0))
    self:_addLine(string.format("Changed types:    %d", d.total_changed or 0))
    self:_addLine(string.format("Redefined funcs:  %d", d.total_redefined or 0),
        UI.Config.WARN)

    if d.redefined and #d.redefined > 0 then
        self:_addSpacer(4)
        self:_addHeader("REDEFINED FUNCTIONS")
        for i = 1, math.min(20, #d.redefined) do
            local r = d.redefined[i]
            local sig = r.signature_changed and " ⚠️" or ""
            self:_addLine("● " .. tostring(r.key) .. sig,
                UI.Config.DANGER, { size = 10, bold = true })
            self:_addLine(string.format("  %s → %s",
                tostring(r.before or "?"):sub(1, 30),
                tostring(r.after or "?"):sub(1, 30)),
                UI.Config.TEXT_DIM, { size = 9 })
        end
    end

    if d.added and #d.added > 0 then
        self:_addSpacer(4)
        self:_addHeader("ADDED GLOBALS")
        for i = 1, math.min(30, #d.added) do
            local a = d.added[i]
            self:_addLine(string.format("+ %s (%s)", tostring(a.key), tostring(a.type)),
                UI.Config.WARN, { size = 10 })
        end
    end
end

--========== RENDER: LOG ==========--
function Dashboard:_renderLog()
    self:_addHeader("EVENT LOG")

    if #self.logLines == 0 then
        self:_addLine("(waiting...)", UI.Config.TEXT_DIM)
        return
    end

    local start = math.max(1, #self.logLines - 100)
    for i = start, #self.logLines do
        local entry = self.logLines[i]
        if entry then
            self:_addLine(tostring(entry.text), entry.color or UI.Config.TEXT_DIM, { size = 10 })
        end
    end
end

--========== RISK HELPER ==========--
function Dashboard:_computeRisk()
    if self.rules and self.rules.computeSessionRisk and self.edr then
        local ok, r = pcall(function()
            return self.rules.computeSessionRisk(self.edr.alerts)
        end)
        if ok and type(r) == "number" then return r end
    end
    return 0
end

--========== UPDATE LOOP ==========--
function Dashboard:startUpdateLoop()
    if self._updateThread or self._destroyed then return end

    self._updateThread = task.spawn(function()
        while not self._destroyed and self.gui and self.gui.Parent do
            task.wait(UI.Config.UPDATE_INTERVAL)
            pcall(function() self:update() end)
        end
    end)
end

function Dashboard:update()
    if self._destroyed or not self.gui or not self.gui.Parent then return end
    safe(function() self:handleViewportChange() end)

    -- Status
    local statusText, statusColor = "⚪ STOPPED", UI.Config.TEXT_DIM
    local running = false
    if self.main and self.main.State then
        local st = self.main.State
        if st.killed then
            statusText = "🔴 KILLED"
            statusColor = UI.Config.DANGER
        elseif st.paused then
            statusText = "🟡 PAUSED"
            statusColor = UI.Config.WARN
        elseif st.running then
            statusText = "🟢 RUNNING"
            statusColor = UI.Config.SUCCESS
            running = true
        end

        if self.startBtn then
            if st.running then
                self.startBtn.Text = "■ STOP"
                self.startBtn.BackgroundColor3 = UI.Config.DANGER
            else
                self.startBtn.Text = "▶ START"
                self.startBtn.BackgroundColor3 = UI.Config.SUCCESS
            end
        end
    end

    if self.statusLbl then
        self.statusLbl.Text = statusText
        self.statusLbl.TextColor3 = statusColor
    end

    -- Risk
    local risk = self:_computeRisk()
    self._stats.risk = risk
    if self.riskFill then
        self.riskFill.Size = UDim2.new(math.clamp(risk, 0, 1), 0, 1, 0)
        self.riskFill.BackgroundColor3 = riskColor(risk)
    end
    if self.riskLbl then
        self.riskLbl.Text = string.format("Risk: %.1f%%", risk * 100)
        self.riskLbl.TextColor3 = riskColor(risk)
    end

    -- Health
    local healthScore = 100
    if self.main and self.main.Health and self.main.Health.getScore then
        healthScore = self.main.Health.getScore()
    end
    self._stats.health = healthScore
    if self.healthFill then
        self.healthFill.Size = UDim2.new(math.clamp(healthScore / 100, 0, 1), 0, 1, 0)
        self.healthFill.BackgroundColor3 = healthColor(healthScore)
    end
    if self.healthLbl then
        self.healthLbl.Text = string.format("Health: %d/100", healthScore)
        self.healthLbl.TextColor3 = healthColor(healthScore)
    end

    -- Stats
    local events = (self.edr and self.edr.session and self.edr.session.events_processed) or 0
    local alerts = #((self.edr and self.edr.alerts) or {})
    local vulnCount = 0
    local M = self.main and self.main.State and self.main.State.modules
    if M and M.Vuln and M.Vuln.getSummary then
        local vs = safe(function() return M.Vuln.getSummary() end)
        if vs then vulnCount = vs.total or 0 end
    end
    self._stats.events = events
    self._stats.alerts = alerts
    self._stats.vulnCount = vulnCount

    if self.statsLbl then
        self.statsLbl.Text = string.format(
            "Events: %s  |  Alerts: %d  |  Vulns: %d",
            fmtNum(events), alerts, vulnCount)
    end

    -- Bubble glow
    if self.bubbleStroke then
        if risk >= 0.85 then
            self.bubbleStroke.Color = UI.Config.DANGER
            self.bubbleStroke.Thickness = 3
        elseif risk >= 0.5 then
            self.bubbleStroke.Color = UI.Config.WARN
            self.bubbleStroke.Thickness = 2
        elseif healthScore < 50 then
            self.bubbleStroke.Color = UI.Config.ORANGE
            self.bubbleStroke.Thickness = 2
        else
            self.bubbleStroke.Color = UI.Config.SUCCESS
            self.bubbleStroke.Thickness = 1
        end
    end

    -- Adaptive render
    local now = os.clock()
    if now - self.lastRender >= UI.Config.RENDER_THROTTLE then
        local dynamicTabs = {
            summary = true, alerts = true, vulns = true,
            api = true, health = true, tos = true,
            timeline = true, log = true,
        }
        if running and dynamicTabs[self.currentTab] then
            self.lastRender = now
            safe(function() self:renderContent() end)
        end
    end
end

function Dashboard:forceRefresh()
    self.lastRender = os.clock()
    safe(function() self:renderContent() end)
end

--========== START/STOP ==========--
function Dashboard:onStartStop()
    if not self.main then
        self:_pushLog("Main not available", UI.Config.WARN)
        return
    end
    local st = self.main.State
    if st and st.running then
        if self.main.stop then self.main.stop("ui_button") end
    else
        if self.main.start then self.main.start() end
    end
    task.wait(0.3)
    self:forceRefresh()
end

--========== LOG ==========--
function Dashboard:_pushLog(text, color)
    table.insert(self.logLines, {
        t = os.clock(),
        text = "› " .. tostring(text or ""),
        color = color or UI.Config.TEXT_DIM,
    })
    if #self.logLines > UI.Config.MAX_LOG_LINES * 2 then
        table.remove(self.logLines, 1)
    end
end

--========== ATTACH TO EDR ==========--
function Dashboard:attachToEDR()
    if not self.edr then return end
    local oldOnAlert = self.edr.onAlert
    self.edr.onAlert = function(alert)
        if oldOnAlert then pcall(oldOnAlert, alert) end
        if self._destroyed then return end
        local sev = alert.severity or 0
        local icon = SEV_ICON[sev] or "·"
        self:_pushLog(string.format("%s [%s] %s",
            icon, alert.rule or "?", tostring(alert.message or ""):sub(1, 60)),
            SEV_COLOR[sev] or UI.Config.TEXT)
    end
end

--========== EXPORT ==========--
UI.Dashboard = Dashboard
UI.SEVERITY_COLORS = SEV_COLOR
UI.SEVERITY_LABELS = SEV_LABEL
UI.SEVERITY_ICONS = SEV_ICON

return UI