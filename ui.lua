--[[
    ============================================================
    EDR UI v2.0 — Mobile-First Full-Featured Dashboard
    ============================================================
    หลักการ:
    - 11 tabs ครอบคลุมทุก feature
    - Error-safe rendering (ทุก render ถูก pcall)
    - Auto-refresh พร้อม throttle ตามชนิดข้อมูล
    - Command console ใช้งานได้จริง
    - Responsive (portrait + landscape)
    - ทำงานร่วมกับ 8 ไฟล์

    Tabs:
      1. summary  — session, top rules, current risk
      2. alerts   — recent alerts (auto-refresh 1s)
      3. vulns    — vulnerability findings
      4. api      — Roblox API stats
      5. health   — module status + recovery
      6. timeline — forensic timeline
      7. ioc      — indicators of compromise
      8. risk     — risk curve
      9. rules    — rule list with toggle
     10. env      — environment diff
     11. log      — event log

    วิธีใช้:
        local UI = require("ui")
        local d = UI.new(edr, rules, report, main)
        d:show()
        -- Main.State.gui.update() เรียก d:update()
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
    PADDING              = 12,
    MAX_WIDTH            = 480,
    MAX_HEIGHT           = 720,

    -- Touch (iOS/Android guideline)
    MIN_TOUCH_HEIGHT     = 44,

    -- Update
    UPDATE_INTERVAL      = 1.0,
    RENDER_THROTTLE      = 1.5,
    MAX_LOG_LINES        = 200,

    -- Colors (GitHub Dark)
    COLOR_BG             = Color3.fromRGB(13, 17, 23),
    COLOR_PANEL          = Color3.fromRGB(22, 27, 34),
    COLOR_PANEL_ALT      = Color3.fromRGB(28, 33, 40),
    COLOR_BORDER         = Color3.fromRGB(48, 54, 61),
    COLOR_TEXT           = Color3.fromRGB(201, 209, 217),
    COLOR_TEXT_DIM       = Color3.fromRGB(139, 148, 158),
    COLOR_TEXT_BRIGHT    = Color3.fromRGB(240, 246, 252),
    COLOR_ACCENT         = Color3.fromRGB(88, 166, 255),
    COLOR_SUCCESS        = Color3.fromRGB(126, 231, 135),
    COLOR_WARN           = Color3.fromRGB(210, 153, 34),
    COLOR_ORANGE         = Color3.fromRGB(240, 140, 50),
    COLOR_DANGER         = Color3.fromRGB(248, 81, 73),
    COLOR_PURPLE         = Color3.fromRGB(188, 140, 255),
    COLOR_PINK           = Color3.fromRGB(255, 121, 198),
}

--========== SEVERITY PALETTE ==========--
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
        _lastData    = {
            risk = 0,
            events = 0,
            alerts = 0,
            vulnFindings = 0,
            recovered = 0,
        },
    }, Dashboard)
    return self
end

--========== BUILD ROOT ==========--
function Dashboard:_buildRoot()
    if self._destroyed then return end
    if self.gui then return end

    local parentGui = getParentGui()

    local gui = mk("ScreenGui", {
        Name = "EDR_UI_" .. tostring(math.random(100000, 999999)),
        ResetOnSpawn = false,
        ZIndexBehavior = Enum.ZIndexBehavior.Sibling,
        DisplayOrder = 100,
        IgnoreGuiInset = false,
        Parent = parentGui,
    })
    self.gui = gui

    --===== Floating Bubble =====--
    local bubble = mk("TextButton", {
        Name = "Bubble",
        Size = UDim2.new(0, 60, 0, 60),
        Position = UDim2.new(1, -75, 0, 100),
        BackgroundColor3 = UI.Config.COLOR_ACCENT,
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
        Color = UI.Config.COLOR_DANGER,
        Thickness = 2,
        Parent = bubble,
    })
    self.bubble = bubble
    self.bubbleStroke = bStroke

    --===== Main Sheet =====--
    local root = mk("Frame", {
        Name = "Root",
        BackgroundColor3 = UI.Config.COLOR_BG,
        BorderSizePixel = 0,
        Active = true,
        ClipsDescendants = true,
        Parent = gui,
    })
    mk("UICorner", { CornerRadius = UDim.new(0, UI.Config.CORNER_RADIUS), Parent = root })
    mk("UIStroke", {
        Color = UI.Config.COLOR_BORDER,
        Thickness = 1.5,
        Parent = root,
    })
    self.root = root

    --===== Header =====--
    local header = mk("Frame", {
        Name = "Header",
        Size = UDim2.new(1, -90, 0, 48),
        Position = UDim2.new(0, 12, 0, 4),
        BackgroundTransparency = 1,
        Parent = root,
    })

    local titleLbl = mk("TextLabel", {
        Size = UDim2.new(1, 0, 0, 22),
        BackgroundTransparency = 1,
        Text = "🛡  EDR Monitor",
        TextColor3 = UI.Config.COLOR_ACCENT,
        TextSize = 15,
        Font = Enum.Font.GothamBold,
        TextXAlignment = Enum.TextXAlignment.Left,
        Parent = header,
    })

    local statusLbl = mk("TextLabel", {
        Size = UDim2.new(1, 0, 0, 20),
        Position = UDim2.new(0, 0, 0, 24),
        BackgroundTransparency = 1,
        Text = "⚪ STOPPED",
        TextColor3 = UI.Config.COLOR_TEXT_DIM,
        TextSize = 11,
        Font = Enum.Font.Code,
        TextXAlignment = Enum.TextXAlignment.Left,
        Parent = header,
    })
    self.statusLbl = statusLbl

    --===== Close Button =====--
    local closeBtn = mk("TextButton", {
        Size = UDim2.new(0, 34, 0, 34),
        Position = UDim2.new(1, -78, 0, 8),
        BackgroundColor3 = UI.Config.COLOR_DANGER,
        BorderSizePixel = 0,
        Text = "✕",
        TextColor3 = Color3.fromRGB(255, 255, 255),
        TextSize = 14,
        Font = Enum.Font.GothamBold,
        ZIndex = 5,
        Parent = root,
    })
    mk("UICorner", { CornerRadius = UDim.new(0, 8), Parent = closeBtn })
    closeBtn.MouseButton1Click:Connect(function()
        safe(function() self:destroy() end)
    end)

    --===== Minimize Button =====--
    local minBtn = mk("TextButton", {
        Size = UDim2.new(0, 34, 0, 34),
        Position = UDim2.new(1, -40, 0, 8),
        BackgroundColor3 = UI.Config.COLOR_PANEL,
        BorderSizePixel = 0,
        Text = "—",
        TextColor3 = UI.Config.COLOR_TEXT,
        TextSize = 18,
        Font = Enum.Font.GothamBold,
        ZIndex = 5,
        Parent = root,
    })
    mk("UICorner", { CornerRadius = UDim.new(0, 8), Parent = minBtn })
    minBtn.MouseButton1Click:Connect(function()
        safe(function() self:minimize() end)
    end)

    --===== Risk Frame =====--
    local riskFrame = mk("Frame", {
        Name = "RiskFrame",
        Size = UDim2.new(1, -24, 0, 34),
        Position = UDim2.new(0, 12, 0, 56),
        BackgroundColor3 = UI.Config.COLOR_PANEL,
        BorderSizePixel = 0,
        Parent = root,
    })
    mk("UICorner", { CornerRadius = UDim.new(0, 8), Parent = riskFrame })

    local barBg = mk("Frame", {
        Size = UDim2.new(1, -16, 0, 8),
        Position = UDim2.new(0, 8, 0, 20),
        BackgroundColor3 = Color3.fromRGB(33, 38, 45),
        BorderSizePixel = 0,
        Parent = riskFrame,
    })
    mk("UICorner", { CornerRadius = UDim.new(0, 4), Parent = barBg })

    local barFill = mk("Frame", {
        Size = UDim2.new(0, 0, 1, 0),
        BackgroundColor3 = UI.Config.COLOR_SUCCESS,
        BorderSizePixel = 0,
        Parent = barBg,
    })
    mk("UICorner", { CornerRadius = UDim.new(0, 4), Parent = barFill })
    self.barFill = barFill

    local riskLbl = mk("TextLabel", {
        Size = UDim2.new(1, -16, 0, 16),
        Position = UDim2.new(0, 8, 0, 3),
        BackgroundTransparency = 1,
        Text = "Risk: 0.0%  |  Events: 0  |  Alerts: 0  |  Vulns: 0",
        TextColor3 = UI.Config.COLOR_TEXT_DIM,
        TextSize = 10,
        Font = Enum.Font.Code,
        TextXAlignment = Enum.TextXAlignment.Left,
        Parent = riskFrame,
    })
    self.riskLbl = riskLbl

    --===== Tab Bar =====--
    local tabBarFrame = mk("Frame", {
        Size = UDim2.new(1, -24, 0, 40),
        Position = UDim2.new(0, 12, 0, 96),
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
            Size = UDim2.new(0, 80, 0, 34),
            BackgroundColor3 = UI.Config.COLOR_PANEL,
            BorderSizePixel = 0,
            Text = tabInfo.label,
            TextColor3 = UI.Config.COLOR_TEXT_DIM,
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

    --===== Content Frame =====--
    local contentFrame = mk("Frame", {
        Size = UDim2.new(1, -24, 1, -196),
        Position = UDim2.new(0, 12, 0, 142),
        BackgroundColor3 = UI.Config.COLOR_PANEL,
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
        ScrollBarImageColor3 = UI.Config.COLOR_BORDER,
        CanvasSize = UDim2.new(0, 0, 0, 0),
        AutomaticCanvasSize = Enum.AutomaticSize.Y,
        ScrollingDirection = Enum.ScrollingDirection.Y,
        Parent = contentFrame,
    })
    local contentList = mk("UIListLayout", {
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
    self.contentList = contentList

    --===== Command Input =====--
    local inputBg = mk("Frame", {
        Size = UDim2.new(1, -24, 0, 40),
        Position = UDim2.new(0, 12, 1, -104),
        BackgroundColor3 = UI.Config.COLOR_PANEL,
        BorderSizePixel = 0,
        Parent = root,
    })
    mk("UICorner", { CornerRadius = UDim.new(0, 8), Parent = inputBg })
    mk("UIStroke", {
        Color = UI.Config.COLOR_BORDER,
        Thickness = 1,
        Parent = inputBg,
    })

    local prompt = mk("TextLabel", {
        Size = UDim2.new(0, 26, 1, 0),
        BackgroundTransparency = 1,
        Text = " ›",
        TextColor3 = UI.Config.COLOR_ACCENT,
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

    cmdBox.FocusLost:Connect(function(enterPressed)
        if not enterPressed then return end
        local text = cmdBox.Text
        cmdBox.Text = ""
        if text == "" then return end
        table.insert(self.cmdHistory, 1, text)
        if #self.cmdHistory > 30 then table.remove(self.cmdHistory) end
        self.historyIdx = 0

        self:_pushLog("› " .. text, UI.Config.COLOR_ACCENT)
        local result = safe(function()
            if self.main and self.main.executeCommand then
                return self.main.executeCommand(text)
            end
            return "Main not available"
        end)
        if result and result ~= "" then
            for line in tostring(result):gmatch("[^\n]+") do
                self:_pushLog(line, UI.Config.COLOR_SUCCESS)
            end
        end
        self:forceRefresh()
    end)

    --===== Action Bar =====--
    local actionBar = mk("Frame", {
        Size = UDim2.new(1, -24, 0, 44),
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

    self.startBtn = makeBtn("▶ START", UI.Config.COLOR_SUCCESS, function()
        self:onStartStop()
    end)
    makeBtn("📄 Export", UI.Config.COLOR_ACCENT, function()
        if self.main and self.main.saveReport then self.main.saveReport() end
    end)
    makeBtn("🔄 Refresh", UI.Config.COLOR_PANEL, function()
        self:forceRefresh()
    end)

    --===== Bubble click =====--
    bubble.MouseButton1Click:Connect(function()
        safe(function() self:maximize() end)
    end)

    -- Initial layout
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
    local isPort = isPortrait()
    if isPort ~= self.lastPortrait then
        self:applyLayout()
    end
end

--========== SHOW/MIN/MAX ==========--
function Dashboard:show()
    if self._destroyed then return end
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
            btn.BackgroundColor3 = UI.Config.COLOR_ACCENT
            btn.TextColor3 = Color3.fromRGB(255, 255, 255)
        else
            btn.BackgroundColor3 = UI.Config.COLOR_PANEL
            btn.TextColor3 = UI.Config.COLOR_TEXT_DIM
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

function Dashboard:_addHeader(text)
    return self:_addLine(text, UI.Config.COLOR_ACCENT, {
        size = 12, bold = true, height = 22,
    })
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
        BackgroundColor3 = UI.Config.COLOR_BORDER,
        BorderSizePixel = 0,
        LayoutOrder = #self.content,
        Parent = self.contentScroll,
    })
    table.insert(self.content, s)
end

--========== RENDER MAIN ==========--
function Dashboard:renderContent()
    if self._destroyed then return end
    if not self.contentScroll then return end

    self:_clearContent()

    local tab = self.currentTab
    local renderFn = self["_render" .. tab:gsub("^%l", string.upper)]
    if type(renderFn) == "function" then
        local ok, err = pcall(renderFn, self)
        if not ok then
            self:_addLine("Render error: " .. tostring(err):sub(1, 100), UI.Config.COLOR_DANGER)
        end
    else
        self:_addLine("Tab not implemented: " .. tostring(tab), UI.Config.COLOR_TEXT_DIM)
    end
end

--========== RENDER: SUMMARY ==========--
function Dashboard:_renderSummary()
    if not self.edr then
        self:_addLine("EDR ไม่พร้อม", UI.Config.COLOR_TEXT_DIM)
        return
    end

    local s = self.edr.session
    if not s then
        self:_addLine("Session ไม่พร้อม", UI.Config.COLOR_TEXT_DIM)
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
    end

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
        self:_addLine("(ยังไม่มี rule ถูก trigger)", UI.Config.COLOR_TEXT_DIM)
    else
        for i = 1, math.min(8, #sorted) do
            local item = sorted[i]
            local color = UI.Config.COLOR_TEXT
            if item.count >= 3 then color = UI.Config.COLOR_DANGER
            elseif item.count >= 1 then color = UI.Config.COLOR_WARN end
            self:_addLine(string.format("%d. %s  ×%d", i, item.rule, item.count), color)
        end
    end

    self:_addSpacer(4)
    self:_addHeader("CURRENT RISK")
    local risk = self:_computeRisk()
    local riskColor = UI.Config.COLOR_SUCCESS
    if risk >= 0.85 then riskColor = UI.Config.COLOR_DANGER
    elseif risk >= 0.65 then riskColor = UI.Config.COLOR_ORANGE
    elseif risk >= 0.35 then riskColor = UI.Config.COLOR_WARN
    end
    self:_addLine(string.format("%.1f%%", risk * 100), riskColor, {
        size = 26, bold = true, height = 34,
    })

    -- Summary ของ Vuln
    local M = self.main and self.main.State and self.main.State.modules
    if M and M.Vuln and M.Vuln.getSummary then
        local vs = safe(function() return M.Vuln.getSummary() end)
        if vs then
            self:_addSpacer(4)
            self:_addHeader("VULNERABILITY SUMMARY")
            self:_addLine("Total:    " .. tostring(vs.total or 0))
            self:_addLine("Critical: " .. tostring((vs.by_sev and vs.by_sev[4]) or 0), UI.Config.COLOR_DANGER)
            self:_addLine("High:     " .. tostring((vs.by_sev and vs.by_sev[3]) or 0), UI.Config.COLOR_ORANGE)
            self:_addLine("Medium:   " .. tostring((vs.by_sev and vs.by_sev[2]) or 0), UI.Config.COLOR_WARN)
        end
    end
end

--========== RENDER: ALERTS ==========--
function Dashboard:_renderAlerts()
    local alerts = (self.edr and self.edr.alerts) or {}
    self:_addHeader("ALERTS (" .. #alerts .. ")")
    self:_addSpacer(2)

    if #alerts == 0 then
        self:_addLine("(ยังไม่มี alert)", UI.Config.COLOR_TEXT_DIM)
        return
    end

    local start = math.max(1, #alerts - 40)
    for i = #alerts, start, -1 do
        local a = alerts[i]
        if a then
            local sev = a.severity or 0
            local color = SEV_COLOR[sev] or UI.Config.COLOR_TEXT
            local icon = SEV_ICON[sev] or "·"
            local label = SEV_LABEL[sev] or "?"

            self:_addLine(string.format("%s [%s] %s", icon, label, a.rule or "?"),
                color, { size = 11, bold = true })

            if a.message then
                self:_addLine("  " .. tostring(a.message):sub(1, 100),
                    UI.Config.COLOR_TEXT_DIM, { size = 10 })
            end

            if a.score then
                self:_addLine(string.format("  score: %.2f | mitre: %s",
                    a.score, a.mitre or "-"),
                    UI.Config.COLOR_TEXT_DIM, { size = 10 })
            end

            self:_addSpacer(3)
        end
    end
end

--========== RENDER: VULNS ==========--
function Dashboard:_renderVulns()
    local M = self.main and self.main.State and self.main.State.modules
    if not M or not M.Vuln then
        self:_addLine("Vuln Scanner ไม่พร้อม", UI.Config.COLOR_TEXT_DIM)
        return
    end

    local sum = safe(function() return M.Vuln.getSummary() end)
    if not sum then
        self:_addLine("ไม่สามารถดึงข้อมูลได้", UI.Config.COLOR_TEXT_DIM)
        return
    end

    self:_addHeader("VULNERABILITY FINDINGS")
    self:_addLine(string.format("Total: %d  |  Critical: %d  |  High: %d  |  Med: %d",
        sum.total or 0,
        (sum.by_sev and sum.by_sev[4]) or 0,
        (sum.by_sev and sum.by_sev[3]) or 0,
        (sum.by_sev and sum.by_sev[2]) or 0
    ), UI.Config.COLOR_TEXT_BRIGHT, { bold = true })

    self:_addSpacer(4)

    -- Category breakdown
    if sum.by_cat and next(sum.by_cat) then
        self:_addHeader("BY CATEGORY")
        for cat, count in pairs(sum.by_cat) do
            self:_addLine(string.format("  • %s  ×%d", tostring(cat), count),
                UI.Config.COLOR_TEXT)
        end
        self:_addSpacer(4)
    end

    -- Top findings
    local top = safe(function() return M.Vuln.getTopFindings(30) end) or {}
    if #top == 0 then
        self:_addLine("(ยังไม่พบช่องโหว่)", UI.Config.COLOR_SUCCESS)
        return
    end

    self:_addHeader("TOP FINDINGS (" .. #top .. ")")
    for i, f in ipairs(top) do
        local sev = f.severity or 0
        local color = SEV_COLOR[sev] or UI.Config.COLOR_TEXT
        local icon = SEV_ICON[sev] or "·"

        self:_addLine(string.format("%s [%s] %s",
            icon, SEV_LABEL[sev] or "?", tostring(f.title or "?")),
            color, { size = 11, bold = true })

        if f.detail then
            self:_addLine("  " .. tostring(f.detail):sub(1, 120),
                UI.Config.COLOR_TEXT_DIM, { size = 10 })
        end

        if f.category then
            local meta = "  cat: " .. tostring(f.category)
            if f.mitre then meta = meta .. " | mitre: " .. tostring(f.mitre) end
            self:_addLine(meta, UI.Config.COLOR_TEXT_DIM, { size = 9 })
        end

        self:_addSpacer(3)
    end
end

--========== RENDER: API ==========--
function Dashboard:_renderApi()
    local M = self.main and self.main.State and self.main.State.modules
    if not M or not M.RobloxAPI then
        self:_addLine("Roblox API Monitor ไม่พร้อม", UI.Config.COLOR_TEXT_DIM)
        return
    end

    local s = safe(function() return M.RobloxAPI.getStats() end)
    if not s then
        self:_addLine("ไม่สามารถดึงสถิติได้", UI.Config.COLOR_TEXT_DIM)
        return
    end

    self:_addHeader("INSTANCE STATS")
    self:_addLine(string.format("Created:   %s", fmtNum(s.instances and s.instances.created or 0)))
    self:_addLine(string.format("Destroyed: %s", fmtNum(s.instances and s.instances.destroyed or 0)))
    self:_addLine(string.format("Tracked:   %s", fmtNum(s.tracked or 0)))

    self:_addSpacer(4)
    self:_addHeader("SENSITIVE SERVICE ACCESS")

    local svcList = safe(function() return M.RobloxAPI.getSensitiveServiceList() end) or {}
    if #svcList == 0 then
        self:_addLine("(ไม่มีการเข้าถึง service ที่ละเอียดอ่อน)", UI.Config.COLOR_TEXT_DIM)
    else
        for i, svc in ipairs(svcList) do
            if i > 20 then break end
            local color = UI.Config.COLOR_TEXT
            if svc.count >= 10 then color = UI.Config.COLOR_DANGER
            elseif svc.count >= 3 then color = UI.Config.COLOR_WARN end
            self:_addLine(string.format("  %-28s ×%d", tostring(svc.service), svc.count), color)
        end
    end

    self:_addSpacer(4)
    self:_addHeader("INFO")
    self:_addLine("LocalPlayer: " .. tostring(
        safe(function()
            return game:GetService("Players").LocalPlayer.Name
        end) or "?"
    ))
    self:_addLine("Place ID:    " .. tostring(
        safe(function() return game.PlaceId end) or "?"
    ))
    self:_addLine("Job ID:      " .. tostring(
        safe(function() return game.JobId end) or "?"
    ):sub(1, 20))
end

--========== RENDER: HEALTH ==========--
function Dashboard:_renderHealth()
    local M = self.main and self.main.State and self.main.State.modules
    if not M then
        self:_addLine("Main ไม่พร้อม", UI.Config.COLOR_TEXT_DIM)
        return
    end

    self:_addHeader("MODULE HEALTH")

    local healthReport = nil
    if self.main and self.main.HealthMonitor then
        healthReport = safe(function()
            return self.main.HealthMonitor.getHealthReport()
        end)
    end

    if not healthReport then
        self:_addLine("(ไม่สามารถดึงข้อมูล health)", UI.Config.COLOR_TEXT_DIM)
    else
        for _, h in ipairs(healthReport) do
            local icon = "?"
            local color = UI.Config.COLOR_TEXT_DIM
            if h.status == "healthy" then
                icon = "✓"; color = UI.Config.COLOR_SUCCESS
            elseif h.status == "error" then
                icon = "✗"; color = UI.Config.COLOR_DANGER
            end
            self:_addLine(string.format("%s %-12s", icon, tostring(h.name or "?")),
                color, { bold = true })
            local detail = string.format("   status=%s  err=%d  retry=%d",
                tostring(h.status), h.err_count or 0, h.retry_count or 0)
            self:_addLine(detail, UI.Config.COLOR_TEXT_DIM, { size = 10 })
        end
    end

    self:_addSpacer(4)
    self:_addHeader("RECOVERY")

    local st = self.main and self.main.State
    if st then
        self:_addLine("Total recovered: " .. fmtNum(st.recovered or 0), UI.Config.COLOR_SUCCESS)
        self:_addLine("Recovery enabled: " .. tostring(
            self.main.Config and self.main.Config.RECOVERY_ENABLED or false
        ))
        self:_addLine("Interval: " .. tostring(
            self.main.Config and self.main.Config.RECOVERY_INTERVAL or "?"
        ) .. "s")
    end

    self:_addSpacer(4)
    self:_addHeader("RECENT ERRORS")

    local errors = st and st.error_log or {}
    if #errors == 0 then
        self:_addLine("(ไม่มี error)", UI.Config.COLOR_SUCCESS)
    else
        local start = math.max(1, #errors - 10)
        for i = start, #errors do
            local e = errors[i]
            if e then
                self:_addLine(string.format("[%.1fs] %s: %s",
                    e.t or 0, tostring(e.module or "?"),
                    tostring(e.message or ""):sub(1, 60)),
                    UI.Config.COLOR_WARN, { size = 10 })
            end
        end
    end
end

--========== RENDER: TIMELINE ==========--
function Dashboard:_renderTimeline()
    self:_addHeader("FORENSIC TIMELINE")

    if not self.report or not self.report.timeline then
        self:_addLine("(ไม่มีข้อมูล timeline)", UI.Config.COLOR_TEXT_DIM)
        return
    end

    local entries = self.report.timeline.entries or {}
    if #entries == 0 then
        self:_addLine("(ยังไม่มี events)", UI.Config.COLOR_TEXT_DIM)
        return
    end

    local t0 = entries[1].t or 0
    local maxShow = 60
    local start = math.max(1, #entries - maxShow)

    for i = start, #entries do
        local e = entries[i]
        if e then
            local icon = SEV_ICON[e.severity or 0] or "·"
            local color = SEV_COLOR[e.severity or 0] or UI.Config.COLOR_TEXT
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

            self:_addLine(string.format("%s %s  %-16s %s",
                icon, rel, tostring(e.type or "?"):sub(1, 16), detail),
                color, { size = 10 })
        end
    end
end

--========== RENDER: IOC ==========--
function Dashboard:_renderIOC()
    self:_addHeader("INDICATORS OF COMPROMISE")

    if not self.report or not self.report.ioc then
        self:_addLine("(ไม่มีข้อมูล IOC)", UI.Config.COLOR_TEXT_DIM)
        return
    end

    local iocs = safe(function() return self.report.ioc:getAll() end) or {}
    if #iocs == 0 then
        self:_addLine("(ยังไม่พบ IOC)", UI.Config.COLOR_TEXT_DIM)
        return
    end

    local typeCounts = {}
    for _, ioc in ipairs(iocs) do
        typeCounts[ioc.type] = (typeCounts[ioc.type] or 0) + 1
    end

    self:_addLine("Summary by type:", UI.Config.COLOR_TEXT_BRIGHT, { bold = true })
    for t, c in pairs(typeCounts) do
        self:_addLine(string.format("  %-16s %d", tostring(t), c), UI.Config.COLOR_TEXT_DIM, { size = 10 })
    end

    self:_addSpacer(4)

    for i = 1, math.min(80, #iocs) do
        local ioc = iocs[i]
        local color = UI.Config.COLOR_TEXT
        if ioc.type == "url" or ioc.type == "ipv4" then
            color = UI.Config.COLOR_ORANGE
        elseif ioc.type == "discord_token" or ioc.type == "telegram_bot" then
            color = UI.Config.COLOR_DANGER
        elseif ioc.type == "domain" then
            color = UI.Config.COLOR_WARN
        elseif ioc.type == "md5" or ioc.type == "sha1" or ioc.type == "sha256" then
            color = UI.Config.COLOR_PURPLE
        end

        self:_addLine(string.format("[%s] ×%d", tostring(ioc.type), ioc.count or 0),
            color, { size = 10, bold = true })
        self:_addLine("  " .. tostring(ioc.value or ""):sub(1, 90),
            UI.Config.COLOR_TEXT_DIM, { size = 10 })
    end
end

--========== RENDER: RISK ==========--
function Dashboard:_renderRisk()
    self:_addHeader("RISK EVOLUTION")

    if not self.report or not self.report.risk_curve then
        self:_addLine("(ไม่มีข้อมูล risk)", UI.Config.COLOR_TEXT_DIM)
        return
    end

    local graph = safe(function()
        return self.report.risk_curve:renderASCII(46, 8)
    end)
    if graph then
        for line in graph:gmatch("[^\n]+") do
            self:_addLine(line, UI.Config.COLOR_SUCCESS, { size = 10 })
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

    self:_addSpacer(4)
    self:_addHeader("THRESHOLDS")

    if self.main and self.main.Config then
        self:_addLine("Warn:     " .. string.format("%.0f%%", (self.main.Config.WARN_THRESHOLD or 0) * 100))
        self:_addLine("Kill:     " .. string.format("%.0f%%", (self.main.Config.KILL_THRESHOLD or 0) * 100))
        self:_addLine("Enabled:  " .. tostring(self.main.Config.KILL_SWITCH_ENABLED))
    end
end

--========== RENDER: RULES ==========--
function Dashboard:_renderRules()
    if not self.rules or not self.rules.ruleOrder then
        self:_addLine("Rules engine ไม่พร้อม", UI.Config.COLOR_TEXT_DIM)
        return
    end

    self:_addHeader("RULES (" .. #self.rules.ruleOrder .. ")")
    self:_addLine("แตะปุ่มเพื่อเปิด/ปิดแต่ละ rule", UI.Config.COLOR_TEXT_DIM, { size = 10 })
    self:_addSpacer(4)

    for _, r in ipairs(self.rules.ruleOrder) do
        local color = SEV_COLOR[r.severity or 0] or UI.Config.COLOR_TEXT
        local icon = r.enabled and "✓" or "✗"

        -- Row container
        local row = mk("Frame", {
            Size = UDim2.new(1, 0, 0, 38),
            BackgroundColor3 = UI.Config.COLOR_PANEL_ALT,
            BorderSizePixel = 0,
            LayoutOrder = #self.content,
            Parent = self.contentScroll,
        })
        mk("UICorner", { CornerRadius = UDim.new(0, 6), Parent = row })
        table.insert(self.content, row)

        local infoLbl = mk("TextLabel", {
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
            BackgroundColor3 = r.enabled and UI.Config.COLOR_SUCCESS or UI.Config.COLOR_BORDER,
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
        self:_addLine("(ยังไม่มี env snapshot)", UI.Config.COLOR_TEXT_DIM)
        return
    end

    local d = self.report.envdiff
    self:_addLine(string.format("Added globals:    %d", d.total_added or 0))
    self:_addLine(string.format("Removed globals:  %d", d.total_removed or 0))
    self:_addLine(string.format("Changed types:    %d", d.total_changed or 0))
    self:_addLine(string.format("Redefined funcs:  %d", d.total_redefined or 0), UI.Config.COLOR_WARN)

    if d.redefined and #d.redefined > 0 then
        self:_addSpacer(4)
        self:_addHeader("REDEFINED FUNCTIONS")
        for i = 1, math.min(20, #d.redefined) do
            local r = d.redefined[i]
            self:_addLine("● " .. tostring(r.key), UI.Config.COLOR_DANGER, { size = 10, bold = true })
            self:_addLine(string.format("  %s → %s",
                tostring(r.before or "?"):sub(1, 30),
                tostring(r.after or "?"):sub(1, 30)),
                UI.Config.COLOR_TEXT_DIM, { size = 9 })
        end
    end

    if d.added and #d.added > 0 then
        self:_addSpacer(4)
        self:_addHeader("ADDED GLOBALS")
        for i = 1, math.min(30, #d.added) do
            local a = d.added[i]
            self:_addLine(string.format("+ %s (%s)", tostring(a.key), tostring(a.type)),
                UI.Config.COLOR_WARN, { size = 10 })
        end
    end
end

--========== RENDER: LOG ==========--
function Dashboard:_renderLog()
    self:_addHeader("EVENT LOG")

    if #self.logLines == 0 then
        self:_addLine("(รอ events...)", UI.Config.COLOR_TEXT_DIM)
        return
    end

    local start = math.max(1, #self.logLines - 100)
    for i = start, #self.logLines do
        local entry = self.logLines[i]
        if entry then
            self:_addLine(tostring(entry.text), entry.color or UI.Config.COLOR_TEXT_DIM, { size = 10 })
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
    if self._updateThread then return end
    if self._destroyed then return end

    self._updateThread = task.spawn(function()
        while not self._destroyed and self.gui and self.gui.Parent do
            task.wait(UI.Config.UPDATE_INTERVAL)
            pcall(function() self:update() end)
        end
    end)
end

function Dashboard:update()
    if self._destroyed then return end
    if not self.gui or not self.gui.Parent then return end

    safe(function() self:handleViewportChange() end)

    -- Status
    local statusText, statusColor = "⚪ STOPPED", UI.Config.COLOR_TEXT_DIM
    local running = false
    if self.main and self.main.State then
        local st = self.main.State
        if st.killed then
            statusText = "🔴 KILLED"
            statusColor = UI.Config.COLOR_DANGER
        elseif st.paused then
            statusText = "🟡 PAUSED"
            statusColor = UI.Config.COLOR_WARN
        elseif st.running then
            statusText = "🟢 RUNNING"
            statusColor = UI.Config.COLOR_SUCCESS
            running = true
        end

        -- Start/Stop button
        if self.startBtn then
            if st.running then
                self.startBtn.Text = "■ STOP"
                self.startBtn.BackgroundColor3 = UI.Config.COLOR_DANGER
            else
                self.startBtn.Text = "▶ START"
                self.startBtn.BackgroundColor3 = UI.Config.COLOR_SUCCESS
            end
        end
    end

    if self.statusLbl then
        self.statusLbl.Text = statusText
        self.statusLbl.TextColor3 = statusColor
    end

    -- Risk bar
    local risk = self:_computeRisk()
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

    -- Metrics label
    local events = (self.edr and self.edr.session and self.edr.session.events_processed) or 0
    local alerts = #((self.edr and self.edr.alerts) or {})
    local vulnCount = 0
    local M = self.main and self.main.State and self.main.State.modules
    if M and M.Vuln and M.Vuln.getSummary then
        local vs = safe(function() return M.Vuln.getSummary() end)
        if vs then vulnCount = vs.total or 0 end
    end

    if self.riskLbl then
        self.riskLbl.Text = string.format(
            "Risk: %.1f%%  |  Events: %s  |  Alerts: %d  |  Vulns: %d",
            risk * 100, fmtNum(events), alerts, vulnCount)
    end

    -- Bubble glow
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

    -- Live tabs: refresh periodically
    local now = os.clock()
    if now - self.lastRender >= UI.Config.RENDER_THROTTLE then
        local dynamicTabs = {
            summary  = true,
            alerts   = true,
            vulns    = true,
            api      = true,
            health   = true,
            timeline = true,
            log      = true,
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
        self:_pushLog("Main ไม่พร้อม", UI.Config.COLOR_WARN)
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
        color = color or UI.Config.COLOR_TEXT_DIM,
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
            SEV_COLOR[sev] or UI.Config.COLOR_TEXT)
    end
end

--========== EXPORT ==========--
UI.Dashboard = Dashboard
UI.SEVERITY_COLORS = SEV_COLOR
UI.SEVERITY_LABELS = SEV_LABEL
UI.SEVERITY_ICONS = SEV_ICON

return UI