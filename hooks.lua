--[[
    ============================================================
    EDR Hooks v1.0 — Behavior Interception Layer
    ============================================================
    หลักการ:
    - ดักจับพฤติกรรมทุกอย่างที่สคริปต์เป้าหมายทำ
    - ส่ง event เข้า edr.bus ผ่าน edr:emit()
    - ทุก hook เก็บ call stack + context
    - Rate limit + dedup + re-entry protection
    - Fallback ทุก primitive (getgenv ไม่มี → ใช้ _G)

    Hooks ที่ติดตั้ง:
    1.  Opcode hook       (debug.sethook)
    2.  Global proxy      (metatable _G)
    3.  Function wrapper  (loadstring, dofile, load)
    4.  Coroutine tracker
    5.  Network hook      (HttpGet, request, HttpService)
    6.  File hook         (readfile, writefile, listfiles)
    7.  String decrypt    (string.char, bit32.bxor, string.gsub)
    8.  Debug library     (debug.getinfo, debug.sethook)
    9.  Metatable hook    (setmetatable, getrawmetatable)
    10. Environment hook  (getgenv, getfenv, setfenv)
    ============================================================
]]

local Hooks = {}

--========== INTERNAL STATE ==========--
local State = {
    edr            = nil,
    installed      = false,
    originals      = {},      -- เก็บฟังก์ชันต้นฉบับ
    inHook         = false,   -- re-entry guard
    rateLimiters   = {},      -- [key] = {last, count}
    lastStrings    = {},      -- LRU ของ string ที่ decrypt แล้ว
    callStack      = {},      -- call stack ปัจจุบัน
    coroutineMap   = {},      -- [co] = metadata
    stackDepth     = 0,
}

--========== CONFIG ==========--
Hooks.Config = {
    -- Rate limit: ปล่อย event ต่อ key ต่อวินาที
    RATE_LIMIT_PER_SEC = 50,
    -- เก็บ string ที่ decrypt ไว้กี่ตัว
    STRING_LRU_SIZE    = 256,
    -- hook opcode ทุกกี่ instructions
    OPCODE_HOOK_COUNT  = 1000,
    -- ความลึกของ stack ที่เก็บ
    MAX_STACK_DEPTH    = 8,
    -- เปิด hook string decrypt
    HOOK_STRING_DECRYPT = true,
    -- เปิด hook global
    HOOK_GLOBAL        = true,
    -- เปิด hook network
    HOOK_NETWORK       = true,
    -- เปิด hook file
    HOOK_FILE          = true,
}

--========== HELPERS ==========--

local function now()
    return os.clock()
end

-- Rate limiter (sliding window)
local function allowRate(key)
    local lim = State.rateLimiters[key]
    local t = now()
    if not lim then
        State.rateLimiters[key] = { window_start = t, count = 1 }
        return true
    end
    if t - lim.window_start >= 1 then
        lim.window_start = t
        lim.count = 1
        return true
    end
    if lim.count < Hooks.Config.RATE_LIMIT_PER_SEC then
        lim.count = lim.count + 1
        return true
    end
    return false
end

-- เก็บ string ที่ decrypt แล้ว (dedup)
local function rememberString(s)
    if not s or #s == 0 or #s > 5000 then return false end
    for _, v in ipairs(State.lastStrings) do
        if v == s then return false end
    end
    table.insert(State.lastStrings, 1, s)
    if #State.lastStrings > Hooks.Config.STRING_LRU_SIZE then
        table.remove(State.lastStrings)
    end
    return true
end

-- ดึง call stack (ปลอดภัย)
local function captureStack(depth)
    depth = depth or Hooks.Config.MAX_STACK_DEPTH
    local stack = {}
    local level = 2
    while level <= depth + 2 do
        local info = debug.getinfo(level, "nSl")
        if not info then break end
        table.insert(stack, {
            name   = info.name or "?",
            source = info.short_src or info.source or "?",
            line   = info.currentline or 0,
            what   = info.what or "?",
        })
        level = level + 1
    end
    return stack
end

-- Safe emit wrapper (กัน re-entry)
local function emit(eventType, data, severity)
    if State.inHook then return end  -- กัน hook เรียกตัวเอง
    State.inHook = true
    local ok, err = pcall(function()
        State.edr:emit(eventType, data, severity)
    end)
    State.inHook = false
    if not ok then
        -- อย่า print ออกไป (target script อาจอ่าน output)
    end
end

-- ตรวจ URL น่าสงสัย
local SUSPICIOUS_PATTERNS = {
    webhook    = "discord.com/api/webhooks",
    telegram   = "api.telegram.org",
    pastebin   = "pastebin.com/raw",
    githubraw  = "raw.githubusercontent.com",
    ip_pattern = "%d+%.%d+%.%d+%.%d+",
    ipv6       = "[:%x:]+:[%x:]+:[%x:]+",
    base64url  = "aHR0cHM6Ly",     -- "https://" base64
    oneliner   = "loadstring",
    suspicious = "%.tk/", "%.ml/", "%.ga/", "%.cf/", "%.gq/",
}

local function isSuspiciousURL(url)
    if type(url) ~= "string" then return false, nil end
    url = url:lower()
    for name, pat in pairs(SUSPICIOUS_PATTERNS) do
        if type(pat) == "table" then
            for _, p in ipairs(pat) do
                if url:find(p, 1, true) then return true, name end
            end
        elseif url:find(pat) then
            return true, name
        end
    end
    return false, nil
end

-- ตรวจว่า string ดูเป็น encrypted/random หรือไม่ (high entropy)
local function stringEntropy(s)
    if not s or #s == 0 then return 0 end
    local freq = {}
    for i = 1, #s do
        local c = s:sub(i, i)
        freq[c] = (freq[c] or 0) + 1
    end
    local H = 0
    for _, count in pairs(freq) do
        local p = count / #s
        H = H - p * (math.log(p) / math.log(2))
    end
    return H
end

-- ตรวจ base64
local function looksBase64(s)
    if type(s) ~= "string" or #s < 20 then return false end
    if #s % 4 ~= 0 then return false end
    if not s:match("^[A-Za-z0-9+/=]+$") then return false end
    return true
end

-- ตรวจ hex
local function looksHex(s)
    if type(s) ~= "string" or #s < 16 then return false end
    return s:match("^[0-9a-fA-F]+$") ~= nil
end

--========== 1. OPCODE HOOK ==========--
-- ใช้ debug.sethook ดัก call/return/line ทุก instruction
local function installOpcodeHook(edr)
    if not debug or not debug.sethook then return nil end

    local originalSethook = debug.sethook
    State.originals.sethook = originalSethook

    local callCount = 0
    local lastEmit = 0

    local function hook(event, line)
        if State.inHook then return end

        callCount = callCount + 1

        -- นับรวมแล้วปล่อย event เป็น interval
        if callCount % Hooks.Config.OPCODE_HOOK_COUNT == 0 then
            local t = now()
            if t - lastEmit >= 0.5 then
                lastEmit = t
                emit("OPCODE_CALL", {
                    count     = callCount,
                    line      = line,
                    event     = event,
                    stack     = captureStack(3),
                }, 0)
            end
        end

        -- ดัก call event
        if event == "call" then
            local info = debug.getinfo(2, "nSl")
            if info then
                emit("OPCODE_CALL", {
                    name   = info.name,
                    source = info.short_src,
                    line   = info.currentline,
                }, 0)
            end
        end
    end

    pcall(function()
        originalSethook(hook, "crl", 0)
    end)

    return function()
        pcall(function() originalSethook() end)
    end
end

--========== 2. GLOBAL PROXY ==========--
-- ดักการอ่าน/เขียน _G ด้วย metatable
local function installGlobalProxy(edr)
    if not setmetatable or not getmetatable then return nil end

    local realG = getgenv and getgenv() or _G
    local originalMeta = getmetatable(realG)

    local proxy = setmetatable({}, {
        __index = function(t, k)
            local v = realG[k]
            if allowRate("global_read:" .. tostring(k)) then
                emit("GLOBAL_READ", { key = tostring(k) }, 0)
            end
            return v
        end,
        __newindex = function(t, k, v)
            local old = realG[k]
            realG[k] = v
            if allowRate("global_write:" .. tostring(k)) then
                emit("GLOBAL_WRITE", {
                    key       = tostring(k),
                    old_type  = type(old),
                    new_type  = type(v),
                    old_value = type(old) == "string" and old:sub(1, 100) or nil,
                    new_value = type(v) == "string" and v:sub(1, 100) or nil,
                    stack     = captureStack(4),
                }, 1)
            end
        end,
        __metatable = "locked",
    })

    -- แทน getgenv ให้ return proxy
    if getgenv then
        State.originals.getgenv = getgenv
        getgenv = function() return proxy end
    end

    return function()
        if getgenv and State.originals.getgenv then
            getgenv = State.originals.getgenv
        end
    end
end

--========== 3. FUNCTION WRAPPER ==========--
-- ห่อฟังก์ชันอันตราย
local DANGEROUS_FUNCS = {
    { env = "loadstring",  name = "loadstring",   sev = 3 },
    { env = "load",        name = "load",         sev = 3 },
    { env = "dofile",      name = "dofile",       sev = 3 },
    { env = "loadfile",    name = "loadfile",     sev = 3 },
    { env = "require",     name = "require",      sev = 2 },
}

local function wrapFunction(env, name, sev)
    local orig = env[name]
    if type(orig) ~= "function" then return nil end
    State.originals[name] = orig

    local wrapped = function(...)
        local args = { ... }
        emit("FUNCTION_CALL", {
            name = name,
            argc = select("#", ...),
            arg1 = type(args[1]) == "string" and args[1]:sub(1, 200) or nil,
            stack = captureStack(5),
        }, sev)
        return orig(...)
    end

    -- ใช้ newcclosure ถ้ามี (ซ่อน identity)
    if newcclosure then
        pcall(function() wrapped = newcclosure(wrapped) end)
    end

    env[name] = wrapped
    return wrapped
end

local function installFunctionWrappers(edr)
    local env = getgenv and getgenv() or _G
    local restored = {}

    for _, entry in ipairs(DANGEROUS_FUNCS) do
        local wrapped = wrapFunction(env, entry.name, entry.sev)
        if wrapped then
            table.insert(restored, { env = env, name = entry.name, orig = State.originals[entry.name] })
        end
    end

    return function()
        for _, r in ipairs(restored) do
            pcall(function() r.env[r.name] = r.orig end)
        end
    end
end

--========== 4. COROUTINE TRACKER ==========--
local function installCoroutineTracker(edr)
    if not coroutine then return nil end

    local origCreate = coroutine.create
    local origResume = coroutine.resume
    local origWrap   = coroutine.wrap
    local origYield  = coroutine.yield
    local origStatus = coroutine.status

    State.originals.coroutine_create = origCreate
    State.originals.coroutine_resume = origResume
    State.originals.coroutine_wrap   = origWrap

    local coCounter = 0
    local resumeCounter = 0

    local function trackCreate(fn)
        coCounter = coCounter + 1
        local co = origCreate(fn)
        State.coroutineMap[co] = {
            id         = coCounter,
            created_at = now(),
            stack      = captureStack(4),
        }
        if allowRate("co_create") then
            emit("COROUTINE_CREATE", {
                id     = coCounter,
                total  = coCounter,
                stack  = State.coroutineMap[co].stack,
            }, 0)
        end
        return co
    end

    local function trackResume(co, ...)
        resumeCounter = resumeCounter + 1
        local meta = State.coroutineMap[co]
        if meta then
            meta.resumes = (meta.resumes or 0) + 1
        end
        if allowRate("co_resume") then
            emit("COROUTINE_RESUME", {
                id     = meta and meta.id or -1,
                total  = resumeCounter,
            }, 0)
        end
        return origResume(co, ...)
    end

    local function trackWrap(fn)
        coCounter = coCounter + 1
        local co = origWrap(fn)
        State.coroutineMap[co] = {
            id         = coCounter,
            created_at = now(),
            wrapped    = true,
            stack      = captureStack(4),
        }
        if allowRate("co_wrap") then
            emit("COROUTINE_CREATE", {
                id     = coCounter,
                total  = coCounter,
                wrapped = true,
                stack  = State.coroutineMap[co].stack,
            }, 0)
        end
        return co
    end

    coroutine.create = function(fn) return trackCreate(fn) end
    coroutine.resume = function(co, ...) return trackResume(co, ...) end
    coroutine.wrap   = function(fn) return trackWrap(fn) end

    if newcclosure then
        pcall(function()
            coroutine.create = newcclosure(coroutine.create)
            coroutine.resume = newcclosure(coroutine.resume)
            coroutine.wrap   = newcclosure(coroutine.wrap)
        end)
    end

    return function()
        coroutine.create = origCreate
        coroutine.resume = origResume
        coroutine.wrap   = origWrap
    end
end

--========== 5. NETWORK HOOK ==========--
local function installNetworkHooks(edr)
    if not Hooks.Config.HOOK_NETWORK then return nil end
    local restored = {}
    local env = getgenv and getgenv() or _G

    -- hook game:HttpGet / HttpPost
    local function hookHttp(method, eventType)
        local ok, service = pcall(function() return game:GetService("HttpService") end)
        if not ok then return end

        local mt = getrawmetatable and getrawmetatable(game)
        if mt and setreadonly then
            -- ไม่แตะ metatable ของ game โดยตรง (อันตราย) — ใช้วิธี wrap service แทน
        end

        local orig = service[method]
        if type(orig) ~= "function" then return end

        State.originals["HttpService_" .. method] = orig

        local wrapped = function(self, url, ...)
            local suspicious, tag = isSuspiciousURL(url)
            emit(eventType, {
                url        = tostring(url):sub(1, 500),
                suspicious = suspicious,
                tag        = tag,
                stack      = captureStack(5),
            }, suspicious and 3 or 1)
            return orig(self, url, ...)
        end

        if newcclosure then
            pcall(function() wrapped = newcclosure(wrapped) end)
        end

        service[method] = wrapped
        table.insert(restored, { service = service, method = method, orig = orig })
    end

    hookHttp("Get",  "HTTP_GET")
    hookHttp("Post", "HTTP_POST")

    -- hook global HttpGet (Synapse/Delta)
    if type(env.HttpGet) == "function" then
        local orig = env.HttpGet
        State.originals.HttpGet = orig

        local wrapped = function(url, ...)
            local suspicious, tag = isSuspiciousURL(url)
            emit("HTTP_GET", {
                url        = tostring(url):sub(1, 500),
                suspicious = suspicious,
                tag        = tag,
                source     = "env.HttpGet",
                stack      = captureStack(5),
            }, suspicious and 3 or 1)
            return orig(url, ...)
        end

        if newcclosure then
            pcall(function() wrapped = newcclosure(wrapped) end)
        end

        env.HttpGet = wrapped
        table.insert(restored, { env = env, method = "HttpGet", orig = orig })
    end

    -- hook request (Delta/Krnl)
    if type(env.request) == "function" then
        local orig = env.request
        State.originals.request = orig

        local wrapped = function(opts)
            local url = opts and opts.Url or "?"
            local method = opts and opts.Method or "GET"
            local suspicious, tag = isSuspiciousURL(url)
            emit("NETWORK_REQUEST", {
                url        = tostring(url):sub(1, 500),
                method     = method,
                suspicious = suspicious,
                tag        = tag,
                source     = "env.request",
                stack      = captureStack(5),
            }, suspicious and 3 or 1)
            return orig(opts)
        end

        if newcclosure then
            pcall(function() wrapped = newcclosure(wrapped) end)
        end

        env.request = wrapped
        table.insert(restored, { env = env, method = "request", orig = orig })
    end

    return function()
        for _, r in ipairs(restored) do
            pcall(function()
                if r.service then r.service[r.method] = r.orig
                elseif r.env then r.env[r.method] = r.orig end
            end)
        end
    end
end

--========== 6. FILE HOOK ==========--
local FILE_FUNCS = {
    { name = "readfile",   eventType = "FILE_READ",  sev = 1 },
    { name = "writefile",  eventType = "FILE_WRITE", sev = 1 },
    { name = "appendfile", eventType = "FILE_WRITE", sev = 1 },
    { name = "delfile",    eventType = "FILE_WRITE", sev = 2 },
    { name = "listfiles",  eventType = "FILE_READ",  sev = 0 },
    { name = "isfile",     eventType = "FILE_READ",  sev = 0 },
    { name = "makefolder", eventType = "FILE_WRITE", sev = 1 },
    { name = "delfolder",  eventType = "FILE_WRITE", sev = 2 },
}

local SENSITIVE_FILE_PATTERNS = {
    "token", "cookie", "session", "password", "credential",
    ".env", "auth", "secret", "key", "wallet", "seed",
}

local function installFileHooks(edr)
    if not Hooks.Config.HOOK_FILE then return nil end
    local env = getgenv and getgenv() or _G
    local restored = {}

    for _, entry in ipairs(FILE_FUNCS) do
        local orig = env[entry.name]
        if type(orig) == "function" then
            State.originals[entry.name] = orig

            local wrapped = function(path, ...)
                local sensitive = false
                if type(path) == "string" then
                    local lower = path:lower()
                    for _, pat in ipairs(SENSITIVE_FILE_PATTERNS) do
                        if lower:find(pat, 1, true) then sensitive = true; break end
                    end
                end

                local sev = entry.sev
                if sensitive then sev = math.max(sev, 3) end

                emit(entry.eventType, {
                    path      = tostring(path):sub(1, 300),
                    sensitive = sensitive,
                    func      = entry.name,
                    stack     = captureStack(5),
                }, sev)

                return orig(path, ...)
            end

            if newcclosure then
                pcall(function() wrapped = newcclosure(wrapped) end)
            end

            env[entry.name] = wrapped
            table.insert(restored, { name = entry.name, orig = orig })
        end
    end

    return function()
        for _, r in ipairs(restored) do
            pcall(function() env[r.name] = r.orig end)
        end
    end
end

--========== 7. STRING DECRYPT DETECTOR ==========--
local function installStringDecryptHook(edr)
    if not Hooks.Config.HOOK_STRING_DECRYPT then return nil end
    if not string then return nil end

    -- Hook string.char
    local origChar = string.char
    if type(origChar) == "function" then
        State.originals.string_char = origChar

        string.char = function(...)
            local n = select("#", ...)
            local result = origChar(...)

            -- ถ้า return string ที่ printable ยาวพอ → เป็นการ decrypt
            if n >= 5 and type(result) == "string"
                and result:match("^[%w%s%p]+$") and #result >= 5
                and rememberString(result)
            then
                if allowRate("string_char") then
                    local suspicious, tag = isSuspiciousURL(result)
                    local entropy = stringEntropy(result)
                    emit("STRING_DECRYPT", {
                        value     = result:sub(1, 200),
                        length    = #result,
                        entropy   = entropy,
                        b64       = looksBase64(result),
                        hex       = looksHex(result),
                        suspicious = suspicious,
                        tag       = tag,
                        source    = "string.char",
                    }, suspicious and 3 or 1)
                end
            end

            return result
        end

        if newcclosure then
            pcall(function() string.char = newcclosure(string.char) end)
        end
    end

    -- Hook string.gsub เพื่อจับ deobfuscation pattern
    local origGsub = string.gsub
    if type(origGsub) == "function" then
        State.originals.string_gsub = origGsub

        string.gsub = function(s, pattern, repl, n)
            local result = origGsub(s, pattern, repl, n)
            -- ถ้า gsub แล้วได้ base64/URL น่าจะเป็น decrypt
            if type(result) == "string" and #result > 20 then
                if rememberString(result) then
                    local suspicious, tag = isSuspiciousURL(result)
                    if suspicious or looksBase64(result) then
                        emit("STRING_DECRYPT", {
                            value     = result:sub(1, 200),
                            suspicious = suspicious,
                            tag       = tag,
                            b64       = looksBase64(result),
                            source    = "string.gsub",
                        }, suspicious and 3 or 1)
                    end
                end
            end
            return result
        end

        if newcclosure then
            pcall(function() string.gsub = newcclosure(string.gsub) end)
        end
    end

    -- Hook bit32.bxor (Luraph ใช้เยอะ)
    if bit32 and type(bit32.bxor) == "function" then
        local origBxor = bit32.bxor
        State.originals.bit32_bxor = origBxor

        local counter = 0
        local lastFlush = now()

        bit32.bxor = function(...)
            counter = counter + 1
            local t = now()
            if t - lastFlush >= 1 then
                if counter >= 100 then  -- decrypt loop pattern
                    if allowRate("bxor_burst") then
                        emit("STRING_DECRYPT", {
                            count   = counter,
                            source  = "bit32.bxor",
                            stack   = captureStack(4),
                        }, 1)
                    end
                end
                counter = 0
                lastFlush = t
            end
            return origBxor(...)
        end

        if newcclosure then
            pcall(function() bit32.bxor = newcclosure(bit32.bxor) end)
        end
    end

    return function()
        if State.originals.string_char then string.char = State.originals.string_char end
        if State.originals.string_gsub then string.gsub = State.originals.string_gsub end
        if bit32 and State.originals.bit32_bxor then bit32.bxor = State.originals.bit32_bxor end
    end
end

--========== 8. DEBUG LIBRARY MONITOR ==========--
local DEBUG_FUNCS = {
    "getinfo", "getlocal", "setupvalue", "setlocal",
    "sethook", "gethook", "traceback", "getregistry",
    "getupvalue", "setupvalue", "getmetatable", "setmetatable",
    "getfenv", "setfenv", "getuservalue",
}

local function installDebugMonitor(edr)
    if not debug then return nil end
    local restored = {}

    for _, name in ipairs(DEBUG_FUNCS) do
        local orig = debug[name]
        if type(orig) == "function" then
            State.originals["debug_" .. name] = orig

            local wrapped = function(...)
                emit("DEBUG_ACCESS", {
                    name  = name,
                    stack = captureStack(5),
                }, 1)
                return orig(...)
            end

            if newcclosure then
                pcall(function() wrapped = newcclosure(wrapped) end)
            end

            debug[name] = wrapped
            table.insert(restored, { name = name, orig = orig })
        end
    end

    return function()
        for _, r in ipairs(restored) do
            pcall(function() debug[r.name] = r.orig end)
        end
    end
end

--========== 9. METATABLE HOOK ==========--
local function installMetatableHook(edr)
    if not setmetatable then return nil end

    local origSetMeta = setmetatable
    local origGetRaw = getrawmetatable
    State.originals.setmetatable = origSetMeta
    if origGetRaw then State.originals.getrawmetatable = origGetRaw end

    setmetatable = function(t, mt)
        if type(t) == "table" and type(mt) == "table" then
            local keys = {}
            for k in pairs(mt) do table.insert(keys, tostring(k)) end
            if allowRate("setmetatable") then
                emit("METATABLE_ACCESS", {
                    op       = "set",
                    keys     = table.concat(keys, ","),
                    stack    = captureStack(4),
                }, 1)
            end
        end
        return origSetMeta(t, mt)
    end

    if getrawmetatable then
        getrawmetatable = function(t)
            if allowRate("getrawmetatable") then
                emit("METATABLE_ACCESS", {
                    op    = "getraw",
                    stack = captureStack(4),
                }, 1)
            end
            return origGetRaw(t)
        end
    end

    if newcclosure then
        pcall(function()
            setmetatable = newcclosure(setmetatable)
            if getrawmetatable then getrawmetatable = newcclosure(getrawmetatable) end
        end)
    end

    return function()
        setmetatable = origSetMeta
        if origGetRaw then getrawmetatable = origGetRaw end
    end
end

--========== 10. ENVIRONMENT HOOK ==========--
local function installEnvironmentHook(edr)
    local env = getgenv and getgenv() or _G
    local restored = {}

    -- getfenv / setfenv
    if type(getfenv) == "function" then
        local orig = getfenv
        State.originals.getfenv = orig
        getfenv = function(...)
            if allowRate("getfenv") then
                emit("ENV_ACCESS", { op = "get", stack = captureStack(4) }, 0)
            end
            return orig(...)
        end
        if newcclosure then pcall(function() getfenv = newcclosure(getfenv) end) end
        table.insert(restored, { name = "getfenv", orig = orig })
    end

    if type(setfenv) == "function" then
        local orig = setfenv
        State.originals.setfenv = orig
        setfenv = function(...)
            emit("ENV_ACCESS", { op = "set", stack = captureStack(4) }, 2)
            return orig(...)
        end
        if newcclosure then pcall(function() setfenv = newcclosure(setfenv) end) end
        table.insert(restored, { name = "setfenv", orig = orig })
    end

    -- Thread identity (Delta / Synapse)
    if type(env.setthreadidentity) == "function" then
        local orig = env.setthreadidentity
        State.originals.setthreadidentity = orig
        env.setthreadidentity = function(id)
            emit("THREAD_IDENTITY", {
                op  = "set",
                id  = id,
                stack = captureStack(4),
            }, 2)
            return orig(id)
        end
        table.insert(restored, { env = env, name = "setthreadidentity", orig = orig })
    end

    if type(env.getthreadidentity) == "function" then
        local orig = env.getthreadidentity
        State.originals.getthreadidentity = orig
        env.getthreadidentity = function()
            local id = orig()
            emit("THREAD_IDENTITY", { op = "get", id = id }, 0)
            return id
        end
        table.insert(restored, { env = env, name = "getthreadidentity", orig = orig })
    end

    return function()
        for _, r in ipairs(restored) do
            pcall(function()
                if r.env then r.env[r.name] = r.orig
                else _G[r.name] = r.orig end
            end)
        end
    end
end

--========== INSTALL ALL ==========--
function Hooks.install(edr)
    if State.installed then
        return false, "already installed"
    end
    State.edr = edr

    local unhooks = {}

    local function try(name, fn)
        local ok, result = pcall(fn, edr)
        if ok and result then
            table.insert(unhooks, { name = name, fn = result })
            if edr.registerHook then
                edr:registerHook("hooks." .. name, result)
            end
        end
    end

    try("opcode",       installOpcodeHook)
    try("global",       installGlobalProxy)
    try("functions",    installFunctionWrappers)
    try("coroutine",    installCoroutineTracker)
    try("network",      installNetworkHooks)
    try("file",         installFileHooks)
    try("string",       installStringDecryptHook)
    try("debug",        installDebugMonitor)
    try("metatable",    installMetatableHook)
    try("environment",  installEnvironmentHook)

    State.installed = true
    State.unhooks = unhooks

    return true, #unhooks
end

--========== UNINSTALL ALL ==========--
function Hooks.uninstall()
    if not State.installed then return end
    for _, entry in ipairs(State.unhooks or {}) do
        pcall(entry.fn)
    end
    State.unhooks = {}
    State.installed = false
end

--========== UTILITIES ==========--
Hooks.isSuspiciousURL = isSuspiciousURL
Hooks.stringEntropy   = stringEntropy
Hooks.looksBase64     = looksBase64
Hooks.looksHex        = looksHex
Hooks.captureStack    = captureStack

--========== EXPORT ==========--
return Hooks