local infectedResources = {}
local scanStats = {
  totalScanned = 0,
  infected = 0,
  cleaned = 0,
  startTime = 0,
  endTime = 0
}

local function isResourceIgnored(resourceName)
  for _, ignored in ipairs(ZayssScanner.IgnoreResources) do
    if resourceName == ignored then
      return true
    end
  end
  return false
end

local function analyzeObfuscationLevel(content)
  if not ZayssScanner.AdvancedDetection.DetectObfuscation then
    return 0, "Low", {}
  end

  local score = 0
  local details = {}

  if ZayssScanner.AdvancedDetection.DetectEval and string.find(content, "eval") then
    score = score + 10
    table.insert(details, "eval() detected")
  end

  if string.find(content, "fromCharCode") then
    score = score + 15
    table.insert(details, "fromCharCode encoding")
  end

  local unicodeCount = 0
  for _ in content:gmatch("\\u%x%x%x%x") do
    unicodeCount = unicodeCount + 1
  end
  if unicodeCount > 50 then
    score = score + 20
    table.insert(details, unicodeCount .. " unicode sequences")
  end

  if ZayssScanner.AdvancedDetection.DetectXOREncryption and string.find(content, "charCodeAt%(0%)%^") then
    score = score + 25
    table.insert(details, "XOR encryption")
  end

  if ZayssScanner.AdvancedDetection.DetectRemoteExecution and string.find(content, "PerformHttpRequest") and string.find(content, "eval") then
    score = score + 30
    table.insert(details, "Remote code execution")
  end

  if ZayssScanner.AdvancedDetection.DetectBase64 and string.find(content, "atob%(") then
    score = score + 15
    table.insert(details, "Base64 decoding")
  end

  if ZayssScanner.AdvancedDetection.DetectSuspiciousAPIs then
    if string.find(content, "ExecuteCommand") or string.find(content, "TriggerServerEvent") then
      score = score + 10
      table.insert(details, "Suspicious API usage")
    end
  end

  local suspicionLevel = "Low"
  if score > 50 then
    suspicionLevel = "CRITICAL"
  elseif score > 30 then
    suspicionLevel = "High"
  elseif score > 15 then
    suspicionLevel = "Medium"
  end

  if score < ZayssScanner.AdvancedDetection.MinObfuscationScore then
    return score, "Low", details
  end

  return score, suspicionLevel, details
end

local function checkForBackdoor(content, resourceName, scriptPath)
  local backdoorPatterns = {
    {pattern = "cipher%-panel", name = "cipher-panel", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "Enchanced_Tabs", name = "Enchanced_Tabs", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "eszjqvpjhiou%.mom", name = "Cipher Backdoor new version", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "cfx%.re", name = "cipher-panel([cfx.re])", type = "[CIPHER BACKDOOR]"},
    {pattern = "pqzskjptss", name = "pqzskjptss", type = "[CIPHER BACKDOOR]"},
    {pattern = "/stage3?", name = "/stage3?", type = "[CIPHER BACKDOOR]"},
    {pattern = "abxcgraovp", name = "abxcgraovp", type = "[CIPHER BACKDOOR]"},
    {pattern = "eszjqvpjhiou", name = "eszjqvpjhiou", type = "[CIPHER BACKDOOR]"},
    {pattern = "rpserveur%.fr", name = "rpserveur.fr", type = "[CIPHER BACKDOOR]"},
    {pattern = "KjnUNXqPtJIgEvURPelSeeNlHRsEvwXhUUjttMNBPYbBHoycMcfTcfpLYTYussggrdtEyi", name = "Cipher Backdoor", type = "[CIPHER BACKDOOR]"},
    {pattern = "helperServer", name = "helperServer", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "ketamin%.cc", name = "ketamin.cc", type = "[[KETAMIN BACKDOOR]]"},
    {pattern = "cipher%-panel%.me", name = "cipher-panel.me", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "blum-panel.me", name = "blum-panel", type = "[[BLUM-PANEL BACKDOOR]]"},
    {pattern = "blum%-panel%.me", name = "blum-panel", type = "[[BLUM-PANEL BACKDOOR]]"},
    {pattern = "blum%-panel%", name = "blum-panel", type = "[[BLUM-PANEL BACKDOOR]]"},
    {pattern = "blum-panel", name = "blum-panel", type = "[[BLUM-PANEL BACKDOOR]]"},
    {pattern = "MpWxwQeLMRJaDFLKmxVIFNeVfzVKaTBiVRvjBoePYciqfpJzxjNPIXedbOtvIbpDxqdoJR", name = "MpWxwQeLMRJaDFLKmxVIFNeVfzVKaTBiVRvjBoePYciqfpJzxjNPIXedbOtvIbpDxqdoJR", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "token%.cipher%-panel%.me", name = "Cipher Token Backdoor (token.cipher-panel.me)", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "kelaidi09981%.org", name = "Cipher Kelaidi Backdoor (kelaidi09981.org)", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "R9D9TJJ", name = "Cipher Backdoor Token R9D9TJJ", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "bGVkPPCKBRqLBok", name = "Cipher RCE Callback (bGVkPPCKBRqLBok)", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "runInThisContext", name = "VM runInThisContext (remote code exec)", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "vm%.runInThisContext", name = "Lua VM runInThisContext reference", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "IsDuplicityVersion", name = "Cipher IsDuplicityVersion check", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "Buffer%.from%('Z2V0'", name = "Cipher Base64 Buffer.from obfuscation", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "Buffer%.from%('dm0='", name = "Cipher Base64 VM require obfuscation", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "Buffer%.from%('ZGF0YQ=='", name = "Cipher Base64 data event obfuscation", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "child_process", name = "Node child_process module (code execution)", type = "[[SUSPICIOUS MODULE]]"},
    {pattern = "sv_licenseKey", name = "Server license key access", type = "[[TOKEN THEFT]]"},
    {pattern = "TXADMIN_DEFAULT_PASSWORD", name = "txAdmin password theft", type = "[[TOKEN THEFT]]"},
    {pattern = "cipher%-panel%.me/", name = "Cipher panel domain with path", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "token%.cipher", name = "Cipher token subdomain", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "appendFileSync", name = "Node appendFileSync (file injection)", type = "[[SUSPICIOUS FILE WRITE]]"},
    {pattern = "callbackEvent", name = "Cipher RCE callbackEvent field", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "quantumdev%.lol", name = "Cipher C2 quantumdev.lol (variante token.cipher-panel.me)", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "noisreVyticilpuDsI", name = "IsDuplicityVersion renverse (bypass scanner par string-reversal)", type = "[[CIPHER LUA BACKDOOR]]"},
    {pattern = "HoYEdDEUWGBVHJk", name = "Nom d'event RCE Cipher obfusque (renverse)", type = "[[CIPHER LUA BACKDOOR]]"},
    {pattern = "kJHVBGWUEdEYoH", name = "Event RCE Cipher kJHVBGWUEdEYoH (octal decode)", type = "[[CIPHER LUA BACKDOOR]]"},
    -- Nouveau domaine C2 Cipher detecte dans oxmysql/dist/build.js
    {pattern = "resourcesfivem%.org", name = "Cipher C2 resourcesfivem.org", type = "[[CIPHER BACKDOOR]]"},
    -- Base64 'get' utilise pour masquer http.get() - signature Cipher Node.js
    {pattern = "Buffer%.from%('Z2V0','base64'%)", name = "Cipher base64 'get' obfuscation (http.get bypass)", type = "[[CIPHER BACKDOOR]]"},
    -- Base64 'data' utilise pour masquer l'evenement .on('data') - variante yarn
    {pattern = "Buffer%.from%('ZGF0YQ==','base64'%)", name = "Cipher base64 'data' event obfuscation", type = "[[CIPHER BACKDOOR]]"},
    -- Base64 'https' utilise pour masquer require('https')
    {pattern = "Buffer%.from%('aHR0cHM=','base64'%)", name = "Cipher base64 'https' require obfuscation", type = "[[CIPHER BACKDOOR]]"},
    -- Nouveau domaine C2 detecte dans webpack_builder.js
    {pattern = "b4lls%.uk", name = "Cipher C2 b4lls.uk", type = "[[CIPHER BACKDOOR]]"},
    -- fromCharCode(104,116,116,112,115) = 'https' encode en charcode
    {pattern = "fromCharCode%(104,116,116,112,115%)", name = "Cipher charcode 'https' obfuscation", type = "[[CIPHER BACKDOOR]]"},
    {pattern = "kJHVBGWUEDdEYoH", name = "Cipher NUI RCE callback kJHVBGWUEDdEYoH", type = "[[CIPHER HTML BACKDOOR]]"},
    {pattern = "fromCharCode%(99,111,100,101%)", name = "Cipher charcode 'code' field (NUI eval backdoor)", type = "[[CIPHER HTML BACKDOOR]]"}
  }

  for _, backdoor in ipairs(backdoorPatterns) do
    if string.find(content, backdoor.pattern) then
      return true, backdoor.name, backdoor.type
    end
  end

  local trimmed = content:match("^%s*(.-)%s*$") or content
  if trimmed:match("^/%*%s*%[.-%]%s*%*/") then
    return true, "Blum Injection Signature (/* [name] */)", "[[BLUM INJECTION]]"
  end

  if trimmed:match("^%(function%(%)%{const%s+%w+=%d+;function%s+%w+%(a,k%)") and string.find(content, "fromCharCode") and string.find(content, "eval") then
    return true, "XOR Obfuscated Blum Backdoor (eval + fromCharCode + XOR)", "[[BLUM XOR BACKDOOR]]"
  end

  if string.find(content, "x=s=>eval%(s%.replace") and string.find(content, "fromCharCode") then
    return true, "XOR Obfuscated Backdoor (eval + fromCharCode)", "[[XOR OBFUSCATION BACKDOOR]]"
  end

  if string.find(content, "String%.fromCharCode") and string.find(content, "eval") then
    return true, "JavaScript Obfuscated eval", "[[OBFUSCATION BACKDOOR]]"
  end

  if string.find(content, "addEventListener") and string.find(content, "fromCharCode") and string.find(content, "eval") and string.find(content, "GetParentResourceName") then
    return true, "Cipher NUI eval listener (HTML message + eval + callback)", "[[CIPHER HTML BACKDOOR]]"
  end

  if string.find(content, "require%('https'%)") and string.find(content, "runInThisContext") then
    return true, "Cipher HTTPS + VM remote exec", "[[CIPHER BACKDOOR]]"
  end

  if string.find(content, "require%('vm'%)") and string.find(content, "Buffer%.concat") and string.find(content, "https%.get") then
    return true, "Cipher VM buffer concat remote exec", "[[CIPHER BACKDOOR]]"
  end

  if string.find(content, "Buffer%.from%('") and string.find(content, "base64") and string.find(content, "toString%]") then
    return true, "Cipher obfuscated Buffer.from base64 chain", "[[CIPHER BACKDOOR]]"
  end

  if string.find(content, "\\x6f\\x6e") or string.find(content, "\\x65\\x76\\x61\\x6c") or string.find(content, "\\x63\\x6f\\x6e\\x63\\x61\\x74") then
    return true, "Cipher hex-escaped JS strings", "[[CIPHER BACKDOOR]]"
  end

  if string.find(content, "bGVkPPCKBRqLBok") then
    return true, "Cipher NUI callback identifier", "[[CIPHER BACKDOOR]]"
  end

  if string.find(content, "globalThis%[") and string.find(content, "%]%(") then
    return true, "GlobalThis execution backdoor", "[[OBFUSCATION BACKDOOR]]"
  end

  if string.find(content, "charCodeAt%(0%)%^%d") then
    return true, "XOR Character encoding", "[[XOR BACKDOOR]]"
  end

  if
    (string.find(content, "SaveResourceFile") or string.find(content, "io%.open%(")) and
    (string.find(content, "GetNumResources") or string.find(content, "GetResourceByFindIndex")) then
    return true, "Resource Injector (writes into other resources)", "[[INJECTOR BACKDOOR]]"
  end

  if
    string.find(content, "PerformHttpRequest") and
    (string.find(content, "SaveResourceFile") or string.find(content, "LoadResourceFile")) then
    return true, "Remote Payload Injector", "[[INJECTOR BACKDOOR]]"
  end

  if string.find(content, "loadstring%(") or
     string.find(content, "assert%(%s*load") or
     string.find(content, "load%(") then
    return true, "Dynamic Lua code execution loader", "[[LUA LOADER BACKDOOR]]"
  end

  if string.find(content, "RegisterNetEvent") and string.find(content, "assert") and string.find(content, "load") and string.find(content, "TriggerServerEvent") then
    if string.find(content, "\\98\\71\\86") or string.find(content, "string%.char%(98,71,86") or string.find(content, "bGVkPPCKBRqLBok") then
      return true, "Cipher Lua obfuscated RCE (RegisterNetEvent + load + assert)", "[[CIPHER LUA BACKDOOR]]"
    end
  end

  if string.find(content, "string%.char%(") and string.find(content, "RegisterNetEvent") and string.find(content, "pcall") and string.find(content, "assert") then
    return true, "Cipher Lua string.char obfuscated event handler", "[[CIPHER LUA BACKDOOR]]"
  end

  if string.find(content, "rawget%(_G") and string.find(content, "rawset") and string.find(content, "string%.char%(") and string.find(content, "CreateThread") then
    return true, "Cipher Lua rawget/rawset obfuscated backdoor", "[[CIPHER LUA BACKDOOR]]"
  end


  if string.find(content, '"R"%.%.') and string.find(content, '"egi"') and (string.find(content, "assert") or string.find(content, "load")) then
    return true, "Cipher Lua string-concat obfuscated RegisterNetEvent", "[[CIPHER LUA BACKDOOR]]"
  end

  if string.find(content, 'local%s+=%s*_?G') and string.find(content, "CreateThread") and (string.find(content, "pcall") or string.find(content, "assert")) then
    return true, "Cipher Lua _G alias obfuscated RCE", "[[CIPHER LUA BACKDOOR]]"
  end

  if (string.find(content, "writeFileSync") or string.find(content, "appendFileSync")) and
     (string.find(content, "GetResourcePath") or string.find(content, "GetNumResources") or string.find(content, "GetResourceByFindIndex")) then
    return true, "JS File Injector (fs write + resource scanning)", "[[JS INJECTOR BACKDOOR]]"
  end

  if string.find(content, "addEventListener") and string.find(content, "eval") and string.find(content, "GetParentResourceName") then
    return true, "NUI eval listener backdoor (message + eval + NUI callback)", "[[CIPHER HTML BACKDOOR]]"
  end

  if string.find(content, '"preinstall"') or string.find(content, '"postinstall"') or string.find(content, '"prepublish"') then
    if string.find(content, "node ") or string.find(content, "curl") or string.find(content, "wget") or
       string.find(content, "eval") or string.find(content, "base64") or string.find(content, "http") then
      return true, "NPM malicious lifecycle script (preinstall/postinstall)", "[[NPM INJECTOR]]"
    end
  end

  if string.find(content, "process%.env") and
     (string.find(content, "https?") or string.find(content, "fetch%(") or string.find(content, "XMLHttpRequest") or string.find(content, "%.get%(")) then
    return true, "Environment variable exfiltration", "[[TOKEN THEFT]]"
  end

  if string.find(content, "require%('https'%)") and string.find(content, "require%('vm'%)") then
    return true, "Cipher HTTPS downloader + VM executor", "[[CIPHER BACKDOOR]]"
  end


  local hexCount = 0
  for _ in content:gmatch("\\x%x%x") do hexCount = hexCount + 1 end
  if hexCount > 5 and (string.find(content, "require") or string.find(content, "addEventListener")) then
    return true, "Heavy hex-escape obfuscation (" .. hexCount .. " sequences)", "[[CIPHER OBFUSCATION]]"
  end

  local charCodeCount = 0
  for _ in content:gmatch("fromCharCode") do charCodeCount = charCodeCount + 1 end
  if charCodeCount >= 3 and (string.find(content, "require") or string.find(content, "eval") or string.find(content, "fetch")) then
    return true, "Heavy fromCharCode obfuscation (" .. charCodeCount .. " usages)", "[[CIPHER OBFUSCATION]]"
  end

  if string.find(content, "fxmanifest") or string.find(content, "__resource%.lua") then
    if string.find(content, "SaveResourceFile") or string.find(content, "io%.open") then
      return true, "Manifest Injector (auto persistence)", "[[PERSISTENCE INJECTOR]]"
    end
  end


  if string.find(content, "\\u%x%x%x%x") and string.find(content, "eval") then
    local unicodeCount = 0
    for _ in content:gmatch("\\u%x%x%x%x") do
      unicodeCount = unicodeCount + 1
    end
    if unicodeCount > 50 then
      return true, "Unicode Obfuscated Code (Suspected XOR)", "[[UNICODE OBFUSCATION BACKDOOR]]"
    end
  end

  if string.find(content, "%.replace%(") and string.find(content, "split%(") and string.find(content, "eval%(") then
    return true, "String manipulation + eval", "[[OBFUSCATION BACKDOOR]]"
  end

  if string.find(content, "https?://") and
     (string.find(content, "PerformHttpRequest") or string.find(content, "InvokeNative")) then
    return true, "Remote payload downloader", "[[REMOTE LOADER]]"
  end

  if string.find(content, "debug%.getinfo") or string.find(content, "pcall%(") then
    return true, "Anti-debug / stealth behavior", "[[STEALTH BACKDOOR]]"
  end

  local writeCount = 0
  for _ in content:gmatch("SaveResourceFile") do writeCount = writeCount + 1 end

  if writeCount >= 3 then
    return true, "Multi-file dropper behavior", "[[DROPPER BACKDOOR]]"
  end


  if string.find(content, "LoadResourceFile") and string.find(content, "load%(") then
    return true, "Dynamic file loading", "[[SUSPICIOUS CODE LOADING]]"
  end

  -- Renversement de string + appel via _G pour masquer les fonctions
  if string.find(content, ":reverse%(%)") and string.find(content, "_G%[") and string.find(content, "CreateThread") then
    return true, "String-reversal obfuscated RCE (_r() + _G[] + CreateThread)", "[[CIPHER LUA BACKDOOR]]"
  end

  -- Strings renverses caracteristiques: "daol"=load, "tressa"=assert ensemble
  if string.find(content, '"daol"') and string.find(content, '"tressa"') then
    return true, "Reversed load+assert strings (string-reversal bypass technique)", "[[CIPHER LUA BACKDOOR]]"
  end

  -- Self-invoking function appendee apres un bloc config (;(function() en debut de ligne)
  -- Pattern: fichier se termine par cette construction apres un tableau Lua legitime
  if string.find(content, "%;%(function%(%)") and string.find(content, "_G%[") and string.find(content, "CreateThread") then
    return true, "Self-invoking RCE function appended to config file", "[[CIPHER LUA BACKDOOR]]"
  end

  -- Escapes octaux lourds dans un acces _G (ex: _G["\107\74\72..."] = event name obfusque)
  -- Compte le nombre de sequences \NNN dans le contenu
  local octalCount = 0
  for _ in content:gmatch("\\%d%d%d") do octalCount = octalCount + 1 end
  if octalCount >= 6 and string.find(content, "_G%[") and string.find(content, "CreateThread") then
    return true, "Octal-escaped _G key access with CreateThread (" .. octalCount .. " sequences)", "[[CIPHER LUA BACKDOOR]]"
  end

  -- Variante Cipher Node.js: fromCharCode utilise pour masquer runInThisContext + https en hex
  if string.find(content, "fromCharCode") and string.find(content, "Buffer%.from%('") and
     (string.find(content, "require%(") or string.find(content, "require%('")) then
    local hexCount2 = 0
    for _ in content:gmatch("\\x%x%x") do hexCount2 = hexCount2 + 1 end
    if hexCount2 >= 4 then
      return true, "Cipher Node.js C2 downloader (fromCharCode + Buffer.from + hex require)", "[[CIPHER BACKDOOR]]"
    end
  end

  -- Combo base64 get + push = signature forte du downloader Cipher Node.js
  if string.find(content, "Buffer%.from%('Z2V0','base64'%)") and
     string.find(content, "Buffer%.from%('cHVzaA==','base64'%)") then
    return true, "Cipher base64 get+push combo (C2 downloader obfuscation)", "[[CIPHER BACKDOOR]]"
  end

  -- Combo base64 data + push (variante yarn_builder)
  if string.find(content, "Buffer%.from%('ZGF0YQ==','base64'%)") and
     string.find(content, "Buffer%.from%('cHVzaA==','base64'%)") then
    return true, "Cipher base64 data+push combo (C2 downloader variante)", "[[CIPHER BACKDOOR]]"
  end

  -- URL C2 Cipher splitee en morceaux (pattern: 'https'+':/'+'/token' ou '/r'+'eso'+'urc')
  if string.find(content, "'https'%s*%.%.%s*':/") or string.find(content, "\"https\"%s*%+%s*\":/") then
    if string.find(content, "runInThisContext") or string.find(content, "\\x76\\x6d") or
       string.find(content, "Buffer%.from%('") then
      return true, "Cipher URL split-concat obfuscation (anti-scanner URL fragmentation)", "[[CIPHER BACKDOOR]]"
    end
  end

  -- Token R9D9TJJ dans une URL concatenee (lettre par lettre ou en morceaux)
  if string.find(content, "'R9'") and string.find(content, "'D9'") and string.find(content, "'TJ'") then
    return true, "Cipher payload token R9D9TJJ fragment (URL split obfuscation)", "[[CIPHER BACKDOOR]]"
  end

  return false, nil, nil
end

local function reportInfection(resourceName, scriptPath, content)
  local isInfected, backdoorName, backdoorType = checkForBackdoor(content, resourceName, scriptPath)
  if not isInfected then return end

  scanStats.infected = scanStats.infected + 1
  local score, level, details = analyzeObfuscationLevel(content)

  table.insert(infectedResources, {
    resource = resourceName,
    file = scriptPath,
    backdoorType = backdoorType,
    backdoorName = backdoorName,
    suspicionScore = score,
    suspicionLevel = level,
    details = details,
    deleted = false
  })

  print("[^4RESSOURCE INFECTÉE DÉTECTÉE^0] - " .. resourceName)
  print("^5  └─ Fichier^0: " .. scriptPath)
  print("^5  └─ Type^0: " .. backdoorType)
  print("^5  └─ Niveau de menace^0: " .. level .. " (Score: ^5" .. score .. "^0)")
end

local function scanResource(resourceName)
  if isResourceIgnored(resourceName) then
    print("(^4ZayssScanner^0): (^6Skip^0) => Ressource whitelist ignorée : ^7" .. resourceName)
    return
  end

  scanStats.totalScanned = scanStats.totalScanned + 1

  local scriptsToScan = {}

  if ZayssScanner.ScanOptions.ScanServerScripts then
    local numServerScripts = GetNumResourceMetadata(resourceName, "server_script")
    for j = 0, numServerScripts - 1 do
      local scriptPath = GetResourceMetadata(resourceName, "server_script", j)
      table.insert(scriptsToScan, {path = scriptPath, type = "server"})
    end
  end

  if ZayssScanner.ScanOptions.ScanClientScripts then
    local numClientScripts = GetNumResourceMetadata(resourceName, "client_script")
    for j = 0, numClientScripts - 1 do
      local scriptPath = GetResourceMetadata(resourceName, "client_script", j)
      table.insert(scriptsToScan, {path = scriptPath, type = "client"})
    end
  end

  if ZayssScanner.ScanOptions.ScanUIPages then
    local numUiPages = GetNumResourceMetadata(resourceName, "ui_page")
    for j = 0, numUiPages - 1 do
      local uiPage = GetResourceMetadata(resourceName, "ui_page", j)
      table.insert(scriptsToScan, {path = uiPage, type = "ui"})
    end
  end

  local scannedPaths = {}

  for _, script in ipairs(scriptsToScan) do
    local scriptPath = script.path
    if scriptPath and not string.find(scriptPath, "*") and not string.find(scriptPath, "^@") then
      local content = LoadResourceFile(resourceName, scriptPath)

      if content and content ~= "" then
        scannedPaths[scriptPath] = true
        reportInfection(resourceName, scriptPath, content)
      end
    end
  end

  if ZayssScanner.ScanOptions.DeepScan then
    local resourcePath = GetResourcePath(resourceName)
    if resourcePath then
      local scanExts = {".js", ".lua", ".html"}
      if ZayssScanner.ScanOptions.ScanPackageJSON then
        table.insert(scanExts, ".json")
      end
      local allFiles = exports[GetCurrentResourceName()]:scanDirectoryRecursive(resourcePath, scanExts)
      if allFiles and type(allFiles) == "table" then
        for _, fullPath in ipairs(allFiles) do
          local relativePath = fullPath:sub(#resourcePath + 1):gsub("^[\\/]+", ""):gsub("\\", "/")
          if not scannedPaths[relativePath] then
            local content = exports[GetCurrentResourceName()]:readFileContent(fullPath)
            if content and content ~= "" and #content < 5000000 then
              reportInfection(resourceName, relativePath, content)
            end
          end
        end
      end
    end
  end
end

local function startScan()
  infectedResources = {}
  scanStats.startTime = os.clock()
  scanStats.totalScanned = 0
  scanStats.infected = 0
  scanStats.cleaned = 0

  print("(^4ZayssScanner^0): (^3Scan^0) => Début de l'analyse approfondie de toutes les ressources...")

  for i = 0, GetNumResources() - 1 do
    local resourceName = GetResourceByFindIndex(i)
    scanResource(resourceName)
  end

  if ZayssScanner.ScanOptions.DeepScan then
    local monitorPath = exports[GetCurrentResourceName()]:getMonitorPath()
    if monitorPath then
      local allowedSystem = {["chat"] = true, ["monitor"] = true, ["[system]"] = true}
      local systemEntries = exports[GetCurrentResourceName()]:readDir(monitorPath)
      if systemEntries and type(systemEntries) == "table" then
        for _, entry in ipairs(systemEntries) do
          local name = entry:gsub("[/\\]$", "")
          if not allowedSystem[name] and name ~= "" then
            print("(^4ZayssScanner^0): ^1[ALERTE]^0 Fichier/dossier suspect dans le répertoire système cfx: ^1" .. name .. "^0")
            scanStats.infected = scanStats.infected + 1
            table.insert(infectedResources, {
              resource = "[cfx-system]",
              file = name,
              backdoorType = "Fichier système non autorisé",
              backdoorName = "cfx-injection",
              suspicionScore = 100,
              suspicionLevel = "CRITIQUE",
              details = "Fichier/dossier non standard dans le répertoire système CFX",
              deleted = false
            })
          end
        end
      end
    end
  end

  scanStats.endTime = os.clock()

  if #infectedResources > 0 then
    print("^5========================================^0")
    print("(^4ZayssScanner^0): (^3Scan^0) => Des backdoors potentielles ont été détectées !")
    print("(^4ZayssScanner^0): (^3Scan^0) => Veuillez vérifier les print ou logs discord si actif pour plus d'informations.")
    print("^5========================================^0")

    for _, infection in ipairs(infectedResources) do
        --print("^5+^0 ^1" .. infection.resource .. "/" .. infection.file .. "^0")
      --print("Type: [^1" .. infection.backdoorType .. "^0]")
    end

    print("^5========================================^0")
    print("(^4ZayssScanner^0): (^3Scan^0) => Informations du scan")
    print("(^4ZayssScanner^0): (^3Scan^0) =>  Total Scanné: ^3" .. scanStats.totalScanned .. " ^0")
    print("(^4ZayssScanner^0): (^3Scan^0) =>  Potentiellement infectés: ^1" .. scanStats.infected .. " ^0")
    print("(^4ZayssScanner^0): (^3Scan^0) =>  Durée du scan: ^3" .. string.format("%.2f", scanStats.endTime - scanStats.startTime) .. "s^0")
    print("^5========================================^0")

    if ZayssScanner.StopServer and scanStats.infected > 0 and scanStats.cleaned == 0 then
      print("(^4ZayssScanner^0): (^3Scan^0) => Backdoors non éliminées détectées !")
      print("(^4ZayssScanner^0): (^3Scan^0) => Le serveur s'arrêtera dans 5 secondes....")
      Citizen.Wait(5000)
      os.exit()
    end
  else
    print("^5========================================^0")
    print("(^4ZayssScanner^0): (^3Scan^0) => Aucune backdoor detecté ")
    print("(^4ZayssScanner^0): (^3Scan^0) => Votre serveur est clean mais veuillez quand meme verifier a la main si vous trouvez des fichiers suspects.")
    print("^5========================================^0")
  end
end

AddEventHandler("onResourceStart", function(resourceName)
  if resourceName == GetCurrentResourceName() then
      print([[
^5          __________                            _________
^5          \____    /____  ___.__. ______ ______/   _____/ ____ _____    ____
^5            /     /\__  \<   |  |/  ___//  ___/\_____  \_/ ___\\__  \  /    \
^5           /     /_ / __ \\___  |\___ \ \___ \ /        \  \___ / __ \|   |  \
^5          /_______ (____  / ____/____  >____  >_______  /\___  >____  /___|  /
^5                  \/    \/\/         \/     \/        \/     \/     \/     \/^0
  ]])
    print("^5=============================================^0")
    print("(^4ZayssScanner^0): Commandes disponibles: ^6scan-backdoor^0 - Lance une analyse dans tous les repertoires du serveur.")
    print("(^4ZayssScanner^0): ZayssScanner By ^5Zayss^0 : https://github.com/zayss212/Zayss-Scanner-AntiBackdoorFiveM")
    print("(^4ZayssScanner^0): N'hésitez pas à rejoindre mon discord : ^5https://discord.gg/MsMw2NQ7Vj^0")
  end

  if ZayssScanner.AutoScan.Enabled  and resourceName ~= GetCurrentResourceName() then
    Citizen.SetTimeout(2000, function()
      print("(^4ZayssScanner^0): Nouvelle ressource détectée: ^7" .. resourceName)
      scanResource(resourceName)
    end)
  end
end)

if ZayssScanner.AutoScan.Enabled then
  Citizen.CreateThread(function()
    while true do
      Citizen.Wait(ZayssScanner.AutoScan.Interval)
      print("(^4ZayssScanner^0): Exécution de l'analyse planifiée selon la config...")
      startScan()
    end
  end)
end

RegisterCommand("scan-backdoor", function()
    print([[^5
        __________                            _________
        \____    /____  ___.__. ______ ______/   _____/ ____ _____    ____
          /     /\__  \<   |  |/  ___//  ___/\_____  \_/ ___\\__  \  /    \
         /     /_ / __ \\___  |\___ \ \___ \ /        \  \___ / __ \|   |  \
        /_______ (____  / ____/____  >____  >_______  /\___  >____  /___|  /
                \/    \/\/         \/     \/        \/     \/     \/     \/
^0]])
  print("^5=============================================^0")
  Wait(1000)
  print("(^4ZayssScanner^0): ^0Recherche de ^6Cipher^0 backdoors...")
  Wait(1000)
  print("(^4ZayssScanner^0): ^0Recherche de ^6Ketamin^0 backdoors...")
  Wait(1000)
  print("(^4ZayssScanner^0): ^0Recherche de ^6XOR obfuscated^0 backdoors...")
  Wait(1000)
  print("(^4ZayssScanner^0): ^0Recherche de ^6Cipher v2^0 backdoors (injectors, npm hooks, token theft)...")
  Wait(1000)
  print("(^4ZayssScanner^0): ^0Recherche de ^6remote execution^0 backdoors...")
  Wait(1000)
  print("(^4ZayssScanner^0): ^0Analyse des niveaux de menace...")
  Wait(1000)
  print("^5=============================================^0")

  startScan()
end)
