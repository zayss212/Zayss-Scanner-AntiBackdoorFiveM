ZayssScanner = {}

ZayssScanner.StopServer = false
ZayssScanner.IgnoreResources = {}

ZayssScanner.ScanOptions = {
    ScanServerScripts = true,
    ScanClientScripts = true,
    ScanUIPages = true,
    ScanHTMLFiles = true,
    ScanJSFiles = true,
    DeepScan = true
}

ZayssScanner.AutoScan = {
    Enabled = false,
    Interval = 3600000,
}

ZayssScanner.AdvancedDetection = {
    DetectObfuscation = true,
    DetectXOREncryption = true,
    DetectBase64 = true,
    DetectRemoteExecution = true,
    DetectEval = true,
    DetectSuspiciousAPIs = true,
    MinObfuscationScore = 30
}

ZayssScanner.Whitelist = {
    Hashes = {},
    Patterns = {}
}

ZayssScanner.CustomSignatures = {}

return ZayssScanner
