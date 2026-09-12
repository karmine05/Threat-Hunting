# ==============================================================================
#  deploy-sysmon.ps1 - Sysmon auto-packager for Windows (Fleet script)
#
#  Single-file Fleet script. Fleet uploads ONE .ps1 (no zip unpack), so this
#  script pulls its own payload at runtime:
#    - Sysmon binaries : Microsoft Sysinternals (official)
#                        https://download.sysinternals.com/files/Sysmon.zip
#    - Config XML      : public GitHub (source of truth)
#                        https://github.com/karmine05/Threat-Hunting
#                        raw: .../main/windows/sysmon/sysmonconfig.xml
#
#  Behavior
#  --------
#  1. If the Sysmon service is NOT installed  -> install with the provided config
#                                               (Sysmon -accepteula -i <config>)
#  2. If the Sysmon service exists but STOPPED -> start it; if it will not start,
#                                               uninstall and re-install.
#  3. If the Sysmon service is ALREADY RUNNING -> BACK OFF (no install, no
#     driver restart). ONLY THEN re-initialize with the provided config
#     (Sysmon -c <config>). If the active config hash already matches, do nothing.
#
#  Fleet
#  -----
#  Controls -> Scripts -> upload this file, scope to Windows, run elevated
#  (fleetd must be packaged with --enable-scripts). Idempotent. Exit 0/1.
#
#  Optional flags:
#      -ConfigUrl <url>     override GitHub config URL
#      -ForceReinstall      uninstall + reinstall even if already running
#      -SkipDownload        use only local SysmonDir / ConfigPath
# ==============================================================================

[CmdletBinding()]
param(
    [string]$SysmonDir = "",
    [string]$ConfigPath = "",
    [string]$ConfigUrl = "https://raw.githubusercontent.com/karmine05/Threat-Hunting/main/windows/sysmon/sysmonconfig.xml",
    [string]$SysmonZipUrl = "https://download.sysinternals.com/files/Sysmon.zip",
    [string]$LogFile = "",
    [switch]$ForceReinstall,
    [switch]$SkipDownload
)

$ErrorActionPreference = "Continue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = "SilentlyContinue"

# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------
$WorkRoot = Join-Path $env:ProgramData "jcode\sysmon"
if (-not $LogFile) { $LogFile = Join-Path $WorkRoot "sysmon-deploy.log" }
try {
    if (-not (Test-Path $WorkRoot)) { New-Item -ItemType Directory -Path $WorkRoot -Force | Out-Null }
} catch { }

function Write-Log {
    param(
        [ValidateSet("INFO", "SUCCESS", "WARN", "ERROR")][string]$Level = "INFO",
        [string]$Message
    )
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts [$Level] $Message"
    $color = switch ($Level) {
        "SUCCESS" { "Green" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        default   { "Cyan" }
    }
    Write-Host $line -ForegroundColor $color
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch { }
}

function Fail {
    param([string]$Message, [int]$ExitCode = 1)
    Write-Log "ERROR" $Message
    Write-Log "ERROR" "deploy-sysmon.ps1 finished with FAILURE. Exit code: $ExitCode"
    exit $ExitCode
}

function Get-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-LoggedProcess {
    param([string]$FilePath, [string[]]$ArgumentList)
    Write-Log "INFO" "  command: $FilePath $($ArgumentList -join ' ')"
    $out = & $FilePath @ArgumentList 2>&1
    $code = $LASTEXITCODE
    ($out | Out-String) -split "`r?`n" | ForEach-Object {
        if ($_ -match '\S') { Write-Log "INFO" "  sysmon> $_" }
    }
    return $code
}

function Get-FileSha256Lower {
    param([string]$Path)
    try { return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLower() } catch { return $null }
}

# ----------------------------------------------------------------------------
# Sysmon service helpers (name varies by arch: Sysmon / Sysmon64 / Sysmon64a)
# ----------------------------------------------------------------------------
function Get-SysmonService {
    foreach ($name in @("Sysmon64", "Sysmon64a", "Sysmon")) {
        $s = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($s) { return $s }
    }
    return $null
}

function Get-ServiceState {
    # Returns "absent" | "running" | "stopped"
    $s = Get-SysmonService
    if (-not $s) { return "absent" }
    if ($s.Status -eq "Running") { return "running" }
    return "stopped"
}

function Get-SysmonServiceName {
    $s = Get-SysmonService
    if ($s) { return $s.Name }
    return $null
}

function Find-SysmonBinary {
    param([string]$Dir)
    $arch = $env:PROCESSOR_ARCHITECTURE
    $candidates = switch ($arch) {
        "AMD64" { @("Sysmon64.exe", "Sysmon.exe") }
        "ARM64" { @("Sysmon64a.exe", "Sysmon64.exe", "Sysmon.exe") }
        "x86"   { @("Sysmon.exe") }
        default { @("Sysmon64.exe", "Sysmon64a.exe", "Sysmon.exe") }
    }
    foreach ($c in $candidates) {
        $p = Join-Path $Dir $c
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return $null
}

function Get-SysmonVersion {
    param([string]$Bin)
    try {
        $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Bin)
        if ($vi.FileVersion) { return $vi.FileVersion }
    } catch { }
    try {
        $out = & $Bin -? 2>&1 | Out-String
        if ($out -match '(\d+\.\d+\.\d+\.\d+)') { return $Matches[1] }
    } catch { }
    return "unknown"
}

function Test-MicrosoftSigned {
    param([string]$Path)
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        if ($sig.Status -ne "Valid") {
            Write-Log "WARN" "Authenticode status for $(Split-Path $Path -Leaf): $($sig.Status)"
            return $false
        }
        $signer = $sig.SignerCertificate.Subject
        if ($signer -notmatch 'Microsoft') {
            Write-Log "WARN" "Unexpected signer for $(Split-Path $Path -Leaf): $signer"
            return $false
        }
        Write-Log "INFO" "Authenticode OK: $(Split-Path $Path -Leaf) signed by $signer"
        return $true
    } catch {
        Write-Log "WARN" "Could not verify Authenticode for $Path : $($_.Exception.Message)"
        return $false
    }
}

function Get-RecentSysmonEvent {
    param([int]$EventId, [int]$MaxAgeMinutes = 60)
    try {
        $evts = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 80 -ErrorAction Stop
        $evts | Where-Object { $_.Id -eq $EventId -and $_.TimeCreated -gt (Get-Date).AddMinutes(-$MaxAgeMinutes) } |
            Select-Object -First 1
    } catch { return $null }
}

function Get-ActiveConfigHash {
    $svcName = Get-SysmonServiceName
    $paths = @()
    if ($svcName) { $paths += "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName\Parameters" }
    $paths += @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon64\Parameters",
        "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon64a\Parameters",
        "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon\Parameters",
        "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters"
    )
    foreach ($p in $paths) {
        try {
            $reg = Get-ItemProperty -Path $p -ErrorAction Stop
            if ($reg.ConfigHash) { return "$($reg.ConfigHash)".ToLower() }
        } catch { }
    }
    try {
        $ev = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" `
                           -FilterXPath "*[System[EventID=5012]]" -MaxEvents 1 -ErrorAction Stop
        foreach ($prop in $ev.Properties) {
            $val = "$($prop.Value)"
            if ($val -match '^[A-Fa-f0-9]{64}$') { return $val.ToLower() }
        }
    } catch { }
    return $null
}

function Test-SysmonWorking {
    $svc = Get-ServiceState
    if ($svc -ne "running") {
        Write-Log "ERROR" "Sysmon driver service is not running (state: $svc)"
        return $false
    }
    $drvCandidates = @(
        (Join-Path $env:SystemRoot "System32\drivers\SysmonDrv.sys"),
        (Join-Path $env:SystemRoot "System32\drivers\Sysmon64.sys")
    )
    $found = $false
    foreach ($drv in $drvCandidates) {
        if (Test-Path $drv) {
            Write-Log "INFO" "Driver file present: $drv"
            $found = $true
        }
    }
    if (-not $found) { Write-Log "WARN" "Sysmon driver file not found under System32\drivers (service is running; continuing)" }
    return $true
}

# ----------------------------------------------------------------------------
# Downloads
# ----------------------------------------------------------------------------
function Get-WebFile {
    param([string]$Url, [string]$OutFile, [int]$Attempts = 3)
    $dir = Split-Path $OutFile
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    for ($i = 1; $i -le $Attempts; $i++) {
        try {
            Write-Log "INFO" "Downloading (attempt $i/$Attempts): $Url"
            Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
            if ((Test-Path $OutFile) -and ((Get-Item $OutFile).Length -gt 0)) { return $true }
        } catch {
            Write-Log "WARN" "Download failed: $($_.Exception.Message)"
            Start-Sleep -Seconds (3 * $i)
        }
    }
    return $false
}

function Resolve-PayloadDir {
    $candidates = @()
    if ($SysmonDir) { $candidates += $SysmonDir }
    if ($PSScriptRoot) {
        $candidates += $PSScriptRoot
        $candidates += (Join-Path $PSScriptRoot "Sysmon")
    }
    $candidates += (Get-Location).Path
    $candidates += $WorkRoot
    foreach ($d in $candidates) {
        if ($d -and (Find-SysmonBinary -Dir $d)) { return $d }
    }
    return $null
}

function Install-SysmonPayload {
    # Ensure Sysmon binaries are on disk. Prefer a local payload (next to the
    # script / -SysmonDir). Otherwise pull the official Sysinternals zip.
    $existing = Resolve-PayloadDir
    if ($existing) {
        Write-Log "INFO" "Using local Sysmon payload: $existing"
        return $existing
    }
    if ($SkipDownload) { Fail "No local Sysmon binary found and -SkipDownload was set." }

    $zip = Join-Path $WorkRoot "Sysmon.zip"
    $extract = Join-Path $WorkRoot "bin"
    if (-not (Get-WebFile -Url $SysmonZipUrl -OutFile $zip)) {
        Fail "Could not download Sysmon from Microsoft: $SysmonZipUrl"
    }
    Write-Log "INFO" "Downloaded Sysmon.zip ($((Get-Item $zip).Length) bytes). SHA256=$(Get-FileSha256Lower $zip)"
    if (Test-Path $extract) { Remove-Item $extract -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $extract -Force | Out-Null
    try {
        Expand-Archive -Path $zip -DestinationPath $extract -Force
    } catch {
        Fail "Failed to extract Sysmon.zip: $($_.Exception.Message)"
    }
    $bin = Find-SysmonBinary -Dir $extract
    if (-not $bin) { Fail "Sysmon.zip extracted but no Sysmon*.exe was found in $extract" }
    if (-not (Test-MicrosoftSigned -Path $bin)) {
        Fail "Downloaded Sysmon binary is not validly signed by Microsoft. Aborting."
    }
    Write-Log "SUCCESS" "Sysmon payload ready: $bin"
    return $extract
}

function Resolve-ConfigFile {
    param([string]$PayloadDir)
    $dest = Join-Path $WorkRoot "sysmonconfig.xml"
    $tried = @()

    function Copy-IfValid([string]$Src) {
        if (-not (Test-Path -LiteralPath $Src)) { return $false }
        try {
            [xml]$xml = Get-Content -LiteralPath $Src -Raw -Encoding UTF8
            if (-not $xml.Sysmon) { return $false }
        } catch { return $false }
        Copy-Item -LiteralPath $Src -Destination $dest -Force
        return $true
    }

    if ($ConfigPath) {
        $tried += $ConfigPath
        if (Copy-IfValid $ConfigPath) { return $dest }
    }
    foreach ($c in @(
            (Join-Path $PayloadDir "sysmonconfig.xml"),
            $(if ($PSScriptRoot) { Join-Path $PSScriptRoot "sysmonconfig.xml" } else { $null }),
            $(if ($PSScriptRoot) { Join-Path $PSScriptRoot "Sysmon\sysmonconfig.xml" } else { $null })
        )) {
        if ($c) {
            $tried += $c
            if (Copy-IfValid $c) {
                Write-Log "INFO" "Using local config: $c"
                return $dest
            }
        }
    }

    if (-not $SkipDownload) {
        $tmp = Join-Path $WorkRoot "sysmonconfig.download.xml"
        if (Get-WebFile -Url $ConfigUrl -OutFile $tmp) {
            $tried += $ConfigUrl
            if (Copy-IfValid $tmp) {
                Write-Log "SUCCESS" "Fetched config from GitHub: $ConfigUrl"
                return $dest
            }
            Write-Log "WARN" "Downloaded config failed XML validation."
        }
    }

    Fail "Sysmon config not found. Tried: $($tried -join '; '). Expected GitHub URL $ConfigUrl"
}

function Assert-ConfigXml {
    param([string]$Path)
    try {
        [xml]$xml = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    } catch {
        Fail "Config XML is not well-formed: $($_.Exception.Message)"
    }
    if (-not $xml.Sysmon) { Fail "Config XML is missing a <Sysmon> root element: $Path" }
    $schema = $null
    try { $schema = $xml.Sysmon.GetAttribute("schemaversion") } catch { }
    Write-Log "INFO" "Config XML is well-formed: $Path (schemaVersion=$schema)"
    return $schema
}

function Get-LastAppliedHashPath { Join-Path $WorkRoot "last-config.sha256" }

function Read-LastAppliedHash {
    $p = Get-LastAppliedHashPath
    if (Test-Path $p) {
        try { return ((Get-Content -LiteralPath $p -Raw).Trim().ToLower()) } catch { }
    }
    return $null
}

function Write-LastAppliedHash {
    param([string]$Hash)
    try { Set-Content -LiteralPath (Get-LastAppliedHashPath) -Value $Hash -Encoding ASCII } catch { }
}

function Invoke-ConfigReinit {
    param([string]$Bin, [string]$Cfg, [string]$OurHash)
    $lastHash = Read-LastAppliedHash
    if ($lastHash) { Write-Log "INFO" "Last applied config hash (local): $lastHash" }
    $activeHash = Get-ActiveConfigHash
    if ($activeHash) {
        Write-Log "INFO" "Active config hash (registry/event): $activeHash"
    } else {
        Write-Log "WARN" "Could not read the active config hash (registry + event log)."
    }
    $already = $false
    if ($OurHash) {
        if ($lastHash -and ($lastHash -eq $OurHash)) { $already = $true }
        if ($activeHash -and ($activeHash -eq $OurHash)) { $already = $true }
    }
    if ($already) {
        Write-Log "SUCCESS" "Backed off: Sysmon is running and the provided config is already active. Nothing to do."
        Write-LastAppliedHash $OurHash
        return "same"
    }

    Write-Log "INFO" "Re-initializing Sysmon with the provided config (live reconfigure, no reinstall)..."
    $code = Invoke-LoggedProcess -FilePath $Bin -ArgumentList @("-c", $Cfg)
    if ($code -eq 0) {
        Write-LastAppliedHash $OurHash
        return "reinit"
    }

    Write-Log "WARN" "Live reconfigure failed (exit $code). Trying stop -> reconfigure -> start..."
    $svcName = Get-SysmonServiceName
    if ($svcName) {
        try { Stop-Service -Name $svcName -Force -ErrorAction Stop } catch {
            Write-Log "WARN" "Stop-Service failed: $($_.Exception.Message)"
        }
        Start-Sleep -Seconds 3
    }
    $code = Invoke-LoggedProcess -FilePath $Bin -ArgumentList @("-c", $Cfg)
    if ($code -ne 0) { return "failed" }
    if ($svcName) {
        try { Start-Service -Name $svcName -ErrorAction Stop } catch {
            Write-Log "WARN" "Start-Service failed: $($_.Exception.Message)"
        }
        Start-Sleep -Seconds 3
    }
    if ((Get-ServiceState) -ne "running") { return "failed" }
    Write-LastAppliedHash $OurHash
    return "restart"
}

function Uninstall-Sysmon {
    param([string]$Bin)
    Write-Log "WARN" "Uninstalling existing Sysmon..."
    [void](Invoke-LoggedProcess -FilePath $Bin -ArgumentList @("-u", "force"))
    Start-Sleep -Seconds 3
    if ((Get-ServiceState) -ne "absent") {
        foreach ($name in @("Sysmon64", "Sysmon64a", "Sysmon")) {
            & sc.exe delete $name 2>&1 | Out-Null
        }
        Start-Sleep -Seconds 2
    }
}

function Install-SysmonFresh {
    param([string]$Bin, [string]$Cfg)
    # Correct Sysinternals syntax: -i takes the config path. Do NOT pass -c here.
    $code = Invoke-LoggedProcess -FilePath $Bin -ArgumentList @("-accepteula", "-i", $Cfg)
    if ($code -ne 0) { Fail "Sysmon install failed (exit $code)." }
    Start-Sleep -Seconds 5
    if (-not (Test-SysmonWorking)) { Fail "Sysmon install reported success but post-install verification failed." }
    Write-LastAppliedHash (Get-FileSha256Lower $Cfg)
    Write-Log "SUCCESS" "Sysmon installed and running."
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
$START = Get-Date
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Sysmon auto-packager - deploy and configure (Fleet script)     " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

Write-Log "INFO" "Host: $env:COMPUTERNAME | OS arch: $env:PROCESSOR_ARCHITECTURE | User: $env:USERNAME"
Write-Log "INFO" "Config source of truth: $ConfigUrl"
Write-Log "INFO" "Log: $LogFile"

if (-not (Get-IsAdmin)) {
    Fail "Administrator rights are required to install/configure the Sysmon driver. Make sure Fleet is running this script elevated."
}

$payloadDir = Install-SysmonPayload
$ConfigPath = Resolve-ConfigFile -PayloadDir $payloadDir
$schemaVer  = Assert-ConfigXml -Path $ConfigPath

$sysmonBin = Find-SysmonBinary -Dir $payloadDir
if (-not $sysmonBin) { Fail "No Sysmon binary found in $payloadDir" }
Write-Log "INFO" "Using Sysmon binary: $sysmonBin (version $(Get-SysmonVersion -Bin $sysmonBin))"

$ourHash = Get-FileSha256Lower $ConfigPath
Write-Log "INFO" "Provided config SHA256: $ourHash"

$svcState = Get-ServiceState
$svcName  = Get-SysmonServiceName
Write-Log "INFO" "Sysmon driver service state: $svcState$(if ($svcName) { " ($svcName)" })"

if ($ForceReinstall -and $svcState -ne "absent") {
    Write-Log "WARN" "-ForceReinstall set. Uninstalling before a clean install."
    Uninstall-Sysmon -Bin $sysmonBin
    $svcState = Get-ServiceState
}

# PATH 1: service absent -> fresh install with config
if ($svcState -eq "absent") {
    Write-Log "INFO" "Sysmon is not installed. Installing with the provided config..."
    Install-SysmonFresh -Bin $sysmonBin -Cfg $ConfigPath
}

# PATH 2: service stopped (or broken) -> try to start, else reinstall
elseif ($svcState -eq "stopped") {
    Write-Log "INFO" "Sysmon service exists but is not running. Attempting to start it..."
    $name = Get-SysmonServiceName
    try {
        Start-Service -Name $name -ErrorAction Stop
        Start-Sleep -Seconds 3
    } catch {
        Write-Log "WARN" "Could not start existing Sysmon service: $($_.Exception.Message)"
    }

    if ((Get-ServiceState) -eq "running") {
        Write-Log "INFO" "Existing Sysmon service started. Re-initializing config..."
        $reinit = Invoke-ConfigReinit -Bin $sysmonBin -Cfg $ConfigPath -OurHash $ourHash
        if ($reinit -eq "failed") { Fail "Re-initializing the Sysmon config failed after starting the service." }
    } else {
        Write-Log "WARN" "Existing Sysmon install appears broken. Uninstalling and reinstalling..."
        Uninstall-Sysmon -Bin $sysmonBin
        Install-SysmonFresh -Bin $sysmonBin -Cfg $ConfigPath
    }
}

# PATH 3: service RUNNING -> BACK OFF (no install), then re-init config only
elseif ($svcState -eq "running") {
    Write-Log "INFO" "Sysmon service is ALREADY RUNNING. Backing off: no install, no driver restart."
    Write-Log "INFO" "Re-initializing with the provided config (idempotent: skipped if already active)..."

    $reinit = Invoke-ConfigReinit -Bin $sysmonBin -Cfg $ConfigPath -OurHash $ourHash
    if ($reinit -eq "failed") { Fail "Re-initializing the Sysmon config failed." }
    switch ($reinit) {
        "same"    { Write-Log "SUCCESS" "Sysmon running with the provided config already active - nothing changed." }
        "reinit"  {
            if ((Get-ServiceState) -ne "running") { Fail "Sysmon service is not running after re-initialization." }
            Write-Log "SUCCESS" "Sysmon re-initialized with the provided config (live reconfigure, no restart)."
        }
        "restart" { Write-Log "SUCCESS" "Sysmon re-initialized with the provided config (required a stop/start cycle)." }
    }
}

# Final verification (audit)
Start-Sleep -Seconds 3
if (-not (Test-SysmonWorking)) { Fail "Sysmon is not running after deploy." }

$ev5012 = Get-RecentSysmonEvent -EventId 16
if (-not $ev5012) { $ev5012 = Get-RecentSysmonEvent -EventId 5012 }
$ev5000 = Get-RecentSysmonEvent -EventId 4
if (-not $ev5000) { $ev5000 = Get-RecentSysmonEvent -EventId 5000 }
if ($ev5012) {
    Write-Log "INFO" "Verified: recent Sysmon config-change event present."
} elseif ($ev5000) {
    Write-Log "INFO" "Verified: recent Sysmon service event present."
} else {
    Write-Log "WARN" "No recent Sysmon config/service events found in the last 60 minutes (audit only)."
}

$elapsed = (Get-Date) - $START
Write-Host ""
Write-Log "SUCCESS" "deploy-sysmon.ps1 finished OK in $([int]$elapsed.TotalSeconds)s. Service state: $(Get-ServiceState). Log: $LogFile"
exit 0
