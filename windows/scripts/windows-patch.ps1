# ==============================================================================
#  windows-patch.ps1 - Windows auto-patcher (Fleet script)
#
#  What it does
#  ------------
#  1. Notifies the logged-on user that Microsoft updates are about to install
#     quietly, then PULLS + INSTALLS the latest Windows / Microsoft updates
#     from Microsoft's official sources (Windows Update / Microsoft Update).
#  2. Updates third-party software via Chocolatey and winget.
#  3. If a reboot is required: host notification (pop-up + event log) then a
#     FORCED restart after a short grace period (shutdown /r /f /t:<grace>).
#
#  Fleet
#  -----
#  Controls -> Scripts -> upload this .ps1, scope to Windows.
#  fleetd must be packaged with --enable-scripts. Runs elevated as SYSTEM.
#  Fleet's default script_execution_timeout is 300s (max 18000). Windows
#  Update cannot finish in 5 minutes, so when this script is launched as
#  SYSTEM (Fleet) it notifies the user, then hands off to a one-shot
#  scheduled task and returns 0 so Fleet does not kill the install.
#
#  Flags:
#      -NoRestart            report reboot needed, do not force it
#      -RestartTimeout 180   grace seconds before forced restart
#      -SkipWindowsUpdate    skip the Microsoft update pass
#      -SkipThirdParty       skip chocolatey / winget
#      -NoNotify             log-only (no pop-up)
#      -InTask               internal: already running as the scheduled task
# ==============================================================================

[CmdletBinding()]
param(
    [switch]$NoRestart,
    [int]$RestartTimeout = 180,
    [switch]$SkipWindowsUpdate,
    [switch]$SkipThirdParty,
    [switch]$NoNotify,
    [switch]$InTask,
    [string]$LogFile = ""
)

$ErrorActionPreference = "Continue"
$ProgressPreference    = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# WUApiLib OperationResultCode: 0=NotStarted 1=InProgress 2=Succeeded
# 3=SucceededWithErrors 4=Failed 5=Aborted
$script:ORC_SUCCEEDED             = 2
$script:ORC_SUCCEEDED_WITH_ERRORS = 3
$script:MICROSOFT_UPDATE_SID      = "7971f918-a847-4430-9279-4a52d1efe18d"

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
$isSystemAccount = ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq "S-1-5-18")

if (-not $LogFile) { $LogFile = "$env:ProgramData\jcode\windows-patch-$(Get-Date -Format 'yyyyMMdd').log" }
try {
    $logDir = Split-Path $LogFile
    if ($logDir -and -not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
} catch { }

function Write-Log {
    param([ValidateSet("INFO","SUCCESS","WARN","ERROR")][string]$Level = "INFO", [string]$Message)
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

function Get-InteractiveUser {
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($cs.UserName) { return $cs.UserName }
    } catch { }
    return $null
}

function Initialize-EventSource {
    $src = "JcodeAutoPatch"
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($src)) {
            New-EventLog -LogName Application -Source $src -ErrorAction SilentlyContinue
        }
        return $src
    } catch { return $src }
}

$EVENT_SOURCE = Initialize-EventSource

function Send-UserNotification {
    param(
        [string]$Title,
        [string]$Message,
        [int]$TimeoutSec = 45,
        [int]$EventId = 1000
    )
    $flat = "$Title - $Message"
    Write-Log "INFO" "NOTIFY: $flat"

    if ($EVENT_SOURCE) {
        try {
            Write-EventLog -LogName Application -Source $EVENT_SOURCE -EventId $EventId `
                -EntryType Information -Message $flat -ErrorAction SilentlyContinue
        } catch { }
    }
    if ($NoNotify) { return }

    $user = Get-InteractiveUser
    if (-not $user) {
        Write-Log "WARN" "No interactive user session; skipping pop-up notification."
        return
    }
    try {
        $msg = Get-Command msg.exe -ErrorAction Stop
        # msg.exe delivers a host pop-up even when this script runs as SYSTEM.
        & $msg.Source * /TIME:$TimeoutSec "$flat" 2>&1 | Out-Null
    } catch {
        Write-Log "WARN" "Failed to deliver pop-up notification: $($_.Exception.Message)"
    }
}

function Test-RebootRequired {
    $sentinels = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting"
    )
    foreach ($s in $sentinels) {
        try { if (Test-Path $s) { return $true } } catch { }
    }
    try {
        $pfn = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
                                -Name PendingFileRenameOperations -ErrorAction Stop
        if ($pfn.PendingFileRenameOperations) { return $true }
    } catch { }
    return $false
}

function Test-ResultOk {
    param([int]$Code)
    return ($Code -eq $script:ORC_SUCCEEDED -or $Code -eq $script:ORC_SUCCEEDED_WITH_ERRORS)
}

$START_TIME      = Get-Date
$FAILURES        = @()
$VERSION_CHANGES = @{}
$REBOOT_REQUIRED = $false
$UPDATES_APPLIED = 0

# ----------------------------------------------------------------------------
# 1) Windows Update from Microsoft official sources
# ----------------------------------------------------------------------------
function Register-MicrosoftUpdateService {
    try {
        $mgr = New-Object -ComObject Microsoft.Update.ServiceManager
        $mgr.ClientApplicationID = "Jcode Windows Patcher"
        $registered = $false
        foreach ($svc in $mgr.Services) {
            if ($svc.ServiceID -eq $script:MICROSOFT_UPDATE_SID) { $registered = $true; break }
        }
        if (-not $registered) {
            Write-Log "INFO" "Registering Microsoft Update service (official catalog, includes Office/other Microsoft products)..."
            [void]$mgr.AddService2($script:MICROSOFT_UPDATE_SID, 7, "")
        } else {
            Write-Log "INFO" "Microsoft Update service already registered."
        }
        return $true
    } catch {
        Write-Log "WARN" "Could not register Microsoft Update service: $($_.Exception.Message)"
        return $false
    }
}

function Get-WsusHint {
    try {
        $p = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction Stop
        if ($p.WUServer) {
            Write-Log "WARN" "WSUS/internal update server is configured by policy: $($p.WUServer). This script still targets Microsoft's official Windows Update / Microsoft Update catalog."
        }
    } catch { }
}

function Install-WindowsUpdates {
    Write-Log "INFO" "=== [1/3] Windows Update (Microsoft official sources) ==="

    if (-not $isAdmin) {
        Write-Log "WARN" "Not running as Administrator. Windows Update requires elevation; skipping."
        $script:FAILURES += "Windows Update (requires admin)"
        return
    }

    Get-WsusHint
    if (-not $InTask) {
        Send-UserNotification -Title "Windows Update" `
            -Message "Starting to install the latest Microsoft updates quietly. This may take several minutes. Please save your work." `
            -TimeoutSec 45 -EventId 1001
    }

    $muOk = Register-MicrosoftUpdateService

    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $session.ClientApplicationID = "Jcode Windows Patcher"
        $searcher = $session.CreateUpdateSearcher()

        if ($muOk) {
            try {
                $searcher.ServerSelection = 3  # ssOthers + ServiceID = Microsoft Update
                $searcher.ServiceID = $script:MICROSOFT_UPDATE_SID
            } catch {
                Write-Log "WARN" "Could not pin Microsoft Update ServiceID; falling back to Windows Update (ssWindowsUpdate=2)."
                $searcher.ServerSelection = 2
            }
        } else {
            $searcher.ServerSelection = 2  # Windows Update (Microsoft official)
        }

        $criteria = "IsInstalled=0 AND Type='Software' AND IsHidden=0"
        $searchResult = $null
        for ($attempt = 1; $attempt -le 2; $attempt++) {
            Write-Log "INFO" "Searching Microsoft official catalog ($criteria) - attempt $attempt..."
            $searchResult = $searcher.Search($criteria)
            if ($searchResult.Updates.Count -gt 0) { break }
            if ($attempt -eq 1) { Start-Sleep -Seconds 5 }
        }

        $count = $searchResult.Updates.Count
        if ($count -eq 0) {
            Write-Log "SUCCESS" "No Windows updates available. System is up to date."
            if (Test-RebootRequired) { $script:REBOOT_REQUIRED = $true }
            return
        }

        Write-Log "INFO" "Found $count update(s):"
        $coll = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($u in $searchResult.Updates) {
            $kb = ""
            try { if ($u.KBArticleIDs -and $u.KBArticleIDs.Count -gt 0) { $kb = "KB$($u.KBArticleIDs.Item(0))" } } catch { }
            Write-Log "INFO" "  - $($u.Title) $kb"
            try { if (-not $u.EulaAccepted) { $u.AcceptEula() } } catch { }
            $needsInput = $false
            try { if ($u.InstallationBehavior -and $u.InstallationBehavior.CanRequestUserInput) { $needsInput = $true } } catch { }
            if ($needsInput) {
                Write-Log "WARN" "Skipping update that may prompt the user: $($u.Title)"
                continue
            }
            [void]$coll.Add($u)
        }
        if ($coll.Count -eq 0) {
            Write-Log "INFO" "No quiet-installable updates remained after filtering."
            if (Test-RebootRequired) { $script:REBOOT_REQUIRED = $true }
            return
        }

        Write-Log "INFO" "Downloading updates from Microsoft..."
        $downloader = $session.CreateUpdateDownloader()
        $downloader.Updates = $coll
        $dl = $downloader.Download()
        if (Test-ResultOk $dl.ResultCode) {
            Write-Log "INFO" "Download complete (result $($dl.ResultCode))."
        } else {
            Write-Log "WARN" "Download result code $($dl.ResultCode); attempting to install what is ready."
        }

        $ready = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($u in $coll) {
            if ($u.IsDownloaded) { [void]$ready.Add($u) }
        }
        if ($ready.Count -eq 0) {
            Write-Log "WARN" "No updates were downloaded; skipping install."
            $script:FAILURES += "Windows Update (download)"
            return
        }

        Write-Log "INFO" "Installing $($ready.Count) update(s) quietly..."
        $installer = $session.CreateUpdateInstaller()
        $installer.Updates = $ready
        try { $installer.ForceQuiet = $true } catch { }
        $res = $installer.Install()

        $script:UPDATES_APPLIED += $ready.Count
        Write-Log "INFO" "Install result code: $($res.ResultCode) (2=Succeeded, 3=SucceededWithErrors)"
        if ($res.RebootRequired) {
            $script:REBOOT_REQUIRED = $true
            Write-Log "WARN" "Windows Update reports a reboot is required."
        }
        if (Test-ResultOk $res.ResultCode) {
            Write-Log "SUCCESS" "Windows updates installed: $($ready.Count) applied."
        } else {
            $script:FAILURES += "Windows Update (install result code $($res.ResultCode))"
            Write-Log "WARN" "Windows Update install did not complete cleanly (result code $($res.ResultCode))."
        }
    }
    catch {
        Write-Log "WARN" "Windows Update COM API failed: $($_.Exception.Message)"
        Write-Log "INFO" "Falling back to USOClient ScanInstallWait (blocks until scan/download/install finish)..."
        try {
            $uso = Get-Command USOClient.exe -ErrorAction Stop
            Start-Process -FilePath $uso.Source -ArgumentList "ScanInstallWait" -Wait -NoNewWindow -ErrorAction Stop | Out-Null
            Start-Sleep -Seconds 5
            Write-Log "INFO" "USOClient ScanInstallWait completed."
        } catch {
            Write-Log "WARN" "USOClient ScanInstallWait failed: $($_.Exception.Message)"
            $script:FAILURES += "Windows Update (USOClient fallback failed)"
        }
    }

    if (Test-RebootRequired) {
        $script:REBOOT_REQUIRED = $true
        Write-Log "WARN" "Registry sentinel indicates a reboot is pending."
    }
}

# ----------------------------------------------------------------------------
# 2a) Chocolatey
# ----------------------------------------------------------------------------
function Get-ChocoExe {
    $cmd = Get-Command choco -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $p = "$env:ProgramData\chocolatey\bin\choco.exe"
    if (Test-Path $p) { return $p }
    return $null
}

function Update-Chocolatey {
    Write-Log "INFO" "=== [2/3] Chocolatey (third-party packages) ==="
    $choco = Get-ChocoExe
    if (-not $choco) {
        Write-Log "INFO" "Chocolatey not installed. Installing from chocolatey.org..."
        try {
            $tmp = "$env:TEMP\choco-install.ps1"
            Invoke-WebRequest -Uri "https://community.chocolatey.org/install.ps1" -OutFile $tmp -UseBasicParsing -ErrorAction Stop
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $tmp 2>&1 | Out-File -FilePath $LogFile -Append
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            Start-Sleep -Seconds 5
            $choco = Get-ChocoExe
            if (-not $choco) {
                Write-Log "WARN" "Chocolatey still not found after install attempt."
                $script:FAILURES += "Chocolatey install"
                return
            }
            Write-Log "SUCCESS" "Chocolatey installed."
        } catch {
            Write-Log "WARN" "Could not install Chocolatey: $($_.Exception.Message)"
            $script:FAILURES += "Chocolatey install"
            return
        }
    }

    try {
        $v0 = (& $choco --version 2>&1)
        & $choco upgrade chocolatey -y --no-progress --timeout 3600 2>&1 | Out-File -FilePath $LogFile -Append
        $v1 = (& $choco --version 2>&1)
        if ($v0 -and $v1 -and "$v0" -ne "$v1") { $script:VERSION_CHANGES["chocolatey"] = "$v0 -> $v1" }
        Write-Log "SUCCESS" "Chocolatey updated ($v1)."
    } catch {
        Write-Log "WARN" "Failed to update Chocolatey itself: $($_.Exception.Message)"
    }

    try {
        Write-Log "INFO" "Upgrading all Chocolatey packages..."
        & $choco upgrade all -y --no-progress --timeout 3600 2>&1 | Out-File -FilePath $LogFile -Append
        $code = $LASTEXITCODE
        # 0=ok, 1=reboot required (choco convention)
        if ($code -in 0, 1, $null) {
            Write-Log "SUCCESS" "Chocolatey packages upgraded (exit $code)."
        } else {
            Write-Log "WARN" "Chocolatey upgrade exit code $code (some packages may have failed)."
            $script:FAILURES += "Chocolatey upgrade (partial, exit $code)"
        }
        if ($code -eq 1) { $script:REBOOT_REQUIRED = $true }
    } catch {
        Write-Log "WARN" "Chocolatey upgrade failed: $($_.Exception.Message)"
        $script:FAILURES += "Chocolatey upgrade"
    }
    try { & $choco cache clean -y 2>&1 | Out-Null } catch { }
}

# ----------------------------------------------------------------------------
# 2b) winget
# ----------------------------------------------------------------------------
function Get-WingetExe {
    $cmd = Get-Command winget -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $apps = Join-Path $env:ProgramFiles "WindowsApps"
    if (Test-Path $apps) {
        $found = Get-ChildItem -Path $apps -Filter winget.exe -Recurse -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    return $null
}

function Update-Winget {
    Write-Log "INFO" "=== [2/3] winget (third-party packages) ==="
    $winget = Get-WingetExe
    if (-not $winget) {
        Write-Log "WARN" "winget not found; skipping winget updates. Chocolatey covers system-wide packages."
        return
    }
    Write-Log "INFO" "Using winget: $winget"
    if ($isSystemAccount) {
        Write-Log "INFO" "Running as SYSTEM. Using machine-scope winget where supported."
    }

    try {
        & $winget source update --disable-interactivity 2>&1 | Out-File -FilePath $LogFile -Append
    } catch {
        Write-Log "WARN" "winget source update failed: $($_.Exception.Message)"
    }

    $wingetArgs = @(
        "upgrade", "--all",
        "--accept-package-agreements", "--accept-source-agreements",
        "--disable-interactivity", "--silent"
    )
    if ($isSystemAccount) { $wingetArgs += @("--scope", "machine") }

    try {
        Write-Log "INFO" "Upgrading all winget packages..."
        & $winget @wingetArgs 2>&1 | Out-File -FilePath $LogFile -Append
        $code = $LASTEXITCODE
        # 0=ok, -1978335189 / 0x8A15002B = no applicable update
        if ($code -in 0, -1978335189, $null) {
            Write-Log "SUCCESS" "winget packages upgraded (exit $code)."
        } else {
            Write-Log "WARN" "winget upgrade exit code $code (some packages may have failed)."
        }
    } catch {
        Write-Log "WARN" "winget upgrade failed: $($_.Exception.Message)"
        $script:FAILURES += "winget upgrade"
    }

    if (Test-RebootRequired) { $script:REBOOT_REQUIRED = $true }
}

# ----------------------------------------------------------------------------
# 3) Reboot handling (forced restart with host notification)
# ----------------------------------------------------------------------------
function Invoke-RebootHandling {
    Write-Log "INFO" "=== [3/3] Reboot handling ==="
    if (-not $script:REBOOT_REQUIRED) {
        Write-Log "INFO" "No reboot required."
        return
    }
    if ($NoRestart) {
        Write-Log "WARN" "Reboot is required but -NoRestart was specified. NOT rebooting."
        Send-UserNotification -Title "Windows Update - Reboot needed" `
            -Message "Updates were installed. A restart is required to finish. Restart was not forced." `
            -TimeoutSec 60 -EventId 1002
        return
    }
    if (-not $isAdmin) {
        Write-Log "WARN" "Reboot required but not elevated; cannot force restart."
        return
    }

    $msg = "Updates were installed. This computer will be RESTARTED in $RestartTimeout seconds to complete the updates. Please save your work."
    Send-UserNotification -Title "Windows Update - Reboot" -Message $msg -TimeoutSec $RestartTimeout -EventId 1003
    Write-Log "WARN" "Forced restart in ${RestartTimeout}s (shutdown /r /f /t:$RestartTimeout)."
    try {
        $shutdown = Get-Command shutdown.exe -ErrorAction Stop
        & $shutdown.Source /r /f /t $RestartTimeout /c "Jcode auto-patch: reboot required to finish Microsoft updates."
        Write-Log "WARN" "Reboot scheduled."
    } catch {
        Write-Log "ERROR" "Failed to trigger reboot: $($_.Exception.Message)"
        $script:FAILURES += "Reboot (could not trigger)"
    }
}

function Write-Summary {
    $dur = (Get-Date) - $START_TIME
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "                 ** UPDATE SUMMARY **                       " -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ("Duration                 : {0}m {1}s" -f [int]$dur.TotalMinutes, $dur.Seconds)
    Write-Host "Log file                 : $LogFile"
    Write-Host "Windows updates applied  : $UPDATES_APPLIED"
    if ($VERSION_CHANGES.Count -gt 0) {
        Write-Host "VERSIONS UPDATED:" -ForegroundColor Green
        foreach ($k in $VERSION_CHANGES.Keys) { Write-Host "  [OK] $k : $($VERSION_CHANGES[$k])" -ForegroundColor Green }
    }
    if ($FAILURES.Count -gt 0) {
        Write-Host "FAILURES:" -ForegroundColor Red
        foreach ($f in $FAILURES) { Write-Host "  [!!] $f" -ForegroundColor Yellow }
    }
    if ($REBOOT_REQUIRED) {
        if ($NoRestart) {
            Write-Host "REBOOT: required - NOT performed (-NoRestart)" -ForegroundColor Yellow
        } else {
            Write-Host "REBOOT: forced restart was issued to the host" -ForegroundColor Yellow
        }
    }
    if ($FAILURES.Count -eq 0) {
        Write-Host "ALL UPDATES COMPLETED SUCCESSFULLY." -ForegroundColor Green
    } else {
        Write-Host "SOME UPDATES FAILED - see log for details." -ForegroundColor Yellow
    }
    Write-Host ""
}

# ==============================================================================
# Main
# ==============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "                ** Windows Auto-Patcher **                  " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Log "INFO" "Started. Host=$env:COMPUTERNAME Admin=$isAdmin SystemAccount=$isSystemAccount Notify=$(-not $NoNotify)"
Write-Log "INFO" "Log file: $LogFile"
if (-not $isAdmin) {
    Write-Log "WARN" "Not running elevated: Windows Update and forced reboot will be skipped."
}

function Get-SelfScriptPath {
    if ($PSCommandPath) { return $PSCommandPath }
    if ($MyInvocation.MyCommand.Path) { return $MyInvocation.MyCommand.Path }
    return $null
}

function Start-DetachedPatchJob {
    $persistDir = "$env:ProgramData\jcode"
    if (-not (Test-Path $persistDir)) { New-Item -ItemType Directory -Path $persistDir -Force | Out-Null }
    $persistScript = Join-Path $persistDir "windows-patch.ps1"
    $src = Get-SelfScriptPath
    if (-not $src -or -not (Test-Path -LiteralPath $src)) {
        Write-Log "WARN" "Cannot locate this script on disk; running inline (Fleet 5-minute timeout may kill a long update)."
        return $false
    }
    Copy-Item -LiteralPath $src -Destination $persistScript -Force

    $argParts = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", "`"$persistScript`"",
        "-InTask",
        "-RestartTimeout", "$RestartTimeout"
    )
    if ($NoRestart)         { $argParts += "-NoRestart" }
    if ($SkipWindowsUpdate) { $argParts += "-SkipWindowsUpdate" }
    if ($SkipThirdParty)    { $argParts += "-SkipThirdParty" }
    if ($NoNotify)          { $argParts += "-NoNotify" }
    if ($LogFile)           { $argParts += @("-LogFile", "`"$LogFile`"") }

    $taskName = "JcodeWindowsPatch"
    try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue } catch { }

    $action    = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ($argParts -join " ")
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $trigger   = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddSeconds(15))
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
                    -ExecutionTimeLimit (New-TimeSpan -Hours 4)
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Trigger $trigger `
        -Settings $settings -Force | Out-Null
    try { Start-ScheduledTask -TaskName $taskName -ErrorAction Stop } catch {
        Write-Log "WARN" "Start-ScheduledTask failed (trigger still set for ~15s): $($_.Exception.Message)"
    }
    Write-Log "SUCCESS" "Scheduled SYSTEM task '$taskName' (survives Fleet's default 5-minute script timeout)."
    Write-Log "INFO" "Follow progress in $LogFile"
    return $true
}

# Fleet (SYSTEM) hand-off: notify the user now, then return so fleetd does not kill the install.
if (-not $InTask -and $isSystemAccount -and $isAdmin) {
    if (-not $SkipWindowsUpdate) {
        Send-UserNotification -Title "Windows Update" `
            -Message "Starting to install the latest Microsoft updates quietly. This may take several minutes. Please save your work." `
            -TimeoutSec 45 -EventId 1001
    }
    if (Start-DetachedPatchJob) { exit 0 }
    Write-Log "WARN" "Scheduled-task hand-off failed; continuing inline."
}

if (-not $SkipWindowsUpdate) { Install-WindowsUpdates; Write-Host "" }
if (-not $SkipThirdParty) {
    Update-Chocolatey; Write-Host ""
    Update-Winget;     Write-Host ""
}

Invoke-RebootHandling
Write-Summary
exit 0
