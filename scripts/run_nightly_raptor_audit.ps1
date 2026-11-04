# Nightly RAPTOR SAST + Post-Quantum Crypto + SCA security audit for QuorumRAG
# (same model as OshoosiClaw/scripts/run_nightly_raptor_audit.ps1).
#   -InstallScheduledTask  registers the per-user Windows Scheduled Task (daily 03:30, staggered
#                          one hour after the OsoosiEDR audit so the two Docker scans never overlap).
# The GitHub Actions workflow .github/workflows/raptor-security.yml also runs nightly (cron 02:30 UTC)
# and on every pull request.
param(
    [switch]$InstallScheduledTask = $false,
    [string]$TaskName = "QuorumRAG-Nightly-Raptor-Security-Audit",
    [string]$At = "03:30AM"
)
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ScriptSelf = $MyInvocation.MyCommand.Path

if ($InstallScheduledTask) {
    $Action = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptSelf`"" `
        -WorkingDirectory $RepoRoot
    $Trigger = New-ScheduledTaskTrigger -Daily -At $At
    $Settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Hours 2)
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $Action `
        -Trigger $Trigger `
        -Settings $Settings `
        -Description "Nightly RAPTOR SAST, Post-Quantum Crypto, and SCA Security Audit for QuorumRAG" `
        -Force | Out-Null
    Write-Host "[+] Registered Windows Scheduled Task '$TaskName' (daily at $At)." -ForegroundColor Green
    exit 0
}

Set-Location $RepoRoot
$LogDir = Join-Path $RepoRoot "logs"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = Join-Path $LogDir "nightly_raptor_audit_${Timestamp}.log"
"[$(Get-Date -Format 'o')] Starting nightly RAPTOR security audit for $RepoRoot" | Out-File -FilePath $LogFile -Encoding utf8

# 1. Local Docker RAPTOR, every suite
$LocalRaptor = "D:\docker\raptor\Invoke-RaptorScan.ps1"
if (Test-Path $LocalRaptor) {
    try {
        & powershell -NoProfile -ExecutionPolicy Bypass -File $LocalRaptor -TargetPath $RepoRoot -Mode all *>> $LogFile
        "[$(Get-Date -Format 'o')] Local RAPTOR exit code: $LASTEXITCODE" | Out-File -FilePath $LogFile -Append -Encoding utf8
    } catch {
        "[$(Get-Date -Format 'o')] Local Docker RAPTOR error: $($_.Exception.Message)" | Out-File -FilePath $LogFile -Append -Encoding utf8
    }
} else {
    "[$(Get-Date -Format 'o')] Local RAPTOR helper not found at $LocalRaptor" | Out-File -FilePath $LogFile -Append -Encoding utf8
}

# 2. Dispatch the GitHub Actions RAPTOR workflow on main (REST API with the git credential helper)
$gitExe = "C:\Program Files\Git\cmd\git.exe"
$pythonExe = if (Test-Path "C:\Python314\python.exe") { "C:\Python314\python.exe" } else { "python" }
$dispatch = @'
import json, subprocess, sys, urllib.request
git_exe = sys.argv[1]
p = subprocess.Popen([git_exe, "credential", "fill"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8")
out, _ = p.communicate("protocol=https\nhost=github.com\n\n")
token = dict(l.split("=", 1) for l in out.splitlines() if "=" in l).get("password", "")
req = urllib.request.Request(
    "https://api.github.com/repos/oyesanyf/QuorumRAG/actions/workflows/raptor-security.yml/dispatches",
    data=json.dumps({"ref": "main"}).encode("utf-8"), method="POST",
    headers={"Authorization": "Bearer " + token, "User-Agent": "QuorumRAG-Nightly-Raptor",
             "Accept": "application/vnd.github+json", "Content-Type": "application/json"})
urllib.request.urlopen(req)
print("[+] Dispatched GitHub Actions raptor-security.yml on main")
'@
$dispatchFile = Join-Path ([System.IO.Path]::GetTempPath()) ("quorumrag-raptor-dispatch-" + [Guid]::NewGuid().ToString("N") + ".py")
[System.IO.File]::WriteAllText($dispatchFile, $dispatch, (New-Object System.Text.UTF8Encoding($false)))
try {
    & $pythonExe $dispatchFile $gitExe *>> $LogFile
} finally {
    Remove-Item -Force $dispatchFile -ErrorAction SilentlyContinue
}

"[$(Get-Date -Format 'o')] Nightly RAPTOR security audit finished." | Out-File -FilePath $LogFile -Append -Encoding utf8
