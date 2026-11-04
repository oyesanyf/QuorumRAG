param(
    [string]$Version = "0.1.0",
    [switch]$SkipBuild = $false,
    [switch]$SkipDefenderScan = $false,
    [string]$CertThumbprint = "9A6D3B509500813058EC63183476464FAC8F015B"
)

# QuorumRAG Windows Release & WiX v5 MSI Packaging Pipeline
# Enforces Universal Zero-Touch PATH & Environment Protection Protocol.

$ErrorActionPreference = "Stop"
if (Test-Path Variable:\PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}
$ProjectRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
Set-Location $ProjectRoot

# Process-scoped PATH additions ONLY (Zero-Touch Registry and System PATH)
$RustupBin = Join-Path $env:USERPROFILE ".rustup\toolchains\stable-x86_64-pc-windows-msvc\bin"
$CargoExe = "cargo"
if (Test-Path (Join-Path $RustupBin "cargo.exe")) {
    $env:PATH = "$RustupBin;$env:PATH"
    $env:RUSTC = Join-Path $RustupBin "rustc.exe"
    $CargoExe = Join-Path $RustupBin "cargo.exe"
}

$ProcessToolDirs = @(
    (Join-Path $env:USERPROFILE ".cargo\bin"),
    (Join-Path $env:USERPROFILE ".dotnet\tools"),
    "C:\Users\oyesanyf\wix_tools\PFiles64\WiX Toolset v5.0\bin",
    "C:\Program Files\Git\cmd",
    "C:\Program Files\dotnet"
)
foreach ($d in $ProcessToolDirs) {
    if ($d -and (Test-Path $d) -and ($env:PATH -notmatch [regex]::Escape($d))) {
        $env:PATH = "$d;$env:PATH"
    }
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " QuorumRAG v$Version Windows Release & MSI Packaging" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Step 0: Fail-Closed Zero-Touch PATH Manifest Audit
$WixWxs = Join-Path $ProjectRoot "wix\QuorumRAG.wxs"
if (-not (Test-Path $WixWxs)) {
    throw "Missing WiX manifest at $WixWxs"
}
$WxsRaw = Get-Content -Path $WixWxs -Raw -Encoding UTF8
$WxsNoComments = [regex]::Replace($WxsRaw, '<!--[\s\S]*?-->', '')
if ($WxsNoComments -match '<\s*Environment\b') {
    throw "SECURITY INVARIANT VIOLATION: WiX Environment element detected in $WixWxs. Zero-Touch PATH law forbids all MSI environment mutations."
}
Write-Host "[0/5] Zero-Touch PATH static manifest audit: PASS (0 Environment tags)" -ForegroundColor Green

# Step 1: Build Release Binary (target\release\quorumrag.exe) with WDAC build-script signing support
$ReleaseExe = Join-Path $ProjectRoot "target\release\quorumrag.exe"
if (-not $SkipBuild) {
    Write-Host "[1/5] Building release binary (quorum-daemon -> quorumrag.exe)..." -ForegroundColor Cyan
    if (Test-Path $ReleaseExe) {
        try {
            Remove-Item -Path $ReleaseExe -Force -ErrorAction Stop
        } catch {
            $lockedCopy = "$ReleaseExe.locked." + (Get-Random)
            Write-Host "  target\release\quorumrag.exe is in use; renaming to $lockedCopy..." -ForegroundColor Yellow
            Move-Item -Path $ReleaseExe -Destination $lockedCopy -Force
        }
    }
    Remove-Item -Path (Join-Path $ProjectRoot "target\release\deps\quorumrag*") -Force -ErrorAction SilentlyContinue

    $env:CARGO_INCREMENTAL = "0"
    $maxAttempts = 15
    $buildOk = $false
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        # Invoke cargo directly (not Start-Process -Wait): -Wait also waits for detached descendants
        # such as the MSVC linker's vctip.exe telemetry helper, which can stall packaging indefinitely.
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $cargoLines = & $CargoExe build --release -p quorum-daemon --bin quorumrag 2>&1 | ForEach-Object {
            $line = "$_"
            Write-Host $line
            $line
        }
        $cargoExit = $LASTEXITCODE
        $ErrorActionPreference = $prevEap
        $errText = ($cargoLines -join "`n")
        if ($cargoExit -eq 0) {
            $buildOk = $true
            break
        }
        # If Windows 11 Smart App Control blocked a stale pre-existing build-script-build.exe
        # (os error 4551), purge ONLY that stale build directory so link.exe emits a fresh
        # Smartlocker-trusted inode on retry.
        if ($errText -match 'target[\\/]release[\\/]build[\\/]([^\\/]+)[\\/]build-script-build' -and $attempt -lt $maxAttempts) {
            $blockedPkgDir = Join-Path $ProjectRoot ("target\release\build\" + $matches[1])
            Write-Host "  [SAC] Purging stale build-script directory '$blockedPkgDir' so link.exe creates a fresh inode ($attempt/$maxAttempts)..." -ForegroundColor Yellow
            Remove-Item -Recurse -Force -Path $blockedPkgDir -ErrorAction SilentlyContinue
            continue
        }
        if ($errText -match 'target[\\/]release[\\/]deps[\\/]([^\\/:\s]+\.dll).*4551' -and $attempt -lt $maxAttempts) {
            $blockedDll = Join-Path $ProjectRoot ("target\release\deps\" + $matches[1])
            Write-Host "  [SAC] Purging stale proc-macro DLL '$blockedDll' so link.exe creates a fresh inode ($attempt/$maxAttempts)..." -ForegroundColor Yellow
            Remove-Item -Force -Path $blockedDll -ErrorAction SilentlyContinue
            continue
        }
        $LASTEXITCODE = $cargoExit
        break
    }
    if (-not $buildOk) {
        throw "cargo build --release failed"
    }
} else {
    Write-Host "[1/5] Skipping cargo build (-SkipBuild)" -ForegroundColor Gray
}

if (-not (Test-Path $ReleaseExe)) {
    $AltExe = Join-Path $ProjectRoot "target\x86_64-pc-windows-msvc\release\quorumrag.exe"
    if (Test-Path $AltExe) {
        New-Item -ItemType Directory -Force -Path (Split-Path $ReleaseExe -Parent) | Out-Null
        Copy-Item -Path $AltExe -Destination $ReleaseExe -Force
    } else {
        throw "Release binary not found at $ReleaseExe"
    }
}

# Break Cargo NTFS hardlink between target\release\quorumrag.exe and target\release\deps\quorumrag*.exe before Authenticode signing
$hlOut = & fsutil hardlink list $ReleaseExe 2>$null
if ($hlOut -and ($hlOut.Count -gt 1)) {
    $targetFull = [System.IO.Path]::GetFullPath($ReleaseExe)
    $driveRoot = [System.IO.Path]::GetPathRoot($targetFull).TrimEnd('\')
    foreach ($hlRel in $hlOut) {
        $hlCandidate = "$driveRoot$hlRel"
        if ([System.IO.Path]::GetFullPath($hlCandidate) -ne $targetFull) {
            Remove-Item -Path $hlCandidate -Force -ErrorAction SilentlyContinue
        }
    }
}

# Pre-sign target\release\quorumrag.exe before embedding into MSI & ZIP so installed binary carries Authenticode signature
$SubmitScript = Join-Path $ProjectRoot "scripts\submit_to_microsoft.ps1"
if (Test-Path $SubmitScript) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File $SubmitScript -Version $Version -SkipDefenderScan -Files $ReleaseExe
}

# Step 2: Stage deploy\windows Portable Bundle (.zip)
Write-Host "[2/5] Staging portable Windows bundle & pruning stale artifacts..." -ForegroundColor Cyan
$WinDeployDir = Join-Path $ProjectRoot "deploy\windows"
New-Item -ItemType Directory -Force -Path $WinDeployDir | Out-Null
Get-ChildItem -Path $WinDeployDir -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

$PortableStage = Join-Path $WinDeployDir "portable_stage\QuorumRAG-$Version-windows-x86_64"
New-Item -ItemType Directory -Force -Path $PortableStage | Out-Null
Copy-Item -Path $ReleaseExe -Destination (Join-Path $PortableStage "quorumrag.exe") -Force
Copy-Item -Path (Join-Path $ProjectRoot "packaging\windows\quorumrag-launch.cmd") -Destination (Join-Path $PortableStage "quorumrag-launch.cmd") -Force
Copy-Item -Path (Join-Path $ProjectRoot "packaging\windows\README_INSTALL.txt") -Destination (Join-Path $PortableStage "README_INSTALL.txt") -Force
Copy-Item -Path (Join-Path $ProjectRoot "packaging\windows\quorumrag-open-ui.cmd") -Destination (Join-Path $PortableStage "quorumrag-open-ui.cmd") -Force
Copy-Item -Path (Join-Path $ProjectRoot "packaging\windows\quorumrag-uninstall.cmd") -Destination (Join-Path $PortableStage "quorumrag-uninstall.cmd") -Force

$ZipOut = Join-Path $WinDeployDir "QuorumRAG-$Version-windows-x86_64.zip"
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory((Split-Path $PortableStage -Parent), $ZipOut)
Remove-Item -Path (Split-Path $PortableStage -Parent) -Recurse -Force
Write-Host "  -> Created portable archive: $ZipOut" -ForegroundColor Green

# Step 3: Resolve WiX v5 CLI & Compile QuorumRAG-<Version>-x86_64.msi
Write-Host "[3/5] Compiling WiX v5 MSI installer..." -ForegroundColor Cyan
$WixCmd = $null
$FoundWix = Get-Command "wix.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($FoundWix) {
    $WixCmd = $FoundWix.Source
} else {
    $CandidateWix = @(
        "C:\Users\oyesanyf\wix_tools\PFiles64\WiX Toolset v5.0\bin\wix.exe",
        (Join-Path $env:USERPROFILE "wix_tools\PFiles64\WiX Toolset v5.0\bin\wix.exe"),
        (Join-Path $env:USERPROFILE ".dotnet\tools\wix.exe"),
        (Join-Path $env:ProgramFiles "WiX Toolset v5.0\bin\wix.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "WiX Toolset v5.0\bin\wix.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\wix\wix.exe")
    )
    foreach ($cand in $CandidateWix) {
        if ($cand -and (Test-Path $cand)) {
            $WixCmd = $cand
            break
        }
    }
}

if (-not $WixCmd) {
    if (Get-Command "dotnet" -ErrorAction SilentlyContinue) {
        Write-Host "  Installing WiX v5.0.2 dotnet tool..." -ForegroundColor Yellow
        & dotnet tool install --global wix --version 5.0.2
        $DotnetWix = Join-Path $env:USERPROFILE ".dotnet\tools\wix.exe"
        if (Test-Path $DotnetWix) { $WixCmd = $DotnetWix }
    }
}

if (-not $WixCmd) {
    throw "WiX v5 (wix.exe) could not be found or installed."
}

$MsiOut = Join-Path $WinDeployDir "QuorumRAG-$Version-x86_64.msi"
& $WixCmd build $WixWxs -arch x64 -d "ProductVersion=$Version" -out $MsiOut
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $MsiOut)) {
    throw "WiX MSI compilation failed (exit code $LASTEXITCODE)"
}
Write-Host "  -> Created MSI installer: $MsiOut" -ForegroundColor Green

# Step 4: Binary MSI Database Inspection (Prove Environment Table is Absent)
Write-Host "[4/5] Auditing compiled MSI database tables via Windows Installer COM..." -ForegroundColor Cyan
$Installer = New-Object -ComObject WindowsInstaller.Installer
$Database = $Installer.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $Installer, @([string]$MsiOut, [int]0))
$TablesView = $Database.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $Database, @('SELECT `Name` FROM `_Tables`'))
$TablesView.GetType().InvokeMember("Execute", "InvokeMethod", $null, $TablesView, $null) | Out-Null
$TableNames = @()
while ($true) {
    $Rec = $TablesView.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $TablesView, $null)
    if (-not $Rec) { break }
    $TableNames += $Rec.GetType().InvokeMember("StringData", "GetProperty", $null, $Rec, @(1))
}
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($TablesView) | Out-Null
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($Database) | Out-Null
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($Installer) | Out-Null

if ($TableNames -contains "Environment") {
    throw "SECURITY INVARIANT VIOLATION: Compiled MSI contains an 'Environment' table!"
}
Write-Host "  -> MSI tables verified ($($TableNames -join ', ')); 'Environment' table is ABSENT (100% Zero-Touch PATH)." -ForegroundColor Green

# Step 5: Authenticode Signing of MSI, Defender Pre-Flight Scan & WDSI Manifest
Write-Host "[5/5] Running Authenticode MSI signing, Defender scan & SHA256SUMS generation..." -ForegroundColor Cyan
if (Test-Path $SubmitScript) {
    # Sign ONLY the MSI here; the exe was signed exactly once before being embedded.
    $subArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $SubmitScript, "-Version", $Version, "-Files", $MsiOut)
    if ($SkipDefenderScan) { $subArgs += "-SkipDefenderScan" }
    & powershell @subArgs
}

$SumsLines = @()
foreach ($art in (Get-ChildItem -Path $WinDeployDir -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" } | Sort-Object Name)) {
    $hash = (Get-FileHash -Path $art.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $SumsLines += "$hash  $($art.Name)"
}
[System.IO.File]::WriteAllLines((Join-Path $WinDeployDir "SHA256SUMS.txt"), $SumsLines, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " Windows Packaging Complete: $WinDeployDir" -ForegroundColor Green
Get-ChildItem -Path $WinDeployDir | Format-Table Name, Length, LastWriteTime -AutoSize
Write-Host "============================================================`n" -ForegroundColor Green
