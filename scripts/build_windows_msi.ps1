param(
    [string]$Version = "0.7.0",
    [switch]$SkipBuild = $false
)

# QuorumRAG Windows Local MSI & Distribution Packaging Script
# Enforces Universal Zero-Touch PATH & Local MSI Preservation Invariants

$ErrorActionPreference = "Stop"
if (Test-Path Variable:\PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$ProjectRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
Set-Location $ProjectRoot

# Process-scoped PATH additions ONLY (Zero-Touch Registry and System PATH)
$candidateDirs = @(
    (Join-Path $env:USERPROFILE ".rustup\toolchains\stable-x86_64-pc-windows-msvc\bin"),
    (Join-Path $env:USERPROFILE ".cargo\bin"),
    (Join-Path $env:USERPROFILE ".dotnet\tools"),
    "C:\Users\oyesanyf\wix_tools\PFiles64\WiX Toolset v5.0\bin",
    "C:\Program Files\Git\cmd",
    "C:\Program Files\dotnet"
)
foreach ($d in $candidateDirs) {
    if ($d -and (Test-Path $d) -and ($env:PATH -notmatch [regex]::Escape($d))) {
        $env:PATH = "$d;$env:PATH"
    }
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " QuorumRAG Local Windows MSI & Packaging Pipeline" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Step 0: Static Zero-Touch PATH manifest audit
$WixWxs = Join-Path $ProjectRoot "wix\QuorumRAG.wxs"
if (-not (Test-Path $WixWxs)) {
    throw "Missing WiX manifest at $WixWxs"
}
$WxsRaw = Get-Content -Path $WixWxs -Raw -Encoding UTF8
$WxsNoComments = [regex]::Replace($WxsRaw, '<!--[\s\S]*?-->', '')
if ($WxsNoComments -match '<\s*Environment\b') {
    throw "SECURITY INVARIANT VIOLATION: WiX Environment element detected in $WixWxs. Zero-Touch PATH law forbids all MSI environment mutations."
}
Write-Host "[0/4] Zero-Touch PATH static audit: PASS (0 Environment elements)" -ForegroundColor Green

# Step 1: Ensure workspace release binaries exist
$ReleaseExe = Join-Path $ProjectRoot "target\release\quorumrag.exe"
$DesktopExe = Join-Path $ProjectRoot "target\release\quorum-desktop.exe"

if (-not $SkipBuild -and (-not (Test-Path $ReleaseExe) -or -not (Test-Path $DesktopExe))) {
    Write-Host "[1/4] Building release binaries via cargo build --release --workspace..." -ForegroundColor Cyan
    & cargo build --release --workspace
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build --release --workspace failed with exit code $LASTEXITCODE"
    }
} else {
    Write-Host "[1/4] Release binaries already built or build skipped." -ForegroundColor Gray
}

# Step 2: Delegate to scripts/package.ps1 for standard WiX compilation and COM table verification
Write-Host "[2/4] Executing WiX v5 MSI packaging and binary table verification..." -ForegroundColor Cyan
$PackageScript = Join-Path $ProjectRoot "scripts\package.ps1"
if (-not (Test-Path $PackageScript)) {
    throw "Missing package script at $PackageScript"
}

& powershell -NoProfile -ExecutionPolicy Bypass -File $PackageScript -Version $Version -SkipBuild -SkipDefenderScan
if ($LASTEXITCODE -ne 0) {
    throw "scripts/package.ps1 failed with exit code $LASTEXITCODE"
}

# Step 3: Prune older builds and stage ONLY the current version MSI & portable ZIP to dist/ and target/wix/
Write-Host "[3/4] Pruning superseded packages and staging v$Version MSI & ZIP to dist/ and target/wix/..." -ForegroundColor Cyan

$DistDir = Join-Path $ProjectRoot "dist"
$TargetWixDir = Join-Path $ProjectRoot "target\wix"
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
New-Item -ItemType Directory -Force -Path $TargetWixDir | Out-Null
Get-ChildItem -Path $DistDir -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $TargetWixDir -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

$SourceMsi = Join-Path $ProjectRoot "deploy\windows\QuorumRAG-$Version-x86_64.msi"
$SourceZip = Join-Path $ProjectRoot "deploy\windows\QuorumRAG-$Version-windows-x86_64.zip"

if (-not (Test-Path $SourceMsi)) {
    throw "Generated MSI not found at $SourceMsi"
}
if (-not (Test-Path $SourceZip)) {
    throw "Generated ZIP not found at $SourceZip"
}

$DistMsiVer = Join-Path $DistDir "QuorumRAG-$Version-x86_64.msi"
$TargetWixMsiVer = Join-Path $TargetWixDir "QuorumRAG-$Version-x86_64.msi"
$DistZipVer = Join-Path $DistDir "QuorumRAG-$Version-windows-x86_64.zip"

Copy-Item -Path $SourceMsi -Destination $DistMsiVer -Force
Copy-Item -Path $SourceMsi -Destination $TargetWixMsiVer -Force
Copy-Item -Path $SourceZip -Destination $DistZipVer -Force

$distSums = @()
foreach ($f in (Get-ChildItem -Path $DistDir -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" } | Sort-Object Name)) {
    $h = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $distSums += "$h  $($f.Name)"
}
[System.IO.File]::WriteAllLines((Join-Path $DistDir "SHA256SUMS.txt"), $distSums, (New-Object System.Text.UTF8Encoding($false)))

# Step 4: Verification of Single-Latest Local MSI Invariants
Write-Host "[4/4] Verifying single-latest local MSI and ZIP invariants..." -ForegroundColor Cyan

$Invariants = @(
    @{ Path = $DistMsiVer; Label = "dist/QuorumRAG-$Version-x86_64.msi" },
    @{ Path = $TargetWixMsiVer; Label = "target/wix/QuorumRAG-$Version-x86_64.msi" },
    @{ Path = $DistZipVer; Label = "dist/QuorumRAG-$Version-windows-x86_64.zip" }
)

foreach ($inv in $Invariants) {
    if (-not (Test-Path $inv.Path)) {
        throw "INVARIANT VIOLATION: Missing required packaging file: $($inv.Label)"
    }
    $len = (Get-Item $inv.Path).Length
    if ($len -le 0) {
        throw "INVARIANT VIOLATION: File is empty (0 bytes): $($inv.Label)"
    }
    Write-Host "  PASS: $($inv.Label) ($len bytes)" -ForegroundColor Green
}

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " Local Windows MSI Packaging Verified Successfully!" -ForegroundColor Green
Write-Host " dist: $DistDir" -ForegroundColor Green
Write-Host " target\wix: $TargetWixDir" -ForegroundColor Green
Write-Host "============================================================`n" -ForegroundColor Green
