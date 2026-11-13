param(
    [string]$Version = "0.6.9",
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

# Step 3: Populate dist/ and target/wix/ directories with required preservation artifacts
Write-Host "[3/4] Staging MSI and portable ZIP artifacts to dist/ and target/wix/..." -ForegroundColor Cyan

$DistDir = Join-Path $ProjectRoot "dist"
$TargetWixDir = Join-Path $ProjectRoot "target\wix"
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
New-Item -ItemType Directory -Force -Path $TargetWixDir | Out-Null

$SourceMsi = Join-Path $ProjectRoot "deploy\windows\QuorumRAG-$Version-x86_64.msi"
$SourceZip = Join-Path $ProjectRoot "deploy\windows\QuorumRAG-$Version-windows-x86_64.zip"

if (-not (Test-Path $SourceMsi)) {
    throw "Generated MSI not found at $SourceMsi"
}
if (-not (Test-Path $SourceZip)) {
    throw "Generated ZIP not found at $SourceZip"
}

# Target destination files
$DistMsi020 = Join-Path $DistDir "QuorumRAG-0.2.0-x86_64.msi"
$TargetWixMsi020 = Join-Path $TargetWixDir "QuorumRAG-0.2.0-x86_64.msi"
$DistMsiVer = Join-Path $DistDir "QuorumRAG-$Version-x86_64.msi"
$TargetWixMsiVer = Join-Path $TargetWixDir "QuorumRAG-$Version-x86_64.msi"

$DistZipGeneric = Join-Path $DistDir "QuorumRAG-windows-x86_64.zip"
$DistZipVer = Join-Path $DistDir "QuorumRAG-$Version-windows-x86_64.zip"

# Copy MSI files
Copy-Item -Path $SourceMsi -Destination $DistMsi020 -Force
Copy-Item -Path $SourceMsi -Destination $TargetWixMsi020 -Force
Copy-Item -Path $SourceMsi -Destination $DistMsiVer -Force
Copy-Item -Path $SourceMsi -Destination $TargetWixMsiVer -Force

# Copy ZIP files
Copy-Item -Path $SourceZip -Destination $DistZipGeneric -Force
Copy-Item -Path $SourceZip -Destination $DistZipVer -Force

# Compute SHA256 checksums
$zipHash = (Get-FileHash -Path $DistZipGeneric -Algorithm SHA256).Hash.ToLowerInvariant()
$msiHash = (Get-FileHash -Path $DistMsi020 -Algorithm SHA256).Hash.ToLowerInvariant()

[System.IO.File]::WriteAllText((Join-Path $DistDir "QuorumRAG-windows-x86_64.zip.sha256"), "$zipHash  QuorumRAG-windows-x86_64.zip`n", (New-Object System.Text.UTF8Encoding($false)))
[System.IO.File]::WriteAllText((Join-Path $DistDir "QuorumRAG-windows-x86_64.sha256"), "$zipHash  QuorumRAG-windows-x86_64.zip`n", (New-Object System.Text.UTF8Encoding($false)))
[System.IO.File]::WriteAllText((Join-Path $DistDir "QuorumRAG-0.2.0-x86_64.msi.sha256"), "$msiHash  QuorumRAG-0.2.0-x86_64.msi`n", (New-Object System.Text.UTF8Encoding($false)))

# Generate dist/SHA256SUMS.txt
$distSums = @()
foreach ($f in (Get-ChildItem -Path $DistDir -File | Where-Object { $_.Name -notlike "*.sha256" -and $_.Name -ne "SHA256SUMS.txt" } | Sort-Object Name)) {
    $h = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $distSums += "$h  $($f.Name)"
}
[System.IO.File]::WriteAllLines((Join-Path $DistDir "SHA256SUMS.txt"), $distSums, (New-Object System.Text.UTF8Encoding($false)))

# Step 4: Verification of Local MSI Preservation Invariants
Write-Host "[4/4] Verifying all local MSI and package preservation invariants..." -ForegroundColor Cyan

$Invariants = @(
    @{ Path = $DistMsi020; Label = "dist/QuorumRAG-0.2.0-x86_64.msi" },
    @{ Path = $TargetWixMsi020; Label = "target/wix/QuorumRAG-0.2.0-x86_64.msi" },
    @{ Path = $DistZipGeneric; Label = "dist/QuorumRAG-windows-x86_64.zip" },
    @{ Path = (Join-Path $DistDir "QuorumRAG-windows-x86_64.zip.sha256"); Label = "dist/QuorumRAG-windows-x86_64.zip.sha256" },
    @{ Path = (Join-Path $DistDir "QuorumRAG-windows-x86_64.sha256"); Label = "dist/QuorumRAG-windows-x86_64.sha256" }
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
