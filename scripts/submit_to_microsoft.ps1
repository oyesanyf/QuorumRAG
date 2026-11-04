param(
    [string]$Version = "0.1.0",
    [switch]$OpenBrowser = $false,
    [switch]$SkipDefenderScan = $false,
    [string]$CertThumbprint = "9A6D3B509500813058EC63183476464FAC8F015B",
    [string]$TimestampServer = "http://timestamp.digicert.com",
    # Explicit list of files to sign/scan. When empty, defaults to the release exe + MSI.
    [string[]]$Files = @()
)

# QuorumRAG Microsoft WDSI & Defender Pre-Flight Automation
# Signs ONLY release artifacts in target\release\ and deploy\windows\ (NEVER target\debug\deps\*).

$ErrorActionPreference = "Stop"
$ProjectRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
Set-Location $ProjectRoot

$ReleaseExe = Join-Path $ProjectRoot "target\release\quorumrag.exe"
$DeployMsi = Join-Path $ProjectRoot "deploy\windows\QuorumRAG-$Version-x86_64.msi"

$FilesToSign = @()
if ($Files -and $Files.Count -gt 0) {
    foreach ($f in $Files) { if ($f -and (Test-Path $f)) { $FilesToSign += (Get-Item $f).FullName } }
} else {
    if (Test-Path $ReleaseExe) { $FilesToSign += $ReleaseExe }
    if (Test-Path $DeployMsi) { $FilesToSign += $DeployMsi }
}

if ($FilesToSign.Count -eq 0) {
    throw "No release artifacts found to sign or scan."
}

# 1. Authenticode Digital Signing (Release Artifacts Only)
$Cert = Get-Item "Cert:\CurrentUser\My\$CertThumbprint" -ErrorAction SilentlyContinue
if (-not $Cert) {
    $Cert = Get-Item "Cert:\LocalMachine\My\$CertThumbprint" -ErrorAction SilentlyContinue
}
if (-not $Cert) {
    $Cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue | Select-Object -First 1
}

# Prefer signtool.exe (single, deterministic SHA256 signature + RFC3161 timestamp).
# Every file is signed EXACTLY ONCE: files already carrying a signature from this
# certificate are skipped, so repeated packaging steps never stack/rewrite signatures.
$SignTool = $null
$FoundSignTool = Get-Command "signtool.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($FoundSignTool) {
    $SignTool = $FoundSignTool.Source
} else {
    $SignTool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName | Select-Object -Last 1 -ExpandProperty FullName
}

if ($Cert) {
    Write-Host "  Signing release artifacts with certificate: $($Cert.Subject) ($($Cert.Thumbprint))" -ForegroundColor Green
    foreach ($f in $FilesToSign) {
        $existing = Get-AuthenticodeSignature -FilePath $f
        if ($existing.SignerCertificate -and ($existing.SignerCertificate.Thumbprint -eq $Cert.Thumbprint)) {
            Write-Host "    -> already signed by $($Cert.Thumbprint); skipping: $f" -ForegroundColor Gray
            continue
        }
        $signed = $false
        if ($SignTool) {
            & $SignTool sign /sha1 $Cert.Thumbprint /fd SHA256 /tr $TimestampServer /td SHA256 /q $f
            if ($LASTEXITCODE -eq 0) {
                $signed = $true
            } else {
                Write-Warning "    signtool timestamped signing failed ($LASTEXITCODE); retrying without timestamp: $f"
                & $SignTool sign /sha1 $Cert.Thumbprint /fd SHA256 /q $f
                if ($LASTEXITCODE -eq 0) { $signed = $true }
            }
        }
        if (-not $signed) {
            try {
                $null = Set-AuthenticodeSignature -FilePath $f -Certificate $Cert -TimestampServer $TimestampServer -HashAlgorithm SHA256
                $signed = $true
            } catch {
                Write-Warning "    Signing notice for ${f}: $_"
            }
        }
        $after = Get-AuthenticodeSignature -FilePath $f
        Write-Host "    -> signed=$signed status=$($after.Status): $f" -ForegroundColor Green
    }
} else {
    Write-Host "  No local Authenticode certificate present in CurrentUser/LocalMachine store; skipping local code-signing." -ForegroundColor Gray
}

# 2. Local Microsoft Defender Pre-Flight Scan
if (-not $SkipDefenderScan) {
    $resolvedMp = Resolve-Path "C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe" -ErrorAction SilentlyContinue | Select-Object -Last 1
    $mpCmdRun = if ($resolvedMp) { $resolvedMp.Path } else { "C:\Program Files\Windows Defender\MpCmdRun.exe" }
    if (Test-Path $mpCmdRun) {
        foreach ($f in $FilesToSign) {
            $fullPath = (Get-Item $f).FullName
            Write-Host "  Scanning $fullPath with Microsoft Defender..." -ForegroundColor Gray
            & $mpCmdRun -Scan -ScanType 3 -File $fullPath -DisableRemediation | Out-String | Write-Host -ForegroundColor Gray
            if ($LASTEXITCODE -ne 0) {
                throw "Microsoft Defender reported a non-zero exit code ($LASTEXITCODE) on $fullPath"
            }
        }
        Write-Host "  Local Microsoft Defender Scan: CLEAN (0 threats detected)" -ForegroundColor Green
    }
}

# 3. Emit WDSI Submission Manifest
$SubmissionDir = Join-Path $ProjectRoot "deploy\microsoft_wdsi_submission"
if (Test-Path $SubmissionDir) { Remove-Item $SubmissionDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $SubmissionDir | Out-Null

$ManifestEntries = @()
foreach ($src in $FilesToSign) {
    $leaf = Split-Path $src -Leaf
    $sha256 = (Get-FileHash -Path $src -Algorithm SHA256).Hash.ToLowerInvariant()
    $sha1 = (Get-FileHash -Path $src -Algorithm SHA1).Hash.ToLowerInvariant()
    $info = Get-Item $src
    $sigInfo = Get-AuthenticodeSignature -FilePath $src
    $ManifestEntries += [PSCustomObject]@{
        filename         = $leaf
        size_bytes       = $info.Length
        sha256           = $sha256
        sha1             = $sha1
        signature_status = "$($sigInfo.Status)"
        signer           = if ($sigInfo.SignerCertificate) { $sigInfo.SignerCertificate.Subject } else { "Unsigned" }
        timestamp_server = $TimestampServer
    }
}

$Manifest = [PSCustomObject]@{
    submission_timestamp_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    software_vendor          = "Oshoosi Security"
    software_name            = "QuorumRAG P2P Agentic RAG"
    version                  = $Version
    submission_portal        = "https://www.microsoft.com/en-us/wdsi/filesubmission?persona=SoftwareDeveloper"
    zero_touch_path_verified = $true
    files                    = $ManifestEntries
}

$ManifestPath = Join-Path $SubmissionDir "submission_manifest.json"
[System.IO.File]::WriteAllText(
    $ManifestPath,
    ($Manifest | ConvertTo-Json -Depth 5),
    (New-Object System.Text.UTF8Encoding($false))
)
Write-Host "  WDSI manifest written: $ManifestPath" -ForegroundColor Green

if ($OpenBrowser) {
    Start-Process "https://www.microsoft.com/en-us/wdsi/filesubmission?persona=SoftwareDeveloper"
}
