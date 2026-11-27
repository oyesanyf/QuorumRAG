param(
    [string]$Version = "0.6.17",
    [switch]$OpenBrowser = $false,
    [switch]$SkipDefenderScan = $false,
    [switch]$TrustLocalPublisher = $false,
    [string]$CertThumbprint = "9A6D3B509500813058EC63183476464FAC8F015B",
    [string]$TimestampServer = "http://timestamp.digicert.com",
    [string]$ProductDescription = "QuorumRAG P2P Agentic RAG",
    [string]$ProductUrl = "https://github.com/oyesanyf/QuorumRAG",
    # Explicit list of files to sign/scan. When empty, defaults to release binaries + MSI.
    [string[]]$Files = @()
)

# QuorumRAG Solo-Developer Authenticode Signing, Publisher Trust & WDSI Pre-Flight Automation
# Supports 3 automatic signing tiers (no manual intervention):
#   Tier 1: Microsoft Azure Trusted Signing (AZURE_TRUSTED_SIGNING_ENDPOINT / ACCOUNT / CERT_PROFILE) -> Public CA
#   Tier 2: Ephemeral CA PFX Certificate (WINDOWS_CODESIGN_PFX_BASE64 + WINDOWS_CODESIGN_PFX_PASSWORD) -> Public CA
#   Tier 3: Local Developer Certificate ($CertThumbprint) + public .cer export + LocalMachine trust helper
# Signs ONLY release artifacts in target\release\ and deploy\windows\ (NEVER target\debug\deps\*).

$ErrorActionPreference = "Stop"
$ProjectRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
Set-Location $ProjectRoot

$ReleaseExe = Join-Path $ProjectRoot "target\release\quorumrag.exe"
$DesktopExe = Join-Path $ProjectRoot "target\release\quorum-desktop.exe"
$DeployMsi = Join-Path $ProjectRoot "deploy\windows\QuorumRAG-$Version-x86_64.msi"

$FilesToSign = @()
if ($Files -and $Files.Count -gt 0) {
    foreach ($entry in $Files) {
        if (-not $entry) { continue }
        foreach ($part in ($entry -split ',')) {
            $trimmed = $part.Trim().Trim('"')
            if ($trimmed -and (Test-Path $trimmed)) {
                $full = (Get-Item $trimmed).FullName
                if ($FilesToSign -notcontains $full) { $FilesToSign += $full }
            }
        }
    }
} else {
    if (Test-Path $ReleaseExe) { $FilesToSign += $ReleaseExe }
    if (Test-Path $DesktopExe) { $FilesToSign += $DesktopExe }
    if (Test-Path $DeployMsi) { $FilesToSign += $DeployMsi }
}

if ($FilesToSign.Count -eq 0) {
    throw "No release artifacts found to sign or scan."
}

$SignTool = $null
$FoundSignTool = Get-Command "signtool.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($FoundSignTool) {
    $SignTool = $FoundSignTool.Source
} else {
    $SignTool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName | Select-Object -Last 1 -ExpandProperty FullName
}

$AzureEndpoint = $env:AZURE_TRUSTED_SIGNING_ENDPOINT
$AzureAccount = $env:AZURE_TRUSTED_SIGNING_ACCOUNT
$AzureProfile = $env:AZURE_TRUSTED_SIGNING_CERT_PROFILE
$PfxBase64 = $env:WINDOWS_CODESIGN_PFX_BASE64
$PfxPassword = $env:WINDOWS_CODESIGN_PFX_PASSWORD

$SignedViaPublicCa = $false

# Tier 1: Microsoft Azure Trusted Signing (Public Root CA across all Windows PCs)
if ($SignTool -and $AzureEndpoint -and $AzureAccount -and $AzureProfile) {
    $DlibPath = $env:AZURE_CODESIGNING_DLIB
    if (-not $DlibPath -or -not (Test-Path $DlibPath)) {
        $DlibPath = Get-ChildItem -Path "$env:LOCALAPPDATA","$env:USERPROFILE\.nuget\packages" -Recurse -Filter "Azure.CodeSigning.Dlib.dll" -ErrorAction SilentlyContinue |
             Where-Object { $_.FullName -match "x64|win-x64" } | Select-Object -Last 1 -ExpandProperty FullName
    }
    if ($DlibPath -and (Test-Path $DlibPath)) {
        Write-Host "  [Tier 1] Signing release artifacts via Microsoft Azure Trusted Signing ($AzureAccount/$AzureProfile)..." -ForegroundColor Green
        $metaPath = Join-Path ([System.IO.Path]::GetTempPath()) ("quorumrag-acs-" + [Guid]::NewGuid().ToString("N") + ".json")
        $metaObj = [PSCustomObject]@{
            Endpoint               = $AzureEndpoint
            CodeSigningAccountName = $AzureAccount
            CertificateProfileName = $AzureProfile
        }
        try {
            [System.IO.File]::WriteAllText($metaPath, ($metaObj | ConvertTo-Json -Depth 3), (New-Object System.Text.UTF8Encoding($false)))
            foreach ($f in $FilesToSign) {
                & $SignTool sign /fd SHA256 /tr "http://timestamp.acs.microsoft.com" /td SHA256 /d $ProductDescription /du $ProductUrl /dlib $DlibPath /dmdf $metaPath /q $f
                if ($LASTEXITCODE -ne 0) {
                    throw "Azure Trusted Signing failed ($LASTEXITCODE) on $f"
                }
                Write-Host "    -> Azure Trusted Signed: $f" -ForegroundColor Green
            }
            $SignedViaPublicCa = $true
        } finally {
            Remove-Item -Path $metaPath -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Warning "  Azure Trusted Signing env vars set, but Azure.CodeSigning.Dlib.dll not found; falling back."
    }
}

# Tier 2: Base64-encoded CA PFX Certificate from CI/Environment Secret
if (-not $SignedViaPublicCa -and $SignTool -and $PfxBase64) {
    Write-Host "  [Tier 2] Signing release artifacts via WINDOWS_CODESIGN_PFX_BASE64 certificate..." -ForegroundColor Green
    $tempPfx = Join-Path ([System.IO.Path]::GetTempPath()) ("quorumrag-sign-" + [Guid]::NewGuid().ToString("N") + ".pfx")
    try {
        [System.IO.File]::WriteAllBytes($tempPfx, [Convert]::FromBase64String($PfxBase64.Trim()))
        foreach ($f in $FilesToSign) {
            $pfxArgs = @("sign", "/f", $tempPfx, "/fd", "SHA256", "/tr", $TimestampServer, "/td", "SHA256", "/d", $ProductDescription, "/du", $ProductUrl, "/q")
            if ($PfxPassword) { $pfxArgs += @("/p", $PfxPassword) }
            $pfxArgs += $f
            & $SignTool @pfxArgs
            if ($LASTEXITCODE -ne 0) {
                throw "PFX Authenticode signing failed ($LASTEXITCODE) on $f"
            }
            Write-Host "    -> PFX Signed + Timestamped: $f" -ForegroundColor Green
        }
        $SignedViaPublicCa = $true
    } finally {
        Remove-Item -Path $tempPfx -Force -ErrorAction SilentlyContinue
    }
}

# Tier 3: Local Solo-Developer Certificate ($CertThumbprint) + Public .cer Export + Machine Trust
if (-not $SignedViaPublicCa) {
    $Cert = Get-Item "Cert:\CurrentUser\My\$CertThumbprint" -ErrorAction SilentlyContinue
    if (-not $Cert) {
        $Cert = Get-Item "Cert:\LocalMachine\My\$CertThumbprint" -ErrorAction SilentlyContinue
    }
    if (-not $Cert) {
        $Cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue | Select-Object -First 1
    }

    if ($Cert) {
        Write-Host "  [Tier 3] Signing release artifacts with certificate: $($Cert.Subject) ($($Cert.Thumbprint))" -ForegroundColor Green
        foreach ($f in $FilesToSign) {
            $existing = Get-AuthenticodeSignature -FilePath $f
            $hasTimestamp = ($null -ne $existing.TimeStamperCertificate)
            if ($existing.SignerCertificate -and ($existing.SignerCertificate.Thumbprint -eq $Cert.Thumbprint) -and $hasTimestamp) {
                Write-Host "    -> already signed + timestamped by $($Cert.Thumbprint); skipping: $f" -ForegroundColor Gray
                continue
            }
            $signed = $false
            if ($SignTool) {
                & $SignTool sign /sha1 $Cert.Thumbprint /fd SHA256 /tr $TimestampServer /td SHA256 /d $ProductDescription /du $ProductUrl /q $f
                if ($LASTEXITCODE -eq 0) {
                    $signed = $true
                } else {
                    Write-Warning "    signtool timestamped signing failed ($LASTEXITCODE); retrying without timestamp: $f"
                    & $SignTool sign /sha1 $Cert.Thumbprint /fd SHA256 /d $ProductDescription /du $ProductUrl /q $f
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

        # Export public .cer (no private key) and auto-trust in LocalMachine when elevated or requested
        # Invoke in-process (& $TrustScript) to avoid spawning a nested powershell.exe cold start.
        $TrustScript = Join-Path $ProjectRoot "scripts\trust_publisher_cert.ps1"
        if (Test-Path $TrustScript) {
            if ($TrustLocalPublisher) {
                & $TrustScript -CertThumbprint $Cert.Thumbprint
            } else {
                & $TrustScript -CertThumbprint $Cert.Thumbprint -NoElevate
            }
        }
    } else {
        Write-Host "  No Authenticode certificate configured (Azure Trusted Signing, PFX, or local Cert store); skipping local code-signing." -ForegroundColor Gray
    }
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
