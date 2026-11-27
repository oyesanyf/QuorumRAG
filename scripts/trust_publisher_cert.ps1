param(
    [string]$CertThumbprint = "9A6D3B509500813058EC63183476464FAC8F015B",
    [string]$CerFilePath = "",
    [switch]$NoElevate = $false
)

# QuorumRAG Solo-Developer LocalMachine Publisher Trust Automation
# Ensures the public code-signing certificate (.cer only; never exports private keys)
# is installed in Cert:\LocalMachine\Root and Cert:\LocalMachine\TrustedPublisher so
# Windows UAC displays "Verified publisher: Oshoosi Developer" instead of "Unknown publisher".
# Obeys Universal Zero-Touch PATH invariant (zero environment/registry PATH changes).

$ErrorActionPreference = "Stop"

$inRoot = Test-Path "Cert:\LocalMachine\Root\$CertThumbprint"
$inPub = Test-Path "Cert:\LocalMachine\TrustedPublisher\$CertThumbprint"

if ($inRoot -and $inPub) {
    Write-Host "[+] Publisher certificate $CertThumbprint is already trusted in LocalMachine\Root and LocalMachine\TrustedPublisher." -ForegroundColor Green
    return
}

$resolvedCer = $CerFilePath
if (-not $resolvedCer -or -not (Test-Path $resolvedCer)) {
    $cert = Get-Item "Cert:\CurrentUser\My\$CertThumbprint" -ErrorAction SilentlyContinue
    if (-not $cert) {
        $cert = Get-Item "Cert:\LocalMachine\My\$CertThumbprint" -ErrorAction SilentlyContinue
    }
    if (-not $cert) {
        Write-Warning "Certificate $CertThumbprint not found in CurrentUser\My or LocalMachine\My; skipping LocalMachine trust."
        return
    }
    $projectRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    $winDeploy = Join-Path $projectRoot "deploy\windows"
    New-Item -ItemType Directory -Force -Path $winDeploy | Out-Null
    $resolvedCer = Join-Path $winDeploy "OshoosiDeveloper.cer"
    Export-Certificate -Cert $cert -FilePath $resolvedCer -Force | Out-Null
    Write-Host "[+] Exported public certificate (no private key) -> $resolvedCer" -ForegroundColor Cyan
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    if (-not $inRoot) {
        Import-Certificate -FilePath $resolvedCer -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
    }
    if (-not $inPub) {
        Import-Certificate -FilePath $resolvedCer -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
    }
    Write-Host "[+] Installed $CertThumbprint into LocalMachine\Root and LocalMachine\TrustedPublisher (Verified Publisher active)." -ForegroundColor Green
    return
}

if ($NoElevate -or ($env:CI -eq "true") -or (-not [Environment]::UserInteractive)) {
    Write-Host "[i] Non-elevated/CI session: run 'powershell -ExecutionPolicy Bypass -File scripts/trust_publisher_cert.ps1' once to elevate and trust $CertThumbprint in LocalMachine." -ForegroundColor Yellow
    return
}

Write-Host "[*] Requesting one-time Administrator elevation to trust $CertThumbprint in LocalMachine\Root & TrustedPublisher..." -ForegroundColor Cyan
$argList = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", "`"$PSCommandPath`"",
    "-CertThumbprint", $CertThumbprint,
    "-CerFilePath", "`"$resolvedCer`"",
    "-NoElevate"
)
$proc = Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs -Wait -PassThru
exit $proc.ExitCode
