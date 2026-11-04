# Run all QuorumRAG E2E Test targets cleanly
$ErrorActionPreference = "Continue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Running QuorumRAG Comprehensive 4-Tier E2E Test Suite" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$targets = @(
    "test_storage_isolation",
    "test_gemma_contract",
    "test_ingestion_dedup",
    "test_federated_mesh",
    "test_web_endpoints",
    "test_cross_feature_combinations",
    "test_real_world_scenarios"
)

$totalPassed = 0
$totalFailed = 0
$results = @()

foreach ($target in $targets) {
    Write-Host "`n---> Executing target: $target..." -ForegroundColor Yellow
    
    # Pre-unblock any built exe to satisfy AppControl/WDAC
    $pattern = Join-Path $PSScriptRoot "target\debug\deps\${target}*.exe"
    Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue

    $output = & cargo test --manifest-path (Join-Path $PSScriptRoot "Cargo.toml") --test $target -- --nocapture 2>&1
    $exitCode = $LASTEXITCODE

    if ($exitCode -eq 0) {
        Write-Host "PASS: $target" -ForegroundColor Green
        $outStr = ($output | Out-String)
        if ($outStr -match "test result: ok\. (\d+) passed") {
            $count = [int]$matches[1]
            $totalPassed += $count
            $results += [PSCustomObject]@{ Target = $target; Status = "PASS"; Tests = $count }
        } else {
            $results += [PSCustomObject]@{ Target = $target; Status = "PASS"; Tests = 1 }
        }
    } else {
        Write-Host "FAIL: $target" -ForegroundColor Red
        $totalFailed += 1
        $results += [PSCustomObject]@{ Target = $target; Status = "FAIL"; Tests = 0 }
        Write-Host ($output | Out-String)
    }
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "E2E Test Execution Summary" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
$results | Format-Table -AutoSize
Write-Host "Total Passed Tests: $totalPassed" -ForegroundColor Green
Write-Host "Total Failed Targets: $totalFailed" -ForegroundColor $(if ($totalFailed -eq 0) { "Green" } else { "Red" })

if ($totalFailed -gt 0) {
    exit 1
} else {
    exit 0
}
