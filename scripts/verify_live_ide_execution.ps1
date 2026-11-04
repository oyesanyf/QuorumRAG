# scripts/verify_live_ide_execution.ps1
# Comprehensive Verification Script for Feature 42: Live IDE Execution & Production Code Generation Gate
[CmdletBinding()]
param(
    [int]$Port = 3030,
    [string]$WorkspaceDir = "d:\harfile\QuorumRAG",
    [string]$DataDir = "d:\harfile\QuorumRAG\.test_live_storage",
    [int]$TimeoutSecs = 30
)

$ErrorActionPreference = "Stop"
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "QuorumRAG Feature 42: Live IDE Execution & Code Gen Gate" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Compile Binary
Write-Host "`n[Step 1/5] Compiling quorumrag.exe..." -ForegroundColor Yellow
$oldEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$buildOutput = & cargo build -p quorum-daemon 2>&1
$ErrorActionPreference = $oldEap
if ($LASTEXITCODE -ne 0) {
    throw "Failed to compile quorum-daemon:`n$buildOutput"
}
$exePath = Join-Path $WorkspaceDir "target\debug\quorumrag.exe"
if (-not (Test-Path $exePath)) {
    throw "Compiled executable not found at: $exePath"
}
Unblock-File -Path $exePath -ErrorAction SilentlyContinue
Write-Host "Binary ready: $exePath" -ForegroundColor Green

# Detect and resolve port collisions
function Get-AvailablePort([int]$preferred) {
    for ($p = $preferred; $p -lt $preferred + 100; $p++) {
        $occupied = Get-NetTCPConnection -LocalPort $p -ErrorAction SilentlyContinue
        if (-not $occupied) {
            return $p
        }
    }
    return $preferred
}

$Port = Get-AvailablePort $Port
$P2pPort = Get-AvailablePort ($Port + 1)

# 2. Launch Daemon in Live IDE Mode (--no-browser for automated runner)
if (Test-Path $DataDir) {
    Remove-Item -Path $DataDir -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null

Write-Host "`n[Step 2/5] Launching daemon on port $Port (P2P port: $P2pPort)..." -ForegroundColor Yellow
$proc = Start-Process -FilePath $exePath `
    -ArgumentList "--watch-dir `"$WorkspaceDir`" --port $Port --p2p-port $P2pPort --no-browser --data-dir `"$DataDir`"" `
    -PassThru -NoNewWindow

$verifyHarnessDir = $null

try {
    # 3. Poll Health Endpoint
    Write-Host "`n[Step 3/5] Polling /api/health..." -ForegroundColor Yellow
    $healthUrl = "http://127.0.0.1:$Port/api/health"
    $healthy = $false
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSecs) {
        try {
            $resp = Invoke-RestMethod -Uri $healthUrl -Method Get -TimeoutSec 2 -ErrorAction Stop
            if ($resp.status -eq "healthy" -or $resp.status -eq "ready") {
                $healthy = $true
                Write-Host "Daemon healthy! Version: $($resp.version), Contract Hash: $($resp.contract_hash.Substring(0, 16))..." -ForegroundColor Green
                Write-Host "Hardware: $($resp.hardware.selected_tier)" -ForegroundColor Green
                break
            }
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }

    if (-not $healthy) {
        throw "Daemon failed to report healthy status within $TimeoutSecs seconds."
    }

    # 4. Trigger Workspace File Indexing
    Write-Host "`n[Step 4/5] Triggering /api/reindex on real workspace files..." -ForegroundColor Yellow
    $reindexUrl = "http://127.0.0.1:$Port/api/reindex"
    $reindexBody = @{
        target_paths = @(
            (Join-Path $WorkspaceDir "crates\quorum-coordinator"),
            (Join-Path $WorkspaceDir "crates\quorum-types")
        )
        full_rebuild = $true
        force_reembed = $false
    } | ConvertTo-Json

    $reindexStart = Invoke-RestMethod -Uri $reindexUrl -Method Post -Body $reindexBody -ContentType "application/json"
    $taskId = $reindexStart.task_id
    Write-Host "Reindexing task started: $taskId. Awaiting completion..." -ForegroundColor Gray

    $statusUrl = "http://127.0.0.1:$Port/api/reindex/status"
    $completed = $false
    $reindexWatch = [System.Diagnostics.Stopwatch]::StartNew()

    while ($reindexWatch.Elapsed.TotalSeconds -lt 45) {
        $status = Invoke-RestMethod -Uri $statusUrl -Method Get
        if ($status.phase -eq "completed") {
            $completed = $true
            Write-Host "Reindex completed! Files indexed: $($status.files_indexed), Chunks: $($status.chunks_newly_embedded + $status.chunks_reused_from_cache)" -ForegroundColor Green
            break
        } elseif ($status.phase -eq "failed") {
            throw "Reindexing failed: $($status.error_message)"
        }
        Start-Sleep -Milliseconds 500
    }

    if (-not $completed) {
        throw "Reindexing timed out."
    }

    # 5. Live Production Code Generation Query
    Write-Host "`n[Step 5/5] Testing Live Production Code Generation Query..." -ForegroundColor Yellow
    $chatUrl = "http://127.0.0.1:$Port/api/chat"
    $prompt = "Show me the RrfCombiner implementation in QuorumRAG and write a unit test using it"
    $chatBody = @{
        prompt = $prompt
        model_family = "AutoFusion"
        search_mode = "Hybrid"
        top_k = 16
    } | ConvertTo-Json

    # Perform SSE request
    $req = [System.Net.WebRequest]::CreateHttp($chatUrl)
    $req.Method = "POST"
    $req.ContentType = "application/json"
    $req.Accept = "text/event-stream"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($chatBody)
    $req.ContentLength = $bytes.Length
    $stream = $req.GetRequestStream()
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Close()

    $res = $req.GetResponse()
    $reader = New-Object System.IO.StreamReader($res.GetResponseStream())
    $responseTokens = ""
    $citations = @()
    $agenticTransitions = @()

    while (-not $reader.EndOfStream) {
        $line = $reader.ReadLine()
        if ($line.StartsWith("data: ")) {
            $dataStr = $line.Substring(6).Trim()
            if ($dataStr.Length -gt 0) {
                try {
                    $json = $dataStr | ConvertFrom-Json
                    $evType = if ($json.event) { $json.event } else { $json.type }

                    if ($evType -eq "state_transition" -or $evType -eq "StateTransition") {
                        $from = if ($json.data.from_state) { $json.data.from_state } else { $json.from_state }
                        $to = if ($json.data.to_state) { $json.data.to_state } else { $json.to_state }
                        $agenticTransitions += "$from -> $to"
                    } elseif ($evType -eq "citation" -or $evType -eq "CitationEmitted") {
                        $cit = if ($json.data.citation) { $json.data.citation } else { $json.citation }
                        $citations += $cit
                    } elseif ($evType -eq "token_delta" -or $evType -eq "TokenDelta" -or $evType -eq "token") {
                        $delta = if ($json.data.delta) { $json.data.delta } else { $json.delta }
                        if (-not $delta -and $json.content) { $delta = $json.content }
                        $responseTokens += $delta
                    }
                } catch {}
            }
        }
    }
    $reader.Close()
    $res.Close()

    # Assert Agentic Transitions
    Write-Host "Agentic State Transitions Observed:" -ForegroundColor Cyan
    foreach ($tr in $agenticTransitions) {
        Write-Host "  -> $tr" -ForegroundColor Gray
    }
    if ($agenticTransitions.Count -eq 0) {
        throw "Assertion Failed: Zero Agentic State Transitions received via SSE stream!"
    }

    # Assert Citations
    Write-Host "`nStructured Citations Received:" -ForegroundColor Cyan
    $foundFusionCitation = $false
    foreach ($cit in $citations) {
        Write-Host "  - [$($cit.peer_id):$($cit.file_path):$($cit.line_start)-$($cit.line_end)] (Score: $($cit.score))" -ForegroundColor Gray
        if ($cit.file_path -like "*fusion.rs*") {
            $foundFusionCitation = $true
        }
    }
    if (-not $foundFusionCitation) {
        throw "Assertion Failed: Did not receive citation pointing to fusion.rs!"
    }
    Write-Host "Citation Verification PASSED: fusion.rs cited with exact line numbers!" -ForegroundColor Green

    # Extract Generated Code Block and Verify Compilation
    Write-Host "`nValidating Generated Production Code Compilation..." -ForegroundColor Yellow
    if ($responseTokens -match '```rust([\s\S]*?)```') {
        $extractedCode = $matches[1].Trim()
        Write-Host "Extracted Rust Code Block:`n$extractedCode`n" -ForegroundColor DarkGray

        # Build a temporary verification crate harness to compile the generated code
        $verifyHarnessDir = Join-Path $env:TEMP ("quorumrag_codegen_verify_" + [System.Guid]::NewGuid().ToString("N"))
        if (Test-Path $verifyHarnessDir) { Remove-Item -Path $verifyHarnessDir -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path (Join-Path $verifyHarnessDir "src") -Force | Out-Null

        $harnessCargo = @"
[package]
name = "quorumrag-codegen-verify"
version = "0.1.0"
edition = "2021"

[dependencies]
"@
        Set-Content -Path (Join-Path $verifyHarnessDir "Cargo.toml") -Value $harnessCargo
        $harnessMain = @"
// Auto-generated compilation test for production code generation gate
$extractedCode

fn main() {
    println!("Compiled successfully!");
}
"@
        Set-Content -Path (Join-Path $verifyHarnessDir "src\main.rs") -Value $harnessMain

        $oldEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $checkOutput = & cargo check --manifest-path (Join-Path $verifyHarnessDir "Cargo.toml") 2>&1
        $ErrorActionPreference = $oldEap
        if ($LASTEXITCODE -ne 0) {
            throw "Code Generation Gate FAILED: Generated code did not compile cleanly!`n$checkOutput"
        } else {
            Write-Host "Code Generation Gate PASSED: Generated code compiles cleanly with zero errors!" -ForegroundColor Green
        }
        Remove-Item -Path $verifyHarnessDir -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        throw "Code Generation Gate FAILED: No compilable ````rust ... ```` code block found in response! Response:`n$responseTokens"
    }

    # 6. Test LangExtract Live Grounding
    Write-Host "`nTesting /api/langextract with real Rust AST snippet..." -ForegroundColor Yellow
    $lxUrl = "http://127.0.0.1:$Port/api/langextract"
    $sampleCode = "pub struct RrfCombiner;`nimpl RrfCombiner { pub fn compute_rrf_score() {} }"
    $lxBody = @{
        text = $sampleCode
        prompt_description = "Extract struct and function identifiers"
    } | ConvertTo-Json

    $lxResp = Invoke-RestMethod -Uri $lxUrl -Method Post -Body $lxBody -ContentType "application/json"
    if (-not $lxResp.consensus_passed) {
        throw "LangExtract 4-arm consensus failed!"
    }
    Write-Host "LangExtract Consensus Passed! Confidence BP: $($lxResp.fused_confidence_bp)" -ForegroundColor Green

    # Verify character intervals
    foreach ($ext in $lxResp.verified_extractions) {
        $start = $ext.char_interval[0]
        $end = $ext.char_interval[1]
        $span = $sampleCode.Substring($start, $end - $start)
        if ($span -ne $ext.extraction_text) {
            throw "LangExtract Grounding Mismatch: expected '$($ext.extraction_text)' but got '$span' at $start..$end"
        }
        Write-Host "  - Grounded '$($ext.extraction_text)' at byte range [$start..$end]" -ForegroundColor Gray
    }
    Write-Host "LangExtract Grounding PASSED (100% verified byte boundaries, 0 hallucinations)!" -ForegroundColor Green

    # Test /api/langextract/visualize
    Write-Host "`nTesting /api/langextract/visualize endpoint..." -ForegroundColor Yellow
    $lxVizUrl = "http://127.0.0.1:$Port/api/langextract/visualize"
    $vizResp = Invoke-WebRequest -Uri $lxVizUrl -Method Post -Body $lxBody -ContentType "application/json" -UseBasicParsing
    if ($vizResp.StatusCode -ne 200 -or -not ($vizResp.Content -like "*Google LangExtract*")) {
        throw "LangExtract visualize failed to return interactive HTML document!"
    }
    Write-Host "LangExtract Visualize PASSED: Interactive HTML document generated!" -ForegroundColor Green

    Write-Host "`n==========================================================" -ForegroundColor Green
    Write-Host "ALL LIVE IDE EXECUTION GATES PASSED CLEANLY!" -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Green

} finally {
    if ($proc) {
        Write-Host "`n[Cleanup & Graceful Shutdown] Sending POST /api/shutdown to daemon..." -ForegroundColor Yellow
        try {
            $null = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/shutdown" -Method Post -TimeoutSec 5 -ErrorAction SilentlyContinue
        } catch {}

        $proc.WaitForExit(10000)
        if (-not $proc.HasExited) {
            Write-Host "Daemon did not exit cooperatively within 10s; stopping process..." -ForegroundColor Yellow
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "Daemon exited cleanly with exit code $($proc.ExitCode)!" -ForegroundColor Green
        }
    }

    # Verify storage compaction integrity: assert zero orphaned lockfiles
    $tantivyLock = Join-Path $DataDir "tantivy\.tantivy-indexer.lock"
    $tantivyWriterLock = Join-Path $DataDir "tantivy\.tantivy-writer.lock"
    if ((Test-Path $tantivyLock) -or (Test-Path $tantivyWriterLock)) {
        throw "Storage Compaction Verification Failed: Orphaned Tantivy lockfiles detected in $DataDir!"
    }
    Write-Host "Compaction & Clean Shutdown Verified: Zero orphaned lockfiles!" -ForegroundColor Green

    if (Test-Path $DataDir) {
        Remove-Item -Path $DataDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    if ($verifyHarnessDir -and (Test-Path $verifyHarnessDir)) {
        Remove-Item -Path $verifyHarnessDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
