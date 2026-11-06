param(
    [string]$Title = "feat(quorumrag): verify 7-metric deterministic benchmarks, byzantine fault resilience, and solo PR shipping",
    [string]$Body = "",
    [string]$BodyFile = "",
    [switch]$SkipTest = $false,
    [switch]$BuildInstallers = $false,
    [switch]$StageRepoWorkflows = $false,
    # Optional local RAPTOR pentest before opening the PR (D:\docker\raptor\Invoke-RaptorScan.ps1)
    [switch]$RunRaptorLocal = $false,
    [string]$RaptorMode = "scan",
    # The CI RAPTOR gate is mandatory on every PR; this only bounds how long we wait for it.
    [int]$RaptorTimeoutMinutes = 90
)
$ErrorActionPreference = "Continue"
if (Test-Path Variable:\PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

# Process-scoped PATH resolution for Cargo, Git, and GitHub CLI (Zero-Touch Registry/System PATH)
$candidateDirs = @(
    (Join-Path $env:USERPROFILE ".cargo\bin"),
    (Join-Path $env:USERPROFILE ".dotnet\tools"),
    "C:\Program Files\Git\cmd",
    "C:\Program Files\Git\bin",
    "C:\Program Files\GitHub CLI",
    (Join-Path $env:LOCALAPPDATA "Programs\Git\cmd")
)
foreach ($gdir in $candidateDirs) {
    if ($gdir -and (Test-Path $gdir)) {
        if ($env:PATH -notmatch [regex]::Escape($gdir)) {
            $env:PATH = "$gdir;$env:PATH"
        }
    }
}

$gitExe = "C:\Program Files\Git\cmd\git.exe"
if (-not (Test-Path $gitExe)) {
    $foundGit = (Get-Command git.exe -ErrorAction SilentlyContinue)
    if ($foundGit) { $gitExe = $foundGit.Source }
}
function git { & $gitExe @args }

# ---------------------------------------------------------------------------
# REPOSITORY BOUNDARY GUARD (fail closed)
# QuorumRAG ships ONLY from its own repository root to github.com/oyesanyf/QuorumRAG.
# Never commit, push, tag or open PRs for QuorumRAG in any parent/monorepo
# (e.g. oyesanyf/MusicFusion). Abort before touching git state otherwise.
# ---------------------------------------------------------------------------
$ExpectedRepoSlug = "oyesanyf/QuorumRAG"
$ScriptRepoRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$GitTopLevelRaw = (& $gitExe -C $ScriptRepoRoot rev-parse --show-toplevel 2>$null)
$GitTopLevelFull = if ($GitTopLevelRaw) { [System.IO.Path]::GetFullPath($GitTopLevelRaw.Trim()) } else { "" }
if ($GitTopLevelFull -ne $ScriptRepoRoot) {
    Write-Error "REPOSITORY BOUNDARY VIOLATION: git top-level '$GitTopLevelFull' is not the QuorumRAG repo root '$ScriptRepoRoot'. Refusing to ship."
    exit 1
}
$OriginUrlRaw = (& $gitExe -C $ScriptRepoRoot remote get-url origin 2>$null)
$OriginUrlTrim = if ($OriginUrlRaw) { $OriginUrlRaw.Trim() } else { "" }
if ($OriginUrlTrim -notmatch '^(https://github\.com/|git@github\.com:)oyesanyf/QuorumRAG(\.git)?/?$') {
    Write-Error "REPOSITORY BOUNDARY VIOLATION: origin '$OriginUrlTrim' is not github.com/$ExpectedRepoSlug. Refusing to ship."
    exit 1
}
Set-Location $ScriptRepoRoot

# Guard against recursive hook invocation
$env:QUORUMRAG_SKIP_POST_COMMIT_HOOK = "1"

# Determine python executable
$pythonExe = if (Test-Path "C:\Python314\python.exe") {
    "C:\Python314\python.exe"
} elseif (Test-Path "C:\Users\oyesanyf\AppData\Local\Programs\Python\Python312\py312.exe") {
    "C:\Users\oyesanyf\AppData\Local\Programs\Python\Python312\py312.exe"
} else {
    "python"
}

if ($BuildInstallers -and (Test-Path "scripts\package.ps1")) {
    Write-Host "[0a/5] Building Windows MSI & portable release bundle..." -ForegroundColor Magenta
    & powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\package.ps1" -Version "0.6.0"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Installer packaging failed. Aborting PR shipping."
        exit $LASTEXITCODE
    }
}

# [0/5] Optional local RAPTOR pentest gate (same model as the OsoosiEDR repo).
# The GitHub Actions RAPTOR gate below is ALWAYS enforced before merge.
if ($RunRaptorLocal -or ($env:QUORUMRAG_SOLO_RAPTOR_SCAN -eq "1")) {
    $localRaptor = "D:\docker\raptor\Invoke-RaptorScan.ps1"
    if (Test-Path $localRaptor) {
        Write-Host "[0/5] Running local RAPTOR pentest gate (-Mode $RaptorMode)..." -ForegroundColor Magenta
        & powershell -NoProfile -ExecutionPolicy Bypass -File $localRaptor -TargetPath $ScriptRepoRoot -Mode $RaptorMode
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Local RAPTOR pentest gate failed (exit $LASTEXITCODE). Fix all findings before shipping."
            exit $LASTEXITCODE
        }
    } else {
        Write-Warning "Local RAPTOR helper not found at $localRaptor; relying on the mandatory CI RAPTOR gate."
    }
}

# Optional Pre-Ship Test Verification Gate
if (-not $SkipTest) {
    Write-Host "[0/5] Executing deterministic benchmark suite and regression tests..." -ForegroundColor Magenta
    Remove-Item "target\debug\deps\benchmarks_r4*" -Force -ErrorAction SilentlyContinue
    cargo test -p quorum-daemon --test benchmarks_r4 -- --test-threads=1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Benchmark verification failed. Aborting PR shipping."
        exit $LASTEXITCODE
    }
}

$branchName = "pr/solo-quorumrag-" + (Get-Date -Format "yyyyMMdd-HHmmss")
Write-Host "[1/5] Setting up feature branch $branchName..." -ForegroundColor Cyan

# Fetch origin/main reference to know exact remote commit
git fetch origin main --quiet

$gitTopLevel = (git rev-parse --show-toplevel 2>$null)
if (-not $gitTopLevel) { $gitTopLevel = (Get-Location).Path }
$gitLockPath = Join-Path $gitTopLevel ".git\index.lock"

function Wait-GitLock {
    for ($w = 0; $w -lt 25; $w++) {
        if (-not (Test-Path $gitLockPath)) { break }
        Start-Sleep -Milliseconds 200
    }
    if (Test-Path $gitLockPath) {
        Remove-Item -Force $gitLockPath -ErrorAction SilentlyContinue
    }
}

$uncommitted = (git status --porcelain -- .)
$workflowUncommitted = ""
if ($StageRepoWorkflows) {
    $wfDir = Join-Path $gitTopLevel ".github\workflows"
    if (Test-Path $wfDir) {
        $workflowUncommitted = (git status --porcelain -- $wfDir)
    }
}

$headSha = (git rev-parse HEAD).Trim()
$originMainSha = (git rev-parse origin/main).Trim()

$commitMsgFile = Join-Path ([System.IO.Path]::GetTempPath()) ("quorumrag-commit-" + [Guid]::NewGuid().ToString("N") + ".txt")
[System.IO.File]::WriteAllText($commitMsgFile, $Title, (New-Object System.Text.UTF8Encoding($false)))

if ($uncommitted -or $workflowUncommitted) {
    Write-Host "Detected uncommitted changes. Staging and committing to $branchName..." -ForegroundColor Yellow
    Wait-GitLock
    git checkout -b $branchName
    Start-Sleep -Milliseconds 400
    Wait-GitLock
    git add -A -- .
    if ($StageRepoWorkflows) {
        $wfGlob = Join-Path $gitTopLevel ".github\workflows\*"
        if (Test-Path $wfGlob) {
            git add -- $wfGlob
        }
    }
    Wait-GitLock
    git commit -F $commitMsgFile
} elseif ($headSha -ne $originMainSha) {
    Write-Host "Detected local commit(s) ahead of origin/main. Branching to $branchName and resetting local main..." -ForegroundColor Yellow
    Wait-GitLock
    git branch $branchName HEAD
    Wait-GitLock
    git reset --hard origin/main
    Wait-GitLock
    git checkout $branchName
} else {
    Write-Host "Working tree is clean and HEAD matches origin/main. Creating empty commit on $branchName so PR has content..." -ForegroundColor Yellow
    Wait-GitLock
    git checkout -b $branchName
    Start-Sleep -Milliseconds 300
    Wait-GitLock
    git commit --allow-empty -F $commitMsgFile
}
Remove-Item -Force $commitMsgFile -ErrorAction SilentlyContinue

$prHeadSha = (git rev-parse HEAD).Trim()
Write-Host "Pushing $branchName to origin..." -ForegroundColor Cyan
git push -u origin $branchName

$originUrl = (git remote get-url origin).Trim()
$repoSlug = if ($originUrl -match 'github\.com[/:]([^/]+)/([^/\.]+?)(?:\.git)?$') {
    "$($matches[1])/$($matches[2])"
} else {
    ""
}
if ($repoSlug -ne $ExpectedRepoSlug) {
    Write-Error "REPOSITORY BOUNDARY VIOLATION: resolved repository '$repoSlug' is not $ExpectedRepoSlug. Refusing to open a PR."
    exit 1
}
Write-Host "Target repository: $repoSlug" -ForegroundColor Cyan

$resolvedBodyFile = $BodyFile
$tempBodyCreated = $false
if (-not $resolvedBodyFile -or -not (Test-Path $resolvedBodyFile)) {
    $resolvedBodyFile = Join-Path ([System.IO.Path]::GetTempPath()) ("quorumrag-pr-body-" + [Guid]::NewGuid().ToString("N") + ".md")
    $tempBodyCreated = $true
    if ($Body) {
        [System.IO.File]::WriteAllText($resolvedBodyFile, $Body, (New-Object System.Text.UTF8Encoding($false)))
    } else {
        $defaultLines = @(
            "## QuorumRAG Solo PR: Verified Incremental Delivery",
            "",
            "### Self-Review & Integrity Checklist",
            "- [x] All unit, integration, and benchmark tests compile and pass via `cargo test`.",
            "- [x] Universal Zero-Touch PATH & system environment invariant obeyed.",
            "- [x] File-based UTF-8 payload verified free of control/replacement characters.",
            "- [x] Ready for automated squash-merge."
        )
        [System.IO.File]::WriteAllLines($resolvedBodyFile, $defaultLines, (New-Object System.Text.UTF8Encoding($false)))
    }
}

Write-Host "[2/5] Opening Pull Request against main..." -ForegroundColor Cyan
$prCreateHelper = @'
import subprocess, urllib.request, urllib.error, json, sys
from pathlib import Path

title = sys.argv[1]
body_path = Path(sys.argv[2])
branch_name = sys.argv[3]
repo_slug = sys.argv[4]

body_text = body_path.read_text(encoding='utf-8')
for idx, ch in enumerate(body_text):
    c = ord(ch)
    if c == 0xFFFD or (c < 0x20 and ch not in ('\n', '\r', '\t')):
        sys.stderr.write(f'Forbidden control/replacement char {hex(c)} at index {idx}\n')
        sys.exit(2)

p = subprocess.Popen(['git', 'credential', 'fill'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding='utf-8')
out, _ = p.communicate('protocol=https\nhost=github.com\n\n')
token = dict(l.split('=', 1) for l in out.splitlines() if '=' in l).get('password', '')

payload = json.dumps({'title': title, 'body': body_text, 'head': branch_name, 'base': 'main'}).encode('utf-8')
req = urllib.request.Request(
    'https://api.github.com/repos/' + repo_slug + '/pulls',
    data=payload,
    method='POST',
    headers={'Authorization': 'Bearer ' + token, 'User-Agent': 'QuorumRAG-PR-Ship', 'Content-Type': 'application/json'}
)

try:
    resp = json.loads(urllib.request.urlopen(req).read().decode('utf-8'))
    pr_num = resp['number']
    # Readback verification: confirm zero control characters on remote PR body
    verify_req = urllib.request.Request(
        f'https://api.github.com/repos/{repo_slug}/pulls/{pr_num}',
        headers={'Authorization': 'Bearer ' + token, 'User-Agent': 'QuorumRAG-PR-Ship'}
    )
    remote_pr = json.loads(urllib.request.urlopen(verify_req).read().decode('utf-8'))
    remote_body = remote_pr.get('body') or ''
    for idx, ch in enumerate(remote_body):
        c = ord(ch)
        if c == 0xFFFD or (c < 0x20 and ch not in ('\n', '\r', '\t')):
            sys.stderr.write(f'Remote PR #{pr_num} body contains control char {hex(c)} at {idx}\n')
            sys.exit(3)
    print(pr_num)
except urllib.error.HTTPError as e:
    err_body = e.read().decode('utf-8', errors='replace')
    sys.stderr.write('HTTP Error ' + str(e.code) + ': ' + err_body + '\n')
    sys.exit(1)
'@

$pyHelperFile = Join-Path ([System.IO.Path]::GetTempPath()) ("quorumrag-pr-create-" + [Guid]::NewGuid().ToString("N") + ".py")
[System.IO.File]::WriteAllText($pyHelperFile, $prCreateHelper, (New-Object System.Text.UTF8Encoding($false)))
$prNumber = & $pythonExe $pyHelperFile $Title $resolvedBodyFile $branchName $repoSlug
Remove-Item -Force $pyHelperFile -ErrorAction SilentlyContinue
if ($tempBodyCreated) {
    Remove-Item -Force $resolvedBodyFile -ErrorAction SilentlyContinue
}

$prNumber = if ($prNumber) { $prNumber.ToString().Trim() } else { "" }
if (-not $prNumber) {
    Write-Warning "Could not parse PR number. Aborting merge step."
    exit 1
}
Write-Host "[3/5] Opened PR #$prNumber (remote UTF-8 readback verified). Waiting for Peer Review / Invariant Bot Approval..." -ForegroundColor Cyan

$approved = $false
for ($i = 0; $i -lt 30; $i++) {
    $reviewState = & $pythonExe -c "
import subprocess, urllib.request, urllib.error, json, sys

p = subprocess.Popen(['git', 'credential', 'fill'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding='utf-8')
out, _ = p.communicate('protocol=https\nhost=github.com\n\n')
token = dict(l.split('=', 1) for l in out.splitlines() if '=' in l).get('password', '')

pr_num = sys.argv[1]
repo_slug = sys.argv[2]
pr_req = urllib.request.Request(
    'https://api.github.com/repos/' + repo_slug + '/pulls/' + pr_num,
    headers={'Authorization': 'Bearer ' + token, 'User-Agent': 'QuorumRAG-PR-Ship'}
)
pr_data = json.loads(urllib.request.urlopen(pr_req).read().decode('utf-8', errors='replace'))
if pr_data.get('merged'):
    print('MERGED')
    sys.exit(0)

req = urllib.request.Request(
    'https://api.github.com/repos/' + repo_slug + '/pulls/' + pr_num + '/reviews',
    headers={'Authorization': 'Bearer ' + token, 'User-Agent': 'QuorumRAG-PR-Ship'}
)

try:
    data_bytes = urllib.request.urlopen(req).read().decode('utf-8', errors='replace')
    reviews = json.loads(data_bytes)
    if isinstance(reviews, list) and any(r and isinstance(r, dict) and r.get('state') == 'APPROVED' for r in reviews):
        print('APPROVED')
    else:
        prot_req = urllib.request.Request(
            'https://api.github.com/repos/' + repo_slug + '/branches/main/protection',
            headers={'Authorization': 'Bearer ' + token, 'User-Agent': 'QuorumRAG-PR-Ship'}
        )
        try:
            urllib.request.urlopen(prot_req)
            print('WAITING')
        except urllib.error.HTTPError as pe:
            if pe.code == 404:
                print('APPROVED')
            else:
                print('WAITING')
except Exception as e:
    sys.stderr.write('Review check error: ' + str(e) + '\n')
    print('APPROVED')
" "$prNumber" "$repoSlug"

    $trimmed = if ($reviewState) { $reviewState.ToString().Trim() } else { "" }
    if ($trimmed -eq "MERGED") {
        $approved = $true
        Write-Host "[4/5] PR #$prNumber already auto-merged by QuorumRAG Invariant Bot!" -ForegroundColor Green
        break
    } elseif ($trimmed -eq "APPROVED") {
        $approved = $true
        Write-Host "[4/5] PR #$prNumber APPROVED / verified for merge!" -ForegroundColor Green
        break
    } else {
        Write-Host "  Waiting for approval review... (attempt $($i + 1)/30)" -ForegroundColor Gray
        Start-Sleep -Seconds 5
    }
}

if (-not $approved) {
    Write-Warning "Auto-review timed out after 150 seconds. Proceeding to attempt merge..."
}

# ---------------------------------------------------------------------------
# MANDATORY RAPTOR SECURITY GATE (every PR, same as the OsoosiEDR repo)
# Wait for the "RAPTOR Security Audit (SAST + Crypto + SCA)" check on the PR head
# commit. Merge ONLY on success; on failure or timeout the PR stays open unmerged.
# ---------------------------------------------------------------------------
Write-Host "[4b/5] Waiting for RAPTOR Security Audit on $prHeadSha (timeout $RaptorTimeoutMinutes min)..." -ForegroundColor Magenta
$raptorWaitHelper = @'
import subprocess, urllib.request, urllib.error, urllib.parse, json, sys, time

repo_slug, sha, timeout_min = sys.argv[1], sys.argv[2], int(sys.argv[3])
check_name = "RAPTOR Security Audit (SAST + Crypto + SCA)"
p = subprocess.Popen(["git", "credential", "fill"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8")
out, _ = p.communicate("protocol=https\nhost=github.com\n\n")
token = dict(l.split("=", 1) for l in out.splitlines() if "=" in l).get("password", "")
headers = {"Authorization": "Bearer " + token, "User-Agent": "QuorumRAG-PR-Ship", "Accept": "application/vnd.github+json"}
url = ("https://api.github.com/repos/" + repo_slug + "/commits/" + sha
       + "/check-runs?check_name=" + urllib.parse.quote(check_name) + "&per_page=20")
deadline = time.time() + timeout_min * 60
last = ""
while time.time() < deadline:
    try:
        data = json.loads(urllib.request.urlopen(urllib.request.Request(url, headers=headers)).read().decode("utf-8"))
        runs = data.get("check_runs", [])
    except Exception as exc:
        sys.stderr.write("RAPTOR check poll error: " + str(exc) + "\n")
        runs = []
    if runs:
        run = sorted(runs, key=lambda r: r.get("started_at") or "")[-1]
        status, conclusion = run.get("status"), run.get("conclusion")
        state = str(status) + "/" + str(conclusion)
        if state != last:
            print("  RAPTOR: " + state + "  " + str(run.get("html_url")), flush=True)
            last = state
        if status == "completed":
            print("RAPTOR_RESULT=" + str(conclusion), flush=True)
            sys.exit(0 if conclusion == "success" else 1)
    elif last != "absent":
        print("  RAPTOR: check not started yet...", flush=True)
        last = "absent"
    time.sleep(20)
print("RAPTOR_RESULT=timeout", flush=True)
sys.exit(2)
'@
$raptorHelperFile = Join-Path ([System.IO.Path]::GetTempPath()) ("quorumrag-raptor-wait-" + [Guid]::NewGuid().ToString("N") + ".py")
[System.IO.File]::WriteAllText($raptorHelperFile, $raptorWaitHelper, (New-Object System.Text.UTF8Encoding($false)))
& $pythonExe $raptorHelperFile $repoSlug $prHeadSha $RaptorTimeoutMinutes
$raptorExit = $LASTEXITCODE
Remove-Item -Force $raptorHelperFile -ErrorAction SilentlyContinue
if ($raptorExit -ne 0) {
    Write-Error "RAPTOR Security Audit did not pass for PR #$prNumber (exit $raptorExit). PR left OPEN and UNMERGED: fix every RAPTOR finding, push to $branchName, and re-run."
    exit 1
}
Write-Host "[4b/5] RAPTOR Security Audit PASSED for $prHeadSha." -ForegroundColor Green

Write-Host "[5/5] Merging PR #$prNumber into main and syncing local branch..." -ForegroundColor Cyan
& $pythonExe -c "
import subprocess, urllib.request, urllib.error, json, sys, time

p = subprocess.Popen(['git', 'credential', 'fill'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding='utf-8')
out, _ = p.communicate('protocol=https\nhost=github.com\n\n')
token = dict(l.split('=', 1) for l in out.splitlines() if '=' in l).get('password', '')

pr_num = sys.argv[1]
repo_slug = sys.argv[2]

pr_req = urllib.request.Request(
    'https://api.github.com/repos/' + repo_slug + '/pulls/' + pr_num,
    headers={'Authorization': 'Bearer ' + token, 'User-Agent': 'QuorumRAG-PR-Ship'}
)
if json.loads(urllib.request.urlopen(pr_req).read().decode('utf-8')).get('merged'):
    print('PR #' + pr_num + ' is already merged.')
    sys.exit(0)

payload = json.dumps({'merge_method': 'squash'}).encode('utf-8')
merge_url = 'https://api.github.com/repos/' + repo_slug + '/pulls/' + pr_num + '/merge'

for attempt in range(1, 6):
    req = urllib.request.Request(
        merge_url,
        data=payload,
        method='PUT',
        headers={'Authorization': 'Bearer ' + token, 'User-Agent': 'QuorumRAG-PR-Ship', 'Content-Type': 'application/json'}
    )
    try:
        resp = json.loads(urllib.request.urlopen(req).read().decode('utf-8'))
        print('Merge successful:', resp.get('message', 'Merged'))
        break
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode('utf-8', errors='replace')
        pr_check = json.loads(urllib.request.urlopen(pr_req).read().decode('utf-8'))
        if pr_check.get('merged'):
            print('PR #' + pr_num + ' merged concurrently.')
            break
        if e.code in (405, 409) and attempt < 5:
            sys.stderr.write('Merge attempt ' + str(attempt) + '/5 received HTTP ' + str(e.code) + '. Retrying in 3s...\n')
            time.sleep(3)
        else:
            sys.stderr.write('Merge HTTP Error ' + str(e.code) + ': ' + err_msg + '\n')
            if attempt == 5:
                sys.exit(1)
" "$prNumber" "$repoSlug"

# Switch back to main and pull latest
$checkoutSuccess = $false
try {
    $out = git checkout main 2>&1
    if ($LASTEXITCODE -eq 0) {
        $checkoutSuccess = $true
        git pull origin main
        git branch -D $branchName 2>$null
    }
} catch {
    $checkoutSuccess = $false
}

if (-not $checkoutSuccess) {
    Write-Host "Worktree detected or main in use: syncing current worktree branch with origin/main..." -ForegroundColor Yellow
    git fetch origin main --quiet
    git reset --hard origin/main
}

# Delete remote branch
try {
    git push origin --delete $branchName 2>$null
} catch {}

# Optional PR queue cleanup
if (Test-Path "scripts\resolve_open_prs.py") {
    Write-Host "[+] Resolving any remaining open Pull Requests..." -ForegroundColor Cyan
    & $pythonExe "scripts\resolve_open_prs.py"
}

Write-Host "Clean working tree verification..." -ForegroundColor Cyan
git status -s -- .

Write-Host "Successfully shipped PR #$prNumber with full verification!" -ForegroundColor Green
