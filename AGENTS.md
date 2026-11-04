# QuorumRAG agent rules

## Repository boundary (absolute)

- QuorumRAG is a **standalone repository**: https://github.com/oyesanyf/QuorumRAG
- The local working copy is `d:\harfile\QuorumRAG`. It has its own `.git`, and its `origin` is `https://github.com/oyesanyf/QuorumRAG.git`.
- Never commit, push, tag, release or open PRs for QuorumRAG code in any other repository. That includes the parent folder `d:\harfile`, which is the `oyesanyf/MusicFusion` repo.
- Never put QuorumRAG files, workflows or releases into MusicFusion. Never run `git` for QuorumRAG work from `d:\harfile`.
- QuorumRAG CI workflows live in this repo's `.github/workflows/`, never in the parent repo's.
- Before any git write, verify that `git rev-parse --show-toplevel` is `d:/harfile/QuorumRAG` and that `git remote get-url origin` is `oyesanyf/QuorumRAG`. If either check fails, stop and ask the user.
- `scripts/solo_pr_ship.ps1` and `scripts/publish_solo_release.py` enforce this and fail closed. Never weaken or bypass these guards.

## Solo-developer shipping (same model as the OsoosiEDR repo)

- Every change reaches `main` through a pull request. Nobody pushes to `main` directly.
- Ship with `powershell -ExecutionPolicy Bypass -File scripts/solo_pr_ship.ps1 -SkipTest -Title '...' -BodyFile <md>`.
- The `.githooks/post-commit` hook runs the same script automatically for commits made on `main`. Enable it once per clone with `git config core.hooksPath .githooks`.
- On every pull request:
  - The PR invariant gate (`.github/workflows/quorumrag-auto-review-bot.yml`) checks for private keys, PATH/environment mutation, build.rs network calls and workflow privilege escalation, then approves.
  - **RAPTOR runs on every pull request** (`.github/workflows/raptor-security.yml`). The scan covers SAST, post-quantum crypto, SCA, a CycloneDX SBOM and OSV-Scanner.
- RAPTOR is the required status check on `main`. `solo_pr_ship.ps1` merges only after RAPTOR passes. If RAPTOR fails or times out, the PR stays open and unmerged until every finding is fixed.
- The RAPTOR gate fails when it parses 0 SARIF files. Never weaken that check.
- RAPTOR also runs:
  - nightly in CI (cron `30 2 * * *` UTC),
  - nightly on this machine through the Windows Scheduled Task `QuorumRAG-Nightly-Raptor-Security-Audit` (`scripts/run_nightly_raptor_audit.ps1`).
- Custom Semgrep rules live in `.raptor/rules/`.
