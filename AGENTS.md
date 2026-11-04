# QuorumRAG agent rules

## Repository boundary (absolute)

- QuorumRAG is a **standalone repository**: https://github.com/oyesanyf/QuorumRAG
- The local working copy is `d:\harfile\QuorumRAG`. It has its own `.git`, and its `origin` is `https://github.com/oyesanyf/QuorumRAG.git`.
- Never commit, push, tag, release or open PRs for QuorumRAG code in any other repository. That includes the parent folder `d:\harfile`, which is the `oyesanyf/MusicFusion` repo.
- Never put QuorumRAG files, workflows or releases into MusicFusion. Never run `git` for QuorumRAG work from `d:\harfile`.
- QuorumRAG CI workflows live in this repo's `.github/workflows/`, never in the parent repo's.
- Before any git write, verify that `git rev-parse --show-toplevel` is `d:/harfile/QuorumRAG` and that `git remote get-url origin` is `oyesanyf/QuorumRAG`. If either check fails, stop and ask the user.
- `scripts/solo_pr_ship.ps1` and `scripts/publish_solo_release.py` enforce this and fail closed. Never weaken or bypass these guards.
