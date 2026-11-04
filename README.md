# QuorumRAG

[![Release](https://img.shields.io/github/v/release/oyesanyf/QuorumRAG?include_prereleases&sort=semver)](https://github.com/oyesanyf/QuorumRAG/releases)
[![Installers](https://github.com/oyesanyf/QuorumRAG/actions/workflows/quorumrag-release.yml/badge.svg)](https://github.com/oyesanyf/QuorumRAG/actions/workflows/quorumrag-release.yml)

Local-first, peer-to-peer agentic Retrieval-Augmented Generation (RAG) daemon with an embedded ChatGPT-style Web UI.

- Hybrid search: LanceDB vectors + Tantivy full-text.
- Multimodal ingestion: documents, images, audio and their metadata. Executables and libraries are excluded.
- LLM answer orchestration with a LangExtract-grounded fallback that cites its sources.
- Ed25519-authenticated libp2p mesh between peers.
- Exports answers as PDF and Word documents.
- Runs fully offline against local Ollama models.

## Contents

- [Install](#install)
- [Build from source](#build-from-source)
- [Repository map](#repository-map)
- [Workspace layout](#workspace-layout)
- [Documentation](#documentation)

## Install

Download a package from [Releases](https://github.com/oyesanyf/QuorumRAG/releases). Every package installs QuorumRAG as an always-on background service and opens http://127.0.0.1:3031/ in your browser:

| OS | Package |
|---|---|
| Windows | `QuorumRAG-<ver>-x86_64.msi` (service `QuorumRAGDaemon`) or the portable `.zip` |
| Debian / Ubuntu | `quorumrag_<ver>_<arch>.deb` (`quorumrag.service`) |
| RHEL / Fedora / SUSE | `quorumrag-<ver>-1.<arch>.rpm` (`quorumrag.service`) |
| macOS | `QuorumRAG-<ver>-macos-universal.pkg` (LaunchDaemon `dev.quorumrag.daemon`) |
| Docker (linux/amd64, linux/arm64) | `ghcr.io/oyesanyf/quorumrag:latest` from [GitHub Packages](https://github.com/oyesanyf/QuorumRAG/pkgs/container/quorumrag) |

Container:

```bash
docker run -d --name quorumrag --network host \
  -v quorumrag-data:/var/lib/quorumrag \
  ghcr.io/oyesanyf/quorumrag:latest
# Web UI: http://127.0.0.1:3031/   (remove with: docker rm -f quorumrag && docker volume rm quorumrag-data)
```

Uninstalling stops the service and deletes it completely. See [docs/INSTALL.md](docs/INSTALL.md) for silent-install options, data locations, purge options and code-signing notes.

## Build from source

```bash
cargo build --release -p quorum-daemon --bin quorumrag
./target/release/quorumrag --host 0.0.0.0 --port 3031 --p2p-port 3032 --data-dir ./data
```

Windows installers: `powershell -ExecutionPolicy Bypass -File scripts/package.ps1`.
Linux and macOS packages: `packaging/linux/build_packages.sh` and `packaging/macos/build_packages.sh`.

## Workspace layout

| Crate | Purpose |
|---|---|
| `quorum-daemon` | HTTP API, embedded Web UI, Windows service entry point (`quorumrag` binary) |
| `quorum-coordinator` | Agentic retrieval, answer synthesis and orchestration |
| `quorum-ingest` | File discovery, parsing and multimodal extraction |
| `quorum-storage` | LanceDB vector store and Tantivy full-text index |
| `quorum-network` | libp2p peer mesh |
| `quorum-contract` | Shared types |

## Repository map

| Path | What is there |
|---|---|
| [`crates/`](crates) | Rust workspace crates (see [Workspace layout](#workspace-layout)) |
| [`crates/quorum-daemon/src/`](crates/quorum-daemon/src) | HTTP handlers, CLI, shutdown, Windows service (`win_service.rs`) |
| [`crates/quorum-coordinator/src/`](crates/quorum-coordinator/src) | Agentic retrieval, `answer_orchestrator.rs`, LangExtract grounding |
| [`crates/quorum-ui/assets/`](crates/quorum-ui/assets) | Embedded Web UI |
| [`packaging/windows/`](packaging/windows) | Launcher, open-UI and complete-uninstall scripts for the MSI and ZIP |
| [`packaging/linux/`](packaging/linux) | deb/rpm/tarball builder, `quorumrag.service`, `quorumrag-ctl` helper |
| [`packaging/macos/`](packaging/macos) | pkg/dmg/tarball builder, LaunchDaemon plist, install/uninstall |
| [`wix/QuorumRAG.wxs`](wix/QuorumRAG.wxs) | WiX v5 MSI definition (auto-start service, browser launch, full removal) |
| [`scripts/`](scripts) | `package.ps1` (Windows build), signing, release and PR shipping |
| [`.github/workflows/`](.github/workflows) | Cross-platform installer + release pipeline, PR invariant gate |
| [`tests/e2e/`](tests/e2e) | End-to-end tests |
| [`policy/`](policy) | Witness / supply-chain policy templates |
| [`docs/`](docs) | Install and multimodal documentation |

## Documentation

- [docs/INSTALL.md](docs/INSTALL.md): service install, silent options, uninstall and purge on every OS, code signing
- [docs/MULTIMODAL.md](docs/MULTIMODAL.md): image/audio/document ingestion, answer orchestration, exports
- [PROJECT.md](PROJECT.md): feature matrix and milestones
- [AGENTS.md](AGENTS.md): rules for automated agents working on this repository
