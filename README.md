# QuorumRAG

Local-first, peer-to-peer agentic Retrieval-Augmented Generation (RAG) daemon with an embedded ChatGPT-style Web UI.

- Hybrid search: LanceDB vectors + Tantivy full-text.
- Multimodal ingestion: documents, images, audio and their metadata. Executables and libraries are excluded.
- LLM answer orchestration with a LangExtract-grounded fallback that cites its sources.
- Ed25519-authenticated libp2p mesh between peers.
- Exports answers as PDF and Word documents.
- Runs fully offline against local Ollama models.

## Install

Download a package from [Releases](https://github.com/oyesanyf/QuorumRAG/releases). Every package installs QuorumRAG as an always-on background service and opens http://127.0.0.1:3031/ in your browser:

| OS | Package |
|---|---|
| Windows | `QuorumRAG-<ver>-x86_64.msi` (service `QuorumRAGDaemon`) or the portable `.zip` |
| Debian / Ubuntu | `quorumrag_<ver>_<arch>.deb` (`quorumrag.service`) |
| RHEL / Fedora / SUSE | `quorumrag-<ver>-1.<arch>.rpm` (`quorumrag.service`) |
| macOS | `QuorumRAG-<ver>-macos-universal.pkg` (LaunchDaemon `dev.quorumrag.daemon`) |

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

More docs: [PROJECT.md](PROJECT.md), [docs/MULTIMODAL.md](docs/MULTIMODAL.md), [docs/INSTALL.md](docs/INSTALL.md).
