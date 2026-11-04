# Project: QuorumRAG

## Architecture
QuorumRAG is a production-grade, local-first, peer-to-peer retrieval-augmented generation daemon and responsive ChatGPT-like web interface. It combines offline deterministic Gemma embedding contracts, embedded LanceDB vector storage with co-located Tantivy BM25 full-text search, an intelligent filesystem ingestion pipeline powered by Google Magika and two-level BLAKE3 deduplication, a non-stubbed rust-libp2p Swarm with 400ms scatter-gather federated retrieval, Ed25519 access-tier isolation, Reciprocal Rank Fusion (RRF), Volatile `ZeroizeOnDrop` memory protection, and a self-contained single `.exe` daemon that automatically opens the ChatGPT web interface.

### High-Level Data Flow
```
[User / Browser]
       │
       ▼ (HTTP / SSE / WebSocket)
[quorum-ui / Axum Web Server] (Embedded HTML/CSS/JS, SSE Streaming, Citations)
       │
       ▼
[quorum-coordinator] ─── (400ms scatter-gather) ───┐
       │                                            ▼
       ├─────────────────────────┐          [quorum-network] (rust-libp2p Swarm)
       ▼                         ▼                  │ (QUIC/TCP/Noise/Yamux/mDNS/CBOR)
[quorum-storage]          [quorum-contract]         ▼
(LanceDB + Tantivy FTS)   (Gemma 768d Offline)   [Remote Peer Swarm Nodes]
  - Arrow Encapsulated     - Deterministic B3       - Ed25519 Access Tier Pre-filter
  - SQL Pre-filtering        contract hash          - ZeroizeOnDrop Remote Chunks
  - Scheduled Compaction   - Constant-time gating   - Reciprocal Rank Fusion (RRF)
       ▲
       │ (Micro-batched writes)
[quorum-ingest]
  - Google Magika Content Classifier (deep-learning / MIME detection)
  - `ignore::WalkBuilder` & `notify` Watcher (300ms debounced)
  - Two-level BLAKE3 deduplication (File catalog + Rename/Move detection + Chunk cache)
```

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Pure Rust Domain Types | Decoupled domain models (`DocumentChunk`, `ScoredChunk`, `AccessTier`, `Citation`) with zero Arrow leakage | M1 | survey |
| 2 | Gemma Embedding Contract | Canonical 768-dim, L2-normalized, Cosine distance embedding specification | M1 | survey (R2) |
| 3 | BLAKE3 Contract Hash Derivation | Deterministic 32-byte BLAKE3 digest over dimension, norm, metric, pooling, sequence length | M1 | survey (R2) |
| 4 | Offline Embedding Engine | Dual-mode runtime: Candle Gemma for production + fast deterministic engine for tests | M1 | survey (R2) |
| 5 | Handshake Contract Validation | Constant-time comparison gating peer connections on identical contract hash | M1 | survey (R2) |
| 6 | Google Magika Content Classifier | Deep-learning content-type inspection before chunking or binary filtering | M1 | follow-up req |
| 7 | Embedded LanceDB Storage Engine | Embedded vector table with persistent columnar format on local disk | M2 | survey (R1) |
| 8 | Arrow `RecordBatch` Isolation | Private internal Arrow interop module; zero Arrow types exported in public APIs | M2 | survey (R1) |
| 9 | IVF_PQ Vector Index & Compaction | Scalable IVF_PQ index creation and scheduled parquet fragment compaction for 30TB+ drives | M2 | survey (R1) |
| 10 | Access Tier SQL Pre-filtering | Native LanceDB `.only_if("access_tier <= N")` scalar filter executed prior to ANN scan | M2 | survey (R1, R3) |
| 11 | Tantivy BM25 Full-Text Search | Co-located BM25 inverted index for keyword search | M2 | survey (R1) |
| 12 | Storage Hybrid Search Combiner | Storage-level reciprocal rank fusion combining vector and keyword hits | M2 | survey (R1) |
| 13 | High-Capacity Filesystem Crawler | Crawl arbitrary local paths/drives with `ignore::WalkBuilder` respecting gitignore | M3 | survey (R1) & follow-up |
| 14 | Real-time Filesystem Watcher | OS event watcher via `notify` with 300ms debouncing window | M3 | survey (R1) |
| 15 | File Filtering Engine | Size caps, binary exclusion, and Magika-verified code/document routing | M3 | survey (R1) & follow-up |
| 16 | Level-1 BLAKE3 File Deduplication | File-level hash catalog with move/rename detection to avoid re-embedding | M3 | survey (R1) |
| 17 | Level-2 BLAKE3 Chunk Deduplication | Chunk text hash cache with micro-batched vectorization and writes | M3 | survey (R1) |
| 18 | rust-libp2p Dual-Transport Swarm | QUIC + TCP (Noise encryption + Yamux multiplexing) non-stubbed swarm | M4 | survey (R3) |
| 19 | LAN Discovery via mDNS | Zero-config peer discovery across local area network | M4 | survey (R3) |
| 20 | Kademlia DHT & Peer Routing | Distributed hash table maintaining active routing table of swarm peers | M4 | survey (R3) |
| 21 | GossipSub Query Broadcast | Mesh broadcast topic with signed message authentication and deduplication | M4 | survey (R3) |
| 22 | Request-Response CBOR Streaming | Binary streaming protocol for point-to-point chunk querying | M4 | survey (R3) |
| 23 | Scatter-Gather Query Coordinator | Parallel dispatch of local LanceDB search and peer queries | M4 | survey (R3) |
| 24 | 400ms Hard Timeout Guard | Strict cancellation of slow peer queries with graceful fallback to local results | M4 | survey (R3) |
| 25 | Ed25519 Query Verification | Digital signature signing and anti-replay timestamp verification (< 60s) | M4 | survey (R3) |
| 26 | Reciprocal Rank Fusion (RRF) | Ordinal score aggregation $RRF(d) = \sum \frac{1}{60 + r(d)}$ with BLAKE3 deduplication | M4 | survey (R3) |
| 27 | Volatile Memory Protection | Remote peer chunks wrapped in `ZeroizeOnDrop` structs; scrubbed on drop | M4 | survey (R3) |
| 28 | ChatGPT Web Chat Interface | Collapsible sidebar, 5-theme switcher, 768px reading column, pill input | M5 | survey (R4) |
| 29 | Structured Source Citations | Inline badges and cards with peer ID, file path, line numbers, score | M5 | survey (R4) |
| 30 | "Ask Anything" Synthesis Router | Answers general knowledge + cited RAG questions from local/mesh files | M5 | follow-up req |
| 31 | Axum 0.7 Web Server & SSE Streaming | Server-Sent Events endpoint `/api/chat/stream`, search API, embedded assets | M5 | survey (R4) |
| 32 | Single `.exe` Launcher & Auto-Browser | Combined daemon + web UI in one binary; opens browser on launch (`--no-browser` option) | M5 | follow-up req |
| 33 | E2E Automated Test Suite | Tiers 1-4 comprehensive opaque-box test suite + Tier 5 adversarial hardening | M6 | survey (R5) |
| 34 | LangGraph-Style Agentic State Graph | Explicit Rust state machine (ClassifyIntent -> RetrieveMesh -> GradeRelevance -> RewriteQuery loop -> SynthesizeWithCitations) with live SSE telemetry | M4, M5 | follow-up req |
| 35 | Full Search Modes (Keyword, Vector, Hybrid) | Explicit support for Keyword (Tantivy BM25), Semantic Vector (LanceDB), and Hybrid (RRF) search modes selectable by user & agentic state graph | M2, M4, M5 | follow-up req |
| 36 | Real-Time OS Watcher with Google Magika | Continuous live filesystem watcher (`notify`) routing file events through Magika content inspection | M3 | follow-up req |
| 37 | Image Indexing Engine (Do Not Skip Images) | Extract rich searchable representations (dimensions, EXIF/metadata, tokens, OCR/caption, format via Magika) into LanceDB + Tantivy | M3 | follow-up req |
| 38 | Dedicated Reindex Process (`reindex`) | Dedicated reindexing process/worker (`quorumrag reindex [--path] [--full]`, `/api/reindex` REST endpoint & Web UI trigger) | M3, M5 | follow-up req |
| 39 | Dedicated Drift Remediation (`fix-drift`) | Detects & heals all 5 drifts: (a) FS <-> DB Merkle drift, (b) LanceDB <-> Tantivy desync, (c) Vector contract drift, (d) ACL policy drift, (e) Storage fragment/tombstone drift | M2, M3, M5 | follow-up req |
| 40 | Fusion Architecture & Hardware-Aware GLM Selection | Direct adoption of `d:\harfile\fusion` routing and dynamic selection of GLM models (`glm-4`, `glm-4-9b`, `glm-edge`, `glm-4v`) based on available RAM/VRAM | M4, M5 | follow-up req |
| 41 | Fusion-Powered Google LangExtract (`langextract_fusion`) | Two-loop structured extraction powered by `LlmFusionConsensus` (adapted from `breakout_defense.rs` lines 3440-3697: Arm 1 SemanticSpanExtractor, Arm 2 SyntacticAstVerifier, Arm 3 CounterfactualJudge, Arm 4 LangGraph state calibration): (1) Ingestion-time grounded preprocessor with 100% `char_interval` verification (hallucination rejection) storing grounded entities/attributes in LanceDB + Tantivy, and (2) Query-time decomposition in `ClassifyIntent` -> `RetrieveMesh` scalar/lexical prefiltering; plus interactive HTML visualizer, `/api/langextract`, and Web UI `@extract` mode | M4, M5 | follow-up req |
| 42 | Live IDE Execution & Production Code Generation Gate | Start compiled `quorumrag.exe` live in IDE, index real workspace files (`d:\harfile\QuorumRAG`), query live daemon API to verify it generates compilable production code with exact `[Peer:File:Lines]` citations & grounded `char_interval` spans, and auto-open ChatGPT Web UI in browser | M5, M6 | follow-up req |
| 43 | Multi-Layer Caching & Re-Cache Subsystem (`recache`) | BLAKE3 QueryCache & EmbeddingCache, cache hit telemetry, `quorumrag recache [--clear] [--warm]`, `/api/cache/recache` & `/api/cache/stats`, auto-invalidation on reindex/fix-drift/watcher, and Web UI Re-Cache button & live stats | M5.5 | follow-up req |
| 44 | Dedup Engine Startup Hydration | Hydrate `TwoLevelDedupEngine` (catalog & chunk cache) from LanceDB on startup (`hydrate_from_storage`) | M7 | follow-up (R1) |
| 45 | Complete Physical Drive Discovery | Windows NTFS, ReFS, exFAT, FAT32 fixed volume support, dot-directory blind spot elimination | M7 | follow-up (R1) |
| 46 | Fast-Path Binary/DLL/EXE Exclusion | Deterministic file extension filtering (.exe, .dll, .sys, .so, .dylib, .pdb, .obj, .class, etc.) prior to file I/O | M7 | follow-up (R1) |
| 47 | Watcher Directory & Sharing Fault Resilience | Recursive directory creation/rename support in `watcher.rs` and retry on Windows sharing violations (Error 32) | M7 | follow-up (R1) |
| 48 | Low-Latency Multi-Hop Query Execution & Relevance Precision | Pre-computed static chunk scoring, stack buffer reuse, multi-term entity matching & GENERIC_ATTRIBUTE_TERMS expansion, post-response sources, fast streaming (<=2s) | M8 | follow-up (R2) |
| 49 | P2P Cryptographic Handshake & Anti-Replay | Enforce Ed25519 signature & timestamp (<60s) verification in `OsoosiMeshInboundHandler::handle_query` with sender pubkey validation | M8 | follow-up (R2) |
| 50 | Byzantine Quorum Consensus Hardening | Bound per-peer voting influence in `RrfCombiner::fuse_rankings`, key on `blake3_hash`, clamp remote chunk tiers | M8 | follow-up (R2) |
| 51 | Air-Gapped Offline Enforcement | Assert loopback address on local Ollama client, restrict swarm dialing to loopback/private subnets | M8 | follow-up (R2) |
| 52 | Active Chat UI Stop Button & In-Flight Cancellation | AbortController, `POST /api/chat/cancel`, `tx.is_closed()` break in SSE word streaming, graph state cancellation | M9 | follow-up (R3) |
| 53 | Monotonic Live Indexer Progress Reporting | Upfront total candidate counting across drive targets, eliminate 25% fake fallback, accurate chunk counts | M9 | follow-up (R3) |
| 54 | Dynamic & Varied Thinking Phrases Engine | 60+ engaging phrase pool, ~650ms random cycle, non-repeating, non-freezing on telemetry before TokenDelta | M9 | follow-up req |
| 55 | Deterministic 7-Metric Benchmark Suite & Fault Regressions | `tests/benchmarks_r4.rs` (latency, disk I/O, CPU, RSS memory, doc/image index, binary exclusion, consensus) & Byzantine regression tests | M10 | follow-up (R4) |
| 56 | Solo Developer PR Shipping & Squash-Merge | Clean branch, atomic commits, automated test suite verification, PR with 7-metric table, self-review & merge into main | M10 | follow-up (R4) |
| 57 | Source Code & Temp File Ingestion Exclusion & RAG Isolation | Ingestion strictly indexes documents and images while excluding FileCategory::Code, source code extensions, and temp/lock files (~*, .tmp, .bak); default exclude_source_code: true; purge/skip code/temp chunks in reindex/retrieval | M8.5 | follow-up req |
| 58 | Executable-Only Binary Filter | `SkipBinary` restricted to compiled executables/shared libraries (PE, ELF, Mach-O, bytecode); audio and images are indexed | M16 | user (multimodal) |
| 59 | Audio Indexing | ID3v1/ID3v2 tags, USLT lyrics, MPEG/WAV/FLAC stream properties, companion lyric files (`audio_indexer.rs`) | M16 | user (multimodal) |
| 60 | EXIF GPS + Offline Reverse Geocoding | TIFF IFD/GPS IFD 0x8825 parsing, XMP/IPTC location, embedded gazetteer with haversine radius matching (`exif.rs`, `reverse_geocoder.rs`) | M16 | user (multimodal) |
| 61 | Query Framing + Media Intent | Conversational framing stripped before BM25; requested modality ranked first (`query_framing.rs`, coordinator retrieve) | M16 | user (multimodal) |
| 62 | Query-Time Vision | Top cited local images sent to a local Ollama vision model; descriptions ground the answer, cached by BLAKE3 (`vision.rs`) | M16 | user (multimodal) |
| 63 | Media Streaming, Open-File, Export | `GET /api/media` (Range, index-gated), `POST /api/open-file` (loopback), `POST /api/export` (PDF 1.4 / DOCX) | M16 | user (multimodal) |
| 64 | Clickable Multimodal UI | Inline image gallery + lightbox, audio/video players, clickable sources and `[n]` citations, Save File PDF/Word menu | M16 | user (multimodal) |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Core Types, Gemma Contract & Magika Classifier | Domain models, Gemma 768d offline embedding contract & BLAKE3 hash gating, Magika content classifier | none | DONE |
| M2 | LanceDB Storage & Tantivy FTS with Arrow Isolation | LanceDB vector table, Tantivy BM25, private Arrow RecordBatch conversion, SQL pre-filter, compaction, search modes, parity healing primitives | M1 | DONE |
| M3 | Filesystem Ingestion, OS Watcher, Image & Reindex Engine | `ignore` crawler, real-time `notify` watcher, Magika routing, Image indexing, Level-1/Level-2 dedup, `reindex` & `fix-drift` worker subsystems | M1, M2 | DONE |
| M4 | rust-libp2p Swarm, Coordinator, Fusion & GLM Selection | libp2p Swarm, 400ms scatter-gather, LangGraph state graph, `fusion` adoption with GLM selection, Fusion-powered LangExtract core engine with `char_interval` grounding | M1, M2, M3 | DONE |
| M5 | ChatGPT Web Interface, Synthesis & Single Executable | Axum web server, embedded UI, search mode toggle, SSE streaming with agentic & GLM telemetry, single `.exe`, reindex/drift triggers, LangExtract UI action, interactive HTML visualizer & `/api/langextract` endpoints, Live IDE Execution & Production Code Generation Verification Gate | M1, M2, M3, M4 | DONE |
| M5.5 | Multi-Layer Caching & Re-Cache Subsystem (`recache`) | BLAKE3 QueryCache & EmbeddingCache, cache hit telemetry, `quorumrag recache [--clear] [--warm]`, `/api/cache/recache` & `/api/cache/stats`, auto-invalidation on reindex/fix-drift/watcher, and Web UI Re-Cache button & live stats | M1, M2, M3, M4, M5 | DONE |
| M6 | Final Acceptance: 100% E2E Test Pass & Adversarial Hardening | Pass 100% of E2E test suite (Tiers 1-4) published by E2E Test Track, Live IDE run & production code generation verification, followed by Tier 5 adversarial audit | M5, M5.5, TEST_READY | DONE |
| M7 | Zero-Overhead Ingestion Pipeline, Dedup Hydration & Binary Filtering | TwoLevelDedupEngine startup hydration from LanceDB, complete physical drive discovery (NTFS/ReFS/exFAT/FAT32), fast-path binary/DLL/EXE exclusion prior to I/O, watcher sharing violation resilience | none | DONE |
| M8 | Low-Latency Query Execution, Consensus & P2P Security Hardening | Multi-hop RAG latency optimization, inbound Ed25519 signature & replay verification (`OsoosiMeshInboundHandler`), Byzantine consensus score stuffing prevention in `RrfCombiner`, strict offline air-gapping | none | DONE |
| M8.5 | Source Code & Temp File Ingestion Exclusion & RAG Isolation | Filter source code extensions, FileCategory::Code, and Office lock/temp files (~*, .tmp, .bak) in Crawler/Router, default exclude_source_code: true in IngestConfig, purge/skip code/temp chunks in reindex/retrieval | M7, M8 | DONE |
| M9 | UI Stop Button & Real-Time Monotonic Indexer Progress | Chat UI stop button with `AbortController`, `POST /api/chat/cancel`, CancellationToken in coordinator graph, monotonic candidate progress calculation, remove 25% fallback, 60+ dynamic thinking phrases engine | M7, M8, M8.5 | DONE |
| M10 | Benchmarks, Byzantine/Fault Regressions & Solo PR Shipping | 7-metric deterministic benchmark suite (`tests/benchmarks_r4.rs`), Byzantine peer & fault regression suite, full test suite verification, solo PR shipping via `scripts/solo_pr_ship.ps1`, clean merge into main | M7, M8, M8.5, M9 | DONE |


## Interface Contracts

### `quorum-types` ↔ All Crates
- `DocumentChunk`:
  - `chunk_id: String`
  - `document_id: String`
  - `file_path: String`
  - `line_start: u32`
  - `line_end: u32`
  - `blake3_hash: String`
  - `access_tier: u8`
  - `vector: Vec<f32>`
  - `text_content: String`
  - `metadata_json: String`
- `ScoredChunk`:
  - `chunk: DocumentChunk`
  - `score: f32`
  - `source_peer: String`
  - `is_remote: bool`
- `EmbeddingContract`:
  - `version: u32`, `model_name: String`, `dimension: usize (768)`, `normalization: String ("L2")`, `distance_metric: String ("Cosine")`, `pooling: String ("MeanPooling")`
  - `fn derive_contract_hash(&self) -> [u8; 32]`

### `quorum-storage` ↔ `quorum-coordinator` / `quorum-ingest`
- `StorageEngine`:
  - `open(path: impl AsRef<Path>) -> Result<Self, StorageError>`
  - `insert_chunks(&self, chunks: &[DocumentChunk]) -> Result<usize, StorageError>`
  - `search_vector(&self, vector: &[f32], max_tier: u8, top_k: usize) -> Result<Vec<ScoredChunk>, StorageError>`
  - `search_text(&self, query: &str, max_tier: u8, top_k: usize) -> Result<Vec<ScoredChunk>, StorageError>`
  - `search_hybrid(&self, text: &str, vector: &[f32], max_tier: u8, top_k: usize) -> Result<Vec<ScoredChunk>, StorageError>`
  - `has_chunk_hash(&self, blake3_hash: &str) -> Result<bool, StorageError>`
  - `compact(&self) -> Result<(), StorageError>`

### `quorum-network` ↔ `quorum-coordinator`
- `FederatedQueryRequest`:
  - `query_id: Uuid`, `sender_peer_id: String`, `sender_pubkey: [u8; 32]`, `query_text: String`, `embedding: Vec<f32>`, `top_k: usize`, `timestamp: i64`, `signature: [u8; 64]`
- `CandidateChunkDto`:
  - `chunk_id: String`, `file_path: String`, `line_start: u32`, `line_end: u32`, `content: String`, `score: f32`, `access_tier: u8`
- `FederatedQueryResponse`:
  - `query_id: Uuid`, `responder_peer_id: String`, `chunks: Vec<CandidateChunkDto>`

### `quorum-coordinator` ↔ `quorum-ui`
- `QueryCoordinator`:
  - `query(&self, prompt: &str, top_k: usize) -> Result<QueryResult, CoordinatorError>`
- `QueryResult`:
  - `chunks: Vec<ScoredChunk>`
  - `synthesis_prompt: String`
  - `execution_time_ms: u64`
  - `sources_cited: Vec<Citation>`

## Code Layout
```
d:\harfile\QuorumRAG\
├── Cargo.toml                  # Virtual workspace
├── crates/
│   ├── quorum-types/           # Pure domain models (zero dependencies on Arrow/LanceDB)
│   ├── quorum-classifier/      # Google Magika content inspection & binary classifier
│   ├── quorum-contract/        # Gemma 768d embedding contract, BLAKE3 derivation, offline engine
│   ├── quorum-storage/         # LanceDB + Tantivy FTS, private Arrow interop, SQL pre-filter, compaction
│   ├── quorum-ingest/          # Filesystem crawler (`ignore`), watcher (`notify`), 2-level BLAKE3 dedup
│   ├── quorum-network/         # rust-libp2p Swarm (QUIC/TCP/Noise/Yamux/mDNS/Kad/Gossip/CBOR)
│   ├── quorum-coordinator/     # 400ms scatter-gather, Ed25519 ACL, RRF combiner, ZeroizeOnDrop
│   ├── quorum-ui/              # Axum 0.7 web server, embedded ChatGPT UI, SSE streaming, synthesis router
│   └── quorum-daemon/          # Binary entrypoint (`quorumrag.exe`), single process launcher, auto-browser
└── tests/
    └── e2e/                    # Opaque-box E2E test suite (Tiers 1-4)
```


## Agentic State Graph Specification (LangGraph Pattern in Rust)

To enable iterative multi-hop reasoning without sacrificing Rust's performance, memory safety, or single-binary simplicity, the query and synthesis layer incorporates an explicit Agentic State Graph:

```
[Start User Prompt]
        │
        ▼
[Node: ClassifyIntent]
   - Determines: Direct General Response vs Local/Mesh Retrieval vs Multi-Hop Query
        │
        ▼
[Node: RetrieveMesh]
   - Parallel 400ms scatter-gather across local LanceDB and libp2p mesh
        │
        ▼
[Node: GradeRelevance]
   - Evaluates retrieved chunks against query intent
        │
        ├─► [Unsatisfactory / Incomplete Relevance (loop max 3)] ──► [Node: RewriteQuery] ──► (Loop back to RetrieveMesh)
        │
        ▼ [Relevance Satisfied / Max Hops Reached]
[Node: SynthesizeWithCitations]
   - Generates grounded streaming response with structured inline citations and execution telemetry
        │
        ▼
[End / Stream to Web UI]
```

### Core Invariants:
1. Pure Rust state machine transitions (`enum QueryState { ClassifyIntent, RetrieveMesh, GradeRelevance, RewriteQuery, SynthesizeWithCitations }`).
2. Maximum loop bound (default 3 hops) to strictly prevent runaway recursion.
3. State graph execution telemetry streamed via SSE to the ChatGPT web interface showing live transition pills (`Classifying -> Searching Mesh -> Grading Chunks -> Synthesizing`).


## Extended Requirements: Full Search Modes, OS Watcher & Image Indexing

### 1. Full Search Mode Support (Keyword, Vector, Hybrid)
- **Keyword / Lexical Search**: Tantivy BM25 term and phrase matching over text, file paths, and metadata.
- **Semantic Vector Search**: LanceDB IVF_PQ cosine similarity over dense Gemma 768d embeddings.
- **Hybrid Search**: Unified query execution evaluating both BM25 and Vector scores, combined via Reciprocal Rank Fusion ($k=60$).
- **API & UI Selection**: The Web UI search bar, API endpoints (`/api/search?mode=...`), and Agentic State Graph (`ClassifyIntent`) explicitly support toggling or routing between `Keyword`, `Semantic`, and `Hybrid` search modes.

### 2. Continuous OS File Watcher with Google Magika
- High-performance, asynchronous OS filesystem watching via `notify-debouncer-full` (or `notify` crate) monitoring designated paths for creation, modification, rename, and deletion events.
- Every detected file passes directly into `quorum-classifier` (Google Magika content-type deep-learning / magic-byte inspection) before routing to the appropriate ingestion extractor and indexing into LanceDB + Tantivy.

### 3. Image Indexing & Retrieval Support (Do Not Skip Images)
- Image files (`image/jpeg`, `image/png`, `image/webp`, `image/gif`, `image/bmp`, `image/tiff`, `image/svg+xml`, etc.) identified by Google Magika are **not skipped**.
- Handled by a dedicated **Image Extractor / Indexer** in `quorum-ingest`:
  - Extracts image dimensions, color format, metadata (EXIF/IPTC/XMP where available), path tokens, and visual description / embedded text.
  - Builds rich, searchable textual representations and computes BLAKE3 chunk hashes.
  - Indexes metadata and visual summaries into LanceDB + Tantivy, enabling users to query and ask questions about local images with structured citations in the ChatGPT interface.


## Dedicated Subsystems: Reindex & Comprehensive Drift Healing (`fix-drift`)

### 1. Dedicated Reindexing Process (`reindex`)
- Standalone CLI command (`quorumrag reindex [--path <dir>] [--full]`), daemon background task, and REST API (`POST /api/reindex`) + Web UI button.
- Recursively traverses watched directories using `ignore::WalkParallel` + Google Magika (`quorum-classifier`).
- Two-level BLAKE3 verification: skips files whose mtime, size, and BLAKE3 hash match existing database records; parses and chunks modified/new files; reuses existing embedding vectors where chunk hashes match.

### 2. Comprehensive Drift Healing Subsystem (`fix-drift`)
First-class background worker, CLI command (`quorumrag fix-drift`), and REST API (`POST /api/drift/fix`, `GET /api/drift/status`) capable of identifying and remediating all 5 categories of drift:
1. **Filesystem <-> Database Drift (Merkle State Drift)**:
   - Detects files deleted or modified while daemon was offline or events dropped during I/O spikes.
   - Deletes orphaned chunks for removed files; indexes untracked/modified files.
2. **Hybrid Index Desynchronization (LanceDB <-> Tantivy Drift)**:
   - Compares the set of `chunk_id` and `chunk_hash` keys across LanceDB and the Tantivy BM25 directory.
   - Heals missing entries in either index to restore 100% mutual consistency.
3. **Embedding Contract / Vector Space Drift**:
   - Detects chunks whose stored contract hash or vector properties differ from the current active Gemma contract.
   - Re-embeds drifted chunks in-place to prevent corrupted multi-space vector distances.
4. **ACL / Access-Tier Policy Drift**:
   - Scans directory paths against updated `raghome.toml` / `quorumrag.toml` watch configurations.
   - Atomically updates stored `access_tier` values for chunks whose folder permissions changed (e.g. from `private` to `household_mesh`).
5. **Storage Fragmentation & Tombstone Drift**:
   - Monitors uncompacted `.lance` fragments and deleted row tombstones, as well as unmerged Tantivy segment files.
   - Triggers `table.optimize()` and Tantivy segment merging to eliminate read degradation.


## Fusion Engine & Hardware-Aware GLM Model Selection (`d:\harfile\fusion`)

To leverage existing fusion intelligence from `d:\harfile\fusion`, QuorumRAG directly integrates the fusion orchestration layer and hardware telemetry probe:

### 1. Fusion Code Adaptation
- Directly ports and adapts the model orchestrator, prompt synthesis pipeline, and streaming response protocol from `d:\harfile\fusion`.
- Embedded inside `quorum-coordinator` and `quorum-ui`, providing zero-overhead, in-process routing.

### 2. Hardware-Aware GLM Model Selection
- Uses dynamic host memory and VRAM telemetry (via `sysinfo` / DirectML / CUDA probes) to inspect available system resources before routing queries:
  - **Tier 1 (High VRAM / Free RAM >= 24GB or VRAM >= 12GB)**: Routes to `glm-4` / `glm-4-9b` (or local GLM-4 runtime / Ollama / llama.cpp / vLLM endpoint).
  - **Tier 2 (Mid Memory / Free RAM >= 12GB or VRAM >= 6GB)**: Routes to `glm-edge` / compact GLM models.
  - **Tier 3 (Constrained / CPU-only fallback)**: Routes to lightweight quantized fallback model or embedded local Gemma/GLM CPU inference.
- Emits real-time hardware telemetry and selected GLM model tier in the Web UI status card and SSE stream headers.


## Multi-Model Architecture & Adaptive Intent + Hardware Fusion Router

### 1. Invariant Embedding Contract
- `google/embeddinggemma-300m` remains the immutable, locked mesh-wide embedding contract across LanceDB tables on every node, ensuring mathematically identical vector spaces across the P2P federation.

### 2. Supported Local Synthesis Models & Roles
- **GLM-4-9B (`glm-4-9b-chat` / `glm4`)**: Primary default synthesis and multi-hop agentic reasoning engine, supporting 128K–1M context windows for dense multi-document synthesis.
- **Qwen 2.5 (`qwen2.5:32b` / `14b` / `7b` / `3b` / `1.5b`)**: Code-specialized synthesis model dynamically sized by runtime memory (`free_ram_gb`, `free_vram_mb`), selected when chunks contain programming language ASTs.
- **Gemma 2 / Gemma 3 (`gemma3:27b` / `gemma3:9b` / `gemma2:9b`)**: Unified Google stack model for fluent natural English prose and concise summaries.

### 3. Adaptive Intent + Hardware Fusion Router (`ClassifyIntent` Node)
- Implements `SynthesisModelFamily::{Glm4Agentic, Qwen25Code, GemmaProse, AutoFusion}`.
- In `AutoFusion` mode, `ClassifyIntent` evaluates:
  1. **Query & Chunk Intent**: If chunks are predominantly `Code` (via Magika classification), route to Qwen 2.5; if multi-hop / multi-document context > 16KB, route to GLM-4-9B (128K); if general prose / notes, route to Gemma 3 or GLM-4.
  2. **Hardware Telemetry**: Inspects runtime free RAM and VRAM, dynamically falling back to quantized tiers or deterministic offline engine if resources are constrained.
- **Hot-Swappable Configuration & Web UI Selector**:
  - `quorumrag.toml` defaults to `glm-4-9b-chat`.
  - The ChatGPT Web UI renders an interactive model pill selector (`GLM-4-9B`, `Qwen 2.5`, `Gemma 2/3`, `Auto-Fusion`), streaming active model family and selection rationale in SSE headers and response badges.


## Source Code Ingestion Exclusion & RAG Document/Image Isolation (Milestone M8.5)

### Core Invariants:
1. **Documents & Images Only**: The ingestion pipeline (`quorum-ingest` / `ClassifierRouter` / `FilesystemCrawler`) strictly indexes documents, text/data files, and image assets (`.pdf`, `.docx`, `.doc`, `.odt`, `.rtf`, `.epub`, `.xlsx`, `.xls`, `.ods`, `.pptx`, `.ppt`, `.odp`, `.txt`, `.md`, `.csv`, `.tsv`, `.json`, `.png`, `.jpg`, `.jpeg`, `.webp`, `.gif`, `.bmp`, `.svg`, `.tiff`, etc.).
2. **Deterministic Source Code Filtering**: Deterministically filter out `FileCategory::Code` and source code extensions (`.rs`, `.py`, `.js`, `.ts`, `.jsx`, `.tsx`, `.c`, `.cpp`, `.h`, `.hpp`, `.cc`, `.cs`, `.java`, `.go`, `.kt`, `.rb`, `.php`, `.swift`, `.scala`, `.sh`, `.bash`, `.ps1`, `.bat`, `.cmd`, `.sql`, `.css`, `.scss`, `.less`, `.vue`, `.svelte`, etc.) in addition to binary/DLL/EXE files.
3. **Preserve Classifier Tests**: `FileTypeClassifier::classify_bytes` in `quorum-classifier` retains `FileCategory::Code` identification capability for classifier unit tests.
4. **Configuration Default**: `IngestConfig::exclude_source_code` defaults to `true` unless a test or explicit flag overrides it.
5. **RAG Search Isolation**: Any source code chunks in existing indexes are filtered/skipped during reindexing or retrieval so RAG queries return only user documents and images.


## Multimodal RAG (Milestone M16)
See `docs/MULTIMODAL.md` for formats, the GPS/geocoder design and coverage limits, query-time vision, the `/api/media`, `/api/open-file`, and `/api/export` security model, reindex instructions, and known open issues.