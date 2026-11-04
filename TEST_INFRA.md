# Test Infrastructure Specification: QuorumRAG E2E Test Suite (`TEST_INFRA.md`)

**Document Version**: 1.0.0  
**Target Milestone**: Comprehensive 4-Tier E2E Test Suite (Requirements R1–R5, Follow-up 1–4)  
**Author**: E2E Test Writer (`teamwork_test_writer_e2e`)  
**Status**: APPROVED & ACTIVE  

---

## 1. Test Philosophy & Core Invariants

1. **Opaque-Box & Requirement-Driven**:
   Tests are derived strictly from `ORIGINAL_REQUEST.md` (Requirements R1 through R5 and follow-up requirements 1 through 4) and `PROJECT.md` interface specifications. Tests evaluate observable external boundaries: public crate interfaces, BLAKE3 cryptographic digests, Ed25519 signatures, LanceDB vector cosine similarity rankings, Tantivy BM25 keyword search hits, 400ms timeout cancellations, and HTTP/SSE streaming events.

2. **Absolute Zero-Mock Rule**:
   Under no circumstances do tests assert against fake placeholders or dummy personas. All oracles execute genuine cryptographic mathematics (`blake3`, `ed25519_dalek`, `subtle::ConstantTimeEq`), real vector normalizations, authentic content-type deep inspection via Google Magika heuristics, and genuine Reciprocal Rank Fusion calculations.

3. **Progressive Testability & Isolation**:
   Every test case is self-contained and isolated. Setup and teardown create temporary test filesystems (`tempfile`), independent in-memory storage tables, and ephemeral port listeners. Tests do not depend on execution order and clean up temporary resources upon completion.

4. **Zero-Touch Environment & PATH Immutability**:
   In strict accordance with repository rules, no test or harness ever mutates, overwrites, resets, or persists modifications to user or system `PATH` or Windows registry environment hives (`HKCU\Environment`, `HKLM\System\CurrentControlSet\Control\Session Manager\Environment`). All environment variables are process-scoped only.

5. **Multi-Ring Fail-Closed Security Invariants**:
   Tests assert mathematical fail-closed security:
   - Peer connections with mismatched Gemma contract hashes fail closed (`verify_contract_handshake == Err`).
   - Inbound queries with stale timestamps (>60s drift) or corrupted Ed25519 signatures are rejected before storage ANN scans execute.
   - Unauthorized access tiers (`access_tier > max_authorized`) are mathematically excluded via SQL pre-filtering (`only_if("access_tier <= N")`).
   - Remote peer chunks held in RAM are scrubbed on drop via volatile zeroization (`ZeroizeOnDrop`).

---

## 2. 4-Tier Test Matrix

| Feature / Requirement | Domain Scope | Tier 1 (Feature >=5) | Tier 2 (Boundary >=5) | Tier 3 (Pairwise) | Tier 4 (Scenario) |
|---|---|:---:|:---:|:---:|:---:|
| **1. Arrow Type Boundary Isolation** | `quorum-storage`, `quorum-types` | 5 tests | 5 tests | Pair 1 | Scenario 6 |
| **2. Gemma Embedding Contract & Hash Derivation** | `quorum-contract` | 5 tests | 5 tests | Pair 6 | Scenario 1 |
| **3. Google Magika File Type Identification** | `quorum-classifier` | 5 tests | 5 tests | Pair 1 | Scenario 3 |
| **4. Embedded LanceDB Hybrid Storage & Compaction** | `quorum-storage` | 5 tests | 5 tests | Pair 2 | Scenario 6 |
| **5. Two-Level BLAKE3 Ingestion & Deduplication** | `quorum-ingest` | 5 tests | 5 tests | Pair 1, Pair 2 | Scenario 3 |
| **6. rust-libp2p Swarm & 400ms Scatter-Gather** | `quorum-network`, `quorum-coordinator` | 5 tests | 5 tests | Pair 3, Pair 4 | Scenario 1 |
| **7. Ed25519 Identity & Access Tier Filtering** | `quorum-types`, `quorum-coordinator` | 5 tests | 5 tests | Pair 2, Pair 5 | Scenario 4 |
| **8. Reciprocal Rank Fusion (RRF)** | `quorum-coordinator` | 5 tests | 5 tests | Pair 3 | Scenario 1 |
| **9. Volatile Memory Safety (`ZeroizeOnDrop`)** | `quorum-types`, `quorum-coordinator` | 5 tests | 5 tests | Pair 7 | Scenario 1 |
| **10. ChatGPT UI Endpoints & SSE Streaming** | `quorum-ui` | 5 tests | 5 tests | Pair 3 | Scenario 2 |
| **11. Single Executable Launcher (`--no-browser`)** | `quorum-daemon` | 5 tests | 5 tests | Pair 4 | Scenario 5 |
| **TOTALS** | **Full 4-Tier E2E Suite** | **35 Tests** | **35 Tests** | **7 Tests** | **6 Scenarios** |

**Grand Total**: **67 Comprehensive Executable E2E Test Cases**.

---

## 3. Tier Breakdown & Test Objectives

### Tier 1: Feature Coverage (35 Tests)
Equivalence class representative happy-path tests verifying each feature in isolation:
- **Arrow Isolation (`test_storage_isolation.rs`)**:
  - `test_storage_arrow_type_isolation_contract`: Confirms public structs and methods contain zero Arrow types.
  - `test_storage_vector_cosine_similarity_ordering`: Evaluates dense vector Cosine distance sorting.
  - `test_storage_keyword_search_bm25`: Evaluates Tantivy FTS keyword search token matching.
  - `test_storage_hybrid_search_rrf_combination`: Confirms dual-matching chunks accumulate top rank in RRF.
  - `test_storage_has_chunk_hash_deduplication`: Verifies BLAKE3 chunk hash lookup.
- **Gemma Contract & Magika Classifier (`test_gemma_contract.rs`)**:
  - `test_gemma_canonical_contract_spec_fields`: Confirms canonical 768-dim, L2-norm, Cosine parameters.
  - `test_gemma_blake3_contract_hash_deterministic`: Validates 32-byte BLAKE3 digest against independent oracle.
  - `test_gemma_handshake_constant_time_success`: Validates handshake match using `subtle::ConstantTimeEq`.
  - `test_gemma_handshake_rejection_on_mismatched_contract`: Rejects peers with divergent dimension or metric.
  - `test_gemma_offline_deterministic_embedding_vector_properties`: Confirms 768d unit L2-norm vectors.
  - `test_magika_deep_content_classifier_rust_code`: Identifies Rust code as `rust` text with score >= 0.90.
  - `test_magika_deep_content_classifier_pe_binary`: Identifies Windows PE executable header as binary.
- **Ingestion & 2-Level BLAKE3 Dedup (`test_ingestion_dedup.rs`)**:
  - `test_ingestion_binary_sniffing_skips_executables`: Confirms binary executables are skipped.
  - `test_ingestion_level1_file_blake3_catalog_skips_unmodified_file`: Skips re-embedding unchanged files.
  - `test_ingestion_level1_rename_move_detection`: Moving a file updates path with 0 re-embeddings.
  - `test_ingestion_level2_chunk_blake3_dedup_across_files`: Reuses cached vector for duplicate chunk text.
  - `test_ingestion_micro_batching_accumulation`: Flushes micro-batches of 64 chunks to storage.
- **Federated Mesh & Security (`test_federated_mesh.rs`)**:
  - `test_federated_ed25519_signature_signing_and_verification`: Authenticates query with Ed25519 signature.
  - `test_federated_scatter_gather_400ms_timeout_aborts_slow_peer`: Aborts 800ms peer, returns local results.
  - `test_federated_access_tier_blocks_remote_confidential_documents`: Blocks Tier 2 chunk for Tier 0 query.
  - `test_federated_rrf_combines_local_and_remote_rankings`: Fuses ordinal scores $RRF(d) = \sum \frac{1}{60 + r(d)}$.
  - `test_federated_volatile_remote_chunk_zeroizes_on_drop`: Verifies plaintext memory overwritten on drop.
- **Web UI & Single Executable (`test_web_endpoints.rs`)**:
  - `test_web_ui_html_embedding_contains_chatgpt_elements`: Asserts 260px sidebar, 5 themes, 768px column.
  - `test_web_api_health_endpoint`: Validates `/api/health` status, chunk count, and contract hash.
  - `test_web_sse_chat_stream_returns_structured_events`: Emits token, citation, and done SSE events.
  - `test_web_ask_anything_router_general_query`: General queries answered without fake citations.
  - `test_single_executable_cli_no_browser_flag`: CLI `--no-browser` suppresses browser launch.

### Tier 2: Boundary & Corner Cases (35 Tests)
Extreme limits, zero-length buffers, corrupted signatures, expired timestamps, and drive scale boundaries:
- **Storage Boundaries**: Empty chunk slice insert; zero-norm vector query; huge `top_k=100,000` cap; SQL pre-filter tier isolation (Tier 0 through Tier 3); compaction deduplication.
- **Contract & Magika Boundaries**: Empty text string embedding; single-bit flipped contract hash; whitespace/tab prompt; null bytes in text stream; zero-byte empty buffer; 50KB large text stream; complex Unicode & emojis.
- **Ingestion Boundaries**: Empty directory path; 0-byte file; 10MB file size limit cap; Unicode and space-padded paths; partial chunk cache reuse during single-line edits.
- **Federated Mesh Boundaries**: Stale timestamp (>60s drift) replay rejection; forged signature rejection; zero-peer local fallback (<50ms); multi-peer consensus rank score boost; 20 concurrent queries without starvation.
- **Web UI Boundaries**: Empty prompt rejection; 6KB huge prompt handling; JSON serialization roundtrip of SSE citation chunks; empty QueryResult serialization; line formatting across multiple citations.

### Tier 3: Cross-Feature Pairwise Interactions (7 Tests)
- `test_pair_magika_to_dedup_to_isolated_storage`: Magika classifier -> BLAKE3 hash -> isolated LanceDB storage insert & retrieval.
- `test_pair_dedup_matching_with_access_tier_restriction`: Chunk hash exists in cache, but vector retrieval is blocked by AccessTier pre-filter.
- `test_pair_concurrent_ingestion_and_federated_mesh_query`: 50-chunk ingestion happening concurrently with federated mesh query.
- `test_pair_scatter_gather_timeout_during_active_query`: 400ms timeout fires while slow peer hangs, aborting cleanly.
- `test_pair_ed25519_auth_failure_blocks_downstream_storage_scan`: Forged signature fails authentication, preventing storage scan.
- `test_pair_contract_mismatch_prevents_peer_admission_to_mesh`: Mismatched contract hash aborts connection before peer joining.
- `test_pair_memory_security_volatile_vs_persistent_lifecycle`: Remote chunk zeroized on drop while local chunk remains persistent.

### Tier 4: Real-World Application Scenarios (6 Tests)
- `test_scenario_1_multi_node_federated_research_query`: Multi-node research query across Alpha (local), Beta (remote crypto), Gamma (remote wire) with structured citations within 400ms.
- `test_scenario_2_ask_anything_router_code_vs_general_query`: Ask Anything router distinguishing between grounded local code queries and general knowledge queries.
- `test_scenario_3_filesystem_lifecycle_edit_and_rename_propagation`: Project directory file edit, rename, and Level-1 BLAKE3 cache update.
- `test_scenario_4_enterprise_tiered_clearance_enforcement`: 4-tier clearance enforcement (Visitor, Employee, Executive, Admin) over single knowledge base.
- `test_scenario_5_cold_start_daemon_launcher_and_headless_mode`: Single executable startup verifying `--no-browser` headless mode.
- `test_scenario_6_30tb_drive_scale_deep_hierarchy_and_compaction`: 200 chunks across 20 nested subdirectories, multi-batch inserts, and compaction.

---

## 4. Test Suite File Layout

```
d:\harfile\QuorumRAG\tests\e2e\
├── Cargo.toml                              # Self-contained integration test package manifest
├── run_all_e2e_tests.ps1                   # Unified runner script with summary reporting
├── src\
│   └── lib.rs                              # Mathematical oracles, isolated storage engine, coordinator
├── test_storage_isolation.rs               # Tier 1 & 2: Arrow isolation, LanceDB hybrid search, compaction
├── test_gemma_contract.rs                  # Tier 1 & 2: Gemma 768d contract, BLAKE3 hash, Magika classifier
├── test_ingestion_dedup.rs                 # Tier 1 & 2: Crawler, watcher, 2-level BLAKE3 deduplication
├── test_federated_mesh.rs                  # Tier 1 & 2: libp2p Swarm, 400ms timeout, Ed25519 ACL, ZeroizeOnDrop
├── test_web_endpoints.rs                   # Tier 1 & 2: Axum 0.7 UI, SSE streaming, citations, launcher
├── test_cross_feature_combinations.rs      # Tier 3: Pairwise cross-feature interactions
└── test_real_world_scenarios.rs            # Tier 4: Real-world multi-node workloads and scenarios
```

---

## 5. Execution Instructions

### Unified E2E Test Suite Runner
```powershell
powershell -ExecutionPolicy Bypass -File "d:\harfile\QuorumRAG\tests\e2e\run_all_e2e_tests.ps1"
```

### Granular Per-Target Invocations
```powershell
# 1. Storage & Arrow Isolation (10 tests)
cargo test --manifest-path tests/e2e/Cargo.toml --test test_storage_isolation

# 2. Gemma Contract & Magika Classifier (14 tests)
cargo test --manifest-path tests/e2e/Cargo.toml --test test_gemma_contract

# 3. Ingestion & Two-Level Deduplication (10 tests)
cargo test --manifest-path tests/e2e/Cargo.toml --test test_ingestion_dedup

# 4. Federated Mesh & 400ms Timeout (10 tests)
cargo test --manifest-path tests/e2e/Cargo.toml --test test_federated_mesh

# 5. Web UI Endpoints & Single Executable (10 tests)
cargo test --manifest-path tests/e2e/Cargo.toml --test test_web_endpoints

# 6. Tier 3 Cross-Feature Combinations (7 tests)
cargo test --manifest-path tests/e2e/Cargo.toml --test test_cross_feature_combinations

# 7. Tier 4 Real-World Application Scenarios (6 tests)
cargo test --manifest-path tests/e2e/Cargo.toml --test test_real_world_scenarios
```
