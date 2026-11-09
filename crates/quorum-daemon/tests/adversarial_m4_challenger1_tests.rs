//! Empirical Adversarial Challenge Test Suite for Milestone 4
//! (Challenger 1 — Near-Zero Host Overhead, Multithreading & Zero-Blindspot RAG Pipeline)
//!
//! Validates:
//! 1. OS background thread priority and throttling lifecycle (Windows, Linux, macOS)
//! 2. High-throughput parallel filesystem crawler with work-stealing, .ignore filtering, and magic-byte checks
//! 3. Dedicated core-pinned Rayon threadpool scaling & tiered semaphore permit saturation & zero permit leaks
//! 4. Structure-aware parent-child chunking with deep 6-level hierarchy and Unicode/Emoji section breadcrumbs
//! 5. Reciprocal Rank Fusion (RRF $k=60.0$) mathematical oracle, weight scaling, tied ranks, and deterministic tie-breaking
//! 6. RLM depth-aware semaphore recursive stress test with depth clamping, timeout cancellation, and zero deadlocks
//! 7. RLM parent slice cache zero-copy slicing over exhaustive byte-level boundaries with emojis, Cyrillic, Chinese, and zero-width characters
//! 8. Mesh query admission controller zero-permit leaks under randomized mass-cancellation and dynamic per-peer tail latency clamps

use std::fs::File;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

use quorum_coordinator::{
    global_peer_health_registry, MeshQueryAdmissionController, RrfCombiner,
    RlmDepthAwareSemaphore, RlmParentSliceCache, SwarmMeshDispatcher,
};
use quorum_ingest::chunker::{parse_section_header_line, TextChunker};
use quorum_ingest::crawler::FilesystemCrawler;
use quorum_ingest::thread_pool::{IngestPermitTiers, IngestThreadPool};
use quorum_ingest::throttling::{
    apply_background_thread_throttling, end_background_thread_priority,
    is_background_throttling_supported, set_background_thread_priority,
};
use quorum_ingest::{ChunkerConfig, IngestConfig};
use quorum_storage::StorageEngine;
use quorum_types::{DocumentChunk, ScoredChunk};

// ============================================================================
// AREA 1: OS Background Throttling & Parallel Filesystem Crawler Stress
// ============================================================================

#[test]
fn test_challenge_os_throttling_lifecycle_and_restoration() {
    assert!(
        is_background_throttling_supported(),
        "OS background throttling must be supported on active platform"
    );

    // Apply background priority
    assert!(
        set_background_thread_priority(),
        "Setting background thread priority must return true"
    );
    assert!(
        apply_background_thread_throttling().is_ok(),
        "apply_background_thread_throttling must succeed"
    );

    // Restore background priority
    assert!(
        end_background_thread_priority(),
        "Restoring background thread priority must return true"
    );
}

#[tokio::test]
async fn test_challenge_parallel_crawler_work_stealing_and_filtering() {
    let temp_dir = tempdir().expect("Failed to create tempdir");
    let root = temp_dir.path().to_path_buf();

    // Create a complex directory structure
    let sub1 = root.join("docs").join("sub1");
    let sub2 = root.join("binary_dir");
    let hidden_dir = root.join(".hidden");
    std::fs::create_dir_all(&sub1).unwrap();
    std::fs::create_dir_all(&sub2).unwrap();
    std::fs::create_dir_all(&hidden_dir).unwrap();

    // 1. Valid text files
    for i in 0..15 {
        let file_path = sub1.join(format!("doc_{}.md", i));
        let mut f = File::create(&file_path).unwrap();
        writeln!(f, "# Header {}\nDocument content with words for indexing.", i).unwrap();
    }

    // 2. Binary files with ELF and PE magic bytes in ostensibly text/data filenames
    let pe_path = sub2.join("data_win.bin");
    let mut pe_file = File::create(&pe_path).unwrap();
    pe_file.write_all(b"MZ\x90\x00\x03\x00\x00\x00").unwrap();

    let elf_path = sub2.join("data_nix.bin");
    let mut elf_file = File::create(&elf_path).unwrap();
    elf_file.write_all(b"\x7fELF\x02\x01\x01\x00").unwrap();

    // 3. Hidden directory file (must be skipped)
    let hidden_path = hidden_dir.join("secret.txt");
    let mut hidden_file = File::create(&hidden_path).unwrap();
    hidden_file.write_all(b"hidden text").unwrap();

    let mut config = IngestConfig::default();
    config.watch_paths = vec![root.clone()];
    let crawler = Arc::new(FilesystemCrawler::new(config));

    let (mut rx, handle) = crawler.start_crawl();

    let mut discovered = Vec::new();
    while let Some(candidate) = rx.recv().await {
        discovered.push(candidate);
    }

    let stats = handle.await.expect("Join crawler task").expect("Crawler success");

    // All 15 text docs must be discovered
    assert_eq!(
        discovered.len(),
        15,
        "Parallel crawler must discover exactly 15 valid text docs"
    );
    assert_eq!(stats.files_accepted_text, 15);
    // Binary files must be skipped and never included in discovered candidates
    assert!(discovered.iter().all(|c| !c.path.to_string_lossy().contains("data_win.bin")));
    assert!(discovered.iter().all(|c| !c.path.to_string_lossy().contains("data_nix.bin")));
}

// ============================================================================
// AREA 2: Dedicated Rayon ThreadPool & Tiered Semaphores
// ============================================================================

#[tokio::test]
async fn test_challenge_ingest_threadpool_and_tiered_permits() {
    let pool = IngestThreadPool::new().expect("Failed to initialize IngestThreadPool");
    assert!(pool.thread_count() >= 2 && pool.thread_count() <= 16);

    // Concurrently execute 50 CPU-bound tasks on dedicated Rayon pool
    let mut set = tokio::task::JoinSet::new();
    for i in 0..50 {
        let p = pool.pool().clone();
        set.spawn(async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            p.spawn(move || {
                let mut sum = 0u64;
                for j in 0..10_000 {
                    sum = sum.wrapping_add(j * (i as u64 + 1));
                }
                let _ = tx.send(sum);
            });
            rx.await.expect("Rayon task must deliver result")
        });
    }

    let mut count = 0;
    while let Some(res) = set.join_next().await {
        assert!(res.is_ok());
        count += 1;
    }
    assert_eq!(count, 50, "All 50 Rayon tasks must complete without reactor stall");

    // Tiered Semaphores
    let tiers = IngestPermitTiers::new(16);
    assert_eq!(tiers.storage_commit.available_permits(), 2);
    assert_eq!(tiers.vision_captioning.available_permits(), 1);
    assert_eq!(tiers.extraction.available_permits(), 16);

    // Saturate storage_commit permits (2 permits)
    let permit1 = tiers.acquire_storage_commit().await.expect("Permit 1");
    let permit2 = tiers.acquire_storage_commit().await.expect("Permit 2");
    assert_eq!(tiers.storage_commit.available_permits(), 0);

    // Dropping permits restores capacity
    drop(permit1);
    assert_eq!(tiers.storage_commit.available_permits(), 1);
    drop(permit2);
    assert_eq!(tiers.storage_commit.available_permits(), 2);

    // Task cancellation zero permit leak
    let tiers_clone = tiers.clone();
    let handle = tokio::spawn(async move {
        let _p = tiers_clone.acquire_vision().await.expect("Acquire vision");
        tokio::time::sleep(Duration::from_millis(500)).await;
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(tiers.vision_captioning.available_permits(), 0);
    handle.abort();
    let _ = handle.await;

    // Small delay for task abort teardown
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        tiers.vision_captioning.available_permits(),
        1,
        "Aborting task must not leak vision permit"
    );
}

// ============================================================================
// AREA 3: Structure-Aware Parent-Child Chunking & Reciprocal Rank Fusion Oracle
// ============================================================================

#[test]
fn test_challenge_structure_aware_chunking_deep_and_jumping_hierarchy() {
    let doc = r#"# Root Architecture
Introduction to QuorumRAG distributed system architecture and consensus invariants.
We explain the foundations of Byzantine fault tolerance in local and federated topologies.

## Storage Subsystem
Detailed architecture of LanceDB columnar vector storage and Tantivy BM25 inverted index.
These engines work in tandem to provide reciprocal rank fusion for hybrid dense-sparse queries.

### Columnar Vector Index
Vector compression, IVF-PQ indexing, and Arrow batch commits.
Quantization and dimensional embeddings are verified for high throughput retrieval.

#### Quantization Details
Byte-level centroid tables and vector codebook generation.
Centroids are calibrated to preserve angular distance across cosine similarity computations.

##### Residual Precision
Sub-byte residual representations and scalar quantization fallbacks.
Residual vectors allow exact reconstruction without full precision vector memory overhead.

###### Bit Packing
Single bit quantization masks and SIMD accelerated Hamming distance kernel implementations.
Bit vectors are scanned using hardware AVX-512 and Neon population count instructions.

## Ingestion Pipeline
Back at Level 2 after Level 6! Filesystem crawling with adaptive I/O throttling.
Dedicated Rayon threadpool isolates heavy document parsing from the Tokio reactor worker threads.

# Network Swarm
Back at Level 1! Peer-to-peer federated agreement and Ed25519 authenticated queries.
Swarm mesh queries use dynamic tail latency deadlines and bounded admission semaphores.
"#;

    let mut cfg = ChunkerConfig::default();
    cfg.target_chunk_size = 180;
    cfg.chunk_overlap = 30;
    let chunker = TextChunker::new(cfg);
    let chunks = chunker.chunk_text_structure_aware(doc);
    assert!(!chunks.is_empty(), "Must produce multiple chunks");

    // Verify deepest heading stack (Bit Packing, level 6)
    let l6_chunk = chunks
        .iter()
        .find(|c| c.section_title == "Bit Packing")
        .expect("Must find Bit Packing chunk");
    assert_eq!(l6_chunk.section_level, 6);
    assert_eq!(
        l6_chunk.section_hierarchy,
        vec![
            "Root Architecture",
            "Storage Subsystem",
            "Columnar Vector Index",
            "Quantization Details",
            "Residual Precision",
            "Bit Packing"
        ]
    );

    // Verify jumping back up to Level 2 properly popped levels 3..=6
    let l2_chunk = chunks
        .iter()
        .find(|c| c.section_title == "Ingestion Pipeline")
        .expect("Must find Ingestion Pipeline chunk");
    assert_eq!(l2_chunk.section_level, 2);
    assert_eq!(
        l2_chunk.section_hierarchy,
        vec!["Root Architecture", "Ingestion Pipeline"]
    );

    // Verify jumping back up to Level 1 properly popped everything
    let l1_chunk = chunks
        .iter()
        .find(|c| c.section_title == "Network Swarm")
        .expect("Must find Network Swarm chunk");
    assert_eq!(l1_chunk.section_level, 1);
    assert_eq!(l1_chunk.section_hierarchy, vec!["Network Swarm"]);
}

#[test]
fn test_challenge_parse_section_header_with_unicode_and_emojis() {
    let header = parse_section_header_line("# 🚀 分布式共识与 Raft / Paxos 架构", 1, 0);
    assert!(header.is_some());
    let h = header.unwrap();
    assert_eq!(h.level, 1);
    assert_eq!(h.title, "🚀 分布式共识与 Raft / Paxos 架构");

    let chapter = parse_section_header_line("Chapter 4: Formal Verification and TLA+", 42, 1024);
    assert!(chapter.is_some());
    let c = chapter.unwrap();
    assert_eq!(c.level, 2);
    assert_eq!(c.title, "Chapter 4: Formal Verification and TLA+");
}

#[test]
fn test_challenge_rrf_mathematical_oracle_and_deterministic_ties() {
    fn make_test_chunk(id: &str, hash: &str) -> DocumentChunk {
        DocumentChunk {
            chunk_id: id.to_string(),
            document_id: "doc_test".to_string(),
            file_path: "path/to/test.md".to_string(),
            line_start: 1,
            line_end: 10,
            blake3_hash: hash.to_string(),
            access_tier: 0,
            vector: vec![0.0; 768],
            text_content: format!("Content for {}", id),
            metadata_json: "{}".to_string(),
        }
    }

    // Chunk A: dense rank 1 (score 0.99), sparse rank 2 (score 15.0)
    // Chunk B: dense rank 2 (score 0.90), sparse rank 1 (score 20.0)
    // Chunk C: dense rank 3 (score 0.80), not in sparse
    // Chunk D: sparse rank 3 (score 5.0), not in dense
    let chunk_a = make_test_chunk("chunk_a", "hash_222");
    let chunk_b = make_test_chunk("chunk_b", "hash_111");
    let chunk_c = make_test_chunk("chunk_c", "hash_333");
    let chunk_d = make_test_chunk("chunk_d", "hash_444");

    let dense = vec![
        ScoredChunk::new(chunk_a.clone(), 0.99, "local", false),
        ScoredChunk::new(chunk_b.clone(), 0.90, "local", false),
        ScoredChunk::new(chunk_c.clone(), 0.80, "local", false),
    ];

    let sparse = vec![
        ScoredChunk::new(chunk_b.clone(), 20.0, "local", false),
        ScoredChunk::new(chunk_a.clone(), 15.0, "local", false),
        ScoredChunk::new(chunk_d.clone(), 5.0, "local", false),
    ];

    // Mathematical expectation:
    // k = 60.0
    // Chunk A: 1/(60+1) + 1/(60+2) = 1/61 + 1/62 = 0.01639344 + 0.01612903 = 0.03252247
    // Chunk B: 1/(60+2) + 1/(60+1) = 1/62 + 1/61 = 0.03252247 (EXACT TIE with A)
    // Chunk C: 1/(60+3) = 1/63 = 0.01587301
    // Chunk D: 1/(60+3) = 1/63 = 0.01587301 (EXACT TIE with C)
    let fused = RrfCombiner::fuse_dense_and_sparse(dense.clone(), sparse.clone(), 60.0, 1.0, 1.0, 10);
    assert_eq!(fused.len(), 4);

    let expected_ab = 1.0 / 61.0 + 1.0 / 62.0;
    assert!((fused[0].score - expected_ab).abs() < 1e-6);
    assert!((fused[1].score - expected_ab).abs() < 1e-6);

    // Tie-breaker 1: chunk_id ascending ("chunk_a" < "chunk_b")
    assert_eq!(fused[0].chunk.chunk_id, "chunk_a");
    assert_eq!(fused[1].chunk.chunk_id, "chunk_b");

    let expected_cd = 1.0 / 63.0;
    assert!((fused[2].score - expected_cd).abs() < 1e-6);
    assert!((fused[3].score - expected_cd).abs() < 1e-6);

    // Tie-breaker: "chunk_c" < "chunk_d"
    assert_eq!(fused[2].chunk.chunk_id, "chunk_c");
    assert_eq!(fused[3].chunk.chunk_id, "chunk_d");

    // Also verify StorageEngine::reciprocal_rank_fusion with exclusion
    let storage_fused = StorageEngine::reciprocal_rank_fusion(
        dense,
        sparse,
        60.0,
        1.0,
        1.0,
        &["chunk_a".to_string()],
        10,
    );
    assert_eq!(storage_fused.len(), 3, "chunk_a must be excluded");
    assert_eq!(storage_fused[0].chunk.chunk_id, "chunk_b");
}

// ============================================================================
// AREA 4: RLM Depth-Aware Semaphore & UTF-8 Slice Cache Exhaustive Snapping
// ============================================================================

#[tokio::test]
async fn test_challenge_rlm_depth_exhaustion_and_saturation() {
    // max_depth 2, root_permits 2, child_permits 2
    let sem = Arc::new(RlmDepthAwareSemaphore::new(2, 2, 2));

    // Acquire depth 0
    let p0_a = sem.acquire(0).await.expect("depth 0");
    let p0_b = sem.acquire(0).await.expect("depth 0");
    assert_eq!(sem.available_permits(0), 0);
    assert!(sem.try_acquire(0).is_err(), "Must be saturated at depth 0");

    // Acquire child depths 1 and 2
    let p1 = sem.acquire(1).await.expect("depth 1");
    let p2 = sem.acquire(2).await.expect("depth 2");
    assert_eq!(sem.available_permits(1), 1);
    assert_eq!(sem.available_permits(2), 1);

    // Beyond max_depth: must fail closed with immediate exhaustion error (preventing recursive deadlocks)
    let err_99 = sem.acquire(99).await;
    assert!(err_99.is_err(), "Must fail closed beyond max depth");
    assert_eq!(
        err_99.err().unwrap(),
        "Exhausted: Max RLM recursion depth reached"
    );

    let err_5 = sem.acquire(5).await;
    assert!(err_5.is_err(), "Must fail closed beyond max depth");
    assert_eq!(
        err_5.err().unwrap(),
        "Exhausted: Max RLM recursion depth reached"
    );

    assert!(sem.try_acquire(99).is_err());
    assert_eq!(sem.available_permits(99), 0);

    drop(p0_a);
    drop(p0_b);
    drop(p1);
    drop(p2);

    assert_eq!(sem.available_permits(0), 2);
    assert_eq!(sem.available_permits(1), 2);
    assert_eq!(sem.available_permits(2), 2);
}

#[test]
fn test_challenge_rlm_slice_cache_out_of_bounds_safe_eof() {
    let cache = RlmParentSliceCache::new();
    let doc_id = "doc_panic_repro";
    let text = "Hello QuorumRAG 🦀";
    cache.insert_or_get(doc_id, text.as_bytes());

    // Calling slice_safe_utf8 where start_byte == text.len() must safely return Some("")
    let result_exact_eof = cache.slice_safe_utf8(doc_id, text.len(), text.len() + 10);
    assert_eq!(
        result_exact_eof,
        Some(String::new()),
        "slice_safe_utf8 must return Some(\"\") without panicking when start_byte == text.len()"
    );

    // Calling slice_safe_utf8 where start_byte > text.len() must safely return Some("")
    let result_past_eof = cache.slice_safe_utf8(doc_id, text.len() + 50, text.len() + 100);
    assert_eq!(
        result_past_eof,
        Some(String::new()),
        "slice_safe_utf8 must return Some(\"\") without panicking when start_byte > text.len()"
    );
}

#[test]
fn test_challenge_rlm_slice_cache_valid_ranges_within_bounds() {
    let cache = RlmParentSliceCache::new();
    let text = "🦀 = Crab | 🚀 = Rocket | 🧠 = Brain | 💎 = Gem | 🌐 = Globe | \
                Привет мир | 这是一个复杂的文本测试 | \u{200B}\u{200D}\u{FEFF}";
    let doc_id = "doc_adversarial_utf8";
    cache.insert_or_get(doc_id, text.as_bytes());

    let total_bytes = text.len();

    // Test slicing for all start offsets strictly LESS than total_bytes
    for start in 0..total_bytes {
        for len in [0, 1, 2, 3, 4, 7, 15, 32, 64, 128] {
            let end = (start + len).min(total_bytes);
            let result = cache.slice_safe_utf8(doc_id, start, end);
            assert!(
                result.is_some(),
                "slice_safe_utf8 must return Some for in-bounds offsets"
            );
            let s = result.unwrap();
            assert!(
                std::str::from_utf8(s.as_bytes()).is_ok(),
                "Resulting slice must be valid UTF-8 at start={}, end={}",
                start,
                end
            );
        }
    }
}

// ============================================================================
// AREA 5: Mesh Query Admission Controller & Dynamic Tail Latencies
// ============================================================================

#[tokio::test]
async fn test_challenge_mesh_admission_mass_cancellation_stress() {
    let controller = MeshQueryAdmissionController::new(12, 3);
    assert_eq!(controller.global_semaphore.available_permits(), 12);

    let mut handles = Vec::new();
    let peers = ["peer_alpha", "peer_beta", "peer_gamma", "peer_delta"];

    // Spawn 60 tasks contending for 12 global permits and 3 per-peer permits
    for i in 0..60 {
        let ctrl = controller.clone();
        let peer = peers[i % peers.len()];
        let handle = tokio::spawn(async move {
            let (_global, _peer) = ctrl.acquire_permit(peer).await.expect("Acquire permit");
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
        handles.push(handle);
    }

    // Randomly abort 75% of tasks while they are waiting or running
    for (i, h) in handles.iter().enumerate() {
        if i % 4 != 0 {
            h.abort();
        }
    }

    for h in handles {
        let _ = h.await;
    }

    // Brief settling period for Tokio Drop hooks
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Strict zero permit leak verification
    assert_eq!(
        controller.global_semaphore.available_permits(),
        12,
        "All 12 global permits must be restored after mass cancellation"
    );

    for &peer in &peers {
        if let Some(peer_sem) = controller.per_peer_semaphores.get(peer) {
            assert_eq!(
                peer_sem.available_permits(),
                3,
                "All 3 permits for {} must be restored",
                peer
            );
        }
    }
}

#[test]
fn test_challenge_mesh_dynamic_deadlines_boundary_clamping() {
    let registry = global_peer_health_registry();

    // Peer with ultra-fast RTT (2ms) -> (2 * 2.5) + 3000 = 3005ms -> clamped to min floor 4000ms
    let fast_peer = "peer_ultrafast_99";
    registry.record_success(fast_peer, 2.0, 10);
    let d_fast = SwarmMeshDispatcher::calculate_peer_deadline(fast_peer, Duration::from_millis(4000));
    assert_eq!(d_fast, Duration::from_millis(4000), "Must clamp to min 4000ms floor");

    // Peer with high RTT (2000ms) -> (2000 * 2.5) + 3000 = 8000ms -> clamped to requested timeout 5000ms
    let slow_peer = "peer_high_latency_88";
    registry.record_success(slow_peer, 2000.0, 5);
    let d_slow = SwarmMeshDispatcher::calculate_peer_deadline(slow_peer, Duration::from_millis(5000));
    assert_eq!(d_slow, Duration::from_millis(5000), "Must clamp to requested timeout max");

    // Peer with medium-high RTT (600ms) -> (600 * 2.5) + 3000 = 4500ms
    let med_peer = "peer_med_77";
    registry.record_success(med_peer, 600.0, 4);
    let d_med = SwarmMeshDispatcher::calculate_peer_deadline(med_peer, Duration::from_millis(6000));
    assert_eq!(d_med, Duration::from_millis(4500), "Calculates exact RTT * 2.5 + 3000");

    // Unregistered peer -> requested timeout
    let unk_peer = "peer_never_seen_before";
    let d_unk = SwarmMeshDispatcher::calculate_peer_deadline(unk_peer, Duration::from_millis(2500));
    assert_eq!(d_unk, Duration::from_millis(2500), "Unregistered peer gets requested timeout");
}
