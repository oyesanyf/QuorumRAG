//! Concurrency, Multithreading, and Zero-Overhead Stress Verification Suite (Milestone 4).
//!
//! Validates:
//! 1. 0 deadlocks under recursive RLM sub-queries via `RlmDepthAwareSemaphore`
//! 2. 0 permit leaks under task cancellation via `MeshQueryAdmissionController`
//! 3. Bounded RSS memory and safe UTF-8 character boundary snapping under high-throughput zero-copy slicing via `RlmParentSliceCache`
//! 4. Fast dynamic tail-latency cutoffs during mesh fan-out via `SwarmMeshDispatcher::calculate_peer_deadline`
//! 5. Structure-aware parent-child chunking and hierarchy breadcrumb propagation in `chunker.rs`
//! 6. Reciprocal Rank Fusion ($k=60.0$) combining dense vectors and sparse lexical spans
//! 7. Cross-platform OS background thread scheduling in `throttling.rs`

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

use quorum_coordinator::{
    global_peer_health_registry, MeshQueryAdmissionController, RrfCombiner,
    RlmDepthAwareSemaphore, RlmParentSliceCache, SwarmMeshDispatcher,
};
use quorum_ingest::chunker::{SectionHierarchyStack, TextChunker};
use quorum_ingest::throttling::{apply_background_thread_throttling, is_background_throttling_supported};
use quorum_ingest::ChunkerConfig;
use quorum_storage::StorageEngine;
use quorum_types::{DocumentChunk, ScoredChunk};

fn recursive_rlm_task(
    sem: Arc<RlmDepthAwareSemaphore>,
    depth: usize,
    max_depth: usize,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        let _permit = sem.acquire(depth).await.expect("Must acquire depth permit");
        tokio::time::sleep(Duration::from_millis(5)).await;

        if depth < max_depth {
            let mut children = Vec::new();
            for _ in 0..2 {
                let s_clone = Arc::clone(&sem);
                children.push(tokio::spawn(recursive_rlm_task(s_clone, depth + 1, max_depth)));
            }
            for child in children {
                child.await.expect("Child task failed");
            }
        }
    })
}

#[tokio::test]
async fn test_rlm_recursive_depth_aware_semaphore_zero_deadlocks() {
    // 4 levels of recursion: depth 0..=3.
    // Root level: 4 permits. Child depths: 4 permits each.
    let sem = Arc::new(RlmDepthAwareSemaphore::new(3, 4, 4));
    let initial_root_permits = sem.available_permits(0);
    assert_eq!(initial_root_permits, 4);

    // Spawn 8 concurrent root tasks that fan out recursively
    let mut root_handles = Vec::new();
    for _ in 0..8 {
        let s_clone = Arc::clone(&sem);
        root_handles.push(tokio::spawn(recursive_rlm_task(s_clone, 0, 3)));
    }

    // Verify all complete within 5 seconds without recursive deadlock
    let completion = timeout(Duration::from_secs(5), async {
        for handle in root_handles {
            handle.await.expect("Root task failed");
        }
    })
    .await;

    assert!(completion.is_ok(), "Recursive RLM tasks must never deadlock!");
    assert_eq!(sem.available_permits(0), 4, "Root permits must fully restore to 4");
    assert_eq!(sem.available_permits(1), 4, "Depth 1 permits must fully restore to 4");
    assert_eq!(sem.available_permits(2), 4, "Depth 2 permits must fully restore to 4");
    assert_eq!(sem.available_permits(3), 4, "Depth 3 permits must fully restore to 4");
}

#[tokio::test]
async fn test_mesh_admission_semaphore_zero_permit_leaks_on_cancellation() {
    let controller = MeshQueryAdmissionController::new(8, 2);
    assert_eq!(controller.global_semaphore.available_permits(), 8);

    let mut handles = Vec::new();
    let peer_name = "peer_test_cancellation_node";

    // Spawn 16 tasks contending for permits
    for i in 0..16 {
        let ctrl = controller.clone();
        let handle = tokio::spawn(async move {
            let (_global, _peer) = ctrl.acquire_permit(peer_name).await.expect("Acquire permit");
            tokio::time::sleep(Duration::from_millis(if i % 2 == 0 { 10 } else { 200 })).await;
        });
        handles.push(handle);
    }

    // Abort all odd-numbered handles midway to simulate query timeout/cancellation
    for (idx, handle) in handles.iter().enumerate() {
        if idx % 2 == 1 {
            handle.abort();
        }
    }

    // Wait for remaining handles
    for handle in handles {
        let _ = handle.await;
    }

    // Give Tokio task teardown a brief moment to drop OwnedSemaphorePermits
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(
        controller.global_semaphore.available_permits(),
        8,
        "Zero permit leaks: global permits must return to full capacity (8)"
    );

    let peer_sem = controller
        .per_peer_semaphores
        .get(peer_name)
        .expect("Peer sem exists");
    assert_eq!(
        peer_sem.available_permits(),
        2,
        "Zero permit leaks: per-peer permits must return to full capacity (2)"
    );
}

#[tokio::test]
async fn test_rlm_slice_cache_bounded_rss_zero_copy() {
    let cache = RlmParentSliceCache::new();

    // Create a 1MB multi-byte UTF-8 string containing Cyrillic, Chinese, Emoji, and ASCII
    let mut source = String::with_capacity(1_050_000);
    let sample_para = "QuorumRAG 高性能分布式检索 🚀 Архитектура ядра и параллелизм. \
                       Structure-aware chunking with deterministic parent-child hierarchy.\n";
    while source.len() < 1_000_000 {
        source.push_str(sample_para);
    }

    let doc_id = "doc_stress_large_parent_01";
    cache.insert_or_get(doc_id, source.as_bytes());
    assert_eq!(cache.len(), 1);

    // Concurrently issue 5,000 zero-copy slice requests with intentionally misaligned byte offsets
    let mut handles = Vec::new();
    for i in 0..5000 {
        let cache_clone = cache.clone();
        let handle = tokio::spawn(async move {
            let start = (i * 179) % 950_000;
            let end = start + 128;
            let sliced = cache_clone.slice_safe_utf8(doc_id, start, end);
            assert!(sliced.is_some(), "Slice must succeed");
            let s = sliced.unwrap();
            assert!(std::str::from_utf8(s.as_bytes()).is_ok(), "Must be valid UTF-8");
        });
        handles.push(handle);
    }

    for h in handles {
        h.await.expect("Slice task failed");
    }

    // Memory footprint: cache maintains only 1 backing buffer
    assert_eq!(cache.len(), 1);
    cache.clear();
    assert_eq!(cache.len(), 0);
}

#[tokio::test]
async fn test_mesh_dynamic_tail_latency_deadlines() {
    let registry = global_peer_health_registry();

    // Fast peer: avg RTT 20ms -> ((20 * 2.5) + 3000) = 3050ms -> clamped to min 4000ms floor
    let fast_peer = "peer_fast_123";
    registry.record_success(fast_peer, 20.0, 5);
    let d_fast = SwarmMeshDispatcher::calculate_peer_deadline(fast_peer, Duration::from_millis(5000));
    assert_eq!(d_fast, Duration::from_millis(4000), "Fast peer clamped to min 4000ms floor");

    // Slower peer: avg RTT 600ms -> ((600 * 2.5) + 3000) = 4500ms
    let slow_peer = "peer_slow_456";
    registry.record_success(slow_peer, 600.0, 3);
    let d_slow = SwarmMeshDispatcher::calculate_peer_deadline(slow_peer, Duration::from_millis(5000));
    assert_eq!(d_slow, Duration::from_millis(4500), "Slower peer deadline scales with RTT");

    // Unknown peer: returns requested timeout
    let unknown_peer = "peer_unknown_789";
    let d_unknown = SwarmMeshDispatcher::calculate_peer_deadline(unknown_peer, Duration::from_millis(4200));
    assert_eq!(d_unknown, Duration::from_millis(4200), "Unknown peer defaults to requested timeout");
}

#[test]
fn test_structure_aware_chunking_propagates_heading_hierarchy() {
    let markdown_doc = r#"# Distributed Consensus Systems
Introduction to Byzantine fault tolerance.

## Paxos and Raft
Comparison of leader-driven consensus algorithms.

### Quorum Slicing
Federated Byzantine Agreement in Stellar and QuorumRAG.
Details on minimal slice sets.
"#;

    let chunker = TextChunker::new(ChunkerConfig::default());
    let chunks = chunker.chunk_text_structure_aware(markdown_doc);
    assert!(!chunks.is_empty(), "Must produce structure-aware chunks");

    // Verify heading breadcrumbs
    let last_chunk = chunks.last().unwrap();
    assert_eq!(
        last_chunk.section_hierarchy,
        vec![
            "Distributed Consensus Systems".to_string(),
            "Paxos and Raft".to_string(),
            "Quorum Slicing".to_string(),
        ]
    );
    assert_eq!(last_chunk.section_title, "Quorum Slicing");
    assert_eq!(last_chunk.section_level, 3);
    assert_eq!(
        last_chunk.section_path,
        "Distributed Consensus Systems > Paxos and Raft > Quorum Slicing"
    );

    // Verify hierarchy stack helper
    let mut stack = SectionHierarchyStack::new();
    stack.push(1, "# Architecture".to_string(), 1, 0);
    stack.push(2, "## Storage".to_string(), 10, 150);
    assert_eq!(stack.hierarchy_titles(), vec!["# Architecture", "## Storage"]);
    assert_eq!(stack.current_title(), "## Storage");
    assert_eq!(stack.breadcrumb_string(), "# Architecture > ## Storage");
}

#[tokio::test]
async fn test_reciprocal_rank_fusion_dense_and_sparse() {
    fn make_chunk(id: &str, text: &str) -> DocumentChunk {
        DocumentChunk {
            chunk_id: id.to_string(),
            document_id: "doc1".to_string(),
            file_path: "docs/architecture.md".to_string(),
            line_start: 1,
            line_end: 10,
            blake3_hash: format!("hash_{}", id),
            access_tier: 0,
            vector: vec![0.0; 768],
            text_content: text.to_string(),
            metadata_json: "{}".to_string(),
        }
    }

    let c1 = make_chunk("chunk_1", "Dense and sparse match");
    let c2 = make_chunk("chunk_2", "Only dense match");
    let c3 = make_chunk("chunk_3", "Only sparse match");

    let dense = vec![
        ScoredChunk::new(c1.clone(), 0.95, "local", false),
        ScoredChunk::new(c2.clone(), 0.85, "local", false),
    ];
    let sparse = vec![
        ScoredChunk::new(c1.clone(), 12.5, "local", false),
        ScoredChunk::new(c3.clone(), 8.2, "local", false),
    ];

    // StorageEngine reciprocal_rank_fusion
    let fused_storage = StorageEngine::reciprocal_rank_fusion(dense.clone(), sparse.clone(), 60.0, 1.0, 1.0, &[], 10);
    assert_eq!(fused_storage.len(), 3);
    assert_eq!(fused_storage[0].chunk.chunk_id, "chunk_1");
    assert!((fused_storage[0].score - (2.0 / 61.0)).abs() < 1e-4);

    // Coordinator RrfCombiner::fuse_dense_and_sparse
    let fused_coordinator = RrfCombiner::fuse_dense_and_sparse(dense, sparse, 60.0, 1.0, 1.0, 10);
    assert_eq!(fused_coordinator.len(), 3);
    assert_eq!(fused_coordinator[0].chunk.chunk_id, "chunk_1");
}

#[test]
fn test_os_background_thread_priority_throttling() {
    assert!(is_background_throttling_supported());
    let res = apply_background_thread_throttling();
    assert!(res.is_ok(), "Applying OS background thread priority must succeed on active host");
}
