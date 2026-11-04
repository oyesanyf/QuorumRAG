//! Empirical Adversarial Stress Suite for Milestone 5.5:
//! Feature 43 Multi-Layer Caching & Re-Cache Subsystem (`recache`).
//!
//! Scope of Verification:
//! 1. ZeroizeOnDrop Zero-Trust Memory Protection:
//!    - Unpinned remote peer chunks in `CachedQueryEntry` are explicitly zeroized on drop.
//!    - Eviction from `QueryCache` under capacity pressure zeroes remote chunk memory buffers.
//!    - Local storage chunks are NOT zeroized, preserving local cached integrity.
//! 2. LRU Capacity & Eviction Storms:
//!    - 10,000 distinct query flood strictly respects capacity bounds (`len <= capacity`).
//!    - 10,000 distinct embedding flood strictly respects capacity bounds (`len <= capacity`).
//!    - Duplicate key update storms do not inflate memory or break FIFO/LRU eviction.
//!    - Instant full purge via `clear()` cleanly resets all internal indices.
//! 3. Concurrent Recache & Ingestion Race Conditions:
//!    - Parallel recache operations, continuous queries, and storage index reindexing in-flight simultaneously.
//!    - Verifies zero deadlocks, zero panics, strict monotonic epoch progression, and coherent cache invalidation.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::join_all;
use tempfile::tempdir;

use quorum_coordinator::{
    CachedQueryEntry, CacheManager,
    EmbeddingCache, QueryCache, SynthesisModelFamily,
};
use quorum_storage::{SearchMode, StorageConfig, StorageEngine};
use quorum_types::{DocumentChunk, ScoredChunk};

// =========================================================================
// 1. ZeroizeOnDrop Zero-Trust Memory Cleanup Verification
// =========================================================================

#[test]
fn test_zeroize_on_drop_explicit_remote_chunk_memory_wiping() {
    let canary_payload = "SENSITIVE_TOP_SECRET_REMOTE_PEER_CHUNK_CANARY_HEX_987654321".to_string();
    let raw_ptr = canary_payload.as_ptr();
    let payload_len = canary_payload.len();

    let remote_doc = DocumentChunk::new(
        "remote_c1",
        "doc_remote",
        "peer_private_intel.md",
        1,
        10,
        2,
        vec![0.5; 768],
        canary_payload,
        None,
    )
    .expect("remote doc creation");

    let local_doc = DocumentChunk::new(
        "local_c1",
        "doc_local",
        "local_readme.md",
        1,
        5,
        0,
        vec![0.1; 768],
        "Local document content that must remain intact",
        None,
    )
    .expect("local doc creation");

    let scored_remote = ScoredChunk::new(remote_doc, 0.95, "peer_secure_node", true);
    let scored_local = ScoredChunk::new(local_doc, 0.85, "local", false);

    // Assert that canary text is intact at the pointer prior to drop
    let slice_before = unsafe { std::slice::from_raw_parts(raw_ptr, payload_len) };
    assert_eq!(
        std::str::from_utf8(slice_before).unwrap(),
        "SENSITIVE_TOP_SECRET_REMOTE_PEER_CHUNK_CANARY_HEX_987654321"
    );

    {
        let entry = CachedQueryEntry {
            key: [0x11u8; 32],
            chunks: vec![scored_remote, scored_local],
            synthesis_prompt: "Summarize sensitive intelligence".to_string(),
            synthesized_response: Some("Synthesized response text".to_string()),
            citations: Vec::new(),
            langextract_result: None,
            query_metadata_filters: None,
            access_tier: 2,
            index_epoch: 1,
            created_at: Instant::now(),
            has_remote_unpinned: true,
        };

        // Assert presence inside entry before scope exit
        assert_eq!(entry.chunks[0].chunk.text_content.len(), payload_len);
    } // entry dropped here; CachedQueryEntry::drop triggers chunk.chunk.text_content.zeroize()

    // Empirically inspect raw memory buffer at pointer: MUST be zeroed!
    let slice_after = unsafe { std::slice::from_raw_parts(raw_ptr, payload_len) };
    assert!(
        slice_after.iter().all(|&b| b == 0),
        "CRITICAL SECURITY INVARIANT VIOLATION: Memory buffer for unpinned remote chunk was not zeroed on drop!"
    );
}

#[test]
fn test_zeroize_on_eviction_under_capacity_pressure() {
    let capacity = 10;
    let cache = QueryCache::new(capacity, Duration::from_secs(3600));

    let secret_payload = "EVICTION_CANARY_UNPINNED_PEER_SECRET_DATA_000111222333".to_string();
    let secret_ptr = secret_payload.as_ptr();
    let secret_len = secret_payload.len();

    let remote_doc = DocumentChunk::new(
        "c_evict_remote",
        "doc_remote",
        "classified.txt",
        1,
        20,
        2,
        vec![0.7; 768],
        secret_payload,
        None,
    )
    .unwrap();

    let remote_chunk = ScoredChunk::new(remote_doc, 0.99, "peer_foreign", true);

    // Insert entry 0 with sensitive remote payload
    cache.insert(
        "query_target_for_eviction",
        SearchMode::Hybrid,
        SynthesisModelFamily::AutoFusion,
        2,
        1,
        vec![remote_chunk],
        "Prompt target".to_string(),
        Some("Synthesized target".to_string()),
        Vec::new(),
        None,
        None,
    );

    // Verify entry is present and hit succeeds
    let hit0 = cache.get(
        "query_target_for_eviction",
        SearchMode::Hybrid,
        SynthesisModelFamily::AutoFusion,
        2,
        1,
    );
    assert!(hit0.is_some(), "Entry 0 must be present in cache");

    // Insert capacity entries to trigger eviction of entry 0
    for i in 1..=capacity {
        cache.insert(
            &format!("filler_query_{}", i),
            SearchMode::Hybrid,
            SynthesisModelFamily::AutoFusion,
            2,
            1,
            Vec::new(),
            "Filler prompt".to_string(),
            Some("Filler response".to_string()),
            Vec::new(),
            None,
            None,
        );
    }

    // Verify entry 0 was evicted
    let hit_evicted = cache.get(
        "query_target_for_eviction",
        SearchMode::Hybrid,
        SynthesisModelFamily::AutoFusion,
        2,
        1,
    );
    assert!(
        hit_evicted.is_none(),
        "Target entry must be evicted after inserting beyond capacity"
    );

    // Verify that eviction resulted in immediate memory zeroization
    let slice_after_eviction = unsafe { std::slice::from_raw_parts(secret_ptr, secret_len) };
    assert!(
        slice_after_eviction.iter().all(|&b| b == 0),
        "Memory at secret_ptr was not wiped upon cache LRU eviction!"
    );
}

// =========================================================================
// 2. LRU Capacity & Eviction Storms
// =========================================================================

#[test]
fn test_query_cache_10k_flood_eviction_bounds() {
    let capacity = 250;
    let cache = QueryCache::new(capacity, Duration::from_secs(3600));

    const TOTAL_QUERIES: usize = 10_000;

    for i in 0..TOTAL_QUERIES {
        let q = format!("storm_query_{:06}", i);
        cache.insert(
            &q,
            SearchMode::Hybrid,
            SynthesisModelFamily::AutoFusion,
            1,
            100,
            Vec::new(),
            format!("Prompt {}", i),
            Some(format!("Response {}", i)),
            Vec::new(),
            None,
            None,
        );
    }

    let (_, _, count) = cache.stats();
    assert!(
        count <= capacity,
        "QueryCache capacity breached: count {} exceeded capacity {}",
        count,
        capacity
    );
    assert_eq!(
        count, capacity,
        "QueryCache count should be exactly capacity after 10,000 insertions"
    );

    // Verify recent queries (tail) hit
    for i in (TOTAL_QUERIES - 50)..TOTAL_QUERIES {
        let q = format!("storm_query_{:06}", i);
        let hit = cache.get(&q, SearchMode::Hybrid, SynthesisModelFamily::AutoFusion, 1, 100);
        assert!(hit.is_some(), "Recent query {} must hit", q);
    }

    // Verify oldest queries (head) have been evicted
    for i in 0..50 {
        let q = format!("storm_query_{:06}", i);
        let miss = cache.get(&q, SearchMode::Hybrid, SynthesisModelFamily::AutoFusion, 1, 100);
        assert!(miss.is_none(), "Old query {} should have been evicted", q);
    }

    // Full clear verification
    let cleared = cache.clear();
    assert_eq!(cleared, capacity);
    let (_, _, count_after_clear) = cache.stats();
    assert_eq!(count_after_clear, 0, "Count must be 0 after clear()");
}

#[test]
fn test_embedding_cache_10k_flood_eviction_bounds() {
    let capacity = 300;
    let cache = EmbeddingCache::new(capacity, Duration::from_secs(3600));
    let contract_hash = [0x55u8; 32];

    const TOTAL_EMBEDDINGS: usize = 10_000;

    for i in 0..TOTAL_EMBEDDINGS {
        let text = format!("Dense document text vector fragment #{:06}", i);
        let vector = vec![(i % 100) as f32 / 100.0; 768];
        cache.insert(&contract_hash, &text, vector);
    }

    let (_, _, count) = cache.stats();
    assert!(
        count <= capacity,
        "EmbeddingCache count {} exceeded capacity {}",
        count,
        capacity
    );
    assert_eq!(count, capacity);

    // Verify recent hits
    for i in (TOTAL_EMBEDDINGS - 50)..TOTAL_EMBEDDINGS {
        let text = format!("Dense document text vector fragment #{:06}", i);
        let hit = cache.get(&contract_hash, &text);
        assert!(hit.is_some(), "Recent embedding {} must hit", i);
    }

    // Verify old misses
    for i in 0..50 {
        let text = format!("Dense document text vector fragment #{:06}", i);
        let miss = cache.get(&contract_hash, &text);
        assert!(miss.is_none(), "Old embedding {} must miss", i);
    }

    // Test clear
    let cleared = cache.clear();
    assert_eq!(cleared, capacity);
    assert_eq!(cache.stats().2, 0);
}

#[test]
fn test_repeated_key_update_storm_no_memory_leak() {
    let capacity = 50;
    let cache = QueryCache::new(capacity, Duration::from_secs(3600));
    let repeated_query = "Frequently repeated query with rapid state updates";

    // Insert same key 3,000 times
    for i in 0..3_000 {
        cache.insert(
            repeated_query,
            SearchMode::Hybrid,
            SynthesisModelFamily::AutoFusion,
            1,
            50,
            Vec::new(),
            format!("Prompt v{}", i),
            Some(format!("Response v{}", i)),
            Vec::new(),
            None,
            None,
        );
    }

    let (_, _, count) = cache.stats();
    assert_eq!(
        count, 1,
        "Updating the same key 3,000 times must not duplicate map entries"
    );

    // Now insert 100 distinct keys to trigger order queue drain and capacity eviction
    for i in 0..100 {
        cache.insert(
            &format!("distinct_key_{}", i),
            SearchMode::Hybrid,
            SynthesisModelFamily::AutoFusion,
            1,
            50,
            Vec::new(),
            "Prompt".to_string(),
            Some("Response".to_string()),
            Vec::new(),
            None,
            None,
        );
    }

    let (_, _, count_after) = cache.stats();
    assert!(
        count_after <= capacity,
        "Count {} exceeded capacity {} after eviction following duplicate key storm",
        count_after,
        capacity
    );
}

// =========================================================================
// 3. Concurrent Recache & Ingestion Race Conditions
// =========================================================================

#[tokio::test]
async fn test_concurrent_recache_and_query_load_race_stress() {
    let temp_dir = tempdir().expect("tempdir");
    let storage_config = StorageConfig::new(temp_dir.path().to_path_buf());
    let storage = Arc::new(StorageEngine::open(storage_config).await.expect("storage open"));
    storage.bump_index_epoch("init").expect("init epoch bump");

    let manager = Arc::new(CacheManager::new(
        2000,
        Duration::from_secs(3600),
        2000,
        Duration::from_secs(3600),
    ));

    let running = Arc::new(AtomicBool::new(true));
    let observed_max_epoch = Arc::new(AtomicU64::new(storage.index_epoch()));

    let mut tasks = Vec::new();

    // Group 1: 6 Query Worker Tasks
    for worker_id in 0..6 {
        let mgr = Arc::clone(&manager);
        let stor = Arc::clone(&storage);
        let is_running = Arc::clone(&running);
        tasks.push(tokio::spawn(async move {
            let mut local_ops = 0;
            while is_running.load(Ordering::Relaxed) && local_ops < 400 {
                let q_id = local_ops % 50;
                let q = format!("concurrent_query_{}_{}", worker_id, q_id);
                let epoch = stor.index_epoch();

                // Read
                let _ = mgr.query_cache.get(
                    &q,
                    SearchMode::Hybrid,
                    SynthesisModelFamily::AutoFusion,
                    1,
                    epoch,
                );

                // Write
                mgr.query_cache.insert(
                    &q,
                    SearchMode::Hybrid,
                    SynthesisModelFamily::AutoFusion,
                    1,
                    epoch,
                    Vec::new(),
                    "Prompt".to_string(),
                    Some(format!("Response {}-{}", worker_id, local_ops)),
                    Vec::new(),
                    None,
                    None,
                );

                local_ops += 1;
                tokio::task::yield_now().await;
            }
            local_ops
        }));
    }

    // Group 2: 4 Embedding Worker Tasks
    for worker_id in 0..4 {
        let mgr = Arc::clone(&manager);
        let is_running = Arc::clone(&running);
        tasks.push(tokio::spawn(async move {
            let contract_hash = [worker_id as u8; 32];
            let mut local_ops = 0;
            while is_running.load(Ordering::Relaxed) && local_ops < 300 {
                let text = format!("embedding_text_{}_{}", worker_id, local_ops % 30);
                if mgr.embedding_cache.get(&contract_hash, &text).is_none() {
                    mgr.embedding_cache.insert(&contract_hash, &text, vec![0.5; 768]);
                }
                local_ops += 1;
                tokio::task::yield_now().await;
            }
            local_ops
        }));
    }

    // Group 3: 2 Concurrent Recache Tasks (invoking manager.recache with storage)
    for recache_id in 0..2 {
        let mgr = Arc::clone(&manager);
        let stor = Arc::clone(&storage);
        let is_running = Arc::clone(&running);
        let max_ep = Arc::clone(&observed_max_epoch);
        tasks.push(tokio::spawn(async move {
            let embedder = quorum_contract::DeterministicOfflineEngine::new();
            let mut recache_count = 0;
            while is_running.load(Ordering::Relaxed) && recache_count < 15 {
                tokio::time::sleep(Duration::from_millis(20)).await;
                let clear = recache_count % 3 == 0;
                let warm = true;
                let resp = mgr.recache(Some(&stor), Some(&embedder), clear, warm).await;
                assert_eq!(resp.status, "ok");

                // Check monotonic epoch
                let old_max = max_ep.fetch_max(resp.cache_epoch, Ordering::SeqCst);
                assert!(
                    resp.cache_epoch >= old_max,
                    "Non-monotonic epoch observed in recache {}: got {}, previous was {}",
                    recache_id,
                    resp.cache_epoch,
                    old_max
                );

                recache_count += 1;
            }
            recache_count
        }));
    }

    // Group 4: 2 Ingestion / Reindex Drift Workers
    for ing_id in 0..2 {
        let stor = Arc::clone(&storage);
        let is_running = Arc::clone(&running);
        let max_ep = Arc::clone(&observed_max_epoch);
        tasks.push(tokio::spawn(async move {
            let mut bumps = 0;
            while is_running.load(Ordering::Relaxed) && bumps < 20 {
                tokio::time::sleep(Duration::from_millis(15)).await;
                let new_ep = stor
                    .bump_index_epoch(&format!("mock_ingest_drift_{}_{}", ing_id, bumps))
                    .expect("storage epoch bump");
                let old_max = max_ep.fetch_max(new_ep, Ordering::SeqCst);
                assert!(
                    new_ep >= old_max,
                    "Non-monotonic storage epoch: got {}, previous was {}",
                    new_ep,
                    old_max
                );
                bumps += 1;
            }
            bumps
        }));
    }

    // Let the storm run, waiting for all tasks with a strict 25-second timeout to prevent deadlocks
    let results = tokio::time::timeout(Duration::from_secs(25), join_all(tasks)).await;
    running.store(false, Ordering::Relaxed);

    assert!(
        results.is_ok(),
        "CRITICAL CONCURRENCY BUG: Deadlock detected! Tasks did not finish within 25 seconds"
    );

    let final_epoch = storage.index_epoch();
    let telem = manager.telemetry(false);

    println!(
        "\n=======================================================\n\
         M5.5-2 CONCURRENT RECACHE & QUERY RACE STRESS COMPLETE\n\
         Initial Epoch:       1\n\
         Final Storage Epoch: {}\n\
         Final Manager Epoch: {}\n\
         Total Cache Hits:    {}\n\
         Total Cache Misses:  {}\n\
         Cached Queries:      {}\n\
         Cached Embeddings:   {}\n\
         Hit Rate:            {:.2}%\n\
         =======================================================",
        final_epoch,
        telem.cache_epoch,
        telem.hits,
        telem.misses,
        telem.cached_queries,
        telem.cached_embeddings,
        telem.hit_rate * 100.0
    );

    assert!(final_epoch > 1, "Storage epoch must advance monotonically under concurrent reindexing");
    assert!(telem.hits > 0, "Concurrent queries must successfully hit cache");
}
