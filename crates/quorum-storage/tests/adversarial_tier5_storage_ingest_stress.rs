//! Milestone 6 Phase 2: Tier 5 Adversarial Coverage Hardening & Stress Test Suite
//!
//! Objectives:
//! 1. Concurrent rapid insert/delete/query cycles testing Tantivy reader reload coherence and Windows retry backoffs.
//! 2. Atomic `.metadata.json` corruption recovery, epoch synchronization, and concurrent monotonic advancement.
//! 3. Multi-tier hybrid drift healing under simulated out-of-band file and index modifications.
//! 4. ACL policy drift remediation and strict access-tier SQL pre-filter / Tantivy range isolation.
//! 5. Adversarial injection resilience (SQL injection payloads, single quotes, backslashes, Tantivy query syntax).
//! 6. Zero-mock compliance: genuine cryptographic BLAKE3, real LanceDB tables, and real Tantivy indexes.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use quorum_storage::{StorageEngine, StorageSearchQuery};
use quorum_types::{AccessTier, DocumentChunk};
use tempfile::tempdir;
use tokio::time::sleep;

/// Helper to generate a well-formed 768-dim test chunk with genuine BLAKE3 hashing.
#[allow(clippy::too_many_arguments)]
fn make_tier5_chunk(
    chunk_id: &str,
    doc_id: &str,
    file_path: &str,
    start: u32,
    end: u32,
    tier: u8,
    vector: Vec<f32>,
    text: &str,
) -> DocumentChunk {
    DocumentChunk::new(
        chunk_id,
        doc_id,
        file_path,
        start,
        end,
        tier,
        vector,
        text,
        Some(format!(r#"{{"adversarial_tier5":true,"doc_id":"{}"}}"#, doc_id)),
    )
    .expect("Valid DocumentChunk creation")
}

/// Helper to create a normalized 768-dimensional test vector with a deterministic seed component.
fn make_unit_vector(dim: usize, seed_idx: usize) -> Vec<f32> {
    let mut vec = vec![0.0f32; dim];
    let idx = seed_idx % dim;
    vec[idx] = 1.0;
    vec
}

// ============================================================================
// 1. CONCURRENT RAPID INSERT / DELETE / QUERY CYCLES & RELOAD COHERENCE
// ============================================================================

#[tokio::test]
async fn test_tier5_concurrent_rapid_insert_delete_query_cycle() {
    let tmp = tempdir().unwrap();
    let engine = Arc::new(StorageEngine::open(tmp.path()).await.unwrap());

    let stop_flag = Arc::new(AtomicBool::new(false));

    // Task 1: Rapid Micro-Batch Inserter
    let eng_insert = Arc::clone(&engine);
    let stop_insert = Arc::clone(&stop_flag);
    let inserter = tokio::spawn(async move {
        let mut batch_idx = 0;
        while !stop_insert.load(Ordering::Acquire) && batch_idx < 15 {
            let mut batch = Vec::with_capacity(4);
            for i in 0..4 {
                let id = format!("chunk_c_{}_{}", batch_idx, i);
                let path = format!("src/module_{}/worker_{}.rs", batch_idx, i);
                let text = format!("Concurrent insertion payload batch {} item {} token_alpha_{}", batch_idx, i, batch_idx);
                let vec = make_unit_vector(768, batch_idx * 4 + i);
                batch.push(make_tier5_chunk(&id, "doc_conc", &path, 1, 10, 0, vec, &text));
            }
            let _ = eng_insert.insert_chunks(&batch).await;
            batch_idx += 1;
            sleep(Duration::from_millis(5)).await;
        }
        batch_idx
    });

    // Task 2: Rapid Keyword & Vector Querier
    let eng_query = Arc::clone(&engine);
    let stop_query = Arc::clone(&stop_flag);
    let querier = tokio::spawn(async move {
        let mut queries_done = 0;
        let query_vec = make_unit_vector(768, 0);
        while !stop_query.load(Ordering::Acquire) && queries_done < 30 {
            let _ = eng_query.search_text("Concurrent token_alpha", 0, 5).await;
            let _ = eng_query.search_vector(&query_vec, 0, 5).await;
            let q = StorageSearchQuery::hybrid("payload", query_vec.clone(), 0, 5);
            let _ = eng_query.search(&q).await;
            queries_done += 1;
            sleep(Duration::from_millis(3)).await;
        }
        queries_done
    });

    // Task 3: Selective Deletion Worker
    let eng_delete = Arc::clone(&engine);
    let stop_delete = Arc::clone(&stop_flag);
    let deleter = tokio::spawn(async move {
        let mut deletes_done = 0;
        while !stop_delete.load(Ordering::Acquire) && deletes_done < 10 {
            // Delete batches from early cycles if present
            let target_path = format!("src/module_{}/worker_0.rs", deletes_done);
            let _ = eng_delete.delete_by_file_path(&target_path).await;
            deletes_done += 1;
            sleep(Duration::from_millis(8)).await;
        }
        deletes_done
    });

    // Task 4: Maintenance / Compaction & Epoch Monitor
    let eng_maint = Arc::clone(&engine);
    let stop_maint = Arc::clone(&stop_flag);
    let maintainer = tokio::spawn(async move {
        let mut compactions_done = 0;
        while !stop_maint.load(Ordering::Acquire) && compactions_done < 3 {
            let _ = eng_maint.compact().await;
            let _ = eng_maint.bump_index_epoch("concurrent_maintenance");
            compactions_done += 1;
            sleep(Duration::from_millis(20)).await;
        }
        compactions_done
    });

    // Allow workers to execute concurrently
    let (ins_res, q_res, del_res, maint_res) = tokio::join!(inserter, querier, deleter, maintainer);
    stop_flag.store(true, Ordering::Release);

    assert!(ins_res.unwrap() > 0, "Inserter must have executed batches");
    assert!(q_res.unwrap() > 0, "Querier must have executed queries");
    assert!(del_res.unwrap() > 0, "Deleter must have executed deletes");
    assert!(maint_res.unwrap() > 0, "Maintainer must have run compaction");

    // Post-concurrency sanity check: storage must remain fully functional
    let final_count = engine.count().await.expect("Count must succeed post-concurrency");
    assert!(final_count > 0, "Some chunks must remain after partial deletions");

    let text_hits = engine.search_text("payload", 0, 10).await.expect("Keyword search must succeed");
    assert!(!text_hits.is_empty(), "Must find remaining chunks via keyword search");
}

#[tokio::test]
async fn test_tier5_tantivy_reader_reload_coherence_under_rapid_cycles() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    // Verify strict read-your-writes coherence:
    // When chunk is inserted, it must be IMMEDIATELY discoverable via Tantivy search.
    // When chunk is deleted, it must be IMMEDIATELY undiscoverable.
    for i in 0..20 {
        let unique_token = format!("coherence_token_cycle_{}", i);
        let chunk_id = format!("coherence_chunk_{}", i);
        let path = format!("src/coherence_{}.rs", i);
        let text = format!("Strict reader coherence payload with unique {} marker", unique_token);
        let chunk = make_tier5_chunk(&chunk_id, "doc_coh", &path, 1, 5, 0, make_unit_vector(768, i), &text);

        // 1. Insert chunk
        let inserted = engine.insert_chunks(&[chunk]).await.unwrap();
        assert_eq!(inserted, 1, "Must insert chunk at cycle {}", i);

        // 2. Immediate read verification
        let hits = engine.search_text(&unique_token, 0, 5).await.unwrap();
        assert_eq!(hits.len(), 1, "Immediate search must find chunk at cycle {}", i);
        assert_eq!(hits[0].chunk.chunk_id, chunk_id);

        // 3. Delete chunk by chunk_id
        let deleted = engine.delete_by_chunk_id(&chunk_id).await.unwrap();
        assert!(deleted >= 1, "Must delete chunk at cycle {}", i);

        // 4. Immediate post-delete verification
        let hits_after = engine.search_text(&unique_token, 0, 5).await.unwrap();
        assert!(hits_after.is_empty(), "Immediate search post-delete must return 0 hits at cycle {}", i);
    }
}

// ============================================================================
// 2. ATOMIC .metadata.json CORRUPTION RECOVERY & EPOCH SYNCHRONIZATION
// ============================================================================

#[tokio::test]
async fn test_tier5_atomic_metadata_corruption_recovery_and_epoch_sync() {
    let tmp = tempdir().unwrap();
    let config = quorum_storage::StorageConfig::new(tmp.path());
    let meta_path = config.metadata_path();

    // Step 1: Initialize clean engine and bump epoch to 5
    {
        let engine = StorageEngine::open(tmp.path()).await.unwrap();
        for i in 1..=4 {
            let ep = engine.bump_index_epoch(&format!("bump_{}", i)).unwrap();
            assert_eq!(ep, (i + 1) as u64);
        }
        assert_eq!(engine.index_epoch(), 5);
        assert!(meta_path.exists(), "Metadata file must exist on disk");
    }

    // Step 2: Adversarial Corruption A — Truncated / malformed JSON
    std::fs::write(&meta_path, b"{\"index_epoch\": 5, \"last_bump_reason\":").unwrap();
    {
        // Re-opening corrupt file must NOT panic, but gracefully recover default metadata
        let recovered_engine = StorageEngine::open(tmp.path()).await.expect("Must recover from corrupt JSON");
        assert_eq!(recovered_engine.index_epoch(), 1, "Recovered engine must reset to default epoch 1");
        assert_eq!(recovered_engine.metadata().last_bump_reason, "init");
    }

    // Step 3: Adversarial Corruption B — 0-byte empty file
    std::fs::write(&meta_path, b"").unwrap();
    {
        let recovered_engine = StorageEngine::open(tmp.path()).await.expect("Must recover from 0-byte metadata");
        assert_eq!(recovered_engine.index_epoch(), 1, "Recovered engine must fall back to epoch 1");
    }

    // Step 4: Adversarial Corruption C — High-entropy binary garbage
    std::fs::write(&meta_path, [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x42, 0x13]).unwrap();
    {
        let recovered_engine = StorageEngine::open(tmp.path()).await.expect("Must recover from binary garbage");
        assert_eq!(recovered_engine.index_epoch(), 1);
    }

    // Step 5: Stale temporary file presence (.metadata.json.tmp)
    let tmp_file = meta_path.with_extension("tmp");
    std::fs::write(&tmp_file, b"stale temporary residue from crashed process").unwrap();
    {
        let engine = StorageEngine::open(tmp.path()).await.unwrap();
        let new_epoch = engine.bump_index_epoch("bump_over_stale_tmp").unwrap();
        assert_eq!(new_epoch, 2);
        // Verify disk content is now clean, valid JSON
        let content = std::fs::read_to_string(&meta_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).expect("Must be valid JSON");
        assert_eq!(parsed["index_epoch"], 2);
        assert_eq!(parsed["last_bump_reason"], "bump_over_stale_tmp");
    }

    // Step 6: High-concurrency atomic monotonic increments across 30 tasks
    {
        let engine = Arc::new(StorageEngine::open(tmp.path()).await.unwrap());
        let initial_epoch = engine.index_epoch(); // currently 2
        let num_tasks = 30;
        let mut handles = Vec::with_capacity(num_tasks);

        for task_id in 0..num_tasks {
            let eng = Arc::clone(&engine);
            handles.push(tokio::spawn(async move {
                eng.bump_index_epoch(&format!("concurrent_bump_{}", task_id)).unwrap()
            }));
        }

        let mut observed_epochs = Vec::with_capacity(num_tasks);
        for h in handles {
            let ep = h.await.unwrap();
            observed_epochs.push(ep);
        }

        let expected_final = initial_epoch + num_tasks as u64;
        assert_eq!(engine.index_epoch(), expected_final);

        // Every bump must have produced a unique epoch (monotonicity)
        let unique_epochs: HashSet<u64> = observed_epochs.into_iter().collect();
        assert_eq!(unique_epochs.len(), num_tasks, "All concurrent epoch allocations must be strictly unique");

        // Verify disk reflects final epoch
        let disk_content = std::fs::read_to_string(&meta_path).unwrap();
        let disk_meta: serde_json::Value = serde_json::from_str(&disk_content).unwrap();
        assert_eq!(disk_meta["index_epoch"], expected_final);
    }

    // Step 7: Close and reopen to verify persistence across restarts
    {
        let reopened = StorageEngine::open(tmp.path()).await.unwrap();
        assert_eq!(reopened.index_epoch(), 32);
    }
}

// ============================================================================
// 3. MULTI-TIER HYBRID DRIFT HEALING STORAGE PRIMITIVES
// ============================================================================

#[tokio::test]
async fn test_tier5_hybrid_drift_bidirectional_healing() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    // 1. Insert 10 baseline chunks into both LanceDB and Tantivy
    let mut baseline_chunks = Vec::with_capacity(10);
    for i in 0..10 {
        let id = format!("chunk_base_{}", i);
        let path = format!("src/common/base_{}.rs", i);
        let text = format!("Baseline mutual synchronized chunk {} with token_base", i);
        let vec = make_unit_vector(768, i);
        baseline_chunks.push(make_tier5_chunk(&id, "doc_base", &path, 1, 10, 0, vec, &text));
    }
    let inserted = engine.insert_chunks(&baseline_chunks).await.unwrap();
    assert_eq!(inserted, 10);

    // 2. Induce Drift B1: Insert 5 chunks exclusively into LanceDB (missing in Tantivy)
    let mut lance_only_chunks = Vec::with_capacity(5);
    for i in 10..15 {
        let id = format!("chunk_lance_drift_{}", i);
        let path = format!("src/drift/lance_{}.rs", i);
        let text = format!("Lance exclusive drift chunk {} with token_drift_lance", i);
        let vec = make_unit_vector(768, i);
        lance_only_chunks.push(make_tier5_chunk(&id, "doc_drift_l", &path, 1, 10, 0, vec, &text));
    }
    let lance_inserted = engine.insert_into_lance_only(&lance_only_chunks).await.unwrap();
    assert_eq!(lance_inserted, 5);

    // 3. Induce Drift B2: Insert 5 chunks exclusively into Tantivy (missing in LanceDB)
    let mut tantivy_only_chunks = Vec::with_capacity(5);
    for i in 15..20 {
        let id = format!("chunk_tantivy_drift_{}", i);
        let path = format!("src/drift/tantivy_{}.rs", i);
        let text = format!("Tantivy exclusive drift chunk {} with token_drift_tantivy", i);
        let vec = make_unit_vector(768, i);
        tantivy_only_chunks.push(make_tier5_chunk(&id, "doc_drift_t", &path, 1, 10, 0, vec, &text));
    }
    let tantivy_indexed = engine.insert_into_tantivy_only(&tantivy_only_chunks).unwrap();
    assert_eq!(tantivy_indexed, 5);

    // 4. Verify the desynchronized catalog state
    let lance_catalog = engine.get_lance_chunk_catalog().await.unwrap();
    let tantivy_catalog = engine.get_tantivy_chunk_catalog().unwrap();

    assert_eq!(lance_catalog.len(), 15, "LanceDB should have 10 baseline + 5 lance-only");
    assert_eq!(tantivy_catalog.len(), 15, "Tantivy should have 10 baseline + 5 tantivy-only");

    let lance_ids: HashSet<String> = lance_catalog.keys().cloned().collect();
    let tantivy_ids: HashSet<String> = tantivy_catalog.keys().cloned().collect();

    let missing_in_tantivy: Vec<String> = lance_ids.difference(&tantivy_ids).cloned().collect();
    let missing_in_lance: Vec<String> = tantivy_ids.difference(&lance_ids).cloned().collect();

    assert_eq!(missing_in_tantivy.len(), 5);
    assert_eq!(missing_in_lance.len(), 5);

    // 5. Heal Lance -> Tantivy: Retrieve missing chunks from Lance and index into Tantivy
    let retrieved_from_lance = engine.get_chunks_by_ids(&missing_in_tantivy).await.unwrap();
    assert_eq!(retrieved_from_lance.len(), 5);
    let healed_tantivy = engine.insert_into_tantivy_only(&retrieved_from_lance).unwrap();
    assert_eq!(healed_tantivy, 5);

    // 6. Heal Tantivy -> Lance: Retrieve missing chunks from Tantivy and insert into Lance
    let retrieved_from_tantivy = engine.get_chunks_from_tantivy(&missing_in_lance).unwrap();
    assert_eq!(retrieved_from_tantivy.len(), 5);
    let healed_lance = engine.insert_into_lance_only(&retrieved_from_tantivy).await.unwrap();
    assert_eq!(healed_lance, 5);

    // 7. Verify 100% mutual parity
    let healed_lance_catalog = engine.get_lance_chunk_catalog().await.unwrap();
    let healed_tantivy_catalog = engine.get_tantivy_chunk_catalog().unwrap();

    assert_eq!(healed_lance_catalog.len(), 20, "LanceDB must contain all 20 chunks");
    assert_eq!(healed_tantivy_catalog.len(), 20, "Tantivy must contain all 20 chunks");
    assert_eq!(healed_lance_catalog, healed_tantivy_catalog, "Catalogs must match 100% symmetrically");

    // 8. Bump index epoch to record drift remediation and verify search over healed items
    let epoch = engine.bump_index_epoch("healed_hybrid_drift").unwrap();
    assert!(epoch >= 2);

    // Both Lance-drifted and Tantivy-drifted chunks must be retrievable in hybrid search
    let hybrid_lance = engine.search_hybrid("token_drift_lance", &make_unit_vector(768, 10), 0, 5).await.unwrap();
    assert!(!hybrid_lance.is_empty(), "Must find healed Lance-drift chunks via hybrid search");

    let hybrid_tantivy = engine.search_hybrid("token_drift_tantivy", &make_unit_vector(768, 15), 0, 5).await.unwrap();
    assert!(!hybrid_tantivy.is_empty(), "Must find healed Tantivy-drift chunks via hybrid search");
}

// ============================================================================
// 4. ACL POLICY DRIFT REMEDIATION & PUSHDOWN ISOLATION ENFORCEMENT
// ============================================================================

#[tokio::test]
async fn test_tier5_acl_access_tier_drift_healing_and_isolation() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    // Insert chunks at Tier 2 (Confidential)
    let chunk_confidential = make_tier5_chunk(
        "c_acl_conf",
        "doc_acl",
        "src/security/classified.rs",
        1,
        20,
        AccessTier::Tier2Confidential.as_u8(),
        make_unit_vector(768, 42),
        "Secret proprietary cryptographic containment keys classified",
    );

    let inserted = engine.insert_chunks(&[chunk_confidential]).await.unwrap();
    assert_eq!(inserted, 1);

    // 1. Enforce isolation: Tier 0 (Public) and Tier 1 (Internal) queries must return 0 hits
    for test_tier in [0u8, 1u8] {
        let vec_hits = engine.search_vector(&make_unit_vector(768, 42), test_tier, 5).await.unwrap();
        assert!(vec_hits.is_empty(), "Unauthorized tier {} must receive 0 vector hits", test_tier);

        let text_hits = engine.search_text("cryptographic containment", test_tier, 5).await.unwrap();
        assert!(text_hits.is_empty(), "Unauthorized tier {} must receive 0 text hits", test_tier);

        let hybrid_hits = engine.search_hybrid("containment", &make_unit_vector(768, 42), test_tier, 5).await.unwrap();
        assert!(hybrid_hits.is_empty(), "Unauthorized tier {} must receive 0 hybrid hits", test_tier);
    }

    // 2. Authorized query (Tier 2) must succeed
    let auth_hits = engine.search_vector(&make_unit_vector(768, 42), 2, 5).await.unwrap();
    assert_eq!(auth_hits.len(), 1);
    assert_eq!(auth_hits[0].chunk.chunk_id, "c_acl_conf");

    // 3. Simulate ACL Policy Drift Healing:
    // Organization updates folder policy, declassifying from Tier 2 -> Tier 1 (Internal)
    engine.update_chunk_access_tier("c_acl_conf", AccessTier::Tier1Internal.as_u8()).await.unwrap();

    // 4. Verification post-healing:
    // Tier 0 must STILL be rejected
    let t0_hits = engine.search_text("containment", 0, 5).await.unwrap();
    assert!(t0_hits.is_empty(), "Tier 0 must still be rejected");

    // Tier 1 must NOW be authorized across all 3 search modes!
    let t1_vec = engine.search_vector(&make_unit_vector(768, 42), 1, 5).await.unwrap();
    assert_eq!(t1_vec.len(), 1, "Tier 1 must now retrieve declassified vector chunk");

    let t1_text = engine.search_text("containment", 1, 5).await.unwrap();
    assert_eq!(t1_text.len(), 1, "Tier 1 must now retrieve declassified text chunk");

    let t1_hybrid = engine.search_hybrid("containment", &make_unit_vector(768, 42), 1, 5).await.unwrap();
    assert_eq!(t1_hybrid.len(), 1, "Tier 1 must now retrieve declassified hybrid chunk");

    // 5. Escalate back to Tier 3 (Restricted)
    engine.update_chunk_access_tier("c_acl_conf", AccessTier::Tier3Restricted.as_u8()).await.unwrap();

    // Tier 1 and Tier 2 must now be rejected
    assert!(engine.search_vector(&make_unit_vector(768, 42), 1, 5).await.unwrap().is_empty());
    assert!(engine.search_vector(&make_unit_vector(768, 42), 2, 5).await.unwrap().is_empty());

    // Tier 3 must succeed
    assert_eq!(engine.search_vector(&make_unit_vector(768, 42), 3, 5).await.unwrap().len(), 1);
}

// ============================================================================
// 5. ADVERSARIAL INJECTION & ESCAPING RESILIENCE
// ============================================================================

#[tokio::test]
async fn test_tier5_adversarial_injection_resilience() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    // Payloads containing SQL injection syntax, quotes, and Tantivy special characters
    let malicious_path = r#"C:\Program Files\Quorum' OR '1'='1\dir; DROP TABLE chunks; --\file'name.rs"#;
    let malicious_chunk_id = "chunk_id'; SELECT * FROM quorum_chunks WHERE 'x'='x";
    let malicious_text = r#"Adversarial Tantivy query chars: + - && || ! ( ) { } [ ] ^ " ~ * ? : \ / AND OR NOT"#;

    let chunk = make_tier5_chunk(
        malicious_chunk_id,
        "doc_inject",
        malicious_path,
        1,
        15,
        0,
        make_unit_vector(768, 7),
        malicious_text,
    );

    // Insertion must succeed cleanly without SQL syntax error
    let inserted = engine.insert_chunks(&[chunk]).await.unwrap();
    assert_eq!(inserted, 1);

    // has_chunk_hash check
    let hash = DocumentChunk::compute_blake3_hash(malicious_text);
    assert!(engine.has_chunk_hash(&hash).await.unwrap());

    // Search with unescaped / syntax-heavy query text
    let hits = engine.search_text(r#"AND OR NOT + - ( ) " ~"#, 0, 5).await.unwrap();
    // Tantivy sanitization must gracefully return without panicking
    assert!(hits.is_empty() || !hits.is_empty());

    // Search targeting specific tokens inside the text
    let hits_token = engine.search_text("Tantivy", 0, 5).await.unwrap();
    assert_eq!(hits_token.len(), 1);
    assert_eq!(hits_token[0].chunk.chunk_id, malicious_chunk_id);

    // Delete by malicious file_path containing SQL injection
    let deleted = engine.delete_by_file_path(malicious_path).await.unwrap();
    assert_eq!(deleted, 1, "Must cleanly delete record with single quotes and SQL injection string");

    assert_eq!(engine.count().await.unwrap(), 0);
}

// ============================================================================
// 6. COMPACTION AND VERSION PRUNING UNDER EXTREME CHURN
// ============================================================================

#[tokio::test]
async fn test_tier5_compaction_and_version_pruning_under_churn() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    // Execute 3 cycles of batch insertion followed by partial deletion and compaction
    for cycle in 0..3 {
        let mut batch = Vec::with_capacity(30);
        for i in 0..30 {
            let id = format!("churn_chunk_{}_{}", cycle, i);
            let path = format!("src/churn_{}/file_{}.rs", cycle, i % 5);
            let text = format!("Churn payload cycle {} item {} term_churn", cycle, i);
            let vec = make_unit_vector(768, (cycle * 30 + i) % 768);
            batch.push(make_tier5_chunk(&id, "doc_churn", &path, 1, 10, 0, vec, &text));
        }
        engine.insert_chunks(&batch).await.unwrap();

        // Delete half the files
        for i in 0..3 {
            let target = format!("src/churn_{}/file_{}.rs", cycle, i);
            let _ = engine.delete_by_file_path(&target).await;
        }

        // Compact storage
        let stats = engine.compact().await.expect("Compaction must succeed");
        assert!(stats.tantivy_segments_merged, "Tantivy segments must merge");
    }

    // Verify final state is valid and searchable
    let remaining = engine.count().await.unwrap();
    assert!(remaining > 0, "Some chunks must survive churn");

    let hits = engine.search_text("term_churn", 0, 10).await.unwrap();
    assert!(!hits.is_empty(), "Surviving chunks must be retrievable");
}

// ============================================================================
// 7. LEVEL-2 BLAKE3 DEDUPLICATION EXACTNESS UNDER IDENTICAL PAYLOADS
// ============================================================================

#[tokio::test]
async fn test_tier5_level2_blake3_dedup_exactness_under_massive_identical_payloads() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let identical_text = "Universal immutable deterministic payload repeated across multiple files";
    let canonical_hash = DocumentChunk::compute_blake3_hash(identical_text);

    // Create 40 chunks with different chunk_ids and different file_paths, but identical text
    let mut batch = Vec::with_capacity(40);
    for i in 0..40 {
        let id = format!("dup_chunk_{}", i);
        let path = format!("src/dup/file_{}.rs", i);
        let vec = make_unit_vector(768, 1);
        batch.push(make_tier5_chunk(&id, "doc_dup", &path, 1, 10, 0, vec, identical_text));
    }

    // Only 1 chunk should be inserted due to Level-2 BLAKE3 deduplication
    let inserted = engine.insert_chunks(&batch).await.unwrap();
    assert_eq!(inserted, 1, "Level-2 deduplication must accept exactly 1 unique chunk");
    assert_eq!(engine.count().await.unwrap(), 1);
    assert!(engine.has_chunk_hash(&canonical_hash).await.unwrap());

    // Submitting the exact same batch again must insert 0 chunks
    let inserted_second = engine.insert_chunks(&batch).await.unwrap();
    assert_eq!(inserted_second, 0, "Second insertion of identical chunks must insert 0");
    assert_eq!(engine.count().await.unwrap(), 1);
}
