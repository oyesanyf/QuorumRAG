//! Adversarial Stress Test Suite for QuorumRAG Reindex Engine and 5-Drift Remediation Engine.
//!
//! EMPIRICAL CHALLENGER M3-2:
//! 1. Reindex Worker Stress:
//!    - Incremental mode fast-path skips and Level-2 chunk cache reuse.
//!    - Rename / move detection on disk (0 neural re-embeddings).
//!    - Full rebuild mode (`full_rebuild: true`) with index compaction.
//!    - Forced re-embedding (`force_reembed: true`) bypassing Level-2 cache.
//!    - Concurrent task collision rejection (`TaskAlreadyRunning`).
//!    - Cooperative cancellation token responsiveness.
//!    - Dry run mode (zero storage mutations).
//!
//! 2. 5-Drift Healer Stress:
//!    - Drift A: Merkle State Drift (deleted disk file -> purged from DB; modified file -> reindexed; untracked file -> added).
//!    - Drift B: Hybrid Index Desync (LanceDB <-> Tantivy bidirectional desync with dimension healing).
//!    - Drift C: Vector Contract Drift (re-embedding drifted vector lengths, unnormalized L2 norms, outdated contract hashes).
//!    - Drift D: ACL Policy Drift (atomic access_tier updates matching directory prefix hierarchy).
//!    - Drift E: Storage Compaction & Tombstone Drift (fragment consolidation and old version pruning).
//!    - Dry run mode verification (zero mutations when dry_run: true).

use std::fs::{create_dir_all, rename};
use std::sync::Arc;
use tempfile::tempdir;

use quorum_classifier::FileTypeClassifier;
use quorum_contract::{EmbeddingContract, EmbeddingGenerator};
use quorum_storage::{StorageConfig, StorageEngine, StorageSearchQuery};
use quorum_types::DocumentChunk;

use quorum_ingest::config::{DriftFixOptions, DriftType, IngestConfig, ReindexOptions};
use quorum_ingest::dedup::TwoLevelDedupEngine;
use quorum_ingest::drift_healer::DriftHealer;
use quorum_ingest::engine::IngestEngine;
use quorum_ingest::error::IngestError;
use quorum_ingest::reindex::{ReindexPhase, ReindexWorker};

/// Deterministic mock embedding generator for tests (canonical 768-dim L2-normalized vectors).
#[derive(Debug, Clone)]
struct TestEmbeddingGenerator {
    contract: EmbeddingContract,
}

impl Default for TestEmbeddingGenerator {
    fn default() -> Self {
        Self {
            contract: EmbeddingContract::canonical_gemma_300m(),
        }
    }
}

impl EmbeddingGenerator for TestEmbeddingGenerator {
    fn contract(&self) -> &EmbeddingContract {
        &self.contract
    }

    fn embed_text(&self, text: &str) -> Result<Vec<f32>, quorum_contract::ContractError> {
        let dim = self.contract.dimension;
        let mut vec = Vec::with_capacity(dim);
        let mut hasher = blake3::Hasher::new();
        hasher.update(text.as_bytes());

        for i in 0..dim {
            let mut step_hasher = hasher.clone();
            step_hasher.update(&(i as u32).to_le_bytes());
            let hash = step_hasher.finalize();
            let raw_int = u32::from_le_bytes([
                hash.as_bytes()[0],
                hash.as_bytes()[1],
                hash.as_bytes()[2],
                hash.as_bytes()[3],
            ]);
            let float_val = (raw_int as f32 / u32::MAX as f32) * 2.0 - 1.0;
            vec.push(float_val);
        }

        // L2 normalize
        let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for v in &mut vec {
                *v /= norm;
            }
        }
        Ok(vec)
    }

    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, quorum_contract::ContractError> {
        texts.iter().map(|t| self.embed_text(t)).collect()
    }
}

// ============================================================================
// PART 1: REINDEX WORKER EMPIRICAL STRESS TESTS
// ============================================================================

#[tokio::test]
async fn test_adversarial_reindex_incremental_skip_and_cache_reuse() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // 1. Setup multi-chunk document: 3 paragraphs of 600 chars each (target chunk size = 500)
    let p1 = "A".repeat(600);
    let p2 = "B".repeat(600);
    let p3 = "C".repeat(600);

    let doc_path = root.join("large_document.txt");
    std::fs::write(&doc_path, format!("{}\n{}\n{}", p1, p2, p3)).unwrap();

    let storage_dir = root.join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        ..Default::default()
    };

    let worker = ReindexWorker::new(
        config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    );

    // Initial incremental run: brand new document
    let prog1 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(prog1.phase, ReindexPhase::Completed);
    assert_eq!(prog1.files_indexed, 1);
    assert_eq!(prog1.files_skipped_unmodified, 0);
    assert!(prog1.chunks_newly_embedded >= 3, "Expected at least 3 initial chunks");
    let initial_embedded = prog1.chunks_newly_embedded;

    // Second incremental run: document is completely untouched
    let prog2 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(prog2.phase, ReindexPhase::Completed);
    assert_eq!(prog2.files_indexed, 0);
    assert_eq!(prog2.files_skipped_unmodified, 1, "Unmodified file must be skipped via Level-1 fast path");
    assert_eq!(prog2.chunks_newly_embedded, 0);
    assert_eq!(prog2.chunks_reused_from_cache, 0);

    // Third incremental run: modify only middle paragraph (p2 -> p2_edited)
    let p2_edited = "Z".repeat(700);
    std::fs::write(&doc_path, format!("{}\n{}\n{}", p1, p2_edited, p3)).unwrap();

    let prog3 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(prog3.phase, ReindexPhase::Completed);
    assert_eq!(prog3.files_indexed, 1);
    assert_eq!(prog3.files_skipped_unmodified, 0);
    assert!(
        prog3.chunks_reused_from_cache >= 1,
        "Level-2 cache must reuse unchanged chunks (reused={})",
        prog3.chunks_reused_from_cache
    );
    assert!(
        prog3.chunks_newly_embedded < initial_embedded,
        "Single paragraph edit must embed strictly fewer chunks than initial ingest (embedded={}, initial={})",
        prog3.chunks_newly_embedded,
        initial_embedded
    );
}

#[tokio::test]
async fn test_adversarial_reindex_rename_and_move_detection() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let old_path = root.join("original_manifest.md");
    let content = "# Secret Project\nDecentralized peer to peer retrieval architecture.";
    std::fs::write(&old_path, content).unwrap();

    let storage_dir = root.join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        ..Default::default()
    };

    let worker = ReindexWorker::new(
        config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    );

    // Initial reindex
    let prog1 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(prog1.files_indexed, 1);
    assert!(prog1.chunks_newly_embedded >= 1);

    // Simulate moving/renaming file on disk
    let new_path = root.join("moved_manifest.md");
    rename(&old_path, &new_path).unwrap();

    // Incremental reindex after rename
    let prog2 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(prog2.files_indexed, 1);
    assert_eq!(
        prog2.chunks_newly_embedded, 0,
        "Moved file must perform ZERO new embedding calculations"
    );

    // Verify catalog entry now records the new path
    let entry = dedup.get_file_entry(&new_path);
    assert!(entry.is_some(), "New path must be registered in Level-1 catalog");
    assert_eq!(entry.unwrap().file_path, new_path);
}

#[tokio::test]
async fn test_adversarial_reindex_force_reembed_and_full_rebuild() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let doc_path = root.join("contract_doc.txt");
    std::fs::write(&doc_path, "Deterministic vector space contract data.").unwrap();

    let storage_dir = root.join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        ..Default::default()
    };

    let worker = ReindexWorker::new(
        config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    );

    // Initial reindex
    let _ = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();

    // Run with force_reembed = true and full_rebuild = true
    let full_opts = ReindexOptions {
        full_rebuild: true,
        force_reembed: true,
        ..Default::default()
    };

    let prog_full = worker.run_reindex_sync(full_opts).await.unwrap();
    assert_eq!(prog_full.phase, ReindexPhase::Completed);
    assert_eq!(prog_full.files_skipped_unmodified, 0, "Full rebuild must not skip any files");
    assert_eq!(
        prog_full.chunks_reused_from_cache, 0,
        "force_reembed must bypass chunk cache completely"
    );
    assert!(prog_full.chunks_newly_embedded >= 1);
}

#[tokio::test]
async fn test_adversarial_reindex_dry_run_leaves_storage_untouched() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let doc_path = root.join("ghost_file.txt");
    std::fs::write(&doc_path, "Ghost content that should never be written to storage.").unwrap();

    let storage_dir = root.join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        ..Default::default()
    };

    let worker = ReindexWorker::new(
        config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    );

    let dry_opts = ReindexOptions {
        dry_run: true,
        ..Default::default()
    };

    let prog = worker.run_reindex_sync(dry_opts).await.unwrap();
    assert_eq!(prog.phase, ReindexPhase::Completed);
    assert_eq!(prog.files_indexed, 1);

    // Verify storage remains 100% empty
    let all_chunks = storage.scan_all_chunks().await.unwrap();
    assert!(all_chunks.is_empty(), "Dry run must not write any chunks to storage!");
}

#[tokio::test]
async fn test_adversarial_reindex_cancellation_responsiveness() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // Create 20 files
    for i in 0..20 {
        let p = root.join(format!("file_{}.txt", i));
        std::fs::write(&p, format!("Content for file number {}", i)).unwrap();
    }

    let storage_dir = root.join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        ..Default::default()
    };

    let worker = ReindexWorker::new(
        config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    );

    // Start async task
    let task_id = worker.start_reindex(ReindexOptions::default()).await.unwrap();
    assert!(!task_id.is_nil());

    // Immediately attempt concurrent start -> should fail closed
    let collision = worker.start_reindex(ReindexOptions::default()).await;
    assert!(
        matches!(collision, Err(IngestError::TaskAlreadyRunning(_))),
        "Concurrent reindex task launch must fail closed with TaskAlreadyRunning"
    );

    // Cooperative cancellation
    let cancelled = worker.cancel_reindex();
    assert!(cancelled);

    // Allow background task loop to process cancellation
    tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

    let progress = worker.get_progress().await.unwrap();
    assert!(
        matches!(progress.phase, ReindexPhase::Cancelled | ReindexPhase::Completed),
        "Worker must cleanly transition to Cancelled or Completed"
    );
}

// ============================================================================
// PART 2: 5-DRIFT REMEDIATION EMPIRICAL STRESS TESTS
// ============================================================================

#[tokio::test]
async fn test_adversarial_drift_a_merkle_state_drift_stress() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let storage_dir = root.join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        ..Default::default()
    };

    let engine = IngestEngine::new(
        config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
    )
    .unwrap();

    // 1. Ingest 3 files
    let f1 = root.join("f1_to_delete.txt");
    let f2 = root.join("f2_to_modify.txt");
    let f3 = root.join("f3_untouched.txt");

    std::fs::write(&f1, "File 1 unique EiffelTowerAlphaOmega content that will be deleted on disk.").unwrap();
    std::fs::write(&f2, "File 2 initial content that will be updated.").unwrap();
    std::fs::write(&f3, "File 3 stable content.").unwrap();

    engine.ingest_file(&f1).await.unwrap();
    engine.ingest_file(&f2).await.unwrap();
    engine.ingest_file(&f3).await.unwrap();

    // Simulate disk modifications while daemon/watcher was OFFLINE:
    // (a) Delete f1 from disk
    std::fs::remove_file(&f1).unwrap();

    // (b) Modify f2 on disk
    std::fs::write(&f2, "File 2 heavily revised content after offline edit.").unwrap();

    // (c) Add f4 to disk without registering in catalog
    let f4 = root.join("f4_added_offline.txt");
    std::fs::write(&f4, "File 4 brand new file created offline.").unwrap();

    let healer = DriftHealer::new(
        config,
        Arc::clone(&storage),
        classifier,
        embedder,
        Arc::clone(engine.dedup()),
    );

    // Run DriftType::MerkleState fix
    let report = healer
        .fix_all_drifts(DriftFixOptions {
            target_drifts: vec![DriftType::MerkleState],
            ..Default::default()
        })
        .await
        .unwrap();

    assert!(report.is_healed);
    assert_eq!(report.orphaned_db_files_purged, 1, "Must purge 1 deleted file");
    assert_eq!(report.outdated_files_reindexed, 1, "Must reindex 1 modified file");
    assert_eq!(report.missing_fs_files_indexed, 1, "Must index 1 new offline file");

    // Verify search: f1 unique content should NOT be found; f4 SHOULD be found
    let query_f1 = StorageSearchQuery::keyword("EiffelTowerAlphaOmega", 0, 5);
    let hits_f1 = storage.search(&query_f1).await.unwrap();
    assert!(hits_f1.is_empty(), "Purged file unique content must no longer appear in search");

    // Verify scan_all_chunks has 0 chunks belonging to f1
    let all_chunks = storage.scan_all_chunks().await.unwrap();
    let f1_path_str = f1.to_string_lossy().to_string();
    assert!(!all_chunks.iter().any(|c| c.file_path == f1_path_str), "No chunks belonging to purged file f1 should remain in storage");

    let query_f4 = StorageSearchQuery::keyword("brand new file", 0, 5);
    let hits_f4 = storage.search(&query_f4).await.unwrap();
    assert!(!hits_f4.is_empty(), "Newly discovered offline file must be searchable");
}

#[tokio::test]
async fn test_adversarial_drift_b_hybrid_index_bidirectional_parity_and_dimension_healing() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let storage_dir = root.join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        ..Default::default()
    };

    // Subcase 1: Chunk exists in LanceDB only (missing in Tantivy)
    let lance_only_chunk = DocumentChunk::new(
        "lance_only_id",
        "doc_lance",
        "lance_path.txt",
        1,
        2,
        0,
        vec![0.1; 768],
        "Unique LanceDB text searching for Tantivy parity",
        None,
    )
    .unwrap();
    storage.insert_into_lance_only(&[lance_only_chunk]).await.unwrap();

    // Subcase 2: Chunk exists in Tantivy only with a CORRUPTED vector (512 dims instead of 768)
    let tantivy_only_corrupted = DocumentChunk {
        chunk_id: "tantivy_only_id".into(),
        document_id: "doc_tantivy".into(),
        file_path: "tantivy_path.txt".into(),
        line_start: 5,
        line_end: 6,
        blake3_hash: "tantivy_hash_123".into(),
        access_tier: 0,
        vector: vec![0.5; 512], // Corrupted dimension!
        text_content: "Tantivy only text with invalid vector dimension".into(),
        metadata_json: "{}".into(),
    };
    storage.insert_into_tantivy_only(&[tantivy_only_corrupted]).unwrap();

    let healer = DriftHealer::new(
        config,
        Arc::clone(&storage),
        classifier,
        Arc::clone(&embedder),
        dedup,
    );

    // Execute Drift B remediation
    let report = healer
        .fix_all_drifts(DriftFixOptions {
            target_drifts: vec![DriftType::HybridIndexDesync],
            ..Default::default()
        })
        .await
        .unwrap();

    assert!(report.is_healed);
    assert_eq!(report.lance_chunks_missing_in_tantivy, 1);
    assert_eq!(report.tantivy_chunks_missing_in_lance, 1);
    assert!(report.hybrid_parity_restored);

    // Verify 100% bidirectional parity
    let lance_cat = storage.get_lance_chunk_catalog().await.unwrap();
    let tantivy_cat = storage.get_tantivy_chunk_catalog().unwrap();

    assert_eq!(lance_cat.len(), 2);
    assert_eq!(tantivy_cat.len(), 2);
    assert!(lance_cat.contains_key("lance_only_id"));
    assert!(lance_cat.contains_key("tantivy_only_id"));
    assert!(tantivy_cat.contains_key("lance_only_id"));
    assert!(tantivy_cat.contains_key("tantivy_only_id"));

    // Verify that tantivy_only_id was dimension-healed to 768 when inserted into LanceDB!
    let chunks = storage.get_chunks_by_ids(&["tantivy_only_id".into()]).await.unwrap();
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].vector.len(), 768, "Tantivy chunk must be healed to canonical 768 dimension");
}

#[tokio::test]
async fn test_adversarial_drift_c_vector_contract_and_l2_norm_healing() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let storage_dir = root.join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        ..Default::default()
    };

    let canonical_hash = embedder.contract().derive_contract_hash_hex();

    // Insert 2 drifted chunks:
    // Chunk 1: Non-unit L2 norm (vector elements 0.01 -> norm ~ 0.277 != 1.0)
    let chunk_norm_drift = DocumentChunk {
        chunk_id: "norm_drift_chunk".into(),
        document_id: "doc1".into(),
        file_path: "p1.txt".into(),
        line_start: 1,
        line_end: 1,
        blake3_hash: "h1".into(),
        access_tier: 0,
        vector: vec![0.01; 768],
        text_content: "Chunk with unnormalized vector".into(),
        metadata_json: format!("{{\"contract_hash\": \"{}\"}}", canonical_hash),
    };

    // Chunk 2: Outdated contract hash in metadata
    let canonical_vec = embedder.embed_text("Valid text").unwrap();
    let chunk_contract_drift = DocumentChunk {
        chunk_id: "contract_drift_chunk".into(),
        document_id: "doc2".into(),
        file_path: "p2.txt".into(),
        line_start: 1,
        line_end: 1,
        blake3_hash: "h2".into(),
        access_tier: 0,
        vector: canonical_vec,
        text_content: "Chunk with legacy outdated contract hash".into(),
        metadata_json: "{\"contract_hash\": \"obsolete_legacy_hash_9999\"}".into(),
    };

    storage.insert_into_lance_only(&[chunk_norm_drift.clone(), chunk_contract_drift.clone()]).await.unwrap();
    storage.insert_into_tantivy_only(&[chunk_norm_drift, chunk_contract_drift]).unwrap();

    let healer = DriftHealer::new(
        config,
        Arc::clone(&storage),
        classifier,
        Arc::clone(&embedder),
        dedup,
    );

    // Fix Vector Contract Drift
    let report = healer
        .fix_all_drifts(DriftFixOptions {
            target_drifts: vec![DriftType::VectorContract],
            ..Default::default()
        })
        .await
        .unwrap();

    assert!(report.is_healed);
    assert_eq!(report.contract_drifted_chunks_reembedded, 2);

    // Verify all chunks in storage now satisfy canonical contract invariants
    let chunks = storage.scan_all_chunks().await.unwrap();
    for c in chunks {
        assert_eq!(c.vector.len(), 768);
        let norm: f32 = c.vector.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() <= 1e-4, "L2 norm must be healed to 1.0 (got {})", norm);
        assert!(c.metadata_json.contains(&canonical_hash), "Contract hash must match canonical");
    }
}

#[tokio::test]
async fn test_adversarial_drift_d_acl_policy_drift_and_retrieval_isolation() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let storage_dir = root.join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let pub_dir = root.join("public_docs");
    let sec_dir = root.join("secure_vault");
    create_dir_all(&pub_dir).unwrap();
    create_dir_all(&sec_dir).unwrap();

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        ..Default::default()
    };

    // Ingest chunks initially with access_tier = 0
    let pub_chunk = DocumentChunk::new(
        "pub_chunk_1",
        "pub_doc",
        pub_dir.join("public.md").to_string_lossy().to_string(),
        1,
        2,
        0,
        embedder.embed_text("Public knowledge for all").unwrap(),
        "Public knowledge for all",
        None,
    )
    .unwrap();

    let sec_chunk = DocumentChunk::new(
        "sec_chunk_1",
        "sec_doc",
        sec_dir.join("confidential.md").to_string_lossy().to_string(),
        1,
        2,
        0, // Initially tier 0 (drifted from policy!)
        embedder.embed_text("Top secret confidential payload").unwrap(),
        "Top secret confidential payload",
        None,
    )
    .unwrap();

    storage.insert_chunks(&[pub_chunk, sec_chunk]).await.unwrap();

    let healer = DriftHealer::new(
        config,
        Arc::clone(&storage),
        classifier,
        Arc::clone(&embedder),
        dedup,
    );

    // Update ACL Policy: sec_dir requires access_tier 3
    let report = healer
        .fix_all_drifts(DriftFixOptions {
            target_drifts: vec![DriftType::AclPolicy],
            access_tier_rules: vec![(sec_dir.clone(), 3)],
            ..Default::default()
        })
        .await
        .unwrap();

    assert!(report.is_healed);
    assert_eq!(report.acl_drifted_chunks_updated, 1);

    // Search with max_tier = 0: Should ONLY find public chunk
    let q_vec = embedder.embed_text("secret").unwrap();
    let hits_tier0 = storage.search_vector(&q_vec, 0, 10).await.unwrap();
    for hit in &hits_tier0 {
        assert_eq!(hit.chunk.access_tier, 0);
        assert!(!hit.chunk.file_path.contains("secure_vault"), "Tier 0 search must NOT leak Tier 3 files");
    }

    // Search with max_tier = 3: Should find secure chunk
    let hits_tier3 = storage.search_vector(&q_vec, 3, 10).await.unwrap();
    let found_secret = hits_tier3.iter().any(|h| h.chunk.file_path.contains("secure_vault"));
    assert!(found_secret, "Tier 3 search must find confidential chunk");
}

#[tokio::test]
async fn test_adversarial_drift_e_storage_compaction_and_dry_run_safety() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let storage_dir = root.join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        ..Default::default()
    };

    // Insert and delete chunks to create tombstones
    let chunk = DocumentChunk::new(
        "compact_chunk_1",
        "compact_doc",
        "compact.txt",
        1,
        1,
        0,
        embedder.embed_text("To be compacted").unwrap(),
        "To be compacted",
        None,
    )
    .unwrap();

    storage.insert_chunks(&[chunk]).await.unwrap();
    storage.delete_by_chunk_id("compact_chunk_1").await.unwrap();

    let healer = DriftHealer::new(
        config,
        Arc::clone(&storage),
        classifier,
        embedder,
        dedup,
    );

    // Test Dry Run first: zero compaction executed
    let dry_report = healer
        .fix_all_drifts(DriftFixOptions {
            target_drifts: vec![DriftType::StorageCompaction],
            dry_run: true,
            ..Default::default()
        })
        .await
        .unwrap();

    assert!(!dry_report.is_healed);
    assert_eq!(dry_report.total_anomalies_healed, 0);

    // Test Real Compaction run
    let live_report = healer
        .fix_all_drifts(DriftFixOptions {
            target_drifts: vec![DriftType::StorageCompaction],
            dry_run: false,
            ..Default::default()
        })
        .await
        .unwrap();

    assert!(live_report.is_healed);
}
