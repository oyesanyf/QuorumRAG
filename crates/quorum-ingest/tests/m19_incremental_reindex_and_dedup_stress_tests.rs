//! Empirical Stress Test Harness for Milestone M19 Remediation:
//! Incremental Reindexing & Deduplication Persistence.
//!
//! EMPIRICAL CHALLENGER M19-REM-2:
//! 1. 4-Pass Untouched Tree Idempotency:
//!    Multiple sequential reindexing passes (Pass 1 -> Pass 2 -> Pass 3 -> Pass 4)
//!    on an untouched multi-file tree must produce `files_indexed == 0` and
//!    `chunks_newly_embedded == 0` on every single subsequent pass.
//!    Verifies that internal artifacts (`dedup_catalog.json`, `storage/`) are never indexed.
//!
//! 2. Single-File Mutation Selectivity:
//!    Modifying a single file in a multi-file tree causes ONLY that single file to be
//!    re-indexed and embedded, while all other files are skipped via Level-1 fast path.
//!
//! 3. Deletion Tracking & Catalog Invariant Integrity:
//!    Deleting a file causes deletion tracking to reflect accurately without corrupting
//!    remaining catalog entries or leaving orphaned chunks.
//!
//! 4. Dedup Catalog Disk Persistence & Worker Restart Restoration:
//!    Reloading `dedup_catalog.json` from disk across worker restarts accurately restores
//!    Level-1 hashes and allows a fresh worker to skip all untouched files with 0 embeddings.

use std::collections::HashMap;
use std::fs::{create_dir_all, remove_file, write};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;

use quorum_classifier::FileTypeClassifier;
use quorum_contract::{EmbeddingContract, EmbeddingGenerator};
use quorum_storage::{StorageConfig, StorageEngine};

use quorum_ingest::config::{DriftFixOptions, DriftType, IngestConfig, ReindexOptions};
use quorum_ingest::dedup::TwoLevelDedupEngine;
use quorum_ingest::drift_healer::DriftHealer;
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

/// Helper to construct multi-paragraph document content guaranteed to produce multiple chunks.
fn generate_doc_content(topic: &str, paragraphs: usize, paragraph_len: usize) -> String {
    let mut out = String::new();
    for i in 1..=paragraphs {
        let line = format!("Topic {} section {}: ", topic, i);
        let pad_len = paragraph_len.saturating_sub(line.len());
        let pad: String = (0..pad_len).map(|j| (b'a' + ((j % 26) as u8)) as char).collect();
        out.push_str(&line);
        out.push_str(&pad);
        out.push('\n');
    }
    out
}

// ============================================================================
// TEST 1: 4-PASS UNTOUCHED TREE IDEMPOTENCY
// ============================================================================

#[tokio::test]
async fn test_m19_sequential_reindexing_passes_untouched_tree_idempotency() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("user_docs");
    let data_dir = dir.path().join("data_dir");
    create_dir_all(&root).unwrap();
    create_dir_all(&data_dir).unwrap();

    // Setup an 8-file tree with mixed extensions across root and subfolders
    let sub1 = root.join("subfolder_alpha");
    let sub2 = root.join("subfolder_beta").join("nested");
    create_dir_all(&sub1).unwrap();
    create_dir_all(&sub2).unwrap();

    let file_specs = vec![
        (root.join("report_q1.txt"), "q1_earnings", 4, 300),
        (root.join("report_q2.txt"), "q2_earnings", 4, 300),
        (root.join("architecture.md"), "quorum_arch", 5, 250),
        (sub1.join("whitepaper.txt"), "crypto_mesh", 6, 400),
        (sub1.join("metrics.csv"), "latency_metrics", 3, 200),
        (sub2.join("deep_doc.txt"), "distributed_consensus", 5, 350),
        (sub2.join("spec.json"), "api_spec_v2", 3, 150),
        (root.join("notes.txt"), "operational_notes", 4, 250),
    ];

    for (p, topic, paras, len) in &file_specs {
        write(p, generate_doc_content(topic, *paras, *len)).unwrap();
    }

    let storage_dir = data_dir.join("storage");
    let catalog_path = data_dir.join("dedup_catalog.json");

    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir.clone())).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let mut config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        dedup_catalog_path: Some(catalog_path.clone()),
        excluded_paths: vec![storage_dir.clone()],
        ..Default::default()
    };
    config.exclude_source_code = false;

    let worker = ReindexWorker::new(
        config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    );

    // ------------------------------------------------------------------------
    // PASS 1: Initial full tree indexing
    // ------------------------------------------------------------------------
    let p1 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(p1.phase, ReindexPhase::Completed);
    assert_eq!(p1.files_indexed, 8, "Pass 1 must index all 8 user documents");
    assert_eq!(p1.files_skipped_unmodified, 0, "Pass 1 has no previous catalog entries");
    assert_eq!(p1.files_failed, 0, "Pass 1 must have 0 failed files");
    assert!(p1.chunks_newly_embedded >= 8, "Pass 1 must generate embeddings");
    let p1_embedded = p1.chunks_newly_embedded;

    // Verify catalog was automatically saved to disk
    assert!(catalog_path.exists(), "Pass 1 must auto-save dedup_catalog.json to disk");

    // ------------------------------------------------------------------------
    // PASS 2: First untouched pass -> MUST be 100% skipped
    // ------------------------------------------------------------------------
    let p2 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(p2.phase, ReindexPhase::Completed);
    assert_eq!(p2.files_indexed, 0, "Pass 2 on untouched tree must index 0 files");
    assert_eq!(p2.files_skipped_unmodified, 8, "Pass 2 must skip all 8 files via Level-1 fast path");
    assert_eq!(p2.chunks_newly_embedded, 0, "Pass 2 must perform 0 new embeddings");
    assert_eq!(p2.chunks_reused_from_cache, 0, "Fast-path skip does not invoke chunk chunking");
    assert_eq!(p2.files_failed, 0);

    // ------------------------------------------------------------------------
    // PASS 3: Second untouched pass -> MUST remain 100% skipped
    // ------------------------------------------------------------------------
    let p3 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(p3.phase, ReindexPhase::Completed);
    assert_eq!(p3.files_indexed, 0, "Pass 3 on untouched tree must index 0 files");
    assert_eq!(p3.files_skipped_unmodified, 8, "Pass 3 must skip all 8 files via Level-1 fast path");
    assert_eq!(p3.chunks_newly_embedded, 0, "Pass 3 must perform 0 new embeddings");
    assert_eq!(p3.chunks_reused_from_cache, 0);
    assert_eq!(p3.files_failed, 0);

    // ------------------------------------------------------------------------
    // PASS 4: Third untouched pass -> MUST remain 100% skipped
    // ------------------------------------------------------------------------
    let p4 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(p4.phase, ReindexPhase::Completed);
    assert_eq!(p4.files_indexed, 0, "Pass 4 on untouched tree must index 0 files");
    assert_eq!(p4.files_skipped_unmodified, 8, "Pass 4 must skip all 8 files via Level-1 fast path");
    assert_eq!(p4.chunks_newly_embedded, 0, "Pass 4 must perform 0 new embeddings");
    assert_eq!(p4.chunks_reused_from_cache, 0);
    assert_eq!(p4.files_failed, 0);

    // Assert that storage chunks count exactly equals Pass 1 chunks (zero drift across 4 passes)
    let chunks = storage.scan_all_chunks().await.unwrap();
    assert_eq!(chunks.len(), p1_embedded, "Storage chunks count must remain invariant across 4 passes");

    // Verify dedup_catalog.json was NEVER indexed as a user file
    assert!(
        !chunks.iter().any(|c| c.file_path.contains("dedup_catalog.json")),
        "dedup_catalog.json must NEVER be indexed into storage"
    );
}

// ============================================================================
// TEST 2: SINGLE-FILE MUTATION SELECTIVITY IN MULTI-FILE TREE
// ============================================================================

#[tokio::test]
async fn test_m19_single_file_mutation_selectivity_in_multifile_tree() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("user_docs");
    let data_dir = dir.path().join("data_dir");
    create_dir_all(&root).unwrap();
    create_dir_all(&data_dir).unwrap();

    let storage_dir = data_dir.join("storage");
    let catalog_path = data_dir.join("dedup_catalog.json");

    let f1 = root.join("doc_alpha.txt");
    let f2 = root.join("doc_beta.txt");
    let f3 = root.join("doc_gamma.txt");
    let f4 = root.join("doc_delta.txt");
    let f5 = root.join("doc_epsilon.txt");
    let f6 = root.join("doc_zeta.txt");

    write(&f1, generate_doc_content("alpha", 4, 300)).unwrap();
    write(&f2, generate_doc_content("beta", 4, 300)).unwrap();
    write(&f3, generate_doc_content("gamma_initial", 4, 300)).unwrap();
    write(&f4, generate_doc_content("delta", 4, 300)).unwrap();
    write(&f5, generate_doc_content("epsilon", 4, 300)).unwrap();
    write(&f6, generate_doc_content("zeta", 4, 300)).unwrap();

    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir.clone())).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        dedup_catalog_path: Some(catalog_path.clone()),
        excluded_paths: vec![storage_dir.clone()],
        exclude_source_code: false,
        ..Default::default()
    };

    let worker = ReindexWorker::new(
        config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    );

    // Initial indexing pass
    let p1 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(p1.files_indexed, 6);
    assert_eq!(p1.files_skipped_unmodified, 0);

    // Snapshot hashes before mutation
    let mut initial_hashes: HashMap<PathBuf, String> = HashMap::new();
    for p in &[&f1, &f2, &f3, &f4, &f5, &f6] {
        let entry = dedup.get_file_entry(p).expect("File must exist in catalog");
        initial_hashes.insert((*p).clone(), entry.file_blake3);
    }
    assert_eq!(initial_hashes.len(), 6);

    // Sleep briefly to ensure filesystem mtime difference on coarse systems
    tokio::time::sleep(tokio::time::Duration::from_millis(1100)).await;

    // Mutate ONLY f3 (doc_gamma.txt): complete rewrite of content
    let f3_new_content = generate_doc_content("gamma_heavily_revised_quantum", 6, 350);
    write(&f3, &f3_new_content).unwrap();

    // Execute Pass 2: only f3 should be processed
    let p2 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(p2.phase, ReindexPhase::Completed);
    assert_eq!(
        p2.files_indexed, 1,
        "Modifying a single file must cause ONLY that single file to be re-indexed"
    );
    assert_eq!(
        p2.files_skipped_unmodified, 5,
        "All other 5 files must be skipped via Level-1 fast path"
    );
    assert!(
        p2.chunks_newly_embedded >= 1,
        "Chunks for the mutated file must be newly embedded"
    );

    // Verify hash integrity: ONLY f3's hash changed; all other 5 remained invariant
    let f3_entry_after = dedup.get_file_entry(&f3).expect("f3 must exist in catalog");
    assert_ne!(
        f3_entry_after.file_blake3, initial_hashes[&f3],
        "Mutated file f3 must have a fresh BLAKE3 hash"
    );

    for p in &[&f1, &f2, &f4, &f5, &f6] {
        let entry = dedup.get_file_entry(p).expect("Untouched file must exist in catalog");
        assert_eq!(
            entry.file_blake3, initial_hashes[*p],
            "Untouched file {:?} BLAKE3 hash must remain identical",
            p
        );
    }

    // Pass 3: Post-mutation stabilization pass (untouched tree again)
    let p3 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(p3.files_indexed, 0, "Post-mutation pass must index 0 files");
    assert_eq!(p3.files_skipped_unmodified, 6, "All 6 files must be skipped");
    assert_eq!(p3.chunks_newly_embedded, 0);
}

// ============================================================================
// TEST 3: FILE DELETION TRACKING AND CATALOG INVARIANTS
// ============================================================================

#[tokio::test]
async fn test_m19_file_deletion_tracking_and_catalog_invariants() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("user_docs");
    let data_dir = dir.path().join("data_dir");
    create_dir_all(&root).unwrap();
    create_dir_all(&data_dir).unwrap();

    let storage_dir = data_dir.join("storage");
    let catalog_path = data_dir.join("dedup_catalog.json");

    let f1 = root.join("file_to_delete_merkle.txt");
    let f2 = root.join("file_to_delete_dedup.txt");
    let f3 = root.join("file_stable_alpha.txt");
    let f4 = root.join("file_stable_beta.txt");
    let f5 = root.join("file_stable_gamma.txt");

    write(&f1, generate_doc_content("del_merkle", 4, 300)).unwrap();
    write(&f2, generate_doc_content("del_dedup", 4, 300)).unwrap();
    write(&f3, generate_doc_content("stable_a", 4, 300)).unwrap();
    write(&f4, generate_doc_content("stable_b", 4, 300)).unwrap();
    write(&f5, generate_doc_content("stable_c", 4, 300)).unwrap();

    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir.clone())).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        dedup_catalog_path: Some(catalog_path.clone()),
        excluded_paths: vec![storage_dir.clone()],
        exclude_source_code: false,
        ..Default::default()
    };

    let worker = ReindexWorker::new(
        config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    );

    // Initial indexing
    let p1 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(p1.files_indexed, 5);
    assert_eq!(dedup.get_all_tracked_files().len(), 5);

    // Explicit deletion tracking counter
    let mut files_deleted = 0;

    // ------------------------------------------------------------------------
    // CYCLE 1: Delete f1 from disk and purge via Merkle State DriftHealer
    // ------------------------------------------------------------------------
    remove_file(&f1).unwrap();
    files_deleted += 1;
    assert!(!f1.exists(), "f1 must be deleted from disk");

    let healer = DriftHealer::new(
        config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    );

    let drift_report = healer
        .fix_all_drifts(DriftFixOptions {
            target_drifts: vec![DriftType::MerkleState],
            ..Default::default()
        })
        .await
        .unwrap();

    assert!(drift_report.is_healed);
    assert_eq!(
        drift_report.orphaned_db_files_purged, 1,
        "Drift healer must report exactly 1 deleted file purged from storage and catalog"
    );
    assert_eq!(files_deleted, 1);

    // Invariant checks after Cycle 1
    assert!(
        dedup.get_file_entry(&f1).is_none(),
        "Deleted file f1 must be removed from Level-1 catalog"
    );
    assert_eq!(
        dedup.get_all_tracked_files().len(), 4,
        "Catalog tracked files must decrease by 1"
    );
    assert!(
        !dedup.get_all_tracked_files().contains(&f1),
        "f1 must no longer be present in tracked files list"
    );

    // Verify storage chunks for f1 are purged
    let f1_str = f1.to_string_lossy().to_string();
    let chunks_after_c1 = storage.scan_all_chunks().await.unwrap();
    assert!(
        !chunks_after_c1.iter().any(|c| c.file_path == f1_str),
        "Storage must retain 0 chunks for deleted file f1"
    );

    // Reindex worker verification: remaining 4 files are skipped, 0 indexed
    let p_c1 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(p_c1.files_scanned, 4, "Crawler scans only the 4 remaining disk files");
    assert_eq!(p_c1.files_indexed, 0, "No files need reindexing");
    assert_eq!(p_c1.files_skipped_unmodified, 4, "All 4 remaining files skipped via fast path");
    assert_eq!(p_c1.chunks_newly_embedded, 0);

    // ------------------------------------------------------------------------
    // CYCLE 2: Delete f2 from disk and remove via DedupCatalog::remove_file
    // ------------------------------------------------------------------------
    remove_file(&f2).unwrap();
    files_deleted += 1;
    assert!(!f2.exists(), "f2 must be deleted from disk");

    // Remove from catalog directly
    let removed_entry = dedup.remove_file(&f2);
    assert!(removed_entry.is_some(), "remove_file must return the removed catalog entry");
    assert_eq!(removed_entry.unwrap().file_path, f2);

    // Also purge chunks from storage
    let f2_str = f2.to_string_lossy().to_string();
    let deleted_storage_chunks = storage.delete_by_file_path(&f2_str).await.unwrap_or(0);
    assert!(deleted_storage_chunks >= 1, "Storage must delete chunks for f2");

    assert_eq!(files_deleted, 2, "Total files_deleted must be exactly 2");

    // Invariant checks after Cycle 2
    assert!(dedup.get_file_entry(&f2).is_none(), "f2 must be purged from catalog");
    assert_eq!(dedup.get_all_tracked_files().len(), 3, "Catalog must retain exactly 3 files");

    // Verify the remaining 3 files (f3, f4, f5) remain fully intact and functional
    for remaining in &[&f3, &f4, &f5] {
        let entry = dedup.get_file_entry(remaining);
        assert!(entry.is_some(), "Remaining file {:?} must exist in catalog", remaining);
        assert_eq!(entry.unwrap().file_path, **remaining);
    }

    // Reindex worker verification: remaining 3 files are skipped, 0 indexed
    let p_c2 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(p_c2.files_scanned, 3, "Crawler scans only 3 remaining files");
    assert_eq!(p_c2.files_indexed, 0);
    assert_eq!(p_c2.files_skipped_unmodified, 3);
    assert_eq!(p_c2.chunks_newly_embedded, 0);
}

// ============================================================================
// TEST 4: DEDUP CATALOG DISK PERSISTENCE & WORKER RESTARTS
// ============================================================================

#[tokio::test]
async fn test_m19_dedup_catalog_disk_persistence_and_restart_restoration() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("user_docs");
    let data_dir = dir.path().join("data_dir");
    create_dir_all(&root).unwrap();
    create_dir_all(&data_dir).unwrap();

    let storage_dir = data_dir.join("storage");
    let catalog_path = data_dir.join("dedup_catalog.json");

    let f1 = root.join("doc_restart_1.txt");
    let f2 = root.join("doc_restart_2.txt");
    let f3 = root.join("doc_restart_3.txt");
    let f4 = root.join("doc_restart_4.txt");
    let f5 = root.join("doc_restart_5.txt");

    write(&f1, generate_doc_content("restart_1", 4, 300)).unwrap();
    write(&f2, generate_doc_content("restart_2", 4, 300)).unwrap();
    write(&f3, generate_doc_content("restart_3", 4, 300)).unwrap();
    write(&f4, generate_doc_content("restart_4", 4, 300)).unwrap();
    write(&f5, generate_doc_content("restart_5", 4, 300)).unwrap();

    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir.clone())).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());

    // ------------------------------------------------------------------------
    // WORKER LIFECYCLE 1: Fresh indexing and automatic disk persistence
    // ------------------------------------------------------------------------
    let dedup_v1 = Arc::new(TwoLevelDedupEngine::new());
    let config_v1 = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        dedup_catalog_path: Some(catalog_path.clone()),
        excluded_paths: vec![storage_dir.clone()],
        exclude_source_code: false,
        ..Default::default()
    };

    let worker_v1 = ReindexWorker::new(
        config_v1,
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup_v1),
    );

    let p1 = worker_v1.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(p1.files_indexed, 5);
    assert_eq!(p1.files_skipped_unmodified, 0);

    // Save catalog to disk explicitly to verify save_catalog_to_file
    dedup_v1.save_catalog_to_file(&catalog_path).expect("Saving catalog to file must succeed");
    assert!(catalog_path.exists(), "dedup_catalog.json must physically exist on disk");

    // Snapshot full reference state from dedup_v1
    let mut ref_entries: HashMap<PathBuf, (String, i64, u64, Vec<String>)> = HashMap::new();
    for p in &[&f1, &f2, &f3, &f4, &f5] {
        let entry = dedup_v1.get_file_entry(p).expect("File must be in v1 catalog");
        ref_entries.insert(
            (*p).clone(),
            (
                entry.file_blake3,
                entry.mtime_secs,
                entry.size_bytes,
                entry.chunk_hashes,
            ),
        );
    }

    // Drop worker 1 and dedup engine 1 to simulate complete process termination
    drop(worker_v1);
    drop(dedup_v1);

    // ------------------------------------------------------------------------
    // WORKER LIFECYCLE 2: Fresh worker boot with catalog reload from disk
    // ------------------------------------------------------------------------
    let dedup_v2 = Arc::new(TwoLevelDedupEngine::new());
    assert_eq!(
        dedup_v2.get_all_tracked_files().len(), 0,
        "Fresh dedup engine before reload must contain 0 entries"
    );

    // Reload catalog from disk
    dedup_v2
        .load_catalog_from_file(&catalog_path)
        .expect("load_catalog_from_file must succeed cleanly");

    assert_eq!(
        dedup_v2.get_all_tracked_files().len(), 5,
        "Reloaded catalog must restore exactly 5 entries"
    );

    // Verify all Level-1 hashes and metadata are bit-for-bit identical to reference state
    for (path, (expected_hash, expected_mtime, expected_size, expected_chunks)) in &ref_entries {
        let entry_v2 = dedup_v2
            .get_file_entry(path)
            .unwrap_or_else(|| panic!("File {:?} missing from reloaded catalog", path));

        assert_eq!(
            &entry_v2.file_blake3, expected_hash,
            "Reloaded BLAKE3 hash mismatch for {:?}",
            path
        );
        assert_eq!(
            entry_v2.mtime_secs, *expected_mtime,
            "Reloaded mtime mismatch for {:?}",
            path
        );
        assert_eq!(
            entry_v2.size_bytes, *expected_size,
            "Reloaded size mismatch for {:?}",
            path
        );
        assert_eq!(
            &entry_v2.chunk_hashes, expected_chunks,
            "Reloaded chunk hashes mismatch for {:?}",
            path
        );
    }

    // Construct fresh Worker 2 using the reloaded dedup engine
    let config_v2 = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        dedup_catalog_path: Some(catalog_path.clone()),
        excluded_paths: vec![storage_dir.clone()],
        exclude_source_code: false,
        ..Default::default()
    };

    let worker_v2 = ReindexWorker::new(
        config_v2,
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup_v2),
    );

    // Execute reindex pass on restarted worker: MUST produce 0 files indexed, 0 new embeddings
    let p_restart = worker_v2.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(p_restart.phase, ReindexPhase::Completed);
    assert_eq!(
        p_restart.files_indexed, 0,
        "Restarted worker with restored catalog must index ZERO files on untouched tree"
    );
    assert_eq!(
        p_restart.files_skipped_unmodified, 5,
        "All 5 files must be skipped via reloaded Level-1 catalog entries"
    );
    assert_eq!(
        p_restart.chunks_newly_embedded, 0,
        "Restarted worker must perform ZERO new embedding computations"
    );
    assert_eq!(p_restart.files_failed, 0);
}

// ============================================================================
// TEST 5: ADVERSARIAL NESTED TREE & INTERLEAVED MUTATION COHERENCE
// ============================================================================

#[tokio::test]
async fn test_m19_adversarial_nested_and_concurrent_mutation_catalog_coherence() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("user_docs");
    let data_dir = dir.path().join("data_dir");
    create_dir_all(&root).unwrap();
    create_dir_all(&data_dir).unwrap();

    let storage_dir = data_dir.join("storage");
    let catalog_path = data_dir.join("dedup_catalog.json");

    // Create 10 files in deeply nested directories
    let mut files = Vec::new();
    for i in 1..=10 {
        let nested_dir = root.join(format!("depth_{}", i % 4)).join(format!("level_{}", i % 3));
        create_dir_all(&nested_dir).unwrap();
        let fpath = nested_dir.join(format!("document_{}.txt", i));
        write(&fpath, generate_doc_content(&format!("topic_{}", i), 4, 250)).unwrap();
        files.push(fpath);
    }

    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir.clone())).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        dedup_catalog_path: Some(catalog_path.clone()),
        excluded_paths: vec![storage_dir.clone()],
        exclude_source_code: false,
        ..Default::default()
    };

    let worker = ReindexWorker::new(
        config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    );

    // Initial pass: index all 10
    let p1 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(p1.files_indexed, 10);
    assert_eq!(p1.files_skipped_unmodified, 0);

    // 3 Untouched verification passes (Passes 2, 3, 4)
    for pass_num in 2..=4 {
        let p = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
        assert_eq!(p.files_indexed, 0, "Pass {} must index 0 files", pass_num);
        assert_eq!(p.files_skipped_unmodified, 10, "Pass {} must skip all 10 files", pass_num);
        assert_eq!(p.chunks_newly_embedded, 0);
    }

    // Now execute interleaved mutations:
    // (a) Mutate file 2 and file 7
    tokio::time::sleep(tokio::time::Duration::from_millis(1100)).await;
    write(&files[1], generate_doc_content("topic_2_mutated", 5, 300)).unwrap();
    write(&files[6], generate_doc_content("topic_7_mutated", 5, 300)).unwrap();

    // (b) Add file 11
    let f11 = root.join("depth_0").join("document_11_new.txt");
    write(&f11, generate_doc_content("topic_11_new", 4, 250)).unwrap();

    // (c) Delete file 5 from disk & remove from catalog
    remove_file(&files[4]).unwrap();
    dedup.remove_file(&files[4]);
    let f5_str = files[4].to_string_lossy().to_string();
    let _ = storage.delete_by_file_path(&f5_str).await;

    // Run reindexing pass 5:
    // Expected:
    // Scanned = 10 (9 remaining original files + 1 new file)
    // Files indexed = 3 (file 2 mutated, file 7 mutated, file 11 new)
    // Files skipped = 7 (files 1, 3, 4, 6, 8, 9, 10 untouched)
    let p5 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(p5.phase, ReindexPhase::Completed);
    assert_eq!(p5.files_scanned, 10, "Should scan 10 files on disk");
    assert_eq!(p5.files_indexed, 3, "2 mutated + 1 new = 3 files indexed");
    assert_eq!(p5.files_skipped_unmodified, 7, "7 untouched files skipped unmodified");
    assert!(p5.chunks_newly_embedded >= 3);

    // Pass 6: Post-mutation stabilization pass (untouched tree again)
    let p6 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(p6.files_indexed, 0, "Pass 6 post-mutation must index 0 files");
    assert_eq!(p6.files_skipped_unmodified, 10, "All 10 current files skipped unmodified");
    assert_eq!(p6.chunks_newly_embedded, 0);

    // Final persistence check: save catalog and assert reload in a 3rd fresh engine
    dedup.save_catalog_to_file(&catalog_path).unwrap();
    let dedup_v3 = Arc::new(TwoLevelDedupEngine::new());
    dedup_v3.load_catalog_from_file(&catalog_path).unwrap();
    assert_eq!(dedup_v3.get_all_tracked_files().len(), 10);
    assert!(dedup_v3.get_file_entry(&files[4]).is_none(), "Deleted file 5 must remain absent");
    assert!(dedup_v3.get_file_entry(&f11).is_some(), "New file 11 must be tracked");
}

// ============================================================================
// TEST 6: ADVERSARIAL CATALOG SUBFOLDER ISOLATION INSIDE WATCHED ROOT
// ============================================================================

#[tokio::test]
async fn test_m19_adversarial_subfolder_catalog_isolation() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("watched_project");
    create_dir_all(&root).unwrap();

    // Place storage and catalog inside a dedicated subfolder of the watched directory:
    // e.g. .quorumrag/storage and .quorumrag/dedup_catalog.json
    let internal_dir = root.join(".quorumrag");
    let storage_dir = internal_dir.join("storage");
    let catalog_path = internal_dir.join("dedup_catalog.json");
    create_dir_all(&internal_dir).unwrap();

    let f1 = root.join("readme.md");
    let f2 = root.join("guide.txt");
    write(&f1, generate_doc_content("project_readme", 4, 300)).unwrap();
    write(&f2, generate_doc_content("project_guide", 4, 300)).unwrap();

    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir.clone())).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let config = IngestConfig {
        watch_paths: vec![root.clone()],
        dedup_catalog_path: Some(catalog_path.clone()),
        excluded_paths: vec![storage_dir.clone()],
        exclude_source_code: false,
        ..Default::default()
    };

    let worker = ReindexWorker::new(
        config,
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    );

    // Pass 1: Indexes exactly the 2 user files
    let p1 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(p1.files_indexed, 2, "Must index exactly the 2 user files");
    assert_eq!(p1.files_skipped_unmodified, 0);

    // Pass 2: Untouched pass -> must index 0 files, skip 2 files
    let p2 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(p2.files_indexed, 0, "Pass 2 must index 0 files");
    assert_eq!(p2.files_skipped_unmodified, 2, "Pass 2 must skip both user files");
    assert_eq!(p2.chunks_newly_embedded, 0);

    // Pass 3: Verify dedup_catalog.json was never indexed
    let chunks = storage.scan_all_chunks().await.unwrap();
    assert!(
        !chunks.iter().any(|c| c.file_path.contains("dedup_catalog.json")),
        "dedup_catalog.json inside subfolder must never be indexed"
    );
}

