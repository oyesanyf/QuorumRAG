//! Adversarial empirical test harness for Milestone 39:
//! TwoLevelDedupEngine Startup Hydration from SQLite Document Catalog.
//!
//! EMPIRICAL CHALLENGER M39-2:
//! 1. Hydration from empty catalog returns 0.
//! 2. Hydration preserves existing in-memory entries without overwriting.
//! 3. Files with updated mtime on disk are detected as modified.
//! 4. Unmodified files are skipped via Level-1 fast path with 0 disk reads (verified by deleting file).
//! 5. Scalability stress test across hundreds of files with idempotency checks.

use std::fs::{create_dir_all, remove_file, write, metadata};
use std::path::PathBuf;
use tempfile::tempdir;

use quorum_storage::{
    derive_work_cluster_id, DocumentCatalog, DocumentCatalogEntry, StorageConfig, StorageEngine,
};
use quorum_ingest::dedup::{DedupAction, FileCatalogEntry, Level1DedupCatalog, TwoLevelDedupEngine};

fn create_catalog_entry(
    file_path: &str,
    doc_id: &str,
    mtime: i64,
    size: i64,
    chunk_count: i64,
) -> DocumentCatalogEntry {
    DocumentCatalogEntry {
        file_path: file_path.to_string(),
        document_id: doc_id.to_string(),
        work_cluster_id: derive_work_cluster_id(file_path),
        doc_title: format!("Title for {}", file_path),
        doc_authors: "Author".to_string(),
        doc_kind: "document".to_string(),
        file_name: std::path::Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string(),
        file_extension: "txt".to_string(),
        folder: "folder".to_string(),
        normalized_stem: derive_work_cluster_id(file_path),
        author_confidence: "metadata".to_string(),
        access_tier: 0,
        mtime_secs: mtime,
        size_bytes: size,
        chunk_count,
        summary_excerpt: "Summary".to_string(),
        created_at: 1700000000,
    }
}

#[tokio::test]
async fn test_dedup_hydrate_from_empty_catalog_returns_zero() {
    let tmp = tempdir().unwrap();
    let config = StorageConfig::new(tmp.path().join("storage")).with_vector_dimension(768);
    let storage = StorageEngine::open(config).await.expect("Storage open");

    let dedup = TwoLevelDedupEngine::new();
    assert_eq!(dedup.catalog().read().unwrap().len(), 0);

    let hydrated_count = dedup.hydrate_from_catalog(&storage).expect("Hydration should succeed");
    assert_eq!(hydrated_count, 0, "Hydrating from empty catalog must return 0");
    assert_eq!(dedup.catalog().read().unwrap().len(), 0, "Dedup catalog must remain empty");
}

#[tokio::test]
async fn test_dedup_hydrate_preserves_existing_in_memory_entries_without_overwriting() {
    let tmp = tempdir().unwrap();
    let config = StorageConfig::new(tmp.path().join("storage")).with_vector_dimension(768);
    let storage = StorageEngine::open(config.clone()).await.expect("Storage open");

    // Populate catalog in storage with entry for file A
    let catalog = DocumentCatalog::open(&config.document_catalog_path()).expect("Open catalog");
    let file_a_path = "D:/docs/document_a.txt";
    let catalog_entry_a = create_catalog_entry(
        file_a_path,
        "catalog_doc_id_111",
        1700001111,
        2222,
        3,
    );
    catalog.upsert_entry(&catalog_entry_a).unwrap();

    // Also add file B to catalog
    let file_b_path = "D:/docs/document_b.txt";
    let catalog_entry_b = create_catalog_entry(
        file_b_path,
        "catalog_doc_id_333",
        1700003333,
        4444,
        2,
    );
    catalog.upsert_entry(&catalog_entry_b).unwrap();

    // Now pre-populate in-memory dedup engine with a CUSTOM entry for file A
    let dedup = TwoLevelDedupEngine::new();
    dedup.register_entry(FileCatalogEntry {
        file_path: PathBuf::from(file_a_path),
        file_blake3: "in_memory_custom_hash_999".to_string(),
        mtime_secs: 1799999999,
        size_bytes: 8888,
        chunk_hashes: vec!["chunk_in_mem_1".to_string(), "chunk_in_mem_2".to_string()],
    });
    assert_eq!(dedup.catalog().read().unwrap().len(), 1);

    // Run hydration from catalog
    let count = dedup.hydrate_from_catalog(&storage).expect("Hydrate from catalog");
    // Only file B should be newly added; file A should be skipped because it already exists in memory!
    assert_eq!(count, 1, "Only file B should be registered, file A must be preserved");
    assert_eq!(dedup.catalog().read().unwrap().len(), 2);

    // Verify file A in memory was NOT overwritten
    let entry_a = dedup.get_file_entry(&PathBuf::from(file_a_path)).expect("Entry A must exist");
    assert_eq!(
        entry_a.file_blake3, "in_memory_custom_hash_999",
        "Hydration must preserve in-memory file_blake3"
    );
    assert_eq!(
        entry_a.mtime_secs, 1799999999,
        "Hydration must preserve in-memory mtime_secs"
    );
    assert_eq!(
        entry_a.size_bytes, 8888,
        "Hydration must preserve in-memory size_bytes"
    );
    assert_eq!(
        entry_a.chunk_hashes,
        vec!["chunk_in_mem_1".to_string(), "chunk_in_mem_2".to_string()],
        "Hydration must preserve in-memory chunk_hashes"
    );

    // Verify file B was properly hydrated from catalog
    let entry_b = dedup.get_file_entry(&PathBuf::from(file_b_path)).expect("Entry B must exist");
    assert_eq!(entry_b.file_blake3, "catalog_doc_id_333");
    assert_eq!(entry_b.mtime_secs, 1700003333);
    assert_eq!(entry_b.size_bytes, 4444);
}

#[tokio::test]
async fn test_dedup_hydrate_unmodified_files_skipped_via_level1_fastpath_zero_disk_reads() {
    let tmp = tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    create_dir_all(&data_dir).unwrap();

    let storage_dir = tmp.path().join("storage");
    let config = StorageConfig::new(storage_dir).with_vector_dimension(768);
    let storage = StorageEngine::open(config.clone()).await.expect("Storage open");
    let catalog = DocumentCatalog::open(&config.document_catalog_path()).expect("Open catalog");

    // Create 5 real files on disk
    let mut file_paths = Vec::new();
    let mut file_mtimes = Vec::new();
    let mut file_sizes = Vec::new();

    for i in 0..5 {
        let file_path = data_dir.join(format!("test_doc_{}.txt", i));
        write(&file_path, format!("Unique content for document number {}", i)).unwrap();

        let meta = metadata(&file_path).unwrap();
        let mtime = meta
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let size = meta.len();
        let hash = Level1DedupCatalog::hash_file_stream(&file_path).unwrap();

        let path_str = file_path.to_str().unwrap();
        let entry = create_catalog_entry(path_str, &hash, mtime, size as i64, 1);
        catalog.upsert_entry(&entry).unwrap();

        file_paths.push(file_path);
        file_mtimes.push(mtime);
        file_sizes.push(size);
    }

    let dedup = TwoLevelDedupEngine::new();
    let hydrated = dedup.hydrate_from_catalog(&storage).unwrap();
    assert_eq!(hydrated, 5);

    // Verify evaluate_file returns Unchanged for all 5 files
    for i in 0..5 {
        let action = dedup
            .evaluate_file(&file_paths[i], file_mtimes[i], file_sizes[i])
            .expect("Evaluate file");
        assert!(
            matches!(action, DedupAction::Unchanged { .. }),
            "Expected Unchanged for file {}, got {:?}",
            i,
            action
        );
    }

    // EMPIRICAL PROOF OF 0 DISK READS:
    // Delete file 0 from disk completely!
    // If evaluate_file attempted to open or read the file from disk, it would fail with NotFound IO error.
    // But because mtime and size match the hydrated catalog, the fast path returns Unchanged immediately!
    remove_file(&file_paths[0]).unwrap();
    assert!(!file_paths[0].exists(), "File 0 must not exist on disk");

    let action_deleted = dedup
        .evaluate_file(&file_paths[0], file_mtimes[0], file_sizes[0])
        .expect("Fast-path evaluation on deleted file must succeed with 0 disk reads");

    assert!(
        matches!(action_deleted, DedupAction::Unchanged { .. }),
        "Deleted file with matching metadata must return Unchanged via 0-disk-read fast path, got {:?}",
        action_deleted
    );
}

#[tokio::test]
async fn test_dedup_hydrate_files_with_updated_mtime_detected_as_modified() {
    let tmp = tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    create_dir_all(&data_dir).unwrap();

    let storage_dir = tmp.path().join("storage");
    let config = StorageConfig::new(storage_dir).with_vector_dimension(768);
    let storage = StorageEngine::open(config.clone()).await.expect("Storage open");
    let catalog = DocumentCatalog::open(&config.document_catalog_path()).expect("Open catalog");

    let file_path = data_dir.join("changing_document.txt");
    write(&file_path, "Initial content 1.0").unwrap();

    let meta = metadata(&file_path).unwrap();
    let initial_mtime = meta
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let initial_size = meta.len();
    let initial_hash = Level1DedupCatalog::hash_file_stream(&file_path).unwrap();

    let path_str = file_path.to_str().unwrap();
    let entry = create_catalog_entry(path_str, &initial_hash, initial_mtime, initial_size as i64, 1);
    catalog.upsert_entry(&entry).unwrap();

    let dedup = TwoLevelDedupEngine::new();
    dedup.hydrate_from_catalog(&storage).unwrap();

    // Simulate updating file: new mtime and altered content
    write(&file_path, "Modified content 2.0 with additional text").unwrap();
    let new_meta = metadata(&file_path).unwrap();
    let new_mtime = initial_mtime + 500; // distinct future mtime
    let new_size = new_meta.len();

    let action = dedup
        .evaluate_file(&file_path, new_mtime, new_size)
        .expect("Evaluate modified file");

    match action {
        DedupAction::ModifiedOrNew { file_blake3, is_new } => {
            assert!(!is_new, "File was previously known, so is_new must be false");
            assert_ne!(
                file_blake3, initial_hash,
                "Content hash must differ from initial hash"
            );
        }
        other => panic!("Expected ModifiedOrNew for updated mtime/content, got {:?}", other),
    }
}

#[tokio::test]
async fn test_dedup_hydrate_stress_hundreds_of_files_and_idempotence() {
    let tmp = tempdir().unwrap();
    let storage_dir = tmp.path().join("storage");
    let config = StorageConfig::new(storage_dir).with_vector_dimension(768);
    let storage = StorageEngine::open(config.clone()).await.expect("Storage open");
    let catalog = DocumentCatalog::open(&config.document_catalog_path()).expect("Open catalog");

    let count = 400;
    for i in 0..count {
        let p = format!("D:/stress/folder_{}/file_{}.txt", i / 20, i);
        let doc_id = format!("doc_b3_hash_{:04}", i);
        let mtime = 1715000000 + (i as i64 * 30);
        let size = 2000 + (i as i64 * 10);
        let entry = create_catalog_entry(&p, &doc_id, mtime, size, 2);
        catalog.upsert_entry(&entry).unwrap();
    }

    let dedup = TwoLevelDedupEngine::new();
    let start = std::time::Instant::now();
    let hydrated = dedup.hydrate_from_catalog(&storage).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(hydrated, count);
    assert_eq!(dedup.catalog().read().unwrap().len(), count);
    println!("Hydrated {} entries in {:?}", count, elapsed);
    assert!(
        elapsed < std::time::Duration::from_millis(300),
        "Hydration of 400 catalog entries should take < 300ms, took {:?}",
        elapsed
    );

    // IDEMPOTENCE: A second consecutive hydration pass must register 0 additional entries
    let second_pass = dedup.hydrate_from_catalog(&storage).unwrap();
    assert_eq!(
        second_pass, 0,
        "Second hydration pass must be a no-op (0 new entries)"
    );
    assert_eq!(dedup.catalog().read().unwrap().len(), count);
}
