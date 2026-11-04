//! Integration test suite for Milestone M7: Zero-Overhead Ingestion Pipeline,
//! Dedup Hydration & Binary Filtering.
//!
//! Covers:
//! 1. Feature 44: TwoLevelDedupEngine startup hydration from LanceDB storage.
//! 2. Feature 45: Drive root expansion without skipping user dot folders (.workspace).
//! 3. Feature 46: Fast-path deterministic binary extension exclusion (without file I/O)
//!    and non-text Data category leak fix.
//! 4. Feature 47: Directory recursive ingest, rename prefix purging, and error handling.

use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::tempdir;

use quorum_classifier::FileTypeClassifier;
use quorum_contract::{EmbeddingContract, EmbeddingGenerator};
use quorum_storage::{StorageConfig, StorageEngine};
use quorum_types::DocumentChunk;

use quorum_ingest::classifier_router::{ClassifierRouter, FilterDecision};
use quorum_ingest::config::IngestConfig;
use quorum_ingest::dedup::{DedupAction, TwoLevelDedupEngine};
use quorum_ingest::engine::IngestEngine;
use quorum_ingest::reindex::ReindexWorker;
use quorum_ingest::watcher::WatcherEvent;

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

#[tokio::test]
async fn test_dedup_startup_hydration_from_storage() {
    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());

    // Create a real file on disk to allow metadata probing
    let file_path = dir.path().join("sample_doc.txt");
    std::fs::write(&file_path, "First line of content\nSecond line of content\nThird line").unwrap();
    let meta = std::fs::metadata(&file_path).unwrap();
    let mtime = meta
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let size = meta.len();

    let doc_blake3 = "doc_hash_1234567890abcdef";
    let chunk0 = DocumentChunk::new(
        format!("{}:0", doc_blake3),
        doc_blake3,
        file_path.to_string_lossy().to_string(),
        1,
        2,
        0,
        vec![0.1; 768],
        "First line of content\nSecond line of content",
        None,
    )
    .unwrap();

    let chunk1 = DocumentChunk::new(
        format!("{}:1", doc_blake3),
        doc_blake3,
        file_path.to_string_lossy().to_string(),
        3,
        3,
        0,
        vec![0.2; 768],
        "Third line",
        None,
    )
    .unwrap();

    let hash0 = chunk0.blake3_hash.clone();
    let hash1 = chunk1.blake3_hash.clone();

    storage.insert_chunks(&[chunk0, chunk1]).await.unwrap();

    // Now test startup hydration into a fresh TwoLevelDedupEngine
    let dedup = TwoLevelDedupEngine::new();
    assert_eq!(dedup.get_all_tracked_files().len(), 0);

    let hydrated_count = dedup.hydrate_from_storage(&storage).await.unwrap();
    assert_eq!(hydrated_count, 2, "Hydrated chunk count must match stored chunks");

    // Level-1 catalog checks
    let entry = dedup.get_file_entry(&file_path).expect("File must be registered in L1 catalog");
    assert_eq!(entry.file_blake3, doc_blake3);
    assert_eq!(entry.mtime_secs, mtime, "mtime must match probed file metadata");
    assert_eq!(entry.size_bytes, size, "size must match probed file metadata");
    assert_eq!(entry.chunk_hashes, vec![hash0.clone(), hash1.clone()], "Chunks must be deterministically sorted");

    // Level-2 chunk cache checks
    assert!(dedup.cache().has_chunk(&hash0));
    assert!(dedup.cache().has_chunk(&hash1));
    assert_eq!(dedup.cache().get(&hash0).unwrap().len(), 768);

    // Level-1 Fast Path check (0 disk reads, 0 hashing)
    let action = dedup.evaluate_file(&file_path, mtime, size).unwrap();
    match action {
        DedupAction::Unchanged { file_blake3, chunk_hashes } => {
            assert_eq!(file_blake3, doc_blake3);
            assert_eq!(chunk_hashes, vec![hash0, hash1]);
        }
        other => panic!("Expected Unchanged, got {:?}", other),
    }
}

#[tokio::test]
async fn test_dedup_startup_hydration_empty_storage() {
    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage_empty");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());

    let dedup = TwoLevelDedupEngine::new();
    let hydrated_count = dedup.hydrate_from_storage(&storage).await.unwrap();

    assert_eq!(hydrated_count, 0);
    assert_eq!(dedup.get_all_tracked_files().len(), 0);
    assert_eq!(dedup.cache().stats().current_size, 0);
}

#[tokio::test]
async fn test_dedup_startup_hydration_offline_drive_fallback() {
    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage_offline");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());

    let offline_path = PathBuf::from("Z:\\offline_drive\\deep\\project_spec.md");
    let doc_blake3 = "offline_hash_abcdef987654";

    let chunk = DocumentChunk::new(
        format!("{}:0", doc_blake3),
        doc_blake3,
        offline_path.to_string_lossy().to_string(),
        1,
        10,
        0,
        vec![0.5; 768],
        "# Offline Architecture Spec",
        None,
    )
    .unwrap();

    let chunk_hash = chunk.blake3_hash.clone();
    storage.insert_chunks(&[chunk]).await.unwrap();

    let dedup = TwoLevelDedupEngine::new();
    let count = dedup.hydrate_from_storage(&storage).await.unwrap();
    assert_eq!(count, 1);

    // Verify fallback to (0, 0) metadata without crashing
    let entry = dedup.get_file_entry(&offline_path).expect("Offline file must still be registered");
    assert_eq!(entry.mtime_secs, 0, "Missing path must fallback to mtime 0");
    assert_eq!(entry.size_bytes, 0, "Missing path must fallback to size 0");
    assert_eq!(entry.chunk_hashes, vec![chunk_hash.clone()]);
    assert!(dedup.cache().has_chunk(&chunk_hash));
}

#[test]
fn test_classifier_router_fast_path_skips_without_file_io() {
    let router = ClassifierRouter::new(IngestConfig::default());

    // Non-existent paths ending in compiled binary extensions
    let binary_paths = [
        Path::new("C:/nonexistent_dir/kernel_driver.sys"),
        Path::new("C:/nonexistent_dir/helper.dll"),
        Path::new("C:/nonexistent_dir/launcher.exe"),
        Path::new("C:/nonexistent_dir/symbols.pdb"),
        Path::new("C:/nonexistent_dir/libcore.so"),
        Path::new("C:/nonexistent_dir/module.pyd"),
        Path::new("C:/nonexistent_dir/firmware.bin"),
    ];

    for path in &binary_paths {
        let decision = router.evaluate_file(path);
        assert!(
            matches!(decision, FilterDecision::SkipBinary { .. }),
            "Path {:?} must return SkipBinary without attempting disk I/O, got {:?}",
            path,
            decision
        );
    }

    // A non-existent text file should fail at metadata/open stage with SkipIoError
    let non_binary_missing = Path::new("C:/nonexistent_dir/real_text_file.txt");
    let decision = router.evaluate_file(non_binary_missing);
    assert!(
        matches!(decision, FilterDecision::SkipIoError { .. }),
        "Non-binary missing file must fail file I/O with SkipIoError, got {:?}",
        decision
    );
}

#[test]
fn test_non_text_data_does_not_leak_to_candidate_text() {
    let dir = tempdir().unwrap();
    let router = ClassifierRouter::new(IngestConfig::default());

    // Create a binary sqlite / data file with non-text bytes
    let db_path = dir.path().join("database.db");
    let mut file = File::create(&db_path).unwrap();
    // Write SQLite header or binary arbitrary data
    file.write_all(b"SQLite format 3\0\x10\0\x01\x01\0@  \0\0\0\x02\0\0\0\0").unwrap();
    file.flush().unwrap();

    let decision = router.evaluate_file(&db_path);
    assert!(
        matches!(decision, FilterDecision::SkipBinary { .. }),
        "Binary Data category file (.db) must be SkipBinary, got {:?}",
        decision
    );
}

#[test]
fn test_reindex_expand_drive_roots_does_not_skip_user_dot_folders() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // Create user dot folders and system skip dirs
    let user_dot_dir = root.join(".workspace");
    create_dir_all(&user_dot_dir).unwrap();
    File::create(user_dot_dir.join("project.json")).unwrap();

    let git_dir = root.join(".git");
    create_dir_all(&git_dir).unwrap();

    let quorum_dir = root.join(".quorumrag-live-data");
    create_dir_all(&quorum_dir).unwrap();

    let lance_dir = root.join(".lance");
    create_dir_all(&lance_dir).unwrap();

    let tantivy_dir = root.join(".tantivy");
    create_dir_all(&tantivy_dir).unwrap();

    let normal_dir = root.join("Documents");
    create_dir_all(&normal_dir).unwrap();

    // Expand drive roots
    let expanded = ReindexWorker::expand_drive_roots(&[root.to_path_buf()]);

    let contains_workspace = expanded.iter().any(|p| p.ends_with(".workspace"));
    let contains_git = expanded.iter().any(|p| p.ends_with(".git"));
    let contains_quorum = expanded.iter().any(|p| p.ends_with(".quorumrag-live-data"));
    let contains_lance = expanded.iter().any(|p| p.ends_with(".lance"));
    let contains_tantivy = expanded.iter().any(|p| p.ends_with(".tantivy"));
    let contains_docs = expanded.iter().any(|p| p.ends_with("Documents"));

    assert!(
        contains_workspace,
        "User .workspace folder must NOT be skipped during drive root expansion"
    );
    assert!(contains_docs, "Normal folder must be expanded");
    assert!(!contains_git, ".git folder must be skipped");
    assert!(!contains_quorum, ".quorumrag-live-data must be skipped");
    assert!(!contains_lance, ".lance must be skipped");
    assert!(!contains_tantivy, ".tantivy must be skipped");
}

#[tokio::test]
async fn test_watcher_directory_recursive_ingest_and_rename() {
    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage_watcher");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());

    let config = IngestConfig {
        watch_paths: vec![dir.path().to_path_buf()],
        ..Default::default()
    };

    let engine = IngestEngine::new(config, Arc::clone(&storage), classifier, Arc::clone(&embedder)).unwrap();

    // 1. Create a directory structure with files
    let src_dir = dir.path().join("source_code");
    let sub_dir = src_dir.join("submodule");
    create_dir_all(&sub_dir).unwrap();

    let file1 = src_dir.join("main.rs");
    let file2 = sub_dir.join("lib.rs");
    std::fs::write(&file1, "fn main() { println!(\"Hello Quorum\"); }").unwrap();
    std::fs::write(&file2, "pub fn helper() -> i32 { 42 }").unwrap();

    // Ingest files
    let res1 = engine.ingest_file(&file1).await.unwrap();
    assert!(res1.is_some() && !res1.unwrap().is_empty());
    let res2 = engine.ingest_file(&file2).await.unwrap();
    assert!(res2.is_some() && !res2.unwrap().is_empty());

    assert!(engine.dedup().get_file_entry(&file1).is_some());
    assert!(engine.dedup().get_file_entry(&file2).is_some());

    // 2. Rename directory: source_code -> renamed_code
    let dst_dir = dir.path().join("renamed_code");
    std::fs::rename(&src_dir, &dst_dir).unwrap();

    let rename_event = WatcherEvent::Rename {
        from: src_dir.clone(),
        to: dst_dir.clone(),
    };

    let mutated = engine.handle_watcher_event(rename_event).await.unwrap();
    assert!(mutated, "Directory rename must mutate storage and catalog");

    // Old paths must be removed
    assert!(engine.dedup().get_file_entry(&file1).is_none());
    assert!(engine.dedup().get_file_entry(&file2).is_none());

    // New paths must be registered
    let new_file1 = dst_dir.join("main.rs");
    let new_file2 = dst_dir.join("submodule").join("lib.rs");
    assert!(engine.dedup().get_file_entry(&new_file1).is_some());
    assert!(engine.dedup().get_file_entry(&new_file2).is_some());
}
