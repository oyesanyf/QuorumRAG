//! Adversarial Empirical Stress Test Suite for Milestone M7.
//!
//! Stress-tests:
//! 1. Watcher Directory Recursion & Deep Hierarchies (5+ levels deep).
//! 2. Rapid Directory Rename Operations (multi-stage prefix purging and reindexing).
//! 3. Watcher Event Queue Backpressure and `QueueOverflow` resilience.
//! 4. Windows Error 32 Sharing Violation Resilience on `ClassifierRouter`.
//! 5. Physical Drive Discovery & Dot-Directory Ingestion (.workspace, .documents vs noise).

use std::fs::create_dir_all;
use std::sync::{mpsc, Arc};
use std::time::Duration;
use tempfile::tempdir;

use quorum_classifier::FileTypeClassifier;
use quorum_contract::{EmbeddingContract, EmbeddingGenerator};
use quorum_storage::{StorageConfig, StorageEngine};

use quorum_ingest::classifier_router::{CandidateKind, ClassifierRouter, FilterDecision};
use quorum_ingest::config::IngestConfig;
use quorum_ingest::engine::IngestEngine;
use quorum_ingest::reindex::ReindexWorker;
use quorum_ingest::watcher::WatcherEvent;

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

/// Deterministic mock embedding generator for tests (canonical 768-dim L2-normalized vectors).
#[derive(Debug, Clone)]
struct MockEmbeddingGenerator {
    contract: EmbeddingContract,
}

impl Default for MockEmbeddingGenerator {
    fn default() -> Self {
        Self {
            contract: EmbeddingContract::canonical_gemma_300m(),
        }
    }
}

impl EmbeddingGenerator for MockEmbeddingGenerator {
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

// ----------------------------------------------------------------------------
// 1. Deeply Nested Directory Hierarchy (6 levels deep) & Recursion Stress Test
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_watcher_deeply_nested_directory_recursion_and_rename_purge() {
    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage_deep_nest");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(MockEmbeddingGenerator::default());

    let config = IngestConfig {
        watch_paths: vec![dir.path().to_path_buf()],
        ..Default::default()
    };

    let engine = IngestEngine::new(config, Arc::clone(&storage), classifier, Arc::clone(&embedder)).unwrap();

    // Construct a 6-level deep directory hierarchy:
    // root/level1/level2/level3/level4/level5/level6
    let root = dir.path();
    let mut current_dir = root.join("alpha");
    let mut file_paths = Vec::new();

    for level in 1..=6 {
        create_dir_all(&current_dir).unwrap();
        let file_path = current_dir.join(format!("document_level_{}.md", level));
        let content = format!("# Level {} Document\nDetailed notes at hierarchy depth {}.\n", level, level);
        std::fs::write(&file_path, content).unwrap();
        file_paths.push(file_path);

        if level < 6 {
            current_dir = current_dir.join(format!("level{}", level + 1));
        }
    }

    // Ingest all files into engine
    for file in &file_paths {
        let chunks = engine.ingest_file(file).await.unwrap();
        assert!(chunks.is_some(), "File {:?} must be ingested successfully", file);
        assert!(!chunks.unwrap().is_empty());
    }

    // Assert all 6 files exist in L1 dedup catalog and LanceDB storage
    assert_eq!(engine.dedup().get_all_tracked_files().len(), 6);
    for file in &file_paths {
        assert!(
            engine.dedup().get_file_entry(file).is_some(),
            "File {:?} must be present in dedup catalog before rename",
            file
        );
    }
    let initial_stored = storage.scan_all_chunks().await.unwrap();
    assert_eq!(initial_stored.len(), 6, "LanceDB must hold exactly 6 chunks");

    // Perform rename at top level: alpha -> renamed_alpha
    let old_alpha = root.join("alpha");
    let new_alpha = root.join("renamed_alpha");
    std::fs::rename(&old_alpha, &new_alpha).unwrap();

    let rename_event = WatcherEvent::Rename {
        from: old_alpha.clone(),
        to: new_alpha.clone(),
    };

    let mutated = engine.handle_watcher_event(rename_event).await.unwrap();
    assert!(mutated, "Directory rename must mutate storage and catalog");

    // Assert: ALL 6 old paths are completely purged from dedup catalog and storage
    for old_file in &file_paths {
        assert!(
            engine.dedup().get_file_entry(old_file).is_none(),
            "Old file path {:?} must be removed from dedup catalog",
            old_file
        );
    }

    let chunks_after_rename = storage.scan_all_chunks().await.unwrap();
    for chunk in &chunks_after_rename {
        assert!(
            !chunk.file_path.contains("\\alpha\\") && !chunk.file_path.contains("/alpha/"),
            "Storage still contains stale old path chunk: {}",
            chunk.file_path
        );
        assert!(
            chunk.file_path.contains("renamed_alpha"),
            "Storage chunk must reflect new path: {}",
            chunk.file_path
        );
    }
    assert_eq!(chunks_after_rename.len(), 6, "Storage must contain exactly 6 chunks for renamed paths");

    // Assert: ALL 6 new paths under renamed_alpha are indexed
    let tracked_now = engine.dedup().get_all_tracked_files();
    assert_eq!(tracked_now.len(), 6);
    for tracked in tracked_now {
        assert!(tracked.starts_with(&new_alpha), "Tracked file must start with new path: {:?}", tracked);
    }

    // Now test directory deletion: delete renamed_alpha
    std::fs::remove_dir_all(&new_alpha).unwrap();
    let remove_event = WatcherEvent::Remove(new_alpha.clone());
    let mutated_remove = engine.handle_watcher_event(remove_event).await.unwrap();
    assert!(mutated_remove, "Directory removal must mutate storage");

    assert_eq!(engine.dedup().get_all_tracked_files().len(), 0);
    let chunks_after_remove = storage.scan_all_chunks().await.unwrap();
    assert_eq!(chunks_after_remove.len(), 0, "All chunks must be completely purged from storage");
}

// ----------------------------------------------------------------------------
// 2. Rapid Directory Rename Operations
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_watcher_rapid_directory_renames_in_sequence() {
    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage_rapid_rename");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(MockEmbeddingGenerator::default());

    let config = IngestConfig {
        watch_paths: vec![dir.path().to_path_buf()],
        ..Default::default()
    };

    let engine = IngestEngine::new(config, Arc::clone(&storage), classifier, Arc::clone(&embedder)).unwrap();

    let root = dir.path();
    let stage1 = root.join("project_stage1");
    let stage2 = root.join("project_stage2");
    let stage3 = root.join("project_stage3");
    let stage4 = root.join("project_stage4");

    create_dir_all(stage1.join("sub")).unwrap();
    let f1 = stage1.join("main.rs");
    let f2 = stage1.join("sub").join("lib.rs");
    std::fs::write(&f1, "fn main() { println!(\"Rapid rename 1\"); }").unwrap();
    std::fs::write(&f2, "pub fn add(a: i32, b: i32) -> i32 { a + b }").unwrap();

    engine.ingest_file(&f1).await.unwrap();
    engine.ingest_file(&f2).await.unwrap();
    assert_eq!(engine.dedup().get_all_tracked_files().len(), 2);

    // Rapid Rename 1: stage1 -> stage2
    std::fs::rename(&stage1, &stage2).unwrap();
    engine
        .handle_watcher_event(WatcherEvent::Rename {
            from: stage1.clone(),
            to: stage2.clone(),
        })
        .await
        .unwrap();

    assert!(engine.dedup().get_file_entry(&f1).is_none());
    assert!(engine.dedup().get_file_entry(&stage2.join("main.rs")).is_some());

    // Rapid Rename 2: stage2 -> stage3
    std::fs::rename(&stage2, &stage3).unwrap();
    engine
        .handle_watcher_event(WatcherEvent::Rename {
            from: stage2.clone(),
            to: stage3.clone(),
        })
        .await
        .unwrap();

    assert!(engine.dedup().get_file_entry(&stage2.join("main.rs")).is_none());
    assert!(engine.dedup().get_file_entry(&stage3.join("main.rs")).is_some());

    // Rapid Rename 3: stage3 -> stage4
    std::fs::rename(&stage3, &stage4).unwrap();
    engine
        .handle_watcher_event(WatcherEvent::Rename {
            from: stage3.clone(),
            to: stage4.clone(),
        })
        .await
        .unwrap();

    assert!(engine.dedup().get_file_entry(&stage3.join("main.rs")).is_none());
    let final_main = stage4.join("main.rs");
    let final_lib = stage4.join("sub").join("lib.rs");
    assert!(engine.dedup().get_file_entry(&final_main).is_some());
    assert!(engine.dedup().get_file_entry(&final_lib).is_some());

    // Verify storage has exactly 2 chunks, all pointing to stage4
    let stored = storage.scan_all_chunks().await.unwrap();
    assert_eq!(stored.len(), 2);
    for chunk in &stored {
        assert!(chunk.file_path.starts_with(&stage4.to_string_lossy().to_string()));
    }
}

// ----------------------------------------------------------------------------
// 3. Event Queue Backpressure and QueueOverflow Resilience
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_watcher_queue_overflow_handling_triggers_healer_without_panic() {
    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage_overflow");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(MockEmbeddingGenerator::default());

    let config = IngestConfig {
        watch_paths: vec![dir.path().to_path_buf()],
        ..Default::default()
    };

    let engine = IngestEngine::new(config, Arc::clone(&storage), classifier, Arc::clone(&embedder)).unwrap();

    // Emitting WatcherEvent::QueueOverflow must be handled gracefully:
    // returns Ok(false), logs warning, and spawns drift remediation without panicking.
    let overflow_event = WatcherEvent::QueueOverflow {
        root: dir.path().to_path_buf(),
        details: "Channel capacity saturated (10,000 events reached)".into(),
    };

    let result = engine.handle_watcher_event(overflow_event).await;
    assert!(result.is_ok(), "Engine must handle QueueOverflow without error: {:?}", result);
    assert!(!result.unwrap(), "QueueOverflow does not directly mutate storage synchronously");
}

// ----------------------------------------------------------------------------
// 4. Windows Error 32 Sharing Violation Resilience on ClassifierRouter
// ----------------------------------------------------------------------------

#[test]
fn test_classifier_router_sharing_violation_recovers_when_lock_released() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("active_document.txt");
    let content = "Critical report content being actively edited by user.";
    std::fs::write(&file_path, content).unwrap();

    let router = ClassifierRouter::new(IngestConfig::default());

    #[cfg(windows)]
    {
        let lock_path = file_path.clone();
        let (tx, rx) = mpsc::channel();

        let handle = std::thread::spawn(move || {
            let exclusive_file = match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(0) // Win32 FILE_SHARE_NONE
                .open(&lock_path)
            {
                Ok(f) => {
                    tx.send(true).unwrap();
                    f
                }
                Err(e) => {
                    tx.send(false).unwrap();
                    panic!("Failed to acquire exclusive lock: {}", e);
                }
            };

            // Hold exclusive lock for 40ms.
            // The router retries with [25ms, 50ms, 100ms] exponential backoff.
            // At 75ms (attempt 2), the lock will be released!
            std::thread::sleep(Duration::from_millis(40));
            drop(exclusive_file);
        });

        let acquired = rx.recv_timeout(Duration::from_secs(3)).expect("Lock acquisition timeout");
        assert!(acquired);

        let decision = router.evaluate_file(&file_path);
        handle.join().unwrap();

        match decision {
            FilterDecision::Accept { kind, size_bytes, .. } => {
                assert!(
                    matches!(kind, CandidateKind::Text { .. }),
                    "Expected CandidateKind::Text, got {:?}",
                    kind
                );
                assert_eq!(size_bytes, content.len() as u64);
            }
            other => panic!("Expected Accept after sharing violation recovery, got {:?}", other),
        }
    }
}

#[test]
fn test_classifier_router_sharing_violation_fails_cleanly_on_persistent_lock() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("persistently_locked.txt");
    std::fs::write(&file_path, "Locked").unwrap();

    let router = ClassifierRouter::new(IngestConfig::default());

    #[cfg(windows)]
    {
        let lock_path = file_path.clone();
        let (tx, rx) = mpsc::channel();

        let handle = std::thread::spawn(move || {
            let exclusive_file = match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(0)
                .open(&lock_path)
            {
                Ok(f) => {
                    tx.send(true).unwrap();
                    f
                }
                Err(e) => {
                    tx.send(false).unwrap();
                    panic!("Failed to acquire exclusive lock: {}", e);
                }
            };

            // Hold lock for 2500ms (exceeding total nested backoff window:
            // 3 router attempts * (25ms+50ms+100ms open retries + 25ms/50ms classifier delays) ~ 600ms)
            std::thread::sleep(Duration::from_millis(2500));
            drop(exclusive_file);
        });

        let acquired = rx.recv_timeout(Duration::from_secs(3)).expect("Lock acquisition timeout");
        assert!(acquired);

        let decision = router.evaluate_file(&file_path);
        handle.join().unwrap();

        assert!(
            matches!(decision, FilterDecision::SkipIoError { .. }),
            "Expected SkipIoError when lock is held beyond backoff window, got {:?}",
            decision
        );
    }
}

// ----------------------------------------------------------------------------
// 5. Physical Drive Discovery & Dot-Directory Ingestion
// ----------------------------------------------------------------------------

#[test]
fn test_expand_drive_roots_preserves_dot_folders_and_prunes_noise() {
    let dir = tempdir().unwrap();
    let mock_drive_root = dir.path().join("mock_drive_d");
    create_dir_all(&mock_drive_root).unwrap();

    // User dot-folders that MUST be preserved:
    let user_dot_folders = [
        mock_drive_root.join(".workspace"),
        mock_drive_root.join(".documents"),
        mock_drive_root.join(".my_notes"),
        mock_drive_root.join(".config_user"),
    ];

    for folder in &user_dot_folders {
        create_dir_all(folder).unwrap();
        std::fs::write(folder.join("manifest.txt"), "Important user metadata").unwrap();
    }

    // Standard folders that MUST be preserved:
    let standard_folders = [
        mock_drive_root.join("Documents"),
        mock_drive_root.join("Projects"),
    ];

    for folder in &standard_folders {
        create_dir_all(folder).unwrap();
        std::fs::write(folder.join("readme.txt"), "Standard folder content").unwrap();
    }

    // Engine metadata / Repository noise folders that MUST be pruned:
    let noise_folders = [
        mock_drive_root.join(".git"),
        mock_drive_root.join(".lance"),
        mock_drive_root.join(".tantivy"),
        mock_drive_root.join(".quorumrag-live-data"),
        mock_drive_root.join(".pytest_cache"),
        mock_drive_root.join("node_modules"),
        mock_drive_root.join("target"),
        mock_drive_root.join("__pycache__"),
        mock_drive_root.join(".venv"),
        mock_drive_root.join(".cargo"),
        mock_drive_root.join(".rustup"),
    ];

    for folder in &noise_folders {
        create_dir_all(folder).unwrap();
        std::fs::write(folder.join("noise.bin"), [0u8; 16]).unwrap();
    }

    // Run drive root expansion
    let expanded = ReindexWorker::expand_drive_roots(&[mock_drive_root.clone()]);

    // Verify user dot-folders are preserved
    for user_folder in &user_dot_folders {
        assert!(
            expanded.iter().any(|p| p == user_folder),
            "User dot-folder {:?} was incorrectly skipped during drive expansion!",
            user_folder
        );
    }

    // Verify standard folders are preserved
    for std_folder in &standard_folders {
        assert!(
            expanded.iter().any(|p| p == std_folder),
            "Standard folder {:?} was missing from drive expansion!",
            std_folder
        );
    }

    // Verify noise folders are strictly pruned
    for noise in &noise_folders {
        assert!(
            !expanded.iter().any(|p| p == noise),
            "Noise folder {:?} must be strictly pruned during drive expansion!",
            noise
        );
    }
}
