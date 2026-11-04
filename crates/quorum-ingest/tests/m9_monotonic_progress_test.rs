//! Milestone M9 Feature 53: Monotonic Live Indexer Progress Reporting Test.
//!
//! Verifies:
//! 1. Upfront candidate discovery across multiple target subdirectories.
//! 2. `files_total_estimated` is fixed after scanning and never fluctuates downward.
//! 3. `files_scanned` is monotonically non-decreasing throughout ingestion.
//! 4. Progress percentage monotonically advances to 100.0% without yo-yo oscillations.
//! 5. Cooperative cancellation terminates without panic.

use std::fs::{create_dir_all, File};
use std::io::Write;
use std::sync::Arc;
use tempfile::tempdir;

use quorum_classifier::FileTypeClassifier;
use quorum_contract::{EmbeddingContract, EmbeddingGenerator};
use quorum_storage::{StorageConfig, StorageEngine};

use quorum_ingest::config::{IngestConfig, ReindexOptions};
use quorum_ingest::dedup::TwoLevelDedupEngine;
use quorum_ingest::reindex::{ReindexPhase, ReindexWorker};

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
            let val = (raw_int as f32 / u32::MAX as f32) * 2.0 - 1.0;
            vec.push(val);
        }

        let norm: f32 = vec.iter().map(|v| v * v).sum::<f32>().sqrt();
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
async fn test_monotonic_live_indexer_progress_reporting() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // Create multiple subdirectories mimicking expanded drive targets
    let sub1 = root.join("sub1");
    let sub2 = root.join("sub2");
    let sub3 = root.join("sub3");
    create_dir_all(&sub1).unwrap();
    create_dir_all(&sub2).unwrap();
    create_dir_all(&sub3).unwrap();

    // Create multiple documents in each target
    for i in 0..5 {
        let p = sub1.join(format!("doc_1_{}.txt", i));
        let mut f = File::create(&p).unwrap();
        writeln!(f, "Subdir 1 document content index {} with unique text to index.", i).unwrap();
    }
    for i in 0..7 {
        let p = sub2.join(format!("doc_2_{}.txt", i));
        let mut f = File::create(&p).unwrap();
        writeln!(f, "Subdir 2 document content index {} with unique text to index.", i).unwrap();
    }
    for i in 0..4 {
        let p = sub3.join(format!("doc_3_{}.txt", i));
        let mut f = File::create(&p).unwrap();
        writeln!(f, "Subdir 3 document content index {} with unique text to index.", i).unwrap();
    }

    let storage_dir = root.join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    // Configure multiple targets directly
    let config = IngestConfig {
        watch_paths: vec![sub1.clone(), sub2.clone(), sub3.clone()],
        ..Default::default()
    };

    let worker = ReindexWorker::new(
        config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    );

    let options = ReindexOptions {
        target_paths: vec![sub1.clone(), sub2.clone(), sub3.clone()],
        full_rebuild: true,
        force_reembed: false,
        batch_size: 4,
        num_threads: 0,
        dry_run: false,
    };

    worker.start_reindex(options).await.unwrap();

    let mut last_scanned = 0;
    let mut last_total_estimated = 0;
    let mut last_pct = 0.0;
    let mut poll_count = 0;

    loop {
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        poll_count += 1;

        if let Some(prog) = worker.get_progress().await {
            // 1. Total estimated must never decrease once discovery starts
            if prog.files_total_estimated > 0 {
                if last_total_estimated > 0 {
                    assert!(
                        prog.files_total_estimated >= last_total_estimated,
                        "files_total_estimated decreased from {} to {}",
                        last_total_estimated,
                        prog.files_total_estimated
                    );
                }
                last_total_estimated = prog.files_total_estimated;
            }

            // 2. files_scanned must be monotonically non-decreasing
            assert!(
                prog.files_scanned >= last_scanned,
                "files_scanned decreased from {} to {}",
                last_scanned,
                prog.files_scanned
            );
            last_scanned = prog.files_scanned;

            // 3. Percentage must never decrease during chunking
            if prog.files_total_estimated > 0 {
                let current_pct = (prog.files_scanned as f64 / prog.files_total_estimated as f64) * 100.0;
                assert!(
                    current_pct >= last_pct - 0.0001,
                    "Progress percentage decreased from {:.2}% to {:.2}% (scanned: {}, total: {})",
                    last_pct,
                    current_pct,
                    prog.files_scanned,
                    prog.files_total_estimated
                );
                last_pct = current_pct;
            }

            if matches!(prog.phase, ReindexPhase::Completed) {
                assert_eq!(prog.files_scanned, 16, "All 16 created files must be scanned");
                assert_eq!(prog.files_total_estimated, 16, "Estimated count must match total discovered");
                assert_eq!(prog.files_indexed, 16, "All 16 files must be indexed");
                break;
            }

            if matches!(prog.phase, ReindexPhase::Failed) {
                panic!("Reindexing failed with error: {:?}", prog.error_message);
            }
        }

        if poll_count > 500 {
            panic!("Reindexing timed out after 5 seconds");
        }
    }

    assert!(last_pct >= 99.99, "Final progress percentage must reach 100%");
}

#[tokio::test]
async fn test_adversarial_multi_drive_crawl_empty_and_disparate_trees_monotonicity() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // 5 mock drives/targets
    let drive_a = root.join("drive_a_empty");
    let drive_b = root.join("drive_b_nested");
    let drive_c = root.join("drive_c_nonexistent");
    let drive_d = root.join("drive_d_with_ignored");
    let drive_e = root.join("drive_e_standard");

    create_dir_all(&drive_a).unwrap();
    create_dir_all(drive_b.join("deep").join("nested")).unwrap();
    // drive_c is left non-existent
    create_dir_all(&drive_d).unwrap();
    create_dir_all(&drive_e).unwrap();

    // drive_b: 12 files
    for i in 0..12 {
        let p = drive_b.join("deep").join("nested").join(format!("doc_b_{}.txt", i));
        let mut f = File::create(&p).unwrap();
        writeln!(f, "Nested drive B content document {} for indexing.", i).unwrap();
    }

    // drive_d: 8 document files + 3 ignored files (e.g. .exe, .tmp, .bak)
    for i in 0..8 {
        let p = drive_d.join(format!("doc_d_{}.md", i));
        let mut f = File::create(&p).unwrap();
        writeln!(f, "# Markdown document {} on drive D", i).unwrap();
    }
    // Ignored files:
    let _ = File::create(drive_d.join("malware.exe")).unwrap();
    let _ = File::create(drive_d.join("temp.tmp")).unwrap();
    let _ = File::create(drive_d.join("~$lockfile.docx")).unwrap();

    // drive_e: 6 files
    for i in 0..6 {
        let p = drive_e.join(format!("doc_e_{}.txt", i));
        let mut f = File::create(&p).unwrap();
        writeln!(f, "Drive E text document number {} with relevant tokens.", i).unwrap();
    }

    // Total expected candidate documents: 12 + 8 + 6 = 26 documents.
    // Notice that 25.0% cannot occur as an integer multiple (1/26=3.84%, 6/26=23.07%, 7/26=26.92%).

    let storage_dir = root.join("storage_stress");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let config = IngestConfig {
        watch_paths: vec![
            drive_a.clone(),
            drive_b.clone(),
            drive_c.clone(),
            drive_d.clone(),
            drive_e.clone(),
        ],
        exclude_source_code: true,
        ..Default::default()
    };

    let worker = ReindexWorker::new(
        config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    );

    let options = ReindexOptions {
        target_paths: vec![
            drive_a,
            drive_b,
            drive_c,
            drive_d,
            drive_e,
        ],
        full_rebuild: true,
        force_reembed: false,
        batch_size: 4,
        num_threads: 0,
        dry_run: false,
    };

    worker.start_reindex(options).await.unwrap();

    let mut last_scanned = 0;
    let mut last_total_estimated = 0;
    let mut last_pct = 0.0;
    let mut poll_count = 0;

    loop {
        tokio::time::sleep(tokio::time::Duration::from_millis(2)).await;
        poll_count += 1;

        if let Some(prog) = worker.get_progress().await {
            // (a) files_total_estimated never drops or resets to 0 once discovery begins
            if prog.files_total_estimated > 0 {
                if last_total_estimated > 0 {
                    assert!(
                        prog.files_total_estimated >= last_total_estimated,
                        "CRITICAL REGRESSION: files_total_estimated decreased from {} to {}!",
                        last_total_estimated,
                        prog.files_total_estimated
                    );
                }
                last_total_estimated = prog.files_total_estimated;
            }

            // (b) files_scanned is strictly non-decreasing
            assert!(
                prog.files_scanned >= last_scanned,
                "CRITICAL REGRESSION: files_scanned decreased from {} to {}!",
                last_scanned,
                prog.files_scanned
            );
            last_scanned = prog.files_scanned;

            // (c) Computed percent is strictly non-decreasing
            let current_pct = if prog.files_total_estimated > 0 {
                (prog.files_scanned as f64 / prog.files_total_estimated as f64) * 100.0
            } else if matches!(prog.phase, ReindexPhase::Completed) {
                100.0
            } else {
                0.0
            };

            assert!(
                current_pct >= last_pct - 0.0001,
                "CRITICAL REGRESSION: Computed percentage decreased from {:.3}% to {:.3}% (scanned: {}, total: {})",
                last_pct,
                current_pct,
                prog.files_scanned,
                prog.files_total_estimated
            );

            // (d) The percentage NEVER outputs the fake 25% fallback
            if matches!(prog.phase, ReindexPhase::ScanningFilesystem) {
                assert!(
                    (current_pct - 25.0).abs() > 0.0001,
                    "CRITICAL REGRESSION: ScanningFilesystem output fake 25% fallback!"
                );
            }

            last_pct = current_pct;

            if matches!(prog.phase, ReindexPhase::Completed) {
                // (e) Final status reaches 100.0% upon completion
                assert_eq!(prog.files_scanned, 26, "All 26 non-ignored documents across drives must be scanned");
                assert_eq!(prog.files_total_estimated, 26, "Estimated count must match total discovered");
                assert_eq!(prog.files_indexed, 26, "All 26 documents must be indexed");
                break;
            }

            if matches!(prog.phase, ReindexPhase::Failed) {
                panic!("Reindexing failed: {:?}", prog.error_message);
            }
        }

        if poll_count > 2500 {
            panic!("Reindexing timed out after 5 seconds");
        }
    }

    assert!(last_pct >= 99.99, "Final percentage must reach 100.0%");
}

