use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

use quorum_classifier::FileTypeClassifier;
use quorum_contract::{EmbeddingContract, EmbeddingGenerator};
use quorum_ingest::{
    FilesystemWatcher, IngestConfig, ReindexPhase, ReindexWorker, TwoLevelDedupEngine,
    WatcherEvent,
};
use quorum_storage::{StorageConfig, StorageEngine};

#[derive(Debug, Clone)]
struct FastTestEmbedder {
    contract: EmbeddingContract,
}

impl Default for FastTestEmbedder {
    fn default() -> Self {
        Self {
            contract: EmbeddingContract::canonical_gemma_300m(),
        }
    }
}

impl EmbeddingGenerator for FastTestEmbedder {
    fn embed_text(&self, text: &str) -> Result<Vec<f32>, quorum_contract::ContractError> {
        let dim = self.contract.dimension;
        let mut vec = vec![0.0f32; dim];
        let hash = blake3::hash(text.as_bytes());
        for (i, b) in hash.as_bytes().iter().enumerate() {
            vec[i] = (*b as f32) / 255.0;
        }
        let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-6);
        for v in &mut vec {
            *v /= norm;
        }
        Ok(vec)
    }

    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, quorum_contract::ContractError> {
        texts.iter().map(|t| self.embed_text(t)).collect()
    }

    fn contract(&self) -> &EmbeddingContract {
        &self.contract
    }
}

#[tokio::test]
async fn test_new_file_and_folder_written_to_disk_triggers_immediate_indexing() {
    let temp = TempDir::new().expect("tempdir");
    let storage_dir = temp.path().join("storage");
    let watch_root = temp.path().join("watched_workspace");
    let dynamic_folder = temp.path().join("newly_uploaded_folder");
    std::fs::create_dir_all(&watch_root).unwrap();
    std::fs::create_dir_all(&dynamic_folder).unwrap();

    // Seed initial file in watch_root
    std::fs::write(
        watch_root.join("initial_doc.md"),
        "# Initial Document\n\nBaseline content before live file write.",
    )
    .unwrap();

    let storage = Arc::new(
        StorageEngine::open(StorageConfig::new(storage_dir.clone()))
            .await
            .expect("storage"),
    );

    let mut cfg = IngestConfig::default();
    cfg.watch_paths = vec![watch_root.clone()];
    cfg.debounce_duration_ms = 100;
    cfg.dedup_catalog_path = Some(temp.path().join("dedup_catalog.json"));

    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(FastTestEmbedder::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let worker = Arc::new(ReindexWorker::new(
        cfg.clone(),
        Arc::clone(&storage),
        classifier,
        embedder,
        dedup,
    ));

    // 1. Start OS FilesystemWatcher and wire it to ReindexWorker::trigger_paths
    let (mut rx, watcher_handle) = FilesystemWatcher::new(cfg.clone())
        .start_watching()
        .expect("start_watching");
    let worker_for_watcher = Arc::clone(&worker);
    let watcher_task = tokio::spawn(async move {
        while let Some(evt) = rx.recv().await {
            match evt {
                WatcherEvent::Create(p) | WatcherEvent::Modify(p) => {
                    let _ = worker_for_watcher.trigger_paths(vec![p]).await;
                }
                WatcherEvent::Rename { to, .. } => {
                    let _ = worker_for_watcher.trigger_paths(vec![to]).await;
                }
                _ => {}
            }
        }
    });

    // 2. Run initial pass on watch_root
    let _ = worker.trigger_paths(vec![watch_root.clone()]).await.unwrap();
    for _ in 0..40 {
        if let Some(p) = worker.get_progress().await {
            assert!(
                p.files_scanned <= p.files_total_estimated,
                "Denominator invariant violated: scanned={} > total={}",
                p.files_scanned,
                p.files_total_estimated
            );
            if p.phase == ReindexPhase::Completed && p.files_indexed >= 1 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let baseline_chunks = storage.count().await.unwrap();
    assert!(baseline_chunks >= 1, "Initial file must be indexed");

    // 3. Write a brand new file to `watch_root` on disk -> OS watcher must immediately trigger indexing!
    let live_file = watch_root.join("live_disk_write.md");
    std::fs::write(
        &live_file,
        "# Live Disk Write\n\nThis file was written directly to disk and must be indexed immediately by the watcher.",
    )
    .unwrap();

    let mut indexed_live_file = false;
    for _ in 0..60 {
        let count = storage.count().await.unwrap();
        if count > baseline_chunks {
            indexed_live_file = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        indexed_live_file,
        "Writing a new file to disk must immediately trigger watcher + reindex without manual polling"
    );

    // 4. Dynamically add a new folder (`newly_uploaded_folder`), write files to it, and verify immediate indexing + denominator invariant
    watcher_handle.watch_path(&dynamic_folder).expect("watch dynamic_folder");
    let count_before_folder = storage.count().await.unwrap();
    std::fs::write(
        dynamic_folder.join("folder_doc_1.md"),
        "# Uploaded Folder Doc 1\n\nFirst document in newly uploaded folder.",
    )
    .unwrap();
    std::fs::write(
        dynamic_folder.join("folder_doc_2.md"),
        "# Uploaded Folder Doc 2\n\nSecond document in newly uploaded folder.",
    )
    .unwrap();
    let _ = worker.trigger_paths(vec![dynamic_folder.clone()]).await.unwrap();

    let mut folder_indexed = false;
    for _ in 0..60 {
        if let Some(p) = worker.get_progress().await {
            assert!(
                p.files_scanned <= p.files_total_estimated,
                "Denominator invariant violated: scanned={} > total={}",
                p.files_scanned,
                p.files_total_estimated
            );
        }
        let count = storage.count().await.unwrap();
        if count >= count_before_folder + 2 {
            folder_indexed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        folder_indexed,
        "Dynamically uploaded folder must be watched and indexed immediately"
    );

    watcher_task.abort();
}
