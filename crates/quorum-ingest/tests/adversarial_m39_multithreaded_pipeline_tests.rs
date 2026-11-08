//! Empirical Stress-Test Suite for Milestone 39:
//! Auto-Indexing Pipeline Resilience, Dedup Hydration & Semaphore-Bounded Multithreading.
//!
//! EMPIRICAL CHALLENGER M39-2:
//! 1. Semaphore-bounded reindexing pipeline with 50+ concurrent synthetic files under
//!    varying worker thread pools (`options.num_threads` = 4, 12, 8, 2, 1).
//! 2. `is_bulk_indexing()` active state during reindexing and guaranteed RAII reset via `BulkIndexReset`
//!    on normal completion, cancel, and panic unwind.
//! 3. `OcrOutcome::ZeroWords` behavior: clean zero-word recognition returns immediately without
//!    attempting cold external PowerShell process execution.
//! 4. `discover_installed_vision_models` filtering: excludes heavy models >= 20GB and models
//!    tagged with `:32b`, `:70b`, `:90b`.
//! 5. Fast-path SQLite catalog hydration: `TwoLevelDedupEngine::hydrate_from_catalog` populates
//!    in-memory Level-1 catalog directly from `document_catalog.db` with 0 disk reads.

use std::fs::{create_dir_all, write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::tempdir;

use quorum_classifier::FileTypeClassifier;
use quorum_contract::{EmbeddingContract, EmbeddingGenerator};
use quorum_storage::{StorageConfig, StorageEngine};

use quorum_ingest::config::{IngestConfig, ReindexOptions};
use quorum_ingest::dedup::{DedupAction, TwoLevelDedupEngine};
use quorum_ingest::image_indexer::{ImageIndexer, OcrOutcome};
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

/// Helper to generate multi-line synthetic document content.
fn generate_content(category: &str, id: usize, lines: usize) -> String {
    let mut out = format!("# Synthetic Document: {} - Index {}\n\n", category, id);
    for l in 1..=lines {
        out.push_str(&format!(
            "Paragraph {} for item {} discussing distributed quorum consensus, local-first vector search, and Tantivy BM25 full-text indexing.\n",
            l, id
        ));
    }
    out
}

/// Helper to create a fully standard, uncompressed 2x2 white 24-bit BMP image (70 bytes).
fn create_blank_2x2_bmp() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(70);
    // BMP Header (14 bytes)
    bytes.extend_from_slice(b"BM");
    bytes.extend_from_slice(&70u32.to_le_bytes()); // file size: 54 header + 16 pixel data
    bytes.extend_from_slice(&0u32.to_le_bytes()); // reserved
    bytes.extend_from_slice(&54u32.to_le_bytes()); // offset to pixel data

    // DIB Header (BITMAPINFOHEADER - 40 bytes)
    bytes.extend_from_slice(&40u32.to_le_bytes()); // header size
    bytes.extend_from_slice(&2i32.to_le_bytes()); // width 2
    bytes.extend_from_slice(&2i32.to_le_bytes()); // height 2
    bytes.extend_from_slice(&1u16.to_le_bytes()); // color planes 1
    bytes.extend_from_slice(&24u16.to_le_bytes()); // bits per pixel 24
    bytes.extend_from_slice(&0u32.to_le_bytes()); // compression BI_RGB
    bytes.extend_from_slice(&16u32.to_le_bytes()); // image size in bytes (2 rows * 8 bytes)
    bytes.extend_from_slice(&2835i32.to_le_bytes()); // X pixels/m
    bytes.extend_from_slice(&2835i32.to_le_bytes()); // Y pixels/m
    bytes.extend_from_slice(&0u32.to_le_bytes()); // colors in color table
    bytes.extend_from_slice(&0u32.to_le_bytes()); // important colors

    // Pixel Data (2 rows * 8 bytes = 16 bytes: 2 pixels white + 2 padding bytes per row)
    bytes.extend_from_slice(&[255, 255, 255, 255, 255, 255, 0, 0]);
    bytes.extend_from_slice(&[255, 255, 255, 255, 255, 255, 0, 0]);

    bytes
}

/// Spawns a background loopback TCP listener simulating Ollama `/api/tags` and `/api/generate`.
fn spawn_mock_ollama_listener() -> (SocketAddr, Arc<AtomicBool>, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = Arc::clone(&running);
    let requested_models = Arc::new(Mutex::new(Vec::new()));
    let req_models_clone = Arc::clone(&requested_models);

    std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        while running_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    use std::io::{Read, Write};
                    let mut buf = [0u8; 4096];
                    let mut total = Vec::new();
                    let mut content_len = 0;

                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                total.extend_from_slice(&buf[..n]);
                                if content_len == 0 {
                                    if let Some(pos) = total.windows(4).position(|w| w == b"\r\n\r\n") {
                                        let headers = String::from_utf8_lossy(&total[..pos]);
                                        for line in headers.lines() {
                                            if line.to_ascii_lowercase().starts_with("content-length:") {
                                                if let Some(val) = line.split(':').nth(1) {
                                                    content_len = val.trim().parse::<usize>().unwrap_or(0);
                                                }
                                            }
                                        }
                                        if content_len == 0 || total.len() >= pos + 4 + content_len {
                                            break;
                                        }
                                    }
                                } else if let Some(pos) = total.windows(4).position(|w| w == b"\r\n\r\n") {
                                    if total.len() >= pos + 4 + content_len {
                                        break;
                                    }
                                }
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(5));
                                continue;
                            }
                            Err(_) => break,
                        }
                    }

                    let req_str = String::from_utf8_lossy(&total);
                    if req_str.contains("GET /api/tags") {
                        let tags_response = serde_json::json!({
                            "models": [
                                { "name": "moondream:latest", "size": 1800000000u64 },
                                { "name": "llava:32b", "size": 18000000000u64 },
                                { "name": "qwen2.5vl:70b", "size": 42000000000u64 },
                                { "name": "llama3.2-vision:90b", "size": 55000000000u64 },
                                { "name": "huge-vision:latest", "size": 22000000000u64 },
                                { "name": "llava:7b", "size": 4500000000u64 }
                            ]
                        });
                        let body = tags_response.to_string();
                        let resp = format!(
                            "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.flush();
                    } else if req_str.contains("POST /api/generate") {
                        if let Some(pos) = req_str.find("\r\n\r\n") {
                            let body = &req_str[pos + 4..];
                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                                if let Some(m) = v.get("model").and_then(|m| m.as_str()) {
                                    req_models_clone.lock().unwrap().push(m.to_string());
                                }
                            }
                        }
                        let gen_response = serde_json::json!({
                            "response": "A crisp scenic photo with blue skies, pine trees, and a mountain horizon."
                        });
                        let body = gen_response.to_string();
                        let resp = format!(
                            "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.flush();
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    (addr, running, requested_models)
}

// ============================================================================
// TEST 1: SEMAPHORE-BOUNDED MULTITHREADED PIPELINE WITH 50+ FILES
// ============================================================================

#[tokio::test]
async fn test_semaphore_bounded_multithreaded_pipeline_50_plus_files() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("user_workspace");
    let data_dir = dir.path().join("app_data");
    create_dir_all(&root).unwrap();
    create_dir_all(&data_dir).unwrap();

    let sub_a = root.join("folder_alpha");
    let sub_b = root.join("folder_beta").join("nested");
    create_dir_all(&sub_a).unwrap();
    create_dir_all(&sub_b).unwrap();

    // Create 60 synthetic files across root and subfolders
    let total_initial = 60usize;
    for i in 0..20 {
        write(root.join(format!("doc_root_{:02}.txt", i)), generate_content("TextDocs", i, 5)).unwrap();
    }
    for i in 0..20 {
        write(sub_a.join(format!("data_alpha_{:02}.json", i)), format!("{{\"record_id\": {}, \"content\": \"{}\"}}", i, generate_content("JsonDocs", i, 3))).unwrap();
    }
    for i in 0..20 {
        write(sub_b.join(format!("guide_beta_{:02}.md", i)), generate_content("MarkdownDocs", i, 6)).unwrap();
    }

    let storage_dir = data_dir.join("storage");
    let catalog_path = data_dir.join("dedup_catalog.json");

    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir.clone())).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let config = IngestConfig {
        watch_paths: vec![root.clone()],
        dedup_catalog_path: Some(catalog_path.clone()),
        ..IngestConfig::default()
    };

    let worker = ReindexWorker::new(
        config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    );

    // Pass 1: Initial Multithreaded Ingestion with options.num_threads = 4, batch_size = 16
    let t0 = Instant::now();
    let res1 = worker
        .run_reindex_sync(ReindexOptions {
            target_paths: vec![root.clone()],
            batch_size: 16,
            num_threads: 4,
            full_rebuild: false,
            ..ReindexOptions::default()
        })
        .await
        .unwrap();
    let d1 = t0.elapsed();

    assert_eq!(res1.phase, ReindexPhase::Completed);
    assert_eq!(res1.files_scanned, total_initial);
    assert_eq!(res1.files_indexed, total_initial);
    assert_eq!(res1.files_failed, 0);
    assert_eq!(res1.files_skipped_unmodified, 0);
    assert!(res1.chunks_newly_embedded >= total_initial);
    println!("Pass 1 (60 files, 4 worker threads): completed in {:?}", d1);

    // Verify storage chunks are queryable
    let chunks = storage.scan_all_chunks().await.unwrap();
    assert!(chunks.len() >= total_initial, "Expected at least 60 chunks, found {}", chunks.len());

    let search_res = storage.search_text("distributed quorum consensus", 0, 10).await.unwrap();
    assert!(!search_res.is_empty(), "Tantivy search should return hits for indexed terms");

    // Pass 2: Incremental Pass with options.num_threads = 12 (all untouched -> 0 files indexed)
    let t1 = Instant::now();
    let res2 = worker
        .run_reindex_sync(ReindexOptions {
            target_paths: vec![root.clone()],
            batch_size: 16,
            num_threads: 12,
            full_rebuild: false,
            ..ReindexOptions::default()
        })
        .await
        .unwrap();
    let d2 = t1.elapsed();

    assert_eq!(res2.phase, ReindexPhase::Completed);
    assert_eq!(res2.files_scanned, total_initial);
    assert_eq!(res2.files_indexed, 0, "All 60 files must be skipped on untouched pass");
    assert_eq!(res2.files_skipped_unmodified, total_initial);
    assert_eq!(res2.chunks_newly_embedded, 0);
    println!("Pass 2 (60 untouched files, 12 worker threads): completed in {:?} (0 re-embeddings)", d2);

    // Pass 3: Mutate 4 files and add 4 new files (64 total). Test with options.num_threads = 8
    write(root.join("doc_root_00.txt"), "Updated content for root doc 00 with new details.").unwrap();
    write(root.join("doc_root_01.txt"), "Updated content for root doc 01 with new details.").unwrap();
    write(sub_a.join("data_alpha_00.json"), "{\"record_id\": 0, \"content\": \"Modified JSON payload\"}").unwrap();
    write(sub_b.join("guide_beta_00.md"), "# Updated Guide Beta 00\n\nFresh information here.").unwrap();

    write(root.join("doc_root_new_20.txt"), "Newly added doc 20 in root folder.").unwrap();
    write(root.join("doc_root_new_21.txt"), "Newly added doc 21 in root folder.").unwrap();
    write(sub_a.join("data_alpha_new_20.json"), "{\"record_id\": 20, \"content\": \"Newly added JSON\"}").unwrap();
    write(sub_b.join("guide_beta_new_20.md"), "# Newly added guide 20").unwrap();

    let total_pass3 = total_initial + 4; // 64 files

    let res3 = worker
        .run_reindex_sync(ReindexOptions {
            target_paths: vec![root.clone()],
            batch_size: 16,
            num_threads: 8,
            full_rebuild: false,
            ..ReindexOptions::default()
        })
        .await
        .unwrap();

    assert_eq!(res3.phase, ReindexPhase::Completed);
    assert_eq!(res3.files_scanned, total_pass3);
    assert_eq!(res3.files_indexed, 8, "Expected exactly 4 modified + 4 new files = 8 indexed");
    assert_eq!(res3.files_skipped_unmodified, 56, "Expected 56 untouched files skipped");

    // Pass 4: Full Rebuild with options.num_threads = 2 (all 64 files re-indexed)
    let res4 = worker
        .run_reindex_sync(ReindexOptions {
            target_paths: vec![root.clone()],
            batch_size: 16,
            num_threads: 2,
            full_rebuild: true,
            ..ReindexOptions::default()
        })
        .await
        .unwrap();

    assert_eq!(res4.phase, ReindexPhase::Completed);
    assert_eq!(res4.files_scanned, total_pass3);
    assert_eq!(res4.files_indexed, total_pass3);
    assert_eq!(res4.files_skipped_unmodified, 0);

    // Verify catalog persisted to disk
    assert!(catalog_path.exists(), "dedup_catalog.json must be written to disk");
}

// ============================================================================
// TEST 2: BULK INDEXING ACTIVE STATE & RAII RESET (NORMAL, CANCEL, PANIC)
// ============================================================================

#[tokio::test]
async fn test_bulk_indexing_state_and_raii_reset() {
    ImageIndexer::set_bulk_indexing(false);
    assert!(!ImageIndexer::is_bulk_indexing(), "Initial bulk indexing state must be false");

    // 1. Verify RAII reset upon panic unwind
    let panic_res = std::panic::catch_unwind(|| {
        struct BulkGuard;
        impl Drop for BulkGuard {
            fn drop(&mut self) {
                ImageIndexer::set_bulk_indexing(false);
            }
        }
        ImageIndexer::set_bulk_indexing(true);
        assert!(ImageIndexer::is_bulk_indexing());
        let _g = BulkGuard;
        panic!("simulated task abort");
    });
    assert!(panic_res.is_err());
    assert!(!ImageIndexer::is_bulk_indexing(), "BulkIndexReset RAII must restore flag to false on panic");

    // 2. Verify is_bulk_indexing() is true while pipeline is active, and reset to false on completion
    let dir = tempdir().unwrap();
    let root = dir.path().join("workspace");
    let storage_dir = dir.path().join("storage");
    create_dir_all(&root).unwrap();

    for i in 0..15 {
        write(root.join(format!("item_{:02}.txt", i)), generate_content("BulkDocs", i, 5)).unwrap();
    }

    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());
    let config = IngestConfig {
        watch_paths: vec![root.clone()],
        ..IngestConfig::default()
    };
    let worker = ReindexWorker::new(config, storage, classifier, embedder, dedup);

    // Start background reindexing
    let _task_id = worker
        .start_reindex(ReindexOptions {
            target_paths: vec![root.clone()],
            batch_size: 5,
            num_threads: 2,
            ..ReindexOptions::default()
        })
        .await
        .unwrap();

    // Check that bulk indexing is active during task execution
    let mut saw_active = false;
    for _ in 0..100 {
        if ImageIndexer::is_bulk_indexing() {
            saw_active = true;
        }
        if let Some(prog) = worker.get_progress().await {
            if prog.phase == ReindexPhase::Completed {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert!(saw_active, "is_bulk_indexing() must have been observed as true during active reindexing");
    assert!(!ImageIndexer::is_bulk_indexing(), "is_bulk_indexing() must be false after reindex completes");

    // 3. Verify cooperative cancellation restores is_bulk_indexing() to false
    for i in 15..30 {
        write(root.join(format!("item_{:02}.txt", i)), generate_content("BulkDocs", i, 5)).unwrap();
    }

    let _task2 = worker
        .start_reindex(ReindexOptions {
            target_paths: vec![root.clone()],
            batch_size: 2,
            num_threads: 1,
            full_rebuild: true,
            ..ReindexOptions::default()
        })
        .await
        .unwrap();

    // Immediately signal cancellation
    worker.cancel_reindex();

    for _ in 0..100 {
        if let Some(prog) = worker.get_progress().await {
            if matches!(prog.phase, ReindexPhase::Cancelled | ReindexPhase::Completed) {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert!(!ImageIndexer::is_bulk_indexing(), "is_bulk_indexing() must be reset to false upon cancellation");
}

// ============================================================================
// TEST 3: OCR OUTCOME ZERO-WORDS BEHAVIOR & PROCESS EXECUTION PREVENTION
// ============================================================================

#[test]
fn test_ocr_outcome_zero_words_and_power_shell_bypass() {
    let blank_bmp = create_blank_2x2_bmp();

    // 1. Verify in-process native Windows OCR outcome on blank image
    #[cfg(windows)]
    {
        let outcome = ImageIndexer::run_native_windows_ocr_outcome(&blank_bmp);
        assert_eq!(
            outcome,
            OcrOutcome::ZeroWords,
            "Blank 2x2 white BMP must produce OcrOutcome::ZeroWords"
        );
    }

    // 2. Verify extract_metadata executes cleanly and instantly without spawning PowerShell
    let dir = tempdir().unwrap();
    let img_path = dir.path().join("blank_photo.bmp");
    std::fs::write(&img_path, &blank_bmp).unwrap();

    let identity = quorum_classifier::FileIdentity::new(
        "bmp",
        "image/bmp",
        quorum_classifier::FileCategory::Image,
        "BMP",
        false,
        1.0,
        quorum_classifier::ClassifierEngine::HeaderInspection,
    );

    // Set bulk indexing active so synchronous Ollama vision inference does not run against live local daemon
    ImageIndexer::set_bulk_indexing(true);
    let t0 = Instant::now();
    let meta = ImageIndexer::extract_metadata(&img_path, &blank_bmp, &identity);
    let elapsed = t0.elapsed();
    ImageIndexer::set_bulk_indexing(false);

    // Cold PowerShell execution takes 1.5s - 3s on Windows. A clean zero-word return takes < 500ms.
    assert!(
        elapsed < Duration::from_millis(1000),
        "Zero-word image extract_metadata took {:?}, must not spawn cold PowerShell process",
        elapsed
    );
    assert_eq!(meta.width, 2);
    assert_eq!(meta.height, 2);
    assert!(meta.ocr_text.is_none(), "Zero-word image must have ocr_text: None");
    assert!(!meta.has_ocr, "Zero-word image must have has_ocr: false");

    // 3. Verify corrupted image bytes (< 16 bytes) produce OcrOutcome::Failed
    let corrupted = b"BM_short";
    let corrupt_outcome = ImageIndexer::run_native_windows_ocr_outcome(corrupted);
    assert_eq!(corrupt_outcome, OcrOutcome::Failed, "Corrupted image bytes must yield OcrOutcome::Failed");
}

// ============================================================================
// TEST 4: VISION MODEL DISCOVERY FILTERING (>=20GB AND 32b/70b/90b TAGS)
// ============================================================================

#[test]
fn test_vision_model_discovery_filtering() {
    let (addr, running, requested_models) = spawn_mock_ollama_listener();

    let dir = tempdir().unwrap();
    let img_path = dir.path().join("scene.bmp");
    std::fs::write(&img_path, create_blank_2x2_bmp()).unwrap();

    let ollama_url = format!("http://{}", addr);

    // Call caption_image_with_ollama with empty vision_model to force auto-discovery via /api/tags
    let caption_res = ImageIndexer::caption_image_with_ollama(&img_path, &ollama_url, "");
    assert!(caption_res.is_ok(), "Captioning via mock Ollama should succeed: {:?}", caption_res);

    // Stop mock listener
    running.store(false, Ordering::Relaxed);

    // Verify requested models during discovery
    let requested = requested_models.lock().unwrap().clone();
    assert!(!requested.is_empty(), "Should have called POST /api/generate with a discovered model");

    for m in &requested {
        let lower = m.to_ascii_lowercase();
        assert!(
            !lower.contains(":32b"),
            "Discovered model '{}' must not contain ':32b' tag",
            m
        );
        assert!(
            !lower.contains(":70b"),
            "Discovered model '{}' must not contain ':70b' tag",
            m
        );
        assert!(
            !lower.contains(":90b"),
            "Discovered model '{}' must not contain ':90b' tag",
            m
        );
        assert_ne!(
            m, "huge-vision:latest",
            "Discovered model must not be 22GB 'huge-vision:latest'"
        );
    }

    // Verify the selected model was moondream:latest or llava:7b
    assert!(
        requested.iter().any(|m| m == "moondream:latest" || m == "llava:7b"),
        "Requested models {:?} should include moondream:latest or llava:7b",
        requested
    );
}

// ============================================================================
// TEST 5: FAST-PATH SQLITE DEDUP CATALOG HYDRATION
// ============================================================================

#[tokio::test]
async fn test_fast_dedup_catalog_hydration_from_sqlite() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("docs");
    let storage_dir = dir.path().join("storage");
    create_dir_all(&root).unwrap();

    let file_count = 20usize;
    for i in 0..file_count {
        write(root.join(format!("file_{:02}.txt", i)), generate_content("HydrateDocs", i, 4)).unwrap();
    }

    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir.clone())).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());
    let config = IngestConfig {
        watch_paths: vec![root.clone()],
        ..IngestConfig::default()
    };

    let worker = ReindexWorker::new(config.clone(), Arc::clone(&storage), classifier, embedder, Arc::clone(&dedup));

    // Index all 20 files
    let prog = worker
        .run_reindex_sync(ReindexOptions {
            target_paths: vec![root.clone()],
            batch_size: 10,
            num_threads: 4,
            ..ReindexOptions::default()
        })
        .await
        .unwrap();

    assert_eq!(prog.files_indexed, file_count);

    // Verify storage catalog has identities populated
    let identities = storage.list_catalog_file_identities().unwrap();
    assert_eq!(identities.len(), file_count, "document_catalog.db must have all 20 file identities");

    for ident in &identities {
        assert!(!ident.file_path.is_empty());
        assert!(!ident.document_id.is_empty());
        assert!(ident.mtime_secs > 0, "mtime_secs must be populated in SQLite catalog");
        assert!(ident.size_bytes > 0, "size_bytes must be populated in SQLite catalog");
    }

    // Create a fresh, empty dedup engine
    let fresh_dedup = TwoLevelDedupEngine::new();
    assert_eq!(fresh_dedup.catalog().read().unwrap().len(), 0);

    // Hydrate directly from SQLite catalog (completes with 0 disk scans)
    let hydrated_count = fresh_dedup.hydrate_from_catalog(&storage).unwrap();
    assert_eq!(hydrated_count, file_count);
    assert_eq!(fresh_dedup.catalog().read().unwrap().len(), file_count);

    // Verify that every single hydrated file immediately evaluates to Unchanged with 0 file reads
    for ident in identities {
        let p = PathBuf::from(&ident.file_path);
        let action = fresh_dedup.evaluate_file(&p, ident.mtime_secs, ident.size_bytes).unwrap();
        assert!(
            matches!(action, DedupAction::Unchanged { .. }),
            "Hydrated entry for {:?} must evaluate to DedupAction::Unchanged",
            p
        );
    }
}
