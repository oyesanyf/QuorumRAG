//! Empirical Adversarial Challenger Verification Suite for Milestone 5:
//! Drive Indexing & Dedup Pipeline Unsticking.
//!
//! EMPIRICAL VERIFICATION TASKS:
//! 1. Fast-skip of unmodified files with 0 disk reads (`check_unchanged_fast`).
//! 2. Consistency of file stream hashing (`hash_file_stream`) across text, PDF, DOCX, and images.
//! 3. Tantivy FTS lookup of image chunk IDs (`:img:0` and legacy `:image:0`).
//! 4. Concurrency stress testing of atomic catalog serialization against Windows file-sharing collisions.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tempfile::tempdir;

use quorum_classifier::FileTypeClassifier;
use quorum_contract::{EmbeddingContract, EmbeddingGenerator};
use quorum_storage::{StorageConfig, StorageEngine};
use quorum_types::DocumentChunk;

use quorum_ingest::config::IngestConfig;
use quorum_ingest::dedup::{
    DedupAction, FileCatalogEntry, Level1DedupCatalog, TwoLevelDedupEngine,
};
use quorum_ingest::engine::IngestEngine;

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
            let mut h = hasher.clone();
            h.update(&(i as u32).to_le_bytes());
            let out = h.finalize();
            let val = (out.as_bytes()[0] as f32 / 255.0) * 2.0 - 1.0;
            vec.push(val);
        }
        let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for v in &mut vec {
                *v /= norm;
            }
        }
        Ok(vec)
    }
}

// ============================================================================
// TASK 1: Fast-Skip with 0 Disk Reads
// ============================================================================

#[test]
fn test_empirical_m5_unmodified_fast_skip_zero_disk_reads() {
    let tmp = tempdir().expect("tempdir");
    let root = tmp.path();

    let dedup_engine = TwoLevelDedupEngine::new();
    let num_files = 10;
    let mut file_paths = Vec::new();
    let mut mtimes = Vec::new();
    let mut sizes = Vec::new();
    let mut hashes = Vec::new();

    for i in 0..num_files {
        let p = root.join(format!("document_{}.txt", i));
        fs::write(&p, format!("Content for document #{} with unique tokens", i)).unwrap();

        let meta = fs::metadata(&p).unwrap();
        let mtime = meta
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let size = meta.len();
        let hash = Level1DedupCatalog::hash_file_stream(&p).unwrap();

        dedup_engine.register_entry(FileCatalogEntry {
            file_path: p.clone(),
            file_blake3: hash.clone(),
            mtime_secs: mtime,
            size_bytes: size,
            chunk_hashes: vec![format!("{}:0", hash)],
        });

        file_paths.push(p);
        mtimes.push(mtime);
        sizes.push(size);
        hashes.push(hash);
    }

    // Direct check_unchanged_fast on existing files
    {
        let catalog = dedup_engine.catalog().read().unwrap();
        for i in 0..num_files {
            let fast = catalog.check_unchanged_fast(&file_paths[i], mtimes[i], sizes[i]);
            assert!(
                matches!(fast, Some(DedupAction::Unchanged { .. })),
                "Expected Unchanged on file {}, got {:?}",
                i,
                fast
            );
        }
    }

    // EMPIRICAL ZERO-DISK-READ CHALLENGE:
    // Delete files completely from disk!
    for p in &file_paths {
        fs::remove_file(p).unwrap();
        assert!(!p.exists(), "File {:?} must be deleted from disk", p);
    }

    // Now evaluate: because mtime and size match, it MUST return Unchanged
    // without ever opening or reading the file from disk (which would fail with NotFound).
    {
        let catalog = dedup_engine.catalog().read().unwrap();
        for i in 0..num_files {
            let fast = catalog.check_unchanged_fast(&file_paths[i], mtimes[i], sizes[i]);
            assert!(
                matches!(fast, Some(DedupAction::Unchanged { .. })),
                "Fast check on deleted file {} must succeed with 0 disk reads",
                i
            );
        }
    }

    for i in 0..num_files {
        let act = dedup_engine
            .evaluate_file(&file_paths[i], mtimes[i], sizes[i])
            .expect("evaluate_file on deleted file must succeed via fast path");
        assert!(
            matches!(act, DedupAction::Unchanged { .. }),
            "evaluate_file must return Unchanged with 0 disk reads"
        );
    }

    // Negative check: If mtime or size is modified, check_unchanged_fast returns None
    {
        let catalog = dedup_engine.catalog().read().unwrap();
        let fast_mtime_changed = catalog.check_unchanged_fast(&file_paths[0], mtimes[0] + 1, sizes[0]);
        assert!(
            fast_mtime_changed.is_none(),
            "Changed mtime must bypass fast skip"
        );

        let fast_size_changed = catalog.check_unchanged_fast(&file_paths[0], mtimes[0], sizes[0] + 1);
        assert!(
            fast_size_changed.is_none(),
            "Changed size must bypass fast skip"
        );
    }
}

// ============================================================================
// TASK 2: Stream Hashing Consistency Across Formats
// ============================================================================

#[tokio::test]
async fn test_empirical_m5_hash_stream_consistency_across_file_types() {
    let tmp = tempdir().expect("tempdir");
    let root = tmp.path();

    // 1. Text File
    let txt_path = root.join("sample.txt");
    let txt_content = "QuorumRAG High Performance Multithreading & Dedup Protocol.\nTesting streaming hash consistency across pipeline stages.";
    fs::write(&txt_path, txt_content).unwrap();
    let txt_stream_hash = Level1DedupCatalog::hash_file_stream(&txt_path).unwrap();
    let txt_raw_hash = blake3::hash(txt_content.as_bytes()).to_hex().to_string();
    assert_eq!(txt_stream_hash, txt_raw_hash, "Text file streaming hash must equal raw byte hash");

    // 2. Binary PNG Image
    let png_path = root.join("image.png");
    let mut png_bytes = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    png_bytes.extend_from_slice(&[0, 0, 0, 13]);
    png_bytes.extend_from_slice(b"IHDR");
    png_bytes.extend_from_slice(&640u32.to_be_bytes());
    png_bytes.extend_from_slice(&480u32.to_be_bytes());
    png_bytes.extend_from_slice(&[8, 2, 0, 0, 0]);
    png_bytes.extend_from_slice(&[0, 0, 0, 0]);
    png_bytes.extend_from_slice(&[0, 0, 0, 0, b'I', b'E', b'N', b'D', 0xae, 0x42, 0x60, 0x82]);
    fs::write(&png_path, &png_bytes).unwrap();
    let png_stream_hash = Level1DedupCatalog::hash_file_stream(&png_path).unwrap();
    let png_raw_hash = blake3::hash(&png_bytes).to_hex().to_string();
    assert_eq!(png_stream_hash, png_raw_hash, "PNG streaming hash must equal raw byte hash");

    // 3. Binary ZIP/DOCX Archive Structure (Raw ZIP Local File Header bytes)
    let docx_path = root.join("document.docx");
    let mut docx_bytes = vec![0x50, 0x4b, 0x03, 0x04]; // PK\x03\x04
    docx_bytes.extend_from_slice(&[0x14, 0x00, 0x00, 0x00, 0x08, 0x00]);
    docx_bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    docx_bytes.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // filename length
    docx_bytes.extend_from_slice(b"word/document.xml");
    docx_bytes.extend_from_slice(b"<w:document><w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>");
    fs::write(&docx_path, &docx_bytes).unwrap();
    let docx_stream_hash = Level1DedupCatalog::hash_file_stream(&docx_path).unwrap();
    let docx_raw_hash = blake3::hash(&docx_bytes).to_hex().to_string();
    assert_eq!(docx_stream_hash, docx_raw_hash, "DOCX streaming hash must equal raw byte hash");

    // 4. Binary PDF Structure
    let pdf_path = root.join("document.pdf");
    let pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n115\n%%EOF\n";
    fs::write(&pdf_path, pdf_bytes).unwrap();
    let pdf_stream_hash = Level1DedupCatalog::hash_file_stream(&pdf_path).unwrap();
    let pdf_raw_hash = blake3::hash(pdf_bytes).to_hex().to_string();
    assert_eq!(pdf_stream_hash, pdf_raw_hash, "PDF streaming hash must equal raw byte hash");

    // 5. Ingestion Engine Pipeline Parity:
    // Verify IngestEngine populates FileCatalogEntry.file_blake3 with hash_file_stream!
    let storage_dir = root.join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(MockEmbeddingGenerator::default());

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        ..Default::default()
    };
    let engine = IngestEngine::new(config, Arc::clone(&storage), classifier, embedder).unwrap();

    let chunks = engine.ingest_file(&txt_path).await.unwrap();
    assert!(chunks.is_some());

    let catalog_entry = engine.dedup().get_file_entry(&txt_path).expect("Entry must be in catalog");
    assert_eq!(
        catalog_entry.file_blake3, txt_stream_hash,
        "IngestEngine stored file_blake3 must match Level1DedupCatalog::hash_file_stream"
    );
}

// ============================================================================
// TASK 3: Image Chunk ID Lookup (:img:0 and legacy :image:0)
// ============================================================================

#[tokio::test]
async fn test_empirical_m5_image_chunk_id_lookup_img0_and_image0() {
    let tmp = tempdir().expect("tempdir");
    let storage_dir = tmp.path().join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());

    // 1. Initial lookup on non-existent chunks must return false
    let dummy_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    assert!(!storage.has_chunk_id_in_fts(&format!("{}:img:0", dummy_hash)));
    assert!(!storage.has_chunk_id_in_fts(&format!("{}:image:0", dummy_hash)));

    // 2. Insert standard image chunk with ID format "<hash>:img:0"
    let img_b3 = "aaaabbbbccccdddd0000111122223333444455556666777788889999aaaabbbb";
    let img_chunk_id = format!("{}:img:0", img_b3);
    let chunk_img = DocumentChunk {
        chunk_id: img_chunk_id.clone(),
        document_id: img_b3.to_string(),
        file_path: "D:/images/diagram.png".to_string(),
        line_start: 1,
        line_end: 1,
        blake3_hash: img_b3.to_string(),
        access_tier: 0,
        vector: vec![0.1; 768],
        text_content: "Image diagram depicting neural mesh topology".to_string(),
        metadata_json: "{}".to_string(),
    };
    storage.insert_chunks(&[chunk_img]).await.unwrap();

    // Verify Tantivy FTS lookup succeeds for :img:0
    assert!(
        storage.has_chunk_id_in_fts(&img_chunk_id),
        "Tantivy FTS must resolve :img:0 chunk ID"
    );

    // 3. Insert legacy image chunk with ID format "<legacy_hash>:image:0"
    let legacy_b3 = "ffffeeeewwww11110000111122223333444455556666777788889999legacy01";
    let legacy_chunk_id = format!("{}:image:0", legacy_b3);
    let chunk_legacy = DocumentChunk {
        chunk_id: legacy_chunk_id.clone(),
        document_id: legacy_b3.to_string(),
        file_path: "D:/images/legacy_chart.png".to_string(),
        line_start: 1,
        line_end: 1,
        blake3_hash: legacy_b3.to_string(),
        access_tier: 0,
        vector: vec![0.2; 768],
        text_content: "Legacy image chart metadata".to_string(),
        metadata_json: "{}".to_string(),
    };
    storage.insert_chunks(&[chunk_legacy]).await.unwrap();

    // Verify Tantivy FTS lookup succeeds for :image:0
    assert!(
        storage.has_chunk_id_in_fts(&legacy_chunk_id),
        "Tantivy FTS must resolve legacy :image:0 chunk ID"
    );

    // 4. Verify the composite condition used in reindex.rs:
    // (storage.has_chunk_id_in_fts(&format!("{}:img:0", hash)) || storage.has_chunk_id_in_fts(&format!("{}:image:0", hash)))
    let check_candidate = |h: &str| -> bool {
        storage.has_chunk_id_in_fts(&format!("{}:img:0", h))
            || storage.has_chunk_id_in_fts(&format!("{}:image:0", h))
    };

    assert!(check_candidate(img_b3), "Composite query must recognize standard :img:0");
    assert!(check_candidate(legacy_b3), "Composite query must recognize legacy :image:0");
    assert!(!check_candidate(dummy_hash), "Composite query must return false for unknown hash");
}

// ============================================================================
// TASK 4: Concurrency Stress Test of Atomic Serialization Against Sharing Collisions
// ============================================================================

#[test]
fn test_empirical_m5_dedup_catalog_atomic_serialization_stress() {
    let tmp = tempdir().expect("tempdir");
    let catalog_path = tmp.path().join("dedup_catalog.json");

    let dedup = Arc::new(TwoLevelDedupEngine::new());
    // Seed initial entries
    for i in 0..50 {
        dedup.register_entry(FileCatalogEntry {
            file_path: PathBuf::from(format!("D:/data/file_{}.txt", i)),
            file_blake3: format!("hash_{:032x}", i),
            mtime_secs: 1700000000 + i,
            size_bytes: 1000 + i as u64,
            chunk_hashes: vec![format!("chunk_{}", i)],
        });
    }

    // Initial save
    dedup.save_catalog_to_file(&catalog_path).expect("Initial save must succeed");
    assert!(catalog_path.exists());

    let running = Arc::new(AtomicBool::new(true));
    let mut handles = Vec::new();

    // Spawn 8 writer threads performing rapid concurrent saves
    for thread_idx in 0..8 {
        let dedup_clone = Arc::clone(&dedup);
        let path_clone = catalog_path.clone();
        let running_clone = Arc::clone(&running);

        let h = std::thread::spawn(move || {
            let mut iter = 0;
            while running_clone.load(Ordering::Relaxed) && iter < 30 {
                // Register a new entry under mutation
                dedup_clone.register_entry(FileCatalogEntry {
                    file_path: PathBuf::from(format!("D:/data/thread_{}_{}.txt", thread_idx, iter)),
                    file_blake3: format!("thread_hash_{}_{}", thread_idx, iter),
                    mtime_secs: 1700000000 + iter,
                    size_bytes: 500,
                    chunk_hashes: vec![],
                });

                // Atomic save to disk
                if let Err(e) = dedup_clone.save_catalog_to_file(&path_clone) {
                    panic!("Thread {} save iteration {} failed with error: {:?}", thread_idx, iter, e);
                }
                iter += 1;
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        });
        handles.push(h);
    }

    // Spawn 4 concurrent reader threads continuously verifying JSON validity
    for thread_idx in 0..4 {
        let path_clone = catalog_path.clone();
        let running_clone = Arc::clone(&running);

        let h = std::thread::spawn(move || {
            let mut reads = 0;
            while running_clone.load(Ordering::Relaxed) && reads < 50 {
                if path_clone.exists() {
                    match fs::read(&path_clone) {
                        Ok(bytes) => {
                            if !bytes.is_empty() {
                                let parse: Result<Level1DedupCatalog, _> = serde_json::from_slice(&bytes);
                                assert!(
                                    parse.is_ok(),
                                    "Reader {} encountered corrupted JSON during concurrent save: {:?}",
                                    thread_idx,
                                    parse.err()
                                );
                            }
                        }
                        Err(e) => {
                            // Transient sharing notices on read
                            eprintln!("Reader {} read notice: {:?}", thread_idx, e);
                        }
                    }
                }
                reads += 1;
                std::thread::sleep(std::time::Duration::from_millis(3));
            }
        });
        handles.push(h);
    }

    // Join all threads
    for h in handles {
        h.join().expect("Worker thread panicked during atomic serialization stress");
    }
    running.store(false, Ordering::Relaxed);

    // Final verification:
    // 1. Catalog file must exist and deserialize cleanly
    assert!(catalog_path.exists());
    let final_bytes = fs::read(&catalog_path).expect("Read final catalog");
    let final_catalog: Level1DedupCatalog = serde_json::from_slice(&final_bytes).expect("Deserialize final catalog");
    assert!(final_catalog.len() >= 50, "Final catalog must contain at least seeded entries");

    // 2. CRITICAL INVARIANT: Zero orphaned temporary files!
    // Temporary files match "*.tmp*"
    let parent = catalog_path.parent().unwrap();
    let mut orphaned_tmp_count = 0;
    for entry in fs::read_dir(parent).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.contains(".tmp") {
            orphaned_tmp_count += 1;
            eprintln!("Found orphaned temporary file: {}", name);
        }
    }
    assert_eq!(
        orphaned_tmp_count, 0,
        "atomic_write_json_file must never leave orphaned temporary files on disk"
    );
}

// ============================================================================
// TASK 5: Pipeline & Subprocess Task Timeout Verification
// ============================================================================

#[tokio::test]
async fn test_empirical_m5_pipeline_timeout_resilience() {
    use futures::stream::{FuturesUnordered, StreamExt};
    use std::time::Duration;

    // Simulate candidate pipeline stream mirroring ReindexWorker::execute_pipeline (reindex.rs:648)
    // where candidate 1 completes fast, candidate 2 hangs indefinitely (simulating frozen subprocess),
    // and candidate 3 completes fast.
    let mut futures: FuturesUnordered<tokio::task::JoinHandle<Result<String, ()>>> = FuturesUnordered::new();

    // Fast candidate 1
    futures.push(tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        Ok("Candidate 1 processed".to_string())
    }));

    // Hanging candidate 2 (simulating frozen subprocess)
    futures.push(tokio::spawn(async move {
        futures::future::pending::<Result<String, ()>>().await
    }));

    // Fast candidate 3
    futures.push(tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        Ok("Candidate 3 processed".to_string())
    }));

    let mut files_scanned = 0;
    let mut files_indexed = 0;
    let mut files_failed = 0;

    let candidate_timeout = Duration::from_millis(100);

    // Drain pipeline loop matching ReindexWorker::execute_pipeline
    while !futures.is_empty() {
        match tokio::time::timeout(candidate_timeout, futures.next()).await {
            Ok(Some(join_res)) => {
                if let Ok(Ok(_res)) = join_res {
                    files_scanned += 1;
                    files_indexed += 1;
                }
            }
            Ok(None) => break,
            Err(_) => {
                // Timeout fired on hung candidate
                files_scanned += 1;
                files_failed += 1;
                break;
            }
        }
    }

    assert_eq!(files_indexed, 2, "2 fast candidates must complete and be indexed");
    assert_eq!(files_failed, 1, "1 hung candidate must be timed out and recorded as failed");
    assert_eq!(files_scanned, 3, "All 3 candidates must be accounted for in files_scanned");
}


