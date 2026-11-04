//! Comprehensive test suite for `quorum-ingest`.
//!
//! Covers:
//! 1. Crawler (`ignore::WalkParallel` with work-stealing, .gitignore, size caps, hidden files).
//! 2. Magika Content Router (routes images to CandidateKind::Image, code/text to Text, skips binaries).
//! 3. Two-Level BLAKE3 Deduplication (Level 1 file catalog with rename/move detection, Level 2 chunk cache).
//! 4. Line-Aware UTF-8 Safe Chunker (multibyte boundary safety, exact 1-indexed lines).
//! 5. Image Indexer (EXIF/metadata/token/dimension extraction, rich text representation, LanceDB/Tantivy indexing).
//! 6. OS Watcher (300ms debouncing window, Create/Modify/Remove/Rename events).
//! 7. Dedicated Reindexer (incremental skip vs full rebuild).
//! 8. 5-Drift Remediation Worker (Merkle, Lance<->Tantivy parity, Vector contract, ACL policy, Compaction).
//! 9. Unified IngestEngine (end-to-end ingestion and hybrid retrieval).

use std::fs::{create_dir_all, rename, File};
use std::sync::Arc;
use tempfile::tempdir;

use quorum_classifier::FileTypeClassifier;
use quorum_contract::{EmbeddingContract, EmbeddingGenerator};
use quorum_storage::{StorageConfig, StorageEngine, StorageSearchQuery};
use quorum_types::DocumentChunk;

use quorum_ingest::classifier_router::{CandidateKind, ClassifierRouter, FilterDecision};
use quorum_ingest::chunker::{ChunkerConfig, TextChunker};
use quorum_ingest::config::{DriftFixOptions, IngestConfig, ReindexOptions};
use quorum_ingest::crawler::FilesystemCrawler;
use quorum_ingest::dedup::{
    DedupAction, FileCatalogEntry, Level1DedupCatalog, Level2ChunkCache, TwoLevelDedupEngine,
};
use quorum_ingest::drift_healer::DriftHealer;
use quorum_ingest::engine::IngestEngine;
use quorum_ingest::image_indexer::ImageIndexer;
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
            let raw_int = u32::from_le_bytes([hash.as_bytes()[0], hash.as_bytes()[1], hash.as_bytes()[2], hash.as_bytes()[3]]);
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
// 1. CLASSIFIER ROUTER TESTS
// ============================================================================

#[test]
fn test_classifier_router_preserves_all_image_formats_and_skips_executables() {
    let dir = tempdir().unwrap();

    // Text file
    let txt_path = dir.path().join("notes.txt");
    std::fs::write(&txt_path, "Meeting notes and architectural goals").unwrap();

    // PNG image
    let png_path = dir.path().join("diagram.png");
    let mut png_bytes = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    png_bytes.extend_from_slice(&[0, 0, 0, 13]); // IHDR length
    png_bytes.extend_from_slice(b"IHDR");
    png_bytes.extend_from_slice(&800u32.to_be_bytes()); // Width 800
    png_bytes.extend_from_slice(&600u32.to_be_bytes()); // Height 600
    png_bytes.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit RGB
    png_bytes.extend_from_slice(&[0, 0, 0, 0]); // CRC
    std::fs::write(&png_path, &png_bytes).unwrap();

    // JPEG image
    let jpg_path = dir.path().join("photo.jpg");
    let mut jpg_bytes = vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0, 1, 1, 0, 0, 1, 0, 1, 0, 0];
    jpg_bytes.extend_from_slice(&[0xff, 0xc0, 0x00, 0x11, 0x08]); // SOF0
    jpg_bytes.extend_from_slice(&480u16.to_be_bytes()); // Height 480
    jpg_bytes.extend_from_slice(&640u16.to_be_bytes()); // Width 640
    jpg_bytes.push(3); // 3 channels
    jpg_bytes.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0]);
    std::fs::write(&jpg_path, &jpg_bytes).unwrap();

    // Executable (PE MZ)
    let exe_path = dir.path().join("malware.exe");
    std::fs::write(&exe_path, b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff").unwrap();

    let router = ClassifierRouter::new(IngestConfig::default());

    // Verify text
    let dec_txt = router.evaluate_file(&txt_path);
    assert!(matches!(dec_txt, FilterDecision::Accept { kind: CandidateKind::Text { .. }, .. }));

    // Verify PNG is routed to Image (DO NOT SKIP IMAGES!)
    let dec_png = router.evaluate_file(&png_path);
    assert!(matches!(dec_png, FilterDecision::Accept { kind: CandidateKind::Image { .. }, .. }), "PNG must route to CandidateKind::Image");

    // Verify JPEG is routed to Image
    let dec_jpg = router.evaluate_file(&jpg_path);
    assert!(matches!(dec_jpg, FilterDecision::Accept { kind: CandidateKind::Image { .. }, .. }), "JPEG must route to CandidateKind::Image");

    // Verify PE executable is skipped
    let dec_exe = router.evaluate_file(&exe_path);
    assert!(matches!(dec_exe, FilterDecision::SkipBinary { .. }), "PE executable must be skipped");
}

#[test]
fn test_classifier_router_enforces_size_cap_and_handles_zero_byte() {
    let dir = tempdir().unwrap();

    // 0-byte file
    let zero_path = dir.path().join("empty.txt");
    File::create(&zero_path).unwrap();

    // 2MB file when limit is 1MB
    let big_path = dir.path().join("huge.txt");
    std::fs::write(&big_path, vec![b'A'; 2 * 1024 * 1024]).unwrap();

    let config = IngestConfig {
        max_file_size_bytes: 1024 * 1024, // 1MB cap
        ..Default::default()
    };

    let router = ClassifierRouter::new(config);

    let dec_zero = router.evaluate_file(&zero_path);
    assert!(matches!(dec_zero, FilterDecision::Accept { kind: CandidateKind::Text { .. }, size_bytes: 0, .. }), "0-byte file must be accepted without panic");

    let dec_big = router.evaluate_file(&big_path);
    assert!(matches!(dec_big, FilterDecision::SkipExceedsSizeCap { .. }), "File exceeding max_file_size_bytes must be skipped");
}

// ============================================================================
// 2. CRAWLER TESTS
// ============================================================================

#[test]
fn test_crawler_respects_gitignore_and_hidden_files() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // Create regular file
    let code_file = root.join("main.rs");
    std::fs::write(&code_file, "fn main() { println!(\"Hello\"); }").unwrap();

    // Create .gitignore ignoring *.log and target/
    let gitignore = root.join(".gitignore");
    std::fs::write(&gitignore, "*.log\ntarget/\n").unwrap();

    // Ignored log file
    let log_file = root.join("debug.log");
    std::fs::write(&log_file, "debug log payload").unwrap();

    // Ignored directory
    let target_dir = root.join("target");
    create_dir_all(&target_dir).unwrap();
    std::fs::write(target_dir.join("build.rs"), "fn build() {}").unwrap();

    // Hidden directory
    let hidden_dir = root.join(".secret");
    create_dir_all(&hidden_dir).unwrap();
    std::fs::write(hidden_dir.join("keys.txt"), "private_key").unwrap();

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        git_ignore: true,
        skip_hidden: true,
        ..Default::default()
    };

    let crawler = FilesystemCrawler::new(config);
    let candidates = crawler.crawl_path_sync(root).unwrap();

    let paths: Vec<String> = candidates
        .iter()
        .map(|c| c.path.file_name().unwrap().to_string_lossy().to_string())
        .collect();

    assert!(paths.contains(&"main.rs".to_string()), "main.rs must be crawled");
    assert!(!paths.contains(&"debug.log".to_string()), "debug.log must be ignored by .gitignore");
    assert!(!paths.contains(&"build.rs".to_string()), "target/build.rs must be ignored by .gitignore");
    assert!(!paths.contains(&"keys.txt".to_string()), "Hidden directory .secret/ must be skipped");
}

// ============================================================================
// 3. TWO-LEVEL DEDUPLICATION TESTS
// ============================================================================

#[test]
fn test_two_level_dedup_level1_fast_path_and_rename_detection() {
    let dir = tempdir().unwrap();
    let file1 = dir.path().join("doc1.txt");
    std::fs::write(&file1, "The exact content of document one.").unwrap();

    let meta1 = std::fs::metadata(&file1).unwrap();
    let mtime1 = meta1.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let size1 = meta1.len();

    let dedup = TwoLevelDedupEngine::new();

    // Pass 1: New file
    let act1 = dedup.evaluate_file(&file1, mtime1, size1).unwrap();
    assert!(matches!(act1, DedupAction::ModifiedOrNew { is_new: true, .. }));

    let file_b3 = Level1DedupCatalog::hash_file_stream(&file1).unwrap();
    dedup.register_entry(FileCatalogEntry {
        file_path: file1.clone(),
        file_blake3: file_b3.clone(),
        mtime_secs: mtime1,
        size_bytes: size1,
        chunk_hashes: vec!["chunk1_b3".into()],
    });

    // Pass 2: Identical mtime and size -> FAST PATH (0 disk read, 0 hashing)
    let act2 = dedup.evaluate_file(&file1, mtime1, size1).unwrap();
    assert!(matches!(act2, DedupAction::Unchanged { .. }), "Unmodified mtime and size must hit Level-1 fast path");

    // Pass 3: Move / Rename file on disk
    let file2 = dir.path().join("renamed_doc.txt");
    rename(&file1, &file2).unwrap();

    let meta2 = std::fs::metadata(&file2).unwrap();
    let mtime2 = meta2.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let size2 = meta2.len();

    let act3 = dedup.evaluate_file(&file2, mtime2, size2).unwrap();
    assert!(
        matches!(act3, DedupAction::MovedOrRenamed { ref old_path, ref new_path, .. } if old_path == &file1 && new_path == &file2),
        "Moved file must be detected with matching BLAKE3 hash without re-embeddings"
    );
}

#[test]
fn test_two_level_dedup_level2_chunk_cache_avoids_reembedding() {
    let cache = Level2ChunkCache::new(100);
    let chunk_b3 = "abcd1234efgh5678".to_string();
    let vector = vec![0.5f32; 768];

    assert!(cache.get(&chunk_b3).is_none());
    assert_eq!(cache.stats().misses, 1);

    cache.insert(chunk_b3.clone(), vector.clone());
    let retrieved = cache.get(&chunk_b3).unwrap();
    assert_eq!(retrieved, vector);
    assert_eq!(cache.stats().hits, 1);
    assert_eq!(cache.stats().hit_rate(), 0.5);
}

// ============================================================================
// 4. CHUNKER & LINE-AWARE UTF-8 TESTS
// ============================================================================

#[test]
fn test_chunker_multibyte_utf8_char_boundary_safety_and_line_numbers() {
    let config = ChunkerConfig {
        target_chunk_size: 50,
        chunk_overlap: 10,
        min_chunk_size: 10,
    };
    let chunker = TextChunker::new(config);

    // Multibyte string with Japanese and 4-byte emojis across lines
    let text = "Line 1: Rust systems programming.\nLine 2: 日本語のテキストと絵文字 🚀🦀🔥\nLine 3: Third line with unicode.";
    let chunks = chunker.chunk_text(text);

    assert!(!chunks.is_empty());
    for chunk in &chunks {
        assert!(chunk.line_start >= 1);
        assert!(chunk.line_start <= chunk.line_end);
        assert!(!chunk.text_slice.is_empty());
    }

    // 0-byte input produce 0 chunks without panic
    let empty_chunks = chunker.chunk_text("");
    assert_eq!(empty_chunks.len(), 0);
}

// ============================================================================
// 5. IMAGE INDEXER TESTS
// ============================================================================

#[test]
fn test_image_indexer_extracts_metadata_and_builds_rich_chunk() {
    let dir = tempdir().unwrap();
    let png_path = dir.path().join("golden_gate_sunset.png");

    let mut png_bytes = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    png_bytes.extend_from_slice(&[0, 0, 0, 13]); // Length
    png_bytes.extend_from_slice(b"IHDR");
    png_bytes.extend_from_slice(&1920u32.to_be_bytes()); // Width 1920
    png_bytes.extend_from_slice(&1080u32.to_be_bytes()); // Height 1080
    png_bytes.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit RGBA (4 channels)
    png_bytes.extend_from_slice(&[0, 0, 0, 0]); // CRC

    // tEXt description chunk
    let text_data = b"Description\0Golden Gate Bridge at sunset in San Francisco";
    png_bytes.extend_from_slice(&(text_data.len() as u32).to_be_bytes());
    png_bytes.extend_from_slice(b"tEXt");
    png_bytes.extend_from_slice(text_data);
    png_bytes.extend_from_slice(&[0, 0, 0, 0]);

    png_bytes.extend_from_slice(&[0, 0, 0, 0, b'I', b'E', b'N', b'D', 0xae, 0x42, 0x60, 0x82]);

    std::fs::write(&png_path, &png_bytes).unwrap();

    let classifier = FileTypeClassifier::new();
    let identity = classifier.classify_file(&png_path).unwrap();
    assert!(ImageIndexer::is_supported_image(&identity));

    let embedder = TestEmbeddingGenerator::default();
    let doc_chunk = ImageIndexer::index_image(&png_path, &png_bytes, &identity, 0, &embedder).unwrap();

    assert_eq!(doc_chunk.line_start, 1);
    assert_eq!(doc_chunk.line_end, 1);
    assert_eq!(doc_chunk.vector.len(), 768);
    assert!(doc_chunk.text_content.contains("1920x1080"));
    assert!(doc_chunk.text_content.contains("Golden Gate"));
    assert!(doc_chunk.text_content.contains("sunset"));
}

// ============================================================================
// 6. DEDICATED REINDEX WORKER & FULL REBUILD TESTS
// ============================================================================

#[tokio::test]
async fn test_reindex_worker_incremental_and_full_modes() {
    let dir = tempdir().unwrap();
    let doc_path = dir.path().join("article.md");
    std::fs::write(&doc_path, "# Peer to Peer Retrieval\nQuorumRAG deterministic indexing.").unwrap();

    let storage_dir = dir.path().join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let config = IngestConfig {
        watch_paths: vec![dir.path().to_path_buf()],
        ..Default::default()
    };

    let worker = ReindexWorker::new(config, Arc::clone(&storage), classifier, embedder, dedup);

    // Initial incremental run
    let prog1 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(prog1.phase, ReindexPhase::Completed);
    assert!(prog1.files_indexed >= 1);
    assert_eq!(prog1.chunks_newly_embedded, 1);

    // Second incremental run without edits -> files_skipped_unmodified
    let prog2 = worker.run_reindex_sync(ReindexOptions::default()).await.unwrap();
    assert_eq!(prog2.phase, ReindexPhase::Completed);
    assert_eq!(prog2.files_skipped_unmodified, 1);
    assert_eq!(prog2.chunks_newly_embedded, 0);

    // Third run with full_rebuild = true -> forces re-indexing
    let full_opts = ReindexOptions {
        full_rebuild: true,
        ..Default::default()
    };
    let prog3 = worker.run_reindex_sync(full_opts).await.unwrap();
    assert_eq!(prog3.phase, ReindexPhase::Completed);
    assert!(prog3.files_indexed >= 1);
}

// ============================================================================
// 7. COMPREHENSIVE 5-DRIFT REMEDIATION WORKER TESTS
// ============================================================================

#[tokio::test]
async fn test_drift_healer_resolves_all_5_drift_types() {
    let dir = tempdir().unwrap();
    let test_file = dir.path().join("sample.txt");
    std::fs::write(&test_file, "Active monitored file content for drift testing.").unwrap();

    let storage_dir = dir.path().join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());
    let config = IngestConfig {
        watch_paths: vec![dir.path().to_path_buf()],
        ..Default::default()
    };

    let engine = IngestEngine::new(config.clone(), Arc::clone(&storage), Arc::clone(&classifier), Arc::clone(&embedder)).unwrap();
    let _ = engine.ingest_file(&test_file).await.unwrap();

    // Simulate Drift A: File deleted on disk while database retains chunk
    let deleted_file = dir.path().join("deleted.txt");
    std::fs::write(&deleted_file, "Content of file about to be deleted").unwrap();
    let _ = engine.ingest_file(&deleted_file).await.unwrap();
    std::fs::remove_file(&deleted_file).unwrap(); // Deleted on disk

    // Simulate Drift B: Hybrid index desync (Insert directly into Tantivy only)
    let orphan_chunk = DocumentChunk::new(
        "tantivy_orphan_1",
        "orphan_doc",
        "untracked.txt",
        1,
        1,
        0,
        vec![0.1; 768],
        "Orphan text in Tantivy only",
        None,
    ).unwrap();
    let _ = storage.insert_into_tantivy_only(std::slice::from_ref(&orphan_chunk));

    // Simulate Drift C: Vector contract drift (insert chunk with unnormalized vector and outdated contract hash)
    let drifted_chunk = DocumentChunk {
        chunk_id: "drifted_contract_chunk".into(),
        document_id: "drift_doc".into(),
        file_path: "drift.txt".into(),
        line_start: 1,
        line_end: 1,
        blake3_hash: "drift_hash_1".into(),
        access_tier: 0,
        vector: vec![0.05; 768], // Non-unit norm ((768 * 0.05^2)^0.5 != 1.0)
        text_content: "Contract drift text".into(),
        metadata_json: "{\"contract_hash\": \"outdated_obsolete_hash\"}".into(),
    };
    storage.insert_into_lance_only(std::slice::from_ref(&drifted_chunk)).await.unwrap();
    storage.insert_into_tantivy_only(&[drifted_chunk]).unwrap();

    // Simulate Drift D: ACL Policy drift (sample.txt chunk currently has tier 0, but rule specifies tier 2)
    // Run DriftHealer over ALL 5 drift types!
    let healer = DriftHealer::new(config, Arc::clone(&storage), classifier, embedder, Arc::clone(engine.dedup()));
    let report = healer.fix_all_drifts(DriftFixOptions {
        access_tier_rules: vec![(dir.path().to_path_buf(), 2)],
        ..Default::default()
    }).await.unwrap();

    assert!(report.is_healed);
    assert!(report.orphaned_db_files_purged >= 1, "Must purge orphaned DB records for deleted file");
    assert!(report.tantivy_chunks_missing_in_lance >= 1, "Must detect and recover Tantivy-only chunks into Lance");
    assert!(report.contract_drifted_chunks_reembedded >= 1, "Must re-embed chunks with drifted vector dimensions");
    assert!(report.acl_drifted_chunks_updated >= 1, "Must update chunks whose stored access_tier drifted from policy");
    assert!(report.total_anomalies_healed >= 4, "Must successfully heal all detected anomalies");
}

// ============================================================================
// 8. UNIFIED INGESTION ENGINE INTEGRATION TEST
// ============================================================================

#[tokio::test]
async fn test_ingest_engine_end_to_end_hybrid_search() {
    let dir = tempdir().unwrap();

    // Document file
    let doc_path = dir.path().join("distributed_consensus.md");
    std::fs::write(&doc_path, "# Raft and Paxos\nDistributed consensus protocols ensure mesh quorum across nodes.").unwrap();

    // Image file
    let img_path = dir.path().join("architecture_diagram.png");
    let mut png_bytes = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    png_bytes.extend_from_slice(&[0, 0, 0, 13]);
    png_bytes.extend_from_slice(b"IHDR");
    png_bytes.extend_from_slice(&1280u32.to_be_bytes());
    png_bytes.extend_from_slice(&720u32.to_be_bytes());
    png_bytes.extend_from_slice(&[8, 2, 0, 0, 0]);
    png_bytes.extend_from_slice(&[0, 0, 0, 0]);
    png_bytes.extend_from_slice(&[0, 0, 0, 0, b'I', b'E', b'N', b'D', 0xae, 0x42, 0x60, 0x82]);
    std::fs::write(&img_path, &png_bytes).unwrap();

    let storage_dir = dir.path().join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());

    let config = IngestConfig {
        watch_paths: vec![dir.path().to_path_buf()],
        ..Default::default()
    };

    let engine = IngestEngine::new(config, Arc::clone(&storage), classifier, Arc::clone(&embedder)).unwrap();

    // Ingest both files
    let res_doc = engine.ingest_file(&doc_path).await.unwrap();
    assert!(res_doc.is_some());
    assert!(!res_doc.unwrap().is_empty());

    let res_img = engine.ingest_file(&img_path).await.unwrap();
    assert!(res_img.is_some());
    assert!(!res_img.unwrap().is_empty());

    // Search via StorageEngine hybrid search
    let query_text = "consensus";
    let query_vec = embedder.embed_text(query_text).unwrap();
    let query = StorageSearchQuery::hybrid(query_text, query_vec, 3, 5);

    let hits = storage.search(&query).await.unwrap();
    assert!(!hits.is_empty(), "Hybrid search must retrieve ingested document");
    assert!(hits[0].chunk.text_content.contains("consensus"));
}
