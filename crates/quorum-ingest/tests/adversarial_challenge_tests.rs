//! Adversarial Empirical Challenge Test Suite for Milestone 3 (`quorum-ingest`).
//!
//! Authored by Challenger M3-1:
//! 1. Crawler edge cases: deep nesting, .gitignore exclusions, hidden files, 0-byte files, and size caps.
//! 2. Two-Level BLAKE3 Dedup:
//!    - Level 1 catalog performs 0 re-embeddings on unmodified files.
//!    - File rename/move updates stored path with 0 re-embeddings.
//!    - Level 2 chunk cache reuses cached embedding vector on identical text across files and on single-line edits.
//! 3. Image preservation: `png`, `jpeg`, `webp`, `gif`, `bmp`, `svg` preserved and indexed; `.exe` rejected.
//! 4. End-to-end storage hybrid search retrieval of image metadata and text chunks.

use std::fs::{create_dir_all, rename, File};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::tempdir;

use quorum_classifier::FileTypeClassifier;
use quorum_contract::{EmbeddingContract, EmbeddingGenerator};
use quorum_storage::{StorageConfig, StorageEngine, StorageSearchQuery};

use quorum_ingest::classifier_router::{CandidateKind, ClassifierRouter, FilterDecision};
use quorum_ingest::chunker::{ChunkerConfig, TextChunker};
use quorum_ingest::config::IngestConfig;
use quorum_ingest::crawler::FilesystemCrawler;
use quorum_ingest::engine::IngestEngine;
use quorum_ingest::image_indexer::ImageIndexer;

/// Counting embedding generator that records every call to `embed_text`.
/// Produces deterministic 768-dim L2-normalized Gemma vectors.
#[derive(Debug)]
struct CountingEmbeddingGenerator {
    contract: EmbeddingContract,
    calls: AtomicUsize,
}

impl CountingEmbeddingGenerator {
    fn new() -> Self {
        Self {
            contract: EmbeddingContract::canonical_gemma_300m(),
            calls: AtomicUsize::new(0),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn reset_count(&self) {
        self.calls.store(0, Ordering::SeqCst);
    }
}

impl EmbeddingGenerator for CountingEmbeddingGenerator {
    fn contract(&self) -> &EmbeddingContract {
        &self.contract
    }

    fn embed_text(&self, text: &str) -> Result<Vec<f32>, quorum_contract::ContractError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
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

// ============================================================================
// 1. CRAWLER EDGE CASES: NESTED DIRS, .GITIGNORE, HIDDEN FILES, 0-BYTE & SIZE CAP
// ============================================================================

#[test]
fn test_adversarial_crawler_nested_and_gitignore_and_hidden() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // 1. Deeply nested directories (5 levels)
    let deep_dir = root.join("lvl1").join("lvl2").join("lvl3").join("lvl4").join("lvl5");
    create_dir_all(&deep_dir).unwrap();
    let deep_file = deep_dir.join("deeply_nested_document.txt");
    std::fs::write(&deep_file, "Deeply nested file content").unwrap();

    // 2. Normal file
    let normal_file = root.join("regular_notes.md");
    std::fs::write(&normal_file, "# Regular markdown notes").unwrap();

    // 3. .gitignore file with directory and pattern exclusions
    let gitignore = root.join(".gitignore");
    std::fs::write(
        &gitignore,
        "*.tmp\n*.log\nbuild_artifacts/\nnode_modules/\n",
    )
    .unwrap();

    // Ignored by pattern
    let tmp_file = root.join("scratch.tmp");
    std::fs::write(&tmp_file, "temporary scratch data").unwrap();
    let log_file = root.join("errors.log");
    std::fs::write(&log_file, "error log data").unwrap();

    // Ignored directory
    let build_dir = root.join("build_artifacts");
    create_dir_all(&build_dir).unwrap();
    std::fs::write(build_dir.join("binary.bin"), "compiled object").unwrap();

    // 4. Hidden directories and hidden files
    let hidden_dir = root.join(".git_hidden");
    create_dir_all(&hidden_dir).unwrap();
    std::fs::write(hidden_dir.join("secret_config.ini"), "secret=true").unwrap();

    let hidden_file = root.join(".dotfile_env");
    std::fs::write(&hidden_file, "ENV=production").unwrap();

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        git_ignore: true,
        skip_hidden: true,
        ..Default::default()
    };

    let crawler = FilesystemCrawler::new(config);
    let candidates = crawler.crawl_path_sync(root).unwrap();

    let discovered_names: Vec<String> = candidates
        .iter()
        .map(|c| c.path.file_name().unwrap().to_string_lossy().to_string())
        .collect();

    // Assertions
    assert!(
        discovered_names.contains(&"deeply_nested_document.txt".to_string()),
        "Crawler must reach 5 levels deep into nested directories"
    );
    assert!(
        discovered_names.contains(&"regular_notes.md".to_string()),
        "Crawler must include regular files"
    );
    assert!(
        !discovered_names.contains(&"scratch.tmp".to_string()),
        ".gitignore *.tmp must be excluded"
    );
    assert!(
        !discovered_names.contains(&"errors.log".to_string()),
        ".gitignore *.log must be excluded"
    );
    assert!(
        !discovered_names.contains(&"binary.bin".to_string()),
        ".gitignore build_artifacts/ directory must be excluded"
    );
    assert!(
        !discovered_names.contains(&"secret_config.ini".to_string()),
        "Hidden directory .git_hidden must be excluded when skip_hidden is true"
    );
    assert!(
        !discovered_names.contains(&".dotfile_env".to_string()),
        "Hidden file .dotfile_env must be excluded when skip_hidden is true"
    );
}

#[tokio::test]
async fn test_adversarial_zero_byte_and_size_caps() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // 1. 0-byte file
    let zero_file = root.join("empty_file.txt");
    File::create(&zero_file).unwrap();

    // 2. Exact size cap test
    let cap_limit = 50 * 1024; // 50 KB cap for this test
    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        max_file_size_bytes: cap_limit,
        ..Default::default()
    };

    let router = ClassifierRouter::new(config.clone());

    // Evaluate 0-byte file: must be accepted as text with size 0
    let dec_zero = router.evaluate_file(&zero_file);
    assert!(
        matches!(dec_zero, FilterDecision::Accept { kind: CandidateKind::Text { .. }, size_bytes: 0, .. }),
        "0-byte file must be accepted with 0 size bytes"
    );

    // Chunker on 0-byte content returns empty vector
    let chunker = TextChunker::new(ChunkerConfig::default());
    let chunks = chunker.chunk_text("");
    assert!(chunks.is_empty(), "Chunker on empty string must produce 0 chunks without panic");

    // Exact cap file: 50 * 1024 bytes
    let exact_cap_file = root.join("exact_cap.txt");
    {
        let mut f = File::create(&exact_cap_file).unwrap();
        f.write_all(&vec![b'A'; cap_limit as usize]).unwrap();
    }
    let dec_exact = router.evaluate_file(&exact_cap_file);
    assert!(
        matches!(dec_exact, FilterDecision::Accept { size_bytes, .. } if size_bytes == cap_limit),
        "File exactly matching max_file_size_bytes must be accepted"
    );

    // Exceeding cap file: 50 * 1024 + 1 bytes
    let over_cap_file = root.join("over_cap.txt");
    {
        let mut f = File::create(&over_cap_file).unwrap();
        f.write_all(&vec![b'A'; (cap_limit + 1) as usize]).unwrap();
    }
    let dec_over = router.evaluate_file(&over_cap_file);
    assert!(
        matches!(dec_over, FilterDecision::SkipExceedsSizeCap { size_bytes, max_bytes } if size_bytes == cap_limit + 1 && max_bytes == cap_limit),
        "File exceeding max_file_size_bytes by 1 byte must be skipped"
    );

    // Confirm default IngestConfig has 50MB size cap
    let default_config = IngestConfig::default();
    assert_eq!(
        default_config.max_file_size_bytes,
        50 * 1024 * 1024,
        "Default IngestConfig must enforce 50MB size cap"
    );
}

// ============================================================================
// 2. TWO-LEVEL BLAKE3 DEDUP: LEVEL 1 (0 RE-EMBEDS ON UNMODIFIED & RENAME/MOVE)
// ============================================================================

#[tokio::test]
async fn test_adversarial_dedup_level1_zero_reembeddings_unmodified_and_rename() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let storage_dir = root.join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder = Arc::new(CountingEmbeddingGenerator::new());

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        ..Default::default()
    };

    let engine = IngestEngine::new(
        config,
        Arc::clone(&storage),
        Arc::clone(&classifier),
        embedder.clone(),
    )
    .unwrap();

    let file_path = root.join("immutable_spec.txt");
    std::fs::write(
        &file_path,
        "System architecture specification: LanceDB vector store with co-located Tantivy index.",
    )
    .unwrap();

    // 1. Initial Ingestion
    embedder.reset_count();
    let res1 = engine.ingest_file(&file_path).await.unwrap();
    assert!(res1.is_some());
    let chunks1 = res1.unwrap();
    assert_eq!(chunks1.len(), 1);
    assert_eq!(embedder.call_count(), 1, "Initial ingest must compute 1 embedding");

    // 2. Re-ingest unmodified file -> LEVEL 1 FAST PATH
    let res2 = engine.ingest_file(&file_path).await.unwrap();
    assert!(res2.is_some());
    let chunks2 = res2.unwrap();
    assert!(
        chunks2.is_empty(),
        "Level 1 fast-path must return empty vector for unmodified file"
    );
    assert_eq!(
        embedder.call_count(),
        1,
        "Level 1 catalog must perform ZERO new embedding calculations on unmodified file"
    );

    // 3. Rename/Move file on disk
    let moved_path = root.join("renamed_spec.txt");
    rename(&file_path, &moved_path).unwrap();

    // Ingest moved file under new path
    let res3 = engine.ingest_file(&moved_path).await.unwrap();
    assert!(res3.is_some());
    let chunks3 = res3.unwrap();
    assert!(
        chunks3.is_empty(),
        "Level 1 rename detection must return empty vector for moved file"
    );
    assert_eq!(
        embedder.call_count(),
        1,
        "Renaming/moving file must update stored path with ZERO new embedding calculations"
    );

    // Verify catalog has updated path
    let tracked_entry = engine.dedup().get_file_entry(&moved_path);
    assert!(tracked_entry.is_some(), "Catalog must record the new file path");
    assert_eq!(tracked_entry.unwrap().file_path, moved_path);
}

// ============================================================================
// 3. TWO-LEVEL BLAKE3 DEDUP: LEVEL 2 CHUNK CACHE REUSE ACROSS FILES & SINGLE-LINE EDITS
// ============================================================================

#[tokio::test]
async fn test_adversarial_dedup_level2_chunk_cache_across_files() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let storage_dir = root.join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder = Arc::new(CountingEmbeddingGenerator::new());

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        ..Default::default()
    };

    let engine = IngestEngine::new(
        config,
        Arc::clone(&storage),
        Arc::clone(&classifier),
        embedder.clone(),
    )
    .unwrap();

    let shared_chunk = "S".repeat(600);
    let file1_unique = "1".repeat(600);
    let file2_unique = "2".repeat(600);

    // File 1 has unique chunk 1 + shared chunk
    let file1 = root.join("module_a.txt");
    std::fs::write(&file1, format!("{}{}", file1_unique, shared_chunk)).unwrap();

    // File 2 has unique chunk 2 + identical shared chunk
    let file2 = root.join("module_b.txt");
    std::fs::write(&file2, format!("{}{}", file2_unique, shared_chunk)).unwrap();

    embedder.reset_count();

    // Ingest File 1: produces 3 chunks (500-char target with 100-char overlap)
    let res1 = engine.ingest_file(&file1).await.unwrap();
    assert!(res1.is_some());
    let chunks1 = res1.unwrap();
    let count1 = embedder.call_count();
    assert_eq!(chunks1.len(), 3, "File 1 should produce 3 chunks");
    assert_eq!(count1, 3, "File 1 should compute 3 embeddings");

    // Ingest File 2: has 3 chunks. The shared tail chunk is recognized -> reused from Level 2 cache!
    let res2 = engine.ingest_file(&file2).await.unwrap();
    assert!(res2.is_some());
    let chunks2 = res2.unwrap();
    assert_eq!(chunks2.len(), 3, "File 2 should produce 3 chunks");

    // File 2 must compute only 2 new embeddings, reusing the shared chunk from Level 2 cache!
    let count2 = embedder.call_count() - count1;
    assert_eq!(
        count2, 2,
        "Level 2 chunk cache must reuse cached vector for shared chunk across distinct files (new embeddings={}, expected=2)",
        count2
    );

    // Verify chunk cache hit rate is positive
    let stats = engine.dedup().cache().stats();
    assert!(stats.hits >= 1, "Level 2 chunk cache must register hit for duplicate chunk text");
}

#[tokio::test]
async fn test_adversarial_dedup_level2_single_line_edit_partial_chunk_reuse() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let storage_dir = root.join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder = Arc::new(CountingEmbeddingGenerator::new());

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        ..Default::default()
    };

    let engine = IngestEngine::new(
        config,
        Arc::clone(&storage),
        Arc::clone(&classifier),
        embedder.clone(),
    )
    .unwrap();

    let p1 = "A".repeat(600);
    let p2_orig = "B".repeat(600);
    let p2_edited = "C".repeat(600);
    let p3 = "D".repeat(600);

    let file_path = root.join("document_multi_chunk.txt");

    // Version 1: multiple chunks
    std::fs::write(&file_path, format!("{}{}{}", p1, p2_orig, p3)).unwrap();

    embedder.reset_count();
    let res1 = engine.ingest_file(&file_path).await.unwrap();
    assert!(res1.is_some());
    let initial_computed = embedder.call_count();
    assert!(initial_computed >= 3, "Expected at least 3 initial chunks");

    // Version 2: Modify ONLY chunk 2, keeping chunk 1 and chunk 3 identical
    std::fs::write(&file_path, format!("{}{}{}", p1, p2_edited, p3)).unwrap();

    // Re-ingest edited file
    let res2 = engine.ingest_file(&file_path).await.unwrap();
    assert!(res2.is_some());
    let additional_computed = embedder.call_count() - initial_computed;

    assert!(
        additional_computed < initial_computed,
        "Single-line edit must reuse unchanged chunks via Level-2 BLAKE3 cache (recomputed={}, initial={})",
        additional_computed,
        initial_computed
    );
}

// ============================================================================
// 4. IMAGE PRESERVATION & INDEXING (PNG, JPEG, WEBP, GIF, BMP, SVG) VS EXE REJECTION
// ============================================================================

#[tokio::test]
async fn test_adversarial_image_formats_preserved_and_indexed() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let router = ClassifierRouter::new(IngestConfig::default());
    let embedder = CountingEmbeddingGenerator::new();

    // 1. PNG Image
    let png_path = root.join("test_image.png");
    let mut png_bytes = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    png_bytes.extend_from_slice(&[0, 0, 0, 13]);
    png_bytes.extend_from_slice(b"IHDR");
    png_bytes.extend_from_slice(&1920u32.to_be_bytes()); // Width 1920
    png_bytes.extend_from_slice(&1080u32.to_be_bytes()); // Height 1080
    png_bytes.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit RGB
    png_bytes.extend_from_slice(&[0, 0, 0, 0]);
    png_bytes.extend_from_slice(&[0, 0, 0, 0, b'I', b'E', b'N', b'D', 0xae, 0x42, 0x60, 0x82]);
    std::fs::write(&png_path, &png_bytes).unwrap();

    let dec_png = router.evaluate_file(&png_path);
    assert!(
        matches!(dec_png, FilterDecision::Accept { kind: CandidateKind::Image { .. }, .. }),
        "PNG image must route to CandidateKind::Image"
    );

    // 2. JPEG Image
    let jpg_path = root.join("test_image.jpg");
    let mut jpg_bytes = vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0, 1, 1, 0, 0, 1, 0, 1, 0, 0];
    jpg_bytes.extend_from_slice(&[0xff, 0xc0, 0x00, 0x11, 0x08]); // SOF0
    jpg_bytes.extend_from_slice(&720u16.to_be_bytes()); // Height 720
    jpg_bytes.extend_from_slice(&1280u16.to_be_bytes()); // Width 1280
    jpg_bytes.push(3);
    jpg_bytes.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0]);
    std::fs::write(&jpg_path, &jpg_bytes).unwrap();

    let dec_jpg = router.evaluate_file(&jpg_path);
    assert!(
        matches!(dec_jpg, FilterDecision::Accept { kind: CandidateKind::Image { .. }, .. }),
        "JPEG image must route to CandidateKind::Image"
    );

    // 3. WebP Image
    let webp_path = root.join("test_image.webp");
    let mut webp_bytes = b"RIFF\x20\x00\x00\x00WEBPVP8 \x14\x00\x00\x00\x00\x00\x00\x9d\x01\x2a".to_vec();
    // 640 x 480 VP8 dimensions
    webp_bytes.extend_from_slice(&640u16.to_le_bytes());
    webp_bytes.extend_from_slice(&480u16.to_le_bytes());
    std::fs::write(&webp_path, &webp_bytes).unwrap();

    let dec_webp = router.evaluate_file(&webp_path);
    assert!(
        matches!(dec_webp, FilterDecision::Accept { kind: CandidateKind::Image { .. }, .. }),
        "WebP image must route to CandidateKind::Image"
    );

    // 4. GIF Image
    let gif_path = root.join("test_image.gif");
    let mut gif_bytes = b"GIF89a".to_vec();
    gif_bytes.extend_from_slice(&320u16.to_le_bytes()); // Width 320
    gif_bytes.extend_from_slice(&240u16.to_le_bytes()); // Height 240
    gif_bytes.extend_from_slice(&[0x80, 0x00, 0x00]);
    std::fs::write(&gif_path, &gif_bytes).unwrap();

    let dec_gif = router.evaluate_file(&gif_path);
    assert!(
        matches!(dec_gif, FilterDecision::Accept { kind: CandidateKind::Image { .. }, .. }),
        "GIF image must route to CandidateKind::Image"
    );

    // 5. BMP Image
    let bmp_path = root.join("test_image.bmp");
    let mut bmp_bytes = b"BM".to_vec();
    bmp_bytes.extend_from_slice(&[0u8; 12]);
    bmp_bytes.extend_from_slice(&40u32.to_le_bytes()); // DIB header size
    bmp_bytes.extend_from_slice(&400i32.to_le_bytes()); // Width 400
    bmp_bytes.extend_from_slice(&300i32.to_le_bytes()); // Height 300
    bmp_bytes.extend_from_slice(&1u16.to_le_bytes()); // Planes 1
    bmp_bytes.extend_from_slice(&24u16.to_le_bytes()); // 24-bit
    bmp_bytes.extend_from_slice(&[0u8; 16]);
    std::fs::write(&bmp_path, &bmp_bytes).unwrap();

    let dec_bmp = router.evaluate_file(&bmp_path);
    assert!(
        matches!(dec_bmp, FilterDecision::Accept { kind: CandidateKind::Image { .. }, .. }),
        "BMP image must route to CandidateKind::Image"
    );

    // 6. SVG Vector Graphic with XML prolog
    let svg_path = root.join("system_architecture.svg");
    let svg_content = r#"<?xml version="1.0" encoding="UTF-8"?>
    <svg width="1024" height="768" xmlns="http://www.w3.org/2000/svg">
        <title>QuorumRAG Mesh Diagram</title>
        <desc>Decentralized peer to peer query coordinator topology</desc>
        <text x="50" y="50">Vector Ingestion Pipeline</text>
    </svg>"#;
    std::fs::write(&svg_path, svg_content).unwrap();

    let dec_svg = router.evaluate_file(&svg_path);
    assert!(
        matches!(dec_svg, FilterDecision::Accept { kind: CandidateKind::Image { .. }, .. }),
        "SVG image with XML prolog must route to CandidateKind::Image"
    );

    // Index SVG via ImageIndexer and verify text extraction
    let classifier = FileTypeClassifier::new();
    let svg_id = classifier.classify_file(&svg_path).unwrap();
    let svg_chunk = ImageIndexer::index_image(&svg_path, svg_content.as_bytes(), &svg_id, 0, &embedder).unwrap();

    assert_eq!(svg_chunk.vector.len(), 768);
    assert!(svg_chunk.text_content.contains("QuorumRAG Mesh Diagram"));
    assert!(svg_chunk.text_content.contains("Vector Ingestion Pipeline"));
    assert!(svg_chunk.text_content.contains("1024x768"));
}

#[test]
fn test_adversarial_image_formats_standalone_svg_without_xml_prolog_differential() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let router = ClassifierRouter::new(IngestConfig::default());

    // Standalone SVG without XML prolog (typical modern export from web tools/Figma)
    let standalone_svg_path = root.join("standalone.svg");
    let standalone_content = r#"<svg width="800" height="600" xmlns="http://www.w3.org/2000/svg">
        <text>Standalone Vector Graphic</text>
    </svg>"#;
    std::fs::write(&standalone_svg_path, standalone_content).unwrap();

    let decision = router.evaluate_file(&standalone_svg_path);
    // Observe: Classifier router skips standalone SVG as binary because inspect_text_content only checks <?xml!
    // This is documented as Finding M3-CHALLENGE-1 in handoff.md.
    let is_accepted = matches!(decision, FilterDecision::Accept { kind: CandidateKind::Image { .. }, .. });
    eprintln!("[OBSERVATION] Standalone SVG without <?xml accepted as Image: {}", is_accepted);
}

#[test]
fn test_adversarial_executable_rejection_pe_elf_macho_wasm() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let router = ClassifierRouter::new(IngestConfig::default());

    // 1. Windows PE .exe
    let exe_path = root.join("daemon_worker.exe");
    std::fs::write(&exe_path, b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00").unwrap();
    let dec_exe = router.evaluate_file(&exe_path);
    assert!(
        matches!(dec_exe, FilterDecision::SkipBinary { .. }),
        "Windows PE executable must be skipped"
    );

    // 2. Linux ELF binary
    let elf_path = root.join("compiled_service.elf");
    std::fs::write(&elf_path, b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00").unwrap();
    let dec_elf = router.evaluate_file(&elf_path);
    assert!(
        matches!(dec_elf, FilterDecision::SkipBinary { .. }),
        "Linux ELF executable must be skipped"
    );

    // 3. WebAssembly module
    let wasm_path = root.join("runtime.wasm");
    std::fs::write(&wasm_path, b"\x00asm\x01\x00\x00\x00\x01\x04\x01\x60\x00\x00").unwrap();
    let dec_wasm = router.evaluate_file(&wasm_path);
    assert!(
        matches!(dec_wasm, FilterDecision::SkipBinary { .. }),
        "WebAssembly binary must be skipped"
    );
}

// ============================================================================
// 5. END-TO-END STORAGE RETRIEVAL OF IMAGE METADATA & TEXT VIA INGEST ENGINE
// ============================================================================

#[tokio::test]
async fn test_adversarial_ingest_engine_end_to_end_image_and_text_search() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let storage_dir = root.join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder = Arc::new(CountingEmbeddingGenerator::new());

    let config = IngestConfig {
        watch_paths: vec![root.to_path_buf()],
        ..Default::default()
    };

    let engine = IngestEngine::new(
        config,
        Arc::clone(&storage),
        Arc::clone(&classifier),
        embedder.clone(),
    )
    .unwrap();

    // Ingest text document
    let text_path = root.join("distributed_raft.md");
    std::fs::write(
        &text_path,
        "# Raft Consensus Protocol\nDeterministic leader election and log replication in distributed swarms.",
    )
    .unwrap();
    let res_text = engine.ingest_file(&text_path).await.unwrap();
    assert!(res_text.is_some());
    assert!(!res_text.unwrap().is_empty());

    // Ingest SVG image diagram
    let svg_path = root.join("consensus_state_diagram.svg");
    let svg_content = r#"<?xml version="1.0" encoding="UTF-8"?>
    <svg width="800" height="600" xmlns="http://www.w3.org/2000/svg">
        <title>Consensus State Machine</title>
        <desc>Leader Follower Candidate transitions</desc>
        <text x="100" y="100">Raft Quorum Heartbeat</text>
    </svg>"#;
    std::fs::write(&svg_path, svg_content).unwrap();
    let res_svg = engine.ingest_file(&svg_path).await.unwrap();
    assert!(res_svg.is_some());
    assert!(!res_svg.unwrap().is_empty());

    // Ingest .exe (must be rejected)
    let exe_path = root.join("malicious.exe");
    std::fs::write(&exe_path, b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff").unwrap();
    let res_exe = engine.ingest_file(&exe_path).await.unwrap();
    assert!(res_exe.is_none(), "Executable must produce None and be skipped");

    // Perform hybrid search for "Heartbeat" (which appears in the SVG diagram!)
    let query_text = "Heartbeat";
    let query_vec = embedder.embed_text(query_text).unwrap();
    let query = StorageSearchQuery::hybrid(query_text, query_vec, 3, 5);

    let hits = storage.search(&query).await.unwrap();
    assert!(!hits.is_empty(), "Search must retrieve ingested SVG image chunk");
    assert!(
        hits.iter().any(|h| h.chunk.text_content.contains("Raft Quorum Heartbeat")),
        "Retrieved chunk must contain text extracted from SVG image"
    );
}
