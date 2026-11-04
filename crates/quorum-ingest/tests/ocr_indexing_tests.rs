//! Non-mocked End-to-End Integration Tests for Ingest-Time Real OCR & Scanned PDF Fallback.
//!
//! Covers:
//! 1. Raster image with synthetic CVE identifier (`CVE-2026-99137`) rendered to pixels with
//!    an unrelated filename, indexed through the full IngestEngine pipeline and retrieved via Tantivy BM25.
//! 2. Scanned / image-only PDF (0 text stream layer) with embedded CVE image, verified for
//!    automatic OCR fallback and full-text keyword retrieval.
//! 3. Legacy image chunk upgrade via ReindexWorker, verifying that image chunks lacking `[OCR Text]`
//!    are upgraded in-place preserving the exact chunk ID `{file_b3}:img:0` without re-downloading.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use tempfile::tempdir;

use quorum_classifier::FileTypeClassifier;
use quorum_contract::{EmbeddingContract, EmbeddingGenerator};
use quorum_storage::{StorageConfig, StorageEngine, StorageSearchQuery};
use quorum_types::DocumentChunk;

use quorum_ingest::config::IngestConfig;
use quorum_ingest::dedup::TwoLevelDedupEngine;
use quorum_ingest::document_extractor::DocumentExtractor;
use quorum_ingest::engine::IngestEngine;
use quorum_ingest::reindex::ReindexWorker;

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

/// Generates a crisp raster PNG image with text rendered onto pixels
/// without external GUI tools or FreeType dependencies.
fn generate_cve_raster_image(path: &Path, text: &str) -> std::io::Result<()> {
    let escaped_path = path.to_string_lossy().replace('\\', "/");
    let script = format!(
        "from PIL import Image, ImageDraw\n\
         img = Image.new('RGB', (600, 50), (255, 255, 255))\n\
         d = ImageDraw.Draw(img)\n\
         d.text((10, 15), '{}', fill=(0, 0, 0))\n\
         scaled = img.resize((1800, 150), Image.NEAREST)\n\
         scaled.save('{}')\n",
        text, escaped_path
    );

    let output = Command::new("python").arg("-c").arg(&script).output()?;

    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "Failed to generate synthetic PNG: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

/// Generates a scanned single-page PDF containing ONLY a raster image and 0 text stream.
fn generate_scanned_cve_pdf(path: &Path, text: &str) -> std::io::Result<()> {
    let temp_png = path.with_extension("temp.png");
    generate_cve_raster_image(&temp_png, text)?;

    let escaped_png = temp_png.to_string_lossy().replace('\\', "/");
    let escaped_pdf = path.to_string_lossy().replace('\\', "/");

    let script = format!(
        "from PIL import Image\n\
         img = Image.open('{}')\n\
         img.save('{}', 'PDF')\n",
        escaped_png, escaped_pdf
    );

    let output = Command::new("python").arg("-c").arg(&script).output()?;

    let _ = std::fs::remove_file(&temp_png);

    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "Failed to generate scanned PDF: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

/// Generates a multi-page scanned PDF containing ONLY raster images on each page.
fn generate_multi_page_scanned_pdf(path: &Path, pages: &[&str]) -> std::io::Result<()> {
    let mut temp_pngs = Vec::new();
    for (i, text) in pages.iter().enumerate() {
        let temp_png = path.with_extension(format!("temp_page_{}.png", i));
        generate_cve_raster_image(&temp_png, text)?;
        temp_pngs.push(temp_png);
    }

    let escaped_pdf = path.to_string_lossy().replace('\\', "/");
    let png_paths: Vec<String> = temp_pngs
        .iter()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .collect();
    let png_paths_json = format!("[\"{}\"]", png_paths.join("\",\""));

    let script = format!(
        "from PIL import Image\n\
         paths = {}\n\
         images = [Image.open(p) for p in paths]\n\
         first = images[0]\n\
         rest = images[1:] if len(images) > 1 else []\n\
         first.save('{}', 'PDF', save_all=True, append_images=rest)\n",
        png_paths_json, escaped_pdf
    );

    let output = Command::new("python").arg("-c").arg(&script).output()?;

    for temp_png in &temp_pngs {
        let _ = std::fs::remove_file(temp_png);
    }

    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "Failed to generate multi-page scanned PDF: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

#[tokio::test]
async fn test_raster_image_cve_ingest_and_retrieval() {
    let dir = tempdir().unwrap();
    let img_path = dir.path().join("screenshot_8472.png");

    // Generate real synthetic image with CVE-2026-99137 in pixels
    generate_cve_raster_image(
        &img_path,
        "CVE-2026-99137 Critical Remote Code Execution",
    )
    .expect("generate test image");

    let storage_dir = dir.path().join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());

    let config = IngestConfig {
        watch_paths: vec![dir.path().to_path_buf()],
        ..Default::default()
    };

    let engine = IngestEngine::new(config, Arc::clone(&storage), classifier, Arc::clone(&embedder)).unwrap();

    // Ingest the image file
    let chunks = engine.ingest_file(&img_path).await.unwrap();
    assert!(chunks.is_some(), "Image must produce indexed chunks");
    let chunk_list = chunks.unwrap();
    assert_eq!(chunk_list.len(), 1);
    assert!(
        chunk_list[0].text_content.contains("CVE-2026-99137"),
        "Chunk text must contain CVE identifier. Got: {}",
        chunk_list[0].text_content
    );
    assert!(
        chunk_list[0].text_content.contains("[OCR Text]"),
        "Chunk text must contain [OCR Text] marker"
    );

    // BM25 Keyword Search for the CVE string
    let query = StorageSearchQuery::keyword("CVE-2026-99137", 3, 5);
    let hits = storage.search(&query).await.unwrap();

    assert!(
        !hits.is_empty(),
        "Search for CVE-2026-99137 must retrieve the image chunk"
    );
    assert_eq!(hits[0].chunk.file_path, img_path.to_string_lossy());
    assert!(hits[0].chunk.text_content.contains("CVE-2026-99137"));
}

#[tokio::test]
async fn test_scanned_pdf_cve_fallback_and_retrieval() {
    let dir = tempdir().unwrap();
    let pdf_path = dir.path().join("scan_doc_99137.pdf");

    // Generate scanned PDF with 0 text layer and embedded CVE image
    generate_scanned_cve_pdf(
        &pdf_path,
        "CVE-2026-99137 Critical Remote Code Execution",
    )
    .expect("generate scanned pdf");

    let storage_dir = dir.path().join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());

    let config = IngestConfig {
        watch_paths: vec![dir.path().to_path_buf()],
        ..Default::default()
    };

    let engine = IngestEngine::new(config, Arc::clone(&storage), classifier, Arc::clone(&embedder)).unwrap();

    // Ingest scanned PDF
    let chunks = engine.ingest_file(&pdf_path).await.unwrap();
    assert!(chunks.is_some(), "Scanned PDF must produce indexed chunks");
    let chunk_list = chunks.unwrap();
    assert!(!chunk_list.is_empty());
    assert!(
        chunk_list[0].text_content.contains("CVE-2026-99137"),
        "Scanned PDF chunk must contain CVE. Got: {}",
        chunk_list[0].text_content
    );
    assert!(
        chunk_list[0].text_content.contains("[Scanned PDF — OCR Extracted Text]"),
        "Scanned PDF chunk must contain scanned marker"
    );

    // Keyword Search
    let query = StorageSearchQuery::keyword("CVE-2026-99137", 3, 5);
    let hits = storage.search(&query).await.unwrap();

    assert!(
        !hits.is_empty(),
        "Search for CVE-2026-99137 must retrieve the scanned PDF chunk"
    );
    assert_eq!(hits[0].chunk.file_path, pdf_path.to_string_lossy());
}

#[tokio::test]
async fn test_legacy_image_chunk_upgrade_without_corrupting_id() {
    let dir = tempdir().unwrap();
    let img_path = dir.path().join("legacy_screenshot.png");

    generate_cve_raster_image(
        &img_path,
        "CVE-2026-99137 Critical Remote Code Execution",
    )
    .unwrap();

    let storage_dir = dir.path().join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());

    let bytes = std::fs::read(&img_path).unwrap();
    let file_b3 = blake3::hash(&bytes).to_hex().to_string();
    let legacy_chunk_id = format!("{}:img:0", file_b3);

    // Manually insert legacy chunk lacking OCR
    let legacy_chunk = DocumentChunk::new(
        legacy_chunk_id.clone(),
        file_b3.clone(),
        img_path.to_string_lossy().to_string(),
        1,
        1,
        0,
        vec![0.01; 768],
        "[Image Document: legacy_screenshot.png]\nFormat: PNG (image/png)\nResolution: 1800x150 pixels",
        Some("{\"mime_type\":\"image/png\",\"visual_description\":null}".into()),
    )
    .unwrap();

    storage.insert_chunks(&[legacy_chunk]).await.unwrap();

    // Verify search returns 0 hits before upgrade
    let query = StorageSearchQuery::keyword("CVE-2026-99137", 3, 5);
    let hits_before = storage.search(&query).await.unwrap();
    assert!(
        hits_before.is_empty(),
        "Legacy chunk without OCR must return 0 hits for CVE"
    );

    // Run upgrade
    let config = IngestConfig {
        watch_paths: vec![dir.path().to_path_buf()],
        ..Default::default()
    };
    let dedup = Arc::new(TwoLevelDedupEngine::new());
    let worker = ReindexWorker::new(config, Arc::clone(&storage), classifier, embedder, dedup);
    let upgraded_count = worker.upgrade_legacy_image_chunks().await.unwrap();

    assert_eq!(upgraded_count, 1, "Must upgrade exactly 1 legacy image chunk");

    // Verify chunk ID is strictly preserved
    let all_chunks = storage.scan_all_chunks().await.unwrap();
    assert_eq!(all_chunks.len(), 1, "Must replace, not duplicate chunk");
    assert_eq!(all_chunks[0].chunk_id, legacy_chunk_id, "Chunk ID must be preserved");
    assert_eq!(all_chunks[0].document_id, file_b3, "Document ID must be preserved");

    // Verify search now retrieves the chunk
    let hits_after = storage.search(&query).await.unwrap();
    assert_eq!(hits_after.len(), 1, "Search must retrieve upgraded chunk");
    assert!(hits_after[0].chunk.text_content.contains("CVE-2026-99137"));
    assert!(hits_after[0].chunk.text_content.contains("[OCR Text]"));
}

#[test]
fn test_adversarial_scanned_pdf_heuristic_boundaries() {
    // Challenge 1: Scanned PDF detection heuristic is_scanned_or_insufficient_text
    // Case 1: Scanner metadata header only, < 10 alnum body characters
    let scan_meta_only = "[PDF Metadata] Producer: Xerox AltaLink C8055 | Author: Anonymous | CreationDate: D:20261104";
    assert!(
        DocumentExtractor::is_scanned_or_insufficient_text(scan_meta_only),
        "PDF with only scanner metadata headers must trigger OCR fallback"
    );

    // Case 2: Scanner metadata + short watermark (< 10 alnum chars)
    let scan_meta_short_body = "[PDF Metadata] Producer: HP ScanJet Pro 3500\n\nPage 1\n";
    assert!(
        DocumentExtractor::is_scanned_or_insufficient_text(scan_meta_short_body),
        "PDF with scanner metadata and < 10 alnum body chars ('Page 1') must trigger OCR fallback"
    );

    // Case 3: Multiple indented metadata lines + exactly 9 alnum body chars
    let scan_meta_9_chars = "  [PDF Metadata] Producer: Canon imageRUNNER\n  [PDF Metadata] ModDate: 2026\n 1 2 3 4 5 6 7 8 9 ";
    assert!(
        DocumentExtractor::is_scanned_or_insufficient_text(scan_meta_9_chars),
        "PDF with metadata and exactly 9 alnum body chars must trigger OCR fallback"
    );

    // Case 4: Empty, whitespace, punctuation only
    assert!(DocumentExtractor::is_scanned_or_insufficient_text(""));
    assert!(DocumentExtractor::is_scanned_or_insufficient_text("   \n\t  \r  "));
    assert!(DocumentExtractor::is_scanned_or_insufficient_text("--- === *** ... ,,, ;;; !!! ???"));

    // Case 5: Scanner metadata + exactly 10 alnum body chars (boundary: >= 10 must bypass OCR)
    let doc_meta_10_chars = "[PDF Metadata] Producer: Xerox Corporation\n\n0123456789";
    assert!(
        !DocumentExtractor::is_scanned_or_insufficient_text(doc_meta_10_chars),
        "PDF with >= 10 alnum body chars must NOT trigger OCR fallback (bypasses OCR immediately)"
    );

    // Case 6: Standard document text with prose
    let normal_doc = "[PDF Metadata] Producer: Xerox Corporation\n\nThis incident report describes the patch applied to all cluster nodes.";
    assert!(
        !DocumentExtractor::is_scanned_or_insufficient_text(normal_doc),
        "Standard document prose must bypass OCR immediately"
    );

    // Case 7: Text without metadata, >= 10 alnum chars
    let plain_doc = "Rust memory safety invariants are guaranteed at compile time.";
    assert!(
        !DocumentExtractor::is_scanned_or_insufficient_text(plain_doc),
        "Plain text without metadata must bypass OCR"
    );

    // Case 8: Text without metadata, exactly 9 alnum chars (< 10)
    let short_plain_doc = "ABC 123 45";
    assert!(
        DocumentExtractor::is_scanned_or_insufficient_text(short_plain_doc),
        "Short text with < 10 alnum chars must trigger OCR"
    );

    // Case 9: Multilingual / Non-ASCII alphanumeric characters (CJK)
    let cjk_doc = "[PDF Metadata] Producer: Xerox\n\n日本語のドキュメントです。十分な文字数があります。";
    assert!(
        !DocumentExtractor::is_scanned_or_insufficient_text(cjk_doc),
        "Unicode CJK characters must be counted as alphanumeric and bypass OCR"
    );
}

#[tokio::test]
async fn test_adversarial_scanned_multipage_pdf_ordering() {
    // Challenge 2: Scanned multi-page PDF image extraction and ordering.
    // Verify pages are output in strictly ascending order:
    // [Scanned PDF — OCR Extracted Text]\n\nPage 1:\n...\n\nPage 2:\n...
    let dir = tempdir().unwrap();
    let pdf_path = dir.path().join("multipage_scanned_audit.pdf");

    let page1_text = "CVE-2026-10001 First Page Incident";
    let page2_text = "CVE-2026-20002 Second Page Exploitation";
    let page3_text = "CVE-2026-30003 Third Page Remediation";

    generate_multi_page_scanned_pdf(&pdf_path, &[page1_text, page2_text, page3_text])
        .expect("generate 3-page scanned PDF");

    // 1. Direct DocumentExtractor extraction verification
    let extracted = DocumentExtractor::extract_pdf_with_ocr_fallback(&pdf_path)
        .expect("extract multi-page scanned PDF");

    assert!(
        extracted.contains("[Scanned PDF — OCR Extracted Text]"),
        "Extracted text must contain Scanned PDF header. Got: {}",
        extracted
    );

    assert!(extracted.contains("Page 1:\n"), "Must contain Page 1 header");
    assert!(extracted.contains("Page 2:\n"), "Must contain Page 2 header");
    assert!(extracted.contains("Page 3:\n"), "Must contain Page 3 header");

    assert!(extracted.contains("CVE-2026-10001"), "Must extract Page 1 text");
    assert!(extracted.contains("CVE-2026-20002"), "Must extract Page 2 text");
    assert!(extracted.contains("CVE-2026-30003"), "Must extract Page 3 text");

    // Strictly ascending order check
    let pos_header = extracted.find("[Scanned PDF — OCR Extracted Text]").unwrap();
    let pos_p1 = extracted.find("Page 1:\n").unwrap();
    let pos_p2 = extracted.find("Page 2:\n").unwrap();
    let pos_p3 = extracted.find("Page 3:\n").unwrap();

    assert!(
        pos_header < pos_p1 && pos_p1 < pos_p2 && pos_p2 < pos_p3,
        "Pages must be ordered in strictly ascending order: pos_header={}, pos_p1={}, pos_p2={}, pos_p3={}",
        pos_header, pos_p1, pos_p2, pos_p3
    );

    // 2. Full IngestEngine indexing and retrieval verification across pages
    let storage_dir = dir.path().join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());

    let config = IngestConfig {
        watch_paths: vec![dir.path().to_path_buf()],
        ..Default::default()
    };
    let engine = IngestEngine::new(config, Arc::clone(&storage), classifier, Arc::clone(&embedder)).unwrap();

    let chunks = engine.ingest_file(&pdf_path).await.unwrap();
    assert!(chunks.is_some(), "Multi-page scanned PDF must produce indexed chunks");

    // Verify search hits for page 1, 2, and 3 terms
    let query_p1 = StorageSearchQuery::keyword("CVE-2026-10001", 3, 5);
    let hits_p1 = storage.search(&query_p1).await.unwrap();
    assert!(!hits_p1.is_empty(), "Must find chunk containing Page 1 content");

    let query_p2 = StorageSearchQuery::keyword("CVE-2026-20002", 3, 5);
    let hits_p2 = storage.search(&query_p2).await.unwrap();
    assert!(!hits_p2.is_empty(), "Must find chunk containing Page 2 content");

    let query_p3 = StorageSearchQuery::keyword("CVE-2026-30003", 3, 5);
    let hits_p3 = storage.search(&query_p3).await.unwrap();
    assert!(!hits_p3.is_empty(), "Must find chunk containing Page 3 content");
}

#[tokio::test]
async fn test_adversarial_legacy_chunk_upgrade_immutability_and_purge() {
    // Challenge 3: Legacy chunk upgrade immutability and purge.
    // Verify that ReindexWorker::upgrade_legacy_image_chunks preserves chunk_id ({file_b3}:img:0)
    // and document_id ({file_b3}) with zero divergence, and purges stale chunks from Tantivy and LanceDB.
    let dir = tempdir().unwrap();
    let img_path_1 = dir.path().join("audit_legacy_asset_1.png");
    let img_path_2 = dir.path().join("unmodified_standalone_2.png");

    let target_cve = "CVE-2026-99137 Critical Remote Code Execution";
    generate_cve_raster_image(&img_path_1, target_cve).unwrap();
    generate_cve_raster_image(&img_path_2, "Standalone Unmodified Image Asset").unwrap();

    let storage_dir = dir.path().join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());

    let bytes_1 = std::fs::read(&img_path_1).unwrap();
    let file_b3_1 = blake3::hash(&bytes_1).to_hex().to_string();
    let legacy_chunk_id_1 = format!("{}:img:0", file_b3_1);

    // Stale legacy chunk text with a distinct obsolete marker for file 1
    let stale_marker = "LEGACY_STALE_MARKER_REV_4412";
    let legacy_chunk_1 = DocumentChunk::new(
        legacy_chunk_id_1.clone(),
        file_b3_1.clone(),
        img_path_1.to_string_lossy().to_string(),
        1,
        1,
        0,
        vec![0.02; 768],
        format!("[Image Document: audit_legacy_asset_1.png]\nFormat: PNG\nTag: {}", stale_marker),
        Some("{\"mime_type\":\"image/png\",\"visual_description\":null}".into()),
    )
    .unwrap();

    // Insert a second chunk for file 2 representing a mismatched document (hash mismatch with disk)
    let mismatched_doc_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let mismatched_chunk_id = format!("{}:img:0", mismatched_doc_id);
    let mismatched_marker = "MISMATCHED_STANDALONE_TAG";
    let mismatched_chunk = DocumentChunk::new(
        mismatched_chunk_id.clone(),
        mismatched_doc_id.to_string(),
        img_path_2.to_string_lossy().to_string(),
        1,
        1,
        0,
        vec![0.03; 768],
        format!("[Image Document: unmodified_standalone_2.png]\nFormat: PNG\nTag: {}", mismatched_marker),
        Some("{\"mime_type\":\"image/png\",\"visual_description\":null}".into()),
    )
    .unwrap();

    storage.insert_chunks(&[legacy_chunk_1, mismatched_chunk]).await.unwrap();

    // Verify initial storage state: count = 2
    assert_eq!(storage.count().await.unwrap(), 2, "Storage must contain 2 initial chunks");

    // Tantivy search for stale marker before upgrade -> 1 hit
    let stale_query = StorageSearchQuery::keyword(stale_marker, 3, 5);
    let stale_hits_before = storage.search(&stale_query).await.unwrap();
    assert_eq!(stale_hits_before.len(), 1, "Stale marker must be searchable before upgrade");

    // Tantivy search for CVE before upgrade -> 0 hits
    let cve_query = StorageSearchQuery::keyword("CVE-2026-99137", 3, 5);
    let cve_hits_before = storage.search(&cve_query).await.unwrap();
    assert!(cve_hits_before.is_empty(), "CVE must not be present before upgrade");

    // Tantivy search for mismatched chunk before upgrade -> 1 hit
    let mismatch_query = StorageSearchQuery::keyword(mismatched_marker, 3, 5);
    let mismatch_hits_before = storage.search(&mismatch_query).await.unwrap();
    assert_eq!(mismatch_hits_before.len(), 1, "Mismatched chunk must be searchable");

    // Execute legacy chunk upgrade
    let config = IngestConfig {
        watch_paths: vec![dir.path().to_path_buf()],
        ..Default::default()
    };
    let dedup = Arc::new(TwoLevelDedupEngine::new());
    let worker = ReindexWorker::new(config, Arc::clone(&storage), classifier, embedder, dedup);
    let upgraded_count = worker.upgrade_legacy_image_chunks().await.unwrap();

    // Exactly 1 chunk should be upgraded; the mismatched chunk must be untouched
    assert_eq!(upgraded_count, 1, "Must upgrade exactly 1 chunk (mismatched doc must be skipped)");

    // LanceDB count check: must still be 2 (replaced 1, did not duplicate or corrupt)
    let all_chunks = storage.scan_all_chunks().await.unwrap();
    assert_eq!(all_chunks.len(), 2, "Total chunk count must remain 2 after replacement");

    let upgraded = all_chunks.iter().find(|c| c.chunk_id == legacy_chunk_id_1).expect("upgraded chunk present");
    assert_eq!(upgraded.document_id, file_b3_1, "document_id must match exactly");
    assert_eq!(upgraded.chunk_id, legacy_chunk_id_1, "chunk_id must be strictly immutable");
    assert!(upgraded.text_content.contains("[OCR Text]"), "Upgraded chunk must contain [OCR Text]");
    assert!(upgraded.text_content.contains("CVE-2026-99137"), "Upgraded chunk must contain CVE");
    assert!(!upgraded.text_content.contains(stale_marker), "Upgraded chunk must not contain stale marker");

    let untouched = all_chunks.iter().find(|c| c.chunk_id == mismatched_chunk_id).expect("mismatched chunk present");
    assert_eq!(untouched.document_id, mismatched_doc_id, "mismatched document_id must remain untouched");

    // Tantivy search verification: stale marker must return 0 hits (purged!)
    let stale_hits_after = storage.search(&stale_query).await.unwrap();
    assert!(stale_hits_after.is_empty(), "Stale chunk must be completely purged from Tantivy search");

    // Tantivy search verification: CVE search must return 1 hit
    let cve_hits_after = storage.search(&cve_query).await.unwrap();
    assert_eq!(cve_hits_after.len(), 1, "Upgraded chunk must be retrievable via Tantivy BM25");
    assert_eq!(cve_hits_after[0].chunk.chunk_id, legacy_chunk_id_1);

    // Tantivy search verification: Mismatched chunk remains searchable
    let mismatch_hits_after = storage.search(&mismatch_query).await.unwrap();
    assert_eq!(mismatch_hits_after.len(), 1, "Mismatched chunk must remain intact and retrievable");
}
