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
