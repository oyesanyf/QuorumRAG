//! Empirical Adversarial Challenger Test Suite for Milestone M18 (Ingest-Time Real OCR for Images).
//!
//! CHALLENGE 1: Adversarial CVE tokens with various Unicode hyphen characters
//!              (em-dash \u{2014}, en-dash \u{2013}, minus \u{2212}, non-breaking \u{2011}, etc.).
//!              Verifies `ImageIndexer::normalize_ocr_text` normalization and Tantivy BM25 retrieval of `CVE-2026-99137`.
//! CHALLENGE 2: Multi-format raster images (.png, .bmp, .jpg) with non-descriptive names.
//!              Verifies pixel-embedded text is OCR'd and retrievable via full-text keyword search.
//! CHALLENGE 3: Verification of `ImageMetadata` JSON serialization, backward compatibility,
//!              and strict chunk ID formula invariant `{file_b3}:img:0`.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use tempfile::tempdir;

use quorum_classifier::{ClassifierEngine, FileCategory, FileIdentity, FileTypeClassifier};
use quorum_contract::{EmbeddingContract, EmbeddingGenerator};
use quorum_storage::{StorageConfig, StorageEngine, StorageSearchQuery};
use quorum_types::DocumentChunk;

use quorum_ingest::config::IngestConfig;
use quorum_ingest::engine::IngestEngine;
use quorum_ingest::image_indexer::{ImageIndexer, ImageMetadata};

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

/// Helper to render high-contrast pixel text in specified image format (.png, .bmp, .jpg)
fn generate_raster_image_with_format(path: &Path, text: &str, pil_format: &str) -> std::io::Result<()> {
    let escaped_path = path.to_string_lossy().replace('\\', "/");
    let script = format!(
        "from PIL import Image, ImageDraw\n\
         img = Image.new('RGB', (600, 50), (255, 255, 255))\n\
         d = ImageDraw.Draw(img)\n\
         d.text((10, 15), '{}', fill=(0, 0, 0))\n\
         scaled = img.resize((1800, 150), Image.NEAREST)\n\
         scaled.save('{}', format='{}')\n",
        text, escaped_path, pil_format
    );

    let output = Command::new("python").arg("-c").arg(&script).output()?;

    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "Failed to generate raster {}: {}",
            pil_format,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

// ========================================================================
// CHALLENGE 1: Adversarial Unicode Hyphen / Dash Normalization & Tantivy BM25
// ========================================================================

#[test]
fn challenge_1_hyphen_normalization_matrix() {
    // Test diverse typographic dashes recognized in OCR outputs:
    // U+2010 (hyphen), U+2011 (non-breaking hyphen), U+2012 (figure dash),
    // U+2013 (en-dash), U+2014 (em-dash), U+2015 (horizontal bar), U+2212 (minus sign)

    // 1. Em-dash variant
    let em_dash_cve = "CVE\u{2014}2026\u{2014}99137";
    assert_eq!(
        ImageIndexer::normalize_ocr_text(em_dash_cve),
        "CVE-2026-99137",
        "Em-dashes must normalize to standard ASCII hyphens"
    );

    // 2. En-dash variant
    let en_dash_cve = "CVE\u{2013}2026\u{2013}99137";
    assert_eq!(
        ImageIndexer::normalize_ocr_text(en_dash_cve),
        "CVE-2026-99137",
        "En-dashes must normalize to standard ASCII hyphens"
    );

    // 3. Minus sign variant
    let minus_cve = "CVE\u{2212}2026\u{2212}99137";
    assert_eq!(
        ImageIndexer::normalize_ocr_text(minus_cve),
        "CVE-2026-99137",
        "Minus signs must normalize to standard ASCII hyphens"
    );

    // 4. Non-breaking hyphen and figure dash
    let mixed_cve = "CVE\u{2011}2026\u{2012}99137";
    assert_eq!(
        ImageIndexer::normalize_ocr_text(mixed_cve),
        "CVE-2026-99137",
        "Non-breaking hyphen and figure dash must normalize to standard ASCII hyphens"
    );

    // 5. Mixed adversarial stream with surrounding dashes
    let adversarial_raw = "ADVISORY:\u{2014}CVE\u{2014}2026\u{2013}99137\u{2015}CRITICAL\u{2212}RCE";
    let normalized = ImageIndexer::normalize_ocr_text(adversarial_raw);
    assert_eq!(
        normalized,
        "ADVISORY:-CVE-2026-99137-CRITICAL-RCE",
        "Adversarial mixed dashes must all map to '-'"
    );
    assert!(
        normalized.contains("CVE-2026-99137"),
        "Normalized text must contain exact standard CVE token"
    );
}

#[tokio::test]
async fn challenge_1_adversarial_dash_ocr_tantivy_retrieval() {
    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());

    // Construct image metadata that originally had em-dashes from OCR
    let raw_ocr_with_emdashes = "SECURITY ALERT: CVE\u{2014}2026\u{2014}99137 Critical Remote Code Execution";
    let normalized_ocr = ImageIndexer::normalize_ocr_text(raw_ocr_with_emdashes);

    let dummy_meta = ImageMetadata {
        mime_type: "image/png".to_string(),
        format_name: "PNG".to_string(),
        width: 1800,
        height: 150,
        aspect_ratio: 12.0,
        channels: 3,
        bit_depth: 8,
        size_bytes: 4096,
        camera_make: None,
        camera_model: None,
        lens_model: None,
        date_time_original: None,
        iso_speed: None,
        f_number: None,
        exposure_time: None,
        focal_length_mm: None,
        gps_latitude: None,
        gps_longitude: None,
        user_comment: None,
        path_tokens: vec!["unrelated_file".to_string()],
        extracted_text: None,
        software: None,
        gps_date_stamp: None,
        keywords: vec![],
        location_name: None,
        location_source: None,
        location_tokens: vec![],
        visual_description: None,
        has_ocr: true,
        is_image: true,
        ocr_text: Some(normalized_ocr.clone()),
    };

    let search_text = ImageIndexer::build_search_text(&dummy_meta, Path::new("unrelated_file.png"));
    assert!(search_text.contains("CVE-2026-99137"), "Search text must contain ASCII CVE");

    let chunk = DocumentChunk::new(
        "test_b3_hash:img:0".to_string(),
        "test_b3_hash".to_string(),
        "d:/harfile/unrelated_file.png".to_string(),
        1,
        1,
        0,
        vec![0.02; 768],
        search_text,
        Some(serde_json::to_string(&dummy_meta).unwrap()),
    )
    .unwrap();

    storage.insert_chunks(&[chunk]).await.unwrap();

    // BM25 Query for standard ASCII hyphenated CVE
    let query = StorageSearchQuery::keyword("CVE-2026-99137", 3, 5);
    let hits = storage.search(&query).await.unwrap();

    assert!(
        !hits.is_empty(),
        "Tantivy BM25 must match CVE-2026-99137 indexed from normalized em-dash OCR"
    );
    assert_eq!(hits[0].chunk.chunk_id, "test_b3_hash:img:0");
    assert!(hits[0].chunk.text_content.contains("CVE-2026-99137"));
    assert!(hits[0].score > 0.0);
}

// ========================================================================
// CHALLENGE 2: Multi-Format Raster Images (.png, .bmp, .jpg) & Non-Descriptive Names
// ========================================================================

#[tokio::test]
async fn challenge_2_raster_formats_with_nondescriptive_names() {
    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(TestEmbeddingGenerator::default());

    let config = IngestConfig {
        watch_paths: vec![dir.path().to_path_buf()],
        ..Default::default()
    };
    let engine = IngestEngine::new(config, Arc::clone(&storage), classifier, Arc::clone(&embedder)).unwrap();

    // 1. PNG format with non-descriptive name
    let png_path = dir.path().join("random_image_123.png");
    generate_raster_image_with_format(&png_path, "CVE-2026-99137 Critical Remote Code Execution", "PNG")
        .expect("generate random PNG");

    // 2. BMP format with non-descriptive name
    let bmp_path = dir.path().join("unknown_asset_999.bmp");
    generate_raster_image_with_format(&bmp_path, "CVE-2026-88241 Critical Remote Code Execution", "BMP")
        .expect("generate random BMP");

    // 3. JPG format with non-descriptive name
    let jpg_path = dir.path().join("dcim_photo_404.jpg");
    generate_raster_image_with_format(&jpg_path, "CVE-2026-77319 Critical Remote Code Execution", "JPEG")
        .expect("generate random JPG");

    // Ingest all 3 distinct raster format files
    let png_chunks = engine.ingest_file(&png_path).await.unwrap().expect("png chunks");
    let bmp_chunks = engine.ingest_file(&bmp_path).await.unwrap().expect("bmp chunks");
    let jpg_chunks = engine.ingest_file(&jpg_path).await.unwrap().expect("jpg chunks");

    assert_eq!(png_chunks.len(), 1);
    assert_eq!(bmp_chunks.len(), 1);
    assert_eq!(jpg_chunks.len(), 1);

    // Verify OCR text in each chunk
    assert!(
        png_chunks[0].text_content.contains("CVE-2026-99137"),
        "PNG chunk must contain pixel-extracted text. Content:\n{}",
        png_chunks[0].text_content
    );
    assert!(
        bmp_chunks[0].text_content.contains("CVE-2026-88241"),
        "BMP chunk must contain pixel-extracted text. Content:\n{}",
        bmp_chunks[0].text_content
    );
    assert!(
        jpg_chunks[0].text_content.contains("CVE-2026-77319"),
        "JPG chunk must contain pixel-extracted text. Content:\n{}",
        jpg_chunks[0].text_content
    );

    // Verify Tantivy BM25 searches for each distinct pixel token retrieve the respective file
    let query_png = StorageSearchQuery::keyword("CVE-2026-99137", 3, 5);
    let hits_png = storage.search(&query_png).await.unwrap();
    assert!(!hits_png.is_empty(), "Search for PNG pixel text must succeed");
    assert_eq!(hits_png[0].chunk.file_path, png_path.to_string_lossy());

    let query_bmp = StorageSearchQuery::keyword("CVE-2026-88241", 3, 5);
    let hits_bmp = storage.search(&query_bmp).await.unwrap();
    assert!(!hits_bmp.is_empty(), "Search for BMP pixel text must succeed");
    assert_eq!(hits_bmp[0].chunk.file_path, bmp_path.to_string_lossy());

    let query_jpg = StorageSearchQuery::keyword("CVE-2026-77319", 3, 5);
    let hits_jpg = storage.search(&query_jpg).await.unwrap();
    assert!(!hits_jpg.is_empty(), "Search for JPG pixel text must succeed");
    assert_eq!(hits_jpg[0].chunk.file_path, jpg_path.to_string_lossy());
}

// ========================================================================
// CHALLENGE 3: ImageMetadata Serialization & Strict Chunk ID Invariant
// ========================================================================

#[test]
fn challenge_3_image_metadata_serialization_and_backward_compatibility() {
    let meta = ImageMetadata {
        mime_type: "image/png".to_string(),
        format_name: "PNG".to_string(),
        width: 1920,
        height: 1080,
        aspect_ratio: 16.0 / 9.0,
        channels: 4,
        bit_depth: 8,
        size_bytes: 123456,
        camera_make: Some("Sony".to_string()),
        camera_model: Some("A7R".to_string()),
        lens_model: Some("FE 24-70mm".to_string()),
        date_time_original: Some("2026:04:17 12:00:00".to_string()),
        iso_speed: Some(100),
        f_number: Some(2.8),
        exposure_time: Some("1/250".to_string()),
        focal_length_mm: Some(50.0),
        gps_latitude: Some(37.7749),
        gps_longitude: Some(-122.4194),
        user_comment: Some("Test image".to_string()),
        path_tokens: vec!["photos".to_string(), "test".to_string()],
        extracted_text: None,
        software: Some("Windows Camera".to_string()),
        gps_date_stamp: Some("2026:04:17".to_string()),
        keywords: vec!["security".to_string(), "patch".to_string()],
        location_name: Some("San Francisco, CA".to_string()),
        location_source: Some("gps".to_string()),
        location_tokens: vec!["francisco".to_string()],
        visual_description: Some("A diagram showing system architecture".to_string()),
        has_ocr: true,
        is_image: true,
        ocr_text: Some("CVE-2026-99137".to_string()),
    };

    // 1. Serialize to JSON
    let json_str = serde_json::to_string(&meta).expect("serialize ImageMetadata");
    assert!(json_str.contains("\"has_ocr\":true"));
    assert!(json_str.contains("\"is_image\":true"));
    assert!(json_str.contains("\"ocr_text\":\"CVE-2026-99137\""));

    // 2. Deserialize back and assert equality
    let deserialized: ImageMetadata = serde_json::from_str(&json_str).expect("deserialize ImageMetadata");
    assert_eq!(meta, deserialized, "Roundtrip serialization must preserve all fields identically");

    // 3. Test backward compatibility: legacy JSON without newly added fields
    let legacy_json = r#"{
        "mime_type": "image/jpeg",
        "format_name": "JPEG",
        "width": 800,
        "height": 600,
        "aspect_ratio": 1.333,
        "channels": 3,
        "bit_depth": 8,
        "size_bytes": 45000,
        "camera_make": null,
        "camera_model": null,
        "lens_model": null,
        "date_time_original": null,
        "iso_speed": null,
        "f_number": null,
        "exposure_time": null,
        "focal_length_mm": null,
        "gps_latitude": null,
        "gps_longitude": null,
        "user_comment": null,
        "path_tokens": ["legacy"],
        "extracted_text": null
    }"#;

    let legacy_meta: ImageMetadata = serde_json::from_str(legacy_json)
        .expect("Legacy JSON lacking new fields must deserialize successfully with defaults");

    assert!(legacy_meta.is_image, "Default for is_image must be true");
    assert!(!legacy_meta.has_ocr, "Default for has_ocr must be false");
    assert_eq!(legacy_meta.ocr_text, None, "Default for ocr_text must be None");
    assert_eq!(legacy_meta.visual_description, None);
    assert!(legacy_meta.keywords.is_empty());
}

#[test]
fn challenge_3_strict_chunk_id_formula_preservation() {
    let dummy_bytes = b"EXACT_IMAGE_PAYLOAD_TEST_CHALLENGER_2026";
    let file_b3 = blake3::hash(dummy_bytes).to_hex().to_string();
    let expected_chunk_id = format!("{}:img:0", file_b3);

    let identity = FileIdentity::new(
        "png",
        "image/png",
        FileCategory::Image,
        "PNG",
        false,
        1.0,
        ClassifierEngine::HeaderInspection,
    );
    let embedder = TestEmbeddingGenerator::default();
    let path = Path::new("test_asset_strict.png");

    let chunk = ImageIndexer::index_image(path, dummy_bytes, &identity, 0, &embedder)
        .expect("index_image must succeed");

    // Strictly verify chunk ID and document ID formulas
    assert_eq!(
        chunk.chunk_id, expected_chunk_id,
        "Chunk ID formula {{file_b3}}:img:0 must be strictly preserved"
    );
    assert_eq!(
        chunk.document_id, file_b3,
        "Document ID must strictly equal hex BLAKE3 of the image bytes"
    );

    // Verify chunk ID satisfies exact regex pattern ^[0-9a-f]{64}:img:0$
    assert_eq!(file_b3.len(), 64, "BLAKE3 hex must be 64 characters");
    assert!(
        chunk.chunk_id.ends_with(":img:0"),
        "Chunk ID must end with ':img:0'"
    );

    // Verify metadata JSON embedded in chunk
    assert!(!chunk.metadata_json.is_empty(), "Metadata JSON must be present");
    let parsed_meta: ImageMetadata = serde_json::from_str(&chunk.metadata_json)
        .expect("Embedded metadata_json must deserialize to ImageMetadata");
    assert_eq!(parsed_meta.mime_type, "image/png");
    assert_eq!(parsed_meta.size_bytes, dummy_bytes.len() as u64);
    assert!(parsed_meta.is_image);
}
