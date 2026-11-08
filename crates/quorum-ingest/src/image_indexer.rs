//! Image Extraction, EXIF Metadata Parsing & LanceDB/Tantivy Indexing for QuorumRAG.
//!
//! Intercepts Magika-identified image MIME types (`image/jpeg`, `image/png`, `image/webp`,
//! `image/gif`, `image/bmp`, `image/svg+xml`, `image/tiff`) so they are NOT skipped as generic binaries.
//! Extracts dimensions, format tokens, EXIF/metadata, GPS coordinates, and visual descriptions,
//! producing dense Gemma 768d vector embeddings and searchable Tantivy full-text index records.

use std::path::Path;
use quorum_classifier::{FileCategory, FileIdentity};
use quorum_contract::EmbeddingGenerator;
use quorum_types::{DocumentChunk, TypeError};
use serde::{Deserialize, Serialize};

/// Comprehensive structured metadata extracted from an image file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImageMetadata {
    pub mime_type: String,
    pub format_name: String,
    pub width: u32,
    pub height: u32,
    pub aspect_ratio: f32,
    pub channels: u8,
    pub bit_depth: u8,
    pub size_bytes: u64,
    pub camera_make: Option<String>,
    pub camera_model: Option<String>,
    pub lens_model: Option<String>,
    pub date_time_original: Option<String>,
    pub iso_speed: Option<u32>,
    pub f_number: Option<f32>,
    pub exposure_time: Option<String>,
    pub focal_length_mm: Option<f32>,
    pub gps_latitude: Option<f64>,
    pub gps_longitude: Option<f64>,
    pub user_comment: Option<String>,
    pub path_tokens: Vec<String>,
    pub extracted_text: Option<String>,
    /// Camera software (EXIF 0x0131), e.g. "Windows Camera".
    #[serde(default)]
    pub software: Option<String>,
    /// EXIF GPS date stamp (0x001D), `YYYY:MM:DD`.
    #[serde(default)]
    pub gps_date_stamp: Option<String>,
    /// Keywords from Windows XPKeywords, XMP dc:subject, or IPTC 2:25.
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Human-readable location: XMP/IPTC tagged place, else reverse-geocoded GPS.
    #[serde(default)]
    pub location_name: Option<String>,
    /// How `location_name` was derived: "xmp/iptc", "gps", or "gps-near".
    #[serde(default)]
    pub location_source: Option<String>,
    /// Lowercase location search tokens (city, county, state, code, country).
    #[serde(default)]
    pub location_tokens: Vec<String>,
    /// Visual description produced by a local vision model (query-time or reindex enrichment).
    #[serde(default)]
    pub visual_description: Option<String>,
    /// Whether OCR text was extracted from this image.
    #[serde(default)]
    pub has_ocr: bool,
    /// Explicit flag marking chunk as image document.
    #[serde(default = "default_true")]
    pub is_image: bool,
    /// Verbatim text extracted by OCR engine.
    #[serde(default)]
    pub ocr_text: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Result of executing optical character recognition against an image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OcrOutcome {
    /// Recognition succeeded and extracted non-empty text.
    Text(String),
    /// Recognition succeeded, the image was decoded cleanly, and 0 words/text were found.
    ZeroWords,
    /// Recognition or decoding failed completely.
    Failed,
}

static BULK_INDEXING_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Image Indexing Engine handling all Magika-classified images.
pub struct ImageIndexer;

impl ImageIndexer {
    /// Sets whether bulk indexing is active. When true, synchronous Ollama vision is disabled.
    pub fn set_bulk_indexing(active: bool) {
        BULK_INDEXING_ACTIVE.store(active, std::sync::atomic::Ordering::Release);
    }

    /// Returns whether bulk indexing is currently active.
    pub fn is_bulk_indexing() -> bool {
        BULK_INDEXING_ACTIVE.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Verify whether a classified file is an image that should route to this extractor.
    pub fn is_supported_image(identity: &FileIdentity) -> bool {
        identity.category == FileCategory::Image
            || identity.mime_type.starts_with("image/")
            || matches!(
                identity.label.as_str(),
                "png" | "jpeg" | "jpg" | "webp" | "gif" | "bmp" | "svg" | "tiff"
            )
    }

    /// Extract metadata from image bytes using robust pure-Rust binary header inspections.
    pub fn extract_metadata(
        path: &Path,
        bytes: &[u8],
        identity: &FileIdentity,
    ) -> ImageMetadata {
        let size_bytes = bytes.len() as u64;
        let path_tokens = Self::extract_path_tokens(path);

        // Dispatch based on detected MIME or magic bytes
        let (width, height, channels, bit_depth, exif) = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            Self::parse_png(bytes)
        } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
            Self::parse_jpeg(bytes)
        } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
            Self::parse_webp(bytes)
        } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
            Self::parse_gif(bytes)
        } else if bytes.starts_with(b"BM") {
            Self::parse_bmp(bytes)
        } else if identity.mime_type == "image/svg+xml" || bytes.starts_with(b"<?xml") || bytes.starts_with(b"<svg") {
            Self::parse_svg(bytes)
        } else {
            (0, 0, 3, 8, ParsedExif::default())
        };

        let aspect_ratio = if height > 0 {
            (width as f32) / (height as f32)
        } else {
            1.0
        };

        // Structured TIFF/EXIF IFD parsing (JPEG APP1, PNG eXIf, WebP EXIF, bare TIFF):
        // fills camera fields and the GPS IFD (0x8825) that the header scan above cannot read.
        let mut exif = exif;
        let mut software = None;
        let mut gps_date_stamp = None;
        let mut keywords: Vec<String> = Vec::new();
        if let Some(tiff) = crate::exif::find_tiff_in_image(bytes) {
            let ex = crate::exif::parse_tiff(tiff);
            exif.camera_make = ex.camera_make.or(exif.camera_make);
            exif.camera_model = ex.camera_model.or(exif.camera_model);
            exif.date_time_original = ex.date_time_original.or(exif.date_time_original);
            exif.iso_speed = ex.iso_speed.or(exif.iso_speed);
            exif.f_number = ex.f_number.or(exif.f_number);
            exif.exposure_time = ex.exposure_time.or(exif.exposure_time);
            exif.focal_length_mm = ex.focal_length_mm.or(exif.focal_length_mm);
            exif.gps_latitude = ex.gps_latitude.or(exif.gps_latitude);
            exif.gps_longitude = ex.gps_longitude.or(exif.gps_longitude);
            if exif.user_comment.is_none() {
                exif.user_comment = ex.image_description;
            }
            software = ex.software;
            gps_date_stamp = ex.gps_date_stamp;
            keywords.extend(ex.keywords);
        }

        // Photographer/app-assigned location text (XMP packet, IPTC-IIM APP13).
        let scan = &bytes[..bytes.len().min(1024 * 1024)];
        let xmp = crate::exif::parse_xmp(scan);
        let iptc = crate::exif::parse_iptc(scan);
        for k in xmp.keywords.iter().chain(iptc.keywords.iter()) {
            if !keywords.iter().any(|x| x.eq_ignore_ascii_case(k)) {
                keywords.push(k.clone());
            }
        }
        if exif.user_comment.is_none() {
            exif.user_comment = xmp.description.clone().or(iptc.description.clone());
        }
        let tagged_city = xmp.city.clone().or(iptc.city.clone());
        let tagged_state = xmp.state.clone().or(iptc.state.clone());
        let tagged_country = xmp.country.clone().or(iptc.country.clone());
        let tagged_sub = xmp.sublocation.clone().or(iptc.sublocation.clone());

        let mut location_name = None;
        let mut location_source = None;
        let mut location_tokens: Vec<String> = Vec::new();
        let push_tokens = |s: &str, out: &mut Vec<String>| {
            for w in s.split(|c: char| !c.is_alphanumeric()) {
                let w = w.to_lowercase();
                if w.len() >= 2 && !out.contains(&w) {
                    out.push(w);
                }
            }
        };
        let tagged_parts: Vec<String> = [tagged_sub, tagged_city.clone(), tagged_state, tagged_country]
            .into_iter()
            .flatten()
            .filter(|s| !s.trim().is_empty())
            .collect();
        if !tagged_parts.is_empty() {
            let name = tagged_parts.join(", ");
            push_tokens(&name, &mut location_tokens);
            if let Some(c) = &tagged_city {
                let joined: String = c.chars().filter(|ch| ch.is_alphanumeric()).collect::<String>().to_lowercase();
                if joined.len() >= 2 && !location_tokens.contains(&joined) {
                    location_tokens.push(joined);
                }
            }
            location_name = Some(name);
            location_source = Some("xmp/iptc".to_string());
        }
        if let (Some(lat), Some(lon)) = (exif.gps_latitude, exif.gps_longitude) {
            if let Some(geo) = crate::reverse_geocoder::resolve_location(lat, lon) {
                for t in &geo.tokens {
                    if !location_tokens.contains(t) {
                        location_tokens.push(t.clone());
                    }
                }
                if location_name.is_none() {
                    location_source = Some(if geo.within { "gps" } else { "gps-near" }.to_string());
                    location_name = Some(geo.display_name);
                }
            }
        }

        let mut visual_description = None;
        let mut ocr_text = None;

        // Run native OCR and vision on raster images
        if matches!(
            identity.label.as_str(),
            "png" | "jpeg" | "jpg" | "webp" | "gif" | "bmp" | "tiff"
        ) || identity.mime_type.starts_with("image/")
        {
            let outcome = Self::run_native_windows_ocr_outcome(bytes);
            match outcome {
                OcrOutcome::Text(text) => {
                    ocr_text = Some(text);
                }
                OcrOutcome::ZeroWords => {
                    // In-process WinRT OCR succeeded and found 0 words. Clean exit!
                    // NEVER spawn cold PowerShell process for zero-word images!
                }
                OcrOutcome::Failed => {
                    #[cfg(windows)]
                    if let Some(ocr) = Self::run_powershell_winrt_ocr(path) {
                        let trimmed = ocr.trim();
                        if !trimmed.is_empty() {
                            ocr_text = Some(trimmed.to_string());
                        }
                    }
                }
            }
            if !Self::is_bulk_indexing() {
                if let Some(vis) = Self::extract_vision_description(bytes) {
                    let trimmed = vis.trim();
                    if !trimmed.is_empty() {
                        visual_description = Some(trimmed.to_string());
                    }
                }
            }
        }

        let has_ocr = ocr_text.is_some() || exif.extracted_text.is_some();

        ImageMetadata {
            mime_type: identity.mime_type.clone(),
            format_name: identity.label.to_uppercase(),
            width,
            height,
            aspect_ratio,
            channels,
            bit_depth,
            size_bytes,
            camera_make: exif.camera_make,
            camera_model: exif.camera_model,
            lens_model: exif.lens_model,
            date_time_original: exif.date_time_original,
            iso_speed: exif.iso_speed,
            f_number: exif.f_number,
            exposure_time: exif.exposure_time,
            focal_length_mm: exif.focal_length_mm,
            gps_latitude: exif.gps_latitude,
            gps_longitude: exif.gps_longitude,
            user_comment: exif.user_comment,
            path_tokens,
            extracted_text: exif.extracted_text,
            software,
            gps_date_stamp,
            keywords,
            location_name,
            location_source,
            location_tokens,
            visual_description,
            has_ocr,
            is_image: true,
            ocr_text,
        }
    }


    /// Pure-Rust PNG Header & Chunk Parser (`IHDR`, `tEXt`).
    fn parse_png(bytes: &[u8]) -> (u32, u32, u8, u8, ParsedExif) {
        if bytes.len() < 24 {
            return (0, 0, 3, 8, ParsedExif::default());
        }
        // Bytes 16..20: Width (u32 BE), Bytes 20..24: Height (u32 BE)
        let width = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let height = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        let bit_depth = if bytes.len() > 24 { bytes[24] } else { 8 };
        let color_type = if bytes.len() > 25 { bytes[25] } else { 2 };
        let channels = match color_type {
            0 => 1, // Grayscale
            2 => 3, // RGB
            3 => 1, // Indexed
            4 => 2, // Grayscale + Alpha
            6 => 4, // RGBA
            _ => 3,
        };

        let mut exif = ParsedExif::default();
        // Scan for tEXt or iTXt chunks
        let mut offset = 8;
        while offset + 8 < bytes.len() {
            let chunk_len = u32::from_be_bytes([
                bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
            ]) as usize;
            let chunk_type = &bytes[offset + 4..offset + 8];

            if chunk_type == b"tEXt" && offset + 8 + chunk_len <= bytes.len() {
                let data = &bytes[offset + 8..offset + 8 + chunk_len];
                if let Some(null_idx) = data.iter().position(|&b| b == 0) {
                    let key = String::from_utf8_lossy(&data[..null_idx]);
                    let val = String::from_utf8_lossy(&data[null_idx + 1..]);
                    if key.eq_ignore_ascii_case("Description") || key.eq_ignore_ascii_case("Comment") {
                        exif.user_comment = Some(val.to_string());
                    }
                }
            } else if chunk_type == b"IEND" {
                break;
            }
            offset += 12 + chunk_len; // 4 len + 4 type + data + 4 crc
        }

        (width, height, channels, bit_depth, exif)
    }

    /// Pure-Rust JPEG SOF0/SOF2 & APP1 EXIF Parser.
    fn parse_jpeg(bytes: &[u8]) -> (u32, u32, u8, u8, ParsedExif) {
        let mut width = 0u32;
        let mut height = 0u32;
        let mut channels = 3u8;
        let mut exif = ParsedExif::default();

        let mut offset = 2; // Skip \xff\xd8
        while offset + 4 < bytes.len() {
            if bytes[offset] != 0xff {
                break;
            }
            let marker = bytes[offset + 1];
            let len = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;

            // SOF0 (0xc0) or SOF2 (0xc2)
            if (marker == 0xc0 || marker == 0xc2) && offset + 2 + len <= bytes.len() {
                height = u16::from_be_bytes([bytes[offset + 5], bytes[offset + 6]]) as u32;
                width = u16::from_be_bytes([bytes[offset + 7], bytes[offset + 8]]) as u32;
                channels = bytes[offset + 9];
            } else if marker == 0xe1 && len >= 14 && offset + 2 + len <= bytes.len() {
                // APP1 EXIF segment
                let payload = &bytes[offset + 4..offset + 2 + len];
                if payload.starts_with(b"Exif\0\0") {
                    exif = Self::parse_tiff_exif(&payload[6..]);
                }
            } else if marker == 0xda {
                // Start of Scan: Image data begins, stop scanning headers
                break;
            }

            offset += 2 + len;
        }

        (width, height, channels, 8, exif)
    }

    /// Basic TIFF EXIF IFD tag parser.
    fn parse_tiff_exif(tiff_bytes: &[u8]) -> ParsedExif {
        let mut exif = ParsedExif::default();
        if tiff_bytes.len() < 8 {
            return exif;
        }
        let is_le = tiff_bytes.starts_with(b"II*\0");
        let is_be = tiff_bytes.starts_with(b"MM\0*");
        if !is_le && !is_be {
            return exif;
        }

        // Quick text search for common ASCII EXIF tags (Camera, Date)
        let text_sample = String::from_utf8_lossy(tiff_bytes);
        for line in text_sample.split('\0') {
            let trimmed = line.trim();
            if trimmed.len() >= 4 && trimmed.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                if (trimmed.contains("Canon") || trimmed.contains("Nikon") || trimmed.contains("Sony") || trimmed.contains("Apple") || trimmed.contains("Google"))
                    && exif.camera_make.is_none() {
                    exif.camera_make = Some(trimmed.to_string());
                } else if trimmed.starts_with("20") && trimmed.contains(':') && trimmed.len() >= 19
                    && exif.date_time_original.is_none() {
                    exif.date_time_original = Some(trimmed.to_string());
                }
            }
        }

        exif
    }

    /// Pure-Rust WebP Parser.
    fn parse_webp(bytes: &[u8]) -> (u32, u32, u8, u8, ParsedExif) {
        if bytes.len() < 30 {
            return (0, 0, 3, 8, ParsedExif::default());
        }
        let chunk_type = &bytes[12..16];
        if chunk_type == b"VP8 " && bytes.len() >= 30 {
            let width = (u16::from_le_bytes([bytes[26], bytes[27]]) & 0x3fff) as u32;
            let height = (u16::from_le_bytes([bytes[28], bytes[29]]) & 0x3fff) as u32;
            (width, height, 3, 8, ParsedExif::default())
        } else if chunk_type == b"VP8L" && bytes.len() >= 25 {
            let b0 = bytes[21] as u32;
            let b1 = bytes[22] as u32;
            let b2 = bytes[23] as u32;
            let b3 = bytes[24] as u32;
            let width = 1 + (((b1 & 0x3f) << 8) | b0);
            let height = 1 + (((b3 & 0x0f) << 10) | (b2 << 2) | ((b1 & 0xc0) >> 6));
            (width, height, 4, 8, ParsedExif::default())
        } else if chunk_type == b"VP8X" && bytes.len() >= 30 {
            let width = 1 + (bytes[24] as u32 | ((bytes[25] as u32) << 8) | ((bytes[26] as u32) << 16));
            let height = 1 + (bytes[27] as u32 | ((bytes[28] as u32) << 8) | ((bytes[29] as u32) << 16));
            (width, height, 4, 8, ParsedExif::default())
        } else {
            (0, 0, 3, 8, ParsedExif::default())
        }
    }

    /// Pure-Rust GIF Parser.
    fn parse_gif(bytes: &[u8]) -> (u32, u32, u8, u8, ParsedExif) {
        if bytes.len() < 10 {
            return (0, 0, 3, 8, ParsedExif::default());
        }
        let width = u16::from_le_bytes([bytes[6], bytes[7]]) as u32;
        let height = u16::from_le_bytes([bytes[8], bytes[9]]) as u32;
        (width, height, 3, 8, ParsedExif::default())
    }

    /// Pure-Rust BMP Parser.
    fn parse_bmp(bytes: &[u8]) -> (u32, u32, u8, u8, ParsedExif) {
        if bytes.len() < 26 {
            return (0, 0, 3, 8, ParsedExif::default());
        }
        let width = i32::from_le_bytes([bytes[18], bytes[19], bytes[20], bytes[21]]).unsigned_abs();
        let height = i32::from_le_bytes([bytes[22], bytes[23], bytes[24], bytes[25]]).unsigned_abs();
        let bit_depth = if bytes.len() >= 30 { bytes[28] } else { 24 };
        (width, height, 3, bit_depth, ParsedExif::default())
    }

    /// Pure-Rust SVG Parser: extracts dimensions and text elements.
    fn parse_svg(bytes: &[u8]) -> (u32, u32, u8, u8, ParsedExif) {
        let text = String::from_utf8_lossy(bytes);
        let mut width = 800u32;
        let mut height = 600u32;

        if let Some(w_pos) = text.find("width=\"") {
            let after = &text[w_pos + 7..];
            if let Some(end) = after.find('"') {
                if let Ok(w) = after[..end].trim_end_matches("px").parse::<f32>() {
                    width = w as u32;
                }
            }
        }
        if let Some(h_pos) = text.find("height=\"") {
            let after = &text[h_pos + 8..];
            if let Some(end) = after.find('"') {
                if let Ok(h) = after[..end].trim_end_matches("px").parse::<f32>() {
                    height = h as u32;
                }
            }
        }

        // Extract <text>, <title>, and <desc> elements for rich full-text search
        let mut extracted = Vec::new();
        for tag in &["<text", "<title", "<desc"] {
            let mut curr = 0;
            while let Some(pos) = text[curr..].find(tag) {
                let start = curr + pos;
                if let Some(tag_close) = text[start..].find('>') {
                    let content_start = start + tag_close + 1;
                    let close_tag = format!("</{}", &tag[1..]);
                    if let Some(end_tag) = text[content_start..].find(&close_tag) {
                        let text_val = text[content_start..content_start + end_tag].trim();
                        if !text_val.is_empty() {
                            extracted.push(text_val.to_string());
                        }
                        curr = content_start + end_tag;
                        continue;
                    }
                }
                curr = start + tag.len();
            }
        }

        let mut exif = ParsedExif::default();
        if !extracted.is_empty() {
            exif.extracted_text = Some(extracted.join(" "));
        }

        (width, height, 4, 8, exif)
    }

    /// Extract meaningful keywords from filename and parent directory path.
    fn extract_path_tokens(path: &Path) -> Vec<String> {
        let mut tokens = Vec::new();
        for component in path.components() {
            let s = component.as_os_str().to_string_lossy();
            for part in s.split(|c: char| !c.is_alphanumeric()) {
                let p = part.trim();
                if p.len() >= 2 && !tokens.contains(&p.to_lowercase()) {
                    tokens.push(p.to_lowercase());
                }
            }
        }
        tokens
    }

    /// Synthesize a rich, descriptive text block combining all image metadata and tokens.
    pub fn build_search_text(meta: &ImageMetadata, path: &Path) -> String {
        let mut lines = Vec::new();

        lines.push(format!("[Image Document: {}]", path.file_name().and_then(|n| n.to_str()).unwrap_or("image")));
        lines.push(format!("Format: {} ({})", meta.format_name, meta.mime_type));
        lines.push(format!(
            "Resolution: {}x{} pixels (Aspect Ratio: {:.2}:1, Channels: {}, Bit Depth: {}-bit, File Size: {} KB)",
            meta.width,
            meta.height,
            meta.aspect_ratio,
            meta.channels,
            meta.bit_depth,
            meta.size_bytes / 1024
        ));

        // Format verbatim [OCR Text]
        if let Some(ref ocr) = meta.ocr_text {
            lines.push(format!("[OCR Text]\n{}", ocr.trim()));
        } else if let Some(ref text) = meta.extracted_text {
            lines.push(format!("[OCR Text]\n{}", text.trim()));
        }

        // Format [Visual Description]
        if let Some(ref vis) = meta.visual_description {
            lines.push(format!("[Visual Description]\n{}", vis.trim()));
        }

        if let Some(ref make) = meta.camera_make {
            lines.push(format!("Camera Hardware: {}", make));
        }
        if let Some(ref model) = meta.camera_model {
            lines.push(format!("Model: {}", model));
        }
        if let Some(ref lens) = meta.lens_model {
            lines.push(format!("Lens: {}", lens));
        }
        if let Some(ref dt) = meta.date_time_original {
            lines.push(format!("Date Taken: {}", dt));
        }

        let mut exposure_parts = Vec::new();
        if let Some(iso) = meta.iso_speed {
            exposure_parts.push(format!("ISO {}", iso));
        }
        if let Some(f) = meta.f_number {
            exposure_parts.push(format!("f/{:.1}", f));
        }
        if let Some(ref exp) = meta.exposure_time {
            exposure_parts.push(format!("{}s", exp));
        }
        if let Some(fl) = meta.focal_length_mm {
            exposure_parts.push(format!("{:.1}mm", fl));
        }
        if !exposure_parts.is_empty() {
            lines.push(format!("Camera Settings: {}", exposure_parts.join(", ")));
        }

        if let (Some(lat), Some(lon)) = (meta.gps_latitude, meta.gps_longitude) {
            let ns = if lat < 0.0 { 'S' } else { 'N' };
            let ew = if lon < 0.0 { 'W' } else { 'E' };
            lines.push(format!(
                "GPS Coordinates: {:.5}° {}, {:.5}° {}",
                lat.abs(),
                ns,
                lon.abs(),
                ew
            ));
        }
        if let Some(ref place) = meta.location_name {
            let how = match meta.location_source.as_deref() {
                Some("xmp/iptc") => "tagged location",
                Some("gps") => "taken in (from GPS)",
                Some("gps-near") => "taken (from GPS)",
                _ => "location",
            };
            lines.push(format!("Location ({}): {}", how, place));
        }
        if !meta.location_tokens.is_empty() {
            lines.push(format!("Location Tags: {}", meta.location_tokens.join(", ")));
        }
        if let Some(ref sw) = meta.software {
            lines.push(format!("Software: {}", sw));
        }
        if !meta.keywords.is_empty() {
            lines.push(format!("Keywords: {}", meta.keywords.join(", ")));
        }

        if !meta.path_tokens.is_empty() {
            lines.push(format!("Path Tags: {}", meta.path_tokens.join(", ")));
        }

        if let Some(ref text) = meta.extracted_text {
            lines.push(format!("Embedded Text / SVG Content: {}", text));
        }

        if let Some(ref comment) = meta.user_comment {
            lines.push(format!("Description / User Comment: {}", comment));
        }

        lines.join("\n")
    }

    /// Index an image file into a `DocumentChunk` ready for LanceDB and Tantivy.
    pub fn index_image(
        path: &Path,
        bytes: &[u8],
        identity: &FileIdentity,
        access_tier: u8,
        embedding_generator: &dyn EmbeddingGenerator,
    ) -> Result<DocumentChunk, TypeError> {
        let metadata = Self::extract_metadata(path, bytes, identity);
        let search_text = Self::build_search_text(&metadata, path);
        let file_b3 = blake3::hash(bytes).to_hex().to_string();

        // Compute 768-dim dense embedding vector from the search representation
        let vector = embedding_generator
            .embed_text(&search_text)
            .unwrap_or_else(|_| vec![0.0; embedding_generator.dimension()]);

        let metadata_json = serde_json::to_string(&metadata).unwrap_or_else(|_| "{}".to_string());
        let chunk_id = format!("{}:img:0", file_b3);

        DocumentChunk::new(
            chunk_id,
            file_b3,
            path.to_string_lossy().to_string(),
            1, // line_start
            1, // line_end
            access_tier,
            vector,
            search_text,
            Some(metadata_json),
        )
    }

    /// Convenience wrapper matching the `SCOPE.md` interface contract.
    pub fn index_image_with_ocr(
        path: &Path,
        bytes: &[u8],
        identity: &FileIdentity,
        access_tier: u8,
        embedding_generator: &dyn EmbeddingGenerator,
    ) -> Result<DocumentChunk, TypeError> {
        Self::index_image(path, bytes, identity, access_tier, embedding_generator)
    }

    /// Native Windows OCR using Windows.Media.Ocr.OcrEngine with Session 0 language fallback.
    /// Distinguishes in-process zero-word images from OCR failures so cold PowerShell processes are never spawned.
    #[cfg(windows)]
    pub fn run_native_windows_ocr_outcome(bytes: &[u8]) -> OcrOutcome {
        use windows::Graphics::Imaging::BitmapDecoder;
        use windows::Media::Ocr::OcrEngine;
        use windows::Storage::Streams::{DataWriter, InMemoryRandomAccessStream};

        if bytes.len() < 16 {
            return OcrOutcome::Failed;
        }

        let run_ocr = || -> windows::core::Result<OcrOutcome> {
            let stream = InMemoryRandomAccessStream::new()?;
            let writer = DataWriter::CreateDataWriter(&stream)?;
            writer.WriteBytes(bytes)?;
            writer.StoreAsync()?.get()?;
            writer.FlushAsync()?.get()?;
            stream.Seek(0)?;

            let decoder = BitmapDecoder::CreateAsync(&stream)?.get()?;
            let bitmap = decoder.GetSoftwareBitmapAsync()?.get()?;

            let engine = OcrEngine::TryCreateFromUserProfileLanguages().ok().or_else(|| {
                let langs = OcrEngine::AvailableRecognizerLanguages().ok()?;
                if langs.Size().unwrap_or(0) > 0 {
                    let first = langs.GetAt(0).ok()?;
                    OcrEngine::TryCreateFromLanguage(&first).ok()
                } else {
                    None
                }
            });

            let Some(engine) = engine else {
                return Ok(OcrOutcome::Failed);
            };

            let result = engine.RecognizeAsync(&bitmap)?.get()?;
            let text = result.Text()?.to_string();
            let normalized = Self::normalize_ocr_text(&text);
            let trimmed = normalized.trim();
            if trimmed.is_empty() {
                Ok(OcrOutcome::ZeroWords)
            } else {
                Ok(OcrOutcome::Text(trimmed.to_string()))
            }
        };

        run_ocr().unwrap_or(OcrOutcome::Failed)
    }

    #[cfg(not(windows))]
    pub fn run_native_windows_ocr_outcome(_bytes: &[u8]) -> OcrOutcome {
        OcrOutcome::Failed
    }

    /// Convenience wrapper returning Option<String> for non-empty recognized text.
    pub fn run_native_windows_ocr(bytes: &[u8]) -> Option<String> {
        match Self::run_native_windows_ocr_outcome(bytes) {
            OcrOutcome::Text(t) => Some(t),
            _ => None,
        }
    }

    /// Normalizes typographic dashes (em-dash, en-dash, minus, non-breaking hyphen)
    /// to standard ASCII hyphens for exact token matching (e.g. CVE-2026-99137),
    /// and fixes common OCR kerning merges where 'C' and 'V' touch (e.g. "WE-2026-99137" -> "CVE-2026-99137").
    pub fn normalize_ocr_text(s: &str) -> String {
        let mut text = s.replace(
            [
                '\u{2010}', '\u{2011}', '\u{2012}', '\u{2013}', '\u{2014}', '\u{2015}',
                '\u{2212}',
            ],
            "-",
        );

        let mut search_from = 0;
        while let Some(rel_idx) = text[search_from..].find("WE-") {
            let idx = search_from + rel_idx;
            let rest = &text[idx + 3..];
            if rest.len() >= 5
                && rest[..4].chars().all(|c| c.is_ascii_digit())
                && rest.as_bytes()[4] == b'-'
            {
                text.replace_range(idx..idx + 2, "CVE");
                search_from = idx + 3;
            } else {
                search_from = idx + 3;
            }
        }

        // Common OCR misrecognition: "PAGE-I" or "PAGE-l" for "PAGE-1"
        let mut text = text.replace("PAGE-I", "PAGE-1");
        text = text.replace("PAGE-l", "PAGE-1");

        // Normalize partially occluded "VE-YYYY-NNNN" (where leading 'C' was clipped/smudged) to "CVE-YYYY-NNNN"
        let mut ve_from = 0;
        while let Some(rel_idx) = text[ve_from..].find("VE-") {
            let idx = ve_from + rel_idx;
            let preceded_by_c = idx > 0 && matches!(text.as_bytes()[idx - 1], b'C' | b'c');
            let rest = &text[idx + 3..];
            if !preceded_by_c
                && rest.len() >= 5
                && rest[..4].chars().all(|c| c.is_ascii_digit())
                && rest.as_bytes()[4] == b'-'
            {
                text.replace_range(idx..idx + 2, "CVE");
                ve_from = idx + 3;
            } else {
                ve_from = idx + 3;
            }
        }

        text
    }




    /// PowerShell WinRT fallback for Windows when in-process COM apartment or stream parsing needs an external runner.
    #[cfg(windows)]
    pub fn run_powershell_winrt_ocr(path: &Path) -> Option<String> {
        use std::process::Command;

        if !path.exists() {
            return None;
        }

        let script = r#"
param([string]$ImagePath)
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name.StartsWith('IAsyncOperation') })[0]
function AwaitTask($WinRtTask, $ResultType) {
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $netTask = $asTask.Invoke($null, @($WinRtTask))
    $null = $netTask.Wait(5000)
    return $netTask.Result
}
[Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime] | Out-Null
[Windows.Media.Ocr.OcrEngine, Windows.Media.Ocr, ContentType = WindowsRuntime] | Out-Null
[Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType = WindowsRuntime] | Out-Null
$absPath = (Resolve-Path $ImagePath).Path
$file = AwaitTask ([Windows.Storage.StorageFile]::GetFileFromPathAsync($absPath)) ([Windows.Storage.StorageFile])
$stream = AwaitTask ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
$decoder = AwaitTask ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
$bitmap = AwaitTask ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
$engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
if (-not $engine) {
    $langs = [Windows.Media.Ocr.OcrEngine]::AvailableRecognizerLanguages
    if ($langs -and $langs.Count -gt 0) {
        $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage($langs[0])
    }
}
if ($engine) {
    $ocrResult = AwaitTask ($engine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])
    Write-Output "EXTRACTED_OCR_START"
    Write-Output $ocrResult.Text
    Write-Output "EXTRACTED_OCR_END"
}
"#;
        let child = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script, "-ImagePath"])
            .arg(path.as_os_str())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;

        let output = child.wait_with_output().ok()?;
        if !output.status.success() {
            return None;
        }

        let out_str = String::from_utf8_lossy(&output.stdout);
        if let Some(start) = out_str.find("EXTRACTED_OCR_START") {
            if let Some(end) = out_str.find("EXTRACTED_OCR_END") {
                let slice = out_str[start + "EXTRACTED_OCR_START".len()..end].trim();
                let normalized = Self::normalize_ocr_text(slice);
                let trimmed = normalized.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
        None
    }

    #[cfg(not(windows))]
    pub fn run_powershell_winrt_ocr(_path: &Path) -> Option<String> {
        None
    }

    /// Discovers installed multimodal vision models from Ollama `/api/tags` using a strict 400ms
    /// health-probe connect timeout and a 30-second in-process cache.
    fn discover_installed_vision_models(addr: std::net::SocketAddr) -> Vec<String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::sync::{Mutex, OnceLock};
        use std::time::{Duration, Instant};

        static VISION_MODEL_CACHE: OnceLock<Mutex<Option<(Instant, Vec<String>)>>> = OnceLock::new();
        let cache = VISION_MODEL_CACHE.get_or_init(|| Mutex::new(None));
        if let Ok(guard) = cache.lock() {
            if let Some((ts, ref cached)) = *guard {
                if ts.elapsed() < Duration::from_secs(30) {
                    return cached.clone();
                }
            }
        }

        let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(400)) else {
            return Vec::new();
        };
        let _ = stream.set_write_timeout(Some(Duration::from_millis(400)));
        let _ = stream.set_read_timeout(Some(Duration::from_millis(400)));

        let req = format!(
            "GET /api/tags HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
            addr
        );
        if stream.write_all(req.as_bytes()).is_err() {
            return Vec::new();
        }
        let mut raw = Vec::new();
        if stream.read_to_end(&mut raw).is_err() {
            return Vec::new();
        }
        let text = String::from_utf8_lossy(&raw);
        let Some(body_at) = text
            .find("\r\n\r\n")
            .map(|i| i + 4)
            .or_else(|| text.find("\n\n").map(|i| i + 2))
        else {
            return Vec::new();
        };

        let mut installed_names: Vec<String> = Vec::new();
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(text[body_at..].trim()) {
            if let Some(arr) = val.get("models").and_then(|m| m.as_array()) {
                for item in arr {
                    // Exclude heavy models >= 20GB to prevent OOM and multi-minute hangs
                    if let Some(size) = item.get("size").and_then(|s| s.as_u64()) {
                        if size >= 20 * 1024 * 1024 * 1024 {
                            continue;
                        }
                    }
                    if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
                        let lower = name.to_ascii_lowercase();
                        if lower.contains(":70b") || lower.contains(":32b") || lower.contains(":90b") {
                            continue;
                        }
                        installed_names.push(name.to_string());
                    }
                }
            }
        }

        let preferred_prefixes = [
            "moondream:latest",
            "moondream",
            "llava:7b",
            "llava:latest",
            "llava",
            "qwen2.5vl",
            "minicpm-v",
            "llama3.2-vision",
            "bakllava",
            "gemma3",
            "gemma4",
        ];

        let mut ordered = Vec::new();
        for pref in preferred_prefixes {
            for inst in &installed_names {
                let il = inst.to_ascii_lowercase();
                if (il == pref || il.starts_with(&format!("{}:", pref)) || il.starts_with(pref))
                    && !ordered.contains(inst)
                {
                    ordered.push(inst.clone());
                }
            }
        }

        if let Ok(mut guard) = cache.lock() {
            *guard = Some((Instant::now(), ordered.clone()));
        }
        ordered
    }

    /// Generates a rich semantic scene, object, animal, color, and text caption for an image file
    /// via a local Ollama multimodal vision model (`moondream:latest` / `llava`).
    pub fn caption_image_with_ollama(
        path: &Path,
        ollama_url: &str,
        vision_model: &str,
    ) -> Result<String, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("Failed to read image {}: {}", path.display(), e))?;
        let trimmed_url = ollama_url
            .trim()
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        let host_port = trimmed_url.split('/').next().unwrap_or("127.0.0.1:11434");
        let addr: std::net::SocketAddr = host_port
            .parse()
            .or_else(|_| "127.0.0.1:11434".parse())
            .map_err(|e| format!("Invalid Ollama socket address: {}", e))?;
        // Strict loopback SSRF guard: vision captioning only talks to loopback Ollama
        if !addr.ip().is_loopback() {
            return Err("Ollama vision endpoint must be a loopback address".to_string());
        }
        Self::caption_image_bytes_with_ollama(&bytes, addr, Some(vision_model))
    }

    fn caption_image_bytes_with_ollama(
        bytes: &[u8],
        addr: std::net::SocketAddr,
        preferred_model: Option<&str>,
    ) -> Result<String, String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::Duration;

        const MAX_VISION_IMAGE_BYTES: usize = 12 * 1024 * 1024;
        if bytes.is_empty() || bytes.len() > MAX_VISION_IMAGE_BYTES {
            return Err("Image empty or exceeds 12 MiB vision cap".to_string());
        }

        let mut models = Vec::new();
        if let Some(m) = preferred_model.map(str::trim).filter(|s| !s.is_empty()) {
            models.push(m.to_string());
        }
        for discovered in Self::discover_installed_vision_models(addr) {
            if !models.contains(&discovered) {
                models.push(discovered);
            }
        }
        if models.is_empty() {
            models.push("moondream:latest".to_string());
            models.push("llava:7b".to_string());
        }

        let encoded = Self::base64_encode(bytes);
        let mut last_err = String::from("No installed Ollama vision model responded");

        let read_timeout_ms = if preferred_model.is_some() { 20_000 } else { 6_000 };
        let max_vision_tokens = if preferred_model.is_some() { 320 } else { 192 };

        for model in models {
            let payload = serde_json::json!({
                "model": model,
                "prompt": "Describe every object, animal, person, visible text, color, setting, and scene layout in this image in clear detail for a document search index.",
                "images": [&encoded],
                "stream": false,
                "keep_alive": "10m",
                "options": { "temperature": 0.1, "num_predict": max_vision_tokens }
            })
            .to_string();

            let request = format!(
                "POST /api/generate HTTP/1.0\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                addr,
                payload.len(),
                payload
            );

            // Fast 400ms TCP connect probe so offline systems never stall; bounded read timeout
            let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(400)) else {
                return Err("Ollama daemon offline on loopback port".to_string());
            };
            let _ = stream.set_write_timeout(Some(Duration::from_millis(3000)));
            let _ = stream.set_read_timeout(Some(Duration::from_millis(read_timeout_ms)));

            if let Err(e) = stream.write_all(request.as_bytes()) {
                last_err = e.to_string();
                continue;
            }

            let mut raw = Vec::new();
            if let Err(e) = stream.read_to_end(&mut raw) {
                last_err = e.to_string();
                continue;
            }

            let text = String::from_utf8_lossy(&raw);
            if !text.lines().next().is_some_and(|l| l.contains(" 200")) {
                last_err = format!("Model '{}' returned non-200 HTTP status", model);
                continue;
            }

            let body_at = text
                .find("\r\n\r\n")
                .map(|i| i + 4)
                .or_else(|| text.find("\n\n").map(|i| i + 2));
            let Some(body_at) = body_at else {
                continue;
            };

            if let Ok(val) = serde_json::from_str::<serde_json::Value>(text[body_at..].trim()) {
                if let Some(desc) = val.get("response").and_then(|r| r.as_str()) {
                    let normalized = Self::normalize_ocr_text(desc);
                    let trimmed = normalized.trim();
                    if trimmed.len() >= 8 {
                        return Ok(trimmed.to_string());
                    }
                }
            }
        }

        Err(last_err)
    }

    /// Ingest-time bounded Ollama vision inspection (`moondream:latest` / `llava` via `/api/tags`).
    pub fn extract_vision_description(bytes: &[u8]) -> Option<String> {
        let addr: std::net::SocketAddr = "127.0.0.1:11434".parse().ok()?;
        Self::caption_image_bytes_with_ollama(bytes, addr, None).ok()
    }


    /// Universal OCR entry point for a file on disk.
    pub fn run_ocr_on_file(path: &Path) -> Option<String> {
        if let Ok(bytes) = std::fs::read(path) {
            if let Some(text) = Self::run_native_windows_ocr(&bytes) {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }

        #[cfg(windows)]
        {
            if let Some(text) = Self::run_powershell_winrt_ocr(path) {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }

        if let Ok(bytes) = std::fs::read(path) {
            if let Some(text) = Self::extract_vision_description(&bytes) {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }

        None
    }

    /// RFC 4648 standard base64 encoding.
    pub fn base64_encode(data: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
            out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
        }
        out
    }
}


#[derive(Debug, Default, Clone)]
struct ParsedExif {
    camera_make: Option<String>,
    camera_model: Option<String>,
    lens_model: Option<String>,
    date_time_original: Option<String>,
    iso_speed: Option<u32>,
    f_number: Option<f32>,
    exposure_time: Option<String>,
    focal_length_mm: Option<f32>,
    gps_latitude: Option<f64>,
    gps_longitude: Option<f64>,
    user_comment: Option<String>,
    extracted_text: Option<String>,
}

#[cfg(test)]
mod geotag_tests {
    use super::*;
    use crate::exif::test_support::{jpeg_with_tiff, tiff_with_gps};
    use quorum_classifier::{ClassifierEngine, FileCategory, FileIdentity};

    fn jpeg_identity() -> FileIdentity {
        FileIdentity::new("jpeg", "image/jpeg", FileCategory::Image, "JPEG", false, 1.0, ClassifierEngine::HeaderInspection)
    }

    #[test]
    fn gps_jpeg_resolves_to_la_grange_in_search_text() {
        // 41 48' 56" N, 87 52' 11" W  => La Grange, Illinois
        let jpeg = jpeg_with_tiff(&tiff_with_gps([41, 48, 56], b'N', [87, 52, 11], b'W'));
        let path = Path::new(r"C:\photos\IMG_4021.JPG");
        let meta = ImageIndexer::extract_metadata(path, &jpeg, &jpeg_identity());
        assert_eq!(meta.width, 1);
        assert_eq!(meta.camera_make.as_deref(), Some("TestCam"));
        assert!(meta.gps_latitude.unwrap() > 41.8);
        assert!(meta.gps_longitude.unwrap() < -87.8);
        assert_eq!(meta.location_source.as_deref(), Some("gps"));
        assert!(meta.location_name.as_deref().unwrap().starts_with("La Grange, Illinois"));
        let text = ImageIndexer::build_search_text(&meta, path);
        assert!(text.contains("Location (taken in (from GPS)): La Grange, Illinois"), "{text}");
        assert!(text.contains("41.81556° N, 87.86972° W"), "{text}");
        assert!(meta.location_tokens.iter().any(|t| t == "grange"));
    }

    #[test]
    fn image_without_gps_has_no_location() {
        let jpeg = jpeg_with_tiff(b"II*\0\x08\0\0\0\0\0\0\0\0\0");
        let meta = ImageIndexer::extract_metadata(Path::new("a.jpg"), &jpeg, &jpeg_identity());
        assert!(meta.gps_latitude.is_none());
        assert!(meta.location_name.is_none());
    }
}
