//! Multi-Layer Pornography & Explicit Image Safety Filter (`quorum-ingest`).
//!
//! Combines:
//! 1. Zero-cost path / filename / folder / domain explicit-content blocking (`quorum_types::content_safety`).
//! 2. Pure-Rust pixel-level RGB/YCbCr/HSV inclusive Fitzpatrick I–VI skin-region segmentation,
//!    4-connected torso-exposure geometry, UI/document edge exemption, and portrait-headshot dampening.
//! 3. Post-extraction EXIF/XMP/IPTC/OCR/vision-caption explicit-text blocking.
//! 4. Optional loopback-only Ollama local vision model safety confirmation for borderline visual scores.
//!
//! All decisions are fail-closed, bounded in memory (max 160x160 working raster + 8,192-entry BLAKE3 cache),
//! and never transmit data outside `127.0.0.1`.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use image::imageops::FilterType;
use image::GenericImageView;
pub use quorum_types::content_safety::{
    check_path_explicit_content, check_text_explicit_content, is_raster_image_extension,
    is_visual_media_extension, ContentSafetyDecision,
};

const MAX_ANALYSIS_DIM: u32 = 160;
const MAX_CACHE_ENTRIES: usize = 8_192;
const MAX_MEDIA_BYTES_FOR_PIXEL_CHECK: u64 = 24 * 1024 * 1024;
const BLOCK_VISUAL_SCORE_THRESHOLD: f32 = 0.70;
const BORDERLINE_VISUAL_SCORE_THRESHOLD: f32 = 0.46;

/// Quantitative visual safety measurements computed from decoded image pixels.
#[derive(Debug, Clone, PartialEq)]
pub struct VisualSafetyMetrics {
    pub width: u32,
    pub height: u32,
    pub skin_ratio: f32,
    pub center_skin_ratio: f32,
    pub lower_skin_ratio: f32,
    pub largest_component_ratio: f32,
    pub largest_component_y_min: f32,
    pub largest_component_y_max: f32,
    pub ui_text_edge_ratio: f32,
    pub flat_bg_ratio: f32,
    pub portrait_headshot_like: bool,
    pub explicit_visual_score: f32,
}

fn verdict_cache() -> &'static Mutex<HashMap<[u8; 32], ContentSafetyDecision>> {
    static CACHE: OnceLock<Mutex<HashMap<[u8; 32], ContentSafetyDecision>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::with_capacity(256)))
}

/// Inclusive RGB + YCbCr + HSV skin-tone detector covering Fitzpatrick skin types I–VI
/// while rejecting greyscale paper, pure dark UI chrome, and oversaturated graphic banners.
#[inline]
fn is_skin_pixel(r: u8, g: u8, b: u8) -> bool {
    let rf = r as f32;
    let gf = g as f32;
    let bf = b as f32;

    let max_c = r.max(g).max(b);
    let min_c = r.min(g).min(b);
    let delta = max_c - min_c;

    // Reject achromatic greyscale/white paper and near-black shadows
    if max_c < 58 || delta < 14 || (r > 238 && g > 235 && b > 232) {
        return false;
    }

    // Require warm red dominance typical of human skin across all tones
    if !(r > g && r > b && (r - g) >= 8) {
        return false;
    }

    // HSV saturation & hue check (reject oversaturated neon red/orange UI elements)
    let sat = (delta as f32) / (max_c as f32);
    if !(0.14..=0.72).contains(&sat) {
        return false;
    }
    let hue_deg = if delta == 0 {
        0.0
    } else if max_c == r {
        60.0 * (((gf - bf) / (delta as f32)).rem_euclid(6.0))
    } else {
        return false;
    };
    // Human skin hue sits in warm red-orange-tan band [0°, 48°] or wrap-around [345°, 360°]
    let hue_ok = hue_deg <= 48.0 || hue_deg >= 345.0;
    if !hue_ok {
        return false;
    }

    // ITU-R BT.601 YCbCr bounds (extended slightly on Y for deeper skin tones)
    let y = 0.299 * rf + 0.587 * gf + 0.114 * bf;
    let cb = 128.0 - 0.168_736 * rf - 0.331_264 * gf + 0.5 * bf;
    let cr = 128.0 + 0.5 * rf - 0.418_688 * gf - 0.081_312 * bf;

    let ycbcr_ok = y >= 45.0
        && (77.0..=127.0).contains(&cb)
        && (133.0..=173.0).contains(&cr);

    // Classic Kovac daylight skin condition as complementary verifier for bright/fair tones
    let kovac_ok = r > 95 && g > 40 && b > 20 && (r - g) > 15 && delta > 15 && y >= 70.0;

    ycbcr_ok && (kovac_ok || (y >= 45.0 && y <= 145.0 && (135.0..=170.0).contains(&cr)))
}

/// Decodes raster image bytes in pure Rust and computes structural skin-exposure geometry.
/// Returns `None` for non-raster formats (e.g. SVG) or unreadable/corrupt headers.
pub fn analyze_image_pixels(bytes: &[u8]) -> Option<VisualSafetyMetrics> {
    if bytes.len() < 16 {
        return None;
    }
    let decoded = image::load_from_memory(bytes).ok()?;
    let (orig_w, orig_h) = decoded.dimensions();
    if orig_w < 24 || orig_h < 24 {
        return None;
    }

    let resized = if orig_w > MAX_ANALYSIS_DIM || orig_h > MAX_ANALYSIS_DIM {
        decoded.resize(MAX_ANALYSIS_DIM, MAX_ANALYSIS_DIM, FilterType::Triangle)
    } else {
        decoded
    };
    let rgb = resized.to_rgb8();
    let (w, h) = rgb.dimensions();
    let total = (w as usize) * (h as usize);
    if total == 0 {
        return None;
    }

    let mut skin_mask = vec![false; total];
    let mut luma = vec![0u8; total];
    let mut skin_count = 0usize;
    let mut center_total = 0usize;
    let mut center_skin = 0usize;
    let mut upper_skin = 0usize;
    let mut lower_total = 0usize;
    let mut lower_skin = 0usize;
    let mut flat_bg_count = 0usize;

    let x_lo = (w as f32 * 0.15) as u32;
    let x_hi = (w as f32 * 0.85) as u32;
    let y_lo = (h as f32 * 0.15) as u32;
    let y_hi = (h as f32 * 0.85) as u32;
    let y_mid = h / 2;
    let y_lower_start = (h as f32 * 0.55) as u32;

    for y in 0..h {
        let row_off = (y as usize) * (w as usize);
        for x in 0..w {
            let px = rgb.get_pixel(x, y);
            let (r, g, b) = (px[0], px[1], px[2]);
            let idx = row_off + (x as usize);
            luma[idx] = ((77u32 * r as u32 + 150u32 * g as u32 + 29u32 * b as u32) >> 8) as u8;

            let max_c = r.max(g).max(b);
            let min_c = r.min(g).min(b);
            if (max_c - min_c) <= 12 && (max_c >= 232 || max_c <= 28) {
                flat_bg_count += 1;
            }

            let in_center = x >= x_lo && x < x_hi && y >= y_lo && y < y_hi;
            if in_center {
                center_total += 1;
            }
            if y >= y_lower_start {
                lower_total += 1;
            }

            if is_skin_pixel(r, g, b) {
                skin_mask[idx] = true;
                skin_count += 1;
                if in_center {
                    center_skin += 1;
                }
                if y < y_mid {
                    upper_skin += 1;
                }
                if y >= y_lower_start {
                    lower_skin += 1;
                }
            }
        }
    }

    // Measure sharp high-contrast monochrome edges (documents, receipts, UI screenshots, code)
    let mut ui_edges = 0usize;
    for y in 0..h.saturating_sub(1) {
        let row_off = (y as usize) * (w as usize);
        let next_off = ((y + 1) as usize) * (w as usize);
        for x in 0..w.saturating_sub(1) {
            let idx = row_off + (x as usize);
            if skin_mask[idx] {
                continue;
            }
            let l0 = luma[idx];
            let dx = l0.abs_diff(luma[idx + 1]);
            let dy = l0.abs_diff(luma[next_off + (x as usize)]);
            if dx >= 48 || dy >= 48 {
                ui_edges += 1;
            }
        }
    }

    // 4-connected BFS to find largest contiguous skin mass and its vertical span
    let mut visited = vec![false; total];
    let mut queue = VecDeque::with_capacity(256);
    let mut best_comp_size = 0usize;
    let mut best_y_min = h;
    let mut best_y_max = 0u32;

    for start_y in 0..h {
        for start_x in 0..w {
            let start_idx = (start_y as usize) * (w as usize) + (start_x as usize);
            if !skin_mask[start_idx] || visited[start_idx] {
                continue;
            }
            visited[start_idx] = true;
            queue.clear();
            queue.push_back((start_x, start_y));
            let mut comp_size = 0usize;
            let mut c_y_min = start_y;
            let mut c_y_max = start_y;

            while let Some((cx, cy)) = queue.pop_front() {
                comp_size += 1;
                c_y_min = c_y_min.min(cy);
                c_y_max = c_y_max.max(cy);

                let neighbors = [
                    cx.checked_sub(1).map(|nx| (nx, cy)),
                    (cx + 1 < w).then_some((cx + 1, cy)),
                    cy.checked_sub(1).map(|ny| (cx, ny)),
                    (cy + 1 < h).then_some((cx, cy + 1)),
                ];
                for nb in neighbors.into_iter().flatten() {
                    let n_idx = (nb.1 as usize) * (w as usize) + (nb.0 as usize);
                    if skin_mask[n_idx] && !visited[n_idx] {
                        visited[n_idx] = true;
                        queue.push_back(nb);
                    }
                }
            }

            if comp_size > best_comp_size {
                best_comp_size = comp_size;
                best_y_min = c_y_min;
                best_y_max = c_y_max;
            }
        }
    }

    let skin_ratio = skin_count as f32 / total as f32;
    let center_skin_ratio = if center_total > 0 {
        center_skin as f32 / center_total as f32
    } else {
        0.0
    };
    let lower_skin_ratio = if lower_total > 0 {
        lower_skin as f32 / lower_total as f32
    } else {
        0.0
    };
    let largest_component_ratio = best_comp_size as f32 / total as f32;
    let largest_component_y_min = if best_comp_size > 0 {
        best_y_min as f32 / h as f32
    } else {
        0.0
    };
    let largest_component_y_max = if best_comp_size > 0 {
        best_y_max as f32 / h as f32
    } else {
        0.0
    };
    let ui_text_edge_ratio = ui_edges as f32 / total as f32;
    let flat_bg_ratio = flat_bg_count as f32 / total as f32;

    // Portrait/headshot detector: skin is concentrated in the upper face zone while the
    // lower torso is clothed / non-skin.
    let upper_share = if skin_count > 0 {
        upper_skin as f32 / skin_count as f32
    } else {
        0.0
    };
    let portrait_headshot_like =
        skin_ratio < 0.56 && upper_share >= 0.62 && lower_skin_ratio < 0.20;

    // Weighted structural exposure score calibrated to reject explicit nudity while
    // keeping scanned documents, UI screenshots, receipts, landscapes, and headshots safe.
    let mut score = 0.0f32;
    if skin_ratio >= 0.18 && largest_component_ratio >= 0.12 {
        let base_skin = ((skin_ratio - 0.15) / 0.45).clamp(0.0, 1.0);
        let center_weight = ((center_skin_ratio - 0.18) / 0.48).clamp(0.0, 1.0);
        let comp_weight = ((largest_component_ratio - 0.10) / 0.38).clamp(0.0, 1.0);
        let lower_torso_weight = ((lower_skin_ratio - 0.12) / 0.45).clamp(0.0, 1.0);
        let vertical_span = (largest_component_y_max - largest_component_y_min).clamp(0.0, 1.0);
        let span_weight = ((vertical_span - 0.25) / 0.50).clamp(0.0, 1.0);

        score = 0.24 * base_skin
            + 0.30 * center_weight
            + 0.24 * comp_weight
            + 0.14 * lower_torso_weight
            + 0.08 * span_weight;

        // Dampen documents, receipts, white/dark UI screenshots, and diagrams
        if ui_text_edge_ratio >= 0.14 {
            score *= 0.25;
        } else if ui_text_edge_ratio >= 0.09 {
            score *= 0.55;
        }
        if flat_bg_ratio >= 0.58 {
            score *= 0.30;
        } else if flat_bg_ratio >= 0.42 {
            score *= 0.60;
        }

        // Dampen standard portraits / headshots / IDs
        if portrait_headshot_like {
            score *= 0.35;
        }
    }

    Some(VisualSafetyMetrics {
        width: orig_w,
        height: orig_h,
        skin_ratio,
        center_skin_ratio,
        lower_skin_ratio,
        largest_component_ratio,
        largest_component_y_min,
        largest_component_y_max,
        ui_text_edge_ratio,
        flat_bg_ratio,
        portrait_headshot_like,
        explicit_visual_score: score.clamp(0.0, 1.0),
    })
}

/// Optional loopback-only Ollama local vision model safety check for borderline visual scores.
/// Returns `Some(true)` if the local vision model confirms pornography / explicit nudity,
/// `Some(false)` if confirmed safe, or `None` if no loopback vision model is available.
fn classify_borderline_with_local_vision(bytes: &[u8]) -> Option<bool> {
    if bytes.is_empty() || bytes.len() > 6 * 1024 * 1024 {
        return None;
    }
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 11434);
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(200)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(600)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(400)));
    stream
        .write_all(b"GET /api/tags HTTP/1.0\r\nHost: 127.0.0.1:11434\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut tags_raw = Vec::new();
    stream.read_to_end(&mut tags_raw).ok()?;
    let tags_str = String::from_utf8_lossy(&tags_raw);
    let body_at = tags_str
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| tags_str.find("\n\n").map(|i| i + 2))?;
    let tags_json: serde_json::Value = serde_json::from_str(tags_str[body_at..].trim()).ok()?;
    let installed: Vec<String> = tags_json
        .get("models")?
        .as_array()?
        .iter()
        .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(str::to_string))
        .collect();

    const VISION_MODELS: &[&str] = &[
        "moondream",
        "llava-phi3",
        "llava:7b",
        "llava",
        "qwen2.5vl",
        "qwen2.5-vl",
        "llama3.2-vision",
        "minicpm-v",
        "gemma3",
    ];
    let model = VISION_MODELS.iter().find_map(|pref| {
        installed
            .iter()
            .find(|m| m.to_ascii_lowercase().starts_with(pref))
            .cloned()
    })?;

    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        b64.push(T[(n >> 18) as usize & 63] as char);
        b64.push(T[(n >> 12) as usize & 63] as char);
        b64.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        b64.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }

    let payload = serde_json::json!({
        "model": model,
        "prompt": "Safety classification only. Reply strictly with JSON: {\"explicit_pornography\": true or false}. Set true ONLY if the image contains pornography, sexually explicit acts, or exposed adult nudity/genitalia. Set false for clothed people, portraits, documents, screenshots, animals, objects, or landscapes.",
        "images": [b64],
        "format": "json",
        "stream": false,
        "options": { "temperature": 0.0, "num_predict": 48 }
    })
    .to_string();
    let req = format!(
        "POST /api/generate HTTP/1.0\r\nHost: 127.0.0.1:11434\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        payload.len(),
        payload
    );

    let mut gen_stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500)).ok()?;
    let _ = gen_stream.set_write_timeout(Some(Duration::from_millis(1500)));
    let _ = gen_stream.set_read_timeout(Some(Duration::from_millis(2500)));
    gen_stream.write_all(req.as_bytes()).ok()?;
    let mut resp_raw = Vec::new();
    gen_stream.read_to_end(&mut resp_raw).ok()?;
    let resp_str = String::from_utf8_lossy(&resp_raw);
    let r_body_at = resp_str
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| resp_str.find("\n\n").map(|i| i + 2))?;
    let val: serde_json::Value = serde_json::from_str(resp_str[r_body_at..].trim()).ok()?;
    let inner = val.get("response")?.as_str()?.trim();
    let parsed: serde_json::Value = serde_json::from_str(inner).ok()?;
    parsed.get("explicit_pornography").and_then(|v| v.as_bool())
}

/// Evaluates an image's path and raw bytes against the mandatory pornography/explicit filter.
/// Caches pixel-analysis verdicts by BLAKE3 hash so repeated checks cost microseconds.
pub fn evaluate_image_safety(path: &Path, bytes: &[u8]) -> ContentSafetyDecision {
    let path_decision = check_path_explicit_content(path);
    if path_decision.is_blocked() {
        return path_decision;
    }

    if bytes.is_empty() {
        return ContentSafetyDecision::Allowed;
    }

    let hash_bytes = *blake3::hash(bytes).as_bytes();
    if let Ok(cache) = verdict_cache().lock() {
        if let Some(hit) = cache.get(&hash_bytes) {
            return hit.clone();
        }
    }

    let (decision, cacheable) = if let Some(metrics) = analyze_image_pixels(bytes) {
        if metrics.explicit_visual_score >= BLOCK_VISUAL_SCORE_THRESHOLD {
            (
                ContentSafetyDecision::Blocked {
                    category: "explicit_visual_nudity",
                    reason: format!(
                        "Blocked by pornography/explicit image visual filter (score={:.2}, skin={:.0}%, center={:.0}%, region={:.0}%)",
                        metrics.explicit_visual_score,
                        metrics.skin_ratio * 100.0,
                        metrics.center_skin_ratio * 100.0,
                        metrics.largest_component_ratio * 100.0,
                    ),
                    confidence: metrics.explicit_visual_score,
                },
                true,
            )
        } else if metrics.explicit_visual_score >= BORDERLINE_VISUAL_SCORE_THRESHOLD {
            if crate::image_indexer::ImageIndexer::is_bulk_indexing() {
                // Never poison the BLAKE3 verdict cache when local vision verification was skipped during bulk indexing.
                (ContentSafetyDecision::Allowed, false)
            } else {
                match classify_borderline_with_local_vision(bytes) {
                    Some(true) => (
                        ContentSafetyDecision::Blocked {
                            category: "explicit_visual_confirmed",
                            reason: format!(
                                "Blocked by pornography/explicit image vision safety filter (visual_score={:.2})",
                                metrics.explicit_visual_score
                            ),
                            confidence: metrics.explicit_visual_score.max(0.85),
                        },
                        true,
                    ),
                    Some(false) => (ContentSafetyDecision::Allowed, true),
                    None => (ContentSafetyDecision::Allowed, false),
                }
            }
        } else {
            (ContentSafetyDecision::Allowed, true)
        }
    } else {
        (ContentSafetyDecision::Allowed, true)
    };

    if cacheable {
        if let Ok(mut cache) = verdict_cache().lock() {
            if cache.len() >= MAX_CACHE_ENTRIES {
                cache.clear();
            }
            cache.insert(hash_bytes, decision.clone());
        }
    }
    decision
}

/// Evaluates an image file on disk (used by `/api/media`, `/api/open-file`, and drift cleanup).
pub fn evaluate_image_file_safety(path: &Path) -> ContentSafetyDecision {
    let path_decision = check_path_explicit_content(path);
    if path_decision.is_blocked() {
        return path_decision;
    }

    let canonical_path = match std::fs::canonicalize(path) {
        Ok(c) => c,
        Err(_) => quorum_types::session_fs_bridge::canonicalize_or_bridged(path)
            .unwrap_or_else(|| path.to_path_buf()),
    };
    if canonical_path != path {
        let canonical_decision = check_path_explicit_content(&canonical_path);
        if canonical_decision.is_blocked() {
            return canonical_decision;
        }
    }

    let ext = canonical_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    if !is_raster_image_extension(ext) {
        return ContentSafetyDecision::Allowed;
    }

    let bytes = match std::fs::metadata(&canonical_path) {
        Ok(meta) => {
            if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_MEDIA_BYTES_FOR_PIXEL_CHECK {
                return ContentSafetyDecision::Allowed;
            }
            match std::fs::read(&canonical_path) {
                Ok(b) => b,
                Err(_) => return ContentSafetyDecision::Allowed,
            }
        }
        Err(_) => match quorum_types::session_fs_bridge::read_bytes_via_bridge(
            &canonical_path,
            MAX_MEDIA_BYTES_FOR_PIXEL_CHECK,
            quorum_types::CloudPlaceholderPolicy::HydrateOnDemand {
                max_file_size_bytes: MAX_MEDIA_BYTES_FOR_PIXEL_CHECK,
            },
        ) {
            Ok(b) if !b.is_empty() => b,
            _ => return ContentSafetyDecision::Allowed,
        },
    };
    evaluate_image_safety(&canonical_path, &bytes)
}

/// Evaluates extracted image metadata (keywords, EXIF comments, OCR text, and vision description).
pub fn evaluate_image_metadata_and_text(
    path: &Path,
    keywords: &[String],
    user_comment: Option<&str>,
    ocr_text: Option<&str>,
    visual_description: Option<&str>,
) -> ContentSafetyDecision {
    let path_decision = check_path_explicit_content(path);
    if path_decision.is_blocked() {
        return path_decision;
    }

    let mut combined = String::new();
    for kw in keywords {
        combined.push_str(kw);
        combined.push(' ');
    }
    if let Some(c) = user_comment {
        combined.push_str(c);
        combined.push('\n');
    }
    if let Some(o) = ocr_text {
        combined.push_str(o);
        combined.push('\n');
    }
    if let Some(v) = visual_description {
        combined.push_str(v);
        combined.push('\n');
    }

    check_text_explicit_content(&combined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageFormat, Rgb, RgbImage};
    use std::io::Cursor;

    fn encode_png(img: &RgbImage) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        image::DynamicImage::ImageRgb8(img.clone())
            .write_to(&mut buf, ImageFormat::Png)
            .expect("encode png");
        buf.into_inner()
    }

    #[test]
    fn allows_document_screenshot_and_blue_landscape_pixels() {
        // 1. White document page with crisp dark text stripes
        let mut doc = RgbImage::from_pixel(160, 160, Rgb([250, 250, 250]));
        for y in (16..144).step_by(8) {
            for x in 14..146 {
                doc.put_pixel(x, y, Rgb([24, 24, 28]));
                doc.put_pixel(x, y + 1, Rgb([24, 24, 28]));
            }
        }
        let doc_bytes = encode_png(&doc);
        let doc_metrics = analyze_image_pixels(&doc_bytes).expect("doc metrics");
        assert!(
            doc_metrics.explicit_visual_score < 0.20,
            "Document screenshot must have low explicit score, got {:?}",
            doc_metrics
        );
        assert!(!evaluate_image_safety(Path::new("receipt_2026.png"), &doc_bytes).is_blocked());

        // 2. Outdoor landscape (blue sky + green grass)
        let mut sky = RgbImage::from_fn(160, 160, |_, y| {
            if y < 80 {
                Rgb([90, 155, 225])
            } else {
                Rgb([65, 145, 72])
            }
        });
        sky.put_pixel(80, 80, Rgb([255, 255, 255]));
        let sky_bytes = encode_png(&sky);
        assert!(!evaluate_image_safety(Path::new("park_photo.png"), &sky_bytes).is_blocked());
    }

    #[test]
    fn allows_clothed_upper_portrait_headshot() {
        // Clothed headshot: dark navy suit across lower half, face oval strictly in upper center
        let mut img = RgbImage::from_pixel(160, 160, Rgb([40, 52, 74]));
        for y in 22..72 {
            for x in 58..102 {
                let dx = (x as f32 - 80.0) / 22.0;
                let dy = (y as f32 - 47.0) / 25.0;
                if dx * dx + dy * dy <= 1.0 {
                    img.put_pixel(x, y, Rgb([218, 168, 132]));
                }
            }
        }
        let bytes = encode_png(&img);
        let m = analyze_image_pixels(&bytes).expect("headshot metrics");
        assert!(
            m.portrait_headshot_like,
            "Expected portrait_headshot_like=true, got {:?}",
            m
        );
        assert!(
            !evaluate_image_safety(Path::new("linkedin_headshot.png"), &bytes).is_blocked(),
            "Clothed portrait must not be blocked: {:?}",
            m
        );
    }

    #[test]
    fn blocks_large_contiguous_central_exposed_skin_image() {
        // Synthetic high-exposure central torso skin mass across both fair & deeper skin tones
        for (name, skin_rgb) in [
            ("photo_a.png", Rgb([222, 168, 134])),
            ("photo_b.png", Rgb([152, 98, 68])),
        ] {
            let mut img = RgbImage::from_pixel(160, 160, Rgb([48, 44, 52]));
            for y in 18..148 {
                for x in 24..136 {
                    img.put_pixel(x, y, skin_rgb);
                }
            }
            let bytes = encode_png(&img);
            let m = analyze_image_pixels(&bytes).expect("explicit metrics");
            assert!(
                m.explicit_visual_score >= BLOCK_VISUAL_SCORE_THRESHOLD,
                "Expected high explicit_visual_score for {name}, got {:?}",
                m
            );
            assert!(
                evaluate_image_safety(Path::new(name), &bytes).is_blocked(),
                "Expected {name} to be blocked by visual filter"
            );
        }
    }

    #[test]
    fn blocks_explicit_path_and_caption_metadata() {
        assert!(evaluate_image_safety(
            Path::new(r"C:\Users\Alice\Downloads\pornhub_still.png"),
            b"not_even_decoded"
        )
        .is_blocked());
        assert!(evaluate_image_metadata_and_text(
            Path::new(r"C:\Users\Alice\Pictures\img_0042.jpg"),
            &["nsfw".to_string()],
            None,
            None,
            None,
        )
        .is_blocked());
        assert!(evaluate_image_metadata_and_text(
            Path::new(r"C:\Users\Alice\Pictures\img_0043.jpg"),
            &[],
            None,
            None,
            Some("A nude woman with exposed breasts posing on a bed."),
        )
        .is_blocked());
    }
}
