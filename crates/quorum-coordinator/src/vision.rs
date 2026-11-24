//! Query-time multimodal inspection of retrieved image files.
//!
//! Image chunks in the index carry only header metadata (format, size, EXIF, GPS, path tags).
//! To answer questions about what an image *shows* ("tell me about image of dogs"), the
//! top cited local image files are read from disk, base64-encoded and sent to a locally
//! installed Ollama vision model (`images: [...]` on `/api/generate`). The returned visual
//! description is injected into that excerpt's context so the answering model is grounded
//! in the real pixels. Descriptions are cached in memory by BLAKE3 content hash, so the
//! same image is never re-analysed. Nothing leaves the machine: only loopback Ollama is used.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// Vision-capable Ollama model families in preference order (fast and small first).
pub const VISION_MODEL_PREFERENCE: &[&str] = &[
    "moondream",
    "llava-phi3",
    "llava:7b",
    "llava",
    "qwen2.5vl",
    "qwen2.5-vl",
    "llama3.2-vision",
    "minicpm-v",
    "bakllava",
    "gemma3",
];

/// Largest image file that will be sent to the vision model.
pub const MAX_VISION_IMAGE_BYTES: u64 = 8 * 1024 * 1024;

/// Pick the preferred installed vision model, if any.
pub fn pick_vision_model(installed: &[String]) -> Option<String> {
    for pref in VISION_MODEL_PREFERENCE {
        if let Some(m) = installed
            .iter()
            .find(|m| m.to_ascii_lowercase().starts_with(&pref.to_ascii_lowercase()))
        {
            return Some(m.clone());
        }
    }
    None
}

/// Whether a retrieved chunk was produced by the image indexer.
pub fn is_image_chunk_text(text: &str) -> bool {
    text.trim_start().starts_with("[Image Document:")
}

/// RFC 4648 standard base64 (with padding).
pub fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
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

fn cache() -> &'static Mutex<HashMap<String, String>> {
    static CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Cached description for exact image bytes, if previously generated.
pub fn cached_description(bytes: &[u8]) -> Option<String> {
    let key = blake3::hash(bytes).to_hex().to_string();
    cache().lock().ok().and_then(|c| c.get(&key).cloned())
}

const VISION_PROMPT: &str = "Describe this image factually in 3 to 5 sentences: the main subjects \
(people, animals with likely breed/species, objects), their colours and appearance, what they are doing, \
the setting/background, and any readable text. Do not guess names or locations that are not visible.";

static PIXEL_SAFETY_HOOK: OnceLock<fn(&Path, &[u8]) -> bool> = OnceLock::new();

/// Registers the daemon's raster pixel pornography/explicit-content safety verifier so
/// query-time Ollama vision inspection refuses explicit images even with benign filenames.
pub fn register_vision_pixel_safety_hook(hook: fn(&Path, &[u8]) -> bool) {
    let _ = PIXEL_SAFETY_HOOK.set(hook);
}

fn is_cloud_placeholder_for_vision(meta: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const MASK: u32 = 0x0040_0000 | 0x0004_0000 | 0x0000_1000;
        (meta.file_attributes() & MASK) != 0
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.len() > 0 && meta.blocks() == 0
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = meta;
        false
    }
}

/// Send one image to the local Ollama vision model and return its description.
/// Fails closed (returns `None`) on any network, timeout, placeholder, safety, or parse error.
pub fn describe_image_file(addr: &SocketAddr, host_port: &str, model: &str, path: &Path, question: &str) -> Option<String> {
    if !addr.ip().is_loopback() {
        return None;
    }
    if quorum_types::content_safety::check_path_explicit_content(path).is_blocked() {
        tracing::warn!(path = %path.display(), "Refusing local vision inspection for explicit/pornographic image path");
        return None;
    }
    let canonical_path = std::fs::canonicalize(path).ok()?;
    if quorum_types::content_safety::check_path_explicit_content(&canonical_path).is_blocked() {
        tracing::warn!(path = %canonical_path.display(), "Refusing local vision inspection for canonical explicit/pornographic image path");
        return None;
    }
    let meta = std::fs::metadata(&canonical_path).ok()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_VISION_IMAGE_BYTES {
        return None;
    }
    if is_cloud_placeholder_for_vision(&meta) {
        let policy = crate::global_mesh_dlp_controller()
            .get_cloud_drives_settings()
            .placeholder_policy()
            .unwrap_or_default();
        match policy {
            quorum_types::CloudPlaceholderPolicy::LocallySyncedOnly => return None,
            quorum_types::CloudPlaceholderPolicy::HydrateOnDemand { max_file_size_bytes } => {
                if meta.len() > max_file_size_bytes {
                    return None;
                }
            }
        }
    }
    let bytes = std::fs::read(&canonical_path).ok()?;
    if let Some(hook) = PIXEL_SAFETY_HOOK.get() {
        if !hook(&canonical_path, &bytes) {
            tracing::warn!(path = %canonical_path.display(), "Refusing local vision inspection: blocked by raster pixel content-safety filter");
            return None;
        }
    }
    let key = blake3::hash(&bytes).to_hex().to_string();
    if let Some(hit) = cache().lock().ok().and_then(|c| c.get(&key).cloned()) {
        return Some(hit);
    }

    let prompt = if question.trim().is_empty() {
        VISION_PROMPT.to_string()
    } else {
        format!("{VISION_PROMPT} The user asked: \"{}\". Mention details relevant to that question.", question.trim())
    };
    let payload = serde_json::json!({
        "model": model,
        "prompt": prompt,
        "images": [base64_encode(&bytes)],
        "stream": false,
        "keep_alive": "30m",
        "options": { "temperature": 0.1, "num_predict": 220 }
    })
    .to_string();
    let request = format!(
        "POST /api/generate HTTP/1.0\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );

    let mut stream = TcpStream::connect_timeout(addr, Duration::from_millis(800)).ok()?;
    let _ = stream.set_write_timeout(Some(Duration::from_millis(2000)));
    let _ = stream.set_read_timeout(Some(Duration::from_millis(2500)));
    stream.write_all(request.as_bytes()).ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw);
    let body_at = text.find("\r\n\r\n").map(|i| i + 4).or_else(|| text.find("\n\n").map(|i| i + 2))?;
    let status_ok = text.lines().next().map_or(false, |l| l.contains(" 200"));
    if !status_ok {
        tracing::warn!(model, path = %path.display(), "Ollama vision request failed: {}", text.lines().next().unwrap_or(""));
        return None;
    }
    let val: serde_json::Value = serde_json::from_str(text[body_at..].trim()).ok()?;
    let desc = val.get("response")?.as_str()?.trim().to_string();
    if desc.len() < 12 {
        return None;
    }
    if quorum_types::content_safety::check_text_explicit_content(&desc).is_blocked() {
        tracing::warn!(path = %path.display(), "Discarded vision description flagged by pornography/explicit content safety filter");
        return None;
    }
    if let Ok(mut c) = cache().lock() {
        if c.len() > 4096 {
            c.clear();
        }
        c.insert(key, desc.clone());
    }
    Some(desc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_rfc4648_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn picks_preferred_installed_vision_model() {
        let installed = vec!["qwen2.5:7b".to_string(), "llava:7b".to_string(), "moondream:latest".to_string()];
        assert_eq!(pick_vision_model(&installed).as_deref(), Some("moondream:latest"));
        let none = vec!["qwen2.5:7b".to_string()];
        assert_eq!(pick_vision_model(&none), None);
    }

    #[test]
    fn detects_image_chunks() {
        assert!(is_image_chunk_text("[Image Document: dog.119.jpg]\nFormat: JPEG"));
        assert!(!is_image_chunk_text("[Audio Document: x.mp3]"));
    }
}
