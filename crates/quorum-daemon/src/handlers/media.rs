//! Secure local media streaming and system-viewer launch for cited files.
//!
//! `GET /api/media?path=<file_path>` streams a file to the Web UI (inline images, `<audio>`,
//! `<video>`, PDF preview, downloads). It is gated so that only files that are part of the
//! indexed knowledge base at access tier 0 can be served: the exact path must exist as a
//! `file_path` term in the Tantivy index. Arbitrary disk reads are therefore impossible, and
//! compiled executables / shared libraries are refused even if indexed.
//!
//! `POST /api/open-file` opens an indexed file in the OS default application, but only for
//! requests arriving on the loopback interface.

use axum::body::Body;
use axum::extract::{ConnectInfo, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use tower::ServiceExt;
use tower_http::services::ServeFile;

use crate::state::DaemonState;

/// Highest access tier the public Web UI may stream (matches chat default `access_tier = 0`).
pub const MEDIA_MAX_TIER: u8 = 0;

#[derive(Debug, Deserialize)]
pub struct MediaQuery {
    pub path: String,
    /// `download=1` forces `Content-Disposition: attachment`.
    #[serde(default)]
    pub download: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OpenFileRequest {
    pub path: String,
}

/// Why a media path was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum MediaPathError {
    Invalid,
    Executable,
    NotIndexed,
    TierDenied,
    ExplicitContentBlocked,
    NotFound,
}

impl MediaPathError {
    fn into_response(self) -> Response {
        let (code, msg) = match self {
            Self::Invalid => (StatusCode::BAD_REQUEST, "Invalid media path"),
            Self::Executable => (
                StatusCode::FORBIDDEN,
                "Executables and shared libraries are never served",
            ),
            Self::NotIndexed => (
                StatusCode::FORBIDDEN,
                "Access denied: file is not part of the indexed knowledge base",
            ),
            Self::TierDenied => (
                StatusCode::FORBIDDEN,
                "Access denied: file is above the permitted access tier",
            ),
            Self::ExplicitContentBlocked => (
                StatusCode::FORBIDDEN,
                "Access denied: blocked by pornography and explicit content safety filter",
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "Indexed file no longer exists on disk",
            ),
        };
        (code, msg).into_response()
    }
}

fn validate_media_lexical_and_traversal(raw: &str) -> Result<(), MediaPathError> {
    if raw.len() > 4096 {
        return Err(MediaPathError::Invalid);
    }
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || raw != trimmed
        || raw.contains('\0')
        || raw.chars().any(|c| c.is_control())
        || raw.chars().any(|c| {
            matches!(
                c,
                '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}'
            )
        })
    {
        return Err(MediaPathError::Invalid);
    }
    let lower = raw.to_ascii_lowercase();
    if lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%00")
        || lower.contains("%252e")
        || lower.contains("%252f")
        || lower.contains("%255c")
        || lower.contains("%2500")
        || lower.contains("%25")
    {
        return Err(MediaPathError::Invalid);
    }
    if raw.contains("..") {
        return Err(MediaPathError::Invalid);
    }
    Ok(())
}

/// Lexical validation shared by both endpoints (no I/O).
pub fn validate_media_path_syntax(raw: &str) -> Result<PathBuf, MediaPathError> {
    validate_media_lexical_and_traversal(raw)?;
    if quorum_coordinator::artemis_airgap::is_artemis_uri(raw) {
        return Err(MediaPathError::Invalid);
    }
    let lower = raw.to_ascii_lowercase();
    if raw.starts_with(r"\\")
        || raw.starts_with("//")
        || lower.contains(r"\\?\unc\")
        || lower.contains("//?/unc/")
    {
        return Err(MediaPathError::Invalid);
    }
    for seg in raw.split(['/', '\\']) {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg != seg.trim() || seg.ends_with('.') || seg.ends_with(' ') {
            return Err(MediaPathError::Invalid);
        }
    }
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(MediaPathError::Invalid);
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(MediaPathError::Invalid);
    }
    // NTFS alternate data streams and drive-relative paths: require valid `X:\` or `X:/`
    // prefix and reject any ':' outside index 1.
    #[cfg(windows)]
    {
        let bytes = raw.as_bytes();
        let is_windows_drive = bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/');
        if !is_windows_drive || bytes[2..].contains(&b':') {
            return Err(MediaPathError::Invalid);
        }
    }
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if quorum_classifier::is_binary_executable_extension(ext) {
            return Err(MediaPathError::Executable);
        }
    }
    Ok(path)
}

/// Full gate: syntax, cloud-drive / Artemis fail-closed check, index membership, tier policy, and on-disk existence.
pub fn authorize_media_path_with_loopback(
    state: &DaemonState,
    raw: &str,
    is_loopback: bool,
) -> Result<PathBuf, MediaPathError> {
    validate_media_lexical_and_traversal(raw)?;
    let key = raw.trim();
    if quorum_coordinator::artemis_airgap::is_artemis_uri(key) {
        return Err(MediaPathError::TierDenied);
    }
    let path = validate_media_path_syntax(raw)?;
    if quorum_types::content_safety::check_path_explicit_content(&path).is_blocked() {
        return Err(MediaPathError::ExplicitContentBlocked);
    }

    let settings = quorum_coordinator::global_mesh_dlp_controller()
        .settings
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    let mut matched_prefixes: Vec<(usize, &str, bool)> = Vec::new();
    for drv in &settings.cloud_drives.drives {
        for p in drv.root_path.iter().chain(drv.custom_paths.iter()) {
            if quorum_types::path_matches_prefix(key, p).unwrap_or(false) {
                let norm_len = quorum_types::normalize_prefix_for_match(p)
                    .map(|n| n.len())
                    .unwrap_or(p.len());
                matched_prefixes.push((norm_len, p.as_str(), drv.enabled));
            }
        }
    }
    if !matched_prefixes.is_empty() {
        let max_len = matched_prefixes
            .iter()
            .map(|(len, _, _)| *len)
            .max()
            .unwrap_or(0);
        let best_matches: Vec<&(usize, &str, bool)> = matched_prefixes
            .iter()
            .filter(|(len, _, _)| *len == max_len)
            .collect();
        let any_disabled = best_matches.iter().any(|(_, _, enabled)| !*enabled);
        let any_enabled_mounted = best_matches
            .iter()
            .any(|(_, p, enabled)| {
                *enabled && quorum_types::session_fs_bridge::path_is_dir_or_bridged(Path::new(p))
            });
        if any_disabled || !any_enabled_mounted {
            return Err(MediaPathError::TierDenied);
        }
    }

    let tier = state
        .storage
        .indexed_path_min_tier(key)
        .map_err(|_| MediaPathError::NotIndexed)?
        .ok_or(MediaPathError::NotIndexed)?;
    if tier > MEDIA_MAX_TIER {
        if !is_loopback {
            return Err(MediaPathError::TierDenied);
        }
        let policy =
            quorum_coordinator::resolve_local_retrieval_policy(&settings, MEDIA_MAX_TIER, &[]);
        if !policy.permits_local_path_and_tier(key, tier, false) {
            return Err(MediaPathError::TierDenied);
        }
    }
    match std::fs::metadata(&path) {
        Ok(m) if m.is_file() => Ok(path),
        _ => match quorum_types::session_fs_bridge::stat_via_bridge(&path) {
            Some(st) if st.exists && st.is_file => Ok(path),
            _ => Err(MediaPathError::NotFound),
        },
    }
}

/// Full gate (strict Tier 0 compatibility entrypoint used by `export.rs`).
pub fn authorize_media_path(state: &DaemonState, raw: &str) -> Result<PathBuf, MediaPathError> {
    authorize_media_path_with_loopback(state, raw, false)
}

fn mime_for(path: &Path) -> String {
    mime_guess::from_path(path)
        .first()
        .map(|m| m.essence_str().to_string())
        .unwrap_or_else(|| "application/octet-stream".to_string())
}

fn content_disposition(path: &Path, attachment: bool) -> HeaderValue {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    // ASCII fallback + RFC 5987 UTF-8 filename.
    let ascii: String = name
        .chars()
        .map(|c| {
            if (c.is_ascii_graphic() && c != '"' && c != '\\') || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let encoded: String = name
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{:02X}", b)
            }
        })
        .collect();
    let kind = if attachment { "attachment" } else { "inline" };
    HeaderValue::from_str(&format!(
        "{kind}; filename=\"{ascii}\"; filename*=UTF-8''{encoded}"
    ))
    .unwrap_or_else(|_| HeaderValue::from_static("inline"))
}

/// GET /api/media?path=... streams an indexed file with MIME type and HTTP Range support.
pub async fn serve_media_handler(
    State(state): State<Arc<DaemonState>>,
    connect: Option<ConnectInfo<SocketAddr>>,
    Query(q): Query<MediaQuery>,
    req: Request,
) -> Response {
    let is_loopback = connect
        .map(|ConnectInfo(addr)| addr.ip().is_loopback())
        .unwrap_or(true);
    let path = match authorize_media_path_with_loopback(&state, &q.path, is_loopback) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    // Pixel-level + path pornography/explicit image safety gate before streaming any bytes.
    let path_for_check = path.clone();
    let safety = tokio::task::spawn_blocking(move || {
        quorum_ingest::content_safety::evaluate_image_file_safety(&path_for_check)
    })
    .await
    .unwrap_or_else(|_| quorum_ingest::content_safety::ContentSafetyDecision::Blocked {
        category: "content_safety_worker_error",
        reason: "Content safety check worker failed (fail-closed)".to_string(),
        confidence: 1.0,
    });
    if let quorum_ingest::content_safety::ContentSafetyDecision::Blocked { reason, .. } = safety {
        tracing::warn!(path = %path.display(), reason = %reason, "Blocked explicit image at /api/media and purging from index");
        let storage_for_purge = Arc::clone(&state.storage);
        let dedup_for_purge = Arc::clone(&state.dedup);
        let coord_for_purge = Arc::clone(&state.coordinator);
        let path_for_purge = path.clone();
        let key_for_purge = path.to_string_lossy().to_string();
        tokio::spawn(async move {
            let _ = storage_for_purge.delete_by_file_path(&key_for_purge).await;
            dedup_for_purge.remove_file(&path_for_purge);
            coord_for_purge.cache_clear_all();
        });
        return MediaPathError::ExplicitContentBlocked.into_response();
    }
    let attachment = matches!(q.download.as_deref(), Some("1") | Some("true"));
    let mime = mime_for(&path);

    // Forward only the conditional/range headers ServeFile understands.
    let mut fwd = Request::builder().method("GET").uri("/");
    for h in [
        header::RANGE,
        header::IF_RANGE,
        header::IF_MODIFIED_SINCE,
        header::IF_NONE_MATCH,
    ] {
        if let Some(v) = req.headers().get(&h) {
            fwd = fwd.header(h, v.clone());
        }
    }
    let fwd = match fwd.body(Body::empty()) {
        Ok(r) => r,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let mime_hv = HeaderValue::from_str(&mime)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    let mut resp = if path.is_file() {
        let resp = match ServeFile::new(&path).oneshot(fwd).await {
            Ok(r) => r,
            Err(never) => match never {},
        };
        resp.map(Body::new)
    } else {
        let policy = quorum_coordinator::global_mesh_dlp_controller()
            .get_cloud_drives_settings()
            .placeholder_policy()
            .unwrap_or_default();
        let path_c = path.clone();
        match tokio::task::spawn_blocking(move || {
            quorum_types::session_fs_bridge::read_bytes_via_bridge(&path_c, 0, policy)
        })
        .await
        {
            Ok(Ok(bytes)) => (StatusCode::OK, Body::from(bytes)).into_response(),
            _ => return MediaPathError::NotFound.into_response(),
        }
    };
    let status = resp.status();
    let h = resp.headers_mut();
    if status.is_success() {
        h.insert(header::CONTENT_TYPE, mime_hv);
        h.insert(
            header::CONTENT_DISPOSITION,
            content_disposition(&path, attachment),
        );
    }
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=300"),
    );
    // Indexed HTML or SVG must never execute script in the UI origin.
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; sandbox"),
    );
    resp
}

/// POST /api/open-file resolves an indexed file or its parent directory in Pure Rust for in-UI viewing (loopback callers only).
/// Never launches external OS File Explorer or shell subprocesses.
pub async fn open_file_handler(
    State(state): State<Arc<DaemonState>>,
    connect: Option<ConnectInfo<SocketAddr>>,
    Json(payload): Json<OpenFileRequest>,
) -> Response {
    let is_loopback = connect
        .map(|ConnectInfo(addr)| addr.ip().is_loopback())
        .unwrap_or(true);
    if !is_loopback {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Opening files in the UI viewer is only allowed from this computer" })),
        )
            .into_response();
    }
    let path = match authorize_media_path_with_loopback(&state, &payload.path, true) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(quorum_types::content_safety::is_visual_media_extension)
    {
        let path_for_check = path.clone();
        let safety = tokio::task::spawn_blocking(move || {
            quorum_ingest::content_safety::evaluate_image_file_safety(&path_for_check)
        })
        .await
        .unwrap_or_else(|_| quorum_ingest::content_safety::ContentSafetyDecision::Blocked {
            category: "content_safety_worker_error",
            reason: "Content safety check worker failed (fail-closed)".to_string(),
            confidence: 1.0,
        });
        if let quorum_ingest::content_safety::ContentSafetyDecision::Blocked { reason, .. } =
            safety
        {
            tracing::warn!(
                path = %path.display(),
                reason = %reason,
                "Blocked explicit image at /api/open-file and purging from index"
            );
            let storage_for_purge = Arc::clone(&state.storage);
            let dedup_for_purge = Arc::clone(&state.dedup);
            let coord_for_purge = Arc::clone(&state.coordinator);
            let path_for_purge = path.clone();
            let key_for_purge = path.to_string_lossy().to_string();
            tokio::spawn(async move {
                let _ = storage_for_purge.delete_by_file_path(&key_for_purge).await;
                dedup_for_purge.remove_file(&path_for_purge);
                coord_for_purge.cache_clear_all();
            });
            return MediaPathError::ExplicitContentBlocked.into_response();
        }
    }
    let parent_dir = path
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    Json(serde_json::json!({
        "status": "ok",
        "engine": "pure_rust_in_ui",
        "path": path.to_string_lossy(),
        "parent_dir": parent_dir
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal_relative_nul_and_encoded() {
        assert_eq!(validate_media_path_syntax(""), Err(MediaPathError::Invalid));
        assert_eq!(
            validate_media_path_syntax("relative/dog.jpg"),
            Err(MediaPathError::Invalid)
        );
        assert_eq!(
            validate_media_path_syntax("a\0b"),
            Err(MediaPathError::Invalid)
        );
        #[cfg(windows)]
        {
            assert_eq!(
                validate_media_path_syntax(r"D:\dataset\..\Windows\win.ini"),
                Err(MediaPathError::Invalid)
            );
            assert_eq!(
                validate_media_path_syntax(r"D:\dataset\%2e%2e\x.jpg"),
                Err(MediaPathError::Invalid)
            );
            assert_eq!(
                validate_media_path_syntax(r"D:\dataset\dog.jpg:secret"),
                Err(MediaPathError::Invalid)
            );
            assert!(validate_media_path_syntax(r"D:\dataset\images\data\dogs\dog.119.jpg").is_ok());
        }
    }

    #[test]
    fn refuses_executables_and_libraries() {
        #[cfg(windows)]
        {
            assert_eq!(
                validate_media_path_syntax(r"C:\Windows\System32\cmd.exe"),
                Err(MediaPathError::Executable)
            );
            assert_eq!(
                validate_media_path_syntax(r"C:\x\lib.dll"),
                Err(MediaPathError::Executable)
            );
        }
        #[cfg(not(windows))]
        {
            assert_eq!(
                validate_media_path_syntax("/usr/lib/libc.so"),
                Err(MediaPathError::Executable)
            );
            assert_eq!(
                validate_media_path_syntax("/x/libfoo.dylib"),
                Err(MediaPathError::Executable)
            );
        }
    }

    #[test]
    fn content_disposition_is_header_safe() {
        let hv = content_disposition(Path::new("Savannah Woman \"x\".mp3"), true);
        let s = hv.to_str().unwrap();
        assert!(
            s.starts_with("attachment; filename=\"Savannah Woman _x_.mp3\""),
            "{s}"
        );
        assert!(
            s.contains("filename*=UTF-8''Savannah%20Woman%20%22x%22.mp3"),
            "{s}"
        );
    }
}
