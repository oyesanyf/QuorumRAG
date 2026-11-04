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
    NotFound,
}

impl MediaPathError {
    fn into_response(self) -> Response {
        let (code, msg) = match self {
            Self::Invalid => (StatusCode::BAD_REQUEST, "Invalid media path"),
            Self::Executable => (StatusCode::FORBIDDEN, "Executables and shared libraries are never served"),
            Self::NotIndexed => (StatusCode::FORBIDDEN, "Access denied: file is not part of the indexed knowledge base"),
            Self::TierDenied => (StatusCode::FORBIDDEN, "Access denied: file is above the permitted access tier"),
            Self::NotFound => (StatusCode::NOT_FOUND, "Indexed file no longer exists on disk"),
        };
        (code, msg).into_response()
    }
}

/// Lexical validation shared by both endpoints (no I/O).
pub fn validate_media_path_syntax(raw: &str) -> Result<PathBuf, MediaPathError> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 4096 || raw.contains('\0') {
        return Err(MediaPathError::Invalid);
    }
    let lower = raw.to_ascii_lowercase();
    if lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") || lower.contains("%00") {
        return Err(MediaPathError::Invalid);
    }
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(MediaPathError::Invalid);
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(MediaPathError::Invalid);
    }
    // NTFS alternate data streams: a ':' anywhere after the drive designator.
    #[cfg(windows)]
    {
        let s = raw.strip_prefix(r"\\?\").unwrap_or(raw);
        if s.get(2..).map_or(false, |rest| rest.contains(':')) {
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

/// Full gate: syntax, index membership at tier 0, and on-disk existence.
pub fn authorize_media_path(state: &DaemonState, raw: &str) -> Result<PathBuf, MediaPathError> {
    let path = validate_media_path_syntax(raw)?;
    let key = raw.trim();
    let tier = state
        .storage
        .indexed_path_min_tier(key)
        .map_err(|_| MediaPathError::NotIndexed)?
        .ok_or(MediaPathError::NotIndexed)?;
    if tier > MEDIA_MAX_TIER {
        return Err(MediaPathError::TierDenied);
    }
    match std::fs::metadata(&path) {
        Ok(m) if m.is_file() => Ok(path),
        _ => Err(MediaPathError::NotFound),
    }
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
        .map(|c| if (c.is_ascii_graphic() && c != '"' && c != '\\') || c == ' ' { c } else { '_' })
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
    HeaderValue::from_str(&format!("{kind}; filename=\"{ascii}\"; filename*=UTF-8''{encoded}"))
        .unwrap_or_else(|_| HeaderValue::from_static("inline"))
}

/// GET /api/media?path=... streams an indexed file with MIME type and HTTP Range support.
pub async fn serve_media_handler(
    State(state): State<Arc<DaemonState>>,
    Query(q): Query<MediaQuery>,
    req: Request,
) -> Response {
    let path = match authorize_media_path(&state, &q.path) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let attachment = matches!(q.download.as_deref(), Some("1") | Some("true"));
    let mime = mime_for(&path);

    // Forward only the conditional/range headers ServeFile understands.
    let mut fwd = Request::builder().method("GET").uri("/");
    for h in [header::RANGE, header::IF_RANGE, header::IF_MODIFIED_SINCE, header::IF_NONE_MATCH] {
        if let Some(v) = req.headers().get(&h) {
            fwd = fwd.header(h, v.clone());
        }
    }
    let fwd = match fwd.body(Body::empty()) {
        Ok(r) => r,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let mime_hv = HeaderValue::from_str(&mime).unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    let resp = match ServeFile::new(&path).oneshot(fwd).await {
        Ok(r) => r,
        Err(never) => match never {},
    };
    let mut resp = resp.map(Body::new);
    let status = resp.status();
    let h = resp.headers_mut();
    if status.is_success() {
        h.insert(header::CONTENT_TYPE, mime_hv);
        h.insert(header::CONTENT_DISPOSITION, content_disposition(&path, attachment));
    }
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, max-age=300"));
    // Indexed HTML or SVG must never execute script in the UI origin.
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; sandbox"),
    );
    resp
}

/// POST /api/open-file opens an indexed file in the OS default viewer (loopback callers only).
pub async fn open_file_handler(
    State(state): State<Arc<DaemonState>>,
    connect: Option<ConnectInfo<SocketAddr>>,
    Json(payload): Json<OpenFileRequest>,
) -> Response {
    let is_loopback = connect.map(|ConnectInfo(addr)| addr.ip().is_loopback()).unwrap_or(false);
    if !is_loopback {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Opening files in the system viewer is only allowed from this computer" })),
        )
            .into_response();
    }
    let path = match authorize_media_path(&state, &payload.path) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    match open::that_detached(&path) {
        Ok(()) => Json(serde_json::json!({ "status": "ok", "path": path.to_string_lossy() })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("Could not open file: {e}") })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal_relative_nul_and_encoded() {
        assert_eq!(validate_media_path_syntax(""), Err(MediaPathError::Invalid));
        assert_eq!(validate_media_path_syntax("relative/dog.jpg"), Err(MediaPathError::Invalid));
        assert_eq!(validate_media_path_syntax("a\0b"), Err(MediaPathError::Invalid));
        #[cfg(windows)]
        {
            assert_eq!(validate_media_path_syntax(r"D:\dataset\..\Windows\win.ini"), Err(MediaPathError::Invalid));
            assert_eq!(validate_media_path_syntax(r"D:\dataset\%2e%2e\x.jpg"), Err(MediaPathError::Invalid));
            assert_eq!(validate_media_path_syntax(r"D:\dataset\dog.jpg:secret"), Err(MediaPathError::Invalid));
            assert!(validate_media_path_syntax(r"D:\dataset\images\data\dogs\dog.119.jpg").is_ok());
        }
    }

    #[test]
    fn refuses_executables_and_libraries() {
        #[cfg(windows)]
        {
            assert_eq!(validate_media_path_syntax(r"C:\Windows\System32\cmd.exe"), Err(MediaPathError::Executable));
            assert_eq!(validate_media_path_syntax(r"C:\x\lib.dll"), Err(MediaPathError::Executable));
        }
        #[cfg(not(windows))]
        {
            assert_eq!(validate_media_path_syntax("/usr/lib/libc.so"), Err(MediaPathError::Executable));
            assert_eq!(validate_media_path_syntax("/x/libfoo.dylib"), Err(MediaPathError::Executable));
        }
    }

    #[test]
    fn content_disposition_is_header_safe() {
        let hv = content_disposition(Path::new("Savannah Woman \"x\".mp3"), true);
        let s = hv.to_str().unwrap();
        assert!(s.starts_with("attachment; filename=\"Savannah Woman _x_.mp3\""), "{s}");
        assert!(s.contains("filename*=UTF-8''Savannah%20Woman%20%22x%22.mp3"), "{s}");
    }
}
