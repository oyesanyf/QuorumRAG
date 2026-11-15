use axum::{
    body::Body,
    http::{header, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;
use std::borrow::Cow;
use std::path::{Component, Path};

#[derive(RustEmbed)]
#[folder = "assets/"]
pub struct WebAssets;

/// Fail-closed `Path::join` replacement guard for relative UI asset lookups:
/// rejects drive letters (`:`), leading slashes/backslashes, UNC prefixes (`\\`),
/// parent traversal (`..`), NUL bytes, percent-encoded traversal (`%2e`, `%2f`, `%5c`, `%00`),
/// NTFS Alternate Data Streams, and any non-`Component::Normal` path segment.
fn is_safe_relative_asset_path(target: &str) -> bool {
    if target.is_empty()
        || target.contains(':')
        || target.starts_with('/')
        || target.starts_with('\\')
        || target.contains("\\\\")
        || target.contains("..")
        || target.contains('\0')
    {
        return false;
    }
    let lower = target.to_ascii_lowercase();
    if lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%00")
    {
        return false;
    }
    let p = Path::new(target);
    let mut saw_normal = false;
    for comp in p.components() {
        match comp {
            Component::Normal(_) => saw_normal = true,
            Component::CurDir => {}
            _ => return false,
        }
    }
    saw_normal
}

/// Compile-time embedded fallback bytes for core UI assets so that under any build profile
/// (debug or release) and on any machine without the source tree, every UI asset is 100% baked into the binary.
pub fn compile_time_embedded_asset(target: &str) -> Option<(&'static [u8], &'static str)> {
    match target {
        "index.html" => Some((
            include_bytes!("../assets/index.html"),
            "text/html; charset=utf-8",
        )),
        "app.js" => Some((
            include_bytes!("../assets/app.js"),
            "application/javascript; charset=utf-8",
        )),
        "styles.css" => Some((
            include_bytes!("../assets/styles.css"),
            "text/css; charset=utf-8",
        )),
        "langextract.html" => Some((
            include_bytes!("../assets/langextract.html"),
            "text/html; charset=utf-8",
        )),
        "favicon.svg" => Some((
            include_bytes!("../assets/favicon.svg"),
            "image/svg+xml",
        )),
        _ => None,
    }
}

/// Retrieves embedded static asset bytes and its MIME content-type (checking disk first for live hot-reload).
pub fn get_asset(path: &str) -> Option<(Cow<'static, [u8]>, &'static str)> {
    let clean_path = path.trim_start_matches('/');
    let stripped = clean_path
        .strip_prefix("../assets/")
        .or_else(|| clean_path.strip_prefix("assets/"))
        .unwrap_or(clean_path);
    if stripped.contains("..") || stripped.contains('\0') {
        return None;
    }
    let target = if stripped.is_empty() {
        "index.html"
    } else {
        stripped
    };

    if is_safe_relative_asset_path(target) {
        for base in [
            Path::new("crates/quorum-ui/assets"),
            Path::new("assets"),
            Path::new(r"d:\harfile\QuorumRAG\crates\quorum-ui\assets"),
        ] {
            let candidate = base.join(target);
            if let Ok(bytes) = std::fs::read(&candidate) {
                let mime = mime_guess::from_path(target)
                    .first_raw()
                    .unwrap_or("application/octet-stream");
                return Some((Cow::Owned(bytes), mime));
            }
        }
    }

    if let Some(file) = WebAssets::get(target) {
        let mime = mime_guess::from_path(target)
            .first_raw()
            .unwrap_or("application/octet-stream");
        return Some((file.data, mime));
    }

    compile_time_embedded_asset(target).map(|(bytes, mime)| (Cow::Borrowed(bytes), mime))
}

/// Returns the index.html string (checking disk first for live hot-reload, then embedded binary bytes).
pub fn get_index_html() -> String {
    for base in [
        Path::new("crates/quorum-ui/assets/index.html"),
        Path::new("assets/index.html"),
        Path::new(r"d:\harfile\QuorumRAG\crates\quorum-ui\assets\index.html"),
    ] {
        if let Ok(bytes) = std::fs::read(base) {
            return String::from_utf8_lossy(&bytes).to_string();
        }
    }
    WebAssets::get("index.html")
        .map(|f| String::from_utf8_lossy(&f.data).to_string())
        .unwrap_or_else(|| include_str!("../assets/index.html").to_string())
}

/// Static asset handler with live disk hot-reload and SPA fallback to index.html.
pub async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let stripped = path.strip_prefix("assets/").unwrap_or(path);
    let target_path = if stripped.is_empty() { "index.html" } else { stripped };

    // Try reading live asset from disk first so UI edits apply immediately without re-linking
    if is_safe_relative_asset_path(target_path) {
        for base in [
            Path::new("crates/quorum-ui/assets"),
            Path::new("assets"),
            Path::new(r"d:\harfile\QuorumRAG\crates\quorum-ui\assets"),
        ] {
            let candidate = base.join(target_path);
            let cache_header = if target_path == "index.html" {
                "no-cache, no-store, must-revalidate"
            } else {
                "public, max-age=0, must-revalidate"
            };
            if let Ok(bytes) = std::fs::read(&candidate) {
                let mime = mime_guess::from_path(target_path)
                    .first_raw()
                    .unwrap_or("application/octet-stream");
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        header::CONTENT_TYPE,
                        HeaderValue::from_str(mime)
                            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
                    )
                    .header(header::CACHE_CONTROL, cache_header)
                    .body(Body::from(bytes))
                    .unwrap_or_else(|_| {
                        (StatusCode::INTERNAL_SERVER_ERROR, "Response building failed")
                            .into_response()
                    });
            }
        }
    }

    let cache_header = if target_path == "index.html" {
        "no-cache, no-store, must-revalidate"
    } else {
        "public, max-age=0, must-revalidate"
    };

    if let Some(content) = WebAssets::get(target_path) {
        let mime = mime_guess::from_path(target_path)
            .first_raw()
            .unwrap_or("application/octet-stream");
        return Response::builder()
            .status(StatusCode::OK)
            .header(
                header::CONTENT_TYPE,
                HeaderValue::from_str(mime)
                    .unwrap_or(HeaderValue::from_static("application/octet-stream")),
            )
            .header(header::CACHE_CONTROL, cache_header)
            .body(Body::from(content.data))
            .unwrap_or_else(|_| {
                (StatusCode::INTERNAL_SERVER_ERROR, "Response building failed").into_response()
            });
    }

    if let Some((bytes, mime)) = compile_time_embedded_asset(target_path) {
        return Response::builder()
            .status(StatusCode::OK)
            .header(
                header::CONTENT_TYPE,
                HeaderValue::from_str(mime)
                    .unwrap_or(HeaderValue::from_static("application/octet-stream")),
            )
            .header(header::CACHE_CONTROL, cache_header)
            .body(Body::from(bytes))
            .unwrap_or_else(|_| {
                (StatusCode::INTERNAL_SERVER_ERROR, "Response building failed").into_response()
            });
    }

    if let Some(content) = WebAssets::get("index.html") {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
            .body(Body::from(content.data))
            .unwrap_or_else(|_| {
                (StatusCode::INTERNAL_SERVER_ERROR, "Response building failed").into_response()
            });
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
        .body(Body::from(include_bytes!("../assets/index.html").as_slice()))
        .unwrap_or_else(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, "Response building failed").into_response()
        })
}
