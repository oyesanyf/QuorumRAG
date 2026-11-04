use axum::{
    body::Body,
    http::{header, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;
use std::borrow::Cow;

#[derive(RustEmbed)]
#[folder = "assets/"]
pub struct WebAssets;

/// Retrieves embedded static asset bytes and its MIME content-type (checking disk first for live hot-reload).
pub fn get_asset(path: &str) -> Option<(Cow<'static, [u8]>, &'static str)> {
    let clean_path = path.trim_start_matches('/');
    let stripped = clean_path.strip_prefix("assets/").unwrap_or(clean_path);
    let target = if stripped.is_empty() {
        "index.html"
    } else {
        stripped
    };

    if !target.contains("..") {
        for base in [
            std::path::Path::new("crates/quorum-ui/assets"),
            std::path::Path::new(r"d:\harfile\QuorumRAG\crates\quorum-ui\assets"),
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

    WebAssets::get(target).map(|file| {
        let mime = mime_guess::from_path(target)
            .first_raw()
            .unwrap_or("application/octet-stream");
        (file.data, mime)
    })
}

/// Returns the index.html string (checking disk first for live hot-reload).
pub fn get_index_html() -> String {
    for base in [
        std::path::Path::new("crates/quorum-ui/assets/index.html"),
        std::path::Path::new(r"d:\harfile\QuorumRAG\crates\quorum-ui\assets\index.html"),
    ] {
        if let Ok(bytes) = std::fs::read(base) {
            return String::from_utf8_lossy(&bytes).to_string();
        }
    }
    WebAssets::get("index.html")
        .map(|f| String::from_utf8_lossy(&f.data).to_string())
        .unwrap_or_else(|| "<html><body><h3>QuorumRAG Web UI</h3></body></html>".to_string())
}

/// Static asset handler with live disk hot-reload and SPA fallback to index.html.
pub async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let stripped = path.strip_prefix("assets/").unwrap_or(path);
    let target_path = if stripped.is_empty() { "index.html" } else { stripped };

    // Try reading live asset from disk first so UI edits apply immediately without re-linking
    if !target_path.contains("..") {
        for base in [
            std::path::Path::new("crates/quorum-ui/assets"),
            std::path::Path::new(r"d:\harfile\QuorumRAG\crates\quorum-ui\assets"),
        ] {
            let candidate = base.join(target_path);
            let cache_header = if target_path == "index.html" {
                "no-cache, no-store, must-revalidate"
            } else {
                "public, max-age=3600"
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
        "public, max-age=3600"
    };

    match WebAssets::get(target_path) {
        Some(content) => {
            let mime = mime_guess::from_path(target_path)
                .first_raw()
                .unwrap_or("application/octet-stream");
            Response::builder()
                .status(StatusCode::OK)
                .header(
                    header::CONTENT_TYPE,
                    HeaderValue::from_str(mime).unwrap_or(HeaderValue::from_static("application/octet-stream")),
                )
                .header(header::CACHE_CONTROL, cache_header)
                .body(Body::from(content.data))
                .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Response building failed").into_response())
        }
        None => match WebAssets::get("index.html") {
            Some(content) => Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
                .body(Body::from(content.data))
                .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Response building failed").into_response()),
            None => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("404 Not Found"))
                .unwrap_or_else(|_| (StatusCode::NOT_FOUND, "Not Found").into_response()),
        },
    }
}
