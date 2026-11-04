//! Empirical Adversarial Stress Suite for QuorumRAG Web UI
//!
//! Areas Covered:
//! 1. Asset Stress & Malformed URI Traversal Probe
//! 2. 5-Theme CSS & ChatGPT Layout Dimensions Assertion (260px sidebar, 768px reading column)
//! 3. SPA Fallback vs Missing Asset Fail-Closed Routing

use axum::http::{StatusCode, Uri};
use quorum_ui::{get_asset, get_index_html, static_handler, WebAssets};

// ============================================================================
// 1. ASSET STRESS & MALFORMED URI PROBE
// ============================================================================

#[tokio::test]
async fn test_uri_traversal_attempts_do_not_leak_or_crash() {
    let malicious_uris = [
        "/../../Cargo.toml",
        "/../../../etc/passwd",
        "/..%2f..%2fCargo.toml",
        "/%2e%2e/%2e%2e/Cargo.toml",
        "/....//....//Cargo.toml",
        "/..\\..\\windows\\win.ini",
        "/assets/../../src/lib.rs",
        "/assets/..%2f..%2fCargo.toml",
        "/styles.css\0malicious",
        "/assets/%00/index.html",
        "/%2e%2e%2f%2e%2e%2fCargo.toml",
    ];

    for uri_str in malicious_uris {
        // Test static_handler doesn't panic and either serves SPA fallback (index.html) or fails cleanly
        if let Ok(uri) = uri_str.parse::<Uri>() {
            let resp = static_handler(uri).await;
            let status = resp.status();
            assert!(
                status == StatusCode::OK || status == StatusCode::NOT_FOUND || status == StatusCode::BAD_REQUEST,
                "URI '{}' returned unexpected status: {:?}",
                uri_str,
                status
            );

            // Read response body and ensure no external system files or Cargo.toml contents are leaked
            let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
                .await
                .expect("Valid body bytes");
            let body_str = String::from_utf8_lossy(&body_bytes);

            // Must NEVER leak Cargo.toml or external system files
            assert!(
                !body_str.contains("[workspace]") && !body_str.contains("root:x:0:0"),
                "Security violation: URI '{}' leaked sensitive file content!",
                uri_str
            );
        }
    }
}

#[test]
fn test_get_asset_malformed_paths_fail_closed() {
    let external_probes = [
        "../../Cargo.toml",
        "/../../Cargo.toml",
        "assets/../../Cargo.toml",
        "..\\..\\Cargo.toml",
        "%2e%2e%2fCargo.toml",
        "non_existent_file.png",
        "styles.css\0extra",
    ];

    for probe in external_probes {
        let result = get_asset(probe);
        assert!(
            result.is_none(),
            "get_asset('{}') for external path should return None, but got asset",
            probe
        );
    }

    // Empty path defaults to index.html
    let empty_res = get_asset("");
    assert!(empty_res.is_some(), "Empty path should map to index.html");
    let (_, mime) = empty_res.unwrap();
    assert_eq!(mime, "text/html");

    // RustEmbed normalizes in-folder references (e.g. ../assets/styles.css) strictly within embedded assets
    let normalized_res = get_asset("../assets/styles.css");
    assert!(
        normalized_res.is_some(),
        "RustEmbed resolves internal assets even if prefixed with folder name"
    );
}

#[tokio::test]
async fn test_spa_fallback_routes() {
    let virtual_routes = [
        "/chat",
        "/chat/c-12345",
        "/settings/themes",
        "/models/glm4",
        "/reindex/history",
    ];

    for route in virtual_routes {
        let uri = Uri::from_static(route);
        let resp = static_handler(uri).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Virtual route '{}' must fall back to index.html with 200 OK",
            route
        );

        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            ct.contains("text/html"),
            "SPA fallback for '{}' must be text/html, got: {}",
            route,
            ct
        );
    }
}

// ============================================================================
// 2. 5-THEME CSS & CHATGPT DIMENSIONS EMPIRICAL ASSERTIONS
// ============================================================================

#[test]
fn test_5_theme_css_variables_and_colors() {
    let (css_bytes, mime) = get_asset("styles.css").expect("styles.css must exist");
    assert_eq!(mime, "text/css");
    let css = String::from_utf8(css_bytes.to_vec()).expect("Valid UTF-8 CSS");

    let required_themes = [
        "body.theme-obsidian",
        "body.theme-dark",
        "body.theme-white",
        "body.theme-midnight",
        "body.theme-warm",
    ];

    for theme_selector in required_themes {
        assert!(
            css.contains(theme_selector),
            "styles.css is missing theme selector: {}",
            theme_selector
        );
    }

    // Verify key color variables exist
    let required_vars = [
        "--bg-canvas",
        "--bg-sidebar",
        "--bg-capsule",
        "--text-primary",
        "--text-muted",
        "--accent",
    ];

    for var in required_vars {
        assert!(
            css.contains(var),
            "styles.css is missing CSS variable: {}",
            var
        );
    }

    // Verify light/dark contrast values:
    // White theme must have light canvas (#ffffff) and dark text (#0d0d0d)
    assert!(css.contains("--bg-canvas: #ffffff;"));
    assert!(css.contains("--text-primary: #0d0d0d;"));

    // Obsidian theme must have pitch black canvas (#000000) and white text (#ffffff)
    assert!(css.contains("--bg-canvas: #000000;"));
    assert!(css.contains("--text-primary: #ffffff;"));

    // Midnight theme must have navy/slate canvas (#0b0f19) and light slate text (#f8fafc)
    assert!(css.contains("--bg-canvas: #0b0f19;"));
    assert!(css.contains("--text-primary: #f8fafc;"));

    // Warm theme must have parchment canvas (#faf8f5) and dark warm text (#2d2a26)
    assert!(css.contains("--bg-canvas: #faf8f5;"));
    assert!(css.contains("--text-primary: #2d2a26;"));
}

#[test]
fn test_sidebar_and_reading_column_dimensions_in_css_and_html() {
    let (css_bytes, _) = get_asset("styles.css").unwrap();
    let css = String::from_utf8_lossy(&css_bytes);

    // 1. Sidebar 260px in CSS
    assert!(
        css.contains("width: 260px") && css.contains("min-width: 260px"),
        "Sidebar width must be strictly 260px with min-width 260px in CSS"
    );

    // 2. Reading column 768px in CSS
    assert!(
        css.contains("max-width: 768px"),
        "Reading column max-width must be strictly 768px in CSS"
    );

    // 3. Dimensions in index.html
    let html = get_index_html();
    assert!(
        html.contains("260px"),
        "index.html must contain 260px sidebar dimensions"
    );
    assert!(
        html.contains("768px"),
        "index.html must contain 768px reading column dimensions"
    );
    assert!(
        html.contains("sidebar-260px"),
        "index.html must contain sidebar-260px class marker"
    );
    assert!(
        html.contains("reading-col-768px"),
        "index.html must contain reading-col-768px class marker"
    );
}

#[test]
fn test_all_five_themes_in_index_html() {
    let html = get_index_html();

    let themes = [
        "theme-obsidian",
        "theme-dark",
        "theme-white",
        "theme-midnight",
        "theme-warm",
    ];

    for t in themes {
        assert!(
            html.contains(t),
            "index.html must contain theme definition or class: {}",
            t
        );
    }
}

// ============================================================================
// 3. STATIC ASSET METADATA & COMPRESSION / CACHE HEADERS
// ============================================================================

#[tokio::test]
async fn test_cache_control_headers_on_static_assets() {
    let assets = ["/styles.css", "/app.js", "/favicon.svg", "/langextract.html"];

    for asset_path in assets {
        let uri = Uri::from_static(asset_path);
        let resp = static_handler(uri).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Asset '{}' must return 200 OK",
            asset_path
        );

        let cache_control = resp
            .headers()
            .get(axum::http::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            cache_control.contains("public") || cache_control.contains("max-age"),
            "Static asset '{}' should specify Cache-Control header, got: {}",
            asset_path,
            cache_control
        );
    }
}

#[test]
fn test_rust_embed_asset_enumeration() {
    let count = WebAssets::iter().count();
    assert!(
        count >= 5,
        "Embedded assets must contain at least 5 files (index.html, styles.css, app.js, langextract.html, favicon.svg), found: {}",
        count
    );

    let filenames: Vec<String> = WebAssets::iter().map(|f| f.to_string()).collect();
    assert!(filenames.iter().any(|f| f.contains("index.html")));
    assert!(filenames.iter().any(|f| f.contains("styles.css")));
    assert!(filenames.iter().any(|f| f.contains("app.js")));
    assert!(filenames.iter().any(|f| f.contains("langextract.html")));
    assert!(filenames.iter().any(|f| f.contains("favicon.svg")));
}
