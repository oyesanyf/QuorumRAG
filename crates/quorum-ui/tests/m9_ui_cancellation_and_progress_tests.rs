//! Milestone M9 UI Verification: Stop Button, Dynamic Thinking Phrases & Monotonic Progress Bar.
//!
//! Verifies:
//! 1. Static asset cache headers (`public, max-age=3600` for assets, `no-cache` for index.html).
//! 2. Stop button DOM existence, attributes, and styling in CSS and HTML.
//! 3. Dynamic thinking phrase pool (>= 60 phrases, 8 architectural domains).
//! 4. In-flight cancellation wiring (/api/chat/cancel, AbortController, Stop button).
//! 5. Monotonic index progress bar without fake 25% fallback or hardcoded initial widths.

use axum::http::{header, StatusCode, Uri};
use quorum_ui::static_handler;

#[tokio::test]
async fn test_cache_headers_differentiation_static_vs_html() {
    // 1. Static assets must have public caching
    let static_assets = ["/styles.css", "/app.js", "/favicon.svg", "/langextract.html"];
    for path in static_assets {
        let uri = Uri::from_static(path);
        let resp = static_handler(uri).await;
        assert_eq!(resp.status(), StatusCode::OK, "Asset {} must be 200 OK", path);

        let cache = resp
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            cache.contains("public") && cache.contains("max-age"),
            "Static asset {} must specify public max-age cache control, got: {}",
            path,
            cache
        );
    }

    // 2. index.html must have no-cache for instant frontend updates
    for path in ["/", "/index.html"] {
        let uri = Uri::from_static(path);
        let resp = static_handler(uri).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let cache = resp
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            cache.contains("no-cache") || cache.contains("no-store"),
            "Root html {} must specify no-cache, got: {}",
            path,
            cache
        );
    }
}

#[test]
fn test_stop_button_dom_and_styling() {
    let html = include_str!("../assets/index.html");
    let css = include_str!("../assets/styles.css");

    // Button presence in input row
    assert!(
        html.contains("id=\"btn-stop\""),
        "index.html must contain #btn-stop"
    );
    assert!(
        html.contains("class=\"btn-stop hidden\""),
        "#btn-stop must have 'btn-stop hidden' class initially"
    );
    assert!(
        html.contains("id=\"btn-send\""),
        "index.html must contain #btn-send alongside #btn-stop"
    );

    // CSS styling
    assert!(
        css.contains(".btn-stop"),
        "styles.css must define .btn-stop class"
    );
    assert!(
        css.contains(".btn-stop:hover"),
        "styles.css must define .btn-stop:hover"
    );
    assert!(
        css.contains("--danger") || css.contains("#ef4444"),
        "styles.css must style .btn-stop with danger accent"
    );
}

#[test]
fn test_thinking_phrases_pool_and_animation_architecture() {
    let js = include_str!("../assets/app.js");

    // 1. Minimum 60 phrases in pool
    let marker = "const THINKING_PHRASES = [";
    let start = js.find(marker).expect("THINKING_PHRASES must exist in app.js");
    let end = js[start..].find("];").expect("Closing bracket for THINKING_PHRASES");
    let pool_block = &js[start + marker.len()..start + end];
    let phrase_count = pool_block
        .lines()
        .map(|l| l.trim())
        .filter(|l| l.starts_with('\''))
        .count();

    assert!(
        phrase_count >= 60,
        "THINKING_PHRASES must contain >= 60 phrases, found: {}",
        phrase_count
    );

    // 2. Architectural domain coverage
    let domains = [
        ("mesh/libp2p", pool_block.contains("libp2p") || pool_block.contains("mDNS")),
        ("Gemma/768d", pool_block.contains("Gemma") && pool_block.contains("768d")),
        ("LanceDB IVF_PQ", pool_block.contains("LanceDB") && pool_block.contains("IVF_PQ")),
        ("Reciprocal Rank Fusion", pool_block.contains("Reciprocal Rank Fusion") || pool_block.contains("RRF")),
        ("Google Magika", pool_block.contains("Magika")),
        ("OCR / Image", pool_block.contains("OCR") || pool_block.contains("image")),
        ("BLAKE3 / Merkle", pool_block.contains("BLAKE3") && pool_block.contains("Merkle")),
        ("Agentic State Graph", pool_block.contains("Agentic State Graph")),
    ];

    for (domain, present) in domains {
        assert!(present, "THINKING_PHRASES must cover architectural domain: {}", domain);
    }

    // 3. Aliases and cycling interval
    assert!(
        js.contains("startThinkingAnimation"),
        "app.js must provide startThinkingAnimation alias"
    );
    assert!(
        js.contains("stopThinkingAnimation"),
        "app.js must provide stopThinkingAnimation alias"
    );
    assert!(
        js.contains("650"),
        "app.js must use ~650ms cycling interval for thinking phrases"
    );
}

#[test]
fn test_cancellation_and_monotonic_progress_wiring() {
    let js = include_str!("../assets/app.js");
    let html = include_str!("../assets/index.html");

    // In-flight cancellation fetch
    assert!(
        js.contains("/api/chat/cancel"),
        "app.js must call /api/chat/cancel upon user cancellation"
    );
    assert!(
        js.contains("query_id: activeQueryId"),
        "app.js must include query_id in /api/chat payload"
    );
    assert!(
        js.contains("*(Generation stopped by user)*"),
        "app.js must append stopped notice when cancelled"
    );

    // Eliminate fake 25% fallback and Math.max(2, ...)
    assert!(
        !js.contains("pct = 25;"),
        "app.js must NOT contain fake 25% progress fallback"
    );
    assert!(
        !js.contains("Math.max(2,"),
        "app.js must NOT contain artificial Math.max(2, ...) floor"
    );

    // Initial progress bar width must be 0% in index.html
    assert!(
        html.contains("id=\"live-indexer-bar\" style=\"width:0%"),
        "index.html must have 0% initial width for #live-indexer-bar"
    );
    assert!(
        html.contains("id=\"top-index-bar\" style=\"width:0%"),
        "index.html must have 0% initial width for #top-index-bar"
    );
}
