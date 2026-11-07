use quorum_ui::get_asset;

#[test]
fn test_session_persistence_and_routing_invariants() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js must exist");
    let js = String::from_utf8_lossy(&js_bytes);

    // 1. Storage key and URL hash synchronization
    assert!(
        js.contains("quorumrag_active_session_id"),
        "app.js must define quorumrag_active_session_id localStorage key"
    );
    assert!(
        js.contains("#session="),
        "app.js must synchronize with #session= in URL hash"
    );
    assert!(
        js.contains("syncSessionPersistence"),
        "app.js must implement syncSessionPersistence"
    );

    // 2. Startup restoration and running task attach
    assert!(
        js.contains("restoreActiveSessionOnStartup"),
        "app.js must implement restoreActiveSessionOnStartup"
    );
    assert!(
        js.contains("/api/chat/active"),
        "app.js must query /api/chat/active to detect running queries on startup"
    );
    assert!(
        js.contains("/api/chat/attach/"),
        "app.js must attach to /api/chat/attach/:session_id"
    );
    assert!(
        js.contains("attachToLiveChatTask"),
        "app.js must implement attachToLiveChatTask"
    );

    // 3. Multi-turn continuation chunk deduplication restoration
    assert!(
        js.contains("activeSessionSeenChunkIds.add(String(cit.chunk_id));"),
        "app.js must restore activeSessionSeenChunkIds from historical citations"
    );

    // 4. Reindex auto-resume polling
    assert!(
        js.contains("pollReindexProgress();"),
        "app.js must call pollReindexProgress() to auto-resume running indexing"
    );
    assert!(
        js.contains("isRunning && !reindexPollInterval"),
        "app.js must check isRunning and !reindexPollInterval to resume polling"
    );

    // 5. New chat & clear history wipe storage and URL hash
    assert!(
        js.contains("syncSessionPersistence(null);"),
        "app.js must clear persistence on new chat and history deletion"
    );

    // 6. Window export helpers for testability and runtime verification
    assert!(
        js.contains("window.restoreActiveSessionOnStartup"),
        "app.js must export restoreActiveSessionOnStartup to window"
    );
    assert!(
        js.contains("window.attachToLiveChatTask"),
        "app.js must export attachToLiveChatTask to window"
    );
    assert!(
        js.contains("window.getActiveSessionId"),
        "app.js must export getActiveSessionId to window"
    );
}

#[test]
fn test_index_html_model_dropdown_contains_gemma_3() {
    let (html_bytes, _) = get_asset("index.html").expect("index.html must exist");
    let html = String::from_utf8_lossy(&html_bytes);

    assert!(
        html.contains("Gemma 3"),
        "index.html must contain Gemma 3 in the top-model-select dropdown"
    );
    assert!(
        html.contains("AutoFusion"),
        "index.html must contain AutoFusion in the top-model-select dropdown"
    );
    assert!(
        html.contains("Gemma4_26b"),
        "index.html must contain Gemma4_26b in the top-model-select dropdown"
    );
}
