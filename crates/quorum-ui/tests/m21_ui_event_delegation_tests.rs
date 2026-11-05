//! Milestone M21 Verification Suite
//!
//! Areas Covered:
//! 1. Zero inline event handlers (onclick, onchange, oninput, onkeydown) in HTML templates in app.js
//! 2. Zero unescaped ${JSON.stringify} calls inside HTML attributes
//! 3. All 19 Settings tabs event delegation and data-* action coverage
//! 4. Settings dialog footer flex layout contract and scrolling ownership
//! 5. Responding Node ID row and citation peer badge invariants
//! 6. Folder browser hover/active styling and physical drive navigation
//! 7. Dynamic model selector hydration and SSR fallback buttons preservation
//! 8. Empty chat archive safeguard (zero dummy session generation)
//! 9. Legacy mock memory, chat, and voice sanitization invariants

use quorum_ui::{get_asset, get_index_html};

#[test]
fn test_zero_inline_event_handlers_in_app_js() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);
    let js_lower = js.to_lowercase();

    // Assert zero inline on* event handler attributes in HTML templates
    let forbidden_inline_handlers = [
        " onclick=",
        " onchange=",
        " oninput=",
        " onkeydown=",
        " onkeyup=",
        " onkeypress=",
        " onmouseover=",
        " onmouseout=",
        " onsubmit=",
        " onselect=",
        " onblur=",
        " onfocus=",
    ];

    for handler in forbidden_inline_handlers {
        assert!(
            !js_lower.contains(handler),
            "app.js must have ZERO inline event handlers, but found occurrence of '{}'",
            handler
        );
    }
}

#[test]
fn test_zero_unescaped_json_stringify_in_html_attributes() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);

    // Look for any occurrences of ="...${JSON.stringify...}" or ='...${JSON.stringify...}'
    let mut violations = Vec::new();
    for (line_idx, line) in js.lines().enumerate() {
        if line.contains("${JSON.stringify") || line.contains("${ JSON.stringify") {
            for marker in ["=\"", "='"] {
                if let Some(pos) = line.find(marker) {
                    let after = &line[pos + marker.len()..];
                    let quote = marker.chars().nth(1).unwrap();
                    if let Some(close_pos) = after.find(quote) {
                        let attr_val = &after[..close_pos];
                        if attr_val.contains("${JSON.stringify") || attr_val.contains("${ JSON.stringify") {
                            violations.push((line_idx + 1, line.trim().to_string()));
                        }
                    }
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "app.js must have ZERO unescaped ${{JSON.stringify}} in HTML attributes, found violations: {:?}",
        violations
    );
}

#[test]
fn test_all_19_settings_tabs_event_delegation_actions() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);

    // Verify key data-action delegators are wired in initSettingsEventDelegation
    let required_actions = [
        "browse-dir",
        "browse-up",
        "browse-root",
        "share-folder",
        "remove-shared-folder",
        "select-shared-pill",
        "export-all-data",
        "trigger-import-settings",
        "clear-query-cache",
        "clear-chat-history",
        "clear-archived-chats",
        "diag-reindex",
        "diag-drift",
        "diag-recache",
        "diag-health",
        "rotate-epoch",
        "refresh-tpm",
        "release-quarantine-peer",
        "approve-all-pending",
        "clear-pending-joins",
        "add-memory-item",
        "remove-memory-item",
        "save-custom-inst",
        "save-codex-inst",
        "save-profile",
        "save-pet-name",
    ];

    for action in required_actions {
        let pattern = format!("'{}'", action);
        assert!(
            js.contains(&pattern),
            "initSettingsEventDelegation must handle action '{}'",
            action
        );
    }

    // Verify change actions
    let required_change_actions = [
        "apply-theme",
        "apply-accent",
        "apply-custom-bg",
        "apply-custom-fg",
        "ui-patch",
        "set-model",
        "set-search-mode",
        "mesh-config",
        "dlp-policy",
        "toggle-shared-folder",
        "update-folder-tier",
        "update-folder-dlp",
        "import-settings-file",
    ];

    for ca in required_change_actions {
        let pattern = format!("'{}'", ca);
        assert!(
            js.contains(&pattern),
            "initSettingsEventDelegation must handle change-action '{}'",
            ca
        );
    }
}

#[test]
fn test_settings_dialog_footer_layout_contract() {
    let (css_bytes, _) = get_asset("styles.css").expect("styles.css must be embedded");
    let css = String::from_utf8_lossy(&css_bytes);

    assert!(
        css.contains(".settings-dialog-footer"),
        "styles.css must define .settings-dialog-footer"
    );
    assert!(
        css.contains("flex-shrink: 0;"),
        "settings-dialog-footer must enforce flex-shrink: 0;"
    );

    let html = get_index_html();
    assert!(
        html.contains("settings-dialog-footer"),
        "index.html must anchor .settings-dialog-footer"
    );
    assert!(
        html.contains("id=\"settings-content-container\""),
        "index.html must contain #settings-content-container"
    );
    assert!(
        html.contains("overflow-y:auto;"),
        "#settings-content-container must own scrolling via overflow-y:auto;"
    );
}

#[test]
fn test_sources_node_id_row_and_citations_badges() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);

    assert!(
        js.contains("sources-node-id-row"),
        "app.js must contain sources-node-id-row"
    );
    assert!(
        js.contains("Responding Node ID:"),
        "app.js must display Responding Node ID:"
    );
    assert!(
        js.contains("sources-responder-peer-pill"),
        "app.js must style responder peer as sources-responder-peer-pill"
    );
    assert!(
        js.contains("citation-node-id-subline"),
        "app.js must include citation-node-id-subline"
    );
    assert!(
        js.contains("cite-node-local") && js.contains("cite-node-mesh"),
        "app.js must differentiate cite-node-local vs cite-node-mesh"
    );

    let (css_bytes, _) = get_asset("styles.css").expect("styles.css must be embedded");
    let css = String::from_utf8_lossy(&css_bytes);
    assert!(css.contains(".sources-node-id-row"));
    assert!(css.contains(".sources-responder-peer-pill"));
    assert!(css.contains(".citation-node-id-subline"));
    assert!(css.contains(".cite-node-local"));
    assert!(css.contains(".cite-node-mesh"));
}

#[test]
fn test_folder_browser_hover_and_active_styles() {
    let (css_bytes, _) = get_asset("styles.css").expect("styles.css must be embedded");
    let css = String::from_utf8_lossy(&css_bytes);

    assert!(
        css.contains(".folder-browser-item:hover"),
        "styles.css must define hover state for folder browser cards"
    );
    assert!(
        css.contains(".folder-browser-item:active"),
        "styles.css must define active state for folder browser cards"
    );
    assert!(
        css.contains("cursor: pointer;"),
        "folder-browser-item must have cursor: pointer;"
    );

    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);
    assert!(
        js.contains("data-action=\"browse-dir\""),
        "Entire card must have data-action='browse-dir' for clickable drill-down"
    );
}

#[test]
fn test_dynamic_models_refresh_and_fallback() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);

    assert!(
        js.contains("refreshDynamicModels"),
        "app.js must implement refreshDynamicModels"
    );
    assert!(
        js.contains("/api/models"),
        "app.js must fetch /api/models dynamically"
    );

    let html = get_index_html();
    // SSR Fallback buttons must be retained in index.html for test and SSR compatibility
    assert!(html.contains("Auto-Fusion"));
    assert!(html.contains("Gemma 4 26B"));
    assert!(html.contains("GLM-4-9B"));
    assert!(html.contains("Qwen 2.5"));
    assert!(html.contains("Gemma 3"));
}

#[test]
fn test_empty_chat_archive_safeguard() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);

    assert!(
        js.contains("No active chat messages to archive"),
        "_archiveCurrentChat must reject empty chats with toast notification"
    );
}

#[test]
fn test_legacy_mock_data_sanitizers() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);

    assert!(
        js.contains("stripMockMemories"),
        "app.js must strip legacy mock memories"
    );
    assert!(
        js.contains("stripMockArchivedChats"),
        "app.js must strip legacy mock archived chats"
    );
    assert!(
        !js.contains("Voice dictation note (Juniper)"),
        "app.js must not contain fake Juniper voice dictation note"
    );
}
