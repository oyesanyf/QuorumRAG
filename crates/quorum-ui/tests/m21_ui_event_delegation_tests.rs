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

#[test]
fn test_m1_settings_text_and_layout_alignment() {
    let (css_bytes, _) = get_asset("styles.css").expect("styles.css must be embedded");
    let css = String::from_utf8_lossy(&css_bytes);

    // 1. Verify CSS layout utilities
    assert!(
        css.contains(".settings-centered-container"),
        "styles.css must define .settings-centered-container"
    );
    assert!(
        css.contains("max-width: 860px;"),
        "styles.css must enforce max-width: 860px;"
    );
    assert!(
        css.contains("margin-inline: auto;"),
        "styles.css must enforce margin-inline: auto;"
    );
    assert!(
        css.contains(".settings-subtab-nav"),
        "styles.css must define .settings-subtab-nav"
    );
    assert!(
        css.contains(".settings-header-action-row"),
        "styles.css must define .settings-header-action-row"
    );
    assert!(
        css.contains(".settings-row-controls"),
        "styles.css must define .settings-row-controls"
    );

    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);

    // 2. Verify subtab nav class used in quickSubTabsBar
    assert!(
        js.contains("<div class=\"settings-subtab-nav\">"),
        "app.js quickSubTabsBar must use class settings-subtab-nav"
    );

    // 3. Verify settings-header-action-row used
    assert!(
        js.contains("<div class=\"settings-header-action-row\">"),
        "app.js must use settings-header-action-row for action title rows"
    );

    // 4. Verify zero inline margin or style overrides on settings-page-title
    assert!(
        !js.contains("<h2 class=\"settings-page-title\" style="),
        "app.js must have ZERO inline style overrides on settings-page-title"
    );

    // 5. Verify models tab subtitle standardization
    assert!(
        js.contains("<p class=\"settings-page-subtitle\">Configure local Ollama instance, QuorumRAG Master IPC bridge, Chrome DevTools Protocol, multi-model fusion panels, and 256k recursive agentic loop chaining.</p>"),
        "models tab must use standardized settings-page-subtitle"
    );

    // 5b. Verify voice tab subtitle standardization
    assert!(
        js.contains("<p class=\"settings-page-subtitle\">Choose the voice used for voice chat and audio synthesis.</p>"),
        "voice tab must use standardized settings-page-subtitle"
    );

    // 6. Verify storage tab quota metric standardization
    assert!(
        js.contains("<p class=\"settings-page-subtitle\" style=\"font-weight:600;"),
        "storage tab quota metric must use settings-page-subtitle"
    );

    // 7. Verify no arbitrary max-width on subtitles in parental and trusted
    assert!(
        !js.contains("style=\"max-width:660px;\""),
        "parental subtitle must not have arbitrary max-width:660px"
    );
    assert!(
        !js.contains("style=\"max-width:680px;\""),
        "trusted subtitle must not have arbitrary max-width:680px"
    );

    // 8. Verify settings-row-controls usage across controls
    assert!(
        js.contains("class=\"settings-row-controls\""),
        "app.js must use settings-row-controls for row buttons and inputs"
    );
    assert!(
        js.matches("settings-row-controls").count() >= 15,
        "app.js must use settings-row-controls widely across settings rows"
    );

    // 9. Verify defensive container wrapping in renderSettingsTabContent
    assert!(
        js.contains("!settingsContent.firstElementChild.classList.contains('settings-centered-container')") ||
        js.contains("settingsContent.querySelector('.settings-centered-container')"),
        "renderSettingsTabContent must verify and defensively wrap in .settings-centered-container"
    );

    // 10. Verify settings-centered-container is present across tabs
    let expected_tabs = [
        "tab === 'general'",
        "tab === 'marketplace'",
        "tab === 'marketplace-ledger'",
        "tab === 'diagnostics'",
        "tab === 'models'",
        "tab === 'appearance'",
        "tab === 'mesh'",
        "tab === 'dlp'",
        "tab === 'notifications'",
        "tab === 'profile'",
        "tab === 'security'",
        "tab === 'account'",
        "tab === 'archived'",
        "tab === 'parental'",
        "tab === 'trusted'",
        "tab === 'voice'",
        "tab === 'storage'",
        "tab === 'personalization'",
        "tab === 'pets'",
        "tab === 'keyboard'",
        "tab === 'usage'",
        "tab === 'datacontrols'",
    ];

    for tab_check in expected_tabs {
        assert!(
            js.contains(tab_check),
            "app.js must handle tab switch branch {}",
            tab_check
        );
    }

    let container_occurrences = js.matches("<div class=\"settings-centered-container\">").count();
    assert!(
        container_occurrences >= 22,
        "app.js must contain settings-centered-container in all 22 tab templates, found {}",
        container_occurrences
    );
}

#[test]
fn test_milestone_2_windows_file_explorer_invariants() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);

    // 1. Verify CANONICAL_CODEBASE_FOLDERS and getCodebaseFoldersList are removed
    assert!(
        !js.contains("CANONICAL_CODEBASE_FOLDERS"),
        "app.js must NEVER contain CANONICAL_CODEBASE_FOLDERS"
    );
    assert!(
        !js.contains("getCodebaseFoldersList"),
        "app.js must NEVER contain getCodebaseFoldersList"
    );
    assert!(
        !js.contains("📂 Browse Codebase Root"),
        "app.js must NEVER contain 'Browse Codebase Root' button"
    );

    // 2. Verify Windows File Explorer functions exist
    assert!(
        js.contains("function renderWindowsFileExplorerHtml"),
        "app.js must implement renderWindowsFileExplorerHtml"
    );
    assert!(
        js.contains("function buildPathBreadcrumbs"),
        "app.js must implement buildPathBreadcrumbs"
    );
    assert!(
        js.contains("function renderReindexExplorer"),
        "app.js must implement renderReindexExplorer"
    );

    // 3. Verify event delegation actions are wired
    let required_explorer_actions = [
        "browse-dir",
        "browse-up",
        "browse-root",
        "trigger-native-folder-picker",
        "newdoc-pick-folder",
        "reindex-pick-folder",
    ];
    for act in required_explorer_actions {
        let pattern = format!("'{}'", act);
        assert!(
            js.contains(&pattern),
            "app.js must handle action '{}' in event delegation",
            act
        );
    }

    // 4. Verify all 5 interfaces integrate the explorer context
    let required_contexts = [
        "contextId: 'general'",
        "contextId: 'mkt'",
        "contextId: 'mesh'",
        "contextId: 'newdoc'",
        "contextId: 'reindex'",
    ];
    for ctx in required_contexts {
        assert!(
            js.contains(ctx),
            "app.js must integrate Windows File Explorer with {}",
            ctx
        );
    }

    // 5. Verify styles.css defines Windows File Explorer classes
    let (css_bytes, _) = get_asset("styles.css").expect("styles.css must be embedded");
    let css = String::from_utf8_lossy(&css_bytes);
    let required_css = [
        ".folder-explorer-container",
        ".folder-explorer-toolbar",
        ".folder-drive-pill",
        ".folder-native-picker-btn",
        ".folder-explorer-address-bar",
        ".folder-breadcrumbs",
        ".folder-breadcrumb-segment",
        ".folder-row",
        ".folder-row-checkbox",
        ".folder-row-details",
        ".folder-select-btn",
    ];
    for cls in required_css {
        assert!(
            css.contains(cls),
            "styles.css must define class {}",
            cls
        );
    }

    // 6. Verify index.html contains reindex-folder-explorer-mount and no codebase placeholder
    let html = get_index_html();
    assert!(
        html.contains("id=\"reindex-folder-explorer-mount\""),
        "index.html must anchor #reindex-folder-explorer-mount in modal-reindex"
    );
    assert!(
        !html.contains("placeholder=\"crates/quorum-coordinator\""),
        "index.html must not suggest crates/quorum-coordinator in modal-reindex"
    );
}

#[test]
fn test_localhost_marketplace_verification_panel() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);

    // 1. Verify marketplace test actions are wired in event delegation
    assert!(
        js.contains("'mkt-issue-test-cert'"),
        "app.js must handle 'mkt-issue-test-cert' in event delegation"
    );
    assert!(
        js.contains("'mkt-exec-test-transaction'"),
        "app.js must handle 'mkt-exec-test-transaction' in event delegation"
    );

    // 2. Verify endpoints called with 127.0.0.1/32
    assert!(
        js.contains("/api/v1/marketplace/test/issue-cert"),
        "app.js must call /api/v1/marketplace/test/issue-cert"
    );
    assert!(
        js.contains("/api/v1/marketplace/test/execute-transaction"),
        "app.js must call /api/v1/marketplace/test/execute-transaction"
    );
    assert!(
        js.contains("127.0.0.1/32"),
        "app.js test cert issuance must authorize 127.0.0.1/32"
    );

    // 3. Verify output box and template integration
    assert!(
        js.contains("marketplace-test-output-box"),
        "app.js must define #marketplace-test-output-box element"
    );
    assert!(
        js.contains("Localhost Marketplace Issuer &amp; Buyer Test Panel"),
        "app.js must render Localhost Marketplace Issuer & Buyer Test Panel heading"
    );
}

