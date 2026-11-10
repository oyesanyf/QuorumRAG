//! Adversarial Challenger Suite for Milestone 5 WebUI
//!
//! Empirically challenges and stress-tests:
//! 1. Mandatory User Invariant: Zero text input for folders across Settings & Modals
//! 2. Artemis DFIR REST endpoints wiring & payload schemas
//! 3. Default-off telemetry collection and marketplace harvesting invariants
//! 4. Prohibited categories lockdown (disabled checkboxes) vs defensive allowlist
//! 5. UI Event delegation, no-inline-handlers, escapeHtml injection safety
//! 6. Settings search indexing & tab switching integration

use quorum_ui::{get_asset, get_index_html};

#[test]
fn test_challenge_zero_typing_folder_inputs_across_settings_and_modals() {
    let html = get_index_html();
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);

    // 1. Assert ZERO <input type="text"> folder inputs across all settings/modals
    let folder_input_ids = [
        "artemis-jsonl-dir-input",
        "mkt-folder-input",
        "new-doc-path-input",
        "new-shared-folder-input",
        "dlp-sim-path",
        "reindex-target-path",
    ];

    for id in &folder_input_ids {
        let text_input_pattern_1 = format!(r#"type="text" id="{id}""#);
        let text_input_pattern_2 = format!(r#"id="{id}" type="text""#);
        let default_type_text_pattern = format!(r#"<input id="{id}">"#);

        assert!(
            !html.contains(&text_input_pattern_1) && !html.contains(&text_input_pattern_2),
            "CRITICAL BUG: index.html contains a visible text input for #{id}"
        );
        assert!(
            !html.contains(&default_type_text_pattern),
            "CRITICAL BUG: index.html contains <input id=\"{id}\"> without type (defaults to text)"
        );

        assert!(
            !js.contains(&text_input_pattern_1) && !js.contains(&text_input_pattern_2),
            "CRITICAL BUG: app.js contains a visible text input for #{id}"
        );

        // Verify it is strictly <input type="hidden">
        let hidden_pattern_1 = format!(r#"type="hidden" id="{id}""#);
        let hidden_pattern_2 = format!(r#"id="{id}"" type="hidden""#);
        let hidden_pattern_3 = format!(r#"<input type="hidden" id="{id}""#);
        assert!(
            html.contains(&hidden_pattern_1)
                || html.contains(&hidden_pattern_2)
                || html.contains(&hidden_pattern_3)
                || js.contains(&hidden_pattern_1)
                || js.contains(&hidden_pattern_2)
                || js.contains(&hidden_pattern_3),
            "CRITICAL BUG: #{id} is not configured as <input type=\"hidden\">"
        );
    }

    // 2. Specific Artemis DFIR folder selection elements check in index.html
    assert!(
        html.contains(r#"<input type="hidden" id="artemis-jsonl-dir-input""#),
        "index.html must contain <input type=\"hidden\" id=\"artemis-jsonl-dir-input\">"
    );
    assert!(
        html.contains(r#"id="artemis-selected-folder-display""#),
        "index.html must contain #artemis-selected-folder-display visual pill"
    );
    assert!(
        html.contains("chatgpt-selected-folder-pill"),
        "index.html #artemis-selected-folder-display must use class chatgpt-selected-folder-pill"
    );
    assert!(
        html.contains(r#"data-action="trigger-native-folder-picker" data-context="artemis""#),
        "index.html must contain native folder picker button with data-context=\"artemis\""
    );
    assert!(
        html.contains(r#"id="artemis-folder-upload-input""#)
            && html.contains("webkitdirectory"),
        "index.html must contain #artemis-folder-upload-input with webkitdirectory"
    );
    assert!(
        html.contains(r#"id="artemis-folder-browser-list""#),
        "index.html must contain #artemis-folder-browser-list container"
    );

    // 3. Artemis DFIR folder selection elements check in app.js
    assert!(
        js.contains(r#"<input type="hidden" id="artemis-jsonl-dir-input""#),
        "app.js must render <input type=\"hidden\" id=\"artemis-jsonl-dir-input\">"
    );
    assert!(
        js.contains(r#"id="artemis-selected-folder-display""#),
        "app.js must render #artemis-selected-folder-display"
    );
    assert!(
        js.contains(r#"data-action="trigger-native-folder-picker" data-context="artemis""#),
        "app.js must render native folder picker button with data-context=\"artemis\""
    );
    assert!(
        js.contains(r#"id="artemis-folder-upload-input" webkitdirectory directory multiple"#),
        "app.js must render folder upload input with webkitdirectory directory multiple"
    );
    assert!(
        js.contains(r#"id="artemis-folder-browser-list""#),
        "app.js must render #artemis-folder-browser-list"
    );
    assert!(
        js.contains("contextId: 'artemis'"),
        "app.js must pass contextId: 'artemis' to renderWindowsFileExplorerHtml"
    );
}

#[test]
fn test_challenge_artemis_daemon_rest_endpoints_wiring() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);

    // 1. All 4 daemon REST endpoints and pick-folder endpoint referenced in app.js
    let required_endpoints = [
        "/api/v1/artemis/status",
        "/api/v1/artemis/config",
        "/api/v1/artemis/collect",
        "/api/v1/artemis/preview-normalizer",
        "/api/fs/pick-folder",
    ];

    for ep in &required_endpoints {
        assert!(
            js.contains(ep),
            "CRITICAL BUG: Endpoint '{ep}' is not referenced in app.js"
        );
    }

    // 2. Data fetching function wires status and config
    assert!(
        js.contains("async function fetchArtemisData()"),
        "app.js must declare async function fetchArtemisData()"
    );
    assert!(
        js.contains("fetch('/api/v1/artemis/status')"),
        "fetchArtemisData must call /api/v1/artemis/status"
    );
    assert!(
        js.contains("fetch('/api/v1/artemis/config')"),
        "fetchArtemisData must call /api/v1/artemis/config"
    );

    // 3. Tab opening triggers data fetch
    assert!(
        js.contains("if (tab === 'artemis-dfir')") && js.contains("await fetchArtemisData();"),
        "openSettingsView must fetch Artemis data when tab === 'artemis-dfir'"
    );

    // 4. Collection trigger wires POST /api/v1/artemis/collect
    assert!(
        js.contains("fetch('/api/v1/artemis/collect'"),
        "trigger-artemis-collect must POST to /api/v1/artemis/collect"
    );
    assert!(
        js.contains("source_type:"),
        "trigger-artemis-collect payload must specify source_type"
    );

    // 5. Normalizer preview trigger wires POST /api/v1/artemis/preview-normalizer
    assert!(
        js.contains("fetch('/api/v1/artemis/preview-normalizer'"),
        "test-artemis-preview must POST to /api/v1/artemis/preview-normalizer"
    );
    assert!(
        js.contains("sample_text:"),
        "test-artemis-preview payload must specify sample_text"
    );
    assert!(
        js.contains("session_salt:"),
        "test-artemis-preview payload must specify session_salt"
    );
}

#[test]
fn test_challenge_default_off_toggles_and_fail_closed_defaults() {
    let html = get_index_html();
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);

    // 1. Initial HTML checkboxes for collection and harvest MUST NOT be checked by default
    assert!(
        html.contains(r#"<input type="checkbox" id="chk-artemis-collection-toggle" class="quorum-switch""#),
        "index.html must render unchecked collection toggle"
    );
    assert!(
        !html.contains(r#"id="chk-artemis-collection-toggle" class="quorum-switch" checked"#),
        "SECURITY BUG: Collection toggle must NOT be checked by default in index.html"
    );

    assert!(
        html.contains(r#"<input type="checkbox" id="chk-artemis-harvest-toggle" class="quorum-switch""#),
        "index.html must render unchecked harvest toggle"
    );
    assert!(
        !html.contains(r#"id="chk-artemis-harvest-toggle" class="quorum-switch" checked"#),
        "SECURITY BUG: Marketplace harvest toggle must NOT be checked by default in index.html"
    );

    // 2. In app.js default fallback state, both toggles must default to false
    assert!(
        js.contains("collection_enabled: false"),
        "app.js fallback status must specify collection_enabled: false"
    );
    assert!(
        js.contains("marketplace_harvest_enabled: false"),
        "app.js fallback status must specify marketplace_harvest_enabled: false"
    );
    assert!(
        js.contains("airgap_enforced: true"),
        "app.js fallback status must specify airgap_enforced: true"
    );
}

#[test]
fn test_challenge_artifact_category_allowlist_and_prohibited_matrix() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);

    // 1. Defensive categories (6)
    let defensive_categories = [
        "process_execution",
        "network_connection",
        "registry_persistence",
        "system_event_log",
        "prefetch_amcache_execution",
        "service_daemon",
    ];

    for cat in &defensive_categories {
        assert!(
            js.contains(cat),
            "app.js must define defensive category '{cat}'"
        );
    }
    assert!(
        js.contains("✅ ALLOWLISTED"),
        "app.js must display ✅ ALLOWLISTED badge for defensive categories"
    );

    // 2. Prohibited categories (4)
    let prohibited_categories = [
        "browser_cookies",
        "browser_history_oauth",
        "credential_store",
        "shell_history_raw",
    ];

    for cat in &prohibited_categories {
        assert!(
            js.contains(cat),
            "app.js must define prohibited category '{cat}'"
        );
    }
    assert!(
        js.contains("🚫 PROHIBITED"),
        "app.js must display 🚫 PROHIBITED badge for personal/credential categories"
    );

    // 3. Prohibited categories checkboxes MUST be permanently disabled and unchecked (never checked=false)
    assert!(
        !js.contains("checked=false"),
        "CRITICAL REGRESSION: app.js contains 'checked=false'. Under W3C HTML5 §2.4.2 boolean attributes, any presence of 'checked' evaluates to true in browser DOM, rendering prohibited categories as checked."
    );
    assert!(
        js.contains(r#"<input type="checkbox" class="quorum-switch" disabled title="Prohibited category cannot be enabled""#),
        "Prohibited category checkboxes must be rendered disabled and unchecked (without checked attribute) in app.js"
    );
}

#[test]
fn test_challenge_ui_event_delegation_and_injection_hygiene() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);

    // 1. Centered container layout contract
    assert!(
        js.contains("<div class=\"settings-centered-container\">\n        <div id=\"settings-tab-artemis-dfir\">")
            || js.contains("<div class=\"settings-centered-container\">\r\n        <div id=\"settings-tab-artemis-dfir\">"),
        "tab === 'artemis-dfir' must be wrapped in <div class=\"settings-centered-container\">"
    );

    // 2. Page title must not contain inline style attribute
    assert!(
        js.contains("<h2 class=\"settings-page-title\">🛡️ Artemis DFIR &amp; Forensics (Local-Only)</h2>"),
        "<h2 class=\"settings-page-title\"> must not have inline style attributes"
    );

    // 3. Dynamic folder variables MUST use escapeHtml() to prevent XSS injection
    assert!(
        js.contains("${escapeHtml(curSelectedDir)}"),
        "curSelectedDir must be escaped with escapeHtml in HTML templates"
    );
    assert!(
        js.contains("${escapeHtml(currentBrowsePath)}"),
        "currentBrowsePath must be escaped with escapeHtml in HTML templates"
    );

    // 4. All Artemis event delegation actions handled in app.js
    let required_actions = [
        "trigger-native-folder-picker",
        "artemis-pick-folder",
        "artemis-select-folder",
        "artemis-select-active-folder",
        "artemis-clear-selected-folder",
        "artemis-toggle-collection",
        "artemis-toggle-harvest",
        "artemis-toggle-redact",
        "artemis-toggle-normalize",
        "artemis-toggle-category",
        "trigger-artemis-collect",
        "test-artemis-preview",
        "artemis-upload-folder",
    ];

    for act in &required_actions {
        let needle = format!("'{act}'");
        assert!(
            js.contains(&needle),
            "initSettingsEventDelegation must handle action '{act}'"
        );
    }

    // 5. artemis-upload-folder must refresh tab controls immediately
    assert!(
        js.contains("case 'artemis-upload-folder':")
            && js.contains("renderSettingsTabContent('artemis-dfir', '');"),
        "artemis-upload-folder event must re-render 'artemis-dfir' tab content to refresh buttons"
    );
}

#[test]
fn test_challenge_search_and_navigation_integration() {
    let html = get_index_html();
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);

    // 1. Navigation item in index.html
    assert!(
        html.contains(r#"<button class="chatgpt-nav-item" data-tab="artemis-dfir""#),
        "index.html must include <button class=\"chatgpt-nav-item\" data-tab=\"artemis-dfir\">"
    );

    // 2. Search keyword auto-routing in app.js
    for keyword in ["artemis", "dfir", "forensic", "telemetry", "evtx"] {
        let kw_check = format!("q.includes('{keyword}')");
        assert!(
            js.contains(&kw_check),
            "Settings search listener in app.js must handle keyword '{keyword}'"
        );
    }

    // 3. Search auto-activates artemis-dfir tab including for 'evtx'
    assert!(
        js.contains("activeSettingsTab = 'artemis-dfir';"),
        "Settings search must activate 'artemis-dfir' tab when keyword matches"
    );
    assert!(
        js.contains("highlightSettingsNav('artemis-dfir');"),
        "Settings search must highlight 'artemis-dfir' nav button"
    );
    let normalized_js = js.replace("\r\n", "\n");
    assert!(
        normalized_js.contains("q.includes('telemetry') || q.includes('evtx')) {\n        activeSettingsTab = 'artemis-dfir';"),
        "Settings search auto-jump branch for 'artemis-dfir' must include q.includes('evtx')"
    );
}
