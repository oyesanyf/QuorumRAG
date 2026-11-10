//! Artemis DFIR & Forensics WebUI Settings Verification Suite
//!
//! Verifies:
//! 1. Navigation item `data-tab="artemis-dfir"` in `index.html`
//! 2. Static initial SSR markup in `index.html`
//! 3. Zero visible text inputs for folder selection (Mandatory User Invariant)
//! 4. Click-to-select folder controls (Native picker, upload input, pill display, interactive explorer)
//! 5. Default-off master toggles and prohibited categories matrix
//! 6. Live keyed BLAKE3 structural normalizer preview controls
//! 7. Event delegation actions wired to daemon REST endpoints

use quorum_ui::{get_asset, get_index_html};

#[test]
fn test_artemis_dfir_settings_nav_in_index_html() {
    let html = get_index_html();
    assert!(
        html.contains(r#"data-tab="artemis-dfir""#),
        "index.html must include settings navigation item data-tab=\"artemis-dfir\""
    );
    assert!(
        html.contains("Artemis DFIR &amp; Forensics"),
        "index.html nav item must display 'Artemis DFIR & Forensics'"
    );
}

#[test]
fn test_artemis_dfir_initial_markup_in_index_html() {
    let html = get_index_html();

    assert!(
        html.contains(r#"id="settings-tab-artemis-dfir""#),
        "index.html must contain #settings-tab-artemis-dfir container"
    );
    assert!(
        html.contains(r#"<input type="hidden" id="artemis-jsonl-dir-input""#),
        "index.html must contain hidden state input for #artemis-jsonl-dir-input"
    );
    assert!(
        !html.contains(r#"type="text" id="artemis-jsonl-dir-input""#),
        "index.html must NEVER contain a text input for #artemis-jsonl-dir-input"
    );
    assert!(
        html.contains(r#"id="artemis-selected-folder-display""#),
        "index.html must contain #artemis-selected-folder-display"
    );
    assert!(
        html.contains(r#"data-action="trigger-native-folder-picker" data-context="artemis""#),
        "index.html must contain native folder picker button for context artemis"
    );
    assert!(
        html.contains(r#"id="artemis-folder-upload-input" webkitdirectory"#),
        "index.html must contain folder upload input with webkitdirectory"
    );
    assert!(
        html.contains(r#"id="artemis-folder-browser-list""#),
        "index.html must contain #artemis-folder-browser-list"
    );
    assert!(
        html.contains(r#"id="chk-artemis-collection-toggle""#),
        "index.html must contain master collection toggle"
    );
    assert!(
        html.contains(r#"id="chk-artemis-harvest-toggle""#),
        "index.html must contain master harvest toggle"
    );
    assert!(
        html.contains(r#"data-action="trigger-artemis-collect""#),
        "index.html must contain on-demand collection trigger"
    );
    assert!(
        html.contains(r#"id="artemis-preview-input""#),
        "index.html must contain preview input element"
    );
    assert!(
        html.contains(r#"data-action="test-artemis-preview""#),
        "index.html must contain preview test trigger"
    );
    assert!(
        html.contains(r#"id="artemis-preview-result-container""#),
        "index.html must contain preview result container"
    );
}

#[test]
fn test_artemis_dfir_click_to_select_folder_controls_in_app_js() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);

    // 1. Tab container and branch
    assert!(
        js.contains("tab === 'artemis-dfir'"),
        "app.js must handle tab switch branch tab === 'artemis-dfir'"
    );
    assert!(
        js.contains(r#"id="settings-tab-artemis-dfir""#),
        "app.js must render container with id=\"settings-tab-artemis-dfir\""
    );

    // 2. Strict hidden input for folder state (ZERO text input for folder paths)
    assert!(
        js.contains(r#"<input type="hidden" id="artemis-jsonl-dir-input""#),
        "#artemis-jsonl-dir-input must be <input type=\"hidden\">"
    );
    assert!(
        !js.contains(r#"type="text" id="artemis-jsonl-dir-input""#)
            && !js.contains(r#"id="artemis-jsonl-dir-input" type="text""#),
        "#artemis-jsonl-dir-input must NEVER be a visible text input"
    );

    // 3. Visual selected folder pill display
    assert!(
        js.contains(r#"id="artemis-selected-folder-display""#),
        "app.js must render #artemis-selected-folder-display"
    );
    assert!(
        js.contains("chatgpt-selected-folder-pill"),
        "#artemis-selected-folder-display must use class chatgpt-selected-folder-pill"
    );

    // 4. Native OS folder picker with artemis context
    assert!(
        js.contains(r#"data-action="trigger-native-folder-picker" data-context="artemis""#),
        "app.js must render native OS folder picker with data-context=\"artemis\""
    );

    // 5. Upload folder picker via webkitdirectory
    assert!(
        js.contains(r#"id="artemis-folder-upload-input" webkitdirectory directory multiple"#),
        "app.js must render folder upload input with webkitdirectory directory multiple"
    );

    // 6. Interactive Windows File Explorer container
    assert!(
        js.contains(r#"id="artemis-folder-browser-list""#),
        "app.js must render #artemis-folder-browser-list"
    );
    assert!(
        js.contains("contextId: 'artemis'"),
        "renderWindowsFileExplorerHtml must be called with contextId: 'artemis'"
    );
}

#[test]
fn test_artemis_dfir_master_toggles_and_prohibitions_in_app_js() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);

    // Master toggles exist
    assert!(
        js.contains(r#"id="chk-artemis-collection-toggle""#),
        "app.js must render #chk-artemis-collection-toggle"
    );
    assert!(
        js.contains(r#"id="chk-artemis-harvest-toggle""#),
        "app.js must render #chk-artemis-harvest-toggle"
    );
    assert!(
        js.contains(r#"id="chk-artemis-redact-secrets""#),
        "app.js must render #chk-artemis-redact-secrets"
    );
    assert!(
        js.contains(r#"id="chk-artemis-normalize-harvest""#),
        "app.js must render #chk-artemis-normalize-harvest"
    );

    // Defensive and prohibited categories
    assert!(
        js.contains("ALLOWLISTED"),
        "app.js must display ALLOWLISTED badge for defensive categories"
    );
    assert!(
        js.contains("PROHIBITED"),
        "app.js must display PROHIBITED badge for personal/credential stores"
    );
    assert!(
        js.contains("browser_cookies") && js.contains("credential_store"),
        "app.js must include browser_cookies and credential_store in prohibited categories"
    );

    // Airgap Notice Card
    assert!(
        js.contains("P2P MESH AIRGAP ACTIVE") || js.contains("Zero-Mesh Isolation Guarantee"),
        "app.js must display P2P Mesh Airgap notice card"
    );
    assert!(
        js.contains("Tier3Restricted") || js.contains("access_tier: 3"),
        "app.js must explain Tier3Restricted / access_tier: 3 airgap policy"
    );

    // HTML5 boolean attribute regression prevention: checked=false evaluates to checked === true in DOM
    assert!(
        !js.contains("checked=false"),
        "CRITICAL REGRESSION: app.js must NEVER contain 'checked=false' because HTML5 boolean attribute semantics evaluate any presence of 'checked' to true"
    );
    assert!(
        js.contains(r#"<input type="checkbox" class="quorum-switch" disabled title="Prohibited category cannot be enabled""#),
        "app.js must render prohibited category checkboxes as disabled without checked attribute so they are OFF"
    );
}

#[test]
fn test_artemis_dfir_event_delegation_actions_wired() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);

    let artemis_actions = [
        "artemis-pick-folder",
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

    for action in artemis_actions {
        let pattern = format!("'{}'", action);
        assert!(
            js.contains(&pattern),
            "initSettingsEventDelegation must handle action '{}'",
            action
        );
    }

    // Context handler check in trigger-native-folder-picker
    assert!(
        js.contains("ctx === 'artemis'"),
        "trigger-native-folder-picker must handle ctx === 'artemis'"
    );

    // Endpoints checked
    assert!(
        js.contains("/api/v1/artemis/status"),
        "app.js must query /api/v1/artemis/status"
    );
    assert!(
        js.contains("/api/v1/artemis/config"),
        "app.js must query /api/v1/artemis/config"
    );
    assert!(
        js.contains("/api/v1/artemis/collect"),
        "app.js must invoke /api/v1/artemis/collect"
    );
    assert!(
        js.contains("/api/v1/artemis/preview-normalizer"),
        "app.js must invoke /api/v1/artemis/preview-normalizer"
    );
}

#[test]
fn test_artemis_dfir_search_auto_jump_and_upload_refresh() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);
    let normalized_js = js.replace("\r\n", "\n");

    // 1. Search auto-jump condition for artemis-dfir MUST include evtx
    assert!(
        normalized_js.contains("q.includes('telemetry') || q.includes('evtx')) {\n        activeSettingsTab = 'artemis-dfir';"),
        "app.js search auto-jump must include q.includes('evtx') in activeSettingsTab = 'artemis-dfir' condition"
    );

    // 2. Nav item filter must also match evtx
    assert!(
        js.contains("q.includes('evtx')"),
        "app.js search nav filter must include 'evtx'"
    );

    // 3. Folder upload action must immediately re-render artemis-dfir tab content
    assert!(
        js.contains("case 'artemis-upload-folder':")
            && js.contains("renderSettingsTabContent('artemis-dfir', '');"),
        "artemis-upload-folder action must call renderSettingsTabContent('artemis-dfir', '')"
    );
}

