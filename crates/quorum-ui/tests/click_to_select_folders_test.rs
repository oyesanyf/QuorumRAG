//! Mechanical verification that every folder selection control across Settings and modals
//! uses click-to-select controls (native OS folder picker, folder browser, or directory file input)
//! and never requires typing folder paths into `<input type="text">`.

#[test]
fn test_every_folder_selector_under_settings_is_click_to_select_not_text_input() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let html = std::fs::read_to_string(manifest_dir.join("assets/index.html"))
        .expect("assets/index.html must exist");
    let js = std::fs::read_to_string(manifest_dir.join("assets/app.js"))
        .expect("assets/app.js must exist");

    // 1. Reindex modal in index.html must use hidden input + click-to-select explorer & browse button
    assert!(
        html.contains(r#"<input type="hidden" id="reindex-target-path""#),
        "#reindex-target-path in index.html must be <input type=\"hidden\"> (not a text input)"
    );
    assert!(
        !html.contains(r#"type="text" id="reindex-target-path""#),
        "#reindex-target-path must never be <input type=\"text\">"
    );
    assert!(
        html.contains(r#"id="btn-browse-reindex-folder""#)
            && html.contains(r#"id="reindex-folder-explorer-mount""#),
        "Reindex modal must provide click-to-select browse button and explorer mount"
    );

    // 2. All folder path state inputs in app.js and index.html must be <input type="hidden"> (never type="text")
    for hidden_id in [
        "mkt-folder-input",
        "new-doc-path-input",
        "new-shared-folder-input",
        "dlp-sim-path",
        "artemis-jsonl-dir-input",
    ] {
        let hidden_pattern = format!(r#"<input type="hidden" id="{hidden_id}""#);
        let text_pattern = format!(r#"<input type="text" id="{hidden_id}""#);
        assert!(
            js.contains(&hidden_pattern) || html.contains(&hidden_pattern),
            "Folder state input #{hidden_id} must be <input type=\"hidden\">"
        );
        assert!(
            !js.contains(&text_pattern) && !html.contains(&text_pattern),
            "Folder state input #{hidden_id} must NEVER be <input type=\"text\">"
        );
    }

    // 3. Entire folder upload via webkitdirectory + native OS folder dialog + Windows Explorer component
    assert!(
        js.contains(r#"id="add-new-folder-file-input" webkitdirectory directory multiple"#)
            || js.contains(r#"id="artemis-folder-upload-input" webkitdirectory directory multiple"#),
        "Must support clicking to upload an entire folder via webkitdirectory"
    );
    for ctx in [
        "general", "mkt", "newdoc", "mesh", "storage", "reindex", "artemis", "dlp",
    ] {
        let explorer_ctx = format!("contextId: '{ctx}'");
        assert!(
            js.contains(&explorer_ctx),
            "renderWindowsFileExplorerHtml must be wired for context '{ctx}'"
        );
    }
    assert!(
        js.contains("window.quorumIndexFolderImmediate = async function(folderPath)"),
        "Clicking a folder in Add Documents / Storage must immediately watch and index it via quorumIndexFolderImmediate"
    );

    // 4. Artemis DFIR settings tab click-to-select folder controls
    assert!(
        html.contains(r#"data-tab="artemis-dfir""#),
        "index.html must contain navigation item for data-tab=\"artemis-dfir\""
    );
    assert!(
        html.contains(r#"id="settings-tab-artemis-dfir""#) && js.contains(r#"id="settings-tab-artemis-dfir""#),
        "index.html and app.js must contain #settings-tab-artemis-dfir container"
    );
    assert!(
        html.contains(r#"id="artemis-selected-folder-display""#)
            && js.contains(r#"id="artemis-selected-folder-display""#),
        "Must contain #artemis-selected-folder-display visual pill"
    );
    assert!(
        html.contains(r#"id="artemis-folder-upload-input""#)
            && js.contains(r#"id="artemis-folder-upload-input""#),
        "Must contain #artemis-folder-upload-input with webkitdirectory"
    );
    assert!(
        html.contains(r#"id="artemis-folder-browser-list""#)
            && js.contains(r#"id="artemis-folder-browser-list""#),
        "Must contain #artemis-folder-browser-list explorer container"
    );
    assert!(
        html.contains(r#"data-action="trigger-native-folder-picker" data-context="artemis""#)
            && js.contains(r#"data-action="trigger-native-folder-picker" data-context="artemis""#),
        "Must contain folder picker button for context artemis"
    );

    // 5. Pure Rust In-UI Folder Picker Modal & Zero External Windows Explorer Dialogs
    assert!(
        html.contains(r#"id="modal-pure-rust-folder-picker""#)
            && js.contains("window.openPureRustFolderPicker = async function"),
        "All folder openers must open the in-UI Pure Rust Folder Picker Modal (#modal-pure-rust-folder-picker)"
    );
    assert!(
        !html.contains("Browse with Windows Explorer...")
            && !js.contains("Browse with Windows Explorer..."),
        "UI must never prompt to open a separate Windows Explorer dialog"
    );
    assert!(
        js.contains("ensurePureRustPickerModal")
            && js.contains("window.applyPickedFolderToContext = async function"),
        "Pure Rust folder picker modal must be self-initializing and wire all contexts in UI"
    );
    assert!(
        html.contains(r#"id="pure-rust-picker-filter-input""#)
            && html.contains(r#"id="btn-pure-rust-picker-create-folder""#),
        "Pure Rust folder picker modal must support live folder filtering and Pure Rust subfolder creation"
    );

    // 6. Artemis DFIR Settings tab must include auto-collection schedule, retention window, and live telemetry badges
    assert!(
        js.contains(r#"id="sel-artemis-auto-interval""#)
            && js.contains(r#"data-change-action="artemis-update-interval""#),
        "Artemis DFIR Settings must expose background auto-collection interval control"
    );
    assert!(
        js.contains(r#"id="sel-artemis-retention-days""#)
            && js.contains(r#"data-change-action="artemis-update-retention""#),
        "Artemis DFIR Settings must expose retention window control"
    );
    assert!(
        js.contains(r#"id="artemis-total-collected-badge""#)
            && js.contains(r#"id="artemis-last-collection-badge""#),
        "Artemis DFIR Settings must expose live collected records and timestamp status badges"
    );

    // 7. Service-mode Session-0 resilience, checkbox toggle preservation, POSIX/UNC/Windows breadcrumbs & dialog accessibility
    assert!(
        js.contains("candidate.cancelled !== true")
            && js.contains("/api/fs/browse-folders?"),
        "loadPureRustPickerDirectory must fall back cleanly to /api/fs/browse-folders when /api/fs/pick-folder returns cancelled in Windows Service mode"
    );
    assert!(
        js.contains("function preventIfNotCheckbox(")
            && js.contains("resolveCleanQuickAccess"),
        "Folder row checkboxes must preserve native check state via preventIfNotCheckbox and strip service-account systemprofile paths"
    );
    assert!(
        js.contains("raw.startsWith('/')"),
        "buildPathBreadcrumbs must support POSIX / paths alongside Windows drive and UNC paths"
    );
    assert!(
        js.contains("z-index:250000") && js.contains("aria-live"),
        "#quorum-settings-toast must render above #modal-pure-rust-folder-picker with polite live-region announcements"
    );
    assert!(
        html.contains(r#"id="modal-pure-rust-folder-picker" class="modal-backdrop hidden" role="dialog" aria-modal="true" aria-labelledby="pure-rust-picker-title""#),
        "#modal-pure-rust-folder-picker must expose accessible dialog semantics (role=\"dialog\", aria-modal=\"true\", aria-labelledby)"
    );

    // 8. Clean user-facing "Select Folder" naming (never "Pure Rust") & drive-root drill-down
    assert!(
        !html.to_ascii_lowercase().contains("pure rust")
            && !js.to_ascii_lowercase().contains("pure rust"),
        "User-facing HTML and JS must never label folder selection as 'Pure Rust' — use 'Select Folder'"
    );
    assert!(
        html.contains("📁 Select Folder")
            && js.contains("📁 Select Folder")
            && js.contains("Drives on this asset:"),
        "Folder selector buttons and modal must say 'Select Folder' and display physical drives on the asset"
    );
    assert!(
        js.contains("const startPath = String(initialPath || '').trim();")
            && js.contains("canonicalComparePathJs")
            && js.contains("normalizeQuickAccessCategoryKey"),
        "Select Folder must open at asset drives root by default and deduplicate quick-access shortcuts"
    );
}
