//! Mechanical verification that every folder selection control across Settings and modals
//! uses click-to-select controls (native OS folder picker, folder browser, or directory file input)
//! and never requires typing folder paths into `<input type="text">`.

use quorum_ui::{get_asset, get_index_html};

#[test]
fn test_every_folder_selector_under_settings_is_click_to_select_not_text_input() {
    let html = get_index_html();
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);

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
    for ctx in ["general", "mkt", "newdoc", "mesh", "storage", "reindex", "artemis"] {
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
        "Must contain native folder picker button for context artemis"
    );
}
