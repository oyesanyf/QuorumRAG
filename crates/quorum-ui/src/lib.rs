//! # QuorumRAG Web UI & Static Assets
//!
//! Embedded responsive ChatGPT-like web interface, static asset handler with
//! mime resolution, LangExtract visualizer, and SPA fallback.

pub mod assets;

pub use assets::{get_asset, get_index_html, static_handler, WebAssets};

#[cfg(test)]
mod tests {
    #[test]
    fn test_every_folder_selector_under_settings_is_click_to_select_not_text_input() {
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let html = std::fs::read_to_string(manifest_dir.join("assets/index.html"))
            .expect("assets/index.html must exist");
        let js = std::fs::read_to_string(manifest_dir.join("assets/app.js"))
            .expect("assets/app.js must exist");

        assert!(html.contains(r#"<input type="hidden" id="reindex-target-path""#));
        assert!(!html.contains(r#"type="text" id="reindex-target-path""#));
        assert!(
            html.contains(r#"id="btn-browse-reindex-folder""#)
                && html.contains(r#"id="reindex-folder-explorer-mount""#)
        );

        for hidden_id in [
            "mkt-folder-input",
            "new-doc-path-input",
            "new-shared-folder-input",
            "dlp-sim-path",
            "artemis-jsonl-dir-input",
        ] {
            let hidden_pattern = format!(r#"<input type="hidden" id="{hidden_id}""#);
            let text_pattern = format!(r#"<input type="text" id="{hidden_id}""#);
            assert!(js.contains(&hidden_pattern) || html.contains(&hidden_pattern));
            assert!(!js.contains(&text_pattern) && !html.contains(&text_pattern));
        }

        for ctx in ["general", "mkt", "newdoc", "mesh", "storage", "reindex", "artemis"] {
            let explorer_ctx = format!("contextId: '{ctx}'");
            assert!(js.contains(&explorer_ctx));
        }
        assert!(
            html.contains(r#"id="modal-pure-rust-folder-picker""#)
                && js.contains("window.openPureRustFolderPicker = async function")
        );
    }
}
