use quorum_ui::{get_asset, get_index_html};

fn normalized_assets() -> (String, String, String) {
    let html = get_index_html().replace("\r\n", "\n");
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes).replace("\r\n", "\n");
    let (css_bytes, _) = get_asset("styles.css").expect("styles.css must be embedded");
    let css = String::from_utf8_lossy(&css_bytes).replace("\r\n", "\n");
    (html, js, css)
}

#[test]
fn test_cloud_drives_nav_item_and_storage_quick_jump() {
    let (html, js, _css) = normalized_assets();

    assert!(
        html.contains(r#"<button class="chatgpt-nav-item" data-tab="cloud-drives""#)
            && html.contains(r#"<span class="nav-item-label">Cloud Drives</span>"#),
        "index.html #settings-nav-list must include top-level Cloud Drives nav item"
    );

    // Verify all Settings sidebar navigation items inside #settings-nav-list are sorted alphabetically (A -> Z).
    let nav_start = html
        .find(r#"<nav id="settings-nav-list""#)
        .expect("#settings-nav-list must exist in index.html");
    let nav_end = html[nav_start..]
        .find("</nav>")
        .expect("#settings-nav-list must have closing </nav>")
        + nav_start;
    let nav_slice = &html[nav_start..nav_end];
    let mut nav_labels: Vec<String> = Vec::new();
    let needle = r#"<span class="nav-item-label">"#;
    let mut cursor = 0usize;
    while let Some(pos) = nav_slice[cursor..].find(needle) {
        let start = cursor + pos + needle.len();
        if let Some(end_rel) = nav_slice[start..].find("</span>") {
            let label = nav_slice[start..start + end_rel]
                .replace("&amp;", "&")
                .trim()
                .to_string();
            nav_labels.push(label);
            cursor = start + end_rel + 7;
        } else {
            break;
        }
    }
    assert!(
        nav_labels.len() >= 20,
        "Expected all settings nav items in #settings-nav-list, got {}",
        nav_labels.len()
    );
    let mut sorted_labels = nav_labels.clone();
    sorted_labels.sort_by_key(|a| a.to_ascii_lowercase());
    assert_eq!(
        nav_labels, sorted_labels,
        "Settings sidebar items must be arranged in strict alphabetical order"
    );

    let storage_idx = js
        .find("else if (tab === 'storage')")
        .expect("storage tab branch must exist in app.js");
    let cloud_idx = js
        .find("else if (tab === 'cloud-drives')")
        .expect("cloud-drives tab branch must exist in app.js");
    assert!(
        cloud_idx > storage_idx,
        "cloud-drives branch should follow storage branch"
    );
    let storage_slice = &js[storage_idx..cloud_idx];
    assert!(
        storage_slice.contains(r#"data-action="jump-tab" data-tab="cloud-drives""#),
        "Storage tab must contain a quick-jump button to cloud-drives"
    );

    let search_start = js
        .find("if (settingsSearchInput)")
        .expect("settingsSearchInput block must exist in app.js");
    let search_end = js[search_start..]
        .find("async function saveUiSettingsPatch(")
        .expect("saveUiSettingsPatch must follow settingsSearchInput block")
        + search_start;
    let search_slice = &js[search_start..search_end];

    for kw in [
        "cloud",
        "gdrive",
        "google drive",
        "onedrive",
        "dropbox",
        "icloud",
        r"/\bbox\b/",
        "nextcloud",
        "proton",
        "pcloud",
        "hydrate",
        "placeholder",
    ] {
        assert!(
            search_slice.contains(kw),
            "app.js #settings-search-input handler must include keyword '{kw}'"
        );
    }
    assert!(
        search_slice.contains("activeSettingsTab = 'cloud-drives';")
            && search_slice.contains("highlightSettingsNav('cloud-drives');"),
        "Settings search input handler must auto-jump and highlight cloud-drives"
    );
}

#[test]
fn test_cloud_drives_providers_default_off_and_badges() {
    let (_html, js, css) = normalized_assets();

    for provider_id in [
        "google_drive",
        "onedrive_personal",
        "onedrive_business",
        "dropbox",
        "icloud_drive",
        "box",
        "nextcloud",
        "proton_drive",
        "pcloud",
    ] {
        assert!(
            js.contains(provider_id),
            "app.js must include cloud drive provider metadata for '{provider_id}'"
        );
    }

    for label in [
        "Google Drive",
        "OneDrive (Personal)",
        "OneDrive (Business)",
        "Dropbox",
        "iCloud Drive",
        "Box",
        "Nextcloud",
        "Proton Drive",
        "pCloud",
    ] {
        assert!(
            js.contains(label),
            "app.js must include provider label '{label}'"
        );
    }

    assert!(
        js.contains("placeholder_mode: 'locally_synced_only'")
            && js.contains("hydration_max_file_size_mb: 25")
            && js.contains("default_enabled: false")
            && js.contains("default_access_tier: 3"),
        "app.js default cloud drives policy must default to disabled, locally_synced_only, 25 MB, Tier 3"
    );

    for badge_text in [
        "Mounted",
        "Not Detected",
        "Session Only",
        "Indexed files:",
        "Local-Only (Mesh Excluded)",
        "Shared with Mesh",
    ] {
        assert!(
            js.contains(badge_text),
            "app.js cloud-drives renderer must display '{badge_text}' badge"
        );
    }

    assert!(
        js.contains("running_as_local_system")
            && js.contains("virtual_drive_guidance")
            && js.contains("session_guidance"),
        "app.js must surface LocalSystem and virtual drive session guidance"
    );

    assert!(
        css.contains(".cloud-drive-card")
            && css.contains(".cloud-drive-banner")
            && css.contains(".cloud-drive-badge"),
        "styles.css must define scoped .cloud-drive-* classes"
    );
}

#[test]
fn test_cloud_drives_hydration_controls_and_access_tier_isolation() {
    let (_html, js, _css) = normalized_assets();

    assert!(
        js.contains("chk-cloud-hydrate-on-demand")
            && js.contains("Hydrate cloud-only files on demand")
            && js.contains("Locally synced files only")
            && js.contains("FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS")
            && js.contains("FILE_ATTRIBUTE_OFFLINE")
            && js.contains("SF_DATALESS"),
        "app.js must render placeholder protection toggle and OS stub attribute explanation"
    );

    assert!(
        js.contains(r#"id="cloud-hydration-max-mb" type="number""#) && js.contains(r#"min="1""#),
        "app.js must render numeric per-file hydration size cap control"
    );

    assert!(
        js.contains(r#"data-change-action="cloud-drive-toggle""#)
            && js.contains(r#"data-action="cloud-drive-reindex""#)
            && js.contains("Reindex Now"),
        "app.js must render per-drive enable/disable switch and Reindex Now button"
    );

    assert!(
        js.contains(r#"data-change-action="cloud-drive-set-tier""#)
            && js.contains("Tier 3: Local-Only (Default)")
            && js.contains("never shared over P2P Mesh unless explicitly added in Mesh &amp; Shared Folders with Tier &lt; 3"),
        "app.js must render Access Tier selector defaulting to Tier 3 Local-Only with Mesh isolation note"
    );
}

#[test]
fn test_cloud_drives_api_endpoints_and_delegated_actions() {
    let (_html, js, _css) = normalized_assets();

    assert!(
        js.contains("fetch('/api/cloud-drives')")
            && js.contains("fetch('/api/cloud-drives/config'")
            && js.contains("fetch('/api/cloud-drives/reindex'"),
        "app.js must call GET /api/cloud-drives, POST /api/cloud-drives/config, and POST /api/cloud-drives/reindex"
    );

    let add_fn_start = js
        .find("window.quorumCloudDriveAddFolder = async function(")
        .expect("quorumCloudDriveAddFolder must exist");
    let reindex_fn_start = js[add_fn_start..]
        .find("window.quorumCloudDriveReindex = async function(")
        .expect("quorumCloudDriveReindex must follow quorumCloudDriveAddFolder")
        + add_fn_start;
    let open_idx = js
        .find("async function openSettingsView(")
        .expect("openSettingsView must exist");
    let add_fn_slice = &js[add_fn_start..reindex_fn_start];
    let reindex_fn_slice = &js[reindex_fn_start..open_idx];

    assert!(
        add_fn_slice.contains("action: 'add_folder'"),
        "quorumCloudDriveAddFolder must send 'add_folder' to /api/cloud-drives/config"
    );

    let close_idx = js[open_idx..]
        .find("function closeSettingsView()")
        .expect("closeSettingsView must follow openSettingsView")
        + open_idx;
    let open_slice = &js[open_idx..close_idx];
    assert!(
        open_slice.contains("if (tab === 'cloud-drives')")
            && open_slice.contains("await fetchCloudDrivesData(true);")
            && open_slice.contains("if (activeSettingsTab === tab)"),
        "openSettingsView must fetch /api/cloud-drives and guard rendering with activeSettingsTab === tab"
    );

    let nav_idx = js
        .find("document.querySelectorAll('#settings-nav-list .chatgpt-nav-item').forEach")
        .expect("nav click handler must exist");
    let search_idx = js[nav_idx..]
        .find("if (settingsSearchInput)")
        .expect("settingsSearchInput handler must follow nav click handler")
        + nav_idx;
    let nav_slice = &js[nav_idx..search_idx];
    assert!(
        nav_slice.contains("if (tab === 'cloud-drives')")
            && nav_slice.contains("await fetchCloudDrivesData(true);")
            && nav_slice.contains("if (activeSettingsTab === tab)"),
        "sidebar nav click handler must fetch /api/cloud-drives and guard rendering with activeSettingsTab === tab"
    );

    let deleg_idx = js
        .find("function initSettingsEventDelegation()")
        .expect("initSettingsEventDelegation must exist");
    let render_idx = js[deleg_idx..]
        .find("function renderSettingsTabContent(")
        .expect("renderSettingsTabContent must follow initSettingsEventDelegation")
        + deleg_idx;
    let deleg_slice = &js[deleg_idx..render_idx];
    for action in ["toggle_drive", "set_hydration", "remove_folder"] {
        assert!(
            deleg_slice.contains(&format!("action: '{action}'")),
            "initSettingsEventDelegation must send '{action}' to /api/cloud-drives/config"
        );
    }
    for handler in [
        "case 'cloud-drive-reindex':",
        "case 'cloud-drive-remove-folder':",
        "case 'cloud-drive-refresh':",
        "case 'cloud-drive-toggle':",
        "case 'cloud-drive-set-tier':",
        "case 'cloud-drive-select-root':",
        "case 'cloud-drives-set-hydration':",
    ] {
        assert!(
            deleg_slice.contains(handler),
            "initSettingsEventDelegation must handle {handler}"
        );
    }

    assert!(
        deleg_slice.contains("changeEl.checked = !nextEnabled;")
            && deleg_slice.contains("showSettingsToast('⚠ '"),
        "cloud-drive-toggle failure must revert checkbox state and show error toast"
    );
    assert!(
        add_fn_slice.contains("cloudDrivesBusyIds.has(cleanId)")
            && reindex_fn_slice.contains("cloudDrivesBusyIds.has(cleanId)")
            && deleg_slice.matches("cloudDrivesBusyIds.has(driveId)").count() >= 4,
        "all 6 per-drive handlers must guard against concurrent requests via cloudDrivesBusyIds.has(...)"
    );
}

#[test]
fn test_cloud_drives_click_to_select_folder_controls_and_hidden_inputs() {
    let (html, js, _css) = normalized_assets();

    assert!(
        js.contains(r#"data-action="trigger-native-folder-picker" data-context="cloud-drives""#)
            && js.contains("pendingCloudDrivePickerId"),
        "app.js must wire click-to-select native folder picker for cloud-drives"
    );

    let close_picker_idx = js
        .find("function closePureRustPickerModal()")
        .expect("closePureRustPickerModal must exist");
    let apply_idx = js
        .find("window.applyPickedFolderToContext = async function(")
        .expect("applyPickedFolderToContext must exist");
    let close_picker_slice = &js[close_picker_idx..apply_idx];
    assert!(
        close_picker_slice.contains("pendingCloudDrivePickerId = '';"),
        "closePureRustPickerModal must clear pendingCloudDrivePickerId on cancel/close"
    );

    let apply_end = js[apply_idx..]
        .find("function renderPureRustPickerModalContent()")
        .expect("renderPureRustPickerModalContent must follow applyPickedFolderToContext")
        + apply_idx;
    let apply_slice = &js[apply_idx..apply_end];
    assert!(
        apply_slice.contains("else if (ctx === 'cloud-drives')")
            && apply_slice.contains("quorumCloudDriveAddFolder")
            && apply_slice.contains("if (ok) {\n        pendingCloudDrivePickerId = '';\n      }"),
        "applyPickedFolderToContext must preserve pendingCloudDrivePickerId on failure and clear only when ok is truthy"
    );

    assert!(
        js.contains(r#"<input type="hidden" id="cloud-drives-selected-folder-input""#)
            && !js.contains(r#"type="text" id="cloud-drives-selected-folder-input""#),
        "Cloud Drives folder path input must be type=hidden, never type=text"
    );

    assert!(
        !html.to_ascii_lowercase().contains("pure rust")
            && !js.to_ascii_lowercase().contains("pure rust"),
        "HTML and JS must never contain user-facing 'pure rust' text"
    );
}

#[test]
fn test_cloud_drives_layout_alignment_and_xss_hygiene() {
    let (_html, js, _css) = normalized_assets();

    let branch_start = js
        .find("else if (tab === 'cloud-drives')")
        .expect("cloud-drives branch must exist");
    let next_branch = js[branch_start..]
        .find("else if (tab === 'personalization')")
        .expect("personalization branch must follow cloud-drives")
        + branch_start;
    let branch_slice = &js[branch_start..next_branch];

    let inner_marker = "settingsContent.innerHTML = `";
    let inner_start = branch_slice
        .find(inner_marker)
        .expect("cloud-drives branch must assign settingsContent.innerHTML")
        + inner_marker.len();
    let inner_end = branch_slice[inner_start..]
        .find("`;")
        .expect("settingsContent.innerHTML template must terminate cleanly")
        + inner_start;
    let template_body = branch_slice[inner_start..inner_end].trim();

    assert!(
        template_body.starts_with(r#"<div class="settings-centered-container">"#)
            && template_body.ends_with("</div>"),
        "cloud-drives settingsContent.innerHTML must wrap in <div class=\"settings-centered-container\">...</div> with zero nested backtick-semicolons"
    );
    assert!(
        template_body.contains(r#"<h2 class="settings-page-title">☁️ Cloud Drives</h2>"#)
            && !template_body.contains(r#"<h2 class="settings-page-title" style="#),
        "cloud-drives title must use .settings-page-title with zero inline style="
    );

    assert!(
        !js.contains("checked=false"),
        "app.js must never emit checked=false"
    );
    assert!(
        !branch_slice.contains(" onclick=")
            && !branch_slice.contains(" onchange=")
            && !branch_slice.contains(" oninput="),
        "cloud-drives tab must use delegated handlers with zero inline on*= attributes"
    );
    assert!(
        !branch_slice.contains("${JSON.stringify"),
        "cloud-drives tab must never embed raw JSON.stringify inside HTML attributes"
    );
    for escaped_expr in [
        "escapeHtml(drvLabel)",
        "escapeHtml(drvId)",
        "escapeHtml(drv.root_path",
        "escapeHtml(guidanceText)",
        "escapeHtml(bannerText)",
        "escapeHtml(cp)",
    ] {
        assert!(
            branch_slice.contains(escaped_expr),
            "cloud-drives template must escape dynamic field via {escaped_expr}"
        );
    }
}

#[test]
fn test_cloud_drives_raptor_security_and_no_mock_data() {
    let (_html, js, _css) = normalized_assets();

    for forbidden in [
        "eval(",
        "new Function(",
        "document.write(",
        "document.writeln(",
    ] {
        assert!(
            !js.contains(forbidden),
            "app.js must not contain dangerous sink '{forbidden}'"
        );
    }

    for fake in ["/Users/johndoe", "C:\\\\FakeDrive", "John Doe"] {
        assert!(
            !js.contains(fake),
            "app.js must never contain fake/mock cloud drive data '{fake}'"
        );
    }

    assert!(
        js.contains("Backend Offline / Unavailable") && js.contains("🔄 Retry"),
        "cloud-drives tab must render honest offline/error state with Retry when daemon is unreachable"
    );
}

#[test]
fn test_cloud_drives_concurrency_hydration_footer_and_light_theme_contrast() {
    let (_html, js, css) = normalized_assets();

    let fetch_idx = js
        .find("async function fetchCloudDrivesData(")
        .expect("fetchCloudDrivesData must exist");
    let post_idx = js[fetch_idx..]
        .find("async function postCloudDrivesConfig(")
        .expect("postCloudDrivesConfig must follow fetchCloudDrivesData")
        + fetch_idx;
    let fetch_slice = &js[fetch_idx..post_idx];
    assert!(
        fetch_slice.contains("const seq = ++cloudDrivesFetchSeq;")
            && fetch_slice.contains("if (seq !== cloudDrivesFetchSeq)")
            && fetch_slice.contains("if (seq === cloudDrivesFetchSeq)"),
        "fetchCloudDrivesData must use monotonic cloudDrivesFetchSeq to discard stale responses"
    );

    let reset_idx = js
        .find("window._resetSettingsToDefaults = async function()")
        .expect("_resetSettingsToDefaults must exist");
    let close_footer_idx = js[reset_idx..]
        .find("window._closeSettingsFromFooter = function()")
        .expect("_closeSettingsFromFooter must follow _resetSettingsToDefaults")
        + reset_idx;
    let reset_slice = &js[reset_idx..close_footer_idx];
    assert!(
        reset_slice.contains("fetch('/api/cloud-drives/config'")
            && reset_slice.contains("placeholder_mode: 'locally_synced_only'")
            && reset_slice.contains("hydration_max_file_size_mb: 25")
            && reset_slice.contains("cachedCloudDrivesData = null;")
            && reset_slice.contains("if (activeSettingsTab === 'cloud-drives')"),
        "_resetSettingsToDefaults must reset cloud drives hydration policy and refresh when active"
    );

    let save_footer_idx = js
        .find("window._saveAllPreferencesFromFooter = async function()")
        .expect("_saveAllPreferencesFromFooter must exist");
    let mesh_cfg_idx = js[save_footer_idx..]
        .find("window.quorumUpdateMeshConfig = async function(")
        .expect("quorumUpdateMeshConfig must follow _saveAllPreferencesFromFooter")
        + save_footer_idx;
    let save_footer_slice = &js[save_footer_idx..mesh_cfg_idx];
    assert!(
        save_footer_slice.contains("chk-cloud-hydrate-on-demand")
            && save_footer_slice.contains("cloud-hydration-max-mb")
            && save_footer_slice.contains("rawMax === '' ? NaN")
            && save_footer_slice.contains("action: 'set_hydration'"),
        "_saveAllPreferencesFromFooter must persist cloud drives hydration with empty-string fallback to 25 MB"
    );

    assert!(
        css.contains("body.theme-white .cloud-drive-card .dlp-badge-redact")
            && css.contains("body.theme-warm .cloud-drive-card .dlp-badge-redact")
            && css.contains("body.theme-white .cloud-drive-banner .dlp-badge-redact")
            && css.contains("body.theme-warm .cloud-drive-banner .dlp-badge-redact"),
        "styles.css must provide readable light-theme overrides for cloud-drives .dlp-badge-redact"
    );
}

#[test]
fn test_folder_picker_select_and_unselect_any_folder_controls() {
    let (html, js, css) = normalized_assets();

    assert!(
        html.contains(r#"id="pure-rust-picker-selected-bar""#)
            && html.contains(r#"id="btn-cancel-pure-rust-picker" class="pill-btn">Done</button>"#),
        "index.html static Select Folder modal must include #pure-rust-picker-selected-bar and Done button"
    );

    assert!(
        js.contains("window.quorumCloudDriveRemoveFolder = async function(")
            && js.contains("window.togglePickedFolderInContext = async function(")
            && js.contains("function getPickerSelectedPaths(")
            && js.contains("function isPickerPathSelected("),
        "app.js must expose select/unselect toggle helpers across folder picker contexts"
    );
    assert!(
        js.contains(r#"id="pure-rust-picker-selected-bar""#)
            && js.contains("data-picker-toggle=")
            && js.contains("data-picker-unselect=")
            && js.contains("✓ Selected — Unselect")
            && js.contains("✕ Unselect Folder (")
            && js.contains("✕ Unselect Active Folder"),
        "folder picker modal and inline explorer must render explicit checkboxes, selected chips, and unselect buttons"
    );
    assert!(
        css.contains(".picker-selected-bar")
            && css.contains(".picker-selected-chip")
            && css.contains(".folder-checkbox-hit")
            && css.contains(".folder-row-checkbox:focus-visible"),
        "styles.css must style the selected-folders chip bar, checkbox hit target, and :focus-visible ring"
    );
}
