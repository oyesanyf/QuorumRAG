//! Tier 1 E2E Tests: Placeholder Protection, Ingest/DLP, Prefix Purge, Mesh Isolation,
//! Local Retrieval, Daemon API, `LocalSystem` / Virtual Drives & WebUI (`F9`–`F18`).
//!
//! 51 opaque-box tests (`F9`:5, `F10`:5, `F11`:5, `F12`:5, `F13`:5, `F14`:5, `F15`:5,
//! `F16`:5, `F17`:5, `F18`:6) against the real `quorumrag` binary, real Win32 file attributes,
//! real HTTP JSON endpoints, `<data_dir>/settings.json`, and real `quorum-ui` assets.

use quorum_e2e::cloud_drives_harness::{
    atlaskv_result_contains_token, find_drive, paths_equivalent, query_result_contains_token,
    query_result_mentions_path, read_repo_ui_assets, set_windows_offline_attribute,
    DaemonTestProcess, ExclusiveFileLockGuard, FakeCloudWorkspace,
};
use quorum_ingest::cloud_drives::{
    is_macos_cloud_placeholder_flags, is_windows_cloud_placeholder_attrs,
    should_skip_cloud_placeholder, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    FILE_ATTRIBUTE_RECALL_ON_OPEN, MACOS_SF_DATALESS,
};
use quorum_types::CloudPlaceholderPolicy;
use reqwest::StatusCode;
use serde_json::json;
use std::time::Duration;

fn extract_cloud_drives_tab_slice(js: &str) -> &str {
    let marker = "else if (tab === 'cloud-drives')";
    let start = js
        .find(marker)
        .expect("app.js renderSettingsTabContent must handle else if (tab === 'cloud-drives')");
    let after = &js[start..];
    let end = after[marker.len()..]
        .find("} else if (tab ===")
        .map(|i| i + marker.len())
        .unwrap_or(after.len());
    &after[..end]
}

fn extract_storage_tab_slice(js: &str) -> &str {
    let marker = "else if (tab === 'storage')";
    let start = js
        .find(marker)
        .expect("app.js renderSettingsTabContent must handle else if (tab === 'storage')");
    let after = &js[start..];
    let end = after[marker.len()..]
        .find("} else if (tab ===")
        .map(|i| i + marker.len())
        .unwrap_or(after.len());
    &after[..end]
}

fn extract_settings_search_slice(js: &str) -> &str {
    let start = js
        .find("if (settingsSearchInput)")
        .expect("app.js must define settingsSearchInput handler");
    let end = js[start..]
        .find("async function saveUiSettingsPatch(")
        .expect("saveUiSettingsPatch must follow settingsSearchInput block")
        + start;
    &js[start..end]
}

fn extract_settings_nav_slice(html: &str) -> &str {
    let start = html
        .find(r#"id="settings-nav-list""#)
        .expect("index.html must include #settings-nav-list");
    let end = html[start..]
        .find("</nav>")
        .expect("#settings-nav-list must close with </nav>")
        + start;
    &html[start..end]
}

// ============================================================================
// F9: Placeholder Protection (`LocallySyncedOnly`) (5 tests)
// ============================================================================

#[tokio::test]
async fn t1_f9_locally_synced_normal_file_accepted() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(
        &dropbox,
        "synced_notes.md",
        "TOKEN_F9_NORMAL_FILE locally synced content",
    );

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    assert_eq!(
        payload["placeholder_mode"].as_str(),
        Some("locally_synced_only")
    );
    assert!(
        find_drive(&payload, "dropbox")["indexed_files"]
            .as_u64()
            .unwrap_or(0)
            >= 1
    );
    let qr = daemon.query_local("TOKEN_F9_NORMAL_FILE").await;
    assert!(query_result_contains_token(&qr, "TOKEN_F9_NORMAL_FILE"));
}

#[tokio::test]
async fn t1_f9_win_offline_attr_skipped_without_open() {
    // Verify Win32 Cloud Filter recall bits and macOS SF_DATALESS bitmask policy contracts across OSes
    assert!(is_windows_cloud_placeholder_attrs(
        FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    ));
    assert!(is_windows_cloud_placeholder_attrs(
        FILE_ATTRIBUTE_RECALL_ON_OPEN
    ));
    assert!(is_macos_cloud_placeholder_flags(MACOS_SF_DATALESS));
    assert!(should_skip_cloud_placeholder(
        true,
        128,
        CloudPlaceholderPolicy::LocallySyncedOnly
    ));

    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "local_ok.txt", "TOKEN_F9_LOCAL_OK real file");

    let _lock = if cfg!(windows) {
        let stub = ws.write_doc(
            &dropbox,
            "cloud_stub.txt",
            "TOKEN_F9_STUB_MUST_SKIP placeholder",
        );
        set_windows_offline_attribute(&stub).expect("set FILE_ATTRIBUTE_OFFLINE");
        Some(ExclusiveFileLockGuard::lock(&stub).expect("exclusive lock on offline stub"))
    } else {
        None
    };

    let daemon = DaemonTestProcess::start(&ws).await;
    let updated = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    daemon
        .wait_for_reindex_settled(Duration::from_secs(10))
        .await;

    let drv = find_drive(&updated, "dropbox");
    assert_eq!(
        drv["indexed_files"].as_u64(),
        Some(1),
        "Only local_ok.txt should be indexed while offline stub is skipped: {}",
        drv
    );
    let qr_ok = daemon.query_local("TOKEN_F9_LOCAL_OK").await;
    assert!(query_result_contains_token(&qr_ok, "TOKEN_F9_LOCAL_OK"));
    if cfg!(windows) {
        let qr_stub = daemon.query_local("TOKEN_F9_STUB_MUST_SKIP").await;
        assert!(
            !query_result_contains_token(&qr_stub, "TOKEN_F9_STUB_MUST_SKIP"),
            "Offline placeholder stub must never be opened or indexed under locally_synced_only"
        );
    }
}

#[tokio::test]
async fn t1_f9_offline_stub_alone_yields_zero_indexed_files() {
    let ws = FakeCloudWorkspace::new();
    let box_dir = ws.plant_box_win("Box");
    let _lock = if cfg!(windows) {
        let stub = ws.write_doc(&box_dir, "only_stub.md", "TOKEN_F9_ONLY_STUB content");
        set_windows_offline_attribute(&stub).expect("set FILE_ATTRIBUTE_OFFLINE");
        Some(ExclusiveFileLockGuard::lock(&stub).expect("exclusive lock"))
    } else {
        None
    };

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "box",
            "enabled": true,
            "root_path": box_dir.to_string_lossy()
        }))
        .await;
    let _ = daemon.post_cloud_drives_reindex("box").await;
    daemon
        .wait_for_reindex_settled(Duration::from_secs(15))
        .await;

    let after = daemon.get_cloud_drives().await;
    let drv = find_drive(&after, "box");
    assert_eq!(drv["indexed_files"].as_u64(), Some(0));
    assert_eq!(drv["indexed_chunks"].as_u64(), Some(0));
    if cfg!(windows) {
        let qr = daemon.query_local("TOKEN_F9_ONLY_STUB").await;
        assert!(!query_result_contains_token(&qr, "TOKEN_F9_ONLY_STUB"));
    }
}

#[tokio::test]
async fn t1_f9_offline_attribute_persisted_and_respected_after_restart() {
    let ws = FakeCloudWorkspace::new();
    let nc = ws.plant_nextcloud_home();
    ws.write_doc(&nc, "synced.txt", "TOKEN_F9_RESTART_SYNCED ok");
    if cfg!(windows) {
        let stub = ws.write_doc(&nc, "stub.txt", "TOKEN_F9_RESTART_STUB offline");
        set_windows_offline_attribute(&stub).expect("set FILE_ATTRIBUTE_OFFLINE");
    }

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("nextcloud", &nc, Some(3), 1)
        .await;
    daemon.shutdown().await;

    let daemon2 = DaemonTestProcess::start(&ws).await;
    let _ = daemon2.post_cloud_drives_reindex("nextcloud").await;
    daemon2
        .wait_for_reindex_settled(Duration::from_secs(15))
        .await;

    let payload = daemon2.get_cloud_drives().await;
    assert_eq!(
        payload["placeholder_mode"].as_str(),
        Some("locally_synced_only")
    );
    assert!(query_result_contains_token(
        &daemon2.query_local("TOKEN_F9_RESTART_SYNCED").await,
        "TOKEN_F9_RESTART_SYNCED"
    ));
    if cfg!(windows) {
        let qr = daemon2.query_local("TOKEN_F9_RESTART_STUB").await;
        assert!(!query_result_contains_token(&qr, "TOKEN_F9_RESTART_STUB"));
    }
}

#[tokio::test]
async fn t1_f9_crawler_mixed_subdirs_skips_placeholders() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox.join("sub1"), "a.txt", "TOKEN_F9_SUB_A ok");
    ws.write_doc(&dropbox.join("sub2"), "b.md", "TOKEN_F9_SUB_B ok");
    if cfg!(windows) {
        let s1 = ws.write_doc(
            &dropbox.join("sub1"),
            "stub1.txt",
            "TOKEN_F9_SUB_STUB1 skip",
        );
        let s2 = ws.write_doc(
            &dropbox.join("sub2"),
            "stub2.txt",
            "TOKEN_F9_SUB_STUB2 skip",
        );
        set_windows_offline_attribute(&s1).expect("set offline s1");
        set_windows_offline_attribute(&s2).expect("set offline s2");
    }

    let daemon = DaemonTestProcess::start(&ws).await;
    let updated = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 2)
        .await;
    daemon
        .wait_for_reindex_settled(Duration::from_secs(10))
        .await;

    assert_eq!(
        find_drive(&updated, "dropbox")["indexed_files"].as_u64(),
        Some(2)
    );
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_F9_SUB_A").await,
        "TOKEN_F9_SUB_A"
    ));
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_F9_SUB_B").await,
        "TOKEN_F9_SUB_B"
    ));
    if cfg!(windows) {
        assert!(!query_result_contains_token(
            &daemon.query_local("TOKEN_F9_SUB_STUB1").await,
            "TOKEN_F9_SUB_STUB1"
        ));
        assert!(!query_result_contains_token(
            &daemon.query_local("TOKEN_F9_SUB_STUB2").await,
            "TOKEN_F9_SUB_STUB2"
        ));
    }
}

// ============================================================================
// F10: Size-Capped On-Demand Hydration (`HydrateOnDemand`) (5 tests)
// ============================================================================

#[tokio::test]
async fn t1_f10_hydrate_on_demand_under_cap_accepted() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let stub = ws.write_sized_file(&dropbox, "small_stub.txt", 4096, "TOKEN_F10_UNDER_CAP");
    if cfg!(windows) {
        set_windows_offline_attribute(&stub).expect("set offline");
    }

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "set_hydration",
            "placeholder_mode": "hydrate_on_demand",
            "hydration_max_file_size_mb": 25
        }))
        .await;
    let updated = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    assert_eq!(
        updated["placeholder_mode"].as_str(),
        Some("hydrate_on_demand")
    );
    let qr = daemon.query_local("TOKEN_F10_UNDER_CAP").await;
    assert!(query_result_contains_token(&qr, "TOKEN_F10_UNDER_CAP"));
}

#[tokio::test]
async fn t1_f10_hydrate_on_demand_over_cap_skipped() {
    assert!(should_skip_cloud_placeholder(
        true,
        2 * 1024 * 1024,
        CloudPlaceholderPolicy::HydrateOnDemand {
            max_file_size_bytes: 1024 * 1024,
        }
    ));

    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "anchor.txt", "TOKEN_F10_ANCHOR normal");
    let _lock = if cfg!(windows) {
        let big_stub = ws.write_sized_file(
            &dropbox,
            "oversized_stub.txt",
            2 * 1024 * 1024,
            "TOKEN_F10_OVER_CAP",
        );
        set_windows_offline_attribute(&big_stub).expect("set offline");
        Some(ExclusiveFileLockGuard::lock(&big_stub).expect("lock oversized stub"))
    } else {
        None
    };

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "set_hydration",
            "placeholder_mode": "hydrate_on_demand",
            "hydration_max_file_size_mb": 1
        }))
        .await;
    let updated = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    daemon
        .wait_for_reindex_settled(Duration::from_secs(10))
        .await;

    assert_eq!(
        find_drive(&updated, "dropbox")["indexed_files"].as_u64(),
        Some(1)
    );
    if cfg!(windows) {
        assert!(!query_result_contains_token(
            &daemon.query_local("TOKEN_F10_OVER_CAP").await,
            "TOKEN_F10_OVER_CAP"
        ));
    }
}

#[tokio::test]
async fn t1_f10_hydrate_default_25mb_cap() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let ok_25mb = ws.write_sized_file(
        &dropbox,
        "exact_25mb.txt",
        25 * 1024 * 1024,
        "TOKEN_F10_DEF_25MB_OK",
    );
    if cfg!(windows) {
        set_windows_offline_attribute(&ok_25mb).expect("set offline 25mb");
    }
    let _lock = if cfg!(windows) {
        let over_25mb = ws.write_sized_file(
            &dropbox,
            "over_25mb_plus_1.txt",
            25 * 1024 * 1024 + 1,
            "TOKEN_F10_DEF_25MB_SKIP",
        );
        set_windows_offline_attribute(&over_25mb).expect("set offline 25mb+1");
        Some(ExclusiveFileLockGuard::lock(&over_25mb).expect("lock 25mb+1 stub"))
    } else {
        None
    };

    let daemon = DaemonTestProcess::start(&ws).await;
    // Omit hydration_max_file_size_mb so daemon defaults to 25 MB
    let updated = daemon
        .post_cloud_drives_config(&json!({
            "action": "set_hydration",
            "placeholder_mode": "hydrate_on_demand"
        }))
        .await;
    assert_eq!(
        updated["placeholder_mode"].as_str(),
        Some("hydrate_on_demand")
    );
    assert_eq!(updated["hydration_max_file_size_mb"].as_u64(), Some(25));

    let after = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    daemon
        .wait_for_reindex_settled(Duration::from_secs(15))
        .await;
    assert_eq!(
        find_drive(&after, "dropbox")["indexed_files"].as_u64(),
        Some(1)
    );
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_F10_DEF_25MB_OK").await,
        "TOKEN_F10_DEF_25MB_OK"
    ));
    if cfg!(windows) {
        assert!(!query_result_contains_token(
            &daemon.query_local("TOKEN_F10_DEF_25MB_SKIP").await,
            "TOKEN_F10_DEF_25MB_SKIP"
        ));
    }
}

#[tokio::test]
async fn t1_f10_hydrate_custom_cap_applied() {
    let ws = FakeCloudWorkspace::new();
    let box_dir = ws.plant_box_win("Box");
    let small_ok =
        ws.write_sized_file(&box_dir, "four_mb.txt", 4 * 1024 * 1024, "TOKEN_F10_4MB_OK");
    if cfg!(windows) {
        set_windows_offline_attribute(&small_ok).expect("set offline 4mb");
    }
    let _lock = if cfg!(windows) {
        let big_skip = ws.write_sized_file(
            &box_dir,
            "six_mb.txt",
            6 * 1024 * 1024,
            "TOKEN_F10_6MB_SKIP",
        );
        set_windows_offline_attribute(&big_skip).expect("set offline 6mb");
        Some(ExclusiveFileLockGuard::lock(&big_skip).expect("lock 6mb stub"))
    } else {
        None
    };

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "set_hydration",
            "placeholder_mode": "hydrate_on_demand",
            "hydration_max_file_size_mb": 5
        }))
        .await;
    let updated = daemon
        .enable_and_reindex_drive("box", &box_dir, Some(3), 1)
        .await;
    daemon
        .wait_for_reindex_settled(Duration::from_secs(10))
        .await;

    assert_eq!(
        find_drive(&updated, "box")["indexed_files"].as_u64(),
        Some(1)
    );
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_F10_4MB_OK").await,
        "TOKEN_F10_4MB_OK"
    ));
    if cfg!(windows) {
        assert!(!query_result_contains_token(
            &daemon.query_local("TOKEN_F10_6MB_SKIP").await,
            "TOKEN_F10_6MB_SKIP"
        ));
    }
}

#[tokio::test]
async fn t1_f10_non_placeholder_uses_normal_ingest_under_hydrate() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(
        &dropbox,
        "regular.md",
        "TOKEN_F10_REGULAR_DOC standard text",
    );

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "set_hydration",
            "placeholder_mode": "hydrate_on_demand",
            "hydration_max_file_size_mb": 1
        }))
        .await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_F10_REGULAR_DOC").await,
        "TOKEN_F10_REGULAR_DOC"
    ));
}

// ============================================================================
// F11: Dynamic Ingest Rules, Prefix Dedup & DLP Hook (5 tests)
// ============================================================================

#[tokio::test]
async fn t1_f11_normalized_prefix_access_tier_rules() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "norm.txt", "TOKEN_F11_NORM_PREFIX path rules");
    let slash_variant = dropbox.to_string_lossy().replace('\\', "/");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": true,
            "access_tier": 3,
            "root_path": slash_variant
        }))
        .await;
    let _ = daemon.post_cloud_drives_reindex("dropbox").await;
    let after = daemon
        .wait_for_indexed("dropbox", 1, Duration::from_secs(30))
        .await;
    assert_eq!(
        find_drive(&after, "dropbox")["access_tier"].as_u64(),
        Some(3)
    );
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_F11_NORM_PREFIX").await,
        "TOKEN_F11_NORM_PREFIX"
    ));
}

#[tokio::test]
async fn t1_f11_reindex_worker_unwatches_disabled_drive() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "watch.txt", "TOKEN_F11_WATCH_TOGGLE");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;

    let settings_on = daemon.get_json("/api/settings").await;
    let watched_on = settings_on["runtime"]["watched_paths"]
        .as_array()
        .expect("watched_paths");
    assert!(
        watched_on
            .iter()
            .filter_map(|v| v.as_str())
            .any(|p| paths_equivalent(p, &dropbox.to_string_lossy())),
        "Enabled drive root must appear in runtime.watched_paths: {:?}",
        watched_on
    );

    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": false
        }))
        .await;
    let settings_off = daemon.get_json("/api/settings").await;
    let watched_off = settings_off["runtime"]["watched_paths"]
        .as_array()
        .expect("watched_paths");
    assert!(
        !watched_off
            .iter()
            .filter_map(|v| v.as_str())
            .any(|p| paths_equivalent(p, &dropbox.to_string_lossy())),
        "Disabled drive root must be unwatched from runtime.watched_paths: {:?}",
        watched_off
    );
}

#[tokio::test]
async fn t1_f11_dedup_purges_disabled_drive_without_affecting_sibling() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let box_dir = ws.plant_box_win("Box");
    ws.write_doc(&dropbox, "d.txt", "TOKEN_F11_DEDUP_DROPBOX content");
    ws.write_doc(&box_dir, "b.txt", "TOKEN_F11_DEDUP_BOX preserved");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    let _ = daemon
        .enable_and_reindex_drive("box", &box_dir, Some(3), 1)
        .await;

    // Disable dropbox -> purges dropbox dedup & storage; box remains intact
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": false
        }))
        .await;
    assert!(!query_result_contains_token(
        &daemon.query_local("TOKEN_F11_DEDUP_DROPBOX").await,
        "TOKEN_F11_DEDUP_DROPBOX"
    ));
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_F11_DEDUP_BOX").await,
        "TOKEN_F11_DEDUP_BOX"
    ));

    // Re-enabling dropbox must re-index cleanly (L1 dedup must NOT wrongly treat purged file as still indexed)
    let reenabled = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    assert_eq!(
        find_drive(&reenabled, "dropbox")["indexed_files"].as_u64(),
        Some(1)
    );
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_F11_DEDUP_DROPBOX").await,
        "TOKEN_F11_DEDUP_DROPBOX"
    ));
}

#[tokio::test]
async fn t1_f11_dlp_content_gate_scrubs_secrets() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let aws_sample = concat!("AKIA", "IOSFODNN7EXAMPLE1234");
    ws.write_doc(
        &dropbox,
        "creds.txt",
        &format!("TOKEN_F11_DLP_TOPIC AWS_KEY={aws_sample} SSN=123-45-6789 summary"),
    );

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;

    let qr = daemon.query_local("TOKEN_F11_DLP_TOPIC").await;
    assert!(query_result_contains_token(&qr, "TOKEN_F11_DLP_TOPIC"));
    assert!(
        !query_result_contains_token(&qr, aws_sample),
        "Raw AWS key must be scrubbed by DLP before storage: {}",
        qr
    );
    assert!(
        !query_result_contains_token(&qr, "123-45-6789"),
        "Raw SSN must be scrubbed by DLP before storage: {}",
        qr
    );
}

#[tokio::test]
async fn t1_f11_semaphore_bounded_cloud_ingest() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    for i in 0..24 {
        ws.write_doc(
            &dropbox,
            &format!("batch_{i:02}.txt"),
            &format!("TOKEN_F11_BATCH_{i:02} semaphore bounded concurrent ingest document"),
        );
    }

    let daemon = DaemonTestProcess::start(&ws).await;
    let updated = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 24)
        .await;
    assert!(
        find_drive(&updated, "dropbox")["indexed_files"]
            .as_u64()
            .unwrap_or(0)
            >= 24
    );
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_F11_BATCH_00").await,
        "TOKEN_F11_BATCH_00"
    ));
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_F11_BATCH_23").await,
        "TOKEN_F11_BATCH_23"
    ));
}

// ============================================================================
// F12: Prefix Purge Across Storage & AtlasKV (5 tests)
// ============================================================================

#[tokio::test]
async fn t1_f12_purge_removes_from_hybrid_and_vector_query() {
    let ws = FakeCloudWorkspace::new();
    let gdrive = ws.plant_google_drive_win_mirror();
    ws.write_doc(
        &gdrive,
        "cloud_vec.md",
        "TOKEN_F12_CLOUD_VEC unique vector payload",
    );
    ws.write_doc(
        &ws.watch_dir,
        "local_vec.md",
        "TOKEN_F12_LOCAL_VEC local baseline",
    );

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon.post_json("/api/reindex", &json!({})).await;
    let _ = daemon
        .enable_and_reindex_drive("google_drive", &gdrive, Some(3), 1)
        .await;

    assert!(query_result_contains_token(
        &daemon
            .post_json(
                "/api/query",
                &json!({ "prompt": "TOKEN_F12_CLOUD_VEC", "access_tier": 3, "search_mode": "Vector", "bypass_cache": true })
            )
            .await,
        "TOKEN_F12_CLOUD_VEC"
    ));

    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "google_drive",
            "enabled": false
        }))
        .await;

    let after_vec = daemon
        .post_json(
            "/api/query",
            &json!({ "prompt": "TOKEN_F12_CLOUD_VEC", "access_tier": 3, "search_mode": "Vector", "bypass_cache": true }),
        )
        .await;
    assert!(!query_result_contains_token(
        &after_vec,
        "TOKEN_F12_CLOUD_VEC"
    ));
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_F12_LOCAL_VEC").await,
        "TOKEN_F12_LOCAL_VEC"
    ));
}

#[tokio::test]
async fn t1_f12_purge_removes_from_keyword_tantivy_query() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "kw.txt", "TOKEN_F12_TANTIVY_KW keyword indexed");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;

    let hit = daemon
        .post_json(
            "/api/query",
            &json!({ "prompt": "TOKEN_F12_TANTIVY_KW", "access_tier": 3, "search_mode": "Keyword", "bypass_cache": true }),
        )
        .await;
    assert!(query_result_contains_token(&hit, "TOKEN_F12_TANTIVY_KW"));

    let _ = daemon
        .post_cloud_drives_config(
            &json!({ "action": "toggle_drive", "id": "dropbox", "enabled": false }),
        )
        .await;

    let miss = daemon
        .post_json(
            "/api/query",
            &json!({ "prompt": "TOKEN_F12_TANTIVY_KW", "access_tier": 3, "search_mode": "Keyword", "bypass_cache": true }),
        )
        .await;
    assert!(!query_result_contains_token(&miss, "TOKEN_F12_TANTIVY_KW"));
}

#[tokio::test]
async fn t1_f12_purge_decrements_catalog_total_files_and_chunks() {
    let ws = FakeCloudWorkspace::new();
    let box_dir = ws.plant_box_win("Box");
    ws.write_doc(&box_dir, "c1.txt", "TOKEN_F12_CAT_1 alpha");
    ws.write_doc(&box_dir, "c2.txt", "TOKEN_F12_CAT_2 beta");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("box", &box_dir, Some(3), 2)
        .await;
    let before_settings = daemon.get_json("/api/settings").await;
    let before_files = before_settings["runtime"]["total_files"]
        .as_u64()
        .unwrap_or(0);
    let before_chunks = before_settings["runtime"]["total_chunks"]
        .as_u64()
        .unwrap_or(0);
    assert!(before_files >= 2 && before_chunks >= 2);

    let disable_resp = daemon
        .post_cloud_drives_config(
            &json!({ "action": "toggle_drive", "id": "box", "enabled": false }),
        )
        .await;
    assert!(
        disable_resp["purged_files"].as_u64().unwrap_or(0) >= 2
            || disable_resp["purged_chunks"].as_u64().unwrap_or(0) >= 2,
        "Disable response must report purged counts: {}",
        disable_resp
    );

    let after_settings = daemon.get_json("/api/settings").await;
    let after_files = after_settings["runtime"]["total_files"]
        .as_u64()
        .unwrap_or(0);
    let after_chunks = after_settings["runtime"]["total_chunks"]
        .as_u64()
        .unwrap_or(0);
    assert!(after_files < before_files);
    assert!(after_chunks < before_chunks);
    assert_eq!(
        find_drive(&daemon.get_cloud_drives().await, "box")["indexed_files"].as_u64(),
        Some(0)
    );
}

#[tokio::test]
async fn t1_f12_purge_clears_atlaskv_and_survives_restart() {
    let ws = FakeCloudWorkspace::new();
    let nc = ws.plant_nextcloud_home();
    ws.write_doc(
        &nc,
        "entities.md",
        "TOKEN_F12_ATLASKV Alice Johnson leads Project Zephyr at Contoso Corp in Zurich.",
    );

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("nextcloud", &nc, Some(3), 1)
        .await;
    assert!(query_result_contains_token(
        &daemon
            .query_local_cached("Project Zephyr TOKEN_F12_ATLASKV")
            .await,
        "TOKEN_F12_ATLASKV"
    ));

    // Directly verify AtlasKV extraction via /api/v1/atlaskv/status & /api/v1/atlaskv/query
    let akv_status_before = daemon.get_atlaskv_status().await;
    let active_before = akv_status_before["stats"]["active_triples"]
        .as_u64()
        .unwrap_or(0);
    assert!(
        active_before >= 1,
        "Expected AtlasKV active_triples >= 1 after ingest, got: {}",
        akv_status_before
    );
    let akv_hit = daemon
        .query_atlaskv("Project Zephyr Alice Johnson", 3)
        .await;
    assert!(
        atlaskv_result_contains_token(&akv_hit, "entities.md")
            || atlaskv_result_contains_token(&akv_hit, "Zephyr")
            || atlaskv_result_contains_token(&akv_hit, "Alice"),
        "AtlasKV query must return extracted triple from Nextcloud doc: {}",
        akv_hit
    );

    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "nextcloud",
            "enabled": false
        }))
        .await;

    // Verify cached query is invalidated immediately after disable purge
    let after_cache = daemon
        .query_local_cached("Project Zephyr TOKEN_F12_ATLASKV")
        .await;
    assert!(!query_result_contains_token(
        &after_cache,
        "TOKEN_F12_ATLASKV"
    ));

    let akv_status_after = daemon.get_atlaskv_status().await;
    let active_after = akv_status_after["stats"]["active_triples"]
        .as_u64()
        .unwrap_or(u64::MAX);
    assert!(
        active_after < active_before,
        "Disable purge must reduce AtlasKV active_triples ({} -> {}): {}",
        active_before,
        active_after,
        akv_status_after
    );
    let akv_miss = daemon
        .query_atlaskv("Project Zephyr Alice Johnson", 3)
        .await;
    assert!(
        !atlaskv_result_contains_token(&akv_miss, "entities.md")
            && !atlaskv_result_contains_token(&akv_miss, "Zephyr"),
        "AtlasKV query after disable must not return purged Nextcloud triples: {}",
        akv_miss
    );

    daemon.shutdown().await;

    let daemon2 = DaemonTestProcess::start(&ws).await;
    let akv_after_restart = daemon2.get_atlaskv_status().await;
    assert_eq!(
        akv_after_restart["stats"]["active_triples"].as_u64(),
        Some(0),
        "Purged AtlasKV triples must remain cleared after restart: {}",
        akv_after_restart
    );
    let after = daemon2
        .query_local("Project Zephyr TOKEN_F12_ATLASKV")
        .await;
    assert!(!query_result_contains_token(&after, "TOKEN_F12_ATLASKV"));
    assert!(!query_result_mentions_path(&after, "entities.md"));
}

#[tokio::test]
async fn t1_f12_index_epoch_bump_and_tier_upgrade_sync() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "epoch.txt", "TOKEN_F12_EPOCH tier sync test");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;

    // Warm QueryCoordinator cache using bypass_cache: false
    assert!(query_result_contains_token(
        &daemon.query_local_cached("TOKEN_F12_EPOCH").await,
        "TOKEN_F12_EPOCH"
    ));

    // Upgrade tier 3 -> 0 and verify retrieval still succeeds cleanly
    let upgraded = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": true,
            "access_tier": 0
        }))
        .await;
    assert_eq!(
        find_drive(&upgraded, "dropbox")["access_tier"].as_u64(),
        Some(0)
    );
    assert!(query_result_contains_token(
        &daemon.query_local_cached("TOKEN_F12_EPOCH").await,
        "TOKEN_F12_EPOCH"
    ));

    let epoch_before = daemon.get_json("/api/settings").await["runtime"]["index_epoch"]
        .as_u64()
        .expect("index_epoch before");
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": false
        }))
        .await;
    let epoch_after = daemon.get_json("/api/settings").await["runtime"]["index_epoch"]
        .as_u64()
        .expect("index_epoch after");
    assert!(
        epoch_after > epoch_before,
        "Disable purge must bump index_epoch ({} -> {})",
        epoch_before,
        epoch_after
    );
    assert!(
        !query_result_contains_token(
            &daemon.query_local_cached("TOKEN_F12_EPOCH").await,
            "TOKEN_F12_EPOCH"
        ),
        "Cached query (bypass_cache=false) must be invalidated after disable purge"
    );
}

// ============================================================================
// F13: Per-Drive Access Tier (`3` local-only) & P2P Mesh Isolation (5 tests)
// ============================================================================

#[tokio::test]
async fn t1_f13_settings_json_persists_cloud_drives() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let sub = ws.mkdir("CustomCloudSub");
    let daemon = DaemonTestProcess::start(&ws).await;

    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "set_hydration",
            "placeholder_mode": "hydrate_on_demand",
            "hydration_max_file_size_mb": 12
        }))
        .await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": true,
            "access_tier": 3,
            "root_path": dropbox.to_string_lossy()
        }))
        .await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "add_folder",
            "id": "dropbox",
            "path": sub.to_string_lossy()
        }))
        .await;

    let disk = ws.read_settings_json();
    assert_eq!(
        disk.pointer("/cloud_drives/placeholder_mode")
            .and_then(|v| v.as_str()),
        Some("hydrate_on_demand")
    );
    assert_eq!(
        disk.pointer("/cloud_drives/hydration_max_file_size_mb")
            .and_then(|v| v.as_u64()),
        Some(12)
    );
    let drives = disk
        .pointer("/cloud_drives/drives")
        .and_then(|v| v.as_array())
        .expect("settings.json cloud_drives.drives");
    let d_entry = drives
        .iter()
        .find(|d| d["id"].as_str() == Some("dropbox"))
        .expect("dropbox in settings.json");
    assert_eq!(d_entry["enabled"].as_bool(), Some(true));
    assert_eq!(d_entry["access_tier"].as_u64(), Some(3));
}

#[tokio::test]
async fn t1_f13_mesh_isolation_bypasses_wildcard() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let doc = ws.write_doc(
        &dropbox,
        "private_cloud.txt",
        "normal project architecture text",
    );

    let daemon = DaemonTestProcess::start(&ws).await;
    let mesh = daemon.get_json("/api/mesh/status").await;
    assert_eq!(mesh["require_explicit_folder_share"].as_bool(), Some(false));

    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;

    let dlp = daemon
        .post_json(
            "/api/dlp/test",
            &json!({
                "text": "normal project architecture text",
                "file_path": doc.to_string_lossy()
            }),
        )
        .await;
    assert_eq!(
        dlp["folder_shared_with_mesh"].as_bool(),
        Some(false),
        "Tier 3 cloud drive path must NOT inherit wildcard folder share: {}",
        dlp
    );
    assert_eq!(dlp["effective_mesh_allowed"].as_bool(), Some(false));
}

#[tokio::test]
async fn t1_f13_mesh_blocks_cloud_in_shared_folders_tier3() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let doc = ws.write_doc(&dropbox, "tier3_shared.txt", "clean text");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    let _ = daemon
        .post_json(
            "/api/mesh/shared-folders",
            &json!({
                "action": "add",
                "path": dropbox.to_string_lossy(),
                "enabled": true,
                "access_tier": 3
            }),
        )
        .await;

    let dlp = daemon
        .post_json(
            "/api/dlp/test",
            &json!({
                "text": "clean text",
                "file_path": doc.to_string_lossy()
            }),
        )
        .await;
    assert_eq!(
        dlp["folder_shared_with_mesh"].as_bool(),
        Some(false),
        "Cloud drive added to shared_folders at Tier 3 must remain blocked from mesh: {}",
        dlp
    );
    assert_eq!(dlp["effective_mesh_allowed"].as_bool(), Some(false));
}

#[tokio::test]
async fn t1_f13_mesh_allows_only_explicit_shared_tier_lt_3() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let doc = ws.write_doc(&dropbox, "team_ok.txt", "clean team memo");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    let _ = daemon
        .post_json(
            "/api/mesh/shared-folders",
            &json!({
                "action": "add",
                "path": dropbox.to_string_lossy(),
                "enabled": true,
                "access_tier": 1
            }),
        )
        .await;

    // Drive is still Tier 3 => even with shared_folders access_tier = 1, max(1, 3) = 3 => BLOCKED
    let dlp_tier3 = daemon
        .post_json(
            "/api/dlp/test",
            &json!({
                "text": "clean team memo",
                "file_path": doc.to_string_lossy()
            }),
        )
        .await;
    assert_eq!(dlp_tier3["folder_shared_with_mesh"].as_bool(), Some(false));
    assert_eq!(dlp_tier3["effective_mesh_allowed"].as_bool(), Some(false));

    // Lower the drive's access_tier < 3 as well => max(1, 1) = 1 < 3 => ALLOWED
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "set_tier",
            "id": "dropbox",
            "access_tier": 1
        }))
        .await;

    let dlp = daemon
        .post_json(
            "/api/dlp/test",
            &json!({
                "text": "clean team memo",
                "file_path": doc.to_string_lossy()
            }),
        )
        .await;
    assert_eq!(dlp["folder_shared_with_mesh"].as_bool(), Some(true));
    assert_eq!(dlp["effective_mesh_allowed"].as_bool(), Some(true));
}

#[tokio::test]
async fn t1_f13_cloud_drive_absent_from_default_mesh_shared_folders() {
    let ws = FakeCloudWorkspace::new();
    let gdrive = ws.plant_google_drive_win_mirror();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&gdrive, "g.txt", "TOKEN_F13_G");
    ws.write_doc(&dropbox, "d.txt", "TOKEN_F13_D");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("google_drive", &gdrive, Some(3), 1)
        .await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;

    let cd = daemon.get_cloud_drives().await;
    assert_eq!(
        find_drive(&cd, "google_drive")["shared_with_mesh"].as_bool(),
        Some(false)
    );
    assert_eq!(
        find_drive(&cd, "dropbox")["shared_with_mesh"].as_bool(),
        Some(false)
    );

    let mesh = daemon.get_json("/api/mesh/status").await;
    for sf in mesh["shared_folders"].as_array().expect("shared_folders") {
        let p = sf["path"].as_str().unwrap_or("");
        assert!(!paths_equivalent(p, &gdrive.to_string_lossy()));
        assert!(!paths_equivalent(p, &dropbox.to_string_lossy()));
    }
}

// ============================================================================
// F14: Local Retrieval of Local-Only Tiers & DLP/Media Gate (5 tests)
// ============================================================================

#[tokio::test]
async fn t1_f14_local_query_retrieves_tier3_cloud() {
    let ws = FakeCloudWorkspace::new();
    let gdrive = ws.plant_google_drive_win_mirror();
    ws.write_doc(
        &gdrive,
        "local_tier3.md",
        "TOKEN_F14_LOCAL_TIER3 confidential memo",
    );

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("google_drive", &gdrive, Some(3), 1)
        .await;
    let qr = daemon.query_local("TOKEN_F14_LOCAL_TIER3").await;
    assert!(query_result_contains_token(&qr, "TOKEN_F14_LOCAL_TIER3"));
}

#[tokio::test]
async fn t1_f14_local_query_default_payload_retrieves_enabled_cloud() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(
        &dropbox,
        "chat_default.md",
        "TOKEN_F14_CHAT_DEFAULT local cloud",
    );

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    let qr = daemon
        .post_json("/api/query", &json!({ "prompt": "TOKEN_F14_CHAT_DEFAULT" }))
        .await;
    assert!(query_result_contains_token(&qr, "TOKEN_F14_CHAT_DEFAULT"));
}

#[tokio::test]
async fn t1_f14_tier_isolation_between_local_and_mesh_status() {
    let ws = FakeCloudWorkspace::new();
    let onedrive = ws.plant_onedrive_personal();
    let doc = ws.write_doc(&onedrive, "private_od.txt", "TOKEN_F14_ISOLATION private");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("onedrive_personal", &onedrive, Some(3), 1)
        .await;

    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_F14_ISOLATION").await,
        "TOKEN_F14_ISOLATION"
    ));
    let dlp = daemon
        .post_json(
            "/api/dlp/test",
            &json!({ "text": "TOKEN_F14_ISOLATION", "file_path": doc.to_string_lossy() }),
        )
        .await;
    assert_eq!(dlp["folder_shared_with_mesh"].as_bool(), Some(false));
    assert_eq!(dlp["effective_mesh_allowed"].as_bool(), Some(false));
}

#[tokio::test]
async fn t1_f14_media_endpoint_tier_enforcement() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let doc = ws.write_doc(&dropbox, "restricted_preview.txt", "TOKEN_F14_MEDIA_TIER3");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;

    let path_str = doc.to_string_lossy().to_string();
    let resp = daemon
        .client
        .get(format!("{}/api/media", daemon.base_url))
        .query(&[("path", path_str.as_str())])
        .send()
        .await
        .expect("send /api/media");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Loopback /api/media must allow enabled & mounted Tier 3 cloud file"
    );
    let body = resp.text().await.expect("read /api/media body");
    assert!(
        body.contains("TOKEN_F14_MEDIA_TIER3"),
        "Loopback /api/media body must contain indexed cloud file content"
    );

    let (dis_st, _, _) = daemon
        .post_json_raw(
            "/api/cloud-drives/config",
            &json!({ "action": "toggle_drive", "id": "dropbox", "enabled": false }),
        )
        .await;
    assert_eq!(dis_st, StatusCode::OK);

    let denied_resp = daemon
        .client
        .get(format!("{}/api/media", daemon.base_url))
        .query(&[("path", path_str.as_str())])
        .send()
        .await
        .expect("send /api/media after disable");
    assert_eq!(
        denied_resp.status(),
        StatusCode::FORBIDDEN,
        "Disabled Tier 3 cloud file must be denied (403) on /api/media"
    );

    let artemis_resp = daemon
        .client
        .get(format!("{}/api/media", daemon.base_url))
        .query(&[("path", "artemis://windows/eventlog/security")])
        .send()
        .await
        .expect("send /api/media for artemis://");
    assert_eq!(
        artemis_resp.status(),
        StatusCode::FORBIDDEN,
        "artemis:// URI must be denied (403) on /api/media"
    );
}

#[tokio::test]
async fn t1_f14_dlp_block_mode_blocks_secret_and_redact_scrubs() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;

    let redact_res = daemon
        .post_json(
            "/api/dlp/test",
            &json!({
                "text": "Patient SSN 123-45-6789 record",
                "mode": "Redact"
            }),
        )
        .await;
    let scrubbed_text = redact_res["inspection"]["scrubbed_text"]
        .as_str()
        .expect("inspection.scrubbed_text must be a string");
    assert!(
        !scrubbed_text.trim().is_empty(),
        "Redact mode must return non-empty scrubbed_text: {}",
        redact_res
    );
    assert!(
        scrubbed_text.contains("Patient") && scrubbed_text.contains("record"),
        "Redact mode must preserve non-secret context: {}",
        redact_res
    );
    assert!(
        !scrubbed_text.contains("123-45-6789"),
        "Redact mode must scrub SSN: {}",
        redact_res
    );

    let block_res = daemon
        .post_json(
            "/api/dlp/test",
            &json!({
                "text": "Patient SSN 123-45-6789 record",
                "mode": "Block"
            }),
        )
        .await;
    assert_eq!(block_res["effective_mesh_allowed"].as_bool(), Some(false));
    assert_eq!(
        block_res["inspection"]["allowed_to_share"].as_bool(),
        Some(false)
    );
}

// ============================================================================
// F15: Daemon Cloud Drives API & Lifecycle (5 tests)
// ============================================================================

#[tokio::test]
async fn t1_f15_api_get_cloud_drives_contract() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;

    assert_eq!(
        payload["placeholder_mode"].as_str(),
        Some("locally_synced_only")
    );
    assert_eq!(payload["hydration_max_file_size_mb"].as_u64(), Some(25));
    assert!(payload
        .get("running_as_local_system")
        .and_then(|v| v.as_bool())
        .is_some());
    assert!(payload.get("virtual_drive_guidance").is_some());

    let drives = payload["drives"].as_array().expect("drives array");
    assert!(drives.len() >= 8);
    for d in drives {
        for key in [
            "id",
            "provider",
            "label",
            "detected",
            "mounted",
            "status",
            "status_label",
            "virtual_drive",
            "session_only",
            "enabled",
            "access_tier",
            "shared_with_mesh",
            "detected_roots",
            "custom_paths",
            "indexed_files",
            "indexed_chunks",
        ] {
            assert!(
                d.get(key).is_some(),
                "Drive entry missing key '{}': {}",
                key,
                d
            );
        }
    }
}

#[tokio::test]
async fn t1_f15_api_post_toggle_enable_indexes() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "enable.txt", "TOKEN_F15_ENABLE_INDEX ok");

    let daemon = DaemonTestProcess::start(&ws).await;
    let after = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    let drv = find_drive(&after, "dropbox");
    assert_eq!(drv["enabled"].as_bool(), Some(true));
    assert!(drv["indexed_files"].as_u64().unwrap_or(0) >= 1);
}

#[tokio::test]
async fn t1_f15_api_post_toggle_disable_purges() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "purge.txt", "TOKEN_F15_DISABLE_PURGE target");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;

    let resp = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": false
        }))
        .await;
    assert!(
        resp["purged_files"].as_u64().unwrap_or(0) >= 1
            || resp["purged_chunks"].as_u64().unwrap_or(0) >= 1,
        "Disable response must report purged counts: {}",
        resp
    );
    let after = daemon.get_cloud_drives().await;
    let drv = find_drive(&after, "dropbox");
    assert_eq!(drv["enabled"].as_bool(), Some(false));
    assert_eq!(drv["indexed_files"].as_u64(), Some(0));
    assert!(!query_result_contains_token(
        &daemon.query_local("TOKEN_F15_DISABLE_PURGE").await,
        "TOKEN_F15_DISABLE_PURGE"
    ));
}

#[tokio::test]
async fn t1_f15_api_post_hydration_and_folders() {
    let ws = FakeCloudWorkspace::new();
    let custom_dir = ws.mkdir("ManualCloudDir");
    let daemon = DaemonTestProcess::start(&ws).await;

    let hyd = daemon
        .post_cloud_drives_config(&json!({
            "action": "set_hydration",
            "placeholder_mode": "hydrate_on_demand",
            "hydration_max_file_size_mb": 10
        }))
        .await;
    assert_eq!(hyd["placeholder_mode"].as_str(), Some("hydrate_on_demand"));
    assert_eq!(hyd["hydration_max_file_size_mb"].as_u64(), Some(10));

    let added = daemon
        .post_cloud_drives_config(&json!({
            "action": "add_folder",
            "id": "box",
            "path": custom_dir.to_string_lossy()
        }))
        .await;
    assert!(find_drive(&added, "box")["custom_paths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| paths_equivalent(v.as_str().unwrap_or(""), &custom_dir.to_string_lossy())));

    let removed = daemon
        .post_cloud_drives_config(&json!({
            "action": "remove_folder",
            "id": "box",
            "path": custom_dir.to_string_lossy()
        }))
        .await;
    assert!(find_drive(&removed, "box")["custom_paths"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn t1_f15_api_post_reindex_returns_triggered_paths() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "trig.txt", "TOKEN_F15_REINDEX_TRIGGER");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": true,
            "root_path": dropbox.to_string_lossy()
        }))
        .await;
    let res = daemon.post_cloud_drives_reindex("dropbox").await;
    assert_eq!(res["ok"].as_bool(), Some(true));
    let paths = res["triggered_paths"]
        .as_array()
        .expect("triggered_paths array");
    assert!(
        paths
            .iter()
            .filter_map(|v| v.as_str())
            .any(|p| paths_equivalent(p, &dropbox.to_string_lossy())),
        "triggered_paths must include drive root: {:?}",
        paths
    );
}

// ============================================================================
// F16: `LocalSystem` Profile Sync & Virtual Drive Status/Guidance (5 tests)
// ============================================================================

#[tokio::test]
async fn t1_f16_api_surfaces_local_system_and_guidance_fields() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;

    assert!(payload["running_as_local_system"].is_boolean());
    assert!(
        payload["virtual_drive_guidance"].is_null()
            || payload["virtual_drive_guidance"].is_string()
    );
    for drv in payload["drives"].as_array().expect("drives") {
        assert!(drv["virtual_drive"].is_boolean());
        assert!(drv["session_only"].is_boolean());
        assert!(drv.get("session_guidance").is_some());
    }
}

#[tokio::test]
async fn t1_f16_drive_entries_have_valid_status_enum_and_labels() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;

    for drv in payload["drives"].as_array().expect("drives") {
        let status = drv["status"].as_str().expect("status string");
        assert!(
            matches!(
                status,
                "mounted" | "not_detected" | "session_only" | "error"
            ),
            "Unexpected cloud drive status '{}': {}",
            status,
            drv
        );
        let label = drv["status_label"].as_str().expect("status_label");
        assert!(!label.trim().is_empty());
    }
}

#[tokio::test]
async fn t1_f16_session_only_implies_actionable_guidance() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;

    let running_as_local_system = payload["running_as_local_system"]
        .as_bool()
        .expect("running_as_local_system boolean");
    if running_as_local_system {
        let guidance = payload["virtual_drive_guidance"].as_str().unwrap_or("");
        assert!(
            !guidance.trim().is_empty(),
            "LocalSystem context must provide non-empty virtual_drive_guidance: {}",
            payload
        );
    }

    let mut mounted_count = 0usize;
    for drv in payload["drives"].as_array().expect("drives") {
        let is_session = drv["session_only"].as_bool().unwrap_or(false)
            || drv["status"].as_str() == Some("session_only");
        if is_session {
            assert_eq!(drv["status"].as_str(), Some("session_only"));
            let guidance = drv["session_guidance"].as_str().unwrap_or("");
            assert!(
                !guidance.trim().is_empty(),
                "session_only drive must provide actionable session_guidance: {}",
                drv
            );
        }
        if drv["mounted"].as_bool() == Some(true) {
            mounted_count += 1;
            let rp = drv["root_path"].as_str().unwrap_or("");
            assert!(
                !rp.trim().is_empty(),
                "mounted drive must have root_path: {}",
                drv
            );
        }
    }
    assert!(
        mounted_count >= 1,
        "Planted Dropbox root must be mounted in {}: {}",
        dropbox.display(),
        payload
    );
}

#[tokio::test]
async fn t1_f16_folder_backed_drive_indexes_alongside_unmounted_virtual() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "folder_backed.txt", "TOKEN_F16_FOLDER_BACKED ok");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;

    let payload = daemon.get_cloud_drives().await;
    assert_eq!(
        find_drive(&payload, "dropbox")["mounted"].as_bool(),
        Some(true)
    );
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_F16_FOLDER_BACKED").await,
        "TOKEN_F16_FOLDER_BACKED"
    ));
}

#[tokio::test]
async fn t1_f16_fs_browse_folders_filters_service_system_profiles() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    let res = daemon.get_json("/api/fs/browse-folders").await;
    let serialized = res.to_string().to_ascii_lowercase();
    assert!(!serialized.contains("systemprofile"));
    assert!(!serialized.contains("localservice"));
    assert!(!serialized.contains("networkservice"));
}

// ============================================================================
// F17: Dedicated `Cloud Drives` WebUI Tab & `Storage` Quick-Jump (5 tests)
// ============================================================================

#[test]
fn t1_f17_index_html_nav_item() {
    let (html, _, _) = read_repo_ui_assets();
    assert!(html.contains(r#"id="settings-nav-list""#));
    assert!(
        html.contains(r#"class="chatgpt-nav-item" data-tab="cloud-drives""#),
        "index.html #settings-nav-list must include data-tab=\"cloud-drives\""
    );
    assert!(html.contains("Cloud Drives"));
}

#[test]
fn t1_f17_storage_tab_quick_jump_link() {
    let (_, js, _) = read_repo_ui_assets();
    let storage_slice = extract_storage_tab_slice(&js);
    assert!(
        storage_slice.contains(r#"data-action="jump-tab""#)
            && storage_slice.contains(r#"data-tab="cloud-drives""#),
        "Storage tab must include quick-jump button to cloud-drives"
    );
}

#[test]
fn t1_f17_render_settings_tab_cloud_drives() {
    let (_, js, _) = read_repo_ui_assets();
    let slice = extract_cloud_drives_tab_slice(&js);
    assert!(slice.contains(r#"<div class="settings-centered-container">"#));
    assert!(slice.contains(r#"<h2 class="settings-page-title">"#));
}

#[test]
fn t1_f17_open_settings_fetches_api() {
    let (_, js, _) = read_repo_ui_assets();
    assert!(js.contains("/api/cloud-drives"));
    assert!(js.contains("/api/cloud-drives/config"));
    assert!(js.contains("/api/cloud-drives/reindex"));
}

#[test]
fn t1_f17_settings_search_keywords_route() {
    let (_, js, _) = read_repo_ui_assets();
    let search_slice = extract_settings_search_slice(&js);
    assert!(
        search_slice.contains("activeSettingsTab = 'cloud-drives'")
            && search_slice.contains("highlightSettingsNav('cloud-drives')"),
        "settingsSearchInput handler must auto-route and highlight 'cloud-drives'"
    );
    let lower = search_slice.to_ascii_lowercase();
    for kw in [
        "cloud",
        "gdrive",
        "google drive",
        "onedrive",
        "dropbox",
        "icloud",
        "box",
        "nextcloud",
        "proton",
        "pcloud",
        "hydrate",
        "placeholder",
    ] {
        assert!(
            lower.contains(kw),
            "settingsSearchInput handler must include keyword '{}' for Cloud Drives search routing",
            kw
        );
    }
}

// ============================================================================
// F18: Cloud Drives UI Controls, Badges & Static Hygiene Invariants (6 tests)
// ============================================================================

#[test]
fn t1_f18_ui_status_badges_and_guidance() {
    let (_, js, _) = read_repo_ui_assets();
    let slice = extract_cloud_drives_tab_slice(&js);
    assert!(slice.contains("Mounted"));
    assert!(slice.contains("Not Detected"));
    assert!(slice.contains("Indexed files"));
    assert!(slice.contains("session_guidance"));
}

#[test]
fn t1_f18_ui_controls_toggles_hydration_cap() {
    let (_, js, _) = read_repo_ui_assets();
    let slice = extract_cloud_drives_tab_slice(&js);
    assert!(slice.contains("Reindex Now"));
    assert!(slice.contains("Hydrate cloud-only files on demand"));
    assert!(slice.contains(r#"type="number""#));
    assert!(slice.contains("settings-input"));
    assert!(slice.contains(r#"id="cloud-hydration-max-mb""#));
    assert!(slice.contains("default 25 MB"));
}

#[test]
fn t1_f18_ui_native_folder_select_no_text_input() {
    let (_, js, _) = read_repo_ui_assets();
    let slice = extract_cloud_drives_tab_slice(&js);
    assert!(slice.contains(r#"data-action="trigger-native-folder-picker""#));
    assert!(slice.contains("📁 Select Folder"));
    assert!(slice.contains(r#"<input type="hidden""#));
    assert!(
        !slice.contains(r#"type="text""#),
        "Cloud Drives tab must NEVER use <input type=\"text\"> for folder paths"
    );
}

#[tokio::test]
async fn t1_f18_ui_no_pure_rust_labels() {
    let (html, js, css) = read_repo_ui_assets();
    assert!(!html.to_ascii_lowercase().contains("pure rust"));
    assert!(!js.to_ascii_lowercase().contains("pure rust"));
    assert!(!css.to_ascii_lowercase().contains("pure rust"));

    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    let (_, _, live_html) = daemon.get_text("/").await;
    let (_, _, live_js) = daemon.get_text("/assets/app.js").await;
    assert!(!live_html.to_ascii_lowercase().contains("pure rust"));
    assert!(!live_js.to_ascii_lowercase().contains("pure rust"));
}

#[test]
fn t1_f18_ui_zero_inline_handlers_json_attrs_checked_false_title_margin() {
    let (html, js, _) = read_repo_ui_assets();
    let js_lower = js.to_ascii_lowercase();
    let nav_lower = extract_settings_nav_slice(&html).to_ascii_lowercase();
    for attr in [
        " onclick=",
        " onchange=",
        " oninput=",
        " onkeydown=",
        " onkeyup=",
        " onsubmit=",
        " onerror=",
    ] {
        assert!(
            !js_lower.contains(attr),
            "Forbidden inline handler {} in app.js",
            attr
        );
        assert!(
            !nav_lower.contains(attr),
            "Forbidden inline handler {} in index.html #settings-nav-list",
            attr
        );
    }
    assert!(!js.contains("checked=false"));
    assert!(!html.contains("checked=false"));

    let slice = extract_cloud_drives_tab_slice(&js);
    for attr in [" onclick=", " onchange=", " oninput="] {
        assert!(!slice.to_ascii_lowercase().contains(attr));
    }
    assert!(slice.contains("escapeHtml("));
    assert!(!slice.contains("${JSON.stringify"));
    assert!(
        !slice.contains(r#"class="settings-page-title" style="#),
        "Cloud Drives <h2 class=\"settings-page-title\"> must have zero inline style"
    );
}

#[tokio::test]
async fn t1_f18_ui_live_daemon_serves_cloud_drives_assets() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;

    let (st_html, hdr_html, body_html) = daemon.get_text("/").await;
    assert_eq!(st_html, StatusCode::OK);
    assert!(hdr_html["content-type"]
        .to_str()
        .unwrap_or("")
        .contains("text/html"));
    assert!(body_html.contains(r#"data-tab="cloud-drives""#));
    assert!(!body_html.contains("checked=false"));
    let live_nav_lower = extract_settings_nav_slice(&body_html).to_ascii_lowercase();
    assert!(!live_nav_lower.contains(" onclick="));
    assert!(!live_nav_lower.contains(" onchange="));

    let (st_js, _, body_js) = daemon.get_text("/assets/app.js").await;
    assert_eq!(st_js, StatusCode::OK);
    assert!(body_js.contains("else if (tab === 'cloud-drives')"));
    assert!(body_js.contains("/api/cloud-drives"));
    let live_cd_slice = extract_cloud_drives_tab_slice(&body_js);
    assert!(live_cd_slice.contains("escapeHtml(drvLabel)"));
    assert!(live_cd_slice.contains("escapeHtml(drvId)"));
    assert!(live_cd_slice.contains("escapeHtml(cp)"));
    assert!(live_cd_slice.contains(r#"<input type="hidden""#));
    assert!(live_cd_slice.contains("Mounted"));
    assert!(live_cd_slice.contains("Not Detected"));
    assert!(live_cd_slice.contains("Indexed files"));
    assert!(!live_cd_slice.contains("${JSON.stringify"));
    let live_js_lower = body_js.to_ascii_lowercase();
    for attr in [" onclick=", " onchange=", " oninput="] {
        assert!(
            !live_js_lower.contains(attr),
            "Live /assets/app.js must contain zero inline handler {}",
            attr
        );
    }

    let (st_css, hdr_css, body_css) = daemon.get_text("/assets/styles.css").await;
    assert_eq!(st_css, StatusCode::OK);
    assert!(hdr_css["content-type"]
        .to_str()
        .unwrap_or("")
        .contains("text/css"));
    assert!(body_css.contains(".settings-centered-container"));
    assert!(body_css.contains(".cloud-drive-card"));
}
