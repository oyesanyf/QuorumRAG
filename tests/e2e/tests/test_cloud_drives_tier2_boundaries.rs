//! Tier 2 E2E Tests: Boundary & Corner Cases (`59` tests across bounded features).
//!
//! Covers fail-closed tier/path validation, exact hydration size boundaries (`size == cap`
//! vs `size == cap + 1`, `0`, `u64::MAX`), sibling prefix purge traps, malformed configs,
//! `LocalSystem` profile filters, HTTP `400`/`404`/`409`/`422` error contracts, and WebUI
//! static security hygiene.

use quorum_e2e::cloud_drives_harness::{
    find_drive, paths_equivalent, query_result_contains_token, read_repo_ui_assets,
    set_windows_offline_attribute, DaemonTestProcess, ExclusiveFileLockGuard, FakeCloudWorkspace,
};
use quorum_ingest::cloud_drives::{
    is_windows_cloud_placeholder_attrs, should_skip_cloud_placeholder, FILE_ATTRIBUTE_OFFLINE,
};
use quorum_ingest::IngestConfig;
use quorum_types::{AccessTier, CloudPlaceholderPolicy};
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
// F1 Boundaries (2 tests)
// ============================================================================

#[tokio::test]
async fn t2_f1_empty_google_drive_root() {
    let ws = FakeCloudWorkspace::new();
    let empty_gdrive = ws.plant_google_drive_win_mirror();

    let daemon = DaemonTestProcess::start(&ws).await;
    let updated = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "google_drive",
            "enabled": true,
            "root_path": empty_gdrive.to_string_lossy()
        }))
        .await;
    let _ = daemon.post_cloud_drives_reindex("google_drive").await;
    daemon
        .wait_for_reindex_settled(Duration::from_secs(10))
        .await;

    let after = daemon.get_cloud_drives().await;
    let drv = find_drive(&after, "google_drive");
    assert_eq!(drv["mounted"].as_bool(), Some(true));
    assert_eq!(drv["indexed_files"].as_u64(), Some(0));
    assert_eq!(
        find_drive(&updated, "google_drive")["enabled"].as_bool(),
        Some(true)
    );
}

#[tokio::test]
async fn t2_f1_nonexistent_google_drive_path() {
    let ws = FakeCloudWorkspace::new();
    let missing = ws.home.join("DoesNotExist_GoogleDrive");
    let daemon = DaemonTestProcess::start(&ws).await;

    let (status, _, _) = daemon
        .post_json_raw(
            "/api/cloud-drives/config",
            &json!({
                "action": "toggle_drive",
                "id": "google_drive",
                "enabled": true,
                "root_path": missing.to_string_lossy()
            }),
        )
        .await;
    if status.is_success() {
        let after = daemon.get_cloud_drives().await;
        let drv = find_drive(&after, "google_drive");
        assert_ne!(drv["mounted"].as_bool(), Some(true));
    } else {
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

// ============================================================================
// F2 Boundaries (3 tests)
// ============================================================================

#[tokio::test]
async fn t2_f2_onedrive_deep_nested_dir_no_hang() {
    let ws = FakeCloudWorkspace::new();
    let od = ws.plant_onedrive_personal();
    let deep = od.join("a/b/c/d/e/f");
    ws.write_doc(&deep, "deep.txt", "TOKEN_T2_F2_DEEP nested one drive");

    let daemon = DaemonTestProcess::start(&ws).await;
    let updated = daemon
        .enable_and_reindex_drive("onedrive_personal", &od, Some(3), 1)
        .await;
    assert_eq!(
        find_drive(&updated, "onedrive_personal")["indexed_files"].as_u64(),
        Some(1)
    );
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T2_F2_DEEP").await,
        "TOKEN_T2_F2_DEEP"
    ));
}

#[tokio::test]
async fn t2_f2_onedrive_multiple_business_tenants() {
    let ws = FakeCloudWorkspace::new();
    let org_a = ws.plant_onedrive_business("OrgA");
    let org_b = ws.plant_onedrive_business("OrgB");
    ws.write_doc(&org_a, "a.txt", "TOKEN_T2_ORGA");
    ws.write_doc(&org_b, "b.txt", "TOKEN_T2_ORGB");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "onedrive_business");
    if cfg!(windows) {
        let roots: Vec<&str> = drv["detected_roots"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(roots
            .iter()
            .any(|r| paths_equivalent(r, &org_a.to_string_lossy())));
        assert!(roots
            .iter()
            .any(|r| paths_equivalent(r, &org_b.to_string_lossy())));
    }
}

#[tokio::test]
async fn t2_f2_onedrive_unicode_tenant_name() {
    let ws = FakeCloudWorkspace::new();
    let uni = ws.plant_onedrive_business("Société Générale 📁");
    ws.write_doc(&uni, "rapport.txt", "TOKEN_T2_F2_UNICODE dossier");

    let daemon = DaemonTestProcess::start(&ws).await;
    let updated = daemon
        .enable_and_reindex_drive("onedrive_business", &uni, Some(3), 1)
        .await;
    let drv = find_drive(&updated, "onedrive_business");
    assert!(paths_equivalent(
        drv["root_path"].as_str().unwrap_or(""),
        &uni.to_string_lossy()
    ));
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T2_F2_UNICODE").await,
        "TOKEN_T2_F2_UNICODE"
    ));
}

// ============================================================================
// F3 Boundaries (2 tests)
// ============================================================================

#[tokio::test]
async fn t2_f3_dropbox_malformed_info_json() {
    let ws = FakeCloudWorkspace::new();
    ws.plant_dropbox_info_json("{ \"personal\": { \"path\": ");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "dropbox");
    assert_eq!(drv["enabled"].as_bool(), Some(false));
}

#[tokio::test]
async fn t2_f3_dropbox_info_json_pointing_to_deleted_dir() {
    let ws = FakeCloudWorkspace::new();
    let deleted = ws.home.join("DeletedDropboxRoot");
    ws.plant_dropbox_info_json(
        &json!({ "personal": { "path": deleted.to_string_lossy() } }).to_string(),
    );

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "dropbox");
    for root in drv["detected_roots"].as_array().into_iter().flatten() {
        assert!(!paths_equivalent(
            root.as_str().unwrap_or(""),
            &deleted.to_string_lossy()
        ));
    }
}

// ============================================================================
// F6 Boundaries (2 tests)
// ============================================================================

#[tokio::test]
async fn t2_f6_nextcloud_malformed_cfg() {
    let ws = FakeCloudWorkspace::new();
    ws.plant_nextcloud_cfg(
        "[Accounts]\ngarbage_without_equals\n0\\Folders\\1\\localPath=\n\x01\x02",
    );

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "nextcloud");
    assert_eq!(drv["enabled"].as_bool(), Some(false));
}

#[tokio::test]
async fn t2_f6_nextcloud_cfg_trailing_slashes_and_mixed_separators() {
    let ws = FakeCloudWorkspace::new();
    let nc = ws.plant_nextcloud_home();
    let slash = format!("{}/", nc.to_string_lossy().replace('\\', "/"));
    let backslash = format!("{}\\", nc.to_string_lossy());
    ws.plant_nextcloud_cfg(&format!(
        "[Accounts]\n0\\Folders\\1\\localPath={}\n0\\Folders\\2\\localPath={}\n",
        slash, backslash
    ));

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "nextcloud");
    let count = drv["detected_roots"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| paths_equivalent(v.as_str().unwrap_or(""), &nc.to_string_lossy()))
        .count();
    assert!(
        count <= 1,
        "Mixed separator Nextcloud paths must deduplicate: {}",
        drv
    );
}

// ============================================================================
// F8 Boundaries: Tiers & Fail-Closed Paths (12 tests)
// ============================================================================

#[tokio::test]
async fn t2_f8_invalid_tier_4() {
    assert!(AccessTier::from_u8(4).is_err());
    let ws = FakeCloudWorkspace::new();
    let box_dir = ws.plant_box_win("Box");
    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "box",
            "enabled": true,
            "access_tier": 3,
            "root_path": box_dir.to_string_lossy()
        }))
        .await;
    let (status, _, _) = daemon
        .post_json_raw(
            "/api/cloud-drives/config",
            &json!({ "action": "toggle_drive", "id": "box", "enabled": true, "access_tier": 4, "root_path": box_dir.to_string_lossy() }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let after = daemon.get_cloud_drives().await;
    assert_eq!(find_drive(&after, "box")["access_tier"].as_u64(), Some(3));
}

#[tokio::test]
async fn t2_f8_invalid_tier_255() {
    assert!(AccessTier::from_u8(u8::MAX).is_err());
    let ws = FakeCloudWorkspace::new();
    let box_dir = ws.plant_box_win("Box");
    let daemon = DaemonTestProcess::start(&ws).await;
    let (status, _, _) = daemon
        .post_json_raw(
            "/api/cloud-drives/config",
            &json!({ "action": "toggle_drive", "id": "box", "enabled": true, "access_tier": 255, "root_path": box_dir.to_string_lossy() }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn t2_f8_negative_tier_minus_1() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    let (status, _, _) = daemon
        .post_raw_body(
            "/api/cloud-drives/config",
            r#"{"action":"toggle_drive","id":"box","enabled":true,"access_tier":-1}"#,
            "application/json",
        )
        .await;
    assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        find_drive(&daemon.get_cloud_drives().await, "box")["enabled"].as_bool(),
        Some(false)
    );
}

#[tokio::test]
async fn t2_f8_non_numeric_tier_admin() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    let (status, _, _) = daemon
        .post_raw_body(
            "/api/cloud-drives/config",
            r#"{"action":"toggle_drive","id":"box","enabled":true,"access_tier":"admin"}"#,
            "application/json",
        )
        .await;
    assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        find_drive(&daemon.get_cloud_drives().await, "box")["enabled"].as_bool(),
        Some(false)
    );
}

#[tokio::test]
async fn t2_f8_path_traversal_dot_dot() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    let (status, _, _) = daemon
        .post_json_raw(
            "/api/cloud-drives/config",
            &json!({ "action": "add_folder", "id": "dropbox", "path": r"C:\Users\Alice\Dropbox\..\..\Windows\System32" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn t2_f8_percent_encoded_traversal_and_nul() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    for bad in [
        r"C:\cloud\%2e%2e\secret",
        r"C:\cloud\dir%2fsub",
        r"C:\cloud\dir%5csub",
        r"C:\cloud\file%00.txt",
    ] {
        let (status, _, _) = daemon
            .post_json_raw(
                "/api/cloud-drives/config",
                &json!({ "action": "add_folder", "id": "dropbox", "path": bad }),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "Must reject {}", bad);
    }
}

#[tokio::test]
async fn t2_f8_raw_nul_byte_in_path() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    let (status, _, _) = daemon
        .post_json_raw(
            "/api/cloud-drives/config",
            &json!({ "action": "add_folder", "id": "dropbox", "path": "C:\\cloud\\file\0.txt" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn t2_f8_unc_and_extended_unc_rejected() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    for unc in [r"\\attacker-server\share\cloud", r"\\?\UNC\server\share"] {
        let (status, _, _) = daemon
            .post_json_raw(
                "/api/cloud-drives/config",
                &json!({ "action": "add_folder", "id": "dropbox", "path": unc }),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "Must reject UNC {}", unc);
    }
}

#[tokio::test]
async fn t2_f8_ntfs_ads_colon_rejected() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    for ads in [r"C:\cloud\file.txt:hidden_stream", r"C:\cloud:stream"] {
        let (status, _, _) = daemon
            .post_json_raw(
                "/api/cloud-drives/config",
                &json!({ "action": "add_folder", "id": "dropbox", "path": ads }),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "Must reject ADS {}", ads);
    }
}

#[tokio::test]
async fn t2_f8_empty_and_whitespace_path_rejected() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    for blank in ["", "   \t\n"] {
        let (status, _, _) = daemon
            .post_json_raw(
                "/api/cloud-drives/config",
                &json!({ "action": "add_folder", "id": "dropbox", "path": blank }),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn t2_f8_relative_and_overlong_4097_path_rejected() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    let overlong = format!("C:\\{}", "a".repeat(4100));
    for bad in ["Dropbox/notes", overlong.as_str()] {
        let (status, _, _) = daemon
            .post_json_raw(
                "/api/cloud-drives/config",
                &json!({ "action": "add_folder", "id": "dropbox", "path": bad }),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn t2_f8_drive_prefix_colon_only_at_index_1() {
    let ws = FakeCloudWorkspace::new();
    let valid = ws.mkdir("ValidDrivePrefix");
    let daemon = DaemonTestProcess::start(&ws).await;

    let (bad_st, _, _) = daemon
        .post_json_raw(
            "/api/cloud-drives/config",
            &json!({ "action": "add_folder", "id": "dropbox", "path": "C:relative" }),
        )
        .await;
    assert_eq!(bad_st, StatusCode::BAD_REQUEST);

    let (ok_st, _, _) = daemon
        .post_json_raw(
            "/api/cloud-drives/config",
            &json!({ "action": "add_folder", "id": "dropbox", "path": valid.to_string_lossy() }),
        )
        .await;
    assert_eq!(ok_st, StatusCode::OK);
}

// ============================================================================
// F9 Boundaries: Placeholder Attributes & Exclusions (5 tests)
// ============================================================================

#[tokio::test]
async fn t2_f9_offline_combined_archive_bitmask() {
    const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
    assert!(!is_windows_cloud_placeholder_attrs(FILE_ATTRIBUTE_ARCHIVE));
    assert!(is_windows_cloud_placeholder_attrs(
        FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_OFFLINE
    ));

    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "ok.txt", "TOKEN_T2_F9_OK");
    let _lock = if cfg!(windows) {
        let stub = ws.write_doc(&dropbox, "combined.txt", "TOKEN_T2_F9_COMBINED_SKIP");
        let attrs = set_windows_offline_attribute(&stub).expect("set offline");
        assert_ne!(attrs & 0x1000, 0);
        Some(ExclusiveFileLockGuard::lock(&stub).expect("lock stub"))
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
    assert_eq!(
        find_drive(&updated, "dropbox")["indexed_files"].as_u64(),
        Some(1)
    );
    if cfg!(windows) {
        assert!(!query_result_contains_token(
            &daemon.query_local("TOKEN_T2_F9_COMBINED_SKIP").await,
            "TOKEN_T2_F9_COMBINED_SKIP"
        ));
    }
}

#[tokio::test]
async fn t2_f9_normal_and_archive_attributes_accepted() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "normal.txt", "TOKEN_T2_F9_NORMAL_1");
    ws.write_doc(&dropbox, "archive.md", "TOKEN_T2_F9_NORMAL_2");

    let daemon = DaemonTestProcess::start(&ws).await;
    let updated = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 2)
        .await;
    assert_eq!(
        find_drive(&updated, "dropbox")["indexed_files"].as_u64(),
        Some(2)
    );
}

#[tokio::test]
async fn t2_f9_ordinary_files_not_misclassified_as_placeholder() {
    let ws = FakeCloudWorkspace::new();
    let box_dir = ws.plant_box_win("Box");
    ws.write_doc(&box_dir, "doc.txt", "TOKEN_T2_F9_ORD_TXT");
    ws.write_doc(&box_dir, "readme.md", "TOKEN_T2_F9_ORD_MD");
    ws.write_doc(
        &box_dir,
        "meta.csv",
        "key,value\ntoken,TOKEN_T2_F9_ORD_CSV\n",
    );

    let daemon = DaemonTestProcess::start(&ws).await;
    let updated = daemon
        .enable_and_reindex_drive("box", &box_dir, Some(3), 3)
        .await;
    assert!(
        find_drive(&updated, "box")["indexed_files"]
            .as_u64()
            .unwrap_or(0)
            >= 3
    );
}

#[tokio::test]
async fn t2_f9_zero_byte_offline_stub_skipped() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let _lock = if cfg!(windows) {
        let zero_stub = ws.write_doc(&dropbox, "empty_stub.txt", "");
        set_windows_offline_attribute(&zero_stub).expect("set offline");
        Some(ExclusiveFileLockGuard::lock(&zero_stub).expect("lock"))
    } else {
        None
    };

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": true,
            "root_path": dropbox.to_string_lossy()
        }))
        .await;
    let _ = daemon.post_cloud_drives_reindex("dropbox").await;
    daemon
        .wait_for_reindex_settled(Duration::from_secs(10))
        .await;
    assert_eq!(
        find_drive(&daemon.get_cloud_drives().await, "dropbox")["indexed_files"].as_u64(),
        Some(0)
    );
}

#[tokio::test]
async fn t2_f9_hidden_tmp_and_lock_files_filtered() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "real.txt", "TOKEN_T2_F9_REAL_KEEP");
    ws.write_doc(&dropbox, "~$temp_lock.txt", "TOKEN_T2_F9_LOCK_SKIP");
    ws.write_doc(&dropbox, ".hidden_state.tmp", "TOKEN_T2_F9_TMP_SKIP");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    daemon
        .wait_for_reindex_settled(Duration::from_secs(10))
        .await;

    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T2_F9_REAL_KEEP").await,
        "TOKEN_T2_F9_REAL_KEEP"
    ));
    assert!(!query_result_contains_token(
        &daemon.query_local("TOKEN_T2_F9_LOCK_SKIP").await,
        "TOKEN_T2_F9_LOCK_SKIP"
    ));
    assert!(!query_result_contains_token(
        &daemon.query_local("TOKEN_T2_F9_TMP_SKIP").await,
        "TOKEN_T2_F9_TMP_SKIP"
    ));
}

// ============================================================================
// F10 Boundaries: Hydration Size Caps (5 tests)
// ============================================================================

#[tokio::test]
async fn t2_f10_hydrate_exact_boundary_size_eq_cap_accepted() {
    assert!(!should_skip_cloud_placeholder(
        true,
        1024 * 1024,
        CloudPlaceholderPolicy::HydrateOnDemand {
            max_file_size_bytes: 1024 * 1024,
        }
    ));

    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let exact = ws.write_sized_file(
        &dropbox,
        "exact_1mb.txt",
        1024 * 1024,
        "TOKEN_T2_F10_EQ_1MB",
    );
    if cfg!(windows) {
        set_windows_offline_attribute(&exact).expect("set offline");
    }

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
    assert_eq!(
        find_drive(&updated, "dropbox")["indexed_files"].as_u64(),
        Some(1)
    );
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T2_F10_EQ_1MB").await,
        "TOKEN_T2_F10_EQ_1MB"
    ));
}

#[tokio::test]
async fn t2_f10_hydrate_exact_boundary_size_eq_cap_plus_1_skipped() {
    assert!(should_skip_cloud_placeholder(
        true,
        1024 * 1024 + 1,
        CloudPlaceholderPolicy::HydrateOnDemand {
            max_file_size_bytes: 1024 * 1024,
        }
    ));

    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "anchor.txt", "TOKEN_T2_F10_ANCHOR");
    let _lock = if cfg!(windows) {
        let over = ws.write_sized_file(
            &dropbox,
            "over_1mb_plus_1.txt",
            1024 * 1024 + 1,
            "TOKEN_T2_F10_OVER_1B",
        );
        set_windows_offline_attribute(&over).expect("set offline");
        Some(ExclusiveFileLockGuard::lock(&over).expect("lock cap+1 stub"))
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
            &daemon.query_local("TOKEN_T2_F10_OVER_1B").await,
            "TOKEN_T2_F10_OVER_1B"
        ));
    }
}

#[tokio::test]
async fn t2_f10_hydrate_zero_mb_clamped_or_rejected() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    let (status, _, body) = daemon
        .post_json_raw(
            "/api/cloud-drives/config",
            &json!({
                "action": "set_hydration",
                "placeholder_mode": "hydrate_on_demand",
                "hydration_max_file_size_mb": 0
            }),
        )
        .await;
    if status.is_success() {
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert!(
            v["hydration_max_file_size_mb"].as_u64().unwrap_or(0) >= 1,
            "0 MB must clamp to >= 1, got {}",
            v
        );
    } else {
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn t2_f10_hydrate_25mb_default_boundary_check() {
    assert!(!should_skip_cloud_placeholder(
        true,
        25 * 1024 * 1024,
        CloudPlaceholderPolicy::HydrateOnDemand {
            max_file_size_bytes: 25 * 1024 * 1024,
        }
    ));
    assert!(should_skip_cloud_placeholder(
        true,
        25 * 1024 * 1024 + 1,
        CloudPlaceholderPolicy::HydrateOnDemand {
            max_file_size_bytes: 25 * 1024 * 1024,
        }
    ));

    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let stub_25mb = ws.write_sized_file(
        &dropbox,
        "stub_25mb.txt",
        25 * 1024 * 1024,
        "TOKEN_T2_F10_25MB",
    );
    if cfg!(windows) {
        set_windows_offline_attribute(&stub_25mb).expect("set offline");
    }

    let daemon = DaemonTestProcess::start(&ws).await;
    let hyd = daemon
        .post_cloud_drives_config(&json!({
            "action": "set_hydration",
            "placeholder_mode": "hydrate_on_demand",
            "hydration_max_file_size_mb": 25
        }))
        .await;
    assert_eq!(hyd["hydration_max_file_size_mb"].as_u64(), Some(25));
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T2_F10_25MB").await,
        "TOKEN_T2_F10_25MB"
    ));
}

#[tokio::test]
async fn t2_f10_hydrate_u64_max_no_integer_overflow() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let small_stub = ws.write_doc(&dropbox, "small.txt", "TOKEN_T2_F10_U64MAX_SMALL");
    if cfg!(windows) {
        set_windows_offline_attribute(&small_stub).expect("set offline");
    }

    let daemon = DaemonTestProcess::start(&ws).await;
    let (status, _, _) = daemon
        .post_json_raw(
            "/api/cloud-drives/config",
            &json!({
                "action": "set_hydration",
                "placeholder_mode": "hydrate_on_demand",
                "hydration_max_file_size_mb": u64::MAX
            }),
        )
        .await;
    // Either rejected fail-closed or clamped safely with saturating math (never wrapping to 0!)
    assert!(
        status == StatusCode::BAD_REQUEST
            || status == StatusCode::UNPROCESSABLE_ENTITY
            || status == StatusCode::OK
    );
    if status == StatusCode::OK {
        let _ = daemon
            .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
            .await;
        assert!(query_result_contains_token(
            &daemon.query_local("TOKEN_T2_F10_U64MAX_SMALL").await,
            "TOKEN_T2_F10_U64MAX_SMALL"
        ));
    }
}

// ============================================================================
// F11 Boundaries: Dedup & Ingest Rules (5 tests)
// ============================================================================

#[tokio::test]
async fn t2_f11_dedup_sibling_prefix_trap() {
    let ws = FakeCloudWorkspace::new();
    let drop_dir = ws.mkdir("Cloud/Drop");
    let dropbox_dir = ws.mkdir("Cloud/Dropbox");
    ws.write_doc(&drop_dir, "a.txt", "TOKEN_T2_F11_DROP_ONLY");
    ws.write_doc(&dropbox_dir, "b.txt", "TOKEN_T2_F11_DROPBOX_KEEP");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("box", &drop_dir, Some(3), 1)
        .await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox_dir, Some(3), 1)
        .await;

    // Disabling "box" (prefix .../Cloud/Drop) MUST NOT purge .../Cloud/Dropbox
    let _ = daemon
        .post_cloud_drives_config(
            &json!({ "action": "toggle_drive", "id": "box", "enabled": false }),
        )
        .await;

    assert!(!query_result_contains_token(
        &daemon.query_local("TOKEN_T2_F11_DROP_ONLY").await,
        "TOKEN_T2_F11_DROP_ONLY"
    ));
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T2_F11_DROPBOX_KEEP").await,
        "TOKEN_T2_F11_DROPBOX_KEEP"
    ));
}

#[tokio::test]
async fn t2_f11_prefix_case_and_slash_normalization() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "norm.txt", "TOKEN_T2_F11_SLASH_NORM");
    let slash = dropbox.to_string_lossy().replace('\\', "/");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": true,
            "root_path": slash
        }))
        .await;
    let _ = daemon.post_cloud_drives_reindex("dropbox").await;
    let _ = daemon
        .wait_for_indexed("dropbox", 1, Duration::from_secs(30))
        .await;

    let _ = daemon
        .post_cloud_drives_config(
            &json!({ "action": "toggle_drive", "id": "dropbox", "enabled": false }),
        )
        .await;
    assert!(!query_result_contains_token(
        &daemon.query_local("TOKEN_T2_F11_SLASH_NORM").await,
        "TOKEN_T2_F11_SLASH_NORM"
    ));
}

#[tokio::test]
async fn t2_f11_nested_custom_folder_and_root_specificity() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let custom = ws.mkdir("CustomExtraCloud");
    ws.write_doc(&dropbox, "root_doc.txt", "TOKEN_T2_F11_ROOT_DOC");
    ws.write_doc(&custom, "custom_doc.txt", "TOKEN_T2_F11_CUSTOM_DOC");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": true,
            "root_path": dropbox.to_string_lossy()
        }))
        .await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "add_folder",
            "id": "dropbox",
            "path": custom.to_string_lossy()
        }))
        .await;
    let _ = daemon.post_cloud_drives_reindex("dropbox").await;
    let _ = daemon
        .wait_for_indexed("dropbox", 2, Duration::from_secs(30))
        .await;

    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "remove_folder",
            "id": "dropbox",
            "path": custom.to_string_lossy()
        }))
        .await;
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T2_F11_ROOT_DOC").await,
        "TOKEN_T2_F11_ROOT_DOC"
    ));
    assert!(!query_result_contains_token(
        &daemon.query_local("TOKEN_T2_F11_CUSTOM_DOC").await,
        "TOKEN_T2_F11_CUSTOM_DOC"
    ));
}

#[tokio::test]
async fn t2_f11_zero_byte_local_file_no_panic() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "zero.txt", "");
    ws.write_doc(&dropbox, "nonempty.txt", "TOKEN_T2_F11_NONEMPTY");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T2_F11_NONEMPTY").await,
        "TOKEN_T2_F11_NONEMPTY"
    ));
}

#[tokio::test]
async fn t2_f11_binary_exe_inside_cloud_drive_rejected() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "valid.txt", "TOKEN_T2_F11_BIN_VALID");
    std::fs::write(
        dropbox.join("payload.exe"),
        b"MZ\x90\x00TOKEN_T2_F11_BINARY_EXE_SHOULD_SKIP",
    )
    .expect("write exe");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    daemon
        .wait_for_reindex_settled(Duration::from_secs(10))
        .await;
    assert!(!query_result_contains_token(
        &daemon
            .query_local("TOKEN_T2_F11_BINARY_EXE_SHOULD_SKIP")
            .await,
        "TOKEN_T2_F11_BINARY_EXE_SHOULD_SKIP"
    ));
}

// ============================================================================
// F12 Boundaries: Prefix Purge (5 tests)
// ============================================================================

#[tokio::test]
async fn t2_f12_purge_sibling_prefix_boundary() {
    let ws = FakeCloudWorkspace::new();
    let db = ws.mkdir("SyncRoots/Dropbox");
    let db_arch = ws.mkdir("SyncRoots/Dropbox Archive");
    ws.write_doc(&db, "active.txt", "TOKEN_T2_F12_DROPBOX_PURGE");
    ws.write_doc(&db_arch, "archive.txt", "TOKEN_T2_F12_ARCHIVE_KEEP");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &db, Some(3), 1)
        .await;
    let _ = daemon
        .enable_and_reindex_drive("box", &db_arch, Some(3), 1)
        .await;

    let _ = daemon
        .post_cloud_drives_config(
            &json!({ "action": "toggle_drive", "id": "dropbox", "enabled": false }),
        )
        .await;

    assert!(!query_result_contains_token(
        &daemon.query_local("TOKEN_T2_F12_DROPBOX_PURGE").await,
        "TOKEN_T2_F12_DROPBOX_PURGE"
    ));
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T2_F12_ARCHIVE_KEEP").await,
        "TOKEN_T2_F12_ARCHIVE_KEEP"
    ));
}

#[tokio::test]
async fn t2_f12_purge_on_empty_unindexed_drive_is_noop() {
    let ws = FakeCloudWorkspace::new();
    let empty = ws.plant_dropbox_standard();
    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": true,
            "root_path": empty.to_string_lossy()
        }))
        .await;
    let off = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": false
        }))
        .await;
    assert_eq!(off["purged_files"].as_u64(), Some(0));
}

#[tokio::test]
async fn t2_f12_remove_single_custom_folder_leaves_other_custom_folder() {
    let ws = FakeCloudWorkspace::new();
    let c_a = ws.mkdir("CustomA");
    let c_b = ws.mkdir("CustomB");
    ws.write_doc(&c_a, "a.txt", "TOKEN_T2_F12_CUSTOM_A");
    ws.write_doc(&c_b, "b.txt", "TOKEN_T2_F12_CUSTOM_B");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "add_folder",
            "id": "dropbox",
            "path": c_a.to_string_lossy()
        }))
        .await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "add_folder",
            "id": "dropbox",
            "path": c_b.to_string_lossy()
        }))
        .await;
    let _ = daemon
        .post_cloud_drives_config(
            &json!({ "action": "toggle_drive", "id": "dropbox", "enabled": true }),
        )
        .await;
    let _ = daemon.post_cloud_drives_reindex("dropbox").await;
    let _ = daemon
        .wait_for_indexed("dropbox", 2, Duration::from_secs(30))
        .await;

    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "remove_folder",
            "id": "dropbox",
            "path": c_a.to_string_lossy()
        }))
        .await;

    assert!(!query_result_contains_token(
        &daemon.query_local("TOKEN_T2_F12_CUSTOM_A").await,
        "TOKEN_T2_F12_CUSTOM_A"
    ));
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T2_F12_CUSTOM_B").await,
        "TOKEN_T2_F12_CUSTOM_B"
    ));
}

#[tokio::test]
async fn t2_f12_double_disable_is_idempotent() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "x.txt", "TOKEN_T2_F12_DOUBLE_DISABLE");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;

    let _ = daemon
        .post_cloud_drives_config(
            &json!({ "action": "toggle_drive", "id": "dropbox", "enabled": false }),
        )
        .await;
    let second = daemon
        .post_cloud_drives_config(
            &json!({ "action": "toggle_drive", "id": "dropbox", "enabled": false }),
        )
        .await;
    assert_eq!(second["purged_files"].as_u64(), Some(0));
}

#[tokio::test]
async fn t2_f12_tier_update_invalid_tier_4_rejected() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": true,
            "access_tier": 3,
            "root_path": dropbox.to_string_lossy()
        }))
        .await;

    let (status, _, _) = daemon
        .post_json_raw(
            "/api/cloud-drives/config",
            &json!({
                "action": "toggle_drive",
                "id": "dropbox",
                "enabled": true,
                "access_tier": 4
            }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        find_drive(&daemon.get_cloud_drives().await, "dropbox")["access_tier"].as_u64(),
        Some(3)
    );
}

// ============================================================================
// F13 Boundaries: Mesh Isolation (5 tests)
// ============================================================================

#[tokio::test]
async fn t2_f13_mesh_disabled_shared_folder_entry_blocked() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let doc = ws.write_doc(&dropbox, "disabled_sf.txt", "clean content");

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
                "enabled": false,
                "access_tier": 0
            }),
        )
        .await;

    let dlp = daemon
        .post_json(
            "/api/dlp/test",
            &json!({ "text": "clean content", "file_path": doc.to_string_lossy() }),
        )
        .await;
    assert_eq!(dlp["folder_shared_with_mesh"].as_bool(), Some(false));
}

#[tokio::test]
async fn t2_f13_mesh_sibling_prefix_folder_not_shared() {
    let ws = FakeCloudWorkspace::new();
    let drive = ws.mkdir("Cloud/Drive");
    let drive_shared = ws.mkdir("Cloud/DriveShared");
    let private_doc = ws.write_doc(&drive, "priv.txt", "private cloud doc");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &drive, Some(3), 1)
        .await;
    let _ = daemon
        .post_json(
            "/api/mesh/shared-folders",
            &json!({
                "action": "add",
                "path": drive_shared.to_string_lossy(),
                "enabled": true,
                "access_tier": 0
            }),
        )
        .await;

    let dlp = daemon
        .post_json(
            "/api/dlp/test",
            &json!({ "text": "private cloud doc", "file_path": private_doc.to_string_lossy() }),
        )
        .await;
    assert_eq!(dlp["folder_shared_with_mesh"].as_bool(), Some(false));
}

#[tokio::test]
async fn t2_f13_mesh_p2p_disabled_blocks_sharing() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let doc = ws.write_doc(&dropbox, "p2p_off.txt", "clean");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .post_json("/api/mesh/config", &json!({ "p2p_enabled": false }))
        .await;
    let _ = daemon
        .post_json(
            "/api/mesh/shared-folders",
            &json!({
                "action": "add",
                "path": dropbox.to_string_lossy(),
                "enabled": true,
                "access_tier": 0
            }),
        )
        .await;

    let dlp = daemon
        .post_json(
            "/api/dlp/test",
            &json!({ "text": "clean", "file_path": doc.to_string_lossy() }),
        )
        .await;
    assert_eq!(dlp["folder_shared_with_mesh"].as_bool(), Some(false));
}

#[tokio::test]
async fn t2_f13_mesh_access_tier_2_boundary_allowed() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let doc = ws.write_doc(&dropbox, "tier2.txt", "clean");

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
                "access_tier": 2
            }),
        )
        .await;

    // Drive is still Tier 3 => even with shared_folders access_tier = 2, max(2, 3) = 3 => BLOCKED
    let dlp_tier3 = daemon
        .post_json(
            "/api/dlp/test",
            &json!({ "text": "clean", "file_path": doc.to_string_lossy() }),
        )
        .await;
    assert_eq!(dlp_tier3["folder_shared_with_mesh"].as_bool(), Some(false));
    assert_eq!(dlp_tier3["effective_mesh_allowed"].as_bool(), Some(false));

    // Lower the drive's access_tier to 2 (< 3) => max(2, 2) = 2 < 3 => ALLOWED
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "set_tier",
            "id": "dropbox",
            "access_tier": 2
        }))
        .await;

    let dlp = daemon
        .post_json(
            "/api/dlp/test",
            &json!({ "text": "clean", "file_path": doc.to_string_lossy() }),
        )
        .await;
    assert_eq!(dlp["folder_shared_with_mesh"].as_bool(), Some(true));
    assert_eq!(dlp["effective_mesh_allowed"].as_bool(), Some(true));
}

#[tokio::test]
async fn t2_f13_mesh_dlp_test_blocks_traversal_path() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .post_json(
            "/api/mesh/shared-folders",
            &json!({
                "action": "add",
                "path": dropbox.to_string_lossy(),
                "enabled": true,
                "access_tier": 0
            }),
        )
        .await;

    let bad_path = format!("{}\\..\\..\\secret.txt", dropbox.to_string_lossy());
    let (status, _, body) = daemon
        .post_json_raw(
            "/api/dlp/test",
            &json!({ "text": "secret", "file_path": bad_path }),
        )
        .await;
    if status.is_success() {
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["folder_shared_with_mesh"].as_bool(), Some(false));
        assert_eq!(v["effective_mesh_allowed"].as_bool(), Some(false));
    } else {
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

// ============================================================================
// F15 Boundaries: Daemon API Error Handling & Concurrency (5 tests)
// ============================================================================

#[tokio::test]
async fn t2_f15_reindex_unknown_drive_id_rejected() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    let (status, _, _) = daemon
        .post_json_raw(
            "/api/cloud-drives/reindex",
            &json!({ "id": "nonexistent_cloud" }),
        )
        .await;
    assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn t2_f15_reindex_disabled_drive_rejected() {
    let ws = FakeCloudWorkspace::new();
    let _dropbox = ws.plant_dropbox_standard();
    let daemon = DaemonTestProcess::start(&ws).await;
    let (status, _, _) = daemon
        .post_json_raw("/api/cloud-drives/reindex", &json!({ "id": "dropbox" }))
        .await;
    assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::CONFLICT);
}

#[tokio::test]
async fn t2_f15_reindex_enabled_unmounted_drive_rejected() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    let initial = find_drive(&daemon.get_cloud_drives().await, "icloud_drive").clone();
    assert_eq!(initial["mounted"].as_bool(), Some(false));

    let (st, _, _) = daemon
        .post_json_raw(
            "/api/cloud-drives/config",
            &json!({ "action": "toggle_drive", "id": "icloud_drive", "enabled": true }),
        )
        .await;
    assert!(
        st.is_success() || st == StatusCode::BAD_REQUEST || st == StatusCode::CONFLICT,
        "Unexpected status enabling unmounted drive: {}",
        st
    );
    if st.is_success() {
        let status_payload = daemon.get_cloud_drives().await;
        let drv = find_drive(&status_payload, "icloud_drive");
        assert_eq!(drv["mounted"].as_bool(), Some(false));
        let (rst, _, _) = daemon
            .post_json_raw(
                "/api/cloud-drives/reindex",
                &json!({ "id": "icloud_drive" }),
            )
            .await;
        assert!(
            rst == StatusCode::BAD_REQUEST || rst == StatusCode::CONFLICT,
            "Reindex on unmounted drive must return 400 or 409, got {}",
            rst
        );
    }
}

#[tokio::test]
async fn t2_f15_config_malformed_json_and_unknown_action() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;

    let (st1, _, _) = daemon
        .post_raw_body(
            "/api/cloud-drives/config",
            "{broken_json",
            "application/json",
        )
        .await;
    assert!(st1 == StatusCode::BAD_REQUEST || st1 == StatusCode::UNPROCESSABLE_ENTITY);

    let (st2, _, _) = daemon
        .post_json_raw(
            "/api/cloud-drives/config",
            &json!({ "action": "unknown_action_xyz", "id": "dropbox" }),
        )
        .await;
    assert!(st2 == StatusCode::BAD_REQUEST || st2 == StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn t2_f15_rapid_enable_disable_enable_sequence() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "rapid.txt", "TOKEN_T2_F15_RAPID_TOGGLE");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": true,
            "root_path": dropbox.to_string_lossy()
        }))
        .await;
    let _ = daemon
        .post_cloud_drives_config(
            &json!({ "action": "toggle_drive", "id": "dropbox", "enabled": false }),
        )
        .await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": true,
            "root_path": dropbox.to_string_lossy()
        }))
        .await;
    let _ = daemon
        .post_cloud_drives_config(
            &json!({ "action": "toggle_drive", "id": "dropbox", "enabled": false }),
        )
        .await;

    let after = daemon.get_cloud_drives().await;
    assert_eq!(
        find_drive(&after, "dropbox")["enabled"].as_bool(),
        Some(false)
    );
    assert!(!query_result_contains_token(
        &daemon.query_local("TOKEN_T2_F15_RAPID_TOGGLE").await,
        "TOKEN_T2_F15_RAPID_TOGGLE"
    ));
}

// ============================================================================
// F16 Boundaries: LocalSystem Profile Filtering & Headless Virtual Drives (3 tests)
// ============================================================================

#[test]
fn t2_f16_profile_enum_skips_system_profile_dirs() {
    let roots = IngestConfig::discover_user_document_roots();
    for r in roots {
        let lower = r.to_string_lossy().to_ascii_lowercase();
        for forbidden in [
            "systemprofile",
            "localservice",
            "networkservice",
            "default user",
            "all users",
        ] {
            assert!(
                !lower.contains(forbidden),
                "System profile '{}' must not appear in discover_user_document_roots: {}",
                forbidden,
                r.display()
            );
        }
    }
}

#[tokio::test]
async fn t2_f16_system_named_subdirs_not_mistaken_for_cloud_roots() {
    let ws = FakeCloudWorkspace::new();
    ws.mkdir("systemprofile/OneDrive");
    ws.mkdir("LocalService/Dropbox");
    ws.mkdir("Public/Box");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    for drv in payload["drives"].as_array().expect("drives") {
        for r in drv["detected_roots"].as_array().into_iter().flatten() {
            let s = r.as_str().unwrap_or("").to_ascii_lowercase();
            assert!(!s.contains("systemprofile") && !s.contains("localservice"));
        }
    }
}

#[tokio::test]
async fn t2_f16_headless_virtual_drive_graceful_status() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let gdrv = find_drive(&payload, "google_drive");
    assert!(matches!(
        gdrv["status"].as_str(),
        Some("mounted" | "not_detected" | "session_only" | "error")
    ));
    assert_eq!(gdrv["enabled"].as_bool(), Some(false));
}

// ============================================================================
// F18 Boundaries: WebUI Static Security Hygiene (5 tests)
// ============================================================================

#[test]
fn t2_f18_xss_escape_html_on_all_cloud_drive_interpolations() {
    let (_, js, _) = read_repo_ui_assets();
    let slice = extract_cloud_drives_tab_slice(&js);
    for var_expr in [
        "escapeHtml(drvLabel)",
        "escapeHtml(drvId)",
        "escapeHtml(drv.root_path",
        "escapeHtml(guidanceText)",
        "escapeHtml(bannerText)",
        "escapeHtml(cp)",
        "escapeHtml(String(maxMb))",
    ] {
        assert!(
            slice.contains(var_expr),
            "Cloud Drives UI template must escape dynamic values via {}",
            var_expr
        );
    }
}

#[test]
fn t2_f18_hydration_size_input_bounds_and_nan_fallback() {
    let (_, js, _) = read_repo_ui_assets();
    let slice = extract_cloud_drives_tab_slice(&js);
    assert!(slice.contains(r#"min="1" max="2048""#));
    assert!(slice.contains("Math.min(2048, Math.round(rawMaxMb))"));
    assert!(js.contains("rawMax === '' ? NaN"));
    for forbidden in [
        "eval(",
        "new Function(",
        "document.write(",
        "document.writeln(",
    ] {
        assert!(
            !js.contains(forbidden),
            "app.js must not contain dangerous sink '{}'",
            forbidden
        );
    }
}

#[test]
fn t2_f18_light_theme_contrast_and_offline_retry_boundary() {
    let (_, js, css) = read_repo_ui_assets();
    let slice = extract_cloud_drives_tab_slice(&js);
    assert!(slice.contains("Backend Offline / Unavailable"));
    assert!(slice.contains("🔄 Retry"));
    for rule in [
        "body.theme-white .cloud-drive-card .dlp-badge-redact",
        "body.theme-warm .cloud-drive-card .dlp-badge-redact",
        "body.theme-white .cloud-drive-banner .dlp-badge-redact",
        "body.theme-warm .cloud-drive-banner .dlp-badge-redact",
    ] {
        assert!(
            css.contains(rule),
            "styles.css missing light-theme contrast rule '{}'",
            rule
        );
    }
}

#[test]
fn t2_f18_zero_inline_handlers_and_json_stringify_attrs() {
    let (html, js, _) = read_repo_ui_assets();
    let nav_html = extract_settings_nav_slice(&html);
    let slice = extract_cloud_drives_tab_slice(&js);
    for src in [nav_html, js.as_str(), slice] {
        let lower = src.to_ascii_lowercase();
        for handler in [
            " onclick=",
            " onchange=",
            " oninput=",
            " onkeydown=",
            " onkeyup=",
            " onsubmit=",
            " onerror=",
        ] {
            assert!(
                !lower.contains(handler),
                "Found forbidden inline handler {}",
                handler
            );
        }
    }
    assert!(!slice.contains("${JSON.stringify"));
    assert!(!nav_html.contains("checked=false"));
    assert!(!slice.contains("checked=false"));
}

#[test]
fn t2_f18_zero_inline_style_on_settings_page_title() {
    let (_, js, _) = read_repo_ui_assets();
    let slice = extract_cloud_drives_tab_slice(&js);
    let inner_marker = "settingsContent.innerHTML = `";
    let inner_start = slice
        .find(inner_marker)
        .expect("cloud-drives slice must assign settingsContent.innerHTML")
        + inner_marker.len();
    let inner_end = slice[inner_start..]
        .find("`;")
        .expect("settingsContent.innerHTML template must terminate cleanly")
        + inner_start;
    let body = slice[inner_start..inner_end].trim();
    assert!(body.starts_with(r#"<div class="settings-centered-container">"#));
    assert!(body.ends_with("</div>"));
    assert!(body.contains(r#"<h2 class="settings-page-title">☁️ Cloud Drives</h2>"#));
    assert!(!body.contains(r#"<h2 class="settings-page-title" style="#));
}
