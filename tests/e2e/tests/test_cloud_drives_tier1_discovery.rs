//! Tier 1 E2E Tests: Cloud Drives Cross-OS Discovery (`F1`–`F7`) & Shared Schema/Validation (`F8`).
//!
//! 40 opaque-box tests (`F1`–`F8`, 5 per feature) exercising the real `quorumrag` binary,
//! real filesystem fixtures, HTTP JSON API (`/api/cloud-drives`, `/api/cloud-drives/config`,
//! `/api/cloud-drives/reindex`, `/api/query`, `/api/mesh/status`), `<data_dir>/settings.json`,
//! and existing stable crate APIs (`AccessTier::from_u8`, `IngestConfig`).

use quorum_e2e::cloud_drives_harness::{
    find_drive, find_drives_by_provider, paths_equivalent, query_result_contains_token,
    DaemonTestProcess, FakeCloudWorkspace,
};
use quorum_ingest::IngestConfig;
use quorum_types::AccessTier;
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::path::Path;

fn drive_has_root(drive: &Value, expected: &Path) -> bool {
    let exp_str = expected.to_string_lossy();
    let in_root = drive
        .get("root_path")
        .and_then(|v| v.as_str())
        .map(|s| paths_equivalent(s, &exp_str))
        .unwrap_or(false);
    let in_detected = drive
        .get("detected_roots")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .any(|s| paths_equivalent(s, &exp_str))
        })
        .unwrap_or(false);
    in_root || in_detected
}

fn assert_default_off_and_tier3(drive: &Value) {
    assert_eq!(
        drive.get("enabled").and_then(|v| v.as_bool()),
        Some(false),
        "Cloud drive must be disabled by default: {}",
        drive
    );
    assert_eq!(
        drive.get("access_tier").and_then(|v| v.as_u64()),
        Some(3),
        "Cloud drive must default to Tier 3 local-only: {}",
        drive
    );
    assert_eq!(
        drive.get("shared_with_mesh").and_then(|v| v.as_bool()),
        Some(false),
        "Cloud drive must not be shared with mesh by default: {}",
        drive
    );
}

// ============================================================================
// F1: Google Drive Cross-OS Discovery (5 tests)
// ============================================================================

#[tokio::test]
async fn t1_f1_google_drive_win_my_drive() {
    let ws = FakeCloudWorkspace::new();
    let root = ws.plant_google_drive_win_mirror();
    let my_drive = ws.plant_google_drive_win_my_drive();
    ws.write_doc(
        &root,
        "gdrive_win_note.txt",
        "TOKEN_F1_WIN_MY_DRIVE quarterly plan",
    );

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "google_drive");
    assert_eq!(drv["provider"].as_str(), Some("google_drive"));
    assert_default_off_and_tier3(drv);
    if cfg!(windows) {
        assert_eq!(drv["detected"].as_bool(), Some(true));
        assert_eq!(drv["mounted"].as_bool(), Some(true));
        assert!(drive_has_root(drv, &ws.home.join("Google Drive")));
        assert!(drive_has_root(drv, &my_drive));
    }

    // Verify planted mirror root can be explicitly enabled, indexed, and queried opaquely.
    let updated = daemon
        .enable_and_reindex_drive("google_drive", &root, Some(3), 1)
        .await;
    let drv_after = find_drive(&updated, "google_drive");
    assert_eq!(drv_after["enabled"].as_bool(), Some(true));
    assert_eq!(drv_after["mounted"].as_bool(), Some(true));
    let qr = daemon.query_local("TOKEN_F1_WIN_MY_DRIVE").await;
    assert!(query_result_contains_token(&qr, "TOKEN_F1_WIN_MY_DRIVE"));
}

#[tokio::test]
async fn t1_f1_google_drive_win_shared_drives() {
    let ws = FakeCloudWorkspace::new();
    let shared = ws.plant_google_drive_win_shared_drives();
    ws.write_doc(
        &shared,
        "team_roadmap.md",
        "TOKEN_F1_SHARED_DRIVES milestone alpha",
    );

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "google_drive");
    assert_default_off_and_tier3(drv);

    let updated = daemon
        .enable_and_reindex_drive("google_drive", &shared, Some(3), 1)
        .await;
    assert!(drive_has_root(
        find_drive(&updated, "google_drive"),
        &shared
    ));
    let qr = daemon.query_local("TOKEN_F1_SHARED_DRIVES").await;
    assert!(query_result_contains_token(&qr, "TOKEN_F1_SHARED_DRIVES"));
}

#[tokio::test]
async fn t1_f1_google_drive_macos_cloudstorage() {
    let ws = FakeCloudWorkspace::new();
    let mac_root = ws.plant_google_drive_macos("alice@example.com");
    ws.write_doc(
        &mac_root,
        "mac_notes.md",
        "TOKEN_F1_MACOS_CLOUDSTORAGE notes",
    );

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "google_drive");
    assert_default_off_and_tier3(drv);
    if cfg!(target_os = "macos") {
        assert_eq!(drv["detected"].as_bool(), Some(true));
        assert!(drive_has_root(drv, &mac_root));
    }

    let updated = daemon
        .enable_and_reindex_drive("google_drive", &mac_root, Some(3), 1)
        .await;
    assert_eq!(
        find_drive(&updated, "google_drive")["mounted"].as_bool(),
        Some(true)
    );
    let qr = daemon.query_local("TOKEN_F1_MACOS_CLOUDSTORAGE").await;
    assert!(query_result_contains_token(
        &qr,
        "TOKEN_F1_MACOS_CLOUDSTORAGE"
    ));
}

#[tokio::test]
async fn t1_f1_google_drive_linux_mounts() {
    let ws = FakeCloudWorkspace::new();
    let linux_root = ws.plant_google_drive_linux("Google Drive");
    let _alt_root = ws.plant_google_drive_linux("google-drive");
    ws.write_doc(
        &linux_root,
        "linux_doc.txt",
        "TOKEN_F1_LINUX_MOUNT architecture",
    );

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "google_drive");
    assert_default_off_and_tier3(drv);
    if cfg!(target_os = "linux") {
        assert_eq!(drv["detected"].as_bool(), Some(true));
        assert!(drive_has_root(drv, &linux_root));
    }

    let _ = daemon
        .enable_and_reindex_drive("google_drive", &linux_root, Some(3), 1)
        .await;
    let qr = daemon.query_local("TOKEN_F1_LINUX_MOUNT").await;
    assert!(query_result_contains_token(&qr, "TOKEN_F1_LINUX_MOUNT"));
}

#[tokio::test]
async fn t1_f1_google_drive_physical_drives_unchanged() {
    use quorum_ingest::cloud_drives::{
        discover_cloud_drives_with_env, CloudDiscoveryEnv, RegistrySyncRoot, TargetOs,
        WindowsDriveMount,
    };

    struct VirtualGDriveEnv;
    impl CloudDiscoveryEnv for VirtualGDriveEnv {
        fn target_os(&self) -> TargetOs {
            TargetOs::Windows
        }
        fn user_profiles(&self) -> Vec<std::path::PathBuf> {
            Vec::new()
        }
        fn env_var(&self, _key: &str) -> Option<String> {
            None
        }
        fn dir_exists(&self, path: &Path) -> bool {
            let s = path.to_string_lossy();
            s.eq_ignore_ascii_case(r"G:\My Drive") || s.eq_ignore_ascii_case(r"G:\Shared drives")
        }
        fn file_exists(&self, _path: &Path) -> bool {
            false
        }
        fn read_dir_names(&self, _path: &Path) -> Vec<String> {
            Vec::new()
        }
        fn read_to_string(&self, _path: &Path) -> Option<String> {
            None
        }
        fn windows_drive_mounts(&self) -> Vec<WindowsDriveMount> {
            vec![WindowsDriveMount {
                letter: 'G',
                root: std::path::PathBuf::from(r"G:\"),
                volume_label: "Google Drive".to_string(),
                is_virtual: true,
                nt_target: r"\Device\GoogleDriveFS".to_string(),
            }]
        }
        fn windows_registry_sync_roots(&self) -> Vec<RegistrySyncRoot> {
            Vec::new()
        }
        fn is_virtual_mount(&self, path: &Path) -> bool {
            path.to_string_lossy()
                .to_ascii_uppercase()
                .starts_with("G:")
        }
    }

    let discovered = discover_cloud_drives_with_env(&VirtualGDriveEnv);
    let gd = discovered
        .iter()
        .find(|d| d.id == "google_drive")
        .expect("google_drive entry");
    assert!(gd.detected && gd.mounted && gd.virtual_drive);
    assert!(gd
        .detected_roots
        .iter()
        .any(|p| paths_equivalent(&p.to_string_lossy(), r"G:\My Drive")));

    let physical = IngestConfig::discover_physical_drives();
    for drive in &physical {
        let s = drive.to_string_lossy().to_ascii_lowercase();
        assert!(
            !s.contains("google drive") && !s.contains("onedrive") && !s.contains("dropbox"),
            "discover_physical_drives() must not return cloud drive labels: {}",
            drive.display()
        );
        #[cfg(windows)]
        {
            // Verify any G:\ entry in physical drives is NOT a Google Drive / virtual mount
            if s.starts_with("g:") {
                let my_drive_sub = drive.join("My Drive");
                assert!(
                    !my_drive_sub.is_dir(),
                    "Virtual Google Drive G:\\ must never appear in discover_physical_drives(): {}",
                    drive.display()
                );
            }
        }
    }

    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    let browse = daemon.get_json("/api/fs/browse-folders").await;
    let browse_drives = browse["drives"].as_array().expect("browse drives array");
    for d in browse_drives {
        let ds = d.as_str().unwrap_or("");
        assert!(!ds.to_ascii_lowercase().contains("google drive"));
    }
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "google_drive");
    assert_default_off_and_tier3(drv);
}

// ============================================================================
// F2: OneDrive (Personal & Business) Cross-OS Discovery (5 tests)
// ============================================================================

#[tokio::test]
async fn t1_f2_onedrive_win_personal() {
    let ws = FakeCloudWorkspace::new();
    let personal = ws.plant_onedrive_personal();
    ws.write_doc(
        &personal,
        "personal.txt",
        "TOKEN_F2_ONEDRIVE_PERSONAL budget",
    );

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "onedrive_personal");
    assert_eq!(drv["provider"].as_str(), Some("onedrive"));
    assert_eq!(drv["account_kind"].as_str(), Some("personal"));
    assert_default_off_and_tier3(drv);
    if cfg!(windows) {
        assert_eq!(drv["detected"].as_bool(), Some(true));
        assert!(drive_has_root(drv, &personal));
    }
}

#[tokio::test]
async fn t1_f2_onedrive_win_business() {
    let ws = FakeCloudWorkspace::new();
    let biz = ws.plant_onedrive_business("Acme Corp");
    ws.write_doc(&biz, "corp_spec.md", "TOKEN_F2_ONEDRIVE_BUSINESS roadmap");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "onedrive_business");
    assert_eq!(drv["provider"].as_str(), Some("onedrive"));
    assert_eq!(drv["account_kind"].as_str(), Some("business"));
    assert_default_off_and_tier3(drv);
    if cfg!(windows) {
        assert_eq!(drv["detected"].as_bool(), Some(true));
        assert!(drive_has_root(drv, &biz));
    }
}

#[tokio::test]
async fn t1_f2_onedrive_macos_cloudstorage() {
    let ws = FakeCloudWorkspace::new();
    let mac_personal = ws.plant_onedrive_macos("OneDrive-Personal");
    let mac_biz = ws.plant_onedrive_macos("OneDrive-AcmeCorp");
    ws.write_doc(&mac_personal, "p.txt", "TOKEN_F2_MAC_PERSONAL");
    ws.write_doc(&mac_biz, "b.txt", "TOKEN_F2_MAC_BUSINESS");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let onedrives = find_drives_by_provider(&payload, "onedrive");
    assert!(
        !onedrives.is_empty(),
        "Expected OneDrive entries in {}",
        payload
    );
    for d in onedrives {
        assert_default_off_and_tier3(d);
    }
    if cfg!(target_os = "macos") {
        let p = find_drive(&payload, "onedrive_personal");
        let b = find_drive(&payload, "onedrive_business");
        assert!(drive_has_root(p, &mac_personal));
        assert!(drive_has_root(b, &mac_biz));
    }
}

#[tokio::test]
async fn t1_f2_onedrive_linux_roots() {
    let ws = FakeCloudWorkspace::new();
    let p_root = ws.plant_onedrive_personal();
    let b_root = ws.plant_onedrive_business("Work");
    ws.write_doc(&p_root, "linux_p.txt", "TOKEN_F2_LINUX_PERSONAL");
    ws.write_doc(&b_root, "linux_b.txt", "TOKEN_F2_LINUX_BUSINESS");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    assert_default_off_and_tier3(find_drive(&payload, "onedrive_personal"));
    assert_default_off_and_tier3(find_drive(&payload, "onedrive_business"));
    if cfg!(target_os = "linux") {
        assert!(drive_has_root(
            find_drive(&payload, "onedrive_personal"),
            &p_root
        ));
        assert!(drive_has_root(
            find_drive(&payload, "onedrive_business"),
            &b_root
        ));
    }
}

#[tokio::test]
async fn t1_f2_onedrive_decoupled_from_user_document_roots() {
    let doc_roots = IngestConfig::discover_user_document_roots();
    for root in &doc_roots {
        let lower = root.to_string_lossy().to_ascii_lowercase();
        assert!(
            !lower.contains("onedrive"),
            "IngestConfig::discover_user_document_roots() must NOT auto-include OneDrive folders: {}",
            root.display()
        );
    }

    let ws = FakeCloudWorkspace::new();
    let _p = ws.plant_onedrive_personal();
    let _b = ws.plant_onedrive_business("Acme Corp");
    let daemon = DaemonTestProcess::start(&ws).await;
    let mesh = daemon.get_json("/api/mesh/status").await;
    let shared = mesh["shared_folders"]
        .as_array()
        .expect("shared_folders array");
    for folder in shared {
        let p = folder["path"].as_str().unwrap_or("").to_ascii_lowercase();
        assert!(
            !p.contains("onedrive"),
            "Daemon must not auto-share OneDrive into mesh.shared_folders: {}",
            mesh
        );
    }
}

// ============================================================================
// F3: Dropbox Cross-OS Discovery (5 tests)
// ============================================================================

#[tokio::test]
async fn t1_f3_dropbox_win_info_json_personal_business() {
    let ws = FakeCloudWorkspace::new();
    let p_dir = ws.mkdir("CustomDropboxPersonal");
    let b_dir = ws.mkdir("CustomDropboxBusiness");
    let info = json!({
        "personal": { "path": p_dir.to_string_lossy(), "host": 12345 },
        "business": { "path": b_dir.to_string_lossy(), "host": 67890 }
    });
    ws.plant_dropbox_info_json(&info.to_string());

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "dropbox");
    assert_eq!(drv["provider"].as_str(), Some("dropbox"));
    assert_default_off_and_tier3(drv);
    if cfg!(windows) {
        assert_eq!(drv["detected"].as_bool(), Some(true));
        assert!(drive_has_root(drv, &p_dir) || drive_has_root(drv, &b_dir));
    }
}

#[tokio::test]
async fn t1_f3_dropbox_win_standard_folder() {
    let ws = FakeCloudWorkspace::new();
    let std_dir = ws.plant_dropbox_standard();
    ws.write_doc(&std_dir, "dropbox_std.md", "TOKEN_F3_DROPBOX_STD memo");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "dropbox");
    assert_default_off_and_tier3(drv);
    if cfg!(windows) {
        assert_eq!(drv["detected"].as_bool(), Some(true));
        assert!(drive_has_root(drv, &std_dir));
    }
}

#[tokio::test]
async fn t1_f3_dropbox_macos_cloudstorage_and_dot_dropbox() {
    let ws = FakeCloudWorkspace::new();
    let mac_dir = ws.plant_dropbox_macos();
    let info = json!({ "personal": { "path": mac_dir.to_string_lossy() } });
    ws.plant_dropbox_info_json(&info.to_string());

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "dropbox");
    assert_default_off_and_tier3(drv);
    if cfg!(target_os = "macos") {
        assert!(drive_has_root(drv, &mac_dir));
    }
}

#[tokio::test]
async fn t1_f3_dropbox_linux_home_and_info_json() {
    let ws = FakeCloudWorkspace::new();
    let linux_dir = ws.plant_dropbox_standard();
    let info = json!({ "personal": { "path": linux_dir.to_string_lossy() } });
    ws.plant_dropbox_info_json(&info.to_string());

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "dropbox");
    assert_default_off_and_tier3(drv);
    if cfg!(target_os = "linux") {
        assert!(drive_has_root(drv, &linux_dir));
    }
}

#[tokio::test]
async fn t1_f3_dropbox_deduplicates_identical_roots() {
    let ws = FakeCloudWorkspace::new();
    let std_dir = ws.plant_dropbox_standard();
    let info = json!({ "personal": { "path": std_dir.to_string_lossy() } });
    ws.plant_dropbox_info_json(&info.to_string());

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "dropbox");
    assert_default_off_and_tier3(drv);

    let roots = drv["detected_roots"]
        .as_array()
        .expect("detected_roots array");
    let matches = roots
        .iter()
        .filter_map(|v| v.as_str())
        .filter(|s| paths_equivalent(s, &std_dir.to_string_lossy()))
        .count();
    assert!(
        matches <= 1,
        "Identical Dropbox root must be deduplicated in detected_roots: {:?}",
        roots
    );
}

// ============================================================================
// F4: iCloud Drive Cross-OS Discovery (5 tests)
// ============================================================================

#[tokio::test]
async fn t1_f4_icloud_win_standard_paths() {
    let ws = FakeCloudWorkspace::new();
    let icloud = ws.plant_icloud_win("iCloudDrive");
    ws.write_doc(&icloud, "icloud_note.txt", "TOKEN_F4_ICLOUD_WIN notes");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "icloud_drive");
    assert_eq!(drv["provider"].as_str(), Some("icloud_drive"));
    assert_default_off_and_tier3(drv);
    if cfg!(windows) {
        assert_eq!(drv["detected"].as_bool(), Some(true));
        assert!(drive_has_root(drv, &icloud));
    }
}

#[tokio::test]
async fn t1_f4_icloud_macos_mobile_documents() {
    let ws = FakeCloudWorkspace::new();
    let mob = ws.plant_icloud_macos_mobile_docs();
    ws.write_doc(&mob, "mob.md", "TOKEN_F4_MAC_MOBILE_DOCS");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "icloud_drive");
    assert_default_off_and_tier3(drv);
    if cfg!(target_os = "macos") {
        assert!(drive_has_root(drv, &mob));
    }
}

#[tokio::test]
async fn t1_f4_icloud_macos_cloudstorage() {
    let ws = FakeCloudWorkspace::new();
    let cs = ws.plant_icloud_macos_cloudstorage();
    ws.write_doc(&cs, "cs.md", "TOKEN_F4_MAC_CLOUDSTORAGE");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "icloud_drive");
    assert_default_off_and_tier3(drv);
    if cfg!(target_os = "macos") {
        assert!(drive_has_root(drv, &cs));
    }
}

#[tokio::test]
async fn t1_f4_icloud_linux_optional_mount() {
    let ws = FakeCloudWorkspace::new();
    let linux_icloud = ws.plant_icloud_win("iCloudDrive");
    ws.write_doc(&linux_icloud, "lin.txt", "TOKEN_F4_LINUX_ICLOUD");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "icloud_drive");
    assert_default_off_and_tier3(drv);
    let _ = daemon
        .enable_and_reindex_drive("icloud_drive", &linux_icloud, Some(3), 1)
        .await;
    let qr = daemon.query_local("TOKEN_F4_LINUX_ICLOUD").await;
    assert!(query_result_contains_token(&qr, "TOKEN_F4_LINUX_ICLOUD"));
}

#[tokio::test]
async fn t1_f4_icloud_default_off_and_tier3() {
    let ws = FakeCloudWorkspace::new();
    let icloud_spaced = ws.plant_icloud_win("iCloud Drive");
    ws.write_doc(&icloud_spaced, "spaced.txt", "TOKEN_F4_ICLOUD_SPACED");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "icloud_drive");
    assert_default_off_and_tier3(drv);
    if cfg!(windows) || cfg!(target_os = "linux") {
        assert_eq!(drv["detected"].as_bool(), Some(true));
        assert!(drive_has_root(drv, &icloud_spaced));
    }
}

// ============================================================================
// F5: Box Cross-OS Discovery (5 tests)
// ============================================================================

#[tokio::test]
async fn t1_f5_box_win_drive_and_sync() {
    let ws = FakeCloudWorkspace::new();
    let box_dir = ws.plant_box_win("Box");
    let _box_sync = ws.plant_box_win("Box Sync");
    ws.write_doc(&box_dir, "box_contract.md", "TOKEN_F5_BOX_WIN");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "box");
    assert_eq!(drv["provider"].as_str(), Some("box"));
    assert_default_off_and_tier3(drv);
    if cfg!(windows) {
        assert_eq!(drv["detected"].as_bool(), Some(true));
        assert!(drive_has_root(drv, &box_dir));
    }
}

#[tokio::test]
async fn t1_f5_box_macos_cloudstorage() {
    let ws = FakeCloudWorkspace::new();
    let mac_box = ws.plant_box_macos();
    ws.write_doc(&mac_box, "box_mac.txt", "TOKEN_F5_BOX_MAC");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "box");
    assert_default_off_and_tier3(drv);
    if cfg!(target_os = "macos") {
        assert!(drive_has_root(drv, &mac_box));
    }
}

#[tokio::test]
async fn t1_f5_box_linux_mount() {
    let ws = FakeCloudWorkspace::new();
    let lin_box = ws.plant_box_win("Box");
    ws.write_doc(&lin_box, "box_lin.txt", "TOKEN_F5_BOX_LINUX");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "box");
    assert_default_off_and_tier3(drv);
    let _ = daemon
        .enable_and_reindex_drive("box", &lin_box, Some(3), 1)
        .await;
    let qr = daemon.query_local("TOKEN_F5_BOX_LINUX").await;
    assert!(query_result_contains_token(&qr, "TOKEN_F5_BOX_LINUX"));
}

#[tokio::test]
async fn t1_f5_box_multi_profile_discovery() {
    let ws = FakeCloudWorkspace::new();
    let box_a = ws.plant_box_win("Box");
    let box_b = ws.plant_box_win("Box Sync");
    ws.write_doc(&box_a, "a.txt", "TOKEN_F5_MULTI_A");
    ws.write_doc(&box_b, "b.txt", "TOKEN_F5_MULTI_B");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "box");
    assert_default_off_and_tier3(drv);
    if cfg!(windows) {
        assert!(drive_has_root(drv, &box_a));
        assert!(drive_has_root(drv, &box_b));
    }
}

#[tokio::test]
async fn t1_f5_box_not_detected_when_absent() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "box");
    assert_default_off_and_tier3(drv);
    assert_eq!(drv["detected"].as_bool(), Some(false));
    assert_eq!(drv["mounted"].as_bool(), Some(false));
    assert!(drv["detected_roots"]
        .as_array()
        .expect("detected_roots")
        .is_empty());
}

// ============================================================================
// F6: Nextcloud Cross-OS Discovery (5 tests)
// ============================================================================

#[tokio::test]
async fn t1_f6_nextcloud_win_cfg_parse() {
    let ws = FakeCloudWorkspace::new();
    let custom_nc = ws.mkdir("NextcloudCustomSync");
    let cfg = format!(
        "[Accounts]\n0\\Folders\\1\\localPath={}\n",
        custom_nc.to_string_lossy().replace('\\', "/")
    );
    ws.plant_nextcloud_cfg(&cfg);

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "nextcloud");
    assert_eq!(drv["provider"].as_str(), Some("nextcloud"));
    assert_default_off_and_tier3(drv);
    if cfg!(windows) {
        assert!(drive_has_root(drv, &custom_nc));
    }
}

#[tokio::test]
async fn t1_f6_nextcloud_win_fallback_dir() {
    let ws = FakeCloudWorkspace::new();
    let nc = ws.plant_nextcloud_home();
    ws.write_doc(&nc, "nc_home.md", "TOKEN_F6_NC_HOME");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "nextcloud");
    assert_default_off_and_tier3(drv);
    if cfg!(windows) {
        assert!(drive_has_root(drv, &nc));
    }
}

#[tokio::test]
async fn t1_f6_nextcloud_macos_prefs_and_cloudstorage() {
    let ws = FakeCloudWorkspace::new();
    let mac_nc = ws.plant_nextcloud_macos_cloudstorage("Work");
    let cfg = format!(
        "[Accounts]\n0\\Folders\\1\\localPath={}\n",
        mac_nc.display()
    );
    ws.plant_nextcloud_cfg(&cfg);

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "nextcloud");
    assert_default_off_and_tier3(drv);
    if cfg!(target_os = "macos") {
        assert!(drive_has_root(drv, &mac_nc));
    }
}

#[tokio::test]
async fn t1_f6_nextcloud_linux_config_and_home() {
    let ws = FakeCloudWorkspace::new();
    let lin_nc = ws.plant_nextcloud_home();
    let cfg = format!(
        "[Accounts]\n0\\Folders\\1\\localPath={}\n",
        lin_nc.display()
    );
    ws.plant_nextcloud_cfg(&cfg);

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "nextcloud");
    assert_default_off_and_tier3(drv);
    if cfg!(target_os = "linux") {
        assert!(drive_has_root(drv, &lin_nc));
    }
}

#[tokio::test]
async fn t1_f6_nextcloud_multi_folder_cfg() {
    let ws = FakeCloudWorkspace::new();
    let nc_a = ws.mkdir("NextcloudA");
    let nc_b = ws.mkdir("NextcloudB");
    let cfg = format!(
        "[Accounts]\n0\\Folders\\1\\localPath={}\n0\\Folders\\2\\localPath={}\n",
        nc_a.to_string_lossy().replace('\\', "/"),
        nc_b.to_string_lossy().replace('\\', "/")
    );
    ws.plant_nextcloud_cfg(&cfg);

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "nextcloud");
    assert_default_off_and_tier3(drv);
    assert!(drive_has_root(drv, &nc_a));
    assert!(drive_has_root(drv, &nc_b));
}

// ============================================================================
// F7: Proton Drive & pCloud Cross-OS Discovery (5 tests)
// ============================================================================

#[tokio::test]
async fn t1_f7_proton_drive_win() {
    let ws = FakeCloudWorkspace::new();
    let proton = ws.plant_proton_drive_win();
    ws.write_doc(&proton.join("My files"), "proton.md", "TOKEN_F7_PROTON_WIN");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "proton_drive");
    assert_eq!(drv["provider"].as_str(), Some("proton_drive"));
    assert_default_off_and_tier3(drv);
    if cfg!(windows) {
        assert_eq!(drv["detected"].as_bool(), Some(true));
        assert!(drive_has_root(drv, &proton));
    }
}

#[tokio::test]
async fn t1_f7_proton_drive_macos_linux() {
    let ws = FakeCloudWorkspace::new();
    let mac_proton = ws.plant_proton_drive_macos("alice@proton.me");
    let lin_proton = ws.plant_proton_drive_linux();
    ws.write_doc(&lin_proton, "lin_proton.txt", "TOKEN_F7_PROTON_LIN");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "proton_drive");
    assert_default_off_and_tier3(drv);
    if cfg!(target_os = "macos") {
        assert!(drive_has_root(drv, &mac_proton));
    }
    if cfg!(target_os = "linux") {
        assert!(drive_has_root(drv, &lin_proton));
    }
    let _ = daemon
        .enable_and_reindex_drive("proton_drive", &lin_proton, Some(3), 1)
        .await;
    let qr = daemon.query_local("TOKEN_F7_PROTON_LIN").await;
    assert!(query_result_contains_token(&qr, "TOKEN_F7_PROTON_LIN"));
}

#[tokio::test]
async fn t1_f7_pcloud_win_drive_and_folder() {
    let ws = FakeCloudWorkspace::new();
    let pc = ws.plant_pcloud_win("pCloudDrive");
    ws.write_doc(&pc, "pcloud_win.txt", "TOKEN_F7_PCLOUD_WIN");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "pcloud");
    assert_eq!(drv["provider"].as_str(), Some("pcloud"));
    assert_default_off_and_tier3(drv);
    if cfg!(windows) {
        assert_eq!(drv["detected"].as_bool(), Some(true));
        assert!(drive_has_root(drv, &pc));
    }
}

#[tokio::test]
async fn t1_f7_pcloud_macos_cloudstorage() {
    let ws = FakeCloudWorkspace::new();
    let mac_pc = ws.plant_pcloud_macos();
    ws.write_doc(&mac_pc, "mac_pc.txt", "TOKEN_F7_PCLOUD_MAC");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "pcloud");
    assert_default_off_and_tier3(drv);
    if cfg!(target_os = "macos") {
        assert!(drive_has_root(drv, &mac_pc));
    }
}

#[tokio::test]
async fn t1_f7_pcloud_linux_mount() {
    let ws = FakeCloudWorkspace::new();
    let lin_pc = ws.plant_pcloud_linux();
    ws.write_doc(&lin_pc, "lin_pc.txt", "TOKEN_F7_PCLOUD_LINUX");

    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drv = find_drive(&payload, "pcloud");
    assert_default_off_and_tier3(drv);
    let _ = daemon
        .enable_and_reindex_drive("pcloud", &lin_pc, Some(3), 1)
        .await;
    let qr = daemon.query_local("TOKEN_F7_PCLOUD_LINUX").await;
    assert!(query_result_contains_token(&qr, "TOKEN_F7_PCLOUD_LINUX"));
}

// ============================================================================
// F8: Shared Cloud Drive Types, Defaults & Fail-Closed Validators (5 tests)
// ============================================================================

#[tokio::test]
async fn t1_f8_provider_serde_snake_case_roundtrip() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;
    let drives = payload["drives"].as_array().expect("drives array");
    let providers: Vec<&str> = drives
        .iter()
        .filter_map(|d| d["provider"].as_str())
        .collect();

    for expected in [
        "google_drive",
        "onedrive",
        "dropbox",
        "icloud_drive",
        "box",
        "nextcloud",
        "proton_drive",
        "pcloud",
    ] {
        assert!(
            providers.contains(&expected),
            "Missing snake_case provider '{}' in {:?}",
            expected,
            providers
        );
    }
}

#[tokio::test]
async fn t1_f8_settings_defaults_fail_closed() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;
    let payload = daemon.get_cloud_drives().await;

    assert_eq!(
        payload["placeholder_mode"].as_str(),
        Some("locally_synced_only")
    );
    assert_eq!(payload["hydration_max_file_size_mb"].as_u64(), Some(25));
    for d in payload["drives"].as_array().expect("drives") {
        assert_default_off_and_tier3(d);
    }

    // Trigger settings persistence and inspect real <data_dir>/settings.json on disk
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "set_hydration",
            "placeholder_mode": "locally_synced_only",
            "hydration_max_file_size_mb": 25
        }))
        .await;
    let settings = ws.read_settings_json();
    assert_eq!(
        settings
            .pointer("/cloud_drives/placeholder_mode")
            .and_then(|v| v.as_str()),
        Some("locally_synced_only")
    );
    assert_eq!(
        settings
            .pointer("/cloud_drives/hydration_max_file_size_mb")
            .and_then(|v| v.as_u64()),
        Some(25)
    );
}

#[tokio::test]
async fn t1_f8_access_tier_validation() {
    for valid in 0u8..=3 {
        assert!(
            AccessTier::from_u8(valid).is_ok(),
            "AccessTier::from_u8({}) must succeed",
            valid
        );
    }
    for invalid in 4u8..=255 {
        assert!(
            AccessTier::from_u8(invalid).is_err(),
            "AccessTier::from_u8({}) must fail closed",
            invalid
        );
    }

    let ws = FakeCloudWorkspace::new();
    let box_dir = ws.plant_box_win("Box");
    let daemon = DaemonTestProcess::start(&ws).await;
    let (status, _, _) = daemon
        .post_json_raw(
            "/api/cloud-drives/config",
            &json!({
                "action": "toggle_drive",
                "id": "box",
                "enabled": true,
                "access_tier": 4,
                "root_path": box_dir.to_string_lossy()
            }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let after = daemon.get_cloud_drives().await;
    assert_eq!(find_drive(&after, "box")["enabled"].as_bool(), Some(false));
}

#[tokio::test]
async fn t1_f8_path_validator_accepts_valid_roots() {
    let ws = FakeCloudWorkspace::new();
    let valid_sub = ws.mkdir("ValidCloudFolder/SubA");
    let daemon = DaemonTestProcess::start(&ws).await;

    let updated = daemon
        .post_cloud_drives_config(&json!({
            "action": "add_folder",
            "id": "dropbox",
            "path": valid_sub.to_string_lossy()
        }))
        .await;

    let drv = find_drive(&updated, "dropbox");
    let custom = drv["custom_paths"].as_array().expect("custom_paths array");
    assert!(
        custom
            .iter()
            .filter_map(|v| v.as_str())
            .any(|p| paths_equivalent(p, &valid_sub.to_string_lossy())),
        "Expected valid folder {} in custom_paths: {:?}",
        valid_sub.display(),
        custom
    );
}

#[tokio::test]
async fn t1_f8_path_validator_rejects_traversal_unc_ads() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;

    let bad_paths = [
        r"C:\Users\Alice\Dropbox\..\..\Windows\System32",
        r"C:\cloud\%2e%2e\secret",
        "C:\\cloud\\file\0.txt",
        r"\\attacker-server\share\cloud",
        r"C:\cloud\file.txt:hidden_stream",
    ];

    for bad in bad_paths {
        let (status, _, body) = daemon
            .post_json_raw(
                "/api/cloud-drives/config",
                &json!({
                    "action": "add_folder",
                    "id": "dropbox",
                    "path": bad
                }),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "Invalid path '{}' must be rejected with 400 Bad Request, got {} ({})",
            bad,
            status,
            body
        );
    }

    let after = daemon.get_cloud_drives().await;
    let custom = find_drive(&after, "dropbox")["custom_paths"]
        .as_array()
        .expect("custom_paths");
    assert!(
        custom.is_empty(),
        "Rejected invalid paths must never persist into custom_paths: {:?}",
        custom
    );
}
