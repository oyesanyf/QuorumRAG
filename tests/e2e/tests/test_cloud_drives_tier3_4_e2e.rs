//! Tier 3 & Tier 4 E2E Tests: 20 Pairwise Combination Tests & 10 Real-World Scenarios.
//!
//! All 30 tests exercise the real `quorumrag` binary, real HTTP JSON API, real storage/AtlasKV
//! persistence across restarts, real DLP/Mesh isolation, real Win32 placeholder attributes,
//! and live served WebUI assets.

use quorum_e2e::cloud_drives_harness::{
    atlaskv_result_contains_token, find_drive, paths_equivalent, query_result_contains_token,
    set_windows_offline_attribute, DaemonTestProcess, ExclusiveFileLockGuard, FakeCloudWorkspace,
};
use quorum_ingest::IngestConfig;
use reqwest::StatusCode;
use serde_json::json;
use std::sync::Arc;
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
// TIER 3: 20 PAIRWISE CROSS-FEATURE COMBINATION TESTS
// ============================================================================

#[tokio::test]
async fn t3_pair_01_enable_ingest_dlp_query_disable_purge() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let aws_sample_p01 = concat!("AKIA", "IOSFODNN7EXAMPLE9999");
    ws.write_doc(
        &dropbox,
        "audit_note.md",
        &format!("TOKEN_T3_P01_CLEAN secret AWS={aws_sample_p01} architecture"),
    );

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;

    let qr = daemon.query_local("TOKEN_T3_P01_CLEAN").await;
    assert!(query_result_contains_token(&qr, "TOKEN_T3_P01_CLEAN"));
    assert!(!query_result_contains_token(&qr, aws_sample_p01));

    let epoch_before = daemon.get_json("/api/settings").await["runtime"]["index_epoch"]
        .as_u64()
        .unwrap();
    let disable = daemon
        .post_cloud_drives_config(
            &json!({ "action": "toggle_drive", "id": "dropbox", "enabled": false }),
        )
        .await;
    assert!(disable["purged_files"].as_u64().unwrap_or(0) >= 1);

    let epoch_after = daemon.get_json("/api/settings").await["runtime"]["index_epoch"]
        .as_u64()
        .unwrap();
    assert!(epoch_after > epoch_before);
    assert!(!query_result_contains_token(
        &daemon.query_local("TOKEN_T3_P01_CLEAN").await,
        "TOKEN_T3_P01_CLEAN"
    ));
}

#[tokio::test]
async fn t3_pair_02_cloud_drive_vs_wildcard_mesh_isolation() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let cloud_doc = ws.write_doc(&dropbox, "cloud.txt", "TOKEN_T3_P02_CLOUD");
    let local_doc = ws.write_doc(&ws.watch_dir, "local.txt", "TOKEN_T3_P02_LOCAL");

    let daemon = DaemonTestProcess::start(&ws).await;
    let mesh = daemon.get_json("/api/mesh/status").await;
    assert_eq!(mesh["require_explicit_folder_share"].as_bool(), Some(false));

    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;

    let dlp_local = daemon
        .post_json(
            "/api/dlp/test",
            &json!({ "text": "clean local text", "file_path": local_doc.to_string_lossy() }),
        )
        .await;
    assert_eq!(dlp_local["folder_shared_with_mesh"].as_bool(), Some(true));

    let dlp_cloud = daemon
        .post_json(
            "/api/dlp/test",
            &json!({ "text": "clean cloud text", "file_path": cloud_doc.to_string_lossy() }),
        )
        .await;
    assert_eq!(dlp_cloud["folder_shared_with_mesh"].as_bool(), Some(false));
    assert_eq!(dlp_cloud["effective_mesh_allowed"].as_bool(), Some(false));
}

#[tokio::test]
async fn t3_pair_03_explicit_shared_folder_tier_lt3_vs_tier3() {
    let ws = FakeCloudWorkspace::new();
    let gdrive = ws.plant_google_drive_win_mirror();
    let sub = gdrive.join("TeamDocs");
    let doc = ws.write_doc(&sub, "team.txt", "TOKEN_T3_P03_TEAM SSN 123-45-6789");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("google_drive", &gdrive, Some(3), 1)
        .await;

    let _ = daemon
        .post_json(
            "/api/mesh/shared-folders",
            &json!({
                "action": "add",
                "path": sub.to_string_lossy(),
                "enabled": true,
                "access_tier": 3
            }),
        )
        .await;
    let blocked = daemon
        .post_json(
            "/api/dlp/test",
            &json!({ "text": "SSN 123-45-6789", "file_path": doc.to_string_lossy() }),
        )
        .await;
    assert_eq!(blocked["folder_shared_with_mesh"].as_bool(), Some(false));

    let _ = daemon
        .post_json(
            "/api/mesh/shared-folders",
            &json!({
                "action": "update_tier",
                "path": sub.to_string_lossy(),
                "access_tier": 1
            }),
        )
        .await;
    // Drive is still Tier 3 => max(1, 3) = 3 => still blocked until drive tier is also < 3
    let still_blocked = daemon
        .post_json(
            "/api/dlp/test",
            &json!({ "text": "SSN 123-45-6789", "file_path": doc.to_string_lossy() }),
        )
        .await;
    assert_eq!(still_blocked["folder_shared_with_mesh"].as_bool(), Some(false));

    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "set_tier",
            "id": "google_drive",
            "access_tier": 1
        }))
        .await;

    let allowed = daemon
        .post_json(
            "/api/dlp/test",
            &json!({ "text": "team share SSN 123-45-6789 end", "file_path": doc.to_string_lossy() }),
        )
        .await;
    assert_eq!(allowed["folder_shared_with_mesh"].as_bool(), Some(true));
    let scrubbed = allowed["inspection"]["scrubbed_text"]
        .as_str()
        .expect("inspection.scrubbed_text must be a string");
    assert!(
        !scrubbed.trim().is_empty(),
        "scrubbed_text must be non-empty: {}",
        allowed
    );
    assert!(
        scrubbed.contains("team share") && scrubbed.contains("end"),
        "Redact mode must preserve non-secret context: {}",
        allowed
    );
    assert!(!scrubbed.contains("123-45-6789"));
}

#[tokio::test]
async fn t3_pair_04_locally_synced_only_mixed_real_and_stub() {
    let ws = FakeCloudWorkspace::new();
    let box_dir = ws.plant_box_win("Box");
    ws.write_doc(&box_dir, "real.md", "TOKEN_T3_P04_REAL synced");
    let _lock = if cfg!(windows) {
        let stub = ws.write_doc(&box_dir, "stub.md", "TOKEN_T3_P04_STUB offline");
        set_windows_offline_attribute(&stub).expect("set offline");
        Some(ExclusiveFileLockGuard::lock(&stub).expect("lock"))
    } else {
        None
    };

    let daemon = DaemonTestProcess::start(&ws).await;
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
        &daemon.query_local("TOKEN_T3_P04_REAL").await,
        "TOKEN_T3_P04_REAL"
    ));
    if cfg!(windows) {
        assert!(!query_result_contains_token(
            &daemon.query_local("TOKEN_T3_P04_STUB").await,
            "TOKEN_T3_P04_STUB"
        ));
    }
}

#[tokio::test]
async fn t3_pair_05_hydrate_toggle_and_size_cap() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let small = ws.write_sized_file(&dropbox, "one_mb.txt", 1024 * 1024, "TOKEN_T3_P05_1MB");
    if cfg!(windows) {
        set_windows_offline_attribute(&small).expect("offline small");
    }
    let _lock = if cfg!(windows) {
        let large = ws.write_sized_file(
            &dropbox,
            "three_mb.txt",
            3 * 1024 * 1024,
            "TOKEN_T3_P05_3MB",
        );
        set_windows_offline_attribute(&large).expect("offline large");
        Some(ExclusiveFileLockGuard::lock(&large).expect("lock large"))
    } else {
        None
    };

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "set_hydration",
            "placeholder_mode": "hydrate_on_demand",
            "hydration_max_file_size_mb": 2
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
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T3_P05_1MB").await,
        "TOKEN_T3_P05_1MB"
    ));
    if cfg!(windows) {
        assert!(!query_result_contains_token(
            &daemon.query_local("TOKEN_T3_P05_3MB").await,
            "TOKEN_T3_P05_3MB"
        ));
    }
}

#[tokio::test]
async fn t3_pair_06_mode_switch_locally_synced_to_hydrate_and_reindex() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "anchor.txt", "TOKEN_T3_P06_ANCHOR");
    let stub = ws.write_sized_file(
        &dropbox,
        "stub_500kb.txt",
        500 * 1024,
        "TOKEN_T3_P06_HYDRATED",
    );
    if cfg!(windows) {
        set_windows_offline_attribute(&stub).expect("set offline");
    }

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    daemon
        .wait_for_reindex_settled(Duration::from_secs(10))
        .await;
    if cfg!(windows) {
        assert!(!query_result_contains_token(
            &daemon.query_local("TOKEN_T3_P06_HYDRATED").await,
            "TOKEN_T3_P06_HYDRATED"
        ));
    }

    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "set_hydration",
            "placeholder_mode": "hydrate_on_demand",
            "hydration_max_file_size_mb": 5
        }))
        .await;
    let _ = daemon.post_cloud_drives_reindex("dropbox").await;
    let _ = daemon
        .wait_for_indexed("dropbox", 2, Duration::from_secs(30))
        .await;
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T3_P06_HYDRATED").await,
        "TOKEN_T3_P06_HYDRATED"
    ));
}

#[tokio::test]
async fn t3_pair_07_webui_contract_to_daemon_http_roundtrip() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "ui_api.txt", "TOKEN_T3_P07_UI_API");
    let daemon = DaemonTestProcess::start(&ws).await;

    let (_, _, js) = daemon.get_text("/assets/app.js").await;
    for ep in [
        "/api/cloud-drives",
        "/api/cloud-drives/config",
        "/api/cloud-drives/reindex",
    ] {
        assert!(js.contains(ep), "Live app.js missing {}", ep);
    }

    let initial = daemon.get_cloud_drives().await;
    assert!(find_drive(&initial, "dropbox")["enabled"].as_bool() == Some(false));
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": true,
            "root_path": dropbox.to_string_lossy()
        }))
        .await;
    let reidx = daemon.post_cloud_drives_reindex("dropbox").await;
    assert_eq!(reidx["ok"].as_bool(), Some(true));
}

#[tokio::test]
async fn t3_pair_08_localsystem_multi_profile_and_virtual_drive_coexistence() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let box_dir = ws.plant_box_win("Box");
    ws.write_doc(&dropbox, "db.txt", "TOKEN_T3_P08_DB");
    ws.write_doc(&box_dir, "bx.txt", "TOKEN_T3_P08_BOX");

    let daemon = DaemonTestProcess::start(&ws).await;
    let cd = daemon.get_cloud_drives().await;
    assert!(cd["running_as_local_system"].is_boolean());
    assert!(cd.get("virtual_drive_guidance").is_some());

    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    let _ = daemon
        .enable_and_reindex_drive("box", &box_dir, Some(3), 1)
        .await;
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T3_P08_DB").await,
        "TOKEN_T3_P08_DB"
    ));
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T3_P08_BOX").await,
        "TOKEN_T3_P08_BOX"
    ));
}

#[tokio::test]
async fn t3_pair_09_onedrive_decoupled_from_doc_roots_and_main_shared_folders() {
    for r in IngestConfig::discover_user_document_roots() {
        assert!(!r
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains("onedrive"));
    }
    let ws = FakeCloudWorkspace::new();
    let od = ws.plant_onedrive_personal();
    let _od_biz = ws.plant_onedrive_business("Contoso");
    ws.write_doc(&od, "od_private.txt", "TOKEN_T3_P09_OD_LOCAL");
    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("onedrive_personal", &od, Some(3), 1)
        .await;
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T3_P09_OD_LOCAL").await,
        "TOKEN_T3_P09_OD_LOCAL"
    ));
    let mesh = daemon.get_json("/api/mesh/status").await;
    for sf in mesh["shared_folders"].as_array().expect("shared_folders") {
        let p = sf["path"].as_str().unwrap_or("").to_ascii_lowercase();
        assert!(!p.contains("onedrive"));
    }
}

#[tokio::test]
async fn t3_pair_10_custom_folder_add_reject_invalid_and_remove_purge() {
    let ws = FakeCloudWorkspace::new();
    let sub = ws.mkdir("CustomSyncSub");
    ws.write_doc(&sub, "sub.txt", "TOKEN_T3_P10_CUSTOM");
    let daemon = DaemonTestProcess::start(&ws).await;

    let (bad_st, _, _) = daemon
        .post_json_raw(
            "/api/cloud-drives/config",
            &json!({ "action": "add_folder", "id": "dropbox", "path": r"C:\bad\..\path" }),
        )
        .await;
    assert_eq!(bad_st, StatusCode::BAD_REQUEST);

    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "add_folder",
            "id": "dropbox",
            "path": sub.to_string_lossy()
        }))
        .await;
    let _ = daemon
        .post_cloud_drives_config(
            &json!({ "action": "toggle_drive", "id": "dropbox", "enabled": true }),
        )
        .await;
    let _ = daemon.post_cloud_drives_reindex("dropbox").await;
    let _ = daemon
        .wait_for_indexed("dropbox", 1, Duration::from_secs(30))
        .await;
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T3_P10_CUSTOM").await,
        "TOKEN_T3_P10_CUSTOM"
    ));

    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "remove_folder",
            "id": "dropbox",
            "path": sub.to_string_lossy()
        }))
        .await;
    assert!(!query_result_contains_token(
        &daemon.query_local("TOKEN_T3_P10_CUSTOM").await,
        "TOKEN_T3_P10_CUSTOM"
    ));
}

#[tokio::test]
async fn t3_pair_11_tier_upgrade_cross_store_sync_and_cache_clear() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(
        &dropbox,
        "sync_tier.txt",
        "TOKEN_T3_P11_TIER_SYNC Alice Chen directs Atlas Meridian.",
    );

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;

    // Warm QueryCoordinator cache (`bypass_cache: false`) while at Tier 3
    assert!(query_result_contains_token(
        &daemon.query_local_cached("TOKEN_T3_P11_TIER_SYNC").await,
        "TOKEN_T3_P11_TIER_SYNC"
    ));
    // At Tier 3, AtlasKV query with max_tier=0 must exclude Tier 3 triples
    let akv_tier0_before = daemon.query_atlaskv("Atlas Meridian Alice Chen", 0).await;
    assert!(!atlaskv_result_contains_token(
        &akv_tier0_before,
        "sync_tier.txt"
    ));

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
    // After tier upgrade -> 0, AtlasKV query at max_tier=0 must now see the synced triple
    let akv_tier0_after = daemon.query_atlaskv("Atlas Meridian Alice Chen", 0).await;
    assert!(
        atlaskv_result_contains_token(&akv_tier0_after, "sync_tier.txt")
            || atlaskv_result_contains_token(&akv_tier0_after, "Meridian")
            || atlaskv_result_contains_token(&akv_tier0_after, "Alice"),
        "Tier upgrade 3 -> 0 must sync AtlasKV access_tier: {}",
        akv_tier0_after
    );
    assert!(query_result_contains_token(
        &daemon.query_local_cached("TOKEN_T3_P11_TIER_SYNC").await,
        "TOKEN_T3_P11_TIER_SYNC"
    ));

    // Disable purge must invalidate QueryCoordinator cache (`bypass_cache: false`)
    let _ = daemon
        .post_cloud_drives_config(
            &json!({ "action": "toggle_drive", "id": "dropbox", "enabled": false }),
        )
        .await;
    assert!(!query_result_contains_token(
        &daemon.query_local_cached("TOKEN_T3_P11_TIER_SYNC").await,
        "TOKEN_T3_P11_TIER_SYNC"
    ));
}

#[tokio::test]
async fn t3_pair_12_dlp_block_mode_prevents_secret_ingest() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(
        &dropbox,
        "secret_block.txt",
        "TOKEN_T3_P12_BLOCKED_DOC Patient SSN 123-45-6789 confidential",
    );
    ws.write_doc(&dropbox, "clean.txt", "TOKEN_T3_P12_CLEAN_DOC architecture");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .post_json(
            "/api/dlp/policy",
            &json!({ "enabled": true, "mode": "Block" }),
        )
        .await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    daemon
        .wait_for_reindex_settled(Duration::from_secs(10))
        .await;

    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T3_P12_CLEAN_DOC").await,
        "TOKEN_T3_P12_CLEAN_DOC"
    ));
    assert!(!query_result_contains_token(
        &daemon.query_local("TOKEN_T3_P12_BLOCKED_DOC").await,
        "TOKEN_T3_P12_BLOCKED_DOC"
    ));
}

#[tokio::test]
async fn t3_pair_13_l2_dedup_shared_chunk_across_two_drives_partial_disable() {
    let ws = FakeCloudWorkspace::new();
    let gdrive = ws.plant_google_drive_win_mirror();
    let dropbox = ws.plant_dropbox_standard();
    let shared_body =
        "TOKEN_T3_P13_SHARED_CONTENT identical cryptographic knowledge paragraph across providers.";
    ws.write_doc(&gdrive, "copy_g.txt", shared_body);
    ws.write_doc(&dropbox, "copy_d.txt", shared_body);

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("google_drive", &gdrive, Some(3), 1)
        .await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;

    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "google_drive",
            "enabled": false
        }))
        .await;

    let qr = daemon.query_local("TOKEN_T3_P13_SHARED_CONTENT").await;
    assert!(
        query_result_contains_token(&qr, "TOKEN_T3_P13_SHARED_CONTENT"),
        "Disabling Google Drive must preserve identical chunk still owned by enabled Dropbox: {}",
        qr
    );
}

#[tokio::test]
async fn t3_pair_14_onedrive_personal_vs_business_independent_lifecycle() {
    let ws = FakeCloudWorkspace::new();
    let personal = ws.plant_onedrive_personal();
    let business = ws.plant_onedrive_business("Acme");
    ws.write_doc(&personal, "p.txt", "TOKEN_T3_P14_PERSONAL");
    ws.write_doc(&business, "b.txt", "TOKEN_T3_P14_BUSINESS");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("onedrive_personal", &personal, Some(3), 1)
        .await;
    let _ = daemon
        .enable_and_reindex_drive("onedrive_business", &business, Some(3), 1)
        .await;

    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "onedrive_personal",
            "enabled": false
        }))
        .await;

    assert!(!query_result_contains_token(
        &daemon.query_local("TOKEN_T3_P14_PERSONAL").await,
        "TOKEN_T3_P14_PERSONAL"
    ));
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T3_P14_BUSINESS").await,
        "TOKEN_T3_P14_BUSINESS"
    ));
}

#[tokio::test]
async fn t3_pair_15_persistence_across_storage_and_settings_reopen() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "persist.md", "TOKEN_T3_P15_PERSISTENCE durable");

    let daemon1 = DaemonTestProcess::start(&ws).await;
    let _ = daemon1
        .post_cloud_drives_config(&json!({
            "action": "set_hydration",
            "placeholder_mode": "hydrate_on_demand",
            "hydration_max_file_size_mb": 10
        }))
        .await;
    let _ = daemon1
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    daemon1.shutdown().await;

    let daemon2 = DaemonTestProcess::start(&ws).await;
    let cd = daemon2.get_cloud_drives().await;
    assert_eq!(cd["placeholder_mode"].as_str(), Some("hydrate_on_demand"));
    assert_eq!(cd["hydration_max_file_size_mb"].as_u64(), Some(10));
    assert_eq!(find_drive(&cd, "dropbox")["enabled"].as_bool(), Some(true));
    assert!(query_result_contains_token(
        &daemon2.query_local("TOKEN_T3_P15_PERSISTENCE").await,
        "TOKEN_T3_P15_PERSISTENCE"
    ));
}

#[tokio::test]
async fn t3_pair_16_concurrent_multi_drive_crawl_and_query() {
    let ws = FakeCloudWorkspace::new();
    let d1 = ws.plant_dropbox_standard();
    let d2 = ws.plant_box_win("Box");
    let d3 = ws.plant_nextcloud_home();
    for i in 0..8 {
        ws.write_doc(&d1, &format!("d{i}.txt"), &format!("TOKEN_T3_P16_DB_{i}"));
        ws.write_doc(&d2, &format!("b{i}.txt"), &format!("TOKEN_T3_P16_BX_{i}"));
        ws.write_doc(&d3, &format!("n{i}.txt"), &format!("TOKEN_T3_P16_NC_{i}"));
    }

    let daemon = Arc::new(DaemonTestProcess::start(&ws).await);
    let _ = tokio::join!(
        daemon.enable_and_reindex_drive("dropbox", &d1, Some(3), 8),
        daemon.enable_and_reindex_drive("box", &d2, Some(3), 8),
        daemon.enable_and_reindex_drive("nextcloud", &d3, Some(3), 8),
    );

    let (q1, q2, q3) = tokio::join!(
        daemon.query_local("TOKEN_T3_P16_DB_0"),
        daemon.query_local("TOKEN_T3_P16_BX_0"),
        daemon.query_local("TOKEN_T3_P16_NC_0"),
    );
    assert!(query_result_contains_token(&q1, "TOKEN_T3_P16_DB_0"));
    assert!(query_result_contains_token(&q2, "TOKEN_T3_P16_BX_0"));
    assert!(query_result_contains_token(&q3, "TOKEN_T3_P16_NC_0"));
}

#[tokio::test]
async fn t3_pair_17_media_endpoint_tier_and_traversal_gate() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let cloud_file = ws.write_doc(&dropbox, "cloud_tier3.txt", "TOKEN_T3_P17_CLOUD");
    let local_file = ws.write_doc(&ws.watch_dir, "local_tier0.txt", "TOKEN_T3_P17_LOCAL");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon.post_json("/api/reindex", &json!({})).await;
    daemon
        .wait_for_reindex_settled(Duration::from_secs(15))
        .await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;

    let cloud_resp = daemon
        .client
        .get(format!("{}/api/media", daemon.base_url))
        .query(&[("path", cloud_file.to_string_lossy().as_ref())])
        .send()
        .await
        .unwrap();
    assert_eq!(cloud_resp.status(), StatusCode::OK);
    assert!(cloud_resp
        .text()
        .await
        .unwrap()
        .contains("TOKEN_T3_P17_CLOUD"));

    let local_st = daemon
        .client
        .get(format!("{}/api/media", daemon.base_url))
        .query(&[("path", local_file.to_string_lossy().as_ref())])
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(local_st, StatusCode::OK);

    let trav_st = daemon
        .client
        .get(format!("{}/api/media", daemon.base_url))
        .query(&[("path", r"C:\safe\%2e%2e\secret.txt")])
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(trav_st, StatusCode::BAD_REQUEST);

    let artemis_st = daemon
        .client
        .get(format!("{}/api/media", daemon.base_url))
        .query(&[("path", "artemis://windows/eventlog/security")])
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(artemis_st, StatusCode::FORBIDDEN);

    let (dis_st, _, _) = daemon
        .post_json_raw(
            "/api/cloud-drives/config",
            &json!({ "action": "toggle_drive", "id": "dropbox", "enabled": false }),
        )
        .await;
    assert_eq!(dis_st, StatusCode::OK);

    let disabled_cloud_st = daemon
        .client
        .get(format!("{}/api/media", daemon.base_url))
        .query(&[("path", cloud_file.to_string_lossy().as_ref())])
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(disabled_cloud_st, StatusCode::FORBIDDEN);

    let local_after_st = daemon
        .client
        .get(format!("{}/api/media", daemon.base_url))
        .query(&[("path", local_file.to_string_lossy().as_ref())])
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(local_after_st, StatusCode::OK);
}

#[tokio::test]
async fn t3_pair_18_webui_storage_jump_and_search_to_cloud_drives() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;

    let (_, _, html) = daemon.get_text("/").await;
    let (_, _, js) = daemon.get_text("/assets/app.js").await;
    assert!(html.contains(r#"data-tab="cloud-drives""#));
    assert!(js.contains(r#"data-action="jump-tab" data-tab="cloud-drives""#));
    assert!(js.contains("tab === 'cloud-drives'"));
    assert!(js.contains("/api/cloud-drives"));
}

#[tokio::test]
async fn t3_pair_19_watcher_watch_and_unwatch_on_toggle() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "initial.txt", "TOKEN_T3_P19_INIT");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;

    let watched_on = daemon.get_json("/api/settings").await["runtime"]["watched_paths"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect::<Vec<_>>();
    assert!(watched_on
        .iter()
        .any(|p| paths_equivalent(p, &dropbox.to_string_lossy())));

    let _ = daemon
        .post_cloud_drives_config(
            &json!({ "action": "toggle_drive", "id": "dropbox", "enabled": false }),
        )
        .await;
    let watched_off = daemon.get_json("/api/settings").await["runtime"]["watched_paths"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect::<Vec<_>>();
    assert!(!watched_off
        .iter()
        .any(|p| paths_equivalent(p, &dropbox.to_string_lossy())));

    ws.write_doc(&dropbox, "after_disable.txt", "TOKEN_T3_P19_AFTER_DISABLE");
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(!query_result_contains_token(
        &daemon.query_local("TOKEN_T3_P19_AFTER_DISABLE").await,
        "TOKEN_T3_P19_AFTER_DISABLE"
    ));
}

#[tokio::test]
async fn t3_pair_20_atlaskv_local_tier3_vs_peer_isolation() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let doc = ws.write_doc(
        &dropbox,
        "kg_tier3.md",
        "TOKEN_T3_P20_ATLASKV Dr. Elena Vance directs Quantum Meridian Lab.",
    );

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;

    let akv_status = daemon.get_atlaskv_status().await;
    assert!(
        akv_status["stats"]["active_triples"].as_u64().unwrap_or(0) >= 1,
        "Expected AtlasKV active_triples >= 1: {}",
        akv_status
    );
    let akv_tier3 = daemon
        .query_atlaskv("Quantum Meridian Lab Elena Vance", 3)
        .await;
    assert!(
        atlaskv_result_contains_token(&akv_tier3, "kg_tier3.md")
            || atlaskv_result_contains_token(&akv_tier3, "Meridian")
            || atlaskv_result_contains_token(&akv_tier3, "Vance"),
        "Local AtlasKV query at max_tier=3 must retrieve Tier 3 triple: {}",
        akv_tier3
    );
    let akv_tier2 = daemon
        .query_atlaskv("Quantum Meridian Lab Elena Vance", 2)
        .await;
    assert!(
        !atlaskv_result_contains_token(&akv_tier2, "kg_tier3.md"),
        "AtlasKV query capped at max_tier=2 must exclude Tier 3 cloud triple: {}",
        akv_tier2
    );

    let qr = daemon
        .query_local("Quantum Meridian Lab TOKEN_T3_P20_ATLASKV")
        .await;
    assert!(query_result_contains_token(&qr, "TOKEN_T3_P20_ATLASKV"));

    let dlp = daemon
        .post_json(
            "/api/dlp/test",
            &json!({ "text": "Dr. Elena Vance", "file_path": doc.to_string_lossy() }),
        )
        .await;
    assert_eq!(dlp["folder_shared_with_mesh"].as_bool(), Some(false));
    assert_eq!(dlp["effective_mesh_allowed"].as_bool(), Some(false));
}

// ============================================================================
// TIER 4: 10 REAL-WORLD APPLICATION SCENARIOS
// ============================================================================

#[tokio::test]
async fn t4_s01_multi_provider_hybrid_workstation() {
    let ws = FakeCloudWorkspace::new();
    let gdrive = ws.plant_google_drive_win_mirror();
    let onedrive_biz = ws.plant_onedrive_business("Acme");
    let dropbox = ws.plant_dropbox_standard();

    ws.write_doc(&gdrive, "strategy.md", "TOKEN_T4_S01_GDRIVE roadmap");
    ws.write_doc(&onedrive_biz, "unopted.md", "TOKEN_T4_S01_ONEDRIVE_OFF");
    let aws_sample_s01 = concat!("AKIA", "IOSFODNN7EXAMPLE5678");
    let db_doc = ws.write_doc(
        &dropbox,
        "payroll.txt",
        &format!("TOKEN_T4_S01_DROPBOX AWS_KEY={aws_sample_s01}"),
    );
    let _lock = if cfg!(windows) {
        let stub = ws.write_doc(&dropbox, "archive_stub.bin.txt", "TOKEN_T4_S01_STUB");
        set_windows_offline_attribute(&stub).expect("set offline");
        Some(ExclusiveFileLockGuard::lock(&stub).expect("lock stub"))
    } else {
        None
    };

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("google_drive", &gdrive, Some(3), 1)
        .await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    daemon
        .wait_for_reindex_settled(Duration::from_secs(10))
        .await;

    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T4_S01_GDRIVE").await,
        "TOKEN_T4_S01_GDRIVE"
    ));
    let db_qr = daemon.query_local("TOKEN_T4_S01_DROPBOX").await;
    assert!(query_result_contains_token(&db_qr, "TOKEN_T4_S01_DROPBOX"));
    assert!(!query_result_contains_token(&db_qr, aws_sample_s01));
    if cfg!(windows) {
        assert!(!query_result_contains_token(
            &daemon.query_local("TOKEN_T4_S01_STUB").await,
            "TOKEN_T4_S01_STUB"
        ));
    }
    assert!(!query_result_contains_token(
        &daemon.query_local("TOKEN_T4_S01_ONEDRIVE_OFF").await,
        "TOKEN_T4_S01_ONEDRIVE_OFF"
    ));

    let dlp = daemon
        .post_json(
            "/api/dlp/test",
            &json!({ "text": "check", "file_path": db_doc.to_string_lossy() }),
        )
        .await;
    assert_eq!(dlp["folder_shared_with_mesh"].as_bool(), Some(false));
}

#[tokio::test]
async fn t4_s02_clean_offboarding_disable_purge() {
    let ws = FakeCloudWorkspace::new();
    let gdrive = ws.plant_google_drive_win_mirror();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&gdrive, "keep.md", "TOKEN_T4_S02_KEEP Google Drive Atlas");
    ws.write_doc(
        &dropbox,
        "offboard.md",
        "TOKEN_T4_S02_PURGE Dropbox Meridian",
    );

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("google_drive", &gdrive, Some(3), 1)
        .await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;

    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T4_S02_KEEP").await,
        "TOKEN_T4_S02_KEEP"
    ));
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T4_S02_PURGE").await,
        "TOKEN_T4_S02_PURGE"
    ));

    let off = daemon
        .post_cloud_drives_config(
            &json!({ "action": "toggle_drive", "id": "dropbox", "enabled": false }),
        )
        .await;
    assert!(off["purged_files"].as_u64().unwrap_or(0) >= 1);

    assert!(!query_result_contains_token(
        &daemon.query_local("TOKEN_T4_S02_PURGE").await,
        "TOKEN_T4_S02_PURGE"
    ));
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T4_S02_KEEP").await,
        "TOKEN_T4_S02_KEEP"
    ));
}

#[tokio::test]
async fn t4_s03_files_on_demand_upgrade_workflow() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "anchor.txt", "TOKEN_T4_S03_ANCHOR");
    let stub_2mb = ws.write_sized_file(
        &dropbox,
        "deck_2mb.txt",
        2 * 1024 * 1024,
        "TOKEN_T4_S03_2MB",
    );
    if cfg!(windows) {
        set_windows_offline_attribute(&stub_2mb).expect("offline 2mb");
    }
    let _lock = if cfg!(windows) {
        let stub_15mb = ws.write_sized_file(
            &dropbox,
            "dump_15mb.txt",
            15 * 1024 * 1024,
            "TOKEN_T4_S03_15MB",
        );
        set_windows_offline_attribute(&stub_15mb).expect("offline 15mb");
        Some(ExclusiveFileLockGuard::lock(&stub_15mb).expect("lock 15mb"))
    } else {
        None
    };

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    daemon
        .wait_for_reindex_settled(Duration::from_secs(10))
        .await;
    if cfg!(windows) {
        assert!(!query_result_contains_token(
            &daemon.query_local("TOKEN_T4_S03_2MB").await,
            "TOKEN_T4_S03_2MB"
        ));
    }

    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "set_hydration",
            "placeholder_mode": "hydrate_on_demand",
            "hydration_max_file_size_mb": 10
        }))
        .await;
    let _ = daemon.post_cloud_drives_reindex("dropbox").await;
    let _ = daemon
        .wait_for_indexed("dropbox", 2, Duration::from_secs(30))
        .await;
    daemon
        .wait_for_reindex_settled(Duration::from_secs(10))
        .await;

    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T4_S03_2MB").await,
        "TOKEN_T4_S03_2MB"
    ));
    if cfg!(windows) {
        assert!(!query_result_contains_token(
            &daemon.query_local("TOKEN_T4_S03_15MB").await,
            "TOKEN_T4_S03_15MB"
        ));
    }
}

#[tokio::test]
async fn t4_s04_localsystem_multi_profile_and_virtual_drive_guidance() {
    let ws = FakeCloudWorkspace::new();
    let db = ws.plant_dropbox_standard();
    let od = ws.plant_onedrive_personal();
    ws.write_doc(&db, "db.txt", "TOKEN_T4_S04_DB");
    ws.write_doc(&od, "od.txt", "TOKEN_T4_S04_OD");

    let daemon = DaemonTestProcess::start(&ws).await;
    let cd = daemon.get_cloud_drives().await;
    let running_as_local_system = cd["running_as_local_system"]
        .as_bool()
        .expect("running_as_local_system bool");
    if running_as_local_system {
        assert!(!cd["virtual_drive_guidance"]
            .as_str()
            .unwrap_or("")
            .trim()
            .is_empty());
    }
    for drv in cd["drives"].as_array().expect("drives") {
        if drv["session_only"].as_bool() == Some(true) {
            assert!(!drv["session_guidance"]
                .as_str()
                .unwrap_or("")
                .trim()
                .is_empty());
        }
        assert_eq!(drv["enabled"].as_bool(), Some(false));
    }

    // Folder-backed syncs remain readable & queryable even when virtual drives are session-scoped
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &db, Some(3), 1)
        .await;
    let _ = daemon
        .enable_and_reindex_drive("onedrive_personal", &od, Some(3), 1)
        .await;
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T4_S04_DB").await,
        "TOKEN_T4_S04_DB"
    ));
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T4_S04_OD").await,
        "TOKEN_T4_S04_OD"
    ));
}

#[tokio::test]
async fn t4_s05_full_daemon_http_lifecycle() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let extra = ws.mkdir("ExtraTeamFolder");
    ws.write_doc(&dropbox, "main.md", "TOKEN_T4_S05_MAIN");
    ws.write_doc(&extra, "extra.md", "TOKEN_T4_S05_EXTRA");

    let daemon = DaemonTestProcess::start(&ws).await;
    let initial = daemon.get_cloud_drives().await;
    assert_eq!(
        find_drive(&initial, "dropbox")["enabled"].as_bool(),
        Some(false)
    );

    let _ = daemon
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 1)
        .await;
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T4_S05_MAIN").await,
        "TOKEN_T4_S05_MAIN"
    ));

    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "add_folder",
            "id": "dropbox",
            "path": extra.to_string_lossy()
        }))
        .await;
    let _ = daemon.post_cloud_drives_reindex("dropbox").await;
    let _ = daemon
        .wait_for_indexed("dropbox", 2, Duration::from_secs(30))
        .await;
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T4_S05_EXTRA").await,
        "TOKEN_T4_S05_EXTRA"
    ));

    let _ = daemon
        .post_cloud_drives_config(
            &json!({ "action": "toggle_drive", "id": "dropbox", "enabled": false }),
        )
        .await;
    let after = daemon.get_cloud_drives().await;
    assert_eq!(
        find_drive(&after, "dropbox")["indexed_files"].as_u64(),
        Some(0)
    );
    assert!(!query_result_contains_token(
        &daemon.query_local("TOKEN_T4_S05_MAIN").await,
        "TOKEN_T4_S05_MAIN"
    ));
    assert!(!query_result_contains_token(
        &daemon.query_local("TOKEN_T4_S05_EXTRA").await,
        "TOKEN_T4_S05_EXTRA"
    ));
}

#[tokio::test]
async fn t4_s06_all_providers_default_off_discovery_audit() {
    let ws = FakeCloudWorkspace::new();
    let _ = ws.plant_google_drive_win_mirror();
    let _ = ws.plant_onedrive_personal();
    let _ = ws.plant_onedrive_business("Corp");
    let db = ws.plant_dropbox_standard();
    ws.plant_dropbox_info_json(
        &json!({ "personal": { "path": db.to_string_lossy() } }).to_string(),
    );
    let _ = ws.plant_icloud_win("iCloudDrive");
    let _ = ws.plant_icloud_macos_cloudstorage();
    let _ = ws.plant_box_win("Box");
    let nc = ws.plant_nextcloud_home();
    ws.plant_nextcloud_cfg(&format!(
        "[Accounts]\n0\\Folders\\1\\localPath={}\n",
        nc.display()
    ));
    let _ = ws.plant_proton_drive_win();
    let _ = ws.plant_pcloud_win("pCloudDrive");
    let _ = ws.plant_pcloud_macos();

    let daemon = DaemonTestProcess::start(&ws).await;
    let cd = daemon.get_cloud_drives().await;
    let drives = cd["drives"].as_array().expect("drives");
    assert!(drives.len() >= 9);
    for d in drives {
        assert_eq!(
            d["detected"].as_bool(),
            Some(true),
            "Provider {} must be detected when planted: {}",
            d["id"],
            d
        );
        assert_eq!(
            d["mounted"].as_bool(),
            Some(true),
            "Provider {} must be mounted when planted: {}",
            d["id"],
            d
        );
        assert_eq!(d["enabled"].as_bool(), Some(false));
        assert_eq!(d["access_tier"].as_u64(), Some(3));
        assert_eq!(d["shared_with_mesh"].as_bool(), Some(false));
        assert_eq!(d["indexed_files"].as_u64(), Some(0));
    }
}

#[tokio::test]
async fn t4_s07_explicit_mesh_opt_in_vs_local_isolation() {
    let ws = FakeCloudWorkspace::new();
    let od = ws.plant_onedrive_personal();
    let gdrive = ws.plant_google_drive_win_mirror();
    let team_docs = gdrive.join("Team Docs");
    let private_od = ws.write_doc(&od, "personal.txt", "private personal file");
    let shared_team = ws.write_doc(&team_docs, "shared.txt", "team doc SSN 123-45-6789 ok");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("onedrive_personal", &od, Some(3), 1)
        .await;
    let _ = daemon
        .enable_and_reindex_drive("google_drive", &gdrive, Some(3), 1)
        .await;
    let _ = daemon
        .post_json(
            "/api/mesh/shared-folders",
            &json!({
                "action": "add",
                "path": team_docs.to_string_lossy(),
                "enabled": true,
                "access_tier": 1
            }),
        )
        .await;

    let dlp_od = daemon
        .post_json(
            "/api/dlp/test",
            &json!({ "text": "private personal file", "file_path": private_od.to_string_lossy() }),
        )
        .await;
    assert_eq!(dlp_od["folder_shared_with_mesh"].as_bool(), Some(false));
    assert_eq!(dlp_od["effective_mesh_allowed"].as_bool(), Some(false));

    // Drive is still Tier 3 => even with shared_folders access_tier = 1, max(1, 3) = 3 => BLOCKED
    let dlp_team_tier3 = daemon
        .post_json(
            "/api/dlp/test",
            &json!({ "text": "team doc SSN 123-45-6789 ok", "file_path": shared_team.to_string_lossy() }),
        )
        .await;
    assert_eq!(
        dlp_team_tier3["folder_shared_with_mesh"].as_bool(),
        Some(false)
    );
    assert_eq!(
        dlp_team_tier3["effective_mesh_allowed"].as_bool(),
        Some(false)
    );

    // Lower Google Drive's access_tier < 3 as well => max(1, 1) = 1 < 3 => ALLOWED
    let _ = daemon
        .post_cloud_drives_config(&json!({
            "action": "set_tier",
            "id": "google_drive",
            "access_tier": 1
        }))
        .await;

    let dlp_team = daemon
        .post_json(
            "/api/dlp/test",
            &json!({ "text": "team doc SSN 123-45-6789 ok", "file_path": shared_team.to_string_lossy() }),
        )
        .await;
    assert_eq!(dlp_team["folder_shared_with_mesh"].as_bool(), Some(true));
    let scrubbed = dlp_team["inspection"]["scrubbed_text"]
        .as_str()
        .expect("inspection.scrubbed_text must be a string");
    assert!(!scrubbed.trim().is_empty());
    assert!(
        scrubbed.contains("team doc") && scrubbed.contains("ok"),
        "Redact mode must preserve non-secret context: {}",
        dlp_team
    );
    assert!(!scrubbed.contains("123-45-6789"));
}

#[tokio::test]
async fn t4_s08_webui_settings_and_security_audit() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;

    let (st_html, _, html) = daemon.get_text("/").await;
    let (st_js, _, js) = daemon.get_text("/assets/app.js").await;
    let (st_css, _, css) = daemon.get_text("/assets/styles.css").await;
    assert_eq!(st_html, StatusCode::OK);
    assert_eq!(st_js, StatusCode::OK);
    assert_eq!(st_css, StatusCode::OK);

    assert!(html.contains(r#"data-tab="cloud-drives""#));
    assert!(!html.contains("checked=false"));
    let nav_lower = extract_settings_nav_slice(&html).to_ascii_lowercase();
    for attr in [" onclick=", " onchange=", " oninput="] {
        assert!(!nav_lower.contains(attr));
    }

    assert!(js.contains(r#"data-action="jump-tab" data-tab="cloud-drives""#));
    assert!(js.contains("else if (tab === 'cloud-drives')"));
    let cd_slice = extract_cloud_drives_tab_slice(&js);
    assert!(cd_slice.contains("Hydrate cloud-only files on demand"));
    assert!(cd_slice.contains("Reindex Now"));
    assert!(cd_slice.contains("📁 Select Folder"));
    assert!(cd_slice.contains(r#"<input type="hidden""#));
    assert!(cd_slice.contains("Mounted"));
    assert!(cd_slice.contains("Not Detected"));
    assert!(cd_slice.contains("Indexed files"));
    assert!(cd_slice.contains("escapeHtml(drvLabel)"));
    assert!(cd_slice.contains("escapeHtml(drvId)"));
    assert!(cd_slice.contains("escapeHtml(cp)"));
    assert!(!cd_slice.contains("${JSON.stringify"));
    assert!(!html.to_ascii_lowercase().contains("pure rust"));
    assert!(!js.to_ascii_lowercase().contains("pure rust"));
    assert!(!css.to_ascii_lowercase().contains("pure rust"));
    assert!(!js.contains("checked=false"));
    let js_lower = js.to_ascii_lowercase();
    for attr in [" onclick=", " onchange=", " oninput="] {
        assert!(!js_lower.contains(attr));
    }
}

#[tokio::test]
async fn t4_s09_restart_persistence_and_dedup_fast_path() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let extra = ws.mkdir("ExtraPersistFolder");
    ws.write_doc(&dropbox, "doc1.md", "TOKEN_T4_S09_DOC1");
    ws.write_doc(&extra, "doc2.md", "TOKEN_T4_S09_DOC2");

    let daemon1 = DaemonTestProcess::start(&ws).await;
    let _ = daemon1
        .post_cloud_drives_config(&json!({
            "action": "set_hydration",
            "placeholder_mode": "hydrate_on_demand",
            "hydration_max_file_size_mb": 15
        }))
        .await;
    let _ = daemon1
        .post_cloud_drives_config(&json!({
            "action": "add_folder",
            "id": "dropbox",
            "path": extra.to_string_lossy()
        }))
        .await;
    let _ = daemon1
        .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 2)
        .await;
    daemon1.shutdown().await;

    let daemon2 = DaemonTestProcess::start(&ws).await;
    let cd = daemon2.get_cloud_drives().await;
    assert_eq!(cd["placeholder_mode"].as_str(), Some("hydrate_on_demand"));
    assert_eq!(cd["hydration_max_file_size_mb"].as_u64(), Some(15));
    assert_eq!(find_drive(&cd, "dropbox")["enabled"].as_bool(), Some(true));
    assert!(query_result_contains_token(
        &daemon2.query_local("TOKEN_T4_S09_DOC1").await,
        "TOKEN_T4_S09_DOC1"
    ));
    assert!(query_result_contains_token(
        &daemon2.query_local("TOKEN_T4_S09_DOC2").await,
        "TOKEN_T4_S09_DOC2"
    ));

    // Trigger reindex on unmodified files after restart -> Level-1 dedup fast path must skip re-embedding
    let _ = daemon2.post_cloud_drives_reindex("dropbox").await;
    daemon2
        .wait_for_reindex_settled(Duration::from_secs(15))
        .await;
    let reindex_status = daemon2.get_json("/api/reindex/status").await;
    assert!(
        reindex_status["files_skipped_unmodified"]
            .as_u64()
            .unwrap_or(0)
            >= 2,
        "Expected dedup fast-path files_skipped_unmodified >= 2 after restart: {}",
        reindex_status
    );
    assert_eq!(
        reindex_status["chunks_newly_embedded"].as_u64(),
        Some(0),
        "Unmodified files after restart must embed 0 new chunks: {}",
        reindex_status
    );
}

#[tokio::test]
async fn t4_s10_adversarial_inputs_and_concurrent_stress() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    ws.write_doc(&dropbox, "ok.txt", "TOKEN_T4_S10_STRESS_OK");
    let daemon = Arc::new(DaemonTestProcess::start(&ws).await);

    let d1 = Arc::clone(&daemon);
    let d2 = Arc::clone(&daemon);
    let d3 = Arc::clone(&daemon);
    let d4 = Arc::clone(&daemon);
    let db_path = dropbox.to_string_lossy().to_string();

    let b_trav = json!({ "action": "add_folder", "id": "dropbox", "path": r"C:\evil\%2e%2e\System32" });
    let b_tier = json!({ "action": "toggle_drive", "id": "dropbox", "enabled": true, "access_tier": 4 });
    let b_unk = json!({ "id": "missing_provider" });

    let (r_trav, r_tier, r_unk, r_valid) = tokio::join!(
        d1.post_json_raw("/api/cloud-drives/config", &b_trav),
        d2.post_json_raw("/api/cloud-drives/config", &b_tier),
        d3.post_json_raw("/api/cloud-drives/reindex", &b_unk),
        d4.enable_and_reindex_drive("dropbox", std::path::Path::new(&db_path), Some(3), 1),
    );

    assert_eq!(r_trav.0, StatusCode::BAD_REQUEST);
    assert_eq!(r_tier.0, StatusCode::BAD_REQUEST);
    assert!(r_unk.0 == StatusCode::BAD_REQUEST || r_unk.0 == StatusCode::NOT_FOUND);
    assert_eq!(
        find_drive(&r_valid, "dropbox")["enabled"].as_bool(),
        Some(true)
    );
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T4_S10_STRESS_OK").await,
        "TOKEN_T4_S10_STRESS_OK"
    ));
}
