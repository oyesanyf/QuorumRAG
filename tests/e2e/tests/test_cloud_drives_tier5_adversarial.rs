//! Tier 5 E2E Adversarial Hardening Tests for QuorumRAG Cloud Drives.
//!
//! Covers live-daemon scenarios identified during Phase 2 white-box adversarial review:
//! - Bulk `drives` round-trip (`GET /api/cloud-drives` -> `POST /api/cloud-drives/config`) with disabled drive `custom_paths`
//! - `add_folder` idempotency and semantics on disabled drives
//! - Non-system `*\Users\<project>` paths permitted across all endpoints vs OS profile root `409` blocking
//! - `POST /api/v1/marketplace/opt-in` strict-ancestor splitting across restart + `POST /api/drift/fix`
//! - `set_root` live swap purging old root and indexing new root
//! - `POST /api/open-file` `403` fail-closed on disabled cloud files
//! - Trailing space and trailing `\.` path segment rejection (`400`)
//! - `toggle_drive` updating `access_tier` cleanly while disabled
//! - Concurrent `POST /api/documents/add` vs drive disable purge with zero resurrection
//! - Concurrent `POST /api/reindex` (`start_reindex`) vs drive disable purge with zero resurrection

use quorum_e2e::cloud_drives_harness::{
    find_drive, paths_equivalent, query_result_contains_token, DaemonTestProcess,
    FakeCloudWorkspace,
};
use reqwest::StatusCode;
use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn t5_bulk_drives_roundtrip_disabled_drive_retaining_custom_paths_succeeds() {
    let ws = FakeCloudWorkspace::new();
    let _dropbox = ws.plant_dropbox_standard();
    let custom_docs = ws.mkdir("CustomDocsRoundtrip");
    let daemon = DaemonTestProcess::start(&ws).await;

    let en = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": true
        }))
        .await;
    assert_eq!(find_drive(&en, "dropbox")["enabled"].as_bool(), Some(true));

    let added = daemon
        .post_cloud_drives_config(&json!({
            "action": "add_folder",
            "id": "dropbox",
            "path": custom_docs.to_string_lossy()
        }))
        .await;
    assert!(!find_drive(&added, "dropbox")["custom_paths"]
        .as_array()
        .unwrap()
        .is_empty());

    let dis = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": false
        }))
        .await;
    assert_eq!(
        find_drive(&dis, "dropbox")["enabled"].as_bool(),
        Some(false)
    );

    // Round-trip GET /api/cloud-drives -> POST /api/cloud-drives/config { "drives": [...] }
    let snapshot = daemon.get_cloud_drives().await;
    let roundtrip = daemon
        .post_cloud_drives_config(&json!({
            "placeholder_mode": snapshot["placeholder_mode"],
            "hydration_max_file_size_mb": snapshot["hydration_max_file_size_mb"],
            "drives": snapshot["drives"]
        }))
        .await;

    let db_after = find_drive(&roundtrip, "dropbox");
    assert_eq!(db_after["enabled"].as_bool(), Some(false));
    assert!(
        db_after["custom_paths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| paths_equivalent(v.as_str().unwrap_or(""), &custom_docs.to_string_lossy())),
        "Disabled drive must retain custom_paths across bulk drives roundtrip: {}",
        db_after
    );
}

#[tokio::test]
async fn t5_add_folder_on_disabled_drive_custom_paths_semantics() {
    let ws = FakeCloudWorkspace::new();
    let _dropbox = ws.plant_dropbox_standard();
    let custom_docs = ws.mkdir("DisabledCustomDocs");
    let daemon = DaemonTestProcess::start(&ws).await;

    let first = daemon
        .post_cloud_drives_config(&json!({
            "action": "add_folder",
            "id": "dropbox",
            "path": custom_docs.to_string_lossy()
        }))
        .await;
    assert_eq!(
        find_drive(&first, "dropbox")["enabled"].as_bool(),
        Some(false)
    );
    assert_eq!(
        find_drive(&first, "dropbox")["custom_paths"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // Repeating add_folder on the same disabled drive must be idempotent 200 OK (no 409 self-conflict)
    let second = daemon
        .post_cloud_drives_config(&json!({
            "action": "add_folder",
            "id": "dropbox",
            "path": custom_docs.to_string_lossy()
        }))
        .await;
    assert_eq!(
        find_drive(&second, "dropbox")["custom_paths"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn t5_non_system_users_subdirectory_permitted_everywhere() {
    let ws = FakeCloudWorkspace::new();
    let project_users = ws.root.path().join("Work").join("Users").join("MyProject");
    std::fs::create_dir_all(&project_users).expect("create Work/Users/MyProject");
    ws.write_doc(&project_users, "proj.txt", "TOKEN_T5_USERS_PROJECT_ALLOWED");

    let daemon = DaemonTestProcess::start(&ws).await;

    // 1. marketplace/opt-in succeeds
    let mkt = daemon
        .post_json(
            "/api/v1/marketplace/opt-in",
            &json!({
                "opt_in_enabled": true,
                "user_consent_checked": true,
                "consent_statement": "Consent for project under Users dir",
                "opt_in_folders": [project_users.to_string_lossy()]
            }),
        )
        .await;
    assert_eq!(mkt["status"].as_str(), Some("updated"));

    // 2. mesh/shared-folders succeeds
    let sf = daemon
        .post_json(
            "/api/mesh/shared-folders",
            &json!({
                "action": "add",
                "path": project_users.to_string_lossy(),
                "enabled": true,
                "access_tier": 0
            }),
        )
        .await;
    assert_eq!(sf["status"].as_str(), Some("ok"));

    // 3. documents/add succeeds and indexes TOKEN_T5_USERS_PROJECT_ALLOWED
    let add_doc = daemon
        .post_json(
            "/api/documents/add",
            &json!({
                "local_paths": [project_users.join("proj.txt").to_string_lossy()]
            }),
        )
        .await;
    assert_eq!(add_doc["status"].as_str(), Some("added_and_indexed"));

    let mut q = serde_json::Value::Null;
    for _ in 0..60 {
        q = daemon.query_local("TOKEN_T5_USERS_PROJECT_ALLOWED").await;
        if query_result_contains_token(&q, "TOKEN_T5_USERS_PROJECT_ALLOWED") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        query_result_contains_token(&q, "TOKEN_T5_USERS_PROJECT_ALLOWED"),
        "Non-system Work/Users/MyProject document must be indexed and searchable: {}",
        q
    );

    // 4. add_folder on dropbox succeeds (not blocked as OS profile root)
    let added = daemon
        .post_cloud_drives_config(&json!({
            "action": "add_folder",
            "id": "dropbox",
            "path": project_users.to_string_lossy()
        }))
        .await;
    assert!(find_drive(&added, "dropbox")["custom_paths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| paths_equivalent(v.as_str().unwrap_or(""), &project_users.to_string_lossy())));
}

#[tokio::test]
async fn t5_system_drive_users_profile_root_still_blocked_409() {
    let ws = FakeCloudWorkspace::new();
    let daemon = DaemonTestProcess::start(&ws).await;

    // ws.home is the active QUORUM_CLOUD_TEST_PROFILE_DIR / USERPROFILE root
    let profile_root = ws.home.to_string_lossy().to_string();
    for (route, payload) in [
        (
            "/api/cloud-drives/config",
            json!({ "action": "add_folder", "id": "dropbox", "path": profile_root }),
        ),
        (
            "/api/v1/marketplace/opt-in",
            json!({
                "opt_in_enabled": true,
                "user_consent_checked": true,
                "consent_statement": "Profile root check",
                "opt_in_folders": [profile_root]
            }),
        ),
        (
            "/api/documents/add",
            json!({ "local_paths": [profile_root] }),
        ),
        ("/api/reindex", json!({ "target_paths": [profile_root] })),
        (
            "/api/mesh/shared-folders",
            json!({ "action": "add", "path": profile_root, "enabled": true, "access_tier": 0 }),
        ),
    ] {
        let (st, _, body) = daemon.post_json_raw(route, &payload).await;
        assert_eq!(
            st,
            StatusCode::CONFLICT,
            "{route} must fail closed with 409 for active user profile root: {body}"
        );
    }

    // On Windows, also verify an existing C:\Users\<name> directory (if present) is blocked as OS profile root
    #[cfg(windows)]
    if let Ok(real_profile) = std::env::var("USERPROFILE") {
        let rp = std::path::Path::new(&real_profile);
        if rp
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().eq_ignore_ascii_case("users"))
            .unwrap_or(false)
            && rp.is_dir()
        {
            let (st, _, body) = daemon
                .post_json_raw(
                    "/api/cloud-drives/config",
                    &json!({ "action": "add_folder", "id": "dropbox", "path": real_profile }),
                )
                .await;
            assert_eq!(
                st,
                StatusCode::CONFLICT,
                "C:\\Users\\<name> must be blocked with 409: {body}"
            );
        }
    }
}

#[tokio::test]
async fn t5_marketplace_opt_in_strict_ancestor_never_leaks_across_restart_and_drift_fix() {
    let ws = FakeCloudWorkspace::new();
    let parent_cloud = ws.mkdir("ParentCloud");
    let dropbox = parent_cloud.join("Dropbox");
    let sibling_dir = parent_cloud.join("SiblingNotes");
    let only_cloud_parent = ws.mkdir("OnlyCloudParent");
    let nextcloud = only_cloud_parent.join("Nextcloud");

    std::fs::create_dir_all(&dropbox).unwrap();
    std::fs::create_dir_all(&sibling_dir).unwrap();
    std::fs::create_dir_all(&nextcloud).unwrap();
    ws.plant_dropbox_info_json(
        &json!({ "personal": { "path": dropbox.to_string_lossy() } }).to_string(),
    );
    ws.plant_nextcloud_cfg(&format!(
        "[Accounts]\n0\\Folders\\1\\localPath={}\n",
        nextcloud.display()
    ));
    ws.write_doc(&sibling_dir, "sib.txt", "TOKEN_T5_MKT_SIBLING_ALLOWED");
    ws.write_doc(&dropbox, "secret.txt", "TOKEN_T5_MKT_DROPBOX_SECRET");
    ws.write_doc(&nextcloud, "nc_secret.txt", "TOKEN_T5_MKT_NEXTCLOUD_SECRET");

    {
        let daemon = DaemonTestProcess::start(&ws).await;
        // ParentCloud splits to SiblingNotes (never persisting unsplit ParentCloud or Dropbox)
        let opt_res = daemon
            .post_json(
                "/api/v1/marketplace/opt-in",
                &json!({
                    "opt_in_enabled": true,
                    "user_consent_checked": true,
                    "consent_statement": "Tier 5 strict ancestor opt-in test",
                    "opt_in_folders": [parent_cloud.to_string_lossy()]
                }),
            )
            .await;
        let persisted = opt_res["opt_in_folders"]
            .as_array()
            .expect("opt_in_folders array");
        assert!(
            persisted.iter().any(|v| paths_equivalent(
                v.as_str().unwrap_or(""),
                &sibling_dir.to_string_lossy()
            )),
            "Expected SiblingNotes in persisted opt_in_folders: {:?}",
            persisted
        );
        assert!(
            !persisted.iter().any(|v| paths_equivalent(
                v.as_str().unwrap_or(""),
                &parent_cloud.to_string_lossy()
            )),
            "Unsplit ParentCloud must NOT be persisted in opt_in_folders: {:?}",
            persisted
        );

        let _ = daemon.post_json("/api/drift/fix", &json!({})).await;
        assert!(query_result_contains_token(
            &daemon.query_local("TOKEN_T5_MKT_SIBLING_ALLOWED").await,
            "TOKEN_T5_MKT_SIBLING_ALLOWED"
        ));
        assert!(!query_result_contains_token(
            &daemon.query_local("TOKEN_T5_MKT_DROPBOX_SECRET").await,
            "TOKEN_T5_MKT_DROPBOX_SECRET"
        ));

        // OnlyCloudParent containing only disabled Nextcloud must reject with 409
        let (st_only, _, body_only) = daemon
            .post_json_raw(
                "/api/v1/marketplace/opt-in",
                &json!({
                    "opt_in_enabled": true,
                    "user_consent_checked": true,
                    "consent_statement": "Should reject empty split",
                    "opt_in_folders": [only_cloud_parent.to_string_lossy()]
                }),
            )
            .await;
        assert_eq!(
            st_only,
            StatusCode::CONFLICT,
            "OnlyCloudParent with 0 non-cloud paths must return 409: {body_only}"
        );

        daemon.shutdown().await;
    }

    // Restart cleanly on same --data-dir and run POST /api/drift/fix again
    let daemon2 = DaemonTestProcess::start(&ws).await;
    let _ = daemon2.post_json("/api/drift/fix", &json!({})).await;
    assert!(query_result_contains_token(
        &daemon2.query_local("TOKEN_T5_MKT_SIBLING_ALLOWED").await,
        "TOKEN_T5_MKT_SIBLING_ALLOWED"
    ));
    assert!(!query_result_contains_token(
        &daemon2.query_local("TOKEN_T5_MKT_DROPBOX_SECRET").await,
        "TOKEN_T5_MKT_DROPBOX_SECRET"
    ));
    assert!(!query_result_contains_token(
        &daemon2.query_local("TOKEN_T5_MKT_NEXTCLOUD_SECRET").await,
        "TOKEN_T5_MKT_NEXTCLOUD_SECRET"
    ));
}

#[tokio::test]
async fn t5_set_root_on_enabled_drive_purges_old_root_and_indexes_new_root() {
    let ws = FakeCloudWorkspace::new();
    let old_root = ws.mkdir("DropboxOld");
    let new_root = ws.mkdir("DropboxNew");
    ws.write_doc(&old_root, "old.txt", "TOKEN_T5_SET_ROOT_OLD");
    ws.write_doc(&new_root, "new.txt", "TOKEN_T5_SET_ROOT_NEW");

    let daemon = DaemonTestProcess::start(&ws).await;
    let _ = daemon
        .enable_and_reindex_drive("dropbox", &old_root, Some(3), 1)
        .await;
    assert!(query_result_contains_token(
        &daemon.query_local("TOKEN_T5_SET_ROOT_OLD").await,
        "TOKEN_T5_SET_ROOT_OLD"
    ));

    // Swap root_path via set_root while drive remains enabled
    let swapped = daemon
        .post_cloud_drives_config(&json!({
            "action": "set_root",
            "id": "dropbox",
            "root_path": new_root.to_string_lossy()
        }))
        .await;
    assert_eq!(
        find_drive(&swapped, "dropbox")["enabled"].as_bool(),
        Some(true)
    );

    let _ = daemon.post_cloud_drives_reindex("dropbox").await;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if query_result_contains_token(
            &daemon.query_local("TOKEN_T5_SET_ROOT_NEW").await,
            "TOKEN_T5_SET_ROOT_NEW",
        ) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "Timed out waiting for new root to index after set_root"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        !query_result_contains_token(
            &daemon.query_local("TOKEN_T5_SET_ROOT_OLD").await,
            "TOKEN_T5_SET_ROOT_OLD"
        ),
        "Old root chunks must be purged immediately when set_root swaps root_path"
    );
}

#[tokio::test]
async fn t5_open_file_disabled_cloud_drive_returns_403() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let doc = ws.write_doc(&dropbox, "disabled_open.txt", "TOKEN_T5_OPEN_FILE_DISABLED");
    let daemon = DaemonTestProcess::start(&ws).await;

    let (status, _, body) = daemon
        .post_json_raw("/api/open-file", &json!({ "path": doc.to_string_lossy() }))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "POST /api/open-file on disabled cloud drive file must return 403 Forbidden: {body}"
    );
}

#[tokio::test]
async fn t5_add_folder_trailing_space_and_trailing_dot_rejected_400() {
    let ws = FakeCloudWorkspace::new();
    let valid = ws.mkdir("ValidCleanFolder");
    let daemon = DaemonTestProcess::start(&ws).await;

    let trailing_space = format!("{} ", valid.to_string_lossy());
    let trailing_dot_seg = format!("{}\\.", valid.to_string_lossy());
    let trailing_slash_dot = format!("{}/.", valid.to_string_lossy());

    for bad in [trailing_space, trailing_dot_seg, trailing_slash_dot] {
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
            "Expected 400 Bad Request for malformed trailing path '{bad}': {body}"
        );
    }
}

#[tokio::test]
async fn t5_toggle_disabled_drive_updates_access_tier_cleanly() {
    let ws = FakeCloudWorkspace::new();
    let box_dir = ws.plant_box_win("Box");
    let daemon = DaemonTestProcess::start(&ws).await;

    let res = daemon
        .post_cloud_drives_config(&json!({
            "action": "toggle_drive",
            "id": "box",
            "enabled": false,
            "access_tier": 2,
            "root_path": box_dir.to_string_lossy()
        }))
        .await;
    let drv = find_drive(&res, "box");
    assert_eq!(drv["enabled"].as_bool(), Some(false));
    assert_eq!(drv["access_tier"].as_u64(), Some(2));
}

#[tokio::test]
async fn t5_concurrent_documents_add_vs_disable_purge_no_resurrection() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    let mut files = Vec::new();
    for i in 0..8 {
        files.push(ws.write_doc(
            &dropbox,
            &format!("doc_{i}.txt"),
            &format!("TOKEN_T5_CONCURRENT_DISABLE_{i}"),
        ));
    }

    let daemon = DaemonTestProcess::start(&ws).await;
    for delay_ms in [0u64, 15, 45] {
        let _ = daemon
            .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 8)
            .await;

        // Issue concurrent POST /api/documents/add while disabling dropbox (single disable ONLY)
        let add_payload = json!({
            "local_paths": files.iter().map(|p| p.to_string_lossy().to_string()).collect::<Vec<_>>()
        });
        let dis_payload = json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": false
        });
        let add_fut = daemon.post_json_raw("/api/documents/add", &add_payload);
        let dis_fut = async {
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            daemon.post_cloud_drives_config(&dis_payload).await
        };

        let ((st_add, _, _), dis_val) = tokio::join!(add_fut, dis_fut);
        assert!(
            st_add.is_success() || st_add == StatusCode::CONFLICT,
            "Unexpected status from concurrent documents/add (delay={delay_ms}ms): {st_add}"
        );
        assert_eq!(
            find_drive(&dis_val, "dropbox")["enabled"].as_bool(),
            Some(false)
        );

        daemon
            .wait_for_reindex_settled(Duration::from_secs(15))
            .await;
        let status_after = daemon.get_cloud_drives().await;
        assert_eq!(
            find_drive(&status_after, "dropbox")["indexed_files"].as_u64(),
            Some(0),
            "Dropbox must have 0 indexed_files after single concurrent disable (delay={delay_ms}ms)"
        );
        assert!(
            !query_result_contains_token(
                &daemon.query_local("TOKEN_T5_CONCURRENT_DISABLE_0").await,
                "TOKEN_T5_CONCURRENT_DISABLE_0"
            ),
            "Query must return 0 hits for doc_0 after single concurrent disable (delay={delay_ms}ms)"
        );
        assert!(
            !query_result_contains_token(
                &daemon.query_local("TOKEN_T5_CONCURRENT_DISABLE_7").await,
                "TOKEN_T5_CONCURRENT_DISABLE_7"
            ),
            "Query must return 0 hits for doc_7 after single concurrent disable (delay={delay_ms}ms)"
        );
    }
}

#[tokio::test]
async fn t5_concurrent_reindex_vs_disable_purge_no_resurrection() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    for i in 0..16 {
        ws.write_doc(
            &dropbox,
            &format!("reindex_doc_{i}.txt"),
            &format!("TOKEN_T5_REINDEX_DISABLE_{i} confidential cloud payload"),
        );
    }

    let daemon = DaemonTestProcess::start(&ws).await;
    for delay_ms in [0u64, 10, 30, 60] {
        let _ = daemon
            .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 16)
            .await;

        let reindex_payload = json!({
            "target_paths": [dropbox.to_string_lossy()],
            "full_rebuild": true,
            "force_reembed": true,
            "batch_size": 4
        });
        let dis_payload = json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": false
        });

        let reindex_fut = daemon.post_json_raw("/api/reindex", &reindex_payload);
        let dis_fut = async {
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            daemon.post_cloud_drives_config(&dis_payload).await
        };

        let ((st_reindex, _, body_reindex), dis_val) = tokio::join!(reindex_fut, dis_fut);
        assert!(
            st_reindex == StatusCode::ACCEPTED || st_reindex == StatusCode::CONFLICT,
            "Unexpected status from concurrent POST /api/reindex (delay={delay_ms}ms): {st_reindex} body={body_reindex}"
        );
        assert_eq!(
            find_drive(&dis_val, "dropbox")["enabled"].as_bool(),
            Some(false)
        );

        daemon
            .wait_for_reindex_settled(Duration::from_secs(15))
            .await;
        let status_after = daemon.get_cloud_drives().await;
        assert_eq!(
            find_drive(&status_after, "dropbox")["indexed_files"].as_u64(),
            Some(0),
            "Dropbox must have 0 indexed_files after single concurrent disable vs POST /api/reindex (delay={delay_ms}ms)"
        );
        assert!(
            !query_result_contains_token(
                &daemon.query_local("TOKEN_T5_REINDEX_DISABLE_0").await,
                "TOKEN_T5_REINDEX_DISABLE_0"
            ),
            "Query must return 0 hits for reindex_doc_0 after single concurrent disable (delay={delay_ms}ms)"
        );
        assert!(
            !query_result_contains_token(
                &daemon.query_local("TOKEN_T5_REINDEX_DISABLE_15").await,
                "TOKEN_T5_REINDEX_DISABLE_15"
            ),
            "Query must return 0 hits for reindex_doc_15 after single concurrent disable (delay={delay_ms}ms)"
        );
    }
}

#[tokio::test]
async fn t5_concurrent_drift_fix_vs_disable_purge_no_resurrection() {
    let ws = FakeCloudWorkspace::new();
    let dropbox = ws.plant_dropbox_standard();
    for i in 0..24 {
        ws.write_doc(
            &dropbox,
            &format!("drift_{i}.txt"),
            &format!("TOKEN_T5_DRIFT_DISABLE_{i} initial cloud content"),
        );
    }

    let daemon = DaemonTestProcess::start(&ws).await;
    for (target_drifts, delay_ms) in [
        (json!(["merkle_state"]), 0u64),
        (json!(["merkle_state"]), 20),
        (json!([]), 0),
        (json!([]), 25),
    ] {
        // Restore initial content and re-enable/index dropbox
        for i in 0..24 {
            ws.write_doc(
                &dropbox,
                &format!("drift_{i}.txt"),
                &format!("TOKEN_T5_DRIFT_DISABLE_{i} initial cloud content"),
            );
        }
        let _ = daemon
            .enable_and_reindex_drive("dropbox", &dropbox, Some(3), 24)
            .await;

        // Wait >1s and modify files on disk so DriftHealer MerkleState sees mtime+size drift
        tokio::time::sleep(Duration::from_millis(1100)).await;
        for i in 0..24 {
            ws.write_doc(
                &dropbox,
                &format!("drift_{i}.txt"),
                &format!(
                    "TOKEN_T5_DRIFT_DISABLE_{i} modified larger cloud payload delay_{delay_ms}_extra"
                ),
            );
        }

        let drift_payload = if target_drifts.as_array().is_some_and(|a| a.is_empty()) {
            json!({})
        } else {
            json!({ "target_drifts": target_drifts })
        };
        let dis_payload = json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": false
        });

        let drift_fut = daemon.post_json_raw("/api/drift/fix", &drift_payload);
        let dis_fut = async {
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            daemon.post_cloud_drives_config(&dis_payload).await
        };

        let ((st_drift, _, body_drift), dis_val) = tokio::join!(drift_fut, dis_fut);
        assert!(
            st_drift == StatusCode::OK || st_drift == StatusCode::CONFLICT,
            "Unexpected status from concurrent POST /api/drift/fix (delay={delay_ms}ms): {st_drift} body={body_drift}"
        );
        assert_eq!(
            find_drive(&dis_val, "dropbox")["enabled"].as_bool(),
            Some(false)
        );

        daemon
            .wait_for_reindex_settled(Duration::from_secs(15))
            .await;

        let status_after = daemon.get_cloud_drives().await;
        let db = find_drive(&status_after, "dropbox");
        assert_eq!(db["enabled"].as_bool(), Some(false));
        assert_eq!(
            db["indexed_files"].as_u64(),
            Some(0),
            "Dropbox must have 0 indexed_files after concurrent drift/fix vs disable (delay={delay_ms}ms): {db}"
        );
        assert_eq!(
            db["indexed_chunks"].as_u64(),
            Some(0),
            "Dropbox must have 0 indexed_chunks after concurrent drift/fix vs disable (delay={delay_ms}ms): {db}"
        );

        let reindex_status = daemon.get_json("/api/reindex/status").await;
        assert_eq!(
            reindex_status["total_stored_chunks"].as_u64(),
            Some(0),
            "Storage must have 0 total_stored_chunks after concurrent drift/fix vs disable (delay={delay_ms}ms): {reindex_status}"
        );

        assert!(
            !query_result_contains_token(
                &daemon.query_local("TOKEN_T5_DRIFT_DISABLE_0").await,
                "TOKEN_T5_DRIFT_DISABLE_0"
            ),
            "Query must return 0 hits for drift_0 after concurrent drift/fix vs disable (delay={delay_ms}ms)"
        );
        assert!(
            !query_result_contains_token(
                &daemon.query_local("TOKEN_T5_DRIFT_DISABLE_23").await,
                "TOKEN_T5_DRIFT_DISABLE_23"
            ),
            "Query must return 0 hits for drift_23 after concurrent drift/fix vs disable (delay={delay_ms}ms)"
        );
    }
}
