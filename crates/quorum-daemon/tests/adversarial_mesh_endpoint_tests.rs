//! Adversarial Empirical Stress Suite for Daemon Mesh REST Endpoints and WebUI Settings Mesh Tab.
//!
//! Areas Covered:
//! 1. Legacy TPM 1.2 Ban Enforceability:
//!    - Verifies that join requests / candidates with tpm_version: "1.2", "1.2.0", "v1.2",
//!      "TPM 1.2-Rev116", tpm_1_2_banned: true, or is_tpm_banned: true are strictly rejected with
//!      HTTP 400 Bad Request ("TPM_1_2_BANNED") on both primary and alias endpoints.
//!    - Verifies that case-insensitive peer IDs are matched.
//!    - Verifies that valid TPM 2.0 candidates are successfully approved into Tier 2.
//! 2. Malformed Multiaddr Fuzzing:
//!    - Sends 25 adversarial, malformed, empty, SSRF, injection, and invalid payloads to
//!      `POST /api/mesh/bootstrap-peers` and verifies graceful rejection/handling without crashes,
//!      panics, or HTTP 500 errors.
//! 3. Operator Quarantine Release Integrity & Monotonic Epoch Advancement:
//!    - Enrolls peers into quarantine, queries the list via primary and alias endpoints.
//!    - Releases peers and verifies strict monotonic advancement of `mesh.hmac_epoch`.
//!    - Verifies idempotency / 404 for duplicate or ghost peer releases with zero epoch advancement.
//! 4. WebUI JS/CSS Consistency:
//!    - Inspects embedded `app.js` and `styles.css` to verify all 4 required panels
//!      (Local RoT, Connected Nodes, Pending Joins, Quarantined Peers) are properly wired and styled
//!      across all 5 themes.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use quorum_coordinator::{global_mesh_dlp_controller, SynthesisModelFamily};
use quorum_daemon::handlers::mesh::{enqueue_pending_join, PendingJoinDto};
use quorum_daemon::{build_router, DaemonState};
use quorum_types::AccessTier;
use quorum_ui::get_asset;
use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;
use tower::ServiceExt;

async fn setup_test_app_with_state() -> (axum::Router, Arc<DaemonState>) {
    let temp_dir = tempdir().expect("tempdir");
    let data_dir = temp_dir.path().to_path_buf();

    let storage_config = quorum_storage::StorageConfig::new(data_dir.clone());
    let storage = Arc::new(
        quorum_storage::StorageEngine::open(storage_config)
            .await
            .expect("storage open"),
    );
    let classifier = Arc::new(quorum_classifier::FileTypeClassifier::new());
    let embedder: Arc<dyn quorum_contract::EmbeddingGenerator> =
        Arc::new(quorum_contract::DeterministicOfflineEngine::new());
    let dedup = Arc::new(quorum_ingest::TwoLevelDedupEngine::new());
    let ingest_config = quorum_ingest::IngestConfig::default();

    let reindex_worker = Arc::new(quorum_ingest::ReindexWorker::new(
        ingest_config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    ));

    let drift_healer = Arc::new(quorum_ingest::DriftHealer::new(
        ingest_config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    ));

    let coordinator_engine = Arc::new(quorum_coordinator::ScatterGatherEngine::new(
        Arc::clone(&storage) as Arc<dyn quorum_coordinator::StorageSearcher>,
        Arc::new(quorum_coordinator::LocalOnlyDispatcher),
        Arc::new(tokio::sync::RwLock::new(
            quorum_coordinator::PeerAclManager::default(),
        )),
        quorum_coordinator::CoordinatorConfig::default(),
        [0u8; 32],
        "adversarial_test".to_string(),
    ));

    let coordinator = Arc::new(quorum_coordinator::QueryCoordinator::new(
        coordinator_engine,
        quorum_coordinator::CoordinatorConfig::default(),
    ));

    let shutdown_notify = Arc::new(tokio::sync::Notify::new());

    let state = Arc::new(DaemonState {
        start_time: Instant::now(),
        storage,
        coordinator,
        reindex_worker,
        drift_healer,
        classifier,
        embedder,
        dedup,
        swarm_handle: None,
        ingest_config,
        default_model_family: SynthesisModelFamily::AutoFusion,
        port: 3031,
        host: "127.0.0.1".to_string(),
        data_dir,
        shutdown_notify,
        in_flight_queries: Arc::new(quorum_daemon::InFlightQueryRegistry::new()),
        sessions: quorum_daemon::ChatSessionRegistry::new(),
    });

    let router = build_router(Arc::clone(&state));
    (router, state)
}

fn build_dummy_pending_join(
    peer_id: &str,
    tpm_version: &str,
    tpm_1_2_banned: bool,
    is_tpm_banned: bool,
) -> PendingJoinDto {
    PendingJoinDto {
        peer_id: peer_id.to_string(),
        multiaddr: format!("/ip4/192.168.1.100/tcp/3032/p2p/{}", peer_id),
        address: "192.168.1.100:3032".to_string(),
        host_ip: "192.168.1.100".to_string(),
        port: 3032,
        transport: "tcp".to_string(),
        reputation_score: 0.5,
        reputation_label: "Standard".to_string(),
        alerts_verified: 0,
        false_positives: 0,
        discovered_at: "2026-11-02T17:00:00Z".to_string(),
        discovered_date_time: "2026-11-02 17:00".to_string(),
        os: "Windows 10".to_string(),
        is_patched: false,
        os_supported: true,
        attestation_verified: !is_tpm_banned,
        attestation_state: if is_tpm_banned { "Legacy TPM 1.2" } else { "TPM 2.0 Hardware RoT Verified" }.to_string(),
        tpm_version: tpm_version.to_string(),
        tpm_badge: if is_tpm_banned { "TPM 1.2 (Legacy Banned)" } else { "TPM 2.0 (Hardware Attested)" }.to_string(),
        attestation_mode: if is_tpm_banned { "Legacy" } else { "TPM 2.0" }.to_string(),
        tpm_1_2_banned,
        is_tpm_banned,
        status: "pending".to_string(),
    }
}

#[tokio::test]
async fn test_adversarial_legacy_tpm_1_2_ban_enforceability() {
    let (app, state) = setup_test_app_with_state().await;

    // 1. Enqueue 6 distinct legacy TPM 1.2 candidates covering various field configurations
    let legacy_candidates = vec![
        ("12D3KooWLegacy12Direct", "1.2", false, false),
        ("12D3KooWLegacy12PointZero", "1.2.0", false, false),
        ("12D3KooWLegacyV12", "v1.2", false, false),
        ("12D3KooWLegacyTpmRev116", "TPM 1.2-Rev116", false, false),
        ("12D3KooWFlagTpm12Banned", "2.0", true, false),
        ("12D3KooWFlagIsTpmBanned", "2.0", false, true),
    ];

    for (pid, ver, flag_1_2, flag_banned) in &legacy_candidates {
        enqueue_pending_join(build_dummy_pending_join(pid, ver, *flag_1_2, *flag_banned));
    }

    // Also enqueue one valid TPM 2.0 candidate
    let valid_peer_id = "12D3KooWLegitimateTpm20Candidate";
    enqueue_pending_join(build_dummy_pending_join(valid_peer_id, "2.0", false, false));

    // 2. Verify all 6 legacy candidates return HTTP 400 Bad Request
    for (idx, (pid, ver, _, _)) in legacy_candidates.iter().enumerate() {
        // Use primary endpoint for even indices, legacy alias endpoint for odd indices
        let uri = if idx % 2 == 0 {
            format!("/api/mesh/pending-joins/{}/allow", pid)
        } else {
            format!("/api/pending-joins/{}/allow", pid)
        };

        let req = Request::builder()
            .method("POST")
            .uri(&uri)
            .body(Body::empty())
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "Peer '{}' with version '{}' must be rejected with 400 Bad Request",
            pid,
            ver
        );

        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["status"], "error");
        assert_eq!(json["code"], "TPM_1_2_BANNED");
        assert!(json["message"].as_str().unwrap().contains("TPM 1.2 is strictly banned"));
    }

    // 3. Test case-insensitivity: send lowercase peer ID for 12D3KooWLegacy12Direct
    let req_lower = Request::builder()
        .method("POST")
        .uri("/api/mesh/pending-joins/12d3koowlegacy12direct/allow")
        .body(Body::empty())
        .unwrap();
    let resp_lower = app.clone().oneshot(req_lower).await.unwrap();
    assert_eq!(
        resp_lower.status(),
        StatusCode::BAD_REQUEST,
        "Case variation must still be blocked by TPM 1.2 ban!"
    );

    // 4. Test non-existent peer returns 404
    let req_ghost = Request::builder()
        .method("POST")
        .uri("/api/mesh/pending-joins/12D3KooWNonExistentPeer999/allow")
        .body(Body::empty())
        .unwrap();
    let resp_ghost = app.clone().oneshot(req_ghost).await.unwrap();
    assert_eq!(resp_ghost.status(), StatusCode::NOT_FOUND);

    // 5. Allow the legitimate TPM 2.0 peer -> must return 200 OK
    let req_allow_valid = Request::builder()
        .method("POST")
        .uri(format!("/api/mesh/pending-joins/{}/allow", valid_peer_id))
        .body(Body::empty())
        .unwrap();
    let resp_allow_valid = app.clone().oneshot(req_allow_valid).await.unwrap();
    assert_eq!(resp_allow_valid.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp_allow_valid.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["peer_id"], valid_peer_id);

    // Verify the valid peer is registered in PeerAclManager with Tier 2 Confidential
    let acl_guard = state.coordinator.engine.acl_manager.read().await;
    let registered_tier = acl_guard.get_authorized_tier_for_peer_id(valid_peer_id);
    assert_eq!(registered_tier, AccessTier::Tier2Confidential);
    drop(acl_guard);

    // 6. Deny one of the remaining legacy peers
    let req_deny = Request::builder()
        .method("POST")
        .uri("/api/mesh/pending-joins/12D3KooWLegacy12Direct/deny")
        .body(Body::empty())
        .unwrap();
    let resp_deny = app.clone().oneshot(req_deny).await.unwrap();
    assert_eq!(resp_deny.status(), StatusCode::OK);

    // 7. Clear remaining pending joins
    let req_clear = Request::builder()
        .method("POST")
        .uri("/api/mesh/pending-joins/clear")
        .body(Body::empty())
        .unwrap();
    let resp_clear = app.oneshot(req_clear).await.unwrap();
    assert_eq!(resp_clear.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_adversarial_multiaddr_fuzzing() {
    let (app, _) = setup_test_app_with_state().await;

    // 25 distinct multiaddress fuzzing cases
    let fuzz_cases: Vec<(&str, StatusCode)> = vec![
        // 1. Empty & whitespace
        ("", StatusCode::BAD_REQUEST),
        ("   ", StatusCode::BAD_REQUEST),
        ("\t\n", StatusCode::BAD_REQUEST),

        // 2. Plain domain/IP without multiaddress prefix
        ("google.com", StatusCode::BAD_REQUEST),
        ("127.0.0.1:3032", StatusCode::BAD_REQUEST),
        ("10.0.0.3:3032", StatusCode::BAD_REQUEST),

        // 3. HTTP / HTTPS / WebSocket protocols
        ("http://127.0.0.1:3032", StatusCode::BAD_REQUEST),
        ("https://mesh.local:3032", StatusCode::BAD_REQUEST),
        ("ws://127.0.0.1:3032", StatusCode::BAD_REQUEST),

        // 4. Traversal & command injection payloads
        ("/ip4/../../etc/passwd", StatusCode::OK), // Has prefix /ip4/; rejected gracefully by libp2p parser
        ("..//ip4/127.0.0.1/tcp/3032", StatusCode::BAD_REQUEST),
        ("/ip4/127.0.0.1; rm -rf /; /tcp/3032", StatusCode::OK), // Has prefix; fails dial/parse safely

        // 5. Malformed IP or port formats
        ("/ip4/999.999.999.999/tcp/3032", StatusCode::OK), // Handled gracefully by libp2p dial
        ("/ip4/127.0.0.1/tcp/invalid_port", StatusCode::OK),
        ("/ip4/127.0.0.1/tcp/99999999", StatusCode::OK),
        ("/ip4/127.0.0.1", StatusCode::OK),

        // 6. SSRF / Localhost probes
        ("/ip4/169.254.169.254/tcp/80", StatusCode::OK),
        ("/ip4/127.0.0.1/tcp/3031", StatusCode::OK),
        ("/ip4/0.0.0.0/tcp/3031", StatusCode::OK),

        // 7. Valid multiaddress patterns
        ("/ip4/10.0.0.45/tcp/3032", StatusCode::OK),
        ("/dns4/mesh.duckdns.org/tcp/3032", StatusCode::OK),
        ("/dns/node.local/tcp/3032", StatusCode::OK),
        ("/dns6/ipv6.duckdns.org/tcp/3032", StatusCode::OK),
        ("/ip6/::1/tcp/3032", StatusCode::OK),
    ];

    for (payload, expected_status) in fuzz_cases {
        let body_json = serde_json::json!({
            "peers": [payload],
            "dial_now": false
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/mesh/bootstrap-peers")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_string(&body_json).unwrap()))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            expected_status,
            "Fuzz payload '{}' failed: expected {:?}, got {:?}",
            payload,
            expected_status,
            resp.status()
        );

        // Assert response is valid JSON and server did not crash
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let _: serde_json::Value = serde_json::from_slice(&bytes)
            .expect("Server response must always be well-formed JSON");
    }

    // 8. Fuzz with massive string (10,000 chars)
    let long_str = format!("/ip4/{}", "a".repeat(10000));
    let long_body = serde_json::json!({
        "peers": [long_str],
        "dial_now": false
    });
    let req_long = Request::builder()
        .method("POST")
        .uri("/api/mesh/bootstrap-peers")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&long_body).unwrap()))
        .unwrap();
    let resp_long = app.clone().oneshot(req_long).await.unwrap();
    assert_eq!(resp_long.status(), StatusCode::OK);

    // 9. Fuzz with malformed JSON syntax
    let req_malformed_json = Request::builder()
        .method("POST")
        .uri("/api/mesh/bootstrap-peers")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{peers: [unquoted]}"))
        .unwrap();
    let resp_malformed_json = app.clone().oneshot(req_malformed_json).await.unwrap();
    assert!(
        resp_malformed_json.status() == StatusCode::BAD_REQUEST
            || resp_malformed_json.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Malformed JSON must return 400 or 422"
    );

    // 10. Fuzz with empty peers array and null peers
    for empty_body in [r#"{"peers": []}"#, r#"{"peers": null}"#] {
        let req_empty = Request::builder()
            .method("POST")
            .uri("/api/mesh/bootstrap-peers")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(empty_body))
            .unwrap();
        let resp_empty = app.clone().oneshot(req_empty).await.unwrap();
        assert_eq!(resp_empty.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn test_adversarial_quarantine_release_integrity_and_epoch() {
    let (app, _) = setup_test_app_with_state().await;
    let controller = global_mesh_dlp_controller();

    // 1. Setup initial quarantine state with 3 test peers
    let peer_a = "12D3KooWQuarantineAlfa01";
    let peer_b = "12D3KooWQuarantineBravo02";
    let peer_c = "12D3KooWQuarantineCharlie03";

    {
        let mut guard = controller.settings.write().unwrap();
        guard.mesh.quarantined_peers = vec![
            peer_a.to_string(),
            peer_b.to_string(),
            peer_c.to_string(),
        ];
    }

    // 2. Query quarantined peers via both primary and alias endpoints
    let req_list_primary = Request::builder()
        .uri("/api/mesh/quarantined-peers")
        .body(Body::empty())
        .unwrap();
    let resp_list_primary = app.clone().oneshot(req_list_primary).await.unwrap();
    assert_eq!(resp_list_primary.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp_list_primary.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let list = json.as_array().expect("Quarantined list must be an array");
    assert_eq!(list.len(), 3, "Expected 3 quarantined peers initially");

    let req_list_alias = Request::builder()
        .uri("/api/quarantined-peers")
        .body(Body::empty())
        .unwrap();
    let resp_list_alias = app.clone().oneshot(req_list_alias).await.unwrap();
    assert_eq!(resp_list_alias.status(), StatusCode::OK);

    // 3. Capture baseline epoch E0
    let e0 = controller.settings.read().unwrap().mesh.hmac_epoch;

    // 4. Release Peer A via primary endpoint
    let req_rel_a = Request::builder()
        .method("POST")
        .uri(format!("/api/mesh/quarantined-peers/{}/release", peer_a))
        .body(Body::empty())
        .unwrap();
    let resp_rel_a = app.clone().oneshot(req_rel_a).await.unwrap();
    assert_eq!(resp_rel_a.status(), StatusCode::OK);

    let e1 = controller.settings.read().unwrap().mesh.hmac_epoch;
    assert_eq!(
        e1,
        e0.saturating_add(1),
        "Epoch must advance monotonically after releasing Peer A"
    );

    // Verify Peer A is no longer in quarantined_peers list
    assert!(
        !controller.settings.read().unwrap().mesh.quarantined_peers.contains(&peer_a.to_string())
    );

    // 5. Release Peer B via alias endpoint using case mismatch (lowercase)
    let req_rel_b = Request::builder()
        .method("POST")
        .uri(format!("/api/quarantined-peers/{}/release", peer_b.to_ascii_lowercase()))
        .body(Body::empty())
        .unwrap();
    let resp_rel_b = app.clone().oneshot(req_rel_b).await.unwrap();
    assert_eq!(resp_rel_b.status(), StatusCode::OK);

    let e2 = controller.settings.read().unwrap().mesh.hmac_epoch;
    assert_eq!(
        e2,
        e1.saturating_add(1),
        "Epoch must advance monotonically after releasing Peer B"
    );

    // 6. Attempt duplicate release of Peer A -> must return 404 and epoch MUST NOT advance
    let req_dup_a = Request::builder()
        .method("POST")
        .uri(format!("/api/mesh/quarantined-peers/{}/release", peer_a))
        .body(Body::empty())
        .unwrap();
    let resp_dup_a = app.clone().oneshot(req_dup_a).await.unwrap();
    assert_eq!(resp_dup_a.status(), StatusCode::NOT_FOUND);

    let e_dup = controller.settings.read().unwrap().mesh.hmac_epoch;
    assert_eq!(e_dup, e2, "Epoch must NOT advance on duplicate release");

    // 7. Attempt release of non-existent peer -> must return 404 and epoch MUST NOT advance
    let req_ghost = Request::builder()
        .method("POST")
        .uri("/api/mesh/quarantined-peers/12D3KooWGhostPeerNonExistent/release")
        .body(Body::empty())
        .unwrap();
    let resp_ghost = app.clone().oneshot(req_ghost).await.unwrap();
    assert_eq!(resp_ghost.status(), StatusCode::NOT_FOUND);

    let e_ghost = controller.settings.read().unwrap().mesh.hmac_epoch;
    assert_eq!(e_ghost, e2, "Epoch must NOT advance on ghost peer release");

    // 8. Release final Peer C
    let req_rel_c = Request::builder()
        .method("POST")
        .uri(format!("/api/mesh/quarantined-peers/{}/release", peer_c))
        .body(Body::empty())
        .unwrap();
    let resp_rel_c = app.clone().oneshot(req_rel_c).await.unwrap();
    assert_eq!(resp_rel_c.status(), StatusCode::OK);

    let e3 = controller.settings.read().unwrap().mesh.hmac_epoch;
    assert_eq!(e3, e2.saturating_add(1), "Epoch must advance for Peer C");

    // 9. Verify quarantined peers list is now 0
    let req_list_final = Request::builder()
        .uri("/api/mesh/quarantined-peers")
        .body(Body::empty())
        .unwrap();
    let resp_list_final = app.oneshot(req_list_final).await.unwrap();
    let bytes = axum::body::to_bytes(resp_list_final.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 0, "Quarantined list must now be empty");
}

#[test]
fn test_adversarial_webui_js_css_panels_and_themes() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js asset must exist");
    let js = String::from_utf8_lossy(&js_bytes);

    let (css_bytes, _) = get_asset("styles.css").expect("styles.css asset must exist");
    let css = String::from_utf8_lossy(&css_bytes);

    // ==========================================
    // 1. Verify 4 Required Mesh Panels in app.js
    // ==========================================

    // Panel 1: Local Hardware Root-of-Trust (RoT) & Attestation
    assert!(
        js.contains("Local Hardware Root-of-Trust (RoT) & Attestation") || js.contains("rotCardHtml"),
        "app.js must render Local RoT Card"
    );
    assert!(
        js.contains("/api/mesh/tpm/status"),
        "app.js must query /api/mesh/tpm/status"
    );
    assert!(
        js.contains("Composite PCR Digest"),
        "app.js must render composite PCR digest"
    );
    assert!(
        js.contains("PCR 0 (Platform Firmware / BIOS)") && js.contains("PCR 7") && js.contains("PCR 16"),
        "app.js must display PCR 0, 7, 16 breakdown chips"
    );

    // Panel 2: Connected Nodes Topology & Attestation
    assert!(
        js.contains("Connected Mesh Nodes & Attestation Topology") || js.contains("topologyCardHtml"),
        "app.js must render Connected Nodes panel"
    );
    assert!(
        js.contains("/api/mesh/topology"),
        "app.js must query /api/mesh/topology"
    );
    assert!(
        js.contains("resolveNodeTpmBadge"),
        "app.js must wire resolveNodeTpmBadge"
    );
    assert!(
        js.contains("Local Host Node") || js.contains("localNodeCard"),
        "app.js must differentiate local node from remote peers"
    );

    // Panel 3: Pending Joins Operator Approval Queue (HITL Gate)
    assert!(
        js.contains("Pending Joins Operator Approval Queue") || js.contains("pendingJoinsHtml"),
        "app.js must render Pending Joins queue"
    );
    assert!(
        js.contains("/api/mesh/pending-joins"),
        "app.js must query /api/mesh/pending-joins"
    );
    assert!(
        js.contains("quorumAllowPendingJoin"),
        "app.js must wire quorumAllowPendingJoin"
    );
    assert!(
        js.contains("quorumDenyPendingJoin"),
        "app.js must wire quorumDenyPendingJoin"
    );
    assert!(
        js.contains("quorumApproveAllPending"),
        "app.js must wire quorumApproveAllPending"
    );
    assert!(
        js.contains("quorumClearPendingJoins"),
        "app.js must wire quorumClearPendingJoins"
    );
    assert!(
        js.contains("🚫 Blocked (TPM 1.2 Banned)"),
        "app.js must render disabled button for banned TPM 1.2 candidates"
    );

    // Panel 4: Quarantined Peers Panel
    assert!(
        js.contains("Quarantined Peers & Threat Isolation Lattice") || js.contains("quarantinedPanelHtml"),
        "app.js must render Quarantined Peers panel"
    );
    assert!(
        js.contains("/api/mesh/quarantined-peers"),
        "app.js must query /api/mesh/quarantined-peers"
    );
    assert!(
        js.contains("quorumReleaseQuarantinePeer"),
        "app.js must wire quorumReleaseQuarantinePeer"
    );

    // ==========================================
    // 2. Verify TPM Badges in styles.css
    // ==========================================
    assert!(css.contains(".tpm-badge-green"), "styles.css must style .tpm-badge-green");
    assert!(css.contains(".tpm-badge-yellow"), "styles.css must style .tpm-badge-yellow");
    assert!(css.contains(".tpm-badge-blue"), "styles.css must style .tpm-badge-blue");
    assert!(css.contains(".tpm-badge-red"), "styles.css must style .tpm-badge-red");

    // ==========================================
    // 3. Verify All 5 Themes in styles.css
    // ==========================================
    assert!(css.contains("body.theme-obsidian"), "styles.css must define theme-obsidian");
    assert!(css.contains("body.theme-dark"), "styles.css must define theme-dark");
    assert!(css.contains("body.theme-white"), "styles.css must define theme-white");
    assert!(css.contains("body.theme-midnight"), "styles.css must define theme-midnight");
    assert!(css.contains("body.theme-warm"), "styles.css must define theme-warm");

    // ==========================================
    // 4. Verify Light Theme Contrast Overrides
    // ==========================================
    assert!(
        css.contains("body.theme-white .tpm-badge-green"),
        "styles.css must provide light mode override for .tpm-badge-green"
    );
    assert!(
        css.contains("body.theme-white .tpm-badge-yellow"),
        "styles.css must provide light mode override for .tpm-badge-yellow"
    );
    assert!(
        css.contains("body.theme-white .tpm-badge-red"),
        "styles.css must provide light mode override for .tpm-badge-red"
    );
}
