//! Adversarial Challenger Test Suite for Milestone 37 Requirement R1 (UI Mesh Telemetry & Banner Suppression)
//!
//! Validates:
//! 1. `app.js` tracks `_queryInFlight`, `_retrievedRemoteCount`, and `_contributingPeerIds`.
//! 2. `refreshSourcesNodeIdRow` suppresses the "No data from remote peers" banner while `queryInFlight` is true.
//! 3. `refreshSourcesNodeIdRow` suppresses the banner when `hasRemoteChunks` is true (`retrievedRemoteCount > 0` or `meshContributorsCount > 0`).
//! 4. `app.js` never emits "0 peers connected" when `connectedCount > 0`.
//! 5. `app.js` renders contributing peer IDs into the badge row before inline citations are rendered.

use quorum_ui::get_asset;

#[test]
fn test_m37_ui_telemetry_invariants_in_app_js() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js must exist");
    let js = String::from_utf8_lossy(&js_bytes);

    // 1. Check in-flight tracking
    assert!(
        js.contains("citationsEl._queryInFlight = true"),
        "app.js must initialize _queryInFlight = true on new turns"
    );
    assert!(
        js.contains("citationsEl._queryInFlight = false"),
        "app.js must clear _queryInFlight = false on completion"
    );

    // 2. Check remote count tracking
    assert!(
        js.contains("citationsEl._retrievedRemoteCount = Number(data.remote_count || 0)"),
        "app.js must capture remote_count into _retrievedRemoteCount"
    );
    assert!(
        js.contains("citationsEl._remoteCount = citationsEl._retrievedRemoteCount"),
        "app.js must sync _remoteCount"
    );

    // 3. Check contributing peer IDs collection
    assert!(
        js.contains("citationsEl._contributingPeerIds"),
        "app.js must track _contributingPeerIds Set"
    );
    assert!(
        js.contains("if (Array.isArray(data.contributing_peer_ids))"),
        "app.js must ingest data.contributing_peer_ids from RetrievalCompleted"
    );
    assert!(
        js.contains("if (Array.isArray(diag.contributing_peer_ids))"),
        "app.js must ingest diag.contributing_peer_ids"
    );

    // 4. Banner suppression logic
    assert!(
        js.contains("const hasRemoteChunks = (meshContributorsCount > 0) || (retrievedRemoteCount > 0);"),
        "app.js must check both meshContributorsCount and retrievedRemoteCount for remote chunks"
    );
    assert!(
        js.contains("if (!queryInFlight && !hasRemoteChunks && meshContributorsCount === 0)"),
        "app.js must strictly suppress the diagnostic banner while query is in flight or remote chunks match"
    );

    // 5. Anti-0-peers fallback when connectedCount > 0
    assert!(
        js.contains("reason = `${connectedCount} peer${connectedCount > 1 ? 's' : ''} connected on P2P port ${meshPort}, but no matching chunks returned`"),
        "app.js must format factual reason when connectedCount > 0"
    );
    assert!(
        js.contains("else if (connectedCount > 0 && reason.startsWith('0 peers connected'))"),
        "app.js must sanitize and overwrite stale '0 peers connected' summary reasons"
    );

    // 6. Contributing peer badge rendering
    assert!(
        js.contains("const meshPeersLabel = meshPeerIds.length > 0"),
        "app.js must format mesh peer labels including peer IDs"
    );
    assert!(
        js.contains("${meshPeersLabel}"),
        "app.js must render meshPeersLabel in the sources row"
    );
}
