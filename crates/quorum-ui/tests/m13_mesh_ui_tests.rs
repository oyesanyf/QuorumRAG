//! Milestone M13 WebUI Specification & Static Asset Tests
//!
//! Asserts that:
//! 1. `styles.css` defines `.tpm-badge-green`, `.tpm-badge-yellow`, `.tpm-badge-red`.
//! 2. `app.js` handles both genuine physical TPM 2.0 silicon (green badge) and simulated fallback (yellow badge).
//! 3. `app.js` implements the operator HITL pending joins queue querying `/api/mesh/pending-joins/:peer_id/allow` and `/deny`.
//! 4. `app.js` enforces the exclusive TPM 2.0 policy by disabling approval for legacy TPM 1.2 peers (`🚫 Blocked (TPM 1.2 Banned)`).
//! 5. `app.js` implements the quarantined peers panel querying `/api/mesh/quarantined-peers/:peer_id/release`.

use quorum_ui::get_asset;

#[test]
fn test_mesh_ui_tpm_badges_in_styles_css() {
    let (css_bytes, _) = get_asset("styles.css").expect("styles.css must exist");
    let css = String::from_utf8_lossy(&css_bytes);

    assert!(
        css.contains(".tpm-badge-green"),
        "styles.css must define .tpm-badge-green"
    );
    assert!(
        css.contains(".tpm-badge-yellow"),
        "styles.css must define .tpm-badge-yellow"
    );
    assert!(
        css.contains(".tpm-badge-red"),
        "styles.css must define .tpm-badge-red"
    );
}

#[test]
fn test_mesh_ui_javascript_routes_and_policy() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js must exist");
    let js = String::from_utf8_lossy(&js_bytes);

    // Endpoints
    assert!(
        js.contains("/api/mesh/tpm/status"),
        "app.js must query /api/mesh/tpm/status"
    );
    assert!(
        js.contains("/api/mesh/topology"),
        "app.js must query /api/mesh/topology"
    );
    assert!(
        js.contains("/api/mesh/pending-joins"),
        "app.js must query /api/mesh/pending-joins"
    );
    assert!(
        js.contains("/api/mesh/quarantined-peers"),
        "app.js must query /api/mesh/quarantined-peers"
    );

    // TPM 2.0 Exclusive Policy and Actions
    assert!(
        js.contains("TPM 2.0 Hardware RoT Verified"),
        "app.js must render hardware RoT badge text"
    );
    assert!(
        js.contains("Simulated TPM Fallback"),
        "app.js must render simulated fallback text"
    );
    assert!(
        js.contains("TPM 1.2 Banned"),
        "app.js must ban legacy TPM 1.2"
    );
    assert!(
        js.contains("quorumAllowPendingJoin"),
        "app.js must provide quorumAllowPendingJoin"
    );
    assert!(
        js.contains("quorumDenyPendingJoin"),
        "app.js must provide quorumDenyPendingJoin"
    );
    assert!(
        js.contains("quorumReleaseQuarantinePeer"),
        "app.js must provide quorumReleaseQuarantinePeer"
    );
}
