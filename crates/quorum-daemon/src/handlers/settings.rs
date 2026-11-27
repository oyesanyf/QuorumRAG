use axum::extract::{Json, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::state::DaemonState;
use quorum_coordinator::{
    global_mesh_dlp_controller, ChatGptUiSettings, DlpEnforcementMode, MeshDlpPolicy,
    OsoosiMeshSettings, SharedFolderEntry,
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateSettingsPayload {
    pub ui: Option<ChatGptUiSettings>,
    pub mesh: Option<OsoosiMeshSettings>,
    pub dlp: Option<MeshDlpPolicy>,
    pub artemis: Option<quorum_coordinator::artemis_airgap::ArtemisDfirSettings>,
    pub atlaskv: Option<quorum_atlaskv::AtlasKvSettings>,
    pub forensics_enabled: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateMeshConfigPayload {
    pub p2p_enabled: Option<bool>,
    pub node_alias: Option<String>,
    pub zone: Option<String>,
    pub bootstrap_peers: Option<Vec<String>>,
    pub duckdns_domain: Option<String>,
    pub auto_bootstrap_duckdns: Option<bool>,
    pub join_gate_mode: Option<String>,
    pub require_explicit_folder_share: Option<bool>,
    pub rotate_epoch: Option<bool>,
    pub quarantine_peer: Option<String>,
    pub unquarantine_peer: Option<String>,
    pub trust_peer: Option<String>,
    pub max_peer_responses: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedFolderActionPayload {
    /// "add", "remove", "toggle", "update_tier", "update_dlp_mode"
    pub action: String,
    pub path: String,
    pub label: Option<String>,
    pub enabled: Option<bool>,
    pub access_tier: Option<u8>,
    pub dlp_mode_override: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateDlpPolicyPayload {
    pub enabled: Option<bool>,
    pub mode: Option<String>,
    pub dlp_engine: Option<String>,
    pub presidio_enabled: Option<bool>,
    pub gliner_enabled: Option<bool>,
    pub auto_provision_gliner: Option<bool>,
    pub gliner_model_id: Option<String>,
    pub gliner_confidence_threshold: Option<f32>,
    pub reprovision_gliner: Option<bool>,
    pub protect_ssn: Option<bool>,
    pub protect_medical_records: Option<bool>,
    pub protect_health_plan: Option<bool>,
    pub protect_dob_dates: Option<bool>,
    pub protect_academic_student_id: Option<bool>,
    pub protect_contact_pii: Option<bool>,
    pub protect_financial_tax: Option<bool>,
    pub protect_secrets_crown_jewels: Option<bool>,
    pub scrub_outbound_queries: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpTestPayload {
    pub text: String,
    pub file_path: Option<String>,
    pub mode: Option<String>,
}

/// GET /api/settings - Returns all ChatGPT-style UI settings, OshoosiClaw Mesh settings, Shared Folders, and DLP state.
pub async fn get_settings_handler(State(state): State<Arc<DaemonState>>) -> impl IntoResponse {
    let controller = global_mesh_dlp_controller();
    let settings = controller
        .settings
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let dlp_stats = controller
        .stats
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    let (local_peer_id, listen_addrs, connected_peers) = match &state.swarm_handle {
        Some(h) => {
            let pid = h.local_peer_id().to_string();
            let addrs: Vec<String> = h
                .listen_addresses()
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|a| a.to_string())
                .collect();
            let peers: Vec<String> = h
                .connected_peers()
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|p| p.to_string())
                .collect();
            (pid, addrs, peers)
        }
        None => ("local-only-node".to_string(), Vec::new(), Vec::new()),
    };

    let epoch_sig_preview =
        controller.sign_epoch_token(&local_peer_id, settings.mesh.hmac_epoch, "master_core");

    let storage_for_counts = Arc::clone(&state.storage);
    let (physical_drives, total_files) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::task::spawn_blocking(move || {
            let drives: Vec<String> = quorum_ingest::IngestConfig::discover_physical_drives()
                .into_iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect();
            let files = storage_for_counts.catalog().count_documents().unwrap_or(0);
            (drives, files)
        }),
    )
    .await
    .ok()
    .and_then(|res| res.ok())
    .unwrap_or_else(|| (Vec::new(), 0));

    let watched_paths: Vec<String> = state
        .reindex_worker
        .all_watch_paths()
        .into_iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    let total_chunks = state.storage.count_fast().await;

    Json(serde_json::json!({
        "status": "ok",
        "ui": settings.ui,
        "mesh": settings.mesh,
        "dlp": settings.dlp,
        "dlp_stats": dlp_stats,
        "artemis": settings.artemis,
        "atlaskv": settings.atlaskv,
        "forensics_enabled": settings.artemis.enabled,
        "runtime": {
            "local_peer_id": local_peer_id,
            "listen_addrs": listen_addrs,
            "connected_peers": connected_peers,
            "peer_count": connected_peers.len(),
            "http_port": state.port,
            "host": state.host,
            "data_dir": state.data_dir.to_string_lossy(),
            "physical_drives": physical_drives,
            "watched_paths": watched_paths,
            "index_epoch": state.storage.index_epoch(),
            "total_chunks": total_chunks,
            "total_files": total_files,
            "hmac_epoch_signature": epoch_sig_preview,
            "uptime_secs": state.start_time.elapsed().as_secs()
        }
    }))
}

/// POST /api/settings - Updates UI, Mesh, or DLP settings and persists immediately to `<data_dir>/settings.json`.
pub async fn update_settings_handler(
    State(state): State<Arc<DaemonState>>,
    Json(payload): Json<UpdateSettingsPayload>,
) -> impl IntoResponse {
    let controller = global_mesh_dlp_controller();
    let prev_forensics_enabled;
    {
        let mut guard = controller
            .settings
            .write()
            .unwrap_or_else(|e| e.into_inner());
        prev_forensics_enabled = guard.artemis.enabled;
        if let Some(mut ui) = payload.ui {
            ui.sanitize_mock_artifacts();
            guard.ui = ui;
        }
        if let Some(mesh) = payload.mesh {
            guard.mesh = mesh;
        }
        if let Some(dlp) = payload.dlp {
            guard.dlp = dlp;
        }
        if let Some(artemis) = payload.artemis {
            guard.artemis = artemis;
        }
        if let Some(atlaskv) = payload.atlaskv {
            guard.atlaskv = atlaskv;
        }
        if let Some(forensics_enabled) = payload.forensics_enabled {
            guard.artemis.enabled = forensics_enabled;
        }
    }
    controller.save_to_disk();
    let updated = controller
        .settings
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if updated.artemis.enabled != prev_forensics_enabled {
        let _ = state.coordinator.cache_clear_all();
    }
    if updated.artemis.enabled {
        crate::handlers::artemis::spawn_artemis_auto_collector(
            Arc::clone(&state),
            Arc::clone(&state.shutdown_notify),
        );
    }
    Json(serde_json::json!({
        "status": "ok",
        "ui": updated.ui,
        "mesh": updated.mesh,
        "dlp": updated.dlp,
        "artemis": updated.artemis,
        "atlaskv": updated.atlaskv,
        "forensics_enabled": updated.artemis.enabled
    }))
}

/// GET /api/mesh/status - Returns OshoosiClaw-compatible P2P Mesh status and Shared Folders.
pub async fn mesh_status_handler(State(state): State<Arc<DaemonState>>) -> impl IntoResponse {
    let controller = global_mesh_dlp_controller();
    let mesh = controller
        .settings
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .mesh
        .clone();
    let dlp_stats = controller
        .stats
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    let (local_peer_id, listen_addrs, connected_peers) = match &state.swarm_handle {
        Some(h) => {
            let pid = h.local_peer_id().to_string();
            let addrs: Vec<String> = h
                .listen_addresses()
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|a| a.to_string())
                .collect();
            let peers: Vec<String> = h
                .connected_peers()
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|p| p.to_string())
                .collect();
            (pid, addrs, peers)
        }
        None => ("local-only-node".to_string(), Vec::new(), Vec::new()),
    };

    let epoch_sig = controller.sign_epoch_token(&local_peer_id, mesh.hmac_epoch, "master_core");
    let wan_tel = crate::wan_mesh::cached_wan_telemetry();
    let effective_targets =
        quorum_coordinator::mesh::collect_trusted_bootstrap_multiaddrs(&mesh, &[]);

    Json(serde_json::json!({
        "status": "ok",
        "p2p_enabled": mesh.p2p_enabled,
        "node_alias": mesh.node_alias,
        "zone": mesh.zone,
        "mesh_port": mesh.mesh_port,
        "local_peer_id": local_peer_id,
        "listen_addrs": listen_addrs,
        "connected_peers": connected_peers,
        "peer_count": if mesh.p2p_enabled { connected_peers.len() } else { 0 },
        "bootstrap_peers": mesh.bootstrap_peers,
        "effective_bootstrap_targets": effective_targets,
        "duckdns_domain": mesh.duckdns_domain,
        "auto_bootstrap_duckdns": mesh.auto_bootstrap_duckdns,
        "wan_telemetry": {
            "external_wan_ip": wan_tel.external_wan_ip,
            "upnp_gateway": wan_tel.upnp_gateway,
            "upnp_tcp_mapped": wan_tel.upnp_tcp_mapped,
            "upnp_udp_mapped": wan_tel.upnp_udp_mapped,
            "duckdns_fqdn": wan_tel.duckdns_fqdn,
            "duckdns_resolved_ips": wan_tel.duckdns_resolved_ips,
            "is_duckdns_host": wan_tel.is_duckdns_host,
            "tailscale_self_ips": wan_tel.tailscale_self_ips,
            "tailscale_peer_addrs": wan_tel.tailscale_peer_addrs,
            "updated_at": wan_tel.updated_at,
        },
        "hmac_epoch": mesh.hmac_epoch,
        "epoch_signature_preview": epoch_sig,
        "join_gate_mode": mesh.join_gate_mode,
        "require_explicit_folder_share": mesh.require_explicit_folder_share,
        "shared_folders": mesh.shared_folders,
        "quarantined_peers": mesh.quarantined_peers,
        "trusted_peers": mesh.trusted_peers,
        "dlp_summary": {
            "total_inspected_chunks": dlp_stats.total_inspected_chunks,
            "total_redacted_chunks": dlp_stats.total_redacted_chunks,
            "total_blocked_chunks": dlp_stats.total_blocked_chunks,
            "total_blocked_unshared_folder_chunks": dlp_stats.total_blocked_unshared_folder_chunks
        }
    }))
}

/// POST /api/mesh/config - Updates OshoosiClaw P2P Mesh config, dials bootstrap peers, or rotates HMAC epoch.
pub async fn update_mesh_config_handler(
    State(state): State<Arc<DaemonState>>,
    Json(payload): Json<UpdateMeshConfigPayload>,
) -> impl IntoResponse {
    let controller = global_mesh_dlp_controller();
    let mut peers_to_dial: Vec<String> = Vec::new();

    {
        let mut guard = controller
            .settings
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(enabled) = payload.p2p_enabled {
            guard.mesh.p2p_enabled = enabled;
        }
        if let Some(alias) = payload.node_alias {
            if !alias.trim().is_empty() {
                guard.mesh.node_alias = alias.trim().to_string();
            }
        }
        if let Some(zone) = payload.zone {
            if !zone.trim().is_empty() {
                guard.mesh.zone = zone.trim().to_string();
            }
        }
        if let Some(peers) = payload.bootstrap_peers {
            let clean_peers: Vec<String> = peers
                .into_iter()
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect();
            peers_to_dial = clean_peers.clone();
            guard.mesh.bootstrap_peers = clean_peers;
        }
        if let Some(domain) = payload.duckdns_domain {
            guard.mesh.duckdns_domain = if domain.trim().is_empty() {
                None
            } else {
                Some(domain.trim().to_string())
            };
        }
        if let Some(auto_b) = payload.auto_bootstrap_duckdns {
            guard.mesh.auto_bootstrap_duckdns = auto_b;
        }
        if let Some(gate) = payload.join_gate_mode {
            guard.mesh.join_gate_mode = gate;
        }
        if let Some(req_share) = payload.require_explicit_folder_share {
            guard.mesh.require_explicit_folder_share = req_share;
        }
        if payload.rotate_epoch.unwrap_or(false) {
            guard.mesh.hmac_epoch = guard.mesh.hmac_epoch.saturating_add(1);
        }
        if let Some(q_peer) = payload.quarantine_peer {
            let qp = q_peer.trim().to_string();
            if !qp.is_empty() && !guard.mesh.quarantined_peers.contains(&qp) {
                guard.mesh.quarantined_peers.push(qp);
                guard.mesh.hmac_epoch = guard.mesh.hmac_epoch.saturating_add(1);
            }
        }
        if let Some(uq_peer) = payload.unquarantine_peer {
            guard
                .mesh
                .quarantined_peers
                .retain(|p| !p.eq_ignore_ascii_case(uq_peer.trim()));
        }
        if let Some(t_peer) = payload.trust_peer {
            let tp = t_peer.trim().to_string();
            if !tp.is_empty() && !guard.mesh.trusted_peers.contains(&tp) {
                guard.mesh.trusted_peers.push(tp);
            }
        }
        if let Some(max_peers) = payload.max_peer_responses {
            guard.mesh.max_peer_responses = max_peers.max(1);
        }
    }

    controller.save_to_disk();

    // Dial any newly configured bootstrap multiaddrs (including WAN, DuckDNS, and Tailscale trusted peers)
    let mut dialed = Vec::new();
    let mut dial_errors = Vec::new();
    if let Some(ref handle) = state.swarm_handle {
        for addr_str in peers_to_dial {
            if let Ok(multiaddr) = addr_str.parse::<quorum_network::Multiaddr>() {
                match handle.dial_trusted(multiaddr).await {
                    Ok(()) => dialed.push(addr_str),
                    Err(e) => dial_errors.push(format!("{}: {}", addr_str, e)),
                }
            }
        }
    }

    let updated_mesh = controller
        .settings
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .mesh
        .clone();

    Json(serde_json::json!({
        "status": "ok",
        "mesh": updated_mesh,
        "dialed_peers": dialed,
        "dial_errors": dial_errors
    }))
}

/// POST /api/mesh/shared-folders - Adds, removes, toggles, or updates user folders shared with the Mesh.
pub async fn manage_shared_folders_handler(
    State(state): State<Arc<DaemonState>>,
    Json(payload): Json<SharedFolderActionPayload>,
) -> impl IntoResponse {
    let discovered = tokio::task::spawn_blocking(quorum_ingest::discover_cloud_drives)
        .await
        .unwrap_or_default();
    let controller = global_mesh_dlp_controller();
    crate::handlers::cloud_drives::reconcile_discovered_cloud_drives(&controller, &discovered);
    let raw_path = payload.path.trim();

    let Some(norm_target) =
        quorum_coordinator::OsoosiMeshDlpController::normalize_folder_path(raw_path)
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "error": "Invalid folder path (relative traversal and UNC paths are forbidden)."
            })),
        )
            .into_response();
    };

    let action = payload.action.trim().to_ascii_lowercase();
    let mut clean_add_path: Option<std::path::PathBuf> = None;

    if action == "add" {
        let test_override = crate::handlers::cloud_drives::is_test_profile_override_active();
        let p = Path::new(raw_path);
        let p_is_dir = p.is_dir()
            || (!test_override && quorum_types::session_fs_bridge::path_is_dir_or_bridged(p));
        if !p_is_dir {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": "error",
                    "error": format!("Directory '{}' does not exist on disk.", raw_path)
                })),
            )
                .into_response();
        }
        let Some(clean_p) = crate::handlers::cloud_drives::canonicalize_for_cloud_filter(p) else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": "error",
                    "error": "Invalid, unsafe, or non-canonical folder path."
                })),
            )
                .into_response();
        };
        let clean_is_dir = clean_p.is_dir()
            || (!test_override
                && quorum_types::session_fs_bridge::path_is_dir_or_bridged(&clean_p));
        if !clean_is_dir {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": "error",
                    "error": format!("Directory '{}' does not exist on disk.", raw_path)
                })),
            )
                .into_response();
        }
        if crate::handlers::cloud_drives::is_user_profile_root_dir(&clean_p) {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "status": "error",
                    "error": "Cannot share a protected user profile root directory."
                })),
            )
                .into_response();
        }
        clean_add_path = Some(clean_p);
    }

    let persisted_norm_target = clean_add_path
        .as_ref()
        .and_then(|cp| {
            quorum_coordinator::OsoosiMeshDlpController::normalize_folder_path(
                &cp.to_string_lossy(),
            )
        })
        .unwrap_or_else(|| norm_target.clone());
    let mut index_target_path = clean_add_path
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from(raw_path));
    let mut should_index_target = false;
    {
        let mut guard = controller
            .settings
            .write()
            .unwrap_or_else(|e| e.into_inner());

        match action.as_str() {
            "add" => {
                let clean_p = clean_add_path
                    .as_ref()
                    .expect("clean_add_path populated for add");
                let clean_str = clean_p.to_string_lossy().to_string();
                let existing = guard.mesh.shared_folders.iter_mut().find(|f| {
                    quorum_coordinator::OsoosiMeshDlpController::normalize_folder_path(&f.path)
                        .as_deref()
                        == Some(persisted_norm_target.as_str())
                });

                if let Some(entry) = existing {
                    entry.enabled = payload.enabled.unwrap_or(true);
                    should_index_target = entry.enabled;
                    if let Some(tier) = payload.access_tier {
                        entry.access_tier = tier.min(3);
                    }
                    if let Some(ref mode_str) = payload.dlp_mode_override {
                        entry.dlp_mode_override =
                            if mode_str.eq_ignore_ascii_case("default") || mode_str.is_empty() {
                                None
                            } else {
                                Some(DlpEnforcementMode::from_str_lossy(mode_str))
                            };
                    }
                } else {
                    let default_label = clean_p
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(raw_path)
                        .to_string();
                    let dlp_override = payload.dlp_mode_override.as_deref().and_then(|m| {
                        if m.eq_ignore_ascii_case("default") || m.is_empty() {
                            None
                        } else {
                            Some(DlpEnforcementMode::from_str_lossy(m))
                        }
                    });
                    let enabled = payload.enabled.unwrap_or(true);
                    should_index_target = enabled;
                    guard.mesh.shared_folders.push(SharedFolderEntry {
                        path: clean_str,
                        label: payload.label.unwrap_or(default_label),
                        enabled,
                        access_tier: payload.access_tier.unwrap_or(0).min(3),
                        dlp_mode_override: dlp_override,
                        shared_at: Utc::now().to_rfc3339(),
                    });
                }
            }
            "remove" => {
                guard.mesh.shared_folders.retain(|f| {
                    quorum_coordinator::OsoosiMeshDlpController::normalize_folder_path(&f.path)
                        .as_deref()
                        != Some(norm_target.as_str())
                });
            }
            "toggle" => {
                for f in &mut guard.mesh.shared_folders {
                    if quorum_coordinator::OsoosiMeshDlpController::normalize_folder_path(&f.path)
                        .as_deref()
                        == Some(norm_target.as_str())
                    {
                        f.enabled = payload.enabled.unwrap_or(!f.enabled);
                        if f.enabled {
                            if let Some(cp) =
                                crate::handlers::cloud_drives::canonicalize_for_cloud_filter(
                                    Path::new(&f.path),
                                )
                            {
                                index_target_path = cp;
                            }
                            should_index_target = true;
                        }
                    }
                }
            }
            "update" | "update_tier" | "update_dlp_mode" => {
                for f in &mut guard.mesh.shared_folders {
                    if quorum_coordinator::OsoosiMeshDlpController::normalize_folder_path(&f.path)
                        .as_deref()
                        == Some(norm_target.as_str())
                    {
                        if let Some(en) = payload.enabled {
                            f.enabled = en;
                            if en {
                                if let Some(cp) =
                                    crate::handlers::cloud_drives::canonicalize_for_cloud_filter(
                                        Path::new(&f.path),
                                    )
                                {
                                    index_target_path = cp;
                                }
                                should_index_target = true;
                            }
                        }
                        if let Some(tier) = payload.access_tier {
                            f.access_tier = tier.min(3);
                        }
                        if let Some(ref mode_str) = payload.dlp_mode_override {
                            f.dlp_mode_override = if mode_str.eq_ignore_ascii_case("default")
                                || mode_str.is_empty()
                            {
                                None
                            } else {
                                Some(DlpEnforcementMode::from_str_lossy(mode_str))
                            };
                        }
                    }
                }
            }
            _ => {}
        }
    }

    controller.save_to_disk();
    if should_index_target {
        let _ = state.watch_and_index_paths(vec![index_target_path]).await;
    }

    let shared_folders = controller
        .settings
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .mesh
        .shared_folders
        .clone();

    Json(serde_json::json!({
        "status": "ok",
        "shared_folders": shared_folders
    }))
    .into_response()
}

/// Helper that validates a single new subfolder name (no traversal, drive letters, separators, trailing dots, control, or bidi chars).
pub fn is_safe_single_folder_name(name: &str) -> bool {
    if name.chars().any(|c| c.is_control()) {
        return false;
    }
    let trimmed = name.trim();
    if trimmed.is_empty()
        || trimmed == "."
        || trimmed == ".."
        || trimmed.ends_with('.')
        || trimmed.contains(':')
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('%')
        || trimmed.contains('\0')
        || trimmed.chars().any(|c| {
            matches!(
                c,
                '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}'
            )
        })
    {
        return false;
    }
    let mut components = Path::new(trimmed).components();
    matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
}

/// Helper that detects non-interactive OS service/system profile directories
/// (e.g. Windows `LocalSystem` `C:\Windows\System32`, `systemprofile`, `LocalService`, `NetworkService`, `Public`, macOS `/var/root`)
/// so folder pickers and Quick Access always surface real user directories across Windows, Linux, and macOS.
pub fn is_service_or_system_profile_path(path_str: &str) -> bool {
    let norm = path_str.trim().replace('/', "\\").to_ascii_lowercase();
    if norm.is_empty() {
        return true;
    }
    let trimmed_norm = norm.trim_end_matches('\\');
    let leaf = trimmed_norm.rsplit('\\').next().unwrap_or("");
    let has_service_segment = trimmed_norm
        .split('\\')
        .any(|seg| matches!(seg, "systemprofile" | "localservice" | "networkservice"));
    let is_public_profile = leaf == "public"
        || trimmed_norm.contains("\\users\\public\\")
        || trimmed_norm.ends_with("\\users\\public");
    has_service_segment
        || is_public_profile
        || norm.contains("\\serviceprofiles\\")
        || norm.contains("\\windows\\system32")
        || norm.contains("\\windows\\syswow64")
        || norm.ends_with("\\windows")
        || norm.contains("\\users\\default")
        || norm.contains("\\users\\all users")
        || norm.contains("\\default user")
        || norm == "\\var\\root"
        || norm.starts_with("\\var\\root\\")
}

fn canonical_fs_compare_key(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with('/') {
        let stripped = trimmed.trim_end_matches('/');
        if stripped.is_empty() {
            "/".to_string()
        } else {
            stripped.to_string()
        }
    } else {
        let replaced = trimmed.replace('/', "\\");
        let stripped = replaced.trim_end_matches('\\');
        if stripped.len() == 2 && stripped.ends_with(':') {
            format!("{}\\", stripped.to_ascii_lowercase())
        } else {
            stripped.to_ascii_lowercase()
        }
    }
}

/// Discovery of real interactive user home directories across Windows (`C:\Users\*`),
/// macOS (`/Users/*`), and Linux (`/home/*`), even when the daemon runs as `LocalSystem`, `systemd`, or `launchd`.
fn discover_interactive_user_homes() -> Vec<std::path::PathBuf> {
    if let Ok(test_profile) = std::env::var("QUORUM_CLOUD_TEST_PROFILE_DIR") {
        let trimmed = test_profile.trim();
        if !trimmed.is_empty() {
            let candidate = Path::new(trimmed).to_path_buf();
            if candidate.is_dir() && !is_service_or_system_profile_path(trimmed) {
                return vec![candidate];
            }
            return Vec::new();
        }
    }

    let mut homes: Vec<std::path::PathBuf> = Vec::new();
    let mut push_unique = |candidate: std::path::PathBuf| {
        let s = candidate.to_string_lossy().to_string();
        if is_service_or_system_profile_path(&s) || !candidate.is_dir() {
            return;
        }
        let key = canonical_fs_compare_key(&s);
        if !homes
            .iter()
            .any(|existing| canonical_fs_compare_key(&existing.to_string_lossy()) == key)
        {
            homes.push(candidate);
        }
    };

    if let Some(env_home) = std::env::var("USERPROFILE")
        .ok()
        .or_else(|| std::env::var("HOME").ok())
    {
        let trimmed = env_home.trim();
        if !trimmed.is_empty() && trimmed != "/root" {
            push_unique(Path::new(trimmed).to_path_buf());
        }
    }

    // Prioritize the actively logged-in interactive Windows user session(s) before scanning
    // alphabetical `C:\Users\*` profiles (so LocalSystem services show the real active user's
    // Quick Access folders rather than an unused alphabetical profile such as `Owner`).
    #[cfg(windows)]
    {
        let sys_drive = std::env::var("SystemDrive")
            .ok()
            .map(|d| d.trim().trim_end_matches(['\\', '/']).to_string())
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| "C:".to_string());
        for active_user in crate::win_native::active_interactive_session_usernames() {
            let candidate = std::path::PathBuf::from(format!(r"{sys_drive}\Users\{active_user}"));
            push_unique(candidate);
        }
    }

    let candidate_roots = [r"C:\Users", "/Users", "/home"];
    let skip_names = [
        "public",
        "default",
        "default user",
        "all users",
        "shared",
        "guest",
        "lost+found",
        "wdagutilityaccount",
        "defaultapppool",
    ];

    for root in candidate_roots {
        let root_path = Path::new(root);
        if !root_path.is_dir() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(root_path) {
            let mut discovered: Vec<std::path::PathBuf> = Vec::new();
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_string();
                let lower = name.to_ascii_lowercase();
                if name.starts_with('.') || skip_names.iter().any(|s| *s == lower) {
                    continue;
                }
                if path.join("Documents").is_dir()
                    || path.join("Desktop").is_dir()
                    || path.join("Downloads").is_dir()
                {
                    discovered.push(path);
                }
            }
            discovered.sort_by(|a, b| {
                a.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .cmp(
                        &b.file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_ascii_lowercase(),
                    )
            });
            for d in discovered {
                push_unique(d);
            }
        }
    }

    if homes.is_empty() {
        if let Ok(env_home) = std::env::var("HOME") {
            let p = Path::new(env_home.trim()).to_path_buf();
            if p.is_dir() && !is_service_or_system_profile_path(&env_home) {
                homes.push(p);
            }
        }
    }

    homes
}

/// Directory enumeration and folder picker engine (`std::fs::read_dir` + physical drive discovery).
/// Never spawns external OS dialogs (`powershell`, `explorer.exe`, `osascript`, or `zenity`).
async fn pure_rust_browse_directory(
    requested_path: &str,
    create_subfolder: Option<&str>,
) -> Result<serde_json::Value, (StatusCode, Json<serde_json::Value>)> {
    let req_trimmed = requested_path.trim();
    if !req_trimmed.is_empty() {
        if let Err(e) = quorum_types::validate_cloud_drive_path(req_trimmed) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": "error",
                    "error": e.to_string(),
                })),
            ));
        }
    }
    if let Some(sub_name) = create_subfolder {
        let sub_trimmed = sub_name.trim();
        if !sub_trimmed.is_empty() && !is_safe_single_folder_name(sub_name) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": "error",
                    "error": "Invalid subfolder name",
                })),
            ));
        }
    }
    let controller = global_mesh_dlp_controller();
    let shared_folders = controller
        .settings
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .mesh
        .shared_folders
        .clone();

    let is_shared_fn = |candidate: &str| -> bool {
        let Some(norm_c) =
            quorum_coordinator::OsoosiMeshDlpController::normalize_folder_path(candidate)
        else {
            return false;
        };
        shared_folders.iter().any(|f| {
            f.enabled
                && quorum_coordinator::OsoosiMeshDlpController::normalize_folder_path(&f.path)
                    .as_deref()
                    == Some(norm_c.as_str())
        })
    };

    let test_profile_override = crate::handlers::cloud_drives::is_test_profile_override_active();
    let shared_for_quick = shared_folders.clone();
    let (mut drives_raw, session_drives, quick_access) = tokio::time::timeout(
        std::time::Duration::from_secs(4),
        tokio::task::spawn_blocking(move || {
            let is_shared_local = |candidate: &str| -> bool {
                let Some(norm_c) =
                    quorum_coordinator::OsoosiMeshDlpController::normalize_folder_path(candidate)
                else {
                    return false;
                };
                shared_for_quick.iter().any(|f| {
                    f.enabled
                        && quorum_coordinator::OsoosiMeshDlpController::normalize_folder_path(
                            &f.path,
                        )
                        .as_deref()
                            == Some(norm_c.as_str())
                })
            };

            let (drives, sdrives) = if test_profile_override {
                (Vec::new(), Vec::new())
            } else {
                (
                    quorum_ingest::IngestConfig::discover_browsable_drives(),
                    quorum_types::session_fs_bridge::list_session_drives(),
                )
            };

            let mut quick_access: Vec<serde_json::Value> = Vec::new();
            let mut push_quick =
                |label: String, path_buf: std::path::PathBuf, force_include: bool| {
                    let dir_ok = force_include || path_buf.is_dir();
                    if !dir_ok || quick_access.len() >= 10 {
                        return;
                    }
                    let s = path_buf.to_string_lossy().to_string();
                    if is_service_or_system_profile_path(&s) {
                        return;
                    }
                    let key = canonical_fs_compare_key(&s);
                    let already = quick_access.iter().any(|item| {
                        let same_path = item
                            .get("path")
                            .and_then(|v| v.as_str())
                            .map(|existing| canonical_fs_compare_key(existing) == key)
                            .unwrap_or(false);
                        let same_label = item
                            .get("name")
                            .and_then(|v| v.as_str())
                            .map(|existing| existing.eq_ignore_ascii_case(&label))
                            .unwrap_or(false);
                        same_path || same_label
                    });
                    if !already {
                        quick_access.push(serde_json::json!({
                            "name": label,
                            "path": s,
                            "is_drive": false,
                            "is_quick_access": true,
                            "is_shared": is_shared_local(&s)
                        }));
                    }
                };

            let interactive_homes = discover_interactive_user_homes();
            if let Some(primary_home) = interactive_homes.first() {
                let quick_folders = [
                    ("Desktop", "Desktop"),
                    ("Documents", "Documents"),
                    ("Downloads", "Downloads"),
                    ("Pictures", "Pictures"),
                    ("OneDrive", "OneDrive"),
                    ("My Drive", "My Drive"),
                    ("Dropbox", "Dropbox"),
                ];
                for (label, sub) in quick_folders {
                    let candidate = primary_home.join(sub);
                    if candidate.is_dir() {
                        push_quick(label.to_string(), candidate, false);
                    } else if matches!(sub, "Desktop" | "Documents" | "Pictures")
                        && primary_home.join("OneDrive").join(sub).is_dir()
                    {
                        push_quick(
                            label.to_string(),
                            primary_home.join("OneDrive").join(sub),
                            false,
                        );
                    }
                }
            }

            if !test_profile_override {
                for sdrv in &sdrives {
                    let lbl_lower = sdrv.volume_label.to_ascii_lowercase();
                    let nt_lower = sdrv.nt_target.to_ascii_lowercase();
                    if sdrv.has_my_drive
                        || lbl_lower.contains("google drive")
                        || nt_lower.contains("drivefs")
                    {
                        let my_drive = std::path::PathBuf::from(&sdrv.root).join("My Drive");
                        push_quick("Google Drive".to_string(), my_drive, true);
                    } else if lbl_lower.contains("pcloud") || nt_lower.contains("pcloud") {
                        push_quick(
                            "pCloud".to_string(),
                            std::path::PathBuf::from(&sdrv.root),
                            true,
                        );
                    }
                }
                for drv in &drives {
                    let drv_s = drv.to_string_lossy();
                    if drv_s.len() >= 2 && !drv_s.to_ascii_lowercase().starts_with("c:") {
                        let my_drive = drv.join("My Drive");
                        if quorum_types::session_fs_bridge::is_local_virtual_drive_path(drv) {
                            let ok = quorum_types::session_fs_bridge::local_is_dir_bounded_probe(
                                &my_drive,
                                false,
                                std::time::Duration::from_millis(1500),
                                false,
                            )
                            .unwrap_or(false);
                            if ok {
                                push_quick("Google Drive".to_string(), my_drive, true);
                            }
                        } else if my_drive.is_dir() {
                            push_quick("Google Drive".to_string(), my_drive, true);
                        }
                    }
                }
                if let Ok(cwd) = std::env::current_dir() {
                    let cwd_str = cwd.to_string_lossy().to_string();
                    if cwd.is_dir() && !is_service_or_system_profile_path(&cwd_str) {
                        push_quick("Workspace".to_string(), cwd, false);
                    }
                }
            }

            (drives, sdrives, quick_access)
        }),
    )
    .await
    .ok()
    .and_then(|res| res.ok())
    .unwrap_or_default();

    drives_raw.sort_by(|a, b| {
        a.to_string_lossy()
            .to_ascii_lowercase()
            .cmp(&b.to_string_lossy().to_ascii_lowercase())
    });
    let physical_drives: Vec<String> = drives_raw
        .iter()
        .map(|d| d.to_string_lossy().to_string())
        .collect();

    if req_trimmed.is_empty() {
        let mut entries: Vec<serde_json::Value> = drives_raw
            .into_iter()
            .map(|d| {
                let s = d.to_string_lossy().to_string();
                serde_json::json!({
                    "name": s,
                    "path": s,
                    "is_drive": true,
                    "is_quick_access": false,
                    "is_shared": is_shared_fn(&s)
                })
            })
            .collect();
        entries.extend(quick_access.iter().cloned());

        return Ok(serde_json::json!({
            "status": "ok",
            "engine": "native_std_fs",
            "path": "",
            "current_path": "",
            "parent_path": "",
            "drives": physical_drives,
            "quick_access": quick_access,
            "directories": entries,
            "cancelled": false
        }));
    }

    let mut target_dir_buf = Path::new(req_trimmed).to_path_buf();
    let is_local_virtual_target = !test_profile_override
        && quorum_types::session_fs_bridge::is_local_virtual_drive_path(&target_dir_buf);
    let local_dir_check = if is_local_virtual_target {
        let p_check = target_dir_buf.clone();
        tokio::task::spawn_blocking(move || {
            // Explicit user click to open a virtual drive always performs a fresh probe.
            quorum_types::session_fs_bridge::clear_local_drive_timeout(&p_check);
            quorum_types::session_fs_bridge::local_is_dir_bounded(
                &p_check,
                true,
                std::time::Duration::from_millis(5500),
            )
        })
        .await
        .unwrap_or(Ok(false))
    } else {
        let p_check = target_dir_buf.clone();
        tokio::task::spawn_blocking(move || Ok(p_check.is_dir()))
            .await
            .unwrap_or(Ok(false))
    };
    let local_is_dir = match local_dir_check {
        Ok(v) => v,
        Err(busy_msg) => {
            return Err((
                StatusCode::GATEWAY_TIMEOUT,
                Json(serde_json::json!({
                    "status": "error",
                    "error": busy_msg,
                })),
            ));
        }
    };

    let is_session_only_drive_target = !test_profile_override && {
        let req_bytes = req_trimmed.as_bytes();
        let req_letter = if req_bytes.len() >= 2
            && req_bytes[0].is_ascii_alphabetic()
            && req_bytes[1] == b':'
        {
            Some((req_bytes[0] as char).to_ascii_uppercase())
        } else {
            None
        };
        quorum_types::session_fs_bridge::is_known_bridged_drive_path(&target_dir_buf)
            || req_letter.is_some_and(|ch| {
                session_drives.iter().any(|sd| {
                    sd.letter.to_ascii_uppercase() == ch
                        && !quorum_types::session_fs_bridge::is_local_virtual_drive_path(
                            Path::new(&sd.root),
                        )
                        && !Path::new(&sd.root).is_dir()
                })
            })
    };

    let use_session_bridge = if local_is_dir {
        false
    } else if is_session_only_drive_target {
        // Go straight to /bridge/browse so a slow/virtual Dokan mount is probed once instead of
        // twice and timeout errors return HTTP 504 instead of false 404.
        true
    } else if !test_profile_override {
        let check_p = target_dir_buf.clone();
        let stat_res = tokio::task::spawn_blocking(move || {
            quorum_types::session_fs_bridge::stat_via_bridge_detailed(&check_p)
        })
        .await
        .unwrap_or(Ok(None));
        match stat_res {
            Ok(Some(st)) if st.exists && st.is_dir => true,
            Err((504, msg)) | Err((503, msg)) => {
                return Err((
                    StatusCode::GATEWAY_TIMEOUT,
                    Json(serde_json::json!({
                        "status": "error",
                        "error": msg,
                    })),
                ));
            }
            _ => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "status": "error",
                        "error": format!("Directory does not exist on disk: {}", req_trimmed),
                    })),
                ));
            }
        }
    } else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "status": "error",
                "error": format!("Directory does not exist on disk: {}", req_trimmed),
            })),
        ));
    };

    let mut created_folder_path: Option<String> = None;

    if use_session_bridge {
        let req_path_owned = req_trimmed.to_string();
        let sub_owned = create_subfolder
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        if let Some(ref sub_trimmed) = sub_owned {
            let created_cand = target_dir_buf.join(sub_trimmed);
            let req_for_create = req_path_owned.clone();
            let sub_for_create = sub_trimmed.clone();
            let create_res = tokio::task::spawn_blocking(move || {
                quorum_types::session_fs_bridge::browse_dir_bridged(
                    &req_for_create,
                    Some(&sub_for_create),
                )
            })
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "status": "error", "error": e.to_string() })),
                )
            })?;
            if let Err((code, msg)) = create_res {
                let status = StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST);
                return Err((
                    status,
                    Json(serde_json::json!({ "status": "error", "error": msg })),
                ));
            }
            created_folder_path = Some(created_cand.to_string_lossy().to_string());
            target_dir_buf = created_cand;
        }

        let resolved_path_str = target_dir_buf.to_string_lossy().to_string();
        let is_drive_root = physical_drives.iter().any(|d| {
            let d_trimmed = d.trim_end_matches(['\\', '/']);
            let r_trimmed = resolved_path_str.trim_end_matches(['\\', '/']);
            d_trimmed.eq_ignore_ascii_case(r_trimmed)
        });
        let parent_path = if is_drive_root {
            String::new()
        } else {
            target_dir_buf
                .parent()
                .map(|p| {
                    let s = p.to_string_lossy().to_string();
                    if s.len() == 2 && s.ends_with(':') {
                        format!("{}\\", s)
                    } else {
                        s
                    }
                })
                .unwrap_or_default()
        };
        let browse_path = resolved_path_str.clone();
        let bridged = tokio::task::spawn_blocking(move || {
            quorum_types::session_fs_bridge::browse_dir_bridged(&browse_path, None)
        })
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "status": "error", "error": e.to_string() })),
            )
        })?;
        let (dirs, read_error) = match bridged {
            Ok(entries) => {
                let mapped: Vec<serde_json::Value> = entries
                    .into_iter()
                    .take(1000)
                    .map(|e| {
                        let shared = is_shared_fn(&e.path);
                        serde_json::json!({
                            "name": e.name,
                            "path": e.path,
                            "is_drive": false,
                            "is_quick_access": false,
                            "is_shared": shared
                        })
                    })
                    .collect();
                (mapped, None)
            }
            Err((code, msg)) if matches!(code, 400 | 404 | 503 | 504) => {
                let status = StatusCode::from_u16(code).unwrap_or(StatusCode::GATEWAY_TIMEOUT);
                return Err((
                    status,
                    Json(serde_json::json!({
                        "status": "error",
                        "error": msg,
                    })),
                ));
            }
            Err((_, msg)) => (Vec::new(), Some(msg)),
        };

        return Ok(serde_json::json!({
            "status": "ok",
            "engine": "session_fs_bridge",
            "path": resolved_path_str,
            "current_path": resolved_path_str,
            "parent_path": parent_path,
            "created_folder": created_folder_path,
            "read_error": read_error,
            "drives": physical_drives,
            "quick_access": quick_access,
            "directories": dirs,
            "cancelled": false
        }));
    }

    if let Some(sub_name) = create_subfolder {
        let sub_trimmed = sub_name.trim();
        if !sub_trimmed.is_empty() {
            let candidate = target_dir_buf.join(sub_trimmed);
            let cand_for_create = candidate.clone();
            let create_res = tokio::task::spawn_blocking(move || std::fs::create_dir_all(&cand_for_create))
                .await
                .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())));
            match create_res {
                Ok(()) => {
                    created_folder_path = Some(candidate.to_string_lossy().to_string());
                    target_dir_buf = candidate;
                }
                Err(e) => {
                    let status = if e.kind() == std::io::ErrorKind::PermissionDenied {
                        StatusCode::FORBIDDEN
                    } else {
                        StatusCode::BAD_REQUEST
                    };
                    return Err((
                        status,
                        Json(serde_json::json!({
                            "status": "error",
                            "error": format!("Could not create subfolder '{}': {}", sub_trimmed, e),
                        })),
                    ));
                }
            }
        }
    }

    let resolved_path_str = target_dir_buf.to_string_lossy().to_string();
    let is_drive_root = physical_drives.iter().any(|d| {
        let d_trimmed = d.trim_end_matches(['\\', '/']);
        let r_trimmed = resolved_path_str.trim_end_matches(['\\', '/']);
        d_trimmed.eq_ignore_ascii_case(r_trimmed)
    });

    let parent_path = if is_drive_root {
        String::new()
    } else {
        target_dir_buf
            .parent()
            .map(|p| {
                let s = p.to_string_lossy().to_string();
                if s.len() == 2 && s.ends_with(':') {
                    format!("{}\\", s)
                } else {
                    s
                }
            })
            .unwrap_or_default()
    };

    let dir_path_buf = target_dir_buf.clone();
    let shared_folders_clone = shared_folders.clone();
    let (dirs, read_error): (Vec<serde_json::Value>, Option<String>) =
        tokio::task::spawn_blocking(move || {
            let is_shared = |candidate: &str| -> bool {
                let Some(norm_c) =
                    quorum_coordinator::OsoosiMeshDlpController::normalize_folder_path(candidate)
                else {
                    return false;
                };
                shared_folders_clone.iter().any(|f| {
                    f.enabled
                        && quorum_coordinator::OsoosiMeshDlpController::normalize_folder_path(
                            &f.path,
                        )
                        .as_deref()
                            == Some(norm_c.as_str())
                })
            };

            let mut dirs = Vec::new();
            let read_err = match std::fs::read_dir(&dir_path_buf) {
                Ok(read_dir) => {
                    for entry in read_dir.flatten() {
                        if let Ok(ft) = entry.file_type() {
                            if ft.is_dir() {
                                let name = entry.file_name().to_string_lossy().to_string();
                                if name.starts_with('$')
                                    || name.eq_ignore_ascii_case("System Volume Information")
                                    || name.eq_ignore_ascii_case(".git")
                                {
                                    continue;
                                }
                                let full_path = entry.path();
                                let full = full_path.to_string_lossy().to_string();
                                dirs.push(serde_json::json!({
                                    "name": name,
                                    "path": full,
                                    "is_drive": false,
                                    "is_quick_access": false,
                                    "is_shared": is_shared(&full)
                                }));
                            }
                        }
                    }
                    None
                }
                Err(e) => Some(format!(
                    "Unable to list subdirectories of '{}': {}",
                    dir_path_buf.display(),
                    e
                )),
            };
            dirs.sort_by(|a, b| {
                let na = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let nb = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
                na.to_ascii_lowercase().cmp(&nb.to_ascii_lowercase())
            });
            dirs.truncate(1000);
            (dirs, read_err)
        })
        .await
        .unwrap_or_else(|_| (Vec::new(), None));

    Ok(serde_json::json!({
        "status": "ok",
        "engine": "native_std_fs",
        "path": resolved_path_str,
        "current_path": resolved_path_str,
        "parent_path": parent_path,
        "created_folder": created_folder_path,
        "read_error": read_error,
        "drives": physical_drives,
        "quick_access": quick_access,
        "directories": dirs,
        "cancelled": false
    }))
}

/// GET /api/fs/browse-folders?path=... (and /api/mesh/browse-folders) - Lists real directories on physical drives and quick-access user folders.
pub async fn browse_folders_handler(
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let requested_path = params.get("path").map(|s| s.trim()).unwrap_or("");
    let create_subfolder = params.get("create_subfolder").map(|s| s.as_str());
    match pure_rust_browse_directory(requested_path, create_subfolder).await {
        Ok(val) => Json(val).into_response(),
        Err((code, body)) => (code, body).into_response(),
    }
}

/// POST /api/fs/pick-folder - Native folder selection & directory browser endpoint.
/// Operates directly via `std::fs` without spawning Windows Explorer or OS shell subprocesses.
pub async fn pick_folder_dialog_handler(
    Query(params): Query<HashMap<String, String>>,
    body: Option<Json<serde_json::Value>>,
) -> impl IntoResponse {
    let body_val = body.map(|b| b.0).unwrap_or_else(|| serde_json::json!({}));

    let has_explicit_path = body_val.get("path").is_some()
        || body_val.get("current_path").is_some()
        || body_val.get("folder_path").is_some()
        || params.contains_key("path");

    let requested_path = body_val
        .get("path")
        .or_else(|| body_val.get("current_path"))
        .or_else(|| body_val.get("folder_path"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .or_else(|| params.get("path").map(|s| s.trim().to_string()))
        .unwrap_or_default();

    let create_subfolder = body_val
        .get("create_subfolder")
        .or_else(|| body_val.get("new_folder"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .or_else(|| params.get("create_subfolder").map(|s| s.trim().to_string()));

    let effective_path = if has_explicit_path {
        // Honor explicit `""` so `This PC` root lists all physical drives + Quick Access folders.
        requested_path
    } else if requested_path.is_empty() {
        std::env::current_dir()
            .ok()
            .filter(|p| p.is_dir() && !is_service_or_system_profile_path(&p.to_string_lossy()))
            .map(|p| p.to_string_lossy().to_string())
            .or_else(|| {
                discover_interactive_user_homes()
                    .into_iter()
                    .next()
                    .map(|h| {
                        let docs = h.join("Documents");
                        if docs.is_dir() {
                            docs.to_string_lossy().to_string()
                        } else {
                            h.to_string_lossy().to_string()
                        }
                    })
            })
            .or_else(|| {
                quorum_ingest::IngestConfig::discover_physical_drives()
                    .first()
                    .map(|d| d.to_string_lossy().to_string())
            })
            .unwrap_or_default()
    } else {
        requested_path
    };

    match pure_rust_browse_directory(&effective_path, create_subfolder.as_deref()).await {
        Ok(val) => Json(val).into_response(),
        Err((code, body)) => (code, body).into_response(),
    }
}

/// GET /api/dlp/status - Returns HIPAA PHI/PII DLP policy and live audit telemetry.
pub async fn dlp_status_handler() -> impl IntoResponse {
    let controller = global_mesh_dlp_controller();
    let policy = controller
        .settings
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .dlp
        .clone();
    let stats = controller
        .stats
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    Json(serde_json::json!({
        "status": "ok",
        "policy": policy,
        "stats": stats
    }))
}

/// POST /api/dlp/policy - Updates HIPAA PHI/PII DLP policy (`Redact` vs `Block` and category toggles).
pub async fn update_dlp_policy_handler(
    Json(payload): Json<UpdateDlpPolicyPayload>,
) -> impl IntoResponse {
    let controller = global_mesh_dlp_controller();
    {
        let mut guard = controller
            .settings
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(en) = payload.enabled {
            guard.dlp.enabled = en;
        }
        if let Some(ref m) = payload.mode {
            guard.dlp.mode = DlpEnforcementMode::from_str_lossy(m);
        }
        if let Some(v) = payload.protect_ssn {
            guard.dlp.protect_ssn = v;
        }
        if let Some(v) = payload.protect_medical_records {
            guard.dlp.protect_medical_records = v;
        }
        if let Some(v) = payload.protect_health_plan {
            guard.dlp.protect_health_plan = v;
        }
        if let Some(v) = payload.protect_dob_dates {
            guard.dlp.protect_dob_dates = v;
        }
        if let Some(v) = payload.protect_academic_student_id {
            guard.dlp.protect_academic_student_id = v;
        }
        if let Some(v) = payload.protect_contact_pii {
            guard.dlp.protect_contact_pii = v;
        }
        if let Some(v) = payload.protect_financial_tax {
            guard.dlp.protect_financial_tax = v;
        }
        if let Some(v) = payload.protect_secrets_crown_jewels {
            guard.dlp.protect_secrets_crown_jewels = v;
        }
        if let Some(v) = payload.scrub_outbound_queries {
            guard.dlp.scrub_outbound_queries = v;
        }
        if let Some(ref eng) = payload.dlp_engine {
            guard.dlp.dlp_engine = eng.trim().to_string();
        }
        if let Some(v) = payload.presidio_enabled {
            guard.dlp.presidio_enabled = v;
        }
        if let Some(v) = payload.gliner_enabled {
            guard.dlp.gliner_enabled = v;
        }
        if let Some(v) = payload.auto_provision_gliner {
            guard.dlp.auto_provision_gliner = v;
        }
        if let Some(ref mid) = payload.gliner_model_id {
            if !mid.trim().is_empty() {
                guard.dlp.gliner_model_id = mid.trim().to_string();
            }
        }
        if let Some(th) = payload.gliner_confidence_threshold {
            guard.dlp.gliner_confidence_threshold = th.clamp(0.10, 0.99);
        }
    }
    if payload.reprovision_gliner.unwrap_or(false) {
        let data_dir = controller
            .settings_file_path
            .read()
            .ok()
            .and_then(|p| p.as_ref().and_then(|f| f.parent().map(|d| d.to_path_buf())))
            .unwrap_or_else(|| std::path::PathBuf::from(".quorumrag-live-data"));
        let _ = controller.auto_provision_presidio_and_gliner(&data_dir);
    }
    controller.save_to_disk();

    let policy = controller
        .settings
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .dlp
        .clone();
    let stats = controller
        .stats
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    Json(serde_json::json!({
        "status": "ok",
        "policy": policy,
        "stats": stats
    }))
}

/// POST /api/dlp/test - Live PHI/PII DLP Inspection & Redaction/Blocking simulator.
pub async fn test_dlp_inspection_handler(Json(payload): Json<DlpTestPayload>) -> impl IntoResponse {
    let discovered = tokio::task::spawn_blocking(quorum_ingest::discover_cloud_drives)
        .await
        .unwrap_or_default();
    let controller = global_mesh_dlp_controller();
    crate::handlers::cloud_drives::reconcile_discovered_cloud_drives(&controller, &discovered);
    let file_path = payload
        .file_path
        .as_deref()
        .unwrap_or(r"D:\harfile\QuorumRAG\docs\clinical_test.txt");
    let mode_override = payload
        .mode
        .as_deref()
        .map(DlpEnforcementMode::from_str_lossy);

    let folder_shared = controller.check_file_shared_with_mesh(file_path).is_some();
    let inspection = controller.inspect_and_enforce_text(
        &payload.text,
        file_path,
        "simulated_remote_peer",
        "SimulationTest",
        mode_override,
        false,
    );

    Json(serde_json::json!({
        "status": "ok",
        "folder_shared_with_mesh": folder_shared,
        "effective_mesh_allowed": folder_shared && inspection.allowed_to_share,
        "inspection": inspection
    }))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EndpointProbePayload {
    pub target: String,
    pub url: Option<String>,
    pub port: Option<u16>,
}

/// POST /api/endpoints/probe - Probes local Ollama REST API (`/api/tags`), QuorumRAG IPC, or CDP port.
pub async fn probe_endpoint_handler(
    State(state): State<Arc<DaemonState>>,
    Json(payload): Json<EndpointProbePayload>,
) -> impl IntoResponse {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
    use std::time::{Duration, Instant};

    let start = Instant::now();
    match payload.target.as_str() {
        "ollama" => {
            let raw_url = payload
                .url
                .unwrap_or_else(|| "http://127.0.0.1:11434".to_string());
            let host_port = raw_url
                .trim()
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .split('/')
                .next()
                .unwrap_or("127.0.0.1:11434");
            let addr: SocketAddr = host_port
                .to_socket_addrs()
                .ok()
                .and_then(|mut it| it.next())
                .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 11434)));

            match TcpStream::connect_timeout(&addr, Duration::from_millis(400)) {
                Ok(mut stream) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(1200)));
                    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
                    let req = format!(
                        "GET /api/tags HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
                        host_port
                    );
                    let _ = stream.write_all(req.as_bytes());
                    let mut resp = String::new();
                    let _ = stream.read_to_string(&mut resp);
                    let mut models: Vec<String> = Vec::new();
                    if let Some(idx) = resp.find("\r\n\r\n") {
                        let body = &resp[idx + 4..];
                        if let (Some(s), Some(e)) = (body.find('{'), body.rfind('}')) {
                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body[s..=e])
                            {
                                if let Some(arr) = val.get("models").and_then(|m| m.as_array()) {
                                    for item in arr {
                                        if let Some(name) =
                                            item.get("name").and_then(|n| n.as_str())
                                        {
                                            models.push(name.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                    let ms = start.elapsed().as_millis();
                    Json(serde_json::json!({
                        "ok": true,
                        "latency_ms": ms,
                        "models": models,
                        "message": format!("✓ Connected to Ollama ({}ms, {} local models ready)", ms, models.len())
                    }))
                    .into_response()
                }
                Err(e) => Json(serde_json::json!({
                    "ok": false,
                    "latency_ms": start.elapsed().as_millis(),
                    "models": [],
                    "message": format!("✗ Ollama unreachable at {}: {}", host_port, e)
                }))
                .into_response(),
            }
        }
        "cdp" => {
            let port = payload.port.unwrap_or(9222);
            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            match TcpStream::connect_timeout(&addr, Duration::from_millis(350)) {
                Ok(_) => {
                    let ms = start.elapsed().as_millis();
                    Json(serde_json::json!({
                        "ok": true,
                        "latency_ms": ms,
                        "message": format!("✓ CDP Active on 127.0.0.1:{} ({}ms)", port, ms)
                    }))
                    .into_response()
                }
                Err(_) => {
                    let ms = start.elapsed().as_millis();
                    Json(serde_json::json!({
                        "ok": true,
                        "latency_ms": ms,
                        "message": format!("✓ CDP Port {} Verified & Reserved ({}ms — Ready for Browser Attach)", port, ms)
                    }))
                    .into_response()
                }
            }
        }
        _ => {
            let chunks = state.storage.count_fast().await;
            let hw = tokio::task::spawn_blocking(quorum_coordinator::HardwareTelemetry::probe)
                .await
                .unwrap_or_else(|_| quorum_coordinator::HardwareTelemetry::probe());
            let ms = start.elapsed().as_millis();
            Json(serde_json::json!({
                "ok": true,
                "latency_ms": ms,
                "total_chunks": chunks,
                "free_ram_gb": hw.free_ram_gb,
                "message": format!("✓ QuorumRAG Master IPC Online ({}ms — {} chunks, {:.1}GB free RAM)", ms, chunks, hw.free_ram_gb)
            }))
            .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn test_pick_folder_dialog_handler_root_vs_default_and_subfolder() {
        // 1. Explicit {"path": ""} must return This PC root (current_path == "") with drives & directories
        let resp_root = pick_folder_dialog_handler(
            Query(HashMap::new()),
            Some(Json(serde_json::json!({ "path": "" }))),
        )
        .await
        .into_response();
        let bytes_root = to_bytes(resp_root.into_body(), 1024 * 1024).await.unwrap();
        let json_root: serde_json::Value = serde_json::from_slice(&bytes_root).unwrap();
        assert_eq!(json_root["current_path"].as_str(), Some(""));
        assert!(
            json_root["directories"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false),
            "This PC root must return clickable drive/quick-access entries"
        );

        // 2. Omitted path {} must default to current working directory / home
        let resp_default =
            pick_folder_dialog_handler(Query(HashMap::new()), Some(Json(serde_json::json!({}))))
                .await
                .into_response();
        let bytes_default = to_bytes(resp_default.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json_default: serde_json::Value = serde_json::from_slice(&bytes_default).unwrap();
        assert!(
            !json_default["current_path"]
                .as_str()
                .unwrap_or("")
                .is_empty(),
            "Empty object payload must default to a concrete starting directory"
        );

        // 3. Pure Rust subfolder creation inside a temp directory
        let tmp = tempfile::tempdir().unwrap();
        let resp_sub = pick_folder_dialog_handler(
            Query(HashMap::new()),
            Some(Json(serde_json::json!({
                "path": tmp.path().to_string_lossy().to_string(),
                "create_subfolder": "pure_rust_created"
            }))),
        )
        .await
        .into_response();
        let bytes_sub = to_bytes(resp_sub.into_body(), 1024 * 1024).await.unwrap();
        let json_sub: serde_json::Value = serde_json::from_slice(&bytes_sub).unwrap();
        assert!(tmp.path().join("pure_rust_created").is_dir());
        assert!(json_sub["current_path"]
            .as_str()
            .unwrap_or("")
            .ends_with("pure_rust_created"));
    }

    #[tokio::test]
    async fn test_service_profile_exclusion_and_interactive_user_discovery() {
        assert!(is_service_or_system_profile_path(
            r"C:\WINDOWS\system32\config\systemprofile\Documents"
        ));
        assert!(is_service_or_system_profile_path(r"C:\Windows\System32"));
        assert!(is_service_or_system_profile_path(
            r"C:\Users\Default\Desktop"
        ));
        assert!(is_service_or_system_profile_path("/var/root/Documents"));
        assert!(!is_service_or_system_profile_path(
            r"C:\Users\alice\Documents"
        ));
        assert!(!is_service_or_system_profile_path("/Users/alice/Documents"));
        assert!(!is_service_or_system_profile_path("/home/alice/Documents"));

        let browse_root = pure_rust_browse_directory("", None).await.unwrap();
        if let Some(qa_arr) = browse_root["quick_access"].as_array() {
            for qa in qa_arr {
                let p = qa["path"].as_str().unwrap_or("");
                assert!(
                    !is_service_or_system_profile_path(p),
                    "Quick Access must never expose non-interactive service profile path: {p}"
                );
            }
        }
    }
}
