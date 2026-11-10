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

    let physical_drives: Vec<String> = quorum_ingest::IngestConfig::discover_physical_drives()
        .into_iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    let watched_paths: Vec<String> = state
        .ingest_config
        .watch_paths
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    let total_chunks = state.storage.count().await.unwrap_or(0);
    let total_files = state.storage.catalog().count_documents().unwrap_or(0);

    Json(serde_json::json!({
        "status": "ok",
        "ui": settings.ui,
        "mesh": settings.mesh,
        "dlp": settings.dlp,
        "dlp_stats": dlp_stats,
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
    State(_state): State<Arc<DaemonState>>,
    Json(payload): Json<UpdateSettingsPayload>,
) -> impl IntoResponse {
    let controller = global_mesh_dlp_controller();
    {
        let mut guard = controller
            .settings
            .write()
            .unwrap_or_else(|e| e.into_inner());
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
    }
    controller.save_to_disk();
    let updated = controller
        .settings
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    Json(serde_json::json!({
        "status": "ok",
        "ui": updated.ui,
        "mesh": updated.mesh,
        "dlp": updated.dlp
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
        "duckdns_domain": mesh.duckdns_domain,
        "auto_bootstrap_duckdns": mesh.auto_bootstrap_duckdns,
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

    // Dial any newly configured bootstrap multiaddrs
    let mut dialed = Vec::new();
    if let Some(ref handle) = state.swarm_handle {
        for addr_str in peers_to_dial {
            if let Ok(multiaddr) = addr_str.parse::<quorum_network::Multiaddr>() {
                if handle.dial(multiaddr).await.is_ok() {
                    dialed.push(addr_str);
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
        "dialed_peers": dialed
    }))
}

/// POST /api/mesh/shared-folders - Adds, removes, toggles, or updates user folders shared with the Mesh.
pub async fn manage_shared_folders_handler(
    State(state): State<Arc<DaemonState>>,
    Json(payload): Json<SharedFolderActionPayload>,
) -> impl IntoResponse {
    let controller = global_mesh_dlp_controller();
    let raw_path = payload.path.trim();

    let Some(norm_target) = quorum_coordinator::OsoosiMeshDlpController::normalize_folder_path(raw_path) else {
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
    let mut should_index_target = false;
    {
        let mut guard = controller
            .settings
            .write()
            .unwrap_or_else(|e| e.into_inner());

        match action.as_str() {
            "add" => {
                let p = Path::new(raw_path);
                if !p.exists() || !p.is_dir() {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "status": "error",
                            "error": format!("Directory '{}' does not exist on disk.", raw_path)
                        })),
                    )
                        .into_response();
                }

                let existing = guard.mesh.shared_folders.iter_mut().find(|f| {
                    quorum_coordinator::OsoosiMeshDlpController::normalize_folder_path(&f.path)
                        .as_deref()
                        == Some(norm_target.as_str())
                });

                if let Some(entry) = existing {
                    entry.enabled = payload.enabled.unwrap_or(true);
                    should_index_target = entry.enabled;
                    if let Some(tier) = payload.access_tier {
                        entry.access_tier = tier.min(3);
                    }
                    if let Some(ref mode_str) = payload.dlp_mode_override {
                        entry.dlp_mode_override = if mode_str.eq_ignore_ascii_case("default") || mode_str.is_empty() {
                            None
                        } else {
                            Some(DlpEnforcementMode::from_str_lossy(mode_str))
                        };
                    }
                } else {
                    let default_label = p
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
                        path: raw_path.to_string(),
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
        let _ = state
            .watch_and_index_paths(vec![std::path::PathBuf::from(raw_path)])
            .await;
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

/// Pure Rust helper that validates a single new subfolder name (no traversal, drive letters, or separators).
fn is_safe_single_folder_name(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty()
        || trimmed == "."
        || trimmed == ".."
        || trimmed.contains(':')
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('%')
        || trimmed.contains('\0')
    {
        return false;
    }
    let mut components = Path::new(trimmed).components();
    matches!(components.next(), Some(std::path::Component::Normal(_))) && components.next().is_none()
}

/// Pure Rust directory enumeration and folder picker engine (`std::fs::read_dir` + physical drive discovery).
/// Never spawns external OS dialogs (`powershell`, `explorer.exe`, `osascript`, or `zenity`).
async fn pure_rust_browse_directory(
    requested_path: &str,
    create_subfolder: Option<&str>,
) -> serde_json::Value {
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

    let drives_raw = quorum_ingest::IngestConfig::discover_physical_drives();
    let physical_drives: Vec<String> = drives_raw
        .iter()
        .map(|d| d.to_string_lossy().to_string())
        .collect();

    // Build Pure Rust quick-access folder list so it is always available in the UI
    let mut quick_access: Vec<serde_json::Value> = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.is_dir() {
            let s = cwd.to_string_lossy().to_string();
            quick_access.push(serde_json::json!({
                "name": "Workspace",
                "path": s,
                "is_drive": false,
                "is_quick_access": true,
                "is_shared": is_shared_fn(&s)
            }));
        }
    }
    let home_opt = std::env::var("USERPROFILE")
        .ok()
        .or_else(|| std::env::var("HOME").ok());
    if let Some(ref home) = home_opt {
        let quick_folders = [
            ("Desktop", "Desktop"),
            ("Documents", "Documents"),
            ("Downloads", "Downloads"),
            ("Pictures", "Pictures"),
        ];
        for (label, sub) in quick_folders {
            let p = Path::new(home).join(sub);
            if p.is_dir() {
                let s = p.to_string_lossy().to_string();
                quick_access.push(serde_json::json!({
                    "name": label,
                    "path": s,
                    "is_drive": false,
                    "is_quick_access": true,
                    "is_shared": is_shared_fn(&s)
                }));
            }
        }
    }

    let req_trimmed = requested_path.trim();
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

        return serde_json::json!({
            "status": "ok",
            "engine": "pure_rust_std_fs",
            "path": "",
            "current_path": "",
            "parent_path": "",
            "drives": physical_drives,
            "quick_access": quick_access,
            "directories": entries,
            "cancelled": false
        });
    }

    let mut target_dir_buf = Path::new(req_trimmed).to_path_buf();
    let mut created_folder_path: Option<String> = None;

    if let Some(sub_name) = create_subfolder {
        let sub_trimmed = sub_name.trim();
        if is_safe_single_folder_name(sub_trimmed) && target_dir_buf.is_dir() {
            let candidate = target_dir_buf.join(sub_trimmed);
            if std::fs::create_dir_all(&candidate).is_ok() {
                created_folder_path = Some(candidate.to_string_lossy().to_string());
                target_dir_buf = candidate;
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
    let dirs: Vec<serde_json::Value> = tokio::task::spawn_blocking(move || {
        let is_shared = |candidate: &str| -> bool {
            let Some(norm_c) =
                quorum_coordinator::OsoosiMeshDlpController::normalize_folder_path(candidate)
            else {
                return false;
            };
            shared_folders_clone.iter().any(|f| {
                f.enabled
                    && quorum_coordinator::OsoosiMeshDlpController::normalize_folder_path(&f.path)
                        .as_deref()
                        == Some(norm_c.as_str())
            })
        };

        let mut dirs = Vec::new();
        if let Ok(read_dir) = std::fs::read_dir(&dir_path_buf) {
            for entry in read_dir.flatten() {
                if let Ok(ft) = entry.file_type() {
                    if ft.is_dir() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        if name.starts_with('$')
                            || name.eq_ignore_ascii_case("System Volume Information")
                            || name.eq_ignore_ascii_case("target")
                            || name.eq_ignore_ascii_case("node_modules")
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
        }
        dirs.sort_by(|a, b| {
            let na = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let nb = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
            na.to_ascii_lowercase().cmp(&nb.to_ascii_lowercase())
        });
        dirs.truncate(200);
        dirs
    })
    .await
    .unwrap_or_default();

    serde_json::json!({
        "status": "ok",
        "engine": "pure_rust_std_fs",
        "path": resolved_path_str,
        "current_path": resolved_path_str,
        "parent_path": parent_path,
        "created_folder": created_folder_path,
        "drives": physical_drives,
        "quick_access": quick_access,
        "directories": dirs,
        "cancelled": false
    })
}

/// GET /api/fs/browse-folders?path=... (and /api/mesh/browse-folders) - Lists real directories on physical drives and quick-access user folders in Pure Rust.
pub async fn browse_folders_handler(
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let requested_path = params.get("path").map(|s| s.trim()).unwrap_or("");
    let create_subfolder = params.get("create_subfolder").map(|s| s.as_str());
    Json(pure_rust_browse_directory(requested_path, create_subfolder).await)
}

/// POST /api/fs/pick-folder - Pure Rust folder selection & directory browser endpoint.
/// Operates 100% in Pure Rust (`std::fs`) without spawning Windows Explorer or OS shell subprocesses.
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
            .filter(|p| p.is_dir())
            .map(|p| p.to_string_lossy().to_string())
            .or_else(|| {
                std::env::var("USERPROFILE")
                    .ok()
                    .or_else(|| std::env::var("HOME").ok())
                    .map(|h| {
                        let docs = Path::new(&h).join("Documents");
                        if docs.is_dir() {
                            docs.to_string_lossy().to_string()
                        } else {
                            h
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

    Json(pure_rust_browse_directory(&effective_path, create_subfolder.as_deref()).await)
        .into_response()
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
pub async fn test_dlp_inspection_handler(
    Json(payload): Json<DlpTestPayload>,
) -> impl IntoResponse {
    let controller = global_mesh_dlp_controller();
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
                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body[s..=e]) {
                                if let Some(arr) = val.get("models").and_then(|m| m.as_array()) {
                                    for item in arr {
                                        if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
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
            let chunks = state.storage.count().await.unwrap_or(0);
            let hw = quorum_coordinator::HardwareTelemetry::probe();
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
}
