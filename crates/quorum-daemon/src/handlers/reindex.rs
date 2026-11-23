use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

use crate::state::DaemonState;
use quorum_ingest::ReindexOptions;

/// Payload to trigger reindexing via `POST /api/reindex`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReindexRequest {
    /// Optional specific directories to reindex.
    pub target_paths: Option<Vec<PathBuf>>,

    /// Bypass mtime and Level-1 BLAKE3 catalogs, re-verifying all files.
    pub full_rebuild: Option<bool>,

    /// Force re-embedding all chunks even if Level-2 hash matches.
    pub force_reembed: Option<bool>,

    /// Batch size for writes.
    pub batch_size: Option<usize>,
}

/// Start background reindexer: `POST /api/reindex`.
pub async fn start_reindex_handler(
    State(state): State<Arc<DaemonState>>,
    Json(payload): Json<ReindexRequest>,
) -> impl IntoResponse {
    let explicit_targets_requested = payload.target_paths.is_some();
    let raw_targets = payload
        .target_paths
        .unwrap_or_else(|| state.reindex_worker.all_watch_paths());

    let discovered = tokio::task::spawn_blocking(quorum_ingest::discover_cloud_drives)
        .await
        .unwrap_or_default();
    let controller = quorum_coordinator::global_mesh_dlp_controller();
    crate::handlers::cloud_drives::reconcile_discovered_cloud_drives(&controller, &discovered);
    let disabled_cloud_roots =
        crate::handlers::cloud_drives::collect_disabled_cloud_roots(&controller, &discovered);

    let mut target_paths = Vec::with_capacity(raw_targets.len());
    for p in raw_targets {
        if p.as_os_str().is_empty() {
            continue;
        }
        let Some(clean_p) = crate::handlers::cloud_drives::canonicalize_for_cloud_filter(&p) else {
            if explicit_targets_requested {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "status": "error",
                        "message": "Invalid, unsafe, or non-canonical path in target_paths"
                    })),
                )
                    .into_response();
            }
            continue;
        };
        crate::handlers::cloud_drives::push_watch_root_excluding_disabled(
            &clean_p,
            &disabled_cloud_roots,
            &mut target_paths,
        );
    }

    if target_paths.is_empty() {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "status": "error",
                "message": "No permitted target_paths remain after excluding disabled cloud drives and protected roots"
            })),
        )
            .into_response();
    }

    if let Some(watcher) = state.fs_watcher() {
        for p in &target_paths {
            if let Some(clean_p) = crate::handlers::cloud_drives::canonicalize_for_cloud_filter(p) {
                if clean_p.exists()
                    && clean_p.is_dir()
                    && !state.reindex_worker.is_path_blocked(&clean_p)
                    && !crate::handlers::cloud_drives::is_user_profile_root_dir(&clean_p)
                    && !crate::handlers::cloud_drives::is_disabled_cloud_root(
                        &clean_p,
                        &disabled_cloud_roots,
                    )
                    && !crate::handlers::cloud_drives::is_strict_ancestor_of_disabled_cloud_root(
                        &clean_p,
                        &disabled_cloud_roots,
                    )
                {
                    let _ = watcher.watch_path(&clean_p);
                }
            }
        }
    }

    if target_paths
        .iter()
        .all(|p| state.reindex_worker.is_path_blocked(p))
    {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "status": "error",
                "message": "No permitted target_paths remain after excluding disabled cloud drives"
            })),
        )
            .into_response();
    }

    let options = ReindexOptions {
        target_paths: target_paths.clone(),
        full_rebuild: payload.full_rebuild.unwrap_or(false),
        force_reembed: payload.force_reembed.unwrap_or(false),
        batch_size: payload.batch_size.unwrap_or(64),
        num_threads: 0,
        dry_run: false,
    };

    info!(
        targets = ?options.target_paths,
        full = options.full_rebuild,
        "Received POST /api/reindex request"
    );

    match state.reindex_worker.start_reindex(options).await {
        Ok(task_id) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "status": "started",
                "task_id": task_id.to_string(),
                "message": "Reindex worker task started in background"
            })),
        )
            .into_response(),
        Err(quorum_ingest::IngestError::Cancelled) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "status": "cancelled",
                "message": "Reindex cancelled due to concurrent cloud-drive disable or purge"
            })),
        )
            .into_response(),
        Err(quorum_ingest::IngestError::TaskAlreadyRunning(_)) => {
            match state.reindex_worker.trigger_paths(target_paths).await {
                Ok(task_id) => (
                    StatusCode::ACCEPTED,
                    Json(serde_json::json!({
                        "status": "queued_priority",
                        "task_id": task_id.to_string(),
                        "message": "Target paths injected at front of active reindex queue"
                    })),
                )
                    .into_response(),
                Err(e) => (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({
                        "status": "error",
                        "message": e.to_string()
                    })),
                )
                    .into_response(),
            }
        }
        Err(e) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "status": "error",
                "message": e.to_string()
            })),
        )
            .into_response(),
    }
}

/// Retrieve live reindex progress: `GET /api/reindex/status`.
pub async fn reindex_status_handler(State(state): State<Arc<DaemonState>>) -> impl IntoResponse {
    let total_stored_chunks = state.storage.count().await.unwrap_or(0);
    let watched_paths: Vec<String> = state
        .reindex_worker
        .all_watch_paths()
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    match state.reindex_worker.get_progress().await {
        Some(mut progress) => {
            progress.files_total_estimated =
                progress.files_total_estimated.max(progress.files_scanned);
            let mut val = serde_json::to_value(&progress).unwrap_or_default();
            if let Some(obj) = val.as_object_mut() {
                let pct = if progress.files_total_estimated > 0 {
                    ((progress.files_scanned as f64 / progress.files_total_estimated as f64)
                        * 100.0)
                        .clamp(0.0, 100.0)
                } else if matches!(progress.phase, quorum_ingest::ReindexPhase::Completed)
                    || total_stored_chunks > 0
                {
                    100.0
                } else {
                    0.0
                };
                obj.insert("percent".to_string(), serde_json::json!(pct));
                obj.insert(
                    "total_stored_chunks".to_string(),
                    serde_json::json!(total_stored_chunks),
                );
                obj.insert("continuous_mode".to_string(), serde_json::json!(true));
                obj.insert(
                    "watched_paths".to_string(),
                    serde_json::json!(watched_paths),
                );
            }
            Json(val).into_response()
        }
        None => {
            let pct = if total_stored_chunks > 0 { 100.0 } else { 0.0 };
            let phase = if total_stored_chunks > 0 {
                "completed"
            } else {
                "scanning_filesystem"
            };
            Json(serde_json::json!({
                "phase": phase,
                "percent": pct,
                "files_scanned": 0,
                "files_total_estimated": 0,
                "files_indexed": 0,
                "files_skipped_unmodified": 0,
                "chunks_newly_embedded": 0,
                "chunks_reused_from_cache": 0,
                "total_stored_chunks": total_stored_chunks,
                "continuous_mode": true,
                "watched_paths": watched_paths,
                "message": if total_stored_chunks > 0 { "Index active and up to date." } else { "Continuous background indexer initializing..." }
            }))
            .into_response()
        }
    }
}

/// Cancel active reindex task: `POST /api/reindex/cancel`.
pub async fn cancel_reindex_handler(State(state): State<Arc<DaemonState>>) -> impl IntoResponse {
    let cancelled = state.reindex_worker.cancel_reindex();
    Json(serde_json::json!({
        "status": "cancel_requested",
        "cancelled": cancelled
    }))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UploadedDocumentDto {
    pub file_name: String,
    pub content_base64: Option<String>,
    pub content_text: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddDocumentsRequest {
    pub uploaded_files: Option<Vec<UploadedDocumentDto>>,
    pub local_paths: Option<Vec<String>>,
    pub add_to_opt_in: Option<bool>,
}

fn decode_base64_standard(input: &str) -> Result<Vec<u8>, String> {
    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    let val = |b: u8| -> Result<u8, String> {
        match b {
            b'A'..=b'Z' => Ok(b - b'A'),
            b'a'..=b'z' => Ok(b - b'a' + 26),
            b'0'..=b'9' => Ok(b - b'0' + 52),
            b'+' | b'-' => Ok(62),
            b'/' | b'_' => Ok(63),
            _ => Err(format!("Invalid base64 byte: {}", b)),
        }
    };
    for chunk in clean.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        let b0 = val(chunk[0])?;
        let b1 = val(chunk[1])?;
        out.push((b0 << 2) | (b1 >> 4));
        if chunk.len() >= 3 && chunk[2] != b'=' {
            let b2 = val(chunk[2])?;
            out.push(((b1 & 0x0F) << 4) | (b2 >> 2));
            if chunk.len() >= 4 && chunk[3] != b'=' {
                let b3 = val(chunk[3])?;
                out.push(((b2 & 0x03) << 6) | b3);
            }
        }
    }
    Ok(out)
}

fn sanitize_uploaded_filename(raw: &str) -> Result<String, &'static str> {
    let lower = raw.to_ascii_lowercase();
    if raw.is_empty()
        || raw.contains(':')
        || raw.contains('/')
        || raw.contains('\\')
        || raw.contains("..")
        || raw.contains('\0')
        || lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%00")
    {
        return Err(
            "Invalid or unsafe document filename (rejected by Path::join Replacement Guard)",
        );
    }
    let path = std::path::Path::new(raw);
    let mut comps = path.components();
    match (comps.next(), comps.next()) {
        (Some(std::path::Component::Normal(os)), None) => {
            let s = os.to_string_lossy().trim().to_string();
            if s.is_empty() || s.starts_with('.') {
                Err("Invalid filename component")
            } else {
                Ok(s)
            }
        }
        _ => Err("Filename must be a single normal path component"),
    }
}

/// Upload and/or index new documents directly into the RAG index (and optionally into Opt-In scope):
/// `POST /api/documents/add`
pub async fn add_documents_handler(
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<AddDocumentsRequest>,
) -> impl IntoResponse {
    let discovered = tokio::task::spawn_blocking(quorum_ingest::discover_cloud_drives)
        .await
        .unwrap_or_default();
    let controller = quorum_coordinator::global_mesh_dlp_controller();
    crate::handlers::cloud_drives::reconcile_discovered_cloud_drives(&controller, &discovered);
    let disabled_cloud_roots =
        crate::handlers::cloud_drives::collect_disabled_cloud_roots(&controller, &discovered);

    let mut filtered_local_paths: Vec<PathBuf> = Vec::new();
    let mut local_inputs_requested = false;
    let mut had_disabled_or_profile = false;
    let mut had_existing_local = false;

    if let Some(paths) = req.local_paths {
        let mut raw_local_candidates = Vec::new();
        for p in paths {
            let trimmed = p.trim();
            if trimmed.is_empty() {
                continue;
            }
            local_inputs_requested = true;
            let raw_pb = PathBuf::from(trimmed);
            let Some(clean_pb) =
                crate::handlers::cloud_drives::canonicalize_for_cloud_filter(&raw_pb)
            else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "Invalid, unsafe, or non-canonical path in local_paths"
                    })),
                )
                    .into_response();
            };
            let is_blocked =
                crate::handlers::cloud_drives::is_disabled_cloud_root(
                    &clean_pb,
                    &disabled_cloud_roots,
                ) || crate::handlers::cloud_drives::is_user_profile_root_dir(&clean_pb);
            if is_blocked {
                had_disabled_or_profile = true;
                continue;
            }
            if clean_pb.exists() {
                had_existing_local = true;
                raw_local_candidates.push(clean_pb);
            }
        }
        for clean_pb in &raw_local_candidates {
            crate::handlers::cloud_drives::push_watch_root_excluding_disabled(
                clean_pb,
                &disabled_cloud_roots,
                &mut filtered_local_paths,
            );
        }
        if local_inputs_requested
            && filtered_local_paths.is_empty()
            && (had_disabled_or_profile || had_existing_local)
        {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "Requested local_paths reside inside disabled cloud drives or excluded roots and cannot be added or indexed"
                })),
            )
                .into_response();
        }
    }

    let mut target_paths: Vec<PathBuf> = Vec::new();
    let mut saved_files: Vec<String> = Vec::new();

    if let Some(files) = req.uploaded_files {
        let uploads_dir = state
            .storage
            .config()
            .storage_path
            .parent()
            .unwrap_or(state.storage.config().storage_path.as_path())
            .join("uploaded_documents");
        if let Err(e) = std::fs::create_dir_all(&uploads_dir) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("Failed to create uploaded_documents dir: {e}") })),
            )
                .into_response();
        }
        for dto in files {
            let clean_name = match sanitize_uploaded_filename(dto.file_name.trim()) {
                Ok(n) => n,
                Err(msg) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({ "error": msg })),
                    )
                        .into_response();
                }
            };
            let bytes = if let Some(ref b64) = dto.content_base64 {
                let payload = b64.split(',').next_back().unwrap_or(b64);
                match decode_base64_standard(payload) {
                    Ok(b) => b,
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({ "error": e })),
                        )
                            .into_response();
                    }
                }
            } else if let Some(ref txt) = dto.content_text {
                txt.as_bytes().to_vec()
            } else {
                continue;
            };

            let dest = uploads_dir.join(&clean_name);
            if let Err(e) = std::fs::write(&dest, &bytes) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": format!("Failed to write {}: {e}", clean_name) })),
                )
                    .into_response();
            }
            saved_files.push(dest.to_string_lossy().to_string());
            target_paths.push(dest);
        }
    }

    for pb in filtered_local_paths {
        let s = pb.to_string_lossy().to_string();
        if !saved_files.contains(&s) {
            saved_files.push(s);
        }
        if !target_paths.contains(&pb) {
            target_paths.push(pb);
        }
    }

    if target_paths.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "No valid files or paths provided to add" })),
        )
            .into_response();
    }

    // Optionally add to Opt-In scope (`opt_in_folders`)
    if req.add_to_opt_in.unwrap_or(false) {
        if let Ok(store) = state.marketplace_store() {
            if let Ok(cfg) = store.get_config() {
                let mut folders = cfg.opt_in_folders.clone();
                for p in &saved_files {
                    if !folders.iter().any(|f| f.eq_ignore_ascii_case(p)) {
                        folders.push(p.clone());
                    }
                }
                let _ = store.update_config(crate::handlers::marketplace::OptInConfigRequest {
                    opt_in_enabled: cfg.opt_in_enabled,
                    user_consent_checked: Some(cfg.user_consent_checked),
                    consent_statement: Some(cfg.consent_statement),
                    opt_in_folders: Some(folders),
                    allowed_jurisdictions: None,
                    five_eyes_enabled: None,
                    price_per_1k_records_cents: None,
                    authority_pubkey_hex: None,
                });
            }
        }
    }

    // Register permitted non-disabled directories with the live OS FilesystemWatcher.
    // Never watch a disabled cloud root, user profile root, or strict ancestor of a disabled
    // cloud root (since `FilesystemWatcher::watch_path` registers `RecursiveMode::Recursive`).
    if target_paths
        .iter()
        .all(|p| state.reindex_worker.is_path_blocked(p))
    {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "Requested paths reside inside disabled cloud drives and cannot be added or indexed"
            })),
        )
            .into_response();
    }
    if let Some(watcher) = state.fs_watcher() {
        for p in &target_paths {
            let dir_to_watch = if p.is_dir() {
                Some(p.as_path())
            } else {
                p.parent()
            };
            if let Some(d) = dir_to_watch {
                if let Some(clean_d) =
                    crate::handlers::cloud_drives::canonicalize_for_cloud_filter(d)
                {
                    if clean_d.exists()
                        && !state.reindex_worker.is_path_blocked(&clean_d)
                        && !crate::handlers::cloud_drives::is_user_profile_root_dir(&clean_d)
                        && !crate::handlers::cloud_drives::is_disabled_cloud_root(
                            &clean_d,
                            &disabled_cloud_roots,
                        )
                        && !crate::handlers::cloud_drives::is_strict_ancestor_of_disabled_cloud_root(
                            &clean_d,
                            &disabled_cloud_roots,
                        )
                    {
                        let _ = watcher.watch_path(&clean_d);
                    }
                }
            }
        }
    }
    state.reindex_worker.add_watch_paths(&target_paths);

    let has_directory_target = target_paths.iter().any(|p| p.is_dir());
    let indexed_chunks_delta = if has_directory_target {
        // Directory / drive selections dispatch immediately onto the priority background
        // reindex worker so selecting a large folder or physical drive never blocks the UI.
        if let Err(e) = state
            .reindex_worker
            .trigger_paths(target_paths.clone())
            .await
        {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
        0
    } else {
        let options = ReindexOptions {
            target_paths: target_paths.clone(),
            full_rebuild: false,
            force_reembed: false,
            batch_size: 32,
            num_threads: 4,
            dry_run: false,
        };
        match state.reindex_worker.run_reindex_sync(options).await {
            Ok(prog) => prog.chunks_newly_embedded + prog.chunks_reused_from_cache,
            Err(quorum_ingest::IngestError::Cancelled) => {
                return (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({
                        "error": "Document indexing cancelled by concurrent cloud-drive disable or purge"
                    })),
                )
                    .into_response();
            }
            Err(quorum_ingest::IngestError::TaskAlreadyRunning(_)) => {
                if state
                    .reindex_worker
                    .trigger_paths(target_paths.clone())
                    .await
                    .is_err()
                {
                    return (
                        StatusCode::CONFLICT,
                        Json(serde_json::json!({
                            "error": "Requested paths are blocked or unavailable for indexing"
                        })),
                    )
                        .into_response();
                }
                0
            }
            Err(e) => {
                return (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
                    .into_response();
            }
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "added_and_indexed",
            "added_count": saved_files.len(),
            "saved_paths": saved_files,
            "chunks_indexed": indexed_chunks_delta,
            "added_to_opt_in": req.add_to_opt_in.unwrap_or(false),
            "message": format!("Added & indexed {} document(s)/path(s)", target_paths.len()),
        })),
    )
        .into_response()
}
