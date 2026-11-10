//! Artemis DFIR Forensic Telemetry Axum 0.7 Handlers (`handlers/artemis.rs`)
//!
//! Provides REST endpoints for:
//! - `GET /api/v1/artemis/status`: Runtime status, toggles, allowed/prohibited categories, airgap state.
//! - `GET /api/v1/artemis/config`: Current Artemis DFIR configuration.
//! - `POST /api/v1/artemis/config` / `PUT /api/v1/artemis/config`: Update and persist settings.
//! - `POST /api/v1/artemis/collect`: Trigger on-demand live forensic collection or import from `.jsonl` dumps.
//! - `POST /api/v1/artemis/preview-normalizer`: Live keyed BLAKE3 structural normalizer preview.

use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use crate::state::DaemonState;
use quorum_contract::ForensicTelemetryType;
use quorum_coordinator::artemis_airgap::prohibited_categories;
use quorum_coordinator::dlp_mesh::global_mesh_dlp_controller;
use quorum_coordinator::ForensicStructuralNormalizer;
use quorum_ingest::secret_scrubber::SecretScrubber;
use quorum_ingest::{
    collect_forensic_directory, collect_live_os_forensics, parse_artemis_jsonl,
    parse_artemis_jsonl_str, ArtemisTelemetryRecord,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{OnceLock, RwLock};

static TOTAL_ARTEMIS_COLLECTED_RECORDS: AtomicUsize = AtomicUsize::new(0);
static LAST_ARTEMIS_COLLECTION_TIMESTAMP: OnceLock<RwLock<Option<String>>> = OnceLock::new();
static LAST_ARTEMIS_COLLECTION_INSTANT: OnceLock<RwLock<Option<Instant>>> = OnceLock::new();

fn last_collection_ts_lock() -> &'static RwLock<Option<String>> {
    LAST_ARTEMIS_COLLECTION_TIMESTAMP.get_or_init(|| RwLock::new(None))
}

fn last_collection_instant_lock() -> &'static RwLock<Option<Instant>> {
    LAST_ARTEMIS_COLLECTION_INSTANT.get_or_init(|| RwLock::new(None))
}

/// Partial or full update payload for Artemis DFIR settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtemisConfigUpdatePayload {
    pub enabled: Option<bool>,
    pub local_collection_enabled: Option<bool>,
    pub marketplace_harvest_enabled: Option<bool>,
    pub allowed_artifact_categories: Option<Vec<String>>,
    pub auto_collection_interval_mins: Option<u32>,
    pub retention_days: Option<u32>,
    pub redact_secrets: Option<bool>,
    pub normalize_for_harvest: Option<bool>,
}

/// Request payload for on-demand forensic collection or import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtemisCollectRequest {
    #[serde(default = "default_source_live")]
    pub source_type: String,
    pub target_path: Option<String>,
    pub path: Option<String>,
    pub folder_path: Option<String>,
    pub file_path: Option<String>,
    pub categories: Option<Vec<String>>,
}

fn default_source_live() -> String {
    "live".to_string()
}

/// Request payload for previewing keyed BLAKE3 structural normalization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtemisPreviewNormalizerRequest {
    pub sample_text: Option<String>,
    pub raw_telemetry: Option<String>,
    pub session_salt: Option<String>,
}

/// GET /api/v1/artemis/status
/// Returns current Artemis DFIR configuration, airgap enforcement, and category allowlists.
pub async fn artemis_status_handler(
    State(_state): State<Arc<DaemonState>>,
) -> impl IntoResponse {
    let controller = global_mesh_dlp_controller();
    let settings = controller.get_settings();
    let total_collected = TOTAL_ARTEMIS_COLLECTED_RECORDS.load(Ordering::Relaxed);
    let last_ts = last_collection_ts_lock()
        .read()
        .ok()
        .and_then(|g| g.clone());

    Json(serde_json::json!({
        "status": "ok",
        "collection_enabled": settings.artemis.local_collection_enabled,
        "marketplace_harvest_enabled": settings.artemis.marketplace_harvest_enabled,
        "airgap_enforced": true,
        "supported_platforms": ["windows", "macos", "linux"],
        "current_platform": std::env::consts::OS,
        "allowed_artifact_categories": settings.artemis.allowed_artifact_categories,
        "prohibited_artifact_categories": prohibited_categories(),
        "auto_collection_interval_mins": settings.artemis.auto_collection_interval_mins,
        "retention_days": settings.artemis.retention_days,
        "redact_secrets": settings.artemis.redact_secrets,
        "normalize_for_harvest": settings.artemis.normalize_for_harvest,
        "total_collected_records": total_collected,
        "last_collection_timestamp": last_ts,
    }))
}

/// GET /api/v1/artemis/config
/// Returns current `ArtemisDfirSettings` as JSON.
pub async fn artemis_get_config_handler() -> impl IntoResponse {
    let controller = global_mesh_dlp_controller();
    let settings = controller.get_settings();
    Json(settings.artemis)
}

/// POST /api/v1/artemis/config and PUT /api/v1/artemis/config
/// Updates `ArtemisDfirSettings` in controller and persists to disk.
pub async fn artemis_update_config_handler(
    Json(body): Json<ArtemisConfigUpdatePayload>,
) -> impl IntoResponse {
    let controller = global_mesh_dlp_controller();
    let mut current = controller.get_settings();

    if let Some(v) = body.enabled {
        current.artemis.enabled = v;
    }
    if let Some(v) = body.local_collection_enabled {
        current.artemis.local_collection_enabled = v;
    }
    if let Some(v) = body.marketplace_harvest_enabled {
        current.artemis.marketplace_harvest_enabled = v;
    }
    if let Some(mut cats) = body.allowed_artifact_categories {
        let prohibited = prohibited_categories();
        cats.retain(|c| {
            let trimmed = c.trim();
            if trimmed.is_empty() {
                return false;
            }
            let lower = trimmed.to_ascii_lowercase();
            let clean = lower.replace('-', "").replace('_', "");
            if prohibited.iter().any(|p| {
                let p_clean = p.replace('-', "").replace('_', "");
                clean == p_clean
                    || lower == *p
                    || lower.contains(p)
                    || p.contains(&lower)
                    || clean.contains(&p_clean)
                    || p_clean.contains(&clean)
            }) {
                return false;
            }
            if let Ok(telemetry_type) = trimmed.parse::<ForensicTelemetryType>() {
                if !telemetry_type.is_marketplace_harvest_allowed() {
                    return false;
                }
            }
            true
        });
        current.artemis.allowed_artifact_categories = cats;
    }
    if let Some(v) = body.auto_collection_interval_mins {
        current.artemis.auto_collection_interval_mins = v;
    }
    if let Some(v) = body.retention_days {
        current.artemis.retention_days = v;
    }
    if let Some(v) = body.redact_secrets {
        current.artemis.redact_secrets = v;
    }
    if let Some(v) = body.normalize_for_harvest {
        current.artemis.normalize_for_harvest = v;
    }

    controller.update_settings(current);
    controller.save_to_disk();
    let updated = controller.get_settings();
    (StatusCode::OK, Json(updated.artemis))
}

const MAX_JSONL_COLLECT_DEPTH: usize = 16;

/// Helper to recursively collect `.jsonl` files from a directory with bounded recursion depth.
fn collect_jsonl_paths(dir: &Path) -> Vec<PathBuf> {
    collect_jsonl_paths_bounded(dir, 0, MAX_JSONL_COLLECT_DEPTH)
}

fn collect_jsonl_paths_bounded(dir: &Path, depth: usize, max_depth: usize) -> Vec<PathBuf> {
    if depth > max_depth {
        return Vec::new();
    }
    let mut results = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            // Skip symlinks to prevent traversal loops
            if entry.file_type().map_or(false, |ft| ft.is_symlink()) {
                continue;
            }
            let path = entry.path();
            if path.is_file() {
                if path
                    .extension()
                    .map_or(false, |ext| ext.eq_ignore_ascii_case("jsonl"))
                {
                    results.push(path);
                }
            } else if path.is_dir() && depth < max_depth {
                results.extend(collect_jsonl_paths_bounded(&path, depth + 1, max_depth));
            }
        }
    }
    results
}

/// POST /api/v1/artemis/collect
/// Triggers on-demand collection or imports forensic telemetry from `.jsonl` files/folders.
pub async fn artemis_collect_handler(
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<ArtemisCollectRequest>,
) -> impl IntoResponse {
    let start_time = Instant::now();
    let controller = global_mesh_dlp_controller();
    let settings = controller.get_settings();

    let source = req.source_type.trim().to_ascii_lowercase();
    let target_path_str = req
        .target_path
        .or(req.path)
        .or(req.folder_path)
        .or(req.file_path);

    // Fail-closed airgap check: live collection requires explicit opt-in
    let is_live_source = source == "live" || (source.is_empty() && target_path_str.is_none());
    if is_live_source && !settings.artemis.local_collection_enabled {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "Local Artemis DFIR collection is disabled by default. Enable in Settings first."
            })),
        )
            .into_response();
    }

    // Fail-fast validation: non-live collection requires target_path or folder_path
    if !is_live_source && target_path_str.as_deref().map_or(true, |s| s.trim().is_empty()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Missing required target_path, folder_path, or file_path for non-live collection"
            })),
        )
            .into_response();
    }

    let mut parsed_records: Vec<ArtemisTelemetryRecord> = Vec::new();

    if let Some(ref path_str) = target_path_str {
        let trimmed_path = path_str.trim();
        let path = Path::new(trimmed_path);

        if path.is_file() {
            let file = match std::fs::File::open(path) {
                Ok(f) => f,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": format!("Cannot open file '{}': {}", trimmed_path, e)
                        })),
                    )
                        .into_response();
                }
            };
            match parse_artemis_jsonl(file) {
                Ok(records) => parsed_records.extend(records),
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": format!("Failed to parse JSONL from '{}': {}", trimmed_path, e)
                        })),
                    )
                        .into_response();
                }
            }
        } else if path.is_dir() {
            let dir_clone = path.to_path_buf();
            if let Ok(records) = tokio::task::spawn_blocking(move || collect_forensic_directory(&dir_clone)).await {
                parsed_records.extend(records);
            }
            if parsed_records.is_empty() {
                let jsonl_files = collect_jsonl_paths(path);
                for jfile in jsonl_files {
                    if let Ok(file) = std::fs::File::open(&jfile) {
                        if let Ok(records) = parse_artemis_jsonl(file) {
                            parsed_records.extend(records);
                        }
                    }
                }
            }
        } else if trimmed_path.starts_with('{') {
            // Direct inline JSONL content
            match parse_artemis_jsonl_str(trimmed_path) {
                Ok(records) => parsed_records.extend(records),
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": format!("Failed to parse inline JSONL: {}", e)
                        })),
                    )
                        .into_response();
                }
            }
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("Specified target_path '{}' does not exist on disk", trimmed_path)
                })),
            )
                .into_response();
        }
    } else if is_live_source {
        // Multi-category live OS forensic telemetry collection across Windows, macOS, and Linux:
        // process_execution, network_connection, registry_persistence, prefetch_amcache_execution,
        // service_daemon, and system_event_log.
        let active_cats = req
            .categories
            .clone()
            .unwrap_or_else(|| settings.artemis.allowed_artifact_categories.clone());
        if let Ok(live_records) =
            tokio::task::spawn_blocking(move || collect_live_os_forensics(&active_cats)).await
        {
            parsed_records.extend(live_records);
        }
    }

    // Optional category filtering
    if let Some(ref cats) = req.categories {
        let normalized_cats: HashSet<String> = cats
            .iter()
            .map(|c| c.trim().to_ascii_lowercase())
            .collect();
        parsed_records.retain(|r| {
            let t_str = r.telemetry_type.as_str().to_ascii_lowercase();
            normalized_cats
                .iter()
                .any(|cat| cat == &t_str || t_str.contains(cat) || cat.contains(&t_str))
        });
    }

    let records_parsed = parsed_records.len();

    // Redact secrets if configured
    if settings.artemis.redact_secrets {
        for record in &mut parsed_records {
            record.summary_text = SecretScrubber::scrub_text(&record.summary_text);
        }
    }

    // Convert to DocumentChunks and batch-embed into storage
    let mut chunks_to_index = Vec::with_capacity(records_parsed);
    for rec in &parsed_records {
        if let Ok(chunk) = rec.to_document_chunk(0) {
            chunks_to_index.push(chunk);
        }
    }

    for batch in chunks_to_index.chunks_mut(64) {
        let texts: Vec<&str> = batch.iter().map(|c| c.text_content.as_str()).collect();
        if let Ok(vecs) = state.embedder.embed_batch(&texts) {
            for (chunk, vec) in batch.iter_mut().zip(vecs.into_iter()) {
                chunk.vector = vec;
            }
        } else {
            for chunk in batch.iter_mut() {
                chunk.vector = state
                    .embedder
                    .embed_text(&chunk.text_content)
                    .unwrap_or_else(|_| vec![0.0f32; state.embedder.dimension()]);
            }
        }
    }

    let chunks_indexed = if !chunks_to_index.is_empty() {
        state
            .storage
            .insert_chunks(&chunks_to_index)
            .await
            .unwrap_or(0)
    } else {
        0
    };

    if chunks_indexed > 0 {
        TOTAL_ARTEMIS_COLLECTED_RECORDS.fetch_add(chunks_indexed, Ordering::Relaxed);
        if let Ok(mut ts) = last_collection_ts_lock().write() {
            *ts = Some(chrono::Utc::now().to_rfc3339());
        }
        if let Ok(mut inst) = last_collection_instant_lock().write() {
            *inst = Some(Instant::now());
        }
    }

    let mut categories_collected: Vec<String> = parsed_records
        .iter()
        .map(|r| r.telemetry_type.as_str().to_string())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    categories_collected.sort();

    let elapsed_ms = start_time.elapsed().as_millis() as u64;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "completed",
            "records_parsed": records_parsed,
            "chunks_indexed": chunks_indexed,
            "categories_collected": categories_collected,
            "elapsed_ms": elapsed_ms,
        })),
    )
        .into_response()
}

/// POST /api/v1/artemis/preview-normalizer
/// Demonstrates live keyed BLAKE3 structural normalization over raw forensic telemetry.
pub async fn artemis_preview_normalizer_handler(
    Json(req): Json<ArtemisPreviewNormalizerRequest>,
) -> impl IntoResponse {
    let raw = req
        .sample_text
        .or(req.raw_telemetry);

    let text = match raw {
        Some(t) if !t.trim().is_empty() => t,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Missing or empty 'sample_text' or 'raw_telemetry' in request body"
                })),
            )
                .into_response();
        }
    };

    let salt = req
        .session_salt
        .as_deref()
        .unwrap_or("artemis-preview-salt");

    let mut normalizer =
        ForensicStructuralNormalizer::from_node_seed(&[0u8; 32], salt);
    let preview = normalizer.preview_normalization(&text);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "preview": preview,
            "original": preview.original_text,
            "normalized": preview.normalized_text,
            "total_replacements": preview.total_replacements,
            "pseudonym_mappings": preview.pseudonym_mappings,
        })),
    )
        .into_response()
}

/// Spawns the background periodic Artemis DFIR auto-collection worker.
///
/// Remains completely dormant unless the operator has explicitly enabled
/// `local_collection_enabled = true` AND configured `auto_collection_interval_mins > 0`.
pub fn spawn_artemis_auto_collector(
    state: Arc<DaemonState>,
    shutdown_notify: Arc<tokio::sync::Notify>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_notify.notified() => break,
                _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
            }

            let settings = global_mesh_dlp_controller().get_settings().artemis;
            if !settings.local_collection_enabled || settings.auto_collection_interval_mins == 0 {
                continue;
            }

            let interval =
                std::time::Duration::from_secs(u64::from(settings.auto_collection_interval_mins) * 60);
            let due = last_collection_instant_lock()
                .read()
                .ok()
                .map_or(true, |guard| match *guard {
                    Some(last) => last.elapsed() >= interval,
                    None => true,
                });

            if !due {
                continue;
            }

            let active_cats = settings.allowed_artifact_categories.clone();
            let Ok(mut parsed_records) =
                tokio::task::spawn_blocking(move || collect_live_os_forensics(&active_cats)).await
            else {
                continue;
            };

            if settings.redact_secrets {
                for record in &mut parsed_records {
                    record.summary_text = SecretScrubber::scrub_text(&record.summary_text);
                }
            }

            let mut chunks_to_index = Vec::with_capacity(parsed_records.len());
            for rec in &parsed_records {
                if let Ok(chunk) = rec.to_document_chunk(0) {
                    chunks_to_index.push(chunk);
                }
            }

            for batch in chunks_to_index.chunks_mut(64) {
                let texts: Vec<&str> = batch.iter().map(|c| c.text_content.as_str()).collect();
                if let Ok(vecs) = state.embedder.embed_batch(&texts) {
                    for (chunk, vec) in batch.iter_mut().zip(vecs.into_iter()) {
                        chunk.vector = vec;
                    }
                } else {
                    for chunk in batch.iter_mut() {
                        chunk.vector = state
                            .embedder
                            .embed_text(&chunk.text_content)
                            .unwrap_or_else(|_| vec![0.0f32; state.embedder.dimension()]);
                    }
                }
            }

            if !chunks_to_index.is_empty() {
                if let Ok(indexed) = state.storage.insert_chunks(&chunks_to_index).await {
                    if indexed > 0 {
                        TOTAL_ARTEMIS_COLLECTED_RECORDS.fetch_add(indexed, Ordering::Relaxed);
                        if let Ok(mut ts) = last_collection_ts_lock().write() {
                            *ts = Some(chrono::Utc::now().to_rfc3339());
                        }
                        if let Ok(mut inst) = last_collection_instant_lock().write() {
                            *inst = Some(Instant::now());
                        }
                    }
                }
            }
        }
    });
}

