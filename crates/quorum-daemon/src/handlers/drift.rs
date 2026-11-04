use axum::extract::{Json, State};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

use crate::state::DaemonState;
use quorum_ingest::{DriftFixOptions, DriftType};

/// Payload to trigger drift remediation: `POST /api/drift/fix`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DriftFixRequest {
    /// Target specific drift types: "merkle_state", "hybrid_index_desync", "vector_contract", "acl_policy", "storage_compaction".
    /// Empty array means target ALL 5 drift categories.
    pub target_drifts: Option<Vec<String>>,

    /// Dry run: detect and report drift anomalies without modifying storage.
    pub dry_run: Option<bool>,
}

/// Run drift remediation: `POST /api/drift/fix`.
pub async fn fix_drift_handler(
    State(state): State<Arc<DaemonState>>,
    Json(payload): Json<DriftFixRequest>,
) -> impl IntoResponse {
    let mut targets = Vec::new();
    if let Some(ref list) = payload.target_drifts {
        for item in list {
            match item.to_lowercase().as_str() {
                "merkle_state" | "merkle" | "fs" => targets.push(DriftType::MerkleState),
                "hybrid_index_desync" | "hybrid" | "desync" => targets.push(DriftType::HybridIndexDesync),
                "vector_contract" | "contract" | "vector" => targets.push(DriftType::VectorContract),
                "acl_policy" | "acl" => targets.push(DriftType::AclPolicy),
                "storage_compaction" | "compaction" => targets.push(DriftType::StorageCompaction),
                _ => {}
            }
        }
    }

    let options = DriftFixOptions {
        target_drifts: targets,
        dry_run: payload.dry_run.unwrap_or(false),
        access_tier_rules: state.ingest_config.access_tier_rules.clone(),
    };

    info!(
        dry_run = options.dry_run,
        targets_count = options.target_drifts.len(),
        "Executing POST /api/drift/fix"
    );

    match state.drift_healer.fix_all_drifts(options).await {
        Ok(report) => Json(report).into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "status": "error",
                "message": e.to_string()
            })),
        )
            .into_response(),
    }
}

/// Retrieve current drift status (runs a fast dry-run inspection): `GET /api/drift/status`.
pub async fn drift_status_handler(
    State(state): State<Arc<DaemonState>>,
) -> impl IntoResponse {
    let options = DriftFixOptions {
        target_drifts: Vec::new(), // Check all 5
        dry_run: true,             // Do not mutate database
        access_tier_rules: state.ingest_config.access_tier_rules.clone(),
    };

    match state.drift_healer.fix_all_drifts(options).await {
        Ok(report) => Json(report).into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "status": "error",
                "message": e.to_string()
            })),
        )
            .into_response(),
    }
}
