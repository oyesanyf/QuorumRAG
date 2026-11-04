use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use std::sync::Arc;

use crate::state::DaemonState;
use quorum_coordinator::HardwareTelemetry;

/// Health & Telemetry endpoint: `GET /api/health`.
pub async fn health_handler(
    State(state): State<Arc<DaemonState>>,
) -> impl IntoResponse {
    let hw = HardwareTelemetry::probe();
    let total_chunks = state.storage.count().await.unwrap_or(0);

    let (connected_peers, listen_addrs) = if let Some(ref swarm) = state.swarm_handle {
        let peers = swarm.connected_peers().await.map(|p| p.len()).unwrap_or(0);
        let addrs = swarm.listen_addresses().await.map(|a| a.iter().map(|m| m.to_string()).collect()).unwrap_or_default();
        (peers, addrs)
    } else {
        (0, Vec::new())
    };

    let uptime_secs = state.start_time.elapsed().as_secs();

    let contract = quorum_contract::EmbeddingContract::canonical_gemma_300m();
    let contract_hash: String = contract
        .derive_contract_hash()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    let selected_tier = if hw.free_ram_gb >= 24.0 || hw.free_vram_mb >= 12000 {
        "Tier 1: High VRAM (GLM-4-9B / Qwen 2.5 32B)"
    } else if hw.free_ram_gb >= 12.0 || hw.free_vram_mb >= 4500 {
        "Tier 2: Mid Memory (GLM-Edge / Qwen 2.5 7B)"
    } else {
        "Tier 3: CPU Quantized / Deterministic Offline Engine"
    };

    let cache_stats = state.coordinator.cache_stats();

    Json(serde_json::json!({
        "status": "healthy",
        "version": "0.1.0",
        "contract_hash": contract_hash,
        "uptime_secs": uptime_secs,
        "cache": {
            "cache_epoch": cache_stats.cache_epoch,
            "cached_queries": cache_stats.cached_queries,
            "cached_embeddings": cache_stats.cached_embeddings,
            "hits": cache_stats.hits,
            "misses": cache_stats.misses,
            "hit_rate": cache_stats.hit_rate,
        },
        "storage": {
            "total_chunks": total_chunks,
            "data_dir": state.data_dir.to_string_lossy(),
        },
        "hardware": {
            "total_ram_gb": hw.total_ram_gb,
            "free_ram_gb": hw.free_ram_gb,
            "cpu_cores": hw.cpu_cores,
            "gpu_name": hw.gpu_name,
            "free_vram_mb": hw.free_vram_mb,
            "selected_tier": selected_tier,
        },
        "network": {
            "connected_peers": connected_peers,
            "listen_addresses": listen_addrs,
            "local_peer_id": state.swarm_handle.as_ref().map(|s| s.local_peer_id().to_string()),
        },
        "active_model_family": format!("{:?}", state.default_model_family),
    }))
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct PullModelRequest {
    pub model: String,
}

/// Triggers background `ollama pull <model>` and returns installed model pills (`POST /api/models/pull`).
pub async fn pull_model_handler(Json(payload): Json<PullModelRequest>) -> impl IntoResponse {
    let model = quorum_coordinator::DeterministicOfflineSynthesisEngine::normalize_requested_model_tag(&payload.model);
    if model.is_empty()
        || model.len() > 64
        || !model
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '-' | '_' | '/'))
    {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid model tag" })),
        )
            .into_response();
    }
    let started = tokio::task::spawn_blocking({
        let m = model.clone();
        move || quorum_coordinator::DeterministicOfflineSynthesisEngine::trigger_background_ollama_pull(&m)
    })
    .await
    .unwrap_or(false);
    let installed = tokio::task::spawn_blocking(
        quorum_coordinator::DeterministicOfflineSynthesisEngine::probe_installed_ollama_models_default,
    )
    .await
    .unwrap_or_default();

    Json(serde_json::json!({
        "status": if started { "pulling" } else { "already_queued_or_installed" },
        "model": model,
        "terminal_command": format!("ollama pull {}", model),
        "installed_models": installed
    }))
    .into_response()
}

/// Model family and hardware telemetry recommendation endpoint: `GET /api/models`.
pub async fn models_handler(
    State(state): State<Arc<DaemonState>>,
) -> impl IntoResponse {
    let hw = HardwareTelemetry::probe();
    let qwen_tag = quorum_coordinator::AutoFusionRouter::size_qwen_by_hardware(&hw);
    let gemma_tag = quorum_coordinator::AutoFusionRouter::size_gemma_by_hardware(&hw);
    let gemma4_eligible = quorum_coordinator::AutoFusionRouter::can_run_gemma4_26b(&hw);
    let installed = tokio::task::spawn_blocking(
        quorum_coordinator::DeterministicOfflineSynthesisEngine::probe_installed_ollama_models_default,
    )
    .await
    .unwrap_or_default();
    let gemma4_installed = installed
        .iter()
        .any(|m| m.eq_ignore_ascii_case("gemma4:26b") || m.to_ascii_lowercase().starts_with("gemma4:26b"));

    Json(serde_json::json!({
        "active_family": format!("{:?}", state.default_model_family),
        "ollama_online": !installed.is_empty(),
        "installed_models": installed,
        "gemma4_26b_installed": gemma4_installed,
        "gemma4_26b_memory_eligible": gemma4_eligible,
        "available_families": [
            {
                "id": "AutoFusion",
                "name": "Auto-Fusion Dynamic Router",
                "description": "Automatically selects Gemma 4 26B, GLM-4-9B, or Qwen 2.5 based on AST code content and runtime free RAM/VRAM."
            },
            {
                "id": "Gemma4_26b",
                "name": "Gemma 4 26B (gemma4:26b)",
                "description": "26B MoE high-precision synthesis gated on >=18 GB free RAM or >=16 GB free VRAM."
            },
            {
                "id": "Glm4Agentic",
                "name": "GLM-4-9B Agentic",
                "description": "Multi-hop graph reasoning with 128K context window."
            },
            {
                "id": "Qwen25Code",
                "name": format!("Qwen 2.5 Code ({})", qwen_tag),
                "description": "Code specialist model sized dynamically by available RAM/VRAM."
            },
            {
                "id": "GemmaProse",
                "name": format!("Gemma Prose ({})", gemma_tag),
                "description": "Crisp natural prose from the Google Gemma stack."
            }
        ],
        "hardware_recommendation": {
            "free_ram_gb": hw.free_ram_gb,
            "free_vram_mb": hw.free_vram_mb,
            "gpu_name": hw.gpu_name,
            "recommended_qwen_tier": qwen_tag,
            "recommended_gemma_tier": gemma_tag,
            "default_synthesis_tier": if gemma4_installed && gemma4_eligible {
                "gemma4:26b"
            } else if hw.free_ram_gb >= 12.0 || hw.free_vram_mb >= 4500 {
                "glm4:9b"
            } else {
                "gemma2:2b"
            }
        }
    }))
}
