use crate::error::CoordinatorError;
use chrono::Utc;
use quorum_contract::EmbeddingGenerator;
use quorum_network::NetworkSwarmHandle;
use quorum_types::{CandidateChunkDto, FederatedQueryRequest, FederatedQueryResponse};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Lightweight signed canary query string recognized by `OsoosiMeshInboundHandler`
/// to verify end-to-end libp2p Noise + Yamux + Ed25519 request-response liveness in <1ms
/// without touching LanceDB or Tantivy. Older peers also handle it safely as an empty-hit query.
pub const P2P_WATCHER_CANARY_QUERY: &str = "__quorum_p2p_watcher_ping__";

/// Live per-peer RTT and reliability telemetry tracked across real queries and watcher probes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerHealthStats {
    pub peer_id: String,
    pub last_rtt_ms: Option<f64>,
    pub avg_rtt_ms: Option<f64>,
    #[serde(default)]
    pub canary_rtt_ms: Option<f64>,
    pub success_count: u64,
    pub failure_count: u64,
    pub consecutive_failures: u32,
    pub last_chunks_returned: usize,
    pub last_seen_rfc3339: Option<String>,
    pub last_error: Option<String>,
}

/// Process-wide thread-safe registry of live P2P peer RTTs and failure streaks.
#[derive(Default)]
pub struct PeerHealthRegistry {
    stats: std::sync::RwLock<HashMap<String, PeerHealthStats>>,
}

impl PeerHealthRegistry {
    pub fn new() -> Self {
        Self {
            stats: std::sync::RwLock::new(HashMap::new()),
        }
    }

    pub fn record_success(&self, peer_id: &str, rtt_ms: f64, chunks_returned: usize) {
        let mut guard = self.stats.write().unwrap_or_else(|e| e.into_inner());
        let entry = guard
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerHealthStats {
                peer_id: peer_id.to_string(),
                ..Default::default()
            });
        let rounded = (rtt_ms * 100.0).round() / 100.0;
        entry.last_rtt_ms = Some(rounded);
        entry.avg_rtt_ms = Some(match entry.avg_rtt_ms {
            Some(prev) => ((prev * 0.7 + rounded * 0.3) * 100.0).round() / 100.0,
            None => rounded,
        });
        entry.success_count = entry.success_count.saturating_add(1);
        entry.consecutive_failures = 0;
        entry.last_chunks_returned = chunks_returned;
        entry.last_seen_rfc3339 = Some(Utc::now().to_rfc3339());
        entry.last_error = None;
    }

    /// Record a lightweight canary probe (updates liveness & canary_rtt_ms without corrupting search avg_rtt_ms).
    pub fn record_canary_probe(&self, peer_id: &str, rtt_ms: f64) {
        let mut guard = self.stats.write().unwrap_or_else(|e| e.into_inner());
        let entry = guard
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerHealthStats {
                peer_id: peer_id.to_string(),
                ..Default::default()
            });
        let rounded = (rtt_ms * 100.0).round() / 100.0;
        entry.canary_rtt_ms = Some(rounded);
        if entry.last_rtt_ms.is_none() {
            entry.last_rtt_ms = Some(rounded);
        }
        entry.success_count = entry.success_count.saturating_add(1);
        entry.consecutive_failures = 0;
        entry.last_seen_rfc3339 = Some(Utc::now().to_rfc3339());
        entry.last_error = None;
    }

    pub fn record_failure(&self, peer_id: &str, error_msg: impl Into<String>) {
        let mut guard = self.stats.write().unwrap_or_else(|e| e.into_inner());
        let entry = guard
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerHealthStats {
                peer_id: peer_id.to_string(),
                ..Default::default()
            });
        entry.failure_count = entry.failure_count.saturating_add(1);
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        entry.last_error = Some(error_msg.into());
    }

    pub fn get(&self, peer_id: &str) -> Option<PeerHealthStats> {
        let guard = self.stats.read().unwrap_or_else(|e| e.into_inner());
        guard.get(peer_id).cloned()
    }

    pub fn snapshot(&self) -> HashMap<String, PeerHealthStats> {
        let guard = self.stats.read().unwrap_or_else(|e| e.into_inner());
        guard.clone()
    }

    pub fn unhealthy_peers(&self, min_consecutive_failures: u32) -> Vec<String> {
        let guard = self.stats.read().unwrap_or_else(|e| e.into_inner());
        guard
            .values()
            .filter(|s| s.consecutive_failures >= min_consecutive_failures)
            .map(|s| s.peer_id.clone())
            .collect()
    }

    pub fn clear_peer_failures(&self, peer_id: &str) {
        let mut guard = self.stats.write().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = guard.get_mut(peer_id) {
            entry.consecutive_failures = 0;
            entry.last_error = None;
        }
    }
}

/// Returns the singleton `PeerHealthRegistry` shared by `SwarmMeshDispatcher`, `/api/peers`, and `p2p_watcher`.
pub fn global_peer_health_registry() -> &'static PeerHealthRegistry {
    static REGISTRY: OnceLock<PeerHealthRegistry> = OnceLock::new();
    REGISTRY.get_or_init(PeerHealthRegistry::new)
}

/// Bounded Admission Controller and Stream Pool Manager for outbound federated P2P mesh queries.
#[derive(Clone)]
pub struct MeshQueryAdmissionController {
    pub global_semaphore: Arc<tokio::sync::Semaphore>,
    pub per_peer_semaphores: Arc<dashmap::DashMap<String, Arc<tokio::sync::Semaphore>>>,
    pub max_per_peer: usize,
    pub global_capacity: usize,
    pub peak_global_in_use: Arc<std::sync::atomic::AtomicUsize>,
    pub total_admitted: Arc<std::sync::atomic::AtomicUsize>,
}

impl MeshQueryAdmissionController {
    pub fn new(global_concurrency: usize, max_per_peer: usize) -> Self {
        let cap = global_concurrency.clamp(8, 128);
        Self {
            global_semaphore: Arc::new(tokio::sync::Semaphore::new(cap)),
            per_peer_semaphores: Arc::new(dashmap::DashMap::new()),
            max_per_peer: max_per_peer.clamp(1, 16),
            global_capacity: cap,
            peak_global_in_use: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            total_admitted: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    pub fn global() -> &'static Self {
        static INSTANCE: OnceLock<MeshQueryAdmissionController> = OnceLock::new();
        INSTANCE.get_or_init(|| MeshQueryAdmissionController::new(64, 4))
    }

    pub async fn acquire_permit(
        &self,
        peer_id: &str,
    ) -> Result<(tokio::sync::OwnedSemaphorePermit, tokio::sync::OwnedSemaphorePermit), CoordinatorError> {
        let global_permit = self
            .global_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| CoordinatorError::Network(format!("Global mesh query semaphore closed: {}", e)))?;

        let peer_sem = self
            .per_peer_semaphores
            .entry(peer_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(self.max_per_peer)))
            .value()
            .clone();

        let peer_permit = peer_sem
            .acquire_owned()
            .await
            .map_err(|e| CoordinatorError::Network(format!("Peer query semaphore closed: {}", e)))?;

        let in_use = self
            .global_capacity
            .saturating_sub(self.global_semaphore.available_permits());
        self.peak_global_in_use
            .fetch_max(in_use, std::sync::atomic::Ordering::Relaxed);
        self.total_admitted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        Ok((global_permit, peer_permit))
    }

    pub fn peak_in_use(&self) -> usize {
        self.peak_global_in_use.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn total_admitted(&self) -> usize {
        self.total_admitted.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn available_global_permits(&self) -> usize {
        self.global_semaphore.available_permits()
    }
}

/// Clean interface abstraction separating mesh querying mechanisms.
#[async_trait::async_trait]
pub trait MeshQueryDispatcher: Send + Sync {
    async fn query_peers(
        &self,
        request: &FederatedQueryRequest,
        timeout: Duration,
    ) -> Result<Vec<FederatedQueryResponse>, CoordinatorError>;

    async fn query_peers_with_diagnostics(
        &self,
        request: &FederatedQueryRequest,
        timeout: Duration,
    ) -> Result<(Vec<FederatedQueryResponse>, quorum_types::FederatedPeerDiagnostics), CoordinatorError> {
        let responses = self.query_peers(request, timeout).await?;
        let diagnostics = quorum_types::FederatedPeerDiagnostics {
            connected_peers_count: self.peer_count(),
            connected_peer_ids: Vec::new(),
            queried_peers_count: responses.len(),
            peer_outcomes: Vec::new(),
            summary_reason: None,
            contributing_peer_ids: Vec::new(),
        };
        Ok((responses, diagnostics))
    }

    fn peer_count(&self) -> usize;
}

/// Simulated remote peer node with network latency and authorized access tier for testing.
#[derive(Debug, Clone)]
pub struct MockRemotePeer {
    pub peer_id: String,
    pub latency: Duration,
    pub max_access_tier: u8,
    pub candidate_chunks: Vec<CandidateChunkDto>,
}

impl MockRemotePeer {
    pub async fn handle_query(&self, requested_tier: u8) -> Vec<CandidateChunkDto> {
        tokio::time::sleep(self.latency).await;
        let effective_tier = requested_tier.min(self.max_access_tier);
        self.candidate_chunks
            .iter()
            .filter(|c| c.access_tier <= effective_tier)
            .cloned()
            .collect()
    }
}

/// In-memory mock dispatcher holding multiple mock peers for deterministic testing.
#[derive(Debug, Default, Clone)]
pub struct MockMeshDispatcher {
    pub peers: Arc<RwLock<Vec<MockRemotePeer>>>,
}

impl MockMeshDispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn add_peer(&self, peer: MockRemotePeer) {
        let mut p = self.peers.write().await;
        p.push(peer);
    }
}

#[async_trait::async_trait]
impl MeshQueryDispatcher for MockMeshDispatcher {
    async fn query_peers(
        &self,
        request: &FederatedQueryRequest,
        timeout: Duration,
    ) -> Result<Vec<FederatedQueryResponse>, CoordinatorError> {
        let (responses, _) = self.query_peers_with_diagnostics(request, timeout).await?;
        Ok(responses)
    }

    async fn query_peers_with_diagnostics(
        &self,
        request: &FederatedQueryRequest,
        timeout: Duration,
    ) -> Result<(Vec<FederatedQueryResponse>, quorum_types::FederatedPeerDiagnostics), CoordinatorError> {
        let peers = self.peers.read().await.clone();
        let connected_peers_count = peers.len();
        let connected_peer_ids: Vec<String> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let mut diagnostics = quorum_types::FederatedPeerDiagnostics::new(
            connected_peers_count,
            connected_peer_ids.clone(),
        );

        let mesh_port = {
            let controller = crate::dlp_mesh::global_mesh_dlp_controller();
            let s = controller.settings.read().unwrap_or_else(|e| e.into_inner());
            s.mesh.mesh_port
        };

        if peers.is_empty() {
            diagnostics.compute_summary_reason(mesh_port, timeout.as_millis() as u64);
            return Ok((Vec::new(), diagnostics));
        }

        diagnostics.queried_peers_count = peers.len();

        use futures::stream::{FuturesUnordered, StreamExt};

        let mut pending_ids: std::collections::HashSet<String> = connected_peer_ids.into_iter().collect();
        let mut futures = FuturesUnordered::new();
        for peer in peers {
            let req = request.clone();
            futures.push(tokio::spawn(async move {
                let _permits = MeshQueryAdmissionController::global()
                    .acquire_permit(&peer.peer_id)
                    .await;
                let start = std::time::Instant::now();
                let chunks = peer.handle_query(0).await;
                let latency_ms = start.elapsed().as_millis() as u64;
                (peer.peer_id, req.query_id, chunks, latency_ms)
            }));
        }

        let max_peer_responses = {
            let controller = crate::dlp_mesh::global_mesh_dlp_controller();
            let s = controller.settings.read().unwrap_or_else(|e| e.into_inner());
            if s.mesh.max_peer_responses > 0 {
                s.mesh.max_peer_responses
            } else {
                8
            }
        };

        let mut responses = Vec::new();
        let primary_deadline = tokio::time::Instant::now() + timeout;
        let mut active_deadline = primary_deadline;
        let mut _got_non_empty = false;

        loop {
            if futures.is_empty() {
                break;
            }
            let now = tokio::time::Instant::now();
            if now >= active_deadline {
                break;
            }
            let remaining = active_deadline.saturating_duration_since(now);
            match tokio::time::timeout(remaining, futures.next()).await {
                Ok(Some(Ok((peer_id, query_id, chunks, latency_ms)))) => {
                    pending_ids.remove(&peer_id);
                    let chunks_count = chunks.len();
                    let status = if chunks_count > 0 {
                        quorum_types::PeerQueryStatus::Connected
                    } else {
                        quorum_types::PeerQueryStatus::ZeroMatchingChunks
                    };
                    diagnostics.peer_outcomes.push(quorum_types::PeerQueryOutcome {
                        peer_id: peer_id.clone(),
                        status,
                        matching_chunk_count: chunks_count,
                        cited_chunk_count: 0,
                        latency_ms,
                        error_message: None,
                    });
                    responses.push(FederatedQueryResponse {
                        query_id,
                        responder_peer_id: peer_id,
                        chunks,
                    });
                    if responses.len() >= max_peer_responses || pending_ids.is_empty() {
                        break;
                    }
                    if chunks_count > 0 {
                        _got_non_empty = true;
                        let max_straggler_grace = Duration::from_millis(300);
                        let straggler_deadline = tokio::time::Instant::now() + max_straggler_grace;
                        if straggler_deadline < active_deadline {
                            active_deadline = straggler_deadline;
                        }
                    }
                }
                _ => break,
            }
        }

        for stalled_peer in pending_ids {
            diagnostics.peer_outcomes.push(quorum_types::PeerQueryOutcome {
                peer_id: stalled_peer,
                status: quorum_types::PeerQueryStatus::TimedOut,
                matching_chunk_count: 0,
                cited_chunk_count: 0,
                latency_ms: timeout.as_millis() as u64,
                error_message: Some(format!("Timed out after {}ms", timeout.as_millis())),
            });
        }

        diagnostics.compute_summary_reason(mesh_port, timeout.as_millis() as u64);

        Ok((responses, diagnostics))
    }

    fn peer_count(&self) -> usize {
        self.peers.try_read().map(|p| p.len()).unwrap_or(0)
    }
}

/// Production mesh dispatcher bridging to the `NetworkSwarmHandle`.
#[derive(Clone)]
pub struct SwarmMeshDispatcher {
    pub handle: NetworkSwarmHandle,
    pub last_bootstrap_dial_ms: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl SwarmMeshDispatcher {
    pub fn new(handle: NetworkSwarmHandle) -> Self {
        Self {
            handle,
            last_bootstrap_dial_ms: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Calculate dynamic per-peer tail-latency deadline based on historical RTT.
    pub fn calculate_peer_deadline(peer_id: &str, requested_timeout: Duration) -> Duration {
        let registry = global_peer_health_registry();
        if let Some(stats) = registry.get(peer_id) {
            if let Some(avg_rtt) = stats.avg_rtt_ms {
                if avg_rtt > 0.0 {
                    let req_ms = requested_timeout.as_millis() as u64;
                    let min_floor = 4000u64.min(req_ms.max(1000));
                    let dyn_ms = ((avg_rtt * 2.5) + 3000.0).round() as u64;
                    return Duration::from_millis(dyn_ms.clamp(min_floor, req_ms.max(min_floor)));
                }
            }
        }
        requested_timeout
    }
}

#[async_trait::async_trait]
impl MeshQueryDispatcher for SwarmMeshDispatcher {
    async fn query_peers(
        &self,
        request: &FederatedQueryRequest,
        timeout: Duration,
    ) -> Result<Vec<FederatedQueryResponse>, CoordinatorError> {
        let (responses, _) = self.query_peers_with_diagnostics(request, timeout).await?;
        Ok(responses)
    }

    async fn query_peers_with_diagnostics(
        &self,
        request: &FederatedQueryRequest,
        timeout: Duration,
    ) -> Result<(Vec<FederatedQueryResponse>, quorum_types::FederatedPeerDiagnostics), CoordinatorError> {
        if crate::artemis_airgap::contains_artemis_query(&request.query_text) {
            let mut diagnostics = quorum_types::FederatedPeerDiagnostics::new(0, Vec::new());
            diagnostics.summary_reason = Some("Suppressed outbound query referencing local-only artemis:// URI".to_string());
            return Ok((Vec::new(), diagnostics));
        }
        let mut peers = self
            .handle
            .connected_peers()
            .await
            .map_err(|e| CoordinatorError::Network(e.to_string()))?;

        // If no peers are currently connected (e.g., idle TCP drop or remote node restarted),
        // proactively dial configured bootstrap_peers and known peers from p2p_known_peers.json on mesh port,
        // subject to a 10-second cooldown so offline peers do not inject 450ms sleep per sub-query.
        if peers.is_empty() {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let last_dial = self
                .last_bootstrap_dial_ms
                .load(std::sync::atomic::Ordering::Relaxed);
            if now_ms.saturating_sub(last_dial) >= 10_000 {
                self.last_bootstrap_dial_ms
                    .store(now_ms, std::sync::atomic::Ordering::Relaxed);
                let (bootstrap_addrs, mesh_port) = {
                    let controller = crate::dlp_mesh::global_mesh_dlp_controller();
                    let s = controller.settings.read().unwrap_or_else(|e| e.into_inner());
                    (s.mesh.bootstrap_peers.clone(), s.mesh.mesh_port)
                };
                let mut dial_targets: Vec<String> = bootstrap_addrs;

                // Discover and dial known peers from p2p_known_peers.json on mesh_port (default 3032)
                let controller = crate::dlp_mesh::global_mesh_dlp_controller();
                let known_peers_path = controller
                    .settings_file_path
                    .read()
                    .ok()
                    .and_then(|p| p.as_ref().and_then(|f| f.parent().map(|d| d.join("p2p_known_peers.json"))));

                if let Some(path) = known_peers_path {
                    if let Ok(raw) = std::fs::read_to_string(&path) {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                            if let Some(multiaddrs) = val.get("multiaddrs").and_then(|m| m.as_array()) {
                                for ma in multiaddrs {
                                    if let Some(s) = ma.as_str() {
                                        let s = s.trim();
                                        if !s.contains("/4001")
                                            && (s.contains(&format!("/tcp/{}", mesh_port))
                                                || s.contains(&format!("/udp/{}", mesh_port))
                                                || s.contains("/tcp/3032"))
                                        {
                                            dial_targets.push(s.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                dial_targets.retain(|a| !a.contains("/4001"));

                if !dial_targets.is_empty() {
                    for addr_str in &dial_targets {
                        if let Ok(addr) = addr_str.trim().parse::<quorum_network::Multiaddr>() {
                            let _ = self.handle.dial(addr).await;
                        }
                    }
                    for _ in 0..9 {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        if let Ok(rechecked) = self.handle.connected_peers().await {
                            if !rechecked.is_empty() {
                                peers = rechecked;
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Filter out non-QuorumRAG IPFS peers on port 4001 before dispatching candidate queries
        let connected_addrs = self.handle.connected_peer_addresses();
        peers.retain(|peer| {
            if let Some(addr) = connected_addrs.get(peer) {
                let s = addr.to_string();
                !s.contains("/tcp/4001") && !s.contains("/udp/4001") && !s.ends_with(":4001")
            } else {
                true
            }
        });

        // Filter out known dead peers (>=3 consecutive failures) when healthy peers exist,
        // but do not evict peers if confirmed reachable by the watcher.
        let registry = global_peer_health_registry();
        if peers.len() > 1 {
            let has_healthy = peers.iter().any(|p| {
                registry.get(&p.to_string()).map_or(true, |s| s.consecutive_failures < 3 || s.canary_rtt_ms.is_some())
            });
            if has_healthy {
                peers.retain(|p| {
                    registry.get(&p.to_string()).map_or(true, |s| s.consecutive_failures < 3 || s.canary_rtt_ms.is_some())
                });
            }
        }

        let mesh_port = {
            let controller = crate::dlp_mesh::global_mesh_dlp_controller();
            let s = controller.settings.read().unwrap_or_else(|e| e.into_inner());
            s.mesh.mesh_port
        };

        let mut diagnostics = quorum_types::FederatedPeerDiagnostics::new(
            peers.len(),
            peers.iter().map(|p| p.to_string()).collect(),
        );

        if peers.is_empty() {
            diagnostics.compute_summary_reason(mesh_port, timeout.as_millis() as u64);
            return Ok((Vec::new(), diagnostics));
        }

        diagnostics.queried_peers_count = peers.len();
        let total_queried = peers.len();

        use futures::stream::{FuturesUnordered, StreamExt};

        let mut pending_peer_ids: HashSet<String> =
            peers.iter().map(|p| p.to_string()).collect();

        let admission = MeshQueryAdmissionController::global().clone();
        let mut futures = FuturesUnordered::new();
        for peer in peers {
            let peer_str = peer.to_string();
            let handle = self.handle.clone();
            let req = request.clone();
            let admission = admission.clone();
            futures.push(tokio::spawn(async move {
                let _permits = match admission.acquire_permit(&peer_str).await {
                    Ok(p) => p,
                    Err(e) => {
                        return (
                            peer_str,
                            Err(quorum_network::NetworkError::Io(std::io::Error::other(e.to_string()))),
                            0.0,
                        );
                    }
                };
                let peer_timeout = Self::calculate_peer_deadline(&peer_str, timeout);
                let started = Instant::now();
                let res = match tokio::time::timeout(peer_timeout, handle.send_query(peer, req)).await {
                    Ok(r) => r,
                    Err(_) => Err(quorum_network::NetworkError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("Dynamic tail-latency deadline ({:?}) exceeded for peer {}", peer_timeout, peer_str),
                    ))),
                };
                let rtt_ms = started.elapsed().as_secs_f64() * 1000.0;
                (peer_str, res, rtt_ms)
            }));
        }

        let max_peer_responses = {
            let controller = crate::dlp_mesh::global_mesh_dlp_controller();
            let s = controller.settings.read().unwrap_or_else(|e| e.into_inner());
            if s.mesh.max_peer_responses > 0 {
                s.mesh.max_peer_responses
            } else {
                8
            }
        };

        let primary_deadline = tokio::time::Instant::now() + timeout;
        let mut active_deadline = primary_deadline;
        let mut _got_non_empty_peer = false;
        let mut responses = Vec::new();

        loop {
            if futures.is_empty() {
                break;
            }
            let now = tokio::time::Instant::now();
            if now >= active_deadline {
                break;
            }
            let remaining = active_deadline.saturating_duration_since(now);
            match tokio::time::timeout(remaining, futures.next()).await {
                Ok(Some(Ok((peer_str, Ok(resp), rtt_ms)))) => {
                    pending_peer_ids.remove(&peer_str);
                    let chunks_len = resp.chunks.len();
                    registry.record_success(&peer_str, rtt_ms, chunks_len);
                    let status = if chunks_len > 0 {
                        quorum_types::PeerQueryStatus::Connected
                    } else {
                        quorum_types::PeerQueryStatus::ZeroMatchingChunks
                    };
                    diagnostics.peer_outcomes.push(quorum_types::PeerQueryOutcome {
                        peer_id: peer_str.clone(),
                        status,
                        matching_chunk_count: chunks_len,
                        cited_chunk_count: 0,
                        latency_ms: rtt_ms as u64,
                        error_message: None,
                    });
                    tracing::info!(
                        peer = %peer_str,
                        rtt_ms = format!("{:.1}", rtt_ms),
                        chunks = chunks_len,
                        "Received federated P2P mesh response"
                    );
                    responses.push(resp);

                    // EARLY RESOLUTION LAW:
                    // 1. If all queried peers have responded or max responses reached, break immediately.
                    if responses.len() >= total_queried || responses.len() >= max_peer_responses || pending_peer_ids.is_empty() {
                        break;
                    }

                    // 2. Once responses have arrived with matching chunks, activate straggler grace.
                    // Straggler grace must only activate when got_non_empty_peer is true (chunks_len > 0).
                    // Never reduce the remaining search deadline when chunks_len == 0 and no other peer has returned hits.
                    if chunks_len > 0 {
                        _got_non_empty_peer = true;
                        let max_straggler_grace = Duration::from_millis(300);
                        let straggler_deadline = tokio::time::Instant::now() + max_straggler_grace;
                        if straggler_deadline < active_deadline {
                            active_deadline = straggler_deadline;
                        }
                    }
                }
                Ok(Some(Ok((peer_str, Err(err), rtt_ms)))) => {
                    pending_peer_ids.remove(&peer_str);
                    let err_str = err.to_string();
                    registry.record_failure(&peer_str, err_str.clone());
                    let status = if err_str.to_ascii_lowercase().contains("policy")
                        || err_str.to_ascii_lowercase().contains("dlp")
                        || err_str.to_ascii_lowercase().contains("folder")
                    {
                        quorum_types::PeerQueryStatus::BlockedByPolicy
                    } else {
                        quorum_types::PeerQueryStatus::NetworkError
                    };
                    diagnostics.peer_outcomes.push(quorum_types::PeerQueryOutcome {
                        peer_id: peer_str.clone(),
                        status,
                        matching_chunk_count: 0,
                        cited_chunk_count: 0,
                        latency_ms: rtt_ms as u64,
                        error_message: Some(err_str.clone()),
                    });
                    tracing::warn!(
                        peer = %peer_str,
                        rtt_ms = format!("{:.1}", rtt_ms),
                        error = %err,
                        "Federated P2P mesh query to peer failed"
                    );
                    if pending_peer_ids.is_empty() || (!responses.is_empty() && responses.len() >= max_peer_responses) {
                        break;
                    }
                }
                Ok(Some(Err(join_err))) => {
                    tracing::warn!("Swarm query task join error: {}", join_err);
                }
                Ok(None) => break,
                Err(_) => {
                    // Deadline reached while remaining peers were still in flight
                    break;
                }
            }
        }

        // Any peers still pending when the primary deadline expired (not merely shortened straggler grace)
        // are recorded as timed-out so the P2P Watcher can proactively probe & heal zombie streams.
        let primary_expired = tokio::time::Instant::now() >= primary_deadline;
        if !pending_peer_ids.is_empty() {
            for stalled_peer in &pending_peer_ids {
                if primary_expired {
                    registry.record_failure(
                        stalled_peer,
                        format!("Timed out after {}ms", timeout.as_millis()),
                    );
                    diagnostics.peer_outcomes.push(quorum_types::PeerQueryOutcome {
                        peer_id: stalled_peer.clone(),
                        status: quorum_types::PeerQueryStatus::TimedOut,
                        matching_chunk_count: 0,
                        cited_chunk_count: 0,
                        latency_ms: timeout.as_millis() as u64,
                        error_message: Some(format!("Timed out after {}ms", timeout.as_millis())),
                    });
                    tracing::warn!(
                        peer = %stalled_peer,
                        timeout_ms = timeout.as_millis() as u64,
                        "Federated P2P mesh query timed out waiting for peer"
                    );
                } else {
                    // Straggler grace cutoff: query succeeded early with faster peers.
                    // Do NOT record failure against peer health registry to prevent false-positive quarantining.
                    diagnostics.peer_outcomes.push(quorum_types::PeerQueryOutcome {
                        peer_id: stalled_peer.clone(),
                        status: quorum_types::PeerQueryStatus::TimedOut,
                        matching_chunk_count: 0,
                        cited_chunk_count: 0,
                        latency_ms: timeout.as_millis() as u64,
                        error_message: Some("Cut off by straggler grace period (early resolution)".to_string()),
                    });
                    tracing::info!(
                        peer = %stalled_peer,
                        "Peer in-flight query superseded by straggler grace cutoff"
                    );
                }
            }
        }

        diagnostics.compute_summary_reason(mesh_port, timeout.as_millis() as u64);

        Ok((responses, diagnostics))
    }

    fn peer_count(&self) -> usize {
        self.handle.connected_peer_addresses().len()
    }
}

/// Dispatches only to local storage without any remote peers.
#[derive(Debug, Default, Clone)]
pub struct LocalOnlyDispatcher;

#[async_trait::async_trait]
impl MeshQueryDispatcher for LocalOnlyDispatcher {
    async fn query_peers(
        &self,
        _request: &FederatedQueryRequest,
        _timeout: Duration,
    ) -> Result<Vec<FederatedQueryResponse>, CoordinatorError> {
        Ok(Vec::new())
    }

    fn peer_count(&self) -> usize {
        0
    }
}

/// Production inbound Mesh query handler enforcing OshoosiClaw Shared Folder ACLs
/// and Two-Tier HIPAA PHI / PII Data Loss Prevention (`Redact` or `Block`).
pub struct OsoosiMeshInboundHandler {
    pub local_storage: Arc<dyn crate::scatter_gather::StorageSearcher>,
    pub local_peer_id: String,
    pub embedder: Option<Arc<dyn quorum_contract::EmbeddingGenerator>>,
}

impl OsoosiMeshInboundHandler {
    pub fn new(
        local_storage: Arc<dyn crate::scatter_gather::StorageSearcher>,
        local_peer_id: impl Into<String>,
    ) -> Self {
        Self {
            local_storage,
            local_peer_id: local_peer_id.into(),
            embedder: None,
        }
    }

    pub fn with_embedder(
        mut self,
        embedder: Arc<dyn quorum_contract::EmbeddingGenerator>,
    ) -> Self {
        self.embedder = Some(embedder);
        self
    }

    pub fn new_with_embedder(
        local_storage: Arc<dyn crate::scatter_gather::StorageSearcher>,
        local_peer_id: impl Into<String>,
        embedder: Arc<dyn quorum_contract::EmbeddingGenerator>,
    ) -> Self {
        Self {
            local_storage,
            local_peer_id: local_peer_id.into(),
            embedder: Some(embedder),
        }
    }
}

#[async_trait::async_trait]
impl quorum_network::InboundQueryHandler for OsoosiMeshInboundHandler {
    async fn handle_query(&self, req: FederatedQueryRequest) -> FederatedQueryResponse {
        // 1. Reject malformed payloads: embedding dimension 768, finite floats, text length <= 4096, top_k > 0 (except signed canary ping)
        if req.embedding.len() != 768
            || !req.embedding.iter().all(|f| f.is_finite())
            || req.query_text.len() > 4096
            || (req.top_k == 0 && req.query_text != P2P_WATCHER_CANARY_QUERY)
        {
            tracing::warn!(
                "Rejecting malformed mesh query payload from peer: {}",
                req.sender_peer_id
            );
            return FederatedQueryResponse {
                query_id: req.query_id,
                responder_peer_id: self.local_peer_id.clone(),
                chunks: Vec::new(),
            };
        }

        // 1b. Reject incoming queries targeting airgapped artemis forensic records
        if crate::artemis_airgap::contains_artemis_query(&req.query_text) {
            tracing::warn!(
                "Rejecting inbound P2P mesh query referencing airgapped artemis:// from peer: {}",
                req.sender_peer_id
            );
            return FederatedQueryResponse {
                query_id: req.query_id,
                responder_peer_id: self.local_peer_id.clone(),
                chunks: Vec::new(),
            };
        }

        // 2. Validate sender_pubkey derives to claimed sender_peer_id
        match quorum_network::derive_peer_id_from_pubkey(&req.sender_pubkey) {
            Ok(derived_id) => {
                if derived_id.to_string() != req.sender_peer_id {
                    tracing::warn!(
                        "Rejecting spoofed sender peer id: claimed={}, derived={}",
                        req.sender_peer_id,
                        derived_id
                    );
                    return FederatedQueryResponse {
                        query_id: req.query_id,
                        responder_peer_id: self.local_peer_id.clone(),
                        chunks: Vec::new(),
                    };
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Rejecting invalid sender pubkey from {}: {}",
                    req.sender_peer_id,
                    e
                );
                return FederatedQueryResponse {
                    query_id: req.query_id,
                    responder_peer_id: self.local_peer_id.clone(),
                    chunks: Vec::new(),
                };
            }
        }

        let controller = crate::dlp_mesh::global_mesh_dlp_controller();
        let (p2p_enabled, is_quarantined, max_tier) = {
            let guard = controller.settings.read().unwrap_or_else(|e| e.into_inner());
            let q = guard
                .mesh
                .quarantined_peers
                .iter()
                .any(|p| p.eq_ignore_ascii_case(&req.sender_peer_id));
            (
                guard.mesh.p2p_enabled,
                q,
                guard.ui.default_peer_access_tier,
            )
        };

        if !p2p_enabled || is_quarantined {
            return FederatedQueryResponse {
                query_id: req.query_id,
                responder_peer_id: self.local_peer_id.clone(),
                chunks: Vec::new(),
            };
        }

        // 3. Cryptographic handshake & anti-replay timestamp verification (drift <= 60s)
        let mut verified_tier = None;
        for t in 0..=3 {
            if let Ok(candidate_tier) = quorum_types::AccessTier::from_u8(t) {
                if crate::crypto::verify_request(&req, candidate_tier, 60).is_ok() {
                    verified_tier = Some(candidate_tier);
                    break;
                }
            }
        }

        let effective_tier = match verified_tier {
            Some(tier) => tier.as_u8().min(max_tier),
            None => {
                tracing::warn!(
                    "Rejecting unverified or stale query signature (>60s drift) from peer: {}",
                    req.sender_peer_id
                );
                return FederatedQueryResponse {
                    query_id: req.query_id,
                    responder_peer_id: self.local_peer_id.clone(),
                    chunks: Vec::new(),
                };
            }
        };

        // Fast-path P2P Watcher signed canary ping: proves full libp2p + Ed25519 + ACL liveness in <1ms
        if req.query_text == P2P_WATCHER_CANARY_QUERY {
            global_peer_health_registry().record_canary_probe(&req.sender_peer_id, 0.5);
            return FederatedQueryResponse {
                query_id: req.query_id,
                responder_peer_id: self.local_peer_id.clone(),
                chunks: Vec::new(),
            };
        }

        // Re-embed query in local embedding space if local embedder is available or incoming vector is unpopulated
        let query_embedding = if let Some(ref embedder) = self.embedder {
            match embedder.embed_text(&req.query_text) {
                Ok(vec) if vec.len() == 768 => vec,
                Ok(_) => req.embedding.clone(),
                Err(err) => {
                    tracing::warn!("Failed to re-embed mesh query text locally: {}; falling back to req.embedding", err);
                    req.embedding.clone()
                }
            }
        } else if req.embedding.iter().all(|&f| f == 0.0) {
            let offline = quorum_contract::DeterministicOfflineEngine::new();
            offline.embed_text(&req.query_text).unwrap_or_else(|_| req.embedding.clone())
        } else {
            req.embedding.clone()
        };

        let (mut scored, text_scored) = tokio::join!(
            self.local_storage.search_hybrid(
                &req.query_text,
                &query_embedding,
                effective_tier,
                req.top_k.clamp(16, 32),
            ),
            self.local_storage
                .search_text(&req.query_text, effective_tier, 24)
        );

        let mut seen_ids: std::collections::HashSet<String> =
            scored.iter().map(|c| c.chunk.chunk_id.clone()).collect();
        for hit in text_scored {
            if seen_ids.insert(hit.chunk.chunk_id.clone()) {
                scored.push(hit);
            }
        }

        // Preserve multimodal chunks matching key query content terms
        let query_words: Vec<&str> = req
            .query_text
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| w.len() >= 4)
            .collect();
        if !query_words.is_empty() && !scored.iter().any(|c| {
            let p = c.chunk.file_path.to_ascii_lowercase();
            p.ends_with(".png") || p.ends_with(".jpg") || p.ends_with(".jpeg")
        }) {
            for word in &query_words {
                let media_hits = self.local_storage.search_text(word, effective_tier, 8).await;
                for hit in media_hits {
                    let path_l = hit.chunk.file_path.to_ascii_lowercase();
                    if (path_l.ends_with(".png")
                        || path_l.ends_with(".jpg")
                        || path_l.ends_with(".jpeg")
                        || path_l.ends_with(".gif")
                        || path_l.ends_with(".webp")
                        || hit.chunk.text_content.starts_with("[Image Document:"))
                        && seen_ids.insert(hit.chunk.chunk_id.clone())
                    {
                        scored.push(hit);
                    }
                }
            }
        }

        // Expand adjacent/body chunks (`{doc_id}:0..=4`) for the top matched multi-chunk documents
        // so when Chunk 0 matches primarily via its title/header banner (e.g. a resume timeline),
        // the subsequent career/body chunks are included in the federated response as well.
        let mut top_doc_ids: Vec<(String, f32)> = Vec::new();
        for item in &scored {
            let doc_prefix = if !item.chunk.document_id.is_empty() {
                item.chunk.document_id.clone()
            } else if let Some((prefix, _)) = item.chunk.chunk_id.rsplit_once(':') {
                prefix.to_string()
            } else {
                continue;
            };
            if !top_doc_ids.iter().any(|(d, _)| d == &doc_prefix) {
                top_doc_ids.push((doc_prefix, item.score));
                if top_doc_ids.len() >= 4 {
                    break;
                }
            }
        }

        if !top_doc_ids.is_empty() {
            let mut sibling_ids: Vec<String> = Vec::new();
            let mut doc_base_scores: std::collections::HashMap<String, f32> =
                std::collections::HashMap::new();
            for (doc_id, base_score) in top_doc_ids {
                doc_base_scores.insert(doc_id.clone(), base_score);
                for idx in 0..=4 {
                    let cand_id = format!("{}:{}", doc_id, idx);
                    if !seen_ids.contains(&cand_id) {
                        sibling_ids.push(cand_id);
                    }
                }
            }
            if !sibling_ids.is_empty() {
                let extra_chunks = self
                    .local_storage
                    .get_chunks_by_ids(&sibling_ids, effective_tier)
                    .await;
                for extra in extra_chunks {
                    if seen_ids.insert(extra.chunk_id.clone()) {
                        let base = doc_base_scores
                            .get(&extra.document_id)
                            .copied()
                            .unwrap_or(0.015);
                        scored.push(quorum_types::ScoredChunk::new(
                            extra,
                            (base * 0.92).max(0.012),
                            "local",
                            false,
                        ));
                    }
                }
            }
        }

        scored.retain(|c| !crate::artemis_airgap::is_airgap_restricted_chunk(&c.chunk));

        let candidate_dtos: Vec<CandidateChunkDto> = scored
            .iter()
            .map(CandidateChunkDto::from_scored_chunk)
            .collect();

        // Filter strictly to user's shared_folders and enforce PHI/PII Redact or Block
        let safe_chunks = controller
            .filter_and_enforce_outbound_mesh_chunks(candidate_dtos, &req.sender_peer_id);

        FederatedQueryResponse {
            query_id: req.query_id,
            responder_peer_id: self.local_peer_id.clone(),
            chunks: safe_chunks,
        }
    }
}
