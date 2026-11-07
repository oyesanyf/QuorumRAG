use crate::error::CoordinatorError;
use chrono::Utc;
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

/// Clean interface abstraction separating mesh querying mechanisms.
#[async_trait::async_trait]
pub trait MeshQueryDispatcher: Send + Sync {
    async fn query_peers(
        &self,
        request: &FederatedQueryRequest,
        timeout: Duration,
    ) -> Result<Vec<FederatedQueryResponse>, CoordinatorError>;

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
        let peers = self.peers.read().await.clone();
        if peers.is_empty() {
            return Ok(Vec::new());
        }

        use futures::stream::{FuturesUnordered, StreamExt};

        let mut futures = FuturesUnordered::new();
        for peer in peers {
            let req = request.clone();
            futures.push(tokio::spawn(async move {
                let chunks = peer.handle_query(0).await;
                FederatedQueryResponse {
                    query_id: req.query_id,
                    responder_peer_id: peer.peer_id,
                    chunks,
                }
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
        let _ = tokio::time::timeout(timeout, async {
            while let Some(res) = futures.next().await {
                if let Ok(resp) = res {
                    responses.push(resp);
                    if responses.len() >= max_peer_responses {
                        break;
                    }
                }
            }
        })
        .await;

        Ok(responses)
    }

    fn peer_count(&self) -> usize {
        0
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
}

#[async_trait::async_trait]
impl MeshQueryDispatcher for SwarmMeshDispatcher {
    async fn query_peers(
        &self,
        request: &FederatedQueryRequest,
        timeout: Duration,
    ) -> Result<Vec<FederatedQueryResponse>, CoordinatorError> {
        let mut peers = self
            .handle
            .connected_peers()
            .await
            .map_err(|e| CoordinatorError::Network(e.to_string()))?;

        // If no peers are currently connected (e.g., idle TCP drop or remote node restarted),
        // proactively dial configured bootstrap_peers from OshoosiClaw Mesh settings and wait briefly,
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
                let bootstrap_addrs = {
                    let controller = crate::dlp_mesh::global_mesh_dlp_controller();
                    let s = controller.settings.read().unwrap_or_else(|e| e.into_inner());
                    s.mesh.bootstrap_peers.clone()
                };
                if !bootstrap_addrs.is_empty() {
                    for addr_str in &bootstrap_addrs {
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

        if peers.is_empty() {
            return Ok(Vec::new());
        }

        use futures::stream::{FuturesUnordered, StreamExt};

        let mut pending_peer_ids: HashSet<String> =
            peers.iter().map(|p| p.to_string()).collect();

        let mut futures = FuturesUnordered::new();
        for peer in peers {
            let peer_str = peer.to_string();
            let handle = self.handle.clone();
            let req = request.clone();
            futures.push(tokio::spawn(async move {
                let started = Instant::now();
                let res = handle.send_query(peer, req).await;
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

        let registry = global_peer_health_registry();
        let primary_deadline = tokio::time::Instant::now() + timeout;
        let mut active_deadline = primary_deadline;
        let mut got_non_empty_peer = false;
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
                    tracing::info!(
                        peer = %peer_str,
                        rtt_ms = format!("{:.1}", rtt_ms),
                        chunks = chunks_len,
                        "Received federated P2P mesh response"
                    );
                    if chunks_len > 0 && !got_non_empty_peer {
                        got_non_empty_peer = true;
                        // Two-stage deadline: once at least one peer has delivered real chunks,
                        // give slower straggler peers a bounded 950ms grace window so dead/stalled
                        // sockets never penalize responsive LAN peers.
                        let grace_deadline =
                            tokio::time::Instant::now() + Duration::from_millis(950);
                        if grace_deadline < active_deadline {
                            active_deadline = grace_deadline;
                        }
                    }
                    responses.push(resp);
                    if responses.len() >= max_peer_responses {
                        break;
                    }
                }
                Ok(Some(Ok((peer_str, Err(err), rtt_ms)))) => {
                    pending_peer_ids.remove(&peer_str);
                    registry.record_failure(&peer_str, err.to_string());
                    tracing::warn!(
                        peer = %peer_str,
                        rtt_ms = format!("{:.1}", rtt_ms),
                        error = %err,
                        "Federated P2P mesh query to peer failed"
                    );
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
        if !pending_peer_ids.is_empty() && tokio::time::Instant::now() >= primary_deadline {
            for stalled_peer in &pending_peer_ids {
                registry.record_failure(
                    stalled_peer,
                    format!("Timed out after {}ms", timeout.as_millis()),
                );
                tracing::warn!(
                    peer = %stalled_peer,
                    timeout_ms = timeout.as_millis() as u64,
                    "Federated P2P mesh query timed out waiting for peer"
                );
            }
        }

        Ok(responses)
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
}

impl OsoosiMeshInboundHandler {
    pub fn new(
        local_storage: Arc<dyn crate::scatter_gather::StorageSearcher>,
        local_peer_id: impl Into<String>,
    ) -> Self {
        Self {
            local_storage,
            local_peer_id: local_peer_id.into(),
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
            global_peer_health_registry().record_success(&req.sender_peer_id, 0.5, 0);
            return FederatedQueryResponse {
                query_id: req.query_id,
                responder_peer_id: self.local_peer_id.clone(),
                chunks: Vec::new(),
            };
        }

        let (mut scored, text_scored) = tokio::join!(
            self.local_storage.search_hybrid(
                &req.query_text,
                &req.embedding,
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
