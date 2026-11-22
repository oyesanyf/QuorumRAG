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

    /// Returns `(local_peer_id, secret_seed)` when backed by a real Ed25519 swarm identity.
    fn signing_credentials(&self) -> Option<(String, [u8; 32])> {
        None
    }

    /// Returns clean dialable multiaddrs (`/ip4/.../tcp/.../p2p/<PeerId>`) of connected peers
    /// for transitive full-mesh discovery, excluding port 4001 noise.
    fn connected_peer_multiaddrs(&self) -> Vec<String> {
        Vec::new()
    }
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

static GLOBAL_MESH_DISPATCHER: std::sync::OnceLock<std::sync::RwLock<Option<Arc<dyn MeshQueryDispatcher>>>> =
    std::sync::OnceLock::new();

pub fn get_global_mesh_dispatcher() -> Option<Arc<dyn MeshQueryDispatcher>> {
    GLOBAL_MESH_DISPATCHER
        .get()?
        .read()
        .ok()?
        .clone()
}

pub fn set_global_mesh_dispatcher(dispatcher: Arc<dyn MeshQueryDispatcher>) {
    let cell = GLOBAL_MESH_DISPATCHER.get_or_init(|| std::sync::RwLock::new(None));
    if let Ok(mut lock) = cell.write() {
        *lock = Some(dispatcher);
    }
}

/// In-memory mock dispatcher holding multiple mock peers for deterministic testing.
#[derive(Debug, Default, Clone)]
pub struct MockMeshDispatcher {
    pub peers: Arc<RwLock<Vec<MockRemotePeer>>>,
    pub warm_llm_peers: Arc<RwLock<std::collections::HashSet<String>>>,
    pub synthesis_responses: Arc<RwLock<std::collections::HashMap<String, String>>>,
}

impl MockMeshDispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn add_peer(&self, peer: MockRemotePeer) {
        let mut p = self.peers.write().await;
        p.push(peer);
    }

    pub async fn register_warm_llm(&self, peer_id: impl Into<String>, simulated_synthesis: Option<String>) {
        let pid = peer_id.into();
        self.warm_llm_peers.write().await.insert(pid.clone());
        if let Some(text) = simulated_synthesis {
            self.synthesis_responses.write().await.insert(pid, text);
        }
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

        let warm_llm_peers = self.warm_llm_peers.read().await.clone();
        let synth_map = self.synthesis_responses.read().await.clone();
        let mut responses = Vec::new();
        let primary_deadline = tokio::time::Instant::now() + timeout;
        let mut active_deadline = primary_deadline;
        let mut got_non_empty = false;

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
                    let is_warm = warm_llm_peers.contains(&peer_id);
                    let synthesis_resp = if let Some(ref relay) = request.synthesis_relay {
                        if is_warm {
                            let text = synth_map.get(&peer_id).cloned().unwrap_or_else(|| {
                                format!("Synthesized answer by {}: grounded in evidence.", peer_id)
                            });
                            Some(quorum_types::MeshSynthesisRelayResponse {
                                synthesized_text: text.clone(),
                                citations: vec![quorum_types::Citation {
                                    peer_id: peer_id.clone(),
                                    file_path: relay.evidence_chunks.first().map(|c| c.file_path.clone()).unwrap_or_default(),
                                    line_start: 1,
                                    line_end: 1,
                                    score: 1.0,
                                    snippet: text.chars().take(120).collect(),
                                    node_id: Some(peer_id.clone()),
                                    is_external_node: true,
                                    origin_label: Some("mesh".to_string()),
                                    node_alias: None,
                                    verbatim_quote: None,
                                    byte_range: None,
                                    grounding_rationale: Some("Synthesized evidence delegation".to_string()),
                                }],
                                model_tag: relay.model_tag.clone().unwrap_or_else(|| "qwen2.5:7b".to_string()),
                                responder_peer_id: peer_id.clone(),
                            })
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    responses.push(FederatedQueryResponse {
                        query_id,
                        responder_peer_id: peer_id,
                        chunks,
                        synthesis_response: synthesis_resp,
                        warm_llm_available: is_warm,
                        peer_multiaddrs: Vec::new(),
                    });
                    if responses.len() >= max_peer_responses || pending_ids.is_empty() {
                        break;
                    }
                    let max_straggler_grace = if chunks_count > 0 {
                        got_non_empty = true;
                        Duration::from_millis(120)
                    } else if !got_non_empty {
                        Duration::from_millis(200)
                    } else {
                        Duration::from_millis(120)
                    };
                    let straggler_deadline = tokio::time::Instant::now() + max_straggler_grace;
                    if straggler_deadline < active_deadline {
                        active_deadline = straggler_deadline;
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

/// Normalizes a configured DuckDNS setting (e.g. `"oshoosi"`, `"oshoosi.duckdns.org"`,
/// `"https://oshoosi.duckdns.org/"`) into `<subdomain>.duckdns.org`.
pub fn normalize_duckdns_fqdn(domain: &str) -> Option<String> {
    let stripped = domain
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if stripped.is_empty()
        || stripped.chars().any(|c| c.is_whitespace() || c.is_control() || c == ':')
    {
        return None;
    }
    if stripped.ends_with(".duckdns.org") {
        Some(stripped)
    } else if stripped.contains('.') {
        Some(stripped)
    } else {
        Some(format!("{}.duckdns.org", stripped))
    }
}

/// Extracts the host literal (`/ip4/<ip>`, `/ip6/<ip>`, or `/dns4/<host>`) from a multiaddr string.
pub fn extract_multiaddr_host_str(addr: &str) -> Option<String> {
    let clean = addr.split("/p2p/").next().unwrap_or(addr).trim();
    let mut parts = clean.split('/').filter(|s| !s.is_empty());
    while let Some(proto) = parts.next() {
        if matches!(proto, "ip4" | "ip6" | "dns" | "dns4" | "dns6" | "dnsaddr") {
            return parts.next().map(|h| h.to_string());
        }
    }
    None
}

/// Collects deduplicated trusted dial targets from explicit `bootstrap_peers`,
/// auto-configured DuckDNS (`<domain>.duckdns.org` across `mesh_port` + `3032`/`3031` TCP & QUIC),
/// and persisted `p2p_known_peers.json` multiaddrs, filtering out port 4001 IPFS noise.
pub fn collect_trusted_bootstrap_multiaddrs(
    mesh: &crate::dlp_mesh::OsoosiMeshSettings,
    known_multiaddrs: &[String],
) -> Vec<String> {
    let mut out = Vec::new();
    let mut push_unique = |raw: &str| {
        let trimmed = raw.split("/p2p/").next().unwrap_or(raw).trim();
        if trimmed.is_empty()
            || trimmed.contains("/tcp/4001")
            || trimmed.contains("/udp/4001")
            || trimmed.ends_with("/4001")
        {
            return;
        }
        if !out.iter().any(|existing: &String| existing.eq_ignore_ascii_case(trimmed)) {
            out.push(trimmed.to_string());
        }
    };

    for bp in &mesh.bootstrap_peers {
        push_unique(bp);
    }

    if mesh.auto_bootstrap_duckdns {
        if let Some(ref raw_domain) = mesh.duckdns_domain {
            if let Some(fqdn) = normalize_duckdns_fqdn(raw_domain) {
                let mut ports = Vec::new();
                for p in [mesh.mesh_port, 3032, 3031] {
                    if p > 0 && p != 4001 && !ports.contains(&p) {
                        ports.push(p);
                    }
                }
                for p in ports {
                    push_unique(&format!("/dns4/{}/tcp/{}", fqdn, p));
                    push_unique(&format!("/dns4/{}/udp/{}/quic-v1", fqdn, p));
                }
            }
        }
    }

    for kp in known_multiaddrs {
        push_unique(kp);
    }

    out
}

/// Formats a connected peer's `(peer_id, Multiaddr)` into a clean dialable multiaddr with `/p2p/<PeerId>`,
/// filtering out port 4001 IPFS swarm noise and avoiding duplicate `/p2p/<PeerId>` suffixes.
pub fn format_clean_peer_multiaddr(peer_id: &str, addr: &quorum_network::Multiaddr) -> Option<String> {
    if peer_id.trim().is_empty() {
        return None;
    }
    let raw = addr.to_string();
    if raw.contains("/tcp/4001")
        || raw.contains("/udp/4001")
        || raw.ends_with(":4001")
        || raw.ends_with("/4001")
        || raw.contains("/4001/")
    {
        return None;
    }
    let base = raw.split("/p2p/").next().unwrap_or(&raw).trim_end_matches('/');
    if base.is_empty() || (!base.contains("/tcp/") && !base.contains("/udp/")) {
        return None;
    }
    Some(format!("{}/p2p/{}", base, peer_id.trim()))
}

/// Filters newly learned `peer_multiaddrs` down to valid, unconnected, non-self, non-4001 dial targets.
pub fn filter_newly_learned_dial_targets(
    candidates: &[String],
    local_peer_id: &str,
    connected_addrs: &HashMap<quorum_network::libp2p::PeerId, quorum_network::Multiaddr>,
    self_listen_addrs: &[quorum_network::Multiaddr],
) -> Vec<quorum_network::Multiaddr> {
    use quorum_network::libp2p::multiaddr::Protocol;

    let connected_peer_ids: HashSet<String> =
        connected_addrs.keys().map(|p| p.to_string()).collect();
    let connected_bases: HashSet<String> = connected_addrs
        .values()
        .map(|a| {
            let s = a.to_string();
            s.split("/p2p/")
                .next()
                .unwrap_or(&s)
                .trim_end_matches('/')
                .to_string()
        })
        .collect();
    let self_listen_bases: HashSet<String> = self_listen_addrs
        .iter()
        .map(|a| {
            let s = a.to_string();
            s.split("/p2p/")
                .next()
                .unwrap_or(&s)
                .trim_end_matches('/')
                .to_string()
        })
        .collect();

    let mut self_non_loopback_ips: HashSet<std::net::IpAddr> = HashSet::new();
    let mut self_listen_ports: HashSet<u16> = HashSet::new();
    for la in self_listen_addrs {
        for proto in la.iter() {
            match proto {
                Protocol::Ip4(ip) if !ip.is_loopback() && !ip.is_unspecified() => {
                    self_non_loopback_ips.insert(std::net::IpAddr::V4(ip));
                }
                Protocol::Ip6(ip) if !ip.is_loopback() && !ip.is_unspecified() => {
                    self_non_loopback_ips.insert(std::net::IpAddr::V6(ip));
                }
                Protocol::Tcp(port) | Protocol::Udp(port) if port > 0 => {
                    self_listen_ports.insert(port);
                }
                _ => {}
            }
        }
    }

    let mut seen_bases = HashSet::new();
    let mut targets = Vec::new();
    for raw in candidates {
        let trimmed = raw.trim();
        if trimmed.is_empty()
            || trimmed.contains("/tcp/4001")
            || trimmed.contains("/udp/4001")
            || trimmed.ends_with(":4001")
            || trimmed.ends_with("/4001")
            || trimmed.contains("/4001/")
        {
            continue;
        }
        let Ok(ma) = trimmed.parse::<quorum_network::Multiaddr>() else {
            continue;
        };
        if !quorum_network::is_allowed_trusted_bootstrap_address(&ma) {
            continue;
        }

        let mut embedded_peer_id: Option<String> = None;
        let mut cand_ip: Option<std::net::IpAddr> = None;
        let mut cand_port: Option<u16> = None;
        for proto in ma.iter() {
            match proto {
                Protocol::P2p(pid) => embedded_peer_id = Some(pid.to_string()),
                Protocol::Ip4(ip) => cand_ip = Some(std::net::IpAddr::V4(ip)),
                Protocol::Ip6(ip) => cand_ip = Some(std::net::IpAddr::V6(ip)),
                Protocol::Tcp(port) | Protocol::Udp(port) => cand_port = Some(port),
                _ => {}
            }
        }

        if let Some(ref pid_str) = embedded_peer_id {
            if !local_peer_id.is_empty() && pid_str == local_peer_id {
                continue;
            }
            if connected_peer_ids.contains(pid_str) {
                continue;
            }
        }

        let base_str = trimmed
            .split("/p2p/")
            .next()
            .unwrap_or(trimmed)
            .trim_end_matches('/')
            .to_string();
        if base_str.is_empty()
            || connected_bases.contains(&base_str)
            || self_listen_bases.contains(&base_str)
        {
            continue;
        }

        if let Some(ip) = cand_ip {
            if self_non_loopback_ips.contains(&ip)
                && (embedded_peer_id.is_none()
                    || cand_port.map_or(true, |p| self_listen_ports.contains(&p)))
            {
                continue;
            }
        }

        if seen_bases.insert(base_str) {
            targets.push(ma);
        }
    }
    targets
}

/// Production mesh dispatcher bridging to the `NetworkSwarmHandle`.
#[derive(Clone)]
pub struct SwarmMeshDispatcher {
    pub handle: NetworkSwarmHandle,
    pub local_peer_id: String,
    pub secret_seed: [u8; 32],
    pub last_bootstrap_dial_ms: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl SwarmMeshDispatcher {
    pub fn new(
        handle: NetworkSwarmHandle,
        local_peer_id: impl Into<String>,
        secret_seed: [u8; 32],
    ) -> Self {
        Self {
            handle,
            local_peer_id: local_peer_id.into(),
            secret_seed,
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

        // If no peers are currently connected (e.g., idle TCP drop, roaming on WAN, or remote node restarted),
        // proactively dial configured bootstrap_peers, auto DuckDNS endpoints, and known peers from p2p_known_peers.json,
        // subject to a 10-second cooldown so offline peers do not stall repeated queries.
        // Skip bootstrap dialing on relayed 1-hop queries (`relay_hops > 0`) so relays never stall.
        if peers.is_empty() && request.relay_hops == 0 {
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
                let mesh_cfg = {
                    let controller = crate::dlp_mesh::global_mesh_dlp_controller();
                    let s = controller.settings.read().unwrap_or_else(|e| e.into_inner());
                    s.mesh.clone()
                };

                // Discover and dial known peers from p2p_known_peers.json on mesh_port (default 3032)
                let mut known_addrs: Vec<String> = Vec::new();
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
                                        known_addrs.push(s.to_string());
                                    }
                                }
                            }
                        }
                    }
                }

                let has_explicit_or_known = !mesh_cfg.bootstrap_peers.is_empty() || !known_addrs.is_empty();
                let mut dial_targets = collect_trusted_bootstrap_multiaddrs(&mesh_cfg, &known_addrs);

                // Resolve auto DuckDNS FQDN with a tight 300ms timeout so travel/WAN nodes also get direct
                // IPv4/IPv6 addresses without blocking offline tests.
                let mut duckdns_resolved = false;
                if mesh_cfg.auto_bootstrap_duckdns {
                    if let Some(fqdn) = mesh_cfg.duckdns_domain.as_deref().and_then(normalize_duckdns_fqdn) {
                        if let Ok(Ok(resolved)) = tokio::time::timeout(
                            Duration::from_millis(300),
                            tokio::net::lookup_host((fqdn.as_str(), mesh_cfg.mesh_port)),
                        )
                        .await
                        {
                            for sock in resolved {
                                duckdns_resolved = true;
                                let ip = sock.ip();
                                for p in [mesh_cfg.mesh_port, 3032, 3031] {
                                    if p > 0 && p != 4001 {
                                        let (tcp_ma, quic_ma) = match ip {
                                            std::net::IpAddr::V4(v4) => (
                                                format!("/ip4/{}/tcp/{}", v4, p),
                                                format!("/ip4/{}/udp/{}/quic-v1", v4, p),
                                            ),
                                            std::net::IpAddr::V6(v6) => (
                                                format!("/ip6/{}/tcp/{}", v6, p),
                                                format!("/ip6/{}/udp/{}/quic-v1", v6, p),
                                            ),
                                        };
                                        if !dial_targets.contains(&tcp_ma) {
                                            dial_targets.push(tcp_ma);
                                        }
                                        if !dial_targets.contains(&quic_ma) {
                                            dial_targets.push(quic_ma);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if !dial_targets.is_empty() {
                    let mut dial_futs = futures::stream::FuturesUnordered::new();
                    for addr_str in &dial_targets {
                        if let Ok(addr) = addr_str.trim().parse::<quorum_network::Multiaddr>() {
                            let h = self.handle.clone();
                            dial_futs.push(async move { h.dial_trusted(addr).await });
                        }
                    }
                    use futures::StreamExt;
                    let mut any_dial_started = false;
                    while let Some(res) = dial_futs.next().await {
                        if res.is_ok() {
                            any_dial_started = true;
                        }
                    }
                    if any_dial_started {
                        // Allow up to 1.8s when dialing real WAN/DuckDNS/explicit peers; keep offline probes fast (350ms).
                        let max_iters = if has_explicit_or_known || duckdns_resolved { 36 } else { 7 };
                        for _ in 0..max_iters {
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
        }

        // Filter out already-visited / sender / origin peers (preventing 1-hop relay echo loops & early straggler cutoff)
        // and filter out non-QuorumRAG IPFS peers on port 4001 before dispatching candidate queries
        let connected_addrs = self.handle.connected_peer_addresses();
        peers.retain(|peer| {
            let pid = peer.to_string();
            if pid == request.sender_peer_id
                || request.origin_peer_id.as_deref() == Some(pid.as_str())
                || request.visited_peers.iter().any(|v| v == &pid)
            {
                return false;
            }
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
        let mut responses = Vec::new();
        let mut seen_learned_addrs: HashSet<String> = HashSet::new();

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
                    if !resp.peer_multiaddrs.is_empty() {
                        let new_candidates: Vec<String> = resp
                            .peer_multiaddrs
                            .iter()
                            .filter(|ma| seen_learned_addrs.insert((*ma).clone()))
                            .cloned()
                            .collect();
                        if !new_candidates.is_empty() {
                            let handle_clone = self.handle.clone();
                            let self_pid = if self.local_peer_id.is_empty() {
                                self.handle.local_peer_id().to_string()
                            } else {
                                self.local_peer_id.clone()
                            };
                            tokio::spawn(async move {
                                let connected_now = handle_clone.connected_peer_addresses();
                                let self_listen =
                                    handle_clone.listen_addresses().await.unwrap_or_default();
                                let targets = filter_newly_learned_dial_targets(
                                    &new_candidates,
                                    &self_pid,
                                    &connected_now,
                                    &self_listen,
                                );
                                for ma in targets {
                                    tracing::info!(
                                        addr = %ma,
                                        "Transitive mesh discovery auto-dialing newly learned peer"
                                    );
                                    if let Err(err) = handle_clone.dial_trusted(ma.clone()).await {
                                        tracing::debug!(
                                            addr = %ma,
                                            error = %err,
                                            "Transitive mesh auto-dial attempt failed"
                                        );
                                    }
                                }
                            });
                        }
                    }
                    responses.push(resp);

                    // EARLY RESOLUTION LAW:
                    // 1. If all queried peers have responded or max responses reached, break immediately.
                    if responses.len() >= total_queried || responses.len() >= max_peer_responses || pending_peer_ids.is_empty() {
                        break;
                    }

                    // 2. Once responses have arrived, activate health-aware straggler grace:
                    // When healthy connected libp2p peers (`consecutive_failures == 0`, including million-chunk hosts)
                    // are still in flight, allow up to 4500ms (bounded by `active_deadline`).
                    // Clamp to 400ms ONLY when all remaining pending peers have `consecutive_failures > 0`.
                    let has_healthy_pending = pending_peer_ids.iter().any(|pid| {
                        registry
                            .get(pid)
                            .map_or(true, |s| s.consecutive_failures == 0)
                    });
                    let max_straggler_grace = if has_healthy_pending {
                        Duration::from_millis(4500)
                    } else {
                        Duration::from_millis(400)
                    };
                    let straggler_deadline = tokio::time::Instant::now() + max_straggler_grace;
                    if straggler_deadline < active_deadline {
                        active_deadline = straggler_deadline;
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
                    if !responses.is_empty() {
                        let has_healthy_pending = pending_peer_ids.iter().any(|pid| {
                            registry
                                .get(pid)
                                .map_or(true, |s| s.consecutive_failures == 0)
                        });
                        let max_straggler_grace = if has_healthy_pending {
                            Duration::from_millis(4500)
                        } else {
                            Duration::from_millis(400)
                        };
                        let straggler_deadline = tokio::time::Instant::now() + max_straggler_grace;
                        if straggler_deadline < active_deadline {
                            active_deadline = straggler_deadline;
                        }
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

    fn signing_credentials(&self) -> Option<(String, [u8; 32])> {
        if self.local_peer_id.is_empty() {
            None
        } else {
            Some((self.local_peer_id.clone(), self.secret_seed))
        }
    }

    fn connected_peer_multiaddrs(&self) -> Vec<String> {
        let self_pid = if self.local_peer_id.is_empty() {
            self.handle.local_peer_id().to_string()
        } else {
            self.local_peer_id.clone()
        };
        let mut out: Vec<String> = self
            .handle
            .connected_peer_addresses()
            .into_iter()
            .filter_map(|(peer_id, addr)| {
                let pid_str = peer_id.to_string();
                if pid_str == self_pid {
                    return None;
                }
                format_clean_peer_multiaddr(&pid_str, &addr)
            })
            .collect();
        out.sort();
        out.dedup();
        out
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
fn seen_query_cache() -> &'static std::sync::RwLock<HashMap<(String, uuid::Uuid), Instant>> {
    static CACHE: OnceLock<std::sync::RwLock<HashMap<(String, uuid::Uuid), Instant>>> =
        OnceLock::new();
    CACHE.get_or_init(|| std::sync::RwLock::new(HashMap::new()))
}

pub struct OsoosiMeshInboundHandler {
    pub local_storage: Arc<dyn crate::scatter_gather::StorageSearcher>,
    pub local_peer_id: String,
    pub embedder: Option<Arc<dyn quorum_contract::EmbeddingGenerator>>,
    pub dispatcher: Arc<std::sync::RwLock<Option<Arc<dyn MeshQueryDispatcher>>>>,
    pub ollama_override: Option<(
        std::net::SocketAddr,
        String,
        crate::hardware::HardwareTelemetry,
        Vec<String>,
    )>,
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
            dispatcher: Arc::new(std::sync::RwLock::new(None)),
            ollama_override: None,
        }
    }

    pub fn with_embedder(
        mut self,
        embedder: Arc<dyn quorum_contract::EmbeddingGenerator>,
    ) -> Self {
        self.embedder = Some(embedder);
        self
    }

    pub fn with_ollama_override(
        mut self,
        addr: std::net::SocketAddr,
        host_port: impl Into<String>,
        hw: crate::hardware::HardwareTelemetry,
        installed_models: Vec<String>,
    ) -> Self {
        self.ollama_override = Some((addr, host_port.into(), hw, installed_models));
        self
    }

    pub fn with_dispatcher(
        self,
        dispatcher: Arc<dyn MeshQueryDispatcher>,
    ) -> Self {
        *self.dispatcher.write().unwrap_or_else(|e| e.into_inner()) = Some(dispatcher);
        self
    }

    pub fn set_dispatcher(&self, dispatcher: Arc<dyn MeshQueryDispatcher>) {
        *self.dispatcher.write().unwrap_or_else(|e| e.into_inner()) = Some(dispatcher);
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
            dispatcher: Arc::new(std::sync::RwLock::new(None)),
            ollama_override: None,
        }
    }

    fn advertised_peer_multiaddrs_for(&self, requester_peer_id: &str) -> Vec<String> {
        let disp_opt = self
            .dispatcher
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let Some(disp) = disp_opt else {
            return Vec::new();
        };
        disp.connected_peer_multiaddrs()
            .into_iter()
            .filter(|ma| {
                let p2p_id = ma.rsplit("/p2p/").next().unwrap_or("");
                let is_requester = !requester_peer_id.is_empty() && p2p_id == requester_peer_id;
                let is_self = !self.local_peer_id.is_empty() && p2p_id == self.local_peer_id;
                !is_requester && !is_self
            })
            .collect()
    }
}

/// Converts delegated `CandidateChunkDto`s into `ScoredChunk`s for `synthesis_relay`,
/// preferring non-empty `expanded_window` over `content` and preserving each chunk's original
/// `origin_peer_id` / `source_peer` with accurate `is_remote` relative to `local_peer_id` / `"local"`.
pub fn build_relay_scored_chunks(
    evidence_chunks: &[CandidateChunkDto],
    local_peer_id: &str,
) -> Vec<quorum_types::ScoredChunk> {
    evidence_chunks
        .iter()
        .map(|dto| {
            let text_content = dto
                .expanded_window
                .as_ref()
                .filter(|w| !w.trim().is_empty())
                .cloned()
                .unwrap_or_else(|| dto.content.clone());
            let doc_chunk = quorum_types::DocumentChunk {
                chunk_id: dto.chunk_id.clone(),
                document_id: dto
                    .chunk_id
                    .rsplit_once(':')
                    .map(|(d, _)| d.to_string())
                    .unwrap_or_else(|| dto.file_path.clone()),
                file_path: dto.file_path.clone(),
                line_start: dto.line_start,
                line_end: dto.line_end,
                blake3_hash: quorum_types::DocumentChunk::compute_blake3_hash(&text_content),
                access_tier: dto.access_tier,
                vector: vec![0.0; 768],
                text_content,
                metadata_json: "{}".to_string(),
            };
            let origin = dto
                .origin_peer_id
                .as_deref()
                .map(str::trim)
                .filter(|p| !p.is_empty());
            let is_remote = origin.map_or(false, |p| {
                p != local_peer_id && !p.eq_ignore_ascii_case("local")
            });
            let source_peer = origin
                .map(|p| p.to_string())
                .unwrap_or_else(|| local_peer_id.to_string());
            let score = if dto.score > 0.0 { dto.score } else { 1.0 };
            quorum_types::ScoredChunk::new(doc_chunk, score, source_peer, is_remote)
        })
        .collect()
}

#[async_trait::async_trait]
impl quorum_network::InboundQueryHandler for OsoosiMeshInboundHandler {
    async fn handle_query(&self, req: FederatedQueryRequest) -> FederatedQueryResponse {
        // 0. Deduplicate duplicate (local_peer_id, query_id) within 60s TTL window to prevent replay or relay loops
        {
            let now = Instant::now();
            let cache_key = (self.local_peer_id.clone(), req.query_id);
            let mut cache = seen_query_cache().write().unwrap_or_else(|e| e.into_inner());
            cache.retain(|_, seen_time| now.duration_since(*seen_time) < Duration::from_secs(60));
            if cache.contains_key(&cache_key) {
                tracing::debug!(
                    "Dropping duplicate mesh query_id {} already processed on {} within 60s TTL",
                    req.query_id,
                    self.local_peer_id
                );
                return FederatedQueryResponse {
                    query_id: req.query_id,
                    responder_peer_id: self.local_peer_id.clone(),
                    chunks: Vec::new(),
                    synthesis_response: None,
                    warm_llm_available: false,
                    peer_multiaddrs: Vec::new(),
                };
            }
            cache.insert(cache_key, now);
        }

        // 0b. Loop prevention: do not process query if this node was already visited
        if req.visited_peers.iter().any(|p| p == &self.local_peer_id) {
            tracing::warn!(
                "Dropping mesh query with loop: local peer {} already visited",
                self.local_peer_id
            );
            return FederatedQueryResponse {
                query_id: req.query_id,
                responder_peer_id: self.local_peer_id.clone(),
                chunks: Vec::new(),
                synthesis_response: None,
                warm_llm_available: false,
                peer_multiaddrs: Vec::new(),
            };
        }

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
                synthesis_response: None,
                warm_llm_available: false,
                peer_multiaddrs: Vec::new(),
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
                synthesis_response: None,
                warm_llm_available: false,
                peer_multiaddrs: Vec::new(),
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
                        synthesis_response: None,
                        warm_llm_available: false,
                        peer_multiaddrs: Vec::new(),
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
                    synthesis_response: None,
                    warm_llm_available: false,
                    peer_multiaddrs: Vec::new(),
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
                synthesis_response: None,
                warm_llm_available: false,
                peer_multiaddrs: Vec::new(),
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
                    synthesis_response: None,
                    warm_llm_available: false,
                    peer_multiaddrs: Vec::new(),
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
                synthesis_response: None,
                warm_llm_available: false,
                peer_multiaddrs: self.advertised_peer_multiaddrs_for(&req.sender_peer_id),
            };
        }

        // If this query carries a synthesis relay payload, handle synthesis delegation:
        if let Some(ref relay) = req.synthesis_relay {
            // Airgap check on evidence chunks
            if relay.evidence_chunks.iter().any(|c| crate::artemis_airgap::is_airgap_restricted_chunk_dto(c)) {
                tracing::warn!("Rejecting synthesis relay with airgapped artemis evidence chunks from peer: {}", req.sender_peer_id);
                return FederatedQueryResponse {
                    query_id: req.query_id,
                    responder_peer_id: self.local_peer_id.clone(),
                    chunks: Vec::new(),
                    synthesis_response: None,
                    warm_llm_available: false,
                    peer_multiaddrs: Vec::new(),
                };
            }

            let scored_chunks = build_relay_scored_chunks(&relay.evidence_chunks, &self.local_peer_id);
            let scored_refs: Vec<&quorum_types::ScoredChunk> = scored_chunks.iter().collect();

            let model = relay.model_tag.as_deref().unwrap_or("qwen2.5:7b");
            let synthesis_opt = if let Some((addr, ref host_port, ref hw, ref installed_models)) =
                self.ollama_override
            {
                let ui = crate::dlp_mesh::ChatGptUiSettings::default();
                crate::offline_engine::DeterministicOfflineSynthesisEngine::query_local_ollama_chat_at(
                    addr,
                    host_port,
                    &relay.prompt,
                    &relay.history,
                    &scored_refs,
                    model,
                    hw,
                    &ui,
                    installed_models,
                    None,
                )
            } else {
                crate::offline_engine::DeterministicOfflineSynthesisEngine::query_local_ollama_chat(
                    &relay.prompt,
                    &relay.history,
                    &scored_refs,
                    model,
                    None,
                )
            };

            if let Some((synthesized_text, citations)) = synthesis_opt {
                return FederatedQueryResponse {
                    query_id: req.query_id,
                    responder_peer_id: self.local_peer_id.clone(),
                    chunks: Vec::new(),
                    synthesis_response: Some(quorum_types::MeshSynthesisRelayResponse {
                        synthesized_text,
                        citations,
                        model_tag: model.to_string(),
                        responder_peer_id: self.local_peer_id.clone(),
                    }),
                    warm_llm_available: true,
                    peer_multiaddrs: self.advertised_peer_multiaddrs_for(&req.sender_peer_id),
                };
            }
        }

        // Spawn loop-free federated relay CONCURRENTLY with local hybrid search + RLM parent expansion
        // so cross-WAN gateway -> home LAN peer fan-out adds zero sequential stall!
        let relay_handle = if req.relay_hops < 3 {
            let disp_opt = self.dispatcher.read().unwrap_or_else(|e| e.into_inner()).clone();
            disp_opt.map(|disp| {
                let mut relayed_req = req.clone();
                let original_origin = req
                    .origin_peer_id
                    .clone()
                    .unwrap_or_else(|| req.sender_peer_id.clone());
                relayed_req.origin_peer_id = Some(original_origin);
                relayed_req.relay_hops = req.relay_hops + 1;
                if !relayed_req.visited_peers.contains(&self.local_peer_id) {
                    relayed_req.visited_peers.push(self.local_peer_id.clone());
                }
                if !relayed_req.visited_peers.contains(&req.sender_peer_id) {
                    relayed_req.visited_peers.push(req.sender_peer_id.clone());
                }
                tokio::spawn(async move {
                    disp.query_peers(&relayed_req, Duration::from_millis(5500))
                        .await
                        .ok()
                })
            })
        } else {
            None
        };

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

        let stripped_entity_q =
            quorum_storage::query_framing::strip_conversational_framing(&req.query_text);
        let stripped_fut = async {
            if !stripped_entity_q.trim().is_empty()
                && !stripped_entity_q.eq_ignore_ascii_case(&req.query_text)
            {
                self.local_storage
                    .search_text(&stripped_entity_q, effective_tier, 96)
                    .await
            } else {
                Vec::new()
            }
        };

        let (mut scored, text_scored, stripped_scored) = tokio::join!(
            self.local_storage.search_hybrid(
                &req.query_text,
                &query_embedding,
                effective_tier,
                req.top_k.clamp(16, 128),
            ),
            self.local_storage
                .search_text(&req.query_text, effective_tier, 96),
            stripped_fut,
        );

        let mut seen_ids: std::collections::HashSet<String> =
            scored.iter().map(|c| c.chunk.chunk_id.clone()).collect();
        for hit in stripped_scored.into_iter().chain(text_scored.into_iter()) {
            if seen_ids.insert(hit.chunk.chunk_id.clone()) {
                scored.push(hit);
            }
        }

        // Prioritize chunks matching ALL non-stopword content terms so multi-word entity queries
        // ("WHO IS ANGELA DAVIS") rank complete entity matches ahead of single-word distractors.
        let content_words: Vec<String> = stripped_entity_q
            .to_ascii_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| w.len() >= 3 && !crate::agentic::retrieve::STOPWORDS.contains(w))
            .fold(Vec::new(), |mut acc, w| {
                let s = w.to_string();
                if !acc.contains(&s) {
                    acc.push(s);
                }
                acc
            });
        if content_words.len() >= 2 && scored.len() > 1 {
            scored.sort_by(|a, b| {
                let count_body_and_raw_hits = |sc: &quorum_types::ScoredChunk| -> (usize, usize) {
                    let cleaned_tl = crate::offline_engine::DeterministicOfflineSynthesisEngine::clean_chunk_text(
                        &sc.chunk.text_content,
                    )
                    .to_ascii_lowercase();
                    let raw_tl = sc.chunk.text_content.to_ascii_lowercase();
                    let fl = sc.chunk.file_path.to_ascii_lowercase();
                    let body_tokens: std::collections::HashSet<&str> = cleaned_tl
                        .split(|c: char| !c.is_alphanumeric())
                        .chain(fl.split(|c: char| !c.is_alphanumeric()))
                        .filter(|w| !w.is_empty())
                        .collect();
                    let raw_tokens: std::collections::HashSet<&str> = raw_tl
                        .split(|c: char| !c.is_alphanumeric())
                        .chain(fl.split(|c: char| !c.is_alphanumeric()))
                        .filter(|w| !w.is_empty())
                        .collect();
                    let body_hits = content_words
                        .iter()
                        .filter(|w| body_tokens.contains(w.as_str()))
                        .count();
                    let raw_hits = content_words
                        .iter()
                        .filter(|w| raw_tokens.contains(w.as_str()))
                        .count();
                    (body_hits, raw_hits)
                };
                count_body_and_raw_hits(b)
                    .cmp(&count_body_and_raw_hits(a))
                    .then_with(|| {
                        b.score
                            .partial_cmp(&a.score)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .then_with(|| a.chunk.chunk_id.cmp(&b.chunk.chunk_id))
                    .then_with(|| a.chunk.blake3_hash.cmp(&b.chunk.blake3_hash))
            });
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
                            (base * 0.94).max(0.012),
                            "local",
                            false,
                        ));
                    }
                }
            }
        }

        scored.retain(|c| !crate::artemis_airgap::is_airgap_restricted_chunk(&c.chunk));

        // Cap per-document-family candidates (max 3 per family) and bound total candidates to 128 before parent-window expansion,
        // and expand 10KB parent windows on the top 32 unique-family candidates.
        let mut scored =
            crate::agentic::retrieve::RetrieveMeshNode::cap_document_families_federated(scored, 3);
        scored.truncate(128);

        // RLM parent-document expansion up to 10,000 bytes BEFORE outbound DLP inspection
        let mut expanded_families: HashSet<String> = HashSet::with_capacity(32);
        let mut candidate_dtos = Vec::with_capacity(scored.len());
        for c in scored.into_iter() {
            let mut dto = CandidateChunkDto::from_scored_chunk(&c);
            dto.origin_peer_id = Some(self.local_peer_id.clone());
            let fam_key = if c.chunk.file_path.to_ascii_lowercase().starts_with("artemis://") {
                c.chunk.file_path.to_ascii_lowercase()
            } else {
                let dk = crate::offline_engine::DeterministicOfflineSynthesisEngine::derive_document_family_key(
                    &c.chunk.file_path,
                );
                if dk.is_empty() {
                    crate::offline_engine::DeterministicOfflineSynthesisEngine::normalize_file_stem(
                        &c.chunk.file_path,
                    )
                } else {
                    dk
                }
            };
            let should_expand = if expanded_families.contains(&fam_key) {
                false
            } else if expanded_families.len() < 32 {
                expanded_families.insert(fam_key);
                true
            } else {
                false
            };
            if should_expand {
                if let Some((_start, _end, expanded_text, _, _)) =
                    self.local_storage.expand_parent_window(
                        &c.chunk.document_id,
                        &c.chunk.text_content,
                        10000,
                        effective_tier,
                    )
                {
                    if !expanded_text.trim().is_empty() {
                        dto.expanded_window = Some(expanded_text);
                    }
                } else if let Some((_start, _end, expanded_text, _, _)) =
                    self.local_storage.expand_parent_window(
                        &c.chunk.file_path,
                        &c.chunk.text_content,
                        10000,
                        effective_tier,
                    )
                {
                    if !expanded_text.trim().is_empty() {
                        dto.expanded_window = Some(expanded_text);
                    }
                }
            }
            candidate_dtos.push(dto);
        }

        // Filter strictly to user's shared_folders and enforce PHI/PII Redact or Block
        let mut safe_chunks = controller
            .filter_and_enforce_outbound_mesh_chunks(candidate_dtos, &req.sender_peer_id);

        // Join concurrent 1-hop federated relay responses and preserve authentic origin_peer_id
        if let Some(jh) = relay_handle {
            if let Ok(Some(relayed_resps)) = jh.await {
                for resp in relayed_resps {
                    for mut chunk in resp.chunks {
                        if chunk
                            .origin_peer_id
                            .as_deref()
                            .map_or(true, |p| p.is_empty() || p.eq_ignore_ascii_case("local"))
                        {
                            chunk.origin_peer_id = Some(resp.responder_peer_id.clone());
                        }
                        safe_chunks.push(chunk);
                    }
                }
            }
        }

        let warm_llm = !crate::offline_engine::DeterministicOfflineSynthesisEngine::probe_installed_ollama_models_default().is_empty();
        FederatedQueryResponse {
            query_id: req.query_id,
            responder_peer_id: self.local_peer_id.clone(),
            chunks: safe_chunks,
            synthesis_response: None,
            warm_llm_available: warm_llm,
            peer_multiaddrs: self.advertised_peer_multiaddrs_for(&req.sender_peer_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quorum_network::libp2p::{Multiaddr, PeerId};

    #[test]
    fn test_format_clean_peer_multiaddr_filters_4001_and_deduplicates_p2p() {
        let pid = PeerId::random().to_string();
        let addr_4001: Multiaddr = "/ip4/10.0.0.165/tcp/4001".parse().unwrap();
        assert!(format_clean_peer_multiaddr(&pid, &addr_4001).is_none());

        let addr_udp_4001: Multiaddr = "/ip4/10.0.0.165/udp/4001/quic-v1".parse().unwrap();
        assert!(format_clean_peer_multiaddr(&pid, &addr_udp_4001).is_none());

        let addr_with_p2p: Multiaddr = format!("/ip4/10.0.0.165/tcp/3032/p2p/{}", pid)
            .parse()
            .unwrap();
        let formatted = format_clean_peer_multiaddr(&pid, &addr_with_p2p).unwrap();
        assert_eq!(formatted, format!("/ip4/10.0.0.165/tcp/3032/p2p/{}", pid));
        assert_eq!(formatted.matches("/p2p/").count(), 1);
    }

    #[test]
    fn test_filter_newly_learned_dial_targets_blocks_self_4001_and_connected() {
        let local_pid = PeerId::random();
        let connected_pid = PeerId::random();
        let new_pid = PeerId::random();

        let mut connected_addrs = HashMap::new();
        connected_addrs.insert(
            connected_pid,
            "/ip4/127.0.0.1/tcp/41001".parse::<Multiaddr>().unwrap(),
        );
        let self_listen = vec![
            "/ip4/127.0.0.1/tcp/41000".parse::<Multiaddr>().unwrap(),
            "/ip4/10.0.0.10/tcp/3032".parse::<Multiaddr>().unwrap(),
        ];

        let candidates = vec![
            format!("/ip4/127.0.0.1/tcp/41000/p2p/{}", local_pid),
            format!("/ip4/10.0.0.10/tcp/3032/p2p/{}", new_pid),
            format!("/ip4/127.0.0.1/tcp/41001/p2p/{}", connected_pid),
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", new_pid),
            format!("/ip4/127.0.0.1/tcp/41002/p2p/{}", new_pid),
            format!("/ip4/127.0.0.1/tcp/41002/p2p/{}", new_pid),
        ];

        let filtered = filter_newly_learned_dial_targets(
            &candidates,
            &local_pid.to_string(),
            &connected_addrs,
            &self_listen,
        );
        assert_eq!(filtered.len(), 1);
        assert_eq!(
            filtered[0].to_string(),
            format!("/ip4/127.0.0.1/tcp/41002/p2p/{}", new_pid)
        );
    }

    #[test]
    fn test_build_relay_scored_chunks_preserves_provenance_and_prefers_expanded_window() {
        let local_pid = "12D3KooWLocalHostPeer";
        let remote_pid = "12D3KooWRemoteHostPeer";
        let dtos = vec![
            CandidateChunkDto {
                chunk_id: "doc_r:0".to_string(),
                file_path: "D:/Remote/Lease.docx".to_string(),
                line_start: 1,
                line_end: 10,
                content: "Short snippet".to_string(),
                score: 0.92,
                access_tier: 0,
                origin_peer_id: Some(remote_pid.to_string()),
                expanded_window: Some("Expanded 10KB lease agreement text".to_string()),
            },
            CandidateChunkDto {
                chunk_id: "doc_l:0".to_string(),
                file_path: "C:/Local/Notes.docx".to_string(),
                line_start: 1,
                line_end: 5,
                content: "Local notes content".to_string(),
                score: 0.88,
                access_tier: 0,
                origin_peer_id: Some(local_pid.to_string()),
                expanded_window: Some("   ".to_string()),
            },
            CandidateChunkDto {
                chunk_id: "doc_loc_kw:0".to_string(),
                file_path: "C:/Local/LocalKw.docx".to_string(),
                line_start: 1,
                line_end: 5,
                content: "Local keyword content".to_string(),
                score: 0.75,
                access_tier: 0,
                origin_peer_id: Some("local".to_string()),
                expanded_window: None,
            },
        ];

        let scored = build_relay_scored_chunks(&dtos, local_pid);
        assert_eq!(scored.len(), 3);
        assert!(scored[0].is_remote);
        assert_eq!(scored[0].source_peer, remote_pid);
        assert_eq!(scored[0].chunk.text_content, "Expanded 10KB lease agreement text");

        assert!(!scored[1].is_remote);
        assert_eq!(scored[1].source_peer, local_pid);
        assert_eq!(scored[1].chunk.text_content, "Local notes content");

        assert!(!scored[2].is_remote);
        assert_eq!(scored[2].source_peer, "local");
    }
}
