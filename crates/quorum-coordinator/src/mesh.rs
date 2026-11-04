use crate::error::CoordinatorError;
use quorum_network::NetworkSwarmHandle;
use quorum_types::{CandidateChunkDto, FederatedQueryRequest, FederatedQueryResponse};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

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
        // Approximate count from blocking read or 0
        0
    }
}

/// Production mesh dispatcher bridging to the `NetworkSwarmHandle`.
#[derive(Clone)]
pub struct SwarmMeshDispatcher {
    pub handle: NetworkSwarmHandle,
}

impl SwarmMeshDispatcher {
    pub fn new(handle: NetworkSwarmHandle) -> Self {
        Self { handle }
    }
}

#[async_trait::async_trait]
impl MeshQueryDispatcher for SwarmMeshDispatcher {
    async fn query_peers(
        &self,
        request: &FederatedQueryRequest,
        timeout: Duration,
    ) -> Result<Vec<FederatedQueryResponse>, CoordinatorError> {
        let peers = self
            .handle
            .connected_peers()
            .await
            .map_err(|e| CoordinatorError::Network(e.to_string()))?;

        if peers.is_empty() {
            return Ok(Vec::new());
        }

        use futures::stream::{FuturesUnordered, StreamExt};

        let mut futures = FuturesUnordered::new();
        for peer in peers {
            let handle = self.handle.clone();
            let req = request.clone();
            futures.push(tokio::spawn(async move {
                handle.send_query(peer, req).await
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
                if let Ok(Ok(resp)) = res {
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
        1
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
        // 1. Reject malformed payloads: embedding dimension 768, finite floats, text length <= 4096, top_k > 0
        if req.embedding.len() != 768
            || !req.embedding.iter().all(|f| f.is_finite())
            || req.query_text.len() > 4096
            || req.top_k == 0
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
        for t in 0..=max_tier.min(3) {
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

        let scored = self
            .local_storage
            .search_hybrid(&req.query_text, &req.embedding, effective_tier, req.top_k.min(16))
            .await;

        let candidate_dtos: Vec<CandidateChunkDto> = scored
            .iter()
            .map(CandidateChunkDto::from_scored_chunk)
            .collect();

        // Filter strictly to user's shared_folders and enforce PHI/PII Redact or Block
        let safe_chunks =
            controller.filter_and_enforce_outbound_mesh_chunks(candidate_dtos, &req.sender_peer_id);

        FederatedQueryResponse {
            query_id: req.query_id,
            responder_peer_id: self.local_peer_id.clone(),
            chunks: safe_chunks,
        }
    }
}
