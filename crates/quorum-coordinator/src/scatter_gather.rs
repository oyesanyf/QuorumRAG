use crate::acl::PeerAclManager;
use crate::config::CoordinatorConfig;
use crate::crypto::sign_request;
use crate::fusion::RrfCombiner;
use crate::mesh::{MeshQueryDispatcher, MockRemotePeer};
use chrono::Utc;
use quorum_types::{
    AccessTier, CandidateChunkDto, FederatedQueryRequest, ScoredChunk, VolatileRemoteChunk,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Abstraction for local storage engines providing hybrid search.
#[async_trait::async_trait]
pub trait StorageSearcher: Send + Sync {
    async fn search_hybrid(
        &self,
        query_text: &str,
        query_vec: &[f32],
        max_tier: u8,
        top_k: usize,
    ) -> Vec<ScoredChunk>;

    async fn search_hybrid_with_exclusion(
        &self,
        query_text: &str,
        query_vec: &[f32],
        max_tier: u8,
        top_k: usize,
        _exclude_chunk_ids: &[String],
    ) -> Vec<ScoredChunk> {
        self.search_hybrid(query_text, query_vec, max_tier, top_k).await
    }

    async fn search_vector(
        &self,
        _vector: &[f32],
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        Vec::new()
    }

    async fn search_text(
        &self,
        _query: &str,
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        Vec::new()
    }

    fn index_epoch(&self) -> u64 {
        1
    }
}

#[async_trait::async_trait]
impl StorageSearcher for quorum_storage::StorageEngine {
    async fn search_hybrid(
        &self,
        query_text: &str,
        query_vec: &[f32],
        max_tier: u8,
        top_k: usize,
    ) -> Vec<ScoredChunk> {
        self.search_hybrid(query_text, query_vec, max_tier, top_k)
            .await
            .unwrap_or_default()
    }

    async fn search_hybrid_with_exclusion(
        &self,
        query_text: &str,
        query_vec: &[f32],
        max_tier: u8,
        top_k: usize,
        exclude_chunk_ids: &[String],
    ) -> Vec<ScoredChunk> {
        self.search_hybrid_with_exclusion(query_text, query_vec, max_tier, top_k, exclude_chunk_ids)
            .await
            .unwrap_or_default()
    }

    async fn search_vector(
        &self,
        vector: &[f32],
        max_tier: u8,
        top_k: usize,
    ) -> Vec<ScoredChunk> {
        self.search_vector(vector, max_tier, top_k)
            .await
            .unwrap_or_default()
    }

    async fn search_text(
        &self,
        query: &str,
        max_tier: u8,
        top_k: usize,
    ) -> Vec<ScoredChunk> {
        self.search_text(query, max_tier, top_k)
            .await
            .unwrap_or_default()
    }

    fn index_epoch(&self) -> u64 {
        self.index_epoch()
    }
}

#[async_trait::async_trait]
impl<T: StorageSearcher + ?Sized> StorageSearcher for Arc<T> {
    async fn search_hybrid(
        &self,
        query_text: &str,
        query_vec: &[f32],
        max_tier: u8,
        top_k: usize,
    ) -> Vec<ScoredChunk> {
        (**self)
            .search_hybrid(query_text, query_vec, max_tier, top_k)
            .await
    }

    async fn search_hybrid_with_exclusion(
        &self,
        query_text: &str,
        query_vec: &[f32],
        max_tier: u8,
        top_k: usize,
        exclude_chunk_ids: &[String],
    ) -> Vec<ScoredChunk> {
        (**self)
            .search_hybrid_with_exclusion(query_text, query_vec, max_tier, top_k, exclude_chunk_ids)
            .await
    }

    async fn search_vector(
        &self,
        vector: &[f32],
        max_tier: u8,
        top_k: usize,
    ) -> Vec<ScoredChunk> {
        (**self).search_vector(vector, max_tier, top_k).await
    }

    async fn search_text(
        &self,
        query: &str,
        max_tier: u8,
        top_k: usize,
    ) -> Vec<ScoredChunk> {
        (**self).search_text(query, max_tier, top_k).await
    }

    fn index_epoch(&self) -> u64 {
        (**self).index_epoch()
    }
}

/// 400ms Scatter-Gather Query Engine coordinating local storage and federated mesh retrieval.
pub struct ScatterGatherEngine {
    pub local_storage: Arc<dyn StorageSearcher>,
    pub mesh_dispatcher: Arc<dyn MeshQueryDispatcher>,
    pub acl_manager: Arc<RwLock<PeerAclManager>>,
    pub config: CoordinatorConfig,
    pub secret_seed: [u8; 32],
    pub sender_peer_id: String,
}

impl ScatterGatherEngine {
    pub fn new(
        local_storage: Arc<dyn StorageSearcher>,
        mesh_dispatcher: Arc<dyn MeshQueryDispatcher>,
        acl_manager: Arc<RwLock<PeerAclManager>>,
        config: CoordinatorConfig,
        secret_seed: [u8; 32],
        sender_peer_id: String,
    ) -> Self {
        Self {
            local_storage,
            mesh_dispatcher,
            acl_manager,
            config,
            secret_seed,
            sender_peer_id,
        }
    }

    /// Dispatches parallel queries across local storage and remote peers with optional cached vector hits
    /// to avoid redundant LanceDB vector nearest-neighbor searches during rewrite hops.
    pub async fn execute_query_with_cached_vector(
        &self,
        query_text: &str,
        query_vec: &[f32],
        cached_vector: Option<&[ScoredChunk]>,
        access_tier: u8,
        top_k: usize,
    ) -> (Vec<ScoredChunk>, Vec<VolatileRemoteChunk>, u64, Vec<ScoredChunk>) {
        self.execute_query_with_cached_vector_and_exclusion(
            query_text,
            query_vec,
            cached_vector,
            access_tier,
            top_k,
            &[],
        )
        .await
    }

    /// Dispatches parallel queries across local storage and remote peers with negative chunk exclusion filtering.
    pub async fn execute_query_with_cached_vector_and_exclusion(
        &self,
        query_text: &str,
        query_vec: &[f32],
        cached_vector: Option<&[ScoredChunk]>,
        access_tier: u8,
        top_k: usize,
        exclude_chunk_ids: &[String],
    ) -> (Vec<ScoredChunk>, Vec<VolatileRemoteChunk>, u64, Vec<ScoredChunk>) {
        let start = tokio::time::Instant::now();
        let candidate_limit = top_k * self.config.candidate_multiplier;
        let exclude_set: std::collections::HashSet<&str> =
            exclude_chunk_ids.iter().map(|s| s.as_str()).collect();

        // 1. Fast Local Search: Reuse cached vector hits if available, avoiding redundant LanceDB scans
        let (local_results, new_cached_vector) = if let Some(cached) = cached_vector {
            if !cached.is_empty() {
                let text_hits = self
                    .local_storage
                    .search_text(query_text, access_tier, candidate_limit)
                    .await;
                // Fuse cached vector hits and fresh text hits via RRF
                let mut rrf_map: std::collections::HashMap<String, (f32, quorum_types::DocumentChunk)> =
                    std::collections::HashMap::new();

                for (i, scored) in cached.iter().enumerate() {
                    if exclude_set.contains(scored.chunk.chunk_id.as_str()) {
                        continue;
                    }
                    let rrf = 1.0 / (60.0 + (i + 1) as f32);
                    let entry = rrf_map
                        .entry(scored.chunk.chunk_id.clone())
                        .or_insert_with(|| (0.0, scored.chunk.clone()));
                    entry.0 += rrf;
                }

                for (i, scored) in text_hits.into_iter().enumerate() {
                    if exclude_set.contains(scored.chunk.chunk_id.as_str()) {
                        continue;
                    }
                    let rrf = 1.0 / (60.0 + (i + 1) as f32);
                    let entry = rrf_map
                        .entry(scored.chunk.chunk_id.clone())
                        .or_insert_with(|| (0.0, scored.chunk.clone()));
                    entry.0 += rrf;
                }

                let mut fused_local: Vec<ScoredChunk> = rrf_map
                    .into_iter()
                    .map(|(_id, (score, chunk))| ScoredChunk::new(chunk, score, "local", false))
                    .collect();
                fused_local.sort_by(|a, b| {
                    b.score
                        .partial_cmp(&a.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                (fused_local, cached.to_vec())
            } else {
                let results = if exclude_chunk_ids.is_empty() {
                    self.local_storage
                        .search_hybrid(query_text, query_vec, access_tier, candidate_limit)
                        .await
                } else {
                    self.local_storage
                        .search_hybrid_with_exclusion(
                            query_text,
                            query_vec,
                            access_tier,
                            candidate_limit,
                            exclude_chunk_ids,
                        )
                        .await
                };
                (results.clone(), results)
            }
        } else {
            let results = if exclude_chunk_ids.is_empty() {
                self.local_storage
                    .search_hybrid(query_text, query_vec, access_tier, candidate_limit)
                    .await
            } else {
                self.local_storage
                    .search_hybrid_with_exclusion(
                        query_text,
                        query_vec,
                        access_tier,
                        candidate_limit,
                        exclude_chunk_ids,
                    )
                    .await
            };
            (results.clone(), results)
        };

        // 2. Parallel Remote Peer Queries bounded by 400ms hard deadline
        // Enforces OshoosiClaw P2P Mesh gate & PHI/PII DLP on both outbound queries and inbound remote chunks
        let controller = crate::dlp_mesh::global_mesh_dlp_controller();
        let p2p_enabled = controller
            .settings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .mesh
            .p2p_enabled;

        let remote_responses = if p2p_enabled {
            if let Some(sanitized_query) = controller.sanitize_outbound_query(query_text) {
                let mut req = FederatedQueryRequest {
                    query_id: Uuid::new_v4(),
                    sender_peer_id: self.sender_peer_id.clone(),
                    sender_pubkey: [0u8; 32],
                    query_text: sanitized_query,
                    embedding: query_vec.to_vec(),
                    top_k,
                    timestamp: Utc::now().timestamp(),
                    signature: [0u8; 64],
                };
                let tier = AccessTier::from_u8(access_tier).unwrap_or(AccessTier::Tier0Public);
                sign_request(&self.secret_seed, &mut req, tier);

                let timeout_dur = Duration::from_millis(self.config.timeout_ms)
                    .saturating_sub(start.elapsed())
                    .max(Duration::from_millis(50));
                self.mesh_dispatcher
                    .query_peers(&req, timeout_dur)
                    .await
                    .unwrap_or_default()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // 3. Ingest candidate chunks into volatile memory containers after inbound PHI/PII DLP gate
        let max_peer_responses = {
            let s = controller.settings.read().unwrap_or_else(|e| e.into_inner());
            if s.mesh.max_peer_responses > 0 {
                s.mesh.max_peer_responses
            } else {
                self.config.max_peer_responses.max(1)
            }
        };

        let mut volatile_chunks = Vec::new();
        let mut remote_lists = Vec::new();
        for resp in remote_responses {
            if remote_lists.len() >= max_peer_responses {
                break;
            }
            let mut clean_peer_chunks = Vec::new();
            for mut chunk in resp.chunks {
                if exclude_set.contains(chunk.chunk_id.as_str()) {
                    continue;
                }
                // Byzantine consensus hardening: validate line numbers and clamp remote access tier
                if chunk.line_start > chunk.line_end {
                    tracing::warn!(
                        "Rejecting malformed remote chunk line_start {} > line_end {} from peer {}",
                        chunk.line_start,
                        chunk.line_end,
                        resp.responder_peer_id
                    );
                    continue;
                }
                chunk.access_tier = chunk.access_tier.min(access_tier);

                let dlp_res = controller.inspect_and_enforce_text(
                    &chunk.content,
                    &chunk.file_path,
                    &resp.responder_peer_id,
                    "InboundMesh",
                    None,
                    false,
                );
                if dlp_res.allowed_to_share {
                    chunk.content = dlp_res.scrubbed_text;
                    volatile_chunks.push(chunk.to_volatile_remote_chunk(&resp.responder_peer_id));
                    clean_peer_chunks.push(chunk);
                }
            }
            if !clean_peer_chunks.is_empty() {
                remote_lists.push((resp.responder_peer_id.clone(), clean_peer_chunks));
            }
        }

        // 4. Reciprocal Rank Fusion preserving responder_peer_id
        let mut fused = RrfCombiner::fuse_rankings_with_peers(
            local_results,
            remote_lists,
            self.config.rrf_k,
            top_k,
        );
        if !exclude_set.is_empty() {
            fused.retain(|c| !exclude_set.contains(c.chunk.chunk_id.as_str()));
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        (fused, volatile_chunks, duration_ms, new_cached_vector)
    }

    /// Dispatches parallel queries across local storage and remote peers with strict 400ms deadline.
    pub async fn execute_query(
        &self,
        query_text: &str,
        query_vec: &[f32],
        access_tier: u8,
        top_k: usize,
    ) -> (Vec<ScoredChunk>, Vec<VolatileRemoteChunk>, u64) {
        let (fused, volatile, duration_ms, _) = self
            .execute_query_with_cached_vector(query_text, query_vec, None, access_tier, top_k)
            .await;
        (fused, volatile, duration_ms)
    }

    /// Dispatches federated text queries across local storage and remote mesh peers.
    pub async fn search_federated_text(
        &self,
        query_text: &str,
        access_tier: u8,
        top_k: usize,
    ) -> Vec<ScoredChunk> {
        let mut results = self.local_storage.search_text(query_text, access_tier, top_k).await;

        let controller = crate::dlp_mesh::global_mesh_dlp_controller();
        let (p2p_enabled, max_peer_responses) = {
            let s = controller.settings.read().unwrap_or_else(|e| e.into_inner());
            let max_peers = if s.mesh.max_peer_responses > 0 {
                s.mesh.max_peer_responses
            } else {
                self.config.max_peer_responses.max(1)
            };
            (s.mesh.p2p_enabled, max_peers)
        };

        if !p2p_enabled {
            return results;
        }

        if let Some(sanitized_query) = controller.sanitize_outbound_query(query_text) {
            use quorum_contract::EmbeddingGenerator;
            let embedder = quorum_contract::DeterministicOfflineEngine::new();
            let query_vec = embedder.embed_text(query_text).unwrap_or_else(|_| vec![0.0; 768]);

            let mut req = FederatedQueryRequest {
                query_id: Uuid::new_v4(),
                sender_peer_id: self.sender_peer_id.clone(),
                sender_pubkey: [0u8; 32],
                query_text: sanitized_query,
                embedding: query_vec,
                top_k,
                timestamp: Utc::now().timestamp(),
                signature: [0u8; 64],
            };
            let tier = AccessTier::from_u8(access_tier).unwrap_or(AccessTier::Tier0Public);
            sign_request(&self.secret_seed, &mut req, tier);

            let timeout_dur = Duration::from_millis(self.config.timeout_ms.min(300));
            if let Ok(responses) = self.mesh_dispatcher.query_peers(&req, timeout_dur).await {
                let mut peer_count = 0;
                for resp in responses {
                    if peer_count >= max_peer_responses {
                        break;
                    }
                    let mut peer_added = false;
                    for mut chunk in resp.chunks {
                        if chunk.line_start > chunk.line_end {
                            continue;
                        }
                        chunk.access_tier = chunk.access_tier.min(access_tier);
                        let dlp_res = controller.inspect_and_enforce_text(
                            &chunk.content,
                            &chunk.file_path,
                            &resp.responder_peer_id,
                            "InboundMesh",
                            None,
                            false,
                        );
                        if dlp_res.allowed_to_share {
                            let doc_chunk = quorum_types::DocumentChunk {
                                chunk_id: chunk.chunk_id,
                                document_id: "remote_doc".to_string(),
                                file_path: chunk.file_path,
                                line_start: chunk.line_start,
                                line_end: chunk.line_end,
                                blake3_hash: quorum_types::DocumentChunk::compute_blake3_hash(&dlp_res.scrubbed_text),
                                access_tier: chunk.access_tier,
                                vector: vec![0.0; 768],
                                text_content: dlp_res.scrubbed_text,
                                metadata_json: "{}".to_string(),
                            };
                            results.push(ScoredChunk::new(doc_chunk, chunk.score, resp.responder_peer_id.clone(), true));
                            peer_added = true;
                        }
                    }
                    if peer_added {
                        peer_count += 1;
                    }
                }
            }
        }
        results
    }
}

/// Compatible FederatedQueryCoordinator satisfying opaque-box tests and standalone retrieval.
#[derive(Clone)]
pub struct FederatedQueryCoordinator<S = Arc<dyn StorageSearcher>> {
    pub local_storage: S,
    pub remote_peers: Vec<MockRemotePeer>,
    pub timeout_duration: Duration,
}

impl<S: StorageSearcher> FederatedQueryCoordinator<S> {
    pub fn new(local_storage: S) -> Self {
        Self {
            local_storage,
            remote_peers: Vec::new(),
            timeout_duration: Duration::from_millis(400),
        }
    }

    pub fn add_peer(&mut self, peer: MockRemotePeer) {
        self.remote_peers.push(peer);
    }

    pub async fn execute_query(
        &self,
        query_text: &str,
        query_vec: &[f32],
        access_tier: u8,
        top_k: usize,
    ) -> (Vec<ScoredChunk>, Vec<VolatileRemoteChunk>, u64) {
        let start = tokio::time::Instant::now();

        // 1. Local Search
        let local_results = self
            .local_storage
            .search_hybrid(query_text, query_vec, access_tier, top_k)
            .await;

        // 2. Parallel Remote Peer Queries bounded by 400ms hard deadline
        use futures::stream::{FuturesUnordered, StreamExt};

        let mut futures = FuturesUnordered::new();
        for peer in &self.remote_peers {
            let peer = peer.clone();
            futures.push(tokio::spawn(async move {
                peer.handle_query(access_tier).await
            }));
        }

        let mut peer_lists: Vec<Vec<CandidateChunkDto>> = Vec::new();
        let _ = tokio::time::timeout(self.timeout_duration, async {
            while let Some(res) = futures.next().await {
                if let Ok(mut chunks) = res {
                    chunks.retain_mut(|c| {
                        if c.line_start > c.line_end {
                            return false;
                        }
                        c.access_tier = c.access_tier.min(access_tier);
                        true
                    });
                    if !chunks.is_empty() {
                        peer_lists.push(chunks);
                    }
                }
            }
        })
        .await;

        // 3. Convert to VolatileRemoteChunk
        let volatile_chunks: Vec<VolatileRemoteChunk> = peer_lists
            .iter()
            .flatten()
            .map(|c| c.to_volatile_remote_chunk("mock_peer"))
            .collect();

        // 4. RRF
        let fused = RrfCombiner::fuse_rankings(
            local_results,
            peer_lists,
            60.0,
            top_k,
        );

        let duration_ms = start.elapsed().as_millis() as u64;
        (fused, volatile_chunks, duration_ms)
    }
}
