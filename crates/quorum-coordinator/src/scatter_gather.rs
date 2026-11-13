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

    async fn get_chunks_by_ids(
        &self,
        _chunk_ids: &[String],
        _max_tier: u8,
    ) -> Vec<quorum_types::DocumentChunk> {
        Vec::new()
    }

    fn index_epoch(&self) -> u64 {
        1
    }

    fn load_parent_document(
        &self,
        _doc_id_or_path: &str,
        _max_tier: u8,
    ) -> Option<quorum_types::IngestedParentDocument> {
        None
    }

    fn peek_slice(
        &self,
        _doc_id_or_path: &str,
        _start_byte: usize,
        _end_byte: usize,
        _max_tier: u8,
    ) -> Option<String> {
        None
    }

    fn regex_grep(
        &self,
        _doc_id_or_path: &str,
        _pattern: &str,
        _max_matches: usize,
        _max_tier: u8,
    ) -> Vec<quorum_types::RegexMatchSpan> {
        Vec::new()
    }

    fn expand_parent_window(
        &self,
        _doc_id_or_path: &str,
        _anchor_text: &str,
        _window_bytes: usize,
        _max_tier: u8,
    ) -> Option<(usize, usize, String, Option<String>, Option<String>)> {
        None
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

    async fn get_chunks_by_ids(
        &self,
        chunk_ids: &[String],
        max_tier: u8,
    ) -> Vec<quorum_types::DocumentChunk> {
        self.get_chunks_by_ids(chunk_ids)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|c| c.access_tier <= max_tier)
            .collect()
    }

    fn index_epoch(&self) -> u64 {
        self.index_epoch()
    }

    fn load_parent_document(
        &self,
        doc_id_or_path: &str,
        max_tier: u8,
    ) -> Option<quorum_types::IngestedParentDocument> {
        quorum_storage::StorageEngine::load_parent_document(self, doc_id_or_path, max_tier)
            .ok()
            .flatten()
    }

    fn peek_slice(
        &self,
        doc_id_or_path: &str,
        start_byte: usize,
        end_byte: usize,
        max_tier: u8,
    ) -> Option<String> {
        quorum_storage::StorageEngine::peek_slice(
            self,
            doc_id_or_path,
            start_byte,
            end_byte,
            max_tier,
        )
        .ok()
        .flatten()
    }

    fn regex_grep(
        &self,
        doc_id_or_path: &str,
        pattern: &str,
        max_matches: usize,
        max_tier: u8,
    ) -> Vec<quorum_types::RegexMatchSpan> {
        quorum_storage::StorageEngine::regex_grep(
            self,
            doc_id_or_path,
            pattern,
            max_matches,
            max_tier,
        )
        .unwrap_or_default()
    }

    fn expand_parent_window(
        &self,
        doc_id_or_path: &str,
        anchor_text: &str,
        window_bytes: usize,
        max_tier: u8,
    ) -> Option<(usize, usize, String, Option<String>, Option<String>)> {
        quorum_storage::StorageEngine::expand_parent_window(
            self,
            doc_id_or_path,
            anchor_text,
            window_bytes,
            max_tier,
        )
        .ok()
        .flatten()
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

    async fn get_chunks_by_ids(
        &self,
        chunk_ids: &[String],
        max_tier: u8,
    ) -> Vec<quorum_types::DocumentChunk> {
        (**self).get_chunks_by_ids(chunk_ids, max_tier).await
    }

    fn index_epoch(&self) -> u64 {
        (**self).index_epoch()
    }

    fn load_parent_document(
        &self,
        doc_id_or_path: &str,
        max_tier: u8,
    ) -> Option<quorum_types::IngestedParentDocument> {
        (**self).load_parent_document(doc_id_or_path, max_tier)
    }

    fn peek_slice(
        &self,
        doc_id_or_path: &str,
        start_byte: usize,
        end_byte: usize,
        max_tier: u8,
    ) -> Option<String> {
        (**self).peek_slice(doc_id_or_path, start_byte, end_byte, max_tier)
    }

    fn regex_grep(
        &self,
        doc_id_or_path: &str,
        pattern: &str,
        max_matches: usize,
        max_tier: u8,
    ) -> Vec<quorum_types::RegexMatchSpan> {
        (**self).regex_grep(doc_id_or_path, pattern, max_matches, max_tier)
    }

    fn expand_parent_window(
        &self,
        doc_id_or_path: &str,
        anchor_text: &str,
        window_bytes: usize,
        max_tier: u8,
    ) -> Option<(usize, usize, String, Option<String>, Option<String>)> {
        (**self).expand_parent_window(doc_id_or_path, anchor_text, window_bytes, max_tier)
    }
}

/// Scatter-Gather Query Engine coordinating local storage and federated mesh retrieval.
pub struct ScatterGatherEngine {
    pub local_storage: Arc<dyn StorageSearcher>,
    pub mesh_dispatcher: Arc<dyn MeshQueryDispatcher>,
    pub acl_manager: Arc<RwLock<PeerAclManager>>,
    pub config: CoordinatorConfig,
    pub secret_seed: [u8; 32],
    pub sender_peer_id: String,
    pub last_peer_diagnostics: Arc<RwLock<Option<quorum_types::FederatedPeerDiagnostics>>>,
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
            last_peer_diagnostics: Arc::new(RwLock::new(None)),
        }
    }

    /// Retrieves the most recent federated peer diagnostics from the latest scatter-gather query.
    pub async fn last_diagnostics(&self) -> Option<quorum_types::FederatedPeerDiagnostics> {
        self.last_peer_diagnostics.read().await.clone()
    }

    /// Stores the active federated peer diagnostics for telemetry and sources reporting.
    pub async fn set_last_diagnostics(&self, diag: quorum_types::FederatedPeerDiagnostics) {
        *self.last_peer_diagnostics.write().await = Some(diag);
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
        self.execute_query_with_p2p_query_and_exclusion(
            query_text,
            query_text,
            query_vec,
            cached_vector,
            access_tier,
            top_k,
            exclude_chunk_ids,
        )
        .await
    }

    /// Dispatches parallel queries with a dedicated unbloated P2P query string for remote peers
    /// while preserving expanded BM25 terms for local storage.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_query_with_p2p_query_and_exclusion(
        &self,
        query_text: &str,
        p2p_query_text: &str,
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

        let controller = crate::dlp_mesh::global_mesh_dlp_controller();
        let p2p_enabled = controller
            .settings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .mesh
            .p2p_enabled;

        // 1. Spawn outbound P2P query onto an independent Tokio worker task BEFORE polling local storage
        // so TCP/Yamux frames flush onto the wire at t=0ms and are never delayed by local disk scans.
        let effective_p2p_query = if p2p_query_text.trim().is_empty() {
            query_text
        } else {
            p2p_query_text
        };
        let suppress_local_forensics_p2p = {
            let ql = query_text.to_ascii_lowercase();
            let asks_remote_mesh = ql.contains("peer")
                || ql.contains("mesh")
                || ql.contains("remote node")
                || ql.contains("cluster")
                || ql.contains("federated");
            crate::offline_engine::ForensicQueryIntent::detect(query_text).is_some()
                && !asks_remote_mesh
        };
        let remote_handle = if p2p_enabled {
            if crate::artemis_airgap::contains_artemis_query(effective_p2p_query) {
                tracing::info!("Suppressed outbound P2P query referencing local-only artemis:// URI: airgap enforced");
                None
            } else if suppress_local_forensics_p2p {
                tracing::info!("Suppressed outbound P2P query for host-local Artemis DFIR forensic question");
                None
            } else {
                controller
                    .sanitize_outbound_query(effective_p2p_query)
                    .map(|sanitized_query| {
                    let mut req = FederatedQueryRequest {
                        query_id: Uuid::new_v4(),
                        sender_peer_id: self.sender_peer_id.clone(),
                        sender_pubkey: [0u8; 32],
                        query_text: sanitized_query,
                        embedding: query_vec.to_vec(),
                        top_k: top_k.max(16),
                        timestamp: Utc::now().timestamp(),
                        signature: [0u8; 64],
                    };
                    let tier = AccessTier::from_u8(access_tier).unwrap_or(AccessTier::Tier0Public);
                    sign_request(&self.secret_seed, &mut req, tier);

                    let timeout_dur = Duration::from_millis(
                        self.config
                            .timeout_ms
                            .saturating_sub(60)
                            .max(self.config.timeout_ms * 3 / 4),
                    );
                    let dispatcher = Arc::clone(&self.mesh_dispatcher);
                    tokio::spawn(async move {
                        dispatcher
                            .query_peers_with_diagnostics(&req, timeout_dur)
                            .await
                            .unwrap_or_else(|_| (Vec::new(), quorum_types::FederatedPeerDiagnostics::default()))
                    })
                })
            }
        } else {
            None
        };

        // 2. Execute Local Storage Search concurrently while remote_handle runs on the Tokio pool.
        // Local Artemis DFIR telemetry chunks are indexed at Tier3Restricted (3) so they never cross the P2P mesh,
        // but local queries on this host may retrieve them when Artemis local collection is enabled or queried.
        let local_access_tier = {
            let ql = query_text.to_ascii_lowercase();
            let is_forensic_q = crate::offline_engine::ForensicQueryIntent::detect(query_text).is_some()
                || crate::offline_engine::ForensicQueryIntent::detect(effective_p2p_query).is_some()
                || ql.contains("artemis")
                || ql.contains("antivirus")
                || ql.contains("defender")
                || ql.contains("codeintegrity")
                || ql.contains("eventlog")
                || ql.contains("systemeventlog");
            let s = controller.settings.read().unwrap_or_else(|e| e.into_inner());
            if s.artemis.enabled || s.artemis.local_collection_enabled || is_forensic_q {
                access_tier.max(quorum_types::AccessTier::Tier3Restricted.as_u8())
            } else {
                access_tier
            }
        };

        let (local_results, new_cached_vector) = if let Some(cached) = cached_vector {
            if !cached.is_empty() {
                let text_hits = self
                    .local_storage
                    .search_text(query_text, local_access_tier, candidate_limit)
                    .await;
                let mut rrf_map: std::collections::HashMap<
                    String,
                    (f32, quorum_types::DocumentChunk),
                > = std::collections::HashMap::new();

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
                        .search_hybrid(query_text, query_vec, local_access_tier, candidate_limit)
                        .await
                } else {
                    self.local_storage
                        .search_hybrid_with_exclusion(
                            query_text,
                            query_vec,
                            local_access_tier,
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
                    .search_hybrid(query_text, query_vec, local_access_tier, candidate_limit)
                    .await
            } else {
                self.local_storage
                    .search_hybrid_with_exclusion(
                        query_text,
                        query_vec,
                        local_access_tier,
                        candidate_limit,
                        exclude_chunk_ids,
                    )
                        .await
            };
            (results.clone(), results)
        };

        let (remote_responses, mut diagnostics) = match remote_handle {
            Some(jh) => jh
                .await
                .unwrap_or_else(|_| (Vec::new(), quorum_types::FederatedPeerDiagnostics::default())),
            None => {
                let mut d = quorum_types::FederatedPeerDiagnostics::default();
                if !p2p_enabled {
                    d.summary_reason = Some("P2P mesh retrieval is disabled in settings".to_string());
                }
                (Vec::new(), d)
            }
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

        let dlp_concurrency = std::thread::available_parallelism()
            .map(|n| (n.get() * 2).clamp(8, 32))
            .unwrap_or(16);
        let dlp_sem = Arc::new(tokio::sync::Semaphore::new(dlp_concurrency));

        use futures::stream::{FuturesUnordered, StreamExt};

        let mut dlp_tasks = FuturesUnordered::new();
        for (resp_idx, resp) in remote_responses.into_iter().enumerate() {
            if resp_idx >= max_peer_responses {
                break;
            }
            let peer_id = resp.responder_peer_id;
            for (chunk_idx, mut chunk) in resp.chunks.into_iter().enumerate() {
                if exclude_set.contains(chunk.chunk_id.as_str()) {
                    continue;
                }
                // Byzantine consensus hardening: validate line numbers and clamp remote access tier
                if chunk.line_start > chunk.line_end {
                    tracing::warn!(
                        "Rejecting malformed remote chunk line_start {} > line_end {} from peer {}",
                        chunk.line_start,
                        chunk.line_end,
                        peer_id
                    );
                    continue;
                }
                if crate::artemis_airgap::is_artemis_uri(&chunk.file_path) {
                    tracing::warn!(
                        "Byzantine peer {} returned illegal artemis:// chunk; dropping.",
                        peer_id
                    );
                    continue;
                }
                chunk.access_tier = chunk.access_tier.min(access_tier);

                let c_ctrl = Arc::clone(&controller);
                let p_id = peer_id.clone();
                let sem = Arc::clone(&dlp_sem);
                dlp_tasks.push(tokio::spawn(async move {
                    let _permit = sem.acquire_owned().await.ok();
                    let dlp_res = c_ctrl.inspect_and_enforce_text(
                        &chunk.content,
                        &chunk.file_path,
                        &p_id,
                        "InboundMesh",
                        None,
                        false,
                    );
                    (resp_idx, chunk_idx, p_id, chunk, dlp_res)
                }));
            }
        }

        let mut inspected_items = Vec::new();
        while let Some(res) = dlp_tasks.next().await {
            if let Ok(item) = res {
                inspected_items.push(item);
            }
        }
        inspected_items.sort_by_key(|(resp_idx, chunk_idx, _, _, _)| (*resp_idx, *chunk_idx));

        let mut volatile_chunks = Vec::with_capacity(inspected_items.len());
        let mut remote_lists = Vec::new();
        let mut current_resp_idx = usize::MAX;
        let mut current_peer = String::new();
        let mut current_list = Vec::new();

        for (resp_idx, _, peer_id, mut chunk, dlp_res) in inspected_items {
            if dlp_res.allowed_to_share {
                chunk.content = dlp_res.scrubbed_text;
                volatile_chunks.push(chunk.to_volatile_remote_chunk(&peer_id));
                if resp_idx != current_resp_idx {
                    if !current_list.is_empty() {
                        remote_lists.push((current_peer, current_list));
                        current_list = Vec::new();
                    }
                    current_resp_idx = resp_idx;
                    current_peer = peer_id;
                }
                current_list.push(chunk);
            }
        }
        if !current_list.is_empty() {
            remote_lists.push((current_peer, current_list));
        }

        // 4. Reciprocal Rank Fusion preserving responder_peer_id
        let remote_lists_snapshot = remote_lists.clone();
        let mut fused = RrfCombiner::fuse_rankings_with_peers(
            local_results,
            remote_lists,
            self.config.rrf_k,
            top_k,
        );
        // When a real P2P Swarm peer (`12D3KooW...`) returns matching chunks that also exist locally,
        // `RrfCombiner` boosts the local chunk's score by 1.25x (consensus boost) and deduplicates by BLAKE3 hash.
        // We also preserve the remote peer's `ScoredChunk` entries so the UI Sources panel and citations
        // display BOTH `(local)` AND `(Peer: 12D3KooW...)` when a document exists across 2+ computers.
        for (peer_id, peer_chunks) in remote_lists_snapshot.clone() {
            if peer_id.is_empty() || peer_id == "local" {
                continue;
            }
            for (rank, dto) in peer_chunks.into_iter().enumerate() {
                let already_present = fused
                    .iter()
                    .any(|sc| sc.source_peer == peer_id && sc.chunk.chunk_id == dto.chunk_id);
                if !already_present {
                    let derived_doc_id = dto
                        .chunk_id
                        .rsplit_once(':')
                        .map(|(d, _)| d.to_string())
                        .unwrap_or_else(|| format!("remote:{}", dto.file_path));
                    let doc_chunk = quorum_types::DocumentChunk {
                        chunk_id: dto.chunk_id,
                        document_id: derived_doc_id,
                        file_path: dto.file_path,
                        line_start: dto.line_start,
                        line_end: dto.line_end,
                        blake3_hash: quorum_types::DocumentChunk::compute_blake3_hash(&dto.content),
                        access_tier: dto.access_tier,
                        vector: vec![0.0; 768],
                        text_content: dto.content,
                        metadata_json: "{}".to_string(),
                    };
                    let rrf_score = (1.0 / (self.config.rrf_k as f32 + (rank + 1) as f32)) * 1.25;
                    fused.push(ScoredChunk::new(doc_chunk, rrf_score, peer_id.clone(), true));
                }
            }
        }
        // Promote chunks (including remote peer chunks) that contain exact rare query tokens (e.g. "16017" in "CVE-2020-16017")
        // when partial matches lack the specific identifier token.
        let q_tokens: Vec<String> = query_text
            .to_ascii_lowercase()
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|t| t.len() >= 4)
            .map(|s| s.to_string())
            .collect();
        if !q_tokens.is_empty() && fused.len() > 1 {
            let hit_counts: Vec<usize> = fused
                .iter()
                .map(|sc| {
                    let text_l = sc.chunk.text_content.to_ascii_lowercase();
                    let path_l = sc.chunk.file_path.to_ascii_lowercase();
                    q_tokens
                        .iter()
                        .filter(|tok| text_l.contains(tok.as_str()) || path_l.contains(tok.as_str()))
                        .count()
                })
                .collect();

            let max_hits = hit_counts.iter().copied().max().unwrap_or(0);
            let min_hits = hit_counts.iter().copied().min().unwrap_or(0);
            if max_hits > min_hits && max_hits == q_tokens.len() {
                let mut decorated: Vec<(usize, ScoredChunk)> =
                    hit_counts.into_iter().zip(fused).collect();
                decorated.sort_by(|(ha, a), (hb, b)| {
                    (*hb == q_tokens.len())
                        .cmp(&(*ha == q_tokens.len()))
                        .then_with(|| {
                            b.score
                                .partial_cmp(&a.score)
                                .unwrap_or(std::cmp::Ordering::Equal)
                        })
                        .then_with(|| a.chunk.chunk_id.cmp(&b.chunk.chunk_id))
                });
                fused = decorated.into_iter().map(|(_, sc)| sc).collect();
            }
        }
        if !exclude_set.is_empty() {
            fused.retain(|c| !exclude_set.contains(c.chunk.chunk_id.as_str()));
        }

        let remote_chunks_count = fused
            .iter()
            .filter(|c| !c.source_peer.is_empty() && c.source_peer != "local")
            .count();

        // Ensure peer_outcomes is populated for all responding peers
        for (peer_id, chunks) in &remote_lists_snapshot {
            if let Some(outcome) = diagnostics.peer_outcomes.iter_mut().find(|o| o.peer_id == *peer_id) {
                if !chunks.is_empty() {
                    outcome.matching_chunk_count = chunks.len();
                    outcome.status = quorum_types::PeerQueryStatus::Connected;
                }
            } else {
                diagnostics.peer_outcomes.push(quorum_types::PeerQueryOutcome {
                    peer_id: peer_id.clone(),
                    status: if !chunks.is_empty() {
                        quorum_types::PeerQueryStatus::Connected
                    } else {
                        quorum_types::PeerQueryStatus::ZeroMatchingChunks
                    },
                    matching_chunk_count: chunks.len(),
                    cited_chunk_count: 0,
                    latency_ms: 0,
                    error_message: None,
                });
            }
        }

        for outcome in &mut diagnostics.peer_outcomes {
            outcome.cited_chunk_count = fused
                .iter()
                .filter(|c| c.source_peer == outcome.peer_id)
                .count();
        }

        let mut contributing_peer_ids: Vec<String> = fused
            .iter()
            .filter(|c| !c.source_peer.is_empty() && c.source_peer != "local")
            .map(|c| c.source_peer.clone())
            .collect();
        contributing_peer_ids.sort();
        contributing_peer_ids.dedup();
        diagnostics.contributing_peer_ids = contributing_peer_ids;

        if remote_chunks_count == 0 {
            if p2p_enabled {
                let mesh_port = {
                    let s = controller.settings.read().unwrap_or_else(|e| e.into_inner());
                    s.mesh.mesh_port
                };
                let timeout_dur_ms = self.config.timeout_ms;
                diagnostics.compute_summary_reason(mesh_port, timeout_dur_ms);
            }
        } else {
            diagnostics.summary_reason = None;
        }

        *self.last_peer_diagnostics.write().await = Some(diagnostics.clone());
        crate::offline_engine::DeterministicOfflineSynthesisEngine::set_active_peer_diagnostics(diagnostics);

        let duration_ms = start.elapsed().as_millis() as u64;
        (fused, volatile_chunks, duration_ms, new_cached_vector)
    }

    /// Dispatches parallel queries across local storage and remote peers.
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

    /// Dispatches federated text queries across local storage and remote mesh peers concurrently,
    /// returning both `ScoredChunk`s and `VolatileRemoteChunk`s.
    pub async fn search_federated_text_with_volatile(
        &self,
        query_text: &str,
        access_tier: u8,
        top_k: usize,
    ) -> (Vec<ScoredChunk>, Vec<VolatileRemoteChunk>) {
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

        let peer_handle = if p2p_enabled {
            if crate::artemis_airgap::contains_artemis_query(query_text) {
                tracing::info!("Suppressed outbound P2P query referencing local-only artemis:// URI: airgap enforced");
                None
            } else {
                controller
                    .sanitize_outbound_query(query_text)
                    .map(|sanitized_query| {
                        use quorum_contract::EmbeddingGenerator;
                        let embedder = quorum_contract::DeterministicOfflineEngine::new();
                        let query_vec = embedder
                            .embed_text(query_text)
                            .unwrap_or_else(|_| vec![0.0; 768]);

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
                        let timeout_dur = Duration::from_millis(self.config.timeout_ms);
                        let dispatcher = Arc::clone(&self.mesh_dispatcher);
                        tokio::spawn(async move { dispatcher.query_peers(&req, timeout_dur).await.ok() })
                    })
            }
        } else {
            None
        };

        let mut results = self
            .local_storage
            .search_text(query_text, access_tier, top_k)
            .await;
        let peer_responses_opt = match peer_handle {
            Some(jh) => jh.await.ok().flatten(),
            None => None,
        };

        let mut volatile = Vec::new();
        if let Some(responses) = peer_responses_opt {
            let dlp_concurrency = std::thread::available_parallelism()
                .map(|n| (n.get() * 2).clamp(8, 32))
                .unwrap_or(16);
            let dlp_sem = Arc::new(tokio::sync::Semaphore::new(dlp_concurrency));

            use futures::stream::{FuturesUnordered, StreamExt};
            let mut dlp_tasks = FuturesUnordered::new();

            for (resp_idx, resp) in responses.into_iter().enumerate() {
                if resp_idx >= max_peer_responses {
                    break;
                }
                let peer_id = resp.responder_peer_id;
                for (chunk_idx, mut chunk) in resp.chunks.into_iter().enumerate() {
                    if chunk.line_start > chunk.line_end {
                        continue;
                    }
                    if crate::artemis_airgap::is_artemis_uri(&chunk.file_path) {
                        tracing::warn!(
                            "Byzantine peer {} returned illegal artemis:// chunk; dropping.",
                            peer_id
                        );
                        continue;
                    }
                    chunk.access_tier = chunk.access_tier.min(access_tier);
                    let c_ctrl = Arc::clone(&controller);
                    let p_id = peer_id.clone();
                    let sem = Arc::clone(&dlp_sem);
                    dlp_tasks.push(tokio::spawn(async move {
                        let _permit = sem.acquire_owned().await.ok();
                        let dlp_res = c_ctrl.inspect_and_enforce_text(
                            &chunk.content,
                            &chunk.file_path,
                            &p_id,
                            "InboundMesh",
                            None,
                            false,
                        );
                        (resp_idx, chunk_idx, p_id, chunk, dlp_res)
                    }));
                }
            }

            let mut evaluated = Vec::new();
            while let Some(res) = dlp_tasks.next().await {
                if let Ok(item) = res {
                    evaluated.push(item);
                }
            }
            evaluated.sort_by_key(|(r_idx, c_idx, _, _, _)| (*r_idx, *c_idx));

            for (_, _, peer_id, mut chunk, dlp_res) in evaluated {
                if dlp_res.allowed_to_share {
                    chunk.content = dlp_res.scrubbed_text.clone();
                    volatile.push(chunk.to_volatile_remote_chunk(&peer_id));
                    let derived_doc_id = chunk
                        .chunk_id
                        .rsplit_once(':')
                        .map(|(d, _)| d.to_string())
                        .unwrap_or_else(|| format!("remote:{}", chunk.file_path));
                    let doc_chunk = quorum_types::DocumentChunk {
                        chunk_id: chunk.chunk_id,
                        document_id: derived_doc_id,
                        file_path: chunk.file_path,
                        line_start: chunk.line_start,
                        line_end: chunk.line_end,
                        blake3_hash: quorum_types::DocumentChunk::compute_blake3_hash(
                            &dlp_res.scrubbed_text,
                        ),
                        access_tier: chunk.access_tier,
                        vector: vec![0.0; 768],
                        text_content: dlp_res.scrubbed_text,
                        metadata_json: "{}".to_string(),
                    };
                    results.push(ScoredChunk::new(
                        doc_chunk,
                        chunk.score,
                        peer_id,
                        true,
                    ));
                }
            }
        }
        (results, volatile)
    }

    /// Dispatches federated text queries across local storage and remote mesh peers concurrently.
    pub async fn search_federated_text(
        &self,
        query_text: &str,
        access_tier: u8,
        top_k: usize,
    ) -> Vec<ScoredChunk> {
        self.search_federated_text_with_volatile(query_text, access_tier, top_k)
            .await
            .0
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

        // 2. Parallel Remote Peer Queries bounded by timeout_duration
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
        let fused = RrfCombiner::fuse_rankings(local_results, peer_lists, 60.0, top_k);

        let duration_ms = start.elapsed().as_millis() as u64;
        (fused, volatile_chunks, duration_ms)
    }
}
