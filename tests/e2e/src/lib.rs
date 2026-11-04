//! Test infrastructure, mathematical oracles, domain contracts, and test fixtures
//! for the QuorumRAG 4-tier opaque-box E2E test suite.

use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use quorum_types::{CandidateChunkDto, DocumentChunk, ScoredChunk, VolatileRemoteChunk};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use subtle::ConstantTimeEq;
use uuid::Uuid;

// ============================================================================
// 1. MATHEMATICAL ORACLE & REFERENCE SPECIFICATIONS
// ============================================================================

/// Canonical Gemma Embedding contract specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddingContractSpec {
    pub contract_version: u32,
    pub model_name: String,
    pub dimension: usize,
    pub normalization: String,
    pub distance_metric: String,
    pub pooling_strategy: String,
    pub max_sequence_length: usize,
}

impl Default for EmbeddingContractSpec {
    fn default() -> Self {
        Self {
            contract_version: 1,
            model_name: "google/embeddinggemma-300m".to_string(),
            dimension: 768,
            normalization: "L2".to_string(),
            distance_metric: "Cosine".to_string(),
            pooling_strategy: "MeanPooling".to_string(),
            max_sequence_length: 512,
        }
    }
}

/// Authoritative oracle: Computes deterministic BLAKE3 contract hash over embedding parameters.
pub fn oracle_derive_contract_hash(spec: &EmbeddingContractSpec) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"QUORUM_RAG_EMBEDDING_CONTRACT_V1\n");
    hasher.update(&spec.contract_version.to_le_bytes());
    hasher.update(spec.model_name.as_bytes());
    hasher.update(b"\n");
    hasher.update(&(spec.dimension as u64).to_le_bytes());
    hasher.update(spec.normalization.as_bytes());
    hasher.update(b"\n");
    hasher.update(spec.distance_metric.as_bytes());
    hasher.update(b"\n");
    hasher.update(spec.pooling_strategy.as_bytes());
    hasher.update(b"\n");
    hasher.update(&(spec.max_sequence_length as u64).to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Authoritative oracle: Constant-time validation of contract hashes during handshake.
pub fn oracle_validate_handshake(local_hash: &[u8; 32], remote_hash: &[u8; 32]) -> bool {
    local_hash.ct_eq(remote_hash).into()
}

/// Authoritative oracle: Computes Reciprocal Rank Fusion (RRF) score for a document.
///
/// Formula: RRF(d) = sum_{m in M} 1 / (k + rank_m(d))
/// where k = 60.0 and rank_m is 1-based ordinal rank.
pub fn oracle_compute_rrf(ranks: &[usize], k: f32) -> f32 {
    ranks.iter().map(|&r| 1.0 / (k + r as f32)).sum()
}

/// Authoritative oracle: Computes Cosine similarity between two vectors.
pub fn oracle_cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    assert_eq!(a.len(), b.len(), "Vector lengths must match");
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm_a == 0.0 || norm_b == 0.0 {
        0.0
    } else {
        (dot / (norm_a * norm_b)).clamp(-1.0, 1.0)
    }
}

/// Authoritative oracle: Deterministic L2-normalized 768-dim vector derived from BLAKE3 text hash.
pub fn oracle_deterministic_vector(text: &str, dimension: usize) -> Vec<f32> {
    let mut vec = Vec::with_capacity(dimension);
    for i in 0..dimension {
        let mut hasher = blake3::Hasher::new();
        hasher.update(text.as_bytes());
        hasher.update(&(i as u64).to_le_bytes());
        let digest = hasher.finalize();
        let bytes: [u8; 4] = [digest.as_bytes()[0], digest.as_bytes()[1], digest.as_bytes()[2], digest.as_bytes()[3]];
        let raw = u32::from_le_bytes(bytes);
        // Map to -1.0 .. 1.0
        let val = (raw as f32 / u32::MAX as f32) * 2.0 - 1.0;
        vec.push(val);
    }
    // L2 Normalize
    let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for v in &mut vec {
            *v /= norm;
        }
    }
    vec
}

/// Authoritative oracle: Ed25519 signing over canonical query payload.
pub fn oracle_sign_query(
    secret_seed: &[u8; 32],
    query_id: Uuid,
    sender_peer_id: &str,
    timestamp: i64,
    query_text: &str,
) -> (VerifyingKey, [u8; 64]) {
    let signing_key = SigningKey::from_bytes(secret_seed);
    let verifying_key = signing_key.verifying_key();

    let mut bytes = Vec::with_capacity(64 + sender_peer_id.len() + query_text.len());
    bytes.extend_from_slice(b"QUORUM_QUERY_V1\n");
    bytes.extend_from_slice(query_id.as_bytes());
    bytes.extend_from_slice(sender_peer_id.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(&timestamp.to_le_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(query_text.as_bytes());

    let signature = signing_key.sign(&bytes);
    (verifying_key, signature.to_bytes())
}

/// Authoritative oracle: Ed25519 verification with anti-replay timestamp freshness.
pub fn oracle_verify_query(
    verifying_key: &VerifyingKey,
    signature_bytes: &[u8; 64],
    query_id: Uuid,
    sender_peer_id: &str,
    timestamp: i64,
    query_text: &str,
    max_drift_secs: i64,
) -> Result<(), &'static str> {
    let now = Utc::now().timestamp();
    if (now - timestamp).abs() > max_drift_secs {
        return Err("Query expired or timestamp clock drift exceeded limit");
    }

    let mut bytes = Vec::with_capacity(64 + sender_peer_id.len() + query_text.len());
    bytes.extend_from_slice(b"QUORUM_QUERY_V1\n");
    bytes.extend_from_slice(query_id.as_bytes());
    bytes.extend_from_slice(sender_peer_id.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(&timestamp.to_le_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(query_text.as_bytes());

    let signature = Signature::from_bytes(signature_bytes);
    verifying_key
        .verify(&bytes, &signature)
        .map_err(|_| "Invalid Ed25519 cryptographic signature")?;

    Ok(())
}

// ============================================================================
// 2. STORAGE ENGINE CONTRACT & OPAQUE-BOX IMPLEMENTATION
// ============================================================================

/// In-memory storage engine fully fulfilling `PROJECT.md § Interface Contracts: quorum-storage`.
/// Invariant: Completely isolated, zero Arrow dependencies exported.
#[derive(Debug, Default, Clone)]
pub struct IsolatedStorageEngine {
    chunks: Vec<DocumentChunk>,
    hash_set: HashMap<String, usize>,
}

impl IsolatedStorageEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_chunks(&mut self, new_chunks: &[DocumentChunk]) -> usize {
        let mut count = 0;
        for c in new_chunks {
            if !self.hash_set.contains_key(&c.blake3_hash) {
                let idx = self.chunks.len();
                self.hash_set.insert(c.blake3_hash.clone(), idx);
                self.chunks.push(c.clone());
                count += 1;
            }
        }
        count
    }

    pub fn has_chunk_hash(&self, blake3_hash: &str) -> bool {
        self.hash_set.contains_key(blake3_hash)
    }

    /// Vector ANN scan with SQL pre-filtering (`access_tier <= max_tier`).
    pub fn search_vector(&self, query_vec: &[f32], max_tier: u8, top_k: usize) -> Vec<ScoredChunk> {
        let mut matches: Vec<ScoredChunk> = self
            .chunks
            .iter()
            .filter(|c| c.access_tier <= max_tier)
            .map(|c| {
                let sim = oracle_cosine_similarity(&c.vector, query_vec);
                ScoredChunk::new(c.clone(), sim, "local", false)
            })
            .collect();

        matches.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        matches.truncate(top_k);
        matches
    }

    /// Keyword BM25/FTS search with SQL pre-filtering (`access_tier <= max_tier`).
    pub fn search_text(&self, query_text: &str, max_tier: u8, top_k: usize) -> Vec<ScoredChunk> {
        let terms: Vec<String> = query_text
            .to_lowercase()
            .split_whitespace()
            .map(|s| s.trim_matches(|c: char| !c.is_alphanumeric()).to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if terms.is_empty() {
            return Vec::new();
        }

        let mut matches: Vec<ScoredChunk> = self
            .chunks
            .iter()
            .filter(|c| c.access_tier <= max_tier)
            .filter_map(|c| {
                let content_lower = c.text_content.to_lowercase();
                let mut matched_terms = 0;
                for t in &terms {
                    if content_lower.contains(t) {
                        matched_terms += 1;
                    }
                }
                if matched_terms > 0 {
                    let score = (matched_terms as f32) / (terms.len() as f32);
                    Some(ScoredChunk::new(c.clone(), score, "local", false))
                } else {
                    None
                }
            })
            .collect();

        matches.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        matches.truncate(top_k);
        matches
    }

    /// Hybrid search combining vector scan and keyword search via Reciprocal Rank Fusion.
    pub fn search_hybrid(&self, query_text: &str, query_vec: &[f32], max_tier: u8, top_k: usize) -> Vec<ScoredChunk> {
        let vector_hits = self.search_vector(query_vec, max_tier, top_k * 2);
        let text_hits = self.search_text(query_text, max_tier, top_k * 2);

        let mut rrf_scores: HashMap<String, (f32, DocumentChunk)> = HashMap::new();

        for (rank_0, scored) in vector_hits.into_iter().enumerate() {
            let rrf = 1.0 / (60.0 + (rank_0 + 1) as f32);
            let entry = rrf_scores.entry(scored.chunk.chunk_id.clone()).or_insert((0.0, scored.chunk));
            entry.0 += rrf;
        }

        for (rank_0, scored) in text_hits.into_iter().enumerate() {
            let rrf = 1.0 / (60.0 + (rank_0 + 1) as f32);
            let entry = rrf_scores.entry(scored.chunk.chunk_id.clone()).or_insert((0.0, scored.chunk));
            entry.0 += rrf;
        }

        let mut combined: Vec<ScoredChunk> = rrf_scores
            .into_iter()
            .map(|(_id, (score, chunk))| ScoredChunk::new(chunk, score, "local", false))
            .collect();

        combined.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        combined.truncate(top_k);
        combined
    }

    pub fn compact(&mut self) -> Result<(), &'static str> {
        // Compaction merges and retains valid unique chunks
        self.chunks.dedup_by(|a, b| a.chunk_id == b.chunk_id);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }
}

// ============================================================================
// 3. FEDERATED SCATTER-GATHER & VOLATILE MEMORY COORDINATOR
// ============================================================================

/// Simulated remote peer node with network latency and authorized access tier.
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

/// Scatter-Gather federated query coordinator with strict 400ms timeout.
#[derive(Debug, Clone)]
pub struct FederatedQueryCoordinator {
    pub local_storage: IsolatedStorageEngine,
    pub remote_peers: Vec<MockRemotePeer>,
    pub timeout_duration: Duration,
}

impl FederatedQueryCoordinator {
    pub fn new(local_storage: IsolatedStorageEngine) -> Self {
        Self {
            local_storage,
            remote_peers: Vec::new(),
            timeout_duration: Duration::from_millis(400),
        }
    }

    pub fn add_peer(&mut self, peer: MockRemotePeer) {
        self.remote_peers.push(peer);
    }

    /// Dispatch scatter-gather query across local storage and remote peers in parallel.
    /// Strictly aborts slow peers that fail to respond within `timeout_duration` (400ms).
    pub async fn execute_query(
        &self,
        query_text: &str,
        query_vec: &[f32],
        access_tier: u8,
        top_k: usize,
    ) -> (Vec<ScoredChunk>, Vec<VolatileRemoteChunk>, u64) {
        let start = tokio::time::Instant::now();

        // 1. Local Search (synchronous / fast)
        let local_results = self.local_storage.search_hybrid(query_text, query_vec, access_tier, top_k);

        // 2. Parallel Remote Peer Queries bounded by 400ms hard deadline
        let mut tasks = Vec::new();
        for peer in &self.remote_peers {
            let peer = peer.clone();
            tasks.push(tokio::spawn(async move {
                peer.handle_query(access_tier).await
            }));
        }

        // Wait for all peer tasks with 400ms hard timeout guard
        let mut peer_lists: Vec<Vec<CandidateChunkDto>> = Vec::new();
        let timeout_result = tokio::time::timeout(self.timeout_duration, async {
            for task in tasks {
                if let Ok(chunks) = task.await {
                    peer_lists.push(chunks);
                }
            }
        })
        .await;

        let _timed_out = timeout_result.is_err();

        // 3. Convert remote candidates to VolatileRemoteChunk (ZeroizeOnDrop)
        let volatile_chunks: Vec<VolatileRemoteChunk> = peer_lists
            .iter()
            .flatten()
            .map(|c| c.to_volatile_remote_chunk("mock_peer"))
            .collect();

        // 4. Reciprocal Rank Fusion across Local + Remote
        let mut rrf_map: HashMap<String, (f32, ScoredChunk)> = HashMap::new();

        // Add local chunks to RRF
        for (rank_0, scored) in local_results.into_iter().enumerate() {
            let score = 1.0 / (60.0 + (rank_0 + 1) as f32);
            let entry = rrf_map.entry(scored.chunk.chunk_id.clone()).or_insert((0.0, scored));
            entry.0 += score;
        }

        // Add remote chunks to RRF per peer list
        for list in peer_lists {
            for (rank_0, candidate) in list.into_iter().enumerate() {
                let score = 1.0 / (60.0 + (rank_0 + 1) as f32);
                let doc_chunk = DocumentChunk {
                    chunk_id: candidate.chunk_id.clone(),
                    document_id: "remote_doc".to_string(),
                    file_path: candidate.file_path,
                    line_start: candidate.line_start,
                    line_end: candidate.line_end,
                    blake3_hash: DocumentChunk::compute_blake3_hash(&candidate.content),
                    access_tier: candidate.access_tier,
                    vector: vec![0.0; 768],
                    text_content: candidate.content,
                    metadata_json: "{}".to_string(),
                };
                let scored = ScoredChunk::new(doc_chunk, candidate.score, "mock_peer", true);
                let entry = rrf_map.entry(candidate.chunk_id).or_insert((0.0, scored));
                entry.0 += score;
            }
        }

        let mut fused: Vec<ScoredChunk> = rrf_map
            .into_iter()
            .map(|(_id, (rrf_score, mut chunk))| {
                chunk.score = rrf_score;
                chunk
            })
            .collect();

        fused.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        fused.truncate(top_k);

        let duration_ms = start.elapsed().as_millis() as u64;
        (fused, volatile_chunks, duration_ms)
    }
}

// ============================================================================
// 4. TEST FIXTURE GENERATORS
// ============================================================================

/// Creates a simulated filesystem tree with various code, document, and binary files.
pub fn create_test_filesystem(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    use std::fs::{create_dir_all, File};
    use std::io::Write;

    let mut created = Vec::new();

    // 1. Rust file
    let rs_dir = root.join("src");
    create_dir_all(&rs_dir)?;
    let rs_path = rs_dir.join("main.rs");
    let mut f = File::create(&rs_path)?;
    writeln!(f, "//! Main entrypoint\npub fn main() {{\n    println!(\"QuorumRAG online\");\n}}")?;
    created.push(rs_path);

    // 2. Python file
    let py_path = root.join("script.py");
    let mut f = File::create(&py_path)?;
    writeln!(f, "#!/usr/bin/env python3\nimport os\ndef run():\n    print('Running agent')")?;
    created.push(py_path);

    // 3. Markdown documentation
    let md_path = root.join("README.md");
    let mut f = File::create(&md_path)?;
    writeln!(f, "# QuorumRAG\n\nPeer-to-peer retrieval augmented generation daemon.")?;
    created.push(md_path);

    // 4. JSON configuration
    let json_path = root.join("config.json");
    let mut f = File::create(&json_path)?;
    writeln!(f, "{{\n  \"port\": 8080,\n  \"dimension\": 768\n}}")?;
    created.push(json_path);

    // 5. Binary PE executable header
    let bin_path = root.join("launcher.exe");
    let mut f = File::create(&bin_path)?;
    f.write_all(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")?;
    created.push(bin_path);

    // 6. Unicode filename
    let unicode_path = root.join("résumé_éditïon.txt");
    let mut f = File::create(&unicode_path)?;
    writeln!(f, "Candidate experience: 10 years of distributed systems.")?;
    created.push(unicode_path);

    // 7. Empty file
    let empty_path = root.join("empty.txt");
    let _ = File::create(&empty_path)?;
    created.push(empty_path);

    Ok(created)
}
