//! Pure domain types, configuration, telemetry traces, and volatile zeroizing DTOs
//! for QuorumRAG's Layer-1 pure-Rust AtlasKV engine.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::AtlasKvError;

/// Validates an access tier value (`0=Public, 1=Internal, 2=Confidential, 3=Restricted`).
#[inline]
pub fn validate_access_tier(tier: u8) -> Result<u8, AtlasKvError> {
    if tier <= 3 {
        Ok(tier)
    } else {
        Err(AtlasKvError::InvalidAccessTier(tier))
    }
}

/// Canonical KG2KV triple record stored in `AtlasKvStore`.
///
/// Mirrors `HKUST-KnowComp/AtlasKV`'s `DataPoint` schema (`name`, `description_type`,
/// `description`, `key_string`) extended with QuorumRAG provenance, access tier,
/// and homonym work-cluster metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KgTripleRecord {
    /// Dense 0-based leaf row index matching `keys_leaf.f16` / `vals_leaf.f16` row offsets.
    pub triple_id: u64,
    /// Deterministic 64-char hex BLAKE3 deduplication digest over normalized `(entity, relation, value, file_path)`.
    pub blake3_hash: String,
    /// Anchor entity (`name` in AtlasKV).
    pub entity: String,
    /// Natural-language relation noun (`description_type` in AtlasKV).
    pub relation: String,
    /// Canonical AtlasKV lookup key: `"the {relation} of {entity}"`.
    pub key_string: String,
    /// Fact / object value payload (`description` in AtlasKV).
    pub value: String,
    /// Parent source document ID.
    pub document_id: String,
    /// Source chunk ID.
    pub chunk_id: String,
    /// Source file path.
    pub file_path: String,
    /// 1-indexed starting line in the source file.
    pub line_start: u32,
    /// 1-indexed ending line in the source file.
    pub line_end: u32,
    /// Canonical work/homonym cluster ID (aligned with `DocumentCatalog::derive_work_cluster_id`).
    pub work_cluster_id: String,
    /// Access tier (`0=Public ..= 3=Restricted`).
    pub access_tier: u8,
    /// Originating node (`"local"` or remote libp2p `PeerId`).
    pub source_peer: String,
}

impl KgTripleRecord {
    /// Builds canonical AtlasKV `key_string = "the {relation} of {entity}"`.
    pub fn build_key_string(entity: &str, relation: &str) -> String {
        let rel = relation.trim();
        let ent = entity.trim();
        if rel.to_ascii_lowercase().starts_with("the ") {
            format!("{} of {}", rel, ent)
        } else {
            format!("the {} of {}", rel, ent)
        }
    }

    /// Computes a deterministic 64-hex BLAKE3 deduplication digest.
    pub fn compute_blake3(entity: &str, relation: &str, value: &str, file_path: &str) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(entity.trim().to_ascii_lowercase().as_bytes());
        hasher.update(b"\x1f");
        hasher.update(relation.trim().to_ascii_lowercase().as_bytes());
        hasher.update(b"\x1f");
        hasher.update(value.trim().to_ascii_lowercase().as_bytes());
        hasher.update(b"\x1f");
        hasher.update(normalize_path_key(file_path).as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Constructs a validated `KgTripleRecord` (assigning `triple_id = 0` until persisted).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        entity: impl Into<String>,
        relation: impl Into<String>,
        value: impl Into<String>,
        document_id: impl Into<String>,
        chunk_id: impl Into<String>,
        file_path: impl Into<String>,
        line_start: u32,
        line_end: u32,
        work_cluster_id: impl Into<String>,
        access_tier: u8,
        source_peer: impl Into<String>,
    ) -> Result<Self, AtlasKvError> {
        validate_access_tier(access_tier)?;
        let entity = entity.into().trim().to_string();
        let relation = relation.into().trim().to_string();
        let value = value.into().trim().to_string();
        let file_path = file_path.into();
        let key_string = Self::build_key_string(&entity, &relation);
        let blake3_hash = Self::compute_blake3(&entity, &relation, &value, &file_path);

        Ok(Self {
            triple_id: 0,
            blake3_hash,
            entity,
            relation,
            key_string,
            value,
            document_id: document_id.into(),
            chunk_id: chunk_id.into(),
            file_path,
            line_start,
            line_end: line_end.max(line_start),
            work_cluster_id: work_cluster_id.into(),
            access_tier,
            source_peer: source_peer.into(),
        })
    }
}

/// Source chunk input for KG2KV extraction (decoupled from Arrow/LanceDB).
#[derive(Debug, Clone)]
pub struct KgSourceChunk {
    pub chunk_id: String,
    pub document_id: String,
    pub file_path: String,
    pub line_start: u32,
    pub line_end: u32,
    pub access_tier: u8,
    pub text_content: String,
    pub metadata_json: String,
}

/// Configuration for the 3-level `Root -> Inter1 -> Leaf` hierarchy and HiKVP pruner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtlasKvTreeConfig {
    /// Number of top-level `Root` clusters retained during HiKVP Stage 1.
    pub root_top_k_kb: usize,
    /// Number of `Inter1` clusters retained during HiKVP Stage 2.
    pub inter_top_k_kb: usize,
    /// Maximum number of `Leaf` triples returned by HiKVP Stage 3.
    pub leaf_top_k_kb: usize,
    /// Embedding vector dimension (canonical QuorumRAG Gemma contract: `768`).
    pub embedding_dim: usize,
    /// Below this active leaf count, exact linear scan runs in < 1 ms without needing tree overhead.
    pub min_triples_for_hierarchy: usize,
    /// Upper clamp on intermediate (`Inter1`) clusters.
    pub max_inter_clusters: usize,
    /// Upper clamp on top-level (`Root`) clusters.
    pub max_root_clusters: usize,
    /// Maximum Spherical K-Means++ iterations per hierarchy layer.
    pub max_kmeans_iters: usize,
}

impl Default for AtlasKvTreeConfig {
    fn default() -> Self {
        Self {
            root_top_k_kb: 32,
            inter_top_k_kb: 64,
            leaf_top_k_kb: 48,
            embedding_dim: 768,
            min_triples_for_hierarchy: 512,
            max_inter_clusters: 65_536,
            max_root_clusters: 2_048,
            max_kmeans_iters: 15,
        }
    }
}

/// Persisted daemon/UI settings for Layer-1 AtlasKV.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AtlasKvSettings {
    pub enabled: bool,
    pub auto_extract_on_ingest: bool,
    pub root_top_k_kb: usize,
    pub inter_top_k_kb: usize,
    pub leaf_top_k_kb: usize,
    pub mesh_centroid_routing: bool,
    pub max_triples_per_chunk: usize,
    pub cluster_rebuild_delta_pct: u8,
}

impl Default for AtlasKvSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_extract_on_ingest: true,
            root_top_k_kb: 32,
            inter_top_k_kb: 64,
            leaf_top_k_kb: 48,
            mesh_centroid_routing: true,
            max_triples_per_chunk: 12,
            cluster_rebuild_delta_pct: 15,
        }
    }
}

/// A HiKVP-scored Knowledge Graph triple returned to retrieval/synthesis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoredKgTriple {
    pub triple: KgTripleRecord,
    /// Cosine similarity score in `[-1.0, 1.0]`.
    pub score: f32,
}

/// Observability & pruning telemetry emitted for every HiKVP search.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiKvpPruningTrace {
    pub total_active_leaves: usize,
    pub root_total: usize,
    pub root_selected: usize,
    pub inter_total: usize,
    pub inter_scanned: usize,
    pub inter_selected: usize,
    pub leaf_candidates_before_filter: usize,
    pub leaf_scanned: usize,
    pub leaf_selected: usize,
    pub access_tier_filtered: usize,
    pub folder_filtered: usize,
    pub used_hierarchy: bool,
    pub elapsed_us: u64,
}

impl HiKvpPruningTrace {
    /// Fraction of active leaves scanned (`0.0..=1.0`). Lower means stronger HiKVP pruning.
    pub fn leaf_scan_ratio(&self) -> f64 {
        if self.total_active_leaves == 0 {
            0.0
        } else {
            self.leaf_scanned as f64 / self.total_active_leaves as f64
        }
    }
}

/// Live storage & cluster topology snapshot for `/api/v1/atlaskv/status`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtlasKvStoreStats {
    pub total_rows: usize,
    pub active_triples: usize,
    pub deleted_triples: usize,
    pub root_clusters: usize,
    pub inter_clusters: usize,
    pub embedding_dim: usize,
    pub hierarchy_built: bool,
    pub incremental_since_rebuild: usize,
    pub disk_bytes_shards: u64,
    pub estimated_resident_ram_bytes: u64,
}

/// Compact privacy-preserving `f16` Root centroid digest shared over libp2p mesh gossip
/// for sublinear centroid-guided peer routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCentroidSummary {
    pub peer_id: String,
    pub max_tier_included: u8,
    pub embedding_dim: usize,
    pub centroid_count: usize,
    pub active_triple_count: usize,
    /// Row-major IEEE-754 little-endian `f16` bytes (`centroid_count * embedding_dim * 2`).
    pub centroids_f16_le: Vec<u8>,
}

impl PeerCentroidSummary {
    /// Serialized payload byte size of the raw centroid matrix.
    #[inline]
    pub fn payload_bytes(&self) -> usize {
        self.centroids_f16_le.len()
    }

    /// Computes maximum cosine similarity between a normalized `query_vec` and this peer's
    /// advertised Root centroids. Higher score indicates stronger topical relevance on this peer.
    pub fn score_query(&self, query_vec: &[f32]) -> Result<f32, AtlasKvError> {
        if query_vec.len() != self.embedding_dim {
            return Err(AtlasKvError::DimensionMismatch {
                expected: self.embedding_dim,
                actual: query_vec.len(),
            });
        }
        if self.centroid_count == 0 {
            return Ok(f32::NEG_INFINITY);
        }
        let row_bytes = self
            .embedding_dim
            .checked_mul(2)
            .ok_or_else(|| AtlasKvError::CorruptedHierarchy("centroid row byte overflow".into()))?;
        let expected_len = self
            .centroid_count
            .checked_mul(row_bytes)
            .ok_or_else(|| AtlasKvError::CorruptedHierarchy("centroid payload overflow".into()))?;
        if self.centroids_f16_le.len() != expected_len {
            return Err(AtlasKvError::CorruptedHierarchy(format!(
                "PeerCentroidSummary byte length {} != expected {}",
                self.centroids_f16_le.len(),
                expected_len
            )));
        }

        let mut best = f32::NEG_INFINITY;
        for c in 0..self.centroid_count {
            let start = c * row_bytes;
            let dot = dot_f16_le(query_vec, &self.centroids_f16_le[start..start + row_bytes]);
            if dot > best {
                best = dot;
            }
        }
        Ok(best)
    }
}

/// Wire DTO for transmitting DLP-inspected Knowledge Graph triples across the libp2p mesh.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize, Default)]
pub struct CandidateKgTripleDto {
    #[zeroize(skip)]
    pub triple_id: u64,
    pub entity: String,
    pub relation: String,
    pub key_string: String,
    pub value: String,
    #[zeroize(skip)]
    pub file_path: String,
    #[zeroize(skip)]
    pub line_start: u32,
    #[zeroize(skip)]
    pub line_end: u32,
    #[zeroize(skip)]
    pub work_cluster_id: String,
    #[zeroize(skip)]
    pub access_tier: u8,
    #[zeroize(skip)]
    pub score: f32,
    #[zeroize(skip)]
    pub origin_peer_id: String,
}

impl CandidateKgTripleDto {
    /// Consumes this DTO into a volatile memory container that zeroizes plaintext on drop.
    pub fn into_volatile(self) -> VolatileRemoteTriple {
        VolatileRemoteTriple {
            triple_id: self.triple_id,
            entity: self.entity,
            relation: self.relation,
            key_string: self.key_string,
            value: self.value,
            file_path: self.file_path,
            line_start: self.line_start,
            line_end: self.line_end,
            work_cluster_id: self.work_cluster_id,
            access_tier: self.access_tier,
            score: self.score,
            origin_peer_id: self.origin_peer_id,
        }
    }
}

/// Volatile container for remote Knowledge Graph triples received from mesh peers.
///
/// Implements `ZeroizeOnDrop` so remote entity/relation/value plaintext is overwritten
/// with zeroes immediately upon drop.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Default)]
pub struct VolatileRemoteTriple {
    #[zeroize(skip)]
    pub triple_id: u64,
    pub entity: String,
    pub relation: String,
    pub key_string: String,
    pub value: String,
    #[zeroize(skip)]
    pub file_path: String,
    #[zeroize(skip)]
    pub line_start: u32,
    #[zeroize(skip)]
    pub line_end: u32,
    #[zeroize(skip)]
    pub work_cluster_id: String,
    #[zeroize(skip)]
    pub access_tier: u8,
    #[zeroize(skip)]
    pub score: f32,
    #[zeroize(skip)]
    pub origin_peer_id: String,
}

/// Zero-allocation dot product between an `f32` slice and little-endian IEEE-754 `f16` bytes.
#[inline]
pub fn dot_f16_le(query: &[f32], f16_le_bytes: &[u8]) -> f32 {
    let mut sum = 0.0f32;
    let (pairs, _) = f16_le_bytes.as_chunks::<2>();
    for (&q, &pair) in query.iter().zip(pairs.iter()) {
        let v = half::f16::from_le_bytes(pair).to_f32();
        sum += q * v;
    }
    sum
}

/// Zero-allocation dot product between two `f32` slices.
#[inline]
pub fn dot_f32(a: &[f32], b: &[f32]) -> f32 {
    let mut sum = 0.0f32;
    for (&x, &y) in a.iter().zip(b.iter()) {
        sum += x * y;
    }
    sum
}

/// L2-normalizes a vector in place; returns `true` if non-zero norm.
#[inline]
pub fn l2_normalize_in_place(vec: &mut [f32]) -> bool {
    let norm_sq: f32 = vec.iter().map(|&x| x * x).sum();
    if norm_sq <= 1e-12 || !norm_sq.is_finite() {
        return false;
    }
    let inv = norm_sq.sqrt().recip();
    for x in vec.iter_mut() {
        *x *= inv;
    }
    true
}

/// Encodes an `f32` vector into little-endian IEEE-754 `f16` bytes appended to `out`.
#[inline]
pub fn encode_f32_to_f16_le(vec: &[f32], out: &mut Vec<u8>) {
    out.reserve(vec.len() * 2);
    for &x in vec {
        let bytes = half::f16::from_f32(x).to_le_bytes();
        out.extend_from_slice(&bytes);
    }
}

/// Cross-OS path normalization for consistent keys and allowed-folder prefix checks.
///
/// Aligns with `quorum_types::normalize_prefix_for_match` and `quorum_storage::file_path_compare_key`:
/// strips Windows verbatim prefixes (`\\?\`, `//?/`) and `\\?\UNC\` / `//?/unc/` -> `\\`,
/// normalizes separators and ASCII-lowercases Windows drive/UNC paths while preserving Unix case.
pub fn normalize_path_key(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let unc_rewritten: Option<String> = {
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with(r"\\?\unc\") || lower.starts_with("//?/unc/") {
            Some(format!(r"\\{}", &trimmed[8..]))
        } else if lower.starts_with(r"\\?\") || lower.starts_with("//?/") {
            Some(trimmed[4..].to_string())
        } else {
            None
        }
    };
    let effective = unc_rewritten.as_deref().unwrap_or(trimmed);

    if let Ok(norm) = quorum_types::normalize_prefix_for_match(effective) {
        return norm;
    }

    let bytes = effective.as_bytes();
    let is_win_drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    let is_unc = effective.starts_with(r"\\") || effective.starts_with("//");
    if cfg!(windows) || is_win_drive || is_unc {
        let replaced = effective.replace('/', "\\");
        let mut out = String::with_capacity(replaced.len());
        let mut chars = replaced.chars().peekable();
        if replaced.starts_with(r"\\") {
            out.push_str(r"\\");
            while matches!(chars.peek(), Some('\\')) {
                chars.next();
            }
        }
        let mut prev_sep = false;
        for ch in chars {
            if ch == '\\' {
                if !prev_sep {
                    out.push('\\');
                }
                prev_sep = true;
            } else {
                out.push(ch.to_ascii_lowercase());
                prev_sep = false;
            }
        }
        if out.len() > 3 && out.ends_with('\\') {
            out.pop();
        }
        out
    } else {
        let mut out = String::with_capacity(effective.len());
        let mut prev_sep = false;
        for ch in effective.chars() {
            if ch == '/' || ch == '\\' {
                if !prev_sep {
                    out.push('/');
                }
                prev_sep = true;
            } else {
                out.push(ch);
                prev_sep = false;
            }
        }
        if out.len() > 1 && out.ends_with('/') {
            out.pop();
        }
        out
    }
}
