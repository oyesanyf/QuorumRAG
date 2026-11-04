//! Pure Rust domain models, access tier specifications, and DTOs for QuorumRAG.
//!
//! # Invariant
//! This crate contains ZERO dependencies on `arrow-array`, `arrow-schema`, or `lancedb`.
//! All types are cleanly serializable and transport-agnostic.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Error types for `quorum-types` domain logic.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TypeError {
    #[error("Invalid access tier: {0}. Valid tiers are 0 (Public), 1 (Internal), 2 (Confidential), 3 (Restricted)")]
    InvalidAccessTier(u8),

    #[error("Failed to parse access tier string '{0}'. Expected 'public', 'internal', 'confidential', 'restricted', or 0..=3")]
    ParseAccessTierError(String),

    #[error("Invalid line range: start line {start} cannot exceed end line {end}")]
    InvalidLineRange { start: u32, end: u32 },

    #[error("Vector dimension mismatch: expected {expected}, got {actual}")]
    VectorDimensionMismatch { expected: usize, actual: usize },

    #[error("Query timestamp expired or clock drift exceeded {drift_seconds}s (server: {server_time}, query: {query_time})")]
    QueryExpired {
        server_time: i64,
        query_time: i64,
        drift_seconds: i64,
    },
}

/// Access tiers for document and chunk level authorization.
///
/// Tiers are monotonically ordered:
/// - `Tier0Public` (0): Open access, unrestricted.
/// - `Tier1Internal` (1): Organization/team internal.
/// - `Tier2Confidential` (2): Sensitive confidential data.
/// - `Tier3Restricted` (3): Strictly restricted boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum AccessTier {
    #[default]
    Tier0Public = 0,
    Tier1Internal = 1,
    Tier2Confidential = 2,
    Tier3Restricted = 3,
}

impl AccessTier {
    /// Convert a raw `u8` value into an `AccessTier`.
    pub fn from_u8(val: u8) -> Result<Self, TypeError> {
        match val {
            0 => Ok(Self::Tier0Public),
            1 => Ok(Self::Tier1Internal),
            2 => Ok(Self::Tier2Confidential),
            3 => Ok(Self::Tier3Restricted),
            other => Err(TypeError::InvalidAccessTier(other)),
        }
    }

    /// Return the raw `u8` representation of the access tier.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Check if this tier is authorized given a peer's authorized upper bound tier.
    #[inline]
    pub fn is_authorized_for(self, max_authorized_tier: Self) -> bool {
        self <= max_authorized_tier
    }

    /// Generate the SQL filter predicate for LanceDB pushdown filtering.
    ///
    /// Example: `"access_tier <= 1"`
    #[inline]
    pub fn sql_filter_lte(self) -> String {
        format!("access_tier <= {}", self.as_u8())
    }

    /// Human-readable label for this tier.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Tier0Public => "public",
            Self::Tier1Internal => "internal",
            Self::Tier2Confidential => "confidential",
            Self::Tier3Restricted => "restricted",
        }
    }
}

impl From<AccessTier> for u8 {
    #[inline]
    fn from(tier: AccessTier) -> Self {
        tier.as_u8()
    }
}

impl TryFrom<u8> for AccessTier {
    type Error = TypeError;

    #[inline]
    fn try_from(val: u8) -> Result<Self, Self::Error> {
        Self::from_u8(val)
    }
}

impl fmt::Display for AccessTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

impl FromStr for AccessTier {
    type Err = TypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "0" | "public" | "tier0" | "tier0_public" => Ok(Self::Tier0Public),
            "1" | "internal" | "tier1" | "tier1_internal" => Ok(Self::Tier1Internal),
            "2" | "confidential" | "tier2" | "tier2_confidential" => Ok(Self::Tier2Confidential),
            "3" | "restricted" | "tier3" | "tier3_restricted" => Ok(Self::Tier3Restricted),
            _ => Err(TypeError::ParseAccessTierError(s.to_string())),
        }
    }
}

/// Pure domain model for an ingested and indexed document chunk.
///
/// Guaranteed free from any Apache Arrow or LanceDB types.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentChunk {
    /// Unique identifier for this chunk (e.g. `{doc_id}:{chunk_index}`).
    pub chunk_id: String,

    /// Unique identifier / hash of the parent source document.
    pub document_id: String,

    /// Relative or canonical path of the source file.
    pub file_path: String,

    /// 1-indexed starting line number in the source file.
    pub line_start: u32,

    /// 1-indexed ending line number in the source file.
    pub line_end: u32,

    /// Hex-encoded BLAKE3 digest of `text_content`.
    pub blake3_hash: String,

    /// Numeric access tier (0=Public, 1=Internal, 2=Confidential, 3=Restricted).
    pub access_tier: u8,

    /// Dense embedding vector (e.g. 768-dimensional Gemma representation).
    pub vector: Vec<f32>,

    /// Plain text content of the chunk.
    pub text_content: String,

    /// Extensible metadata JSON payload.
    pub metadata_json: String,
}

impl DocumentChunk {
    /// Compute the 64-character lowercase hex BLAKE3 hash for arbitrary text content.
    pub fn compute_blake3_hash(content: &str) -> String {
        blake3::hash(content.as_bytes()).to_hex().to_string()
    }

    /// Construct a new `DocumentChunk` with automated validation and BLAKE3 computation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chunk_id: impl Into<String>,
        document_id: impl Into<String>,
        file_path: impl Into<String>,
        line_start: u32,
        line_end: u32,
        access_tier: u8,
        vector: Vec<f32>,
        text_content: impl Into<String>,
        metadata_json: Option<String>,
    ) -> Result<Self, TypeError> {
        if line_start > line_end {
            return Err(TypeError::InvalidLineRange {
                start: line_start,
                end: line_end,
            });
        }
        // Enforce valid access tier bounds (0..=3)
        AccessTier::from_u8(access_tier)?;

        let text = text_content.into();
        let blake3_hash = Self::compute_blake3_hash(&text);
        let meta = metadata_json.unwrap_or_else(|| "{}".to_string());

        Ok(Self {
            chunk_id: chunk_id.into(),
            document_id: document_id.into(),
            file_path: file_path.into(),
            line_start,
            line_end,
            blake3_hash,
            access_tier,
            vector,
            text_content: text,
            metadata_json: meta,
        })
    }

    /// Access the strongly typed `AccessTier` for this chunk.
    pub fn access_tier_typed(&self) -> Result<AccessTier, TypeError> {
        AccessTier::from_u8(self.access_tier)
    }

    /// Verify whether `blake3_hash` matches the current `text_content`.
    pub fn verify_hash(&self) -> bool {
        let expected = Self::compute_blake3_hash(&self.text_content);
        self.blake3_hash == expected
    }
}

/// A retrieved chunk accompanied by its relevance or similarity score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoredChunk {
    /// Underlying document chunk.
    pub chunk: DocumentChunk,

    /// Relevance or similarity score (e.g. Cosine similarity 0.0..1.0 or RRF fused score).
    pub score: f32,

    /// Peer identifier that produced or hosts this chunk ("local" for local storage).
    pub source_peer: String,

    /// Flag indicating whether the chunk originated from a remote swarm peer.
    pub is_remote: bool,
}

impl ScoredChunk {
    /// Create a new `ScoredChunk` instance.
    pub fn new(
        chunk: DocumentChunk,
        score: f32,
        source_peer: impl Into<String>,
        is_remote: bool,
    ) -> Self {
        Self {
            chunk,
            score,
            source_peer: source_peer.into(),
            is_remote,
        }
    }

    /// Convert this scored chunk into a lightweight citation for user-facing responses.
    pub fn to_citation(&self) -> Citation {
        let snippet = if self.chunk.text_content.len() > 240 {
            let mut end = 240;
            while !self.chunk.text_content.is_char_boundary(end) && end > 0 {
                end -= 1;
            }
            format!("{}...", &self.chunk.text_content[..end])
        } else {
            self.chunk.text_content.clone()
        };

        Citation {
            peer_id: self.source_peer.clone(),
            file_path: self.chunk.file_path.clone(),
            line_start: self.chunk.line_start,
            line_end: self.chunk.line_end,
            score: self.score,
            snippet,
        }
    }
}

/// Structured document source citation for UI responses and synthesis prompts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Citation {
    /// Peer ID providing the document ("local" or libp2p PeerId string).
    pub peer_id: String,

    /// File path where the snippet resides.
    pub file_path: String,

    /// 1-indexed starting line number.
    pub line_start: u32,

    /// 1-indexed ending line number.
    pub line_end: u32,

    /// Calculated relevance or similarity score.
    pub score: f32,

    /// Brief plain text excerpt.
    pub snippet: String,
}

/// Data transfer object for transmitting candidate chunks across the network or between layers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct CandidateChunkDto {
    #[zeroize(skip)]
    pub chunk_id: String,
    #[zeroize(skip)]
    pub file_path: String,
    #[zeroize(skip)]
    pub line_start: u32,
    #[zeroize(skip)]
    pub line_end: u32,
    pub content: String,
    #[zeroize(skip)]
    pub score: f32,
    #[zeroize(skip)]
    pub access_tier: u8,
}

impl CandidateChunkDto {
    /// Convert from a `ScoredChunk`.
    pub fn from_scored_chunk(scored: &ScoredChunk) -> Self {
        Self {
            chunk_id: scored.chunk.chunk_id.clone(),
            file_path: scored.chunk.file_path.clone(),
            line_start: scored.chunk.line_start,
            line_end: scored.chunk.line_end,
            content: scored.chunk.text_content.clone(),
            score: scored.score,
            access_tier: scored.chunk.access_tier,
        }
    }

    /// Consumes this DTO by value into a volatile memory container without duplicating heap memory.
    pub fn into_volatile_remote_chunk(self, peer_id: impl Into<String>) -> VolatileRemoteChunk {
        VolatileRemoteChunk {
            chunk_id: self.chunk_id,
            peer_id: peer_id.into(),
            file_path: self.file_path,
            line_start: self.line_start,
            line_end: self.line_end,
            score: self.score,
            access_tier: self.access_tier,
            content: self.content,
        }
    }

    /// Wrap this DTO in a volatile memory container that zeroizes content upon drop.
    /// Prefer `into_volatile_remote_chunk` to avoid heap retention of plaintext.
    pub fn to_volatile_remote_chunk(&self, peer_id: impl Into<String>) -> VolatileRemoteChunk {
        self.clone().into_volatile_remote_chunk(peer_id)
    }
}

/// Request dispatched across the rust-libp2p swarm for federated scatter-gather retrieval.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FederatedQueryRequest {
    /// Unique query identifier for request/response tracking.
    pub query_id: Uuid,

    /// Sender's libp2p PeerId string.
    pub sender_peer_id: String,

    /// Sender's Ed25519 public key bytes (32 bytes).
    pub sender_pubkey: [u8; 32],

    /// The user query string in plain text.
    pub query_text: String,

    /// Gemma dense query embedding vector.
    pub embedding: Vec<f32>,

    /// Maximum number of candidate chunks requested from the peer.
    pub top_k: usize,

    /// UTC unix timestamp in seconds when the query was created.
    pub timestamp: i64,

    /// Ed25519 signature over canonical query payload (64 bytes).
    #[serde(with = "serde_sig64")]
    pub signature: [u8; 64],
}

/// Helper module to serialize and deserialize 64-byte Ed25519 signatures.
pub mod serde_sig64 {
    use serde::{self, Deserializer, Serializer};

    pub fn serialize<S>(sig: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let mut s = String::with_capacity(128);
            for b in sig {
                use std::fmt::Write;
                let _ = write!(s, "{:02x}", b);
            }
            serializer.serialize_str(&s)
        } else {
            serializer.serialize_bytes(sig)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SigVisitor;

        impl<'de> serde::de::Visitor<'de> for SigVisitor {
            type Value = [u8; 64];

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a 64-byte signature array, byte slice, or 128-char hex string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let bytes = v.as_bytes();
                if bytes.len() != 128 {
                    return Err(E::custom(format!(
                        "hex signature must be 128 hex characters, got {}",
                        bytes.len()
                    )));
                }
                let mut out = [0u8; 64];
                for i in 0..64 {
                    let hi = match bytes[i * 2] {
                        b'0'..=b'9' => bytes[i * 2] - b'0',
                        b'a'..=b'f' => bytes[i * 2] - b'a' + 10,
                        b'A'..=b'F' => bytes[i * 2] - b'A' + 10,
                        _ => return Err(E::custom("invalid hex character in signature")),
                    };
                    let lo = match bytes[i * 2 + 1] {
                        b'0'..=b'9' => bytes[i * 2 + 1] - b'0',
                        b'a'..=b'f' => bytes[i * 2 + 1] - b'a' + 10,
                        b'A'..=b'F' => bytes[i * 2 + 1] - b'A' + 10,
                        _ => return Err(E::custom("invalid hex character in signature")),
                    };
                    out[i] = (hi << 4) | lo;
                }
                Ok(out)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != 64 {
                    return Err(E::custom(format!(
                        "signature bytes must be exactly 64 bytes, got {}",
                        v.len()
                    )));
                }
                let mut out = [0u8; 64];
                out.copy_from_slice(v);
                Ok(out)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut out = [0u8; 64];
                for byte in &mut out {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("signature sequence too short"))?;
                }
                Ok(out)
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_any(SigVisitor)
        } else {
            deserializer.deserialize_bytes(SigVisitor)
        }
    }
}

impl FederatedQueryRequest {
    /// Construct the canonical bytes used for Ed25519 signing and verification.
    ///
    /// Layout:
    /// `"QUORUM_QUERY_V1\n"` || `query_id` (16 bytes) || `sender_peer_id` (bytes) ||
    /// `\n` || `sender_pubkey` (32 bytes) || `\n` || `timestamp` (8 bytes LE) ||
    /// `\n` || `top_k` (8 bytes LE) || `\n` || `embedding_digest` (32 bytes BLAKE3) ||
    /// `\n` || `query_text` (bytes)
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            128 + self.sender_peer_id.len() + self.query_text.len() + (self.embedding.len() * 4),
        );
        bytes.extend_from_slice(b"QUORUM_QUERY_V1\n");
        bytes.extend_from_slice(self.query_id.as_bytes());
        bytes.extend_from_slice(self.sender_peer_id.as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(&self.sender_pubkey);
        bytes.push(b'\n');
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(&(self.top_k as u64).to_le_bytes());
        bytes.push(b'\n');
        let mut emb_hasher = blake3::Hasher::new();
        for &val in &self.embedding {
            emb_hasher.update(&val.to_le_bytes());
        }
        bytes.extend_from_slice(emb_hasher.finalize().as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(self.query_text.as_bytes());
        bytes
    }

    /// Compute the 32-byte BLAKE3 digest of the canonical signing bytes.
    pub fn canonical_digest(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_signing_bytes()).as_bytes()
    }

    /// Verify whether this query timestamp is fresh within `max_drift_secs` (e.g. 60 seconds).
    pub fn is_fresh(&self, max_drift_secs: i64) -> Result<(), TypeError> {
        let now = Utc::now().timestamp();
        let drift = now
            .checked_sub(self.timestamp)
            .and_then(|d| d.checked_abs())
            .unwrap_or(i64::MAX);

        if drift > max_drift_secs {
            Err(TypeError::QueryExpired {
                server_time: now,
                query_time: self.timestamp,
                drift_seconds: max_drift_secs,
            })
        } else {
            Ok(())
        }
    }
}

/// Response returned by a peer answering a `FederatedQueryRequest`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FederatedQueryResponse {
    /// Matches the `query_id` in the request.
    pub query_id: Uuid,

    /// PeerId of the responding node.
    pub responder_peer_id: String,

    /// Ranked candidate chunks found by the peer under the requester's authorized access tier.
    pub chunks: Vec<CandidateChunkDto>,
}

/// Volatile memory wrapper for remote chunks received from untrusted peers.
///
/// Implements `ZeroizeOnDrop` so that plaintext chunk content residing in memory
/// is wiped with zeroes immediately when dropped, preventing heap leaks or paging to swap.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct VolatileRemoteChunk {
    #[zeroize(skip)]
    pub chunk_id: String,

    #[zeroize(skip)]
    pub peer_id: String,

    #[zeroize(skip)]
    pub file_path: String,

    #[zeroize(skip)]
    pub line_start: u32,

    #[zeroize(skip)]
    pub line_end: u32,

    #[zeroize(skip)]
    pub score: f32,

    #[zeroize(skip)]
    pub access_tier: u8,

    /// Volatile plaintext content, scrubbed on drop.
    pub content: String,
}

impl VolatileRemoteChunk {
    /// Borrow the plaintext content.
    #[inline]
    pub fn content(&self) -> &str {
        &self.content
    }

    /// Convert into a user-facing `Citation`.
    pub fn to_citation(&self) -> Citation {
        let snippet = if self.content.len() > 240 {
            let mut end = 240;
            while !self.content.is_char_boundary(end) && end > 0 {
                end -= 1;
            }
            format!("{}...", &self.content[..end])
        } else {
            self.content.clone()
        };

        Citation {
            peer_id: self.peer_id.clone(),
            file_path: self.file_path.clone(),
            line_start: self.line_start,
            line_end: self.line_end,
            score: self.score,
            snippet,
        }
    }
}

/// High-level result produced by the query coordinator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueryResult {
    /// Fused, deduplicated, and ranked scored chunks.
    pub chunks: Vec<ScoredChunk>,

    /// Augmented prompt formatted for downstream synthesis.
    pub synthesis_prompt: String,

    /// Execution time in milliseconds for the complete scatter-gather operation.
    pub execution_time_ms: u64,

    /// Extracted citations for all referenced sources.
    pub sources_cited: Vec<Citation>,

    /// Flag indicating whether this result was served directly from the BLAKE3 QueryCache.
    #[serde(default)]
    pub cache_hit: bool,

    /// The index/cache epoch at the time of retrieval.
    #[serde(default)]
    pub cache_epoch: u64,
}

/// Live telemetry metrics for multi-layer query and embedding caching.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct CacheTelemetry {
    /// Whether the active request resulted in a cache hit.
    pub cache_hit: bool,
    /// Total cumulative cache hits across coordinator lifetime.
    pub hits: u64,
    /// Total cumulative cache misses across coordinator lifetime.
    pub misses: u64,
    /// Calculated cache hit rate: hits / (hits + misses).
    pub hit_rate: f32,
    /// Number of active entries currently retained in QueryCache.
    pub cached_queries: usize,
    /// Number of active vectors currently retained in EmbeddingCache.
    pub cached_embeddings: usize,
    /// Monotonically increasing cache epoch counter.
    pub cache_epoch: u64,
}

impl CacheTelemetry {
    pub fn new(
        cache_hit: bool,
        hits: u64,
        misses: u64,
        cached_queries: usize,
        cached_embeddings: usize,
        cache_epoch: u64,
    ) -> Self {
        let total = hits.saturating_add(misses);
        let hit_rate = if total == 0 {
            0.0
        } else {
            hits as f32 / total as f32
        };

        Self {
            cache_hit,
            hits,
            misses,
            hit_rate,
            cached_queries,
            cached_embeddings,
            cache_epoch,
        }
    }
}

/// Status response returned by `POST /api/cache/recache` and `quorumrag recache`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecacheResponse {
    pub status: String,
    pub cache_epoch: u64,
    pub cleared_entries: usize,
    pub warmed_entries: usize,
    pub duration_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_tier_order_and_conversions() {
        assert!(AccessTier::Tier0Public < AccessTier::Tier1Internal);
        assert!(AccessTier::Tier1Internal < AccessTier::Tier2Confidential);
        assert!(AccessTier::Tier2Confidential < AccessTier::Tier3Restricted);

        assert_eq!(AccessTier::from_u8(0).unwrap(), AccessTier::Tier0Public);
        assert_eq!(AccessTier::from_u8(1).unwrap(), AccessTier::Tier1Internal);
        assert_eq!(AccessTier::from_u8(2).unwrap(), AccessTier::Tier2Confidential);
        assert_eq!(AccessTier::from_u8(3).unwrap(), AccessTier::Tier3Restricted);
        assert!(AccessTier::from_u8(4).is_err());

        assert_eq!(AccessTier::Tier0Public.as_u8(), 0);
        assert_eq!(AccessTier::Tier1Internal.as_u8(), 1);
        assert_eq!(AccessTier::Tier2Confidential.as_u8(), 2);
        assert_eq!(AccessTier::Tier3Restricted.as_u8(), 3);

        assert_eq!(AccessTier::Tier1Internal.sql_filter_lte(), "access_tier <= 1");
        assert_eq!(AccessTier::Tier3Restricted.sql_filter_lte(), "access_tier <= 3");

        // String parsing
        assert_eq!("public".parse::<AccessTier>().unwrap(), AccessTier::Tier0Public);
        assert_eq!("internal".parse::<AccessTier>().unwrap(), AccessTier::Tier1Internal);
        assert_eq!("confidential".parse::<AccessTier>().unwrap(), AccessTier::Tier2Confidential);
        assert_eq!("restricted".parse::<AccessTier>().unwrap(), AccessTier::Tier3Restricted);
        assert_eq!("1".parse::<AccessTier>().unwrap(), AccessTier::Tier1Internal);
        assert!("unknown".parse::<AccessTier>().is_err());
    }

    #[test]
    fn test_access_tier_authorization_check() {
        let user_tier = AccessTier::Tier1Internal;
        assert!(AccessTier::Tier0Public.is_authorized_for(user_tier));
        assert!(AccessTier::Tier1Internal.is_authorized_for(user_tier));
        assert!(!AccessTier::Tier2Confidential.is_authorized_for(user_tier));
        assert!(!AccessTier::Tier3Restricted.is_authorized_for(user_tier));
    }

    #[test]
    fn test_document_chunk_creation_and_hash_verification() {
        let text = "fn main() { println!(\"Hello QuorumRAG!\"); }";
        let expected_hash = blake3::hash(text.as_bytes()).to_hex().to_string();

        let chunk = DocumentChunk::new(
            "chunk-1",
            "doc-1",
            "src/main.rs",
            1,
            5,
            AccessTier::Tier0Public.as_u8(),
            vec![0.1; 768],
            text,
            None,
        )
        .expect("Valid chunk");

        assert_eq!(chunk.blake3_hash, expected_hash);
        assert!(chunk.verify_hash());
        assert_eq!(chunk.access_tier_typed().unwrap(), AccessTier::Tier0Public);
    }

    #[test]
    fn test_document_chunk_invalid_line_range() {
        let err = DocumentChunk::new(
            "chunk-1",
            "doc-1",
            "src/main.rs",
            10,
            5, // invalid: start > end
            0,
            vec![0.0; 768],
            "invalid line numbers",
            None,
        );
        assert!(err.is_err());
        assert_eq!(
            err.unwrap_err(),
            TypeError::InvalidLineRange { start: 10, end: 5 }
        );
    }

    #[test]
    fn test_scored_chunk_to_citation() {
        let text = "Line 1: System initialization\nLine 2: Quorum verified.";
        let chunk = DocumentChunk::new(
            "chunk-123",
            "doc-456",
            "crates/core/src/init.rs",
            10,
            12,
            1,
            vec![0.5; 768],
            text,
            None,
        )
        .unwrap();

        let scored = ScoredChunk::new(chunk, 0.94, "peer-alpha", true);
        let citation = scored.to_citation();

        assert_eq!(citation.peer_id, "peer-alpha");
        assert_eq!(citation.file_path, "crates/core/src/init.rs");
        assert_eq!(citation.line_start, 10);
        assert_eq!(citation.line_end, 12);
        assert!((citation.score - 0.94).abs() < 1e-5);
        assert_eq!(citation.snippet, text);
    }

    #[test]
    fn test_volatile_remote_chunk_zeroize_on_drop() {
        let dto = CandidateChunkDto {
            chunk_id: "c-1".to_string(),
            file_path: "secret.txt".to_string(),
            line_start: 1,
            line_end: 2,
            content: "SUPER_SECRET_PAYLOAD_TOKEN".to_string(),
            score: 0.99,
            access_tier: 2,
        };

        let mut volatile = dto.to_volatile_remote_chunk("peer-x");
        assert_eq!(volatile.content(), "SUPER_SECRET_PAYLOAD_TOKEN");

        // Manually trigger zeroize to verify mutation
        volatile.content.zeroize();
        assert!(volatile.content().is_empty() || volatile.content().chars().all(|c| c == '\0'));
    }

    #[test]
    fn test_federated_query_freshness_and_signing_bytes() {
        let req = FederatedQueryRequest {
            query_id: Uuid::new_v4(),
            sender_peer_id: "peer-123".to_string(),
            sender_pubkey: [1u8; 32],
            query_text: "What is QuorumRAG?".to_string(),
            embedding: vec![0.0; 768],
            top_k: 10,
            timestamp: Utc::now().timestamp(),
            signature: [0u8; 64],
        };

        // Fresh within 60s
        assert!(req.is_fresh(60).is_ok());

        // Stale request (e.g. 5 minutes ago)
        let mut stale_req = req.clone();
        stale_req.timestamp -= 300;
        assert!(stale_req.is_fresh(60).is_err());

        // Canonical bytes deterministic
        let bytes1 = req.canonical_signing_bytes();
        let bytes2 = req.canonical_signing_bytes();
        assert_eq!(bytes1, bytes2);
        assert_eq!(req.canonical_digest(), *blake3::hash(&bytes1).as_bytes());
    }

    #[test]
    fn test_json_serde_roundtrip() {
        let chunk = DocumentChunk::new(
            "c-42",
            "doc-1",
            "README.md",
            1,
            10,
            0,
            vec![0.123, 0.456],
            "# QuorumRAG",
            Some("{\"author\":\"alice\"}".to_string()),
        )
        .unwrap();

        let serialized = serde_json::to_string(&chunk).expect("serialize chunk");
        let deserialized: DocumentChunk =
            serde_json::from_str(&serialized).expect("deserialize chunk");

        assert_eq!(chunk, deserialized);
    }

    #[test]
    fn test_cache_telemetry_and_query_result_serde() {
        let telem = CacheTelemetry::new(true, 8, 2, 10, 50, 3);
        assert!(telem.cache_hit);
        assert_eq!(telem.hits, 8);
        assert_eq!(telem.misses, 2);
        assert!((telem.hit_rate - 0.8).abs() < 1e-5);
        assert_eq!(telem.cache_epoch, 3);

        // Verify QueryResult default deserialization without cache fields
        let json_str = r#"{
            "chunks": [],
            "synthesis_prompt": "hello",
            "execution_time_ms": 12,
            "sources_cited": []
        }"#;
        let qr: QueryResult = serde_json::from_str(json_str).expect("deserialize legacy QueryResult");
        assert!(!qr.cache_hit);
        assert_eq!(qr.cache_epoch, 0);

        let recache = RecacheResponse {
            status: "ok".to_string(),
            cache_epoch: 4,
            cleared_entries: 10,
            warmed_entries: 5,
            duration_ms: 22,
        };
        let recache_json = serde_json::to_string(&recache).unwrap();
        let recache_de: RecacheResponse = serde_json::from_str(&recache_json).unwrap();
        assert_eq!(recache, recache_de);
    }
}
