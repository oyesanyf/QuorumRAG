//! # `quorum-atlaskv`
//!
//! Pure-Rust Layer-1 integration of **AtlasKV** (*"Augmenting LLMs with Billion-Scale
//! Knowledge Graphs in 20GB VRAM"*, HKUST-KnowComp, ICLR 2026, MIT License) for QuorumRAG.
//!
//! ## Key Capabilities
//! - **KG2KV Extraction (`kg2kv`)**: Deterministic, character-span-grounded triple extraction
//!   normalized to `"the {relation} of {entity}"` keys with BLAKE3 deduplication, secret
//!   scrubbing, homonym work-cluster isolation, and fail-closed `artemis://` air-gap enforcement.
//! - **3-Level Hierarchical Centroid Index (`hierarchy`)**: Disk-backed IEEE-754 `f16` memmap
//!   vector shards + parallel Mini-Batch Spherical K-Means++ (`Root -> Inter1 -> Leaf`) scaling
//!   as $k_{\text{inter1}} = \lceil N^{2/3} \rceil$ and $k_{\text{root}} = \lceil N^{1/3} \rceil$.
//! - **Sublinear HiKVP Pruning (`hikvp`)**: Zero-allocation `f16 -> f32` leaf scoring with
//!   branchless fail-closed `access_tier` and normalized shared-folder pre-filtering.
//! - **Native AtlasKV Format Interop (`interop`)**: Pure-Rust NumPy `.npy` v1.0/v2.0 and
//!   `*_qkv.json` / `c2id` / `id2c` import & export with strict path-traversal containment.
//! - **Federated Mesh Centroid Routing**: Privacy-preserving `f16` Root centroid digests
//!   (`PeerCentroidSummary`) and `ZeroizeOnDrop` remote triple wrappers (`VolatileRemoteTriple`).

pub mod error;
pub mod hierarchy;
pub mod hikvp;
pub mod interop;
pub mod kg2kv;
pub mod types;

pub use error::AtlasKvError;
pub use hierarchy::AtlasKvStore;
pub use hikvp::format_grounded_kg_context;
pub use interop::{
    export_atlaskv_dataset, import_atlaskv_dataset, read_npy_2d_as_f32,
    validate_safe_relative_path, write_npy_f32, AtlasKvExportManifest, AtlasKvQkvItem,
};
pub use kg2kv::{scrub_sensitive_tokens, Kg2KvExtractor, Kg2KvExtractorConfig};
pub use types::{
    dot_f16_le, dot_f32, encode_f32_to_f16_le, l2_normalize_in_place, normalize_path_key,
    validate_access_tier, AtlasKvSettings, AtlasKvStoreStats, AtlasKvTreeConfig,
    CandidateKgTripleDto, HiKvpPruningTrace, KgSourceChunk, KgTripleRecord, PeerCentroidSummary,
    ScoredKgTriple, VolatileRemoteTriple,
};
