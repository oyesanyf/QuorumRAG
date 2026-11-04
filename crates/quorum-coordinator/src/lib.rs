pub mod acl;
pub mod agentic;
pub mod answer_orchestrator;
pub mod cache;
pub mod config;
pub mod coordinator;
pub mod crypto;
pub mod dlp_mesh;
pub mod error;
pub mod fusion;
pub mod hardware;
pub mod langextract;
pub mod mesh;
pub mod model_router;
pub mod offline_engine;
pub mod scatter_gather;
pub mod telemetry;
pub mod tpm;
pub mod types;
pub mod vision;
pub mod volatile;

pub use acl::{AccessTierPolicy, AttestationTier, PeerAclManager, PeerAttestationRecord};
pub use tpm::{
    compute_pcr_composite_digest, default_pcr_selection, extend_simulated_pcr_16,
    inspect_tpm_hardware, reset_simulated_pcr_16, simulated_pcr, TpmEkCertificate,
    TpmHardwareInspection, TpmOemVendor, PCR_APPLICATION_AUDIT, PCR_PLATFORM_FIRMWARE,
    PCR_SECURE_BOOT,
};
pub use agentic::{
    AgenticStateGraphRunner, ContinuationFacetExtractor, RewriteContinuationNode,
};
pub use cache::{
    derive_embedding_cache_key, derive_query_cache_key, normalize_text_for_caching,
    CachedQueryEntry, CacheManager, EmbeddingCache, QueryCache,
};
pub use config::CoordinatorConfig;
pub use coordinator::QueryCoordinator;
pub use crypto::{
    canonical_query_bytes, oracle_sign_query, oracle_verify_query, sign_query, sign_request,
    verify_query, verify_request,
};
pub use error::CoordinatorError;
pub use fusion::RrfCombiner;
pub use hardware::HardwareTelemetry;
pub use mesh::{
    LocalOnlyDispatcher, MeshQueryDispatcher, MockMeshDispatcher, MockRemotePeer,
    OsoosiMeshInboundHandler, SwarmMeshDispatcher,
};
pub use model_router::AutoFusionRouter;
pub use offline_engine::DeterministicOfflineSynthesisEngine;
pub use scatter_gather::{FederatedQueryCoordinator, ScatterGatherEngine, StorageSearcher};
pub use telemetry::AgenticTelemetryEvent;
pub use types::{
    AgenticGraphState, AgenticStateName, ChatTurnMessage, QueryIntentType, RelevanceGrade,
    SynthesisModelFamily,
};
pub use volatile::{scrub_volatile, wrap_candidates, VolatileRemoteChunk};
pub use langextract::{
    extract_query_metadata_filters, filter_grounded, ground_extraction, ConsensusExtractionResult,
    ExampleData, Extraction, LlmFusionArmReport, LlmFusionConsensus,
};
pub use dlp_mesh::{
    global_mesh_dlp_controller, ArchivedChatEntry, ChatGptUiSettings, DetectedPhiSpan,
    DlpAuditEvent, DlpEnforcementMode, DlpInspectionResult, DlpTelemetryStats, MeshDlpPolicy,
    OsoosiMeshDlpController, OsoosiMeshSettings, PersistedDaemonSettings, SharedFolderEntry,
    UiPreferencesConfig,
};
