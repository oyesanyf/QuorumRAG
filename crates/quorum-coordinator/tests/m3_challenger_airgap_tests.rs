//! Empirical Adversarial Challenger Tests for Milestone 3: P2P Mesh Airgap.
//!
//! Stress-tests and challenges the hard P2P mesh airgap in `crates/quorum-coordinator`:
//! 1. Inbound query gauntlet (mixed-case, percent-encoded, backslash, prefix/suffix variations).
//! 2. Candidate chunk isolation (`Tier3Restricted`, `artemis_dfir: true`, `mesh_sharable: false`)
//!    even when `require_explicit_folder_share = false`.
//! 3. Outbound scatter-gather query suppression.
//! 4. Byzantine peer response dropping on ingestion.
//! 5. Settings fail-closed default invariants.

use chrono::Utc;
use quorum_coordinator::artemis_airgap::*;
use quorum_coordinator::crypto::sign_request;
use quorum_coordinator::dlp_mesh::{
    global_mesh_dlp_controller, OsoosiMeshDlpController, PersistedDaemonSettings,
};
use quorum_coordinator::mesh::{OsoosiMeshInboundHandler, SwarmMeshDispatcher};
use quorum_coordinator::scatter_gather::StorageSearcher;
use quorum_coordinator::MeshQueryDispatcher;
use quorum_network::{
    load_or_generate_node_seed, start_network_node,
    InboundQueryHandler, NetworkConfig,
};
use quorum_types::{
    AccessTier, CandidateChunkDto, DocumentChunk, FederatedQueryRequest, ScoredChunk,
    VolatileRemoteChunk,
};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use uuid::Uuid;

/// Mock storage populated with both sensitive Artemis DFIR records and benign public records
/// to verify airgap filtration under adversarial queries.
struct AdversarialMockStorage;

#[async_trait::async_trait]
impl StorageSearcher for AdversarialMockStorage {
    async fn search_hybrid(
        &self,
        _query_text: &str,
        _query_vec: &[f32],
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        let artemis_chunk_1 = DocumentChunk::new(
            "artemis_chunk_001",
            "artemis_doc_1",
            "artemis://windows/eventlog/security/4688",
            1,
            20,
            AccessTier::Tier3Restricted.as_u8(),
            vec![0.05; 768],
            "CommandLine: powershell.exe -enc <sensitive_payload>",
            Some(r#"{"artemis_dfir": true, "mesh_sharable": false}"#.to_string()),
        )
        .unwrap();

        let artemis_chunk_2 = DocumentChunk::new(
            "artemis_chunk_002",
            "artemis_doc_2",
            "artemis://macos/unified_log/audit",
            1,
            15,
            AccessTier::Tier0Public.as_u8(), // Intentionally Tier 0 to verify URI-based airgap block!
            vec![0.05; 768],
            "process execution event payload",
            Some(r#"{"artemis_dfir": true}"#.to_string()),
        )
        .unwrap();

        let benign_chunk = DocumentChunk::new(
            "benign_chunk_001",
            "benign_doc_1",
            "C:\\SharedFolder\\public_whitepaper.pdf",
            1,
            50,
            AccessTier::Tier0Public.as_u8(),
            vec![0.05; 768],
            "Public whitepaper discussing distributed consensus.",
            Some(r#"{"artemis_dfir": false, "mesh_sharable": true}"#.to_string()),
        )
        .unwrap();

        vec![
            ScoredChunk::new(artemis_chunk_1, 0.99, "local", false),
            ScoredChunk::new(artemis_chunk_2, 0.95, "local", false),
            ScoredChunk::new(benign_chunk, 0.80, "local", false),
        ]
    }

    async fn search_text(
        &self,
        _query: &str,
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        Vec::new()
    }
}

/// Helper to generate authentic signed FederatedQueryRequest
fn make_signed_request(
    seed: &[u8; 32],
    query_text: &str,
    tier: AccessTier,
) -> FederatedQueryRequest {
    let secret = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(*seed).unwrap();
    let kp = quorum_network::libp2p::identity::ed25519::Keypair::from(secret);
    let peer_id = quorum_network::libp2p::identity::Keypair::from(kp.clone())
        .public()
        .to_peer_id()
        .to_string();

    let mut req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: peer_id,
        sender_pubkey: [0u8; 32],
        query_text: query_text.to_string(),
        embedding: vec![0.05; 768],
        top_k: 10,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
        origin_peer_id: None,
        relay_hops: 0,
        visited_peers: Vec::new(),
    };
    sign_request(seed, &mut req, tier);
    req
}

/// EMPIRICAL TEST 1: Inbound Query Gauntlet
/// Challenges inbound queries across mixed case, prefix/suffix, brackets,
/// and URL encoded variations. Asserts that ZERO artemis chunks ever leak
/// and direct artemis:// queries are strictly rejected with empty results.
#[tokio::test]
async fn test_adversarial_inbound_queries_artemis_gauntlet() {
    let temp = tempfile::tempdir().unwrap();
    let node_seed = load_or_generate_node_seed(temp.path()).unwrap();

    // Enable mesh with wide open folder sharing (require_explicit_folder_share = false)
    {
        let ctrl = global_mesh_dlp_controller();
        let mut s = ctrl.settings.write().unwrap();
        s.mesh.p2p_enabled = true;
        s.mesh.require_explicit_folder_share = false;
        s.ui.default_peer_access_tier = 3; // Allow up to tier 3 to test airgap override!
    }

    let storage = Arc::new(AdversarialMockStorage);
    let handler = OsoosiMeshInboundHandler::new(storage, "12D3KooWReceiverChallenger".to_string());

    let test_queries = [
        // Standard lowercase
        "artemis://windows/eventlog/security/4688",
        // Mixed case variations
        "ARTEMIS://windows/eventlog/security/4688",
        "ArTeMiS://macos/unified_log",
        "aRTEmIs://linux/auditd",
        // Prefix and suffix variations
        "prefix query text artemis://windows/eventlog",
        "artemis://windows/eventlog with trailing search params",
        "select * from [artemis://registry/run] where key='test'",
        "\"artemis://windows/sysmon\"",
        // Raw scheme
        "artemis://",
        "ARTEMIS://",
    ];

    for query in &test_queries {
        let req = make_signed_request(&node_seed, query, AccessTier::Tier3Restricted);
        let resp = handler.handle_query(req).await;

        // 1. Direct artemis queries must be 100% rejected immediately at step 1b
        assert!(
            resp.chunks.is_empty(),
            "Query '{}' referencing artemis:// must be completely rejected with 0 chunks, got {}",
            query,
            resp.chunks.len()
        );

        // 2. Direct verification of contains_artemis_query
        assert!(
            contains_artemis_query(query),
            "contains_artemis_query must return true for '{}'",
            query
        );
    }

    // Now test URL-encoded and alternate path representations:
    // Even if an attacker encodes characters or queries arbitrary text,
    // NO artemis chunks can EVER cross the boundary to the responder!
    let encoded_or_obfuscated = [
        "artemis%3A%2F%2Fwindows/eventlog",
        "artemis%3a%2f%2fwindows/eventlog",
        "ARTEMIS%3A%2F%2Fwindows/eventlog",
        "artemis%3A//windows/eventlog",
        "artemis:%2F%2Fwindows/eventlog",
        "find all events matching artemis",
        "show me everything in storage",
    ];

    for query in &encoded_or_obfuscated {
        let req = make_signed_request(&node_seed, query, AccessTier::Tier3Restricted);
        let resp = handler.handle_query(req).await;

        // CRITICAL INVARIANT: Zero artemis chunks may EVER be returned!
        for chunk in &resp.chunks {
            assert!(
                !is_artemis_uri(&chunk.file_path),
                "LEAK DETECTED: Handler returned artemis URI '{}' for query '{}'",
                chunk.file_path,
                query
            );
            assert!(
                chunk.access_tier < AccessTier::Tier3Restricted.as_u8(),
                "LEAK DETECTED: Handler returned Tier3Restricted chunk '{}' for query '{}'",
                chunk.chunk_id,
                query
            );
        }
    }
}

/// EMPIRICAL TEST 2: Candidate Chunks Isolation Under Wide Open Folder Sharing
/// Tests that candidate chunks with `access_tier = 3` (`Tier3Restricted`),
/// `artemis_dfir: true`, or `mesh_sharable: false` are 100% blocked from outbound
/// responses even when `require_explicit_folder_share = false`.
#[test]
fn test_adversarial_candidate_chunks_isolation_wide_open_share() {
    let controller = OsoosiMeshDlpController {
        settings: RwLock::new(PersistedDaemonSettings {
            mesh: quorum_coordinator::OsoosiMeshSettings {
                p2p_enabled: true,
                require_explicit_folder_share: false, // WIDE OPEN sharing
                shared_folders: Vec::new(),
                ..Default::default()
            },
            ..Default::default()
        }),
        stats: RwLock::new(Default::default()),
        settings_file_path: RwLock::new(None),
        hmac_secret: [0u8; 32],
    };

    // 1. check_file_shared_with_mesh MUST reject artemis:// unconditionally
    let artemis_paths = [
        "artemis://windows/eventlog/security/4688",
        "ARTEMIS://macos/unified_log",
        "  artemis://linux/journald  ",
        "prefix/artemis://nested/uri",
    ];
    for path in &artemis_paths {
        assert!(
            controller.check_file_shared_with_mesh(path).is_none(),
            "check_file_shared_with_mesh must reject '{}' even when require_explicit_folder_share is false",
            path
        );
        assert!(
            is_artemis_uri(path),
            "is_artemis_uri must return true for '{}'",
            path
        );
    }

    // 2. Comprehensive CandidateChunkDto filter gauntlet
    let candidate_dtos = vec![
        // Benign public chunk (should pass)
        CandidateChunkDto {
            chunk_id: "public_chunk_1".to_string(),
            file_path: "C:\\public\\guide.txt".to_string(),
            line_start: 1,
            line_end: 20,
            content: "Benign documentation text".to_string(),
            score: 0.95,
            access_tier: AccessTier::Tier0Public.as_u8(),
            origin_peer_id: None,
        },
        // Artemis URI with Tier 0 (MUST BE BLOCKED)
        CandidateChunkDto {
            chunk_id: "artemis_dto_1".to_string(),
            file_path: "artemis://windows/eventlog/4688".to_string(),
            line_start: 1,
            line_end: 20,
            content: "cmdline: net user evil /add".to_string(),
            score: 0.99,
            access_tier: AccessTier::Tier0Public.as_u8(),
            origin_peer_id: None,
        },
        // Artemis URI uppercase with Tier 0 (MUST BE BLOCKED)
        CandidateChunkDto {
            chunk_id: "artemis_dto_2".to_string(),
            file_path: "ARTEMIS://macos/unified_log".to_string(),
            line_start: 1,
            line_end: 15,
            content: "sudo execution telemetry".to_string(),
            score: 0.92,
            access_tier: AccessTier::Tier0Public.as_u8(),
            origin_peer_id: None,
        },
        // Tier3Restricted with benign path (MUST BE BLOCKED)
        CandidateChunkDto {
            chunk_id: "tier3_dto_1".to_string(),
            file_path: "C:\\public\\top_secret.txt".to_string(),
            line_start: 1,
            line_end: 10,
            content: "Top secret internal notes".to_string(),
            score: 0.91,
            access_tier: AccessTier::Tier3Restricted.as_u8(),
            origin_peer_id: None,
        },
        // Tier 4 (above Tier 3) with benign path (MUST BE BLOCKED)
        CandidateChunkDto {
            chunk_id: "tier4_dto_1".to_string(),
            file_path: "C:\\public\\tier4.txt".to_string(),
            line_start: 1,
            line_end: 10,
            content: "Super secret tier 4".to_string(),
            score: 0.90,
            access_tier: 4,
            origin_peer_id: None,
        },
    ];

    let filtered = controller.filter_and_enforce_outbound_mesh_chunks(candidate_dtos, "peer_challenger");
    assert_eq!(
        filtered.len(),
        1,
        "Exactly 1 chunk (the public one) must pass outbound filter, but got {}",
        filtered.len()
    );
    assert_eq!(filtered[0].chunk_id, "public_chunk_1");

    // 3. DocumentChunk predicate gauntlet (checks artemis_dfir and mesh_sharable flags in metadata_json)
    let doc_chunks = [
        // artemis_dfir: true (MUST BE BLOCKED)
        (
            DocumentChunk::new(
                "doc_1", "d1", "C:\\normal\\file1.txt", 1, 5, 0,
                vec![0.0; 768], "content",
                Some(r#"{"artemis_dfir": true}"#.to_string()),
            ).unwrap(),
            true, // restricted
        ),
        // mesh_sharable: false (MUST BE BLOCKED)
        (
            DocumentChunk::new(
                "doc_2", "d2", "C:\\normal\\file2.txt", 1, 5, 0,
                vec![0.0; 768], "content",
                Some(r#"{"mesh_sharable": false}"#.to_string()),
            ).unwrap(),
            true, // restricted
        ),
        // both artemis_dfir: true and mesh_sharable: false (MUST BE BLOCKED)
        (
            DocumentChunk::new(
                "doc_3", "d3", "C:\\normal\\file3.txt", 1, 5, 0,
                vec![0.0; 768], "content",
                Some(r#"{"artemis_dfir": true, "mesh_sharable": false}"#.to_string()),
            ).unwrap(),
            true, // restricted
        ),
        // artemis_dfir: false and mesh_sharable: false (MUST BE BLOCKED)
        (
            DocumentChunk::new(
                "doc_4", "d4", "C:\\normal\\file4.txt", 1, 5, 0,
                vec![0.0; 768], "content",
                Some(r#"{"artemis_dfir": false, "mesh_sharable": false}"#.to_string()),
            ).unwrap(),
            true, // restricted
        ),
        // access_tier = 3 (MUST BE BLOCKED regardless of metadata)
        (
            DocumentChunk::new(
                "doc_5", "d5", "C:\\normal\\file5.txt", 1, 5, 3,
                vec![0.0; 768], "content",
                Some(r#"{"artemis_dfir": false, "mesh_sharable": true}"#.to_string()),
            ).unwrap(),
            true, // restricted
        ),
        // artemis:// path (MUST BE BLOCKED regardless of metadata and tier 0)
        (
            DocumentChunk::new(
                "doc_6", "d6", "artemis://linux/journald", 1, 5, 0,
                vec![0.0; 768], "content",
                Some(r#"{"artemis_dfir": false, "mesh_sharable": true}"#.to_string()),
            ).unwrap(),
            true, // restricted
        ),
        // benign chunk: tier 0, clean path, mesh_sharable: true (MUST BE ALLOWED)
        (
            DocumentChunk::new(
                "doc_safe", "dsafe", "C:\\normal\\safe.txt", 1, 5, 0,
                vec![0.0; 768], "content",
                Some(r#"{"artemis_dfir": false, "mesh_sharable": true}"#.to_string()),
            ).unwrap(),
            false, // NOT restricted
        ),
    ];

    for (chunk, expected_restricted) in &doc_chunks {
        let is_restricted = is_airgap_restricted_chunk(chunk);
        assert_eq!(
            is_restricted, *expected_restricted,
            "Chunk '{}' restriction expectation failed: expected={}, got={}",
            chunk.chunk_id, expected_restricted, is_restricted
        );
    }
}

/// EMPIRICAL TEST 3: Outbound Scatter-Gather Query Suppression
/// Tests that outbound scatter-gather queries mentioning `artemis://`
/// are 100% suppressed from remote P2P dispatch.
#[tokio::test]
async fn test_adversarial_outbound_scatter_gather_suppression() {
    let controller = global_mesh_dlp_controller();

    // 1. sanitize_outbound_query suppression check
    let outbound_queries_artemis = [
        "Search artemis://windows/eventlog for cmdline",
        "ARTEMIS://macos/unified_log query",
        "find evidence in artemis://sysmon/1",
        "artemis://",
    ];

    for query in &outbound_queries_artemis {
        let sanitized = controller.sanitize_outbound_query(query);
        assert!(
            sanitized.is_none(),
            "Outbound query '{}' mentioning artemis:// MUST be suppressed (return None), but got {:?}",
            query,
            sanitized
        );
    }

    // Standard benign queries must pass sanitize_outbound_query
    let benign_query = "What is the consensus algorithm in quorum-coordinator?";
    let sanitized_benign = controller.sanitize_outbound_query(benign_query);
    assert!(
        sanitized_benign.is_some(),
        "Benign query '{}' must not be suppressed",
        benign_query
    );

    // 2. SwarmMeshDispatcher suppression check
    let config = NetworkConfig::new_localhost();
    let (_jh, handle) = start_network_node(config, None).await.unwrap();
    let dispatcher = SwarmMeshDispatcher::new(handle);
    let temp = tempfile::tempdir().unwrap();
    let seed = load_or_generate_node_seed(temp.path()).unwrap();
    let req = make_signed_request(&seed, "Search artemis://windows/registry", AccessTier::Tier0Public);

    let (responses, diagnostics) = dispatcher
        .query_peers_with_diagnostics(&req, Duration::from_millis(500))
        .await
        .expect("query_peers_with_diagnostics should succeed with empty results");

    assert!(
        responses.is_empty(),
        "SwarmMeshDispatcher must return 0 peer responses when query contains artemis://"
    );
    assert!(
        diagnostics
            .summary_reason
            .as_ref()
            .map(|r| r.contains("artemis://"))
            .unwrap_or(false),
        "Diagnostics summary must explain airgap suppression reason, got: {:?}",
        diagnostics.summary_reason
    );
}

/// EMPIRICAL TEST 4: Byzantine Peer Responses Dropping on Ingestion
/// Tests that byzantine peer responses returning `artemis://` chunks are 100% dropped on ingestion.
#[test]
fn test_adversarial_byzantine_peer_response_dropping() {
    let controller = OsoosiMeshDlpController {
        settings: RwLock::new(PersistedDaemonSettings {
            mesh: quorum_coordinator::OsoosiMeshSettings {
                p2p_enabled: true,
                require_explicit_folder_share: false,
                shared_folders: Vec::new(),
                ..Default::default()
            },
            ..Default::default()
        }),
        stats: RwLock::new(Default::default()),
        settings_file_path: RwLock::new(None),
        hmac_secret: [0u8; 32],
    };

    // Byzantine peer attempts to inject airgapped/forensic telemetry into our local context
    let byzantine_chunks = vec![
        VolatileRemoteChunk {
            chunk_id: "byzantine_chunk_1".to_string(),
            file_path: "artemis://victim_machine/eventlog/security".to_string(),
            line_start: 1,
            line_end: 10,
            content: "Leaked host eventlog telemetry".to_string(),
            score: 0.99,
            peer_id: "12D3KooWByzantinePeerAlpha".to_string(),
            access_tier: 0,
        },
        VolatileRemoteChunk {
            chunk_id: "byzantine_chunk_2".to_string(),
            file_path: "ARTEMIS://victim_machine/macos/unified_log".to_string(),
            line_start: 1,
            line_end: 5,
            content: "Leaked macos telemetry".to_string(),
            score: 0.98,
            peer_id: "12D3KooWByzantinePeerBeta".to_string(),
            access_tier: 0,
        },
        VolatileRemoteChunk {
            chunk_id: "byzantine_chunk_3".to_string(),
            file_path: "prefix/artemis://nested".to_string(),
            line_start: 1,
            line_end: 5,
            content: "Leaked nested artemis telemetry".to_string(),
            score: 0.97,
            peer_id: "12D3KooWByzantinePeerGamma".to_string(),
            access_tier: 0,
        },
        VolatileRemoteChunk {
            chunk_id: "legitimate_peer_chunk".to_string(),
            file_path: "C:\\shared\\peer_analysis.md".to_string(),
            line_start: 1,
            line_end: 25,
            content: "Clean peer analysis notes on network architecture".to_string(),
            score: 0.85,
            peer_id: "12D3KooWHonestPeer".to_string(),
            access_tier: 0,
        },
    ];

    let sanitized = controller.enforce_inbound_remote_chunks(byzantine_chunks);
    assert_eq!(
        sanitized.len(),
        1,
        "All 3 byzantine artemis:// chunks must be dropped on ingestion; only the legitimate chunk may survive, but got {}",
        sanitized.len()
    );
    assert_eq!(sanitized[0].chunk_id, "legitimate_peer_chunk");
    assert_eq!(sanitized[0].peer_id, "12D3KooWHonestPeer");

    // Also verify CandidateChunkDto representation for Byzantine chunks in scatter_gather
    let byzantine_dto_artemis = CandidateChunkDto {
        chunk_id: "b_dto_1".to_string(),
        file_path: "artemis://byzantine/leak".to_string(),
        line_start: 1,
        line_end: 10,
        content: "leaked".to_string(),
        score: 0.99,
        access_tier: 0,
        origin_peer_id: None,
    };
    assert!(
        is_airgap_restricted_chunk_dto(&byzantine_dto_artemis),
        "Byzantine DTO with artemis:// must be flagged as restricted"
    );

    let byzantine_dto_tier3 = CandidateChunkDto {
        chunk_id: "b_dto_2".to_string(),
        file_path: "C:\\shared\\file.txt".to_string(),
        line_start: 1,
        line_end: 10,
        content: "leaked restricted tier".to_string(),
        score: 0.99,
        access_tier: AccessTier::Tier3Restricted.as_u8(),
        origin_peer_id: None,
    };
    assert!(
        is_airgap_restricted_chunk_dto(&byzantine_dto_tier3),
        "Byzantine DTO with Tier3Restricted must be flagged as restricted"
    );
}

/// EMPIRICAL TEST 5: Artemis Settings Fail-Closed Security Invariants
/// Tests that Artemis configuration defaults to completely disabled for both
/// local collection and marketplace harvest, with all defensive invariants intact.
#[test]
fn test_adversarial_settings_fail_closed_invariants() {
    let settings = ArtemisDfirSettings::default();

    // 1. Invariant: Master toggle, local collection, and marketplace harvest must all default to FALSE
    assert!(!settings.enabled, "Master toggle must default to false");
    assert!(!settings.local_collection_enabled, "Local collection must default to false");
    assert!(!settings.marketplace_harvest_enabled, "Marketplace harvest must default to false");

    // 2. Invariant: Auto collection must be disabled (interval = 0)
    assert_eq!(settings.auto_collection_interval_mins, 0, "Auto collection interval must be 0");

    // 3. Invariant: Redaction and normalization must default to true
    assert!(settings.redact_secrets, "Secret redaction must default to true");
    assert!(settings.normalize_for_harvest, "Normalization for harvest must default to true");

    // 4. Invariant: Prohibited categories must NEVER appear in allowed categories
    let allowed = &settings.allowed_artifact_categories;
    for prohibited in prohibited_categories() {
        assert!(
            !allowed.contains(&prohibited.to_string()),
            "Prohibited category '{}' must NOT be in default allowed categories",
            prohibited
        );
    }

    // 5. Invariant: Deserializing empty JSON `{}` must produce identical fail-closed defaults
    let empty_json = "{}";
    let deser: ArtemisDfirSettings = serde_json::from_str(empty_json).expect("deserialize empty json");
    assert_eq!(deser, settings, "Empty JSON must produce identical fail-closed defaults");
}

/// Storage mock holding strictly Artemis DFIR forensic records.
struct PureArtemisStorage;

#[async_trait::async_trait]
impl StorageSearcher for PureArtemisStorage {
    async fn search_hybrid(
        &self,
        _query_text: &str,
        _query_vec: &[f32],
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        let chunk1 = DocumentChunk::new(
            "pure_artemis_1",
            "artemis_d1",
            "artemis://windows/registry/run",
            1,
            10,
            3,
            vec![0.01; 768],
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            Some(r#"{"artemis_dfir": true}"#.to_string()),
        ).unwrap();

        let chunk2 = DocumentChunk::new(
            "pure_artemis_2",
            "artemis_d2",
            "artemis://linux/proc/cmdline",
            1,
            5,
            0, // Even if access tier is marked 0
            vec![0.01; 768],
            "sensitive cmdline args",
            Some(r#"{"mesh_sharable": false}"#.to_string()),
        ).unwrap();

        vec![
            ScoredChunk::new(chunk1, 0.99, "local", false),
            ScoredChunk::new(chunk2, 0.95, "local", false),
        ]
    }

    async fn search_text(
        &self,
        _query: &str,
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        Vec::new()
    }
}

/// EMPIRICAL TEST 6: Pure Artemis Storage Defense Gauntlet
/// In a workstation or node with pure Artemis DFIR records indexed,
/// ANY peer query (whether requesting benign terms, wildcards, URL-encoded artemis,
/// or raw SQL) MUST return exactly 0 chunks. 100% rejection/empty chunks.
#[tokio::test]
async fn test_adversarial_pure_artemis_storage_returns_empty_chunks_for_any_query() {
    let temp = tempfile::tempdir().unwrap();
    let node_seed = load_or_generate_node_seed(temp.path()).unwrap();

    let storage = Arc::new(PureArtemisStorage);
    let handler = OsoosiMeshInboundHandler::new(storage, "12D3KooWPureArtemisGuardian".to_string());

    // Configure DLP controller for wide open sharing to prove that airgap overrides sharing
    {
        let ctrl = global_mesh_dlp_controller();
        let mut s = ctrl.settings.write().unwrap();
        s.mesh.p2p_enabled = true;
        s.mesh.require_explicit_folder_share = false;
        s.ui.default_peer_access_tier = 3;
    }

    let probe_queries = [
        "artemis://windows/registry/run",
        "ARTEMIS://windows/registry/run",
        "artemis%3A%2F%2Fwindows/registry/run",
        "artemis%3a%2f%2fwindows/registry/run",
        "artemis:\\windows\\registry\\run",
        "artemis:/windows/registry/run",
        "SELECT * FROM *",
        "find all run keys",
        "show me everything",
        "",
        "   ",
        "a",
        "powershell",
        "cmdline",
    ];

    for query in &probe_queries {
        let req = make_signed_request(&node_seed, query, AccessTier::Tier3Restricted);
        let resp = handler.handle_query(req).await;

        assert!(
            resp.chunks.is_empty(),
            "Pure Artemis storage leaked chunks for query '{}': got {} chunks",
            query,
            resp.chunks.len()
        );
    }
}

/// EMPIRICAL TEST 7: Exhaustive Airgap Restriction Matrix
/// Stress-tests every edge case of DocumentChunk and CandidateChunkDto
/// for access tier boundaries, corrupted metadata, missing fields, and case folding.
#[test]
fn test_adversarial_airgap_restriction_matrix() {
    // 1. All tiers >= 3 must be restricted
    for tier in 3..=255u8 {
        let dto = CandidateChunkDto {
            chunk_id: format!("tier_test_{tier}"),
            file_path: "C:\\benign\\doc.txt".to_string(),
            line_start: 1,
            line_end: 10,
            content: "content".to_string(),
            score: 0.5,
            access_tier: tier,
            origin_peer_id: None,
        };
        assert!(
            is_airgap_restricted_chunk_dto(&dto),
            "CandidateChunkDto with access_tier {} must be restricted",
            tier
        );
    }

    // 2. Tiers 0, 1, 2 with benign path must not be restricted
    for tier in 0..=2u8 {
        let dto = CandidateChunkDto {
            chunk_id: format!("tier_safe_{tier}"),
            file_path: "C:\\benign\\doc.txt".to_string(),
            line_start: 1,
            line_end: 10,
            content: "content".to_string(),
            score: 0.5,
            access_tier: tier,
            origin_peer_id: None,
        };
        assert!(
            !is_airgap_restricted_chunk_dto(&dto),
            "CandidateChunkDto with access_tier {} and benign path must NOT be restricted",
            tier
        );
    }

    // 3. Any tier with artemis:// path must be restricted
    for tier in 0..=2u8 {
        let dto = CandidateChunkDto {
            chunk_id: format!("artemis_tier_{tier}"),
            file_path: "artemis://test".to_string(),
            line_start: 1,
            line_end: 10,
            content: "content".to_string(),
            score: 0.5,
            access_tier: tier,
            origin_peer_id: None,
        };
        assert!(
            is_airgap_restricted_chunk_dto(&dto),
            "CandidateChunkDto with artemis:// path must be restricted regardless of tier {}",
            tier
        );
    }

    // 4. Corrupted or malicious JSON metadata handling in DocumentChunk
    let malformed_metadata = [
        "not valid json {{{",
        "",
        "null",
        "42",
        "[]",
        r#"{"artemis_dfir": "not_a_bool"}"#,
        r#"{"mesh_sharable": "not_a_bool"}"#,
    ];

    for bad_meta in &malformed_metadata {
        // Safe chunk with malformed JSON and tier 0 -> allowed (fail-open for non-artemis metadata error)
        let safe_doc = DocumentChunk::new(
            "malformed_safe", "doc", "C:\\safe.txt", 1, 5, 0,
            vec![0.0; 768], "text", Some(bad_meta.to_string()),
        ).unwrap();
        assert!(
            !is_airgap_restricted_chunk(&safe_doc),
            "Malformed metadata on benign path should not trigger artemis airgap"
        );

        // Artemis chunk with malformed JSON -> must still be blocked by path
        let artemis_doc = DocumentChunk::new(
            "malformed_artemis", "doc", "artemis://test", 1, 5, 0,
            vec![0.0; 768], "text", Some(bad_meta.to_string()),
        ).unwrap();
        assert!(
            is_airgap_restricted_chunk(&artemis_doc),
            "Artemis path must be blocked even if metadata JSON is malformed"
        );

        // Tier 3 chunk with malformed JSON -> must still be blocked by tier
        let tier3_doc = DocumentChunk::new(
            "malformed_tier3", "doc", "C:\\safe.txt", 1, 5, 3,
            vec![0.0; 768], "text", Some(bad_meta.to_string()),
        ).unwrap();
        assert!(
            is_airgap_restricted_chunk(&tier3_doc),
            "Tier 3 must be blocked even if metadata JSON is malformed"
        );
    }
}

/// EMPIRICAL TEST 8: Windows Backslash and Percent-Encoded URI Gauntlet
/// Stress-tests `is_artemis_uri` and `contains_artemis_query` against all Windows
/// backslash (`artemis:\\`, `artemis:\`) and percent-encoded variations (`artemis%3a%5c%5c`,
/// `artemis%3a//`, `artemis%3a\\`, `artemis%3a/`, `artemis%3a\`, etc.).
#[test]
fn test_adversarial_windows_backslash_and_percent_encoded_uri_gauntlet() {
    let test_uris = [
        // Windows backslash standard and mixed case
        "artemis:\\windows\\eventlog\\security\\4688",
        "ARTEMIS:\\windows\\eventlog\\security\\4688",
        "ArTeMiS:\\registry\\hklm",
        "artemis:\\",
        "ARTEMIS:\\",
        // Single backslash / colon variants
        "artemis:\\windows",
        "artemis:\\\\network\\share",
        "artemis:windows\\evtx",
        // Percent-encoded variations (both lower and uppercase hex)
        "artemis%3a%2f%2fwindows/eventlog",
        "artemis%3A%2F%2Fwindows/eventlog",
        "artemis%3a%5c%5cwindows\\eventlog",
        "artemis%3A%5C%5Cwindows\\eventlog",
        // Hybrid percent-encoded colon with literal slashes/backslashes
        "artemis%3a//windows/eventlog",
        "artemis%3A//windows/eventlog",
        "artemis%3a\\\\windows\\eventlog",
        "artemis%3A\\\\windows\\eventlog",
        "artemis%3a/windows",
        "artemis%3a\\windows",
        // Nested inside other URIs or paths
        "C:\\malicious\\artemis:\\nested",
        "file:///host/artemis%3a%5c%5cpayload",
        "smb://share/artemis%3a//leak",
    ];

    for uri in &test_uris {
        assert!(
            is_artemis_uri(uri),
            "FAIL-CLOSED VIOLATION: is_artemis_uri returned false for URI '{}'",
            uri
        );
    }

    let test_queries = [
        "artemis:\\windows\\eventlog\\security\\4688",
        "ARTEMIS:\\windows\\eventlog",
        "select * from artemis:\\registry",
        "artemis:\\",
        "artemis%3a%2f%2fwindows",
        "artemis%3A%2F%2Fwindows",
        "artemis%3a%5c%5cwindows",
        "artemis%3A%5C%5Cwindows",
        "artemis%3a//windows",
        "artemis%3a\\\\windows",
        "artemis%3a/windows",
        "artemis%3a\\windows",
        "query targeting artemis:\\windows\\sysmon",
        "query with artemis%3a%5c%5cpayload",
    ];

    for query in &test_queries {
        assert!(
            contains_artemis_query(query),
            "FAIL-CLOSED VIOLATION: contains_artemis_query returned false for query '{}'",
            query
        );
    }
}

/// EMPIRICAL TEST 9: Windows Backslash and Percent-Encoded Outbound Suppression & Inbound Rejection
/// Verifies that:
/// 1. Outbound queries with Windows backslashes and percent encoding are suppressed (return None).
/// 2. Inbound queries with Windows backslashes and percent encoding return 0 chunks immediately.
/// 3. Inbound chunks with Windows backslashes and percent encoding from peers are dropped.
#[tokio::test]
async fn test_adversarial_windows_backslash_and_percent_encoded_mesh_pipeline() {
    let controller = global_mesh_dlp_controller();
    let temp = tempfile::tempdir().unwrap();
    let node_seed = load_or_generate_node_seed(temp.path()).unwrap();

    let adversarial_queries = [
        "artemis:\\windows\\eventlog\\security",
        "ARTEMIS:\\system32\\winevt",
        "artemis%3a%5c%5cwindows\\eventlog",
        "artemis%3A%5C%5Cwindows\\eventlog",
        "artemis%3a//windows/eventlog",
        "artemis%3a\\\\windows\\eventlog",
        "search artemis:\\windows\\registry for Run",
    ];

    // 1. Outbound query suppression
    for query in &adversarial_queries {
        let sanitized = controller.sanitize_outbound_query(query);
        assert!(
            sanitized.is_none(),
            "FAIL-CLOSED VIOLATION: sanitize_outbound_query allowed query '{}'",
            query
        );
    }

    // 2. Inbound query rejection
    let storage = Arc::new(AdversarialMockStorage);
    let handler = OsoosiMeshInboundHandler::new(storage, "12D3KooWWindowsAirgapTester".to_string());

    for query in &adversarial_queries {
        let req = make_signed_request(&node_seed, query, AccessTier::Tier3Restricted);
        let resp = handler.handle_query(req).await;
        assert!(
            resp.chunks.is_empty(),
            "FAIL-CLOSED VIOLATION: Inbound query '{}' was not rejected, returned {} chunks",
            query,
            resp.chunks.len()
        );
    }

    // 3. Inbound remote chunks dropping (Byzantine peer sending Windows/percent-encoded URIs)
    let peer_chunks = vec![
        VolatileRemoteChunk {
            chunk_id: "chunk_win_1".to_string(),
            file_path: "artemis:\\windows\\eventlog\\security".to_string(),
            line_start: 1,
            line_end: 10,
            content: "payload".to_string(),
            score: 0.99,
            peer_id: "12D3KooWPeer1".to_string(),
            access_tier: 0,
        },
        VolatileRemoteChunk {
            chunk_id: "chunk_win_2".to_string(),
            file_path: "artemis%3a%5c%5cwindows\\eventlog".to_string(),
            line_start: 1,
            line_end: 10,
            content: "payload".to_string(),
            score: 0.99,
            peer_id: "12D3KooWPeer2".to_string(),
            access_tier: 0,
        },
        VolatileRemoteChunk {
            chunk_id: "chunk_win_3".to_string(),
            file_path: "artemis%3a//windows/eventlog".to_string(),
            line_start: 1,
            line_end: 10,
            content: "payload".to_string(),
            score: 0.99,
            peer_id: "12D3KooWPeer3".to_string(),
            access_tier: 0,
        },
        VolatileRemoteChunk {
            chunk_id: "chunk_win_4".to_string(),
            file_path: "artemis%3a\\\\windows\\eventlog".to_string(),
            line_start: 1,
            line_end: 10,
            content: "payload".to_string(),
            score: 0.99,
            peer_id: "12D3KooWPeer4".to_string(),
            access_tier: 0,
        },
        VolatileRemoteChunk {
            chunk_id: "legit_chunk".to_string(),
            file_path: "C:\\shared\\legit.txt".to_string(),
            line_start: 1,
            line_end: 10,
            content: "clean text".to_string(),
            score: 0.85,
            peer_id: "12D3KooWHonestPeer".to_string(),
            access_tier: 0,
        },
    ];

    let sanitized = controller.enforce_inbound_remote_chunks(peer_chunks);
    assert_eq!(
        sanitized.len(),
        1,
        "FAIL-CLOSED VIOLATION: Expected only 1 clean chunk to survive, but got {}",
        sanitized.len()
    );
    assert_eq!(sanitized[0].chunk_id, "legit_chunk");
}

