use std::sync::{Arc, Mutex, RwLock};

use chrono::Utc;
use quorum_atlaskv::{l2_normalize_in_place, AtlasKvStore, AtlasKvTreeConfig, KgTripleRecord};
use quorum_contract::EmbeddingGenerator;
use quorum_coordinator::agentic::retrieve::RetrieveMeshNode;
use quorum_coordinator::crypto::sign_request;
use quorum_coordinator::dlp_mesh::{
    global_mesh_dlp_controller, DlpEnforcementMode, OsoosiMeshDlpController,
    PersistedDaemonSettings, SharedFolderEntry,
};
use quorum_coordinator::mesh::{
    MeshQueryDispatcher, MockMeshDispatcher, MockRemotePeer, OsoosiMeshInboundHandler,
};
use quorum_coordinator::rlm_orchestrator::RlmOrchestrator;
use quorum_coordinator::{
    has_cloud_drive_metadata, is_artemis_dfir_chunk, resolve_local_retrieval_policy,
    AgenticGraphState, CoordinatorConfig, PeerAclManager, QueryCoordinator, ScatterGatherEngine,
    StorageSearcher, SynthesisModelFamily,
};
use quorum_network::InboundQueryHandler;
use quorum_types::{
    AccessTier, CandidateChunkDto, CloudDriveConfigEntry, CloudDriveProvider, CloudDrivesSettings,
    CloudPlaceholderMode, DlpContentGate, DocumentChunk, DocumentFormat, FederatedQueryRequest,
    FederatedQueryResponse, IngestedParentDocument, ScoredChunk, TypeError,
};
use tempfile::tempdir;
use uuid::Uuid;

static GLOBAL_SETTINGS_MUTEX: Mutex<()> = Mutex::new(());

struct GlobalSettingsGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    prev: PersistedDaemonSettings,
}

impl GlobalSettingsGuard {
    fn lock_and_set<F: FnOnce(&mut PersistedDaemonSettings)>(f: F) -> Self {
        let lock = GLOBAL_SETTINGS_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let ctrl = global_mesh_dlp_controller();
        let prev = ctrl.get_settings();
        let mut next = PersistedDaemonSettings::default();
        f(&mut next);
        ctrl.update_settings(next);
        Self { _lock: lock, prev }
    }
}

impl Drop for GlobalSettingsGuard {
    fn drop(&mut self) {
        global_mesh_dlp_controller().update_settings(self.prev.clone());
    }
}

fn make_chunk_with_meta(
    chunk_id: &str,
    doc_id: &str,
    file_path: &str,
    tier: u8,
    text: &str,
    meta: Option<&str>,
) -> DocumentChunk {
    let embedder = quorum_contract::DeterministicOfflineEngine::new();
    let vec = embedder
        .embed_text(text)
        .unwrap_or_else(|_| vec![0.05; 768]);
    DocumentChunk::new(
        chunk_id,
        doc_id,
        file_path,
        1,
        10,
        tier,
        vec,
        text,
        meta.map(|s| s.to_string()),
    )
    .expect("valid chunk")
}

struct InMemoryF14Storage {
    chunks: Vec<DocumentChunk>,
    parents: Vec<(IngestedParentDocument, u8)>,
    atlaskv: Option<Arc<AtlasKvStore>>,
}

#[async_trait::async_trait]
impl StorageSearcher for InMemoryF14Storage {
    async fn search_hybrid(
        &self,
        _query_text: &str,
        _query_vec: &[f32],
        max_tier: u8,
        top_k: usize,
    ) -> Vec<ScoredChunk> {
        self.chunks
            .iter()
            .filter(|c| c.access_tier <= max_tier)
            .take(top_k)
            .map(|c| ScoredChunk::new(c.clone(), 0.9, "local", false))
            .collect()
    }

    async fn search_text(&self, query: &str, max_tier: u8, top_k: usize) -> Vec<ScoredChunk> {
        let ql = query.to_ascii_lowercase();
        self.chunks
            .iter()
            .filter(|c| {
                c.access_tier <= max_tier
                    && (c.text_content.to_ascii_lowercase().contains(&ql)
                        || ql.split_whitespace().any(|w| {
                            w.len() >= 3 && c.text_content.to_ascii_lowercase().contains(w)
                        }))
            })
            .take(top_k)
            .map(|c| ScoredChunk::new(c.clone(), 0.85, "local", false))
            .collect()
    }

    async fn get_chunks_by_ids(&self, chunk_ids: &[String], max_tier: u8) -> Vec<DocumentChunk> {
        self.chunks
            .iter()
            .filter(|c| c.access_tier <= max_tier && chunk_ids.contains(&c.chunk_id))
            .cloned()
            .collect()
    }

    fn expand_parent_window(
        &self,
        doc_id_or_path: &str,
        _anchor_text: &str,
        _window_bytes: usize,
        max_tier: u8,
    ) -> Option<(usize, usize, String, Option<String>, Option<String>)> {
        self.parents
            .iter()
            .find(|(p, t)| {
                *t <= max_tier && (p.doc_id == doc_id_or_path || p.source_path == doc_id_or_path)
            })
            .map(|(p, _)| {
                (
                    0,
                    p.full_text.len(),
                    p.full_text.clone(),
                    p.title.clone(),
                    p.author.clone(),
                )
            })
    }

    fn atlaskv(&self) -> Option<Arc<AtlasKvStore>> {
        self.atlaskv.clone()
    }
}

struct RecordingMeshDispatcher {
    recorded_tiers: Arc<Mutex<Vec<u8>>>,
    responses: Vec<FederatedQueryResponse>,
}

#[async_trait::async_trait]
impl MeshQueryDispatcher for RecordingMeshDispatcher {
    async fn query_peers(
        &self,
        req: &FederatedQueryRequest,
        _timeout: std::time::Duration,
    ) -> Result<Vec<FederatedQueryResponse>, quorum_coordinator::CoordinatorError> {
        for t in 0..=3 {
            if let Ok(tier) = AccessTier::from_u8(t) {
                if quorum_coordinator::verify_request(req, tier, 60).is_ok() {
                    self.recorded_tiers.lock().unwrap().push(t);
                    break;
                }
            }
        }
        Ok(self.responses.clone())
    }

    fn peer_count(&self) -> usize {
        1
    }
}

#[test]
fn test_persisted_settings_cloud_drives_defaults_legacy_json_and_sanitization() {
    // 1. Default PersistedDaemonSettings
    let def = PersistedDaemonSettings::default();
    assert_eq!(
        def.cloud_drives.placeholder_mode,
        CloudPlaceholderMode::LocallySyncedOnly
    );
    assert_eq!(def.cloud_drives.hydration_max_file_size_mb, 25);
    assert!(def.cloud_drives.drives.is_empty());

    // 2. Legacy settings.json lacking "cloud_drives" deserializes cleanly
    let mut legacy_val = serde_json::to_value(&def).unwrap();
    legacy_val.as_object_mut().unwrap().remove("cloud_drives");
    let legacy_json = serde_json::to_string(&legacy_val).unwrap();
    let parsed_legacy: PersistedDaemonSettings = serde_json::from_str(&legacy_json).unwrap();
    assert_eq!(
        parsed_legacy.cloud_drives.placeholder_mode,
        CloudPlaceholderMode::LocallySyncedOnly
    );
    assert_eq!(parsed_legacy.cloud_drives.hydration_max_file_size_mb, 25);
    assert!(parsed_legacy.cloud_drives.drives.is_empty());

    // 3. init_persistence sanitizes invalid persisted cloud_drives fail-closed
    let tmp = tempdir().unwrap();
    let mut bad_settings_json = serde_json::to_value(&def).unwrap();
    bad_settings_json["cloud_drives"] = serde_json::json!({
        "placeholder_mode": "hydrate_on_demand",
        "hydration_max_file_size_mb": 0,
        "drives": [
            {
                "id": "onedrive_bad_tier",
                "provider": "one_drive",
                "label": "OneDrive Bad Tier",
                "enabled": true,
                "root_path": "C:\\Users\\Alice\\OneDrive",
                "access_tier": 9
            },
            {
                "id": "gdrive_bad_path",
                "provider": "google_drive",
                "label": "GDrive Bad Path",
                "enabled": true,
                "root_path": "C:\\Users\\Alice\\..\\Evil",
                "custom_paths": ["C:\\Users\\Alice\\GoodSub", "C:\\Users\\Alice\\Bad%2e%2eSub"],
                "access_tier": 3
            },
            {
                "id": "",
                "provider": "dropbox",
                "label": "Missing Id",
                "enabled": true
            }
        ]
    });
    std::fs::write(
        tmp.path().join("settings.json"),
        serde_json::to_string_pretty(&bad_settings_json).unwrap(),
    )
    .unwrap();

    let ctrl = OsoosiMeshDlpController::new();
    ctrl.init_persistence(tmp.path());
    let loaded = ctrl.get_cloud_drives_settings();
    assert_eq!(
        loaded.placeholder_mode,
        CloudPlaceholderMode::LocallySyncedOnly
    );
    assert_eq!(loaded.hydration_max_file_size_mb, 25);
    assert_eq!(loaded.drives.len(), 2);
    assert!(!loaded.drives[0].enabled);
    assert_eq!(loaded.drives[0].access_tier, 3);
    assert!(!loaded.drives[1].enabled);
    assert!(loaded.drives[1].root_path.is_none());
    assert_eq!(
        loaded.drives[1].custom_paths,
        vec![r"C:\Users\Alice\GoodSub".to_string()]
    );

    // 4. update_cloud_drives_settings rejects invalid tier, traversal path, and duplicate IDs
    let bad_update = CloudDrivesSettings {
        placeholder_mode: CloudPlaceholderMode::LocallySyncedOnly,
        hydration_max_file_size_mb: 25,
        drives: vec![CloudDriveConfigEntry {
            id: "od".to_string(),
            provider: CloudDriveProvider::OneDrive,
            label: "OneDrive".to_string(),
            enabled: true,
            root_path: Some(r"C:\Users\Alice\OneDrive".to_string()),
            custom_paths: Vec::new(),
            access_tier: 4,
            account_kind: None,
        }],
    };
    assert_eq!(
        ctrl.update_cloud_drives_settings(bad_update),
        Err(TypeError::InvalidAccessTier(4))
    );
}

#[test]
fn test_f13_cloud_drive_mesh_isolation_all_8_providers_and_bypass_gauntlet() {
    let ctrl = OsoosiMeshDlpController {
        settings: RwLock::new(PersistedDaemonSettings {
            mesh: quorum_coordinator::OsoosiMeshSettings {
                p2p_enabled: true,
                require_explicit_folder_share: false, // WIDE OPEN wildcard fallback!
                shared_folders: vec![SharedFolderEntry {
                    // Parent folder share MUST NOT leak child OneDrive/Dropbox/etc.
                    path: r"C:\Users\Alice".to_string(),
                    label: "User Profile".to_string(),
                    enabled: true,
                    access_tier: 0,
                    dlp_mode_override: None,
                    shared_at: Utc::now().to_rfc3339(),
                }],
                ..Default::default()
            },
            cloud_drives: CloudDrivesSettings {
                placeholder_mode: CloudPlaceholderMode::LocallySyncedOnly,
                hydration_max_file_size_mb: 25,
                drives: vec![CloudDriveConfigEntry {
                    id: "custom_sync".to_string(),
                    provider: CloudDriveProvider::Nextcloud,
                    label: "Custom Sync".to_string(),
                    enabled: false, // Even disabled configured drives are isolated!
                    root_path: Some(r"D:\PrivateVaultSync".to_string()),
                    custom_paths: vec![r"E:\AltCloudRoot".to_string()],
                    access_tier: 3,
                    account_kind: None,
                }],
            },
            ..Default::default()
        }),
        stats: RwLock::new(Default::default()),
        settings_file_path: RwLock::new(None),
        hmac_secret: [0u8; 32],
    };

    // Normal non-cloud file under C:\Users\Alice\Documents IS shared
    assert!(ctrl
        .check_file_shared_with_mesh(r"C:\Users\Alice\Documents\public.txt")
        .is_some());

    // All 8 cloud providers' standard sync roots + configured roots MUST be blocked
    // despite require_explicit_folder_share = false AND parent C:\Users\Alice shared!
    let cloud_paths = [
        r"G:\My Drive\budget.xlsx",
        r"G:\Shared drives\eng\spec.md",
        "/Users/alice/Library/CloudStorage/GoogleDrive-a@gmail.com/My Drive/doc.pdf",
        "/home/alice/Google Drive/notes.txt",
        r"C:\Users\Alice\OneDrive\tax_2025.pdf",
        r"C:\Users\Alice\OneDrive - Contoso\roadmap.docx",
        r"C:\Users\Alice\Dropbox\keys.txt",
        r"C:\Users\Alice\Dropbox (Personal)\memo.txt",
        r"C:\Users\Alice\iCloudDrive\photo.jpg",
        "/Users/alice/Library/Mobile Documents/com~apple~CloudDocs/notes.txt",
        r"C:\Users\Alice\Box\contract.pdf",
        r"C:\Users\Alice\Box Sync\ledger.xlsx",
        r"C:\Users\Alice\Nextcloud\wiki.md",
        r"C:\Users\Alice\Proton Drive\vault.txt",
        r"P:\pCloud Drive\archive.pdf",
        r"C:\Users\Alice\pCloud\file.txt",
        r"D:\PrivateVaultSync\secret.txt",
        r"E:\AltCloudRoot\nested\secret.txt",
    ];
    for p in cloud_paths {
        assert!(
            ctrl.check_file_shared_with_mesh(p).is_none(),
            "Cloud path '{p}' leaked over mesh!"
        );
    }

    // Adversarial path obfuscation / normalization bypass attempts MUST fail closed
    let bypass_paths = [
        r"C:\Users\Alice\OneDrive.\secret.txt",
        r"C:\Users\Alice\OneDrive \secret.txt",
        r"C:\Users\Alice\OneDrive\secret.txt ",
        r"\\?\C:\Users\Alice\OneDrive\secret.txt",
        r"C:\Users\Alice\One%44rive\secret.txt",
        r"C:\Users\Alice\%2e%2e\OneDrive\secret.txt",
        r"C:\Users\Alice\.\OneDrive\secret.txt",
        r"C:\Users\Alice\OneDrive\file.txt:ads_stream",
        r"C:\Users\Alice\OneDrive\bad%252e%252e\file.txt",
    ];
    for p in bypass_paths {
        assert!(
            ctrl.check_file_shared_with_mesh(p).is_none(),
            "Bypass path '{p}' leaked over mesh!"
        );
    }

    // Explicit opt-in SharedFolderEntry inside cloud root:
    // - Tier 3 drive OR Tier 3 shared folder => STILL blocked (even if DTO stamped tier 0)
    // - Tier 1 drive AND Tier 1 shared folder => allowed
    {
        let mut g = ctrl.settings.write().unwrap();
        g.cloud_drives.drives.push(CloudDriveConfigEntry {
            id: "od_opt_in".to_string(),
            provider: CloudDriveProvider::OneDrive,
            label: "OneDrive".to_string(),
            enabled: true,
            root_path: Some(r"C:\Users\Alice\OneDrive".to_string()),
            custom_paths: Vec::new(),
            access_tier: 3, // Tier 3 local-only!
            account_kind: Some("personal".to_string()),
        });
        g.mesh.shared_folders.push(SharedFolderEntry {
            path: r"C:\Users\Alice\OneDrive\SharedSub".to_string(),
            label: "SharedSub".to_string(),
            enabled: true,
            access_tier: 1, // Folder says tier 1, but drive says tier 3 => max(1, 3) = 3 => BLOCKED!
            dlp_mode_override: None,
            shared_at: Utc::now().to_rfc3339(),
        });
    }
    assert!(ctrl
        .check_file_shared_with_mesh(r"C:\Users\Alice\OneDrive\SharedSub\file.txt")
        .is_none());

    // Lower drive access_tier to 2 => effective tier = max(1, 2) = 2 < 3 => ALLOWED!
    {
        let mut g = ctrl.settings.write().unwrap();
        g.cloud_drives.drives.last_mut().unwrap().access_tier = 2;
    }
    let allowed_entry = ctrl
        .check_file_shared_with_mesh(r"C:\Users\Alice\OneDrive\SharedSub\file.txt")
        .expect("Explicit opt-in with effective tier < 3 must be shared");
    assert_eq!(allowed_entry.access_tier, 2);

    // Outbound filter drops tier-3 shared folder even if DTO chunk.access_tier == 0
    {
        let mut g = ctrl.settings.write().unwrap();
        g.cloud_drives.drives.last_mut().unwrap().access_tier = 3;
    }
    let dtos = vec![
        CandidateChunkDto {
            chunk_id: "c_cloud_spoof_0".to_string(),
            file_path: r"C:\Users\Alice\OneDrive\SharedSub\file.txt".to_string(),
            line_start: 1,
            line_end: 5,
            content: "Cloud secret".to_string(),
            score: 0.9,
            access_tier: 0,
            origin_peer_id: None,
            expanded_window: None,
        },
        CandidateChunkDto {
            chunk_id: "c_doc_ok".to_string(),
            file_path: r"C:\Users\Alice\Documents\public.txt".to_string(),
            line_start: 1,
            line_end: 5,
            content: "Public document".to_string(),
            score: 0.8,
            access_tier: 0,
            origin_peer_id: None,
            expanded_window: None,
        },
    ];
    let filtered = ctrl.filter_and_enforce_outbound_mesh_chunks(dtos, "peer_x");
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].chunk_id, "c_doc_ok");
}

#[tokio::test]
async fn test_f13_inbound_handler_blocks_cloud_drive_metadata_caps_tier2_and_filters_relays() {
    let _guard = GlobalSettingsGuard::lock_and_set(|s| {
        s.mesh.p2p_enabled = true;
        s.mesh.require_explicit_folder_share = false;
        s.ui.default_peer_access_tier = 3; // Even if UI config says 3, handler caps at 2!
    });

    // Chunks at custom non-marker path D:\CustomCloud\secret.txt with "cloud_drive" metadata,
    // plus a Tier 3 normal chunk, plus a valid Tier 0 public chunk
    let cloud_meta_chunk = make_chunk_with_meta(
        "c_meta:0",
        "d_meta",
        r"D:\CustomCloud\secret.txt",
        0,
        "Cloud metadata chunk",
        Some(r#"{"cloud_drive":"proton_drive"}"#),
    );
    let tier3_chunk = make_chunk_with_meta(
        "c_t3:0",
        "d_t3",
        r"D:\Public\tier3.txt",
        3,
        "Tier 3 local secret",
        None,
    );
    let public_chunk = make_chunk_with_meta(
        "c_pub:0",
        "d_pub",
        r"D:\Public\ok.txt",
        0,
        "Public safe doc",
        None,
    );

    let storage = Arc::new(InMemoryF14Storage {
        chunks: vec![cloud_meta_chunk, tier3_chunk, public_chunk],
        parents: Vec::new(),
        atlaskv: None,
    });

    let relay_mock = MockMeshDispatcher::new();
    relay_mock
        .add_peer(MockRemotePeer {
            peer_id: "12D3KooWRelayPeer".to_string(),
            latency: std::time::Duration::from_millis(0),
            max_access_tier: 3,
            candidate_chunks: vec![
                CandidateChunkDto {
                    chunk_id: "relay_t3".to_string(),
                    file_path: r"D:\Relay\secret.txt".to_string(),
                    line_start: 1,
                    line_end: 5,
                    content: "Relayed tier 3 leak".to_string(),
                    score: 0.9,
                    access_tier: 3,
                    origin_peer_id: None,
                    expanded_window: None,
                },
                CandidateChunkDto {
                    chunk_id: "relay_artemis".to_string(),
                    file_path: "artemis://windows/eventlog".to_string(),
                    line_start: 1,
                    line_end: 5,
                    content: "Relayed artemis leak".to_string(),
                    score: 0.9,
                    access_tier: 0,
                    origin_peer_id: None,
                    expanded_window: None,
                },
                CandidateChunkDto {
                    chunk_id: "relay_ok".to_string(),
                    file_path: r"D:\Relay\ok.txt".to_string(),
                    line_start: 1,
                    line_end: 5,
                    content: "Relayed public".to_string(),
                    score: 0.9,
                    access_tier: 0,
                    origin_peer_id: None,
                    expanded_window: None,
                },
            ],
        })
        .await;

    let mut handler = OsoosiMeshInboundHandler::new(storage, "12D3KooWLocalHost".to_string());
    handler.dispatcher = Arc::new(RwLock::new(Some(Arc::new(relay_mock))));

    let seed = [0x21u8; 32];
    let sk = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(seed).unwrap();
    let kp = quorum_network::libp2p::identity::ed25519::Keypair::from(sk);
    let sender_peer_id = quorum_network::libp2p::identity::Keypair::from(kp)
        .public()
        .to_peer_id()
        .to_string();

    let mut req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id,
        sender_pubkey: [0u8; 32],
        query_text: "test query".to_string(),
        embedding: vec![0.05; 768],
        top_k: 10,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
        origin_peer_id: None,
        relay_hops: 0,
        visited_peers: Vec::new(),
        synthesis_relay: None,
    };
    sign_request(&seed, &mut req, AccessTier::Tier3Restricted);

    let resp = handler.handle_query(req).await;
    let ids: Vec<&str> = resp.chunks.iter().map(|c| c.chunk_id.as_str()).collect();
    assert!(ids.contains(&"c_pub:0"));
    assert!(ids.contains(&"relay_ok"));
    assert!(
        !ids.contains(&"c_meta:0"),
        "cloud_drive metadata chunk leaked: {ids:?}"
    );
    assert!(
        !ids.contains(&"c_t3:0"),
        "Tier 3 local chunk leaked: {ids:?}"
    );
    assert!(
        !ids.contains(&"relay_t3"),
        "Relayed Tier 3 chunk leaked: {ids:?}"
    );
    assert!(
        !ids.contains(&"relay_artemis"),
        "Relayed artemis chunk leaked: {ids:?}"
    );
}

#[tokio::test]
async fn test_f14_local_retrieval_cloud_drives_across_coordinator_scatter_retrieve_hikvp_rlm() {
    let kv_dir = tempdir().unwrap();
    let kv_store = Arc::new(
        AtlasKvStore::open(
            kv_dir.path(),
            AtlasKvTreeConfig {
                embedding_dim: 768,
                min_triples_for_hierarchy: 4,
                ..Default::default()
            },
        )
        .unwrap(),
    );

    let od_path = r"C:\Users\Alice\OneDrive\q4_cloud_plan.txt";
    let disabled_drop_path = r"C:\Users\Alice\Dropbox\disabled_secret.txt";
    let non_cloud_t3_path = r"C:\Users\Alice\PrivateTax\return.pdf";
    let artemis_path = "artemis://windows/eventlog/4688";
    let artemis_meta_path = r"C:\Users\Alice\OneDrive\forensic_shadow.json";

    let c_od_0 = make_chunk_with_meta(
        "doc_od:0",
        "doc_od",
        od_path,
        3,
        "QuorumCloudPlan milestone alpha on OneDrive",
        Some(r#"{"cloud_drive":"onedrive"}"#),
    );
    let c_od_1 = make_chunk_with_meta(
        "doc_od:1",
        "doc_od",
        od_path,
        3,
        "QuorumCloudPlan sibling budget details",
        Some(r#"{"cloud_drive":"onedrive"}"#),
    );
    let c_disabled = make_chunk_with_meta(
        "doc_drop:0",
        "doc_drop",
        disabled_drop_path,
        3,
        "QuorumCloudPlan disabled Dropbox secret",
        None,
    );
    let c_tax = make_chunk_with_meta(
        "doc_tax:0",
        "doc_tax",
        non_cloud_t3_path,
        3,
        "QuorumCloudPlan unrelated tier3 tax file",
        None,
    );
    let c_artemis = make_chunk_with_meta(
        "doc_art:0",
        "doc_art",
        artemis_path,
        3,
        "QuorumCloudPlan artemis process eventlog",
        None,
    );
    let c_artemis_spaced = make_chunk_with_meta(
        "doc_art_meta:0",
        "doc_art_meta",
        artemis_meta_path,
        3,
        "QuorumCloudPlan spaced artemis dfir json",
        Some(r#"{"artemis_dfir": true, "mesh_sharable": false}"#),
    );

    // Insert KG triples into AtlasKV (Tier 3 OneDrive vs Tier 3 Artemis)
    let mut kvec = c_od_0.vector.clone();
    l2_normalize_in_place(&mut kvec);
    let kv_triples = vec![
        KgTripleRecord::new(
            "QuorumCloudPlan",
            "location",
            "OneDrive_Q4_Cloud_Triple",
            "doc_od",
            "doc_od:0",
            od_path,
            1,
            5,
            "doc_od",
            3,
            "local",
        )
        .unwrap(),
        KgTripleRecord::new(
            "ArtemisSecret",
            "event",
            "Artemis_Blocked_Triple",
            "doc_art",
            "doc_art:0",
            artemis_path,
            1,
            5,
            "doc_art",
            3,
            "local",
        )
        .unwrap(),
        KgTripleRecord::new(
            "DropboxDisabled",
            "location",
            "Disabled_Dropbox_Triple",
            "doc_drop",
            "doc_drop:0",
            disabled_drop_path,
            1,
            5,
            "doc_drop",
            3,
            "local",
        )
        .unwrap(),
    ];
    kv_store
        .insert_triples(&kv_triples, &vec![kvec.clone(); 3], &vec![kvec.clone(); 3])
        .unwrap();

    let storage = Arc::new(InMemoryF14Storage {
        chunks: vec![
            c_od_0.clone(),
            c_od_1.clone(),
            c_disabled.clone(),
            c_tax.clone(),
            c_artemis.clone(),
            c_artemis_spaced.clone(),
        ],
        parents: vec![
            (
                IngestedParentDocument {
                    doc_id: "doc_od".to_string(),
                    blake3_hash: "h_od".to_string(),
                    source_path: od_path.to_string(),
                    os_platform: "windows".to_string(),
                    format: DocumentFormat::PlainText,
                    title: Some("Q4 Cloud Plan".to_string()),
                    author: Some("Alice".to_string()),
                    created_unix_secs: 1,
                    modified_unix_secs: 1,
                    byte_len: 44,
                    full_text: "Full OneDrive Parent Text QuorumCloudPlan".to_string(),
                    metadata: Default::default(),
                },
                3,
            ),
            (
                IngestedParentDocument {
                    doc_id: "doc_art_meta".to_string(),
                    blake3_hash: "h_art".to_string(),
                    source_path: artemis_meta_path.to_string(),
                    os_platform: "windows".to_string(),
                    format: DocumentFormat::PlainText,
                    title: Some("Artemis Shadow".to_string()),
                    author: None,
                    created_unix_secs: 1,
                    modified_unix_secs: 1,
                    byte_len: 30,
                    full_text: "SHOULD_NEVER_EXPAND_ARTEMIS_DFIR".to_string(),
                    metadata: Default::default(),
                },
                3,
            ),
        ],
        atlaskv: Some(kv_store),
    });

    let recorded_tiers = Arc::new(Mutex::new(Vec::new()));
    let dispatcher = Arc::new(RecordingMeshDispatcher {
        recorded_tiers: Arc::clone(&recorded_tiers),
        responses: Vec::new(),
    });

    let sg = Arc::new(ScatterGatherEngine::new(
        storage.clone(),
        dispatcher,
        Arc::new(tokio::sync::RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        [0x77u8; 32],
        "local_peer".to_string(),
    ));
    let coord = QueryCoordinator::new(Arc::clone(&sg), CoordinatorConfig::default());

    // Configure OneDrive ENABLED at Tier 3, Dropbox DISABLED, Artemis ENABLED but local_collection_enabled = FALSE
    let _guard = GlobalSettingsGuard::lock_and_set(|s| {
        s.mesh.p2p_enabled = true;
        s.atlaskv.enabled = true;
        s.artemis.enabled = true;
        s.artemis.local_collection_enabled = false;
        s.cloud_drives.drives = vec![
            CloudDriveConfigEntry {
                id: "onedrive_personal".to_string(),
                provider: CloudDriveProvider::OneDrive,
                label: "OneDrive".to_string(),
                enabled: true,
                root_path: Some(r"C:\Users\Alice\OneDrive".to_string()),
                custom_paths: Vec::new(),
                access_tier: 3,
                account_kind: Some("personal".to_string()),
            },
            CloudDriveConfigEntry {
                id: "dropbox".to_string(),
                provider: CloudDriveProvider::Dropbox,
                label: "Dropbox".to_string(),
                enabled: false,
                root_path: Some(r"C:\Users\Alice\Dropbox".to_string()),
                custom_paths: Vec::new(),
                access_tier: 3,
                account_kind: None,
            },
        ];
    });

    // 1. QueryCoordinator::query retrieves enabled Tier 3 OneDrive + AtlasKV triple,
    //    blocks disabled Dropbox, non-cloud Tier 3, and both artemis:// & spaced artemis_dfir,
    //    and signs outbound P2P request at Tier 0!
    let res = coord.query("QuorumCloudPlan", 10).await.unwrap();
    let res_ids: Vec<&str> = res
        .chunks
        .iter()
        .map(|c| c.chunk.chunk_id.as_str())
        .collect();
    assert!(
        res_ids.contains(&"doc_od:0"),
        "OneDrive chunk missing: {res_ids:?}"
    );
    assert!(!res_ids.contains(&"doc_drop:0"));
    assert!(!res_ids.contains(&"doc_tax:0"));
    assert!(!res_ids.contains(&"doc_art:0"));
    assert!(!res_ids.contains(&"doc_art_meta:0"));
    assert!(res.synthesis_prompt.contains("OneDrive_Q4_Cloud_Triple"));
    assert!(!res.synthesis_prompt.contains("Artemis_Blocked_Triple"));
    assert!(!res.synthesis_prompt.contains("Disabled_Dropbox_Triple"));

    // Outbound P2P stayed strictly at Tier 0
    {
        let tiers = recorded_tiers.lock().unwrap();
        assert!(!tiers.is_empty());
        assert!(
            tiers.iter().all(|&t| t == 0),
            "Outbound P2P elevated beyond Tier 0: {tiers:?}"
        );
    }

    // 2. ScatterGatherEngine::search_federated_text_with_volatile honors local Tier 3 OneDrive
    //    while keeping outbound P2P at Tier 0 and artemis airgapped
    let (text_hits, _) = sg
        .search_federated_text_with_volatile("QuorumCloudPlan", 0, 10)
        .await;
    let text_ids: Vec<&str> = text_hits
        .iter()
        .map(|c| c.chunk.chunk_id.as_str())
        .collect();
    assert!(text_ids.contains(&"doc_od:0"));
    assert!(!text_ids.contains(&"doc_drop:0"));
    assert!(!text_ids.contains(&"doc_art:0"));
    assert!(!text_ids.contains(&"doc_art_meta:0"));
    assert_eq!(recorded_tiers.lock().unwrap().last().copied(), Some(0));

    // 3. RetrieveMeshNode::execute retrieves OneDrive primary stitched with sibling (doc_od:1) and filters artemis
    let mut state = AgenticGraphState::new("QuorumCloudPlan", SynthesisModelFamily::AutoFusion, 3);
    RetrieveMeshNode::execute(&mut state, &sg, &c_od_0.vector, 0, 10).await;
    let node_ids: Vec<&str> = state
        .retrieved_chunks
        .iter()
        .map(|c| c.chunk.chunk_id.as_str())
        .collect();
    assert!(node_ids.contains(&"doc_od:0"));
    let od_stitched = state
        .retrieved_chunks
        .iter()
        .find(|c| c.chunk.chunk_id == "doc_od:0")
        .expect("doc_od:0 should be present in retrieved_chunks");
    assert!(
        od_stitched
            .chunk
            .text_content
            .contains("milestone alpha on OneDrive")
            && od_stitched
                .chunk
                .text_content
                .contains("sibling budget details"),
        "Stitched OneDrive chunk should merge doc_od:0 and doc_od:1 text: {}",
        od_stitched.chunk.text_content
    );
    assert!(!node_ids.contains(&"doc_drop:0"));
    assert!(!node_ids.contains(&"doc_tax:0"));
    assert!(!node_ids.contains(&"doc_art:0"));
    assert!(!node_ids.contains(&"doc_art_meta:0"));

    // 4. RlmOrchestrator skips spaced `"artemis_dfir": true` & percent-encoded artemis://,
    //    while expanding Tier 3 OneDrive parent window when max_tier = 3
    let c_artemis_encoded = make_chunk_with_meta(
        "doc_art_enc:0",
        "doc_art_enc",
        "artemis%3a//windows/registry",
        3,
        "encoded artemis",
        None,
    );
    assert!(is_artemis_dfir_chunk(&c_artemis_spaced));
    assert!(is_artemis_dfir_chunk(&c_artemis_encoded));

    let mut rlm_chunks = vec![
        ScoredChunk::new(c_od_0.clone(), 0.9, "local", false),
        ScoredChunk::new(c_artemis_spaced.clone(), 0.9, "local", false),
    ];
    let sem = Arc::new(quorum_coordinator::RlmDepthAwareSemaphore::new(4, 16, 8));
    RlmOrchestrator::enrich_retrieved_chunks_with_parent_rlm_concurrent(
        "QuorumCloudPlan",
        &mut rlm_chunks,
        storage.clone(),
        3,
        sem,
        None,
    )
    .await;
    assert!(rlm_chunks[0]
        .chunk
        .text_content
        .contains("Full OneDrive Parent Text"));
    assert!(!rlm_chunks[1]
        .chunk
        .text_content
        .contains("SHOULD_NEVER_EXPAND_ARTEMIS_DFIR"));

    // 5. QueryCoordinator::query_agentic_with_history_and_session retrieves enabled Tier 3 OneDrive
    //    via AgenticStateGraphRunner (HiKVP + RetrieveMeshNode + RLM) while keeping P2P at Tier 0
    let agentic_res = coord
        .query_agentic_with_history_and_session(
            "QuorumCloudPlan",
            Vec::new(),
            SynthesisModelFamily::AutoFusion,
            10,
            Default::default(),
            None,
        )
        .await
        .unwrap();
    let agentic_ids: Vec<&str> = agentic_res
        .chunks
        .iter()
        .map(|c| c.chunk.chunk_id.as_str())
        .collect();
    assert!(agentic_ids.contains(&"doc_od:0"));
    assert!(!agentic_ids.contains(&"doc_art:0"));
    assert!(!agentic_ids.contains(&"doc_art_meta:0"));
    assert!(
        recorded_tiers.lock().unwrap().iter().all(|&t| t == 0),
        "query_agentic must keep outbound P2P at Tier 0 for cloud drives"
    );

    // Policy check: disabling OneDrive immediately blocks Tier 3 local chunks
    let mut off_settings = global_mesh_dlp_controller().get_settings();
    off_settings.cloud_drives.drives[0].enabled = false;
    let off_policy = resolve_local_retrieval_policy(&off_settings, 0, &["QuorumCloudPlan"]);
    assert_eq!(off_policy.local_access_tier, 0);
    assert!(!off_policy.permits_local_chunk(&c_od_0));
}

#[test]
fn test_dlp_content_gate_sync_redact_block_and_invalid_tier() {
    let ctrl = OsoosiMeshDlpController::new();
    let jwt_tok = concat!("eyJhbGciOiJIUzI1NiIs", "InR5cCI6IkpXVCJ9_secret_token");
    let pg_uri = concat!("postgres", "://admin:", "s3cr3tPass", "@db.internal:5432/prod");
    let aws_key = concat!("AKIA", "IOSFODNN7EXAMPLE");
    let oai_key = concat!("sk-proj-", "1234567890abcdefghijklmnop");
    let gh_tok = concat!("ghp_", "1234567890abcdefghij1234567890abcd");
    let slack_tok = concat!("xoxb-", "1234567890-abcdefghij");
    let gcp_key = concat!("AIzaSy", "DaGmWKa4JsXZ-HjGw7ISLn_3namBGtQe0");
    let payload = format!(
        "Bearer {jwt_tok} | {pg_uri} | {aws_key} | {oai_key} | {gh_tok} | {slack_tok} | {gcp_key} | SSN: 123-45-6789"
    );

    // Invalid tier > 3 fails closed
    assert!(ctrl
        .inspect_ingest_text(r"C:\Users\Alice\OneDrive\a.txt", &payload, 4)
        .is_err());

    // Redact mode sanitizes all secrets + SSN
    let scrubbed = ctrl
        .inspect_ingest_text(r"C:\Users\Alice\OneDrive\a.txt", &payload, 3)
        .expect("Redact mode must return scrubbed text");
    assert!(!scrubbed.contains(aws_key));
    assert!(!scrubbed.contains("s3cr3tPass"));
    assert!(!scrubbed.contains("123-45-6789"));
    assert!(!scrubbed.contains(jwt_tok));
    assert!(!scrubbed.contains(gcp_key));
    assert!(!scrubbed.contains(slack_tok));
    assert!(scrubbed.contains("[REDACTED:CROWN_JEWEL_SECRET]"));
    assert!(scrubbed.contains("[REDACTED:PHI_SSN]"));

    // Block mode returns Err(reason) on tainted text and Ok on clean text
    {
        let mut g = ctrl.settings.write().unwrap();
        g.dlp.mode = DlpEnforcementMode::Block;
    }
    let blocked = ctrl.inspect_ingest_text(r"C:\Users\Alice\OneDrive\a.txt", &payload, 3);
    assert!(blocked.is_err());
    let clean = ctrl
        .inspect_ingest_text(
            r"C:\Users\Alice\OneDrive\clean.txt",
            "Quarterly architecture notes without secrets",
            3,
        )
        .expect("Clean text must pass even in Block mode");
    assert_eq!(clean, "Quarterly architecture notes without secrets");
}

#[tokio::test]
async fn test_dlp_content_gate_inside_tokio_runtime_and_spawn_blocking() {
    let ctrl = Arc::new(OsoosiMeshDlpController::new());
    let gate: Arc<dyn DlpContentGate> = ctrl.clone();

    // Direct call inside async Tokio test (must never panic with blocking_read)
    let res = gate
        .inspect_ingest_text(
            r"C:\Users\Alice\Dropbox\doc.txt",
            "Contact: alice@example.com",
            3,
        )
        .unwrap();
    assert!(!res.contains("alice@example.com"));

    // Call inside spawn_blocking (matching IngestThreadPool execution)
    let gate_bg = Arc::clone(&gate);
    let synthetic_pem = format!(
        "{}{}{}\nMIIEowIBAAKCAQEA\n{}{}{}",
        "-----BEGIN ", "RSA PRIVATE ", "KEY-----",
        "-----END ", "RSA PRIVATE ", "KEY-----"
    );
    let bg_res = tokio::task::spawn_blocking(move || {
        gate_bg.inspect_ingest_text(r"C:\Users\Alice\Dropbox\key.pem", &synthetic_pem, 3)
    })
    .await
    .unwrap()
    .unwrap();
    assert!(!bg_res.contains("MIIEowIBAAKCAQEA"));
}

#[test]
fn test_dlp_content_gate_base64_bearer_and_extended_db_uri_schemes() {
    let ctrl = OsoosiMeshDlpController::new();
    let mongo_uri = format!(
        "URI: {}://admin:{}@localhost/prod",
        "mongodb+srv", "s3cr3tPass"
    );
    let redis_uri = format!(
        "URI: {}://:{}@redis-internal:6380/0",
        "rediss", "mySecretPass99"
    );
    let cases: [(&str, String, &[&str]); 4] = [
        (
            "bearer_plus_slash",
            format!("Authorization: Bearer {}", concat!("abc+def/", "ghi=1234567890")),
            &["abc+def", "1234567890"][..],
        ),
        (
            "bearer_b64_eq",
            format!("Authorization: Bearer {}", concat!("dXNlcjpwYXNz", "MTIzNDU2Nzg5MA==")),
            &["dXNlcjpwYXNz", "=="][..],
        ),
        (
            "mongodb_srv",
            mongo_uri,
            &["s3cr3tPass", "mongodb+srv://"][..],
        ),
        (
            "rediss_no_user",
            redis_uri,
            &["mySecretPass99", "rediss://"][..],
        ),
    ];

    for (name, input, forbidden) in &cases {
        let scrubbed = ctrl
            .inspect_ingest_text(r"C:\Users\Alice\OneDrive\secrets.txt", input.as_str(), 3)
            .unwrap_or_else(|e| panic!("Redact mode failed for {name}: {e}"));
        assert!(
            scrubbed.contains("[REDACTED:CROWN_JEWEL_SECRET]"),
            "Expected CROWN_JEWEL_SECRET redaction for {name}, got: {scrubbed}"
        );
        for tok in *forbidden {
            assert!(
                !scrubbed.contains(tok),
                "Remainder '{tok}' leaked after Redact for {name}: {scrubbed}"
            );
        }
    }

    {
        let mut g = ctrl.settings.write().unwrap();
        g.dlp.mode = DlpEnforcementMode::Block;
    }
    for (name, input, _) in &cases {
        let res = ctrl.inspect_ingest_text(r"C:\Users\Alice\OneDrive\secrets.txt", input.as_str(), 3);
        assert!(res.is_err(), "Block mode must reject {name}, got: {res:?}");
    }
}

#[tokio::test]
async fn test_json_unicode_escape_metadata_cannot_bypass_artemis_or_cloud_drive_gates() {
    let artemis_escaped = make_chunk_with_meta(
        "c_art_esc:0",
        "d_art_esc",
        r"C:\Users\Alice\OneDrive\escaped_dfir.json",
        3,
        "Escaped artemis dfir chunk",
        Some(r#"{"artemis\u005fdfir": true}"#),
    );
    assert!(
        is_artemis_dfir_chunk(&artemis_escaped),
        "JSON unicode escape must still be detected by is_artemis_dfir_chunk"
    );

    let mut settings = PersistedDaemonSettings::default();
    settings.artemis.enabled = false;
    settings.cloud_drives.drives.push(CloudDriveConfigEntry {
        id: "od".to_string(),
        provider: CloudDriveProvider::OneDrive,
        label: "OneDrive".to_string(),
        enabled: true,
        root_path: Some(r"C:\Users\Alice\OneDrive".to_string()),
        custom_paths: Vec::new(),
        access_tier: 3,
        account_kind: Some("personal".to_string()),
    });
    let off_policy = resolve_local_retrieval_policy(&settings, 0, &["escaped"]);
    assert!(
        !off_policy.permits_local_chunk(&artemis_escaped),
        "Disabled Artemis must block unicode-escaped artemis_dfir chunk even on enabled Cloud Drive"
    );

    let cloud_escaped = make_chunk_with_meta(
        "c_cloud_esc:0",
        "d_cloud_esc",
        r"D:\CustomRoot\escaped_cloud.txt",
        0,
        "Escaped cloud_drive metadata chunk",
        Some(r#"{"cloud\u005fdrive": "onedrive"}"#),
    );
    assert!(
        has_cloud_drive_metadata(&cloud_escaped),
        "JSON unicode escape must still be detected by has_cloud_drive_metadata"
    );

    let _guard = GlobalSettingsGuard::lock_and_set(|s| {
        s.mesh.p2p_enabled = true;
        s.mesh.require_explicit_folder_share = false;
    });
    let storage = Arc::new(InMemoryF14Storage {
        chunks: vec![cloud_escaped],
        parents: Vec::new(),
        atlaskv: None,
    });
    let handler = OsoosiMeshInboundHandler::new(storage, "12D3KooWLocalHost".to_string());
    let seed = [0x33u8; 32];
    let sk = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(seed).unwrap();
    let kp = quorum_network::libp2p::identity::ed25519::Keypair::from(sk);
    let sender_peer_id = quorum_network::libp2p::identity::Keypair::from(kp)
        .public()
        .to_peer_id()
        .to_string();
    let mut req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id,
        sender_pubkey: [0u8; 32],
        query_text: "Escaped cloud_drive metadata".to_string(),
        embedding: vec![0.05; 768],
        top_k: 10,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
        origin_peer_id: None,
        relay_hops: 0,
        visited_peers: Vec::new(),
        synthesis_relay: None,
    };
    sign_request(&seed, &mut req, AccessTier::Tier2Confidential);
    let resp = handler.handle_query(req).await;
    assert!(
        resp.chunks.is_empty(),
        "Unicode-escaped cloud_drive metadata chunk must be blocked from P2P mesh: {:?}",
        resp.chunks
    );
}

#[tokio::test]
async fn test_query_agentic_forensic_query_does_not_elevate_peer_tier_or_disabled_cloud_drive() {
    let disabled_drop_path = r"C:\Users\Alice\Dropbox\forensic_dns_leak.txt";
    let c_disabled_drop = make_chunk_with_meta(
        "drop_forensic:0",
        "drop_forensic",
        disabled_drop_path,
        3,
        "artemis dns traffic port 53 inside disabled dropbox",
        None,
    );
    let c_artemis = make_chunk_with_meta(
        "art_forensic:0",
        "art_forensic",
        "artemis://windows/sysmon/dns/22",
        3,
        "artemis dns traffic port 53 sysmon event 22",
        None,
    );

    let storage = Arc::new(InMemoryF14Storage {
        chunks: vec![c_disabled_drop, c_artemis],
        parents: Vec::new(),
        atlaskv: None,
    });
    let recorded_tiers = Arc::new(Mutex::new(Vec::new()));
    let dispatcher = Arc::new(RecordingMeshDispatcher {
        recorded_tiers: Arc::clone(&recorded_tiers),
        responses: Vec::new(),
    });
    let sg = Arc::new(ScatterGatherEngine::new(
        storage,
        dispatcher,
        Arc::new(tokio::sync::RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        [0x88u8; 32],
        "local_peer".to_string(),
    ));
    let coord = QueryCoordinator::new(sg, CoordinatorConfig::default());

    let _guard = GlobalSettingsGuard::lock_and_set(|s| {
        s.mesh.p2p_enabled = true;
        s.artemis.enabled = true;
        s.artemis.local_collection_enabled = false;
        s.cloud_drives.drives = vec![CloudDriveConfigEntry {
            id: "dropbox".to_string(),
            provider: CloudDriveProvider::Dropbox,
            label: "Dropbox".to_string(),
            enabled: false,
            root_path: Some(r"C:\Users\Alice\Dropbox".to_string()),
            custom_paths: Vec::new(),
            access_tier: 3,
            account_kind: None,
        }];
    });

    let res = coord
        .query_agentic_with_history_and_session(
            "Check artemis dns traffic on this machine",
            Vec::new(),
            SynthesisModelFamily::AutoFusion,
            10,
            Default::default(),
            None,
        )
        .await
        .unwrap();
    let ids: Vec<&str> = res
        .chunks
        .iter()
        .map(|c| c.chunk.chunk_id.as_str())
        .collect();
    assert!(
        !ids.contains(&"drop_forensic:0"),
        "Disabled Tier 3 Dropbox leaked during forensic agentic query: {ids:?}"
    );
    assert!(
        ids.contains(&"art_forensic:0"),
        "Artemis telemetry should still be locally accessible when artemis.enabled=true: {ids:?}"
    );
    {
        let tiers = recorded_tiers.lock().unwrap();
        assert!(
            tiers.is_empty(),
            "Host-local forensic query should suppress outbound P2P fan-out: {tiers:?}"
        );
    }

    let res2 = coord
        .query_agentic_with_history_and_session(
            "Check artemis dns traffic across mesh peers",
            Vec::new(),
            SynthesisModelFamily::AutoFusion,
            10,
            Default::default(),
            None,
        )
        .await
        .unwrap();
    let ids2: Vec<&str> = res2
        .chunks
        .iter()
        .map(|c| c.chunk.chunk_id.as_str())
        .collect();
    assert!(
        !ids2.contains(&"drop_forensic:0"),
        "Disabled Tier 3 Dropbox leaked during remote forensic agentic query: {ids2:?}"
    );
    let tiers2 = recorded_tiers.lock().unwrap();
    assert!(!tiers2.is_empty());
    assert!(
        tiers2.iter().all(|&t| t == 0),
        "Forensic agentic query elevated outbound P2P signing tier beyond Tier 0: {tiers2:?}"
    );
}

#[test]
fn test_disabled_cloud_drive_rules_stay_tier3_and_local_policy_blocks_stale_tier0() {
    let ctrl = OsoosiMeshDlpController::new();
    {
        let mut g = ctrl.settings.write().unwrap();
        g.cloud_drives.drives = vec![
            CloudDriveConfigEntry {
                id: "dropbox".to_string(),
                provider: CloudDriveProvider::Dropbox,
                label: "Dropbox".to_string(),
                enabled: false,
                root_path: Some(r"C:\Users\Alice\Dropbox".to_string()),
                custom_paths: Vec::new(),
                access_tier: 0,
                account_kind: None,
            },
            CloudDriveConfigEntry {
                id: "onedrive_personal".to_string(),
                provider: CloudDriveProvider::OneDrive,
                label: "OneDrive".to_string(),
                enabled: true,
                root_path: Some(r"C:\Users\Alice\OneDrive".to_string()),
                custom_paths: Vec::new(),
                access_tier: 2,
                account_kind: Some("personal".to_string()),
            },
        ];
    }

    let rules = ctrl.cloud_drive_access_tier_rules();
    let drop_rule = rules
        .iter()
        .find(|(p, _)| p.to_string_lossy().to_ascii_lowercase().contains("dropbox"))
        .expect("Disabled cloud drive root must remain in access_tier_rules");
    assert_eq!(drop_rule.1, 3, "Disabled cloud root must map to Tier 3");
    let od_rule = rules
        .iter()
        .find(|(p, _)| {
            p.to_string_lossy()
                .to_ascii_lowercase()
                .contains("onedrive")
        })
        .expect("Enabled cloud drive root must be in access_tier_rules");
    assert_eq!(od_rule.1, 2);

    let settings = ctrl.get_settings();
    let policy = resolve_local_retrieval_policy(&settings, 0, &["test"]);
    let stale_tier0_disabled_chunk = make_chunk_with_meta(
        "stale_drop:0",
        "stale_drop",
        r"C:\Users\Alice\Dropbox\rapid.txt",
        0,
        "stale tier 0 chunk inside disabled dropbox",
        None,
    );
    assert!(
        !policy.permits_local_chunk(&stale_tier0_disabled_chunk),
        "LocalRetrievalPolicy must fail closed on disabled cloud drive paths even if chunk access_tier == 0"
    );

    let enabled_tier2_chunk = make_chunk_with_meta(
        "od_t2:0",
        "od_t2",
        r"C:\Users\Alice\OneDrive\work.txt",
        2,
        "enabled tier 2 chunk inside onedrive",
        None,
    );
    assert!(policy.permits_local_chunk(&enabled_tier2_chunk));
}

#[test]
fn test_local_retrieval_policy_rejects_traversal_encoded_ads_unc_while_allowing_fixtures_and_verbatim(
) {
    let mut settings = PersistedDaemonSettings::default();
    settings.cloud_drives.drives = vec![
        CloudDriveConfigEntry {
            id: "onedrive_personal".to_string(),
            provider: CloudDriveProvider::OneDrive,
            label: "OneDrive".to_string(),
            enabled: true,
            root_path: Some(r"C:\Allowed".to_string()),
            custom_paths: Vec::new(),
            access_tier: 3,
            account_kind: None,
        },
        CloudDriveConfigEntry {
            id: "gdrive".to_string(),
            provider: CloudDriveProvider::GoogleDrive,
            label: "Google Drive".to_string(),
            enabled: true,
            root_path: Some(r"G:\My Drive".to_string()),
            custom_paths: Vec::new(),
            access_tier: 3,
            account_kind: None,
        },
    ];
    let policy = resolve_local_retrieval_policy(&settings, 0, &["test"]);

    for unsafe_path in [
        r"G:\My Drive\..\secret.txt",
        r"G:\My Drive\%2e%2e\secret.txt",
        r"G:\My Drive\file.txt:ads",
        r"G:\My Drive\file.txt%3aads",
        r"\\server\share\a.txt",
        r"\\?\UNC\server\share\a.txt",
        "G:\\My Drive\\ctrl\u{202E}txt",
        "G:\\My Drive\\nul\0.txt",
        "C:secret.txt",
        r"C:\Allowed\trailing.",
        r"C:\Allowed\space ",
    ] {
        assert!(
            !policy.permits_local_path_and_tier(unsafe_path, 0, false),
            "Unsafe path must fail closed even at tier 0: {unsafe_path}"
        );
    }

    assert!(policy.permits_local_path_and_tier("bench.rs", 0, false));
    assert!(policy.permits_local_path_and_tier(r"\\?\C:\Allowed\doc.txt", 3, false));
}

#[test]
fn test_equal_length_prefix_ties_fail_closed_across_policy_and_ingest_rules() {
    let ctrl = OsoosiMeshDlpController::new();
    {
        let mut g = ctrl.settings.write().unwrap();
        g.cloud_drives.drives = vec![
            CloudDriveConfigEntry {
                id: "drive_disabled".to_string(),
                provider: CloudDriveProvider::Dropbox,
                label: "Dropbox".to_string(),
                enabled: false,
                root_path: Some(r"C:\Users\Alice\SharedRoot".to_string()),
                custom_paths: Vec::new(),
                access_tier: 0,
                account_kind: None,
            },
            CloudDriveConfigEntry {
                id: "drive_enabled".to_string(),
                provider: CloudDriveProvider::OneDrive,
                label: "OneDrive".to_string(),
                enabled: true,
                root_path: Some(r"C:\Users\Alice\SharedRoot".to_string()),
                custom_paths: Vec::new(),
                access_tier: 0,
                account_kind: None,
            },
        ];
    }

    let settings = ctrl.get_settings();
    let policy = resolve_local_retrieval_policy(&settings, 0, &["test"]);
    assert!(
        !policy.permits_local_path_and_tier(r"C:\Users\Alice\SharedRoot\plan.txt", 0, false),
        "Equal-length disabled-vs-enabled cloud prefix tie must fail closed"
    );

    let rules = ctrl.cloud_drive_access_tier_rules();
    let mut cfg = quorum_ingest::IngestConfig::default();
    cfg.access_tier_rules = rules;
    assert_eq!(
        cfg.resolve_access_tier(std::path::Path::new(r"C:\Users\Alice\SharedRoot\plan.txt")),
        3,
        "Disabled Tier 3 rule must win over equal-length enabled Tier 0 rule"
    );

    // Two enabled drives with identical prefix length resolve deterministically to max tier (3)
    {
        let mut g = ctrl.settings.write().unwrap();
        g.cloud_drives.drives[0].enabled = true;
        g.cloud_drives.drives[0].access_tier = 3;
        g.cloud_drives.drives[1].enabled = true;
        g.cloud_drives.drives[1].access_tier = 0;
    }
    let tied_settings = ctrl.get_settings();
    let tied_policy = resolve_local_retrieval_policy(&tied_settings, 0, &["test"]);
    assert!(tied_policy.permits_local_path_and_tier(
        r"C:\Users\Alice\SharedRoot\plan.txt",
        3,
        false
    ));
    let mut cfg_tied = quorum_ingest::IngestConfig::default();
    cfg_tied.access_tier_rules = ctrl.cloud_drive_access_tier_rules();
    assert_eq!(
        cfg_tied.resolve_access_tier(std::path::Path::new(r"C:\Users\Alice\SharedRoot\plan.txt")),
        3
    );
}

#[test]
fn test_disabled_cloud_drive_with_tier0_and_shared_folders_fails_closed() {
    let ctrl = OsoosiMeshDlpController::new();
    {
        let mut g = ctrl.settings.write().unwrap();
        g.mesh.p2p_enabled = true;
        g.mesh.require_explicit_folder_share = true;
        g.mesh.shared_folders = vec![SharedFolderEntry {
            path: r"C:\Users\Alice\Dropbox".to_string(),
            label: "Dropbox".to_string(),
            enabled: true,
            access_tier: 0,
            dlp_mode_override: None,
            shared_at: "2026-11-23T00:00:00Z".to_string(),
        }];
        g.cloud_drives.drives = vec![CloudDriveConfigEntry {
            id: "dropbox".to_string(),
            provider: CloudDriveProvider::Dropbox,
            label: "Dropbox".to_string(),
            enabled: false,
            root_path: Some(r"C:\Users\Alice\Dropbox".to_string()),
            custom_paths: Vec::new(),
            access_tier: 0,
            account_kind: None,
        }];
    }

    assert_eq!(
        ctrl.effective_cloud_drive_tier_for_path(r"C:\Users\Alice\Dropbox\doc.txt"),
        Some(3),
        "Disabled drive must clamp effective tier to Tier 3"
    );
    assert!(
        ctrl.check_file_shared_with_mesh(r"C:\Users\Alice\Dropbox\doc.txt")
            .is_none(),
        "Disabled cloud drive must never be shared with mesh even if in shared_folders with tier 0"
    );
}

#[tokio::test]
async fn test_scatter_gather_cached_vector_preserves_enabled_copy_sharing_chunk_id_with_disabled_drive(
) {
    let disabled_path = r"C:\Users\Alice\Dropbox\dup_secret.txt";
    let enabled_path = r"C:\Users\Alice\OneDrive\dup_secret.txt";
    let mut c_disabled = make_chunk_with_meta(
        "dup_shared:0",
        "doc_dup",
        disabled_path,
        3,
        "shared quorum secret token",
        None,
    );
    let mut c_enabled = make_chunk_with_meta(
        "dup_shared:0",
        "doc_dup",
        enabled_path,
        3,
        "shared quorum secret token",
        None,
    );
    // Give identical vector so both match text/cached paths
    c_enabled.vector = c_disabled.vector.clone();
    c_disabled.blake3_hash = "same_hash".to_string();
    c_enabled.blake3_hash = "same_hash".to_string();

    let storage = Arc::new(InMemoryF14Storage {
        chunks: vec![c_disabled.clone(), c_enabled.clone()],
        parents: Vec::new(),
        atlaskv: None,
    });
    let dispatcher = Arc::new(RecordingMeshDispatcher {
        recorded_tiers: Arc::new(Mutex::new(Vec::new())),
        responses: Vec::new(),
    });
    let sg = ScatterGatherEngine::new(
        storage,
        dispatcher,
        Arc::new(tokio::sync::RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        [0x77u8; 32],
        "local_peer".to_string(),
    );

    let _guard = GlobalSettingsGuard::lock_and_set(|s| {
        s.mesh.p2p_enabled = false;
        s.cloud_drives.drives = vec![
            CloudDriveConfigEntry {
                id: "dropbox".to_string(),
                provider: CloudDriveProvider::Dropbox,
                label: "Dropbox".to_string(),
                enabled: false,
                root_path: Some(r"C:\Users\Alice\Dropbox".to_string()),
                custom_paths: Vec::new(),
                access_tier: 3,
                account_kind: None,
            },
            CloudDriveConfigEntry {
                id: "onedrive_personal".to_string(),
                provider: CloudDriveProvider::OneDrive,
                label: "OneDrive".to_string(),
                enabled: true,
                root_path: Some(r"C:\Users\Alice\OneDrive".to_string()),
                custom_paths: Vec::new(),
                access_tier: 3,
                account_kind: Some("personal".to_string()),
            },
        ];
    });

    let cached_vector = vec![
        ScoredChunk::new(c_disabled.clone(), 0.99, "local", false),
        ScoredChunk::new(c_enabled.clone(), 0.95, "local", false),
    ];
    let (results, _, _, _) = sg
        .execute_query_with_p2p_query_and_exclusion(
            "shared quorum secret token",
            "shared quorum secret token",
            &c_enabled.vector,
            Some(&cached_vector),
            0,
            10,
            &[],
        )
        .await;

    let paths: Vec<&str> = results.iter().map(|c| c.chunk.file_path.as_str()).collect();
    assert!(
        paths.contains(&enabled_path),
        "Enabled OneDrive copy must be preserved when cached vector shares chunk_id with disabled Dropbox copy: {paths:?}"
    );
    assert!(
        !paths.contains(&disabled_path),
        "Disabled Dropbox copy must be filtered out: {paths:?}"
    );
}

#[test]
fn t5_normalize_folder_path_unix_case_preservation_matches_quorum_types() {
    let upper = OsoosiMeshDlpController::normalize_folder_path("/home/alice/Nextcloud/Docs")
        .expect("valid unix path");
    let lower = OsoosiMeshDlpController::normalize_folder_path("/home/alice/nextcloud/docs")
        .expect("valid unix path");
    assert_ne!(
        upper, lower,
        "Unix paths in normalize_folder_path must preserve case just like quorum_types::normalize_prefix_for_match"
    );
    assert!(OsoosiMeshDlpController::is_standard_cloud_root_marker(
        &upper
    ));
    assert!(OsoosiMeshDlpController::is_standard_cloud_root_marker(
        "/Users/Alice/Library/CloudStorage/GoogleDrive-a/My Drive/doc.txt"
    ));

    // Windows drive paths remain case-insensitive
    assert_eq!(
        OsoosiMeshDlpController::normalize_folder_path(r"C:\Users\Alice\OneDrive\Docs"),
        OsoosiMeshDlpController::normalize_folder_path("c:/users/alice/onedrive/docs")
    );
}
