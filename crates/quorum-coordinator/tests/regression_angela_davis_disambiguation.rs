//! Regression test suite for v0.6.6:
//! 1. General Two-Layer Homonym Entity Disambiguation (Angela Davis + Michael Chen — zero hardcoded names).
//! 2. Cross-All-Hosts 1-Hop Mesh Relay (`Node A -> Gateway B -> LAN Peer C`) with 10,000-byte RLM Parent
//!    Expansion and Authentic `origin_peer_id` Provenance Attribution.
//! 3. Universal Clean Response Formatting (ChatGPT `entity[...]` tag normalization, `**:::` removal,
//!    broken mid-sentence lowercase fragment stripping, IPv4 `71.194.142.20:3032` preservation,
//!    and `.pm` / single-word remote distractor rejection).

use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use quorum_network::InboundQueryHandler;
use quorum_types::{
    AccessTier, DocumentChunk, FederatedQueryRequest, FederatedQueryResponse, ScoredChunk,
};
use quorum_coordinator::{
    answer_orchestrator::classify_entity_domain_cluster,
    offline_engine::DeterministicOfflineSynthesisEngine,
    CoordinatorConfig, CoordinatorError, LocalOnlyDispatcher, MeshQueryDispatcher,
    OsoosiMeshInboundHandler, PeerAclManager, QueryCoordinator, ScatterGatherEngine,
    SynthesisModelFamily,
};

struct HandlerBridgeDispatcher {
    handler: Arc<OsoosiMeshInboundHandler>,
}

#[async_trait::async_trait]
impl MeshQueryDispatcher for HandlerBridgeDispatcher {
    async fn query_peers(
        &self,
        request: &FederatedQueryRequest,
        _timeout: Duration,
    ) -> Result<Vec<FederatedQueryResponse>, CoordinatorError> {
        let resp = self.handler.handle_query(request.clone()).await;
        Ok(vec![resp])
    }

    fn peer_count(&self) -> usize {
        1
    }
}

#[test]
fn test_entity_domain_cluster_classification_general() {
    let scholar_text = "Angela Davis is an American political activist and scholar whose landmark work Women, Race & Class was first published in 1981, exploring critical theory.";
    let scholar_path = "C:/Docs/Women Race Class Summary.docx";
    assert_eq!(
        classify_entity_domain_cluster(scholar_path, scholar_text),
        "Academic Scholarship, Published Works & Critical Theory"
    );

    let lease_text = "SIMPLE LEASE AGREEMENT between Angela Davis (landlord) and Casey Ringgold (tenant) for the dwelling unit at 2913 Castiglione St., New Orleans, LA.";
    let lease_path = "C:/Leases/Susan MONTH TO MONTH LEASE AGREEMENT.doc";
    assert_eq!(
        classify_entity_domain_cluster(lease_path, lease_text),
        "Residential Property Leasing & Real Estate Management"
    );

    let ministry_text = "Reverend Angela Davis serves as a Unity minister exploring divine presence, metaphysical balance, and STEWARD board leadership.";
    let ministry_path = "C:/Ministry/Computer Manuscript Assistance.docx";
    assert_eq!(
        classify_entity_domain_cluster(ministry_path, ministry_text),
        "Religious Ministry, Spiritual Teaching & Organizational Stewardship"
    );

    let clinical_text = "Dr. Michael Chen, MD is an attending physician and clinical cardiologist treating patient cardiovascular diagnosis records at Memorial Hospital.";
    let clinical_path = "C:/Hospital/Cardiology_Roster.pdf";
    assert_eq!(
        classify_entity_domain_cluster(clinical_path, clinical_text),
        "Clinical & Healthcare Records"
    );

    let eng_text = "Michael Chen is a principal software engineer and CISSP security architect specializing in distributed systems and Kubernetes.";
    let eng_path = "C:/Engineering/Michael_Chen_Profile.pdf";
    assert_eq!(
        classify_entity_domain_cluster(eng_path, eng_text),
        "Software Engineering, Architecture & Cybersecurity"
    );
}

#[test]
fn test_universal_formatting_hygiene_and_ipv4_preservation() {
    // 1. Normalize ChatGPT entity[...] tags, strip `**:::`, and strip assistant meta-chatter
    let noisy_chatgpt_export = concat!(
        "**:::Women Race Class Summary\n",
        "entity[\"book\",\"Women, Race & Class\",\"Angela Davis 1981\"] is a landmark work by ",
        "entity[\"people\",\"Angela Davis\",\"American political activist and scholar\"], first published in 1981.\n",
        "Hi! It looks like you mentioned \"zrubrics\" - could you clarify what you mean?\n",
        "Feel free to upload it so I can analyze and correct it for grammar."
    );
    let cleaned = DeterministicOfflineSynthesisEngine::clean_chunk_text(noisy_chatgpt_export);
    assert!(
        cleaned.contains("Women, Race & Class is a landmark work by Angela Davis, first published in 1981."),
        "Must cleanly unwrap entity[...] labels: {}",
        cleaned
    );
    assert!(!cleaned.contains("entity[\""), "Must strip raw entity[...] tags: {}", cleaned);
    assert!(!cleaned.contains("**:::"), "Must strip **::: markers: {}", cleaned);
    assert!(!cleaned.contains("zrubrics"), "Must strip ChatGPT meta-chatter: {}", cleaned);

    // 2. Strip mid-sentence leading lowercase fragment ("n emergency...") to first complete sentence
    let sliced_fragment = "n emergency, or situation which could cause damages to the property. Call 911 in case of emergency. Lessor is not liable to any resident, guest, or occupant for personal injury or property damage.";
    let cleaned_frag = DeterministicOfflineSynthesisEngine::clean_chunk_text(sliced_fragment);
    assert!(
        cleaned_frag.starts_with("Call 911 in case of emergency."),
        "Must advance past broken mid-sentence fragment to first complete sentence: {}",
        cleaned_frag
    );

    // 3. Never truncate IPv4 endpoints (`71.194.142.20:3032`) mid-octet in pack_context_window
    let ipv4_text = format!(
        "QuorumRAG gateway node connected cleanly to remote WAN mesh endpoint 71.194.142.20:3032 over libp2p TCP. {}",
        "Additional telemetry padding words for context window budget testing. ".repeat(6)
    );
    let ipv4_chunk = DocumentChunk::new(
        "c_ipv4",
        "doc_ipv4",
        "C:/Logs/mesh_status.txt",
        1,
        5,
        0,
        vec![0.0f32; 768],
        &ipv4_text,
        None,
    )
    .expect("chunk");
    let scored = ScoredChunk::new(ipv4_chunk, 0.95, "local", false);
    // Budget cuts right around `71.194.142.20:3032`
    let packed = DeterministicOfflineSynthesisEngine::pack_context_window(&[scored], 96);
    assert!(!packed.is_empty());
    assert!(
        !packed[0].chunk.text_content.ends_with("71.194.142."),
        "pack_context_window must never cut mid-IPv4 address: {}",
        packed[0].chunk.text_content
    );
}

#[tokio::test]
async fn test_who_is_angela_davis_two_layer_disambiguation() {
    let temp_dir = tempdir().expect("tempdir");
    let storage_config = quorum_storage::StorageConfig::new(temp_dir.path().to_path_buf());
    let storage = Arc::new(
        quorum_storage::StorageEngine::open(storage_config)
            .await
            .expect("storage open"),
    );

    let dummy_embedding = vec![0.0f32; 768];

    let scholar_chunk = DocumentChunk::new(
        "doc_scholar:0",
        "doc_scholar",
        "C:/Library/Women Race Class Summary.docx",
        1,
        25,
        0,
        dummy_embedding.clone(),
        "entity[\"book\",\"Women, Race & Class\",\"Angela Davis 1981\"] is a landmark work by entity[\"people\",\"Angela Davis\",\"American political activist and scholar\"], first published in 1981, examining the intersectionality of race, gender, and class in critical theory.",
        Some(r#"{"doc_title":"Women, Race & Class","doc_author":"Angela Davis"}"#.to_string()),
    )
    .expect("chunk");

    let lease_chunk_1 = DocumentChunk::new(
        "doc_lease_susan:0",
        "doc_lease_susan",
        "C:/Leases/Susan MONTH TO MONTH LEASE AGREEMENT.doc",
        1,
        30,
        0,
        dummy_embedding.clone(),
        "SIMPLE LEASE AGREEMENT made between Angela Davis (landlord) and Casey Ringgold (tenant) for the dwelling unit located at 2913 Castiglione St. New Orleans, LA 70119. Monthly rent is $614.00.",
        None,
    )
    .expect("chunk");

    let lease_chunk_2 = DocumentChunk::new(
        "doc_lease_ava:0",
        "doc_lease_ava",
        "C:/Leases/Ava Davis LEASE AGREEMENT.doc",
        1,
        30,
        0,
        dummy_embedding.clone(),
        "SIMPLE MONTH TO MONTH YEAR LEASE AGREEMENT entered into between Firldeal (Angela Davis) Breure (lessor) and Ava Davis (tenant, not related) for the dwelling unit located at 1967 Hope St. New Orleans, LA.",
        None,
    )
    .expect("chunk");

    let ministry_chunk = DocumentChunk::new(
        "doc_ministry:0",
        "doc_ministry",
        "C:/Ministry/Computer Manuscript Assistance.docx",
        1,
        25,
        0,
        dummy_embedding.clone(),
        "Angela Davis serves as a Unity minister and STEWARD board participant exploring spiritual teaching, divine presence, and community stewardship.",
        None,
    )
    .expect("chunk");

    let perl_code_distractor = DocumentChunk::new(
        "doc_perl:0",
        "doc_perl",
        "C:/Perl/DateTime/LeapSecond/Davis.pm",
        1,
        20,
        0,
        dummy_embedding.clone(),
        "package DateTime::Davis; # Angela Davis Perl module fixture that must be excluded from prose RAG.",
        None,
    )
    .expect("chunk");

    let distractor_zrubrics = DocumentChunk::new(
        "doc_zrubrics:0",
        "doc_zrubrics",
        "C:/Projects/Zrubrics Clarification.docx",
        1,
        20,
        0,
        dummy_embedding.clone(),
        "Zrubrics Clarification document explaining student rubric scoring metrics and Davis grading scales.",
        None,
    )
    .expect("chunk");

    storage
        .insert_chunks(&[
            scholar_chunk,
            lease_chunk_1,
            lease_chunk_2,
            ministry_chunk,
            perl_code_distractor,
            distractor_zrubrics,
        ])
        .await
        .expect("insert");

    let scatter_gather = Arc::new(ScatterGatherEngine::new(
        Arc::clone(&storage) as Arc<dyn quorum_coordinator::StorageSearcher>,
        Arc::new(LocalOnlyDispatcher),
        Arc::new(tokio::sync::RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        [0x5Cu8; 32],
        "12D3KooWAngelaTestNode".to_string(),
    ));

    let coordinator = Arc::new(QueryCoordinator::new(
        scatter_gather,
        CoordinatorConfig::default(),
    ));

    let result = coordinator
        .query_agentic_with_history_and_session(
            "WHO IS ANGELA DAVIS",
            Vec::new(),
            SynthesisModelFamily::AutoFusion,
            12,
            std::collections::HashSet::new(),
            None,
        )
        .await
        .expect("query");

    let answer = result.synthesis_prompt;

    assert!(
        answer.contains("multiple distinct individuals") || answer.contains("distinct contexts"),
        "Must open with explicit homonym disambiguation: {}",
        answer
    );
    assert!(
        answer.contains("### Academic Scholarship, Published Works & Critical Theory"),
        "Must contain Academic Scholarship section: {}",
        answer
    );
    assert!(
        answer.contains("### Residential Property Leasing & Real Estate Management"),
        "Must contain Residential Property Leasing section: {}",
        answer
    );
    assert!(
        answer.contains("### Religious Ministry, Spiritual Teaching & Organizational Stewardship"),
        "Must contain Religious Ministry section: {}",
        answer
    );
    assert!(!answer.contains("Born as Angela Yvonne Davis"));
    assert!(!answer.contains("entity[\""));
    assert!(!answer.contains("Zrubrics"));
    assert!(!answer.contains("Davis.pm"));
    println!("\n=== [REGRESSION TEST OUTPUT: WHO IS ANGELA DAVIS (2-LAYER DISAMBIGUATION)] ===\n{}\n=== [END OUTPUT] ===", answer);
}

#[tokio::test]
async fn test_general_homonym_disambiguation_michael_chen() {
    let temp_dir = tempdir().expect("tempdir");
    let storage_config = quorum_storage::StorageConfig::new(temp_dir.path().to_path_buf());
    let storage = Arc::new(
        quorum_storage::StorageEngine::open(storage_config)
            .await
            .expect("storage open"),
    );

    let dummy_embedding = vec![0.0f32; 768];

    let clinician = DocumentChunk::new(
        "chen_med:0",
        "chen_med",
        "C:/Records/Cardiology_Department_Roster.docx",
        1,
        20,
        0,
        dummy_embedding.clone(),
        "Michael Chen is an attending physician and clinical cardiologist at St. Jude Medical Hospital overseeing patient cardiac diagnosis protocols since 2019.",
        None,
    )
    .expect("chunk");

    let architect = DocumentChunk::new(
        "chen_eng:0",
        "chen_eng",
        "C:/Engineering/Staff_Architect_Bio.pdf",
        1,
        20,
        0,
        dummy_embedding,
        "Michael Chen is a CISSP security architect and principal software engineer building Kubernetes microservices and cryptographic key-management pipelines in Austin, TX.",
        None,
    )
    .expect("chunk");

    storage
        .insert_chunks(&[clinician, architect])
        .await
        .expect("insert");

    let scatter_gather = Arc::new(ScatterGatherEngine::new(
        Arc::clone(&storage) as Arc<dyn quorum_coordinator::StorageSearcher>,
        Arc::new(LocalOnlyDispatcher),
        Arc::new(tokio::sync::RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        [0x6Du8; 32],
        "12D3KooWMichaelChenNode".to_string(),
    ));

    let coordinator = Arc::new(QueryCoordinator::new(
        scatter_gather,
        CoordinatorConfig::default(),
    ));

    let result = coordinator
        .query_agentic_with_history_and_session(
            "who is michael chen",
            Vec::new(),
            SynthesisModelFamily::AutoFusion,
            12,
            std::collections::HashSet::new(),
            None,
        )
        .await
        .expect("query");

    let answer = result.synthesis_prompt;
    assert!(
        answer.contains("multiple distinct individuals") || answer.contains("distinct contexts"),
        "General homonym disambiguation must trigger for Michael Chen (even in lowercase query): {}",
        answer
    );
    assert!(answer.contains("### Clinical & Healthcare Records"), "{}", answer);
    assert!(answer.contains("### Software Engineering, Architecture & Cybersecurity"), "{}", answer);
}

#[tokio::test]
async fn test_three_node_one_hop_mesh_relay_parent_rlm_expansion_and_provenance() {
    let dir_a = tempdir().expect("dir_a");
    let dir_b = tempdir().expect("dir_b");
    let dir_c = tempdir().expect("dir_c");

    // Ensure shared folders allow our temporary directories across in-process nodes
    {
        let controller = quorum_coordinator::dlp_mesh::global_mesh_dlp_controller();
        let mut guard = controller.settings.write().unwrap();
        guard.mesh.p2p_enabled = true;
        guard.mesh.require_explicit_folder_share = false;
    }

    let storage_a = Arc::new(
        quorum_storage::StorageEngine::open(quorum_storage::StorageConfig::new(dir_a.path().to_path_buf()))
            .await
            .expect("storage_a"),
    );
    let storage_b = Arc::new(
        quorum_storage::StorageEngine::open(quorum_storage::StorageConfig::new(dir_b.path().to_path_buf()))
            .await
            .expect("storage_b"),
    );
    let storage_c = Arc::new(
        quorum_storage::StorageEngine::open(quorum_storage::StorageConfig::new(dir_c.path().to_path_buf()))
            .await
            .expect("storage_c"),
    );

    let seed_a = [0x11u8; 32];
    let pubkey_a = ed25519_dalek::SigningKey::from_bytes(&seed_a)
        .verifying_key()
        .to_bytes();
    let peer_a_id = quorum_network::derive_peer_id_from_pubkey(&pubkey_a)
        .expect("peer_a")
        .to_string();
    let peer_b_id = "12D3KooWEcNhbaJtvJCF6QqvWwzxWTXBMfMqvxrRbxKbAZ2ZvKR5".to_string();
    let peer_c_id = "12D3KooWKHc3HiYDTmS9jymRJxHjuBEQ6Z3veB21KmzuH52iRFYu".to_string();

    let emb = vec![0.05f32; 768];

    // Node A (Texas laptop): hosts Academic cluster
    storage_a
        .insert_chunks(&[DocumentChunk::new(
            "node_a_scholar:0",
            "node_a_scholar",
            "C:/TexasDocs/Women_Race_Class_Summary.docx",
            1,
            30,
            0,
            emb.clone(),
            "Angela Davis authored the 1981 landmark critical theory book Women, Race & Class, examining historical labor, abolitionism, and intersectionality across nineteen chapters.",
            None,
        )
        .unwrap()])
        .await
        .unwrap();

    // Node B (Home NAT Gateway): hosts Ministry cluster
    storage_b
        .insert_chunks(&[DocumentChunk::new(
            "node_b_ministry:0",
            "node_b_ministry",
            "C:/GatewayDocs/Unity_Ministry_Board.docx",
            1,
            30,
            0,
            emb.clone(),
            "Reverend Angela Davis serves on the STEWARD ministry board and leads Unity spiritual teaching sessions focused on community stewardship and contemplative service.",
            None,
        )
        .unwrap()])
        .await
        .unwrap();

    // Node C (Home LAN Peer behind Gateway B): multi-chunk Lease document (>1,200 bytes across sibling chunks)
    // Chunk 0 is short (<200 bytes), while Chunks 1 & 2 hold rich lease terms that RLM 10,000-byte parent expansion stitches!
    let c0 = DocumentChunk::new(
        "node_c_lease:0",
        "node_c_lease",
        "C:/LanPeerDocs/Castiglione_Lease_2015.doc",
        1,
        10,
        0,
        emb.clone(),
        "SIMPLE MONTH TO MONTH YEAR LEASE AGREEMENT entered into between Angela Davis (landlord) and Aerial McDougle (tenant).",
        None,
    )
    .unwrap();
    let c1 = DocumentChunk::new(
        "node_c_lease:1",
        "node_c_lease",
        "C:/LanPeerDocs/Castiglione_Lease_2015.doc",
        11,
        35,
        0,
        emb.clone(),
        "The leased dwelling unit is located at 2913 Castiglione St., New Orleans, LA 70119 with monthly rent of $725.00 payable on the first business day of each calendar month. Security deposit of $725.00 is held in escrow.",
        None,
    )
    .unwrap();
    let c2 = DocumentChunk::new(
        "node_c_lease:2",
        "node_c_lease",
        "C:/LanPeerDocs/Castiglione_Lease_2015.doc",
        36,
        65,
        0,
        emb,
        "No subletting is permitted without prior written consent of the lessor. Renters insurance covering personal property is strongly recommended for the full duration of occupancy at Castiglione St.",
        None,
    )
    .unwrap();
    storage_c.insert_chunks(&[c0, c1, c2]).await.unwrap();

    // Wire 3-node topology: Node A -> Gateway B -> LAN Peer C
    let handler_c = Arc::new(OsoosiMeshInboundHandler::new(
        Arc::clone(&storage_c) as Arc<dyn quorum_coordinator::StorageSearcher>,
        peer_c_id.clone(),
    ));
    let bridge_b_to_c = Arc::new(HandlerBridgeDispatcher {
        handler: Arc::clone(&handler_c),
    });
    let handler_b = Arc::new(
        OsoosiMeshInboundHandler::new(
            Arc::clone(&storage_b) as Arc<dyn quorum_coordinator::StorageSearcher>,
            peer_b_id.clone(),
        )
        .with_dispatcher(bridge_b_to_c),
    );
    let bridge_a_to_b = Arc::new(HandlerBridgeDispatcher {
        handler: Arc::clone(&handler_b),
    });

    let acl = Arc::new(tokio::sync::RwLock::new(PeerAclManager::default()));
    {
        let mut g = acl.write().await;
        g.register_peer_id(peer_b_id.clone(), AccessTier::Tier0Public);
        g.register_peer_id(peer_c_id.clone(), AccessTier::Tier0Public);
    }

    let mut cfg = CoordinatorConfig::default();
    cfg.timeout_ms = 5000;
    let scatter_a = Arc::new(ScatterGatherEngine::new(
        Arc::clone(&storage_a) as Arc<dyn quorum_coordinator::StorageSearcher>,
        bridge_a_to_b,
        acl,
        cfg.clone(),
        seed_a,
        peer_a_id,
    ));

    // Verify scatter-gather provenance & RLM 10,000-byte parent expansion on relayed Peer C chunk
    let (fused, _volatile, _elapsed_ms, _local_vec_hits) = scatter_a
        .execute_query_with_cached_vector("WHO IS ANGELA DAVIS", &[0.05f32; 768], None, 0, 12)
        .await;
    let diag = scatter_a
        .last_diagnostics()
        .await
        .expect("federated diagnostics");

    let peer_c_chunk = fused
        .iter()
        .find(|c| c.source_peer == peer_c_id)
        .expect("Relayed chunk from LAN Peer C must preserve Peer C's authentic origin_peer_id");
    assert!(
        peer_c_chunk.chunk.text_content.contains("monthly rent of $725.00")
            && peer_c_chunk.chunk.text_content.contains("No subletting is permitted")
            && peer_c_chunk.chunk.text_content.contains("Castiglione St."),
        "Peer C inbound handler must RLM-expand full parent window across sibling chunks before returning: {}",
        peer_c_chunk.chunk.text_content
    );
    assert!(
        peer_c_chunk.chunk.text_content.contains("[REDACTED:GLINER_LOCATION]")
            || peer_c_chunk.chunk.text_content.contains("2913 Castiglione St."),
        "Peer C outbound Three-Engine DLP must inspect expanded parent window prior to wire egress: {}",
        peer_c_chunk.chunk.text_content
    );
    assert!(
        diag.contributing_peer_ids.contains(&peer_b_id) && diag.contributing_peer_ids.contains(&peer_c_id),
        "Diagnostics must credit both Gateway B and relayed LAN Peer C: {:?}",
        diag.contributing_peer_ids
    );

    // Verify full 1-question synthesis across all 3 hosts
    let coordinator_a = QueryCoordinator::new(scatter_a, cfg);
    let res = coordinator_a
        .query_agentic_with_history_and_session(
            "WHO IS ANGELA DAVIS",
            Vec::new(),
            SynthesisModelFamily::AutoFusion,
            12,
            std::collections::HashSet::new(),
            None,
        )
        .await
        .expect("agentic query across 3 hosts");

    let ans = res.synthesis_prompt;
    assert!(ans.contains("Women, Race & Class"), "Must include Node A Academic record: {}", ans);
    assert!(ans.contains("STEWARD"), "Must include Gateway Node B Ministry record: {}", ans);
    assert!(
        ans.contains("Castiglione") && ans.contains("$725.00") && ans.contains("Aerial McDougle"),
        "Must include relayed LAN Peer C Lease record: {}",
        ans
    );
    assert!(ans.len() >= 900, "Cross-all-hosts disambiguated RLM answer must be thorough and detailed (got {} chars)", ans.len());
    println!(
        "\n=== [REGRESSION TEST OUTPUT: 3-HOST 1-HOP MESH RELAY + 10KB RLM EXPANSION (WHO IS ANGELA DAVIS)] ===\nContributing Peers: {:?}\n{}\n=== [END 3-HOST OUTPUT] ===",
        diag.contributing_peer_ids, ans
    );
}

#[tokio::test]
async fn test_expanded_window_outbound_and_inbound_dlp_and_rrf_preservation() {
    use quorum_coordinator::dlp_mesh::{
        DlpEnforcementMode, OsoosiMeshDlpController, PersistedDaemonSettings,
    };
    use quorum_coordinator::fusion::RrfCombiner;
    use quorum_types::CandidateChunkDto;
    use zeroize::Zeroize;

    let mut settings = PersistedDaemonSettings::default();
    settings.mesh.p2p_enabled = true;
    settings.mesh.require_explicit_folder_share = false;
    settings.dlp.enabled = true;
    settings.dlp.mode = DlpEnforcementMode::Redact;
    settings.dlp.protect_ssn = true;

    let controller = OsoosiMeshDlpController {
        settings: std::sync::RwLock::new(settings),
        stats: std::sync::RwLock::new(Default::default()),
        settings_file_path: std::sync::RwLock::new(None),
        hmac_secret: [0x33u8; 32],
    };

    let canonical_content = "Angela Davis (landlord) entered into a residential lease agreement.";
    let canonical_hash = DocumentChunk::compute_blake3_hash(canonical_content);
    let raw_window = "Angela Davis (landlord) entered into a residential lease agreement. Tenant SSN: 123-45-6789 and monthly rent $725.00.";

    let outbound_dto = CandidateChunkDto {
        chunk_id: "lease_dlp:0".to_string(),
        file_path: "C:/Leases/Lease_DLP.doc".to_string(),
        line_start: 1,
        line_end: 20,
        content: canonical_content.to_string(),
        score: 0.91,
        access_tier: 0,
        origin_peer_id: Some("12D3KooWPeerDlp".to_string()),
        expanded_window: Some(raw_window.to_string()),
    };

    // 1. Outbound Redact mode: scrubs SSN inside expanded_window while keeping canonical content intact
    let outbound_filtered =
        controller.filter_and_enforce_outbound_mesh_chunks(vec![outbound_dto.clone()], "peer_req");
    assert_eq!(outbound_filtered.len(), 1);
    let win_after_outbound = outbound_filtered[0]
        .expanded_window
        .as_deref()
        .expect("expanded_window retained under Redact");
    assert!(
        !win_after_outbound.contains("123-45-6789")
            && win_after_outbound.contains("[REDACTED:PHI_SSN]"),
        "Outbound DLP must redact SSN in expanded_window: {}",
        win_after_outbound
    );
    assert_eq!(outbound_filtered[0].content, canonical_content);

    // 2. Outbound Block mode: blocks the entire DTO if expanded_window contains unshareable PHI/PII
    {
        let mut g = controller.settings.write().unwrap();
        g.dlp.mode = DlpEnforcementMode::Block;
    }
    let blocked_outbound =
        controller.filter_and_enforce_outbound_mesh_chunks(vec![outbound_dto.clone()], "peer_req");
    assert!(
        blocked_outbound.is_empty(),
        "Outbound Block policy must block chunk when expanded_window contains SSN"
    );

    // 3. Inbound Block mode: clears tainted expanded_window = None while keeping clean canonical chunk
    let inbound_volatile_raw = outbound_dto.clone().into_volatile_remote_chunk("12D3KooWPeerDlp");
    assert!(inbound_volatile_raw.expanded_window.is_some());
    let inbound_blocked_win = controller.enforce_inbound_remote_chunks(vec![inbound_volatile_raw]);
    assert_eq!(inbound_blocked_win.len(), 1);
    assert!(
        inbound_blocked_win[0].expanded_window.is_none(),
        "Inbound Block policy must clear tainted expanded_window to None"
    );

    // 4. Inbound Redact mode + VolatileRemoteChunk zeroization + RRF fusion preservation
    {
        let mut g = controller.settings.write().unwrap();
        g.dlp.mode = DlpEnforcementMode::Redact;
    }
    let mut inbound_clean = controller
        .enforce_inbound_remote_chunks(vec![outbound_dto
            .clone()
            .into_volatile_remote_chunk("12D3KooWPeerDlp")]);
    assert_eq!(inbound_clean.len(), 1);
    let scrubbed_win = inbound_clean[0]
        .expanded_window
        .as_deref()
        .expect("inbound redacted window")
        .to_string();
    assert!(!scrubbed_win.contains("123-45-6789"));
    assert!(scrubbed_win.contains("$725.00"));

    // Zeroize verification on VolatileRemoteChunk.expanded_window
    inbound_clean[0].zeroize();
    assert!(
        inbound_clean[0]
            .expanded_window
            .as_deref()
            .map_or(true, |s| s.is_empty()),
        "VolatileRemoteChunk.zeroize() must wipe expanded_window"
    );

    // RRF consumption: blake3_hash uses canonical content, text_content uses scrubbed expanded_window
    let fused = RrfCombiner::fuse_rankings_with_peers(
        Vec::new(),
        vec![("12D3KooWPeerDlp".to_string(), outbound_filtered)],
        60.0,
        10,
    );
    assert_eq!(fused.len(), 1);
    assert_eq!(
        fused[0].chunk.blake3_hash, canonical_hash,
        "RrfCombiner must preserve canonical chunk content BLAKE3 hash"
    );
    assert!(
        fused[0].chunk.text_content.contains("$725.00")
            && !fused[0].chunk.text_content.contains("123-45-6789"),
        "RrfCombiner must populate text_content from DLP-scrubbed expanded_window: {}",
        fused[0].chunk.text_content
    );
}

#[test]
fn test_clean_chunk_text_strips_inline_and_sliced_kind_file_banners_and_spiritual_cluster() {
    // 1. Sliced mid-banner tails (`| Kind: article | File: ...]`, `Kind: article | File: ...]`, `| Author: ... | Kind: ... | File: ...]`)
    let sliced_1 = "| Kind: article | File: Ava Davis LEASE AGREEMENT.doc] SIMPLE MONTH TO MONTH LEASE AGREEMENT between Angela Davis (lessor) and Ava Davis (tenant).";
    let cleaned_1 = DeterministicOfflineSynthesisEngine::clean_chunk_text(sliced_1);
    assert!(
        !cleaned_1.contains("Kind: article") && !cleaned_1.contains("Ava Davis LEASE AGREEMENT.doc]"),
        "Must strip leading `| Kind: article | File: ...]`: {}",
        cleaned_1
    );
    assert!(cleaned_1.contains("SIMPLE MONTH TO MONTH LEASE AGREEMENT"));

    let sliced_2 = "Kind: article | File: Fun Storytelling Themes.docx] Creative narrative arcs engage readers from the opening paragraph.";
    let cleaned_2 = DeterministicOfflineSynthesisEngine::clean_chunk_text(sliced_2);
    assert!(
        !cleaned_2.contains("Kind: article") && !cleaned_2.contains("Fun Storytelling Themes.docx]"),
        "Must strip `Kind: article | File: ...]`: {}",
        cleaned_2
    );
    assert!(cleaned_2.contains("Creative narrative arcs"));

    let sliced_author = "Themes\" | Author: Angela Davis | Kind: article | File: Breath and Hierarchy.docx] Conscious breathing restores calm focus.";
    let cleaned_author = DeterministicOfflineSynthesisEngine::clean_chunk_text(sliced_author);
    assert!(
        !cleaned_author.to_ascii_lowercase().contains("angela davis")
            && !cleaned_author.contains("Breath and Hierarchy.docx]"),
        "Must strip sliced Author/Kind/File banner before token matching: {}",
        cleaned_author
    );

    // 1b. Sliced banner with `| Rev: 2 |` (emitted by `chunker::build_contextual_header`) and mid-`Author:` byte slice
    let sliced_with_rev = "Themes\" | Author: Angela Davis | Rev: 2 | Kind: article | File: Breath and Hierarchy.docx] Conscious breathing restores calm focus.";
    let cleaned_rev = DeterministicOfflineSynthesisEngine::clean_chunk_text(sliced_with_rev);
    assert!(
        !cleaned_rev.to_ascii_lowercase().contains("angela davis")
            && !cleaned_rev.contains("Rev: 2")
            && !cleaned_rev.contains("Breath and Hierarchy.docx]"),
        "Must strip sliced Author + Rev + Kind + File banner: {}",
        cleaned_rev
    );

    let sliced_mid_author = "Angela Davis | Kind: article | File: Breath and Hierarchy.docx] Conscious breathing restores calm focus.";
    let cleaned_mid_author = DeterministicOfflineSynthesisEngine::clean_chunk_text(sliced_mid_author);
    assert!(
        !cleaned_mid_author.to_ascii_lowercase().contains("angela davis")
            && !cleaned_mid_author.contains("Breath and Hierarchy.docx]"),
        "Must strip mid-Author byte-sliced banner: {}",
        cleaned_mid_author
    );

    // 1c. Cross-OS family key parity between Windows backslash paths and POSIX slash paths
    assert_eq!(
        DeterministicOfflineSynthesisEngine::derive_document_family_key(
            "D:\\HostWEcNh\\Women Race Class Summary (1).docx"
        ),
        DeterministicOfflineSynthesisEngine::derive_document_family_key(
            "/home/host_linux/Women Race Class Summary.docx"
        ),
        "Windows backslash and POSIX slash paths must derive the identical document family key on all OSes"
    );

    // 2. Inline mid-line `[Document: ...]` and `[Word/Document ...]` banners
    let inline_banner = "First paragraph sentence. [Document: \"Ava Davis LEASE AGREEMENT\" | Author: Angela Davis | Kind: article | File: Ava Davis LEASE AGREEMENT.doc] Second paragraph sentence.";
    let cleaned_inline = DeterministicOfflineSynthesisEngine::clean_chunk_text(inline_banner);
    assert!(
        !cleaned_inline.contains("[Document:") && !cleaned_inline.contains("Kind: article"),
        "Must strip inline mid-line [Document: ...] banner: {}",
        cleaned_inline
    );
    assert!(
        cleaned_inline.contains("First paragraph sentence.")
            && cleaned_inline.contains("Second paragraph sentence.")
    );

    // 3. Spiritual/New Thought dissertation must classify as Religious Ministry, NOT Academic Scholarship
    let spiritual_dissertation = "Angela Davis explores New Thought philosophy, Ma'at, divine intelligence, yarnspinner cosmology, and the planetary human in this metaphysical dissertation and thesis on spiritual affirmations.";
    assert_eq!(
        classify_entity_domain_cluster("C:/Ministry/Planetary_Human_Thesis.docx", spiritual_dissertation),
        "Religious Ministry, Spiritual Teaching & Organizational Stewardship"
    );
}

#[tokio::test]
async fn test_who_is_angela_davis_rejects_distractors_and_aligns_citations_1_to_1_across_duplicates() {
    let dummy_emb = vec![0.02f32; 768];

    // Canonical Cluster 1: Academic (present on BOTH local and remote peer -> must deduplicate to 1 family!)
    let scholar_local = ScoredChunk::new(
        DocumentChunk::new(
            "local_wrc:0",
            "local_wrc",
            "C:/HostWDRDL/Women Race Class Summary.docx",
            1,
            25,
            0,
            dummy_emb.clone(),
            "Women, Race & Class is a landmark critical theory work by Angela Davis, first published in 1981, analyzing race, gender, and class.",
            None,
        )
        .unwrap(),
        0.96,
        "local",
        false,
    );
    let scholar_remote_dup = ScoredChunk::new(
        DocumentChunk::new(
            "remote_wrc:0",
            "remote_wrc",
            "D:/HostWEcNh/Women Race Class Summary.docx",
            1,
            28,
            0,
            dummy_emb.clone(),
            "Women, Race & Class (1981) by American scholar and political activist Angela Davis examines abolitionism and critical theory across thirteen chapters.",
            None,
        )
        .unwrap(),
        0.94,
        "12D3KooWEcNhbaJtvJCF",
        true,
    );

    // Canonical Cluster 2: Lease (Ava Davis lease duplicated across local + remote, plus remote Susan lease)
    let ava_local = ScoredChunk::new(
        DocumentChunk::new(
            "local_ava:0",
            "local_ava",
            "C:/HostWDRDL/Ava Davis LEASE AGREEMENT.doc",
            1,
            25,
            0,
            dummy_emb.clone(),
            "| Kind: article | File: Ava Davis LEASE AGREEMENT.doc] SIMPLE MONTH TO MONTH LEASE AGREEMENT between Firldeal (Angela Davis) Breure (lessor) and Ava Davis (tenant) at 1967 Hope St., New Orleans, LA.",
            None,
        )
        .unwrap(),
        0.92,
        "local",
        false,
    );
    let ava_remote_dup = ScoredChunk::new(
        DocumentChunk::new(
            "remote_ava:0",
            "remote_ava",
            "D:/HostWEcNh/Ava Davis LEASE AGREEMENT (1).doc",
            1,
            25,
            0,
            dummy_emb.clone(),
            "SIMPLE MONTH TO MONTH LEASE AGREEMENT between Firldeal (Angela Davis) Breure (lessor) and Ava Davis (tenant) for 1967 Hope St., New Orleans, LA.",
            None,
        )
        .unwrap(),
        0.89,
        "12D3KooWEcNhbaJtvJCF",
        true,
    );
    let susan_remote = ScoredChunk::new(
        DocumentChunk::new(
            "remote_susan:0",
            "remote_susan",
            "E:/HostWKHc3/Susan MONTH TO MONTH LEASE AGREEMENT.doc",
            1,
            30,
            0,
            dummy_emb.clone(),
            "SIMPLE LEASE AGREEMENT between Angela Davis (landlord) and Casey Ringgold (tenant) for the dwelling unit at 2913 Castiglione St., New Orleans, LA 70119 with monthly rent of $614.00.",
            None,
        )
        .unwrap(),
        0.90,
        "12D3KooWKHc3HiYDTmS9",
        true,
    );

    // Canonical Cluster 3: Spiritual / New Thought Ministry (remote peer)
    let ministry_remote = ScoredChunk::new(
        DocumentChunk::new(
            "remote_ministry:0",
            "remote_ministry",
            "D:/HostWEcNh/Planetary_Human_Manuscript.docx",
            1,
            30,
            0,
            dummy_emb.clone(),
            "Reverend Angela Davis examines New Thought ministry, Ma'at, divine intelligence, and the planetary human in this metaphysical dissertation.",
            None,
        )
        .unwrap(),
        0.88,
        "12D3KooWEcNhbaJtvJCF",
        true,
    );

    // Distractor 1: Non-contiguous Alderman Davis + distant Angela (`Good Times Murder Mystery.docx`)
    let distractor_murder_mystery = ScoredChunk::new(
        DocumentChunk::new(
            "dist_mystery:0",
            "dist_mystery",
            "D:/HostWEcNh/Good Times Murder Mystery.docx",
            1,
            40,
            0,
            dummy_emb.clone(),
            "Alderman Davis arrived at the Chicago banquet hall at midnight to question the suspects about the missing ledger while three tables away across the crowded ballroom Angela whispered a clue to the detective.",
            None,
        )
        .unwrap(),
        0.87,
        "12D3KooWEcNhbaJtvJCF",
        true,
    );

    // Distractor 2: Header-only `Author: Angela Davis` + single-name `"Angela"` in body (`Affirmations Lost and Restored.docx`)
    let distractor_affirmations = ScoredChunk::new(
        DocumentChunk::new(
            "dist_affirm:0",
            "dist_affirm",
            "D:/HostWEcNh/Affirmations Lost and Restored.docx",
            1,
            25,
            0,
            dummy_emb.clone(),
            "[Document: \"Affirmations Lost and Restored\" | Author: Angela Davis | Kind: article | File: Affirmations Lost and Restored.docx]\nDaily spoken affirmations help Angela cultivate inner peace and gratitude.",
            None,
        )
        .unwrap(),
        0.86,
        "12D3KooWEcNhbaJtvJCF",
        true,
    );

    // Distractor 3: Sliced mid-banner with `Rev:` and mid-`Author:` slice (`Breath and Hierarchy.docx` + `Fun Storytelling Themes.docx`)
    let distractor_breath = ScoredChunk::new(
        DocumentChunk::new(
            "dist_breath:0",
            "dist_breath",
            "D:\\HostWEcNh\\Breath and Hierarchy.docx",
            1,
            25,
            0,
            dummy_emb.clone(),
            "Themes\" | Author: Angela Davis | Rev: 2 | Kind: article | File: Breath and Hierarchy.docx] Conscious breathwork balances somatic hierarchy and nervous system regulation.",
            None,
        )
        .unwrap(),
        0.85,
        "12D3KooWEcNhbaJtvJCF",
        true,
    );
    let distractor_mid_author = ScoredChunk::new(
        DocumentChunk::new(
            "dist_story:0",
            "dist_story",
            "D:\\HostWEcNh\\Fun Storytelling Themes.docx",
            1,
            25,
            0,
            dummy_emb,
            "Angela Davis | Kind: article | File: Fun Storytelling Themes.docx] Creative narrative arcs engage listeners from the opening sentence.",
            None,
        )
        .unwrap(),
        0.84,
        "12D3KooWEcNhbaJtvJCF",
        true,
    );

    let all_inputs = vec![
        scholar_local,
        scholar_remote_dup,
        ava_local,
        ava_remote_dup,
        susan_remote,
        ministry_remote,
        distractor_murder_mystery,
        distractor_affirmations,
        distractor_breath,
        distractor_mid_author,
    ];

    for query in ["Who is Angela Davis", "WHO IS ANGELA DAVIS"] {
        let (answer, citations) = DeterministicOfflineSynthesisEngine::synthesize_with_history(
            query,
            query,
            &[],
            &all_inputs,
            "offline",
            None,
        );

        // Must reject Alderman Davis and header-only Author essays
        assert!(
            !answer.contains("Good Times Murder Mystery") && !answer.contains("Alderman Davis"),
            "Must reject non-contiguous Alderman Davis distractor for `{query}`:\n{answer}"
        );
        assert!(
            !answer.contains("Affirmations Lost and Restored"),
            "Must reject Author-header + single-first-name distractor for `{query}`:\n{answer}"
        );
        assert!(
            !answer.contains("Breath and Hierarchy") && !answer.contains("Fun Storytelling Themes"),
            "Must reject sliced Author/Rev and mid-Author banner distractors for `{query}`:\n{answer}"
        );
        assert!(
            !answer.contains("Kind: article"),
            "Must strip sliced `| Kind: article | File: ...]` banners for `{query}`:\n{answer}"
        );
        assert!(
            !answer.contains("***:") && !answer.contains("*:**"),
            "Must never emit broken `***:` CommonMark italics around Mesh Peer badge for `{query}`:\n{answer}"
        );

        // Exactly 4 unique canonical document families must survive:
        // 1. Women Race Class Summary, 2. Ava Davis LEASE AGREEMENT, 3. Susan MONTH TO MONTH LEASE AGREEMENT, 4. Planetary_Human_Manuscript
        assert_eq!(
            citations.len(),
            4,
            "Duplicate local+remote families must collapse to 4 unique canonical citations for `{query}`, got {}: {:?}",
            citations.len(),
            citations.iter().map(|c| &c.file_path).collect::<Vec<_>>()
        );

        // Verify 1-to-1 citation alignment: [1]..[4] present, zero [5]..[9] out-of-bounds citations!
        for k in 1..=4 {
            assert!(
                answer.contains(&format!("[{k}]")),
                "Expected citation [{k}] in answer for `{query}`:\n{answer}"
            );
        }
        for oob in 5..=12 {
            assert!(
                !answer.contains(&format!("[{oob}]")),
                "Dangling out-of-bounds citation [{oob}] leaked for `{query}`:\n{answer}"
            );
        }

        // Verify Sources footer has exactly 4 document bullet links matching citations.len()
        let source_bullets = answer
            .lines()
            .filter(|l| l.trim_start().starts_with("- [📄 "))
            .count();
        assert_eq!(
            source_bullets,
            citations.len(),
            "Sources block bullet count ({source_bullets}) must match citations.len() ({}) 1-to-1:\n{answer}",
            citations.len()
        );
    }
}
