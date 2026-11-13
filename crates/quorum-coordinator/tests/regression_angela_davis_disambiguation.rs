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
        peer_c_chunk.chunk.text_content.contains("2913 Castiglione St.")
            && peer_c_chunk.chunk.text_content.contains("No subletting is permitted"),
        "Peer C inbound handler must RLM-expand full parent window across sibling chunks before returning: {}",
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
    assert!(ans.contains("2913 Castiglione St."), "Must include relayed LAN Peer C Lease record: {}", ans);
    assert!(ans.len() >= 900, "Cross-all-hosts disambiguated RLM answer must be thorough and detailed (got {} chars)", ans.len());
}
