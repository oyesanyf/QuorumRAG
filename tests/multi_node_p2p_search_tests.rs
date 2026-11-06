//! Multi-Node Automated Integration Test Suite for QuorumRAG P2P Mesh
//!
//! Validates:
//! 1. Multi-node libp2p swarm connection, point-to-point query routing, and response aggregation.
//! 2. Wire protocol query aggregation with real StorageEngine, SwarmMeshDispatcher, and OsoosiMeshInboundHandler.
//! 3. Out-of-the-box fresh install search parity: remote indexed documents return chunks without manual ACL configuration.
//! 4. Authentic peer citations: [Peer:File:Lines] citations with valid scores and peer IDs.
//! 5. Hybrid fusion combining local chunks and remote peer chunks into a unified ranked result set.

use quorum_coordinator::{
    global_mesh_dlp_controller, CoordinatorConfig, OsoosiMeshInboundHandler, PeerAclManager,
    QueryCoordinator, ScatterGatherEngine, SwarmMeshDispatcher,
};
use quorum_network::{start_network_node, NetworkConfig};
use quorum_storage::{StorageConfig, StorageEngine};
use quorum_types::DocumentChunk;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn test_multi_node_p2p_wire_query_aggregation() {
    // 0. Ensure global Mesh DLP controller is initialized with out-of-the-box defaults (require_explicit_folder_share: false)
    let dlp_controller = global_mesh_dlp_controller();
    {
        let mut guard = dlp_controller.settings.write().unwrap();
        guard.mesh.p2p_enabled = true;
        guard.mesh.require_explicit_folder_share = false;
        guard.mesh.shared_folders.clear();
    }

    // 1. Setup Node B (remote data owner)
    let temp_dir_b = tempfile::tempdir().expect("Node B temp dir");
    let storage_cfg_b = StorageConfig::new(temp_dir_b.path().to_path_buf());
    let storage_b = Arc::new(StorageEngine::open(storage_cfg_b).await.expect("StorageEngine B"));

    let seed_b = [0x22u8; 32];
    let secret_b = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(seed_b).unwrap();
    let ed_kp_b = quorum_network::libp2p::identity::ed25519::Keypair::from(secret_b);
    let peer_id_b = quorum_network::libp2p::identity::Keypair::from(ed_kp_b).public().to_peer_id();
    let peer_id_b_str = peer_id_b.to_string();

    // Index sample documents into Node B's storage
    let doc_b_path = r"C:\Users\engineer\Documents\p2p_mesh_specification.md";
    let chunk_b = DocumentChunk::new(
        "chunk_b_mesh_spec",
        "doc_mesh_specification",
        doc_b_path,
        1,
        35,
        0, // Tier 0 Public
        vec![0.15; 768],
        "QuorumRAG multi-host peer-to-peer mesh architecture ensures out-of-the-box parity between local development and MSI-installed production environments.",
        None,
    )
    .expect("Valid chunk B");

    storage_b.insert_chunks(&[chunk_b]).await.expect("Insert chunks into Node B");

    // Start Node B's libp2p network node with OsoosiMeshInboundHandler
    let inbound_handler_b = Arc::new(OsoosiMeshInboundHandler::new(
        Arc::clone(&storage_b) as Arc<dyn quorum_coordinator::StorageSearcher>,
        peer_id_b_str.clone(),
    ));

    let mut net_config_b = NetworkConfig::new_localhost();
    net_config_b.ed25519_seed = Some(seed_b);

    let (_join_b, handle_b) = start_network_node(net_config_b, Some(inbound_handler_b))
        .await
        .expect("Start network node B");

    let addrs_b = handle_b.listen_addresses().await.expect("Node B listen addresses");
    let tcp_addr_b = addrs_b
        .iter()
        .find(|a| a.to_string().contains("/tcp/"))
        .cloned()
        .expect("Node B should have TCP listen address");

    // 2. Setup Node A (querying coordinator node)
    let temp_dir_a = tempfile::tempdir().expect("Node A temp dir");
    let storage_cfg_a = StorageConfig::new(temp_dir_a.path().to_path_buf());
    let storage_a = Arc::new(StorageEngine::open(storage_cfg_a).await.expect("StorageEngine A"));

    let seed_a = [0x11u8; 32];
    let secret_a = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(seed_a).unwrap();
    let ed_kp_a = quorum_network::libp2p::identity::ed25519::Keypair::from(secret_a);
    let peer_id_a = quorum_network::libp2p::identity::Keypair::from(ed_kp_a).public().to_peer_id();
    let peer_id_a_str = peer_id_a.to_string();

    let mut net_config_a = NetworkConfig::new_localhost();
    net_config_a.ed25519_seed = Some(seed_a);

    let (_join_a, handle_a) = start_network_node(net_config_a, None)
        .await
        .expect("Start network node A");

    // Node A dials Node B over localhost TCP
    handle_a.dial(tcp_addr_b).await.expect("Node A dials Node B");

    // Allow libp2p Identify and connection handshake to settle
    tokio::time::sleep(Duration::from_millis(350)).await;

    let connected_peers_a = handle_a.connected_peers().await.expect("Connected peers");
    assert!(
        connected_peers_a.contains(&peer_id_b),
        "Node A must be connected to Node B over libp2p"
    );

    // 3. Assemble Node A's QueryCoordinator with real SwarmMeshDispatcher
    let mesh_dispatcher = Arc::new(SwarmMeshDispatcher {
        handle: handle_a.clone(),
    });

    let mut coord_cfg = CoordinatorConfig::default();
    coord_cfg.max_peer_responses = 8;
    coord_cfg.timeout_ms = 3500;

    let acl_manager = Arc::new(tokio::sync::RwLock::new(PeerAclManager::default()));

    let engine = Arc::new(ScatterGatherEngine::new(
        Arc::clone(&storage_a) as Arc<dyn quorum_coordinator::StorageSearcher>,
        mesh_dispatcher,
        acl_manager,
        coord_cfg.clone(),
        seed_a,
        peer_id_a_str.clone(),
    ));

    let coordinator = QueryCoordinator::new(engine, coord_cfg);

    // 4. Execute query on Node A for mesh architecture
    let prompt = "QuorumRAG multi-host peer-to-peer mesh architecture";
    let query_result = coordinator
        .query(prompt, 10)
        .await
        .expect("Coordinator query execution succeeds");

    // 5. Assertions on Aggregated Results
    assert!(
        !query_result.chunks.is_empty(),
        "Query result must contain chunks aggregated from Node B"
    );

    let found_chunk_b = query_result
        .chunks
        .iter()
        .find(|c| c.chunk.chunk_id == "chunk_b_mesh_spec");

    assert!(
        found_chunk_b.is_some(),
        "Node B's chunk must be present in aggregated search results on Node A"
    );

    let chunk_b_result = found_chunk_b.unwrap();
    assert!(
        chunk_b_result.is_remote,
        "Aggregated chunk must be labeled as is_remote: true"
    );
    assert_eq!(
        chunk_b_result.source_peer, peer_id_b_str,
        "Source peer must match Node B's exact PeerId"
    );
    assert!(
        chunk_b_result.score > 0.0,
        "Aggregated chunk must have a positive RRF score"
    );

    // 6. Assertions on Authentic Citations
    assert!(
        !query_result.sources_cited.is_empty(),
        "Sources cited must contain citations for remote chunks"
    );

    let citation_b = query_result
        .sources_cited
        .iter()
        .find(|c| c.file_path == doc_b_path);

    assert!(
        citation_b.is_some(),
        "Citation for Node B's document must exist in sources_cited"
    );

    let cit = citation_b.unwrap();
    assert_eq!(cit.peer_id, peer_id_b_str);
    assert_eq!(cit.line_start, 1);
    assert_eq!(cit.line_end, 35);
    assert!(cit.is_external_node);
    assert!(cit.snippet.contains("peer-to-peer mesh architecture"));

    // Verify format citation string matches [Peer:File:Lines]
    let citation_formatted = format!("[Peer:{}:{}:Lines {}-{}]", cit.peer_id, cit.file_path, cit.line_start, cit.line_end);
    assert!(
        citation_formatted.contains(&peer_id_b_str),
        "Formatted citation must include Node B's peer ID"
    );
    assert!(
        citation_formatted.contains("Lines 1-35"),
        "Formatted citation must include valid line bounds"
    );

    // 7. Clean Shutdown
    let _ = handle_a.shutdown().await;
    let _ = handle_b.shutdown().await;
}

#[tokio::test]
async fn test_multi_node_bidirectional_hybrid_fusion() {
    let dlp_controller = global_mesh_dlp_controller();
    {
        let mut guard = dlp_controller.settings.write().unwrap();
        guard.mesh.p2p_enabled = true;
        guard.mesh.require_explicit_folder_share = false;
        guard.mesh.shared_folders.clear();
    }

    // Node B setup
    let temp_dir_b = tempfile::tempdir().expect("Node B temp dir");
    let storage_cfg_b = StorageConfig::new(temp_dir_b.path().to_path_buf());
    let storage_b = Arc::new(StorageEngine::open(storage_cfg_b).await.expect("StorageEngine B"));

    let seed_b = [0x44u8; 32];
    let secret_b = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(seed_b).unwrap();
    let ed_kp_b = quorum_network::libp2p::identity::ed25519::Keypair::from(secret_b);
    let peer_id_b = quorum_network::libp2p::identity::Keypair::from(ed_kp_b).public().to_peer_id();

    let remote_doc_path = r"C:\Users\operator\Documents\swarm_operations.md";
    let remote_chunk = DocumentChunk::new(
        "chunk_remote_swarm_ops",
        "doc_swarm_ops",
        remote_doc_path,
        10,
        50,
        0,
        vec![0.2; 768],
        "Remote Swarm Operations: Dynamic topology discovery and reciprocal rank fusion across mesh nodes.",
        None,
    )
    .expect("Valid remote chunk");
    storage_b.insert_chunks(&[remote_chunk]).await.expect("Insert remote chunk");

    let inbound_b = Arc::new(OsoosiMeshInboundHandler::new(
        Arc::clone(&storage_b) as Arc<dyn quorum_coordinator::StorageSearcher>,
        peer_id_b.to_string(),
    ));

    let mut net_config_b = NetworkConfig::new_localhost();
    net_config_b.ed25519_seed = Some(seed_b);
    let (_join_b, handle_b) = start_network_node(net_config_b, Some(inbound_b)).await.unwrap();

    let addrs_b = handle_b.listen_addresses().await.unwrap();
    let tcp_addr_b = addrs_b.iter().find(|a| a.to_string().contains("/tcp/")).cloned().unwrap();

    // Node A setup with local document
    let temp_dir_a = tempfile::tempdir().expect("Node A temp dir");
    let storage_cfg_a = StorageConfig::new(temp_dir_a.path().to_path_buf());
    let storage_a = Arc::new(StorageEngine::open(storage_cfg_a).await.expect("StorageEngine A"));

    let local_doc_path = r"C:\Users\operator\Documents\local_runbook.md";
    let local_chunk = DocumentChunk::new(
        "chunk_local_runbook",
        "doc_local_runbook",
        local_doc_path,
        1,
        20,
        0,
        vec![0.2; 768],
        "Local Operations Runbook: Standard procedures for daemon startup and diagnostic telemetry.",
        None,
    )
    .expect("Valid local chunk");
    storage_a.insert_chunks(&[local_chunk]).await.expect("Insert local chunk");

    let seed_a = [0x33u8; 32];
    let secret_a = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(seed_a).unwrap();
    let ed_kp_a = quorum_network::libp2p::identity::ed25519::Keypair::from(secret_a);
    let peer_id_a = quorum_network::libp2p::identity::Keypair::from(ed_kp_a).public().to_peer_id();

    let mut net_config_a = NetworkConfig::new_localhost();
    net_config_a.ed25519_seed = Some(seed_a);
    let (_join_a, handle_a) = start_network_node(net_config_a, None).await.unwrap();

    handle_a.dial(tcp_addr_b).await.unwrap();
    tokio::time::sleep(Duration::from_millis(350)).await;

    let mesh_dispatcher = Arc::new(SwarmMeshDispatcher {
        handle: handle_a.clone(),
    });

    let mut coord_cfg = CoordinatorConfig::default();
    coord_cfg.max_peer_responses = 8;
    coord_cfg.timeout_ms = 3500;

    let acl_mgr = Arc::new(tokio::sync::RwLock::new(PeerAclManager::default()));
    let engine = Arc::new(ScatterGatherEngine::new(
        Arc::clone(&storage_a) as Arc<dyn quorum_coordinator::StorageSearcher>,
        mesh_dispatcher,
        acl_mgr,
        coord_cfg.clone(),
        seed_a,
        peer_id_a.to_string(),
    ));

    let coordinator = QueryCoordinator::new(engine, coord_cfg);

    let prompt = "Operations procedures and swarm telemetry";
    let result = coordinator.query(prompt, 10).await.unwrap();

    // Verify hybrid fusion contains BOTH local and remote chunks
    let has_local = result.chunks.iter().any(|c| c.chunk.chunk_id == "chunk_local_runbook" && !c.is_remote);
    let has_remote = result.chunks.iter().any(|c| c.chunk.chunk_id == "chunk_remote_swarm_ops" && c.is_remote);

    assert!(has_local, "Aggregated result must contain local document chunk");
    assert!(has_remote, "Aggregated result must contain remote swarm document chunk");

    // Verify citations list contains both local and peer entries
    let cit_local = result.sources_cited.iter().find(|c| c.file_path == local_doc_path);
    let cit_remote = result.sources_cited.iter().find(|c| c.file_path == remote_doc_path);

    assert!(cit_local.is_some(), "Local citation must be present");
    assert!(cit_remote.is_some(), "Remote peer citation must be present");

    assert!(!cit_local.unwrap().is_external_node, "Local citation must have is_external_node: false");
    assert!(cit_remote.unwrap().is_external_node, "Remote citation must have is_external_node: true");
    assert_eq!(cit_remote.unwrap().peer_id, peer_id_b.to_string());

    let _ = handle_a.shutdown().await;
    let _ = handle_b.shutdown().await;
}

#[tokio::test]
async fn test_fresh_install_untrusted_peer_access_tier_parity() {
    let dlp_controller = global_mesh_dlp_controller();
    {
        let mut guard = dlp_controller.settings.write().unwrap();
        guard.mesh.p2p_enabled = true;
        guard.mesh.require_explicit_folder_share = false;
    }

    // Node B with public Tier 0 document
    let temp_dir_b = tempfile::tempdir().unwrap();
    let storage_b = Arc::new(StorageEngine::open(StorageConfig::new(temp_dir_b.path().to_path_buf())).await.unwrap());

    let seed_b = [0x66u8; 32];
    let secret_b = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(seed_b).unwrap();
    let ed_kp_b = quorum_network::libp2p::identity::ed25519::Keypair::from(secret_b);
    let peer_id_b = quorum_network::libp2p::identity::Keypair::from(ed_kp_b).public().to_peer_id();

    let doc_path = r"C:\Users\public\Documents\announcement.txt";
    let chunk = DocumentChunk::new(
        "public_announcement_1",
        "doc_public",
        doc_path,
        1,
        10,
        0, // Public Tier 0
        vec![0.1; 768],
        "Public Announcement: QuorumRAG network discovery active across all subnets.",
        None,
    )
    .unwrap();
    storage_b.insert_chunks(&[chunk]).await.unwrap();

    let inbound_b = Arc::new(OsoosiMeshInboundHandler::new(
        Arc::clone(&storage_b) as Arc<dyn quorum_coordinator::StorageSearcher>,
        peer_id_b.to_string(),
    ));

    let mut net_config_b = NetworkConfig::new_localhost();
    net_config_b.ed25519_seed = Some(seed_b);
    let (_join_b, handle_b) = start_network_node(net_config_b, Some(inbound_b)).await.unwrap();

    let addrs_b = handle_b.listen_addresses().await.unwrap();
    let tcp_addr_b = addrs_b.iter().find(|a| a.to_string().contains("/tcp/")).cloned().unwrap();

    // Node A with fresh-install default ACL (Node B is not in trusted_peers)
    let temp_dir_a = tempfile::tempdir().unwrap();
    let storage_a = Arc::new(StorageEngine::open(StorageConfig::new(temp_dir_a.path().to_path_buf())).await.unwrap());

    let seed_a = [0x55u8; 32];
    let secret_a = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(seed_a).unwrap();
    let ed_kp_a = quorum_network::libp2p::identity::ed25519::Keypair::from(secret_a);
    let peer_id_a = quorum_network::libp2p::identity::Keypair::from(ed_kp_a).public().to_peer_id();

    let mut net_config_a = NetworkConfig::new_localhost();
    net_config_a.ed25519_seed = Some(seed_a);
    let (_join_a, handle_a) = start_network_node(net_config_a, None).await.unwrap();

    handle_a.dial(tcp_addr_b).await.unwrap();
    tokio::time::sleep(Duration::from_millis(350)).await;

    let mesh_dispatcher = Arc::new(SwarmMeshDispatcher {
        handle: handle_a.clone(),
    });

    let mut coord_cfg = CoordinatorConfig::default();
    coord_cfg.max_peer_responses = 8;
    coord_cfg.timeout_ms = 3500;

    let acl_mgr = Arc::new(tokio::sync::RwLock::new(PeerAclManager::default()));
    let engine = Arc::new(ScatterGatherEngine::new(
        storage_a,
        mesh_dispatcher,
        acl_mgr,
        coord_cfg.clone(),
        seed_a,
        peer_id_a.to_string(),
    ));

    let coordinator = QueryCoordinator::new(engine, coord_cfg);

    let prompt = "QuorumRAG network discovery active";
    let result = coordinator.query(prompt, 5).await.unwrap();
    assert!(
        result.chunks.iter().any(|c| c.chunk.chunk_id == "public_announcement_1"),
        "Public announcement chunk must be returned to unverified peer under Tier 0 policy out-of-the-box"
    );

    let _ = handle_a.shutdown().await;
    let _ = handle_b.shutdown().await;
}
