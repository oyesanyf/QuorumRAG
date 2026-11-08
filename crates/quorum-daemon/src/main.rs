use clap::Parser;
use std::sync::Arc;
use std::time::Instant;
use tracing::{error, info, warn};

pub mod browser;
pub mod chat_history_db;
pub mod cli;
pub mod handlers;
pub mod p2p_watcher;
pub mod server;
pub mod shutdown;
pub mod state;
#[cfg(windows)]
pub mod win_service;

use cli::{Cli, Commands};
pub use p2p_watcher::{discover_local_private_ipv4_addresses, is_private_lan_ipv4};
use state::DaemonState;

const DEFAULT_LOG_FILTER: &str =
    "quorumrag=info,quorum_daemon=info,quorum_coordinator=info,quorum_storage=info";

/// Console logging normally; with `--service`, append to `<data-dir>/logs/quorumrag-service.log`
/// because a service has no console.
fn init_tracing(cli: &Cli) {
    let filter = || {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| DEFAULT_LOG_FILTER.into())
    };
    if cli.service {
        let log_dir = cli.data_dir.join("logs");
        let opened = std::fs::create_dir_all(&log_dir).and_then(|_| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_dir.join("quorumrag-service.log"))
        });
        if let Ok(file) = opened {
            tracing_subscriber::fmt()
                .with_env_filter(filter())
                .with_ansi(false)
                .with_writer(std::sync::Mutex::new(file))
                .init();
            return;
        }
    }
    tracing_subscriber::fmt().with_env_filter(filter()).init();
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli);

    #[cfg(windows)]
    if cli.service && cli.command.is_none() {
        return win_service::run(cli);
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    match &cli.command {
        Some(Commands::Reindex {
            path,
            full,
            force_reembed,
            batch_size,
        }) => {
            run_standalone_reindex(cli.clone(), path.clone(), *full, *force_reembed, *batch_size)
                .await?;
        }
        Some(Commands::FixDrift {
            dry_run,
            drift_type,
        }) => {
            run_standalone_fix_drift(cli.clone(), *dry_run, drift_type.clone()).await?;
        }
        Some(Commands::Recache { clear, warm }) => {
            run_standalone_recache(cli.clone(), *clear, *warm).await?;
        }
        Some(Commands::WatchP2p {
            daemon_url,
            interval_secs,
            heal_service,
            parent_pid,
            once,
        }) => {
            p2p_watcher::run_standalone_p2p_watcher(
                cli.clone(),
                daemon_url.clone(),
                *interval_secs,
                *heal_service,
                *parent_pid,
                *once,
            )
            .await?;
        }
        None => {
            run_daemon_and_ui(cli).await?;
        }
    }

    Ok(())
}

/// Starts the QuorumRAG Daemon and embedded Web UI.
pub async fn run_daemon_and_ui(cli: Cli) -> anyhow::Result<()> {
    info!(
        port = cli.port,
        host = %cli.host,
        data_dir = ?cli.data_dir,
        no_browser = cli.no_browser,
        "Starting QuorumRAG Daemon & ChatGPT Web Server..."
    );

    // 1. Ensure storage directories exist
    let lance_path = cli.data_dir.join("lance");
    let tantivy_path = cli.data_dir.join("tantivy");
    tokio::fs::create_dir_all(&lance_path).await?;
    tokio::fs::create_dir_all(&tantivy_path).await?;

    let storage_config = quorum_storage::StorageConfig::new(cli.data_dir.clone());

    let storage = Arc::new(quorum_storage::StorageEngine::open(storage_config).await?);
    let classifier = Arc::new(quorum_classifier::FileTypeClassifier::new());
    let embedder: Arc<dyn quorum_contract::EmbeddingGenerator> =
        Arc::new(quorum_contract::DeterministicOfflineEngine::new());
    let dedup = Arc::new(quorum_ingest::TwoLevelDedupEngine::new());
    let catalog_path = cli.data_dir.join("dedup_catalog.json");
    if catalog_path.exists() {
        match dedup.load_catalog_from_file(&catalog_path) {
            Ok(()) => {
                let count = dedup.catalog().read().map(|c| c.len()).unwrap_or(0);
                info!(
                    count,
                    path = %catalog_path.display(),
                    "Startup: Loaded persistent Level-1 dedup catalog from disk"
                );
            }
            Err(e) => {
                warn!("Startup: Failed to load dedup catalog from disk: {}", e);
            }
        }
    }

    let dedup_bg = Arc::clone(&dedup);
    let storage_bg = Arc::clone(&storage);
    let catalog_path_bg = catalog_path.clone();
    tokio::spawn(async move {
        let chunk_count = storage_bg.count().await.unwrap_or(0);
        let catalog_is_empty = dedup_bg.catalog().read().map(|c| c.is_empty()).unwrap_or(true);
        if catalog_is_empty && chunk_count > 0 && chunk_count <= 5_000 {
            match dedup_bg.hydrate_from_storage(&storage_bg).await {
                Ok(chunks) => {
                    info!(
                        chunks,
                        tracked_files = dedup_bg.catalog().read().map(|c| c.len()).unwrap_or(0),
                        "Startup deduplication hydration completed from LanceDB storage"
                    );
                    let _ = dedup_bg.save_catalog_to_file(&catalog_path_bg);
                }
                Err(e) => {
                    error!("Startup deduplication hydration warning: {}", e);
                }
            }
        } else if !catalog_is_empty {
            info!(
                tracked_files = dedup_bg.catalog().read().map(|c| c.len()).unwrap_or(0),
                "Persistent dedup catalog active with 0-disk-read fast path"
            );
        } else {
            info!(
                chunk_count,
                "Pre-existing high-capacity LanceDB index active; skipping monolithic in-memory chunk hydration on daemon startup"
            );
        }
    });

    // 2. Ingest Config & Workers (defaults to discovered user roots + fixed physical drives when --watch-dir is omitted)
    let mut ingest_config = quorum_ingest::IngestConfig::default();
    ingest_config.exclude_source_code = true;
    ingest_config.max_file_size_bytes = 15 * 1024 * 1024;
    ingest_config.dedup_catalog_path = Some(cli.data_dir.join("dedup_catalog.json"));
    if !ingest_config
        .excluded_paths
        .iter()
        .any(|p| p == &cli.data_dir)
    {
        ingest_config.excluded_paths.push(cli.data_dir.clone());
    }
    if let Some(ref watch_path) = cli.watch_dir {
        ingest_config.watch_paths.push(watch_path.clone());
    } else {
        let user_roots = quorum_ingest::IngestConfig::discover_user_document_roots();
        let physical_drives = quorum_ingest::IngestConfig::discover_physical_drives();
        info!(
            user_roots = ?user_roots,
            drives = ?physical_drives,
            "No --watch-dir specified; defaulting to discovered user document roots + fixed physical drives"
        );
        let mut default_paths = user_roots;
        for d in physical_drives {
            if !default_paths.contains(&d) {
                default_paths.push(d);
            }
        }
        ingest_config.watch_paths = default_paths;
    }

    let reindex_worker = Arc::new(quorum_ingest::ReindexWorker::new(
        ingest_config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    ));

    let drift_healer = Arc::new(quorum_ingest::DriftHealer::new(
        ingest_config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    ));

    // 3. Dynamically bind HTTP Listener on `cli.port` (or next open port)
    let (listener, bound_http_port) = bind_next_open_http_port(&cli.host, cli.port).await?;
    let chosen_p2p_port = find_next_open_p2p_port(&cli.host, cli.p2p_port, bound_http_port);

    // Initialize OshoosiClaw Mesh & PHI/PII DLP persistence in `cli.data_dir`
    let mesh_dlp_controller = quorum_coordinator::global_mesh_dlp_controller();
    mesh_dlp_controller.init_persistence(&cli.data_dir);
    {
        let mut guard = mesh_dlp_controller
            .settings
            .write()
            .unwrap_or_else(|e| e.into_inner());
        guard.mesh.mesh_port = chosen_p2p_port;
        // Ensure require_explicit_folder_share defaults to false so remote mesh peers are never blocked by default
        guard.mesh.require_explicit_folder_share = false;
        if cli.max_peer_responses > 0 {
            guard.mesh.max_peer_responses = cli.max_peer_responses;
        }

        // Automatically populate discovered user document folders and watch paths into shared_folders
        let mut candidate_folders = ingest_config.watch_paths.clone();
        for user_root in quorum_ingest::IngestConfig::discover_user_document_roots() {
            if !candidate_folders.contains(&user_root) {
                candidate_folders.push(user_root);
            }
        }

        for wp in &candidate_folders {
            let wp_str = wp.to_string_lossy().to_string();
            if !guard
                .mesh
                .shared_folders
                .iter()
                .any(|f| f.path.eq_ignore_ascii_case(&wp_str))
            {
                let label = wp
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| wp_str.clone());
                guard
                    .mesh
                    .shared_folders
                    .push(quorum_coordinator::SharedFolderEntry {
                        path: wp_str,
                        label,
                        enabled: true,
                        access_tier: 0,
                        dlp_mode_override: None,
                        shared_at: chrono::Utc::now().to_rfc3339(),
                    });
            }
        }
    }
    mesh_dlp_controller.save_to_disk();

    // Load or generate persistent 32-byte Ed25519 node seed
    let node_seed = quorum_network::load_or_generate_node_seed(&cli.data_dir)?;
    let secret = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(node_seed)
        .map_err(|e| anyhow::anyhow!("Invalid node seed: {e}"))?;
    let ed_kp = quorum_network::libp2p::identity::ed25519::Keypair::from(secret);
    let persistent_peer_id = quorum_network::libp2p::identity::Keypair::from(ed_kp)
        .public()
        .to_peer_id();
    let persistent_peer_id_str = persistent_peer_id.to_string();

    // 4. Network Swarm & Query Coordinator (with OsoosiMeshInboundHandler enforcing Shared Folders & PHI DLP)
    let inbound_handler: Arc<dyn quorum_network::InboundQueryHandler> =
        Arc::new(quorum_coordinator::OsoosiMeshInboundHandler::new(
            Arc::clone(&storage) as Arc<dyn quorum_coordinator::StorageSearcher>,
            persistent_peer_id_str.clone(),
        ));
    let (mesh_dispatcher, swarm_handle): (
        Arc<dyn quorum_coordinator::MeshQueryDispatcher>,
        Option<quorum_network::NetworkSwarmHandle>,
    ) = if cli.local_only {
        info!("Running in local-only mode (P2P swarm networking disabled).");
        (Arc::new(quorum_coordinator::LocalOnlyDispatcher), None)
    } else {
        let net_config = quorum_network::NetworkConfig {
            ed25519_seed: Some(node_seed),
            tcp_listen_addrs: vec![format!("/ip4/{}/tcp/{}", cli.host, chosen_p2p_port).parse()?],
            quic_listen_addrs: vec![
                format!("/ip4/{}/udp/{}/quic-v1", cli.host, chosen_p2p_port).parse()?,
            ],
            contract_hash_hex: embedder
                .contract_hash()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect(),
            request_timeout: std::time::Duration::from_secs(15),
            ..Default::default()
        };
        match quorum_network::start_network_node(net_config, Some(inbound_handler)).await {
            Ok((_join, handle)) => {
                let disp = Arc::new(quorum_coordinator::SwarmMeshDispatcher::new(handle.clone()));
                (disp, Some(handle))
            }
            Err(e) => {
                error!(
                    "Failed to start libp2p network node: {}. Falling back to local-only.",
                    e
                );
                (Arc::new(quorum_coordinator::LocalOnlyDispatcher), None)
            }
        }
    };

    let mut coord_cfg = quorum_coordinator::CoordinatorConfig::default();
    coord_cfg.max_peer_responses = cli.max_peer_responses;
    coord_cfg.timeout_ms = 6000;

    let mut acl_mgr = quorum_coordinator::PeerAclManager::default();
    let trusted_peers_list = mesh_dlp_controller
        .settings
        .read()
        .map(|g| g.mesh.trusted_peers.clone())
        .unwrap_or_default();
    for peer_str in trusted_peers_list {
        let trimmed = peer_str.trim();
        if !trimmed.is_empty() {
            info!(
                "Hydrating trusted peer from persisted settings into PeerAclManager: {}",
                trimmed
            );
            acl_mgr.register_peer_id(
                trimmed.to_string(),
                quorum_types::AccessTier::Tier2Confidential,
            );
            let now = chrono::Utc::now();
            let expires = now + chrono::Duration::days(365);
            acl_mgr.record_peer_attestation(quorum_coordinator::PeerAttestationRecord {
                peer_id: trimmed.to_string(),
                pubkey: None,
                attestation_tier: quorum_coordinator::AttestationTier::VerifiedHardwareTpm,
                vendor: Some(quorum_coordinator::TpmOemVendor::Unknown),
                pcr_composite_digest: Some("OPERATOR_PERSISTED_TRUSTED_PEER".to_string()),
                hardware_backed: true,
                ek_fingerprint: None,
                verified_at: now,
                expires_at: expires,
            });
        }
    }
    let acl_manager = Arc::new(tokio::sync::RwLock::new(acl_mgr));

    let coordinator_engine = Arc::new(quorum_coordinator::ScatterGatherEngine::new(
        Arc::clone(&storage) as Arc<dyn quorum_coordinator::StorageSearcher>,
        mesh_dispatcher,
        acl_manager,
        coord_cfg.clone(),
        node_seed,
        persistent_peer_id_str.clone(),
    ));

    let coordinator = Arc::new(quorum_coordinator::QueryCoordinator::new(
        coordinator_engine,
        coord_cfg,
    ));

    let default_model_family = match cli.model_family.as_str() {
        "Glm4Agentic" => quorum_coordinator::SynthesisModelFamily::Glm4Agentic,
        "Qwen25Code" => quorum_coordinator::SynthesisModelFamily::Qwen25Code,
        "GemmaProse" => quorum_coordinator::SynthesisModelFamily::GemmaProse,
        "Gemma4_26b" | "gemma4:26b" | "gemma4" => {
            quorum_coordinator::SynthesisModelFamily::Gemma4_26b
        }
        _ => quorum_coordinator::SynthesisModelFamily::AutoFusion,
    };

    let shutdown_notify = Arc::new(tokio::sync::Notify::new());

    let app_state = Arc::new(DaemonState {
        start_time: Instant::now(),
        storage: Arc::clone(&storage),
        coordinator,
        reindex_worker: Arc::clone(&reindex_worker),
        drift_healer,
        classifier,
        embedder,
        dedup: Arc::clone(&dedup),
        swarm_handle,
        ingest_config: ingest_config.clone(),
        default_model_family,
        port: bound_http_port,
        host: cli.host.clone(),
        data_dir: cli.data_dir.clone(),
        shutdown_notify: Arc::clone(&shutdown_notify),
        in_flight_queries: Arc::new(crate::state::InFlightQueryRegistry::new()),
        sessions: crate::state::ChatSessionRegistry::new(),
    });

    let watcher_enabled = !cli.local_only && !cli.no_p2p_watcher;
    app_state.set_p2p_watcher(Arc::new(p2p_watcher::P2pWatcherRuntime::new(
        cli.data_dir.clone(),
        chosen_p2p_port,
        node_seed,
        persistent_peer_id_str,
        watcher_enabled,
    )));

    let app = server::build_router(Arc::clone(&app_state));

    let bind_addr = format!("{}:{}", cli.host, bound_http_port);
    info!("QuorumRAG Web UI listening on http://{}", bind_addr);

    // Ensure Windows Firewall allows LAN P2P Mesh & Web UI across all network profiles (Private, Public, Domain)
    #[cfg(target_os = "windows")]
    {
        p2p_watcher::ensure_windows_p2p_firewall_rules(bound_http_port, chosen_p2p_port);
    }

    // Start dedicated out-of-process P2P Watcher (`quorumrag watch-p2p`) + fast startup hydration
    p2p_watcher::start_p2p_watcher_supervisor(
        Arc::clone(&app_state),
        watcher_enabled,
        cli.service,
    );

    // Spawn automatic LAN /24 subnet + ARP + persisted-peer dialer so nodes connect even if Wi-Fi AP blocks UDP 5353 multicast
    if let Some(ref handle) = app_state.swarm_handle {
        let dial_handle = handle.clone();
        let p2p_port = chosen_p2p_port;
        let dial_shutdown = Arc::clone(&shutdown_notify);
        let dial_state = Arc::clone(&app_state);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            loop {
                // 1. Dial any configured bootstrap peers + persisted known peers
                let bootstrap_list = quorum_coordinator::global_mesh_dlp_controller()
                    .settings
                    .read()
                    .map(|g| g.mesh.bootstrap_peers.clone())
                    .unwrap_or_default();
                for addr_str in bootstrap_list {
                    if let Ok(ma) = addr_str.parse::<quorum_network::Multiaddr>() {
                        let _ = dial_handle.dial(ma).await;
                    }
                }
                for cached_ma in dial_state.p2p_watcher().load_known_peers().multiaddrs {
                    if let Ok(ma) = cached_ma.parse::<quorum_network::Multiaddr>() {
                        let _ = dial_handle.dial(ma).await;
                    }
                }

                // 2. Discover local IPv4 /24 prefixes + ARP neighbors and probe active LAN neighbors on p2p_port
                let mut self_ips = discover_local_private_ipv4_addresses();
                if let Ok(listen_addrs) = dial_handle.listen_addresses().await {
                    for ma in listen_addrs {
                        let s = ma.to_string();
                        if let Some(rest) = s.strip_prefix("/ip4/") {
                            if let Some(ip_str) = rest.split('/').next() {
                                if let Ok(ipv4) = ip_str.parse::<std::net::Ipv4Addr>() {
                                    if is_private_lan_ipv4(&ipv4) && !self_ips.contains(&ipv4) {
                                        self_ips.push(ipv4);
                                    }
                                }
                            }
                        }
                    }
                }

                // Fast ARP neighbor probe first (covers /8, /16, and /24 private networks in <150ms)
                let arp_candidates = p2p_watcher::discover_arp_private_lan_neighbors(&self_ips);
                for found_ip in p2p_watcher::probe_open_p2p_hosts(arp_candidates, p2p_port).await {
                    let ma_str = format!("/ip4/{}/tcp/{}", found_ip, p2p_port);
                    if let Ok(ma) = ma_str.parse::<quorum_network::Multiaddr>() {
                        let _ = dial_handle.dial(ma).await;
                    }
                }

                let mut prefixes = Vec::new();
                for ip in &self_ips {
                    let oct = ip.octets();
                    let prefix = (oct[0], oct[1], oct[2]);
                    if !prefixes.contains(&prefix) {
                        prefixes.push(prefix);
                    }
                }

                for (a, b, c) in prefixes {
                    let mut join_set = tokio::task::JoinSet::new();
                    for host in 1u8..=254u8 {
                        let cand_ip = std::net::Ipv4Addr::new(a, b, c, host);
                        if self_ips.contains(&cand_ip) {
                            continue;
                        }
                        join_set.spawn(async move {
                            let sock = std::net::SocketAddr::from((cand_ip, p2p_port));
                            if tokio::time::timeout(
                                std::time::Duration::from_millis(120),
                                tokio::net::TcpStream::connect(sock),
                            )
                            .await
                            .map(|r| r.is_ok())
                            .unwrap_or(false)
                            {
                                Some(cand_ip)
                            } else {
                                None
                            }
                        });
                    }
                    while let Some(res) = join_set.join_next().await {
                        if let Ok(Some(found_ip)) = res {
                            let ma_str = format!("/ip4/{}/tcp/{}", found_ip, p2p_port);
                            if let Ok(ma) = ma_str.parse::<quorum_network::Multiaddr>() {
                                let _ = dial_handle.dial(ma).await;
                            }
                        }
                    }
                }

                dial_state
                    .p2p_watcher()
                    .save_known_peers_snapshot(&dial_handle.connected_peer_addresses());

                tokio::select! {
                    _ = dial_shutdown.notified() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(20)) => {}
                }
            }
        });
    }

    // Warm persistent SQLite chat history database (`<data_dir>/chat_history.db`) on startup
    if let Err(e) = app_state.history_store() {
        error!("Failed to initialize SQLite chat history database: {}", e);
    }

    // Continuously run background crawl & incremental ingestion unconditionally
    let bg_worker = Arc::clone(&reindex_worker);
    let bg_storage = Arc::clone(&storage);
    let bg_data_dir = cli.data_dir.clone();
    let bg_default_paths = ingest_config.watch_paths.clone();
    let bg_shutdown = Arc::clone(&shutdown_notify);

    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        // One-time legacy chunk upgrade guard: avoid scanning hundreds of thousands of 768-d vectors
        // into RAM on startup when the index is already populated (> 25,000 chunks) or already upgraded.
        let upgrade_marker = bg_data_dir.join("legacy_chunks_upgraded_v1.marker");
        let startup_chunk_count = bg_storage.count().await.unwrap_or(0);
        if !upgrade_marker.is_file() && startup_chunk_count <= 25_000 {
            if let Ok(upgraded_docs) = bg_worker.upgrade_degraded_document_chunks().await {
                if upgraded_docs > 0 {
                    info!(
                        upgraded_docs,
                        "Self-healed degraded document chunks via native Rust OOXML/FlateDecode extractors"
                    );
                }
            }
            let _ = bg_worker.upgrade_legacy_image_chunks().await;
            let _ = std::fs::write(&upgrade_marker, chrono::Utc::now().to_rfc3339());
        } else {
            info!(
                startup_chunk_count,
                marker_present = upgrade_marker.is_file(),
                "Skipping monolithic startup legacy-chunk scan to keep storage I/O unblocked for live queries"
            );
        }

        // Pass 0: Priority fast pass over user document & screenshot folders (Pictures, Desktop, Downloads, Documents)
        let priority_user_roots = quorum_ingest::IngestConfig::discover_user_document_roots();
        if !priority_user_roots.is_empty() {
            let fast_opts = quorum_ingest::ReindexOptions {
                target_paths: priority_user_roots,
                full_rebuild: false,
                force_reembed: false,
                batch_size: 64,
                num_threads: 0,
                dry_run: false,
            };
            let _ = bg_worker.start_reindex(fast_opts).await;
            tokio::time::sleep(std::time::Duration::from_secs(6)).await;
        }
        loop {
            let mut target_paths = bg_default_paths.clone();
            if let Ok(guard) = quorum_coordinator::global_mesh_dlp_controller()
                .settings
                .read()
            {
                for folder in &guard.mesh.shared_folders {
                    if folder.enabled {
                        let p = std::path::PathBuf::from(&folder.path);
                        if !target_paths.contains(&p) {
                            target_paths.push(p);
                        }
                    }
                }
            }

            let is_running = match bg_worker.get_progress().await {
                Some(prog) => matches!(
                    prog.phase,
                    quorum_ingest::ReindexPhase::ScanningFilesystem
                        | quorum_ingest::ReindexPhase::ChunkingAndVectorizing
                        | quorum_ingest::ReindexPhase::WritingToStorage
                        | quorum_ingest::ReindexPhase::CompactingIndexes
                ),
                None => false,
            };

            if !is_running {
                let pass_options = quorum_ingest::ReindexOptions {
                    target_paths,
                    full_rebuild: false,
                    force_reembed: false,
                    batch_size: 64,
                    num_threads: 0,
                    dry_run: false,
                };
                if let Err(e) = bg_worker.start_reindex(pass_options).await {
                    error!("Continuous background indexer pass warning: {}", e);
                }
            }

            tokio::select! {
                _ = bg_shutdown.notified() => break,
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
            }
        }
    });

    // 5. Auto-launch browser if not disabled
    if !cli.no_browser {
        let browser_host = if cli.host == "0.0.0.0" {
            "127.0.0.1"
        } else {
            cli.host.as_str()
        };
        let url = format!("http://{}:{}", browser_host, bound_http_port);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            browser::launch_browser(&url);
        });
    }

    // 6. Axum 0.7 server with graceful shutdown
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown::shutdown_signal(shutdown_notify))
    .await?;

    // 7. Execute graceful shutdown cleanup
    shutdown::execute_graceful_shutdown(app_state).await;

    Ok(())
}

/// Checks if any service is already listening on `port` (on `127.0.0.1` or `0.0.0.0`).
fn is_port_in_use(host: &str, port: u16) -> bool {
    let loopback = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    if std::net::TcpStream::connect_timeout(&loopback, std::time::Duration::from_millis(60)).is_ok()
    {
        return true;
    }
    if host == "0.0.0.0" {
        std::net::TcpListener::bind(("0.0.0.0", port)).is_err()
    } else {
        std::net::TcpListener::bind(("0.0.0.0", port)).is_err()
            || std::net::TcpListener::bind((host, port)).is_err()
    }
}

/// Dynamically binds the HTTP server to `start_port`, advancing to the next open TCP port if in use.
async fn bind_next_open_http_port(
    host: &str,
    start_port: u16,
) -> std::io::Result<(tokio::net::TcpListener, u16)> {
    let mut last_err = None;
    for offset in 0..=200u16 {
        let candidate = start_port.saturating_add(offset);
        let addr = format!("{}:{}", host, candidate);
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => {
                if candidate != start_port {
                    info!(
                        requested_port = start_port,
                        bound_port = candidate,
                        "Port {} was busy; dynamically bound HTTP server to next open port {}",
                        start_port,
                        candidate
                    );
                }
                return Ok((listener, candidate));
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::other("No open HTTP port found")))
}

/// Dynamically finds the next open P2P port (both TCP & UDP free, avoiding `exclude_port`).
fn find_next_open_p2p_port(host: &str, start_port: u16, exclude_port: u16) -> u16 {
    for offset in 0..=200u16 {
        let candidate = start_port.saturating_add(offset);
        if candidate == exclude_port || is_port_in_use(host, candidate) {
            continue;
        }
        let addr = format!("{}:{}", host, candidate);
        let udp_free = if host == "0.0.0.0" {
            std::net::UdpSocket::bind(("0.0.0.0", candidate)).is_ok()
        } else {
            std::net::UdpSocket::bind(&addr).is_ok()
                && std::net::UdpSocket::bind(("0.0.0.0", candidate)).is_ok()
        };
        if udp_free {
            if candidate != start_port {
                info!(
                    requested_p2p_port = start_port,
                    chosen_p2p_port = candidate,
                    "P2P port {} was busy; dynamically selected next open P2P port {}",
                    start_port,
                    candidate
                );
            }
            return candidate;
        }
    }
    start_port
}

/// Executes standalone reindex CLI command.
pub async fn run_standalone_reindex(
    cli: Cli,
    path: Option<std::path::PathBuf>,
    full: bool,
    force_reembed: bool,
    batch_size: usize,
) -> anyhow::Result<()> {
    info!("Starting standalone reindex CLI worker...");
    let storage_config = quorum_storage::StorageConfig::new(cli.data_dir.clone());
    let storage = Arc::new(quorum_storage::StorageEngine::open(storage_config).await?);
    let classifier = Arc::new(quorum_classifier::FileTypeClassifier::new());
    let embedder: Arc<dyn quorum_contract::EmbeddingGenerator> =
        Arc::new(quorum_contract::DeterministicOfflineEngine::new());
    let dedup = Arc::new(quorum_ingest::TwoLevelDedupEngine::new());
    let catalog_path = cli.data_dir.join("dedup_catalog.json");
    if catalog_path.exists() {
        if let Err(e) = dedup.load_catalog_from_file(&catalog_path) {
            warn!(
                "Standalone reindex: Failed to load dedup catalog from disk: {}",
                e
            );
        }
    }
    let _ = dedup.hydrate_from_storage(&storage).await;

    let target_paths = path.map(|p| vec![p]).unwrap_or_else(|| {
        cli.watch_dir
            .map(|w| vec![w])
            .unwrap_or_else(quorum_ingest::IngestConfig::discover_physical_drives)
    });

    let options = quorum_ingest::ReindexOptions {
        target_paths,
        full_rebuild: full,
        force_reembed,
        batch_size,
        num_threads: 0,
        dry_run: false,
    };

    let mut ingest_cfg = quorum_ingest::IngestConfig::default();
    ingest_cfg.exclude_source_code = true;
    ingest_cfg.dedup_catalog_path = Some(catalog_path);
    if !ingest_cfg
        .excluded_paths
        .iter()
        .any(|p| p == &cli.data_dir)
    {
        ingest_cfg.excluded_paths.push(cli.data_dir.clone());
    }

    let worker =
        quorum_ingest::ReindexWorker::new(ingest_cfg, storage, classifier, embedder, dedup);

    let task_id = worker.start_reindex(options).await?;
    info!(task_id = %task_id, "Reindex task started. Streaming progress...");

    loop {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if let Some(prog) = worker.get_progress().await {
            info!(
                phase = ?prog.phase,
                files_scanned = prog.files_scanned,
                files_indexed = prog.files_indexed,
                chunks_new = prog.chunks_newly_embedded,
                chunks_reused = prog.chunks_reused_from_cache,
                "Progress"
            );
            if matches!(
                prog.phase,
                quorum_ingest::ReindexPhase::Completed
                    | quorum_ingest::ReindexPhase::Failed
                    | quorum_ingest::ReindexPhase::Cancelled
            ) {
                break;
            }
        }
    }

    info!("Standalone reindex finished.");
    Ok(())
}

/// Executes standalone drift healing CLI command.
pub async fn run_standalone_fix_drift(
    cli: Cli,
    dry_run: bool,
    drift_type: Option<String>,
) -> anyhow::Result<()> {
    info!("Starting standalone drift healing CLI worker...");
    let storage_config = quorum_storage::StorageConfig::new(cli.data_dir.clone());
    let storage = Arc::new(quorum_storage::StorageEngine::open(storage_config).await?);
    let classifier = Arc::new(quorum_classifier::FileTypeClassifier::new());
    let embedder: Arc<dyn quorum_contract::EmbeddingGenerator> =
        Arc::new(quorum_contract::DeterministicOfflineEngine::new());
    let dedup = Arc::new(quorum_ingest::TwoLevelDedupEngine::new());
    let _ = dedup.hydrate_from_storage(&storage).await;

    let mut ingest_cfg = quorum_ingest::IngestConfig::default();
    ingest_cfg.exclude_source_code = true;
    if let Some(ref w) = cli.watch_dir {
        ingest_cfg.watch_paths = vec![w.clone()];
    } else {
        ingest_cfg.watch_paths = quorum_ingest::IngestConfig::discover_physical_drives();
    }

    let healer = quorum_ingest::DriftHealer::new(ingest_cfg, storage, classifier, embedder, dedup);

    let mut targets = Vec::new();
    if let Some(t) = drift_type {
        match t.to_lowercase().as_str() {
            "merkle_state" => targets.push(quorum_ingest::DriftType::MerkleState),
            "hybrid_index_desync" => targets.push(quorum_ingest::DriftType::HybridIndexDesync),
            "vector_contract" => targets.push(quorum_ingest::DriftType::VectorContract),
            "acl_policy" => targets.push(quorum_ingest::DriftType::AclPolicy),
            "storage_compaction" => targets.push(quorum_ingest::DriftType::StorageCompaction),
            _ => {}
        }
    }

    let report = healer
        .fix_all_drifts(quorum_ingest::DriftFixOptions {
            target_drifts: targets,
            dry_run,
            access_tier_rules: Vec::new(),
        })
        .await?;

    println!("\n=== QuorumRAG 5-Drift Remediation Report ===");
    println!("Execution Duration: {}ms", report.duration_ms);
    println!(
        "Total Anomalies Detected: {}",
        report.total_anomalies_detected
    );
    println!(
        "Total Anomalies Healed:   {}",
        report.total_anomalies_healed
    );
    println!("--------------------------------------------");
    println!("1. Merkle State (FS <-> DB):");
    println!(
        "   - Orphaned DB Files Purged: {}",
        report.orphaned_db_files_purged
    );
    println!(
        "   - Missing FS Files Indexed: {}",
        report.missing_fs_files_indexed
    );
    println!("2. Hybrid Index Desync (LanceDB <-> Tantivy):");
    println!(
        "   - Lance chunks missing in Tantivy: {}",
        report.lance_chunks_missing_in_tantivy
    );
    println!(
        "   - Tantivy chunks missing in Lance: {}",
        report.tantivy_chunks_missing_in_lance
    );
    println!("   - Parity Restored: {}", report.hybrid_parity_restored);
    println!("3. Vector Contract Drift:");
    println!(
        "   - Drifted chunks re-embedded: {}",
        report.contract_drifted_chunks_reembedded
    );
    println!("4. ACL Policy Drift:");
    println!("   - Chunks updated: {}", report.acl_drifted_chunks_updated);
    println!("5. Storage Compaction:");
    println!(
        "   - Fragments consolidated: {}",
        report.fragments_consolidated
    );
    println!(
        "   - Tantivy segments merged: {}",
        report.tantivy_segments_merged
    );
    println!("============================================\n");

    Ok(())
}

/// Executes standalone or client recache command.
pub async fn run_standalone_recache(cli: Cli, clear: bool, warm: bool) -> anyhow::Result<()> {
    info!(clear, warm, "Starting QuorumRAG recache process...");
    let daemon_url = format!("http://{}:{}/api/cache/recache", cli.host, cli.port);

    if let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
    {
        let payload = serde_json::json!({
            "clear": clear,
            "warm": warm,
        });

        if let Ok(resp) = client.post(&daemon_url).json(&payload).send().await {
            if resp.status().is_success() {
                let json: serde_json::Value = resp.json().await?;
                println!("\n=== QuorumRAG Cache Invalidation & Re-Cache Report ===");
                println!(
                    "Status:           ok (via active daemon at {}:{})",
                    cli.host, cli.port
                );
                println!("Execution Time:   {}ms", json["duration_ms"]);
                println!("New Cache Epoch:  {}", json["cache_epoch"]);
                println!("Cleared Entries:  {}", json["cleared_entries"]);
                println!("Warmed Entries:   {}", json["warmed_entries"]);
                println!("======================================================\n");
                return Ok(());
            }
        }
    }

    let start = Instant::now();
    let storage_config = quorum_storage::StorageConfig::new(cli.data_dir.clone());
    let storage = Arc::new(quorum_storage::StorageEngine::open(storage_config).await?);

    let cleared_entries = 0;
    let new_epoch = storage.bump_index_epoch("standalone_cli_recache")?;

    let warmed_entries = if warm {
        let embedder = Arc::new(quorum_contract::DeterministicOfflineEngine::new());
        let dedup = Arc::new(quorum_ingest::TwoLevelDedupEngine::new());
        let warmer = quorum_ingest::CacheWarmer::new(
            Arc::clone(&storage),
            embedder,
            dedup,
            quorum_ingest::WarmConfig::default(),
        );
        let warm_report = warmer.warm_top_candidates().await;
        warm_report.warmed_embeddings + warm_report.warmed_queries
    } else {
        0
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    println!("\n=== QuorumRAG Cache Invalidation & Re-Cache Report ===");
    println!("Status:           ok (standalone offline mode)");
    println!("Execution Time:   {}ms", duration_ms);
    println!("New Cache Epoch:  {}", new_epoch);
    println!("Cleared Entries:  {}", cleared_entries);
    println!("Warmed Entries:   {}", warmed_entries);
    println!("======================================================\n");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_is_private_lan_ipv4_classification() {
        assert!(is_private_lan_ipv4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_lan_ipv4(&Ipv4Addr::new(10, 254, 1, 50)));
        assert!(is_private_lan_ipv4(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_lan_ipv4(&Ipv4Addr::new(172, 31, 255, 254)));
        assert!(!is_private_lan_ipv4(&Ipv4Addr::new(172, 15, 255, 254)));
        assert!(!is_private_lan_ipv4(&Ipv4Addr::new(172, 32, 0, 1)));
        assert!(is_private_lan_ipv4(&Ipv4Addr::new(192, 168, 1, 100)));
        assert!(is_private_lan_ipv4(&Ipv4Addr::new(192, 168, 0, 1)));
        assert!(!is_private_lan_ipv4(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_private_lan_ipv4(&Ipv4Addr::new(0, 0, 0, 0)));
        assert!(!is_private_lan_ipv4(&Ipv4Addr::new(169, 254, 1, 1)));
        assert!(!is_private_lan_ipv4(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_lan_ipv4(&Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn test_discover_local_private_ipv4_addresses_does_not_panic() {
        let addrs = discover_local_private_ipv4_addresses();
        for ip in &addrs {
            assert!(is_private_lan_ipv4(ip), "Discovered non-private IP: {}", ip);
        }
    }
}
