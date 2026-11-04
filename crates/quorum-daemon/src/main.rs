use clap::Parser;
use std::sync::Arc;
use std::time::Instant;
use tracing::{error, info};

pub mod browser;
pub mod cli;
pub mod handlers;
pub mod server;
pub mod shutdown;
pub mod state;
#[cfg(windows)]
pub mod win_service;

use cli::{Cli, Commands};
use state::DaemonState;

const DEFAULT_LOG_FILTER: &str = "quorumrag=info,quorum_daemon=info,quorum_coordinator=info,quorum_storage=info";

/// Console logging normally; with `--service`, append to `<data-dir>/logs/quorumrag-service.log`
/// because a service has no console.
fn init_tracing(cli: &Cli) {
    let filter = || {
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| DEFAULT_LOG_FILTER.into())
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
            run_standalone_reindex(cli.clone(), path.clone(), *full, *force_reembed, *batch_size).await?;
        }
        Some(Commands::FixDrift { dry_run, drift_type }) => {
            run_standalone_fix_drift(cli.clone(), *dry_run, drift_type.clone()).await?;
        }
        Some(Commands::Recache { clear, warm }) => {
            run_standalone_recache(cli.clone(), *clear, *warm).await?;
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
    let embedder: Arc<dyn quorum_contract::EmbeddingGenerator> = Arc::new(
        quorum_contract::DeterministicOfflineEngine::new()
    );
    let dedup = Arc::new(quorum_ingest::TwoLevelDedupEngine::new());
    let dedup_bg = Arc::clone(&dedup);
    let storage_bg = Arc::clone(&storage);
    tokio::spawn(async move {
        let chunk_count = storage_bg.count().await.unwrap_or(0);
        if chunk_count > 0 && chunk_count <= 5_000 {
            match dedup_bg.hydrate_from_storage(&storage_bg).await {
                Ok(chunks) => {
                    info!(
                        chunks,
                        tracked_files = dedup_bg.catalog().read().map(|c| c.len()).unwrap_or(0),
                        "Startup deduplication hydration completed from LanceDB storage"
                    );
                }
                Err(e) => {
                    error!("Startup deduplication hydration warning: {}", e);
                }
            }
        } else {
            info!(
                chunk_count,
                "Pre-existing high-capacity LanceDB index active; skipping monolithic in-memory chunk hydration on daemon startup"
            );
        }
    });

    // 2. Ingest Config & Workers (defaults to all physical fixed drives when --watch-dir is omitted)
    let mut ingest_config = quorum_ingest::IngestConfig::default();
    ingest_config.exclude_source_code = true;
    ingest_config.max_file_size_bytes = 15 * 1024 * 1024; // 15MB cap skips monolithic raw dumps
    if let Some(ref watch_path) = cli.watch_dir {
        ingest_config.watch_paths.push(watch_path.clone());
    } else {
        let mut priority_paths: Vec<std::path::PathBuf> = Vec::new();
        for dir in [
            r"D:\femi\Femi_Oyesanya_CV_2026.pdf",
            r"D:\chatgpt3\ChatGPT_Restored_Data\Word_Conversations\AI Job Loss Alternatives.docx",
            r"D:\chatgpt3\ChatGPT_Restored_Data\Word_Conversations\40 Affirmations for Angela.docx",
            r"D:\chatgpt3\ChatGPT_Restored_Data\Word_Conversations\Cigna Coverage Dispute.docx",
            r"D:\chatgpt3\ChatGPT_Restored_Data\Word_Conversations\Breath and Hierarchy.docx",
            r"D:\chatgpt3\ChatGPT_Restored_Data\Word_Conversations\Mineral Wealth in Ukraine.docx",
            r"D:\chatgpt3\ChatGPT_Restored_Data\Word_Conversations",
            r"D:\school",
            r"D:\femi",
            r"D:\articles",
        ] {
            let p = std::path::PathBuf::from(dir);
            if p.exists() {
                priority_paths.push(p);
            }
        }
        let physical_drives = quorum_ingest::IngestConfig::discover_physical_drives();
        info!(
            drives = ?physical_drives,
            "No --watch-dir specified; defaulting to priority user document folders + fixed physical drives"
        );
        for d in physical_drives {
            if !priority_paths.contains(&d) {
                priority_paths.push(d);
            }
        }
        ingest_config.watch_paths = priority_paths;
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
        if cli.max_peer_responses > 0 {
            guard.mesh.max_peer_responses = cli.max_peer_responses;
        }
    }

    // Load or generate persistent 32-byte Ed25519 node seed
    let node_seed = quorum_network::load_or_generate_node_seed(&cli.data_dir)?;
    let secret = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(node_seed)
        .map_err(|e| anyhow::anyhow!("Invalid node seed: {e}"))?;
    let ed_kp = quorum_network::libp2p::identity::ed25519::Keypair::from(secret);
    let persistent_peer_id = quorum_network::libp2p::identity::Keypair::from(ed_kp).public().to_peer_id();
    let persistent_peer_id_str = persistent_peer_id.to_string();

    // 4. Network Swarm & Query Coordinator (with OsoosiMeshInboundHandler enforcing Shared Folders & PHI DLP)
    let inbound_handler: Arc<dyn quorum_network::InboundQueryHandler> = Arc::new(
        quorum_coordinator::OsoosiMeshInboundHandler::new(
            Arc::clone(&storage) as Arc<dyn quorum_coordinator::StorageSearcher>,
            persistent_peer_id_str.clone(),
        ),
    );
    let (mesh_dispatcher, swarm_handle): (Arc<dyn quorum_coordinator::MeshQueryDispatcher>, Option<quorum_network::NetworkSwarmHandle>) = if cli.local_only {
        info!("Running in local-only mode (P2P swarm networking disabled).");
        (Arc::new(quorum_coordinator::LocalOnlyDispatcher), None)
    } else {
        let net_config = quorum_network::NetworkConfig {
            ed25519_seed: Some(node_seed),
            tcp_listen_addrs: vec![format!("/ip4/{}/tcp/{}", cli.host, chosen_p2p_port).parse()?],
            quic_listen_addrs: vec![format!("/ip4/{}/udp/{}/quic-v1", cli.host, chosen_p2p_port).parse()?],
            contract_hash_hex: embedder.contract_hash().iter().map(|b| format!("{:02x}", b)).collect(),
            ..Default::default()
        };
        match quorum_network::start_network_node(net_config, Some(inbound_handler)).await {
            Ok((_join, handle)) => {
                let disp = Arc::new(quorum_coordinator::SwarmMeshDispatcher {
                    handle: handle.clone(),
                });
                (disp, Some(handle))
            }
            Err(e) => {
                error!("Failed to start libp2p network node: {}. Falling back to local-only.", e);
                (Arc::new(quorum_coordinator::LocalOnlyDispatcher), None)
            }
        }
    };

    let mut coord_cfg = quorum_coordinator::CoordinatorConfig::default();
    coord_cfg.max_peer_responses = cli.max_peer_responses;

    let coordinator_engine = Arc::new(quorum_coordinator::ScatterGatherEngine::new(
        Arc::clone(&storage) as Arc<dyn quorum_coordinator::StorageSearcher>,
        mesh_dispatcher,
        Arc::new(tokio::sync::RwLock::new(quorum_coordinator::PeerAclManager::default())),
        coord_cfg.clone(),
        node_seed,
        persistent_peer_id_str,
    ));

    let coordinator = Arc::new(quorum_coordinator::QueryCoordinator::new(
        coordinator_engine,
        coord_cfg,
    ));

    let default_model_family = match cli.model_family.as_str() {
        "Glm4Agentic" => quorum_coordinator::SynthesisModelFamily::Glm4Agentic,
        "Qwen25Code" => quorum_coordinator::SynthesisModelFamily::Qwen25Code,
        "GemmaProse" => quorum_coordinator::SynthesisModelFamily::GemmaProse,
        "Gemma4_26b" | "gemma4:26b" | "gemma4" => quorum_coordinator::SynthesisModelFamily::Gemma4_26b,
        _ => quorum_coordinator::SynthesisModelFamily::AutoFusion,
    };

    let shutdown_notify = Arc::new(tokio::sync::Notify::new());

    let app_state = Arc::new(DaemonState {
        start_time: Instant::now(),
        storage,
        coordinator,
        reindex_worker: Arc::clone(&reindex_worker),
        drift_healer,
        classifier,
        embedder,
        dedup,
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

    let app = server::build_router(Arc::clone(&app_state));

    let bind_addr = format!("{}:{}", cli.host, bound_http_port);
    info!("QuorumRAG Web UI listening on http://{}", bind_addr);

    // Continuously run background Magika crawl & incremental ingestion when --watch-dir is explicitly specified
    if let Some(ref watch_path) = cli.watch_dir {
        let bg_worker = Arc::clone(&reindex_worker);
        let bg_paths = vec![watch_path.clone()];
        let bg_shutdown = Arc::clone(&shutdown_notify);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
            loop {
                // Collect target watch path + any user-configured shared folders
                let mut target_paths = bg_paths.clone();
                if let Ok(guard) = quorum_coordinator::global_mesh_dlp_controller().settings.read() {
                    for folder in &guard.mesh.shared_folders {
                        let p = std::path::PathBuf::from(&folder.path);
                        if !target_paths.contains(&p) {
                            target_paths.push(p);
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
    }

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

    // 5. Axum 0.7 server with graceful shutdown
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .with_graceful_shutdown(shutdown::shutdown_signal(shutdown_notify))
        .await?;

    // 6. Execute graceful shutdown cleanup
    shutdown::execute_graceful_shutdown(app_state).await;

    Ok(())
}

/// Checks if any service is already listening on `port` (on `127.0.0.1` or `0.0.0.0`).
fn is_port_in_use(host: &str, port: u16) -> bool {
    let loopback = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    if std::net::TcpStream::connect_timeout(&loopback, std::time::Duration::from_millis(60)).is_ok() {
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
    let embedder: Arc<dyn quorum_contract::EmbeddingGenerator> = Arc::new(
        quorum_contract::DeterministicOfflineEngine::new()
    );
    let dedup = Arc::new(quorum_ingest::TwoLevelDedupEngine::new());
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

    let worker = quorum_ingest::ReindexWorker::new(
        ingest_cfg,
        storage,
        classifier,
        embedder,
        dedup,
    );

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
    let embedder: Arc<dyn quorum_contract::EmbeddingGenerator> = Arc::new(
        quorum_contract::DeterministicOfflineEngine::new()
    );
    let dedup = Arc::new(quorum_ingest::TwoLevelDedupEngine::new());
    let _ = dedup.hydrate_from_storage(&storage).await;

    let mut ingest_cfg = quorum_ingest::IngestConfig::default();
    ingest_cfg.exclude_source_code = true;
    if let Some(ref w) = cli.watch_dir {
        ingest_cfg.watch_paths = vec![w.clone()];
    } else {
        ingest_cfg.watch_paths = quorum_ingest::IngestConfig::discover_physical_drives();
    }

    let healer = quorum_ingest::DriftHealer::new(
        ingest_cfg,
        storage,
        classifier,
        embedder,
        dedup,
    );

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
    println!("Total Anomalies Detected: {}", report.total_anomalies_detected);
    println!("Total Anomalies Healed:   {}", report.total_anomalies_healed);
    println!("--------------------------------------------");
    println!("1. Merkle State (FS <-> DB):");
    println!("   - Orphaned DB Files Purged: {}", report.orphaned_db_files_purged);
    println!("   - Missing FS Files Indexed: {}", report.missing_fs_files_indexed);
    println!("2. Hybrid Index Desync (LanceDB <-> Tantivy):");
    println!("   - Lance chunks missing in Tantivy: {}", report.lance_chunks_missing_in_tantivy);
    println!("   - Tantivy chunks missing in Lance: {}", report.tantivy_chunks_missing_in_lance);
    println!("   - Parity Restored: {}", report.hybrid_parity_restored);
    println!("3. Vector Contract Drift:");
    println!("   - Drifted chunks re-embedded: {}", report.contract_drifted_chunks_reembedded);
    println!("4. ACL Policy Drift:");
    println!("   - Chunks updated: {}", report.acl_drifted_chunks_updated);
    println!("5. Storage Compaction:");
    println!("   - Fragments consolidated: {}", report.fragments_consolidated);
    println!("   - Tantivy segments merged: {}", report.tantivy_segments_merged);
    println!("============================================\n");

    Ok(())
}

/// Executes standalone or client recache command.
pub async fn run_standalone_recache(
    cli: Cli,
    clear: bool,
    warm: bool,
) -> anyhow::Result<()> {
    info!(clear, warm, "Starting QuorumRAG recache process...");
    let daemon_url = format!("http://{}:{}/api/cache/recache", cli.host, cli.port);

    // 1. Attempt client call to active daemon
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
                println!("Status:           ok (via active daemon at {}:{})", cli.host, cli.port);
                println!("Execution Time:   {}ms", json["duration_ms"]);
                println!("New Cache Epoch:  {}", json["cache_epoch"]);
                println!("Cleared Entries:  {}", json["cleared_entries"]);
                println!("Warmed Entries:   {}", json["warmed_entries"]);
                println!("======================================================\n");
                return Ok(());
            }
        }
    }

    // 2. Standalone offline fallback
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
