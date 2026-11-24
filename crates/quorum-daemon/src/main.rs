use clap::Parser;
use std::sync::Arc;
use std::time::Instant;
use tracing::{error, info, warn};

pub mod browser;
pub mod chat_history_db;
pub mod cli;
pub mod handlers;
pub mod nimble_provisioner;
pub mod p2p_watcher;
pub mod server;
pub mod shutdown;
pub mod state;
pub mod wan_mesh;
#[cfg(windows)]
pub mod win_native;
#[cfg(windows)]
pub mod win_service;

use cli::{Cli, Commands};
pub use p2p_watcher::{discover_local_private_ipv4_addresses, is_private_lan_ipv4};
use state::DaemonState;

const DEFAULT_LOG_FILTER: &str =
    "quorumrag=info,quorum_daemon=info,quorum_coordinator=info,quorum_storage=info";

/// Returns true when running as a background daemon or P2P watcher on Windows where a visible
/// DOS/console window must be hidden and detached (unless `QUORUM_SHOW_CONSOLE=1` is set).
#[cfg(windows)]
fn should_detach_windows_console(cli: &Cli) -> bool {
    if std::env::var("QUORUM_SHOW_CONSOLE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return false;
    }
    !matches!(
        cli.command,
        Some(Commands::Reindex { .. })
            | Some(Commands::FixDrift { .. })
            | Some(Commands::Recache { .. })
    )
}

/// Immediately hides (`SW_HIDE`) and detaches (`FreeConsole`) any attached Windows console window
/// so launching `quorumrag.exe` (via shortcut, WMI, Explorer, or service) never shows a DOS window.
#[cfg(windows)]
fn detach_and_hide_windows_console(cli: &Cli) {
    if !should_detach_windows_console(cli) {
        return;
    }
    unsafe extern "system" {
        fn GetConsoleWindow() -> isize;
        fn ShowWindow(hwnd: isize, n_cmd_show: i32) -> i32;
        fn FreeConsole() -> i32;
    }
    unsafe {
        let hwnd = GetConsoleWindow();
        if hwnd != 0 {
            let _ = ShowWindow(hwnd, 0); // SW_HIDE = 0
        }
        let _ = FreeConsole();
    }
}

/// File logging (`<data-dir>/logs/quorumrag-service.log`) when running as a service or detached
/// background daemon on Windows; console logging for explicit interactive CLI subcommands.
fn init_tracing(cli: &Cli) {
    let filter = || {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| DEFAULT_LOG_FILTER.into())
    };
    #[cfg(windows)]
    let use_file_log = cli.service || should_detach_windows_console(cli);
    #[cfg(not(windows))]
    let use_file_log = cli.service;

    if use_file_log {
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

pub fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    #[cfg(windows)]
    detach_and_hide_windows_console(&cli);
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
            run_standalone_reindex(
                cli.clone(),
                path.clone(),
                *full,
                *force_reembed,
                *batch_size,
            )
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

use handlers::cloud_drives::{
    collect_disabled_cloud_roots, collect_filtered_initial_watch_dirs,
    collect_pass0_priority_user_roots, effective_ingest_max_file_size_bytes,
    expand_physical_watch_paths, is_disabled_cloud_root, push_watch_root_excluding_disabled,
};

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

    let catalog_is_empty = dedup.catalog().read().map(|c| c.is_empty()).unwrap_or(true);
    if catalog_is_empty {
        match dedup.hydrate_from_catalog(&storage) {
            Ok(count) if count > 0 => {
                info!(
                    count,
                    tracked_files = dedup.catalog().read().map(|c| c.len()).unwrap_or(0),
                    "Startup deduplication hydration completed synchronously from SQLite document catalog"
                );
                let _ = dedup.save_catalog_to_file(&catalog_path);
            }
            Ok(_) => {
                // SQLite catalog had 0 entries; fallback to LanceDB if <= 50,000 chunks
                let chunk_count = storage.count().await.unwrap_or(0);
                if chunk_count > 0 && chunk_count <= 50_000 {
                    match dedup.hydrate_from_storage(&storage).await {
                        Ok(chunks) => {
                            info!(
                                chunks,
                                tracked_files = dedup.catalog().read().map(|c| c.len()).unwrap_or(0),
                                "Startup deduplication hydration completed synchronously from LanceDB storage"
                            );
                            let _ = dedup.save_catalog_to_file(&catalog_path);
                        }
                        Err(e) => {
                            error!("Startup deduplication hydration warning: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                error!("Startup deduplication hydration warning: {}", e);
            }
        }
    } else {
        info!(
            tracked_files = dedup.catalog().read().map(|c| c.len()).unwrap_or(0),
            "Persistent dedup catalog active with 0-disk-read fast path"
        );
    }

    // Initialize OshoosiClaw Mesh, PHI/PII DLP & Cloud Drives persistence BEFORE constructing workers
    // Register raster pixel pornography/explicit-content safety hook for query-time Ollama vision.
    quorum_coordinator::vision::register_vision_pixel_safety_hook(|p, b| {
        !quorum_ingest::content_safety::evaluate_image_safety(p, b).is_blocked()
    });

    let mesh_dlp_controller = quorum_coordinator::global_mesh_dlp_controller();
    mesh_dlp_controller.init_persistence(&cli.data_dir);
    let discovered_cloud_drives = quorum_ingest::discover_cloud_drives();
    handlers::cloud_drives::reconcile_discovered_cloud_drives(
        &mesh_dlp_controller,
        &discovered_cloud_drives,
    );

    // 2. Ingest Config & Workers (defaults to discovered user roots + safe expanded drive slices when --watch-dir is omitted)
    let cloud_drives_settings = mesh_dlp_controller.get_cloud_drives_settings();
    let mut ingest_config = quorum_ingest::IngestConfig::default();
    ingest_config.exclude_source_code = true;
    ingest_config.max_file_size_bytes =
        effective_ingest_max_file_size_bytes(&cloud_drives_settings);
    ingest_config.access_tier_rules = mesh_dlp_controller.cloud_drive_access_tier_rules();
    ingest_config.placeholder_policy = cloud_drives_settings
        .placeholder_policy()
        .unwrap_or_default();
    ingest_config.dedup_catalog_path = Some(cli.data_dir.join("dedup_catalog.json"));
    if !ingest_config
        .excluded_paths
        .iter()
        .any(|p| p == &cli.data_dir)
    {
        ingest_config.excluded_paths.push(cli.data_dir.clone());
    }
    let disabled_cloud_roots =
        collect_disabled_cloud_roots(&mesh_dlp_controller, &discovered_cloud_drives);
    let enabled_cloud_paths = handlers::cloud_drives::collect_enabled_cloud_paths_filtered(
        &mesh_dlp_controller,
        &disabled_cloud_roots,
    );

    if let Some(ref watch_path) = cli.watch_dir {
        push_watch_root_excluding_disabled(
            watch_path,
            &disabled_cloud_roots,
            &mut ingest_config.watch_paths,
        );
        for cp in &enabled_cloud_paths {
            push_watch_root_excluding_disabled(
                cp,
                &disabled_cloud_roots,
                &mut ingest_config.watch_paths,
            );
        }
    } else {
        let isolated_watch_only = std::env::var("QUORUM_ISOLATED_WATCH_DIR")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let user_roots = if isolated_watch_only {
            Vec::new()
        } else {
            quorum_ingest::IngestConfig::discover_user_document_roots()
        };
        let physical_drives = if isolated_watch_only {
            Vec::new()
        } else {
            quorum_ingest::IngestConfig::discover_physical_drives()
        };
        info!(
            user_roots = ?user_roots,
            drives = ?physical_drives,
            "No --watch-dir specified; defaulting to discovered user document roots + expanded fixed drive slices"
        );
        let mut default_paths = Vec::new();

        // 1. Expanded non-C: data physical drive slices (skipping user profile roots & disabled cloud drives at any depth)
        let data_drives: Vec<std::path::PathBuf> = physical_drives
            .iter()
            .filter(|d| !d.to_string_lossy().to_ascii_uppercase().starts_with("C:"))
            .cloned()
            .collect();
        for slice in expand_physical_watch_paths(&data_drives, &disabled_cloud_roots) {
            if !default_paths.contains(&slice) {
                default_paths.push(slice);
            }
        }

        // 2. Documents, Desktop, Downloads
        for sub in ["documents", "desktop", "downloads"] {
            for root in &user_roots {
                let name = root
                    .file_name()
                    .map(|n| n.to_string_lossy().to_ascii_lowercase())
                    .unwrap_or_default();
                if name == sub {
                    push_watch_root_excluding_disabled(
                        root,
                        &disabled_cloud_roots,
                        &mut default_paths,
                    );
                }
            }
        }

        // 3. User document roots other than Pictures
        for root in &user_roots {
            let name = root
                .file_name()
                .map(|n| n.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if name != "pictures" {
                push_watch_root_excluding_disabled(root, &disabled_cloud_roots, &mut default_paths);
            }
        }

        // 4. Pictures roots
        for root in &user_roots {
            let name = root
                .file_name()
                .map(|n| n.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if name == "pictures" {
                push_watch_root_excluding_disabled(root, &disabled_cloud_roots, &mut default_paths);
            }
        }

        // 5. Enabled opt-in Cloud Drives
        for cp in &enabled_cloud_paths {
            push_watch_root_excluding_disabled(cp, &disabled_cloud_roots, &mut default_paths);
        }

        // 6. Expanded remaining drive slices (C:\) excluding C:\Users\<user> profile roots & disabled cloud roots
        let sys_drives: Vec<std::path::PathBuf> = physical_drives
            .into_iter()
            .filter(|d| d.to_string_lossy().to_ascii_uppercase().starts_with("C:"))
            .collect();
        for slice in expand_physical_watch_paths(&sys_drives, &disabled_cloud_roots) {
            if !default_paths.contains(&slice) {
                default_paths.push(slice);
            }
        }

        ingest_config.watch_paths = default_paths;
    }

    let dlp_gate: Arc<dyn quorum_types::DlpContentGate> =
        Arc::clone(&mesh_dlp_controller) as Arc<dyn quorum_types::DlpContentGate>;
    let reindex_worker = Arc::new(
        quorum_ingest::ReindexWorker::new(
            ingest_config.clone(),
            Arc::clone(&storage),
            Arc::clone(&classifier),
            Arc::clone(&embedder),
            Arc::clone(&dedup),
        )
        .with_dlp_gate(Arc::clone(&dlp_gate)),
    );
    reindex_worker.update_blocked_prefixes(disabled_cloud_roots.clone());

    let drift_healer = Arc::new(
        quorum_ingest::DriftHealer::new(
            ingest_config.clone(),
            Arc::clone(&storage),
            Arc::clone(&classifier),
            Arc::clone(&embedder),
            Arc::clone(&dedup),
        )
        .with_dlp_gate(dlp_gate)
        .with_reindex_barrier(&reindex_worker),
    );
    drift_healer.update_blocked_prefixes(disabled_cloud_roots.clone());

    // 3. Dynamically bind HTTP Listener on `cli.port` (or next open port)
    let (listener, bound_http_port) = bind_next_open_http_port(&cli.host, cli.port).await?;
    let chosen_p2p_port = find_next_open_p2p_port(&cli.host, cli.p2p_port, bound_http_port);

    let isolated_watch_only = std::env::var("QUORUM_ISOLATED_WATCH_DIR")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut candidate_folders = ingest_config.watch_paths.clone();
    if !isolated_watch_only {
        for user_root in quorum_ingest::IngestConfig::discover_user_document_roots() {
            push_watch_root_excluding_disabled(
                &user_root,
                &disabled_cloud_roots,
                &mut candidate_folders,
            );
        }
    }
    let non_cloud_candidates: Vec<std::path::PathBuf> = candidate_folders
        .into_iter()
        .filter(|wp| {
            let wp_str = wp.to_string_lossy();
            wp.is_dir()
                && !mesh_dlp_controller.is_cloud_drive_path(&wp_str)
                && !quorum_coordinator::OsoosiMeshDlpController::is_standard_cloud_root_marker(
                    &wp_str,
                )
        })
        .collect();

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

        // Apply CLI forensics subsystem overrides
        if cli.no_forensics || cli.forensics == Some(false) {
            guard.artemis.enabled = false;
        } else if cli.forensics == Some(true) {
            guard.artemis.enabled = true;
        }

        // Automatically populate non-cloud user document folders and watch paths into shared_folders
        for wp in &non_cloud_candidates {
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
    let inbound_obj = Arc::new(
        quorum_coordinator::OsoosiMeshInboundHandler::new(
            Arc::clone(&storage) as Arc<dyn quorum_coordinator::StorageSearcher>,
            persistent_peer_id_str.clone(),
        )
        .with_embedder(Arc::clone(&embedder)),
    );
    let inbound_handler: Arc<dyn quorum_network::InboundQueryHandler> = inbound_obj.clone();
    let (mesh_dispatcher, swarm_handle): (
        Arc<dyn quorum_coordinator::MeshQueryDispatcher>,
        Option<quorum_network::NetworkSwarmHandle>,
    ) = if cli.local_only {
        info!("Running in local-only mode (P2P swarm networking disabled).");
        (Arc::new(quorum_coordinator::LocalOnlyDispatcher), None)
    } else {
        let startup_bootstrap_peers = {
            let g = mesh_dlp_controller
                .settings
                .read()
                .unwrap_or_else(|e| e.into_inner());
            g.mesh
                .bootstrap_peers
                .iter()
                .filter_map(|s| s.trim().parse::<quorum_network::Multiaddr>().ok())
                .filter(quorum_network::is_allowed_trusted_bootstrap_address)
                .collect::<Vec<_>>()
        };
        let mut tcp_listen_addrs =
            vec![format!("/ip4/{}/tcp/{}", cli.host, chosen_p2p_port).parse()?];
        let mut quic_listen_addrs =
            vec![format!("/ip4/{}/udp/{}/quic-v1", cli.host, chosen_p2p_port).parse()?];
        if cli.host == "0.0.0.0" {
            if let Ok(ma6) = format!("/ip6/::/tcp/{}", chosen_p2p_port).parse() {
                tcp_listen_addrs.push(ma6);
            }
            if let Ok(ma6q) = format!("/ip6/::/udp/{}/quic-v1", chosen_p2p_port).parse() {
                quic_listen_addrs.push(ma6q);
            }
        }
        let net_config = quorum_network::NetworkConfig {
            ed25519_seed: Some(node_seed),
            tcp_listen_addrs,
            quic_listen_addrs,
            bootstrap_peers: startup_bootstrap_peers,
            contract_hash_hex: embedder
                .contract_hash()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect(),
            request_timeout: std::time::Duration::from_secs(120),
            ..Default::default()
        };
        match quorum_network::start_network_node(net_config, Some(inbound_handler)).await {
            Ok((_join, handle)) => {
                let disp = Arc::new(quorum_coordinator::SwarmMeshDispatcher::new(
                    handle.clone(),
                    persistent_peer_id_str.clone(),
                    node_seed,
                ));
                inbound_obj.set_dispatcher(disp.clone());
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
    coord_cfg.timeout_ms = 8000;

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
    p2p_watcher::start_p2p_watcher_supervisor(Arc::clone(&app_state), watcher_enabled, cli.service);

    // Start background periodic Artemis DFIR auto-collector (only when forensics is enabled)
    let forensics_enabled = quorum_coordinator::global_mesh_dlp_controller()
        .get_settings()
        .artemis
        .enabled;
    if forensics_enabled {
        handlers::artemis::spawn_artemis_auto_collector(
            Arc::clone(&app_state),
            Arc::clone(&shutdown_notify),
        );
    }

    // Feature 15 & 16: Calculate live host resources FIRST (`HardwareTelemetry` + `AutoFusionRouter::calculate_provision_plan`),
    // then provision ONLY the hardware-fitted model tier (single-flight, non-blocking).
    if !crate::nimble_provisioner::NimbleProvisioner::is_autoinstall_disabled() {
        let nimble_prov = app_state.nimble_provisioner();
        tokio::spawn(async move {
            let pre_plan = nimble_prov.calculate_provision_plan(&[]);
            info!(
                "Pre-provisioning resource calculation: {:.1} GB free RAM, {} MB free VRAM, {:.1} GB free disk -> requested='{}', effective='{}', downsized={}",
                pre_plan.free_ram_gb,
                pre_plan.free_vram_mb,
                pre_plan.free_disk_gb,
                pre_plan.requested_tag,
                pre_plan.effective_tag,
                pre_plan.downsized_for_resources
            );
            if !pre_plan.disk_sufficient {
                warn!(
                    "Skipping automatic model provisioning: insufficient disk space ({:.1} GB free)",
                    pre_plan.free_disk_gb
                );
                return;
            }

            let mut status = nimble_prov.probe_status().await;
            if status.state == "offline" && nimble_prov.ensure_ollama_daemon_async().await {
                status = nimble_prov.probe_status().await;
            }

            if !pre_plan.downsized_for_resources && status.memory_sufficient {
                if status.state == "not_installed" {
                    info!(
                        "Resources sufficient for Nimble-9B ({:.1} GB free RAM); launching single-flight background provisioning...",
                        status.free_ram_gb
                    );
                    let _ = nimble_prov.trigger_provision();
                }
            } else if status.fallback_state != "ready" && status.fallback_state != "downloading" {
                info!(
                    "Nimble-9B gated by pre-provisioning resource calculation ({:.1} GB free RAM); auto-provisioning hardware-sized fallback '{}'...",
                    status.free_ram_gb, status.fallback_model_tag
                );
                let _ = nimble_prov.spawn_fallback_pull(&status.fallback_model_tag);
            }
        });
    } else {
        info!("QUORUM_DISABLE_OLLAMA_AUTOINSTALL=1 set; skipping automated Nimble-9B background provisioning");
    }

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
                        let _ = dial_handle.dial_trusted(ma).await;
                    }
                }
                for cached_ma in dial_state.p2p_watcher().load_known_peers().multiaddrs {
                    if let Ok(ma) = cached_ma.parse::<quorum_network::Multiaddr>() {
                        let _ = dial_handle.dial_trusted(ma).await;
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
                        let _ = dial_handle.dial_trusted(ma).await;
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
                                let _ = dial_handle.dial_trusted(ma).await;
                            }
                        }
                    }
                }

                // Travel / Cross-Network WAN & Overlay Connectivity:
                // 1. Best-effort SSDP UPnP IGD port-forwarding for TCP/UDP p2p_port + WAN IP discovery.
                // 2. Concurrent DuckDNS + Tailscale (100.64.0.0/10) + explicit bootstrap_peers + persisted WAN peer dials.
                let local_v4s = discover_local_private_ipv4_addresses();
                if let Some(primary_lan) = local_v4s.first().copied() {
                    let _ = wan_mesh::try_upnp_igd_map_mesh_ports(primary_lan, p2p_port).await;
                }
                let mesh_cfg_snap = {
                    let ctrl = quorum_coordinator::global_mesh_dlp_controller();
                    let g = ctrl.settings.read().unwrap_or_else(|e| e.into_inner());
                    g.mesh.clone()
                };
                if mesh_cfg_snap.p2p_enabled {
                    let known_list = dial_state.p2p_watcher().load_known_peers().multiaddrs;
                    let wan_targets = wan_mesh::collect_wan_and_overlay_dial_targets(
                        &mesh_cfg_snap,
                        &known_list,
                        &local_v4s,
                    )
                    .await;
                    let mut wan_futs = futures_util::stream::FuturesUnordered::new();
                    for target_str in wan_targets {
                        if let Ok(ma) = target_str.parse::<quorum_network::Multiaddr>() {
                            let h = dial_handle.clone();
                            wan_futs.push(async move {
                                let _ = h.dial_trusted(ma).await;
                            });
                        }
                    }
                    use futures_util::StreamExt;
                    while wan_futs.next().await.is_some() {}
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

    // Ensure `<data_dir>/uploaded_documents` exists and is watched
    let uploaded_docs_dir = cli.data_dir.join("uploaded_documents");
    let _ = std::fs::create_dir_all(&uploaded_docs_dir);

    // Collect initial real-time watch directories (user roots + uploaded_documents + shared_folders + opt_in_folders + expanded workspace slices)
    let isolated_watch_only = std::env::var("QUORUM_ISOLATED_WATCH_DIR")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let user_watch_roots = if isolated_watch_only {
        Vec::new()
    } else {
        quorum_ingest::IngestConfig::discover_user_document_roots()
    };
    let mut shared_watch_folders = Vec::new();
    if let Ok(guard) = quorum_coordinator::global_mesh_dlp_controller()
        .settings
        .read()
    {
        for folder in &guard.mesh.shared_folders {
            if folder.enabled {
                shared_watch_folders.push(std::path::PathBuf::from(&folder.path));
            }
        }
    }
    let mut opt_in_watch_folders = Vec::new();
    if let Ok(store) = app_state.marketplace_store() {
        if let Ok(cfg) = store.get_config() {
            for f in &cfg.opt_in_folders {
                opt_in_watch_folders.push(std::path::PathBuf::from(f));
            }
        }
    }
    let live_enabled_cloud_paths = handlers::cloud_drives::collect_enabled_cloud_paths_filtered(
        &mesh_dlp_controller,
        &disabled_cloud_roots,
    );
    let expanded_watch_paths =
        expand_physical_watch_paths(&ingest_config.watch_paths, &disabled_cloud_roots);
    let initial_watch_dirs = collect_filtered_initial_watch_dirs(
        &user_watch_roots,
        Some(&uploaded_docs_dir),
        &shared_watch_folders,
        &opt_in_watch_folders,
        &live_enabled_cloud_paths,
        &expanded_watch_paths,
        &disabled_cloud_roots,
    );
    reindex_worker.add_watch_paths(&initial_watch_dirs);

    // Start real-time OS FilesystemWatcher (`ReadDirectoryChangesW` / `inotify` / `FSEvents`)
    let mut rt_watcher_cfg = ingest_config.clone();
    rt_watcher_cfg.debounce_duration_ms = 200;
    rt_watcher_cfg.watch_paths = initial_watch_dirs
        .iter()
        .filter(|p| {
            let is_enabled_cloud_drive = live_enabled_cloud_paths.iter().any(|cp| cp == *p);
            p.exists()
                && p.is_dir()
                && (is_enabled_cloud_drive || (p.parent().is_some() && p.to_string_lossy().len() > 3))
                && !handlers::cloud_drives::is_user_profile_root_dir(p)
                && !is_disabled_cloud_root(p, &disabled_cloud_roots)
                && !handlers::cloud_drives::is_strict_ancestor_of_disabled_cloud_root(
                    p,
                    &disabled_cloud_roots,
                )
        })
        .cloned()
        .collect();
    match quorum_ingest::FilesystemWatcher::new(rt_watcher_cfg).start_watching() {
        Ok((mut watcher_rx, watcher_handle)) => {
            let handle_arc = Arc::new(watcher_handle);
            app_state.set_fs_watcher(Arc::clone(&handle_arc));
            let watcher_state = Arc::clone(&app_state);
            let watcher_shutdown = Arc::clone(&shutdown_notify);
            let abs_data_dir_str = std::fs::canonicalize(&cli.data_dir)
                .unwrap_or_else(|_| {
                    std::env::current_dir()
                        .map(|cwd| cwd.join(&cli.data_dir))
                        .unwrap_or_else(|_| cli.data_dir.clone())
                })
                .to_string_lossy()
                .trim_start_matches(r"\\?\")
                .to_ascii_lowercase();
            let abs_uploads_dir_str = std::fs::canonicalize(&uploaded_docs_dir)
                .unwrap_or_else(|_| {
                    std::env::current_dir()
                        .map(|cwd| cwd.join(&uploaded_docs_dir))
                        .unwrap_or_else(|_| uploaded_docs_dir.clone())
                })
                .to_string_lossy()
                .trim_start_matches(r"\\?\")
                .to_ascii_lowercase();
            let excluded_data_dir = cli.data_dir.clone();
            let allowed_uploads_dir = uploaded_docs_dir.clone();
            let watcher_discovered_cloud = discovered_cloud_drives.clone();

            tokio::spawn(async move {
                let is_internal_noise = |p: &std::path::Path| -> bool {
                    if p.starts_with(&excluded_data_dir) && !p.starts_with(&allowed_uploads_dir) {
                        return true;
                    }
                    let s = p
                        .to_string_lossy()
                        .trim_start_matches(r"\\?\")
                        .to_ascii_lowercase();
                    if !abs_data_dir_str.is_empty()
                        && s.starts_with(&abs_data_dir_str)
                        && !s.starts_with(&abs_uploads_dir_str)
                    {
                        return true;
                    }
                    s.contains("\\target\\")
                        || s.contains("/target/")
                        || s.ends_with("\\target")
                        || s.ends_with("/target")
                        || s.contains("\\.git\\")
                        || s.contains("/.git/")
                        || s.ends_with("\\.git")
                        || s.ends_with("/.git")
                        || s.contains("\\.atlaskv\\")
                        || s.contains("/.atlaskv/")
                        || s.ends_with("\\.atlaskv")
                        || s.ends_with("/.atlaskv")
                        || s.contains("\\node_modules\\")
                        || s.contains("/node_modules/")
                        || s.contains("\\appdata\\")
                        || s.contains("/appdata/")
                        || s.contains("\\temp\\")
                        || s.contains("/temp/")
                        || s.contains("\\.gemini\\")
                        || s.contains("/.gemini/")
                        || s.contains("\\.cargo\\")
                        || s.contains("\\.rustup\\")
                        || s.contains(".lance")
                        || s.contains(".tantivy")
                        || s.contains("quorumrag-service.log")
                        || s.contains("p2p-watcher.log")
                        || s.contains("p2p_watcher")
                        || s.contains("p2p_known_peers.json")
                        || s.ends_with(".metadata.json")
                        || s.ends_with(".db-wal")
                        || s.ends_with(".db-shm")
                        || s.ends_with(".db-journal")
                        || s.ends_with("dedup_catalog.json")
                        || s.ends_with(".tmp")
                };

                loop {
                    let first_evt = tokio::select! {
                        _ = watcher_shutdown.notified() => break,
                        evt = watcher_rx.recv() => match evt {
                            Some(e) => e,
                            None => break,
                        }
                    };

                    let mut batch_events = vec![first_evt];
                    let coalesce_deadline =
                        tokio::time::Instant::now() + std::time::Duration::from_millis(150);
                    while let Ok(Some(next_evt)) =
                        tokio::time::timeout_at(coalesce_deadline, watcher_rx.recv()).await
                    {
                        batch_events.push(next_evt);
                        if batch_events.len() >= 256 {
                            break;
                        }
                    }

                    let live_disabled_cloud = collect_disabled_cloud_roots(
                        &quorum_coordinator::global_mesh_dlp_controller(),
                        &watcher_discovered_cloud,
                    );
                    let mut paths_to_index: Vec<std::path::PathBuf> = Vec::new();
                    let mut paths_to_remove: Vec<String> = Vec::new();

                    for evt in batch_events {
                        match evt {
                            quorum_ingest::WatcherEvent::Create(p)
                            | quorum_ingest::WatcherEvent::Modify(p) => {
                                if !is_internal_noise(&p)
                                    && !is_disabled_cloud_root(&p, &live_disabled_cloud)
                                    && !watcher_state.reindex_worker.is_path_blocked(&p)
                                    && p.exists()
                                    && !paths_to_index.contains(&p)
                                {
                                    paths_to_index.push(p);
                                }
                            }
                            quorum_ingest::WatcherEvent::Rename { from, to } => {
                                if !is_internal_noise(&from) {
                                    paths_to_remove.push(from.to_string_lossy().to_string());
                                }
                                if !is_internal_noise(&to)
                                    && !is_disabled_cloud_root(&to, &live_disabled_cloud)
                                    && !watcher_state.reindex_worker.is_path_blocked(&to)
                                    && to.exists()
                                    && !paths_to_index.contains(&to)
                                {
                                    paths_to_index.push(to);
                                }
                            }
                            quorum_ingest::WatcherEvent::Remove(p) => {
                                if !is_internal_noise(&p) {
                                    paths_to_remove.push(p.to_string_lossy().to_string());
                                }
                            }
                            quorum_ingest::WatcherEvent::QueueOverflow { root, .. } => {
                                if !root.as_os_str().is_empty()
                                    && root.exists()
                                    && !watcher_state.reindex_worker.is_path_blocked(&root)
                                {
                                    push_watch_root_excluding_disabled(
                                        &root,
                                        &live_disabled_cloud,
                                        &mut paths_to_index,
                                    );
                                }
                            }
                        }
                    }

                    if !paths_to_remove.is_empty() {
                        let _ = watcher_state
                            .storage
                            .delete_by_file_paths(&paths_to_remove)
                            .await;
                        for removed in &paths_to_remove {
                            watcher_state.dedup.remove_file(std::path::Path::new(removed));
                        }
                        watcher_state.coordinator.cache_clear_all();
                    }
                    if !paths_to_index.is_empty() {
                        info!(
                            changed_count = paths_to_index.len(),
                            sample = %paths_to_index[0].display(),
                            "Real-time OS FilesystemWatcher detected disk write; triggering immediate indexing"
                        );
                        let _ = watcher_state.watch_and_index_paths(paths_to_index).await;
                    }
                }
            });
        }
        Err(e) => {
            error!("Failed to start real-time OS FilesystemWatcher: {}", e);
        }
    }

    // Continuously run background crawl & incremental ingestion unconditionally
    let bg_worker = Arc::clone(&reindex_worker);
    let bg_storage = Arc::clone(&storage);
    let bg_state = Arc::clone(&app_state);
    let bg_data_dir = cli.data_dir.clone();
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

        // Pass 0: Priority fast pass over user document folders AND enabled cloud drives
        // so enabled cloud drives start auto-indexing immediately on startup.
        let pass0_controller = quorum_coordinator::global_mesh_dlp_controller();
        let pass0_disabled_cloud =
            collect_disabled_cloud_roots(&pass0_controller, &discovered_cloud_drives);
        let pass0_raw_roots = if isolated_watch_only {
            Vec::new()
        } else {
            quorum_ingest::IngestConfig::discover_user_document_roots()
        };
        let up_dir = bg_data_dir.join("uploaded_documents");
        let mut priority_user_roots = collect_pass0_priority_user_roots(
            &pass0_raw_roots,
            Some(&up_dir),
            &pass0_disabled_cloud,
        );
        for cp in handlers::cloud_drives::collect_enabled_cloud_paths_filtered(
            &pass0_controller,
            &pass0_disabled_cloud,
        ) {
            push_watch_root_excluding_disabled(
                &cp,
                &pass0_disabled_cloud,
                &mut priority_user_roots,
            );
        }
        if !priority_user_roots.is_empty() && bg_worker.get_progress().await.is_none() {
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
        let mut watched_cloud_paths_seen: std::collections::HashSet<std::path::PathBuf> =
            std::collections::HashSet::new();
        loop {
            let controller = quorum_coordinator::global_mesh_dlp_controller();
            let live_discovered_cloud =
                tokio::task::spawn_blocking(quorum_ingest::discover_cloud_drives)
                    .await
                    .unwrap_or_default();
            handlers::cloud_drives::reconcile_discovered_cloud_drives(
                &controller,
                &live_discovered_cloud,
            );
            let live_disabled_cloud =
                collect_disabled_cloud_roots(&controller, &live_discovered_cloud);
            bg_worker.update_blocked_prefixes(live_disabled_cloud.clone());
            bg_state
                .drift_healer
                .update_blocked_prefixes(live_disabled_cloud.clone());
            let live_enabled_cloud = handlers::cloud_drives::collect_enabled_cloud_paths_filtered(
                &controller,
                &live_disabled_cloud,
            );
            // Evict temporarily unmounted or disabled cloud roots so remounting re-attaches
            // the OS FilesystemWatcher handle automatically.
            watched_cloud_paths_seen.retain(|p| p.is_dir() && live_enabled_cloud.contains(p));
            // Automatically attach any newly mounted or enabled cloud drives to the real-time
            // FilesystemWatcher, ReindexWorker, and DriftHealer, and priority-queue them if a
            // long physical scan is already underway.
            let mut newly_mounted_cloud: Vec<std::path::PathBuf> = Vec::new();
            for cp in &live_enabled_cloud {
                if cp.is_dir() && watched_cloud_paths_seen.insert(cp.clone()) {
                    newly_mounted_cloud.push(cp.clone());
                }
            }
            if !newly_mounted_cloud.is_empty() {
                if let Some(watcher) = bg_state.fs_watcher() {
                    for cp in &newly_mounted_cloud {
                        if !handlers::cloud_drives::is_user_profile_root_dir(cp)
                            && !is_disabled_cloud_root(cp, &live_disabled_cloud)
                            && !handlers::cloud_drives::is_strict_ancestor_of_disabled_cloud_root(
                                cp,
                                &live_disabled_cloud,
                            )
                        {
                            let _ = watcher.watch_path(cp);
                        }
                    }
                }
                bg_worker.add_watch_paths(&newly_mounted_cloud);
                bg_state.sync_drift_healer_watch_paths().await;
            }
            let mut target_paths: Vec<std::path::PathBuf> = Vec::new();
            for cp in &live_enabled_cloud {
                push_watch_root_excluding_disabled(cp, &live_disabled_cloud, &mut target_paths);
            }
            for p in bg_worker.all_watch_paths() {
                push_watch_root_excluding_disabled(&p, &live_disabled_cloud, &mut target_paths);
            }
            if let Ok(guard) = controller.settings.read() {
                for folder in &guard.mesh.shared_folders {
                    if folder.enabled {
                        let p = std::path::PathBuf::from(&folder.path);
                        push_watch_root_excluding_disabled(
                            &p,
                            &live_disabled_cloud,
                            &mut target_paths,
                        );
                    }
                }
            }
            if let Ok(store) = bg_state.marketplace_store() {
                if let Ok(cfg) = store.get_config() {
                    for folder in &cfg.opt_in_folders {
                        let p = std::path::PathBuf::from(folder);
                        if p.exists() {
                            push_watch_root_excluding_disabled(
                                &p,
                                &live_disabled_cloud,
                                &mut target_paths,
                            );
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

            if !is_running && !target_paths.is_empty() {
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
            } else if is_running && !newly_mounted_cloud.is_empty() {
                let _ = bg_worker.trigger_paths(newly_mounted_cloud).await;
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

    // Register raster pixel pornography/explicit-content safety hook for query-time Ollama vision.
    quorum_coordinator::vision::register_vision_pixel_safety_hook(|p, b| {
        !quorum_ingest::content_safety::evaluate_image_safety(p, b).is_blocked()
    });

    let mesh_dlp_controller = quorum_coordinator::global_mesh_dlp_controller();
    mesh_dlp_controller.init_persistence(&cli.data_dir);
    let discovered_cloud = quorum_ingest::discover_cloud_drives();
    handlers::cloud_drives::reconcile_discovered_cloud_drives(
        &mesh_dlp_controller,
        &discovered_cloud,
    );
    let disabled_cloud_roots =
        collect_disabled_cloud_roots(&mesh_dlp_controller, &discovered_cloud);
    let cloud_drives_settings = mesh_dlp_controller.get_cloud_drives_settings();

    let target_paths = if let Some(p) = path {
        let mut filtered = Vec::new();
        push_watch_root_excluding_disabled(&p, &disabled_cloud_roots, &mut filtered);
        filtered
    } else if let Some(w) = cli.watch_dir {
        let mut filtered = Vec::new();
        push_watch_root_excluding_disabled(&w, &disabled_cloud_roots, &mut filtered);
        filtered
    } else {
        let physical = quorum_ingest::IngestConfig::discover_physical_drives();
        let mut expanded = expand_physical_watch_paths(&physical, &disabled_cloud_roots);
        for cp in handlers::cloud_drives::collect_enabled_cloud_paths_filtered(
            &mesh_dlp_controller,
            &disabled_cloud_roots,
        ) {
            push_watch_root_excluding_disabled(&cp, &disabled_cloud_roots, &mut expanded);
        }
        expanded
    };

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
    ingest_cfg.max_file_size_bytes = effective_ingest_max_file_size_bytes(&cloud_drives_settings);
    ingest_cfg.access_tier_rules = mesh_dlp_controller.cloud_drive_access_tier_rules();
    ingest_cfg.placeholder_policy = cloud_drives_settings
        .placeholder_policy()
        .unwrap_or_default();
    ingest_cfg.dedup_catalog_path = Some(catalog_path);
    if !ingest_cfg.excluded_paths.iter().any(|p| p == &cli.data_dir) {
        ingest_cfg.excluded_paths.push(cli.data_dir.clone());
    }

    let dlp_gate: Arc<dyn quorum_types::DlpContentGate> =
        Arc::clone(&mesh_dlp_controller) as Arc<dyn quorum_types::DlpContentGate>;
    let worker =
        quorum_ingest::ReindexWorker::new(ingest_cfg, storage, classifier, embedder, dedup)
            .with_dlp_gate(dlp_gate);
    worker.update_blocked_prefixes(disabled_cloud_roots);

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

    // Register raster pixel pornography/explicit-content safety hook for query-time Ollama vision.
    quorum_coordinator::vision::register_vision_pixel_safety_hook(|p, b| {
        !quorum_ingest::content_safety::evaluate_image_safety(p, b).is_blocked()
    });

    let mesh_dlp_controller = quorum_coordinator::global_mesh_dlp_controller();
    mesh_dlp_controller.init_persistence(&cli.data_dir);
    let discovered_cloud = quorum_ingest::discover_cloud_drives();
    handlers::cloud_drives::reconcile_discovered_cloud_drives(
        &mesh_dlp_controller,
        &discovered_cloud,
    );
    let access_tier_rules = mesh_dlp_controller.cloud_drive_access_tier_rules();
    let disabled_cloud_roots =
        collect_disabled_cloud_roots(&mesh_dlp_controller, &discovered_cloud);
    let cloud_drives_settings = mesh_dlp_controller.get_cloud_drives_settings();

    let mut ingest_cfg = quorum_ingest::IngestConfig::default();
    ingest_cfg.exclude_source_code = true;
    ingest_cfg.max_file_size_bytes = effective_ingest_max_file_size_bytes(&cloud_drives_settings);
    ingest_cfg.access_tier_rules = access_tier_rules.clone();
    ingest_cfg.placeholder_policy = cloud_drives_settings
        .placeholder_policy()
        .unwrap_or_default();
    if let Some(ref w) = cli.watch_dir {
        push_watch_root_excluding_disabled(w, &disabled_cloud_roots, &mut ingest_cfg.watch_paths);
    } else {
        let physical = quorum_ingest::IngestConfig::discover_physical_drives();
        let mut expanded = expand_physical_watch_paths(&physical, &disabled_cloud_roots);
        for cp in handlers::cloud_drives::collect_enabled_cloud_paths_filtered(
            &mesh_dlp_controller,
            &disabled_cloud_roots,
        ) {
            push_watch_root_excluding_disabled(&cp, &disabled_cloud_roots, &mut expanded);
        }
        ingest_cfg.watch_paths = expanded;
    }

    let dlp_gate: Arc<dyn quorum_types::DlpContentGate> =
        Arc::clone(&mesh_dlp_controller) as Arc<dyn quorum_types::DlpContentGate>;
    let healer = quorum_ingest::DriftHealer::new(ingest_cfg, storage, classifier, embedder, dedup)
        .with_dlp_gate(dlp_gate);
    healer.update_blocked_prefixes(disabled_cloud_roots);

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
            access_tier_rules,
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
