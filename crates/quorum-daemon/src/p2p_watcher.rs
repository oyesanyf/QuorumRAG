//! Dedicated P2P Mesh Watcher Process & Self-Healing Supervisor (`quorumrag watch-p2p`).
//!
//! Guarantees continuous P2P mesh connectivity and query responsiveness across Windows, Linux, and macOS via:
//! 1. **Out-of-Process OS Watcher (`watch-p2p`)**: Independent child process that continuously verifies
//!    daemon `/api/health`, local TCP P2P listener binding, ARP + `/24` LAN peer reachability, and end-to-end
//!    Ed25519-signed libp2p request-response round-trips, triggering automatic heal/redial whenever a peer
//!    drops or a Yamux stream wedges.
//! 2. **In-Daemon Child Supervisor**: Monitors the `watch-p2p` OS child process and respawns it automatically
//!    if terminated unexpectedly, while reaping it cleanly during graceful shutdown.
//! 3. **Persisted Known-Peer Cache (`<data_dir>/p2p_known_peers.json`)**: Remembers verified LAN/WAN peer
//!    multiaddrs across restarts for sub-500ms reconnection at startup before subnet scanning begins.

use axum::extract::{Json, State};
use axum::response::IntoResponse;
use chrono::Utc;
use quorum_coordinator::{
    global_mesh_dlp_controller, global_peer_health_registry, sign_request, PeerHealthStats,
    P2P_WATCHER_CANARY_QUERY,
};
use quorum_network::{libp2p::PeerId, Multiaddr};
use quorum_types::{AccessTier, FederatedQueryRequest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tracing::{info, warn};
use uuid::Uuid;

use crate::cli::Cli;
use crate::state::DaemonState;

/// Helper to determine if an IPv4 address belongs to an RFC1918 private LAN subnet
/// (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and is not loopback, link-local, or unspecified.
pub fn is_private_lan_ipv4(ipv4: &Ipv4Addr) -> bool {
    if ipv4.is_loopback() || ipv4.is_unspecified() || ipv4.is_link_local() {
        return false;
    }
    let oct = ipv4.octets();
    if oct[0] == 10 {
        return true;
    }
    if oct[0] == 172 && (16..=31).contains(&oct[1]) {
        return true;
    }
    if oct[0] == 192 && oct[1] == 168 {
        return true;
    }
    false
}

/// Discovers the local host's real network interface IPv4 addresses on private LAN subnets
/// using kernel routing table probes via connected UDP sockets and hostname resolution.
pub fn discover_local_private_ipv4_addresses() -> Vec<Ipv4Addr> {
    let mut discovered: Vec<Ipv4Addr> = Vec::new();
    let probe_targets = [
        "1.1.1.1:80",
        "8.8.8.8:80",
        "10.255.255.255:80",
        "10.0.0.1:80",
        "10.1.1.1:80",
        "172.16.0.1:80",
        "172.31.255.255:80",
        "192.168.0.1:80",
        "192.168.1.1:80",
        "192.168.2.1:80",
        "192.168.50.1:80",
        "192.168.100.1:80",
        "192.168.178.1:80",
    ];

    for target in probe_targets {
        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
            if socket.connect(target).is_ok() {
                if let Ok(SocketAddr::V4(addr)) = socket.local_addr() {
                    let ip = *addr.ip();
                    if is_private_lan_ipv4(&ip) && !discovered.contains(&ip) {
                        discovered.push(ip);
                    }
                }
            }
        }
    }

    if let Ok(host) = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")) {
        if let Ok(addrs) = format!("{}:0", host).to_socket_addrs() {
            for sa in addrs {
                if let SocketAddr::V4(v4) = sa {
                    let ip = *v4.ip();
                    if is_private_lan_ipv4(&ip) && !discovered.contains(&ip) {
                        discovered.push(ip);
                    }
                }
            }
        }
    }

    discovered
}

/// Per-peer canary probe outcome recorded by `/api/mesh/watcher/probe`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCanaryProbeResult {
    pub peer_id: String,
    pub multiaddr: Option<String>,
    pub reachable: bool,
    pub rtt_ms: f64,
    pub consecutive_failures: u32,
    pub error: Option<String>,
    pub probed_at: String,
}

/// Persisted known-peer cache stored at `<data_dir>/p2p_known_peers.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedKnownPeers {
    pub updated_at: String,
    pub multiaddrs: Vec<String>,
    #[serde(default)]
    pub peer_map: HashMap<String, String>,
}

/// Live status payload returned by `GET /api/mesh/watcher` and persisted to `<data_dir>/p2p_watcher_status.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pWatcherStatusDto {
    pub active: bool,
    pub watcher_pid: Option<u32>,
    pub daemon_pid: u32,
    pub watcher_restarts: u64,
    pub p2p_enabled: bool,
    pub p2p_port: u16,
    pub connected_peers: usize,
    pub healthy_peers: usize,
    pub known_cached_peers: Vec<String>,
    pub probe_runs: u64,
    pub heal_runs: u64,
    pub zombies_evicted: u64,
    pub peers_redialed: u64,
    pub last_probe_at: Option<String>,
    pub last_heal_at: Option<String>,
    pub last_heal_reason: Option<String>,
    pub peer_probes: Vec<PeerCanaryProbeResult>,
    pub peer_health: HashMap<String, PeerHealthStats>,
}

/// Optional payload accepted by `POST /api/mesh/watcher/heal`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HealMeshRequest {
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub discovered_ips: Vec<String>,
    #[serde(default)]
    pub force_redial_all: bool,
}

/// Shared runtime state held inside `DaemonState` for supervising the `watch-p2p` OS child process
/// and serving `/api/mesh/watcher/*` control endpoints.
pub struct P2pWatcherRuntime {
    pub data_dir: PathBuf,
    pub p2p_port: u16,
    pub node_seed: [u8; 32],
    pub local_peer_id: String,
    pub enabled: AtomicBool,
    pub shutting_down: AtomicBool,
    pub watcher_pid: AtomicU32,
    pub watcher_restarts: AtomicU64,
    pub probe_runs: AtomicU64,
    pub heal_runs: AtomicU64,
    pub zombies_evicted: AtomicU64,
    pub peers_redialed: AtomicU64,
    pub child_process: Mutex<Option<std::process::Child>>,
    pub last_probe_at: RwLock<Option<String>>,
    pub last_heal_at: RwLock<Option<String>>,
    pub last_heal_reason: RwLock<Option<String>>,
    pub last_probe_results: RwLock<Vec<PeerCanaryProbeResult>>,
}

impl P2pWatcherRuntime {
    pub fn new(
        data_dir: PathBuf,
        p2p_port: u16,
        node_seed: [u8; 32],
        local_peer_id: String,
        enabled: bool,
    ) -> Self {
        Self {
            data_dir,
            p2p_port,
            node_seed,
            local_peer_id,
            enabled: AtomicBool::new(enabled),
            shutting_down: AtomicBool::new(false),
            watcher_pid: AtomicU32::new(0),
            watcher_restarts: AtomicU64::new(0),
            probe_runs: AtomicU64::new(0),
            heal_runs: AtomicU64::new(0),
            zombies_evicted: AtomicU64::new(0),
            peers_redialed: AtomicU64::new(0),
            child_process: Mutex::new(None),
            last_probe_at: RwLock::new(None),
            last_heal_at: RwLock::new(None),
            last_heal_reason: RwLock::new(None),
            last_probe_results: RwLock::new(Vec::new()),
        }
    }

    pub fn known_peers_path(&self) -> PathBuf {
        self.data_dir.join("p2p_known_peers.json")
    }

    pub fn lock_file_path(&self) -> PathBuf {
        self.data_dir.join("p2p_watcher.lock")
    }

    pub fn load_known_peers(&self) -> PersistedKnownPeers {
        load_known_peers_from_dir(&self.data_dir)
    }

    pub fn save_known_peers_snapshot(&self, connected: &HashMap<PeerId, Multiaddr>) {
        if connected.is_empty() {
            return;
        }
        let mut cache = self.load_known_peers();
        let mut set: BTreeSet<String> = cache.multiaddrs.into_iter().collect();

        for (pid, addr) in connected {
            let dialable = strip_p2p_suffix(&addr.to_string());
            if is_dialable_lan_or_wan_multiaddr(&dialable) {
                set.insert(dialable.clone());
                cache.peer_map.insert(pid.to_string(), dialable);
            }
        }

        cache.multiaddrs = set.into_iter().collect();
        cache.updated_at = Utc::now().to_rfc3339();
        if let Ok(json) = serde_json::to_string_pretty(&cache) {
            let _ = std::fs::write(self.known_peers_path(), json);
        }
    }

    /// Terminates and reaps the supervised `watch-p2p` OS child process during graceful daemon shutdown.
    pub fn stop_child_process(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
        if let Ok(mut guard) = self.child_process.lock() {
            if let Some(mut child) = guard.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        self.watcher_pid.store(0, Ordering::SeqCst);
        let _ = std::fs::remove_file(self.lock_file_path());
    }
}

/// Loads persisted known peer multiaddrs from `<data_dir>/p2p_known_peers.json`.
pub fn load_known_peers_from_dir(data_dir: &Path) -> PersistedKnownPeers {
    let path = data_dir.join("p2p_known_peers.json");
    if let Ok(raw) = std::fs::read_to_string(&path) {
        if let Ok(parsed) = serde_json::from_str::<PersistedKnownPeers>(&raw) {
            return parsed;
        }
    }
    PersistedKnownPeers::default()
}

/// Strips trailing `/p2p/<PeerId>` from a multiaddr so dialing works even if a remote host regenerated its keypair,
/// while Noise handshake still verifies cryptographic PeerId authenticity.
pub fn strip_p2p_suffix(addr: &str) -> String {
    if let Some((base, _)) = addr.split_once("/p2p/") {
        base.to_string()
    } else {
        addr.to_string()
    }
}

/// Validates that a multiaddr points to a dialable private LAN or routable host (rejecting loopback/unspecified/ephemeral).
pub fn is_dialable_lan_or_wan_multiaddr(addr: &str) -> bool {
    if let Some(rest) = addr.strip_prefix("/ip4/") {
        let mut parts = rest.split('/');
        let Some(ip_str) = parts.next() else {
            return false;
        };
        let Ok(ip) = ip_str.parse::<Ipv4Addr>() else {
            return false;
        };
        if ip.is_loopback() || ip.is_unspecified() || ip.is_link_local() || ip.is_multicast() {
            return false;
        }
        let oct = ip.octets();
        if oct[3] == 0 || oct[3] == 255 {
            return false;
        }
        if let (Some(proto), Some(port_str)) = (parts.next(), parts.next()) {
            if (proto == "tcp" || proto == "udp") && port_str.parse::<u16>().unwrap_or(0) > 0 {
                return true;
            }
        }
        false
    } else {
        addr.starts_with("/dns4/") || addr.starts_with("/dns/")
    }
}

/// Extracts `ip:port` from a libp2p Multiaddr string for clean UI display in `/api/peers`.
pub fn format_socket_from_multiaddr(addr: &str) -> Option<String> {
    let clean = strip_p2p_suffix(addr);
    if let Some(rest) = clean.strip_prefix("/ip4/") {
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() >= 3 && (parts[1] == "tcp" || parts[1] == "udp") {
            return Some(format!("{}:{}", parts[0], parts[2]));
        }
    } else if let Some(rest) = clean.strip_prefix("/dns4/") {
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() >= 3 {
            return Some(format!("{}:{}", parts[0], parts[2]));
        }
    }
    None
}

/// Parses the OS ARP neighbor table (`arp -a`) to immediately discover active RFC1918 LAN hosts
/// across `/8`, `/16`, and `/24` private networks without waiting for full subnet sweeps.
pub fn discover_arp_private_lan_neighbors(self_ips: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    let mut neighbors = BTreeSet::new();
    let output = match std::process::Command::new("arp").arg("-a").output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    for token in text.split(|c: char| {
        c.is_whitespace() || matches!(c, '(' | ')' | '[' | ']' | ',' | ';' | '<' | '>')
    }) {
        if token.chars().filter(|&c| c == '.').count() != 3 {
            continue;
        }
        if let Ok(ip) = token.parse::<Ipv4Addr>() {
            let oct = ip.octets();
            if oct[3] == 0 || oct[3] == 255 {
                continue;
            }
            if is_private_lan_ipv4(&ip) && !self_ips.contains(&ip) {
                neighbors.insert(ip);
            }
        }
    }
    neighbors.into_iter().collect()
}

/// Probes candidate IPv4 hosts in parallel for an open TCP `p2p_port` (`140ms` connect timeout).
pub async fn probe_open_p2p_hosts(candidates: Vec<Ipv4Addr>, p2p_port: u16) -> Vec<Ipv4Addr> {
    if candidates.is_empty() {
        return Vec::new();
    }
    let mut open_hosts = BTreeSet::new();
    for chunk in candidates.chunks(64) {
        let mut join_set = tokio::task::JoinSet::new();
        for &ip in chunk {
            join_set.spawn(async move {
                let sock = SocketAddr::from((ip, p2p_port));
                match tokio::time::timeout(
                    Duration::from_millis(140),
                    tokio::net::TcpStream::connect(sock),
                )
                .await
                {
                    Ok(Ok(stream)) => {
                        drop(stream);
                        Some(ip)
                    }
                    _ => None,
                }
            });
        }
        while let Some(res) = join_set.join_next().await {
            if let Ok(Some(ip)) = res {
                open_hosts.insert(ip);
            }
        }
    }
    open_hosts.into_iter().collect()
}

/// Discovers all reachable LAN peers listening on `p2p_port` across persisted cache, ARP cache, and `/24` prefixes.
pub async fn discover_reachable_lan_p2p_ips(
    data_dir: &Path,
    p2p_port: u16,
    include_full_subnet_sweep: bool,
) -> Vec<Ipv4Addr> {
    let self_ips = discover_local_private_ipv4_addresses();
    let mut candidates = BTreeSet::new();

    let known = load_known_peers_from_dir(data_dir);
    for ma in &known.multiaddrs {
        if let Some(rest) = ma.strip_prefix("/ip4/") {
            if let Some(ip_str) = rest.split('/').next() {
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    if is_private_lan_ipv4(&ip) && !self_ips.contains(&ip) {
                        candidates.insert(ip);
                    }
                }
            }
        }
    }

    for ip in discover_arp_private_lan_neighbors(&self_ips) {
        candidates.insert(ip);
    }

    if include_full_subnet_sweep {
        let mut prefixes = Vec::new();
        for ip in &self_ips {
            let oct = ip.octets();
            let prefix = (oct[0], oct[1], oct[2]);
            if !prefixes.contains(&prefix) {
                prefixes.push(prefix);
            }
        }
        for (a, b, c) in prefixes {
            for host in 1u8..=254u8 {
                let cand = Ipv4Addr::new(a, b, c, host);
                if !self_ips.contains(&cand) {
                    candidates.insert(cand);
                }
            }
        }
    }

    probe_open_p2p_hosts(candidates.into_iter().collect(), p2p_port).await
}

/// Executes a real Ed25519-signed libp2p canary query against every currently connected peer,
/// measuring live RTT and detecting half-open or wedged Yamux streams.
pub async fn run_in_daemon_canary_probe(state: &Arc<DaemonState>) -> Vec<PeerCanaryProbeResult> {
    let watcher = state.p2p_watcher();
    watcher.probe_runs.fetch_add(1, Ordering::Relaxed);
    let now_str = Utc::now().to_rfc3339();
    if let Ok(mut guard) = watcher.last_probe_at.write() {
        *guard = Some(now_str);
    }

    let Some(ref handle) = state.swarm_handle else {
        return Vec::new();
    };

    let p2p_enabled = global_mesh_dlp_controller()
        .settings
        .read()
        .map(|g| g.mesh.p2p_enabled)
        .unwrap_or(true);
    if !p2p_enabled {
        return Vec::new();
    }

    let connected = handle.connected_peers().await.unwrap_or_default();
    let addr_map = handle.connected_peer_addresses();
    watcher.save_known_peers_snapshot(&addr_map);

    if connected.is_empty() {
        if let Ok(mut guard) = watcher.last_probe_results.write() {
            guard.clear();
        }
        return Vec::new();
    }

    let mut req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: watcher.local_peer_id.clone(),
        sender_pubkey: [0u8; 32],
        query_text: P2P_WATCHER_CANARY_QUERY.to_string(),
        embedding: vec![0.0; 768],
        top_k: 0,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&watcher.node_seed, &mut req, AccessTier::Tier0Public);

    let mut join_set = tokio::task::JoinSet::new();
    for peer in connected {
        let h = handle.clone();
        let r = req.clone();
        let ma_str = addr_map.get(&peer).map(|m| m.to_string());
        join_set.spawn(async move {
            let started = Instant::now();
            let outcome = tokio::time::timeout(Duration::from_secs(4), h.send_query(peer, r)).await;
            let rtt_ms = (started.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
            (peer, ma_str, outcome, rtt_ms)
        });
    }

    let registry = global_peer_health_registry();
    let mut results = Vec::new();
    while let Some(joined) = join_set.join_next().await {
        if let Ok((peer, ma_str, outcome, rtt_ms)) = joined {
            let peer_id_str = peer.to_string();
            match outcome {
                Ok(Ok(resp)) => {
                    registry.record_success(&peer_id_str, rtt_ms, resp.chunks.len());
                    results.push(PeerCanaryProbeResult {
                        peer_id: peer_id_str,
                        multiaddr: ma_str,
                        reachable: true,
                        rtt_ms,
                        consecutive_failures: 0,
                        error: None,
                        probed_at: Utc::now().to_rfc3339(),
                    });
                }
                Ok(Err(net_err)) => {
                    let msg = net_err.to_string();
                    registry.record_failure(&peer_id_str, &msg);
                    let consec = registry
                        .get(&peer_id_str)
                        .map(|s| s.consecutive_failures)
                        .unwrap_or(1);
                    results.push(PeerCanaryProbeResult {
                        peer_id: peer_id_str,
                        multiaddr: ma_str,
                        reachable: false,
                        rtt_ms,
                        consecutive_failures: consec,
                        error: Some(msg),
                        probed_at: Utc::now().to_rfc3339(),
                    });
                }
                Err(_) => {
                    let msg = "Canary libp2p probe timed out after 4000ms".to_string();
                    registry.record_failure(&peer_id_str, &msg);
                    let consec = registry
                        .get(&peer_id_str)
                        .map(|s| s.consecutive_failures)
                        .unwrap_or(1);
                    results.push(PeerCanaryProbeResult {
                        peer_id: peer_id_str,
                        multiaddr: ma_str,
                        reachable: false,
                        rtt_ms,
                        consecutive_failures: consec,
                        error: Some(msg),
                        probed_at: Utc::now().to_rfc3339(),
                    });
                }
            }
        }
    }

    results.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
    if let Ok(mut guard) = watcher.last_probe_results.write() {
        *guard = results.clone();
    }
    results
}

/// Evicts dead/zombie peer sessions, re-asserts firewall rules when isolated, and dials all
/// bootstrap, persisted-cache, ARP-neighbor, and caller-supplied LAN peers.
pub async fn run_in_daemon_mesh_heal(state: &Arc<DaemonState>, req: HealMeshRequest) -> usize {
    let Some(ref handle) = state.swarm_handle else {
        return 0;
    };

    let p2p_enabled = global_mesh_dlp_controller()
        .settings
        .read()
        .map(|g| g.mesh.p2p_enabled)
        .unwrap_or(true);
    if !p2p_enabled {
        return 0;
    }

    let watcher = state.p2p_watcher();
    watcher.heal_runs.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut guard) = watcher.last_heal_at.write() {
        *guard = Some(Utc::now().to_rfc3339());
    }
    if let Ok(mut guard) = watcher.last_heal_reason.write() {
        *guard = Some(
            req.reason
                .clone()
                .unwrap_or_else(|| "proactive_mesh_heal".to_string()),
        );
    }

    let registry = global_peer_health_registry();
    let zombie_ids = registry.unhealthy_peers(2);
    let addr_snapshot = handle.connected_peer_addresses();

    let mut zombie_redial_addrs = BTreeSet::new();
    for z_id in &zombie_ids {
        if let Ok(pid) = z_id.parse::<PeerId>() {
            if let Some(prev_addr) = addr_snapshot.get(&pid) {
                let clean = strip_p2p_suffix(&prev_addr.to_string());
                if is_dialable_lan_or_wan_multiaddr(&clean) {
                    zombie_redial_addrs.insert(clean);
                }
            }
            let _ = handle.disconnect_peer(pid).await;
            registry.clear_peer_failures(z_id);
            watcher.zombies_evicted.fetch_add(1, Ordering::Relaxed);
            warn!(
                peer = %z_id,
                "P2P Watcher evicted unresponsive peer stream and scheduled clean reconnect"
            );
        }
    }

    #[cfg(target_os = "windows")]
    if addr_snapshot.is_empty() {
        ensure_windows_p2p_firewall_rules(state.port, watcher.p2p_port);
    }

    let mut dial_targets = BTreeSet::new();
    for z_addr in zombie_redial_addrs {
        dial_targets.insert(z_addr);
    }

    if let Ok(guard) = global_mesh_dlp_controller().settings.read() {
        for bp in &guard.mesh.bootstrap_peers {
            let clean = strip_p2p_suffix(bp.trim());
            if clean.starts_with("/ip4/") || clean.starts_with("/dns4/") || clean.starts_with("/dns/") {
                dial_targets.insert(clean);
            }
        }
    }

    let known = watcher.load_known_peers();
    for ma in &known.multiaddrs {
        let clean = strip_p2p_suffix(ma.trim());
        if is_dialable_lan_or_wan_multiaddr(&clean) {
            dial_targets.insert(clean);
        }
    }

    let p2p_port = watcher.p2p_port;
    let self_ips = discover_local_private_ipv4_addresses();
    for ip_str in &req.discovered_ips {
        if let Ok(ip) = ip_str.trim().parse::<Ipv4Addr>() {
            if is_private_lan_ipv4(&ip) && !self_ips.contains(&ip) {
                dial_targets.insert(format!("/ip4/{}/tcp/{}", ip, p2p_port));
            }
        }
    }

    if req.discovered_ips.is_empty() || req.force_redial_all {
        let live_lan = discover_reachable_lan_p2p_ips(&state.data_dir, p2p_port, false).await;
        for ip in live_lan {
            dial_targets.insert(format!("/ip4/{}/tcp/{}", ip, p2p_port));
        }
    }

    let currently_connected_bases: BTreeSet<String> = handle
        .connected_peer_addresses()
        .values()
        .map(|m| strip_p2p_suffix(&m.to_string()))
        .collect();

    let mut dialed_count = 0usize;
    for target in dial_targets {
        if !req.force_redial_all && currently_connected_bases.contains(&target) {
            continue;
        }
        if let Ok(ma) = target.parse::<Multiaddr>() {
            if handle.dial(ma).await.is_ok() {
                dialed_count += 1;
                watcher.peers_redialed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    if dialed_count > 0 {
        tokio::time::sleep(Duration::from_millis(350)).await;
    }

    let refreshed_addrs = handle.connected_peer_addresses();
    watcher.save_known_peers_snapshot(&refreshed_addrs);
    dialed_count
}

/// Builds the live `P2pWatcherStatusDto` snapshot for HTTP endpoints and health telemetry.
pub async fn build_watcher_status_dto(state: &Arc<DaemonState>) -> P2pWatcherStatusDto {
    let watcher = state.p2p_watcher();
    let p2p_enabled = global_mesh_dlp_controller()
        .settings
        .read()
        .map(|g| g.mesh.p2p_enabled)
        .unwrap_or(true);

    let connected_peers = match &state.swarm_handle {
        Some(h) => {
            let map = h.connected_peer_addresses();
            watcher.save_known_peers_snapshot(&map);
            h.connected_peers().await.map(|v| v.len()).unwrap_or(0)
        }
        None => 0,
    };

    let peer_health = global_peer_health_registry().snapshot();
    let peer_probes = watcher
        .last_probe_results
        .read()
        .map(|g| g.clone())
        .unwrap_or_default();

    let healthy_peers = if !peer_probes.is_empty() {
        peer_probes.iter().filter(|p| p.reachable).count()
    } else {
        connected_peers
    };

    let pid_raw = watcher.watcher_pid.load(Ordering::Acquire);
    let known = watcher.load_known_peers();

    P2pWatcherStatusDto {
        active: watcher.enabled.load(Ordering::Acquire) && (pid_raw > 0 || state.swarm_handle.is_some()),
        watcher_pid: if pid_raw > 0 { Some(pid_raw) } else { None },
        daemon_pid: std::process::id(),
        watcher_restarts: watcher.watcher_restarts.load(Ordering::Relaxed),
        p2p_enabled,
        p2p_port: watcher.p2p_port,
        connected_peers,
        healthy_peers,
        known_cached_peers: known.multiaddrs,
        probe_runs: watcher.probe_runs.load(Ordering::Relaxed),
        heal_runs: watcher.heal_runs.load(Ordering::Relaxed),
        zombies_evicted: watcher.zombies_evicted.load(Ordering::Relaxed),
        peers_redialed: watcher.peers_redialed.load(Ordering::Relaxed),
        last_probe_at: watcher.last_probe_at.read().ok().and_then(|g| g.clone()),
        last_heal_at: watcher.last_heal_at.read().ok().and_then(|g| g.clone()),
        last_heal_reason: watcher.last_heal_reason.read().ok().and_then(|g| g.clone()),
        peer_probes,
        peer_health,
    }
}

/// `GET /api/mesh/watcher` — Returns P2P watcher process telemetry, known peer cache, and probe RTTs.
pub async fn get_p2p_watcher_status_handler(
    State(state): State<Arc<DaemonState>>,
) -> impl IntoResponse {
    Json(build_watcher_status_dto(&state).await)
}

/// `POST /api/mesh/watcher/probe` — Runs immediate Ed25519-signed canary probes across all connected peers.
pub async fn post_p2p_watcher_probe_handler(
    State(state): State<Arc<DaemonState>>,
) -> impl IntoResponse {
    let _ = run_in_daemon_canary_probe(&state).await;
    Json(build_watcher_status_dto(&state).await)
}

/// `POST /api/mesh/watcher/heal` — Evicts zombie peer streams and re-dials reachable LAN/bootstrap/cached peers.
pub async fn post_p2p_watcher_heal_handler(
    State(state): State<Arc<DaemonState>>,
    payload: Option<Json<HealMeshRequest>>,
) -> impl IntoResponse {
    let req = payload.map(|Json(r)| r).unwrap_or_default();
    let _ = run_in_daemon_mesh_heal(&state, req).await;
    let _ = run_in_daemon_canary_probe(&state).await;
    Json(build_watcher_status_dto(&state).await)
}

/// Re-asserts Windows Firewall inbound rules for the running QuorumRAG binary and LAN P2P ports.
#[cfg(target_os = "windows")]
pub fn ensure_windows_p2p_firewall_rules(http_port: u16, p2p_port: u16) {
    if let Ok(exe_path) = std::env::current_exe() {
        let exe_str = exe_path.to_string_lossy().to_string();
        let _ = std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=QuorumRAG P2P Mesh (All Profiles)",
                "dir=in",
                "action=allow",
                &format!("program={}", exe_str),
                "enable=yes",
                "profile=any",
            ])
            .output();
        let _ = std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=QuorumRAG LAN Ports (TCP 3031-3032)",
                "dir=in",
                "action=allow",
                "protocol=TCP",
                &format!("localport={},{}", http_port, p2p_port),
                "enable=yes",
                "profile=any",
            ])
            .output();
        let _ = std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=QuorumRAG LAN Ports (UDP 3032,5353)",
                "dir=in",
                "action=allow",
                "protocol=UDP",
                &format!("localport={},5353", p2p_port),
                "enable=yes",
                "profile=any",
            ])
            .output();
    }
}

/// Spawns `quorumrag watch-p2p` as an independent OS child process and supervises it continuously,
/// while performing immediate startup hydration of persisted + ARP LAN peers.
pub fn start_p2p_watcher_supervisor(
    state: Arc<DaemonState>,
    spawn_os_process: bool,
    is_service_mode: bool,
) {
    if state.swarm_handle.is_none() {
        return;
    }

    let hydrate_state = Arc::clone(&state);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let dialed = run_in_daemon_mesh_heal(
            &hydrate_state,
            HealMeshRequest {
                reason: Some("startup_fast_hydration".to_string()),
                discovered_ips: Vec::new(),
                force_redial_all: true,
            },
        )
        .await;
        if dialed > 0 {
            info!(
                dialed,
                "P2P Watcher fast startup hydration dialed persisted & ARP LAN peers"
            );
            tokio::time::sleep(Duration::from_millis(600)).await;
            let _ = run_in_daemon_canary_probe(&hydrate_state).await;
        }
    });

    if !spawn_os_process
        || std::env::var("QUORUMRAG_DISABLE_WATCHER_SPAWN")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    {
        return;
    }

    let sup_state = Arc::clone(&state);
    tokio::spawn(async move {
        let daemon_pid = std::process::id();
        let mut first_spawn = true;

        loop {
            let watcher = sup_state.p2p_watcher();
            if watcher.shutting_down.load(Ordering::Acquire) {
                break;
            }

            let needs_spawn = {
                if let Ok(mut guard) = watcher.child_process.lock() {
                    match guard.as_mut() {
                        Some(child) => match child.try_wait() {
                            Ok(Some(exit_status)) => {
                                warn!(
                                    status = %exit_status,
                                    "P2P Watcher child process exited unexpectedly; respawning..."
                                );
                                *guard = None;
                                watcher.watcher_pid.store(0, Ordering::Release);
                                true
                            }
                            Ok(None) => false,
                            Err(_) => {
                                *guard = None;
                                watcher.watcher_pid.store(0, Ordering::Release);
                                true
                            }
                        },
                        None => true,
                    }
                } else {
                    false
                }
            };

            if needs_spawn && !watcher.shutting_down.load(Ordering::Acquire) {
                if let Ok(exe) = std::env::current_exe() {
                    let daemon_url = format!("http://127.0.0.1:{}", sup_state.port);
                    let mut cmd = std::process::Command::new(exe);
                    cmd.arg("--data-dir")
                        .arg(&sup_state.data_dir)
                        .arg("--host")
                        .arg("127.0.0.1")
                        .arg("--port")
                        .arg(sup_state.port.to_string())
                        .arg("--p2p-port")
                        .arg(watcher.p2p_port.to_string())
                        .arg("--no-browser")
                        .arg("watch-p2p")
                        .arg("--daemon-url")
                        .arg(&daemon_url)
                        .arg("--interval-secs")
                        .arg("10")
                        .arg("--parent-pid")
                        .arg(daemon_pid.to_string());
                    if is_service_mode {
                        cmd.arg("--heal-service");
                    }
                    cmd.stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null());

                    #[cfg(target_os = "windows")]
                    {
                        use std::os::windows::process::CommandExt;
                        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
                        cmd.creation_flags(CREATE_NO_WINDOW);
                    }

                    match cmd.spawn() {
                        Ok(child) => {
                            let cpid = child.id();
                            watcher.watcher_pid.store(cpid, Ordering::Release);
                            if !first_spawn {
                                watcher.watcher_restarts.fetch_add(1, Ordering::Relaxed);
                            }
                            first_spawn = false;
                            info!(
                                watcher_pid = cpid,
                                daemon_url = %daemon_url,
                                p2p_port = watcher.p2p_port,
                                "Spawned dedicated QuorumRAG P2P Watcher OS process (watch-p2p)"
                            );
                            if let Ok(mut guard) = watcher.child_process.lock() {
                                *guard = Some(child);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to spawn P2P Watcher OS process: {}", e);
                        }
                    }
                }
            }

            tokio::select! {
                _ = sup_state.shutdown_notify.notified() => {
                    sup_state.p2p_watcher().stop_child_process();
                    break;
                }
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            }
        }
    });
}

/// Checks whether a given OS PID is currently alive using `sysinfo`.
fn is_os_pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let mut sys = sysinfo::System::new();
    let spid = sysinfo::Pid::from_u32(pid);
    sys.refresh_process(spid)
}

/// Appends a timestamped structured line to `<data_dir>/logs/p2p-watcher.log`.
fn append_watcher_log(data_dir: &Path, message: &str) {
    let log_dir = data_dir.join("logs");
    let _ = std::fs::create_dir_all(&log_dir);
    let log_file = log_dir.join("p2p-watcher.log");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)
    {
        let _ = writeln!(f, "[{}] {}", Utc::now().to_rfc3339(), message);
    }
}

/// Attempts platform-native service restart when `--heal-service` is enabled and the daemon stopped responding.
fn attempt_platform_service_restart(data_dir: &Path) {
    append_watcher_log(
        data_dir,
        "WARN: Daemon health & P2P listener unreachable for 2 consecutive checks; triggering OS service restart",
    );
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("sc.exe")
            .args(["start", "QuorumRAGDaemon"])
            .output();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["start", "quorumrag"])
            .output();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("launchctl")
            .args(["kickstart", "-k", "system/dev.quorumrag.daemon"])
            .output();
    }
}

/// Standalone out-of-process P2P Watcher entrypoint (`quorumrag watch-p2p`).
pub async fn run_standalone_p2p_watcher(
    cli: Cli,
    daemon_url: Option<String>,
    interval_secs: u64,
    heal_service: bool,
    parent_pid: Option<u32>,
    once: bool,
) -> anyhow::Result<()> {
    let _ = std::fs::create_dir_all(&cli.data_dir);
    let lock_path = cli.data_dir.join("p2p_watcher.lock");
    let my_pid = std::process::id();

    if !once && lock_path.is_file() {
        if let Ok(existing_raw) = std::fs::read_to_string(&lock_path) {
            if let Ok(existing_pid) = existing_raw.trim().parse::<u32>() {
                if existing_pid != my_pid && is_os_pid_alive(existing_pid) {
                    info!(
                        existing_pid,
                        "Another P2P Watcher OS process is already active for {:?}; exiting duplicate.",
                        cli.data_dir
                    );
                    return Ok(());
                }
            }
        }
    }
    let _ = std::fs::write(&lock_path, my_pid.to_string());

    let base_url = daemon_url
        .unwrap_or_else(|| format!("http://127.0.0.1:{}", cli.port))
        .trim_end_matches('/')
        .to_string();
    let tick_secs = interval_secs.clamp(3, 300);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(6))
        .build()?;

    append_watcher_log(
        &cli.data_dir,
        &format!(
            "INFO: P2P Watcher started (pid={}, daemon_url={}, p2p_port={}, interval={}s, heal_service={})",
            my_pid, base_url, cli.p2p_port, tick_secs, heal_service
        ),
    );

    let mut consecutive_daemon_failures = 0u32;
    let mut cycle_idx = 0u64;

    loop {
        cycle_idx = cycle_idx.wrapping_add(1);

        if !heal_service {
            if let Some(ppid) = parent_pid {
                if !is_os_pid_alive(ppid) {
                    append_watcher_log(
                        &cli.data_dir,
                        &format!("INFO: Parent daemon pid {} exited; stopping P2P Watcher.", ppid),
                    );
                    break;
                }
            }
        }

        let health_url = format!("{}/api/health", base_url);
        let p2p_loopback = SocketAddr::from(([127, 0, 0, 1], cli.p2p_port));
        let tcp_listener_ok = tokio::time::timeout(
            Duration::from_millis(400),
            tokio::net::TcpStream::connect(p2p_loopback),
        )
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);

        let health_resp = client.get(&health_url).send().await;
        match health_resp {
            Ok(resp) if resp.status().is_success() => {
                consecutive_daemon_failures = 0;

                let do_full_sweep = cycle_idx == 1 || cycle_idx % 6 == 0;
                let reachable_ips =
                    discover_reachable_lan_p2p_ips(&cli.data_dir, cli.p2p_port, do_full_sweep)
                        .await;
                let ip_strings: Vec<String> =
                    reachable_ips.iter().map(|ip| ip.to_string()).collect();

                let probe_url = format!("{}/api/mesh/watcher/probe", base_url);
                if let Ok(probe_http) = client.post(&probe_url).send().await {
                    if let Ok(mut status_dto) = probe_http.json::<P2pWatcherStatusDto>().await {
                        status_dto.watcher_pid = Some(my_pid);
                        let has_failed_peer = status_dto
                            .peer_probes
                            .iter()
                            .any(|p| !p.reachable || p.consecutive_failures >= 2);
                        let missing_reachable_peers = status_dto.p2p_enabled
                            && !reachable_ips.is_empty()
                            && status_dto.connected_peers < reachable_ips.len();
                        let isolated_mesh =
                            status_dto.p2p_enabled && status_dto.connected_peers == 0;

                        if has_failed_peer || missing_reachable_peers || isolated_mesh || !tcp_listener_ok {
                            let reason = if has_failed_peer {
                                "unresponsive_peer_canary_probe"
                            } else if missing_reachable_peers {
                                "reachable_lan_peer_not_connected"
                            } else if !tcp_listener_ok {
                                "local_p2p_port_unreachable"
                            } else {
                                "zero_connected_peers_redial"
                            };

                            let heal_url = format!("{}/api/mesh/watcher/heal", base_url);
                            let heal_req = HealMeshRequest {
                                reason: Some(reason.to_string()),
                                discovered_ips: ip_strings.clone(),
                                force_redial_all: has_failed_peer,
                            };
                            if let Ok(heal_http) = client.post(&heal_url).json(&heal_req).send().await {
                                if let Ok(mut healed_dto) =
                                    heal_http.json::<P2pWatcherStatusDto>().await
                                {
                                    healed_dto.watcher_pid = Some(my_pid);
                                    append_watcher_log(
                                        &cli.data_dir,
                                        &format!(
                                            "HEAL: reason={} connected={} healthy={} lan_open={:?}",
                                            reason,
                                            healed_dto.connected_peers,
                                            healed_dto.healthy_peers,
                                            ip_strings
                                        ),
                                    );
                                    status_dto = healed_dto;
                                }
                            }
                        }

                        if let Ok(pretty) = serde_json::to_string_pretty(&status_dto) {
                            let _ = std::fs::write(
                                cli.data_dir.join("p2p_watcher_status.json"),
                                pretty,
                            );
                        }
                    }
                }
            }
            _ => {
                consecutive_daemon_failures = consecutive_daemon_failures.saturating_add(1);
                append_watcher_log(
                    &cli.data_dir,
                    &format!(
                        "WARN: Daemon health probe failed (streak={}, tcp_p2p_ok={})",
                        consecutive_daemon_failures, tcp_listener_ok
                    ),
                );
                if heal_service && consecutive_daemon_failures >= 2 {
                    attempt_platform_service_restart(&cli.data_dir);
                    consecutive_daemon_failures = 0;
                }
            }
        }

        if once {
            break;
        }

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                append_watcher_log(&cli.data_dir, "INFO: P2P Watcher received Ctrl+C; exiting cleanly.");
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(tick_secs)) => {}
        }
    }

    let _ = std::fs::remove_file(&lock_path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_p2p_suffix_and_socket_formatting() {
        let ma = "/ip4/10.0.0.165/tcp/3032/p2p/12D3KooWKHc3HiYDTmS9jymRJxHjuBEQ6Z3veB21KmzuH52iRFYu";
        assert_eq!(strip_p2p_suffix(ma), "/ip4/10.0.0.165/tcp/3032");
        assert_eq!(
            format_socket_from_multiaddr(ma),
            Some("10.0.0.165:3032".to_string())
        );
        assert!(is_dialable_lan_or_wan_multiaddr("/ip4/10.0.0.165/tcp/3032"));
        assert!(!is_dialable_lan_or_wan_multiaddr("/ip4/127.0.0.1/tcp/3032"));
        assert!(!is_dialable_lan_or_wan_multiaddr("/ip4/10.0.0.255/tcp/3032"));
    }
}
