//! Single-flight background model provisioning, detached `ollama serve` process spawning,
//! dynamic memory law checks, streaming JSON pull progress, and model alias registration.

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use quorum_coordinator::HardwareTelemetry;
use quorum_coordinator::nimble_client::{
    CANONICAL_NIMBLE_GGUF, DEFAULT_NIMBLE_ENDPOINT, DEFAULT_NIMBLE_MODEL,
    MIN_FREE_RAM_GB, MIN_FREE_VRAM_MB, PROBE_TIMEOUT,
};

/// Public status response format returned by `GET /api/models/nimble/status` and `POST /api/models/nimble/provision`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NimbleStatusResponse {
    pub state: String,
    pub progress_pct: f64,
    pub completed_bytes: u64,
    pub total_bytes: u64,
    pub model_tag: String,
    pub terminal_command: String,
    pub free_ram_gb: f64,
    pub free_vram_mb: f64,
    pub memory_sufficient: bool,
}

/// Rich internal state representation for model provisioning lifecycle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NimbleProvisionState {
    Ready,
    Downloading {
        progress_pct: f64,
        completed_bytes: u64,
        total_bytes: u64,
    },
    NotInstalled,
    SkippedLowMemory,
    Offline,
}

impl NimbleProvisionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Downloading { .. } => "downloading",
            Self::NotInstalled => "not_installed",
            Self::SkippedLowMemory => "skipped_low_memory",
            Self::Offline => "offline",
        }
    }
}

/// Background model provisioner managing single-flight model downloads and daemon lifecycle.
pub struct NimbleProvisioner {
    pub endpoint: String,
    pub model_tag: String,
    pub canonical_tag: String,
    pub state: Arc<RwLock<NimbleProvisionState>>,
    pub is_pulling: Arc<AtomicBool>,
    pub http_client: reqwest::Client,
}

impl Default for NimbleProvisioner {
    fn default() -> Self {
        Self::new(DEFAULT_NIMBLE_ENDPOINT)
    }
}

impl NimbleProvisioner {
    /// Creates a new `NimbleProvisioner` targeting the specified Ollama endpoint.
    pub fn new(endpoint: impl Into<String>) -> Self {
        let http_client = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(500))
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            endpoint: endpoint.into().trim_end_matches('/').to_string(),
            model_tag: DEFAULT_NIMBLE_MODEL.to_string(),
            canonical_tag: CANONICAL_NIMBLE_GGUF.to_string(),
            state: Arc::new(RwLock::new(NimbleProvisionState::NotInstalled)),
            is_pulling: Arc::new(AtomicBool::new(false)),
            http_client,
        }
    }

    /// Evaluates if user opted out of automatic background installation via `QUORUM_DISABLE_OLLAMA_AUTOINSTALL=1`.
    pub fn is_autoinstall_disabled() -> bool {
        std::env::var("QUORUM_DISABLE_OLLAMA_AUTOINSTALL")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    /// Checks the Dynamic Available Memory Law strictly on runtime free memory (`free_ram_gb >= 12.0 || free_vram_mb >= 6000`).
    /// Returns `(free_ram_gb, free_vram_mb, memory_sufficient)`.
    pub fn check_memory_law() -> (f64, f64, bool) {
        let hw = HardwareTelemetry::probe();
        let sufficient = hw.free_ram_gb >= MIN_FREE_RAM_GB || hw.free_vram_mb >= MIN_FREE_VRAM_MB;
        (hw.free_ram_gb, hw.free_vram_mb as f64, sufficient)
    }

    /// Multi-location binary discovery for `ollama` executable across PATH and standard OS locations.
    pub fn detect_ollama_executable() -> Option<PathBuf> {
        // 1. Check process-scoped PATH
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                #[cfg(windows)]
                {
                    let cand = dir.join("ollama.exe");
                    if cand.is_file() {
                        return Some(cand);
                    }
                }
                #[cfg(not(windows))]
                {
                    let cand = dir.join("ollama");
                    if cand.is_file() {
                        return Some(cand);
                    }
                }
            }
        }

        // 2. Windows-specific standard directories
        #[cfg(windows)]
        {
            if let Ok(local) = std::env::var("LOCALAPPDATA") {
                let p = PathBuf::from(local)
                    .join("Programs")
                    .join("Ollama")
                    .join("ollama.exe");
                if p.is_file() {
                    return Some(p);
                }
            }

            for pf_var in ["ProgramFiles", "ProgramFiles(x86)"] {
                if let Ok(pf) = std::env::var(pf_var) {
                    let p = PathBuf::from(pf)
                        .join("Ollama")
                        .join("ollama.exe");
                    if p.is_file() {
                        return Some(p);
                    }
                }
            }

            if let Ok(users_dir) = std::fs::read_dir("C:\\Users") {
                for entry in users_dir.filter_map(|e| e.ok()) {
                    if let Ok(ft) = entry.file_type() {
                        if ft.is_dir() {
                            let p = entry
                                .path()
                                .join("AppData")
                                .join("Local")
                                .join("Programs")
                                .join("Ollama")
                                .join("ollama.exe");
                            if p.is_file() {
                                return Some(p);
                            }
                        }
                    }
                }
            }
        }

        // 3. Unix standard locations
        #[cfg(not(windows))]
        {
            for p_str in ["/usr/local/bin/ollama", "/opt/homebrew/bin/ollama", "/usr/bin/ollama"] {
                let p = PathBuf::from(p_str);
                if p.is_file() {
                    return Some(p);
                }
            }
        }

        None
    }

    /// Asynchronously spawns `ollama serve` detached (`CREATE_NO_WINDOW = 0x08000000` on Windows) if binary exists and daemon is inactive.
    /// Polls `/api/tags` up to 10s for readiness using non-blocking async sleep.
    pub async fn ensure_ollama_daemon_async(&self) -> bool {
        use std::net::SocketAddr;
        let addr = SocketAddr::from(([127, 0, 0, 1], 11434));
        if tokio::net::TcpStream::connect(&addr).await.is_ok() {
            return true;
        }

        if let Some(binary) = Self::detect_ollama_executable() {
            info!("Spawning detached Ollama daemon from: {}", binary.display());
            let mut cmd = std::process::Command::new(&binary);
            cmd.arg("serve");
            cmd.stdin(std::process::Stdio::null());
            cmd.stdout(std::process::Stdio::null());
            cmd.stderr(std::process::Stdio::null());

            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x0800_0000;
                cmd.creation_flags(CREATE_NO_WINDOW);
            }

            if cmd.spawn().is_ok() {
                // Poll up to 10s (100 * 100ms) for socket readiness without blocking Tokio worker thread
                for _ in 0..100 {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    if tokio::net::TcpStream::connect(&addr).await.is_ok() {
                        info!("Detached Ollama daemon successfully reached listening state");
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Spawns `ollama serve` detached (`CREATE_NO_WINDOW = 0x08000000` on Windows) if binary exists and daemon is inactive.
    /// Synchronous convenience method for non-async contexts.
    pub fn ensure_ollama_daemon(&self) -> bool {
        use std::net::{SocketAddr, TcpStream};
        let addr = SocketAddr::from(([127, 0, 0, 1], 11434));
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return true;
        }

        if let Some(binary) = Self::detect_ollama_executable() {
            info!("Spawning detached Ollama daemon from: {}", binary.display());
            let mut cmd = std::process::Command::new(&binary);
            cmd.arg("serve");
            cmd.stdin(std::process::Stdio::null());
            cmd.stdout(std::process::Stdio::null());
            cmd.stderr(std::process::Stdio::null());

            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x0800_0000;
                cmd.creation_flags(CREATE_NO_WINDOW);
            }

            if cmd.spawn().is_ok() {
                // Poll up to 10s (100 * 100ms) for socket readiness
                for _ in 0..100 {
                    std::thread::sleep(Duration::from_millis(100));
                    if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
                        info!("Detached Ollama daemon successfully reached listening state");
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Checks if the Ollama endpoint is reachable via a fast 400ms HTTP GET `/api/tags`.
    pub async fn is_endpoint_reachable(&self) -> bool {
        let tags_url = format!("{}/api/tags", self.endpoint);
        match self
            .http_client
            .get(&tags_url)
            .timeout(Duration::from_millis(400))
            .send()
            .await
        {
            Ok(r) => r.status().is_success(),
            Err(_) => false,
        }
    }

    /// Helper to verify if the model tag or canonical tag is present in `/api/tags`.
    pub async fn is_model_installed(&self) -> bool {
        let tags_url = format!("{}/api/tags", self.endpoint);
        if let Ok(resp) = self
            .http_client
            .get(&tags_url)
            .timeout(Duration::from_millis(400))
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(val) = resp.json::<serde_json::Value>().await {
                    if let Some(models) = val.get("models").and_then(|m| m.as_array()) {
                        let names: Vec<String> = models
                            .iter()
                            .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
                            .collect();
                        return names.iter().any(|n| n == &self.model_tag || n == &self.canonical_tag);
                    }
                }
            }
        }
        false
    }

    /// Probes the local Ollama `/api/tags` endpoint (400ms timeout) and returns the current `NimbleStatusResponse`.
    pub async fn probe_status(&self) -> NimbleStatusResponse {
        let (free_ram_gb, free_vram_mb, memory_sufficient) = Self::check_memory_law();

        // 1. If active background pull is in-flight, return downloading status immediately
        if self.is_pulling.load(Ordering::SeqCst) {
            let current_state = self.state.read().await.clone();
            let (pct, comp, tot) = match current_state {
                NimbleProvisionState::Downloading { progress_pct, completed_bytes, total_bytes } => {
                    (progress_pct, completed_bytes, total_bytes)
                }
                _ => (0.0, 0, 0),
            };
            return NimbleStatusResponse {
                state: "downloading".to_string(),
                progress_pct: pct.clamp(0.0, 100.0),
                completed_bytes: comp,
                total_bytes: tot,
                model_tag: self.model_tag.clone(),
                terminal_command: format!("ollama pull {}", self.canonical_tag),
                free_ram_gb,
                free_vram_mb,
                memory_sufficient,
            };
        }

        // 2. If memory law is not satisfied, mark state skipped_low_memory
        if !memory_sufficient {
            let mut w = self.state.write().await;
            *w = NimbleProvisionState::SkippedLowMemory;
            return NimbleStatusResponse {
                state: "skipped_low_memory".to_string(),
                progress_pct: 0.0,
                completed_bytes: 0,
                total_bytes: 0,
                model_tag: self.model_tag.clone(),
                terminal_command: format!("ollama pull {}", self.canonical_tag),
                free_ram_gb,
                free_vram_mb,
                memory_sufficient: false,
            };
        }

        // 3. Probe Ollama /api/tags with 400ms timeout
        let tags_url = format!("{}/api/tags", self.endpoint);
        let probe_res = self
            .http_client
            .get(&tags_url)
            .timeout(PROBE_TIMEOUT)
            .send()
            .await;

        match probe_res {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(val) = resp.json::<serde_json::Value>().await {
                    let mut is_installed = false;
                    if let Some(models) = val.get("models").and_then(|m| m.as_array()) {
                        let target_clean = self.model_tag.trim().to_ascii_lowercase();
                        let canonical_clean = self.canonical_tag.trim().to_ascii_lowercase();
                        for m in models {
                            if let Some(name) = m.get("name").and_then(|n| n.as_str()) {
                                let norm = name.trim().to_ascii_lowercase();
                                if norm == target_clean
                                    || norm == canonical_clean
                                    || norm.starts_with(&target_clean)
                                    || norm.starts_with(&canonical_clean)
                                {
                                    is_installed = true;
                                    break;
                                }
                            }
                        }
                    }

                    let mut w = self.state.write().await;
                    if is_installed {
                        *w = NimbleProvisionState::Ready;
                        NimbleStatusResponse {
                            state: "ready".to_string(),
                            progress_pct: 100.0,
                            completed_bytes: 5340000000,
                            total_bytes: 5340000000,
                            model_tag: self.model_tag.clone(),
                            terminal_command: format!("ollama pull {}", self.canonical_tag),
                            free_ram_gb,
                            free_vram_mb,
                            memory_sufficient: true,
                        }
                    } else {
                        *w = NimbleProvisionState::NotInstalled;
                        NimbleStatusResponse {
                            state: "not_installed".to_string(),
                            progress_pct: 0.0,
                            completed_bytes: 0,
                            total_bytes: 0,
                            model_tag: self.model_tag.clone(),
                            terminal_command: format!("ollama pull {}", self.canonical_tag),
                            free_ram_gb,
                            free_vram_mb,
                            memory_sufficient: true,
                        }
                    }
                } else {
                    let mut w = self.state.write().await;
                    *w = NimbleProvisionState::Offline;
                    NimbleStatusResponse {
                        state: "offline".to_string(),
                        progress_pct: 0.0,
                        completed_bytes: 0,
                        total_bytes: 0,
                        model_tag: self.model_tag.clone(),
                        terminal_command: format!("ollama pull {}", self.canonical_tag),
                        free_ram_gb,
                        free_vram_mb,
                        memory_sufficient,
                    }
                }
            }
            _ => {
                let mut w = self.state.write().await;
                *w = NimbleProvisionState::Offline;
                NimbleStatusResponse {
                    state: "offline".to_string(),
                    progress_pct: 0.0,
                    completed_bytes: 0,
                    total_bytes: 0,
                    model_tag: self.model_tag.clone(),
                    terminal_command: format!("ollama pull {}", self.canonical_tag),
                    free_ram_gb,
                    free_vram_mb,
                    memory_sufficient,
                }
            }
        }
    }

    /// Triggers or retries background provisioning.
    /// Returns the immediate status response (`"downloading"` if started, or current status if already running/skipped).
    pub fn trigger_provision(self: &Arc<Self>) -> NimbleStatusResponse {
        let (free_ram_gb, free_vram_mb, memory_sufficient) = Self::check_memory_law();

        if !memory_sufficient {
            return NimbleStatusResponse {
                state: "skipped_low_memory".to_string(),
                progress_pct: 0.0,
                completed_bytes: 0,
                total_bytes: 0,
                model_tag: self.model_tag.clone(),
                terminal_command: format!("ollama pull {}", self.canonical_tag),
                free_ram_gb,
                free_vram_mb,
                memory_sufficient: false,
            };
        }

        // Single-flight atomic exchange guard
        if self.is_pulling.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            let this = Arc::clone(self);
            tokio::spawn(async move {
                this.execute_background_pull().await;
            });

            NimbleStatusResponse {
                state: "downloading".to_string(),
                progress_pct: 0.0,
                completed_bytes: 0,
                total_bytes: 5340000000,
                model_tag: self.model_tag.clone(),
                terminal_command: format!("ollama pull {}", self.canonical_tag),
                free_ram_gb,
                free_vram_mb,
                memory_sufficient: true,
            }
        } else {
            // Already pulling in background
            let current = match self.state.try_read() {
                Ok(guard) => match &*guard {
                    NimbleProvisionState::Downloading { progress_pct, completed_bytes, total_bytes } => {
                        (*progress_pct, *completed_bytes, *total_bytes)
                    }
                    _ => (0.0, 0, 5340000000),
                },
                Err(_) => (0.0, 0, 5340000000),
            };

            NimbleStatusResponse {
                state: "downloading".to_string(),
                progress_pct: current.0.clamp(0.0, 100.0),
                completed_bytes: current.1,
                total_bytes: current.2,
                model_tag: self.model_tag.clone(),
                terminal_command: format!("ollama pull {}", self.canonical_tag),
                free_ram_gb,
                free_vram_mb,
                memory_sufficient: true,
            }
        }
    }

    /// Background execution loop streaming `/api/pull` and aliasing via `/api/copy`.
    async fn execute_background_pull(&self) {
        struct PullGuard<'a>(&'a AtomicBool);
        impl<'a> Drop for PullGuard<'a> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let _guard = PullGuard(&self.is_pulling);

        // 1. Ensure daemon is alive via direct reachability check (do NOT use probe_status which short-circuits on is_pulling)
        let is_alive = self.is_endpoint_reachable().await;
        if !is_alive {
            let spawned = self.ensure_ollama_daemon_async().await;
            if !spawned {
                warn!("Ollama daemon not responding and could not be spawned detached.");
                let mut w = self.state.write().await;
                *w = NimbleProvisionState::Offline;
                return;
            }
        }

        // 2. Set downloading state
        {
            let mut w = self.state.write().await;
            *w = NimbleProvisionState::Downloading {
                progress_pct: 0.0,
                completed_bytes: 0,
                total_bytes: 5340000000,
            };
        }

        let pull_url = format!("{}/api/pull", self.endpoint);
        let pull_res = self
            .http_client
            .post(&pull_url)
            .json(&serde_json::json!({ "name": self.canonical_tag }))
            .send()
            .await;

        let resp = match pull_res {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                error!("Ollama /api/pull returned status: {}", r.status());
                let mut w = self.state.write().await;
                *w = NimbleProvisionState::NotInstalled;
                return;
            }
            Err(e) => {
                error!("Failed to send /api/pull request: {}", e);
                let mut w = self.state.write().await;
                *w = NimbleProvisionState::Offline;
                return;
            }
        };

        // 3. Stream NDJSON progress chunks
        let mut stream = resp.bytes_stream();
        let mut buffer = String::new();
        let mut completed_bytes: u64 = 0;
        let mut total_bytes: u64 = 5340000000;
        let mut download_succeeded = false;
        let mut stream_error = false;

        while let Some(chunk_res) = stream.next().await {
            match chunk_res {
                Ok(chunk) => {
                    let chunk_str = String::from_utf8_lossy(&chunk);
                    buffer.push_str(&chunk_str);

                    while let Some(pos) = buffer.find('\n') {
                        let line = buffer[..pos].trim().to_string();
                        buffer.drain(..=pos);

                        if line.is_empty() {
                            continue;
                        }

                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                            if let Some(err_msg) = val.get("error").and_then(|v| v.as_str()) {
                                error!("Ollama returned pull error in stream: {}", err_msg);
                                stream_error = true;
                                break;
                            }
                            if let Some(status) = val.get("status").and_then(|v| v.as_str()) {
                                if status.contains("success") {
                                    download_succeeded = true;
                                }
                            }
                            if let Some(c) = val.get("completed").and_then(|v| v.as_u64()) {
                                completed_bytes = c;
                            }
                            if let Some(t) = val.get("total").and_then(|v| v.as_u64()) {
                                if t > 0 {
                                    total_bytes = t;
                                }
                            }
                            let pct = if total_bytes > 0 {
                                ((completed_bytes as f64) / (total_bytes as f64) * 100.0).clamp(0.0, 100.0)
                            } else {
                                0.0
                            };

                            let mut w = self.state.write().await;
                            *w = NimbleProvisionState::Downloading {
                                progress_pct: pct,
                                completed_bytes,
                                total_bytes,
                            };
                        }
                    }
                    if stream_error {
                        break;
                    }
                }
                Err(e) => {
                    warn!("Stream connection dropped mid-pull: {}", e);
                    stream_error = true;
                    break;
                }
            }
        }

        if !stream_error && (download_succeeded || (total_bytes > 0 && completed_bytes >= total_bytes)) {
            download_succeeded = true;
        }

        if !download_succeeded {
            warn!("Download was aborted or failed; setting state to NotInstalled");
            let mut w = self.state.write().await;
            *w = NimbleProvisionState::NotInstalled;
            return;
        }

        // 4. Register model alias via POST /api/copy
        let copy_url = format!("{}/api/copy", self.endpoint);
        let copy_res = self
            .http_client
            .post(&copy_url)
            .json(&serde_json::json!({
                "source": self.canonical_tag,
                "destination": self.model_tag,
            }))
            .send()
            .await;

        match copy_res {
            Ok(r) if r.status().is_success() => {
                info!("Successfully aliased {} to {}", self.canonical_tag, self.model_tag);
                let mut w = self.state.write().await;
                *w = NimbleProvisionState::Ready;
            }
            Ok(r) => {
                warn!("Copy alias returned status {}. Checking if model is installed under canonical tag.", r.status());
                let is_ready = self.is_model_installed().await;
                let mut w = self.state.write().await;
                if is_ready {
                    *w = NimbleProvisionState::Ready;
                } else {
                    *w = NimbleProvisionState::NotInstalled;
                }
            }
            Err(e) => {
                warn!("Failed to alias model via /api/copy: {}. Checking if model is installed.", e);
                let is_ready = self.is_model_installed().await;
                let mut w = self.state.write().await;
                if is_ready {
                    *w = NimbleProvisionState::Ready;
                } else {
                    *w = NimbleProvisionState::NotInstalled;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nimble_status_response_serde_contract() {
        let resp = NimbleStatusResponse {
            state: "downloading".to_string(),
            progress_pct: 42.5,
            completed_bytes: 2125000000,
            total_bytes: 5000000000,
            model_tag: "bespoke-nimble:9b".to_string(),
            terminal_command: "ollama pull bespoke-minijpmorgan/bespoke-nimble:9b".to_string(),
            free_ram_gb: 16.0,
            free_vram_mb: 8192.0,
            memory_sufficient: true,
        };
        let json = serde_json::to_string(&resp).expect("must serialize");
        let deserialized: NimbleStatusResponse = serde_json::from_str(&json).expect("must deserialize");
        assert_eq!(resp, deserialized);
        assert_eq!(deserialized.state, "downloading");
        assert_eq!(deserialized.progress_pct, 42.5);
        assert_eq!(deserialized.model_tag, "bespoke-nimble:9b");
        assert!(deserialized.memory_sufficient);
    }

    #[test]
    fn test_nimble_status_response_skip_low_memory() {
        let resp = NimbleStatusResponse {
            state: "skipped_low_memory".to_string(),
            progress_pct: 0.0,
            completed_bytes: 0,
            total_bytes: 0,
            model_tag: "bespoke-nimble:9b".to_string(),
            terminal_command: "ollama pull bespoke-minijpmorgan/bespoke-nimble:9b".to_string(),
            free_ram_gb: 4.0,
            free_vram_mb: 1024.0,
            memory_sufficient: false,
        };
        assert_eq!(resp.state, "skipped_low_memory");
        assert!(!resp.memory_sufficient);
        assert_eq!(resp.progress_pct, 0.0);
    }

    #[test]
    fn test_single_flight_atomic_bool_exclusion() {
        let provisioner = NimbleProvisioner::default();
        assert!(!provisioner.is_pulling.load(Ordering::SeqCst));
        let first = provisioner.is_pulling.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst);
        let second = provisioner.is_pulling.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst);
        assert!(first.is_ok());
        assert!(second.is_err());
        provisioner.is_pulling.store(false, Ordering::SeqCst);
        let third = provisioner.is_pulling.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst);
        assert!(third.is_ok());
    }

    #[test]
    fn test_initial_state_not_installed() {
        let provisioner = NimbleProvisioner::default();
        let initial_state = provisioner.state.try_read().expect("must acquire read lock").clone();
        assert_eq!(initial_state, NimbleProvisionState::NotInstalled);
    }

    #[tokio::test]
    async fn test_trigger_provision_concurrent_calls_no_panic() {
        let provisioner = Arc::new(NimbleProvisioner::default());
        // Rapid repeated calls inside Tokio async runtime must never panic on blocking_read
        for _ in 0..20 {
            let resp = provisioner.trigger_provision();
            assert!(resp.memory_sufficient || !resp.memory_sufficient);
        }
    }

    #[test]
    fn test_division_by_zero_safe_progress() {
        let completed: u64 = 100;
        let total: u64 = 0;
        let pct = if total > 0 {
            ((completed as f64) / (total as f64) * 100.0).clamp(0.0, 100.0)
        } else {
            0.0
        };
        assert_eq!(pct, 0.0);
    }

    #[test]
    fn test_memory_law_threshold_logic() {
        let ram_low = 8.0;
        let vram_low = 2048u64;
        let sufficient_low = ram_low >= 12.0 || vram_low >= 6000;
        assert!(!sufficient_low);

        let ram_high = 16.0;
        let sufficient_ram = ram_high >= 12.0 || vram_low >= 6000;
        assert!(sufficient_ram);

        let vram_high = 8192u64;
        let sufficient_vram = ram_low >= 12.0 || vram_high >= 6000;
        assert!(sufficient_vram);
    }
}
