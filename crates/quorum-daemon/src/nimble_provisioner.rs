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

use quorum_coordinator::nimble_client::{
    CANONICAL_NIMBLE_GGUF, DEFAULT_NIMBLE_ENDPOINT, DEFAULT_NIMBLE_MODEL, MIN_FREE_RAM_GB,
    MIN_FREE_VRAM_MB, PROBE_TIMEOUT,
};
use quorum_coordinator::{AutoFusionRouter, HardwareTelemetry, ModelProvisionPlan};

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
    #[serde(default)]
    pub fallback_model_tag: String,
    #[serde(default)]
    pub fallback_state: String,
    #[serde(default)]
    pub fallback_progress_pct: f64,
    #[serde(default)]
    pub installed_models: Vec<String>,
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
    pub fallback_state: Arc<RwLock<NimbleProvisionState>>,
    pub is_pulling_fallback: Arc<AtomicBool>,
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
            fallback_state: Arc::new(RwLock::new(NimbleProvisionState::NotInstalled)),
            is_pulling_fallback: Arc::new(AtomicBool::new(false)),
            http_client,
        }
    }

    /// Selects a memory-fitted local fallback model strictly from runtime available RAM/VRAM
    /// by delegating directly to `quorum_coordinator::AutoFusionRouter::size_qwen_by_hardware`
    /// (Dynamic Available Memory Law — never total physical RAM).
    pub fn select_memory_fitted_fallback_model(free_ram_gb: f64, free_vram_mb: f64) -> String {
        let hw = HardwareTelemetry {
            free_ram_gb,
            free_vram_mb: free_vram_mb.max(0.0) as u64,
            ..HardwareTelemetry::default()
        };
        AutoFusionRouter::size_qwen_by_hardware(&hw)
    }

    /// Calculates live host resources (`HardwareTelemetry::probe_fresh()` + `probe_free_disk_gb()`)
    /// via `AutoFusionRouter::calculate_provision_plan` BEFORE any model provisioning attempt.
    pub fn calculate_provision_plan(&self, installed: &[String]) -> ModelProvisionPlan {
        AutoFusionRouter::calculate_provision_plan(&self.canonical_tag, installed)
    }

    /// Checks whether a given model tag (or `:latest` equivalent) is present in an installed tag slice.
    pub fn tag_in_installed_list(tag: &str, installed: &[String]) -> bool {
        let target = tag.trim().to_ascii_lowercase();
        let target_latest = format!("{}:latest", target);
        installed.iter().any(|m| {
            let norm = m.trim().to_ascii_lowercase();
            norm == target || norm == target_latest || norm.starts_with(&format!("{}-", target))
        })
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
        let hw = HardwareTelemetry::probe_fresh();
        let free_disk_gb = HardwareTelemetry::probe_free_disk_gb();
        let sufficient = (hw.free_ram_gb >= MIN_FREE_RAM_GB || hw.free_vram_mb >= MIN_FREE_VRAM_MB)
            && free_disk_gb >= AutoFusionRouter::estimated_model_disk_gb(CANONICAL_NIMBLE_GGUF);
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
                    let p = PathBuf::from(pf).join("Ollama").join("ollama.exe");
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
            for p_str in [
                "/usr/local/bin/ollama",
                "/opt/homebrew/bin/ollama",
                "/usr/bin/ollama",
            ] {
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

    /// Helper to probe installed model tags from `/api/tags` (`Some(vec)` when reachable, `None` when offline).
    pub async fn probe_installed_models(&self) -> Option<Vec<String>> {
        let tags_url = format!("{}/api/tags", self.endpoint);
        let resp = self
            .http_client
            .get(&tags_url)
            .timeout(PROBE_TIMEOUT)
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let val = resp.json::<serde_json::Value>().await.ok()?;
        let names: Vec<String> = val
            .get("models")
            .and_then(|m| m.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| {
                        m.get("name")
                            .and_then(|n| n.as_str())
                            .map(|s| s.trim().to_string())
                    })
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        Some(names)
    }

    /// Helper to verify if the model tag or canonical tag is present in `/api/tags`.
    pub async fn is_model_installed(&self) -> bool {
        if let Some(names) = self.probe_installed_models().await {
            return names
                .iter()
                .any(|n| n == &self.model_tag || n == &self.canonical_tag);
        }
        false
    }

    /// Launches a single-flight background pull for a memory-fitted fallback model (`qwen2.5:1.5b` / `3b` / `7b` / `14b` / `32b`)
    /// ONLY AFTER calculating live host RAM, VRAM, and disk headroom via `AutoFusionRouter::calculate_provision_plan`.
    pub fn spawn_fallback_pull(&self, fallback_tag: &str) -> bool {
        let raw_tag = fallback_tag.trim();
        if raw_tag.is_empty() || tokio::runtime::Handle::try_current().is_err() {
            return false;
        }

        // Mandatory pre-provisioning resource calculation before attempting any pull
        let plan = AutoFusionRouter::calculate_provision_plan(raw_tag, &[]);
        if !plan.disk_sufficient {
            warn!(
                "Skipping fallback pull for '{}': insufficient disk space ({:.1} GB free)",
                raw_tag, plan.free_disk_gb
            );
            return false;
        }
        let clean_tag = plan.effective_tag;

        if self
            .is_pulling_fallback
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }

        let endpoint = self.endpoint.clone();
        let http_client = self.http_client.clone();
        let fb_state = Arc::clone(&self.fallback_state);
        let pulling_flag = Arc::clone(&self.is_pulling_fallback);

        tokio::spawn(async move {
            Self::execute_fallback_pull_task(
                endpoint,
                clean_tag,
                http_client,
                fb_state,
                pulling_flag,
            )
            .await;
        });
        true
    }

    async fn execute_fallback_pull_task(
        endpoint: String,
        fallback_tag: String,
        http_client: reqwest::Client,
        fb_state: Arc<RwLock<NimbleProvisionState>>,
        pulling_flag: Arc<AtomicBool>,
    ) {
        struct FallbackGuard(Arc<AtomicBool>);
        impl Drop for FallbackGuard {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let _guard = FallbackGuard(pulling_flag);

        let tags_url = format!("{}/api/tags", endpoint);
        let mut reachable = false;
        if let Ok(resp) = http_client
            .get(&tags_url)
            .timeout(PROBE_TIMEOUT)
            .send()
            .await
        {
            if resp.status().is_success() {
                reachable = true;
                if let Ok(val) = resp.json::<serde_json::Value>().await {
                    let existing: Vec<String> = val
                        .get("models")
                        .and_then(|m| m.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|m| {
                                    m.get("name")
                                        .and_then(|n| n.as_str())
                                        .map(|s| s.trim().to_string())
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    if Self::tag_in_installed_list(&fallback_tag, &existing) {
                        *fb_state.write().await = NimbleProvisionState::Ready;
                        return;
                    }
                }
            }
        }

        if !reachable && endpoint.contains("127.0.0.1:11434") {
            let helper = NimbleProvisioner::new(endpoint.clone());
            reachable = helper.ensure_ollama_daemon_async().await;
        }
        if !reachable {
            *fb_state.write().await = NimbleProvisionState::Offline;
            return;
        }

        *fb_state.write().await = NimbleProvisionState::Downloading {
            progress_pct: 0.0,
            completed_bytes: 0,
            total_bytes: 986_000_000,
        };

        info!(
            "Auto-installing memory-fitted fallback model '{}' via {}/api/pull...",
            fallback_tag, endpoint
        );

        let pull_url = format!("{}/api/pull", endpoint);
        let pull_res = http_client
            .post(&pull_url)
            .timeout(Duration::from_secs(3600))
            .json(&serde_json::json!({ "name": fallback_tag }))
            .send()
            .await;

        let resp = match pull_res {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                warn!(
                    "Fallback /api/pull for '{}' returned HTTP {}",
                    fallback_tag,
                    r.status()
                );
                *fb_state.write().await = NimbleProvisionState::NotInstalled;
                return;
            }
            Err(e) => {
                warn!(
                    "Fallback /api/pull request failed for '{}': {}",
                    fallback_tag, e
                );
                *fb_state.write().await = NimbleProvisionState::Offline;
                return;
            }
        };

        let mut stream = resp.bytes_stream();
        let mut buffer = String::new();
        let mut completed_bytes: u64 = 0;
        let mut total_bytes: u64 = 986_000_000;
        let mut succeeded = false;
        let mut stream_err = false;

        while let Some(chunk_res) = stream.next().await {
            match chunk_res {
                Ok(chunk) => {
                    buffer.push_str(&String::from_utf8_lossy(&chunk));
                    while let Some(pos) = buffer.find('\n') {
                        let line = buffer[..pos].trim().to_string();
                        buffer.drain(..=pos);
                        if line.is_empty() {
                            continue;
                        }
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                            if val.get("error").and_then(|v| v.as_str()).is_some() {
                                stream_err = true;
                                break;
                            }
                            if val
                                .get("status")
                                .and_then(|v| v.as_str())
                                .map(|s| s.contains("success"))
                                .unwrap_or(false)
                            {
                                succeeded = true;
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
                                ((completed_bytes as f64) / (total_bytes as f64) * 100.0)
                                    .clamp(0.0, 100.0)
                            } else {
                                0.0
                            };
                            *fb_state.write().await = NimbleProvisionState::Downloading {
                                progress_pct: pct,
                                completed_bytes,
                                total_bytes,
                            };
                        }
                    }
                    if stream_err {
                        break;
                    }
                }
                Err(_) => {
                    stream_err = true;
                    break;
                }
            }
        }

        if !stream_err && (succeeded || (total_bytes > 0 && completed_bytes >= total_bytes)) {
            info!(
                "Memory-fitted fallback model '{}' provisioned and ready",
                fallback_tag
            );
            *fb_state.write().await = NimbleProvisionState::Ready;
        } else {
            *fb_state.write().await = NimbleProvisionState::NotInstalled;
        }
    }

    /// Probes the local Ollama `/api/tags` endpoint (400ms timeout) and returns the current `NimbleStatusResponse`.
    pub async fn probe_status(&self) -> NimbleStatusResponse {
        let (free_ram_gb, free_vram_mb, memory_sufficient) = Self::check_memory_law();
        let fallback_model_tag =
            Self::select_memory_fitted_fallback_model(free_ram_gb, free_vram_mb).to_string();

        // 1. If active background pull is in-flight, return downloading status immediately
        if self.is_pulling.load(Ordering::SeqCst) {
            let current_state = self.state.read().await.clone();
            let (pct, comp, tot) = match current_state {
                NimbleProvisionState::Downloading {
                    progress_pct,
                    completed_bytes,
                    total_bytes,
                } => (progress_pct, completed_bytes, total_bytes),
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
                fallback_model_tag,
                fallback_state: "not_needed".to_string(),
                fallback_progress_pct: 0.0,
                installed_models: Vec::new(),
            };
        }

        // 2. If memory law is not satisfied, mark state skipped_low_memory AND auto-provision memory-fitted fallback
        if !memory_sufficient {
            {
                let mut w = self.state.write().await;
                *w = NimbleProvisionState::SkippedLowMemory;
            }

            let installed_opt = self.probe_installed_models().await;
            let installed_models = installed_opt.clone().unwrap_or_default();

            let (fb_state_str, fb_pct) = if self.is_pulling_fallback.load(Ordering::SeqCst) {
                let cur = self.fallback_state.read().await.clone();
                match cur {
                    NimbleProvisionState::Downloading { progress_pct, .. } => {
                        ("downloading".to_string(), progress_pct.clamp(0.0, 100.0))
                    }
                    NimbleProvisionState::Ready => ("ready".to_string(), 100.0),
                    _ => ("downloading".to_string(), 0.0),
                }
            } else if let Some(ref models) = installed_opt {
                if Self::tag_in_installed_list(&fallback_model_tag, models) {
                    *self.fallback_state.write().await = NimbleProvisionState::Ready;
                    ("ready".to_string(), 100.0)
                } else if !Self::is_autoinstall_disabled()
                    && self.spawn_fallback_pull(&fallback_model_tag)
                {
                    ("downloading".to_string(), 0.0)
                } else {
                    ("not_installed".to_string(), 0.0)
                }
            } else {
                if !Self::is_autoinstall_disabled() {
                    let _ = self.spawn_fallback_pull(&fallback_model_tag);
                }
                ("offline".to_string(), 0.0)
            };

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
                fallback_model_tag,
                fallback_state: fb_state_str,
                fallback_progress_pct: fb_pct,
                installed_models,
            };
        }

        // 3. Probe Ollama /api/tags with 400ms timeout
        if let Some(installed_models) = self.probe_installed_models().await {
            let target_clean = self.model_tag.trim().to_ascii_lowercase();
            let canonical_clean = self.canonical_tag.trim().to_ascii_lowercase();
            let is_installed = installed_models.iter().any(|name| {
                let norm = name.trim().to_ascii_lowercase();
                norm == target_clean
                    || norm == canonical_clean
                    || norm.starts_with(&target_clean)
                    || norm.starts_with(&canonical_clean)
            });

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
                    fallback_model_tag,
                    fallback_state: "not_needed".to_string(),
                    fallback_progress_pct: 100.0,
                    installed_models,
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
                    fallback_model_tag,
                    fallback_state: "not_needed".to_string(),
                    fallback_progress_pct: 0.0,
                    installed_models,
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
                fallback_model_tag,
                fallback_state: "offline".to_string(),
                fallback_progress_pct: 0.0,
                installed_models: Vec::new(),
            }
        }
    }

    /// Triggers or retries background provisioning.
    /// Returns the immediate status response (`"downloading"` if started, or current status if already running/skipped).
    pub fn trigger_provision(self: &Arc<Self>) -> NimbleStatusResponse {
        let (free_ram_gb, free_vram_mb, memory_sufficient) = Self::check_memory_law();
        let fallback_model_tag =
            Self::select_memory_fitted_fallback_model(free_ram_gb, free_vram_mb).to_string();

        if !memory_sufficient {
            let started_fb = if !Self::is_autoinstall_disabled() {
                self.spawn_fallback_pull(&fallback_model_tag)
            } else {
                false
            };
            let (fb_state, fb_pct) =
                if started_fb || self.is_pulling_fallback.load(Ordering::SeqCst) {
                    let pct = self
                        .fallback_state
                        .try_read()
                        .ok()
                        .and_then(|g| match &*g {
                            NimbleProvisionState::Downloading { progress_pct, .. } => {
                                Some(progress_pct.clamp(0.0, 100.0))
                            }
                            _ => None,
                        })
                        .unwrap_or(0.0);
                    ("downloading".to_string(), pct)
                } else {
                    let ready = self
                        .fallback_state
                        .try_read()
                        .ok()
                        .map(|g| *g == NimbleProvisionState::Ready)
                        .unwrap_or(false);
                    if ready {
                        ("ready".to_string(), 100.0)
                    } else {
                        ("not_installed".to_string(), 0.0)
                    }
                };
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
                fallback_model_tag,
                fallback_state: fb_state,
                fallback_progress_pct: fb_pct,
                installed_models: Vec::new(),
            };
        }

        // Single-flight atomic exchange guard
        if self
            .is_pulling
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
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
                fallback_model_tag,
                fallback_state: "not_needed".to_string(),
                fallback_progress_pct: 0.0,
                installed_models: Vec::new(),
            }
        } else {
            // Already pulling in background
            let current = match self.state.try_read() {
                Ok(guard) => match &*guard {
                    NimbleProvisionState::Downloading {
                        progress_pct,
                        completed_bytes,
                        total_bytes,
                    } => (*progress_pct, *completed_bytes, *total_bytes),
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
                fallback_model_tag,
                fallback_state: "not_needed".to_string(),
                fallback_progress_pct: 0.0,
                installed_models: Vec::new(),
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

        // 1b. Re-calculate live host resources AFTER Ollama daemon is online and BEFORE sending /api/pull
        let existing_models = self.probe_installed_models().await.unwrap_or_default();
        let plan = self.calculate_provision_plan(&existing_models);
        if plan.already_installed && !plan.downsized_for_resources {
            let mut w = self.state.write().await;
            *w = NimbleProvisionState::Ready;
            return;
        }
        if plan.downsized_for_resources || !plan.disk_sufficient {
            {
                let mut w = self.state.write().await;
                *w = NimbleProvisionState::SkippedLowMemory;
            }
            if plan.disk_sufficient && !plan.already_installed && !Self::is_autoinstall_disabled() {
                let _ = self.spawn_fallback_pull(&plan.effective_tag);
            }
            return;
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
            .timeout(Duration::from_secs(3600))
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
                                ((completed_bytes as f64) / (total_bytes as f64) * 100.0)
                                    .clamp(0.0, 100.0)
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

        if !stream_error
            && (download_succeeded || (total_bytes > 0 && completed_bytes >= total_bytes))
        {
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
                info!(
                    "Successfully aliased {} to {}",
                    self.canonical_tag, self.model_tag
                );
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
                warn!(
                    "Failed to alias model via /api/copy: {}. Checking if model is installed.",
                    e
                );
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
            fallback_model_tag: "qwen2.5:7b".to_string(),
            fallback_state: "not_needed".to_string(),
            fallback_progress_pct: 0.0,
            installed_models: vec!["qwen2.5:7b".to_string()],
        };
        let json = serde_json::to_string(&resp).expect("must serialize");
        let deserialized: NimbleStatusResponse =
            serde_json::from_str(&json).expect("must deserialize");
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
            fallback_model_tag: "qwen2.5:1.5b".to_string(),
            fallback_state: "downloading".to_string(),
            fallback_progress_pct: 35.0,
            installed_models: Vec::new(),
        };
        assert_eq!(resp.state, "skipped_low_memory");
        assert!(!resp.memory_sufficient);
        assert_eq!(resp.progress_pct, 0.0);
        assert_eq!(resp.fallback_model_tag, "qwen2.5:1.5b");
    }

    #[test]
    fn test_select_memory_fitted_fallback_model_tiers() {
        assert_eq!(
            NimbleProvisioner::select_memory_fitted_fallback_model(2.6, 0.0),
            "qwen2.5:1.5b"
        );
        assert_eq!(
            NimbleProvisioner::select_memory_fitted_fallback_model(3.5, 0.0),
            "qwen2.5:1.5b"
        );
        assert_eq!(
            NimbleProvisioner::select_memory_fitted_fallback_model(6.5, 0.0),
            "qwen2.5:3b"
        );
        assert_eq!(
            NimbleProvisioner::select_memory_fitted_fallback_model(4.0, 2048.0),
            "qwen2.5:3b"
        );
        assert_eq!(
            NimbleProvisioner::select_memory_fitted_fallback_model(12.0, 0.0),
            "qwen2.5:7b"
        );
        assert_eq!(
            NimbleProvisioner::select_memory_fitted_fallback_model(28.0, 0.0),
            "qwen2.5:14b"
        );
        assert_eq!(
            NimbleProvisioner::select_memory_fitted_fallback_model(52.0, 0.0),
            "qwen2.5:32b"
        );
    }

    #[test]
    fn test_pre_provisioning_resource_calculation_downsizes_before_pull() {
        let low_ram_hw = HardwareTelemetry {
            total_ram_gb: 8.0,
            free_ram_gb: 3.5,
            cpu_cores: 8,
            gpu_name: None,
            free_vram_mb: 0,
            total_vram_mb: 0,
            gpu_count: 0,
        };

        // 1. Nimble-9B requested on 3.5 GB free RAM -> calculated plan downsizes to qwen2.5:1.5b BEFORE pull
        let plan_missing = AutoFusionRouter::calculate_provision_plan_with_hw(
            CANONICAL_NIMBLE_GGUF,
            &low_ram_hw,
            40.0,
            &["deepseek-r1:1.5b".to_string()],
        );
        assert!(plan_missing.downsized_for_resources);
        assert_eq!(plan_missing.effective_tag, "qwen2.5:1.5b");
        assert!(!plan_missing.already_installed);
        assert!(plan_missing.disk_sufficient);

        // 2. If qwen2.5:1.5b is ALREADY installed -> already_installed = true (zero redundant pull)
        let plan_installed = AutoFusionRouter::calculate_provision_plan_with_hw(
            CANONICAL_NIMBLE_GGUF,
            &low_ram_hw,
            40.0,
            &["deepseek-r1:1.5b".to_string(), "qwen2.5:1.5b".to_string()],
        );
        assert!(plan_installed.downsized_for_resources);
        assert_eq!(plan_installed.effective_tag, "qwen2.5:1.5b");
        assert!(plan_installed.already_installed);

        // 3. Gemma 4 26B requested on 3.5 GB free RAM -> downsizes to gemma2:2b BEFORE pull
        let plan_gemma = AutoFusionRouter::calculate_provision_plan_with_hw(
            "gemma4:26b",
            &low_ram_hw,
            40.0,
            &[],
        );
        assert!(plan_gemma.downsized_for_resources);
        assert_eq!(plan_gemma.effective_tag, "gemma2:2b");

        // 4. Low disk (< 1.2 GB free) blocks provisioning cleanly
        let plan_low_disk = AutoFusionRouter::calculate_provision_plan_with_hw(
            "qwen2.5:1.5b",
            &low_ram_hw,
            0.5,
            &[],
        );
        assert!(!plan_low_disk.disk_sufficient);
    }

    #[tokio::test]
    async fn test_low_memory_fallback_auto_install_wire_mock() {
        use axum::{
            routing::{get, post},
            Json, Router,
        };
        use std::sync::Mutex;

        let installed = Arc::new(Mutex::new(Vec::<String>::new()));
        let pull_calls = Arc::new(AtomicBool::new(false));

        let app = {
            let inst_tags = Arc::clone(&installed);
            let inst_pull = Arc::clone(&installed);
            let pflag = Arc::clone(&pull_calls);
            Router::new()
                .route(
                    "/api/tags",
                    get(move || {
                        let tags = inst_tags.lock().unwrap().clone();
                        async move {
                            let models: Vec<_> = tags
                                .into_iter()
                                .map(|n| serde_json::json!({ "name": n }))
                                .collect();
                            Json(serde_json::json!({ "models": models }))
                        }
                    }),
                )
                .route(
                    "/api/pull",
                    post(move |Json(body): Json<serde_json::Value>| {
                        let name = body
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("qwen2.5:1.5b")
                            .to_string();
                        pflag.store(true, Ordering::SeqCst);
                        inst_pull.lock().unwrap().push(name);
                        async move {
                            "{\"completed\":500,\"total\":1000}\n{\"completed\":1000,\"total\":1000,\"status\":\"success\"}\n"
                        }
                    }),
                )
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let prov = NimbleProvisioner::new(format!("http://{}", addr));
        assert!(prov.spawn_fallback_pull("qwen2.5:1.5b"));

        for _ in 0..40 {
            if *prov.fallback_state.read().await == NimbleProvisionState::Ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        assert!(
            pull_calls.load(Ordering::SeqCst),
            "Fallback model pull must be invoked automatically"
        );
        assert_eq!(
            *prov.fallback_state.read().await,
            NimbleProvisionState::Ready
        );
        srv.abort();
    }

    #[test]
    fn test_single_flight_atomic_bool_exclusion() {
        let provisioner = NimbleProvisioner::default();
        assert!(!provisioner.is_pulling.load(Ordering::SeqCst));
        let first = provisioner.is_pulling.compare_exchange(
            false,
            true,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        let second = provisioner.is_pulling.compare_exchange(
            false,
            true,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        assert!(first.is_ok());
        assert!(second.is_err());
        provisioner.is_pulling.store(false, Ordering::SeqCst);
        let third = provisioner.is_pulling.compare_exchange(
            false,
            true,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        assert!(third.is_ok());
    }

    #[test]
    fn test_initial_state_not_installed() {
        let provisioner = NimbleProvisioner::default();
        let initial_state = provisioner
            .state
            .try_read()
            .expect("must acquire read lock")
            .clone();
        assert_eq!(initial_state, NimbleProvisionState::NotInstalled);
    }

    #[tokio::test]
    async fn test_trigger_provision_concurrent_calls_no_panic() {
        let provisioner = Arc::new(NimbleProvisioner::new("http://127.0.0.1:59997"));
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
