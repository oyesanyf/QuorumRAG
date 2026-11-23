//! Shared opaque-box E2E test harness for QuorumRAG Cloud Drives (`F1`–`F18`).
//!
//! Zero M1–M4 compile-time coupling and zero SUT mocks:
//! - Spawns real `quorumrag` daemon child processes with isolated TempDirs, ports, and child env vars.
//! - Enforces the SPA fallback guard (`content-type` must contain `application/json`) on all API calls.
//! - Provides real filesystem layouts, Win32 `FILE_ATTRIBUTE_OFFLINE` + exclusive lock helpers,
//!   and WebUI asset readers.

use reqwest::header::HeaderMap;
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead as _, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tempfile::TempDir;

pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
pub const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
pub const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
pub const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
pub const SF_DATALESS: u32 = 0x4000_0000;

static DAEMON_BIN: OnceLock<PathBuf> = OnceLock::new();
static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

pub fn env_lock() -> &'static Mutex<()> {
    ENV_MUTEX.get_or_init(|| Mutex::new(()))
}

/// Returns the standalone `d:\harfile\QuorumRAG` repository root.
pub fn repo_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("tests/e2e must live two levels below repository root")
        .to_path_buf()
}

/// Resolves `QUORUM_DAEMON_BIN` if set, otherwise builds `quorumrag` once via Cargo.
pub fn quorum_daemon_binary() -> &'static PathBuf {
    DAEMON_BIN.get_or_init(|| {
        if let Some(explicit) = std::env::var_os("QUORUM_DAEMON_BIN") {
            let trimmed = explicit.to_string_lossy().trim().to_string();
            if !trimmed.is_empty() {
                let p = PathBuf::from(&trimmed);
                assert!(
                    p.is_file(),
                    "QUORUM_DAEMON_BIN points to missing binary: {}",
                    p.display()
                );
                return p;
            }
        }

        let root = repo_root();
        let manifest = root.join("Cargo.toml");
        let output = Command::new("cargo")
            .arg("build")
            .arg("--bin")
            .arg("quorumrag")
            .arg("--manifest-path")
            .arg(&manifest)
            .output()
            .expect("failed to invoke cargo build --bin quorumrag");

        assert!(
            output.status.success(),
            "cargo build --bin quorumrag failed (exit {:?}):\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let bin_name = if cfg!(windows) {
            "quorumrag.exe"
        } else {
            "quorumrag"
        };
        let built = root.join("target").join("debug").join(bin_name);
        assert!(
            built.is_file(),
            "Expected freshly built daemon binary at {}",
            built.display()
        );
        built
    })
}

/// Allocates a free localhost TCP port for an isolated daemon child.
pub fn allocate_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").port()
}

/// Normalizes a path string for cross-separator / Windows case-insensitive comparison.
pub fn normalize_cmp_path(raw: &str) -> String {
    let mut s = raw.trim().replace('/', "\\");
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        s = stripped.to_string();
    }
    while s.len() > 3 && s.ends_with('\\') {
        s.pop();
    }
    if cfg!(windows) {
        s.to_ascii_lowercase()
    } else {
        s.replace('\\', "/")
    }
}

pub fn paths_equivalent(a: &str, b: &str) -> bool {
    normalize_cmp_path(a) == normalize_cmp_path(b)
}

/// Isolated temporary workspace simulating user profiles, appdata, and cloud sync roots.
pub struct FakeCloudWorkspace {
    pub root: TempDir,
    pub home: PathBuf,
    pub appdata: PathBuf,
    pub localappdata: PathBuf,
    pub xdg_config: PathBuf,
    pub data_dir: PathBuf,
    pub watch_dir: PathBuf,
}

impl FakeCloudWorkspace {
    pub fn new() -> Self {
        let root = tempfile::tempdir().expect("create FakeCloudWorkspace tempdir");
        let base = root.path();
        let home = base.join("profile");
        let appdata = home.join("AppData").join("Roaming");
        let localappdata = home.join("AppData").join("Local");
        let xdg_config = home.join(".config");
        let data_dir = base.join("quorum_data");
        let watch_dir = base.join("quorum_watch");

        for d in [
            &home,
            &appdata,
            &localappdata,
            &xdg_config,
            &data_dir,
            &watch_dir,
        ] {
            fs::create_dir_all(d).expect("create workspace subdir");
        }

        Self {
            root,
            home,
            appdata,
            localappdata,
            xdg_config,
            data_dir,
            watch_dir,
        }
    }

    pub fn settings_json_path(&self) -> PathBuf {
        self.data_dir.join("settings.json")
    }

    pub fn read_settings_json(&self) -> Value {
        let path = self.settings_json_path();
        let raw = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
        serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
    }

    pub fn mkdir(&self, rel: &str) -> PathBuf {
        let p = self.home.join(rel);
        fs::create_dir_all(&p).expect("create dir");
        p
    }

    pub fn write_doc(&self, dir: &Path, filename: &str, content: &str) -> PathBuf {
        fs::create_dir_all(dir).expect("create parent dir");
        let p = dir.join(filename);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).expect("create file parent");
        }
        fs::write(&p, content.as_bytes()).expect("write doc");
        p
    }

    pub fn write_sized_file(
        &self,
        dir: &Path,
        filename: &str,
        size_bytes: usize,
        header_token: &str,
    ) -> PathBuf {
        fs::create_dir_all(dir).expect("create parent dir");
        let p = dir.join(filename);
        let mut f = fs::File::create(&p).expect("create sized file");
        let header = format!("{header_token}\n");
        let hb = header.as_bytes();
        if size_bytes <= hb.len() {
            f.write_all(&hb[..size_bytes]).expect("write header slice");
            return p;
        }
        f.write_all(hb).expect("write header");
        let mut remaining = size_bytes - hb.len();
        let block = vec![b'A'; 65536];
        while remaining > 0 {
            let chunk = remaining.min(block.len());
            let mut written_line = false;
            if chunk >= 64 {
                f.write_all(&block[..chunk - 1]).expect("write filler");
                f.write_all(b"\n").expect("write newline");
                written_line = true;
            }
            if !written_line {
                f.write_all(&block[..chunk]).expect("write tail");
            }
            remaining -= chunk;
        }
        f.flush().expect("flush sized file");
        p
    }

    // --- Cross-OS provider tree builders ---

    pub fn plant_google_drive_win_my_drive(&self) -> PathBuf {
        self.mkdir("My Drive")
    }

    pub fn plant_google_drive_win_mirror(&self) -> PathBuf {
        self.mkdir("Google Drive/My Drive")
    }

    pub fn plant_google_drive_win_shared_drives(&self) -> PathBuf {
        self.mkdir("Google Drive/Shared drives")
    }

    pub fn plant_google_drive_macos(&self, account: &str) -> PathBuf {
        self.mkdir(&format!(
            "Library/CloudStorage/GoogleDrive-{account}/My Drive"
        ))
    }

    pub fn plant_google_drive_linux(&self, variant: &str) -> PathBuf {
        self.mkdir(variant)
    }

    pub fn plant_onedrive_personal(&self) -> PathBuf {
        self.mkdir("OneDrive")
    }

    pub fn plant_onedrive_business(&self, org: &str) -> PathBuf {
        self.mkdir(&format!("OneDrive - {org}"))
    }

    pub fn plant_onedrive_macos(&self, folder_name: &str) -> PathBuf {
        self.mkdir(&format!("Library/CloudStorage/{folder_name}"))
    }

    pub fn plant_dropbox_standard(&self) -> PathBuf {
        self.mkdir("Dropbox")
    }

    pub fn plant_dropbox_macos(&self) -> PathBuf {
        self.mkdir("Library/CloudStorage/Dropbox")
    }

    pub fn plant_dropbox_info_json(&self, json_body: &str) {
        let win_dir = self.appdata.join("Dropbox");
        fs::create_dir_all(&win_dir).expect("appdata dropbox");
        fs::write(win_dir.join("info.json"), json_body).expect("write win info.json");

        let posix_dir = self.home.join(".dropbox");
        fs::create_dir_all(&posix_dir).expect(".dropbox");
        fs::write(posix_dir.join("info.json"), json_body).expect("write posix info.json");
    }

    pub fn plant_icloud_win(&self, folder: &str) -> PathBuf {
        self.mkdir(folder)
    }

    pub fn plant_icloud_macos_mobile_docs(&self) -> PathBuf {
        self.mkdir("Library/Mobile Documents/com~apple~CloudDocs")
    }

    pub fn plant_icloud_macos_cloudstorage(&self) -> PathBuf {
        self.mkdir("Library/CloudStorage/iCloudDrive")
    }

    pub fn plant_box_win(&self, folder: &str) -> PathBuf {
        self.mkdir(folder)
    }

    pub fn plant_box_macos(&self) -> PathBuf {
        self.mkdir("Library/CloudStorage/Box-Box")
    }

    pub fn plant_nextcloud_home(&self) -> PathBuf {
        self.mkdir("Nextcloud")
    }

    pub fn plant_nextcloud_macos_cloudstorage(&self, suffix: &str) -> PathBuf {
        self.mkdir(&format!("Library/CloudStorage/Nextcloud-{suffix}"))
    }

    pub fn plant_nextcloud_cfg(&self, cfg_text: &str) {
        for dir in [
            self.appdata.join("Nextcloud"),
            self.home.join("Library/Preferences/Nextcloud"),
            self.xdg_config.join("Nextcloud"),
        ] {
            fs::create_dir_all(&dir).expect("create nextcloud cfg dir");
            fs::write(dir.join("nextcloud.cfg"), cfg_text).expect("write nextcloud.cfg");
        }
    }

    pub fn plant_proton_drive_win(&self) -> PathBuf {
        let _ = self.mkdir("Proton Drive/My files");
        self.home.join("Proton Drive")
    }

    pub fn plant_proton_drive_macos(&self, account: &str) -> PathBuf {
        self.mkdir(&format!("Library/CloudStorage/ProtonDrive-{account}"))
    }

    pub fn plant_proton_drive_linux(&self) -> PathBuf {
        self.mkdir("ProtonDrive")
    }

    pub fn plant_pcloud_win(&self, folder: &str) -> PathBuf {
        self.mkdir(folder)
    }

    pub fn plant_pcloud_macos(&self) -> PathBuf {
        self.mkdir("Library/CloudStorage/pCloudDrive")
    }

    pub fn plant_pcloud_linux(&self) -> PathBuf {
        self.mkdir("pCloudDrive")
    }
}

impl Default for FakeCloudWorkspace {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// WIN32 REAL PLACEHOLDER ATTRIBUTE & EXCLUSIVE LOCK HELPERS
// ============================================================================

#[cfg(windows)]
mod win32_fs {
    use super::*;
    use std::os::windows::ffi::OsStrExt;

    const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
    const GENERIC_READ: u32 = 0x8000_0000;
    const OPEN_EXISTING: u32 = 3;
    const INVALID_HANDLE_VALUE: isize = -1;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileAttributesW(lpFileName: *const u16) -> u32;
        fn SetFileAttributesW(lpFileName: *const u16, dwFileAttributes: u32) -> i32;
        fn CreateFileW(
            lpFileName: *const u16,
            dwDesiredAccess: u32,
            dwShareMode: u32,
            lpSecurityAttributes: *mut core::ffi::c_void,
            dwCreationDisposition: u32,
            dwFlagsAndAttributes: u32,
            hTemplateFile: isize,
        ) -> isize;
        fn CloseHandle(hObject: isize) -> i32;
    }

    fn to_wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub fn get_attrs(path: &Path) -> std::io::Result<u32> {
        let wide = to_wide(path);
        let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
        if attrs == INVALID_FILE_ATTRIBUTES {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(attrs)
        }
    }

    pub fn set_offline(path: &Path) -> std::io::Result<u32> {
        let wide = to_wide(path);
        let current = get_attrs(path)?;
        let target = current | FILE_ATTRIBUTE_OFFLINE;
        let ok = unsafe { SetFileAttributesW(wide.as_ptr(), target) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let verified = get_attrs(path)?;
        if (verified & FILE_ATTRIBUTE_OFFLINE) == 0 {
            return Err(std::io::Error::other(format!(
                "FILE_ATTRIBUTE_OFFLINE did not persist on {}",
                path.display()
            )));
        }
        Ok(verified)
    }

    pub struct ExclusiveFileLockGuard {
        handle: isize,
    }

    impl ExclusiveFileLockGuard {
        pub fn lock(path: &Path) -> std::io::Result<Self> {
            let wide = to_wide(path);
            let handle = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ,
                    0, // dwShareMode = 0: deny all concurrent open/read/write handles
                    core::ptr::null_mut(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    0,
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(Self { handle })
            }
        }
    }

    impl Drop for ExclusiveFileLockGuard {
        fn drop(&mut self) {
            if self.handle != INVALID_HANDLE_VALUE && self.handle != 0 {
                unsafe {
                    let _ = CloseHandle(self.handle);
                }
            }
        }
    }
}

#[cfg(not(windows))]
mod win32_fs {
    use super::*;

    pub fn get_attrs(_path: &Path) -> std::io::Result<u32> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Win32 file attributes are only supported on Windows",
        ))
    }

    pub fn set_offline(_path: &Path) -> std::io::Result<u32> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Win32 FILE_ATTRIBUTE_OFFLINE is only supported on Windows",
        ))
    }

    pub struct ExclusiveFileLockGuard;

    impl ExclusiveFileLockGuard {
        pub fn lock(_path: &Path) -> std::io::Result<Self> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Win32 CreateFileW exclusive lock is only supported on Windows",
            ))
        }
    }
}

pub use win32_fs::ExclusiveFileLockGuard;

pub fn set_windows_offline_attribute(path: &Path) -> std::io::Result<u32> {
    win32_fs::set_offline(path)
}

pub fn get_windows_file_attributes(path: &Path) -> std::io::Result<u32> {
    win32_fs::get_attrs(path)
}

// ============================================================================
// OPAQUE-BOX DAEMON CHILD PROCESS HARNESS
// ============================================================================

pub struct DaemonTestProcess {
    pub http_port: u16,
    pub p2p_port: u16,
    pub base_url: String,
    pub data_dir: PathBuf,
    pub client: Client,
    child: Option<Child>,
    logs: Arc<Mutex<String>>,
}

impl DaemonTestProcess {
    pub async fn start(ws: &FakeCloudWorkspace) -> Self {
        Self::start_with_env(ws, &[]).await
    }

    pub async fn start_with_env(ws: &FakeCloudWorkspace, extra_env: &[(&str, &str)]) -> Self {
        let bin = quorum_daemon_binary();
        let requested_http = allocate_free_port();
        let p2p_port = allocate_free_port();

        let mut cmd = Command::new(bin);
        cmd.arg("--host")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(requested_http.to_string())
            .arg("--p2p-port")
            .arg(p2p_port.to_string())
            .arg("--data-dir")
            .arg(&ws.data_dir)
            .arg("--watch-dir")
            .arg(&ws.watch_dir)
            .arg("--local-only")
            .arg("--no-p2p-watcher")
            .arg("--no-browser")
            .arg("--no-forensics")
            .env("RUST_LOG", "quorumrag=info,quorum_daemon=info")
            .env("QUORUM_ISOLATED_WATCH_DIR", "1")
            .env("QUORUM_DISABLE_OLLAMA_AUTOINSTALL", "1")
            .env("QUORUM_SHOW_CONSOLE", "1")
            .env("QUORUM_CLOUD_TEST_PROFILE_DIR", &ws.home)
            .env("USERPROFILE", &ws.home)
            .env("HOME", &ws.home)
            .env("APPDATA", &ws.appdata)
            .env("LOCALAPPDATA", &ws.localappdata)
            .env("XDG_CONFIG_HOME", &ws.xdg_config)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        for &(k, v) in extra_env {
            cmd.env(k, v);
        }

        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("Failed to spawn {}: {}", bin.display(), e));

        let logs = Arc::new(Mutex::new(String::new()));
        let actual_port = Arc::new(Mutex::new(None::<u16>));

        if let Some(stdout) = child.stdout.take() {
            let logs_c = Arc::clone(&logs);
            let port_c = Arc::clone(&actual_port);
            std::thread::spawn(move || {
                let reader = std::io::BufReader::new(stdout);
                for line in reader.lines().map_while(Result::ok) {
                    if let Some(idx) = line.find("QuorumRAG Web UI listening on http://") {
                        let after = &line[idx + "QuorumRAG Web UI listening on http://".len()..];
                        let host_port = after.split_whitespace().next().unwrap_or(after);
                        if let Some((_, port_part)) = host_port.rsplit_once(':') {
                            let digits: String = port_part
                                .chars()
                                .take_while(|c| c.is_ascii_digit())
                                .collect();
                            if let Ok(p) = digits.parse::<u16>() {
                                if let Ok(mut g) = port_c.lock() {
                                    if g.is_none() {
                                        *g = Some(p);
                                    }
                                }
                            }
                        }
                    }
                    if let Ok(mut g) = logs_c.lock() {
                        if g.len() < 128 * 1024 {
                            g.push_str(&line);
                            g.push('\n');
                        }
                    }
                }
            });
        }

        if let Some(stderr) = child.stderr.take() {
            let logs_c = Arc::clone(&logs);
            std::thread::spawn(move || {
                let reader = std::io::BufReader::new(stderr);
                for line in reader.lines().map_while(Result::ok) {
                    if let Ok(mut g) = logs_c.lock() {
                        if g.len() < 128 * 1024 {
                            g.push_str(&line);
                            g.push('\n');
                        }
                    }
                }
            });
        }

        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .expect("build reqwest client");

        let mut proc = Self {
            http_port: requested_http,
            p2p_port,
            base_url: format!("http://127.0.0.1:{requested_http}"),
            data_dir: ws.data_dir.clone(),
            client,
            child: Some(child),
            logs,
        };

        proc.wait_until_healthy(&actual_port).await;
        proc
    }

    async fn wait_until_healthy(&mut self, detected_port: &Arc<Mutex<Option<u16>>>) {
        let deadline = Instant::now() + Duration::from_secs(45);
        let expected_data_dir = self.data_dir.to_string_lossy().to_string();
        loop {
            let mut port_confirmed = false;
            if let Ok(Some(p)) = detected_port.lock().map(|g| *g) {
                port_confirmed = true;
                if p != self.http_port {
                    self.http_port = p;
                    self.base_url = format!("http://127.0.0.1:{p}");
                }
            }

            if let Some(child) = self.child.as_mut() {
                if let Ok(Some(status)) = child.try_wait() {
                    let log_dump = self.captured_logs();
                    panic!(
                        "quorumrag exited prematurely with status {:?} before /api/health ready.\nLogs:\n{}",
                        status, log_dump
                    );
                }
            }

            let url = format!("{}/api/health", self.base_url);
            if let Ok(resp) = self.client.get(&url).send().await {
                if resp.status().is_success() {
                    let ct = resp
                        .headers()
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    if ct.contains("application/json") {
                        if let Ok(val) = resp.json::<Value>().await {
                            let is_healthy =
                                val.get("status").and_then(|v| v.as_str()) == Some("healthy");
                            let reported_dir = val
                                .pointer("/storage/data_dir")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let matches_our_daemon = !reported_dir.is_empty()
                                && paths_equivalent(reported_dir, &expected_data_dir);
                            if is_healthy && (matches_our_daemon || port_confirmed) {
                                assert!(
                                    matches_our_daemon,
                                    "Health probe attached to wrong daemon: expected data_dir='{}', got '{}'",
                                    expected_data_dir, reported_dir
                                );
                                return;
                            }
                        }
                    }
                }
            }

            if Instant::now() >= deadline {
                let log_dump = self.captured_logs();
                panic!(
                    "Timed out waiting for {} /api/health to report healthy for data_dir '{}'.\nLogs:\n{}",
                    self.base_url, expected_data_dir, log_dump
                );
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }

    pub fn captured_logs(&self) -> String {
        self.logs.lock().map(|g| g.clone()).unwrap_or_default()
    }

    fn url(&self, path: &str) -> String {
        if path.starts_with('/') {
            format!("{}{}", self.base_url, path)
        } else {
            format!("{}/{}", self.base_url, path)
        }
    }

    /// SPA Fallback Guard: fails loudly if an API route fell through to `quorum_ui::static_handler` HTML.
    pub fn assert_json_content_type(headers: &HeaderMap, route: &str, body_preview: &str) {
        let ct = headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.to_ascii_lowercase().contains("application/json"),
            "SPA FALLBACK / CONTENT-TYPE VIOLATION on {}: expected application/json, got Content-Type='{}'. Body preview: {}",
            route,
            ct,
            &body_preview[..body_preview.len().min(300)]
        );
    }

    pub fn assert_not_html_spa_fallback(headers: &HeaderMap, route: &str, body_preview: &str) {
        let ct = headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        let trimmed = body_preview.trim_start();
        assert!(
            !ct.contains("text/html") && !trimmed.starts_with("<!DOCTYPE") && !trimmed.starts_with("<html"),
            "SPA FALLBACK VIOLATION on {}: received HTML instead of API response (Content-Type='{}'). Body preview: {}",
            route,
            ct,
            &body_preview[..body_preview.len().min(300)]
        );
    }

    pub async fn get_json(&self, path: &str) -> Value {
        let url = self.url(path);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {} failed: {}", url, e));
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.text().await.expect("read GET response body");
        Self::assert_json_content_type(&headers, path, &body);
        assert!(
            status.is_success(),
            "GET {} expected 2xx JSON, got {} with body: {}",
            path,
            status,
            body
        );
        serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("Invalid JSON from GET {}: {}: {}", path, e, body))
    }

    pub async fn post_json(&self, path: &str, payload: &Value) -> Value {
        let url = self.url(path);
        let resp = self
            .client
            .post(&url)
            .json(payload)
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST {} failed: {}", url, e));
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.text().await.expect("read POST response body");
        Self::assert_json_content_type(&headers, path, &body);
        assert!(
            status.is_success(),
            "POST {} expected 2xx JSON, got {} with body: {}",
            path,
            status,
            body
        );
        serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("Invalid JSON from POST {}: {}: {}", path, e, body))
    }

    pub async fn post_json_raw(
        &self,
        path: &str,
        payload: &Value,
    ) -> (StatusCode, HeaderMap, String) {
        let url = self.url(path);
        let resp = self
            .client
            .post(&url)
            .json(payload)
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST {} failed: {}", url, e));
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.text().await.expect("read POST raw body");
        Self::assert_not_html_spa_fallback(&headers, path, &body);
        (status, headers, body)
    }

    pub async fn post_raw_body(
        &self,
        path: &str,
        raw_body: &str,
        content_type: &str,
    ) -> (StatusCode, HeaderMap, String) {
        let url = self.url(path);
        let resp = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(raw_body.to_string())
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST raw {} failed: {}", url, e));
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.text().await.expect("read POST raw body");
        Self::assert_not_html_spa_fallback(&headers, path, &body);
        (status, headers, body)
    }

    pub async fn get_raw(&self, path: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
        let url = self.url(path);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET raw {} failed: {}", url, e));
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = resp.bytes().await.expect("read bytes").to_vec();
        (status, headers, bytes)
    }

    pub async fn get_text(&self, path: &str) -> (StatusCode, HeaderMap, String) {
        let (status, headers, bytes) = self.get_raw(path).await;
        (
            status,
            headers,
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    pub async fn get_cloud_drives(&self) -> Value {
        self.get_json("/api/cloud-drives").await
    }

    pub async fn post_cloud_drives_config(&self, payload: &Value) -> Value {
        self.post_json("/api/cloud-drives/config", payload).await
    }

    pub async fn post_cloud_drives_reindex(&self, drive_id: &str) -> Value {
        self.post_json("/api/cloud-drives/reindex", &json!({ "id": drive_id }))
            .await
    }

    pub async fn enable_and_reindex_drive(
        &self,
        drive_id: &str,
        root_path: &Path,
        access_tier: Option<u8>,
        min_indexed_files: u64,
    ) -> Value {
        let mut payload = json!({
            "action": "toggle_drive",
            "id": drive_id,
            "enabled": true,
            "root_path": root_path.to_string_lossy().to_string(),
        });
        if let Some(t) = access_tier {
            payload["access_tier"] = json!(t);
        }
        let _ = self.post_cloud_drives_config(&payload).await;
        let _ = self.post_cloud_drives_reindex(drive_id).await;
        self.wait_for_indexed(drive_id, min_indexed_files, Duration::from_secs(90))
            .await
    }

    /// Evaluates `/api/reindex/status` using the real `ReindexProgress` schema (`task_id` + `phase`).
    pub fn is_reindex_running(status: &Value) -> bool {
        let has_active_task_id = status
            .get("task_id")
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        let phase = status.get("phase").and_then(|v| v.as_str()).unwrap_or("");
        let active_phase = matches!(
            phase,
            "scanning_filesystem"
                | "chunking_and_vectorizing"
                | "writing_to_storage"
                | "compacting_indexes"
        );
        has_active_task_id && active_phase
    }

    pub async fn wait_for_indexed(
        &self,
        drive_id: &str,
        min_files: u64,
        timeout: Duration,
    ) -> Value {
        let deadline = Instant::now() + timeout;
        loop {
            let payload = self.get_cloud_drives().await;
            let drv = find_drive(&payload, drive_id);
            let count = drv
                .get("indexed_files")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            if count >= min_files {
                let status = self.get_json("/api/reindex/status").await;
                if !Self::is_reindex_running(&status) {
                    return payload;
                }
            }
            if Instant::now() >= deadline {
                panic!(
                    "Timed out waiting for drive '{}' to reach indexed_files >= {} and settle. Latest payload: {}",
                    drive_id, min_files, payload
                );
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    pub async fn wait_for_reindex_settled(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        // Brief initial grace window so freshly triggered background task registers active task_id
        tokio::time::sleep(Duration::from_millis(350)).await;
        loop {
            let status = self.get_json("/api/reindex/status").await;
            if !Self::is_reindex_running(&status) {
                return;
            }
            if Instant::now() >= deadline {
                panic!("Timed out waiting for reindex worker to settle: {}", status);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    pub async fn query_local(&self, prompt: &str) -> Value {
        self.post_json(
            "/api/query",
            &json!({
                "prompt": prompt,
                "access_tier": 3,
                "search_mode": "Hybrid",
                "bypass_cache": true,
                "top_k": 32
            }),
        )
        .await
    }

    pub async fn query_local_cached(&self, prompt: &str) -> Value {
        self.post_json(
            "/api/query",
            &json!({
                "prompt": prompt,
                "access_tier": 3,
                "search_mode": "Hybrid",
                "bypass_cache": false,
                "top_k": 32
            }),
        )
        .await
    }

    pub async fn get_atlaskv_status(&self) -> Value {
        self.get_json("/api/v1/atlaskv/status").await
    }

    pub async fn query_atlaskv(&self, query: &str, max_tier: u8) -> Value {
        self.post_json(
            "/api/v1/atlaskv/query",
            &json!({
                "query": query,
                "max_tier": max_tier,
                "top_k": 32
            }),
        )
        .await
    }

    pub async fn shutdown(mut self) {
        let _ = self.client.post(self.url("/api/shutdown")).send().await;
        let Some(mut child) = self.child.take() else {
            return;
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(75)).await;
                }
                _ => {
                    let _ = tokio::task::spawn_blocking(move || {
                        let _ = child.kill();
                        let _ = child.wait();
                    })
                    .await;
                    return;
                }
            }
        }
    }

    fn send_sync_shutdown(&self) {
        let addr: SocketAddr = format!("127.0.0.1:{}", self.http_port)
            .parse()
            .expect("valid socket addr");
        if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(1)) {
            let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
            let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
            let req = format!(
                "POST /api/shutdown HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                self.http_port
            );
            let _ = stream.write_all(req.as_bytes());
            let mut sink = [0u8; 256];
            let _ = stream.read(&mut sink);
        }
    }

    fn terminate_inner(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        self.send_sync_shutdown();
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(75));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
            }
        }
    }
}

impl Drop for DaemonTestProcess {
    fn drop(&mut self) {
        self.terminate_inner();
    }
}

/// Finds a drive entry by `id` inside `GET /api/cloud-drives` response JSON.
pub fn find_drive<'a>(payload: &'a Value, id: &str) -> &'a Value {
    let drives = payload
        .get("drives")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("Missing 'drives' array in payload: {}", payload));
    drives
        .iter()
        .find(|d| d.get("id").and_then(|v| v.as_str()) == Some(id))
        .unwrap_or_else(|| panic!("Drive id '{}' not found in payload: {}", id, payload))
}

/// Finds all drive entries matching a given `provider` string (e.g., `"onedrive"`, `"dropbox"`).
pub fn find_drives_by_provider<'a>(payload: &'a Value, provider: &str) -> Vec<&'a Value> {
    let drives = payload
        .get("drives")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("Missing 'drives' array in payload: {}", payload));
    drives
        .iter()
        .filter(|d| d.get("provider").and_then(|v| v.as_str()) == Some(provider))
        .collect()
}

/// Checks whether a `QueryResult` JSON actually retrieved `token` inside indexed chunk content or citations
/// (explicitly avoiding `synthesis_prompt`, which echoes the query prompt itself).
pub fn query_result_contains_token(result: &Value, token: &str) -> bool {
    let in_chunks = result
        .get("chunks")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter().any(|scored| {
                let text = scored
                    .pointer("/chunk/text_content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let path = scored
                    .pointer("/chunk/file_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                text.contains(token) || path.contains(token)
            })
        })
        .unwrap_or(false);

    let in_citations = result
        .get("sources_cited")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter().any(|cit| {
                let snippet = cit.get("snippet").and_then(|v| v.as_str()).unwrap_or("");
                let path = cit.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
                snippet.contains(token) || path.contains(token)
            })
        })
        .unwrap_or(false);

    in_chunks || in_citations
}

/// Checks whether a `QueryResult` JSON cites or includes a chunk from a path matching `needle`.
pub fn query_result_mentions_path(result: &Value, needle: &str) -> bool {
    let needle_norm = normalize_cmp_path(needle);
    let in_chunks = result
        .get("chunks")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter().any(|scored| {
                let path = scored
                    .pointer("/chunk/file_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                normalize_cmp_path(path).contains(&needle_norm)
            })
        })
        .unwrap_or(false);

    let in_citations = result
        .get("sources_cited")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter().any(|cit| {
                let path = cit.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
                normalize_cmp_path(path).contains(&needle_norm)
            })
        })
        .unwrap_or(false);

    in_chunks || in_citations
}

/// Checks whether a `POST /api/v1/atlaskv/query` response contains `token` in its retrieved
/// triples or `formatted_context`.
pub fn atlaskv_result_contains_token(result: &Value, token: &str) -> bool {
    let in_triples = result
        .get("triples")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter().any(|scored| {
                let entity = scored
                    .pointer("/triple/entity")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let value = scored
                    .pointer("/triple/value")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let key_string = scored
                    .pointer("/triple/key_string")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let file_path = scored
                    .pointer("/triple/file_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                entity.contains(token)
                    || value.contains(token)
                    || key_string.contains(token)
                    || file_path.contains(token)
            })
        })
        .unwrap_or(false);
    let in_ctx = result
        .get("formatted_context")
        .and_then(|v| v.as_str())
        .map(|s| s.contains(token))
        .unwrap_or(false);
    in_triples || in_ctx
}

/// Reads real `crates/quorum-ui/assets/{index.html, app.js, styles.css}` from the workspace.
pub fn read_repo_ui_assets() -> (String, String, String) {
    let assets = repo_root().join("crates").join("quorum-ui").join("assets");
    let html = fs::read_to_string(assets.join("index.html")).expect("read index.html");
    let js = fs::read_to_string(assets.join("app.js")).expect("read app.js");
    let css = fs::read_to_string(assets.join("styles.css")).expect("read styles.css");
    (html, js, css)
}
