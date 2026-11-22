#![cfg_attr(windows, windows_subsystem = "windows")]
//! QuorumRAG Native Cross-Platform GUI Launcher & Silent Installer Helper (`quorum-desktop`).
//!
//! Compiled as a pure GUI-subsystem executable on Windows (`IMAGE_SUBSYSTEM_WINDOWS_GUI = 2`),
//! a Universal2 Mach-O app executable on macOS (`QuorumRAG.app/Contents/MacOS/QuorumRAG`),
//! and a native desktop launcher on Linux (`/usr/lib/quorumrag/quorum-desktop`).
//!
//! Responsibilities:
//! 1. Desktop / Start Menu / Dock / AppGrid launch (`0` arguments):
//!    - Probes `http://127.0.0.1:<port>/api/health` over native TCP (`0` `curl`/`cmd` spawns).
//!    - Starts/waits on the OS service (`QuorumRAGDaemon` via Win32 SCM, `dev.quorumrag.daemon`
//!      LaunchDaemon, or `quorumrag.service` systemd unit) when installed, or launches a
//!      detached per-user `quorumrag` background daemon (`CREATE_NO_WINDOW`) in portable mode.
//!    - Opens `http://127.0.0.1:<port>/` via native `ShellExecuteW` / `open::that`.
//! 2. Silent MSI / OS Installer CustomAction operations (Windows & cross-OS):
//!    - `--open-ui [--port 3031] [--timeout-secs 90]`
//!    - `--wait-health [--port 3031] [--timeout-secs 90]`
//!    - `--msi-kill-orphans`
//!    - `--msi-stop-cleanup [--delete-service]`
//!    - `--msi-firewall-add [--program <EXE>] [--http-port 3031] [--p2p-port 3032]`
//!    - `--msi-firewall-remove`
//!    - `--msi-remove-data --data-dir <DIR>`

use std::env;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(windows)]
mod win_native;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const DEFAULT_HTTP_PORT: u16 = 3031;
const DEFAULT_P2P_PORT: u16 = 3032;

fn sanitize_cli_path(raw: &str) -> PathBuf {
    let cleaned = raw.trim().trim_matches('"').trim();
    PathBuf::from(cleaned)
}

fn default_http_port() -> u16 {
    env::var("QUORUMRAG_PORT")
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|&p| p > 0)
        .unwrap_or(DEFAULT_HTTP_PORT)
}

/// Pure-Rust non-blocking HTTP health probe against `127.0.0.1:<port>/api/health`
/// (eliminates `curl.exe` / `wget` console loops on all OSes).
fn probe_daemon_health(port: u16, timeout_ms: u64) -> bool {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let timeout = Duration::from_millis(timeout_ms);
    let mut stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let req = format!(
        "GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }

    let mut buf = [0u8; 256];
    match stream.read(&mut buf) {
        Ok(n) if n >= 12 => {
            let head = String::from_utf8_lossy(&buf[..n]);
            head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200")
        }
        _ => false,
    }
}

fn wait_for_daemon_health(port: u16, max_wait_secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(max_wait_secs);
    while Instant::now() < deadline {
        if probe_daemon_health(port, 1200) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    probe_daemon_health(port, 1200)
}

fn open_browser_native(url: &str) {
    #[cfg(windows)]
    {
        if win_native::shell_open_url(url).is_err() {
            let _ = open::that(url);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = open::that(url);
    }
}

fn find_quorumrag_binary() -> Option<PathBuf> {
    if let Ok(current_exe) = env::current_exe() {
        if let Some(exe_dir) = current_exe.parent() {
            let sibling_names: &[&str] = if cfg!(windows) {
                &["quorumrag.exe", "quorumrag"]
            } else {
                // On macOS `.app` bundles (`Contents/MacOS/QuorumRAG`), the daemon sits next to it
                // as `quorumrag-bin` or `quorumrag`.
                &["quorumrag-bin", "quorumrag", "quorumrag.exe"]
            };
            for name in sibling_names {
                let cand = exe_dir.join(name);
                if cand.is_file() {
                    return Some(cand);
                }
            }
        }
    }

    #[cfg(unix)]
    {
        for sys_cand in ["/usr/bin/quorumrag", "/usr/local/bin/quorumrag"] {
            let p = Path::new(sys_cand);
            if p.is_file() {
                return Some(p.to_path_buf());
            }
        }
    }

    if let Some(path_var) = env::var_os("PATH") {
        for dir in env::split_paths(&path_var) {
            let candidate = if cfg!(windows) {
                dir.join("quorumrag.exe")
            } else {
                dir.join("quorumrag")
            };
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    None
}

fn default_user_data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(local_app) = env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local_app).join("QuorumRAG").join("data");
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("QuorumRAG")
                .join("data");
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(xdg) = env::var_os("XDG_DATA_HOME") {
            if !xdg.is_empty() {
                return PathBuf::from(xdg).join("QuorumRAG").join("data");
            }
        }
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("QuorumRAG")
                .join("data");
        }
    }
    env::temp_dir().join("QuorumRAG").join("data")
}

/// Safely removes the QuorumRAG data directory during explicit `REMOVEDATA=1` uninstall,
/// clearing any read-only file flags first while refusing non-QuorumRAG root paths.
fn remove_quorum_data_dir_safe(target: &Path) -> std::io::Result<()> {
    let file_name_ok = target
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.eq_ignore_ascii_case("QuorumRAG"))
        .unwrap_or(false);
    if !file_name_ok || target.parent().is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Refusing to remove directory whose leaf name is not 'QuorumRAG'",
        ));
    }
    if !target.exists() {
        return Ok(());
    }

    clear_readonly_recursive(target);
    std::fs::remove_dir_all(target)
}

fn clear_readonly_recursive(path: &Path) {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return;
        }
        let mut perms = meta.permissions();
        if perms.readonly() {
            perms.set_readonly(false);
            let _ = std::fs::set_permissions(path, perms);
        }
        if meta.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    clear_readonly_recursive(&entry.path());
                }
            }
        }
    }
}

fn parse_u16_flag(args: &[String], flag: &str, default_val: u16) -> u16 {
    for (idx, a) in args.iter().enumerate() {
        if a == flag {
            if let Some(val) = args.get(idx + 1) {
                if let Ok(parsed) = val.trim().parse::<u16>() {
                    if parsed > 0 {
                        return parsed;
                    }
                }
            }
        } else if let Some(rest) = a.strip_prefix(&format!("{flag}=")) {
            if let Ok(parsed) = rest.trim().parse::<u16>() {
                if parsed > 0 {
                    return parsed;
                }
            }
        }
    }
    default_val
}

fn parse_u64_flag(args: &[String], flag: &str, default_val: u64) -> u64 {
    for (idx, a) in args.iter().enumerate() {
        if a == flag {
            if let Some(val) = args.get(idx + 1) {
                if let Ok(parsed) = val.trim().parse::<u64>() {
                    return parsed;
                }
            }
        } else if let Some(rest) = a.strip_prefix(&format!("{flag}=")) {
            if let Ok(parsed) = rest.trim().parse::<u64>() {
                return parsed;
            }
        }
    }
    default_val
}

fn parse_str_flag(args: &[String], flag: &str) -> Option<String> {
    for (idx, a) in args.iter().enumerate() {
        if a == flag {
            if let Some(val) = args.get(idx + 1) {
                return Some(val.clone());
            }
        } else if let Some(rest) = a.strip_prefix(&format!("{flag}=")) {
            return Some(rest.to_string());
        }
    }
    None
}

fn run_default_desktop_launcher() -> i32 {
    let port = default_http_port();
    let url = format!("http://127.0.0.1:{port}/");

    // 1. Fast reuse guard: if local daemon already responds on `/api/health`, open UI immediately.
    if probe_daemon_health(port, 1200) {
        open_browser_native(&url);
        return 0;
    }

    // 2. Native OS service check/start (no console windows or batch wrappers).
    #[cfg(windows)]
    {
        match win_native::query_windows_service_status("QuorumRAGDaemon") {
            win_native::ServiceStateSummary::Running
            | win_native::ServiceStateSummary::StartPending => {
                let _ = wait_for_daemon_health(port, 90);
                open_browser_native(&url);
                return 0;
            }
            win_native::ServiceStateSummary::Stopped
            | win_native::ServiceStateSummary::Other(_) => {
                let _ = win_native::start_windows_service("QuorumRAGDaemon");
                if wait_for_daemon_health(port, 45) {
                    open_browser_native(&url);
                    return 0;
                }
            }
            win_native::ServiceStateSummary::NotInstalled => {}
        }
    }

    #[cfg(target_os = "macos")]
    {
        if Path::new("/Library/LaunchDaemons/dev.quorumrag.daemon.plist").exists() {
            if wait_for_daemon_health(port, 45) {
                open_browser_native(&url);
                return 0;
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let has_unit = Path::new("/lib/systemd/system/quorumrag.service").exists()
            || Path::new("/usr/lib/systemd/system/quorumrag.service").exists()
            || Path::new("/etc/systemd/system/quorumrag.service").exists();
        if has_unit && wait_for_daemon_health(port, 45) {
            open_browser_native(&url);
            return 0;
        }
    }

    // 3. Per-user / portable / drag-installed `.app` mode: spawn detached `quorumrag` background daemon.
    let Some(quorumrag_bin) = find_quorumrag_binary() else {
        open_browser_native(&url);
        return 1;
    };

    let data_dir = default_user_data_dir();
    let _ = std::fs::create_dir_all(&data_dir);

    let mut cmd = Command::new(quorumrag_bin);
    cmd.arg("--host")
        .arg("0.0.0.0")
        .arg("--port")
        .arg(port.to_string())
        .arg("--p2p-port")
        .arg(DEFAULT_P2P_PORT.to_string())
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("--no-browser")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(windows)]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    if cmd.spawn().is_ok() {
        let _ = wait_for_daemon_health(port, 60);
    }
    open_browser_native(&url);
    0
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        std::process::exit(run_default_desktop_launcher());
    }

    let first = args[0].as_str();
    match first {
        "--version" | "-V" => {
            let _ = writeln!(
                std::io::stdout(),
                "quorum-desktop {}",
                env!("CARGO_PKG_VERSION")
            );
            std::process::exit(0);
        }
        "--wait-health" => {
            let port = parse_u16_flag(&args, "--port", default_http_port());
            let timeout_secs = parse_u64_flag(&args, "--timeout-secs", 90);
            let ok = wait_for_daemon_health(port, timeout_secs);
            std::process::exit(if ok { 0 } else { 1 });
        }
        "--open-ui" => {
            #[cfg(windows)]
            {
                win_native::refresh_shell_icon_cache();
            }
            let port = parse_u16_flag(&args, "--port", default_http_port());
            let timeout_secs = parse_u64_flag(&args, "--timeout-secs", 90);
            let url = format!("http://127.0.0.1:{port}/");
            let _ = wait_for_daemon_health(port, timeout_secs);
            open_browser_native(&url);
            std::process::exit(0);
        }
        "--msi-refresh-icons" => {
            #[cfg(windows)]
            {
                win_native::refresh_shell_icon_cache();
            }
            std::process::exit(0);
        }
        "--msi-kill-orphans" => {
            #[cfg(windows)]
            {
                let _ = win_native::terminate_processes_by_name(
                    "quorumrag.exe",
                    std::process::id(),
                );
            }
            std::process::exit(0);
        }
        "--msi-stop-cleanup" => {
            #[cfg(windows)]
            {
                let delete_service = args.iter().any(|a| a == "--delete-service");
                let _ = win_native::stop_and_cleanup_windows_service(
                    "QuorumRAGDaemon",
                    delete_service,
                    Duration::from_secs(10),
                );
            }
            std::process::exit(0);
        }
        "--msi-firewall-add" => {
            #[cfg(windows)]
            {
                let http_port = parse_u16_flag(&args, "--http-port", DEFAULT_HTTP_PORT);
                let p2p_port = parse_u16_flag(&args, "--p2p-port", DEFAULT_P2P_PORT);
                let prog_path = parse_str_flag(&args, "--program")
                    .map(|s| sanitize_cli_path(&s))
                    .or_else(|| {
                        parse_str_flag(&args, "--install-dir")
                            .map(|d| sanitize_cli_path(&d).join("quorumrag.exe"))
                    });
                let _ = win_native::ensure_quorum_firewall_rules(
                    prog_path.as_deref(),
                    http_port,
                    p2p_port,
                );
            }
            std::process::exit(0);
        }
        "--msi-firewall-remove" => {
            #[cfg(windows)]
            {
                let _ = win_native::remove_quorum_firewall_rules();
            }
            std::process::exit(0);
        }
        "--msi-remove-data" => {
            if let Some(dir_raw) = parse_str_flag(&args, "--data-dir") {
                let target = sanitize_cli_path(&dir_raw);
                let _ = remove_quorum_data_dir_safe(&target);
            }
            std::process::exit(0);
        }
        _ => {
            // Forward explicit CLI flags directly to `quorumrag` without console window allocation.
            let Some(quorumrag_bin) = find_quorumrag_binary() else {
                std::process::exit(1);
            };
            let mut cmd = Command::new(quorumrag_bin);
            cmd.args(&args);
            #[cfg(windows)]
            {
                cmd.creation_flags(CREATE_NO_WINDOW);
            }
            let code = cmd
                .status()
                .ok()
                .and_then(|s| s.code())
                .unwrap_or(1);
            std::process::exit(code);
        }
    }
}
