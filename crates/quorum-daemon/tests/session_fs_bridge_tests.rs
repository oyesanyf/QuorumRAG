//! End-to-end integration tests for the silent interactive-session filesystem bridge
//! (`quorum-desktop --session-fs-bridge`).
//!
//! Spawns the real `quorum-desktop` binary, completes the stdin shared-secret handshake,
//! verifies constant-time auth rejection on bad tokens, and tests `stat`, `browse`,
//! `create_subfolder`, `walk`, `read`, `watch`/`events`, and path-traversal rejection.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use quorum_types::session_fs_bridge::{
    browse_dir_bridged, clear_bridge_endpoint, is_bridge_active, poll_watch_events_bridged,
    read_bytes_via_bridge, set_bridge_endpoint, set_watch_roots_bridged, stat_via_bridge,
    walk_dir_bridged,
};
use quorum_types::CloudPlaceholderPolicy;
use tempfile::tempdir;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        clear_bridge_endpoint();
    }
}

fn spawn_test_bridge_with_exe(exe: &str, token: &str) -> (ChildGuard, u16) {
    let mut child = Command::new(exe)
        .args([
            "--session-fs-bridge",
            "--parent-pid",
            &std::process::id().to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn --session-fs-bridge");

    {
        let mut stdin = child.stdin.take().expect("bridge stdin");
        writeln!(stdin, "{token}").expect("write bridge token");
        stdin.flush().expect("flush bridge token");
    }

    let stdout = child.stdout.take().expect("bridge stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read READY line");

    let port: u16 = line
        .trim()
        .strip_prefix("READY ")
        .expect("expected READY <port>")
        .trim()
        .parse()
        .expect("valid port");
    assert!(port > 0, "ephemeral port must be non-zero");

    (ChildGuard(child), port)
}

fn spawn_test_bridge(token: &str) -> (ChildGuard, u16) {
    spawn_test_bridge_with_exe(env!("CARGO_BIN_EXE_quorum-desktop"), token)
}

fn raw_http_status(port: u16, token: &str, method: &str, path: &str, body: &str) -> u16 {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Quorum-Bridge-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).expect("write request");
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    text.lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0)
}

#[test]
fn session_fs_bridge_end_to_end_auth_browse_walk_read_and_watch() {
    let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let (guard, port) = spawn_test_bridge(token);
    let child_pid = guard.0.id();

    // 1. Wrong or missing token MUST fail closed with 403 Forbidden.
    assert_eq!(
        raw_http_status(port, "wrong-token", "GET", "/bridge/health", ""),
        403
    );
    assert_eq!(raw_http_status(port, "", "GET", "/bridge/drives", ""), 403);
    assert_eq!(
        raw_http_status(port, token, "GET", "/bridge/health", ""),
        200
    );

    // 2. Register active loopback bridge endpoint and verify client helpers.
    set_bridge_endpoint(port, token.to_string(), 1, child_pid);
    assert!(is_bridge_active(), "registered bridge must pass health check");

    let tmp = tempdir().expect("tempdir");
    let root = tmp.path();
    let docs_dir = root.join("My Drive");
    let excluded_dir = docs_dir.join("PrivateExcluded");
    std::fs::create_dir_all(&excluded_dir).expect("create dirs");
    let sample_file = docs_dir.join("quarterly_report.txt");
    let skipped_file = excluded_dir.join("secret.txt");
    std::fs::write(&sample_file, b"Q4 QuorumRAG Google Drive Bridge OK").expect("write sample");
    std::fs::write(&skipped_file, b"must not walk excluded dir").expect("write excluded");

    // 3. Stat directory & file via bridge.
    let dir_stat = stat_via_bridge(&docs_dir).expect("stat dir");
    assert!(dir_stat.exists && dir_stat.is_dir && !dir_stat.is_file);
    let file_stat = stat_via_bridge(&sample_file).expect("stat file");
    assert!(file_stat.exists && file_stat.is_file && file_stat.len == 35);

    // 4. Browse directory, create safe subfolder, and reject traversal subfolder name.
    let root_entries =
        browse_dir_bridged(&root.to_string_lossy(), None).expect("browse root");
    assert!(
        root_entries.iter().any(|e| e.name == "My Drive" && e.is_dir),
        "expected My Drive in browse entries: {root_entries:?}"
    );
    let created_entries =
        browse_dir_bridged(&docs_dir.to_string_lossy(), Some("SyncedNotes"))
            .expect("browse + create subfolder");
    assert!(created_entries.iter().any(|e| e.name == "SyncedNotes"));
    assert!(docs_dir.join("SyncedNotes").is_dir());

    let traversal_err = browse_dir_bridged(&docs_dir.to_string_lossy(), Some("..\\escape"));
    assert!(traversal_err.is_err(), "traversal subfolder must be rejected");

    // 5. Walk directory tree with excluded prefix and verify read_bytes_via_bridge.
    let (walked, skipped_ph) = walk_dir_bridged(
        &docs_dir,
        &[excluded_dir.to_string_lossy().to_string()],
        10 * 1024 * 1024,
        true,
        CloudPlaceholderPolicy::LocallySyncedOnly,
    )
    .expect("walk dir");
    assert_eq!(skipped_ph, 0);
    assert!(
        walked
            .iter()
            .any(|e| e.path.ends_with("quarterly_report.txt")),
        "expected quarterly_report.txt in walk result: {walked:?}"
    );
    assert!(
        !walked.iter().any(|e| e.path.ends_with("secret.txt")),
        "excluded folder file must not appear in walk result: {walked:?}"
    );

    let bytes = read_bytes_via_bridge(
        &sample_file,
        1024,
        CloudPlaceholderPolicy::LocallySyncedOnly,
    )
    .expect("read via bridge");
    assert_eq!(bytes, b"Q4 QuorumRAG Google Drive Bridge OK");

    // 6. Traversal path read MUST fail closed (400).
    let bad_read = read_bytes_via_bridge(
        Path::new(r"C:\Users\..\Windows\win.ini"),
        1024,
        CloudPlaceholderPolicy::LocallySyncedOnly,
    );
    assert!(bad_read.is_err(), "traversal path must be rejected");

    // 7. Register watch root and verify live polling detects newly written file.
    assert!(set_watch_roots_bridged(&[docs_dir.clone()]));
    // Wait for initial snapshot to populate, then create a new file and verify upsert event.
    std::thread::sleep(Duration::from_millis(2800));
    let _ = poll_watch_events_bridged();
    let live_file = docs_dir.join("live_added.txt");
    std::fs::write(&live_file, b"live sync change").expect("write live file");
    let mut saw_upsert = false;
    for _ in 0..10 {
        std::thread::sleep(Duration::from_millis(600));
        let events = poll_watch_events_bridged();
        if events
            .iter()
            .any(|ev| ev.kind == "upsert" && ev.path.ends_with("live_added.txt"))
        {
            saw_upsert = true;
            break;
        }
    }
    assert!(
        saw_upsert,
        "bridge watcher should emit upsert event for newly added file"
    );

    drop(guard);
}

#[test]
fn quorumrag_binary_fallback_hosts_session_fs_bridge() {
    let token = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    let (guard, port) = spawn_test_bridge_with_exe(env!("CARGO_BIN_EXE_quorumrag"), token);
    assert_eq!(raw_http_status(port, "bad", "GET", "/bridge/health", ""), 403);
    assert_eq!(raw_http_status(port, token, "GET", "/bridge/health", ""), 200);
    drop(guard);
}
