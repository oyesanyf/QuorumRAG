//! Native Win32 & COM system integration for QuorumRAG on Windows.
//!
//! Eliminates all external CLI console tool spawns (`netsh.exe`, `sc.exe`, `taskkill.exe`,
//! `arp.exe`, `cmd.exe /c start`) during MSI installation, upgrades, uninstallation,
//! desktop shortcut launching, and background P2P mesh execution so zero DOS/console
//! windows ever flash or pop open.
//!
//! Intentionally depends ONLY on `std` and `windows` so this module can be compiled into
//! both `quorumrag` (daemon) and `quorum-desktop` (lightweight GUI-subsystem launcher &
//! MSI setup helper).

#![allow(dead_code)]

use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, Instant};

use windows::core::{w, BSTR, HRESULT, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, VARIANT_TRUE};
use windows::Win32::NetworkManagement::IpHelper::{
    GetIpNetTable, MIB_IPNETROW_LH, MIB_IPNETTABLE, MIB_IPNET_TYPE_INVALID,
};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NetFwPolicy2, NetFwRule, NET_FW_ACTION_ALLOW,
    NET_FW_IP_PROTOCOL_TCP, NET_FW_IP_PROTOCOL_UDP, NET_FW_PROFILE2_ALL, NET_FW_PROFILE2_DOMAIN,
    NET_FW_PROFILE2_PRIVATE, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, DeleteService, OpenSCManagerW, OpenServiceW,
    QueryServiceStatus, StartServiceW, SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS,
    SERVICE_STOP, SERVICE_STOPPED,
};
use windows::Win32::System::Threading::{
    OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};
use windows::Win32::UI::Shell::{
    SHChangeNotify, ShellExecuteW, SHCNE_ASSOCCHANGED, SHCNE_UPDATEDIR, SHCNF_FLUSH, SHCNF_IDLIST,
    SHCNF_PATHW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// Standard `DELETE` access right (`0x00010000`) for `OpenServiceW` -> `DeleteService`.
const ACCESS_DELETE: u32 = 0x0001_0000;

/// Win32 `ERROR_INSUFFICIENT_BUFFER` (`122`) returned by `GetIpNetTable` sizing calls.
const WIN32_ERROR_INSUFFICIENT_BUFFER: u32 = 122;

/// COM `RPC_E_CHANGED_MODE` (`0x80010106`) when thread already initialized COM in STA mode.
const COM_RPC_E_CHANGED_MODE: HRESULT = HRESULT(0x8001_0106u32 as i32);

/// Canonical and legacy Windows Firewall rule names managed by QuorumRAG.
pub const QUORUM_FIREWALL_RULE_NAMES: &[&str] = &[
    "QuorumRAG P2P Mesh (Program-In)",
    "QuorumRAG LAN Discovery (UDP 5353-In)",
    "QuorumRAG LAN Discovery (UDP 5353-Out)",
    "QuorumRAG P2P Swarm (TCP 3032-In)",
    "QuorumRAG P2P Swarm (TCP 3032-Out)",
    // Legacy rule names from <= v0.6.16 `netsh` invocations (cleaned up automatically)
    "QuorumRAG P2P Mesh",
    "QuorumRAG P2P Mesh (All Profiles)",
    "QuorumRAG LAN Ports (TCP 3031-3032)",
    "QuorumRAG LAN Ports (UDP 3032,5353)",
];

struct ComApartmentGuard {
    should_uninit: bool,
}

impl ComApartmentGuard {
    fn init() -> Result<Self, String> {
        // SAFETY: `CoInitializeEx` is thread-local and safe with `None` reserved pointer.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr.is_ok() {
            Ok(Self {
                should_uninit: true,
            })
        } else if hr == COM_RPC_E_CHANGED_MODE {
            // COM is already initialized on this thread (e.g. STA); in-proc firewall COM still works.
            Ok(Self {
                should_uninit: false,
            })
        } else {
            Err(format!("CoInitializeEx failed: 0x{:08x}", hr.0 as u32))
        }
    }
}

impl Drop for ComApartmentGuard {
    fn drop(&mut self) {
        if self.should_uninit {
            // SAFETY: Paired 1:1 with a successful `CoInitializeEx` on this thread.
            unsafe {
                CoUninitialize();
            }
        }
    }
}

struct ScHandleGuard(SC_HANDLE);

impl Drop for ScHandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `self.0` is an owned, non-null SCM/service handle.
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

fn wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Probes native COM `INetFwPolicy2::CurrentProfileTypes` without mutating system firewall state.
/// Safe to execute in unprivileged unit tests to verify COM firewall binding availability.
pub fn probe_firewall_com_policy_profiles() -> Result<i32, String> {
    let _com = ComApartmentGuard::init()?;
    // SAFETY: `NetFwPolicy2` is a standard system in-proc COM class (`hnetcfg.dll`).
    let policy: INetFwPolicy2 =
        unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| format!("CoCreateInstance(NetFwPolicy2) failed: {e}"))?;
    // SAFETY: `policy` is a valid COM interface pointer.
    unsafe { policy.CurrentProfileTypes() }
        .map_err(|e| format!("INetFwPolicy2::CurrentProfileTypes failed: {e}"))
}

struct FirewallRuleSpec<'a> {
    name: &'a str,
    description: &'a str,
    program: Option<&'a str>,
    protocol: Option<i32>,
    local_ports: Option<String>,
    remote_ports: Option<String>,
    inbound: bool,
    profiles: i32,
}

fn upsert_single_firewall_rule(rules: &INetFwRules, spec: &FirewallRuleSpec<'_>) -> Result<(), String> {
    // Remove any existing rule with the same name first so upgrades/restarts stay 100% idempotent.
    // SAFETY: `rules` is a valid `INetFwRules` COM collection; `Remove` returns S_FALSE/error if absent.
    unsafe {
        let _ = rules.Remove(&BSTR::from(spec.name));
    }

    // SAFETY: `NetFwRule` is a standard system in-proc COM class (`hnetcfg.dll`).
    let rule: INetFwRule = unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER) }
        .map_err(|e| format!("CoCreateInstance(NetFwRule) failed for '{}': {e}", spec.name))?;

    // SAFETY: All `INetFwRule` setter calls operate on owned `BSTR` values and valid enum constants.
    // Note: `SetProtocol` MUST precede `SetLocalPorts`/`SetRemotePorts` per Windows Firewall COM contract.
    unsafe {
        rule.SetName(&BSTR::from(spec.name))
            .map_err(|e| format!("SetName('{}') failed: {e}", spec.name))?;
        rule.SetDescription(&BSTR::from(spec.description))
            .map_err(|e| format!("SetDescription('{}') failed: {e}", spec.name))?;
        rule.SetGrouping(&BSTR::from("QuorumRAG"))
            .map_err(|e| format!("SetGrouping('{}') failed: {e}", spec.name))?;

        if let Some(app) = spec.program {
            if !app.is_empty() {
                rule.SetApplicationName(&BSTR::from(app))
                    .map_err(|e| format!("SetApplicationName('{}') failed: {e}", spec.name))?;
            }
        }
        if let Some(proto) = spec.protocol {
            rule.SetProtocol(proto)
                .map_err(|e| format!("SetProtocol('{}') failed: {e}", spec.name))?;
        }
        if let Some(ref lp) = spec.local_ports {
            rule.SetLocalPorts(&BSTR::from(lp.as_str()))
                .map_err(|e| format!("SetLocalPorts('{}') failed: {e}", spec.name))?;
        }
        if let Some(ref rp) = spec.remote_ports {
            rule.SetRemotePorts(&BSTR::from(rp.as_str()))
                .map_err(|e| format!("SetRemotePorts('{}') failed: {e}", spec.name))?;
        }

        rule.SetDirection(if spec.inbound {
            NET_FW_RULE_DIR_IN
        } else {
            NET_FW_RULE_DIR_OUT
        })
        .map_err(|e| format!("SetDirection('{}') failed: {e}", spec.name))?;
        rule.SetAction(NET_FW_ACTION_ALLOW)
            .map_err(|e| format!("SetAction('{}') failed: {e}", spec.name))?;
        rule.SetProfiles(spec.profiles)
            .map_err(|e| format!("SetProfiles('{}') failed: {e}", spec.name))?;
        rule.SetEnabled(VARIANT_TRUE)
            .map_err(|e| format!("SetEnabled('{}') failed: {e}", spec.name))?;

        rules
            .Add(&rule)
            .map_err(|e| format!("INetFwRules::Add('{}') failed: {e}", spec.name))?;
    }

    Ok(())
}

/// Provisions QuorumRAG Windows Firewall rules via native COM (`INetFwPolicy2` / `INetFwRule`)
/// without spawning `netsh.exe` or any console process.
pub fn ensure_quorum_firewall_rules(
    program_path: Option<&Path>,
    http_port: u16,
    p2p_port: u16,
) -> Result<usize, String> {
    let _com = ComApartmentGuard::init()?;
    // SAFETY: `NetFwPolicy2` is a system COM class in `hnetcfg.dll`.
    let policy: INetFwPolicy2 =
        unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| format!("CoCreateInstance(NetFwPolicy2) failed: {e}"))?;
    // SAFETY: `policy` is valid.
    let rules: INetFwRules = unsafe { policy.Rules() }
        .map_err(|e| format!("INetFwPolicy2::Rules failed: {e}"))?;

    // Clean up legacy rule names first so upgrades from <= v0.6.16 leave zero stale entries.
    for legacy in &[
        "QuorumRAG P2P Mesh",
        "QuorumRAG P2P Mesh (All Profiles)",
        "QuorumRAG LAN Ports (TCP 3031-3032)",
        "QuorumRAG LAN Ports (UDP 3032,5353)",
    ] {
        // SAFETY: `rules` is valid; `Remove` safely ignores missing rule names.
        unsafe {
            let _ = rules.Remove(&BSTR::from(*legacy));
        }
    }

    let program_str = program_path
        .map(|p| p.to_string_lossy().trim_matches('"').to_string())
        .filter(|s| !s.is_empty());

    let lan_profiles = NET_FW_PROFILE2_PRIVATE.0 | NET_FW_PROFILE2_DOMAIN.0;
    let tcp_in_ports = if http_port == p2p_port {
        format!("{p2p_port}")
    } else {
        format!("{http_port},{p2p_port}")
    };
    let udp_in_ports = if p2p_port == 5353 {
        "5353".to_string()
    } else {
        format!("{p2p_port},5353")
    };

    let mut specs = Vec::with_capacity(5);
    if let Some(ref prog) = program_str {
        specs.push(FirewallRuleSpec {
            name: "QuorumRAG P2P Mesh (Program-In)",
            description: "Allow QuorumRAG daemon inbound peer-to-peer mesh traffic",
            program: Some(prog.as_str()),
            protocol: None,
            local_ports: None,
            remote_ports: None,
            inbound: true,
            profiles: NET_FW_PROFILE2_ALL.0,
        });
    }
    specs.extend([
        FirewallRuleSpec {
            name: "QuorumRAG LAN Discovery (UDP 5353-In)",
            description: "Allow QuorumRAG mDNS and QUIC LAN peer discovery inbound",
            program: None,
            protocol: Some(NET_FW_IP_PROTOCOL_UDP.0),
            local_ports: Some(udp_in_ports),
            remote_ports: None,
            inbound: true,
            profiles: lan_profiles,
        },
        FirewallRuleSpec {
            name: "QuorumRAG LAN Discovery (UDP 5353-Out)",
            description: "Allow QuorumRAG mDNS LAN peer discovery outbound",
            program: None,
            protocol: Some(NET_FW_IP_PROTOCOL_UDP.0),
            local_ports: Some("5353".to_string()),
            remote_ports: None,
            inbound: false,
            profiles: lan_profiles,
        },
        FirewallRuleSpec {
            name: "QuorumRAG P2P Swarm (TCP 3032-In)",
            description: "Allow QuorumRAG HTTP/P2P LAN swarm inbound connections",
            program: None,
            protocol: Some(NET_FW_IP_PROTOCOL_TCP.0),
            local_ports: Some(tcp_in_ports),
            remote_ports: None,
            inbound: true,
            profiles: lan_profiles,
        },
        FirewallRuleSpec {
            name: "QuorumRAG P2P Swarm (TCP 3032-Out)",
            description: "Allow QuorumRAG P2P LAN swarm outbound connections",
            program: None,
            protocol: Some(NET_FW_IP_PROTOCOL_TCP.0),
            local_ports: None,
            remote_ports: Some(p2p_port.to_string()),
            inbound: false,
            profiles: lan_profiles,
        },
    ]);

    let mut applied = 0usize;
    let mut first_err: Option<String> = None;
    for spec in &specs {
        match upsert_single_firewall_rule(&rules, spec) {
            Ok(()) => applied += 1,
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }

    if applied == 0 {
        if let Some(err) = first_err {
            return Err(err);
        }
    }
    Ok(applied)
}

/// Removes all current and legacy QuorumRAG Windows Firewall rules via native COM (`INetFwPolicy2`).
pub fn remove_quorum_firewall_rules() -> Result<usize, String> {
    let _com = ComApartmentGuard::init()?;
    // SAFETY: `NetFwPolicy2` is a system COM class in `hnetcfg.dll`.
    let policy: INetFwPolicy2 =
        unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| format!("CoCreateInstance(NetFwPolicy2) failed: {e}"))?;
    // SAFETY: `policy` is valid.
    let rules: INetFwRules = unsafe { policy.Rules() }
        .map_err(|e| format!("INetFwPolicy2::Rules failed: {e}"))?;

    let mut removed = 0usize;
    for name in QUORUM_FIREWALL_RULE_NAMES {
        // Loop up to 4 times per name in case older `netsh` installs stacked duplicate entries.
        for _ in 0..4 {
            // SAFETY: `rules` is valid; `Remove` deletes one matching rule per call.
            let res = unsafe { rules.Remove(&BSTR::from(*name)) };
            if res.is_ok() {
                removed += 1;
            } else {
                break;
            }
        }
    }
    Ok(removed)
}

/// Summary of a Windows Service state queried natively via Win32 SCM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStateSummary {
    NotInstalled,
    Running,
    StartPending,
    Stopped,
    Other(u32),
}

/// Queries the current status of a Windows service via `OpenSCManagerW` + `QueryServiceStatus`
/// without spawning `sc.exe`.
pub fn query_windows_service_status(service_name: &str) -> ServiceStateSummary {
    // SAFETY: Read-only connection to the local Service Control Manager.
    let scm = match unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) } {
        Ok(h) => ScHandleGuard(h),
        Err(_) => return ServiceStateSummary::NotInstalled,
    };

    let svc_w = wide_nul(service_name);
    // SAFETY: `svc_w` is NUL-terminated UTF-16 valid for the call.
    let svc = match unsafe { OpenServiceW(scm.0, PCWSTR(svc_w.as_ptr()), SERVICE_QUERY_STATUS) } {
        Ok(h) => ScHandleGuard(h),
        Err(_) => return ServiceStateSummary::NotInstalled,
    };

    let mut status = SERVICE_STATUS::default();
    // SAFETY: `svc.0` has `SERVICE_QUERY_STATUS` access and `status` is valid writable memory.
    if unsafe { QueryServiceStatus(svc.0, &mut status) }.is_err() {
        return ServiceStateSummary::NotInstalled;
    }

    match status.dwCurrentState {
        SERVICE_RUNNING => ServiceStateSummary::Running,
        SERVICE_START_PENDING => ServiceStateSummary::StartPending,
        SERVICE_STOPPED => ServiceStateSummary::Stopped,
        other => ServiceStateSummary::Other(other.0),
    }
}

/// Starts a Windows service natively via `StartServiceW` (no `sc.exe` console spawn).
/// Returns `Ok(true)` if already running or start initiated.
pub fn start_windows_service(service_name: &str) -> Result<bool, String> {
    // SAFETY: Connects to local SCM.
    let scm = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
        .map_err(|e| format!("OpenSCManagerW failed: {e}"))?;
    let _scm_guard = ScHandleGuard(scm);

    let svc_w = wide_nul(service_name);
    // SAFETY: Opens `service_name` with `SERVICE_QUERY_STATUS | SERVICE_START`.
    let svc = unsafe {
        OpenServiceW(
            scm,
            PCWSTR(svc_w.as_ptr()),
            SERVICE_QUERY_STATUS | SERVICE_START,
        )
    }
    .map_err(|e| format!("OpenServiceW('{service_name}') failed: {e}"))?;
    let _svc_guard = ScHandleGuard(svc);

    let mut status = SERVICE_STATUS::default();
    // SAFETY: `svc` is valid.
    if unsafe { QueryServiceStatus(svc, &mut status) }.is_ok()
        && (status.dwCurrentState == SERVICE_RUNNING
            || status.dwCurrentState == SERVICE_START_PENDING)
    {
        return Ok(true);
    }

    // SAFETY: Starts service with zero extra vector arguments.
    unsafe { StartServiceW(svc, None) }
        .map(|()| true)
        .map_err(|e| format!("StartServiceW('{service_name}') failed: {e}"))
}

/// Stops a Windows service via Win32 `ControlService(SERVICE_CONTROL_STOP)`, terminates any
/// lingering `quorumrag.exe` child/orphan processes via Toolhelp32, and optionally deletes
/// the service registration (`DeleteService`) — completely replacing `cmd.exe /c sc.exe & taskkill.exe`.
pub fn stop_and_cleanup_windows_service(
    service_name: &str,
    delete_service: bool,
    stop_timeout: Duration,
) -> Result<(), String> {
    if let Ok(scm) = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) } {
        let _scm_guard = ScHandleGuard(scm);
        let svc_w = wide_nul(service_name);
        let desired = SERVICE_STOP
            | SERVICE_QUERY_STATUS
            | if delete_service { ACCESS_DELETE } else { 0 };

        // SAFETY: `svc_w` is NUL-terminated UTF-16.
        if let Ok(svc) = unsafe { OpenServiceW(scm, PCWSTR(svc_w.as_ptr()), desired) } {
            let _svc_guard = ScHandleGuard(svc);
            let mut status = SERVICE_STATUS::default();

            // SAFETY: Queries and sends `SERVICE_CONTROL_STOP` when not already stopped.
            let already_stopped = unsafe { QueryServiceStatus(svc, &mut status) }.is_ok()
                && status.dwCurrentState == SERVICE_STOPPED;

            if !already_stopped {
                unsafe {
                    let _ = ControlService(svc, SERVICE_CONTROL_STOP, &mut status);
                }
                let deadline = Instant::now() + stop_timeout;
                while Instant::now() < deadline {
                    if unsafe { QueryServiceStatus(svc, &mut status) }.is_ok()
                        && status.dwCurrentState == SERVICE_STOPPED
                    {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(150));
                }
            }

            // Ensure no orphaned `quorumrag.exe` (such as detached `watch-p2p` or hung child) holds file locks.
            let _ = terminate_processes_by_name("quorumrag.exe", std::process::id());

            if delete_service {
                // SAFETY: `svc` was opened with `ACCESS_DELETE`.
                unsafe {
                    let _ = DeleteService(svc);
                }
            }
            return Ok(());
        }
    }

    // Even if the service was not registered, clean up any orphan `quorumrag.exe` holding locks.
    let _ = terminate_processes_by_name("quorumrag.exe", std::process::id());
    Ok(())
}

/// Terminates all processes matching `exe_name` (case-insensitive, e.g. `"quorumrag.exe"`),
/// excluding `skip_pid` and system PIDs (`0`, `4`), using native Win32 Toolhelp32 + `TerminateProcess`.
pub fn terminate_processes_by_name(exe_name: &str, skip_pid: u32) -> usize {
    // SAFETY: `CreateToolhelp32Snapshot` with `TH32CS_SNAPPROCESS` takes a point-in-time process snapshot.
    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(h) => h,
        Err(_) => return 0,
    };

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut terminated = 0usize;
    // SAFETY: `entry.dwSize` is initialized to `size_of::<PROCESSENTRY32W>()`.
    let mut has_entry = unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok();
    while has_entry {
        let pid = entry.th32ProcessID;
        if pid != 0 && pid != 4 && pid != skip_pid {
            let nul_pos = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            let current_name = String::from_utf16_lossy(&entry.szExeFile[..nul_pos]);
            if current_name.eq_ignore_ascii_case(exe_name) {
                // SAFETY: Opens target PID with minimal `PROCESS_TERMINATE | PROCESS_SYNCHRONIZE` rights.
                if let Ok(proc_handle) =
                    unsafe { OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, false, pid) }
                {
                    unsafe {
                        if TerminateProcess(proc_handle, 1).is_ok() {
                            let _ = WaitForSingleObject(proc_handle, 3_000);
                            terminated += 1;
                        }
                        let _ = CloseHandle(proc_handle);
                    }
                }
            }
        }
        // SAFETY: Advances snapshot cursor.
        has_entry = unsafe { Process32NextW(snapshot, &mut entry) }.is_ok();
    }

    // SAFETY: Closes Toolhelp32 snapshot handle.
    unsafe {
        let _ = CloseHandle(snapshot);
    }
    terminated
}

/// Reads the Windows kernel IPv4 ARP neighbor table directly via `iphlpapi.dll` `GetIpNetTable`
/// in microseconds without spawning `arp.exe`.
pub fn get_windows_arp_ipv4_neighbors() -> Vec<Ipv4Addr> {
    let mut size: u32 = 0;
    // SAFETY: Sizing query (`None` buffer) populates `size` with required byte length.
    let first_rc = unsafe { GetIpNetTable(None, &mut size, false) };
    if first_rc != 0 && first_rc != WIN32_ERROR_INSUFFICIENT_BUFFER {
        return Vec::new();
    }
    if size == 0 {
        return Vec::new();
    }

    // Over-allocate slightly on 8-byte aligned boundary in case neighbor entries arrive between calls.
    let alloc_bytes = (size as usize).saturating_add(1024);
    let mut aligned_buf = vec![0u64; alloc_bytes.div_ceil(8)];
    let mut actual_size = (aligned_buf.len() * 8) as u32;
    let table_ptr = aligned_buf.as_mut_ptr() as *mut MIB_IPNETTABLE;

    // SAFETY: `table_ptr` points to 8-byte aligned writable memory of `actual_size` bytes.
    let rc = unsafe { GetIpNetTable(Some(table_ptr), &mut actual_size, false) };
    if rc != 0 {
        return Vec::new();
    }

    let header_offset = std::mem::offset_of!(MIB_IPNETTABLE, table);
    let row_size = std::mem::size_of::<MIB_IPNETROW_LH>();
    let usable_bytes = (actual_size as usize).min(aligned_buf.len() * 8);
    if usable_bytes < header_offset || row_size == 0 {
        return Vec::new();
    }

    // SAFETY: `usable_bytes >= header_offset` guarantees `dwNumEntries` is initialized.
    let reported_entries = unsafe { (*table_ptr).dwNumEntries as usize };
    let max_entries = (usable_bytes - header_offset) / row_size;
    let count = reported_entries.min(max_entries);

    // SAFETY: `count <= max_entries` guarantees all `count` rows reside within `aligned_buf`.
    let rows = unsafe { std::slice::from_raw_parts((*table_ptr).table.as_ptr(), count) };

    let mut ips = Vec::with_capacity(count);
    for row in rows {
        // SAFETY: Union fields `dwType` and `Type` are identical 32-bit integers.
        let entry_type = unsafe { row.Anonymous.Type };
        if entry_type == MIB_IPNET_TYPE_INVALID {
            continue;
        }
        // `MIB_IPNETROW_LH::dwAddr` is stored in network byte order in memory (`IN_ADDR`).
        let ip = Ipv4Addr::from(row.dwAddr.to_ne_bytes());
        if !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast() {
            ips.push(ip);
        }
    }
    ips
}

/// Opens an `http://` or `https://` URL in the user's default browser using Win32 `ShellExecuteW`
/// without ever spawning `cmd.exe /c start`.
pub fn shell_open_url(url: &str) -> Result<(), String> {
    let trimmed = url.trim();
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return Err("Refusing to pass non-HTTP(S) URI to ShellExecuteW".to_string());
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err("Refusing URI containing control characters".to_string());
    }

    let url_w = wide_nul(trimmed);
    // SAFETY: `url_w` is NUL-terminated UTF-16 validated to start with `http://` or `https://`.
    let res = unsafe {
        ShellExecuteW(
            None,
            w!("open"),
            PCWSTR(url_w.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    let code = res.0 as isize;
    if code > 32 {
        Ok(())
    } else {
        Err(format!("ShellExecuteW returned status code {code}"))
    }
}

/// Flushes the Windows Explorer shell icon cache so newly installed/upgraded Desktop and
/// Start Menu shortcuts immediately display the custom QuorumRAG icon without a reboot.
pub fn refresh_shell_icon_cache() {
    // SAFETY: `SHChangeNotify` with `SHCNE_ASSOCCHANGED | SHCNF_IDLIST` accepts null item pointers.
    unsafe {
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST | SHCNF_FLUSH, None, None);
    }

    for env_key in ["PUBLIC", "USERPROFILE"] {
        if let Some(root) = std::env::var_os(env_key) {
            let desktop = std::path::PathBuf::from(root).join("Desktop");
            if desktop.is_dir() {
                let path_w = wide_nul(&desktop.to_string_lossy());
                // SAFETY: `path_w` is a NUL-terminated UTF-16 path string matching `SHCNF_PATHW`.
                unsafe {
                    SHChangeNotify(
                        SHCNE_UPDATEDIR,
                        SHCNF_PATHW | SHCNF_FLUSH,
                        Some(path_w.as_ptr().cast()),
                        None,
                    );
                }
            }
        }
    }
}
