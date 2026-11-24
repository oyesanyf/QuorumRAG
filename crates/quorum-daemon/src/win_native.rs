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
    QueryServiceStatus, QueryServiceStatusEx, StartServiceW, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_CONTINUE_PENDING, SERVICE_CONTROL_STOP, SERVICE_PAUSED,
    SERVICE_PAUSE_PENDING, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_PROCESS,
    SERVICE_STOP, SERVICE_STOPPED, SERVICE_STOP_PENDING,
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

fn upsert_single_firewall_rule(
    rules: &INetFwRules,
    spec: &FirewallRuleSpec<'_>,
) -> Result<(), String> {
    // Remove any existing rule with the same name first so upgrades/restarts stay 100% idempotent.
    // SAFETY: `rules` is a valid `INetFwRules` COM collection; `Remove` returns S_FALSE/error if absent.
    unsafe {
        let _ = rules.Remove(&BSTR::from(spec.name));
    }

    // SAFETY: `NetFwRule` is a standard system in-proc COM class (`hnetcfg.dll`).
    let rule: INetFwRule = unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER) }
        .map_err(|e| {
            format!(
                "CoCreateInstance(NetFwRule) failed for '{}': {e}",
                spec.name
            )
        })?;

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
    let rules: INetFwRules =
        unsafe { policy.Rules() }.map_err(|e| format!("INetFwPolicy2::Rules failed: {e}"))?;

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
    let rules: INetFwRules =
        unsafe { policy.Rules() }.map_err(|e| format!("INetFwPolicy2::Rules failed: {e}"))?;

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

/// Summary of all 7 Win32 Service Control Manager states queried natively via SCM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStateSummary {
    NotInstalled,
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
    Other(u32),
}

impl ServiceStateSummary {
    pub fn from_win32_state(state: SERVICE_STATUS_CURRENT_STATE) -> Self {
        match state {
            SERVICE_STOPPED => Self::Stopped,
            SERVICE_START_PENDING => Self::StartPending,
            SERVICE_STOP_PENDING => Self::StopPending,
            SERVICE_RUNNING => Self::Running,
            SERVICE_CONTINUE_PENDING => Self::ContinuePending,
            SERVICE_PAUSE_PENDING => Self::PausePending,
            SERVICE_PAUSED => Self::Paused,
            other => Self::Other(other.0),
        }
    }
}

/// Queries `SERVICE_STATUS_PROCESS` (`dwCurrentState` + `dwProcessId`) via `QueryServiceStatusEx`.
fn query_service_status_process(svc: SC_HANDLE) -> Option<SERVICE_STATUS_PROCESS> {
    let mut ssp = SERVICE_STATUS_PROCESS::default();
    let mut bytes_needed = 0u32;
    let buf_len = std::mem::size_of::<SERVICE_STATUS_PROCESS>();
    // SAFETY: `ssp` is stack-allocated, properly aligned, and valid for `buf_len` writable bytes.
    let buf = unsafe {
        std::slice::from_raw_parts_mut(
            (&mut ssp as *mut SERVICE_STATUS_PROCESS).cast::<u8>(),
            buf_len,
        )
    };
    if unsafe { QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, Some(buf), &mut bytes_needed) }
        .is_ok()
    {
        return Some(ssp);
    }
    // Fallback to `QueryServiceStatus` if `QueryServiceStatusEx` is unavailable.
    let mut status = SERVICE_STATUS::default();
    if unsafe { QueryServiceStatus(svc, &mut status) }.is_ok() {
        ssp.dwCurrentState = status.dwCurrentState;
        return Some(ssp);
    }
    None
}

/// Queries the current status of a Windows service via `OpenSCManagerW` + `QueryServiceStatusEx`
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

    match query_service_status_process(svc.0) {
        Some(ssp) => ServiceStateSummary::from_win32_state(ssp.dwCurrentState),
        None => ServiceStateSummary::NotInstalled,
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

/// Terminates a single PID safely (excluding system PIDs 0/4 and `skip_pid`).
fn terminate_pid_safe(pid: u32, skip_pid: u32) -> bool {
    if pid == 0 || pid == 4 || pid == skip_pid {
        return false;
    }
    // SAFETY: Opens target PID with minimal `PROCESS_TERMINATE | PROCESS_SYNCHRONIZE` rights.
    if let Ok(proc_handle) =
        unsafe { OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, false, pid) }
    {
        let killed = unsafe {
            let ok = TerminateProcess(proc_handle, 0).is_ok();
            if ok {
                let _ = WaitForSingleObject(proc_handle, 3_000);
            }
            let _ = CloseHandle(proc_handle);
            ok
        };
        return killed;
    }
    false
}

/// Polls SCM until the service reaches `SERVICE_STOPPED` or `timeout` elapses.
fn wait_until_service_stopped(svc: SC_HANDLE, timeout: Duration) -> (bool, u32) {
    let deadline = Instant::now() + timeout;
    let mut last_pid = 0u32;
    loop {
        if let Some(ssp) = query_service_status_process(svc) {
            if ssp.dwProcessId != 0 {
                last_pid = ssp.dwProcessId;
            }
            if ssp.dwCurrentState == SERVICE_STOPPED {
                return (true, last_pid);
            }
        } else {
            return (true, last_pid);
        }
        if Instant::now() >= deadline {
            return (false, last_pid);
        }
        std::thread::sleep(Duration::from_millis(120));
    }
}

/// Explicitly inspects the live Win32 SCM state of `service_name` and reconciles EVERY possible
/// state (`Stopped`, `Running`, `Paused`, `StartPending`, `StopPending`, `ContinuePending`,
/// `PausePending`, `NotInstalled`, or `MarkedForDelete`) cleanly before MSI file replacement,
/// repair, upgrade, or uninstall.
///
/// Escalates to terminating the service's exact SCM `dwProcessId` plus any orphaned `quorumrag.exe`
/// (`watch-p2p`) processes if an older binary refuses to stop within `stop_timeout`, waits until
/// SCM confirms `SERVICE_STOPPED`, and (when `delete_service` is true) deletes the service and
/// waits for SCM to finish clearing the `MARKED_FOR_DELETE` tombstone.
pub fn stop_and_cleanup_windows_service(
    service_name: &str,
    delete_service: bool,
    stop_timeout: Duration,
) -> Result<(), String> {
    let self_pid = std::process::id();
    if let Ok(scm) = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) } {
        let _scm_guard = ScHandleGuard(scm);
        let svc_w = wide_nul(service_name);
        let desired =
            SERVICE_STOP | SERVICE_QUERY_STATUS | if delete_service { ACCESS_DELETE } else { 0 };

        // SAFETY: `svc_w` is NUL-terminated UTF-16.
        if let Ok(svc) = unsafe { OpenServiceW(scm, PCWSTR(svc_w.as_ptr()), desired) } {
            let mut service_pid = 0u32;
            let mut stopped = false;

            {
                let _svc_guard = ScHandleGuard(svc);
                if let Some(ssp) = query_service_status_process(svc) {
                    service_pid = ssp.dwProcessId;
                    let state = ServiceStateSummary::from_win32_state(ssp.dwCurrentState);
                    match state {
                        ServiceStateSummary::Stopped => {
                            stopped = true;
                        }
                        ServiceStateSummary::StopPending => {
                            // Service is already stopping; wait for it to finish cleanly without
                            // issuing a duplicate ControlService (which fails with ERROR_SERVICE_CANNOT_ACCEPT_CTRL).
                            let (ok, pid) = wait_until_service_stopped(svc, stop_timeout);
                            stopped = ok;
                            if pid != 0 {
                                service_pid = pid;
                            }
                        }
                        ServiceStateSummary::StartPending
                        | ServiceStateSummary::ContinuePending
                        | ServiceStateSummary::PausePending => {
                            // Pending transition cannot accept STOP immediately; wait briefly for
                            // transition to settle, then issue STOP if not already stopped.
                            let settle_deadline = Instant::now() + Duration::from_secs(3);
                            while Instant::now() < settle_deadline {
                                if let Some(cur) = query_service_status_process(svc) {
                                    if cur.dwProcessId != 0 {
                                        service_pid = cur.dwProcessId;
                                    }
                                    match ServiceStateSummary::from_win32_state(cur.dwCurrentState)
                                    {
                                        ServiceStateSummary::Stopped => {
                                            stopped = true;
                                            break;
                                        }
                                        ServiceStateSummary::Running
                                        | ServiceStateSummary::Paused => {
                                            break;
                                        }
                                        _ => {}
                                    }
                                } else {
                                    stopped = true;
                                    break;
                                }
                                std::thread::sleep(Duration::from_millis(120));
                            }
                            if !stopped {
                                let mut ctl_status = SERVICE_STATUS::default();
                                unsafe {
                                    let _ =
                                        ControlService(svc, SERVICE_CONTROL_STOP, &mut ctl_status);
                                }
                                let (ok, pid) = wait_until_service_stopped(svc, stop_timeout);
                                stopped = ok;
                                if pid != 0 {
                                    service_pid = pid;
                                }
                            }
                        }
                        ServiceStateSummary::Running
                        | ServiceStateSummary::Paused
                        | ServiceStateSummary::Other(_) => {
                            let mut ctl_status = SERVICE_STATUS::default();
                            // SAFETY: `svc` was opened with `SERVICE_STOP`.
                            unsafe {
                                let _ = ControlService(svc, SERVICE_CONTROL_STOP, &mut ctl_status);
                            }
                            let (ok, pid) = wait_until_service_stopped(svc, stop_timeout);
                            stopped = ok;
                            if pid != 0 {
                                service_pid = pid;
                            }
                        }
                        ServiceStateSummary::NotInstalled => {
                            stopped = true;
                        }
                    }
                }

                // If service failed to stop cleanly within `stop_timeout` (e.g., upgrading from an
                // older binary whose shutdown hangs), terminate its exact SCM PID + all `quorumrag.exe`
                // children and wait until SCM observes `SERVICE_STOPPED`.
                if !stopped {
                    if service_pid != 0 {
                        let _ = terminate_pid_safe(service_pid, self_pid);
                    }
                    let _ = terminate_processes_by_name("quorumrag.exe", self_pid);
                    let _ = wait_until_service_stopped(svc, Duration::from_secs(5));
                } else {
                    // Service is stopped; still reap any detached `quorumrag.exe` (`watch-p2p` or portable).
                    let _ = terminate_processes_by_name("quorumrag.exe", self_pid);
                }

                if delete_service {
                    // SAFETY: `svc` was opened with `ACCESS_DELETE`.
                    unsafe {
                        let _ = DeleteService(svc);
                    }
                }
            }
            // `_svc_guard` is now dropped (handle closed), allowing SCM to finalize deletion.
            if delete_service {
                let del_deadline = Instant::now() + Duration::from_secs(5);
                while Instant::now() < del_deadline {
                    match unsafe { OpenServiceW(scm, PCWSTR(svc_w.as_ptr()), SERVICE_QUERY_STATUS) }
                    {
                        Ok(h) => {
                            unsafe {
                                let _ = CloseServiceHandle(h);
                            }
                            std::thread::sleep(Duration::from_millis(120));
                        }
                        Err(_) => break,
                    }
                }
            }
            return Ok(());
        }
    }

    // Service is not registered (or SCM unavailable); still clean up any portable/orphan `quorumrag.exe`.
    let _ = terminate_processes_by_name("quorumrag.exe", self_pid);
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

/// Returns true when `QUORUM_CLOUD_TEST_PROFILE_DIR` is set and non-empty so host session,
/// registry, and drive-letter probes remain strictly hermetic during tests.
pub fn is_test_profile_override_active() -> bool {
    std::env::var("QUORUM_CLOUD_TEST_PROFILE_DIR")
        .ok()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

/// Pure predicate checking whether a Windows SID string is `LocalSystem` (`S-1-5-18`).
pub fn is_local_system_sid_str(sid: &str) -> bool {
    sid.trim().eq_ignore_ascii_case("S-1-5-18")
}

/// Normalizes a Windows drive-letter or folder mount hint (e.g. `"G"`, `"G:\\"`, `"G:\\My Drive"`)
/// while rejecting UNC paths, traversal, NUL, control/bidi chars, trailing `.`/space, and ADS colons.
pub fn normalize_virtual_drive_mount_hint(
    raw: &str,
    default_subdir: Option<&str>,
) -> Option<String> {
    if raw.contains('\0')
        || raw.chars().any(|c| {
            c.is_control()
                || matches!(
                    c,
                    '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}'
                )
        })
    {
        return None;
    }
    let trimmed = raw.trim_matches(' ').trim_matches('"').trim_matches(' ');
    if trimmed.is_empty()
        || trimmed.starts_with(r"\\")
        || trimmed.starts_with("//")
        || trimmed.contains("..")
    {
        return None;
    }

    let bytes = trimmed.as_bytes();
    let drive_letter = if bytes.len() == 1 && bytes[0].is_ascii_alphabetic() {
        Some(bytes[0].to_ascii_uppercase() as char)
    } else if bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        Some(bytes[0].to_ascii_uppercase() as char)
    } else if bytes.len() == 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        Some(bytes[0].to_ascii_uppercase() as char)
    } else {
        None
    };

    let candidate = if let Some(letter) = drive_letter {
        match default_subdir {
            Some(sub) if !sub.trim().is_empty() => format!("{letter}:\\{}", sub.trim()),
            _ => format!("{letter}:\\"),
        }
    } else if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        trimmed.replace('/', "\\")
    } else {
        return None;
    };

    quorum_types::validate_cloud_drive_path(&candidate).ok()
}

/// Metadata for a virtual cloud drive detected in an interactive Windows user session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InteractiveVirtualDriveHint {
    pub provider_id: String,
    pub root_path: String,
    pub account_kind: Option<String>,
    pub source: String,
}

/// Probe result from `WTSEnumerateSessionsW` + `HKEY_USERS\<SID>` virtual drive inspection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionVirtualDriveProbe {
    pub active_interactive_sessions: usize,
    pub hints: Vec<InteractiveVirtualDriveHint>,
}

/// Returns `true` when the current process token runs under Windows `LocalSystem` (`S-1-5-18`).
pub fn is_running_as_local_system() -> bool {
    use std::ffi::c_void;
    use std::ptr::null_mut;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn CloseHandle(h_object: *mut c_void) -> i32;
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(
            process_handle: *mut c_void,
            desired_access: u32,
            token_handle: *mut *mut c_void,
        ) -> i32;
        fn GetTokenInformation(
            token_handle: *mut c_void,
            token_information_class: u32,
            token_information: *mut c_void,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
        fn ConvertSidToStringSidW(sid: *mut c_void, string_sid: *mut *mut u16) -> i32;
    }

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER: u32 = 1;

    #[repr(C)]
    struct SidAndAttributes {
        sid: *mut c_void,
        attributes: u32,
    }

    struct RawHandleGuard(*mut c_void);
    impl Drop for RawHandleGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    struct LocalMemGuard(*mut u16);
    impl Drop for LocalMemGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = LocalFree(self.0.cast());
                }
            }
        }
    }

    let mut token_raw: *mut c_void = null_mut();
    // SAFETY: `GetCurrentProcess()` returns a pseudo-handle; `token_raw` receives the opened handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_raw) } == 0
        || token_raw.is_null()
    {
        return false;
    }
    let _token_guard = RawHandleGuard(token_raw);

    let mut needed: u32 = 0;
    // SAFETY: Sizing query passes `null_mut()` and length 0.
    unsafe {
        let _ = GetTokenInformation(token_raw, TOKEN_USER, null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return false;
    }

    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: `buf` is 8-byte aligned and at least `needed` bytes long.
    if unsafe {
        GetTokenInformation(
            token_raw,
            TOKEN_USER,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return false;
    }

    if (needed as usize) < std::mem::size_of::<SidAndAttributes>() {
        return false;
    }

    // SAFETY: `buf` holds a valid `TOKEN_USER` structure initialized by `GetTokenInformation`.
    let sid_ptr = unsafe { (*(buf.as_ptr() as *const SidAndAttributes)).sid };
    if sid_ptr.is_null() {
        return false;
    }

    let mut string_sid: *mut u16 = null_mut();
    // SAFETY: `sid_ptr` points inside `buf`; `ConvertSidToStringSidW` allocates `string_sid` via LocalAlloc.
    if unsafe { ConvertSidToStringSidW(sid_ptr, &mut string_sid) } == 0 || string_sid.is_null() {
        return false;
    }
    let _sid_guard = LocalMemGuard(string_sid);

    let mut len = 0usize;
    // SAFETY: `string_sid` is NUL-terminated by `ConvertSidToStringSidW`.
    unsafe {
        while *string_sid.add(len) != 0 && len < 256 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(string_sid, len);
        let sid_str = String::from_utf16_lossy(slice);
        is_local_system_sid_str(&sid_str)
    }
}

/// Returns the Windows Terminal Services session ID for the current process (`0` for Session 0 services).
pub fn current_session_id() -> Option<u32> {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcessId() -> u32;
        fn ProcessIdToSessionId(dw_process_id: u32, p_session_id: *mut u32) -> i32;
    }

    let mut session_id: u32 = 0;
    // SAFETY: `session_id` is a valid stack `u32`.
    let ok = unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id) };
    if ok != 0 {
        Some(session_id)
    } else {
        None
    }
}

/// Returns `true` when the current process is executing in Windows Session 0.
pub fn is_session_zero() -> bool {
    current_session_id() == Some(0)
}

unsafe fn read_reg_sz_raw(h_key: *mut std::ffi::c_void, value_name: &str) -> Option<String> {
    #[link(name = "advapi32")]
    extern "system" {
        fn RegQueryValueExW(
            h_key: *mut std::ffi::c_void,
            lp_value_name: *const u16,
            lp_reserved: *const u32,
            lp_type: *mut u32,
            lp_data: *mut u8,
            lpcb_data: *mut u32,
        ) -> i32;
    }

    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;

    let val_w = wide_nul(value_name);
    let mut data_type = 0u32;
    let mut data_size = 0u32;
    if RegQueryValueExW(
        h_key,
        val_w.as_ptr(),
        std::ptr::null(),
        &mut data_type,
        std::ptr::null_mut(),
        &mut data_size,
    ) != 0
        || data_size == 0
        || !matches!(data_type, REG_SZ | REG_EXPAND_SZ)
    {
        return None;
    }

    let u16_len = (data_size as usize / 2) + 1;
    let mut buf = vec![0u16; u16_len];
    if RegQueryValueExW(
        h_key,
        val_w.as_ptr(),
        std::ptr::null(),
        &mut data_type,
        buf.as_mut_ptr() as *mut u8,
        &mut data_size,
    ) != 0
        || !matches!(data_type, REG_SZ | REG_EXPAND_SZ)
    {
        return None;
    }

    let count = (data_size as usize / 2).min(buf.len());
    let slice = &buf[..count];
    let trimmed = slice
        .iter()
        .position(|&c| c == 0)
        .map(|pos| &slice[..pos])
        .unwrap_or(slice);
    let s = String::from_utf16_lossy(trimmed).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

unsafe fn read_reg_binary_raw(h_key: *mut std::ffi::c_void, value_name: &str) -> Option<Vec<u8>> {
    #[link(name = "advapi32")]
    extern "system" {
        fn RegQueryValueExW(
            h_key: *mut std::ffi::c_void,
            lp_value_name: *const u16,
            lp_reserved: *const u32,
            lp_type: *mut u32,
            lp_data: *mut u8,
            lpcb_data: *mut u32,
        ) -> i32;
    }

    const REG_BINARY: u32 = 3;
    let val_w = wide_nul(value_name);
    let mut reg_type: u32 = 0;
    let mut byte_len: u32 = 0;
    let status = RegQueryValueExW(
        h_key,
        val_w.as_ptr(),
        std::ptr::null(),
        &mut reg_type,
        std::ptr::null_mut(),
        &mut byte_len,
    );
    if status != 0 || reg_type != REG_BINARY || byte_len == 0 || byte_len > 65_536 {
        return None;
    }
    let mut buf = vec![0u8; byte_len as usize];
    let status2 = RegQueryValueExW(
        h_key,
        val_w.as_ptr(),
        std::ptr::null(),
        &mut reg_type,
        buf.as_mut_ptr(),
        &mut byte_len,
    );
    if status2 != 0 {
        return None;
    }
    buf.truncate(byte_len as usize);
    Some(buf)
}

/// Extracts a Google Drive File Stream virtual drive letter (e.g. `G:` -> `G:\My Drive`)
/// from Google Drive for Desktop v134+ `HKCU\Software\Google\DriveFS\Share\SyncTargets`
/// protobuf blobs where the mount drive letter is stored as a length-delimited 2-byte field
/// (`[0x02, b'G', b':']`) rather than legacy `MountPoint`/`DefaultMountPoint` string values.
fn extract_drivefs_mount_from_sync_targets(raw: &[u8]) -> Option<String> {
    for idx in 0..raw.len().saturating_sub(2) {
        if raw[idx] == 2 && raw[idx + 2] == b':' {
            let letter = raw[idx + 1];
            if letter.is_ascii_alphabetic() {
                let upper = (letter as char).to_ascii_uppercase();
                if upper != 'C' {
                    return normalize_virtual_drive_mount_hint(
                        &format!("{upper}:"),
                        Some("My Drive"),
                    );
                }
            }
        }
    }
    None
}

unsafe fn enum_reg_subkeys_raw(h_key: *mut std::ffi::c_void) -> Vec<String> {
    #[link(name = "advapi32")]
    extern "system" {
        fn RegEnumKeyExW(
            h_key: *mut std::ffi::c_void,
            dw_index: u32,
            lp_name: *mut u16,
            lpcch_name: *mut u32,
            lp_reserved: *mut u32,
            lp_class: *mut u16,
            lpcch_class: *mut u32,
            lpft_last_write_time: *mut std::ffi::c_void,
        ) -> i32;
    }

    let mut out = Vec::new();
    let mut idx = 0u32;
    let mut name_buf = [0u16; 256];
    loop {
        let mut name_len = name_buf.len() as u32;
        let status = RegEnumKeyExW(
            h_key,
            idx,
            name_buf.as_mut_ptr(),
            &mut name_len,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        if status != 0 {
            break;
        }
        idx += 1;
        out.push(String::from_utf16_lossy(&name_buf[..name_len as usize]));
    }
    out
}

/// Returns usernames for active/connected interactive Windows Terminal Services sessions
/// (`WTSActive` first, then `WTSConnected`, then `WTSDisconnected`, excluding Session 0).
///
/// Allows Session-0 `LocalSystem` services to prioritize the actually logged-in user's
/// `C:\Users\<username>` profile in folder pickers and Quick Access shortcuts instead of
/// falling back to the first alphabetical folder under `C:\Users`.
pub fn active_interactive_session_usernames() -> Vec<String> {
    use std::ffi::c_void;
    use std::ptr::null_mut;

    if is_test_profile_override_active() {
        return Vec::new();
    }

    #[repr(C)]
    struct WtsSessionInfoW {
        session_id: u32,
        win_station_name: *mut u16,
        state: u32,
    }

    #[link(name = "wtsapi32")]
    extern "system" {
        fn WTSEnumerateSessionsW(
            h_server: *mut c_void,
            reserved: u32,
            version: u32,
            pp_session_info: *mut *mut WtsSessionInfoW,
            p_count: *mut u32,
        ) -> i32;
        fn WTSQuerySessionInformationW(
            h_server: *mut c_void,
            session_id: u32,
            wts_info_class: u32,
            pp_buffer: *mut *mut u16,
            p_bytes_returned: *mut u32,
        ) -> i32;
        fn WTSFreeMemory(p_memory: *mut c_void);
    }

    struct WtsMemGuard(*mut c_void);
    impl Drop for WtsMemGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    WTSFreeMemory(self.0);
                }
            }
        }
    }

    const WTS_ACTIVE: u32 = 0;
    const WTS_CONNECTED: u32 = 1;
    const WTS_DISCONNECTED: u32 = 4;
    const WTS_USER_NAME: u32 = 5;

    let mut ranked: Vec<(u8, String)> = Vec::new();
    let mut sessions_ptr: *mut WtsSessionInfoW = null_mut();
    let mut session_count: u32 = 0;
    // SAFETY: `WTSEnumerateSessionsW` allocates `sessions_ptr` freed by `WtsMemGuard`.
    if unsafe { WTSEnumerateSessionsW(null_mut(), 0, 1, &mut sessions_ptr, &mut session_count) }
        != 0
        && !sessions_ptr.is_null()
    {
        let _guard = WtsMemGuard(sessions_ptr.cast());
        // SAFETY: `session_count` entries reside at `sessions_ptr`.
        let entries = unsafe { std::slice::from_raw_parts(sessions_ptr, session_count as usize) };
        for s in entries {
            let prio = match s.state {
                WTS_ACTIVE if s.session_id > 0 => 0u8,
                WTS_CONNECTED if s.session_id > 0 => 1u8,
                WTS_DISCONNECTED if s.session_id > 0 => 2u8,
                _ => continue,
            };
            let mut user_ptr: *mut u16 = null_mut();
            let mut bytes_ret: u32 = 0;
            if unsafe {
                WTSQuerySessionInformationW(
                    null_mut(),
                    s.session_id,
                    WTS_USER_NAME,
                    &mut user_ptr,
                    &mut bytes_ret,
                )
            } != 0
                && !user_ptr.is_null()
            {
                let _user_guard = WtsMemGuard(user_ptr.cast());
                let max_u16 = (bytes_ret as usize) / 2;
                let slice = unsafe { std::slice::from_raw_parts(user_ptr, max_u16) };
                let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
                let username = String::from_utf16_lossy(&slice[..end]).trim().to_string();
                if !username.is_empty() {
                    ranked.push((prio, username));
                }
            }
        }
    }

    ranked.sort_by_key(|(prio, _)| *prio);
    let mut out = Vec::new();
    for (_, user) in ranked {
        if !out.iter().any(|u: &String| u.eq_ignore_ascii_case(&user)) {
            out.push(user);
        }
    }
    out
}

/// Returns `true` when any process whose executable name matches `exe_names` (case-insensitive)
/// is actively running inside an interactive Windows user session (`SessionId > 0`).
///
/// Prevents Session-0 `LocalSystem` services from fabricating `session_only` virtual drive hints
/// (such as `G:\My Drive` or `P:\`) from stale registry keys when the cloud sync client is not
/// actually running.
pub fn is_process_running_in_interactive_session(exe_names: &[&str]) -> bool {
    if exe_names.is_empty() || is_test_profile_override_active() {
        return false;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn ProcessIdToSessionId(dw_process_id: u32, p_session_id: *mut u32) -> i32;
    }

    // SAFETY: `CreateToolhelp32Snapshot` with `TH32CS_SNAPPROCESS` takes a point-in-time process snapshot.
    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(h) => h,
        Err(_) => return false,
    };

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut found = false;
    // SAFETY: `entry.dwSize` is initialized to `size_of::<PROCESSENTRY32W>()`.
    let mut has_entry = unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok();
    while has_entry {
        let pid = entry.th32ProcessID;
        if pid != 0 && pid != 4 {
            let nul_pos = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            let current_name = String::from_utf16_lossy(&entry.szExeFile[..nul_pos]);
            if exe_names
                .iter()
                .any(|target| current_name.eq_ignore_ascii_case(target))
            {
                let mut sid: u32 = 0;
                // SAFETY: `sid` is a valid stack `u32`.
                if unsafe { ProcessIdToSessionId(pid, &mut sid) } != 0 && sid > 0 {
                    found = true;
                    break;
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
    found
}

/// Detects active interactive user sessions (`WTSEnumerateSessionsW`) and per-user virtual
/// stream drive registrations (`HKEY_USERS\<SID>\Software\Google\DriveFS*`, `pCloud`, `Network\*`).
///
/// Virtual-drive hints are only emitted when the corresponding cloud client process is actually
/// running inside an interactive user session (`SessionId > 0`), avoiding phantom `G:\My Drive`
/// or `P:\` hints when the client is closed or uninstalled.
///
/// Immediately returns an empty probe when `QUORUM_CLOUD_TEST_PROFILE_DIR` is active.
pub fn detect_interactive_session_virtual_drives() -> SessionVirtualDriveProbe {
    use std::ffi::c_void;
    use std::ptr::null_mut;

    if is_test_profile_override_active() {
        return SessionVirtualDriveProbe::default();
    }

    #[repr(C)]
    struct WtsSessionInfoW {
        session_id: u32,
        win_station_name: *mut u16,
        state: u32,
    }

    #[link(name = "wtsapi32")]
    extern "system" {
        fn WTSEnumerateSessionsW(
            h_server: *mut c_void,
            reserved: u32,
            version: u32,
            pp_session_info: *mut *mut WtsSessionInfoW,
            p_count: *mut u32,
        ) -> i32;
        fn WTSQuerySessionInformationW(
            h_server: *mut c_void,
            session_id: u32,
            wts_info_class: u32,
            pp_buffer: *mut *mut u16,
            p_bytes_returned: *mut u32,
        ) -> i32;
        fn WTSFreeMemory(p_memory: *mut c_void);
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            h_key: *mut c_void,
            lp_sub_key: *const u16,
            ul_options: u32,
            sam_desired: u32,
            phk_result: *mut *mut c_void,
        ) -> i32;
        fn RegCloseKey(h_key: *mut c_void) -> i32;
    }

    struct WtsMemGuard(*mut c_void);
    impl Drop for WtsMemGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    WTSFreeMemory(self.0);
                }
            }
        }
    }

    const WTS_ACTIVE: u32 = 0;
    const WTS_CONNECTED: u32 = 1;
    const WTS_DISCONNECTED: u32 = 4;
    const WTS_USER_NAME: u32 = 5;
    const HKEY_USERS: *mut c_void = 0x8000_0003u32 as usize as *mut c_void;
    const KEY_READ: u32 = 0x20019;

    let mut probe = SessionVirtualDriveProbe::default();

    let mut sessions_ptr: *mut WtsSessionInfoW = null_mut();
    let mut session_count: u32 = 0;
    // SAFETY: `WTSEnumerateSessionsW` allocates `sessions_ptr` which is freed by `WtsMemGuard`.
    if unsafe { WTSEnumerateSessionsW(null_mut(), 0, 1, &mut sessions_ptr, &mut session_count) }
        != 0
        && !sessions_ptr.is_null()
    {
        let _guard = WtsMemGuard(sessions_ptr.cast());
        // SAFETY: `session_count` entries are allocated at `sessions_ptr`.
        let entries = unsafe { std::slice::from_raw_parts(sessions_ptr, session_count as usize) };
        for s in entries {
            if s.session_id == 0
                || !matches!(s.state, WTS_ACTIVE | WTS_CONNECTED | WTS_DISCONNECTED)
            {
                continue;
            }
            let mut user_ptr: *mut u16 = null_mut();
            let mut bytes_ret: u32 = 0;
            if unsafe {
                WTSQuerySessionInformationW(
                    null_mut(),
                    s.session_id,
                    WTS_USER_NAME,
                    &mut user_ptr,
                    &mut bytes_ret,
                )
            } != 0
                && !user_ptr.is_null()
            {
                let _user_guard = WtsMemGuard(user_ptr.cast());
                let max_u16 = (bytes_ret as usize) / 2;
                let slice = unsafe { std::slice::from_raw_parts(user_ptr, max_u16) };
                let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
                let username = String::from_utf16_lossy(&slice[..end]);
                if !username.trim().is_empty() {
                    probe.active_interactive_sessions += 1;
                }
            }
        }
    }

    let mut push_hint = |hint: InteractiveVirtualDriveHint| {
        if !probe.hints.iter().any(|h| {
            h.provider_id == hint.provider_id && h.root_path.eq_ignore_ascii_case(&hint.root_path)
        }) {
            probe.hints.push(hint);
        }
    };

    let google_drive_running = is_process_running_in_interactive_session(&[
        "GoogleDriveFS.exe",
        "googledrivesync.exe",
    ]);
    let pcloud_running = is_process_running_in_interactive_session(&[
        "pCloud.exe",
        "pCloud Drive.exe",
        "pCloudDrive.exe",
    ]);

    unsafe {
        let empty_w = [0u16];
        let mut h_users: *mut c_void = null_mut();
        if RegOpenKeyExW(HKEY_USERS, empty_w.as_ptr(), 0, KEY_READ, &mut h_users) == 0
            && !h_users.is_null()
        {
            for sid in enum_reg_subkeys_raw(h_users) {
                let lower = sid.to_ascii_lowercase();
                if lower == ".default"
                    || lower.ends_with("_classes")
                    || lower.starts_with("s-1-5-18")
                    || lower.starts_with("s-1-5-19")
                    || lower.starts_with("s-1-5-20")
                {
                    continue;
                }

                // 1. Google Drive for Desktop (`Software\Google\DriveFS\Share` & `DriveFS`)
                // Only emit a Session-Only virtual drive hint when GoogleDriveFS is actively
                // running in an interactive session — stale registry keys when closed must NOT
                // fabricate a non-existent `G:\My Drive` path.
                if google_drive_running {
                    let share_sub = wide_nul(&format!(r"{sid}\Software\Google\DriveFS\Share"));
                    let mut h_share: *mut c_void = null_mut();
                    if RegOpenKeyExW(HKEY_USERS, share_sub.as_ptr(), 0, KEY_READ, &mut h_share) == 0
                        && !h_share.is_null()
                    {
                        if let Some(mp) = read_reg_sz_raw(h_share, "MountPoint")
                            .and_then(|v| normalize_virtual_drive_mount_hint(&v, Some("My Drive")))
                            .or_else(|| {
                                read_reg_binary_raw(h_share, "SyncTargets")
                                    .and_then(|b| extract_drivefs_mount_from_sync_targets(&b))
                            })
                        {
                            push_hint(InteractiveVirtualDriveHint {
                                provider_id: "google_drive".to_string(),
                                root_path: mp,
                                account_kind: None,
                                source: format!(r"HKU\{sid}\Software\Google\DriveFS\Share"),
                            });
                        }
                        RegCloseKey(h_share);
                    }

                    let dfs_sub = wide_nul(&format!(r"{sid}\Software\Google\DriveFS"));
                    let mut h_dfs: *mut c_void = null_mut();
                    if RegOpenKeyExW(HKEY_USERS, dfs_sub.as_ptr(), 0, KEY_READ, &mut h_dfs) == 0
                        && !h_dfs.is_null()
                    {
                        if let Some(mp) = read_reg_sz_raw(h_dfs, "DefaultMountPoint")
                            .or_else(|| read_reg_sz_raw(h_dfs, "MountPoint"))
                            .and_then(|v| normalize_virtual_drive_mount_hint(&v, Some("My Drive")))
                        {
                            push_hint(InteractiveVirtualDriveHint {
                                provider_id: "google_drive".to_string(),
                                root_path: mp,
                                account_kind: None,
                                source: format!(r"HKU\{sid}\Software\Google\DriveFS"),
                            });
                        }
                        RegCloseKey(h_dfs);
                    }
                }

                // 2. pCloud Drive (`Software\pCloud`) — only when pCloud is actually running
                if pcloud_running {
                    for pcloud_key in [
                        format!(r"{sid}\Software\pCloud\pCloud Drive"),
                        format!(r"{sid}\Software\pCloud"),
                    ] {
                        let pc_w = wide_nul(&pcloud_key);
                        let mut h_pc: *mut c_void = null_mut();
                        if RegOpenKeyExW(HKEY_USERS, pc_w.as_ptr(), 0, KEY_READ, &mut h_pc) == 0
                            && !h_pc.is_null()
                        {
                            if let Some(mp) = read_reg_sz_raw(h_pc, "MountPoint")
                                .or_else(|| read_reg_sz_raw(h_pc, "mount_point"))
                                .or_else(|| read_reg_sz_raw(h_pc, "drive_letter"))
                                .and_then(|v| normalize_virtual_drive_mount_hint(&v, None))
                            {
                                push_hint(InteractiveVirtualDriveHint {
                                    provider_id: "pcloud".to_string(),
                                    root_path: mp,
                                    account_kind: None,
                                    source: format!(r"HKU\{pcloud_key}"),
                                });
                            }
                            RegCloseKey(h_pc);
                        }
                    }
                }

                // 3. Per-user mapped network drives (`HKU\<SID>\Network\*`)
                let net_sub = wide_nul(&format!(r"{sid}\Network"));
                let mut h_net: *mut c_void = null_mut();
                if RegOpenKeyExW(HKEY_USERS, net_sub.as_ptr(), 0, KEY_READ, &mut h_net) == 0
                    && !h_net.is_null()
                {
                    for letter in enum_reg_subkeys_raw(h_net) {
                        let letter_w = wide_nul(&letter);
                        let mut h_drive: *mut c_void = null_mut();
                        if RegOpenKeyExW(h_net, letter_w.as_ptr(), 0, KEY_READ, &mut h_drive) == 0
                            && !h_drive.is_null()
                        {
                            if let Some(remote) = read_reg_sz_raw(h_drive, "RemotePath") {
                                let rem_lower = remote.to_ascii_lowercase();
                                if google_drive_running
                                    && (rem_lower.contains("googledrive")
                                        || rem_lower.contains("drivefs"))
                                {
                                    if let Some(mp) = normalize_virtual_drive_mount_hint(
                                        &letter,
                                        Some("My Drive"),
                                    ) {
                                        push_hint(InteractiveVirtualDriveHint {
                                            provider_id: "google_drive".to_string(),
                                            root_path: mp,
                                            account_kind: None,
                                            source: format!(r"HKU\{sid}\Network\{letter}"),
                                        });
                                    }
                                } else if pcloud_running && rem_lower.contains("pcloud") {
                                    if let Some(mp) =
                                        normalize_virtual_drive_mount_hint(&letter, None)
                                    {
                                        push_hint(InteractiveVirtualDriveHint {
                                            provider_id: "pcloud".to_string(),
                                            root_path: mp,
                                            account_kind: None,
                                            source: format!(r"HKU\{sid}\Network\{letter}"),
                                        });
                                    }
                                }
                            }
                            RegCloseKey(h_drive);
                        }
                    }
                    RegCloseKey(h_net);
                }
            }
            RegCloseKey(h_users);
        }
    }

    probe
}

/// Probes virtual drives mounted in the current interactive user session (`HKCU` + drive letters
/// such as `G:\My Drive` / `P:\`) for `quorum-desktop.exe --cloud-drive-relay`.
pub fn probe_current_user_virtual_drives() -> Vec<InteractiveVirtualDriveHint> {
    use std::ffi::c_void;
    use std::ptr::null_mut;

    if is_test_profile_override_active() {
        return Vec::new();
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            h_key: *mut c_void,
            lp_sub_key: *const u16,
            ul_options: u32,
            sam_desired: u32,
            phk_result: *mut *mut c_void,
        ) -> i32;
        fn RegCloseKey(h_key: *mut c_void) -> i32;
    }

    const HKEY_CURRENT_USER: *mut c_void = 0x8000_0001u32 as usize as *mut c_void;
    const KEY_READ: u32 = 0x20019;

    let mut candidates: Vec<(String, String, String)> = Vec::new();

    unsafe {
        for (sub, val, subdir, prov_id, src) in [
            (
                r"Software\Google\DriveFS\Share",
                "MountPoint",
                Some("My Drive"),
                "google_drive",
                r"HKCU\Software\Google\DriveFS\Share",
            ),
            (
                r"Software\Google\DriveFS",
                "DefaultMountPoint",
                Some("My Drive"),
                "google_drive",
                r"HKCU\Software\Google\DriveFS",
            ),
            (
                r"Software\pCloud\pCloud Drive",
                "MountPoint",
                None,
                "pcloud",
                r"HKCU\Software\pCloud\pCloud Drive",
            ),
            (
                r"Software\pCloud",
                "drive_letter",
                None,
                "pcloud",
                r"HKCU\Software\pCloud",
            ),
        ] {
            let sub_w = wide_nul(sub);
            let mut h_key: *mut c_void = null_mut();
            if RegOpenKeyExW(HKEY_CURRENT_USER, sub_w.as_ptr(), 0, KEY_READ, &mut h_key) == 0
                && !h_key.is_null()
            {
                if let Some(mp) = read_reg_sz_raw(h_key, val)
                    .and_then(|v| normalize_virtual_drive_mount_hint(&v, subdir))
                {
                    candidates.push((prov_id.to_string(), mp, src.to_string()));
                }
                RegCloseKey(h_key);
            }
        }
    }

    // Scan all mounted drive letters D:\..Z:\ in the current user session for Google Drive and pCloud
    // virtual mounts (handles custom drive letters beyond G:\ and P:\).
    #[link(name = "kernel32")]
    extern "system" {
        fn GetDriveTypeW(lp_root_path_name: *const u16) -> u32;
        fn GetVolumeInformationW(
            lp_root_path_name: *const u16,
            lp_volume_name_buffer: *mut u16,
            n_volume_name_size: u32,
            lp_volume_serial_number: *mut u32,
            lp_maximum_component_length: *mut u32,
            lp_file_system_flags: *mut u32,
            lp_file_system_name_buffer: *mut u16,
            n_file_system_name_size: u32,
        ) -> i32;
    }
    const DRIVE_UNKNOWN: u32 = 0;
    const DRIVE_NO_ROOT_DIR: u32 = 1;
    for letter in b'D'..=b'Z' {
        let ch = letter as char;
        let root_str = format!("{ch}:\\");
        let root_w = wide_nul(&root_str);
        // SAFETY: `root_w` is NUL-terminated UTF-16.
        let dt = unsafe { GetDriveTypeW(root_w.as_ptr()) };
        if dt == DRIVE_UNKNOWN || dt == DRIVE_NO_ROOT_DIR {
            continue;
        }
        let mut vol_buf = [0u16; 261];
        let mut fs_buf = [0u16; 261];
        // SAFETY: Valid writable stack buffers sized by `.len()`.
        let vol_ok = unsafe {
            GetVolumeInformationW(
                root_w.as_ptr(),
                vol_buf.as_mut_ptr(),
                vol_buf.len() as u32,
                null_mut(),
                null_mut(),
                null_mut(),
                fs_buf.as_mut_ptr(),
                fs_buf.len() as u32,
            )
        };
        let vol_label = if vol_ok != 0 {
            let vlen = vol_buf.iter().position(|&c| c == 0).unwrap_or(0);
            String::from_utf16_lossy(&vol_buf[..vlen]).to_ascii_lowercase()
        } else {
            String::new()
        };
        if vol_label.contains("google drive") {
            candidates.push((
                "google_drive".to_string(),
                format!("{ch}:\\My Drive"),
                "drive_letter_probe".to_string(),
            ));
            candidates.push((
                "google_drive".to_string(),
                format!("{ch}:\\Shared drives"),
                "drive_letter_probe".to_string(),
            ));
        } else if vol_label.contains("pcloud") {
            candidates.push((
                "pcloud".to_string(),
                root_str,
                "drive_letter_probe".to_string(),
            ));
        }
    }

    for (prov_id, fallback_path, src) in [
        ("google_drive", r"G:\My Drive", "drive_letter_probe"),
        ("google_drive", r"G:\Shared drives", "drive_letter_probe"),
        ("pcloud", r"P:\", "drive_letter_probe"),
    ] {
        candidates.push((
            prov_id.to_string(),
            fallback_path.to_string(),
            src.to_string(),
        ));
    }

    let mut out: Vec<InteractiveVirtualDriveHint> = Vec::new();
    for (prov_id, path_str, src) in candidates {
        let p = Path::new(&path_str);
        if p.is_dir() && std::fs::read_dir(p).is_ok() {
            if !out
                .iter()
                .any(|h| h.provider_id == prov_id && h.root_path.eq_ignore_ascii_case(&path_str))
            {
                out.push(InteractiveVirtualDriveHint {
                    provider_id: prov_id,
                    root_path: path_str,
                    account_kind: None,
                    source: src,
                });
            }
        }
    }
    out
}

/// Spawns `quorum-desktop.exe --session-fs-bridge --parent-pid <pid>` silently inside the active
/// interactive desktop user session (Session >= 1) from a `LocalSystem` Windows service (Session 0),
/// using `WTSQueryUserToken` (+ UAC `TokenLinkedToken` resolution so the bridge runs in the exact
/// unelevated logon session that hosts Google Drive Dokan / WinFSP mounts like `G:\`) and
/// `CreateProcessAsUserW`.
///
/// The 256-bit shared authentication token is passed strictly via an anonymous stdin pipe (never
/// in CLI arguments or disk). Returns `(loopback_port, session_id, child_pid)` on success.
pub fn spawn_session_fs_bridge(
    desktop_exe: &Path,
    token: &str,
) -> Result<(u16, u32, u32), String> {
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};

    if is_test_profile_override_active() {
        return Err("test profile override active".to_string());
    }
    if !desktop_exe.is_file() {
        return Err(format!(
            "quorum-desktop binary not found at {}",
            desktop_exe.display()
        ));
    }

    #[repr(C)]
    struct WtsSessionInfoW {
        session_id: u32,
        win_station_name: *mut u16,
        state: u32,
    }

    #[repr(C)]
    struct SecurityAttributes {
        n_length: u32,
        lp_security_descriptor: *mut c_void,
        b_inherit_handle: i32,
    }

    #[repr(C)]
    struct StartupInfoW {
        cb: u32,
        lp_reserved: *mut u16,
        lp_desktop: *mut u16,
        lp_title: *mut u16,
        dw_x: u32,
        dw_y: u32,
        dw_x_size: u32,
        dw_y_size: u32,
        dw_x_count_chars: u32,
        dw_y_count_chars: u32,
        dw_fill_attribute: u32,
        dw_flags: u32,
        w_show_window: u16,
        cb_reserved2: u16,
        lp_reserved2: *mut u8,
        h_std_input: *mut c_void,
        h_std_output: *mut c_void,
        h_std_error: *mut c_void,
    }

    #[repr(C)]
    struct ProcessInformation {
        h_process: *mut c_void,
        h_thread: *mut c_void,
        dw_process_id: u32,
        dw_thread_id: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn WTSGetActiveConsoleSessionId() -> u32;
        fn CloseHandle(h_object: *mut c_void) -> i32;
        fn CreatePipe(
            h_read_pipe: *mut *mut c_void,
            h_write_pipe: *mut *mut c_void,
            lp_pipe_attributes: *const SecurityAttributes,
            n_size: u32,
        ) -> i32;
        fn SetHandleInformation(h_object: *mut c_void, dw_mask: u32, dw_flags: u32) -> i32;
        fn WriteFile(
            h_file: *mut c_void,
            lp_buffer: *const u8,
            n_number_of_bytes_to_write: u32,
            lp_number_of_bytes_written: *mut u32,
            lp_overlapped: *mut c_void,
        ) -> i32;
        fn PeekNamedPipe(
            h_named_pipe: *mut c_void,
            lp_buffer: *mut u8,
            n_buffer_size: u32,
            lp_bytes_read: *mut u32,
            lp_total_bytes_avail: *mut u32,
            lp_bytes_left_this_message: *mut u32,
        ) -> i32;
        fn ReadFile(
            h_file: *mut c_void,
            lp_buffer: *mut u8,
            n_number_of_bytes_to_read: u32,
            lp_number_of_bytes_read: *mut u32,
            lp_overlapped: *mut c_void,
        ) -> i32;
        fn GetLastError() -> u32;
        fn TerminateProcess(h_process: *mut c_void, u_exit_code: u32) -> i32;
    }

    #[link(name = "wtsapi32")]
    extern "system" {
        fn WTSEnumerateSessionsW(
            h_server: *mut c_void,
            reserved: u32,
            version: u32,
            pp_session_info: *mut *mut WtsSessionInfoW,
            p_count: *mut u32,
        ) -> i32;
        fn WTSQueryUserToken(session_id: u32, ph_token: *mut *mut c_void) -> i32;
        fn WTSFreeMemory(p_memory: *mut c_void);
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn GetTokenInformation(
            token_handle: *mut c_void,
            token_information_class: u32,
            token_information: *mut c_void,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
        fn DuplicateTokenEx(
            h_existing_token: *mut c_void,
            dw_desired_access: u32,
            lp_token_attributes: *const c_void,
            impersonation_level: u32,
            token_type: u32,
            ph_new_token: *mut *mut c_void,
        ) -> i32;
        fn CreateProcessAsUserW(
            h_token: *mut c_void,
            lp_application_name: *const u16,
            lp_command_line: *mut u16,
            lp_process_attributes: *const c_void,
            lp_thread_attributes: *const c_void,
            b_inherit_handles: i32,
            dw_creation_flags: u32,
            lp_environment: *const c_void,
            lp_current_directory: *const u16,
            lp_startup_info: *const StartupInfoW,
            lp_process_information: *mut ProcessInformation,
        ) -> i32;
    }

    #[link(name = "userenv")]
    extern "system" {
        fn CreateEnvironmentBlock(
            lp_environment: *mut *mut c_void,
            h_token: *mut c_void,
            b_inherit: i32,
        ) -> i32;
        fn DestroyEnvironmentBlock(lp_environment: *mut c_void) -> i32;
    }

    struct RawHandleGuard(*mut c_void);
    impl Drop for RawHandleGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    struct EnvBlockGuard(*mut c_void);
    impl Drop for EnvBlockGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    DestroyEnvironmentBlock(self.0);
                }
            }
        }
    }

    struct WtsMemGuard(*mut c_void);
    impl Drop for WtsMemGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    WTSFreeMemory(self.0);
                }
            }
        }
    }

    const WTS_ACTIVE: u32 = 0;
    const WTS_CONNECTED: u32 = 1;
    const TOKEN_ELEVATION_TYPE: u32 = 18;
    const TOKEN_LINKED_TOKEN: u32 = 19;
    const TOKEN_ELEVATION_TYPE_FULL: u32 = 2;
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    const SECURITY_IMPERSONATION: u32 = 2;
    const TOKEN_PRIMARY: u32 = 1;
    const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
    const STARTF_USESTDHANDLES: u32 = 0x0000_0100;
    const STARTF_USESHOWWINDOW: u32 = 0x0000_0001;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;

    let mut candidate_sessions: Vec<u32> = Vec::new();
    let active_console = unsafe { WTSGetActiveConsoleSessionId() };
    if active_console != 0 && active_console != u32::MAX {
        candidate_sessions.push(active_console);
    }

    let mut sessions_ptr: *mut WtsSessionInfoW = null_mut();
    let mut session_count: u32 = 0;
    if unsafe { WTSEnumerateSessionsW(null_mut(), 0, 1, &mut sessions_ptr, &mut session_count) }
        != 0
        && !sessions_ptr.is_null()
    {
        let _guard = WtsMemGuard(sessions_ptr.cast());
        let entries = unsafe { std::slice::from_raw_parts(sessions_ptr, session_count as usize) };
        for s in entries {
            if s.session_id != 0
                && matches!(s.state, WTS_ACTIVE | WTS_CONNECTED)
                && !candidate_sessions.contains(&s.session_id)
            {
                candidate_sessions.push(s.session_id);
            }
        }
    }

    if candidate_sessions.is_empty() {
        return Err("no active interactive Windows user session found".to_string());
    }

    let mut chosen_session: u32 = 0;
    let mut raw_user_token: *mut c_void = null_mut();
    for sid in candidate_sessions {
        let mut h_tok: *mut c_void = null_mut();
        if unsafe { WTSQueryUserToken(sid, &mut h_tok) } != 0 && !h_tok.is_null() {
            chosen_session = sid;
            raw_user_token = h_tok;
            break;
        }
    }
    if raw_user_token.is_null() {
        return Err(format!(
            "WTSQueryUserToken failed for all active sessions (err={})",
            unsafe { GetLastError() }
        ));
    }
    let _raw_user_tok_guard = RawHandleGuard(raw_user_token);

    let mut _linked_tok_guard = RawHandleGuard(null_mut());
    let mut source_token = raw_user_token;
    let mut elev_type: u32 = 0;
    let mut ret_len: u32 = 0;
    if unsafe {
        GetTokenInformation(
            raw_user_token,
            TOKEN_ELEVATION_TYPE,
            (&mut elev_type as *mut u32).cast(),
            std::mem::size_of::<u32>() as u32,
            &mut ret_len,
        )
    } != 0
        && elev_type == TOKEN_ELEVATION_TYPE_FULL
    {
        let mut linked_handle: *mut c_void = null_mut();
        let mut linked_len: u32 = 0;
        if unsafe {
            GetTokenInformation(
                raw_user_token,
                TOKEN_LINKED_TOKEN,
                (&mut linked_handle as *mut *mut c_void).cast(),
                std::mem::size_of::<*mut c_void>() as u32,
                &mut linked_len,
            )
        } != 0
            && !linked_handle.is_null()
        {
            _linked_tok_guard = RawHandleGuard(linked_handle);
            source_token = linked_handle;
        }
    }

    let mut primary_token: *mut c_void = null_mut();
    if unsafe {
        DuplicateTokenEx(
            source_token,
            MAXIMUM_ALLOWED,
            null(),
            SECURITY_IMPERSONATION,
            TOKEN_PRIMARY,
            &mut primary_token,
        )
    } == 0
        || primary_token.is_null()
    {
        return Err(format!("DuplicateTokenEx failed (err={})", unsafe {
            GetLastError()
        }));
    }
    let _primary_tok_guard = RawHandleGuard(primary_token);

    let mut env_block: *mut c_void = null_mut();
    let _env_guard = if unsafe { CreateEnvironmentBlock(&mut env_block, primary_token, 0) } != 0
        && !env_block.is_null()
    {
        EnvBlockGuard(env_block)
    } else {
        EnvBlockGuard(null_mut())
    };

    let sa = SecurityAttributes {
        n_length: std::mem::size_of::<SecurityAttributes>() as u32,
        lp_security_descriptor: null_mut(),
        b_inherit_handle: 1,
    };
    let mut child_stdin_r: *mut c_void = null_mut();
    let mut parent_stdin_w: *mut c_void = null_mut();
    let mut parent_stdout_r: *mut c_void = null_mut();
    let mut child_stdout_w: *mut c_void = null_mut();
    if unsafe { CreatePipe(&mut child_stdin_r, &mut parent_stdin_w, &sa, 0) } == 0 {
        return Err("CreatePipe(stdin) failed".to_string());
    }
    let mut g_child_stdin_r = RawHandleGuard(child_stdin_r);
    let mut g_parent_stdin_w = RawHandleGuard(parent_stdin_w);

    if unsafe { CreatePipe(&mut parent_stdout_r, &mut child_stdout_w, &sa, 0) } == 0 {
        return Err("CreatePipe(stdout) failed".to_string());
    }
    let g_parent_stdout_r = RawHandleGuard(parent_stdout_r);
    let mut g_child_stdout_w = RawHandleGuard(child_stdout_w);

    unsafe {
        SetHandleInformation(parent_stdin_w, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(parent_stdout_r, HANDLE_FLAG_INHERIT, 0);
    }

    let mut desktop_w = wide_nul(r"winsta0\default");
    let app_w = wide_nul(&desktop_exe.to_string_lossy());
    let mut cmd_w = wide_nul(&format!(
        "\"{}\" --session-fs-bridge --parent-pid {}",
        desktop_exe.display(),
        std::process::id()
    ));
    let work_dir_w = desktop_exe
        .parent()
        .map(|p| wide_nul(&p.to_string_lossy()));

    let si = StartupInfoW {
        cb: std::mem::size_of::<StartupInfoW>() as u32,
        lp_reserved: null_mut(),
        lp_desktop: desktop_w.as_mut_ptr(),
        lp_title: null_mut(),
        dw_x: 0,
        dw_y: 0,
        dw_x_size: 0,
        dw_y_size: 0,
        dw_x_count_chars: 0,
        dw_y_count_chars: 0,
        dw_fill_attribute: 0,
        dw_flags: STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW,
        w_show_window: 0,
        cb_reserved2: 0,
        lp_reserved2: null_mut(),
        h_std_input: child_stdin_r,
        h_std_output: child_stdout_w,
        h_std_error: child_stdout_w,
    };
    let mut pi = ProcessInformation {
        h_process: null_mut(),
        h_thread: null_mut(),
        dw_process_id: 0,
        dw_thread_id: 0,
    };

    let flags = CREATE_NO_WINDOW
        | if !_env_guard.0.is_null() {
            CREATE_UNICODE_ENVIRONMENT
        } else {
            0
        };
    let ok = unsafe {
        CreateProcessAsUserW(
            primary_token,
            app_w.as_ptr(),
            cmd_w.as_mut_ptr(),
            null(),
            null(),
            1,
            flags,
            _env_guard.0,
            work_dir_w.as_ref().map_or(null(), |v| v.as_ptr()),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(format!("CreateProcessAsUserW failed (err={})", unsafe {
            GetLastError()
        }));
    }
    let g_proc = RawHandleGuard(pi.h_process);
    let _g_thread = RawHandleGuard(pi.h_thread);

    drop(std::mem::replace(
        &mut g_child_stdin_r,
        RawHandleGuard(null_mut()),
    ));
    drop(std::mem::replace(
        &mut g_child_stdout_w,
        RawHandleGuard(null_mut()),
    ));

    let secret_line = format!("{token}\n");
    let mut written: u32 = 0;
    let w_ok = unsafe {
        WriteFile(
            g_parent_stdin_w.0,
            secret_line.as_ptr(),
            secret_line.len() as u32,
            &mut written,
            null_mut(),
        )
    };
    drop(std::mem::replace(
        &mut g_parent_stdin_w,
        RawHandleGuard(null_mut()),
    ));
    if w_ok == 0 || written as usize != secret_line.len() {
        unsafe {
            TerminateProcess(g_proc.0, 1);
        }
        return Err("failed to write bridge token to stdin pipe".to_string());
    }

    let mut collected = Vec::with_capacity(128);
    let mut chunk = [0u8; 128];
    for _ in 0..100 {
        let mut avail: u32 = 0;
        let peek_ok = unsafe {
            PeekNamedPipe(
                g_parent_stdout_r.0,
                null_mut(),
                0,
                null_mut(),
                &mut avail,
                null_mut(),
            )
        };
        if peek_ok == 0 {
            break;
        }
        if avail > 0 {
            let to_read = (avail as usize).min(chunk.len()) as u32;
            let mut got: u32 = 0;
            if unsafe {
                ReadFile(
                    g_parent_stdout_r.0,
                    chunk.as_mut_ptr(),
                    to_read,
                    &mut got,
                    null_mut(),
                )
            } != 0
                && got > 0
            {
                collected.extend_from_slice(&chunk[..got as usize]);
                if collected.contains(&b'\n') || collected.len() >= 128 {
                    break;
                }
            }
        } else {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    let line = String::from_utf8_lossy(&collected);
    if let Some(port_str) = line
        .lines()
        .find_map(|l| l.trim().strip_prefix("READY "))
    {
        if let Ok(port) = port_str.trim().parse::<u16>() {
            if port > 0 {
                return Ok((port, chosen_session, pi.dw_process_id));
            }
        }
    }

    unsafe {
        TerminateProcess(g_proc.0, 1);
    }
    Err(format!(
        "session-fs-bridge did not report READY <port> (got '{}')",
        line.trim()
    ))
}
