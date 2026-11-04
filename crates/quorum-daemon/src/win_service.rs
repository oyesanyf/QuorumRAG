//! Windows Service Control Manager integration.
//!
//! The MSI registers `quorumrag.exe --service ...` as the auto-start `QuorumRAGDaemon` service.
//! With `--service`, the process connects to the SCM through `StartServiceCtrlDispatcherW`,
//! reports START_PENDING -> RUNNING, runs the normal daemon on a Tokio runtime, and on
//! STOP/SHUTDOWN triggers the daemon's graceful shutdown (index flush) before reporting STOPPED.
//! Launched outside the SCM, `--service` fails with a clear message instead of hanging.

use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use windows_sys::Win32::Foundation::{ERROR_CALL_NOT_IMPLEMENTED, NO_ERROR};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW, SERVICE_ACCEPT_SHUTDOWN,
    SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
    SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOPPED, SERVICE_STOP_PENDING,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

use crate::cli::Cli;

/// Service name registered by the MSI (`wix/QuorumRAG.wxs`).
pub const SERVICE_NAME: &str = "QuorumRAGDaemon";

/// Win32 error reported when the daemon exits with an error (ERROR_EXCEPTION_IN_SERVICE).
const ERROR_EXCEPTION_IN_SERVICE: u32 = 1064;
/// StartServiceCtrlDispatcherW failure when the process was not started by the SCM.
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;

static CLI_SLOT: OnceLock<Mutex<Option<Cli>>> = OnceLock::new();
static STATUS_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn report(state: u32, accepted: u32, checkpoint: u32, wait_hint_ms: u32, exit_code: u32) {
    let handle = STATUS_HANDLE.load(Ordering::SeqCst);
    if handle.is_null() {
        return;
    }
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepted,
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: checkpoint,
        dwWaitHint: wait_hint_ms,
    };
    // SAFETY: `handle` was returned by RegisterServiceCtrlHandlerExW and `status` outlives the call.
    unsafe {
        SetServiceStatus(handle, &status);
    }
}

unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            tracing::info!("SCM requested stop; starting graceful shutdown");
            report(SERVICE_STOP_PENDING, 0, 1, 30_000, NO_ERROR);
            crate::shutdown::request_external_stop();
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    let name = wide(SERVICE_NAME);
    // SAFETY: `name` is a NUL-terminated UTF-16 string valid for the duration of the call.
    let handle = RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control_handler), null());
    if handle.is_null() {
        tracing::error!("RegisterServiceCtrlHandlerExW failed: {}", std::io::Error::last_os_error());
        return;
    }
    STATUS_HANDLE.store(handle, Ordering::SeqCst);
    report(SERVICE_START_PENDING, 0, 1, 60_000, NO_ERROR);

    let cli = CLI_SLOT.get().and_then(|slot| slot.lock().ok().and_then(|mut g| g.take()));
    let Some(cli) = cli else {
        report(SERVICE_STOPPED, 0, 0, 0, ERROR_EXCEPTION_IN_SERVICE);
        return;
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!("Failed to start Tokio runtime for service: {e}");
            report(SERVICE_STOPPED, 0, 0, 0, ERROR_EXCEPTION_IN_SERVICE);
            return;
        }
    };

    report(SERVICE_RUNNING, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN, 0, 0, NO_ERROR);
    tracing::info!("QuorumRAG is running as Windows service '{SERVICE_NAME}'");

    let result = runtime.block_on(crate::run_daemon_and_ui(cli));
    let exit_code = match &result {
        Ok(()) => NO_ERROR,
        Err(e) => {
            tracing::error!("QuorumRAG service exited with error: {e:#}");
            ERROR_EXCEPTION_IN_SERVICE
        }
    };
    report(SERVICE_STOP_PENDING, 0, 2, 15_000, exit_code);
    runtime.shutdown_timeout(Duration::from_secs(10));
    report(SERVICE_STOPPED, 0, 0, 0, exit_code);
}

/// Hand control to the Service Control Manager. Blocks until the service stops.
pub fn run(cli: Cli) -> anyhow::Result<()> {
    CLI_SLOT.get_or_init(|| Mutex::new(Some(cli)));
    let mut name = wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW { lpServiceName: name.as_mut_ptr(), lpServiceProc: Some(service_main) },
        SERVICE_TABLE_ENTRYW { lpServiceName: null_mut(), lpServiceProc: None },
    ];
    // SAFETY: the table is NUL-entry terminated and outlives the blocking dispatcher call.
    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            anyhow::bail!(
                "--service is only for the Windows Service Control Manager. Start it with `sc start {SERVICE_NAME}`, \
                 or run without --service for console mode."
            );
        }
        return Err(anyhow::anyhow!("StartServiceCtrlDispatcherW failed: {err}"));
    }
    Ok(())
}
