use tracing::{info, warn};

/// Cross-platform browser auto-launcher using native OS APIs (zero console/shell spawns).
pub fn launch_browser(url: &str) {
    info!("Auto-opening default web browser to {}", url);

    #[cfg(windows)]
    {
        // Primary: native Win32 ShellExecuteW (zero cmd.exe / shell process creation).
        if let Err(e) = crate::win_native::shell_open_url(url) {
            warn!(
                "Win32 ShellExecuteW failed ({}), attempting open::that fallback...",
                e
            );
            if let Err(e2) = open::that(url) {
                warn!("open::that fallback also failed to open browser: {}", e2);
            }
        }
    }

    #[cfg(not(windows))]
    {
        if let Err(e) = open::that(url) {
            warn!("Failed to auto-open browser on unix: {}", e);
        }
    }
}
