use tracing::{info, warn};

/// Cross-platform browser auto-launcher with Windows native fallback.
pub fn launch_browser(url: &str) {
    info!("Auto-opening default web browser to {}", url);

    #[cfg(windows)]
    {
        // 1. Try 'open' crate
        if let Err(e) = open::that(url) {
            warn!("open::that failed ({}), falling back to Windows 'cmd /c start'...", e);
            use std::os::windows::process::CommandExt;
            use std::process::Command;

            let status = Command::new("cmd")
                .args(["/c", "start", "", url])
                .creation_flags(0x08000000) // CREATE_NO_WINDOW
                .spawn();

            if let Err(e2) = status {
                warn!("Windows cmd fallback failed to open browser: {}", e2);
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
