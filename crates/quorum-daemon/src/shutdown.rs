use std::sync::{Arc, OnceLock};
use tracing::{error, info, warn};
use crate::state::DaemonState;

/// Process-wide stop request used by the Windows service control handler.
fn external_stop() -> &'static tokio::sync::Notify {
    static STOP: OnceLock<tokio::sync::Notify> = OnceLock::new();
    STOP.get_or_init(tokio::sync::Notify::new)
}

/// Ask the running daemon to shut down gracefully (safe to call from any thread).
pub fn request_external_stop() {
    // notify_one stores a permit, so a stop requested before the server awaits is not lost.
    external_stop().notify_one();
}

/// Installs OS signal listeners (Ctrl+C / SIGINT on all platforms, SIGTERM on unix)
/// and listens for internal shutdown notification.
pub async fn shutdown_signal(notify: Arc<tokio::sync::Notify>) {
    let ctrl_c = async {
        // A Windows service has no console; if the handler cannot be installed, wait for other signals.
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C / SIGINT. Initiating graceful shutdown...");
        },
        _ = terminate => {
            info!("Received SIGTERM. Initiating graceful shutdown...");
        },
        _ = notify.notified() => {
            info!("Received internal shutdown notification (/api/shutdown). Initiating graceful shutdown...");
        },
        _ = external_stop().notified() => {
            info!("Received service stop request. Initiating graceful shutdown...");
        },
    }
}

/// Executes orderly cleanup and database flush when shutdown signal is triggered.
pub async fn execute_graceful_shutdown(state: Arc<DaemonState>) {
    info!("Executing QuorumRAG graceful shutdown sequence...");

    // 1. Cooperative cancellation of active reindexer
    let cancelled = state.reindex_worker.cancel_reindex();
    if cancelled {
        info!("Active reindex worker cancelled successfully.");
    }

    // 2. Shut down libp2p swarm actor
    if let Some(ref swarm) = state.swarm_handle {
        match swarm.shutdown().await {
            Ok(_) => info!("Libp2p network swarm actor shut down cleanly."),
            Err(e) => warn!("Libp2p network swarm shutdown error: {}", e),
        }
    }

    // 3. Compact and commit LanceDB and Tantivy indexes
    info!("Flushing and compacting LanceDB & Tantivy storage indexes...");
    match state.storage.compact().await {
        Ok(stats) => {
            info!(
                "Storage indexes cleanly committed: {} fragments removed, {} added, Tantivy segments merged: {}",
                stats.fragments_removed, stats.fragments_added, stats.tantivy_segments_merged
            );
        }
        Err(e) => {
            error!("Error flushing storage during shutdown: {}", e);
        }
    }

    info!("QuorumRAG shutdown sequence complete. Goodbye!");
}
