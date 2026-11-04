use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// QuorumRAG Command-Line Interface.
#[derive(Parser, Debug, Clone)]
#[command(name = "quorumrag")]
#[command(author = "QuorumRAG Team")]
#[command(version = "0.1.0")]
#[command(about = "QuorumRAG: Local-First P2P Retrieval-Augmented Generation Daemon & ChatGPT Web UI", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Port to bind the web server and UI on (automatically advances to next open port if busy)
    #[arg(short, long, default_value_t = 3030)]
    pub port: u16,

    /// Host interface to bind on (defaults to 0.0.0.0 so both localhost and remote LAN peers can connect)
    #[arg(long, default_value = "0.0.0.0")]
    pub host: String,

    /// Root directory for LanceDB and Tantivy persistent data
    #[arg(long, default_value = "./data")]
    pub data_dir: PathBuf,

    /// Directory to index and watch for changes (defaults to all fixed physical drives when omitted)
    #[arg(long)]
    pub watch_dir: Option<PathBuf>,

    /// Do not auto-open the default browser upon server startup (for headless or CI test runs)
    #[arg(long, default_value_t = false)]
    pub no_browser: bool,

    /// Port for libp2p P2P swarm (TCP & QUIC; automatically advances to next open port if busy)
    #[arg(long, default_value_t = 3031)]
    pub p2p_port: u16,

    /// Run in local-only mode (disable remote peer networking)
    #[arg(long, default_value_t = false)]
    pub local_only: bool,

    /// Default synthesis model family: AutoFusion, Glm4Agentic, Qwen25Code, GemmaProse
    #[arg(long, default_value = "AutoFusion")]
    pub model_family: String,

    /// Maximum number of remote peer responses to collect/fuse per query (default: 8)
    #[arg(long, default_value_t = 8)]
    pub max_peer_responses: usize,

    /// Run under the Windows Service Control Manager (used by the installed QuorumRAGDaemon service).
    /// Logs go to <data-dir>/logs/quorumrag-service.log. On Linux/macOS this flag only enables file logging.
    #[arg(long, default_value_t = false)]
    pub service: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Run standalone reindex worker process on designated directories
    Reindex {
        /// Target directory path to reindex (defaults to configured watch_dir or current working dir)
        #[arg(short, long)]
        path: Option<PathBuf>,

        /// Full rebuild: bypass mtime and Level-1 BLAKE3 catalogs, re-verifying all files
        #[arg(short, long, default_value_t = false)]
        full: bool,

        /// Force re-embedding all chunks even if Level-2 chunk BLAKE3 cache matches
        #[arg(long, default_value_t = false)]
        force_reembed: bool,

        /// Micro-batch size for writes to storage
        #[arg(long, default_value_t = 64)]
        batch_size: usize,
    },

    /// Run standalone drift healing process repairing all 5 drift types
    FixDrift {
        /// Dry run mode: detect and report drift anomalies without mutating storage
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Target specific drift category: merkle_state, hybrid_index_desync, vector_contract, acl_policy, storage_compaction (default: all 5)
        #[arg(long)]
        drift_type: Option<String>,
    },

    /// Invalidate, synchronize, and pre-warm BLAKE3 query and embedding caches
    Recache {
        /// Force full eviction of all cached query and embedding entries instead of soft epoch increment
        #[arg(short, long, default_value_t = false)]
        clear: bool,

        /// Pre-warm hot query embeddings and high-frequency document chunks from persistent index
        #[arg(short, long, default_value_t = false)]
        warm: bool,
    },
}
