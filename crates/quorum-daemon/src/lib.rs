pub mod browser;
pub mod chat_history_db;
pub mod cli;
pub mod handlers;
pub mod p2p_watcher;
pub mod server;
pub mod shutdown;
pub mod state;
pub mod wan_mesh;

pub use chat_history_db::{
    ChatHistoryStore, ChatSessionDetail, ChatSessionSummary, StoredChatMessage,
};
pub use cli::{Cli, Commands};
pub use p2p_watcher::{
    discover_local_private_ipv4_addresses, is_private_lan_ipv4, P2pWatcherRuntime,
    P2pWatcherStatusDto,
};
pub use server::build_router;
pub use state::{
    ActiveChatTask, ActiveChatTaskSummary, ChatSessionData, ChatSessionRegistry, DaemonState,
    InFlightCancelToken, InFlightEntry, InFlightGuard, InFlightQueryRegistry,
    DEFAULT_TASK_GRACE_PERIOD,
};
