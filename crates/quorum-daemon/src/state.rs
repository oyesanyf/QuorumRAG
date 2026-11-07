use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tokio::task::AbortHandle;

use quorum_classifier::FileTypeClassifier;
use quorum_contract::EmbeddingGenerator;
use quorum_coordinator::{AgenticTelemetryEvent, QueryCoordinator, SynthesisModelFamily};
use quorum_ingest::{DriftHealer, IngestConfig, ReindexWorker, TwoLevelDedupEngine};
use quorum_network::NetworkSwarmHandle;
use quorum_storage::StorageEngine;

/// Default retention window for completed chat tasks before memory pruning (30 seconds).
pub const DEFAULT_TASK_GRACE_PERIOD: Duration = Duration::from_secs(30);

/// Token for cooperative query cancellation checks.
#[derive(Clone, Default)]
pub struct InFlightCancelToken(Arc<AtomicBool>);

impl InFlightCancelToken {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Rich active chat task tracking background execution, buffered event logs, and broadcast channels.
pub struct ActiveChatTask {
    pub query_id: String,
    pub session_id: String,
    pub prompt: String,
    pub model_family: String,
    pub started_at_ms: u64,
    pub completed_at_ms: Arc<AtomicU64>,
    pub completed: Arc<AtomicBool>,
    pub cancelled: Arc<AtomicBool>,
    pub token: InFlightCancelToken,
    pub abort_handle: Arc<Mutex<Option<AbortHandle>>>,
    pub event_log: Arc<Mutex<Vec<AgenticTelemetryEvent>>>,
    pub broadcaster: broadcast::Sender<AgenticTelemetryEvent>,
}

impl ActiveChatTask {
    pub fn new(
        query_id: String,
        session_id: String,
        prompt: String,
        model_family: String,
    ) -> Self {
        let (broadcaster, _) = broadcast::channel(8192);
        let started_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            query_id,
            session_id,
            prompt,
            model_family,
            started_at_ms,
            completed_at_ms: Arc::new(AtomicU64::new(0)),
            completed: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            token: InFlightCancelToken::new(),
            abort_handle: Arc::new(Mutex::new(None)),
            event_log: Arc::new(Mutex::new(Vec::new())),
            broadcaster,
        }
    }

    pub fn set_abort_handle(&self, handle: AbortHandle) {
        if let Ok(mut lock) = self.abort_handle.lock() {
            *lock = Some(handle);
        }
    }

    pub fn is_running(&self) -> bool {
        !self.completed.load(Ordering::SeqCst) && !self.cancelled.load(Ordering::SeqCst)
    }

    pub fn is_completed(&self) -> bool {
        self.completed.load(Ordering::SeqCst)
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn mark_completed(&self) {
        self.completed.store(true, Ordering::SeqCst);
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.completed_at_ms.store(now_ms, Ordering::SeqCst);
    }

    pub fn cancel(&self) -> bool {
        let was_running = !self.completed.load(Ordering::SeqCst)
            && !self.cancelled.swap(true, Ordering::SeqCst);
        if was_running {
            self.token.cancel();
            self.record_event(AgenticTelemetryEvent::ExecutionError {
                failed_state: quorum_coordinator::types::AgenticStateName::SynthesizeWithCitations,
                error_message: "Query cancelled by user".to_string(),
                fallback_action: "Terminated in-flight execution".to_string(),
            });
            if let Ok(mut lock) = self.abort_handle.lock() {
                if let Some(handle) = lock.take() {
                    handle.abort();
                }
            }
            self.mark_completed();
            true
        } else {
            false
        }
    }

    /// Records an event to the internal replay log and broadcasts it to live subscribers atomically.
    pub fn record_event(&self, event: AgenticTelemetryEvent) {
        if let Ok(mut log) = self.event_log.lock() {
            log.push(event.clone());
            let _ = self.broadcaster.send(event);
        }
    }

    /// Takes a consistent snapshot of all buffered events and subscribes to future broadcast events atomically.
    pub fn snapshot_and_subscribe(
        &self,
    ) -> (Vec<AgenticTelemetryEvent>, broadcast::Receiver<AgenticTelemetryEvent>) {
        if let Ok(log) = self.event_log.lock() {
            let snapshot = log.clone();
            let rx = self.broadcaster.subscribe();
            (snapshot, rx)
        } else {
            (Vec::new(), self.broadcaster.subscribe())
        }
    }
}

/// JSON summary of active running chat task for `GET /api/chat/active`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActiveChatTaskSummary {
    pub query_id: String,
    pub session_id: String,
    pub prompt: String,
    pub model_family: String,
    pub started_at_ms: u64,
}

/// Backward-compatible handle for in-flight tasks and cancellation.
#[derive(Clone)]
pub struct InFlightEntry {
    pub token: InFlightCancelToken,
    pub abort_handle: Arc<Mutex<Option<AbortHandle>>>,
    pub task: Arc<ActiveChatTask>,
}

impl InFlightEntry {
    pub fn set_abort_handle(&self, handle: AbortHandle) {
        self.task.set_abort_handle(handle);
    }
}

/// Guard dropped when background worker completes, marking task completed and pruning stale tasks.
pub struct InFlightGuard {
    pub query_id: String,
    pub registry: Arc<RwLock<HashMap<String, Arc<ActiveChatTask>>>>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let grace_ms = DEFAULT_TASK_GRACE_PERIOD.as_millis() as u64;

        if let Ok(mut map) = self.registry.write() {
            if let Some(task) = map.get(&self.query_id) {
                if !task.completed.load(Ordering::SeqCst) {
                    task.mark_completed();
                }
            }
            // Opportunistic prune of stale completed tasks exceeding retention window
            map.retain(|_, task| {
                if !task.completed.load(Ordering::SeqCst) && !task.cancelled.load(Ordering::SeqCst) {
                    true
                } else {
                    let completed_at = task.completed_at_ms.load(Ordering::SeqCst);
                    if completed_at == 0 {
                        true
                    } else {
                        now_ms.saturating_sub(completed_at) < grace_ms
                    }
                }
            });
        }
    }
}

/// Thread-safe registry mapping `query_id` to rich `ActiveChatTask` state.
#[derive(Clone, Default)]
pub struct InFlightQueryRegistry {
    queries: Arc<RwLock<HashMap<String, Arc<ActiveChatTask>>>>,
}

impl InFlightQueryRegistry {
    pub fn new() -> Self {
        Self {
            queries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registers a rich active chat task with full event buffering and broadcasting.
    pub fn register_task(
        &self,
        query_id: String,
        session_id: String,
        prompt: String,
        model_family: String,
    ) -> (Arc<ActiveChatTask>, InFlightGuard) {
        let task = Arc::new(ActiveChatTask::new(
            query_id.clone(),
            session_id,
            prompt,
            model_family,
        ));
        if let Ok(mut map) = self.queries.write() {
            map.insert(query_id.clone(), Arc::clone(&task));
        }
        let guard = InFlightGuard {
            query_id,
            registry: Arc::clone(&self.queries),
        };
        (task, guard)
    }

    /// Backward-compatible registration helper for tests and callers with only `query_id`.
    pub fn register(&self, query_id: String) -> (InFlightEntry, InFlightGuard) {
        let session_id = format!("s-{}", query_id);
        let (task, guard) = self.register_task(
            query_id,
            session_id,
            String::new(),
            "AutoFusion".to_string(),
        );
        let entry = InFlightEntry {
            token: task.token.clone(),
            abort_handle: Arc::clone(&task.abort_handle),
            task,
        };
        (entry, guard)
    }

    /// Retrieves active or recently completed chat task by `query_id`.
    pub fn get_by_query_id(&self, query_id: &str) -> Option<Arc<ActiveChatTask>> {
        self.prune_stale(DEFAULT_TASK_GRACE_PERIOD);
        if let Ok(map) = self.queries.read() {
            map.get(query_id).cloned()
        } else {
            None
        }
    }

    /// Retrieves active or recently completed chat task by `session_id`.
    pub fn get_by_session_id(&self, session_id: &str) -> Option<Arc<ActiveChatTask>> {
        self.prune_stale(DEFAULT_TASK_GRACE_PERIOD);
        if let Ok(map) = self.queries.read() {
            // Prefer running task first
            let running = map
                .values()
                .filter(|t| t.session_id == session_id && t.is_running())
                .max_by_key(|t| t.started_at_ms);
            if let Some(t) = running {
                return Some(Arc::clone(t));
            }
            // Fallback to recent completed task within retention window
            map.values()
                .filter(|t| t.session_id == session_id)
                .max_by_key(|t| t.started_at_ms)
                .cloned()
        } else {
            None
        }
    }

    /// Lists summaries of all currently running tasks for `GET /api/chat/active`.
    pub fn list_active(&self) -> Vec<ActiveChatTaskSummary> {
        self.prune_stale(DEFAULT_TASK_GRACE_PERIOD);
        if let Ok(map) = self.queries.read() {
            let mut list: Vec<ActiveChatTaskSummary> = map
                .values()
                .filter(|t| t.is_running())
                .map(|t| ActiveChatTaskSummary {
                    query_id: t.query_id.clone(),
                    session_id: t.session_id.clone(),
                    prompt: t.prompt.clone(),
                    model_family: t.model_family.clone(),
                    started_at_ms: t.started_at_ms,
                })
                .collect();
            list.sort_by_key(|s| std::cmp::Reverse(s.started_at_ms));
            list
        } else {
            Vec::new()
        }
    }

    /// Alias for `list_active()`
    pub fn get_active_tasks(&self) -> Vec<ActiveChatTaskSummary> {
        self.list_active()
    }

    /// Cancels a running query by `query_id`.
    pub fn cancel(&self, query_id: &str) -> bool {
        if let Ok(map) = self.queries.read() {
            if let Some(task) = map.get(query_id) {
                return task.cancel();
            }
        }
        false
    }

    /// Cancels running queries matching `session_id`.
    pub fn cancel_session(&self, session_id: &str) -> bool {
        if let Ok(map) = self.queries.read() {
            let mut any = false;
            for task in map.values() {
                if task.session_id == session_id && task.is_running() {
                    task.cancel();
                    any = true;
                }
            }
            return any;
        }
        false
    }

    /// Cancels all running queries.
    pub fn cancel_all(&self) -> usize {
        let mut count = 0;
        if let Ok(map) = self.queries.read() {
            for task in map.values() {
                if task.is_running() {
                    task.cancel();
                    count += 1;
                }
            }
        }
        count
    }

    /// Prunes completed or cancelled tasks whose grace retention window has elapsed.
    pub fn prune_stale(&self, grace_period: Duration) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let grace_ms = grace_period.as_millis() as u64;

        if let Ok(mut map) = self.queries.write() {
            map.retain(|_, task| {
                if !task.completed.load(Ordering::SeqCst) && !task.cancelled.load(Ordering::SeqCst) {
                    true
                } else {
                    let completed_at = task.completed_at_ms.load(Ordering::SeqCst);
                    if completed_at == 0 {
                        true
                    } else {
                        now_ms.saturating_sub(completed_at) < grace_ms
                    }
                }
            });
        }
    }

    /// Prunes completed or cancelled tasks with default grace period.
    pub fn prune_stale_default(&self) {
        self.prune_stale(DEFAULT_TASK_GRACE_PERIOD);
    }
}

/// Session data tracking seen chunk IDs and last active timestamp for multi-turn continuation deduplication.
#[derive(Debug, Clone)]
pub struct ChatSessionData {
    pub session_id: String,
    pub seen_chunk_ids: HashSet<String>,
    pub last_active: Instant,
}

/// Thread-safe registry mapping session IDs to their active continuation state, seen chunk IDs,
/// and lazily-initialized SQLite chat history store.
#[derive(Clone, Default)]
pub struct ChatSessionRegistry {
    sessions: Arc<RwLock<HashMap<String, ChatSessionData>>>,
    history_db: Arc<RwLock<Option<Arc<crate::chat_history_db::ChatHistoryStore>>>>,
    pub(crate) p2p_watcher_runtime: Arc<RwLock<Option<Arc<crate::p2p_watcher::P2pWatcherRuntime>>>>,
}

impl ChatSessionRegistry {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            history_db: Arc::new(RwLock::new(None)),
            p2p_watcher_runtime: Arc::new(RwLock::new(None)),
        }
    }

    pub fn get_seen_chunks(&self, session_id: &str) -> HashSet<String> {
        if let Ok(map) = self.sessions.read() {
            map.get(session_id)
                .map(|s| s.seen_chunk_ids.clone())
                .unwrap_or_default()
        } else {
            HashSet::new()
        }
    }

    pub fn record_seen_chunks(&self, session_id: &str, chunk_ids: &[String]) {
        if let Ok(mut map) = self.sessions.write() {
            let entry = map.entry(session_id.to_string()).or_insert_with(|| ChatSessionData {
                session_id: session_id.to_string(),
                seen_chunk_ids: HashSet::new(),
                last_active: Instant::now(),
            });
            entry.last_active = Instant::now();
            for id in chunk_ids {
                entry.seen_chunk_ids.insert(id.clone());
            }
        }
    }

    pub fn remove_session(&self, session_id: &str) {
        if let Ok(mut map) = self.sessions.write() {
            map.remove(session_id);
        }
    }

    pub fn clear_all_sessions(&self) {
        if let Ok(mut map) = self.sessions.write() {
            map.clear();
        }
    }

    pub fn prune_stale_sessions(&self, max_idle: std::time::Duration) {
        if let Ok(mut map) = self.sessions.write() {
            map.retain(|_, v| v.last_active.elapsed() < max_idle);
        }
    }
}

/// Global shared application state for Axum daemon routes.
pub struct DaemonState {
    pub start_time: Instant,
    pub storage: Arc<StorageEngine>,
    pub coordinator: Arc<QueryCoordinator>,
    pub reindex_worker: Arc<ReindexWorker>,
    pub drift_healer: Arc<DriftHealer>,
    pub classifier: Arc<FileTypeClassifier>,
    pub embedder: Arc<dyn EmbeddingGenerator>,
    pub dedup: Arc<TwoLevelDedupEngine>,
    pub swarm_handle: Option<NetworkSwarmHandle>,
    pub ingest_config: IngestConfig,
    pub default_model_family: SynthesisModelFamily,
    pub port: u16,
    pub host: String,
    pub data_dir: PathBuf,
    pub shutdown_notify: Arc<tokio::sync::Notify>,
    pub in_flight_queries: Arc<InFlightQueryRegistry>,
    pub sessions: ChatSessionRegistry,
}

impl DaemonState {
    /// Attaches an explicit `P2pWatcherRuntime` configured at daemon startup.
    pub fn set_p2p_watcher(&self, runtime: Arc<crate::p2p_watcher::P2pWatcherRuntime>) {
        if let Ok(mut guard) = self.sessions.p2p_watcher_runtime.write() {
            *guard = Some(runtime);
        }
    }

    /// Returns the active `P2pWatcherRuntime` (lazily initializing a default instance for test harnesses).
    pub fn p2p_watcher(&self) -> Arc<crate::p2p_watcher::P2pWatcherRuntime> {
        if let Ok(guard) = self.sessions.p2p_watcher_runtime.read() {
            if let Some(ref existing) = *guard {
                return Arc::clone(existing);
            }
        }
        let mut wguard = self
            .sessions
            .p2p_watcher_runtime
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(ref existing) = *wguard {
            return Arc::clone(existing);
        }
        let default_rt = Arc::new(crate::p2p_watcher::P2pWatcherRuntime::new(
            self.data_dir.clone(),
            self.port.saturating_add(1),
            self.coordinator.engine.secret_seed,
            self.coordinator.engine.sender_peer_id.clone(),
            self.swarm_handle.is_some(),
        ));
        *wguard = Some(Arc::clone(&default_rt));
        default_rt
    }
    /// Returns the persistent SQLite `ChatHistoryStore` backed by `<data_dir>/chat_history.db`.
    pub fn history_store(&self) -> Result<Arc<crate::chat_history_db::ChatHistoryStore>, String> {
        if let Ok(guard) = self.sessions.history_db.read() {
            if let Some(ref existing) = *guard {
                return Ok(Arc::clone(existing));
            }
        }
        let mut wguard = self
            .sessions
            .history_db
            .write()
            .map_err(|e| format!("History DB lock poisoned: {e}"))?;
        if let Some(ref existing) = *wguard {
            return Ok(Arc::clone(existing));
        }
        let db_path = self.data_dir.join("chat_history.db");
        let opened = Arc::new(
            crate::chat_history_db::ChatHistoryStore::open(&db_path)
                .map_err(|e| format!("Failed to open {}: {e}", db_path.display()))?,
        );
        *wguard = Some(Arc::clone(&opened));
        Ok(opened)
    }
}
