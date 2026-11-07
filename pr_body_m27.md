## Summary

Milestone M27 implements session and running-task persistence across browser refreshes and tab switches, resolving the user goal: *"if I refresh while a task is running, it does not remember the session"*.

### Key Changes

1. **Daemon-Owned Task Decoupling & Event Buffering (`crates/quorum-daemon/src/state.rs`, `lib.rs`)**:
   - Implemented `ActiveChatTask` with `query_id`, `session_id`, `prompt`, `model_family`, `started_at_ms`, `event_log: Arc<Mutex<Vec<AgenticTelemetryEvent>>>`, and `broadcaster: broadcast::Sender<AgenticTelemetryEvent>`.
   - Implemented atomic `snapshot_and_subscribe()` capturing pre-existing telemetry events from `event_log` while subscribing to future broadcast events, guaranteeing zero event loss and zero duplicate replay.
   - Introduced `DEFAULT_TASK_GRACE_PERIOD` (30s) retention with opportunistic pruning so reconnecting or refreshing clients have a grace window to retrieve completed query responses.
   - Enhanced `InFlightQueryRegistry` to support `register_task`, `get_by_query_id`, `get_by_session_id`, `list_active`, `cancel`, `cancel_session`, and `cancel_all`.

2. **Early Pending Turn & Cancellation Persistence in SQLite (`crates/quorum-daemon/src/chat_history_db.rs`)**:
   - Added `record_pending_turn`: immediately persists the conversation session (with title derived from prompt), user prompt row (`role='user'`), and an empty assistant placeholder row (`role='assistant', content=''`) prior to synthesis execution.
   - Handled prompt regeneration in-place: re-submitting the same prompt clears the trailing assistant row instead of appending duplicate user messages.
   - Added `record_cancelled_turn` / `mark_turn_cancelled`: updates any trailing pending empty assistant row upon cancellation to `*[Generation stopped by user]*`, preventing orphaned blank rows in SQLite.

3. **Decoupled SSE Execution & Re-Attach Endpoints (`crates/quorum-daemon/src/handlers/chat.rs`, `server.rs`)**:
   - In `chat_sse_handler`, immediately invokes `record_pending_turn`, registers `ActiveChatTask`, creates an internal daemon-owned channel (`mpsc::channel(16384)`), and spawns a background collector bridge that logs and broadcasts telemetry events.
   - Because the daemon owns the receiver, client browser disconnects or refreshes no longer abort the agentic query coordinator loop.
   - Implemented `GET /api/chat/active` returning JSON summaries of running chat tasks.
   - Implemented `GET /api/chat/attach/:session_id` returning an SSE stream that atomically replays snapshot events followed by live broadcast telemetry until completion.
   - Enhanced `POST /api/chat/cancel` to support cancellation by `session_id` as well as `query_id`, marking cancelled state in SQLite history.

4. **Frontend Session Persistence, Live Re-Attach & Reindex Resume (`crates/quorum-ui/assets/app.js`, `index.html`)**:
   - Replaced unconditional random session generation on startup with `syncSessionPersistence(sessionId)` synchronizing with `localStorage['quorumrag_active_session_id']` and URL hash `#session=<id>`.
   - Wired session persistence across prompt submission, sidebar session switching, session deletion, clearing all chats, and the `New Chat` button.
   - Restored `activeSessionSeenChunkIds` from historical citations to maintain multi-turn chunk deduplication across page refreshes.
   - Implemented `restoreActiveSessionOnStartup()`: prioritizes URL hash -> localStorage -> running tasks from `/api/chat/active` -> clean new chat; loads conversation history and re-attaches to live streaming if a task is active.
   - Implemented `attachToLiveChatTask(activeTask)`: connects to `GET /api/chat/attach/:session_id`, progressively streams token chunks, renders citations, manages action buttons, and wires `btnStop` cancellation.
   - Auto-resumes reindex progress polling on startup if a background indexing job is active.
   - Restored `Gemma 3` option in `crates/quorum-ui/assets/index.html` dropdown.

5. **Test Coverage & Verification**:
   - Added `crates/quorum-daemon/tests/task_decoupling_and_reattach_tests.rs` (5 integration tests):
     - `test_in_flight_registry_active_task_buffering_and_broadcast`
     - `test_sqlite_chat_history_record_pending_and_cancellation`
     - `test_active_chat_tasks_endpoint_and_reattach_flow`
     - `test_cancel_chat_by_session_id_and_cleanup`
     - `test_chat_sse_handler_pending_turn_and_client_disconnect`
   - Added `crates/quorum-ui/tests/m27_session_persistence_ui_tests.rs` (2 contract tests):
     - `test_index_html_model_dropdown_contains_gemma_3`
     - `test_session_persistence_and_routing_invariants`
   - Ran `cargo test -p quorum-daemon --test task_decoupling_and_reattach_tests`: 5 passed, 0 failed.
   - Ran `cargo test -p quorum-daemon --test daemon_tests`: 2 passed, 0 failed.
   - Ran `cargo test -p quorum-daemon --test adversarial_endpoint_tests`: 9 passed, 0 failed.
   - Ran `cargo test -p quorum-daemon --test adversarial_mesh_endpoint_tests`: 4 passed, 0 failed.
   - Ran `cargo test -p quorum-ui`: 30 passed, 0 failed.
