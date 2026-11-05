//! Persistent SQLite Chat History Store (`<data_dir>/chat_history.db`).
//!
//! Persists all user/assistant conversation sessions, rendered Markdown responses,
//! grounded RAG source citations, and responding Mesh Node IDs across daemon restarts,
//! MSI upgrades, and browser reloads. Supports listing sessions, loading a single
//! conversation, deleting a single conversation, and deleting all conversations.

use chrono::Utc;
use quorum_types::Citation;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Summary row for rendering a conversation entry in the left `HISTORY` sidebar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatSessionSummary {
    pub session_id: String,
    pub title: String,
    pub model_family: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub message_count: usize,
}

/// Persisted message turn inside a conversation session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredChatMessage {
    pub id: i64,
    pub session_id: String,
    pub role: String,
    pub content: String,
    pub citations: Vec<Citation>,
    pub responder_peer_id: String,
    pub created_at: i64,
}

/// Full conversation payload returned by `GET /api/history/:session_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatSessionDetail {
    pub session: ChatSessionSummary,
    pub messages: Vec<StoredChatMessage>,
}

/// Thread-safe SQLite-backed conversation store.
pub struct ChatHistoryStore {
    db_path: PathBuf,
    conn: Mutex<Connection>,
}

impl ChatHistoryStore {
    /// Opens or initializes `<data_dir>/chat_history.db` in WAL mode with foreign-key enforcement.
    pub fn open(db_path: &Path) -> rusqlite::Result<Self> {
        if let Some(parent) = db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS chat_sessions (
                 session_id TEXT PRIMARY KEY,
                 title TEXT NOT NULL,
                 model_family TEXT NOT NULL DEFAULT 'AutoFusion',
                 created_at INTEGER NOT NULL,
                 updated_at INTEGER NOT NULL,
                 message_count INTEGER NOT NULL DEFAULT 0
             );
             CREATE INDEX IF NOT EXISTS idx_chat_sessions_updated
                 ON chat_sessions(updated_at DESC);
             CREATE TABLE IF NOT EXISTS chat_messages (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 session_id TEXT NOT NULL,
                 role TEXT NOT NULL,
                 content TEXT NOT NULL,
                 citations_json TEXT NOT NULL DEFAULT '[]',
                 responder_peer_id TEXT NOT NULL DEFAULT 'local',
                 created_at INTEGER NOT NULL,
                 FOREIGN KEY(session_id) REFERENCES chat_sessions(session_id) ON DELETE CASCADE
             );
             CREATE INDEX IF NOT EXISTS idx_chat_messages_session
                 ON chat_messages(session_id, id ASC);",
        )?;
        Ok(Self {
            db_path: db_path.to_path_buf(),
            conn: Mutex::new(conn),
        })
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Derives a clean, human-readable sidebar title from the opening user prompt.
    pub fn derive_title(prompt: &str) -> String {
        let collapsed = prompt.split_whitespace().collect::<Vec<_>>().join(" ");
        let trimmed = collapsed.trim();
        if trimmed.is_empty() {
            return "New Conversation".to_string();
        }
        if trimmed.chars().count() <= 56 {
            return trimmed.to_string();
        }
        let prefix: String = trimmed.chars().take(54).collect();
        format!("{}…", prefix.trim_end())
    }

    /// Atomically persists a completed `(user_prompt, assistant_answer, citations)` turn.
    /// If the user regenerated the exact same trailing prompt in the same session, replaces
    /// the trailing assistant response in place rather than duplicating the user message.
    pub fn record_turn(
        &self,
        session_id: &str,
        user_prompt: &str,
        assistant_answer: &str,
        citations: &[Citation],
        responder_peer_id: &str,
        model_family: &str,
    ) -> rusqlite::Result<()> {
        let sid = session_id.trim();
        let clean_prompt = user_prompt.trim();
        if sid.is_empty() || clean_prompt.is_empty() {
            return Ok(());
        }

        let now = Utc::now().timestamp_millis();
        let citations_json =
            serde_json::to_string(citations).unwrap_or_else(|_| "[]".to_string());
        let resp_peer = if responder_peer_id.trim().is_empty() {
            "local"
        } else {
            responder_peer_id.trim()
        };
        let model_str = if model_family.trim().is_empty() {
            "AutoFusion"
        } else {
            model_family.trim()
        };

        let mut guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = guard.transaction()?;

        let exists: Option<String> = tx
            .query_row(
                "SELECT title FROM chat_sessions WHERE session_id = ?1",
                params![sid],
                |r| r.get(0),
            )
            .optional()?;

        if exists.is_none() {
            let title = Self::derive_title(clean_prompt);
            tx.execute(
                "INSERT INTO chat_sessions (session_id, title, model_family, created_at, updated_at, message_count)
                 VALUES (?1, ?2, ?3, ?4, ?4, 0)",
                params![sid, title, model_str, now],
            )?;
        }

        // Check whether this is an in-place regeneration of the last user prompt
        let last_two: Vec<(i64, String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT id, role, content FROM chat_messages
                 WHERE session_id = ?1
                 ORDER BY id DESC LIMIT 2",
            )?;
            let mapped = stmt.query_map(params![sid], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            mapped.flatten().collect()
        };

        let regenerated_assistant_id = if last_two.len() >= 2
            && last_two[0].1 == "assistant"
            && last_two[1].1 == "user"
            && last_two[1].2.trim() == clean_prompt
        {
            Some(last_two[0].0)
        } else {
            None
        };

        if let Some(asst_row_id) = regenerated_assistant_id {
            tx.execute(
                "UPDATE chat_messages
                 SET content = ?1, citations_json = ?2, responder_peer_id = ?3, created_at = ?4
                 WHERE id = ?5",
                params![assistant_answer, citations_json, resp_peer, now, asst_row_id],
            )?;
        } else {
            tx.execute(
                "INSERT INTO chat_messages (session_id, role, content, citations_json, responder_peer_id, created_at)
                 VALUES (?1, 'user', ?2, '[]', 'local', ?3)",
                params![sid, clean_prompt, now],
            )?;
            tx.execute(
                "INSERT INTO chat_messages (session_id, role, content, citations_json, responder_peer_id, created_at)
                 VALUES (?1, 'assistant', ?2, ?3, ?4, ?5)",
                params![sid, assistant_answer, citations_json, resp_peer, now + 1],
            )?;
        }

        let msg_count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM chat_messages WHERE session_id = ?1",
            params![sid],
            |r| r.get(0),
        )?;

        tx.execute(
            "UPDATE chat_sessions
             SET updated_at = ?1, model_family = ?2, message_count = ?3
             WHERE session_id = ?4",
            params![now + 1, model_str, msg_count, sid],
        )?;

        tx.commit()?;
        Ok(())
    }

    /// Lists persisted conversation sessions ordered by most recently active first.
    pub fn list_sessions(&self, limit: usize) -> rusqlite::Result<Vec<ChatSessionSummary>> {
        let cap = limit.clamp(1, 500) as i64;
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = guard.prepare(
            "SELECT session_id, title, model_family, created_at, updated_at, message_count
             FROM chat_sessions
             ORDER BY updated_at DESC, rowid DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![cap], |r| {
            let cnt: i64 = r.get(5)?;
            Ok(ChatSessionSummary {
                session_id: r.get(0)?,
                title: r.get(1)?,
                model_family: r.get(2)?,
                created_at: r.get(3)?,
                updated_at: r.get(4)?,
                message_count: cnt.max(0) as usize,
            })
        })?;
        Ok(rows.flatten().collect())
    }

    /// Loads a single conversation session and all of its ordered turns + citations.
    pub fn get_session(&self, session_id: &str) -> rusqlite::Result<Option<ChatSessionDetail>> {
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let summary: Option<ChatSessionSummary> = guard
            .query_row(
                "SELECT session_id, title, model_family, created_at, updated_at, message_count
                 FROM chat_sessions
                 WHERE session_id = ?1",
                params![session_id],
                |r| {
                    let cnt: i64 = r.get(5)?;
                    Ok(ChatSessionSummary {
                        session_id: r.get(0)?,
                        title: r.get(1)?,
                        model_family: r.get(2)?,
                        created_at: r.get(3)?,
                        updated_at: r.get(4)?,
                        message_count: cnt.max(0) as usize,
                    })
                },
            )
            .optional()?;

        let Some(session) = summary else {
            return Ok(None);
        };

        let mut stmt = guard.prepare(
            "SELECT id, session_id, role, content, citations_json, responder_peer_id, created_at
             FROM chat_messages
             WHERE session_id = ?1
             ORDER BY id ASC",
        )?;
        let mapped = stmt.query_map(params![session_id], |r| {
            let cit_raw: String = r.get(4)?;
            let citations: Vec<Citation> = serde_json::from_str(&cit_raw).unwrap_or_default();
            Ok(StoredChatMessage {
                id: r.get(0)?,
                session_id: r.get(1)?,
                role: r.get(2)?,
                content: r.get(3)?,
                citations,
                responder_peer_id: r.get(5)?,
                created_at: r.get(6)?,
            })
        })?;
        let messages: Vec<StoredChatMessage> = mapped.flatten().collect();

        Ok(Some(ChatSessionDetail { session, messages }))
    }

    /// Deletes a single conversation session and all of its messages from SQLite.
    pub fn delete_session(&self, session_id: &str) -> rusqlite::Result<bool> {
        let mut guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = guard.transaction()?;
        tx.execute(
            "DELETE FROM chat_messages WHERE session_id = ?1",
            params![session_id],
        )?;
        let removed = tx.execute(
            "DELETE FROM chat_sessions WHERE session_id = ?1",
            params![session_id],
        )?;
        tx.commit()?;
        Ok(removed > 0)
    }

    /// Deletes ALL conversation sessions and messages from SQLite, returning the deleted session count.
    pub fn delete_all_sessions(&self) -> rusqlite::Result<usize> {
        let mut guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = guard.transaction()?;
        tx.execute("DELETE FROM chat_messages", [])?;
        let removed = tx.execute("DELETE FROM chat_sessions", [])?;
        tx.commit()?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqlite_chat_history_persistence_delete_one_and_delete_all() {
        let tmp = tempfile::tempdir().unwrap();
        let db_file = tmp.path().join("chat_history.db");

        {
            let store = ChatHistoryStore::open(&db_file).expect("open store");
            let cit = Citation {
                peer_id: "12D3KooWRemotePeer".to_string(),
                file_path: "D:\\docs\\Femi_Oyesanya_AI_Security_Resume_Timeline_Fixed.pdf".to_string(),
                line_start: 1,
                line_end: 42,
                score: 0.96,
                snippet: "Principal AI Security Architect (2022–Present)".to_string(),
                node_id: Some("12D3KooWRemotePeer".to_string()),
                is_external_node: true,
                origin_label: Some("mesh".to_string()),
                node_alias: None,
            };
            store
                .record_turn(
                    "s-1001",
                    "What roles has Femi Oyesanya held according to the resume timeline?",
                    "He has served as Principal AI Security Architect [1].",
                    &[cit],
                    "12D3KooWLocalNode",
                    "AutoFusion",
                )
                .unwrap();

            store
                .record_turn(
                    "s-1002",
                    "Does Femi Oyesanya have a CISSP?",
                    "Yes, Femi Oyesanya is a CISSP-certified security professional.",
                    &[],
                    "12D3KooWLocalNode",
                    "AutoFusion",
                )
                .unwrap();
        }

        // Reopen from disk to prove durable SQLite persistence across restarts
        let reopened = ChatHistoryStore::open(&db_file).expect("reopen store");
        let sessions = reopened.list_sessions(50).unwrap();
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].session_id, "s-1002");
        assert_eq!(sessions[1].session_id, "s-1001");

        let detail = reopened
            .get_session("s-1001")
            .unwrap()
            .expect("session s-1001 exists");
        assert_eq!(detail.messages.len(), 2);
        assert_eq!(detail.messages[0].role, "user");
        assert_eq!(detail.messages[1].role, "assistant");
        assert_eq!(detail.messages[1].citations.len(), 1);
        assert_eq!(
            detail.messages[1].citations[0].node_id.as_deref(),
            Some("12D3KooWRemotePeer")
        );
        assert_eq!(detail.messages[1].responder_peer_id, "12D3KooWLocalNode");

        // Delete a single conversation (`s-1001`) and verify `s-1002` remains intact
        assert!(reopened.delete_session("s-1001").unwrap());
        assert!(reopened.get_session("s-1001").unwrap().is_none());
        let after_single_delete = reopened.list_sessions(50).unwrap();
        assert_eq!(after_single_delete.len(), 1);
        assert_eq!(after_single_delete[0].session_id, "s-1002");

        // Delete all conversations and verify database is completely empty
        let cleared = reopened.delete_all_sessions().unwrap();
        assert_eq!(cleared, 1);
        assert!(reopened.list_sessions(50).unwrap().is_empty());
    }
}
