//! Store 1: SQLite Document Catalog with FTS5 and work clustering.
//!
//! Provides single-row-per-document persistence, instant $O(1)$ work enumeration,
//! near-duplicate revision clustering (`work_cluster_id`), and full-text author/title search.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use regex::Regex;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::error::StorageError;

/// Canonical entry representing an indexed document in the catalog.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DocumentCatalogEntry {
    pub file_path: String,
    pub document_id: String,
    pub work_cluster_id: String,
    pub doc_title: String,
    pub doc_authors: String,
    pub doc_kind: String,
    pub file_name: String,
    pub file_extension: String,
    pub folder: String,
    pub normalized_stem: String,
    pub author_confidence: String,
    pub access_tier: u8,
    pub mtime_secs: i64,
    pub size_bytes: i64,
    pub chunk_count: i64,
    pub summary_excerpt: String,
    pub created_at: i64,
}

/// Normalizes file stems and collapses near-duplicate revisions and drafts into a canonical `work_cluster_id`.
///
/// Strips revision patterns such as `_v\d+`, `_final`, `_corrected`, `_rewritten`, `_typesetting`,
/// `_arxiv`, `_draft`, `_copy`, `-\d+$`, and `\(\d+\)`.
pub fn derive_work_cluster_id(file_name_or_path: &str) -> String {
    let stem = Path::new(file_name_or_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(file_name_or_path);

    let mut lower = stem.to_ascii_lowercase();
    let patterns = [
        r"_v\d+(_\d+)?",
        r"_final",
        r"_corrected",
        r"_rewritten",
        r"_typesetting",
        r"_arxiv",
        r"_draft",
        r"_copy",
        r"-\d+$",
        r"\(\d+\)",
    ];
    for pat in patterns {
        if let Ok(re) = Regex::new(pat) {
            lower = re.replace_all(&lower, "").to_string();
        }
    }
    let normalized = lower.replace(['_', '-', '.', ' '], " ");
    let parts: Vec<&str> = normalized.split_whitespace().collect();
    parts.join(" ")
}

/// Helper to parse document metadata from contextual chunk header `[Document: "..." | Author: ... | Kind: ... | File: ...]`.
pub fn parse_contextual_header(text: &str) -> Option<(String, String, String, String)> {
    if !text.starts_with("[Document:") {
        return None;
    }
    let first_line = text.lines().next()?;
    if !first_line.ends_with(']') {
        return None;
    }
    let inner = &first_line[1..first_line.len() - 1];
    let parts: Vec<&str> = inner.split(" | ").collect();
    if parts.len() < 4 {
        return None;
    }

    let title = parts[0].strip_prefix("Document: ")?.trim_matches('"').to_string();
    let author = parts[1].strip_prefix("Author: ")?.to_string();
    let kind = parts[2].strip_prefix("Kind: ")?.to_string();
    let file = parts[3].strip_prefix("File: ")?.to_string();
    Some((title, author, kind, file))
}

/// Extract title from chunk text or file path.
pub fn extract_title_from_chunk(text: &str, file_path: &str) -> String {
    if let Some((title, _, _, _)) = parse_contextual_header(text) {
        if !title.trim().is_empty() {
            return title;
        }
    }
    let file_stem = Path::new(file_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Untitled Document");
    file_stem.replace(['_', '-'], " ").trim().to_string()
}

/// Extract authors from chunk text.
pub fn extract_author_from_chunk(text: &str) -> String {
    if let Some((_, author, _, _)) = parse_contextual_header(text) {
        if !author.trim().is_empty() {
            return author;
        }
    }
    "Unknown".to_string()
}

/// Extract document kind from chunk text or file path.
pub fn extract_kind_from_chunk(text: &str, file_path: &str) -> String {
    if let Some((_, _, kind, _)) = parse_contextual_header(text) {
        if !kind.trim().is_empty() {
            return kind;
        }
    }
    let ext = Path::new(file_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    match ext.as_str() {
        "pdf" | "docx" | "doc" | "odt" | "rtf" => "article".to_string(),
        "jpg" | "jpeg" | "png" | "webp" | "bmp" => "image_ocr".to_string(),
        "mp3" | "wav" | "m4a" | "flac" => "audio".to_string(),
        "rs" | "py" | "js" | "ts" | "c" | "cpp" => "source_code".to_string(),
        _ => "general_doc".to_string(),
    }
}

/// Thread-safe SQLite Document Catalog.
pub struct DocumentCatalog {
    conn: Arc<Mutex<Connection>>,
    db_path: PathBuf,
}

impl DocumentCatalog {
    /// Opens or initializes the SQLite Document Catalog database.
    pub fn open(db_path: &Path) -> Result<Self, StorageError> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| StorageError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA temp_store = MEMORY;
             PRAGMA foreign_keys = ON;",
        )?;

        // Initialize schema
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS document_catalog (
                file_path TEXT PRIMARY KEY,
                document_id TEXT NOT NULL,
                work_cluster_id TEXT NOT NULL,
                doc_title TEXT NOT NULL,
                doc_authors TEXT NOT NULL,
                doc_kind TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_extension TEXT NOT NULL,
                folder TEXT NOT NULL,
                normalized_stem TEXT NOT NULL,
                author_confidence TEXT NOT NULL DEFAULT 'metadata',
                access_tier INTEGER NOT NULL DEFAULT 0,
                mtime_secs INTEGER NOT NULL DEFAULT 0,
                size_bytes INTEGER NOT NULL DEFAULT 0,
                chunk_count INTEGER NOT NULL DEFAULT 1,
                summary_excerpt TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_doc_catalog_cluster ON document_catalog(work_cluster_id);
            CREATE INDEX IF NOT EXISTS idx_doc_catalog_kind ON document_catalog(doc_kind);
            CREATE INDEX IF NOT EXISTS idx_doc_catalog_tier ON document_catalog(access_tier);
            CREATE INDEX IF NOT EXISTS idx_doc_catalog_folder ON document_catalog(folder);
            CREATE INDEX IF NOT EXISTS idx_doc_catalog_doc_id ON document_catalog(document_id);

            CREATE VIRTUAL TABLE IF NOT EXISTS document_catalog_fts USING fts5(
                file_path UNINDEXED,
                doc_title,
                doc_authors,
                file_name,
                summary_excerpt,
                tokenize = 'porter unicode61'
            );

            CREATE TRIGGER IF NOT EXISTS trg_doc_catalog_ai AFTER INSERT ON document_catalog BEGIN
                INSERT INTO document_catalog_fts(file_path, doc_title, doc_authors, file_name, summary_excerpt)
                VALUES (new.file_path, new.doc_title, new.doc_authors, new.file_name, new.summary_excerpt);
            END;

            CREATE TRIGGER IF NOT EXISTS trg_doc_catalog_ad AFTER DELETE ON document_catalog BEGIN
                DELETE FROM document_catalog_fts WHERE file_path = old.file_path;
            END;

            CREATE TRIGGER IF NOT EXISTS trg_doc_catalog_au AFTER UPDATE ON document_catalog BEGIN
                DELETE FROM document_catalog_fts WHERE file_path = old.file_path;
                INSERT INTO document_catalog_fts(file_path, doc_title, doc_authors, file_name, summary_excerpt)
                VALUES (new.file_path, new.doc_title, new.doc_authors, new.file_name, new.summary_excerpt);
            END;",
        )?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path: db_path.to_path_buf(),
        })
    }

    /// Access the file path of this catalog.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Inserts or replaces a document catalog entry.
    pub fn upsert_entry(&self, entry: &DocumentCatalogEntry) -> Result<(), StorageError> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO document_catalog (
                file_path, document_id, work_cluster_id, doc_title, doc_authors, doc_kind,
                file_name, file_extension, folder, normalized_stem, author_confidence,
                access_tier, mtime_secs, size_bytes, chunk_count, summary_excerpt, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
            ON CONFLICT(file_path) DO UPDATE SET
                document_id = excluded.document_id,
                work_cluster_id = excluded.work_cluster_id,
                doc_title = excluded.doc_title,
                doc_authors = excluded.doc_authors,
                doc_kind = excluded.doc_kind,
                file_name = excluded.file_name,
                file_extension = excluded.file_extension,
                folder = excluded.folder,
                normalized_stem = excluded.normalized_stem,
                author_confidence = excluded.author_confidence,
                access_tier = excluded.access_tier,
                mtime_secs = excluded.mtime_secs,
                size_bytes = excluded.size_bytes,
                chunk_count = excluded.chunk_count,
                summary_excerpt = excluded.summary_excerpt;",
            params![
                entry.file_path,
                entry.document_id,
                entry.work_cluster_id,
                entry.doc_title,
                entry.doc_authors,
                entry.doc_kind,
                entry.file_name,
                entry.file_extension,
                entry.folder,
                entry.normalized_stem,
                entry.author_confidence,
                entry.access_tier,
                entry.mtime_secs,
                entry.size_bytes,
                entry.chunk_count,
                entry.summary_excerpt,
                entry.created_at,
            ],
        )?;
        Ok(())
    }

    /// Deletes a document entry by its file path.
    pub fn delete_by_file_path(&self, file_path: &str) -> Result<bool, StorageError> {
        let conn = self.conn.lock();
        let rows = conn.execute(
            "DELETE FROM document_catalog WHERE file_path = ?1",
            params![file_path],
        )?;
        Ok(rows > 0)
    }

    /// Retrieves an entry by its exact file path.
    pub fn get_by_file_path(&self, file_path: &str) -> Result<Option<DocumentCatalogEntry>, StorageError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT file_path, document_id, work_cluster_id, doc_title, doc_authors, doc_kind,
                    file_name, file_extension, folder, normalized_stem, author_confidence,
                    access_tier, mtime_secs, size_bytes, chunk_count, summary_excerpt, created_at
             FROM document_catalog WHERE file_path = ?1",
        )?;

        let mut rows = stmt.query(params![file_path])?;
        if let Some(row) = rows.next()? {
            Ok(Some(Self::row_to_entry(row)?))
        } else {
            Ok(None)
        }
    }

    /// Returns the total number of documents in the catalog.
    pub fn count_documents(&self) -> Result<usize, StorageError> {
        let conn = self.conn.lock();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM document_catalog",
            [],
            |r| r.get(0),
        )?;
        Ok(count as usize)
    }

    /// Enumerates distinct matching documents across title, author, filename, or summary, collapsed by `work_cluster_id`.
    pub fn catalog_find_documents(&self, query: &str, limit: usize) -> Result<Vec<DocumentCatalogEntry>, StorageError> {
        self.catalog_find_documents_extended(query, None, 3, limit)
    }

    /// Extended catalog search supporting doc_kind filtering and access tier constraints, collapsed by `work_cluster_id`.
    pub fn catalog_find_documents_extended(
        &self,
        query: &str,
        doc_kinds: Option<&[&str]>,
        max_tier: u8,
        limit: usize,
    ) -> Result<Vec<DocumentCatalogEntry>, StorageError> {
        let conn = self.conn.lock();
        let trimmed = query.trim();

        // If query is empty or wildcard "*", return recent documents ordered by mtime
        if trimmed.is_empty() || trimmed == "*" {
            let mut sql = String::from(
                "SELECT file_path, document_id, work_cluster_id, doc_title, doc_authors, doc_kind,
                        file_name, file_extension, folder, normalized_stem, author_confidence,
                        access_tier, mtime_secs, size_bytes, chunk_count, summary_excerpt, created_at
                 FROM document_catalog
                 WHERE access_tier <= ?1",
            );
            if let Some(kinds) = doc_kinds {
                if !kinds.is_empty() {
                    let kind_list = kinds.iter().map(|k| format!("'{}'", k.replace('\'', "''"))).collect::<Vec<_>>().join(",");
                    sql.push_str(&format!(" AND doc_kind IN ({})", kind_list));
                }
            }
            sql.push_str(" GROUP BY work_cluster_id ORDER BY mtime_secs DESC LIMIT ?2;");

            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(params![max_tier, limit as i64], Self::row_to_entry)?;
            let mut entries = Vec::new();
            for r in rows {
                entries.push(r?);
            }
            return Ok(entries);
        }

        // Try FTS5 MATCH first
        let fts_query = sanitize_fts5_query(trimmed);
        let fts_result = (|| -> Result<Vec<DocumentCatalogEntry>, StorageError> {
            let mut sql = String::from(
                "SELECT c.file_path, c.document_id, c.work_cluster_id, c.doc_title, c.doc_authors, c.doc_kind,
                        c.file_name, c.file_extension, c.folder, c.normalized_stem, c.author_confidence,
                        c.access_tier, c.mtime_secs, c.size_bytes, c.chunk_count, c.summary_excerpt, c.created_at
                 FROM document_catalog_fts fts
                 JOIN document_catalog c ON c.file_path = fts.file_path
                 WHERE document_catalog_fts MATCH ?1 AND c.access_tier <= ?2",
            );
            if let Some(kinds) = doc_kinds {
                if !kinds.is_empty() {
                    let kind_list = kinds.iter().map(|k| format!("'{}'", k.replace('\'', "''"))).collect::<Vec<_>>().join(",");
                    sql.push_str(&format!(" AND c.doc_kind IN ({})", kind_list));
                }
            }
            sql.push_str(" GROUP BY c.work_cluster_id ORDER BY fts.rank ASC, c.mtime_secs DESC LIMIT ?3;");

            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(params![fts_query, max_tier, limit as i64], Self::row_to_entry)?;
            let mut entries = Vec::new();
            for r in rows {
                entries.push(r?);
            }
            Ok(entries)
        })();

        if let Ok(entries) = fts_result {
            if !entries.is_empty() {
                return Ok(entries);
            }
        }

        // Fallback: LIKE substring match across doc_title, doc_authors, file_name, summary_excerpt
        let like_pattern = format!("%{}%", trimmed.replace('%', "\\%").replace('_', "\\_"));
        let mut sql = String::from(
            "SELECT file_path, document_id, work_cluster_id, doc_title, doc_authors, doc_kind,
                    file_name, file_extension, folder, normalized_stem, author_confidence,
                    access_tier, mtime_secs, size_bytes, chunk_count, summary_excerpt, created_at
             FROM document_catalog
             WHERE (doc_title LIKE ?1 ESCAPE '\\'
                 OR doc_authors LIKE ?1 ESCAPE '\\'
                 OR file_name LIKE ?1 ESCAPE '\\'
                 OR summary_excerpt LIKE ?1 ESCAPE '\\')
               AND access_tier <= ?2",
        );
        if let Some(kinds) = doc_kinds {
            if !kinds.is_empty() {
                let kind_list = kinds.iter().map(|k| format!("'{}'", k.replace('\'', "''"))).collect::<Vec<_>>().join(",");
                sql.push_str(&format!(" AND doc_kind IN ({})", kind_list));
            }
        }
        sql.push_str(" GROUP BY work_cluster_id ORDER BY mtime_secs DESC LIMIT ?3;");

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![like_pattern, max_tier, limit as i64], Self::row_to_entry)?;
        let mut entries = Vec::new();
        for r in rows {
            entries.push(r?);
        }
        Ok(entries)
    }

    /// Hydrates the document catalog from an existing slice of chunks in a single batched transaction.
    pub fn hydrate_from_chunks(&self, chunks: &[quorum_types::DocumentChunk]) -> Result<usize, StorageError> {
        if chunks.is_empty() {
            return Ok(0);
        }

        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;

        // Group chunks by file_path
        let mut doc_map: HashMap<String, Vec<&quorum_types::DocumentChunk>> = HashMap::new();
        for chunk in chunks {
            doc_map.entry(chunk.file_path.clone()).or_default().push(chunk);
        }

        let mut count = 0;
        for (file_path, file_chunks) in doc_map {
            // Find chunk 0 or first chunk
            let primary = file_chunks
                .iter()
                .find(|c| c.chunk_id.ends_with(":0"))
                .copied()
                .unwrap_or(file_chunks[0]);

            let path_obj = Path::new(&file_path);
            let file_name = path_obj.file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string();
            let file_ext = path_obj.extension().and_then(|e| e.to_str()).unwrap_or("").to_string();
            let folder = path_obj.parent().and_then(|p| p.to_str()).unwrap_or("").to_string();
            let normalized_stem = derive_work_cluster_id(&file_name);
            let work_cluster_id = normalized_stem.clone();

            let doc_title = extract_title_from_chunk(&primary.text_content, &file_path);
            let doc_authors = extract_author_from_chunk(&primary.text_content);
            let doc_kind = extract_kind_from_chunk(&primary.text_content, &file_path);
            let summary_excerpt = primary.text_content.chars().take(400).collect::<String>();

            tx.execute(
                "INSERT INTO document_catalog (
                    file_path, document_id, work_cluster_id, doc_title, doc_authors, doc_kind,
                    file_name, file_extension, folder, normalized_stem, author_confidence,
                    access_tier, mtime_secs, size_bytes, chunk_count, summary_excerpt, created_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
                ON CONFLICT(file_path) DO NOTHING;",
                params![
                    file_path,
                    primary.document_id,
                    work_cluster_id,
                    doc_title,
                    doc_authors,
                    doc_kind,
                    file_name,
                    file_ext,
                    folder,
                    normalized_stem,
                    "metadata",
                    primary.access_tier,
                    0i64,
                    0i64,
                    file_chunks.len() as i64,
                    summary_excerpt,
                    chrono::Utc::now().timestamp(),
                ],
            )?;
            count += 1;
        }

        tx.commit()?;
        Ok(count)
    }

    /// Hydrates the document catalog from the storage engine's stored Tantivy chunks if currently empty.
    pub fn hydrate_document_catalog_if_needed(&self, storage: &crate::engine::StorageEngine) -> Result<usize, StorageError> {
        if self.count_documents()? > 0 {
            return Ok(0);
        }
        let chunks = storage.scan_all_chunks_fast()?;
        if chunks.is_empty() {
            return Ok(0);
        }
        self.hydrate_from_chunks(&chunks)
    }

    fn row_to_entry(row: &rusqlite::Row) -> rusqlite::Result<DocumentCatalogEntry> {
        Ok(DocumentCatalogEntry {
            file_path: row.get(0)?,
            document_id: row.get(1)?,
            work_cluster_id: row.get(2)?,
            doc_title: row.get(3)?,
            doc_authors: row.get(4)?,
            doc_kind: row.get(5)?,
            file_name: row.get(6)?,
            file_extension: row.get(7)?,
            folder: row.get(8)?,
            normalized_stem: row.get(9)?,
            author_confidence: row.get(10)?,
            access_tier: row.get(11)?,
            mtime_secs: row.get(12)?,
            size_bytes: row.get(13)?,
            chunk_count: row.get(14)?,
            summary_excerpt: row.get(15)?,
            created_at: row.get(16)?,
        })
    }
}

/// Helper: Sanitizes a query string for safe use in SQLite FTS5 MATCH expressions.
fn sanitize_fts5_query(query: &str) -> String {
    let tokens: Vec<String> = query
        .split(|c: char| c.is_whitespace() || c.is_ascii_punctuation())
        .filter(|t| !t.is_empty())
        .map(|t| format!("\"{}\"", t.replace('"', "")))
        .collect();

    if tokens.is_empty() {
        "\"*\"".to_string()
    } else {
        tokens.join(" AND ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_derive_work_cluster_id_collapses_revisions() {
        assert_eq!(derive_work_cluster_id("RedactX_v3_final.pdf"), "redactx");
        assert_eq!(derive_work_cluster_id("RedactX_v3_typesetting.pdf"), "redactx");
        assert_eq!(derive_work_cluster_id("ACDSO_v2_draft.pdf"), "acdso");
        assert_eq!(derive_work_cluster_id("paper_v1 (1).pdf"), "paper");
        assert_eq!(derive_work_cluster_id("Femi_Oyesanya_CV_2026.pdf"), "femi oyesanya cv 2026");
    }

    #[test]
    fn test_document_catalog_crud_and_fts() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("document_catalog.db");
        let catalog = DocumentCatalog::open(&db_path).expect("open catalog");

        let entry1 = DocumentCatalogEntry {
            file_path: "D:/docs/RedactX_v1.pdf".to_string(),
            document_id: "doc-1".to_string(),
            work_cluster_id: "redactx".to_string(),
            doc_title: "RedactX: Privacy First redaction".to_string(),
            doc_authors: "Femi Oyesanya".to_string(),
            doc_kind: "research_paper".to_string(),
            file_name: "RedactX_v1.pdf".to_string(),
            file_extension: "pdf".to_string(),
            folder: "D:/docs".to_string(),
            normalized_stem: "redactx".to_string(),
            author_confidence: "verified_byline".to_string(),
            access_tier: 0,
            mtime_secs: 1000,
            size_bytes: 50000,
            chunk_count: 5,
            summary_excerpt: "An architectural paper on privacy".to_string(),
            created_at: 1000,
        };

        let entry2 = DocumentCatalogEntry {
            file_path: "D:/docs/RedactX_v2_final.pdf".to_string(),
            document_id: "doc-2".to_string(),
            work_cluster_id: "redactx".to_string(),
            doc_title: "RedactX: Privacy First redaction (Final)".to_string(),
            doc_authors: "Femi Oyesanya".to_string(),
            doc_kind: "research_paper".to_string(),
            file_name: "RedactX_v2_final.pdf".to_string(),
            file_extension: "pdf".to_string(),
            folder: "D:/docs".to_string(),
            normalized_stem: "redactx".to_string(),
            author_confidence: "verified_byline".to_string(),
            access_tier: 0,
            mtime_secs: 2000,
            size_bytes: 52000,
            chunk_count: 6,
            summary_excerpt: "An architectural paper on privacy final".to_string(),
            created_at: 2000,
        };

        let entry3 = DocumentCatalogEntry {
            file_path: "D:/docs/QuorumRAG_Arch.pdf".to_string(),
            document_id: "doc-3".to_string(),
            work_cluster_id: "quorumrag arch".to_string(),
            doc_title: "QuorumRAG Architecture".to_string(),
            doc_authors: "Quorum Team".to_string(),
            doc_kind: "article".to_string(),
            file_name: "QuorumRAG_Arch.pdf".to_string(),
            file_extension: "pdf".to_string(),
            folder: "D:/docs".to_string(),
            normalized_stem: "quorumrag arch".to_string(),
            author_confidence: "metadata".to_string(),
            access_tier: 0,
            mtime_secs: 3000,
            size_bytes: 40000,
            chunk_count: 4,
            summary_excerpt: "Federated RAG architecture with mesh consensus".to_string(),
            created_at: 3000,
        };

        catalog.upsert_entry(&entry1).unwrap();
        catalog.upsert_entry(&entry2).unwrap();
        catalog.upsert_entry(&entry3).unwrap();

        assert_eq!(catalog.count_documents().unwrap(), 3);

        // Find by author "Femi Oyesanya" -> collapses 2 revisions of RedactX into 1 work cluster
        let femi_docs = catalog.catalog_find_documents("Femi Oyesanya", 10).unwrap();
        assert_eq!(femi_docs.len(), 1, "Expected 1 collapsed work cluster for RedactX, got: {:?}", femi_docs);
        assert_eq!(femi_docs[0].work_cluster_id, "redactx");

        // Find by topic "QuorumRAG"
        let quorum_docs = catalog.catalog_find_documents("QuorumRAG", 10).unwrap();
        assert_eq!(quorum_docs.len(), 1);
        assert_eq!(quorum_docs[0].work_cluster_id, "quorumrag arch");

        // Delete entry1
        catalog.delete_by_file_path("D:/docs/RedactX_v1.pdf").unwrap();
        assert_eq!(catalog.count_documents().unwrap(), 2);
    }
}
