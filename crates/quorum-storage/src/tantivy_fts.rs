//! Co-located Tantivy BM25 full-text search index.
//!
//! # Invariant: Absolute Arrow Isolation
//! All types and internal Tantivy dependencies are strictly `pub(crate)`.

use std::collections::BTreeSet;
use std::fs::create_dir_all;
use std::ops::Bound;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use quorum_types::{DocumentChunk, ScoredChunk};
use tantivy::collector::{Count, TopDocs};
use tantivy::merge_policy::NoMergePolicy;
use tantivy::query::{BooleanQuery, QueryParser, RangeQuery, TermQuery};
use tantivy::schema::*;
use tantivy::index::SegmentId;
use tantivy::{Index, IndexReader, IndexWriter, TantivyDocument, Term};

use crate::error::StorageError;

/// Verification criteria applied during reader synchronization to ensure
/// read-your-writes coherence for specific operations.
#[derive(Debug, Clone, Copy)]
enum SyncCheck<'a> {
    /// General synchronization (verifies commit sequence and metadata parity).
    None,
    /// Verifies that a specific chunk_id is present and searchable.
    DocPresent { chunk_id: &'a str },
    /// Verifies that a specific chunk_id has been purged / marked deleted.
    DocAbsent { chunk_id: &'a str },
    /// Verifies that all documents with the specified file_path have been purged.
    FilePathAbsent { file_path: &'a str },
    /// Verifies that all documents have been cleared (`num_docs == 0`).
    AllCleared,
}

/// Helper to parse the monotonic commit sequence number embedded in Tantivy's `IndexMeta.payload`.
fn parse_commit_seq(meta: &tantivy::IndexMeta) -> u64 {
    if let Some(ref p) = meta.payload {
        if let Some(val) = p.strip_prefix("seq:") {
            if let Ok(seq) = val.parse::<u64>() {
                return seq;
            }
        }
    }
    0
}

/// Tantivy inverted index providing BM25 keyword search with access-tier filtering.
pub(crate) struct TantivyFtsIndex {
    index: Index,
    reader: IndexReader,
    writer: Mutex<Option<IndexWriter<TantivyDocument>>>,
    last_commit_opstamp: AtomicU64,
    last_commit_seq: AtomicU64,
    synced_seq: AtomicU64,
    field_chunk_id: Field,
    field_document_id: Field,
    field_file_path: Field,
    field_file_path_text: Field,
    field_line_start: Field,
    field_line_end: Field,
    field_blake3_hash: Field,
    field_access_tier: Field,
    field_text_content: Field,
    field_metadata_json: Field,
    field_vector_bytes: Field,
}

impl TantivyFtsIndex {
    /// Helper to instantiate a new IndexWriter configured with NoMergePolicy, retrying on transient Windows file lock delays.
    fn create_writer_inner(index: &Index) -> Result<IndexWriter<TantivyDocument>, StorageError> {
        let mut attempts = 0;
        loop {
            match index.writer_with_num_threads::<TantivyDocument>(1, 50_000_000) {
                Ok(writer) => {
                    writer.set_merge_policy(Box::new(NoMergePolicy));
                    return Ok(writer);
                }
                Err(e) => {
                    attempts += 1;
                    if attempts >= 25 {
                        return Err(StorageError::Tantivy(format!(
                            "Failed to create Tantivy writer after {} attempts: {}", attempts, e
                        )));
                    }
                    std::thread::yield_now();
                    std::thread::sleep(std::time::Duration::from_millis(10 * attempts as u64));
                }
            }
        }
    }

    /// Accesses the active writer, instantiating one if currently None.
    fn get_or_recreate_writer<'a>(
        index: &Index,
        guard: &'a mut Option<IndexWriter<TantivyDocument>>,
    ) -> Result<&'a mut IndexWriter<TantivyDocument>, StorageError> {
        if guard.is_none() {
            *guard = Some(Self::create_writer_inner(index)?);
        }
        Ok(guard.as_mut().expect("writer initialized"))
    }

    /// Drops any existing IndexWriter to release `.tantivy-writer.lock` before creating a fresh writer.
    fn recreate_writer(
        index: &Index,
        guard: &mut Option<IndexWriter<TantivyDocument>>,
    ) -> Result<(), StorageError> {
        *guard = None;
        std::thread::yield_now();
        std::thread::sleep(std::time::Duration::from_millis(5));
        *guard = Some(Self::create_writer_inner(index)?);
        Ok(())
    }

    /// Opens or creates the Tantivy index at `path`.
    pub(crate) fn open(path: &Path) -> Result<Self, StorageError> {
        create_dir_all(path).map_err(|e| StorageError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        let mut builder = Schema::builder();
        let field_chunk_id = builder.add_text_field("chunk_id", STRING | STORED);
        let field_document_id = builder.add_text_field("document_id", STRING | STORED);
        let field_file_path = builder.add_text_field("file_path", STRING | STORED);
        let field_file_path_text = builder.add_text_field("file_path_text", TEXT);
        let field_line_start = builder.add_u64_field("line_start", FAST | STORED);
        let field_line_end = builder.add_u64_field("line_end", FAST | STORED);
        let field_blake3_hash = builder.add_text_field("blake3_hash", STRING | STORED);
        let field_access_tier = builder.add_u64_field("access_tier", FAST | STORED | INDEXED);
        let field_text_content = builder.add_text_field("text_content", TEXT | STORED);
        let field_metadata_json = builder.add_text_field("metadata_json", STRING | STORED);
        let field_vector_bytes = builder.add_bytes_field("vector_bytes", STORED);
        let schema = builder.build();

        let index = Index::open_in_dir(path)
            .or_else(|_| Index::create_in_dir(path, schema))
            .map_err(|e| StorageError::Tantivy(e.to_string()))?;

        let writer = Self::create_writer_inner(&index)?;

        let reader = index
            .reader_builder()
            .reload_policy(tantivy::ReloadPolicy::Manual)
            .try_into()
            .map_err(|e| StorageError::Tantivy(format!("Failed to create Tantivy reader: {}", e)))?;

        let (initial_opstamp, initial_seq) = match index.load_metas() {
            Ok(m) => {
                let seq = parse_commit_seq(&m);
                (m.opstamp, seq)
            }
            Err(_) => (0, 0),
        };
        let last_commit_opstamp = AtomicU64::new(initial_opstamp);
        let last_commit_seq = AtomicU64::new(initial_seq);
        let synced_seq = AtomicU64::new(initial_seq);

        Ok(Self {
            index,
            reader,
            writer: Mutex::new(Some(writer)),
            last_commit_opstamp,
            last_commit_seq,
            synced_seq,
            field_chunk_id,
            field_document_id,
            field_file_path,
            field_file_path_text,
            field_line_start,
            field_line_end,
            field_blake3_hash,
            field_access_tier,
            field_text_content,
            field_metadata_json,
            field_vector_bytes,
        })
    }

    /// Converts a domain DocumentChunk into a TantivyDocument.
    fn chunk_to_doc(&self, c: &DocumentChunk) -> TantivyDocument {
        let mut doc = TantivyDocument::default();
        doc.add_text(self.field_chunk_id, &c.chunk_id);
        doc.add_text(self.field_document_id, &c.document_id);
        doc.add_text(self.field_file_path, &c.file_path);
        let normalized_path_tokens = c.file_path.replace(['_', '-', '\\', '/', '.'], " ");
        doc.add_text(
            self.field_file_path_text,
            &format!("{} {}", c.file_path, normalized_path_tokens),
        );
        doc.add_u64(self.field_line_start, c.line_start as u64);
        doc.add_u64(self.field_line_end, c.line_end as u64);
        doc.add_text(self.field_blake3_hash, &c.blake3_hash);
        doc.add_u64(self.field_access_tier, c.access_tier as u64);
        doc.add_text(self.field_text_content, &c.text_content);
        doc.add_text(self.field_metadata_json, &c.metadata_json);

        let mut vec_bytes = Vec::with_capacity(c.vector.len() * 4);
        for &f in &c.vector {
            vec_bytes.extend_from_slice(&f.to_le_bytes());
        }
        doc.add_bytes(self.field_vector_bytes, &vec_bytes);
        doc
    }

    /// Indexes a slice of chunks into the Tantivy BM25 inverted index.
    ///
    /// Implements full batch-replay recovery: if the underlying Tantivy IndexWriter
    /// is killed or panics during `add_document` or `commit`, a fresh writer is
    /// instantiated and all chunks in the batch are replayed from chunk 0.
    pub(crate) fn index_chunks(&self, chunks: &[DocumentChunk]) -> Result<usize, StorageError> {
        if chunks.is_empty() {
            return Ok(0);
        }

        let mut writer_guard = self
            .writer
            .lock()
            .map_err(|_| StorageError::Tantivy("Tantivy index writer mutex poisoned".into()))?;

        let mut recovery_attempts = 0;
        const MAX_RECOVERIES: usize = 10;

        'batch_attempt: loop {
            let add_err = {
                let writer = Self::get_or_recreate_writer(&self.index, &mut writer_guard)?;

                let mut err = None;
                for c in chunks {
                    let doc = self.chunk_to_doc(c);
                    if let Err(e) = writer.add_document(doc) {
                        err = Some(e);
                        break;
                    }
                }
                err
            };

            if let Some(e) = add_err {
                tracing::warn!(
                    "Tantivy writer failed during add_document (attempt {} of {}); re-creating and replaying batch: {}",
                    recovery_attempts + 1,
                    MAX_RECOVERIES,
                    e
                );
                recovery_attempts += 1;
                if recovery_attempts > MAX_RECOVERIES {
                    return Err(StorageError::Tantivy(format!(
                        "Exceeded maximum writer recoveries ({}) during add_document: {}",
                        MAX_RECOVERIES, e
                    )));
                }
                Self::recreate_writer(&self.index, &mut writer_guard)?;
                // Replay the full batch from index 0 on the fresh writer
                continue 'batch_attempt;
            }

            let next_seq = self.last_commit_seq.fetch_add(1, Ordering::SeqCst) + 1;
            let commit_res = {
                let writer = Self::get_or_recreate_writer(&self.index, &mut writer_guard)?;
                commit_single(writer, Some(&format!("seq:{}", next_seq)))
            };

            match commit_res {
                Ok(op) => {
                    self.last_commit_opstamp.store(op, Ordering::Release);
                }
                Err(e) => {
                    tracing::warn!(
                        "Tantivy writer failed during commit (attempt {} of {}); re-creating and replaying batch: {}",
                        recovery_attempts + 1,
                        MAX_RECOVERIES,
                        e
                    );
                    recovery_attempts += 1;
                    if recovery_attempts > MAX_RECOVERIES {
                        return Err(StorageError::Tantivy(format!(
                            "Exceeded maximum writer recoveries ({}) during commit: {}",
                            MAX_RECOVERIES, e
                        )));
                    }
                    Self::recreate_writer(&self.index, &mut writer_guard)?;
                    // Replay the full batch from index 0 on the fresh writer
                    continue 'batch_attempt;
                }
            }

            break 'batch_attempt;
        }

        drop(writer_guard);

        // Verify that the first chunk is discoverable before returning
        let first_chunk_id = &chunks[0].chunk_id;
        self.reload_with_retry(SyncCheck::DocPresent { chunk_id: first_chunk_id })?;

        Ok(chunks.len())
    }

    /// Executes BM25 full-text search with `access_tier <= max_tier` filtering.
    pub(crate) fn search(
        &self,
        query_text: &str,
        max_tier: u8,
        top_k: usize,
    ) -> Result<Vec<ScoredChunk>, StorageError> {
        let trimmed = query_text.trim();
        if trimmed.is_empty() || top_k == 0 {
            return Ok(Vec::new());
        }

        tracing::info!(query = %trimmed, "TantivyFtsIndex::search start");
        self.reload_with_retry(SyncCheck::None)?;
        tracing::info!("TantivyFtsIndex::search reload_with_retry done");
        let searcher = self.reader.searcher();
        if searcher.num_docs() == 0 {
            return Ok(Vec::new());
        }
        let mut query_parser = QueryParser::for_index(
            &self.index,
            vec![self.field_text_content, self.field_file_path_text],
        );
        query_parser.set_field_boost(self.field_file_path_text, 3.0);

        let has_explicit_syntax = trimmed.contains(':')
            || trimmed.contains('"')
            || trimmed.contains('+')
            || trimmed.contains('*');

        let effective_query_str: String = if !has_explicit_syntax {
            const QUESTION_STOPWORDS: &[&str] = &[
                "what", "does", "do", "did", "where", "when", "who", "how", "why",
                "is", "are", "was", "were", "the", "a", "an", "to", "for", "of",
                "in", "on", "at", "with", "from", "by", "about", "go", "fo", "went",
                "attend", "attended", "tell", "me", "can", "you", "please", "his", "her", "their",
            ];
            // Remove conversational framing ("show me the file that contains a ...",
            // "are there pictures taken in ...") so only the subject drives BM25.
            let subject = crate::query_framing::strip_conversational_framing(trimmed);
            let subject_src: &str = if subject.is_empty() { trimmed } else { subject.as_str() };
            let sanitized: String = subject_src
                .chars()
                .map(|c| if c.is_alphanumeric() || c == '_' { c } else { ' ' })
                .collect();
            let mut content_terms: Vec<&str> = sanitized
                .split_whitespace()
                .filter(|w| !QUESTION_STOPWORDS.contains(&w.to_ascii_lowercase().as_str()))
                .collect();
            let lower_q = trimmed.to_ascii_lowercase();
            if lower_q.contains("school") || lower_q.contains("college") || lower_q.contains("education") {
                content_terms.push("university");
                content_terms.push("transcript");
            }
            if content_terms.is_empty() {
                trimmed.to_string()
            } else {
                content_terms.join(" ")
            }
        } else {
            trimmed.to_string()
        };

        // Parse query with fallback if query has syntax chars
        let parsed_query = query_parser.parse_query(&effective_query_str).or_else(|_| {
            let sanitized: String = trimmed
                .chars()
                .map(|c| if c.is_alphanumeric() { c } else { ' ' })
                .collect();
            let terms: Vec<&str> = sanitized.split_whitespace().collect();
            if terms.is_empty() {
                query_parser.parse_query("*")
            } else {
                query_parser.parse_query(&terms.join(" "))
            }
        });

        let text_query = match parsed_query {
            Ok(q) => q,
            Err(_) => return Ok(Vec::new()),
        };

        let tier_range = RangeQuery::new(
            Bound::Included(Term::from_field_u64(self.field_access_tier, 0)),
            Bound::Included(Term::from_field_u64(self.field_access_tier, max_tier as u64)),
        );

        let combined = BooleanQuery::intersection(vec![text_query, Box::new(tier_range)]);
        let num_docs = searcher.num_docs() as usize;
        // Over-fetch when the index is large so monolithic dumps (chat.html, conversations-*.json)
        // or source code files never crowd out real PDF/DOCX documents before top_k truncation.
        let fetch_limit = if num_docs > 500 {
            top_k.saturating_mul(3).max(96).min(180).min(num_docs.max(1))
        } else {
            top_k.min(num_docs.max(1))
        };
        let top_docs = searcher
            .search(&combined, &TopDocs::with_limit(fetch_limit).order_by_score())
            .map_err(|e| StorageError::Tantivy(format!("Search execution failed: {}", e)))?;

        let mut primary_chunks = Vec::with_capacity(top_k.min(top_docs.len()));
        let mut fallback_chunks = Vec::new();
        for (score, doc_address) in top_docs {
            let doc: TantivyDocument = searcher
                .doc(doc_address)
                .map_err(|e| StorageError::Tantivy(format!("Failed to retrieve document: {}", e)))?;

            let chunk = self.doc_to_chunk(&doc);
            let path_l = chunk.file_path.to_ascii_lowercase();
            let file_l = std::path::Path::new(&chunk.file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();

            if file_l.starts_with('~')
                || file_l.starts_with(".~lock")
                || file_l == "chat.html"
                || (file_l.starts_with("conversations-") && file_l.ends_with(".json"))
            {
                continue;
            }

            // Indexed media (audio/image chunks) are user content even inside a repo tree such as
            // D:\harfile\music, so only code/config files under the repo root are demoted.
            let is_media_chunk = chunk.text_content.trim_start().starts_with("[Audio Document:")
                || chunk.text_content.trim_start().starts_with("[Image Document:")
                || chunk.text_content.trim_start().starts_with("[Video Document:");
            let is_low_priority_code_or_repo = (!is_media_chunk
                && (path_l.contains("\\harfile\\") || path_l.contains("/harfile/")))
                || file_l.ends_with(".rs")
                || file_l.ends_with(".py")
                || file_l.ends_with(".js")
                || file_l.ends_with(".ts")
                || file_l.ends_with(".json")
                || file_l.ends_with(".toml")
                || file_l.ends_with(".lock");

            let scored = ScoredChunk::new(chunk, score, "local", false);
            if is_low_priority_code_or_repo {
                fallback_chunks.push(scored);
            } else {
                primary_chunks.push(scored);
                if primary_chunks.len() >= top_k {
                    break;
                }
            }
        }

        if primary_chunks.len() < top_k {
            for c in fallback_chunks {
                primary_chunks.push(c);
                if primary_chunks.len() >= top_k {
                    break;
                }
            }
        }
        let mut scored_chunks = primary_chunks;

        scored_chunks.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.chunk.chunk_id.cmp(&b.chunk.chunk_id))
        });

        Ok(scored_chunks)
    }

    /// Returns the lowest `access_tier` among chunks whose stored `file_path` equals `file_path`
    /// exactly, or `None` when the path is not part of the index.
    pub(crate) fn indexed_path_min_tier(&self, file_path: &str) -> Result<Option<u8>, StorageError> {
        self.reload_with_retry(SyncCheck::None)?;
        let searcher = self.reader.searcher();
        let term = Term::from_field_text(self.field_file_path, file_path);
        let query = TermQuery::new(term, IndexRecordOption::Basic);
        let hits = searcher
            .search(&query, &TopDocs::with_limit(64).order_by_score())
            .map_err(|e| StorageError::Tantivy(e.to_string()))?;
        let mut min_tier: Option<u8> = None;
        for (_score, addr) in hits {
            let doc: TantivyDocument = searcher
                .doc(addr)
                .map_err(|e| StorageError::Tantivy(e.to_string()))?;
            let chunk = self.doc_to_chunk(&doc);
            min_tier = Some(min_tier.map_or(chunk.access_tier, |t: u8| t.min(chunk.access_tier)));
        }
        Ok(min_tier)
    }

    /// Checks if a chunk hash already exists in the Tantivy index.
    pub(crate) fn has_chunk_hash(&self, blake3_hash: &str) -> Result<bool, StorageError> {
        self.reload_with_retry(SyncCheck::None)?;
        let searcher = self.reader.searcher();
        let term = Term::from_field_text(self.field_blake3_hash, blake3_hash);
        let query = TermQuery::new(term, IndexRecordOption::Basic);
        let hits = searcher
            .search(&query, &TopDocs::with_limit(1).order_by_score())
            .map_err(|e| StorageError::Tantivy(e.to_string()))?;
        Ok(!hits.is_empty())
    }

    /// Deletes all indexed documents matching the specified `file_path`.
    pub(crate) fn delete_by_file_path(&self, file_path: &str) -> Result<usize, StorageError> {
        self.reload_with_retry(SyncCheck::None)?;
        let term = Term::from_field_text(self.field_file_path, file_path);
        let query = TermQuery::new(term.clone(), IndexRecordOption::Basic);
        let searcher = self.reader.searcher();
        let count = searcher
            .search(&query, &Count)
            .map_err(|e| StorageError::Tantivy(format!("Count matching documents failed: {}", e)))?;

        if count == 0 {
            return Ok(0);
        }

        let mut writer_guard = self
            .writer
            .lock()
            .map_err(|_| StorageError::Tantivy("Tantivy writer mutex poisoned".into()))?;

        let mut recovery_attempts = 0;
        const MAX_RECOVERIES: usize = 10;
        'delete_attempt: loop {
            let next_seq = self.last_commit_seq.fetch_add(1, Ordering::SeqCst) + 1;
            let delete_res = {
                let writer = Self::get_or_recreate_writer(&self.index, &mut writer_guard)?;
                let _ = writer.delete_term(term.clone());
                commit_single(writer, Some(&format!("seq:{}", next_seq)))
            };

            match delete_res {
                Ok(op) => {
                    self.last_commit_opstamp.store(op, Ordering::Release);
                    break 'delete_attempt;
                }
                Err(e) => {
                    tracing::warn!(
                        "Tantivy delete_by_file_path failed during commit (attempt {} of {}); recreating writer: {}",
                        recovery_attempts + 1,
                        MAX_RECOVERIES,
                        e
                    );
                    recovery_attempts += 1;
                    if recovery_attempts > MAX_RECOVERIES {
                        return Err(StorageError::Tantivy(format!(
                            "Exceeded maximum writer recoveries ({}) during delete: {}",
                            MAX_RECOVERIES, e
                        )));
                    }
                    Self::recreate_writer(&self.index, &mut writer_guard)?;
                    continue 'delete_attempt;
                }
            }
        }

        drop(writer_guard);
        self.reload_with_retry(SyncCheck::FilePathAbsent { file_path })?;

        Ok(count)
    }

    /// Merges Tantivy index segments to reclaim deleted space and consolidate inverted indexes.
    pub(crate) fn compact(&self) -> Result<(), StorageError> {
        let mut writer_guard = self
            .writer
            .lock()
            .map_err(|_| StorageError::Tantivy("Tantivy writer mutex poisoned".into()))?;

        // 1. Commit any pending uncommitted additions/deletions before merging
        let pre_seq = self.last_commit_seq.fetch_add(1, Ordering::SeqCst) + 1;
        if let Ok(w) = Self::get_or_recreate_writer(&self.index, &mut writer_guard) {
            match commit_single(w, Some(&format!("seq:{}", pre_seq))) {
                Ok(op) => {
                    self.last_commit_opstamp.store(op, Ordering::Release);
                }
                Err(e) => {
                    tracing::warn!("Tantivy writer error during compact pre-commit; recreating: {}", e);
                    let _ = Self::recreate_writer(&self.index, &mut writer_guard);
                }
            }
        }

        // 2. Enumerate all active segment IDs currently in the committed index metadata
        let segment_ids = self
            .index
            .searchable_segment_ids()
            .map_err(|e| StorageError::Tantivy(format!("Failed to list searchable segment IDs: {}", e)))?;

        // 3. Consolidate segments if multiple segments exist
        if segment_ids.len() >= 2 {
            tracing::info!(
                segment_count = segment_ids.len(),
                "Consolidating Tantivy segments during compaction"
            );
            let mut merge_attempts = 0;
            loop {
                let writer = match Self::get_or_recreate_writer(&self.index, &mut writer_guard) {
                    Ok(w) => w,
                    Err(e) => {
                        tracing::warn!("Failed to get writer during merge: {}", e);
                        break;
                    }
                };
                match writer.merge(&segment_ids).wait() {
                    Ok(_merged) => {
                        let post_seq = self.last_commit_seq.fetch_add(1, Ordering::SeqCst) + 1;
                        if let Ok(w) = Self::get_or_recreate_writer(&self.index, &mut writer_guard) {
                            match commit_single(w, Some(&format!("seq:{}", post_seq))) {
                                Ok(op) => {
                                    self.last_commit_opstamp.store(op, Ordering::Release);
                                }
                                Err(e) => {
                                    tracing::warn!("Commit after merge failed: {}", e);
                                    let _ = Self::recreate_writer(&self.index, &mut writer_guard);
                                }
                            }
                        }
                        break;
                    }
                    Err(e) => {
                        merge_attempts += 1;
                        tracing::warn!(attempt = merge_attempts, "Retrying segment merge after error: {}", e);
                        let _ = Self::recreate_writer(&self.index, &mut writer_guard);
                        if merge_attempts >= 5 {
                            break;
                        }
                        std::thread::yield_now();
                        std::thread::sleep(std::time::Duration::from_millis(20 * merge_attempts as u64));
                    }
                }
            }
        }

        drop(writer_guard);

        // 4. Final reader reload so searchers immediately pick up consolidated state
        self.reload_with_retry(SyncCheck::None)?;

        Ok(())
    }

    /// Converts a retrieved TantivyDocument into a domain DocumentChunk.
    pub(crate) fn doc_to_chunk(&self, doc: &TantivyDocument) -> DocumentChunk {
        let chunk_id = doc
            .get_first(self.field_chunk_id)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let document_id = doc
            .get_first(self.field_document_id)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let file_path = doc
            .get_first(self.field_file_path)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let line_start = doc
            .get_first(self.field_line_start)
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as u32;
        let line_end = doc
            .get_first(self.field_line_end)
            .and_then(|v| v.as_u64())
            .unwrap_or(line_start as u64) as u32;
        let blake3_hash = doc
            .get_first(self.field_blake3_hash)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let access_tier = doc
            .get_first(self.field_access_tier)
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8;
        let text_content = doc
            .get_first(self.field_text_content)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let metadata_json = doc
            .get_first(self.field_metadata_json)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        let vector = if let Some(bytes) = doc.get_first(self.field_vector_bytes).and_then(|v| v.as_bytes()) {
            bytes
                .as_chunks::<4>()
                .0
                .iter()
                .map(|b| f32::from_le_bytes(*b))
                .collect()
        } else {
            Vec::new()
        };

        DocumentChunk {
            chunk_id,
            document_id,
            file_path,
            line_start,
            line_end,
            blake3_hash,
            access_tier,
            vector,
            text_content,
            metadata_json,
        }
    }

    /// Scans all stored chunks in Tantivy.
    pub(crate) fn scan_all_chunks(&self) -> Result<Vec<DocumentChunk>, StorageError> {
        self.reload_with_retry(SyncCheck::None)?;
        let searcher = self.reader.searcher();
        let query = tantivy::query::AllQuery;
        let num_docs = searcher.num_docs() as usize;
        if num_docs == 0 {
            return Ok(Vec::new());
        }
        let fetch_limit = num_docs.clamp(10_000, 500_000);
        let top_docs = searcher
            .search(&query, &TopDocs::with_limit(fetch_limit).order_by_score())
            .map_err(|e| StorageError::Tantivy(format!("Scan search failed: {}", e)))?;

        let mut chunks = Vec::with_capacity(top_docs.len());
        for (_score, doc_address) in top_docs {
            let doc: TantivyDocument = searcher
                .doc(doc_address)
                .map_err(|e| StorageError::Tantivy(format!("Failed to retrieve document: {}", e)))?;
            chunks.push(self.doc_to_chunk(&doc));
        }
        Ok(chunks)
    }

    /// Deletes a specific chunk by its chunk_id.
    pub(crate) fn delete_by_chunk_id(&self, chunk_id: &str) -> Result<usize, StorageError> {
        self.reload_with_retry(SyncCheck::None)?;
        let term = Term::from_field_text(self.field_chunk_id, chunk_id);
        let query = TermQuery::new(term.clone(), IndexRecordOption::Basic);
        let searcher = self.reader.searcher();
        let count = searcher
            .search(&query, &Count)
            .map_err(|e| StorageError::Tantivy(format!("Count matching documents failed: {}", e)))?;

        if count == 0 {
            return Ok(0);
        }

        let mut writer_guard = self
            .writer
            .lock()
            .map_err(|_| StorageError::Tantivy("Tantivy writer mutex poisoned".into()))?;

        let mut recovery_attempts = 0;
        const MAX_RECOVERIES: usize = 10;
        'delete_attempt: loop {
            let next_seq = self.last_commit_seq.fetch_add(1, Ordering::SeqCst) + 1;
            let delete_res = {
                let writer = Self::get_or_recreate_writer(&self.index, &mut writer_guard)?;
                let _ = writer.delete_term(term.clone());
                commit_single(writer, Some(&format!("seq:{}", next_seq)))
            };

            match delete_res {
                Ok(op) => {
                    self.last_commit_opstamp.store(op, Ordering::Release);
                    break 'delete_attempt;
                }
                Err(e) => {
                    tracing::warn!(
                        "Tantivy delete_by_chunk_id failed during commit (attempt {} of {}); recreating writer: {}",
                        recovery_attempts + 1,
                        MAX_RECOVERIES,
                        e
                    );
                    recovery_attempts += 1;
                    if recovery_attempts > MAX_RECOVERIES {
                        return Err(StorageError::Tantivy(format!(
                            "Exceeded maximum writer recoveries ({}) during delete: {}",
                            MAX_RECOVERIES, e
                        )));
                    }
                    Self::recreate_writer(&self.index, &mut writer_guard)?;
                    continue 'delete_attempt;
                }
            }
        }

        drop(writer_guard);
        self.reload_with_retry(SyncCheck::DocAbsent { chunk_id })?;

        Ok(count)
    }

    /// Clears all indexed documents from the Tantivy index.
    #[allow(dead_code)]
    pub(crate) fn clear(&self) -> Result<(), StorageError> {
        let mut writer_guard = self
            .writer
            .lock()
            .map_err(|_| StorageError::Tantivy("Tantivy writer mutex poisoned".into()))?;

        let mut recovery_attempts = 0;
        const MAX_RECOVERIES: usize = 10;
        'clear_attempt: loop {
            let next_seq = self.last_commit_seq.fetch_add(1, Ordering::SeqCst) + 1;
            let clear_res = {
                let writer = Self::get_or_recreate_writer(&self.index, &mut writer_guard)?;
                let _ = writer.delete_all_documents();
                commit_single(writer, Some(&format!("seq:{}", next_seq)))
            };

            match clear_res {
                Ok(op) => {
                    self.last_commit_opstamp.store(op, Ordering::Release);
                    break 'clear_attempt;
                }
                Err(e) => {
                    tracing::warn!(
                        "Tantivy clear failed during commit (attempt {} of {}); recreating writer: {}",
                        recovery_attempts + 1,
                        MAX_RECOVERIES,
                        e
                    );
                    recovery_attempts += 1;
                    if recovery_attempts > MAX_RECOVERIES {
                        return Err(StorageError::Tantivy(format!(
                            "Exceeded maximum writer recoveries ({}) during clear: {}",
                            MAX_RECOVERIES, e
                        )));
                    }
                    Self::recreate_writer(&self.index, &mut writer_guard)?;
                    continue 'clear_attempt;
                }
            }
        }

        drop(writer_guard);
        self.reload_with_retry(SyncCheck::AllCleared)?;

        Ok(())
    }

    /// Reloads the Tantivy reader, retrying on transient Windows file lock errors
    /// and ensuring the reader is synchronized to at least the last committed sequence,
    /// opstamp, and semantic invariant (e.g. document presence/absence).
    fn reload_with_retry(&self, check: SyncCheck<'_>) -> Result<(), StorageError> {
        let target_seq = self.last_commit_seq.load(Ordering::Acquire);
        let min_opstamp = self.last_commit_opstamp.load(Ordering::Acquire);

        // Fast path: if reader is already synchronized to at least target_seq, no reload needed!
        // But only if no specific semantic verification (e.g. DocPresent/DocAbsent) is required.
        if self.synced_seq.load(Ordering::Acquire) >= target_seq
            && matches!(check, SyncCheck::None)
        {
            return Ok(());
        }

        const MAX_ATTEMPTS: usize = 300;
        let mut last_err = String::new();

        for attempt in 1..=MAX_ATTEMPTS {
            // Step 1: Inspect on-disk metadata to ensure the writer's commit has flushed to disk.
            let meta = match self.index.load_metas() {
                Ok(m) => m,
                Err(e) => {
                    last_err = format!("Failed to load metas: {}", e);
                    std::thread::yield_now();
                    if attempt > 10 {
                        std::thread::sleep(std::time::Duration::from_micros(100));
                    }
                    continue;
                }
            };

            let disk_seq = parse_commit_seq(&meta);
            if target_seq > 0 && (disk_seq < target_seq || meta.opstamp < min_opstamp) {
                last_err = format!(
                    "On-disk metadata stale: seq {} < target {}, opstamp {} < min {}",
                    disk_seq, target_seq, meta.opstamp, min_opstamp
                );
                std::thread::yield_now();
                if attempt > 5 {
                    let backoff = if attempt <= 20 { 100 } else if attempt <= 50 { 250 } else { 500 };
                    std::thread::sleep(std::time::Duration::from_micros(backoff));
                }
                continue;
            }

            // Step 2: Reload reader from verified on-disk metadata
            if let Err(e) = self.reader.reload() {
                last_err = format!("Reader reload failed: {}", e);
                std::thread::yield_now();
                if attempt > 10 {
                    std::thread::sleep(std::time::Duration::from_micros(100));
                }
                continue;
            }

            // Step 3: Verify reader's searcher reflects the commit
            let searcher = self.reader.searcher();
            let disk_segments: BTreeSet<(SegmentId, Option<u64>)> = meta
                .segments
                .iter()
                .map(|s| (s.id(), s.delete_opstamp()))
                .collect();
            let searcher_segments: BTreeSet<(SegmentId, Option<u64>)> = searcher
                .segment_readers()
                .iter()
                .map(|r| (r.segment_id(), r.delete_opstamp()))
                .collect();

            if disk_segments != searcher_segments {
                last_err = format!(
                    "Segment mismatch between disk ({:?}) and searcher ({:?})",
                    disk_segments, searcher_segments
                );
                std::thread::yield_now();
                if attempt > 5 {
                    std::thread::sleep(std::time::Duration::from_micros(100));
                }
                continue;
            }

            // If disk metadata has segments, searcher must not have empty segments
            if !meta.segments.is_empty() && searcher_segments.is_empty() {
                last_err = "Disk has segments but searcher segment set is empty".to_string();
                std::thread::yield_now();
                if attempt > 5 {
                    std::thread::sleep(std::time::Duration::from_micros(100));
                }
                continue;
            }

            // Step 4: Semantic verification based on SyncCheck
            match check {
                SyncCheck::None => {}
                SyncCheck::DocPresent { chunk_id } => {
                    let term = Term::from_field_text(self.field_chunk_id, chunk_id);
                    let query = TermQuery::new(term, IndexRecordOption::Basic);
                    let count = searcher.search(&query, &Count).unwrap_or(0);
                    if count == 0 {
                        last_err = format!("DocPresent verification failed for chunk_id {}", chunk_id);
                        std::thread::yield_now();
                        if attempt > 5 {
                            let backoff = if attempt <= 20 { 100 } else if attempt <= 50 { 250 } else { 500 };
                            std::thread::sleep(std::time::Duration::from_micros(backoff));
                        }
                        continue;
                    }
                }
                SyncCheck::DocAbsent { chunk_id } => {
                    let term = Term::from_field_text(self.field_chunk_id, chunk_id);
                    let query = TermQuery::new(term, IndexRecordOption::Basic);
                    let count = searcher.search(&query, &Count).unwrap_or(0);
                    if count > 0 {
                        last_err = format!("DocAbsent verification failed for chunk_id {} (count={})", chunk_id, count);
                        std::thread::yield_now();
                        if attempt > 5 {
                            let backoff = if attempt <= 20 { 100 } else if attempt <= 50 { 250 } else { 500 };
                            std::thread::sleep(std::time::Duration::from_micros(backoff));
                        }
                        continue;
                    }
                }
                SyncCheck::FilePathAbsent { file_path } => {
                    let term = Term::from_field_text(self.field_file_path, file_path);
                    let query = TermQuery::new(term, IndexRecordOption::Basic);
                    let count = searcher.search(&query, &Count).unwrap_or(0);
                    if count > 0 {
                        last_err = format!("FilePathAbsent verification failed for file_path {} (count={})", file_path, count);
                        std::thread::yield_now();
                        if attempt > 5 {
                            let backoff = if attempt <= 20 { 100 } else if attempt <= 50 { 250 } else { 500 };
                            std::thread::sleep(std::time::Duration::from_micros(backoff));
                        }
                        continue;
                    }
                }
                SyncCheck::AllCleared => {
                    if searcher.num_docs() > 0 {
                        last_err = format!("AllCleared verification failed: num_docs={}", searcher.num_docs());
                        std::thread::yield_now();
                        if attempt > 5 {
                            let backoff = if attempt <= 20 { 100 } else if attempt <= 50 { 250 } else { 500 };
                            std::thread::sleep(std::time::Duration::from_micros(backoff));
                        }
                        continue;
                    }
                }
            }

            // Step 5: All checks passed! Update synced sequence counter
            self.synced_seq.store(target_seq, Ordering::Release);
            return Ok(());
        }

        // Fail-closed invariant: Never return Ok(()) on attempt exhaustion!
        Err(StorageError::Tantivy(format!(
            "Tantivy reader reload failed to synchronize with commit opstamp {} (target seq {}) after {} attempts. Last error: {}",
            min_opstamp, target_seq, MAX_ATTEMPTS, last_err
        )))
    }
}

/// Helper that prepares and executes a single Tantivy commit with an optional payload message.
///
/// If `prepare_commit` or `commit` encounters an error, it fails fast and returns `Err`
/// immediately to allow the caller's recovery loop to re-add uncommitted documents and
/// replay the batch without losing documents.
fn commit_single(
    writer: &mut IndexWriter<TantivyDocument>,
    payload: Option<&str>,
) -> Result<u64, StorageError> {
    let mut prepared = writer
        .prepare_commit()
        .map_err(|e| StorageError::Tantivy(format!("Tantivy prepare_commit error: {}", e)))?;

    if let Some(msg) = payload {
        prepared.set_payload(msg);
    }

    prepared
        .commit()
        .map_err(|e| StorageError::Tantivy(format!("Tantivy commit error: {}", e)))
}
