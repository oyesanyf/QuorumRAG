//! Two-Level BLAKE3 Deduplication Engine for QuorumRAG.
//!
//! Level 1: Full-file BLAKE3 hash catalog mapping `(file_path, file_blake3, mtime, size)`.
//!          Detects renames and moves, and skips unchanged files entirely with zero re-embeddings.
//! Level 2: Chunk-level BLAKE3 hash cache mapping `chunk_blake3 -> Vec<f32>` ensuring
//!          identical text chunks across distinct files or edits reuse existing embeddings.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};

/// Catalog entry recording metadata and content hashes for a tracked file on disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileCatalogEntry {
    /// Canonical or relative path of the file.
    pub file_path: PathBuf,
    /// 64-character lowercase hex BLAKE3 hash of the entire file content.
    pub file_blake3: String,
    /// Last modified timestamp in seconds since Unix epoch.
    pub mtime_secs: i64,
    /// File size in bytes.
    pub size_bytes: u64,
    /// List of Level-2 chunk BLAKE3 hashes generated from this file.
    pub chunk_hashes: Vec<String>,
}

/// Action to be taken for a file evaluated against the Level-1 catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DedupAction {
    /// File has identical mtime and size, or identical BLAKE3 content hash.
    /// Action: Skip chunking and embedding entirely.
    Unchanged {
        file_blake3: String,
        chunk_hashes: Vec<String>,
    },
    /// File content hash matches an existing entry under a different path.
    /// Action: Rename/Move detected. Update catalog path, zero new embeddings!
    MovedOrRenamed {
        old_path: PathBuf,
        new_path: PathBuf,
        file_blake3: String,
        chunk_hashes: Vec<String>,
    },
    /// File is either new or its content BLAKE3 hash has changed.
    /// Action: Proceed to chunking; chunk vectors will be checked against Level-2 cache.
    ModifiedOrNew {
        file_blake3: String,
        is_new: bool,
    },
}

/// Level-1 File Deduplication Catalog with fast-path metadata checking and rename detection.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Level1DedupCatalog {
    /// Primary index: file_blake3 -> FileCatalogEntry
    entries: HashMap<String, FileCatalogEntry>,
    /// Secondary index: file_path -> file_blake3 (preserves original path casing)
    path_to_hash: HashMap<PathBuf, String>,
    /// Normalized lookup index: normalized_key -> original path in `path_to_hash`
    #[serde(skip)]
    norm_to_raw: HashMap<PathBuf, PathBuf>,
}

/// Atomically persists a serialized JSON byte payload to disk using a unique temporary file
/// and exponential retry backoff on rename to prevent Windows ERROR_SHARING_VIOLATION collisions.
fn atomic_write_json_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let unique_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let temp_path = path.with_extension(format!("tmp.{}.{}", std::process::id(), unique_id));
    std::fs::write(&temp_path, bytes)?;

    let mut renamed = false;
    for attempt in 0..5 {
        if std::fs::rename(&temp_path, path).is_ok() {
            renamed = true;
            break;
        }
        if path.exists() {
            let _ = std::fs::remove_file(path);
            if std::fs::rename(&temp_path, path).is_ok() {
                renamed = true;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(15 * (1 << attempt)));
    }
    if !renamed {
        let _ = std::fs::remove_file(&temp_path);
        return Err(io::Error::other("Failed to rename temporary dedup catalog after 5 attempts"));
    }
    Ok(())
}

fn normalize_dedup_path_key(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if let Ok(norm) = quorum_types::normalize_prefix_for_match(&raw) {
        return PathBuf::from(norm);
    }
    let trimmed = raw.trim();
    if cfg!(windows)
        || (trimmed.len() >= 2
            && trimmed.as_bytes()[0].is_ascii_alphabetic()
            && trimmed.as_bytes()[1] == b':')
    {
        let replaced = trimmed.replace('/', "\\");
        let stripped = replaced.strip_prefix(r"\\?\").unwrap_or(&replaced);
        let mut out = String::with_capacity(stripped.len());
        let mut prev_sep = false;
        for ch in stripped.chars() {
            if ch == '\\' {
                if !prev_sep {
                    out.push('\\');
                }
                prev_sep = true;
            } else {
                out.push(ch.to_ascii_lowercase());
                prev_sep = false;
            }
        }
        if out.len() > 3 && out.ends_with('\\') {
            out.pop();
        }
        PathBuf::from(out)
    } else {
        path.to_path_buf()
    }
}

impl Level1DedupCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load catalog from a JSON file on disk, indexing normalized lookup keys.
    pub fn load_from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let f = File::open(path)?;
        let reader = BufReader::new(f);
        let mut catalog: Self = serde_json::from_reader(reader)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        catalog.rebuild_norm_index();
        Ok(catalog)
    }

    fn rebuild_norm_index(&mut self) {
        self.norm_to_raw.clear();
        self.norm_to_raw.reserve(self.path_to_hash.len());
        for raw in self.path_to_hash.keys() {
            self.norm_to_raw
                .insert(normalize_dedup_path_key(raw), raw.clone());
        }
    }

    fn lookup_hash_and_raw(&self, path: &Path) -> Option<(&PathBuf, &String)> {
        if let Some((k, v)) = self.path_to_hash.get_key_value(path) {
            return Some((k, v));
        }
        let key = normalize_dedup_path_key(path);
        if let Some(raw) = self.norm_to_raw.get(&key) {
            if let Some((k, v)) = self.path_to_hash.get_key_value(raw) {
                return Some((k, v));
            }
        }
        if self.norm_to_raw.is_empty() && !self.path_to_hash.is_empty() {
            return self
                .path_to_hash
                .iter()
                .find(|(k, _)| normalize_dedup_path_key(k) == key);
        }
        None
    }

    fn insert_path_mapping(&mut self, raw_path: PathBuf, hash: String) {
        let key = normalize_dedup_path_key(&raw_path);
        if let Some(prev_raw) = self.norm_to_raw.insert(key, raw_path.clone()) {
            if prev_raw != raw_path {
                self.path_to_hash.remove(&prev_raw);
            }
        }
        self.path_to_hash.insert(raw_path, hash);
    }

    fn remove_path_mapping(&mut self, path: &Path) -> Option<String> {
        let key = normalize_dedup_path_key(path);
        if let Some(hash) = self.path_to_hash.remove(path) {
            if self.norm_to_raw.get(&key).map(|p| p.as_path()) == Some(path) {
                self.norm_to_raw.remove(&key);
            }
            return Some(hash);
        }
        if let Some(raw) = self.norm_to_raw.remove(&key) {
            return self.path_to_hash.remove(&raw);
        }
        if self.norm_to_raw.is_empty() && !self.path_to_hash.is_empty() {
            if let Some(found) = self
                .path_to_hash
                .keys()
                .find(|k| normalize_dedup_path_key(k) == key)
                .cloned()
            {
                return self.path_to_hash.remove(&found);
            }
        }
        None
    }

    /// Persist catalog atomically to a JSON file on disk using in-memory serialization
    /// and a single buffered OS write (avoiding millions of unbuffered WriteFile syscalls).
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        atomic_write_json_file(path.as_ref(), &bytes)
    }

    /// Zero-I/O fast path check: returns `Some(DedupAction::Unchanged)` if `(path, mtime, size)` match.
    pub fn check_unchanged_fast(
        &self,
        path: &Path,
        current_mtime: i64,
        current_size: u64,
    ) -> Option<DedupAction> {
        let (_, existing_hash) = self.lookup_hash_and_raw(path)?;
        let entry = self.entries.get(existing_hash)?;
        if entry.mtime_secs == current_mtime && entry.size_bytes == current_size {
            Some(DedupAction::Unchanged {
                file_blake3: existing_hash.clone(),
                chunk_hashes: entry.chunk_hashes.clone(),
            })
        } else {
            None
        }
    }

    /// Evaluates a pre-hashed file against the catalog without performing disk I/O under the lock.
    pub fn evaluate_prehashed_file(
        &mut self,
        path: &Path,
        current_mtime: i64,
        current_size: u64,
        file_b3: String,
    ) -> DedupAction {
        let key = normalize_dedup_path_key(path);
        let existing_match = self
            .lookup_hash_and_raw(path)
            .map(|(_, h)| h == &file_b3)
            .unwrap_or(false);
        let known_path = self.lookup_hash_and_raw(path).is_some();

        if let Some(entry) = self.entries.get_mut(&file_b3) {
            if normalize_dedup_path_key(&entry.file_path) == key {
                entry.mtime_secs = current_mtime;
                entry.size_bytes = current_size;
                let chunk_hashes = entry.chunk_hashes.clone();
                self.insert_path_mapping(path.to_path_buf(), file_b3.clone());
                return DedupAction::Unchanged {
                    file_blake3: file_b3,
                    chunk_hashes,
                };
            } else if existing_match {
                return DedupAction::Unchanged {
                    file_blake3: file_b3,
                    chunk_hashes: entry.chunk_hashes.clone(),
                };
            } else if !entry.file_path.exists() {
                let old_path = entry.file_path.clone();
                let chunk_hashes = entry.chunk_hashes.clone();
                entry.file_path = path.to_path_buf();
                entry.mtime_secs = current_mtime;
                entry.size_bytes = current_size;
                self.remove_path_mapping(&old_path);
                self.insert_path_mapping(path.to_path_buf(), file_b3.clone());
                return DedupAction::MovedOrRenamed {
                    old_path,
                    new_path: path.to_path_buf(),
                    file_blake3: file_b3,
                    chunk_hashes,
                };
            } else {
                return DedupAction::ModifiedOrNew {
                    file_blake3: file_b3,
                    is_new: !known_path,
                };
            }
        }
        DedupAction::ModifiedOrNew {
            file_blake3: file_b3,
            is_new: !known_path,
        }
    }

    /// Compute 64-char lowercase hex BLAKE3 hash of a file via streaming reader,
    /// failing closed under `CloudPlaceholderPolicy::LocallySyncedOnly`.
    pub fn hash_file_stream(path: impl AsRef<Path>) -> io::Result<String> {
        Self::hash_file_stream_with_policy(
            path,
            quorum_types::CloudPlaceholderPolicy::LocallySyncedOnly,
        )
    }

    /// Compute 64-char lowercase hex BLAKE3 hash of a file after enforcing `policy` on
    /// OS cloud-placeholder attributes before opening the file.
    pub fn hash_file_stream_with_policy(
        path: impl AsRef<Path>,
        policy: quorum_types::CloudPlaceholderPolicy,
    ) -> io::Result<String> {
        let p = path.as_ref();
        crate::cloud_drives::ensure_open_allowed_for_placeholder(p, policy)?;
        let f = quorum_classifier::FileTypeClassifier::open_file_with_retry(p)?;
        let mut reader = BufReader::with_capacity(64 * 1024, f);
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0u8; 64 * 1024];

        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        Ok(hasher.finalize().to_hex().to_string())
    }

    /// Check a file's status against the catalog before reading content (defaults fail-closed to `LocallySyncedOnly`).
    pub fn evaluate_file(
        &mut self,
        path: &Path,
        current_mtime: i64,
        current_size: u64,
    ) -> io::Result<DedupAction> {
        self.evaluate_file_with_policy(
            path,
            current_mtime,
            current_size,
            quorum_types::CloudPlaceholderPolicy::LocallySyncedOnly,
        )
    }

    /// Check a file's status against the catalog before reading content under `policy`.
    ///
    /// 1. Fast Path: If path, mtime, and size match existing entry -> Unchanged (0 disk read).
    /// 2. Move/Rename Detection: If content hash exists under another path -> MovedOrRenamed.
    /// 3. Otherwise -> ModifiedOrNew.
    pub fn evaluate_file_with_policy(
        &mut self,
        path: &Path,
        current_mtime: i64,
        current_size: u64,
        policy: quorum_types::CloudPlaceholderPolicy,
    ) -> io::Result<DedupAction> {
        let key = normalize_dedup_path_key(path);
        // Step 1: Check if path exists in secondary index
        if let Some((_, existing_hash)) = self.lookup_hash_and_raw(path) {
            let existing_hash = existing_hash.clone();
            if let Some(entry) = self.entries.get(&existing_hash) {
                if entry.mtime_secs == current_mtime && entry.size_bytes == current_size {
                    // FAST PATH: mtime and size unchanged, skip reading file!
                    return Ok(DedupAction::Unchanged {
                        file_blake3: existing_hash,
                        chunk_hashes: entry.chunk_hashes.clone(),
                    });
                }
            }
        }

        // Step 2: Content may have changed or file is moved/new. Compute BLAKE3 hash.
        let file_b3 = Self::hash_file_stream_with_policy(path, policy)?;

        let existing_match = self
            .lookup_hash_and_raw(path)
            .map(|(_, h)| h == &file_b3)
            .unwrap_or(false);
        let known_path = self.lookup_hash_and_raw(path).is_some();

        // Check if content hash already exists in catalog
        if let Some(entry) = self.entries.get_mut(&file_b3) {
            if normalize_dedup_path_key(&entry.file_path) == key {
                // Content identical, but mtime or size metadata changed (e.g. touched)
                entry.mtime_secs = current_mtime;
                entry.size_bytes = current_size;
                let chunk_hashes = entry.chunk_hashes.clone();
                self.insert_path_mapping(path.to_path_buf(), file_b3.clone());
                return Ok(DedupAction::Unchanged {
                    file_blake3: file_b3,
                    chunk_hashes,
                });
            } else if existing_match {
                return Ok(DedupAction::Unchanged {
                    file_blake3: file_b3,
                    chunk_hashes: entry.chunk_hashes.clone(),
                });
            } else if !entry.file_path.exists() {
                // RENAME OR MOVE DETECTED!
                let old_path = entry.file_path.clone();
                let chunk_hashes = entry.chunk_hashes.clone();

                // Update indices
                entry.file_path = path.to_path_buf();
                entry.mtime_secs = current_mtime;
                entry.size_bytes = current_size;
                self.remove_path_mapping(&old_path);
                self.insert_path_mapping(path.to_path_buf(), file_b3.clone());

                return Ok(DedupAction::MovedOrRenamed {
                    old_path,
                    new_path: path.to_path_buf(),
                    file_blake3: file_b3,
                    chunk_hashes,
                });
            } else {
                // Identical content exists at another live path on disk; index this copy too.
                return Ok(DedupAction::ModifiedOrNew {
                    file_blake3: file_b3,
                    is_new: !known_path,
                });
            }
        }

        // Step 3: Truly new or modified content
        Ok(DedupAction::ModifiedOrNew {
            file_blake3: file_b3,
            is_new: !known_path,
        })
    }

    /// Register or update an entry in the catalog after chunking/indexing.
    pub fn register_entry(&mut self, entry: FileCatalogEntry) {
        self.insert_path_mapping(entry.file_path.clone(), entry.file_blake3.clone());
        self.entries.insert(entry.file_blake3.clone(), entry);
    }

    /// Remove a file from the catalog when deleted on disk.
    pub fn remove_file(&mut self, path: &Path) -> Option<FileCatalogEntry> {
        let hash = self.remove_path_mapping(path)?;
        let surviving_path = self
            .path_to_hash
            .iter()
            .find_map(|(p, h)| if h == &hash { Some(p.clone()) } else { None });
        if let Some(surviving) = surviving_path {
            if let Some(entry) = self.entries.get_mut(&hash) {
                let mut removed_copy = entry.clone();
                removed_copy.file_path = path.to_path_buf();
                if normalize_dedup_path_key(&entry.file_path) == normalize_dedup_path_key(path) {
                    entry.file_path = surviving;
                }
                return Some(removed_copy);
            }
            None
        } else {
            self.entries.remove(&hash)
        }
    }

    /// Boundary-safe removal of all catalog entries whose `file_path` matches `prefix`
    /// (normalized across slashes, `\\?\`, and Windows case).
    pub fn remove_by_prefix(&mut self, prefix: &Path) -> Vec<FileCatalogEntry> {
        let matching_paths: Vec<PathBuf> = self
            .path_to_hash
            .keys()
            .filter(|p| crate::config::path_matches_prefix(p, prefix))
            .cloned()
            .collect();

        let mut removed_hashes: Vec<(PathBuf, String)> = Vec::with_capacity(matching_paths.len());
        for p in matching_paths {
            self.norm_to_raw.remove(&normalize_dedup_path_key(&p));
            if let Some(hash) = self.path_to_hash.remove(&p) {
                removed_hashes.push((p, hash));
            }
        }

        let mut removed = Vec::new();
        for (p, hash) in removed_hashes {
            let surviving_path = self
                .path_to_hash
                .iter()
                .find_map(|(sp, sh)| if sh == &hash { Some(sp.clone()) } else { None });
            if let Some(surviving) = surviving_path {
                if let Some(entry) = self.entries.get_mut(&hash) {
                    let mut removed_copy = entry.clone();
                    removed_copy.file_path = p;
                    if crate::config::path_matches_prefix(&entry.file_path, prefix) {
                        entry.file_path = surviving;
                    }
                    removed.push(removed_copy);
                }
            } else if let Some(e) = self.entries.remove(&hash) {
                removed.push(e);
            }
        }

        let matching_hashes: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, entry)| crate::config::path_matches_prefix(&entry.file_path, prefix))
            .map(|(h, _)| h.clone())
            .collect();
        for h in matching_hashes {
            let surviving_path = self
                .path_to_hash
                .iter()
                .find_map(|(sp, sh)| if sh == &h { Some(sp.clone()) } else { None });
            if let Some(surviving) = surviving_path {
                if let Some(entry) = self.entries.get_mut(&h) {
                    entry.file_path = surviving;
                }
            } else if let Some(e) = self.entries.remove(&h) {
                self.remove_path_mapping(&e.file_path);
                removed.push(e);
            }
        }

        removed
    }

    pub fn get_file_entry(&self, path: &Path) -> Option<&FileCatalogEntry> {
        self.lookup_hash_and_raw(path)
            .and_then(|(_, hash)| self.entries.get(hash))
    }

    pub fn get_all_tracked_files(&self) -> Vec<PathBuf> {
        self.path_to_hash.keys().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Statistics for Level-2 Chunk Cache telemetry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub capacity: usize,
    pub current_size: usize,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f32 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f32 / total as f32
        }
    }
}

/// Level-2 Chunk Cache mapping `chunk_blake3 -> Vec<f32>` (Gemma 768d embedding).
///
/// Thread-safe bounded LRU cache preventing duplicate neural embeddings across
/// distinct files or within single-line edits.
pub struct Level2ChunkCache {
    inner: Arc<RwLock<Level2ChunkCacheInner>>,
}

struct Level2ChunkCacheInner {
    capacity: usize,
    map: HashMap<String, (Vec<f32>, usize)>,
    order: VecDeque<String>,
    hits: u64,
    misses: u64,
}

impl Level2ChunkCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Level2ChunkCacheInner {
                capacity: capacity.max(128),
                map: HashMap::with_capacity(capacity.min(65536)),
                order: VecDeque::with_capacity(capacity.min(65536)),
                hits: 0,
                misses: 0,
            })),
        }
    }

    /// Check if chunk vector is present without counting as hit/miss.
    pub fn has_chunk(&self, chunk_blake3: &str) -> bool {
        self.inner.read().map(|i| i.map.contains_key(chunk_blake3)).unwrap_or(false)
    }

    /// Retrieve cached embedding vector if present.
    pub fn get(&self, chunk_blake3: &str) -> Option<Vec<f32>> {
        let mut inner = self.inner.write().ok()?;
        if let Some(vec) = inner.map.get(chunk_blake3).map(|(v, _)| v.clone()) {
            inner.hits += 1;
            Some(vec)
        } else {
            inner.misses += 1;
            None
        }
    }

    /// Insert a newly computed embedding vector into the cache.
    pub fn insert(&self, chunk_blake3: String, vector: Vec<f32>) {
        let mut inner = match self.inner.write() {
            Ok(guard) => guard,
            Err(_) => return,
        };

        if inner.map.contains_key(&chunk_blake3) {
            return;
        }

        // Evict if at capacity
        while inner.map.len() >= inner.capacity && !inner.order.is_empty() {
            if let Some(oldest) = inner.order.pop_front() {
                inner.map.remove(&oldest);
            }
        }

        let order_len = inner.order.len();
        inner.order.push_back(chunk_blake3.clone());
        inner.map.insert(chunk_blake3, (vector, order_len));
    }

    /// Expands the cache capacity if `min_capacity` exceeds the current capacity.
    pub fn ensure_capacity(&self, min_capacity: usize) {
        if let Ok(mut inner) = self.inner.write() {
            if min_capacity > inner.capacity {
                inner.capacity = min_capacity;
            }
        }
    }

    /// Inserts a batch of chunk hash and embedding vector pairs under a single write lock.
    pub fn insert_batch(&self, items: impl IntoIterator<Item = (String, Vec<f32>)>) {
        let mut inner = match self.inner.write() {
            Ok(guard) => guard,
            Err(_) => return,
        };

        for (chunk_blake3, vector) in items {
            if inner.map.contains_key(&chunk_blake3) {
                continue;
            }

            // Evict if at capacity
            while inner.map.len() >= inner.capacity && !inner.order.is_empty() {
                if let Some(oldest) = inner.order.pop_front() {
                    inner.map.remove(&oldest);
                }
            }

            let order_len = inner.order.len();
            inner.order.push_back(chunk_blake3.clone());
            inner.map.insert(chunk_blake3, (vector, order_len));
        }
    }

    /// Removes the specified chunk hashes from the Level-2 cache and eviction queue.
    pub fn remove_hashes(&self, hashes: &std::collections::HashSet<String>) -> usize {
        if hashes.is_empty() {
            return 0;
        }
        let Ok(mut inner) = self.inner.write() else {
            return 0;
        };
        let mut removed = 0usize;
        for h in hashes {
            if inner.map.remove(h).is_some() {
                removed += 1;
            }
        }
        if removed > 0 {
            inner.order.retain(|k| !hashes.contains(k));
        }
        removed
    }

    pub fn stats(&self) -> CacheStats {
        let inner = self.inner.read().unwrap();
        CacheStats {
            hits: inner.hits,
            misses: inner.misses,
            capacity: inner.capacity,
            current_size: inner.map.len(),
        }
    }
}

/// Unified Two-Level Deduplication Engine combining Level-1 File Catalog
/// and Level-2 Chunk Vector Cache with thread-safe synchronization.
#[derive(Clone)]
pub struct TwoLevelDedupEngine {
    catalog: Arc<RwLock<Level1DedupCatalog>>,
    cache: Arc<Level2ChunkCache>,
}

impl Default for TwoLevelDedupEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl TwoLevelDedupEngine {
    pub fn new() -> Self {
        Self {
            catalog: Arc::new(RwLock::new(Level1DedupCatalog::new())),
            cache: Arc::new(Level2ChunkCache::new(50_000)),
        }
    }

    pub fn catalog(&self) -> &Arc<RwLock<Level1DedupCatalog>> {
        &self.catalog
    }

    pub fn cache(&self) -> &Arc<Level2ChunkCache> {
        &self.cache
    }

    /// Zero-I/O metadata fast-path check under a read lock.
    pub fn check_unchanged_fast(
        &self,
        path: &Path,
        current_mtime: i64,
        current_size: u64,
    ) -> Option<DedupAction> {
        let catalog = self.catalog.read().ok()?;
        catalog.check_unchanged_fast(path, current_mtime, current_size)
    }

    /// Evaluates a file against the Level-1 catalog (defaults fail-closed to `LocallySyncedOnly`).
    pub fn evaluate_file(
        &self,
        path: &Path,
        current_mtime: i64,
        current_size: u64,
    ) -> io::Result<DedupAction> {
        self.evaluate_file_with_policy(
            path,
            current_mtime,
            current_size,
            quorum_types::CloudPlaceholderPolicy::LocallySyncedOnly,
        )
    }

    /// Evaluates a file against the Level-1 catalog without holding the catalog lock during BLAKE3 disk I/O,
    /// enforcing `policy` before opening the file on fast-path misses.
    pub fn evaluate_file_with_policy(
        &self,
        path: &Path,
        current_mtime: i64,
        current_size: u64,
        policy: quorum_types::CloudPlaceholderPolicy,
    ) -> io::Result<DedupAction> {
        if let Some(unchanged) = self.check_unchanged_fast(path, current_mtime, current_size) {
            return Ok(unchanged);
        }
        let file_b3 = Level1DedupCatalog::hash_file_stream_with_policy(path, policy)?;
        let mut catalog = self.catalog.write().map_err(|_| {
            io::Error::other("Level 1 catalog lock poisoned")
        })?;
        Ok(catalog.evaluate_prehashed_file(path, current_mtime, current_size, file_b3))
    }

    /// Registers a newly indexed file into the Level-1 catalog.
    pub fn register_entry(&self, entry: FileCatalogEntry) {
        if let Ok(mut catalog) = self.catalog.write() {
            catalog.register_entry(entry);
        }
    }

    /// Removes a file from the catalog when deleted from disk.
    pub fn remove_file(&self, path: &Path) -> Option<FileCatalogEntry> {
        let mut catalog = self.catalog.write().ok()?;
        catalog.remove_file(path)
    }

    /// Boundary-safe removal of all tracked files matching `prefix` from Level-1 catalog,
    /// also evicting orphaned chunk hashes from `Level2ChunkCache`.
    pub fn remove_by_prefix(&self, prefix: &Path) -> usize {
        let (removed_count, orphan_hashes) = {
            let Ok(mut catalog) = self.catalog.write() else {
                return 0;
            };
            let removed_entries = catalog.remove_by_prefix(prefix);
            if removed_entries.is_empty() {
                return 0;
            }
            let mut candidate_hashes: std::collections::HashSet<String> = removed_entries
                .iter()
                .flat_map(|e| e.chunk_hashes.iter().cloned())
                .collect();
            for remaining in catalog.entries.values() {
                for h in &remaining.chunk_hashes {
                    candidate_hashes.remove(h);
                }
            }
            (removed_entries.len(), candidate_hashes)
        };
        self.cache.remove_hashes(&orphan_hashes);
        removed_count
    }

    /// Boundary-safe prefix removal followed by atomic persistence of `dedup_catalog.json` when mutated.
    pub fn remove_by_prefix_and_save(
        &self,
        prefix: &Path,
        catalog_path: Option<&Path>,
    ) -> io::Result<usize> {
        let removed = self.remove_by_prefix(prefix);
        if removed > 0 {
            if let Some(path) = catalog_path {
                self.save_catalog_to_file(path)?;
            }
        }
        Ok(removed)
    }

    pub fn get_file_entry(&self, path: &Path) -> Option<FileCatalogEntry> {
        let catalog = self.catalog.read().ok()?;
        catalog.get_file_entry(path).cloned()
    }

    pub fn get_all_tracked_files(&self) -> Vec<PathBuf> {
        let catalog = self.catalog.read().ok();
        catalog.map(|c| c.get_all_tracked_files()).unwrap_or_default()
    }

    /// Loads the Level-1 File Catalog from a JSON file on disk.
    pub fn load_catalog_from_file(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let loaded = Level1DedupCatalog::load_from_file(path)?;
        let mut catalog = self.catalog.write().map_err(|_| {
            io::Error::other("Level 1 catalog lock poisoned")
        })?;
        *catalog = loaded;
        Ok(())
    }

    /// Persists the Level-1 File Catalog atomically to a JSON file on disk,
    /// releasing the catalog read lock before performing the OS disk write.
    pub fn save_catalog_to_file(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let bytes = {
            let catalog = self.catalog.read().map_err(|_| {
                io::Error::other("Level 1 catalog lock poisoned")
            })?;
            serde_json::to_vec(&*catalog).map_err(io::Error::other)?
        };
        atomic_write_json_file(path.as_ref(), &bytes)
    }

    /// Hydrates deduplication state (both Level-1 File Catalog and Level-2 Chunk Cache)
    /// directly from stored LanceDB chunks on startup.
    ///
    /// # Behavior
    /// 1. Scans all stored `DocumentChunk` records from LanceDB via `storage.scan_all_chunks().await?`.
    /// 2. Expands `Level2ChunkCache` capacity to accommodate all stored chunks without eviction.
    /// 3. Populates `Level2ChunkCache` with `(blake3_hash, vector)` under a single batch operation.
    /// 4. Groups chunks by parent `document_id` (the BLAKE3 digest of the document).
    /// 5. Sorts chunk hashes for each document deterministically by `(line_start, chunk_index)`.
    /// 6. Probes local filesystem metadata for each unique file to prime `mtime_secs` and `size_bytes`
    ///    for immediate Level-1 Fast Path hits, safely falling back to `(0, 0)` for offline drives.
    /// 7. Populates `Level1DedupCatalog` under a single write lock.
    ///
    /// Returns the total number of hydrated chunks.
    pub async fn hydrate_from_storage(
        &self,
        storage: &Arc<quorum_storage::StorageEngine>,
    ) -> Result<usize, crate::error::IngestError> {
        let chunks = storage.scan_all_chunks().await?;
        if chunks.is_empty() {
            return Ok(0);
        }

        let chunk_count = chunks.len();

        // Step 1: Ensure Level-2 cache capacity and batch-insert chunk vectors
        self.cache.ensure_capacity(chunk_count);
        let cache_items = chunks
            .iter()
            .filter(|c| !c.vector.is_empty())
            .map(|c| (c.blake3_hash.clone(), c.vector.clone()));
        self.cache.insert_batch(cache_items);

        // Step 2: Group chunks by document_id:
        // document_id -> (file_path, Vec<(line_start, chunk_index, blake3_hash)>)
        let mut doc_groups: HashMap<String, (PathBuf, Vec<(u32, usize, String)>)> = HashMap::new();

        for chunk in chunks {
            // Parse chunk index from chunk_id (e.g. "{doc_id}:{chunk_index}")
            let chunk_index: usize = chunk
                .chunk_id
                .rsplit_once(':')
                .and_then(|(_, idx)| idx.parse().ok())
                .unwrap_or(0);

            let group = doc_groups
                .entry(chunk.document_id)
                .or_insert_with(|| (PathBuf::from(&chunk.file_path), Vec::new()));
            group.1.push((chunk.line_start, chunk_index, chunk.blake3_hash));
        }

        // Step 3: Populate Level-1 File Catalog under single lock
        let mut catalog = self.catalog.write().map_err(|_| {
            std::io::Error::other("Level 1 dedup catalog lock poisoned")
        })?;

        for (doc_id, (file_path, mut chunk_list)) in doc_groups {
            // Sort chunks by line_start and chunk_index to maintain deterministic order
            chunk_list.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
            let chunk_hashes: Vec<String> = chunk_list.into_iter().map(|(_, _, hash)| hash).collect();

            // Opportunistically probe disk metadata for fast-path evaluation; fallback to (0, 0)
            let (mtime_secs, size_bytes) = match std::fs::metadata(&file_path) {
                Ok(meta) => {
                    let mtime = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    (mtime, meta.len())
                }
                Err(_) => (0, 0),
            };

            catalog.register_entry(FileCatalogEntry {
                file_path,
                file_blake3: doc_id,
                mtime_secs,
                size_bytes,
                chunk_hashes,
            });
        }

        Ok(chunk_count)
    }

    /// Hydrates Level-1 deduplication state directly from SQLite `document_catalog.db`.
    /// Does NOT scan LanceDB vectors into memory, completing in milliseconds.
    pub fn hydrate_from_catalog(
        &self,
        storage: &quorum_storage::StorageEngine,
    ) -> Result<usize, crate::error::IngestError> {
        let identities = storage.list_catalog_file_identities()?;
        if identities.is_empty() {
            return Ok(0);
        }

        let mut catalog = self.catalog.write().map_err(|_| {
            std::io::Error::other("Level 1 dedup catalog lock poisoned")
        })?;

        let mut count = 0;
        for ident in identities {
            let path = PathBuf::from(&ident.file_path);
            if catalog.get_file_entry(&path).is_some() {
                continue;
            }

            catalog.register_entry(FileCatalogEntry {
                file_path: path,
                file_blake3: ident.document_id,
                mtime_secs: ident.mtime_secs,
                size_bytes: ident.size_bytes,
                chunk_hashes: Vec::new(),
            });
            count += 1;
        }

        Ok(count)
    }
}
