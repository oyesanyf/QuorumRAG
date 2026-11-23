//! Disk-backed 3-Level Hierarchical Centroid Index (`Root -> Inter1 -> Leaf`)
//! and SQLite + IEEE-754 `f16` memory-mapped Knowledge Graph store.
//!
//! # Architecture & Memory Discipline
//! - `triples_meta.sqlite` (WAL mode): stores triple text, provenance, `work_cluster_id`,
//!   `access_tier`, `blake3_hash` (UNIQUE index), and soft-delete flags.
//! - `keys_leaf.f16` & `vals_leaf.f16`: flat row-major IEEE-754 little-endian `f16` shards
//!   mapped read-only via `memmap2::Mmap` (50% smaller than `f32`, ~0 resident RAM until
//!   pruned leaf pages are touched).
//! - `hierarchy_index.bin`: crash-safe atomic binary snapshot of `Root` (`k = ceil(N^(1/3))`)
//!   and `Inter1` (`k = ceil(N^(2/3))`) centroids, CSR adjacency (`root_c2id`, `inter_c2id`),
//!   and branchless `leaf_access_tier` / `leaf_active` side arrays.
//! - On Windows, active `Mmap` handles are deterministically dropped under the write lock
//!   before any file append or truncation so OS Error 32 never occurs.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use memmap2::Mmap;
use parking_lot::{Mutex, RwLock};
use rayon::prelude::*;
use rusqlite::{params, Connection};

use crate::error::AtlasKvError;
use crate::types::{
    dot_f16_le, dot_f32, encode_f32_to_f16_le, l2_normalize_in_place, normalize_path_key,
    validate_access_tier, AtlasKvStoreStats, AtlasKvTreeConfig, KgTripleRecord,
    PeerCentroidSummary,
};

const HIERARCHY_MAGIC: &[u8; 8] = b"ATKVH001";
const MINI_BATCH_THRESHOLD: usize = 25_000;
const MINI_BATCH_SIZE: usize = 16_384;

/// Compressed Sparse Row (CSR) adjacency list for `c2id` cluster-to-child mappings.
#[derive(Debug, Clone, Default)]
pub(crate) struct CsrAdjacency {
    /// Length = `num_clusters + 1`. Children of cluster `c` live at `children[offsets[c]..offsets[c+1]]`.
    pub(crate) offsets: Vec<u32>,
    pub(crate) children: Vec<u32>,
}

impl CsrAdjacency {
    pub(crate) fn from_buckets(buckets: &[Vec<u32>]) -> Self {
        let mut offsets = Vec::with_capacity(buckets.len() + 1);
        let total: usize = buckets.iter().map(|b| b.len()).sum();
        let mut children = Vec::with_capacity(total);
        offsets.push(0);
        for b in buckets {
            children.extend_from_slice(b);
            offsets.push(children.len() as u32);
        }
        Self { offsets, children }
    }

    pub(crate) fn to_buckets(&self) -> Vec<Vec<u32>> {
        if self.offsets.len() < 2 {
            return Vec::new();
        }
        let n = self.offsets.len() - 1;
        let mut out = Vec::with_capacity(n);
        for c in 0..n {
            let s = self.offsets[c] as usize;
            let e = self.offsets[c + 1] as usize;
            out.push(self.children[s..e].to_vec());
        }
        out
    }

    #[inline]
    pub(crate) fn cluster_count(&self) -> usize {
        self.offsets.len().saturating_sub(1)
    }

    #[inline]
    pub(crate) fn children_of(&self, cluster_idx: usize) -> &[u32] {
        if cluster_idx + 1 >= self.offsets.len() {
            return &[];
        }
        let start = self.offsets[cluster_idx] as usize;
        let end = self.offsets[cluster_idx + 1] as usize;
        if start <= end && end <= self.children.len() {
            &self.children[start..end]
        } else {
            &[]
        }
    }
}

/// In-memory view of the 3-level hierarchy and read-only `f16` memmap handles.
#[derive(Default)]
pub(crate) struct StoreIndexState {
    pub(crate) total_rows: usize,
    pub(crate) active_rows: usize,
    pub(crate) incremental_since_rebuild: usize,
    pub(crate) hierarchy_built: bool,
    /// Row-major `root_count * dim` L2-normalized `f32` centroids.
    pub(crate) root_centroids: Vec<f32>,
    /// Row-major `inter_count * dim` L2-normalized `f32` centroids.
    pub(crate) inter_centroids: Vec<f32>,
    /// `root_c2id`: Root cluster index -> child `Inter1` cluster indices.
    pub(crate) root_c2id: CsrAdjacency,
    /// `inter_c2id`: `Inter1` cluster index -> child `Leaf` triple IDs.
    pub(crate) inter_c2id: CsrAdjacency,
    /// Side-array indexed by `triple_id` (`0..total_rows`) for O(1) fail-closed tier filtering.
    pub(crate) leaf_access_tier: Vec<u8>,
    /// Side-array indexed by `triple_id`: `1` = active, `0` = deleted.
    pub(crate) leaf_active: Vec<u8>,
    /// Read-only memory map over `keys_leaf.f16`.
    pub(crate) keys_mmap: Option<Mmap>,
    /// Read-only memory map over `vals_leaf.f16`.
    pub(crate) vals_mmap: Option<Mmap>,
}

impl StoreIndexState {
    #[inline]
    pub(crate) fn root_count(&self, dim: usize) -> usize {
        self.root_centroids.len().checked_div(dim).unwrap_or(0)
    }

    #[inline]
    pub(crate) fn inter_count(&self, dim: usize) -> usize {
        self.inter_centroids.len().checked_div(dim).unwrap_or(0)
    }

    #[inline]
    pub(crate) fn key_f16_row(&self, triple_id: usize, dim: usize) -> Option<&[u8]> {
        let mmap = self.keys_mmap.as_ref()?;
        let row_bytes = dim.checked_mul(2)?;
        let start = triple_id.checked_mul(row_bytes)?;
        let end = start.checked_add(row_bytes)?;
        if end <= mmap.len() {
            Some(&mmap[start..end])
        } else {
            None
        }
    }

    #[inline]
    pub(crate) fn val_f16_row(&self, triple_id: usize, dim: usize) -> Option<&[u8]> {
        let mmap = self.vals_mmap.as_ref()?;
        let row_bytes = dim.checked_mul(2)?;
        let start = triple_id.checked_mul(row_bytes)?;
        let end = start.checked_add(row_bytes)?;
        if end <= mmap.len() {
            Some(&mmap[start..end])
        } else {
            None
        }
    }

    fn drop_mmaps(&mut self) {
        self.keys_mmap = None;
        self.vals_mmap = None;
    }

    fn remap_shards(&mut self, keys_path: &Path, vals_path: &Path) -> Result<(), AtlasKvError> {
        self.drop_mmaps();
        if keys_path.exists() {
            let meta = fs::metadata(keys_path).map_err(|e| AtlasKvError::Io {
                path: keys_path.to_path_buf(),
                source: e,
            })?;
            if meta.len() > 0 {
                let file = File::open(keys_path).map_err(|e| AtlasKvError::Io {
                    path: keys_path.to_path_buf(),
                    source: e,
                })?;
                // SAFETY: File is only mutated while write lock is held and existing mmaps are dropped first.
                let mmap = unsafe {
                    Mmap::map(&file).map_err(|e| AtlasKvError::Io {
                        path: keys_path.to_path_buf(),
                        source: e,
                    })?
                };
                self.keys_mmap = Some(mmap);
            }
        }
        if vals_path.exists() {
            let meta = fs::metadata(vals_path).map_err(|e| AtlasKvError::Io {
                path: vals_path.to_path_buf(),
                source: e,
            })?;
            if meta.len() > 0 {
                let file = File::open(vals_path).map_err(|e| AtlasKvError::Io {
                    path: vals_path.to_path_buf(),
                    source: e,
                })?;
                // SAFETY: File is only mutated while write lock is held and existing mmaps are dropped first.
                let mmap = unsafe {
                    Mmap::map(&file).map_err(|e| AtlasKvError::Io {
                        path: vals_path.to_path_buf(),
                        source: e,
                    })?
                };
                self.vals_mmap = Some(mmap);
            }
        }
        Ok(())
    }
}

/// Embedded pure-Rust AtlasKV store managing KG2KV triples, `f16` vector shards,
/// and the 3-level `Root -> Inter1 -> Leaf` hierarchical index.
pub struct AtlasKvStore {
    pub(crate) dir: PathBuf,
    pub(crate) config: AtlasKvTreeConfig,
    pub(crate) db: Mutex<Connection>,
    pub(crate) state: RwLock<StoreIndexState>,
}

impl AtlasKvStore {
    /// Opens or initializes an `AtlasKvStore` inside `dir`.
    pub fn open(dir: impl AsRef<Path>, config: AtlasKvTreeConfig) -> Result<Self, AtlasKvError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).map_err(|e| AtlasKvError::Io {
            path: dir.clone(),
            source: e,
        })?;

        let db_path = dir.join("triples_meta.sqlite");
        let mut conn = Connection::open(&db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA temp_store = MEMORY;
             CREATE TABLE IF NOT EXISTS triples (
                 triple_id       INTEGER PRIMARY KEY,
                 blake3_hash     TEXT NOT NULL,
                 entity          TEXT NOT NULL,
                 relation        TEXT NOT NULL,
                 key_string      TEXT NOT NULL,
                 value           TEXT NOT NULL,
                 document_id     TEXT NOT NULL,
                 chunk_id        TEXT NOT NULL,
                 file_path       TEXT NOT NULL,
                 file_path_norm  TEXT NOT NULL,
                 line_start      INTEGER NOT NULL,
                 line_end        INTEGER NOT NULL,
                 work_cluster_id TEXT NOT NULL,
                 access_tier     INTEGER NOT NULL,
                 source_peer     TEXT NOT NULL,
                 deleted         INTEGER NOT NULL DEFAULT 0
             );
             CREATE INDEX IF NOT EXISTS idx_triples_blake3 ON triples(blake3_hash);
             CREATE INDEX IF NOT EXISTS idx_triples_file_norm ON triples(file_path_norm);
             CREATE INDEX IF NOT EXISTS idx_triples_doc_id ON triples(document_id);
             CREATE INDEX IF NOT EXISTS idx_triples_tier_active ON triples(deleted, access_tier);",
        )?;

        // Backfill any legacy `file_path_norm` rows (Unix mixed-case, Windows roots, UNC,
        // `\\?\` / `//?/`) whose stored key diverges from `normalize_path_key(&file_path)`.
        {
            let tx = conn.transaction()?;
            let updates: Vec<(i64, String)> = {
                let mut stmt =
                    tx.prepare("SELECT triple_id, file_path, file_path_norm FROM triples")?;
                let mut rows = stmt.query([])?;
                let mut pending = Vec::new();
                while let Some(row) = rows.next()? {
                    let tid: i64 = row.get(0)?;
                    let fp: String = row.get(1)?;
                    let existing_norm: String = row.get(2)?;
                    let expected_norm = normalize_path_key(&fp);
                    if existing_norm != expected_norm {
                        pending.push((tid, expected_norm));
                    }
                }
                pending
            };
            if !updates.is_empty() {
                let mut upd =
                    tx.prepare("UPDATE triples SET file_path_norm = ?1 WHERE triple_id = ?2")?;
                for (tid, norm) in updates {
                    upd.execute(params![norm, tid])?;
                }
            }
            tx.commit()?;
        }

        let mut index_state = StoreIndexState::default();
        let hier_path = dir.join("hierarchy_index.bin");
        let keys_path = dir.join("keys_leaf.f16");
        let vals_path = dir.join("vals_leaf.f16");

        if hier_path.exists() {
            if let Ok(loaded) = load_hierarchy_bin(&hier_path, config.embedding_dim) {
                index_state = loaded;
            }
        }

        // Reconcile side arrays with SQLite if hierarchy_index.bin did not exist yet
        let db_max_rows: usize = conn
            .query_row(
                "SELECT COALESCE(MAX(triple_id) + 1, 0) FROM triples",
                [],
                |r| r.get::<_, i64>(0),
            )?
            .max(0) as usize;

        if index_state.total_rows != db_max_rows {
            index_state.leaf_access_tier = vec![3u8; db_max_rows];
            index_state.leaf_active = vec![0u8; db_max_rows];
            let mut stmt = conn.prepare(
                "SELECT triple_id, access_tier, deleted FROM triples ORDER BY triple_id ASC",
            )?;
            let mut active = 0usize;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)? as usize,
                    row.get::<_, i64>(1)? as u8,
                    row.get::<_, i64>(2)?,
                ))
            })?;
            for item in rows {
                let (tid, tier, deleted) = item?;
                if tid < db_max_rows {
                    index_state.leaf_access_tier[tid] = tier;
                    if deleted == 0 {
                        index_state.leaf_active[tid] = 1;
                        active += 1;
                    }
                }
            }
            index_state.total_rows = db_max_rows;
            index_state.active_rows = active;
            index_state.hierarchy_built = false;
            index_state.root_centroids.clear();
            index_state.inter_centroids.clear();
            index_state.root_c2id = CsrAdjacency::default();
            index_state.inter_c2id = CsrAdjacency::default();
        }

        index_state.remap_shards(&keys_path, &vals_path)?;

        Ok(Self {
            dir,
            config,
            db: Mutex::new(conn),
            state: RwLock::new(index_state),
        })
    }

    pub fn config(&self) -> &AtlasKvTreeConfig {
        &self.config
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn keys_path(&self) -> PathBuf {
        self.dir.join("keys_leaf.f16")
    }

    pub(crate) fn vals_path(&self) -> PathBuf {
        self.dir.join("vals_leaf.f16")
    }

    pub(crate) fn hierarchy_path(&self) -> PathBuf {
        self.dir.join("hierarchy_index.bin")
    }

    /// Inserts triples alongside their `key` and `value` embeddings, performing BLAKE3 deduplication,
    /// L2 normalization, `f16` shard appending, and instant incremental cluster attachment if a
    /// hierarchy is already built.
    pub fn insert_triples(
        &self,
        triples: &[KgTripleRecord],
        key_vecs: &[Vec<f32>],
        val_vecs: &[Vec<f32>],
    ) -> Result<usize, AtlasKvError> {
        if triples.len() != key_vecs.len() || triples.len() != val_vecs.len() {
            return Err(AtlasKvError::LengthMismatch {
                context: format!(
                    "triples ({}), key_vecs ({}), and val_vecs ({}) must match",
                    triples.len(),
                    key_vecs.len(),
                    val_vecs.len()
                ),
            });
        }
        if triples.is_empty() {
            return Ok(0);
        }

        let dim = self.config.embedding_dim;
        for (idx, (kv, vv)) in key_vecs.iter().zip(val_vecs.iter()).enumerate() {
            if kv.len() != dim {
                return Err(AtlasKvError::DimensionMismatch {
                    expected: dim,
                    actual: kv.len(),
                });
            }
            if vv.len() != dim {
                return Err(AtlasKvError::DimensionMismatch {
                    expected: dim,
                    actual: vv.len(),
                });
            }
            validate_access_tier(triples[idx].access_tier)?;
        }

        let mut db = self.db.lock();
        let mut st = self.state.write();

        // Filter duplicates against active SQLite hashes and within this batch
        let mut seen_batch: HashSet<String> = HashSet::with_capacity(triples.len());
        let mut to_insert: Vec<(KgTripleRecord, Vec<f32>, Vec<f32>)> =
            Vec::with_capacity(triples.len());

        {
            let mut exists_stmt = db.prepare_cached(
                "SELECT 1 FROM triples WHERE blake3_hash = ?1 AND deleted = 0 LIMIT 1",
            )?;
            for ((rec, kv), vv) in triples.iter().zip(key_vecs.iter()).zip(val_vecs.iter()) {
                let hash = if rec.blake3_hash.is_empty() {
                    KgTripleRecord::compute_blake3(
                        &rec.entity,
                        &rec.relation,
                        &rec.value,
                        &rec.file_path,
                    )
                } else {
                    rec.blake3_hash.clone()
                };
                if !seen_batch.insert(hash.clone()) {
                    continue;
                }
                let already_exists = exists_stmt.query_row(params![&hash], |_| Ok(())).is_ok();
                if already_exists {
                    continue;
                }
                let mut r = rec.clone();
                r.blake3_hash = hash;
                if r.key_string.is_empty() {
                    r.key_string = KgTripleRecord::build_key_string(&r.entity, &r.relation);
                }
                let mut kn = kv.clone();
                let mut vn = vv.clone();
                l2_normalize_in_place(&mut kn);
                l2_normalize_in_place(&mut vn);
                to_insert.push((r, kn, vn));
            }
        }

        if to_insert.is_empty() {
            return Ok(0);
        }

        // Encode f16 shard bytes before mutating files
        let mut key_bytes = Vec::with_capacity(to_insert.len() * dim * 2);
        let mut val_bytes = Vec::with_capacity(to_insert.len() * dim * 2);
        for (_, kn, vn) in &to_insert {
            encode_f32_to_f16_le(kn, &mut key_bytes);
            encode_f32_to_f16_le(vn, &mut val_bytes);
        }

        let keys_path = self.keys_path();
        let vals_path = self.vals_path();

        // Windows safety: release read-only mmaps before writing to shard files
        st.drop_mmaps();

        append_bytes(&keys_path, &key_bytes)?;
        append_bytes(&vals_path, &val_bytes)?;

        // Commit SQLite rows atomically
        let start_tid = st.total_rows;
        let tx = db.transaction()?;
        {
            let mut ins = tx.prepare_cached(
                "INSERT INTO triples (
                    triple_id, blake3_hash, entity, relation, key_string, value,
                    document_id, chunk_id, file_path, file_path_norm,
                    line_start, line_end, work_cluster_id, access_tier, source_peer, deleted
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, 0)",
            )?;
            for (offset, (rec, _, _)) in to_insert.iter().enumerate() {
                let tid = (start_tid + offset) as i64;
                let norm_path = normalize_path_key(&rec.file_path);
                ins.execute(params![
                    tid,
                    rec.blake3_hash,
                    rec.entity,
                    rec.relation,
                    rec.key_string,
                    rec.value,
                    rec.document_id,
                    rec.chunk_id,
                    rec.file_path,
                    norm_path,
                    rec.line_start as i64,
                    rec.line_end as i64,
                    rec.work_cluster_id,
                    rec.access_tier as i64,
                    rec.source_peer,
                ])?;
            }
        }
        tx.commit()?;

        // Update side arrays & optionally attach incrementally to existing hierarchy
        let added = to_insert.len();
        for (rec, _, _) in &to_insert {
            st.leaf_access_tier.push(rec.access_tier);
            st.leaf_active.push(1);
        }
        st.total_rows += added;
        st.active_rows += added;
        st.incremental_since_rebuild += added;

        if st.hierarchy_built && st.inter_count(dim) > 0 && st.root_count(dim) > 0 {
            let mut inter_buckets = st.inter_c2id.to_buckets();
            let root_count = st.root_count(dim);
            for (offset, (_, kn, _)) in to_insert.iter().enumerate() {
                let tid = (start_tid + offset) as u32;
                // Find nearest Root -> nearest Inter1 child
                let mut best_root = 0usize;
                let mut best_root_sim = f32::NEG_INFINITY;
                for r in 0..root_count {
                    let s = dot_f32(kn, &st.root_centroids[r * dim..(r + 1) * dim]);
                    if s > best_root_sim {
                        best_root_sim = s;
                        best_root = r;
                    }
                }
                let candidate_inters = st.root_c2id.children_of(best_root);
                let mut best_inter = candidate_inters.first().copied().unwrap_or(0) as usize;
                let mut best_inter_sim = f32::NEG_INFINITY;
                for &inter_id_u32 in candidate_inters {
                    let inter_id = inter_id_u32 as usize;
                    let s = dot_f32(
                        kn,
                        &st.inter_centroids[inter_id * dim..(inter_id + 1) * dim],
                    );
                    if s > best_inter_sim {
                        best_inter_sim = s;
                        best_inter = inter_id;
                    }
                }
                if best_inter < inter_buckets.len() {
                    inter_buckets[best_inter].push(tid);
                }
            }
            st.inter_c2id = CsrAdjacency::from_buckets(&inter_buckets);
            save_hierarchy_bin(&self.hierarchy_path(), dim, &st)?;
        }

        st.remap_shards(&keys_path, &vals_path)?;
        Ok(added)
    }

    /// Rebuilds the 3-level `Root -> Inter1 -> Leaf` hierarchical centroid index using parallel
    /// Mini-Batch Spherical K-Means++ over all active leaf key embeddings.
    ///
    /// Follows AtlasKV's scaling law:
    /// - $k_{\text{inter1}} = \lceil N^{2/3} \rceil$ (clamped)
    /// - $k_{\text{root}} = \lceil N^{1/3} \rceil$ (clamped)
    pub fn rebuild_hierarchy(&self) -> Result<AtlasKvStoreStats, AtlasKvError> {
        let mut st = self.state.write();
        self.rebuild_hierarchy_locked(&mut st)
    }

    fn rebuild_hierarchy_locked(
        &self,
        st: &mut StoreIndexState,
    ) -> Result<AtlasKvStoreStats, AtlasKvError> {
        let dim = self.config.embedding_dim;

        let active_ids: Vec<u32> = st
            .leaf_active
            .iter()
            .enumerate()
            .filter_map(|(idx, &flag)| if flag == 1 { Some(idx as u32) } else { None })
            .collect();

        let n = active_ids.len();
        if n < 4 {
            st.hierarchy_built = false;
            st.root_centroids.clear();
            st.inter_centroids.clear();
            st.root_c2id = CsrAdjacency::default();
            st.inter_c2id = CsrAdjacency::default();
            st.incremental_since_rebuild = 0;
            save_hierarchy_bin(&self.hierarchy_path(), dim, st)?;
            return Ok(self.compute_stats_locked(st));
        }

        let keys_mmap = st.keys_mmap.as_ref().ok_or_else(|| {
            AtlasKvError::CorruptedHierarchy("keys_leaf.f16 shard missing during rebuild".into())
        })?;
        let mmap_slice: &[u8] = keys_mmap;

        // Compute AtlasKV 3-level cluster counts: k_inter1 = ceil(N^(2/3)), k_root = ceil(N^(1/3))
        let k_inter_raw = (n as f64).powf(2.0 / 3.0).ceil() as usize;
        let k_inter = k_inter_raw.clamp(2, self.config.max_inter_clusters).min(n);
        let k_root_raw = (n as f64).powf(1.0 / 3.0).ceil() as usize;
        let k_root = k_root_raw
            .clamp(1, self.config.max_root_clusters)
            .min(k_inter);

        // Stage 1: Cluster active Leaf keys -> Inter1 centroids
        let (inter_centroids, inter_buckets) = spherical_kmeans_f16_leaves(
            mmap_slice,
            &active_ids,
            dim,
            k_inter,
            self.config.max_kmeans_iters,
            0x4154_4C41_534B_5601,
        );
        let actual_inter = inter_buckets.len();
        let actual_root_target = k_root.min(actual_inter).max(1);

        // Stage 2: Cluster Inter1 centroids -> Root centroids
        let (root_centroids, root_buckets) = spherical_kmeans_f32_rows(
            &inter_centroids,
            actual_inter,
            dim,
            actual_root_target,
            self.config.max_kmeans_iters,
            0x4154_4C41_534B_5602,
        );

        st.inter_centroids = inter_centroids;
        st.inter_c2id = CsrAdjacency::from_buckets(&inter_buckets);
        st.root_centroids = root_centroids;
        st.root_c2id = CsrAdjacency::from_buckets(&root_buckets);
        st.hierarchy_built = true;
        st.incremental_since_rebuild = 0;

        save_hierarchy_bin(&self.hierarchy_path(), dim, st)?;
        Ok(self.compute_stats_locked(st))
    }

    /// Marks all KG triples originating from `file_path` as deleted so they immediately vanish
    /// from HiKVP queries without stalling ingestion.
    pub fn delete_by_file_path(&self, file_path: &str) -> Result<usize, AtlasKvError> {
        let norm = normalize_path_key(file_path);
        let db = self.db.lock();
        let mut st = self.state.write();

        let mut stmt =
            db.prepare("SELECT triple_id FROM triples WHERE file_path_norm = ?1 AND deleted = 0")?;
        let tids: Vec<usize> = stmt
            .query_map(params![&norm], |row| Ok(row.get::<_, i64>(0)? as usize))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);

        if tids.is_empty() {
            return Ok(0);
        }

        db.execute(
            "UPDATE triples SET deleted = 1 WHERE file_path_norm = ?1 AND deleted = 0",
            params![&norm],
        )?;

        let mut removed = 0usize;
        for tid in tids {
            if tid < st.leaf_active.len() && st.leaf_active[tid] == 1 {
                st.leaf_active[tid] = 0;
                removed += 1;
            }
        }
        st.active_rows = st.active_rows.saturating_sub(removed);

        if removed > 0 && (st.hierarchy_built || self.hierarchy_path().exists()) {
            save_hierarchy_bin(&self.hierarchy_path(), self.config.embedding_dim, &st)?;
        }

        Ok(removed)
    }

    /// Marks all KG triples whose raw `file_path` falls under `prefix` (validated and matched
    /// fail-closed on component boundaries via `quorum_types::path_matches_prefix`) as deleted,
    /// keeps the HiKVP hierarchy consistent, and persists `hierarchy_index.bin`.
    pub fn delete_by_path_prefix(&self, prefix: &str) -> Result<usize, AtlasKvError> {
        let norm_prefix = quorum_types::normalize_prefix_for_match(prefix)?;
        let mut db = self.db.lock();
        let mut st = self.state.write();

        let tids: Vec<usize> = {
            let mut stmt =
                db.prepare("SELECT triple_id, file_path FROM triples WHERE deleted = 0")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, i64>(0)? as usize, row.get::<_, String>(1)?))
            })?;
            let mut matched = Vec::new();
            for item in rows {
                let (tid, fp) = item?;
                if quorum_types::path_matches_prefix(&fp, &norm_prefix).unwrap_or(false) {
                    matched.push(tid);
                }
            }
            matched
        };

        if tids.is_empty() {
            return Ok(0);
        }

        let tx = db.transaction()?;
        {
            let mut upd = tx.prepare_cached(
                "UPDATE triples SET deleted = 1 WHERE triple_id = ?1 AND deleted = 0",
            )?;
            for &tid in &tids {
                upd.execute(params![tid as i64])?;
            }
        }
        tx.commit()?;

        let mut removed = 0usize;
        for tid in tids {
            if tid < st.leaf_active.len() && st.leaf_active[tid] == 1 {
                st.leaf_active[tid] = 0;
                removed += 1;
            }
        }
        st.active_rows = st.leaf_active.iter().filter(|&&b| b == 1).count();

        let mut saved_hier = false;
        if st.hierarchy_built {
            if st.active_rows < 4 || st.keys_mmap.is_none() {
                st.hierarchy_built = false;
                st.root_centroids.clear();
                st.inter_centroids.clear();
                st.root_c2id = CsrAdjacency::default();
                st.inter_c2id = CsrAdjacency::default();
                st.incremental_since_rebuild = 0;
            } else {
                let _ = self.rebuild_hierarchy_locked(&mut st)?;
                saved_hier = true;
            }
        }

        if removed > 0 && !saved_hier {
            save_hierarchy_bin(&self.hierarchy_path(), self.config.embedding_dim, &st)?;
        }

        Ok(removed)
    }

    /// Updates `access_tier` across SQLite `triples`, in-memory `leaf_access_tier`, and
    /// `hierarchy_index.bin` for all active triples originating from `chunk_id`.
    pub fn update_chunk_access_tier(
        &self,
        chunk_id: &str,
        new_tier: u8,
    ) -> Result<usize, AtlasKvError> {
        validate_access_tier(new_tier)?;
        let mut db = self.db.lock();
        let mut st = self.state.write();

        let tids: Vec<usize> = {
            let mut stmt = db.prepare(
                "SELECT triple_id FROM triples WHERE chunk_id = ?1 AND deleted = 0 AND access_tier != ?2",
            )?;
            let rows = stmt
                .query_map(params![chunk_id, new_tier as i64], |row| {
                    Ok(row.get::<_, i64>(0)? as usize)
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };

        if tids.is_empty() {
            return Ok(0);
        }

        let tx = db.transaction()?;
        tx.execute(
            "UPDATE triples SET access_tier = ?1 WHERE chunk_id = ?2 AND deleted = 0 AND access_tier != ?1",
            params![new_tier as i64, chunk_id],
        )?;
        tx.commit()?;

        let mut updated = 0usize;
        for tid in tids {
            if tid < st.leaf_access_tier.len() {
                st.leaf_access_tier[tid] = new_tier;
                updated += 1;
            }
        }

        if updated > 0 && (st.hierarchy_built || self.hierarchy_path().exists()) {
            save_hierarchy_bin(&self.hierarchy_path(), self.config.embedding_dim, &st)?;
        }

        Ok(updated)
    }

    /// Updates `access_tier` across SQLite `triples`, in-memory `leaf_access_tier`, and
    /// `hierarchy_index.bin` for active triples matching `(chunk_id, file_path_norm)`,
    /// preserving sibling copies at other paths.
    pub fn update_chunk_access_tier_for_file(
        &self,
        chunk_id: &str,
        file_path: &str,
        new_tier: u8,
    ) -> Result<usize, AtlasKvError> {
        validate_access_tier(new_tier)?;
        let norm = normalize_path_key(file_path);
        let mut db = self.db.lock();
        let mut st = self.state.write();

        let tids: Vec<usize> = {
            let mut stmt = db.prepare(
                "SELECT triple_id FROM triples WHERE chunk_id = ?1 AND file_path_norm = ?2 AND deleted = 0 AND access_tier != ?3",
            )?;
            let rows = stmt
                .query_map(params![chunk_id, &norm, new_tier as i64], |row| {
                    Ok(row.get::<_, i64>(0)? as usize)
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };

        if tids.is_empty() {
            return Ok(0);
        }

        let tx = db.transaction()?;
        tx.execute(
            "UPDATE triples SET access_tier = ?1 WHERE chunk_id = ?2 AND file_path_norm = ?3 AND deleted = 0 AND access_tier != ?1",
            params![new_tier as i64, chunk_id, &norm],
        )?;
        tx.commit()?;

        let mut updated = 0usize;
        for tid in tids {
            if tid < st.leaf_access_tier.len() {
                st.leaf_access_tier[tid] = new_tier;
                updated += 1;
            }
        }

        if updated > 0 && (st.hierarchy_built || self.hierarchy_path().exists()) {
            save_hierarchy_bin(&self.hierarchy_path(), self.config.embedding_dim, &st)?;
        }

        Ok(updated)
    }

    /// Updates `access_tier` across SQLite `triples`, in-memory `leaf_access_tier`, and
    /// `hierarchy_index.bin` for all active triples matching `prefix` on component boundaries.
    pub fn update_access_tier_by_path_prefix(
        &self,
        prefix: &str,
        new_tier: u8,
    ) -> Result<usize, AtlasKvError> {
        validate_access_tier(new_tier)?;
        let norm_prefix = quorum_types::normalize_prefix_for_match(prefix)?;
        let mut db = self.db.lock();
        let mut st = self.state.write();

        let tids: Vec<usize> = {
            let mut stmt = db.prepare(
                "SELECT triple_id, file_path FROM triples WHERE deleted = 0 AND access_tier != ?1",
            )?;
            let rows = stmt.query_map(params![new_tier as i64], |row| {
                Ok((row.get::<_, i64>(0)? as usize, row.get::<_, String>(1)?))
            })?;
            let mut matched = Vec::new();
            for item in rows {
                let (tid, fp) = item?;
                if quorum_types::path_matches_prefix(&fp, &norm_prefix).unwrap_or(false) {
                    matched.push(tid);
                }
            }
            matched
        };

        if tids.is_empty() {
            return Ok(0);
        }

        let tx = db.transaction()?;
        {
            let mut upd = tx.prepare_cached(
                "UPDATE triples SET access_tier = ?1 WHERE triple_id = ?2 AND deleted = 0",
            )?;
            for &tid in &tids {
                upd.execute(params![new_tier as i64, tid as i64])?;
            }
        }
        tx.commit()?;

        let mut updated = 0usize;
        for tid in tids {
            if tid < st.leaf_access_tier.len() {
                st.leaf_access_tier[tid] = new_tier;
                updated += 1;
            }
        }

        if updated > 0 && (st.hierarchy_built || self.hierarchy_path().exists()) {
            save_hierarchy_bin(&self.hierarchy_path(), self.config.embedding_dim, &st)?;
        }

        Ok(updated)
    }

    /// Removes all triples, shards, and hierarchy state cleanly (safely releasing Windows mmaps first).
    pub fn clear_all(&self) -> Result<(), AtlasKvError> {
        let db = self.db.lock();
        let mut st = self.state.write();
        st.drop_mmaps();

        db.execute("DELETE FROM triples", [])?;
        for p in [self.keys_path(), self.vals_path(), self.hierarchy_path()] {
            if p.exists() {
                fs::remove_file(&p).map_err(|e| AtlasKvError::Io { path: p, source: e })?;
            }
        }

        *st = StoreIndexState::default();
        Ok(())
    }

    /// Exports a compact, privacy-preserving `f16` Root centroid digest strictly computed from
    /// active leaves with `access_tier <= max_tier` (capped to `max_centroids`), safe for libp2p
    /// mesh gossip and centroid-guided peer routing.
    pub fn export_root_centroid_summary(
        &self,
        peer_id: &str,
        max_tier: u8,
        max_centroids: usize,
    ) -> Result<PeerCentroidSummary, AtlasKvError> {
        validate_access_tier(max_tier)?;
        let dim = self.config.embedding_dim;
        let st = self.state.read();
        let max_c = max_centroids.clamp(1, 256);

        let Some(keys_mmap) = st.keys_mmap.as_ref() else {
            return Ok(PeerCentroidSummary {
                peer_id: peer_id.to_string(),
                max_tier_included: max_tier,
                embedding_dim: dim,
                centroid_count: 0,
                active_triple_count: 0,
                centroids_f16_le: Vec::new(),
            });
        };

        let mut authorized_total = 0usize;
        let mut group_centroids: Vec<(usize, Vec<f32>)> = Vec::new();

        if st.hierarchy_built && st.root_c2id.cluster_count() > 0 {
            // Re-average strictly authorized leaves (`access_tier <= max_tier`) inside each Root subtree
            // so zero Confidential/Restricted vector signal ever bleeds into public mesh centroids!
            for r in 0..st.root_c2id.cluster_count() {
                let mut acc = vec![0.0f32; dim];
                let mut count = 0usize;
                for &inter_id in st.root_c2id.children_of(r) {
                    for &leaf_id_u32 in st.inter_c2id.children_of(inter_id as usize) {
                        let lid = leaf_id_u32 as usize;
                        if lid < st.leaf_active.len()
                            && st.leaf_active[lid] == 1
                            && st.leaf_access_tier[lid] <= max_tier
                        {
                            if let Some(row) = st.key_f16_row(lid, dim) {
                                accumulate_f16_into_f32(&mut acc, row);
                                count += 1;
                            }
                        }
                    }
                }
                if count > 0 && l2_normalize_in_place(&mut acc) {
                    authorized_total += count;
                    group_centroids.push((count, acc));
                }
            }
        } else {
            // Small unclustered store: compute up to `max_c` centroids or direct authorized leaf mean
            let mut auth_ids = Vec::new();
            for lid in 0..st.total_rows {
                if st.leaf_active[lid] == 1 && st.leaf_access_tier[lid] <= max_tier {
                    auth_ids.push(lid as u32);
                }
            }
            authorized_total = auth_ids.len();
            if !auth_ids.is_empty() {
                let k = (auth_ids.len() as f64).powf(1.0 / 3.0).ceil() as usize;
                let k = k.clamp(1, max_c).min(auth_ids.len());
                let (cents, buckets) = spherical_kmeans_f16_leaves(
                    keys_mmap,
                    &auth_ids,
                    dim,
                    k,
                    8,
                    0x4154_4C41_534B_5603,
                );
                for (idx, b) in buckets.iter().enumerate() {
                    if !b.is_empty() {
                        group_centroids.push((b.len(), cents[idx * dim..(idx + 1) * dim].to_vec()));
                    }
                }
            }
        }

        // Keep top-`max_c` most populated authorized centroids
        group_centroids.sort_by_key(|a| std::cmp::Reverse(a.0));
        group_centroids.truncate(max_c);

        let mut f16_bytes = Vec::with_capacity(group_centroids.len() * dim * 2);
        for (_, vec_f32) in &group_centroids {
            encode_f32_to_f16_le(vec_f32, &mut f16_bytes);
        }

        Ok(PeerCentroidSummary {
            peer_id: peer_id.to_string(),
            max_tier_included: max_tier,
            embedding_dim: dim,
            centroid_count: group_centroids.len(),
            active_triple_count: authorized_total,
            centroids_f16_le: f16_bytes,
        })
    }

    /// Returns live statistics about triple counts, hierarchy topology, disk, and RAM usage.
    pub fn stats(&self) -> AtlasKvStoreStats {
        let st = self.state.read();
        self.compute_stats_locked(&st)
    }

    pub(crate) fn compute_stats_locked(&self, st: &StoreIndexState) -> AtlasKvStoreStats {
        let dim = self.config.embedding_dim;
        let disk_keys = fs::metadata(self.keys_path()).map(|m| m.len()).unwrap_or(0);
        let disk_vals = fs::metadata(self.vals_path()).map(|m| m.len()).unwrap_or(0);
        let disk_hier = fs::metadata(self.hierarchy_path())
            .map(|m| m.len())
            .unwrap_or(0);

        let ram_bytes = (st.root_centroids.len() * 4
            + st.inter_centroids.len() * 4
            + (st.root_c2id.offsets.len() + st.root_c2id.children.len()) * 4
            + (st.inter_c2id.offsets.len() + st.inter_c2id.children.len()) * 4
            + st.leaf_access_tier.len()
            + st.leaf_active.len()) as u64;

        AtlasKvStoreStats {
            total_rows: st.total_rows,
            active_triples: st.active_rows,
            deleted_triples: st.total_rows.saturating_sub(st.active_rows),
            root_clusters: st.root_count(dim),
            inter_clusters: st.inter_count(dim),
            embedding_dim: dim,
            hierarchy_built: st.hierarchy_built,
            incremental_since_rebuild: st.incremental_since_rebuild,
            disk_bytes_shards: disk_keys + disk_vals + disk_hier,
            estimated_resident_ram_bytes: ram_bytes,
        }
    }

    /// Loads `KgTripleRecord` metadata rows from SQLite for a given list of `triple_id`s.
    pub(crate) fn fetch_records_by_ids(
        &self,
        triple_ids: &[u32],
    ) -> Result<HashMap<u64, KgTripleRecord>, AtlasKvError> {
        if triple_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let db = self.db.lock();
        let mut out = HashMap::with_capacity(triple_ids.len());
        let mut stmt = db.prepare_cached(
            "SELECT triple_id, blake3_hash, entity, relation, key_string, value,
                    document_id, chunk_id, file_path, line_start, line_end,
                    work_cluster_id, access_tier, source_peer
             FROM triples WHERE triple_id = ?1 AND deleted = 0",
        )?;
        for &tid in triple_ids {
            if let Ok(rec) = stmt.query_row(params![tid as i64], row_to_triple) {
                out.insert(rec.triple_id, rec);
            }
        }
        Ok(out)
    }

    /// Loads all active records matching `access_tier <= max_tier` ordered by `triple_id`.
    pub(crate) fn fetch_all_active_records(
        &self,
        max_tier: u8,
    ) -> Result<Vec<KgTripleRecord>, AtlasKvError> {
        validate_access_tier(max_tier)?;
        let db = self.db.lock();
        let mut stmt = db.prepare(
            "SELECT triple_id, blake3_hash, entity, relation, key_string, value,
                    document_id, chunk_id, file_path, line_start, line_end,
                    work_cluster_id, access_tier, source_peer
             FROM triples WHERE deleted = 0 AND access_tier <= ?1
             ORDER BY triple_id ASC",
        )?;
        let rows = stmt
            .query_map(params![max_tier as i64], row_to_triple)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

fn row_to_triple(row: &rusqlite::Row<'_>) -> rusqlite::Result<KgTripleRecord> {
    Ok(KgTripleRecord {
        triple_id: row.get::<_, i64>(0)? as u64,
        blake3_hash: row.get(1)?,
        entity: row.get(2)?,
        relation: row.get(3)?,
        key_string: row.get(4)?,
        value: row.get(5)?,
        document_id: row.get(6)?,
        chunk_id: row.get(7)?,
        file_path: row.get(8)?,
        line_start: row.get::<_, i64>(9)? as u32,
        line_end: row.get::<_, i64>(10)? as u32,
        work_cluster_id: row.get(11)?,
        access_tier: row.get::<_, i64>(12)? as u8,
        source_peer: row.get(13)?,
    })
}

fn append_bytes(path: &Path, data: &[u8]) -> Result<(), AtlasKvError> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| AtlasKvError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    file.write_all(data).map_err(|e| AtlasKvError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    file.flush().map_err(|e| AtlasKvError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(())
}

#[inline]
fn accumulate_f16_into_f32(acc: &mut [f32], f16_le_bytes: &[u8]) {
    let (pairs, _) = f16_le_bytes.as_chunks::<2>();
    for (dst, &pair) in acc.iter_mut().zip(pairs.iter()) {
        *dst += half::f16::from_le_bytes(pair).to_f32();
    }
}

#[inline]
fn decode_f16_row(f16_le_bytes: &[u8], out: &mut [f32]) {
    let (pairs, _) = f16_le_bytes.as_chunks::<2>();
    for (dst, &pair) in out.iter_mut().zip(pairs.iter()) {
        *dst = half::f16::from_le_bytes(pair).to_f32();
    }
}

/// Deterministic fast PRNG (SplitMix64) for reproducible K-Means++ seeding.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / ((1u64 << 53) as f64))
    }

    fn gen_range(&mut self, upper: usize) -> usize {
        if upper <= 1 {
            0
        } else {
            (self.next_u64() as usize) % upper
        }
    }
}

/// Parallel Mini-Batch Spherical K-Means++ directly over read-only `f16` leaf shards.
fn spherical_kmeans_f16_leaves(
    keys_mmap: &[u8],
    active_ids: &[u32],
    dim: usize,
    k: usize,
    max_iters: usize,
    seed: u64,
) -> (Vec<f32>, Vec<Vec<u32>>) {
    let n = active_ids.len();
    let k = k.clamp(1, n);
    let row_bytes = dim * 2;
    let mut rng = SplitMix64(seed);

    // Choose training sample (full active set when <= 25K, stratified random sample when larger)
    let sample_ids: Vec<u32> = if n <= MINI_BATCH_THRESHOLD {
        active_ids.to_vec()
    } else {
        let mut sampled = Vec::with_capacity(MINI_BATCH_SIZE);
        let stride = (n as f64) / (MINI_BATCH_SIZE as f64);
        for i in 0..MINI_BATCH_SIZE {
            let base = ((i as f64) * stride) as usize;
            let jitter = rng.gen_range((stride.ceil() as usize).max(1));
            let idx = (base + jitter).min(n - 1);
            sampled.push(active_ids[idx]);
        }
        sampled
    };

    // Decode sample into contiguous f32 matrix for fast K-Means++ initialization & Lloyd loops
    let m = sample_ids.len();
    let mut sample_mat = vec![0.0f32; m * dim];
    sample_mat
        .par_chunks_mut(dim)
        .enumerate()
        .for_each(|(i, dst)| {
            let lid = sample_ids[i] as usize;
            let start = lid * row_bytes;
            if start + row_bytes <= keys_mmap.len() {
                decode_f16_row(&keys_mmap[start..start + row_bytes], dst);
            }
        });

    let (trained_centroids, _) = spherical_kmeans_f32_rows(&sample_mat, m, dim, k, max_iters, seed);
    drop(sample_mat);

    let trained_k = trained_centroids.len() / dim;

    // Assign ALL active leaves in parallel directly from f16 mmap -> build exact mean centroids & buckets
    let assignments: Vec<usize> = active_ids
        .par_iter()
        .map(|&lid| {
            let start = (lid as usize) * row_bytes;
            let row = &keys_mmap[start..start + row_bytes];
            let mut best_c = 0usize;
            let mut best_sim = f32::NEG_INFINITY;
            for c in 0..trained_k {
                let sim = dot_f16_le(&trained_centroids[c * dim..(c + 1) * dim], row);
                if sim > best_sim {
                    best_sim = sim;
                    best_c = c;
                }
            }
            best_c
        })
        .collect();

    let mut raw_buckets: Vec<Vec<u32>> = vec![Vec::new(); trained_k];
    for (&lid, &c) in active_ids.iter().zip(assignments.iter()) {
        raw_buckets[c].push(lid);
    }

    // Drop any empty buckets and compute exact L2-normalized mean centroids in original d-dim space
    let non_empty: Vec<Vec<u32>> = raw_buckets.into_iter().filter(|b| !b.is_empty()).collect();
    let final_k = non_empty.len();
    let mut final_centroids = vec![0.0f32; final_k * dim];

    final_centroids
        .par_chunks_mut(dim)
        .enumerate()
        .for_each(|(c, dst)| {
            for &lid in &non_empty[c] {
                let start = (lid as usize) * row_bytes;
                accumulate_f16_into_f32(dst, &keys_mmap[start..start + row_bytes]);
            }
            l2_normalize_in_place(dst);
        });

    (final_centroids, non_empty)
}

/// Parallel Spherical K-Means++ over a contiguous `n * dim` `f32` matrix.
fn spherical_kmeans_f32_rows(
    data: &[f32],
    n: usize,
    dim: usize,
    k: usize,
    max_iters: usize,
    seed: u64,
) -> (Vec<f32>, Vec<Vec<u32>>) {
    let k = k.clamp(1, n);
    let mut rng = SplitMix64(seed);

    // K-Means++ initialization using cosine distance (1 - cos_sim)
    let mut centroids = vec![0.0f32; k * dim];
    let first = rng.gen_range(n);
    centroids[0..dim].copy_from_slice(&data[first * dim..(first + 1) * dim]);
    l2_normalize_in_place(&mut centroids[0..dim]);

    let mut min_dist = vec![f32::INFINITY; n];
    for c_idx in 1..k {
        let prev_c = &centroids[(c_idx - 1) * dim..c_idx * dim];
        min_dist.par_iter_mut().enumerate().for_each(|(i, d)| {
            let sim = dot_f32(&data[i * dim..(i + 1) * dim], prev_c);
            let dist = (1.0 - sim).max(0.0);
            if dist < *d {
                *d = dist;
            }
        });

        let total_weight: f64 = min_dist.iter().map(|&d| (d as f64) * (d as f64)).sum();
        let chosen = if total_weight <= 1e-12 {
            rng.gen_range(n)
        } else {
            let mut target = rng.next_f64() * total_weight;
            let mut idx = n - 1;
            for (i, &d) in min_dist.iter().enumerate() {
                let w = (d as f64) * (d as f64);
                if target <= w {
                    idx = i;
                    break;
                }
                target -= w;
            }
            idx
        };
        centroids[c_idx * dim..(c_idx + 1) * dim]
            .copy_from_slice(&data[chosen * dim..(chosen + 1) * dim]);
        l2_normalize_in_place(&mut centroids[c_idx * dim..(c_idx + 1) * dim]);
    }

    // Parallel Lloyd iterations
    let mut labels = vec![0usize; n];
    for _iter in 0..max_iters.max(1) {
        let new_labels: Vec<usize> = (0..n)
            .into_par_iter()
            .map(|i| {
                let row = &data[i * dim..(i + 1) * dim];
                let mut best_c = 0usize;
                let mut best_sim = f32::NEG_INFINITY;
                for c in 0..k {
                    let sim = dot_f32(row, &centroids[c * dim..(c + 1) * dim]);
                    if sim > best_sim {
                        best_sim = sim;
                        best_c = c;
                    }
                }
                best_c
            })
            .collect();

        let changed: usize = labels
            .iter()
            .zip(new_labels.iter())
            .filter(|(a, b)| a != b)
            .count();
        labels = new_labels;

        // Recompute centroids
        let mut sums = vec![0.0f32; k * dim];
        let mut counts = vec![0usize; k];
        for (i, &c) in labels.iter().enumerate() {
            counts[c] += 1;
            let dst = &mut sums[c * dim..(c + 1) * dim];
            let src = &data[i * dim..(i + 1) * dim];
            for (d, &s) in dst.iter_mut().zip(src.iter()) {
                *d += s;
            }
        }
        for c in 0..k {
            if counts[c] > 0 {
                let dst = &mut sums[c * dim..(c + 1) * dim];
                if l2_normalize_in_place(dst) {
                    centroids[c * dim..(c + 1) * dim].copy_from_slice(dst);
                }
            }
        }

        if changed * 200 <= n {
            // Converged (< 0.5% points reassigned)
            break;
        }
    }

    let mut raw_buckets: Vec<Vec<u32>> = vec![Vec::new(); k];
    for (i, &c) in labels.iter().enumerate() {
        raw_buckets[c].push(i as u32);
    }

    let mut final_buckets = Vec::with_capacity(k);
    let mut final_centroids = Vec::with_capacity(k * dim);
    for (c, b) in raw_buckets.into_iter().enumerate() {
        if !b.is_empty() {
            final_centroids.extend_from_slice(&centroids[c * dim..(c + 1) * dim]);
            final_buckets.push(b);
        }
    }

    (final_centroids, final_buckets)
}

/// Atomically persists the 3-level hierarchy & branchless side-arrays to `hierarchy_index.bin`.
fn save_hierarchy_bin(path: &Path, dim: usize, st: &StoreIndexState) -> Result<(), AtlasKvError> {
    let tmp = path.with_extension("bin.tmp");
    let mut buf = Vec::with_capacity(
        64 + (st.root_centroids.len() + st.inter_centroids.len()) * 4
            + (st.root_c2id.offsets.len()
                + st.root_c2id.children.len()
                + st.inter_c2id.offsets.len()
                + st.inter_c2id.children.len())
                * 4
            + st.leaf_access_tier.len()
            + st.leaf_active.len(),
    );

    buf.extend_from_slice(HIERARCHY_MAGIC);
    buf.extend_from_slice(&(dim as u32).to_le_bytes());
    buf.extend_from_slice(&(st.total_rows as u64).to_le_bytes());
    buf.extend_from_slice(&(st.active_rows as u64).to_le_bytes());
    buf.extend_from_slice(&(st.incremental_since_rebuild as u64).to_le_bytes());
    buf.push(u8::from(st.hierarchy_built));

    write_f32_vec(&mut buf, &st.root_centroids);
    write_f32_vec(&mut buf, &st.inter_centroids);
    write_u32_vec(&mut buf, &st.root_c2id.offsets);
    write_u32_vec(&mut buf, &st.root_c2id.children);
    write_u32_vec(&mut buf, &st.inter_c2id.offsets);
    write_u32_vec(&mut buf, &st.inter_c2id.children);
    write_u8_vec(&mut buf, &st.leaf_access_tier);
    write_u8_vec(&mut buf, &st.leaf_active);

    fs::write(&tmp, &buf).map_err(|e| AtlasKvError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    fs::rename(&tmp, path).map_err(|e| AtlasKvError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(())
}

fn load_hierarchy_bin(path: &Path, expected_dim: usize) -> Result<StoreIndexState, AtlasKvError> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|mut f| f.read_to_end(&mut bytes))
        .map_err(|e| AtlasKvError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    let mut pos = 0usize;

    let magic = read_slice(&bytes, &mut pos, 8)?;
    if magic != HIERARCHY_MAGIC {
        return Err(AtlasKvError::CorruptedHierarchy(
            "invalid hierarchy magic header".into(),
        ));
    }
    let dim = read_u32(&bytes, &mut pos)? as usize;
    if dim != expected_dim {
        return Err(AtlasKvError::DimensionMismatch {
            expected: expected_dim,
            actual: dim,
        });
    }
    let total_rows = read_u64(&bytes, &mut pos)? as usize;
    let active_rows = read_u64(&bytes, &mut pos)? as usize;
    let incremental_since_rebuild = read_u64(&bytes, &mut pos)? as usize;
    let hierarchy_built = read_slice(&bytes, &mut pos, 1)?[0] != 0;

    let root_centroids = read_f32_vec(&bytes, &mut pos)?;
    let inter_centroids = read_f32_vec(&bytes, &mut pos)?;
    let root_offsets = read_u32_vec(&bytes, &mut pos)?;
    let root_children = read_u32_vec(&bytes, &mut pos)?;
    let inter_offsets = read_u32_vec(&bytes, &mut pos)?;
    let inter_children = read_u32_vec(&bytes, &mut pos)?;
    let leaf_access_tier = read_u8_vec(&bytes, &mut pos)?;
    let leaf_active = read_u8_vec(&bytes, &mut pos)?;

    if leaf_access_tier.len() != total_rows || leaf_active.len() != total_rows {
        return Err(AtlasKvError::CorruptedHierarchy(
            "side-array length mismatch".into(),
        ));
    }

    Ok(StoreIndexState {
        total_rows,
        active_rows,
        incremental_since_rebuild,
        hierarchy_built,
        root_centroids,
        inter_centroids,
        root_c2id: CsrAdjacency {
            offsets: root_offsets,
            children: root_children,
        },
        inter_c2id: CsrAdjacency {
            offsets: inter_offsets,
            children: inter_children,
        },
        leaf_access_tier,
        leaf_active,
        keys_mmap: None,
        vals_mmap: None,
    })
}

fn write_f32_vec(buf: &mut Vec<u8>, v: &[f32]) {
    buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
    for &x in v {
        buf.extend_from_slice(&x.to_le_bytes());
    }
}

fn write_u32_vec(buf: &mut Vec<u8>, v: &[u32]) {
    buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
    for &x in v {
        buf.extend_from_slice(&x.to_le_bytes());
    }
}

fn write_u8_vec(buf: &mut Vec<u8>, v: &[u8]) {
    buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
    buf.extend_from_slice(v);
}

fn read_slice<'a>(bytes: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], AtlasKvError> {
    let end = pos
        .checked_add(len)
        .ok_or_else(|| AtlasKvError::CorruptedHierarchy("cursor overflow".into()))?;
    if end > bytes.len() {
        return Err(AtlasKvError::CorruptedHierarchy("unexpected EOF".into()));
    }
    let slice = &bytes[*pos..end];
    *pos = end;
    Ok(slice)
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, AtlasKvError> {
    let s = read_slice(bytes, pos, 4)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64(bytes: &[u8], pos: &mut usize) -> Result<u64, AtlasKvError> {
    let s = read_slice(bytes, pos, 8)?;
    Ok(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

fn read_f32_vec(bytes: &[u8], pos: &mut usize) -> Result<Vec<f32>, AtlasKvError> {
    let count = read_u64(bytes, pos)? as usize;
    let byte_len = count
        .checked_mul(4)
        .ok_or_else(|| AtlasKvError::CorruptedHierarchy("f32 vec overflow".into()))?;
    let s = read_slice(bytes, pos, byte_len)?;
    let mut out = Vec::with_capacity(count);
    let (chunks, _) = s.as_chunks::<4>();
    for &chunk in chunks {
        out.push(f32::from_le_bytes(chunk));
    }
    Ok(out)
}

fn read_u32_vec(bytes: &[u8], pos: &mut usize) -> Result<Vec<u32>, AtlasKvError> {
    let count = read_u64(bytes, pos)? as usize;
    let byte_len = count
        .checked_mul(4)
        .ok_or_else(|| AtlasKvError::CorruptedHierarchy("u32 vec overflow".into()))?;
    let s = read_slice(bytes, pos, byte_len)?;
    let mut out = Vec::with_capacity(count);
    let (chunks, _) = s.as_chunks::<4>();
    for &chunk in chunks {
        out.push(u32::from_le_bytes(chunk));
    }
    Ok(out)
}

fn read_u8_vec(bytes: &[u8], pos: &mut usize) -> Result<Vec<u8>, AtlasKvError> {
    let count = read_u64(bytes, pos)? as usize;
    let s = read_slice(bytes, pos, count)?;
    Ok(s.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::l2_normalize_in_place;
    use tempfile::TempDir;

    fn unit_vec(dim: usize, seed: usize) -> Vec<f32> {
        let mut v = vec![0.05f32; dim];
        v[seed % dim] = 1.0;
        l2_normalize_in_place(&mut v);
        v
    }

    #[test]
    fn t5_atlaskv_open_backfills_legacy_unix_root_and_unc_file_path_norm() {
        let tmp = TempDir::new().unwrap();
        let cfg = AtlasKvTreeConfig {
            embedding_dim: 16,
            min_triples_for_hierarchy: 4,
            ..Default::default()
        };
        let q = unit_vec(16, 5);

        let unix_path = "/home/alice/Nextcloud/SecretReport.txt";
        let win_root_path = r"C:\";
        let unc_path = r"\\fileserver\ConfidentialShare\Plan.txt";
        let verb_path = r"\\?\C:\Users\Alice\OneDrive\Legacy.txt";

        {
            let store = AtlasKvStore::open(tmp.path(), cfg.clone()).unwrap();
            let records = vec![
                KgTripleRecord::new(
                    "UnixEnt",
                    "clearance",
                    "unix_secret",
                    "d_unix",
                    "c_unix",
                    unix_path,
                    1,
                    5,
                    "d_unix",
                    0,
                    "local",
                )
                .unwrap(),
                KgTripleRecord::new(
                    "RootEnt",
                    "clearance",
                    "root_secret",
                    "d_root",
                    "c_root",
                    win_root_path,
                    1,
                    5,
                    "d_root",
                    0,
                    "local",
                )
                .unwrap(),
                KgTripleRecord::new(
                    "UncEnt",
                    "clearance",
                    "unc_secret",
                    "d_unc",
                    "c_unc",
                    unc_path,
                    1,
                    5,
                    "d_unc",
                    0,
                    "local",
                )
                .unwrap(),
                KgTripleRecord::new(
                    "VerbEnt",
                    "clearance",
                    "verb_secret",
                    "d_verb",
                    "c_verb",
                    verb_path,
                    1,
                    5,
                    "d_verb",
                    0,
                    "local",
                )
                .unwrap(),
            ];
            store
                .insert_triples(&records, &vec![q.clone(); 4], &vec![q.clone(); 4])
                .unwrap();
            store.rebuild_hierarchy().unwrap();

            // Seed legacy pre-Iteration-3 file_path_norm values directly in SQLite
            let db = store.db.lock();
            db.execute(
                "UPDATE triples SET file_path_norm = ?1 WHERE chunk_id = 'c_unix'",
                params!["/home/alice/nextcloud/secretreport.txt"],
            )
            .unwrap();
            db.execute(
                "UPDATE triples SET file_path_norm = ?1 WHERE chunk_id = 'c_root'",
                params!["c:"],
            )
            .unwrap();
            db.execute(
                "UPDATE triples SET file_path_norm = ?1 WHERE chunk_id = 'c_unc'",
                params!["//fileserver/confidentialshare/plan.txt"],
            )
            .unwrap();
            db.execute(
                "UPDATE triples SET file_path_norm = ?1 WHERE chunk_id = 'c_verb'",
                params!["//?/c:/users/alice/onedrive/legacy.txt"],
            )
            .unwrap();
        }

        // Reopen must backfill every legacy row so tier updates & deletes match
        let reopened = AtlasKvStore::open(tmp.path(), cfg).unwrap();

        assert_eq!(
            reopened
                .update_chunk_access_tier_for_file("c_unix", unix_path, 3)
                .unwrap(),
            1
        );
        assert_eq!(
            reopened
                .update_chunk_access_tier_for_file("c_root", win_root_path, 3)
                .unwrap(),
            1
        );
        assert_eq!(
            reopened
                .update_chunk_access_tier_for_file("c_unc", unc_path, 3)
                .unwrap(),
            1
        );
        assert_eq!(
            reopened
                .update_chunk_access_tier_for_file(
                    "c_verb",
                    r"C:\Users\Alice\OneDrive\Legacy.txt",
                    3
                )
                .unwrap(),
            1
        );

        let (t0_hits, _) = reopened.hikvp_search(&q, 0, 10, None).unwrap();
        assert_eq!(
            t0_hits.len(),
            0,
            "No legacy row may leak at Tier 0 after reopen + tier upgrade: {t0_hits:?}"
        );

        assert_eq!(reopened.delete_by_file_path(unix_path).unwrap(), 1);
        assert_eq!(reopened.delete_by_file_path(win_root_path).unwrap(), 1);
        assert_eq!(reopened.delete_by_file_path(unc_path).unwrap(), 1);
        assert_eq!(
            reopened
                .delete_by_file_path(r"C:\Users\Alice\OneDrive\Legacy.txt")
                .unwrap(),
            1
        );
        assert_eq!(reopened.stats().active_triples, 0);
    }
}
