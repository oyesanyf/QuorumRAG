//! Pure-Rust native `HKUST-KnowComp/AtlasKV` format interoperability (`.npy` v1.0/v2.0,
//! `*_qkv.json`, `*_c2id_mapping.json`, `*_id2c_mapping.json`) plus strict fail-closed
//! path-traversal containment.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::AtlasKvError;
use crate::hierarchy::AtlasKvStore;
use crate::types::{validate_access_tier, KgTripleRecord};

const NPY_MAGIC: &[u8; 6] = b"\x93NUMPY";

/// Exact `HKUST-KnowComp/AtlasKV` `DataPoint` JSON entry (`*_qkv.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtlasKvQkvItem {
    pub name: String,
    pub description_type: String,
    pub description: String,
    #[serde(rename = "Q", default)]
    pub question: String,
    #[serde(rename = "A", default)]
    pub answer: String,
    #[serde(default)]
    pub key_string: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work_cluster_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_start: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_end: Option<u32>,
}

/// Manifest describing files written by `export_atlaskv_dataset`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtlasKvExportManifest {
    pub dataset_prefix: String,
    pub exported_triples: usize,
    pub embedding_dim: usize,
    pub root_clusters: usize,
    pub inter_clusters: usize,
    pub qkv_json_path: PathBuf,
    pub key_npy_path: PathBuf,
    pub val_npy_path: PathBuf,
    pub root_npy_path: Option<PathBuf>,
    pub inter1_npy_path: Option<PathBuf>,
}

/// Fail-closed path containment check for relative user-supplied import/export filenames.
///
/// Blocks drive letters (`:`), leading `/` or `\`, UNC paths (`\\`), parent traversal (`..`),
/// percent-encoded traversal (`%2e`, `%2f`, `%5c`, `%00`), null bytes, and NTFS Alternate
/// Data Streams (`:`) before joining onto `base_dir`.
pub fn validate_safe_relative_path(
    base_dir: &Path,
    user_rel_path: &str,
) -> Result<PathBuf, AtlasKvError> {
    let trimmed = user_rel_path.trim();
    if trimmed.is_empty() {
        return Err(AtlasKvError::PathTraversal("empty relative path".into()));
    }
    if trimmed.contains('\0') {
        return Err(AtlasKvError::PathTraversal("null byte rejected".into()));
    }
    let lower = trimmed.to_ascii_lowercase();
    for forbidden in ["%2e", "%2f", "%5c", "%00", ".."] {
        if lower.contains(forbidden) {
            return Err(AtlasKvError::PathTraversal(format!(
                "forbidden sequence '{}' in path '{}'",
                forbidden, trimmed
            )));
        }
    }
    if trimmed.starts_with('/')
        || trimmed.starts_with('\\')
        || trimmed.starts_with("\\\\")
        || trimmed.contains(':')
    {
        return Err(AtlasKvError::PathTraversal(format!(
            "absolute, UNC, drive-letter, or ADS path rejected: '{}'",
            trimmed
        )));
    }

    let rel = Path::new(trimmed);
    let mut clean = PathBuf::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(seg) => {
                let s = seg.to_string_lossy();
                if s.contains(':') || s == ".." {
                    return Err(AtlasKvError::PathTraversal(format!(
                        "unsafe path component '{}'",
                        s
                    )));
                }
                clean.push(seg);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(AtlasKvError::PathTraversal(format!(
                    "disallowed path component in '{}'",
                    trimmed
                )));
            }
        }
    }

    if clean.as_os_str().is_empty() {
        return Err(AtlasKvError::PathTraversal(
            "path resolved to empty relative path".into(),
        ));
    }

    Ok(base_dir.join(clean))
}

/// Writes a C-contiguous 2D `f32` matrix in NumPy `.npy` v1.0 format (`descr = '<f4'`).
pub fn write_npy_f32(
    path: &Path,
    data: &[f32],
    rows: usize,
    cols: usize,
) -> Result<(), AtlasKvError> {
    let expected = rows
        .checked_mul(cols)
        .ok_or_else(|| AtlasKvError::NpyFormat("shape overflow".into()))?;
    if data.len() != expected {
        return Err(AtlasKvError::NpyFormat(format!(
            "data len {} != {}x{}",
            data.len(),
            rows,
            cols
        )));
    }

    let header = build_npy_v1_header("<f4", rows, cols)?;
    let mut file = File::create(path).map_err(|e| AtlasKvError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    file.write_all(&header).map_err(|e| AtlasKvError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    let mut raw = Vec::with_capacity(data.len() * 4);
    for &x in data {
        raw.extend_from_slice(&x.to_le_bytes());
    }
    file.write_all(&raw).map_err(|e| AtlasKvError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    file.flush().map_err(|e| AtlasKvError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(())
}

/// Reads a C-contiguous 2D NumPy `.npy` v1.0/v2.0 matrix (`'<f4'` or `'<f2'`) into `f32` rows.
pub fn read_npy_2d_as_f32(path: &Path) -> Result<(Vec<f32>, usize, usize), AtlasKvError> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|mut f| f.read_to_end(&mut bytes))
        .map_err(|e| AtlasKvError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

    if bytes.len() < 10 || &bytes[0..6] != NPY_MAGIC {
        return Err(AtlasKvError::NpyFormat("missing \\x93NUMPY magic".into()));
    }
    let major = bytes[6];
    let minor = bytes[7];
    let (header_len, header_start) = match (major, minor) {
        (1, 0) => {
            let len = u16::from_le_bytes([bytes[8], bytes[9]]) as usize;
            (len, 10usize)
        }
        (2, 0) => {
            if bytes.len() < 12 {
                return Err(AtlasKvError::NpyFormat("truncated v2 header".into()));
            }
            let len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
            (len, 12usize)
        }
        _ => {
            return Err(AtlasKvError::NpyFormat(format!(
                "unsupported .npy version {}.{}",
                major, minor
            )));
        }
    };

    let data_start = header_start
        .checked_add(header_len)
        .ok_or_else(|| AtlasKvError::NpyFormat("header len overflow".into()))?;
    if data_start > bytes.len() {
        return Err(AtlasKvError::NpyFormat("truncated .npy header".into()));
    }

    let header_str = std::str::from_utf8(&bytes[header_start..data_start])
        .map_err(|_| AtlasKvError::NpyFormat("non-UTF8 .npy header".into()))?;

    let is_f4 = header_str.contains("'<f4'") || header_str.contains("\"<f4\"");
    let is_f2 = header_str.contains("'<f2'") || header_str.contains("\"<f2\"");
    if !is_f4 && !is_f2 {
        return Err(AtlasKvError::NpyFormat(format!(
            "unsupported dtype in header: {}",
            header_str.trim()
        )));
    }
    if header_str.contains("True") {
        return Err(AtlasKvError::NpyFormat(
            "fortran_order=True is not supported".into(),
        ));
    }

    let (rows, cols) = parse_npy_2d_shape(header_str)?;
    let count = rows
        .checked_mul(cols)
        .ok_or_else(|| AtlasKvError::NpyFormat("shape element count overflow".into()))?;
    let elem_bytes = if is_f4 { 4usize } else { 2usize };
    let expected_bytes = count
        .checked_mul(elem_bytes)
        .ok_or_else(|| AtlasKvError::NpyFormat("payload byte size overflow".into()))?;

    let payload = &bytes[data_start..];
    if payload.len() != expected_bytes {
        return Err(AtlasKvError::NpyFormat(format!(
            "payload length {} != expected {}",
            payload.len(),
            expected_bytes
        )));
    }

    let mut out = Vec::with_capacity(count);
    if is_f4 {
        let (chunks, _) = payload.as_chunks::<4>();
        for &chunk in chunks {
            out.push(f32::from_le_bytes(chunk));
        }
    } else {
        let (chunks, _) = payload.as_chunks::<2>();
        for &chunk in chunks {
            out.push(half::f16::from_le_bytes(chunk).to_f32());
        }
    }

    Ok((out, rows, cols))
}

/// Exports active authorized records (`access_tier <= max_tier`) and 3-level hierarchy into exact
/// `HKUST-KnowComp/AtlasKV` dataset layout (`*_qkv.json`, `*_embd_key.npy`, `*_embd_value.npy`,
/// `*_embd_key_root.npy`, `*_embd_key_inter1.npy`, and `c2id`/`id2c` JSON mappings).
pub fn export_atlaskv_dataset(
    store: &AtlasKvStore,
    out_dir: &Path,
    dataset_prefix: &str,
    max_tier: u8,
) -> Result<AtlasKvExportManifest, AtlasKvError> {
    validate_access_tier(max_tier)?;
    // Validate prefix as a safe single-segment path component
    let _ = validate_safe_relative_path(out_dir, dataset_prefix)?;
    fs::create_dir_all(out_dir).map_err(|e| AtlasKvError::Io {
        path: out_dir.to_path_buf(),
        source: e,
    })?;

    let records = store.fetch_all_active_records(max_tier)?;
    let dim = store.config().embedding_dim;
    let st = store.state.read();

    let mut qkv_items = Vec::with_capacity(records.len());
    let mut key_mat = Vec::with_capacity(records.len() * dim);
    let mut val_mat = Vec::with_capacity(records.len() * dim);
    let mut old_to_new: BTreeMap<u32, usize> = BTreeMap::new();

    for (new_idx, rec) in records.iter().enumerate() {
        let tid = rec.triple_id as usize;
        let k_row = st.key_f16_row(tid, dim).ok_or_else(|| {
            AtlasKvError::CorruptedHierarchy(format!("missing key vector for triple_id {}", tid))
        })?;
        let v_row = st.val_f16_row(tid, dim).ok_or_else(|| {
            AtlasKvError::CorruptedHierarchy(format!("missing val vector for triple_id {}", tid))
        })?;

        let (k_pairs, _) = k_row.as_chunks::<2>();
        for &pair in k_pairs {
            key_mat.push(half::f16::from_le_bytes(pair).to_f32());
        }
        let (v_pairs, _) = v_row.as_chunks::<2>();
        for &pair in v_pairs {
            val_mat.push(half::f16::from_le_bytes(pair).to_f32());
        }

        old_to_new.insert(rec.triple_id as u32, new_idx);
        qkv_items.push(AtlasKvQkvItem {
            name: rec.entity.clone(),
            description_type: rec.relation.clone(),
            description: rec.value.clone(),
            question: format!("What is {}?", rec.key_string),
            answer: format!("{} is {}", rec.key_string, rec.value),
            key_string: rec.key_string.clone(),
            file_path: Some(rec.file_path.clone()),
            work_cluster_id: Some(rec.work_cluster_id.clone()),
            line_start: Some(rec.line_start),
            line_end: Some(rec.line_end),
        });
    }

    let qkv_json_path = out_dir.join(format!("{}_qkv.json", dataset_prefix));
    let key_npy_path = out_dir.join(format!("{}_embd_key.npy", dataset_prefix));
    let val_npy_path = out_dir.join(format!("{}_embd_value.npy", dataset_prefix));

    let qkv_str = serde_json::to_string_pretty(&qkv_items)?;
    fs::write(&qkv_json_path, qkv_str).map_err(|e| AtlasKvError::Io {
        path: qkv_json_path.clone(),
        source: e,
    })?;
    write_npy_f32(&key_npy_path, &key_mat, records.len(), dim)?;
    write_npy_f32(&val_npy_path, &val_mat, records.len(), dim)?;

    let mut root_npy_path = None;
    let mut inter1_npy_path = None;
    let mut exported_roots = 0usize;
    let mut exported_inters = 0usize;

    if st.hierarchy_built && !records.is_empty() && st.inter_count(dim) > 0 && st.root_count(dim) > 0
    {
        // Filter inter1 clusters to only exported authorized leaf indices
        let mut inter_c2id: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut inter_id2c: BTreeMap<String, usize> = BTreeMap::new();
        let mut inter_old_to_new: BTreeMap<u32, usize> = BTreeMap::new();
        let mut inter_mat: Vec<f32> = Vec::new();

        for old_i in 0..st.inter_c2id.cluster_count() {
            let mut remapped_leaves = Vec::new();
            for &old_leaf in st.inter_c2id.children_of(old_i) {
                if let Some(&new_leaf) = old_to_new.get(&old_leaf) {
                    remapped_leaves.push(new_leaf);
                }
            }
            if !remapped_leaves.is_empty() {
                let new_i = exported_inters;
                inter_old_to_new.insert(old_i as u32, new_i);
                for &nl in &remapped_leaves {
                    inter_id2c.insert(nl.to_string(), new_i);
                }
                inter_c2id.insert(new_i.to_string(), remapped_leaves);
                inter_mat.extend_from_slice(&st.inter_centroids[old_i * dim..(old_i + 1) * dim]);
                exported_inters += 1;
            }
        }

        let mut root_c2id: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut root_id2c: BTreeMap<String, usize> = BTreeMap::new();
        let mut root_mat: Vec<f32> = Vec::new();

        for old_r in 0..st.root_c2id.cluster_count() {
            let mut remapped_inters = Vec::new();
            for &old_i in st.root_c2id.children_of(old_r) {
                if let Some(&new_i) = inter_old_to_new.get(&old_i) {
                    remapped_inters.push(new_i);
                }
            }
            if !remapped_inters.is_empty() {
                let new_r = exported_roots;
                for &ni in &remapped_inters {
                    root_id2c.insert(ni.to_string(), new_r);
                }
                root_c2id.insert(new_r.to_string(), remapped_inters);
                root_mat.extend_from_slice(&st.root_centroids[old_r * dim..(old_r + 1) * dim]);
                exported_roots += 1;
            }
        }

        if exported_inters > 0 && exported_roots > 0 {
            let i_npy = out_dir.join(format!("{}_embd_key_inter1.npy", dataset_prefix));
            let r_npy = out_dir.join(format!("{}_embd_key_root.npy", dataset_prefix));
            write_npy_f32(&i_npy, &inter_mat, exported_inters, dim)?;
            write_npy_f32(&r_npy, &root_mat, exported_roots, dim)?;

            write_json_file(
                &out_dir.join(format!(
                    "{}_embd_key_inter1_c2id_mapping.json",
                    dataset_prefix
                )),
                &inter_c2id,
            )?;
            write_json_file(
                &out_dir.join(format!(
                    "{}_embd_key_inter1_id2c_mapping.json",
                    dataset_prefix
                )),
                &inter_id2c,
            )?;
            write_json_file(
                &out_dir.join(format!("{}_embd_key_root_c2id_mapping.json", dataset_prefix)),
                &root_c2id,
            )?;
            write_json_file(
                &out_dir.join(format!("{}_embd_key_root_id2c_mapping.json", dataset_prefix)),
                &root_id2c,
            )?;

            inter1_npy_path = Some(i_npy);
            root_npy_path = Some(r_npy);
        }
    }

    Ok(AtlasKvExportManifest {
        dataset_prefix: dataset_prefix.to_string(),
        exported_triples: records.len(),
        embedding_dim: dim,
        root_clusters: exported_roots,
        inter_clusters: exported_inters,
        qkv_json_path,
        key_npy_path,
        val_npy_path,
        root_npy_path,
        inter1_npy_path,
    })
}

/// Imports an `HKUST-KnowComp/AtlasKV` dataset (`{prefix}_qkv.json`, `{prefix}_embd_key.npy`,
/// `{prefix}_embd_value.npy`) directly into `store` with validated `access_tier`.
pub fn import_atlaskv_dataset(
    store: &AtlasKvStore,
    in_dir: &Path,
    dataset_prefix: &str,
    access_tier: u8,
) -> Result<usize, AtlasKvError> {
    validate_access_tier(access_tier)?;
    let _ = validate_safe_relative_path(in_dir, dataset_prefix)?;

    let qkv_path = in_dir.join(format!("{}_qkv.json", dataset_prefix));
    let key_path = in_dir.join(format!("{}_embd_key.npy", dataset_prefix));
    let val_path = in_dir.join(format!("{}_embd_value.npy", dataset_prefix));

    let raw_json = fs::read_to_string(&qkv_path).map_err(|e| AtlasKvError::Io {
        path: qkv_path.clone(),
        source: e,
    })?;
    let items: Vec<AtlasKvQkvItem> = serde_json::from_str(&raw_json)?;

    let (keys_flat, k_rows, k_cols) = read_npy_2d_as_f32(&key_path)?;
    let (vals_flat, v_rows, v_cols) = read_npy_2d_as_f32(&val_path)?;

    let expected_dim = store.config().embedding_dim;
    if k_cols != expected_dim || v_cols != expected_dim {
        return Err(AtlasKvError::DimensionMismatch {
            expected: expected_dim,
            actual: if k_cols != expected_dim { k_cols } else { v_cols },
        });
    }
    if k_rows != items.len() || v_rows != items.len() {
        return Err(AtlasKvError::LengthMismatch {
            context: format!(
                "qkv items ({}), key rows ({}), and val rows ({}) must match",
                items.len(),
                k_rows,
                v_rows
            ),
        });
    }

    let mut records = Vec::with_capacity(items.len());
    let mut key_vecs = Vec::with_capacity(items.len());
    let mut val_vecs = Vec::with_capacity(items.len());

    for (idx, item) in items.iter().enumerate() {
        let file_path = item
            .file_path
            .clone()
            .unwrap_or_else(|| format!("atlaskv://{}_qkv.json", dataset_prefix));
        let work_cluster = item
            .work_cluster_id
            .clone()
            .unwrap_or_else(|| dataset_prefix.to_ascii_lowercase());
        let rec = KgTripleRecord::new(
            &item.name,
            &item.description_type,
            &item.description,
            format!("atlaskv:{}:{}", dataset_prefix, idx),
            format!("atlaskv:{}:chunk:{}", dataset_prefix, idx),
            file_path,
            item.line_start.unwrap_or(1),
            item.line_end.unwrap_or(1),
            work_cluster,
            access_tier,
            "local",
        )?;
        records.push(rec);
        key_vecs.push(keys_flat[idx * expected_dim..(idx + 1) * expected_dim].to_vec());
        val_vecs.push(vals_flat[idx * expected_dim..(idx + 1) * expected_dim].to_vec());
    }

    store.insert_triples(&records, &key_vecs, &val_vecs)
}

fn build_npy_v1_header(descr: &str, rows: usize, cols: usize) -> Result<Vec<u8>, AtlasKvError> {
    let mut dict = format!(
        "{{'descr': '{}', 'fortran_order': False, 'shape': ({}, {}), }}",
        descr, rows, cols
    );
    // Align total header size (10 + header_len) to 64-byte boundary ending with '\n'
    let preamble = 10usize;
    let total_unpadded = preamble + dict.len() + 1;
    let pad = (64 - (total_unpadded % 64)) % 64;
    for _ in 0..pad {
        dict.push(' ');
    }
    dict.push('\n');

    let header_len = dict.len();
    if header_len > u16::MAX as usize {
        return Err(AtlasKvError::NpyFormat("header exceeds v1.0 limit".into()));
    }

    let mut out = Vec::with_capacity(preamble + header_len);
    out.extend_from_slice(NPY_MAGIC);
    out.push(1);
    out.push(0);
    out.extend_from_slice(&(header_len as u16).to_le_bytes());
    out.extend_from_slice(dict.as_bytes());
    Ok(out)
}

fn parse_npy_2d_shape(header: &str) -> Result<(usize, usize), AtlasKvError> {
    let shape_pos = header
        .find("'shape'")
        .or_else(|| header.find("\"shape\""))
        .ok_or_else(|| AtlasKvError::NpyFormat("missing shape key".into()))?;
    let after = &header[shape_pos..];
    let open = after
        .find('(')
        .ok_or_else(|| AtlasKvError::NpyFormat("missing shape '('".into()))?;
    let close = after[open..]
        .find(')')
        .ok_or_else(|| AtlasKvError::NpyFormat("missing shape ')'".into()))?;
    let tuple_str = &after[open + 1..open + close];
    let dims: Vec<usize> = tuple_str
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<usize>()
                .map_err(|_| AtlasKvError::NpyFormat(format!("invalid dim '{}'", s)))
        })
        .collect::<Result<Vec<_>, _>>()?;

    if dims.len() != 2 {
        return Err(AtlasKvError::NpyFormat(format!(
            "expected 2D shape, got {:?}",
            dims
        )));
    }
    Ok((dims[0], dims[1]))
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<(), AtlasKvError> {
    let text = serde_json::to_string_pretty(value)?;
    fs::write(path, text).map_err(|e| AtlasKvError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}
