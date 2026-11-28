//! Sublinear 3-Level Hierarchical Key-Value Pruning (`HiKVP`) and homonym-safe
//! synthesis context formatting for QuorumRAG.
//!
//! Mirrors `AtlaskvLlamaAttention`'s `Root -> Inter1 -> Leaf` pruning pipeline natively
//! in Rust with zero heap allocation per leaf dot product, fail-closed `access_tier`
//! pre-filtering, and normalized cross-OS shared-folder enforcement.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use rayon::prelude::*;

use crate::error::AtlasKvError;
use crate::hierarchy::AtlasKvStore;
use crate::types::{
    dot_f16_le, dot_f32, l2_normalize_in_place, normalize_path_key, validate_access_tier,
    HiKvpPruningTrace, ScoredKgTriple,
};

impl AtlasKvStore {
    /// Executes sublinear 3-level HiKVP search (`Root -> Inter1 -> Leaf`) over the embedded
    /// Knowledge Graph store with fail-closed `access_tier <= max_tier` and optional
    /// `allowed_folders` containment.
    pub fn hikvp_search(
        &self,
        query_vec: &[f32],
        max_tier: u8,
        top_k: usize,
        allowed_folders: Option<&[String]>,
    ) -> Result<(Vec<ScoredKgTriple>, HiKvpPruningTrace), AtlasKvError> {
        let start = Instant::now();
        validate_access_tier(max_tier)?;
        let dim = self.config.embedding_dim;
        if query_vec.len() != dim {
            return Err(AtlasKvError::DimensionMismatch {
                expected: dim,
                actual: query_vec.len(),
            });
        }

        let mut trace = HiKvpPruningTrace::default();
        if top_k == 0 {
            trace.elapsed_us = start.elapsed().as_micros() as u64;
            return Ok((Vec::new(), trace));
        }

        let mut q = query_vec.to_vec();
        if !l2_normalize_in_place(&mut q) {
            trace.elapsed_us = start.elapsed().as_micros() as u64;
            return Ok((Vec::new(), trace));
        }

        let normalized_folders: Option<Vec<String>> = allowed_folders.map(|folders| {
            folders
                .iter()
                .map(|f| normalize_path_key(f))
                .filter(|f| !f.is_empty())
                .collect()
        });

        let effective_limit = top_k.min(self.config.leaf_top_k_kb.max(top_k));
        // Over-fetch slightly before SQLite folder filtering if folder restriction is active
        let pre_folder_limit = if normalized_folders.is_some() {
            (effective_limit * 4).max(64)
        } else {
            effective_limit
        };

        let scored_ids: Vec<(u32, f32)> = {
            let st = self.state.read();
            trace.total_active_leaves = st.active_rows;
            trace.root_total = st.root_count(dim);
            trace.inter_total = st.inter_count(dim);

            let Some(keys_mmap) = st.keys_mmap.as_ref() else {
                trace.elapsed_us = start.elapsed().as_micros() as u64;
                return Ok((Vec::new(), trace));
            };
            let mmap_slice: &[u8] = keys_mmap;
            let row_bytes = dim * 2;

            let use_hierarchy = st.hierarchy_built
                && st.active_rows >= self.config.min_triples_for_hierarchy
                && trace.root_total > 0
                && trace.inter_total > 0;
            trace.used_hierarchy = use_hierarchy;

            let candidate_leaves: Vec<u32> = if use_hierarchy {
                // Stage 1: Score Root centroids -> retain top `root_top_k_kb`
                let root_k = self.config.root_top_k_kb.min(trace.root_total).max(1);
                let mut root_scores: Vec<(usize, f32)> = (0..trace.root_total)
                    .map(|r| (r, dot_f32(&q, &st.root_centroids[r * dim..(r + 1) * dim])))
                    .collect();
                select_top_k_desc(&mut root_scores, root_k);
                trace.root_selected = root_scores.len();

                // Gather covered Inter1 indices via `root_c2id`
                let mut covered_inters: Vec<u32> = Vec::new();
                for &(root_idx, _) in &root_scores {
                    covered_inters.extend_from_slice(st.root_c2id.children_of(root_idx));
                }
                trace.inter_scanned = covered_inters.len();

                // Stage 2: Score covered Inter1 centroids -> retain top `inter_top_k_kb`
                let inter_k = self.config.inter_top_k_kb.min(covered_inters.len()).max(1);
                let mut inter_scores: Vec<(usize, f32)> = if covered_inters.len() > 64 {
                    covered_inters
                        .par_iter()
                        .map(|&inter_u32| {
                            let i = inter_u32 as usize;
                            let sim = dot_f32(&q, &st.inter_centroids[i * dim..(i + 1) * dim]);
                            (i, sim)
                        })
                        .collect()
                } else {
                    covered_inters
                        .iter()
                        .map(|&inter_u32| {
                            let i = inter_u32 as usize;
                            let sim = dot_f32(&q, &st.inter_centroids[i * dim..(i + 1) * dim]);
                            (i, sim)
                        })
                        .collect()
                };
                select_top_k_desc(&mut inter_scores, inter_k);
                trace.inter_selected = inter_scores.len();

                // Gather covered Leaf IDs via `inter_c2id`
                let mut leaves = Vec::new();
                for &(inter_idx, _) in &inter_scores {
                    leaves.extend_from_slice(st.inter_c2id.children_of(inter_idx));
                }
                leaves
            } else {
                // Fast exact scan for small graphs below `min_triples_for_hierarchy`
                (0..st.total_rows)
                    .filter_map(|id| {
                        if st.leaf_active[id] == 1 {
                            Some(id as u32)
                        } else {
                            None
                        }
                    })
                    .collect()
            };

            trace.leaf_candidates_before_filter = candidate_leaves.len();

            // Stage 3: Fail-closed branchless active & access_tier pre-filter BEFORE scoring
            let mut authorized_leaves: Vec<u32> = Vec::with_capacity(candidate_leaves.len());
            let mut tier_blocked = 0usize;
            for &lid_u32 in &candidate_leaves {
                let lid = lid_u32 as usize;
                if lid >= st.leaf_active.len() || st.leaf_active[lid] == 0 {
                    continue;
                }
                if st.leaf_access_tier[lid] > max_tier {
                    tier_blocked += 1;
                    continue;
                }
                authorized_leaves.push(lid_u32);
            }
            trace.access_tier_filtered = tier_blocked;
            trace.leaf_scanned = authorized_leaves.len();

            // Zero-allocation on-the-fly f16 -> f32 dot-product scoring over pruned leaf slice
            let mut leaf_scores: Vec<(u32, f32)> = if authorized_leaves.len() > 256 {
                authorized_leaves
                    .par_iter()
                    .filter_map(|&lid_u32| {
                        let start_b = (lid_u32 as usize).checked_mul(row_bytes)?;
                        let end_b = start_b.checked_add(row_bytes)?;
                        if end_b <= mmap_slice.len() {
                            let sim = dot_f16_le(&q, &mmap_slice[start_b..end_b]);
                            Some((lid_u32, sim))
                        } else {
                            None
                        }
                    })
                    .collect()
            } else {
                authorized_leaves
                    .iter()
                    .filter_map(|&lid_u32| {
                        let start_b = (lid_u32 as usize).checked_mul(row_bytes)?;
                        let end_b = start_b.checked_add(row_bytes)?;
                        if end_b <= mmap_slice.len() {
                            let sim = dot_f16_le(&q, &mmap_slice[start_b..end_b]);
                            Some((lid_u32, sim))
                        } else {
                            None
                        }
                    })
                    .collect()
            };

            select_top_k_desc_u32(&mut leaf_scores, pre_folder_limit);
            leaf_scores
        };

        // Fetch SQLite metadata ONLY for the shortlisted top leaf IDs
        let shortlist_ids: Vec<u32> = scored_ids.iter().map(|&(id, _)| id).collect();
        let meta_map = self.fetch_records_by_ids(&shortlist_ids)?;

        let mut results = Vec::with_capacity(effective_limit.min(scored_ids.len()));
        for (lid, score) in scored_ids {
            if results.len() >= effective_limit {
                break;
            }
            let Some(rec) = meta_map.get(&(lid as u64)) else {
                continue;
            };
            // Double-check access_tier defense-in-depth
            if rec.access_tier > max_tier {
                trace.access_tier_filtered += 1;
                continue;
            }
            // Enforce optional allowed-folder containment (e.g., remote P2P shared-folders policy)
            if let Some(ref allowed) = normalized_folders {
                if !is_path_inside_allowed_folders(&rec.file_path, allowed) {
                    trace.folder_filtered += 1;
                    continue;
                }
            }
            results.push(ScoredKgTriple {
                triple: rec.clone(),
                score,
            });
        }

        trace.leaf_selected = results.len();
        trace.elapsed_us = start.elapsed().as_micros() as u64;
        Ok((results, trace))
    }
}

/// Formats HiKVP-pruned triples into a compact, homonym-cluster-grouped evidence block
/// for Ollama synthesis models (`gemma4:26b`, `qwen2.5`, `Bespoke-Nimble-9B`), preventing
/// conflation of distinct individuals/works while preserving exact file/line provenance.
pub fn format_grounded_kg_context(triples: &[ScoredKgTriple]) -> String {
    if triples.is_empty() {
        return String::new();
    }

    let mut by_cluster: BTreeMap<String, Vec<&ScoredKgTriple>> = BTreeMap::new();
    for item in triples {
        let cluster = if item.triple.work_cluster_id.trim().is_empty() {
            "general".to_string()
        } else {
            item.triple.work_cluster_id.clone()
        };
        by_cluster.entry(cluster).or_default().push(item);
    }

    let mut out = String::from(
        "### [AtlasKV Grounded Knowledge Graph Triples]\n\
         Each cluster below represents a distinct source document/context. Do NOT merge identities across clusters.\n",
    );
    let mut ref_idx = 1usize;
    for (cluster, items) in by_cluster {
        out.push_str(&format!("\n#### Context Cluster: `{}`\n", cluster));
        for item in items {
            let normalized_fp = item.triple.file_path.replace('\\', "/");
            let basename = Path::new(&normalized_fp)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(&item.triple.file_path);
            let origin = if item.triple.source_peer.eq_ignore_ascii_case("local")
                || item.triple.source_peer.is_empty()
            {
                "local".to_string()
            } else {
                format!("Mesh Peer {}", item.triple.source_peer)
            };
            out.push_str(&format!(
                "- [KG-Ref {}] **{}** = {} _(source: `{}`, lines {}-{}, origin: {}, score: {:.3})_\n",
                ref_idx,
                item.triple.key_string,
                item.triple.value,
                basename,
                item.triple.line_start,
                item.triple.line_end,
                origin,
                item.score
            ));
            ref_idx += 1;
        }
    }
    out
}

pub(crate) fn is_path_inside_allowed_folders(
    file_path: &str,
    allowed_norm_folders: &[String],
) -> bool {
    if allowed_norm_folders.is_empty() {
        return false;
    }
    let norm_file = normalize_path_key(file_path);
    for folder in allowed_norm_folders {
        if norm_file == *folder {
            return true;
        }
        if folder.ends_with('/') || folder.ends_with('\\') {
            if norm_file.starts_with(folder.as_str()) {
                return true;
            }
        } else if let Some(rest) = norm_file.strip_prefix(folder.as_str()) {
            if rest.starts_with('/') || rest.starts_with('\\') {
                return true;
            }
        }
    }
    false
}

fn select_top_k_desc(items: &mut Vec<(usize, f32)>, k: usize) {
    if k == 0 {
        items.clear();
        return;
    }
    let cmp = |a: &(usize, f32), b: &(usize, f32)| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    };
    if items.len() > k {
        items.select_nth_unstable_by(k - 1, cmp);
        items.truncate(k);
    }
    items.sort_unstable_by(cmp);
}

fn select_top_k_desc_u32(items: &mut Vec<(u32, f32)>, k: usize) {
    if k == 0 {
        items.clear();
        return;
    }
    let cmp = |a: &(u32, f32), b: &(u32, f32)| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    };
    if items.len() > k {
        items.select_nth_unstable_by(k - 1, cmp);
        items.truncate(k);
    }
    items.sort_unstable_by(cmp);
}
