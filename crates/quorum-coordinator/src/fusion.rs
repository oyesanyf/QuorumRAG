use quorum_types::{CandidateChunkDto, DocumentChunk, ScoredChunk};
use std::collections::{HashMap, HashSet};

pub struct RrfCombiner;

impl RrfCombiner {
    /// Computes theoretical RRF score across 1-based ranks: sum 1 / (k + r).
    pub fn compute_rrf_score(ranks: &[usize], k: f32) -> f32 {
        ranks.iter().map(|&r| 1.0 / (k + r as f32)).sum()
    }

    /// Combines local rankings and remote peer candidate lists using Reciprocal Rank Fusion ($k=60.0$)
    /// with BLAKE3 deduplication, 1.25x multi-peer consensus boost, and deterministic tie-breaking on `(chunk_id, blake3_hash)`.
    pub fn fuse_rankings(
        local_results: Vec<ScoredChunk>,
        remote_peer_lists: Vec<Vec<CandidateChunkDto>>,
        k: f32,
        top_k: usize,
    ) -> Vec<ScoredChunk> {
        let paired = remote_peer_lists
            .into_iter()
            .enumerate()
            .map(|(i, list)| (format!("remote_peer_{}", i + 1), list))
            .collect();
        Self::fuse_rankings_with_peers(local_results, paired, k, top_k)
    }

    /// Combines local rankings and remote peer candidate lists paired with real `responder_peer_id`,
    /// preserving the actual peer identity in `ScoredChunk.source_peer`.
    pub fn fuse_rankings_with_peers(
        local_results: Vec<ScoredChunk>,
        remote_peer_lists: Vec<(String, Vec<CandidateChunkDto>)>,
        k: f32,
        top_k: usize,
    ) -> Vec<ScoredChunk> {
        // Map from cryptographic blake3_hash to (base_rrf_score, ScoredChunk, HashSet of distinct peer IDs)
        // Local is peer 0; remote peers are indexed 1..=N
        let mut rrf_map: HashMap<String, (f32, ScoredChunk, HashSet<usize>)> = HashMap::new();

        const LOCAL_PEER_ID: usize = 0;

        // 1. Local chunk rankings with intra-local deduplication
        let mut seen_local_hashes: HashSet<String> = HashSet::new();
        for (rank_0, scored) in local_results.into_iter().enumerate() {
            let hash = if scored.chunk.blake3_hash.is_empty() {
                DocumentChunk::compute_blake3_hash(&scored.chunk.text_content)
            } else {
                scored.chunk.blake3_hash.clone()
            };

            if !seen_local_hashes.insert(hash.clone()) {
                continue;
            }

            let score = 1.0 / (k + (rank_0 + 1) as f32);
            let entry = rrf_map
                .entry(hash)
                .or_insert_with(|| (0.0, scored, HashSet::new()));
            entry.0 += score;
            entry.2.insert(LOCAL_PEER_ID);
        }

        // 2. Remote peer chunk rankings with intra-peer anti-stuffing protection
        for (remote_idx, (peer_id, list)) in remote_peer_lists.into_iter().enumerate() {
            let remote_peer_numeric_id = remote_idx + 1;
            let mut seen_peer_hashes: HashSet<String> = HashSet::new();

            for (rank_0, candidate) in list.into_iter().enumerate() {
                let content_hash = DocumentChunk::compute_blake3_hash(&candidate.content);

                // Byzantine consensus hardening: a remote peer contributes at most ONCE per unique chunk content
                if !seen_peer_hashes.insert(content_hash.clone()) {
                    continue;
                }

                let score = 1.0 / (k + (rank_0 + 1) as f32);
                let entry = rrf_map.entry(content_hash.clone()).or_insert_with(|| {
                    let derived_doc_id = candidate
                        .chunk_id
                        .rsplit_once(':')
                        .map(|(d, _)| d.to_string())
                        .unwrap_or_else(|| format!("remote:{}", candidate.file_path));
                    let doc_chunk = DocumentChunk {
                        chunk_id: candidate.chunk_id.clone(),
                        document_id: derived_doc_id,
                        file_path: candidate.file_path,
                        line_start: candidate.line_start,
                        line_end: candidate.line_end,
                        blake3_hash: content_hash,
                        access_tier: candidate.access_tier,
                        vector: vec![0.0; 768],
                        text_content: candidate.content,
                        metadata_json: "{}".to_string(),
                    };
                    let scored = ScoredChunk::new(doc_chunk, candidate.score, peer_id.clone(), true);
                    (0.0, scored, HashSet::new())
                });
                entry.0 += score;
                entry.2.insert(remote_peer_numeric_id);
            }
        }

        // 3. Finalize scores with 1.25x multi-peer consensus boost for chunks seen across >= 2 peers
        let mut fused: Vec<ScoredChunk> = rrf_map
            .into_iter()
            .map(|(_hash, (base_score, mut chunk, peers))| {
                let final_score = if peers.len() >= 2 {
                    base_score * 1.25
                } else {
                    base_score
                };
                chunk.score = final_score;
                chunk
            })
            .collect();

        // 4. Deterministic tie-breaking
        fused.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.chunk.chunk_id.cmp(&b.chunk.chunk_id))
                .then_with(|| a.chunk.blake3_hash.cmp(&b.chunk.blake3_hash))
        });

        // 5. Guaranteed federated peer diversity slots and interleaving
        let (local_chunks, remote_chunks): (Vec<ScoredChunk>, Vec<ScoredChunk>) =
            fused.into_iter().partition(|c| c.source_peer == "local");

        if remote_chunks.is_empty() {
            let mut res = local_chunks;
            res.truncate(top_k);
            return res;
        }

        if local_chunks.is_empty() {
            let mut res = remote_chunks;
            res.truncate(top_k);
            return res;
        }

        let target_len = top_k.min(local_chunks.len() + remote_chunks.len());
        let guaranteed_remote_slots = remote_chunks
            .len()
            .min(std::cmp::max(2, top_k / 3))
            .min(target_len);

        // Count how many remote chunks naturally fall into top target_len by score
        let natural_remote_count = {
            let mut count = 0;
            let mut loc_idx = 0;
            let mut rem_idx = 0;
            for _ in 0..target_len {
                match (local_chunks.get(loc_idx), remote_chunks.get(rem_idx)) {
                    (Some(loc), Some(rem)) => {
                        if rem.score >= loc.score {
                            count += 1;
                            rem_idx += 1;
                        } else {
                            loc_idx += 1;
                        }
                    }
                    (None, Some(_)) => {
                        count += 1;
                        rem_idx += 1;
                    }
                    (Some(_), None) => {
                        loc_idx += 1;
                    }
                    (None, None) => break,
                }
            }
            count
        };

        let num_remote = natural_remote_count
            .max(guaranteed_remote_slots)
            .min(remote_chunks.len())
            .min(target_len);
        let num_local = target_len - num_remote;

        let max_consecutive_local = ((num_local + num_remote) / (num_remote + 1)).max(1);
        let mut local_iter = local_chunks.into_iter().take(num_local).peekable();
        let mut remote_iter = remote_chunks.into_iter().take(num_remote).peekable();
        let mut result = Vec::with_capacity(target_len);
        let mut consecutive_local = 0;

        while result.len() < target_len {
            match (local_iter.peek(), remote_iter.peek()) {
                (Some(loc), Some(rem)) => {
                    if rem.score >= loc.score || consecutive_local >= max_consecutive_local {
                        result.push(remote_iter.next().unwrap());
                        consecutive_local = 0;
                    } else {
                        result.push(local_iter.next().unwrap());
                        consecutive_local += 1;
                    }
                }
                (Some(_), None) => {
                    result.push(local_iter.next().unwrap());
                }
                (None, Some(_)) => {
                    result.push(remote_iter.next().unwrap());
                }
                (None, None) => break,
            }
        }

        result
    }
}
