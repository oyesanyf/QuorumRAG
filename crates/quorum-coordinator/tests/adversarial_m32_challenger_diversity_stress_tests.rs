//! Adversarial Challenger M32 Stress Tests:
//! Rigorous empirical verification of guaranteed federated peer diversity slots,
//! interleaving invariants, extreme distributions (50:1, 100:10), diverse top_k values,
//! starvation prevention, and randomized stress harnesses.

use quorum_coordinator::fusion::RrfCombiner;
use quorum_types::{CandidateChunkDto, DocumentChunk, ScoredChunk};

fn create_local_chunk(id: usize, score: f32) -> ScoredChunk {
    let chunk = DocumentChunk::new(
        &format!("local_chunk_{:04}", id),
        &format!("local_doc_{:04}", id),
        &format!("C:/local/data/doc_{:04}.txt", id),
        1,
        20,
        0,
        vec![0.1; 768],
        &format!("Local distinct content line {:04} for candidate retrieval", id),
        None,
    )
    .expect("Valid DocumentChunk");
    ScoredChunk::new(chunk, score, "local", false)
}

fn create_remote_candidate(peer: &str, id: usize, score: f32) -> CandidateChunkDto {
    CandidateChunkDto {
        chunk_id: format!("remote_{}_{:04}", peer, id),
        file_path: format!("D:/remote/{}/evidence_{:04}.pdf", peer, id),
        line_start: 1,
        line_end: 25,
        score,
        access_tier: 0,
        content: format!("Remote peer {} distinct payload segment {:04}", peer, id),
    }
}

/// 1. Extreme distribution: 50 local chunks vs 1 remote peer chunk.
/// Tests across top_k in [3, 5, 10, 20].
/// Asserts that the single remote chunk is guaranteed a slot and is interleaved rather than starved.
#[test]
fn test_extreme_distribution_50_local_vs_1_remote() {
    let local_count = 50;
    let top_k_values = vec![3, 5, 10, 20];

    for top_k in top_k_values {
        let mut local_results = Vec::with_capacity(local_count);
        for i in 0..local_count {
            let score = 0.999 - (i as f32 * 0.005);
            local_results.push(create_local_chunk(i, score));
        }

        let remote_peer_id = "12D3KooWAlphaHost111".to_string();
        let remote_list = vec![create_remote_candidate(&remote_peer_id, 1, 0.001)];
        let remote_peers = vec![(remote_peer_id.clone(), remote_list)];

        let fused = RrfCombiner::fuse_rankings_with_peers(local_results, remote_peers, 60.0, top_k);

        assert_eq!(
            fused.len(),
            top_k,
            "Fused length must equal top_k={}",
            top_k
        );

        let remote_fused: Vec<(usize, &ScoredChunk)> = fused
            .iter()
            .enumerate()
            .filter(|(_, c)| c.source_peer == remote_peer_id)
            .collect();

        // min(1, max(2, top_k / 3)) = 1
        assert_eq!(
            remote_fused.len(),
            1,
            "The single remote chunk must be awarded a slot under top_k={}",
            top_k
        );

        let (remote_idx, remote_chunk) = remote_fused[0];
        assert_eq!(remote_chunk.chunk.chunk_id, format!("remote_{}_0001", remote_peer_id));

        // Interleaving assertion: local hits cannot monopolize top ranks.
        // max_consecutive_local = ((top_k - 1 + 1) / (1 + 1)).max(1) = top_k / 2.
        let max_consecutive_local = (top_k / 2).max(1);
        assert!(
            remote_idx <= max_consecutive_local,
            "Remote chunk index {} exceeds max_consecutive_local {} for top_k={}",
            remote_idx,
            max_consecutive_local,
            top_k
        );
    }
}

/// 2. Extreme distribution: 100 local chunks vs 10 remote peer chunks.
/// Tests across diverse top_k values: [3, 5, 10, 20].
/// Asserts that AT LEAST min(remote_chunks.len(), max(2, top_k / 3)) slots are guaranteed,
/// and that interleaving prevents local monopolization.
#[test]
fn test_extreme_distribution_100_local_vs_10_remote() {
    let local_count = 100;
    let remote_count = 10;
    let top_k_values = vec![3, 5, 10, 20];

    for top_k in top_k_values {
        let mut local_results = Vec::with_capacity(local_count);
        for i in 0..local_count {
            let score = 0.999 - (i as f32 * 0.002);
            local_results.push(create_local_chunk(i, score));
        }

        let remote_peer_id = "12D3KooWBetaHost222".to_string();
        let mut remote_list = Vec::with_capacity(remote_count);
        for j in 0..remote_count {
            let score = 0.010 - (j as f32 * 0.0005);
            remote_list.push(create_remote_candidate(&remote_peer_id, j, score));
        }
        let remote_peers = vec![(remote_peer_id.clone(), remote_list)];

        let fused = RrfCombiner::fuse_rankings_with_peers(local_results, remote_peers, 60.0, top_k);

        assert_eq!(
            fused.len(),
            top_k,
            "Fused length must equal top_k={}",
            top_k
        );

        let remote_fused: Vec<(usize, &ScoredChunk)> = fused
            .iter()
            .enumerate()
            .filter(|(_, c)| c.source_peer == remote_peer_id)
            .collect();

        let guaranteed_remote_slots = remote_count.min(std::cmp::max(2, top_k / 3)).min(top_k);
        assert!(
            remote_fused.len() >= guaranteed_remote_slots,
            "Failed guaranteed remote slots for top_k={}: expected >= {}, got {}",
            top_k,
            guaranteed_remote_slots,
            remote_fused.len()
        );

        // Verify interleaving:
        // Consecutive local chunks before all remote chunks are placed must not exceed max_consecutive_local
        let num_remote = remote_fused.len();
        let num_local = top_k - num_remote;
        let max_consecutive_local = ((num_local + num_remote) / (num_remote + 1)).max(1);

        let mut consecutive_local = 0;
        let mut remotes_seen = 0;
        for c in &fused {
            if c.source_peer == "local" {
                consecutive_local += 1;
                if remotes_seen < num_remote {
                    assert!(
                        consecutive_local <= max_consecutive_local,
                        "Monopolization violation at top_k={}: consecutive_local {} > max_consecutive_local {}",
                        top_k,
                        consecutive_local,
                        max_consecutive_local
                    );
                }
            } else {
                consecutive_local = 0;
                remotes_seen += 1;
            }
        }
        assert_eq!(remotes_seen, num_remote);
    }
}

/// 3. Starvation Resistance: When local chunks strictly outscore all remote chunks
/// (e.g., local chunks have multi-peer consensus boost),
/// assert that guaranteed diversity slots kick in and award EXACTLY min(remote.len(), max(2, top_k / 3)),
/// and local hits do NOT monopolize top ranks.
#[test]
fn test_starvation_resistance_when_all_locals_outscore_remotes() {
    let top_k_values = vec![3, 5, 10, 20];

    for top_k in top_k_values {
        // Create 50 local chunks
        let mut local_results = Vec::new();
        for i in 0..50 {
            local_results.push(create_local_chunk(i, 0.99));
        }

        // Create an internal booster peer that agrees with all local chunks,
        // giving them 1.25x consensus boost so that ALL local chunks strictly outrank any remote chunk
        let mut local_booster = Vec::new();
        for i in 0..50 {
            local_booster.push(CandidateChunkDto {
                chunk_id: format!("boost_{:04}", i),
                file_path: format!("C:/local/data/doc_{:04}.txt", i),
                line_start: 1,
                line_end: 20,
                score: 0.99,
                access_tier: 0,
                content: format!("Local distinct content line {:04} for candidate retrieval", i),
            });
        }

        // Remote peer provides 10 distinct chunks (no consensus boost)
        let remote_peer_id = "12D3KooWRemoteStarvedPeer".to_string();
        let mut remote_list = Vec::new();
        for j in 0..10 {
            remote_list.push(create_remote_candidate(&remote_peer_id, j, 0.10));
        }

        let remote_peers = vec![
            ("local_booster_peer".to_string(), local_booster),
            (remote_peer_id.clone(), remote_list),
        ];

        let fused = RrfCombiner::fuse_rankings_with_peers(local_results, remote_peers, 60.0, top_k);
        assert_eq!(fused.len(), top_k);

        let remote_fused: Vec<&ScoredChunk> = fused
            .iter()
            .filter(|c| c.source_peer == remote_peer_id)
            .collect();

        // Since every local chunk has 1.25x boosted RRF score, natural_remote_count = 0.
        // Therefore, diversity slots MUST award EXACTLY min(10, max(2, top_k / 3)) slots.
        let expected_slots = 10usize.min(std::cmp::max(2, top_k / 3)).min(top_k);
        assert_eq!(
            remote_fused.len(),
            expected_slots,
            "Starvation protection failed at top_k={}: expected {} slots, got {}",
            top_k,
            expected_slots,
            remote_fused.len()
        );

        // Verify interleaving prevents local monopolization
        let num_local = top_k - expected_slots;
        let num_remote = expected_slots;
        let max_consecutive_local = ((num_local + num_remote) / (num_remote + 1)).max(1);

        let mut consecutive_local = 0;
        let mut remotes_seen = 0;
        for c in &fused {
            if c.source_peer == "local" {
                consecutive_local += 1;
                if remotes_seen < num_remote {
                    assert!(
                        consecutive_local <= max_consecutive_local,
                        "Interleaving failed under starvation at top_k={}: consecutive_local {} > max {}",
                        top_k,
                        consecutive_local,
                        max_consecutive_local
                    );
                }
            } else if c.source_peer == remote_peer_id {
                consecutive_local = 0;
                remotes_seen += 1;
            }
        }
        assert_eq!(remotes_seen, expected_slots);
    }
}

/// 4. Boundary top_k values: top_k = 0, 1, 2, and very large top_k = 200.
#[test]
fn test_boundary_top_k_values() {
    let local_count = 10;
    let remote_count = 5;

    let mk_inputs = || {
        let mut locals = Vec::new();
        for i in 0..local_count {
            locals.push(create_local_chunk(i, 0.90 - (i as f32 * 0.02)));
        }
        let mut remotes = Vec::new();
        for j in 0..remote_count {
            remotes.push(create_remote_candidate("peer_boundary", j, 0.40 - (j as f32 * 0.02)));
        }
        (locals, vec![("peer_boundary".to_string(), remotes)])
    };

    // top_k = 0 -> empty result without panic
    {
        let (locals, remotes) = mk_inputs();
        let res = RrfCombiner::fuse_rankings_with_peers(locals, remotes, 60.0, 0);
        assert_eq!(res.len(), 0);
    }

    // top_k = 1 -> exactly 1 chunk returned (guaranteed remote slot capped at target_len=1)
    {
        let (locals, remotes) = mk_inputs();
        let res = RrfCombiner::fuse_rankings_with_peers(locals, remotes, 60.0, 1);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].source_peer, "peer_boundary");
    }

    // top_k = 2 -> min(5, max(2, 2/3)).min(2) = 2 remote slots
    {
        let (locals, remotes) = mk_inputs();
        let res = RrfCombiner::fuse_rankings_with_peers(locals, remotes, 60.0, 2);
        assert_eq!(res.len(), 2);
        let rem_count = res.iter().filter(|c| c.source_peer == "peer_boundary").count();
        assert_eq!(rem_count, 2);
    }

    // top_k = 200 (greater than total available chunks: 10 + 5 = 15)
    {
        let (locals, remotes) = mk_inputs();
        let res = RrfCombiner::fuse_rankings_with_peers(locals, remotes, 60.0, 200);
        assert_eq!(res.len(), 15, "Target len must cap at total chunks available (15)");
        let rem_count = res.iter().filter(|c| c.source_peer == "peer_boundary").count();
        assert_eq!(rem_count, 5, "All 5 remote chunks must be present");
        let loc_count = res.iter().filter(|c| c.source_peer == "local").count();
        assert_eq!(loc_count, 10, "All 10 local chunks must be present");
    }
}

/// 5. Empty collections: zero remote chunks vs zero local chunks.
#[test]
fn test_empty_collections_resilience() {
    // 0 remote chunks, 10 local chunks
    {
        let mut locals = Vec::new();
        for i in 0..10 {
            locals.push(create_local_chunk(i, 0.9 - (i as f32 * 0.05)));
        }
        let res = RrfCombiner::fuse_rankings_with_peers(locals, Vec::new(), 60.0, 5);
        assert_eq!(res.len(), 5);
        assert!(res.iter().all(|c| c.source_peer == "local"));
    }

    // 0 local chunks, 10 remote chunks
    {
        let mut remotes = Vec::new();
        for j in 0..10 {
            remotes.push(create_remote_candidate("peer_lone", j, 0.8 - (j as f32 * 0.05)));
        }
        let res = RrfCombiner::fuse_rankings_with_peers(
            Vec::new(),
            vec![("peer_lone".to_string(), remotes)],
            60.0,
            5,
        );
        assert_eq!(res.len(), 5);
        assert!(res.iter().all(|c| c.source_peer == "peer_lone"));
    }

    // Both empty
    {
        let res = RrfCombiner::fuse_rankings_with_peers(Vec::new(), Vec::new(), 60.0, 5);
        assert!(res.is_empty());
    }
}

/// 6. Multiple remote peers: chunks distributed across multiple distinct remote peers.
#[test]
fn test_multiple_remote_peers_diversity() {
    let mut locals = Vec::new();
    for i in 0..20 {
        locals.push(create_local_chunk(i, 0.95 - (i as f32 * 0.01)));
    }

    let mut peer_a = Vec::new();
    for j in 0..3 {
        peer_a.push(create_remote_candidate("peer_a", j, 0.10));
    }

    let mut peer_b = Vec::new();
    for k in 0..3 {
        peer_b.push(create_remote_candidate("peer_b", k, 0.12));
    }

    let remote_peers = vec![
        ("peer_a".to_string(), peer_a),
        ("peer_b".to_string(), peer_b),
    ];

    let top_k = 10;
    // Guaranteed slots = min(6, max(2, 10 / 3)) = min(6, 3) = 3
    let fused = RrfCombiner::fuse_rankings_with_peers(locals, remote_peers, 60.0, top_k);
    assert_eq!(fused.len(), top_k);

    let remote_chunks: Vec<&ScoredChunk> = fused
        .iter()
        .filter(|c| c.source_peer != "local")
        .collect();
    assert!(
        remote_chunks.len() >= 3,
        "Expected at least 3 remote chunks, got {}",
        remote_chunks.len()
    );

    // Verify both peers can contribute chunks
    let has_peer_a = remote_chunks.iter().any(|c| c.source_peer == "peer_a");
    let has_peer_b = remote_chunks.iter().any(|c| c.source_peer == "peer_b");
    assert!(has_peer_a && has_peer_b, "Both remote peers must have slots represented");
}

/// 7. Multi-peer consensus boost: identical chunk across local and remote gets 1.25x boost.
#[test]
fn test_multi_peer_consensus_boost_and_deduplication() {
    let content = "Critical shared protocol invariant specification";
    let chunk_local = DocumentChunk::new(
        "shared_chunk_1",
        "doc_shared",
        "C:/local/spec.txt",
        1,
        10,
        0,
        vec![0.1; 768],
        content,
        None,
    )
    .unwrap();
    let local_scored = ScoredChunk::new(chunk_local, 0.50, "local", false);

    let remote_candidate = CandidateChunkDto {
        chunk_id: "remote_chunk_shared_1".to_string(),
        file_path: "D:/remote/spec.txt".to_string(),
        line_start: 1,
        line_end: 10,
        score: 0.50,
        access_tier: 0,
        content: content.to_string(),
    };

    let fused = RrfCombiner::fuse_rankings_with_peers(
        vec![local_scored],
        vec![("peer_remote_agree".to_string(), vec![remote_candidate])],
        60.0,
        5,
    );

    // Must deduplicate to 1 chunk
    assert_eq!(fused.len(), 1);
    let expected_base = (1.0 / 61.0) + (1.0 / 61.0);
    let expected_boosted = expected_base * 1.25;
    let diff = (fused[0].score - expected_boosted).abs();
    assert!(diff < 1e-5, "Expected boosted score {}, got {}", expected_boosted, fused[0].score);
}

/// 8. Randomized property-based stress oracle over 50 randomized iterations:
/// Verifies invariants across arbitrary random counts of local, remote, and top_k values.
#[test]
fn test_randomized_stress_oracle() {
    let mut lcg_state: u64 = 0xDEADBEEFCAFE;
    let mut next_rand = || -> u64 {
        lcg_state = lcg_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        lcg_state
    };

    for trial in 0..50 {
        let local_count = (next_rand() % 40) as usize; // 0..39
        let remote_count = (next_rand() % 15) as usize; // 0..14
        let top_k = ((next_rand() % 20) + 1) as usize; // 1..20

        let mut locals = Vec::with_capacity(local_count);
        for i in 0..local_count {
            let score = ((next_rand() % 1000) as f32) / 1000.0;
            locals.push(create_local_chunk(trial * 1000 + i, score));
        }

        let mut remotes = Vec::with_capacity(remote_count);
        for j in 0..remote_count {
            let score = ((next_rand() % 1000) as f32) / 1000.0;
            remotes.push(create_remote_candidate("rand_peer", trial * 1000 + j, score));
        }

        let fused = RrfCombiner::fuse_rankings_with_peers(
            locals,
            vec![("rand_peer".to_string(), remotes)],
            60.0,
            top_k,
        );

        let target_len = top_k.min(local_count + remote_count);
        assert_eq!(
            fused.len(),
            target_len,
            "Trial {}: Fused len {} must equal target_len {}",
            trial,
            fused.len(),
            target_len
        );

        let rem_in_fused = fused.iter().filter(|c| c.source_peer == "rand_peer").count();
        let guaranteed_remote_slots = remote_count
            .min(std::cmp::max(2, top_k / 3))
            .min(target_len);

        assert!(
            rem_in_fused >= guaranteed_remote_slots,
            "Trial {}: Remote chunks in fused ({}) must be >= guaranteed_remote_slots ({}) for top_k={}, local={}, remote={}",
            trial,
            rem_in_fused,
            guaranteed_remote_slots,
            top_k,
            local_count,
            remote_count
        );

        // Verify interleaving: consecutive locals before all remotes placed must be bounded
        if rem_in_fused > 0 && fused.len() > rem_in_fused {
            let num_local = fused.len() - rem_in_fused;
            let num_remote = rem_in_fused;
            let max_consecutive_local = ((num_local + num_remote) / (num_remote + 1)).max(1);

            let mut consecutive = 0;
            let mut remotes_found = 0;
            for c in &fused {
                if c.source_peer == "local" {
                    consecutive += 1;
                    if remotes_found < num_remote {
                        assert!(
                            consecutive <= max_consecutive_local,
                            "Trial {}: Consecutive locals {} exceeded max_consecutive_local {} before all remotes placed",
                            trial,
                            consecutive,
                            max_consecutive_local
                        );
                    }
                } else {
                    consecutive = 0;
                    remotes_found += 1;
                }
            }
        }
    }
}
