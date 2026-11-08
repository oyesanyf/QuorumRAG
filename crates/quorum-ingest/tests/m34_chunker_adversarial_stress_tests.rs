//! Empirical Adversarial Stress Test Suite for Milestone M34:
//! Boundary Snapping, Mid-Word Avoidance, and Multibyte UTF-8 Safety in `TextChunker`.

use quorum_ingest::chunker::{ChunkerConfig, TextChunker};

/// Helper oracle that checks whether a chunk boundary cuts an alphanumeric word in half
/// despite the presence of whitespace or sentence punctuation in the candidate window.
fn assert_no_mid_word_cuts(content: &str, target_chunk_size: usize, chunk_overlap: usize) {
    let config = ChunkerConfig {
        target_chunk_size,
        chunk_overlap,
        min_chunk_size: 1.max(target_chunk_size / 5),
    };
    let chunker = TextChunker::new(config);
    let chunks = chunker.chunk_text(content);

    if content.is_empty() {
        assert!(chunks.is_empty(), "Empty content must produce 0 chunks");
        return;
    }

    let mut last_char_end = 0;

    for (i, chunk) in chunks.iter().enumerate() {
        // Invariant 1: Valid slice bounds and char boundary alignment
        assert!(chunk.char_start <= chunk.char_end);
        assert!(chunk.char_end <= content.len());
        assert!(content.is_char_boundary(chunk.char_start), "char_start {} not a char boundary", chunk.char_start);
        assert!(content.is_char_boundary(chunk.char_end), "char_end {} not a char boundary", chunk.char_end);
        assert_eq!(chunk.text_slice, &content[chunk.char_start..chunk.char_end]);
        assert_eq!(chunk.chunk_index, i);

        // Invariant 2: Non-empty trimmed slice
        assert!(!chunk.text_slice.trim().is_empty(), "Chunk {} slice is empty", i);

        // Invariant 3: Monotonic progression
        if i > 0 {
            assert!(
                chunk.char_start > chunks[i - 1].char_start,
                "Chunk {} start {} did not strictly advance past previous start {}",
                i,
                chunk.char_start,
                chunks[i - 1].char_start
            );
        }
        last_char_end = last_char_end.max(chunk.char_end);

        // Invariant 4: No mid-word start when whitespace/punctuation exists
        if chunk.char_start > 0 {
            let prev_char = content[..chunk.char_start].chars().next_back().unwrap();
            let first_char = chunk.text_slice.chars().next().unwrap();

            if prev_char.is_alphanumeric() && first_char.is_alphanumeric() {
                // If both are alphanumeric, check if whitespace was available in the candidate range
                let candidate_bound = if i > 0 { chunks[i - 1].char_start } else { 0 };
                let mut search_start = chunk.char_start.saturating_sub(60).max(candidate_bound);
                while !content.is_char_boundary(search_start) && search_start < chunk.char_start {
                    search_start += 1;
                }
                let search_window = &content[search_start..chunk.char_start.min(content.len())];
                let has_ws = search_window.chars().any(char::is_whitespace);
                assert!(
                    !has_ws,
                    "Chunk {} (size {}, overlap {}) started mid-word ('{}' preceded by '{}') at offset {}: '{}' | full slice: '{}'",
                    i, target_chunk_size, chunk_overlap, first_char, prev_char, chunk.char_start, search_window, chunk.text_slice
                );
            }
        }

        // Invariant 5: No mid-word end when whitespace exists in lookback window
        if chunk.char_end < content.len() {
            let last_char = chunk.text_slice.chars().next_back().unwrap();
            let next_char = content[chunk.char_end..].chars().next().unwrap();

            if last_char.is_alphanumeric() && next_char.is_alphanumeric() {
                let mut lookback = chunk.char_end.saturating_sub(target_chunk_size / 4);
                while !content.is_char_boundary(lookback) && lookback < chunk.char_end {
                    lookback += 1;
                }
                let window = &content[lookback..chunk.char_end];
                let has_ws = window.chars().any(char::is_whitespace);
                assert!(
                    !has_ws,
                    "Chunk {} ended mid-word ('{}' followed by '{}') even though whitespace exists in window: '{}'",
                    i, last_char, next_char, window
                );
            }
        }
    }

    // Invariant 6: Content coverage
    assert_eq!(last_char_end, content.len(), "Chunks did not cover through end of content");
}

#[test]
fn test_m34_chunking_english_prose_varied_sizes() {
    let text = "Software development in Python and systems architecture requires more than recognizing names. \
Comprehensive security engineering involves continuous remediation, automated scanning in GitHub Actions, \
and real-time data engineering pipelines. Furthermore, communications data and connected disclosure policy \
must protect all participants from accidental privacy exposure. Each node maintains a local database and \
synchronizes through a decentralized peer-to-peer protocol.";

    // Test a combinatorial matrix of chunk sizes and overlaps
    let sizes = [30, 50, 80, 100, 150, 200, 300, 500];
    let overlaps = [0, 5, 15, 30, 50, 80];

    for &size in &sizes {
        for &overlap in &overlaps {
            assert_no_mid_word_cuts(text, size, overlap);
        }
    }
}

#[test]
fn test_m34_chunking_explicit_known_broken_fragments_avoided() {
    let text = "Software development in Python and systems architecture requires more than recognizing names. \
Comprehensive security engineering involves continuous remediation, automated scanning in GitHub Actions, \
and real-time data engineering pipelines. Furthermore, communications data and connected disclosure policy \
must protect all participants from accidental privacy exposure.";

    // Target the specific broken fragments noted in M34 requirements
    let forbidden_start_fragments = [
        "lopment", "a engineering", "ns Data", "urity", "diation",
        "anning in GitHub", "ected disclosure", "quires more than",
    ];
    let forbidden_end_fragments = [
        "Pyt", "Comple", "remed",
    ];

    for size in (30..=250).step_by(15) {
        for overlap in (0..=size).step_by(15) {
            let config = ChunkerConfig {
                target_chunk_size: size,
                chunk_overlap: overlap,
                min_chunk_size: 10,
            };
            let chunker = TextChunker::new(config);
            let chunks = chunker.chunk_text(text);

            for (i, chunk) in chunks.iter().enumerate() {
                let slice = chunk.text_slice.trim();
                for &frag in &forbidden_start_fragments {
                    assert!(
                        !slice.starts_with(frag),
                        "Chunk {i} with size {size}/overlap {overlap} started with forbidden fragment '{frag}': {slice}"
                    );
                }
                for &frag in &forbidden_end_fragments {
                    assert!(
                        !slice.ends_with(frag),
                        "Chunk {i} with size {size}/overlap {overlap} ended with forbidden fragment '{frag}': {slice}"
                    );
                }
            }
        }
    }
}

#[test]
fn test_m34_chunking_multibyte_cjk_and_emojis() {
    let japanese_text = "人工知能（AI）と分散型検索エンジンQuorumRAGは、プライバシーを保護しながら高速な情報共有を実現します。\n\n\
ピアツーピアネットワークによる耐障害性と自律的なデータ同期が特徴です。セキュアな分散ハッシュテーブルとローカル埋め込みモデルを組み合わせ、\
クラウドに依存しない主権的な知識管理環境を提供します。";

    let mixed_cjk_emoji_text = "Line 1: Rust systems programming with 🦀 Rustacean tools.\n\
Line 2: 日本語のテキストと絵文字 🚀🔥⚡ による多言語テスト。\n\
Line 3: 繁體中文與簡體中文數據檢索：分佈式共識算法與區塊鏈驗證。\n\
Line 4: 한국어 자연어 처리 및 지식 그래프 합성 테스트입니다.\n\
Line 5: Multilingual security verification passed cleanly with zero panics! 🛡️✨";

    let sizes = [40, 75, 120, 200];
    let overlaps = [0, 10, 25, 60];

    for &size in &sizes {
        for &overlap in &overlaps {
            assert_no_mid_word_cuts(japanese_text, size, overlap);
            assert_no_mid_word_cuts(mixed_cjk_emoji_text, size, overlap);
        }
    }
}

#[test]
fn test_m34_chunking_code_snippets() {
    let rust_code = r#"
pub fn evaluate_consensus_quorum(votes: &[PeerVote], threshold: f64) -> Result<QuorumDecision, ConsensusError> {
    let total_weight: f64 = votes.iter().map(|v| v.weight).sum();
    if total_weight <= 0.0 {
        return Err(ConsensusError::EmptyVoterPool);
    }
    let affirmative_weight: f64 = votes
        .iter()
        .filter(|v| v.decision == VoteChoice::Affirmative)
        .map(|v| v.weight)
        .sum();
    let ratio = affirmative_weight / total_weight;
    if ratio >= threshold {
        Ok(QuorumDecision::Accepted { ratio, votes_count: votes.len() })
    } else {
        Ok(QuorumDecision::Rejected { ratio, votes_count: votes.len() })
    }
}
"#;

    let sizes = [50, 90, 150, 250];
    let overlaps = [0, 10, 30, 60];

    for &size in &sizes {
        for &overlap in &overlaps {
            assert_no_mid_word_cuts(rust_code, size, overlap);
        }
    }
}

#[test]
fn test_m34_chunking_mixed_alphanumeric_and_symbols() {
    let mixed_text = "Endpoints: https://api.quorumrag.internal/v1/scatter-gather?timeout=500ms&top_k=10. \
SHA-256 hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. \
Configuration keys: cluster.p2p.listen_addr=127.0.0.1:3032, dlp.vaultgemma_1b.redact_mode=strict. \
Version v0.2.0-rc.3 deployed on 2026-11-08T05:10:00Z with 99.99% uptime.";

    let sizes = [40, 80, 140, 220];
    let overlaps = [0, 10, 25, 50];

    for &size in &sizes {
        for &overlap in &overlaps {
            assert_no_mid_word_cuts(mixed_text, size, overlap);
        }
    }
}

#[test]
fn test_m34_chunking_extreme_overlap_and_sizes() {
    let text = "First sentence of paragraph. Second sentence with important details. Third sentence for testing.";

    // 1. Overlap equals target size
    let config_equal = ChunkerConfig {
        target_chunk_size: 50,
        chunk_overlap: 50,
        min_chunk_size: 10,
    };
    let chunker_equal = TextChunker::new(config_equal);
    let chunks_equal = chunker_equal.chunk_text(text);
    assert!(!chunks_equal.is_empty());
    for chunk in &chunks_equal {
        assert!(!chunk.text_slice.is_empty());
    }

    // 2. Overlap greater than target size (must not loop infinitely)
    let config_greater = ChunkerConfig {
        target_chunk_size: 40,
        chunk_overlap: 100,
        min_chunk_size: 10,
    };
    let chunker_greater = TextChunker::new(config_greater);
    let chunks_greater = chunker_greater.chunk_text(text);
    assert!(!chunks_greater.is_empty());
    for chunk in &chunks_greater {
        assert!(!chunk.text_slice.is_empty());
    }

    // 3. Single long word with NO whitespace or punctuation (100 chars)
    let solid_word = "a".repeat(100);
    let config_solid = ChunkerConfig {
        target_chunk_size: 25,
        chunk_overlap: 5,
        min_chunk_size: 5,
    };
    let chunker_solid = TextChunker::new(config_solid);
    let chunks_solid = chunker_solid.chunk_text(&solid_word);
    assert!(!chunks_solid.is_empty());
    let mut total_chars = 0;
    for chunk in &chunks_solid {
        total_chars = total_chars.max(chunk.char_end);
    }
    assert_eq!(total_chars, solid_word.len());
}
