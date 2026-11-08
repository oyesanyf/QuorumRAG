//! Adversarial Empirical Stress Test Suite for Milestone M34:
//! Sentence Truncation, Extreme Boundaries, and Document Family Deduplication.

use quorum_coordinator::offline_engine::DeterministicOfflineSynthesisEngine;
use quorum_types::{DocumentChunk, ScoredChunk};

fn make_test_scored_chunk(id: &str, file: &str, score: f32) -> ScoredChunk {
    let chunk = DocumentChunk::new(
        id,
        "doc_alpha",
        file,
        1,
        10,
        0,
        vec![0.1f32; 768],
        "Sample text content for chunk testing.",
        None,
    )
    .unwrap();
    ScoredChunk::new(chunk, score, "local", false)
}

#[test]
fn test_m34_sentence_truncation_extreme_max_chars() {
    let sample = "Software engineering requires continuous automated verification. \
Decentralized P2P search provides resilient, private document retrieval without centralized telemetry. \
Multi-ring isolation protects sensitive information across all participating nodes.";

    // 1. max_chars = 0
    let t0 = DeterministicOfflineSynthesisEngine::truncate_to_sentence_boundary(sample, 0);
    assert_eq!(t0, "");

    // 2. max_chars = 1
    let t1 = DeterministicOfflineSynthesisEngine::truncate_to_sentence_boundary(sample, 1);
    assert_eq!(t1, "S");

    // 3. max_chars = 10
    // "Software engineering" -> budget 10 is "Software e".
    // Fallback whitespace is at index 8 ("Software ").
    // Must snap cleanly to "Software" without cutting "engineering" as "e".
    let t10 = DeterministicOfflineSynthesisEngine::truncate_to_sentence_boundary(sample, 10);
    assert_eq!(t10, "Software");

    // 4. max_chars = 70
    // First sentence is 65 chars long ending with '.'
    // Must snap cleanly to whole first sentence.
    let t70 = DeterministicOfflineSynthesisEngine::truncate_to_sentence_boundary(sample, 70);
    assert!(
        t70.ends_with('.'),
        "Must end with sentence terminal period, got: '{}'",
        t70
    );
    assert_eq!(
        t70,
        "Software engineering requires continuous automated verification."
    );

    // 5. max_chars = 800 (larger than text)
    let t800 = DeterministicOfflineSynthesisEngine::truncate_to_sentence_boundary(sample, 800);
    assert_eq!(t800, sample);

    // 6. max_chars = 10000 (extreme large boundary)
    let t10k = DeterministicOfflineSynthesisEngine::truncate_to_sentence_boundary(sample, 10000);
    assert_eq!(t10k, sample);
}

#[test]
fn test_m34_sentence_truncation_very_long_sentence_no_punctuation() {
    // 100 words separated by spaces without any period, question mark, or exclamation
    let words: Vec<&str> = (0..100).map(|_| "unpunctuated").collect();
    let text = words.join(" ");

    let t50 = DeterministicOfflineSynthesisEngine::truncate_to_sentence_boundary(&text, 50);
    // Must not end mid-word
    assert!(
        !t50.ends_with("unp") && !t50.ends_with("unpunctu"),
        "Truncation ended mid-word: '{}'",
        t50
    );
    // Each word is "unpunctuated" (12 chars). 50 / 13 = 3 words with spaces = 38 chars.
    let count = t50.split_whitespace().count();
    assert!(count >= 3 && count <= 4);
    for w in t50.split_whitespace() {
        assert_eq!(w, "unpunctuated", "Word must be complete");
    }
}

#[test]
fn test_m34_sentence_truncation_solid_unspaced_string() {
    // Continuous 500-char string with no whitespace and no punctuation
    let solid = "x".repeat(500);

    let t25 = DeterministicOfflineSynthesisEngine::truncate_to_sentence_boundary(&solid, 25);
    assert_eq!(t25.len(), 25);
    assert_eq!(t25, &solid[..25]);

    let t100 = DeterministicOfflineSynthesisEngine::truncate_to_sentence_boundary(&solid, 100);
    assert_eq!(t100.len(), 100);
}

#[test]
fn test_m34_sentence_truncation_multibyte_cjk_and_emojis() {
    let japanese_text = "人工知能と分散型検索エンジンQuorumRAGは、プライバシーを保護しながら高速な情報共有を実現します。セキュアな分散ハッシュテーブルとローカル埋め込みモデルを組み合わせ、主権的な知識管理環境を提供します。";

    // Extreme boundaries over multibyte Japanese UTF-8 characters (3 bytes per Kanji/Hiragana)
    for max_c in [1, 2, 5, 10, 20, 40, 80, 200] {
        let truncated = DeterministicOfflineSynthesisEngine::truncate_to_sentence_boundary(japanese_text, max_c);
        assert!(
            truncated.chars().count() <= max_c,
            "Truncated char count {} exceeded max_chars {}",
            truncated.chars().count(),
            max_c
        );
        // Ensure no UTF-8 character boundary corruption
        assert_eq!(truncated, truncated.trim());
    }

    // 4-byte UTF-8 emojis
    let emojis = "🦀🚀🔥⚡🛡️🧠💡🌍🎯💻";
    for max_c in [1, 3, 5, 10] {
        let truncated = DeterministicOfflineSynthesisEngine::truncate_to_sentence_boundary(emojis, max_c);
        assert!(
            truncated.chars().count() <= max_c,
            "Emoji truncated count {} exceeded max_chars {}",
            truncated.chars().count(),
            max_c
        );
    }
}

#[test]
fn test_m34_sentence_truncation_abbreviations_and_numbers() {
    // Decimals and abbreviations should not trigger false sentence boundaries
    let text = "Version 1.0.4 was released on Nov. 8th. The price is $12.50 per unit. Final sentence follows.";

    // Budget of 45 characters falls around "Nov. 8th."
    let t45 = DeterministicOfflineSynthesisEngine::truncate_to_sentence_boundary(text, 45);
    // Boundary must be either at the first full sentence terminal ("released on Nov. 8th.") or whitespace
    assert!(!t45.is_empty());
    assert!(!t45.ends_with("1."));
    assert!(!t45.ends_with("12."));

    // Budget that encompasses the first sentence ("Version 1.0.4 was released on Nov. 8th.")
    let t50 = DeterministicOfflineSynthesisEngine::truncate_to_sentence_boundary(text, 50);
    assert!(t50.ends_with('.'));
}

#[test]
fn test_m34_canonical_document_family_deduplication() {
    // Revisions, versions, and copy numbers must map to the same family key
    let family1 = DeterministicOfflineSynthesisEngine::derive_document_family_key("Femi_Oyesanya_Enhanced_Resume_2026.docx");
    let family2 = DeterministicOfflineSynthesisEngine::derive_document_family_key("Femi_Oyesanya_Enhanced_Resume_v2.docx");
    let family3 = DeterministicOfflineSynthesisEngine::derive_document_family_key("Femi_Oyesanya_Enhanced_Resume (1).pdf");
    let family4 = DeterministicOfflineSynthesisEngine::derive_document_family_key("Femi_Oyesanya_Enhanced_Resume_Final.pdf");

    assert_eq!(family1, family2, "Year and version revisions must share same family key");
    assert_eq!(family2, family3, "Copy number (1) must share same family key");
    assert_eq!(family3, family4, "Final revision must share same family key");

    // RedactX-v3 reports must share family key
    let rx1 = DeterministicOfflineSynthesisEngine::derive_document_family_key("RedactX_v3_evaluation_report.pdf");
    let rx2 = DeterministicOfflineSynthesisEngine::derive_document_family_key("RedactX_v3_technical_specification.docx");
    let rx3 = DeterministicOfflineSynthesisEngine::derive_document_family_key("RedactX_v3_final.pdf");
    assert_eq!(rx1, rx2);
    assert_eq!(rx2, rx3);

    // Multimodal image and distinct documents must NEVER be collapsed
    let img_family = DeterministicOfflineSynthesisEngine::derive_document_family_key("Femi_Oyesanya_Enhanced_Resume.png");
    assert_ne!(family1, img_family, "Image must have distinct family prefix");

    let w2_family = DeterministicOfflineSynthesisEngine::derive_document_family_key("Femi_Oyesanya_W2_2026.pdf");
    assert_ne!(family1, w2_family, "W2 tax form must not collide with Resume family");
}

#[test]
fn test_m34_canonical_document_selection_scoring() {
    let c1 = make_test_scored_chunk("c1", "Femi_Oyesanya_Enhanced_Resume_2024.pdf", 0.9);
    let c2 = make_test_scored_chunk("c2", "Femi_Oyesanya_Enhanced_Resume_Draft.docx", 0.9);
    let c3 = make_test_scored_chunk("c3", "Femi_Oyesanya_Enhanced_Resume_2026_Final.docx", 0.9);
    let c4 = make_test_scored_chunk("c4", "Femi_Oyesanya_Enhanced_Resume (1).pdf", 0.9);

    let candidates = vec![&c1, &c2, &c3, &c4];

    let canonical = DeterministicOfflineSynthesisEngine::pick_canonical_document_for_family(&candidates);
    assert!(canonical.is_some());
    assert_eq!(
        canonical.unwrap().chunk.file_path,
        "Femi_Oyesanya_Enhanced_Resume_2026_Final.docx",
        "Must pick the 2026 Final docx over drafts and older pdf revisions"
    );
}

#[test]
fn test_m34_typo_query_normalization() {
    let (corrected_upper, _) = DeterministicOfflineSynthesisEngine::correct_query_spelling("Whi is Femi Oyesanya", false);
    assert_eq!(corrected_upper, "Who is Femi Oyesanya");

    let (corrected_lower, _) = DeterministicOfflineSynthesisEngine::correct_query_spelling("whi is Femi Oyesanya", false);
    assert_eq!(corrected_lower, "who is Femi Oyesanya");

    let (corrected2, _) = DeterministicOfflineSynthesisEngine::correct_query_spelling("Whos Femi Oyesanya", false);
    assert_eq!(corrected2, "Who's Femi Oyesanya");

    let (corrected3, _) = DeterministicOfflineSynthesisEngine::correct_query_spelling("Whoo is Femi Oyesanya", false);
    assert_eq!(corrected3, "Who is Femi Oyesanya");
}
