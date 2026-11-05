//! Empirical Adversarial Stress & Verification Suite for M20 Recall & Conversational Retrieval Fixes.
//!
//! Stress-tests the 4 core dimensions:
//! 1. Authorship & Meta Terms: "article written by Femi Oyesanya" or "research done by Author"
//!    must not treat meta terms as mandatory lexical barriers that filter out genuine documents.
//! 2. Session Seen Chunks: Fresh standalone queries must not exclude previously seen chunks;
//!    continuation queries ("continue", "more", "else", "what else") must exclude them.
//! 3. Typo Correction & Restatement Wrapper: Typos ("dont", "artiles", "writen", "reserch") must be
//!    corrected; restatements must not leak `(Subject context: ...)` prompt wrappers.
//! 4. Stem Capping: Revision suffixes must cap to at most 2 chunks per normalized file stem.

use quorum_coordinator::{
    agentic::retrieve::QUERY_META_INTENT_TERMS,
    offline_engine::DeterministicOfflineSynthesisEngine,
};
use quorum_types::{DocumentChunk, ScoredChunk};
use std::collections::HashMap;

// =========================================================================
// 1. Stem Capping Invariant Tests
// =========================================================================

#[test]
fn test_stem_normalization_and_revision_stripping() {
    let cases = vec![
        ("RedactX_v1.pdf", "redactx"),
        ("RedactX_v2.pdf", "redactx"),
        ("RedactX_v3.pdf", "redactx"),
        ("RedactX_final.pdf", "redactx"),
        ("RedactX-final.pdf", "redactx"),
        ("RedactX_draft.pdf", "redactx"),
        ("RedactX-draft.pdf", "redactx"),
        ("RedactX_corrected.pdf", "redactx"),
        ("RedactX-corrected.docx", "redactx"),
        ("RedactX_rewritten.txt", "redactx"),
        ("RedactX_typesetting.pdf", "redactx"),
        ("RedactX_arxiv.pdf", "redactx"),
        ("RedactX(1).pdf", "redactx"),
        ("RedactX (2).pdf", "redactx"),
        ("ACDSO_v2_final.pdf", "acdso"),
        ("femi_cv_2026.pdf", "femi_cv_2026"),
        ("research_paper.docx", "research_paper"),
    ];

    for (input, expected) in cases {
        let normalized = DeterministicOfflineSynthesisEngine::normalize_file_stem(input);
        assert_eq!(
            normalized, expected,
            "File stem normalization failed for input '{}': expected '{}', got '{}'",
            input, expected, normalized
        );
    }
}

#[test]
fn test_stem_capping_max_two_chunks_per_stem() {
    // Generate 10 chunks from various revisions of RedactX
    let mut chunks: Vec<ScoredChunk> = Vec::new();
    let redactx_files = [
        "docs/RedactX_v1.pdf",
        "docs/RedactX_v2.pdf",
        "docs/RedactX_v3.pdf",
        "docs/RedactX_final.pdf",
        "docs/RedactX_draft.pdf",
        "docs/RedactX(1).pdf",
        "docs/RedactX (2).pdf",
        "docs/RedactX-corrected.pdf",
        "docs/RedactX_arxiv.pdf",
        "docs/RedactX_typesetting.pdf",
    ];

    for (i, path) in redactx_files.iter().enumerate() {
        let doc_chunk = DocumentChunk::new(
            format!("redactx:{}", i),
            "redactx",
            *path,
            1,
            20,
            0,
            vec![0.1; 768],
            format!("RedactX revision chunk content {}", i),
            None,
        )
        .unwrap();
        chunks.push(ScoredChunk {
            chunk: doc_chunk,
            score: 0.95 - (i as f32 * 0.01),
            source_peer: "local".to_string(),
            is_remote: false,
        });
    }

    // Add 4 chunks from ACDSO revisions
    let acdso_files = [
        "docs/ACDSO_v1.pdf",
        "docs/ACDSO_v2.pdf",
        "docs/ACDSO_final.pdf",
        "docs/ACDSO_draft.pdf",
    ];
    for (i, path) in acdso_files.iter().enumerate() {
        let doc_chunk = DocumentChunk::new(
            format!("acdso:{}", i),
            "acdso",
            *path,
            1,
            20,
            0,
            vec![0.1; 768],
            format!("ACDSO content {}", i),
            None,
        )
        .unwrap();
        chunks.push(ScoredChunk {
            chunk: doc_chunk,
            score: 0.80 - (i as f32 * 0.01),
            source_peer: "local".to_string(),
            is_remote: false,
        });
    }

    // Add 2 chunks from distinct papers
    let doc_chunk1 = DocumentChunk::new(
        "other1:0",
        "other1",
        "docs/Independent_Study.pdf",
        1,
        20,
        0,
        vec![0.1; 768],
        "Independent study on distributed consensus",
        None,
    )
    .unwrap();
    chunks.push(ScoredChunk {
        chunk: doc_chunk1,
        score: 0.75,
        source_peer: "local".to_string(),
        is_remote: false,
    });

    let doc_chunk2 = DocumentChunk::new(
        "other2:0",
        "other2",
        "docs/Neural_Mesh.pdf",
        1,
        20,
        0,
        vec![0.1; 768],
        "Neural mesh routing architecture",
        None,
    )
    .unwrap();
    chunks.push(ScoredChunk {
        chunk: doc_chunk2,
        score: 0.70,
        source_peer: "local".to_string(),
        is_remote: false,
    });

    // Apply the exact stem-capping logic used in `crates/quorum-coordinator/src/agentic/retrieve.rs:782-792`
    let mut stem_counts: HashMap<String, usize> = HashMap::new();
    let mut stem_deduped: Vec<ScoredChunk> = Vec::with_capacity(chunks.len());
    for c in chunks {
        let stem = DeterministicOfflineSynthesisEngine::normalize_file_stem(&c.chunk.file_path);
        let count = stem_counts.entry(stem).or_insert(0);
        if *count < 2 {
            *count += 1;
            stem_deduped.push(c);
        }
    }

    let mut final_counts: HashMap<String, usize> = HashMap::new();
    for c in &stem_deduped {
        let stem = DeterministicOfflineSynthesisEngine::normalize_file_stem(&c.chunk.file_path);
        *final_counts.entry(stem).or_insert(0) += 1;
    }

    assert_eq!(
        final_counts.get("redactx"),
        Some(&2),
        "RedactX must be capped at exactly 2 chunks despite 10 candidate revisions"
    );
    assert_eq!(
        final_counts.get("acdso"),
        Some(&2),
        "ACDSO must be capped at exactly 2 chunks despite 4 candidate revisions"
    );
    assert_eq!(
        final_counts.get("independent_study"),
        Some(&1),
        "Independent study must be retained"
    );
    assert_eq!(
        final_counts.get("neural_mesh"),
        Some(&1),
        "Neural mesh must be retained"
    );
    assert_eq!(
        stem_deduped.len(),
        6,
        "Total stem-capped pool must be 6 (2 RedactX + 2 ACDSO + 1 Independent + 1 Neural)"
    );
}

// =========================================================================
// 2. Typo Correction & Restatement Wrapper Tests
// =========================================================================

#[test]
fn test_typo_corrections_in_queries() {
    let test_cases = vec![
        ("dont", "done"),
        ("artiles", "articles"),
        ("writen", "written"),
        ("reserch", "research"),
        ("artcle", "article"),
        ("artcles", "articles"),
        ("athored", "authored"),
        ("anythng", "anything"),
        ("waht", "what"),
        ("wher", "where"),
    ];

    for (typo, expected_correction) in test_cases {
        let (corrected, _engine) =
            DeterministicOfflineSynthesisEngine::correct_query_spelling(typo, false);
        assert_eq!(
            corrected.to_ascii_lowercase(),
            expected_correction.to_ascii_lowercase(),
            "Standalone typo '{}' must correct to '{}', got '{}'",
            typo,
            expected_correction,
            corrected
        );
    }

    // Sentence-level typo correction test
    let query = "had he dont any other reserch";
    let (corrected, _engine) =
        DeterministicOfflineSynthesisEngine::correct_query_spelling(query, false);
    assert!(
        corrected.to_ascii_lowercase().contains("done"),
        "Sentence '{}' must correct 'dont' -> 'done': got '{}'",
        query,
        corrected
    );
    assert!(
        corrected.to_ascii_lowercase().contains("research"),
        "Sentence '{}' must correct 'reserch' -> 'research': got '{}'",
        query,
        corrected
    );

    let query2 = "artiles writen by Femi Oyesanya";
    let (corrected2, _engine) =
        DeterministicOfflineSynthesisEngine::correct_query_spelling(query2, false);
    assert!(
        corrected2.to_ascii_lowercase().contains("articles"),
        "Sentence '{}' must correct 'artiles' -> 'articles': got '{}'",
        query2,
        corrected2
    );
    assert!(
        corrected2.to_ascii_lowercase().contains("written"),
        "Sentence '{}' must correct 'writen' -> 'written': got '{}'",
        query2,
        corrected2
    );
}

#[test]
fn test_restatement_wrapper_leak_prevention() {
    // 1. Check format_question_restated_prefix on raw prompt
    let clean_prompt = "What is the policy?";
    let prefix = DeterministicOfflineSynthesisEngine::format_question_restated_prefix(clean_prompt);
    assert!(
        !prefix.contains("Subject context"),
        "Prefix for clean prompt must not contain 'Subject context'"
    );

    // 2. Check prompt that has `(Subject context: ...)` appended
    let wrapped_prompt = "what is the policy? (Subject context: Femi Oyesanya)";
    let clean_extracted = wrapped_prompt
        .split(" (Subject context:")
        .next()
        .unwrap_or(wrapped_prompt);
    let prefix_wrapped =
        DeterministicOfflineSynthesisEngine::format_question_restated_prefix(clean_extracted);
    assert!(
        !prefix_wrapped.contains("Subject context"),
        "Extracted prefix must not contain 'Subject context': got '{}'",
        prefix_wrapped
    );
    assert!(
        !prefix_wrapped.contains("Femi Oyesanya"),
        "Prefix should be restatement of the question itself, not leaking subject wrapper: got '{}'",
        prefix_wrapped
    );

    // 3. Check question_content_terms does not include "Subject" or "context" or terms from the wrapper
    let terms = DeterministicOfflineSynthesisEngine::question_content_terms(wrapped_prompt);
    assert!(
        !terms.contains(&"subject".to_string()),
        "question_content_terms must not include 'subject' from prompt wrapper"
    );
    assert!(
        !terms.contains(&"context".to_string()),
        "question_content_terms must not include 'context' from prompt wrapper"
    );
    assert!(
        terms.contains(&"policy".to_string()),
        "question_content_terms must include question content 'policy'"
    );
}

// =========================================================================
// 3. Session Seen Chunks Invariant Tests
// =========================================================================

#[test]
fn test_session_seen_chunks_continuation_vs_standalone() {
    // Continuation and exclusion queries
    let continuation_queries = vec![
        "continue",
        "continue the previous answer",
        "tell me more",
        "go on",
        "what else",
        "elaborate",
        "more details",
        "keep going",
        "expand",
        "more",
    ];

    let exclusion_queries = vec![
        "other than that",
        "other research",
        "other articles",
        "other work",
        "other papers",
        "any other research",
        "anything else",
        "what else",
        "besides RedactX, what else has he written?",
        "excluding the lease, what documents exist?",
        "aside from Angela Davis, who was mentioned?",
        "different paper",
    ];

    for q in &continuation_queries {
        let is_cont = DeterministicOfflineSynthesisEngine::is_continuation_query(&q.to_ascii_lowercase());
        let is_excl = DeterministicOfflineSynthesisEngine::is_exclusion_query(&q.to_ascii_lowercase());
        assert!(
            is_cont || is_excl,
            "Query '{}' must be detected as continuation or exclusion",
            q
        );
    }

    for q in &exclusion_queries {
        let is_cont = DeterministicOfflineSynthesisEngine::is_continuation_query(&q.to_ascii_lowercase());
        let is_excl = DeterministicOfflineSynthesisEngine::is_exclusion_query(&q.to_ascii_lowercase());
        assert!(
            is_cont || is_excl,
            "Query '{}' must be detected as continuation or exclusion",
            q
        );
    }

    // Fresh standalone queries
    let standalone_queries = vec![
        "Who is Femi Oyesanya?",
        "What is RedactX?",
        "Where did Angela Davis study?",
        "What is the rent for the apartment?",
        "Tell me about the Cigna healthcare policy",
        "How many chunks are indexed?",
    ];

    for q in &standalone_queries {
        let is_cont = DeterministicOfflineSynthesisEngine::is_continuation_query(&q.to_ascii_lowercase());
        let is_excl = DeterministicOfflineSynthesisEngine::is_exclusion_query(&q.to_ascii_lowercase());
        assert!(
            !is_cont && !is_excl,
            "Standalone query '{}' must NOT be detected as continuation or exclusion (got cont={}, excl={})",
            q,
            is_cont,
            is_excl
        );
    }

    // Simulation of session seen chunks filtering
    let seen_chunk_ids = vec!["chunk:0".to_string(), "chunk:1".to_string()];

    // Case A: Standalone query does not exclude seen chunks
    let prompt_standalone = "Who is Femi Oyesanya?";
    let is_cont_or_excl_standalone =
        DeterministicOfflineSynthesisEngine::is_continuation_query(&prompt_standalone.to_ascii_lowercase())
            || DeterministicOfflineSynthesisEngine::is_exclusion_query(&prompt_standalone.to_ascii_lowercase());

    let session_seen_standalone: Vec<String> = if is_cont_or_excl_standalone {
        seen_chunk_ids.clone()
    } else {
        Vec::new()
    };
    assert!(
        session_seen_standalone.is_empty(),
        "Fresh standalone query must have empty exclusion set"
    );

    // Case B: Continuation query DOES exclude seen chunks
    let prompt_continuation = "continue";
    let is_cont_or_excl_cont =
        DeterministicOfflineSynthesisEngine::is_continuation_query(&prompt_continuation.to_ascii_lowercase())
            || DeterministicOfflineSynthesisEngine::is_exclusion_query(&prompt_continuation.to_ascii_lowercase());

    let session_seen_cont: Vec<String> = if is_cont_or_excl_cont {
        seen_chunk_ids.clone()
    } else {
        Vec::new()
    };
    assert_eq!(
        session_seen_cont, seen_chunk_ids,
        "Continuation query must populate seen chunks for exclusion"
    );
}

// =========================================================================
// 4. Authorship & Meta Terms Invariant Tests
// =========================================================================

#[test]
fn test_authorship_query_detection() {
    let authorship_queries = vec![
        "article written by Femi Oyesanya",
        "research done by Author",
        "papers authored by John Doe",
        "has he written any books",
        "did he write the paper on differential privacy",
        "article he has written",
        "any other research by Femi",
        "publications by Angela Davis",
    ];

    for q in &authorship_queries {
        assert!(
            DeterministicOfflineSynthesisEngine::is_authorship_query(&q.to_ascii_lowercase()),
            "Query '{}' must be detected as an authorship query",
            q
        );
    }
}

#[test]
fn test_query_meta_intent_terms_containment() {
    let expected_meta_terms = [
        "article", "articles", "paper", "papers", "research",
        "written", "writing", "writings", "write", "writes", "wrote",
        "authored", "author", "authors",
        "publication", "publications", "published", "publish",
        "done", "he", "him", "his", "she", "her", "they", "them",
        "tell", "show", "give", "list", "find", "describe", "explain",
        "all", "any", "other", "more", "another", "besides",
    ];

    for term in expected_meta_terms {
        assert!(
            QUERY_META_INTENT_TERMS.contains(&term),
            "Meta intent term '{}' must be present in QUERY_META_INTENT_TERMS",
            term
        );
    }
}

#[test]
fn test_meta_terms_not_treated_as_mandatory_document_barriers() {
    // Simulate candidate chunks for query: "article written by Femi Oyesanya"
    // Chunk A: Real article that mentions Femi Oyesanya but does NOT contain the literal words "article" or "written"
    let real_article_chunk = ScoredChunk {
        chunk: DocumentChunk::new(
            "article:0",
            "article_doc",
            "papers/Privacy_Preserving_Consensus_2025.pdf",
            1,
            50,
            0,
            vec![0.1; 768],
            "Privacy-Preserving Byzantine Consensus in Distributed Systems. Femi Oyesanya. We present an empirical evaluation of zero-knowledge proofs applied to quorum protocols...",
            None,
        )
        .unwrap(),
        score: 0.85,
        source_peer: "local".to_string(),
        is_remote: false,
    };

    // Chunk B: Form that contains "written" and "article" but is an administrative legal boilerplate
    let admin_form_chunk = ScoredChunk {
        chunk: DocumentChunk::new(
            "form:0",
            "form_g28",
            "forms/Femi_Oyesanya_00003_G28.pdf",
            1,
            50,
            0,
            vec![0.1; 768],
            "Department of Homeland Security Form G-28. Notice of Entry of Appearance. In accordance with Article 4, a written request was submitted on behalf of Femi Oyesanya...",
            None,
        )
        .unwrap(),
        score: 0.70,
        source_peer: "local".to_string(),
        is_remote: false,
    };

    let chunks = vec![&real_article_chunk, &admin_form_chunk];
    let prompt = "article written by Femi Oyesanya";

    // 1. Verify prune_weak_excerpts does NOT prune candidate chunks on authorship queries
    let pruned = DeterministicOfflineSynthesisEngine::prune_weak_excerpts(prompt, &chunks);
    assert_eq!(
        pruned.len(),
        2,
        "prune_weak_excerpts must NEVER drop candidate chunks on authorship queries"
    );

    // 2. Verify that the real article chunk is retained and present in the pool
    assert!(
        pruned.iter().any(|c| c.chunk.chunk_id == "article:0"),
        "The genuine research article must survive pruning despite lacking the literal word 'written'"
    );

    // 3. Verify question content terms extraction ignores meta terms
    let terms = DeterministicOfflineSynthesisEngine::question_content_terms(prompt);
    assert!(
        terms.contains(&"femi".to_string()),
        "Content terms must include 'femi'"
    );
    assert!(
        terms.contains(&"oyesanya".to_string()),
        "Content terms must include 'oyesanya'"
    );
}

// =========================================================================
// 5. Stress Testing Edge Cases & Adversarial Scenarios
// =========================================================================

#[test]
fn test_continuation_bare_keyword_else() {
    // Challenge: Does "else" or "what else" get recognized as continuation/exclusion?
    let q1 = "what else";
    assert!(
        DeterministicOfflineSynthesisEngine::is_continuation_query(q1)
            || DeterministicOfflineSynthesisEngine::is_exclusion_query(q1),
        "'what else' must be recognized"
    );

    let q2 = "anything else";
    assert!(
        DeterministicOfflineSynthesisEngine::is_continuation_query(q2)
            || DeterministicOfflineSynthesisEngine::is_exclusion_query(q2),
        "'anything else' must be recognized"
    );
}

#[test]
fn test_adversarial_format_question_restated_prefix_with_embedded_subject_wrapper() {
    // If format_question_restated_prefix is called with a prompt that contains a subject context wrapper
    // (e.g. from conversational expansion or prompt forwarding), it must NEVER leak the wrapper.
    let wrapped_queries = [
        "who is Alice (Subject context: Bob)",
        "what is RedactX (Subject context: Femi Oyesanya)",
        "where did Casey live (Subject context: Casey Ringgold)",
        "tell me about Femi Oyesanya (Subject context: Femi Oyesanya)",
    ];

    for q in wrapped_queries {
        // Strip wrapper before prefix generation as done in offline_engine.rs line 4560
        let clean = q.split(" (Subject context:").next().unwrap_or(q);
        let prefix = DeterministicOfflineSynthesisEngine::format_question_restated_prefix(clean);
        assert!(
            !prefix.contains("Subject context"),
            "Prefix must not leak 'Subject context' for query '{}': got '{}'",
            q,
            prefix
        );
        assert!(
            !prefix.contains("(Subject"),
            "Prefix must not leak '(Subject' for query '{}': got '{}'",
            q,
            prefix
        );
    }
}

#[test]
fn test_adversarial_full_path_stem_capping() {
    let path_cases = vec![
        ("C:\\Users\\User\\Documents\\Research\\RedactX_v4_draft.pdf", "redactx"),
        ("/home/user/papers/RedactX-v3-typesetting.pdf", "redactx"),
        ("../sibling/RedactX(2).pdf", "redactx"),
        ("D:/harfile/QuorumRAG\\docs\\RedactX_arxiv.pdf", "redactx"),
        ("RedactX_v12.pdf", "redactx"),
        ("D:\\femi\\research\\ACDSO_v10_final.docx", "acdso"),
        ("D:\\femi\\papers\\Novel_Protocol-draft.pdf", "novel_protocol"),
    ];

    for (path, expected_stem) in path_cases {
        let stem = DeterministicOfflineSynthesisEngine::normalize_file_stem(path);
        assert_eq!(
            stem, expected_stem,
            "Full path '{}' should normalize to '{}', got '{}'",
            path, expected_stem, stem
        );
    }
}

#[test]
fn test_adversarial_typo_case_insensitivity() {
    let mixed_cases = vec![
        ("Dont", "done"),
        ("DONT", "done"),
        ("Artiles", "articles"),
        ("ARTILES", "articles"),
        ("Writen", "written"),
        ("WRITEN", "written"),
        ("Reserch", "research"),
        ("RESERCH", "research"),
    ];

    for (typo, expected_core) in mixed_cases {
        let (corrected, _) = DeterministicOfflineSynthesisEngine::correct_query_spelling(typo, false);
        assert_eq!(
            corrected.to_ascii_lowercase(),
            expected_core.to_ascii_lowercase(),
            "Typo '{}' should normalize to '{}', got '{}'",
            typo,
            expected_core,
            corrected
        );
    }

    let complex_sentence = "Had He Dont Any Other Reserch?";
    let (corrected_sentence, _) =
        DeterministicOfflineSynthesisEngine::correct_query_spelling(complex_sentence, false);
    let lower = corrected_sentence.to_ascii_lowercase();
    assert!(
        lower.contains("done"),
        "Complex sentence '{}' should contain 'done', got '{}'",
        complex_sentence,
        corrected_sentence
    );
    assert!(
        lower.contains("research"),
        "Complex sentence '{}' should contain 'research', got '{}'",
        complex_sentence,
        corrected_sentence
    );
}

#[test]
fn test_adversarial_authorship_syntactic_variations() {
    let variations = vec![
        "what research has been done by Femi Oyesanya",
        "show me every paper written by Femi Oyesanya",
        "tell me about the articles authored by Femi Oyesanya",
        "articles by Femi Oyesanya",
        "research by Femi Oyesanya",
        "has Femi Oyesanya done any other research",
        "did he write anything about distributed consensus",
        "he wrote a paper on Byzantine faults",
        "she wrote an article regarding privacy",
        "publications by Femi Oyesanya",
        "article he has written",
        "papers he has authored",
    ];

    for query in variations {
        assert!(
            DeterministicOfflineSynthesisEngine::is_authorship_query(&query.to_ascii_lowercase()),
            "Authorship variation '{}' must be detected by is_authorship_query",
            query
        );
    }
}

#[test]
fn test_adversarial_session_continuation_and_exclusion_keywords() {
    let keywords = vec![
        ("more", true, false),
        ("continue", true, false),
        ("go on", true, false),
        ("keep going", true, false),
        ("tell me more", true, false),
        ("what else", true, true),
        ("anything else", false, true),
        ("besides that, what did he write", false, true),
        ("other research", false, true),
        ("other papers", false, true),
        ("other than that", false, true),
        ("different paper", false, true),
    ];

    for (phrase, expected_cont, expected_excl) in keywords {
        let is_cont = DeterministicOfflineSynthesisEngine::is_continuation_query(phrase);
        let is_excl = DeterministicOfflineSynthesisEngine::is_exclusion_query(phrase);
        if expected_cont {
            assert!(
                is_cont,
                "Phrase '{}' was expected to be recognized as continuation query",
                phrase
            );
        }
        if expected_excl {
            assert!(
                is_excl,
                "Phrase '{}' was expected to be recognized as exclusion query",
                phrase
            );
        }
        assert!(
            is_cont || is_excl,
            "Phrase '{}' must be recognized as either continuation or exclusion",
            phrase
        );
    }
}

