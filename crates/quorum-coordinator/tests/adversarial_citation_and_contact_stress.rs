//! Adversarial stress test harness for `RlmOrchestrator::verify_and_attach_verbatim_grounding`,
//! `safe_truncate_str`, and `answer_orchestrator::is_contact_bar_or_header`.
//!
//! # Verification Scope
//! Tests extreme edge cases:
//! 1. Verbatim quote extraction across multi-byte UTF-8 boundaries (emojis, CJK, Cyrillic, Arabic).
//! 2. Strings exceeding 260 bytes where byte 260 splits a 4-byte UTF-8 emoji.
//! 3. Grounding invariant: `raw_source.contains(&quote)` MUST hold 100% of the time.
//! 4. Byte spans: `abs_start + quote.len() == abs_end` and `&raw_parent[abs_start..abs_end] == quote`.
//! 5. Contact bar filtering matrix: zero false positives on legitimate prose; zero false negatives on contact headers.

use quorum_coordinator::answer_orchestrator::is_contact_bar_or_header;
use quorum_coordinator::rlm_orchestrator::RlmOrchestrator;
use quorum_types::{DocumentChunk, ScoredChunk};

#[test]
fn test_adversarial_contact_bar_matrix() {
    // True positives: MUST be recognized as contact bars or headers
    let contact_bars = [
        "Femi Oyesanya | Atlanta, GA | femi@example.com | (404) 555-0199",
        "John Doe • Senior Architect • Seattle, WA • jdoe@amazon.com",
        "Email: support@quorumrag.io | Phone: +1-800-555-0100",
        "Phone: 404-555-0199",
        "Tel: +1 (555) 234-5678",
        "Mobile: 555-0199 | Office: 555-0198",
        "femi.oyesanya@cybersecurity-research.org | linkedin.com/in/fomioyesanya",
        "Address: 100 Main St | Suite 400 | Atlanta GA 30303",
        "P.O. Box 1234, Atlanta, GA 30301 | info@example.com",
        "Telephone: (404) 555-1212",
        "Contact Info: jdoe@example.com",
        "Location: Greater Atlanta Area | Portfolio: https://github.com/example",
    ];

    for bar in contact_bars {
        assert!(
            is_contact_bar_or_header(bar),
            "Expected contact bar detection for: '{}'",
            bar
        );
    }

    // False positive prevention: Legitimate sentences MUST NOT be recognized as contact bars
    let legitimate_prose = [
        "Femi Oyesanya is a Distinguished Enterprise Information Security Architect and Cyber Defense Leader.",
        "The team researched automated defenses against spear phishing emails and credential harvesting.",
        "Engineered zero-trust architectures and post-quantum cryptographic enclaves across financial infrastructure.",
        "The mobile phone application was tested against distributed denial of service attacks.",
        "Prior to joining the cybersecurity institute, he led large-scale cloud transformations across distributed systems.",
        "Recognized for authoring novel decentralized quorum consensus protocols and Byzantine telemetry networks.",
        "Received a Bachelor of Science in Computer Science from the University of Ibadan.",
        "Demonstrated a 99.8% reduction in unauthorized egress attempts through hardware-enforced isolation.",
    ];

    for prose in legitimate_prose {
        assert!(
            !is_contact_bar_or_header(prose),
            "Legitimate prose must NOT be flagged as contact bar: '{}'",
            prose
        );
    }
}

#[test]
fn test_adversarial_verbatim_extraction_with_multibyte_emojis_at_boundary() {
    // Construct a line with > 260 bytes where byte 260 falls in the middle of a 4-byte emoji
    // 258 ASCII bytes + 4-byte emoji 🦀 (0xF0 0x9F 0xA6 0x80) + trailing text
    let mut line = "Enterprise zero-trust architecture requires continuous verification of sovereign identity tokens. ".repeat(2);
    // line is currently ~198 bytes
    line.push_str("Additional context: ");
    while line.len() < 258 {
        line.push('x');
    }
    assert_eq!(line.len(), 258);
    line.push_str("🦀 Critical security finding in post-quantum enclave.");
    assert!(!line.is_char_boundary(260));

    let prompt = "What is the critical security finding?";
    let answer = "The enterprise zero-trust architecture identified a critical security finding.";

    let res = RlmOrchestrator::extract_best_verbatim_span(prompt, answer, &line);
    assert!(res.is_some(), "Must extract best verbatim span");
    let (quote, start, end, overlap) = res.unwrap();

    assert!(overlap > 0);
    assert_eq!(end - start, quote.len());
    assert!(line.contains(&quote), "Extracted quote MUST be a literal substring of line");
    assert_eq!(&line[start..end], quote);
    assert!(line.is_char_boundary(start));
    assert!(line.is_char_boundary(end));
    assert!(quote.len() <= 260, "Quote length must be clamped to <= 260 bytes");
}

#[test]
fn test_adversarial_cjk_arabic_verbatim_grounding() {
    let raw_source = "量子暗号化とゼロトラスト防御ネットワークの検証。\n\
                      شبكة الدفاع السيبراني اللامركزية عبر العقد الموزعة.\n\
                      Autonomous Byzantine-fault-tolerant telemetry and post-quantum ML-KEM migration framework.";

    let prompt = "How does the post-quantum ML-KEM migration framework work?";
    let answer = "The system uses an autonomous Byzantine-fault-tolerant telemetry and post-quantum ML-KEM migration framework.";

    let chunk = DocumentChunk::new(
        "chunk_intl_1",
        "doc_intl_1",
        "/intl/security.txt",
        1,
        3,
        0,
        vec![0.0; 768],
        raw_source,
        Some("{\"parent_window_start_byte\":0,\"parent_window_end_byte\":250}".to_string()),
    )
    .unwrap();

    let scored = ScoredChunk::new(chunk, 0.95, "local", false);
    let mut citations = vec![scored.to_citation()];
    let refs = [&scored];

    RlmOrchestrator::verify_and_attach_verbatim_grounding(prompt, answer, &refs, &mut citations);

    assert_eq!(citations.len(), 1);
    let cit = &citations[0];
    assert!(cit.verbatim_quote.is_some(), "Citation must have verbatim quote attached");
    let quote = cit.verbatim_quote.as_ref().unwrap();

    assert!(raw_source.contains(quote), "Verbatim quote MUST be contained in raw_source");
    assert!(cit.byte_range.is_some());
    let (abs_start, abs_end) = cit.byte_range.unwrap();
    assert_eq!(abs_end - abs_start, quote.len());
    assert_eq!(&raw_source[abs_start..abs_end], quote);
}

#[test]
fn test_adversarial_synthetic_header_offset_alignment() {
    let parent_body = "Distinguished Enterprise Information Security Architect and Cyber Defense Leader with over 15 years experience.";
    let synthetic_header = "[Document: Title: \"Femi Oyesanya Resume\" | Author: Femi Oyesanya]\n";
    let text_content = format!("{}{}", synthetic_header, parent_body);

    let base_parent_offset = 1200usize; // Say parent window started at byte 1200 in raw doc

    let meta = format!(
        "{{\"parent_window_start_byte\":{},\"parent_window_end_byte\":{}}}",
        base_parent_offset,
        base_parent_offset + parent_body.len()
    );

    let chunk = DocumentChunk::new(
        "chunk_synth_1",
        "doc_synth_1",
        "/docs/resume.docx",
        1,
        2,
        0,
        vec![0.0; 768],
        &text_content,
        Some(meta),
    )
    .unwrap();

    let scored = ScoredChunk::new(chunk, 0.99, "local", false);
    let mut citations = vec![scored.to_citation()];
    let refs = [&scored];

    let prompt = "Who is Femi Oyesanya?";
    let answer = "Femi Oyesanya is a Distinguished Enterprise Information Security Architect and Cyber Defense Leader.";

    RlmOrchestrator::verify_and_attach_verbatim_grounding(prompt, answer, &refs, &mut citations);

    assert_eq!(citations.len(), 1);
    let cit = &citations[0];
    let quote = cit.verbatim_quote.as_ref().expect("verbatim quote attached");

    // Invariant 1: Quote is a literal substring of text_content
    assert!(text_content.contains(quote));

    // Invariant 2: Quote does NOT contain the synthetic header
    assert!(!quote.contains("[Document:"));

    // Invariant 3: Quote is a literal substring of parent_body
    assert!(parent_body.contains(quote));

    // Invariant 4: Adjusted abs_start and abs_end match parent doc offset
    let (abs_start, abs_end) = cit.byte_range.expect("byte range attached");
    let rel_offset_in_parent_body = parent_body.find(quote).expect("found in body");

    assert_eq!(abs_start, base_parent_offset + rel_offset_in_parent_body);
    assert_eq!(abs_end, abs_start + quote.len());
}
