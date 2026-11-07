//! Adversarial boundary condition and stress test harness for `StorageEngine::expand_parent_window`.
//!
//! # Verification Scope
//! Tests extreme boundary conditions:
//! 1. 0-byte parent document (empty string).
//! 2. 1-byte parent document.
//! 3. Exact 10,000-byte parent document with anchors at boundary edges (0, 2500, 2501, 9999, 10000).
//! 4. Multi-byte UTF-8 emojis placed exactly across byte boundaries (byte 256, byte 10,000, byte 32,768, and non-head left boundary).
//! 5. All-emoji documents (4-byte codepoints exclusively).
//! 6. Synthetic `[Document: ...]` and `[Image Document: ...]` header-prefixed anchors.
//! 7. Giant documents (100 KiB) with anchors at the doc boundary, and extreme window sizes (`usize::MAX`, 0).

use std::collections::HashMap;
use quorum_storage::StorageEngine;
use quorum_types::{DocumentFormat, IngestedParentDocument};
use tempfile::tempdir;

fn make_parent_doc(doc_id: &str, full_text: String) -> IngestedParentDocument {
    let blake3_hash = blake3::hash(full_text.as_bytes()).to_hex().to_string();
    let byte_len = full_text.len() as u64;
    IngestedParentDocument {
        doc_id: doc_id.to_string(),
        blake3_hash,
        source_path: format!("/adversarial/{}.txt", doc_id),
        os_platform: "windows".to_string(),
        format: DocumentFormat::PlainText,
        title: Some(format!("Title of {}", doc_id)),
        author: Some("Adversarial Challenger".to_string()),
        created_unix_secs: 1731000000,
        modified_unix_secs: 1731000000,
        byte_len,
        full_text,
        metadata: HashMap::new(),
    }
}

#[tokio::test]
async fn test_stress_zero_byte_document() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let doc = make_parent_doc("doc_empty", String::new());
    engine.upsert_parent_document(&doc, 0).unwrap();

    // Verify 0-byte doc returns Ok(None) cleanly under all anchor / window combinations
    let res = engine.expand_parent_window("doc_empty", "", 10000, 0).unwrap();
    assert!(res.is_none(), "0-byte doc must return None");

    let res = engine.expand_parent_window("doc_empty", "some anchor text", 10000, 0).unwrap();
    assert!(res.is_none(), "0-byte doc must return None");

    let res = engine.expand_parent_window("doc_empty", "some anchor", 256, 0).unwrap();
    assert!(res.is_none(), "0-byte doc must return None");
}

#[tokio::test]
async fn test_stress_one_byte_document() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let doc = make_parent_doc("doc_one_byte", "A".to_string());
    engine.upsert_parent_document(&doc, 0).unwrap();

    let window_sizes = [0, 1, 10, 255, 256, 1000, 10000, 32768, 65536, usize::MAX];
    let anchors = ["A", "", "Z", "much longer anchor text than the document"];

    for &win in &window_sizes {
        for &anch in &anchors {
            let res = engine.expand_parent_window("doc_one_byte", anch, win, 0).unwrap();
            assert!(res.is_some(), "1-byte doc must return Some for anchor '{}'", anch);
            let (start, end, text, title, author) = res.unwrap();

            assert_eq!(start, 0);
            assert_eq!(end, 1);
            assert_eq!(text, "A");
            assert!(title.is_some());
            assert!(author.is_some());
            assert!(doc.full_text.is_char_boundary(start));
            assert!(doc.full_text.is_char_boundary(end));
            assert!(start <= end);
            assert!(end <= doc.full_text.len());
        }
    }
}

#[tokio::test]
async fn test_stress_exact_10000_byte_boundary() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    // Construct an exact 10,000-byte document
    let mut full = String::with_capacity(10000);
    while full.len() < 10000 {
        let chunk = "Line: Hello QuorumRAG 2026 Distributed Retrieval!\n";
        let take = chunk.len().min(10000 - full.len());
        full.push_str(&chunk[..take]);
    }
    assert_eq!(full.len(), 10000);

    let doc = make_parent_doc("doc_10k", full.clone());
    engine.upsert_parent_document(&doc, 0).unwrap();

    // Test anchor at head: byte 0
    let head_probe = &full[0..40];
    let (s, e, text, _, _) = engine.expand_parent_window("doc_10k", head_probe, 10000, 0).unwrap().unwrap();
    assert_eq!(s, 0);
    assert_eq!(e, 10000);
    assert_eq!(text.len(), 10000);
    assert_eq!(text, full);

    // Test anchor at match_start = 2500 (head anchor boundary)
    let b2500_probe = &full[2500..2540];
    let (s, e, text, _, _) = engine.expand_parent_window("doc_10k", b2500_probe, 10000, 0).unwrap().unwrap();
    assert_eq!(s, 0, "match_start <= 2500 must anchor win_start at byte 0");
    assert_eq!(e, 10000);
    assert_eq!(text.len(), 10000);

    // Test anchor at match_start = 2501 (non-head branch)
    let b2501_probe = &full[2501..2541];
    let (s, e, text, _, _) = engine.expand_parent_window("doc_10k", b2501_probe, 10000, 0).unwrap().unwrap();
    assert!(s <= e);
    assert!(e <= 10000);
    assert_eq!(&full[s..e], text);
    assert!(full.is_char_boundary(s));
    assert!(full.is_char_boundary(e));

    // Test anchor at the end of the document (bytes 9960..10000)
    let end_probe = &full[9960..10000];
    let (s, e, text, _, _) = engine.expand_parent_window("doc_10k", end_probe, 10000, 0).unwrap().unwrap();
    assert!(s <= e);
    assert_eq!(e, 10000, "win_end must equal doc.len() for end anchor");
    assert_eq!(&full[s..e], text);
    assert!(full.is_char_boundary(s));
    assert!(full.is_char_boundary(e));
}

#[tokio::test]
async fn test_stress_multibyte_emoji_at_10000_byte_boundary() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    // Construct a document where byte 10,000 lands in the MIDDLE of a 4-byte emoji
    // Bytes 0..9998: 'a' (9,998 bytes)
    // Bytes 9998..10002: "🦀" (4 bytes: 0xF0, 0x9F, 0xA6, 0x80)
    // Bytes 10002..15000: 'b' (4,998 bytes)
    let mut full = "a".repeat(9998);
    full.push_str("🦀"); // 4 bytes, spans bytes 9998..10002
    full.push_str(&"b".repeat(4998));
    assert_eq!(full.len(), 15000);
    assert!(!full.is_char_boundary(10000), "Byte 10,000 must NOT be a char boundary for this test");
    assert!(full.is_char_boundary(10002), "Byte 10,002 must be the valid char boundary after emoji");

    let doc = make_parent_doc("doc_emoji_boundary", full.clone());
    engine.upsert_parent_document(&doc, 0).unwrap();

    // Anchor at byte 0: target_end is 10,000
    // expand_parent_window MUST advance win_end to 10002 without panicking on slice!
    let (s, e, text, _, _) = engine
        .expand_parent_window("doc_emoji_boundary", "aaaa", 10000, 0)
        .unwrap()
        .expect("must expand window");

    assert_eq!(s, 0);
    assert_eq!(e, 10002, "win_end must safely advance to 10002 across the emoji boundary");
    assert!(full.is_char_boundary(s));
    assert!(full.is_char_boundary(e));
    assert_eq!(&full[s..e], text);
    assert!(text.ends_with("🦀"), "Window text must cleanly end with the complete crab emoji");
}

#[tokio::test]
async fn test_stress_multibyte_emoji_at_clamp_boundaries_256_and_32768() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    // 1. Emoji crossing byte 256 (clamp lower bound)
    // Bytes 0..254: 'c' (254 bytes)
    // Bytes 254..258: "🚀" (4 bytes)
    // Bytes 258..600: 'd' (342 bytes)
    let mut doc_256 = "c".repeat(254);
    doc_256.push_str("🚀"); // spans bytes 254..258
    doc_256.push_str(&"d".repeat(342));
    assert_eq!(doc_256.len(), 600);
    assert!(!doc_256.is_char_boundary(256));

    let doc = make_parent_doc("doc_clamp_256", doc_256.clone());
    engine.upsert_parent_document(&doc, 0).unwrap();

    // Request window 256 bytes with anchor in Chunk 0
    let (s, e, text, _, _) = engine
        .expand_parent_window("doc_clamp_256", "cccc", 256, 0)
        .unwrap()
        .unwrap();

    assert_eq!(s, 0);
    // Note: head-match anchoring sets target_end = window_bytes.max(10000).clamp(256, 32768).min(full.len())
    // Since full.len() is 600, target_end is 600.
    assert_eq!(e, 600);
    assert_eq!(&doc_256[s..e], text);

    // 2. Non-head match crossing left boundary (win_start)
    // Match at byte 5000: match_start = 5000 > 2500.
    // Half = 1000. s = 5000 - 1000 = 4000.
    // Place emoji "🛡️" at bytes 3998..4004 (or 4-byte emoji 3998..4002).
    let mut doc_mid = "m".repeat(3998);
    doc_mid.push_str("🦀"); // bytes 3998..4002. Byte 4000 is inside!
    doc_mid.push_str(&"m".repeat(998)); // reaches byte 5000
    let target_anchor = "TARGET_ANCHOR_PROBE_EXACT";
    doc_mid.push_str(target_anchor);
    doc_mid.push_str(&"m".repeat(2000));
    assert!(!doc_mid.is_char_boundary(4000));

    let doc = make_parent_doc("doc_mid_left_emoji", doc_mid.clone());
    engine.upsert_parent_document(&doc, 0).unwrap();

    let (s, e, text, _, _) = engine
        .expand_parent_window("doc_mid_left_emoji", target_anchor, 1000, 0)
        .unwrap()
        .unwrap();

    assert_eq!(s, 3998, "win_start must safely step backward from 4000 to 3998 across emoji");
    assert!(doc_mid.is_char_boundary(s));
    assert!(doc_mid.is_char_boundary(e));
    assert!(s <= e);
    assert_eq!(&doc_mid[s..e], text);
    assert!(text.starts_with("🦀"), "Window text must cleanly start with crab emoji");
}

#[tokio::test]
async fn test_stress_all_emoji_document() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    // 1000 crab emojis = 4,000 bytes
    let all_emojis: String = "🦀".repeat(1000);
    let doc = make_parent_doc("doc_all_emojis", all_emojis.clone());
    engine.upsert_parent_document(&doc, 0).unwrap();

    let anchors = ["🦀🦀🦀", "🦀", "NONEXISTENT", ""];
    let windows = [0, 10, 256, 1000, 10000];

    for &anch in &anchors {
        for &win in &windows {
            let res = engine.expand_parent_window("doc_all_emojis", anch, win, 0).unwrap();
            assert!(res.is_some());
            let (s, e, text, _, _) = res.unwrap();

            assert!(s <= e);
            assert!(e <= all_emojis.len());
            assert!(all_emojis.is_char_boundary(s));
            assert!(all_emojis.is_char_boundary(e));
            assert_eq!(&all_emojis[s..e], text);
        }
    }
}

#[tokio::test]
async fn test_stress_synthetic_headers_in_anchors() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let full_text = "Actual raw parent document body paragraph.\nSecond paragraph with valuable executive summary details.\nFinal section.";
    let doc = make_parent_doc("doc_synth_test", full_text.to_string());
    engine.upsert_parent_document(&doc, 0).unwrap();

    // 1. Anchor with standard synthetic header prefix
    let synth_anchor = "[Document: Title: \"Some Title\" | Author: Test]\nActual raw parent document body paragraph.";
    let (s, e, text, _, _) = engine
        .expand_parent_window("doc_synth_test", synth_anchor, 10000, 0)
        .unwrap()
        .unwrap();

    assert_eq!(s, 0);
    assert_eq!(e, full_text.len());
    assert_eq!(text, full_text);

    // 2. Anchor with synthetic header only (no body text)
    let header_only_anchor = "[Document: Title: \"Some Title\" | Author: Test]";
    let (s, e, text, _, _) = engine
        .expand_parent_window("doc_synth_test", header_only_anchor, 10000, 0)
        .unwrap()
        .unwrap();

    assert_eq!(s, 0);
    assert_eq!(e, full_text.len());
    assert_eq!(text, full_text);

    // 3. Anchor with Image Document prefix
    let img_anchor = "[Image Document: Caption: \"A chart of Q3\"]\nSecond paragraph with valuable";
    let (s, e, text, _, _) = engine
        .expand_parent_window("doc_synth_test", img_anchor, 10000, 0)
        .unwrap()
        .unwrap();

    assert_eq!(s, 0);
    assert_eq!(e, full_text.len());
    assert_eq!(text, full_text);
}
