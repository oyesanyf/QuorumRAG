//! Empirical Challenger Stress Tests: Multi-byte UTF-8 Corner Cases for Google Magika Classifier.
//!
//! Evaluates classifier resilience against 4-byte emojis, RTL Arabic, Cyrillic, Devanagari,
//! zero-width codepoints, and truncation at the exact 512-byte sample boundary.

use quorum_classifier::{FileCategory, FileTypeClassifier};

#[test]
fn test_4byte_emoji_truncation_at_512_boundary_all_offsets() {
    let classifier = FileTypeClassifier::new();

    // 4-byte emojis: 🦀 U+1F980, 🚀 U+1F680, 🔥 U+1F525, 💎 U+1F48E
    // We want to test cutting into a 4-byte emoji at byte offset 1, 2, and 3 when sample is sliced at 512.
    // 127 emojis = 508 bytes.
    // Adding 0, 1, 2, 3 ASCII padding bytes shifts the 128th emoji across the 512 boundary.
    for padding_len in 0..=4 {
        let mut text = String::new();
        // 127 emojis = 508 bytes
        for _ in 0..127 {
            text.push('🦀');
        }
        // Add padding
        text.push_str(&"x".repeat(padding_len));
        // Add more emojis to guarantee length > 512
        for _ in 0..20 {
            text.push('🚀');
        }

        let bytes = text.as_bytes();
        assert!(bytes.len() > 512);

        // Classification must not panic and must correctly classify as text, not binary
        let id = classifier.classify_bytes(bytes, None);
        assert!(
            id.is_text,
            "4-byte emoji text with padding {} failed! label={}, is_binary={}",
            padding_len, id.label, id.is_binary
        );
        assert!(!id.is_binary);
    }
}

#[test]
fn test_arabic_rtl_multibyte_utf8_classification() {
    let classifier = FileTypeClassifier::new();

    // Arabic text (2 bytes per character in UTF-8)
    let arabic = "مرحبا بالعالم هذا اختبار لنظام استرجاع المعلومات واستخراج النصوص باللغة العربية بدقة متناهية ودون أخطاء.";
    let mut text = String::new();
    while text.len() < 1000 {
        text.push_str(arabic);
        text.push(' ');
    }

    let bytes = text.as_bytes();
    let id = classifier.classify_bytes(bytes, None);

    assert!(id.is_text, "Arabic text was falsely marked as binary! label={}", id.label);
    assert!(!id.is_binary);
    assert_eq!(id.category, FileCategory::Text);
}

#[test]
fn test_cyrillic_multibyte_utf8_classification() {
    let classifier = FileTypeClassifier::new();

    // Cyrillic Russian text (2 bytes per char in UTF-8)
    let russian = "Привет, мир! Это тестовый документ на русском языке для проверки корректности классификатора.";
    let mut text = String::new();
    while text.len() < 1000 {
        text.push_str(russian);
        text.push('\n');
    }

    let bytes = text.as_bytes();
    let id = classifier.classify_bytes(bytes, None);

    assert!(id.is_text, "Cyrillic text was falsely marked as binary! label={}", id.label);
    assert!(!id.is_binary);
}

#[test]
fn test_devanagari_hindi_multibyte_utf8_classification() {
    let classifier = FileTypeClassifier::new();

    // Devanagari Hindi text (3 bytes per char in UTF-8)
    let hindi = "नमस्ते दुनिया! यह एक परीक्षण दस्तावेज़ है जो यह सुनिश्चित करता है कि मल्टी-बाइट यूटीएफ़-8 वर्ण सही ढंग से पहचाने जाते हैं।";
    let mut text = String::new();
    while text.len() < 1000 {
        text.push_str(hindi);
        text.push('\n');
    }

    let bytes = text.as_bytes();
    let id = classifier.classify_bytes(bytes, None);

    assert!(id.is_text, "Hindi text was falsely marked as binary! label={}", id.label);
    assert!(!id.is_binary);
}

#[test]
fn test_polyglot_multibyte_code_with_shebang() {
    let classifier = FileTypeClassifier::new();

    // Python script with shebang, Japanese docstring, Arabic comment, emojis
    let code = r#"#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
これは日本語のドキュメント文字列です。
مرحبا بكم في كود بايثون
🦀🚀🔥
"""
import sys

def main():
    print("こんにちは世界")
    sys.exit(0)

if __name__ == "__main__":
    main()
"#;

    let id = classifier.classify_bytes(code.as_bytes(), None);
    assert_eq!(id.label, "python");
    assert!(id.is_text);
    assert_eq!(id.category, FileCategory::Code);
}

#[test]
fn test_rust_code_with_cjk_and_emojis() {
    let classifier = FileTypeClassifier::new();

    let rust_code = r#"
/// 🦀 高性能检索增强生成系统 (High performance RAG system)
/// 
/// 支持多语言文本：
/// - 中文：你好，世界！
/// - 日本語：こんにちは世界
/// - 한국어: 안녕하세요 세계
pub fn process_multibyte_tokens() -> Result<(), String> {
    let text = "🚀🔥";
    println!("{}", text);
    Ok(())
}
"#;

    let id = classifier.classify_bytes(rust_code.as_bytes(), Some("lib.rs"));
    assert_eq!(id.label, "rust");
    assert!(id.is_text);
    assert_eq!(id.category, FileCategory::Code);
}

#[test]
fn test_unicode_special_spaces_and_zero_width_chars() {
    let classifier = FileTypeClassifier::new();

    // Zero-width space (U+200B), zero-width joiner (U+200D), non-breaking space (U+00A0)
    let mut special_text = "This is a document with zero-width characters: \u{200B}\u{200C}\u{200D}\u{00A0}.".repeat(50);
    special_text.push_str(" Valid document body continues.");

    let id = classifier.classify_bytes(special_text.as_bytes(), None);
    assert!(id.is_text);
    assert!(!id.is_binary);
}

#[test]
fn test_overlong_and_corrupt_utf8_fails_closed_safely() {
    let classifier = FileTypeClassifier::new();

    // Construct buffer with overlong UTF-8 bytes and high non-printable byte ratio
    let mut corrupt = vec![0xC0, 0xAF]; // Overlong ASCII '/'
    corrupt.extend_from_slice(&[0xFF, 0xFE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    corrupt.extend(vec![0xAA; 500]);

    let id = classifier.classify_bytes(&corrupt, None);
    // Should classify as binary without panic
    assert!(id.is_binary);
    assert!(!id.is_text);
}
