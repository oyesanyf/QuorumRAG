//! Adversarial Stress Tests for QuorumRAG Google Magika Classifier.
//!
//! Evaluates classifier resilience against corrupt headers, polyglots,
//! binary/text hybrids, high-entropy byte streams, truncated magic headers,
//! and unicode edge cases.

use quorum_classifier::{FileCategory, FileTypeClassifier};
use tempfile::NamedTempFile;

#[test]
fn test_zero_byte_inputs() {
    let classifier = FileTypeClassifier::new();

    // 1. Zero-byte buffer without filename hint
    let id_empty = classifier.classify_bytes(&[], None);
    assert_eq!(id_empty.label, "empty");
    assert_eq!(id_empty.mime_type, "application/x-empty");
    assert_eq!(id_empty.category, FileCategory::Text);
    assert!(id_empty.is_text);
    assert!(!id_empty.is_binary);

    // 2. Zero-byte buffer with various filename hints
    let id_rs = classifier.classify_bytes(&[], Some("main.rs"));
    assert_eq!(id_rs.label, "rust");
    assert!(id_rs.is_text);

    let id_exe = classifier.classify_bytes(&[], Some("payload.exe"));
    assert_eq!(id_exe.label, "pebin");
    assert!(id_exe.is_binary);

    let id_pdf = classifier.classify_bytes(&[], Some("doc.pdf"));
    assert_eq!(id_pdf.label, "pdf");
    assert!(id_pdf.is_binary);

    // 3. Zero-byte physical file on disk with known text extension (.txt)
    let temp_txt = tempfile::Builder::new().suffix(".txt").tempfile().expect("Failed to create temp txt file");
    let file_id_txt = classifier.classify_file(temp_txt.path()).expect("Failed to classify empty txt file");
    assert_eq!(file_id_txt.label, "txt");
    assert!(file_id_txt.is_text);

    // 4. Zero-byte physical file on disk with unknown extension
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let file_id = classifier.classify_file(temp_file.path()).expect("Failed to classify empty file");
    // Under current implementation, an empty file with unknown extension delegates to classify_by_extension which returns unknown binary
    assert_eq!(file_id.label, "unknown");
    assert!(file_id.is_binary);

}

#[test]
fn test_single_byte_and_boundary_slices() {
    let classifier = FileTypeClassifier::new();

    // Slices from 1 byte to 16 bytes containing partial magic markers
    let partials: Vec<&[u8]> = vec![
        b"M",
        b"P",
        b"\x7f",
        b"\x1f",
        b"R",
        b"S",
        b"%",
        b"#",
        b"{",
        b"[",
        b"<",
        b"-",
        b"MZ",
        b"PK",
        b"\x7fE",
        b"\x7fEL",
        b"%PD",
        b"%PDF",
        b"\0as",
        b"GIF",
        b"RIFF",
        b"fLa",
        b"Ogg",
        b"ID3",
        b"37",
        b"7z",
    ];

    for partial in partials {
        // Must never panic and must classify cleanly
        let id = classifier.classify_bytes(partial, None);
        assert!(!id.label.is_empty(), "Empty label for partial {:?}", partial);
        // is_text and is_binary must be strict inverses
        assert_eq!(id.is_text, !id.is_binary);
    }
}

#[test]
fn test_macho_and_java_class_boundary_lengths() {
    let classifier = FileTypeClassifier::new();

    // 0xcafebabe can be Mach-O Fat Universal binary or Java Class file depending on length and bytes 6..8
    let cafebabe = [0xca, 0xfe, 0xba, 0xbe];
    let id4 = classifier.classify_bytes(&cafebabe, None);
    assert_eq!(id4.label, "macho");
    assert!(id4.is_binary);

    // 5, 6, 7 bytes with 0xcafebabe
    let id5 = classifier.classify_bytes(&[0xca, 0xfe, 0xba, 0xbe, 0x00], None);
    assert_eq!(id5.label, "macho");

    let id7 = classifier.classify_bytes(&[0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00], None);
    assert_eq!(id7.label, "macho");

    // 8 bytes with major version 52 (Java 8 class file)
    let java_bytes = [0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 52];
    let id_java = classifier.classify_bytes(&java_bytes, None);
    assert_eq!(id_java.label, "class");
    assert_eq!(id_java.mime_type, "application/java-vm");
    assert!(id_java.is_binary);

    // 8 bytes with major version outside 45..=70 -> should classify as Mach-O
    let macho_bytes = [0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 10];
    let id_macho = classifier.classify_bytes(&macho_bytes, None);
    assert_eq!(id_macho.label, "macho");
    assert!(id_macho.is_binary);
}

#[test]
fn test_tar_boundary_lengths() {
    let classifier = FileTypeClassifier::new();

    // TAR requires 'ustar' at offset 257 (total length >= 262)
    let mut buf = vec![0u8; 261];
    buf[257..261].copy_from_slice(b"usta");
    let id_short = classifier.classify_bytes(&buf, None);
    assert_ne!(id_short.label, "tar");

    let mut buf262 = vec![0u8; 262];
    buf262[257..262].copy_from_slice(b"ustar");
    let id_tar = classifier.classify_bytes(&buf262, None);
    assert_eq!(id_tar.label, "tar");
    assert_eq!(id_tar.category, FileCategory::Archive);
    assert!(id_tar.is_binary);
}

#[test]
fn test_polyglot_and_hybrid_files() {
    let classifier = FileTypeClassifier::new();

    // Polyglot 1: JPEG header followed by ZIP archive structure
    let mut jpeg_zip = vec![0xff, 0xd8, 0xff, 0xe0];
    jpeg_zip.extend_from_slice(b"PK\x03\x04\x14\x00\x00\x00word/document.xml");
    let id_jpeg_zip = classifier.classify_bytes(&jpeg_zip, None);
    assert_eq!(id_jpeg_zip.label, "jpeg");
    assert_eq!(id_jpeg_zip.category, FileCategory::Image);
    assert!(id_jpeg_zip.is_binary);

    // Polyglot 2: PE MZ header followed by valid Rust source code
    let mut pe_rust = b"MZ\x90\x00\x03\x00".to_vec();
    pe_rust.extend_from_slice(b"\r\npub fn main() { println!(\"hello\"); }\r\n");
    let id_pe_rust = classifier.classify_bytes(&pe_rust, Some("tricky.rs"));
    // Header inspection precedes text inspection, so MZ must be identified as executable
    assert_eq!(id_pe_rust.label, "pebin");
    assert_eq!(id_pe_rust.category, FileCategory::Executable);
    assert!(id_pe_rust.is_binary);
    assert!(!id_pe_rust.is_text);

    // Polyglot 3: GIF header prepended to HTML
    let mut gif_html = b"GIF89a\x01\x00\x01\x00".to_vec();
    gif_html.extend_from_slice(b"<html><body><h1>Evil payload</h1></body></html>");
    let id_gif_html = classifier.classify_bytes(&gif_html, Some("image.php"));
    assert_eq!(id_gif_html.label, "gif");
    assert_eq!(id_gif_html.category, FileCategory::Image);
    assert!(id_gif_html.is_binary);
}

#[test]
fn test_null_byte_binary_detection_at_boundaries() {
    let classifier = FileTypeClassifier::new();

    // 1. Text with null byte at offset 0
    let mut buf = b"Hello world this is plain text".to_vec();
    buf[0] = 0x00;
    let id0 = classifier.classify_bytes(&buf, None);
    assert!(id0.is_binary);

    // 2. Text with null byte at offset 500
    let mut buf500 = vec![b'a'; 1500];
    buf500[500] = 0x00;
    let id500 = classifier.classify_bytes(&buf500, None);
    assert!(id500.is_binary);

    // 3. Text with null byte at offset 1023 (within first 1024 bytes)
    let mut buf1023 = vec![b'a'; 2000];
    buf1023[1023] = 0x00;
    let id1023 = classifier.classify_bytes(&buf1023, None);
    assert!(id1023.is_binary);

    // 4. Text with null byte at offset 1024 (beyond first 1024 bytes)
    let mut buf1024 = vec![b'a'; 2000];
    buf1024[1024] = 0x00;
    let id1024 = classifier.classify_bytes(&buf1024, None);
    assert!(!id1024.label.is_empty());
}

#[test]
fn test_high_entropy_random_byte_stream() {
    let classifier = FileTypeClassifier::new();

    // Generate 4096 pseudo-random bytes using deterministic XorShift64
    let mut state: u64 = 0xDEADBEEFCAFE1234;
    let mut random_stream = vec![0u8; 4096];
    for chunk in random_stream.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let bytes = state.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }

    let id = classifier.classify_bytes(&random_stream, None);
    assert!(id.is_binary, "High entropy random stream must be classified as binary");
    assert!(!id.is_text);
    assert_eq!(id.category, FileCategory::Unknown);
    assert_eq!(id.mime_type, "application/octet-stream");
}

#[test]
fn test_invalid_utf8_byte_sequences() {
    let classifier = FileTypeClassifier::new();

    // 1. Overlong 2-byte sequence for ASCII 'A' (0xC0 0xBF)
    let invalid_overlong = [0xC0, 0xAF, b'h', b'e', b'l', b'l', b'o'];
    let id_overlong = classifier.classify_bytes(&invalid_overlong, None);
    assert!(!id_overlong.label.is_empty());

    // 2. Dangling continuation bytes
    let invalid_dangling = [0x80, 0x81, 0x82, 0x83, 0x84];
    let id_dangling = classifier.classify_bytes(&invalid_dangling, None);
    assert!(!id_dangling.label.is_empty());

    // 3. Truncated 4-byte sequence
    let truncated_4byte = [0xF0, 0x90, 0x80];
    let id_trunc = classifier.classify_bytes(&truncated_4byte, None);
    assert!(!id_trunc.label.is_empty());

    // 4. Sequence with 0xFF bytes
    let ff_bytes = [0xFF, 0xFF, 0xFF, 0xFF];
    let id_ff = classifier.classify_bytes(&ff_bytes, None);
    assert!(!id_ff.label.is_empty());
}

#[test]
fn test_shebang_adversarial_variations() {
    let classifier = FileTypeClassifier::new();

    // Empty shebang
    let id1 = classifier.classify_bytes(b"#!\n", None);
    assert!(id1.is_text);

    // Shebang with huge space padding
    let mut huge_shebang = b"#!".to_vec();
    huge_shebang.extend(vec![b' '; 500]);
    huge_shebang.extend_from_slice(b"/usr/bin/env python3\nprint('hello')\n");
    let id2 = classifier.classify_bytes(&huge_shebang, None);
    assert_eq!(id2.label, "python");
    assert_eq!(id2.category, FileCategory::Code);
    assert!(id2.is_text);

    // Shebang with null byte inside line -> should fail-closed to binary
    let shebang_null = b"#! /usr/bin/python\0exec\nprint('hi')";
    let id3 = classifier.classify_bytes(shebang_null, None);
    assert!(id3.is_binary);
}

#[test]
fn test_directory_and_nonexistent_paths() {
    let classifier = FileTypeClassifier::new();

    // 1. Existing directory
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let dir_id = classifier.classify_file(temp_dir.path()).expect("classify directory");
    assert_eq!(dir_id.label, "directory");
    assert_eq!(dir_id.mime_type, "inode/directory");
    assert!(!dir_id.is_text);

    // 2. Non-existent path returns std::io::Error
    let non_existent = temp_dir.path().join("does_not_exist_at_all.xyz");
    let err = classifier.classify_file(non_existent);
    assert!(err.is_err());
}

#[test]
fn test_cjk_multibyte_utf8_sliced_at_512_bytes() {
    let classifier = FileTypeClassifier::new();

    // Chinese characters are 3 bytes each in UTF-8.
    // 170 characters * 3 bytes = 510 bytes.
    // The 171st character starts at byte 510, with bytes 510, 511, 512.
    // When is_high_entropy_binary slices at ..512, byte 512 is omitted, leaving bytes 510 and 511 of a 3-byte char.
    // Let's create a valid UTF-8 string containing 200 Chinese characters (600 bytes total).
    let mut cjk_text = String::new();
    for _ in 0..200 {
        cjk_text.push('测'); // U+6D4B is 3 bytes: 0xE6 0xB5 0x8B
    }
    let cjk_bytes = cjk_text.as_bytes();
    assert_eq!(cjk_bytes.len(), 600);
    assert!(std::str::from_utf8(cjk_bytes).is_ok());

    let id = classifier.classify_bytes(cjk_bytes, None);
    assert!(
        id.is_text,
        "Valid UTF-8 CJK text of 600 bytes was falsely classified as binary! label={}, is_binary={}",
        id.label, id.is_binary
    );
}

