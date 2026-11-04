//! Tests for Milestone M7 Fast-Path Compiled Binary Exclusion & Sharing Violation Retries.

use quorum_classifier::{
    is_binary_executable_extension, FileCategory, FileTypeClassifier, COMPILED_BINARY_EXTENSIONS,
};
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_fast_path_binary_extensions_all_mapped() {
    let classifier = FileTypeClassifier::new();

    // Verify all 29 compiled binary extensions
    assert_eq!(COMPILED_BINARY_EXTENSIONS.len(), 29);

    for &ext in COMPILED_BINARY_EXTENSIONS {
        // Must match helper function with or without leading dot
        assert!(
            is_binary_executable_extension(ext),
            "Extension '{}' failed is_binary_executable_extension",
            ext
        );
        let with_dot = format!(".{}", ext);
        assert!(
            is_binary_executable_extension(&with_dot),
            "Extension '{}' failed with leading dot",
            with_dot
        );

        // Must classify to FileCategory::Executable with is_text = false and is_binary = true
        let fake_filename = format!("sample.{}", ext);
        let id = classifier.classify_by_extension(&fake_filename, 1.0);
        assert_eq!(
            id.category,
            FileCategory::Executable,
            "Extension '{}' did not map to FileCategory::Executable: {:?}",
            ext,
            id.category
        );
        assert!(
            !id.is_text,
            "Extension '{}' incorrectly marked as is_text",
            ext
        );
        assert!(
            id.is_binary,
            "Extension '{}' not marked as is_binary",
            ext
        );
    }
}

#[test]
fn test_open_file_with_retry_succeeds_on_normal_file() {
    let mut temp = NamedTempFile::new().unwrap();
    writeln!(temp, "Hello QuorumRAG M7").unwrap();

    let file = FileTypeClassifier::open_file_with_retry(temp.path());
    assert!(file.is_ok(), "Failed to open normal file with retry");
}

#[test]
fn test_open_file_with_retry_fails_cleanly_on_missing_file() {
    let non_existent = std::path::Path::new("Z:\\nonexistent_m7_test_file.xyz");
    let res = FileTypeClassifier::open_file_with_retry(non_existent);
    assert!(res.is_err(), "Expected error for missing file");
}

#[test]
fn test_audio_extensions_classified_and_not_binary_executable() {
    let classifier = FileTypeClassifier::new();
    let audio_exts = [
        "mp3", "wav", "flac", "ogg", "m4a", "aac", "wma", "aiff", "aif", "opus",
    ];

    for ext in audio_exts {
        assert!(
            !is_binary_executable_extension(ext),
            "Audio extension '{}' must NOT be classified as executable binary",
            ext
        );
        let filename = format!("track.{}", ext);
        let id = classifier.classify_by_extension(&filename, 1.0);
        assert_eq!(
            id.category,
            FileCategory::Audio,
            "Audio extension '{}' did not map to FileCategory::Audio",
            ext
        );
    }
}

#[test]
fn test_image_extensions_classified_and_not_binary_executable() {
    let classifier = FileTypeClassifier::new();
    let image_exts = [
        "png", "jpg", "jpeg", "webp", "gif", "bmp", "svg", "tiff", "tif", "ico", "avif", "heic",
    ];

    for ext in image_exts {
        assert!(
            !is_binary_executable_extension(ext),
            "Image extension '{}' must NOT be classified as executable binary",
            ext
        );
        let filename = format!("picture.{}", ext);
        let id = classifier.classify_by_extension(&filename, 1.0);
        assert_eq!(
            id.category,
            FileCategory::Image,
            "Image extension '{}' did not map to FileCategory::Image",
            ext
        );
    }
}
