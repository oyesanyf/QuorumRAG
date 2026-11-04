//! Google Magika Content Classifier Router & Binary Filter.
//!
//! # Core Invariants:
//! 1. DO NOT SKIP IMAGES! Images (`png`, `jpeg`, `webp`, `gif`, `bmp`, `tiff`, `svg`, etc.)
//!    must be routed to `CandidateKind::Image` for rich metadata and feature indexing.
//! 2. Text, source code, and documents route to `CandidateKind::Text` for chunking.
//! 3. Compiled binaries (PE, ELF, Mach-O, WASM), archives, and audio/video are filtered out.
//! 4. Files exceeding the configured size cap (default: 50MB) are rejected.
//! 5. 0-byte files are accepted as text with 0 chunks without panic.

use std::path::Path;
use quorum_classifier::{FileCategory, FileIdentity, FileTypeClassifier};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::config::IngestConfig;

/// Classified candidate destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateKind {
    /// Text, code, or structured document -> routed to Chunker -> Gemma Embedder.
    Text {
        char_count_estimate: usize,
    },
    /// Image file -> routed to ImageIndexer (dimensions, EXIF, tokens, visual summary).
    Image {
        format_label: String,
        mime_type: String,
    },
    /// Audio file -> routed to AudioIndexer (ID3 tags, MPEG frame sync, lyrics, track info).
    Audio {
        format_label: String,
        mime_type: String,
    },
}

/// Filter decision with explicit audit rationale.
#[derive(Debug, Clone, PartialEq)]
pub enum FilterDecision {
    /// Valid candidate accepted for pipeline ingestion.
    Accept {
        identity: FileIdentity,
        kind: CandidateKind,
        size_bytes: u64,
        mtime_secs: i64,
    },
    /// Skipped because file size exceeds configured cap.
    SkipExceedsSizeCap {
        size_bytes: u64,
        max_bytes: u64,
    },
    /// Skipped because it is a non-indexable compiled binary, archive, or media stream.
    SkipBinary {
        identity: FileIdentity,
    },
    /// Skipped because file is hidden and skip_hidden is active.
    SkipHidden,
    /// Skipped because symlink following is disabled.
    SkipSymlink,
    /// Skipped due to inaccessible or locked file after retry.
    SkipIoError {
        error: String,
    },
}

/// Content-type classifier router combining Google Magika with QuorumRAG filtering policies.
#[derive(Debug, Clone)]
pub struct ClassifierRouter {
    classifier: FileTypeClassifier,
    config: IngestConfig,
}

impl ClassifierRouter {
    pub fn new(config: IngestConfig) -> Self {
        Self {
            classifier: FileTypeClassifier::new(),
            config,
        }
    }

    /// Evaluates a candidate path on disk and returns the definitive routing decision.
    pub fn evaluate_file(&self, path: &Path) -> FilterDecision {
        // Fast-path binary/executable/DLL exclusion:
        // Exclude compiled binaries immediately BEFORE executing std::fs::metadata or File::open
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if quorum_classifier::is_binary_executable_extension(ext) {
                let identity = self.classifier.classify_by_extension(
                    path.to_str().unwrap_or(ext),
                    1.0,
                );
                debug!(
                    path = %path.display(),
                    extension = %ext,
                    "Fast-path filtered out compiled binary/executable without disk I/O"
                );
                return FilterDecision::SkipBinary { identity };
            }
        }

        // 1. Check symlink policy
        if !self.config.follow_symlinks {
            if let Ok(meta) = std::fs::symlink_metadata(path) {
                if meta.file_type().is_symlink() {
                    return FilterDecision::SkipSymlink;
                }
            }
        }

        // 2. Check hidden file policy and Office temporary lock files
        if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
            if self.config.skip_hidden && file_name.starts_with('.') {
                return FilterDecision::SkipHidden;
            }
            let lower_name = file_name.to_ascii_lowercase();
            if lower_name.starts_with('~')
                || lower_name.starts_with(".~lock")
                || lower_name.ends_with(".tmp")
                || lower_name.ends_with(".bak")
                || lower_name.ends_with(".wbk")
            {
                return FilterDecision::SkipHidden;
            }
            if self.config.exclude_source_code {
                const EXCLUDED_SOURCE_EXTS: &[&str] = &[
                    ".rs", ".py", ".js", ".ts", ".jsx", ".tsx", ".c", ".cpp", ".h", ".hpp",
                    ".cc", ".cs", ".java", ".go", ".kt", ".rb", ".php", ".swift", ".scala",
                    ".sh", ".bash", ".ps1", ".bat", ".cmd", ".sql", ".css", ".scss", ".less",
                    ".vue", ".svelte", ".toml", ".yaml", ".yml", ".lock", ".dat", ".log",
                    ".json", ".jsonl", ".xml", ".html", ".htm", ".tex", ".aux", ".bbl",
                    ".blg", ".out", ".toc", ".synctex", ".crt", ".pem", ".key",
                ];
                if EXCLUDED_SOURCE_EXTS.iter().any(|ext| lower_name.ends_with(ext)) {
                    let identity = self.classifier.classify_by_extension(file_name, 1.0);
                    return FilterDecision::SkipBinary { identity };
                }
            }
        }

        // 3. Inspect metadata with retry for Windows sharing violations
        let metadata = match self.read_metadata_with_retry(path, 3) {
            Ok(m) => m,
            Err(e) => return FilterDecision::SkipIoError { error: e.to_string() },
        };

        if !metadata.is_file() {
            return FilterDecision::SkipIoError { error: "Path is not a regular file".into() };
        }

        let size = metadata.len();
        if size > self.config.max_file_size_bytes {
            return FilterDecision::SkipExceedsSizeCap {
                size_bytes: size,
                max_bytes: self.config.max_file_size_bytes,
            };
        }

        let mtime = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // 4. Content classification via Google Magika (first 4KB inspection with sharing violation retry)
        let identity = match self.classify_file_with_retry(path, 3) {
            Ok(id) => id,
            Err(e) => return FilterDecision::SkipIoError { error: e.to_string() },
        };

        // 5. Ingestion Routing Invariant:
        // DO NOT SKIP IMAGES! Images must route to ImageIndexer.
        if identity.category == FileCategory::Image || Self::is_image_mime(&identity.mime_type) || Self::is_image_label(&identity.label) {
            return FilterDecision::Accept {
                identity: identity.clone(),
                kind: CandidateKind::Image {
                    format_label: identity.label,
                    mime_type: identity.mime_type,
                },
                size_bytes: size,
                mtime_secs: mtime,
            };
        }

        // 5b. Audio Ingestion Routing Invariant:
        // DO NOT SKIP AUDIO! Audio files (MP3, WAV, FLAC, OGG, M4A, AAC, WMA, AIFF, OPUS)
        // must route to AudioIndexer for rich metadata, ID3, and companion lyrics indexing.
        if identity.category == FileCategory::Audio
            || Self::is_audio_mime(&identity.mime_type)
            || Self::is_audio_label(&identity.label)
        {
            return FilterDecision::Accept {
                identity: identity.clone(),
                kind: CandidateKind::Audio {
                    format_label: identity.label,
                    mime_type: identity.mime_type,
                },
                size_bytes: size,
                mtime_secs: mtime,
            };
        }

        // 6. Text / Source Code / Structured Data Routing
        if self.config.exclude_source_code && identity.category == FileCategory::Code {
            return FilterDecision::SkipBinary { identity };
        }
        // Structured text data (JSON, YAML, TOML, CSV, TSV) matches via `identity.is_text == true`.
        // Non-text Data (is_text == false, e.g. SQLite, PCAP, raw binary) must NOT bypass binary filtering into CandidateKind::Text.
        if identity.is_text || matches!(
            identity.category,
            FileCategory::Code | FileCategory::Text | FileCategory::Document
        ) {
            return FilterDecision::Accept {
                identity,
                kind: CandidateKind::Text {
                    char_count_estimate: size as usize,
                },
                size_bytes: size,
                mtime_secs: mtime,
            };
        }

        // 7. Non-indexable compiled binaries (PE, ELF, Mach-O, DEX, WASM, Archives, Video)
        debug!(
            path = %path.display(),
            label = %identity.label,
            mime = %identity.mime_type,
            category = %identity.category,
            "Filtered out non-indexable binary/media file"
        );
        FilterDecision::SkipBinary { identity }
    }

    /// Fast helper to confirm if a MIME type represents a supported image format.
    pub fn is_image_mime(mime: &str) -> bool {
        matches!(
            mime,
            "image/jpeg"
                | "image/png"
                | "image/webp"
                | "image/gif"
                | "image/bmp"
                | "image/tiff"
                | "image/svg+xml"
                | "image/x-icon"
                | "image/avif"
        )
    }

    /// Fast helper to confirm if a label represents an image format.
    pub fn is_image_label(label: &str) -> bool {
        matches!(
            label,
            "png" | "jpeg" | "jpg" | "webp" | "gif" | "bmp" | "svg" | "tiff"
        )
    }

    /// Fast helper to confirm if a MIME type represents a supported audio format.
    pub fn is_audio_mime(mime: &str) -> bool {
        mime.starts_with("audio/")
            || matches!(
                mime,
                "audio/mpeg"
                    | "audio/mp3"
                    | "audio/wav"
                    | "audio/vnd.wave"
                    | "audio/x-wav"
                    | "audio/wave"
                    | "audio/flac"
                    | "audio/x-flac"
                    | "audio/ogg"
                    | "audio/vorbis"
                    | "audio/mp4"
                    | "audio/m4a"
                    | "audio/x-m4a"
                    | "audio/aac"
                    | "audio/x-ms-wma"
                    | "audio/aiff"
                    | "audio/x-aiff"
                    | "audio/opus"
            )
    }

    /// Fast helper to confirm if a label represents an audio format.
    pub fn is_audio_label(label: &str) -> bool {
        matches!(
            label.to_ascii_lowercase().as_str(),
            "mp3" | "wav" | "flac" | "ogg" | "m4a" | "aac" | "wma" | "aiff" | "aif" | "opus"
        )
    }

    /// Windows file-lock retry helper: retries `std::fs::metadata` on sharing violations.
    fn read_metadata_with_retry(&self, path: &Path, retries: usize) -> std::io::Result<std::fs::Metadata> {
        let mut last_err = None;
        for attempt in 0..retries {
            match std::fs::metadata(path) {
                Ok(m) => return Ok(m),
                Err(e) => {
                    last_err = Some(e);
                    if attempt + 1 < retries {
                        std::thread::sleep(std::time::Duration::from_millis(50 * (attempt as u64 + 1)));
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| std::io::Error::other("Unknown error")))
    }

    /// Windows file-lock retry helper: retries `classify_file` on transient sharing violations.
    fn classify_file_with_retry(&self, path: &Path, retries: usize) -> std::io::Result<FileIdentity> {
        const BACKOFFS_MS: [u64; 3] = [25, 50, 100];
        let mut last_err = None;
        for attempt in 0..retries {
            match self.classifier.classify_file(path) {
                Ok(id) => return Ok(id),
                Err(e) => {
                    let is_sharing_violation = e.raw_os_error() == Some(32)
                        || e.kind() == std::io::ErrorKind::PermissionDenied;
                    last_err = Some(e);
                    if !is_sharing_violation {
                        break;
                    }
                    if attempt + 1 < retries {
                        let delay = BACKOFFS_MS.get(attempt).copied().unwrap_or(100);
                        std::thread::sleep(std::time::Duration::from_millis(delay));
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| std::io::Error::other("Classification failed")))
    }
}
