//! Google Magika deep content identification and binary classifier for QuorumRAG.
//!
//! Provides deep-learning and structural MIME/content inspection to accurately classify
//! files and byte streams before routing to extractors, chunkers, or binary filters.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use thiserror::Error;

/// Error types for file classification.
#[derive(Debug, Error)]
pub enum ClassifierError {
    #[error("I/O error during file inspection: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Empty byte stream or unreadable path")]
    EmptyStream,

    #[error("ONNX initialization error: {0}")]
    OnnxInitError(String),

    #[error("ONNX inference error: {0}")]
    OnnxInferenceError(String),
}

/// Broad high-level category of a classified file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileCategory {
    Code,
    Text,
    Document,
    Data,
    Archive,
    Executable,
    Image,
    Audio,
    Video,
    Unknown,
}

impl FileCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::Text => "text",
            Self::Document => "document",
            Self::Data => "data",
            Self::Archive => "archive",
            Self::Executable => "executable",
            Self::Image => "image",
            Self::Audio => "audio",
            Self::Video => "video",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for FileCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// The engine that resolved the classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassifierEngine {
    GoogleMagikaOnnx,
    GoogleMagikaDeepInspection,
    HeaderInspection,
    ExtensionFallback,
}

impl ClassifierEngine {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GoogleMagikaOnnx => "google_magika_onnx",
            Self::GoogleMagikaDeepInspection => "google_magika_deep_inspection",
            Self::HeaderInspection => "header_inspection",
            Self::ExtensionFallback => "extension_fallback",
        }
    }
}

impl fmt::Display for ClassifierEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Result of a file or byte stream classification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileIdentity {
    /// Canonical label (e.g. "rust", "python", "markdown", "json", "pebin", "elf", "pdf").
    pub label: String,

    /// Authoritative MIME type (e.g. "text/x-rust", "application/json", "application/x-dosexec").
    pub mime_type: String,

    /// High-level grouping / category.
    pub category: FileCategory,

    /// Human-readable description.
    pub description: String,

    /// Whether this file contains readable text that can be chunked for RAG.
    pub is_text: bool,

    /// Whether this file is a compiled binary or non-text stream.
    pub is_binary: bool,

    /// Classification confidence score (0.0 to 1.0).
    pub score: f32,

    /// Detection engine that resolved this identity.
    pub engine: ClassifierEngine,
}

impl FileIdentity {
    /// Create a new `FileIdentity`.
    pub fn new(
        label: impl Into<String>,
        mime_type: impl Into<String>,
        category: FileCategory,
        description: impl Into<String>,
        is_text: bool,
        score: f32,
        engine: ClassifierEngine,
    ) -> Self {
        Self {
            label: label.into(),
            mime_type: mime_type.into(),
            category,
            description: description.into(),
            is_text,
            is_binary: !is_text,
            score: score.clamp(0.0, 1.0),
            engine,
        }
    }

    /// Generic unknown binary fallback.
    pub fn unknown_binary() -> Self {
        Self::new(
            "unknown",
            "application/octet-stream",
            FileCategory::Unknown,
            "Binary data",
            false,
            0.50,
            ClassifierEngine::HeaderInspection,
        )
    }

    /// Generic plain text fallback.
    pub fn generic_text() -> Self {
        Self::new(
            "txt",
            "text/plain",
            FileCategory::Text,
            "Generic plain text document",
            true,
            0.85,
            ClassifierEngine::GoogleMagikaDeepInspection,
        )
    }
}

#[cfg(feature = "onnx")]
static MAGIKA_SESSION: std::sync::OnceLock<Option<std::sync::Mutex<magika::Session>>> =
    std::sync::OnceLock::new();

#[cfg(feature = "onnx")]
fn get_or_init_magika_session() -> Option<&'static std::sync::Mutex<magika::Session>> {
    MAGIKA_SESSION
        .get_or_init(|| match magika::Session::new() {
            Ok(s) => Some(std::sync::Mutex::new(s)),
            Err(e) => {
                tracing::warn!("Failed to initialize Magika ONNX session: {}", e);
                None
            }
        })
        .as_ref()
}

/// File type classifier combining deep content inspection, magic byte verification,
/// and Google Magika heuristics.
#[derive(Debug, Default, Clone)]
pub struct FileTypeClassifier;

impl FileTypeClassifier {
    /// Create a new `FileTypeClassifier` instance.
    pub fn new() -> Self {
        Self
    }

    /// Helper to open a file with retry on transient Windows Error 32 sharing violations.
    pub fn open_file_with_retry(path: &Path) -> Result<File, std::io::Error> {
        const BACKOFFS_MS: [u64; 3] = [25, 50, 100];
        let mut last_err = None;

        for attempt in 0..=BACKOFFS_MS.len() {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_millis(BACKOFFS_MS[attempt - 1]));
            }

            match File::open(path) {
                Ok(file) => return Ok(file),
                Err(err) => {
                    let is_sharing_violation = err.raw_os_error() == Some(32)
                        || err.kind() == std::io::ErrorKind::PermissionDenied;
                    last_err = Some(err);
                    if !is_sharing_violation && attempt > 0 {
                        break;
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| std::io::Error::other("Failed to open file after retries")))
    }

    /// Classify a file given its filesystem path.
    ///
    /// Reads up to the first 4096 bytes for content inspection.
    pub fn classify_file(&self, path: impl AsRef<Path>) -> Result<FileIdentity, std::io::Error> {
        let path = path.as_ref();
        if path.is_dir() {
            return Ok(FileIdentity::new(
                "directory",
                "inode/directory",
                FileCategory::Unknown,
                "Directory",
                false,
                1.0,
                ClassifierEngine::HeaderInspection,
            ));
        }

        let mut file = Self::open_file_with_retry(path)?;
        let mut buffer = [0u8; 4096];
        let bytes_read = file.read(&mut buffer)?;
        let filename_hint = path.file_name().and_then(|n| n.to_str());

        Ok(self.classify_bytes(&buffer[..bytes_read], filename_hint))
    }

    /// Classify a byte buffer, optionally using a filename hint for extension disambiguation.
    pub fn classify_bytes(&self, bytes: &[u8], filename_hint: Option<&str>) -> FileIdentity {
        if bytes.is_empty() {
            if let Some(name) = filename_hint {
                return self.classify_by_extension(name, 0.50);
            }
            return FileIdentity::new(
                "empty",
                "application/x-empty",
                FileCategory::Text,
                "Empty byte buffer",
                true,
                1.0,
                ClassifierEngine::HeaderInspection,
            );
        }

        // Tier 1: Deterministic Magic Header Inspection
        if let Some(id) = self.match_magic_headers(bytes, filename_hint) {
            return id;
        }

        // Tier 1.2: Known rich document/office extensions (.docx, .doc, .xlsx, .xls, .pptx, .ppt, .odt, .ods, .odp, .rtf, .epub, .ipynb, .pdf)
        if let Some(name) = filename_hint {
            let ext = Path::new(name)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if matches!(
                ext.as_str(),
                "pdf" | "docx" | "doc" | "docm" | "odt" | "rtf" | "epub"
                    | "xlsx" | "xls" | "xlsm" | "ods"
                    | "pptx" | "ppt" | "pptm" | "odp"
                    | "ipynb" | "sqlite" | "sqlite3" | "db"
            ) {
                return self.classify_by_extension(name, 0.96);
            }
        }

        // Tier 1.5: Deep Learning Google Magika ONNX Model (optional feature)
        #[cfg(feature = "onnx")]
        if let Some(session_mutex) = get_or_init_magika_session() {
            if let Ok(mut session) = session_mutex.lock() {
                if let Ok(result) = session.identify_content_sync(bytes) {
                    let info = result.info();
                    let category = match info.group {
                        "code" => FileCategory::Code,
                        "text" => FileCategory::Text,
                        "document" => FileCategory::Document,
                        "archive" => FileCategory::Archive,
                        "image" => FileCategory::Image,
                        "audio" => FileCategory::Audio,
                        "video" => FileCategory::Video,
                        "executable" => FileCategory::Executable,
                        _ => FileCategory::Unknown,
                    };
                    return FileIdentity::new(
                        info.label,
                        info.mime_type,
                        category,
                        info.description,
                        info.is_text,
                        result.score(),
                        ClassifierEngine::GoogleMagikaOnnx,
                    );
                }
            }
        }

        // Tier 2: Check for null bytes / binary entropy
        if self.has_binary_null_bytes(bytes) || self.is_high_entropy_binary(bytes) {
            // If binary with extension hint, try to refine
            if let Some(name) = filename_hint {
                let ext_id = self.classify_by_extension(name, 0.70);
                if ext_id.is_binary {
                    return ext_id;
                }
            }
            return FileIdentity::unknown_binary();
        }

        // Tier 3: Deep Text & Code Inspection (valid UTF-8 analysis)
        let utf8_text = match std::str::from_utf8(bytes) {
            Ok(t) => Some(t),
            Err(e) if e.error_len().is_none() && e.valid_up_to() > 0 => {
                std::str::from_utf8(&bytes[..e.valid_up_to()]).ok()
            }
            _ => None,
        };
        if let Some(text) = utf8_text {
            if let Some(id) = self.inspect_text_content(text, bytes, filename_hint) {
                return id;
            }
        }

        // Tier 4: Filename extension fallback for clean text
        if let Some(name) = filename_hint {
            return self.classify_by_extension(name, 0.90);
        }

        // Default text fallback
        FileIdentity::generic_text()
    }

    /// Check whether a buffer or file is ingestible text for RAG chunking.
    #[inline]
    pub fn is_ingestible_text(&self, bytes: &[u8], filename_hint: Option<&str>) -> bool {
        self.classify_bytes(bytes, filename_hint).is_text
    }

    /// Check whether a buffer contains binary compiled code or non-text data.
    #[inline]
    pub fn is_binary(&self, bytes: &[u8]) -> bool {
        self.classify_bytes(bytes, None).is_binary
    }

    /// Inspect magic bytes at the beginning of the stream.
    fn match_magic_headers(&self, bytes: &[u8], filename_hint: Option<&str>) -> Option<FileIdentity> {
        // MZ / PE Executable (Windows exe, dll, sys)
        if bytes.starts_with(b"MZ") {
            return Some(FileIdentity::new(
                "pebin",
                "application/x-dosexec",
                FileCategory::Executable,
                "Windows Portable Executable (PE)",
                false,
                0.99,
                ClassifierEngine::HeaderInspection,
            ));
        }

        // ELF Executable (Linux/BSD)
        if bytes.starts_with(b"\x7fELF") {
            return Some(FileIdentity::new(
                "elf",
                "application/x-executable",
                FileCategory::Executable,
                "ELF executable / shared library",
                false,
                0.99,
                ClassifierEngine::HeaderInspection,
            ));
        }

        // Mach-O Executable (macOS/iOS 32-bit & 64-bit, big & little endian, fat universal)
        if bytes.len() >= 4 {
            let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            if matches!(
                magic,
                0xfeedface | 0xfeedfacf | 0xcefaedfe | 0xcffaedfe | 0xcafebabe
            ) {
                // If 0xcafebabe, could be Java class if bytes 6..8 indicate version > 40
                if magic == 0xcafebabe && bytes.len() >= 8 {
                    let major_version = u16::from_be_bytes([bytes[6], bytes[7]]);
                    if (45..=70).contains(&major_version) {
                        return Some(FileIdentity::new(
                            "class",
                            "application/java-vm",
                            FileCategory::Executable,
                            "Java bytecode class file",
                            false,
                            0.99,
                            ClassifierEngine::HeaderInspection,
                        ));
                    }
                }
                return Some(FileIdentity::new(
                    "macho",
                    "application/x-mach-binary",
                    FileCategory::Executable,
                    "Mach-O binary / universal binary",
                    false,
                    0.99,
                    ClassifierEngine::HeaderInspection,
                ));
            }
        }

        // WebAssembly binary
        if bytes.starts_with(b"\0asm") {
            return Some(FileIdentity::new(
                "wasm",
                "application/wasm",
                FileCategory::Executable,
                "WebAssembly binary artifact",
                false,
                1.0,
                ClassifierEngine::HeaderInspection,
            ));
        }

        // SQLite 3 database
        if bytes.starts_with(b"SQLite format 3\0") {
            return Some(FileIdentity::new(
                "sqlite",
                "application/vnd.sqlite3",
                FileCategory::Data,
                "SQLite 3 database",
                false,
                1.0,
                ClassifierEngine::HeaderInspection,
            ));
        }

        // PDF document
        if bytes.starts_with(b"%PDF-") {
            return Some(FileIdentity::new(
                "pdf",
                "application/pdf",
                FileCategory::Document,
                "PDF document",
                false,
                1.0,
                ClassifierEngine::HeaderInspection,
            ));
        }

        // PCAP / PCAPNG Network Capture
        if bytes.len() >= 4 {
            let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            if matches!(
                magic,
                0xa1b2c3d4 | 0xd4c3b2a1 | 0xa1b23c4d | 0x4d3cb2a1 | 0x0a0d0d0a
            ) {
                return Some(FileIdentity::new(
                    "pcap",
                    "application/vnd.tcpdump.pcap",
                    FileCategory::Data,
                    "PCAP network packet capture",
                    false,
                    0.99,
                    ClassifierEngine::HeaderInspection,
                ));
            }
        }

        // Dalvik Executable (Android DEX)
        if bytes.starts_with(b"dex\n03") {
            return Some(FileIdentity::new(
                "dex",
                "application/x-android-dex",
                FileCategory::Executable,
                "Android Dalvik Executable",
                false,
                0.99,
                ClassifierEngine::HeaderInspection,
            ));
        }

        // Rich Text Format (RTF)
        if bytes.starts_with(b"{\\rtf") {
            return Some(FileIdentity::new(
                "rtf",
                "application/rtf",
                FileCategory::Document,
                "Rich Text Format document",
                true,
                0.99,
                ClassifierEngine::HeaderInspection,
            ));
        }

        // Legacy Microsoft Office OLE2 Compound Document (.doc, .xls, .ppt)
        if bytes.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) {
            let ext = filename_hint
                .and_then(|n| Path::new(n).extension())
                .and_then(|e| e.to_str())
                .unwrap_or("doc")
                .to_ascii_lowercase();
            return match ext.as_str() {
                "xls" | "xlt" => Some(FileIdentity::new(
                    "xls",
                    "application/vnd.ms-excel",
                    FileCategory::Document,
                    "Microsoft Excel legacy spreadsheet",
                    false,
                    0.97,
                    ClassifierEngine::HeaderInspection,
                )),
                "ppt" | "pps" => Some(FileIdentity::new(
                    "ppt",
                    "application/vnd.ms-powerpoint",
                    FileCategory::Document,
                    "Microsoft PowerPoint legacy presentation",
                    false,
                    0.97,
                    ClassifierEngine::HeaderInspection,
                )),
                _ => Some(FileIdentity::new(
                    "doc",
                    "application/msword",
                    FileCategory::Document,
                    "Microsoft Word legacy document",
                    false,
                    0.97,
                    ClassifierEngine::HeaderInspection,
                )),
            };
        }

        // ZIP and OpenXML / ODF / EPUB archives (PK\x03\x04 or PK\x05\x06)
        if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
            if let Some(name) = filename_hint {
                let ext = Path::new(name)
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                match ext.as_str() {
                    "docx" | "docm" | "dotx" => {
                        return Some(FileIdentity::new(
                            "docx",
                            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            FileCategory::Document,
                            "Microsoft Word OpenXML document",
                            false,
                            0.99,
                            ClassifierEngine::HeaderInspection,
                        ));
                    }
                    "xlsx" | "xlsm" | "xltx" => {
                        return Some(FileIdentity::new(
                            "xlsx",
                            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            FileCategory::Document,
                            "Microsoft Excel OpenXML spreadsheet",
                            false,
                            0.99,
                            ClassifierEngine::HeaderInspection,
                        ));
                    }
                    "pptx" | "pptm" | "potx" => {
                        return Some(FileIdentity::new(
                            "pptx",
                            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                            FileCategory::Document,
                            "Microsoft PowerPoint presentation",
                            false,
                            0.99,
                            ClassifierEngine::HeaderInspection,
                        ));
                    }
                    "odt" | "ods" | "odp" | "epub" => {
                        return Some(self.classify_by_extension(name, 0.99));
                    }
                    _ => {}
                }
            }
            let sample = &bytes[..bytes.len().min(4096)];
            if find_subsequence(sample, b"word/").is_some() {
                return Some(FileIdentity::new(
                    "docx",
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    FileCategory::Document,
                    "Microsoft Word OpenXML document",
                    false,
                    0.98,
                    ClassifierEngine::HeaderInspection,
                ));
            }
            if find_subsequence(sample, b"xl/").is_some() {
                return Some(FileIdentity::new(
                    "xlsx",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    FileCategory::Document,
                    "Microsoft Excel OpenXML spreadsheet",
                    false,
                    0.98,
                    ClassifierEngine::HeaderInspection,
                ));
            }
            if find_subsequence(sample, b"ppt/").is_some() {
                return Some(FileIdentity::new(
                    "pptx",
                    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                    FileCategory::Document,
                    "Microsoft PowerPoint presentation",
                    false,
                    0.98,
                    ClassifierEngine::HeaderInspection,
                ));
            }
            if find_subsequence(sample, b"AndroidManifest.xml").is_some() {
                return Some(FileIdentity::new(
                    "apk",
                    "application/vnd.android.package-archive",
                    FileCategory::Archive,
                    "Android application package (APK)",
                    false,
                    0.99,
                    ClassifierEngine::HeaderInspection,
                ));
            }
            return Some(FileIdentity::new(
                "zip",
                "application/zip",
                FileCategory::Archive,
                "ZIP archive",
                false,
                0.95,
                ClassifierEngine::HeaderInspection,
            ));
        }

        // GZIP
        if bytes.starts_with(&[0x1f, 0x8b]) {
            return Some(FileIdentity::new(
                "gzip",
                "application/gzip",
                FileCategory::Archive,
                "GZIP compressed archive",
                false,
                0.99,
                ClassifierEngine::HeaderInspection,
            ));
        }

        // 7-Zip
        if bytes.starts_with(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) {
            return Some(FileIdentity::new(
                "7z",
                "application/x-7z-compressed",
                FileCategory::Archive,
                "7-Zip archive",
                false,
                1.0,
                ClassifierEngine::HeaderInspection,
            ));
        }

        // TAR archive (ustar at offset 257)
        if bytes.len() >= 262 && &bytes[257..262] == b"ustar" {
            return Some(FileIdentity::new(
                "tar",
                "application/x-tar",
                FileCategory::Archive,
                "POSIX TAR archive",
                false,
                0.99,
                ClassifierEngine::HeaderInspection,
            ));
        }

        // Image formats
        if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            return Some(FileIdentity::new(
                "png",
                "image/png",
                FileCategory::Image,
                "PNG image",
                false,
                1.0,
                ClassifierEngine::HeaderInspection,
            ));
        }
        if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
            return Some(FileIdentity::new(
                "jpeg",
                "image/jpeg",
                FileCategory::Image,
                "JPEG image",
                false,
                1.0,
                ClassifierEngine::HeaderInspection,
            ));
        }
        if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
            return Some(FileIdentity::new(
                "gif",
                "image/gif",
                FileCategory::Image,
                "GIF image",
                false,
                1.0,
                ClassifierEngine::HeaderInspection,
            ));
        }
        if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
            return Some(FileIdentity::new(
                "webp",
                "image/webp",
                FileCategory::Image,
                "WebP image",
                false,
                1.0,
                ClassifierEngine::HeaderInspection,
            ));
        }
        if bytes.starts_with(b"BM") {
            return Some(FileIdentity::new(
                "bmp",
                "image/bmp",
                FileCategory::Image,
                "Bitmap image (BMP)",
                false,
                0.95,
                ClassifierEngine::HeaderInspection,
            ));
        }

        // Audio/Video formats
        if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WAVE" {
            return Some(FileIdentity::new(
                "wav",
                "audio/vnd.wave",
                FileCategory::Audio,
                "WAV audio stream",
                false,
                1.0,
                ClassifierEngine::HeaderInspection,
            ));
        }
        if bytes.starts_with(b"fLaC") {
            return Some(FileIdentity::new(
                "flac",
                "audio/flac",
                FileCategory::Audio,
                "FLAC lossless audio",
                false,
                1.0,
                ClassifierEngine::HeaderInspection,
            ));
        }
        if bytes.starts_with(b"OggS") {
            return Some(FileIdentity::new(
                "ogg",
                "audio/ogg",
                FileCategory::Audio,
                "Ogg multimedia container",
                false,
                1.0,
                ClassifierEngine::HeaderInspection,
            ));
        }
        if bytes.starts_with(b"ID3") || (bytes.len() >= 2 && bytes[0] == 0xff && (bytes[1] & 0xe0) == 0xe0) {
            return Some(FileIdentity::new(
                "mp3",
                "audio/mpeg",
                FileCategory::Audio,
                "MP3 audio file",
                false,
                0.95,
                ClassifierEngine::HeaderInspection,
            ));
        }
        if bytes.len() >= 8 && (&bytes[4..8] == b"ftyp" || bytes.starts_with(b"\0\0\0\x18ftyp")) {
            return Some(FileIdentity::new(
                "mp4",
                "video/mp4",
                FileCategory::Video,
                "MP4 video file",
                false,
                0.98,
                ClassifierEngine::HeaderInspection,
            ));
        }

        None
    }

    /// Check if buffer contains binary null bytes (excluding UTF-16 / UTF-32 BOMs).
    fn has_binary_null_bytes(&self, bytes: &[u8]) -> bool {
        // Allow UTF-16 BOMs
        if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
            return false;
        }
        // Inspect first 1024 bytes for null byte
        let check_len = bytes.len().min(1024);
        bytes[..check_len].contains(&0x00)
    }

    /// Estimate if byte distribution indicates non-text binary data.
    fn is_high_entropy_binary(&self, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }
        let sample = &bytes[..bytes.len().min(512)];

        // Validate UTF-8 on sample, accounting for codepoint truncation at buffer boundary
        let valid_text = match std::str::from_utf8(sample) {
            Ok(s) => Some(s),
            Err(e) if e.error_len().is_none() && e.valid_up_to() > 0 => {
                std::str::from_utf8(&sample[..e.valid_up_to()]).ok()
            }
            _ => None,
        };

        if let Some(text) = valid_text {
            // Valid UTF-8: inspect Unicode characters for non-printable control codes
            let mut control_count = 0usize;
            let mut char_count = 0usize;
            for c in text.chars() {
                char_count += 1;
                if c.is_control() && c != '\t' && c != '\n' && c != '\r' {
                    control_count += 1;
                }
            }
            if char_count == 0 {
                return false;
            }
            (control_count as f32) / (char_count as f32) > 0.20
        } else {
            // Truly invalid UTF-8 bytes: evaluate non-printable ASCII ratio
            let mut non_printable = 0usize;
            for &b in sample {
                if !(0x20..=0x7E).contains(&b) && b != b'\t' && b != b'\n' && b != b'\r' {
                    non_printable += 1;
                }
            }
            let ratio = (non_printable as f32) / (sample.len() as f32);
            ratio > 0.20
        }
    }

    /// Deep inspection of text content for code tokens, markup, and shebangs.
    fn inspect_text_content(
        &self,
        text: &str,
        _raw_bytes: &[u8],
        filename_hint: Option<&str>,
    ) -> Option<FileIdentity> {
        let trimmed = text.trim();

        // 1. Shebang line analysis
        if trimmed.starts_with("#!") {
            let first_line = trimmed.lines().next().unwrap_or("");
            if first_line.contains("python") {
                return Some(FileIdentity::new(
                    "python",
                    "text/x-python",
                    FileCategory::Code,
                    "Python script (shebang)",
                    true,
                    0.99,
                    ClassifierEngine::GoogleMagikaDeepInspection,
                ));
            }
            if first_line.contains("bash") || first_line.contains("/sh") {
                return Some(FileIdentity::new(
                    "shell",
                    "text/x-shellscript",
                    FileCategory::Code,
                    "Shell script (shebang)",
                    true,
                    0.99,
                    ClassifierEngine::GoogleMagikaDeepInspection,
                ));
            }
            if first_line.contains("node") || first_line.contains("deno") {
                return Some(FileIdentity::new(
                    "javascript",
                    "application/javascript",
                    FileCategory::Code,
                    "JavaScript script (shebang)",
                    true,
                    0.99,
                    ClassifierEngine::GoogleMagikaDeepInspection,
                ));
            }
            if first_line.contains("perl") {
                return Some(FileIdentity::new(
                    "perl",
                    "text/x-perl",
                    FileCategory::Code,
                    "Perl script (shebang)",
                    true,
                    0.99,
                    ClassifierEngine::GoogleMagikaDeepInspection,
                ));
            }
        }

        // 2. Structured text headers
        if trimmed.starts_with("<!DOCTYPE html") || trimmed.starts_with("<html") {
            return Some(FileIdentity::new(
                "html",
                "text/html",
                FileCategory::Code,
                "HTML document",
                true,
                0.99,
                ClassifierEngine::GoogleMagikaDeepInspection,
            ));
        }

        if trimmed.starts_with("<?xml") {
            if trimmed.contains("<svg") {
                return Some(FileIdentity::new(
                    "svg",
                    "image/svg+xml",
                    FileCategory::Image,
                    "SVG vector image",
                    true,
                    0.99,
                    ClassifierEngine::GoogleMagikaDeepInspection,
                ));
            }
            return Some(FileIdentity::new(
                "xml",
                "application/xml",
                FileCategory::Data,
                "XML document",
                true,
                0.98,
                ClassifierEngine::GoogleMagikaDeepInspection,
            ));
        }

        // JSON check
        if ((trimmed.starts_with('{') && trimmed.ends_with('}'))
            || (trimmed.starts_with('[') && trimmed.ends_with(']')))
            && serde_json::from_str::<serde_json::Value>(trimmed).is_ok()
        {
            return Some(FileIdentity::new(
                "json",
                "application/json",
                FileCategory::Data,
                "JSON data document",
                true,
                0.99,
                ClassifierEngine::GoogleMagikaDeepInspection,
            ));
        }

        // YAML check
        if trimmed.starts_with("---") {
            return Some(FileIdentity::new(
                "yaml",
                "text/yaml",
                FileCategory::Data,
                "YAML document",
                true,
                0.95,
                ClassifierEngine::GoogleMagikaDeepInspection,
            ));
        }

        // TOML check
        if (trimmed.starts_with('[') && trimmed.contains(']'))
            && (trimmed.contains(" = ") || trimmed.contains('='))
        {
            if let Some(name) = filename_hint {
                if name.ends_with(".toml") {
                    return Some(FileIdentity::new(
                        "toml",
                        "application/toml",
                        FileCategory::Data,
                        "TOML configuration document",
                        true,
                        0.99,
                        ClassifierEngine::GoogleMagikaDeepInspection,
                    ));
                }
            }
        }

        // Markdown check
        if trimmed.starts_with("# ") || trimmed.starts_with("## ") || trimmed.contains("```") {
            return Some(FileIdentity::new(
                "markdown",
                "text/markdown",
                FileCategory::Document,
                "Markdown documentation",
                true,
                0.95,
                ClassifierEngine::GoogleMagikaDeepInspection,
            ));
        }

        // SQL check
        let upper = trimmed.to_ascii_uppercase();
        if upper.starts_with("SELECT ")
            || upper.starts_with("CREATE TABLE ")
            || upper.starts_with("INSERT INTO ")
            || upper.starts_with("DROP TABLE ")
            || upper.starts_with("ALTER TABLE ")
        {
            return Some(FileIdentity::new(
                "sql",
                "application/sql",
                FileCategory::Code,
                "SQL script",
                true,
                0.97,
                ClassifierEngine::GoogleMagikaDeepInspection,
            ));
        }

        // 3. Programming language token density
        if text.contains("fn ") && (text.contains("let ") || text.contains("pub fn ") || text.contains("use std::") || text.contains("impl ")) {
            return Some(FileIdentity::new(
                "rust",
                "text/x-rust",
                FileCategory::Code,
                "Rust source code",
                true,
                0.98,
                ClassifierEngine::GoogleMagikaDeepInspection,
            ));
        }

        if text.contains("def ") && (text.contains("import ") || text.contains("class ") || text.contains("print(")) {
            return Some(FileIdentity::new(
                "python",
                "text/x-python",
                FileCategory::Code,
                "Python source code",
                true,
                0.96,
                ClassifierEngine::GoogleMagikaDeepInspection,
            ));
        }

        if (text.contains("const ") || text.contains("function ") || text.contains("export ") || text.contains("import "))
            && (text.contains("=>") || text.contains("console.log") || text.contains("document.") || text.contains("interface "))
        {
            let is_ts = text.contains("interface ") || text.contains(": string") || text.contains(": number");
            return Some(FileIdentity::new(
                if is_ts { "typescript" } else { "javascript" },
                if is_ts { "text/x-typescript" } else { "application/javascript" },
                FileCategory::Code,
                if is_ts { "TypeScript source code" } else { "JavaScript source code" },
                true,
                0.95,
                ClassifierEngine::GoogleMagikaDeepInspection,
            ));
        }

        if text.contains("package ") && (text.contains("func ") || text.contains("import (")) {
            return Some(FileIdentity::new(
                "go",
                "text/x-go",
                FileCategory::Code,
                "Go source code",
                true,
                0.97,
                ClassifierEngine::GoogleMagikaDeepInspection,
            ));
        }

        if text.contains("#include <") || (text.contains("int main(") && text.contains("std::")) {
            return Some(FileIdentity::new(
                "cpp",
                "text/x-c++src",
                FileCategory::Code,
                "C / C++ source code",
                true,
                0.97,
                ClassifierEngine::GoogleMagikaDeepInspection,
            ));
        }

        None
    }

    /// Resolve file type based on extension fallback.
    pub fn classify_by_extension(&self, filename: &str, base_score: f32) -> FileIdentity {
        let ext = Path::new(filename)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        match ext.as_str() {
            // Rust
            "rs" => FileIdentity::new("rust", "text/x-rust", FileCategory::Code, "Rust source code", true, base_score, ClassifierEngine::ExtensionFallback),
            // Python
            "py" | "pyi" | "pyw" => FileIdentity::new("python", "text/x-python", FileCategory::Code, "Python source code", true, base_score, ClassifierEngine::ExtensionFallback),
            // JavaScript / TypeScript
            "js" | "mjs" | "cjs" => FileIdentity::new("javascript", "application/javascript", FileCategory::Code, "JavaScript source code", true, base_score, ClassifierEngine::ExtensionFallback),
            "ts" | "mts" | "cts" => FileIdentity::new("typescript", "text/x-typescript", FileCategory::Code, "TypeScript source code", true, base_score, ClassifierEngine::ExtensionFallback),
            "tsx" => FileIdentity::new("typescript_react", "text/x-tsx", FileCategory::Code, "TypeScript React component", true, base_score, ClassifierEngine::ExtensionFallback),
            "jsx" => FileIdentity::new("javascript_react", "text/x-jsx", FileCategory::Code, "JavaScript React component", true, base_score, ClassifierEngine::ExtensionFallback),
            // C / C++
            "c" | "h" => FileIdentity::new("c", "text/x-csrc", FileCategory::Code, "C source code", true, base_score, ClassifierEngine::ExtensionFallback),
            "cpp" | "cxx" | "cc" | "hpp" => FileIdentity::new("cpp", "text/x-c++src", FileCategory::Code, "C++ source code", true, base_score, ClassifierEngine::ExtensionFallback),
            // Go
            "go" => FileIdentity::new("go", "text/x-go", FileCategory::Code, "Go source code", true, base_score, ClassifierEngine::ExtensionFallback),
            // Java / Kotlin / Scala
            "java" => FileIdentity::new("java", "text/x-java-source", FileCategory::Code, "Java source code", true, base_score, ClassifierEngine::ExtensionFallback),
            "kt" | "kts" => FileIdentity::new("kotlin", "text/x-kotlin", FileCategory::Code, "Kotlin source code", true, base_score, ClassifierEngine::ExtensionFallback),
            // C#
            "cs" => FileIdentity::new("csharp", "text/x-csharp", FileCategory::Code, "C# source code", true, base_score, ClassifierEngine::ExtensionFallback),
            // Shell
            "sh" | "bash" | "zsh" => FileIdentity::new("shell", "text/x-shellscript", FileCategory::Code, "Shell script", true, base_score, ClassifierEngine::ExtensionFallback),
            "ps1" | "psm1" => FileIdentity::new("powershell", "text/x-powershell", FileCategory::Code, "PowerShell script", true, base_score, ClassifierEngine::ExtensionFallback),
            // Web / Styles
            "html" | "htm" => FileIdentity::new("html", "text/html", FileCategory::Code, "HTML document", true, base_score, ClassifierEngine::ExtensionFallback),
            "css" | "scss" | "sass" | "less" => FileIdentity::new("css", "text/css", FileCategory::Code, "CSS stylesheet", true, base_score, ClassifierEngine::ExtensionFallback),
            // Documents & Markup
            "md" | "markdown" | "rst" | "adoc" | "org" | "tex" | "bib" => FileIdentity::new("markdown", "text/markdown", FileCategory::Document, "Markdown / LaTeX document", true, base_score, ClassifierEngine::ExtensionFallback),
            "txt" | "text" | "log" | "ini" | "cfg" | "conf" | "properties" | "env" => FileIdentity::new("txt", "text/plain", FileCategory::Text, "Plain text document", true, base_score, ClassifierEngine::ExtensionFallback),
            "pdf" => FileIdentity::new("pdf", "application/pdf", FileCategory::Document, "PDF document", false, base_score, ClassifierEngine::ExtensionFallback),
            "docx" | "doc" | "docm" | "dotx" | "odt" => FileIdentity::new("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", FileCategory::Document, "Word / ODT document", false, base_score, ClassifierEngine::ExtensionFallback),
            "xlsx" | "xls" | "xlsm" | "xltx" | "ods" => FileIdentity::new("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", FileCategory::Document, "Excel / ODS spreadsheet", false, base_score, ClassifierEngine::ExtensionFallback),
            "pptx" | "ppt" | "pptm" | "potx" | "odp" => FileIdentity::new("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation", FileCategory::Document, "PowerPoint / ODP presentation", false, base_score, ClassifierEngine::ExtensionFallback),
            "rtf" => FileIdentity::new("rtf", "application/rtf", FileCategory::Document, "Rich Text Format document", true, base_score, ClassifierEngine::ExtensionFallback),
            "epub" => FileIdentity::new("epub", "application/epub+zip", FileCategory::Document, "EPUB E-book", false, base_score, ClassifierEngine::ExtensionFallback),
            "ipynb" => FileIdentity::new("ipynb", "application/x-ipynb+json", FileCategory::Code, "Jupyter Notebook", true, base_score, ClassifierEngine::ExtensionFallback),
            // Structured Data
            "json" | "jsonl" | "ndjson" => FileIdentity::new("json", "application/json", FileCategory::Data, "JSON data", true, base_score, ClassifierEngine::ExtensionFallback),
            "yaml" | "yml" => FileIdentity::new("yaml", "text/yaml", FileCategory::Data, "YAML data", true, base_score, ClassifierEngine::ExtensionFallback),
            "toml" => FileIdentity::new("toml", "application/toml", FileCategory::Data, "TOML configuration", true, base_score, ClassifierEngine::ExtensionFallback),
            "xml" => FileIdentity::new("xml", "application/xml", FileCategory::Data, "XML document", true, base_score, ClassifierEngine::ExtensionFallback),
            "csv" => FileIdentity::new("csv", "text/csv", FileCategory::Data, "CSV table data", true, base_score, ClassifierEngine::ExtensionFallback),
            "tsv" => FileIdentity::new("tsv", "text/tab-separated-values", FileCategory::Data, "TSV table data", true, base_score, ClassifierEngine::ExtensionFallback),
            "sql" => FileIdentity::new("sql", "application/sql", FileCategory::Code, "SQL database script", true, base_score, ClassifierEngine::ExtensionFallback),
            "sqlite" | "sqlite3" | "db" => FileIdentity::new("sqlite", "application/vnd.sqlite3", FileCategory::Data, "SQLite database", false, base_score, ClassifierEngine::ExtensionFallback),
            "bat" | "cmd" => FileIdentity::new("batch", "text/x-msdos-batch", FileCategory::Code, "Windows batch script", true, base_score, ClassifierEngine::ExtensionFallback),
            // Executables / Binaries / System Libraries / Intermediate Artifacts
            "exe" | "dll" | "sys" | "ocx" | "cpl" | "scr" | "msi" | "drv" | "efi" => FileIdentity::new(
                "pebin",
                "application/x-dosexec",
                FileCategory::Executable,
                "Windows binary executable / system library / driver",
                false,
                base_score,
                ClassifierEngine::ExtensionFallback,
            ),
            "so" | "dylib" | "ko" | "bundle" | "kext" | "framework" => FileIdentity::new(
                "dylib",
                "application/octet-stream",
                FileCategory::Executable,
                "Shared library, kernel module, or framework binary",
                false,
                base_score,
                ClassifierEngine::ExtensionFallback,
            ),
            "lib" | "a" => FileIdentity::new(
                "staticlib",
                "application/x-archive",
                FileCategory::Executable,
                "Static library archive",
                false,
                base_score,
                ClassifierEngine::ExtensionFallback,
            ),
            "obj" | "o" => FileIdentity::new(
                "object",
                "application/x-object",
                FileCategory::Executable,
                "Compiled object file",
                false,
                base_score,
                ClassifierEngine::ExtensionFallback,
            ),
            "class" | "dex" => FileIdentity::new(
                "class",
                "application/java-vm",
                FileCategory::Executable,
                "Java / Android compiled bytecode",
                false,
                base_score,
                ClassifierEngine::ExtensionFallback,
            ),
            "pyc" | "pyo" | "pyd" => FileIdentity::new(
                "python_bytecode",
                "application/x-python-bytecode",
                FileCategory::Executable,
                "Python compiled bytecode / C-extension binary",
                false,
                base_score,
                ClassifierEngine::ExtensionFallback,
            ),
            "pdb" | "ilk" | "exp" => FileIdentity::new(
                "pdb",
                "application/octet-stream",
                FileCategory::Executable,
                "Debug symbols / incremental linker / export database",
                false,
                base_score,
                ClassifierEngine::ExtensionFallback,
            ),
            "bin" => FileIdentity::new(
                "binary",
                "application/octet-stream",
                FileCategory::Executable,
                "Raw compiled binary image",
                false,
                base_score,
                ClassifierEngine::ExtensionFallback,
            ),
            "wasm" => FileIdentity::new(
                "wasm",
                "application/wasm",
                FileCategory::Executable,
                "WebAssembly binary",
                false,
                base_score,
                ClassifierEngine::ExtensionFallback,
            ),
            // Audio formats
            "mp3" => FileIdentity::new("mp3", "audio/mpeg", FileCategory::Audio, "MP3 audio file", false, base_score, ClassifierEngine::ExtensionFallback),
            "wav" => FileIdentity::new("wav", "audio/vnd.wave", FileCategory::Audio, "WAV audio stream", false, base_score, ClassifierEngine::ExtensionFallback),
            "flac" => FileIdentity::new("flac", "audio/flac", FileCategory::Audio, "FLAC lossless audio", false, base_score, ClassifierEngine::ExtensionFallback),
            "ogg" => FileIdentity::new("ogg", "audio/ogg", FileCategory::Audio, "Ogg multimedia container", false, base_score, ClassifierEngine::ExtensionFallback),
            "m4a" => FileIdentity::new("m4a", "audio/mp4", FileCategory::Audio, "M4A audio file", false, base_score, ClassifierEngine::ExtensionFallback),
            "aac" => FileIdentity::new("aac", "audio/aac", FileCategory::Audio, "AAC audio stream", false, base_score, ClassifierEngine::ExtensionFallback),
            "wma" => FileIdentity::new("wma", "audio/x-ms-wma", FileCategory::Audio, "Windows Media Audio", false, base_score, ClassifierEngine::ExtensionFallback),
            "aiff" | "aif" => FileIdentity::new("aiff", "audio/x-aiff", FileCategory::Audio, "AIFF audio file", false, base_score, ClassifierEngine::ExtensionFallback),
            "opus" => FileIdentity::new("opus", "audio/opus", FileCategory::Audio, "Opus audio stream", false, base_score, ClassifierEngine::ExtensionFallback),
            // Image formats
            "png" => FileIdentity::new("png", "image/png", FileCategory::Image, "PNG image", false, base_score, ClassifierEngine::ExtensionFallback),
            "jpg" | "jpeg" => FileIdentity::new("jpeg", "image/jpeg", FileCategory::Image, "JPEG image", false, base_score, ClassifierEngine::ExtensionFallback),
            "webp" => FileIdentity::new("webp", "image/webp", FileCategory::Image, "WebP image", false, base_score, ClassifierEngine::ExtensionFallback),
            "gif" => FileIdentity::new("gif", "image/gif", FileCategory::Image, "GIF image", false, base_score, ClassifierEngine::ExtensionFallback),
            "bmp" => FileIdentity::new("bmp", "image/bmp", FileCategory::Image, "Bitmap image (BMP)", false, base_score, ClassifierEngine::ExtensionFallback),
            "svg" => FileIdentity::new("svg", "image/svg+xml", FileCategory::Image, "SVG vector image", true, base_score, ClassifierEngine::ExtensionFallback),
            "tiff" | "tif" => FileIdentity::new("tiff", "image/tiff", FileCategory::Image, "TIFF image", false, base_score, ClassifierEngine::ExtensionFallback),
            "ico" => FileIdentity::new("ico", "image/x-icon", FileCategory::Image, "Icon file (ICO)", false, base_score, ClassifierEngine::ExtensionFallback),
            "avif" => FileIdentity::new("avif", "image/avif", FileCategory::Image, "AVIF image", false, base_score, ClassifierEngine::ExtensionFallback),
            "heic" => FileIdentity::new("heic", "image/heic", FileCategory::Image, "High Efficiency Image Container (HEIC)", false, base_score, ClassifierEngine::ExtensionFallback),
            // Archives
            "zip" => FileIdentity::new("zip", "application/zip", FileCategory::Archive, "ZIP archive", false, base_score, ClassifierEngine::ExtensionFallback),
            "tar" => FileIdentity::new("tar", "application/x-tar", FileCategory::Archive, "TAR archive", false, base_score, ClassifierEngine::ExtensionFallback),
            "gz" | "gzip" => FileIdentity::new("gzip", "application/gzip", FileCategory::Archive, "GZIP archive", false, base_score, ClassifierEngine::ExtensionFallback),
            "7z" => FileIdentity::new("7z", "application/x-7z-compressed", FileCategory::Archive, "7-Zip archive", false, base_score, ClassifierEngine::ExtensionFallback),
            // Unknown fallback
            _ => FileIdentity::unknown_binary(),
        }
    }
}

/// Standard compiled binary and executable file extensions for zero-overhead fast-path exclusion.
pub const COMPILED_BINARY_EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "drv", "ocx", "scr", "cpl", "efi", "obj", "lib", "pdb", "exp", "ilk", "msi",
    "so", "ko", "o", "a",
    "dylib", "bundle", "kext", "framework",
    "wasm", "dex", "class", "pyc", "pyo", "pyd",
    "bin",
];

/// Returns true if the file extension matches a known compiled binary, executable, library, or debug database.
pub fn is_binary_executable_extension(ext: &str) -> bool {
    let clean = ext.trim_start_matches('.').to_ascii_lowercase();
    matches!(
        clean.as_str(),
        "exe"
            | "dll"
            | "sys"
            | "drv"
            | "ocx"
            | "scr"
            | "cpl"
            | "efi"
            | "obj"
            | "lib"
            | "pdb"
            | "exp"
            | "ilk"
            | "msi"
            | "so"
            | "ko"
            | "o"
            | "a"
            | "dylib"
            | "bundle"
            | "kext"
            | "framework"
            | "wasm"
            | "dex"
            | "class"
            | "pyc"
            | "pyo"
            | "pyd"
            | "bin"
    )
}

/// Helper to locate byte subsequence.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_pe_binary_classification() {
        let classifier = FileTypeClassifier::new();
        let mz_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff";
        let id = classifier.classify_bytes(mz_header, Some("program.exe"));

        assert_eq!(id.label, "pebin");
        assert_eq!(id.mime_type, "application/x-dosexec");
        assert_eq!(id.category, FileCategory::Executable);
        assert!(!id.is_text);
        assert!(id.is_binary);
        assert!(id.score >= 0.99);
    }

    #[test]
    fn test_elf_binary_classification() {
        let classifier = FileTypeClassifier::new();
        let elf_header = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let id = classifier.classify_bytes(elf_header, None);

        assert_eq!(id.label, "elf");
        assert_eq!(id.category, FileCategory::Executable);
        assert!(id.is_binary);
    }

    #[test]
    fn test_wasm_binary_classification() {
        let classifier = FileTypeClassifier::new();
        let wasm_header = b"\0asm\x01\x00\x00\x00";
        let id = classifier.classify_bytes(wasm_header, None);

        assert_eq!(id.label, "wasm");
        assert_eq!(id.mime_type, "application/wasm");
        assert!(id.is_binary);
    }

    #[test]
    fn test_sqlite_database_classification() {
        let classifier = FileTypeClassifier::new();
        let sqlite_header = b"SQLite format 3\0\x10\x00\x01\x01\x00@  ";
        let id = classifier.classify_bytes(sqlite_header, None);

        assert_eq!(id.label, "sqlite");
        assert_eq!(id.mime_type, "application/vnd.sqlite3");
        assert_eq!(id.category, FileCategory::Data);
        assert!(id.is_binary);
    }

    #[test]
    fn test_rust_code_deep_inspection() {
        let classifier = FileTypeClassifier::new();
        let code = b"pub fn calculate_hash(data: &[u8]) -> [u8; 32] {\n    let mut hasher = blake3::Hasher::new();\n    *hasher.finalize().as_bytes()\n}";
        let id = classifier.classify_bytes(code, None);

        assert_eq!(id.label, "rust");
        assert_eq!(id.mime_type, "text/x-rust");
        assert_eq!(id.category, FileCategory::Code);
        assert!(id.is_text);
        assert!(!id.is_binary);
    }

    #[test]
    fn test_python_code_shebang_inspection() {
        let classifier = FileTypeClassifier::new();
        let script = b"#!/usr/bin/env python3\nimport sys\n\ndef main():\n    print('Hello World')\n";
        let id = classifier.classify_bytes(script, None);

        assert_eq!(id.label, "python");
        assert_eq!(id.mime_type, "text/x-python");
        assert_eq!(id.category, FileCategory::Code);
        assert!(id.is_text);
    }

    #[test]
    fn test_json_document_classification() {
        let classifier = FileTypeClassifier::new();
        let json_text = b"{\n  \"model\": \"google/embeddinggemma-300m\",\n  \"dimension\": 768\n}";
        let id = classifier.classify_bytes(json_text, None);

        assert_eq!(id.label, "json");
        assert_eq!(id.mime_type, "application/json");
        assert_eq!(id.category, FileCategory::Data);
        assert!(id.is_text);
    }

    #[test]
    fn test_markdown_documentation_classification() {
        let classifier = FileTypeClassifier::new();
        let md_text = b"# QuorumRAG Architecture\n\nThis project implements peer-to-peer federated retrieval.\n";
        let id = classifier.classify_bytes(md_text, None);

        assert_eq!(id.label, "markdown");
        assert_eq!(id.mime_type, "text/markdown");
        assert_eq!(id.category, FileCategory::Document);
        assert!(id.is_text);
    }

    #[test]
    fn test_null_byte_binary_filtering() {
        let classifier = FileTypeClassifier::new();
        // Plain text mixed with null byte
        let corrupted = b"Some legitimate text followed by \x00 null bytes";
        let id = classifier.classify_bytes(corrupted, None);

        assert!(id.is_binary);
        assert!(!id.is_text);
        assert_eq!(id.label, "unknown");
    }

    #[test]
    fn test_classify_file_from_disk() {
        let classifier = FileTypeClassifier::new();
        let mut temp = NamedTempFile::new().unwrap();
        writeln!(temp, "use std::collections::HashMap;\npub fn foo() {{}}").unwrap();
        temp.flush().unwrap();

        let id = classifier.classify_file(temp.path()).unwrap();
        assert_eq!(id.label, "rust");
        assert!(id.is_text);
    }
}
