//! Acceptance test suite for Milestone M8.5: Source Code & Temp File Exclusion (Feature 57).
//!
//! Validates:
//! 1. `test_classifier_router_excludes_all_source_code_extensions_when_active`
//! 2. `test_classifier_router_excludes_office_temporary_lock_and_autosave_files`
//! 3. `test_crawler_directory_pruning_and_file_filtering_under_source_exclusion`
//! 4. `test_magika_content_inspection_rejects_extensionless_scripts`

use std::fs::{create_dir_all, File};
use std::io::Write;
use tempfile::tempdir;

use quorum_classifier::FileCategory;
use quorum_ingest::classifier_router::{CandidateKind, ClassifierRouter, FilterDecision};
use quorum_ingest::config::IngestConfig;
use quorum_ingest::crawler::FilesystemCrawler;

#[test]
fn test_classifier_router_excludes_all_source_code_extensions_when_active() {
    let dir = tempdir().expect("tempdir creation");
    let base_path = dir.path();

    // All source code and config extensions excluded under Feature 57
    let all_excluded_extensions = [
        "rs", "py", "js", "ts", "jsx", "tsx", "c", "cpp", "h", "hpp",
        "cc", "cs", "java", "go", "kt", "rb", "php", "swift", "scala",
        "sh", "bash", "ps1", "bat", "cmd", "sql", "css", "scss", "less",
        "vue", "svelte", "toml", "yaml", "yml", "lock", "dat", "log",
        "json", "jsonl", "xml", "html", "htm", "tex", "aux", "bbl",
        "blg", "out", "toc", "synctex", "crt", "pem", "key",
    ];

    let mut active_cfg = IngestConfig::default();
    active_cfg.exclude_source_code = true;
    let router_active = ClassifierRouter::new(active_cfg);

    // 1. Verify that when exclude_source_code is true, EVERY excluded extension returns SkipBinary
    for ext in &all_excluded_extensions {
        let filename = format!("module_component.{}", ext);
        let file_path = base_path.join(&filename);
        {
            let mut f = File::create(&file_path).expect("create file");
            writeln!(f, "/* Source code definition for testing .{} */", ext).expect("write file");
        }

        let decision = router_active.evaluate_file(&file_path);
        assert!(
            matches!(decision, FilterDecision::SkipBinary { .. }),
            "Extension .{} must be rejected as SkipBinary when exclude_source_code is true, got {:?}",
            ext,
            decision
        );
    }

    // 2. Verify that when exclude_source_code is false, primary code extensions are accepted as Text
    let mut inactive_cfg = IngestConfig::default();
    inactive_cfg.exclude_source_code = false;
    let router_inactive = ClassifierRouter::new(inactive_cfg);

    let standard_code_extensions = [
        "rs", "py", "js", "ts", "jsx", "tsx", "c", "cpp", "go", "java",
        "kt", "cs", "sh", "ps1", "sql", "html", "css",
    ];

    for ext in &standard_code_extensions {
        let filename = format!("standard_code.{}", ext);
        let file_path = base_path.join(&filename);
        {
            let mut f = File::create(&file_path).expect("create file");
            writeln!(f, "/* Implementation body for .{} */", ext).expect("write file");
        }

        let decision = router_inactive.evaluate_file(&file_path);
        assert!(
            matches!(decision, FilterDecision::Accept { kind: CandidateKind::Text { .. }, .. }),
            "Extension .{} must be accepted as Text when exclude_source_code is false, got {:?}",
            ext,
            decision
        );
    }
}

#[test]
fn test_classifier_router_excludes_office_temporary_lock_and_autosave_files() {
    let dir = tempdir().expect("tempdir creation");
    let base_path = dir.path();

    let temp_filenames = [
        "~$Annual_Report_2026.docx",
        "~$Strategy_Presentation.pptx",
        "~$Financial_Model.xlsx",
        "~autosave_meeting_notes.docx",
        "~WRL0002.tmp",
        ".~lock.Employee_Handbook.docx#",
        "draft_document.tmp",
        "archive_backup.bak",
        "Autosaved Document.wbk",
    ];

    let mut config_active = IngestConfig::default();
    config_active.exclude_source_code = true;
    let router_active = ClassifierRouter::new(config_active);

    let config_inactive = IngestConfig::default();
    let router_inactive = ClassifierRouter::new(config_inactive);

    for name in &temp_filenames {
        let file_path = base_path.join(name);
        {
            let mut f = File::create(&file_path).expect("create file");
            writeln!(f, "Temporary office lock / autosave buffer binary header").expect("write file");
        }

        // Must be rejected as SkipHidden regardless of exclude_source_code toggle
        let dec_active = router_active.evaluate_file(&file_path);
        assert_eq!(
            dec_active,
            FilterDecision::SkipHidden,
            "Office temp/lock file '{}' must return SkipHidden when active, got {:?}",
            name,
            dec_active
        );

        let dec_inactive = router_inactive.evaluate_file(&file_path);
        assert_eq!(
            dec_inactive,
            FilterDecision::SkipHidden,
            "Office temp/lock file '{}' must return SkipHidden when inactive, got {:?}",
            name,
            dec_inactive
        );
    }
}

#[test]
fn test_crawler_directory_pruning_and_file_filtering_under_source_exclusion() {
    let dir = tempdir().expect("tempdir creation");
    let root = dir.path();

    // 1. Create document directories with legitimate user files
    let docs_dir = root.join("documents");
    create_dir_all(&docs_dir).expect("create docs dir");
    File::create(docs_dir.join("whitepaper.pdf")).unwrap().write_all(b"%PDF-1.5 legitimate document").unwrap();
    File::create(docs_dir.join("quarterly_report.docx")).unwrap().write_all(b"PK\x03\x04 docx document").unwrap();
    File::create(docs_dir.join("meeting_minutes.txt")).unwrap().write_all(b"Meeting minutes text").unwrap();
    File::create(docs_dir.join("architecture_overview.md")).unwrap().write_all(b"# Architecture Overview").unwrap();

    // 2. Create image directory with legitimate image files
    let img_dir = root.join("images");
    create_dir_all(&img_dir).expect("create img dir");
    File::create(img_dir.join("system_architecture.png")).unwrap().write_all(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR").unwrap();
    File::create(img_dir.join("logo.jpg")).unwrap().write_all(b"\xFF\xD8\xFF\xE0\0\x10JFIF").unwrap();
    File::create(img_dir.join("icon.svg")).unwrap().write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 100 100\"></svg>").unwrap();

    // 3. Create code directories that must be pruned / excluded
    let src_dir = root.join("src");
    create_dir_all(&src_dir).expect("create src dir");
    File::create(src_dir.join("main.rs")).unwrap().write_all(b"fn main() {}").unwrap();
    File::create(src_dir.join("lib.rs")).unwrap().write_all(b"pub fn add() {}").unwrap();

    let tools_dir = root.join("tools");
    create_dir_all(&tools_dir).expect("create tools dir");
    File::create(tools_dir.join("build_helper.py")).unwrap().write_all(b"print('building')").unwrap();

    let harfile_dir = root.join("harfile");
    create_dir_all(&harfile_dir).expect("create harfile dir");
    File::create(harfile_dir.join("dump.har")).unwrap().write_all(b"{\"log\": {}}").unwrap();

    // 4. Create lock & temp files that must be excluded
    File::create(docs_dir.join("~$quarterly_report.docx")).unwrap().write_all(b"lock bytes").unwrap();
    File::create(docs_dir.join("~WRL0001.tmp")).unwrap().write_all(b"temp bytes").unwrap();
    File::create(root.join("cargo.lock")).unwrap().write_all(b"version = 3").unwrap();
    File::create(root.join("scratchpad.tmp")).unwrap().write_all(b"scratch").unwrap();
    File::create(root.join("old_draft.bak")).unwrap().write_all(b"backup").unwrap();

    // Configure crawler with exclude_source_code = true
    let mut config = IngestConfig::default();
    config.exclude_source_code = true;
    config.watch_paths = vec![root.to_path_buf()];
    let crawler = FilesystemCrawler::new(config);

    let candidates = crawler.crawl_path_sync(root).expect("crawl_path_sync");

    let filenames: Vec<String> = candidates
        .iter()
        .filter_map(|p| p.path.file_name().and_then(|n| n.to_str()).map(|s| s.to_string()))
        .collect();

    // Must contain all legitimate user documents and images
    assert!(filenames.contains(&"whitepaper.pdf".to_string()), "PDF document must be crawled");
    assert!(filenames.contains(&"quarterly_report.docx".to_string()), "DOCX document must be crawled");
    assert!(filenames.contains(&"meeting_minutes.txt".to_string()), "TXT document must be crawled");
    assert!(filenames.contains(&"architecture_overview.md".to_string()), "MD document must be crawled");
    assert!(filenames.contains(&"system_architecture.png".to_string()), "PNG image must be crawled");
    assert!(filenames.contains(&"logo.jpg".to_string()), "JPG image must be crawled");
    assert!(filenames.contains(&"icon.svg".to_string()), "SVG image must be crawled");

    // Must NOT contain any source code or script files
    assert!(!filenames.contains(&"main.rs".to_string()), "main.rs must be excluded");
    assert!(!filenames.contains(&"lib.rs".to_string()), "lib.rs must be excluded");
    assert!(!filenames.contains(&"build_helper.py".to_string()), "build_helper.py must be excluded");

    // Must NOT contain any temporary or lock files
    assert!(!filenames.iter().any(|f| f.starts_with('~')), "Tilde temp files must be excluded");
    assert!(!filenames.iter().any(|f| f.ends_with(".tmp")), ".tmp files must be excluded");
    assert!(!filenames.iter().any(|f| f.ends_with(".bak")), ".bak files must be excluded");
    assert!(!filenames.contains(&"cargo.lock".to_string()), "cargo.lock must be excluded");
}

#[test]
fn test_magika_content_inspection_rejects_extensionless_scripts() {
    let dir = tempdir().expect("tempdir creation");
    let script_path = dir.path().join("automated_task_runner");

    // Write an extensionless executable script with Python shebang
    {
        let mut f = File::create(&script_path).expect("create script file");
        writeln!(f, "#!/usr/bin/env python3").expect("write shebang");
        writeln!(f, "import os, sys").expect("write import");
        writeln!(f, "def run():").expect("write def");
        writeln!(f, "    print('Executing background maintenance task')").expect("write body");
        writeln!(f, "if __name__ == '__main__': run()").expect("write main");
    }

    // 1. With exclude_source_code = true, Magika content inspection classifies as Code and rejects with SkipBinary
    let mut config_active = IngestConfig::default();
    config_active.exclude_source_code = true;
    let router_active = ClassifierRouter::new(config_active);

    let decision_active = router_active.evaluate_file(&script_path);
    match decision_active {
        FilterDecision::SkipBinary { identity } => {
            assert_eq!(
                identity.category,
                FileCategory::Code,
                "Extensionless python script must be classified as Code, got {:?}",
                identity.category
            );
        }
        other => panic!("Expected SkipBinary for extensionless script, got {:?}", other),
    }

    // 2. With exclude_source_code = false, the script is accepted for ingestion as CandidateKind::Text
    let config_inactive = IngestConfig::default();
    let router_inactive = ClassifierRouter::new(config_inactive);

    let decision_inactive = router_inactive.evaluate_file(&script_path);
    match decision_inactive {
        FilterDecision::Accept { identity, kind, .. } => {
            assert_eq!(
                identity.category,
                FileCategory::Code,
                "Must be recognized as Code"
            );
            assert!(
                matches!(kind, CandidateKind::Text { .. }),
                "Accepted as Text candidate"
            );
        }
        other => panic!("Expected Accept for extensionless script when code exclusion disabled, got {:?}", other),
    }
}
