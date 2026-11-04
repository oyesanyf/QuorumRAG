//! Adversarial Challenger Stress Test Suite for Milestone M8.5 (Feature 57).
//!
//! Independently verifies:
//! 1. `ClassifierRouter` rejects all source code extensions (including uppercase/mixed case, multi-dot) when `exclude_source_code = true`.
//! 2. `ClassifierRouter` rejects Office lock and autosave files (`~$*`, `~WRL*.tmp`, `report.bak`, `backup.wbk`, `.~lock*`, uppercase variants).
//! 3. `FilesystemCrawler` aggressively prunes directories (`node_modules`, `target`, `.git`, `__pycache__`, `.venv`, `tools`, `harfile`, `yara`, etc.),
//!    ensuring legitimate documents nested inside pruned directories are strictly ignored, while discovering legitimate documents and images in allowed trees.
//! 4. Magika content inspection rejects extensionless scripts (`#!/usr/bin/env python3`, `#!/bin/bash`, `#!/usr/bin/env node`, `#!/bin/sh`)
//!    under `exclude_source_code = true`.

use std::fs::{create_dir_all, File};
use std::io::Write;
use tempfile::tempdir;

use quorum_classifier::FileCategory;
use quorum_ingest::classifier_router::{CandidateKind, ClassifierRouter, FilterDecision};
use quorum_ingest::config::IngestConfig;
use quorum_ingest::crawler::FilesystemCrawler;

#[test]
fn test_adversarial_source_code_extension_rejection_and_case_insensitivity() {
    let dir = tempdir().expect("tempdir");
    let base = dir.path();

    let mut config = IngestConfig::default();
    config.exclude_source_code = true;
    let router = ClassifierRouter::new(config);

    // Adversarial variations: uppercase, mixed-case, multi-dot filenames
    let test_cases = [
        // Standard lowercase
        ("module.rs", true),
        ("script.py", true),
        ("frontend.js", true),
        ("types.ts", true),
        ("component.tsx", true),
        ("view.jsx", true),
        ("kernel.c", true),
        ("engine.cpp", true),
        ("header.h", true),
        ("header.hpp", true),
        ("main.cc", true),
        ("Service.cs", true),
        ("Application.java", true),
        ("server.go", true),
        ("activity.kt", true),
        ("gem.rb", true),
        ("index.php", true),
        ("App.swift", true),
        ("Build.scala", true),
        ("install.sh", true),
        ("setup.bash", true),
        ("deploy.ps1", true),
        ("build.bat", true),
        ("run.cmd", true),
        ("schema.sql", true),
        ("style.css", true),
        ("theme.scss", true),
        ("base.less", true),
        ("App.vue", true),
        ("Widget.svelte", true),
        ("Cargo.toml", true),
        ("config.yaml", true),
        ("manifest.yml", true),
        ("data.lock", true),
        ("table.dat", true),
        ("system.log", true),
        ("payload.json", true),
        ("stream.jsonl", true),
        ("pom.xml", true),
        ("index.html", true),
        ("page.htm", true),
        ("paper.tex", true),
        ("document.aux", true),
        ("refs.bbl", true),
        ("refs.blg", true),
        ("build.out", true),
        ("contents.toc", true),
        ("doc.synctex", true),
        ("cert.crt", true),
        ("key.pem", true),
        ("private.key", true),
        // Uppercase / mixed-case variations (Windows filesystem case-insensitivity stress)
        ("MAIN.RS", true),
        ("SCRIPT.PY", true),
        ("APP.JS", true),
        ("INDEX.TS", true),
        ("Core.CPP", true),
        ("Driver.C", true),
        ("CONFIG.TOML", true),
        ("SETTINGS.YAML", true),
        ("METRICS.JSON", true),
        ("DEPLOY.PS1", true),
        ("RUN.BAT", true),
        // Multi-dot filenames
        ("my.special.module.rs", true),
        ("archive.data.schema.json", true),
        ("app.config.prod.yaml", true),
        ("component.test.spec.tsx", true),
    ];

    for (filename, should_skip) in &test_cases {
        let p = base.join(filename);
        {
            let mut f = File::create(&p).unwrap();
            writeln!(f, "/* test source content for {} */", filename).unwrap();
        }

        let decision = router.evaluate_file(&p);
        if *should_skip {
            assert!(
                matches!(decision, FilterDecision::SkipBinary { .. }),
                "Filename '{}' must be rejected with SkipBinary, got {:?}",
                filename,
                decision
            );
        }
    }
}

#[test]
fn test_adversarial_office_temporary_lock_and_autosave_rejection() {
    let dir = tempdir().expect("tempdir");
    let base = dir.path();

    let mut config = IngestConfig::default();
    config.exclude_source_code = true;
    let router = ClassifierRouter::new(config);

    let temp_lock_files = [
        "~$Financial_Quarterly_Report_2026.docx",
        "~$Executive_Summary.pptx",
        "~$Payroll_Master.xlsx",
        "~autosave_meeting_notes.docx",
        "~WRL0002.tmp",
        "~WRL0003.tmp",
        ".~lock.Employee_Handbook.docx#",
        ".~lock.strategy.ods#",
        "draft_document.tmp",
        "archive_backup.bak",
        "Autosaved Document.wbk",
        // Uppercase variants
        "~$UPPERCASE_LOCK.DOCX",
        "REPORT_BACKUP.BAK",
        "AUTOSAVE_DRAFT.WBK",
        "STREAM_CACHE.TMP",
        // Space variations
        "~$ Space Document.docx",
        "~ Draft Space.docx",
    ];

    for name in &temp_lock_files {
        let p = base.join(name);
        {
            let mut f = File::create(&p).unwrap();
            writeln!(f, "Temporary lock binary header payload").unwrap();
        }

        let decision = router.evaluate_file(&p);
        assert_eq!(
            decision,
            FilterDecision::SkipHidden,
            "Office lock/temp file '{}' must be rejected with SkipHidden, got {:?}",
            name,
            decision
        );
    }
}

#[test]
fn test_adversarial_crawler_deep_pruning_and_boundary_isolation() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    // 1. Create deeply nested allowed directories with valid documents and images
    let deep_docs = root.join("corporate").join("legal").join("contracts");
    create_dir_all(&deep_docs).unwrap();
    File::create(deep_docs.join("master_agreement.pdf")).unwrap().write_all(b"%PDF-1.7 Master Agreement Body").unwrap();
    File::create(deep_docs.join("nda_template.docx")).unwrap().write_all(b"PK\x03\x04 NDA template").unwrap();
    File::create(deep_docs.join("addendum.txt")).unwrap().write_all(b"Plain text addendum").unwrap();
    File::create(deep_docs.join("specifications.md")).unwrap().write_all(b"# Technical Specifications").unwrap();
    File::create(deep_docs.join("schedule.xlsx")).unwrap().write_all(b"PK\x03\x04 Excel Schedule").unwrap();

    let deep_images = root.join("assets").join("brand").join("diagrams");
    create_dir_all(&deep_images).unwrap();
    File::create(deep_images.join("network_topology.png")).unwrap().write_all(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR").unwrap();
    File::create(deep_images.join("headshot.jpg")).unwrap().write_all(b"\xFF\xD8\xFF\xE0\0\x10JFIF").unwrap();
    File::create(deep_images.join("workflow.svg")).unwrap().write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>").unwrap();

    // 2. Adversarial Traps: Pruned directories containing files that LOOK like legitimate documents
    // Even if they have .pdf or .docx, they MUST be pruned because their parent directory is excluded!
    let trap_dirs = [
        root.join("node_modules").join("package_a"),
        root.join("target").join("debug").join("build"),
        root.join(".git").join("hooks"),
        root.join("__pycache__"),
        root.join(".venv").join("lib"),
        root.join("venv").join("bin"),
        root.join("tools").join("ci"),
        root.join("harfile").join("sessions"),
        root.join("yara").join("signatures"),
        root.join("rules").join("detection"),
        root.join("db").join("sqlite"),
        root.join("dataset").join("samples"),
    ];

    for td in &trap_dirs {
        create_dir_all(td).unwrap();
        File::create(td.join("trap_document.pdf")).unwrap().write_all(b"%PDF-1.4 Trap inside excluded folder").unwrap();
        File::create(td.join("trap_manual.docx")).unwrap().write_all(b"PK\x03\x04 Trap manual").unwrap();
        File::create(td.join("code_file.rs")).unwrap().write_all(b"fn evil() {}").unwrap();
    }

    // 3. Mixed temp and code files placed inside legitimate document directories
    File::create(deep_docs.join("~$master_agreement.docx")).unwrap().write_all(b"lock data").unwrap();
    File::create(deep_docs.join("~WRL9999.tmp")).unwrap().write_all(b"temp data").unwrap();
    File::create(deep_docs.join("contract_draft.bak")).unwrap().write_all(b"bak data").unwrap();
    File::create(deep_docs.join("contract_draft.wbk")).unwrap().write_all(b"wbk data").unwrap();
    File::create(deep_docs.join("contract_parser.rs")).unwrap().write_all(b"pub fn parse() {}").unwrap();
    File::create(deep_docs.join("contract_calc.py")).unwrap().write_all(b"def calc(): pass").unwrap();
    File::create(deep_docs.join("native_plugin.dll")).unwrap().write_all(b"MZ\x90\0DLL").unwrap();
    File::create(deep_docs.join("installer.exe")).unwrap().write_all(b"MZ\x90\0EXE").unwrap();

    // Execute crawler with exclude_source_code = true
    let mut config = IngestConfig::default();
    config.exclude_source_code = true;
    config.watch_paths = vec![root.to_path_buf()];
    let crawler = FilesystemCrawler::new(config);

    let candidates = crawler.crawl_path_sync(root).expect("crawl_path_sync");

    let discovered_paths: Vec<String> = candidates
        .iter()
        .map(|c| c.path.to_string_lossy().to_string())
        .collect();

    let discovered_names: Vec<String> = candidates
        .iter()
        .filter_map(|c| c.path.file_name().and_then(|n| n.to_str()).map(|s| s.to_string()))
        .collect();

    // 1. Legitimate files must be present
    assert!(discovered_names.contains(&"master_agreement.pdf".to_string()), "PDF must be discovered");
    assert!(discovered_names.contains(&"nda_template.docx".to_string()), "DOCX must be discovered");
    assert!(discovered_names.contains(&"addendum.txt".to_string()), "TXT must be discovered");
    assert!(discovered_names.contains(&"specifications.md".to_string()), "MD must be discovered");
    assert!(discovered_names.contains(&"schedule.xlsx".to_string()), "XLSX must be discovered");
    assert!(discovered_names.contains(&"network_topology.png".to_string()), "PNG must be discovered");
    assert!(discovered_names.contains(&"headshot.jpg".to_string()), "JPG must be discovered");
    assert!(discovered_names.contains(&"workflow.svg".to_string()), "SVG must be discovered");

    // 2. Traps inside pruned directories must NEVER be discovered
    for path in &discovered_paths {
        assert!(!path.contains("node_modules"), "node_modules must be pruned: {}", path);
        assert!(!path.contains("target"), "target must be pruned: {}", path);
        assert!(!path.contains(".git"), ".git must be pruned: {}", path);
        assert!(!path.contains("__pycache__"), "__pycache__ must be pruned: {}", path);
        assert!(!path.contains(".venv"), ".venv must be pruned: {}", path);
        assert!(!path.contains("tools"), "tools must be pruned: {}", path);
        assert!(!path.contains("harfile"), "harfile must be pruned: {}", path);
        assert!(!path.contains("yara"), "yara must be pruned: {}", path);
        assert!(!path.contains("rules"), "rules must be pruned: {}", path);
        assert!(!path.contains("db"), "db must be pruned: {}", path);
        assert!(!path.contains("dataset"), "dataset must be pruned: {}", path);
    }

    // 3. Mixed code, temp, and binary files in allowed directory must be filtered out
    assert!(!discovered_names.contains(&"contract_parser.rs".to_string()), "RS file must be filtered");
    assert!(!discovered_names.contains(&"contract_calc.py".to_string()), "PY file must be filtered");
    assert!(!discovered_names.contains(&"installer.exe".to_string()), "EXE file must be filtered");
    assert!(!discovered_names.contains(&"native_plugin.dll".to_string()), "DLL file must be filtered");
    assert!(!discovered_names.iter().any(|n| n.starts_with('~')), "Tilde lock files must be filtered");
    assert!(!discovered_names.iter().any(|n| n.ends_with(".tmp")), ".tmp files must be filtered");
    assert!(!discovered_names.iter().any(|n| n.ends_with(".bak")), ".bak files must be filtered");
    assert!(!discovered_names.iter().any(|n| n.ends_with(".wbk")), ".wbk files must be filtered");

    // Total count of discovered files must equal exactly the 8 legitimate files
    assert_eq!(
        candidates.len(),
        8,
        "Exactly 8 legitimate documents/images must be discovered, got {}: {:?}",
        candidates.len(),
        discovered_names
    );
}

#[test]
fn test_adversarial_magika_extensionless_scripts_rejected_under_code_exclusion() {
    let dir = tempdir().expect("tempdir");
    let base = dir.path();

    let mut config = IngestConfig::default();
    config.exclude_source_code = true;
    let router = ClassifierRouter::new(config);

    // Extensionless scripts with various shebangs -> Magika classifies as Code and router rejects as SkipBinary
    let scripts = [
        ("python_runner", "#!/usr/bin/env python3\nimport sys\nprint('hello')\n"),
        ("bash_deployer", "#!/bin/bash\necho 'deploying service'\nexit 0\n"),
        ("node_worker", "#!/usr/bin/env node\nconsole.log('worker active');\n"),
        ("sh_script", "#!/bin/sh\nset -e\necho 'running'\n"),
    ];

    for (name, content) in &scripts {
        let p = base.join(name);
        {
            let mut f = File::create(&p).unwrap();
            f.write_all(content.as_bytes()).unwrap();
        }

        let decision = router.evaluate_file(&p);
        match decision {
            FilterDecision::SkipBinary { identity } => {
                assert_eq!(
                    identity.category,
                    FileCategory::Code,
                    "Script '{}' must be categorized as FileCategory::Code by Magika, got {:?}",
                    name,
                    identity.category
                );
            }
            other => panic!("Script '{}' must be rejected with SkipBinary, got {:?}", name, other),
        }
    }

    // Extensionless markdown document (starts with '# ') is recognized as Document and Accepted
    let md_path = base.join("QUORUMRAG_SPEC");
    {
        let mut f = File::create(&md_path).unwrap();
        writeln!(f, "# QuorumRAG System Architecture\n\nThis document describes peer-to-peer retrieval.").unwrap();
    }
    let decision = router.evaluate_file(&md_path);
    match decision {
        FilterDecision::Accept { kind, identity, .. } => {
            assert_eq!(identity.category, FileCategory::Document);
            assert!(matches!(kind, CandidateKind::Text { .. }));
        }
        other => panic!("Extensionless markdown spec should be Accepted, got {:?}", other),
    }
}
