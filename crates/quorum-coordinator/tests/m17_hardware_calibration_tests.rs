//! Milestone M17: Hardware Calibration, Multi-GPU Probing, EDR Dynamic Available Memory Law & Ollama Lifecycle Tests.

use quorum_coordinator::hardware::HardwareTelemetry;
use quorum_coordinator::model_router::AutoFusionRouter;
use quorum_coordinator::offline_engine::DeterministicOfflineSynthesisEngine;
use quorum_coordinator::types::SynthesisModelFamily;

#[test]
fn test_multi_gpu_nvidia_smi_parsing_single() {
    let output = "NVIDIA GeForce RTX 4090, 24576, 22000\n";
    let (name, free_vram, total_vram, count) = HardwareTelemetry::parse_nvidia_smi_output(output);

    assert_eq!(count, 1);
    assert_eq!(name, Some("NVIDIA GeForce RTX 4090".to_string()));
    assert_eq!(free_vram, 22000);
    assert_eq!(total_vram, 24576);
}

#[test]
fn test_multi_gpu_nvidia_smi_parsing_dual_identical() {
    // Verifies multi-line CSV output aggregation across multiple GPUs
    let output = "NVIDIA GeForce RTX 4090, 24576, 22000\nNVIDIA GeForce RTX 4090, 24576, 23000\n";
    let (name, free_vram, total_vram, count) = HardwareTelemetry::parse_nvidia_smi_output(output);

    assert_eq!(count, 2);
    assert_eq!(name, Some("2x NVIDIA GeForce RTX 4090".to_string()));
    assert_eq!(free_vram, 45000);
    assert_eq!(total_vram, 49152);
}

#[test]
fn test_multi_gpu_nvidia_smi_parsing_quad_identical() {
    let output = "NVIDIA RTX A6000, 49152, 45000\nNVIDIA RTX A6000, 49152, 46000\nNVIDIA RTX A6000, 49152, 47000\nNVIDIA RTX A6000, 49152, 48000\n";
    let (name, free_vram, total_vram, count) = HardwareTelemetry::parse_nvidia_smi_output(output);

    assert_eq!(count, 4);
    assert_eq!(name, Some("4x NVIDIA RTX A6000".to_string()));
    assert_eq!(free_vram, 186000);
    assert_eq!(total_vram, 196608);
}

#[test]
fn test_multi_gpu_nvidia_smi_parsing_mixed_gpus() {
    let output = "NVIDIA GeForce RTX 4090, 24576, 22000\nNVIDIA GeForce RTX 3090, 24576, 21000\n";
    let (name, free_vram, total_vram, count) = HardwareTelemetry::parse_nvidia_smi_output(output);

    assert_eq!(count, 2);
    assert_eq!(name, Some("NVIDIA GeForce RTX 4090 + NVIDIA GeForce RTX 3090".to_string()));
    assert_eq!(free_vram, 43000);
    assert_eq!(total_vram, 49152);
}

#[test]
fn test_multi_gpu_nvidia_smi_parsing_two_column_fallback() {
    let output = "NVIDIA RTX 4000 Ada Generation, 18000\nNVIDIA RTX 4000 Ada Generation, 19000\n";
    let (name, free_vram, _, count) = HardwareTelemetry::parse_nvidia_smi_output(output);

    assert_eq!(count, 2);
    assert_eq!(name, Some("2x NVIDIA RTX 4000 Ada Generation".to_string()));
    assert_eq!(free_vram, 37000);
}

#[test]
fn test_multi_gpu_nvidia_smi_parsing_empty_or_whitespace() {
    let (name1, free1, total1, count1) = HardwareTelemetry::parse_nvidia_smi_output("");
    assert_eq!(count1, 0);
    assert_eq!(name1, None);
    assert_eq!(free1, 0);
    assert_eq!(total1, 0);

    let (name2, free2, total2, count2) = HardwareTelemetry::parse_nvidia_smi_output("   \n\n\r\n   ");
    assert_eq!(count2, 0);
    assert_eq!(name2, None);
    assert_eq!(free2, 0);
    assert_eq!(total2, 0);
}

#[test]
fn test_edr_dynamic_available_memory_matrix() {
    // 1. Tier 1: Free RAM >= 48GB OR Free VRAM >= 24GB -> 32b
    let hw_t1_ram = HardwareTelemetry {
        free_ram_gb: 52.0,
        free_vram_mb: 1_000,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw_t1_ram), "qwen2.5:32b");

    let hw_t1_vram = HardwareTelemetry {
        free_ram_gb: 4.0,
        free_vram_mb: 26_000,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw_t1_vram), "qwen2.5:32b");

    // 2. Tier 2: Free RAM >= 24GB OR Free VRAM >= 14GB -> 14b
    let hw_t2_ram = HardwareTelemetry {
        free_ram_gb: 28.0,
        free_vram_mb: 2_000,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw_t2_ram), "qwen2.5:14b");

    let hw_t2_vram = HardwareTelemetry {
        free_ram_gb: 4.0,
        free_vram_mb: 15_000,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw_t2_vram), "qwen2.5:14b");

    // 3. Tier 3: Free RAM >= 12GB OR Free VRAM >= 4.5GB -> 7b
    let hw_t3_ram = HardwareTelemetry {
        free_ram_gb: 14.0,
        free_vram_mb: 1_000,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw_t3_ram), "qwen2.5:7b");

    let hw_t3_vram = HardwareTelemetry {
        free_ram_gb: 4.0,
        free_vram_mb: 5_000,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw_t3_vram), "qwen2.5:7b");

    // 4. Tier 4: Free RAM >= 6GB OR Free VRAM >= 2GB -> 3b
    let hw_t4_ram = HardwareTelemetry {
        free_ram_gb: 7.5,
        free_vram_mb: 500,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw_t4_ram), "qwen2.5:3b");

    let hw_t4_vram = HardwareTelemetry {
        free_ram_gb: 2.0,
        free_vram_mb: 2_500,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw_t4_vram), "qwen2.5:3b");

    // 5. Tier 5: Free RAM < 6GB AND Free VRAM < 2GB -> 1.5b
    let hw_t5 = HardwareTelemetry {
        free_ram_gb: 3.5,
        free_vram_mb: 500,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw_t5), "qwen2.5:1.5b");

    // Invariant: Never append -coder
    assert!(!AutoFusionRouter::size_qwen_by_hardware(&hw_t1_ram).contains("-coder"));
    assert!(!AutoFusionRouter::size_qwen_by_hardware(&hw_t2_ram).contains("-coder"));
    assert!(!AutoFusionRouter::size_qwen_by_hardware(&hw_t3_ram).contains("-coder"));
    assert!(!AutoFusionRouter::size_qwen_by_hardware(&hw_t4_ram).contains("-coder"));
    assert!(!AutoFusionRouter::size_qwen_by_hardware(&hw_t5).contains("-coder"));
}

#[test]
fn test_small_computer_inventory_simulation() {
    // Simulation of constrained smaller computer from bug report:
    // User had installed:
    // embeddinggemma:latest
    // moondream:latest
    // deepseek-r1:1.5b
    // qwen2.5:1.5b
    // qwen2.5:0.5b
    // fenkohq/foundation-sec-8b:latest
    let hw_small = HardwareTelemetry {
        total_ram_gb: 16.0,
        free_ram_gb: 3.8, // Constrained free RAM
        cpu_cores: 4,
        gpu_name: None,
        free_vram_mb: 0,
        total_vram_mb: 0,
        gpu_count: 0,
    };

    let installed_inventory = vec![
        "embeddinggemma:latest".to_string(),
        "moondream:latest".to_string(),
        "deepseek-r1:1.5b".to_string(),
        "qwen2.5:1.5b".to_string(),
        "qwen2.5:0.5b".to_string(),
        "fenkohq/foundation-sec-8b:latest".to_string(),
    ];

    // 1. AutoFusion router selection:
    let (_fam, tag, rationale) = AutoFusionRouter::select_model_calibrated(
        SynthesisModelFamily::AutoFusion,
        "What is QuorumRAG?",
        &[],
        &hw_small,
        &installed_inventory,
    );

    // Assert it selects the installed 1.5b model fitting memory
    assert_eq!(tag, "qwen2.5:1.5b");
    // Assert it NEVER selects uninstalled gemma2:2b
    assert_ne!(tag, "gemma2:2b");
    // Assert it excludes embedding and vision models
    assert_ne!(tag, "embeddinggemma:latest");
    assert_ne!(tag, "moondream:latest");
    // Assert it excludes oversized 8B model on 3.8GB RAM host
    assert_ne!(tag, "fenkohq/foundation-sec-8b:latest");
    assert!(rationale.contains("host-calibrated"));

    // 2. If qwen2.5:1.5b is not installed, it falls back to highest-capability installed chat model: deepseek-r1:1.5b
    let alternate_inventory = vec![
        "embeddinggemma:latest".to_string(),
        "moondream:latest".to_string(),
        "deepseek-r1:1.5b".to_string(),
        "qwen2.5:0.5b".to_string(),
    ];
    let (_, tag2, _) = AutoFusionRouter::select_model_calibrated(
        SynthesisModelFamily::AutoFusion,
        "What is QuorumRAG?",
        &[],
        &hw_small,
        &alternate_inventory,
    );
    assert_eq!(tag2, "deepseek-r1:1.5b");
    assert_ne!(tag2, "gemma2:2b");

    // 3. DeterministicOfflineSynthesisEngine::resolve_ollama_model_tag verification
    let resolved = DeterministicOfflineSynthesisEngine::resolve_ollama_model_tag(
        "AutoFusion",
        &hw_small,
        &installed_inventory,
    );
    assert_eq!(resolved, "qwen2.5:1.5b");

    let resolved_gemma_req = DeterministicOfflineSynthesisEngine::resolve_ollama_model_tag(
        "gemma4:26b",
        &hw_small,
        &installed_inventory,
    );
    // Even when gemma4:26b is requested, on small computer it never returns uninstalled gemma2:2b
    assert_ne!(resolved_gemma_req, "gemma2:2b");
    assert!(resolved_gemma_req == "qwen2.5:1.5b" || resolved_gemma_req == "deepseek-r1:1.5b");

    // Explicit requests for pure embedding or vision models must not be selected for chat synthesis
    let resolved_emb = DeterministicOfflineSynthesisEngine::resolve_ollama_model_tag(
        "embeddinggemma:latest",
        &hw_small,
        &installed_inventory,
    );
    assert_ne!(resolved_emb, "embeddinggemma:latest");
    assert!(resolved_emb == "qwen2.5:1.5b" || resolved_emb == "deepseek-r1:1.5b");

    let resolved_vis = DeterministicOfflineSynthesisEngine::resolve_ollama_model_tag(
        "moondream:latest",
        &hw_small,
        &installed_inventory,
    );
    assert_ne!(resolved_vis, "moondream:latest");
    assert!(resolved_vis == "qwen2.5:1.5b" || resolved_vis == "deepseek-r1:1.5b");
}

#[test]
fn test_zero_touch_path_prepending_in_process_memory() {
    // Tests process-scoped PATH mutation without touching Windows Registry
    let initial_path = std::env::var("PATH").unwrap_or_default();
    let temp_test_dir = std::env::temp_dir().join("quorum_test_path_dir_m17");
    let _ = std::fs::create_dir_all(&temp_test_dir);

    // Prepend to process memory
    let mut paths = std::env::split_paths(&initial_path).collect::<Vec<_>>();
    if !paths.iter().any(|p| p == &temp_test_dir) {
        paths.insert(0, temp_test_dir.clone());
        if let Ok(new_path) = std::env::join_paths(paths) {
            std::env::set_var("PATH", new_path);
        }
    }

    let modified_path = std::env::var("PATH").unwrap_or_default();
    assert!(
        modified_path.contains(&temp_test_dir.to_string_lossy().to_string()),
        "Process PATH must contain prepended test directory in memory"
    );

    // Restore original PATH
    std::env::set_var("PATH", initial_path);

    // Verify binary detection does not panic
    let _ = DeterministicOfflineSynthesisEngine::detect_ollama_binary();
    let _ = std::fs::remove_dir_all(&temp_test_dir);
}

#[test]
fn test_disk_ollama_manifest_discovery() {
    let temp_models = std::env::temp_dir().join("quorum_test_ollama_models_m17");
    let manifests_root = temp_models
        .join("manifests")
        .join("registry.ollama.ai");

    let qwen_dir = manifests_root.join("library").join("qwen2.5");
    let deepseek_dir = manifests_root.join("library").join("deepseek-r1");
    let custom_dir = manifests_root.join("fenkohq").join("foundation-sec-8b");

    let _ = std::fs::create_dir_all(&qwen_dir);
    let _ = std::fs::create_dir_all(&deepseek_dir);
    let _ = std::fs::create_dir_all(&custom_dir);

    let _ = std::fs::write(qwen_dir.join("1.5b"), b"{}");
    let _ = std::fs::write(deepseek_dir.join("latest"), b"{}");
    let _ = std::fs::write(custom_dir.join("latest"), b"{}");

    // Point OLLAMA_MODELS to temp root
    let prev = std::env::var("OLLAMA_MODELS").ok();
    std::env::set_var("OLLAMA_MODELS", &temp_models);

    let discovered = DeterministicOfflineSynthesisEngine::discover_disk_ollama_manifests();

    // Cleanup env
    if let Some(p) = prev {
        std::env::set_var("OLLAMA_MODELS", p);
    } else {
        std::env::remove_var("OLLAMA_MODELS");
    }
    let _ = std::fs::remove_dir_all(&temp_models);

    assert!(
        discovered.contains(&"qwen2.5:1.5b".to_string()),
        "Disk discovery must find qwen2.5:1.5b"
    );
    assert!(
        discovered.contains(&"deepseek-r1:latest".to_string()),
        "Disk discovery must find deepseek-r1:latest"
    );
    assert!(
        discovered.contains(&"fenkohq/foundation-sec-8b:latest".to_string()),
        "Disk discovery must find fenkohq/foundation-sec-8b:latest"
    );
}

#[test]
fn test_adversarial_nvidia_smi_quad_gpus_with_unit_suffixes_and_whitespace() {
    let output = "  NVIDIA RTX A6000  ,  49152 MiB  ,  45000 MiB  \n\
                  NVIDIA RTX A6000 , 49152MB, 46000MB \n\
                  NVIDIA RTX A6000,49152 MiB,47000 MiB\n\
                  NVIDIA RTX A6000 , 49152 , 48000 \n";
    let (name, free_vram, total_vram, count) = HardwareTelemetry::parse_nvidia_smi_output(output);

    assert_eq!(count, 4);
    assert_eq!(name, Some("4x NVIDIA RTX A6000".to_string()));
    assert_eq!(free_vram, 186000, "Must sum free VRAM across 4 GPUs with unit suffixes");
    assert_eq!(total_vram, 196608, "Must sum total VRAM across 4 GPUs with unit suffixes");
}

#[test]
fn test_adversarial_nvidia_smi_single_gpu_trailing_newlines() {
    let output = "\n\nNVIDIA GeForce RTX 4090, 24576, 22000\r\n\r\n\n\n";
    let (name, free_vram, total_vram, count) = HardwareTelemetry::parse_nvidia_smi_output(output);

    assert_eq!(count, 1);
    assert_eq!(name, Some("NVIDIA GeForce RTX 4090".to_string()));
    assert_eq!(free_vram, 22000);
    assert_eq!(total_vram, 24576);
}

#[test]
fn test_adversarial_nvidia_smi_mixed_gpus_three_types() {
    let output = "NVIDIA GeForce RTX 4090, 24576, 22000\n\
                  NVIDIA GeForce RTX 3090, 24576, 20000\n\
                  NVIDIA A100-PCIE-40GB, 40960, 38000\n";
    let (name, free_vram, total_vram, count) = HardwareTelemetry::parse_nvidia_smi_output(output);

    assert_eq!(count, 3);
    assert_eq!(
        name,
        Some("NVIDIA GeForce RTX 4090 + NVIDIA GeForce RTX 3090 + NVIDIA A100-PCIE-40GB".to_string())
    );
    assert_eq!(free_vram, 80000);
    assert_eq!(total_vram, 90112);
}

#[test]
fn test_adversarial_nvidia_smi_malformed_and_non_numeric() {
    // Empty output
    let (name_empty, free_e, total_e, count_e) = HardwareTelemetry::parse_nvidia_smi_output("");
    assert_eq!(count_e, 0);
    assert_eq!(name_empty, None);
    assert_eq!(free_e, 0);
    assert_eq!(total_e, 0);

    // Malformed lines: no commas, empty names, non-numeric tokens
    let malformed = "just a random error message from driver\n\
                     ,,,\n\
                     NVIDIA RTX 4000, N/A, [Not Supported]\n\
                     NVIDIA RTX 4000, 20000, corrupted_token\n";
    let (name_m, free_m, total_m, count_m) = HardwareTelemetry::parse_nvidia_smi_output(malformed);

    assert_eq!(count_m, 2, "Only lines with valid GPU names should be counted");
    assert_eq!(name_m, Some("2x NVIDIA RTX 4000".to_string()));
    assert_eq!(free_m, 0, "Corrupted/non-numeric free VRAM should safely default to 0 without panic");
    assert_eq!(total_m, 20000);
}

#[test]
fn test_adversarial_edr_memory_law_exact_boundaries() {
    // Exactly at boundary: free RAM = 48.0 GB, free VRAM = 24000 MB -> qwen2.5:32b
    let hw_exact_32b = HardwareTelemetry {
        free_ram_gb: 48.0,
        free_vram_mb: 24_000,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw_exact_32b), "qwen2.5:32b");
    assert!(AutoFusionRouter::model_fits_free_memory("qwen2.5:32b", &hw_exact_32b));

    // Just below boundary: free RAM = 47.9 GB, free VRAM = 23999 MB -> qwen2.5:14b
    let hw_below_32b = HardwareTelemetry {
        free_ram_gb: 47.9,
        free_vram_mb: 23_999,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw_below_32b), "qwen2.5:14b");
    assert!(!AutoFusionRouter::model_fits_free_memory("qwen2.5:32b", &hw_below_32b));
    assert!(AutoFusionRouter::model_fits_free_memory("qwen2.5:14b", &hw_below_32b));

    // Exactly at 14b boundary: free RAM = 24.0 GB, free VRAM = 14000 MB
    let hw_exact_14b = HardwareTelemetry {
        free_ram_gb: 24.0,
        free_vram_mb: 14_000,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw_exact_14b), "qwen2.5:14b");

    // Just below 14b boundary: free RAM = 23.9 GB, free VRAM = 13999 MB -> qwen2.5:7b
    let hw_below_14b = HardwareTelemetry {
        free_ram_gb: 23.9,
        free_vram_mb: 13_999,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw_below_14b), "qwen2.5:7b");

    // Exactly at 7b boundary: free RAM = 12.0 GB, free VRAM = 4500 MB
    let hw_exact_7b = HardwareTelemetry {
        free_ram_gb: 12.0,
        free_vram_mb: 4_500,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw_exact_7b), "qwen2.5:7b");

    // Just below 7b boundary: free RAM = 11.9 GB, free VRAM = 4499 MB -> qwen2.5:3b
    let hw_below_7b = HardwareTelemetry {
        free_ram_gb: 11.9,
        free_vram_mb: 4_499,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw_below_7b), "qwen2.5:3b");

    // Exactly at 3b boundary: free RAM = 6.0 GB, free VRAM = 2000 MB
    let hw_exact_3b = HardwareTelemetry {
        free_ram_gb: 6.0,
        free_vram_mb: 2_000,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw_exact_3b), "qwen2.5:3b");

    // Just below 3b boundary: free RAM = 5.9 GB, free VRAM = 1999 MB -> qwen2.5:1.5b
    let hw_below_3b = HardwareTelemetry {
        free_ram_gb: 5.9,
        free_vram_mb: 1_999,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw_below_3b), "qwen2.5:1.5b");

    // Extremely constrained: free RAM = 0.5 GB, free VRAM = 0 MB -> qwen2.5:1.5b
    let hw_extreme_low = HardwareTelemetry {
        free_ram_gb: 0.5,
        free_vram_mb: 0,
        ..Default::default()
    };
    assert_eq!(AutoFusionRouter::size_qwen_by_hardware(&hw_extreme_low), "qwen2.5:1.5b");
    assert!(!AutoFusionRouter::model_fits_free_memory("qwen2.5:3b", &hw_extreme_low));
    assert!(AutoFusionRouter::model_fits_free_memory("qwen2.5:1.5b", &hw_extreme_low));
    assert!(AutoFusionRouter::model_fits_free_memory("qwen2.5:0.5b", &hw_extreme_low));
}
