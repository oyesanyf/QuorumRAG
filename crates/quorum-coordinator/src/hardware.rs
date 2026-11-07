use serde::{Deserialize, Serialize};
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareTelemetry {
    pub total_ram_gb: f64,
    pub free_ram_gb: f64,
    pub cpu_cores: usize,
    pub gpu_name: Option<String>,
    pub free_vram_mb: u64,
    #[serde(default)]
    pub total_vram_mb: u64,
    #[serde(default)]
    pub gpu_count: usize,
}

impl Default for HardwareTelemetry {
    fn default() -> Self {
        Self {
            total_ram_gb: 16.0,
            free_ram_gb: 8.0,
            cpu_cores: 8,
            gpu_name: None,
            free_vram_mb: 0,
            total_vram_mb: 0,
            gpu_count: 0,
        }
    }
}

impl HardwareTelemetry {
    /// Probes live host RAM via `sysinfo` and GPU VRAM via `nvidia-smi` (with CREATE_NO_WINDOW).
    /// Cached for 30 seconds and uses lightweight memory-only refresh to avoid process/disk scan stalls.
    pub fn probe() -> Self {
        use std::sync::{Mutex, OnceLock};
        use std::time::{Duration, Instant};

        static CACHE: OnceLock<Mutex<Option<(Instant, HardwareTelemetry)>>> = OnceLock::new();
        let cache_mutex = CACHE.get_or_init(|| Mutex::new(None));
        if let Ok(guard) = cache_mutex.lock() {
            if let Some((ts, ref cached)) = *guard {
                if ts.elapsed() < Duration::from_secs(30) {
                    return cached.clone();
                }
            }
        }

        let mut sys = System::new();
        sys.refresh_memory();

        let total_ram_gb = (sys.total_memory() as f64 / 1_073_741_824.0).max(1.0);
        let free_ram_gb = (sys.available_memory() as f64 / 1_073_741_824.0).max(0.5);
        let cpu_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(8)
            .max(1);

        let (gpu_name, free_vram_mb, total_vram_mb, gpu_count) = Self::probe_gpu();

        let fresh = Self {
            total_ram_gb,
            free_ram_gb,
            cpu_cores,
            gpu_name,
            free_vram_mb,
            total_vram_mb,
            gpu_count,
        };

        if let Ok(mut guard) = cache_mutex.lock() {
            *guard = Some((Instant::now(), fresh.clone()));
        }

        fresh
    }

    /// Parses multi-line `nvidia-smi` CSV output line-by-line.
    /// Handles both 3-column (`name,memory.total,memory.free`) and 2-column (`name,memory.free`) formats.
    /// Sums free and total VRAM across all detected discrete GPUs and formats compound GPU names cleanly.
    pub fn parse_nvidia_smi_output(stdout: &str) -> (Option<String>, u64, u64, usize) {
        let mut gpu_names: Vec<String> = Vec::new();
        let mut total_vram_mb: u64 = 0;
        let mut free_vram_mb: u64 = 0;

        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
            let parse_mb = |token: &str| -> u64 {
                let digits: String = token
                    .chars()
                    .skip_while(|c| !c.is_ascii_digit())
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                digits.parse::<u64>().unwrap_or(0)
            };
            if parts.len() >= 3 {
                let name = parts[0].to_string();
                let total_mb = parse_mb(parts[1]);
                let free_mb = parse_mb(parts[2]);
                if !name.is_empty() {
                    gpu_names.push(name);
                    total_vram_mb += total_mb;
                    free_vram_mb += free_mb;
                }
            } else if parts.len() == 2 {
                let name = parts[0].to_string();
                let free_mb = parse_mb(parts[1]);
                if !name.is_empty() {
                    gpu_names.push(name);
                    free_vram_mb += free_mb;
                }
            }
        }

        let gpu_count = gpu_names.len();
        if gpu_count == 0 {
            return (None, 0, 0, 0);
        }

        let formatted_name = Self::format_compound_gpu_name(&gpu_names);
        (Some(formatted_name), free_vram_mb, total_vram_mb, gpu_count)
    }

    /// Formats compound GPU names cleanly.
    /// If all GPU names are identical (e.g. two RTX 4090s), formats as `"2x NVIDIA GeForce RTX 4090"`.
    /// If distinct, joins with `" + "` (e.g. `"NVIDIA RTX 4090 + RTX 3090"`).
    pub fn format_compound_gpu_name(names: &[String]) -> String {
        if names.is_empty() {
            return String::new();
        }
        if names.len() == 1 {
            return names[0].clone();
        }
        let first = &names[0];
        if names.iter().all(|n| n == first) {
            format!("{}x {}", names.len(), first)
        } else {
            names.join(" + ")
        }
    }

    fn probe_gpu() -> (Option<String>, u64, u64, usize) {
        use std::sync::{Mutex, OnceLock};
        use std::time::{Duration, Instant};

        static GPU_CACHE: OnceLock<Mutex<Option<(Instant, (Option<String>, u64, u64, usize))>>> = OnceLock::new();
        let cache_mutex = GPU_CACHE.get_or_init(|| Mutex::new(None));
        if let Ok(guard) = cache_mutex.lock() {
            if let Some((ts, ref cached)) = *guard {
                // If no GPU was detected, cache the negative result for 5 minutes (300s).
                // If an NVIDIA GPU is present, refresh free VRAM every 30s.
                let ttl = if cached.3 == 0 {
                    Duration::from_secs(300)
                } else {
                    Duration::from_secs(30)
                };
                if ts.elapsed() < ttl {
                    return cached.clone();
                }
            }
        }

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            use std::path::Path;
            use std::process::Command;

            let candidate_binaries = [
                "nvidia-smi",
                r"C:\Windows\System32\nvidia-smi.exe",
                r"C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe",
            ];

            for binary in candidate_binaries {
                // Fast path: skip explicit file paths that do not exist on disk
                if binary.contains('\\') && !Path::new(binary).exists() {
                    continue;
                }

                // First attempt: 3-column query (name, memory.total, memory.free)
                let mut cmd = Command::new(binary);
                cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
                cmd.args(["--query-gpu=name,memory.total,memory.free", "--format=csv,noheader,nounits"]);

                if let Ok(output) = cmd.output() {
                    if output.status.success() {
                        let text = String::from_utf8_lossy(&output.stdout);
                        let (name, free_mb, total_mb, count) = Self::parse_nvidia_smi_output(&text);
                        if count > 0 {
                            let res = (name, free_mb, total_mb, count);
                            if let Ok(mut guard) = cache_mutex.lock() {
                                *guard = Some((Instant::now(), res.clone()));
                            }
                            return res;
                        }
                    }
                }

                // Fallback attempt: 2-column query (name, memory.free)
                let mut cmd2 = Command::new(binary);
                cmd2.creation_flags(0x08000000); // CREATE_NO_WINDOW
                cmd2.args(["--query-gpu=name,memory.free", "--format=csv,noheader,nounits"]);

                if let Ok(output) = cmd2.output() {
                    if output.status.success() {
                        let text = String::from_utf8_lossy(&output.stdout);
                        let (name, free_mb, total_mb, count) = Self::parse_nvidia_smi_output(&text);
                        if count > 0 {
                            let res = (name, free_mb, total_mb, count);
                            if let Ok(mut guard) = cache_mutex.lock() {
                                *guard = Some((Instant::now(), res.clone()));
                            }
                            return res;
                        }
                    }
                }
            }
        }

        #[cfg(not(windows))]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("nvidia-smi")
                .args(["--query-gpu=name,memory.total,memory.free", "--format=csv,noheader,nounits"])
                .output()
            {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    let (name, free_mb, total_mb, count) = Self::parse_nvidia_smi_output(&text);
                    if count > 0 {
                        let res = (name, free_mb, total_mb, count);
                        if let Ok(mut guard) = cache_mutex.lock() {
                            *guard = Some((Instant::now(), res.clone()));
                        }
                        return res;
                    }
                }
            }

            if let Ok(output) = Command::new("nvidia-smi")
                .args(["--query-gpu=name,memory.free", "--format=csv,noheader,nounits"])
                .output()
            {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    let (name, free_mb, total_mb, count) = Self::parse_nvidia_smi_output(&text);
                    if count > 0 {
                        let res = (name, free_mb, total_mb, count);
                        if let Ok(mut guard) = cache_mutex.lock() {
                            *guard = Some((Instant::now(), res.clone()));
                        }
                        return res;
                    }
                }
            }
        }

        let negative = (None, 0, 0, 0);
        if let Ok(mut guard) = cache_mutex.lock() {
            *guard = Some((Instant::now(), negative.clone()));
        }
        negative
    }
}
