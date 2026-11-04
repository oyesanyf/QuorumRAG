use serde::{Deserialize, Serialize};
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareTelemetry {
    pub total_ram_gb: f64,
    pub free_ram_gb: f64,
    pub cpu_cores: usize,
    pub gpu_name: Option<String>,
    pub free_vram_mb: u64,
}

impl Default for HardwareTelemetry {
    fn default() -> Self {
        Self {
            total_ram_gb: 16.0,
            free_ram_gb: 8.0,
            cpu_cores: 8,
            gpu_name: None,
            free_vram_mb: 0,
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

        let (gpu_name, free_vram_mb) = Self::probe_gpu();

        let fresh = Self {
            total_ram_gb,
            free_ram_gb,
            cpu_cores,
            gpu_name,
            free_vram_mb,
        };

        if let Ok(mut guard) = cache_mutex.lock() {
            *guard = Some((Instant::now(), fresh.clone()));
        }

        fresh
    }

    fn probe_gpu() -> (Option<String>, u64) {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            use std::process::Command;

            let mut cmd = Command::new("nvidia-smi");
            cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
            cmd.args(["--query-gpu=name,memory.free", "--format=csv,noheader,nounits"]);

            if let Ok(output) = cmd.output() {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    let line = text.trim();
                    let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
                    if parts.len() >= 2 {
                        let name = parts[0].to_string();
                        let free_mb: u64 = parts[1].parse().unwrap_or(0);
                        return (Some(name), free_mb);
                    }
                }
            }
        }

        #[cfg(not(windows))]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("nvidia-smi")
                .args(["--query-gpu=name,memory.free", "--format=csv,noheader,nounits"])
                .output()
            {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    let line = text.trim();
                    let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
                    if parts.len() >= 2 {
                        let name = parts[0].to_string();
                        let free_mb: u64 = parts[1].parse().unwrap_or(0);
                        return (Some(name), free_mb);
                    }
                }
            }
        }

        (None, 0)
    }
}
