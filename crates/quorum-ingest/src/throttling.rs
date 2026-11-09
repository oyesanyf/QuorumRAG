//! Host Overhead Throttling & Background Thread Priority Control.
//!
//! Enforces OS-specific low-priority background thread scheduling across:
//! - Windows: `THREAD_MODE_BACKGROUND_BEGIN` (CPU + low I/O priority) / `THREAD_MODE_BACKGROUND_END`.
//! - Linux: `setpriority(PRIO_PROCESS, 0, 19)` + `ioprio_set` (`IOPRIO_CLASS_IDLE`).
//! - macOS: `setpriority(PRIO_PROCESS, 0, 19)` + `pthread_set_qos_class_self_np(QOS_CLASS_BACKGROUND, 0)`.

#[cfg(windows)]
mod platform {
    extern "system" {
        fn GetCurrentThread() -> isize;
        fn SetThreadPriority(hThread: isize, nPriority: i32) -> i32;
        fn SetThreadAffinityMask(hThread: isize, dwThreadAffinityMask: usize) -> usize;
        fn GetCurrentProcess() -> isize;
        fn K32GetProcessMemoryInfo(
            Process: isize,
            ppsmemCounters: *mut ProcessMemoryCounters,
            cb: u32,
        ) -> i32;
    }

    #[repr(C)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }

    const THREAD_MODE_BACKGROUND_BEGIN: i32 = 0x00010000;
    const THREAD_MODE_BACKGROUND_END: i32 = 0x00020000;
    const THREAD_PRIORITY_BELOW_NORMAL: i32 = -1;

    /// Sets the current thread to background processing mode.
    /// Lowers CPU priority to background and disk I/O priority to IoPriorityVeryLow.
    pub fn set_background_thread_priority() -> bool {
        unsafe {
            // Prefer Windows background mode (both CPU and I/O priority lowered)
            if SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN) != 0 {
                return true;
            }
            // Fallback to below-normal CPU priority
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL) != 0
        }
    }

    /// Restores thread priority back to normal.
    pub fn end_background_thread_priority() -> bool {
        unsafe {
            SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_END) != 0
        }
    }

    /// Pins a background ingestion worker thread away from CPU Core 0 (when >= 4 logical cores exist)
    /// so Core 0 remains dedicated to foreground UI responsiveness and the main Tokio async reactor.
    pub fn pin_worker_thread_to_background_core(worker_index: usize) -> bool {
        let total_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(usize::BITS as usize);
        if total_cores < 4 {
            return false;
        }
        let bg_cores = total_cores - 1;
        let target_core = 1 + (worker_index % bg_cores);
        let mask: usize = 1usize << target_core;
        unsafe { SetThreadAffinityMask(GetCurrentThread(), mask) != 0 }
    }

    /// Returns the current process Resident Set Size (WorkingSetSize) in bytes.
    pub fn current_process_rss_bytes() -> u64 {
        unsafe {
            let mut counters = std::mem::zeroed::<ProcessMemoryCounters>();
            counters.cb = std::mem::size_of::<ProcessMemoryCounters>() as u32;
            if K32GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.cb) != 0 {
                counters.working_set_size as u64
            } else {
                0
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    const IOPRIO_CLASS_SHIFT: i32 = 13;
    const IOPRIO_CLASS_IDLE: i32 = 3;
    const IOPRIO_CLASS_BE: i32 = 2;
    const IOPRIO_WHO_PROCESS: i32 = 1;

    /// Sets thread to lowest CPU nice priority (19) and idle I/O priority.
    pub fn set_background_thread_priority() -> bool {
        unsafe {
            let _ = libc::setpriority(libc::PRIO_PROCESS, 0, 19);
            let ioprio = IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT;
            let _ = libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0, ioprio);
        }
        true
    }

    /// Restores thread CPU and I/O priority back to normal.
    pub fn end_background_thread_priority() -> bool {
        unsafe {
            let _ = libc::setpriority(libc::PRIO_PROCESS, 0, 0);
            let ioprio = (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | 4;
            let _ = libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0, ioprio);
        }
        true
    }

    /// Pins a background ingestion worker thread away from CPU Core 0 on Linux.
    pub fn pin_worker_thread_to_background_core(worker_index: usize) -> bool {
        let total_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        if total_cores < 4 {
            return false;
        }
        let bg_cores = total_cores - 1;
        let target_core = 1 + (worker_index % bg_cores);
        unsafe {
            let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_ZERO(&mut cpuset);
            libc::CPU_SET(target_core, &mut cpuset);
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &cpuset) == 0
        }
    }

    /// Reads resident set size (RSS) from `/proc/self/statm` on Linux.
    pub fn current_process_rss_bytes() -> u64 {
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            if let Some(rss_pages_str) = statm.split_whitespace().nth(1) {
                if let Ok(rss_pages) = rss_pages_str.parse::<u64>() {
                    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
                    return rss_pages.saturating_mul(page_size);
                }
            }
        }
        0
    }
}

#[cfg(target_os = "macos")]
mod platform {
    extern "C" {
        fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
    }

    const QOS_CLASS_BACKGROUND: u32 = 0x09;
    const QOS_CLASS_DEFAULT: u32 = 0x15;

    /// Sets thread to background QoS class and nice value 19 on macOS.
    pub fn set_background_thread_priority() -> bool {
        unsafe {
            let _ = libc::setpriority(libc::PRIO_PROCESS, 0, 19);
            let _ = pthread_set_qos_class_self_np(QOS_CLASS_BACKGROUND, 0);
        }
        true
    }

    /// Restores thread to default QoS class and nice value 0 on macOS.
    pub fn end_background_thread_priority() -> bool {
        unsafe {
            let _ = libc::setpriority(libc::PRIO_PROCESS, 0, 0);
            let _ = pthread_set_qos_class_self_np(QOS_CLASS_DEFAULT, 0);
        }
        true
    }

    /// On macOS Apple Silicon / Intel, background QoS routes threads to Efficiency cores (E-cores).
    pub fn pin_worker_thread_to_background_core(_worker_index: usize) -> bool {
        set_background_thread_priority()
    }

    /// Returns resident set size / max RSS in bytes on macOS via `getrusage`.
    pub fn current_process_rss_bytes() -> u64 {
        unsafe {
            let mut usage: libc::rusage = std::mem::zeroed();
            if libc::getrusage(libc::RUSAGE_SELF, &mut usage) == 0 {
                usage.ru_maxrss.max(0) as u64
            } else {
                0
            }
        }
    }
}

#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
mod platform {
    pub fn set_background_thread_priority() -> bool {
        unsafe {
            let _ = libc::setpriority(libc::PRIO_PROCESS, 0, 19);
        }
        true
    }

    pub fn end_background_thread_priority() -> bool {
        unsafe {
            let _ = libc::setpriority(libc::PRIO_PROCESS, 0, 0);
        }
        true
    }

    pub fn pin_worker_thread_to_background_core(_worker_index: usize) -> bool {
        set_background_thread_priority()
    }

    pub fn current_process_rss_bytes() -> u64 {
        unsafe {
            let mut usage: libc::rusage = std::mem::zeroed();
            if libc::getrusage(libc::RUSAGE_SELF, &mut usage) == 0 {
                (usage.ru_maxrss.max(0) as u64).saturating_mul(1024)
            } else {
                0
            }
        }
    }
}

#[cfg(not(any(windows, unix)))]
mod platform {
    pub fn set_background_thread_priority() -> bool {
        false
    }

    pub fn end_background_thread_priority() -> bool {
        false
    }

    pub fn pin_worker_thread_to_background_core(_worker_index: usize) -> bool {
        false
    }

    pub fn current_process_rss_bytes() -> u64 {
        0
    }
}

pub use platform::{
    current_process_rss_bytes, end_background_thread_priority,
    pin_worker_thread_to_background_core, set_background_thread_priority,
};

/// High-level helper applying OS background thread throttling.
pub fn apply_background_thread_throttling() -> Result<(), String> {
    if set_background_thread_priority() {
        Ok(())
    } else {
        Err("Failed to set background thread priority on active OS".to_string())
    }
}

/// Returns whether low-priority background scheduling is supported on the active OS.
pub fn is_background_throttling_supported() -> bool {
    cfg!(any(windows, unix))
}
