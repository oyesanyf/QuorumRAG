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
}

#[cfg(not(any(windows, unix)))]
mod platform {
    pub fn set_background_thread_priority() -> bool {
        false
    }

    pub fn end_background_thread_priority() -> bool {
        false
    }
}

pub use platform::{end_background_thread_priority, set_background_thread_priority};

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
