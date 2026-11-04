//! Host Overhead Throttling & Background Thread Priority Control.

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

#[cfg(not(windows))]
mod platform {
    pub fn set_background_thread_priority() -> bool {
        false
    }

    pub fn end_background_thread_priority() -> bool {
        false
    }
}

pub use platform::{end_background_thread_priority, set_background_thread_priority};
