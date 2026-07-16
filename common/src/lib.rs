//! Common utilities for Custos.
//!
//! Provides shared abstractions, safety guards, helper macros,
//! and OS-level operations like thread pinning.

use std::io;

/// Pins the current thread to a specific CPU core.
///
/// # Safety
///
/// This function relies on `sched_setaffinity` on Linux which is an OS-specific
/// system call. On success, it guarantees the thread is pinned.
pub fn pin_thread_to_core(core_id: usize) -> Result<(), io::Error> {
    #[cfg(target_os = "linux")]
    unsafe {
        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(core_id, &mut cpuset);
        let pid = 0; // 0 matches the calling thread
        let res = libc::sched_setaffinity(
            pid,
            std::mem::size_of::<libc::cpu_set_t>(),
            &cpuset as *const libc::cpu_set_t,
        );
        if res != 0 {
            return Err(io::Error::last_os_error());
        }
        tracing::info!("Successfully pinned thread to CPU core {}", core_id);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = core_id;
        tracing::warn!("Thread pinning (sched_setaffinity) is only supported on Linux. Skipping thread pinning.");
    }
    Ok(())
}
