//! Common utilities for Custos.
//!
//! Provides shared abstractions, safety guards, helper macros,
//! OS-level operations like thread pinning, and shared enumerations
//! used across all processing phases.

use std::io;

pub mod metrics;
pub use metrics::{
    render_prometheus_metrics, start_metrics_server, MetricsConfig, MetricsServerHandle,
    ThreadStats,
};

// ---------------------------------------------------------------------------
// UMEM layout constants
// ---------------------------------------------------------------------------

/// Standard AF_XDP UMEM frame size (2 KiB).
///
/// Each frame must be a power of two and ≥ the maximum expected packet size.
/// 2 KiB comfortably fits an Ethernet MTU of 1500 bytes plus all headers.
pub const UMEM_FRAME_SIZE: u32 = 2048;

/// Default number of entries in the Fill and Completion rings.
///
/// Must be a power of two. Sized to match `UMEM_FRAME_SIZE` so that the rings
/// can hold one descriptor per frame, preventing descriptor starvation under
/// maximum batch load.
pub const UMEM_RING_SIZE: u32 = 2048;

// ---------------------------------------------------------------------------
// Operation mode
// ---------------------------------------------------------------------------

/// Packet processing mode for the AF_XDP fast-path loop.
///
/// Parsed from the `--mode` CLI argument on startup and stored as a compact
/// enum so that hot-path comparisons are integer checks, not string scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationMode {
    /// Drop every received packet immediately, recycling frames back to
    /// the Fill ring. Used for performance baseline / traffic absorption.
    Drop,
    /// Forward received packets unchanged to the TX ring.
    Forward,
    /// Swap Ethernet source and destination MAC addresses in-place, then
    /// forward the modified packet back on the same interface.
    Echo,
}

impl std::str::FromStr for OperationMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "drop" => Ok(Self::Drop),
            "forward" => Ok(Self::Forward),
            "echo" => Ok(Self::Echo),
            other => Err(format!(
                "unknown operation mode {other:?}; expected one of: drop, forward, echo"
            )),
        }
    }
}

impl std::fmt::Display for OperationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Drop => write!(f, "drop"),
            Self::Forward => write!(f, "forward"),
            Self::Echo => write!(f, "echo"),
        }
    }
}

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
