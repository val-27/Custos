//! Transmit optimizations for high-performance zero-copy rings.
//! Targets NUMA-aligned batching and hardware prefetching configurations.

/// Prefetches a packet data descriptor cacheline.
pub fn prefetch_cacheline(_addr: *const u8) {
    #[cfg(target_arch = "x86_64")]
    std::arch::x86_64::_mm_prefetch(_addr as *const i8, std::arch::x86_64::_MM_HINT_T0);
}
