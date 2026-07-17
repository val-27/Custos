//! # Custos Transmit Optimizations Library
//!
//! This module provides a set of high-performance transmission utilities for zero-copy AF_XDP rings.
//! It includes:
//! - Batching submissions to the Tx queue to amortize syscall overhead.
//! - Prefetching packet data descriptors inside the Completion Queue to reduce L1/L2 cache misses.
//! - Lock-free, shared-nothing sharding designs.
//! - NUMA-node and CPU core affinity alignment.
//! - Cross-platform simulation and compilation support.

use std::fs;
use std::io;
use std::path::Path;

#[cfg(target_os = "linux")]
pub use xsk_rs::{CompQueue, Fd, FillQueue, FrameDesc, RxQueue, TxQueue, Umem};

#[cfg(not(target_os = "linux"))]
pub use mock::{CompQueue, Fd, FillQueue, FrameDesc, RxQueue, TxQueue, Umem};

/// Cache-line aligned statistics structure to prevent false sharing
/// across CPU cores in high-throughput multi-threaded configurations.
///
/// # Performance Rationale
///
/// CPU cache lines are typically 64 bytes. In a multi-core environment, if multiple threads write
/// to fields located within the same cache line, it triggers cache invalidations (cache bouncing).
/// Aligning this structure to 64 bytes ensures it has its own cache line, eliminating false sharing.
#[repr(align(64))]
#[derive(Debug, Default, Clone)]
pub struct CacheAlignedStats {
    /// Number of packets successfully transmitted.
    pub tx_packets: u64,
    /// Total number of bytes successfully transmitted.
    pub tx_bytes: u64,
    /// Number of packets recycled back to the Fill Queue.
    pub recycled_packets: u64,
}

/// Prefetches a packet data descriptor or raw packet payload cacheline.
///
/// # Safety
///
/// This function uses hardware assembly instructions to prefetch the memory address
/// into the L1 CPU cache without modifying execution state or causing exceptions on null pointers.
#[inline(always)]
pub fn prefetch_cacheline(addr: *const u8) {
    // SAFETY: Safe prefetch instruction wrapper. The address is not dereferenced.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            std::arch::x86_64::_mm_prefetch(addr as *const i8, std::arch::x86_64::_MM_HINT_T0);
        }
        #[cfg(target_arch = "aarch64")]
        {
            // Use inline assembly for standard L1 data prefetch on arm64/aarch64.
            std::arch::asm!(
                "prfm pldl1keep, [{x}]",
                x = in(reg) addr,
                options(nostack, preserves_flags, readonly)
            );
        }
    }
}

/// A high-performance batcher for submitting packet descriptors to the AF_XDP Tx Ring.
///
/// # Purpose
///
/// Submitting packets individually to the Tx ring requires frequent kernel transitions and
/// ring descriptor updates. `TxBatcher` buffers descriptors in userspace and pushes them in
/// larger chunks to amortize these synchronization/syscall costs.
pub struct TxBatcher {
    tx_q: TxQueue,
    buffer: Vec<FrameDesc>,
    batch_size: usize,
    stats: CacheAlignedStats,
}

impl TxBatcher {
    /// Creates a new `TxBatcher` wrapping a `TxQueue`.
    pub fn new(tx_q: TxQueue, batch_size: usize) -> Self {
        Self {
            tx_q,
            buffer: Vec::with_capacity(batch_size),
            batch_size,
            stats: CacheAlignedStats::default(),
        }
    }

    /// Enqueues a `FrameDesc` to the transmission buffer.
    /// If the buffer size reaches the designated `batch_size`, the batch is automatically flushed.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the descriptor contains a valid payload inside UMEM,
    /// and that the descriptor ownership is transferred to the Tx ring.
    #[inline]
    pub unsafe fn enqueue(&mut self, desc: FrameDesc) -> Result<usize, io::Error> {
        self.buffer.push(desc);
        if self.buffer.len() >= self.batch_size {
            self.flush()
        } else {
            Ok(0)
        }
    }

    /// Submits all currently buffered descriptors in a single batch to the Tx ring.
    ///
    /// # Safety
    ///
    /// Transmits all buffered descriptors to the network card.
    pub unsafe fn flush(&mut self) -> Result<usize, io::Error> {
        if self.buffer.is_empty() {
            return Ok(0);
        }

        let mut offset = 0;
        let total = self.buffer.len();

        while offset < total {
            // SAFETY: Transmit the slice of FrameDescs.
            let produced = self.tx_q.produce(&self.buffer[offset..total]);
            if produced > 0 {
                for desc in &self.buffer[offset..(offset + produced)] {
                    self.stats.tx_bytes += desc.lengths().data() as u64;
                }
                self.stats.tx_packets += produced as u64;
                offset += produced;
            } else {
                if self.tx_q.needs_wakeup() {
                    if let Err(err) = self.tx_q.wakeup() {
                        self.buffer.drain(..offset);
                        return Err(err);
                    }
                }
                // Yield thread execution briefly to allow the driver to clean up descriptors.
                std::hint::spin_loop();
            }
        }

        self.buffer.clear();
        if self.tx_q.needs_wakeup() {
            self.tx_q.wakeup()?;
        }
        Ok(offset)
    }

    /// Retrieves references to aligned transmission metrics.
    pub fn stats(&self) -> &CacheAlignedStats {
        &self.stats
    }

    /// Resets the internal transmit statistics counters.
    pub fn reset_stats(&mut self) {
        self.stats = CacheAlignedStats::default();
    }
}

/// Helper manager for zero-copy forwarding pipeline, combining batching and prefetch-driven reclamation.
pub struct OptimizedForwarder {
    batcher: TxBatcher,
    reclaim_buffer: Vec<FrameDesc>,
    pending_reclaim: Vec<FrameDesc>,
}

impl OptimizedForwarder {
    /// Creates a new `OptimizedForwarder` wrapping a `TxQueue`.
    pub fn new(tx_q: TxQueue, batch_size: usize) -> Self {
        Self {
            batcher: TxBatcher::new(tx_q, batch_size),
            reclaim_buffer: vec![FrameDesc::default(); batch_size],
            pending_reclaim: Vec::with_capacity(batch_size),
        }
    }

    /// Performs true zero-copy forwarding of a packet descriptor.
    /// Enqueues the descriptor directly to the Tx batcher without copying any frame data.
    ///
    /// # Safety
    ///
    /// The frame data descriptor must represent a valid, parsed, and modified packet
    /// originally retrieved from the RX ring.
    #[inline]
    pub unsafe fn forward(&mut self, desc: FrameDesc) -> Result<usize, io::Error> {
        self.batcher.enqueue(desc)
    }

    /// Reclaims completed transmission descriptors from the Completion Queue,
    /// applies CPU prefetch hints to the packet buffers, and returns them to the Fill Queue.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the completion and fill queues belong to the same UMEM
    /// memory pool, and that descriptors returned are valid to receive new packets.
    pub unsafe fn reclaim_completed(
        &mut self,
        cq: &mut CompQueue,
        fq: &mut FillQueue,
        umem: &Umem,
        rx_q: &mut RxQueue,
    ) -> Result<usize, io::Error> {
        if self.pending_reclaim.is_empty() {
            // A. Consume reclaimed descriptors from Completion Queue
            let completed = cq.consume(&mut self.reclaim_buffer[..]);
            if completed == 0 {
                return Ok(0);
            }

            // B. Apply CPU prefetch hints to the reclaimed UMEM frame buffers
            for desc in self.reclaim_buffer.iter().take(completed) {
                let data = umem.data(desc);
                let ptr = data.contents().as_ptr();
                prefetch_cacheline(ptr);
            }

            self.pending_reclaim
                .extend_from_slice(&self.reclaim_buffer[..completed]);
        }

        if self.pending_reclaim.is_empty() {
            return Ok(0);
        }

        // C. Produce reclaimed frames back to the RX Fill Queue
        let mut recycled = 0;
        while !self.pending_reclaim.is_empty() {
            let produced = fq.produce(&self.pending_reclaim[..]);
            if produced > 0 {
                self.batcher.stats.recycled_packets += produced as u64;
                recycled += produced;
                self.pending_reclaim.drain(..produced);
            } else {
                if fq.needs_wakeup() {
                    fq.wakeup(rx_q.fd_mut(), 0)?;
                }
                std::hint::spin_loop();
            }
        }

        Ok(recycled)
    }

    /// Flushes any pending packets remaining in the TX batch buffer.
    ///
    /// # Safety
    ///
    /// The caller must ensure each buffered descriptor is still owned by the batcher and can be
    /// transferred to the Tx ring.
    pub unsafe fn flush(&mut self) -> Result<usize, io::Error> {
        self.batcher.flush()
    }

    /// Returns a reference to the performance stats of the forwarder.
    pub fn stats(&self) -> &CacheAlignedStats {
        self.batcher.stats()
    }
}

/// Resolves the NUMA node for a given network interface.
///
/// Returns `None` if the interface or system does not expose NUMA node files (e.g. non-Linux systems).
pub fn get_interface_numa_node(interface: &str) -> Option<i32> {
    let path_str = format!("/sys/class/net/{}/device/numa_node", interface);
    let path = Path::new(&path_str);
    if path.exists() {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(numa_node) = content.trim().parse::<i32>() {
                // If it returns -1, it means the hardware is UMA or not specified
                return if numa_node >= 0 {
                    Some(numa_node)
                } else {
                    None
                };
            }
        }
    }
    None
}

/// Retrieves a list of CPU cores assigned to a specific NUMA node on Linux.
pub fn get_numa_cores(numa_node: i32) -> Result<Vec<usize>, io::Error> {
    let path_str = format!("/sys/devices/system/node/node{}/cpulist", numa_node);
    let path = Path::new(&path_str);
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "NUMA node cpulist not found on this system",
        ));
    }

    let content = fs::read_to_string(path)?;
    let mut cores = Vec::new();
    for part in content.trim().split(',') {
        if part.contains('-') {
            let mut range = part.split('-');
            if let (Some(start_str), Some(end_str)) = (range.next(), range.next()) {
                if let (Ok(start), Ok(end)) = (start_str.parse::<usize>(), end_str.parse::<usize>())
                {
                    for cpu in start..=end {
                        cores.push(cpu);
                    }
                }
            }
        } else if let Ok(cpu) = part.parse::<usize>() {
            cores.push(cpu);
        }
    }
    Ok(cores)
}

/// Pins the current thread to a CPU core matching the interface's NUMA node.
pub fn pin_thread_to_numa_node_core(
    numa_node: i32,
    preferred_core: usize,
) -> Result<usize, io::Error> {
    let cores = get_numa_cores(numa_node)?;
    if cores.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "No CPU cores available on target NUMA node",
        ));
    }
    let target_core = if cores.contains(&preferred_core) {
        preferred_core
    } else {
        cores[preferred_core % cores.len()]
    };
    custos_common::pin_thread_to_core(target_core)?;
    Ok(target_core)
}

/// Mock implementation of zero-copy AF_XDP rings for compilation and testing on macOS and other platforms.
#[cfg(not(target_os = "linux"))]
pub mod mock {
    use std::cell::UnsafeCell;
    use std::io;
    use std::sync::Mutex;

    /// Mock representation of a FrameDesc.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct FrameDesc {
        addr: u64,
        len: u32,
    }

    impl FrameDesc {
        /// Creates a new FrameDesc with address and length.
        pub fn new(addr: u64, len: u32) -> Self {
            Self { addr, len }
        }

        /// Returns the UMEM frame offset address.
        pub fn addr(&self) -> u64 {
            self.addr
        }

        /// Returns frame data length configurations.
        pub fn lengths(&self) -> FrameLengths {
            FrameLengths { len: self.len }
        }
    }

    /// Mock representation of FrameLengths.
    #[derive(Debug, Clone, Copy)]
    pub struct FrameLengths {
        len: u32,
    }

    impl FrameLengths {
        /// Returns the exact size of the payload data.
        pub fn data(&self) -> u32 {
            self.len
        }
    }

    /// Mock representation of Umem memory pool.
    pub struct Umem {
        storage: UnsafeCell<Vec<u8>>,
    }

    unsafe impl Send for Umem {}
    unsafe impl Sync for Umem {}

    impl Umem {
        /// Creates a mock Umem and a pool of frame descriptors.
        pub fn new_mock(size: usize) -> (Self, Vec<FrameDesc>) {
            let storage = UnsafeCell::new(vec![0u8; size]);
            let mut descs = Vec::new();
            for i in 0..(size / 2048) {
                descs.push(FrameDesc {
                    addr: (i * 2048) as u64,
                    len: 2048,
                });
            }
            (Self { storage }, descs)
        }

        /// Returns read-only access to a mock descriptor's packet memory.
        ///
        /// # Safety
        ///
        /// The descriptor address and length must describe a frame fully contained in this UMEM.
        pub unsafe fn data(&self, desc: &FrameDesc) -> UmemData<'_> {
            let ptr = self.storage.get();
            let slice = std::slice::from_raw_parts(ptr as *const u8, (*ptr).len());
            let offset = desc.addr as usize;
            UmemData {
                slice: &slice[offset..(offset + desc.len as usize)],
            }
        }

        /// Returns read-write access to a mock descriptor's packet memory.
        ///
        /// # Safety
        ///
        /// The descriptor address and length must describe a frame fully contained in this UMEM,
        /// and no other references to the same frame may exist while the mutable slice is live.
        pub unsafe fn data_mut(&self, desc: &mut FrameDesc) -> UmemDataMut<'_> {
            let ptr = self.storage.get();
            let slice = std::slice::from_raw_parts_mut(ptr as *mut u8, (*ptr).len());
            let offset = desc.addr as usize;
            UmemDataMut {
                slice: &mut slice[offset..(offset + desc.len as usize)],
            }
        }
    }

    /// Read-only wrapper around mock Umem payload memory.
    pub struct UmemData<'a> {
        slice: &'a [u8],
    }

    impl<'a> UmemData<'a> {
        /// Retrieves the underlying byte slice.
        pub fn contents(&self) -> &[u8] {
            self.slice
        }
    }

    /// Read-write wrapper around mock Umem payload memory.
    pub struct UmemDataMut<'a> {
        slice: &'a mut [u8],
    }

    impl<'a> UmemDataMut<'a> {
        /// Retrieves the underlying mutable byte slice.
        pub fn contents_mut(&mut self) -> &mut [u8] {
            self.slice
        }
    }

    // Shared thread-safe queue to simulate a virtual kernel ring interface
    static TX_IN_FLIGHT: Mutex<Vec<FrameDesc>> = Mutex::new(Vec::new());

    /// Mock TxQueue ring.
    pub struct TxQueue {}

    impl Default for TxQueue {
        fn default() -> Self {
            Self::new()
        }
    }

    impl TxQueue {
        /// Creates a new TxQueue.
        pub fn new() -> Self {
            Self {}
        }

        /// Inserts descriptors to the mock transmission ring.
        ///
        /// # Safety
        ///
        /// The caller must transfer ownership of the descriptors to the mock transmit ring until
        /// they are consumed from the completion queue.
        pub unsafe fn produce(&mut self, descs: &[FrameDesc]) -> usize {
            let mut lock = TX_IN_FLIGHT.lock().unwrap();
            lock.extend_from_slice(descs);
            descs.len()
        }

        /// Checks if driver needs wakeup call.
        pub fn needs_wakeup(&self) -> bool {
            false
        }

        /// Triggers manual kernel transmit wakeup.
        pub fn wakeup(&self) -> Result<(), io::Error> {
            Ok(())
        }
    }

    /// Mock Completion Queue ring.
    pub struct CompQueue {}

    impl Default for CompQueue {
        fn default() -> Self {
            Self::new()
        }
    }

    impl CompQueue {
        /// Creates a new CompQueue.
        pub fn new() -> Self {
            Self {}
        }

        /// Consumes completed descriptors from the virtual kernel ring.
        ///
        /// # Safety
        ///
        /// The destination slice must be valid for writes, and the caller must reclaim ownership
        /// only for the number of descriptors returned.
        pub unsafe fn consume(&mut self, descs: &mut [FrameDesc]) -> usize {
            let mut lock = TX_IN_FLIGHT.lock().unwrap();
            let to_consume = std::cmp::min(descs.len(), lock.len());
            for desc in descs.iter_mut().take(to_consume) {
                *desc = lock.remove(0);
            }
            to_consume
        }
    }

    /// Mock Fill Queue ring.
    pub struct FillQueue {}

    impl Default for FillQueue {
        fn default() -> Self {
            Self::new()
        }
    }

    impl FillQueue {
        /// Creates a new FillQueue.
        pub fn new() -> Self {
            Self {}
        }

        /// Returns descriptors to the receive ring.
        ///
        /// # Safety
        ///
        /// The caller must ensure the descriptors are no longer owned by the Tx or completion
        /// paths before recycling them to the fill ring.
        pub unsafe fn produce(&mut self, descs: &[FrameDesc]) -> usize {
            descs.len()
        }

        /// Checks if driver needs wakeup.
        pub fn needs_wakeup(&self) -> bool {
            false
        }

        /// Triggers wakeup.
        pub fn wakeup(&mut self, _fd: &mut Fd, _timeout: i32) -> Result<(), io::Error> {
            Ok(())
        }
    }

    /// Mock RxQueue ring.
    pub struct RxQueue {
        fd: Fd,
    }

    impl Default for RxQueue {
        fn default() -> Self {
            Self::new()
        }
    }

    impl RxQueue {
        /// Creates a new RxQueue.
        pub fn new() -> Self {
            Self { fd: Fd {} }
        }

        /// Receives descriptors.
        ///
        /// # Safety
        ///
        /// The destination slice must be valid for writes, and the caller must treat returned
        /// descriptors as exclusively owned by the receive path.
        pub unsafe fn consume(&mut self, _descs: &mut [FrameDesc]) -> usize {
            0
        }

        /// Returns mutable reference to the mock file descriptor.
        pub fn fd_mut(&mut self) -> &mut Fd {
            &mut self.fd
        }
    }

    /// Mock File Descriptor.
    pub struct Fd {}
}
