//! Multi-queue sharding and CPU core thread pinning.
//! Supports shared-nothing Fast Path threads per interface queue.

use custos_common::pin_thread_to_core;
use custos_tx_optimizations::{
    get_interface_numa_node, pin_thread_to_numa_node_core, CompQueue, FillQueue, FrameDesc,
    OptimizedForwarder, RxQueue, TxQueue, Umem,
};

/// Per-queue resources owned exclusively by a sharded worker.
pub struct ShardResources {
    /// UMEM backing the RX/TX queue pair.
    pub umem: Umem,
    /// Receive queue for the assigned NIC queue.
    pub rx_q: RxQueue,
    /// Transmit queue for the assigned NIC queue.
    pub tx_q: TxQueue,
    /// Completion queue for transmitted descriptors.
    pub cq: CompQueue,
    /// Fill queue for recycled receive descriptors.
    pub fq: FillQueue,
}

/// Spawns a worker sharded to a specific core and queue ID.
///
/// # Performance Rationale
///
/// Implements a strict shared-nothing Fast Path polling loop.
/// The thread is pinned to the specified core, and operates on the dedicated queue
/// without cross-thread sharing of ring buffers or descriptors, avoiding cache bouncing.
/// It also queries the NIC's NUMA affinity and aligns the CPU core pinning accordingly.
pub fn spawn_sharded_worker(
    core_id: usize,
    queue_id: u32,
    interface: &str,
    resources: ShardResources,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. NUMA and Core Affinity Alignment
    // Try to retrieve NUMA node of the interface and align the polling thread.
    if let Some(numa_node) = get_interface_numa_node(interface) {
        tracing::info!(
            "Interface {} is bound to NUMA node {}. Aligning thread...",
            interface,
            numa_node
        );
        match pin_thread_to_numa_node_core(numa_node, core_id) {
            Ok(pinned_core) => {
                tracing::info!(
                    "Successfully pinned thread to NUMA-aligned core {}",
                    pinned_core
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to pin thread to NUMA-aligned core: {:?}. Falling back to core {}.",
                    e,
                    core_id
                );
                pin_thread_to_core(core_id)?;
            }
        }
    } else {
        tracing::info!(
            "No NUMA configuration found for interface {}. Pinning to core {}.",
            interface,
            core_id
        );
        pin_thread_to_core(core_id)?;
    }

    run_worker_loop(core_id, queue_id, resources)
}

/// Spawns a sharded worker backed by mock queues for simulation platforms.
#[cfg(not(target_os = "linux"))]
pub fn spawn_mock_sharded_worker(
    core_id: usize,
    queue_id: u32,
    interface: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (umem, _frame_descs) = Umem::new_mock(65536);
    spawn_sharded_worker(
        core_id,
        queue_id,
        interface,
        ShardResources {
            umem,
            rx_q: RxQueue::new(),
            tx_q: TxQueue::new(),
            cq: CompQueue::new(),
            fq: FillQueue::new(),
        },
    )
}

fn run_worker_loop(
    core_id: usize,
    queue_id: u32,
    resources: ShardResources,
) -> Result<(), Box<dyn std::error::Error>> {
    let ShardResources {
        umem,
        mut rx_q,
        tx_q,
        mut cq,
        mut fq,
    } = resources;

    let mut forwarder = OptimizedForwarder::new(tx_q, 64);
    let mut rx_descs = vec![FrameDesc::default(); 64];

    tracing::info!(
        "Starting sharded Fast Path event loop for queue={} on core={}",
        queue_id,
        core_id
    );

    // 3. Fast Path Polling Loop
    loop {
        // A. Consume from Rx Queue
        // SAFETY: Safe queue access.
        let received = unsafe { rx_q.consume(&mut rx_descs[..]) };

        if received > 0 {
            // B. Zero-copy process and forward
            for desc in rx_descs.iter().take(received) {
                let mut desc = *desc;
                // In-place payload modification / MAC swap simulation
                // SAFETY: Exclusive ownership of the received descriptor.
                unsafe {
                    let mut data = umem.data_mut(&mut desc);
                    let content = data.contents_mut();
                    if content.len() >= 12 {
                        let mut mac_dst = [0u8; 6];
                        let mut mac_src = [0u8; 6];
                        mac_dst.copy_from_slice(&content[0..6]);
                        mac_src.copy_from_slice(&content[6..12]);
                        content[0..6].copy_from_slice(&mac_src);
                        content[6..12].copy_from_slice(&mac_dst);
                    }

                    // Enqueue to TX batcher
                    let _ = forwarder.forward(desc)?;
                }
            }
        }

        // C. Periodic completion reclaiming and batch flushing
        // SAFETY: Safe to reclaim completed Tx frames and flush the batcher.
        unsafe {
            let _ = forwarder.reclaim_completed(&mut cq, &mut fq, &umem, &mut rx_q)?;
            let _ = forwarder.flush()?;
        }

        // Yield slightly if no packets in this cycle
        if received == 0 {
            std::hint::spin_loop();
        }
    }
}
