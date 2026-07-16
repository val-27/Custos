//! Multi-queue sharding and CPU core thread pinning.
//! Supports shared-nothing Fast Path threads per interface queue.

use custos_tx_optimizations::{
    RxQueue, TxQueue, CompQueue, FillQueue, Umem, FrameDesc, OptimizedForwarder,
    get_interface_numa_node, pin_thread_to_numa_node_core
};
use custos_common::pin_thread_to_core;

/// Spawns a worker sharded to a specific core and queue ID.
///
/// # Performance Rationale
///
/// Implements a strict shared-nothing Fast Path polling loop.
/// The thread is pinned to the specified core, and operates on the dedicated queue
/// without cross-thread sharing of ring buffers or descriptors, avoiding cache bouncing.
/// It also queries the NIC's NUMA affinity and aligns the CPU core pinning accordingly.
pub fn spawn_sharded_worker(core_id: usize, queue_id: u32, interface: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 1. NUMA and Core Affinity Alignment
    // Try to retrieve NUMA node of the interface and align the polling thread.
    if let Some(numa_node) = get_interface_numa_node(interface) {
        tracing::info!(
            "Interface {} is bound to NUMA node {}. Aligning thread...",
            interface, numa_node
        );
        match pin_thread_to_numa_node_core(numa_node) {
            Ok(pinned_core) => {
                tracing::info!("Successfully pinned thread to NUMA-aligned core {}", pinned_core);
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to pin thread to NUMA-aligned core: {:?}. Falling back to core {}.",
                    e, core_id
                );
                pin_thread_to_core(core_id)?;
            }
        }
    } else {
        tracing::info!("No NUMA configuration found for interface {}. Pinning to core {}.", interface, core_id);
        pin_thread_to_core(core_id)?;
    }

    // 2. Queue and UMEM setup
    // For cross-platform simulation and testing, we use the platform-appropriate types
    // from custos-tx-optimizations.
    let (umem, _frame_descs) = Umem::new_mock(65536);
    let mut rx_q = RxQueue::new();
    let tx_q = TxQueue::new();
    let mut cq = CompQueue::new();
    let mut fq = FillQueue::new();

    let mut forwarder = OptimizedForwarder::new(tx_q, 64);
    let mut rx_descs = vec![FrameDesc::default(); 64];

    tracing::info!(
        "Starting sharded Fast Path event loop for queue={} on core={}",
        queue_id, core_id
    );

    // 3. Fast Path Polling Loop
    loop {
        // A. Consume from Rx Queue
        // SAFETY: Safe queue access.
        let received = unsafe { rx_q.consume(&mut rx_descs[..]) };

        if received > 0 {
            // B. Zero-copy process and forward
            for i in 0..received {
                let mut desc = rx_descs[i];
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
