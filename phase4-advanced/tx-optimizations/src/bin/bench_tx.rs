//! Benchmark program to measure before/after performance of AF_XDP TX optimizations.
//! Runs on both Linux and macOS (via mock).

use std::time::Instant;
use custos_tx_optimizations::{
    mock::{CompQueue, FillQueue, FrameDesc, RxQueue, TxQueue, Umem},
    OptimizedForwarder,
};

const TOTAL_PACKETS: u64 = 10_000_000;
const BATCH_SIZE: usize = 64;

fn main() {
    println!("==========================================================");
    println!("          CUSTOS TX OPTIMIZATION BENCHMARK RUNNER         ");
    println!("==========================================================");
    println!("Total Packets to process: {}", TOTAL_PACKETS);
    println!("Optimized Batch Size:     {}", BATCH_SIZE);
    println!("----------------------------------------------------------");

    // 1. Run Baseline (Unoptimized, batch size = 1, no prefetch)
    println!("Running Baseline Benchmark (Unoptimized)...");
    let (baseline_pps, baseline_duration) = run_baseline();
    println!("Baseline:  {:.2} Mpps (Duration: {:.2?})", baseline_pps / 1_000_000.0, baseline_duration);
    println!("----------------------------------------------------------");

    // 2. Run Optimized (Batch size = 64, with prefetch)
    println!("Running Optimized Benchmark (Batch size = 64 + Prefetch)...");
    let (opt_pps, opt_duration) = run_optimized();
    println!("Optimized: {:.2} Mpps (Duration: {:.2?})", opt_pps / 1_000_000.0, opt_duration);
    println!("----------------------------------------------------------");

    // 3. Print Results Comparison
    let speedup = opt_pps / baseline_pps;
    println!("==========================================================");
    println!("                    BENCHMARK RESULTS                     ");
    println!("==========================================================");
    println!("Mode                  | Throughput (Mpps) | Latency / Packet");
    println!("----------------------------------------------------------");
    println!(
        "Unoptimized (Base)    | {:<17.2} | {:.4} ns",
        baseline_pps / 1_000_000.0,
        (baseline_duration.as_nanos() as f64) / (TOTAL_PACKETS as f64)
    );
    println!(
        "Optimized (Batch+Pref)| {:<17.2} | {:.4} ns",
        opt_pps / 1_000_000.0,
        (opt_duration.as_nanos() as f64) / (TOTAL_PACKETS as f64)
    );
    println!("----------------------------------------------------------");
    println!("Performance Uplift: {:.2}x Speedup", speedup);
    println!("==========================================================");
}

fn run_baseline() -> (f64, std::time::Duration) {
    let (_umem, frame_descs) = Umem::new_mock(65536);
    let mut tx_q = TxQueue::new();
    let mut cq = CompQueue::new();
    let mut fq = FillQueue::new();
    let mut rx_q = RxQueue::new();

    let start = Instant::now();
    let mut processed = 0u64;

    while processed < TOTAL_PACKETS {
        // Submit one frame
        let desc = frame_descs[(processed % frame_descs.len() as u64) as usize];
        unsafe {
            let produced = tx_q.produce(&[desc]);
            assert_eq!(produced, 1);
            if tx_q.needs_wakeup() {
                tx_q.wakeup().unwrap();
            }
        }

        // Reclaim one frame
        let mut reclaim_buf = [FrameDesc::default(); 1];
        unsafe {
            let completed = cq.consume(&mut reclaim_buf[..]);
            assert_eq!(completed, 1);
            let recycled = fq.produce(&reclaim_buf[..]);
            assert_eq!(recycled, 1);
            if fq.needs_wakeup() {
                fq.wakeup(rx_q.fd_mut(), 0).unwrap();
            }
        }

        processed += 1;
    }

    let duration = start.elapsed();
    let pps = (TOTAL_PACKETS as f64) / duration.as_secs_f64();
    (pps, duration)
}

fn run_optimized() -> (f64, std::time::Duration) {
    let (umem, frame_descs) = Umem::new_mock(65536);
    let tx_q = TxQueue::new();
    let mut cq = CompQueue::new();
    let mut fq = FillQueue::new();
    let mut rx_q = RxQueue::new();

    let mut forwarder = OptimizedForwarder::new(tx_q, BATCH_SIZE);

    let start = Instant::now();
    let mut processed = 0u64;

    while processed < TOTAL_PACKETS {
        // Forward in batches
        let desc = frame_descs[(processed % frame_descs.len() as u64) as usize];
        unsafe {
            let _ = forwarder.forward(desc).unwrap();
        }

        processed += 1;

        // Periodically reclaim completed frames in batch
        if processed % BATCH_SIZE as u64 == 0 {
            unsafe {
                let _ = forwarder.reclaim_completed(&mut cq, &mut fq, &umem, &mut rx_q).unwrap();
            }
        }
    }

    // Flush any remaining
    unsafe {
        let _ = forwarder.flush().unwrap();
        // Final reclaim to ensure cleanup matches
        let _ = forwarder.reclaim_completed(&mut cq, &mut fq, &umem, &mut rx_q).unwrap();
    }

    let duration = start.elapsed();
    let pps = (TOTAL_PACKETS as f64) / duration.as_secs_f64();
    (pps, duration)
}
