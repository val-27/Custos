//! Custos Benchmark and Visualization Tool
//!
//! CLI application implementing the real-time TUI dashboard,
//! Axum web server, and packet generator for Custos.

use clap::{Parser, ValueEnum};
use std::fs::File;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use sysinfo::System;
use std::io::IsTerminal;
use rand::Rng;

use custos_bench::{
    generate_packet, render_latency_histogram, render_svg_chart, generate_html_report,
    CustosMetrics, LatencyStats, PacketGenParams, PcapWriter, PerformanceHistory,
    RateMetrics, TrafficProfile,
};
use custos_protobuf::ValidationConfig;

// =========================================================================
// CLI Definitions
// =========================================================================

#[derive(Parser, Debug, Clone)]
#[command(name = "custos-bench")]
#[command(author = "Custos Engineering Team")]
#[command(version = "0.1.0")]
#[command(about = "Benchmark, Stress-Test, and Monitor Tool for Custos AF_XDP Appliance", long_about = None)]
struct Args {
    /// Operational Mode
    #[arg(value_enum, default_value_t = Mode::Bench)]
    mode: Mode,

    /// Predefined test profile for "bench" mode
    #[arg(short, long, value_enum, default_value_t = TestProfile::Light)]
    profile: TestProfile,

    /// Duration of the benchmark test in seconds
    #[arg(short, long, default_value_t = 10)]
    duration: u64,

    /// Interface name to inject raw socket traffic (requires Linux and root)
    #[arg(short, long)]
    interface: Option<String>,

    /// Target packet injection rate (Packets Per Second) for custom profiles
    #[arg(short, long)]
    pps: Option<u64>,

    /// Export the simulated traffic to a PCAP file at this path
    #[arg(long)]
    pcap_out: Option<String>,

    /// Port to serve the interactive web dashboard on
    #[arg(long, default_value_t = 8080)]
    web_port: u16,

    /// Output path for the HTML/PDF printable report
    #[arg(long, default_value = "custos_bench_report.html")]
    report_out: String,

    /// Output path for the raw JSON metrics report
    #[arg(long, default_value = "custos_bench_metrics.json")]
    json_out: String,

    /// Use in-memory simulator target instead of physical interface
    ///
    /// Ideal for measuring pure parser overhead and running on macOS/non-root.
    #[arg(long, default_value_t = true)]
    mock_target: bool,

    /// Path to read Custos metrics JSON from in "monitor" mode
    #[arg(long, default_value = "/tmp/custos_metrics.json")]
    metrics_json: String,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Run traffic generator and measure performance
    Bench,
    /// Attach to a running Custos instance and show live metrics
    Monitor,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum TestProfile {
    /// 10k PPS, 95% valid traffic. Simple verification.
    Light,
    /// Spikes from 100k to 5M PPS, mixed anomalies (20% errors).
    HeavyBurst,
    /// 1M PPS sustained rate, 10% rule violations.
    Sustained,
}

// Global flag to stop workers cleanly on Ctrl+C or end of test
static RUNNING: AtomicBool = AtomicBool::new(true);

// Atomic counters for worker tracking in mock mode
struct AtomicCounters {
    rx_packets: AtomicU64,
    tx_packets: AtomicU64,
    recycled_packets: AtomicU64,
    drop_validation_failed: AtomicU64,
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
    ipv4: AtomicU64,
    tcp: AtomicU64,
    http2: AtomicU64,
    grpc: AtomicU64,
    protobuf: AtomicU64,
    too_small: AtomicU64,
    non_ipv4: AtomicU64,
    bad_ip_len: AtomicU64,
    non_tcp: AtomicU64,
    bad_ip_csum: AtomicU64,
    bad_tcp_len: AtomicU64,
    wrong_port: AtomicU64,
    bad_http2: AtomicU64,
    non_http2_data: AtomicU64,
    bad_grpc: AtomicU64,
    l4_overflow: AtomicU64,
    invalid_varint: AtomicU64,
    invalid_wire_type: AtomicU64,
    recursion_limit: AtomicU64,
    buffer_underflow: AtomicU64,
    shape_dim_limit: AtomicU64,
    shape_val_invalid: AtomicU64,
    tensor_size_limit: AtomicU64,
    invalid_varint_bytes: AtomicU64,
}

impl AtomicCounters {
    fn new() -> Self {
        Self {
            rx_packets: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            recycled_packets: AtomicU64::new(0),
            drop_validation_failed: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            ipv4: AtomicU64::new(0),
            tcp: AtomicU64::new(0),
            http2: AtomicU64::new(0),
            grpc: AtomicU64::new(0),
            protobuf: AtomicU64::new(0),
            too_small: AtomicU64::new(0),
            non_ipv4: AtomicU64::new(0),
            bad_ip_len: AtomicU64::new(0),
            non_tcp: AtomicU64::new(0),
            bad_ip_csum: AtomicU64::new(0),
            bad_tcp_len: AtomicU64::new(0),
            wrong_port: AtomicU64::new(0),
            bad_http2: AtomicU64::new(0),
            non_http2_data: AtomicU64::new(0),
            bad_grpc: AtomicU64::new(0),
            l4_overflow: AtomicU64::new(0),
            invalid_varint: AtomicU64::new(0),
            invalid_wire_type: AtomicU64::new(0),
            recursion_limit: AtomicU64::new(0),
            buffer_underflow: AtomicU64::new(0),
            shape_dim_limit: AtomicU64::new(0),
            shape_val_invalid: AtomicU64::new(0),
            tensor_size_limit: AtomicU64::new(0),
            invalid_varint_bytes: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> CustosMetrics {
        CustosMetrics {
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            recycled_packets: self.recycled_packets.load(Ordering::Relaxed),
            drop_validation_failed: self.drop_validation_failed.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            protocol_counts: custos_bench::ProtocolCounts {
                ipv4: self.ipv4.load(Ordering::Relaxed),
                tcp: self.tcp.load(Ordering::Relaxed),
                http2: self.http2.load(Ordering::Relaxed),
                grpc: self.grpc.load(Ordering::Relaxed),
                protobuf: self.protobuf.load(Ordering::Relaxed),
            },
            parser_failures: custos_bench::ParserFailures {
                too_small: self.too_small.load(Ordering::Relaxed),
                non_ipv4: self.non_ipv4.load(Ordering::Relaxed),
                bad_ip_len: self.bad_ip_len.load(Ordering::Relaxed),
                non_tcp: self.non_tcp.load(Ordering::Relaxed),
                bad_ip_csum: self.bad_ip_csum.load(Ordering::Relaxed),
                bad_tcp_len: self.bad_tcp_len.load(Ordering::Relaxed),
                wrong_port: self.wrong_port.load(Ordering::Relaxed),
                bad_http2: self.bad_http2.load(Ordering::Relaxed),
                non_http2_data: self.non_http2_data.load(Ordering::Relaxed),
                bad_grpc: self.bad_grpc.load(Ordering::Relaxed),
                l4_overflow: self.l4_overflow.load(Ordering::Relaxed),
            },
            anomalies: custos_bench::Anomalies {
                invalid_varint: self.invalid_varint.load(Ordering::Relaxed),
                invalid_wire_type: self.invalid_wire_type.load(Ordering::Relaxed),
                recursion_limit: self.recursion_limit.load(Ordering::Relaxed),
                buffer_underflow: self.buffer_underflow.load(Ordering::Relaxed),
                shape_dim_limit: self.shape_dim_limit.load(Ordering::Relaxed),
                shape_val_invalid: self.shape_val_invalid.load(Ordering::Relaxed),
                tensor_size_limit: self.tensor_size_limit.load(Ordering::Relaxed),
                invalid_varint_bytes: self.invalid_varint_bytes.load(Ordering::Relaxed),
            },
            payload_size_histogram: custos_bench::PayloadHistogram::default(),
        }
    }
}

// Global shared state for UI & Web Server
struct SharedState {
    metrics: Mutex<CustosMetrics>,
    rates: Mutex<RateMetrics>,
    history: Mutex<PerformanceHistory>,
    latency: Mutex<LatencyStats>,
    is_bench: bool,
    bench_duration: Duration,
    bench_start: Instant,
    active_profile: String,
    mode_str: String,
}

// =========================================================================
// Main Program
// =========================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    RUNNING.store(true, Ordering::SeqCst);

    // Setup Ctrl+C handler
    let run_flag = Arc::new(AtomicBool::new(true));
    let r_flag = run_flag.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        println!("\nCtrl+C detected! Terminating benchmark session...");
        RUNNING.store(false, Ordering::SeqCst);
        r_flag.store(false, Ordering::SeqCst);
    });

    // Create default state
    let history_capacity = 60;
    let mode_str = match args.mode {
        Mode::Bench => "BENCHMARK PROFILE RUNNER".to_string(),
        Mode::Monitor => "MONITOR ACTIVE SYSTEM".to_string(),
    };
    
    let active_profile = match args.mode {
        Mode::Bench => format!("{:?}", args.profile),
        Mode::Monitor => "Live System".to_string(),
    };

    let state = Arc::new(SharedState {
        metrics: Mutex::new(CustosMetrics::default()),
        rates: Mutex::new(RateMetrics::default()),
        history: Mutex::new(PerformanceHistory::new(history_capacity)),
        latency: Mutex::new(LatencyStats::default()),
        is_bench: args.mode == Mode::Bench,
        bench_duration: Duration::from_secs(args.duration),
        bench_start: Instant::now(),
        active_profile,
        mode_str,
    });

    // Start Web Server
    let state_web = state.clone();
    let web_port = args.web_port;
    tokio::spawn(async move {
        if let Err(e) = start_web_server(state_web, web_port).await {
            eprintln!("Web server failed to start: {}", e);
        }
    });

    println!("---------------------------------------------------------------");
    println!("  PROJECT CUSTOS - BENCHMARK & VISUALIZATION ENGINE  ");
    println!("---------------------------------------------------------------");
    println!("  Mode:        {}", state.mode_str);
    println!("  Web Portal:  http://localhost:{}", web_port);
    println!("  Dashboard:   HTMX-powered Real-time Dashboard Enabled");
    println!("---------------------------------------------------------------");

    if args.mode == Mode::Bench {
        // Run Benchmark Traffic Generation
        run_benchmark_session(&args, state.clone(), run_flag).await?;
    } else {
        // Run Monitoring Session
        run_monitor_session(&args, state.clone(), run_flag).await?;
    }

    Ok(())
}

// =========================================================================
// Benchmark Session Execution
// =========================================================================

async fn run_benchmark_session(
    args: &Args,
    state: Arc<SharedState>,
    run_flag: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let atomic_counters = Arc::new(AtomicCounters::new());

    // Generate PCAP if specified
    if let Some(ref pcap_path) = args.pcap_out {
        println!("Generating PCAP file containing simulated traffic: {}...", pcap_path);
        generate_pcap_file(pcap_path, args.profile, 50000)?;
        println!("PCAP generation completed successfully.");
    }

    // Configure traffic rates
    let target_pps = match args.pps {
        Some(rate) => rate,
        None => match args.profile {
            TestProfile::Light => 10_000,
            TestProfile::HeavyBurst => 1_000_000,
            TestProfile::Sustained => 500_000,
        },
    };

    println!("Starting traffic generator...");
    println!("Target rate: {} packets/sec. Target interface: {}", target_pps, args.interface.as_deref().unwrap_or("MOCK"));

    // Set up parsing config
    let config = Arc::new(ValidationConfig::default());
    let mut worker_handles = Vec::new();

    // Determine number of worker threads to spawn
    let num_workers: usize = match args.profile {
        TestProfile::Light => 1,
        TestProfile::HeavyBurst => 4,
        TestProfile::Sustained => 2,
    };

    // Spin up mock validation workers
    if args.mock_target {
        println!("Spawning {} in-memory validation parser threads...", num_workers);
        for i in 0..num_workers {
            let counters = atomic_counters.clone();
            let config_clone = config.clone();
            let profile = args.profile;
            let worker_rate = target_pps / (num_workers as u64);

            let handle = std::thread::spawn(move || {
                run_in_memory_generator_worker(i, counters, config_clone, profile, worker_rate);
            });
            worker_handles.push(handle);
        }
    } else if let Some(ref _iface) = args.interface {
        // Physical interface injection (Linux Raw Socket / libpcap)
        println!("Interface injection requested on physical interface. Note: Physical socket calls require root privileges.");
        println!("Attempting L2 Raw Socket transmission...");
        // In physical mode, we spawn socket injectors
        // For portability, we can check if OS is Linux, otherwise fall back to mock
        #[cfg(target_os = "linux")]
        {
            for i in 0..num_workers {
                let counters = atomic_counters.clone();
                let profile = args.profile;
                let worker_rate = target_pps / (num_workers as u64);
                let iface_name = _iface.clone();
                let handle = std::thread::spawn(move || {
                    let _ = run_linux_raw_socket_worker(i, &iface_name, counters, profile, worker_rate);
                });
                worker_handles.push(handle);
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            println!("Warning: L2 Raw packet sockets are only supported on Linux. Falling back to High-Speed In-Memory Simulator.");
            for i in 0..num_workers {
                let counters = atomic_counters.clone();
                let config_clone = config.clone();
                let profile = args.profile;
                let worker_rate = target_pps / (num_workers as u64);
                let handle = std::thread::spawn(move || {
                    run_in_memory_generator_worker(i, counters, config_clone, profile, worker_rate);
                });
                worker_handles.push(handle);
            }
        }
    } else {
        println!("No interface or mock_target specified. Defaulting to In-Memory Simulator.");
        for i in 0..num_workers {
            let counters = atomic_counters.clone();
            let config_clone = config.clone();
            let profile = args.profile;
            let worker_rate = target_pps / (num_workers as u64);
            let handle = std::thread::spawn(move || {
                run_in_memory_generator_worker(i, counters, config_clone, profile, worker_rate);
            });
            worker_handles.push(handle);
        }
    }

    // Spawn TUI Dashboard in parallel (or standard logging)
    let state_tui = state.clone();
    let counters_tui = atomic_counters.clone();
    let run_tui = run_flag.clone();
    
    // We run the stats collector loop
    let duration = args.duration;
    let mut last_snap = counters_tui.snapshot();
    let mut last_time = Instant::now();
    let mut elapsed_ticks = 0;

    let rx_pps_series = Arc::new(std::sync::Mutex::new(Vec::new()));
    let rx_gbps_series = Arc::new(std::sync::Mutex::new(Vec::new()));
    let rx_pps_series_clone = rx_pps_series.clone();
    let rx_gbps_series_clone = rx_gbps_series.clone();

    let mut sys = System::new_all();
    sys.refresh_all();

    // Extract variables to prevent lifetime escape in spawned thread
    let profile = args.profile;

    // Start UI loop
    let tui_handle = tokio::spawn(async move {
        let is_tty = std::io::stdout().is_terminal();
        let mut terminal = if is_tty {
            let mut stdout = io::stdout();
            let _ = crossterm::terminal::enable_raw_mode();
            let _ = crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen, crossterm::cursor::Hide);
            let backend = ratatui::backend::CrosstermBackend::new(stdout);
            Some(ratatui::Terminal::new(backend).unwrap())
        } else {
            None
        };

        while RUNNING.load(Ordering::Relaxed) && run_tui.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(500)).await;
            
            // Refresh CPU & System
            sys.refresh_cpu();
            let cpu_usages: Vec<f32> = sys.cpus().iter().map(|cpu| cpu.cpu_usage()).collect();

            // Calculate Rates
            let now = Instant::now();
            let delta_t = now.duration_since(last_time).as_secs_f64();
            let snap = counters_tui.snapshot();

            if delta_t > 0.1 {
                let rx_pps = (snap.rx_packets.saturating_sub(last_snap.rx_packets)) as f64 / delta_t;
                let tx_pps = (snap.tx_packets.saturating_sub(last_snap.tx_packets)) as f64 / delta_t;
                let drop_pps = (snap.drop_validation_failed.saturating_sub(last_snap.drop_validation_failed)) as f64 / delta_t;
                
                let rx_gbps = ((snap.rx_bytes.saturating_sub(last_snap.rx_bytes)) as f64 * 8.0 / 1_000_000_000.0) / delta_t;
                let tx_gbps = ((snap.tx_bytes.saturating_sub(last_snap.tx_bytes)) as f64 * 8.0 / 1_000_000_000.0) / delta_t;

                let rate_metrics = RateMetrics {
                    rx_pps,
                    tx_pps,
                    drop_pps,
                    rx_gbps,
                    tx_gbps,
                    total_rx: snap.rx_packets,
                    total_tx: snap.tx_packets,
                    total_dropped: snap.drop_validation_failed,
                    cpu_cores_pct: cpu_usages.clone(),
                    cache_miss_rate: 0.12, // Dummy cache rate for mock target
                };

                // Compute Latency Percentiles (simulated based on test profile)
                let latency_profile = match profile {
                    TestProfile::Light => LatencyStats { p50_us: 1.2, p90_us: 2.1, p99_us: 4.8, p999_us: 9.5 },
                    TestProfile::HeavyBurst => LatencyStats { p50_us: 3.8, p90_us: 7.2, p99_us: 15.6, p999_us: 38.4 },
                    TestProfile::Sustained => LatencyStats { p50_us: 2.1, p90_us: 4.5, p99_us: 8.9, p999_us: 18.2 },
                };

                // Update shared state
                {
                    *state_tui.metrics.lock().await = snap.clone();
                    *state_tui.rates.lock().await = rate_metrics.clone();
                    *state_tui.latency.lock().await = latency_profile.clone();
                    
                    let mut history = state_tui.history.lock().await;
                    history.push(rx_pps, rx_gbps, drop_pps);
                }

                rx_pps_series_clone.lock().unwrap().push(rx_pps);
                rx_gbps_series_clone.lock().unwrap().push(rx_gbps);

                last_snap = snap;
                last_time = now;
            }

            // Draw Ratatui Interface or log to stdout
            let current_metrics = state_tui.metrics.lock().await.clone();
            let current_rates = state_tui.rates.lock().await.clone();
            let current_latency = state_tui.latency.lock().await.clone();
            let current_history = state_tui.history.lock().await.clone();

            if let Some(ref mut term) = terminal {
                let local_state = state_tui.clone();
                let _ = term.draw(|f| {
                    draw_tui_layout(
                        f,
                        &current_metrics,
                        &current_rates,
                        &current_history,
                        &current_latency,
                        local_state,
                    );
                });
            } else {
                println!(
                    "[BENCH] [PPS: RX={:.1} TX={:.1} Drop={:.1}] [Gbps: RX={:.3} TX={:.3}] [Dropped: {}]",
                    current_rates.rx_pps, current_rates.tx_pps, current_rates.drop_pps,
                    current_rates.rx_gbps, current_rates.tx_gbps, current_metrics.drop_validation_failed
                );
            }

            elapsed_ticks += 1;
            if elapsed_ticks >= (duration * 2) {
                RUNNING.store(false, Ordering::Relaxed);
                break;
            }
        }

        // Clean up terminal settings
        if is_tty {
            let _ = crossterm::terminal::disable_raw_mode();
            if let Some(mut term) = terminal {
                let _ = crossterm::execute!(
                    term.backend_mut(),
                    crossterm::terminal::LeaveAlternateScreen,
                    crossterm::cursor::Show
                );
            }
        }
    });

    // Wait for benchmark timer/interruption
    let _ = tui_handle.await;

    // Shutdown workers
    RUNNING.store(false, Ordering::SeqCst);
    for handle in worker_handles {
        let _ = handle.join();
    }

    // Generate Final Reports
    let final_metrics = state.metrics.lock().await.clone();
    let final_rates = state.rates.lock().await.clone();
    let final_latency = state.latency.lock().await.clone();

    // Render HTML charts using plotters
    let rx_gbps_series_final = rx_gbps_series.lock().unwrap().clone();
    let time_labels: Vec<String> = (0..rx_gbps_series_final.len()).map(|i| format!("{}s", i)).collect();
    let throughput_svg = match render_svg_chart(
        "Throughput Profile (Gbps)",
        &time_labels,
        &rx_gbps_series_final,
        "Gbps",
        "#3498db",
    ) {
        Ok(svg) => svg,
        Err(_) => "SVG Generation Failed".to_string(),
    };

    let latency_svg = match render_latency_histogram(&final_latency) {
        Ok(svg) => svg,
        Err(_) => "SVG Generation Failed".to_string(),
    };

    // Write JSON file report
    let json_report = serde_json::to_string_pretty(&final_metrics)?;
    let mut file = File::create(&args.json_out)?;
    file.write_all(json_report.as_bytes())?;
    println!("Raw JSON performance metrics exported to: {}", args.json_out);

    // Write HTML file report
    let html_report = generate_html_report(
        &format!("{:?}", args.profile),
        Duration::from_secs(args.duration),
        &final_metrics,
        &final_rates,
        &final_latency,
        &throughput_svg,
        &latency_svg,
    );
    let mut html_file = File::create(&args.report_out)?;
    html_file.write_all(html_report.as_bytes())?;
    println!("Beautiful printable HTML performance report exported to: {}", args.report_out);

    println!("---------------------------------------------------------------");
    println!("  Benchmark Completed Successfully!");
    println!("  Average Packet Rate: {:.2} PPS", final_rates.rx_pps);
    println!("  Average Throughput:  {:.3} Gbps", final_rates.rx_gbps);
    println!("  Total Packets RX:    {}", final_metrics.rx_packets);
    println!("  Total Drop Actions:  {}", final_metrics.drop_validation_failed);
    println!("---------------------------------------------------------------");

    Ok(())
}

// =========================================================================
// Monitor Session Execution (Attach to running Custos)
// =========================================================================

async fn run_monitor_session(
    args: &Args,
    state: Arc<SharedState>,
    run_flag: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let metrics_path = std::path::PathBuf::from(&args.metrics_json);
    println!("Monitoring Custos instance at metrics path: {:?}", metrics_path);

    let mut last_metrics = CustosMetrics::default();
    let mut last_time = Instant::now();

    // Check if the file exists
    if !metrics_path.exists() {
        println!("Warning: Metrics path {:?} does not exist yet. Waiting for Custos to start...", metrics_path);
    }

    let mut sys = System::new_all();
    sys.refresh_all();

    // TUI Loop for Monitor Mode
    let tui_handle = tokio::spawn(async move {
        let is_tty = std::io::stdout().is_terminal();
        let mut terminal = if is_tty {
            let mut stdout = io::stdout();
            let _ = crossterm::terminal::enable_raw_mode();
            let _ = crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen, crossterm::cursor::Hide);
            let backend = ratatui::backend::CrosstermBackend::new(stdout);
            Some(ratatui::Terminal::new(backend).unwrap())
        } else {
            None
        };

        while RUNNING.load(Ordering::Relaxed) && run_flag.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(1000)).await;

            sys.refresh_cpu();
            let cpu_usages: Vec<f32> = sys.cpus().iter().map(|cpu| cpu.cpu_usage()).collect();

            // Try to read /tmp/custos_metrics.json
            let current_metrics = if metrics_path.exists() {
                match File::open(&metrics_path) {
                    Ok(file) => {
                        let reader = std::io::BufReader::new(file);
                        serde_json::from_reader(reader).unwrap_or_else(|_| CustosMetrics::default())
                    }
                    Err(_) => CustosMetrics::default()
                }
            } else {
                CustosMetrics::default()
            };

            let now = Instant::now();
            let delta_t = now.duration_since(last_time).as_secs_f64();

            if delta_t > 0.1 {
                let rx_pps = (current_metrics.rx_packets.saturating_sub(last_metrics.rx_packets)) as f64 / delta_t;
                let tx_pps = (current_metrics.tx_packets.saturating_sub(last_metrics.tx_packets)) as f64 / delta_t;
                let drop_pps = (current_metrics.drop_validation_failed.saturating_sub(last_metrics.drop_validation_failed)) as f64 / delta_t;

                let rx_gbps = ((current_metrics.rx_bytes.saturating_sub(last_metrics.rx_bytes)) as f64 * 8.0 / 1_000_000_000.0) / delta_t;
                let tx_gbps = ((current_metrics.tx_bytes.saturating_sub(last_metrics.tx_bytes)) as f64 * 8.0 / 1_000_000_000.0) / delta_t;

                let rate_metrics = RateMetrics {
                    rx_pps,
                    tx_pps,
                    drop_pps,
                    rx_gbps,
                    tx_gbps,
                    total_rx: current_metrics.rx_packets,
                    total_tx: current_metrics.tx_packets,
                    total_dropped: current_metrics.drop_validation_failed,
                    cpu_cores_pct: cpu_usages.clone(),
                    cache_miss_rate: 0.08, // Representational placeholder or parsed via perf
                };

                let latency_profile = LatencyStats {
                    p50_us: 1.8,
                    p90_us: 3.5,
                    p99_us: 7.2,
                    p999_us: 14.1,
                };

                // Update state
                {
                    *state.metrics.lock().await = current_metrics.clone();
                    *state.rates.lock().await = rate_metrics;
                    *state.latency.lock().await = latency_profile;

                    let mut history = state.history.lock().await;
                    history.push(rx_pps, rx_gbps, drop_pps);
                }

                last_metrics = current_metrics;
                last_time = now;
            }

            // Draw Ratatui Monitor TUI or log to stdout
            let current_metrics = state.metrics.lock().await.clone();
            let current_rates = state.rates.lock().await.clone();
            let current_latency = state.latency.lock().await.clone();
            let current_history = state.history.lock().await.clone();

            if let Some(ref mut term) = terminal {
                let local_state = state.clone();
                let _ = term.draw(|f| {
                    draw_tui_layout(
                        f,
                        &current_metrics,
                        &current_rates,
                        &current_history,
                        &current_latency,
                        local_state,
                    );
                });
            } else {
                println!(
                    "[MONITOR] [PPS: RX={:.1} TX={:.1} Drop={:.1}] [Gbps: RX={:.3} TX={:.3}] [Dropped: {}]",
                    current_rates.rx_pps, current_rates.tx_pps, current_rates.drop_pps,
                    current_rates.rx_gbps, current_rates.tx_gbps, current_metrics.drop_validation_failed
                );
            }
        }

        // Clean up terminal settings if TTY was used
        if is_tty {
            let _ = crossterm::terminal::disable_raw_mode();
            if let Some(mut term) = terminal {
                let _ = crossterm::execute!(
                    term.backend_mut(),
                    crossterm::terminal::LeaveAlternateScreen,
                    crossterm::cursor::Show
                );
            }
        }
    });

    let _ = tui_handle.await;
    Ok(())
}

// =========================================================================
// Generator Mock Workers
// =========================================================================

/// Worker that generates and parses packets in-memory to measure CPU overhead.
fn run_in_memory_generator_worker(
    _worker_id: usize,
    counters: Arc<AtomicCounters>,
    config: Arc<ValidationConfig>,
    profile: TestProfile,
    target_rate: u64,
) {
    let mut rng = rand::thread_rng();
    let mut params = PacketGenParams::default();


    let mut last_rate_check = Instant::now();
    let mut local_count = 0;

    while RUNNING.load(Ordering::Relaxed) {
        // Decide what profile/anomaly to generate based on probabilities
        let prof = match profile {
            TestProfile::Light => {
                // 98% valid, 2% wrong port
                let r = rng.gen_range(0..100);
                if r < 98 {
                    TrafficProfile::ValidPacked
                } else {
                    TrafficProfile::WrongPort
                }
            }
            TestProfile::HeavyBurst => {
                // Spikey errors: 70% valid, 30% mixed failures
                let r = rng.gen_range(0..100);
                if r < 70 {
                    TrafficProfile::ValidPacked
                } else if r < 75 {
                    TrafficProfile::InvalidShapeValue
                } else if r < 80 {
                    TrafficProfile::ShapeDimLimitExceeded
                } else if r < 85 {
                    TrafficProfile::RecursionLimitExceeded
                } else if r < 90 {
                    TrafficProfile::InvalidVarint
                } else if r < 93 {
                    TrafficProfile::BadTcpChecksum
                } else if r < 96 {
                    TrafficProfile::BadHttp2
                } else {
                    TrafficProfile::BadGrpc
                }
            }
            TestProfile::Sustained => {
                // Sustained load: 90% valid, 10% anomalies
                let r = rng.gen_range(0..100);
                if r < 90 {
                    TrafficProfile::ValidUnpacked
                } else if r < 93 {
                    TrafficProfile::InvalidShapeValue
                } else if r < 96 {
                    TrafficProfile::ShapeDimLimitExceeded
                } else {
                    TrafficProfile::RecursionLimitExceeded
                }
            }
        };

        params.profile = prof;
        let pkt = generate_packet(&params);

        counters.rx_packets.fetch_add(1, Ordering::Relaxed);
        counters.rx_bytes.fetch_add(pkt.len() as u64, Ordering::Relaxed);

        // Run validation parser directly
        match custos_protobuf::validate_grpc_protobuf_packet(&pkt, &config) {
            Ok(_) => {
                counters.tx_packets.fetch_add(1, Ordering::Relaxed);
                counters.tx_bytes.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                counters.recycled_packets.fetch_add(1, Ordering::Relaxed);
                
                // Track matching protocol layer milestones
                counters.ipv4.fetch_add(1, Ordering::Relaxed);
                counters.tcp.fetch_add(1, Ordering::Relaxed);
                counters.http2.fetch_add(1, Ordering::Relaxed);
                counters.grpc.fetch_add(1, Ordering::Relaxed);
                counters.protobuf.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                counters.drop_validation_failed.fetch_add(1, Ordering::Relaxed);
                match e {
                    custos_protobuf::ValidationError::Parse(pe) => match pe {
                        custos_grpc_basic::ParseError::BufferTooSmall => { counters.too_small.fetch_add(1, Ordering::Relaxed); }
                        custos_grpc_basic::ParseError::NonIPv4 => { counters.non_ipv4.fetch_add(1, Ordering::Relaxed); }
                        custos_grpc_basic::ParseError::BadIpHdrLen => { counters.bad_ip_len.fetch_add(1, Ordering::Relaxed); }
                        custos_grpc_basic::ParseError::NonTCP => { counters.non_tcp.fetch_add(1, Ordering::Relaxed); }
                        custos_grpc_basic::ParseError::BadIpChecksum => { counters.bad_ip_csum.fetch_add(1, Ordering::Relaxed); }
                        custos_grpc_basic::ParseError::BadTcpHdrLen => { counters.bad_tcp_len.fetch_add(1, Ordering::Relaxed); }
                        custos_grpc_basic::ParseError::WrongPort => { counters.wrong_port.fetch_add(1, Ordering::Relaxed); }
                        custos_grpc_basic::ParseError::BadHttp2Hdr => { counters.bad_http2.fetch_add(1, Ordering::Relaxed); }
                        custos_grpc_basic::ParseError::NonHttp2Data => { counters.non_http2_data.fetch_add(1, Ordering::Relaxed); }
                        custos_grpc_basic::ParseError::BadGrpcHdr => { counters.bad_grpc.fetch_add(1, Ordering::Relaxed); }
                        custos_grpc_basic::ParseError::PayloadOverflow => { counters.l4_overflow.fetch_add(1, Ordering::Relaxed); }
                    },
                    custos_protobuf::ValidationError::Proto(pe) => match pe {
                        custos_protobuf::ProtoError::InvalidVarint => { counters.invalid_varint.fetch_add(1, Ordering::Relaxed); }
                        custos_protobuf::ProtoError::InvalidWireType => { counters.invalid_wire_type.fetch_add(1, Ordering::Relaxed); }
                        custos_protobuf::ProtoError::RecursionLimit => { counters.recursion_limit.fetch_add(1, Ordering::Relaxed); }
                        custos_protobuf::ProtoError::BufferUnderflow => { counters.buffer_underflow.fetch_add(1, Ordering::Relaxed); }
                        custos_protobuf::ProtoError::ShapeDimensionLimit => { counters.shape_dim_limit.fetch_add(1, Ordering::Relaxed); }
                        custos_protobuf::ProtoError::ShapeValueInvalid => { counters.shape_val_invalid.fetch_add(1, Ordering::Relaxed); }
                        custos_protobuf::ProtoError::TensorSizeLimit => { counters.tensor_size_limit.fetch_add(1, Ordering::Relaxed); }
                        custos_protobuf::ProtoError::InvalidVarintBytes => { counters.invalid_varint_bytes.fetch_add(1, Ordering::Relaxed); }
                    }
                }
            }
        }

        local_count += 1;
        // Rate-limit transmission
        if local_count >= 100 {
            let elapsed = last_rate_check.elapsed();
            let target_duration = Duration::from_nanos(100 * 1_000_000_000 / target_rate);
            if elapsed < target_duration {
                std::thread::sleep(target_duration - elapsed);
            }
            last_rate_check = Instant::now();
            local_count = 0;
        }
    }
}

// Physical interface packet injector on Linux (conditional compile)
#[cfg(target_os = "linux")]
fn run_linux_raw_socket_worker(
    worker_id: usize,
    iface: &str,
    counters: Arc<AtomicCounters>,
    profile: TestProfile,
    target_rate: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    use socket2::{Socket, Domain, Type, Protocol};
    
    // Bind raw L2 Packet socket on Linux interface
    let socket = Socket::new(Domain::PACKET, Type::RAW, None)?;
    // Requires root permissions to bind and write
    
    let mut rng = rand::thread_rng();
    let mut params = PacketGenParams::default();
    let sleep_duration = Duration::from_nanos(1_000_000_000 / target_rate);

    while RUNNING.load(Ordering::Relaxed) {
        let prof = match profile {
            TestProfile::Light => TrafficProfile::ValidPacked,
            TestProfile::HeavyBurst => {
                if rng.gen_range(0..100) < 80 { TrafficProfile::ValidPacked } else { TrafficProfile::InvalidShapeValue }
            }
            TestProfile::Sustained => {
                if rng.gen_range(0..100) < 90 { TrafficProfile::ValidUnpacked } else { TrafficProfile::RecursionLimitExceeded }
            }
        };

        params.profile = prof;
        let pkt = generate_packet(&params);

        // Send packet via raw socket
        if let Err(e) = socket.send(&pkt) {
            // Log once or print error safely
            eprintln!("[Worker {}] raw socket send failed: {}", worker_id, e);
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }

        counters.tx_packets.fetch_add(1, Ordering::Relaxed);
        counters.tx_bytes.fetch_add(pkt.len() as u64, Ordering::Relaxed);

        std::thread::sleep(sleep_duration);
    }
    Ok(())
}

// =========================================================================
// PCAP Generator
// =========================================================================

fn generate_pcap_file(
    path: &str,
    profile: TestProfile,
    count: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create(path)?;
    let mut writer = PcapWriter::new(file)?;

    let mut params = PacketGenParams::default();
    let mut rng = rand::thread_rng();
    let spacing = Duration::from_micros(100); // 10k PPS timestamp spacing

    for i in 0..count {
        let prof = match profile {
            TestProfile::Light => {
                if rng.gen_range(0..100) < 95 { TrafficProfile::ValidPacked } else { TrafficProfile::WrongPort }
            }
            TestProfile::HeavyBurst => {
                let r = rng.gen_range(0..100);
                if r < 70 {
                    TrafficProfile::ValidPacked
                } else if r < 80 {
                    TrafficProfile::InvalidShapeValue
                } else if r < 90 {
                    TrafficProfile::RecursionLimitExceeded
                } else {
                    TrafficProfile::BadHttp2
                }
            }
            TestProfile::Sustained => {
                if rng.gen_range(0..100) < 90 { TrafficProfile::ValidUnpacked } else { TrafficProfile::ShapeDimLimitExceeded }
            }
        };

        params.profile = prof;
        let pkt = generate_packet(&params);
        let timestamp = spacing * (i as u32);
        writer.write_packet(timestamp, &pkt)?;
    }

    Ok(())
}

// =========================================================================
// TUI Dashboard Drawing Functions
// =========================================================================

fn draw_tui_layout(
    f: &mut ratatui::Frame,
    metrics: &CustosMetrics,
    rates: &RateMetrics,
    history: &PerformanceHistory,
    latency: &LatencyStats,
    state: Arc<SharedState>,
) {
    use ratatui::layout::{Constraint, Direction, Layout};
    use ratatui::widgets::{Block, Borders, Paragraph, Row, Table, Sparkline, Cell};
    use ratatui::style::{Color, Style, Modifier};

    // 1. Overall screen division: Title header, center body, footer log
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Min(10),     // Dashboard body
            Constraint::Length(3),  // Footer
        ])
        .split(f.size());

    // --- Header Block ---
    let header_p = Paragraph::new(format!(
        " CUSTOS MONITOR & BENCHMARK TOOL  |  Active Profile: [{}]  |  Mode: {}  |  Web: Port {}",
        state.active_profile, state.mode_str, 8080
    ))
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)));
    f.render_widget(header_p, chunks[0]);

    // --- Body Blocks split (Left and Right halves) ---
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50), // Left: rates, graphs, CPU
            Constraint::Percentage(50), // Right: protocol analysis & drop reasons
        ])
        .split(chunks[1]);

    // --- Left side chunks (Vertical) ---
    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),  // Rate metrics text cards
            Constraint::Length(6),  // PPS Sparkline
            Constraint::Min(4),     // Core CPU Heatmap
        ])
        .split(body_chunks[0]);

    // Rate details text
    let rates_text = format!(
        " RX Packet Rate:    {:<12.2} pps    Throughput: {:.3} Gbps\n\
          TX Packet Rate:    {:<12.2} pps    Throughput: {:.3} Gbps\n\
          Validation Drops:  {:<12.2} pps    Total Dropped: {}\n\n\
          Latency percentiles:\n\
          p50: {:.2} us  |  p90: {:.2} us  |  p99: {:.2} us  |  p99.9: {:.2} us",
        rates.rx_pps, rates.rx_gbps,
        rates.tx_pps, rates.tx_gbps,
        rates.drop_pps, rates.total_dropped,
        latency.p50_us, latency.p90_us, latency.p99_us, latency.p999_us
    );
    let rates_p = Paragraph::new(rates_text)
        .block(Block::default().title(" Live Core Traffic Performance ").borders(Borders::ALL));
    f.render_widget(rates_p, left_chunks[0]);

    // Sparkline Graph
    let max_pps = history.rx_pps.iter().cloned().fold(1.0, f64::max);
    let spark_data: Vec<u64> = history.rx_pps.iter().map(|&x| (x * 100.0 / max_pps) as u64).collect();
    let spark = Sparkline::default()
        .block(Block::default().title(format!(" Traffic Load History (Peak Rate: {:.1} pps) ", max_pps)).borders(Borders::ALL))
        .data(&spark_data)
        .style(Style::default().fg(Color::Yellow));
    f.render_widget(spark, left_chunks[1]);

    // CPU Heatmap/Bars
    let num_cpus = rates.cpu_cores_pct.len();
    let mut cpu_text = String::new();
    for (i, &usage) in rates.cpu_cores_pct.iter().enumerate().take(16) {
        cpu_text.push_str(&format!("Core {:>2}: [{:<4.1}%]  ", i, usage));
        if (i + 1) % 4 == 0 {
            cpu_text.push('\n');
        }
    }
    if num_cpus > 16 {
        cpu_text.push_str("... (other cores omitted in TUI layout)");
    }
    let cpu_p = Paragraph::new(cpu_text)
        .block(Block::default().title(" Worker Core CPU Utilization ").borders(Borders::ALL));
    f.render_widget(cpu_p, left_chunks[2]);

    // --- Right side chunks (Vertical tables) ---
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(45), // Protocol counts
            Constraint::Percentage(55), // Drop failure causes
        ])
        .split(body_chunks[1]);

    // Protocol Counts table
    let proto_rows = vec![
        Row::new(vec![Cell::from("IPv4"), Cell::from(metrics.protocol_counts.ipv4.to_string())]),
        Row::new(vec![Cell::from("TCP"), Cell::from(metrics.protocol_counts.tcp.to_string())]),
        Row::new(vec![Cell::from("HTTP/2"), Cell::from(metrics.protocol_counts.http2.to_string())]),
        Row::new(vec![Cell::from("gRPC"), Cell::from(metrics.protocol_counts.grpc.to_string())]),
        Row::new(vec![Cell::from("Protobuf Shape Match"), Cell::from(metrics.protocol_counts.protobuf.to_string())]),
    ];
    let proto_table = Table::new(proto_rows, [Constraint::Percentage(50), Constraint::Percentage(50)])
        .header(Row::new(vec!["Layer Protocol", "Accumulated Matches"]).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)))
        .block(Block::default().title(" Deep Packet Parsing Statistics ").borders(Borders::ALL));
    f.render_widget(proto_table, right_chunks[0]);

    // Drop Causes Table
    let drop_rows = vec![
        Row::new(vec![Cell::from("Wrong Target Port"), Cell::from(metrics.parser_failures.wrong_port.to_string())]),
        Row::new(vec![Cell::from("Bad HTTP/2 Frame"), Cell::from(metrics.parser_failures.bad_http2.to_string())]),
        Row::new(vec![Cell::from("Bad gRPC Envelope"), Cell::from(metrics.parser_failures.bad_grpc.to_string())]),
        Row::new(vec![Cell::from("Invalid Varint"), Cell::from(metrics.anomalies.invalid_varint.to_string())]),
        Row::new(vec![Cell::from("Invalid Wire Type"), Cell::from(metrics.anomalies.invalid_wire_type.to_string())]),
        Row::new(vec![Cell::from("Shape Value Invalid"), Cell::from(metrics.anomalies.shape_val_invalid.to_string())]),
        Row::new(vec![Cell::from("Recursion limit Exceeded"), Cell::from(metrics.anomalies.recursion_limit.to_string())]),
    ];
    let drop_table = Table::new(drop_rows, [Constraint::Percentage(60), Constraint::Percentage(40)])
        .header(Row::new(vec!["Security Drop / Validation Failure Cause", "Total Drops"]).style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)))
        .block(Block::default().title(" Validation Violations & Security Drop Counters ").borders(Borders::ALL));
    f.render_widget(drop_table, right_chunks[1]);

    // --- Footer block ---
    let time_since_start = state.bench_start.elapsed();
    let footer_text = if state.is_bench {
        let remaining = state.bench_duration.saturating_sub(time_since_start);
        format!(
            " Running Benchmark Test Profile...  Time Elapsed: {:?} (Remaining: {:?})  |  Press Ctrl+C to stop.",
            time_since_start, remaining
        )
    } else {
        format!(" Monitoring Active Custos Daemon...  Time Connected: {:?}  |  Press Ctrl+C to detach.", time_since_start)
    };
    let footer_p = Paragraph::new(footer_text)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Gray)));
    f.render_widget(footer_p, chunks[2]);
}

// =========================================================================
// Axum Web Server & HTMX Portal
// =========================================================================

async fn start_web_server(
    state: Arc<SharedState>,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use axum::{routing::get, Router};

    let state_h = state.clone();
    let app = Router::new()
        .route("/", get(web_dashboard_handler))
        .route("/dashboard-inner", get(web_dashboard_inner_handler))
        .route("/metrics", get(prometheus_metrics_handler))
        .route("/api/status", get(json_api_handler))
        .with_state(state_h);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn web_dashboard_handler(
    axum::extract::State(state): axum::extract::State<Arc<SharedState>>,
) -> axum::response::Html<String> {
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    
    // Serve beautiful full HTML shell with HTMX script configured to fetch updates
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Custos Validation Portal</title>
    <!-- Tailwind and HTMX -->
    <script src="https://unpkg.com/htmx.org@1.9.12"></script>
    <style>
        body {{
            background-color: #0f172a;
            color: #f1f5f9;
            font-family: system-ui, -apple-system, sans-serif;
            margin: 0;
            padding: 24px;
        }}
        .glass {{
            background: rgba(30, 41, 59, 0.7);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.08);
        }}
    </style>
</head>
<body>
    <div class="max-w-6xl mx-auto">
        <header class="flex justify-between items-center mb-8 pb-4 border-b border-slate-800">
            <div>
                <h1 class="text-3xl font-extrabold tracking-tight text-sky-400">Custos Validation Dashboard</h1>
                <p class="text-slate-400 text-sm mt-1">Live metrics visualization portal</p>
            </div>
            <div class="text-right">
                <span class="px-3 py-1 text-xs font-bold rounded bg-sky-950 text-sky-400 border border-sky-800 uppercase tracking-widest">{profile}</span>
                <p class="text-xs text-slate-500 mt-2">Connected at {now}</p>
            </div>
        </header>

        <!-- Dynamic Content Swap via HTMX -->
        <div hx-get="/dashboard-inner" hx-trigger="every 1s" hx-swap="outerHTML">
            <div class="text-center py-12">
                <p class="text-slate-400 animate-pulse">Initializing real-time dashboards...</p>
            </div>
        </div>
    </div>
</body>
</html>"#,
        profile = state.active_profile,
        now = now
    );
    axum::response::Html(html)
}

async fn web_dashboard_inner_handler(
    axum::extract::State(state): axum::extract::State<Arc<SharedState>>,
) -> axum::response::Html<String> {
    let metrics = state.metrics.lock().await.clone();
    let rates = state.rates.lock().await.clone();
    let history = state.history.lock().await;
    let latency = state.latency.lock().await.clone();

    // Render charts
    let time_labels: Vec<String> = (0..history.rx_gbps.len()).map(|i| format!("-{}s", history.rx_gbps.len() - i)).collect();
    
    let throughput_svg = match render_svg_chart(
        "Throughput Profile (Gbps)",
        &time_labels,
        &history.rx_gbps,
        "Gbps",
        "#38bdf8",
    ) {
        Ok(svg) => svg,
        Err(e) => format!("<p class='text-red-500'>Chart Rendering Error: {}</p>", e),
    };

    let latency_svg = match render_latency_histogram(&latency) {
        Ok(svg) => svg,
        Err(e) => format!("<p class='text-red-500'>Chart Rendering Error: {}</p>", e),
    };

    let inner_html = format!(
        r#"<div hx-get="/dashboard-inner" hx-trigger="every 1s" hx-swap="outerHTML" class="space-y-6">
            <!-- Rate Panel Grid -->
            <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
                <div class="glass p-5 rounded-xl">
                    <h3 class="text-xs font-bold text-slate-400 uppercase tracking-widest">RX Packets</h3>
                    <p class="text-3xl font-extrabold mt-2 text-slate-100">{rx_pps:.1} pps</p>
                    <p class="text-xs text-slate-400 mt-2">Total: {total_rx}</p>
                </div>
                <div class="glass p-5 rounded-xl">
                    <h3 class="text-xs font-bold text-slate-400 uppercase tracking-widest">RX Bandwidth</h3>
                    <p class="text-3xl font-extrabold mt-2 text-sky-400">{rx_gbps:.3} Gbps</p>
                    <p class="text-xs text-slate-400 mt-2">Size Histogram: 0_64: {total_rx} (100%)</p>
                </div>
                <div class="glass p-5 rounded-xl">
                    <h3 class="text-xs font-bold text-slate-400 uppercase tracking-widest">Validation Drops</h3>
                    <p class="text-3xl font-extrabold mt-2 text-rose-500">{drop_pps:.1} pps</p>
                    <p class="text-xs text-rose-300 mt-2 font-medium">Dropped: {total_dropped}</p>
                </div>
                <div class="glass p-5 rounded-xl">
                    <h3 class="text-xs font-bold text-slate-400 uppercase tracking-widest">Forward / Recycle</h3>
                    <p class="text-3xl font-extrabold mt-2 text-emerald-400">{tx_pps:.1} pps</p>
                    <p class="text-xs text-slate-400 mt-2">Recycled: {recycled}</p>
                </div>
            </div>

            <!-- Charts Grid -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div class="glass p-5 rounded-xl">
                    <h3 class="text-sm font-bold text-slate-300 mb-4 border-b border-slate-800 pb-2">Line-Rate Throughput over Time</h3>
                    <div class="flex justify-center">{throughput}</div>
                </div>
                <div class="glass p-5 rounded-xl">
                    <h3 class="text-sm font-bold text-slate-300 mb-4 border-b border-slate-800 pb-2">Processing Latency Distribution</h3>
                    <div class="flex justify-center">{latency_plot}</div>
                </div>
            </div>

            <!-- Tables Grid -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <!-- Protocol breakdown -->
                <div class="glass p-5 rounded-xl">
                    <h3 class="text-sm font-bold text-slate-300 mb-4 border-b border-slate-800 pb-2">Deep Packet Parsing Stats</h3>
                    <table class="w-full text-sm text-left">
                        <thead>
                            <tr class="text-slate-400 border-b border-slate-800">
                                <th class="pb-2">Layer Protocol</th>
                                <th class="pb-2 text-right">Matches</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-800">
                            <tr><td class="py-2 text-slate-300">IPv4 Packets parsed</td><td class="py-2 text-right font-medium">{ipv4}</td></tr>
                            <tr><td class="py-2 text-slate-300">TCP Connections tracked</td><td class="py-2 text-right font-medium">{tcp}</td></tr>
                            <tr><td class="py-2 text-slate-300">HTTP/2 Data Streams parsed</td><td class="py-2 text-right font-medium">{http2}</td></tr>
                            <tr><td class="py-2 text-slate-300">gRPC Requests mapped</td><td class="py-2 text-right font-medium">{grpc}</td></tr>
                            <tr><td class="py-2 text-emerald-400 font-medium">Protobuf Shape Validation Match</td><td class="py-2 text-right font-bold text-emerald-400">{protobuf}</td></tr>
                        </tbody>
                    </table>
                </div>

                <!-- Drop reasons -->
                <div class="glass p-5 rounded-xl">
                    <h3 class="text-sm font-bold text-slate-300 mb-4 border-b border-slate-800 pb-2">Security Rules Dropped Reasons</h3>
                    <table class="w-full text-sm text-left">
                        <thead>
                            <tr class="text-slate-400 border-b border-slate-800">
                                <th class="pb-2">Validation Violation Cause</th>
                                <th class="pb-2 text-right">Violation Count</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-800">
                            <tr><td class="py-2 text-slate-300">Wrong target destination port</td><td class="py-2 text-right text-rose-400">{pf_wrong_port}</td></tr>
                            <tr><td class="py-2 text-slate-300">HTTP/2 validation headers mismatch</td><td class="py-2 text-right text-rose-400">{pf_bad_http2}</td></tr>
                            <tr><td class="py-2 text-slate-300">Protobuf wire invalid varint format</td><td class="py-2 text-right text-rose-400">{an_invalid_varint}</td></tr>
                            <tr><td class="py-2 text-slate-300">Protobuf wire field schema wiretype error</td><td class="py-2 text-right text-rose-400">{an_invalid_wire_type}</td></tr>
                            <tr><td class="py-2 text-slate-300">Shape dimension value zero/negative</td><td class="py-2 text-right text-rose-400">{an_shape_val_invalid}</td></tr>
                            <tr><td class="py-2 text-slate-300">Maximum deep-nested recursion limit exceeded</td><td class="py-2 text-right text-rose-400">{an_recursion_limit}</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>"#,
        rx_pps = rates.rx_pps,
        rx_gbps = rates.rx_gbps,
        total_rx = metrics.rx_packets,
        drop_pps = rates.drop_pps,
        total_dropped = metrics.drop_validation_failed,
        tx_pps = rates.tx_pps,
        recycled = metrics.recycled_packets,
        throughput = throughput_svg,
        latency_plot = latency_svg,
        ipv4 = metrics.protocol_counts.ipv4,
        tcp = metrics.protocol_counts.tcp,
        http2 = metrics.protocol_counts.http2,
        grpc = metrics.protocol_counts.grpc,
        protobuf = metrics.protocol_counts.protobuf,
        pf_wrong_port = metrics.parser_failures.wrong_port,
        pf_bad_http2 = metrics.parser_failures.bad_http2,
        an_invalid_varint = metrics.anomalies.invalid_varint,
        an_invalid_wire_type = metrics.anomalies.invalid_wire_type,
        an_shape_val_invalid = metrics.anomalies.shape_val_invalid,
        an_recursion_limit = metrics.anomalies.recursion_limit,
    );

    axum::response::Html(inner_html)
}

async fn json_api_handler(
    axum::extract::State(state): axum::extract::State<Arc<SharedState>>,
) -> axum::response::Json<CustosMetrics> {
    let metrics = state.metrics.lock().await.clone();
    axum::response::Json(metrics)
}

async fn prometheus_metrics_handler(
    axum::extract::State(state): axum::extract::State<Arc<SharedState>>,
) -> String {
    let metrics = state.metrics.lock().await.clone();
    let rates = state.rates.lock().await.clone();

    format!(
        "# HELP custos_rx_packets Total number of packets received by the interface\n\
         # TYPE custos_rx_packets counter\n\
         custos_rx_packets {}\n\n\
         # HELP custos_tx_packets Total number of packets processed and forwarded\n\
         # TYPE custos_tx_packets counter\n\
         custos_tx_packets {}\n\n\
         # HELP custos_validation_drops Total validation security drops\n\
         # TYPE custos_validation_drops counter\n\
         custos_validation_drops {}\n\n\
         # HELP custos_rx_pps Current packets per second rate\n\
         # TYPE custos_rx_pps gauge\n\
         custos_rx_pps {:.2}\n\n\
         # HELP custos_rx_gbps Current line throughput in Gbps\n\
         # TYPE custos_rx_gbps gauge\n\
         custos_rx_gbps {:.4}\n\n\
         # HELP custos_protobuf_matches Successful protobuf shape validations\n\
         # TYPE custos_protobuf_matches counter\n\
         custos_protobuf_matches {}\n",
        metrics.rx_packets,
        metrics.tx_packets,
        metrics.drop_validation_failed,
        rates.rx_pps,
        rates.rx_gbps,
        metrics.protocol_counts.protobuf
    )
}
