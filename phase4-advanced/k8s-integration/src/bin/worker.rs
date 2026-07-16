#![allow(unused_imports, unreachable_code)]

//! Unprivileged Worker for Custos.
//!
//! Receives the AF_XDP socket FD and shared UMEM memfd via SCM_RIGHTS, maps the UMEM,
//! maps the socket rings (RX, TX, Fill, Completion), pins the thread to the specified CPU core,
//! and runs the high-performance packet processing loop zero-copy.

use clap::Parser;
use custos_k8s_integration::{recv_fds, WorkerConfig};
use std::error::Error;
use std::io::{self, Read};
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::ptr;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn, Level};
use tracing_subscriber::FmtSubscriber;

/// CLI Arguments for the Worker.
#[derive(Parser, Debug)]
#[command(name = "custos-k8s-worker")]
#[command(about = "Unprivileged Custos Worker for AF_XDP Processing", long_about = None)]
pub struct Args {
    /// Unix domain socket path to connect to the daemon
    #[arg(short, long, default_value = "/var/run/custos.sock")]
    pub socket_path: String,

    /// CPU core to pin the polling thread to
    #[arg(short, long, default_value_t = 1)]
    pub core: usize,

    /// Operation mode: "forward" or "echo"
    #[arg(short, long, default_value = "forward")]
    pub mode: String,

    /// Enable verbose logging (level DEBUG)
    #[arg(short, long)]
    pub verbose: bool,
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use custos_protobuf::{validate_grpc_protobuf_packet, ValidationConfig, ValidationError};

    /// Maps the AF_XDP rings from the socket file descriptor on Linux.
    ///
    /// # Safety Invariants
    /// * The passed file descriptor `fd` must represent a bound, open AF_XDP socket.
    pub unsafe fn map_rings(
        fd: RawFd,
        config: &WorkerConfig,
    ) -> io::Result<(
        libxdp_sys::xsk_ring_cons,
        libxdp_sys::xsk_ring_prod,
        libxdp_sys::xsk_ring_prod,
        libxdp_sys::xsk_ring_cons,
    )> {
        // 1. Getsockopt to retrieve offsets
        let mut off: libxdp_sys::xdp_mmap_offsets = std::mem::zeroed();
        let mut optlen = std::mem::size_of::<libxdp_sys::xdp_mmap_offsets>() as libc::socklen_t;
        // SAFETY: Calling getsockopt on a valid socket FD to retrieve kernel mapping offsets.
        let res = libc::getsockopt(
            fd,
            libc::SOL_XDP,
            libc::XDP_MMAP_OFFSETS,
            &mut off as *mut _ as *mut libc::c_void,
            &mut optlen,
        );
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        // 2. mmap the rings
        // RX ring
        // SAFETY: mmap is called with valid size and offset (XDP_PGOFF_RX_RING = 0)
        let rx_map = libc::mmap(
            std::ptr::null_mut(),
            (off.rx.desc + config.rx_size * std::mem::size_of::<libxdp_sys::xdp_desc>() as u32)
                as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        if rx_map == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        // TX ring
        // SAFETY: mmap is called with valid size and offset (XDP_PGOFF_TX_RING = 0x80000000)
        let tx_map = libc::mmap(
            std::ptr::null_mut(),
            (off.tx.desc + config.tx_size * std::mem::size_of::<libxdp_sys::xdp_desc>() as u32)
                as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0x80000000,
        );
        if tx_map == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        // Fill ring
        // SAFETY: mmap is called with valid size and offset (XDP_UMEM_PGOFF_FILL_RING = 0x100000000)
        let fill_map = libc::mmap(
            std::ptr::null_mut(),
            (off.fr.desc + config.fill_size * std::mem::size_of::<u64>() as u32) as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0x100000000,
        );
        if fill_map == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        // Completion ring
        // SAFETY: mmap is called with valid size and offset (XDP_UMEM_PGOFF_COMP_RING = 0x180000000)
        let comp_map = libc::mmap(
            std::ptr::null_mut(),
            (off.cr.desc + config.comp_size * std::mem::size_of::<u64>() as u32) as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0x180000000,
        );
        if comp_map == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        // 3. Populate rings structures
        let rx = libxdp_sys::xsk_ring_cons {
            cached_prod: 0,
            cached_cons: 0,
            mask: config.rx_size - 1,
            size: config.rx_size,
            producer: (rx_map as usize + off.rx.producer as usize) as *const u32,
            consumer: (rx_map as usize + off.rx.consumer as usize) as *mut u32,
            ring: (rx_map as usize + off.rx.desc as usize) as *mut libc::c_void,
            flags: (rx_map as usize + off.rx.flags as usize) as *const u32,
        };

        let tx = libxdp_sys::xsk_ring_prod {
            cached_prod: 0,
            cached_cons: 0,
            mask: config.tx_size - 1,
            size: config.tx_size,
            producer: (tx_map as usize + off.tx.producer as usize) as *mut u32,
            consumer: (tx_map as usize + off.tx.consumer as usize) as *const u32,
            ring: (tx_map as usize + off.tx.desc as usize) as *mut libc::c_void,
            flags: (tx_map as usize + off.tx.flags as usize) as *mut u32,
        };

        let fill = libxdp_sys::xsk_ring_prod {
            cached_prod: 0,
            cached_cons: 0,
            mask: config.fill_size - 1,
            size: config.fill_size,
            producer: (fill_map as usize + off.fr.producer as usize) as *mut u32,
            consumer: (fill_map as usize + off.fr.consumer as usize) as *const u32,
            ring: (fill_map as usize + off.fr.desc as usize) as *mut libc::c_void,
            flags: (fill_map as usize + off.fr.flags as usize) as *mut u32,
        };

        let comp = libxdp_sys::xsk_ring_cons {
            cached_prod: 0,
            cached_cons: 0,
            mask: config.comp_size - 1,
            size: config.comp_size,
            producer: (comp_map as usize + off.cr.producer as usize) as *const u32,
            consumer: (comp_map as usize + off.cr.consumer as usize) as *mut u32,
            ring: (comp_map as usize + off.cr.desc as usize) as *mut libc::c_void,
            flags: (comp_map as usize + off.cr.flags as usize) as *const u32,
        };

        Ok((rx, tx, fill, comp))
    }

    /// Runs the core AF_XDP packet polling and processing loop.
    ///
    /// # Safety Invariants
    /// * `umem_addr` must point to the mapped shared memory UMEM region.
    pub unsafe fn run_packet_loop(
        args: &Args,
        config: &WorkerConfig,
        socket_fd: RawFd,
        umem_addr: *mut libc::c_void,
    ) -> Result<(), Box<dyn Error>> {
        // Initialize rings
        // SAFETY: We pass validated FDs and configuration structures.
        let (mut rx_ring, mut tx_ring, mut fill_ring, mut comp_ring) =
            unsafe { map_rings(socket_fd, config)? };
        info!("AF_XDP RX, TX, Fill, and Completion rings mapped successfully");

        // Populate Fill Ring with all available frames initially
        let mut idx: u32 = 0;
        // SAFETY: xsk_ring_prod__reserve is a C helper to allocate fill slots.
        let reserved = unsafe {
            libxdp_sys::xsk_ring_prod__reserve(&mut fill_ring, config.fill_size, &mut idx)
        };
        if reserved != config.fill_size {
            return Err("Failed to populate initial Fill ring slots".into());
        }
        for i in 0..reserved {
            // SAFETY: fill_addr fetches the address slot reference.
            let fill_addr =
                unsafe { libxdp_sys::xsk_ring_prod__fill_addr(&mut fill_ring, idx + i) };
            unsafe {
                *fill_addr = (i as u64) * config.frame_size as u64;
            }
        }
        // SAFETY: Submit the initial fill slots to hardware.
        unsafe {
            libxdp_sys::xsk_ring_prod__submit(&mut fill_ring, reserved);
        }
        info!("Populated Fill Queue with {} frames", reserved);

        // Set validation config
        let mut validation_config = ValidationConfig::default();
        validation_config.target_port = config.target_port;
        info!(
            "Protobuf Validation Rules target_port: {}",
            validation_config.target_port
        );

        // Stats tracking
        let mut rx_packets: u64 = 0;
        let mut tx_packets: u64 = 0;
        let mut drop_packets: u64 = 0;
        let mut recycled_packets: u64 = 0;
        let mut last_stats_time = Instant::now();

        const BATCH_SIZE: u32 = 64;

        loop {
            // A. Consume received packets from RX Ring
            let mut rx_idx: u32 = 0;
            // SAFETY: Peek consumption slots in RX Ring.
            let received =
                unsafe { libxdp_sys::xsk_ring_cons__peek(&mut rx_ring, BATCH_SIZE, &mut rx_idx) };

            if received > 0 {
                rx_packets += received as u64;

                for i in 0..received {
                    // SAFETY: rx_desc fetches descriptor pointer.
                    let rx_desc =
                        unsafe { libxdp_sys::xsk_ring_cons__rx_desc(&rx_ring, rx_idx + i) };
                    let offset = unsafe { (*rx_desc).addr as usize };
                    let len = unsafe { (*rx_desc).len as usize };

                    // Get slice pointing to the packet payload in the shared UMEM
                    // SAFETY: Read-only slice referencing the mapped UMEM region.
                    let buf = unsafe {
                        std::slice::from_raw_parts((umem_addr as usize + offset) as *const u8, len)
                    };

                    // Validate packet using Phase 3 engine
                    match validate_grpc_protobuf_packet(buf, &validation_config) {
                        Ok((_shape, _shape_len)) => {
                            // Forward or Echo packet
                            if args.mode == "echo" {
                                // Swap source and destination MACs in-place
                                // SAFETY: We have exclusive access to the packet payload slice.
                                let contents = unsafe {
                                    std::slice::from_raw_parts_mut(
                                        (umem_addr as usize + offset) as *mut u8,
                                        len,
                                    )
                                };
                                if contents.len() >= 12 {
                                    let mut mac_dst = [0u8; 6];
                                    let mut mac_src = [0u8; 6];
                                    mac_dst.copy_from_slice(&contents[0..6]);
                                    mac_src.copy_from_slice(&contents[6..12]);
                                    contents[0..6].copy_from_slice(&mac_src);
                                    contents[6..12].copy_from_slice(&mac_dst);
                                }
                            }

                            // Submit packet to TX Ring
                            let mut tx_idx: u32 = 0;
                            // SAFETY: Reserve a slot in TX ring.
                            let reserved = unsafe {
                                libxdp_sys::xsk_ring_prod__reserve(&mut tx_ring, 1, &mut tx_idx)
                            };
                            if reserved > 0 {
                                // SAFETY: Retrieve TX descriptor reference.
                                let tx_desc = unsafe {
                                    libxdp_sys::xsk_ring_prod__tx_desc(&mut tx_ring, tx_idx)
                                };
                                unsafe {
                                    (*tx_desc).addr = offset as u64;
                                    (*tx_desc).len = len as u32;
                                    (*tx_desc).options = 0;
                                }
                                // SAFETY: Submit slot to hardware ring.
                                unsafe {
                                    libxdp_sys::xsk_ring_prod__submit(&mut tx_ring, 1);
                                }
                                tx_packets += 1;
                            } else {
                                // Fallback to recycling directly if TX ring is full
                                let mut fill_idx: u32 = 0;
                                // SAFETY: Recycle frame back to Fill ring.
                                let res_fill = unsafe {
                                    libxdp_sys::xsk_ring_prod__reserve(
                                        &mut fill_ring,
                                        1,
                                        &mut fill_idx,
                                    )
                                };
                                if res_fill > 0 {
                                    let fill_addr = unsafe {
                                        libxdp_sys::xsk_ring_prod__fill_addr(
                                            &mut fill_ring,
                                            fill_idx,
                                        )
                                    };
                                    unsafe {
                                        *fill_addr = offset as u64;
                                    }
                                    unsafe {
                                        libxdp_sys::xsk_ring_prod__submit(&mut fill_ring, 1);
                                    }
                                }
                                drop_packets += 1;
                            }
                        }
                        Err(e) => {
                            // Validation failed! Log drop reason (ignoring payloads for privacy) and recycle
                            trace!("Packet validation failed: {:?}. Dropping packet.", e);

                            let mut fill_idx: u32 = 0;
                            // SAFETY: Recycle frame back to Fill ring.
                            let res_fill = unsafe {
                                libxdp_sys::xsk_ring_prod__reserve(&mut fill_ring, 1, &mut fill_idx)
                            };
                            if res_fill > 0 {
                                let fill_addr = unsafe {
                                    libxdp_sys::xsk_ring_prod__fill_addr(&mut fill_ring, fill_idx)
                                };
                                unsafe {
                                    *fill_addr = offset as u64;
                                }
                                unsafe {
                                    libxdp_sys::xsk_ring_prod__submit(&mut fill_ring, 1);
                                }
                            }
                            drop_packets += 1;
                        }
                    }
                }
                // SAFETY: Release consumed slots.
                unsafe {
                    libxdp_sys::xsk_ring_cons__release(&mut rx_ring, received);
                }
            }

            // B. Reclaim completed TX frames from Completion Ring and return to Fill Ring
            let mut comp_idx: u32 = 0;
            // SAFETY: Peek Completion queue.
            let completed = unsafe {
                libxdp_sys::xsk_ring_cons__peek(&mut comp_ring, BATCH_SIZE, &mut comp_idx)
            };
            if completed > 0 {
                let mut fill_idx: u32 = 0;
                // SAFETY: Reserve slots to recycle frames.
                let reserved = unsafe {
                    libxdp_sys::xsk_ring_prod__reserve(&mut fill_ring, completed, &mut fill_idx)
                };
                if reserved > 0 {
                    for i in 0..reserved {
                        // SAFETY: Read completed address offset.
                        let comp_addr = unsafe {
                            libxdp_sys::xsk_ring_cons__comp_addr(&comp_ring, comp_idx + i)
                        };
                        let completed_offset = unsafe { *comp_addr };

                        // SAFETY: Write slot in Fill queue.
                        let fill_addr = unsafe {
                            libxdp_sys::xsk_ring_prod__fill_addr(&mut fill_ring, fill_idx + i)
                        };
                        unsafe {
                            *fill_addr = completed_offset;
                        }
                    }
                    // SAFETY: Submit recycled slots.
                    unsafe {
                        libxdp_sys::xsk_ring_prod__submit(&mut fill_ring, reserved);
                    }
                    recycled_packets += reserved as u64;
                    // SAFETY: Release only completion slots recycled into the fill ring.
                    unsafe {
                        libxdp_sys::xsk_ring_cons__release(&mut comp_ring, reserved);
                    }
                }
            }

            // C. Wakeups if needed
            // SAFETY: Check needs_wakeup on TX ring.
            if unsafe { libxdp_sys::xsk_ring_prod__needs_wakeup(&tx_ring) } != 0 {
                // SAFETY: sendto syscall triggers kernel TX processing.
                let _ = unsafe {
                    libc::sendto(
                        socket_fd,
                        ptr::null(),
                        0,
                        libc::MSG_DONTWAIT,
                        ptr::null(),
                        0,
                    )
                };
            }

            // SAFETY: Check needs_wakeup on Fill ring.
            if unsafe { libxdp_sys::xsk_ring_prod__needs_wakeup(&fill_ring) } != 0 {
                // SAFETY: poll syscall triggers kernel RX/Fill processing.
                let mut fds = [libc::pollfd {
                    fd: socket_fd,
                    events: libc::POLLIN,
                    revents: 0,
                }];
                let _ = unsafe { libc::poll(fds.as_mut_ptr(), 1, 0) };
            }

            // D. Periodic statistics logging
            if last_stats_time.elapsed() >= Duration::from_secs(1) {
                info!(
                    "Periodic Statistics: RX={} TX={} Dropped={} Recycled={}",
                    rx_packets, tx_packets, drop_packets, recycled_packets
                );
                last_stats_time = Instant::now();
            }
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let log_level = if args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let subscriber = FmtSubscriber::builder().with_max_level(log_level).finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting Custos Unprivileged Kubernetes Worker...");
    info!("Configuration: {:?}", args);

    // Thread Pinning
    custos_common::pin_thread_to_core(args.core)?;

    // Connect to host daemon's UDS
    info!("Connecting to host daemon UDS at: {}", args.socket_path);
    let mut stream = UnixStream::connect(&args.socket_path)?;

    // 1. Read JSON configuration
    let mut config_line = String::new();
    let mut byte = [0u8; 1];
    while byte[0] != b'\n' {
        stream.read_exact(&mut byte)?;
        config_line.push(byte[0] as char);
    }
    let config: WorkerConfig = serde_json::from_str(&config_line)?;
    info!("Received WorkerConfig from daemon: {:?}", config);

    // 2. Receive FDs
    let mut fds = [0; 2];
    let count = recv_fds(&stream, &mut fds)?;
    if count < 2 {
        return Err("Failed to receive both socket and memfd file descriptors".into());
    }
    let socket_fd = fds[0];
    let memfd = fds[1];
    info!("Received socket FD: {}, memfd FD: {}", socket_fd, memfd);

    // Map shared UMEM frames in worker process
    let umem_size = (config.frame_count * config.frame_size) as usize;
    // SAFETY: mmap is called on the valid memfd file descriptor to map the memory region.
    let umem_addr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            umem_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            memfd,
            0,
        )
    };
    if umem_addr == libc::MAP_FAILED {
        return Err(format!("mmap of memfd failed: {}", io::Error::last_os_error()).into());
    }
    info!(
        "Shared UMEM mapped in worker at virtual address: {:?}",
        umem_addr
    );

    #[cfg(target_os = "linux")]
    {
        // SAFETY: We pass validated FDs, configuration, and mapped memory address.
        unsafe { linux::run_packet_loop(&args, &config, socket_fd, umem_addr)? };
    }

    #[cfg(not(target_os = "linux"))]
    {
        info!("Kubernetes worker stub running successfully on development OS.");
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    Ok(())
}
