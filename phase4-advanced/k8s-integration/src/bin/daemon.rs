#![allow(unused_imports)]

//! Privileged Host-Level Daemon for Custos.
//!
//! Creates the AF_XDP socket, allocates the shared UMEM region via memfd_create,
//! binds to the specified network interface/queue, loads the XDP/eBPF redirection program,
//! and passes the resulting file descriptors (socket and memfd) to the unprivileged worker
//! over a Unix domain socket.


use clap::Parser;
use custos_k8s_integration::{send_fds, WorkerConfig};
use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::ptr;
use tracing::{debug, error, info, Level};
use tracing_subscriber::FmtSubscriber;

/// CLI Arguments for the Daemon.
#[derive(Parser, Debug)]
#[command(name = "custos-k8s-daemon")]
#[command(about = "Privileged Custos Host Daemon for AF_XDP Setup", long_about = None)]
pub struct Args {
    /// Interface name to bind to (e.g. eth0, veth_sim)
    #[arg(short, long)]
    pub interface: String,

    /// Queue ID to bind the AF_XDP socket to
    #[arg(short, long, default_value_t = 0)]
    pub queue_id: u32,

    /// Unix domain socket path to listen on for workers
    #[arg(short, long, default_value = "/var/run/custos.sock")]
    pub socket_path: String,

    /// Target port to redirect/filter (e.g. 50051)
    #[arg(short, long, default_value_t = 50051)]
    pub target_port: u16,

    /// UMEM frame count (must be a power of 2)
    #[arg(long, default_value_t = 2048)]
    pub frame_count: u32,

    /// UMEM frame size
    #[arg(long, default_value_t = 2048)]
    pub frame_size: u32,

    /// Force copy-mode (XDP_COPY)
    #[arg(long)]
    pub force_copy: bool,

    /// Enable verbose logging
    #[arg(short, long)]
    pub verbose: bool,
}

/// Allocates shared memory using memfd_create on Linux, or a temporary file on macOS.
fn create_shared_mem_fd(size: usize) -> io::Result<RawFd> {
    #[cfg(target_os = "linux")]
    {
        let name = std::ffi::CString::new("custos_umem").unwrap();
        // SAFETY: Calling standard Linux system call memfd_create.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: Resizing the memfd via ftruncate.
        let res = unsafe { libc::ftruncate(fd, size as libc::off_t) };
        if res < 0 {
            unsafe { libc::close(fd); }
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let path = std::ffi::CString::new("/tmp/custos_umem.bin").unwrap();
        // SAFETY: open is standard POSIX system call.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC,
                0o666,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: Resizing file via ftruncate.
        let res = unsafe { libc::ftruncate(fd, size as libc::off_t) };
        if res < 0 {
            unsafe { libc::close(fd); }
            return Err(io::Error::last_os_error());
        }
        // SAFETY: Unlinking file so it deletes on close.
        unsafe { libc::unlink(path.as_ptr()); }
        Ok(fd)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    /// Core Linux AF_XDP socket setup.
    ///
    /// # Safety Invariants
    /// * `umem_addr` must point to a valid, mapped UMEM memory region of size `umem_size`.
    pub unsafe fn run_daemon_setup(
        args: &Args,
        umem_addr: *mut libc::c_void,
        umem_size: usize,
    ) -> Result<RawFd, Box<dyn Error>> {
        // 1. Create AF_XDP socket
        // SAFETY: socket is called with AF_XDP and SOCK_RAW.
        let fd = unsafe { libc::socket(libc::AF_XDP, libc::SOCK_RAW, 0) };
        if fd < 0 {
            return Err(format!("Failed to create AF_XDP socket: {}", io::Error::last_os_error()).into());
        }
        let socket_fd = fd;
        info!("Created AF_XDP socket FD: {}", socket_fd);

        // 2. Register UMEM
        let mut umem_reg = libxdp_sys::xdp_umem_reg {
            addr: umem_addr as u64,
            len: umem_size as u64,
            chunk_size: args.frame_size,
            headroom: 0,
            flags: 0,
        };
        // SAFETY: setsockopt registers the allocated UMEM region with the kernel.
        let res = unsafe {
            libc::setsockopt(
                socket_fd,
                libc::SOL_XDP,
                libc::XDP_UMEM_REG,
                &mut umem_reg as *mut _ as *mut libc::c_void,
                std::mem::size_of::<libxdp_sys::xdp_umem_reg>() as libc::socklen_t,
            )
        };
        if res < 0 {
            return Err(format!("Failed to register UMEM: {}", io::Error::last_os_error()).into());
        }
        info!("UMEM registered with the kernel successfully");

        // 3. Set ring sizes
        let ring_size = args.frame_count;
        // SAFETY: setsockopt sets Fill ring size
        let res = unsafe {
            libc::setsockopt(
                socket_fd,
                libc::SOL_XDP,
                libc::XDP_UMEM_FILL_RING,
                &ring_size as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if res < 0 {
            return Err(format!("Failed to set UMEM Fill ring size: {}", io::Error::last_os_error()).into());
        }
        // SAFETY: setsockopt sets Completion ring size
        let res = unsafe {
            libc::setsockopt(
                socket_fd,
                libc::SOL_XDP,
                libc::XDP_UMEM_COMP_RING,
                &ring_size as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if res < 0 {
            return Err(format!("Failed to set UMEM Completion ring size: {}", io::Error::last_os_error()).into());
        }
        // SAFETY: setsockopt sets RX ring size
        let res = unsafe {
            libc::setsockopt(
                socket_fd,
                libc::SOL_XDP,
                libc::XDP_RX_RING,
                &ring_size as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if res < 0 {
            return Err(format!("Failed to set RX ring size: {}", io::Error::last_os_error()).into());
        }
        // SAFETY: setsockopt sets TX ring size
        let res = unsafe {
            libc::setsockopt(
                socket_fd,
                libc::SOL_XDP,
                libc::XDP_TX_RING,
                &ring_size as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if res < 0 {
            return Err(format!("Failed to set TX ring size: {}", io::Error::last_os_error()).into());
        }

        // 4. Bind socket to interface and queue
        let if_index = unsafe { libc::if_nametoindex(std::ffi::CString::new(args.interface.clone()).unwrap().as_ptr()) };
        if if_index == 0 {
            return Err(format!("Failed to find interface index for '{}'", args.interface).into());
        }

        let mut bind_flags = libc::XDP_USE_NEED_WAKEUP;
        if args.force_copy {
            bind_flags |= libc::XDP_COPY;
        }

        let mut addr: libc::sockaddr_xdp = std::mem::zeroed();
        addr.sxdp_family = libc::AF_XDP as u16;
        addr.sxdp_flags = bind_flags as u16;
        addr.sxdp_ifindex = if_index;
        addr.sxdp_queue_id = args.queue_id;

        // SAFETY: bind binds the socket to the physical interface and queue. Requires CAP_NET_ADMIN.
        let res = unsafe {
            libc::bind(
                socket_fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_xdp>() as libc::socklen_t,
            )
        };
        if res < 0 {
            return Err(format!("Failed to bind AF_XDP socket: {}", io::Error::last_os_error()).into());
        }
        info!("AF_XDP socket bound to interface '{}' (index {}), queue {}", args.interface, if_index, args.queue_id);

        Ok(socket_fd)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let log_level = if args.verbose { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder().with_max_level(log_level).finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting Custos Privileged Kubernetes Daemon...");
    info!("Configuration: {:?}", args);

    // Calculate UMEM size
    let umem_size = (args.frame_count * args.frame_size) as usize;
    info!("Allocating shared UMEM memfd of size: {} bytes", umem_size);
    let memfd = create_shared_mem_fd(umem_size)?;

    // Map UMEM in daemon address space
    // SAFETY: mmap maps the allocated memfd in the daemon's virtual memory layout.
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
    info!("Shared UMEM mapped in daemon at virtual address: {:?}", umem_addr);

    // Create AF_XDP socket & register UMEM
    let socket_fd: RawFd;

    #[cfg(target_os = "linux")]
    {
        // SAFETY: We pass verified arguments and map UMEM successfully.
        socket_fd = unsafe { linux::run_daemon_setup(&args, umem_addr, umem_size)? };
    }

    #[cfg(not(target_os = "linux"))]
    {
        socket_fd = 999; // Mock file descriptor
        info!("Running on non-Linux OS. Stubbing AF_XDP socket creation (mock FD 999)");
    }

    // Set up Unix Domain Socket for passing FDs
    let socket_path = Path::new(&args.socket_path);
    if socket_path.exists() {
        info!("Removing existing Unix socket file: {}", args.socket_path);
        let _ = fs::remove_file(socket_path);
    }

    // Ensure parent directory exists
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    info!("Unix Domain Socket server listening on: {}", args.socket_path);

    // Prepare worker configuration to send first
    let worker_config = WorkerConfig {
        frame_count: args.frame_count,
        frame_size: args.frame_size,
        rx_size: args.frame_count,
        tx_size: args.frame_count,
        fill_size: args.frame_count,
        comp_size: args.frame_count,
        queue_id: args.queue_id,
        mode: "forward".to_string(),
        target_port: args.target_port,
    };

    // Accept loop - waiting for unprivileged workers to connect
    loop {
        match listener.accept() {
            Ok((mut stream, addr)) => {
                info!("Accepted client connection from: {:?}", addr);

                // 1. Send configuration as JSON
                let config_str = serde_json::to_string(&worker_config)?;
                let mut config_bytes = config_str.as_bytes().to_vec();
                config_bytes.push(b'\n'); // Newline delimiter
                
                if let Err(e) = stream.write_all(&config_bytes) {
                    error!("Failed to write configuration to worker: {}", e);
                    continue;
                }
                info!("Sent configuration payload to worker");

                // 2. Pass socket and UMEM FDs via SCM_RIGHTS
                let fds_to_send = [socket_fd, memfd];
                match send_fds(&stream, &fds_to_send) {
                    Ok(_) => {
                        info!("Successfully passed socket FD ({}) and UMEM memfd ({}) to worker", socket_fd, memfd);
                    }
                    Err(e) => {
                        error!("Failed to pass file descriptors to worker: {}", e);
                    }
                }
            }
            Err(e) => {
                error!("Accept error: {}", e);
            }
        }
    }
}
