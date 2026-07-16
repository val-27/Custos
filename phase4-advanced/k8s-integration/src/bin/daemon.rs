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
use std::os::unix::fs::PermissionsExt;
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
            unsafe {
                libc::close(fd);
            }
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
            unsafe {
                libc::close(fd);
            }
            return Err(io::Error::last_os_error());
        }
        // SAFETY: Unlinking file so it deletes on close.
        unsafe {
            libc::unlink(path.as_ptr());
        }
        Ok(fd)
    }
}

/// Verifies the peer credentials of the worker connecting over UDS.
#[cfg(target_os = "linux")]
fn verify_peer_credentials(stream: &std::os::unix::net::UnixStream) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let mut ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt is called on the UnixStream FD to verify credentials.
    let res = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if res < 0 {
        return Err(io::Error::last_os_error());
    }

    // Allow root (0), the unprivileged worker UID (10001), or 'nobody' (65534).
    if ucred.uid != 0 && ucred.uid != 10001 && ucred.uid != 65534 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Unauthorized peer connection from UID {}", ucred.uid),
        ));
    }
    info!("Verified worker credentials: PID={}, UID={}, GID={}", ucred.pid, ucred.uid, ucred.gid);
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    /// Core Linux AF_XDP socket setup using libxdp.
    ///
    /// # Safety Invariants
    /// * `umem_addr` must point to a valid, mapped UMEM memory region of size `umem_size`.
    pub unsafe fn run_daemon_setup(
        args: &Args,
        umem_addr: *mut libc::c_void,
        umem_size: usize,
    ) -> Result<(RawFd, *mut libxdp_sys::xsk_umem, *mut libxdp_sys::xsk_socket), Box<dyn Error>> {
        let mut umem_ptr: *mut libxdp_sys::xsk_umem = std::ptr::null_mut();
        let mut fq = Box::new(std::mem::zeroed::<libxdp_sys::xsk_ring_prod>());
        let mut cq = Box::new(std::mem::zeroed::<libxdp_sys::xsk_ring_cons>());

        let umem_config = libxdp_sys::xsk_umem_config {
            fill_size: args.frame_count,
            comp_size: args.frame_count,
            frame_size: args.frame_size,
            frame_headroom: 0,
            flags: 0,
        };

        // 1. Create UMEM
        // SAFETY: calling libxdp_sys::xsk_umem__create to create the UMEM.
        let err = unsafe {
            libxdp_sys::xsk_umem__create(
                &mut umem_ptr,
                umem_addr,
                umem_size as u64,
                fq.as_mut(),
                cq.as_mut(),
                &umem_config,
            )
        };
        if err != 0 {
            return Err(format!("xsk_umem__create failed: {}", io::Error::from_raw_os_error(-err)).into());
        }
        info!("UMEM registered with the kernel successfully using libxdp");

        // 2. Create Socket Config
        let socket_config = libxdp_sys::xsk_socket_config {
            rx_size: args.frame_count,
            tx_size: args.frame_count,
            libxdp_flags: 0,
            xdp_flags: 0,
            bind_flags: if args.force_copy {
                libxdp_sys::XDP_COPY as u16
            } else {
                libxdp_sys::XDP_USE_NEED_WAKEUP as u16
            },
        };

        // 3. Create Socket (automatically binds to interface and loads BPF program)
        let mut socket_ptr: *mut libxdp_sys::xsk_socket = std::ptr::null_mut();
        let mut rx = Box::new(std::mem::zeroed::<libxdp_sys::xsk_ring_cons>());
        let mut tx = Box::new(std::mem::zeroed::<libxdp_sys::xsk_ring_prod>());
        let ifname_cstr = std::ffi::CString::new(args.interface.clone()).unwrap();

        // SAFETY: calling libxdp_sys::xsk_socket__create to create and bind the socket.
        let err = unsafe {
            libxdp_sys::xsk_socket__create(
                &mut socket_ptr,
                ifname_cstr.as_ptr(),
                args.queue_id,
                umem_ptr,
                rx.as_mut(),
                tx.as_mut(),
                &socket_config,
            )
        };
        if err != 0 {
            // SAFETY: Clean up UMEM if socket creation fails.
            unsafe { libxdp_sys::xsk_umem__delete(umem_ptr); }
            return Err(format!("xsk_socket__create failed: {}", io::Error::from_raw_os_error(-err)).into());
        }

        // 4. Get socket FD
        // SAFETY: Calling xsk_socket__fd on a valid socket pointer.
        let socket_fd = unsafe { libxdp_sys::xsk_socket__fd(socket_ptr) };
        if socket_fd < 0 {
            // SAFETY: Clean up resources on failure.
            unsafe {
                libxdp_sys::xsk_socket__delete(socket_ptr);
                libxdp_sys::xsk_umem__delete(umem_ptr);
            }
            return Err(format!("xsk_socket__fd returned invalid fd: {}", socket_fd).into());
        }

        info!("AF_XDP socket created, bound, and default eBPF redirect program attached successfully");
        Ok((socket_fd, umem_ptr, socket_ptr))
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
    info!(
        "Shared UMEM mapped in daemon at virtual address: {:?}",
        umem_addr
    );

    // Create AF_XDP socket & register UMEM
    let socket_fd: RawFd;
    let _umem_ptr: *mut libc::c_void;
    let _socket_ptr: *mut libc::c_void;

    #[cfg(target_os = "linux")]
    {
        // SAFETY: We pass verified arguments and map UMEM successfully.
        let (fd, u_ptr, s_ptr) = unsafe { linux::run_daemon_setup(&args, umem_addr, umem_size)? };
        socket_fd = fd;
        _umem_ptr = u_ptr as *mut libc::c_void;
        _socket_ptr = s_ptr as *mut libc::c_void;
    }

    #[cfg(not(target_os = "linux"))]
    {
        socket_fd = 999; // Mock file descriptor
        _umem_ptr = ptr::null_mut();
        _socket_ptr = ptr::null_mut();
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
    // Set 0o660 permissions so only owner and group can write/read the socket
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660))?;
    info!(
        "Unix Domain Socket server listening on: {} (mode: 0660)",
        args.socket_path
    );

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

                // Authenticate peer credentials on Linux
                #[cfg(target_os = "linux")]
                {
                    if let Err(e) = verify_peer_credentials(&stream) {
                        error!("Peer credentials validation failed: {}. Rejecting client.", e);
                        continue;
                    }
                }

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
                        info!(
                            "Successfully passed socket FD ({}) and UMEM memfd ({}) to worker",
                            socket_fd, memfd
                        );
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
