//! Kubernetes Daemon Integration.
//! Handles SCM_RIGHTS Unix domain socket file descriptor passing for unprivileged XDP execution.
//!
//! Provides utilities for transferring file descriptors (socket and memfd) from the
//! privileged daemon to the unprivileged worker.

use std::io::{self, BufRead, BufReader};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use custos_common::OperationMode;

/// Configuration passed from the daemon to the worker over UDS.
///
/// Serialized as JSON and transmitted newline-delimited over the Unix domain socket
/// before the `SCM_RIGHTS` ancillary message carrying the AF_XDP socket fd.
///
/// # Field Notes
/// - `mode`: one of `"forward"` or `"echo"`. Must match a valid [`custos_common::OperationMode`].
/// - `queue_id`: the NIC hardware queue to bind the AF_XDP socket to.
/// - `target_port`: destination TCP port used by the protobuf validation filter.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct WorkerConfig {
    /// Number of UMEM frames (must be a power of two).
    pub frame_count: u32,
    /// Size of each UMEM frame in bytes (typically 2048).
    pub frame_size: u32,
    /// Number of entries in the RX ring.
    pub rx_size: u32,
    /// Number of entries in the TX ring.
    pub tx_size: u32,
    /// Number of entries in the Fill ring.
    pub fill_size: u32,
    /// Number of entries in the Completion ring.
    pub comp_size: u32,
    /// NIC hardware queue index.
    pub queue_id: u32,
    /// Packet processing mode.
    pub mode: OperationMode,
    /// Target TCP destination port for gRPC validation.
    pub target_port: u16,
}

/// Errors that can occur during K8s daemon↔worker socket handshake.
#[derive(Debug)]
pub enum K8sError {
    /// Failed to connect or perform I/O on the Unix domain socket.
    Io(io::Error),
    /// The worker config JSON received from the daemon could not be parsed.
    ConfigParse(serde_json::Error),
    /// The `SCM_RIGHTS` message was received but contained no file descriptors.
    NoFdsReceived,
}

impl std::fmt::Display for K8sError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "Unix socket I/O error: {}", e),
            Self::ConfigParse(e) => write!(f, "Worker config parse error: {}", e),
            Self::NoFdsReceived => write!(f, "SCM_RIGHTS message contained no file descriptors"),
        }
    }
}

impl std::error::Error for K8sError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::ConfigParse(e) => Some(e),
            Self::NoFdsReceived => None,
        }
    }
}

impl From<io::Error> for K8sError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for K8sError {
    fn from(e: serde_json::Error) -> Self {
        Self::ConfigParse(e)
    }
}

/// Sends a list of file descriptors over a Unix domain socket using `SCM_RIGHTS`.
///
/// # Purpose
/// This function allows the privileged daemon to transfer ownership/access of critical, restricted
/// resources (the bound AF_XDP socket and the shared UMEM memfd) to the unprivileged worker process.
///
/// # Safety Invariants
/// * The Unix domain socket stream must be active and valid.
/// * The passed file descriptors must represent open, valid, and active resources.
/// * The receiver must use the matching `recv_fds` implementation to read the ancillary message payload.
///
/// # Performance Rationale
/// Zero-copy descriptor passing via the kernel kernel-space duplicate operation avoids copying packet payloads.
/// The vector allocation for the control buffer is done based on slice length to keep allocation costs minimal.
pub fn send_fds(stream: &UnixStream, fds: &[RawFd]) -> io::Result<()> {
    let socket_fd = stream.as_raw_fd();

    // We send 1 dummy byte of payload data to ensure getsockopt/recvmsg handles the message.
    let mut dummy: libc::c_char = 0;
    let mut iov = libc::iovec {
        iov_base: &mut dummy as *mut _ as *mut libc::c_void,
        iov_len: 1,
    };

    // SAFETY: CMSG_LEN is a safe glibc macro called via libc bindings.
    let cmsg_len = unsafe { libc::CMSG_LEN(std::mem::size_of_val(fds) as libc::c_uint) };
    let mut cmsg_buf = vec![0u8; cmsg_len as usize];

    let msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: cmsg_buf.as_mut_ptr() as *mut libc::c_void,
        msg_controllen: cmsg_len,
        msg_flags: 0,
    };

    // SAFETY: We query the first control message header using the msghdr pointer.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(io::Error::other("CMSG_FIRSTHDR failed"));
    }

    // SAFETY: The allocated `cmsg_buf` is guaranteed to be big enough to write the `fds` array.
    // We perform a direct copy of RawFd integers into the CMSG data segment.
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = cmsg_len;

        let data_ptr = libc::CMSG_DATA(cmsg) as *mut RawFd;
        std::ptr::copy_nonoverlapping(fds.as_ptr(), data_ptr, fds.len());
    }

    // SAFETY: sendmsg is a standard POSIX system call. We pass a valid msghdr pointing to
    // temporary buffers pinned in memory for the duration of the call.
    let sent = unsafe { libc::sendmsg(socket_fd, &msg, 0) };
    if sent < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Receives a list of file descriptors over a Unix domain socket using `SCM_RIGHTS`.
///
/// # Purpose
/// This function is called by the unprivileged worker to inherit the socket and memfd descriptors passed by the daemon.
///
/// # Safety Invariants
/// * The caller must supply a mutable slice `fds` which has enough space to hold all received descriptors.
/// * The received file descriptors become owned by the calling process and must be closed or wrapped properly.
///
/// # Performance Rationale
/// Avoids overhead by utilizing a single `recvmsg` syscall. Memory allocation for the buffer is bounded
/// and matched to the size of the target `fds` slice.
pub fn recv_fds(stream: &UnixStream, fds: &mut [RawFd]) -> io::Result<usize> {
    let socket_fd = stream.as_raw_fd();

    let mut dummy: libc::c_char = 0;
    let mut iov = libc::iovec {
        iov_base: &mut dummy as *mut _ as *mut libc::c_void,
        iov_len: 1,
    };

    // SAFETY: CMSG_LEN is a safe glibc macro called via libc bindings.
    let cmsg_len = unsafe { libc::CMSG_LEN(std::mem::size_of_val(fds) as libc::c_uint) };
    let mut cmsg_buf = vec![0u8; cmsg_len as usize];

    let mut msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: cmsg_buf.as_mut_ptr() as *mut libc::c_void,
        msg_controllen: cmsg_len,
        msg_flags: 0,
    };

    // SAFETY: recvmsg is a standard POSIX system call. We pass a mutable pointer to msghdr
    // which remains pinned in the caller's stack frame.
    let received = unsafe { libc::recvmsg(socket_fd, &mut msg, 0) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: We query the first control message header using the msghdr pointer.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(io::Error::other("No control message received"));
    }

    // SAFETY: We validate the levels, types, and sizes before reading the descriptors.
    // The data is copied safely using `copy_nonoverlapping` into the pre-allocated slice.
    unsafe {
        if (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return Err(io::Error::other("Received invalid control message"));
        }

        let data_ptr = libc::CMSG_DATA(cmsg) as *const RawFd;
        let num_fds =
            ((*cmsg).cmsg_len - libc::CMSG_LEN(0)) as usize / std::mem::size_of::<RawFd>();
        let copy_count = std::cmp::min(fds.len(), num_fds);
        std::ptr::copy_nonoverlapping(data_ptr, fds.as_mut_ptr(), copy_count);
        Ok(copy_count)
    }
}

/// Receives an AF_XDP socket file descriptor over `SCM_RIGHTS` and wraps it in an [`OwnedFd`].
///
/// # Purpose
/// Called by the unprivileged worker to inherit the bound AF_XDP socket descriptor
/// sent by the privileged daemon. The returned [`OwnedFd`] guarantees the fd is
/// closed when it goes out of scope, preventing descriptor leaks.
///
/// # Errors
/// - [`K8sError::Io`] — I/O failure on the Unix socket (connect, read, or `recvmsg`).
/// - [`K8sError::ConfigParse`] — The JSON `WorkerConfig` line could not be deserialized.
/// - [`K8sError::NoFdsReceived`] — The `SCM_RIGHTS` message contained zero file descriptors.
///
/// # Safety Invariants
/// The function receives raw `RawFd` integers from the kernel via `SCM_RIGHTS` and
/// immediately wraps the first one in `OwnedFd` so that Rust owns its lifetime.
/// Any additional fds beyond the first are closed explicitly to prevent leaks.
pub fn receive_socket_fd(socket_path: &str) -> Result<(OwnedFd, WorkerConfig), K8sError> {
    tracing::info!("Connecting to UNIX socket at: {}", socket_path);
    let stream = UnixStream::connect(socket_path)?;

    // Read the newline-delimited JSON WorkerConfig using a buffered reader.
    // BufReader::read_line is efficient (buffers internally) and handles multi-byte UTF-8
    // correctly, unlike the previous byte-by-byte loop with `as char` truncation.
    let mut config_line = String::new();
    {
        let mut reader = BufReader::new(&stream);
        reader.read_line(&mut config_line)?;
    }
    let config: WorkerConfig = serde_json::from_str(config_line.trim_end())?;
    tracing::debug!("Received worker config: {:?}", config);

    // Receive up to 2 fds (daemon may send socket fd + optional memfd).
    let mut raw_fds: [RawFd; 2] = [-1; 2];
    let count = recv_fds(&stream, &mut raw_fds)?;

    if count == 0 {
        return Err(K8sError::NoFdsReceived);
    }

    // SAFETY: The kernel guarantees that each RawFd in raw_fds[0..count] is a valid,
    // open file descriptor owned by this process as of the recvmsg call. Wrapping in
    // OwnedFd transfers that ownership to Rust, which will close it on drop.
    let socket_fd = unsafe { OwnedFd::from_raw_fd(raw_fds[0]) };

    // Explicitly close any additional fds received beyond the first to avoid leaks.
    // The daemon may send a second fd (e.g. memfd for UMEM) that this simplified
    // receiver does not use. Dropping them here prevents fd exhaustion.
    for &extra_fd in &raw_fds[1..count] {
        // SAFETY: extra_fd is a valid open fd received via SCM_RIGHTS and not yet owned
        // by any Rust type. We close it directly to release the kernel resource.
        let ret = unsafe { libc::close(extra_fd) };
        if ret != 0 {
            tracing::warn!(
                "Failed to close extra received fd {}: {}",
                extra_fd,
                io::Error::last_os_error()
            );
        }
    }

    tracing::info!(
        "Successfully received {} file descriptor(s) over UDS SCM_RIGHTS",
        count
    );
    Ok((socket_fd, config))
}


#[cfg(test)]
mod tests {
    use super::{recv_fds, send_fds};
    use std::fs::File;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn passes_multiple_file_descriptors_over_unix_socket() {
        let (sender, receiver) = UnixStream::pair().expect("create UnixStream pair");
        let first = File::open("Cargo.toml").expect("open first descriptor");
        let second = File::open("Cargo.toml").expect("open second descriptor");
        let sent = [first.as_raw_fd(), second.as_raw_fd()];

        send_fds(&sender, &sent).expect("send descriptors");

        let mut received = [-1; 2];
        let count = recv_fds(&receiver, &mut received).expect("receive descriptors");

        assert_eq!(count, sent.len());
        for fd in received {
            assert!(fd >= 0);
            // SAFETY: `recv_fds` returned owned descriptors that this test must close.
            assert_eq!(unsafe { libc::close(fd) }, 0);
        }
    }
}
