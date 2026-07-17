//! Kubernetes Daemon Integration.
//! Handles SCM_RIGHTS Unix domain socket file descriptor passing for unprivileged XDP execution.
//!
//! Provides utilities for transferring file descriptors (socket and memfd) from the
//! privileged daemon to the unprivileged worker.

use std::io::{self, Read};
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;

/// Configuration passed from the daemon to the worker over UDS.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct WorkerConfig {
    pub frame_count: u32,
    pub frame_size: u32,
    pub rx_size: u32,
    pub tx_size: u32,
    pub fill_size: u32,
    pub comp_size: u32,
    pub queue_id: u32,
    pub mode: String,
    pub target_port: u16,
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

/// Receives an AF_XDP socket file descriptor over SCM_RIGHTS (compatible with the skeleton design).
pub fn receive_socket_fd(socket_path: &str) -> Result<std::os::unix::io::RawFd, String> {
    tracing::info!("Connecting to UNIX socket at: {}", socket_path);
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("Failed to connect to Unix socket: {}", e))?;
    let mut config_line = String::new();
    let mut byte = [0u8; 1];
    while byte[0] != b'\n' {
        stream
            .read_exact(&mut byte)
            .map_err(|e| format!("Failed to receive worker configuration: {}", e))?;
        config_line.push(byte[0] as char);
    }
    serde_json::from_str::<WorkerConfig>(&config_line)
        .map_err(|e| format!("Failed to parse worker configuration: {}", e))?;

    let mut fds = [0; 2];
    let count = recv_fds(&stream, &mut fds)
        .map_err(|e| format!("Failed to receive file descriptors: {}", e))?;

    if count == 0 {
        return Err("No file descriptors received".to_string());
    }

    tracing::info!(
        "Successfully received {} file descriptors over UDS SCM_RIGHTS",
        count
    );
    Ok(fds[0])
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
