//! Bounded per-datagram Linux credential observation. This does not authenticate
//! an independent authority, authorize work, or establish process ownership.

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;

pub struct CredentialReceiver {
    socket: UnixDatagram,
}

impl CredentialReceiver {
    /// Enables kernel credentials on an already-created local datagram socket.
    /// No network socket is bound or connected by this function.
    pub fn new(socket: UnixDatagram) -> io::Result<Self> {
        let enabled: libc::c_int = 1;
        // SAFETY: socket is live and enabled points to a valid integer.
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&enabled as *const libc::c_int).cast(),
                std::mem::size_of_val(&enabled) as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { socket })
    }

    /// Consumes one bounded, nonblocking probe. Any payload other than `P`,
    /// truncated message, missing/duplicate credentials, or unexpected control
    /// message is rejected. Received SCM_RIGHTS descriptors are always closed.
    pub fn matches_sender(&self, expected_pid: u32) -> io::Result<bool> {
        self.receive_observation(expected_pid)
            .map(|(matched, _)| matched)
    }

    fn receive_observation(&self, expected_pid: u32) -> io::Result<(bool, libc::c_int)> {
        let mut bytes = [0u8; 2];
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        // usize guarantees alignment for cmsghdr; the fixed buffer is bounded.
        let mut control = [0usize; 32];
        // SAFETY: zero initializes all optional msghdr fields to empty.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        // SAFETY: message references live writable buffers; CLOEXEC prevents
        // received descriptors being inherited before we can reject them.
        let received = unsafe {
            libc::recvmsg(
                self.socket.as_raw_fd(),
                &mut message,
                libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: recvmsg supplied the ancillary buffer; each descriptor it
        // installed is owned by this process and must be closed exactly once.
        let matched = unsafe {
            parse_control(&message, received, &bytes, expected_pid, |fd| {
                libc::close(fd);
            })
        };
        Ok((matched, message.msg_flags))
    }
}

/// Caller supplies an aligned control buffer valid for msg_controllen bytes;
/// close_right receives every complete descriptor in well-formed SCM_RIGHTS.
unsafe fn parse_control(
    message: &libc::msghdr,
    received: isize,
    bytes: &[u8; 2],
    expected_pid: u32,
    mut close_right: impl FnMut(libc::c_int),
) -> bool {
    let mut valid = received == 1
        && bytes[0] == b'P'
        && message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0;
    let mut sender = None;
    let mut seen_credentials = false;
    // SAFETY: recvmsg populated msg_control and msg_controllen. CMSG helpers
    // iterate within that kernel-produced buffer; lengths are checked below.
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        // SAFETY: header was returned by the kernel CMSG iterator.
        let (length, level, kind) = unsafe {
            (
                (*header).cmsg_len,
                (*header).cmsg_level,
                (*header).cmsg_type,
            )
        };
        let base = unsafe { libc::CMSG_LEN(0) } as usize;
        let start = (header as usize).saturating_sub(message.msg_control as usize);
        if length < base
            || start > message.msg_controllen
            || length > message.msg_controllen - start
        {
            valid = false;
            break;
        }
        let data_len = length - base;
        // SAFETY: CMSG_DATA points into the valid current control message.
        let data = unsafe { libc::CMSG_DATA(header) };
        if level == libc::SOL_SOCKET && kind == libc::SCM_RIGHTS {
            valid = false;
            if !data_len.is_multiple_of(std::mem::size_of::<libc::c_int>()) {
                valid = false;
            }
            for index in 0..(data_len / std::mem::size_of::<libc::c_int>()) {
                // SAFETY: kernel supplied data_len bytes; unaligned reads
                // avoid depending on alignment of an ancillary payload.
                let fd = unsafe {
                    std::ptr::read_unaligned(
                        data.add(index * std::mem::size_of::<libc::c_int>())
                            .cast::<libc::c_int>(),
                    )
                };
                // SAFETY: SCM_RIGHTS transfers ownership of each descriptor.
                close_right(fd);
            }
        } else if level == libc::SOL_SOCKET
            && kind == libc::SCM_CREDENTIALS
            && data_len == std::mem::size_of::<libc::ucred>()
            && !seen_credentials
        {
            seen_credentials = true;
            // SAFETY: the checked control payload contains a complete ucred.
            let credentials = unsafe { std::ptr::read_unaligned(data.cast::<libc::ucred>()) };
            sender = u32::try_from(credentials.pid).ok().filter(|pid| *pid > 0);
        } else {
            valid = false;
        }
        // SAFETY: header is the current element of message's control buffer.
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
    valid && sender == Some(expected_pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    #[test]
    fn synthetic_controls_reject_missing_duplicate_and_malformed_credentials() {
        let mut control = [0usize; 32];
        // SAFETY: zero initializes optional msghdr fields.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_control = control.as_mut_ptr().cast();
        let cred_len = std::mem::size_of::<libc::ucred>() as u32;
        // SAFETY: CMSG_SPACE performs arithmetic on a bounded constant.
        let space = unsafe { libc::CMSG_SPACE(cred_len) } as usize;
        let parse = |msg: &libc::msghdr| {
            // SAFETY: msg always points at the aligned control array above;
            // no synthetic control claims to contain real descriptors.
            unsafe { parse_control(msg, 1, b"P\0", 42, |_| panic!("unexpected rights")) }
        };
        assert!(!parse(&message));
        message.msg_controllen = space;
        // SAFETY: control is aligned and contains room for two credentials.
        unsafe {
            let first = libc::CMSG_FIRSTHDR(&message);
            (*first).cmsg_level = libc::SOL_SOCKET;
            (*first).cmsg_type = libc::SCM_CREDENTIALS;
            (*first).cmsg_len = libc::CMSG_LEN(cred_len) as usize;
            std::ptr::write_unaligned(
                libc::CMSG_DATA(first).cast::<libc::ucred>(),
                libc::ucred {
                    pid: 42,
                    uid: 1,
                    gid: 1,
                },
            );
        }
        assert!(parse(&message));
        message.msg_controllen = space * 2;
        // SAFETY: the second header and payload fit in the control array.
        unsafe {
            let second = (message.msg_control as *mut u8)
                .add(space)
                .cast::<libc::cmsghdr>();
            (*second).cmsg_level = libc::SOL_SOCKET;
            (*second).cmsg_type = libc::SCM_CREDENTIALS;
            (*second).cmsg_len = libc::CMSG_LEN(cred_len) as usize;
            std::ptr::write_unaligned(
                libc::CMSG_DATA(second).cast::<libc::ucred>(),
                libc::ucred {
                    pid: 42,
                    uid: 1,
                    gid: 1,
                },
            );
        }
        assert!(!parse(&message));
        message.msg_controllen = space;
        // SAFETY: first header is within the initialized control array.
        unsafe {
            (*libc::CMSG_FIRSTHDR(&message)).cmsg_len = space + 1;
        }
        assert!(!parse(&message));
        unsafe {
            (*libc::CMSG_FIRSTHDR(&message)).cmsg_len = 0;
        }
        assert!(!parse(&message));
    }

    #[test]
    fn credentials_and_payload_are_observations_not_authorization() {
        let (sender, receiver) = UnixDatagram::pair().unwrap();
        let receiver = CredentialReceiver::new(receiver).unwrap();
        sender.send(b"P").unwrap();
        assert!(receiver.matches_sender(std::process::id()).unwrap());
        sender.send(b"P").unwrap();
        assert!(!receiver
            .matches_sender(std::process::id().wrapping_add(1))
            .unwrap());
        sender.send(b"invalid").unwrap();
        assert!(!receiver.matches_sender(std::process::id()).unwrap());
        assert_eq!(
            receiver
                .matches_sender(std::process::id())
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn received_rights_are_rejected_and_closed() {
        const CHILD: &str = "TUCUPI_RIGHTS_ISOLATED_TEST";
        if std::env::var_os(CHILD).is_none() {
            let directory = tempfile::tempdir().unwrap();
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "authority_message::tests::received_rights_are_rejected_and_closed",
                    "--nocapture",
                ])
                .env_clear()
                .env("HOME", directory.path())
                .env("TMPDIR", directory.path())
                .env(CHILD, "1")
                .stdin(std::process::Stdio::null())
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "isolated descriptor test failed: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            return;
        }
        for count in [1, 4, 128] {
            check_received_rights(count);
        }
    }

    fn check_received_rights(count: usize) {
        let (sender, socket) = UnixDatagram::pair().unwrap();
        let receiver = CredentialReceiver::new(socket).unwrap();
        let mut pipe = [-1; 2];
        // SAFETY: pipe points to space for two newly allocated descriptors.
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
            0
        );
        // SAFETY: successful pipe2 returned two uniquely owned descriptors.
        let reader = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
        let writer = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
        let mut payload = *b"P";
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: 1,
        };
        // 128 descriptors exceed the receiver's 256-byte ancillary buffer,
        // forcing kernel-side control truncation; the smaller cases fit.
        let data_size = count * std::mem::size_of::<libc::c_int>();
        let space = unsafe { libc::CMSG_SPACE(data_size as u32) } as usize;
        let mut control = vec![0usize; space.div_ceil(std::mem::size_of::<usize>())];
        // SAFETY: zero is valid for optional msghdr fields.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = space;
        // SAFETY: the control buffer is aligned and large enough for this header and descriptor.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(data_size as u32) as usize;
            for index in 0..count {
                std::ptr::write_unaligned(
                    libc::CMSG_DATA(header).cast::<libc::c_int>().add(index),
                    writer.as_raw_fd(),
                );
            }
            assert_eq!(libc::sendmsg(sender.as_raw_fd(), &message, 0), 1);
        }
        drop(writer);
        let (matched, flags) = receiver.receive_observation(std::process::id()).unwrap();
        assert!(!matched);
        assert_eq!(flags & libc::MSG_CTRUNC != 0, count == 128);
        let mut byte = 0u8;
        // EOF proves no transferred write descriptor remains open in this process.
        // SAFETY: reader is live and byte is a writable one-byte buffer.
        assert_eq!(
            unsafe { libc::read(reader.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) },
            0
        );
    }
}
