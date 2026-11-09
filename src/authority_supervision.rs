//! Read-only Linux process observation, not an authority or process-tree
//! supervisor. A pidfd does not prove provenance, isolation, or cleanup.

use crate::authority_store::{self, RecordObservation};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::Child;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectChildObservation {
    NotExitedObserved,
    ExitObserved,
    Unknown,
}

/// A pinned process handle, if the kernel permits opening one. The caller's
/// Child and numeric PID are not proof that the process belongs to a trusted
/// authority, and PID reuse before pidfd_open is not ruled out by this API.
pub struct DirectChildObserver {
    pidfd: OwnedFd,
    pid: u32,
}

impl DirectChildObserver {
    pub fn from_child(child: &Child) -> std::io::Result<Self> {
        Self::from_pid(child.id())
    }

    /// Kernel-supplied pidfd for the process that connected this socket.
    /// This is only local evidence: socket passing and namespaces remain
    /// unresolved and neither endpoint is authenticated by this function.
    pub(crate) fn from_connected_peer(stream: &UnixStream, peer_pid: u32) -> std::io::Result<Self> {
        let mut raw_fd: libc::c_int = -1;
        let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: stream is live and the output buffer and length are valid.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERPIDFD,
                (&mut raw_fd as *mut libc::c_int).cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if raw_fd < 0 {
            return Err(std::io::Error::other("invalid peer pidfd"));
        }
        // SAFETY: successful SO_PEERPIDFD returned a fresh owned descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        if length as usize != std::mem::size_of::<libc::c_int>() {
            return Err(std::io::Error::other("invalid peer pidfd length"));
        }
        // SAFETY: pidfd is live and F_GETFD reads descriptor flags only.
        let flags = unsafe { libc::fcntl(pidfd.as_raw_fd(), libc::F_GETFD) };
        if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
            return Err(std::io::Error::other("peer pidfd is not close-on-exec"));
        }
        Ok(Self {
            pidfd,
            pid: peer_pid,
        })
    }

    fn from_pid(pid: u32) -> std::io::Result<Self> {
        let checked_pid =
            i32::try_from(pid).map_err(|_| std::io::Error::other("invalid child pid"))?;
        // SAFETY: pidfd_open takes a numeric PID and zero flags, returning a
        // fresh close-on-exec descriptor or a negative error. It sends no signal.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, checked_pid, 0u32) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = i32::try_from(fd).map_err(|_| std::io::Error::other("invalid pidfd"))?;
        // SAFETY: successful pidfd_open produced a fresh owned descriptor.
        Ok(Self {
            pidfd: unsafe { OwnedFd::from_raw_fd(fd) },
            pid,
        })
    }

    /// Non-authoritative locator, never proof of identity after restart.
    pub(crate) fn pid_locator(&self) -> u32 {
        self.pid
    }

    /// Kernel check at this instant only: waitid succeeds only for an
    /// unreaped child of this process. WNOWAIT does not consume its exit.
    /// This is not a durable identity binding or authority authentication.
    pub(crate) fn verify_unexited_direct_child(&self) -> std::io::Result<()> {
        // SAFETY: zeroed siginfo is a valid output buffer for waitid.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: pidfd is live; info is writable; WNOHANG and WNOWAIT ensure
        // this does not wait for or reap the child.
        let result = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                self.pidfd.as_raw_fd() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: waitid initialized info; a nonzero si_pid means an exit was
        // observed, without consuming the status because WNOWAIT was used.
        if unsafe { info.si_pid() } != 0 {
            return Err(std::io::Error::other("direct child already exited"));
        }
        Ok(())
    }

    /// Nonblocking snapshot only; absence of an exit event is not proof of
    /// liveness, identity, isolation, or the state of descendants.
    pub fn observe(&self) -> DirectChildObservation {
        let mut pollfd = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pollfd points to one valid pollfd and timeout zero never waits.
        let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
        if result < 0 || pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return DirectChildObservation::Unknown;
        }
        if pollfd.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            return DirectChildObservation::ExitObserved;
        }
        if result == 0 {
            return DirectChildObservation::NotExitedObserved;
        }
        DirectChildObservation::Unknown
    }
}

/// Combines two untrusted observations without inferring a link between them.
/// Descendant cleanup and rollback are never established by this report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryObservation {
    pub record: RecordObservation,
    pub direct_child: DirectChildObservation,
}

impl RecoveryObservation {
    pub fn inspect(directory: &File, child: Option<&DirectChildObserver>) -> Self {
        Self {
            record: authority_store::observe_record(directory),
            direct_child: child.map_or(
                DirectChildObservation::Unknown,
                DirectChildObserver::observe,
            ),
        }
    }

    pub fn permits_operation(self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};

    #[test]
    fn pidfd_observation_and_record_remain_blocked_after_direct_child_exit() {
        let dir = tempfile::tempdir().unwrap();
        let directory = File::open(dir.path()).unwrap();
        let path = dir.path().join("authority-state.json");
        let bytes = serde_json::to_vec(&serde_json::json!({"version":1,"generation":vec![1;16],"state":{"Pending":{"attempt":vec![2;16]}}})).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let mut child = Command::new("/bin/sh")
            .args(["-c", "IFS= read -r line"])
            .env_clear()
            .env("HOME", dir.path())
            .env("TMPDIR", dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let observer = match DirectChildObserver::from_child(&child) {
            Ok(observer) => observer,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("pidfd unavailable in isolated test: {error}");
            }
        };
        let before = RecoveryObservation::inspect(&directory, Some(&observer));
        observer.verify_unexited_direct_child().unwrap();
        assert_eq!(
            before.direct_child,
            DirectChildObservation::NotExitedObserved
        );
        assert!(!before.permits_operation());
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"synthetic\n")
            .unwrap();
        let mut exited = libc::pollfd {
            fd: observer.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: exited is a valid pollfd; the bounded wait is test-only.
        assert_eq!(unsafe { libc::poll(&mut exited, 1, 1000) }, 1);
        assert!(observer.verify_unexited_direct_child().is_err());
        // The failed verification must not reap the exit status.
        assert!(child.wait().unwrap().success());
        assert!(observer.verify_unexited_direct_child().is_err());
        let after = RecoveryObservation::inspect(&directory, Some(&observer));
        assert_eq!(after.direct_child, DirectChildObservation::ExitObserved);
        assert_eq!(after.record, before.record);
        assert_eq!(std::fs::read(path).unwrap(), bytes);
        assert!(!after.permits_operation());
        let missing = RecoveryObservation::inspect(&directory, None);
        assert_eq!(missing.direct_child, DirectChildObservation::Unknown);
        assert!(!missing.permits_operation());
    }

    #[test]
    fn kernel_waitid_rejects_a_live_grandchild() {
        use std::io::{BufRead, BufReader};
        let dir = tempfile::tempdir().unwrap();
        let mut parent = Command::new("/bin/sh")
            .args(["-c", "sleep 30 & p=$!; printf '%s\\n' \"$p\"; IFS= read -r x; kill \"$p\"; wait \"$p\" 2>/dev/null"])
            .env_clear().env("PATH", "/usr/bin:/bin").env("HOME", dir.path())
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut output = BufReader::new(parent.stdout.take().unwrap());
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        let pid: u32 = line.trim().parse().unwrap();
        let observer = DirectChildObserver::from_pid(pid).unwrap();
        let error = observer.verify_unexited_direct_child().unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
        parent.stdin.take().unwrap().write_all(b"stop\n").unwrap();
        let _ = parent.wait().unwrap();
    }
}
