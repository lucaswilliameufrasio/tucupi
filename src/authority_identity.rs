//! Linux identity/storage diagnostics only. Numeric UIDs, mode bits, and
//! kernel socket credentials do not authenticate an independent authority.

use crate::authority_store::{self, RecordObservation};
use crate::authority_supervision::{DirectChildObservation, DirectChildObserver};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryEvidence {
    Unavailable,
    SameUidAsWorkload,
    DirectoryMismatch,
    ConsistentButUnauthenticated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityStorageObservation {
    pub boundary: BoundaryEvidence,
    pub record: RecordObservation,
}

impl IdentityStorageObservation {
    pub fn permits_operation(self) -> bool {
        false
    }
}

/// Compares a connected Unix peer's kernel credentials with a supplied store
/// descriptor and workload UID. All inputs, including the workload UID and
/// directory provenance, may be adversarial. It does not read the peer's
/// messages, create a connection or authenticate either process. A match says
/// nothing about ACLs, mount/user namespaces, executable identity, provisioning,
/// file descriptor passing, concurrent modification, or process-tree cleanup.
pub fn observe_identity_storage(
    peer: &UnixStream,
    directory: &File,
    workload_uid: u32,
) -> IdentityStorageObservation {
    let record = authority_store::observe_record(directory);
    let boundary = match kernel_peer_credentials(peer) {
        None => BoundaryEvidence::Unavailable,
        Some((_, pid)) if !peer_not_exited(peer, pid) => BoundaryEvidence::Unavailable,
        Some((uid, _)) if uid == workload_uid => BoundaryEvidence::SameUidAsWorkload,
        Some((uid, _)) => match directory.metadata() {
            Ok(meta)
                if meta.is_dir()
                    && meta.uid() == uid
                    && meta.nlink() > 0
                    && meta.mode() & 0o022 == 0 =>
            {
                BoundaryEvidence::ConsistentButUnauthenticated
            }
            _ => BoundaryEvidence::DirectoryMismatch,
        },
    };
    IdentityStorageObservation { boundary, record }
}

/// Peer UID at connection time only. Socket passing, user namespaces, and
/// credential changes mean this is not authentication of the current writer.
pub(crate) fn kernel_peer_uid(peer: &UnixStream) -> Option<u32> {
    kernel_peer_credentials(peer).map(|(uid, _)| uid)
}

fn kernel_peer_credentials(peer: &UnixStream) -> Option<(u32, u32)> {
    // SAFETY: ucred is a plain kernel output buffer and zero initializes it.
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: peer is a live descriptor and both output pointers are valid.
    let result = unsafe {
        libc::getsockopt(
            peer.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::ucred>() || credentials.pid <= 0
    {
        return None;
    }
    Some((credentials.uid, u32::try_from(credentials.pid).ok()?))
}

fn peer_not_exited(peer: &UnixStream, pid: u32) -> bool {
    let Ok(observer) = DirectChildObserver::from_connected_peer(peer, pid) else {
        return false;
    };
    // This only asks whether the peer pidfd has an exit event; the peer need
    // not be a direct child. It does not establish continuing socket ownership.
    observer.observe() == DirectChildObservation::NotExitedObserved
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn identity_storage_comparison_never_authenticates_or_consumes_socket_data() {
        let dir = tempfile::tempdir().unwrap();
        let directory = File::open(dir.path()).unwrap();
        let record = dir.path().join("authority-state.json");
        let bytes = serde_json::to_vec(&serde_json::json!({"version":1,"generation":vec![1;16],"state":{"Pending":{"attempt":vec![2;16]}}})).unwrap();
        std::fs::write(&record, &bytes).unwrap();
        let (mut stream, mut other) = UnixStream::pair().unwrap();
        other.write_all(b"synthetic").unwrap();
        // SAFETY: geteuid reads the current effective UID only.
        let uid = unsafe { libc::geteuid() };
        let same = observe_identity_storage(&stream, &directory, uid);
        if same.boundary == BoundaryEvidence::Unavailable {
            assert!(DirectChildObserver::from_connected_peer(&stream, std::process::id()).is_err());
            assert!(!same.permits_operation());
            eprintln!("peer pidfd unavailable; only fail-closed behavior verified");
            return;
        }
        assert_eq!(same.boundary, BoundaryEvidence::SameUidAsWorkload);
        assert!(!same.permits_operation());
        // This deliberately supplies a fictional different workload UID. It
        // does not create or prove a real cross-UID boundary.
        let candidate = observe_identity_storage(&stream, &directory, uid.wrapping_add(1));
        assert_eq!(
            candidate.boundary,
            BoundaryEvidence::ConsistentButUnauthenticated
        );
        assert!(!candidate.permits_operation());
        let core = crate::authority_core::AuthorityCore::new(directory.try_clone().unwrap());
        assert_eq!(
            core.inspect_identity_storage(&stream, uid.wrapping_add(1)),
            candidate
        );
        assert_eq!(std::fs::read(record).unwrap(), bytes);
        let mut input = [0u8; 9];
        stream.read_exact(&mut input).unwrap();
        assert_eq!(&input, b"synthetic");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let unsafe_dir = observe_identity_storage(&stream, &directory, uid.wrapping_add(1));
        assert_eq!(unsafe_dir.boundary, BoundaryEvidence::DirectoryMismatch);
        assert!(!unsafe_dir.permits_operation());
    }

    #[test]
    fn exited_authority_peer_becomes_unavailable_even_if_socket_remains_open() {
        use std::os::unix::net::UnixListener;
        use std::process::{Command, Stdio};
        if let Some(path) = std::env::var_os("TUCUPI_IDENTITY_PEER_CHILD") {
            let mut peer = UnixStream::connect(path).unwrap();
            peer.write_all(b"R").unwrap();
            let mut gate = [0];
            peer.read_exact(&mut gate).unwrap();
            std::process::exit(if gate == *b"G" { 0 } else { 77 });
        }
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("peer.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "authority_identity::tests::exited_authority_peer_becomes_unavailable_even_if_socket_remains_open"])
            .env_clear().env("HOME", dir.path()).env("TMPDIR", dir.path())
            .env("TUCUPI_IDENTITY_PEER_CHILD", &socket).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        let mut ready = [0];
        peer.read_exact(&mut ready).unwrap();
        assert_eq!(ready, *b"R");
        let directory = File::open(dir.path()).unwrap();
        // SAFETY: geteuid reads the current effective UID only.
        let uid = unsafe { libc::geteuid() };
        let initial = observe_identity_storage(&peer, &directory, uid);
        if initial.boundary == BoundaryEvidence::Unavailable {
            assert!(DirectChildObserver::from_connected_peer(&peer, child.id()).is_err());
        } else {
            assert_eq!(initial.boundary, BoundaryEvidence::SameUidAsWorkload);
        }
        assert!(!initial.permits_operation());
        peer.write_all(b"G").unwrap();
        assert!(child.wait().unwrap().success());
        let after = observe_identity_storage(&peer, &directory, uid);
        assert_eq!(after.boundary, BoundaryEvidence::Unavailable);
        assert!(!after.permits_operation());
    }

    #[test]
    fn unconnected_socket_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: socket creates a fresh, uniquely owned unconnected descriptor.
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        assert!(fd >= 0);
        // SAFETY: fd is a newly created Unix socket owned by this test.
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        let observed = observe_identity_storage(&stream, &File::open(dir.path()).unwrap(), 42);
        assert_eq!(observed.boundary, BoundaryEvidence::Unavailable);
        assert!(!observed.permits_operation());
    }
}
