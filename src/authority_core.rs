//! Fail-closed authority composition, not an authenticated service or sandbox.
//! Never expose state-changing methods to callers without independent identity,
//! authorization, protected storage and an approved provisioning design.

use crate::authority_store;
use crate::authority_supervision::{DirectChildObserver, RecoveryObservation};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::process::Child;

/// Owns a supplied directory descriptor. Its provenance and isolation are not
/// authenticated by this type; no constructor implicitly provisions anything.
pub struct AuthorityCore {
    directory: File,
}

/// Process-local association only. Its IDs are caller-supplied, the record and
/// process are unauthenticated, and it cannot be restored as proof on restart.
pub struct QuarantinedAttempt {
    directory: File,
    generation: [u8; 16],
    attempt: [u8; 16],
    observer: DirectChildObserver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingEvidence {
    ConsistentButUnauthenticated,
    UnavailableOrMismatch,
}

/// Both pieces remain untrusted; this type cannot grant permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityBindingEvidence {
    pub identity: Option<crate::authority_identity::IdentityStorageObservation>,
    pub binding: BindingEvidence,
}

impl IdentityBindingEvidence {
    pub fn permits_operation(self) -> bool {
        false
    }
}

impl BindingEvidence {
    pub fn permits_operation(self) -> bool {
        false
    }
}

impl QuarantinedAttempt {
    pub fn supplied_identity(&self) -> ([u8; 16], [u8; 16]) {
        (self.generation, self.attempt)
    }

    pub fn inspect(&self) -> RecoveryObservation {
        RecoveryObservation::inspect(&self.directory, Some(&self.observer))
    }

    /// Consume one nonblocking datagram as local evidence only. No message is
    /// a proof of authority, exclusive descriptor ownership, or recovery.
    pub fn inspect_message_sender(
        &self,
        receiver: &crate::authority_message::CredentialReceiver,
    ) -> BindingEvidence {
        if self.observer.verify_unexited_direct_child().is_err() {
            return BindingEvidence::UnavailableOrMismatch;
        }
        if !matches!(
            receiver.matches_sender(self.observer.pid_locator()),
            Ok(true)
        ) || self.observer.verify_unexited_direct_child().is_err()
        {
            return BindingEvidence::UnavailableOrMismatch;
        }
        BindingEvidence::ConsistentButUnauthenticated
    }

    /// Combines a single received datagram with a local, untrusted journal
    /// comparison. The checks are not atomic, nor do they authenticate the
    /// directory or bind the sender to an independent authority.
    pub fn inspect_message_binding(
        &self,
        receiver: &crate::authority_message::CredentialReceiver,
    ) -> BindingEvidence {
        self.inspect_message_binding_with_owner(receiver, 0)
    }

    fn inspect_message_binding_with_owner(
        &self,
        receiver: &crate::authority_message::CredentialReceiver,
        owner: u32,
    ) -> BindingEvidence {
        if self.inspect_message_sender(receiver) != BindingEvidence::ConsistentButUnauthenticated
            || !authority_store::binding_matches(
                &self.directory,
                owner,
                self.generation,
                self.attempt,
                self.observer.pid_locator(),
            )
            || self.observer.verify_unexited_direct_child().is_err()
        {
            return BindingEvidence::UnavailableOrMismatch;
        }
        BindingEvidence::ConsistentButUnauthenticated
    }

    /// Compare kernel peer credentials, the local pidfd and untrusted records.
    /// Matching evidence never authenticates either side or authorizes work.
    pub fn inspect_peer_binding(&self, stream: &UnixStream) -> BindingEvidence {
        self.inspect_peer_binding_with_owner(stream, 0)
    }

    /// Derives workload UID from its socket and compares independent-authority
    /// evidence and the pending binding. Neither socket is authenticated; the
    /// descriptor, process and directory may be spoofed or replaced.
    pub fn inspect_identity_binding(
        &self,
        authority_peer: &UnixStream,
        workload_peer: &UnixStream,
    ) -> IdentityBindingEvidence {
        self.inspect_identity_binding_with_owner(authority_peer, workload_peer, 0)
    }

    fn inspect_identity_binding_with_owner(
        &self,
        authority_peer: &UnixStream,
        workload_peer: &UnixStream,
        owner: u32,
    ) -> IdentityBindingEvidence {
        let identity = crate::authority_identity::kernel_peer_uid(workload_peer).map(|uid| {
            crate::authority_identity::observe_identity_storage(
                authority_peer,
                &self.directory,
                uid,
            )
        });
        let binding = self.inspect_peer_binding_with_owner(workload_peer, owner);
        IdentityBindingEvidence { identity, binding }
    }

    fn inspect_peer_binding_with_owner(&self, stream: &UnixStream, owner: u32) -> BindingEvidence {
        if self.observer.verify_unexited_direct_child().is_err() {
            return BindingEvidence::UnavailableOrMismatch;
        }
        // SAFETY: ucred is a plain kernel output buffer.
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: stream owns a live socket and the output buffers are valid.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut size,
            )
        };
        if result != 0
            || size as usize != std::mem::size_of::<libc::ucred>()
            || credentials.pid <= 0
            || u32::try_from(credentials.pid).ok() != Some(self.observer.pid_locator())
            || !authority_store::binding_matches(
                &self.directory,
                owner,
                self.generation,
                self.attempt,
                self.observer.pid_locator(),
            )
            || self.observer.verify_unexited_direct_child().is_err()
        {
            return BindingEvidence::UnavailableOrMismatch;
        }
        let Ok(peer) =
            DirectChildObserver::from_connected_peer(stream, self.observer.pid_locator())
        else {
            return BindingEvidence::UnavailableOrMismatch;
        };
        if peer.verify_unexited_direct_child().is_err()
            || self.observer.verify_unexited_direct_child().is_err()
        {
            return BindingEvidence::UnavailableOrMismatch;
        }
        BindingEvidence::ConsistentButUnauthenticated
    }

    /// Explicitly persists an untrusted locator after another direct-child
    /// check. Errors may leave a partial or complete binding record. It must
    /// not be used to adopt a PID after restart or authorize any operation.
    pub fn record_observed_binding(&self) -> io::Result<()> {
        self.record_observed_binding_with(authority_store::create_observed_binding)
    }

    fn record_observed_binding_with(
        &self,
        persist: impl FnOnce(&File, [u8; 16], [u8; 16], u32) -> io::Result<()>,
    ) -> io::Result<()> {
        self.observer.verify_unexited_direct_child()?;
        persist(
            &self.directory,
            self.generation,
            self.attempt,
            self.observer.pid_locator(),
        )?;
        // An error after this point is ambiguous: the record may already exist.
        self.observer.verify_unexited_direct_child()?;
        Ok(())
    }
}

impl AuthorityCore {
    pub fn new(directory: File) -> Self {
        Self { directory }
    }

    pub fn inspect(&self, child: Option<&DirectChildObserver>) -> RecoveryObservation {
        RecoveryObservation::inspect(&self.directory, child)
    }

    /// Diagnostic only: workload UID and peer are not authenticated and a
    /// numeric match does not create a security boundary.
    pub fn inspect_identity_storage(
        &self,
        peer: &UnixStream,
        workload_uid: u32,
    ) -> crate::authority_identity::IdentityStorageObservation {
        crate::authority_identity::observe_identity_storage(peer, &self.directory, workload_uid)
    }

    /// Explicitly records a pending intent, then returns a blocked observation.
    /// This does not spawn, release, cancel, or adopt any process. Supplying a
    /// child observer does not bind it to the record or prove ownership. A
    /// publication error can leave a partial record and must not be retried by
    /// removing it. Do not call this without independently authorized setup.
    pub fn stage_pending(
        &self,
        generation: [u8; 16],
        attempt: [u8; 16],
        child: Option<&DirectChildObserver>,
    ) -> io::Result<RecoveryObservation> {
        self.stage_pending_with(
            generation,
            attempt,
            child,
            authority_store::create_initial_pending,
        )
    }

    /// Persists intent before acquiring a pidfd for an already-existing child.
    /// This starts no work and never proves that the child belongs to the
    /// attempt; no PID is persisted or adopted on restart. If pidfd acquisition
    /// fails, the pending record remains and the caller must not erase it.
    pub fn stage_observed_pending(
        &self,
        generation: [u8; 16],
        attempt: [u8; 16],
        child: &Child,
    ) -> io::Result<QuarantinedAttempt> {
        self.stage_observed_pending_with(
            generation,
            attempt,
            authority_store::create_initial_pending,
            || DirectChildObserver::from_child(child),
        )
    }

    fn stage_observed_pending_with(
        &self,
        generation: [u8; 16],
        attempt: [u8; 16],
        persist: impl FnOnce(&File, [u8; 16], [u8; 16]) -> io::Result<()>,
        capture: impl FnOnce() -> io::Result<DirectChildObserver>,
    ) -> io::Result<QuarantinedAttempt> {
        let directory = self.directory.try_clone()?;
        persist(&self.directory, generation, attempt)?;
        let observer = capture()?;
        observer.verify_unexited_direct_child()?;
        Ok(QuarantinedAttempt {
            directory,
            generation,
            attempt,
            observer,
        })
    }

    fn stage_pending_with(
        &self,
        generation: [u8; 16],
        attempt: [u8; 16],
        child: Option<&DirectChildObserver>,
        persist: impl FnOnce(&File, [u8; 16], [u8; 16]) -> io::Result<()>,
    ) -> io::Result<RecoveryObservation> {
        persist(&self.directory, generation, attempt)?;
        Ok(self.inspect(child))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority_supervision::DirectChildObservation;
    use std::io::Write;
    use std::process::{Command, Stdio};

    #[test]
    fn message_evidence_matches_only_live_synthetic_child_and_never_authorizes() {
        use std::io::Read;
        use std::os::unix::net::UnixDatagram;
        if let Some(path) = std::env::var_os("TUCUPI_MESSAGE_CHILD") {
            let mut gate = [0];
            for _ in 0..3 {
                std::io::stdin().read_exact(&mut gate).unwrap();
                UnixDatagram::unbound()
                    .unwrap()
                    .send_to(b"P", &path)
                    .unwrap();
                std::io::stdout().write_all(b"R").unwrap();
                std::io::stdout().flush().unwrap();
            }
            std::io::stdin().read_exact(&mut gate).unwrap();
            std::process::exit(0);
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("message.sock");
        let receiver =
            crate::authority_message::CredentialReceiver::new(UnixDatagram::bind(&path).unwrap())
                .unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "authority_core::tests::message_evidence_matches_only_live_synthetic_child_and_never_authorizes"])
            .env_clear().env("HOME", dir.path()).env("TMPDIR", dir.path())
            .env("TUCUPI_MESSAGE_CHILD", &path)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let core = AuthorityCore::new(File::open(dir.path()).unwrap());
        let association = core
            .stage_observed_pending_with(
                [1; 16],
                [2; 16],
                authority_store::create_pending_for_test,
                || DirectChildObserver::from_child(&child),
            )
            .unwrap();
        assert_eq!(
            association.inspect_message_sender(&receiver),
            BindingEvidence::UnavailableOrMismatch
        );
        UnixDatagram::unbound()
            .unwrap()
            .send_to(b"P", &path)
            .unwrap();
        assert_eq!(
            association.inspect_message_sender(&receiver),
            BindingEvidence::UnavailableOrMismatch
        );
        // SAFETY: read-only query of the synthetic test process's UID.
        let uid = unsafe { libc::geteuid() };
        for phase in 0..3 {
            if phase == 1 {
                association
                    .record_observed_binding_with(authority_store::create_binding_for_test)
                    .unwrap();
            } else if phase == 2 {
                std::fs::write(dir.path().join("authority-binding.json"), b"invalid").unwrap();
            }
            child.stdin.as_mut().unwrap().write_all(b"G").unwrap();
            let mut ack = [0];
            loop {
                child.stdout.as_mut().unwrap().read_exact(&mut ack).unwrap();
                if ack == *b"R" {
                    break;
                }
            }
            let evidence = association.inspect_message_binding_with_owner(&receiver, uid);
            if phase == 1
                && authority_store::binding_resolution_for_test(&association.directory).is_ok()
            {
                assert_eq!(evidence, BindingEvidence::ConsistentButUnauthenticated);
            } else {
                assert_eq!(evidence, BindingEvidence::UnavailableOrMismatch);
            }
            assert!(!evidence.permits_operation());
        }
        child.stdin.take().unwrap().write_all(b"X").unwrap();
        assert!(child.wait().unwrap().success());
        assert_eq!(
            association.inspect_message_sender(&receiver),
            BindingEvidence::UnavailableOrMismatch
        );
    }

    #[test]
    fn peer_pid_and_persisted_binding_are_only_untrusted_consistency_evidence() {
        use std::io::Read;
        use std::os::unix::net::UnixListener;
        if let Some(path) = std::env::var_os("TUCUPI_BINDING_PEER_CHILD") {
            let mut stream = UnixStream::connect(path).unwrap();
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            std::process::exit(if byte == *b"G" { 0 } else { 77 });
        }
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("synthetic.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "authority_core::tests::peer_pid_and_persisted_binding_are_only_untrusted_consistency_evidence"])
            .env_clear().env("HOME", dir.path()).env("TMPDIR", dir.path())
            .env("TUCUPI_BINDING_PEER_CHILD", &socket)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let core = AuthorityCore::new(File::open(dir.path()).unwrap());
        let association = core
            .stage_observed_pending_with(
                [1; 16],
                [2; 16],
                authority_store::create_pending_for_test,
                || DirectChildObserver::from_child(&child),
            )
            .unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        // SAFETY: geteuid reads the synthetic test's effective UID only.
        let uid = unsafe { libc::geteuid() };
        assert_eq!(
            association.inspect_peer_binding_with_owner(&peer, uid),
            BindingEvidence::UnavailableOrMismatch
        );
        association
            .record_observed_binding_with(authority_store::create_binding_for_test)
            .unwrap();
        let peer_pidfd = match DirectChildObserver::from_connected_peer(&peer, child.id()) {
            Ok(handle) => handle,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(
                        libc::ENOPROTOOPT
                            | libc::EOPNOTSUPP
                            | libc::EINVAL
                            | libc::ENOSYS
                            | libc::EPERM
                    )
                ) =>
            {
                assert_eq!(
                    association.inspect_peer_binding_with_owner(&peer, uid),
                    BindingEvidence::UnavailableOrMismatch
                );
                assert!(!BindingEvidence::UnavailableOrMismatch.permits_operation());
                peer.write_all(b"G").unwrap();
                assert!(child.wait().unwrap().success());
                eprintln!("SO_PEERPIDFD unavailable; only fail-closed behavior verified");
                return;
            }
            Err(error) => panic!("unexpected peer pidfd error: {error}"),
        };
        peer_pidfd.verify_unexited_direct_child().unwrap();
        if let Err(error) = authority_store::binding_resolution_for_test(&association.directory) {
            assert!(matches!(
                error.raw_os_error(),
                Some(libc::ENOSYS | libc::EINVAL | libc::EPERM | libc::E2BIG | libc::EOPNOTSUPP)
            ));
            assert_eq!(
                association.inspect_peer_binding_with_owner(&peer, uid),
                BindingEvidence::UnavailableOrMismatch
            );
            peer.write_all(b"G").unwrap();
            assert!(child.wait().unwrap().success());
            eprintln!("openat2 unavailable; only fail-closed behavior verified");
            return;
        }
        let evidence = association.inspect_peer_binding_with_owner(&peer, uid);
        assert_eq!(evidence, BindingEvidence::ConsistentButUnauthenticated);
        assert!(!evidence.permits_operation());
        let (other, _other_peer) = UnixStream::pair().unwrap();
        assert_eq!(
            association.inspect_peer_binding_with_owner(&other, uid),
            BindingEvidence::UnavailableOrMismatch
        );
        let combined = association.inspect_identity_binding_with_owner(&other, &peer, uid);
        assert_eq!(
            combined.identity.unwrap().boundary,
            crate::authority_identity::BoundaryEvidence::SameUidAsWorkload
        );
        assert_eq!(
            combined.binding,
            BindingEvidence::ConsistentButUnauthenticated
        );
        assert!(!combined.permits_operation());
        let no_child_binding = association.inspect_identity_binding_with_owner(&peer, &other, uid);
        assert_eq!(
            no_child_binding.binding,
            BindingEvidence::UnavailableOrMismatch
        );
        assert!(!no_child_binding.permits_operation());
        let same_process_peer =
            DirectChildObserver::from_connected_peer(&other, std::process::id()).unwrap();
        assert!(same_process_peer.verify_unexited_direct_child().is_err());
        let binding_path = dir.path().join("authority-binding.json");
        let moved = dir.path().join("moved-binding.json");
        std::fs::rename(&binding_path, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &binding_path).unwrap();
        assert_eq!(
            association.inspect_peer_binding_with_owner(&peer, uid),
            BindingEvidence::UnavailableOrMismatch
        );
        std::fs::remove_file(&binding_path).unwrap();
        std::fs::rename(&moved, &binding_path).unwrap();
        std::fs::write(dir.path().join("authority-binding.json"), b"malformed").unwrap();
        assert_eq!(
            association.inspect_peer_binding_with_owner(&peer, uid),
            BindingEvidence::UnavailableOrMismatch
        );
        peer.write_all(b"G").unwrap();
        assert!(child.wait().unwrap().success());
        assert!(peer_pidfd.verify_unexited_direct_child().is_err());
        assert_eq!(
            association.inspect_peer_binding_with_owner(&peer, uid),
            BindingEvidence::UnavailableOrMismatch
        );
        assert!(!association.inspect().permits_operation());
    }

    #[test]
    fn local_association_persists_first_and_never_authorizes() {
        let dir = tempfile::tempdir().unwrap();
        let core = AuthorityCore::new(File::open(dir.path()).unwrap());
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
        let association = core
            .stage_observed_pending_with(
                [4; 16],
                [5; 16],
                authority_store::create_pending_for_test,
                || {
                    assert!(dir.path().join("authority-state.json").exists());
                    DirectChildObserver::from_child(&child)
                },
            )
            .unwrap();
        assert_eq!(association.supplied_identity(), ([4; 16], [5; 16]));
        assert_eq!(
            association.inspect().direct_child,
            DirectChildObservation::NotExitedObserved
        );
        assert!(!association.inspect().permits_operation());
        association
            .record_observed_binding_with(authority_store::create_binding_for_test)
            .unwrap();
        let binding_path = dir.path().join("authority-binding.json");
        let bytes = std::fs::read(&binding_path).unwrap();
        let binding: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(binding["pid"], child.id());
        assert_eq!(binding["generation"], serde_json::json!(vec![4; 16]));
        assert_eq!(binding["attempt"], serde_json::json!(vec![5; 16]));
        assert_eq!(
            association
                .record_observed_binding_with(authority_store::create_binding_for_test)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&binding_path).unwrap(), bytes);
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"synthetic\n")
            .unwrap();
        assert!(child.wait().unwrap().success());
        assert_eq!(
            association.inspect().direct_child,
            DirectChildObservation::ExitObserved
        );
        assert!(!association.inspect().permits_operation());
        assert!(association
            .record_observed_binding_with(authority_store::create_binding_for_test)
            .is_err());
        drop(association);
        let restarted = AuthorityCore::new(File::open(dir.path()).unwrap());
        assert_eq!(
            restarted.inspect(None).direct_child,
            DirectChildObservation::Unknown
        );
        assert!(!restarted.inspect(None).permits_operation());
    }

    #[test]
    fn failed_pidfd_acquisition_leaves_pending_record_and_retry_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let core = AuthorityCore::new(File::open(dir.path()).unwrap());
        let result = core.stage_observed_pending_with(
            [1; 16],
            [2; 16],
            authority_store::create_pending_for_test,
            || {
                assert!(dir.path().join("authority-state.json").exists());
                Err(io::Error::other("synthetic pidfd failure"))
            },
        );
        assert!(result.is_err());
        let path = dir.path().join("authority-state.json");
        let before = std::fs::read(&path).unwrap();
        let retry = core.stage_observed_pending_with(
            [1; 16],
            [2; 16],
            authority_store::create_pending_for_test,
            || panic!("capture must not run after duplicate publication"),
        );
        assert!(matches!(retry, Err(error) if error.kind() == io::ErrorKind::AlreadyExists));
        assert_eq!(std::fs::read(path).unwrap(), before);
        assert!(!core.inspect(None).permits_operation());
    }

    #[test]
    fn child_reaped_between_pidfd_capture_and_verification_remains_pending() {
        let dir = tempfile::tempdir().unwrap();
        let core = AuthorityCore::new(File::open(dir.path()).unwrap());
        let mut child = Command::new("/bin/sh")
            .args(["-c", "IFS= read -r line"])
            .env_clear()
            .env("HOME", dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let result = core.stage_observed_pending_with(
            [7; 16],
            [8; 16],
            authority_store::create_pending_for_test,
            || {
                let observer = DirectChildObserver::from_child(&child)?;
                child.stdin.take().unwrap().write_all(b"exit\n")?;
                child.wait()?;
                Ok(observer)
            },
        );
        assert!(result.is_err());
        assert!(dir.path().join("authority-state.json").exists());
        assert!(!core.inspect(None).permits_operation());
    }

    #[test]
    fn explicit_pending_and_direct_child_observation_never_authorize_or_repeat() {
        let dir = tempfile::tempdir().unwrap();
        let core = AuthorityCore::new(File::open(dir.path()).unwrap());
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
                panic!("pidfd unavailable: {error}");
            }
        };
        let staged = core
            .stage_pending_with(
                [1; 16],
                [2; 16],
                Some(&observer),
                authority_store::create_pending_for_test,
            )
            .unwrap();
        assert_eq!(
            staged.direct_child,
            DirectChildObservation::NotExitedObserved
        );
        assert!(!staged.permits_operation());
        let path = dir.path().join("authority-state.json");
        let before = std::fs::read(&path).unwrap();
        assert_eq!(
            core.stage_pending_with(
                [1; 16],
                [3; 16],
                Some(&observer),
                authority_store::create_pending_for_test
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"synthetic\n")
            .unwrap();
        assert!(child.wait().unwrap().success());
        let after = core.inspect(Some(&observer));
        assert_eq!(after.direct_child, DirectChildObservation::ExitObserved);
        assert!(!after.permits_operation());
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[test]
    fn failed_publication_is_not_reinterpreted_as_clean_state() {
        let dir = tempfile::tempdir().unwrap();
        let core = AuthorityCore::new(File::open(dir.path()).unwrap());
        let error = core
            .stage_pending_with([1; 16], [2; 16], None, |_, _, _| {
                Err(io::Error::other("synthetic failure"))
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(!core.inspect(None).permits_operation());
        assert!(!dir.path().join("authority-state.json").exists());
    }
}
