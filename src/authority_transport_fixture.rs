//! Read-only synthetic wire experiment, not an authenticated production client.
//! A peer UID is not proof of executable identity, authorization, ownership,
//! authority generation or protection against UID namespaces and impersonation.

use crate::authority_lifecycle_fixture::{Id, State};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_FRAME: usize = 4096;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SyntheticResponse {
    version: u8,
    request_id: Id,
    state: State,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    interrupted_phase: Option<crate::authority_journal_fixture::InterruptedPhase>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SyntheticRequest {
    version: u8,
    request_id: Id,
    operation: SyntheticOperation,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
enum SyntheticOperation {
    Inspect,
}

fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "synthetic peer rejected")
}

fn malformed() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid synthetic authority response",
    )
}

/// Inspect kernel-supplied peer metadata on an already-connected local socket.
/// The expected UID itself must be provisioned by a trusted authority; this
/// fixture does not implement provisioning or prove a usable trust boundary.
fn verify_peer(stream: &UnixStream, expected_uid: u32) -> io::Result<()> {
    // SAFETY: zeroed ucred is a valid output buffer for getsockopt.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: stream owns a live fd; cred and len point to valid writable buffers.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: geteuid has no arguments and does not mutate state.
    let own_uid = unsafe { libc::geteuid() };
    if len as usize != std::mem::size_of::<libc::ucred>()
        || cred.pid <= 0
        || cred.uid == own_uid
        || cred.uid != expected_uid
    {
        return Err(denied());
    }
    Ok(())
}

fn decode_response(reader: &mut impl Read, expected_request: Id) -> io::Result<SyntheticResponse> {
    let bytes = read_frame(reader)?;
    let response: SyntheticResponse = serde_json::from_slice(&bytes).map_err(|_| malformed())?;
    if response.version != 1
        || response.request_id != expected_request
        || !crate::authority_journal_fixture::valid_recorded_phase(
            response.state,
            response.interrupted_phase,
        )
    {
        return Err(malformed());
    }
    Ok(response)
}

fn read_frame(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(malformed());
    }
    let mut bytes = vec![0u8; length];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(malformed());
    }
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()
}

/// One experimental server lifecycle, with a cooperative server-only lock.
/// Startup reconciliation is not authentication or production authority.
pub struct SyntheticServer {
    directory: PathBuf,
    _cooperative_lock: CooperativeLock,
}

pub(crate) struct CooperativeLock {
    file: File,
    directory: PathBuf,
    pinned_directory: File,
}

impl CooperativeLock {
    pub(crate) fn check_directory(&self, directory: &Path) -> io::Result<()> {
        if self.directory != directory {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fixture lock directory mismatch",
            ));
        }
        let original_dir = self.pinned_directory.metadata()?;
        let current_dir = std::fs::metadata(directory)?;
        let locked = self.file.metadata()?;
        let named = std::fs::symlink_metadata(directory.join("server.lock"))?;
        if !current_dir.is_dir()
            || !named.file_type().is_file()
            || locked.nlink() == 0
            || (original_dir.dev(), original_dir.ino()) != (current_dir.dev(), current_dir.ino())
            || (locked.dev(), locked.ino()) != (named.dev(), named.ino())
        {
            return Err(io::Error::other("fixture lock or directory changed"));
        }
        Ok(())
    }
}

impl Drop for CooperativeLock {
    fn drop(&mut self) {
        // SAFETY: the owned descriptor is live; explicit unlock also avoids
        // retaining the flock through an inherited descriptor before exec.
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Cooperating fixture components hold this lock for the complete operation.
/// An adversarial same-UID process can replace the inode or ignore the lock.
pub(crate) fn acquire_cooperative_lock(directory: &Path) -> io::Result<CooperativeLock> {
    crate::authority_journal_fixture::load(directory)?;
    let pinned_directory = File::open(directory)?;
    if !pinned_directory.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture path is not a directory",
        ));
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(directory.join("server.lock"))?;
    if !lock.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture lock is not a regular file",
        ));
    }
    // SAFETY: lock owns a live file descriptor. The lock is released on close.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let guard = CooperativeLock {
        file: lock,
        directory: directory.to_path_buf(),
        pinned_directory,
    };
    guard.check_directory(directory)?;
    Ok(guard)
}

impl SyntheticServer {
    pub fn open(directory: &Path) -> io::Result<Self> {
        Self::open_with_fault(directory, crate::authority_journal_fixture::Fault::None)
    }

    fn open_with_fault(
        directory: &Path,
        fault: crate::authority_journal_fixture::Fault,
    ) -> io::Result<Self> {
        let lock = acquire_cooperative_lock(directory)?;
        crate::authority_journal_fixture::reopen_for_recovery_locked(&lock, directory, fault)?;
        Ok(Self {
            directory: directory.to_path_buf(),
            _cooperative_lock: lock,
        })
    }

    /// Handles one read-only request. UID filtering is not authentication.
    pub fn serve(&self, stream: UnixStream, expected_uid: u32) -> io::Result<()> {
        verify_peer(&stream, expected_uid)?;
        self._cooperative_lock.check_directory(&self.directory)?;
        serve_read_only_fixture(stream, self)
    }

    /// Local fixture diagnostic only; neither the file nor this result is
    /// authenticated, and it never establishes ownership or cleanup.
    pub fn diagnostic(&self) -> io::Result<crate::authority_lifecycle_fixture::RecoveryDiagnostic> {
        self._cooperative_lock.check_directory(&self.directory)?;
        let snapshot = crate::authority_journal_fixture::load(&self.directory)?;
        Ok(crate::authority_lifecycle_fixture::RecoveryDiagnostic::from_snapshot(snapshot))
    }
}

fn serve_read_only_fixture(mut stream: UnixStream, server: &SyntheticServer) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    let request: SyntheticRequest =
        serde_json::from_slice(&read_frame(&mut stream)?).map_err(|_| malformed())?;
    server
        ._cooperative_lock
        .check_directory(&server.directory)?;
    if request.version != 1 {
        return Err(malformed());
    }
    match request.operation {
        SyntheticOperation::Inspect => {
            let snapshot = crate::authority_journal_fixture::load(&server.directory)?;
            let response = SyntheticResponse {
                version: 1,
                request_id: request.request_id,
                state: snapshot.state,
                interrupted_phase: snapshot.interrupted_phase,
            };
            let bytes = serde_json::to_vec(&response).map_err(|_| malformed())?;
            server
                ._cooperative_lock
                .check_directory(&server.directory)?;
            write_frame(&mut stream, &bytes)
        }
    }
}

/// Test-only status reader. Peer credentials and matching frames are not
/// sufficient authentication, so this fixture rejects even a well-formed reply.
pub fn read_synthetic_status(
    mut stream: UnixStream,
    expected_uid: u32,
    request_id: Id,
) -> io::Result<State> {
    verify_peer(&stream, expected_uid)?;
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    reject_unverified_response(&mut stream, request_id)
}

fn reject_unverified_response(reader: &mut impl Read, request_id: Id) -> io::Result<State> {
    let _ = decode_response(reader, request_id)?;
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "synthetic authority is not authenticated",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority_journal_fixture::{self, Fault};
    use crate::authority_lifecycle_fixture::Event;
    use std::io::{Cursor, Write};

    #[test]
    fn cooperative_server_lock_blocks_another_process_and_releases_on_drop() {
        if let Some(directory) = std::env::var_os("TUCUPI_SERVER_LOCK_FIXTURE_CHILD") {
            let result = SyntheticServer::open(Path::new(&directory));
            std::process::exit(if result.is_ok() { 0 } else { 77 });
        }
        let dir = tempfile::tempdir().unwrap();
        authority_journal_fixture::initialize(dir.path()).unwrap();
        let server = SyntheticServer::open(dir.path()).unwrap();
        let run_child = || {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "authority_transport_fixture::tests::cooperative_server_lock_blocks_another_process_and_releases_on_drop"])
                .env_clear().env("HOME", dir.path()).env("TMPDIR", dir.path())
                .env("TUCUPI_SERVER_LOCK_FIXTURE_CHILD", dir.path())
                .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
                .status().unwrap().code()
        };
        assert_eq!(run_child(), Some(77));
        drop(server);
        assert_eq!(run_child(), Some(0));
    }

    #[test]
    fn synthetic_server_refuses_symlinked_lock_without_altering_target() {
        let dir = tempfile::tempdir().unwrap();
        authority_journal_fixture::initialize(dir.path()).unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"unchanged").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("server.lock")).unwrap();
        assert!(SyntheticServer::open(dir.path()).is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"unchanged");
    }

    #[test]
    fn server_diagnostic_refuses_replaced_cooperative_lock() {
        let dir = tempfile::tempdir().unwrap();
        authority_journal_fixture::initialize(dir.path()).unwrap();
        let server = SyntheticServer::open(dir.path()).unwrap();
        std::fs::rename(dir.path().join("server.lock"), dir.path().join("old.lock")).unwrap();
        std::fs::write(dir.path().join("server.lock"), b"").unwrap();
        assert!(server.diagnostic().is_err());
    }

    #[test]
    fn synthetic_request_returns_no_status_when_lock_is_replaced_before_request() {
        let dir = tempfile::tempdir().unwrap();
        authority_journal_fixture::initialize(dir.path()).unwrap();
        let fixture = SyntheticServer::open(dir.path()).unwrap();
        let (server, mut client) = UnixStream::pair().unwrap();
        // This tests the read-only handler only, not peer authentication.
        let worker = std::thread::spawn(move || serve_read_only_fixture(server, &fixture));
        std::fs::rename(dir.path().join("server.lock"), dir.path().join("old.lock")).unwrap();
        std::fs::write(dir.path().join("server.lock"), b"").unwrap();
        let request = SyntheticRequest {
            version: 1,
            request_id: [5; 16],
            operation: SyntheticOperation::Inspect,
        };
        write_frame(&mut client, &serde_json::to_vec(&request).unwrap()).unwrap();
        assert!(worker.join().unwrap().is_err());
        let mut byte = [0; 1];
        assert_eq!(client.read(&mut byte).unwrap(), 0);
    }

    fn frame(bytes: &[u8]) -> Vec<u8> {
        let mut out = (bytes.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    }

    #[test]
    fn kernel_peer_credentials_reject_same_uid_before_reading_payload() {
        let (client, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(&[0xff; 4]).unwrap();
        // SAFETY: geteuid is a read-only process query.
        let own_uid = unsafe { libc::geteuid() };
        assert_eq!(
            read_synthetic_status(client, own_uid, [1; 16])
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn synthetic_server_rejects_same_uid_without_touching_journal() {
        let directory = tempfile::tempdir().unwrap();
        authority_journal_fixture::initialize(directory.path()).unwrap();
        let fixture = SyntheticServer::open(directory.path()).unwrap();
        let before = std::fs::read(directory.path().join("state.json")).unwrap();
        let (server, _client) = UnixStream::pair().unwrap();
        // SAFETY: geteuid is a read-only process query.
        let uid = unsafe { libc::geteuid() };
        let error = fixture.serve(server, uid).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            std::fs::read(directory.path().join("state.json")).unwrap(),
            before
        );
    }

    #[test]
    fn synthetic_server_reads_journal_and_never_authorizes_work() {
        let directory = tempfile::tempdir().unwrap();
        let initial = authority_journal_fixture::initialize(directory.path()).unwrap();
        let ready = authority_journal_fixture::publish(
            directory.path(),
            initial,
            Event::Provisioned,
            Fault::None,
        )
        .unwrap();
        let pending = authority_journal_fixture::publish(
            directory.path(),
            ready,
            Event::IntentPersisted { attempt: [7; 16] },
            Fault::None,
        )
        .unwrap();
        let fixture = SyntheticServer::open(directory.path()).unwrap();
        let recovered = authority_journal_fixture::load(directory.path()).unwrap();
        assert_eq!(recovered.version, pending.version + 1);
        assert_eq!(
            recovered.state,
            State::RecoveryRequired {
                attempt: [7; 16],
                incarnation: None
            }
        );
        let before = std::fs::read(directory.path().join("state.json")).unwrap();
        let (server, mut client) = UnixStream::pair().unwrap();
        // This explicitly bypasses peer verification to test protocol plumbing;
        // it is not evidence of an authenticated cross-UID connection.
        let worker = std::thread::spawn(move || serve_read_only_fixture(server, &fixture));
        let id = [9; 16];
        let request = SyntheticRequest {
            version: 1,
            request_id: id,
            operation: SyntheticOperation::Inspect,
        };
        write_frame(&mut client, &serde_json::to_vec(&request).unwrap()).unwrap();
        let response = decode_response(&mut client, id).unwrap();
        let state = response.state;
        worker.join().unwrap().unwrap();
        assert_eq!(state, recovered.state);
        assert!(matches!(
            crate::authority_lifecycle_fixture::RecoveryView::from_observation(Some(state)),
            crate::authority_lifecycle_fixture::RecoveryView::RecoveryNeeded { .. }
        ));
        let diagnostic =
            crate::authority_lifecycle_fixture::RecoveryDiagnostic::from_recorded_state(
                state,
                response.interrupted_phase,
            );
        assert_eq!(
            diagnostic.phase,
            crate::authority_lifecycle_fixture::RecordedPhase::Intent
        );
        assert_eq!(diagnostic.attempt, Some([7; 16]));
        assert!(!diagnostic.execution_verified);
        assert!(!diagnostic.descendant_cleanup_verified);
        assert!(!diagnostic.rollback_verified);
        assert!(!state.authorizes_real_work());
        assert_eq!(
            std::fs::read(directory.path().join("state.json")).unwrap(),
            before
        );
    }

    #[test]
    fn synthetic_server_startup_failure_never_produces_server() {
        for fault in [Fault::BeforeRename, Fault::AfterRename] {
            let dir = tempfile::tempdir().unwrap();
            let initial = authority_journal_fixture::initialize(dir.path()).unwrap();
            let ready = authority_journal_fixture::publish(
                dir.path(),
                initial,
                Event::Provisioned,
                Fault::None,
            )
            .unwrap();
            authority_journal_fixture::publish(
                dir.path(),
                ready,
                Event::IntentPersisted { attempt: [8; 16] },
                Fault::None,
            )
            .unwrap();
            assert!(SyntheticServer::open_with_fault(dir.path(), fault).is_err());
            let restarted = SyntheticServer::open(dir.path()).unwrap();
            let state = authority_journal_fixture::load(&restarted.directory)
                .unwrap()
                .state;
            assert_eq!(
                state,
                State::RecoveryRequired {
                    attempt: [8; 16],
                    incarnation: None
                }
            );
            assert!(!state.authorizes_real_work());
        }
        let dir = tempfile::tempdir().unwrap();
        assert!(SyntheticServer::open(dir.path()).is_err());
        assert!(!dir.path().join("state.json").exists());
    }

    #[test]
    fn synthetic_server_restart_persists_diagnostic_across_processes() {
        if let Some(directory) = std::env::var_os("TUCUPI_SYNTHETIC_SERVER_RESTART") {
            let server = SyntheticServer::open(Path::new(&directory)).unwrap();
            let diagnostic = server.diagnostic().unwrap();
            assert_eq!(
                diagnostic.phase,
                crate::authority_lifecycle_fixture::RecordedPhase::ReleaseRecorded
            );
            assert_eq!(diagnostic.attempt, Some([3; 16]));
            assert_eq!(diagnostic.incarnation, Some([4; 16]));
            assert!(
                !diagnostic.execution_verified
                    && !diagnostic.descendant_cleanup_verified
                    && !diagnostic.rollback_verified
            );
            std::process::exit(77);
        }
        let dir = tempfile::tempdir().unwrap();
        let initial = authority_journal_fixture::initialize(dir.path()).unwrap();
        let ready = authority_journal_fixture::publish(
            dir.path(),
            initial,
            Event::Provisioned,
            Fault::None,
        )
        .unwrap();
        let intent = authority_journal_fixture::publish(
            dir.path(),
            ready,
            Event::IntentPersisted { attempt: [3; 16] },
            Fault::None,
        )
        .unwrap();
        let bound = authority_journal_fixture::publish(
            dir.path(),
            intent,
            Event::BindingPersisted {
                attempt: [3; 16],
                incarnation: [4; 16],
            },
            Fault::None,
        )
        .unwrap();
        let released = authority_journal_fixture::publish(
            dir.path(),
            bound,
            Event::ReleaseRecorded {
                attempt: [3; 16],
                incarnation: [4; 16],
            },
            Fault::None,
        )
        .unwrap();
        for iteration in 0..2 {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "authority_transport_fixture::tests::synthetic_server_restart_persists_diagnostic_across_processes"])
                .env_clear().env("HOME", dir.path()).env("TMPDIR", dir.path())
                .env("TUCUPI_SYNTHETIC_SERVER_RESTART", dir.path())
                .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().unwrap();
            assert_eq!(status.code(), Some(77));
            let snapshot = authority_journal_fixture::load(dir.path()).unwrap();
            assert_eq!(
                snapshot.version,
                released.version + 1,
                "restart {iteration} must not repeat reconciliation"
            );
            assert_eq!(
                snapshot.interrupted_phase,
                Some(authority_journal_fixture::InterruptedPhase::ReleaseRecorded)
            );
            assert!(!snapshot.state.authorizes_real_work());
        }
        let server = SyntheticServer::open(dir.path()).unwrap();
        std::fs::write(dir.path().join("state.json"), b"invalid").unwrap();
        assert_eq!(
            server.diagnostic().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn legacy_journal_response_reports_unknown_phase_and_is_untrusted() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = serde_json::json!({"version": 5, "state": {"RecoveryRequired": {"attempt": vec![4; 16], "incarnation": null}}});
        std::fs::write(
            dir.path().join("state.json"),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        let fixture = SyntheticServer::open(dir.path()).unwrap();
        let (server, mut client) = UnixStream::pair().unwrap();
        // Protocol plumbing only: bypasses peer verification, not an authenticated connection.
        let worker = std::thread::spawn(move || serve_read_only_fixture(server, &fixture));
        let id = [6; 16];
        let request = SyntheticRequest {
            version: 1,
            request_id: id,
            operation: SyntheticOperation::Inspect,
        };
        write_frame(&mut client, &serde_json::to_vec(&request).unwrap()).unwrap();
        let bytes = read_frame(&mut client).unwrap();
        worker.join().unwrap().unwrap();
        let decoded = decode_response(&mut Cursor::new(frame(&bytes)), id).unwrap();
        assert_eq!(decoded.interrupted_phase, None);
        let diagnostic =
            crate::authority_lifecycle_fixture::RecoveryDiagnostic::from_recorded_state(
                decoded.state,
                decoded.interrupted_phase,
            );
        assert_eq!(
            diagnostic.phase,
            crate::authority_lifecycle_fixture::RecordedPhase::InterruptedPhaseUnknown
        );
        assert!(
            !diagnostic.execution_verified
                && !diagnostic.descendant_cleanup_verified
                && !diagnostic.rollback_verified
        );
        assert_eq!(
            reject_unverified_response(&mut Cursor::new(frame(&bytes)), id)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn synthetic_server_rejects_unknown_operation_and_missing_record() {
        for payload in [br#"{"version":1,"request_id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"operation":"Unlock"}"#.as_slice(), br#"{"version":1,"request_id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"operation":"Inspect"}"#.as_slice()] {
            let directory = tempfile::tempdir().unwrap();
            authority_journal_fixture::initialize(directory.path()).unwrap();
            let fixture = SyntheticServer::open(directory.path()).unwrap();
            std::fs::remove_file(directory.path().join("state.json")).unwrap();
            let (server, mut client) = UnixStream::pair().unwrap();
            write_frame(&mut client, payload).unwrap();
            assert!(serve_read_only_fixture(server, &fixture).is_err());
            assert!(!directory.path().join("state.json").exists());
        }
    }

    #[test]
    fn synthetic_frames_require_matching_request_version_and_bounded_body() {
        let id = [1; 16];
        let response = SyntheticResponse {
            version: 1,
            request_id: id,
            state: State::RecoveryRequired {
                attempt: [2; 16],
                incarnation: None,
            },
            interrupted_phase: Some(authority_journal_fixture::InterruptedPhase::Intent),
        };
        let payload = serde_json::to_vec(&response).unwrap();
        let inconsistent = SyntheticResponse {
            version: 1,
            request_id: id,
            state: State::Ready,
            interrupted_phase: Some(authority_journal_fixture::InterruptedPhase::Bound),
        };
        let invalid = serde_json::to_vec(&inconsistent).unwrap();
        assert_eq!(
            decode_response(&mut Cursor::new(frame(&invalid)), id)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(reject_unverified_response(&mut Cursor::new(frame(&invalid)), id).is_err());
        let decoded = decode_response(&mut Cursor::new(frame(&payload)), id).unwrap();
        assert_eq!(decoded.state, response.state);
        assert_eq!(decoded.interrupted_phase, response.interrupted_phase);
        assert!(!decoded.state.authorizes_real_work());
        assert_eq!(
            reject_unverified_response(&mut Cursor::new(frame(&payload)), id)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            decode_response(&mut Cursor::new(frame(&payload)), [3; 16])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        let wrong_version = serde_json::to_vec(&SyntheticResponse {
            version: 2,
            ..response
        })
        .unwrap();
        assert_eq!(
            decode_response(&mut Cursor::new(frame(&wrong_version)), id)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            decode_response(&mut Cursor::new(frame(b"{}")), id)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            decode_response(&mut Cursor::new(((MAX_FRAME + 1) as u32).to_be_bytes()), id)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            decode_response(&mut Cursor::new(vec![0, 0, 0, 4, b'{']), id)
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
