//! Linux descriptor-relative record building blocks. This module does not provision or protect
//! storage, authenticate an authority, prevent rollback, or authorize work.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;

const MAX_RECORD: u64 = 4096;
const RECORD_NAME: &[u8] = b"authority-state.json\0";
const BINDING_NAME: &[u8] = b"authority-binding.json\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordObservation {
    Unknown(RecordUnknownReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordUnknownReason {
    DirectoryUnverified,
    RecordUnavailable,
    RecordUnverified,
    RecordMalformed,
    AuthorityUnverified,
}

impl RecordObservation {
    pub fn permits_operation(self) -> bool {
        false
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    generation: [u8; 16],
    state: RecordState,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
enum RecordState {
    Pending { attempt: [u8; 16] },
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedBinding {
    version: u8,
    generation: [u8; 16],
    attempt: [u8; 16],
    /// A non-authoritative locator; it may be reused and is never adoption proof.
    pid: u32,
}

/// Structural comparison only: files, their origin, and their contents are not
/// authenticated. The caller must never use a match to authorize or adopt PID.
pub(crate) fn binding_matches(
    directory: &File,
    owner: u32,
    generation: [u8; 16],
    attempt: [u8; 16],
    pid: u32,
) -> bool {
    let Ok(record) = read_untrusted_record(directory, owner) else {
        return false;
    };
    let RecordState::Pending {
        attempt: pending_attempt,
    } = record.state;
    if record.generation != generation || pending_attempt != attempt || pid == 0 {
        return false;
    }
    // No fallback: unsupported openat2 or a rejected path is unverified.
    let Ok(file) = open_binding_beneath(directory) else {
        return false;
    };
    let Ok(meta) = file.metadata() else {
        return false;
    };
    if !meta.is_file() || meta.uid() != owner || meta.mode() & 0o022 != 0 || meta.nlink() != 1 {
        return false;
    }
    let mut bytes = Vec::new();
    if file.take(MAX_RECORD + 1).read_to_end(&mut bytes).is_err() || bytes.len() as u64 > MAX_RECORD
    {
        return false;
    }
    let Ok(binding) = serde_json::from_slice::<ObservedBinding>(&bytes) else {
        return false;
    };
    binding.version == 1
        && binding.generation == generation
        && binding.attempt == attempt
        && binding.pid == pid
}

/// Kernel-enforced relative resolution for the binding record only. The base
/// descriptor and filesystem remain unauthenticated, and no result authorizes
/// work. In particular this does not protect against modifications to an inode.
fn open_binding_beneath(directory: &File) -> io::Result<File> {
    // SAFETY: open_how is a plain kernel structure and zero initializes all
    // fields and any future extension to the conservative default.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_BENEATH
        | libc::RESOLVE_NO_SYMLINKS
        | libc::RESOLVE_NO_MAGICLINKS
        | libc::RESOLVE_NO_XDEV;
    // SAFETY: directory and fixed NUL-terminated name are live, and how has
    // the kernel open_how layout and exact size for this syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory.as_raw_fd(),
            BINDING_NAME.as_ptr().cast::<libc::c_char>(),
            &how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat2 returned a fresh file descriptor.
    Ok(unsafe { File::from_raw_fd(fd as libc::c_int) })
}

#[cfg(test)]
pub(crate) fn binding_resolution_for_test(directory: &File) -> io::Result<()> {
    open_binding_beneath(directory).map(|_| ())
}

/// Explicit create-only primitive for an already-provisioned directory. It
/// must not be called as automatic setup: missing state never means clean.
/// The caller must establish authority, isolation, provenance and approval
/// separately. Errors may leave a partial or complete record; never retry by
/// deleting or replacing it. This function grants no permission to run work.
pub fn create_initial_pending(
    directory: &File,
    generation: [u8; 16],
    attempt: [u8; 16],
) -> io::Result<()> {
    create_initial_pending_with_hook(directory, 0, generation, attempt, |_| Ok(()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CreateStep {
    Created,
    Written,
}

fn create_initial_pending_with_hook(
    directory: &File,
    expected_uid: u32,
    generation: [u8; 16],
    attempt: [u8; 16],
    mut hook: impl FnMut(CreateStep) -> io::Result<()>,
) -> io::Result<()> {
    if generation == [0; 16] || attempt == [0; 16] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid record identifier",
        ));
    }
    let dir = directory.metadata()?;
    if !dir.is_dir() || dir.uid() != expected_uid || dir.mode() & 0o022 != 0 || dir.nlink() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unverified record directory",
        ));
    }
    let bytes = serde_json::to_vec(&Record {
        version: 1,
        generation,
        state: RecordState::Pending { attempt },
    })?;
    // SAFETY: directory is a live descriptor and the fixed name is NUL-terminated.
    // O_EXCL prevents replacing an existing file, including a symbolic link.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            RECORD_NAME.as_ptr().cast(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a fresh owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    hook(CreateStep::Created)?;
    file.write_all(&bytes)?;
    hook(CreateStep::Written)?;
    file.sync_all()?;
    directory.sync_all()?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn create_pending_for_test(
    directory: &File,
    generation: [u8; 16],
    attempt: [u8; 16],
) -> io::Result<()> {
    // SAFETY: geteuid only reads the effective UID of the isolated test process.
    let owner = unsafe { libc::geteuid() };
    create_initial_pending_with_hook(directory, owner, generation, attempt, |_| Ok(()))
}

/// Reads at most 4097 bytes of a fixed record name relative to an existing
/// directory descriptor. Even a well-formed root-owned record is untrusted:
/// the directory origin, ACLs, mounts, namespaces, replacement, and freshness
/// are not verified. This never creates files and always returns Unknown.
pub fn observe_record(directory: &File) -> RecordObservation {
    observe_record_with_owner(directory, 0)
}

fn observe_record_with_owner(directory: &File, expected_uid: u32) -> RecordObservation {
    match read_untrusted_record(directory, expected_uid) {
        Ok(_) => RecordObservation::Unknown(RecordUnknownReason::AuthorityUnverified),
        Err(reason) => RecordObservation::Unknown(reason),
    }
}

fn read_untrusted_record(
    directory: &File,
    expected_uid: u32,
) -> Result<Record, RecordUnknownReason> {
    let Ok(dir) = directory.metadata() else {
        return Err(RecordUnknownReason::DirectoryUnverified);
    };
    if !dir.is_dir() || dir.uid() != expected_uid || dir.mode() & 0o022 != 0 || dir.nlink() == 0 {
        return Err(RecordUnknownReason::DirectoryUnverified);
    }
    // SAFETY: directory is an owned live descriptor and RECORD_NAME is a
    // fixed, NUL-terminated name. NONBLOCK prevents a FIFO from blocking.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            RECORD_NAME.as_ptr().cast(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(RecordUnknownReason::RecordUnavailable);
    }
    // SAFETY: openat returned a fresh file descriptor owned by this function.
    let record = unsafe { File::from_raw_fd(fd) };
    let Ok(meta) = record.metadata() else {
        return Err(RecordUnknownReason::RecordUnverified);
    };
    if !meta.is_file()
        || meta.uid() != expected_uid
        || meta.mode() & 0o022 != 0
        || meta.nlink() != 1
    {
        return Err(RecordUnknownReason::RecordUnverified);
    }
    let mut bytes = Vec::new();
    if record.take(MAX_RECORD + 1).read_to_end(&mut bytes).is_err()
        || bytes.len() as u64 > MAX_RECORD
    {
        return Err(RecordUnknownReason::RecordMalformed);
    }
    let Ok(record) = serde_json::from_slice::<Record>(&bytes) else {
        return Err(RecordUnknownReason::RecordMalformed);
    };
    let RecordState::Pending { attempt } = &record.state;
    // Identifiers are bounded, not evidence of provenance or ownership.
    if record.version != 1 || record.generation == [0; 16] || *attempt == [0; 16] {
        return Err(RecordUnknownReason::RecordMalformed);
    }
    Ok(record)
}

/// Records an untrusted process locator once, after matching an existing
/// pending record. This is not a verified process binding, and cannot authorize
/// launch, recovery, PID adoption or record deletion after restart.
pub(crate) fn create_observed_binding(
    directory: &File,
    generation: [u8; 16],
    attempt: [u8; 16],
    pid: u32,
) -> io::Result<()> {
    create_observed_binding_with_hook(directory, 0, generation, attempt, pid, |_| Ok(()))
}

fn create_observed_binding_with_hook(
    directory: &File,
    owner: u32,
    generation: [u8; 16],
    attempt: [u8; 16],
    pid: u32,
    mut hook: impl FnMut(CreateStep) -> io::Result<()>,
) -> io::Result<()> {
    if pid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid process locator",
        ));
    }
    let record = read_untrusted_record(directory, owner).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "pending record unavailable or invalid",
        )
    })?;
    let RecordState::Pending {
        attempt: existing_attempt,
    } = record.state;
    if record.generation != generation || existing_attempt != attempt {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pending record mismatch",
        ));
    }
    let bytes = serde_json::to_vec(&ObservedBinding {
        version: 1,
        generation,
        attempt,
        pid,
    })?;
    // SAFETY: directory is a live descriptor and the fixed name is terminated.
    // O_EXCL avoids replacing any existing binding, including symlinks.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            BINDING_NAME.as_ptr().cast(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat produced a fresh owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    hook(CreateStep::Created)?;
    file.write_all(&bytes)?;
    hook(CreateStep::Written)?;
    file.sync_all()?;
    directory.sync_all()?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn create_binding_for_test(
    directory: &File,
    generation: [u8; 16],
    attempt: [u8; 16],
    pid: u32,
) -> io::Result<()> {
    // SAFETY: geteuid is read-only and this helper is compiled only for tests.
    let owner = unsafe { libc::geteuid() };
    create_observed_binding_with_hook(directory, owner, generation, attempt, pid, |_| Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn observed_binding_requires_matching_pending_and_never_replaces_partial_data() {
        // SAFETY: geteuid only reads the current effective UID.
        let uid = unsafe { libc::geteuid() };
        for failure in [Some(CreateStep::Created), Some(CreateStep::Written), None] {
            let dir = tempfile::tempdir().unwrap();
            let directory = File::open(dir.path()).unwrap();
            let write_binding = |generation, attempt, pid| {
                create_observed_binding_with_hook(&directory, uid, generation, attempt, pid, |_| {
                    Ok(())
                })
            };
            assert!(write_binding([1; 16], [2; 16], 123).is_err());
            create_pending_for_test(&directory, [1; 16], [2; 16]).unwrap();
            assert!(write_binding([3; 16], [2; 16], 123).is_err());
            assert!(write_binding([1; 16], [3; 16], 123).is_err());
            assert!(write_binding([1; 16], [2; 16], 0).is_err());
            assert!(!dir.path().join("authority-binding.json").exists());
            let result =
                create_observed_binding_with_hook(&directory, uid, [1; 16], [2; 16], 123, |step| {
                    if Some(step) == failure {
                        return Err(io::Error::other("synthetic failure"));
                    }
                    Ok(())
                });
            assert_eq!(result.is_ok(), failure.is_none());
            let path = dir.path().join("authority-binding.json");
            let before = std::fs::read(&path).unwrap();
            assert_eq!(
                write_binding([1; 16], [2; 16], 123).unwrap_err().kind(),
                io::ErrorKind::AlreadyExists
            );
            assert_eq!(std::fs::read(path).unwrap(), before);
            assert!(!observe_record_with_owner(&directory, uid).permits_operation());
        }
    }

    #[test]
    fn create_only_pending_preserves_partial_or_completed_records_on_error() {
        // SAFETY: geteuid only reads the current effective UID.
        let uid = unsafe { libc::geteuid() };
        for failure in [Some(CreateStep::Created), Some(CreateStep::Written), None] {
            let dir = tempfile::tempdir().unwrap();
            let directory = File::open(dir.path()).unwrap();
            let result =
                create_initial_pending_with_hook(&directory, uid, [1; 16], [2; 16], |step| {
                    if Some(step) == failure {
                        return Err(io::Error::other("synthetic failure"));
                    }
                    Ok(())
                });
            assert_eq!(result.is_ok(), failure.is_none());
            let path = dir.path().join("authority-state.json");
            let bytes = std::fs::read(&path).unwrap();
            let observation = observe_record_with_owner(&directory, uid);
            if failure == Some(CreateStep::Created) {
                assert_eq!(
                    observation,
                    RecordObservation::Unknown(RecordUnknownReason::RecordMalformed)
                );
            } else {
                assert_eq!(
                    observation,
                    RecordObservation::Unknown(RecordUnknownReason::AuthorityUnverified)
                );
            }
            assert!(!observation.permits_operation());
            assert_eq!(
                create_initial_pending_with_hook(&directory, uid, [3; 16], [4; 16], |_| Ok(()))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::AlreadyExists
            );
            assert_eq!(std::fs::read(path).unwrap(), bytes);
        }
    }

    #[test]
    fn create_only_pending_rejects_invalid_ids_and_existing_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let directory = File::open(dir.path()).unwrap();
        // SAFETY: geteuid only reads the current effective UID.
        let uid = unsafe { libc::geteuid() };
        assert_eq!(
            create_initial_pending_with_hook(&directory, uid, [0; 16], [2; 16], |_| Ok(()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(!dir.path().join("authority-state.json").exists());
        let target = dir.path().join("target");
        std::fs::write(&target, b"untouched").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("authority-state.json")).unwrap();
        assert_eq!(
            create_initial_pending_with_hook(&directory, uid, [1; 16], [2; 16], |_| Ok(()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(target).unwrap(), b"untouched");
    }

    #[test]
    fn concurrent_create_only_calls_have_one_winner() {
        let dir = tempfile::tempdir().unwrap();
        let directory = File::open(dir.path()).unwrap();
        // SAFETY: geteuid only reads the current effective UID.
        let uid = unsafe { libc::geteuid() };
        let barrier = std::sync::Barrier::new(2);
        let (first, second) = std::thread::scope(|scope| {
            let run = |attempt| {
                barrier.wait();
                create_initial_pending_with_hook(
                    &directory,
                    uid,
                    [1; 16],
                    [attempt; 16],
                    |_| Ok(()),
                )
            };
            let a = scope.spawn(move || run(2));
            let b = scope.spawn(move || run(3));
            (a.join().unwrap(), b.join().unwrap())
        });
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert_eq!(
            first.err().or_else(|| second.err()).unwrap().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            observe_record_with_owner(&directory, uid),
            RecordObservation::Unknown(RecordUnknownReason::AuthorityUnverified)
        );
    }

    #[test]
    fn anchored_record_reader_fails_closed_for_invalid_and_untrusted_records() {
        let dir = tempfile::tempdir().unwrap();
        let directory = File::open(dir.path()).unwrap();
        // SAFETY: geteuid only reads the current effective UID.
        let uid = unsafe { libc::geteuid() };
        let observe = || observe_record_with_owner(&directory, uid);
        assert_eq!(
            observe(),
            RecordObservation::Unknown(RecordUnknownReason::RecordUnavailable)
        );
        let path = dir.path().join("authority-state.json");
        std::fs::write(&path, b"{invalid").unwrap();
        assert_eq!(
            observe(),
            RecordObservation::Unknown(RecordUnknownReason::RecordMalformed)
        );
        std::fs::write(&path, vec![b'x'; MAX_RECORD as usize + 1]).unwrap();
        assert_eq!(
            observe(),
            RecordObservation::Unknown(RecordUnknownReason::RecordMalformed)
        );
        let record = serde_json::json!({"version":1,"generation":vec![1;16],"state":{"Pending":{"attempt":vec![2;16]}}});
        let bytes = serde_json::to_vec(&record).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let result = observe();
        assert_eq!(
            result,
            RecordObservation::Unknown(RecordUnknownReason::AuthorityUnverified)
        );
        assert!(!result.permits_operation());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            observe(),
            RecordObservation::Unknown(RecordUnknownReason::RecordUnverified)
        );
    }

    #[test]
    fn anchored_record_reader_rejects_links_and_does_not_block_on_fifo() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let directory = File::open(dir.path()).unwrap();
        // SAFETY: geteuid only reads the current effective UID.
        let uid = unsafe { libc::geteuid() };
        let path = dir.path().join("authority-state.json");
        let target = dir.path().join("target");
        std::fs::write(&target, b"untouched").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert_eq!(
            observe_record_with_owner(&directory, uid),
            RecordObservation::Unknown(RecordUnknownReason::RecordUnavailable)
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::hard_link(&target, &path).unwrap();
        assert_eq!(
            observe_record_with_owner(&directory, uid),
            RecordObservation::Unknown(RecordUnknownReason::RecordUnverified)
        );
        std::fs::remove_file(&path).unwrap();
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: name refers to a fresh path inside the synthetic directory.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert_eq!(
            observe_record_with_owner(&directory, uid),
            RecordObservation::Unknown(RecordUnknownReason::RecordUnverified)
        );
        assert_eq!(std::fs::read(target).unwrap(), b"untouched");
    }
}
