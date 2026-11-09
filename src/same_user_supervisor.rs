//! Same-user local observation building block, not provider admission or a
//! sandbox. It does not spawn, signal, adopt, or clean up any process.
use crate::authority_supervision::DirectChildObserver;
use crate::recovery_state;
use std::fs::File;
use std::io;
use std::path::Path;
use std::process::Child;

/// This component has no evidence establishing either outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryOutcome {
    Unknown,
}

/// Result recorded for the direct child only, not its descendants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectExitObservation {
    SuccessRecorded,
    FailureRecorded,
    /// No exit record found alongside a valid pending child locator. This is
    /// not evidence that the child is alive or that descendants are clean.
    NotRecorded,
    UnavailableOrInvalid,
}

/// A valid envelope does not establish a complete backup or authenticity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotObservation {
    ValidEnvelopeObserved,
    UnavailableOrInvalid,
}

/// Fixture-only observation; neither variant authorizes work or real rollback.
#[cfg(feature = "codex-fixture")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntheticRollbackObservation {
    RecordObserved,
    UnavailableOrInvalid,
}

/// Reopen an unauthenticated fixture record without modifying state or
/// establishing what happened to descendants or to any real project.
#[cfg(feature = "codex-fixture")]
pub fn inspect_synthetic_rollback(state: &Path) -> SyntheticRollbackObservation {
    match recovery_state::open_provisioned_state_directory(state)
        .and_then(|directory| recovery_state::fixture_rollback_observed(&directory))
    {
        Ok(()) => SyntheticRollbackObservation::RecordObserved,
        Err(_) => SyntheticRollbackObservation::UnavailableOrInvalid,
    }
}

/// Point-in-time fixture observation only; no variant authorizes an operation.
#[cfg(feature = "codex-fixture")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntheticTargetObservation {
    MatchesSnapshot,
    DiffersFromSnapshot,
    UnavailableOrInvalid,
}

/// Compare an owned disposable target after a valid synthetic rollback record.
/// Read-only, unauthenticated and non-atomic; a match does not prove cleanup.
#[cfg(feature = "codex-fixture")]
pub fn inspect_synthetic_rollback_target(
    state: &Path,
    target: &tempfile::TempDir,
) -> SyntheticTargetObservation {
    match recovery_state::open_provisioned_state_directory(state) {
        Ok(directory) => inspect_synthetic_rollback_target_in(state, &directory, target),
        Err(_) => SyntheticTargetObservation::UnavailableOrInvalid,
    }
}

/// Compare only a disposable target after a valid synthetic resume record.
/// The observation is non-atomic and never proves cleanup or real rollback.
#[cfg(feature = "codex-fixture")]
pub fn inspect_synthetic_resume_target(
    state: &Path,
    target: &tempfile::TempDir,
) -> SyntheticTargetObservation {
    match recovery_state::open_provisioned_state_directory(state) {
        Ok(directory) => inspect_synthetic_resume_target_in(state, &directory, target),
        Err(_) => SyntheticTargetObservation::UnavailableOrInvalid,
    }
}

#[cfg(feature = "codex-fixture")]
pub(crate) fn inspect_synthetic_rollback_target_in(
    state: &Path,
    directory: &File,
    target: &tempfile::TempDir,
) -> SyntheticTargetObservation {
    inspect_synthetic_target_with_record(
        state,
        directory,
        target,
        recovery_state::fixture_rollback_observed,
    )
}

#[cfg(feature = "codex-fixture")]
pub(crate) fn inspect_synthetic_resume_target_in(
    state: &Path,
    directory: &File,
    target: &tempfile::TempDir,
) -> SyntheticTargetObservation {
    inspect_synthetic_target_with_record(
        state,
        directory,
        target,
        recovery_state::fixture_resume_observed,
    )
}

#[cfg(feature = "codex-fixture")]
fn inspect_synthetic_target_with_record(
    state: &Path,
    directory: &File,
    target: &tempfile::TempDir,
    verify_record: fn(&File) -> io::Result<()>,
) -> SyntheticTargetObservation {
    let observe = || -> io::Result<bool> {
        verify_named_recovery_directory(state, directory)?;
        verify_record(directory)?;
        let snapshot = read_synthetic_files_in(directory)?;
        if snapshot.cargo_lock.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported fixture snapshot",
            ));
        }
        let matches = compare_synthetic_target(target.path(), snapshot.cargo_toml.as_deref())?;
        verify_named_recovery_directory(state, directory)?;
        if read_synthetic_files_in(directory)? != snapshot {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fixture snapshot changed",
            ));
        }
        verify_record(directory)?;
        verify_named_recovery_directory(state, directory)?;
        Ok(matches)
    };
    match observe() {
        Ok(true) => SyntheticTargetObservation::MatchesSnapshot,
        Ok(false) => SyntheticTargetObservation::DiffersFromSnapshot,
        Err(_) => SyntheticTargetObservation::UnavailableOrInvalid,
    }
}

/// Observation only: neither result authorizes work or proves real rollback.
#[cfg(feature = "codex-fixture")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntheticTwoFileObservation {
    RecordObserved,
    UnavailableOrInvalid,
}

#[cfg(feature = "codex-fixture")]
pub fn inspect_synthetic_two_file_rollback(state: &Path) -> SyntheticTwoFileObservation {
    match recovery_state::open_provisioned_state_directory(state)
        .and_then(|directory| recovery_state::fixture_multi_rollback_observed(&directory))
    {
        Ok(()) => SyntheticTwoFileObservation::RecordObserved,
        Err(_) => SyntheticTwoFileObservation::UnavailableOrInvalid,
    }
}

/// Local fixture observation; never an authorization or real rollback proof.
#[cfg(feature = "codex-fixture")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntheticTwoFileResumeObservation {
    RecordObserved,
    UnavailableOrInvalid,
}

#[cfg(feature = "codex-fixture")]
pub fn inspect_synthetic_two_file_resume(state: &Path) -> SyntheticTwoFileResumeObservation {
    match recovery_state::open_provisioned_state_directory(state)
        .and_then(|directory| recovery_state::fixture_multi_resume_observed(&directory))
    {
        Ok(()) => SyntheticTwoFileResumeObservation::RecordObserved,
        Err(_) => SyntheticTwoFileResumeObservation::UnavailableOrInvalid,
    }
}

/// A local fixture observation is never proof of real recovery or cleanup.
#[cfg(feature = "codex-fixture")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntheticResumeObservation {
    RecordObserved,
    UnavailableOrInvalid,
}

#[cfg(feature = "codex-fixture")]
pub fn inspect_synthetic_resume(state: &Path) -> SyntheticResumeObservation {
    match recovery_state::open_provisioned_state_directory(state)
        .and_then(|directory| recovery_state::fixture_resume_observed(&directory))
    {
        Ok(()) => SyntheticResumeObservation::RecordObserved,
        Err(_) => SyntheticResumeObservation::UnavailableOrInvalid,
    }
}

/// Local records are observations, not proof of process ownership or cleanup.
#[derive(Debug, PartialEq, Eq)]
pub struct RecoveryInspection {
    pub local_evidence: recovery_state::LocalRecoveryEvidence,
    pub direct_exit: DirectExitObservation,
    pub snapshot: SnapshotObservation,
    pub descendant_cleanup: RecoveryOutcome,
    pub rollback: RecoveryOutcome,
}

/// Reopen local evidence without modifying it, adopting processes, or
/// authorizing work. The underlying reads are not an atomic snapshot, and
/// same-UID processes can alter the records.
pub fn inspect_recovery(state_directory: &Path) -> RecoveryInspection {
    let (local_evidence, exit) = recovery_state::local_recovery_with_exit_at(state_directory);
    let direct_exit = match (exit, &local_evidence) {
        (Some(true), _) => DirectExitObservation::SuccessRecorded,
        (Some(false), _) => DirectExitObservation::FailureRecorded,
        (None, recovery_state::LocalRecoveryEvidence::PendingChildLocatorObserved) => {
            DirectExitObservation::NotRecorded
        }
        (None, _) => DirectExitObservation::UnavailableOrInvalid,
    };
    RecoveryInspection {
        local_evidence,
        direct_exit,
        snapshot: match read_pending_snapshot(state_directory) {
            Ok(_) => SnapshotObservation::ValidEnvelopeObserved,
            Err(_) => SnapshotObservation::UnavailableOrInvalid,
        },
        descendant_cleanup: RecoveryOutcome::Unknown,
        rollback: RecoveryOutcome::Unknown,
    }
}

/// Inspect the configured default location without creating or modifying it.
pub fn inspect_default_recovery() -> RecoveryInspection {
    match recovery_state::default_state_path() {
        Ok(path) => inspect_recovery(&path),
        Err(_) => RecoveryInspection {
            local_evidence: recovery_state::LocalRecoveryEvidence::StateUnavailable,
            direct_exit: DirectExitObservation::UnavailableOrInvalid,
            snapshot: SnapshotObservation::UnavailableOrInvalid,
            descendant_cleanup: RecoveryOutcome::Unknown,
            rollback: RecoveryOutcome::Unknown,
        },
    }
}

/// Read a bounded snapshot associated with the pending intent. This never
/// restores files or verifies cleanup. Data is not encrypted; use synthetic
/// data only until a suitable secret-handling policy has been implemented.
pub fn read_pending_snapshot(state_directory: &Path) -> io::Result<Vec<u8>> {
    let directory = recovery_state::open_provisioned_state_directory(state_directory)?;
    recovery_state::read_recovery_snapshot(&directory)
}

/// Synthetic data only. Fixed names describe presence, not filesystem
/// ownership, permissions, symlinks, consistency, or production rollback.
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyntheticFileSnapshot {
    pub version: u8,
    #[serde(deserialize_with = "serde::Deserialize::deserialize")]
    pub cargo_toml: Option<Vec<u8>>,
    #[serde(deserialize_with = "serde::Deserialize::deserialize")]
    pub cargo_lock: Option<Vec<u8>>,
}

impl SyntheticFileSnapshot {
    pub(crate) fn valid(&self) -> bool {
        self.version == 1
            && self.cargo_toml.as_ref().is_none_or(|v| v.len() <= 65536)
            && self.cargo_lock.as_ref().is_none_or(|v| v.len() <= 65536)
    }
}

/// Reopen synthetic metadata only; this does not restore or authorize work.
pub fn read_synthetic_files(state: &Path) -> io::Result<SyntheticFileSnapshot> {
    let directory = recovery_state::open_provisioned_state_directory(state)?;
    read_synthetic_files_in(&directory)
}

fn read_synthetic_files_in(directory: &File) -> io::Result<SyntheticFileSnapshot> {
    let bytes = recovery_state::read_recovery_snapshot(directory)?;
    parse_synthetic_files(&bytes)
}

fn parse_synthetic_files(bytes: &[u8]) -> io::Result<SyntheticFileSnapshot> {
    let snapshot: SyntheticFileSnapshot = serde_json::from_slice(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid synthetic file snapshot",
        )
    })?;
    if !snapshot.valid() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid synthetic file snapshot",
        ));
    }
    Ok(snapshot)
}

/// Point-in-time consistency check, not a protection against path races or
/// malicious same-UID writers. Never used to authorize a provider.
pub(crate) fn verify_named_recovery_directory(state: &Path, pinned: &File) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let named = recovery_state::open_provisioned_state_directory(state)?;
    let pinned_meta = pinned.metadata()?;
    let named_meta = named.metadata()?;
    if pinned_meta.nlink() == 0
        || (pinned_meta.dev(), pinned_meta.ino()) != (named_meta.dev(), named_meta.ino())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recovery directory replaced",
        ));
    }
    Ok(())
}

/// Restore a validated synthetic snapshot into a newly created private
/// temporary directory, never into the original tree. The returned TempDir
/// owns cleanup. An interrupted process can leave partial temporary files;
/// their existence is not evidence of completed recovery. This does not
/// restore a real project, verify descendants, or authorize any operation.
pub fn restore_synthetic_snapshot(state: &Path, parent: &Path) -> io::Result<tempfile::TempDir> {
    restore_synthetic_snapshot_with_hook(state, parent, |_| {})
}

fn restore_synthetic_snapshot_with_hook(
    state: &Path,
    parent: &Path,
    after_file: impl FnMut(&Path),
) -> io::Result<tempfile::TempDir> {
    let snapshot = read_synthetic_files(state)?;
    restore_synthetic_contents(&snapshot, parent, after_file)
}

fn restore_synthetic_contents(
    snapshot: &SyntheticFileSnapshot,
    parent: &Path,
    mut after_file: impl FnMut(&Path),
) -> io::Result<tempfile::TempDir> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let destination = tempfile::tempdir_in(parent)?;
    for (name, contents) in [
        ("Cargo.toml", snapshot.cargo_toml.as_deref()),
        ("Cargo.lock", snapshot.cargo_lock.as_deref()),
    ] {
        if let Some(contents) = contents {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(destination.path().join(name))?;
            file.write_all(contents)?;
            file.sync_all()?;
            after_file(destination.path());
        }
    }
    File::open(destination.path())?.sync_all()?;
    Ok(destination)
}

/// Synthetic drill only: replace one file in an owned disposable TempDir.
/// This is not safe against concurrent writers, does not establish descendant
/// cleanup, and must never be used for a real project. Failures after rename
/// are ambiguous; neither this function nor its result authorizes Codex.
#[cfg(feature = "codex-fixture")]
pub fn rollback_synthetic_manifest(
    state: &Path,
    target: &tempfile::TempDir,
    expected_current: &[u8],
) -> io::Result<()> {
    rollback_synthetic_manifest_with_hook(state, target, expected_current, |_| {})
}

/// Runs only the isolated synthetic copy-and-rollback drill. It does not
/// reconcile a real project, prove process-tree cleanup, or clear the attempt.
/// This does not protect the snapshot or target against same-UID interference.
#[cfg(feature = "codex-fixture")]
pub fn recover_synthetic_attempt(
    state: &Path,
    target: &tempfile::TempDir,
    expected_current: &[u8],
) -> io::Result<tempfile::TempDir> {
    recover_synthetic_attempt_with_hook(state, target, expected_current, || {})
}

/// Fixture-only recovery using an attempt-bound synthetic post-image.
/// The post-image is local unauthenticated evidence and never authorizes Codex.
#[cfg(feature = "codex-fixture")]
pub fn recover_synthetic_attempt_with_persisted_postimage(
    state: &Path,
    target: &tempfile::TempDir,
) -> io::Result<tempfile::TempDir> {
    let directory = recovery_state::open_provisioned_state_directory(state)?;
    let expected = recovery_state::fixture_read_postimage_state(&directory)?;
    recover_synthetic_attempt_with_precondition(
        state,
        target.path(),
        expected.as_deref(),
        || {},
        |_| {},
        |_| Ok(()),
        SyntheticRecoveryPolicy::Persisted,
    )
}

/// Reopen only a disposable synthetic target after a recorded direct exit.
/// Persisted PIDs are not adopted or signaled. This does not prove descendant
/// cleanup, authenticate same-UID records, or authorize real project recovery.
#[cfg(feature = "codex-fixture")]
pub fn reopen_synthetic_attempt_after_exit(
    state: &Path,
    target: &tempfile::TempDir,
) -> io::Result<tempfile::TempDir> {
    reopen_synthetic_attempt_after_exit_with_hooks(state, target, |_| {}, |_| Ok(()))
}

#[cfg(feature = "codex-fixture")]
fn reopen_synthetic_attempt_after_exit_with_hooks(
    state: &Path,
    target: &tempfile::TempDir,
    rollback_hook: impl FnMut(&str),
    record_hook: impl FnMut(&str) -> io::Result<()>,
) -> io::Result<tempfile::TempDir> {
    let directory = recovery_state::open_provisioned_state_directory(state)?;
    reopen_synthetic_attempt_after_exit_in_with_hooks(
        state,
        &directory,
        target,
        rollback_hook,
        record_hook,
    )
}

/// Fixture-only entry point for a caller that already owns the directory.
#[cfg(feature = "codex-fixture")]
pub(crate) fn reopen_synthetic_attempt_after_exit_in(
    state: &Path,
    directory: &File,
    target: &tempfile::TempDir,
) -> io::Result<tempfile::TempDir> {
    reopen_synthetic_attempt_after_exit_in_with_hooks(state, directory, target, |_| {}, |_| Ok(()))
}

#[cfg(feature = "codex-fixture")]
fn reopen_synthetic_attempt_after_exit_in_with_hooks(
    state: &Path,
    directory: &File,
    target: &tempfile::TempDir,
    rollback_hook: impl FnMut(&str),
    record_hook: impl FnMut(&str) -> io::Result<()>,
) -> io::Result<tempfile::TempDir> {
    verify_named_recovery_directory(state, directory)?;
    let direct_exit = recovery_state::fixture_verified_direct_exit(directory)?;
    let expected = recovery_state::fixture_read_postimage_state(directory)?;
    recover_synthetic_attempt_with_precondition(
        state,
        target.path(),
        expected.as_deref(),
        || {},
        rollback_hook,
        record_hook,
        SyntheticRecoveryPolicy::ReopenedAfterExit {
            direct_exit,
            directory: directory.try_clone()?,
        },
    )
}

#[cfg(feature = "codex-fixture")]
enum SyntheticRecoveryPolicy {
    CallerProvided,
    Persisted,
    ReopenedAfterExit {
        direct_exit: Vec<u8>,
        directory: File,
    },
}

#[cfg(feature = "codex-fixture")]
impl SyntheticRecoveryPolicy {
    fn postimage_required(&self) -> bool {
        !matches!(self, Self::CallerProvided)
    }

    fn verify_exit(&self, directory: &File) -> io::Result<()> {
        if let Self::ReopenedAfterExit { direct_exit, .. } = self {
            if recovery_state::fixture_verified_direct_exit(directory)? != *direct_exit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "fixture direct exit changed",
                ));
            }
        }
        Ok(())
    }

    fn exit_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::ReopenedAfterExit { direct_exit, .. } => Some(direct_exit),
            _ => None,
        }
    }
}

/// Fixture-only, non-atomic two-file drill. The persisted post-image is a
/// serialized `SyntheticFileSnapshot`. Not for real projects or Codex.
#[cfg(feature = "codex-fixture")]
pub fn recover_synthetic_two_files(state: &Path, target: &tempfile::TempDir) -> io::Result<()> {
    recover_synthetic_two_files_with_hook(state, target.path(), |_| {})
}

/// Fixture-only observation after result publication failure. Never modifies
/// the two target files or clears the attempt. Checks are not atomic with
/// publication and do not establish real recovery or descendant cleanup.
#[cfg(feature = "codex-fixture")]
pub fn resume_synthetic_two_files(state: &Path, target: &tempfile::TempDir) -> io::Result<()> {
    resume_synthetic_two_files_with_hook(state, target.path(), |_| Ok(()))
}

#[cfg(feature = "codex-fixture")]
fn resume_synthetic_two_files_with_hook(
    state: &Path,
    target: &Path,
    record_hook: impl FnMut(&str) -> io::Result<()>,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let directory = recovery_state::open_provisioned_state_directory(state)?;
    let lease = recovery_state::fixture_recovery_lease(&directory)?;
    recovery_state::verify_fixture_recovery_lease(&directory, &lease)?;
    let attempt = recovery_state::fixture_pending_attempt(&directory)?;
    let snapshot_bytes = recovery_state::read_recovery_snapshot(&directory)?;
    let original = parse_synthetic_files(&snapshot_bytes)?;
    let postimage = recovery_state::fixture_read_multi_postimage(&directory)?;
    let expected: SyntheticFileSnapshot = serde_json::from_slice(&postimage).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid synthetic multi postimage",
        )
    })?;
    if !expected.valid() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid synthetic multi postimage",
        ));
    }
    let pinned = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(target)?;
    let path = std::path::PathBuf::from(format!("/proc/self/fd/{}", pinned.as_raw_fd()));
    verify_synthetic_target_path(target, &pinned)?;
    for (name, content) in [
        ("Cargo.toml", original.cargo_toml.as_deref()),
        ("Cargo.lock", original.cargo_lock.as_deref()),
    ] {
        if read_fixture_target_file(&path, name)?.as_deref() != content {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "synthetic file not restored",
            ));
        }
    }
    verify_named_recovery_directory(state, &directory)?;
    recovery_state::verify_fixture_recovery_lease(&directory, &lease)?;
    if read_synthetic_files_in(&directory)? != original
        || recovery_state::fixture_read_multi_postimage(&directory)? != postimage
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "synthetic recovery record changed",
        ));
    }
    verify_synthetic_target_path(target, &pinned)?;
    for (name, content) in [
        ("Cargo.toml", original.cargo_toml.as_deref()),
        ("Cargo.lock", original.cargo_lock.as_deref()),
    ] {
        if read_fixture_target_file(&path, name)?.as_deref() != content {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "synthetic file not restored",
            ));
        }
    }
    recovery_state::fixture_multi_resume_record(
        &directory,
        &attempt,
        &snapshot_bytes,
        &postimage,
        record_hook,
    )
}

#[cfg(feature = "codex-fixture")]
fn read_fixture_target_file(directory: &Path, name: &str) -> io::Result<Option<Vec<u8>>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(directory.join(name))
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid synthetic file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "synthetic file too large",
        ));
    }
    Ok(Some(bytes))
}

#[cfg(feature = "codex-fixture")]
pub(crate) fn recover_synthetic_two_files_with_hook(
    state: &Path,
    target: &Path,
    after_file: impl FnMut(&str),
) -> io::Result<()> {
    recover_synthetic_two_files_with_hooks(state, target, after_file, |_| Ok(()))
}

#[cfg(feature = "codex-fixture")]
fn recover_synthetic_two_files_with_hooks(
    state: &Path,
    target: &Path,
    mut after_file: impl FnMut(&str),
    record_hook: impl FnMut(&str) -> io::Result<()>,
) -> io::Result<()> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let directory = recovery_state::open_provisioned_state_directory(state)?;
    let lease = recovery_state::fixture_recovery_lease(&directory)?;
    recovery_state::verify_fixture_recovery_lease(&directory, &lease)?;
    let attempt = recovery_state::fixture_rollback_begin(&directory)?;
    let snapshot_bytes = recovery_state::read_recovery_snapshot(&directory)?;
    let original = parse_synthetic_files(&snapshot_bytes)?;
    let postimage = recovery_state::fixture_read_multi_postimage(&directory)?;
    let expected: SyntheticFileSnapshot = serde_json::from_slice(&postimage).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid synthetic multi postimage",
        )
    })?;
    if !expected.valid() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid synthetic multi postimage",
        ));
    }
    let pinned = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(target)?;
    verify_synthetic_target_path(target, &pinned)?;
    let pinned_path = std::path::PathBuf::from(format!("/proc/self/fd/{}", pinned.as_raw_fd()));
    let files = [
        (
            "Cargo.toml",
            original.cargo_toml.as_deref(),
            expected.cargo_toml.as_deref(),
        ),
        (
            "Cargo.lock",
            original.cargo_lock.as_deref(),
            expected.cargo_lock.as_deref(),
        ),
    ];
    // Preflight all files before any mutation; a partial prior retry is allowed.
    for (name, before, after) in files {
        let current = read_fixture_target_file(&pinned_path, name)?;
        if current.as_deref() != before && current.as_deref() != after {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "synthetic file conflict",
            ));
        }
    }
    for (name, before, after) in files {
        verify_named_recovery_directory(state, &directory)?;
        recovery_state::verify_fixture_recovery_lease(&directory, &lease)?;
        if recovery_state::fixture_rollback_begin(&directory)? != attempt {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fixture attempt changed",
            ));
        }
        if read_synthetic_files_in(&directory)? != original
            || recovery_state::fixture_read_multi_postimage(&directory)? != postimage
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "synthetic recovery record changed",
            ));
        }
        verify_synthetic_target_path(target, &pinned)?;
        let current = read_fixture_target_file(&pinned_path, name)?;
        if current.as_deref() == before {
            after_file(name);
            continue;
        }
        if current.as_deref() != after {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "synthetic file conflict",
            ));
        }
        let path = pinned_path.join(name);
        if let Some(contents) = before {
            let mut staged = tempfile::NamedTempFile::new_in(&pinned_path)?;
            staged.write_all(contents)?;
            staged.as_file().sync_all()?;
            verify_synthetic_target_path(target, &pinned)?;
            if after.is_none() {
                staged
                    .persist_noclobber(&path)
                    .map_err(|error| error.error)?;
            } else {
                if read_fixture_target_file(&pinned_path, name)?.as_deref() != after {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "synthetic file conflict",
                    ));
                }
                staged.persist(&path).map_err(|error| error.error)?;
            }
        } else {
            std::fs::remove_file(path)?;
        }
        verify_synthetic_target_path(target, &pinned)?;
        pinned.sync_all()?;
        after_file(name);
    }
    verify_named_recovery_directory(state, &directory)?;
    recovery_state::verify_fixture_recovery_lease(&directory, &lease)?;
    if read_synthetic_files_in(&directory)? != original
        || recovery_state::fixture_read_multi_postimage(&directory)? != postimage
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "synthetic recovery record changed",
        ));
    }
    verify_synthetic_target_path(target, &pinned)?;
    for (name, before, _) in files {
        if read_fixture_target_file(&pinned_path, name)?.as_deref() != before {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "synthetic file conflict",
            ));
        }
    }
    recovery_state::fixture_multi_rollback_record(
        &directory,
        &attempt,
        &snapshot_bytes,
        &postimage,
        record_hook,
    )
}

/// Reconcile only an already-restored synthetic file after fixture result
/// publication failed. This never changes that target or clears records. It
/// does not prove cleanup, survive same-UID interference, or authorize Codex.
#[cfg(feature = "codex-fixture")]
pub fn resume_synthetic_attempt(state: &Path, target: &tempfile::TempDir) -> io::Result<()> {
    resume_synthetic_attempt_with_hook(state, target, || {})
}

/// Observe an already-restored disposable target after interrupted publication,
/// requiring persisted direct-exit and postimage evidence. No target or pending
/// record is removed, and this does not establish cleanup or authorize Codex.
#[cfg(feature = "codex-fixture")]
pub fn resume_reopened_synthetic_attempt_after_exit(
    state: &Path,
    target: &tempfile::TempDir,
) -> io::Result<()> {
    resume_reopened_synthetic_attempt_after_exit_with_hook(state, target, || {})
}

#[cfg(feature = "codex-fixture")]
fn resume_reopened_synthetic_attempt_after_exit_with_hook(
    state: &Path,
    target: &tempfile::TempDir,
    after_target: impl FnOnce(),
) -> io::Result<()> {
    let directory = recovery_state::open_provisioned_state_directory(state)?;
    resume_reopened_synthetic_attempt_after_exit_in_with_hook(
        state,
        &directory,
        target,
        after_target,
    )
}

/// Fixture-only entry point for a caller that already owns the directory.
#[cfg(feature = "codex-fixture")]
pub(crate) fn resume_reopened_synthetic_attempt_after_exit_in(
    state: &Path,
    directory: &File,
    target: &tempfile::TempDir,
) -> io::Result<()> {
    resume_reopened_synthetic_attempt_after_exit_in_with_hook(state, directory, target, || {})
}

#[cfg(feature = "codex-fixture")]
fn resume_reopened_synthetic_attempt_after_exit_in_with_hook(
    state: &Path,
    directory: &File,
    target: &tempfile::TempDir,
    after_target: impl FnOnce(),
) -> io::Result<()> {
    verify_named_recovery_directory(state, directory)?;
    let direct_exit = recovery_state::fixture_verified_direct_exit(directory)?;
    recovery_state::fixture_read_postimage_state(directory)?;
    resume_synthetic_attempt_with_policy(
        state,
        target,
        after_target,
        Some((&direct_exit, directory)),
    )
}

#[cfg(feature = "codex-fixture")]
fn resume_synthetic_attempt_with_hook(
    state: &Path,
    target: &tempfile::TempDir,
    after_target: impl FnOnce(),
) -> io::Result<()> {
    resume_synthetic_attempt_with_policy(state, target, after_target, None)
}

#[cfg(feature = "codex-fixture")]
fn resume_synthetic_attempt_with_policy(
    state: &Path,
    target: &tempfile::TempDir,
    after_target: impl FnOnce(),
    reopened: Option<(&[u8], &File)>,
) -> io::Result<()> {
    let directory = match reopened {
        Some((_, directory)) => directory.try_clone()?,
        None => recovery_state::open_provisioned_state_directory(state)?,
    };
    verify_named_recovery_directory(state, &directory)?;
    let lease = recovery_state::fixture_recovery_lease(&directory)?;
    recovery_state::verify_fixture_recovery_lease(&directory, &lease)?;
    let attempt = recovery_state::fixture_pending_attempt(&directory)?;
    let snapshot_bytes = recovery_state::read_recovery_snapshot(&directory)?;
    let snapshot = parse_synthetic_files(&snapshot_bytes)?;
    let postimage = recovery_state::fixture_single_postimage(&directory)?;
    if reopened.is_some() && postimage.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture postimage absent",
        ));
    }
    let original = snapshot.cargo_toml.as_deref();
    if snapshot.cargo_lock.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "synthetic lockfile rollback unsupported",
        ));
    }
    verify_synthetic_restored_target(target.path(), original)?;
    after_target();
    // These rechecks detect changes but are not atomic with publication.
    verify_named_recovery_directory(state, &directory)?;
    if read_synthetic_files_in(&directory)? != snapshot {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "synthetic snapshot changed",
        ));
    }
    verify_synthetic_restored_target(target.path(), original)?;
    verify_named_recovery_directory(state, &directory)?;
    recovery_state::verify_fixture_recovery_lease(&directory, &lease)?;
    recovery_state::fixture_resume_record(
        &directory,
        &attempt,
        &snapshot_bytes,
        postimage.as_ref().map(|value| value.as_deref()),
        reopened.map(|(direct_exit, _)| direct_exit),
    )
}

#[cfg(feature = "codex-fixture")]
fn verify_synthetic_restored_target(target: &Path, original: Option<&[u8]>) -> io::Result<()> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::symlink_metadata(target.join("Cargo.lock")) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "synthetic lockfile present",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(target.join("Cargo.toml"))
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound && original.is_none() => {
            return Ok(())
        }
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid synthetic target",
        ));
    }
    let mut current = Vec::new();
    file.take(65537).read_to_end(&mut current)?;
    if Some(current.as_slice()) != original {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "synthetic target not restored",
        ));
    }
    Ok(())
}

#[cfg(feature = "codex-fixture")]
fn compare_synthetic_target(target: &Path, original: Option<&[u8]>) -> io::Result<bool> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::symlink_metadata(target.join("Cargo.lock")) {
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(target.join("Cargo.toml"))
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(original.is_none()),
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid synthetic target",
        ));
    }
    let mut current = Vec::new();
    file.take(65537).read_to_end(&mut current)?;
    Ok(Some(current.as_slice()) == original)
}

#[cfg(feature = "codex-fixture")]
fn recover_synthetic_attempt_with_hook(
    state: &Path,
    target: &tempfile::TempDir,
    expected_current: &[u8],
    after_copy: impl FnOnce(),
) -> io::Result<tempfile::TempDir> {
    recover_synthetic_attempt_with_hooks(state, target, expected_current, after_copy, |_| Ok(()))
}

#[cfg(feature = "codex-fixture")]
fn recover_synthetic_attempt_with_hooks(
    state: &Path,
    target: &tempfile::TempDir,
    expected_current: &[u8],
    after_copy: impl FnOnce(),
    record_hook: impl FnMut(&str) -> io::Result<()>,
) -> io::Result<tempfile::TempDir> {
    recover_synthetic_attempt_with_rollback_hook(
        state,
        target,
        expected_current,
        after_copy,
        |_| {},
        record_hook,
    )
}

#[cfg(feature = "codex-fixture")]
fn recover_synthetic_attempt_with_rollback_hook(
    state: &Path,
    target: &tempfile::TempDir,
    expected_current: &[u8],
    after_copy: impl FnOnce(),
    rollback_hook: impl FnMut(&str),
    record_hook: impl FnMut(&str) -> io::Result<()>,
) -> io::Result<tempfile::TempDir> {
    recover_synthetic_attempt_with_precondition(
        state,
        target.path(),
        Some(expected_current),
        after_copy,
        rollback_hook,
        record_hook,
        SyntheticRecoveryPolicy::CallerProvided,
    )
}

#[cfg(feature = "codex-fixture")]
// Private path-based core permits an isolated test process to operate on the
// owning test's TempDir. Public fixture entry points still require a TempDir;
// this is not a safe recovery API for arbitrary project paths.
fn recover_synthetic_attempt_with_precondition(
    state: &Path,
    target: &Path,
    expected_current: Option<&[u8]>,
    after_copy: impl FnOnce(),
    rollback_hook: impl FnMut(&str),
    record_hook: impl FnMut(&str) -> io::Result<()>,
    policy: SyntheticRecoveryPolicy,
) -> io::Result<tempfile::TempDir> {
    let directory = match &policy {
        SyntheticRecoveryPolicy::ReopenedAfterExit { directory, .. } => directory.try_clone()?,
        _ => recovery_state::open_provisioned_state_directory(state)?,
    };
    verify_named_recovery_directory(state, &directory)?;
    // Retained through result publication; closing after error or process
    // exit releases the advisory lease. No authorization is implied.
    let lease = recovery_state::fixture_recovery_lease(&directory)?;
    recovery_state::verify_fixture_recovery_lease(&directory, &lease)?;
    verify_named_recovery_directory(state, &directory)?;
    policy.verify_exit(&directory)?;
    let attempt = recovery_state::fixture_rollback_begin(&directory)?;
    let snapshot_bytes = recovery_state::read_recovery_snapshot(&directory)?;
    let snapshot = parse_synthetic_files(&snapshot_bytes)?;
    let planned_postimage = if policy.postimage_required() {
        Some(expected_current)
    } else {
        None
    };
    if recovery_state::fixture_single_postimage(&directory)?
        .as_ref()
        .map(|value| value.as_deref())
        != planned_postimage
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture postimage does not match recovery mode",
        ));
    }
    let copy = restore_synthetic_contents(&snapshot, target, |_| {})?;
    after_copy();
    // Fail closed if the persisted evidence changed while staging the copy.
    // This comparison is not atomic with the subsequent filesystem change.
    verify_named_recovery_directory(state, &directory)?;
    recovery_state::verify_fixture_recovery_lease(&directory, &lease)?;
    if read_synthetic_files_in(&directory)? != snapshot {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "synthetic snapshot changed",
        ));
    }
    verify_named_recovery_directory(state, &directory)?;
    if policy.postimage_required()
        && recovery_state::fixture_read_postimage_state(&directory)?.as_deref() != expected_current
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture postimage changed",
        ));
    }
    if recovery_state::fixture_rollback_begin(&directory)? != attempt {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture attempt changed",
        ));
    }
    policy.verify_exit(&directory)?;
    rollback_synthetic_contents(&snapshot, target, expected_current, rollback_hook)?;
    verify_named_recovery_directory(state, &directory)?;
    if read_synthetic_files_in(&directory)? != snapshot {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "synthetic snapshot changed after rollback",
        ));
    }
    verify_named_recovery_directory(state, &directory)?;
    let original = snapshot.cargo_toml.as_deref();
    verify_synthetic_restored_target(target, original)?;
    recovery_state::verify_fixture_recovery_lease(&directory, &lease)?;
    if policy.postimage_required()
        && recovery_state::fixture_read_postimage_state(&directory)?.as_deref() != expected_current
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture postimage changed after rollback",
        ));
    }
    // A publication failure is ambiguous; do not clear records or infer that
    // the target was unchanged. The record is fixture-only and create-only.
    recovery_state::fixture_rollback_record_with_hook(
        &directory,
        &attempt,
        &snapshot_bytes,
        planned_postimage,
        policy.exit_bytes(),
        record_hook,
    )?;
    Ok(copy)
}

#[cfg(feature = "codex-fixture")]
fn rollback_synthetic_manifest_with_hook(
    state: &Path,
    target: &tempfile::TempDir,
    expected_current: &[u8],
    hook: impl FnMut(&str),
) -> io::Result<()> {
    let snapshot = read_synthetic_files(state)?;
    rollback_synthetic_contents(&snapshot, target.path(), Some(expected_current), hook)
}

#[cfg(feature = "codex-fixture")]
fn rollback_synthetic_contents(
    snapshot: &SyntheticFileSnapshot,
    target: &Path,
    expected_current: Option<&[u8]>,
    mut hook: impl FnMut(&str),
) -> io::Result<()> {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let original = snapshot.cargo_toml.as_deref();
    if snapshot.cargo_lock.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "synthetic lockfile rollback unsupported",
        ));
    }
    let pinned = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(target)?;
    verify_synthetic_target_path(target, &pinned)?;
    let pinned_path = std::path::PathBuf::from(format!("/proc/self/fd/{}", pinned.as_raw_fd()));
    match std::fs::symlink_metadata(pinned_path.join("Cargo.lock")) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "synthetic lockfile present",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let path = pinned_path.join("Cargo.toml");
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound && original.is_none() => {
            verify_synthetic_target_path(target, &pinned)?;
            return pinned.sync_all();
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && expected_current.is_none() => {
            let original = original.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing synthetic original")
            })?;
            let mut staged = tempfile::NamedTempFile::new_in(&pinned_path)?;
            staged.write_all(original)?;
            staged.as_file().sync_all()?;
            hook("prepared");
            verify_synthetic_target_path(target, &pinned)?;
            staged
                .persist_noclobber(&path)
                .map_err(|error| error.error)?;
            hook("renamed");
            verify_synthetic_target_path(target, &pinned)?;
            return pinned.sync_all();
        }
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() || expected_current.is_some_and(|value| value.len() > 65536) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid synthetic target",
        ));
    }
    let mut current = Vec::new();
    file.take(65537).read_to_end(&mut current)?;
    if Some(current.as_slice()) == original {
        verify_synthetic_target_path(target, &pinned)?;
        pinned.sync_all()?;
        return Ok(());
    }
    if Some(current.as_slice()) != expected_current {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "synthetic target changed",
        ));
    }
    let Some(original) = original else {
        hook("prepared");
        verify_synthetic_target_path(target, &pinned)?;
        std::fs::remove_file(&path)?;
        hook("removed");
        verify_synthetic_target_path(target, &pinned)?;
        return pinned.sync_all();
    };
    let mut staged = tempfile::NamedTempFile::new_in(&pinned_path)?;
    staged.write_all(original)?;
    staged.as_file().sync_all()?;
    hook("prepared");
    verify_synthetic_target_path(target, &pinned)?;
    staged.persist(&path).map_err(|error| error.error)?;
    hook("renamed");
    verify_synthetic_target_path(target, &pinned)?;
    pinned.sync_all()
}

/// Detects replacement at the time of the check only. Does not authenticate
/// a directory against processes with the same UID or close the later race.
#[cfg(feature = "codex-fixture")]
fn verify_named_synthetic_target(target: &tempfile::TempDir, pinned: &File) -> io::Result<()> {
    verify_synthetic_target_path(target.path(), pinned)
}

#[cfg(feature = "codex-fixture")]
fn verify_synthetic_target_path(target: &Path, pinned: &File) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let named = std::fs::symlink_metadata(target)?;
    let held = pinned.metadata()?;
    // SAFETY: geteuid is a read-only process query.
    if !named.is_dir()
        || !held.is_dir()
        || held.nlink() == 0
        || held.uid() != unsafe { libc::geteuid() }
        || (named.dev(), named.ino()) != (held.dev(), held.ino())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "synthetic target replaced",
        ));
    }
    Ok(())
}

/// Intent persisted before a caller creates a child. The caller still owns
/// child creation, containment and cleanup; this type grants no permission.
pub struct PendingAttempt {
    directory: File,
    state_path: std::path::PathBuf,
    attempt: String,
}

impl PendingAttempt {
    /// Opens previously provisioned state and creates an intent. Errors can
    /// leave partial state; no automatic deletion or retry is performed.
    pub fn begin(state_directory: &Path, attempt: &str) -> io::Result<Self> {
        Self::begin_with_open_hook(state_directory, attempt, || {})
    }

    fn begin_with_open_hook(
        state_directory: &Path,
        attempt: &str,
        after_open: impl FnOnce(),
    ) -> io::Result<Self> {
        let state_path = if state_directory.is_absolute() {
            state_directory.to_path_buf()
        } else {
            std::env::current_dir()?.join(state_directory)
        };
        let directory = recovery_state::open_provisioned_state_directory(&state_path)?;
        after_open();
        Self::begin_in(directory, &state_path, attempt)
    }

    pub(crate) fn begin_in(directory: File, state_path: &Path, attempt: &str) -> io::Result<Self> {
        if !state_path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "recovery state path must be absolute",
            ));
        }
        Self::begin_in_with_hook(directory, state_path, attempt, |_| {})
    }

    fn begin_in_with_hook(
        directory: File,
        state_path: &Path,
        attempt: &str,
        mut hook: impl FnMut(&str),
    ) -> io::Result<Self> {
        hook("path-observed");
        verify_named_recovery_directory(state_path, &directory)?;
        recovery_state::verify_provisioned_marker(&directory)?;
        recovery_state::persist_pending_intent(&directory, attempt)?;
        hook("intent-written");
        verify_named_recovery_directory(state_path, &directory)?;
        Ok(Self {
            directory,
            state_path: state_path.to_path_buf(),
            attempt: attempt.to_owned(),
        })
    }

    /// Store one create-only bounded snapshot before binding a child. This
    /// does not authorize execution or prove a complete rollback set. A failed
    /// write may leave an incomplete record; never remove it automatically.
    /// The bytes are not encrypted; use synthetic data only.
    pub fn store_synthetic_snapshot(&self, bytes: &[u8]) -> io::Result<()> {
        self.store_synthetic_snapshot_with_hook(bytes, || {})
    }

    fn store_synthetic_snapshot_with_hook(
        &self,
        bytes: &[u8],
        after_write: impl FnOnce(),
    ) -> io::Result<()> {
        self.write_with_named_state(|| {
            recovery_state::persist_recovery_snapshot(&self.directory, &self.attempt, bytes)?;
            after_write();
            Ok(())
        })
    }

    fn write_with_named_state(&self, write: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        verify_named_recovery_directory(&self.state_path, &self.directory)?;
        write()?;
        verify_named_recovery_directory(&self.state_path, &self.directory)
    }

    /// Persist synthetic file-presence metadata; bytes are not encrypted.
    pub fn store_synthetic_files(&self, snapshot: &SyntheticFileSnapshot) -> io::Result<()> {
        if !snapshot.valid() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid synthetic file snapshot",
            ));
        }
        let bytes = serde_json::to_vec(snapshot).map_err(io::Error::other)?;
        self.store_synthetic_snapshot(&bytes)
    }

    /// Persist expected synthetic bytes before binding a child; not encrypted.
    #[cfg(feature = "codex-fixture")]
    pub fn store_synthetic_postimage(&self, bytes: &[u8]) -> io::Result<()> {
        self.write_with_named_state(|| {
            recovery_state::fixture_store_postimage(&self.directory, &self.attempt, bytes)
        })
    }

    /// Record that a fixture manifest is expected to be absent after the attempt.
    #[cfg(feature = "codex-fixture")]
    pub fn store_synthetic_absent_postimage(&self) -> io::Result<()> {
        self.write_with_named_state(|| {
            recovery_state::fixture_store_absent_postimage(&self.directory, &self.attempt)
        })
    }

    /// Persist expected synthetic states of both fixed fixture files.
    #[cfg(feature = "codex-fixture")]
    pub fn store_synthetic_two_file_postimage(
        &self,
        snapshot: &SyntheticFileSnapshot,
    ) -> io::Result<()> {
        if !snapshot.valid() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid synthetic multi postimage",
            ));
        }
        let bytes = serde_json::to_vec(snapshot).map_err(io::Error::other)?;
        self.write_with_named_state(|| {
            recovery_state::fixture_store_multi_postimage(&self.directory, &self.attempt, &bytes)
        })
    }

    /// Capture only the two fixed synthetic files from a disposable fixture.
    /// Reads are sequential and unauthenticated, not a consistent backup. This
    /// must never be used for real project data or to authorize a provider.
    #[cfg(feature = "codex-fixture")]
    pub fn capture_synthetic_files(
        &self,
        source: &tempfile::TempDir,
    ) -> io::Result<SyntheticFileSnapshot> {
        let snapshot = read_synthetic_source(source)?;
        self.store_synthetic_files(&snapshot)?;
        Ok(snapshot)
    }

    /// Observe an already-created child without taking ownership. On error the
    /// caller retains its handle and responsibility for stopping/reaping it.
    /// PID and pidfd checks are local, not proof of isolation or restart-safe
    /// process identity. A child can exit between checks.
    pub fn bind_child<'a>(self, child: &'a mut Child) -> io::Result<ObservedChild<'a>> {
        self.bind_child_with_hook(child, || {})
    }

    fn bind_child_with_hook<'a>(
        self,
        child: &'a mut Child,
        after_locator: impl FnOnce(),
    ) -> io::Result<ObservedChild<'a>> {
        verify_named_recovery_directory(&self.state_path, &self.directory)?;
        let observer = DirectChildObserver::from_child(child)?;
        observer.verify_unexited_direct_child()?;
        recovery_state::persist_child_locator(&self.directory, &self.attempt, child.id())?;
        after_locator();
        verify_named_recovery_directory(&self.state_path, &self.directory)?;
        // On failure the locator may already be persisted; retain quarantine.
        observer.verify_unexited_direct_child()?;
        Ok(ObservedChild {
            directory: self.directory,
            state_path: self.state_path,
            attempt: self.attempt,
            child,
            observer,
            exit_record: ExitRecord::Pending,
        })
    }
}

/// Bounded fixture-only read; no atomicity or same-UID trust guarantee.
#[cfg(feature = "codex-fixture")]
pub(crate) fn read_synthetic_source(
    source: &tempfile::TempDir,
) -> io::Result<SyntheticFileSnapshot> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source.path())?;
    verify_named_synthetic_target(source, &directory)?;
    let pinned = std::path::PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    let read_file = |name: &str| -> io::Result<Option<Vec<u8>>> {
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(pinned.join(name))
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid synthetic source",
            ));
        }
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "synthetic source too large",
            ));
        }
        Ok(Some(bytes))
    };
    let snapshot = SyntheticFileSnapshot {
        version: 1,
        cargo_toml: read_file("Cargo.toml")?,
        cargo_lock: read_file("Cargo.lock")?,
    };
    verify_named_synthetic_target(source, &directory)?;
    Ok(snapshot)
}

/// Borrows the direct-child handle; it cannot prove descendant cleanup or
/// restore a backup, and it does not authorize any work.
pub struct ObservedChild<'a> {
    directory: File,
    state_path: std::path::PathBuf,
    attempt: String,
    child: &'a mut Child,
    observer: DirectChildObserver,
    exit_record: ExitRecord,
}

enum ExitRecord {
    Pending,
    Recorded(bool),
    PublicationFailed,
}

impl ObservedChild<'_> {
    pub fn direct_child_observation(&self) -> crate::authority_supervision::DirectChildObservation {
        self.observer.observe()
    }

    /// Nonblocking; if the child has exited, reaps it and persists only its
    /// direct exit result. Errors can leave a partial or complete exit record.
    /// Neither success nor a missing event proves cleanup or rollback.
    pub fn poll_and_record_exit(&mut self) -> io::Result<Option<bool>> {
        self.poll_and_record_exit_with_hook(|| {})
    }

    fn poll_and_record_exit_with_hook(
        &mut self,
        after_publication: impl FnOnce(),
    ) -> io::Result<Option<bool>> {
        match self.exit_record {
            ExitRecord::Recorded(success) => return Ok(Some(success)),
            ExitRecord::PublicationFailed => {
                return Err(io::Error::other(
                    "direct exit publication previously failed",
                ))
            }
            ExitRecord::Pending => {}
        }
        let Some(status) = self.child.try_wait()? else {
            return Ok(None);
        };
        let publication = (|| {
            verify_named_recovery_directory(&self.state_path, &self.directory)?;
            recovery_state::persist_direct_exit(&self.directory, &self.attempt, status.success())?;
            after_publication();
            verify_named_recovery_directory(&self.state_path, &self.directory)
        })();
        if let Err(error) = publication {
            // The write may have completed partially or failed after sync.
            // Never retry or infer success from an ambiguous publication.
            self.exit_record = ExitRecord::PublicationFailed;
            return Err(error);
        }
        self.exit_record = ExitRecord::Recorded(status.success());
        Ok(Some(status.success()))
    }

    pub fn permits_operation(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    const ID: &str = "0123456789abcdef0123456789abcdef";

    struct TestChild(Child);
    impl Drop for TestChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn recorded_direct_exit_does_not_clear_live_descendant() {
        use std::io::{BufRead, BufReader};
        const WORKER: &str = "TUCUPI_LIVE_DESCENDANT_WORKER";
        if std::env::var_os(WORKER).is_some() {
            // SAFETY: this changes only the disposable test worker; it lets the
            // worker reap its own orphaned grandchild, not arbitrary processes.
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let marker = root.path().join("descendant-finished");
            let source = tempfile::tempdir_in(root.path()).unwrap();
            let manifest = source.path().join("Cargo.toml");
            std::fs::write(&manifest, b"original").unwrap();
            let pending = PendingAttempt::begin(&state, ID).unwrap();
            #[cfg(feature = "codex-fixture")]
            {
                pending.capture_synthetic_files(&source).unwrap();
                pending.store_synthetic_postimage(b"modified").unwrap();
            }
            let mut child = TestChild(
                Command::new("/bin/sh")
                    .args([
                        "-c",
                        "exec 3<&0; IFS= read -r go; [ \"$go\" = go ] || exit 90; printf modified > \"$2\"; /bin/sh -c 'IFS= read -r token; [ \"$token\" = finish ] || exit 91; printf later > \"$2\"; printf alive > \"$1\"' fixture \"$1\" \"$2\" <&3 >/dev/null 2>&1 & printf '%s\\n' \"$!\"",
                        "fixture",
                    ])
                    .arg(&marker)
                    .arg(&manifest)
                    .env_clear()
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            let mut input = child.0.stdin.take().unwrap();
            let mut output = BufReader::new(child.0.stdout.take().unwrap());
            let mut observed = pending.bind_child(&mut child.0).unwrap();
            input.write_all(b"go\n").unwrap();
            let mut line = String::new();
            output.read_line(&mut line).unwrap();
            let descendant: libc::pid_t = line.trim().parse().unwrap();
            assert!(descendant > 0);
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                if let Some(success) = observed.poll_and_record_exit().unwrap() {
                    assert!(success);
                    break;
                }
                assert!(Instant::now() < deadline, "direct child did not exit");
                std::thread::sleep(Duration::from_millis(10));
            }
            let mut status = 0;
            // SAFETY: descendant is the child PID printed by our direct child;
            // the worker is a subreaper and the status pointer is valid.
            assert_eq!(
                unsafe { libc::waitpid(descendant, &mut status, libc::WNOHANG) },
                0
            );
            let inspection = inspect_recovery(&state);
            assert_eq!(
                inspection.direct_exit,
                DirectExitObservation::SuccessRecorded
            );
            assert_eq!(inspection.descendant_cleanup, RecoveryOutcome::Unknown);
            assert_eq!(inspection.rollback, RecoveryOutcome::Unknown);
            assert!(!observed.permits_operation());
            assert!(recovery_state::codex_recovery_preflight_at(&state).is_err());
            assert!(PendingAttempt::begin(&state, ID).is_err());
            assert!(!marker.exists());
            assert_eq!(std::fs::read(&manifest).unwrap(), b"modified");
            #[cfg(feature = "codex-fixture")]
            {
                assert_eq!(
                    inspect_synthetic_rollback_target(&state, &source),
                    SyntheticTargetObservation::UnavailableOrInvalid
                );
                let copy = reopen_synthetic_attempt_after_exit(&state, &source).unwrap();
                assert_eq!(
                    std::fs::read(copy.path().join("Cargo.toml")).unwrap(),
                    b"original"
                );
                assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
                assert_eq!(
                    inspect_synthetic_rollback_target(&state, &source),
                    SyntheticTargetObservation::MatchesSnapshot
                );
                assert_eq!(
                    inspect_recovery(&state).descendant_cleanup,
                    RecoveryOutcome::Unknown
                );
                assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
                assert!(recovery_state::codex_recovery_preflight_at(&state).is_err());
            }
            input.write_all(b"finish\n").unwrap();
            drop(input);
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                // SAFETY: this is the same specific adopted child and the
                // status pointer is valid. The check never signals a PID.
                let result = unsafe { libc::waitpid(descendant, &mut status, libc::WNOHANG) };
                if result == descendant {
                    break;
                }
                assert_eq!(result, 0);
                assert!(Instant::now() < deadline, "descendant did not exit");
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
            assert_eq!(std::fs::read(&marker).unwrap(), b"alive");
            assert_eq!(std::fs::read(&manifest).unwrap(), b"later");
            #[cfg(feature = "codex-fixture")]
            {
                let record = std::fs::read(state.join("pending-fixture-rollback")).unwrap();
                assert_eq!(
                    inspect_synthetic_rollback_target(&state, &source),
                    SyntheticTargetObservation::DiffersFromSnapshot
                );
                assert_eq!(
                    std::fs::read(state.join("pending-fixture-rollback")).unwrap(),
                    record
                );
                assert_eq!(std::fs::read(&manifest).unwrap(), b"later");
                std::fs::remove_file(&manifest).unwrap();
                std::os::unix::fs::symlink("missing-fixture", &manifest).unwrap();
                assert_eq!(
                    inspect_synthetic_rollback_target(&state, &source),
                    SyntheticTargetObservation::UnavailableOrInvalid
                );
            }
            assert_eq!(
                inspect_recovery(&state).descendant_cleanup,
                RecoveryOutcome::Unknown
            );
            assert!(recovery_state::codex_recovery_preflight_at(&state).is_err());
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "same_user_supervisor::tests::recorded_direct_exit_does_not_clear_live_descendant",
            ])
            .env_clear()
            .env("HOME", root.path())
            .env("TMPDIR", root.path())
            .env(WORKER, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(
            status.success(),
            "isolated descendant worker failed: {status}"
        );
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn capture_synthetic_files_survives_supervisor_exit_and_rejects_invalid_inputs() {
        use std::os::unix::fs::symlink;
        const CHILD: &str = "TUCUPI_CAPTURE_SYNTHETIC_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let root = Path::new(&path);
            let pending = PendingAttempt::begin(&root.join("state"), ID).unwrap();
            let source = tempfile::tempdir_in(root).unwrap();
            std::fs::write(source.path().join("Cargo.toml"), b"synthetic\0manifest").unwrap();
            pending.capture_synthetic_files(&source).unwrap();
            let mut child = Command::new("/bin/sh")
                .args(["-c", "IFS= read -r line"])
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut observed = pending.bind_child(&mut child).unwrap();
            assert_eq!(observed.poll_and_record_exit().unwrap(), None);
            std::process::exit(77);
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["state", "invalid"] {
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new(name))
                .unwrap();
        }
        let state = root.path().join("state");
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "same_user_supervisor::tests::capture_synthetic_files_survives_supervisor_exit_and_rejects_invalid_inputs"])
            .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, root.path())
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
        assert_eq!(status.code(), Some(77));
        let snapshot = read_synthetic_files(&state).unwrap();
        assert_eq!(snapshot.cargo_toml, Some(b"synthetic\0manifest".to_vec()));
        assert_eq!(snapshot.cargo_lock, None);
        let restored = restore_synthetic_snapshot(&state, root.path()).unwrap();
        assert_eq!(
            std::fs::read(restored.path().join("Cargo.toml")).unwrap(),
            b"synthetic\0manifest"
        );
        assert!(!restored.path().join("Cargo.lock").exists());
        assert_eq!(
            inspect_recovery(&state).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
        assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
        assert!(PendingAttempt::begin(&state, ID).is_err());

        let invalid = root.path().join("invalid");
        let pending = PendingAttempt::begin(&invalid, ID).unwrap();
        let source = tempfile::tempdir_in(root.path()).unwrap();
        let protected = root.path().join("protected");
        std::fs::write(&protected, b"unchanged").unwrap();
        symlink(&protected, source.path().join("Cargo.toml")).unwrap();
        assert!(pending.capture_synthetic_files(&source).is_err());
        assert!(!invalid.join("pending-snapshot").exists());
        std::fs::remove_file(source.path().join("Cargo.toml")).unwrap();
        std::fs::write(source.path().join("Cargo.toml"), vec![b'x'; 65537]).unwrap();
        assert!(pending.capture_synthetic_files(&source).is_err());
        assert!(!invalid.join("pending-snapshot").exists());
        assert_eq!(std::fs::read(protected).unwrap(), b"unchanged");
        assert!(PendingAttempt::begin(&invalid, ID).is_err());
    }

    #[test]
    fn synthetic_file_metadata_reopens_without_fixture_feature() {
        const CHILD: &str = "TUCUPI_METADATA_OWNER_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let pending = PendingAttempt::begin(Path::new(&path), ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"synthetic\0manifest".to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
            std::process::exit(77);
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let state = root.path().join("state");
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "same_user_supervisor::tests::synthetic_file_metadata_reopens_without_fixture_feature"])
            .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, &state)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
        assert_eq!(status.code(), Some(77));
        assert_eq!(
            read_synthetic_files(&state).unwrap(),
            SyntheticFileSnapshot {
                version: 1,
                cargo_toml: Some(b"synthetic\0manifest".to_vec()),
                cargo_lock: None,
            }
        );
        assert_eq!(
            inspect_recovery(&state).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
        assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
        assert!(PendingAttempt::begin(&state, ID).is_err());
    }

    #[test]
    fn synthetic_file_snapshot_reopens_after_supervisor_exit() {
        const CHILD: &str = "TUCUPI_FILE_SNAPSHOT_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let pending = PendingAttempt::begin(Path::new(&path), ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"synthetic\0manifest".to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
            let mut child = Command::new("/bin/sh")
                .args(["-c", "IFS= read -r line"])
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut observed = pending.bind_child(&mut child).unwrap();
            assert_eq!(observed.poll_and_record_exit().unwrap(), None);
            std::process::exit(77);
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let state = root.path().join("state");
        let protected = root.path().join("protected");
        std::fs::write(&protected, b"unchanged").unwrap();
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "same_user_supervisor::tests::synthetic_file_snapshot_reopens_after_supervisor_exit"])
            .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, &state)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
        assert_eq!(result.code(), Some(77));
        let restored = restore_synthetic_snapshot(&state, root.path()).unwrap();
        assert_eq!(
            std::fs::read(restored.path().join("Cargo.toml")).unwrap(),
            b"synthetic\0manifest"
        );
        assert!(!restored.path().join("Cargo.lock").exists());
        assert_eq!(std::fs::read(&protected).unwrap(), b"unchanged");
        let inspection = inspect_recovery(&state);
        assert_eq!(inspection.descendant_cleanup, RecoveryOutcome::Unknown);
        assert_eq!(inspection.rollback, RecoveryOutcome::Unknown);
        assert!(!state.join("pending-fixture-rollback").exists());
        assert!(PendingAttempt::begin(&state, ID).is_err());
        #[cfg(feature = "codex-fixture")]
        {
            let target = tempfile::tempdir_in(root.path()).unwrap();
            std::fs::write(target.path().join("Cargo.toml"), b"modified").unwrap();
            assert!(rollback_synthetic_manifest(&state, &target, b"different").is_err());
            assert_eq!(
                std::fs::read(target.path().join("Cargo.toml")).unwrap(),
                b"modified"
            );
            rollback_synthetic_manifest(&state, &target, b"modified").unwrap();
            assert_eq!(
                std::fs::read(target.path().join("Cargo.toml")).unwrap(),
                b"synthetic\0manifest"
            );
            rollback_synthetic_manifest(&state, &target, b"modified").unwrap();
            assert_eq!(
                inspect_recovery(&state).descendant_cleanup,
                RecoveryOutcome::Unknown
            );
            assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
            assert_eq!(std::fs::read(&protected).unwrap(), b"unchanged");
        }
        let snapshot = state.join("pending-snapshot");
        let mut corrupt = std::fs::read(&snapshot).unwrap();
        *corrupt.last_mut().unwrap() ^= 1;
        std::fs::write(snapshot, corrupt).unwrap();
        let count = std::fs::read_dir(root.path()).unwrap().count();
        assert!(restore_synthetic_snapshot(&state, root.path()).is_err());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), count);
        assert_eq!(std::fs::read(&protected).unwrap(), b"unchanged");
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_rollback_refuses_symlink_and_unexpected_lockfile() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let state = root.path().join("state");
        let pending = PendingAttempt::begin(&state, ID).unwrap();
        pending
            .store_synthetic_files(&SyntheticFileSnapshot {
                version: 1,
                cargo_toml: Some(b"original".to_vec()),
                cargo_lock: None,
            })
            .unwrap();
        let protected = root.path().join("protected");
        std::fs::write(&protected, b"modified").unwrap();
        let link_target = tempfile::tempdir_in(root.path()).unwrap();
        symlink(&protected, link_target.path().join("Cargo.toml")).unwrap();
        assert!(rollback_synthetic_manifest(&state, &link_target, b"modified").is_err());
        assert_eq!(std::fs::read(&protected).unwrap(), b"modified");
        let lock_target = tempfile::tempdir_in(root.path()).unwrap();
        std::fs::write(lock_target.path().join("Cargo.toml"), b"modified").unwrap();
        std::fs::write(lock_target.path().join("Cargo.lock"), b"preserve").unwrap();
        assert!(rollback_synthetic_manifest(&state, &lock_target, b"modified").is_err());
        assert_eq!(
            std::fs::read(lock_target.path().join("Cargo.toml")).unwrap(),
            b"modified"
        );
        assert_eq!(
            std::fs::read(lock_target.path().join("Cargo.lock")).unwrap(),
            b"preserve"
        );
        assert_eq!(
            inspect_recovery(&state).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_recovery_restores_absence_without_removing_unexpected_content() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let state = root.path().join("state");
        let pending = PendingAttempt::begin(&state, ID).unwrap();
        let source = tempfile::tempdir_in(root.path()).unwrap();
        pending.capture_synthetic_files(&source).unwrap();
        let target = tempfile::tempdir_in(root.path()).unwrap();
        let manifest = target.path().join("Cargo.toml");
        let protected = target.path().join("protected");
        std::fs::write(&manifest, b"unexpected").unwrap();
        std::fs::write(&protected, b"unchanged").unwrap();
        assert!(recover_synthetic_attempt(&state, &target, b"created").is_err());
        assert_eq!(std::fs::read(&manifest).unwrap(), b"unexpected");
        assert!(!state.join("pending-fixture-rollback").exists());
        std::fs::write(&manifest, b"created").unwrap();
        let copy = recover_synthetic_attempt(&state, &target, b"created").unwrap();
        assert!(!copy.path().join("Cargo.toml").exists());
        assert!(!manifest.exists());
        assert_eq!(std::fs::read(&protected).unwrap(), b"unchanged");
        assert_eq!(
            inspect_synthetic_rollback(&state),
            SyntheticRollbackObservation::RecordObserved
        );
        assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
        assert_eq!(
            inspect_recovery(&state).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
        assert!(PendingAttempt::begin(&state, ID).is_err());
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn persisted_synthetic_postimage_guides_recovery_after_supervisor_exit() {
        const CHILD: &str = "TUCUPI_POSTIMAGE_OWNER_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let state = Path::new(&path);
            let pending = PendingAttempt::begin(state, ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"original".to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
            pending.store_synthetic_postimage(b"modified").unwrap();
            assert_eq!(
                pending
                    .store_synthetic_postimage(b"other")
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::AlreadyExists
            );
            let mut child = Command::new("/bin/sh")
                .args(["-c", "IFS= read -r line"])
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut observed = pending.bind_child(&mut child).unwrap();
            assert_eq!(observed.poll_and_record_exit().unwrap(), None);
            std::process::exit(77);
        }
        for corrupt in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "same_user_supervisor::tests::persisted_synthetic_postimage_guides_recovery_after_supervisor_exit"])
                .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, &state)
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
            assert_eq!(status.code(), Some(77));
            let target = tempfile::tempdir_in(root.path()).unwrap();
            let manifest = target.path().join("Cargo.toml");
            std::fs::write(&manifest, b"modified").unwrap();
            let record = state.join("pending-fixture-postimage");
            if corrupt {
                let mut bytes = std::fs::read(&record).unwrap();
                *bytes.last_mut().unwrap() ^= 1;
                std::fs::write(&record, bytes).unwrap();
                assert!(
                    recover_synthetic_attempt_with_persisted_postimage(&state, &target).is_err()
                );
                assert_eq!(std::fs::read(&manifest).unwrap(), b"modified");
                assert!(!state.join("pending-fixture-rollback").exists());
            } else {
                let original_record = std::fs::read(&record).unwrap();
                let _copy =
                    recover_synthetic_attempt_with_persisted_postimage(&state, &target).unwrap();
                assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
                assert_eq!(std::fs::read(&record).unwrap(), original_record);
            }
            assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
            assert_eq!(
                inspect_recovery(&state).descendant_cleanup,
                RecoveryOutcome::Unknown
            );
            assert!(PendingAttempt::begin(&state, ID).is_err());
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn reopened_synthetic_recovery_uses_recorded_direct_exit() {
        const CHILD: &str = "TUCUPI_REOPEN_EXIT_SUPERVISOR";
        const RECOVERER: &str = "TUCUPI_REOPEN_EXIT_RECOVERER";
        if let Some(root) = std::env::var_os(RECOVERER) {
            let state = Path::new(&root).join("state");
            let target = std::env::var_os("TUCUPI_REOPEN_EXIT_TARGET").unwrap();
            let stage = std::env::var("TUCUPI_REOPEN_EXIT_STAGE").unwrap();
            let directory = recovery_state::open_provisioned_state_directory(&state).unwrap();
            let direct_exit = recovery_state::fixture_verified_direct_exit(&directory).unwrap();
            let expected = recovery_state::fixture_read_postimage_state(&directory).unwrap();
            let _ = recover_synthetic_attempt_with_precondition(
                &state,
                Path::new(&target),
                expected.as_deref(),
                || {},
                |_| {},
                |step| {
                    if step == stage {
                        std::process::exit(78);
                    }
                    Ok(())
                },
                SyntheticRecoveryPolicy::ReopenedAfterExit {
                    direct_exit,
                    directory,
                },
            );
            panic!("recoverer did not reach interruption point");
        }
        if let Some(root) = std::env::var_os(CHILD) {
            let root = Path::new(&root);
            let state = root.join("state");
            let target = std::env::var_os("TUCUPI_REOPEN_EXIT_TARGET").unwrap();
            let code = std::env::var("TUCUPI_REOPEN_EXIT_CODE").unwrap();
            let pending = PendingAttempt::begin(&state, ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"original".to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
            pending.store_synthetic_postimage(b"modified").unwrap();
            let mut child = TestChild(
                Command::new("/bin/sh")
                    .args([
                        "-c",
                        "IFS= read -r line; printf modified > \"$1/Cargo.toml\"; exit \"$2\"",
                        "fixture",
                    ])
                    .arg(&target)
                    .arg(&code)
                    .env_clear()
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            let mut input = child.0.stdin.take().unwrap();
            let mut observed = pending.bind_child(&mut child.0).unwrap();
            input.write_all(b"go\n").unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                if let Some(success) = observed.poll_and_record_exit().unwrap() {
                    assert_eq!(success, code == "0");
                    assert!(!observed.permits_operation());
                    break;
                }
                assert!(Instant::now() < deadline, "synthetic child did not exit");
                std::thread::sleep(Duration::from_millis(10));
            }
            std::process::exit(77);
        }
        for code in ["0", "7", "9", "10"] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let target = tempfile::tempdir_in(root.path()).unwrap();
            let manifest = target.path().join("Cargo.toml");
            std::fs::write(&manifest, b"original").unwrap();
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "same_user_supervisor::tests::reopened_synthetic_recovery_uses_recorded_direct_exit"])
                .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, root.path())
                .env("TUCUPI_REOPEN_EXIT_TARGET", target.path()).env("TUCUPI_REOPEN_EXIT_CODE", code)
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
            assert_eq!(status.code(), Some(77));
            assert_eq!(std::fs::read(&manifest).unwrap(), b"modified");
            let exit_path = state.join("pending-exit");
            let exit = std::fs::read(&exit_path).unwrap();
            let intent = std::fs::read(state.join("pending-intent")).unwrap();
            let original_directory =
                recovery_state::open_provisioned_state_directory(&state).unwrap();
            let replacement = root.path().join("replacement");
            std::fs::create_dir(&replacement).unwrap();
            std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o700)).unwrap();
            for entry in std::fs::read_dir(&state).unwrap() {
                let entry = entry.unwrap();
                assert!(entry.file_type().unwrap().is_file());
                std::fs::copy(entry.path(), replacement.join(entry.file_name())).unwrap();
            }
            let original_path = root.path().join("original-state");
            std::fs::rename(&state, &original_path).unwrap();
            std::fs::rename(&replacement, &state).unwrap();
            assert!(recovery_state::fixture_verified_direct_exit(
                &recovery_state::open_provisioned_state_directory(&state).unwrap()
            )
            .is_ok());
            let swapped =
                reopen_synthetic_attempt_after_exit_in(&state, &original_directory, &target);
            assert!(swapped.is_err());
            assert_eq!(std::fs::read(&manifest).unwrap(), b"modified");
            assert!(!state.join("pending-fixture-rollback").exists());
            std::fs::rename(&state, &replacement).unwrap();
            std::fs::rename(&original_path, &state).unwrap();
            std::fs::remove_file(&exit_path).unwrap();
            assert!(reopen_synthetic_attempt_after_exit(&state, &target).is_err());
            assert_eq!(std::fs::read(&manifest).unwrap(), b"modified");
            assert!(!state.join("pending-fixture-rollback").exists());
            std::fs::write(&exit_path, b"partial").unwrap();
            std::fs::set_permissions(&exit_path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(reopen_synthetic_attempt_after_exit(&state, &target).is_err());
            assert_eq!(std::fs::read(&manifest).unwrap(), b"modified");
            std::fs::write(&exit_path, &exit).unwrap();
            let raced = recover_synthetic_attempt_with_precondition(
                &state,
                target.path(),
                Some(b"modified"),
                || {
                    std::fs::write(&exit_path, b"partial").unwrap();
                },
                |_| {},
                |_| panic!("changed exit must not publish"),
                SyntheticRecoveryPolicy::ReopenedAfterExit {
                    direct_exit: exit.clone(),
                    directory: recovery_state::open_provisioned_state_directory(&state).unwrap(),
                },
            );
            assert!(raced.is_err());
            assert_eq!(std::fs::read(&manifest).unwrap(), b"modified");
            assert!(!state.join("pending-fixture-rollback").exists());
            std::fs::write(&exit_path, &exit).unwrap();
            let changed_after_mutation = reopen_synthetic_attempt_after_exit_with_hooks(
                &state,
                &target,
                |step| {
                    if step == "renamed" {
                        std::fs::write(&exit_path, b"partial").unwrap();
                    }
                },
                |_| Ok(()),
            );
            assert!(changed_after_mutation.is_err());
            assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
            assert!(!state.join("pending-fixture-rollback").exists());
            assert_eq!(std::fs::read(state.join("pending-intent")).unwrap(), intent);
            let inspection = inspect_recovery(&state);
            assert_eq!(inspection.descendant_cleanup, RecoveryOutcome::Unknown);
            assert_eq!(inspection.rollback, RecoveryOutcome::Unknown);
            assert!(recovery_state::codex_recovery_preflight_at(&state).is_err());
            std::fs::write(&exit_path, &exit).unwrap();
            std::fs::write(&manifest, b"conflict").unwrap();
            assert!(reopen_synthetic_attempt_after_exit(&state, &target).is_err());
            assert_eq!(std::fs::read(&manifest).unwrap(), b"conflict");
            std::fs::write(&manifest, b"modified").unwrap();
            if code == "9" || code == "10" {
                let stage = if code == "9" { "created" } else { "written" };
                let interrupted = Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "same_user_supervisor::tests::reopened_synthetic_recovery_uses_recorded_direct_exit"])
                    .env_clear().env("HOME", root.path()).env("TMPDIR", root.path())
                    .env(RECOVERER, root.path()).env("TUCUPI_REOPEN_EXIT_TARGET", target.path())
                    .env("TUCUPI_REOPEN_EXIT_STAGE", stage)
                    .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
                assert_eq!(interrupted.code(), Some(78));
                assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
                let rollback_path = state.join("pending-fixture-rollback");
                let partial = std::fs::read(&rollback_path).unwrap();
                assert_eq!(partial.is_empty(), code == "9");
                let original_directory =
                    recovery_state::open_provisioned_state_directory(&state).unwrap();
                let replacement_resume = root.path().join("replacement-resume");
                std::fs::create_dir(&replacement_resume).unwrap();
                std::fs::set_permissions(
                    &replacement_resume,
                    std::fs::Permissions::from_mode(0o700),
                )
                .unwrap();
                for entry in std::fs::read_dir(&state).unwrap() {
                    let entry = entry.unwrap();
                    assert!(entry.file_type().unwrap().is_file());
                    std::fs::copy(entry.path(), replacement_resume.join(entry.file_name()))
                        .unwrap();
                }
                std::fs::rename(&state, &original_path).unwrap();
                std::fs::rename(&replacement_resume, &state).unwrap();
                assert!(resume_reopened_synthetic_attempt_after_exit_in(
                    &state,
                    &original_directory,
                    &target
                )
                .is_err());
                assert!(!state.join("pending-fixture-resume").exists());
                std::fs::rename(&state, &replacement_resume).unwrap();
                std::fs::rename(&original_path, &state).unwrap();
                std::fs::write(&exit_path, b"partial").unwrap();
                assert!(resume_reopened_synthetic_attempt_after_exit(&state, &target).is_err());
                std::fs::write(&exit_path, &exit).unwrap();
                let raced_resume =
                    resume_reopened_synthetic_attempt_after_exit_with_hook(&state, &target, || {
                        std::fs::write(&exit_path, b"partial").unwrap();
                    });
                assert!(raced_resume.is_err());
                assert!(!state.join("pending-fixture-resume").exists());
                std::fs::write(&exit_path, &exit).unwrap();
                let postimage = state.join("pending-fixture-postimage");
                let held_postimage = root.path().join("held-postimage");
                std::fs::rename(&postimage, &held_postimage).unwrap();
                assert!(resume_reopened_synthetic_attempt_after_exit(&state, &target).is_err());
                std::fs::rename(&held_postimage, &postimage).unwrap();
                std::fs::write(&manifest, b"conflict").unwrap();
                assert!(resume_reopened_synthetic_attempt_after_exit(&state, &target).is_err());
                assert_eq!(std::fs::read(&manifest).unwrap(), b"conflict");
                assert!(!state.join("pending-fixture-resume").exists());
                std::fs::write(&manifest, b"original").unwrap();
                assert_eq!(
                    inspect_synthetic_resume_target(&state, &target),
                    SyntheticTargetObservation::UnavailableOrInvalid
                );
                resume_reopened_synthetic_attempt_after_exit(&state, &target).unwrap();
                assert_eq!(
                    inspect_synthetic_resume_target(&state, &target),
                    SyntheticTargetObservation::MatchesSnapshot
                );
                let resume_path = state.join("pending-fixture-resume");
                let resume = std::fs::read(&resume_path).unwrap();
                std::fs::write(&manifest, b"later divergence").unwrap();
                assert_eq!(
                    inspect_synthetic_resume_target(&state, &target),
                    SyntheticTargetObservation::DiffersFromSnapshot
                );
                assert_eq!(std::fs::read(&resume_path).unwrap(), resume);
                std::fs::write(&resume_path, b"invalid").unwrap();
                assert_eq!(
                    inspect_synthetic_resume_target(&state, &target),
                    SyntheticTargetObservation::UnavailableOrInvalid
                );
                std::fs::write(&resume_path, &resume).unwrap();
                std::fs::write(&manifest, b"original").unwrap();
                assert_eq!(std::fs::read(&rollback_path).unwrap(), partial);
                assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
                assert_eq!(std::fs::read(state.join("pending-intent")).unwrap(), intent);
                assert!(recovery_state::codex_recovery_preflight_at(&state).is_err());
                let inspection = inspect_recovery(&state);
                assert_eq!(inspection.descendant_cleanup, RecoveryOutcome::Unknown);
                assert_eq!(inspection.rollback, RecoveryOutcome::Unknown);
                continue;
            }
            let copy = reopen_synthetic_attempt_after_exit(&state, &target).unwrap();
            assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
            assert_eq!(
                std::fs::read(copy.path().join("Cargo.toml")).unwrap(),
                b"original"
            );
            assert_eq!(std::fs::read(&exit_path).unwrap(), exit);
            assert_eq!(std::fs::read(state.join("pending-intent")).unwrap(), intent);
            assert!(reopen_synthetic_attempt_after_exit(&state, &target).is_err());
            assert!(recovery_state::codex_recovery_preflight_at(&state).is_err());
            let inspection = inspect_recovery(&state);
            assert_eq!(inspection.descendant_cleanup, RecoveryOutcome::Unknown);
            assert_eq!(inspection.rollback, RecoveryOutcome::Unknown);
            assert!(PendingAttempt::begin(&state, ID).is_err());
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_absent_postimage_restores_deleted_file_without_clobbering() {
        const CHILD: &str = "TUCUPI_ABSENT_POSTIMAGE_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let pending = PendingAttempt::begin(Path::new(&path), ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"original".to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
            pending.store_synthetic_absent_postimage().unwrap();
            assert_eq!(
                pending.store_synthetic_postimage(b"").unwrap_err().kind(),
                io::ErrorKind::AlreadyExists
            );
            let mut child = Command::new("/bin/sh")
                .args(["-c", "IFS= read -r line"])
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut observed = pending.bind_child(&mut child).unwrap();
            assert_eq!(observed.poll_and_record_exit().unwrap(), None);
            std::process::exit(77);
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let state = root.path().join("state");
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "same_user_supervisor::tests::synthetic_absent_postimage_restores_deleted_file_without_clobbering"])
            .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, &state)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
        assert_eq!(status.code(), Some(77));
        let target = tempfile::tempdir_in(root.path()).unwrap();
        let manifest = target.path().join("Cargo.toml");
        let protected = target.path().join("protected");
        std::fs::write(&protected, b"unchanged").unwrap();
        std::fs::write(&manifest, b"").unwrap();
        assert!(recover_synthetic_attempt_with_persisted_postimage(&state, &target).is_err());
        assert_eq!(std::fs::read(&manifest).unwrap(), b"");
        assert!(!state.join("pending-fixture-rollback").exists());
        std::fs::remove_file(&manifest).unwrap();
        let raced = recover_synthetic_attempt_with_precondition(
            &state,
            target.path(),
            None,
            || {},
            |step| {
                if step == "prepared" {
                    std::fs::write(&manifest, b"unexpected").unwrap();
                }
            },
            |_| panic!("conflict must not publish result"),
            SyntheticRecoveryPolicy::Persisted,
        );
        assert!(raced.is_err());
        assert_eq!(std::fs::read(&manifest).unwrap(), b"unexpected");
        assert!(!state.join("pending-fixture-rollback").exists());
        std::fs::remove_file(&manifest).unwrap();
        let _copy = recover_synthetic_attempt_with_persisted_postimage(&state, &target).unwrap();
        assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
        assert_eq!(std::fs::read(&protected).unwrap(), b"unchanged");
        assert_eq!(
            inspect_recovery(&state).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
        assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
        assert!(PendingAttempt::begin(&state, ID).is_err());
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_postimage_refuses_different_snapshot_with_same_attempt() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["first", "second", "missing"] {
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new(name))
                .unwrap();
        }
        let first = root.path().join("first");
        let second = root.path().join("second");
        let missing = root.path().join("missing");
        let missing_pending = PendingAttempt::begin(&missing, ID).unwrap();
        assert!(missing_pending
            .store_synthetic_postimage(b"modified")
            .is_err());
        assert!(!missing.join("pending-fixture-postimage").exists());
        for (path, content) in [
            (&first, b"snapshot A".as_slice()),
            (&second, b"snapshot B".as_slice()),
        ] {
            let pending = PendingAttempt::begin(path, ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(content.to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
            pending.store_synthetic_postimage(b"modified").unwrap();
        }
        let mismatched = std::fs::read(second.join("pending-snapshot")).unwrap();
        std::fs::write(first.join("pending-snapshot"), &mismatched).unwrap();
        let target = tempfile::tempdir_in(root.path()).unwrap();
        let manifest = target.path().join("Cargo.toml");
        std::fs::write(&manifest, b"modified").unwrap();
        assert!(recover_synthetic_attempt_with_persisted_postimage(&first, &target).is_err());
        assert_eq!(std::fs::read(&manifest).unwrap(), b"modified");
        assert!(!first.join("pending-fixture-rollback").exists());
        assert_eq!(
            std::fs::read(first.join("pending-snapshot")).unwrap(),
            mismatched
        );
        assert_eq!(
            inspect_recovery(&first).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
        assert_eq!(inspect_recovery(&first).rollback, RecoveryOutcome::Unknown);
        assert!(PendingAttempt::begin(&first, ID).is_err());
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn interrupted_absent_synthetic_rollback_can_resume_same_target() {
        use std::io::{Read, Write};
        const CHILD: &str = "TUCUPI_ABSENT_ROLLBACK_CHILD";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = Path::new(&root);
            let mut gate = [0_u8; 1];
            std::io::stdin().read_exact(&mut gate).unwrap();
            let snapshot = read_synthetic_files(&root.join("state")).unwrap();
            let target = std::env::var_os("TUCUPI_ABSENT_ROLLBACK_TARGET").unwrap();
            let _ = rollback_synthetic_contents(
                &snapshot,
                Path::new(&target),
                Some(b"created"),
                |step| {
                    if step == "removed" {
                        std::process::exit(77);
                    }
                },
            );
            panic!("synthetic interruption did not occur");
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let state = root.path().join("state");
        let pending = PendingAttempt::begin(&state, ID).unwrap();
        let source = tempfile::tempdir_in(root.path()).unwrap();
        pending.capture_synthetic_files(&source).unwrap();
        let target = tempfile::tempdir_in(root.path()).unwrap();
        std::fs::write(target.path().join("Cargo.toml"), b"created").unwrap();
        std::fs::write(target.path().join("protected"), b"unchanged").unwrap();
        let mut child = TestChild(Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "same_user_supervisor::tests::interrupted_absent_synthetic_rollback_can_resume_same_target"])
            .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, root.path())
            .env("TUCUPI_ABSENT_ROLLBACK_TARGET", target.path())
            .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
        let mut input = child.0.stdin.take().unwrap();
        let observed = pending.bind_child(&mut child.0).unwrap();
        assert!(!observed.permits_operation());
        drop(observed);
        input.write_all(b"x").unwrap();
        assert_eq!(child.0.wait().unwrap().code(), Some(77));
        assert!(!target.path().join("Cargo.toml").exists());
        assert_eq!(
            std::fs::read(target.path().join("protected")).unwrap(),
            b"unchanged"
        );
        assert!(!state.join("pending-fixture-rollback").exists());
        assert_eq!(
            inspect_recovery(&state).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
        assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
        let copy = recover_synthetic_attempt(&state, &target, b"created").unwrap();
        assert!(!target.path().join("Cargo.toml").exists());
        assert!(!copy.path().join("Cargo.toml").exists());
        assert_eq!(
            std::fs::read(target.path().join("protected")).unwrap(),
            b"unchanged"
        );
        assert_eq!(
            inspect_synthetic_rollback(&state),
            SyntheticRollbackObservation::RecordObserved
        );
        assert_eq!(
            inspect_recovery(&state).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
        assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
        assert!(PendingAttempt::begin(&state, ID).is_err());
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn interrupted_deleted_synthetic_file_recovery_can_resume_same_target() {
        use std::io::{Read, Write};
        const CHILD: &str = "TUCUPI_DELETED_RECOVERY_CHILD";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = Path::new(&root);
            let mut gate = [0_u8; 1];
            std::io::stdin().read_exact(&mut gate).unwrap();
            let point = std::env::var("TUCUPI_DELETED_RECOVERY_POINT").unwrap();
            let target = std::env::var_os("TUCUPI_DELETED_RECOVERY_TARGET").unwrap();
            let snapshot = read_synthetic_files(&root.join("state")).unwrap();
            let _ = rollback_synthetic_contents(&snapshot, Path::new(&target), None, |step| {
                if step == point {
                    std::process::exit(77);
                }
            });
            panic!("synthetic interruption did not occur");
        }
        for point in ["prepared", "renamed"] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let pending = PendingAttempt::begin(&state, ID).unwrap();
            let source = tempfile::tempdir_in(root.path()).unwrap();
            std::fs::write(source.path().join("Cargo.toml"), b"original").unwrap();
            pending.capture_synthetic_files(&source).unwrap();
            pending.store_synthetic_absent_postimage().unwrap();
            let target = tempfile::tempdir_in(root.path()).unwrap();
            std::fs::write(target.path().join("protected"), b"unchanged").unwrap();
            let mut child = TestChild(Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "same_user_supervisor::tests::interrupted_deleted_synthetic_file_recovery_can_resume_same_target"])
                .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, root.path())
                .env("TUCUPI_DELETED_RECOVERY_POINT", point).env("TUCUPI_DELETED_RECOVERY_TARGET", target.path())
                .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
            let mut input = child.0.stdin.take().unwrap();
            let observed = pending.bind_child(&mut child.0).unwrap();
            assert!(!observed.permits_operation());
            drop(observed);
            input.write_all(b"x").unwrap();
            assert_eq!(child.0.wait().unwrap().code(), Some(77));
            let manifest = target.path().join("Cargo.toml");
            if point == "prepared" {
                assert!(!manifest.exists());
            } else {
                assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
            }
            assert!(!state.join("pending-fixture-rollback").exists());
            let snapshot = std::fs::read(state.join("pending-snapshot")).unwrap();
            let postimage = std::fs::read(state.join("pending-fixture-postimage")).unwrap();
            let _copy =
                recover_synthetic_attempt_with_persisted_postimage(&state, &target).unwrap();
            assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
            assert_eq!(
                std::fs::read(target.path().join("protected")).unwrap(),
                b"unchanged"
            );
            assert_eq!(
                std::fs::read(state.join("pending-snapshot")).unwrap(),
                snapshot
            );
            assert_eq!(
                std::fs::read(state.join("pending-fixture-postimage")).unwrap(),
                postimage
            );
            assert_eq!(
                inspect_recovery(&state).descendant_cleanup,
                RecoveryOutcome::Unknown
            );
            assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
            assert!(PendingAttempt::begin(&state, ID).is_err());
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_two_file_recovery_resumes_after_interruption() {
        use std::io::{Read, Write};
        const CHILD: &str = "TUCUPI_MULTI_RECOVERY_CHILD";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = Path::new(&root);
            let target = std::env::var_os("TUCUPI_MULTI_RECOVERY_TARGET").unwrap();
            let mut gate = [0_u8; 1];
            std::io::stdin().read_exact(&mut gate).unwrap();
            let _ = recover_synthetic_two_files_with_hook(
                &root.join("state"),
                Path::new(&target),
                |name| {
                    if name == "Cargo.toml" {
                        std::process::exit(77);
                    }
                },
            );
            panic!("synthetic interruption did not occur");
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let state = root.path().join("state");
        let pending = PendingAttempt::begin(&state, ID).unwrap();
        let source = tempfile::tempdir_in(root.path()).unwrap();
        std::fs::write(source.path().join("Cargo.toml"), b"original\0manifest").unwrap();
        pending.capture_synthetic_files(&source).unwrap();
        pending
            .store_synthetic_two_file_postimage(&SyntheticFileSnapshot {
                version: 1,
                cargo_toml: Some(b"changed".to_vec()),
                cargo_lock: Some(b"created".to_vec()),
            })
            .unwrap();
        let target = tempfile::tempdir_in(root.path()).unwrap();
        let manifest = target.path().join("Cargo.toml");
        let lock = target.path().join("Cargo.lock");
        std::fs::write(&manifest, b"changed").unwrap();
        std::fs::write(&lock, b"conflict").unwrap();
        std::fs::write(target.path().join("protected"), b"unchanged").unwrap();
        assert!(recover_synthetic_two_files(&state, &target).is_err());
        assert_eq!(std::fs::read(&manifest).unwrap(), b"changed");
        assert_eq!(std::fs::read(&lock).unwrap(), b"conflict");
        assert!(!state.join("pending-fixture-multi-rollback").exists());
        std::fs::write(&lock, b"created").unwrap();
        let mut child = TestChild(Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "same_user_supervisor::tests::synthetic_two_file_recovery_resumes_after_interruption"])
            .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, root.path())
            .env("TUCUPI_MULTI_RECOVERY_TARGET", target.path())
            .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
        let mut input = child.0.stdin.take().unwrap();
        let observed = pending.bind_child(&mut child.0).unwrap();
        assert!(!observed.permits_operation());
        drop(observed);
        input.write_all(b"x").unwrap();
        assert_eq!(child.0.wait().unwrap().code(), Some(77));
        assert_eq!(std::fs::read(&manifest).unwrap(), b"original\0manifest");
        assert_eq!(std::fs::read(&lock).unwrap(), b"created");
        assert!(!state.join("pending-fixture-multi-rollback").exists());
        let snapshot = std::fs::read(state.join("pending-snapshot")).unwrap();
        let postimage = std::fs::read(state.join("pending-fixture-postimage")).unwrap();
        recover_synthetic_two_files(&state, &target).unwrap();
        assert_eq!(std::fs::read(&manifest).unwrap(), b"original\0manifest");
        assert!(!lock.exists());
        assert_eq!(
            std::fs::read(target.path().join("protected")).unwrap(),
            b"unchanged"
        );
        assert_eq!(
            std::fs::read(state.join("pending-snapshot")).unwrap(),
            snapshot
        );
        assert_eq!(
            std::fs::read(state.join("pending-fixture-postimage")).unwrap(),
            postimage
        );
        assert!(state.join("pending-fixture-multi-rollback").exists());
        assert!(recover_synthetic_two_files(&state, &target).is_err());
        assert_eq!(
            inspect_recovery(&state).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
        assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
        assert!(PendingAttempt::begin(&state, ID).is_err());
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_recovery_refuses_cross_mode_and_legacy_postimages() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["single", "multi"] {
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new(name))
                .unwrap();
        }
        let single = root.path().join("single");
        let multi = root.path().join("multi");
        let original = SyntheticFileSnapshot {
            version: 1,
            cargo_toml: Some(b"original".to_vec()),
            cargo_lock: None,
        };
        let expected = SyntheticFileSnapshot {
            version: 1,
            cargo_toml: Some(b"modified".to_vec()),
            cargo_lock: None,
        };
        let encoded = serde_json::to_vec(&expected).unwrap();
        let pending = PendingAttempt::begin(&single, ID).unwrap();
        pending.store_synthetic_files(&original).unwrap();
        pending.store_synthetic_postimage(&encoded).unwrap();
        let pending = PendingAttempt::begin(&multi, ID).unwrap();
        pending.store_synthetic_files(&original).unwrap();
        pending
            .store_synthetic_two_file_postimage(&expected)
            .unwrap();
        let target = tempfile::tempdir_in(root.path()).unwrap();
        let manifest = target.path().join("Cargo.toml");
        std::fs::write(&manifest, b"modified").unwrap();
        assert!(recover_synthetic_two_files(&single, &target).is_err());
        assert_eq!(std::fs::read(&manifest).unwrap(), b"modified");
        std::fs::write(&manifest, &encoded).unwrap();
        assert!(recover_synthetic_attempt_with_persisted_postimage(&multi, &target).is_err());
        assert_eq!(std::fs::read(&manifest).unwrap(), encoded);
        assert!(!single.join("pending-fixture-multi-rollback").exists());
        assert!(!multi.join("pending-fixture-rollback").exists());
        let legacy = single.join("pending-fixture-postimage");
        let mut bytes = std::fs::read(&legacy).unwrap();
        bytes[..8].copy_from_slice(b"TUCPOST2");
        std::fs::write(&legacy, &bytes).unwrap();
        assert!(recover_synthetic_attempt_with_persisted_postimage(&single, &target).is_err());
        assert!(recover_synthetic_two_files(&single, &target).is_err());
        assert_eq!(std::fs::read(&legacy).unwrap(), bytes);
        assert_eq!(
            inspect_recovery(&single).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
        assert_eq!(inspect_recovery(&multi).rollback, RecoveryOutcome::Unknown);
        assert!(PendingAttempt::begin(&single, ID).is_err());
        assert!(PendingAttempt::begin(&multi, ID).is_err());
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn interrupted_two_file_result_reopens_without_authorizing() {
        use std::io::{Read, Write};
        const CHILD: &str = "TUCUPI_MULTI_RESULT_CHILD";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = Path::new(&root);
            let target = std::env::var_os("TUCUPI_MULTI_RESULT_TARGET").unwrap();
            let point = std::env::var("TUCUPI_MULTI_RESULT_POINT").unwrap();
            let mut gate = [0_u8; 1];
            std::io::stdin().read_exact(&mut gate).unwrap();
            let _ = recover_synthetic_two_files_with_hooks(
                &root.join("state"),
                Path::new(&target),
                |_| {},
                |step| {
                    if step == point {
                        std::process::exit(77);
                    }
                    Ok(())
                },
            );
            panic!("synthetic interruption did not occur");
        }
        for point in ["created", "written"] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let pending = PendingAttempt::begin(&state, ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"original manifest".to_vec()),
                    cargo_lock: Some(b"original lock".to_vec()),
                })
                .unwrap();
            pending
                .store_synthetic_two_file_postimage(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"modified manifest".to_vec()),
                    cargo_lock: Some(b"modified lock".to_vec()),
                })
                .unwrap();
            let target = tempfile::tempdir_in(root.path()).unwrap();
            std::fs::write(target.path().join("Cargo.toml"), b"modified manifest").unwrap();
            std::fs::write(target.path().join("Cargo.lock"), b"modified lock").unwrap();
            std::fs::write(target.path().join("protected"), b"unchanged").unwrap();
            let mut child = TestChild(Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "same_user_supervisor::tests::interrupted_two_file_result_reopens_without_authorizing"])
                .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, root.path())
                .env("TUCUPI_MULTI_RESULT_TARGET", target.path()).env("TUCUPI_MULTI_RESULT_POINT", point)
                .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
            let mut input = child.0.stdin.take().unwrap();
            let observed = pending.bind_child(&mut child.0).unwrap();
            assert!(!observed.permits_operation());
            drop(observed);
            input.write_all(b"x").unwrap();
            assert_eq!(child.0.wait().unwrap().code(), Some(77));
            assert_eq!(
                std::fs::read(target.path().join("Cargo.toml")).unwrap(),
                b"original manifest"
            );
            assert_eq!(
                std::fs::read(target.path().join("Cargo.lock")).unwrap(),
                b"original lock"
            );
            assert_eq!(
                std::fs::read(target.path().join("protected")).unwrap(),
                b"unchanged"
            );
            let record = state.join("pending-fixture-multi-rollback");
            let before = std::fs::read(&record).unwrap();
            let expected = if point == "created" {
                SyntheticTwoFileObservation::UnavailableOrInvalid
            } else {
                SyntheticTwoFileObservation::RecordObserved
            };
            assert_eq!(inspect_synthetic_two_file_rollback(&state), expected);
            assert_eq!(std::fs::read(&record).unwrap(), before);
            assert!(recover_synthetic_two_files(&state, &target).is_err());
            assert_eq!(std::fs::read(&record).unwrap(), before);
            assert_eq!(
                inspect_recovery(&state).descendant_cleanup,
                RecoveryOutcome::Unknown
            );
            assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
            assert!(PendingAttempt::begin(&state, ID).is_err());
            if point == "written" {
                std::fs::write(&record, b"partial").unwrap();
                assert_eq!(
                    inspect_synthetic_two_file_rollback(&state),
                    SyntheticTwoFileObservation::UnavailableOrInvalid
                );
                assert_eq!(std::fs::read(&record).unwrap(), b"partial");
            }
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_two_file_result_rejects_changed_recovery_plan() {
        for different_snapshot in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            for name in ["first", "second"] {
                recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new(name))
                    .unwrap();
            }
            let first = root.path().join("first");
            let second = root.path().join("second");
            for (path, original, expected) in [
                (&first, b"original".as_slice(), b"modified".as_slice()),
                (
                    &second,
                    if different_snapshot {
                        b"other".as_slice()
                    } else {
                        b"original".as_slice()
                    },
                    b"alternate".as_slice(),
                ),
            ] {
                let pending = PendingAttempt::begin(path, ID).unwrap();
                pending
                    .store_synthetic_files(&SyntheticFileSnapshot {
                        version: 1,
                        cargo_toml: Some(original.to_vec()),
                        cargo_lock: None,
                    })
                    .unwrap();
                pending
                    .store_synthetic_two_file_postimage(&SyntheticFileSnapshot {
                        version: 1,
                        cargo_toml: Some(expected.to_vec()),
                        cargo_lock: None,
                    })
                    .unwrap();
            }
            let target = tempfile::tempdir_in(root.path()).unwrap();
            let manifest = target.path().join("Cargo.toml");
            std::fs::write(&manifest, b"modified").unwrap();
            recover_synthetic_two_files(&first, &target).unwrap();
            assert_eq!(
                inspect_synthetic_two_file_rollback(&first),
                SyntheticTwoFileObservation::RecordObserved
            );
            resume_synthetic_two_files(&first, &target).unwrap();
            assert_eq!(
                inspect_synthetic_two_file_resume(&first),
                SyntheticTwoFileResumeObservation::RecordObserved
            );
            let result = std::fs::read(first.join("pending-fixture-multi-rollback")).unwrap();
            let resume = std::fs::read(first.join("pending-fixture-multi-resume")).unwrap();
            for name in ["pending-snapshot", "pending-fixture-postimage"] {
                let replacement = std::fs::read(second.join(name)).unwrap();
                std::fs::write(first.join(name), replacement).unwrap();
            }
            assert_eq!(
                inspect_synthetic_two_file_rollback(&first),
                SyntheticTwoFileObservation::UnavailableOrInvalid
            );
            assert_eq!(
                inspect_synthetic_two_file_resume(&first),
                SyntheticTwoFileResumeObservation::UnavailableOrInvalid
            );
            assert!(resume_synthetic_two_files(&first, &target).is_err());
            assert_eq!(
                std::fs::read(first.join("pending-fixture-multi-rollback")).unwrap(),
                result
            );
            assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
            assert_eq!(
                std::fs::read(first.join("pending-fixture-multi-resume")).unwrap(),
                resume
            );
            assert_eq!(
                inspect_recovery(&first).descendant_cleanup,
                RecoveryOutcome::Unknown
            );
            assert_eq!(inspect_recovery(&first).rollback, RecoveryOutcome::Unknown);
            assert!(PendingAttempt::begin(&first, ID).is_err());
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn single_file_result_and_resume_reject_replaced_snapshot() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for (name, content) in [
            ("first", b"original".as_slice()),
            ("second", b"different".as_slice()),
        ] {
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new(name))
                .unwrap();
            let pending = PendingAttempt::begin(&root.path().join(name), ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(content.to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
        }
        let state = root.path().join("first");
        let target = tempfile::tempdir_in(root.path()).unwrap();
        let manifest = target.path().join("Cargo.toml");
        std::fs::write(&manifest, b"modified").unwrap();
        recover_synthetic_attempt(&state, &target, b"modified").unwrap();
        resume_synthetic_attempt(&state, &target).unwrap();
        assert_eq!(
            inspect_synthetic_rollback(&state),
            SyntheticRollbackObservation::RecordObserved
        );
        assert_eq!(
            inspect_synthetic_resume(&state),
            SyntheticResumeObservation::RecordObserved
        );
        let result = std::fs::read(state.join("pending-fixture-rollback")).unwrap();
        let resume = std::fs::read(state.join("pending-fixture-resume")).unwrap();
        let replacement = std::fs::read(root.path().join("second/pending-snapshot")).unwrap();
        std::fs::write(state.join("pending-snapshot"), &replacement).unwrap();
        assert_eq!(
            inspect_synthetic_rollback(&state),
            SyntheticRollbackObservation::UnavailableOrInvalid
        );
        assert_eq!(
            inspect_synthetic_resume(&state),
            SyntheticResumeObservation::UnavailableOrInvalid
        );
        assert_eq!(
            std::fs::read(state.join("pending-fixture-rollback")).unwrap(),
            result
        );
        assert_eq!(
            std::fs::read(state.join("pending-fixture-resume")).unwrap(),
            resume
        );
        assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
        assert_eq!(
            inspect_recovery(&state).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
        assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
        assert!(PendingAttempt::begin(&state, ID).is_err());
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn single_file_results_reject_changed_persisted_postimage() {
        for absent in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            for name in ["first", "second"] {
                recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new(name))
                    .unwrap();
                let pending = PendingAttempt::begin(&root.path().join(name), ID).unwrap();
                pending
                    .store_synthetic_files(&SyntheticFileSnapshot {
                        version: 1,
                        cargo_toml: Some(b"original".to_vec()),
                        cargo_lock: None,
                    })
                    .unwrap();
                if name == "first" && absent {
                    pending.store_synthetic_absent_postimage().unwrap();
                } else if name == "first" {
                    pending.store_synthetic_postimage(b"modified").unwrap();
                } else if absent {
                    pending.store_synthetic_postimage(b"").unwrap();
                } else {
                    pending.store_synthetic_postimage(b"different").unwrap();
                }
            }
            let state = root.path().join("first");
            let target = tempfile::tempdir_in(root.path()).unwrap();
            let manifest = target.path().join("Cargo.toml");
            if !absent {
                std::fs::write(&manifest, b"modified").unwrap();
            }
            recover_synthetic_attempt_with_persisted_postimage(&state, &target).unwrap();
            resume_synthetic_attempt(&state, &target).unwrap();
            assert_eq!(
                inspect_synthetic_rollback(&state),
                SyntheticRollbackObservation::RecordObserved
            );
            assert_eq!(
                inspect_synthetic_resume(&state),
                SyntheticResumeObservation::RecordObserved
            );
            let rollback = std::fs::read(state.join("pending-fixture-rollback")).unwrap();
            let resumed = std::fs::read(state.join("pending-fixture-resume")).unwrap();
            let replacement =
                std::fs::read(root.path().join("second/pending-fixture-postimage")).unwrap();
            std::fs::write(state.join("pending-fixture-postimage"), &replacement).unwrap();
            assert_eq!(
                inspect_synthetic_rollback(&state),
                SyntheticRollbackObservation::UnavailableOrInvalid
            );
            assert_eq!(
                inspect_synthetic_resume(&state),
                SyntheticResumeObservation::UnavailableOrInvalid
            );
            assert_eq!(
                std::fs::read(state.join("pending-fixture-rollback")).unwrap(),
                rollback
            );
            assert_eq!(
                std::fs::read(state.join("pending-fixture-resume")).unwrap(),
                resumed
            );
            assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
            assert_eq!(
                inspect_recovery(&state).descendant_cleanup,
                RecoveryOutcome::Unknown
            );
            assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
            assert!(PendingAttempt::begin(&state, ID).is_err());
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn orphaned_single_resume_blocks_both_synthetic_recovery_modes() {
        for multi in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let pending = PendingAttempt::begin(&state, ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"original".to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
            if multi {
                pending
                    .store_synthetic_two_file_postimage(&SyntheticFileSnapshot {
                        version: 1,
                        cargo_toml: Some(b"modified".to_vec()),
                        cargo_lock: None,
                    })
                    .unwrap();
            }
            let orphan = state.join("pending-fixture-resume");
            std::fs::write(&orphan, b"partial").unwrap();
            let target = tempfile::tempdir_in(root.path()).unwrap();
            let manifest = target.path().join("Cargo.toml");
            std::fs::write(&manifest, b"modified").unwrap();
            if multi {
                assert!(recover_synthetic_two_files(&state, &target).is_err());
            } else {
                assert!(recover_synthetic_attempt(&state, &target, b"modified").is_err());
            }
            let directory = recovery_state::open_provisioned_state_directory(&state).unwrap();
            let snapshot = recovery_state::read_recovery_snapshot(&directory).unwrap();
            if multi {
                let postimage = recovery_state::fixture_read_multi_postimage(&directory).unwrap();
                assert!(recovery_state::fixture_multi_rollback_record(
                    &directory,
                    ID,
                    &snapshot,
                    &postimage,
                    |_| Ok(())
                )
                .is_err());
            } else {
                assert!(recovery_state::fixture_rollback_record_with_hook(
                    &directory,
                    ID,
                    &snapshot,
                    None,
                    None,
                    |_| Ok(())
                )
                .is_err());
            }
            assert_eq!(std::fs::read(&manifest).unwrap(), b"modified");
            assert_eq!(std::fs::read(&orphan).unwrap(), b"partial");
            assert!(!state.join("pending-fixture-rollback").exists());
            assert!(!state.join("pending-fixture-multi-rollback").exists());
            let inspection = inspect_recovery(&state);
            assert_eq!(inspection.descendant_cleanup, RecoveryOutcome::Unknown);
            assert_eq!(inspection.rollback, RecoveryOutcome::Unknown);
            assert!(PendingAttempt::begin(&state, ID).is_err());
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_recovery_stops_when_conflicting_result_appears_midflight() {
        for multi in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let pending = PendingAttempt::begin(&state, ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"original".to_vec()),
                    cargo_lock: if multi {
                        Some(b"old lock".to_vec())
                    } else {
                        None
                    },
                })
                .unwrap();
            if multi {
                pending
                    .store_synthetic_two_file_postimage(&SyntheticFileSnapshot {
                        version: 1,
                        cargo_toml: Some(b"modified".to_vec()),
                        cargo_lock: Some(b"new lock".to_vec()),
                    })
                    .unwrap();
            }
            let target = tempfile::tempdir_in(root.path()).unwrap();
            let manifest = target.path().join("Cargo.toml");
            let lock = target.path().join("Cargo.lock");
            let conflict = state.join("pending-fixture-resume");
            std::fs::write(&manifest, b"modified").unwrap();
            if multi {
                std::fs::write(&lock, b"new lock").unwrap();
                let result = recover_synthetic_two_files_with_hook(&state, target.path(), |name| {
                    if name == "Cargo.toml" {
                        std::fs::write(&conflict, b"partial").unwrap();
                    }
                });
                assert!(result.is_err());
                assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
                assert_eq!(std::fs::read(&lock).unwrap(), b"new lock");
            } else {
                let result =
                    recover_synthetic_attempt_with_hook(&state, &target, b"modified", || {
                        std::fs::write(&conflict, b"partial").unwrap();
                    });
                assert!(result.is_err());
                assert_eq!(std::fs::read(&manifest).unwrap(), b"modified");
            }
            assert_eq!(std::fs::read(&conflict).unwrap(), b"partial");
            assert!(!state.join("pending-fixture-rollback").exists());
            assert!(!state.join("pending-fixture-multi-rollback").exists());
            assert_eq!(
                inspect_recovery(&state).descendant_cleanup,
                RecoveryOutcome::Unknown
            );
            assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
            assert!(PendingAttempt::begin(&state, ID).is_err());
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_observations_reject_cross_mode_records() {
        for multi in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let pending = PendingAttempt::begin(&state, ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"original".to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
            if multi {
                pending
                    .store_synthetic_two_file_postimage(&SyntheticFileSnapshot {
                        version: 1,
                        cargo_toml: Some(b"modified".to_vec()),
                        cargo_lock: None,
                    })
                    .unwrap();
            }
            let target = tempfile::tempdir_in(root.path()).unwrap();
            let manifest = target.path().join("Cargo.toml");
            std::fs::write(&manifest, b"modified").unwrap();
            if multi {
                recover_synthetic_two_files(&state, &target).unwrap();
                resume_synthetic_two_files(&state, &target).unwrap();
                assert_eq!(
                    inspect_synthetic_two_file_rollback(&state),
                    SyntheticTwoFileObservation::RecordObserved
                );
                assert_eq!(
                    inspect_synthetic_two_file_resume(&state),
                    SyntheticTwoFileResumeObservation::RecordObserved
                );
            } else {
                recover_synthetic_attempt(&state, &target, b"modified").unwrap();
                resume_synthetic_attempt(&state, &target).unwrap();
                assert_eq!(
                    inspect_synthetic_rollback(&state),
                    SyntheticRollbackObservation::RecordObserved
                );
                assert_eq!(
                    inspect_synthetic_resume(&state),
                    SyntheticResumeObservation::RecordObserved
                );
            }
            let conflicts = if multi {
                ["pending-fixture-rollback", "pending-fixture-resume"]
            } else {
                [
                    "pending-fixture-multi-rollback",
                    "pending-fixture-multi-resume",
                ]
            };
            for name in conflicts {
                let conflict = state.join(name);
                std::fs::write(&conflict, b"partial").unwrap();
                if multi {
                    assert_eq!(
                        inspect_synthetic_two_file_rollback(&state),
                        SyntheticTwoFileObservation::UnavailableOrInvalid
                    );
                    assert_eq!(
                        inspect_synthetic_two_file_resume(&state),
                        SyntheticTwoFileResumeObservation::UnavailableOrInvalid
                    );
                } else {
                    assert_eq!(
                        inspect_synthetic_rollback(&state),
                        SyntheticRollbackObservation::UnavailableOrInvalid
                    );
                    assert_eq!(
                        inspect_synthetic_resume(&state),
                        SyntheticResumeObservation::UnavailableOrInvalid
                    );
                }
                assert_eq!(std::fs::read(&conflict).unwrap(), b"partial");
                assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
                assert!(PendingAttempt::begin(&state, ID).is_err());
                std::fs::remove_file(&conflict).unwrap(); // Owned temporary fixture only.
            }
            let inspection = inspect_recovery(&state);
            assert_eq!(inspection.descendant_cleanup, RecoveryOutcome::Unknown);
            assert_eq!(inspection.rollback, RecoveryOutcome::Unknown);
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_two_file_resume_reopens_after_publication_failure() {
        const CHILD: &str = "TUCUPI_MULTI_RESUME_OBSERVER";
        if let Some(path) = std::env::var_os(CHILD) {
            let state = Path::new(&path);
            assert_eq!(
                inspect_synthetic_two_file_resume(state),
                SyntheticTwoFileResumeObservation::RecordObserved
            );
            assert_eq!(
                inspect_recovery(state).descendant_cleanup,
                RecoveryOutcome::Unknown
            );
            assert_eq!(inspect_recovery(state).rollback, RecoveryOutcome::Unknown);
            assert!(PendingAttempt::begin(state, ID).is_err());
            return;
        }
        for point in ["created", "written"] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let pending = PendingAttempt::begin(&state, ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"original".to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
            pending
                .store_synthetic_two_file_postimage(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"modified".to_vec()),
                    cargo_lock: Some(b"created".to_vec()),
                })
                .unwrap();
            let target = tempfile::tempdir_in(root.path()).unwrap();
            let manifest = target.path().join("Cargo.toml");
            let lock = target.path().join("Cargo.lock");
            std::fs::write(&manifest, b"modified").unwrap();
            std::fs::write(&lock, b"created").unwrap();
            std::fs::write(target.path().join("protected"), b"unchanged").unwrap();
            let result = recover_synthetic_two_files_with_hooks(
                &state,
                target.path(),
                |_| {},
                |step| {
                    if step == point {
                        return Err(io::Error::other("injected publication failure"));
                    }
                    Ok(())
                },
            );
            assert!(result.is_err());
            assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
            assert!(!lock.exists());
            let prior = state.join("pending-fixture-multi-rollback");
            let before = std::fs::read(&prior).unwrap();
            let intent = std::fs::read(state.join("pending-intent")).unwrap();
            std::fs::write(&lock, b"conflict").unwrap();
            assert!(resume_synthetic_two_files(&state, &target).is_err());
            assert_eq!(std::fs::read(&lock).unwrap(), b"conflict");
            assert!(!state.join("pending-fixture-multi-resume").exists());
            std::fs::remove_file(&lock).unwrap(); // This test owns the disposable target.
            resume_synthetic_two_files(&state, &target).unwrap();
            let resume = state.join("pending-fixture-multi-resume");
            let resume_bytes = std::fs::read(&resume).unwrap();
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "same_user_supervisor::tests::synthetic_two_file_resume_reopens_after_publication_failure"])
                .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, &state)
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
            assert!(status.success());
            assert!(resume_synthetic_two_files(&state, &target).is_err());
            assert_eq!(std::fs::read(&resume).unwrap(), resume_bytes);
            assert_eq!(std::fs::read(&prior).unwrap(), before);
            if point == "written" {
                std::fs::write(&prior, b"").unwrap();
                assert_eq!(
                    inspect_synthetic_two_file_resume(&state),
                    SyntheticTwoFileResumeObservation::UnavailableOrInvalid
                );
                assert_eq!(std::fs::read(&resume).unwrap(), resume_bytes);
                std::fs::write(&prior, &before).unwrap();
                assert_eq!(
                    inspect_synthetic_two_file_resume(&state),
                    SyntheticTwoFileResumeObservation::RecordObserved
                );
            }
            assert_eq!(std::fs::read(state.join("pending-intent")).unwrap(), intent);
            assert_eq!(
                std::fs::read(target.path().join("protected")).unwrap(),
                b"unchanged"
            );
            std::fs::write(&resume, b"partial").unwrap();
            assert_eq!(
                inspect_synthetic_two_file_resume(&state),
                SyntheticTwoFileResumeObservation::UnavailableOrInvalid
            );
            assert!(PendingAttempt::begin(&state, ID).is_err());
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn interrupted_two_file_resume_publication_remains_pending() {
        use std::io::{Read, Write};
        const CHILD: &str = "TUCUPI_MULTI_RESUME_WRITE_CHILD";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = Path::new(&root);
            let target = std::env::var_os("TUCUPI_MULTI_RESUME_WRITE_TARGET").unwrap();
            let point = std::env::var("TUCUPI_MULTI_RESUME_WRITE_POINT").unwrap();
            let mut gate = [0_u8; 1];
            std::io::stdin().read_exact(&mut gate).unwrap();
            let _ = resume_synthetic_two_files_with_hook(
                &root.join("state"),
                Path::new(&target),
                |step| {
                    if step == point {
                        std::process::exit(77);
                    }
                    Ok(())
                },
            );
            panic!("synthetic interruption did not occur");
        }
        for point in ["created", "written"] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let pending = PendingAttempt::begin(&state, ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"original".to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
            pending
                .store_synthetic_two_file_postimage(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"modified".to_vec()),
                    cargo_lock: Some(b"created".to_vec()),
                })
                .unwrap();
            let target = tempfile::tempdir_in(root.path()).unwrap();
            std::fs::write(target.path().join("Cargo.toml"), b"modified").unwrap();
            std::fs::write(target.path().join("Cargo.lock"), b"created").unwrap();
            std::fs::write(target.path().join("protected"), b"unchanged").unwrap();
            let mut child = TestChild(Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "same_user_supervisor::tests::interrupted_two_file_resume_publication_remains_pending"])
                .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, root.path())
                .env("TUCUPI_MULTI_RESUME_WRITE_TARGET", target.path()).env("TUCUPI_MULTI_RESUME_WRITE_POINT", point)
                .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
            let mut input = child.0.stdin.take().unwrap();
            let observed = pending.bind_child(&mut child.0).unwrap();
            assert!(!observed.permits_operation());
            drop(observed);
            let failed = recover_synthetic_two_files_with_hooks(
                &state,
                target.path(),
                |_| {},
                |step| {
                    if step == "created" {
                        return Err(io::Error::other("injected failure"));
                    }
                    Ok(())
                },
            );
            assert!(failed.is_err());
            let prior = std::fs::read(state.join("pending-fixture-multi-rollback")).unwrap();
            let intent = std::fs::read(state.join("pending-intent")).unwrap();
            let snapshot = std::fs::read(state.join("pending-snapshot")).unwrap();
            let postimage = std::fs::read(state.join("pending-fixture-postimage")).unwrap();
            input.write_all(b"x").unwrap();
            assert_eq!(child.0.wait().unwrap().code(), Some(77));
            let resume = state.join("pending-fixture-multi-resume");
            let bytes = std::fs::read(&resume).unwrap();
            let expected = if point == "created" {
                SyntheticTwoFileResumeObservation::UnavailableOrInvalid
            } else {
                SyntheticTwoFileResumeObservation::RecordObserved
            };
            assert_eq!(inspect_synthetic_two_file_resume(&state), expected);
            assert!(resume_synthetic_two_files(&state, &target).is_err());
            assert_eq!(std::fs::read(&resume).unwrap(), bytes);
            assert_eq!(
                std::fs::read(state.join("pending-fixture-multi-rollback")).unwrap(),
                prior
            );
            assert_eq!(std::fs::read(state.join("pending-intent")).unwrap(), intent);
            assert_eq!(
                std::fs::read(state.join("pending-snapshot")).unwrap(),
                snapshot
            );
            assert_eq!(
                std::fs::read(state.join("pending-fixture-postimage")).unwrap(),
                postimage
            );
            assert_eq!(
                std::fs::read(target.path().join("Cargo.toml")).unwrap(),
                b"original"
            );
            assert!(!target.path().join("Cargo.lock").exists());
            assert_eq!(
                std::fs::read(target.path().join("protected")).unwrap(),
                b"unchanged"
            );
            assert_eq!(
                inspect_recovery(&state).descendant_cleanup,
                RecoveryOutcome::Unknown
            );
            assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
            assert!(PendingAttempt::begin(&state, ID).is_err());
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_rollback_refuses_replaced_target_directory() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let state = root.path().join("state");
        let pending = PendingAttempt::begin(&state, ID).unwrap();
        pending
            .store_synthetic_files(&SyntheticFileSnapshot {
                version: 1,
                cargo_toml: Some(b"original".to_vec()),
                cargo_lock: None,
            })
            .unwrap();
        let target = tempfile::tempdir_in(root.path()).unwrap();
        std::fs::write(target.path().join("Cargo.toml"), b"modified").unwrap();
        let moved = root.path().join("moved-target");
        let protected = root.path().join("protected");
        std::fs::write(&protected, b"unchanged").unwrap();
        let result = rollback_synthetic_manifest_with_hook(&state, &target, b"modified", |step| {
            if step == "prepared" {
                std::fs::rename(target.path(), &moved).unwrap();
                std::fs::create_dir(target.path()).unwrap();
                std::fs::set_permissions(target.path(), std::fs::Permissions::from_mode(0o700))
                    .unwrap();
                std::fs::write(target.path().join("Cargo.toml"), b"replacement").unwrap();
            }
        });
        assert!(
            matches!(&result, Err(error) if error.kind() == io::ErrorKind::InvalidData),
            "{result:?}"
        );
        assert_eq!(
            std::fs::read(moved.join("Cargo.toml")).unwrap(),
            b"modified"
        );
        assert_eq!(
            std::fs::read(target.path().join("Cargo.toml")).unwrap(),
            b"replacement"
        );
        assert_eq!(std::fs::read(protected).unwrap(), b"unchanged");
        assert!(!state.join("pending-fixture-rollback").exists());
        assert_eq!(
            inspect_recovery(&state).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
        assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
        assert!(PendingAttempt::begin(&state, ID).is_err());
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_recovery_does_not_publish_after_target_replaced_post_rename() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let state = root.path().join("state");
        let pending = PendingAttempt::begin(&state, ID).unwrap();
        pending
            .store_synthetic_files(&SyntheticFileSnapshot {
                version: 1,
                cargo_toml: Some(b"original".to_vec()),
                cargo_lock: None,
            })
            .unwrap();
        let target = tempfile::tempdir_in(root.path()).unwrap();
        std::fs::write(target.path().join("Cargo.toml"), b"modified").unwrap();
        let moved = root.path().join("moved");
        let result = recover_synthetic_attempt_with_rollback_hook(
            &state,
            &target,
            b"modified",
            || {},
            |step| {
                if step == "renamed" {
                    std::fs::rename(target.path(), &moved).unwrap();
                    std::fs::create_dir(target.path()).unwrap();
                    std::fs::write(target.path().join("Cargo.toml"), b"replacement").unwrap();
                }
            },
            |_| panic!("result must not be published"),
        );
        assert!(result.is_err());
        assert_eq!(
            std::fs::read(moved.join("Cargo.toml")).unwrap(),
            b"original"
        );
        assert_eq!(
            std::fs::read(target.path().join("Cargo.toml")).unwrap(),
            b"replacement"
        );
        assert!(!state.join("pending-fixture-rollback").exists());
        assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
        assert_eq!(
            inspect_recovery(&state).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
        assert!(PendingAttempt::begin(&state, ID).is_err());
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_recovery_does_not_publish_if_snapshot_changes_after_rename() {
        for valid_replacement in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            for name in ["state", "other"] {
                recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new(name))
                    .unwrap();
            }
            let state = root.path().join("state");
            let other = root.path().join("other");
            for (directory, bytes) in [
                (&state, b"original".as_slice()),
                (&other, b"different".as_slice()),
            ] {
                let pending = PendingAttempt::begin(directory, ID).unwrap();
                pending
                    .store_synthetic_files(&SyntheticFileSnapshot {
                        version: 1,
                        cargo_toml: Some(bytes.to_vec()),
                        cargo_lock: None,
                    })
                    .unwrap();
            }
            let replacement = if valid_replacement {
                std::fs::read(other.join("pending-snapshot")).unwrap()
            } else {
                b"corrupt".to_vec()
            };
            let target = tempfile::tempdir_in(root.path()).unwrap();
            let manifest = target.path().join("Cargo.toml");
            std::fs::write(&manifest, b"modified").unwrap();
            let intent = std::fs::read(state.join("pending-intent")).unwrap();
            let result = recover_synthetic_attempt_with_rollback_hook(
                &state,
                &target,
                b"modified",
                || {},
                |step| {
                    if step == "renamed" {
                        std::fs::write(state.join("pending-snapshot"), &replacement).unwrap();
                    }
                },
                |_| panic!("result must not be published"),
            );
            assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
            assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
            assert_eq!(
                std::fs::read(state.join("pending-snapshot")).unwrap(),
                replacement
            );
            assert_eq!(std::fs::read(state.join("pending-intent")).unwrap(), intent);
            assert!(!state.join("pending-fixture-rollback").exists());
            assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
            assert_eq!(
                inspect_recovery(&state).descendant_cleanup,
                RecoveryOutcome::Unknown
            );
            assert!(PendingAttempt::begin(&state, ID).is_err());
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_recovery_does_not_publish_if_target_changes_after_rename() {
        for add_lock in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let pending = PendingAttempt::begin(&state, ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"original".to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
            let target = tempfile::tempdir_in(root.path()).unwrap();
            let manifest = target.path().join("Cargo.toml");
            std::fs::write(&manifest, b"modified").unwrap();
            let snapshot = std::fs::read(state.join("pending-snapshot")).unwrap();
            let intent = std::fs::read(state.join("pending-intent")).unwrap();
            let result = recover_synthetic_attempt_with_rollback_hook(
                &state,
                &target,
                b"modified",
                || {},
                |step| {
                    if step == "renamed" {
                        if add_lock {
                            std::fs::write(target.path().join("Cargo.lock"), b"unexpected")
                                .unwrap();
                        } else {
                            std::fs::write(&manifest, b"conflict").unwrap();
                        }
                    }
                },
                |_| panic!("result must not be published"),
            );
            assert!(result.is_err());
            if add_lock {
                assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
                assert_eq!(
                    std::fs::read(target.path().join("Cargo.lock")).unwrap(),
                    b"unexpected"
                );
            } else {
                assert_eq!(std::fs::read(&manifest).unwrap(), b"conflict");
            }
            assert_eq!(
                std::fs::read(state.join("pending-snapshot")).unwrap(),
                snapshot
            );
            assert_eq!(std::fs::read(state.join("pending-intent")).unwrap(), intent);
            assert!(!state.join("pending-fixture-rollback").exists());
            assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
            assert_eq!(
                inspect_recovery(&state).descendant_cleanup,
                RecoveryOutcome::Unknown
            );
            assert!(PendingAttempt::begin(&state, ID).is_err());
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_rollback_observation_reopens_without_authorizing() {
        const CHILD: &str = "TUCUPI_ROLLBACK_RESULT_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let state = Path::new(&path);
            assert_eq!(
                inspect_synthetic_rollback(state),
                SyntheticRollbackObservation::RecordObserved
            );
            let inspection = inspect_recovery(state);
            assert_eq!(inspection.descendant_cleanup, RecoveryOutcome::Unknown);
            assert_eq!(inspection.rollback, RecoveryOutcome::Unknown);
            assert!(PendingAttempt::begin(state, ID).is_err());
            return;
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let state = root.path().join("state");
        let pending = PendingAttempt::begin(&state, ID).unwrap();
        pending
            .store_synthetic_files(&SyntheticFileSnapshot {
                version: 1,
                cargo_toml: Some(b"original".to_vec()),
                cargo_lock: None,
            })
            .unwrap();
        assert_eq!(
            inspect_synthetic_rollback(&state),
            SyntheticRollbackObservation::UnavailableOrInvalid
        );
        let target = tempfile::tempdir_in(root.path()).unwrap();
        std::fs::write(target.path().join("Cargo.toml"), b"modified").unwrap();
        let _copy = recover_synthetic_attempt(&state, &target, b"modified").unwrap();
        let path = state.join("pending-fixture-rollback");
        let before = std::fs::read(&path).unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "same_user_supervisor::tests::synthetic_rollback_observation_reopens_without_authorizing"])
            .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, &state)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
        assert!(status.success());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::write(&path, b"partial fixture record").unwrap();
        assert_eq!(
            inspect_synthetic_rollback(&state),
            SyntheticRollbackObservation::UnavailableOrInvalid
        );
        assert!(recover_synthetic_attempt(&state, &target, b"modified").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"partial fixture record");
        assert_eq!(
            std::fs::read(target.path().join("Cargo.toml")).unwrap(),
            b"original"
        );
        assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_recovery_lease_excludes_cooperative_processes() {
        const CHILD: &str = "TUCUPI_RECOVERY_LEASE_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let root = Path::new(&path);
            let target = tempfile::tempdir_in(root).unwrap();
            std::fs::write(target.path().join("Cargo.toml"), b"modified").unwrap();
            let error =
                recover_synthetic_attempt(&root.join("state"), &target, b"modified").unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            assert_eq!(
                std::fs::read(target.path().join("Cargo.toml")).unwrap(),
                b"modified"
            );
            assert!(!root.join("state/pending-fixture-rollback").exists());
            return;
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let state = root.path().join("state");
        let pending = PendingAttempt::begin(&state, ID).unwrap();
        pending
            .store_synthetic_files(&SyntheticFileSnapshot {
                version: 1,
                cargo_toml: Some(b"original".to_vec()),
                cargo_lock: None,
            })
            .unwrap();
        let directory = recovery_state::open_provisioned_state_directory(&state).unwrap();
        let lease = recovery_state::fixture_recovery_lease(&directory).unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "same_user_supervisor::tests::synthetic_recovery_lease_excludes_cooperative_processes"])
            .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, root.path())
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
        assert!(status.success());
        assert_eq!(
            inspect_recovery(&state).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
        assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
        drop(lease);
        let target = tempfile::tempdir_in(root.path()).unwrap();
        std::fs::write(target.path().join("Cargo.toml"), b"modified").unwrap();
        let _copy = recover_synthetic_attempt(&state, &target, b"modified").unwrap();
        assert_eq!(
            std::fs::read(target.path().join("Cargo.toml")).unwrap(),
            b"original"
        );
        assert!(PendingAttempt::begin(&state, ID).is_err());
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_recovery_refuses_replaced_lease_inode_with_identical_snapshot() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let state = root.path().join("state");
        let pending = PendingAttempt::begin(&state, ID).unwrap();
        pending
            .store_synthetic_files(&SyntheticFileSnapshot {
                version: 1,
                cargo_toml: Some(b"original".to_vec()),
                cargo_lock: None,
            })
            .unwrap();
        let path = state.join("pending-snapshot");
        let bytes = std::fs::read(&path).unwrap();
        let target = tempfile::tempdir_in(root.path()).unwrap();
        let manifest = target.path().join("Cargo.toml");
        std::fs::write(&manifest, b"modified").unwrap();
        let result = recover_synthetic_attempt_with_hook(&state, &target, b"modified", || {
            use std::io::Write;
            let mut replacement = tempfile::NamedTempFile::new_in(&state).unwrap();
            replacement.write_all(&bytes).unwrap();
            replacement.persist(&path).unwrap();
        });
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(std::fs::read(&manifest).unwrap(), b"modified");
        assert!(!state.join("pending-fixture-rollback").exists());
        assert_eq!(
            inspect_recovery(&state).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
        assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
        assert!(PendingAttempt::begin(&state, ID).is_err());
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn interrupted_lease_holder_leaves_pending_attempt_and_allows_isolated_retry() {
        const CHILD: &str = "TUCUPI_LEASE_INTERRUPTION_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let root = Path::new(&path);
            let state = root.join("state");
            let pending = PendingAttempt::begin(&state, ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"original".to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
            let mut child = Command::new("/bin/sh")
                .args(["-c", "IFS= read -r line"])
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut observed = pending.bind_child(&mut child).unwrap();
            assert_eq!(observed.poll_and_record_exit().unwrap(), None);
            let target = tempfile::tempdir_in(root).unwrap();
            std::fs::write(target.path().join("Cargo.toml"), b"modified").unwrap();
            std::fs::write(
                root.join("interrupted-target"),
                target.path().as_os_str().as_encoded_bytes(),
            )
            .unwrap();
            let _ = recover_synthetic_attempt_with_hook(&state, &target, b"modified", || {
                let directory = recovery_state::open_provisioned_state_directory(&state).unwrap();
                assert_eq!(
                    recovery_state::fixture_recovery_lease(&directory)
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::WouldBlock
                );
                std::process::exit(77);
            });
            panic!("synthetic interruption did not occur");
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let state = root.path().join("state");
        std::fs::write(root.path().join("protected"), b"unchanged").unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "same_user_supervisor::tests::interrupted_lease_holder_leaves_pending_attempt_and_allows_isolated_retry"])
            .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, root.path())
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
        assert_eq!(status.code(), Some(77));
        let interrupted = std::path::PathBuf::from(
            std::fs::read_to_string(root.path().join("interrupted-target")).unwrap(),
        );
        assert_eq!(
            std::fs::read(interrupted.join("Cargo.toml")).unwrap(),
            b"modified"
        );
        assert!(!state.join("pending-fixture-rollback").exists());
        let intent = std::fs::read(state.join("pending-intent")).unwrap();
        let snapshot = std::fs::read(state.join("pending-snapshot")).unwrap();
        assert!(PendingAttempt::begin(&state, ID).is_err());
        assert_eq!(
            inspect_recovery(&state).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
        assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
        let retry = tempfile::tempdir_in(root.path()).unwrap();
        std::fs::write(retry.path().join("Cargo.toml"), b"modified").unwrap();
        let _copy = recover_synthetic_attempt(&state, &retry, b"modified").unwrap();
        assert_eq!(
            std::fs::read(retry.path().join("Cargo.toml")).unwrap(),
            b"original"
        );
        assert_eq!(
            std::fs::read(interrupted.join("Cargo.toml")).unwrap(),
            b"modified"
        );
        assert_eq!(
            std::fs::read(root.path().join("protected")).unwrap(),
            b"unchanged"
        );
        assert_eq!(std::fs::read(state.join("pending-intent")).unwrap(), intent);
        assert_eq!(
            std::fs::read(state.join("pending-snapshot")).unwrap(),
            snapshot
        );
        assert_eq!(
            inspect_recovery(&state).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
        assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
        assert!(PendingAttempt::begin(&state, ID).is_err());
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn interrupted_synthetic_rollback_result_stays_pending() {
        const CHILD: &str = "TUCUPI_ROLLBACK_RECORD_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let root = Path::new(&path);
            let point = std::env::var("TUCUPI_ROLLBACK_RECORD_POINT").unwrap();
            let target = tempfile::tempdir_in(root).unwrap();
            std::fs::write(target.path().join("Cargo.toml"), b"modified").unwrap();
            std::fs::write(
                root.join("result-target"),
                target.path().as_os_str().as_encoded_bytes(),
            )
            .unwrap();
            let _ = recover_synthetic_attempt_with_hooks(
                &root.join("state"),
                &target,
                b"modified",
                || {},
                |step| {
                    if step == point {
                        std::process::exit(77);
                    }
                    Ok(())
                },
            );
            panic!("fixture interruption did not occur");
        }
        for point in ["created", "written"] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let pending = PendingAttempt::begin(&state, ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"original".to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
            std::fs::write(root.path().join("protected"), b"unchanged").unwrap();
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "same_user_supervisor::tests::interrupted_synthetic_rollback_result_stays_pending"])
                .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, root.path())
                .env("TUCUPI_ROLLBACK_RECORD_POINT", point)
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
            assert_eq!(status.code(), Some(77));
            let target = std::path::PathBuf::from(
                std::fs::read_to_string(root.path().join("result-target")).unwrap(),
            );
            assert_eq!(
                std::fs::read(target.join("Cargo.toml")).unwrap(),
                b"original"
            );
            assert_eq!(
                std::fs::read(root.path().join("protected")).unwrap(),
                b"unchanged"
            );
            let record = state.join("pending-fixture-rollback");
            let before = std::fs::read(&record).unwrap();
            let expected = if point == "created" {
                SyntheticRollbackObservation::UnavailableOrInvalid
            } else {
                SyntheticRollbackObservation::RecordObserved
            };
            assert_eq!(inspect_synthetic_rollback(&state), expected);
            assert_eq!(
                inspect_recovery(&state).descendant_cleanup,
                RecoveryOutcome::Unknown
            );
            assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
            assert!(PendingAttempt::begin(&state, ID).is_err());
            let other = tempfile::tempdir_in(root.path()).unwrap();
            std::fs::write(other.path().join("Cargo.toml"), b"modified").unwrap();
            assert!(recover_synthetic_attempt(&state, &other, b"modified").is_err());
            assert_eq!(
                std::fs::read(other.path().join("Cargo.toml")).unwrap(),
                b"modified"
            );
            assert_eq!(std::fs::read(&record).unwrap(), before);
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_resume_observes_restored_target_after_publication_failure() {
        const CHILD: &str = "TUCUPI_RESUME_OBSERVE_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let state = Path::new(&path);
            assert_eq!(
                inspect_synthetic_resume(state),
                SyntheticResumeObservation::RecordObserved
            );
            assert_eq!(
                inspect_recovery(state).descendant_cleanup,
                RecoveryOutcome::Unknown
            );
            assert_eq!(inspect_recovery(state).rollback, RecoveryOutcome::Unknown);
            assert!(PendingAttempt::begin(state, ID).is_err());
            return;
        }
        for point in ["created", "written"] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let pending = PendingAttempt::begin(&state, ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"original".to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
            let target = tempfile::tempdir_in(root.path()).unwrap();
            let manifest = target.path().join("Cargo.toml");
            std::fs::write(&manifest, b"modified").unwrap();
            std::fs::write(root.path().join("protected"), b"unchanged").unwrap();
            let result = recover_synthetic_attempt_with_hooks(
                &state,
                &target,
                b"modified",
                || {},
                |step| {
                    if step == point {
                        return Err(io::Error::other("injected publication failure"));
                    }
                    Ok(())
                },
            );
            assert!(result.is_err());
            assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
            let prior = state.join("pending-fixture-rollback");
            let before = std::fs::read(&prior).unwrap();
            let intent = std::fs::read(state.join("pending-intent")).unwrap();
            std::fs::write(&manifest, b"conflict").unwrap();
            assert!(resume_synthetic_attempt(&state, &target).is_err());
            assert_eq!(std::fs::read(&manifest).unwrap(), b"conflict");
            assert!(!state.join("pending-fixture-resume").exists());
            // Restore only this test's disposable target to exercise resumption.
            std::fs::write(&manifest, b"original").unwrap();
            resume_synthetic_attempt(&state, &target).unwrap();
            let resume = std::fs::read(state.join("pending-fixture-resume")).unwrap();
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "same_user_supervisor::tests::synthetic_resume_observes_restored_target_after_publication_failure"])
                .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, &state)
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
            assert!(status.success());
            assert_eq!(
                std::fs::read(state.join("pending-fixture-resume")).unwrap(),
                resume
            );
            assert!(resume_synthetic_attempt(&state, &target).is_err());
            assert_eq!(
                std::fs::read(state.join("pending-fixture-resume")).unwrap(),
                resume
            );
            assert_eq!(std::fs::read(&prior).unwrap(), before);
            assert_eq!(std::fs::read(state.join("pending-intent")).unwrap(), intent);
            assert_eq!(
                std::fs::read(root.path().join("protected")).unwrap(),
                b"unchanged"
            );
            assert_eq!(
                inspect_recovery(&state).descendant_cleanup,
                RecoveryOutcome::Unknown
            );
            assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
            assert!(PendingAttempt::begin(&state, ID).is_err());
            std::fs::write(state.join("pending-fixture-resume"), b"partial").unwrap();
            assert_eq!(
                inspect_synthetic_resume(&state),
                SyntheticResumeObservation::UnavailableOrInvalid
            );
            assert!(resume_synthetic_attempt(&state, &target).is_err());
            assert_eq!(std::fs::read(&prior).unwrap(), before);
            assert_eq!(std::fs::read(state.join("pending-intent")).unwrap(), intent);
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_resume_refuses_changed_snapshot_after_target_check() {
        for valid_replacement in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            for name in ["state-a", "state-b"] {
                recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new(name))
                    .unwrap();
            }
            let state = root.path().join("state-a");
            let other = root.path().join("state-b");
            for (path, content) in [
                (&state, b"original".as_slice()),
                (&other, b"different".as_slice()),
            ] {
                let pending = PendingAttempt::begin(path, ID).unwrap();
                pending
                    .store_synthetic_files(&SyntheticFileSnapshot {
                        version: 1,
                        cargo_toml: Some(content.to_vec()),
                        cargo_lock: None,
                    })
                    .unwrap();
            }
            let target = tempfile::tempdir_in(root.path()).unwrap();
            let manifest = target.path().join("Cargo.toml");
            std::fs::write(&manifest, b"modified").unwrap();
            let result = recover_synthetic_attempt_with_hooks(
                &state,
                &target,
                b"modified",
                || {},
                |step| {
                    if step == "created" {
                        return Err(io::Error::other("injected failure"));
                    }
                    Ok(())
                },
            );
            assert!(result.is_err());
            assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
            let prior = std::fs::read(state.join("pending-fixture-rollback")).unwrap();
            let intent = std::fs::read(state.join("pending-intent")).unwrap();
            let replacement = if valid_replacement {
                std::fs::read(other.join("pending-snapshot")).unwrap()
            } else {
                b"corrupt".to_vec()
            };
            let result = resume_synthetic_attempt_with_hook(&state, &target, || {
                // Test-only simulated interference; both directories are disposable.
                std::fs::write(state.join("pending-snapshot"), &replacement).unwrap();
            });
            assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
            assert!(!state.join("pending-fixture-resume").exists());
            assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
            assert_eq!(
                std::fs::read(state.join("pending-snapshot")).unwrap(),
                replacement
            );
            assert_eq!(
                std::fs::read(state.join("pending-fixture-rollback")).unwrap(),
                prior
            );
            assert_eq!(std::fs::read(state.join("pending-intent")).unwrap(), intent);
            assert_eq!(
                inspect_recovery(&state).descendant_cleanup,
                RecoveryOutcome::Unknown
            );
            assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
            assert!(PendingAttempt::begin(&state, ID).is_err());
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_resume_refuses_target_changed_after_initial_check() {
        for unexpected_lock in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let pending = PendingAttempt::begin(&state, ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"original".to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
            let target = tempfile::tempdir_in(root.path()).unwrap();
            let manifest = target.path().join("Cargo.toml");
            std::fs::write(&manifest, b"modified").unwrap();
            let result = recover_synthetic_attempt_with_hooks(
                &state,
                &target,
                b"modified",
                || {},
                |step| {
                    if step == "created" {
                        return Err(io::Error::other("injected failure"));
                    }
                    Ok(())
                },
            );
            assert!(result.is_err());
            let snapshot = std::fs::read(state.join("pending-snapshot")).unwrap();
            let prior = std::fs::read(state.join("pending-fixture-rollback")).unwrap();
            let result = resume_synthetic_attempt_with_hook(&state, &target, || {
                if unexpected_lock {
                    std::fs::write(target.path().join("Cargo.lock"), b"unexpected").unwrap();
                } else {
                    std::fs::write(&manifest, b"conflict").unwrap();
                }
            });
            assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
            assert!(!state.join("pending-fixture-resume").exists());
            if unexpected_lock {
                assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
                assert_eq!(
                    std::fs::read(target.path().join("Cargo.lock")).unwrap(),
                    b"unexpected"
                );
            } else {
                assert_eq!(std::fs::read(&manifest).unwrap(), b"conflict");
            }
            assert_eq!(
                std::fs::read(state.join("pending-snapshot")).unwrap(),
                snapshot
            );
            assert_eq!(
                std::fs::read(state.join("pending-fixture-rollback")).unwrap(),
                prior
            );
            assert_eq!(
                inspect_recovery(&state).descendant_cleanup,
                RecoveryOutcome::Unknown
            );
            assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
            assert!(PendingAttempt::begin(&state, ID).is_err());
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_recovery_refuses_replaced_state_directory() {
        for resume in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let moved = root.path().join("old-state");
            let pending = PendingAttempt::begin(&state, ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"original".to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
            let target = tempfile::tempdir_in(root.path()).unwrap();
            let manifest = target.path().join("Cargo.toml");
            std::fs::write(&manifest, b"modified").unwrap();
            std::fs::write(root.path().join("protected"), b"unchanged").unwrap();
            if resume {
                let result = recover_synthetic_attempt_with_hooks(
                    &state,
                    &target,
                    b"modified",
                    || {},
                    |step| {
                        if step == "created" {
                            return Err(io::Error::other("injected failure"));
                        }
                        Ok(())
                    },
                );
                assert!(result.is_err());
                assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
            }
            let replace = || {
                std::fs::rename(&state, &moved).unwrap();
                recovery_state::provision_state_directory(
                    root.path(),
                    std::ffi::OsStr::new("state"),
                )
                .unwrap();
                let replacement = PendingAttempt::begin(&state, ID).unwrap();
                replacement
                    .store_synthetic_files(&SyntheticFileSnapshot {
                        version: 1,
                        cargo_toml: Some(b"original".to_vec()),
                        cargo_lock: None,
                    })
                    .unwrap();
            };
            if resume {
                assert!(resume_synthetic_attempt_with_hook(&state, &target, replace).is_err());
                assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
                assert!(!moved.join("pending-fixture-resume").exists());
            } else {
                assert!(
                    recover_synthetic_attempt_with_hook(&state, &target, b"modified", replace)
                        .is_err()
                );
                assert_eq!(std::fs::read(&manifest).unwrap(), b"modified");
                assert!(!moved.join("pending-fixture-rollback").exists());
            }
            assert!(!state.join("pending-fixture-resume").exists());
            assert!(!state.join("pending-fixture-rollback").exists());
            assert_eq!(
                std::fs::read(root.path().join("protected")).unwrap(),
                b"unchanged"
            );
            assert_eq!(
                inspect_recovery(&state).descendant_cleanup,
                RecoveryOutcome::Unknown
            );
            assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
            assert!(PendingAttempt::begin(&state, ID).is_err());
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_recovery_refuses_snapshot_corruption_after_copy() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let state = root.path().join("state");
        let pending = PendingAttempt::begin(&state, ID).unwrap();
        pending
            .store_synthetic_files(&SyntheticFileSnapshot {
                version: 1,
                cargo_toml: Some(b"snapshot A".to_vec()),
                cargo_lock: None,
            })
            .unwrap();
        let target = tempfile::tempdir_in(root.path()).unwrap();
        std::fs::write(target.path().join("Cargo.toml"), b"modified").unwrap();
        let protected = root.path().join("protected");
        std::fs::write(&protected, b"unchanged").unwrap();
        let path = state.join("pending-snapshot");
        let result = recover_synthetic_attempt_with_hook(&state, &target, b"modified", || {
            // Synthetic fault between phases; never modify a real record.
            std::fs::write(&path, b"corrupt fixture").unwrap();
        });
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
        assert_eq!(
            std::fs::read(target.path().join("Cargo.toml")).unwrap(),
            b"modified"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"corrupt fixture");
        assert!(!state.join("pending-fixture-rollback").exists());
        assert_eq!(std::fs::read(protected).unwrap(), b"unchanged");
        let inspection = inspect_recovery(&state);
        assert_eq!(
            inspection.snapshot,
            SnapshotObservation::UnavailableOrInvalid
        );
        assert_eq!(inspection.descendant_cleanup, RecoveryOutcome::Unknown);
        assert_eq!(inspection.rollback, RecoveryOutcome::Unknown);
        assert!(PendingAttempt::begin(&state, ID).is_err());
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_recovery_refuses_different_valid_snapshot_after_copy() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["state-a", "state-b"] {
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new(name))
                .unwrap();
        }
        let state = root.path().join("state-a");
        let other = root.path().join("state-b");
        for (path, contents) in [
            (&state, b"snapshot A".as_slice()),
            (&other, b"snapshot B".as_slice()),
        ] {
            let pending = PendingAttempt::begin(path, ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(contents.to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
        }
        let replacement = std::fs::read(other.join("pending-snapshot")).unwrap();
        let target = tempfile::tempdir_in(root.path()).unwrap();
        std::fs::write(target.path().join("Cargo.toml"), b"modified").unwrap();
        let result = recover_synthetic_attempt_with_hook(&state, &target, b"modified", || {
            // Synthetic fault only: same id and valid digest, different bytes.
            std::fs::write(state.join("pending-snapshot"), &replacement).unwrap();
        });
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
        assert_eq!(
            std::fs::read(target.path().join("Cargo.toml")).unwrap(),
            b"modified"
        );
        assert_eq!(
            std::fs::read(state.join("pending-snapshot")).unwrap(),
            replacement
        );
        assert_eq!(
            inspect_recovery(&state).snapshot,
            SnapshotObservation::ValidEnvelopeObserved
        );
        assert_eq!(
            inspect_recovery(&state).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
        assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
        assert!(!state.join("pending-fixture-rollback").exists());
        assert!(PendingAttempt::begin(&state, ID).is_err());
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn interrupted_supervised_synthetic_rollback_remains_pending() {
        const CHILD: &str = "TUCUPI_SUPERVISED_ROLLBACK_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let root = Path::new(&path);
            let point = std::env::var("TUCUPI_SUPERVISED_ROLLBACK_POINT").unwrap();
            let target = tempfile::tempdir_in(root).unwrap();
            std::fs::write(target.path().join("Cargo.toml"), b"modified").unwrap();
            std::fs::write(
                root.join("interrupted-target"),
                target.path().as_os_str().as_encoded_bytes(),
            )
            .unwrap();
            let _ = rollback_synthetic_manifest_with_hook(
                &root.join("state"),
                &target,
                b"modified",
                |step| {
                    if step == point {
                        std::process::exit(77);
                    }
                },
            );
            panic!("fixture interruption did not occur");
        }
        for point in ["prepared", "renamed"] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let pending = PendingAttempt::begin(&state, ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"original".to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
            let mut child = TestChild(
                Command::new("/bin/sh")
                    .args(["-c", "IFS= read -r line"])
                    .env_clear()
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            let mut observed = pending.bind_child(&mut child.0).unwrap();
            assert_eq!(observed.poll_and_record_exit().unwrap(), None);
            std::fs::write(root.path().join("protected"), b"unchanged").unwrap();
            let before = std::fs::read(state.join("pending-snapshot")).unwrap();
            let result = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "same_user_supervisor::tests::interrupted_supervised_synthetic_rollback_remains_pending"])
                .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, root.path())
                .env("TUCUPI_SUPERVISED_ROLLBACK_POINT", point)
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
            assert_eq!(result.code(), Some(77));
            let target = std::path::PathBuf::from(
                std::fs::read_to_string(root.path().join("interrupted-target")).unwrap(),
            );
            let expected: &[u8] = if point == "prepared" {
                b"modified"
            } else {
                b"original"
            };
            assert_eq!(std::fs::read(target.join("Cargo.toml")).unwrap(), expected);
            assert_eq!(
                std::fs::read(state.join("pending-snapshot")).unwrap(),
                before
            );
            assert_eq!(
                std::fs::read(root.path().join("protected")).unwrap(),
                b"unchanged"
            );
            assert_eq!(
                inspect_recovery(&state).descendant_cleanup,
                RecoveryOutcome::Unknown
            );
            assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
            assert!(!observed.permits_operation());
            assert!(PendingAttempt::begin(&state, ID).is_err());
            let retry = tempfile::tempdir_in(root.path()).unwrap();
            std::fs::write(retry.path().join("Cargo.toml"), b"modified").unwrap();
            rollback_synthetic_manifest(&state, &retry, b"modified").unwrap();
            assert_eq!(
                std::fs::read(retry.path().join("Cargo.toml")).unwrap(),
                b"original"
            );
        }
    }

    #[test]
    fn interrupted_synthetic_restore_is_not_treated_as_completed() {
        const CHILD: &str = "TUCUPI_RESTORE_INTERRUPT_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let root = Path::new(&path);
            let _ =
                restore_synthetic_snapshot_with_hook(&root.join("state"), root, |destination| {
                    std::fs::write(
                        root.join("partial-path"),
                        destination.as_os_str().as_encoded_bytes(),
                    )
                    .unwrap();
                    std::process::exit(77);
                });
            panic!("fixture interruption did not occur");
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let state = root.path().join("state");
        let pending = PendingAttempt::begin(&state, ID).unwrap();
        pending
            .store_synthetic_files(&SyntheticFileSnapshot {
                version: 1,
                cargo_toml: Some(b"manifest".to_vec()),
                cargo_lock: Some(b"lock".to_vec()),
            })
            .unwrap();
        let snapshot = std::fs::read(state.join("pending-snapshot")).unwrap();
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "same_user_supervisor::tests::interrupted_synthetic_restore_is_not_treated_as_completed"])
            .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, root.path())
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
        assert_eq!(result.code(), Some(77));
        let partial = std::path::PathBuf::from(
            std::fs::read_to_string(root.path().join("partial-path")).unwrap(),
        );
        assert_eq!(
            std::fs::read(partial.join("Cargo.toml")).unwrap(),
            b"manifest"
        );
        assert!(!partial.join("Cargo.lock").exists());
        let restored = restore_synthetic_snapshot(&state, root.path()).unwrap();
        assert_ne!(restored.path(), partial);
        assert_eq!(
            std::fs::read(restored.path().join("Cargo.toml")).unwrap(),
            b"manifest"
        );
        assert_eq!(
            std::fs::read(restored.path().join("Cargo.lock")).unwrap(),
            b"lock"
        );
        assert!(!partial.join("Cargo.lock").exists());
        assert_eq!(
            std::fs::read(state.join("pending-snapshot")).unwrap(),
            snapshot
        );
        assert_eq!(
            inspect_recovery(&state).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
        assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
        assert!(PendingAttempt::begin(&state, ID).is_err());
    }

    #[test]
    fn synthetic_restore_rejects_missing_file_metadata() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let state = root.path().join("state");
        let pending = PendingAttempt::begin(&state, ID).unwrap();
        pending
            .store_synthetic_snapshot(br#"{"version":1,"cargo_toml":null}"#)
            .unwrap();
        let count = std::fs::read_dir(root.path()).unwrap().count();
        assert_eq!(
            restore_synthetic_snapshot(&state, root.path())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), count);
        assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
    }

    #[test]
    fn synthetic_snapshot_survives_owner_exit_and_rejects_corruption() {
        const CHILD: &str = "TUCUPI_SNAPSHOT_OWNER_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let pending = PendingAttempt::begin(Path::new(&path), ID).unwrap();
            pending
                .store_synthetic_snapshot(b"synthetic backup\0data")
                .unwrap();
            assert_eq!(
                pending
                    .store_synthetic_snapshot(b"replacement")
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::AlreadyExists
            );
            let mut child = Command::new("/bin/sh")
                .args(["-c", "IFS= read -r line"])
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut observed = pending.bind_child(&mut child).unwrap();
            assert_eq!(observed.poll_and_record_exit().unwrap(), None);
            std::process::exit(77);
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let state = root.path().join("state");
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "same_user_supervisor::tests::synthetic_snapshot_survives_owner_exit_and_rejects_corruption"])
            .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, &state)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
        assert_eq!(status.code(), Some(77));
        let snapshot = state.join("pending-snapshot");
        let before = std::fs::read(&snapshot).unwrap();
        assert_eq!(
            read_pending_snapshot(&state).unwrap(),
            b"synthetic backup\0data"
        );
        assert_eq!(std::fs::read(&snapshot).unwrap(), before);
        assert_eq!(
            inspect_recovery(&state).snapshot,
            SnapshotObservation::ValidEnvelopeObserved
        );
        assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
        assert_eq!(
            inspect_recovery(&state).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
        assert!(PendingAttempt::begin(&state, ID).is_err());
        let mut corrupt = before;
        *corrupt.last_mut().unwrap() ^= 1;
        std::fs::write(&snapshot, corrupt).unwrap();
        assert_eq!(
            read_pending_snapshot(&state).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            inspect_recovery(&state).snapshot,
            SnapshotObservation::UnavailableOrInvalid
        );
        assert_eq!(inspect_recovery(&state).rollback, RecoveryOutcome::Unknown);
        assert_eq!(
            inspect_recovery(&state).descendant_cleanup,
            RecoveryOutcome::Unknown
        );
        assert!(PendingAttempt::begin(&state, ID).is_err());
    }

    #[test]
    fn failed_exit_publication_is_terminal_even_if_obstruction_disappears() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let state = root.path().join("state");
        let pending = PendingAttempt::begin(&state, ID).unwrap();
        let mut child = TestChild(
            Command::new("/bin/sh")
                .args(["-c", "IFS= read -r line"])
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let mut input = child.0.stdin.take().unwrap();
        let mut observed = pending.bind_child(&mut child.0).unwrap();
        let exit_path = state.join("pending-exit");
        std::fs::write(&exit_path, b"partial fixture record").unwrap();
        input.write_all(b"exit\n").unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match observed.poll_and_record_exit() {
                Err(_) => break,
                Ok(None) => {
                    assert!(Instant::now() < deadline, "synthetic child did not exit");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(Some(_)) => panic!("publication must fail"),
            }
        }
        assert_eq!(
            std::fs::read(&exit_path).unwrap(),
            b"partial fixture record"
        );
        std::fs::remove_file(&exit_path).unwrap(); // Only this test's synthetic obstruction.
        assert!(observed.poll_and_record_exit().is_err());
        assert!(!exit_path.exists());
        assert!(!observed.permits_operation());
        assert!(PendingAttempt::begin(&state, ID).is_err());
        assert_eq!(
            recovery_state::local_recovery_evidence_at(&state),
            recovery_state::LocalRecoveryEvidence::PendingChildLocatorObserved
        );
    }

    #[test]
    fn binding_reaped_child_fails_without_consuming_caller_or_clearing_intent() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let path = root.path().join("state");
        let pending = PendingAttempt::begin(&path, ID).unwrap();
        let mut child = TestChild(
            Command::new("/bin/sh")
                .args(["-c", "exit 0"])
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        assert!(child.0.wait().unwrap().success());
        assert!(pending.bind_child(&mut child.0).is_err());
        assert!(child.0.try_wait().unwrap().is_some());
        assert_eq!(
            recovery_state::local_recovery_evidence_at(&path),
            recovery_state::LocalRecoveryEvidence::PendingIntentObserved
        );
        assert!(!path.join("pending-child").exists());
        assert!(PendingAttempt::begin(&path, ID).is_err());
    }

    #[test]
    fn direct_child_exit_is_recorded_but_never_authorizes() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let path = root.path().join("state");
        let pending = PendingAttempt::begin(&path, ID).unwrap();
        assert_eq!(
            recovery_state::local_recovery_evidence_at(&path),
            recovery_state::LocalRecoveryEvidence::PendingIntentObserved
        );
        let mut child = TestChild(
            Command::new("/bin/sh")
                .args(["-c", "IFS= read -r line"])
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let mut stdin = child.0.stdin.take().unwrap();
        {
            let mut observation = pending.bind_child(&mut child.0).unwrap();
            assert_eq!(observation.poll_and_record_exit().unwrap(), None);
            assert!(!observation.permits_operation());
            assert_eq!(
                recovery_state::local_recovery_evidence_at(&path),
                recovery_state::LocalRecoveryEvidence::PendingChildLocatorObserved
            );
            stdin.write_all(b"exit\n").unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                if let Some(success) = observation.poll_and_record_exit().unwrap() {
                    assert!(success);
                    assert_eq!(observation.poll_and_record_exit().unwrap(), Some(true));
                    break;
                }
                assert!(Instant::now() < deadline, "synthetic child did not exit");
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(!observation.permits_operation());
        }
        assert_eq!(
            recovery_state::local_recovery_evidence_at(&path),
            recovery_state::LocalRecoveryEvidence::PendingDirectExitRecorded
        );
        assert_eq!(
            inspect_recovery(&path).direct_exit,
            DirectExitObservation::SuccessRecorded
        );
        assert!(PendingAttempt::begin(&path, ID).is_err());
    }

    #[test]
    fn inspection_distinguishes_failed_direct_exit_from_invalid_record() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let path = root.path().join("state");
        let pending = PendingAttempt::begin(&path, ID).unwrap();
        let mut child = TestChild(
            Command::new("/bin/sh")
                .args(["-c", "IFS= read -r line; exit 7"])
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let mut stdin = child.0.stdin.take().unwrap();
        let mut observed = pending.bind_child(&mut child.0).unwrap();
        assert_eq!(
            inspect_recovery(&path).direct_exit,
            DirectExitObservation::NotRecorded
        );
        stdin.write_all(b"go\n").unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(success) = observed.poll_and_record_exit().unwrap() {
                assert!(!success);
                break;
            }
            assert!(Instant::now() < deadline, "synthetic child did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
        let record = path.join("pending-exit");
        let before = std::fs::read(&record).unwrap();
        let inspection = inspect_recovery(&path);
        assert_eq!(
            inspection.direct_exit,
            DirectExitObservation::FailureRecorded
        );
        assert_eq!(inspection.descendant_cleanup, RecoveryOutcome::Unknown);
        assert_eq!(inspection.rollback, RecoveryOutcome::Unknown);
        assert_eq!(std::fs::read(&record).unwrap(), before);
        std::fs::write(&record, b"partial").unwrap();
        let inspection = inspect_recovery(&path);
        assert_eq!(
            inspection.direct_exit,
            DirectExitObservation::UnavailableOrInvalid
        );
        assert_eq!(
            inspection.local_evidence,
            recovery_state::LocalRecoveryEvidence::RecordsInconsistent
        );
        assert_eq!(inspection.descendant_cleanup, RecoveryOutcome::Unknown);
        assert_eq!(inspection.rollback, RecoveryOutcome::Unknown);
        assert!(!observed.permits_operation());
        assert!(PendingAttempt::begin(&path, ID).is_err());
    }

    #[test]
    fn direct_exit_rejects_replaced_state_directory_before_and_after_publication() {
        for after_publication in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let moved = root.path().join("moved");
            let pending = PendingAttempt::begin(&state, ID).unwrap();
            let mut child = TestChild(
                Command::new("/bin/sh")
                    .args(["-c", "IFS= read -r line; exit 0"])
                    .env_clear()
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            let mut input = child.0.stdin.take().unwrap();
            let mut observed = pending.bind_child(&mut child.0).unwrap();
            let intent = std::fs::read(state.join("pending-intent")).unwrap();
            let locator = std::fs::read(state.join("pending-child")).unwrap();
            if !after_publication {
                std::fs::rename(&state, &moved).unwrap();
                recovery_state::provision_state_directory(
                    root.path(),
                    std::ffi::OsStr::new("state"),
                )
                .unwrap();
            }
            input.write_all(b"go\n").unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let result = observed.poll_and_record_exit_with_hook(|| {
                    if after_publication {
                        std::fs::rename(&state, &moved).unwrap();
                        recovery_state::provision_state_directory(
                            root.path(),
                            std::ffi::OsStr::new("state"),
                        )
                        .unwrap();
                    }
                });
                match result {
                    Ok(None) => {
                        assert!(Instant::now() < deadline, "fixture child did not exit");
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                    Ok(Some(_)) => {
                        panic!("replaced state must not produce a successful publication")
                    }
                }
            }
            assert!(observed.poll_and_record_exit().is_err());
            assert!(!observed.permits_operation());
            assert_eq!(std::fs::read(moved.join("pending-intent")).unwrap(), intent);
            assert_eq!(std::fs::read(moved.join("pending-child")).unwrap(), locator);
            assert_eq!(moved.join("pending-exit").exists(), after_publication);
            assert!(!state.join("pending-exit").exists());
            assert!(!state.join("pending-intent").exists());
            let inspection = inspect_recovery(&moved);
            assert_eq!(inspection.descendant_cleanup, RecoveryOutcome::Unknown);
            assert_eq!(inspection.rollback, RecoveryOutcome::Unknown);
            assert!(PendingAttempt::begin(&moved, ID).is_err());
        }
    }

    #[test]
    fn child_binding_rejects_replaced_state_before_and_after_locator() {
        for after_locator in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let moved = root.path().join("moved");
            let pending = PendingAttempt::begin(&state, ID).unwrap();
            let intent = std::fs::read(state.join("pending-intent")).unwrap();
            let mut child = TestChild(
                Command::new("/bin/sh")
                    .args(["-c", "IFS= read -r line; exit 0"])
                    .env_clear()
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            if !after_locator {
                std::fs::rename(&state, &moved).unwrap();
                recovery_state::provision_state_directory(
                    root.path(),
                    std::ffi::OsStr::new("state"),
                )
                .unwrap();
            }
            let result = pending.bind_child_with_hook(&mut child.0, || {
                if after_locator {
                    std::fs::rename(&state, &moved).unwrap();
                    recovery_state::provision_state_directory(
                        root.path(),
                        std::ffi::OsStr::new("state"),
                    )
                    .unwrap();
                }
            });
            assert!(result.is_err());
            drop(result);
            assert!(child.0.try_wait().unwrap().is_none());
            child.0.stdin.take().unwrap().write_all(b"go\n").unwrap();
            assert!(child.0.wait().unwrap().success());
            assert_eq!(std::fs::read(moved.join("pending-intent")).unwrap(), intent);
            assert_eq!(moved.join("pending-child").exists(), after_locator);
            assert!(!moved.join("pending-exit").exists());
            assert!(!state.join("pending-intent").exists());
            assert!(!state.join("pending-child").exists());
            let inspection = inspect_recovery(&moved);
            assert_eq!(inspection.descendant_cleanup, RecoveryOutcome::Unknown);
            assert_eq!(inspection.rollback, RecoveryOutcome::Unknown);
            assert!(PendingAttempt::begin(&moved, ID).is_err());
        }
    }

    #[test]
    fn synthetic_snapshot_rejects_replaced_state_before_and_after_write() {
        for after_write in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let moved = root.path().join("moved");
            let pending = PendingAttempt::begin(&state, ID).unwrap();
            let intent = std::fs::read(state.join("pending-intent")).unwrap();
            if !after_write {
                std::fs::rename(&state, &moved).unwrap();
                recovery_state::provision_state_directory(
                    root.path(),
                    std::ffi::OsStr::new("state"),
                )
                .unwrap();
            }
            let result = pending.store_synthetic_snapshot_with_hook(b"synthetic", || {
                if after_write {
                    std::fs::rename(&state, &moved).unwrap();
                    recovery_state::provision_state_directory(
                        root.path(),
                        std::ffi::OsStr::new("state"),
                    )
                    .unwrap();
                }
            });
            assert!(result.is_err());
            assert_eq!(std::fs::read(moved.join("pending-intent")).unwrap(), intent);
            assert_eq!(moved.join("pending-snapshot").exists(), after_write);
            assert!(!state.join("pending-intent").exists());
            assert!(!state.join("pending-snapshot").exists());
            assert!(pending.store_synthetic_snapshot(b"retry").is_err());
            assert!(PendingAttempt::begin(&moved, ID).is_err());
            let inspection = inspect_recovery(&moved);
            assert_eq!(inspection.descendant_cleanup, RecoveryOutcome::Unknown);
            assert_eq!(inspection.rollback, RecoveryOutcome::Unknown);
        }
    }

    #[test]
    fn pending_intent_rejects_replaced_state_before_and_after_write() {
        for phase in ["path-observed", "intent-written"] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let moved = root.path().join("moved");
            let directory = recovery_state::open_provisioned_state_directory(&state).unwrap();
            let result = PendingAttempt::begin_in_with_hook(directory, &state, ID, |step| {
                if step == phase {
                    std::fs::rename(&state, &moved).unwrap();
                    recovery_state::provision_state_directory(
                        root.path(),
                        std::ffi::OsStr::new("state"),
                    )
                    .unwrap();
                }
            });
            assert!(result.is_err());
            assert_eq!(
                moved.join("pending-intent").exists(),
                phase == "intent-written"
            );
            assert!(!state.join("pending-intent").exists());
            assert!(!moved.join("pending-child").exists());
            assert!(!state.join("pending-child").exists());
            if phase == "intent-written" {
                let before = std::fs::read(moved.join("pending-intent")).unwrap();
                assert!(PendingAttempt::begin(&moved, ID).is_err());
                assert_eq!(std::fs::read(moved.join("pending-intent")).unwrap(), before);
            }
            let inspection = inspect_recovery(&moved);
            assert_eq!(inspection.descendant_cleanup, RecoveryOutcome::Unknown);
            assert_eq!(inspection.rollback, RecoveryOutcome::Unknown);
        }
    }

    #[test]
    fn pending_intent_preserves_requested_path_across_open() {
        for replace in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let moved = root.path().join("moved");
            let result = PendingAttempt::begin_with_open_hook(&state, ID, || {
                std::fs::rename(&state, &moved).unwrap();
                if replace {
                    recovery_state::provision_state_directory(
                        root.path(),
                        std::ffi::OsStr::new("state"),
                    )
                    .unwrap();
                }
            });
            assert!(result.is_err());
            assert!(!moved.join("pending-intent").exists());
            assert!(!moved.join("pending-child").exists());
            if replace {
                assert!(!state.join("pending-intent").exists());
                assert!(!state.join("pending-child").exists());
            }
            let inspection = inspect_recovery(&moved);
            assert_eq!(inspection.descendant_cleanup, RecoveryOutcome::Unknown);
            assert_eq!(inspection.rollback, RecoveryOutcome::Unknown);
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_postimage_writers_reject_replaced_state() {
        for mode in 0..3 {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let state = root.path().join("state");
            let moved = root.path().join("moved");
            let pending = PendingAttempt::begin(&state, ID).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"original".to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
            let snapshot = std::fs::read(state.join("pending-snapshot")).unwrap();
            std::fs::rename(&state, &moved).unwrap();
            recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap();
            let result = match mode {
                0 => pending.store_synthetic_postimage(b"modified"),
                1 => pending.store_synthetic_absent_postimage(),
                _ => pending.store_synthetic_two_file_postimage(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"modified".to_vec()),
                    cargo_lock: None,
                }),
            };
            assert!(result.is_err());
            assert_eq!(
                std::fs::read(moved.join("pending-snapshot")).unwrap(),
                snapshot
            );
            assert!(!moved.join("pending-fixture-postimage").exists());
            assert!(!state.join("pending-fixture-postimage").exists());
            assert!(PendingAttempt::begin(&moved, ID).is_err());
        }
    }

    #[test]
    fn interrupted_owner_leaves_pending_child_and_refuses_duplicate() {
        const CHILD: &str = "TUCUPI_SAME_USER_SUPERVISOR_TEST";
        if let Some(path) = std::env::var_os(CHILD) {
            let pending = PendingAttempt::begin(Path::new(&path), ID).unwrap();
            let mut child = Command::new("/bin/sh")
                .args(["-c", "IFS= read -r line"])
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut observed = pending.bind_child(&mut child).unwrap();
            assert_eq!(observed.poll_and_record_exit().unwrap(), None);
            // The synthetic child sees EOF when this process exits.
            std::process::exit(77);
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let path = root.path().join("state");
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "same_user_supervisor::tests::interrupted_owner_leaves_pending_child_and_refuses_duplicate"])
            .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, &path)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
        assert_eq!(status.code(), Some(77));
        let intent = std::fs::read(path.join("pending-intent")).unwrap();
        let locator = std::fs::read(path.join("pending-child")).unwrap();
        let inspection = inspect_recovery(&path);
        assert_eq!(
            inspection.local_evidence,
            recovery_state::LocalRecoveryEvidence::PendingChildLocatorObserved
        );
        assert_eq!(inspection.descendant_cleanup, RecoveryOutcome::Unknown);
        assert_eq!(inspection.rollback, RecoveryOutcome::Unknown);
        assert_eq!(std::fs::read(path.join("pending-intent")).unwrap(), intent);
        assert_eq!(std::fs::read(path.join("pending-child")).unwrap(), locator);
        assert_eq!(
            recovery_state::local_recovery_evidence_at(&path),
            recovery_state::LocalRecoveryEvidence::PendingChildLocatorObserved
        );
        assert!(PendingAttempt::begin(&path, ID).is_err());
        assert!(!path.join("pending-exit").exists());
    }

    #[test]
    fn inspection_never_marks_missing_or_corrupt_state_clean() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.path().join("state");
        let inspection = inspect_recovery(&state);
        assert_eq!(
            inspection.local_evidence,
            recovery_state::LocalRecoveryEvidence::StateUnavailable
        );
        assert_eq!(
            inspection.snapshot,
            SnapshotObservation::UnavailableOrInvalid
        );
        assert_eq!(inspection.descendant_cleanup, RecoveryOutcome::Unknown);
        assert_eq!(inspection.rollback, RecoveryOutcome::Unknown);
        recovery_state::provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
            .unwrap();
        let _pending = PendingAttempt::begin(&state, ID).unwrap();
        std::fs::write(state.join("pending-intent"), b"partial").unwrap();
        let inspection = inspect_recovery(&state);
        assert_eq!(
            inspection.local_evidence,
            recovery_state::LocalRecoveryEvidence::AttemptUnavailableOrInvalid
        );
        assert_eq!(inspection.descendant_cleanup, RecoveryOutcome::Unknown);
        assert_eq!(inspection.rollback, RecoveryOutcome::Unknown);
        assert_eq!(
            std::fs::read(state.join("pending-intent")).unwrap(),
            b"partial"
        );
        assert!(PendingAttempt::begin(&state, ID).is_err());
    }
}
