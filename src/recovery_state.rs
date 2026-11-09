//! Linux recovery-state building blocks. These do not authorize a review,
//! recover a unit, or provide a trusted persistent anchor by themselves.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

/// Persisted identifiers are inputs to observation, not proof of ownership.
#[derive(Debug, PartialEq, Eq)]
pub struct AttemptIdentity {
    pub attempt: String,
    pub unit: String,
    pub invocation: String,
    pub boot: String,
    pub manager_epoch: String,
}

fn valid_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl AttemptIdentity {
    /// Strict, bounded record format. It cannot establish provenance.
    pub fn parse(content: &str) -> io::Result<Self> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid recovery attempt record",
            )
        };
        if content.len() > 512 || !content.ends_with('\n') {
            return Err(invalid());
        }
        let mut lines = content.lines();
        if lines.next() != Some("tucupi-recovery-attempt-v1") {
            return Err(invalid());
        }
        let attempt = lines
            .next()
            .and_then(|line| line.strip_prefix("attempt="))
            .ok_or_else(invalid)?;
        let unit = lines
            .next()
            .and_then(|line| line.strip_prefix("unit="))
            .ok_or_else(invalid)?;
        let invocation = lines
            .next()
            .and_then(|line| line.strip_prefix("invocation="))
            .ok_or_else(invalid)?;
        let boot = lines
            .next()
            .and_then(|line| line.strip_prefix("boot="))
            .ok_or_else(invalid)?;
        let manager_epoch = lines
            .next()
            .and_then(|line| line.strip_prefix("manager_epoch="))
            .ok_or_else(invalid)?;
        if lines.next().is_some()
            || !valid_id(attempt)
            || !valid_id(invocation)
            || !valid_id(boot)
            || !valid_id(manager_epoch)
            || unit != format!("tucupi-review-{attempt}.service")
        {
            return Err(invalid());
        }
        Ok(Self {
            attempt: attempt.into(),
            unit: unit.into(),
            invocation: invocation.into(),
            boot: boot.into(),
            manager_epoch: manager_epoch.into(),
        })
    }
}

/// Open a record without following a final symlink. Any read/validation error
/// must remain blocked; this function never mutates or clears the record.
pub fn read_attempt_identity(directory: &File) -> io::Result<AttemptIdentity> {
    let path = format!("/proc/self/fd/{}/pending-attempt", directory.as_raw_fd());
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no arguments and does not mutate program state.
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untrusted recovery attempt record",
        ));
    }
    let mut content = String::new();
    file.take(513).read_to_string(&mut content)?;
    AttemptIdentity::parse(&content)
}

#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryObservation {
    StateUnavailable,
    RecordUnavailable,
    RecordChanged,
    ManagerUnavailable,
    ManagerChanged,
    UnitMissing,
    UnitIdentityMismatch,
    UnitStillActive,
    GroupPopulated,
    GroupUnknown,
    EmptyObservedButUnverified,
    ManagerEpochUnknown,
}

/// Diagnostic only: no variant authorizes an update or deletion. Even a
/// matching unit cannot authenticate the manager epoch or establish cleanup.
pub async fn inspect_persisted_attempt(path: &Path, runtime: &Path) -> RecoveryObservation {
    let directory = match open_provisioned_state_directory(path) {
        Ok(directory) => directory,
        Err(_) => return RecoveryObservation::StateUnavailable,
    };
    let identity = match read_attempt_identity(&directory) {
        Ok(identity) => identity,
        Err(_) => return RecoveryObservation::RecordUnavailable,
    };
    let observation =
        match crate::manager_observation::observe_same_connection(&identity.unit, runtime).await {
            Ok(observation) => observation,
            Err(_) => return RecoveryObservation::ManagerUnavailable,
        };
    match read_attempt_identity(&directory) {
        Ok(again) if again == identity => {}
        _ => return RecoveryObservation::RecordChanged,
    }
    if observation.unit != identity.unit || observation.invocation != identity.invocation {
        return RecoveryObservation::UnitIdentityMismatch;
    }
    RecoveryObservation::ManagerEpochUnknown
}

pub async fn inspect_configured_codex(
    config: &crate::config::Config,
) -> Option<RecoveryObservation> {
    if config.review_provider() != "codex" || !config.review_llm() {
        return None;
    }
    let path = match default_state_path() {
        Ok(path) => path,
        Err(_) => return Some(RecoveryObservation::StateUnavailable),
    };
    // SAFETY: geteuid is read-only and has no arguments.
    let runtime = std::path::PathBuf::from(format!("/run/user/{}", unsafe { libc::geteuid() }));
    Some(inspect_persisted_attempt(&path, &runtime).await)
}

/// Caller-supplied observations must come from an independently validated
/// manager and cgroup. This classifier never authorizes clearing a record.
pub struct ManagerSnapshot<'a> {
    pub boot: &'a str,
    pub manager_epoch: &'a str,
    pub unit: &'a str,
    pub invocation: &'a str,
    pub active_state: &'a str,
    pub populated: Option<bool>,
}

pub fn classify_recovery(
    identity: &AttemptIdentity,
    manager: io::Result<Option<ManagerSnapshot<'_>>>,
) -> RecoveryObservation {
    let snapshot = match manager {
        Err(_) => return RecoveryObservation::ManagerUnavailable,
        Ok(None) => return RecoveryObservation::UnitMissing,
        Ok(Some(snapshot)) => snapshot,
    };
    if snapshot.boot != identity.boot || snapshot.manager_epoch != identity.manager_epoch {
        return RecoveryObservation::ManagerChanged;
    }
    if snapshot.unit != identity.unit || snapshot.invocation != identity.invocation {
        return RecoveryObservation::UnitIdentityMismatch;
    }
    if !matches!(snapshot.active_state, "inactive" | "failed") {
        return RecoveryObservation::UnitStillActive;
    }
    match snapshot.populated {
        Some(true) => RecoveryObservation::GroupPopulated,
        None => RecoveryObservation::GroupUnknown,
        Some(false) => RecoveryObservation::EmptyObservedButUnverified,
    }
}

/// The production Codex path remains unavailable: a valid format marker is
/// not proof that a previous attempt or the manager has been reconciled.
/// Other providers retain their existing availability policy.
pub fn codex_recovery_preflight(config: &crate::config::Config) -> io::Result<()> {
    if config.review_provider() != "codex" || !config.review_llm() {
        return Ok(());
    }
    let path = default_state_path()?;
    codex_recovery_preflight_at(&path)
}

pub(crate) fn default_state_path() -> io::Result<std::path::PathBuf> {
    let base = match std::env::var_os("XDG_STATE_HOME") {
        Some(value) if !value.is_empty() => std::path::PathBuf::from(value),
        _ => std::path::PathBuf::from(
            std::env::var_os("HOME")
                .ok_or_else(|| io::Error::other("recovery state unavailable"))?,
        )
        .join(".local")
        .join("state"),
    };
    if !base.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "recovery state unavailable",
        ));
    }
    Ok(base.join("tucupi").join("recovery"))
}

/// Explicitly initialize the local recovery directory. This never clears or
/// replaces existing recovery state and does not establish a clean attempt.
/// The XDG state base must already exist, belong to the current user and not
/// be group/world writable. An error may leave a new empty parent directory.
pub fn provision_default_recovery() -> io::Result<()> {
    let target = default_state_path()?;
    let base = target.parent().and_then(Path::parent).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "invalid recovery state path")
    })?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(base)?;
    let metadata = directory.metadata()?;
    // SAFETY: geteuid only reads the effective UID.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid state base directory",
        ));
    }
    // SAFETY: directory is live and the fixed name is NUL-terminated.
    let result = unsafe { libc::mkdirat(directory.as_raw_fd(), c"tucupi".as_ptr(), 0o700) };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error);
        }
    } else {
        directory.sync_all()?;
    }
    let parent =
        std::path::PathBuf::from(format!("/proc/self/fd/{}/tucupi", directory.as_raw_fd()));
    provision_state_directory(&parent, std::ffi::OsStr::new("recovery"))
}

/// Read-only local evidence, not a clean-state or process-cleanup decision.
#[derive(Debug, PartialEq, Eq)]
pub enum LocalRecoveryEvidence {
    StateUnavailable,
    AttemptUnavailableOrInvalid,
    PendingAttemptObserved,
    PendingIntentObserved,
    PendingChildLocatorObserved,
    PendingDirectExitRecorded,
    RecordsInconsistent,
}

pub fn local_recovery_evidence() -> LocalRecoveryEvidence {
    match default_state_path() {
        Ok(path) => local_recovery_evidence_at(&path),
        Err(_) => LocalRecoveryEvidence::StateUnavailable,
    }
}

pub(crate) fn local_recovery_evidence_at(path: &Path) -> LocalRecoveryEvidence {
    local_recovery_with_exit_at(path).0
}

/// A status is returned only when the exit record agrees with local binding
/// and intent. The advisory guard coordinates participating writers only;
/// these reads are not an authenticated snapshot.
pub(crate) fn local_recovery_with_exit_at(path: &Path) -> (LocalRecoveryEvidence, Option<bool>) {
    let Ok(directory) = open_provisioned_state_directory(path) else {
        return (LocalRecoveryEvidence::StateUnavailable, None);
    };
    let Ok(_guard) = RecoveryWriteGuard::acquire(&directory) else {
        return (LocalRecoveryEvidence::StateUnavailable, None);
    };
    let base = local_binding_evidence(&directory);
    match read_direct_exit(&directory) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => (base, None),
        Ok((attempt, success))
            if matches!(
                base,
                LocalRecoveryEvidence::PendingAttemptObserved
                    | LocalRecoveryEvidence::PendingChildLocatorObserved
            ) && read_pending_intent(&directory).is_ok_and(|intent| intent == attempt) =>
        {
            (
                LocalRecoveryEvidence::PendingDirectExitRecorded,
                Some(success),
            )
        }
        _ => (LocalRecoveryEvidence::RecordsInconsistent, None),
    }
}

fn local_binding_evidence(directory: &File) -> LocalRecoveryEvidence {
    let child = read_child_locator(directory);
    if let Ok((ref child_attempt, _)) = child {
        return match (
            read_pending_intent(directory),
            read_attempt_identity(directory),
        ) {
            (Ok(intent), Err(error))
                if intent == *child_attempt && error.kind() == io::ErrorKind::NotFound =>
            {
                LocalRecoveryEvidence::PendingChildLocatorObserved
            }
            _ => LocalRecoveryEvidence::RecordsInconsistent,
        };
    } else if child.as_ref().unwrap_err().kind() != io::ErrorKind::NotFound {
        return LocalRecoveryEvidence::RecordsInconsistent;
    }
    match (
        read_pending_intent(directory),
        read_attempt_identity(directory),
    ) {
        (Ok(intent), Ok(binding)) if intent == binding.attempt => {
            LocalRecoveryEvidence::PendingAttemptObserved
        }
        (Ok(_), Ok(_)) => LocalRecoveryEvidence::RecordsInconsistent,
        (Ok(_), Err(error)) if error.kind() == io::ErrorKind::NotFound => {
            LocalRecoveryEvidence::PendingIntentObserved
        }
        (Ok(_), Err(_)) => LocalRecoveryEvidence::RecordsInconsistent,
        (Err(error), Ok(_)) if error.kind() == io::ErrorKind::NotFound => {
            LocalRecoveryEvidence::PendingAttemptObserved
        }
        (Err(_), Ok(_)) => LocalRecoveryEvidence::RecordsInconsistent,
        (Err(_), Err(_)) => LocalRecoveryEvidence::AttemptUnavailableOrInvalid,
    }
}

/// Direct-child wait result; not descendant cleanup or rollback.
/// Errors can leave a partial record, which remains blocked and is not deleted.
pub(crate) fn persist_direct_exit(
    directory: &File,
    attempt: &str,
    success: bool,
) -> io::Result<()> {
    persist_direct_exit_with_hook(directory, attempt, success, |_| Ok(()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExitWriteStep {
    Created,
    Written,
}

fn persist_direct_exit_with_hook(
    directory: &File,
    attempt: &str,
    success: bool,
    mut hook: impl FnMut(ExitWriteStep) -> io::Result<()>,
) -> io::Result<()> {
    let _guard = RecoveryWriteGuard::acquire(directory)?;
    if read_pending_intent(directory)? != attempt || !valid_id(attempt) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "recovery intent mismatch",
        ));
    }
    let binding_digest = direct_exit_evidence_digest(directory, attempt, success)?;
    let path = format!("/proc/self/fd/{}/pending-exit", directory.as_raw_fd());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    hook(ExitWriteStep::Created)?;
    writeln!(
        file,
        "tucupi-recovery-exit-v3\nattempt={attempt}\nsuccess={}\nbinding={binding_digest}",
        u8::from(success)
    )?;
    hook(ExitWriteStep::Written)?;
    file.sync_all()?;
    directory.sync_all()?;
    Ok(())
}

// The digest links records but cannot authenticate them or authorize use of a PID.
fn direct_exit_evidence_digest(
    directory: &File,
    attempt: &str,
    success: bool,
) -> io::Result<String> {
    use sha2::{Digest, Sha256};
    let canonical = match (
        read_attempt_identity(directory),
        read_child_locator(directory),
    ) {
        (Ok(binding), Err(error))
            if error.kind() == io::ErrorKind::NotFound && binding.attempt == attempt =>
        {
            format!(
                "unit\n{}\n{}\n{}\n{}\n{}\n",
                binding.attempt,
                binding.unit,
                binding.invocation,
                binding.boot,
                binding.manager_epoch
            )
        }
        (Err(error), Ok((child_attempt, pid)))
            if error.kind() == io::ErrorKind::NotFound && child_attempt == attempt =>
        {
            format!("child\n{child_attempt}\n{pid}\n")
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "recovery binding unavailable",
            ))
        }
    };
    let mut hash = Sha256::new();
    hash.update(b"tucupi-recovery-exit-v3\n");
    hash.update(attempt.as_bytes());
    hash.update([u8::from(success)]);
    hash.update(canonical.as_bytes());
    Ok(format!("{:x}", hash.finalize()))
}

fn read_direct_exit(directory: &File) -> io::Result<(String, bool)> {
    let path = format!("/proc/self/fd/{}/pending-exit", directory.as_raw_fd());
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid is a read-only process query.
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid direct exit record",
        ));
    }
    let mut content = String::new();
    file.take(257).read_to_string(&mut content)?;
    let mut lines = content.lines();
    let header = lines.next();
    let attempt = lines.next().and_then(|line| line.strip_prefix("attempt="));
    let success = match lines.next() {
        Some("success=1") => Some(true),
        Some("success=0") => Some(false),
        _ => None,
    };
    let binding = lines.next().and_then(|line| line.strip_prefix("binding="));
    if content.len() > 256
        || !content.ends_with('\n')
        || header != Some("tucupi-recovery-exit-v3")
        || !attempt.is_some_and(valid_id)
        || success.is_none()
        || !binding.is_some_and(|digest| {
            attempt
                .zip(success)
                .and_then(|(id, result)| direct_exit_evidence_digest(directory, id, result).ok())
                .as_deref()
                == Some(digest)
        })
        || lines.next().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid direct exit record",
        ));
    }
    Ok((attempt.unwrap().to_owned(), success.unwrap()))
}

/// Persist a direct-child locator for local recovery evidence. This is not
/// process identity, does not prove ownership or isolation, and must never be
/// used to adopt or signal a process after restart. Unresolved/partial state
/// stays blocked. Callers must serialize their entire supervision lifecycle.
pub(crate) fn persist_child_locator(directory: &File, attempt: &str, pid: u32) -> io::Result<()> {
    if !valid_id(attempt) || pid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid child locator",
        ));
    }
    let _guard = RecoveryWriteGuard::acquire(directory)?;
    require_record_absent(directory, "pending-exit")?;
    if read_pending_intent(directory)? != attempt {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "recovery intent mismatch",
        ));
    }
    let unit_path = format!("/proc/self/fd/{}/pending-attempt", directory.as_raw_fd());
    match std::fs::symlink_metadata(unit_path) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "unit binding exists",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let path = format!("/proc/self/fd/{}/pending-child", directory.as_raw_fd());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    write!(
        file,
        "tucupi-recovery-child-v1\nattempt={attempt}\npid={pid}\n"
    )?;
    file.sync_all()?;
    directory.sync_all()?;
    Ok(())
}

fn read_child_locator(directory: &File) -> io::Result<(String, u32)> {
    let path = format!("/proc/self/fd/{}/pending-child", directory.as_raw_fd());
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid is a read-only process query.
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid child locator",
        ));
    }
    let mut content = String::new();
    file.take(129).read_to_string(&mut content)?;
    let mut lines = content.lines();
    let header = lines.next();
    let attempt = lines.next().and_then(|line| line.strip_prefix("attempt="));
    let pid = lines
        .next()
        .and_then(|line| line.strip_prefix("pid="))
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0);
    if content.len() > 128
        || !content.ends_with('\n')
        || header != Some("tucupi-recovery-child-v1")
        || !attempt.is_some_and(valid_id)
        || pid.is_none()
        || lines.next().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid child locator",
        ));
    }
    Ok((attempt.unwrap().to_owned(), pid.unwrap()))
}

/// Create-only local intent before starting an attempt. This building block is
/// not wired to execution: the caller must own admission and serialize all
/// attempt operations. Failures can leave a partial file; never delete or
/// replace it to retry. Same-UID processes can alter it, and fsync is not proof
/// against storage rollback or power-loss on every filesystem.
pub fn persist_pending_intent(directory: &File, attempt: &str) -> io::Result<()> {
    if !valid_id(attempt) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid recovery attempt id",
        ));
    }
    let meta = directory.metadata()?;
    // SAFETY: geteuid is a read-only process query.
    if !meta.is_dir()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.nlink() == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid recovery directory",
        ));
    }
    let _guard = RecoveryWriteGuard::acquire(directory)?;
    // A previous binding, even malformed or a dangling symlink, represents
    // unresolved work. This check is not atomic with intent creation; callers
    // must serialize admission and same-UID interference remains out of scope.
    for name in [
        "pending-attempt",
        "pending-child",
        "pending-exit",
        "pending-snapshot",
        "pending-fixture-postimage",
        "pending-fixture-rollback",
        "pending-fixture-multi-rollback",
        "pending-fixture-multi-resume",
        "pending-fixture-resume",
    ] {
        require_record_absent(directory, name)?;
    }
    let path = format!("/proc/self/fd/{}/pending-intent", directory.as_raw_fd());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    write!(file, "tucupi-recovery-intent-v1\nattempt={attempt}\n")?;
    file.sync_all()?;
    directory.sync_all()?;
    Ok(())
}

fn require_record_absent(directory: &File, name: &str) -> io::Result<()> {
    let path = format!("/proc/self/fd/{}/{name}", directory.as_raw_fd());
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "recovery record already exists",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Advisory serialization for writers that use this module. The lock is on an
/// independently opened descriptor for the pinned directory; same-UID writers
/// can ignore it or replace paths. This is not an authentication boundary.
struct RecoveryWriteGuard(File);

/// Synthetic post-image only: no encryption, authentication or production
/// recovery guarantee. Partial create-only records remain unresolved.
#[cfg(feature = "codex-fixture")]
pub(crate) fn fixture_store_postimage(
    directory: &File,
    attempt: &str,
    bytes: &[u8],
) -> io::Result<()> {
    fixture_store_postimage_with_hook(directory, attempt, Some(bytes), b"TUCSING2", |_| {})
}

#[cfg(feature = "codex-fixture")]
pub(crate) fn fixture_store_absent_postimage(directory: &File, attempt: &str) -> io::Result<()> {
    fixture_store_postimage_with_hook(directory, attempt, None, b"TUCSING2", |_| {})
}

#[cfg(feature = "codex-fixture")]
pub(crate) fn fixture_store_multi_postimage(
    directory: &File,
    attempt: &str,
    bytes: &[u8],
) -> io::Result<()> {
    fixture_store_postimage_with_hook(directory, attempt, Some(bytes), b"TUCMULT2", |_| {})
}

#[cfg(feature = "codex-fixture")]
fn fixture_store_postimage_with_hook(
    directory: &File,
    attempt: &str,
    bytes: Option<&[u8]>,
    magic: &[u8; 8],
    mut hook: impl FnMut(&str),
) -> io::Result<()> {
    use sha2::{Digest, Sha256};
    if bytes.is_some_and(|bytes| bytes.len() > 65536) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "synthetic postimage too large",
        ));
    }
    let _guard = RecoveryWriteGuard::acquire(directory)?;
    if read_pending_intent(directory)? != attempt {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture intent mismatch",
        ));
    }
    for name in ["pending-attempt", "pending-child", "pending-exit"] {
        require_record_absent(directory, name)?;
    }
    let snapshot = read_recovery_snapshot_locked(directory)?;
    let path = format!(
        "/proc/self/fd/{}/pending-fixture-postimage",
        directory.as_raw_fd()
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    hook("created");
    file.write_all(magic)?;
    file.write_all(attempt.as_bytes())?;
    let length = bytes.map_or(u32::MAX, |bytes| bytes.len() as u32);
    let payload = bytes.unwrap_or_default();
    file.write_all(&length.to_be_bytes())?;
    let mut digest = Sha256::new();
    digest.update(magic);
    digest.update(length.to_be_bytes());
    digest.update(payload);
    file.write_all(&digest.finalize())?;
    file.write_all(&Sha256::digest(&snapshot))?;
    hook("header");
    file.write_all(payload)?;
    hook("payload");
    file.sync_all()?;
    directory.sync_all()
}

#[cfg(all(test, feature = "codex-fixture"))]
pub(crate) fn fixture_read_postimage(directory: &File) -> io::Result<Vec<u8>> {
    fixture_read_postimage_state(directory)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "fixture postimage is absent"))
}

#[cfg(feature = "codex-fixture")]
pub(crate) fn fixture_read_postimage_state(directory: &File) -> io::Result<Option<Vec<u8>>> {
    fixture_read_typed_postimage(directory, b"TUCSING2")
}

#[cfg(feature = "codex-fixture")]
pub(crate) fn fixture_read_multi_postimage(directory: &File) -> io::Result<Vec<u8>> {
    fixture_read_typed_postimage(directory, b"TUCMULT2")?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "fixture multi postimage absent"))
}

#[cfg(feature = "codex-fixture")]
fn fixture_read_typed_postimage(directory: &File, magic: &[u8; 8]) -> io::Result<Option<Vec<u8>>> {
    let _guard = RecoveryWriteGuard::acquire(directory)?;
    fixture_read_typed_postimage_locked(directory, magic)
}

#[cfg(feature = "codex-fixture")]
fn fixture_read_typed_postimage_locked(
    directory: &File,
    magic: &[u8; 8],
) -> io::Result<Option<Vec<u8>>> {
    use sha2::{Digest, Sha256};
    let attempt = read_pending_intent(directory)?;
    let snapshot = read_recovery_snapshot_locked(directory)?;
    let path = format!(
        "/proc/self/fd/{}/pending-fixture-postimage",
        directory.as_raw_fd()
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    // SAFETY: geteuid is a read-only process query.
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid fixture postimage",
        ));
    }
    let mut data = Vec::new();
    file.take((108 + 65536 + 1) as u64).read_to_end(&mut data)?;
    if data.len() < 108
        || data.len() > 108 + 65536
        || &data[..8] != magic
        || &data[8..40] != attempt.as_bytes()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid fixture postimage",
        ));
    }
    let length = u32::from_be_bytes(
        data[40..44]
            .try_into()
            .map_err(|_| io::Error::other("invalid length"))?,
    );
    let payload = &data[108..];
    let mut digest = Sha256::new();
    digest.update(magic);
    digest.update(length.to_be_bytes());
    digest.update(payload);
    if (length == u32::MAX && !payload.is_empty())
        || (length != u32::MAX && length as usize != payload.len())
        || digest.finalize().as_slice() != &data[44..76]
        || Sha256::digest(&snapshot).as_slice() != &data[76..108]
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid fixture postimage",
        ));
    }
    if length == u32::MAX {
        Ok(None)
    } else {
        Ok(Some(payload.to_vec()))
    }
}

/// Serialize cooperating synthetic recovery operations using an independently
/// opened snapshot descriptor. The lock is advisory, scoped to this inode,
/// and cannot prevent replacement or interference by the same UID.
#[cfg(feature = "codex-fixture")]
pub(crate) fn fixture_recovery_lease(directory: &File) -> io::Result<File> {
    let path = format!("/proc/self/fd/{}/pending-snapshot", directory.as_raw_fd());
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    // SAFETY: geteuid is a read-only process query.
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid fixture snapshot",
        ));
    }
    // SAFETY: file owns a live descriptor and LOCK_NB never waits.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // Closing this independently opened descriptor releases the advisory lock.
    Ok(file)
}

/// Point-in-time check only: a replacement can occur after this comparison.
#[cfg(feature = "codex-fixture")]
pub(crate) fn verify_fixture_recovery_lease(directory: &File, lease: &File) -> io::Result<()> {
    let path = format!("/proc/self/fd/{}/pending-snapshot", directory.as_raw_fd());
    let named = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let current = named.metadata()?;
    let held = lease.metadata()?;
    if !current.is_file()
        || held.nlink() != 1
        || current.nlink() != 1
        || (held.dev(), held.ino()) != (current.dev(), current.ino())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture snapshot lease replaced",
        ));
    }
    Ok(())
}

/// Fixture-only result: not proof of real rollback, cleanup, or ownership.
#[cfg(feature = "codex-fixture")]
pub(crate) fn fixture_rollback_begin(directory: &File) -> io::Result<String> {
    let _guard = RecoveryWriteGuard::acquire(directory)?;
    let attempt = read_pending_intent(directory)?;
    require_record_absent(directory, "pending-fixture-rollback")?;
    require_record_absent(directory, "pending-fixture-resume")?;
    require_record_absent(directory, "pending-fixture-multi-rollback")?;
    require_record_absent(directory, "pending-fixture-multi-resume")?;
    Ok(attempt)
}

#[cfg(feature = "codex-fixture")]
pub(crate) fn fixture_multi_rollback_record(
    directory: &File,
    attempt: &str,
    snapshot: &[u8],
    postimage: &[u8],
    mut hook: impl FnMut(&str) -> io::Result<()>,
) -> io::Result<()> {
    let _guard = RecoveryWriteGuard::acquire(directory)?;
    if read_pending_intent(directory)? != attempt {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture intent mismatch",
        ));
    }
    require_record_absent(directory, "pending-fixture-rollback")?;
    require_record_absent(directory, "pending-fixture-resume")?;
    require_record_absent(directory, "pending-fixture-multi-resume")?;
    fixture_multi_verify_plan_locked(directory, snapshot, postimage)?;
    hook("plan-verified")?;
    let record = fixture_multi_result_body(attempt, "rollback", snapshot, postimage);
    let path = format!(
        "/proc/self/fd/{}/pending-fixture-multi-rollback",
        directory.as_raw_fd()
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    hook("created")?;
    file.write_all(record.as_bytes())?;
    hook("written")?;
    file.sync_all()?;
    directory.sync_all()
}

/// Local fixture evidence only; it cannot establish real rollback or cleanup.
#[cfg(feature = "codex-fixture")]
pub(crate) fn fixture_multi_rollback_observed(directory: &File) -> io::Result<()> {
    let _guard = RecoveryWriteGuard::acquire(directory)?;
    require_record_absent(directory, "pending-fixture-rollback")?;
    require_record_absent(directory, "pending-fixture-resume")?;
    let attempt = read_pending_intent(directory)?;
    let content = read_fixture_record(directory, "pending-fixture-multi-rollback")?;
    let expected = fixture_multi_result_body_locked(directory, &attempt, "rollback")?;
    if content != expected.as_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid fixture multi rollback record",
        ));
    }
    Ok(())
}

/// Preserve the prior record, including a partial write. This is only an
/// observation of synthetic targets, not a cleanup or authorization decision.
#[cfg(feature = "codex-fixture")]
pub(crate) fn fixture_multi_resume_record(
    directory: &File,
    attempt: &str,
    snapshot: &[u8],
    postimage: &[u8],
    mut hook: impl FnMut(&str) -> io::Result<()>,
) -> io::Result<()> {
    let _guard = RecoveryWriteGuard::acquire(directory)?;
    if read_pending_intent(directory)? != attempt {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture intent mismatch",
        ));
    }
    require_record_absent(directory, "pending-fixture-multi-resume")?;
    require_record_absent(directory, "pending-fixture-rollback")?;
    require_record_absent(directory, "pending-fixture-resume")?;
    fixture_multi_verify_plan_locked(directory, snapshot, postimage)?;
    hook("plan-verified")?;
    let prior = read_fixture_record(directory, "pending-fixture-multi-rollback")?;
    let expected = fixture_multi_result_body(attempt, "rollback", snapshot, postimage);
    if !expected.as_bytes().starts_with(&prior) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid fixture multi rollback record",
        ));
    }
    let resume = fixture_multi_resume_body(attempt, snapshot, postimage, &prior);
    let path = format!(
        "/proc/self/fd/{}/pending-fixture-multi-resume",
        directory.as_raw_fd()
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    hook("created")?;
    file.write_all(resume.as_bytes())?;
    hook("written")?;
    file.sync_all()?;
    directory.sync_all()
}

#[cfg(feature = "codex-fixture")]
fn fixture_multi_verify_plan_locked(
    directory: &File,
    snapshot: &[u8],
    postimage: &[u8],
) -> io::Result<()> {
    if read_recovery_snapshot_locked(directory)? != snapshot
        || fixture_read_typed_postimage_locked(directory, b"TUCMULT2")?.as_deref()
            != Some(postimage)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture recovery plan changed before publication",
        ));
    }
    Ok(())
}

#[cfg(feature = "codex-fixture")]
pub(crate) fn fixture_multi_resume_observed(directory: &File) -> io::Result<()> {
    let _guard = RecoveryWriteGuard::acquire(directory)?;
    require_record_absent(directory, "pending-fixture-rollback")?;
    require_record_absent(directory, "pending-fixture-resume")?;
    let attempt = read_pending_intent(directory)?;
    let prior = read_fixture_record(directory, "pending-fixture-multi-rollback")?;
    let rollback = fixture_multi_result_body_locked(directory, &attempt, "rollback")?;
    let resume = fixture_multi_resume_body_locked(directory, &attempt, &prior)?;
    if !rollback.as_bytes().starts_with(&prior)
        || read_fixture_record(directory, "pending-fixture-multi-resume")? != resume.as_bytes()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid fixture multi resume record",
        ));
    }
    Ok(())
}

#[cfg(feature = "codex-fixture")]
fn fixture_multi_resume_body_locked(
    directory: &File,
    attempt: &str,
    prior: &[u8],
) -> io::Result<String> {
    let snapshot = read_recovery_snapshot_locked(directory)?;
    let postimage =
        fixture_read_typed_postimage_locked(directory, b"TUCMULT2")?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "fixture multi postimage absent")
        })?;
    Ok(fixture_multi_resume_body(
        attempt, &snapshot, &postimage, prior,
    ))
}

#[cfg(feature = "codex-fixture")]
fn fixture_multi_resume_body(
    attempt: &str,
    snapshot: &[u8],
    postimage: &[u8],
    prior: &[u8],
) -> String {
    use sha2::{Digest, Sha256};
    let base = fixture_multi_result_body(attempt, "resume", snapshot, postimage);
    format!(
        "{}prior={:x}\n",
        base.replacen("multi-resume-v2", "multi-resume-v3", 1),
        Sha256::digest(prior)
    )
}

/// Called only while holding RecoveryWriteGuard; the digest binds local
/// evidence but is not authentication against same-UID writers.
#[cfg(feature = "codex-fixture")]
fn fixture_multi_result_body_locked(
    directory: &File,
    attempt: &str,
    kind: &str,
) -> io::Result<String> {
    let snapshot = read_recovery_snapshot_locked(directory)?;
    let postimage =
        fixture_read_typed_postimage_locked(directory, b"TUCMULT2")?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "fixture multi postimage absent")
        })?;
    Ok(fixture_multi_result_body(
        attempt, kind, &snapshot, &postimage,
    ))
}

#[cfg(feature = "codex-fixture")]
fn fixture_multi_result_body(
    attempt: &str,
    kind: &str,
    snapshot: &[u8],
    postimage: &[u8],
) -> String {
    use sha2::{Digest, Sha256};
    format!("tucupi-fixture-multi-{kind}-v2\nattempt={attempt}\nsnapshot={:x}\npostimage={:x}\nsynthetic-two-file=observed\n", Sha256::digest(snapshot), Sha256::digest(postimage))
}

#[cfg(feature = "codex-fixture")]
pub(crate) fn fixture_pending_attempt(directory: &File) -> io::Result<String> {
    let _guard = RecoveryWriteGuard::acquire(directory)?;
    read_pending_intent(directory)
}

#[cfg(feature = "codex-fixture")]
fn fixture_verified_direct_exit_locked(directory: &File) -> io::Result<Vec<u8>> {
    let base = local_binding_evidence(directory);
    let (attempt, _) = read_direct_exit(directory)?;
    if !matches!(
        base,
        LocalRecoveryEvidence::PendingAttemptObserved
            | LocalRecoveryEvidence::PendingChildLocatorObserved
    ) || read_pending_intent(directory)? != attempt
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture direct exit unavailable",
        ));
    }
    read_fixture_record(directory, "pending-exit")
}

#[cfg(feature = "codex-fixture")]
pub(crate) fn fixture_verified_direct_exit(directory: &File) -> io::Result<Vec<u8>> {
    let _guard = RecoveryWriteGuard::acquire(directory)?;
    fixture_verified_direct_exit_locked(directory)
}

#[cfg(feature = "codex-fixture")]
pub(crate) fn fixture_rollback_record_with_hook(
    directory: &File,
    attempt: &str,
    snapshot: &[u8],
    postimage: Option<Option<&[u8]>>,
    direct_exit: Option<&[u8]>,
    mut hook: impl FnMut(&str) -> io::Result<()>,
) -> io::Result<()> {
    let _guard = RecoveryWriteGuard::acquire(directory)?;
    if read_pending_intent(directory)? != attempt {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture intent mismatch",
        ));
    }
    require_record_absent(directory, "pending-fixture-resume")?;
    require_record_absent(directory, "pending-fixture-multi-rollback")?;
    require_record_absent(directory, "pending-fixture-multi-resume")?;
    if read_recovery_snapshot_locked(directory)? != snapshot {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture snapshot changed before publication",
        ));
    }
    let current = fixture_single_postimage_locked(directory)?;
    if current.as_ref().map(|value| value.as_deref()) != postimage {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture postimage changed before publication",
        ));
    }
    if let Some(expected) = direct_exit {
        if fixture_verified_direct_exit_locked(directory)? != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fixture direct exit changed",
            ));
        }
    }
    let record = fixture_single_result_body(attempt, snapshot, postimage);
    let path = format!(
        "/proc/self/fd/{}/pending-fixture-rollback",
        directory.as_raw_fd()
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    hook("created")?;
    file.write_all(record.as_bytes())?;
    hook("written")?;
    file.sync_all()?;
    directory.sync_all()
}

/// A valid record is only local, unauthenticated fixture evidence.
#[cfg(feature = "codex-fixture")]
pub(crate) fn fixture_rollback_observed(directory: &File) -> io::Result<()> {
    let _guard = RecoveryWriteGuard::acquire(directory)?;
    require_record_absent(directory, "pending-fixture-multi-rollback")?;
    require_record_absent(directory, "pending-fixture-multi-resume")?;
    let attempt = read_pending_intent(directory)?;
    let content = read_fixture_record(directory, "pending-fixture-rollback")?;
    let snapshot = read_recovery_snapshot_locked(directory)?;
    let postimage = fixture_single_postimage_locked(directory)?;
    let expected = fixture_single_result_body(
        &attempt,
        &snapshot,
        postimage.as_ref().map(|value| value.as_deref()),
    );
    if content != expected.as_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid fixture rollback record",
        ));
    }
    Ok(())
}

#[cfg(feature = "codex-fixture")]
fn read_fixture_record(directory: &File, name: &str) -> io::Result<Vec<u8>> {
    let path = format!("/proc/self/fd/{}/{name}", directory.as_raw_fd());
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    // SAFETY: geteuid is a read-only process query.
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid fixture rollback record",
        ));
    }
    let mut content = Vec::new();
    file.take(513).read_to_end(&mut content)?;
    Ok(content)
}

/// Record only that an isolated fixture target was observed at the snapshot
/// bytes after an interrupted result publication. The original result and
/// pending intent are retained; neither record authorizes any real operation.
#[cfg(feature = "codex-fixture")]
pub(crate) fn fixture_resume_record(
    directory: &File,
    attempt: &str,
    snapshot: &[u8],
    postimage: Option<Option<&[u8]>>,
    direct_exit: Option<&[u8]>,
) -> io::Result<()> {
    let _guard = RecoveryWriteGuard::acquire(directory)?;
    if read_pending_intent(directory)? != attempt {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture intent mismatch",
        ));
    }
    require_record_absent(directory, "pending-fixture-resume")?;
    require_record_absent(directory, "pending-fixture-multi-rollback")?;
    require_record_absent(directory, "pending-fixture-multi-resume")?;
    if read_recovery_snapshot_locked(directory)? != snapshot {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture snapshot changed before publication",
        ));
    }
    let current = fixture_single_postimage_locked(directory)?;
    if current.as_ref().map(|value| value.as_deref()) != postimage {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture postimage changed before publication",
        ));
    }
    if let Some(expected) = direct_exit {
        if fixture_verified_direct_exit_locked(directory)? != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fixture direct exit changed",
            ));
        }
    }
    let content = read_fixture_record(directory, "pending-fixture-rollback")?;
    let expected = fixture_single_result_body(attempt, snapshot, postimage);
    if !expected.as_bytes().starts_with(&content) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid fixture rollback record",
        ));
    }
    let path = format!(
        "/proc/self/fd/{}/pending-fixture-resume",
        directory.as_raw_fd()
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(fixture_single_resume_body(attempt, snapshot, postimage, &content).as_bytes())?;
    file.sync_all()?;
    directory.sync_all()
}

#[cfg(feature = "codex-fixture")]
pub(crate) fn fixture_resume_observed(directory: &File) -> io::Result<()> {
    let _guard = RecoveryWriteGuard::acquire(directory)?;
    require_record_absent(directory, "pending-fixture-multi-rollback")?;
    require_record_absent(directory, "pending-fixture-multi-resume")?;
    let attempt = read_pending_intent(directory)?;
    let prior = read_fixture_record(directory, "pending-fixture-rollback")?;
    let snapshot = read_recovery_snapshot_locked(directory)?;
    let postimage = fixture_single_postimage_locked(directory)?;
    let postimage = postimage.as_ref().map(|value| value.as_deref());
    let rollback = fixture_single_result_body(&attempt, &snapshot, postimage);
    let resumed = fixture_single_resume_body(&attempt, &snapshot, postimage, &prior);
    if !rollback.as_bytes().starts_with(&prior)
        || read_fixture_record(directory, "pending-fixture-resume")? != resumed.as_bytes()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid fixture resume record",
        ));
    }
    Ok(())
}

#[cfg(feature = "codex-fixture")]
fn fixture_single_result_body(
    attempt: &str,
    snapshot: &[u8],
    postimage: Option<Option<&[u8]>>,
) -> String {
    use sha2::{Digest, Sha256};
    match postimage {
        None => format!("tucupi-fixture-rollback-v2\nattempt={attempt}\nsnapshot={:x}\nsynthetic-one-file=observed\n", Sha256::digest(snapshot)),
        Some(value) => format!("tucupi-fixture-rollback-v3\nattempt={attempt}\nsnapshot={:x}\npostimage={:x}\nsynthetic-one-file=observed\n", Sha256::digest(snapshot), fixture_single_postimage_digest(value)),
    }
}

#[cfg(feature = "codex-fixture")]
fn fixture_single_resume_body(
    attempt: &str,
    snapshot: &[u8],
    postimage: Option<Option<&[u8]>>,
    prior: &[u8],
) -> String {
    use sha2::{Digest, Sha256};
    match postimage {
        None => format!("tucupi-fixture-resume-v2\nattempt={attempt}\nsnapshot={:x}\nprior={:x}\nsynthetic-target=observed\n", Sha256::digest(snapshot), Sha256::digest(prior)),
        Some(value) => format!("tucupi-fixture-resume-v3\nattempt={attempt}\nsnapshot={:x}\npostimage={:x}\nprior={:x}\nsynthetic-target=observed\n", Sha256::digest(snapshot), fixture_single_postimage_digest(value), Sha256::digest(prior)),
    }
}

#[cfg(feature = "codex-fixture")]
fn fixture_single_postimage_digest(value: Option<&[u8]>) -> sha2::digest::Output<sha2::Sha256> {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"fixture-single-postimage-v1\n");
    match value {
        Some(bytes) => {
            digest.update([1]);
            digest.update(bytes);
        }
        None => digest.update([0]),
    }
    digest.finalize()
}

#[cfg(feature = "codex-fixture")]
fn fixture_single_postimage_locked(directory: &File) -> io::Result<Option<Option<Vec<u8>>>> {
    let path = format!(
        "/proc/self/fd/{}/pending-fixture-postimage",
        directory.as_raw_fd()
    );
    match std::fs::symlink_metadata(path) {
        Ok(_) => fixture_read_typed_postimage_locked(directory, b"TUCSING2").map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(feature = "codex-fixture")]
pub(crate) fn fixture_single_postimage(directory: &File) -> io::Result<Option<Option<Vec<u8>>>> {
    let _guard = RecoveryWriteGuard::acquire(directory)?;
    fixture_single_postimage_locked(directory)
}

// Bounded single-record snapshot primitive, not a complete backup or rollback.
// Data is not encrypted and must not contain secrets. The digest detects
// accidental corruption but cannot authenticate records against the same UID.
const SNAPSHOT_MAX: usize = 1024 * 1024;
const SNAPSHOT_HEADER: usize = 8 + 32 + 8 + 32;

pub(crate) fn persist_recovery_snapshot(
    directory: &File,
    attempt: &str,
    bytes: &[u8],
) -> io::Result<()> {
    persist_recovery_snapshot_with_hook(directory, attempt, bytes, |_| {})
}

fn persist_recovery_snapshot_with_hook(
    directory: &File,
    attempt: &str,
    bytes: &[u8],
    mut hook: impl FnMut(&str),
) -> io::Result<()> {
    use sha2::{Digest, Sha256};
    if !valid_id(attempt) || bytes.len() > SNAPSHOT_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid recovery snapshot",
        ));
    }
    let _guard = RecoveryWriteGuard::acquire(directory)?;
    if read_pending_intent(directory)? != attempt {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recovery intent mismatch",
        ));
    }
    for name in ["pending-attempt", "pending-child", "pending-exit"] {
        require_record_absent(directory, name)?;
    }
    let path = format!("/proc/self/fd/{}/pending-snapshot", directory.as_raw_fd());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    hook("created");
    file.write_all(b"TUCUPI01")?;
    file.write_all(attempt.as_bytes())?;
    file.write_all(&(bytes.len() as u64).to_be_bytes())?;
    file.write_all(&Sha256::digest(bytes))?;
    hook("header");
    file.write_all(bytes)?;
    hook("payload");
    file.sync_all()?;
    directory.sync_all()
}

pub(crate) fn read_recovery_snapshot(directory: &File) -> io::Result<Vec<u8>> {
    let _guard = RecoveryWriteGuard::acquire(directory)?;
    read_recovery_snapshot_locked(directory)
}

fn read_recovery_snapshot_locked(directory: &File) -> io::Result<Vec<u8>> {
    use sha2::{Digest, Sha256};
    let attempt = read_pending_intent(directory)?;
    let path = format!("/proc/self/fd/{}/pending-snapshot", directory.as_raw_fd());
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    // SAFETY: geteuid is a read-only process query.
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid recovery snapshot",
        ));
    }
    let mut record = Vec::new();
    file.take((SNAPSHOT_HEADER + SNAPSHOT_MAX + 1) as u64)
        .read_to_end(&mut record)?;
    if record.len() < SNAPSHOT_HEADER
        || record.len() > SNAPSHOT_HEADER + SNAPSHOT_MAX
        || &record[..8] != b"TUCUPI01"
        || &record[8..40] != attempt.as_bytes()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid recovery snapshot",
        ));
    }
    let length = u64::from_be_bytes(
        record[40..48]
            .try_into()
            .map_err(|_| io::Error::other("invalid length"))?,
    );
    let payload = &record[SNAPSHOT_HEADER..];
    if length != payload.len() as u64 || Sha256::digest(payload).as_slice() != &record[48..80] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid recovery snapshot",
        ));
    }
    Ok(payload.to_vec())
}

impl RecoveryWriteGuard {
    fn acquire(directory: &File) -> io::Result<Self> {
        let path = format!("/proc/self/fd/{}", directory.as_raw_fd());
        let lock = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(path)?;
        // SAFETY: lock owns a live directory descriptor; nonblocking flock
        // does not wait for another writer and does not alter privileges.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(lock))
    }
}

impl Drop for RecoveryWriteGuard {
    fn drop(&mut self) {
        // SAFETY: the guard still owns the live descriptor at this point.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Persist a same-user attempt binding after its matching intent. The binding
/// is create-only; errors may leave a partial file and must never cause an
/// automatic retry that removes it. Caller-supplied manager/unit IDs are not
/// proof of ownership, execution, cleanup, rollback, or authorization.
pub fn persist_attempt_binding(directory: &File, identity: &AttemptIdentity) -> io::Result<()> {
    let meta = directory.metadata()?;
    // SAFETY: geteuid is a read-only process query.
    if !meta.is_dir()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.nlink() == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid recovery directory",
        ));
    }
    let content = format!("tucupi-recovery-attempt-v1\nattempt={}\nunit={}\ninvocation={}\nboot={}\nmanager_epoch={}\n", identity.attempt, identity.unit, identity.invocation, identity.boot, identity.manager_epoch);
    let parsed = AttemptIdentity::parse(&content)?;
    let _guard = RecoveryWriteGuard::acquire(directory)?;
    require_record_absent(directory, "pending-child")?;
    require_record_absent(directory, "pending-exit")?;
    if read_pending_intent(directory)? != parsed.attempt {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "recovery intent mismatch",
        ));
    }
    let path = format!("/proc/self/fd/{}/pending-attempt", directory.as_raw_fd());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    directory.sync_all()?;
    Ok(())
}

fn read_pending_intent(directory: &File) -> io::Result<String> {
    let path = format!("/proc/self/fd/{}/pending-intent", directory.as_raw_fd());
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    // SAFETY: geteuid is a read-only process query.
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid recovery intent",
        ));
    }
    let mut content = String::new();
    file.take(129).read_to_string(&mut content)?;
    let mut lines = content.lines();
    let header_valid = content.len() <= 128
        && content.ends_with('\n')
        && lines.next() == Some("tucupi-recovery-intent-v1");
    let attempt = lines.next().and_then(|line| line.strip_prefix("attempt="));
    if !header_valid || !attempt.is_some_and(valid_id) || lines.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid recovery intent",
        ));
    }
    Ok(attempt.unwrap().to_owned())
}

/// Test-only inspection: an attempt id is evidence, not recovery authority.
#[cfg(test)]
pub(crate) fn fixture_read_pending_intent(path: &Path) -> io::Result<String> {
    let directory = open_provisioned_state_directory(path)?;
    read_pending_intent(&directory)
}

pub(crate) fn codex_recovery_preflight_at(path: &Path) -> io::Result<()> {
    let _directory = open_provisioned_state_directory(path)?;
    Err(io::Error::other("supervised recovery not reconciled"))
}

/// Opens an already-provisioned private directory without creating anything.
/// Missing, inaccessible, symlinked, shared, or incorrectly owned state is an
/// error; callers must treat every error as blocked, not as a clean install.
/// This validates only the final component and the current instant: it does
/// not establish a trusted parent, prevent later substitution, or prove cleanup.
pub fn open_private_state_directory(path: &Path) -> io::Result<File> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid recovery state path",
        ));
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let pinned = directory.metadata()?;
    let named = std::fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no arguments and does not mutate program state.
    let effective_uid = unsafe { libc::geteuid() };
    if !named.file_type().is_dir()
        || pinned.nlink() == 0
        || pinned.uid() != effective_uid
        || pinned.mode() & 0o077 != 0
        || (pinned.dev(), pinned.ino()) != (named.dev(), named.ino())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untrusted recovery state directory",
        ));
    }
    Ok(directory)
}

const FORMAT_MARKER: &str = "tucupi-recovery-state-v1\n";

/// Explicitly provision a new directory under a previously existing private
/// parent. Never reinitialize, overwrite, or delete an existing path. This
/// operation records a format marker, not proof of clean supervised work.
/// A failed or interrupted provisioning must be treated as unavailable.
pub fn provision_state_directory(parent: &Path, name: &std::ffi::OsStr) -> io::Result<()> {
    provision_state_directory_with_hook(parent, name, || Ok(()))
}

fn provision_state_directory_with_hook(
    parent: &Path,
    name: &std::ffi::OsStr,
    after_create: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let mut parts = Path::new(name).components();
    if !matches!(parts.next(), Some(Component::Normal(_))) || parts.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid state directory name",
        ));
    }
    let name = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid state directory name"))?;
    let pinned_parent = open_private_state_directory(parent)
        .map_err(|error| io::Error::new(error.kind(), format!("recovery parent: {error}")))?;
    // SAFETY: the directory descriptor and NUL-terminated name remain valid;
    // mkdirat cannot overwrite an existing path and applies the process umask.
    if unsafe { libc::mkdirat(pinned_parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }
    after_create()?;
    let anchored_path = Path::new("/proc/self/fd")
        .join(pinned_parent.as_raw_fd().to_string())
        .join(std::ffi::OsStr::from_bytes(name.as_bytes()));
    let child = open_private_state_directory(&anchored_path)
        .map_err(|error| io::Error::new(error.kind(), format!("recovery child: {error}")))?;
    let marker_path = format!("/proc/self/fd/{}/format", child.as_raw_fd());
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(marker_path)?;
    marker.write_all(FORMAT_MARKER.as_bytes())?;
    marker.sync_all()?;
    child.sync_all()?;
    pinned_parent.sync_all()?;
    let current_parent = open_private_state_directory(parent)?.metadata()?;
    let pinned = pinned_parent.metadata()?;
    if (current_parent.dev(), current_parent.ino()) != (pinned.dev(), pinned.ino()) {
        return Err(io::Error::other(
            "recovery parent changed during provisioning",
        ));
    }
    let current_child =
        open_private_state_directory(&parent.join(std::ffi::OsStr::from_bytes(name.as_bytes())))?
            .metadata()?;
    let pinned_child = child.metadata()?;
    if (current_child.dev(), current_child.ino()) != (pinned_child.dev(), pinned_child.ino()) {
        return Err(io::Error::other(
            "recovery directory changed during provisioning",
        ));
    }
    Ok(())
}

/// Check that a directory contains a complete known format marker. Success is
/// not proof of a clean attempt and must not by itself authorize execution.
pub fn open_provisioned_state_directory(path: &Path) -> io::Result<File> {
    let directory = open_private_state_directory(path)?;
    verify_provisioned_marker(&directory)?;
    Ok(directory)
}

pub(crate) fn verify_provisioned_marker(directory: &File) -> io::Result<()> {
    let marker_path = format!("/proc/self/fd/{}/format", directory.as_raw_fd());
    let marker = OpenOptions::new()
        .read(true)
        // Avoid waiting for a FIFO writer. The metadata check below still
        // requires a regular, private file; O_NONBLOCK is not a general device
        // isolation guarantee.
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(marker_path)?;
    let meta = marker.metadata()?;
    // SAFETY: geteuid has no arguments and does not mutate program state.
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untrusted recovery format marker",
        ));
    }
    let mut content = String::new();
    marker.take(128).read_to_string(&mut content)?;
    if content != FORMAT_MARKER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid recovery format marker",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn recovery_format_fifo_is_rejected_without_writer() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let marker = std::ffi::CString::new(state.join("format").as_os_str().as_bytes()).unwrap();
        // SAFETY: marker is a valid NUL-terminated path in a temporary directory.
        assert_eq!(unsafe { libc::mkfifo(marker.as_ptr(), 0o600) }, 0);
        assert!(open_provisioned_state_directory(&state).is_err());
    }

    const ATTEMPT: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn unterminated_unit_binding_is_inconsistent_and_preserved() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        provision_state_directory(root.path(), std::ffi::OsStr::new("state")).unwrap();
        let state = root.path().join("state");
        let directory = open_provisioned_state_directory(&state).unwrap();
        persist_pending_intent(&directory, ATTEMPT).unwrap();
        let identity = AttemptIdentity {
            attempt: ATTEMPT.into(),
            unit: format!("tucupi-review-{ATTEMPT}.service"),
            invocation: "11111111111111111111111111111111".into(),
            boot: "22222222222222222222222222222222".into(),
            manager_epoch: "33333333333333333333333333333333".into(),
        };
        persist_attempt_binding(&directory, &identity).unwrap();
        persist_direct_exit(&directory, ATTEMPT, true).unwrap();
        let binding_path = state.join("pending-attempt");
        let mut partial = std::fs::read(&binding_path).unwrap();
        assert_eq!(partial.pop(), Some(b'\n'));
        std::fs::write(&binding_path, &partial).unwrap();
        let exit = std::fs::read(state.join("pending-exit")).unwrap();
        assert!(read_attempt_identity(&directory).is_err());
        assert_eq!(
            local_recovery_with_exit_at(&state),
            (LocalRecoveryEvidence::RecordsInconsistent, None)
        );
        let inspection = crate::same_user_supervisor::inspect_recovery(&state);
        assert_eq!(
            inspection.descendant_cleanup,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            inspection.rollback,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert!(crate::same_user_supervisor::PendingAttempt::begin(&state, ATTEMPT).is_err());
        assert_eq!(std::fs::read(binding_path).unwrap(), partial);
        assert_eq!(std::fs::read(state.join("pending-exit")).unwrap(), exit);
    }

    #[test]
    fn hardlinked_unit_binding_invalidates_direct_exit_without_changing_records() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        provision_state_directory(root.path(), std::ffi::OsStr::new("state")).unwrap();
        let state = root.path().join("state");
        let directory = open_provisioned_state_directory(&state).unwrap();
        persist_pending_intent(&directory, ATTEMPT).unwrap();
        let identity = AttemptIdentity {
            attempt: ATTEMPT.into(),
            unit: format!("tucupi-review-{ATTEMPT}.service"),
            invocation: "11111111111111111111111111111111".into(),
            boot: "22222222222222222222222222222222".into(),
            manager_epoch: "33333333333333333333333333333333".into(),
        };
        persist_attempt_binding(&directory, &identity).unwrap();
        persist_direct_exit(&directory, ATTEMPT, true).unwrap();
        assert_eq!(
            local_recovery_with_exit_at(&state),
            (LocalRecoveryEvidence::PendingDirectExitRecorded, Some(true))
        );
        let binding = state.join("pending-attempt");
        let alias = root.path().join("binding-alias");
        let before_binding = std::fs::read(&binding).unwrap();
        let before_exit = std::fs::read(state.join("pending-exit")).unwrap();
        std::fs::hard_link(&binding, &alias).unwrap();
        assert!(read_attempt_identity(&directory).is_err());
        assert_eq!(
            local_recovery_with_exit_at(&state),
            (LocalRecoveryEvidence::RecordsInconsistent, None)
        );
        assert_eq!(std::fs::read(&alias).unwrap(), before_binding);
        assert_eq!(
            std::fs::read(state.join("pending-exit")).unwrap(),
            before_exit
        );
        let inspection = crate::same_user_supervisor::inspect_recovery(&state);
        assert_eq!(
            inspection.descendant_cleanup,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            inspection.rollback,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert!(crate::same_user_supervisor::PendingAttempt::begin(&state, ATTEMPT).is_err());
        std::fs::remove_file(&alias).unwrap();
        assert_eq!(
            local_recovery_with_exit_at(&state),
            (LocalRecoveryEvidence::PendingDirectExitRecorded, Some(true))
        );
    }

    #[test]
    fn direct_exit_rejects_flipped_result_and_preserves_v2() {
        for success in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            provision_state_directory(root.path(), std::ffi::OsStr::new("state")).unwrap();
            let state = root.path().join("state");
            let directory = open_provisioned_state_directory(&state).unwrap();
            persist_pending_intent(&directory, ATTEMPT).unwrap();
            persist_child_locator(&directory, ATTEMPT, 101).unwrap();
            persist_direct_exit(&directory, ATTEMPT, success).unwrap();
            assert_eq!(
                local_recovery_with_exit_at(&state),
                (
                    LocalRecoveryEvidence::PendingDirectExitRecorded,
                    Some(success)
                )
            );
            let path = state.join("pending-exit");
            let original = std::fs::read_to_string(&path).unwrap();
            let altered = original.replace(
                &format!("success={}", u8::from(success)),
                &format!("success={}", u8::from(!success)),
            );
            std::fs::write(&path, &altered).unwrap();
            assert_eq!(
                local_recovery_with_exit_at(&state),
                (LocalRecoveryEvidence::RecordsInconsistent, None)
            );
            assert_eq!(std::fs::read_to_string(&path).unwrap(), altered);
            let legacy = original.replacen("tucupi-recovery-exit-v3", "tucupi-recovery-exit-v2", 1);
            std::fs::write(&path, &legacy).unwrap();
            assert_eq!(
                local_recovery_with_exit_at(&state),
                (LocalRecoveryEvidence::RecordsInconsistent, None)
            );
            assert_eq!(std::fs::read_to_string(&path).unwrap(), legacy);
            let inspection = crate::same_user_supervisor::inspect_recovery(&state);
            assert_eq!(
                inspection.descendant_cleanup,
                crate::same_user_supervisor::RecoveryOutcome::Unknown
            );
            assert_eq!(
                inspection.rollback,
                crate::same_user_supervisor::RecoveryOutcome::Unknown
            );
            assert!(crate::same_user_supervisor::PendingAttempt::begin(&state, ATTEMPT).is_err());
        }
    }

    #[test]
    fn direct_exit_rejects_replaced_locator_and_preserves_legacy_record() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for (name, pid) in [("first", 101), ("second", 102)] {
            provision_state_directory(root.path(), std::ffi::OsStr::new(name)).unwrap();
            let path = root.path().join(name);
            let directory = open_provisioned_state_directory(&path).unwrap();
            persist_pending_intent(&directory, ATTEMPT).unwrap();
            persist_child_locator(&directory, ATTEMPT, pid).unwrap();
            persist_direct_exit(&directory, ATTEMPT, true).unwrap();
        }
        let first = root.path().join("first");
        let second = root.path().join("second");
        assert_eq!(
            local_recovery_with_exit_at(&first),
            (LocalRecoveryEvidence::PendingDirectExitRecorded, Some(true))
        );
        let exit_path = first.join("pending-exit");
        let exit = std::fs::read(&exit_path).unwrap();
        std::fs::write(
            first.join("pending-child"),
            std::fs::read(second.join("pending-child")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            local_recovery_with_exit_at(&first),
            (LocalRecoveryEvidence::RecordsInconsistent, None)
        );
        assert_eq!(std::fs::read(&exit_path).unwrap(), exit);
        let legacy = format!("tucupi-recovery-exit-v1\nattempt={ATTEMPT}\nsuccess=1\n");
        std::fs::write(&exit_path, &legacy).unwrap();
        assert_eq!(
            local_recovery_with_exit_at(&first),
            (LocalRecoveryEvidence::RecordsInconsistent, None)
        );
        assert_eq!(std::fs::read(&exit_path).unwrap(), legacy.as_bytes());
        assert!(crate::same_user_supervisor::PendingAttempt::begin(&first, ATTEMPT).is_err());
        let inspection = crate::same_user_supervisor::inspect_recovery(&first);
        assert_eq!(
            inspection.descendant_cleanup,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            inspection.rollback,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn multi_publication_remains_bound_to_verified_plan_when_changed_after_check() {
        use crate::same_user_supervisor::{PendingAttempt, SyntheticFileSnapshot};
        for resume in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            for (name, expected) in [
                ("first", b"first".as_slice()),
                ("second", b"second".as_slice()),
            ] {
                provision_state_directory(root.path(), std::ffi::OsStr::new(name)).unwrap();
                let pending = PendingAttempt::begin(&root.path().join(name), ATTEMPT).unwrap();
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
                        cargo_toml: Some(expected.to_vec()),
                        cargo_lock: None,
                    })
                    .unwrap();
            }
            let first = root.path().join("first");
            let directory = open_provisioned_state_directory(&first).unwrap();
            let snapshot = read_recovery_snapshot(&directory).unwrap();
            let postimage = fixture_read_multi_postimage(&directory).unwrap();
            let path = first.join("pending-fixture-postimage");
            let original = std::fs::read(&path).unwrap();
            let replacement =
                std::fs::read(root.path().join("second/pending-fixture-postimage")).unwrap();
            if resume {
                let _ = fixture_multi_rollback_record(
                    &directory,
                    ATTEMPT,
                    &snapshot,
                    &postimage,
                    |step| {
                        if step == "created" {
                            return Err(io::Error::other("synthetic interruption"));
                        }
                        Ok(())
                    },
                );
            }
            let mut hook = |step: &str| -> io::Result<()> {
                if step == "plan-verified" {
                    std::fs::write(&path, &replacement)?;
                }
                Ok(())
            };
            if resume {
                fixture_multi_resume_record(&directory, ATTEMPT, &snapshot, &postimage, &mut hook)
                    .unwrap();
                assert!(fixture_multi_resume_observed(&directory).is_err());
                std::fs::write(&path, &original).unwrap();
                fixture_multi_resume_observed(&directory).unwrap();
            } else {
                fixture_multi_rollback_record(
                    &directory, ATTEMPT, &snapshot, &postimage, &mut hook,
                )
                .unwrap();
                assert!(fixture_multi_rollback_observed(&directory).is_err());
                std::fs::write(&path, &original).unwrap();
                fixture_multi_rollback_observed(&directory).unwrap();
            }
            assert!(PendingAttempt::begin(&first, ATTEMPT).is_err());
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn multi_result_publication_rejects_plan_changed_before_lock() {
        use crate::same_user_supervisor::{PendingAttempt, SyntheticFileSnapshot};
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["first", "second", "third"] {
            provision_state_directory(root.path(), std::ffi::OsStr::new(name)).unwrap();
            let path = root.path().join(name);
            let pending = PendingAttempt::begin(&path, ATTEMPT).unwrap();
            pending
                .store_synthetic_files(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(if name == "third" {
                        b"first".to_vec()
                    } else {
                        name.as_bytes().to_vec()
                    }),
                    cargo_lock: None,
                })
                .unwrap();
            pending
                .store_synthetic_two_file_postimage(&SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(if name == "third" {
                        b"alternate".to_vec()
                    } else {
                        b"changed".to_vec()
                    }),
                    cargo_lock: None,
                })
                .unwrap();
        }
        let first = root.path().join("first");
        let second = root.path().join("second");
        let directory = open_provisioned_state_directory(&first).unwrap();
        let snapshot = read_recovery_snapshot(&directory).unwrap();
        let postimage = fixture_read_multi_postimage(&directory).unwrap();
        let third = root.path().join("third");
        std::fs::write(
            first.join("pending-fixture-postimage"),
            std::fs::read(third.join("pending-fixture-postimage")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            fixture_multi_rollback_record(&directory, ATTEMPT, &snapshot, &postimage, |_| Ok(()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            fixture_multi_resume_record(&directory, ATTEMPT, &snapshot, &postimage, |_| Ok(()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        for name in ["pending-snapshot", "pending-fixture-postimage"] {
            std::fs::write(first.join(name), std::fs::read(second.join(name)).unwrap()).unwrap();
        }
        let error =
            fixture_multi_rollback_record(&directory, ATTEMPT, &snapshot, &postimage, |_| Ok(()))
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!first.join("pending-fixture-multi-rollback").exists());
        let error =
            fixture_multi_resume_record(&directory, ATTEMPT, &snapshot, &postimage, |_| Ok(()))
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!first.join("pending-fixture-multi-resume").exists());
        assert!(PendingAttempt::begin(&first, ATTEMPT).is_err());
        let inspection = crate::same_user_supervisor::inspect_recovery(&first);
        assert_eq!(
            inspection.descendant_cleanup,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            inspection.rollback,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn synthetic_postimage_digest_covers_mode_and_absence_marker() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["single", "multi"] {
            provision_state_directory(root.path(), std::ffi::OsStr::new(name)).unwrap();
        }
        let single = root.path().join("single");
        let pending = crate::same_user_supervisor::PendingAttempt::begin(&single, ATTEMPT).unwrap();
        pending
            .store_synthetic_files(&crate::same_user_supervisor::SyntheticFileSnapshot {
                version: 1,
                cargo_toml: Some(b"original".to_vec()),
                cargo_lock: None,
            })
            .unwrap();
        pending.store_synthetic_absent_postimage().unwrap();
        let path = single.join("pending-fixture-postimage");
        let mut data = std::fs::read(&path).unwrap();
        data[40..44].copy_from_slice(&0_u32.to_be_bytes());
        std::fs::write(&path, &data).unwrap();
        let directory = open_provisioned_state_directory(&single).unwrap();
        assert_eq!(
            fixture_read_postimage_state(&directory).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(std::fs::read(&path).unwrap(), data);
        assert!(crate::same_user_supervisor::PendingAttempt::begin(&single, ATTEMPT).is_err());

        let multi = root.path().join("multi");
        let pending = crate::same_user_supervisor::PendingAttempt::begin(&multi, ATTEMPT).unwrap();
        pending
            .store_synthetic_files(&crate::same_user_supervisor::SyntheticFileSnapshot {
                version: 1,
                cargo_toml: Some(b"original".to_vec()),
                cargo_lock: None,
            })
            .unwrap();
        pending
            .store_synthetic_two_file_postimage(
                &crate::same_user_supervisor::SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"modified".to_vec()),
                    cargo_lock: None,
                },
            )
            .unwrap();
        let path = multi.join("pending-fixture-postimage");
        let mut data = std::fs::read(&path).unwrap();
        data[..8].copy_from_slice(b"TUCSING2");
        std::fs::write(&path, &data).unwrap();
        let directory = open_provisioned_state_directory(&multi).unwrap();
        assert_eq!(
            fixture_read_postimage_state(&directory).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(std::fs::read(&path).unwrap(), data);
        assert!(crate::same_user_supervisor::PendingAttempt::begin(&multi, ATTEMPT).is_err());
        assert_eq!(
            crate::same_user_supervisor::inspect_recovery(&multi).descendant_cleanup,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn interrupted_fixture_postimage_publication_remains_pending() {
        use std::process::{Command, Stdio};
        const CHILD: &str = "TUCUPI_POSTIMAGE_WRITE_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let state = Path::new(&path);
            let point = std::env::var("TUCUPI_POSTIMAGE_WRITE_POINT").unwrap();
            let pending =
                crate::same_user_supervisor::PendingAttempt::begin(state, ATTEMPT).unwrap();
            pending
                .store_synthetic_files(&crate::same_user_supervisor::SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"original".to_vec()),
                    cargo_lock: None,
                })
                .unwrap();
            let directory = open_provisioned_state_directory(state).unwrap();
            let _ = fixture_store_postimage_with_hook(
                &directory,
                ATTEMPT,
                Some(b"modified"),
                b"TUCSING2",
                |step| {
                    if step == point {
                        std::process::exit(77);
                    }
                },
            );
            panic!("fixture interruption did not occur");
        }
        for point in ["created", "header", "payload"] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            provision_state_directory(root.path(), std::ffi::OsStr::new("state")).unwrap();
            let state = root.path().join("state");
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "recovery_state::tests::interrupted_fixture_postimage_publication_remains_pending"])
                .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, &state)
                .env("TUCUPI_POSTIMAGE_WRITE_POINT", point)
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
            assert_eq!(status.code(), Some(77));
            let path = state.join("pending-fixture-postimage");
            let before = std::fs::read(&path).unwrap();
            let directory = open_provisioned_state_directory(&state).unwrap();
            if point == "payload" {
                assert_eq!(fixture_read_postimage(&directory).unwrap(), b"modified");
            } else {
                assert!(fixture_read_postimage(&directory).is_err());
            }
            assert_eq!(
                fixture_store_postimage(&directory, ATTEMPT, b"replacement")
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::AlreadyExists
            );
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert!(!state.join("pending-child").exists());
            assert!(crate::same_user_supervisor::PendingAttempt::begin(&state, ATTEMPT).is_err());
            let inspection = crate::same_user_supervisor::inspect_recovery(&state);
            assert_eq!(
                inspection.descendant_cleanup,
                crate::same_user_supervisor::RecoveryOutcome::Unknown
            );
            assert_eq!(
                inspection.rollback,
                crate::same_user_supervisor::RecoveryOutcome::Unknown
            );
        }
    }

    #[test]
    fn interrupted_snapshot_publication_never_clears_attempt() {
        use std::process::{Command, Stdio};
        const CHILD: &str = "TUCUPI_SNAPSHOT_WRITE_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let state = Path::new(&path);
            let point = std::env::var("TUCUPI_SNAPSHOT_WRITE_POINT").unwrap();
            let _pending =
                crate::same_user_supervisor::PendingAttempt::begin(state, ATTEMPT).unwrap();
            let directory = open_provisioned_state_directory(state).unwrap();
            let _ = persist_recovery_snapshot_with_hook(
                &directory,
                ATTEMPT,
                b"synthetic snapshot",
                |step| {
                    if step == point {
                        std::process::exit(77);
                    }
                },
            );
            panic!("synthetic interruption did not occur");
        }
        for point in ["created", "header", "payload"] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            provision_state_directory(root.path(), std::ffi::OsStr::new("state")).unwrap();
            let state = root.path().join("state");
            std::fs::write(root.path().join("protected"), b"unchanged").unwrap();
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "recovery_state::tests::interrupted_snapshot_publication_never_clears_attempt",
                ])
                .env_clear()
                .env("HOME", root.path())
                .env("TMPDIR", root.path())
                .env(CHILD, &state)
                .env("TUCUPI_SNAPSHOT_WRITE_POINT", point)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(77));
            let path = state.join("pending-snapshot");
            let before = std::fs::read(&path).unwrap();
            let inspection = crate::same_user_supervisor::inspect_recovery(&state);
            let expected = if point == "payload" {
                crate::same_user_supervisor::SnapshotObservation::ValidEnvelopeObserved
            } else {
                crate::same_user_supervisor::SnapshotObservation::UnavailableOrInvalid
            };
            assert_eq!(inspection.snapshot, expected);
            assert_eq!(
                inspection.descendant_cleanup,
                crate::same_user_supervisor::RecoveryOutcome::Unknown
            );
            assert_eq!(
                inspection.rollback,
                crate::same_user_supervisor::RecoveryOutcome::Unknown
            );
            assert!(!state.join("pending-child").exists());
            assert!(crate::same_user_supervisor::PendingAttempt::begin(&state, ATTEMPT).is_err());
            let directory = open_provisioned_state_directory(&state).unwrap();
            assert_eq!(
                persist_recovery_snapshot(&directory, ATTEMPT, b"replacement")
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::AlreadyExists
            );
            assert_eq!(std::fs::read(path).unwrap(), before);
            assert_eq!(
                std::fs::read(root.path().join("protected")).unwrap(),
                b"unchanged"
            );
        }
    }
    const INVOCATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BOOT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const EPOCH: &str = "cccccccccccccccccccccccccccccccc";

    fn record() -> String {
        format!("tucupi-recovery-attempt-v1\nattempt={ATTEMPT}\nunit=tucupi-review-{ATTEMPT}.service\ninvocation={INVOCATION}\nboot={BOOT}\nmanager_epoch={EPOCH}\n")
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn interrupted_exit_publication_preserves_unknown_recovery() {
        const CHILD: &str = "TUCUPI_EXIT_PUBLICATION_CHILD";
        if let Some(root) = std::env::var_os(CHILD) {
            let phase = std::env::var("TUCUPI_EXIT_PUBLICATION_PHASE").unwrap();
            let dir = open_provisioned_state_directory(Path::new(&root)).unwrap();
            let _ = persist_direct_exit_with_hook(&dir, ATTEMPT, false, |step| {
                if (phase == "created" && step == ExitWriteStep::Created)
                    || (phase == "written" && step == ExitWriteStep::Written)
                {
                    std::process::exit(77);
                }
                Ok(())
            });
            panic!("synthetic interruption did not occur");
        }
        for phase in ["created", "written"] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            provision_state_directory(root.path(), std::ffi::OsStr::new("state")).unwrap();
            let state = root.path().join("state");
            let dir = open_provisioned_state_directory(&state).unwrap();
            persist_pending_intent(&dir, ATTEMPT).unwrap();
            persist_child_locator(&dir, ATTEMPT, 1).unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "recovery_state::tests::interrupted_exit_publication_preserves_unknown_recovery"])
                .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, &state)
                .env("TUCUPI_EXIT_PUBLICATION_PHASE", phase)
                .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
                .status().unwrap();
            assert_eq!(status.code(), Some(77));
            let path = state.join("pending-exit");
            let before = std::fs::read(&path).unwrap();
            let expected = if phase == "created" {
                LocalRecoveryEvidence::RecordsInconsistent
            } else {
                LocalRecoveryEvidence::PendingDirectExitRecorded
            };
            assert_eq!(local_recovery_evidence_at(&state), expected);
            assert!(codex_recovery_preflight_at(&state).is_err());
            assert_eq!(
                persist_direct_exit(&dir, ATTEMPT, false)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::AlreadyExists
            );
            assert_eq!(std::fs::read(path).unwrap(), before);
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn direct_exit_record_does_not_complete_recovery_or_overwrite() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        provision_state_directory(root.path(), std::ffi::OsStr::new("state")).unwrap();
        let state = root.path().join("state");
        let dir = open_provisioned_state_directory(&state).unwrap();
        assert!(persist_direct_exit(&dir, ATTEMPT, false).is_err());
        persist_pending_intent(&dir, ATTEMPT).unwrap();
        assert!(persist_direct_exit(&dir, ATTEMPT, false).is_err());
        persist_child_locator(&dir, ATTEMPT, 1).unwrap();
        assert!(persist_direct_exit(&dir, INVOCATION, true).is_err());
        persist_direct_exit(&dir, ATTEMPT, false).unwrap();
        assert_eq!(
            read_direct_exit(&dir).unwrap(),
            (ATTEMPT.to_string(), false)
        );
        assert_eq!(
            local_recovery_evidence_at(&state),
            LocalRecoveryEvidence::PendingDirectExitRecorded
        );
        let record_path = state.join("pending-exit");
        let before = std::fs::read(&record_path).unwrap();
        assert_eq!(
            persist_direct_exit(&dir, ATTEMPT, true).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&record_path).unwrap(), before);
        assert!(codex_recovery_preflight_at(&state).is_err());
        std::fs::write(&record_path, b"partial").unwrap();
        assert_eq!(
            local_recovery_evidence_at(&state),
            LocalRecoveryEvidence::RecordsInconsistent
        );
        assert!(codex_recovery_preflight_at(&state).is_err());
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn child_locator_requires_intent_and_is_never_a_clean_state() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        provision_state_directory(root.path(), std::ffi::OsStr::new("state")).unwrap();
        let state = root.path().join("state");
        let dir = open_provisioned_state_directory(&state).unwrap();
        assert!(persist_child_locator(&dir, ATTEMPT, 1).is_err());
        persist_pending_intent(&dir, ATTEMPT).unwrap();
        assert!(persist_child_locator(&dir, INVOCATION, 1).is_err());
        persist_child_locator(&dir, ATTEMPT, 1).unwrap();
        assert_eq!(
            local_recovery_evidence_at(&state),
            LocalRecoveryEvidence::PendingChildLocatorObserved
        );
        assert_eq!(
            persist_child_locator(&dir, ATTEMPT, 1).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(
            persist_attempt_binding(&dir, &AttemptIdentity::parse(&record()).unwrap()).is_err()
        );
        assert!(codex_recovery_preflight_at(&state).is_err());
        std::fs::write(state.join("pending-child"), b"partial").unwrap();
        assert_eq!(
            local_recovery_evidence_at(&state),
            LocalRecoveryEvidence::RecordsInconsistent
        );
        assert!(codex_recovery_preflight_at(&state).is_err());
    }

    #[test]
    fn cooperative_binding_requires_intent_and_never_replaces_pending_state() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        provision_state_directory(root.path(), std::ffi::OsStr::new("state")).unwrap();
        let state = root.path().join("state");
        let directory = open_provisioned_state_directory(&state).unwrap();
        let identity = AttemptIdentity::parse(&record()).unwrap();
        assert!(persist_attempt_binding(&directory, &identity).is_err());
        assert!(!state.join("pending-attempt").exists());
        persist_pending_intent(&directory, ATTEMPT).unwrap();
        let other = AttemptIdentity::parse(&record().replace(ATTEMPT, INVOCATION)).unwrap();
        assert_eq!(
            persist_attempt_binding(&directory, &other)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        let lock = RecoveryWriteGuard::acquire(&directory).unwrap();
        assert_eq!(
            persist_attempt_binding(&directory, &identity)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(!state.join("pending-attempt").exists());
        drop(lock);
        persist_attempt_binding(&directory, &identity).unwrap();
        assert_eq!(read_attempt_identity(&directory).unwrap(), identity);
        let bytes = std::fs::read(state.join("pending-attempt")).unwrap();
        assert_eq!(
            persist_attempt_binding(&directory, &identity)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(state.join("pending-attempt")).unwrap(), bytes);
        assert_eq!(
            local_recovery_evidence_at(&state),
            LocalRecoveryEvidence::PendingAttemptObserved
        );
        assert!(codex_recovery_preflight_at(&state).is_err());
    }

    #[test]
    fn recovery_evidence_detects_conflicting_or_partial_persistent_records() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        provision_state_directory(root.path(), std::ffi::OsStr::new("state")).unwrap();
        let state = root.path().join("state");
        let dir = open_provisioned_state_directory(&state).unwrap();
        persist_pending_intent(&dir, ATTEMPT).unwrap();
        let binding = state.join("pending-attempt");
        assert_eq!(
            local_recovery_evidence_at(&state),
            LocalRecoveryEvidence::PendingIntentObserved
        );
        std::fs::write(&binding, record()).unwrap();
        std::fs::set_permissions(&binding, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            local_recovery_evidence_at(&state),
            LocalRecoveryEvidence::PendingAttemptObserved
        );
        let mismatch = record().replace(ATTEMPT, INVOCATION);
        std::fs::write(&binding, &mismatch).unwrap();
        assert_eq!(
            local_recovery_evidence_at(&state),
            LocalRecoveryEvidence::RecordsInconsistent
        );
        assert_eq!(std::fs::read_to_string(&binding).unwrap(), mismatch);
        assert!(codex_recovery_preflight_at(&state).is_err());
        std::fs::write(&binding, b"partial").unwrap();
        assert_eq!(
            local_recovery_evidence_at(&state),
            LocalRecoveryEvidence::RecordsInconsistent
        );
        std::fs::write(&binding, record()).unwrap();
        std::fs::write(state.join("pending-intent"), b"partial").unwrap();
        assert_eq!(
            local_recovery_evidence_at(&state),
            LocalRecoveryEvidence::RecordsInconsistent
        );
        assert!(codex_recovery_preflight_at(&state).is_err());
    }

    #[test]
    fn pending_intent_survives_process_exit_and_duplicate_is_blocked() {
        const CHILD: &str = "TUCUPI_RECOVERY_INTENT_TEST_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let directory = open_provisioned_state_directory(Path::new(&path)).unwrap();
            persist_pending_intent(&directory, ATTEMPT).unwrap();
            std::process::exit(77);
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        provision_state_directory(root.path(), std::ffi::OsStr::new("state")).unwrap();
        let state = root.path().join("state");
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "recovery_state::tests::pending_intent_survives_process_exit_and_duplicate_is_blocked"])
            .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, &state)
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
            .status().unwrap();
        assert_eq!(result.code(), Some(77));
        assert_eq!(
            local_recovery_evidence_at(&state),
            LocalRecoveryEvidence::PendingIntentObserved
        );
        let path = state.join("pending-intent");
        let before = std::fs::read(&path).unwrap();
        let dir = open_provisioned_state_directory(&state).unwrap();
        assert_eq!(
            persist_pending_intent(&dir, ATTEMPT).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(codex_recovery_preflight_at(&state).is_err());
        std::fs::write(&path, b"partial").unwrap();
        assert_eq!(
            local_recovery_evidence_at(&state),
            LocalRecoveryEvidence::AttemptUnavailableOrInvalid
        );
        assert!(codex_recovery_preflight_at(&state).is_err());
    }

    #[test]
    fn local_evidence_never_calls_missing_or_invalid_records_clean() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.path().join("state");
        assert_eq!(
            local_recovery_evidence_at(&state),
            LocalRecoveryEvidence::StateUnavailable
        );
        provision_state_directory(root.path(), std::ffi::OsStr::new("state")).unwrap();
        assert_eq!(
            local_recovery_evidence_at(&state),
            LocalRecoveryEvidence::AttemptUnavailableOrInvalid
        );
        let attempt = state.join("pending-attempt");
        std::fs::write(&attempt, b"partial").unwrap();
        std::fs::set_permissions(&attempt, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            local_recovery_evidence_at(&state),
            LocalRecoveryEvidence::AttemptUnavailableOrInvalid
        );
        std::fs::write(&attempt, record()).unwrap();
        let before = std::fs::read(&attempt).unwrap();
        assert_eq!(
            local_recovery_evidence_at(&state),
            LocalRecoveryEvidence::PendingAttemptObserved
        );
        assert_eq!(std::fs::read(attempt).unwrap(), before);
        assert!(codex_recovery_preflight_at(&state).is_err());
    }

    #[test]
    fn persisted_identity_rejects_bad_unit_symlink_and_partial_records() {
        let root = tempfile::tempdir().unwrap();
        let directory = OpenOptions::new().read(true).open(root.path()).unwrap();
        let path = root.path().join("pending-attempt");
        assert!(read_attempt_identity(&directory).is_err());
        std::fs::write(&path, record()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_attempt_identity(&directory).unwrap().attempt, ATTEMPT);
        std::fs::write(
            &path,
            record()
                .replace(ATTEMPT, "ffffffffffffffffffffffffffffffff")
                .replacen("attempt=ffffffff", "attempt=01234567", 1),
        )
        .unwrap();
        assert!(read_attempt_identity(&directory).is_err());
        std::fs::write(&path, "tucupi-recovery-attempt-v1\nattempt=").unwrap();
        assert!(read_attempt_identity(&directory).is_err());
        std::fs::remove_file(&path).unwrap();
        symlink(root.path().join("missing"), &path).unwrap();
        assert!(read_attempt_identity(&directory).is_err());
    }

    #[test]
    fn reconciliation_never_clears_on_outage_restart_or_empty_snapshot() {
        let id = AttemptIdentity::parse(&record()).unwrap();
        let snapshot = |boot, epoch, unit, invocation, state, populated| ManagerSnapshot {
            boot,
            manager_epoch: epoch,
            unit,
            invocation,
            active_state: state,
            populated,
        };
        assert_eq!(
            classify_recovery(&id, Err(io::Error::other("synthetic manager unavailable"))),
            RecoveryObservation::ManagerUnavailable
        );
        assert_eq!(
            classify_recovery(&id, Ok(None)),
            RecoveryObservation::UnitMissing
        );
        assert_eq!(
            classify_recovery(
                &id,
                Ok(Some(snapshot(
                    BOOT,
                    "dddddddddddddddddddddddddddddddd",
                    &id.unit,
                    INVOCATION,
                    "inactive",
                    Some(false)
                )))
            ),
            RecoveryObservation::ManagerChanged
        );
        assert_eq!(
            classify_recovery(
                &id,
                Ok(Some(snapshot(
                    "dddddddddddddddddddddddddddddddd",
                    EPOCH,
                    &id.unit,
                    INVOCATION,
                    "inactive",
                    Some(false)
                )))
            ),
            RecoveryObservation::ManagerChanged
        );
        assert_eq!(
            classify_recovery(
                &id,
                Ok(Some(snapshot(
                    BOOT,
                    EPOCH,
                    &id.unit,
                    "dddddddddddddddddddddddddddddddd",
                    "inactive",
                    Some(false)
                )))
            ),
            RecoveryObservation::UnitIdentityMismatch
        );
        assert_eq!(
            classify_recovery(
                &id,
                Ok(Some(snapshot(
                    BOOT,
                    EPOCH,
                    &id.unit,
                    INVOCATION,
                    "active",
                    Some(false)
                )))
            ),
            RecoveryObservation::UnitStillActive
        );
        assert_eq!(
            classify_recovery(
                &id,
                Ok(Some(snapshot(
                    BOOT,
                    EPOCH,
                    &id.unit,
                    INVOCATION,
                    "failed",
                    Some(true)
                )))
            ),
            RecoveryObservation::GroupPopulated
        );
        assert_eq!(
            classify_recovery(
                &id,
                Ok(Some(snapshot(
                    BOOT, EPOCH, &id.unit, INVOCATION, "failed", None
                )))
            ),
            RecoveryObservation::GroupUnknown
        );
        assert_eq!(
            classify_recovery(
                &id,
                Ok(Some(snapshot(
                    BOOT,
                    EPOCH,
                    &id.unit,
                    INVOCATION,
                    "failed",
                    Some(false)
                )))
            ),
            RecoveryObservation::EmptyObservedButUnverified
        );
    }

    #[test]
    fn persisted_attempt_stays_unchanged_after_synthetic_manager_outage_and_restart() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("pending-attempt");
        let original = record();
        std::fs::write(&path, &original).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let directory = OpenOptions::new().read(true).open(root.path()).unwrap();
        let before = read_attempt_identity(&directory).unwrap();
        assert_eq!(
            classify_recovery(&before, Err(io::Error::other("synthetic outage"))),
            RecoveryObservation::ManagerUnavailable
        );
        drop(directory);
        let reopened = OpenOptions::new().read(true).open(root.path()).unwrap();
        let after = read_attempt_identity(&reopened).unwrap();
        assert_eq!(before, after);
        assert_eq!(std::fs::read_to_string(path).unwrap(), original);
        let restarted = ManagerSnapshot {
            boot: BOOT,
            manager_epoch: "dddddddddddddddddddddddddddddddd",
            unit: &after.unit,
            invocation: INVOCATION,
            active_state: "inactive",
            populated: Some(false),
        };
        assert_eq!(
            classify_recovery(&after, Ok(Some(restarted))),
            RecoveryObservation::ManagerChanged
        );
    }

    #[test]
    fn codex_preflight_blocks_missing_and_unreconciled_state() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.path().join("state");
        assert!(codex_recovery_preflight_at(&state).is_err());
        provision_state_directory(root.path(), std::ffi::OsStr::new("state")).unwrap();
        let error = codex_recovery_preflight_at(&state).unwrap_err();
        assert_eq!(error.to_string(), "supervised recovery not reconciled");
    }

    #[test]
    fn explicit_provision_is_exclusive_and_reopenable() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.path().join("state");
        provision_state_directory(root.path(), std::ffi::OsStr::new("state")).unwrap();
        assert!(open_provisioned_state_directory(&state).is_ok());
        assert!(open_provisioned_state_directory(&state).is_ok());
        assert_eq!(
            provision_state_directory(root.path(), std::ffi::OsStr::new("state"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            std::fs::read_to_string(state.join("format")).unwrap(),
            FORMAT_MARKER
        );
    }

    #[test]
    fn interrupted_or_hostile_provisioning_does_not_overwrite() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.path().join("state");
        assert!(provision_state_directory_with_hook(
            root.path(),
            std::ffi::OsStr::new("state"),
            || Err(io::Error::other("synthetic interruption"))
        )
        .is_err());
        assert!(open_provisioned_state_directory(&state).is_err());
        assert!(provision_state_directory(root.path(), std::ffi::OsStr::new("state")).is_err());
        assert!(provision_state_directory(root.path(), std::ffi::OsStr::new("../escape")).is_err());
        let link = root.path().join("link");
        symlink(&state, &link).unwrap();
        assert!(provision_state_directory(root.path(), std::ffi::OsStr::new("link")).is_err());
        assert!(!state.join("format").exists());
    }

    #[test]
    fn invalid_or_symlinked_format_marker_is_not_accepted() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(state.join("format"), b"partial").unwrap();
        std::fs::set_permissions(state.join("format"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        assert!(open_provisioned_state_directory(&state).is_err());
        std::fs::remove_file(state.join("format")).unwrap();
        symlink(root.path().join("missing"), state.join("format")).unwrap();
        assert!(open_provisioned_state_directory(&state).is_err());
    }

    #[test]
    fn recovery_directory_requires_explicit_private_provisioning() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        assert!(open_private_state_directory(&state).is_err());
        assert!(!state.exists());
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(open_private_state_directory(&state).is_ok());
        // A separate open simulates only reopening, not manager reconciliation.
        assert!(open_private_state_directory(&state).is_ok());
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(open_private_state_directory(&state).is_err());
    }

    #[test]
    fn recovery_directory_rejects_symlinks_files_and_relative_paths() {
        let root = tempfile::tempdir().unwrap();
        let link = root.path().join("link");
        symlink(root.path(), &link).unwrap();
        assert!(open_private_state_directory(&link).is_err());
        let file = root.path().join("file");
        std::fs::write(&file, b"synthetic").unwrap();
        assert!(open_private_state_directory(&file).is_err());
        assert!(open_private_state_directory(Path::new("relative")).is_err());
    }
}
