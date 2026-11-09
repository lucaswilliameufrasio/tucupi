//! Experimental Linux cgroup checks. These do not establish isolation, verify
//! process ownership or cleanup, or authorize starting a provider.

use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::{Component, Path, PathBuf};

const MEMORY_MAX: u64 = 512 * 1024 * 1024;
const TASKS_MAX: u64 = 64;

/// Experimental, monotonic fixture marker in a caller-provided private directory.
/// This is not production recovery, cgroup ownership, or a cleanup proof.
#[cfg(feature = "codex-fixture")]
pub struct FixtureRecoveryMarker {
    directory: std::fs::File,
    path: PathBuf,
}

#[cfg(feature = "codex-fixture")]
impl FixtureRecoveryMarker {
    pub fn open(directory: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let pinned = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory)?;
        let result = Self {
            directory: pinned,
            path: directory.to_path_buf(),
        };
        result.verify_directory_identity()?;
        Ok(result)
    }

    // A point-in-time check only; this does not make a caller-selected path
    // trustworthy or prevent a concurrent replacement after verification.
    fn verify_directory_identity(&self) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let pinned = self.directory.metadata()?;
        let current = std::fs::symlink_metadata(&self.path)?;
        if !current.file_type().is_dir()
            || pinned.nlink() == 0
            || (pinned.dev(), pinned.ino()) != (current.dev(), current.ino())
        {
            return Err(std::io::Error::other(
                "fixture state directory identity changed",
            ));
        }
        Ok(())
    }

    fn marker_path(&self) -> PathBuf {
        PathBuf::from(format!(
            "/proc/self/fd/{}/unverified",
            self.directory.as_raw_fd()
        ))
    }

    /// Persist a marker before fixture work. Existing markers and all errors
    /// reject admission; there is deliberately no clearing operation.
    pub fn arm(&self) -> std::io::Result<()> {
        self.create_marker(None)
    }

    /// Record a synthetic attempt identifier; it is not systemd identity.
    pub fn arm_with_identity(&self, identity: &str) -> std::io::Result<()> {
        if identity.len() != 32 || !identity.bytes().all(|value| value.is_ascii_hexdigit()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid fixture attempt identity",
            ));
        }
        self.create_marker(Some(identity))
    }

    /// Append one fixture-only observation. Neither the unit name nor the
    /// invocation ID is authenticated or evidence of cleanup or ownership.
    pub fn bind_fixture_unit(
        &self,
        identity: &str,
        unit: &str,
        invocation: &str,
    ) -> std::io::Result<()> {
        self.verify_directory_identity()?;
        use std::io::{Read, Write};
        use std::os::unix::fs::OpenOptionsExt;
        let unit_id = unit
            .strip_prefix("tucupi-registry-test-")
            .and_then(|value| value.strip_suffix(".service"))
            .unwrap_or("");
        let valid =
            |value: &str| value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
        if !valid(identity) || !valid(unit_id) || !valid(invocation) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid fixture binding",
            ));
        }
        let marker = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.marker_path())?;
        let mut content = String::new();
        marker.take(128).read_to_string(&mut content)?;
        if content != format!("fixture-attempt-v1:{identity}\n") {
            return Err(std::io::Error::other("fixture attempt mismatch"));
        }
        let path = PathBuf::from(format!(
            "/proc/self/fd/{}/unit-observation",
            self.directory.as_raw_fd()
        ));
        let mut record = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        writeln!(record, "fixture-unit-v1:{identity}:{unit}:{invocation}")?;
        record.sync_all()?;
        self.directory.sync_all()?;
        self.verify_directory_identity()
    }

    fn create_marker(&self, identity: Option<&str>) -> std::io::Result<()> {
        self.create_marker_with_hook(identity, || {})
    }

    fn create_marker_with_hook(
        &self,
        identity: Option<&str>,
        before_final_check: impl FnOnce(),
    ) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        self.verify_directory_identity()?;
        let mut marker = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.marker_path())?;
        if let Some(identity) = identity {
            writeln!(marker, "fixture-attempt-v1:{identity}")?;
        }
        marker.sync_all()?;
        self.directory.sync_all()?;
        before_final_check();
        self.verify_directory_identity()
    }

    /// The caller must treat any error as blocked. A missing marker is only
    /// meaningful under the experiment's trusted, existing directory premise.
    pub fn blocked(&self) -> std::io::Result<bool> {
        self.verify_directory_identity()?;
        let blocked = match std::fs::symlink_metadata(self.marker_path()) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }?;
        self.verify_directory_identity()?;
        Ok(blocked)
    }
}

#[cfg(feature = "codex-fixture")]
fn fixture_membership_matches(text: &str, expected: &Path) -> bool {
    let mut unified = text.lines().filter_map(|line| line.strip_prefix("0::"));
    match (unified.next(), unified.next()) {
        (Some(path), None) => Path::new(path) == expected,
        _ => false,
    }
}

/// Pins an observed directory against later replacement of its pathname.
/// Opening it does not prove that it is a cgroup, belongs to this attempt,
/// or cannot be repopulated. It must never authorize a review by itself.
pub struct CgroupObservation {
    directory: std::fs::File,
}

/// Fixture-only cancellation handle opened by the pinned-directory check.
/// This type does not establish ownership of the cgroup.
#[cfg(feature = "codex-fixture")]
pub(crate) struct FixtureKillHandle {
    file: std::fs::File,
    pinned: Option<(std::fs::File, PathBuf)>,
}

#[cfg(feature = "codex-fixture")]
impl FixtureKillHandle {
    pub(crate) fn request_stop(&mut self) -> Result<(), &'static str> {
        use std::io::Write;
        use std::os::unix::fs::MetadataExt;
        if let Some((directory, expected)) = &self.pinned {
            let pinned_path = format!("/proc/self/fd/{}", directory.as_raw_fd());
            let link =
                std::fs::read_link(pinned_path).map_err(|_| "fixture cancellation unavailable")?;
            let pinned = directory
                .metadata()
                .map_err(|_| "fixture cancellation unavailable")?;
            let current =
                std::fs::metadata(expected).map_err(|_| "fixture cancellation unavailable")?;
            if link != *expected || (pinned.dev(), pinned.ino()) != (current.dev(), current.ino()) {
                return Err("fixture cancellation unavailable");
            }
        }
        self.file
            .write_all(b"1")
            .map_err(|_| "fixture cancellation unavailable")
    }

    #[cfg(test)]
    pub(crate) fn synthetic(file: std::fs::File) -> Self {
        Self { file, pinned: None }
    }
}

/// Observations only; none establishes ownership, isolation, or safe cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupSequenceState {
    Populated,
    EmptyAfterPopulated,
}

/// Tracks one pinned directory. Errors are terminal, including repopulation.
/// A valid sequence alone must never authorize promotion of a review.
pub struct CgroupSequence {
    observation: CgroupObservation,
    state: Option<CgroupSequenceState>,
    failed: bool,
    #[cfg(feature = "codex-fixture")]
    cancellation_requested: bool,
}

impl CgroupSequence {
    pub fn new(observation: CgroupObservation) -> Self {
        Self {
            observation,
            state: None,
            failed: false,
            #[cfg(feature = "codex-fixture")]
            cancellation_requested: false,
        }
    }

    /// Synthetic delegated-cgroup experiment only. This does not establish
    /// ownership or permit promotion of a review result.
    #[cfg(feature = "codex-fixture")]
    pub(crate) fn cancel_fixture(&mut self) -> Result<(), &'static str> {
        if self.failed
            || self.cancellation_requested
            || self.state != Some(CgroupSequenceState::Populated)
        {
            return Err("invalid fixture cancellation state");
        }
        self.cancellation_requested = true;
        let result = (|| self.observation.fixture_kill_handle()?.request_stop())();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    pub fn observe(&mut self) -> Result<CgroupSequenceState, &'static str> {
        if self.failed {
            return Err("cgroup observation invalidated");
        }
        let populated = match self.observation.populated() {
            Ok(populated) => populated,
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        let next = match (self.state, populated) {
            (None, true) | (Some(CgroupSequenceState::Populated), true) => {
                CgroupSequenceState::Populated
            }
            (
                Some(CgroupSequenceState::Populated | CgroupSequenceState::EmptyAfterPopulated),
                false,
            ) => CgroupSequenceState::EmptyAfterPopulated,
            _ => {
                self.failed = true;
                return Err("invalid cgroup observation sequence");
            }
        };
        self.state = Some(next);
        Ok(next)
    }

    #[cfg(feature = "codex-fixture")]
    pub(crate) fn verify_fixture_child(
        &self,
        child: &mut std::process::Child,
    ) -> Result<(), &'static str> {
        self.observation.verify_fixture_child(child)
    }
}

impl CgroupObservation {
    /// Test-only handle to the pinned, expected fixture child group. A file
    /// descriptor and matching path do not establish production ownership.
    #[cfg(feature = "codex-fixture")]
    pub(crate) fn fixture_kill_handle(&self) -> Result<FixtureKillHandle, &'static str> {
        let membership =
            std::fs::read_to_string("/proc/self/cgroup").map_err(|_| "cgroup unavailable")?;
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::/"))
            .ok_or("cgroup unavailable")?;
        let relative = Path::new(relative);
        if relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err("invalid fixture cgroup");
        }
        let expected = Path::new("/sys/fs/cgroup")
            .join(relative)
            .join("tucupi-child-fixture");
        let pinned = format!("/proc/self/fd/{}", self.directory.as_raw_fd());
        if std::fs::read_link(&pinned).map_err(|_| "cgroup unavailable")? != expected {
            return Err("unexpected fixture cgroup");
        }
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(format!("{pinned}/cgroup.kill"))
            .map_err(|_| "fixture cancellation unavailable")?;
        let directory = self
            .directory
            .try_clone()
            .map_err(|_| "fixture cancellation unavailable")?;
        Ok(FixtureKillHandle {
            file,
            pinned: Some((directory, expected)),
        })
    }

    /// Test-only admission of a child held by this process. This is not an
    /// isolation boundary or an ownership guarantee for production.
    #[cfg(feature = "codex-fixture")]
    pub fn admit_fixture_child(&self, child: &mut std::process::Child) -> Result<(), &'static str> {
        use std::io::Write;
        if child
            .try_wait()
            .map_err(|_| "fixture child unavailable")?
            .is_some()
        {
            return Err("fixture child already exited");
        }
        let membership =
            std::fs::read_to_string("/proc/self/cgroup").map_err(|_| "cgroup unavailable")?;
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::/"))
            .ok_or("cgroup unavailable")?;
        let relative = Path::new(relative);
        if relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err("invalid fixture cgroup");
        }
        let expected = Path::new("/sys/fs/cgroup")
            .join(relative)
            .join("tucupi-child-fixture");
        let pinned = format!("/proc/self/fd/{}", self.directory.as_raw_fd());
        if std::fs::read_link(&pinned).map_err(|_| "cgroup unavailable")? != expected {
            return Err("unexpected fixture cgroup");
        }
        let mut procs = std::fs::OpenOptions::new()
            .write(true)
            .open(format!("{pinned}/cgroup.procs"))
            .map_err(|_| "fixture admission unavailable")?;
        write!(procs, "{}", child.id()).map_err(|_| "fixture admission unavailable")?;
        self.verify_fixture_child(child)
    }

    /// Point-in-time fixture diagnostic, not a process or cgroup ownership proof.
    #[cfg(feature = "codex-fixture")]
    pub(crate) fn verify_fixture_child(
        &self,
        child: &mut std::process::Child,
    ) -> Result<(), &'static str> {
        let membership =
            std::fs::read_to_string("/proc/self/cgroup").map_err(|_| "cgroup unavailable")?;
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::/"))
            .ok_or("cgroup unavailable")?;
        let relative = Path::new(relative);
        if relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err("invalid fixture cgroup");
        }
        let expected = Path::new("/sys/fs/cgroup")
            .join(relative)
            .join("tucupi-child-fixture");
        let pinned = format!("/proc/self/fd/{}", self.directory.as_raw_fd());
        if std::fs::read_link(&pinned).map_err(|_| "cgroup unavailable")? != expected {
            return Err("unexpected fixture cgroup");
        }
        let child_membership = std::fs::read_to_string(format!("/proc/{}/cgroup", child.id()))
            .map_err(|_| "fixture child membership unavailable")?;
        let expected_membership = Path::new("/").join(relative).join("tucupi-child-fixture");
        if !fixture_membership_matches(&child_membership, &expected_membership) {
            return Err("fixture child membership mismatch");
        }
        if child
            .try_wait()
            .map_err(|_| "fixture child unavailable")?
            .is_some()
        {
            return Err("fixture child already exited");
        }
        Ok(())
    }

    pub fn open(group: &Path) -> Result<Self, &'static str> {
        let directory = std::fs::File::open(group).map_err(|_| "cgroup unavailable")?;
        if !directory
            .metadata()
            .map_err(|_| "cgroup unavailable")?
            .is_dir()
        {
            return Err("cgroup unavailable");
        }
        Ok(Self { directory })
    }

    pub fn populated(&self) -> Result<bool, &'static str> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(format!(
                "/proc/self/fd/{}/cgroup.events",
                self.directory.as_raw_fd()
            ))
            .map_err(|_| "cgroup events unavailable")?;
        if !file
            .metadata()
            .map_err(|_| "cgroup events unavailable")?
            .is_file()
        {
            return Err("invalid cgroup events");
        }
        let mut bytes = Vec::new();
        file.take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| "cgroup events unavailable")?;
        if bytes.len() > 4096 {
            return Err("invalid cgroup events");
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| "invalid cgroup events")?;
        let mut populated = None;
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            if fields.next() == Some("populated") {
                let value = match fields.next() {
                    Some("0") => false,
                    Some("1") => true,
                    _ => return Err("invalid cgroup events"),
                };
                if fields.next().is_some() || populated.replace(value).is_some() {
                    return Err("invalid cgroup events");
                }
            }
        }
        populated.ok_or("invalid cgroup events")
    }
}

/// Convenience observation; not cleanup or ownership proof.
pub fn observe_cgroup_populated(group: &Path) -> Result<bool, &'static str> {
    CgroupObservation::open(group)?.populated()
}

/// Compare the current cgroup membership with a path obtained by the trusted
/// supervisor. This is only a point-in-time check, not an ownership guarantee.
pub fn check_current_cgroup_matches(expected: &str) -> Result<(), &'static str> {
    let membership = std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|_| "cgroup membership unavailable")?;
    check_membership(&membership, expected)
}

fn check_membership(membership: &str, expected: &str) -> Result<(), &'static str> {
    let mut entries = membership
        .lines()
        .filter_map(|line| line.strip_prefix("0::"));
    let actual = entries.next().ok_or("unified cgroup unavailable")?;
    if entries.next().is_some() || expected.is_empty() || actual != expected {
        return Err("cgroup membership mismatch");
    }
    Ok(())
}

/// Inspect configured cgroup-v2 limits for the current process. Success is not
/// proof that a sandbox, credentials, descendants, or resource limits are safe.
pub fn check_current_cgroup_limits() -> Result<(), &'static str> {
    let membership = std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|_| "cgroup membership unavailable")?;
    let path = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or("unified cgroup unavailable")?;
    let relative = Path::new(path)
        .strip_prefix("/")
        .map_err(|_| "invalid cgroup membership")?;
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("invalid cgroup membership");
    }
    let group: PathBuf = Path::new("/sys/fs/cgroup").join(relative);
    check_limits(&group)
}

fn check_limits(group: &Path) -> Result<(), &'static str> {
    let read_number = |file: &str| -> Result<u64, &'static str> {
        let value =
            std::fs::read_to_string(group.join(file)).map_err(|_| "cgroup limit unavailable")?;
        value
            .trim()
            .parse::<u64>()
            .map_err(|_| "invalid cgroup limit")
    };
    let memory = read_number("memory.max")?;
    let tasks = read_number("pids.max")?;
    if memory == 0 || memory > MEMORY_MAX || tasks == 0 || tasks > TASKS_MAX {
        return Err("cgroup limit exceeds fixture policy");
    }
    let cpu =
        std::fs::read_to_string(group.join("cpu.max")).map_err(|_| "cgroup limit unavailable")?;
    let mut fields = cpu.split_whitespace();
    let quota = fields
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or("invalid cpu limit")?;
    let period = fields
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or("invalid cpu limit")?;
    if fields.next().is_some()
        || quota == 0
        || period == 0
        || u128::from(quota) * 2 > u128::from(period)
    {
        return Err("cpu limit exceeds fixture policy");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn invalid_cgroup_events_are_nonblocking_and_permanently_unknown() {
        use super::{CgroupObservation, CgroupSequence};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let fifo_group = root.path().join("fifo");
        std::fs::create_dir(&fifo_group).unwrap();
        let fifo = fifo_group.join("cgroup.events");
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: path is NUL terminated and points into this temporary tree.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let mut sequence = CgroupSequence::new(CgroupObservation::open(&fifo_group).unwrap());
        assert!(sequence.observe().is_err());
        assert!(sequence.observe().is_err());

        let symlink_group = root.path().join("symlink");
        std::fs::create_dir(&symlink_group).unwrap();
        let fake = root.path().join("fake-events");
        std::fs::write(&fake, b"populated 0\n").unwrap();
        symlink(&fake, symlink_group.join("cgroup.events")).unwrap();
        let mut sequence = CgroupSequence::new(CgroupObservation::open(&symlink_group).unwrap());
        assert!(sequence.observe().is_err());
        assert!(sequence.observe().is_err());
        assert_eq!(std::fs::read(fake).unwrap(), b"populated 0\n");
    }
    use super::*;

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn fixture_marker_rejects_directory_replacement_during_commit() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let moved = root.path().join("old-state");
        std::fs::create_dir(&state).unwrap();
        let marker = FixtureRecoveryMarker::open(&state).unwrap();
        let result =
            marker.create_marker_with_hook(Some("0123456789abcdef0123456789abcdef"), || {
                std::fs::rename(&state, &moved).unwrap();
                std::fs::create_dir(&state).unwrap();
            });
        assert!(result.is_err());
        assert!(marker.blocked().is_err());
        assert!(moved.join("unverified").exists());
        assert!(!state.join("unverified").exists());
        // An independently reopened replacement still cannot know the old
        // directory existed: this hook is not a trusted persistent anchor.
        assert!(!FixtureRecoveryMarker::open(&state)
            .unwrap()
            .blocked()
            .unwrap());
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn fixture_recovery_rejects_replaced_state_directory() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let moved = root.path().join("old-state");
        std::fs::create_dir(&state).unwrap();
        let marker = FixtureRecoveryMarker::open(&state).unwrap();
        std::fs::rename(&state, &moved).unwrap();
        std::fs::create_dir(&state).unwrap();
        assert!(marker.blocked().is_err());
        assert!(marker.arm().is_err());
        assert!(!moved.join("unverified").exists());
        // A new process sees only the replacement: no durable root of trust
        // currently tells it an older directory existed.
        let replacement = FixtureRecoveryMarker::open(&state).unwrap();
        assert!(!replacement.blocked().unwrap());
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn fixture_binding_requires_matching_attempt_and_cannot_be_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let marker = FixtureRecoveryMarker::open(dir.path()).unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        let other = "ffffffffffffffffffffffffffffffff";
        let unit = "tucupi-registry-test-0123456789abcdef0123456789abcdef.service";
        let invocation = "abcdefabcdefabcdefabcdefabcdefab";
        assert!(marker.bind_fixture_unit(id, unit, invocation).is_err());
        marker.arm_with_identity(id).unwrap();
        assert!(marker.bind_fixture_unit(other, unit, invocation).is_err());
        assert!(marker
            .bind_fixture_unit(id, "other.service", invocation)
            .is_err());
        marker.bind_fixture_unit(id, unit, invocation).unwrap();
        assert!(marker.bind_fixture_unit(id, unit, invocation).is_err());
        assert!(marker.blocked().unwrap());
        assert!(std::fs::read_to_string(dir.path().join("unit-observation"))
            .unwrap()
            .contains(invocation));
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn fixture_identity_is_validated_and_partial_record_stays_blocked() {
        let directory = tempfile::tempdir().unwrap();
        let marker = FixtureRecoveryMarker::open(directory.path()).unwrap();
        assert!(marker.arm_with_identity("../invalid").is_err());
        assert!(!marker.blocked().unwrap());
        std::fs::write(directory.path().join("unverified"), b"fixture-attempt-v1:").unwrap();
        assert!(marker.blocked().unwrap());
        assert!(marker
            .arm_with_identity("0123456789abcdef0123456789abcdef")
            .is_err());
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn fixture_recovery_marker_blocks_reopen_and_rejects_second_admission() {
        let dir = tempfile::tempdir().unwrap();
        let first = FixtureRecoveryMarker::open(dir.path()).unwrap();
        assert!(!first.blocked().unwrap());
        first.arm().unwrap();
        drop(first);
        let restarted = FixtureRecoveryMarker::open(dir.path()).unwrap();
        assert!(restarted.blocked().unwrap());
        assert_eq!(
            restarted.arm().unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn fixture_recovery_marker_fails_closed_on_deleted_directory_and_symlinks() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("state");
        std::fs::create_dir(&directory).unwrap();
        let marker = FixtureRecoveryMarker::open(&directory).unwrap();
        symlink("missing", directory.join("unverified")).unwrap();
        assert!(marker.blocked().unwrap());
        assert!(marker.arm().is_err());
        std::fs::remove_file(directory.join("unverified")).unwrap();
        std::fs::remove_dir(&directory).unwrap();
        assert!(marker.blocked().is_err());
        assert!(marker.arm().is_err());
        symlink(root.path(), &directory).unwrap();
        assert!(FixtureRecoveryMarker::open(&directory).is_err());
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    #[ignore = "requires a dedicated delegated systemd user unit"]
    fn stale_fixture_handle_rejects_recreated_group() {
        let membership = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::/"))
            .unwrap();
        let relative = Path::new(relative);
        assert!(relative
            .components()
            .all(|part| matches!(part, Component::Normal(_))));
        let group = Path::new("/sys/fs/cgroup")
            .join(relative)
            .join("tucupi-child-fixture");
        std::fs::create_dir(&group).unwrap();
        let observation = CgroupObservation::open(&group).unwrap();
        let mut old_handle = observation.fixture_kill_handle().unwrap();
        std::fs::remove_dir(&group).unwrap();
        std::fs::create_dir(&group).unwrap();
        let mut child = std::process::Command::new("/usr/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        std::fs::write(group.join("cgroup.procs"), child.id().to_string()).unwrap();
        let stop_result = old_handle.request_stop();
        let child_was_running = matches!(child.try_wait(), Ok(None));
        let _ = child.kill();
        let reaped = child.wait().is_ok();
        assert_eq!(stop_result, Err("fixture cancellation unavailable"));
        assert!(child_was_running);
        assert!(reaped);
        std::fs::remove_dir(&group).unwrap();
        println!("stale fixture handle rejected; replacement child remained running");
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn fixture_membership_requires_one_exact_unified_path() {
        let expected = Path::new("/synthetic/tucupi-child-fixture");
        assert!(fixture_membership_matches(
            "0::/synthetic/tucupi-child-fixture\n",
            expected
        ));
        for text in [
            "0::/synthetic/other\n",
            "0::/synthetic/tucupi-child-fixture/subgroup\n",
            "0::/synthetic/tucupi-child-fixture (deleted)\n",
            "0::/synthetic/tucupi-child-fixture\n0::/synthetic/tucupi-child-fixture\n",
            "1:name=/synthetic/tucupi-child-fixture\n",
        ] {
            assert!(!fixture_membership_matches(text, expected));
        }
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn fixture_kill_handle_refuses_unrelated_directory_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let kill = dir.path().join("cgroup.kill");
        std::fs::write(&kill, "untouched").unwrap();
        let observation = CgroupObservation::open(dir.path()).unwrap();
        assert!(observation.fixture_kill_handle().is_err());
        assert_eq!(std::fs::read_to_string(kill).unwrap(), "untouched");
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn fixture_admission_refuses_unrelated_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cgroup.procs");
        std::fs::write(&path, "untouched").unwrap();
        let observation = CgroupObservation::open(dir.path()).unwrap();
        let marker = dir.path().join("started");
        let mut child = std::process::Command::new("/usr/bin/python3")
            .args([
                "-c",
                "import pathlib,sys; sys.stdin.buffer.read(1); pathlib.Path(sys.argv[1]).touch()",
            ])
            .arg(&marker)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let result = observation.admit_fixture_child(&mut child);
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(result.is_err());
        assert!(!marker.exists());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "untouched");
    }

    #[cfg(feature = "codex-fixture")]
    #[test]
    fn fixture_cancellation_rejects_unowned_path_and_invalidates_observation() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cgroup.events"), "populated 1\n").unwrap();
        std::fs::write(dir.path().join("cgroup.kill"), "untouched").unwrap();
        let mut sequence = CgroupSequence::new(CgroupObservation::open(dir.path()).unwrap());
        assert_eq!(sequence.observe(), Ok(CgroupSequenceState::Populated));
        assert!(sequence.cancel_fixture().is_err());
        assert!(sequence.cancel_fixture().is_err());
        assert!(sequence.observe().is_err());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("cgroup.kill")).unwrap(),
            "untouched"
        );
    }

    #[test]
    fn sequence_requires_population_and_permanently_rejects_repopulation() {
        let dir = tempfile::tempdir().unwrap();
        let events = dir.path().join("cgroup.events");
        std::fs::write(&events, "populated 0\n").unwrap();
        let mut premature = CgroupSequence::new(CgroupObservation::open(dir.path()).unwrap());
        assert!(premature.observe().is_err());
        std::fs::write(&events, "populated 1\n").unwrap();
        assert!(premature.observe().is_err());
        let mut sequence = CgroupSequence::new(CgroupObservation::open(dir.path()).unwrap());
        assert_eq!(sequence.observe(), Ok(CgroupSequenceState::Populated));
        std::fs::write(&events, "populated 0\n").unwrap();
        assert_eq!(
            sequence.observe(),
            Ok(CgroupSequenceState::EmptyAfterPopulated)
        );
        std::fs::write(&events, "populated 1\n").unwrap();
        assert!(sequence.observe().is_err());
        std::fs::write(&events, "populated 0\n").unwrap();
        assert!(sequence.observe().is_err());
        std::fs::write(&events, "populated 1\n").unwrap();
        let mut missing = CgroupSequence::new(CgroupObservation::open(dir.path()).unwrap());
        assert_eq!(missing.observe(), Ok(CgroupSequenceState::Populated));
        std::fs::remove_file(&events).unwrap();
        assert!(missing.observe().is_err());
        std::fs::write(&events, "populated 0\n").unwrap();
        assert!(missing.observe().is_err());
    }

    #[test]
    fn observation_keeps_original_directory_after_path_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("group");
        std::fs::create_dir(&original).unwrap();
        std::fs::write(original.join("cgroup.events"), "populated 1\n").unwrap();
        let observation = CgroupObservation::open(&original).unwrap();
        std::fs::rename(&original, dir.path().join("old")).unwrap();
        std::fs::create_dir(&original).unwrap();
        std::fs::write(original.join("cgroup.events"), "populated 0\n").unwrap();
        assert_eq!(observation.populated(), Ok(true));
        assert_eq!(observe_cgroup_populated(&original), Ok(false));
    }

    #[test]
    fn cgroup_population_observation_fails_closed_on_missing_or_malformed_events() {
        let dir = tempfile::tempdir().unwrap();
        let events = dir.path().join("cgroup.events");
        assert!(observe_cgroup_populated(dir.path()).is_err());
        for (body, expected) in [
            ("populated 0\nfrozen 0\n", false),
            ("populated 1\nfrozen 0\n", true),
        ] {
            std::fs::write(&events, body).unwrap();
            assert_eq!(observe_cgroup_populated(dir.path()), Ok(expected));
        }
        for body in [
            "frozen 0\n",
            "populated 2\n",
            "populated 0 extra\n",
            "populated 0\npopulated 1\n",
        ] {
            std::fs::write(&events, body).unwrap();
            assert!(observe_cgroup_populated(dir.path()).is_err());
        }
        std::fs::write(&events, vec![b'x'; 4097]).unwrap();
        assert!(observe_cgroup_populated(dir.path()).is_err());
    }

    #[test]
    fn membership_requires_one_exact_supervisor_selected_cgroup() {
        assert!(check_membership("0::/fixture.service\n", "/fixture.service").is_ok());
        assert!(check_membership("0::/other.service\n", "/fixture.service").is_err());
        assert!(check_membership("0::/fixture.service\n0::/other\n", "/fixture.service").is_err());
        assert!(check_membership("0::/fixture.service\n", "").is_err());
        assert!(check_membership("1:cpu:/fixture.service\n", "/fixture.service").is_err());
    }

    #[test]
    fn limits_fail_closed_for_missing_unlimited_or_excessive_values() {
        let dir = tempfile::tempdir().unwrap();
        let group = dir.path();
        assert!(check_limits(group).is_err());
        std::fs::write(group.join("memory.max"), "536870912").unwrap();
        std::fs::write(group.join("pids.max"), "64").unwrap();
        std::fs::write(group.join("cpu.max"), "50000 100000").unwrap();
        assert!(check_limits(group).is_ok());
        for (file, invalid, valid) in [
            ("memory.max", "max", "536870912"),
            ("memory.max", "536870913", "536870912"),
            ("pids.max", "65", "64"),
            ("cpu.max", "max 100000", "50000 100000"),
            ("cpu.max", "50001 100000", "50000 100000"),
            ("cpu.max", "0 100000", "50000 100000"),
        ] {
            std::fs::write(group.join(file), invalid).unwrap();
            assert!(check_limits(group).is_err(), "{file}: {invalid}");
            std::fs::write(group.join(file), valid).unwrap();
        }
    }
}
