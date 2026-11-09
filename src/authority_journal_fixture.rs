//! Synthetic single-writer journal. This is not protected from the same UID,
//! is not an authority, and must never be used to authorize production work.

use crate::authority_lifecycle_fixture::{Event, State};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const MAX_RECORD: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub version: u64,
    pub state: State,
    /// Unauthenticated fixture evidence, absent in older records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interrupted_phase: Option<InterruptedPhase>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InterruptedPhase {
    Intent,
    Bound,
    ReleaseRecorded,
    DirectChildExited { success: bool },
}

/// Structural consistency only; matching values are not authenticated.
pub(crate) fn valid_recorded_phase(state: State, phase: Option<InterruptedPhase>) -> bool {
    matches!(
        (state, phase),
        (_, None)
            | (
                State::RecoveryRequired {
                    incarnation: None,
                    ..
                },
                Some(InterruptedPhase::Intent),
            )
            | (
                State::RecoveryRequired {
                    incarnation: Some(_),
                    ..
                },
                Some(
                    InterruptedPhase::Bound
                        | InterruptedPhase::ReleaseRecorded
                        | InterruptedPhase::DirectChildExited { .. }
                ),
            )
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    None,
    BeforeRename,
    AfterRename,
}

/// Missing, malformed and oversized records remain errors, never `Ready`.
pub fn load(directory: &Path) -> io::Result<Snapshot> {
    let mut bytes = Vec::new();
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(directory.join("state.json"))?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture record is not a regular file",
        ));
    }
    file.take(MAX_RECORD + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture record too large",
        ));
    }
    let snapshot: Snapshot = serde_json::from_slice(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid fixture record"))?;
    if !valid_recorded_phase(snapshot.state, snapshot.interrupted_phase) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inconsistent fixture recovery phase",
        ));
    }
    Ok(snapshot)
}

/// Initialization is explicit and refuses to overwrite an existing record.
pub fn initialize(directory: &Path) -> io::Result<Snapshot> {
    let snapshot = Snapshot {
        version: 0,
        state: State::Unprovisioned,
        interrupted_phase: None,
    };
    let mut temp = tempfile::NamedTempFile::new_in(directory)?;
    serde_json::to_writer(&mut temp, &snapshot)?;
    temp.flush()?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(directory.join("state.json"))
        .map_err(|error| error.error)?;
    File::open(directory)?.sync_all()?;
    Ok(snapshot)
}

/// Cooperating fixture writers serialize through the shared advisory lock.
/// Same-UID replacement and writers that ignore the lock remain unprotected.
pub fn publish(
    directory: &Path,
    expected: Snapshot,
    event: Event,
    fault: Fault,
) -> io::Result<Snapshot> {
    let lock = crate::authority_transport_fixture::acquire_cooperative_lock(directory)?;
    publish_locked(&lock, directory, expected, event, fault)
}

/// Caller must hold the fixture's cooperative lock for the complete operation.
pub(crate) fn publish_locked(
    lock: &crate::authority_transport_fixture::CooperativeLock,
    directory: &Path,
    expected: Snapshot,
    event: Event,
    fault: Fault,
) -> io::Result<Snapshot> {
    lock.check_directory(directory)?;
    if load(directory)? != expected {
        return Err(io::Error::other("stale fixture snapshot"));
    }
    let next = Snapshot {
        version: expected
            .version
            .checked_add(1)
            .ok_or_else(|| io::Error::other("fixture version exhausted"))?,
        state: expected.state.apply(event).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid fixture transition")
        })?,
        interrupted_phase: match (expected.state, event) {
            (State::Intent { .. }, Event::Interrupted) => Some(InterruptedPhase::Intent),
            (State::Bound { .. }, Event::Interrupted) => Some(InterruptedPhase::Bound),
            (State::Released { .. }, Event::Interrupted) => Some(InterruptedPhase::ReleaseRecorded),
            (State::DirectChildExited { success, .. }, Event::Interrupted) => {
                Some(InterruptedPhase::DirectChildExited { success })
            }
            (State::RecoveryRequired { .. }, Event::Interrupted) => expected.interrupted_phase,
            _ => None,
        },
    };
    let mut temp = tempfile::NamedTempFile::new_in(directory)?;
    serde_json::to_writer(&mut temp, &next)?;
    temp.flush()?;
    temp.as_file().sync_all()?;
    if fault == Fault::BeforeRename {
        return Err(io::Error::other("synthetic failure before rename"));
    }
    lock.check_directory(directory)?;
    fs::rename(temp.path(), directory.join("state.json"))?;
    if fault == Fault::AfterRename {
        return Err(io::Error::other(
            "synthetic failure after rename; outcome ambiguous",
        ));
    }
    // An error here is ambiguous: rename may already have published the record.
    lock.check_directory(directory)?;
    File::open(directory)?.sync_all()?;
    Ok(next)
}

/// Synthetic single-writer startup reconciliation. A pending record is
/// persisted as recovery-required before it is returned; errors (including an
/// ambiguous post-rename error) must be treated as unavailable by the caller.
/// This does not inspect or stop processes, authenticate state, or prove that
/// a stored Ready record is clean. It must not be used as an authorization.
pub fn reopen_for_recovery(directory: &Path, fault: Fault) -> io::Result<Snapshot> {
    let lock = crate::authority_transport_fixture::acquire_cooperative_lock(directory)?;
    reopen_for_recovery_locked(&lock, directory, fault)
}

/// Caller must hold the fixture's cooperative lock.
pub(crate) fn reopen_for_recovery_locked(
    lock: &crate::authority_transport_fixture::CooperativeLock,
    directory: &Path,
    fault: Fault,
) -> io::Result<Snapshot> {
    lock.check_directory(directory)?;
    let current = load(directory)?;
    match current.state {
        State::Intent { .. }
        | State::Bound { .. }
        | State::Released { .. }
        | State::DirectChildExited { .. } => {
            publish_locked(lock, directory, current, Event::Interrupted, fault)
        }
        State::Unprovisioned | State::Ready | State::RecoveryRequired { .. } => Ok(current),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaced_lock_or_directory_rejects_reconciliation_and_publication() {
        for replace_directory in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("active");
            fs::create_dir(&path).unwrap();
            let initial = initialize(&path).unwrap();
            let lock = crate::authority_transport_fixture::acquire_cooperative_lock(&path).unwrap();
            if replace_directory {
                fs::rename(&path, root.path().join("old")).unwrap();
                fs::create_dir(&path).unwrap();
                initialize(&path).unwrap();
            } else {
                fs::rename(path.join("server.lock"), path.join("old.lock")).unwrap();
                fs::write(path.join("server.lock"), b"").unwrap();
            }
            let before = fs::read(path.join("state.json")).unwrap();
            assert!(
                publish_locked(&lock, &path, initial, Event::Provisioned, Fault::None).is_err()
            );
            assert!(reopen_for_recovery_locked(&lock, &path, Fault::None).is_err());
            assert_eq!(fs::read(path.join("state.json")).unwrap(), before);
        }
    }

    #[test]
    fn locked_operations_reject_guard_from_another_fixture_directory() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        initialize(first.path()).unwrap();
        let other = initialize(second.path()).unwrap();
        let lock =
            crate::authority_transport_fixture::acquire_cooperative_lock(first.path()).unwrap();
        assert_eq!(
            publish_locked(&lock, second.path(), other, Event::Provisioned, Fault::None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            reopen_for_recovery_locked(&lock, second.path(), Fault::None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(load(second.path()).unwrap(), other);
    }

    #[test]
    fn contradictory_phase_records_are_unavailable_not_recovered() {
        let dir = tempfile::tempdir().unwrap();
        let attempt = [1; 16];
        for (state, phase) in [
            (State::Ready, InterruptedPhase::Intent),
            (
                State::RecoveryRequired {
                    attempt,
                    incarnation: None,
                },
                InterruptedPhase::Bound,
            ),
            (
                State::RecoveryRequired {
                    attempt,
                    incarnation: None,
                },
                InterruptedPhase::ReleaseRecorded,
            ),
            (
                State::RecoveryRequired {
                    attempt,
                    incarnation: Some([2; 16]),
                },
                InterruptedPhase::Intent,
            ),
        ] {
            let record = Snapshot {
                version: 3,
                state,
                interrupted_phase: Some(phase),
            };
            let path = dir.path().join("state.json");
            let bytes = serde_json::to_vec(&record).unwrap();
            fs::write(&path, &bytes).unwrap();
            assert_eq!(
                load(dir.path()).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(
                reopen_for_recovery(dir.path(), Fault::None)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }

    #[test]
    fn startup_persists_recovery_and_preserves_identity_for_each_pending_phase() {
        for phase in 0..3 {
            let dir = tempfile::tempdir().unwrap();
            let initial = initialize(dir.path()).unwrap();
            let ready = publish(dir.path(), initial, Event::Provisioned, Fault::None).unwrap();
            let intent = publish(
                dir.path(),
                ready,
                Event::IntentPersisted { attempt: [1; 16] },
                Fault::None,
            )
            .unwrap();
            let pending = if phase == 0 {
                intent
            } else {
                let bound = publish(
                    dir.path(),
                    intent,
                    Event::BindingPersisted {
                        attempt: [1; 16],
                        incarnation: [2; 16],
                    },
                    Fault::None,
                )
                .unwrap();
                if phase == 1 {
                    bound
                } else {
                    publish(
                        dir.path(),
                        bound,
                        Event::ReleaseRecorded {
                            attempt: [1; 16],
                            incarnation: [2; 16],
                        },
                        Fault::None,
                    )
                    .unwrap()
                }
            };
            let reopened = reopen_for_recovery(dir.path(), Fault::None).unwrap();
            assert_eq!(reopened.version, pending.version + 1);
            assert_eq!(
                reopened.state,
                State::RecoveryRequired {
                    attempt: [1; 16],
                    incarnation: if phase == 0 { None } else { Some([2; 16]) }
                }
            );
            assert_eq!(load(dir.path()).unwrap(), reopened);
            assert_eq!(
                reopened.interrupted_phase,
                Some(match phase {
                    0 => InterruptedPhase::Intent,
                    1 => InterruptedPhase::Bound,
                    _ => InterruptedPhase::ReleaseRecorded,
                })
            );
            let diagnostic = crate::authority_lifecycle_fixture::RecoveryDiagnostic::from_snapshot(
                load(dir.path()).unwrap(),
            );
            assert_eq!(
                diagnostic.phase,
                match phase {
                    0 => crate::authority_lifecycle_fixture::RecordedPhase::Intent,
                    1 => crate::authority_lifecycle_fixture::RecordedPhase::Bound,
                    _ => crate::authority_lifecycle_fixture::RecordedPhase::ReleaseRecorded,
                }
            );
            assert!(
                !diagnostic.execution_verified
                    && !diagnostic.descendant_cleanup_verified
                    && !diagnostic.rollback_verified
            );
            assert_eq!(
                reopen_for_recovery(dir.path(), Fault::None).unwrap(),
                reopened
            );
            assert!(!reopened.state.authorizes_real_work());
        }
    }

    #[test]
    fn legacy_interrupted_record_has_unknown_phase_and_remains_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = serde_json::json!({"version": 3, "state": {"RecoveryRequired": {"attempt": vec![1; 16], "incarnation": null}}});
        fs::write(
            dir.path().join("state.json"),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        let snapshot = reopen_for_recovery(dir.path(), Fault::None).unwrap();
        assert_eq!(snapshot.interrupted_phase, None);
        assert_eq!(
            crate::authority_lifecycle_fixture::RecoveryDiagnostic::from_snapshot(snapshot).phase,
            crate::authority_lifecycle_fixture::RecordedPhase::InterruptedPhaseUnknown
        );
        assert!(!snapshot.state.authorizes_real_work());
    }

    #[test]
    fn startup_failures_never_invent_clean_state_or_initialize() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            reopen_for_recovery(dir.path(), Fault::None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert!(!dir.path().join("state.json").exists());
        let initial = initialize(dir.path()).unwrap();
        let ready = publish(dir.path(), initial, Event::Provisioned, Fault::None).unwrap();
        let pending = publish(
            dir.path(),
            ready,
            Event::IntentPersisted { attempt: [3; 16] },
            Fault::None,
        )
        .unwrap();
        assert!(reopen_for_recovery(dir.path(), Fault::BeforeRename).is_err());
        assert_eq!(load(dir.path()).unwrap(), pending);
        assert!(reopen_for_recovery(dir.path(), Fault::AfterRename).is_err());
        let persisted = load(dir.path()).unwrap();
        assert_eq!(
            persisted.state,
            State::RecoveryRequired {
                attempt: [3; 16],
                incarnation: None
            }
        );
        assert_eq!(
            reopen_for_recovery(dir.path(), Fault::None).unwrap(),
            persisted
        );
        assert!(!persisted.state.authorizes_real_work());
    }

    #[test]
    fn synthetic_process_exit_after_injected_publication_failure() {
        if let Some(directory) = std::env::var_os("TUCUPI_JOURNAL_FIXTURE_CHILD") {
            let path = Path::new(&directory);
            let current = load(path).unwrap();
            let fault = if path.join("after-rename").exists() {
                Fault::AfterRename
            } else {
                Fault::BeforeRename
            };
            assert!(publish(
                path,
                current,
                Event::IntentPersisted { attempt: [9; 16] },
                fault
            )
            .is_err());
            std::process::exit(77);
        }
        for fault in [Fault::BeforeRename, Fault::AfterRename] {
            let directory = tempfile::tempdir().unwrap();
            let initial = initialize(directory.path()).unwrap();
            let ready =
                publish(directory.path(), initial, Event::Provisioned, Fault::None).unwrap();
            if fault == Fault::AfterRename {
                fs::write(directory.path().join("after-rename"), "").unwrap();
            }
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "authority_journal_fixture::tests::synthetic_process_exit_after_injected_publication_failure"])
                .env_clear().env("HOME", directory.path()).env("TMPDIR", directory.path())
                .env("TUCUPI_JOURNAL_FIXTURE_CHILD", directory.path())
                .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().unwrap();
            assert_eq!(status.code(), Some(77));
            let loaded = load(directory.path()).unwrap();
            match fault {
                Fault::BeforeRename => assert_eq!(loaded, ready),
                Fault::AfterRename => {
                    assert_eq!(loaded.state, State::Intent { attempt: [9; 16] });
                    assert_eq!(
                        loaded.state.after_restart(),
                        State::RecoveryRequired {
                            attempt: [9; 16],
                            incarnation: None
                        }
                    );
                    assert!(!loaded.state.authorizes_real_work());
                }
                Fault::None => unreachable!(),
            }
        }
    }

    #[test]
    fn synthetic_restart_distinguishes_pre_and_post_rename_failures() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(
            load(directory.path()).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        let initial = initialize(directory.path()).unwrap();
        assert!(initialize(directory.path()).is_err());
        let ready = publish(directory.path(), initial, Event::Provisioned, Fault::None).unwrap();
        let intent = Event::IntentPersisted { attempt: [7; 16] };
        assert!(publish(directory.path(), ready, intent, Fault::BeforeRename).is_err());
        assert_eq!(load(directory.path()).unwrap(), ready);
        assert!(publish(directory.path(), ready, intent, Fault::AfterRename).is_err());
        let restarted = load(directory.path()).unwrap();
        assert_eq!(restarted.version, ready.version + 1);
        assert_eq!(restarted.state, State::Intent { attempt: [7; 16] });
        assert_eq!(
            restarted.state.after_restart(),
            State::RecoveryRequired {
                attempt: [7; 16],
                incarnation: None
            }
        );
        assert!(publish(directory.path(), ready, intent, Fault::None).is_err());
        assert!(!restarted.state.authorizes_real_work());
    }

    #[test]
    fn synthetic_record_corruption_never_defaults_to_ready() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        for bytes in [
            b"{\"version\":0".to_vec(),
            vec![b'x'; MAX_RECORD as usize + 1],
            b"{}".to_vec(),
        ] {
            fs::write(&path, bytes).unwrap();
            assert_eq!(
                load(directory.path()).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn synthetic_special_files_are_not_read() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let target = dir.path().join("target.json");
        fs::write(&target, b"{} ").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(load(dir.path()).is_err());
        fs::remove_file(&path).unwrap();
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: name is NUL-terminated and points into this private fixture directory.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(load(dir.path()).is_err());
    }
}
