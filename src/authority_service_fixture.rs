//! Synthetic process-gate experiment. Not a service, sandbox, authority,
//! protected storage, process-tree supervisor, or production authorization.

use crate::authority_coordinator_fixture;
use crate::authority_journal_fixture::{self, Fault};
use crate::authority_lifecycle_fixture::{Event, Id};
use crate::authority_supervision::DirectChildObserver;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus};

/// Test-only integration with the same-user recovery intent. The two stores
/// are not transactional; any partial result remains blocked. This must only
/// be used with disposable fixture directories and harmless child processes.
pub fn start_synthetic_with_recovery(
    recovery_directory: &std::fs::File,
    journal_directory: &Path,
    attempt: Id,
    incarnation: Id,
    spawn_fixture: impl FnOnce() -> io::Result<Child>,
) -> io::Result<SyntheticChild> {
    start_synthetic_with_recovery_hook(
        recovery_directory,
        journal_directory,
        attempt,
        incarnation,
        spawn_fixture,
        || Ok(()),
    )
}

fn encode_fixture_id(id: Id) -> io::Result<String> {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(32);
    for byte in id {
        write!(&mut encoded, "{byte:02x}").map_err(io::Error::other)?;
    }
    Ok(encoded)
}

fn start_synthetic_with_recovery_hook(
    recovery_directory: &std::fs::File,
    journal_directory: &Path,
    attempt: Id,
    incarnation: Id,
    spawn_fixture: impl FnOnce() -> io::Result<Child>,
    after_binding: impl FnOnce() -> io::Result<()>,
) -> io::Result<SyntheticChild> {
    let recovery = recovery_directory.try_clone()?;
    let encoded = encode_fixture_id(attempt)?;
    let synthetic_binding = crate::recovery_state::AttemptIdentity {
        unit: format!("tucupi-review-{encoded}.service"),
        attempt: encoded.clone(),
        invocation: encode_fixture_id(incarnation)?,
        boot: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        manager_epoch: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
    };
    crate::recovery_state::persist_pending_intent(recovery_directory, &encoded)?;
    let mut child = start_synthetic_attempt_with_hook(
        journal_directory,
        attempt,
        incarnation,
        Fault::None,
        Fault::None,
        spawn_fixture,
        || {
            crate::recovery_state::persist_attempt_binding(recovery_directory, &synthetic_binding)?;
            after_binding()
        },
    )?;
    child.recovery_directory = Some(recovery);
    Ok(child)
}

/// Owns only the direct fixture child. Drop performs best-effort cleanup;
/// neither a successful wait nor Drop establishes descendant cleanup.
pub struct SyntheticChild {
    child: Option<Child>,
    observer: Option<DirectChildObserver>,
    directory: PathBuf,
    attempt: Id,
    incarnation: Id,
    recovery_directory: Option<std::fs::File>,
}

impl SyntheticChild {
    pub fn wait(mut self) -> io::Result<ExitStatus> {
        self.wait_with_fault(Fault::None)
    }

    fn wait_with_fault(&mut self, fault: Fault) -> io::Result<ExitStatus> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| io::Error::other("fixture child unavailable"))?;
        let status = child.wait()?;
        self.child = None;
        let current = authority_journal_fixture::load(&self.directory)?;
        authority_journal_fixture::publish(
            &self.directory,
            current,
            Event::DirectChildExitObserved {
                attempt: self.attempt,
                incarnation: self.incarnation,
                success: status.success(),
            },
            fault,
        )?;
        if let Some(directory) = &self.recovery_directory {
            crate::recovery_state::persist_direct_exit(
                directory,
                &encode_fixture_id(self.attempt)?,
                status.success(),
            )?;
        }
        Ok(status)
    }
}

impl Drop for SyntheticChild {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            // Best effort only. Failure is not evidence of cleanup, and there
            // is no descendant tracking or guaranteed bounded shutdown here.
            if child.kill().is_ok() {
                let _ = child.wait();
            }
        }
    }
}

/// Test-only composition: persist intent, create a gated synthetic child,
/// persist binding and release, then send one gate byte. IDs and callbacks
/// are untrusted; the caller must use isolated, harmless fixture processes.
/// An error leaves recovery pending and makes no cleanup/rollback claim.
pub fn start_synthetic_attempt(
    directory: &Path,
    attempt: Id,
    incarnation: Id,
    binding_fault: Fault,
    release_fault: Fault,
    spawn_fixture: impl FnOnce() -> io::Result<Child>,
) -> io::Result<SyntheticChild> {
    start_synthetic_attempt_with_hook(
        directory,
        attempt,
        incarnation,
        binding_fault,
        release_fault,
        spawn_fixture,
        || Ok(()),
    )
}

fn start_synthetic_attempt_with_hook(
    directory: &Path,
    attempt: Id,
    incarnation: Id,
    binding_fault: Fault,
    release_fault: Fault,
    spawn_fixture: impl FnOnce() -> io::Result<Child>,
    before_release: impl FnOnce() -> io::Result<()>,
) -> io::Result<SyntheticChild> {
    let mut owned = SyntheticChild {
        child: None,
        observer: None,
        directory: directory.to_path_buf(),
        attempt,
        incarnation,
        recovery_directory: None,
    };
    let (intent, _) = authority_coordinator_fixture::persist_intent_and_create(
        directory,
        attempt,
        Fault::None,
        || {
            owned.child = Some(spawn_fixture()?);
            let child = owned
                .child
                .as_ref()
                .ok_or_else(|| io::Error::other("fixture child unavailable"))?;
            let observer = DirectChildObserver::from_child(child)?;
            observer.verify_unexited_direct_child()?;
            owned.observer = Some(observer);
            Ok(incarnation)
        },
    )?;
    let bound = authority_coordinator_fixture::persist_binding(
        directory,
        intent,
        attempt,
        incarnation,
        binding_fault,
    )?;
    before_release()?;
    owned
        .observer
        .as_ref()
        .ok_or_else(|| io::Error::other("fixture observer unavailable"))?
        .verify_unexited_direct_child()?;
    authority_coordinator_fixture::persist_release_and_open(
        directory,
        bound,
        attempt,
        incarnation,
        release_fault,
        || {
            owned
                .observer
                .as_ref()
                .ok_or_else(|| io::Error::other("fixture observer unavailable"))?
                .verify_unexited_direct_child()?;
            let child = owned
                .child
                .as_mut()
                .ok_or_else(|| io::Error::other("fixture child unavailable"))?;
            let mut gate = child
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("fixture gate unavailable"))?;
            gate.write_all(b"G")?;
            gate.flush()
        },
    )?;
    Ok(owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority_journal_fixture::{self, Fault};
    use crate::authority_lifecycle_fixture::{Event, State};
    use std::io::Read;
    use std::process::{Command, Stdio};

    #[test]
    fn recovery_binding_survives_supervisor_exit_before_gate_release() {
        use std::os::unix::fs::PermissionsExt;
        const CHILD: &str = "TUCUPI_AFTER_BINDING_CHILD";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = Path::new(&root);
            let recovery =
                crate::recovery_state::open_provisioned_state_directory(&root.join("recovery"))
                    .unwrap();
            let _ = start_synthetic_with_recovery_hook(
                &recovery,
                &root.join("journal"),
                [1; 16],
                [2; 16],
                || {
                    Command::new("/bin/sh")
                        .args(["-c", "IFS= read -r line"])
                        .env_clear()
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                },
                || {
                    assert_eq!(
                        crate::recovery_state::local_recovery_evidence_at(&root.join("recovery")),
                        crate::recovery_state::LocalRecoveryEvidence::PendingAttemptObserved
                    );
                    assert!(matches!(
                        authority_journal_fixture::load(&root.join("journal"))
                            .unwrap()
                            .state,
                        State::Bound { .. }
                    ));
                    std::process::exit(77);
                },
            );
            panic!("synthetic interruption did not occur");
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::recovery_state::provision_state_directory(
            root.path(),
            std::ffi::OsStr::new("recovery"),
        )
        .unwrap();
        let journal = root.path().join("journal");
        std::fs::create_dir(&journal).unwrap();
        let initial = authority_journal_fixture::initialize(&journal).unwrap();
        authority_journal_fixture::publish(&journal, initial, Event::Provisioned, Fault::None)
            .unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "authority_service_fixture::tests::recovery_binding_survives_supervisor_exit_before_gate_release"])
            .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, root.path())
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
        assert_eq!(status.code(), Some(77));
        let recovery_path = root.path().join("recovery");
        assert_eq!(
            crate::recovery_state::local_recovery_evidence_at(&recovery_path),
            crate::recovery_state::LocalRecoveryEvidence::PendingAttemptObserved
        );
        let snapshot =
            authority_journal_fixture::reopen_for_recovery(&journal, Fault::None).unwrap();
        let diagnostic =
            crate::authority_lifecycle_fixture::RecoveryDiagnostic::from_snapshot(snapshot);
        assert_eq!(
            diagnostic.phase,
            crate::authority_lifecycle_fixture::RecordedPhase::Bound
        );
        assert!(
            !diagnostic.execution_verified
                && !diagnostic.descendant_cleanup_verified
                && !diagnostic.rollback_verified
        );
        assert!(!snapshot.state.authorizes_real_work());
        let recovery =
            crate::recovery_state::open_provisioned_state_directory(&recovery_path).unwrap();
        let result = start_synthetic_with_recovery(&recovery, &journal, [1; 16], [2; 16], || {
            panic!("duplicate must not spawn")
        });
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::AlreadyExists));
    }

    #[test]
    fn interrupted_supervisor_preserves_intent_and_unknown_outcomes() {
        use std::os::unix::fs::PermissionsExt;
        const CHILD: &str = "TUCUPI_RECOVERY_SUPERVISOR_CHILD";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = Path::new(&root);
            let recovery =
                crate::recovery_state::open_provisioned_state_directory(&root.join("recovery"))
                    .unwrap();
            let _ = start_synthetic_with_recovery(
                &recovery,
                &root.join("journal"),
                [1; 16],
                [2; 16],
                || {
                    assert_eq!(
                        crate::recovery_state::local_recovery_evidence_at(&root.join("recovery")),
                        crate::recovery_state::LocalRecoveryEvidence::PendingIntentObserved
                    );
                    // Harmless child exits on stdin EOF when its parent exits.
                    let _child = Command::new("/bin/sh")
                        .args(["-c", "IFS= read -r line"])
                        .env_clear()
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()?;
                    std::process::exit(77);
                },
            );
            panic!("synthetic interruption did not occur");
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::recovery_state::provision_state_directory(
            root.path(),
            std::ffi::OsStr::new("recovery"),
        )
        .unwrap();
        let journal = root.path().join("journal");
        std::fs::create_dir(&journal).unwrap();
        let initial = authority_journal_fixture::initialize(&journal).unwrap();
        authority_journal_fixture::publish(&journal, initial, Event::Provisioned, Fault::None)
            .unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "authority_service_fixture::tests::interrupted_supervisor_preserves_intent_and_unknown_outcomes"])
            .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, root.path())
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
        assert_eq!(status.code(), Some(77));
        let recovery_path = root.path().join("recovery");
        assert_eq!(
            crate::recovery_state::local_recovery_evidence_at(&recovery_path),
            crate::recovery_state::LocalRecoveryEvidence::PendingIntentObserved
        );
        let snapshot =
            authority_journal_fixture::reopen_for_recovery(&journal, Fault::None).unwrap();
        let diagnostic =
            crate::authority_lifecycle_fixture::RecoveryDiagnostic::from_snapshot(snapshot);
        assert!(matches!(snapshot.state, State::RecoveryRequired { .. }));
        assert!(!diagnostic.execution_verified);
        assert!(!diagnostic.descendant_cleanup_verified);
        assert!(!diagnostic.rollback_verified);
        assert!(!snapshot.state.authorizes_real_work());
        let recovery =
            crate::recovery_state::open_provisioned_state_directory(&recovery_path).unwrap();
        let result = start_synthetic_with_recovery(&recovery, &journal, [1; 16], [2; 16], || {
            panic!("duplicate must not spawn")
        });
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::AlreadyExists));
    }

    #[test]
    fn exited_child_is_rejected_before_synthetic_binding_and_release() {
        let dir = tempfile::tempdir().unwrap();
        let initial = authority_journal_fixture::initialize(dir.path()).unwrap();
        authority_journal_fixture::publish(dir.path(), initial, Event::Provisioned, Fault::None)
            .unwrap();
        let result = start_synthetic_attempt(
            dir.path(),
            [1; 16],
            [2; 16],
            Fault::None,
            Fault::None,
            || {
                assert_eq!(
                    authority_journal_fixture::load(dir.path())?.state,
                    State::Intent { attempt: [1; 16] }
                );
                let mut child = Command::new("/bin/sh")
                    .args(["-c", "exit 0"])
                    .env_clear()
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()?;
                child.wait()?;
                Ok(child)
            },
        );
        assert!(result.is_err());
        assert_eq!(
            authority_journal_fixture::load(dir.path()).unwrap().state,
            State::Intent { attempt: [1; 16] }
        );
        let recovered =
            authority_journal_fixture::reopen_for_recovery(dir.path(), Fault::None).unwrap();
        assert!(matches!(recovered.state, State::RecoveryRequired { .. }));
        assert!(!recovered.state.authorizes_real_work());
    }

    #[test]
    fn recorded_exit_requires_matching_attempt_and_preserves_failure_on_restart() {
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
            Event::IntentPersisted { attempt: [1; 16] },
            Fault::None,
        )
        .unwrap();
        let bound = authority_journal_fixture::publish(
            dir.path(),
            intent,
            Event::BindingPersisted {
                attempt: [1; 16],
                incarnation: [2; 16],
            },
            Fault::None,
        )
        .unwrap();
        let released = authority_journal_fixture::publish(
            dir.path(),
            bound,
            Event::ReleaseRecorded {
                attempt: [1; 16],
                incarnation: [2; 16],
            },
            Fault::None,
        )
        .unwrap();
        assert!(authority_journal_fixture::publish(
            dir.path(),
            released,
            Event::DirectChildExitObserved {
                attempt: [3; 16],
                incarnation: [2; 16],
                success: false
            },
            Fault::None
        )
        .is_err());
        assert!(authority_journal_fixture::publish(
            dir.path(),
            released,
            Event::DirectChildExitObserved {
                attempt: [1; 16],
                incarnation: [2; 16],
                success: false
            },
            Fault::AfterRename
        )
        .is_err());
        let observed = authority_journal_fixture::load(dir.path()).unwrap();
        assert_eq!(
            observed.state,
            State::DirectChildExited {
                attempt: [1; 16],
                incarnation: [2; 16],
                success: false
            }
        );
        let recovered =
            authority_journal_fixture::reopen_for_recovery(dir.path(), Fault::None).unwrap();
        let diagnostic =
            crate::authority_lifecycle_fixture::RecoveryDiagnostic::from_snapshot(recovered);
        assert_eq!(diagnostic.recorded_direct_child_success, Some(false));
        assert!(!diagnostic.descendant_cleanup_verified && !diagnostic.rollback_verified);
        assert!(!recovered.state.authorizes_real_work());
    }

    #[test]
    fn gated_child_follows_persisted_lifecycle_and_failure_stays_pending() {
        if let Some(directory) = std::env::var_os("TUCUPI_SYNTHETIC_GATE_CHILD") {
            let mut byte = [0u8; 1];
            if std::io::stdin().read_exact(&mut byte).is_ok() && byte == *b"G" {
                std::fs::write(Path::new(&directory).join("gate-effect"), b"synthetic").unwrap();
                std::process::exit(0);
            }
            std::process::exit(77);
        }
        for (binding_fault, release_fault) in [
            (Fault::BeforeRename, Fault::None),
            (Fault::AfterRename, Fault::None),
            (Fault::None, Fault::BeforeRename),
            (Fault::None, Fault::AfterRename),
            (Fault::None, Fault::None),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let initial = authority_journal_fixture::initialize(dir.path()).unwrap();
            authority_journal_fixture::publish(
                dir.path(),
                initial,
                Event::Provisioned,
                Fault::None,
            )
            .unwrap();
            let result = start_synthetic_attempt(
                dir.path(),
                [1; 16],
                [2; 16],
                binding_fault,
                release_fault,
                || {
                    assert_eq!(
                        authority_journal_fixture::load(dir.path())?.state,
                        State::Intent { attempt: [1; 16] }
                    );
                    Command::new(std::env::current_exe()?)
                    .args(["--exact", "authority_service_fixture::tests::gated_child_follows_persisted_lifecycle_and_failure_stays_pending"])
                    .env_clear().env("HOME", dir.path()).env("TMPDIR", dir.path())
                    .env("TUCUPI_SYNTHETIC_GATE_CHILD", dir.path())
                    .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()
                },
            );
            if binding_fault == Fault::None && release_fault == Fault::None {
                assert!(result.unwrap().wait().unwrap().success());
                assert_eq!(
                    authority_journal_fixture::load(dir.path()).unwrap().state,
                    State::DirectChildExited {
                        attempt: [1; 16],
                        incarnation: [2; 16],
                        success: true
                    }
                );
                assert_eq!(
                    std::fs::read(dir.path().join("gate-effect")).unwrap(),
                    b"synthetic"
                );
            } else {
                assert!(result.is_err());
                assert!(!dir.path().join("gate-effect").exists());
            }
            let recovered =
                authority_journal_fixture::reopen_for_recovery(dir.path(), Fault::None).unwrap();
            assert!(matches!(recovered.state, State::RecoveryRequired { .. }));
            assert!(!recovered.state.authorizes_real_work());
            if binding_fault == Fault::None && release_fault == Fault::None {
                assert_eq!(
                    recovered.interrupted_phase,
                    Some(
                        authority_journal_fixture::InterruptedPhase::DirectChildExited {
                            success: true
                        }
                    )
                );
            }
        }
    }
}
