//! Synthetic ordering experiment only: no OS supervision, authentication,
//! independent storage, IPC authority or production-work authorization.

use crate::authority_journal_fixture::{self, Fault, Snapshot};
use crate::authority_lifecycle_fixture::{Event, Id, State};
use std::io;
use std::path::Path;

/// Persists intent before invoking a synthetic unit-creation callback. An
/// existing intent is never treated as permission to create another unit.
pub fn persist_intent_and_create(
    directory: &Path,
    attempt: Id,
    fault: Fault,
    create: impl FnOnce() -> io::Result<Id>,
) -> io::Result<(Snapshot, Id)> {
    let lock = crate::authority_transport_fixture::acquire_cooperative_lock(directory)?;
    let current = authority_journal_fixture::load(directory)?;
    if current.state != State::Ready {
        return Err(io::Error::other("fixture admission blocked"));
    }
    let intent = authority_journal_fixture::publish_locked(
        &lock,
        directory,
        current,
        Event::IntentPersisted { attempt },
        fault,
    )?;
    let incarnation = create()?;
    Ok((intent, incarnation))
}

/// Records a synthetic binding. The caller-supplied identity is not proof of
/// ownership, and a failed/ambiguous publication does not open the gate.
pub fn persist_binding(
    directory: &Path,
    intent: Snapshot,
    attempt: Id,
    incarnation: Id,
    fault: Fault,
) -> io::Result<Snapshot> {
    let lock = crate::authority_transport_fixture::acquire_cooperative_lock(directory)?;
    if intent.state != (State::Intent { attempt }) {
        return Err(io::Error::other("fixture intent mismatch"));
    }
    authority_journal_fixture::publish_locked(
        &lock,
        directory,
        intent,
        Event::BindingPersisted {
            attempt,
            incarnation,
        },
        fault,
    )
}

/// Records release before invoking a synthetic gate callback. An ambiguous
/// error or already-released attempt never causes an automatic second release.
pub fn persist_release_and_open(
    directory: &Path,
    bound: Snapshot,
    attempt: Id,
    incarnation: Id,
    fault: Fault,
    open: impl FnOnce() -> io::Result<()>,
) -> io::Result<Snapshot> {
    let lock = crate::authority_transport_fixture::acquire_cooperative_lock(directory)?;
    if bound.state
        != (State::Bound {
            attempt,
            incarnation,
        })
    {
        return Err(io::Error::other("fixture binding mismatch"));
    }
    let released = authority_journal_fixture::publish_locked(
        &lock,
        directory,
        bound,
        Event::ReleaseRecorded {
            attempt,
            incarnation,
        },
        fault,
    )?;
    open()?;
    Ok(released)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn ready(path: &Path) -> Snapshot {
        let initial = authority_journal_fixture::initialize(path).unwrap();
        authority_journal_fixture::publish(path, initial, Event::Provisioned, Fault::None).unwrap()
    }

    #[test]
    fn cooperative_server_and_coordinator_do_not_run_callbacks_concurrently() {
        let dir = tempfile::tempdir().unwrap();
        let before = ready(dir.path());
        let server = crate::authority_transport_fixture::SyntheticServer::open(dir.path()).unwrap();
        let calls = Cell::new(0);
        assert!(authority_journal_fixture::publish(
            dir.path(),
            before,
            Event::IntentPersisted { attempt: [9; 16] },
            Fault::None
        )
        .is_err());
        assert!(authority_journal_fixture::reopen_for_recovery(dir.path(), Fault::None).is_err());
        assert!(
            persist_intent_and_create(dir.path(), [1; 16], Fault::None, || {
                calls.set(calls.get() + 1);
                Ok([2; 16])
            })
            .is_err()
        );
        assert_eq!(calls.get(), 0);
        assert_eq!(authority_journal_fixture::load(dir.path()).unwrap(), before);
        drop(server);
        let (intent, incarnation) =
            persist_intent_and_create(dir.path(), [1; 16], Fault::None, || {
                calls.set(calls.get() + 1);
                assert!(
                    crate::authority_transport_fixture::SyntheticServer::open(dir.path()).is_err()
                );
                Ok([2; 16])
            })
            .unwrap();
        let bound = persist_binding(dir.path(), intent, [1; 16], incarnation, Fault::None).unwrap();
        persist_release_and_open(dir.path(), bound, [1; 16], incarnation, Fault::None, || {
            assert!(crate::authority_transport_fixture::SyntheticServer::open(dir.path()).is_err());
            Ok(())
        })
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert!(!authority_journal_fixture::load(dir.path())
            .unwrap()
            .state
            .authorizes_real_work());
    }

    #[test]
    fn server_reconciliation_between_steps_invalidates_old_intent() {
        let dir = tempfile::tempdir().unwrap();
        ready(dir.path());
        let (intent, incarnation) =
            persist_intent_and_create(dir.path(), [3; 16], Fault::None, || Ok([4; 16])).unwrap();
        let server = crate::authority_transport_fixture::SyntheticServer::open(dir.path()).unwrap();
        assert!(matches!(
            authority_journal_fixture::load(dir.path()).unwrap().state,
            State::RecoveryRequired { .. }
        ));
        drop(server);
        assert!(persist_binding(dir.path(), intent, [3; 16], incarnation, Fault::None).is_err());
        assert!(matches!(
            authority_journal_fixture::load(dir.path()).unwrap().state,
            State::RecoveryRequired { .. }
        ));
    }

    #[test]
    fn intent_failure_never_creates_and_ambiguous_retry_never_duplicates() {
        for fault in [Fault::BeforeRename, Fault::AfterRename] {
            let dir = tempfile::tempdir().unwrap();
            let original = ready(dir.path());
            let calls = Cell::new(0);
            assert!(persist_intent_and_create(dir.path(), [1; 16], fault, || {
                calls.set(calls.get() + 1);
                Ok([2; 16])
            })
            .is_err());
            assert_eq!(calls.get(), 0);
            let observed = authority_journal_fixture::load(dir.path()).unwrap();
            if fault == Fault::BeforeRename {
                assert_eq!(observed, original);
            } else {
                assert_eq!(observed.state, State::Intent { attempt: [1; 16] });
                assert!(
                    persist_intent_and_create(dir.path(), [1; 16], Fault::None, || {
                        calls.set(calls.get() + 1);
                        Ok([2; 16])
                    })
                    .is_err()
                );
                assert_eq!(calls.get(), 0);
                assert!(matches!(
                    observed.state.after_restart(),
                    State::RecoveryRequired { .. }
                ));
            }
        }
    }

    #[test]
    fn binding_and_release_fail_closed_on_ambiguous_results() {
        for fault in [Fault::BeforeRename, Fault::AfterRename] {
            let dir = tempfile::tempdir().unwrap();
            ready(dir.path());
            let created = Cell::new(0);
            let (intent, incarnation) =
                persist_intent_and_create(dir.path(), [1; 16], Fault::None, || {
                    created.set(created.get() + 1);
                    Ok([2; 16])
                })
                .unwrap();
            assert_eq!(created.get(), 1);
            assert!(
                persist_binding(dir.path(), intent, [3; 16], incarnation, Fault::None).is_err()
            );
            let bound =
                persist_binding(dir.path(), intent, [1; 16], incarnation, Fault::None).unwrap();
            let opened = Cell::new(0);
            assert!(persist_release_and_open(
                dir.path(),
                bound,
                [1; 16],
                incarnation,
                fault,
                || {
                    opened.set(opened.get() + 1);
                    Ok(())
                }
            )
            .is_err());
            assert_eq!(opened.get(), 0);
            let observed = authority_journal_fixture::load(dir.path()).unwrap();
            if fault == Fault::AfterRename {
                assert!(matches!(observed.state, State::Released { .. }));
                assert!(persist_release_and_open(
                    dir.path(),
                    bound,
                    [1; 16],
                    incarnation,
                    Fault::None,
                    || {
                        opened.set(opened.get() + 1);
                        Ok(())
                    }
                )
                .is_err());
                assert_eq!(opened.get(), 0);
            } else {
                assert_eq!(observed, bound);
            }
            assert!(matches!(
                observed.state.after_restart(),
                State::RecoveryRequired { .. }
            ));
            assert!(!observed.state.authorizes_real_work());
        }
    }

    #[test]
    fn failed_creation_leaves_pending_intent_and_rejects_retry() {
        let dir = tempfile::tempdir().unwrap();
        ready(dir.path());
        assert!(
            persist_intent_and_create(dir.path(), [1; 16], Fault::None, || Err(io::Error::other(
                "synthetic failure"
            )))
            .is_err()
        );
        let calls = Cell::new(0);
        assert!(
            persist_intent_and_create(dir.path(), [1; 16], Fault::None, || {
                calls.set(calls.get() + 1);
                Ok([2; 16])
            })
            .is_err()
        );
        assert_eq!(calls.get(), 0);
        assert!(matches!(
            authority_journal_fixture::load(dir.path())
                .unwrap()
                .state
                .after_restart(),
            State::RecoveryRequired { .. }
        ));
    }

    #[test]
    fn gate_callback_error_after_side_effect_stays_unknown_and_is_not_repeated() {
        let dir = tempfile::tempdir().unwrap();
        ready(dir.path());
        let (intent, incarnation) =
            persist_intent_and_create(dir.path(), [1; 16], Fault::None, || Ok([2; 16])).unwrap();
        let bound = persist_binding(dir.path(), intent, [1; 16], incarnation, Fault::None).unwrap();
        let gate_marker = dir.path().join("synthetic-gate-effect");
        let calls = Cell::new(0);
        assert!(persist_release_and_open(
            dir.path(),
            bound,
            [1; 16],
            incarnation,
            Fault::None,
            || {
                calls.set(calls.get() + 1);
                std::fs::write(&gate_marker, b"synthetic effect")?;
                Err(io::Error::other("synthetic response lost"))
            }
        )
        .is_err());
        assert_eq!(std::fs::read(&gate_marker).unwrap(), b"synthetic effect");
        assert!(persist_release_and_open(
            dir.path(),
            bound,
            [1; 16],
            incarnation,
            Fault::None,
            || {
                calls.set(calls.get() + 1);
                Ok(())
            }
        )
        .is_err());
        assert_eq!(calls.get(), 1);
        let server = crate::authority_transport_fixture::SyntheticServer::open(dir.path()).unwrap();
        let diagnostic = server.diagnostic().unwrap();
        assert_eq!(
            diagnostic.phase,
            crate::authority_lifecycle_fixture::RecordedPhase::ReleaseRecorded
        );
        assert_eq!(
            diagnostic.gate_outcome,
            crate::authority_lifecycle_fixture::GateOutcome::Unknown
        );
        assert!(
            !diagnostic.execution_verified
                && !diagnostic.descendant_cleanup_verified
                && !diagnostic.rollback_verified
        );
        assert!(!authority_journal_fixture::load(dir.path())
            .unwrap()
            .state
            .authorizes_real_work());
    }

    #[test]
    fn synthetic_happy_path_keeps_order_and_remains_non_authoritative() {
        let dir = tempfile::tempdir().unwrap();
        ready(dir.path());
        let (intent, incarnation) =
            persist_intent_and_create(dir.path(), [4; 16], Fault::None, || {
                assert!(matches!(
                    authority_journal_fixture::load(dir.path()).unwrap().state,
                    State::Intent { .. }
                ));
                Ok([5; 16])
            })
            .unwrap();
        let bound = persist_binding(dir.path(), intent, [4; 16], incarnation, Fault::None).unwrap();
        let released =
            persist_release_and_open(dir.path(), bound, [4; 16], incarnation, Fault::None, || {
                assert!(matches!(
                    authority_journal_fixture::load(dir.path()).unwrap().state,
                    State::Released { .. }
                ));
                Ok(())
            })
            .unwrap();
        assert_eq!(
            authority_journal_fixture::load(dir.path()).unwrap(),
            released
        );
        assert!(!released.state.authorizes_real_work());
    }

    #[test]
    fn ambiguous_binding_never_opens_and_restart_remains_blocked() {
        for fault in [Fault::BeforeRename, Fault::AfterRename] {
            let dir = tempfile::tempdir().unwrap();
            ready(dir.path());
            let (intent, incarnation) =
                persist_intent_and_create(dir.path(), [1; 16], Fault::None, || Ok([2; 16]))
                    .unwrap();
            assert!(persist_binding(dir.path(), intent, [1; 16], incarnation, fault).is_err());
            let state = authority_journal_fixture::load(dir.path()).unwrap().state;
            assert!(matches!(
                state.after_restart(),
                State::RecoveryRequired { .. }
            ));
            assert!(!state.authorizes_real_work());
        }
    }
}
