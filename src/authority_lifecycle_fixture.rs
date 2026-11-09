//! Synthetic lifecycle model only. It is not a daemon, a trusted registry,
//! an authentication mechanism, or authorization to start real work.

/// Opaque identifiers used by the synthetic model, not proof of provenance.
pub type Id = [u8; 16];

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum State {
    Unprovisioned,
    Ready,
    Intent {
        attempt: Id,
    },
    Bound {
        attempt: Id,
        incarnation: Id,
    },
    Released {
        attempt: Id,
        incarnation: Id,
    },
    DirectChildExited {
        attempt: Id,
        incarnation: Id,
        success: bool,
    },
    RecoveryRequired {
        attempt: Id,
        incarnation: Option<Id>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Provisioned,
    IntentPersisted {
        attempt: Id,
    },
    BindingPersisted {
        attempt: Id,
        incarnation: Id,
    },
    ReleaseRecorded {
        attempt: Id,
        incarnation: Id,
    },
    DirectChildExitObserved {
        attempt: Id,
        incarnation: Id,
        success: bool,
    },
    Interrupted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidTransition;

impl State {
    /// Models only already-persisted events. Calling this does not persist,
    /// authenticate, provision, launch, stop, or clear anything.
    pub fn apply(self, event: Event) -> Result<Self, InvalidTransition> {
        match (self, event) {
            (Self::Unprovisioned, Event::Provisioned) => Ok(Self::Ready),
            (Self::Ready, Event::IntentPersisted { attempt }) => Ok(Self::Intent { attempt }),
            (Self::Intent { attempt }, Event::IntentPersisted { attempt: incoming })
                if attempt == incoming =>
            {
                Ok(self)
            }
            (
                Self::Intent { attempt },
                Event::BindingPersisted {
                    attempt: incoming,
                    incarnation,
                },
            ) if attempt == incoming => Ok(Self::Bound {
                attempt,
                incarnation,
            }),
            (
                Self::Bound {
                    attempt,
                    incarnation,
                },
                Event::BindingPersisted {
                    attempt: incoming,
                    incarnation: other,
                },
            ) if attempt == incoming && incarnation == other => Ok(self),
            (
                Self::Released {
                    attempt,
                    incarnation,
                },
                Event::DirectChildExitObserved {
                    attempt: incoming,
                    incarnation: other,
                    success,
                },
            ) if attempt == incoming && incarnation == other => Ok(Self::DirectChildExited {
                attempt,
                incarnation,
                success,
            }),
            (
                Self::DirectChildExited {
                    attempt,
                    incarnation,
                    success,
                },
                Event::DirectChildExitObserved {
                    attempt: incoming,
                    incarnation: other,
                    success: incoming_success,
                },
            ) if attempt == incoming && incarnation == other && success == incoming_success => {
                Ok(self)
            }
            (
                Self::Bound {
                    attempt,
                    incarnation,
                },
                Event::ReleaseRecorded {
                    attempt: incoming,
                    incarnation: other,
                },
            ) if attempt == incoming && incarnation == other => Ok(Self::Released {
                attempt,
                incarnation,
            }),
            (
                Self::Released {
                    attempt,
                    incarnation,
                },
                Event::ReleaseRecorded {
                    attempt: incoming,
                    incarnation: other,
                },
            ) if attempt == incoming && incarnation == other => Ok(self),
            (Self::Intent { attempt }, Event::Interrupted) => Ok(Self::RecoveryRequired {
                attempt,
                incarnation: None,
            }),
            (
                Self::Bound {
                    attempt,
                    incarnation,
                }
                | Self::Released {
                    attempt,
                    incarnation,
                }
                | Self::DirectChildExited {
                    attempt,
                    incarnation,
                    ..
                },
                Event::Interrupted,
            ) => Ok(Self::RecoveryRequired {
                attempt,
                incarnation: Some(incarnation),
            }),
            (Self::RecoveryRequired { .. }, Event::Interrupted) => Ok(self),
            _ => Err(InvalidTransition),
        }
    }

    /// A restart with an incomplete operation cannot become clean by itself.
    pub fn after_restart(self) -> Self {
        match self {
            Self::Intent { attempt } => Self::RecoveryRequired {
                attempt,
                incarnation: None,
            },
            Self::Bound {
                attempt,
                incarnation,
            }
            | Self::Released {
                attempt,
                incarnation,
            }
            | Self::DirectChildExited {
                attempt,
                incarnation,
                ..
            } => Self::RecoveryRequired {
                attempt,
                incarnation: Some(incarnation),
            },
            other => other,
        }
    }

    /// No state in this fixture authorizes any production operation.
    pub fn authorizes_real_work(self) -> bool {
        false
    }
}

/// A bounded presentation for a synthetic recovery journey. Neither the source
/// nor any displayed identifier is authenticated by this fixture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryView {
    AuthorityUnavailable,
    NotProvisioned,
    NoPendingWorkObserved,
    Pending {
        attempt: Id,
        incarnation: Option<Id>,
    },
    RecoveryNeeded {
        attempt: Id,
        incarnation: Option<Id>,
    },
}

impl RecoveryView {
    pub fn from_observation(observed: Option<State>) -> Self {
        match observed {
            None => Self::AuthorityUnavailable,
            Some(State::Unprovisioned) => Self::NotProvisioned,
            Some(State::Ready) => Self::NoPendingWorkObserved,
            Some(State::Intent { attempt }) => Self::Pending {
                attempt,
                incarnation: None,
            },
            Some(
                State::Bound {
                    attempt,
                    incarnation,
                }
                | State::Released {
                    attempt,
                    incarnation,
                }
                | State::DirectChildExited {
                    attempt,
                    incarnation,
                    ..
                },
            ) => Self::Pending {
                attempt,
                incarnation: Some(incarnation),
            },
            Some(State::RecoveryRequired {
                attempt,
                incarnation,
            }) => Self::RecoveryNeeded {
                attempt,
                incarnation,
            },
        }
    }

    /// There is no self-service unlock or automatic restore in this fixture.
    pub fn authorizes_recovery(self) -> bool {
        false
    }
}

/// Diagnostic only: recorded phase is not proof that callbacks ran or that a
/// workload, its descendants, or a rollback completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordedPhase {
    Intent,
    Bound,
    ReleaseRecorded,
    DirectChildExitRecorded,
    InterruptedPhaseUnknown,
    NoPendingRecordObserved,
    Unprovisioned,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryDiagnostic {
    pub phase: RecordedPhase,
    pub attempt: Option<Id>,
    pub incarnation: Option<Id>,
    /// Persisting a release record does not prove that the gate opened.
    pub gate_outcome: GateOutcome,
    /// Synthetic journal claim only, not authenticated or evidence of tree cleanup.
    pub recorded_direct_child_success: Option<bool>,
    /// These outcomes are not established by this model or its journal.
    pub execution_verified: bool,
    pub descendant_cleanup_verified: bool,
    pub rollback_verified: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateOutcome {
    Unknown,
}

impl RecoveryDiagnostic {
    /// Journal metadata is only a recorded phase, never evidence of actual
    /// execution or cleanup. Legacy records retain an unknown phase.
    pub fn from_snapshot(snapshot: crate::authority_journal_fixture::Snapshot) -> Self {
        Self::from_recorded_state(snapshot.state, snapshot.interrupted_phase)
    }

    pub fn from_recorded_state(
        state: State,
        interrupted_phase: Option<crate::authority_journal_fixture::InterruptedPhase>,
    ) -> Self {
        let mut diagnostic = Self::from_observation(Some(state));
        if matches!(state, State::RecoveryRequired { .. }) {
            diagnostic.phase = match interrupted_phase {
                Some(crate::authority_journal_fixture::InterruptedPhase::Intent) => {
                    RecordedPhase::Intent
                }
                Some(crate::authority_journal_fixture::InterruptedPhase::Bound) => {
                    RecordedPhase::Bound
                }
                Some(crate::authority_journal_fixture::InterruptedPhase::ReleaseRecorded) => {
                    RecordedPhase::ReleaseRecorded
                }
                Some(crate::authority_journal_fixture::InterruptedPhase::DirectChildExited {
                    success,
                }) => {
                    diagnostic.recorded_direct_child_success = Some(success);
                    RecordedPhase::DirectChildExitRecorded
                }
                None => RecordedPhase::InterruptedPhaseUnknown,
            };
        }
        diagnostic
    }

    pub fn from_observation(state: Option<State>) -> Self {
        let (phase, attempt, incarnation) = match state {
            None => (RecordedPhase::Unavailable, None, None),
            Some(State::Unprovisioned) => (RecordedPhase::Unprovisioned, None, None),
            Some(State::Ready) => (RecordedPhase::NoPendingRecordObserved, None, None),
            Some(State::Intent { attempt }) => (RecordedPhase::Intent, Some(attempt), None),
            Some(State::Bound {
                attempt,
                incarnation,
            }) => (RecordedPhase::Bound, Some(attempt), Some(incarnation)),
            Some(State::Released {
                attempt,
                incarnation,
            }) => (
                RecordedPhase::ReleaseRecorded,
                Some(attempt),
                Some(incarnation),
            ),
            Some(State::DirectChildExited {
                attempt,
                incarnation,
                ..
            }) => (
                RecordedPhase::DirectChildExitRecorded,
                Some(attempt),
                Some(incarnation),
            ),
            Some(State::RecoveryRequired {
                attempt,
                incarnation,
            }) => (
                RecordedPhase::InterruptedPhaseUnknown,
                Some(attempt),
                incarnation,
            ),
        };
        Self {
            phase,
            attempt,
            incarnation,
            gate_outcome: GateOutcome::Unknown,
            recorded_direct_child_success: match state {
                Some(State::DirectChildExited { success, .. }) => Some(success),
                _ => None,
            },
            execution_verified: false,
            descendant_cleanup_verified: false,
            rollback_verified: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_distinguish_recorded_phase_from_unverified_outcomes() {
        let attempt = [1; 16];
        let incarnation = [2; 16];
        for (state, phase) in [
            (None, RecordedPhase::Unavailable),
            (Some(State::Unprovisioned), RecordedPhase::Unprovisioned),
            (Some(State::Ready), RecordedPhase::NoPendingRecordObserved),
            (Some(State::Intent { attempt }), RecordedPhase::Intent),
            (
                Some(State::Bound {
                    attempt,
                    incarnation,
                }),
                RecordedPhase::Bound,
            ),
            (
                Some(State::Released {
                    attempt,
                    incarnation,
                }),
                RecordedPhase::ReleaseRecorded,
            ),
            (
                Some(
                    State::Released {
                        attempt,
                        incarnation,
                    }
                    .after_restart(),
                ),
                RecordedPhase::InterruptedPhaseUnknown,
            ),
        ] {
            let diagnostic = RecoveryDiagnostic::from_observation(state);
            assert_eq!(diagnostic.phase, phase);
            assert!(!diagnostic.execution_verified);
            assert!(!diagnostic.descendant_cleanup_verified);
            assert!(!diagnostic.rollback_verified);
            if phase == RecordedPhase::InterruptedPhaseUnknown {
                assert_eq!(diagnostic.attempt, Some(attempt));
                assert_eq!(diagnostic.incarnation, Some(incarnation));
            }
        }
    }

    #[test]
    fn lifecycle_requires_order_and_binds_identity() {
        let a = [1; 16];
        let b = [2; 16];
        let c = [3; 16];
        let ready = State::Unprovisioned.apply(Event::Provisioned).unwrap();
        assert!(State::Unprovisioned
            .apply(Event::IntentPersisted { attempt: a })
            .is_err());
        assert!(ready
            .apply(Event::ReleaseRecorded {
                attempt: a,
                incarnation: b
            })
            .is_err());
        let intent = ready.apply(Event::IntentPersisted { attempt: a }).unwrap();
        assert_eq!(
            intent.apply(Event::IntentPersisted { attempt: a }),
            Ok(intent)
        );
        assert!(intent.apply(Event::IntentPersisted { attempt: b }).is_err());
        assert!(intent
            .apply(Event::BindingPersisted {
                attempt: b,
                incarnation: c
            })
            .is_err());
        let bound = intent
            .apply(Event::BindingPersisted {
                attempt: a,
                incarnation: b,
            })
            .unwrap();
        assert_eq!(
            bound.apply(Event::BindingPersisted {
                attempt: a,
                incarnation: b
            }),
            Ok(bound)
        );
        assert!(bound
            .apply(Event::ReleaseRecorded {
                attempt: a,
                incarnation: c
            })
            .is_err());
        let released = bound
            .apply(Event::ReleaseRecorded {
                attempt: a,
                incarnation: b,
            })
            .unwrap();
        assert_eq!(
            released.apply(Event::ReleaseRecorded {
                attempt: a,
                incarnation: b
            }),
            Ok(released)
        );
        assert!(!released.authorizes_real_work());
    }

    #[test]
    fn interruption_and_restart_never_clear_incomplete_work() {
        let a = [1; 16];
        let b = [2; 16];
        for state in [
            State::Intent { attempt: a },
            State::Bound {
                attempt: a,
                incarnation: b,
            },
            State::Released {
                attempt: a,
                incarnation: b,
            },
            State::RecoveryRequired {
                attempt: a,
                incarnation: Some(b),
            },
        ] {
            let expected = match state {
                State::Intent { .. } => State::RecoveryRequired {
                    attempt: a,
                    incarnation: None,
                },
                _ => State::RecoveryRequired {
                    attempt: a,
                    incarnation: Some(b),
                },
            };
            assert_eq!(state.after_restart(), expected);
            assert_eq!(state.apply(Event::Interrupted), Ok(expected));
            assert!(state.after_restart().apply(Event::Provisioned).is_err());
            assert!(!state.after_restart().authorizes_real_work());
        }
        assert_eq!(State::Unprovisioned.after_restart(), State::Unprovisioned);
        assert!(!State::Ready.authorizes_real_work());
    }

    #[test]
    fn recovery_view_retains_attempt_identity_without_granting_unlock() {
        let attempt = [1; 16];
        let incarnation = [2; 16];
        let observations = [
            (None, RecoveryView::AuthorityUnavailable),
            (Some(State::Unprovisioned), RecoveryView::NotProvisioned),
            (Some(State::Ready), RecoveryView::NoPendingWorkObserved),
            (
                Some(State::Intent { attempt }),
                RecoveryView::Pending {
                    attempt,
                    incarnation: None,
                },
            ),
            (
                Some(State::Bound {
                    attempt,
                    incarnation,
                }),
                RecoveryView::Pending {
                    attempt,
                    incarnation: Some(incarnation),
                },
            ),
            (
                Some(
                    State::Released {
                        attempt,
                        incarnation,
                    }
                    .after_restart(),
                ),
                RecoveryView::RecoveryNeeded {
                    attempt,
                    incarnation: Some(incarnation),
                },
            ),
        ];
        for (observation, expected) in observations {
            let view = RecoveryView::from_observation(observation);
            assert_eq!(view, expected);
            assert!(!view.authorizes_recovery());
        }
    }
}
