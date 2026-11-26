// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The exit code over every combination of what the host can observe,
//! and the named cases the precedence exists for.

use super::*;

const STOPS: [StopObserved; 4] = [
    StopObserved::Pending,
    StopObserved::Stopped,
    StopObserved::Abandoned,
    StopObserved::DriverEndedUnexpectedly,
];

const CAUSES: [ShutdownCause; 2] = [
    ShutdownCause::Signal,
    ShutdownCause::StartupFailedAfterAdmission,
];

/// Every observation the host can gather: 2 × 2 × 4 × 2 × 2.
fn every_observation() -> Vec<ShutdownObserved> {
    let mut all = Vec::new();
    for fenced in [false, true] {
        for budget_expired in [false, true] {
            for stop in STOPS {
                for drained in [false, true] {
                    for cause in CAUSES {
                        all.push(ShutdownObserved {
                            fenced,
                            budget_expired,
                            stop,
                            drained,
                            cause,
                        });
                    }
                }
            }
        }
    }
    all
}

/// The precedence, row by row, over every observation: each row decides
/// exactly the observations the rows above it left.
#[test]
fn every_observation_exits_by_the_precedence() {
    let all = every_observation();
    assert_eq!(all.len(), 64);
    for observed in all {
        let code = shutdown_exit_code(&observed);
        let expected = if observed.fenced {
            EXIT_FENCED
        } else if observed.budget_expired {
            EXIT_DEADLINE_EXPIRED
        } else if observed.stop == StopObserved::Stopped && observed.drained {
            match observed.cause {
                ShutdownCause::Signal => EXIT_DRAINED,
                ShutdownCause::StartupFailedAfterAdmission => EXIT_STARTUP_FAILED,
            }
        } else {
            EXIT_SERVE_FAILED
        };
        assert_eq!(code, expected, "{observed:?}");
    }
}

/// Exactly one observation exits drained: a signal, no fence, no expiry,
/// a stop that answered `Stopped` and a finished drain. Exactly one exits
/// as a startup failure: the same, begun by a failure after admission.
#[test]
fn drained_and_startup_failed_each_have_one_observation() {
    let all = every_observation();
    let drained: Vec<_> = all
        .iter()
        .filter(|o| shutdown_exit_code(o) == EXIT_DRAINED)
        .collect();
    assert_eq!(
        drained,
        [&ShutdownObserved {
            fenced: false,
            budget_expired: false,
            stop: StopObserved::Stopped,
            drained: true,
            cause: ShutdownCause::Signal,
        }]
    );
    let refused: Vec<_> = all
        .iter()
        .filter(|o| shutdown_exit_code(o) == EXIT_STARTUP_FAILED)
        .collect();
    assert_eq!(
        refused,
        [&ShutdownObserved {
            fenced: false,
            budget_expired: false,
            stop: StopObserved::Stopped,
            drained: true,
            cause: ShutdownCause::StartupFailedAfterAdmission,
        }]
    );
}

/// The cases the precedence is for, by name.
#[test]
fn the_named_cases() {
    let base = ShutdownObserved {
        fenced: false,
        budget_expired: false,
        stop: StopObserved::Stopped,
        drained: true,
        cause: ShutdownCause::Signal,
    };
    // A fence and an expired budget together: the fence.
    let both = ShutdownObserved {
        fenced: true,
        budget_expired: true,
        stop: StopObserved::Pending,
        drained: false,
        ..base
    };
    assert_eq!(shutdown_exit_code(&both), EXIT_FENCED);
    // A fence during the final clean write, with everything else done.
    let clean_write_fenced = ShutdownObserved {
        fenced: true,
        ..base
    };
    assert_eq!(shutdown_exit_code(&clean_write_fenced), EXIT_FENCED);
    // A hung final write: the stop never answers, the budget expires.
    let hung = ShutdownObserved {
        budget_expired: true,
        stop: StopObserved::Pending,
        ..base
    };
    assert_eq!(shutdown_exit_code(&hung), EXIT_DEADLINE_EXPIRED);
    // A refused volume whose clean write hangs, with no signal.
    let refused_and_hung = ShutdownObserved {
        cause: ShutdownCause::StartupFailedAfterAdmission,
        ..hung
    };
    assert_eq!(shutdown_exit_code(&refused_and_hung), EXIT_DEADLINE_EXPIRED);
    // A bind failure after admission: clean stop, then a startup failure.
    let bind_failed = ShutdownObserved {
        cause: ShutdownCause::StartupFailedAfterAdmission,
        ..base
    };
    assert_eq!(shutdown_exit_code(&bind_failed), EXIT_STARTUP_FAILED);
    // An abandoned run and a driver that ended unasked, drained or not.
    for stop in [
        StopObserved::Abandoned,
        StopObserved::DriverEndedUnexpectedly,
    ] {
        for drained in [false, true] {
            let ended = ShutdownObserved {
                stop,
                drained,
                ..base
            };
            assert_eq!(shutdown_exit_code(&ended), EXIT_SERVE_FAILED, "{ended:?}");
        }
    }
    // A clean stop with the drain unfinished is never drained.
    let undrained = ShutdownObserved {
        drained: false,
        ..base
    };
    assert_eq!(shutdown_exit_code(&undrained), EXIT_SERVE_FAILED);
    assert_eq!(shutdown_exit_code(&base), EXIT_DRAINED);
}
