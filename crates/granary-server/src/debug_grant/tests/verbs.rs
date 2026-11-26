// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::{Arc, mpsc};
use std::time::Duration;

use super::super::verbs::{TEMP, show_on};
use super::*;
use crate::protected_dir::tests::{Call, Pause, Phase, Recorder};
use granary_core::debug_grant::{decode_grant, encode_grant};

#[test]
fn debug_grant_issue_carries_incarnation_and_all_fields_into_the_file() {
    let fx = Fx::new();
    fx.enrollment(false);
    let scope = GrantScope::Conjunction {
        principal: id(1),
        volume: volume("data"),
    };
    let got = apply(&fx, expected(0), &issue(scope.clone()), &NOW).unwrap();
    let wanted = DebugGrant::new(GrantFields {
        incarnation: incarnation(),
        file_revision: 1,
        grant_generation: 1,
        action: GrantAction::Issue,
        issuer_uid: nix::unistd::geteuid().as_raw(),
        owner: Owner::from_bytes(b"operator").unwrap(),
        reason: Reason::from_bytes(b"incident").unwrap(),
        issued_at: NOW.0,
        expires_at: Timestamp {
            secs: 700,
            nanos: 123,
        },
        scope,
        line_ceiling: 50,
        byte_ceiling: 50_000,
    })
    .unwrap();
    assert_eq!(
        decode_grant(&fx.bytes().unwrap()).unwrap(),
        wanted,
        "published fields including incarnation"
    );
    assert_eq!(got, wanted);
    assert_eq!(show_on(&NixOps, &fx.dir, OPTIONS).unwrap(), Some(wanted));
}

#[test]
fn debug_grant_reissue_continues_revision_and_increments_generation() {
    for (other_incarnation, expired, revoked) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let fx = Fx::new();
        let mut f = base(GrantScope::Volume(volume("data"))).fields().clone();
        if other_incarnation {
            f.incarnation = Incarnation::from_bytes([9; 16]);
        }
        if revoked {
            f.action = GrantAction::Revoke;
        }
        fx.put(&DebugGrant::new(f).unwrap());
        let clock = if expired {
            Fixed(Timestamp {
                secs: 700,
                nanos: 123,
            })
        } else {
            Fixed(NOW.0)
        };
        let got = apply(
            &fx,
            expected(4),
            &issue(GrantScope::Volume(volume("data"))),
            &clock,
        )
        .unwrap();
        assert_eq!(
            (got.fields().file_revision, got.fields().grant_generation),
            (5, 3)
        );
        assert_eq!(got.fields().incarnation, incarnation());
        assert_eq!(decode_grant(&fx.bytes().unwrap()).unwrap(), got);
    }
}

#[test]
fn debug_grant_issue_refusals_leave_bytes_unchanged() {
    let scope = GrantScope::Volume(volume("data"));
    let fx = Fx::new();
    fx.put(&base(scope.clone()));
    let before = fx.bytes();
    refused(
        apply(&fx, expected(4), &issue(scope.clone()), &NOW),
        "live-grant",
    );
    refused(
        apply(&fx, expected(3), &issue(scope.clone()), &NOW),
        "revision-mismatch",
    );
    assert_eq!(fx.bytes(), before);
    let fx = Fx::new();
    refused(
        apply(&fx, expected(0), &issue(GrantScope::Principal(id(1))), &NOW),
        "enrollment-unavailable",
    );
    fx.enrollment(false);
    refused(
        apply(&fx, expected(0), &issue(GrantScope::Principal(id(2))), &NOW),
        "principal-absent",
    );
    fx.enrollment(true);
    refused(
        apply(&fx, expected(0), &issue(GrantScope::Principal(id(1))), &NOW),
        "principal-retired",
    );
    assert_eq!(fx.bytes(), None);
    for (duration, lines, bytes, code) in [
        (0, 1, 1024, "duration-bound"),
        (901, 1, 1024, "duration-bound"),
        (1, 0, 1024, "issuance-budget"),
        (1, 1025, 1024, "issuance-budget"),
        (1, 1, 1023, "issuance-budget"),
        (1, 1, 1_048_577, "issuance-budget"),
    ] {
        let mut m = issue(scope.clone());
        if let Mutation::Issue(i) = &mut m {
            i.duration = duration;
            i.lines = lines;
            i.bytes = bytes;
        }
        refused(apply(&fx, expected(0), &m, &NOW), code);
        assert_eq!(fx.bytes(), None);
    }
    refused(
        apply(
            &fx,
            expected(0),
            &issue(scope.clone()),
            &Fixed(Timestamp {
                secs: i64::MAX,
                nanos: 0,
            }),
        ),
        "timestamp-overflow",
    );
    refused(
        apply(
            &fx,
            expected(0),
            &issue(scope.clone()),
            &Fixed(Timestamp {
                secs: 0,
                nanos: 1_000_000_000,
            }),
        ),
        "invalid-clock",
    );
    let mut f = base(scope.clone()).fields().clone();
    f.file_revision = u64::MAX;
    f.grant_generation = u64::MAX;
    fx.put(&DebugGrant::new(f).unwrap());
    let before = fx.bytes();
    refused(
        apply(
            &fx,
            expected(u64::MAX),
            &issue(scope),
            &Fixed(Timestamp {
                secs: 800,
                nanos: 0,
            }),
        ),
        "revision-overflow",
    );
    assert_eq!(fx.bytes(), before);
}

#[test]
fn debug_grant_narrowing_widening_is_refused() {
    let p = GrantScope::Principal(id(1));
    let v = GrantScope::Volume(volume("data"));
    let both = GrantScope::Conjunction {
        principal: id(1),
        volume: volume("data"),
    };
    let cases = [
        (p.clone(), v.clone()),
        (v.clone(), p.clone()),
        (both.clone(), p.clone()),
        (both.clone(), v.clone()),
        (p.clone(), GrantScope::Principal(id(2))),
        (v.clone(), GrantScope::Volume(volume("other"))),
        (
            p.clone(),
            GrantScope::Conjunction {
                principal: id(2),
                volume: volume("data"),
            },
        ),
        (
            v.clone(),
            GrantScope::Conjunction {
                principal: id(1),
                volume: volume("other"),
            },
        ),
        (
            both.clone(),
            GrantScope::Conjunction {
                principal: id(2),
                volume: volume("data"),
            },
        ),
        (
            both,
            GrantScope::Conjunction {
                principal: id(1),
                volume: volume("other"),
            },
        ),
    ];
    for (old, new) in cases {
        let fx = Fx::new();
        fx.put(&base(old));
        let before = fx.bytes();
        refused(
            apply(&fx, expected(4), &Mutation::Narrow(narrow(new)), &NOW),
            "scope-widening",
        );
        assert_eq!(
            fx.bytes(),
            before,
            "widening must leave published bytes unchanged"
        );
    }
}

#[test]
fn debug_grant_narrowing_expiry_extension_is_refused() {
    let fx = Fx::new();
    let scope = GrantScope::Volume(volume("data"));
    fx.put(&base(scope.clone()));
    let before = fx.bytes();
    for expires_at in [
        Timestamp {
            secs: 701,
            nanos: 123,
        },
        Timestamp {
            secs: 700,
            nanos: 124,
        },
    ] {
        let mut n = narrow(scope.clone());
        n.expires_at = expires_at;
        refused(
            apply(&fx, expected(4), &Mutation::Narrow(n), &NOW),
            "expiry-extension",
        );
        assert_eq!(fx.bytes(), before);
    }
}

#[test]
fn debug_grant_expired_narrowing_is_refused_at_the_boundary() {
    let fx = Fx::new();
    let scope = GrantScope::Volume(volume("data"));
    fx.put(&base(scope.clone()));
    let before = fx.bytes();
    // Positive control one nanosecond before the exact expiry.
    let control = Fx::new();
    control.put(&base(scope.clone()));
    apply(
        &control,
        expected(4),
        &Mutation::Narrow(narrow(scope.clone())),
        &Fixed(Timestamp {
            secs: 700,
            nanos: 122,
        }),
    )
    .unwrap();
    for now in [
        Timestamp {
            secs: 700,
            nanos: 123,
        },
        Timestamp {
            secs: 701,
            nanos: 0,
        },
    ] {
        refused(
            apply(
                &fx,
                expected(4),
                &Mutation::Narrow(narrow(scope.clone())),
                &Fixed(now),
            ),
            "expired",
        );
        assert_eq!(fx.bytes(), before);
    }
}

#[test]
fn debug_grant_narrowing_preserves_metadata_and_allows_conjunction_and_zero() {
    let both = GrantScope::Conjunction {
        principal: id(1),
        volume: volume("data"),
    };
    for scope in [
        GrantScope::Principal(id(1)),
        GrantScope::Volume(volume("data")),
        both.clone(),
    ] {
        let fx = Fx::new();
        fx.enrollment(false);
        let old = base(scope);
        fx.put(&old);
        let mut n = narrow(both.clone());
        n.lines = 0;
        n.bytes = 0;
        n.expires_at = Timestamp {
            secs: 600,
            nanos: 0,
        };
        let mut wanted = old.fields().clone();
        wanted.file_revision = 5;
        wanted.action = GrantAction::Narrow;
        wanted.scope = both.clone();
        wanted.line_ceiling = 0;
        wanted.byte_ceiling = 0;
        wanted.expires_at = n.expires_at;
        let got = apply(&fx, expected(4), &Mutation::Narrow(n), &NOW).unwrap();
        assert_eq!(got, DebugGrant::new(wanted).unwrap());
        assert_eq!(decode_grant(&fx.bytes().unwrap()).unwrap(), got);
    }
}

#[test]
fn debug_grant_narrow_and_revoke_refusals_leave_bytes_unchanged() {
    let scope = GrantScope::Volume(volume("data"));
    let fx = Fx::new();
    for m in [
        Mutation::Narrow(narrow(scope.clone())),
        Mutation::Revoke { generation: 2 },
    ] {
        refused(apply(&fx, expected(0), &m, &NOW), "missing-grant");
        fx.put(&base(scope.clone()));
        let before = fx.bytes();
        refused(
            apply(
                &fx,
                Expected {
                    incarnation: Incarnation::from_bytes([0; 16]),
                    revision: 4,
                },
                &m,
                &NOW,
            ),
            "incarnation-mismatch",
        );
        let wrong = match &m {
            Mutation::Narrow(n) => {
                let mut n = n.clone();
                n.generation = 3;
                Mutation::Narrow(n)
            }
            _ => Mutation::Revoke { generation: 3 },
        };
        refused(apply(&fx, expected(4), &wrong, &NOW), "generation-mismatch");
        assert_eq!(fx.bytes(), before);
        std::fs::remove_file(fx.dir.join(NAME)).unwrap();
    }
}

#[test]
fn debug_grant_budget_unchanged_invalid_and_revoked_refusals() {
    let scope = GrantScope::Volume(volume("data"));
    let fx = Fx::new();
    fx.put(&base(scope.clone()));
    let before = fx.bytes();
    for (lines, bytes, expiry, code) in [
        (
            51,
            50_000,
            Timestamp {
                secs: 700,
                nanos: 123,
            },
            "budget-increase",
        ),
        (
            49,
            50_001,
            Timestamp {
                secs: 700,
                nanos: 123,
            },
            "budget-increase",
        ),
        (
            50,
            50_000,
            Timestamp {
                secs: 700,
                nanos: 123,
            },
            "unchanged",
        ),
        (49, 50_000, NOW.0, "invalid-record"),
        (
            49,
            50_000,
            Timestamp {
                secs: 700,
                nanos: 1_000_000_000,
            },
            "expiry-extension",
        ),
    ] {
        let mut n = narrow(scope.clone());
        n.lines = lines;
        n.bytes = bytes;
        n.expires_at = expiry;
        refused(apply(&fx, expected(4), &Mutation::Narrow(n), &NOW), code);
        assert_eq!(fx.bytes(), before);
    }
    refused(
        apply(
            &fx,
            expected(4),
            &Mutation::Narrow(narrow(scope.clone())),
            &Fixed(Timestamp {
                secs: 100,
                nanos: 1_000_000_000,
            }),
        ),
        "invalid-clock",
    );
    let revoked = apply(
        &fx,
        expected(4),
        &Mutation::Revoke { generation: 2 },
        &Fixed(Timestamp {
            secs: 800,
            nanos: 0,
        }),
    )
    .unwrap();
    let mut wanted = base(scope.clone()).fields().clone();
    wanted.file_revision = 5;
    wanted.action = GrantAction::Revoke;
    assert_eq!(
        revoked,
        DebugGrant::new(wanted).unwrap(),
        "expired revoke retains all metadata"
    );
    assert_eq!(decode_grant(&fx.bytes().unwrap()).unwrap(), revoked);
    let before = fx.bytes();
    refused(
        apply(&fx, expected(5), &Mutation::Narrow(narrow(scope)), &NOW),
        "revoked",
    );
    refused(
        apply(&fx, expected(5), &Mutation::Revoke { generation: 2 }, &NOW),
        "revoked",
    );
    assert_eq!(fx.bytes(), before);
}

#[test]
fn debug_grant_revision_compare_and_swap_allows_exactly_one_writer() {
    let fx = Fx::new();
    let scope = GrantScope::Volume(volume("data"));
    fx.put(&base(scope.clone()));
    let ops = Recorder::new();
    let pause = Arc::new(Pause::default());
    let hook = Arc::clone(&pause);
    ops.set_hook(move |call, phase| {
        if *call == Call::CreateExclAt(TEMP.to_owned()) && phase == Phase::Before {
            hook.arrive_and_wait();
        }
        Ok(())
    });
    let dir = fx.dir.clone();
    let a_change = Mutation::Narrow(narrow(scope.clone()));
    let a =
        std::thread::spawn(move || mutate_on(&ops, &dir, OPTIONS, expected(4), &a_change, &NOW));
    assert!(pause.wait_arrived(Duration::from_secs(5)));
    let b_ops = Recorder::new();
    let locking = Arc::new(Pause::default());
    let hook = Arc::clone(&locking);
    b_ops.set_hook(move |call, phase| {
        if matches!(call, Call::Lock { .. }) && phase == Phase::Before {
            hook.release();
            hook.arrive_and_wait();
        }
        Ok(())
    });
    let dir = fx.dir.clone();
    let mut b_narrow = narrow(scope);
    b_narrow.lines = 48;
    let (tx, rx) = mpsc::channel();
    let b = std::thread::spawn(move || {
        tx.send(mutate_on(
            &b_ops,
            &dir,
            OPTIONS,
            expected(4),
            &Mutation::Narrow(b_narrow),
            &NOW,
        ))
        .unwrap();
    });
    assert!(locking.wait_arrived(Duration::from_secs(5)));
    let early = rx.recv_timeout(Duration::from_millis(100));
    pause.release();
    let published = a.join().unwrap().unwrap();
    assert!(
        early.is_err(),
        "second writer waited on the directory flock"
    );
    let result = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    b.join().unwrap();
    refused(result, "revision-mismatch");
    assert_eq!(
        fx.bytes().unwrap(),
        encode_grant(&published).as_bytes(),
        "exactly one writer published"
    );
}

#[test]
fn debug_grant_issue_accepts_all_scopes_and_issuance_boundaries() {
    for scope in [
        GrantScope::Principal(id(1)),
        GrantScope::Volume(volume("data")),
        GrantScope::Conjunction {
            principal: id(1),
            volume: volume("data"),
        },
    ] {
        for (duration, lines, bytes) in [(1, 1, 1024), (900, 1024, 1_048_576)] {
            let fx = Fx::new();
            fx.enrollment(false);
            let mut m = issue(scope.clone());
            if let Mutation::Issue(i) = &mut m {
                i.duration = duration;
                i.lines = lines;
                i.bytes = bytes;
                i.owner = Owner::from_bytes(&[b'o'; 64]).unwrap();
                i.reason = Reason::from_bytes(&[b'r'; 256]).unwrap();
            }
            let clock = Fixed(Timestamp {
                secs: i64::MIN,
                nanos: 999_999_999,
            });
            let got = apply(&fx, expected(0), &m, &clock).unwrap();
            assert_eq!(got.fields().issued_at, clock.0);
            assert_eq!(
                got.fields().expires_at,
                Timestamp {
                    secs: i64::MIN + i64::try_from(duration).unwrap(),
                    nanos: 999_999_999
                }
            );
            assert_eq!(
                granary_core::debug_grant::decode_grant(&fx.bytes().unwrap()).unwrap(),
                got
            );
        }
    }
}

#[test]
fn debug_grant_mutation_serializes_with_enrollment_on_the_same_directory_lock() {
    let fx = Fx::new();
    fx.enrollment(false);
    let ops = Recorder::new();
    let pause = Arc::new(Pause::default());
    let hook = Arc::clone(&pause);
    ops.set_hook(move |call, phase| {
        if *call == Call::CreateExclAt(TEMP.to_owned()) && phase == Phase::Before {
            hook.arrive_and_wait();
        }
        Ok(())
    });
    let dir = fx.dir.clone();
    let a = std::thread::spawn(move || {
        mutate_on(
            &ops,
            &dir,
            OPTIONS,
            expected(0),
            &issue(GrantScope::Principal(id(1))),
            &NOW,
        )
    });
    assert!(pause.wait_arrived(Duration::from_secs(5)));
    let dir = fx.dir.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let b = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        done_tx
            .send(crate::enrollment::attach(
                &dir,
                OPTIONS,
                id(1),
                ClientSpkiDigest::from_bytes([2; 32]),
            ))
            .unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let early = done_rx.recv_timeout(Duration::from_millis(100));
    pause.release();
    let grant = a.join().unwrap().unwrap();
    let finished_early = early.is_ok();
    let attached = early
        .or_else(|_| done_rx.recv_timeout(Duration::from_secs(5)))
        .unwrap()
        .unwrap();
    b.join().unwrap();
    assert!(
        !finished_early,
        "enrollment waited for the grant's directory flock"
    );
    assert_eq!(attached.0, id(1));
    assert_eq!(decode_grant(&fx.bytes().unwrap()).unwrap(), grant);
    let set =
        granary_core::enrollment::decode_set(&std::fs::read(fx.dir.join("ENROLLMENT")).unwrap())
            .unwrap();
    assert!(set.lookup(&ClientSpkiDigest::from_bytes([2; 32])).is_some());
}

#[test]
fn debug_grant_narrow_introduced_principal_must_be_enrolled_and_active() {
    let scope = GrantScope::Volume(volume("data"));
    let both = GrantScope::Conjunction {
        principal: id(1),
        volume: volume("data"),
    };
    for (enrolled, retired, want) in [
        (true, false, "principal-absent"),
        (true, true, "principal-retired"),
        (false, false, "enrollment-unavailable"),
    ] {
        let fx = Fx::new();
        if enrolled {
            fx.enrollment(retired);
        }
        fx.put(&base(scope.clone()));
        let before = fx.bytes();
        let mut n = narrow(both.clone());
        if enrolled && !retired {
            n.scope = GrantScope::Conjunction {
                principal: id(2),
                volume: volume("data"),
            };
        }
        refused(apply(&fx, expected(4), &Mutation::Narrow(n), &NOW), want);
        assert_eq!(
            fx.bytes(),
            before,
            "introducing an unavailable principal changes no grant bytes"
        );
    }
    let fx = Fx::new();
    fx.enrollment(false);
    fx.put(&base(scope));
    let got = apply(
        &fx,
        expected(4),
        &Mutation::Narrow(narrow(both.clone())),
        &NOW,
    )
    .unwrap();
    assert_eq!(got.fields().scope, both);
    assert_eq!(decode_grant(&fx.bytes().unwrap()).unwrap(), got);
}

#[test]
fn debug_grant_issue_and_narrow_read_the_clock_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Counted {
        value: Timestamp,
        calls: AtomicUsize,
    }
    impl Clock for Counted {
        fn now(&self) -> Timestamp {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.value
        }
    }
    for valid in [true, false] {
        for issuing in [true, false] {
            let fx = Fx::new();
            let scope = GrantScope::Volume(volume("data"));
            let (e, mutation) = if issuing {
                (expected(0), issue(scope))
            } else {
                fx.put(&base(scope.clone()));
                (expected(4), Mutation::Narrow(narrow(scope)))
            };
            let value = if valid {
                NOW.0
            } else {
                Timestamp {
                    secs: 100,
                    nanos: 1_000_000_000,
                }
            };
            let clock = Counted {
                value,
                calls: AtomicUsize::new(0),
            };
            let result = apply(&fx, e, &mutation, &clock);
            if valid {
                result.unwrap();
            } else {
                refused(result, "invalid-clock");
            }
            assert_eq!(
                clock.calls.load(Ordering::Relaxed),
                1,
                "one clock reading per time-dependent verb"
            );
        }
    }
}
