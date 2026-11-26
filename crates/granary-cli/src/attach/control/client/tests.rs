// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

use super::super::tests::hello;
use super::*;
use granary_core::mount_control::{Report, ReportKind, ResultKind};

struct FixedNow(tokio::time::Instant);
impl SyncRuntime for FixedNow {
    fn now(&self) -> tokio::time::Instant {
        self.0
    }
    fn spawn<T: Send + 'static>(
        &self,
        work: impl std::future::Future<Output = T> + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, granary_client::SyncRuntimeError>> + Send {
        TokioSyncRuntime.spawn(work)
    }
    fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, granary_client::SyncRuntimeError>> + Send {
        TokioSyncRuntime.blocking(work)
    }
    fn blocking_async<T: Send + 'static, F: std::future::Future<Output = T> + Send + 'static>(
        &self,
        work: impl FnOnce() -> F + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, granary_client::SyncRuntimeError>> + Send {
        TokioSyncRuntime.blocking_async(work)
    }
    fn sleep(&self, duration: Duration) -> impl std::future::Future<Output = ()> + Send {
        TokioSyncRuntime.sleep(duration)
    }
    fn timeout_at<T: Send>(
        &self,
        deadline: tokio::time::Instant,
        work: impl std::future::Future<Output = T> + Send,
    ) -> impl std::future::Future<Output = Result<T, granary_client::SyncRuntimeError>> + Send {
        TokioSyncRuntime.timeout_at(deadline, work)
    }
}

#[tokio::test]
async fn control_clock_overflow_is_unknown() {
    use super::super::testkit::{ScriptedStream, frame};
    let mut maximum = TokioSyncRuntime.now();
    for shift in (0..64).rev() {
        if let Some(later) = maximum.checked_add(Duration::from_secs(1_u64 << shift)) {
            maximum = later;
        }
    }
    assert!(
        maximum.checked_add(Duration::from_secs(2)).is_none(),
        "fixture maximum={maximum:?}"
    );
    let hello = hello();
    let mut cases = 0;
    for (now, overflow) in [(TokioSyncRuntime.now(), false), (maximum, true)] {
        let bytes = [
            frame(&Message::Hello(hello.clone())),
            frame(&Message::Accepted(hello.instance)),
            frame(&Message::Final {
                instance: hello.instance,
                result: ResultKind::Clean,
                report: Some(Report {
                    kind: ReportKind::Committed(9),
                    elapsed_ms: 12,
                    residue: None,
                }),
            }),
        ]
        .concat();
        let (stream, script) = ScriptedStream::new(bytes);
        let lines = std::sync::Mutex::new(Vec::new());
        let result = exchange(
            stream,
            hello.key,
            0,
            0,
            TokioSyncRuntime.now() + HANDSHAKE_BOUND,
            &FixedNow(now),
            &|line| lines.lock().unwrap().push(line),
        )
        .await;
        if overflow {
            assert_eq!(
                (
                    result.unwrap_err().to_string(),
                    script.lock().unwrap().output.clone(),
                    lines.into_inner().unwrap()
                ),
                (
                    "control deadline overflow".into(),
                    Vec::<u8>::new(),
                    vec![unknown(Some(&hello))]
                )
            );
        } else {
            assert_eq!(result.unwrap(), MountOutcome::Clean);
            assert_eq!(
                script.lock().unwrap().output,
                frame(&Message::Stop {
                    instance: hello.instance,
                    key: hello.key
                })
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one finite table spells out every valid report/result/mode status"
)]
fn umount_exit_table() {
    use granary_core::mount_control::FailureClass;
    let hello = hello();
    let endings = [
        (
            ResultKind::Clean,
            MountOutcome::Clean,
            "; daemon ending clean (exit 0)",
        ),
        (
            ResultKind::RuntimeFailure,
            MountOutcome::RuntimeFailure,
            "; daemon session/cache ending was not clean (exit 1)",
        ),
        (
            ResultKind::CacheCloseFailed,
            MountOutcome::CacheCloseFailed,
            "; daemon session/cache ending was not clean; cache failed or was not closed (exit 3)",
        ),
    ];
    let kept = "the overlay, staging and intent are kept in store: preserve it; the next mount with this store can finish interrupted non-fenced shutdown before serving; fenced or damaged state needs explicit recovery";
    let mut cases = 0;
    for (kind, data) in [
        (
            ReportKind::Committed(9),
            "shutdown committed seq=9 in 12 ms",
        ),
        (ReportKind::Clean, "shutdown had nothing to commit in 12 ms"),
    ] {
        for (result, expected, suffix) in endings {
            let report = Some(Report {
                kind,
                elapsed_ms: 12,
                residue: None,
            });
            assert_eq!(
                status(
                    &hello,
                    &Message::Final {
                        instance: hello.instance,
                        result,
                        report
                    }
                )
                .unwrap(),
                (
                    expected,
                    format!("gran umount: {data}; store store; counts not reported{suffix}")
                )
            );
            cases += 1;
        }
    }
    for (kind, result, expected, data, suffix) in [
        (
            ReportKind::Bound,
            ResultKind::Stopped,
            MountOutcome::Stopped,
            "shutdown stopped at its bound after 12 ms",
            "; daemon stopped (exit 4)",
        ),
        (
            ReportKind::Signal,
            ResultKind::Stopped,
            MountOutcome::Stopped,
            "shutdown stopped by a signal after 12 ms",
            "; daemon stopped (exit 4)",
        ),
        (
            ReportKind::UnknownCut,
            ResultKind::Stopped,
            MountOutcome::Stopped,
            "shutdown stopped; the cut was not recorded after 12 ms",
            "; daemon stopped (exit 4)",
        ),
        (
            ReportKind::Internal,
            ResultKind::RuntimeFailure,
            MountOutcome::RuntimeFailure,
            "shutdown lost its sequence after 12 ms",
            "; daemon session/cache ending was not clean (exit 1)",
        ),
    ] {
        let report = Some(Report {
            kind,
            elapsed_ms: 12,
            residue: None,
        });
        assert_eq!(
            status(
                &hello,
                &Message::Final {
                    instance: hello.instance,
                    result,
                    report
                }
            )
            .unwrap(),
            (
                expected,
                format!("gran umount: {data}: what was left could not be read; {kept}{suffix}")
            )
        );
        assert_eq!(
            status(
                &hello,
                &Message::Final {
                    instance: hello.instance,
                    result: ResultKind::Clean,
                    report
                }
            )
            .unwrap_err()
            .to_string(),
            "invalid mount control final result/report/mode"
        );
        cases += 1;
    }
    for (class, label) in [
        (FailureClass::Io, "io"),
        (FailureClass::Refused, "refused"),
        (FailureClass::Conflict, "conflict"),
        (FailureClass::Unavailable, "unavailable"),
        (FailureClass::Corrupt, "corrupt"),
        (FailureClass::Internal, "internal"),
    ] {
        let report = Some(Report {
            kind: ReportKind::Failed(class),
            elapsed_ms: 12,
            residue: None,
        });
        assert_eq!(
            status(
                &hello,
                &Message::Final {
                    instance: hello.instance,
                    result: ResultKind::RuntimeFailure,
                    report
                }
            )
            .unwrap(),
            (
                MountOutcome::RuntimeFailure,
                format!(
                    "gran umount: shutdown failed ({label}) after 12 ms: what was left could not be read; {kept}; daemon session/cache ending was not clean (exit 1)"
                )
            )
        );
        cases += 1;
    }
    let fenced = Message::Final {
        instance: hello.instance,
        result: ResultKind::Fenced,
        report: Some(Report {
            kind: ReportKind::Fenced,
            elapsed_ms: 12,
            residue: None,
        }),
    };
    assert_eq!(status(&hello,&fenced).unwrap(),(MountOutcome::Fenced,"gran umount: shutdown fenced after 12 ms: what was left could not be read; the authority refused this mount's ownership or its commit; the overlay is kept in store: preserve it; recovery is explicit; daemon fenced (exit 5)".into()));
    cases += 1;
    assert_eq!(status(&hello,&Message::Final{instance:hello.instance,result:ResultKind::RuntimeFailure,report:None}).unwrap(),
        (MountOutcome::RuntimeFailure,"gran umount: the shutdown did not run; the overlay is kept in store: preserve it; the next mount with this store can finish interrupted non-fenced shutdown before serving; fenced or damaged state needs explicit recovery; elapsed time and counts unknown; daemon session/cache ending was not clean (exit 1)".into()));
    cases += 1;
    let readonly = Hello {
        mode: Mode::ReadOnly,
        ..hello.clone()
    };
    for (result, expected, suffix) in endings {
        assert_eq!(
            status(
                &readonly,
                &Message::Final {
                    instance: readonly.instance,
                    result,
                    report: None
                }
            )
            .unwrap(),
            (
                expected,
                format!("gran umount: read-only daemon ending{suffix}")
            )
        );
        cases += 1;
    }
    assert_eq!(
        unknown(Some(&hello)),
        "gran umount: shutdown outcome unknown; preserve store store; inspect the daemon's status"
    );
    assert_eq!(
        unknown(None),
        "gran umount: shutdown outcome unavailable; inspect the daemon's status"
    );
    assert_eq!(cases, 21);
}

#[test]
fn control_advertised_bound_and_unknown() {
    let mut hello = hello();
    let mut cases = 0;
    for (bound, expected) in [(0, 35_500), (1, 36_500), (30, 65_500), (3600, 3_635_500)] {
        hello.mode = if bound == 0 {
            Mode::ReadOnly
        } else {
            Mode::Writable {
                bound_seconds: bound,
                store: b"store".to_vec(),
            }
        };
        assert_eq!(final_wait(&hello), Duration::from_millis(expected));
        cases += 1;
    }
    assert_eq!(cases, 4);
}

#[tokio::test]
async fn control_disconnect_and_death() {
    use super::super::testkit::{ScriptedStream, frame};
    let hello = hello();
    let mut cases = 0;
    for (result, expected) in [
        (ResultKind::Clean, MountOutcome::Clean),
        (ResultKind::RuntimeFailure, MountOutcome::RuntimeFailure),
        (ResultKind::CacheCloseFailed, MountOutcome::CacheCloseFailed),
        (ResultKind::Stopped, MountOutcome::Stopped),
        (ResultKind::Fenced, MountOutcome::Fenced),
    ] {
        let report = Some(Report {
            kind: match result {
                ResultKind::Stopped => ReportKind::Signal,
                ResultKind::Fenced => ReportKind::Fenced,
                _ => ReportKind::Committed(9),
            },
            elapsed_ms: 12,
            residue: None,
        });
        let final_bytes = frame(&Message::Final {
            instance: hello.instance,
            result,
            report,
        });
        for cut in [0, 1, final_bytes.len() - 1, final_bytes.len()] {
            let mut bytes = frame(&Message::Hello(hello.clone()));
            bytes.extend(frame(&Message::Accepted(hello.instance)));
            bytes.extend_from_slice(&final_bytes[..cut]);
            let (stream, script) = ScriptedStream::new(bytes);
            script.lock().unwrap().eof = true;
            let lines = std::sync::Mutex::new(Vec::new());
            let sink = |line| lines.lock().unwrap().push(line);
            let actual = exchange(
                stream,
                hello.key,
                0,
                0,
                TokioSyncRuntime.now() + HANDSHAKE_BOUND,
                &TokioSyncRuntime,
                &sink,
            )
            .await;
            if cut == final_bytes.len() {
                assert_eq!(actual.unwrap(), expected);
            } else {
                assert!(actual.is_err(), "partial Final accepted: {actual:?}");
                assert_eq!(lines.lock().unwrap().last(), Some(&unknown(Some(&hello))));
            }
            assert_eq!(
                script.lock().unwrap().output,
                frame(&Message::Stop {
                    instance: hello.instance,
                    key: hello.key
                })
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 20);
}

#[tokio::test(start_paused = true)]
async fn control_absolute_deadlines_and_boundary() {
    use super::super::testkit::{ScriptedStream, frame};
    use std::{future::Future as _, task::Poll};
    let mut cases = 0;
    for (bound, wait_ms) in [(0, 35_500), (1, 36_500), (30, 65_500), (3600, 3_635_500)] {
        for complete in [false, true] {
            let mut hello = hello();
            if bound == 0 {
                hello.mode = Mode::ReadOnly;
            } else {
                hello.mode = Mode::Writable {
                    bound_seconds: bound,
                    store: b"store".to_vec(),
                };
            }
            let mut bytes = frame(&Message::Hello(hello.clone()));
            bytes.extend(frame(&Message::Accepted(hello.instance)));
            let (stream, script) = ScriptedStream::new(bytes);
            let lines = std::sync::Mutex::new(Vec::new());
            let sink = |line| lines.lock().unwrap().push(line);
            let mut exchange = std::pin::pin!(exchange(
                stream,
                hello.key,
                0,
                0,
                TokioSyncRuntime.now() + HANDSHAKE_BOUND,
                &TokioSyncRuntime,
                &sink
            ));
            let first = std::future::poll_fn(|cx| Poll::Ready(exchange.as_mut().poll(cx))).await;
            assert!(first.is_pending(), "first poll={first:?}");
            let final_bytes = frame(&Message::Final {
                instance: hello.instance,
                result: ResultKind::Clean,
                report: (bound != 0).then_some(Report {
                    kind: ReportKind::Committed(9),
                    elapsed_ms: 12,
                    residue: None,
                }),
            });
            tokio::time::advance(Duration::from_millis(10)).await;
            script.lock().unwrap().input.extend(&final_bytes[..2]);
            let partial = std::future::poll_fn(|cx| Poll::Ready(exchange.as_mut().poll(cx))).await;
            assert!(partial.is_pending(), "partial poll={partial:?}");
            tokio::time::advance(Duration::from_millis(wait_ms - 11)).await;
            let before = std::future::poll_fn(|cx| Poll::Ready(exchange.as_mut().poll(cx))).await;
            assert!(
                before.is_pending(),
                "premature final deadline: {before:?}, bound={bound}"
            );
            if complete {
                script.lock().unwrap().input.extend(&final_bytes[2..]);
            }
            tokio::time::advance(Duration::from_millis(1)).await;
            let boundary = std::future::poll_fn(|cx| Poll::Ready(exchange.as_mut().poll(cx))).await;
            match boundary {
                Poll::Ready(Ok(outcome)) if complete => assert_eq!(outcome, MountOutcome::Clean),
                Poll::Ready(Err(error)) if !complete => {
                    assert_eq!(error.to_string(), "control Final deadline");
                    assert_eq!(lines.lock().unwrap().last(), Some(&unknown(Some(&hello))));
                }
                actual => panic!(
                    "wrong boundary decision for bound={bound}, complete={complete}: {actual:?}"
                ),
            }
            cases += 1;
        }
    }
    assert_eq!(cases, 8);
}

#[tokio::test]
async fn control_key_mismatch_refuses_before_stop() {
    use super::super::testkit::{ScriptedStream, frame};
    let expected = hello();
    let key = expected.key;
    let mut cases = 0;
    for key in [
        MountKey {
            namespace_dev: 3,
            ..key
        },
        MountKey {
            namespace_ino: 3,
            ..key
        },
        MountKey { mount_id: 4, ..key },
        MountKey {
            fuse_major: 1,
            ..key
        },
        MountKey {
            fuse_minor: 5,
            ..key
        },
    ] {
        let advertised = Hello {
            key,
            ..expected.clone()
        };
        let (stream, script) = ScriptedStream::new(frame(&Message::Hello(advertised)));
        let lines = std::sync::Mutex::new(Vec::new());
        let actual = exchange(
            stream,
            expected.key,
            0,
            0,
            TokioSyncRuntime.now() + HANDSHAKE_BOUND,
            &TokioSyncRuntime,
            &|line| lines.lock().unwrap().push(line),
        )
        .await;
        assert_eq!(
            (
                actual.unwrap_err().to_string(),
                script.lock().unwrap().output.clone(),
                lines.into_inner().unwrap()
            ),
            (
                "refusing: control mount identity mismatch".into(),
                Vec::<u8>::new(),
                vec![unknown(None)]
            )
        );
        cases += 1;
    }
    assert_eq!(cases, 5);
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one finite table pairs valid exchanges with peer and ordering refusals"
)]
async fn control_peer_and_message_order_refusals() {
    use super::super::testkit::{ScriptedStream, frame};
    let hello = hello();
    let valid_final = Message::Final {
        instance: hello.instance,
        result: ResultKind::Clean,
        report: Some(Report {
            kind: ReportKind::Committed(9),
            elapsed_ms: 12,
            residue: None,
        }),
    };
    let accepted = Message::Accepted(hello.instance);
    let mut cases = 0;
    for (peer, first, second, last, reason, stops) in [
        (
            None,
            Message::Hello(hello.clone()),
            accepted.clone(),
            valid_final.clone(),
            "refusing: control server peer uid mismatch or unavailable",
            0,
        ),
        (
            Some(1),
            Message::Hello(hello.clone()),
            accepted.clone(),
            valid_final.clone(),
            "refusing: control server peer uid mismatch or unavailable",
            0,
        ),
        (
            Some(0),
            Message::Hello(Hello {
                key: MountKey {
                    mount_id: 99,
                    ..hello.key
                },
                ..hello.clone()
            }),
            accepted.clone(),
            valid_final.clone(),
            "refusing: control mount identity mismatch",
            0,
        ),
        (
            Some(0),
            Message::Accepted(hello.instance),
            accepted.clone(),
            valid_final.clone(),
            "refusing: expected control Hello",
            0,
        ),
        (
            Some(0),
            Message::Hello(hello.clone()),
            Message::Accepted([8; 16]),
            valid_final.clone(),
            "refusing: expected matching control Accepted",
            1,
        ),
        (
            Some(0),
            Message::Hello(hello.clone()),
            Message::Hello(hello.clone()),
            valid_final.clone(),
            "refusing: expected matching control Accepted",
            1,
        ),
        (
            Some(0),
            Message::Hello(hello.clone()),
            accepted.clone(),
            Message::Accepted(hello.instance),
            "invalid mount control message order",
            1,
        ),
        (
            Some(0),
            Message::Hello(hello.clone()),
            accepted.clone(),
            Message::Final {
                instance: [8; 16],
                result: ResultKind::Clean,
                report: Some(Report {
                    kind: ReportKind::Committed(9),
                    elapsed_ms: 12,
                    residue: None,
                }),
            },
            "invalid mount control instance",
            1,
        ),
    ] {
        let (stream, script) =
            ScriptedStream::new([frame(&first), frame(&second), frame(&last)].concat());
        script.lock().unwrap().peer = peer;
        let lines = std::sync::Mutex::new(Vec::new());
        let sink = |line| lines.lock().unwrap().push(line);
        let actual = exchange(
            stream,
            hello.key,
            0,
            0,
            TokioSyncRuntime.now() + HANDSHAKE_BOUND,
            &TokioSyncRuntime,
            &sink,
        )
        .await;
        let output = script.lock().unwrap().output.clone();
        let expected = if stops == 0 {
            Vec::new()
        } else {
            frame(&Message::Stop {
                instance: hello.instance,
                key: hello.key,
            })
        };
        assert_eq!(
            (actual.unwrap_err().to_string(), output),
            (reason.to_owned(), expected)
        );
        assert_eq!(
            lines.lock().unwrap().last(),
            Some(&unknown((stops != 0).then_some(&hello)))
        );
        cases += 1;
    }
    assert_eq!(cases, 8);
}
