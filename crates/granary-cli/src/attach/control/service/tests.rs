// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

use super::super::{
    testkit::{ScriptedListener, ScriptedStream},
    tests::hello,
};
use super::*;

fn final_message() -> Message {
    Message::Final {
        instance: hello().instance,
        result: granary_core::mount_control::ResultKind::RuntimeFailure,
        report: None,
    }
}

struct FaultListener {
    arrivals: std::sync::Mutex<VecDeque<io::Result<ScriptedStream>>>,
    polls: std::cell::Cell<usize>,
}
impl Listener for FaultListener {
    type Stream = ScriptedStream;
    fn poll_accept(&self, _: &mut std::task::Context<'_>) -> Poll<io::Result<Self::Stream>> {
        self.polls.set(self.polls.get() + 1);
        self.arrivals
            .lock()
            .unwrap()
            .pop_front()
            .map_or(Poll::Pending, Poll::Ready)
    }
}

#[tokio::test(start_paused = true)]
async fn control_transient_accept_errors_retry() {
    use super::super::testkit::frame;
    let mut cases = 0;
    for (errno, code) in [
        ("EMFILE", libc::EMFILE),
        ("ENFILE", libc::ENFILE),
        ("ENOBUFS", libc::ENOBUFS),
        ("ECONNABORTED", libc::ECONNABORTED),
        ("EINTR", libc::EINTR),
        ("ENOMEM", libc::ENOMEM),
        ("EAGAIN", libc::EAGAIN),
    ] {
        let (publish, state) = watch::channel(State::Serving(hello()));
        let keep_publisher = publish.clone();
        let (stream, script) = ScriptedStream::new(frame(&Message::Stop {
            instance: hello().instance,
            key: hello().key,
        }));
        script.lock().unwrap().on_read = Some(Box::new(move || {
            publish.send_replace(State::Final {
                message: final_message(),
                published_at: TokioSyncRuntime.now(),
            });
        }));
        let error = || io::Error::from_raw_os_error(code);
        let kind = error().kind();
        let listener = FaultListener {
            arrivals: std::sync::Mutex::new(VecDeque::from([
                Err(error()),
                Err(error()),
                Ok(stream),
            ])),
            polls: std::cell::Cell::new(0),
        };
        let (send, receive) = mpsc::channel();
        let mut service = pin!(serve(&listener, state, send, 0, &TokioSyncRuntime));
        let first = poll_fn(|cx| Poll::Ready(service.as_mut().poll(cx))).await;
        assert!(
            matches!(first, Poll::Pending),
            "transient {errno:?} ended service: {first:?}"
        );
        assert_eq!(
            (listener.polls.get(), receive.try_iter().collect::<Vec<_>>()),
            (1, vec![Exit::ControlError { kind, fatal: false }])
        );
        tokio::time::advance(Duration::from_millis(99)).await;
        let before = poll_fn(|cx| Poll::Ready(service.as_mut().poll(cx))).await;
        assert!(matches!(before, Poll::Pending), "backoff result={before:?}");
        assert_eq!(listener.polls.get(), 1, "accept retried before backoff");
        tokio::time::advance(Duration::from_millis(1)).await;
        let retry = poll_fn(|cx| Poll::Ready(service.as_mut().poll(cx))).await;
        assert!(
            matches!(retry, Poll::Pending),
            "second transient result={retry:?}"
        );
        assert_eq!((listener.polls.get(), receive.try_iter().count()), (2, 0));
        tokio::time::advance(Duration::from_millis(100)).await;
        service.await.unwrap();
        assert_eq!(
            receive.try_iter().collect::<Vec<_>>(),
            vec![Exit::ControlUmount]
        );
        assert_eq!(
            script.lock().unwrap().output,
            [
                frame(&Message::Hello(hello())),
                frame(&Message::Accepted(hello().instance)),
                frame(&final_message())
            ]
            .concat()
        );
        drop(keep_publisher);
        cases += 1;
    }
    assert_eq!(cases, 7);
}

#[test]
fn control_fatal_accept_error_reaches_daemon() {
    let mut cases = 0;
    for error in [
        io::Error::new(io::ErrorKind::InvalidInput, "listener is not listening"),
        io::Error::new(io::ErrorKind::Unsupported, "accept unsupported"),
        io::Error::new(io::ErrorKind::NotConnected, "listener disconnected"),
        io::Error::from_raw_os_error(libc::EBADF),
        io::Error::from_raw_os_error(libc::ENOTSOCK),
    ] {
        let kind = error.kind();
        let listener = FaultListener {
            arrivals: std::sync::Mutex::new(VecDeque::from([Err(error)])),
            polls: std::cell::Cell::new(0),
        };
        let (send, receive) = mpsc::channel();
        let mut control =
            Control::start_with_listener(0, hello().instance, hello().mode, send, (), move |()| {
                Ok(listener)
            })
            .unwrap();
        control.done.recv_timeout(IO_BOUND).unwrap();
        control.thread.take().unwrap().join().unwrap();
        assert_eq!(
            receive.try_iter().collect::<Vec<_>>(),
            vec![Exit::ControlError { kind, fatal: true }]
        );
        cases += 1;
    }
    assert_eq!(cases, 5);
}

#[tokio::test(start_paused = true)]
async fn control_final_interrupts_accept_backoff() {
    let listener = FaultListener {
        arrivals: std::sync::Mutex::new(VecDeque::from([Err(io::Error::from_raw_os_error(
            libc::EMFILE,
        ))])),
        polls: std::cell::Cell::new(0),
    };
    let (publish, state) = watch::channel(State::Serving(hello()));
    let (send, receive) = mpsc::channel();
    let mut service = pin!(serve(&listener, state, send, 0, &TokioSyncRuntime));
    let before = poll_fn(|cx| Poll::Ready(service.as_mut().poll(cx))).await;
    assert!(matches!(before, Poll::Pending), "backoff result={before:?}");
    let now = TokioSyncRuntime.now();
    publish.send_replace(State::Final {
        message: final_message(),
        published_at: now,
    });
    let after = poll_fn(|cx| Poll::Ready(service.as_mut().poll(cx))).await;
    assert!(
        matches!(after, Poll::Ready(Ok(()))),
        "Final during backoff={after:?}"
    );
    assert_eq!(
        (
            listener.polls.get(),
            receive.try_iter().count(),
            TokioSyncRuntime.now()
        ),
        (1, 1, now)
    );
}

#[tokio::test]
async fn control_idle_final_wakes() {
    let mut cases = 0;
    for before in [true, false] {
        let listener = ScriptedListener::default();
        let (publish, state) = watch::channel(State::Starting);
        let (coordinator, _receive) = mpsc::channel();
        let (done, finished) = mpsc::channel();
        if before {
            publish.send_replace(State::Final {
                message: final_message(),
                published_at: TokioSyncRuntime.now(),
            });
        }
        let task = TokioSyncRuntime.spawn(async move {
            let guard = DoneGuard::new(done);
            serve(&listener, state, coordinator, 0, &TokioSyncRuntime)
                .await
                .unwrap();
            guard.send();
        });
        tokio::task::yield_now().await;
        if !before {
            publish.send_replace(State::Final {
                message: final_message(),
                published_at: TokioSyncRuntime.now(),
            });
        }
        let result = TokioSyncRuntime
            .timeout_at(TokioSyncRuntime.now() + IO_BOUND, task)
            .await;
        assert!(matches!(result, Ok(Ok(()))), "idle final result={result:?}");
        assert_eq!(finished.try_recv(), Ok(()));
        cases += 1;
    }
    let listener = ScriptedListener::default();
    let (publish, state) = watch::channel(State::Serving(hello()));
    let (coordinator, _receive) = mpsc::channel();
    drop(publish);
    let result = serve(&listener, state, coordinator, 0, &TokioSyncRuntime).await;
    assert_eq!(result.unwrap_err().to_string(), "control publisher lost");
    assert_eq!(cases, 2);
}

#[tokio::test]
async fn control_publication_between_check_and_park() {
    struct PublishOnAccept(std::sync::Mutex<Option<watch::Sender<State>>>);
    impl Listener for PublishOnAccept {
        type Stream = ScriptedStream;
        fn poll_accept(&self, _: &mut std::task::Context<'_>) -> Poll<io::Result<ScriptedStream>> {
            if let Some(publish) = self.0.lock().unwrap().take() {
                publish.send_replace(State::Final {
                    message: final_message(),
                    published_at: TokioSyncRuntime.now(),
                });
            }
            Poll::Pending
        }
    }
    let (publish, state) = watch::channel(State::Starting);
    let listener = PublishOnAccept(std::sync::Mutex::new(Some(publish.clone())));
    let (send, _receive) = mpsc::channel();
    let actual = TokioSyncRuntime
        .timeout_at(
            TokioSyncRuntime.now() + IO_BOUND,
            serve(&listener, state, send, 0, &TokioSyncRuntime),
        )
        .await;
    assert!(
        matches!(actual, Ok(Ok(()))),
        "check/park publication={actual:?}"
    );
    assert!(
        listener.0.lock().unwrap().is_none(),
        "fixture never published"
    );
    drop(publish);
}

#[tokio::test]
async fn control_accept_fairness() {
    struct Arrivals {
        count: std::sync::atomic::AtomicUsize,
        publish: std::sync::Mutex<Option<watch::Sender<State>>>,
    }
    impl Listener for Arrivals {
        type Stream = ScriptedStream;
        fn poll_accept(&self, _: &mut std::task::Context<'_>) -> Poll<io::Result<ScriptedStream>> {
            let count = self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            assert!(
                count <= 64,
                "accept work ignored final publication: calls={count}"
            );
            if count == 32 {
                self.publish
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send_replace(State::Final {
                        message: final_message(),
                        published_at: TokioSyncRuntime.now(),
                    });
            }
            Poll::Ready(Ok(ScriptedStream::new(Vec::new()).0))
        }
    }
    let (publish, state) = watch::channel(State::Serving(hello()));
    let listener = Arrivals {
        count: std::sync::atomic::AtomicUsize::new(0),
        publish: std::sync::Mutex::new(Some(publish.clone())),
    };
    let (send, _receive) = mpsc::channel();
    let actual = serve(&listener, state, send, 0, &TokioSyncRuntime).await;
    assert_eq!(
        (
            actual.is_ok(),
            listener.count.load(std::sync::atomic::Ordering::SeqCst)
        ),
        (true, 32),
        "service={actual:?}"
    );
    drop(publish);
}

#[tokio::test]
async fn control_partial_stop_has_no_effect() {
    use super::super::testkit::frame;
    let stop = frame(&Message::Stop {
        instance: hello().instance,
        key: hello().key,
    });
    let mut cases = 0;
    for cut in 0..=stop.len() {
        let (stream, script) = ScriptedStream::new(stop[..cut].to_vec());
        script.lock().unwrap().eof = true;
        let listener = ScriptedListener::default();
        listener.streams.lock().unwrap().push_back(stream);
        let (publish, state) = watch::channel(State::Serving(hello()));
        let (send, receive) = mpsc::channel();
        let task = TokioSyncRuntime
            .spawn(async move { serve(&listener, state, send, 0, &TokioSyncRuntime).await });
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        let requests: Vec<_> = receive.try_iter().collect();
        assert_eq!(
            requests,
            if cut == stop.len() {
                vec![Exit::ControlUmount]
            } else {
                Vec::new()
            },
            "Stop bytes={cut}"
        );
        publish.send_replace(State::Final {
            message: final_message(),
            published_at: TokioSyncRuntime.now(),
        });
        assert!(matches!(task.await, Ok(Ok(()))));
        cases += 1;
    }
    assert_eq!(cases, 60);
}

#[tokio::test]
async fn control_stop_registration() {
    let mut cases = 0;
    for alive in [true, false] {
        let (stream, script) = ScriptedStream::new(Vec::new());
        let (send, receive) = mpsc::channel();
        let mut receive = Some(receive);
        if !alive {
            drop(receive.take());
        }
        let mut connection = Connection {
            stream,
            hello: Some(hello()),
            reader: Reader::default(),
            output: VecDeque::new(),
            deadline: Some(TokioSyncRuntime.now() + IO_BOUND),
            subscribed: false,
            close_after_write: false,
        };
        let mut requested = false;
        connection
            .admit(
                &Message::Stop {
                    instance: hello().instance,
                    key: hello().key,
                },
                &mut requested,
                &send,
            )
            .unwrap();
        assert_eq!(
            (
                requested,
                connection.subscribed,
                connection.output.len(),
                connection.close_after_write
            ),
            (alive, alive, 1, !alive)
        );
        if let Some(receive) = receive {
            assert_eq!(receive.try_recv(), Ok(Exit::ControlUmount));
            connection
                .admit(
                    &Message::Stop {
                        instance: hello().instance,
                        key: hello().key,
                    },
                    &mut requested,
                    &send,
                )
                .unwrap();
            assert_eq!(receive.try_recv(), Err(mpsc::TryRecvError::Empty));
        } else {
            let live = std::future::poll_fn(|cx| {
                Poll::Ready(connection.poll(cx, &mut requested, &send, false))
            })
            .await
            .unwrap();
            assert_eq!(
                (live, script.lock().unwrap().output.clone()),
                (
                    false,
                    super::super::testkit::frame(&Message::Reject(Reject::CoordinatorLost))
                )
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[tokio::test]
async fn control_successful_enqueue_racing_final() {
    use super::super::testkit::frame;
    let (publish, state) = watch::channel(State::Serving(hello()));
    let keep_publisher = publish.clone();
    let (stream, script) = ScriptedStream::new(frame(&Message::Stop {
        instance: hello().instance,
        key: hello().key,
    }));
    script.lock().unwrap().on_read = Some(Box::new(move || {
        publish.send_replace(State::Final {
            message: final_message(),
            published_at: TokioSyncRuntime.now(),
        });
    }));
    let listener = ScriptedListener::default();
    listener.streams.lock().unwrap().push_back(stream);
    let (send, receive) = mpsc::channel();
    serve(&listener, state, send, 0, &TokioSyncRuntime)
        .await
        .unwrap();
    assert_eq!(
        receive.try_iter().collect::<Vec<_>>(),
        vec![Exit::ControlUmount]
    );
    let expected = [
        frame(&Message::Hello(hello())),
        frame(&Message::Accepted(hello().instance)),
        frame(&final_message()),
    ]
    .concat();
    assert_eq!(script.lock().unwrap().output, expected);
    drop(keep_publisher);
}

#[test]
fn control_done_on_unwind() {
    let (send, receive) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let _done = DoneGuard::new(send);
        std::panic::resume_unwind(Box::new("injected control loop panic"));
    });
    assert!(thread.join().is_err());
    assert_eq!(receive.try_recv(), Ok(()));
}

#[tokio::test]
async fn control_drop_closes_starting_and_serving() {
    let mut cases = 0;
    for initial in [State::Starting, State::Serving(hello())] {
        let listener = FaultListener {
            arrivals: std::sync::Mutex::new(VecDeque::new()),
            polls: std::cell::Cell::new(0),
        };
        let (state, receive) = watch::channel(initial);
        let (_done, finished) = mpsc::channel();
        let control = Control {
            state,
            done: finished,
            thread: None,
            instance: hello().instance,
            mode: hello().mode,
            hello: None,
        };
        let (send, _receive) = mpsc::channel();
        let mut service = pin!(serve(&listener, receive, send, 0, &TokioSyncRuntime));
        let before = poll_fn(|cx| Poll::Ready(service.as_mut().poll(cx))).await;
        assert!(matches!(before, Poll::Pending), "live service={before:?}");
        assert!(listener.polls.get() > 0, "listener never polled");
        let polls = listener.polls.get();
        drop(control);
        let after = poll_fn(|cx| Poll::Ready(service.as_mut().poll(cx))).await;
        assert!(
            matches!(after, Poll::Ready(Ok(()))),
            "Closing result={after:?}"
        );
        assert_eq!(listener.polls.get(), polls, "Closing accepted more peers");
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[tokio::test(start_paused = true)]
async fn control_partial_peers_cannot_hold_final() {
    use super::super::testkit::frame;
    let listener = ScriptedListener::default();
    let mut scripts = Vec::new();
    let stop = frame(&Message::Stop {
        instance: hello().instance,
        key: hello().key,
    });
    for index in 0..17 {
        let input = match index {
            0 => stop[..2].to_vec(),
            1 => stop[..9].to_vec(),
            _ => stop.clone(),
        };
        let (stream, script) = ScriptedStream::new(input);
        listener.streams.lock().unwrap().push_back(stream);
        scripts.push(script);
    }
    let (publish, state) = watch::channel(State::Serving(hello()));
    let (send, receive) = mpsc::channel();
    let task = TokioSyncRuntime
        .spawn(async move { serve(&listener, state, send, 0, &TokioSyncRuntime).await });
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert_eq!(receive.try_recv(), Ok(Exit::ControlUmount));
    assert_eq!(receive.try_recv(), Err(mpsc::TryRecvError::Empty));
    assert!(
        scripts[16].lock().unwrap().closed,
        "17th connection remained resident"
    );
    let accepted = [
        frame(&Message::Hello(hello())),
        frame(&Message::Accepted(hello().instance)),
    ]
    .concat();
    for script in scripts.iter().take(15).skip(2) {
        let mut script = script.lock().unwrap();
        assert_eq!(script.output, accepted);
        script.blocked = true;
    }
    publish.send_replace(State::Final {
        message: final_message(),
        published_at: TokioSyncRuntime.now(),
    });
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        scripts[15].lock().unwrap().output,
        [accepted, frame(&final_message())].concat()
    );
    tokio::time::advance(IO_BOUND).await;
    let actual = TokioSyncRuntime
        .timeout_at(
            TokioSyncRuntime.now() + IO_BOUND + Duration::from_millis(500),
            task,
        )
        .await;
    assert!(
        matches!(actual, Ok(Ok(Ok(())))),
        "final delivery={actual:?}"
    );
    assert!(scripts.iter().all(|script| script.lock().unwrap().closed));
    assert_eq!(scripts.len(), 17);
}

#[tokio::test]
async fn control_two_umounts_one_sequence() {
    use super::super::testkit::frame;
    let listener = ScriptedListener::default();
    let mut scripts = Vec::new();
    for _ in 0..2 {
        let (stream, script) = ScriptedStream::new(Vec::new());
        listener.streams.lock().unwrap().push_back(stream);
        scripts.push(script);
    }
    let (publish, state) = watch::channel(State::Serving(hello()));
    let (send, receive) = mpsc::channel();
    let task = TokioSyncRuntime
        .spawn(async move { serve(&listener, state, send, 0, &TokioSyncRuntime).await });
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    for script in &scripts {
        assert_eq!(
            script.lock().unwrap().output,
            frame(&Message::Hello(hello()))
        );
    }
    for script in &scripts {
        let mut script = script.lock().unwrap();
        script.input.extend(frame(&Message::Stop {
            instance: hello().instance,
            key: hello().key,
        }));
        script.wake.take().unwrap().wake();
    }
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert_eq!(receive.try_recv(), Ok(Exit::ControlUmount));
    assert_eq!(receive.try_recv(), Err(mpsc::TryRecvError::Empty));
    publish.send_replace(State::Final {
        message: final_message(),
        published_at: TokioSyncRuntime.now(),
    });
    assert!(matches!(task.await, Ok(Ok(()))));
    let expected = [
        frame(&Message::Hello(hello())),
        frame(&Message::Accepted(hello().instance)),
        frame(&final_message()),
    ]
    .concat();
    for script in &scripts {
        assert_eq!(script.lock().unwrap().output, expected);
    }
    assert_eq!(scripts.len(), 2);
}

#[test]
fn control_final_is_after_cache_and_session() {
    use super::super::super::{MountOutcome, SessionVerdict, finish_control};
    use granary_core::mount_control::{Mode, ResultKind};
    let mut cases = 0;
    for (session, cache, expected) in [
        (
            SessionVerdict::Joined(granary_fuse::SessionEnd::Clean),
            Some(Ok(())),
            MountOutcome::Clean,
        ),
        (
            SessionVerdict::Joined(granary_fuse::SessionEnd::Clean),
            Some(Err("injected cache close error".into())),
            MountOutcome::CacheCloseFailed,
        ),
        (
            SessionVerdict::Joined(granary_fuse::SessionEnd::Survived),
            Some(Ok(())),
            MountOutcome::RuntimeFailure,
        ),
        (
            SessionVerdict::NotJoined { listed: Ok(false) },
            None,
            MountOutcome::CacheCloseFailed,
        ),
    ] {
        let (state, mut watch) = watch::channel(State::Starting);
        let view = state.subscribe();
        let (done, finished) = mpsc::channel();
        let (observed, receipt) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            let final_message = runtime.block_on(async {
                loop {
                    let current = watch.borrow_and_update().clone();
                    if let State::Final { message, .. } = current {
                        break message;
                    }
                    watch.changed().await.unwrap();
                }
            });
            observed.send(final_message).unwrap();
            drop(runtime);
            done.send(()).unwrap();
        });
        let mut control = Control {
            state,
            done: finished,
            thread: Some(thread),
            instance: hello().instance,
            mode: Mode::Writable {
                bound_seconds: 30,
                store: b"store".to_vec(),
            },
            hello: None,
        };
        control.serving(hello().key).unwrap();
        let report = Some(granary_client::ShutdownReport {
            outcome: granary_client::ShutdownOutcome::Committed(9),
            cut: None,
            residue: None,
            elapsed_ms: 12,
        });
        let reads = std::cell::Cell::new(0);
        let outcome = finish_control(control, report, true, &session, || {
            let current = view.borrow().clone();
            assert!(
                matches!(current, State::Serving(_)),
                "Final published before cache observation: {current:?}"
            );
            reads.set(reads.get() + 1);
            cache
        });
        let message = receipt.try_recv().unwrap();
        let Message::Final { result, report, .. } = message else {
            panic!("expected Final: {message:?}");
        };
        assert_eq!(
            (
                outcome,
                reads.get(),
                result,
                report.map(|report| report.kind)
            ),
            (
                expected,
                1,
                match expected {
                    MountOutcome::Clean => ResultKind::Clean,
                    MountOutcome::CacheCloseFailed => ResultKind::CacheCloseFailed,
                    _ => ResultKind::RuntimeFailure,
                },
                Some(granary_core::mount_control::ReportKind::Committed(9))
            )
        );
        cases += 1;
    }
    assert_eq!(cases, 4);
}
