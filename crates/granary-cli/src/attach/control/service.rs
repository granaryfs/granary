// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! One bounded socket loop, woken by sticky lifecycle publication.

use super::super::Exit;
use super::{
    peer_admitted,
    transport::{Listener, Reader, Stream, Writer, malformed},
};
use granary_client::{SyncRuntime, TokioSyncRuntime};
use granary_core::mount_control::{Hello, Message, Reject};
use std::{
    collections::VecDeque,
    future::{Future as _, poll_fn},
    io,
    pin::pin,
    sync::mpsc,
    task::Poll,
    time::Duration,
};
#[cfg(target_os = "linux")]
use tokio::net::UnixListener;
use tokio::{io::ReadBuf, sync::watch};

const IO_BOUND: Duration = Duration::from_secs(2);
pub(super) const DONE_BOUND: Duration = Duration::from_millis(2500);
const CAPACITY: usize = 16;
const ACCEPT_BUDGET: usize = 16;
pub(super) const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

pub(super) fn fatal_listener_error(error: &io::Error) -> bool {
    if matches!(error.raw_os_error(), Some(libc::EBADF | libc::ENOTSOCK)) {
        return true;
    }
    matches!(
        error.kind(),
        io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported | io::ErrorKind::NotConnected
    )
}

#[derive(Debug, Clone)]
pub(super) enum State {
    Starting,
    Serving(Hello),
    Final {
        message: Message,
        published_at: tokio::time::Instant,
    },
    Closing,
}

struct Connection<S> {
    stream: S,
    hello: Option<Hello>,
    reader: Reader,
    output: VecDeque<Writer>,
    deadline: Option<tokio::time::Instant>,
    subscribed: bool,
    close_after_write: bool,
}
impl<S: Stream> Connection<S> {
    fn queue(&mut self, message: &Message) -> io::Result<()> {
        self.output.push_back(Writer::new(message)?);
        Ok(())
    }
    fn admit(
        &mut self,
        message: &Message,
        requested: &mut bool,
        coordinator: &mpsc::Sender<Exit>,
    ) -> io::Result<()> {
        let Some(hello) = &self.hello else {
            return Err(malformed("request before Hello"));
        };
        match message {
            Message::Stop { instance, key } if *instance == hello.instance && *key == hello.key => {
                if !*requested {
                    if coordinator.send(Exit::ControlUmount).is_err() {
                        self.close_after_write = true;
                        return self.queue(&Message::Reject(Reject::CoordinatorLost));
                    }
                    *requested = true;
                }
                self.subscribed = true;
                self.queue(&Message::Accepted(*instance))
            }
            Message::Stop { .. } => {
                self.close_after_write = true;
                self.queue(&Message::Reject(Reject::IdentityMismatch))
            }
            _ => {
                self.close_after_write = true;
                self.queue(&Message::Reject(Reject::MalformedRequest))
            }
        }
    }
    fn poll(
        &mut self,
        cx: &mut std::task::Context<'_>,
        requested: &mut bool,
        coordinator: &mpsc::Sender<Exit>,
        finalizing: bool,
    ) -> io::Result<bool> {
        if let Some(output) = self.output.front_mut()
            && let Poll::Ready(result) = output.poll(&mut self.stream, cx)
        {
            result?;
            self.output.pop_front();
            if !self.output.is_empty() {
                cx.waker().wake_by_ref();
            }
        }
        if self.output.is_empty() && (self.close_after_write || finalizing) {
            return Ok(false);
        }
        if self.subscribed && self.output.is_empty() {
            self.deadline = None;
        }
        if self.subscribed || self.close_after_write {
            // EOF removes only this subscription; extra bytes refuse duplicate frames.
            let mut byte = [0];
            let mut read = ReadBuf::new(&mut byte);
            if let Poll::Ready(result) =
                std::pin::Pin::new(&mut self.stream).poll_read(cx, &mut read)
            {
                result?;
                return Ok(false);
            }
        } else if self.output.is_empty()
            && let Poll::Ready(message) = self.reader.poll(&mut self.stream, cx)
        {
            self.admit(&message?, requested, coordinator)?;
            cx.waker().wake_by_ref();
        }
        Ok(true)
    }
}

/// # Cancellation safety
/// Dropping the loop closes every subscription. An enqueued stop belongs to
/// the coordinator and cannot be undone by transport loss.
#[expect(
    clippy::too_many_lines,
    reason = "one biased poll loop keeps watch, deadline, stream and listener work in their required order"
)]
pub(super) async fn serve<R: SyncRuntime, L: Listener>(
    listener: &L,
    mut state: watch::Receiver<State>,
    coordinator: mpsc::Sender<Exit>,
    owner: u32,
    runtime: &R,
) -> io::Result<()> {
    let mut connections: Vec<Connection<L::Stream>> = Vec::new();
    let mut requested = false;
    let mut final_message = None;
    let mut final_deadline = None;
    let mut accept_after = None;
    let mut reported_accept_errors = Vec::new();
    loop {
        let current = state.borrow_and_update().clone();
        if matches!(current, State::Closing) {
            return Ok(());
        }
        if let State::Final {
            message,
            published_at,
        } = &current
            && final_message.is_none()
        {
            final_deadline = published_at.checked_add(IO_BOUND);
            connections.retain_mut(|connection| {
                if !connection.subscribed {
                    return false;
                }
                connection.queue(message).is_ok()
            });
            final_message = Some(message.clone());
        }
        let now = runtime.now();
        if accept_after.is_some_and(|end| now >= end) {
            accept_after = None;
        }
        if final_message.is_some()
            && (connections.is_empty() || final_deadline.is_none_or(|end| now >= end))
        {
            return Ok(());
        }
        connections.retain(|connection| connection.deadline.is_none_or(|end| now < end));
        let next_deadline = connections
            .iter()
            .filter_map(|connection| connection.deadline)
            .chain(final_deadline)
            .chain(accept_after)
            .min();
        // Keep changed() alive across Pending. Its registration must outlive
        // the poll so publication between inspection and parking wakes us.
        let mut changed = pin!(state.changed());
        let mut timer = pin!(async {
            if let Some(end) = next_deadline {
                runtime.sleep(end.saturating_duration_since(now)).await;
            } else {
                std::future::pending::<()>().await;
            }
        });
        poll_fn(|cx| {
            match changed.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(_)) => {
                    return Poll::Ready(Err(io::Error::other("control publisher lost")));
                }
                Poll::Pending => (),
            }
            if timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ok(()));
            }
            connections.retain_mut(|connection| {
                connection
                    .poll(cx, &mut requested, &coordinator, final_message.is_some())
                    .unwrap_or(false)
            });
            if final_message.is_some() {
                if connections.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Pending;
            }
            if accept_after.is_some() {
                return Poll::Pending;
            }
            let mut accepted = false;
            for _ in 0..ACCEPT_BUDGET {
                match listener.poll_accept(cx) {
                    Poll::Pending => {
                        return if accepted {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Pending
                        };
                    }
                    Poll::Ready(Err(error)) => {
                        if fatal_listener_error(&error) {
                            return Poll::Ready(Err(error));
                        }
                        let kind = error.kind();
                        if !reported_accept_errors.contains(&kind) {
                            reported_accept_errors.push(kind);
                            let _ = coordinator.send(Exit::ControlError { kind, fatal: false });
                        }
                        accept_after = runtime.now().checked_add(ACCEPT_BACKOFF);
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Ok(stream)) => {
                        if !peer_admitted(stream.peer_uid(), owner, owner)
                            || connections.len() >= CAPACITY
                        {
                            continue;
                        }
                        let hello = match &current {
                            State::Serving(hello) => Some(hello.clone()),
                            _ => None,
                        };
                        let mut connection = Connection {
                            stream,
                            hello: hello.clone(),
                            reader: Reader::default(),
                            output: VecDeque::new(),
                            deadline: runtime.now().checked_add(IO_BOUND),
                            subscribed: false,
                            close_after_write: hello.is_none(),
                        };
                        connection.queue(
                            &hello.map_or(Message::Reject(Reject::Starting), Message::Hello),
                        )?;
                        connections.push(connection);
                        accepted = true;
                        cx.waker().wake_by_ref();
                    }
                }
            }
            cx.waker().wake_by_ref();
            Poll::Ready(Ok(()))
        })
        .await?;
    }
}

fn service_failed(
    error: io::Error,
    ready: &mpsc::Sender<io::Result<()>>,
    coordinator: &mpsc::Sender<Exit>,
) {
    let _ = coordinator.send(Exit::ControlError {
        kind: error.kind(),
        fatal: true,
    });
    let _ = ready.send(Err(error));
}

pub(super) struct DoneGuard(Option<mpsc::Sender<()>>);
impl DoneGuard {
    pub(super) fn new(done: mpsc::Sender<()>) -> Self {
        Self(Some(done))
    }
    pub(super) fn send(mut self) {
        if let Some(done) = self.0.take() {
            let _ = done.send(());
        }
    }
}
impl Drop for DoneGuard {
    fn drop(&mut self) {
        if let Some(done) = self.0.take() {
            let _ = done.send(());
        }
    }
}

pub(in crate::attach) struct Control {
    state: watch::Sender<State>,
    done: mpsc::Receiver<()>,
    thread: Option<std::thread::JoinHandle<()>>,
    instance: granary_core::mount_control::Instance,
    mode: granary_core::mount_control::Mode,
    hello: Option<Hello>,
}
impl Control {
    #[cfg(target_os = "linux")]
    pub(in crate::attach) fn start(
        owner: u32,
        target: &std::path::Path,
        mode: granary_core::mount_control::Mode,
        coordinator: mpsc::Sender<Exit>,
    ) -> io::Result<Self> {
        use granary_core::secure_random::SecureRandom as _;
        mode.validate().map_err(malformed)?;
        let mut instance = [0; 16];
        granary_net::secure_random::OsSecureRandom::new()
            .fill(&mut instance)
            .map_err(malformed)?;
        let endpoint = super::endpoint::Endpoint::bind(
            owner,
            super::super::mount_table::mount_namespace()?,
            target,
        )?;
        Self::start_with_listener(owner, instance, mode, coordinator, endpoint, |endpoint| {
            UnixListener::from_std(endpoint.take_listener()?)
        })
    }
    #[cfg(any(target_os = "linux", test))]
    fn start_with_listener<E: Send + 'static, L: Listener>(
        owner: u32,
        instance: granary_core::mount_control::Instance,
        mode: granary_core::mount_control::Mode,
        coordinator: mpsc::Sender<Exit>,
        endpoint: E,
        open_listener: impl FnOnce(&mut E) -> io::Result<L> + Send + 'static,
    ) -> io::Result<Self> {
        let (state, receive) = watch::channel(State::Starting);
        let (done, finished) = mpsc::channel();
        let (ready, readiness) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("granary-control".into())
            .spawn(move || {
                let guard = DoneGuard::new(done);
                let mut endpoint = endpoint;
                let result = (|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    let result = runtime.block_on(async {
                        let listener = open_listener(&mut endpoint)?;
                        if matches!(*receive.borrow(), State::Closing) {
                            return Ok(());
                        }
                        let _ = ready.send(Ok(()));
                        serve(
                            &listener,
                            receive,
                            coordinator.clone(),
                            owner,
                            &TokioSyncRuntime,
                        )
                        .await
                    });
                    drop(runtime);
                    result
                })();
                if let Err(error) = result {
                    service_failed(error, &ready, &coordinator);
                }
                drop(endpoint);
                guard.send();
            })?;
        if let Ok(Ok(())) = readiness.recv_timeout(IO_BOUND) {
            Ok(Self {
                state,
                done: finished,
                thread: Some(thread),
                instance,
                mode,
                hello: None,
            })
        } else {
            state.send_replace(State::Closing);
            Err(io::Error::other(
                "control service startup failed or timed out",
            ))
        }
    }
    pub(in crate::attach) fn serving(
        &mut self,
        key: granary_core::mount_control::MountKey,
    ) -> io::Result<()> {
        let hello = Hello {
            instance: self.instance,
            key,
            mode: self.mode.clone(),
        };
        granary_core::mount_control::encode(&Message::Hello(hello.clone())).map_err(malformed)?;
        self.state
            .send(State::Serving(hello.clone()))
            .map_err(malformed)?;
        self.hello = Some(hello);
        Ok(())
    }
    pub(in crate::attach) fn finish(
        mut self,
        outcome: super::MountOutcome,
        report: Option<granary_client::ShutdownReport>,
    ) {
        let published_at = TokioSyncRuntime.now();
        let message = Message::Final {
            instance: self.instance,
            result: super::wire_result(outcome),
            report: report.map(super::wire_report),
        };
        let valid = self
            .hello
            .as_ref()
            .is_some_and(|hello| hello.validate_final(&message).is_ok());
        self.state.send_replace(if valid {
            State::Final {
                message,
                published_at,
            }
        } else {
            State::Closing
        });
        if self
            .done
            .recv_timeout(
                DONE_BOUND.saturating_sub(
                    TokioSyncRuntime
                        .now()
                        .saturating_duration_since(published_at),
                ),
            )
            .is_ok()
            && let Some(thread) = self.thread.take()
        {
            let _ = thread.join();
        }
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        self.state.send_replace(State::Closing);
    }
}

#[cfg(test)]
mod tests;
