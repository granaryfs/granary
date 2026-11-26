// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Separately framed, bounded support-producer exchanges.

use super::{
    peer_admitted,
    service::{ACCEPT_BACKOFF, DONE_BOUND, DoneGuard, fatal_listener_error},
    transport::{Listener, Stream, malformed},
};
use granary_client::{SyncRuntime, TokioSyncRuntime};
use granary_core::{support::BundleArchive, support_trigger as wire};
use std::{
    future::{Future as _, poll_fn},
    io,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    task::Poll,
    time::Duration,
};
#[cfg(target_os = "linux")]
use tokio::net::{UnixListener, UnixStream};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::watch,
};

const IO_BOUND: Duration = Duration::from_secs(2);

type Collector = dyn Fn() -> io::Result<BundleArchive> + Send + Sync;

#[derive(Clone)]
pub(in crate::attach) struct Producer {
    layout: wire::SourceLayout,
    mounted: Arc<AtomicBool>,
    collect: Arc<Collector>,
}

impl Producer {
    pub(in crate::attach) fn new(
        layout: wire::SourceLayout,
        collect: impl Fn() -> io::Result<BundleArchive> + Send + Sync + 'static,
    ) -> Self {
        Self {
            mounted: Arc::new(AtomicBool::new(matches!(
                layout.mount,
                wire::MountState::Mounted { .. }
            ))),
            layout,
            collect: Arc::new(collect),
        }
    }

    pub(in crate::attach) fn mark_absent(&self) {
        self.mounted.store(false, Ordering::Release);
    }

    fn layout(&self) -> wire::SourceLayout {
        let mut layout = self.layout.clone();
        if !self.mounted.load(Ordering::Acquire) {
            layout.mount = wire::MountState::Absent;
        }
        layout
    }

    #[cfg(test)]
    pub(super) fn unavailable() -> Self {
        Self::new(
            wire::SourceLayout {
                mount: wire::MountState::Absent,
                roots: Vec::new(),
            },
            || Err(malformed("support producer unavailable")),
        )
    }
}

#[derive(Clone, Copy)]
enum Frame {
    Header,
    Bundle,
}

fn allocate_frame(
    prefix: [u8; 4],
    frame: Frame,
    allocate: impl FnOnce(usize) -> Vec<u8>,
) -> io::Result<Vec<u8>> {
    let length = match frame {
        Frame::Header => wire::header_frame_length(prefix),
        Frame::Bundle => wire::bundle_frame_length(prefix),
    }
    .map_err(|_| malformed("support size bound"))?;
    Ok(allocate(length))
}

async fn read_exact_until<R: SyncRuntime, S: Stream>(
    stream: &mut S,
    bytes: &mut [u8],
    deadline: tokio::time::Instant,
    runtime: &R,
) -> io::Result<()> {
    runtime
        .timeout_at(deadline, async {
            let mut offset = 0;
            while offset < bytes.len() {
                let slot = bytes
                    .get_mut(offset..)
                    .ok_or_else(|| malformed("invalid support read offset"))?;
                let count = stream.read(slot).await?;
                if count == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated support exchange",
                    ));
                }
                offset = offset
                    .checked_add(count)
                    .ok_or_else(|| malformed("invalid support read offset"))?;
            }
            Ok(())
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "support producer unavailable"))?
}

async fn write_exact_until<R: SyncRuntime, S: Stream>(
    stream: &mut S,
    bytes: &[u8],
    deadline: tokio::time::Instant,
    runtime: &R,
) -> io::Result<()> {
    runtime
        .timeout_at(deadline, async {
            let mut offset = 0;
            while offset < bytes.len() {
                let slot = bytes
                    .get(offset..)
                    .ok_or_else(|| malformed("invalid support write offset"))?;
                let count = stream.write(slot).await?;
                if count == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "support write returned zero",
                    ));
                }
                offset = offset
                    .checked_add(count)
                    .ok_or_else(|| malformed("invalid support write offset"))?;
            }
            Ok(())
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "support producer unavailable"))?
}

async fn require_eof_until<R: SyncRuntime, S: Stream>(
    stream: &mut S,
    deadline: tokio::time::Instant,
    runtime: &R,
    refusal: &'static str,
) -> io::Result<()> {
    runtime
        .timeout_at(deadline, async {
            let mut byte = [0];
            if stream.read(&mut byte).await? == 0 {
                Ok(())
            } else {
                Err(malformed(refusal))
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "support producer unavailable"))?
}

#[cfg(any(test, target_os = "linux"))]
async fn read_frame<R: SyncRuntime, S: Stream>(
    stream: &mut S,
    deadline: tokio::time::Instant,
    runtime: &R,
    frame: Frame,
) -> io::Result<Vec<u8>> {
    let mut prefix = [0; 4];
    read_exact_until(stream, &mut prefix, deadline, runtime).await?;
    let mut body = allocate_frame(prefix, frame, |length| vec![0; length])?;
    read_exact_until(stream, &mut body, deadline, runtime).await?;
    Ok(body)
}

async fn write_frame<R: SyncRuntime, S: Stream>(
    stream: &mut S,
    deadline: tokio::time::Instant,
    runtime: &R,
    body: &[u8],
    frame: Frame,
) -> io::Result<()> {
    let prefix = u32::try_from(body.len())
        .map_err(|_| malformed("support size bound"))?
        .to_be_bytes();
    match frame {
        Frame::Header => wire::header_frame_length(prefix),
        Frame::Bundle => wire::bundle_frame_length(prefix),
    }
    .map_err(|_| malformed("support size bound"))?;
    write_exact_until(stream, &prefix, deadline, runtime).await?;
    write_exact_until(stream, body, deadline, runtime).await
}

async fn answer_with_report<R: SyncRuntime, S: Stream>(
    mut stream: S,
    owner: u32,
    admitted: u32,
    producer: &Producer,
    report: &dyn Fn(std::fmt::Arguments<'_>),
    runtime: &R,
) -> io::Result<()> {
    if !peer_admitted(stream.peer_uid(), owner, admitted) {
        return Err(malformed(
            "refusing: support peer uid mismatch or unavailable",
        ));
    }
    let deadline = runtime
        .now()
        .checked_add(IO_BOUND)
        .ok_or_else(|| malformed("support deadline overflow"))?;
    let mut request = [0; wire::REQUEST_LEN];
    read_exact_until(&mut stream, &mut request, deadline, runtime).await?;
    wire::decode_request(&request).map_err(|_| malformed("malformed support request"))?;
    require_eof_until(&mut stream, deadline, runtime, "malformed support request").await?;
    let Ok(archive) = (producer.collect)() else {
        report(format_args!("gran mount: support producer unavailable"));
        let unavailable = wire::encode_header(&wire::Header::Unavailable)
            .map_err(|_| malformed("malformed support reply"))?;
        return write_frame(&mut stream, deadline, runtime, &unavailable, Frame::Header).await;
    };
    let bundle = archive
        .encode()
        .map_err(|_| malformed("support producer unavailable"))?;
    BundleArchive::decode(&bundle).map_err(|_| malformed("support producer unavailable"))?;
    let header = wire::encode_header(&wire::Header::Layout(producer.layout()))
        .map_err(|_| malformed("support producer unavailable"))?;
    write_frame(&mut stream, deadline, runtime, &header, Frame::Header).await?;
    write_frame(&mut stream, deadline, runtime, &bundle, Frame::Bundle).await
}

#[cfg(test)]
pub(super) async fn answer<R: SyncRuntime, S: Stream>(
    stream: S,
    owner: u32,
    admitted: u32,
    producer: &Producer,
    runtime: &R,
) -> io::Result<()> {
    answer_with_report(stream, owner, admitted, producer, &|_| {}, runtime).await
}

/// # Cancellation safety
/// Cancellation closes the accepted stream. One admitted collection either
/// completes or reaches its absolute deadline before another is accepted.
async fn serve<R: SyncRuntime, L: Listener>(
    listener: &L,
    mut closing: watch::Receiver<bool>,
    owner: u32,
    producer: Producer,
    runtime: &R,
) -> io::Result<()> {
    loop {
        let accepted = {
            let mut changed = pin!(closing.changed());
            poll_fn(|cx| {
                if changed.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Ok(None));
                }
                listener.poll_accept(cx).map(|accepted| accepted.map(Some))
            })
            .await
        };
        let stream = match accepted {
            Ok(Some(stream)) => stream,
            Ok(None) => return Ok(()),
            Err(error) if fatal_listener_error(&error) => return Err(error),
            Err(_) => {
                let mut changed = pin!(closing.changed());
                let mut timer = pin!(runtime.sleep(ACCEPT_BACKOFF));
                let closing = poll_fn(|cx| {
                    if changed.as_mut().poll(cx).is_ready() {
                        Poll::Ready(true)
                    } else if timer.as_mut().poll(cx).is_ready() {
                        Poll::Ready(false)
                    } else {
                        Poll::Pending
                    }
                })
                .await;
                if closing {
                    return Ok(());
                }
                continue;
            }
        };
        let mut response = pin!(answer_with_report(
            stream,
            owner,
            owner,
            &producer,
            &crate::terminal::write_line,
            runtime
        ));
        let completed = {
            let mut changed = pin!(closing.changed());
            poll_fn(|cx| {
                if changed.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(false);
                }
                match response.as_mut().poll(cx) {
                    Poll::Ready(result) => {
                        let _ = result;
                        Poll::Ready(true)
                    }
                    Poll::Pending => Poll::Pending,
                }
            })
            .await
        };
        if !completed {
            return Ok(());
        }
    }
}

#[cfg(any(test, target_os = "linux"))]
pub(super) async fn request<R: SyncRuntime, S: Stream>(
    mut stream: S,
    owner: u32,
    admitted: u32,
    deadline: tokio::time::Instant,
    runtime: &R,
) -> Result<(wire::Header, Option<BundleArchive>), RequestFailure> {
    if !peer_admitted(stream.peer_uid(), owner, admitted) {
        return Err(RequestFailure::Unavailable);
    }
    write_exact_until(&mut stream, &wire::request(), deadline, runtime)
        .await
        .map_err(|_| RequestFailure::Unavailable)?;
    runtime
        .timeout_at(deadline, stream.shutdown())
        .await
        .map_err(|_| RequestFailure::Unavailable)?
        .map_err(|_| RequestFailure::Unavailable)?;
    let body = read_frame(&mut stream, deadline, runtime, Frame::Header)
        .await
        .map_err(|error| reply_failure(error.kind()))?;
    let header = wire::decode_header(&body).map_err(|_| RequestFailure::Malformed)?;
    let bundle = if matches!(header, wire::Header::Layout(_)) {
        let body = read_frame(&mut stream, deadline, runtime, Frame::Bundle)
            .await
            .map_err(|error| reply_failure(error.kind()))?;
        Some(BundleArchive::decode(&body).map_err(|_| RequestFailure::Malformed)?)
    } else {
        None
    };
    require_eof_until(&mut stream, deadline, runtime, "malformed support reply")
        .await
        .map_err(|error| reply_failure(error.kind()))?;
    Ok((header, bundle))
}

#[cfg(any(test, target_os = "linux"))]
fn reply_failure(kind: io::ErrorKind) -> RequestFailure {
    match kind {
        io::ErrorKind::TimedOut
        | io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionAborted => RequestFailure::Unavailable,
        _ => RequestFailure::Malformed,
    }
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestFailure {
    Unavailable,
    Malformed,
}

#[cfg(any(test, target_os = "linux"))]
impl std::fmt::Display for RequestFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "support producer unavailable",
            Self::Malformed => "malformed support reply",
        })
    }
}

#[cfg(any(test, target_os = "linux"))]
impl std::error::Error for RequestFailure {}

#[cfg(any(test, target_os = "linux"))]
async fn connect_until<R: SyncRuntime, S: Stream>(
    connect: impl Future<Output = io::Result<S>> + Send,
    recheck: impl FnOnce() -> io::Result<()>,
    deadline: tokio::time::Instant,
    runtime: &R,
) -> Result<S, RequestFailure> {
    let stream = runtime
        .timeout_at(deadline, connect)
        .await
        .map_err(|_| RequestFailure::Unavailable)?
        .map_err(|_| RequestFailure::Unavailable)?;
    recheck().map_err(|_| RequestFailure::Unavailable)?;
    Ok(stream)
}

#[cfg(any(test, target_os = "linux"))]
async fn request_live_with<R: SyncRuntime, S: Stream>(
    connect: impl Future<Output = io::Result<S>> + Send,
    recheck: impl FnOnce() -> io::Result<()> + Send,
    admitted: u32,
    deadline: tokio::time::Instant,
    runtime: &R,
) -> Result<(wire::SourceLayout, BundleArchive), RequestFailure> {
    let stream = connect_until(connect, recheck, deadline, runtime).await?;
    let (header, archive) = request(stream, admitted, admitted, deadline, runtime).await?;
    match (header, archive) {
        (wire::Header::Layout(layout), Some(archive)) => Ok((layout, archive)),
        (wire::Header::Unavailable, None) => Err(RequestFailure::Unavailable),
        _ => Err(RequestFailure::Malformed),
    }
}

#[cfg(target_os = "linux")]
pub(in crate::attach) fn request_live(
    target: &std::path::Path,
    namespace: (u64, u64),
    admitted: u32,
) -> Result<(wire::SourceLayout, BundleArchive), RequestFailure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| RequestFailure::Unavailable)?;
    runtime.block_on(async {
        let deadline = TokioSyncRuntime
            .now()
            .checked_add(IO_BOUND)
            .ok_or(RequestFailure::Unavailable)?;
        let directory = super::endpoint::Directory::open(admitted, false)
            .map_err(|_| RequestFailure::Unavailable)?;
        let name = super::endpoint::support_socket_name(namespace, target);
        let (path, metadata) = directory
            .connect_path(&name, admitted)
            .map_err(|_| RequestFailure::Unavailable)?;
        request_live_with(
            UnixStream::connect(&path),
            || directory.recheck_socket(&name, &metadata),
            admitted,
            deadline,
            &TokioSyncRuntime,
        )
        .await
    })
}

pub(in crate::attach) struct Support {
    closing: watch::Sender<bool>,
    done: mpsc::Receiver<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(target_os = "linux")]
pub(in crate::attach) struct PreparedSupport(pub(super) super::endpoint::Endpoint);

impl Support {
    #[cfg(target_os = "linux")]
    pub(in crate::attach) fn prepare(
        owner: u32,
        target: &std::path::Path,
    ) -> io::Result<PreparedSupport> {
        let endpoint = super::endpoint::Endpoint::bind_support(
            owner,
            super::super::mount_table::mount_namespace()?,
            target,
        )?;
        Ok(PreparedSupport(endpoint))
    }

    #[cfg(target_os = "linux")]
    pub(in crate::attach) fn start(
        owner: u32,
        prepared: PreparedSupport,
        producer: Producer,
    ) -> io::Result<Self> {
        let endpoint = prepared.0;
        Self::start_with_listener(owner, endpoint, producer, |endpoint| {
            UnixListener::from_std(endpoint.take_listener()?)
        })
    }

    #[cfg(any(test, target_os = "linux"))]
    fn start_with_listener<E: Send + 'static, L: Listener>(
        owner: u32,
        endpoint: E,
        producer: Producer,
        open: impl FnOnce(&mut E) -> io::Result<L> + Send + 'static,
    ) -> io::Result<Self> {
        let (closing, state) = watch::channel(false);
        let (done, finished) = mpsc::channel();
        let (ready, readiness) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("granary-support".into())
            .spawn(move || {
                let guard = DoneGuard::new(done);
                let mut endpoint = endpoint;
                let result = (|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    let result = runtime.block_on(async {
                        let listener = open(&mut endpoint)?;
                        let _ = ready.send(Ok(()));
                        serve(&listener, state, owner, producer, &TokioSyncRuntime).await
                    });
                    drop(runtime);
                    result
                })();
                if let Err(error) = result {
                    let _ = ready.send(Err(error));
                }
                drop(endpoint);
                guard.send();
            })?;
        if let Ok(Ok(())) = readiness.recv_timeout(IO_BOUND) {
            Ok(Self {
                closing,
                done: finished,
                thread: Some(thread),
            })
        } else {
            closing.send_replace(true);
            if finished.recv_timeout(DONE_BOUND).is_ok() {
                let _ = thread.join();
            }
            Err(io::Error::other(
                "support service startup failed or timed out",
            ))
        }
    }
}

impl Drop for Support {
    fn drop(&mut self) {
        self.closing.send_replace(true);
        if self.done.recv_timeout(DONE_BOUND).is_ok()
            && let Some(thread) = self.thread.take()
        {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests;
