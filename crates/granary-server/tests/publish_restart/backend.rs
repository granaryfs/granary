// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parent-owned signed HTTP attempts; issuer disconnect never cancels a capture.
use std::collections::BTreeMap;
use std::future::{Future as _, poll_fn};
use std::sync::{Arc, Mutex};
use std::task::Poll;

use granary_core::hash::GrainId;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, oneshot};
use tokio::task::JoinSet;
use tokio::time::timeout;

use super::support::WAIT;

const FRAME_LIMIT: usize = 2 * 1024 * 1024;

fn invalid() -> std::io::Error {
    std::io::Error::other("incomplete or unsupported backend HTTP frame")
}

/// A bounded HTTP/1 frame. Headers and signed body remain byte-identical.
fn frame(bytes: &[u8]) -> std::io::Result<Option<usize>> {
    if bytes.len() > FRAME_LIMIT {
        return Err(invalid());
    }
    let Some(end) = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|n| n + 4)
    else {
        return Ok(None);
    };
    let head = std::str::from_utf8(bytes.get(..end).ok_or_else(invalid)?).map_err(|_| invalid())?;
    let header = |name: &str| {
        head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then_some(value.trim())
        })
    };
    if header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        let mut cursor = end;
        loop {
            let rest = bytes.get(cursor..).ok_or_else(invalid)?;
            let Some(n) = rest.windows(2).position(|w| w == b"\r\n") else {
                return Ok(None);
            };
            let size =
                std::str::from_utf8(rest.get(..n).ok_or_else(invalid)?).map_err(|_| invalid())?;
            let size = usize::from_str_radix(size.split(';').next().ok_or_else(invalid)?, 16)
                .map_err(|_| invalid())?;
            cursor = cursor.checked_add(n + 2).ok_or_else(invalid)?;
            let finish = cursor
                .checked_add(size)
                .and_then(|n| n.checked_add(2))
                .filter(|n| *n <= FRAME_LIMIT)
                .ok_or_else(invalid)?;
            if bytes.len() < finish {
                return Ok(None);
            }
            if bytes.get(finish - 2..finish) != Some(b"\r\n") {
                return Err(invalid());
            }
            cursor = finish;
            if size == 0 {
                return Ok(Some(cursor));
            }
        }
    }
    let length =
        header("content-length").map_or(Ok(0), |v| v.parse::<usize>().map_err(|_| invalid()))?;
    let finish = end
        .checked_add(length)
        .filter(|n| *n <= FRAME_LIMIT)
        .ok_or_else(invalid)?;
    Ok((bytes.len() >= finish).then_some(finish))
}

pub(super) async fn read_frame(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    buffered: &mut Vec<u8>,
    request: bool,
    head_only: bool,
) -> std::io::Result<Vec<u8>> {
    timeout(WAIT, async {
        let mut continued = false;
        loop {
            let framed = frame(buffered)?;
            if head_only
                && let Some(end) = buffered
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|n| n + 4)
            {
                return Ok(buffered.drain(..end).collect());
            }
            if let Some(n) = framed {
                return Ok(buffered.drain(..n).collect());
            }
            if request && !continued && buffered.windows(4).any(|w| w == b"\r\n\r\n") {
                let end = buffered
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|n| n + 4)
                    .ok_or_else(invalid)?;
                let text = std::str::from_utf8(buffered.get(..end).ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
                if text
                    .lines()
                    .any(|l| l.eq_ignore_ascii_case("expect: 100-continue"))
                {
                    stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
                }
                continued = true;
            }
            let mut chunk = [0; 8192];
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(invalid());
            }
            buffered.extend_from_slice(chunk.get(..n).ok_or_else(invalid)?);
        }
    })
    .await
    .map_err(|_| invalid())?
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Identity {
    pub(super) volume: String,
    pub(super) seq: u64,
    pub(super) id: GrainId,
    pub(super) occurrence: u64,
}

fn root_put(raw: &[u8]) -> std::io::Result<Option<(String, u64, Vec<u8>)>> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|n| n + 4)
        .ok_or_else(invalid)?;
    let head = std::str::from_utf8(raw.get(..end).ok_or_else(invalid)?).map_err(|_| invalid())?;
    let mut words = head.lines().next().ok_or_else(invalid)?.split_whitespace();
    if words.next() != Some("PUT") {
        return Ok(None);
    }
    let path = words.next().ok_or_else(invalid)?;
    let Some((_, key)) = path.split_once("/root/") else {
        return Ok(None);
    };
    let Some((volume, seq)) = key.split_once('/') else {
        return Err(invalid());
    };
    if seq == "CURRENT" {
        return Ok(None);
    }
    let seq = seq.parse::<u64>().map_err(|_| invalid())?;
    if !head
        .lines()
        .any(|l| l.eq_ignore_ascii_case("if-none-match: *"))
        || frame(raw)? != Some(raw.len())
    {
        return Err(invalid());
    }
    Ok(Some((
        volume.to_owned(),
        seq,
        raw.get(end..).ok_or_else(invalid)?.to_vec(),
    )))
}

struct Pending {
    identity: Identity,
    body: Vec<u8>,
    release: oneshot::Sender<()>,
    result: oneshot::Receiver<std::io::Result<u16>>,
    detach: Option<oneshot::Sender<oneshot::Sender<()>>>,
}
#[derive(Default)]
struct State {
    faults: Vec<String>,
    counts: BTreeMap<(String, u64, GrainId), u64>,
    pending: Vec<Pending>,
    finished: Vec<(Identity, u16)>,
    issuer_refusals: Vec<Identity>,
    /// Status answered, in place of forwarding, to every bin or meta PUT.
    content_put_fault: Option<u16>,
    injected: u64,
}

pub(super) struct Proxy {
    pub(super) endpoint: String,
    state: Arc<Mutex<State>>,
    changed: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}
impl Proxy {
    pub(super) async fn new(upstream: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State::default()));
        let changed = Arc::new(Notify::new());
        let shared = state.clone();
        let notify = changed.clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                enum Event {
                    Accepted(std::io::Result<(TcpStream, std::net::SocketAddr)>),
                    Finished(Option<Result<std::io::Result<()>, tokio::task::JoinError>>),
                }
                let event = {
                    let mut accept = std::pin::pin!(listener.accept());
                    let joining = !tasks.is_empty();
                    let mut join = std::pin::pin!(tasks.join_next());
                    poll_fn(|cx| {
                        if let Poll::Ready(result) = accept.as_mut().poll(cx) {
                            return Poll::Ready(Event::Accepted(result));
                        }
                        if joining && let Poll::Ready(result) = join.as_mut().poll(cx) {
                            return Poll::Ready(Event::Finished(result));
                        }
                        Poll::Pending
                    })
                    .await
                };
                match event {
                    Event::Accepted(Ok((client, _))) => {
                        tasks.spawn(relay(
                            client,
                            upstream.clone(),
                            shared.clone(),
                            notify.clone(),
                        ));
                    }
                    Event::Accepted(Err(error)) => {
                        shared.lock().unwrap().faults.push(error.to_string());
                        break;
                    }
                    Event::Finished(Some(Ok(Ok(()))) | None) => {}
                    Event::Finished(Some(result)) => {
                        shared.lock().unwrap().faults.push(format!("{result:?}"));
                    }
                }
            }
        });
        Self {
            endpoint,
            state,
            changed,
            task,
        }
    }
    pub(super) async fn captured(&self) -> Identity {
        timeout(WAIT, async {
            loop {
                let changed = self.changed.notified();
                if let Some(p) = self.state.lock().unwrap().pending.first() {
                    return p.identity.clone();
                }
                changed.await;
            }
        })
        .await
        .expect("no complete backend capture")
    }
    pub(super) async fn captured_except(&self, old: &Identity) -> Identity {
        timeout(WAIT, async {
            loop {
                let changed = self.changed.notified();
                if let Some(p) = self
                    .state
                    .lock()
                    .unwrap()
                    .pending
                    .iter()
                    .find(|p| p.identity != *old)
                {
                    return p.identity.clone();
                }
                changed.await;
            }
        })
        .await
        .expect("no replayed backend attempt")
    }
    pub(super) fn captures(&self) -> Vec<(Identity, Vec<u8>)> {
        self.state
            .lock()
            .unwrap()
            .pending
            .iter()
            .map(|p| (p.identity.clone(), p.body.clone()))
            .collect()
    }
    pub(super) fn body(&self, identity: &Identity) -> Vec<u8> {
        self.state
            .lock()
            .unwrap()
            .pending
            .iter()
            .find(|p| p.identity == *identity)
            .unwrap()
            .body
            .clone()
    }
    pub(super) async fn captured_matching(&self, id: GrainId) -> Identity {
        timeout(WAIT, async {
            loop {
                let changed = self.changed.notified();
                if let Some(p) = self
                    .state
                    .lock()
                    .unwrap()
                    .pending
                    .iter()
                    .find(|p| p.identity.id == id)
                {
                    return p.identity.clone();
                }
                changed.await;
            }
        })
        .await
        .expect("matching PUT never captured")
    }
    /// Settle only the issuer with a terminal backend refusal, retaining the
    /// original signed request for a separately commanded late release.
    pub(super) async fn detach(&self, expected: &Identity) -> Result<(), String> {
        let detach = self
            .state
            .lock()
            .unwrap()
            .pending
            .iter_mut()
            .find(|p| p.identity == *expected)
            .and_then(|p| p.detach.take())
            .ok_or("wrong or already detached PUT")?;
        let (acknowledge, acknowledged) = oneshot::channel();
        detach
            .send(acknowledge)
            .map_err(|_| "issuer control lost")?;
        timeout(WAIT, acknowledged)
            .await
            .map_err(|_| "issuer detach timed out")?
            .map_err(|_| "issuer detach not acknowledged".to_owned())?;
        self.state
            .lock()
            .unwrap()
            .issuer_refusals
            .push(expected.clone());
        Ok(())
    }
    pub(super) async fn release(&self, expected: &Identity) -> Result<u16, String> {
        let pending = {
            let mut state = self.state.lock().unwrap();
            let index = state
                .pending
                .iter()
                .position(|p| p.identity == *expected)
                .ok_or("wrong or premature PUT release")?;
            let pending = state.pending.remove(index);
            if GrainId::of(&pending.body) != expected.id {
                return Err("altered captured body".into());
            }
            pending
        };
        pending
            .release
            .send(())
            .map_err(|()| "capture was cancelled")?;
        let status = timeout(WAIT, pending.result)
            .await
            .map_err(|_| "release timed out")?
            .map_err(|_| "capture result lost")?
            .map_err(|e| e.to_string())?;
        self.state
            .lock()
            .unwrap()
            .finished
            .push((expected.clone(), status));
        Ok(status)
    }
    pub(super) fn issuer_refusals(&self) -> Vec<Identity> {
        self.state.lock().unwrap().issuer_refusals.clone()
    }
    pub(super) fn finished(&self) -> Vec<(Identity, u16)> {
        let state = self.state.lock().unwrap();
        assert!(
            state.faults.is_empty(),
            "backend relay failed: {:?}",
            state.faults
        );
        state.finished.clone()
    }
    /// Answer every content (bin or meta) PUT with `status` instead of
    /// forwarding it. Root PUTs and every read are untouched.
    pub(super) fn fail_content_puts(&self, status: u16) {
        self.state.lock().unwrap().content_put_fault = Some(status);
    }
    /// Content PUTs answered by the injected fault so far.
    pub(super) fn injected(&self) -> u64 {
        self.state.lock().unwrap().injected
    }
    pub(super) fn pending(&self) -> usize {
        self.state.lock().unwrap().pending.len()
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

enum Control {
    Release,
    Detach(oneshot::Sender<()>),
}

async fn wait_for_release(
    client: &mut (impl AsyncWrite + Unpin),
    mut released: oneshot::Receiver<()>,
    mut detached: oneshot::Receiver<oneshot::Sender<()>>,
) -> std::io::Result<()> {
    let control = poll_fn(|cx| {
        if let Poll::Ready(result) = std::pin::Pin::new(&mut released).poll(cx) {
            return Poll::Ready(result.map(|()| Control::Release).map_err(|_| invalid()));
        }
        if let Poll::Ready(result) = std::pin::Pin::new(&mut detached).poll(cx) {
            return Poll::Ready(result.map(Control::Detach).map_err(|_| invalid()));
        }
        Poll::Pending
    })
    .await?;
    if let Control::Detach(acknowledge) = control {
        // 403 is terminal for this issuer; no retry policy can silently issue
        // another attempt. It is not an authority/client answer.
        let _ = client
            .write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await;
        let _ = client.shutdown().await;
        // A disconnected issuer cannot cancel the parent's signed capture.
        let _ = acknowledge.send(());
        released.await.map_err(|_| invalid())?;
    }
    Ok(())
}

async fn relay(
    mut client: TcpStream,
    upstream: String,
    state: Arc<Mutex<State>>,
    changed: Arc<Notify>,
) -> std::io::Result<()> {
    let mut buffered = Vec::new();
    loop {
        let Ok(raw) = read_frame(&mut client, &mut buffered, true, false).await else {
            return Ok(());
        };
        let capture = if let Some((volume, seq, body)) = root_put(&raw)? {
            let id = GrainId::of(&body);
            let (release, released) = oneshot::channel();
            let (detach, detached) = oneshot::channel();
            let (result, observed) = oneshot::channel();
            {
                let mut s = state.lock().map_err(|_| invalid())?;
                let count = s.counts.entry((volume.clone(), seq, id)).or_default();
                *count += 1;
                let identity = Identity {
                    volume,
                    seq,
                    id,
                    occurrence: *count,
                };
                s.pending.push(Pending {
                    identity,
                    body,
                    release,
                    result: observed,
                    detach: Some(detach),
                });
            }
            changed.notify_one();
            // This belongs to the parent, independent of the issuer socket.
            wait_for_release(&mut client, released, detached).await?;
            Some(result)
        } else {
            None
        };
        if capture.is_none() && is_content_put(&raw) {
            let fault = {
                let mut s = state.lock().map_err(|_| invalid())?;
                let fault = s.content_put_fault;
                s.injected += u64::from(fault.is_some());
                fault
            };
            if let Some(status) = fault {
                let reply = format!("HTTP/1.1 {status} Injected\r\ncontent-length: 0\r\n\r\n");
                if client.write_all(reply.as_bytes()).await.is_err() {
                    return Ok(());
                }
                continue;
            }
        }
        let forwarded = forward(&upstream, &raw).await;
        if let Some(result) = capture {
            let status = forwarded
                .as_ref()
                .map(|r| status(r))
                .map_err(|e| std::io::Error::other(e.to_string()))
                .and_then(std::convert::identity);
            let _observed = result.send(status);
        }
        let response = forwarded?;
        if client.write_all(&response).await.is_err() {
            return Ok(());
        }
    }
}

/// A PUT of a content-addressed bin or metadata object, by request path.
fn is_content_put(raw: &[u8]) -> bool {
    let line = raw.split(|b| *b == b'\r').next().unwrap_or_default();
    let mut words = line.split(|b| *b == b' ');
    words.next() == Some(b"PUT")
        && words.next().is_some_and(|path| {
            path.windows(6).any(|w| w == b"/bins/") || path.windows(6).any(|w| w == b"/meta/")
        })
}

async fn forward(upstream: &str, raw: &[u8]) -> std::io::Result<Vec<u8>> {
    timeout(WAIT, async {
        let mut server = TcpStream::connect(upstream).await?;
        server.write_all(raw).await?;
        let mut buffered = Vec::new();
        loop {
            let response =
                read_frame(&mut server, &mut buffered, false, raw.starts_with(b"HEAD ")).await?;
            if status(&response)? >= 200 {
                return Ok(response);
            }
        }
    })
    .await
    .map_err(|_| invalid())?
}
fn status(response: &[u8]) -> std::io::Result<u16> {
    std::str::from_utf8(
        response
            .get(
                ..response
                    .iter()
                    .position(|b| *b == b'\r')
                    .ok_or_else(invalid)?,
            )
            .ok_or_else(invalid)?,
    )
    .map_err(|_| invalid())?
    .split_whitespace()
    .nth(1)
    .ok_or_else(invalid)?
    .parse()
    .map_err(|_| invalid())
}

#[test]
fn capture_framing_controls() {
    let good = b"PUT /granary-test/root/alpha/00000000000000000001 HTTP/1.1\r\nif-none-match: *\r\ncontent-length: 3\r\n\r\nabc";
    assert_eq!(
        root_put(good).unwrap(),
        Some(("alpha".into(), 1, b"abc".to_vec()))
    );
    assert!(
        root_put(good.get(..good.len() - 1).unwrap()).is_err(),
        "truncated capture admitted"
    );
    assert!(root_put(&good.repeat(FRAME_LIMIT / good.len() + 1)).is_err());
    assert!(
        root_put(
            &String::from_utf8_lossy(good)
                .replace("if-none-match: *", "if-none-match: other")
                .into_bytes()
        )
        .is_err(),
        "create-only condition lost"
    );
    assert_eq!(
        frame(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
            .unwrap(),
        Some(60)
    );
    super::support::observe("backend::capture_framing_controls", &[]);
}

struct Issuer {
    stream: tokio::io::DuplexStream,
    fail_shutdown: bool,
}
impl AsyncWrite for Issuer {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_write(cx, bytes)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.fail_shutdown {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        std::pin::Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn detached_capture_remains_releasable() {
    let mut outcomes = Vec::new();
    for (closed, fail_shutdown) in [(false, false), (true, false), (false, true)] {
        let identity = Identity {
            volume: "alpha".into(),
            seq: 1,
            id: GrainId::of(b"signed"),
            occurrence: 1,
        };
        let (release, released) = oneshot::channel();
        let (result, observed) = oneshot::channel();
        let (detach, detached) = oneshot::channel::<oneshot::Sender<()>>();
        let (stream, peer) = tokio::io::duplex(1024);
        let _peer = (!closed).then_some(peer);
        let task = tokio::spawn(async move {
            let mut issuer = Issuer {
                stream,
                fail_shutdown,
            };
            if wait_for_release(&mut issuer, released, detached)
                .await
                .is_ok()
            {
                let _ = result.send(Ok(200));
            }
        });
        let proxy = Proxy {
            endpoint: String::new(),
            state: Arc::new(Mutex::new(State {
                pending: vec![Pending {
                    identity: identity.clone(),
                    body: b"signed".to_vec(),
                    release,
                    result: observed,
                    detach: Some(detach),
                }],
                ..State::default()
            })),
            changed: Arc::new(Notify::new()),
            task,
        };
        let detached = proxy.detach(&identity).await;
        let retained = (proxy.pending(), proxy.captures(), proxy.issuer_refusals());
        assert!(
            proxy.detach(&identity).await.is_err(),
            "issuer detached twice"
        );
        let released = proxy.release(&identity).await;
        outcomes.push((
            closed,
            fail_shutdown,
            detached,
            retained,
            released,
            (proxy.pending(), proxy.finished()),
        ));
    }
    let identity = Identity {
        volume: "alpha".into(),
        seq: 1,
        id: GrainId::of(b"signed"),
        occurrence: 1,
    };
    assert_eq!(
        outcomes,
        [(false, false), (true, false), (false, true)].map(|(closed, fail_shutdown)| (
            closed,
            fail_shutdown,
            Ok(()),
            (
                1,
                vec![(identity.clone(), b"signed".to_vec())],
                vec![identity.clone()]
            ),
            Ok(200),
            (0, vec![(identity.clone(), 200)])
        )),
        "issuer write/shutdown failure must acknowledge detach and preserve the parent-owned capture"
    );
    super::support::observe("backend::detached_capture_remains_releasable", &[]);
}
