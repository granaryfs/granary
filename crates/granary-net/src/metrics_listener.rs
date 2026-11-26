// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Dedicated TLS and HTTP/1.1 transport for one local metrics store.

use std::convert::Infallible;
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::task::{Context, Poll};
use std::time::Duration;

use granary_core::hash::GrainId;
use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::header::{
    AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, EXPECT, HOST,
    HeaderValue, ORIGIN, TRANSFER_ENCODING, UPGRADE,
};
use hyper::{
    Method, Request, Response, StatusCode, Version, server::conn::http1, service::service_fn,
};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::runtime::Builder;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::accept::{Raced, race};

const MAX_HEAD: usize = 8192;
const MAX_HEADERS: usize = 16;
const MAX_CONNECTIONS: usize = 4;
const MAX_RESPONSE: usize = 65_536;
const LIFETIME: Duration = Duration::from_secs(5);
const CONTENT: &str = "text/plain; version=0.0.4; charset=utf-8";
const TOKEN_DOMAIN: &[u8; 24] = b"granary-metrics-auth-v1\0";

// Pending TCP errors listed in accept(2). Keep the raw values scoped to their
// OS ABI so unrelated errors with the same numbers stay fatal.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
const ACCEPT_NETWORK_ERRORS: &[i32] = &[
    100, // ENETDOWN
    71,  // EPROTO
    92,  // ENOPROTOOPT
    112, // EHOSTDOWN
    64,  // ENONET
    113, // EHOSTUNREACH
    95,  // EOPNOTSUPP
    101, // ENETUNREACH
];
#[cfg(target_os = "macos")]
const ACCEPT_NETWORK_ERRORS: &[i32] = &[
    50,  // ENETDOWN
    100, // EPROTO
    42,  // ENOPROTOOPT
    64,  // EHOSTDOWN
    65,  // EHOSTUNREACH
    102, // EOPNOTSUPP
    51,  // ENETUNREACH
];
#[cfg(not(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )
)))]
const ACCEPT_NETWORK_ERRORS: &[i32] = &[];

fn retry_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    ) || error
        .raw_os_error()
        .is_some_and(|errno| ACCEPT_NETWORK_ERRORS.contains(&errno))
}

/// A numeric address in the listener's exact loopback profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint(SocketAddr);

/// A refused metrics address or configuration. The reason contains no input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigurationError {
    /// Only `127.0.0.1` and `::1` with a nonzero port are allowed.
    Address,
    /// The bearer file must contain exactly 64 lowercase hex digits.
    Token,
    /// The TLS certificate chain or private key is unusable.
    Tls,
}

impl fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Address => "metrics address must be 127.0.0.1 or [::1] with a nonzero port",
            Self::Token => "invalid metrics token file",
            Self::Tls => "invalid metrics tls certificate or private key",
        })
    }
}

impl std::error::Error for ConfigurationError {}

impl FromStr for Endpoint {
    type Err = ConfigurationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let addr: SocketAddr = value.parse().map_err(|_| ConfigurationError::Address)?;
        if loopback(addr) && addr.port() != 0 {
            Ok(Self(addr))
        } else {
            Err(ConfigurationError::Address)
        }
    }
}

fn loopback(addr: SocketAddr) -> bool {
    match addr {
        SocketAddr::V4(addr) => *addr.ip() == Ipv4Addr::LOCALHOST,
        SocketAddr::V6(addr) => {
            *addr.ip() == Ipv6Addr::LOCALHOST && addr.scope_id() == 0 && addr.flowinfo() == 0
        }
    }
}

fn bound_address(endpoint: Endpoint, bound: SocketAddr) -> bool {
    loopback(bound) && bound == endpoint.0
}

fn peer_address(endpoint: Endpoint, peer: SocketAddr) -> bool {
    loopback(peer) && peer.ip() == endpoint.0.ip()
}

fn can_admit(endpoint: Endpoint, peer: SocketAddr, active: usize) -> bool {
    active < MAX_CONNECTIONS && peer_address(endpoint, peer)
}

fn token_hash(token: &[u8]) -> Option<GrainId> {
    let token = crate::config::decode_hex32(std::str::from_utf8(token).ok()?).ok()?;
    let mut input = [0; TOKEN_DOMAIN.len() + 32];
    let (domain, decoded) = input.split_at_mut(TOKEN_DOMAIN.len());
    domain.copy_from_slice(TOKEN_DOMAIN);
    decoded.copy_from_slice(&token);
    Some(GrainId::of(&input))
}

/// Validated, dedicated configuration. Debug output omits credential material.
pub struct Configuration {
    endpoint: Endpoint,
    token: GrainId,
    acceptor: TlsAcceptor,
}

impl fmt::Debug for Configuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Configuration")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl Configuration {
    /// Validate the dedicated TLS configuration and digest the bearer.
    ///
    /// # Errors
    /// Returns an error if the bearer or TLS PEM material is unusable.
    pub fn new(
        endpoint: Endpoint,
        token: &[u8],
        certificate: &[u8],
        key: &[u8],
    ) -> Result<Self, ConfigurationError> {
        let token = token_hash(token).ok_or(ConfigurationError::Token)?;
        let certs = CertificateDer::pem_slice_iter(certificate)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ConfigurationError::Tls)?;
        let key = PrivateKeyDer::from_pem_slice(key).map_err(|_| ConfigurationError::Tls)?;
        let mut tls = crate::tls::server_tls_config(certs, key, crate::tls::ClientAuth::None)
            .map_err(|_| ConfigurationError::Tls)?;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        tls.send_tls13_tickets = 0;
        tls.max_tls13_tickets = 0;
        crate::tls::resumption_is_off(&tls).map_err(|_| ConfigurationError::Tls)?;
        Ok(Self {
            endpoint,
            token,
            acceptor: TlsAcceptor::from(Arc::new(tls)),
        })
    }
}

/// Terminal outcome of a TLS-admitted connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrapeResult {
    /// A metrics response finished.
    Ok,
    /// The peer ended the connection without a request, or the request was refused.
    Refused,
    /// The connection exceeded its lifetime.
    Limited,
    /// Rendering or connection I/O failed.
    Failed,
    /// The listener was cancelled.
    Cancelled,
}

/// A failure of the exporter itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The listener encountered an I/O failure.
    Io,
    /// The exporter could not render a snapshot or lost a connection task.
    Internal,
}

/// Notifications delivered on the listener's worker thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The bound socket is registered and the worker has started.
    Started,
    /// One terminal outcome for a TLS-admitted connection.
    Scrape(ScrapeResult),
    /// The exporter failed.
    Failed(Failure),
    /// The listener stopped.
    Stopped,
}

/// An unavailable listener during binding or worker startup.
#[derive(Debug)]
pub enum StartError {
    /// The listener could not bind its configured address.
    Bind(io::Error),
    /// The bound address was outside the configuration.
    Address,
    /// The worker could not be started.
    Worker(io::Error),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind(error) => write!(f, "metrics listener bind: {error}"),
            Self::Address => f.write_str("metrics listener bound address mismatch"),
            Self::Worker(error) => write!(f, "metrics listener worker: {error}"),
        }
    }
}

impl std::error::Error for StartError {}

/// Owns cancellation of one listener. Dropping it requests shutdown.
#[derive(Debug)]
#[must_use]
pub struct Listener(watch::Sender<bool>);

impl Drop for Listener {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

/// Start the worker and expose one store. The render future is called only
/// for an authorized scrape and must yield if it performs asynchronous work.
/// Dropping the returned owner cancels sockets without joining the worker.
///
/// # Errors
/// If binding, checking the bound address or starting the worker fails.
pub fn start<R, F, N>(config: Configuration, render: R, notify: N) -> Result<Listener, StartError>
where
    R: Fn() -> F + Send + Sync + 'static,
    F: Future<Output = Result<Vec<u8>, Failure>> + Send + 'static,
    N: Fn(Event) + Send + Sync + 'static,
{
    let socket = std::net::TcpListener::bind(config.endpoint.0).map_err(StartError::Bind)?;
    if !bound_address(
        config.endpoint,
        socket.local_addr().map_err(StartError::Bind)?,
    ) {
        return Err(StartError::Address);
    }
    socket.set_nonblocking(true).map_err(StartError::Bind)?;

    let (stop, shutdown) = watch::channel(false);
    let worker_stop = stop.clone();
    let (ready, startup) = mpsc::sync_channel(1);
    let dispatcher = tracing::dispatcher::get_default(Clone::clone);
    std::thread::Builder::new()
        .name("gran-metrics".to_owned())
        .spawn(move || {
            tracing::dispatcher::with_default(&dispatcher, || {
                let runtime = Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build();
                let result = runtime.and_then(|runtime| {
                    let listener = {
                        let _entered = runtime.enter();
                        TcpListener::from_std(socket)?
                    };
                    notify(Event::Started);
                    let _ = ready.send(Ok(()));
                    let service = Arc::new(Service::new(config, render, notify));
                    runtime.block_on(worker(
                        move |cx| listener.poll_accept(cx),
                        worker_stop,
                        shutdown,
                        service,
                    ));
                    Ok(())
                });
                if let Err(error) = result {
                    let _ = ready.send(Err(error));
                }
            });
        })
        .map_err(StartError::Worker)?;

    startup
        .recv()
        .map_err(|_| StartError::Worker(io::Error::other("worker exited during startup")))?
        .map_err(StartError::Worker)?;
    Ok(Listener(stop))
}

struct Service<R, N> {
    config: Configuration,
    render: R,
    notify: N,
    render_failed: AtomicBool,
    worker_failed: AtomicBool,
}

impl<R, N: Fn(Event)> Service<R, N> {
    const fn new(config: Configuration, render: R, notify: N) -> Self {
        Self {
            config,
            render,
            notify,
            render_failed: AtomicBool::new(false),
            worker_failed: AtomicBool::new(false),
        }
    }

    fn fail(&self, latch: &AtomicBool, class: Failure) {
        if !latch.swap(true, Ordering::Relaxed) {
            (self.notify)(Event::Failed(class));
        }
    }
}

async fn worker<I, R, F, N>(
    mut poll_accept: impl FnMut(&mut Context<'_>) -> Poll<io::Result<(I, SocketAddr)>>,
    stop: watch::Sender<bool>,
    mut shutdown: watch::Receiver<bool>,
    service: Arc<Service<R, N>>,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    R: Fn() -> F + Send + Sync + 'static,
    F: Future<Output = Result<Vec<u8>, Failure>> + Send + 'static,
    N: Fn(Event) + Send + Sync + 'static,
{
    let mut active = JoinSet::new();
    loop {
        let next = poll_fn(|cx| {
            while let Poll::Ready(Some(outcome)) = active.poll_join_next(cx) {
                if outcome.is_err() {
                    return Poll::Ready(Err(Failure::Internal));
                }
            }
            poll_accept(cx).map(|result| match result {
                Ok(accepted) => Ok(Some(accepted)),
                Err(error) if retry_accept_error(&error) => Ok(None),
                Err(_) => Err(Failure::Io),
            })
        });
        match race(&mut shutdown, next).await {
            Raced::Shutdown(_) => break,
            Raced::Ready(Err(class)) => {
                service.fail(&service.worker_failed, class);
                stop.send_replace(true);
                break;
            }
            // Recheck cancellation and completed tasks before polling accept again.
            Raced::Ready(Ok(None)) => {}
            Raced::Ready(Ok(Some((stream, peer)))) => {
                if can_admit(service.config.endpoint, peer, active.len()) {
                    let task = connection(stream, Arc::clone(&service), shutdown.clone());
                    #[expect(
                        clippy::disallowed_methods,
                        reason = "the dedicated network runtime owns and bounds each connection task"
                    )]
                    active.spawn(task);
                }
            }
        }
    }
    drop(poll_accept);
    // Only the worker reaps its tasks. Each races cancellation before its I/O.
    while active.join_next().await.is_some() {}
    (service.notify)(Event::Stopped);
}

// Construct the timeout on admission, before the task can be scheduled.
fn connection<I, R, F, N>(
    stream: I,
    service: Arc<Service<R, N>>,
    mut shutdown: watch::Receiver<bool>,
) -> impl Future<Output = ()>
where
    I: AsyncRead + AsyncWrite + Unpin,
    R: Fn() -> F,
    F: Future<Output = Result<Vec<u8>, Failure>>,
    N: Fn(Event),
{
    let admitted = Arc::new(AtomicBool::new(false));
    let tls_admitted = Arc::clone(&admitted);
    let server = Arc::clone(&service);
    let work = timeout(LIFETIME, async move {
        let Ok(tls) = server.config.acceptor.accept(stream).await else {
            return ScrapeResult::Refused;
        };
        // With no offered ALPN, rustls leaves it unset and HTTP/1 still applies.
        tls_admitted.store(true, Ordering::Relaxed);
        serve_http(tls, &server).await
    });
    async move {
        let outcome = match race(&mut shutdown, work).await {
            Raced::Shutdown(_) => ScrapeResult::Cancelled,
            Raced::Ready(Err(_)) => ScrapeResult::Limited,
            Raced::Ready(Ok(result)) => result,
        };
        if admitted.load(Ordering::Relaxed) {
            (service.notify)(Event::Scrape(outcome));
        }
    }
}

async fn serve_http<I, R, F, N>(stream: I, service: &Service<R, N>) -> ScrapeResult
where
    I: AsyncRead + AsyncWrite + Unpin,
    R: Fn() -> F,
    F: Future<Output = Result<Vec<u8>, Failure>>,
    N: Fn(Event),
{
    let handled = OnceLock::new();
    let response = service_fn(|request| async {
        let (status, bytes, result) = reply(service, request).await;
        let _ = handled.set(result);
        let mut response = Response::new(ReplyBody(Some(bytes)));
        *response.status_mut() = status;
        let headers = response.headers_mut();
        headers.insert(CONNECTION, HeaderValue::from_static("close"));
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(CONTENT));
        Ok::<_, Infallible>(response)
    });
    match http1::Builder::new()
        .keep_alive(false)
        .header_read_timeout(None)
        .auto_date_header(false)
        .max_buf_size(MAX_HEAD)
        .max_headers(MAX_HEADERS)
        .serve_connection(TokioIo::new(stream), response)
        .await
    {
        Ok(()) => handled.into_inner().unwrap_or(ScrapeResult::Refused),
        Err(error) if error.is_parse() => ScrapeResult::Refused,
        Err(_) => ScrapeResult::Failed,
    }
}

async fn reply<R, F, N>(
    service: &Service<R, N>,
    request: Request<Incoming>,
) -> (StatusCode, Bytes, ScrapeResult)
where
    R: Fn() -> F,
    F: Future<Output = Result<Vec<u8>, Failure>>,
    N: Fn(Event),
{
    let refusal = check_request(&service.config, &request);
    // Never poll a request body, including Expect: 100-continue.
    drop(request);
    if let Err((status, text)) = refusal {
        return (status, Bytes::from_static(text), ScrapeResult::Refused);
    }
    if !service.render_failed.load(Ordering::Relaxed) {
        let class = match (service.render)().await {
            Ok(body) if body.len() <= MAX_RESPONSE => {
                return (StatusCode::OK, Bytes::from(body), ScrapeResult::Ok);
            }
            Ok(_) => Failure::Internal,
            Err(class) => class,
        };
        service.fail(&service.render_failed, class);
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Bytes::from_static(b"metrics unavailable\n"),
        ScrapeResult::Failed,
    )
}

fn check_request(
    config: &Configuration,
    request: &Request<Incoming>,
) -> Result<(), (StatusCode, &'static [u8])> {
    let headers = request.headers();
    let mut hosts = headers.get_all(HOST).iter();
    let host = hosts.next().and_then(|value| value.to_str().ok());
    let mut auth = headers.get_all(AUTHORIZATION).iter();
    let bearer = auth.next();
    let upgrade = headers.get_all(CONNECTION).iter().any(|value| {
        value
            .as_bytes()
            .split(|&byte| byte == b',')
            .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"upgrade"))
    });
    if request.version() != Version::HTTP_11
        || hosts.next().is_some()
        || !host.is_some_and(|host| matching_host(config.endpoint, host))
        || auth.next().is_some()
        || headers.contains_key(ORIGIN)
        || headers.contains_key(UPGRADE)
        || upgrade
        || headers.contains_key(EXPECT)
        || headers.contains_key(TRANSFER_ENCODING)
        || headers
            .get(CONTENT_LENGTH)
            .is_some_and(|value| !value.as_bytes().iter().all(|&byte| byte == b'0'))
    {
        return Err((StatusCode::BAD_REQUEST, b"bad request\n"));
    }
    if request.method() != Method::GET {
        return Err((StatusCode::METHOD_NOT_ALLOWED, b"method not allowed\n"));
    }
    let uri = request.uri();
    if uri.scheme().is_some()
        || uri.authority().is_some()
        || uri.path() != "/metrics"
        || uri.query().is_some()
    {
        return Err((StatusCode::NOT_FOUND, b"not found\n"));
    }
    let digest = bearer.and_then(|value| {
        let (scheme, token) = value.as_bytes().split_at_checked(7)?;
        scheme
            .eq_ignore_ascii_case(b"Bearer ")
            .then(|| token_hash(token))
            .flatten()
    });
    if digest != Some(config.token) {
        return Err((StatusCode::UNAUTHORIZED, b"unauthorized\n"));
    }
    Ok(())
}

fn matching_host(endpoint: Endpoint, host: &str) -> bool {
    if let Ok(addr) = host.parse::<SocketAddr>() {
        return addr == endpoint.0;
    }
    endpoint.0.port() == 443
        && if let Some(ip) = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
        {
            ip.parse::<Ipv6Addr>()
                .is_ok_and(|ip| IpAddr::V6(ip) == endpoint.0.ip())
        } else {
            host.parse::<Ipv4Addr>()
                .is_ok_and(|ip| IpAddr::V4(ip) == endpoint.0.ip())
        }
}

struct ReplyBody(Option<Bytes>);

impl Body for ReplyBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.0.take().map(|bytes| Ok(Frame::data(bytes))))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.0.as_ref().map_or(0, |bytes| bytes.len() as u64))
    }
}

#[cfg(test)]
mod tests;
