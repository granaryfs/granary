// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![expect(
    clippy::disallowed_methods,
    reason = "drive both ends of the transport in tests"
)]

use std::future::{Ready, pending, ready};
use std::sync::atomic::AtomicUsize;

use rcgen::CertifiedKey;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf, duplex};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio_rustls::{TlsConnector, client::TlsStream};

use super::*;

const TOKEN: [u8; 64] = [b'a'; 64];
const WATCHDOG: Duration = Duration::from_secs(8);

struct Fixture {
    cert: CertifiedKey<rcgen::KeyPair>,
    endpoint: Endpoint,
}

impl Fixture {
    fn new(endpoint: &str, san: &str) -> Self {
        Self {
            cert: rcgen::generate_simple_self_signed(vec![san.to_owned()]).unwrap(),
            endpoint: endpoint.parse().unwrap(),
        }
    }

    fn config(&self) -> Configuration {
        Configuration::new(
            self.endpoint,
            &TOKEN,
            self.cert.cert.pem().as_bytes(),
            self.cert.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap()
    }

    fn client(&self, offer: Option<&[u8]>) -> TlsConnector {
        let mut roots = RootCertStore::empty();
        roots.add(self.cert.cert.der().clone()).unwrap();
        let mut client = ClientConfig::builder_with_provider(Arc::new(crate::crypto_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols.extend(offer.map(<[u8]>::to_vec));
        TlsConnector::from(Arc::new(client))
    }
}

fn fixture() -> Fixture {
    Fixture::new("127.0.0.1:9900", "127.0.0.1")
}

fn report(sender: UnboundedSender<Event>) -> impl Fn(Event) {
    move |event| {
        let _ = sender.send(event);
    }
}

fn render() -> Ready<Result<Vec<u8>, Failure>> {
    ready(Ok(b"one_metric 1\n".to_vec()))
}

async fn connect<I>(
    connector: &TlsConnector,
    endpoint: Endpoint,
    stream: I,
) -> io::Result<TlsStream<I>>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    connector.connect(endpoint.0.ip().into(), stream).await
}

fn request(
    endpoint: Endpoint,
    method: &str,
    path: &str,
    version: &str,
    auth: &[&[u8]],
    extra: &str,
) -> Vec<u8> {
    let mut head = format!("{method} {path} {version}\r\nHost: {}\r\n", endpoint.0).into_bytes();
    for token in auth {
        head.extend_from_slice(b"Authorization: Bearer ");
        head.extend_from_slice(token);
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(extra.as_bytes());
    head.extend_from_slice(b"\r\n");
    head
}

fn get(endpoint: Endpoint, extra: &str) -> Vec<u8> {
    request(endpoint, "GET", "/metrics", "HTTP/1.1", &[&TOKEN], extra)
}

fn padded_head(endpoint: Endpoint, len: usize) -> Vec<u8> {
    let head = get(endpoint, "X-Padding: \r\n");
    get(
        endpoint,
        &format!("X-Padding: {}\r\n", "a".repeat(len - head.len())),
    )
}

async fn read_reply(stream: &mut (impl AsyncRead + Unpin)) -> (Vec<u8>, Option<io::ErrorKind>) {
    let mut response = Vec::new();
    let error = timeout(WATCHDOG, stream.read_to_end(&mut response))
        .await
        .unwrap()
        .err()
        .map(|err| err.kind());
    (response, error)
}

async fn outcome(events: &mut UnboundedReceiver<Event>) -> Event {
    timeout(WATCHDOG, events.recv()).await.unwrap().unwrap()
}

fn assert_reply(reply: &[u8], status: u16, handler: bool) {
    let response = std::str::from_utf8(reply).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    assert_eq!(
        head.lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1)),
        Some(status.to_string().as_str())
    );
    assert_eq!(
        head.lines().any(|line| line == "cache-control: no-store"),
        handler
    );
    if handler {
        assert!(head.lines().any(|line| line == "connection: close"));
        assert!(body.len() <= if status == 200 { MAX_RESPONSE } else { 256 });
    } else {
        assert!(body.is_empty());
    }
}

async fn exchange(
    fixture: &Fixture,
    request: &[u8],
    alpn: Option<&[u8]>,
) -> (Vec<u8>, Option<io::ErrorKind>, Vec<Event>) {
    let (stop, shutdown) = watch::channel(false);
    let (tx, mut events) = unbounded_channel();
    let service = Arc::new(Service::new(fixture.config(), render, report(tx)));
    let (client, server) = duplex(32_768);
    let task = tokio::spawn(connection(server, service, shutdown));
    let mut tls = timeout(
        WATCHDOG,
        connect(&fixture.client(alpn), fixture.endpoint, client),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), alpn);
    tls.write_all(request).await.unwrap();
    let (response, error) = read_reply(&mut tls).await;
    task.await.unwrap();
    drop(stop);
    let mut observed = Vec::new();
    while let Ok(event) = events.try_recv() {
        observed.push(event);
    }
    (response, error, observed)
}

#[test]
fn address_and_peer_profile() {
    for allowed in ["127.0.0.1:1", "[::1]:65535", "[0:0:0:0:0:0:0:1]:9900"] {
        let endpoint: Endpoint = allowed.parse().unwrap();
        assert!(bound_address(endpoint, endpoint.0));
        assert!(peer_address(
            endpoint,
            SocketAddr::new(endpoint.0.ip(), 12345)
        ));
    }
    let v4 = "127.0.0.1:9900".parse().unwrap();
    let v6 = "[::1]:9900".parse().unwrap();
    for denied in [
        "localhost:9900",
        "127.0.0.1:0",
        "[::1]:65536",
        "0.0.0.0:9900",
        "[::]:9900",
        "[::ffff:127.0.0.1]:9900",
        "127.0.0.2:9900",
        "192.0.2.1:9900",
        "[::1%3]:9900",
        "[2001:db8::1]:9900",
    ] {
        assert!(denied.parse::<Endpoint>().is_err(), "{denied}");
        if let Ok(addr) = denied.parse::<SocketAddr>()
            && addr.port() == 9900
        {
            assert!(
                !bound_address(v4, addr) && !bound_address(v6, addr),
                "{denied}"
            );
            assert!(
                !peer_address(v4, addr) && !peer_address(v6, addr),
                "{denied}"
            );
        }
    }
    assert!(!bound_address(v4, "127.0.0.1:9901".parse().unwrap()));
    assert!(!peer_address(v6, "127.0.0.1:9900".parse().unwrap()));
    assert!(matching_host("127.0.0.1:443".parse().unwrap(), "127.0.0.1"));
    assert!(matching_host(
        "[::1]:443".parse().unwrap(),
        "[0:0:0:0:0:0:0:1]"
    ));
    assert!(!matching_host(v4, "127.0.0.1"));
}

#[test]
fn admission_reserves_at_most_four_connection_slots() {
    let endpoint = "127.0.0.1:9900".parse().unwrap();
    let peer = "127.0.0.1:12345".parse().unwrap();
    for active in 0..4 {
        assert!(can_admit(endpoint, peer, active));
    }
    assert!(!can_admit(endpoint, peer, 4));
}

#[test]
fn accept_errors_distinguish_connection_failures_from_listener_failures() {
    for kind in [
        io::ErrorKind::Interrupted,
        io::ErrorKind::ConnectionAborted,
        io::ErrorKind::ConnectionReset,
    ] {
        assert!(retry_accept_error(&kind.into()), "{kind:?}");
    }

    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )
    ))]
    for (name, linux, macos, retry) in [
        ("EINTR", 4, 4, true),
        ("ECONNABORTED", 103, 53, true),
        ("ECONNRESET", 104, 54, true),
        ("ENETDOWN", 100, 50, true),
        ("EPROTO", 71, 100, true),
        ("ENOPROTOOPT", 92, 42, true),
        ("EHOSTDOWN", 112, 64, true),
        #[cfg(target_os = "linux")]
        ("ENONET", 64, 0, true),
        ("EHOSTUNREACH", 113, 65, true),
        ("EOPNOTSUPP", 95, 102, true),
        ("ENETUNREACH", 101, 51, true),
        ("EMFILE", 24, 24, false),
        ("ENFILE", 23, 23, false),
        ("ENOBUFS", 105, 55, false),
        ("ENOMEM", 12, 12, false),
    ] {
        let errno = if cfg!(target_os = "macos") {
            macos
        } else {
            linux
        };
        assert_eq!(
            retry_accept_error(&io::Error::from_raw_os_error(errno)),
            retry,
            "{name}"
        );
    }
    assert!(!retry_accept_error(&io::Error::from_raw_os_error(i32::MAX)));
}

#[tokio::test]
async fn bearer_and_handler_refusals() {
    let f = fixture();
    let control = get(f.endpoint, "Content-Length: 0\r\n");
    let cases = [
        (200, control),
        (
            401,
            request(f.endpoint, "GET", "/metrics", "HTTP/1.1", &[], ""),
        ),
        (
            401,
            request(
                f.endpoint,
                "GET",
                "/metrics",
                "HTTP/1.1",
                &[&[b'b'; 64]],
                "",
            ),
        ),
        (
            400,
            request(
                f.endpoint,
                "GET",
                "/metrics",
                "HTTP/1.1",
                &[&TOKEN, &TOKEN],
                "",
            ),
        ),
        (
            405,
            request(f.endpoint, "POST", "/metrics", "HTTP/1.1", &[&TOKEN], ""),
        ),
        (
            404,
            request(f.endpoint, "GET", "/metrics?", "HTTP/1.1", &[&TOKEN], ""),
        ),
        (
            404,
            request(f.endpoint, "GET", "/other", "HTTP/1.1", &[&TOKEN], ""),
        ),
        (
            404,
            request(
                f.endpoint,
                "GET",
                "http://127.0.0.1:9900/metrics",
                "HTTP/1.1",
                &[&TOKEN],
                "",
            ),
        ),
        (
            400,
            request(f.endpoint, "GET", "/metrics", "HTTP/1.0", &[&TOKEN], ""),
        ),
        (400, get(f.endpoint, "Host: 127.0.0.1:9900\r\n")),
        (400, get(f.endpoint, "Origin: null\r\n")),
        (400, get(f.endpoint, "Upgrade: websocket\r\n")),
        (400, get(f.endpoint, "Connection: keep-alive, UpGrade\r\n")),
        (
            400,
            get(f.endpoint, "Expect: 100-continue\r\nContent-Length: 1\r\n"),
        ),
        (400, get(f.endpoint, "Expect: 100-continue\r\n")),
        (400, get(f.endpoint, "Transfer-Encoding: chunked\r\n")),
        (400, get(f.endpoint, "Content-Length: 1\r\n")),
    ];
    for (index, (status, request)) in cases.into_iter().enumerate() {
        let (response, error, events) = exchange(&f, &request, Some(b"http/1.1")).await;
        assert!(
            !response.is_empty(),
            "case {index}, expected {status}, close {error:?}"
        );
        let close = if index == 11 {
            Some(io::ErrorKind::UnexpectedEof)
        } else {
            None
        };
        assert_eq!(error, close, "case {index}, expected {status}");
        assert_reply(&response, status, true);
        let result = if status == 200 {
            ScrapeResult::Ok
        } else {
            ScrapeResult::Refused
        };
        assert_eq!(events, [Event::Scrape(result)]);
    }
    let (response, error, events) = exchange(&f, &get(f.endpoint, ""), None).await;
    assert_eq!(error, None);
    assert_reply(&response, 200, true);
    assert_eq!(events, [Event::Scrape(ScrapeResult::Ok)]);
}

#[tokio::test]
async fn fragment_suffix_preserves_route_and_bearer_check() {
    let f = fixture();
    let alpn = Some(b"http/1.1".as_slice());
    let (control, close, events) = exchange(&f, &get(f.endpoint, ""), alpn).await;
    assert_reply(&control, 200, true);
    assert_eq!(close, None);
    assert_eq!(events, [Event::Scrape(ScrapeResult::Ok)]);

    let authorized = request(f.endpoint, "GET", "/metrics#x", "HTTP/1.1", &[&TOKEN], "");
    assert_eq!(
        exchange(&f, &authorized, alpn).await,
        (control, close, events)
    );

    let unauthorized = request(f.endpoint, "GET", "/metrics#x", "HTTP/1.1", &[], "");
    let (response, close, events) = exchange(&f, &unauthorized, alpn).await;
    assert_reply(&response, 401, true);
    assert_eq!(close, None);
    assert_eq!(events, [Event::Scrape(ScrapeResult::Refused)]);
}

#[tokio::test]
async fn parser_refusals_and_independent_header_cap() {
    let f = fixture();
    let control = get(f.endpoint, &"X-Filler: a\r\n".repeat(14));
    let (response, error, events) = exchange(&f, &control, None).await;
    assert_eq!(error, None);
    assert_reply(&response, 200, true);
    assert_eq!(events, [Event::Scrape(ScrapeResult::Ok)]);
    for (status, request) in [
        (431, get(f.endpoint, &"X-Filler: a\r\n".repeat(15))),
        (400, get(f.endpoint, "Content-Length: x\r\n")),
        (
            400,
            get(f.endpoint, "Content-Length: 18446744073709551616\r\n"),
        ),
        (
            400,
            get(f.endpoint, "Content-Length: 0\r\nContent-Length: 1\r\n"),
        ),
        (400, get(f.endpoint, "Transfer-Encoding: gzip\r\n")),
        (
            431,
            get(f.endpoint, "Content-Length: 18446744073709551615\r\n"),
        ),
    ] {
        let (response, error, events) = exchange(&f, &request, None).await;
        assert_eq!(error, None);
        assert_reply(&response, status, false);
        assert_eq!(events, [Event::Scrape(ScrapeResult::Refused)]);
    }
    let (response, error, events) = exchange(&f, b"PRI * HTTP/2.0\r\n\r\n", None).await;
    assert_eq!(error, None);
    assert_reply(&response, 400, false);
    assert_eq!(events, [Event::Scrape(ScrapeResult::Refused)]);
    let (response, error, events) = exchange(&f, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", None).await;
    assert!(response.is_empty());
    assert_eq!(error, Some(io::ErrorKind::UnexpectedEof));
    assert_eq!(events, [Event::Scrape(ScrapeResult::Refused)]);
}

// A split is established by the server's actual decrypted read before sending
// the suffix. One TLS write on the coalesced arm contains the whole head.
struct ObservedRead<I>(I, UnboundedSender<usize>);

impl<I: AsyncRead + Unpin> AsyncRead for ObservedRead<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.0).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = result {
            let read = buf.filled().len() - before;
            let _ = self.1.send(read);
        }
        result
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for ObservedRead<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

async fn measure_head<I>(f: &Fixture, client: I, server: I, len: usize, split: Option<usize>)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = Service::new(f.config(), render, |_| {});
    let (tx, mut rx) = unbounded_channel();
    let worker = tokio::spawn(async move {
        let tls = service.config.acceptor.accept(server).await.unwrap();
        serve_http(ObservedRead(tls, tx), &service).await
    });
    let mut client = timeout(
        WATCHDOG,
        connect(&f.client(Some(b"http/1.1")), f.endpoint, client),
    )
    .await
    .unwrap()
    .unwrap();
    let head = padded_head(f.endpoint, len);
    assert_eq!(head.len(), len);
    if let Some(split) = split {
        let (prefix, suffix) = head.split_at(split);
        client.write_all(prefix).await.unwrap();
        client.flush().await.unwrap();
        assert_eq!(timeout(WATCHDOG, rx.recv()).await.unwrap(), Some(split));
        client.write_all(suffix).await.unwrap();
    } else {
        client.write_all(&head).await.unwrap();
    }
    let (response, error) = read_reply(&mut client).await;
    assert_eq!(error, None);
    let outcome = worker.await.unwrap();
    if split.is_none() {
        assert_eq!(rx.recv().await, Some(8192));
    }
    if len == 8192 {
        assert_reply(&response, 200, true);
        assert_eq!(outcome, ScrapeResult::Ok);
    } else {
        assert_reply(&response, 431, false);
        assert_eq!(outcome, ScrapeResult::Refused);
    }
}

#[tokio::test]
async fn tls_head_byte_cap_with_controlled_reads() {
    let f = fixture();
    for len in [8192, 8193] {
        for split in [None, Some(1), Some(2048), Some(8191)] {
            let (client, server) = duplex(32_768);
            measure_head(&f, client, server, len, split).await;
        }
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn metrics_linux_tls_head_byte_cap_with_controlled_reads() {
    let f = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    for len in [8192, 8193] {
        for split in [None, Some(1), Some(2048), Some(8191)] {
            let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (server, _) = listener.accept().await.unwrap();
            measure_head(&f, client, server, len, split).await;
        }
    }
}

#[tokio::test]
async fn tls_trust_ip_san_and_plaintext() {
    let f = fixture();
    let impostor = fixture();
    let wrong_san = Fixture::new("127.0.0.1:9900", "127.0.0.2");
    for (server, client) in [
        (&impostor, f.client(None)),
        (&wrong_san, wrong_san.client(None)),
    ] {
        let (stream, impostor) = duplex(32_768);
        let acceptor = server.config().acceptor;
        let witnessed = tokio::spawn(async move {
            if let Ok(mut tls) = acceptor.accept(impostor).await {
                let mut data = [0; 1];
                return tls.read(&mut data).await.is_ok_and(|read| read > 0);
            }
            false
        });
        let accepted = match timeout(WATCHDOG, connect(&client, f.endpoint, stream))
            .await
            .unwrap()
        {
            Ok(mut client) => {
                let _ = client.write_all(&get(f.endpoint, "")).await;
                true
            }
            Err(_) => false,
        };
        assert!(!accepted);
        assert!(!timeout(WATCHDOG, witnessed).await.unwrap().unwrap());
    }

    let (stop, shutdown) = watch::channel(false);
    let (tx, mut events) = unbounded_channel();
    let renders = Arc::new(AtomicUsize::new(0));
    let source = Arc::clone(&renders);
    let service = Arc::new(Service::new(
        f.config(),
        move || {
            source.fetch_add(1, Ordering::Relaxed);
            render()
        },
        report(tx),
    ));
    let (mut client, server) = duplex(32_768);
    let worker = tokio::spawn(connection(server, Arc::clone(&service), shutdown.clone()));
    client.write_all(&get(f.endpoint, "")).await.unwrap();
    let _ = read_reply(&mut client).await;
    worker.await.unwrap();
    let (client, server) = duplex(32_768);
    let worker = tokio::spawn(connection(server, service, shutdown));
    assert!(
        connect(&f.client(Some(b"h2")), f.endpoint, client)
            .await
            .is_err()
    );
    worker.await.unwrap();
    drop(stop);
    assert_eq!(renders.load(Ordering::Relaxed), 0);
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn cancellation_eof_and_render_failure_are_terminal() {
    let f = fixture();
    let (stop, shutdown) = watch::channel(false);
    let (tx, mut events) = unbounded_channel();
    let (captured, mut captured_rx) = unbounded_channel();
    let service = Arc::new(Service::new(
        f.config(),
        move || {
            let _ = captured.send(());
            pending::<Result<Vec<u8>, Failure>>()
        },
        report(tx),
    ));
    let (client, server) = duplex(32_768);
    let worker = tokio::spawn(connection(server, service, shutdown));
    let mut client = connect(&f.client(None), f.endpoint, client).await.unwrap();
    client.write_all(&get(f.endpoint, "")).await.unwrap();
    timeout(WATCHDOG, captured_rx.recv())
        .await
        .unwrap()
        .unwrap();
    stop.send_replace(true);
    assert_eq!(
        outcome(&mut events).await,
        Event::Scrape(ScrapeResult::Cancelled)
    );
    worker.await.unwrap();
    assert!(events.try_recv().is_err());

    let (_stop, shutdown) = watch::channel(false);
    let (tx, mut events) = unbounded_channel();
    let service = Arc::new(Service::new(
        f.config(),
        || ready(Err(Failure::Internal)),
        report(tx),
    ));
    let (client, server) = duplex(32_768);
    let worker = tokio::spawn(connection(server, Arc::clone(&service), shutdown.clone()));
    let mut client = connect(&f.client(None), f.endpoint, client).await.unwrap();
    client.shutdown().await.unwrap();
    let _ = read_reply(&mut client).await;
    worker.await.unwrap();
    assert_eq!(
        outcome(&mut events).await,
        Event::Scrape(ScrapeResult::Refused)
    );

    for attempt in 0..2 {
        let (client, server) = duplex(32_768);
        let worker = tokio::spawn(connection(server, Arc::clone(&service), shutdown.clone()));
        let mut client = connect(&f.client(None), f.endpoint, client).await.unwrap();
        client.write_all(&get(f.endpoint, "")).await.unwrap();
        let (response, error) = read_reply(&mut client).await;
        assert_eq!(error, None);
        assert_reply(&response, 503, true);
        if attempt == 0 {
            assert_eq!(outcome(&mut events).await, Event::Failed(Failure::Internal));
        }
        assert_eq!(
            outcome(&mut events).await,
            Event::Scrape(ScrapeResult::Failed)
        );
        worker.await.unwrap();
    }
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn render_failure_then_worker_io_failure_emits_both_events() {
    let f = fixture();
    let (stop, shutdown) = watch::channel(false);
    let (tx, mut events) = unbounded_channel();
    let service = Arc::new(Service::new(
        f.config(),
        || ready(Err(Failure::Internal)),
        report(tx),
    ));
    let (arrivals, mut accepting) = unbounded_channel();
    let worker = tokio::spawn(worker(
        move |cx| accepting.poll_recv(cx).map(|result| result.unwrap()),
        stop,
        shutdown,
        service,
    ));

    let (client, server) = duplex(32_768);
    arrivals
        .send(Err(io::ErrorKind::Interrupted.into()))
        .unwrap();
    arrivals.send(Ok((server, f.endpoint.0))).unwrap();
    let mut client = timeout(WATCHDOG, connect(&f.client(None), f.endpoint, client))
        .await
        .unwrap()
        .unwrap();
    client.write_all(&get(f.endpoint, "")).await.unwrap();
    let (response, error) = read_reply(&mut client).await;
    assert_eq!(error, None);
    assert_reply(&response, 503, true);
    assert_eq!(outcome(&mut events).await, Event::Failed(Failure::Internal));
    assert_eq!(
        outcome(&mut events).await,
        Event::Scrape(ScrapeResult::Failed)
    );

    arrivals
        .send(Err(io::Error::other("accept failed")))
        .unwrap();
    assert_eq!(outcome(&mut events).await, Event::Failed(Failure::Io));
    assert_eq!(outcome(&mut events).await, Event::Stopped);
    timeout(WATCHDOG, worker).await.unwrap().unwrap();
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn one_lifetime_covers_handshake_header_and_blocked_write() {
    let f = fixture();
    let (_stop, shutdown) = watch::channel(false);
    let (tx, mut events) = unbounded_channel();
    let (rendered, mut rendering) = unbounded_channel();
    let service = Arc::new(Service::new(
        f.config(),
        move || {
            let _ = rendered.send(());
            ready(Ok(vec![b'a'; MAX_RESPONSE]))
        },
        report(tx),
    ));
    let (mut handshake_peer, server) = duplex(1024);
    let handshake = tokio::spawn(connection(server, Arc::clone(&service), shutdown.clone()));

    let connector = f.client(None);
    let (client, server) = duplex(1024);
    let header = tokio::spawn(connection(server, Arc::clone(&service), shutdown.clone()));
    let mut header_peer = connect(&connector, f.endpoint, client).await.unwrap();
    header_peer
        .write_all(b"GET /metrics HTTP/1.1\r\n")
        .await
        .unwrap();

    let (client, server) = duplex(1024);
    let write = tokio::spawn(connection(server, service, shutdown));
    let mut nonreader = connect(&connector, f.endpoint, client).await.unwrap();
    nonreader.write_all(&get(f.endpoint, "")).await.unwrap();
    timeout(WATCHDOG, rendering.recv()).await.unwrap().unwrap();

    let mut byte = [0; 1];
    assert!(
        timeout(Duration::from_millis(50), handshake_peer.read(&mut byte))
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(50), events.recv())
            .await
            .is_err()
    );
    assert_eq!(
        timeout(WATCHDOG, events.recv()).await.ok().flatten(),
        Some(Event::Scrape(ScrapeResult::Limited)),
        "the five-second deadline must close a TLS-admitted stalled connection"
    );
    assert_eq!(
        outcome(&mut events).await,
        Event::Scrape(ScrapeResult::Limited)
    );
    assert_eq!(
        timeout(WATCHDOG, handshake_peer.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    for task in [handshake, header, write] {
        timeout(WATCHDOG, task).await.unwrap().unwrap();
    }
    assert!(events.try_recv().is_err());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn metrics_linux_occupied_and_free_ipv4_ipv6() {
    use tokio::net::TcpStream;

    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let held = std::net::TcpListener::bind(SocketAddr::new(ip, 0)).unwrap();
        let addr = held.local_addr().unwrap();
        let f = Fixture::new(&addr.to_string(), &ip.to_string());
        let (tx, mut events) = unbounded_channel();
        let occupied = start(f.config(), render, report(tx));
        assert!(matches!(
            occupied,
            Err(StartError::Bind(error)) if error.kind() == io::ErrorKind::AddrInUse
        ));
        assert!(events.try_recv().is_err());
        drop(held);
        let (tx, mut events) = unbounded_channel();
        let owner = start(f.config(), render, report(tx)).unwrap();
        assert_eq!(outcome(&mut events).await, Event::Started);
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut tls = timeout(WATCHDOG, connect(&f.client(None), f.endpoint, stream))
            .await
            .unwrap()
            .unwrap();
        tls.write_all(&get(f.endpoint, "")).await.unwrap();
        let (response, error) = read_reply(&mut tls).await;
        assert_eq!(error, None);
        assert_reply(&response, 200, true);
        assert_eq!(outcome(&mut events).await, Event::Scrape(ScrapeResult::Ok));

        if ip.is_ipv4() {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.bind("127.0.0.2:0".parse().unwrap()).unwrap();
            let stream = socket.connect(addr).await.unwrap();
            assert!(
                timeout(WATCHDOG, connect(&f.client(None), f.endpoint, stream))
                    .await
                    .unwrap()
                    .is_err()
            );
        }
        drop(owner);
        assert_eq!(outcome(&mut events).await, Event::Stopped);
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn metrics_linux_fifth_connection_closes_and_cancellation_drains() {
    use tokio::net::TcpStream;

    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = held.local_addr().unwrap();
    let f = Fixture::new(&addr.to_string(), "127.0.0.1");
    drop(held);

    let (tx, mut events) = unbounded_channel();
    let (entered, mut renders) = unbounded_channel();
    let owner = start(
        f.config(),
        move || {
            let _ = entered.send(());
            pending::<Result<Vec<u8>, Failure>>()
        },
        report(tx),
    )
    .unwrap();
    assert_eq!(outcome(&mut events).await, Event::Started);

    let connector = f.client(None);
    let mut active = Vec::new();
    for _ in 0..4 {
        let socket = TcpStream::connect(addr).await.unwrap();
        let mut tls = timeout(WATCHDOG, connect(&connector, f.endpoint, socket))
            .await
            .unwrap()
            .unwrap();
        tls.write_all(&get(f.endpoint, "")).await.unwrap();
        timeout(WATCHDOG, renders.recv()).await.unwrap().unwrap();
        active.push(tls);
    }
    let fifth = TcpStream::connect(addr).await.unwrap();
    assert!(
        timeout(
            Duration::from_secs(1),
            connect(&connector, f.endpoint, fifth)
        )
        .await
        .unwrap()
        .is_err()
    );
    assert!(events.try_recv().is_err());

    drop(owner);
    for mut tls in active {
        let (response, error) = read_reply(&mut tls).await;
        assert!(response.is_empty());
        assert_eq!(error, Some(io::ErrorKind::UnexpectedEof));
        assert_eq!(
            outcome(&mut events).await,
            Event::Scrape(ScrapeResult::Cancelled)
        );
    }
    assert_eq!(outcome(&mut events).await, Event::Stopped);
    assert!(TcpStream::connect(addr).await.is_err());
}
