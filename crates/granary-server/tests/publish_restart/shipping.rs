// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A TLS tap forwards the fixture's enrolled identity to the shipping gateway.
//! It observes requests/replies; only the binary decides or writes publications.
use std::fs::OpenOptions;
use std::io::Write as _;
use std::process::Command;
use std::sync::Arc;

use http_body_util::{BodyExt as _, Full};
use hyper::{Request, Response, body::Incoming};
use rustls_pki_types::pem::PemObject as _;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

use super::*;

fn append(path: &std::path::Path, line: &str) -> std::io::Result<()> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?
        .write_all(line.as_bytes())
}

async fn forward(
    request: Request<Incoming>,
    address: std::net::SocketAddr,
    tls: Arc<rustls::ClientConfig>,
    dir: std::path::PathBuf,
) -> std::io::Result<Response<Full<hyper::body::Bytes>>> {
    let (parts, body) = request.into_parts();
    let body = body
        .collect()
        .await
        .map_err(std::io::Error::other)?
        .to_bytes();
    let path = parts.uri.path();
    let mut target = path.to_owned();
    if let Some(query) = parts.uri.query() {
        target.push('?');
        target.push_str(query);
    }
    let mut raw = format!(
        "{} {target} HTTP/1.1\r\nhost: {address}\r\nconnection: close\r\ncontent-length: {}\r\n",
        parts.method,
        body.len()
    )
    .into_bytes();
    for (name, value) in &parts.headers {
        if !["host", "connection", "content-length", "transfer-encoding"].contains(&name.as_str()) {
            raw.extend_from_slice(name.as_str().as_bytes());
            raw.extend_from_slice(b": ");
            raw.extend_from_slice(value.as_bytes());
            raw.extend_from_slice(b"\r\n");
        }
    }
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(&body);
    let socket = TcpStream::connect(address).await?;
    let mut upstream = tokio_rustls::TlsConnector::from(tls)
        .connect(
            rustls_pki_types::ServerName::try_from("localhost").unwrap(),
            socket,
        )
        .await?;
    upstream.write_all(&raw).await?;
    if parts.method == "POST" && path == "/volume/alpha/publish" {
        let header = |name| {
            parts
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("missing")
        };
        append(
            &dir.join("notes"),
            &format!(
                "POST alpha {} {} {}\n",
                header("granary-epoch"),
                header("granary-operation"),
                hex(&body)
            ),
        )?;
    }
    let mut buffered = Vec::new();
    let raw = super::super::backend::read_frame(
        &mut upstream,
        &mut buffered,
        false,
        parts.method == "HEAD",
    )
    .await?;
    let (response, token, body) = gateway_response(&raw)?;
    append(
        &dir.join("responses"),
        &format!(
            "{} {path} {} {token} {}\n",
            parts.method,
            response.status().as_u16(),
            hex(&body)
        ),
    )?;
    Ok(response)
}

type GatewayResponse = (Response<Full<hyper::body::Bytes>>, String, Vec<u8>);

fn ready_listener(
    lines: &str,
    pid: u32,
    owns: impl FnOnce(u32, u16) -> std::io::Result<bool>,
) -> std::io::Result<Option<std::net::SocketAddr>> {
    let Some(address) = lines.lines().find_map(|line| {
        if !line.contains(r#""message":"listening""#) {
            return None;
        }
        let (_, fields) = line.split_once(r#""addr":""#)?;
        let (reported, _) = fields.split_once('"')?;
        let address = reported.parse::<std::net::SocketAddr>().ok()?;
        (address.ip() == std::net::Ipv4Addr::LOCALHOST && address.port() != 0).then_some(address)
    }) else {
        return Ok(None);
    };
    Ok(owns(pid, address.port())?.then_some(address))
}

fn listener_ownership_controls() {
    let report = |address: &str| {
        format!(r#"{{"level":"INFO","fields":{{"message":"listening","addr":"{address}"}}}}"#)
    };
    let checked = std::cell::Cell::new(None);
    let owns = |pid, port| {
        checked.set(Some((pid, port)));
        Ok(true)
    };
    for port in [12345, 23456] {
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let log = report(&address.to_string());
        let ready = ready_listener(&log, 37, owns).unwrap();
        assert_eq!(
            (ready, checked.take()),
            (Some(address), Some((37, port))),
            "shipping readiness must learn and check the reported address {address}"
        );
    }

    let log = report("127.0.0.1:12345");
    let foreign = ready_listener(&log, 37, |pid, port| {
        checked.set(Some((pid, port)));
        Ok(false)
    })
    .unwrap();
    assert_eq!(
        (foreign, checked.take()),
        (None, Some((37, 12345))),
        "foreign listener must not supply shipping readiness"
    );
    println!("REFUSED foreign listener");

    let denied = ready_listener(&log, 37, |pid, port| {
        checked.set(Some((pid, port)));
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "listener ownership probe denied",
        ))
    })
    .unwrap_err();
    assert_eq!(
        (denied.kind(), denied.to_string().as_str(), checked.take()),
        (
            std::io::ErrorKind::PermissionDenied,
            "listener ownership probe denied",
            Some((37, 12345))
        )
    );
    println!("REFUSED {denied}");

    for (log, refusal) in [
        (String::new(), "missing listening line"),
        (
            r#"{"level":"INFO","fields":{"message":"starting","addr":"127.0.0.1:12345"}}"#.into(),
            "address in a message other than listening",
        ),
        (report("127.0.0.1:"), "unparseable listening address"),
        (report("127.0.0.1:0"), "zero listening port"),
        (report("127.0.0.2:12345"), "unexpected listening IP"),
    ] {
        let ready = ready_listener(&log, 37, owns).unwrap();
        assert_eq!((ready, checked.take()), (None, None), "{refusal}: {log:?}");
        println!("REFUSED {refusal}");
    }
}

pub(crate) fn gateway_response(raw: &[u8]) -> std::io::Result<GatewayResponse> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|n| n + 4)
        .ok_or_else(|| std::io::Error::other("missing HTTP response header"))?;
    let head = std::str::from_utf8(
        raw.get(..end)
            .ok_or_else(|| std::io::Error::other("truncated header"))?,
    )
    .map_err(std::io::Error::other)?;
    let mut lines = head.lines();
    let code = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| std::io::Error::other("missing HTTP status"))?;
    let mut response = Response::builder().status(code);
    let mut token = "-";
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| std::io::Error::other("malformed HTTP header"))?;
        if name.eq_ignore_ascii_case("granary-error") {
            token = value.trim();
        }
        // The gateway's Full bodies have a known length. Refuse another
        // encoding rather than misreporting framed chunks as response bytes.
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(std::io::Error::other(
                "unexpected streaming gateway response",
            ));
        }
        if !name.eq_ignore_ascii_case("connection") {
            response = response.header(name, value.trim());
        }
    }
    let body = raw
        .get(end..)
        .ok_or_else(|| std::io::Error::other("truncated body"))?
        .to_vec();
    let response = response
        .body(Full::new(body.clone().into()))
        .map_err(std::io::Error::other)?;
    Ok((response, token.to_owned(), body))
}

#[test]
fn gateway_response_controls() {
    listener_ownership_controls();
    super::replay_snapshot_controls();
    let (response, token, body) = gateway_response(
        b"HTTP/1.1 202 Accepted\r\ncontent-length: 3\r\ngranary-error: unavailable\r\n\r\nabc",
    )
    .unwrap();
    assert_eq!(
        (response.status().as_u16(), token, body),
        (202, "unavailable".into(), b"abc".to_vec())
    );
    assert!(
        gateway_response(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n")
            .is_err(),
        "streaming framing masqueraded as gateway body bytes"
    );
    for invalid in [
        b"missing header".as_slice(),
        b"HTTP/1.1 nope Bad\r\n\r\n",
        b"HTTP/1.1 200 OK\r\ninvalid\r\n\r\n",
    ] {
        assert!(
            gateway_response(invalid).is_err(),
            "malformed response accepted: {invalid:?}"
        );
    }
    observe("tails::shipping::gateway_response_controls", &[]);
}

#[expect(
    clippy::too_many_lines,
    reason = "one control composes the shipping binary, enrolled TLS tap and real backend"
)]
pub(super) async fn run() {
    let mut fx = Composition::new(false).await;
    // Initialise through the real host API, then cleanly transfer that empty
    // authority to the binary. No fabricated record or marker is installed.
    fx.stop().await;
    assert!(fx.records().is_empty());
    let private = fx.client.scratch.0.join("private");
    let binary = super::super::composition::shipping_server();
    let mut command = Command::new(binary);
    command.env_clear();
    for (key, value) in fx.command.get_envs() {
        if !key.as_encoded_bytes().starts_with(b"GRANARY_TEST_")
            && !key.as_encoded_bytes().starts_with(b"GRANARY_COMPOSITION_")
            && let Some(value) = value
        {
            command.env(key, value);
        }
    }
    command
        .env("GRANARY_LISTEN", "127.0.0.1:0")
        .env("GRANARY_TLS_CERT", private.join("server.pem"))
        .env("GRANARY_TLS_KEY", private.join("server.key"));
    let log = fx.client.scratch.0.join("shipping-host.log");
    let mut server = Process::spawn_logged(&mut command, &log);
    let pid = server.id();
    let ready = super::super::support::wait_report(&mut server, WAIT, async {
        loop {
            let lines = std::fs::read_to_string(&log)
                .map_err(|error| format!("cannot read shipping server log: {error}"))?;
            if let Some(address) =
                ready_listener(&lines, pid, super::super::composition::owns_listener)
                    .map_err(|error| error.to_string())?
            {
                return Ok(address);
            }
            sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await;
    let Ok(address) = ready else {
        server.assert_or_kill(false, &format!("shipping server readiness: {ready:?}"));
        return;
    };
    let certs = |name| {
        rustls_pki_types::CertificateDer::pem_file_iter(private.join(name))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs("ca.pem") {
        roots.add(cert).unwrap();
    }
    let mut client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            certs("client.pem"),
            rustls_pki_types::PrivateKeyDer::from_pem_file(private.join("client.key")).unwrap(),
        )
        .unwrap();
    client.alpn_protocols = vec![b"http/1.1".to_vec()];
    let client = Arc::new(client);
    let tls = granary_net::tls::server_tls_config(
        certs("server.pem"),
        rustls_pki_types::PrivateKeyDer::from_pem_file(private.join("server.key")).unwrap(),
        granary_net::tls::ClientAuth::Enrolled {
            ca: certs("ca.pem"),
            clock: Arc::new(super::super::composition::WallClock),
        },
    )
    .unwrap();
    let listener = super::super::composition::host_listener(fx.addr).unwrap();
    let dir = fx.client.scratch.0.clone();
    let service = hyper::service::service_fn(move |request| {
        forward(request, address, client.clone(), dir.clone())
    });
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let tap = tokio::spawn(granary_net::accept::serve(
        listener,
        Arc::new(tls),
        service,
        stopping,
        granary_net::accept::AcceptConfig::default(),
    ));
    let mut command = fx.client.command(false);
    let rendezvous = Rendezvous::arm(&mut command, &fx.client.scratch.0, "dispatch", "after", 1);
    let mut process = Process::spawn(&mut command);
    let reached = rendezvous.reached(&mut process).await;
    process.assert_or_kill(
        reached.is_ok(),
        &format!("shipping gateway answer: {reached:?}"),
    );
    let (_, mut stream) = reached.unwrap();
    let old = fx.client.record().unwrap();
    let capture = fx.proxy.captured().await;
    process.assert_or_kill(
        (capture.seq, capture.id, fx.proxy.body(&capture))
            == (
                old.candidates[0].seq,
                old.candidates[0].id,
                old.candidates[0].root.clone(),
            ),
        "shipping authority's captured PUT differs from A",
    );
    let released = fx.proxy.release(&capture).await;
    process.assert_or_kill(
        released == Ok(200),
        &format!("shipping A release: {released:?}"),
    );
    stream.write_all(b"continue\n").await.unwrap();
    let output = process.output().await;
    let diagnostic = diagnostics(&output);
    report(&output, 0, &old, "landed");
    let mut order: Vec<_> = fx
        .preparation_requests(&old.frozen.initial_root)
        .await
        .into_iter()
        .map(|path| (Preparation, path))
        .collect();
    order.extend([
        (Recovery, format!("GET {ROOT_PATH}")),
        (Preparation, "GET /volume/alpha/max-seq".into()),
        (Publication, "POST /volume/alpha/publish".into()),
        (Recovery, format!("GET {ROOT_PATH}")),
        (Preparation, "GET /volume/alpha/max-seq".into()),
        (Hint, "PUT /volume/alpha/hint".into()),
    ]);
    assert_eq!(
        oracle::request_trace(&fx.responses()),
        Ok(((1, 10, 2, 1), order)),
        "shipping gateway's exact client request trace\n{}\n{diagnostic}",
        fx.responses()
    );
    let c = &old.candidates[0];
    assert!(
        oracle::trace_and_occupancy(
            &fx.notes(),
            &fx.responses(),
            &exact(&old),
            &[&accepted(&old)],
            &fx.roots().await,
            c.seq,
            &c.root
        ),
        "shipping gateway publishes exactly once and lands A\n{diagnostic}"
    );
    let before = fx.responses();
    let human = Process::spawn(&mut fx.client.shipping_command(true, false))
        .output()
        .await;
    let text = assert_exit(&human, 0);
    assert!(
        text.contains(&format!("seq=1 id={}", c.id)) && text.contains("route=authority"),
        "shipping CLI human winner output\n{}",
        diagnostics(&human)
    );
    assert_eq!(
        oracle::request_trace(fx.responses().strip_prefix(&before).unwrap()),
        Ok(((0, 0, 0, 1), vec![(Hint, "PUT /volume/alpha/hint".into())])),
        "completed human invocation only repairs its hint\n{}",
        diagnostics(&human)
    );
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &server.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    assert_exit(&server.host_output().await, 0);
    assert_eq!(
        (
            fx.records().len(),
            fx.proxy.finished().len(),
            fx.proxy.pending()
        ),
        (3, 1, 0),
        "shipping server's one decision/attestation/landing and one creation\n{diagnostic}"
    );
    stop.send(true).unwrap();
    assert_eq!(
        timeout(super::super::support::HOST_DRAIN, tap)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        granary_net::accept::ShutdownOutcome::Drained
    );
}
