// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process custody and identity checks for authority restart schedules.

use super::super::{Fixture, roomy};
use super::*;
use crate::authority::crash::{self, Plan, Site};
use granary_core::{binstore::BinStore, rootstore::RootStore};
use http_body_util::{BodyExt as _, Full};
use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
    service::Service,
};
use std::{
    convert::Infallible,
    future::Future,
    io,
    net::SocketAddr,
    path::Path,
    pin::Pin,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

const CHILD: &str = "GRANARY_SERVER_CRASH_CHILD";
const LIVE_MOUNT_STOP: &str = "GRANARY_SERVER_CRASH_LIVE_MOUNT_STOP";
const PARKED: &str = "GRANARY_SERVER_CRASH_PARKED";
const PARK_WAIT: Duration = Duration::from_mins(2);
const CHILD_TEST: &str = "conformance_http::intents::convergence::server_crash::authority_child";
const WAIT: Duration = Duration::from_secs(10);
const CHILD_STOP_WAIT: Duration = Duration::from_secs(20);
const CLEAN_STOP_WAIT: Duration = Duration::from_secs(25);
const LIVE_MOUNT_DRAIN: Duration = Duration::from_secs(1);
const POLL: Duration = Duration::from_millis(10);

pub(in crate::conformance_http::intents) struct ObservedService<R> {
    service: crate::GrainService<R>,
    tap: Option<PathBuf>,
    next: Arc<std::sync::Mutex<u64>>,
}
impl<R> ObservedService<R> {
    pub(in crate::conformance_http::intents) fn new(
        service: crate::GrainService<R>,
        tap: Option<PathBuf>,
    ) -> Self {
        Self {
            service,
            tap,
            next: Arc::default(),
        }
    }
}
impl<R> Clone for ObservedService<R> {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
            tap: self.tap.clone(),
            next: self.next.clone(),
        }
    }
}
impl<R: RootStore + BinStore + 'static> Service<Request<Incoming>> for ObservedService<R> {
    type Response = Response<Full<Bytes>>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn call(&self, request: Request<Incoming>) -> Self::Future {
        let Some(tap) = self
            .tap
            .as_ref()
            .filter(|_| request.method() == hyper::Method::POST)
        else {
            let answer = self.service.call(request);
            return Box::pin(
                async move { answer.await.map_err(|never: Infallible| match never {}) },
            );
        };
        let path = {
            let mut next = self
                .next
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let path = tap.join(format!("packet-{next}"));
            std::fs::write(path.with_extension("started"), []).unwrap();
            *next = next.saturating_add(1);
            path
        };
        let service = self.service.clone();
        let tap = tap.clone();
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            std::fs::write(path.with_extension("method"), parts.method.as_str()).unwrap();
            std::fs::write(
                path.with_extension("path"),
                parts
                    .uri
                    .path_and_query()
                    .map_or(parts.uri.path(), |value| value.as_str()),
            )
            .unwrap();
            let mut request_error = None;
            let bytes = match body.collect().await {
                Ok(body) => body.to_bytes(),
                Err(error) => {
                    request_error = Some(format!("cannot collect request body: {error}"));
                    Bytes::new()
                }
            };
            std::fs::write(path.with_extension("body"), &bytes).unwrap();
            for (extension, name) in [
                ("content-type", "content-type"),
                ("epoch", "granary-epoch"),
                ("operation", "granary-operation"),
            ] {
                let values: Vec<_> = parts.headers.get_all(name).iter().collect();
                if values.len() > 1 {
                    request_error = Some(format!("duplicate observed request header {name}"));
                }
                if let Some(value) = values.first() {
                    std::fs::write(path.with_extension(extension), value.as_bytes()).unwrap();
                }
            }
            if let Some(error) = &request_error {
                std::fs::write(path.with_extension("request-error"), error).unwrap();
            }
            std::fs::write(path.with_extension("request"), []).unwrap();
            if let Some(error) = request_error {
                let mut response = Response::new(Full::new(Bytes::from(error)));
                *response.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                return Ok(response);
            }
            let ownership = if parts.uri.path().ends_with("/intent/ownership") {
                granary_core::intent::decode_ownership(&bytes)
                    .ok()
                    .map(|request| request.mode)
            } else {
                None
            };
            if matches!(
                ownership,
                Some(granary_core::intent::OwnershipMode::Takeover { .. })
            ) && take_disk_loss_marker(&tap, "hold-takeover")
            {
                hold_takeover(&tap).await;
            }
            let response = service
                .request_for_test(Request::from_parts(parts, Full::new(bytes)))
                .await;
            let lose_reply = lose_ownership_reply(&tap, ownership);
            record_response(&path, response, lose_reply).await
        })
    }
}

async fn record_response(
    path: &Path,
    response: Response<Full<Bytes>>,
    lose_reply: bool,
) -> io::Result<Response<Full<Bytes>>> {
    let (parts, body) = response.into_parts();
    let bytes = match body.collect().await {
        Ok(body) => body.to_bytes(),
        Err(never) => match never {},
    };
    std::fs::write(
        path.with_extension("status"),
        parts.status.as_u16().to_string(),
    )
    .unwrap();
    let errors: Vec<_> = parts.headers.get_all("granary-error").iter().collect();
    if errors.len() > 1 {
        std::fs::write(
            path.with_extension("response-error"),
            "duplicate observed Granary-Error",
        )
        .unwrap();
    }
    if let Some(error) = errors.first() {
        std::fs::write(path.with_extension("error"), error.as_bytes()).unwrap();
    }
    std::fs::write(path.with_extension("answer"), &bytes).unwrap();
    if lose_reply {
        assert_eq!(parts.status, hyper::StatusCode::OK);
        std::fs::write(path.with_extension("reply-lost"), []).unwrap();
    }
    std::fs::write(path.with_extension("response"), []).unwrap();
    if lose_reply {
        return Err(io::Error::other(
            "disk-loss fixture dropped recorded ownership reply",
        ));
    }
    Ok(Response::from_parts(parts, Full::new(bytes)))
}

async fn hold_takeover(tap: &Path) {
    std::fs::write(tap.join("takeover-held"), []).unwrap();
    let started = Instant::now();
    while !tap.join("send-takeover").exists() {
        assert!(started.elapsed() < WAIT, "held takeover was never released");
        tokio::time::sleep(POLL).await;
    }
}

fn lose_ownership_reply(
    tap: &Path,
    ownership: Option<granary_core::intent::OwnershipMode>,
) -> bool {
    use granary_core::intent::OwnershipMode;
    match ownership {
        Some(OwnershipMode::Acquire { .. }) => take_disk_loss_marker(tap, "lose-acquire"),
        Some(OwnershipMode::Takeover { .. }) => take_disk_loss_marker(tap, "lose-takeover"),
        None => false,
    }
}

fn take_disk_loss_marker(tap: &Path, name: &str) -> bool {
    match std::fs::remove_file(tap.join(name)) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => panic!("cannot consume disk-loss marker {name}: {error}"),
    }
}

fn fresh_directory(path: &Path) -> Result<(), String> {
    std::fs::create_dir(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            "authority child refuses stale witness directory".to_owned()
        } else {
            format!("authority child cannot create witness directory: {error}")
        }
    })
}

fn read_witness(path: &Path) -> Result<Option<String>, &'static str> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("authority child cannot read witness file"),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ChildCommand {
    Stop(ChildStop),
    Initialise,
    Maintain,
    FailSync,
    Held {
        site: String,
        occurrence: u64,
        binding: String,
    },
    Fenced,
    Arm {
        site: Site,
        hold: bool,
        binding: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChildStop {
    Drained,
    LiveMount,
}

fn child_command(text: &str) -> Result<ChildCommand, &'static str> {
    let fields: Vec<_> = text.split(' ').collect();
    let command = match fields.as_slice() {
        ["stop"] => ChildCommand::Stop(ChildStop::Drained),
        ["stop-live"] => ChildCommand::Stop(ChildStop::LiveMount),
        ["initialise"] => ChildCommand::Initialise,
        ["maintain"] => ChildCommand::Maintain,
        ["fail-sync"] => ChildCommand::FailSync,
        ["fenced"] => ChildCommand::Fenced,
        ["held", site, occurrence, binding]
            if !site.is_empty()
                && !binding.is_empty()
                && occurrence.parse::<u64>().is_ok_and(|n| n > 0) =>
        {
            ChildCommand::Held {
                site: (*site).to_owned(),
                occurrence: occurrence
                    .parse()
                    .map_err(|_| "authority child refuses malformed command")?,
                binding: (*binding).to_owned(),
            }
        }
        ["arm", site, hold, binding]
            if !binding.is_empty()
                && Site::parse(site).is_some()
                && matches!(*hold, "true" | "false") =>
        {
            ChildCommand::Arm {
                site: Site::parse(site).ok_or("authority child refuses malformed command")?,
                hold: hold
                    .parse()
                    .map_err(|_| "authority child refuses malformed command")?,
                binding: (*binding).to_owned(),
            }
        }
        _ => return Err("authority child refuses malformed command"),
    };
    Ok(command)
}

fn fence_witness(
    fence: Option<&crate::authority::Fence>,
    volume: &granary_core::root::VolumeName,
    failure_fired: bool,
    calls: &[&str],
) -> Result<(), &'static str> {
    let exact_fence = fence.is_some_and(|fence| {
        fence.call == crate::authority::LogCall::Append
            && fence.volume.as_ref() == Some(volume)
            && fence.cause
                == crate::authority::FenceCause::Failed(
                    granary_core::decisionlog::LogIoError::SyncFailed,
                )
    });
    if exact_fence && failure_fired && calls.contains(&"file-sync") {
        Ok(())
    } else {
        Err("authority child refuses incomplete fence witness")
    }
}

pub(super) fn fenced_response(status: u16, error: Option<&[u8]>) -> Result<(), &'static str> {
    if (status, error) == (503, Some(b"fenced".as_slice())) {
        Ok(())
    } else {
        Err("authority child refuses non-fenced response witness")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PacketWitness<'a> {
    pub(super) method: &'a [u8],
    pub(super) target: &'a [u8],
    pub(super) content_type: Option<&'a [u8]>,
    pub(super) epoch: Option<&'a [u8]>,
    pub(super) operation: Option<&'a [u8]>,
    pub(super) body: &'a [u8],
}

#[derive(Debug)]
pub(super) struct ObservedPacket {
    pub(super) index: u64,
    pub(super) path: PathBuf,
    pub(super) method: Vec<u8>,
    pub(super) target: Vec<u8>,
    pub(super) content_type: Option<Vec<u8>>,
    pub(super) epoch: Option<Vec<u8>>,
    pub(super) operation: Option<Vec<u8>>,
    pub(super) body: Vec<u8>,
}

pub(super) fn optional_packet_file(path: &Path, extension: &str) -> Option<Vec<u8>> {
    match std::fs::read(path.with_extension(extension)) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => panic!(
            "cannot read observed packet {}: {error}",
            path.with_extension(extension).display()
        ),
    }
}

fn packet_file(path: &Path, extension: &str) -> Result<Vec<u8>, String> {
    let file = path.with_extension(extension);
    std::fs::read(&file)
        .map_err(|error| format!("cannot read observed packet {}: {error}", file.display()))
}

fn read_observed_packets(root: &Path) -> Result<Vec<ObservedPacket>, String> {
    let entries = std::fs::read_dir(root)
        .map_err(|error| format!("cannot read observed packet directory: {error}"))?;
    let mut packets = Vec::new();
    for entry in entries {
        let request = entry
            .map_err(|error| format!("cannot read observed packet entry: {error}"))?
            .path();
        if request
            .extension()
            .is_none_or(|extension| extension != "request")
        {
            continue;
        }
        let path = request.with_extension("");
        if let Some(error) = optional_packet_file(&path, "request-error") {
            return Err(format!(
                "observed packet {} failed capture: {}",
                path.display(),
                String::from_utf8_lossy(&error)
            ));
        }
        let index = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix("packet-"))
            .and_then(|index| index.parse().ok())
            .ok_or_else(|| format!("malformed observed packet name: {}", path.display()))?;
        packets.push(ObservedPacket {
            index,
            method: packet_file(&path, "method")?,
            target: packet_file(&path, "path")?,
            content_type: optional_packet_file(&path, "content-type"),
            epoch: optional_packet_file(&path, "epoch"),
            operation: optional_packet_file(&path, "operation"),
            body: packet_file(&path, "body")?,
            path,
        });
    }
    packets.sort_by_key(|packet| packet.index);
    Ok(packets)
}

pub(super) fn observed_packets(root: &Path) -> Vec<ObservedPacket> {
    read_observed_packets(root).unwrap_or_else(|error| panic!("{error}"))
}

fn completed_packet_cursor(started: &[u64], completed: &[u64]) -> Result<u64, &'static str> {
    if !started.iter().all(|index| completed.contains(index)) {
        return Err("authority child refuses incomplete observed packet boundary");
    }
    Ok(started
        .iter()
        .max()
        .map_or(0, |index| index.saturating_add(1)))
}

pub(super) fn observed_packet_cursor(root: &Path) -> u64 {
    let started = Instant::now();
    loop {
        let indices: Vec<u64> = std::fs::read_dir(root)
            .unwrap_or_else(|error| panic!("cannot read observed packet directory: {error}"))
            .map(|entry| {
                entry
                    .unwrap_or_else(|error| panic!("cannot read observed packet entry: {error}"))
                    .path()
            })
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "started")
            })
            .map(|path| {
                path.with_extension("")
                    .file_name()
                    .and_then(|name| name.to_str())
                    .and_then(|name| name.strip_prefix("packet-"))
                    .and_then(|index| index.parse().ok())
                    .unwrap_or_else(|| panic!("malformed observed packet name: {}", path.display()))
            })
            .collect();
        let packets = observed_packets(root);
        let completed: Vec<_> = packets.iter().map(|packet| packet.index).collect();
        match completed_packet_cursor(&indices, &completed) {
            Ok(cursor) => return cursor,
            Err(error) => assert!(started.elapsed() < WAIT, "{error}"),
        }
        std::thread::sleep(POLL);
    }
}

pub(super) fn observed_response(path: &Path) -> Result<(), &'static str> {
    if !path.with_extension("response").exists() {
        return Err("authority child refuses incomplete observed response");
    }
    if path.with_extension("response-error").exists() {
        return Err("authority child refuses malformed observed response");
    }
    Ok(())
}

pub(super) fn observed_boundary(root: &Path, file: &str) -> u64 {
    std::fs::read_to_string(root.join(format!("{file}.cursor")))
        .unwrap()
        .parse()
        .unwrap()
}

pub(super) fn packet_witness(
    actual: &PacketWitness<'_>,
    expected: &PacketWitness<'_>,
) -> Result<(), &'static str> {
    if actual == expected {
        Ok(())
    } else {
        Err("authority child refuses changed operation packet")
    }
}

#[test]
fn server_crash_witness_read_valid_and_malformed_controls() {
    let root = crate::authority::tests::intents::scratch();
    let path = root.join("ready");
    assert_eq!(read_witness(&path), Ok(None));
    std::fs::write(&path, "123 42 ready 1 endpoint").unwrap();
    assert_eq!(
        read_witness(&path),
        Ok(Some("123 42 ready 1 endpoint".to_owned()))
    );
    assert_eq!(
        read_witness(&root),
        Err("authority child cannot read witness file")
    );
    let cases = 1;
    assert!(cases > 0);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn server_crash_command_valid_and_malformed_controls() {
    for valid in [
        "stop",
        "stop-live",
        "initialise",
        "maintain",
        "fail-sync",
        "fenced",
        "held sync.commit/before_submit 2 operation",
        "arm MarkSynced true operation",
    ] {
        assert!(
            child_command(valid).is_ok(),
            "valid command refused: {valid}"
        );
    }
    let mut cases = 0;
    for malformed in [
        "",
        "stop now",
        "stop-live now",
        "initialise now",
        "maintain now",
        "held sync.commit/before_submit 0 operation",
        "held sync.commit/before_submit two operation",
        "held  1 operation",
        "arm Unknown true operation",
        "arm MarkSynced maybe operation",
        "arm MarkSynced true ",
    ] {
        assert_eq!(
            child_command(malformed),
            Err("authority child refuses malformed command"),
            "malformed command accepted: {malformed:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 11);
}

#[test]
fn server_crash_fence_valid_and_malformed_controls() {
    let fixture = Fixture::new(None);
    let volume = fixture.volume();
    let valid = crate::authority::Fence {
        call: crate::authority::LogCall::Append,
        volume: Some(volume.clone()),
        cause: crate::authority::FenceCause::Failed(
            granary_core::decisionlog::LogIoError::SyncFailed,
        ),
    };
    assert_eq!(
        fence_witness(Some(&valid), &volume, true, &["file-sync"]),
        Ok(())
    );
    let wrong_call = crate::authority::Fence {
        call: crate::authority::LogCall::IntentStore,
        ..valid.clone()
    };
    let wrong_cause = crate::authority::Fence {
        cause: crate::authority::FenceCause::Dropped,
        ..valid.clone()
    };
    let wrong_volume = crate::authority::Fence {
        volume: None,
        ..valid.clone()
    };
    let mut cases = 0;
    for observed in [
        fence_witness(None, &volume, true, &["file-sync"]),
        fence_witness(Some(&wrong_call), &volume, true, &["file-sync"]),
        fence_witness(Some(&wrong_cause), &volume, true, &["file-sync"]),
        fence_witness(Some(&wrong_volume), &volume, true, &["file-sync"]),
        fence_witness(Some(&valid), &volume, false, &["file-sync"]),
        fence_witness(Some(&valid), &volume, true, &[]),
    ] {
        assert_eq!(
            observed,
            Err("authority child refuses incomplete fence witness")
        );
        cases += 1;
    }
    assert_eq!(cases, 6);
}

#[test]
fn server_crash_fenced_response_valid_and_malformed_controls() {
    assert_eq!(fenced_response(503, Some(b"fenced")), Ok(()));
    let mut cases = 0;
    for observed in [
        fenced_response(200, Some(b"fenced")),
        fenced_response(503, Some(b"unavailable")),
        fenced_response(503, None),
    ] {
        assert_eq!(
            observed,
            Err("authority child refuses non-fenced response witness")
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

fn observed_packet_file_controls() -> usize {
    let root = crate::authority::tests::intents::scratch();
    let path = root.join("packet-0");
    std::fs::write(path.with_extension("body"), b"root").unwrap();
    std::fs::write(path.with_extension("method"), b"POST").unwrap();
    std::fs::write(path.with_extension("path"), b"/volume/test/publish").unwrap();
    assert!(
        observed_packets(&root).is_empty(),
        "packet without its completion marker was visible"
    );
    assert_eq!(observed_packet_cursor(&root), 0);
    std::fs::write(path.with_extension("started"), []).unwrap();
    std::fs::write(path.with_extension("request"), []).unwrap();
    let complete = observed_packets(&root);
    let [packet] = complete.as_slice() else {
        panic!("completed packet was not unique: {complete:?}");
    };
    assert_eq!(
        (
            packet.index,
            packet.path.as_path(),
            packet.method.as_slice(),
            packet.target.as_slice(),
            packet.content_type.as_deref(),
            packet.epoch.as_deref(),
            packet.operation.as_deref(),
            packet.body.as_slice(),
        ),
        (
            0,
            path.as_path(),
            b"POST".as_slice(),
            b"/volume/test/publish".as_slice(),
            None,
            None,
            None,
            b"root".as_slice(),
        )
    );
    assert_eq!(observed_packet_cursor(&root), 1);
    assert_eq!(completed_packet_cursor(&[0, 1], &[0, 1]), Ok(2));
    assert_eq!(
        completed_packet_cursor(&[0, 1], &[1]),
        Err("authority child refuses incomplete observed packet boundary")
    );
    std::fs::write(root.join("reached.cursor"), "1").unwrap();
    assert_eq!(observed_boundary(&root, "reached"), 1);
    std::fs::write(root.join("packet-1.request"), []).unwrap();
    let missing = root.join("packet-1.method");
    let error = std::fs::read(&missing).unwrap_err();
    let expected = format!("cannot read observed packet {}: {error}", missing.display());
    let refusal = match read_observed_packets(&root) {
        Err(error) => error,
        Ok(packets) => panic!("completed packet was accepted: {packets:?}"),
    };
    assert_eq!(refusal, expected, "completed packet refusal");
    std::fs::remove_file(root.join("packet-1.request")).unwrap();
    std::fs::write(root.join("packet-2.request-error"), "duplicate header").unwrap();
    std::fs::write(root.join("packet-2.request"), []).unwrap();
    let refusal = match read_observed_packets(&root) {
        Err(error) => error,
        Ok(packets) => panic!("failed packet capture was accepted: {packets:?}"),
    };
    assert_eq!(
        refusal,
        format!(
            "observed packet {} failed capture: duplicate header",
            root.join("packet-2").display()
        )
    );
    std::fs::remove_dir_all(root).unwrap();
    3
}

#[test]
fn server_crash_packet_valid_and_malformed_controls() {
    let valid = PacketWitness {
        method: b"POST",
        target: b"/volume/test/publish",
        content_type: Some(b"application/vnd.granary.root.v1"),
        epoch: Some(b"0011"),
        operation: Some(b"2233"),
        body: b"root",
    };
    assert_eq!(packet_witness(&valid, &valid), Ok(()));
    let malformed = [
        PacketWitness {
            method: b"PUT",
            ..valid
        },
        PacketWitness {
            target: b"/volume/other/publish",
            ..valid
        },
        PacketWitness {
            content_type: None,
            ..valid
        },
        PacketWitness {
            epoch: Some(b"0012"),
            ..valid
        },
        PacketWitness {
            operation: Some(b"2244"),
            ..valid
        },
        PacketWitness {
            body: b"changed",
            ..valid
        },
    ];
    let mut cases = 0;
    for actual in malformed {
        assert_eq!(
            packet_witness(&actual, &valid),
            Err("authority child refuses changed operation packet")
        );
        cases += 1;
    }
    assert_eq!(cases, 6);
    assert_eq!(observed_packet_file_controls(), 3);
}

#[test]
fn server_crash_response_marker_valid_and_malformed_controls() {
    let root = crate::authority::tests::intents::scratch();
    let path = root.join("packet-0");
    std::fs::write(path.with_extension("response"), []).unwrap();
    assert_eq!(observed_response(&path), Ok(()));
    std::fs::remove_file(path.with_extension("response")).unwrap();
    assert_eq!(
        observed_response(&path),
        Err("authority child refuses incomplete observed response")
    );
    std::fs::write(path.with_extension("response"), []).unwrap();
    std::fs::write(path.with_extension("response-error"), "duplicate header").unwrap();
    assert_eq!(
        observed_response(&path),
        Err("authority child refuses malformed observed response")
    );
    let cases = 2;
    assert_eq!(cases, 2);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn server_crash_selects_observed_occurrence() {
    let root = crate::authority::tests::intents::scratch();
    let path = root.join("points");
    crash::install(&path, Plan::List).unwrap();
    crash::hit(Site::IntentBeforeReply, Some("BINDING earlier-1"));
    crash::hit(Site::IntentBeforeReply, Some("BINDING earlier-2"));
    let occurrence = u64::from(crash::arm_next(Site::IntentBeforeReply, false));
    assert_eq!(occurrence, 3);
    let watcher_root = root.clone();
    let watcher = std::thread::spawn(move || {
        wait_for_armed_site(
            &watcher_root,
            42,
            (
                Site::IntentBeforeReply,
                false,
                occurrence,
                "operation".to_owned(),
            ),
        );
    });
    crash::hit(Site::IntentBeforeReply, Some("BINDING operation"));
    watcher.join().unwrap();
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .any(|line| line == "HIT IntentBeforeReply 3")
    );
    assert_eq!(
        read_witness(&root.join("reached")).unwrap(),
        Some(format!(
            "{} 42 IntentBeforeReply 3 operation",
            std::process::id()
        ))
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn server_crash_reached_binding_valid_and_malformed_controls() {
    let root = crate::authority::tests::intents::scratch();
    let path = root.join("points");
    crash::install(&path, Plan::List).unwrap();
    let occurrence = u64::from(crash::arm_next(Site::IntentBeforeReply, false));
    crash::hit(Site::IntentBeforeReply, Some("BINDING actual-operation"));
    let points = std::fs::read_to_string(path).unwrap();
    let marker = format!("HIT IntentBeforeReply {occurrence}");
    let actual = reached_binding(&root, &points, Site::IntentBeforeReply, &marker);
    assert_eq!(
        reached_binding_witness(actual.as_deref(), "actual-operation"),
        Ok(())
    );
    assert_eq!(
        reached_binding_witness(actual.as_deref(), "wrong-operation"),
        Err("authority child refuses changed reached binding")
    );
    let cases = 1;
    assert!(cases > 0);
    std::fs::remove_dir_all(root).unwrap();
}

fn witness(actual: &str, expected: &str) -> Result<(), &'static str> {
    if actual != expected {
        return Err("authority child witness identity mismatch");
    }
    Ok(())
}

#[test]
fn server_crash_witness_valid_and_malformed_controls() {
    let expected = "123 42 IntentBeforeReply 7 operation-digest";
    let mut cases = 0;
    for malformed in [
        "124 42 IntentBeforeReply 7 operation-digest",
        "123 41 IntentBeforeReply 7 operation-digest",
        "123 42 MarkSynced 7 operation-digest",
        "123 42 IntentBeforeReply 6 operation-digest",
        "123 42 IntentBeforeReply 7 other-operation",
        "",
    ] {
        assert_eq!(witness(expected, expected), Ok(()));
        assert_eq!(
            witness(malformed, expected),
            Err("authority child witness identity mismatch"),
            "malformed witness accepted: {malformed:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 6);
}

#[test]
fn server_crash_stale_witness_valid_and_malformed_controls() {
    let root = crate::authority::tests::intents::scratch();
    let path = root.join("boot-42");
    assert!(fresh_directory(&path).is_ok());
    std::fs::write(path.join("ready"), "123 42 ready 1 endpoint").unwrap();
    assert_eq!(
        fresh_directory(&path),
        Err("authority child refuses stale witness directory".to_owned())
    );
    let cases = 1;
    assert!(cases > 0);
    std::fs::remove_dir_all(root).unwrap();
}

pub(super) struct ServerChild {
    child: Child,
    pub(super) root: PathBuf,
    boot: u8,
    command: u64,
}
impl ServerChild {
    pub(super) fn start(
        fixture: &Fixture,
        prefix: &str,
        addr: SocketAddr,
        boot: u8,
        live_mount_stop: bool,
    ) -> Self {
        let mut process = Self::spawn(fixture, prefix, addr, boot, live_mount_stop, false);
        process.reached("ready", "ready", 1, &addr.to_string());
        process
    }
    /// Execute an authority child that opens the authority only at
    /// [`Self::release`]. Exec closes every descriptor the child inherits, and
    /// on Linux closing one on a FUSE file waits for that file's in-flight
    /// fsync, so a parent spawns here before it opens a file on its mount.
    pub(super) fn parked(fixture: &Fixture, prefix: &str, addr: SocketAddr, boot: u8) -> Self {
        Self::spawn(fixture, prefix, addr, boot, false, true)
    }
    /// Let a [`Self::parked`] child open the authority, and wait until it serves.
    pub(super) fn release(mut self, addr: SocketAddr) -> Self {
        std::fs::write(self.root.join("go"), b"").unwrap();
        self.reached("ready", "ready", 1, &addr.to_string());
        self
    }
    fn spawn(
        fixture: &Fixture,
        prefix: &str,
        addr: SocketAddr,
        boot: u8,
        live_mount_stop: bool,
        parked: bool,
    ) -> Self {
        let root = fixture.dir.join(format!("boot-{boot}"));
        fresh_directory(&root).expect("authority child refuses stale witness directory");
        let temporary = root.join("tmp");
        std::fs::create_dir(&temporary).unwrap();
        std::fs::write(root.join("config"), format!("{addr}\n{prefix}")).unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                CHILD_TEST,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, &root)
            .env(LIVE_MOUNT_STOP, live_mount_stop.to_string())
            .env(PARKED, parked.to_string())
            .env("TMPDIR", &temporary)
            .current_dir(&root)
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(root.join("stdout")).unwrap())
            .stderr(std::fs::File::create(root.join("stderr")).unwrap())
            .spawn()
            .unwrap();
        Self {
            child,
            root,
            boot,
            command: 0,
        }
    }
    fn diagnostics(&self) -> String {
        format!(
            "stdout: {}\nstderr: {}",
            std::fs::read_to_string(self.root.join("stdout")).unwrap(),
            std::fs::read_to_string(self.root.join("stderr")).unwrap()
        )
    }
    pub(super) fn reached(&mut self, file: &str, site: &str, occurrence: u64, binding: &str) {
        let started = Instant::now();
        loop {
            match read_witness(&self.root.join(file)) {
                Ok(Some(actual)) => {
                    let expected = format!(
                        "{} {} {site} {occurrence} {binding}",
                        self.child.id(),
                        self.boot
                    );
                    assert_eq!(
                        witness(&actual, &expected),
                        Ok(()),
                        "actual: {actual:?}; expected: {expected:?}"
                    );
                    assert!(
                        self.child.try_wait().unwrap().is_none(),
                        "child exited at witness: {}",
                        self.diagnostics()
                    );
                    return;
                }
                Ok(None) => (),
                Err(error) => panic!("{error}: {}", self.root.join(file).display()),
            }
            assert!(
                self.child.try_wait().unwrap().is_none() && started.elapsed() < WAIT,
                "authority witness {file} missing: {}",
                self.diagnostics()
            );
            std::thread::sleep(POLL);
        }
    }
    pub(super) fn send(&mut self, text: &str) -> String {
        self.command += 1;
        let name = format!("command-{}", self.command);
        std::fs::write(self.root.join("command.next"), text).unwrap();
        std::fs::rename(self.root.join("command.next"), self.root.join(&name)).unwrap();
        name
    }
    pub(super) fn arm(&mut self, site: Site, hold: bool, binding: &str) -> u64 {
        let name = self.send(&format!("arm {} {hold} {binding}", site.name()));
        let started = Instant::now();
        let reply = self.root.join(format!("{name}.armed"));
        while !reply.exists() {
            assert!(
                started.elapsed() < WAIT && self.child.try_wait().unwrap().is_none(),
                "authority arm not acknowledged: {}",
                self.diagnostics()
            );
            std::thread::sleep(POLL);
        }
        let k = std::fs::read_to_string(reply).unwrap().parse().unwrap();
        assert!(k > 0);
        k
    }
    fn wait(&mut self, bound: Duration) -> io::Result<Option<ExitStatus>> {
        let started = Instant::now();
        loop {
            let status = self.child.try_wait()?;
            if status.is_some() || started.elapsed() >= bound {
                return Ok(status);
            }
            std::thread::sleep(POLL);
        }
    }
    pub(super) fn stop(&mut self, kill: bool) {
        self.stop_with(kill, "stop");
    }
    #[cfg(target_os = "linux")]
    pub(super) fn stop_mounted(&mut self, kill: bool) {
        self.stop_with(kill, "stop-live");
    }
    fn stop_with(&mut self, kill: bool, command: &str) {
        use std::os::unix::process::ExitStatusExt as _;
        if kill {
            self.child.kill().unwrap();
        } else {
            self.send(command);
        }
        let status = self
            .wait(if kill { WAIT } else { CLEAN_STOP_WAIT })
            .unwrap()
            .unwrap_or_else(|| panic!("authority did not stop: {}", self.diagnostics()));
        assert_eq!(
            (status.success(), status.signal()),
            (!kill, kill.then_some(9)),
            "authority child termination: {}",
            self.diagnostics()
        );
    }
}
impl Drop for ServerChild {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            if self.wait(WAIT).ok().flatten().is_none() {
                write_direct(
                    format!(
                        "{{\"event\":\"integration.server_crash.child_cleanup\",\"pid\":{},\"reaped\":false}}\n",
                        self.child.id()
                    )
                    .as_bytes(),
                );
            }
        }
    }
}

fn publish_witness(root: &Path, boot: u8, file: &str, site: &str, occurrence: u64, binding: &str) {
    let temporary = root.join(format!("{file}.next"));
    std::fs::write(
        &temporary,
        format!(
            "{} {boot} {site} {occurrence} {binding}",
            std::process::id()
        ),
    )
    .unwrap();
    std::fs::rename(temporary, root.join(file)).unwrap();
}

#[test]
fn server_crash_child_custody_kill_clean_and_drop_controls() {
    let fixture = Fixture::new(None);
    let addr = "127.0.0.1:1".parse().unwrap();
    let mut cases = 0;
    for (boot, kill) in [(91, true), (92, false)] {
        let mut child = ServerChild::start(&fixture, "custody-probe", addr, boot, false);
        let k = child.arm(Site::IntentBeforeReply, kill, "probe");
        child.reached("reached", "IntentBeforeReply", k, "probe");
        child.stop(kill);
        cases += 1;
    }
    let child = ServerChild::start(&fixture, "custody-probe", addr, 93, false);
    let pid = nix::unistd::Pid::from_raw(i32::try_from(child.child.id()).unwrap());
    drop(child);
    assert_eq!(
        nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)),
        Err(nix::errno::Errno::ECHILD)
    );
    assert_eq!(cases, 2);
}

async fn custody_probe(root: &Path, boot: u8, addr: SocketAddr) {
    publish_witness(root, boot, "ready", "ready", 1, &addr.to_string());
    let mut command = 1;
    let started = Instant::now();
    loop {
        assert!(started.elapsed() < WAIT, "custody command deadline");
        let name = format!("command-{command}");
        if let Ok(text) = std::fs::read_to_string(root.join(&name)) {
            command += 1;
            match child_command(&text).unwrap_or_else(|error| panic!("{error}: {text:?}")) {
                ChildCommand::Stop(ChildStop::Drained) => return,
                ChildCommand::Arm { .. } => {
                    let armed = root.join(format!("{name}.armed"));
                    let temporary = root.join(format!("{name}.armed.next"));
                    std::fs::write(&temporary, "1").unwrap();
                    std::fs::rename(temporary, armed).unwrap();
                    publish_witness(root, boot, "reached", "IntentBeforeReply", 1, "probe");
                }
                _ => panic!("authority child refuses malformed command: {text:?}"),
            }
        }
        tokio::time::sleep(POLL).await;
    }
}

type ArmedSite = (Site, bool, u64, String);

fn reached_binding(root: &Path, points: &str, site: Site, marker: &str) -> Option<String> {
    if site == Site::IntentBeforeReply {
        let lines: Vec<_> = points.lines().collect();
        let marker = lines.iter().position(|line| *line == marker)?;
        return marker
            .checked_sub(1)
            .and_then(|index| lines.get(index))
            .and_then(|line| line.strip_prefix("BINDING "))
            .map(str::to_owned);
    }
    if site == Site::MarkSynced {
        let packets: Vec<_> = observed_packets(root)
            .into_iter()
            .filter(|packet| packet.target.ends_with(b"/publish"))
            .collect();
        let [packet] = packets.as_slice() else {
            return None;
        };
        return Some(granary_core::hash::GrainId::of(&packet.body).to_string());
    }
    None
}

fn reached_binding_witness(actual: Option<&str>, expected: &str) -> Result<(), &'static str> {
    if actual != Some(expected) {
        return Err("authority child refuses changed reached binding");
    }
    Ok(())
}

fn wait_for_armed_site(root: &Path, boot: u8, armed: ArmedSite) {
    let (site, hold, occurrence, binding) = armed;
    let marker = if hold { "REACHED" } else { "HIT" };
    let expected = format!("{marker} {} {occurrence}", site.name());
    let started = Instant::now();
    loop {
        let points = std::fs::read_to_string(root.join("points")).unwrap();
        if points.lines().any(|line| line == expected) {
            reached_binding_witness(
                reached_binding(root, &points, site, &expected).as_deref(),
                &binding,
            )
            .unwrap_or_else(|error| panic!("{error}"));
            let temporary = root.join("reached.cursor.next");
            std::fs::write(&temporary, observed_packet_cursor(root).to_string()).unwrap();
            std::fs::rename(temporary, root.join("reached.cursor")).unwrap();
            publish_witness(root, boot, "reached", &site.name(), occurrence, &binding);
            return;
        }
        assert!(started.elapsed() < WAIT, "authority site witness deadline");
        std::thread::sleep(POLL);
    }
}

struct AuthorityCommandContext<'a> {
    root: &'a Path,
    boot: u8,
    fixture: &'a Fixture,
    rec: &'a crate::authority::tests::intents::Recording,
    server: &'a super::super::Server,
}
impl AuthorityCommandContext<'_> {
    fn done(&self, name: &str, operation: &str, occurrence: u64, binding: &str) {
        publish_witness(
            self.root,
            self.boot,
            &format!("{name}.done"),
            operation,
            occurrence,
            binding,
        );
    }
    async fn initialise(&self, name: &str) {
        self.server
            .handle
            .initialise(&self.fixture.volume())
            .await
            .unwrap();
        self.done(name, "initialise", 1, self.fixture.volume().as_str());
    }
    async fn maintain(&self, name: &str) {
        self.fixture
            .clock
            .0
            .store(1_000_000, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            self.server
                .handle
                .maintain_intents(&self.fixture.volume(), &self.fixture.enrolled(), 0,)
                .await
                .status()
                .as_u16(),
            200
        );
        self.done(name, "maintain", 1, self.fixture.volume().as_str());
    }
    async fn apply(&self, name: &str, command: ChildCommand) -> Option<ChildStop> {
        match command {
            ChildCommand::Stop(stop) => return Some(stop),
            ChildCommand::Initialise => self.initialise(name).await,
            ChildCommand::Maintain => self.maintain(name).await,
            ChildCommand::FailSync => {
                self.rec.clear();
                self.rec.fail_next_sync();
                self.done(name, "fail-sync", 1, "file-sync");
            }
            ChildCommand::Held {
                site,
                occurrence,
                binding,
            } => self.done(name, &site, occurrence, &binding),
            ChildCommand::Fenced => {
                let fence = self.server.handle.watch_fence().borrow().clone();
                assert_eq!(
                    fence_witness(
                        fence.as_ref(),
                        &self.fixture.volume(),
                        self.rec.sync_failure_fired(),
                        &self.rec.calls(),
                    ),
                    Ok(()),
                    "authority fence witness: {fence:?}; calls: {:?}",
                    self.rec.calls()
                );
                self.done(name, "fenced", 1, "file-sync");
            }
            ChildCommand::Arm {
                site,
                hold,
                binding,
            } => {
                let occurrence = u64::from(crash::arm_next(site, hold));
                let armed = self.root.join(format!("{name}.armed"));
                let temporary = self.root.join(format!("{name}.armed.next"));
                std::fs::write(&temporary, occurrence.to_string()).unwrap();
                std::fs::rename(temporary, armed).unwrap();
                let root = self.root.to_owned();
                let boot = self.boot;
                std::thread::spawn(move || {
                    wait_for_armed_site(&root, boot, (site, hold, occurrence, binding));
                });
            }
        }
        None
    }
}

async fn authority_commands(
    root: &Path,
    boot: u8,
    fixture: &Fixture,
    rec: &crate::authority::tests::intents::Recording,
    server: &super::super::Server,
) -> ChildStop {
    let context = AuthorityCommandContext {
        root,
        boot,
        fixture,
        rec,
        server,
    };
    let mut command = 1;
    let mut last_command = Instant::now();
    loop {
        assert!(
            last_command.elapsed() < Duration::from_mins(1),
            "authority parent command deadline"
        );
        let name = format!("command-{command}");
        match std::fs::read_to_string(root.join(&name)) {
            Ok(text) => {
                command += 1;
                last_command = Instant::now();
                let parsed =
                    child_command(&text).unwrap_or_else(|error| panic!("{error}: {text:?}"));
                if let Some(stop) = context.apply(&name, parsed).await {
                    return stop;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => panic!("cannot read authority command: {error}"),
        }
        tokio::time::sleep(POLL).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "re-executed by authority crash parents with a fresh boot directory"]
async fn authority_child() {
    use crate::authority::tests::intents::{recording, recording_log};
    let root = PathBuf::from(std::env::var_os(CHILD).expect("authority child marker"));
    if std::env::var(PARKED).unwrap().parse::<bool>().unwrap() {
        let parked = Instant::now();
        while !root.join("go").exists() {
            assert!(
                parked.elapsed() < PARK_WAIT,
                "parked authority was never released"
            );
            tokio::time::sleep(POLL).await;
        }
    }
    let live_mount_stop = std::env::var(LIVE_MOUNT_STOP)
        .unwrap()
        .parse::<bool>()
        .unwrap();
    let boot = root
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("boot-")
        .unwrap()
        .parse::<u8>()
        .unwrap();
    let config = std::fs::read_to_string(root.join("config")).unwrap();
    let (addr, prefix) = config.split_once('\n').unwrap();
    let addr = addr.parse::<SocketAddr>().unwrap();
    if prefix == "custody-probe" {
        custody_probe(&root, boot, addr).await;
        return;
    }
    let selected = select_store(&|name| std::env::var(name).ok()).unwrap();
    assert_eq!(
        selected.label, "S3/MinIO",
        "composed restart requires the same external backend"
    );
    let backend = Arc::new(object_store::prefix::PrefixStore::new(
        selected.backend,
        prefix,
    ));
    let mut fixture = Fixture::existing(root.parent().unwrap().to_owned(), backend);
    fixture.tap = Some(root.clone());
    let rec = recording(&fixture.state);
    let (log, intents) = recording_log(rec.clone());
    crash::install(&root.join("points"), Plan::List).unwrap();
    let accept = if live_mount_stop {
        granary_net::accept::AcceptConfig {
            shutdown_deadline: LIVE_MOUNT_DRAIN,
            ..granary_net::accept::AcceptConfig::default()
        }
    } else {
        granary_net::accept::AcceptConfig::default()
    };
    let server = tokio::time::timeout(
        WAIT,
        fixture.start_on_log(boot, roomy(), false, Some(addr), accept, log, intents),
    )
    .await
    .unwrap();
    publish_witness(&root, boot, "ready", "ready", 1, &addr.to_string());
    let stop = authority_commands(&root, boot, &fixture, &rec, &server).await;
    tokio::time::timeout(CHILD_STOP_WAIT, async {
        if server.handle.watch_fence().borrow().is_some() {
            server.shutdown.send(true).unwrap();
            server.served.await.unwrap().unwrap();
            assert!(matches!(
                server.driver.await.unwrap(),
                crate::RunEnd::Fenced(_)
            ));
        } else if stop == ChildStop::LiveMount {
            server.shutdown.send(true).unwrap();
            assert_eq!(
                server.served.await.unwrap().unwrap(),
                granary_net::accept::ShutdownOutcome::DeadlineExpired
            );
            assert_eq!(server.handle.stop().await, crate::RunEnd::Stopped);
            assert_eq!(server.driver.await.unwrap(), crate::RunEnd::Stopped);
        } else {
            server.stop().await;
        }
    })
    .await
    .unwrap();
}
