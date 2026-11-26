// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The ignored real-TLS server observer child and its JSON-lines contract.
//! Nextest uses the printed default path; an explicit path requires invoking
//! the libtest binary directly with `--skip=granary-q3-output=<path>`.

use super::super::super::file_log::FileLogOn;
use super::capture::Capture;
use super::io::{Call, IoSample, TimedFileOps, TimedLog, TimedStore, Timings};
use super::observers::{Attempt, AttemptOutcome, landed_growth};
use super::rows::{Driver, Fixture, LogSetup, RAISED, runtime_thread};
use super::transport::{CredentialPaths, Material};
use super::*;
use granary_client::{OwnedCandidate, PublishRequest, PublishResponse};
use granary_core::intent::{self, Ownership, OwnershipMode};
use granary_core::retained_submission::Scope;
use granary_store::backend::GranaryStore;
use http_body_util::Full;
use hyper::{Request as HyperRequest, body::Bytes};
use object_store::ObjectStoreExt as _;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::future::poll_fn;
use std::io::{BufWriter, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

const SCHEMA: &str = "granary.q3.server.v2";
const OUTPUT_ARGUMENT: &str = "--skip=granary-q3-output=";
const HANDOFF_ARGUMENT: &str = "--skip=granary-q3-handoff=";
const BIND_ARGUMENT: &str = "--skip=granary-q3-bind=";
const STORE_DELAY: Duration = Duration::from_millis(5);
const FILE_DELAY: Duration = Duration::from_millis(7);

fn net_events_path(path: &Path) -> PathBuf {
    path.with_extension("net-events.log")
}

#[derive(Clone)]
struct NetEventSink {
    state: Arc<Mutex<NetEventFile>>,
}

struct NetEventFile {
    file: std::fs::File,
    failure: Option<String>,
}

impl NetEventSink {
    fn create(path: &Path) -> Result<Self, String> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| format!("server observer cannot create net event log: {error}"))?;
        Ok(Self {
            state: Arc::new(Mutex::new(NetEventFile {
                file,
                failure: None,
            })),
        })
    }

    fn record(&self, event: &Event<'_>) {
        let metadata = event.metadata();
        let mut fields = NetEventFields::default();
        event.record(&mut fields);
        let mut line = format!(
            "{} {} {}",
            metadata.level(),
            metadata.target(),
            fields.message.unwrap_or_default()
        );
        for field in fields.values {
            line.push(' ');
            line.push_str(&field);
        }
        line.push('\n');
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.failure.is_some() {
            return;
        }
        if let Err(error) = state.file.write_all(line.as_bytes()) {
            state.failure = Some(error.to_string());
        }
    }

    fn finish(&self) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(error) = &state.failure {
            return Err(format!(
                "server observer net event log write failed: {error}"
            ));
        }
        state
            .file
            .flush()
            .map_err(|error| format!("server observer net event log flush failed: {error}"))
    }
}

#[derive(Default)]
struct NetEventFields {
    message: Option<String>,
    values: Vec<String>,
}

impl Visit for NetEventFields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let rendered = format!("{value:?}").replace('\n', " ").replace('\r', " ");
        if field.name() == "message" {
            self.message = Some(rendered);
        } else {
            self.values.push(format!("{}={rendered}", field.name()));
        }
    }
}

fn is_net_event(metadata: &Metadata<'_>) -> bool {
    metadata.is_event()
        && metadata.target().starts_with("granary_net")
        && matches!(
            *metadata.level(),
            tracing::Level::ERROR
                | tracing::Level::WARN
                | tracing::Level::INFO
                | tracing::Level::DEBUG
        )
}

struct ServeSubscriber {
    capture: Capture,
    net_events: NetEventSink,
}

struct NetEventSubscriber {
    net_events: NetEventSink,
}

impl Subscriber for NetEventSubscriber {
    fn register_callsite(
        &self,
        metadata: &'static Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if is_net_event(metadata) {
            tracing::subscriber::Interest::always()
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
        Some(tracing::metadata::LevelFilter::DEBUG)
    }

    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        is_net_event(metadata)
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        if is_net_event(event.metadata()) {
            self.net_events.record(event);
        }
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

impl Subscriber for ServeSubscriber {
    fn register_callsite(
        &self,
        metadata: &'static Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if is_net_event(metadata) {
            tracing::subscriber::Interest::always()
        } else {
            self.capture.register_callsite(metadata)
        }
    }

    fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
        Some(tracing::metadata::LevelFilter::TRACE)
    }

    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        is_net_event(metadata) || self.capture.enabled(metadata)
    }

    fn new_span(&self, attrs: &Attributes<'_>) -> Id {
        self.capture.new_span(attrs)
    }

    fn record(&self, span: &Id, values: &Record<'_>) {
        self.capture.record(span, values);
    }

    fn record_follows_from(&self, span: &Id, follows: &Id) {
        self.capture.record_follows_from(span, follows);
    }

    fn event(&self, event: &Event<'_>) {
        if is_net_event(event.metadata()) {
            self.net_events.record(event);
        }
        self.capture.event(event);
    }

    fn enter(&self, span: &Id) {
        self.capture.enter(span);
    }

    fn exit(&self, span: &Id) {
        self.capture.exit(span);
    }

    fn clone_span(&self, span: &Id) -> Id {
        self.capture.clone_span(span)
    }

    fn try_close(&self, span: Id) -> bool {
        self.capture.try_close(span)
    }
}

fn serve_dispatch(
    path: &Path,
    capture: Capture,
) -> Result<(tracing::Dispatch, tracing::Dispatch, NetEventSink), String> {
    let net_events = NetEventSink::create(&net_events_path(path))?;
    let driver_dispatch = tracing::Dispatch::new(ServeSubscriber {
        capture,
        net_events: net_events.clone(),
    });
    let accept_dispatch = tracing::Dispatch::new(NetEventSubscriber {
        net_events: net_events.clone(),
    });
    Ok((driver_dispatch, accept_dispatch, net_events))
}

pub(super) type Backend = GranaryStore<Arc<dyn object_store::ObjectStore>>;
type ObservedDriver = Driver<Backend, TimedLog<FileLogOn<Arc<TimedFileOps>>>>;

pub(super) fn require_minio(label: &str) -> Result<(), String> {
    if label.starts_with("AmazonS3(") {
        Ok(())
    } else {
        Err("server observer row requires S3/MinIO".to_owned())
    }
}

fn output_path(
    args: impl IntoIterator<Item = OsString>,
    default_dir: &Path,
) -> Result<PathBuf, &'static str> {
    let prefix = OsStr::new(OUTPUT_ARGUMENT);
    let mut selected = None;
    for argument in args {
        let Some(bytes) = argument
            .as_encoded_bytes()
            .strip_prefix(prefix.as_encoded_bytes())
        else {
            continue;
        };
        if selected.is_some() {
            return Err("server observer output argument is duplicated");
        }
        if bytes.is_empty() {
            return Err("server observer output path is empty");
        }
        selected = Some(PathBuf::from(OsString::from_vec(bytes.to_vec())));
    }
    Ok(selected.unwrap_or_else(|| default_dir.join("server-observers.jsonl")))
}

fn serve_options(
    args: impl IntoIterator<Item = OsString>,
) -> Result<Option<(PathBuf, IpAddr)>, &'static str> {
    let handoff_prefix = OsStr::new(HANDOFF_ARGUMENT);
    let bind_prefix = OsStr::new(BIND_ARGUMENT);
    let mut handoff = None;
    let mut bind = None;
    for argument in args {
        let bytes = argument.as_encoded_bytes();
        if let Some(value) = bytes.strip_prefix(handoff_prefix.as_encoded_bytes()) {
            if handoff.is_some() {
                return Err("server observer handoff argument is duplicated");
            }
            if value.is_empty() {
                return Err("server observer handoff path is empty");
            }
            handoff = Some(PathBuf::from(OsString::from_vec(value.to_vec())));
        }
        if let Some(value) = bytes.strip_prefix(bind_prefix.as_encoded_bytes()) {
            if bind.is_some() {
                return Err("server observer bind argument is duplicated");
            }
            let value = std::str::from_utf8(value)
                .map_err(|_| "server observer bind address is invalid")?;
            bind = Some(
                value
                    .parse()
                    .map_err(|_| "server observer bind address is invalid")?,
            );
        }
    }
    match (handoff, bind) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err("server observer bind requires a handoff directory"),
        (Some(handoff), bind) => Ok(Some((
            handoff,
            bind.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        ))),
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "the ignored harness uses its process id only to isolate its temporary output directory"
)]
fn run_directory(parent: &Path) -> Result<PathBuf, String> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = parent.join(format!(
        "granary-q3-server-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|error| format!("server observer cannot create run directory: {error}"))?;
    Ok(path)
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            value if value.is_control() => {
                let value = u32::from(value);
                out.push_str("\\u");
                for shift in [12, 8, 4, 0] {
                    out.push(char::from_digit((value >> shift) & 0xf, 16).unwrap_or('0'));
                }
            }
            value => out.push(value),
        }
    }
    out.push('"');
    out
}

fn write_attempts(
    output: &mut impl std::io::Write,
    pass: &str,
    attempts: &[Attempt],
) -> Result<(), String> {
    let mut ordinals = BTreeMap::<&str, usize>::new();
    for sample in attempts {
        let ordinal = sample.request_id.as_deref().map_or(1, |id| {
            let ordinal = ordinals.entry(id).or_default();
            *ordinal = ordinal.saturating_add(1);
            *ordinal
        });
        let request_id = sample
            .request_id
            .as_deref()
            .map_or_else(|| "null".to_owned(), json_string);
        let request_id_kind = if sample.request_id_refusal.is_some() {
            "malformed"
        } else if sample.request_id.is_some() {
            "present"
        } else {
            "absent"
        };
        let (status, outcome) = match sample.outcome {
            AttemptOutcome::Response(409) => ("409".to_owned(), "conflict"),
            AttemptOutcome::Response(429) => ("429".to_owned(), "rate_limited"),
            AttemptOutcome::Response(status @ 200..=299) => (status.to_string(), "success"),
            AttemptOutcome::Response(status) => (status.to_string(), "refused"),
            AttemptOutcome::ServiceError => ("null".to_owned(), "service_error"),
            AttemptOutcome::Cancelled => ("null".to_owned(), "cancelled"),
        };
        writeln!(
            output,
            "{{\"schema\":\"{SCHEMA}\",\"pass\":{},\"kind\":\"http_attempt\",\"arrival_seq\":{},\"method\":{},\"route\":{},\"status\":{},\"outcome\":\"{outcome}\",\"duration_ns\":{},\"request_id\":{request_id},\"request_id_kind\":\"{request_id_kind}\",\"attempt_ordinal\":{ordinal}}}",
            json_string(pass),
            sample.arrival_seq,
            json_string(&sample.method),
            json_string(&sample.route),
            status,
            sample.elapsed.as_nanos(),
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

fn prepare_handoff(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() {
                return Err("server observer handoff is not a directory".to_owned());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(path)
                .map_err(|error| format!("server observer cannot create handoff: {error}"))?;
        }
        Err(error) => return Err(format!("server observer cannot inspect handoff: {error}")),
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("server observer cannot inspect handoff: {error}"))?;
    if metadata.mode() & 0o777 != 0o700 || metadata.uid() != nix::unistd::geteuid().as_raw() {
        return Err("server observer handoff ownership or mode is invalid".to_owned());
    }
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("server observer cannot create handoff file: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("server observer cannot write handoff file: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("server observer cannot sync handoff file: {error}"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("server observer cannot set handoff mode: {error}"))
}

fn write_handoff(
    dir: &Path,
    base: &str,
    pin: &[u8; 32],
    credentials: &CredentialPaths,
) -> Result<(), String> {
    let path_text = |path: &Path| {
        path.to_str()
            .map(|value| value.as_bytes().to_vec())
            .ok_or_else(|| "server observer handoff path is not Unicode".to_owned())
    };
    let seed = dir.join("signing.seed");
    let parent = dir
        .parent()
        .ok_or_else(|| "server observer handoff has no parent".to_owned())?;
    let client_root = parent.join("client/root");
    let client_log = parent.join("client-events.jsonl");
    write_private(&seed, &[0x5A; 32])?;
    let signing_key = publisher();
    let root_key = signing_key.public_key();
    let values = [
        ("base-url", base.as_bytes().to_vec()),
        ("server-pin", hex(pin).into_bytes()),
        ("ca-cert-path", path_text(&credentials.ca)?),
        ("client-cert-path", path_text(&credentials.certificate)?),
        (
            "client-credential-path",
            path_text(&credentials.credential)?,
        ),
        ("signing-seed-path", path_text(&seed)?),
        ("root-key", hex(root_key).into_bytes()),
        ("volume", b"v000".to_vec()),
        ("credential-context", b"q3-server".to_vec()),
        ("client-root-path", path_text(&client_root)?),
        ("client-log-path", path_text(&client_log)?),
        (
            "server-uid",
            nix::unistd::geteuid().as_raw().to_string().into_bytes(),
        ),
    ];
    for (name, value) in values {
        write_private(&dir.join(name), &value)?;
    }
    write_private(&dir.join("ready"), b"")
}

fn require_populations(
    attempts: usize,
    store_samples: usize,
    file_samples: usize,
    gate_samples: usize,
    losses: (usize, usize, usize),
) -> Result<(), &'static str> {
    if losses != (0, 0, 0) {
        return Err("server observer sample loss is nonzero");
    }
    if attempts == 0 {
        return Err("server observer attempt population is empty");
    }
    if store_samples == 0 || file_samples == 0 {
        return Err("server observer I/O population is empty");
    }
    if gate_samples == 0 {
        return Err("server observer gate population is empty");
    }
    Ok(())
}

#[expect(
    clippy::cast_precision_loss,
    reason = "the JSON carries an approximate displayed rate beside exact counts and nanoseconds"
)]
fn landed_line(
    pass: &str,
    before: u64,
    after: u64,
    growth: u64,
    put_attempts: usize,
    elapsed: Duration,
) -> String {
    let roots_per_second = if elapsed.is_zero() {
        0.0
    } else {
        growth as f64 / elapsed.as_secs_f64()
    };
    format!(
        "{{\"schema\":\"{SCHEMA}\",\"pass\":{},\"kind\":\"landed_window\",\"before_max_seq\":{before},\"after_max_seq\":{after},\"chain_growth\":{growth},\"final_depth\":{after},\"put_attempts\":{put_attempts},\"elapsed_ns\":{},\"roots_per_second\":{roots_per_second:.6},\"intervening_roots_readable\":true,\"sample_loss\":0}}",
        json_string(pass),
        elapsed.as_nanos(),
    )
}

struct PassData {
    pass: &'static str,
    attempts: Vec<Attempt>,
    io_samples: Vec<IoSample>,
    spans: Vec<super::capture::Sample>,
    counts: [usize; 13],
    bytes: [usize; 13],
    losses: (usize, usize, usize),
    before: u64,
    after: u64,
    growth: u64,
    landed_elapsed: Duration,
}

#[expect(
    clippy::disallowed_methods,
    reason = "the external-I/O harness yields between bounded server-side completion observations"
)]
async fn wait_closed(handle: &AuthorityHandle, volume: &VolumeName) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if handle
                .volume_view(volume)
                .and_then(super::super::super::observation::VolumeView::status)
                .is_some_and(|status| status.open.is_none())
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .map_err(|_| "server observer publication remained open".to_owned())
}

pub(super) async fn clear_prefix(store: &Arc<dyn object_store::ObjectStore>) -> Result<(), String> {
    let mut pending = vec![object_store::path::Path::default()];
    while let Some(prefix) = pending.pop() {
        let listed = store
            .list_with_delimiter((!prefix.as_ref().is_empty()).then_some(&prefix))
            .await
            .map_err(|error| format!("server observer MinIO cleanup failed: {error}"))?;
        pending.extend(listed.common_prefixes);
        for object in listed.objects {
            store
                .delete(&object.location)
                .await
                .map_err(|error| format!("server observer MinIO cleanup failed: {error}"))?;
        }
    }
    Ok(())
}

pub(super) fn measurement_backends(
    pass: &str,
    configured: &crate::config::StoreConfig,
    digest: granary_core::enrollment::ClientSpkiDigest,
) -> ([Backend; 3], Arc<dyn object_store::ObjectStore>) {
    let prefix = format!("q3-server-{pass}-{digest}").replace(':', "-");
    let prefixed: Arc<dyn object_store::ObjectStore> = Arc::new(
        object_store::prefix::PrefixStore::new(Arc::clone(&configured.store), prefix),
    );
    (
        [
            GranaryStore::new(Arc::clone(&prefixed)),
            GranaryStore::new(Arc::clone(&prefixed)),
            GranaryStore::new(Arc::clone(&prefixed)),
        ],
        prefixed,
    )
}

async fn create_fixture(
    pass: &str,
    base: &Path,
    configured: &crate::config::StoreConfig,
    io: Timings,
    digest: granary_core::enrollment::ClientSpkiDigest,
    depth: u64,
    writable_tree: bool,
) -> Result<
    (
        Fixture<Backend>,
        ObservedDriver,
        Arc<dyn object_store::ObjectStore>,
    ),
    String,
> {
    let (backends, prefixed) = measurement_backends(pass, configured, digest);
    let dir = base.join(pass);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|error| format!("server observer cannot create fixture: {error}"))?;
    let volume = vol("v000");
    if writable_tree {
        let source = dir.join("source");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&source)
            .map_err(|error| format!("server observer cannot create source: {error}"))?;
        std::fs::write(source.join("base.txt"), b"q3 loopback smoke base\n")
            .map_err(|error| format!("server observer cannot create source: {error}"))?;
        let store = granary_client::Store::open(&dir.join("publication"))
            .map_err(|error| error.to_string())?;
        let remote = GranaryStore::new(Arc::clone(&prefixed));
        let published = granary_client::publish(
            &remote,
            &store,
            &source,
            &volume,
            &publisher(),
            &granary_core::identity::WriterIdentity::from_bytes(*b"q3-server-child!"),
            granary_core::root::Timestamp {
                secs: 1_760_000_000,
                nanos: 0,
            },
            granary_client::Policy::default(),
        )
        .await
        .map_err(|error| error.to_string())?;
        if published.seq != 1 {
            return Err("server observer base publication sequence is invalid".to_owned());
        }
    }
    let log_timings = io.clone();
    let (fixture, driver) = Fixture::new(
        &dir,
        backends,
        io,
        move |inner| TimedLog {
            inner,
            timings: log_timings,
        },
        std::slice::from_ref(&volume),
        depth,
        true,
        RAISED,
        None,
        LogSetup::Deferred,
        digest,
        true,
        true,
        configured.dispatch_deadline,
    )
    .await?;
    Ok((fixture, driver, prefixed))
}

async fn initialise_fixture(
    handle: &AuthorityHandle,
    volume: &VolumeName,
) -> Result<Epoch, String> {
    match handle.initialise(volume).await {
        Ok(crate::authority::Initialised::Created { epoch }) => Ok(epoch),
        Ok(crate::authority::Initialised::Kept { .. }) => {
            Err("server observer fixture kept a pre-existing authority log".to_owned())
        }
        Err(error) => Err(format!(
            "server observer fixture initialisation failed: {error:?}"
        )),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one pass retains the real request, durability, root and gate observations"
)]
async fn execute_pass(
    pass: &'static str,
    base: &Path,
    configured: &crate::config::StoreConfig,
    io: Timings,
) -> Result<PassData, String> {
    let material = Material::for_host("localhost").unwrap();
    let digest = material.digest();
    let (fixture, driver, prefixed) =
        create_fixture(pass, base, configured, io, digest, 1, false).await?;
    let volume = vol("v000");
    let capture = Capture::new(262_144);
    let driver_run = runtime_thread(driver.run(), tracing::Dispatch::new(capture.clone()));
    let epoch = initialise_fixture(&fixture.handle, &volume).await?;
    let (peer, attempts, _) = material.serve_observed_bound(
        fixture.service.clone(),
        &fixture.dir,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        "localhost",
        tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()),
    )?;
    let scope = Scope {
        authority_base: peer.base.as_bytes().to_vec(),
        pins: vec![peer.pin],
        credential_context: b"q3-server".to_vec(),
    };
    let ownership = intent::encode_ownership(Ownership {
        writer: [1; 16],
        instance: [2; 16],
        mode: OwnershipMode::Acquire { observed_cursor: 0 },
    })
    .map_err(|error| error.to_string())?;
    let grant = peer
        .client
        .intent_acquire_once(&scope, &volume, &ownership)
        .await
        .map_err(|error| error.to_string())?;
    if grant.status() != 200 {
        return Err(format!(
            "server observer acquisition returned {}",
            grant.status()
        ));
    }
    let receipt = intent::decode_grant(grant.body())
        .map_err(|error| error.to_string())?
        .receipt;
    let root = good_root(&volume, 1, None, 1);
    let registration =
        intent::encode_register(&receipt.writer, receipt.epoch, &receipt.instance, 1, &root)
            .map_err(|error| error.to_string())?;
    let registered = peer
        .client
        .intent_register_once(&scope, &volume, &registration, |_, _| true)
        .await
        .map_err(|error| error.to_string())?;
    if registered.status() != 200 {
        return Err(format!(
            "server observer register returned {}",
            registered.status()
        ));
    }
    let before = fixture
        .store
        .max_seq(volume.as_str())
        .await
        .map_err(|error| error.to_string())?
        .unwrap_or(0);
    let owned =
        OwnedCandidate::new(volume.as_str(), Arc::from(root)).map_err(|error| error.to_string())?;
    let request = PublishRequest::new(
        volume.as_str(),
        epoch,
        b"publish-1",
        owned.clone(),
        vec![owned.clone()],
    )
    .map_err(|error| error.to_string())?;
    let started = stopwatch();
    let published = peer
        .client
        .publish_once(&request)
        .await
        .map_err(|error| error.to_string())?;
    if !matches!(
        published,
        PublishResponse::Accepted(_) | PublishResponse::Landed(_)
    ) {
        return Err(format!("server observer publish returned {published:?}"));
    }
    wait_closed(&fixture.handle, &volume).await?;
    let landed_elapsed = started.elapsed();
    let (after, growth) = landed_growth(&fixture.store, &volume, before)
        .await
        .map_err(str::to_owned)?;
    let stale = good_root(&volume, 2, Some(GrainId::of(b"not-the-head")), 1);
    let stale = OwnedCandidate::new(volume.as_str(), Arc::from(stale))
        .map_err(|error| error.to_string())?;
    let conflict = PublishRequest::new(
        volume.as_str(),
        epoch,
        b"publish-conflict",
        stale.clone(),
        vec![stale],
    )
    .map_err(|error| error.to_string())?;
    if !matches!(
        peer.client
            .publish_once(&conflict)
            .await
            .map_err(|error| error.to_string())?,
        PublishResponse::Conflict(_)
    ) {
        return Err("server observer conflict control did not conflict".to_owned());
    }
    let (attempts, attempt_loss) = attempts.take();
    peer.finish().await;
    fixture.handle.stop().await;
    if driver_run
        .join()
        .map_err(|_| "server observer driver panicked")?
        != RunEnd::Stopped
    {
        return Err("server observer driver did not stop".to_owned());
    }
    let (io_samples, io_loss) = fixture.io.take();
    let counts = fixture.io.counts();
    let bytes = fixture.io.bytes();
    let (spans, span_loss) = capture.take();
    let store_samples = io_samples
        .iter()
        .filter(|sample| sample.call == Call::Put)
        .count();
    let file_samples = io_samples
        .iter()
        .filter(|sample| sample.call == Call::SyncFile)
        .count();
    let gate_samples = spans
        .iter()
        .filter(|sample| sample.name == "authority_log_wait")
        .count();
    require_populations(
        attempts.len(),
        store_samples,
        file_samples,
        gate_samples,
        (attempt_loss, io_loss, span_loss),
    )
    .map_err(str::to_owned)?;
    let data = PassData {
        pass,
        attempts,
        io_samples,
        spans,
        counts,
        bytes,
        losses: (attempt_loss, io_loss, span_loss),
        before,
        after,
        growth,
        landed_elapsed,
    };
    drop(fixture);
    clear_prefix(&prefixed).await?;
    Ok(data)
}

fn duration_summary(values: &[u128]) -> Result<(usize, u128, u128, u128, u128), &'static str> {
    let minimum = values
        .iter()
        .copied()
        .min()
        .ok_or("no successful samples")?;
    let maximum = values
        .iter()
        .copied()
        .max()
        .ok_or("no successful samples")?;
    Ok((
        values.len(),
        minimum,
        super::output::quantile(values, 50)?,
        super::output::quantile(values, 99)?,
        maximum,
    ))
}

fn observed_delay(
    samples: &[IoSample],
    call: Call,
    declared: Duration,
    loss: usize,
) -> Result<Vec<u128>, &'static str> {
    if loss != 0 {
        return Err("slow control sample loss is nonzero");
    }
    let samples: Vec<_> = samples
        .iter()
        .filter(|sample| sample.call == call)
        .collect();
    if samples.is_empty() {
        return Err("slow control seam has no samples");
    }
    if samples.iter().any(|sample| !sample.success) {
        return Err("slow control seam observed a failed operation");
    }
    if samples.iter().any(|sample| sample.elapsed < declared) {
        return Err("slow control observed less than its declared delay");
    }
    Ok(samples
        .into_iter()
        .map(|sample| sample.elapsed.as_nanos())
        .collect())
}

fn write_durability(
    output: &mut impl std::io::Write,
    pass: &str,
    counts: &[usize; 13],
    bytes: &[usize; 13],
) -> Result<(), String> {
    writeln!(
        output,
        "{{\"schema\":\"{SCHEMA}\",\"pass\":{},\"kind\":\"durability\",\"intent_logical_commits\":{},\"intent_write_calls\":{},\"intent_write_bytes\":{},\"intent_file_barriers\":{},\"intent_dir_barriers\":{},\"decision_log_appends\":{},\"decision_file_barriers\":{},\"decision_dir_barriers\":{},\"sample_loss\":0}}",
        json_string(pass),
        counts[Call::IntentCommit as usize],
        counts[Call::IntentWrite as usize],
        bytes[Call::IntentWrite as usize],
        counts[Call::IntentSyncFile as usize],
        counts[Call::IntentSyncDir as usize],
        counts[Call::DecisionAppend as usize],
        counts[Call::DecisionSyncFile as usize],
        counts[Call::DecisionSyncDir as usize],
    )
    .map_err(|error| error.to_string())
}

fn write_pass(output: &mut impl std::io::Write, data: &PassData) -> Result<(), String> {
    write_attempts(output, data.pass, &data.attempts)?;
    write_durability(output, data.pass, &data.counts, &data.bytes)?;
    writeln!(
        output,
        "{}",
        landed_line(
            data.pass,
            data.before,
            data.after,
            data.growth,
            data.counts[Call::Put as usize],
            data.landed_elapsed,
        )
    )
    .map_err(|error| error.to_string())?;
    let gates: Vec<_> = data
        .spans
        .iter()
        .filter(|sample| sample.name == "authority_log_wait")
        .map(|sample| sample.end.duration_since(sample.start).as_nanos())
        .collect();
    let (count, minimum, p50, p99, maximum) = duration_summary(&gates).map_err(str::to_owned)?;
    writeln!(
        output,
        "{{\"schema\":\"{SCHEMA}\",\"pass\":{},\"kind\":\"gate\",\"name\":\"authority_log_wait\",\"sample_count\":{count},\"min_ns\":{minimum},\"p50_ns\":{p50},\"p99_ns\":{p99},\"max_ns\":{maximum},\"sample_loss\":0}}",
        json_string(data.pass),
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

#[derive(Default)]
struct MountedWindow {
    start: Option<(u64, Instant)>,
    rows: Vec<u8>,
}

impl MountedWindow {
    async fn mark(
        &mut self,
        start: Option<bool>,
        store: &TimedStore<Backend>,
        handle: &AuthorityHandle,
    ) -> Result<(), String> {
        let volume = vol("v000");
        if start == Some(true) && self.start.is_none() && self.rows.is_empty() {
            let before = store
                .max_seq(volume.as_str())
                .await
                .map_err(|e| e.to_string())?
                .ok_or("mounted window has no initial root")?;
            store.timings.counts();
            store.timings.bytes();
            self.start = Some((before, stopwatch()));
            return Ok(());
        }
        if start != Some(false) {
            return Err("invalid mounted window marker".to_owned());
        }
        let (before, started) = self.start.take().ok_or("mounted window has no start")?;
        wait_closed(handle, &volume).await?;
        let elapsed = started.elapsed();
        let counts = store.timings.counts();
        let bytes = store.timings.bytes();
        let (after, growth) = landed_growth(store, &volume, before).await?;
        write_durability(&mut self.rows, "serve", &counts, &bytes)?;
        writeln!(
            self.rows,
            "{}",
            landed_line(
                "serve",
                before,
                after,
                growth,
                counts[Call::Put as usize],
                elapsed
            )
        )
        .map_err(|error| error.to_string())
    }
}

async fn run_serve(path: &Path, base: &Path, handoff: &Path, bind: IpAddr) -> Result<(), String> {
    prepare_handoff(handoff)?;
    let configured = crate::config::store_from_env()?;
    let host = bind.to_string();
    let material = Material::for_host(&host)?;
    let (fixture, driver, prefixed) = create_fixture(
        "serve",
        base,
        &configured,
        Timings::new(262_144),
        material.digest(),
        1,
        true,
    )
    .await?;
    let capture = Capture::new(262_144);
    let (driver_dispatch, accept_dispatch, net_events) = serve_dispatch(path, capture)?;
    let driver_run = runtime_thread(driver.run(), driver_dispatch);
    initialise_fixture(&fixture.handle, &vol("v000")).await?;
    let (markers, mut requests) = tokio::sync::mpsc::channel(1);
    let service = fixture.service.clone();
    let marked = hyper::service::service_fn(move |request: HyperRequest<hyper::body::Incoming>| {
        let (markers, service) = (markers.clone(), service.clone());
        async move {
            use hyper::service::Service as _;
            if request.method() == hyper::Method::POST && request.uri().path() == "/q3-marker" {
                let start = request.headers().get("granary-request-id").and_then(|id| {
                    match id.to_str().ok()?.rsplit('-').next()? {
                        "start" => Some(true),
                        "end" => Some(false),
                        _ => None,
                    }
                });
                let (reply, result) = tokio::sync::oneshot::channel();
                let passed = markers.send((start, reply)).await.is_ok() && result.await == Ok(true);
                let mut response = hyper::Response::new(Full::new(Bytes::new()));
                *response.status_mut() = if passed {
                    hyper::StatusCode::NO_CONTENT
                } else {
                    hyper::StatusCode::INTERNAL_SERVER_ERROR
                };
                return Ok(response);
            }
            service.call(request).await
        }
    });
    let (peer, attempts, credentials) = material.serve_observed_bound(
        marked,
        handoff,
        SocketAddr::new(bind, 0),
        &host,
        accept_dispatch,
    )?;
    write_handoff(handoff, &peer.base, &peer.pin, &credentials)?;
    let mut window = MountedWindow::default();
    let stop = tokio::signal::ctrl_c();
    tokio::pin!(stop);
    while let Some((start, reply)) = poll_fn(|cx| {
        if let std::task::Poll::Ready(stopped) = stop.as_mut().poll(cx) {
            return std::task::Poll::Ready(stopped.map(|()| None).map_err(|e| e.to_string()));
        }
        requests.poll_recv(cx).map(Ok)
    })
    .await?
    {
        let _ = reply.send(
            window
                .mark(start, &fixture.store, &fixture.handle)
                .await
                .is_ok(),
        );
    }
    peer.finish().await;
    let (attempts, loss) = attempts.take();
    if loss != 0 {
        return Err("server observer attempt sample loss is nonzero".to_owned());
    }
    if attempts.is_empty() {
        return Err("server observer attempt population is empty".to_owned());
    }
    fixture.handle.stop().await;
    if driver_run
        .join()
        .map_err(|_| "server observer driver panicked")?
        != RunEnd::Stopped
    {
        return Err("server observer driver did not stop".to_owned());
    }
    net_events.finish()?;
    let output_file = std::fs::File::create(path)
        .map_err(|error| format!("server observer cannot create output: {error}"))?;
    let mut output = BufWriter::new(output_file);
    write_attempts(&mut output, "serve", &attempts)?;
    output
        .write_all(&window.rows)
        .map_err(|error| error.to_string())?;
    output.flush().map_err(|error| error.to_string())?;
    drop(fixture);
    clear_prefix(&prefixed).await
}

async fn run(path: &Path, base: &Path) -> Result<(), String> {
    let configured = crate::config::store_from_env()?;
    require_minio(&configured.store.to_string())?;
    let measurement = execute_pass("measurement", base, &configured, Timings::new(262_144)).await?;
    let slow = execute_pass(
        "slow_control",
        base,
        &configured,
        Timings::delayed(262_144, STORE_DELAY, FILE_DELAY),
    )
    .await?;
    let store = observed_delay(&slow.io_samples, Call::Put, STORE_DELAY, slow.losses.1)
        .map_err(str::to_owned)?;
    let file = observed_delay(&slow.io_samples, Call::SyncFile, FILE_DELAY, slow.losses.1)
        .map_err(str::to_owned)?;
    let store = duration_summary(&store).map_err(str::to_owned)?;
    let file = duration_summary(&file).map_err(str::to_owned)?;
    let output_file = std::fs::File::create(path)
        .map_err(|error| format!("server observer cannot create output: {error}"))?;
    let mut output = BufWriter::new(output_file);
    write_pass(&mut output, &measurement)?;
    write_pass(&mut output, &slow)?;
    writeln!(
        output,
        "{{\"schema\":\"{SCHEMA}\",\"pass\":\"slow_control\",\"kind\":\"slow_control\",\"declared_store_delay_ns\":{},\"declared_file_delay_ns\":{},\"store_sample_count\":{},\"store_min_ns\":{},\"store_p50_ns\":{},\"store_p99_ns\":{},\"store_max_ns\":{},\"file_sample_count\":{},\"file_min_ns\":{},\"file_p50_ns\":{},\"file_p99_ns\":{},\"file_max_ns\":{},\"success\":true,\"sample_loss\":0}}",
        STORE_DELAY.as_nanos(),
        FILE_DELAY.as_nanos(),
        store.0,
        store.1,
        store.2,
        store.3,
        store.4,
        file.0,
        file.1,
        file.2,
        file.3,
        file.4,
    )
    .map_err(|error| error.to_string())?;
    output.flush().map_err(|error| error.to_string())
}

#[test]
fn authority_measurement_output_argument_controls() {
    let default = Path::new("/tmp/default-row");
    assert_eq!(
        output_path(
            [OsString::from(
                "--skip=granary-q3-output=/tmp/explicit.jsonl"
            )],
            default,
        ),
        Ok(PathBuf::from("/tmp/explicit.jsonl"))
    );
    let cases = [
        (
            vec![OsString::from("--skip=granary-q3-output=")],
            "server observer output path is empty",
        ),
        (
            vec![
                OsString::from("--skip=granary-q3-output=/tmp/a"),
                OsString::from("--skip=granary-q3-output=/tmp/b"),
            ],
            "server observer output argument is duplicated",
        ),
    ];
    assert!(!cases.is_empty());
    for (args, refusal) in cases {
        assert_eq!(output_path(args, default), Err(refusal));
    }
}

#[test]
fn authority_measurement_serve_dispatch_keeps_net_events_and_capture_spans() {
    let base = run_directory(&std::env::temp_dir()).unwrap();
    let output = base.join("server-observers.jsonl");
    let capture = Capture::new(8);
    let (driver_dispatch, accept_dispatch, net_events) =
        serve_dispatch(&output, capture.clone()).unwrap();
    tracing::dispatcher::with_default(&accept_dispatch, || {
        tracing::callsite::rebuild_interest_cache();
        let span = tracing::trace_span!("authority_queue");
        drop(span);
        tracing::debug!(
            target: "granary_net::accept",
            rotate_after = ?Duration::from_secs(225),
            "connection rotating: graceful shutdown started"
        );
        tracing::info!(target: "granary_server::control", "discarded control event");
    });
    let (samples, lost) = capture.take();
    assert_eq!(
        (samples.len(), lost),
        (0, 0),
        "the accept dispatch must not add authority spans to Capture"
    );

    tracing::dispatcher::with_default(&driver_dispatch, || {
        tracing::callsite::rebuild_interest_cache();
        let span = tracing::trace_span!("authority_chain", phase = "resolve_head");
        drop(span);
        tracing::info!(
            target: "granary_net::accept",
            lifetime = ?Duration::from_mins(5),
            "connection closed: lifetime bound reached"
        );
    });
    drop(driver_dispatch);
    drop(accept_dispatch);
    net_events.finish().unwrap();

    let text = std::fs::read_to_string(net_events_path(&output)).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "only granary_net events at debug and above belong in the file: {text:?}"
    );
    assert!(
        lines.iter().any(|line| {
            line.contains("connection rotating: graceful shutdown started")
                && line.contains("rotate_after=225s")
        }),
        "rotation debug event missing: {text:?}"
    );
    assert!(
        lines.iter().any(|line| {
            line.contains("connection closed: lifetime bound reached")
                && line.contains("lifetime=300s")
        }),
        "lifetime-bound info event missing: {text:?}"
    );
    assert!(!text.contains("discarded control event"), "{text:?}");
    let (samples, lost) = capture.take();
    assert_eq!(
        (
            samples.first().map(|sample| (sample.name, sample.phase)),
            samples.len(),
            lost,
        ),
        (Some(("authority_chain", "resolve_head")), 1, 0),
        "the forwarding subscriber must preserve Capture's span lifecycle"
    );
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn authority_measurement_serve_argument_controls() {
    assert_eq!(serve_options(Vec::<OsString>::new()), Ok(None));
    assert_eq!(
        serve_options([
            OsString::from("--skip=granary-q3-handoff=/tmp/q3-handoff"),
            OsString::from("--skip=granary-q3-bind=192.0.2.10"),
        ]),
        Ok(Some((
            PathBuf::from("/tmp/q3-handoff"),
            IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10)),
        )))
    );
    let cases = [
        (
            vec![OsString::from("--skip=granary-q3-handoff=")],
            "server observer handoff path is empty",
        ),
        (
            vec![OsString::from("--skip=granary-q3-bind=not-an-address")],
            "server observer bind address is invalid",
        ),
        (
            vec![OsString::from("--skip=granary-q3-bind=127.0.0.1")],
            "server observer bind requires a handoff directory",
        ),
    ];
    assert!(!cases.is_empty());
    for (args, refusal) in cases {
        assert_eq!(serve_options(args), Err(refusal));
    }
}

#[test]
fn authority_measurement_handoff_modes_and_fields() {
    let base = run_directory(&std::env::temp_dir()).unwrap();
    let handoff = base.join("handoff");
    prepare_handoff(&handoff).unwrap();
    let credentials = CredentialPaths {
        ca: handoff.join("ca.pem"),
        certificate: handoff.join("client.pem"),
        credential: handoff.join("client.key"),
    };
    write_handoff(&handoff, "https://127.0.0.1:1", &[7; 32], &credentials).unwrap();
    let entries: Vec<_> = std::fs::read_dir(&handoff)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 14, "all handoff fields must be present");
    assert_eq!(std::fs::metadata(&handoff).unwrap().mode() & 0o777, 0o700);
    assert!(
        entries
            .iter()
            .all(|path| std::fs::metadata(path).unwrap().mode() & 0o777 == 0o600),
        "every handoff file must be private: {entries:?}"
    );
    assert_eq!(
        std::fs::read_to_string(handoff.join("client-root-path")).unwrap(),
        base.join("client/root").to_string_lossy()
    );
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn authority_measurement_minio_requirement_controls() {
    assert_eq!(require_minio("AmazonS3(bucket)"), Ok(()));
    let cases = ["InMemory", "LocalFileSystem(/tmp)"];
    assert!(!cases.is_empty());
    for label in cases {
        assert_eq!(
            require_minio(label),
            Err("server observer row requires S3/MinIO".to_owned())
        );
    }
}

#[test]
fn authority_measurement_attempt_json_contract() {
    let sample = Attempt {
        arrival_seq: 1,
        method: "POST".to_owned(),
        route: "/volume/:volume/publish".to_owned(),
        outcome: AttemptOutcome::Response(409),
        elapsed: Duration::from_nanos(5),
        request_id: Some("fsync-1".to_owned()),
        request_id_refusal: None,
    };
    let mut bytes = Vec::new();
    write_attempts(&mut bytes, "measurement", &[sample]).unwrap();
    let line = String::from_utf8(bytes).unwrap();
    assert_eq!(
        line,
        concat!(
            "{\"schema\":\"granary.q3.server.v2\",\"pass\":\"measurement\",\"kind\":\"http_attempt\",",
            "\"arrival_seq\":1,",
            "\"method\":\"POST\",\"route\":\"/volume/:volume/publish\",",
            "\"status\":409,\"outcome\":\"conflict\",\"duration_ns\":5,",
            "\"request_id\":\"fsync-1\",\"request_id_kind\":\"present\",",
            "\"attempt_ordinal\":1}\n"
        )
    );
    for forbidden in ["body", "credential", "authorization"] {
        assert!(
            !line.contains(forbidden),
            "forbidden field {forbidden}: {line}"
        );
    }
}

#[test]
fn authority_measurement_population_and_loss_controls() {
    assert_eq!(require_populations(1, 1, 1, 1, (0, 0, 0)), Ok(()));
    let cases = [
        (
            (1, 1, 1, 1, (1, 0, 0)),
            "server observer sample loss is nonzero",
        ),
        (
            (0, 1, 1, 1, (0, 0, 0)),
            "server observer attempt population is empty",
        ),
        (
            (1, 0, 1, 1, (0, 0, 0)),
            "server observer I/O population is empty",
        ),
        (
            (1, 1, 1, 0, (0, 0, 0)),
            "server observer gate population is empty",
        ),
    ];
    assert!(!cases.is_empty());
    for ((attempts, store, file, gate, losses), refusal) in cases {
        assert_eq!(
            require_populations(attempts, store, file, gate, losses),
            Err(refusal)
        );
    }
}

#[test]
fn authority_measurement_landed_json_uses_sequence_not_put_attempts() {
    let line = landed_line("measurement", 0, 1, 1, 2, Duration::from_secs(1));
    assert!(
        line.contains("\"chain_growth\":1") && line.contains("\"roots_per_second\":1.000000"),
        "landed JSON used a PUT diagnostic instead of sequence growth: {line}"
    );
    assert!(!line.contains("\"chain_growth\":2"));
    assert!(line.contains("\"put_attempts\":2"));
}

#[test]
fn authority_measurement_slow_control_compares_observed_delays() {
    let at = stopwatch();
    let sample = |call, elapsed, success| IoSample {
        call,
        elapsed,
        start: at,
        end: at + elapsed,
        bytes: 0,
        success,
    };
    let delay = Duration::from_millis(5);
    let valid = [
        sample(Call::Put, delay, true),
        sample(Call::SyncFile, delay + Duration::from_nanos(1), true),
    ];
    assert_eq!(
        observed_delay(&valid, Call::Put, delay, 0),
        Ok(vec![delay.as_nanos()])
    );
    assert_eq!(
        observed_delay(&valid, Call::SyncFile, delay, 0),
        Ok(vec![(delay + Duration::from_nanos(1)).as_nanos()])
    );
    let cases = [
        (
            vec![sample(
                Call::Put,
                delay
                    .checked_sub(Duration::from_nanos(1))
                    .unwrap_or_default(),
                true,
            )],
            0,
            "slow control observed less than its declared delay",
        ),
        (
            vec![sample(Call::Put, delay, false)],
            0,
            "slow control seam observed a failed operation",
        ),
        (Vec::new(), 0, "slow control seam has no samples"),
        (
            vec![sample(Call::Put, delay, true)],
            1,
            "slow control sample loss is nonzero",
        ),
    ];
    assert!(!cases.is_empty());
    for (samples, loss, refusal) in cases {
        assert_eq!(
            observed_delay(&samples, Call::Put, delay, loss),
            Err(refusal)
        );
    }
    let undelayed = Timings::new(1);
    assert_eq!(
        (undelayed.store_delay, undelayed.file_delay),
        (Duration::ZERO, Duration::ZERO)
    );
}

#[test]
fn authority_measurement_cancelled_attempt_json_is_marked_by_pass() {
    let sample = Attempt {
        arrival_seq: 1,
        method: "POST".to_owned(),
        route: "/volume/:volume/publish".to_owned(),
        outcome: AttemptOutcome::Cancelled,
        elapsed: Duration::from_nanos(7),
        request_id: None,
        request_id_refusal: None,
    };
    let mut bytes = Vec::new();
    write_attempts(&mut bytes, "slow_control", &[sample]).unwrap();
    let line = String::from_utf8(bytes).unwrap();
    assert!(line.contains("\"pass\":\"slow_control\""));
    assert!(line.contains("\"status\":null,\"outcome\":\"cancelled\""));
}

#[tokio::test]
async fn authority_measurement_minio_prefix_cleanup_removes_nested_objects() {
    let inner: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let prefixed: Arc<dyn object_store::ObjectStore> =
        Arc::new(object_store::prefix::PrefixStore::new(inner, "q3-control"));
    prefixed
        .put(
            &object_store::path::Path::from("volume/root"),
            object_store::PutPayload::from_static(b"root"),
        )
        .await
        .unwrap();
    clear_prefix(&prefixed).await.unwrap();
    let listed = prefixed.list_with_delimiter(None).await.unwrap();
    assert_eq!((listed.objects.len(), listed.common_prefixes.len()), (0, 0));
}

#[tokio::test]
async fn authority_measurement_serve_fixture_exposes_intents() -> Result<(), String> {
    let scratch = std::fs::canonicalize(std::env::temp_dir())
        .map_err(|error| format!("serve control cannot resolve its scratch directory: {error}"))?;
    let base = run_directory(&scratch)?;
    let configured = crate::config::StoreConfig {
        admission: crate::Admission::chain_fixture(),
        store: Arc::new(object_store::memory::InMemory::new()),
        dispatch_deadline: None,
        ignored_proxy_variables: Vec::new(),
    };
    let digest = Material::for_host("127.0.0.1").unwrap().digest();
    let (fixture, driver, prefixed) = create_fixture(
        "serve-control",
        &base,
        &configured,
        Timings::new(1024),
        digest,
        1,
        true,
    )
    .await
    .unwrap();
    let volume = vol("v000");
    let driver_run = runtime_thread(
        driver.run(),
        tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()),
    );
    let initialised = initialise_fixture(&fixture.handle, &volume).await;
    let mut readback = HyperRequest::builder()
        .uri(format!("/volume/{}/intent", volume.as_str()))
        .body(Full::new(Bytes::new()))
        .unwrap();
    readback
        .extensions_mut()
        .insert(granary_net::identity::ConnectionIdentity::Verified(digest));
    let readback = fixture.send(readback).await;
    let ownership = intent::encode_ownership(Ownership {
        writer: [1; 16],
        instance: [2; 16],
        mode: OwnershipMode::Acquire { observed_cursor: 0 },
    })
    .unwrap();
    let mut acquire = HyperRequest::builder()
        .method("POST")
        .uri(format!("/volume/{}/intent/ownership", volume.as_str()))
        .header(hyper::header::CONTENT_TYPE, intent::MEDIA_OWNERSHIP)
        .body(Full::new(Bytes::from(ownership)))
        .unwrap();
    acquire
        .extensions_mut()
        .insert(granary_net::identity::ConnectionIdentity::Verified(digest));
    let acquired = fixture.send(acquire).await;
    fixture.handle.stop().await;
    assert_eq!(driver_run.join().unwrap(), RunEnd::Stopped);
    clear_prefix(&prefixed).await.unwrap();
    assert_eq!(
        (
            initialised.is_ok(),
            readback.status().as_u16(),
            acquired.status().as_u16(),
        ),
        (true, 200, 200),
        "serve mode must create the log through the intent-rebinding path before handoff"
    );
    std::fs::remove_dir_all(base)
        .map_err(|error| format!("serve control cannot remove run directory: {error}"))?;
    Ok(())
}

#[tokio::test]
#[ignore = "real TLS and MinIO; includes a separate synchronous slow-control pass"]
async fn authority_measurement_server_observers_jsonl() -> Result<(), String> {
    let base = run_directory(&std::env::temp_dir())?;
    let args: Vec<_> = std::env::args_os().collect();
    let path = output_path(args.clone(), &base)?;
    if let Some((handoff, bind)) = serve_options(args)? {
        run_serve(&path, &base, &handoff, bind).await?;
    } else {
        run(&path, &base).await?;
    }
    tracing::info!("server observer samples: {}", path.display());
    Ok(())
}
