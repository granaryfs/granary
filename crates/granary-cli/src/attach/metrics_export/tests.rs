// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "create and mutate scratch files to exercise descriptor custody and bounded reads"
)]

use std::cell::Cell;
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::process::Command;

use granary_client::ClientMetrics;
use granary_net::metrics_listener::{Event, Failure, ScrapeResult, StartError};

use super::*;
use crate::attach::tests::MountScratchDir;

const TOKEN: [u8; 64] = [b'a'; 64];
const TEST_CERT: &[u8] = include_bytes!("testdata/test-cert.pem");
const TEST_KEY: &[u8] = include_bytes!("testdata/test-key.pem");

fn mount_args() -> Vec<OsString> {
    [
        "vol",
        "/mount",
        "--endpoint",
        "https://example.test",
        "--pin",
        "sha256/AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        "--trust-server",
        "--cache-dir",
        "/cache",
        "--foreground",
    ]
    .map(OsString::from)
    .to_vec()
}

fn metrics() -> ClientMetrics {
    ClientMetrics::new(&mut granary_net::secure_random::OsSecureRandom::new())
}

fn rendered(metrics: &ClientMetrics) -> String {
    metrics.snapshot().unwrap().render_prometheus().unwrap()
}

#[test]
fn default_is_dormant_at_the_bind_seam() {
    let args = crate::attach::parse_mount(&mount_args()).unwrap();
    let config = args.metrics.prepare(0).unwrap();
    let metrics = metrics();
    let calls = Cell::new(0);
    let launched = start_with(config, &metrics, |_| {
        calls.set(calls.get() + 1);
        Ok(())
    });
    assert_eq!((launched, calls.get()), (None, 0));
    assert!(!rendered(&metrics).contains("metrics_listener_up"));

    let inputs = Inputs::new();
    let valid = inputs
        .check(&inputs.token, &inputs.key, inputs.uid)
        .unwrap();
    assert_eq!(
        start_with(Some(valid), &metrics, |_| {
            calls.set(calls.get() + 1);
            Ok(())
        }),
        Some(())
    );
    assert_eq!(calls.get(), 1);
}

#[test]
fn metrics_options_require_the_complete_numeric_profile_once() {
    let mut args = mount_args();
    args.extend(["--metrics-listen", "127.0.0.1:12345"].map(OsString::from));
    assert!(crate::attach::parse_mount(&args).is_err());
    args.extend(
        [
            "--metrics-token-file",
            "token",
            "--metrics-tls-cert",
            "cert",
            "--metrics-tls-key",
            "key",
        ]
        .map(OsString::from),
    );
    assert!(
        crate::attach::parse_mount(&args)
            .unwrap()
            .metrics
            .configured()
    );
    args.extend(["--metrics-listen", "127.0.0.1:12345"].map(OsString::from));
    assert!(crate::attach::parse_mount(&args).is_err());
}

fn private_file(path: &Path, data: &[u8]) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    std::io::Write::write_all(&mut file, data).unwrap();
}

struct Inputs {
    dir: MountScratchDir,
    token: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    uid: u32,
}

impl Inputs {
    fn new() -> Self {
        let dir = MountScratchDir::new();
        let token = dir.0.join("token");
        let cert = dir.0.join("cert");
        let key = dir.0.join("key");
        private_file(&token, &TOKEN);
        private_file(&key, TEST_KEY);
        fs::write(&cert, TEST_CERT).unwrap();
        let uid = fs::metadata(&token).unwrap().uid();
        Self {
            dir,
            token,
            cert,
            key,
            uid,
        }
    }

    fn check(
        &self,
        token: &Path,
        key: &Path,
        uid: u32,
    ) -> Result<Configuration, (&'static str, FailureClass)> {
        read_configuration(
            "127.0.0.1:9900".parse().unwrap(),
            token,
            &self.cert,
            key,
            uid,
        )
    }
}

#[tokio::test]
async fn token_file_custody_and_format_refusals() {
    let inputs = Inputs::new();
    let f = |path: &Path, uid| inputs.check(path, &inputs.key, uid).unwrap_err().0;
    let custody = "metrics token file custody refused";
    let invalid = "invalid metrics token file";
    assert!(inputs.check(&inputs.token, &inputs.key, inputs.uid).is_ok());
    assert_eq!(f(&inputs.token, inputs.uid ^ 1), custody, "wrong owner");
    assert_eq!(
        f(&inputs.dir.0.join("missing"), inputs.uid),
        custody,
        "unreadable path"
    );

    let link = inputs.dir.0.join("symlink");
    symlink(&inputs.token, &link).unwrap();
    assert_eq!(f(&link, inputs.uid), custody, "symlink");

    let fifo = inputs.dir.0.join("fifo");
    assert!(
        Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let metadata = fs::metadata(&fifo).unwrap();
    assert_eq!(metadata.uid(), inputs.uid);
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    let (result, checked) = tokio::sync::oneshot::channel();
    let cert = inputs.cert.clone();
    let key = inputs.key.clone();
    let uid = inputs.uid;
    std::thread::spawn(move || {
        let refused =
            read_configuration("127.0.0.1:9900".parse().unwrap(), &fifo, &cert, &key, uid)
                .err()
                .map(|(message, _)| message);
        let _ = result.send(refused);
    });
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), checked)
            .await
            .ok()
            .and_then(Result::ok),
        Some(Some(custody)),
        "fifo must be refused without waiting for a writer"
    );

    let link = inputs.dir.0.join("hard-link");
    fs::hard_link(&inputs.token, &link).unwrap();
    assert_eq!(f(&inputs.token, inputs.uid), custody, "multiple links");
    fs::remove_file(link).unwrap();
    fs::set_permissions(&inputs.token, fs::Permissions::from_mode(0o640)).unwrap();
    assert_eq!(f(&inputs.token, inputs.uid), custody, "mode");
    if inputs.uid != 0 {
        fs::set_permissions(&inputs.token, fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(f(&inputs.token, inputs.uid), custody, "unreadable mode");
    }
    fs::set_permissions(&inputs.token, fs::Permissions::from_mode(0o600)).unwrap();

    for (label, contents) in [
        ("too short", vec![b'a'; 63]),
        ("overlong", vec![b'a'; 66]),
        ("uppercase", vec![b'A'; 64]),
        ("newline", vec![b'\n'; 64]),
        ("nonhex", vec![b'g'; 64]),
    ] {
        fs::write(&inputs.token, &contents).unwrap();
        assert_eq!(f(&inputs.token, inputs.uid), invalid, "{label}");
    }
}

#[cfg(target_vendor = "apple")]
#[test]
fn metrics_token_file_refuses_granting_acl() {
    let inputs = Inputs::new();
    let status = Command::new("chmod")
        .args(["+a", "everyone allow read"])
        .arg(&inputs.token)
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        inputs
            .check(&inputs.token, &inputs.key, inputs.uid)
            .unwrap_err()
            .0,
        "metrics token file custody refused"
    );
}

#[test]
fn tls_key_is_custodied_and_tls_inputs_are_bounded() {
    let inputs = Inputs::new();
    let link = inputs.dir.0.join("key-link");
    symlink(&inputs.key, &link).unwrap();
    assert_eq!(
        inputs
            .check(&inputs.token, &link, inputs.uid)
            .unwrap_err()
            .0,
        "metrics tls key custody refused"
    );
    fs::write(&inputs.key, vec![b'a'; 65_537]).unwrap();
    assert_eq!(
        inputs
            .check(&inputs.token, &inputs.key, inputs.uid)
            .unwrap_err()
            .0,
        "metrics tls key exceeds 65536 bytes"
    );
    fs::write(&inputs.key, b"invalid PEM").unwrap();
    fs::write(&inputs.cert, vec![b'a'; 65_537]).unwrap();
    assert_eq!(
        inputs
            .check(&inputs.token, &inputs.key, inputs.uid)
            .unwrap_err()
            .0,
        "metrics tls certificate exceeds 65536 bytes"
    );
}

#[test]
fn bounded_read_limits_consumed_bytes_and_keeps_io_failure() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }
    assert_eq!(
        read_bounded(Broken, 64).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    let mut source = std::io::Cursor::new([0; 70]);
    assert_eq!(
        read_bounded(&mut source, 64).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(source.position(), 65);
}

fn capture(events: impl FnOnce()) -> String {
    use granary_client::{LogFormat, LogRecord, RecordWriter, closed_subscriber};
    #[derive(Clone, Default)]
    struct Buffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl RecordWriter for Buffer {
        fn write_record(&self, record: &LogRecord) {
            self.0.lock().unwrap().extend_from_slice(record.as_bytes());
        }
    }
    let buffer = Buffer::default();
    let subscriber = closed_subscriber(
        LogFormat::Json,
        tracing_subscriber::EnvFilter::new("error"),
        buffer.clone(),
    );
    tracing::subscriber::with_default(subscriber, events);
    String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap()
}

#[test]
fn startup_and_runtime_events_set_listener_health_and_classify_scrapes() {
    let metrics = metrics();
    let inputs = Inputs::new();
    let valid = inputs
        .check(&inputs.token, &inputs.key, inputs.uid)
        .unwrap();
    let occupied = capture(|| {
        let launched = start_with(Some(valid), &metrics, |_| {
            Err::<(), _>(StartError::Bind(io::ErrorKind::AddrInUse.into()))
        });
        assert!(launched.is_none());
    });
    assert!(occupied.contains("\"event\":\"op.failed\""));
    assert!(occupied.contains("\"kind\":\"session\"") && occupied.contains("\"class\":\"io\""));
    assert!(rendered(&metrics).contains("metrics_listener_up 0\n"));
    record_event(&metrics, Event::Started);
    assert!(rendered(&metrics).contains("metrics_listener_up 1\n"));
    let failure = capture(|| record_event(&metrics, Event::Failed(Failure::Internal)));
    assert!(failure.contains("\"event\":\"metrics.export_failed\""));
    assert!(failure.contains("\"class\":\"internal\""));
    record_event(&metrics, Event::Scrape(ScrapeResult::Cancelled));
    let text = rendered(&metrics);
    assert!(text.contains("metrics_listener_up 0\n"));
    assert!(text.contains("metrics_scrapes_total{result=\"failed\"} 1\n"));
}

#[cfg(target_os = "linux")]
#[test]
fn metrics_linux_occupied_degrades_and_invalid_configuration_refuses() {
    use std::net::TcpListener;
    let held = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = held.local_addr().unwrap();
    let metrics = metrics();
    let inputs = Inputs::new();
    let options = Options {
        endpoint: Some(addr.to_string().parse().unwrap()),
        token: Some(inputs.token.clone()),
        cert: Some(inputs.cert.clone()),
        key: Some(inputs.key.clone()),
    };
    let valid = options.prepare(inputs.uid).unwrap();
    let event = capture(|| assert!(start(valid, &metrics).is_none()));
    assert!(event.contains("\"event\":\"op.failed\""));
    assert!(event.contains("\"kind\":\"session\"") && event.contains("\"class\":\"io\""));
    assert!(rendered(&metrics).contains("metrics_listener_up 0\n"));

    fs::write(&inputs.key, b"invalid PEM").unwrap();
    let event = capture(|| assert!(options.prepare(inputs.uid).is_err()));
    assert!(event.contains("\"class\":\"refused\""));

    fs::write(&inputs.key, TEST_KEY).unwrap();
    drop(held);
    let mut export = None;
    let event = capture(|| {
        export = start(options.prepare(inputs.uid).unwrap(), &metrics);
    });
    assert!(export.is_some());
    assert!(event.is_empty());
    assert!(rendered(&metrics).contains("metrics_listener_up 1\n"));
    drop(export);
}
