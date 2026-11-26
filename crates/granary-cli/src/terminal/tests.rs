// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Watchdogs run outside the thread issuing each terminal diagnostic.
#![cfg(test)]

use super::*;

const WATCHDOG: Duration = WRITE_BOUND.saturating_mul(4);

struct BlockForever(mpsc::Sender<Vec<u8>>);

impl Write for BlockForever {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.send(bytes.to_vec()).expect("write entered");
        loop {
            std::thread::park();
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn blocked_direct_write_returns_within_bound() {
    let (entered, writes) = mpsc::channel();
    let (done, finished) = mpsc::channel();
    std::thread::spawn(move || {
        write_line_to(BlockForever(entered), format_args!("refused"), WRITE_BOUND);
        done.send(()).expect("watchdog alive");
    });
    assert_eq!(
        finished.recv_timeout(WATCHDOG),
        Ok(()),
        "direct write exceeded watchdog"
    );
    assert_eq!(
        writes.try_recv().expect("destination was attempted"),
        b"refused\n"
    );
}

/// Accept only a few bytes per write, and publish the whole buffer on flush.
/// This distinguishes complete delivery from one successful partial write.
struct Draining {
    bytes: Vec<u8>,
    flushed: mpsc::Sender<Vec<u8>>,
}

impl Write for Draining {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let accepted = bytes.len().min(3);
        self.bytes.extend_from_slice(&bytes[..accepted]);
        Ok(accepted)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flushed.send(self.bytes.clone()).expect("reader alive");
        Ok(())
    }
}

#[test]
fn draining_direct_write_delivers_exact_whole_record() {
    let (flushed, records) = mpsc::channel();
    let (done, finished) = mpsc::channel();
    std::thread::spawn(move || {
        let destination = Draining {
            bytes: Vec::new(),
            flushed,
        };
        write_line_to(
            destination,
            format_args!("gran mount: {} — {}", "refused", 17),
            WRITE_BOUND,
        );
        done.send(()).expect("watchdog alive");
    });
    assert_eq!(
        finished.recv_timeout(WATCHDOG),
        Ok(()),
        "draining write exceeded watchdog"
    );
    assert_eq!(
        records.try_recv().expect("flushed before return"),
        "gran mount: refused — 17\n".as_bytes()
    );
}

#[test]
fn blocked_panic_hook_returns_while_sender_is_held() {
    let (entered, writes) = mpsc::channel();
    let (done, finished) = mpsc::channel();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        report_panic(|message| {
            write_line_to(BlockForever(entered), message, WRITE_BOUND);
        });
        // This sender stays live throughout the hook, just as before unwinding.
        sender.send(()).expect("receiver alive");
        done.send(()).expect("watchdog alive");
    });
    assert_eq!(
        finished.recv_timeout(WATCHDOG),
        Ok(()),
        "panic hook exceeded watchdog"
    );
    assert_eq!(receiver.try_recv(), Ok(()), "sender survived the hook");
    assert_eq!(
        writes.try_recv().expect("panic write was attempted"),
        b"gran: panic: internal failure\n"
    );
}

#[test]
fn blocked_typed_refusal_returns_unchanged() {
    use crate::admission::ProcessCredentials;
    use crate::attach::{
        MountOutcome, MountRefusal, mount_attempt_with_credentials, mount_exit_code, parse_mount,
    };

    let (entered, writes) = mpsc::channel();
    let (done, finished) = mpsc::channel();
    std::thread::spawn(move || {
        let args = [
            "vol",
            "/unused",
            "--endpoint",
            "https://h",
            "--pin",
            &crate::tests::a_pin(),
            "--trust-server",
        ];
        let args = args
            .iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>();
        #[cfg(feature = "conformance-breakage")]
        let args = {
            let mut args = args;
            args.extend(
                ["--breakage", granary_fuse::Breakage::TruncateRead.name()]
                    .map(std::ffi::OsString::from),
            );
            args
        };
        let margs = parse_mount(&args).expect("valid mount arguments");
        let credentials = ProcessCredentials {
            ruid: 1000,
            euid: 1001,
            rgid: 2000,
            egid: 2000,
            set_id_tainted: false,
        };
        let outcome =
            mount_attempt_with_credentials(&margs, &credentials, &mut Vec::new(), &|message| {
                write_line_to(BlockForever(entered.clone()), message, WRITE_BOUND);
            });
        done.send(outcome).expect("watchdog alive");
    });
    assert!(
        matches!(
            finished.recv_timeout(WATCHDOG),
            Ok(Err(MountRefusal::SetIdExecution))
        ),
        "typed refusal exceeded watchdog or changed variant"
    );
    let diagnostic = writes.try_recv().expect("refusal write was attempted");
    let credentials = ProcessCredentials {
        ruid: 1000,
        euid: 1001,
        rgid: 2000,
        egid: 2000,
        set_id_tainted: false,
    };
    let reason = crate::admission::set_id_refusal(&credentials).expect("set-ID refusal");
    assert_eq!(diagnostic, format!("gran mount: {reason}\n").as_bytes());
    assert_eq!(
        mount_exit_code(MountOutcome::RuntimeFailure),
        std::process::ExitCode::from(1)
    );
}

static HOOKED: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

fn capture_hooked(message: std::fmt::Arguments<'_>) {
    HOOKED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .extend_from_slice(format!("{message}\n").as_bytes());
}

#[test]
fn the_installed_hook_reports_only_the_fixed_class() {
    // Each test runs in its own process under nextest, so replacing the
    // process-wide hook here cannot reach another test.
    std::panic::set_hook(super::panic_hook(capture_hooked));
    let unwound = std::panic::catch_unwind(|| panic!("sentinel-panic-payload"));
    drop(std::panic::take_hook());
    assert!(unwound.is_err(), "the closure must have panicked");
    let reported = String::from_utf8(
        HOOKED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone(),
    )
    .expect("the report is UTF-8");
    assert!(
        reported == "gran: panic: internal failure\n",
        "panic diagnostic must be fixed"
    );
}

#[test]
fn direct_panic_report_discards_payload_location_and_backtrace() {
    report_panic(|message| {
        assert!(
            message.to_string() == "gran: panic: internal failure",
            "direct panic diagnostic must be fixed"
        );
    });
}

/// Only the parent runs this arm: nextest's ordinary invocation is inert.
#[test]
fn panic_child() {
    if std::env::var_os("GRANARY_TEST_PANIC_CHILD").is_none() {
        return;
    }
    install_panic_hook();
    let _file_logging = std::env::var_os("GRANARY_TEST_PANIC_FILE").map(|path| {
        let path = std::path::PathBuf::from(path);
        let file =
            crate::logging::RotatingFile::open(&path, crate::admission::process_credentials().euid)
                .expect("synthetic log file");
        let settings = crate::logging::Settings {
            filter_source: 1,
            paths: granary_client::LogPaths::Redacted,
            format: granary_client::LogFormat::Json,
            file: Some(path),
            filter: None,
        };
        let (sink, worker) = crate::sink::sink_to(crate::logging::Destination::new(
            std::io::stderr(),
            Some(file),
            settings.format,
        ));
        crate::logging::install(
            &settings,
            tracing_subscriber::EnvFilter::new("off"),
            sink.clone(),
        )
        .expect("subscriber installation");
        (sink, worker)
    });
    if std::env::var_os("GRANARY_TEST_BLOCK_STDERR").is_some() {
        let (acquired, locked) = mpsc::channel();
        std::thread::spawn(move || {
            let filler = vec![b's'; 65536];
            let mut stderr = std::io::stderr().lock();
            acquired.send(()).expect("blocked destination premise");
            // The original handle stays locked, and its unread pipe fills.
            // The panic must exit while this thread is still inside write.
            loop {
                stderr.write_all(&filler).expect("synthetic filler");
            }
        });
        locked
            .recv_timeout(Duration::from_secs(1))
            .expect("original stderr locked");
    }
    let child = std::thread::Builder::new()
        .name("sentinel-thread-name".to_owned())
        .spawn(|| {
            println!("panic-ready");
            panic!("sentinel-panic-payload");
        })
        .expect("synthetic panic thread");
    match child.join() {
        Err(payload) => std::panic::resume_unwind(payload),
        Ok(()) => panic!("panic premise did not fire"),
    }
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "test-only filesystem premise: verify that the child configured its synthetic log file before the panic; never an operator file"
)]
fn blocked_original_stderr_panic_exits_with_and_without_file_logging() {
    let scratch = crate::tests::ScratchDir::new();
    for file_logging in [false, true] {
        let path = scratch.0.join("synthetic.log");
        let mut command =
            std::process::Command::new(std::env::current_exe().expect("test executable"));
        command
            .args(["--exact", "terminal::tests::panic_child", "--nocapture"])
            .env("GRANARY_TEST_PANIC_CHILD", "1")
            .env("GRANARY_TEST_BLOCK_STDERR", "1")
            .env("RUST_LOG", "off")
            .env("RUST_BACKTRACE", "full")
            .env_remove("GRANARY_TEST_PANIC_FILE")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if file_logging {
            command.env("GRANARY_TEST_PANIC_FILE", &path);
        }
        let mut child = command.spawn().expect("blocked panic child");
        let tick = std::sync::Condvar::new();
        let lock = std::sync::Mutex::new(());
        let mut guard = lock.lock().expect("watchdog");
        let mut exited = false;
        for _ in 0..200 {
            if child.try_wait().expect("child status").is_some() {
                exited = true;
                break;
            }
            guard = tick
                .wait_timeout(guard, Duration::from_millis(20))
                .expect("watchdog")
                .0;
        }
        if !exited {
            child.kill().expect("kill only the child this test started");
        }
        let output = child.wait_with_output().expect("child reaped");
        let ready = output
            .stdout
            .windows(b"panic-ready\n".len())
            .any(|w| w == b"panic-ready\n");
        assert_eq!(
            (exited, output.status.code(), ready, path.is_file()),
            (true, Some(101), true, file_logging),
            "blocked panic child must exit within bound after the panic premise"
        );
    }
}

#[test]
fn direct_panic_hook_ignores_backtrace_setting_with_logging_off() {
    for backtrace in ["0", "1", "full"] {
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", "terminal::tests::panic_child", "--nocapture"])
            .env("GRANARY_TEST_PANIC_CHILD", "1")
            .env("RUST_LOG", "off")
            .env("RUST_BACKTRACE", backtrace)
            .output()
            .expect("panic child ran");
        assert!(
            (output.status.code(), output.stderr.as_slice())
                == (Some(101), b"gran: panic: internal failure\n"),
            "panic child must preserve failure and emit only its fixed diagnostic"
        );
    }
}
