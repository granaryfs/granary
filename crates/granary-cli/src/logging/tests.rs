// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for [`super`]: option selection from the three sources, the
//! rotated file, the JSON rendering of the sink's own lines, and the events
//! asserted by name and field through the real sink in both renderings.
//!
//! No test sleeps; every wait is a `Condvar` woken by the event it waits for.
#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use super::*;
use crate::admission::process_credentials;
use crate::sink::{Stream, sink_to};
use crate::tests::ScratchDir;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::{Arc, Condvar, Mutex};

fn os(text: &str) -> OsString {
    OsString::from(text)
}

fn args(list: &[&str]) -> Vec<OsString> {
    list.iter().map(|a| os(a)).collect()
}

fn no_env(_name: &str) -> Option<OsString> {
    None
}

fn no_file(_path: &Path) -> Result<String, String> {
    Err("no configuration file expected".to_owned())
}

fn euid() -> u32 {
    process_credentials().euid
}

/// Every declaration in this module must be classified; adding a carrier
/// requires a fixed Debug body and a fixture, even when it is private.
fn debug_inventory(source: &str) -> Result<usize, &'static str> {
    let words = source
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    let mut types = words
        .windows(2)
        .filter(|pair| matches!(pair[0], "struct" | "enum"))
        .map(|pair| pair[1])
        .collect::<Vec<_>>();
    types.sort_unstable();
    if types
        != [
            "Destination",
            "Flags",
            "Prepared",
            "Raw",
            "RotatingFile",
            "Settings",
        ]
    {
        return Err("unclassified logging type");
    }
    let debug_count = words.iter().filter(|word| **word == "Debug").count();
    if debug_count != 6 {
        return Err("logging Debug inventory changed");
    }
    let compact = source.split_whitespace().collect::<Vec<_>>().join(" ");
    for (head, class) in [
        (
            "impl std::fmt::Debug for Flags",
            "Flags(<log-file>, <configuration>)",
        ),
        (
            "impl std::fmt::Debug for Settings",
            "Settings(<log-file>, <filter>)",
        ),
        (
            "impl std::fmt::Debug for Raw",
            "Raw(<log-file>, <configuration>)",
        ),
        ("impl std::fmt::Debug for RotatingFile", "<log-file>"),
        (
            "impl<E: Write> std::fmt::Debug for Destination<E>",
            "Destination(<log-file>, <writer>)",
        ),
        (
            "impl std::fmt::Debug for Prepared",
            "Prepared(<log-file>, <configuration>, <arguments>)",
        ),
    ] {
        let body = format!(
            "{head} {{ fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{ f.write_str(\"{class}\") }} }}"
        );
        if !compact.contains(&body) {
            return Err("logging Debug must emit only its fixed classes");
        }
    }
    Ok(types.len())
}

#[test]
fn module_debug_inventory_requires_fixed_classes_for_every_carrier() {
    let cwd = std::env::current_dir().expect("runtime directory");
    let file = cwd
        .ancestors()
        .map(|root| root.join("crates/granary-cli/src/logging.rs"))
        .find(|file| file.is_file())
        .expect("logging source is readable from runtime directory");
    let source = std::fs::read_to_string(file).expect("logging source read");
    assert_eq!(debug_inventory(&source), Ok(6), "module Debug inventory");
    let cases = [
        (
            format!("{source}\n// Debug"),
            "logging Debug inventory changed",
        ),
        (
            format!("{source}\nstruct Extra {{ path: PathBuf }}"),
            "unclassified logging type",
        ),
        (
            source.replace("f.write_str(\"<log-file>\")", "self.path.fmt(f)"),
            "logging Debug must emit only its fixed classes",
        ),
    ];
    for (malformed, refusal) in &cases {
        assert_eq!(
            debug_inventory(malformed),
            Err(*refusal),
            "inventory refusal"
        );
    }
    assert_eq!(cases.len(), 3, "nonempty inventory controls");
}

struct DebugBomb(std::sync::atomic::AtomicUsize);

impl std::fmt::Debug for DebugBomb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        f.write_str("<bomb>")
    }
}

impl Write for DebugBomb {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn assert_debug_class(value: &impl std::fmt::Debug, class: &str) {
    assert!(format!("{value:?}") == class, "Debug class mismatch");
    assert!(
        format!("{value:#?}") == class,
        "alternate Debug class mismatch"
    );
}

#[test]
fn logging_debug_retains_no_configuration_paths_arguments_or_nested_state() {
    let flags = Flags {
        paths: Some(os("sentinel-path-policy")),
        format: Some(os("sentinel-format")),
        file: Some(os("sentinel-directory/sentinel-name")),
        filter: Some(os("sentinel-filter")),
        config: Some(os("sentinel-configuration")),
    };
    assert_debug_class(&flags, "Flags(<log-file>, <configuration>)");
    let raw = Raw {
        paths: flags.paths.clone(),
        format: flags.format.clone(),
        file: flags.file.clone(),
        filter: flags.filter.clone(),
    };
    assert_debug_class(&raw, "Raw(<log-file>, <configuration>)");
    let settings = Settings {
        filter_source: 3,
        paths: granary_client::LogPaths::Redacted,
        format: LogFormat::Json,
        file: Some(PathBuf::from("sentinel-directory/sentinel-name")),
        filter: Some(EnvFilter::new("sentinel_filter_target=trace")),
    };
    assert_debug_class(&settings, "Settings(<log-file>, <filter>)");
    let dir = ScratchDir::new();
    let mut file = RotatingFile::open(&dir.0.join("sentinel-name"), euid()).expect("synthetic log");
    file.notice = Some(
        granary_client::OperatorNotice::rotation_failed(FailureClass::Io).render(LogFormat::Text),
    );
    assert_debug_class(&file, "<log-file>");
    let destination = Destination::new(
        DebugBomb(std::sync::atomic::AtomicUsize::new(0)),
        Some(file),
        LogFormat::Json,
    );
    assert_debug_class(&destination, "Destination(<log-file>, <writer>)");
    assert_eq!(
        destination
            .standard_error
            .0
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "nested Debug must not run"
    );
    let prepared = Prepared {
        settings,
        file: destination.file,
        filter: EnvFilter::new("sentinel_filter_target=trace"),
        complaint: Some((
            FilterRejection::Malformed,
            granary_client::FilterDetail::Malformed,
        )),
        args: args(&["sentinel-operand"]),
    };
    assert_debug_class(
        &prepared,
        "Prepared(<log-file>, <configuration>, <arguments>)",
    );
}

// ------------------------------------------------------------------ flags

/// Valid and malformed flag forms, each asserting the refusal text.
#[test]
fn flag_splitting_takes_leading_log_options_and_refuses_malformed_ones() {
    let (flags, rest) = Flags::split(args(&[
        "--log-format",
        "json",
        "--log-file",
        "/x",
        "thresh",
        "--log-format",
    ]))
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(flags.format, Some(os("json")));
    assert_eq!(flags.file, Some(os("/x")));
    assert_eq!(
        rest,
        args(&["thresh", "--log-format"]),
        "only LEADING options are taken"
    );

    let refused: &[(&[&str], &str)] = &[
        (
            &["--log-bogus", "x", "thresh"],
            "--log-bogus: not a logging option",
        ),
        (
            &["--log-format", "json", "--log-format", "text"],
            "--log-format: given more than once",
        ),
        (&["--log-file"], "--log-file: needs a value"),
        (&["--log-config"], "--log-config: needs a value"),
    ];
    for (input, want) in refused {
        let error = Flags::split(args(input)).expect_err(want);
        assert!(
            error.contains(want),
            "{input:?}: want {want:?}, got {error:?}"
        );
    }
    assert!(!refused.is_empty());
}

// ---------------------------------------------------------------- sources

fn resolve_flag(name: &str, value: &str) -> Result<Settings, String> {
    let (flags, _) = Flags::split(args(&[name, value])).unwrap_or_else(|e| panic!("{e}"));
    resolve(&flags, &no_env, &no_file)
}

fn resolve_env(name: &'static str, value: &'static str) -> Result<Settings, String> {
    resolve(
        &Flags::default(),
        &move |n| (n == name).then(|| os(value)),
        &no_file,
    )
}

fn resolve_file(text: &str) -> Result<Settings, String> {
    let (flags, _) = Flags::split(args(&["--log-config", "/etc/gran/log.conf"]))
        .unwrap_or_else(|e| panic!("{e}"));
    resolve(&flags, &no_env, &move |path| {
        assert_eq!(path, Path::new("/etc/gran/log.conf"));
        Ok(text.to_owned())
    })
}

/// A valid and a malformed counterpart per setting for the FLAG source. The
/// refusals name the flag and the expectation; the valid values take effect.
#[test]
fn the_flag_source_accepts_a_valid_value_and_refuses_a_malformed_one() {
    assert_eq!(
        resolve_flag("--log-format", "json").unwrap().format,
        LogFormat::Json
    );
    assert_eq!(
        resolve_flag("--log-file", "/var/log/gran.log")
            .unwrap()
            .file,
        Some(PathBuf::from("/var/log/gran.log"))
    );
    assert_eq!(
        resolve_flag("--log-filter", "granary_client=debug")
            .unwrap()
            .filter
            .unwrap()
            .to_string(),
        "granary_client=debug"
    );
    let refused = [
        (
            "--log-format",
            "xml",
            "--log-format: expected one of text, json; got \"xml\"",
        ),
        (
            "--log-format",
            "JSON",
            "--log-format: expected one of text, json; got \"JSON\"",
        ),
        ("--log-file", "", "--log-file: needs a nonempty file path"),
        (
            "--log-filter",
            "granary_client=loud",
            "--log-filter: \"granary_client=loud\" was not understood",
        ),
        (
            "--log-filter",
            "",
            "--log-filter: needs at least one filter directive",
        ),
    ];
    for (name, value, want) in refused {
        let error = resolve_flag(name, value).expect_err(want);
        assert!(
            error.contains(want),
            "{name} {value:?}: want {want:?}, got {error:?}"
        );
    }
    assert!(!refused.is_empty());
}

#[test]
fn the_environment_source_accepts_a_valid_value_and_refuses_a_malformed_one() {
    assert_eq!(
        resolve_env(ENV_FORMAT, "json").unwrap().format,
        LogFormat::Json
    );
    assert_eq!(
        resolve_env(ENV_FILE, "/var/log/gran.log").unwrap().file,
        Some(PathBuf::from("/var/log/gran.log"))
    );
    assert!(resolve_env(ENV_FILTER, "warn").unwrap().filter.is_some());
    let refused = [
        (
            ENV_FORMAT,
            "xml",
            "GRANARY_LOG_FORMAT: expected one of text, json; got \"xml\"",
        ),
        (
            ENV_FORMAT,
            "",
            "GRANARY_LOG_FORMAT: expected one of text, json; got \"\"",
        ),
        (ENV_FILE, "", "GRANARY_LOG_FILE: needs a nonempty file path"),
        (
            ENV_FILTER,
            "granary_client=loud",
            "GRANARY_LOG_FILTER: \"granary_client=loud\" was not understood",
        ),
    ];
    for (name, value, want) in refused {
        let error = resolve_env(name, value).expect_err(want);
        assert!(
            error.contains(want),
            "{name} {value:?}: want {want:?}, got {error:?}"
        );
    }
    assert!(!refused.is_empty());
}

#[test]
fn the_file_source_accepts_a_valid_value_and_refuses_a_malformed_one() {
    let ok = resolve_file("# comment\n\nformat = json\nfile = /var/log/gran.log\nfilter = warn\n")
        .unwrap();
    assert_eq!(ok.format, LogFormat::Json);
    assert_eq!(ok.file, Some(PathBuf::from("/var/log/gran.log")));
    assert!(ok.filter.is_some());
    let refused = [
        (
            "format = xml\n",
            "/etc/gran/log.conf: format: expected one of text, json; got \"xml\"",
        ),
        (
            "file =\n",
            "/etc/gran/log.conf: file: needs a nonempty file path",
        ),
        (
            "filter = granary_client=loud\n",
            "/etc/gran/log.conf: filter: \"granary_client=loud\" was not understood",
        ),
        ("colour = blue\n", "log configuration: unknown key"),
        (
            "format = json\nformat = text\n",
            "line 2: format given more than once",
        ),
        ("format json\n", "line 1: expected `key = value`"),
    ];
    for (text, want) in refused {
        let error = resolve_file(text).expect_err(want);
        assert!(
            error.contains(want),
            "{text:?}: want {want:?}, got {error:?}"
        );
    }
    assert!(!refused.is_empty());
}

/// The configuration file's path itself comes from a flag or the environment;
/// an empty one is refused and an unreadable one carries the reader's text.
#[test]
fn the_configuration_file_path_is_refused_when_empty_or_unreadable() {
    let (flags, _) = Flags::split(args(&["--log-config", ""])).unwrap();
    let error = resolve(&flags, &no_env, &no_file).unwrap_err();
    assert!(
        error.contains("--log-config: needs a nonempty file path"),
        "{error}"
    );
    let from_env = resolve(
        &Flags::default(),
        &|n| (n == ENV_CONFIG).then(|| os("/nope")),
        &|_| Err("/nope: cannot open the log configuration".to_owned()),
    )
    .unwrap_err();
    assert!(
        from_env.contains("cannot open the log configuration"),
        "{from_env}"
    );
}

/// Flag beats environment beats file; the default is text on standard error.
#[test]
fn precedence_is_flag_then_environment_then_file_then_default() {
    let (flags, _) = Flags::split(args(&["--log-format", "text", "--log-config", "/c"])).unwrap();
    let env = |n: &str| match n {
        ENV_FORMAT => Some(os("json")),
        ENV_FILE => Some(os("/env.log")),
        _ => None,
    };
    let read = |_: &Path| Ok("format = json\nfile = /file.log\nfilter = debug\n".to_owned());
    let all = resolve(&flags, &env, &read).unwrap();
    assert_eq!(
        all.format,
        LogFormat::Text,
        "flag beats environment and file"
    );
    assert_eq!(
        all.file,
        Some(PathBuf::from("/env.log")),
        "environment beats file"
    );
    assert_eq!(
        all.filter.unwrap().to_string(),
        "debug",
        "file when nothing above it"
    );
    let none = resolve(&Flags::default(), &no_env, &no_file).unwrap();
    assert_eq!(
        (none.format, none.file, none.filter.is_none()),
        (LogFormat::Text, None, true)
    );
}

/// A malformed value is refused even when a higher source overrides it: the
/// plausible wrong implementation validates only the winner.
#[test]
fn a_malformed_value_is_refused_even_when_a_higher_source_overrides_it() {
    let (flags, _) = Flags::split(args(&["--log-format", "json"])).unwrap();
    let error = resolve(&flags, &|n| (n == ENV_FORMAT).then(|| os("xml")), &no_file).unwrap_err();
    assert!(
        error.contains("GRANARY_LOG_FORMAT: expected one of text, json"),
        "{error}"
    );
}

#[test]
fn a_value_that_is_not_utf8_is_refused() {
    use std::os::unix::ffi::OsStringExt as _;
    let bad = OsString::from_vec(vec![0x66, 0xff]);
    let error = resolve(
        &Flags::default(),
        &move |n| (n == ENV_FORMAT).then(|| bad.clone()),
        &no_file,
    )
    .unwrap_err();
    assert!(
        error.contains("GRANARY_LOG_FORMAT: the value is not valid UTF-8"),
        "{error}"
    );
}

// ----------------------------------------------------- configuration file

fn write_config(dir: &ScratchDir, name: &str, text: &str, mode: u32) -> PathBuf {
    let path = dir.0.join(name);
    std::fs::write(&path, text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

#[test]
fn the_configuration_reader_enforces_custody() {
    let dir = ScratchDir::new();
    let good = write_config(&dir, "good.conf", "format = json\n", 0o600);
    assert_eq!(read_config_file(&good, euid()).unwrap(), "format = json\n");

    let loose = write_config(&dir, "loose.conf", "format = json\n", 0o666);
    let link = dir.0.join("link.conf");
    std::os::unix::fs::symlink(&good, &link).unwrap();
    let big = write_config(
        &dir,
        "big.conf",
        &"#".repeat(usize::try_from(CONFIG_MAX_BYTES).unwrap() + 1),
        0o600,
    );
    let refused: [(PathBuf, u32, &str); 6] = [
        (loose, euid(), "writable by group or other"),
        (
            good.clone(),
            euid().wrapping_add(1),
            "not owned by the user running gran",
        ),
        (dir.0.clone(), euid(), "not a regular file"),
        (link, euid(), "cannot open the log configuration"),
        (big, euid(), "larger than 16384 bytes"),
        (
            dir.0.join("absent.conf"),
            euid(),
            "cannot open the log configuration",
        ),
    ];
    for (path, uid, want) in &refused {
        let error = read_config_file(path, *uid).expect_err(want);
        assert!(
            error.contains(want),
            "{path:?}: want {want:?}, got {error:?}"
        );
    }
}

// ------------------------------------------------------------ rotated file

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

fn generation_of(path: &Path, n: u32) -> PathBuf {
    generation(path, n)
}

#[test]
fn the_rotated_file_rolls_over_at_its_bound_and_keeps_a_fixed_count() {
    let dir = ScratchDir::new();
    let path = dir.0.join("gran.log");
    let mut file = RotatingFile::open_with(&path, euid(), 20, 2).unwrap();
    for message in [
        "aaaaaaaa\n",
        "bbbbbbbb\n",
        "cccccccc\n",
        "dddddddd\n",
        "eeeeeeee\n",
    ] {
        file.write_all(message.as_bytes()).unwrap();
    }
    file.flush().unwrap();
    // 9 bytes per message, bound 20: two fit per file.
    assert_eq!(read(&path), "eeeeeeee\n");
    assert_eq!(read(&generation_of(&path, 1)), "cccccccc\ndddddddd\n");
    assert_eq!(read(&generation_of(&path, 2)), "aaaaaaaa\nbbbbbbbb\n");
    assert!(
        !generation_of(&path, 3).exists(),
        "keep=2 never creates a third generation"
    );
}

#[test]
fn the_rotated_file_never_splits_a_message_and_takes_an_oversize_one_whole() {
    let dir = ScratchDir::new();
    let path = dir.0.join("gran.log");
    let mut file = RotatingFile::open_with(&path, euid(), 10, 1).unwrap();
    file.write_all(b"small\n").unwrap();
    file.write_all(b"a message far longer than the bound\n")
        .unwrap();
    assert_eq!(read(&path), "a message far longer than the bound\n");
    assert_eq!(read(&generation_of(&path, 1)), "small\n");
}

#[test]
fn the_rotated_file_is_private_and_resumes_the_length_of_an_existing_file() {
    let dir = ScratchDir::new();
    let path = dir.0.join("gran.log");
    {
        let mut file = RotatingFile::open_with(&path, euid(), 20, 1).unwrap();
        file.write_all(b"0123456789\n").unwrap();
    }
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let mut file = RotatingFile::open_with(&path, euid(), 20, 1).unwrap();
    file.write_all(b"0123456789\n").unwrap();
    assert_eq!(
        read(&generation_of(&path, 1)),
        "0123456789\n",
        "11 resumed + 11 > 20 rotates"
    );
    assert_eq!(read(&path), "0123456789\n");
}

#[test]
fn the_rotated_file_refuses_a_link_a_stranger_file_and_a_loose_mode() {
    let dir = ScratchDir::new();
    let target = dir.0.join("target.log");
    std::fs::write(&target, "").unwrap();
    let link = dir.0.join("link.log");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let loose = dir.0.join("loose.log");
    std::fs::write(&loose, "").unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o664)).unwrap();
    let own = dir.0.join("own.log");
    std::fs::write(&own, "").unwrap();
    std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o600)).unwrap();
    let refused: [(&Path, u32); 3] = [
        (&link, euid()),
        (&loose, euid()),
        (&own, euid().wrapping_add(1)),
    ];
    for (path, uid) in refused {
        let error = RotatingFile::open_with(path, uid, 100, 1).expect_err("must be refused");
        assert!(!error.to_string().is_empty(), "{path:?}");
    }
    assert_eq!(
        RotatingFile::open_with(&loose, euid(), 100, 1)
            .unwrap_err()
            .to_string(),
        "the log file is writable by group or other"
    );
    assert_eq!(
        RotatingFile::open_with(&own, euid().wrapping_add(1), 100, 1)
            .unwrap_err()
            .to_string(),
        "the log file is not owned by the user running gran"
    );
    assert_eq!(read(&target), "", "nothing was written through the link");
}

// ------------------------------------------------------- the JSON rendering

#[test]
fn worker_notices_have_only_fixed_templates_and_typed_counts() {
    let notice =
        granary_client::OperatorNotice::rotation_failed(FailureClass::Io).render(LogFormat::Json);
    let text = std::str::from_utf8(notice.as_bytes()).unwrap();
    assert!(text.contains("<log-file>") && text.contains("cannot rotate"));
    let loss = granary_client::OperatorNotice::sink_loss(12, 5, 3).render(LogFormat::Json);
    assert_eq!(
        std::str::from_utf8(loss.as_bytes()).unwrap(),
        "{\"event\":\"log.sink_loss\",\"telemetry_dropped\":12,\"protected_lost\":5,\"local_lost\":3}\n"
    );
}

// ------------------------------------------- through the real sink, end to end

/// A destination whose writes block until released, and which records what it
/// is given: the only way to make real backpressure without a real pipe.
#[derive(Clone, Default)]
struct Gate {
    state: Arc<(Mutex<bool>, Condvar)>,
    written: Arc<Mutex<Vec<u8>>>,
}

impl Gate {
    fn closed() -> Self {
        Self::default()
    }

    fn open(&self) {
        let (lock, cv) = &*self.state;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }

    fn text(&self) -> String {
        String::from_utf8(self.written.lock().unwrap().clone()).unwrap()
    }
}

impl Write for Gate {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let (lock, cv) = &*self.state;
        let mut open = lock.lock().unwrap();
        while !*open {
            open = cv.wait(open).unwrap();
        }
        drop(open);
        self.written.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Fill a held sink past its bounds with tagged telemetry and protected
/// messages, release it, and read what reached the destination.
fn overflow(format: LogFormat) -> (String, usize, usize) {
    let gate = Gate::closed();
    let (sink, mut worker) = sink_to(Destination::new(gate.clone(), None, format));
    let telemetry = crate::sink::CAPACITY + 100;
    let protected = 100;
    {
        let mut writer = sink.writer(Stream::Telemetry);
        for n in 0..telemetry {
            match format {
                LogFormat::Json => writeln!(writer, "{{\"tag\":\"T:{n}\"}}").unwrap(),
                LogFormat::Text => writeln!(writer, "T:{n}").unwrap(),
            }
        }
        let mut writer = sink.writer(Stream::Protected);
        for n in 0..protected {
            writeln!(writer, "P:{n}").unwrap();
        }
    }
    gate.open();
    worker.close();
    (gate.text(), telemetry, protected)
}

fn delivered(text: &str, tag: &str) -> usize {
    text.lines()
        .filter(|l| l.contains(&format!("\"{tag}:")) || l.starts_with(&format!("{tag}:")))
        .count()
}

/// The sink's loss report, driven for real: the JSON stream has every line an
/// object, and the loss events' counts add up with what was delivered to the
/// number submitted, for both streams. The text stream keeps the legacy line.
#[test]
fn a_real_sink_overflow_is_reported_as_loss_events_in_json_and_text() {
    let (json, telemetry, protected) = overflow(LogFormat::Json);
    assert!(
        json.lines()
            .all(|l| (l.starts_with('{') && l.ends_with('}')) || l.starts_with("P:")),
        "every JSON line is an object: {json}"
    );
    let (mut dropped, mut lost) = (0_usize, 0_usize);
    for line in json.lines().filter(|l| l.contains(SINK_LOSS)) {
        let counts = line
            .trim_start_matches("{\"event\":\"log.sink_loss\",\"telemetry_dropped\":")
            .trim_end_matches('}');
        let (t, p) = counts.split_once(",\"protected_lost\":").unwrap();
        dropped += t.parse::<usize>().unwrap();
        let (p, local) = p.split_once(",\"local_lost\":").unwrap();
        assert_eq!(local, "0");
        lost += p.parse::<usize>().unwrap();
    }
    assert!(
        dropped >= 100 && lost > 0,
        "the overflow must have lost both kinds: {dropped} {lost}"
    );
    assert_eq!(
        delivered(&json, "T") + dropped,
        telemetry,
        "telemetry: delivered + reported == submitted"
    );
    assert_eq!(
        delivered(&json, "P") + lost,
        protected,
        "protected: delivered + reported == submitted"
    );

    let (text, ..) = overflow(LogFormat::Text);
    assert!(
        text.contains("telemetry line(s) dropped under backpressure"),
        "{text}"
    );
    assert!(
        text.contains("PROTECTED message(s) LOST under backpressure"),
        "{text}"
    );
    assert!(
        !text.contains(SINK_LOSS),
        "text keeps the legacy line, not the event"
    );
}

/// The destination routes: the file when there is one, standard error when
/// not; text passes through unchanged.
#[test]
fn the_destination_writes_the_file_when_given_one_and_standard_error_otherwise() {
    let dir = ScratchDir::new();
    let path = dir.0.join("gran.log");
    let stderr = Gate::default();
    stderr.open();
    let file = RotatingFile::open(&path, euid()).unwrap();
    let mut to_file = Destination::new(stderr.clone(), Some(file), LogFormat::Text);
    to_file.write_all(b"to the file\n").unwrap();
    to_file.flush().unwrap();
    assert_eq!(
        (read(&path), stderr.text()),
        ("to the file\n".to_owned(), String::new())
    );

    let mut to_stderr = Destination::new(stderr.clone(), None, LogFormat::Json);
    to_stderr.write_all(b"plain\n").unwrap();
    assert_eq!(stderr.text(), "plain\n");
    assert_eq!(read(&path), "to the file\n");
}

/// The vocabulary through the production assembly: client events, the real
/// subscriber builder, the real sink and the destination, in both renderings,
/// with the operation's id on each.
#[test]
fn seeded_events_reach_the_destination_with_their_names_fields_and_id_in_both_renderings() {
    use granary_client::{
        FailureClass, OperationKind, RetryReason, op_failed, op_retry, operation_span,
    };
    let id = granary_client::CorrelationId::draw(&mut Fixed).unwrap();
    for format in [LogFormat::Json, LogFormat::Text] {
        let gate = Gate::default();
        gate.open();
        let (sink, mut worker) = sink_to(Destination::new(gate.clone(), None, format));
        let filter = EnvFilter::try_new("info").unwrap();
        let dispatch = granary_client::subscriber(format, filter, sink);
        tracing::subscriber::with_default(dispatch, || {
            operation_span(OperationKind::Commit, &id).in_scope(|| {
                op_retry(OperationKind::Commit, 2, RetryReason::Conflict);
                op_failed(OperationKind::Commit, FailureClass::Refused);
            });
        });
        worker.close();
        let out = gate.text();
        let needles: &[&str] = match format {
            LogFormat::Json => &[
                "\"event\":\"op.retry\"",
                "\"kind\":\"commit\"",
                "\"attempt\":2",
                "\"reason\":\"conflict\"",
                "\"event\":\"op.failed\"",
                "\"class\":\"refused\"",
                "\"op\":\"cor-0102030405060708\"",
            ],
            LogFormat::Text => &[
                "event=\"op.retry\"",
                "attempt=2",
                "reason=\"conflict\"",
                "event=\"op.failed\"",
                "class=\"refused\"",
                "op=\"cor-0102030405060708\"",
            ],
        };
        for needle in needles {
            assert!(out.contains(needle), "{format:?}: missing {needle}\n{out}");
        }
        assert_eq!(out.lines().count(), 2, "{format:?}: {out}");
    }
}

struct Fixed;

impl granary_core::secure_random::SecureRandom for Fixed {
    fn fill(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), granary_core::secure_random::EntropyUnavailable> {
        for (slot, byte) in dest.iter_mut().zip(1_u8..) {
            *slot = byte;
        }
        Ok(())
    }
}

/// The session span carries a fresh id on its events.
#[test]
fn the_session_span_gives_each_event_a_correlation_id() {
    let gate = Gate::default();
    gate.open();
    let (sink, mut worker) = sink_to(Destination::new(gate.clone(), None, LogFormat::Json));
    let dispatch =
        granary_client::subscriber(LogFormat::Json, EnvFilter::try_new("debug").unwrap(), sink);
    tracing::subscriber::with_default(dispatch, || {
        let span = session_span().expect("the test host has entropy");
        let _entered = span.enter();
        granary_client::log_config(LogFormat::Json, LogDestination::File);
    });
    worker.close();
    let out = gate.text();
    assert!(out.contains("\"event\":\"log.config\""), "{out}");
    assert!(
        out.contains("\"format\":\"json\"") && out.contains("\"destination\":\"file\""),
        "{out}"
    );
    assert!(out.contains("\"op\":\"cor-"), "{out}");
    assert!(out.contains("\"kind\":\"session\""), "{out}");
}

/// The JSON rendering runs on the sink's worker, so a destination that never
/// drains blocks that one thread and nothing else: events are emitted without
/// waiting, and the close returns within its bound instead of hanging. The
/// plausible wrong implementation renders (or writes) on the producer's
/// thread, which this test would then never finish.
#[test]
fn a_blocked_destination_blocks_neither_the_producers_nor_the_close_in_json() {
    let gate = Gate::closed();
    let (sink, mut worker) = sink_to(Destination::new(gate.clone(), None, LogFormat::Json));
    let dispatch =
        granary_client::subscriber(LogFormat::Json, EnvFilter::try_new("info").unwrap(), sink);
    crate::tests::within_deadline(
        "emitting JSON events into a blocked destination",
        move || {
            tracing::subscriber::with_default(dispatch, || {
                for attempt in 1..=50 {
                    granary_client::op_retry(
                        granary_client::OperationKind::Commit,
                        attempt,
                        granary_client::RetryReason::Transient,
                    );
                }
            });
        },
    );
    crate::tests::within_deadline(
        "closing a sink whose JSON destination is blocked",
        move || {
            worker.close();
        },
    );
    assert_eq!(
        gate.text(),
        "",
        "nothing could be written while the destination was held"
    );
}

// ------------------------------------------ a failing file never ends logging

fn open_gate() -> Gate {
    let gate = Gate::default();
    gate.open();
    gate
}

/// A rotated file whose write always fails: its descriptor is read-only.
fn unwritable_file(dir: &ScratchDir) -> RotatingFile {
    let path = dir.0.join("gran.log");
    std::fs::write(&path, "").unwrap();
    RotatingFile {
        path: path.clone(),
        file: File::open(&path).unwrap(),
        written: 0,
        rotate_at: 1024,
        max: 1024,
        keep: 1,
        euid: euid(),
        failure_reported: false,
        notice: None,
        paths: granary_client::LogPaths::Redacted,
        history: granary_client::BundleHistory::default(),
        format: LogFormat::Text,
    }
}

#[test]
fn a_failed_rotation_keeps_appending_reports_once_and_retries_at_the_next_bound() {
    let dir = ScratchDir::new();
    let path = dir.0.join("gran.log");
    // A directory where generation 1 must go makes the rename fail.
    std::fs::create_dir(generation(&path, 1)).unwrap();
    let stderr = open_gate();
    let file = RotatingFile::open_with(&path, euid(), 20, 1).unwrap();
    let mut destination = Destination::new(stderr.clone(), Some(file), LogFormat::Text);
    for message in [
        "aaaaaaaa\n",
        "bbbbbbbb\n",
        "cccccccc\n",
        "dddddddd\n",
        "eeeeeeee\n",
    ] {
        destination
            .write_all(message.as_bytes())
            .unwrap_or_else(|e| panic!("{message:?}: {e}"));
    }
    let logged = read(&path);
    for message in ["aaaaaaaa", "bbbbbbbb", "cccccccc", "dddddddd", "eeeeeeee"] {
        assert!(
            logged.contains(message),
            "{message} must still be logged: {logged}"
        );
    }
    assert_eq!(
        logged.matches("cannot rotate the log file").count(),
        1,
        "one report for a failure that repeats: {logged}"
    );
    assert_eq!(stderr.text(), "", "the file is still the destination");

    // The cause goes away; the next bound rotates and re-arms the report.
    std::fs::remove_dir(generation(&path, 1)).unwrap();
    for message in ["ffffffff\n", "gggggggg\n", "hhhhhhhh\n"] {
        destination.write_all(message.as_bytes()).unwrap();
    }
    assert!(
        generation(&path, 1).is_file(),
        "the rotation is retried and succeeds"
    );
    assert!(read(&generation(&path, 1)).contains("aaaaaaaa"));
}

#[test]
fn a_failed_file_write_falls_back_to_standard_error_and_reports_once_there() {
    for format in [LogFormat::Text, LogFormat::Json] {
        let dir = ScratchDir::new();
        let stderr = open_gate();
        let mut destination = Destination::new(stderr.clone(), Some(unwritable_file(&dir)), format);
        destination
            .write_all(b"first\n")
            .expect("a failure the destination can absorb is not an error");
        destination.write_all(b"second\n").unwrap();
        let text = stderr.text();
        assert_eq!(
            text.matches("cannot write the log file").count(),
            1,
            "{format:?}: reported once: {text}"
        );
        assert!(text.contains("first") && text.contains("second"), "{text}");
        assert!(
            text.find("cannot write").unwrap() < text.find("first").unwrap(),
            "the report precedes the line that triggered it: {text}"
        );
        if format == LogFormat::Json {
            assert!(
                text.lines()
                    .filter(|l| l.contains("log.line"))
                    .all(|l| l.starts_with('{') && l.ends_with('}')),
                "{text}"
            );
        }
        assert_eq!(
            read(&dir.0.join("gran.log")),
            "",
            "nothing reached the file"
        );
    }
}

/// Through the real sink: after the file has failed, a protected message is
/// still delivered, and the worker has not given up.
#[test]
fn a_protected_message_after_a_file_failure_is_still_delivered() {
    for rename_failure in [false, true] {
        let dir = ScratchDir::new();
        let stderr = open_gate();
        let (file, destination_path) = if rename_failure {
            let path = dir.0.join("gran.log");
            std::fs::create_dir(generation(&path, 1)).unwrap();
            (RotatingFile::open_with(&path, euid(), 16, 1).unwrap(), path)
        } else {
            (unwritable_file(&dir), dir.0.join("gran.log"))
        };
        let (sink, mut worker) = sink_to(Destination::new(
            stderr.clone(),
            Some(file),
            LogFormat::Text,
        ));
        for n in 0..4 {
            writeln!(sink.writer(Stream::Telemetry), "telemetry {n} padding").unwrap();
        }
        writeln!(
            sink.writer(Stream::Protected),
            "PROTECTED after the failure"
        )
        .unwrap();
        worker.close();
        let delivered = format!("{}{}", stderr.text(), read(&destination_path));
        assert!(
            delivered.contains("PROTECTED after the failure"),
            "rename_failure={rename_failure}: {delivered}"
        );
    }
}

// --------------------------------------------- named pipes and hard links

fn mkfifo(path: &Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success(), "mkfifo {path:?}");
}

/// Run `work` on its own thread and give it a bound: a path that blocks on a
/// named pipe fails the test instead of hanging it.
fn within_bound<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    let (done, result) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ignored = done.send(work());
    });
    result
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the open waited on a named pipe")
}

#[test]
fn a_named_pipe_as_the_configuration_file_is_refused_without_waiting() {
    let dir = ScratchDir::new();
    let fifo = dir.0.join("log.conf");
    mkfifo(&fifo);
    std::fs::set_permissions(&fifo, std::fs::Permissions::from_mode(0o600)).unwrap();
    let uid = euid();
    let error = within_bound(move || read_config_file(&fifo, uid)).expect_err("a pipe is refused");
    assert!(error.contains("not a regular file"), "{error}");
}

#[test]
fn a_named_pipe_as_the_log_file_is_refused_without_waiting() {
    let dir = ScratchDir::new();
    let fifo = dir.0.join("gran.log");
    mkfifo(&fifo);
    std::fs::set_permissions(&fifo, std::fs::Permissions::from_mode(0o600)).unwrap();
    let uid = euid();

    // No reader holds the pipe: a blocking write open would wait forever.
    let path = fifo.clone();
    let error = within_bound(move || RotatingFile::open_with(&path, uid, 100, 1))
        .expect_err("a pipe is refused");
    assert_eq!(error.to_string(), "the log file is not a regular file");

    // A reader holds it: the open succeeds and the file type refuses it.
    let reader = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&fifo)
        .unwrap();
    let path = fifo.clone();
    let error = within_bound(move || RotatingFile::open_with(&path, uid, 100, 1))
        .expect_err("a pipe is refused");
    assert_eq!(error.to_string(), "the log file is not a regular file");
    drop(reader);
}

#[test]
fn a_log_file_opened_without_blocking_still_takes_writes() {
    let dir = ScratchDir::new();
    let path = dir.0.join("gran.log");
    let mut file = RotatingFile::open_with(&path, euid(), 100, 1).unwrap();
    file.write_all(b"written\n").unwrap();
    file.flush().unwrap();
    assert_eq!(read(&path), "written\n");
}

#[test]
fn a_log_file_with_another_hard_link_is_refused() {
    let dir = ScratchDir::new();
    let own = dir.0.join("own.log");
    std::fs::write(&own, "").unwrap();
    std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o600)).unwrap();
    // Control: a file with one link opens.
    RotatingFile::open_with(&own, euid(), 100, 1).unwrap();
    std::fs::hard_link(&own, dir.0.join("other-name")).unwrap();
    let error = RotatingFile::open_with(&own, euid(), 100, 1).expect_err("two links");
    assert_eq!(
        error.to_string(),
        "the log file has more than one hard link"
    );
}

// ------------------------------------------------------------ set-ID runs

fn credentials(set_id_tainted: bool) -> ProcessCredentials {
    ProcessCredentials {
        ruid: euid(),
        euid: euid(),
        rgid: 0,
        egid: 0,
        set_id_tainted,
    }
}

fn prepared(credentials: &ProcessCredentials, list: &[&str], rust_log: Option<&str>) -> Prepared {
    prepare_with(
        credentials,
        false,
        args(list),
        crate::env_filter_from,
        rust_log.map_or(Err(std::env::VarError::NotPresent), |v| Ok(v.to_owned())),
        &|name| (name == ENV_FORMAT).then(|| os("json")),
    )
    .unwrap_or_else(|_| panic!("preparation was refused"))
}

#[test]
fn a_set_id_process_ignores_the_logging_environment_and_rust_log() {
    // Control: an ordinary process takes both.
    let ordinary = prepared(&credentials(false), &["thresh", "f"], Some("trace"));
    assert_eq!(ordinary.settings.format, LogFormat::Json);
    assert_eq!(ordinary.filter.to_string(), "trace");

    let tainted = prepared(&credentials(true), &["thresh", "f"], Some("trace"));
    assert_eq!(tainted.settings.format, LogFormat::Text);
    assert_eq!(tainted.filter.to_string(), "info", "the default filter");
    assert!(tainted.complaint.is_none());
}

#[test]
fn a_set_id_process_drops_the_logging_flags_unread_and_dispatches_the_verb() {
    let list = [
        "--log-format",
        "json",
        "--log-file",
        "/x/never",
        "thresh",
        "f",
    ];
    let tainted = prepared(&credentials(true), &list, None);
    assert_eq!(tainted.args, args(&["thresh", "f"]));
    assert_eq!(tainted.settings.format, LogFormat::Text);
    assert!(tainted.settings.file.is_none() && tainted.file.is_none());
}

#[test]
fn production_subscriber_refuses_foreign_fields_and_keeps_protected_results_off_the_log_file() {
    let dir = ScratchDir::new();
    let path = dir.0.join("synthetic-log-name");
    let stderr = open_gate();
    let file = RotatingFile::open(&path, euid()).unwrap();
    let (sink, mut worker) = sink_to(Destination::new(
        stderr.clone(),
        Some(file),
        LogFormat::Json,
    ));
    let subscriber =
        granary_client::subscriber(LogFormat::Json, EnvFilter::new("trace"), sink.clone());
    tracing::subscriber::with_default(subscriber, || {
        tracing::warn!(target: "granary_client::event", secret = "synthetic-secret", "synthetic-secret");
        granary_client::op_failed(OperationKind::Commit, FailureClass::Io);
        writeln!(sink.protected_writer(), "synthetic-secret local result").unwrap();
    });
    worker.close();
    let telemetry = read(&path);
    assert!(
        telemetry.contains("op.failed"),
        "legitimate production control"
    );
    assert!(
        telemetry.contains("unregistered_callsite"),
        "foreign production control"
    );
    assert!(
        !telemetry.contains("synthetic-secret"),
        "foreign fields and local results never enter telemetry"
    );
    assert_eq!(stderr.text(), "synthetic-secret local result\n");
}

#[test]
fn rotation_notice_is_projected_before_retention_without_the_source_name() {
    let dir = ScratchDir::new();
    let path = dir.0.join("synthetic-secret-log-name");
    let mut file = RotatingFile::open_with(&path, euid(), 1, 1).unwrap();
    std::fs::create_dir(generation(&path, 1)).unwrap();
    file.rotate();
    let notice = file
        .take_notice()
        .expect("failed rotation retains a notice");
    let text = std::str::from_utf8(notice.as_bytes()).unwrap();
    assert!(text.contains("<log-file>") && text.contains("cannot rotate"));
    assert!(
        !text.contains("synthetic-secret"),
        "retained notice contains only projected classes"
    );
}

#[test]
fn sink_loss_fields_match_the_document_and_three_stream_accounting() {
    let row = "| `log.sink_loss` | sink | `telemetry_dropped`, `protected_lost`, `local_lost` |";
    let document = include_str!("../../../../docs/operating-client-observability.md");
    assert_eq!(
        document
            .lines()
            .filter(|line| line.starts_with(row))
            .count(),
        1,
        "sink loss document table changed"
    );
    let output = granary_client::OperatorNotice::sink_loss(2, 3, 5).render(LogFormat::Json);
    assert_eq!(
        std::str::from_utf8(output.as_bytes()).unwrap(),
        "{\"event\":\"log.sink_loss\",\"telemetry_dropped\":2,\"protected_lost\":3,\"local_lost\":5}\n",
        "local loss encoded count changed"
    );
}

#[test]
fn every_typed_local_report_stays_on_original_stderr_in_both_formats_and_with_logging_off() {
    use granary_client::{
        Age, CloseStage, CorrelationId, EquivocationNotice, LocalConflictStatus, LocalReport,
        LocalReporter as _,
    };
    use granary_core::hash::GrainId;
    use granary_core::root::VolumeName;
    let volume = VolumeName::new("synthetic-local-volume".to_owned()).unwrap();
    let root = GrainId::of(b"synthetic-wire");
    let cached = GrainId::of(b"synthetic-cached");
    let operation =
        CorrelationId::draw(&mut granary_net::secure_random::OsSecureRandom::new()).unwrap();
    let conflict =
        LocalConflictStatus::new(Path::new("synthetic-conflict-path"), operation).unwrap();
    let reports = [
        LocalReport::pinned(volume.clone(), 13, root, cached),
        LocalReport::history(),
        LocalReport::equivocation(EquivocationNotice::new(volume.clone(), 13, root, cached)),
        LocalReport::cache_unverified(volume.clone(), 13),
        LocalReport::cache_degraded(),
        LocalReport::signature_unchecked(),
        LocalReport::degraded(volume, 13, Age::Seconds(17)),
        LocalReport::close_warning(
            CloseStage::RefusedMount,
            FailureClass::Io,
            Some(libc::ENOSPC),
        ),
        LocalReport::close_warning(CloseStage::Shutdown, FailureClass::Io, None),
        LocalReport::close_warning(CloseStage::Drop, FailureClass::Refused, None),
        LocalReport::conflict(conflict),
    ];
    let expected: Vec<u8> = reports
        .iter()
        .flat_map(|report| report.render().as_bytes().to_vec())
        .collect();
    for format in [LogFormat::Text, LogFormat::Json] {
        for filter in ["trace", "off"] {
            for with_file in [false, true] {
                let dir = ScratchDir::new();
                let path = dir.0.join("telemetry.log");
                let file = with_file.then(|| RotatingFile::open(&path, euid()).unwrap());
                let original = Gate::default();
                original.open();
                let (sink, mut worker) = sink_to(Destination::new(original.clone(), file, format));
                let subscriber =
                    granary_client::subscriber(format, EnvFilter::new(filter), sink.clone());
                tracing::subscriber::with_default(subscriber, || {
                    let mut writer = sink.protected_writer();
                    for report in &reports {
                        writer.report(report);
                    }
                });
                worker.close();
                assert_eq!(
                    original.text().as_bytes(),
                    expected,
                    "Local text/fields changed under output policy"
                );
                if with_file {
                    assert_eq!(read(&path), "", "local report teed into log file");
                }
            }
        }
    }
}

#[test]
fn captured_stderr_owns_a_duplicate_and_drains_while_the_rust_stderr_lock_is_held() {
    use granary_client::LocalReporter as _;
    use std::os::fd::AsRawFd as _;
    let stderr = std::io::stderr();
    let original = capture_stderr(&std::io::stderr()).unwrap();
    assert_ne!(
        original.as_raw_fd(),
        libc::STDERR_FILENO,
        "stderr descriptor was not duplicated"
    );
    let _held = stderr.lock();
    let (sink, mut worker) = sink_to(Destination::new(original, None, LogFormat::Text));
    sink.protected_writer()
        .report(&granary_client::LocalReport::history());
    worker.close();
    assert!(
        worker.drained(),
        "captured descriptor still waits for the Rust stderr lock"
    );
}

#[test]
fn path_policy_validates_all_sources_precedence_and_fresh_defaults() {
    use granary_client::LogPaths;
    for value in ["redacted", "full"] {
        let expected = LogPaths::parse(value).unwrap();
        assert_eq!(resolve_flag("--log-paths", value).unwrap().paths, expected);
        assert_eq!(resolve_env(ENV_PATHS, value).unwrap().paths, expected);
        assert_eq!(
            resolve_file(&format!("paths = {value}\n")).unwrap().paths,
            expected
        );
    }
    let (flags, _) = Flags::split(args(&[
        "--log-paths",
        "redacted",
        "--log-config",
        "synthetic-config",
    ]))
    .unwrap();
    let selected = resolve(
        &flags,
        &|name| (name == ENV_PATHS).then(|| os("full")),
        &|_| Ok("paths = full\n".to_owned()),
    )
    .unwrap();
    assert_eq!(selected.paths, LogPaths::Redacted);
    let refused = resolve(
        &flags,
        &|name| (name == ENV_PATHS).then(|| os("synthetic-invalid")),
        &|_| Ok("paths = full\n".to_owned()),
    )
    .expect_err("invalid overridden environment activated policy");
    assert!(
        refused == "log paths (environment): expected redacted or full",
        "invalid overridden environment activated policy"
    );
    let refused = resolve(&flags, &no_env, &|_| {
        Ok("paths = synthetic-invalid\n".to_owned())
    })
    .expect_err("invalid overridden file activated policy");
    assert!(
        refused == "log paths (configuration): expected redacted or full",
        "invalid overridden file activated policy"
    );
    let (flags, _) = Flags::split(args(&["--log-config", "synthetic-config"])).unwrap();
    assert_eq!(
        resolve(
            &flags,
            &|name| (name == ENV_PATHS).then(|| os("redacted")),
            &|_| Ok("paths = full\n".to_owned())
        )
        .unwrap()
        .paths,
        LogPaths::Redacted
    );
    assert_eq!(
        resolve(&Flags::default(), &no_env, &no_file).unwrap().paths,
        LogPaths::Redacted
    );
}

#[test]
fn set_id_path_policy_is_unread_and_mount_helper_uses_the_normal_environment_route() {
    use granary_client::LogPaths;
    let tainted = prepare_with(
        &credentials(true),
        false,
        args(&[
            "--log-paths",
            "synthetic-invalid",
            "--log-paths",
            "full",
            "thresh",
            "f",
        ]),
        crate::env_filter_from,
        Err(std::env::VarError::NotPresent),
        &|_| panic!("set-ID logging reader called"),
    )
    .unwrap();
    assert_eq!(tainted.settings.paths, LogPaths::Redacted);
    assert_eq!(tainted.args, args(&["thresh", "f"]));
    let mounted = prepare_with(
        &credentials(false),
        true,
        args(&["synthetic-volume", "synthetic-mountpoint"]),
        crate::env_filter_from,
        Err(std::env::VarError::NotPresent),
        &|name| (name == ENV_PATHS).then(|| os("full")),
    )
    .unwrap();
    assert_eq!(mounted.settings.paths, LogPaths::Full);
}

#[test]
fn worker_path_notices_and_loss_feed_independent_redacted_bundle_input() {
    use granary_client::{BundleHistory, LogPaths, OperatorNotice};
    let path = Path::new("synthetic-log-directory/synthetic-log-name");
    for format in [LogFormat::Text, LogFormat::Json] {
        for notice in [
            OperatorNotice::rotation_failed(FailureClass::Io),
            OperatorNotice::write_failed(FailureClass::Io),
        ] {
            let (redacted, redacted_bundle) =
                notice.project_log_file(format, LogPaths::Redacted, path);
            let (full, full_bundle) = notice.project_log_file(format, LogPaths::Full, path);
            assert!(
                !std::str::from_utf8(redacted.as_bytes())
                    .unwrap()
                    .contains("synthetic-"),
                "default worker notice retained path bytes"
            );
            assert!(
                std::str::from_utf8(full.as_bytes())
                    .unwrap()
                    .contains("synthetic-log-directory/synthetic-log-name"),
                "worker notice lost full-path policy"
            );
            assert!(
                redacted_bundle.as_bytes() == full_bundle.as_bytes(),
                "worker bundle inherited log policy"
            );
        }
        let dir = ScratchDir::new();
        let history = BundleHistory::default();
        let stderr = open_gate();
        let file = unwritable_file(&dir);
        let supplied = file.path.to_str().unwrap().to_owned();
        let mut destination = Destination::with_policy(
            stderr.clone(),
            Some(file),
            format,
            LogPaths::Full,
            history.clone(),
        );
        destination.write_all(b"safe telemetry\n").unwrap();
        let snapshot = history.snapshot();
        assert!(
            snapshot.records().len() == 1
                && std::str::from_utf8(snapshot.records()[0].as_bytes())
                    .unwrap()
                    .contains("\"path\":\"<log-file>\""),
            "write fallback did not feed redacted history"
        );
        assert!(
            stderr.text().contains(&supplied),
            "file fallback did not honor ordinary-path opt-in"
        );
        let gate = Gate::closed();
        let (sink, mut worker) = sink_to(Destination::with_policy(
            gate.clone(),
            None,
            format,
            LogPaths::Full,
            history.clone(),
        ));
        for _ in 0..crate::sink::CAPACITY + 100 {
            writeln!(sink.writer(Stream::Telemetry), "safe telemetry").unwrap();
        }
        gate.open();
        worker.close();
        assert!(worker.drained(), "worker completion premise failed");
        let snapshot = history.snapshot();
        assert!(
            snapshot
                .records()
                .iter()
                .any(|record| std::str::from_utf8(record.as_bytes())
                    .unwrap()
                    .contains("log.sink_loss")),
            "sink loss never reached independent bundle input"
        );
    }
}

#[test]
fn rotation_projects_before_retaining_notice_and_feeds_redacted_history() {
    for format in [LogFormat::Text, LogFormat::Json] {
        for policy in [
            granary_client::LogPaths::Redacted,
            granary_client::LogPaths::Full,
        ] {
            let dir = ScratchDir::new();
            let path = dir.0.join("synthetic-log-name");
            std::fs::create_dir(generation(&path, 1)).unwrap();
            let history = granary_client::BundleHistory::default();
            let mut file = RotatingFile::open_with(&path, euid(), 8, 1).unwrap();
            file.format = format;
            file.paths = policy;
            file.history = history.clone();
            file.write_all(b"aaaaaa\n").unwrap();
            file.write_all(b"bbbbbb\n").unwrap();
            let retained = file.notice.as_ref().expect("rotation failure premise");
            let retained = std::str::from_utf8(retained.as_bytes()).unwrap();
            if policy == granary_client::LogPaths::Full {
                assert!(
                    retained.contains(path.to_str().unwrap()),
                    "retained rotation notice lost authorized path"
                );
            } else {
                assert!(
                    !retained.contains("synthetic-log-name"),
                    "retained rotation notice contains raw path"
                );
            }
            let snapshot = history.snapshot();
            assert!(
                snapshot.records().len() == 1,
                "rotation failed to feed bundle input before retention"
            );
            let bundle = std::str::from_utf8(snapshot.records()[0].as_bytes()).unwrap();
            assert!(
                bundle.contains("\"path\":\"<log-file>\"")
                    && !bundle.contains("synthetic-log-name"),
                "rotation history inherited log policy"
            );
        }
    }
}

use crate::tests::observability_scan as scan;

#[test]
fn worker_notice_seeded_sweep_checks_log_file_class_and_independent_bundle() {
    use granary_client::{LogPaths, OperatorNotice};
    for format in [LogFormat::Text, LogFormat::Json] {
        for notice in [
            OperatorNotice::rotation_failed(FailureClass::Io),
            OperatorNotice::write_failed(FailureClass::Io),
            OperatorNotice::sink_loss(7, 11, 13),
        ] {
            let mut bundles = Vec::new();
            for policy in [LogPaths::Redacted, LogPaths::Full] {
                let (log, bundle) =
                    notice.project_log_file(format, policy, Path::new(scan::ORDINARY[0]));
                let record = String::from_utf8(log.as_bytes().to_vec()).unwrap();
                assert_eq!(
                    scan::scan(std::slice::from_ref(&record), scan::SECRETS),
                    Ok(()),
                    "worker free-text forwarding leaked seeded material"
                );
                if policy == LogPaths::Redacted {
                    assert_eq!(
                        scan::scan(&[record], scan::ORDINARY),
                        Ok(()),
                        "worker default path absence"
                    );
                }
                let bundle = String::from_utf8(bundle.as_bytes().to_vec()).unwrap();
                assert_eq!(
                    scan::scan(std::slice::from_ref(&bundle), scan::ORDINARY),
                    Ok(()),
                    "worker bundle path absence"
                );
                assert_eq!(
                    scan::scan(std::slice::from_ref(&bundle), scan::SECRETS),
                    Ok(()),
                    "worker bundle secret absence"
                );
                bundles.push(bundle);
            }
            assert!(bundles[0] == bundles[1], "worker bundle policy changed");
        }
    }
}

#[test]
fn equals_spellings_of_every_logging_option_get_the_same_unknown_option_refusal() {
    for option in [
        "--log-format=json",
        "--log-file=synthetic-name",
        "--log-filter=info",
        "--log-config=synthetic-name",
        "--log-paths=full",
        "--log-paths=redacted",
        "--log-pathsfull",
    ] {
        let refused = Flags::split(args(&[option, "thresh"])).expect_err("equals spelling");
        assert!(
            refused
                == format!(
                    "{option}: not a logging option; the options are {}",
                    FLAGS.join(", ")
                ),
            "wrong refusal for the equals spelling"
        );
    }
    assert!(
        Flags::split(args(&["--log-paths", "full", "thresh"])).is_ok(),
        "the separate-word spelling stays accepted"
    );
}

#[test]
fn bundle_filter_source_tracks_precedence_and_default() {
    let mut cases = 0;
    for (flag, environment, file, expected) in [
        (false, false, false, 1),
        (false, false, true, 5),
        (false, true, true, 4),
        (true, true, true, 3),
    ] {
        let flags = Flags {
            filter: flag.then(|| os("info")),
            config: file.then(|| os("synthetic-log-config")),
            ..Flags::default()
        };
        let settings = resolve(
            &flags,
            &|name| (environment && name == ENV_FILTER).then(|| os("warn")),
            &|_| Ok("filter = error".to_owned()),
        )
        .unwrap();
        assert_eq!(
            settings.filter_source, expected,
            "support filter source did not preserve precedence"
        );
        cases += 1;
    }
    assert_eq!(cases, 4);
}

#[test]
fn bundle_filter_source_retains_rust_log_after_prepare_consumes_filter() {
    let prepared = prepared(&credentials(false), &["mount"], Some("warn"));
    assert!(
        (
            prepared.settings.filter_source,
            prepared.settings.filter.is_none()
        ) == (2, true),
        "RUST_LOG provenance disappeared with consumed filter"
    );
}

#[test]
fn bundle_filter_source_uses_accepted_rust_log_or_default() {
    use std::os::unix::ffi::OsStringExt as _;
    let cases = [
        (Ok("warn".to_owned()), 2, "warn", None),
        (
            Ok("invalid-target=loud".to_owned()),
            1,
            "info",
            Some(FilterRejection::Malformed),
        ),
        (Ok(String::new()), 1, "info", None),
        (
            Err(std::env::VarError::NotUnicode(OsString::from_vec(vec![
                0xff,
            ]))),
            1,
            "info",
            Some(FilterRejection::NotUnicode),
        ),
        (Err(std::env::VarError::NotPresent), 1, "info", None),
    ];
    let mut defaults = 0;
    for (raw, source, filter, rejection) in cases {
        let prepared = prepare_with(
            &credentials(false),
            false,
            args(&["mount"]),
            crate::env_filter_from,
            raw,
            &no_env,
        )
        .unwrap();
        assert_eq!(
            (
                prepared.settings.filter_source,
                prepared.filter.to_string(),
                prepared.complaint.map(|(reason, _)| reason)
            ),
            (source, filter.to_owned(), rejection),
            "support source must name the filter actually in force"
        );
        defaults += usize::from(source == 1);
    }
    assert_eq!(defaults, 4, "default-filter controls must execute");
}

#[test]
fn bundle_filter_source_keeps_configured_filter_over_rust_log() {
    let dir = ScratchDir::new();
    let config = write_config(&dir, "filter.conf", "filter = error\n", 0o600);
    let mut cases = 0;
    for (options, environment, source) in [
        (args(&["--log-filter", "error", "mount"]), None, 3),
        (args(&["mount"]), Some(ENV_FILTER), 4),
        (
            vec![os("--log-config"), config.into_os_string(), os("mount")],
            None,
            5,
        ),
    ] {
        let prepared = prepare_with(
            &credentials(false),
            false,
            options,
            crate::env_filter_from,
            Ok("warn".to_owned()),
            &|name| (environment == Some(name)).then(|| os("error")),
        )
        .unwrap();
        assert_eq!(
            (
                prepared.settings.filter_source,
                prepared.filter.to_string(),
                prepared.complaint.is_none()
            ),
            (source, "error".to_owned(), true),
            "configured filter source must survive RUST_LOG"
        );
        cases += 1;
    }
    assert_eq!(cases, 3, "configured-source controls must execute");
}
