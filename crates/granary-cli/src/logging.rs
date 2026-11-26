// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! How `gran` selects and renders its log output: the format (text or JSON),
//! the destination (standard error or a size-rotated file) and the filter,
//! each chosen by a flag, an environment variable or a configuration file.
//! `docs/operating-client-observability.md` states the operator-facing rules.
//!
//! **Nothing here changes the sink.** The destination built here is the
//! writer the existing bounded sink drains: the sink's queue, its worker,
//! its loss counting and its close bound are unchanged, and a blocking or
//! failing file only ever blocks or ends that one worker thread. A producer
//! never waits on the file, exactly as it never waits on standard error.
//!
//! **A malformed value is refused, never accepted or rounded.** Every source
//! is validated even when a higher-precedence source overrides it, so a typo
//! in the environment is found the day it is made, not the day the flag that
//! hid it is dropped. The one legacy exception is `RUST_LOG`, whose reading
//! stays in `main` (an unreadable value runs the default filter and says so
//! with a `log.filter_rejected` event).
//!
//! Precedence, per setting: flag, then environment, then configuration file,
//! then the default.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read as _, Write};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use granary_client::{
    CorrelationId, FailureClass, FilterRejection, LogDestination, LogFormat, OperationKind,
};
use granary_net::secure_random::OsSecureRandom;
use tracing_subscriber::EnvFilter;

use crate::admission::{ProcessCredentials, process_credentials};

/// The flags this module owns, in the order the usage text lists them.
pub(crate) const FLAGS: [&str; 5] = [
    "--log-format",
    "--log-file",
    "--log-filter",
    "--log-config",
    "--log-paths",
];

pub(crate) const ENV_FORMAT: &str = "GRANARY_LOG_FORMAT";
pub(crate) const ENV_FILE: &str = "GRANARY_LOG_FILE";
pub(crate) const ENV_FILTER: &str = "GRANARY_LOG_FILTER";
pub(crate) const ENV_CONFIG: &str = "GRANARY_LOG_CONFIG";
pub(crate) const ENV_PATHS: &str = "GRANARY_LOG_PATHS";

/// A rotated file rolls over before a message that would take it past this.
pub(crate) const ROTATE_BYTES: u64 = 8 * 1024 * 1024;

/// How many rotated generations are kept beside the live file
/// (`<file>.1` is the newest).
pub(crate) const ROTATE_KEEP: u32 = 3;

/// The configuration file is read up to this many bytes; a larger file is
/// refused rather than truncated.
pub(crate) const CONFIG_MAX_BYTES: u64 = 16 * 1024;

/// The event name the JSON stream gives a sink loss report.
#[cfg(test)]
pub(crate) const SINK_LOSS: &str = "log.sink_loss";

/// What the command line named, before any validation.
#[derive(Default)]
pub(crate) struct Flags {
    paths: Option<OsString>,
    format: Option<OsString>,
    file: Option<OsString>,
    filter: Option<OsString>,
    config: Option<OsString>,
}

impl std::fmt::Debug for Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Flags(<log-file>, <configuration>)")
    }
}

impl Flags {
    /// Take the leading `--log-*` options off `args`, returning them and the
    /// remaining arguments (the verb and its own operands).
    ///
    /// Only the four names in [`FLAGS`] are accepted; any other `--log-`
    /// option, a repeated one and one without a value are refused.
    pub(crate) fn split(args: Vec<OsString>) -> Result<(Self, Vec<OsString>), String> {
        let mut flags = Self::default();
        let mut rest = args.into_iter().peekable();
        while let Some(name) = rest
            .peek()
            .and_then(|first| first.to_str())
            .filter(|name| name.starts_with("--log-"))
            .map(str::to_owned)
        {
            let slot = match name.as_str() {
                "--log-format" => &mut flags.format,
                "--log-file" => &mut flags.file,
                "--log-filter" => &mut flags.filter,
                "--log-config" => &mut flags.config,
                "--log-paths" => &mut flags.paths,
                _ => {
                    return Err(format!(
                        "{name}: not a logging option; the options are {}",
                        FLAGS.join(", ")
                    ));
                }
            };
            if slot.is_some() {
                return Err(if name == "--log-paths" {
                    "log paths (flag): repeated option".to_owned()
                } else {
                    format!("{name}: given more than once")
                });
            }
            rest.next();
            if name == "--log-paths"
                && rest
                    .peek()
                    .is_none_or(|next| next.to_str().is_some_and(|s| s.starts_with("--")))
            {
                return Err("log paths (flag): missing value".to_owned());
            }
            *slot = Some(
                rest.next()
                    .ok_or_else(|| format!("{name}: needs a value"))?,
            );
        }
        Ok((flags, rest.collect()))
    }
}

/// The settings a run uses.
pub(crate) struct Settings {
    pub(crate) paths: granary_client::LogPaths,
    pub(crate) filter_source: u8,
    pub(crate) format: LogFormat,
    pub(crate) file: Option<PathBuf>,
    /// A validated filter from a flag, the environment or the file; `None`
    /// leaves the choice to `RUST_LOG`. [`prepare`] takes it out.
    pub(crate) filter: Option<EnvFilter>,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Settings(<log-file>, <filter>)")
    }
}

/// One source's raw values.
#[derive(Default)]
struct Raw {
    paths: Option<OsString>,
    format: Option<OsString>,
    file: Option<OsString>,
    filter: Option<OsString>,
}

impl std::fmt::Debug for Raw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Raw(<log-file>, <configuration>)")
    }
}

/// Resolve the settings from the three sources.
///
/// `env` reads an environment variable; `read` returns a configuration
/// file's text (the real reader checks custody, a test's returns a fixture).
///
/// # Errors
/// The first malformed value found, with the source and key it came from.
pub(crate) fn resolve(
    flags: &Flags,
    env: &dyn Fn(&str) -> Option<OsString>,
    read: &dyn Fn(&Path) -> Result<String, String>,
) -> Result<Settings, String> {
    let from_flags = Raw {
        paths: flags.paths.clone(),
        format: flags.format.clone(),
        file: flags.file.clone(),
        filter: flags.filter.clone(),
    };
    let from_env = Raw {
        paths: env(ENV_PATHS),
        format: env(ENV_FORMAT),
        file: env(ENV_FILE),
        filter: env(ENV_FILTER),
    };
    let config_path = flags
        .config
        .clone()
        .map(|p| ("--log-config".to_owned(), p))
        .or_else(|| env(ENV_CONFIG).map(|p| (ENV_CONFIG.to_owned(), p)));
    let (config_label, from_file) = match config_path {
        None => (String::new(), Raw::default()),
        Some((origin, path)) => {
            if path.is_empty() {
                return Err(format!("{origin}: needs a nonempty file path"));
            }
            let path = PathBuf::from(path);
            let text = read(&path)?;
            let label = path.display().to_string();
            (label.clone(), parse_config(&label, &text)?)
        }
    };

    let sources: [(&Raw, [String; 3]); 3] = [
        (&from_flags, FLAGS_KEYS.map(str::to_owned)),
        (&from_env, ENV_KEYS.map(str::to_owned)),
        (
            &from_file,
            FILE_KEYS.map(|key| format!("{config_label}: {key}")),
        ),
    ];

    let mut paths = None;
    let mut format = None;
    let mut file = None;
    let mut filter = None;
    let mut filter_source = None;
    for (((raw, names), source), tag) in sources
        .iter()
        .zip(["flag", "environment", "configuration"])
        .zip([3, 4, 5])
    {
        if let Some(value) = &raw.paths {
            let text = value
                .to_str()
                .ok_or_else(|| format!("log paths ({source}): value is not valid UTF-8"))?;
            let parsed = granary_client::LogPaths::parse(text)
                .ok_or_else(|| format!("log paths ({source}): expected redacted or full"))?;
            paths.get_or_insert(parsed);
        }
        if let Some(value) = &raw.format {
            let parsed = parse_format(&names[0], value)?;
            format.get_or_insert(parsed);
        }
        if let Some(value) = &raw.file {
            let parsed = parse_file(&names[1], value)?;
            file.get_or_insert(parsed);
        }
        if let Some(value) = &raw.filter {
            let parsed = parse_filter(&names[2], value)?;
            filter.get_or_insert(parsed);
            filter_source.get_or_insert(tag);
        }
    }
    Ok(Settings {
        filter_source: filter_source.unwrap_or(1),
        paths: paths.unwrap_or_default(),
        format: format.unwrap_or(LogFormat::Text),
        file,
        filter,
    })
}

// The names a refusal quotes, per source and per setting: format, file,
// filter. The file source prefixes the key with the file's path.
const FLAGS_KEYS: [&str; 3] = ["--log-format", "--log-file", "--log-filter"];
const ENV_KEYS: [&str; 3] = [ENV_FORMAT, ENV_FILE, ENV_FILTER];
const FILE_KEYS: [&str; 3] = ["format", "file", "filter"];

fn text_of<'a>(name: &str, value: &'a OsStr) -> Result<&'a str, String> {
    value
        .to_str()
        .ok_or_else(|| format!("{name}: the value is not valid UTF-8"))
}

fn parse_format(name: &str, value: &OsStr) -> Result<LogFormat, String> {
    let text = text_of(name, value)?;
    LogFormat::parse(text).ok_or_else(|| {
        let members: Vec<&str> = LogFormat::ALL.iter().map(|m| m.as_str()).collect();
        format!(
            "{name}: expected one of {}; got {text:?}",
            members.join(", ")
        )
    })
}

fn parse_file(name: &str, value: &OsStr) -> Result<PathBuf, String> {
    if value.is_empty() {
        return Err(format!("{name}: needs a nonempty file path"));
    }
    if value.as_bytes().contains(&0) {
        return Err(format!("{name}: a file path cannot contain a NUL byte"));
    }
    Ok(PathBuf::from(value))
}

/// Parse a filter value strictly: the whole value must be understood. (The
/// lenient `RUST_LOG` reader keeps the directives it can read; a value an
/// operator typed into one of these three sources is refused instead.)
fn parse_filter(name: &str, value: &OsStr) -> Result<EnvFilter, String> {
    let text = text_of(name, value)?;
    if text.is_empty() {
        return Err(format!("{name}: needs at least one filter directive"));
    }
    EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
        .parse(text)
        .map_err(|error| format!("{name}: {text:?} was not understood ({error})"))
}

/// Parse a configuration file: `key = value` lines, `#` comments and blank
/// lines. Keys are `format`, `file` and `filter`; an unknown or repeated key
/// is refused.
fn parse_config(label: &str, text: &str) -> Result<Raw, String> {
    let mut raw = Raw::default();
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            if line.split_whitespace().next() == Some("paths") {
                return Err("log paths (configuration): expected redacted or full".to_owned());
            }
            if !matches!(
                line.split_whitespace().next(),
                Some("format" | "file" | "filter")
            ) {
                return Err("log configuration: unknown key".to_owned());
            }
            return Err(format!("{label}: line {number}: expected `key = value`"));
        };
        let (key, value) = (key.trim(), OsString::from(value.trim()));
        let slot = match key {
            "format" => &mut raw.format,
            "file" => &mut raw.file,
            "filter" => &mut raw.filter,
            "paths" => &mut raw.paths,
            _ => {
                return Err("log configuration: unknown key".to_owned());
            }
        };
        if slot.is_some() {
            if key == "paths" {
                return Err("log paths (configuration): repeated key".to_owned());
            }
            return Err(format!(
                "{label}: line {number}: {key} given more than once"
            ));
        }
        *slot = Some(value);
    }
    Ok(raw)
}

/// Read a configuration file, refusing one another user could have written.
///
/// A log file path or filter taken from a file a stranger can edit would let
/// that stranger choose where a privileged `gran` appends, so the file must
/// be a regular file, owned by the effective user, and not writable by group
/// or other. It is opened without following a final symbolic link and without
/// blocking (so a named pipe at the path is refused by the file-type check
/// instead of waiting for a writer), and read to a fixed bound.
///
/// # Errors
/// A text naming the file and the reason.
#[expect(
    clippy::disallowed_methods,
    reason = "this is the one place the configuration file is opened: O_NOFOLLOW and \
              O_NONBLOCK, then a custody check on the opened handle, then a bounded read; the file is operator \
              configuration outside any store or cache directory"
)]
pub(crate) fn read_config_file(path: &Path, euid: u32) -> Result<String, String> {
    let shown = path.display();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("{shown}: cannot open the log configuration: {e}"))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("{shown}: cannot inspect the log configuration: {e}"))?;
    if !meta.is_file() {
        return Err(format!(
            "{shown}: the log configuration is not a regular file"
        ));
    }
    if meta.uid() != euid {
        return Err(format!(
            "{shown}: the log configuration is not owned by the user running gran"
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{shown}: the log configuration is writable by group or other"
        ));
    }
    let mut text = String::new();
    file.take(CONFIG_MAX_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("{shown}: cannot read the log configuration: {e}"))?;
    if text.len() as u64 > CONFIG_MAX_BYTES {
        return Err(format!(
            "{shown}: the log configuration is larger than {CONFIG_MAX_BYTES} bytes"
        ));
    }
    Ok(text)
}

/// A log file that rolls over by size.
///
/// It is written only from the sink's worker thread. Before a message that
/// would take the file past its bound, `<file>` becomes `<file>.1`, `.1`
/// becomes `.2`, and so on up to the kept count (the oldest is overwritten),
/// and a fresh `<file>` is opened. A message is never split across files. One
/// process owns a log file; two writers rotating the same path would trade
/// each other's generations.
///
/// **A failed rotation never ends logging.** When a rename or the reopen
/// fails, the current file keeps taking messages, the failure is held as a
/// notice for the [`Destination`] to report once, and the next attempt waits
/// for the file to grow by another bound.
pub(crate) struct RotatingFile {
    path: PathBuf,
    file: File,
    written: u64,
    /// The length at which the next message rolls the file over. It is `max`
    /// for a file that rotated (or was opened), and `max` past the length at
    /// the failure after a failed rotation.
    rotate_at: u64,
    max: u64,
    keep: u32,
    euid: u32,
    /// Set after a failed rotation that has been reported, cleared by a
    /// rotation that succeeds, so a persistent failure is one report.
    failure_reported: bool,
    notice: Option<granary_client::LogRecord>,
    paths: granary_client::LogPaths,
    history: granary_client::BundleHistory,
    format: LogFormat,
}

impl std::fmt::Debug for RotatingFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<log-file>")
    }
}

impl RotatingFile {
    /// Open (creating, mode 0600) the live file with the shipped bounds.
    pub(crate) fn open(path: &Path, euid: u32) -> std::io::Result<Self> {
        Self::open_with(path, euid, ROTATE_BYTES, ROTATE_KEEP)
    }

    /// Open with explicit bounds (a test uses small ones).
    pub(crate) fn open_with(path: &Path, euid: u32, max: u64, keep: u32) -> std::io::Result<Self> {
        let (file, written) = open_log(path, euid, 0)?;
        Ok(Self {
            path: path.to_owned(),
            file,
            written,
            rotate_at: max,
            max,
            keep,
            euid,
            failure_reported: false,
            notice: None,
            paths: granary_client::LogPaths::Redacted,
            history: granary_client::BundleHistory::default(),
            format: LogFormat::Text,
        })
    }

    /// Roll the generations over. On failure the current file stays in use,
    /// the next attempt is one bound further on, and the first failure since
    /// the last success leaves a notice.
    fn rotate(&mut self) {
        if let Ok((file, written)) = open_log(&self.path, self.euid, self.keep) {
            self.file = file;
            self.written = written;
            self.rotate_at = self.max;
            self.failure_reported = false;
        } else {
            self.rotate_at = self.written.saturating_add(self.max);
            if !self.failure_reported {
                self.failure_reported = true;
                let (log, bundle) =
                    granary_client::OperatorNotice::rotation_failed(FailureClass::Io)
                        .project_log_file(self.format, self.paths, &self.path);
                self.history.record(bundle);
                self.notice = Some(log);
            }
        }
    }

    /// The report a failed rotation left, if it has not been taken yet.
    fn take_notice(&mut self) -> Option<granary_client::LogRecord> {
        self.notice.take()
    }

    /// Append a report line to the current file without counting it toward
    /// the next rotation: the bound measures messages, and a report written
    /// after a failed rotation must not bring the retry forward.
    fn append_notice(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.file.write_all(bytes)?;
        let len = bytes.len() as u64;
        self.written = self.written.saturating_add(len);
        self.rotate_at = self.rotate_at.saturating_add(len);
        Ok(())
    }
}

/// The path of rotated generation `n` of `path`.
fn generation(path: &Path, n: u32) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{n}"));
    PathBuf::from(name)
}

/// Open the live log file, first rolling the existing generations over when
/// `keep` is nonzero. Returns the handle and the file's current length.
///
/// The open does not follow a final symbolic link, does not block (a named
/// pipe at the path is refused by the file-type check, or by the open itself
/// when no reader holds it) and creates the file private to the user; an
/// existing file must be a regular file with one link, owned by the effective
/// user and not writable by group or other.
#[expect(
    clippy::disallowed_methods,
    reason = "this is the one place the log file is renamed and opened: O_NOFOLLOW, O_NONBLOCK \
              and 0600 on create, then a custody check on the opened handle; the path is \
              operator configuration and is not inside any store or cache directory"
)]
fn open_log(path: &Path, euid: u32, keep: u32) -> std::io::Result<(File, u64)> {
    let refuse =
        |why: &str| std::io::Error::new(std::io::ErrorKind::PermissionDenied, why.to_owned());
    if keep > 0 {
        for n in (1..keep).rev() {
            ignore_missing(std::fs::rename(
                generation(path, n),
                generation(path, n + 1),
            ))?;
        }
        ignore_missing(std::fs::rename(path, generation(path, 1)))?;
    }
    let file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| {
            // A named pipe nobody is reading refuses a non-blocking write open
            // with ENXIO; name it as the refusal it is.
            if e.raw_os_error() == Some(libc::ENXIO) {
                refuse("the log file is not a regular file")
            } else {
                e
            }
        })?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(refuse("the log file is not a regular file"));
    }
    if meta.nlink() != 1 {
        return Err(refuse("the log file has more than one hard link"));
    }
    if meta.uid() != euid {
        return Err(refuse("the log file is not owned by the user running gran"));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(refuse("the log file is writable by group or other"));
    }
    // O_NONBLOCK stays set: on a regular file, which the checks above have
    // just established, reads and writes never return EAGAIN for it, so it
    // changes nothing about how the handle behaves.
    Ok((file, meta.len()))
}

fn ignore_missing(result: std::io::Result<()>) -> std::io::Result<()> {
    match result {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

impl Write for RotatingFile {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.write_all(bytes)?;
        Ok(bytes.len())
    }

    /// One message, whole, into the current file, rolling over first when it
    /// would not fit and the file already holds something. A rotation that
    /// fails is reported through [`RotatingFile::take_notice`] and the message
    /// still goes to the current file; only a failed write is an error.
    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let len = bytes.len() as u64;
        if self.written > 0 && self.written.saturating_add(len) > self.rotate_at {
            self.rotate();
        }
        self.file.write_all(bytes)?;
        self.written = self.written.saturating_add(len);
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

/// The destination the sink's worker drains: standard error, or a rotated
/// file, accepting pre-encoded telemetry unchanged.
///
/// Protected results remain local on original stderr. Worker notices use fixed
/// templates and scalar encoders; no destination parses or redacts text.
///
/// **A file that fails never ends logging.** A failed rotation is reported
/// once and the current file keeps taking messages. A failed write to the file
/// moves the destination to standard error for the rest of the process, says
/// so once there, and writes the message that failed to standard error. Only a
/// failure of standard error itself is an error to the sink's worker.
pub(crate) struct Destination<E: Write> {
    standard_error: E,
    file: Option<RotatingFile>,
    format: LogFormat,
    paths: granary_client::LogPaths,
    history: granary_client::BundleHistory,
}

impl<E: Write> std::fmt::Debug for Destination<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Destination(<log-file>, <writer>)")
    }
}

impl<E: Write> Destination<E> {
    #[cfg(test)]
    pub(crate) fn new(standard_error: E, file: Option<RotatingFile>, format: LogFormat) -> Self {
        Self::with_policy(
            standard_error,
            file,
            format,
            granary_client::LogPaths::Redacted,
            granary_client::BundleHistory::default(),
        )
    }

    pub(crate) fn with_policy(
        standard_error: E,
        mut file: Option<RotatingFile>,
        format: LogFormat,
        paths: granary_client::LogPaths,
        history: granary_client::BundleHistory,
    ) -> Self {
        if let Some(file) = file.as_mut() {
            file.paths = paths;
            file.history = history.clone();
            file.format = format;
        }
        Self {
            standard_error,
            file,
            format,
            paths,
            history,
        }
    }

    pub(crate) fn history(&self) -> granary_client::BundleHistory {
        self.history.clone()
    }

    pub(crate) fn format(&self) -> LogFormat {
        self.format
    }

    /// Protected operator results go to the owned original stderr.
    /// Only pre-encoded telemetry goes to the selected log destination.
    pub(crate) fn write_stream(
        &mut self,
        stream: crate::sink::Stream,
        bytes: &[u8],
    ) -> std::io::Result<()> {
        match stream {
            crate::sink::Stream::Protected | crate::sink::Stream::Local => {
                self.standard_error.write_all(bytes)?;
                let _best_effort = self.standard_error.flush();
                Ok(())
            }
            crate::sink::Stream::Telemetry => {
                self.write_all(bytes)?;
                let _best_effort = self.flush();
                Ok(())
            }
        }
    }
}

impl<E: Write> Write for Destination<E> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.write_all(bytes)?;
        Ok(bytes.len())
    }

    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let Some(file) = self.file.as_mut() else {
            return self.standard_error.write_all(bytes);
        };
        if file.write_all(bytes).is_ok() {
            if let Some(notice) = file.take_notice() {
                let rendered = notice;
                if let Some(file) = self.file.as_mut() {
                    // A failure to record the notice surfaces as the
                    // next message's write failure and its fallback.
                    let _best_effort = file.append_notice(rendered.as_bytes());
                }
            }
            Ok(())
        } else {
            let (rendered, bundle) = granary_client::OperatorNotice::write_failed(FailureClass::Io)
                .project_log_file(self.format, self.paths, &file.path);
            self.history.record(bundle);
            self.file = None;
            self.standard_error.write_all(rendered.as_bytes())?;
            self.standard_error.write_all(bytes)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.file {
            Some(file) => file.flush(),
            None => self.standard_error.flush(),
        }
    }
}

/// Everything `main` needs once the logging options are settled.
pub(crate) struct Prepared {
    pub(crate) settings: Settings,
    /// The opened rotated file, when one was asked for.
    pub(crate) file: Option<RotatingFile>,
    /// The filter to install.
    pub(crate) filter: EnvFilter,
    /// Set when `RUST_LOG` was not used: the closed reason and fixed explanation.
    pub(crate) complaint: Option<(FilterRejection, granary_client::FilterDetail)>,
    /// The arguments left for the verb.
    pub(crate) args: Vec<OsString>,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Prepared(<log-file>, <configuration>, <arguments>)")
    }
}

/// How `RUST_LOG` is read: the legacy reader, which returns the filter and any
/// complaint instead of printing it.
pub(crate) type LegacyFilter =
    fn(Result<String, std::env::VarError>) -> (EnvFilter, Option<granary_client::FilterDetail>);

/// Settle the logging options before anything is written.
///
/// Reads the leading `--log-*` arguments (not for `mount.gran`, whose
/// operands are the kernel's), the environment and the configuration file,
/// opens the rotated file when one was chosen, and picks the filter. A set-ID
/// process takes no logging configuration from its arguments, environment
/// (`RUST_LOG` included) or configuration file: every verb that matters
/// refuses it, and until then it must not let its invoker choose a file it
/// writes or a verbosity it logs at. Its leading `--log-*` arguments are still
/// removed, unread, so the verb it names runs its own set-ID refusal instead
/// of rejecting a logging option as an unknown command.
///
/// # Errors
/// A refusal is written through the bounded direct path and returned as the
/// exit code: 2 for a value that was not accepted, 1 for a file that could
/// not be opened.
pub(crate) fn prepare(
    mount_gran: bool,
    all_args: Vec<OsString>,
    legacy_filter: LegacyFilter,
) -> Result<Prepared, ExitCode> {
    let credentials = process_credentials();
    let rust_log = if credentials.set_id_tainted {
        Err(std::env::VarError::NotPresent)
    } else {
        std::env::var("RUST_LOG")
    };
    prepare_with(
        &credentials,
        mount_gran,
        all_args,
        legacy_filter,
        rust_log,
        &|name| std::env::var_os(name),
    )
}

/// [`prepare`] with the process identity, `RUST_LOG` and the environment
/// passed in, so a test can present a set-ID process.
pub(crate) fn prepare_with(
    credentials: &ProcessCredentials,
    mount_gran: bool,
    all_args: Vec<OsString>,
    legacy_filter: LegacyFilter,
    rust_log: Result<String, std::env::VarError>,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Prepared, ExitCode> {
    let refuse = |code: u8, message: &dyn std::fmt::Display| {
        crate::terminal::write_line(format_args!("gran: {message}"));
        ExitCode::from(code)
    };
    let (flags, args) = if mount_gran {
        (Flags::default(), all_args)
    } else if credentials.set_id_tainted {
        let mut args = all_args.into_iter().peekable();
        while args
            .peek()
            .and_then(|a| a.to_str())
            .is_some_and(|a| a.starts_with("--log-"))
        {
            args.next();
            if args
                .peek()
                .is_some_and(|a| !a.to_str().is_some_and(|a| a.starts_with("--")))
            {
                args.next();
            }
        }
        (Flags::default(), args.collect())
    } else {
        Flags::split(all_args).map_err(|e| refuse(2, &e))?
    };
    let (flags, rust_log) = if credentials.set_id_tainted {
        (Flags::default(), Err(std::env::VarError::NotPresent))
    } else {
        (flags, rust_log)
    };
    let mut settings = if credentials.set_id_tainted {
        resolve(&flags, &|_| None, &|_| Err(String::new()))
    } else {
        resolve(&flags, env, &|path| {
            read_config_file(path, credentials.euid)
        })
    }
    .map_err(|e| refuse(2, &e))?;
    let file = settings
        .file
        .as_deref()
        .map(|path| {
            RotatingFile::open(path, credentials.euid).map_err(|e| {
                refuse(
                    1,
                    &format_args!("cannot open the log file {}: {e}", path.display()),
                )
            })
        })
        .transpose()?;
    let from_rust_log =
        settings.filter.is_none() && rust_log.as_ref().is_ok_and(|value| !value.is_empty());
    let (filter, complaint) = if let Some(filter) = settings.filter.take() {
        (filter, None)
    } else {
        legacy_filter(rust_log)
    };
    if from_rust_log && complaint.is_none() {
        settings.filter_source = 2;
    }
    Ok(Prepared {
        settings,
        file,
        filter,
        complaint: complaint.map(|detail| {
            (
                match detail {
                    granary_client::FilterDetail::NotUnicode => FilterRejection::NotUnicode,
                    granary_client::FilterDetail::Malformed => FilterRejection::Malformed,
                },
                detail,
            )
        }),
        args,
    })
}

/// Install the subscriber that writes through `writer`.
///
/// Scalar output adds no terminal controls in either format.
///
/// # Errors
/// A subscriber was already installed.
#[cfg(test)]
pub(crate) fn install<W>(settings: &Settings, filter: EnvFilter, writer: W) -> Result<(), String>
where
    W: granary_client::RecordWriter + Clone + Send + Sync + 'static,
{
    install_with_history(
        settings,
        filter,
        writer,
        granary_client::BundleHistory::default(),
    )
}

pub(crate) fn install_with_history<W>(
    settings: &Settings,
    filter: EnvFilter,
    writer: W,
    history: granary_client::BundleHistory,
) -> Result<(), String>
where
    W: granary_client::RecordWriter + Clone + Send + Sync + 'static,
{
    use tracing_subscriber::util::SubscriberInitExt as _;
    granary_client::closed_subscriber_with_paths(
        settings.format,
        filter,
        writer,
        settings.paths,
        history,
    )
    .try_init()
    .map_err(|e| e.to_string())
}

/// What `log.config` reports for these settings.
pub(crate) fn destination_of(settings: &Settings) -> LogDestination {
    if settings.file.is_some() {
        LogDestination::File
    } else {
        LogDestination::Stderr
    }
}

/// Open the span of this process's run, with a fresh correlation id.
///
/// Returns `None` after saying so when the operating system's entropy could
/// not be read: the run proceeds without an id rather than with a made-up
/// one, and the failure is an event, not a silence.
pub(crate) fn session_span() -> Option<tracing::Span> {
    if let Ok(id) = CorrelationId::draw(&mut OsSecureRandom::new()) {
        Some(granary_client::operation_span(OperationKind::Session, &id))
    } else {
        granary_client::op_failed(OperationKind::Session, FailureClass::Unavailable);
        None
    }
}

#[cfg(test)]
mod tests;

/// Duplicate the descriptor before any redirection; the worker owns this file.
pub(crate) fn capture_stderr(stderr: &std::io::Stderr) -> Result<File, ExitCode> {
    use std::os::fd::AsFd as _;
    stderr
        .as_fd()
        .try_clone_to_owned()
        .map(File::from)
        .map_err(|_| {
            crate::terminal::write_line(format_args!(
                "gran: cannot capture original standard error"
            ));
            ExitCode::FAILURE
        })
}
