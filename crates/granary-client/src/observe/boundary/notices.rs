// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Worker notices are fixed templates over closed classes and counts.

use super::{BundleRecord, FailureClass, LogFormat, LogPath, LogPaths, LogRecord, Scalar, quoted};
use std::fmt::Write as _;

/// An operator notice with no text, path, or error-object input.
///
/// ```compile_fail,E0308
/// use granary_client::OperatorNotice;
/// let notice = OperatorNotice::rotation_failed("synthetic-secret");
/// ```
/// ```compile_fail,E0308
/// use granary_client::OperatorNotice;
/// let notice = OperatorNotice::write_failed(std::path::Path::new("synthetic-key"));
/// ```
#[derive(Debug)]
pub struct OperatorNotice(Notice);
#[derive(Debug)]
enum Notice {
    Rotation(FailureClass),
    Write(FailureClass),
    Loss(u64, u64, u64),
}
impl OperatorNotice {
    /// A rotation refused; logging continues in the current file.
    #[must_use]
    pub fn rotation_failed(class: FailureClass) -> Self {
        Self(Notice::Rotation(class))
    }
    /// A file write refused; logging continues on standard error.
    #[must_use]
    pub fn write_failed(class: FailureClass) -> Self {
        Self(Notice::Write(class))
    }
    /// Whole records refused by bounded admission.
    #[must_use]
    pub fn sink_loss(telemetry_dropped: u64, protected_lost: u64, local_lost: u64) -> Self {
        Self(Notice::Loss(telemetry_dropped, protected_lost, local_lost))
    }
    /// Encode before retaining a notice or handing it to a destination.
    #[must_use]
    pub fn render(&self, format: LogFormat) -> LogRecord {
        LogRecord(self.encode(format, "<log-file>"))
    }

    /// Project an eligible ordinary log-file slot before retaining worker output.
    /// The bundle member is encoded independently with redacted policy.
    #[must_use]
    pub fn project_log_file(
        &self,
        format: LogFormat,
        paths: LogPaths,
        path: &std::path::Path,
    ) -> (LogRecord, BundleRecord) {
        let Scalar::Text(projected) = LogPath::log_file(path).project(paths) else {
            unreachable!()
        };
        (
            LogRecord(self.encode(format, &projected)),
            self.bundle_record(),
        )
    }

    /// Independently encode the closed notice for bundle input.
    #[must_use]
    pub fn bundle_record(&self) -> BundleRecord {
        BundleRecord(self.encode(LogFormat::Json, "<log-file>"))
    }

    fn encode(&self, format: LogFormat, path: &str) -> String {
        let mut out = String::new();
        match &self.0 {
            Notice::Rotation(class) | Notice::Write(class) => {
                let message = match self.0 {
                    Notice::Rotation(_) => {
                        "[gran log: cannot rotate the log file <log-file>; continuing in the current file]"
                    }
                    _ => {
                        "[gran log: cannot write the log file <log-file>; logging continues on standard error]"
                    }
                };
                match format {
                    LogFormat::Json => {
                        out.push_str("{\"event\":\"log.line\",\"message\":");
                        quoted(&mut out, message);
                        out.push_str(",\"path\":");
                        quoted(&mut out, path);
                        out.push_str(",\"class\":");
                        quoted(&mut out, class.as_str());
                        out.push('}');
                    }
                    LogFormat::Text => {
                        let _ = write!(out, "{message} class=\"{}\" path=", class.as_str());
                        quoted(&mut out, path);
                    }
                }
            }
            Notice::Loss(t, p, l) => match format {
                LogFormat::Json => {
                    let _ = write!(
                        out,
                        "{{\"event\":\"log.sink_loss\",\"telemetry_dropped\":{t},\"protected_lost\":{p},\"local_lost\":{l}}}"
                    );
                }
                LogFormat::Text => match (t, p) {
                    (0, 0) => {
                        let _ = write!(
                            out,
                            "[gran log sink: {l} LOCAL message(s) LOST under backpressure]"
                        );
                    }
                    (0, p) => {
                        let _ = write!(
                            out,
                            "[gran log sink: {p} PROTECTED message(s) LOST under backpressure]"
                        );
                    }
                    (t, 0) => {
                        let _ = write!(
                            out,
                            "[gran log sink: {t} telemetry line(s) dropped under backpressure]"
                        );
                    }
                    (t, p) => {
                        let _ = write!(
                            out,
                            "[gran log sink: {t} telemetry line(s) dropped and {p} PROTECTED message(s) LOST under backpressure]"
                        );
                    }
                },
            },
        }
        if let Notice::Loss(_, _, local) = self.0
            && format == LogFormat::Text
        {
            let _ = write!(out, " local_lost={local}");
        }
        out.push('\n');
        out
    }
}
