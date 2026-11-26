// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! One invocation result across publication routes and all failure boundaries.

use granary_client::{PinDifference, PublishResponse, PublishSummary, StatusResponse};
use granary_core::{
    hash::GrainId,
    retained_submission::Completion,
    root::{VolumeName, decode_root},
};
use std::{io::Write, path::PathBuf, process::ExitCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Landed,
    Pending,
    Refused,
    Unresolved,
    BackendError,
    LocalError,
    UsageError,
    Abandoned,
}
impl Outcome {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Landed | Self::Abandoned => 0,
            Self::LocalError => 1,
            Self::UsageError => 2,
            Self::Pending => 3,
            Self::Refused => 4,
            Self::Unresolved => 5,
            Self::BackendError => 6,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Landed => "landed",
            Self::Pending => "pending",
            Self::Refused => "refused",
            Self::Unresolved => "unresolved",
            Self::BackendError => "backend-error",
            Self::LocalError => "local-error",
            Self::UsageError => "usage-error",
            Self::Abandoned => "abandoned",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Route {
    Authority,
    ServerSeam,
    DirectS3,
    Local,
}
impl Route {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Authority => "authority",
            Self::ServerSeam => "server-seam",
            Self::DirectS3 => "direct-s3",
            Self::Local => "local",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Retention {
    None,
    Live,
    Archive,
    Unknown,
}
impl Retention {
    fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Live => "live",
            Self::Archive => "archive",
            Self::Unknown => "unknown",
        }
    }
}
#[derive(Debug, Clone)]
pub(crate) struct Identification {
    status: u16,
    token: Option<&'static str>,
    kind: &'static str,
}
impl Identification {
    pub(crate) fn status(answer: &StatusResponse) -> Self {
        let (status, token) = answer.identification();
        Self {
            status,
            token,
            kind: match answer {
                StatusResponse::Observed(_) => "observed",
                StatusResponse::Refused(_) => "refused",
                StatusResponse::ServiceUnavailable(_) => "service-unavailable",
                StatusResponse::Internal => "internal",
            },
        }
    }
    pub(crate) fn response(answer: &PublishResponse) -> Self {
        let (status, token) = answer.identification();
        Self {
            status,
            token,
            kind: match answer {
                PublishResponse::Landed(_) => "landed",
                PublishResponse::Lost(_) => "lost",
                PublishResponse::Accepted(_) => "accepted",
                PublishResponse::Open(_) => "open",
                PublishResponse::Conflict(_) => "conflict",
                PublishResponse::Refused(_) => "refused",
                PublishResponse::RateLimited => "rate-limited",
                PublishResponse::ServiceUnavailable(_) => "service-unavailable",
                PublishResponse::Internal => "internal",
            },
        }
    }
    fn json(&self) -> String {
        object(&[
            ("status", self.status.to_string()),
            ("token", optional(self.token)),
            ("kind", quote(self.kind)),
        ])
    }
}
#[derive(Debug, Clone)]
pub(crate) struct Advisory {
    pub(crate) result: &'static str,
    pub(crate) reason: Option<&'static str>,
}
impl Advisory {
    pub(crate) const fn new(result: &'static str, reason: Option<&'static str>) -> Self {
        Self { result, reason }
    }
    fn json(&self) -> String {
        object(&[
            ("result", quote(self.result)),
            ("reason", optional(self.reason)),
        ])
    }
}
#[derive(Debug, Clone)]
pub(crate) struct Winner {
    pub(crate) seq: u64,
    pub(crate) id: GrainId,
    pub(crate) manifest_root: Option<GrainId>,
    pub(crate) root_epoch: Option<u64>,
    pub(crate) evidence: &'static str,
    pub(crate) receipt: Option<granary_core::authority_answer::Receipt>,
}
impl Winner {
    pub(crate) fn authority(done: &Completion) -> Self {
        let root = decode_root(&done.root).ok();
        Self {
            seq: done.seq,
            id: done.id,
            manifest_root: root.as_ref().map(|d| d.manifest_root),
            root_epoch: root.map(|d| d.epoch),
            evidence: if done.receipt.is_some() {
                "receipt"
            } else {
                "chain"
            },
            receipt: done.receipt,
        }
    }
    fn json(&self) -> String {
        object(&[
            ("seq", self.seq.to_string()),
            ("id", quote(&self.id.to_string())),
            (
                "manifest_root",
                optional(self.manifest_root.map(|id| id.to_string()).as_deref()),
            ),
            ("root_epoch", number(self.root_epoch)),
            ("evidence", quote(self.evidence)),
            (
                "receipt",
                self.receipt.map_or_else(null, |r| {
                    object(&[
                        ("epoch", quote(&hex(&r.position.epoch.to_bytes()))),
                        ("position", r.position.entry_seq.to_string()),
                    ])
                }),
            ),
        ])
    }
}
#[derive(Debug, Clone)]
pub(crate) struct Remedy {
    pub(crate) action: &'static str,
    pub(crate) publication_id: Option<[u8; 16]>,
}
impl Remedy {
    fn json(&self) -> String {
        object(&[
            ("action", quote(self.action)),
            (
                "publication_id",
                optional(self.publication_id.map(|id| hex(&id)).as_deref()),
            ),
        ])
    }
}
#[derive(Debug)]
pub(crate) struct InvocationReport {
    #[cfg(feature = "publish-restart-tests")]
    pub(crate) restart_record: Option<granary_core::retained_submission::Submission>,
    pub(crate) action: &'static str,
    pub(crate) route: Option<Route>,
    pub(crate) volume: Option<VolumeName>,
    pub(crate) publication_id: Option<[u8; 16]>,
    pub(crate) previous_completion_id: Option<[u8; 16]>,
    pub(crate) outcome: Outcome,
    pub(crate) uncertain: bool,
    pub(crate) retention: Retention,
    pub(crate) routing_evidence: Option<Identification>,
    pub(crate) response: Option<Identification>,
    pub(crate) diagnostic: Option<String>,
    pub(crate) next_action: Option<Remedy>,
    pub(crate) completion: Option<Winner>,
    pub(crate) archive: Option<PathBuf>,
    pub(crate) pin_difference: Option<PinDifference>,
    pub(crate) cache: Advisory,
    pub(crate) hint: Advisory,
    pub(crate) summary: Option<PublishSummary>,
    pub(crate) response_bytes: Option<u64>,
}
impl InvocationReport {
    pub(crate) fn new(volume: Option<VolumeName>) -> Self {
        Self {
            #[cfg(feature = "publish-restart-tests")]
            restart_record: None,
            action: "publish",
            route: None,
            volume,
            publication_id: None,
            previous_completion_id: None,
            outcome: Outcome::LocalError,
            uncertain: false,
            retention: Retention::None,
            routing_evidence: None,
            response: None,
            diagnostic: None,
            next_action: None,
            completion: None,
            archive: None,
            pin_difference: None,
            cache: Advisory::new("not-configured", None),
            hint: Advisory::new("not-attempted", None),
            summary: None,
            response_bytes: None,
        }
    }
    pub(crate) fn usage(error: String) -> Self {
        let mut result = Self::new(None);
        result.outcome = Outcome::UsageError;
        result.diagnostic = Some(error);
        result
    }
    pub(crate) fn fail(&mut self, outcome: Outcome, diagnostic: impl Into<String>) {
        self.outcome = outcome;
        let mut diagnostic = diagnostic.into();
        if let Some(id) = self.previous_completion_id {
            use std::fmt::Write as _;
            let _ = write!(
                diagnostic,
                "; previously completed publication={}",
                hex(&id)
            );
        }
        self.diagnostic = Some(diagnostic);
    }
    pub(crate) fn remedy(&mut self, action: &'static str) {
        self.next_action = Some(Remedy {
            action,
            publication_id: self.publication_id,
        });
    }
    pub(crate) fn json(&self) -> String {
        let metrics = self.summary.map_or_else(
            || {
                object(&[
                    ("response_bytes", number(self.response_bytes)),
                    ("publication", null()),
                ])
            },
            |s| {
                object(&[
                    ("response_bytes", number(self.response_bytes)),
                    (
                        "publication",
                        object(&[
                            ("novel_objects", s.novel_objects.to_string()),
                            ("novel_bytes", s.novel_bytes.to_string()),
                            ("bins_uploaded", s.bins_uploaded.to_string()),
                            ("bin_bytes_uploaded", s.bin_bytes_uploaded.to_string()),
                        ]),
                    ),
                ])
            },
        );
        let pins = self.pin_difference.as_ref().map_or_else(null, |p| {
            object(&[
                (
                    "retained",
                    array(p.retained.iter().map(|pin| quote(&hex(pin)))),
                ),
                (
                    "configured",
                    array(p.configured.iter().map(|pin| quote(&hex(pin)))),
                ),
            ])
        });
        let mut result = object(&[
            ("schema_version", "1".into()),
            ("action", quote(self.action)),
            ("route", optional(self.route.map(Route::name))),
            (
                "volume",
                optional(self.volume.as_ref().map(VolumeName::as_str)),
            ),
            (
                "publication_id",
                optional(self.publication_id.map(|id| hex(&id)).as_deref()),
            ),
            ("outcome", quote(self.outcome.name())),
            ("exit_code", self.outcome.code().to_string()),
            ("uncertain", self.uncertain.to_string()),
            ("retention", quote(self.retention.name())),
            (
                "routing_evidence",
                self.routing_evidence
                    .as_ref()
                    .map_or_else(null, Identification::json),
            ),
            (
                "response",
                self.response
                    .as_ref()
                    .map_or_else(null, Identification::json),
            ),
            ("diagnostic", optional(self.diagnostic.as_deref())),
            (
                "next_action",
                self.next_action.as_ref().map_or_else(null, Remedy::json),
            ),
            (
                "completion",
                self.completion.as_ref().map_or_else(null, Winner::json),
            ),
            (
                "archive",
                optional(
                    self.archive
                        .as_ref()
                        .map(|p| p.to_string_lossy())
                        .as_deref(),
                ),
            ),
            ("pin_difference", pins),
            ("cache", self.cache.json()),
            ("hint", self.hint.json()),
            ("metrics", metrics),
        ]);
        result.push('\n');
        result
    }
    pub(crate) fn render(&self, json: bool, out: &mut dyn Write, err: &mut dyn Write) -> ExitCode {
        #[cfg(feature = "publish-restart-tests")]
        self.restart_point("output-write", "before");
        let result = if json {
            out.write_all(self.json().as_bytes())
        } else {
            self.human(out, err)
        };
        #[cfg(feature = "publish-restart-tests")]
        self.restart_point("output-write", "after");
        if result.is_err() {
            let _ = writeln!(
                err,
                "gran publish: output failed; outcome={} seq={} publication={}; known landing or archival remains valid",
                self.outcome.name(),
                self.completion
                    .as_ref()
                    .map_or_else(|| "unavailable".into(), |w| w.seq.to_string()),
                self.publication_id
                    .map_or_else(|| "unavailable".into(), |id| hex(&id))
            );
            return ExitCode::from(1);
        }
        ExitCode::from(self.outcome.code())
    }
    #[cfg(feature = "publish-restart-tests")]
    pub(crate) fn restart_point(&self, cut: &str, side: &str) {
        if let Some(record) = &self.restart_record
            && let Err(error) = granary_client::publish_restart::point(cut, side, record)
        {
            let _ = writeln!(
                std::io::stderr(),
                "restart rendezvous protocol error at {cut}: {error}"
            );
            std::process::exit(1);
        }
    }
    #[expect(
        clippy::too_many_lines,
        reason = "one renderer covers success, retained stops, abandonment and advisory output"
    )]
    fn human(&self, out: &mut dyn Write, err: &mut dyn Write) -> std::io::Result<()> {
        if let Some(s) = &self.summary {
            let mut bytes = Vec::new();
            if let Some(volume) = &self.volume {
                let _ = crate::report_publish(
                    volume,
                    s,
                    self.cache.result == "skipped",
                    &mut bytes,
                    err,
                );
            }
            let text = String::from_utf8_lossy(&bytes);
            if self.route == Some(Route::ServerSeam) {
                if let Some((first, rest)) = text.split_once('\n') {
                    writeln!(out, "{first} route=server-seam")?;
                    out.write_all(rest.as_bytes())?;
                }
            } else {
                out.write_all(&bytes)?;
            }
        } else if self.outcome == Outcome::Landed {
            if let Some(w) = &self.completion {
                writeln!(
                    out,
                    "published {} seq={} id={} publication={} route=authority evidence={}",
                    self.volume.as_ref().map_or("", VolumeName::as_str),
                    w.seq,
                    w.id,
                    self.publication_id
                        .map_or_else(|| "unavailable".into(), |id| hex(&id)),
                    w.evidence
                )?;
            }
        } else if self.outcome == Outcome::Abandoned {
            writeln!(
                out,
                "abandoned publication={} archive={} pin-difference={}; recovery stopped; all candidates retained; publication may still land; abandonment does not unblock the volume; a wedged volume remains unavailable to every publisher until out-of-band repair",
                self.publication_id
                    .map_or_else(|| "unavailable".into(), |id| hex(&id)),
                self.archive
                    .as_ref()
                    .map_or_else(|| "unavailable".into(), |p| p.display().to_string()),
                self.pin_difference.is_some()
            )?;
        } else {
            let _ = writeln!(
                err,
                "gran publish: {}: {}",
                self.outcome.name(),
                self.diagnostic.as_deref().unwrap_or("publication stopped")
            );
            if let Some(e) = &self.routing_evidence {
                let _ = writeln!(
                    err,
                    "status={} token={}",
                    e.status,
                    e.token.unwrap_or("none")
                );
            }
            if let Some(e) = &self.response {
                let _ = writeln!(
                    err,
                    "response status={} token={} kind={}",
                    e.status,
                    e.token.unwrap_or("none"),
                    e.kind
                );
            }
            if self.retention == Retention::Live
                && let Some(id) = self.publication_id
            {
                let _ = writeln!(err, "submission retained publication={}", hex(&id));
            }
            if self.retention == Retention::Unknown {
                let _ = writeln!(
                    err,
                    "publication durability is uncertain; inspect the original store before continuing"
                );
            }
            if let Some(archive) = &self.archive {
                let _ = writeln!(err, "archive={}", archive.display());
            }
            if self.uncertain {
                let _ = writeln!(
                    err,
                    "the publication may have landed; {}",
                    if self.publication_id.is_some() {
                        "resume this publication"
                    } else {
                        "read the head back or re-run the direct route to converge"
                    }
                );
            }
            if let Some(remedy) = &self.next_action {
                let _ = writeln!(err, "next action: {}", remedy.action);
                if let Some(id) = remedy.publication_id {
                    let _ = writeln!(
                        err,
                        "use the original store and scope: --recover {}; or --abandon {} --acknowledge-may-land",
                        hex(&id),
                        hex(&id)
                    );
                }
            }
        }
        for (name, advisory) in [("cache", &self.cache), ("hint", &self.hint)] {
            if matches!(advisory.result, "failed" | "skipped") {
                let _ = writeln!(
                    err,
                    "gran publish: {name} {}: {} (advisory)",
                    advisory.result,
                    advisory.reason.unwrap_or("repair on the next invocation")
                );
            }
        }
        Ok(())
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::new();
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}
fn null() -> String {
    "null".into()
}
fn number(value: Option<u64>) -> String {
    value.map_or_else(null, |n| n.to_string())
}
fn optional(value: Option<&str>) -> String {
    value.map_or_else(null, quote)
}
fn array(values: impl Iterator<Item = String>) -> String {
    format!("[{}]", values.collect::<Vec<_>>().join(","))
}
fn object(fields: &[(&str, String)]) -> String {
    format!(
        "{{{}}}",
        fields
            .iter()
            .map(|(key, value)| format!("{}:{value}", quote(key)))
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// A JSON string literal, quotes included, with every control character
/// escaped.
pub(crate) fn quote(value: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(ch));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests;
