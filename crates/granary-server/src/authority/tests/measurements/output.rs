// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Export happens after the timed interval. The runner attaches venue metadata.

use super::*;
use granary_core::authority_answer as codec;
use http_body_util::{BodyExt as _, Full};
use hyper::Response;
use hyper::body::Bytes;
use std::fmt::Write as _;
use std::io::Write as _;

enum ProgressMessage {
    Record(String),
    Finish(std::sync::mpsc::Sender<Result<(), String>>),
}

pub(super) struct Progress {
    sender: std::sync::mpsc::Sender<ProgressMessage>,
    started: std::time::Instant,
}

impl Progress {
    pub(super) fn for_row(row: &str) -> Result<Self, String> {
        let dir = std::env::var_os("GRANARY_MEASURE_OUTPUT")
            .ok_or_else(|| "pivot progress output directory missing".to_owned())?;
        Self::create(std::path::Path::new(&dir).join(format!("{row}.progress.tsv")))
    }

    fn create(path: std::path::PathBuf) -> Result<Self, String> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| format!("pivot progress create failed: {error}"))?;
        file.write_all(
            b"phase\toffset_ns\tvolumes_prepared\tprincipals_enrolled\tintent_rows_prepared\tpilot_publishes\topen_loop_sends\topen_loop_completions\n",
        )
        .map_err(|error| format!("pivot progress write failed: {error}"))?;
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut error = None;
            for message in receiver {
                match message {
                    ProgressMessage::Record(line) if error.is_none() => {
                        if let Err(cause) = file.write_all(line.as_bytes()) {
                            error = Some(format!("pivot progress write failed: {cause}"));
                        }
                    }
                    ProgressMessage::Record(_) => {}
                    ProgressMessage::Finish(reply) => {
                        if error.is_none()
                            && let Err(cause) = file.flush()
                        {
                            error = Some(format!("pivot progress write failed: {cause}"));
                        }
                        let _ = reply.send(error.map_or(Ok(()), Err));
                        break;
                    }
                }
            }
        });
        Ok(Self {
            sender,
            started: super::stopwatch(),
        })
    }

    pub(super) fn record(&mut self, phase: &str, counts: [usize; 6]) -> Result<(), String> {
        let [volumes, principals, rows, pilots, sends, completions] = counts;
        self.sender
            .send(ProgressMessage::Record(format!(
                "{phase}\t{}\t{volumes}\t{principals}\t{rows}\t{pilots}\t{sends}\t{completions}\n",
                self.started.elapsed().as_nanos(),
            )))
            .map_err(|_| "pivot progress writer stopped".to_owned())
    }

    pub(super) fn finish(&mut self) -> Result<(), String> {
        let (reply, result) = std::sync::mpsc::channel();
        self.sender
            .send(ProgressMessage::Finish(reply))
            .map_err(|_| "pivot progress writer stopped".to_owned())?;
        result
            .recv()
            .map_err(|_| "pivot progress writer stopped".to_owned())?
    }
}

pub(super) fn quantile(values: &[u128], percent: usize) -> Result<u128, &'static str> {
    if values.is_empty() {
        return Err("no successful samples");
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted
        .get((sorted.len() * percent).div_ceil(100).saturating_sub(1))
        .copied()
        .ok_or("invalid percentile")
}
pub(super) fn checked_status(
    code: u16,
    token: bool,
    media: Option<&str>,
    bytes: &[u8],
) -> Result<codec::VolumeStatus, &'static str> {
    if code != 200 || token {
        return Err("status response is not a success");
    }
    if media != Some("application/vnd.granary.volume-status.v1") {
        return Err("status media type mismatch");
    }
    codec::decode_status(bytes).map_err(|_| "status success body does not decode")
}
pub(super) async fn status(
    response: Response<Full<Bytes>>,
) -> Result<codec::VolumeStatus, &'static str> {
    let (parts, body) = response.into_parts();
    let bytes = body
        .collect()
        .await
        .unwrap_or_else(|never| match never {})
        .to_bytes();
    checked_status(
        parts.status.as_u16(),
        parts.headers.contains_key("granary-error"),
        parts
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        &bytes,
    )
}
pub(super) fn distribution(fields: &mut BTreeMap<String, String>, name: &str, values: &[u128]) {
    fields.insert(format!("{name}_count"), values.len().to_string());
    for p in [50, 90, 99] {
        fields.insert(
            format!("{name}_p{p}_ns"),
            quantile(values, p).unwrap().to_string(),
        );
    }
}
pub(super) fn write(row: &str, fields: &BTreeMap<String, String>) {
    let mut text = String::new();
    for (key, value) in fields {
        assert!(
            !key.contains(['\t', '\n']) && !value.contains(['\t', '\n']),
            "invalid export field"
        );
        text.push_str(key);
        text.push('\t');
        text.push_str(value);
        text.push('\n');
    }
    write_tsv(row, &text);
}

pub(super) fn write_tsv(row: &str, text: &str) {
    let dir =
        std::env::var_os("GRANARY_MEASURE_OUTPUT").expect("runner supplies GRANARY_MEASURE_OUTPUT");
    std::fs::write(std::path::Path::new(&dir).join(format!("{row}.tsv")), text).unwrap();
}

pub(super) fn write_samples(row: &str, values: &[u128]) -> String {
    let dir =
        std::env::var_os("GRANARY_MEASURE_OUTPUT").expect("runner supplies GRANARY_MEASURE_OUTPUT");
    let name = format!("{row}.samples.ns");
    std::fs::write(std::path::Path::new(&dir).join(&name), samples_text(values)).unwrap();
    name
}

/// `value<TAB>index` lines in `(value, index)` order, the order the runner
/// validates: equal values are ordered by their sample index rather than left
/// to the sort.
fn samples_text(values: &[u128]) -> String {
    let mut sorted: Vec<_> = values.iter().copied().enumerate().collect();
    sorted.sort_unstable_by_key(|&(index, value)| (value, index));
    sorted
        .into_iter()
        .fold(String::new(), |mut text, (index, value)| {
            writeln!(&mut text, "{value}\t{index}").unwrap();
            text
        })
}

#[test]
fn authority_measurement_samples_order_ties_by_index() {
    // Sample 2 ties sample 0's value; the runner requires (value, index) order.
    assert_eq!(samples_text(&[5, 3, 5, 1]), "1\t3\n3\t1\n5\t0\n5\t2\n");
}

#[test]
fn authority_measurement_status_and_population_controls() {
    let bytes = codec::encode_status(codec::VolumeStatus {
        epoch: Epoch::from_bytes([1; 16]),
        head: None,
        open: None,
    })
    .unwrap();
    let media = Some("application/vnd.granary.volume-status.v1");
    assert!(checked_status(200, false, media, &bytes).is_ok());
    let cases = [
        (404, true, None, &[][..], "status response is not a success"),
        (
            200,
            true,
            media,
            bytes.as_slice(),
            "status response is not a success",
        ),
        (
            200,
            false,
            None,
            bytes.as_slice(),
            "status media type mismatch",
        ),
        (
            200,
            false,
            media,
            &[][..],
            "status success body does not decode",
        ),
    ];
    assert!(!cases.is_empty());
    for (code, token, media, body, refusal) in cases {
        assert_eq!(checked_status(code, token, media, body), Err(refusal));
    }
    assert_eq!(quantile(&[1, 2, 3, 4], 50), Ok(2));
    assert_eq!(quantile(&[], 50), Err("no successful samples"));
    let mut fields = BTreeMap::new();
    distribution(&mut fields, "latency", &[1, 2, 3, 4, 5]);
    assert_eq!(fields.get("latency_p90_ns").map(String::as_str), Some("5"));
}

#[test]
fn authority_measurement_progress_records_phase_and_counts() {
    let dir = super::super::intents::scratch();
    let path = dir.join("pivot.progress.tsv");
    let mut progress = Progress::create(path.clone()).unwrap();
    progress
        .record("setup", [4, 65_536, 4_096, 8, 100, 90])
        .unwrap();
    progress.finish().unwrap();
    let text = std::fs::read_to_string(path).unwrap();
    let rows: Vec<_> = text.lines().collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0],
        "phase\toffset_ns\tvolumes_prepared\tprincipals_enrolled\tintent_rows_prepared\tpilot_publishes\topen_loop_sends\topen_loop_completions"
    );
    let fields: Vec<_> = rows[1].split('\t').collect();
    assert_eq!(fields.first().copied(), Some("setup"));
    assert!(
        fields
            .get(1)
            .is_some_and(|value| value.parse::<u128>().is_ok())
    );
    assert_eq!(
        fields.get(2..),
        Some(&["4", "65536", "4096", "8", "100", "90"][..])
    );
    std::fs::remove_dir_all(dir).unwrap();
}
