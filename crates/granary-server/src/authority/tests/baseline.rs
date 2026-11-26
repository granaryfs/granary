// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The durability baseline's measurements of the production log adapter:
//! timed by this test around the adapter's calls, never by the adapter.
//!
//! - **Commit latency**: each `append` of a publication's three records (a
//!   decision, its attestation, its landed outcome), one volume's chain of
//!   publications, each record's size beside its time.
//! - **Replay time against log size**: a start over a crafted log of `k`
//!   landed publications (the marker clean), timed from the call to `start`
//!   to its return: the marker read and write, the classification, the
//!   replay and the re-sync.
//!
//! One run writes one JSON document; the record's script summarises runs.
//! Ignored: it takes its directory, its output and its sizes from the
//! environment, and panics without them.

use std::fmt::Write as _;
use std::future::Future;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use granary_core::authlog::{
    Operation, Principal, Record, RecordBody, RootBytes, SubmissionIdentity, Tenant, encode_append,
    encode_envelope,
};
use granary_core::clock::Clock;
use granary_core::decisionlog::DecisionLog;
use granary_core::hash::GrainId;
use granary_core::runmarker::{RunMarker, encode_marker};
use granary_sim::fakes::{Faults, Sim};

use super::super::file_log::FileLog;
use super::super::{AuthorityParts, start};
use super::{
    FixedClock, TestStore, YieldPause, attestation, block, boot, configs, envelope, good_root,
    landed, log_bytes, rng, secure, vol,
};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is unset: see the baseline record"))
}

/// A clock reading, for a measurement: the time is what is measured.
#[expect(
    clippy::disallowed_methods,
    reason = "a measurement's wall time is its subject; nothing under test reads it"
)]
fn stopwatch() -> Instant {
    Instant::now()
}

/// Poll an adapter call once: every call completes in the poll that makes
/// it (the adapter's contract), so no scheduler's time is in the figure.
fn once<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("an adapter call did not complete in its first poll"),
    }
}

/// `n` landed publications on vol-a: a chain of roots, each decided under
/// its own operation, attested and landed, in log order.
fn publications(n: u64) -> Vec<Record> {
    let volume = vol("vol-a");
    let mut records = Vec::new();
    let mut parent = None;
    for seq in 1..=n {
        let candidate = good_root(&volume, seq, parent, 1);
        let decision = Record::new(
            seq,
            RecordBody::Decision {
                identity: SubmissionIdentity::new(
                    Tenant::new(vec![0x11]).unwrap(),
                    Principal::new(vec![0x22]).unwrap(),
                    Operation::new(seq.to_be_bytes().to_vec()).unwrap(),
                    GrainId::of(&candidate),
                ),
                root_seq: seq,
                base: parent,
                decided_at: FixedClock.now(),
                candidate: RootBytes::new(candidate.clone()).unwrap(),
            },
        )
        .unwrap();
        parent = Some(GrainId::of(&candidate));
        let attested = attestation(&decision);
        let outcome = landed(&decision);
        records.extend([decision, attested, outcome]);
    }
    records
}

fn kind(record: &Record) -> &'static str {
    match record.body() {
        RecordBody::Decision { .. } => "decision",
        RecordBody::Attestation { .. } => "attestation",
        RecordBody::Landed { .. } => "landed",
        RecordBody::Lost { .. } => "lost",
    }
}

/// A provisioned, empty state directory under `base`, canonical and
/// `0o700` (the protection walk refuses a symbolic link at any component,
/// and any group or other access to the directory).
fn fresh(base: &Path, name: &str) -> PathBuf {
    let anchor = base.canonicalize().unwrap().join(name);
    let _ = std::fs::remove_dir_all(&anchor);
    let state = anchor.join("state");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    state
}

/// The measurements (module docs), written as one JSON document.
#[test]
#[ignore = "a measurement: GRANARY_BASELINE_DIR, _OUT, _PUBLICATIONS and _REPLAY name its run"]
fn measure_the_adapter() {
    let base = PathBuf::from(env("GRANARY_BASELINE_DIR"));
    let out = PathBuf::from(env("GRANARY_BASELINE_OUT"));
    let n: u64 = env("GRANARY_BASELINE_PUBLICATIONS").parse().unwrap();
    let replay: Vec<u64> = env("GRANARY_BASELINE_REPLAY")
        .split(',')
        .map(|k| k.trim().parse().unwrap())
        .collect();
    let volume = vol("vol-a");
    let env_a = envelope(&volume, 7);
    let records = publications(n.max(replay.iter().copied().max().unwrap_or(0)));

    // Commit latency: the adapter over a fresh state directory, marked
    // running as a start would, the log initialised, then each append.
    let state = fresh(&base, "commit");
    let log = FileLog::new(&state, true).unwrap();
    once(log.write_marker(&encode_marker(&RunMarker::Running(boot(1))))).unwrap();
    once(log.initialise(&encode_envelope(&env_a))).unwrap();
    let mut json = String::from("{\"appends\":[");
    let appends = usize::try_from(n * 3).unwrap();
    for (i, record) in records.iter().take(appends).enumerate() {
        let append = encode_append(&env_a, record).unwrap();
        let bytes = append.record().len() + append.mark().len();
        let at = stopwatch();
        once(log.append(&append)).unwrap();
        let ns = at.elapsed().as_nanos();
        let comma = if i == 0 { "" } else { "," };
        let _ = write!(
            json,
            "{comma}{{\"kind\":\"{}\",\"bytes\":{bytes},\"ns\":{ns}}}",
            kind(record)
        );
    }
    json.push_str("],\"replay\":[");

    // Replay against log size: a crafted log of `k` publications beside a
    // clean marker, and a start timed around the call.
    for (i, k) in replay.iter().enumerate() {
        let state = fresh(&base, &format!("replay-{k}"));
        let prefix = usize::try_from(k * 3).unwrap();
        let bytes = log_bytes(&env_a, records.get(..prefix).unwrap());
        std::fs::write(state.join("vol-a.log"), &bytes).unwrap();
        std::fs::write(
            state.join("MARKER"),
            encode_marker(&RunMarker::Clean).as_bytes(),
        )
        .unwrap();
        let sim = Sim::new();
        let parts = AuthorityParts {
            admission: crate::Admission::chain_fixture(),
            log: FileLog::new(&state, true).unwrap(),
            store: TestStore::new(sim.node(1, Faults::none())),
            clock: FixedClock,
            rng: rng(1),
            secure_random: secure(1),
            pause: YieldPause,
        };
        let volumes = configs(std::slice::from_ref(&volume));
        let at = stopwatch();
        let started = block(async move { start(parts, boot(2), volumes).await });
        let ns = at.elapsed().as_nanos();
        assert!(started.is_ok(), "the start over {k} publications refused");
        let comma = if i == 0 { "" } else { "," };
        let _ = write!(
            json,
            "{comma}{{\"publications\":{k},\"log_bytes\":{},\"start_ns\":{ns}}}",
            bytes.len()
        );
    }
    json.push_str("]}\n");
    std::fs::write(out, json).unwrap();
}
