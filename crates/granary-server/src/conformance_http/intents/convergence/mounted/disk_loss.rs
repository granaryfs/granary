// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit recovery after a mounted writer is killed, with and without its store.

use super::super::server_crash::{
    ObservedPacket, observed_packet_cursor, observed_packets, optional_packet_file,
};
use super::crash::{ClientChild, WriterInputs};
use super::*;
use crate::conformance_http::intents::{WallClock, sync_loss::recover::land};
use granary_core::{
    hash::GrainId,
    intent::{self, OwnershipMode},
    retained_submission::Scope,
};
use std::fmt::Write as _;
use std::process::{Command, Stdio};

const CHILD: &str = "GRANARY_DISK_LOSS_CHILD";
const CHILD_TEST: &str =
    "conformance_http::intents::convergence::mounted::disk_loss::disk_loss_child";
const GRAN: &str = "GRANARY_DISK_LOSS_GRAN";
const CONTEXT: &str = "disk-loss";
const HOLD: (&str, &str) = ("sync.commit_wait", "background");
const ACK: &[u8] = b"acknowledged bytes";
const PREFIX: &[u8] = b"synced prefix";
const TAIL: &[u8] = b" followed by an unsynced tail";
const RENAMED: &[u8] = b"synced under its new name";
const UNSYNCED: &[u8] = b"never synced";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Prepared,
    Published,
    AlreadyLanded,
    BeforeRefresh,
    OverlappingSibling,
    SecondWriter,
    KeyLoss,
    LostReplies,
    StaleGeneration,
    StaleEpoch,
}

impl Case {
    const ALL: [Self; 10] = [
        Self::Prepared,
        Self::Published,
        Self::AlreadyLanded,
        Self::BeforeRefresh,
        Self::OverlappingSibling,
        Self::SecondWriter,
        Self::KeyLoss,
        Self::LostReplies,
        Self::StaleGeneration,
        Self::StaleEpoch,
    ];

    fn cut(self) -> bool {
        matches!(self, Self::BeforeRefresh | Self::OverlappingSibling)
    }

    fn wide(self) -> bool {
        self == Self::Prepared
    }

    fn stale(self) -> bool {
        matches!(self, Self::StaleGeneration | Self::StaleEpoch)
    }
}

fn witness(dir: &Path, value: &str) {
    std::fs::write(dir.join("ready.next"), value).unwrap();
    std::fs::rename(dir.join("ready.next"), dir.join("ready")).unwrap();
}

fn overwrite(path: &Path, bytes: &[u8]) -> std::fs::File {
    let mut file = std::fs::File::create(path).unwrap();
    file.write_all(bytes).unwrap();
    file
}

fn scope(inputs: &WriterInputs) -> Scope {
    Scope {
        authority_base: inputs.endpoint.as_bytes().to_vec(),
        pins: vec![inputs.pin],
        credential_context: CONTEXT.as_bytes().to_vec(),
    }
}

#[test]
#[ignore = "re-executed by the disk-loss rows with an isolated mounted writer"]
fn disk_loss_child() {
    let dir = PathBuf::from(std::env::var_os(CHILD).expect("disk-loss fixture directory"));
    let inputs = WriterInputs::load(dir.clone());
    let case = std::fs::read_to_string(dir.join("case")).unwrap();
    let case = Case::ALL
        .into_iter()
        .find(|candidate| format!("{candidate:?}") == case)
        .unwrap();
    let captured = capture(LogPaths::Redacted);
    let profile = if case == Case::Published {
        SyncProfile::Published
    } else {
        SyncProfile::DurablePrepared
    };
    let writer = inputs.mount_with(81, profile, &scope(&inputs), &WallClock, |faults| {
        faults.arm(HOLD.0, HOLD.1, 1, FaultAction::Block);
    });
    held(&writer.faults, HOLD);
    let mount = &writer.mountpoint;
    let a = overwrite(&mount.join("a"), ACK);
    a.sync_all().unwrap();
    if case.wide() {
        let mut c = overwrite(&mount.join("c"), PREFIX);
        c.sync_all().unwrap();
        let e = overwrite(&mount.join("e"), RENAMED);
        e.sync_all().unwrap();
        std::fs::rename(mount.join("e"), mount.join("renamed")).unwrap();
        std::fs::File::open(mount).unwrap().sync_all().unwrap();

        c.write_all(TAIL).unwrap();
        drop(overwrite(&mount.join("b"), UNSYNCED));
        drop(overwrite(&mount.join("d"), UNSYNCED));
        std::fs::rename(mount.join("d"), mount.join("unsynced-rename")).unwrap();
    }
    std::fs::write(dir.join("writer"), writer.writer).unwrap();
    witness(&dir, "acknowledged");
    if case.cut() {
        wait_until(
            || dir.join("land").exists(),
            "parent did not release background hold",
        );
        if case == Case::OverlappingSibling {
            // This write is deliberately unacknowledged. The landing and the
            // older selection share a parent and writer, but differ at a.
            drop(overwrite(&mount.join("a"), WINNER_BYTES));
        }
        writer.faults.resume_at(REFRESH.0, REFRESH.1);
        held(&writer.faults, REFRESH);
        let lines = captured.lines();
        assert_eq!(
            events(&lines, "sync.fault")
                .filter(|line| {
                    field(line, "point") == Some(REFRESH.0)
                        && field(line, "phase") == Some(REFRESH.1)
                        && number_field(line, "occurrence") == Some(1)
                })
                .count(),
            1
        );
        witness(&dir, "landed-before-refresh");
    }
    // Both the loss case and its intact control end at the same cut.
    assert_eq!(std::io::stdin().read(&mut [0]).unwrap(), 0);
    panic!("disk-loss parent exited without killing its writer");
}

fn events<'a>(lines: &'a [String], event: &'a str) -> impl Iterator<Item = &'a str> {
    lines
        .iter()
        .map(String::as_str)
        .filter(move |line| field(line, "event") == Some(event))
}

struct RecoveryResult {
    code: Option<i32>,
    lines: Vec<String>,
}

impl RecoveryResult {
    fn assert_event(&self, event: &str, count: usize) {
        assert_eq!(events(&self.lines, event).count(), count, "{event}");
    }

    fn assert_status(&self, code: i32, diagnostic: &str) {
        assert_eq!(self.code, Some(code), "expected {diagnostic}");
        if !diagnostic.is_empty() {
            assert!(
                self.lines.iter().any(|line| line.contains(diagnostic)),
                "missing diagnostic: {diagnostic}"
            );
        }
    }
}

fn recover(
    harness: &Harness,
    inputs: &WriterInputs,
    writer: [u8; 16],
    acknowledge: bool,
) -> RecoveryResult {
    let binary =
        std::env::var_os(GRAN).expect("set GRANARY_DISK_LOSS_GRAN to the built gran binary");
    let mut writer_hex = String::with_capacity(32);
    for byte in writer {
        write!(writer_hex, "{byte:02x}").unwrap();
    }
    let stderr = inputs.root.join("recover.stderr");
    let mut command = Command::new(binary);
    command
        .current_dir(&inputs.root)
        .args(["--log-format", "json", "--log-paths", "full", "recover"])
        .arg(inputs.root.join("store"))
        .arg(harness.fixture.volume().as_str())
        .args(["--writer", &writer_hex, "--endpoint", &inputs.endpoint])
        .arg("--pin")
        .arg(granary_net::config::render_tls_pin(&inputs.pin))
        .args(["--credential-context", CONTEXT])
        .arg("--key-seed")
        .arg(inputs.keys.join("root.seed"))
        .arg("--client-cert")
        .arg(inputs.keys.join("client-0.pem"))
        .arg("--client-key")
        .arg(inputs.keys.join("client-0.key"))
        .env("GRANARY_LOG_FILTER", "trace")
        .env_remove("GRANARY_LOG_FILE")
        .env_remove("GRANARY_LOG_CONFIG")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&stderr).unwrap());
    if acknowledge {
        command.args(["--acknowledge-takeover", &writer_hex]);
    }
    let mut child = command.spawn().unwrap();
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() >= WRITABLE_JOIN_BOUND + WAIT {
            child.kill().unwrap();
            wait_until(
                || child.try_wait().unwrap().is_some(),
                "killed recovery process could not be reaped",
            );
            panic!("gran recover did not exit within the row bound");
        }
        std::thread::sleep(JOIN_POLL);
    };
    RecoveryResult {
        code: status.code(),
        lines: std::fs::read_to_string(stderr)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect(),
    }
}

fn packets(harness: &Harness, suffix: &str) -> Vec<ObservedPacket> {
    let tap = harness.fixture.tap.as_ref().unwrap();
    let boundary = observed_packet_cursor(tap);
    let path = format!("/volume/{}{}", harness.fixture.volume().as_str(), suffix);
    observed_packets(tap)
        .into_iter()
        .filter(|packet| packet.index < boundary && packet.target == path.as_bytes())
        .collect()
}

fn all_posts(harness: &Harness) -> u64 {
    observed_packet_cursor(harness.fixture.tap.as_ref().unwrap())
}

fn tap(harness: &Harness) -> &Path {
    harness.fixture.tap.as_deref().unwrap()
}

fn ownership_packets(harness: &Harness) -> Vec<ObservedPacket> {
    packets(harness, "/intent/ownership")
}

fn grant(packet: &ObservedPacket) -> intent::Grant {
    assert_eq!(
        optional_packet_file(&packet.path, "status").as_deref(),
        Some(b"200".as_slice())
    );
    let grant =
        intent::decode_grant(&optional_packet_file(&packet.path, "answer").unwrap()).unwrap();
    assert_eq!(grant.request_id, GrainId::of(&packet.body));
    grant
}

fn assert_replayed(packets: &[ObservedPacket]) -> intent::Receipt {
    let [first, second] = packets else {
        panic!(
            "expected one lost reply and one replay, saw {} requests",
            packets.len()
        );
    };
    assert_eq!(first.body, second.body);
    assert_eq!(first.content_type, second.content_type);
    assert!(optional_packet_file(&first.path, "reply-lost").is_some());
    assert!(optional_packet_file(&second.path, "reply-lost").is_none());
    assert_eq!(
        optional_packet_file(&first.path, "answer"),
        optional_packet_file(&second.path, "answer"),
        "replayed grant bytes changed"
    );
    let initial = grant(first);
    assert_eq!(
        initial,
        grant(second),
        "the replay must return the recorded grant"
    );
    initial.receipt
}

fn race_takeover(
    harness: &Harness,
    inputs: &WriterInputs,
    writer: [u8; 16],
    case: Case,
    lost: bool,
) {
    let selected = selection(harness, writer).unwrap();
    let before = ownership_packets(harness);
    let [acquisition] = before.as_slice() else {
        panic!("expected one acquisition before stale takeover");
    };
    let old = grant(acquisition).receipt;
    let client = harness.fixture.client(harness.addr, 0);
    let scope = harness.fixture.scope(harness.addr, 0);
    let volume = harness.fixture.volume();
    let tap = tap(harness);
    std::fs::write(tap.join("hold-takeover"), []).unwrap();
    let result = std::thread::scope(|thread| {
        let recovery = thread.spawn(|| recover(harness, inputs, writer, lost));
        wait_until(
            || tap.join("takeover-held").exists(),
            "selected takeover did not reach the authority",
        );
        let answer = if case == Case::StaleGeneration {
            let changed = intent::encode_register(
                &writer,
                selected.0,
                &old.instance,
                selected.1 + 1,
                &selected.2,
            )
            .unwrap();
            harness
                .runtime
                .block_on(
                    client.intent_register_once(&scope, &volume, &changed, |doc, prefix| {
                        let keys = TrustedKeys::new([*harness.key.public_key()]).unwrap();
                        granary_store::crypto::check_signatures(doc, prefix, &keys).is_ok()
                    }),
                )
                .unwrap()
        } else {
            let changed = crate::conformance_http::intents::takeover(
                intent::Receipt {
                    generation: selected.1,
                    state: intent::ReceiptState::Live {
                        prepared_root_id: GrainId::of(&selected.2),
                    },
                    ..old
                },
                97,
            );
            harness
                .runtime
                .block_on(client.intent_takeover_once(&scope, &volume, &changed))
                .unwrap()
        };
        // Release the original packet only after the competing update was judged.
        std::fs::write(tap.join("send-takeover"), []).unwrap();
        assert_eq!(answer.status(), 200);
        recovery.join().unwrap()
    });
    let (epoch, generation, token, count) = if case == Case::StaleGeneration {
        (selected.0, selected.1 + 1, "intent-changed", 2)
    } else {
        (selected.0 + 1, selected.1, "intent-superseded", 3)
    };
    result.assert_status(1, "IntentSelectionChanged");
    result.assert_event("recover.selection_changed", 1);
    result.assert_event("recover.landed", 0);
    assert_eq!(
        events(&result.lines, "recover.selection_changed")
            .next()
            .and_then(|line| field(line, "token")),
        Some(token)
    );
    let attempts = ownership_packets(harness);
    assert_eq!(attempts.len(), count);
    let original = &attempts[1];
    let request = intent::decode_ownership(&original.body).unwrap();
    assert_eq!(request.writer, writer);
    assert_eq!(
        request.mode,
        OwnershipMode::Takeover {
            expected_epoch: selected.0,
            generation: selected.1,
            state: intent::ReceiptState::Live {
                prepared_root_id: GrainId::of(&selected.2)
            },
            recovery_ack: lost,
        }
    );
    assert_eq!(
        optional_packet_file(&original.path, "status").as_deref(),
        Some(b"409".as_slice())
    );
    assert_eq!(
        selection(harness, writer),
        Some((epoch, generation, selected.2))
    );
}

fn assert_lost_takeover(harness: &Harness, before: (u64, u64, &[u8]), lost: bool) {
    let packets = ownership_packets(harness);
    assert_eq!(packets.len(), 4);
    let receipt = assert_replayed(&packets[2..]);
    let request = intent::decode_ownership(&packets[2].body).unwrap();
    let (epoch, generation, root) = before;
    let state = intent::ReceiptState::Live {
        prepared_root_id: GrainId::of(root),
    };
    assert_eq!(
        request.mode,
        OwnershipMode::Takeover {
            expected_epoch: epoch,
            generation,
            state,
            recovery_ack: lost,
        }
    );
    assert_eq!(
        (receipt.epoch, receipt.generation, receipt.state),
        (epoch + 1, generation, state)
    );
}

fn selection(harness: &Harness, writer: [u8; 16]) -> Option<(u64, u64, Vec<u8>)> {
    let keys = TrustedKeys::new([*harness.key.public_key()]).unwrap();
    let volume = harness.fixture.volume();
    let verifies =
        |doc: &_, prefix: &_| granary_store::crypto::check_signatures(doc, prefix, &keys).is_ok();
    let reply = harness
        .runtime
        .block_on(
            harness
                .fixture
                .client(harness.addr, 0)
                .intent_readback_once(&harness.fixture.scope(harness.addr, 0), &volume, verifies),
        )
        .unwrap();
    let readback = granary_core::intent::decode_readback(reply.body(), &volume, verifies).unwrap();
    readback
        .rows
        .iter()
        .find(|row| row.writer == writer)
        .map(|row| (row.epoch, row.generation, row.root.to_vec()))
}

fn assert_reader(harness: &Harness, files: &[(&str, &[u8])]) {
    let reader = harness.reader();
    let mut names: Vec<_> = files.iter().map(|(path, _)| (*path).to_owned()).collect();
    names.sort();
    assert_eq!(mounted_names(&reader.mountpoint), names);
    for (path, bytes) in files {
        assert_eq!(
            std::fs::read(reader.mountpoint.join(path)).unwrap(),
            *bytes,
            "{path}"
        );
    }
    reader.finish();
}

fn land_before_recovery(
    case: Case,
    harness: &Harness,
    inputs: &WriterInputs,
    child: &mut ClientChild,
    writer: [u8; 16],
    selected: &[u8],
) {
    if case == Case::AlreadyLanded {
        harness.runtime.block_on(land(
            &harness.fixture,
            harness.addr,
            &harness.fixture.client(harness.addr, 0),
            selected.to_vec(),
            "exact-landing",
        ));
        assert_eq!(root(harness, 2), selected);
    } else if case.cut() {
        std::fs::remove_file(inputs.root.join("ready")).unwrap();
        std::fs::write(inputs.root.join("land"), []).unwrap();
        child.ready("landed-before-refresh");
        let keys = TrustedKeys::new([*harness.key.public_key()]).unwrap();
        let landed = root(harness, 2);
        assert_ne!(
            landed.as_slice(),
            selected,
            "the landing and selection need distinct root identities"
        );
        let published = verify_root(&landed, &keys);
        let selected = verify_root(selected, &keys);
        let base = verify_root(&root(harness, 1), &keys);
        assert_eq!(published.writer_uuid, writer);
        assert_eq!(selected.writer_uuid, writer);
        assert_eq!(selected.seq, 2);
        assert_eq!(selected.parent, published.parent);
        assert_eq!(selected.parent, Some(GrainId::of(&root(harness, 1))));
        assert_ne!(selected.manifest_root, base.manifest_root);
        assert_eq!(
            selected.manifest_root == published.manifest_root,
            case == Case::BeforeRefresh,
            "the positive cut needs equal-manifest proof and the negative cut needs different manifests",
        );
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the paired cases share the same consent, custody, dispatch and reader assertions"
)]
fn assert_recovery(
    harness: &Harness,
    inputs: &WriterInputs,
    writer: [u8; 16],
    case: Case,
    lost: bool,
) {
    let before_head = head_seq(harness);
    let before_root = root(harness, before_head);
    let before_posts = all_posts(harness);
    let before_publishes = packets(harness, "/publish").len();
    let before_selection = selection(harness, writer).unwrap();
    let store = inputs.root.join("store");
    // The recovered instance uses the same store path. Only the loss case
    // removes it, after reaping the old process and detaching its mount.
    if lost {
        std::fs::remove_dir_all(&store).unwrap();
        assert!(!store.exists());
        let no_consent = recover(harness, inputs, writer, false);
        no_consent.assert_status(
            1,
            &format!(
                "selected E={} G={} root={} parent_seq=1",
                before_selection.0,
                before_selection.1,
                GrainId::of(&before_selection.2)
            ),
        );
        no_consent.assert_event("recover.landed", 0);
        assert!(!store.exists());
        assert_eq!(all_posts(harness), before_posts);
        assert_eq!(selection(harness, writer).unwrap(), before_selection);
        assert_eq!(head_seq(harness), before_head);
        assert_eq!(root(harness, before_head), before_root);
    }
    let key_lost = case == Case::KeyLoss;
    let local_evidence = || {
        let overlay = inputs.overlay_for(&scope(inputs));
        ["ownership", "journal"]
            .map(|name| GrainId::of(&std::fs::read(overlay.join(name)).unwrap()))
    };
    let before_local = (key_lost && !lost).then(local_evidence);
    if key_lost {
        std::fs::remove_file(inputs.keys.join("root.seed")).unwrap();
    }
    assert!(inputs.keys.join("client-0.pem").is_file());
    assert!(inputs.keys.join("client-0.key").is_file());
    assert_eq!(inputs.keys.join("root.seed").is_file(), !key_lost);
    if case.stale() {
        race_takeover(harness, inputs, writer, case, lost);
        assert_eq!(head_seq(harness), before_head);
        assert_eq!(root(harness, before_head), before_root);
        assert_eq!(packets(harness, "/publish").len(), before_publishes);
        assert_reader(harness, &[("a", BASE_BYTES)]);
        write_direct(format!(
            "{{\"event\":\"integration.disk_loss\",\"case\":\"{case:?}\",\"lost\":{lost},\"head_before\":{before_head},\"head_after\":{before_head},\"recovery_publications\":0}}\n"
        ).as_bytes());
        return;
    }
    if case == Case::LostReplies {
        std::fs::write(tap(harness).join("lose-takeover"), []).unwrap();
    }
    let recovery = recover(harness, inputs, writer, lost);
    if case == Case::LostReplies {
        assert_lost_takeover(
            harness,
            (before_selection.0, before_selection.1, &before_selection.2),
            lost,
        );
    }
    let conflict = case == Case::SecondWriter || (lost && case == Case::OverlappingSibling);
    let should_publish = matches!(case, Case::Prepared | Case::LostReplies);
    if key_lost {
        recovery.assert_status(1, "RecoverySigningKeyRefused");
        recovery.assert_event("recover.signing_key_refused", 1);
        recovery.assert_event("recover.landed", 0);
        recovery.assert_event("recover.subsumed", 0);
        assert_eq!(store.exists(), !lost);
        assert_eq!((!lost).then(local_evidence), before_local);
        assert_eq!(all_posts(harness), before_posts);
        assert_eq!(selection(harness, writer).unwrap(), before_selection);
    } else if conflict {
        recovery.assert_status(1, "RecoveryConflict");
        recovery.assert_event("recover.conflict", 1);
        recovery.assert_event("recover.subsumed", 0);
        recovery.assert_event("recover.journal_finished", 0);
        assert_eq!(selection(harness, writer).unwrap().2, before_selection.2);
    } else {
        recovery.assert_status(0, if lost { "" } else { "JournalFinished" });
        recovery.assert_event("recover.journal_finished", usize::from(!lost));
        if lost {
            recovery.assert_event("recover.landed", usize::from(should_publish));
            recovery.assert_event("recover.subsumed", usize::from(!should_publish));
            if should_publish {
                assert_eq!(
                    events(&recovery.lines, "recover.landed")
                        .find_map(|line| number_field(line, "seq")),
                    Some(before_head + 1),
                );
            } else {
                let relation = if before_root == before_selection.2 {
                    "equal"
                } else {
                    "later"
                };
                let proof = events(&recovery.lines, "recover.subsumed").next().unwrap();
                assert_eq!(
                    (field(proof, "relation"), number_field(proof, "seq")),
                    (Some(relation), Some(before_head))
                );
            }
        } else if case.cut() {
            recovery.assert_event("recover.fence_settled", 1);
        }
        assert!(
            selection(harness, writer).is_none(),
            "successful recovery did not release the row"
        );
    }
    let after = head_seq(harness);
    assert_eq!(after, before_head + u64::from(should_publish));
    assert_eq!(
        packets(harness, "/publish").len(),
        before_publishes + usize::from(should_publish),
        "unexpected publication dispatch during recovery"
    );
    if should_publish && lost {
        assert_eq!(
            root(harness, after),
            before_selection.2,
            "step 0 must publish the exact registered root"
        );
    } else if !should_publish {
        assert_eq!(root(harness, after), before_root);
    }
    let tail = [PREFIX, TAIL].concat();
    match case {
        Case::Prepared if lost => {
            assert_reader(harness, &[("a", ACK), ("c", PREFIX), ("renamed", RENAMED)]);
        }
        Case::Prepared => assert_reader(
            harness,
            &[
                ("a", ACK),
                ("b", UNSYNCED),
                ("c", &tail),
                ("renamed", RENAMED),
                ("unsynced-rename", UNSYNCED),
            ],
        ),
        Case::OverlappingSibling | Case::SecondWriter => {
            assert_reader(harness, &[("a", WINNER_BYTES)]);
        }
        Case::KeyLoss => assert_reader(harness, &[("a", BASE_BYTES)]),
        _ => assert_reader(harness, &[("a", ACK)]),
    }

    write_direct(format!(
        "{{\"event\":\"integration.disk_loss\",\"case\":\"{case:?}\",\"lost\":{lost},\"head_before\":{before_head},\"head_after\":{after},\"recovery_publications\":{}}}\n",
        usize::from(should_publish)
    ).as_bytes());
}

fn run(case: Case) {
    if !venue(&format!("disk_loss_{case:?}")) {
        return;
    }
    let _row = ROW
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut cases = 0;
    for lost in [true, false] {
        let harness =
            Harness::with_fixture(Some(("a", BASE_BYTES)), LogPaths::Redacted, |fixture| {
                let tap = fixture.dir.join("packets");
                std::fs::create_dir(&tap).unwrap();
                fixture.tap = Some(tap);
            });
        let inputs = WriterInputs::save(&harness, "disk-loss");
        assert!(!inputs.keys.starts_with(inputs.root.join("store")));
        std::fs::write(inputs.root.join("case"), format!("{case:?}")).unwrap();
        if case == Case::LostReplies {
            std::fs::write(tap(&harness).join("lose-acquire"), []).unwrap();
        }
        let mut child = ClientChild::spawn(&inputs, CHILD, CHILD_TEST);
        child.ready("acknowledged");
        let writer = std::fs::read(inputs.root.join("writer"))
            .unwrap()
            .try_into()
            .unwrap();
        let published = case == Case::Published;
        assert_eq!(head_seq(&harness), if published { 2 } else { 1 });
        assert_eq!(
            packets(&harness, "/publish").len(),
            1 + usize::from(published)
        );

        let selected =
            selection(&harness, writer).expect("acknowledged fsync left no authority selection");
        if case == Case::LostReplies {
            let packets = ownership_packets(&harness);
            let receipt = assert_replayed(&packets);
            let request = intent::decode_ownership(&packets[0].body).unwrap();
            let OwnershipMode::Acquire { observed_cursor } = request.mode else {
                panic!("initial grant did not acquire the mounted writer");
            };
            assert_eq!(
                (request.writer, receipt.writer, receipt.epoch),
                (writer, writer, observed_cursor + 1)
            );
            assert_eq!(receipt.epoch, selected.0);
        }
        let keys = TrustedKeys::new([*harness.key.public_key()]).unwrap();
        let prepared = verify_root(&selected.2, &keys);
        assert_eq!(
            (prepared.seq, prepared.parent, prepared.writer_uuid),
            (2, Some(GrainId::of(&root(&harness, 1))), writer)
        );
        if published {
            assert_eq!(root(&harness, 2), selected.2);
        }

        land_before_recovery(case, &harness, &inputs, &mut child, writer, &selected.2);
        assert_eq!(selection(&harness, writer).unwrap(), selected);
        child.stop(true);
        if case == Case::SecondWriter {
            let other = harness.writer(1, "other-writer", 82);
            assert_ne!(other.writer, writer);
            overwrite(&other.mountpoint.join("a"), WINNER_BYTES)
                .sync_all()
                .unwrap();
            other.finish();
        }
        let landed =
            published || case.cut() || matches!(case, Case::AlreadyLanded | Case::SecondWriter);
        assert_eq!(head_seq(&harness), 1 + u64::from(landed));
        assert_eq!(packets(&harness, "/publish").len(), 1 + usize::from(landed));
        assert_recovery(&harness, &inputs, writer, case, lost);
        cases += 1;
        harness.stop();
    }
    assert_eq!(cases, 2);
}

#[test]
fn writable_linux_disk_loss_durable_prepared() {
    run(Case::Prepared);
}

#[test]
fn writable_linux_disk_loss_published() {
    run(Case::Published);
}

#[test]
fn writable_linux_disk_loss_stale_prepared() {
    run(Case::AlreadyLanded);
}

#[test]
fn writable_linux_disk_loss_landed_before_refresh() {
    run(Case::BeforeRefresh);
}

#[test]
fn writable_linux_disk_loss_landed_overlapping_sibling() {
    run(Case::OverlappingSibling);
}

#[test]
fn writable_linux_disk_loss_concurrent_same_path() {
    run(Case::SecondWriter);
}

#[test]
fn writable_linux_disk_loss_key_and_store() {
    run(Case::KeyLoss);
}

#[test]
fn writable_linux_disk_loss_lost_ownership_replies() {
    run(Case::LostReplies);
}

#[test]
fn writable_linux_disk_loss_stale_selections() {
    run(Case::StaleGeneration);
    run(Case::StaleEpoch);
}
