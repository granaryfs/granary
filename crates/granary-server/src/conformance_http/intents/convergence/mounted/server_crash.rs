// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! An authority process restart under a live writable mount.

use super::super::server_crash::{ObservedPacket as Packet, ServerChild};
use super::*;
use crate::authority::crash::Site;
use crate::conformance_http::intents::{acquire, granted, registration, release, takeover};
use granary_client::IntentReply;
use granary_core::intent::Verdict;
use granary_core::{hash::GrainId, overlay_ownership, retained_submission};

const REGISTRATION: (&str, &str) = ("sync.registration", "before_dispatch");

#[derive(Clone, Copy, Debug)]
enum Cut {
    RegistrationUnsent,
    RegistrationRecorded,
    PublicationRecorded,
}
impl Cut {
    fn seam(self) -> (&'static str, &'static str) {
        match self {
            Self::RegistrationUnsent | Self::RegistrationRecorded => REGISTRATION,
            Self::PublicationRecorded => ("sync.commit", "before_submit"),
        }
    }
    fn site(self) -> Option<Site> {
        match self {
            Self::RegistrationRecorded => Some(Site::IntentBeforeReply),
            Self::PublicationRecorded => Some(Site::MarkSynced),
            Self::RegistrationUnsent => None,
        }
    }
    fn registration(self) -> bool {
        self.seam().0 == "sync.registration"
    }
}

fn pending_registration(writer: &WritableHandle, request: Option<GrainId>) -> (Vec<u8>, Vec<u8>) {
    let carrier =
        overlay_ownership::decode(&std::fs::read(writer.overlay.join("ownership")).unwrap())
            .unwrap();
    let pending: Vec<_> = carrier
        .pending
        .iter()
        .filter(|pending| {
            pending.operation == overlay_ownership::Operation::Register
                && !pending.terminal
                && request.is_none_or(|request| GrainId::of(&pending.body) == request)
        })
        .collect();
    let [request] = pending.as_slice() else {
        panic!("no unique retained registration for {request:?}: {carrier:?}");
    };
    (request.body.clone(), request.context.clone())
}

fn publication_path(harness: &Harness, writer: &WritableHandle) -> PathBuf {
    writer
        .overlay
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("publications")
        .join(harness.fixture.scope(harness.addr, 0).digest().unwrap())
        .join(format!("{}.sub", harness.fixture.volume().as_str()))
}

fn publication(harness: &Harness, writer: &WritableHandle) -> retained_submission::Submission {
    retained_submission::decode(&std::fs::read(publication_path(harness, writer)).unwrap()).unwrap()
}

fn candidate(harness: &Harness, writer: &WritableHandle) -> retained_submission::Candidate {
    let record = publication(harness, writer);
    let active: Vec<_> = record
        .candidates
        .iter()
        .filter(|candidate| candidate.role == retained_submission::Role::Active)
        .collect();
    let [candidate] = active.as_slice() else {
        panic!("no unique active candidate: {record:?}");
    };
    (*candidate).clone()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CallerState {
    Pending,
    Acknowledged,
    Failed(Option<i32>),
}

fn hex(bytes: &[u8]) -> Vec<u8> {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
        .into_bytes()
}

fn operation_target(harness: &Harness, registration: bool) -> Vec<u8> {
    format!(
        "/volume/{}/{}",
        harness.fixture.volume().as_str(),
        if registration { "intent" } else { "publish" }
    )
    .into_bytes()
}

fn operation_identity(
    packet: &Packet,
    target: &[u8],
    expected: &[u8],
    publication: Option<&retained_submission::Candidate>,
) -> bool {
    if packet.target != target {
        return false;
    }
    match publication {
        None => GrainId::of(&packet.body) == GrainId::of(expected),
        Some(candidate) => {
            let epoch = hex(&candidate.request.epoch);
            let operation = hex(&candidate.request.operation);
            packet.operation.as_deref() == Some(operation.as_slice())
                && packet.epoch.as_deref() == Some(epoch.as_slice())
        }
    }
}

fn endpoint_packets(
    harness: &Harness,
    child: &ServerChild,
    after: u64,
    before: u64,
    registration: bool,
) -> Vec<Packet> {
    let target = operation_target(harness, registration);
    super::super::server_crash::observed_packets(&child.root)
        .into_iter()
        .filter(|packet| packet.index >= after && packet.index < before && packet.target == target)
        .collect()
}

fn operation_packets(
    harness: &Harness,
    child: &ServerChild,
    after: u64,
    before: u64,
    registration: bool,
    expected: &[u8],
    publication: Option<&retained_submission::Candidate>,
) -> Vec<Packet> {
    let target = operation_target(harness, registration);
    let packets = endpoint_packets(harness, child, after, before, registration);
    assert_operation_packets(&target, expected, publication, &packets);
    packets
}

fn assert_operation_packets(
    target: &[u8],
    expected: &[u8],
    publication: Option<&retained_submission::Candidate>,
    packets: &[Packet],
) {
    for packet in packets {
        let (content_type, epoch, operation) = if let Some(candidate) = publication {
            (
                Some(b"application/vnd.granary.root.v1".as_slice()),
                Some(hex(&candidate.request.epoch)),
                Some(hex(&candidate.request.operation)),
            )
        } else {
            (
                Some(granary_core::intent::MEDIA_REGISTER.as_bytes()),
                None,
                None,
            )
        };
        let expected_packet = super::super::server_crash::PacketWitness {
            method: b"POST",
            target,
            content_type,
            epoch: epoch.as_deref(),
            operation: operation.as_deref(),
            body: expected,
        };
        let actual_packet = super::super::server_crash::PacketWitness {
            method: &packet.method,
            target: &packet.target,
            content_type: packet.content_type.as_deref(),
            epoch: packet.epoch.as_deref(),
            operation: packet.operation.as_deref(),
            body: &packet.body,
        };
        assert_eq!(
            super::super::server_crash::packet_witness(&actual_packet, &expected_packet),
            Ok(()),
            "operation metadata changed: {packet:?}"
        );
    }
}

fn assert_registration_answer(
    registration: &granary_core::intent::Registration<'_>,
    packet: &Packet,
) {
    assert_eq!(
        super::super::server_crash::observed_response(&packet.path),
        Ok(()),
        "registration response was incomplete: {packet:?}"
    );
    let status = std::fs::read_to_string(packet.path.with_extension("status")).unwrap();
    assert_eq!(
        status, "200",
        "registration was not acknowledged: {packet:?}"
    );
    let receipt = granary_core::intent::decode_receipt(
        &std::fs::read(packet.path.with_extension("answer")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        (
            receipt.writer,
            receipt.epoch,
            receipt.instance,
            receipt.generation,
            receipt.state,
        ),
        (
            registration.writer,
            registration.epoch,
            registration.instance,
            registration.generation,
            granary_core::intent::ReceiptState::Live {
                prepared_root_id: registration.root_id()
            },
        ),
        "registration did not receive its live receipt: {packet:?}"
    );
}

fn assert_fenced_answers(packets: &[Packet]) {
    for packet in packets {
        assert_eq!(
            super::super::server_crash::observed_response(&packet.path),
            Ok(()),
            "fenced response was incomplete: {packet:?}"
        );
        let status = std::fs::read_to_string(packet.path.with_extension("status"))
            .unwrap()
            .parse()
            .unwrap();
        let error = super::super::server_crash::optional_packet_file(&packet.path, "error");
        assert_eq!(
            super::super::server_crash::fenced_response(status, error.as_deref()),
            Ok(()),
            "real authority did not answer 503 fenced: {packet:?}"
        );
    }
}

fn assert_registration_sequence<'a>(
    harness: &Harness,
    retained: &[u8],
    packets: &'a [Packet],
    require_newer: bool,
) -> granary_core::intent::Registration<'a> {
    let trusted = TrustedKeys::new([*harness.key.public_key()]).unwrap();
    let volume = harness.fixture.volume();
    let verify = |doc: &granary_core::root::RootDoc, prefix: &[u8]| {
        granary_store::crypto::check_signatures(doc, prefix, &trusted).is_ok()
    };
    let original = granary_core::intent::decode_register(retained, &volume, verify).unwrap();
    let mut previous = (original.generation, retained);
    let mut last = None;
    let target = operation_target(harness, true);
    for packet in packets {
        let request = granary_core::intent::decode_register(&packet.body, &volume, verify).unwrap();
        assert_eq!(
            (
                request.writer,
                request.epoch,
                request.instance,
                !require_newer || request.generation > original.generation,
                request.generation >= previous.0,
                request.generation != previous.0 || packet.body.as_slice() == previous.1,
            ),
            (
                original.writer,
                original.epoch,
                original.instance,
                true,
                true,
                true
            ),
            "registration sequence changed ownership, generation order, or retry bytes: {packet:?}"
        );
        assert_operation_packets(&target, &packet.body, None, std::slice::from_ref(packet));
        assert_registration_answer(&request, packet);
        previous = (request.generation, packet.body.as_slice());
        last = Some(request);
    }
    last.unwrap_or_else(|| panic!("operation sent no registration"))
}

fn authority_log(
    harness: &Harness,
) -> (
    granary_core::authlog::Epoch,
    Vec<granary_core::authlog::Record>,
) {
    let bytes = std::fs::read(
        harness
            .fixture
            .state
            .join(format!("{}.log", harness.fixture.volume().as_str())),
    )
    .unwrap();
    let granary_core::authlog::Classified::Log {
        envelope, records, ..
    } = granary_core::authlog::classify(&bytes, &harness.fixture.volume()).unwrap()
    else {
        panic!("authority log has no envelope");
    };
    (envelope.epoch(), records)
}

fn authority_epoch(harness: &Harness) -> granary_core::authlog::Epoch {
    authority_log(harness).0
}

fn intent_store(harness: &Harness) -> crate::authority::intent::Snapshot {
    crate::authority::intent::codec::decode(
        std::fs::read(
            harness
                .fixture
                .state
                .join(format!("{}.intent", harness.fixture.volume().as_str())),
        )
        .unwrap()
        .as_slice(),
        &harness.fixture.volume(),
        None,
        &TrustedKeys::new([*harness.key.public_key()]).unwrap(),
    )
    .unwrap()
}

#[derive(Clone, Copy)]
enum IntentRequest {
    Acquire,
    Takeover,
    Register,
    Release,
}

fn send_intent(
    harness: &Harness,
    principal: usize,
    operation: IntentRequest,
    body: &[u8],
) -> IntentReply {
    let client = harness.fixture.client(harness.addr, principal);
    let scope = harness.fixture.scope(harness.addr, principal);
    harness
        .runtime
        .block_on(async {
            tokio::time::timeout(WAIT, async {
                match operation {
                    IntentRequest::Acquire => {
                        client
                            .intent_acquire_once(&scope, &harness.fixture.volume(), body)
                            .await
                    }
                    IntentRequest::Takeover => {
                        client
                            .intent_takeover_once(&scope, &harness.fixture.volume(), body)
                            .await
                    }
                    IntentRequest::Register => {
                        client
                            .intent_register_once(
                                &scope,
                                &harness.fixture.volume(),
                                body,
                                |_, _| true,
                            )
                            .await
                    }
                    IntentRequest::Release => {
                        client
                            .intent_release_once(&scope, &harness.fixture.volume(), body)
                            .await
                    }
                }
            })
            .await
        })
        .unwrap_or_else(|_| panic!("intent request exceeded {WAIT:?}"))
        .unwrap()
}

fn witnessed_intent(
    harness: &Harness,
    child: &mut ServerChild,
    principal: usize,
    operation: IntentRequest,
    body: &[u8],
) -> IntentReply {
    let binding = GrainId::of(body).to_string();
    let occurrence = child.arm(Site::IntentBeforeReply, false, &binding);
    let answer = send_intent(harness, principal, operation, body);
    child.reached(
        "reached",
        &Site::IntentBeforeReply.name(),
        occurrence,
        &binding,
    );
    answer
}

fn readback(harness: &Harness, principal: usize) -> (u64, Vec<([u8; 16], u64, u64)>) {
    let trusted = TrustedKeys::new([*harness.key.public_key()]).unwrap();
    let client = harness.fixture.client(harness.addr, principal);
    let scope = harness.fixture.scope(harness.addr, principal);
    let answer = harness
        .runtime
        .block_on(async {
            tokio::time::timeout(
                WAIT,
                client.intent_readback_once(&scope, &harness.fixture.volume(), |doc, prefix| {
                    granary_store::crypto::check_signatures(doc, prefix, &trusted).is_ok()
                }),
            )
            .await
        })
        .unwrap_or_else(|_| panic!("intent readback exceeded {WAIT:?}"))
        .unwrap();
    let decoded = granary_core::intent::decode_readback(
        answer.body(),
        &harness.fixture.volume(),
        |doc, prefix| granary_store::crypto::check_signatures(doc, prefix, &trusted).is_ok(),
    )
    .unwrap();
    (
        decoded.cursor,
        decoded
            .rows
            .iter()
            .map(|row| (row.writer, row.epoch, row.generation))
            .collect(),
    )
}

fn child_lifecycle(child: &mut ServerChild, command: &str, volume: &str) {
    let name = child.send(command);
    child.reached(&format!("{name}.done"), command, 1, volume);
}

fn progress(point: &str, phase: &str, kill: bool, step: &str) {
    write_direct(
        format!(
            "{{\"event\":\"integration.server_crash.progress\",\"point\":\"{point}\",\"phase\":\"{phase}\",\"kill\":{kill},\"step\":\"{step}\"}}\n"
        )
        .as_bytes(),
    );
}

fn reader_contents(harness: &Harness) -> (Vec<u8>, Vec<u8>, Vec<String>) {
    let mut reader = harness.reader();
    let mountpoint = reader.mountpoint.clone();
    let reads = spawn_fuse(move || {
        let base = std::fs::read(mountpoint.join("base")).unwrap();
        let work = std::fs::read(mountpoint.join("work")).unwrap();
        (base, work, mounted_names(&mountpoint))
    });
    let contents = join_fuse_within(reads, &mut reader.mount, WAIT, "fresh reader mount wedged");
    reader.finish();
    contents
}

fn registration_refresh(
    harness: &Harness,
    writer: &WritableHandle,
    authority: &ServerChild,
    start: u64,
    retained: &[u8],
    first_expected: Option<&[u8]>,
    expected_head: u64,
) -> (retained_submission::Candidate, u64, Vec<u8>) {
    let (point, phase) = REGISTRATION;
    let event = held(&writer.faults, REFRESH);
    progress(point, phase, true, "refresh-held");
    let Some(request) = event.request else {
        panic!("landed registration refresh has no request identity: {event:?}");
    };
    let (fresh, context) = pending_registration(writer, Some(request));
    let landed = candidate(harness, writer);
    assert_eq!(
        (
            event.capture > 0,
            context.is_empty(),
            fresh.as_slice() != retained,
            landed.seq,
            head_seq(harness),
        ),
        (true, true, true, expected_head, expected_head),
        "refresh did not hold the retained landing's registration: {event:?}"
    );

    let boundary = super::super::server_crash::observed_packet_cursor(&authority.root);
    writer.faults.resume();
    wait_until(
        || {
            harness.capture.lines().iter().any(|line| {
                field(line, "event") == Some("mount.view")
                    && field(line, "cause") == Some("landed")
                    && field(line, "outcome") == Some("installed")
                    && number_field(line, "seq") == Some(expected_head)
            })
        },
        "writer did not install the landing after its registration refresh",
    );
    progress(point, phase, true, "landing-installed");
    let end = super::super::server_crash::observed_packet_cursor(&authority.root);
    let packets = endpoint_packets(harness, authority, start, end, true);
    let (before_refresh, refresh) =
        packets.split_at(packets.partition_point(|packet| packet.index < boundary));
    assert_eq!(
        (
            before_refresh
                .iter()
                .find(|packet| packet.body == fresh)
                .map(|packet| packet.index),
            refresh.first().map(|packet| packet.body.as_slice()),
            refresh
                .iter()
                .find(|packet| packet.body != fresh)
                .map(|packet| packet.index),
        ),
        (None, Some(fresh.as_slice()), None),
        "held refresh did not dispatch its exact bytes after release: {packets:?}"
    );
    if let Some(expected) = first_expected {
        assert_eq!(
            (
                before_refresh.first().map(|packet| packet.body.as_slice()),
                before_refresh
                    .iter()
                    .find(|packet| packet.body != expected)
                    .map(|packet| packet.index),
            ),
            (Some(expected), None),
            "next fsync did not dispatch its held registration: {before_refresh:?}"
        );
    }
    let require_newer = first_expected.is_some()
        || packets
            .first()
            .is_some_and(|packet| packet.body != retained);
    let registration = assert_registration_sequence(harness, retained, &packets, require_newer);
    let snapshot = intent_snapshot(harness, 0, writer.writer);
    assert_eq!(
        (
            writer.writer,
            snapshot.epoch,
            snapshot.generation,
            snapshot.root.as_slice(),
            snapshot.live_rows,
            snapshot.live_root_bytes,
        ),
        (
            registration.writer,
            registration.epoch,
            registration.generation,
            registration.root,
            1,
            registration.root.len(),
        ),
        "fresh registration did not replace the writer's sole charged row"
    );
    (landed, end, fresh)
}

fn next_registration_sync(
    harness: &Harness,
    writer: &mut WritableHandle,
    authority: &ServerChild,
    installed: u64,
    retained: &[u8],
    head: u64,
) -> (retained_submission::Candidate, u64) {
    let (point, phase) = REGISTRATION;
    writer.faults.arm(point, phase, 1, FaultAction::Block);
    progress(point, phase, true, "next-fsync");
    // A clean file still seals a capture. With no fresh writes, the live
    // loop has no dirty span to take over before the fsync seals it.
    let path = writer.mountpoint.join("work");
    let retry = spawn_fuse(move || std::fs::File::open(path)?.sync_all());
    let event = held(&writer.faults, REGISTRATION);
    progress(point, phase, true, "next-fsync-held");
    let (bytes, context) = pending_registration(writer, event.request);
    let has_capture = event.capture > 0;
    let capture_matches_context = has_capture != context.is_empty();
    assert_eq!(
        (
            event.request,
            has_capture,
            capture_matches_context,
            retry.handle.is_finished(),
            head_seq(harness),
        ),
        (Some(GrainId::of(&bytes)), true, true, false, head),
        "next-fsync submission identity and blocked caller: {event:?}"
    );
    let start = super::super::server_crash::observed_packet_cursor(&authority.root);
    let unexpected = endpoint_packets(harness, authority, installed, start, true);
    assert!(
        unexpected.is_empty(),
        "registration followed the retained install before next fsync dispatched: {unexpected:?}"
    );
    writer.faults.resume_at(REFRESH.0, REFRESH.1);
    progress(point, phase, true, "next-fsync-released");
    let (landed, end, _) = registration_refresh(
        harness,
        writer,
        authority,
        start,
        retained,
        Some(&bytes),
        head + 1,
    );
    join_fuse_within(
        retry,
        &mut writer.mount,
        WRITABLE_JOIN_BOUND,
        "next fsync did not finish after its landing installed",
    )
    .unwrap();
    progress(point, phase, true, "next-fsync-answered");
    (landed, end)
}

#[expect(
    clippy::too_many_lines,
    reason = "paired process cuts keep operation, wire bytes, durable record and reader evidence in one schedule"
)]
fn run(cut: Cut) {
    if !venue(&format!("server_crash_{cut:?}")) {
        return;
    }
    let _row = ROW
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut cases = 0;
    for kill in [true, false] {
        let mut harness = Harness::new(Some(("base", BASE_BYTES)), LogPaths::Redacted);
        assert_eq!(
            harness.store_label, "S3/MinIO",
            "authority process restart requires persistent composed content"
        );
        let prefix = format!("mounted-convergence-{}", harness.keys.run_name().unwrap());
        harness.stop_server();
        let mut child = ServerChild::start(&harness.fixture, &prefix, harness.addr, 42, false);
        let mut writer = harness.writer(0, "writer", 81);
        let before = head_seq(&harness);
        let (point, phase) = cut.seam();
        let registration_restart = kill && cut.registration();
        // The restart's process is executed before the operation below opens
        // `work`: its fsync is held across the restart, and on Linux a child's
        // exec-time close of an inherited descriptor on that file waits for it.
        let mut parked =
            kill.then(|| ServerChild::parked(&harness.fixture, &prefix, harness.addr, 43));
        progress(point, phase, kill, "mount-ready");
        writer.faults.arm(point, phase, 1, FaultAction::Block);
        let cursor = super::super::server_crash::observed_packet_cursor(&child.root);
        let path = writer.mountpoint.join("work");
        let operation_path = path.clone();
        let mut operation = Some(spawn_fuse(move || {
            let work = std::fs::File::create(operation_path)?;
            (&work).write_all(LOSER_BYTES)?;
            work.sync_all()
        }));
        wait_until(
            || !writer.faults.sync_fired().is_empty(),
            "client cut never fired",
        );
        let events = writer.faults.sync_fired();
        let [event] = events.as_slice() else {
            panic!("ambiguous client hold: {events:?}");
        };
        assert_eq!(
            (
                event.name,
                event.phase,
                event.occurrence,
                event.capture > 0,
                operation
                    .as_ref()
                    .is_some_and(|operation| operation.handle.is_finished())
            ),
            (point, phase, 1, true, false),
            "client hold identity and blocked caller: {events:?}"
        );
        progress(point, phase, kill, "client-held");
        let publication = (!cut.registration()).then(|| candidate(&harness, &writer));
        let bytes = publication.as_ref().map_or_else(
            || pending_registration(&writer, None).0,
            |candidate| candidate.root.clone(),
        );
        let mut replay_bytes = bytes.clone();
        let mut replay_publication = publication.clone();
        let mut fresh_judgment = false;
        let mut original_judgment_landed = false;
        let binding = GrainId::of(&bytes).to_string();
        if cut.registration() {
            assert_eq!(
                event.request,
                Some(GrainId::of(&bytes)),
                "held registration changed its request bytes"
            );
        }
        let occurrence = cut.site().map(|site| child.arm(site, kill, &binding));
        if let Some(site) = cut.site() {
            if registration_restart {
                writer.faults.resume_at(REFRESH.0, REFRESH.1);
            } else {
                writer.faults.resume();
            }
            let target = operation_target(&harness, cut.registration());
            wait_until(
                || {
                    super::super::server_crash::observed_packets(&child.root)
                        .iter()
                        .any(|packet| {
                            packet.index >= cursor
                                && operation_identity(packet, &target, &bytes, publication.as_ref())
                        })
                },
                "armed operation did not reach the authority child",
            );
            child.reached("reached", &site.name(), occurrence.unwrap(), &binding);
            progress(point, phase, kill, "authority-cut-reached");
            if let Some(candidate) = &publication {
                let matching: Vec<_> = authority_log(&harness)
                    .1
                    .into_iter()
                    .filter(|record| {
                        record.body().identity().candidate_id() == candidate.id
                            && record.body().identity().operation().as_bytes()
                                == candidate.request.operation
                    })
                    .collect();
                assert!(
                    matching.iter().any(|record| matches!(
                        record.body(),
                        granary_core::authlog::RecordBody::Decision { .. }
                    )),
                    "MarkSynced did not commit the identified decision: {matching:?}"
                );
                if kill {
                    assert_eq!(
                        matching.len(),
                        1,
                        "cut was after the decision reply: {matching:?}"
                    );
                }
            }
            if kill {
                assert!(
                    !operation
                        .as_ref()
                        .is_some_and(|operation| operation.handle.is_finished()),
                    "caller acknowledged before durable-record cut"
                );
            }
        }
        // The control follows the same seam and operation; its HIT continues.
        if cut.site().is_none() {
            let boundary = super::super::server_crash::observed_packet_cursor(&child.root);
            let packets = endpoint_packets(&harness, &child, cursor, boundary, cut.registration());
            assert!(
                packets.is_empty(),
                "client hold dispatched to the pre-crash authority: {packets:?}"
            );
            let name = child.send(&format!("held {point}/{phase} 1 {binding}"));
            child.reached(
                &format!("{name}.done"),
                &format!("{point}/{phase}"),
                1,
                &binding,
            );
        }
        let mut first_sync = None;
        if !kill {
            if cut.site().is_none() {
                writer.faults.resume();
            }
            progress(point, phase, kill, "control-caller-answer");
            let answered = join_fuse_within(
                operation
                    .take()
                    .unwrap_or_else(|| panic!("control FUSE call already joined")),
                &mut writer.mount,
                WRITABLE_JOIN_BOUND,
                "control fsync did not finish after its hold was released",
            );
            assert!(answered.is_ok(), "control fsync failed: {answered:?}");
            first_sync = Some(answered);
        }
        let (mut authority, mut replay_start) = if kill {
            progress(point, phase, kill, "authority-stop");
            child.stop(true);
            let old_boundary = super::super::server_crash::observed_packet_cursor(&child.root);
            if cut.site().is_some() {
                let sent = operation_packets(
                    &harness,
                    &child,
                    cursor,
                    old_boundary,
                    cut.registration(),
                    &bytes,
                    publication.as_ref(),
                );
                assert_eq!(sent.len(), 1, "cut has no unique wire operation: {sent:?}");
            }
            if registration_restart && cut.site().is_none() {
                writer.faults.resume_at(REFRESH.0, REFRESH.1);
                progress(point, phase, kill, "client-released");
            }
            let restarted = parked
                .take()
                .unwrap_or_else(|| panic!("no parked restart"))
                .release(harness.addr);
            if registration_restart {
                // The writer's wall clock is the fixture tick. Moving it past the
                // unsent attempt's backoff admits that attempt's retry.
                harness
                    .fixture
                    .clock
                    .0
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            progress(point, phase, kill, "authority-restarted");
            (restarted, 0)
        } else {
            let old_boundary = super::super::server_crash::observed_packet_cursor(&child.root);
            if cut.registration() {
                let sent = endpoint_packets(&harness, &child, cursor, old_boundary, true);
                assert_eq!(
                    sent.first().map(|packet| packet.body.as_slice()),
                    Some(bytes.as_slice()),
                    "registration control did not dispatch its held request: {sent:?}"
                );
                assert_registration_sequence(&harness, &bytes, &sent, false);
            } else {
                let sent = operation_packets(
                    &harness,
                    &child,
                    cursor,
                    old_boundary,
                    false,
                    &bytes,
                    publication.as_ref(),
                );
                assert_eq!(sent.len(), 1, "cut has no unique wire operation: {sent:?}");
            }
            progress(point, phase, kill, "control-continued");
            (child, cursor)
        };
        // The original fsync or the live loop installs the retained work.
        // A second fsync could take over the same lane or seal another one.
        let refreshed = registration_restart.then(|| {
            registration_refresh(
                &harness,
                &writer,
                &authority,
                replay_start,
                &bytes,
                None,
                before + 1,
            )
        });
        let sync = first_sync.unwrap_or_else(|| {
            progress(point, phase, kill, "first-caller-answer");
            join_fuse_within(
                operation
                    .take()
                    .unwrap_or_else(|| panic!("restart FUSE call already joined")),
                &mut writer.mount,
                WRITABLE_JOIN_BOUND,
                "fsync did not finish across authority restart",
            )
        });
        if let Err(error) = &sync {
            assert_eq!(
                error.raw_os_error(),
                Some(libc::EIO),
                "an authority restart returned an unexpected fsync error"
            );
        }
        assert!(
            !registration_restart || sync.is_ok(),
            "held registration did not land across the authority restart: {sync:?}"
        );
        let mut first_refresh = None;
        let registration_landings = refreshed.map(|(retained, installed, refresh)| {
            let (next, end) = next_registration_sync(
                &harness,
                &mut writer,
                &authority,
                installed,
                &refresh,
                before + 1,
            );
            first_refresh = Some(refresh);
            ((retained, next), end)
        });
        let mut replayed = kill && !registration_restart;
        if replayed && (cut.site().is_some() || sync.is_err()) {
            let failed_boundary =
                super::super::server_crash::observed_packet_cursor(&authority.root);
            if let Some(original) = &publication {
                let exact_retries = operation_packets(
                    &harness,
                    &authority,
                    replay_start,
                    failed_boundary,
                    false,
                    &bytes,
                    Some(original),
                );
                if exact_retries.is_empty() {
                    if sync.is_ok() {
                        assert_eq!(
                            head_seq(&harness),
                            before + 1,
                            "publication fsync succeeded without a visible recovered landing"
                        );
                        replayed = false;
                        progress(point, phase, kill, "first-retry-landed");
                    } else {
                        assert_eq!(
                            sync.as_ref().err().and_then(std::io::Error::raw_os_error),
                            Some(libc::EIO),
                            "unanswered publication returned an unexpected error"
                        );
                        assert_eq!(
                            candidate(&harness, &writer).root,
                            bytes,
                            "unreconciled publication did not retain its exact request"
                        );
                        progress(point, phase, kill, "first-retry-retained");
                    }
                } else {
                    let [packet] = exact_retries.as_slice() else {
                        panic!(
                            "publication produced duplicate recorded-judgment retries: {exact_retries:?}"
                        );
                    };
                    assert_eq!(
                        super::super::server_crash::observed_response(&packet.path),
                        Ok(()),
                        "publication response was incomplete: {packet:?}"
                    );
                    let status =
                        std::fs::read_to_string(packet.path.with_extension("status")).unwrap();
                    let answer = granary_core::authority_answer::decode(
                        &std::fs::read(packet.path.with_extension("answer")).unwrap(),
                    )
                    .unwrap();
                    let valid = match answer {
                        granary_core::authority_answer::PublishAnswer::Landed {
                            receipt, ..
                        } => {
                            status == "200"
                                && receipt.position.epoch.to_bytes() == original.request.epoch
                                && receipt.root_seq == original.seq
                                && receipt.stored_id == original.id
                        }
                        granary_core::authority_answer::PublishAnswer::Accepted {
                            position,
                            candidate_id,
                        }
                        | granary_core::authority_answer::PublishAnswer::Open {
                            position,
                            candidate_id,
                        } => {
                            status == "202"
                                && position.epoch.to_bytes() == original.request.epoch
                                && candidate_id == original.id
                        }
                        _ => false,
                    };
                    assert!(
                        valid,
                        "recorded publication retry answer changed: {answer:?}"
                    );
                    if sync.is_ok() {
                        assert_eq!(
                            head_seq(&harness),
                            before + 1,
                            "publication fsync succeeded before its landing answer"
                        );
                        replayed = false;
                    }
                    progress(point, phase, kill, "first-retry-observed");
                }
            }
            replay_start = failed_boundary;
            if replayed {
                writer.faults.arm(point, phase, 1, FaultAction::Block);
                progress(point, phase, kill, "retry-fsync");
                let retry_path = path.clone();
                let retry = spawn_fuse(move || std::fs::File::open(retry_path)?.sync_all());
                wait_until(
                    || !writer.faults.sync_fired().is_empty(),
                    "next fsync did not reach its submission seam",
                );
                let events = writer.faults.sync_fired();
                let [event] = events.as_slice() else {
                    panic!("ambiguous retained-operation retry: {events:?}");
                };
                assert_eq!(
                    (
                        event.name,
                        event.phase,
                        event.occurrence,
                        event.capture > 0,
                        event.request.is_none(),
                        retry.handle.is_finished()
                    ),
                    (point, phase, 1, true, true, false),
                    "next-fsync submission identity and blocked caller: {events:?}"
                );
                progress(point, phase, kill, "retry-held");
                if let Some(original) = &publication {
                    let take_over_boundary =
                        super::super::server_crash::observed_packet_cursor(&authority.root);
                    let take_over = operation_packets(
                        &harness,
                        &authority,
                        replay_start,
                        take_over_boundary,
                        false,
                        &bytes,
                        Some(original),
                    );
                    assert!(
                        take_over.len() <= 1,
                        "take-over duplicated the retained publication: {take_over:?}"
                    );
                    let retry_publication = candidate(&harness, &writer);
                    if retry_publication.request == original.request {
                        assert!(
                            (retry_publication.root == bytes
                                && retry_publication.number == original.number
                                && retry_publication.id == original.id)
                                || (retry_publication.number > original.number
                                    && ((retry_publication.root == bytes
                                        && retry_publication.id == original.id)
                                        || (retry_publication.root != bytes
                                            && retry_publication.id != original.id))),
                            "take-over neither replayed the retained candidate nor advanced its fresh judgment: {retry_publication:?}"
                        );
                    } else {
                        original_judgment_landed = authority_log(&harness).1.iter().any(|record| {
                            matches!(
                                record.body(),
                                granary_core::authlog::RecordBody::Landed { .. }
                            ) && record.body().identity().operation().as_bytes()
                                == original.request.operation
                        });
                        assert_eq!(
                            (
                                retry_publication.request.epoch,
                                retry_publication.request.operation != original.request.operation,
                                retry_publication.root != bytes,
                                retry_publication.id != original.id,
                                head_seq(&harness)
                            ),
                            (original.request.epoch, true, true, true, before + 1),
                            "next fsync prepared a new operation before take-over installed the retained landing"
                        );
                        fresh_judgment = true;
                    }
                    replay_bytes.clone_from(&retry_publication.root);
                    replay_publication = Some(retry_publication);
                }
                writer.faults.resume();
                join_fuse_within(
                    retry,
                    &mut writer.mount,
                    WRITABLE_JOIN_BOUND,
                    "next fsync did not submit its retained work",
                )
                .unwrap();
            }
        }
        if replayed {
            wait_until(
                || {
                    let boundary =
                        super::super::server_crash::observed_packet_cursor(&authority.root);
                    !endpoint_packets(&harness, &authority, replay_start, boundary, false)
                        .is_empty()
                },
                "restart did not observe the retained operation",
            );
        }
        let replay_boundary = super::super::server_crash::observed_packet_cursor(&authority.root);
        if replayed {
            let packets = operation_packets(
                &harness,
                &authority,
                replay_start,
                replay_boundary,
                false,
                &replay_bytes,
                replay_publication.as_ref(),
            );
            assert_eq!(
                packets.len(),
                1,
                "restart did not receive exactly one publication: {packets:?}"
            );
        }
        let additional_judgment =
            registration_restart || (fresh_judgment && original_judgment_landed);
        let expected_head = before + 1 + u64::from(additional_judgment);
        wait_until(
            || head_seq(&harness) == expected_head,
            "restart did not land the expected publication judgments",
        );
        progress(point, phase, kill, "landing-visible");
        let writer = if let Some((_, installed)) = &registration_landings {
            writer.finish();
            let end = super::super::server_crash::observed_packet_cursor(&authority.root);
            // A stage whose fsync landed keeps its synced mark without a
            // checkpoint boundary, so the unmount seals that clean stage and
            // registers it once more. Nothing is published from it.
            let shutdown = endpoint_packets(&harness, &authority, *installed, end, true);
            assert_eq!(
                shutdown.len(),
                1,
                "unmount did not register its clean stage exactly once: {shutdown:?}"
            );
            assert_registration_sequence(
                &harness,
                first_refresh
                    .as_deref()
                    .unwrap_or_else(|| panic!("no fresh registration before the unmount")),
                &shutdown,
                true,
            );
            let published = endpoint_packets(&harness, &authority, *installed, end, false);
            assert!(
                published.is_empty(),
                "unmount published after the next-fsync install: {published:?}"
            );
            None
        } else {
            Some(writer)
        };
        let (epoch, records) = authority_log(&harness);
        let landed: Vec<_> = records
            .iter()
            .filter_map(|record| match record.body() {
                granary_core::authlog::RecordBody::Landed { identity } => Some(identity),
                _ => None,
            })
            .collect();
        assert_eq!(
            landed.len(),
            2 + usize::from(additional_judgment),
            "base plus the retained and any additional judgment: {landed:?}"
        );
        let (original, replayed) = registration_landings.as_ref().map_or(
            (publication.as_ref(), replay_publication.as_ref()),
            |((retained, next), _)| (Some(retained), Some(next)),
        );
        if let (Some(original), Some(replayed)) = (original, replayed) {
            let landings_for = |operation: [u8; 16]| {
                landed
                    .iter()
                    .filter(|identity| identity.operation().as_bytes() == operation)
                    .count()
            };
            assert_eq!(
                (
                    landings_for(original.request.operation),
                    landings_for(replayed.request.operation),
                    replayed.request.operation != original.request.operation
                ),
                (
                    usize::from(!fresh_judgment || original_judgment_landed),
                    1,
                    fresh_judgment || registration_restart,
                ),
                "publication judgment did not land exactly once: {landed:?}"
            );
        }
        if let Some(((retained, next), _)) = &registration_landings {
            let work: Vec<_> = landed
                .iter()
                .skip(1)
                .map(|identity| (identity.operation().as_bytes(), identity.candidate_id()))
                .collect();
            assert_eq!(
                (
                    head_seq(&harness),
                    epoch.to_bytes() == retained.request.epoch,
                    epoch.to_bytes() == next.request.epoch,
                    work.as_slice(),
                ),
                (
                    expected_head,
                    true,
                    true,
                    [
                        (retained.request.operation.as_slice(), retained.id),
                        (next.request.operation.as_slice(), next.id),
                    ]
                    .as_slice(),
                ),
                "registration restart changed the ordered landing identities or final head: {landed:?}"
            );
        }
        assert_eq!(
            reader_contents(&harness),
            (
                BASE_BYTES.to_vec(),
                LOSER_BYTES.to_vec(),
                vec!["base".to_owned(), "work".to_owned()]
            ),
            "fresh authority reader lost the retained landing"
        );
        if let Some(writer) = writer {
            writer.finish();
        }
        authority.stop(false);
        cases += 1;
        write_direct(format!("{{\"event\":\"integration.server_crash\",\"point\":\"{point}\",\"phase\":\"{phase}\",\"kill\":{kill},\"cases\":1}}\n").as_bytes());
    }
    assert_eq!(cases, 2);
}

#[test]
fn writable_linux_server_crash_registration_before_dispatch() {
    run(Cut::RegistrationUnsent);
}
#[test]
fn writable_linux_server_crash_registration_recorded_before_reply() {
    run(Cut::RegistrationRecorded);
}
#[test]
fn writable_linux_server_crash_publication_recorded_before_reply() {
    run(Cut::PublicationRecorded);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the retained record, failed caller, replay packet and landed operation are one crash schedule"
)]
fn writable_linux_server_crash_publication_before_submit() {
    if !venue("server_crash_publication_before_submit") {
        return;
    }
    let _row = ROW
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut cases = 0;
    for kill in [true, false] {
        let mut harness = Harness::new(Some(("base", BASE_BYTES)), LogPaths::Redacted);
        assert_eq!(harness.store_label, "S3/MinIO");
        let prefix = format!("mounted-convergence-{}", harness.keys.run_name().unwrap());
        harness.stop_server();
        let mut child = ServerChild::start(&harness.fixture, &prefix, harness.addr, 42, false);
        let mut writer = harness.writer(0, "writer", 81);
        let landed_before = authority_log(&harness)
            .1
            .into_iter()
            .filter(|record| {
                matches!(
                    record.body(),
                    granary_core::authlog::RecordBody::Landed { .. }
                )
            })
            .count();
        progress("sync.commit", "before_submit", kill, "mount-ready");
        writer
            .faults
            .arm("sync.commit", "before_submit", 1, FaultAction::Block);
        let cursor = super::super::server_crash::observed_packet_cursor(&child.root);
        let path = writer.mountpoint.join("work");
        let operation_path = path.clone();
        let result = Arc::new(Mutex::new(CallerState::Pending));
        let outcome = result.clone();
        let operation = spawn_fuse(move || {
            let work = std::fs::File::create(operation_path).unwrap();
            (&work).write_all(LOSER_BYTES).unwrap();
            *outcome.lock().unwrap() = match work.sync_all() {
                Ok(()) => CallerState::Acknowledged,
                Err(error) => CallerState::Failed(error.raw_os_error()),
            };
        });
        wait_until(
            || writer.faults.sync_fired().len() == 1,
            "publication did not reach its before-submit hold",
        );
        let events = writer.faults.sync_fired();
        let [event] = events.as_slice() else {
            panic!("ambiguous before-submit hold: {events:?}");
        };
        assert_eq!(
            (
                event.name,
                event.phase,
                event.occurrence,
                event.capture > 0,
                event.request,
                operation.handle.is_finished(),
                *result.lock().unwrap()
            ),
            (
                "sync.commit",
                "before_submit",
                1,
                true,
                None,
                false,
                CallerState::Pending
            ),
            "before-submit seam did not hold the unacknowledged caller: {events:?}"
        );
        let retained_record = publication(&harness, &writer);
        assert!(
            !matches!(
                &retained_record.phase,
                retained_submission::Phase::Unresolved(retained_submission::Probe {
                    reason: retained_submission::ProbeReason::Transport,
                    ..
                })
            ),
            "publication was unresolved before boot 42 stopped"
        );
        let retained = candidate(&harness, &writer);
        progress("sync.commit", "before_submit", kill, "client-held");
        let mut authority = if kill {
            child.stop(true);
            let boundary = super::super::server_crash::observed_packet_cursor(&child.root);
            let packets = endpoint_packets(&harness, &child, cursor, boundary, false);
            assert!(
                packets.is_empty(),
                "before-submit hold dispatched to boot 42: {packets:?}"
            );
            writer.faults.resume();
            wait_until(
                || {
                    matches!(
                        publication(&harness, &writer).phase,
                        retained_submission::Phase::Unresolved(retained_submission::Probe {
                            reason: retained_submission::ProbeReason::Transport,
                            ..
                        })
                    )
                },
                "transport failure did not reach the retained publication record",
            );
            assert_eq!(
                writer.faults.sync_fired().len(),
                1,
                "transport classification waited on a second before-submit hold"
            );
            join_fuse_within(
                operation,
                &mut writer.mount,
                WRITABLE_JOIN_BOUND,
                "unreachable authority did not fail the held fsync",
            );
            assert_eq!(
                *result.lock().unwrap(),
                CallerState::Failed(Some(libc::EIO)),
                "unreachable authority acknowledged the held fsync"
            );
            let unresolved = publication(&harness, &writer);
            let evidence = unresolved
                .candidates
                .iter()
                .find(|candidate| candidate.number == retained.number)
                .map(|candidate| candidate.evidence);
            assert_eq!(
                evidence.map(|evidence| {
                    (
                        evidence.started.checked_sub(retained.evidence.started),
                        evidence.proved_no_write,
                        evidence.last_answered_attempt,
                        evidence.decision_seen,
                    )
                }),
                Some((
                    Some(1),
                    retained.evidence.proved_no_write,
                    retained.evidence.last_answered_attempt,
                    retained.evidence.decision_seen,
                )),
                "transport attempt changed acknowledgement or decision evidence"
            );
            let mut unresolved_candidates = unresolved.candidates;
            for candidate in &mut unresolved_candidates {
                if candidate.number == retained.number {
                    candidate.evidence.started = retained.evidence.started;
                }
            }
            assert_eq!(
                (unresolved.publication_id, unresolved_candidates),
                (retained_record.publication_id, retained_record.candidates),
                "transport classification changed the retained publication"
            );
            let landed: Vec<_> = authority_log(&harness)
                .1
                .into_iter()
                .filter(|record| {
                    matches!(
                        record.body(),
                        granary_core::authlog::RecordBody::Landed { .. }
                    )
                })
                .collect();
            let retained_landings = landed
                .iter()
                .filter(|record| {
                    record.body().identity().operation().as_bytes() == retained.request.operation
                })
                .count();
            assert_eq!(
                (landed.len(), retained_landings),
                (landed_before, 0),
                "dead boot 42 landed the held publication: {landed:?}"
            );
            progress("sync.commit", "before_submit", kill, "transport-unresolved");
            ServerChild::start(&harness.fixture, &prefix, harness.addr, 43, false)
        } else {
            writer.faults.resume();
            join_fuse_within(
                operation,
                &mut writer.mount,
                WRITABLE_JOIN_BOUND,
                "control fsync did not finish after before-submit resumed",
            );
            assert_eq!(
                *result.lock().unwrap(),
                CallerState::Acknowledged,
                "control before-submit fsync was not acknowledged"
            );
            let boundary = super::super::server_crash::observed_packet_cursor(&child.root);
            let sent = operation_packets(
                &harness,
                &child,
                cursor,
                boundary,
                false,
                &retained.root,
                Some(&retained),
            );
            assert_eq!(
                sent.len(),
                1,
                "control did not submit exactly once: {sent:?}"
            );
            child
        };
        let replay_start = super::super::server_crash::observed_packet_cursor(&authority.root);
        let retry = spawn_fuse(move || std::fs::File::open(path)?.sync_all());
        join_fuse_within(
            retry,
            &mut writer.mount,
            WRITABLE_JOIN_BOUND,
            "next fsync did not finish the retained publication",
        )
        .unwrap();
        let replay_boundary = super::super::server_crash::observed_packet_cursor(&authority.root);
        let publish_packets =
            endpoint_packets(&harness, &authority, replay_start, replay_boundary, false);
        let (replayed, fresh): (Vec<_>, Vec<_>) = publish_packets.into_iter().partition(|packet| {
            operation_identity(
                packet,
                &operation_target(&harness, false),
                &retained.root,
                Some(&retained),
            )
        });
        if kill {
            assert_operation_packets(
                &operation_target(&harness, false),
                &retained.root,
                Some(&retained),
                &replayed,
            );
            assert_eq!(
                replayed.len(),
                1,
                "boot 43 did not receive one unchanged retained replay: {replayed:?}"
            );
            assert!(
                fresh.len() <= 1,
                "boot 43 sent more than one separately judged fresh operation: {fresh:?}"
            );
            let replay_before_fresh = replayed
                .first()
                .is_some_and(|replay| fresh.iter().all(|packet| replay.index < packet.index));
            assert!(
                replay_before_fresh,
                "boot 43 judged fresh work before replaying the retained candidate: replayed {replayed:?}, fresh {fresh:?}"
            );
        } else {
            assert!(
                replayed.is_empty() && fresh.len() <= 1,
                "control's next fsync replayed the acknowledged publication or sent more than one fresh operation: replayed {replayed:?}, fresh {fresh:?}"
            );
        }
        let landed: Vec<_> = authority_log(&harness)
            .1
            .into_iter()
            .filter(|record| {
                matches!(
                    record.body(),
                    granary_core::authlog::RecordBody::Landed { .. }
                )
            })
            .collect();
        let retained_landings = landed
            .iter()
            .filter(|record| {
                record.body().identity().operation().as_bytes() == retained.request.operation
            })
            .count();
        assert_eq!(
            retained_landings, 1,
            "retained operation did not land exactly once: {landed:?}"
        );
        for packet in &fresh {
            let operation = packet
                .operation
                .as_deref()
                .unwrap_or_else(|| panic!("fresh publication has no operation: {packet:?}"));
            let count = landed
                .iter()
                .filter(|record| hex(record.body().identity().operation().as_bytes()) == operation)
                .count();
            assert_eq!(count, 1, "fresh operation did not land once: {packet:?}");
        }
        assert_eq!(
            reader_contents(&harness),
            (
                BASE_BYTES.to_vec(),
                LOSER_BYTES.to_vec(),
                vec!["base".to_owned(), "work".to_owned()]
            ),
            "fresh reader lost the before-submit publication"
        );
        writer.finish();
        authority.stop(false);
        cases += 1;
        write_direct(format!("{{\"event\":\"integration.server_crash\",\"point\":\"sync.commit\",\"phase\":\"before_submit\",\"kill\":{kill},\"cases\":1}}\n").as_bytes());
    }
    assert_eq!(cases, 2);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the old-epoch landing, log replacement, intent rebind and chain recovery are one restart schedule"
)]
fn writable_linux_server_crash_stale_epoch_reinitialise_recovers_chain() {
    if !venue("server_crash_stale_epoch_reinitialise_recovers_chain") {
        return;
    }
    let _row = ROW
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut cases = 0;
    for kill in [true, false] {
        let mut harness = Harness::new(Some(("base", BASE_BYTES)), LogPaths::Redacted);
        assert_eq!(harness.store_label, "S3/MinIO");
        let prefix = format!("mounted-convergence-{}", harness.keys.run_name().unwrap());
        harness.stop_server();
        let mut child = ServerChild::start(&harness.fixture, &prefix, harness.addr, 42, true);
        let mut writer = harness.writer(0, "writer", 81);
        let path = writer.mountpoint.join("work");
        let first_path = path.clone();
        let first = spawn_fuse(move || {
            let work = std::fs::File::create(first_path)?;
            (&work).write_all(LOSER_BYTES)?;
            work.sync_all()
        });
        join_fuse_within(
            first,
            &mut writer.mount,
            WRITABLE_JOIN_BOUND,
            "old-epoch setup fsync did not finish",
        )
        .unwrap();
        let old_epoch = authority_epoch(&harness);
        let old_head = head_seq(&harness);
        assert_eq!(old_head, 2, "old epoch did not land the mounted write");
        writer
            .faults
            .arm("sync.commit", "before_submit", 1, FaultAction::Block);
        let stale_path = path.clone();
        let stale = spawn_fuse(move || {
            let work = std::fs::OpenOptions::new().write(true).open(stale_path)?;
            work.set_len(0)?;
            (&work).write_all(WINNER_BYTES)?;
            work.sync_all()
        });
        wait_until(
            || writer.faults.sync_fired().len() == 1,
            "stale candidate did not reach before-submit",
        );
        let events = writer.faults.sync_fired();
        let [event] = events.as_slice() else {
            panic!("ambiguous stale-candidate seam: {events:?}");
        };
        assert_eq!(
            (
                event.name,
                event.phase,
                event.occurrence,
                event.capture > 0,
                stale.handle.is_finished()
            ),
            ("sync.commit", "before_submit", 1, true, false),
            "stale-candidate seam did not hold the caller: {events:?}"
        );
        let retained = candidate(&harness, &writer);
        assert_eq!(
            retained.request.epoch,
            old_epoch.to_bytes(),
            "held candidate was not built under the old epoch"
        );
        child.stop_mounted(kill);
        writer.faults.resume();
        wait_until(
            || {
                matches!(
                    publication(&harness, &writer).phase,
                    retained_submission::Phase::Unresolved(retained_submission::Probe {
                        reason: retained_submission::ProbeReason::Transport,
                        ..
                    })
                )
            },
            "dead old epoch did not leave an unresolved retained candidate",
        );
        let stale_result = join_fuse_within(
            stale,
            &mut writer.mount,
            WRITABLE_JOIN_BOUND,
            "dead old epoch did not answer the stale-candidate fsync",
        );
        assert_eq!(
            stale_result.err().and_then(|error| error.raw_os_error()),
            Some(libc::EIO),
            "dead old epoch acknowledged the stale candidate"
        );
        std::fs::remove_file(
            harness
                .fixture
                .state
                .join(format!("{}.log", harness.fixture.volume().as_str())),
        )
        .unwrap();
        assert!(
            harness
                .fixture
                .state
                .join(format!("{}.intent", harness.fixture.volume().as_str()))
                .is_file(),
            "stale-epoch setup removed the intent store"
        );
        let mut authority = ServerChild::start(&harness.fixture, &prefix, harness.addr, 43, false);
        child_lifecycle(
            &mut authority,
            "initialise",
            harness.fixture.volume().as_str(),
        );
        let new_epoch = authority_epoch(&harness);
        assert_ne!(new_epoch, old_epoch, "re-initialise reused the old epoch");
        let cursor = super::super::server_crash::observed_packet_cursor(&authority.root);
        let second = spawn_fuse(move || std::fs::File::open(&path)?.sync_all());
        join_fuse_within(
            second,
            &mut writer.mount,
            WRITABLE_JOIN_BOUND,
            "stale-epoch fsync did not recover through the chain",
        )
        .unwrap();
        let boundary = super::super::server_crash::observed_packet_cursor(&authority.root);
        let packets = endpoint_packets(&harness, &authority, cursor, boundary, false);
        let answers: Vec<_> = packets
            .iter()
            .map(|packet| {
                assert_eq!(
                    super::super::server_crash::observed_response(&packet.path),
                    Ok(()),
                    "stale-epoch publication response was incomplete: {packet:?}"
                );
                (
                    packet,
                    std::fs::read_to_string(packet.path.with_extension("status")).unwrap(),
                    super::super::server_crash::optional_packet_file(&packet.path, "error"),
                )
            })
            .collect();
        let retained_operation = hex(&retained.request.operation);
        let retained_epoch = hex(&retained.request.epoch);
        let retained_answers: Vec<_> = answers
            .iter()
            .filter(|(packet, _, _)| {
                packet.operation.as_deref() == Some(retained_operation.as_slice())
                    && packet.epoch.as_deref() == Some(retained_epoch.as_slice())
            })
            .map(|(_, status, error)| (status.as_str(), error.as_deref()))
            .collect();
        assert_eq!(
            retained_answers,
            vec![("409", Some(b"epoch-mismatch".as_slice()))],
            "retained operation did not receive exactly one old-epoch mismatch: {answers:?}"
        );
        let recovered = candidate(&harness, &writer);
        assert_eq!(
            (
                recovered.request.epoch,
                recovered.request.operation != retained.request.operation
            ),
            (new_epoch.to_bytes(), true),
            "epoch recovery did not create a fresh current identity"
        );
        let recovered_operation = hex(&recovered.request.operation);
        let recovered_epoch = hex(&recovered.request.epoch);
        let accepted: Vec<_> = answers
            .iter()
            .filter(|(_, status, _)| status == "202")
            .collect();
        assert!(
            (1..=2).contains(&accepted.len())
                && accepted.iter().all(|(packet, _, error)| {
                    error.is_none()
                        && packet.operation.as_deref() != Some(retained_operation.as_slice())
                        && packet.epoch.as_deref() == Some(recovered_epoch.as_slice())
                })
                && accepted.iter().any(|(packet, _, _)| {
                    packet.operation.as_deref() == Some(recovered_operation.as_slice())
                }),
            "new epoch did not accept the recovered identity plus at most one fresh judgment: {answers:?}"
        );
        let landed_operations: Vec<_> = authority_log(&harness)
            .1
            .into_iter()
            .filter_map(|record| {
                matches!(
                    record.body(),
                    granary_core::authlog::RecordBody::Landed { .. }
                )
                .then(|| record.body().identity().operation().as_bytes().to_vec())
            })
            .collect();
        assert!(
            (1..=2).contains(&landed_operations.len())
                && landed_operations.iter().enumerate().all(|(at, operation)| {
                    !landed_operations
                        .iter()
                        .take(at)
                        .any(|earlier| earlier == operation)
                }),
            "epoch recovery duplicated an operation or exceeded its fresh judgment: {landed_operations:?}"
        );
        let recovered_head = head_seq(&harness);
        assert_eq!(
            (recovered_head, intent_store(&harness).epoch),
            (
                old_head + u64::try_from(landed_operations.len()).unwrap(),
                new_epoch
            ),
            "recovered publication or intent rebind did not reach the new epoch"
        );
        assert_eq!(
            reader_contents(&harness),
            (
                BASE_BYTES.to_vec(),
                WINNER_BYTES.to_vec(),
                vec!["base".to_owned(), "work".to_owned()]
            ),
            "fresh reader did not traverse the healthy recovered chain"
        );
        writer.finish();
        authority.stop(false);
        cases += 1;
        write_direct(format!("{{\"event\":\"integration.server_crash\",\"point\":\"sync.commit\",\"phase\":\"epoch-recovery\",\"kill\":{kill},\"cases\":1}}\n").as_bytes());
    }
    assert_eq!(cases, 2);
}

#[test]
fn writable_linux_server_crash_intent_rows_and_zero_rows_survive_restart() {
    if !venue("server_crash_intent_rows_and_zero_rows_survive_restart") {
        return;
    }
    let _row = ROW
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut cases = 0;
    for kill in [true, false] {
        let mut harness = Harness::new(Some(("base", BASE_BYTES)), LogPaths::Redacted);
        assert_eq!(harness.store_label, "S3/MinIO");
        let prefix = format!("mounted-convergence-{}", harness.keys.run_name().unwrap());
        harness.stop_server();
        let mut child = ServerChild::start(&harness.fixture, &prefix, harness.addr, 42, true);
        let writer = harness.writer(0, "writer", 81);
        let acquired_a = send_intent(&harness, 1, IntentRequest::Acquire, &acquire(8, 2, 0));
        let a = granted(&acquired_a).receipt;
        let registered_a = send_intent(&harness, 1, IntentRequest::Register, &registration(a, 1));
        let a = granary_core::intent::decode_receipt(registered_a.body()).unwrap();
        let acquired_b = send_intent(&harness, 1, IntentRequest::Acquire, &acquire(9, 3, a.epoch));
        let b = granted(&acquired_b).receipt;
        let registered_b = send_intent(&harness, 1, IntentRequest::Register, &registration(b, 1));
        let b = granary_core::intent::decode_receipt(registered_b.body()).unwrap();
        let release_b_body = release(b, 1);
        let release_b_answer = witnessed_intent(
            &harness,
            &mut child,
            1,
            IntentRequest::Release,
            &release_b_body,
        );
        assert_eq!(release_b_answer.status(), 200);
        child.stop_mounted(kill);
        let mut authority = ServerChild::start(&harness.fixture, &prefix, harness.addr, 43, false);
        let snapshot = intent_store(&harness);
        let principal = snapshot
            .principals
            .get(harness.fixture.principals.get(1).unwrap())
            .unwrap();
        let row_a = principal.rows.get(&a.writer).unwrap();
        let row_b = principal.rows.get(&b.writer).unwrap();
        assert_eq!(
            (
                principal.h,
                row_a.receipt.state,
                row_a.root.is_empty(),
                row_b.receipt.state,
                row_b.root.is_empty(),
                readback(&harness, 1)
            ),
            (
                b.epoch,
                a.state,
                false,
                granary_core::intent::ReceiptState::Released,
                true,
                (b.epoch, vec![(a.writer, a.epoch, a.generation)])
            ),
            "restart did not preserve the live record and released row"
        );
        let release_a = send_intent(&harness, 1, IntentRequest::Release, &release(a, 1));
        assert_eq!(release_a.status(), 200);
        authority.stop(false);
        authority = ServerChild::start(&harness.fixture, &prefix, harness.addr, 44, false);
        let snapshot = intent_store(&harness);
        let principal = snapshot
            .principals
            .get(harness.fixture.principals.get(1).unwrap())
            .unwrap();
        assert_eq!(
            (
                readback(&harness, 1),
                principal.rows.len(),
                principal
                    .rows
                    .values()
                    .all(|row| row.receipt.state == granary_core::intent::ReceiptState::Released)
            ),
            ((b.epoch, Vec::new()), 2, true),
            "restart with zero live rows lost the cursor or released records"
        );
        writer.finish();
        authority.stop(false);
        cases += 1;
        write_direct(format!("{{\"event\":\"integration.server_crash\",\"point\":\"IntentBeforeReply\",\"phase\":\"rows-and-zero\",\"kill\":{kill},\"cases\":1}}\n").as_bytes());
    }
    assert_eq!(cases, 2);
}

#[test]
fn writable_linux_server_crash_successive_transfers_fence_delayed_high_generation() {
    if !venue("server_crash_successive_transfers_fence_delayed_high_generation") {
        return;
    }
    let _row = ROW
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut cases = 0;
    for kill in [true, false] {
        let mut harness = Harness::new(Some(("base", BASE_BYTES)), LogPaths::Redacted);
        assert_eq!(harness.store_label, "S3/MinIO");
        let prefix = format!("mounted-convergence-{}", harness.keys.run_name().unwrap());
        harness.stop_server();
        let mut child = ServerChild::start(&harness.fixture, &prefix, harness.addr, 42, true);
        let writer = harness.writer(0, "writer", 81);
        let acquired = send_intent(&harness, 1, IntentRequest::Acquire, &acquire(7, 2, 0));
        let old = granted(&acquired).receipt;
        let registered = send_intent(&harness, 1, IntentRequest::Register, &registration(old, 1));
        let old = granary_core::intent::decode_receipt(registered.body()).unwrap();
        let delayed_register = registration(old, 99);
        let delayed_release = release(old, 99);
        let first_transfer = witnessed_intent(
            &harness,
            &mut child,
            1,
            IntentRequest::Takeover,
            &takeover(old, 3),
        );
        let first = granted(&first_transfer).receipt;
        assert!(first.epoch > old.epoch);
        child.stop_mounted(kill);
        let mut authority = ServerChild::start(&harness.fixture, &prefix, harness.addr, 43, false);
        let second_transfer =
            send_intent(&harness, 1, IntentRequest::Takeover, &takeover(first, 4));
        let second = granted(&second_transfer).receipt;
        let third_transfer =
            send_intent(&harness, 1, IntentRequest::Takeover, &takeover(second, 5));
        let third = granted(&third_transfer).receipt;
        assert_eq!(
            (
                first.epoch > old.epoch,
                second.epoch > first.epoch,
                third.epoch > second.epoch,
                third.instance
            ),
            (true, true, true, [5; 16]),
            "successive transfers did not advance ownership across restart"
        );
        let delayed_registration =
            send_intent(&harness, 1, IntentRequest::Register, &delayed_register);
        let decoded = granary_core::intent::decode_register(
            &delayed_register,
            &harness.fixture.volume(),
            |_, _| true,
        )
        .unwrap();
        assert_eq!(
            delayed_registration.registration(&granary_core::intent::RegisterRequest {
                writer: old.writer,
                epoch: old.epoch,
                instance: old.instance,
                generation: 99,
                root_id: decoded.root_id(),
            }),
            Verdict::Superseded(third),
            "delayed high-G registration regained ownership after restart"
        );
        let delayed_release_answer =
            send_intent(&harness, 1, IntentRequest::Release, &delayed_release);
        assert_eq!(
            delayed_release_answer.release(&granary_core::intent::ReleaseRequest {
                writer: old.writer,
                epoch: old.epoch,
                instance: old.instance,
                generation: 99,
            }),
            Verdict::Superseded(third),
            "delayed high-G release regained ownership after restart"
        );
        let snapshot = intent_store(&harness);
        let recorded = snapshot
            .principals
            .get(harness.fixture.principals.get(1).unwrap())
            .and_then(|principal| principal.rows.get(&old.writer))
            .map(|row| row.receipt)
            .unwrap();
        assert_eq!(
            recorded, third,
            "durable row differs from the last transfer"
        );
        writer.finish();
        authority.stop(false);
        cases += 1;
        write_direct(format!("{{\"event\":\"integration.server_crash\",\"point\":\"IntentBeforeReply\",\"phase\":\"successive-transfer\",\"kill\":{kill},\"cases\":1}}\n").as_bytes());
    }
    assert_eq!(cases, 2);
}

#[test]
fn writable_linux_server_crash_store_loss_refusals() {
    if !venue("server_crash_store_loss_refusals") {
        return;
    }
    let _row = ROW
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut cases = 0;
    for mode in ["absent", "unbound", "re-provisioned-empty"] {
        for kill in [true, false] {
            let mut harness = Harness::new(Some(("base", BASE_BYTES)), LogPaths::Redacted);
            assert_eq!(harness.store_label, "S3/MinIO");
            let prefix = format!("mounted-convergence-{}", harness.keys.run_name().unwrap());
            harness.stop_server();
            let mut child = ServerChild::start(&harness.fixture, &prefix, harness.addr, 42, true);
            let writer = harness.writer(0, "writer", 81);
            let acquired = send_intent(&harness, 1, IntentRequest::Acquire, &acquire(6, 2, 0));
            let row = granted(&acquired).receipt;
            let register = registration(row, 1);
            let registered =
                witnessed_intent(&harness, &mut child, 1, IntentRequest::Register, &register);
            let row = granary_core::intent::decode_receipt(registered.body()).unwrap();
            child.stop_mounted(kill);
            let log = harness
                .fixture
                .state
                .join(format!("{}.log", harness.fixture.volume().as_str()));
            let intents = harness
                .fixture
                .state
                .join(format!("{}.intent", harness.fixture.volume().as_str()));
            if mode != "absent" {
                std::fs::remove_file(&log).unwrap();
            }
            if mode != "unbound" {
                std::fs::remove_file(&intents).unwrap();
            }
            let mut authority =
                ServerChild::start(&harness.fixture, &prefix, harness.addr, 43, false);
            if mode == "re-provisioned-empty" {
                child_lifecycle(
                    &mut authority,
                    "initialise",
                    harness.fixture.volume().as_str(),
                );
            }
            let body = release(row, 1);
            let refused = send_intent(&harness, 1, IntentRequest::Release, &body);
            let judged = refused.release(&granary_core::intent::ReleaseRequest {
                writer: row.writer,
                epoch: row.epoch,
                instance: row.instance,
                generation: 1,
            });
            if mode == "re-provisioned-empty" {
                assert_eq!(
                    (refused.status(), judged),
                    (409, Verdict::Absent),
                    "re-provisioned empty store did not answer intent-absent"
                );
            } else {
                assert_eq!(
                    (refused.status(), judged),
                    (
                        503,
                        Verdict::Unknown(granary_core::intent::UnknownCause::Unavailable)
                    ),
                    "{mode} store did not answer unavailable"
                );
            }
            writer.finish();
            authority.stop(false);
            cases += 1;
            write_direct(format!("{{\"event\":\"integration.server_crash\",\"point\":\"IntentBeforeReply\",\"phase\":\"store-loss-{mode}\",\"kill\":{kill},\"cases\":1}}\n").as_bytes());
        }
    }
    assert_eq!(cases, 6);
}

#[test]
fn writable_linux_server_crash_intent_eviction_and_exhaustion() {
    if !venue("server_crash_intent_eviction_and_exhaustion") {
        return;
    }
    let _row = ROW
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut cases = 0;
    for kill in [true, false] {
        let mut harness = Harness::new(Some(("base", BASE_BYTES)), LogPaths::Redacted);
        assert_eq!(harness.store_label, "S3/MinIO");
        let prefix = format!("mounted-convergence-{}", harness.keys.run_name().unwrap());
        harness.stop_server();
        let mut child = ServerChild::start(&harness.fixture, &prefix, harness.addr, 42, true);
        let writer = harness.writer(0, "writer", 81);
        let acquired = send_intent(&harness, 1, IntentRequest::Acquire, &acquire(5, 2, 0));
        let row = granted(&acquired).receipt;
        let release_body = release(row, 1);
        let released = witnessed_intent(
            &harness,
            &mut child,
            1,
            IntentRequest::Release,
            &release_body,
        );
        assert_eq!(released.status(), 200);
        child.stop_mounted(kill);
        let mut authority = ServerChild::start(&harness.fixture, &prefix, harness.addr, 43, false);
        child_lifecycle(
            &mut authority,
            "maintain",
            harness.fixture.volume().as_str(),
        );
        let absent = send_intent(&harness, 1, IntentRequest::Release, &release_body);
        assert_eq!(
            absent.release(&granary_core::intent::ReleaseRequest {
                writer: row.writer,
                epoch: row.epoch,
                instance: row.instance,
                generation: 1,
            }),
            Verdict::Absent,
            "evicted released row remained addressable"
        );
        assert_eq!(
            readback(&harness, 1),
            (row.epoch, Vec::new()),
            "eviction did not retain the allocator cursor"
        );
        authority.stop(false);
        let mut snapshot = intent_store(&harness);
        snapshot
            .principals
            .get_mut(harness.fixture.principals.get(1).unwrap())
            .unwrap()
            .h = u64::MAX;
        let mut bytes = Vec::new();
        crate::authority::intent::codec::encode(&snapshot, &mut bytes).unwrap();
        std::fs::write(
            harness
                .fixture
                .state
                .join(format!("{}.intent", harness.fixture.volume().as_str())),
            bytes,
        )
        .unwrap();
        authority = ServerChild::start(&harness.fixture, &prefix, harness.addr, 44, false);
        let exhausted_body = acquire(4, 9, u64::MAX);
        let exhausted = send_intent(&harness, 1, IntentRequest::Acquire, &exhausted_body);
        assert_eq!(
            exhausted.ownership(&exhausted_body).unwrap(),
            Verdict::EpochExhausted,
            "exhausted cursor allocated another ownership epoch"
        );
        writer.finish();
        authority.stop(false);
        cases += 1;
        write_direct(format!("{{\"event\":\"integration.server_crash\",\"point\":\"IntentBeforeReply\",\"phase\":\"eviction-exhaustion\",\"kill\":{kill},\"cases\":1}}\n").as_bytes());
    }
    assert_eq!(cases, 2);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "real sync-failure, fenced HTTP response and retained client evidence share one ordered schedule"
)]
fn writable_linux_server_crash_fenced_retains_submission() {
    if !venue("server_crash_fenced_retains_submission") {
        return;
    }
    let _row = ROW
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut cases = 0;
    for kill in [true, false] {
        let mut harness = Harness::new(Some(("base", BASE_BYTES)), LogPaths::Redacted);
        assert_eq!(harness.store_label, "S3/MinIO");
        let prefix = format!("mounted-convergence-{}", harness.keys.run_name().unwrap());
        harness.stop_server();
        let mut child = ServerChild::start(&harness.fixture, &prefix, harness.addr, 42, false);
        let mut writer = harness.writer(0, "writer", 81);
        progress("file-sync", "fenced", kill, "mount-ready");
        writer.faults.arm_repeated(
            "sync.commit",
            "before_submit",
            std::num::NonZeroU64::new(2).unwrap(),
            FaultAction::Block,
        );
        let path = writer.mountpoint.join("work");
        let operation_path = path.clone();
        let result = Arc::new(Mutex::new(CallerState::Pending));
        let outcome = result.clone();
        let operation = spawn_fuse(move || {
            let work = std::fs::File::create(operation_path).unwrap();
            (&work).write_all(LOSER_BYTES).unwrap();
            *outcome.lock().unwrap() = match work.sync_all() {
                Ok(()) => CallerState::Acknowledged,
                Err(error) => CallerState::Failed(error.raw_os_error()),
            };
        });
        wait_until(
            || writer.faults.sync_fired().len() == 1,
            "fence setup did not hold publication",
        );
        progress("file-sync", "fenced", kill, "client-held");
        let before = publication(&harness, &writer);
        let retained = candidate(&harness, &writer);
        let cursor = super::super::server_crash::observed_packet_cursor(&child.root);
        let name = child.send("fail-sync");
        child.reached(&format!("{name}.done"), "fail-sync", 1, "file-sync");
        writer.faults.resume_one();
        wait_until(
            || writer.faults.sync_fired().len() == 2,
            "fenced publication did not exhaust its first bounded drive",
        );
        progress("file-sync", "fenced", kill, "bounded-drive-finished");
        let fenced_boundary = super::super::server_crash::observed_packet_cursor(&child.root);
        let fenced_packets = operation_packets(
            &harness,
            &child,
            cursor,
            fenced_boundary,
            false,
            &retained.root,
            Some(&retained),
        );
        assert_eq!(
            fenced_packets.len(),
            1,
            "second fault did not bound the first fenced send"
        );
        assert_fenced_answers(&fenced_packets);
        let name = child.send("fenced");
        child.reached(&format!("{name}.done"), "fenced", 1, "file-sync");
        let after = publication(&harness, &writer);
        assert_eq!(
            (
                after.publication_id,
                after
                    .candidates
                    .iter()
                    .any(|candidate| candidate.root == retained.root)
            ),
            (before.publication_id, true),
            "fenced publication discarded work: {after:?}"
        );
        assert_ne!(
            *result.lock().unwrap(),
            CallerState::Acknowledged,
            "fenced publication acknowledged before process termination"
        );
        assert!(
            staging_payloads(&writer)
                .iter()
                .any(|bytes| bytes == LOSER_BYTES),
            "fence discarded overlay payload"
        );
        writer.faults.resume_one();
        assert!(
            finished_within(&operation.handle, WAIT),
            "fenced fsync did not answer after its blocked retry was released"
        );
        assert_eq!(
            *result.lock().unwrap(),
            CallerState::Failed(Some(libc::ESTALE)),
            "fenced refusal did not fail the original caller"
        );
        progress("file-sync", "fenced", kill, "caller-answered");
        let post_fence_boundary = super::super::server_crash::observed_packet_cursor(&child.root);
        let post_fence_packets = operation_packets(
            &harness,
            &child,
            fenced_boundary,
            post_fence_boundary,
            false,
            &retained.root,
            Some(&retained),
        );
        assert_fenced_answers(&post_fence_packets);
        assert_eq!(
            (fenced_packets.len(), post_fence_packets.len()),
            (1, 7),
            "fence did not expose the coordinator's eight bounded sends"
        );
        let (mut authority, replay_start) = if kill {
            progress("file-sync", "fenced", kill, "authority-stop");
            child.stop(true);
            let stopped_boundary = super::super::server_crash::observed_packet_cursor(&child.root);
            let stopped_packets = endpoint_packets(
                &harness,
                &child,
                post_fence_boundary,
                stopped_boundary,
                false,
            );
            assert!(
                stopped_packets.is_empty(),
                "fenced coordinator dispatched before process termination: {stopped_packets:?}"
            );
            let restarted = ServerChild::start(&harness.fixture, &prefix, harness.addr, 43, false);
            let replay_start = super::super::server_crash::observed_packet_cursor(&restarted.root);
            progress("file-sync", "fenced", kill, "authority-restarted");
            (restarted, replay_start)
        } else {
            progress("file-sync", "fenced", kill, "authority-continued");
            (child, post_fence_boundary)
        };
        let events = writer.faults.sync_fired();
        let [first, second] = events.as_slice() else {
            panic!("fenced publication has ambiguous fault events: {events:?}");
        };
        assert_eq!(
            (
                first.name,
                first.phase,
                first.occurrence,
                second.name,
                second.phase,
                second.occurrence,
                *result.lock().unwrap()
            ),
            (
                "sync.commit",
                "before_submit",
                1,
                "sync.commit",
                "before_submit",
                2,
                CallerState::Failed(Some(libc::ESTALE))
            ),
            "fenced caller acknowledged or retried another seam: {events:?}"
        );
        assert_eq!(
            candidate(&harness, &writer).root,
            retained.root,
            "fenced client replaced its retained candidate"
        );
        assert_eq!(
            head_seq(&harness),
            1,
            "fenced authority landed a publication"
        );
        progress("file-sync", "fenced", kill, "retry-fsync");
        let retry = spawn_fuse(move || std::fs::File::open(path)?.sync_all());
        let retry = join_fuse_within(
            retry,
            &mut writer.mount,
            WAIT,
            "fenced mount did not answer the next fsync",
        );
        assert_eq!(
            retry.err().and_then(|error| error.raw_os_error()),
            Some(libc::ESTALE),
            "fenced mount retried or acknowledged a later fsync"
        );
        progress("file-sync", "fenced", kill, "retry-refused");
        assert_eq!(
            *result.lock().unwrap(),
            CallerState::Failed(Some(libc::ESTALE)),
            "fenced fsync acknowledged after its terminal error"
        );
        let replay_boundary = super::super::server_crash::observed_packet_cursor(&authority.root);
        let replay_packets =
            endpoint_packets(&harness, &authority, replay_start, replay_boundary, false);
        assert!(
            replay_packets.is_empty(),
            "fenced client sent a publication after restart: {replay_packets:?}"
        );
        assert_eq!(
            head_seq(&harness),
            1,
            "fenced publication landed after restart"
        );
        join_fuse_within(
            operation,
            &mut writer.mount,
            WAIT,
            "fenced fsync did not finish after recovery",
        );
        writer.finish();
        authority.stop(false);
        cases += 1;
        write_direct(format!("{{\"event\":\"integration.server_crash\",\"point\":\"file-sync\",\"phase\":\"fenced\",\"kill\":{kill},\"cases\":1}}\n").as_bytes());
    }
    assert_eq!(cases, 2);
}
