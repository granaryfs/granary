// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Release retries preserve exact evidence. Grants retire older terminal Releases.

use super::*;
use crate::writable_store::IntentCompletion;
use granary_core::overlay_ownership::{self as ownership, Carrier, Pending};

mod absence;
mod eviction;
mod handshake;
mod lifecycle;

fn exchange(
    client: &mut WritableStore<SimIo>,
    authority: &mut Authority,
    request: &PendingIntent,
    at: u64,
) -> Result<IntentCompletion, CoordinationError> {
    exchange_with(client, request, at, || authority.send(request))
}

fn exchange_with(
    client: &mut WritableStore<SimIo>,
    request: &PendingIntent,
    at: u64,
    send: impl FnOnce() -> IntentReply,
) -> Result<IntentCompletion, CoordinationError> {
    client.dispatch(request, &Tick(at))?;
    let answer = send();
    client.complete(
        request,
        Ok(&answer),
        &Tick(at + 1),
        &mut SeededRng::new(1),
        0,
        None,
    )
}

fn releases(carrier: &Carrier) -> impl Iterator<Item = &Pending> {
    carrier
        .pending
        .iter()
        .filter(|pending| pending.operation == Operation::Release)
}

fn released_then_reopened() -> (Scratch, SimIo, WritableStore<SimIo>, Authority) {
    let (scratch, io, mut client, mut authority) = serving();
    let request = client
        .prepare_release(&Tick(100), crate::DEFAULT_RESOLUTION_BOUND, None)
        .unwrap();
    let completion = exchange(&mut client, &mut authority, &request, 100).unwrap();
    assert_eq!(
        completion,
        IntentCompletion::Accepted(authority.row.unwrap())
    );
    assert_eq!(client.snapshot().phase, Phase::Released);
    assert_eq!(authority.row.unwrap().state, ReceiptState::Released);
    let prior = releases(client.snapshot()).next().unwrap().clone();
    assert!(prior.terminal && prior.answered);
    drop(client);
    io.crash();
    let client = start(&scratch, &io, 30);
    assert_eq!(releases(client.snapshot()).collect::<Vec<_>>(), [&prior]);
    (scratch, io, client, authority)
}

fn take_over(client: &mut WritableStore<SimIo>, authority: &mut Authority) -> Carrier {
    let before = intent::decode_receipt(&client.snapshot().current).unwrap();
    let request = client.prepare_succession(&Tick(1010)).unwrap();
    let completion = exchange(client, authority, &request, 1010).unwrap();
    let granted = authority.row.unwrap();
    assert_eq!(completion, IntentCompletion::Accepted(granted));
    assert!(granted.epoch > before.epoch);
    assert_eq!(client.snapshot().phase, Phase::OwnedStart);
    client.snapshot().clone()
}

fn register_after_remount(
    client: &mut WritableStore<SimIo>,
    authority: &mut Authority,
    io: &SimIo,
) {
    open(client, io);
    let request = client
        .prepare_registration(
            &root(client.writer_uuid(), 2),
            vec![],
            &Tick(1020),
            |_, _| true,
        )
        .unwrap();
    let completion = exchange(client, authority, &request, 1020).unwrap();
    let registered = authority.row.unwrap();
    assert_eq!(completion, IntentCompletion::Accepted(registered));
    assert!(matches!(registered.state, ReceiptState::Live { .. }));
}

#[track_caller]
fn assert_remount_release(
    client: &mut WritableStore<SimIo>,
    authority: &mut Authority,
    post_grant: &Carrier,
    prepared: Result<PendingIntent, CoordinationError>,
    former_codec_error: &str,
) {
    let request = prepared.unwrap_or_else(|error| {
        assert!(
            matches!(&error, CoordinationError::Codec(ownership::Error(message)) if *message == former_codec_error),
            "unexpected release preparation failure: {error:?}"
        );
        panic!("release preparation rejected: {error}");
    });
    let completion = exchange(client, authority, &request, 1030).unwrap();
    let row = authority.row.unwrap();
    assert_eq!(row.state, ReceiptState::Released, "authority row");
    assert_eq!(completion, IntentCompletion::Accepted(row));
    assert_eq!(client.snapshot().phase, Phase::Released);
    let release = intent::decode_release(request.bytes()).unwrap();
    assert_eq!(release.epoch, row.epoch);
    assert_eq!(
        release.epoch,
        intent::decode_receipt(&post_grant.current).unwrap().epoch
    );
    let pending = releases(client.snapshot()).collect::<Vec<_>>();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].body, request.bytes());
    assert!(pending[0].terminal && pending[0].answered);
    assert_eq!(releases(post_grant).count(), 0, "post-grant release slots");
}

#[test]
fn release_after_remount_and_registration_uses_the_new_epoch() {
    let (_scratch, io, mut client, mut authority) = released_then_reopened();
    let post_grant = take_over(&mut client, &mut authority);
    register_after_remount(&mut client, &mut authority, &io);
    let prepared = client.prepare_release(&Tick(1030), crate::DEFAULT_RESOLUTION_BOUND, None);
    assert_remount_release(
        &mut client,
        &mut authority,
        &post_grant,
        prepared,
        "pending slots",
    );
}

#[test]
fn release_after_clean_remount_reuses_the_generation() {
    let (_scratch, _io, mut client, mut authority) = released_then_reopened();
    let post_grant = take_over(&mut client, &mut authority);
    client.enter_recovery_serving().unwrap();
    let prepared = client.prepare_release(&Tick(1030), crate::DEFAULT_RESOLUTION_BOUND, None);
    assert_remount_release(
        &mut client,
        &mut authority,
        &post_grant,
        prepared,
        "pending order",
    );
    assert_eq!(authority.row.unwrap().generation, post_grant.sent);
}

#[test]
fn recovery_release_after_remount_uses_the_new_epoch() {
    let (_scratch, _io, mut client, mut authority) = released_then_reopened();
    let post_grant = take_over(&mut client, &mut authority);
    let prepared = client.prepare_recovery_release(&Tick(1030), crate::DEFAULT_RESOLUTION_BOUND);
    assert_remount_release(
        &mut client,
        &mut authority,
        &post_grant,
        prepared,
        "pending order",
    );
}

#[test]
fn fenced_takeover_keeps_the_terminal_release() {
    let (_scratch, io, mut client, mut authority) = released_then_reopened();
    let prior = releases(client.snapshot()).next().unwrap().clone();
    let request = client.prepare_succession(&Tick(1010)).unwrap();
    let before_fence = client.snapshot().revision;
    authority.cursor += 1;
    authority.row = Some(Receipt {
        epoch: authority.cursor,
        instance: [40; 16],
        ..authority.row.unwrap()
    });
    assert!(matches!(
        exchange(&mut client, &mut authority, &request, 1010),
        Err(CoordinationError::Fenced {
            recorded_generation: Some(_)
        })
    ));
    let fenced = ownership::decode(&io.recovered_bytes("ownership").unwrap()).unwrap();
    assert_eq!(fenced.phase, Phase::Fenced);
    assert_eq!(fenced.revision, client.snapshot().revision);
    assert!(fenced.revision > before_fence);
    assert_eq!(
        intent::decode_receipt(&fenced.fence_evidence).unwrap(),
        authority.row.unwrap()
    );
    assert_eq!(
        releases(&fenced).collect::<Vec<_>>(),
        [&prior],
        "fence revision release evidence"
    );
}

#[test]
fn expired_unknown_release_that_never_landed_is_replayed_before_the_next_grant() {
    let (scratch, io, mut client, mut authority) = serving();
    let request = client
        .prepare_release(&Tick(100), crate::DEFAULT_RESOLUTION_BOUND, Some(1000))
        .unwrap();
    client.dispatch(&request, &Tick(100)).unwrap();
    let completion = client
        .complete(
            &request,
            Err(IntentTransportError::Transport),
            &Tick(101),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    assert_eq!(completion, IntentCompletion::Unknown);
    let mut rearmed = releases(client.snapshot()).next().unwrap().clone();
    assert!(!rearmed.terminal && !rearmed.answered && rearmed.answer.is_empty());
    rearmed.eligible = 1000;
    rearmed.expires = 31_000;
    client.settle_expired_release(&Tick(1000)).unwrap();
    assert_eq!(client.snapshot().phase, Phase::Releasing);
    assert_eq!(releases(client.snapshot()).collect::<Vec<_>>(), [&rearmed]);
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 30);
    assert_eq!(releases(client.snapshot()).collect::<Vec<_>>(), [&rearmed]);
    assert!(matches!(
        client.prepare_succession(&Tick(1000)),
        Err(CoordinationError::Refused("IntentOwnershipUnresolved"))
    ));
    let [replay] = client.retained_requests().try_into().unwrap();
    assert_eq!(replay.bytes(), request.bytes());
    assert_eq!(
        exchange(&mut client, &mut authority, &replay, 1000).unwrap(),
        IntentCompletion::Accepted(authority.row.unwrap())
    );
    assert_eq!(client.snapshot().phase, Phase::Released);
    assert_eq!(authority.row.unwrap().state, ReceiptState::Released);
    let post_grant = take_over(&mut client, &mut authority);
    register_after_remount(&mut client, &mut authority, &io);
    let prepared = client.prepare_release(&Tick(1030), crate::DEFAULT_RESOLUTION_BOUND, None);
    assert_remount_release(
        &mut client,
        &mut authority,
        &post_grant,
        prepared,
        "pending slots",
    );
}

#[test]
fn expired_release_never_dispatched_is_retired_unsent() {
    let (scratch, io, mut client, _authority) = serving();
    client
        .prepare_release(&Tick(100), crate::DEFAULT_RESOLUTION_BOUND, Some(1000))
        .unwrap();
    let mut retired = releases(client.snapshot()).next().unwrap().clone();
    assert_eq!(retired.attempts, 0);
    retired.terminal = true;
    client.settle_expired_release(&Tick(1000)).unwrap();
    drop(client);
    io.crash();
    let client = start(&scratch, &io, 30);
    assert_eq!(releases(client.snapshot()).collect::<Vec<_>>(), [&retired]);
    assert!(client.retained_requests().is_empty());
}

#[test]
fn expired_release_of_a_displaced_owner_is_retired_unsent() {
    for wrong_epoch in [false, true] {
        let (scratch, io, mut client, _authority) = serving();
        let request = client
            .prepare_release(&Tick(100), crate::DEFAULT_RESOLUTION_BOUND, Some(1000))
            .unwrap();
        client.dispatch(&request, &Tick(100)).unwrap();
        let mut carrier = client.snapshot().clone();
        let pending = carrier
            .pending
            .iter_mut()
            .find(|p| p.operation == Operation::Release)
            .unwrap();
        let mut release = intent::decode_release(&pending.body).unwrap();
        if wrong_epoch {
            release.epoch += 1;
        } else {
            release.instance = [99; 16];
        }
        pending.body = intent::encode_release(release).unwrap();
        let mut retired = pending.clone();
        retired.terminal = true;
        drop(client);
        io.mutate_recovered("ownership", |bytes| {
            *bytes = ownership::encode(&carrier).unwrap();
        });
        io.crash();
        let mut client = start(&scratch, &io, 30);
        client.settle_expired_release(&Tick(1000)).unwrap();
        assert_eq!(releases(client.snapshot()).collect::<Vec<_>>(), [&retired]);
        assert!(client.retained_requests().is_empty());
    }
}

#[test]
fn grant_keeps_same_epoch_terminal_and_older_nonterminal_release_evidence() {
    // The codec permits one Release slot, so exercise each guard in its own carrier.
    for (same_epoch, terminal) in [(true, true), (false, false)] {
        let (scratch, io, mut client, mut authority) = released_then_reopened();
        client.prepare_succession(&Tick(1010)).unwrap();
        let mut carrier = client.snapshot().clone();
        let pending = carrier
            .pending
            .iter_mut()
            .find(|pending| pending.operation == Operation::Release)
            .unwrap();
        let mut release = intent::decode_release(&pending.body).unwrap();
        release.epoch += u64::from(same_epoch);
        pending.body = intent::encode_release(release).unwrap();
        pending.terminal = terminal;
        pending.answered = false;
        pending.answer.clear();
        let expected = pending.clone();
        drop(client);
        io.mutate_recovered("ownership", |bytes| {
            *bytes = ownership::encode(&carrier).unwrap();
        });
        io.crash();
        let mut client = start(&scratch, &io, 50);
        let request = client
            .retained_requests()
            .into_iter()
            .find(|request| request.operation() == Operation::Ownership)
            .unwrap();
        let completion = exchange(&mut client, &mut authority, &request, 1010).unwrap();
        let granted = authority.row.unwrap();
        assert_eq!(completion, IntentCompletion::Accepted(granted));
        assert_eq!(release.epoch == granted.epoch, same_epoch);
        assert_eq!(
            releases(client.snapshot()).collect::<Vec<_>>(),
            [&expected],
            "same epoch: {same_epoch}, terminal: {terminal}"
        );
    }
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}
impl Capture {
    fn contains(&self, event: &str, kind: &str, class: &str) -> bool {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .any(|line| {
                line.contains("\"level\":\"ERROR\"")
                    && line.contains(&format!("\"event\":\"{event}\""))
                    && line.contains(&format!("\"kind\":\"{kind}\""))
                    && line.contains(&format!("\"class\":\"{class}\""))
            })
    }
    fn subscriber(&self) -> Box<dyn tracing::Subscriber + Send + Sync> {
        crate::observe::subscriber(
            crate::observe::LogFormat::Json,
            tracing_subscriber::EnvFilter::new("trace"),
            self.clone(),
        )
    }
}

fn accepted_release_control() {
    let (_scratch, _io, mut client, mut authority) = serving();
    let request = client
        .prepare_release(&Tick(100), crate::DEFAULT_RESOLUTION_BOUND, Some(1000))
        .unwrap();
    client.dispatch(&request, &Tick(100)).unwrap();
    let answer = authority.send(&request);
    client
        .complete(
            &request,
            Ok(&answer),
            &Tick(101),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    assert_eq!(
        (
            client.snapshot().phase,
            authority.sends.len(),
            client.snapshot().pending.last().unwrap().terminal
        ),
        (Phase::Released, 3, true),
        "release control includes acquire, initial registration and one release"
    );
}

#[test]
fn terminal_release_refusals_are_loud_and_keep_evidence() {
    let mut cases = 0;
    for (status, token, reason) in [
        (400, "bad-request", "IntentTerminalRefusal"),
        (403, "no-principal", "IntentTerminalRefusal"),
        (404, "unknown-target", "IntentNotImplemented"),
    ] {
        accepted_release_control();
        let (_scratch, _io, mut client, _authority) = serving();
        let request = client
            .prepare_release(&Tick(100), crate::DEFAULT_RESOLUTION_BOUND, Some(1000))
            .unwrap();
        client.dispatch(&request, &Tick(100)).unwrap();
        let before = client.snapshot().current.clone();
        let answer = reply(status, Some(token), None, vec![]);
        let events = Capture::default();
        let result = tracing::subscriber::with_default(events.subscriber(), || {
            client.complete(
                &request,
                Ok(&answer),
                &Tick(101),
                &mut SeededRng::new(1),
                0,
                None,
            )
        });
        assert_eq!(
            (
                result.as_ref().err().map(ToString::to_string),
                events.contains("op.failed", "session", "refused"),
                events.contains("op.failed", "unmount", "refused")
            ),
            (Some(format!("intent refused: {reason}")), true, true),
            "terminal release diagnostic and failure events for {status}/{token}"
        );
        let pending = client.snapshot().pending.last().unwrap();
        assert_eq!(
            (
                client.snapshot().phase,
                pending.terminal,
                pending.attempts,
                pending.body.iter().eq(request.bytes()),
                client.snapshot().current == before
            ),
            (Phase::Releasing, true, 1, true, true),
            "terminal release preserves exact request and live receipt"
        );
        assert!(matches!(
            client.dispatch(&request, &Tick(102)),
            Err(CoordinationError::Refused("IntentRequestRetired"))
        ));
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[test]
fn unknown_release_retries_exact_bytes_and_expires_loudly() {
    let mut cases = 0;
    for status in [None, Some(500), Some(503), Some(429)] {
        accepted_release_control();
        let (_scratch, _io, mut client, mut authority) = serving();
        let request = client
            .prepare_release(&Tick(100), crate::DEFAULT_RESOLUTION_BOUND, Some(1000))
            .unwrap();
        let before = client.snapshot().current.clone();
        let events = Capture::default();
        let expired = tracing::subscriber::with_default(events.subscriber(), || {
            for attempt in 1..=2 {
                let at = if attempt == 1 {
                    100
                } else {
                    client.snapshot().pending.last().unwrap().eligible
                };
                client.dispatch(&request, &Tick(at)).unwrap();
                // A lost reply can follow a successful remote release. Retrying
                // it still uses the exact request retained before the first send.
                let _accepted = authority.send(&request);
                let answer = status.map(|status| {
                    reply(
                        status,
                        Some(if status == 429 {
                            "rate-limited"
                        } else {
                            "intent-unavailable"
                        }),
                        None,
                        vec![],
                    )
                });
                let response = answer.as_ref().ok_or(IntentTransportError::Transport);
                let result = client.complete(
                    &request,
                    response,
                    &Tick(at + 1),
                    &mut SeededRng::new(1),
                    if status == Some(429) { 200 } else { 0 },
                    None,
                );
                assert!(
                    matches!(result, Ok(crate::IntentCompletion::Unknown)),
                    "unknown release outcome: {result:?}"
                );
                let pending = client.snapshot().pending.last().unwrap();
                assert_eq!(
                    (
                        pending.terminal,
                        pending.attempts,
                        pending.expires,
                        pending.body.iter().eq(request.bytes()),
                        client.snapshot().current == before
                    ),
                    (false, attempt, 1000, true, true),
                    "unknown release preserves live evidence and absolute bound"
                );
            }
            assert!(
                !events.contains("op.failed", "session", "unavailable"),
                "retryable outcomes are not terminal deadline failures"
            );
            client.dispatch(&request, &Tick(1000))
        });
        assert_eq!(
            (
                expired.as_ref().err().map(ToString::to_string),
                events.contains("op.failed", "session", "unavailable")
            ),
            (Some("intent refused: IntentRetryDeadline".to_owned()), true),
            "expired release diagnostic and unavailable event"
        );
        assert_eq!(
            (
                client.snapshot().phase,
                authority.sends.len(),
                authority
                    .sends
                    .iter()
                    .skip(2)
                    .all(|body| body.iter().eq(request.bytes())),
                client.snapshot().pending.last().unwrap().terminal
            ),
            (Phase::Releasing, 4, true, false),
            "two exact release sends, no acknowledgement, no evidence discard"
        );
        cases += 1;
    }
    assert_eq!(cases, 4);
}

#[test]
fn release_horizon_clamps_long_configuration_and_retains_expired_request() {
    let mut cases = 0;
    for (bound, enclosing, expires) in [
        (std::time::Duration::from_secs(30), None, 30_100),
        (std::time::Duration::from_hours(48), None, 86_400_100),
        (std::time::Duration::from_hours(48), Some(1000), 1000),
    ] {
        accepted_release_control();
        let (_scratch, _io, mut client, _authority) = serving();
        let request = client
            .prepare_release(&Tick(100), bound, enclosing)
            .unwrap();
        client.dispatch(&request, &Tick(100)).unwrap();
        let events = Capture::default();
        let result = tracing::subscriber::with_default(events.subscriber(), || {
            client.dispatch(&request, &Tick(expires))
        });
        assert_eq!(
            (
                result.as_ref().err().map(ToString::to_string),
                events.contains("op.failed", "session", "unavailable")
            ),
            (Some("intent refused: IntentRetryDeadline".to_owned()), true),
            "release horizon diagnostic and unavailable event"
        );
        let pending = client.snapshot().pending.last().unwrap();
        assert_eq!(
            (
                client.snapshot().phase,
                pending.expires,
                pending.terminal,
                pending.attempts,
                pending.body.iter().eq(request.bytes())
            ),
            (Phase::Releasing, expires, false, 1, true),
            "expired release preserves exact evidence under the original horizon"
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[test]
fn release_event_capture_requires_one_complete_error_record() {
    let valid = br#"{"level":"ERROR","event":"op.failed","kind":"session","class":"refused"}"#;
    let mut cases = 0;
    for malformed in [
        b"".as_slice(),
        br#"{"level":"INFO","event":"op.failed","kind":"session","class":"refused"}"#,
        br#"{"level":"ERROR","event":"op.retry","kind":"session","class":"refused"}"#,
        br#"{"level":"ERROR","event":"op.failed","kind":"unmount","class":"refused"}"#,
        br#"{"level":"ERROR","event":"op.failed","kind":"session","class":"unavailable"}"#,
        b"{\"level\":\"ERROR\",\"event\":\"op.failed\"}\n{\"kind\":\"session\",\"class\":\"refused\"}",
    ] {
        let good = Capture(Arc::new(Mutex::new(valid.to_vec())));
        let bad = Capture(Arc::new(Mutex::new(malformed.to_vec())));
        assert_eq!(
            (good.contains("op.failed", "session", "refused"),
             bad.contains("op.failed", "session", "refused")),
            (true, false),
            "event capture must discriminate complete ERROR record, case {cases}"
        );
        cases += 1;
    }
    assert_eq!(cases, 6);
}
