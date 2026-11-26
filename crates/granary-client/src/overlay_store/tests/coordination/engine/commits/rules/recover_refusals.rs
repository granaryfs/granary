// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
//! `gran recover` rows for saved admission refusals.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reveal {
    Nothing,
    Foreign,
}

type RetainedAnswer = (String, Option<(u16, String)>, u16);

#[derive(Debug)]
struct Seen {
    result: String,
    sends: usize,
    archived: bool,
    retained: Option<RetainedAnswer>,
}

struct Case {
    scratch: Scratch,
    io: SimIo,
    remote: Arc<Remote>,
    writer: [u8; 16],
    record: granary_core::retained_submission::Submission,
}

fn case(runtime: &tokio::runtime::Runtime, plan: &[PublishPlan], reveal: Reveal) -> Case {
    let (fixture, lane) = sealed_boundary(runtime);
    fixture
        .remote
        .publication_plan
        .lock()
        .unwrap()
        .extend(plan.iter().copied());
    let before = budget::saved(&fixture);
    let first = runtime.block_on(Box::pin(fixture.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::ExplicitRecovery,
        SyncOptions::default(),
    )));
    let record = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| budget::saved(&fixture)))
        .unwrap_or(before);
    println!(
        "OBS mount drive plan_len={} -> {:?} admission={:?} sends={}",
        plan.len(),
        first
            .as_ref()
            .map(|r| (
                format!("{:?}", r.outcome)
                    .chars()
                    .take(20)
                    .collect::<String>(),
                r.uncertain
            ))
            .map_err(ToString::to_string),
        fixture
            .store
            .lock()
            .unwrap()
            .sync_admission_open()
            .map_err(|e| e.to_string()),
        fixture.remote.publication_sends.lock().unwrap().len(),
    );
    let candidate = record.candidates.first().unwrap().clone();
    let (scratch, io, remote, local) = fixture.reload_carrier();
    let writer = local.writer_uuid();
    drop(local);
    let published = match reveal {
        Reveal::Foreign => Some(runtime.block_on(super::selected::one_file(
            &remote,
            b"foreign",
            b"occupied",
            [99; 16],
        ))),
        Reveal::Nothing => None,
    };
    if let Some(root) = published {
        let seq = granary_core::root::decode_root(&root).unwrap().seq;
        assert_eq!(seq, candidate.seq);
        remote.published.lock().unwrap().insert(seq, root);
    }
    Case {
        scratch,
        io,
        remote,
        writer,
        record,
    }
}

fn recover(case: &Case, runtime: &tokio::runtime::Runtime, ack: Option<[u8; 16]>) -> Seen {
    let result = recovery_outcome(
        &case.scratch,
        &case.io,
        &case.remote,
        runtime,
        case.writer,
        None,
        ack,
        FaultControl::default(),
    );
    let mut reopened = start(&case.scratch, &case.io, 131);
    let retained = super::selected::retained(&mut reopened).map(|r| {
        (
            budget::publication_hex(r.publication_id),
            r.last_response
                .as_ref()
                .map(|a| (a.status, String::from_utf8_lossy(&a.token).into_owned())),
            r.unavailable_exemptions,
        )
    });
    let digest = case.record.scope.digest().unwrap();
    let archived = reopened
        .publication_transaction(|journal| {
            journal.archived(&digest, &case.record.volume, case.record.publication_id)
        })
        .unwrap();
    Seen {
        result: match &result {
            Ok(outcome) => format!("Ok({outcome:?})"),
            Err(error) => format!("Err({error})"),
        },
        sends: case.remote.publication_sends.lock().unwrap().len(),
        archived,
        retained,
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the scripted continuation cases share one table and assertion loop"
)]
fn recover_refusal_missing_explore() {
    use PublishPlan as P;
    let runtime = runtime();
    for (name, plan, reveal, steps) in [
        (
            "E missing; ack+Land; plain; plain",
            vec![P::MissingReference],
            Reveal::Nothing,
            vec![(true, Some(P::Land)), (false, None), (false, None)],
        ),
        (
            "F missing; plain x2; ack+Missing x2; plain",
            vec![P::MissingReference],
            Reveal::Nothing,
            vec![
                (false, None),
                (false, None),
                (true, Some(P::MissingReference)),
                (true, Some(P::MissingReference)),
                (false, None),
            ],
        ),
        (
            "G timeout+missing foreign; plain; ack+Missing; plain",
            vec![P::Timeout, P::MissingReference],
            Reveal::Foreign,
            vec![
                (false, None),
                (true, Some(P::MissingReference)),
                (false, None),
            ],
        ),
        (
            "H timeout+missing nothing; plain; ack+Missing; ack+Land; plain",
            vec![P::Timeout, P::MissingReference],
            Reveal::Nothing,
            vec![
                (false, None),
                (true, Some(P::MissingReference)),
                (true, Some(P::Land)),
                (false, None),
            ],
        ),
        (
            "I missing; ack+Invalid; plain; plain",
            vec![P::MissingReference],
            Reveal::Nothing,
            vec![
                (true, Some(P::InvalidReference)),
                (false, None),
                (false, None),
            ],
        ),
        (
            "J missing; ack+Unavailable; plain; ack+Timeout; plain",
            vec![P::MissingReference],
            Reveal::Nothing,
            vec![
                (true, Some(P::Unavailable)),
                (false, None),
                (true, Some(P::Timeout)),
                (false, None),
            ],
        ),
    ] {
        let case = case(&runtime, &plan, reveal);
        println!(
            "OBS {name} pub={}",
            budget::publication_hex(case.record.publication_id)
        );
        for (index, (ack, answer)) in steps.into_iter().enumerate() {
            if let Some(answer) = answer {
                case.remote
                    .publication_plan
                    .lock()
                    .unwrap()
                    .push_back(answer);
            }
            let before = case.remote.publication_sends.lock().unwrap().len();
            let missing_before = {
                let mut reopened = start(&case.scratch, &case.io, 131);
                super::selected::retained(&mut reopened).is_some_and(|r| {
                    r.publication_id == case.record.publication_id
                        && r.last_response
                            .is_some_and(|a| a.status == 400 && a.token == b"missing-reference")
                })
            };
            let seen = recover(&case, &runtime, ack.then_some(case.record.publication_id));
            if missing_before {
                assert_eq!(
                    (seen.sends - before, seen.archived, seen.retained.is_some()),
                    (usize::from(ack), false, true),
                    "{name} step{index}: (sends by this run, archived, still retained) over a saved missing-reference: {seen:?}"
                );
            }
            println!(
                "OBS {name} step{index} ack={ack}: {seen:?} plan_left={}",
                case.remote.publication_plan.lock().unwrap().len()
            );
            case.remote.publication_plan.lock().unwrap().clear();
        }
    }
}

#[test]
fn recover_refusal_wrong_ack() {
    let runtime = runtime();
    let case = case(&runtime, &[PublishPlan::MissingReference], Reveal::Nothing);
    let mut other = case.record.publication_id;
    other[0] ^= 0xff;
    let seen = recover(&case, &runtime, Some(other));
    println!("OBS wrong-ack: {seen:?}");
    assert_eq!(
        (seen.sends, seen.archived, seen.retained.is_some()),
        (1, false, true)
    );
}

/// Plain recovery completes after stripping the refused boundary and a rerun
/// finds no work to send.
#[test]
fn recover_refusal_settles_without_an_error_after_archiving() {
    let runtime = runtime();
    for (refusal, token) in [
        (PublishPlan::InvalidReference, "invalid-reference"),
        (PublishPlan::WorkLimit, "publish-work-limit"),
    ] {
        let case = case(&runtime, &[PublishPlan::Timeout, refusal], Reveal::Foreign);
        let seen = recover(&case, &runtime, None);
        println!("OBS settled refusal: {seen:?}");
        assert!(
            !(seen.archived && seen.result.starts_with("Err(")),
            "recover archived the refused publication and stripped its boundary, then returned an error: {seen:?}"
        );
        assert_eq!(
            (
                seen.archived,
                seen.result.starts_with("Ok("),
                seen.result.contains(token)
            ),
            (true, true, true),
            "plain recovery must finish with the saved refusal: {seen:?}"
        );
        let rerun = recover(&case, &runtime, None);
        assert_eq!(
            (rerun.result.as_str(), rerun.sends),
            ("Ok(NothingOwed)", seen.sends),
            "plain recovery rerun must converge without another publish: {rerun:?}"
        );
    }
}

/// The never-landed proof makes the reported refusal certain.
#[test]
fn recover_refusal_text_is_certain_after_a_never_landed_proof() {
    let runtime = runtime();
    for refusal in [PublishPlan::InvalidReference, PublishPlan::WorkLimit] {
        let case = case(&runtime, &[PublishPlan::Timeout, refusal], Reveal::Foreign);
        let seen = recover(&case, &runtime, None);
        assert!(
            !(seen.archived && seen.result.contains("earlier attempts unresolved")),
            "archived on a never-landed proof, reported as unresolved: {seen:?}"
        );
    }
}

/// Recover reports the mount's saved refusal after the mount strips its boundary.
#[test]
fn recover_refusal_after_mount_terminal_refusal_names_the_token() {
    let runtime = runtime();
    for (refusal, token) in [
        (PublishPlan::InvalidReference, "invalid-reference"),
        (PublishPlan::WorkLimit, "publish-work-limit"),
    ] {
        let case = case(&runtime, &[refusal], Reveal::Nothing);
        let seen = recover(&case, &runtime, None);
        println!("OBS mount-terminal then recover: {seen:?}");
        assert!(
            seen.result.contains(token),
            "recover after a mount-terminal {token}: result names no token and sends went 1 -> {}: {seen:?}",
            seen.sends
        );
        assert_eq!(
            (seen.result.starts_with("Ok("), seen.sends, seen.archived),
            (true, 2, true),
            "reporting the refusal must preserve recovery's publication: {seen:?}"
        );
    }
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "damage and restore only the fixture's private archive"
)]
fn recover_refusal_report_unavailable_after_mount_terminal_refusal() {
    use tracing_subscriber::layer::SubscriberExt as _;

    struct UnprotectArchive(PathBuf);
    impl tracing_subscriber::Layer<tracing_subscriber::Registry> for UnprotectArchive {
        #[expect(
            clippy::disallowed_methods,
            reason = "change only the fixture archive's mode after durable recovery"
        )]
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _: tracing_subscriber::layer::Context<'_, tracing_subscriber::Registry>,
        ) {
            if event.metadata().name() == "recover.journal_finished" {
                std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o400)).unwrap();
            }
        }
    }

    let runtime = runtime();
    let case = case(&runtime, &[PublishPlan::InvalidReference], Reveal::Nothing);
    let archives = {
        let mut local = start(&case.scratch, &case.io, 131);
        local
            .publication_transaction(|journal| journal.list_archives(&case.record.volume))
            .unwrap()
    };
    let [archive] = archives.as_slice() else {
        panic!("expected the mount's sole archive, got {archives:?}");
    };
    assert_eq!(
        (archive.settled, archive.submission.publication_id),
        (true, case.record.publication_id)
    );
    let bytes = std::fs::read(&archive.path).unwrap();

    let subscriber = tracing_subscriber::registry().with(UnprotectArchive(archive.path.clone()));
    let result = tracing::subscriber::with_default(subscriber, || {
        recovery_outcome(
            &case.scratch,
            &case.io,
            &case.remote,
            &runtime,
            case.writer,
            None,
            None,
            FaultControl::default(),
        )
    });
    assert_eq!(
        std::fs::metadata(&archive.path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o400,
        "the completion event must make the archive fail its custody check: {result:?}"
    );
    std::fs::set_permissions(&archive.path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut reopened = start(&case.scratch, &case.io, 131);
    let after = reopened
        .publication_transaction(|journal| journal.list_archives(&case.record.volume))
        .unwrap();
    let sends = case.remote.publication_sends.lock().unwrap().len();
    let expected_reason = format!("{}: unprotected mode", archive.path.display());
    assert_eq!(
        (
            matches!(&result,
                Ok(crate::RecoveryOutcome::JournalFinishedWithUnavailableRefusalReport {
                    base_seq: 2,
                    refusals,
                    reason,
                }) if refusals.is_empty() && *reason == expected_reason),
            reopened.recovery_released(),
            sends,
            after.len(),
            std::fs::read(&archive.path).unwrap() == bytes,
        ),
        (true, true, 2, 1, true),
        "expected finished recovery with unavailable refusal report ({expected_reason}), unchanged sends and archive: {result:?}"
    );
}
