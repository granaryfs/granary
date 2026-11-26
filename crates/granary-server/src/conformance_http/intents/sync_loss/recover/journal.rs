// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

struct ImmediateDelay;
impl RecoveryDelay for ImmediateDelay {
    fn jitter(&mut self, _: Duration) -> Duration {
        Duration::ZERO
    }
    fn wait(&mut self, _: Duration) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(std::future::ready(()))
    }
}

#[derive(Clone, Default)]
struct RecoveryEvents(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for RecoveryEvents {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RecoveryEvents {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}
impl RecoveryEvents {
    fn guard(&self) -> tracing::subscriber::DefaultGuard {
        tracing::subscriber::set_default(granary_client::subscriber(
            granary_client::LogFormat::Json,
            tracing_subscriber::EnvFilter::new("trace"),
            self.clone(),
        ))
    }
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// The real authority acknowledged `a`; the local journal also retains a suffix.
async fn journal_store(fx: &Fixture, addr: SocketAddr, mode: &str) -> ([u8; 16], Arc<Cut>) {
    let (writer, _, content) = writer_at(fx, addr, "journal-store").await;
    let a = writer.create("a", b"acknowledged");
    acknowledged(&writer, &[a]).await;
    let durable = content.objects.lock().unwrap().clone();
    {
        let mut local = writer.local.lock().unwrap();
        for (id, bytes) in durable {
            local.put_immutable(id, &bytes).unwrap();
        }
    }
    if mode == "plain" {
        writer.create("residual", b"remaining");
    } else {
        let mut secure = SeededSecureRandom::for_incarnation(91, 1);
        let lane = writer
            .engine
            .construct_commit(SyncOptions::default(), &mut secure)
            .await
            .unwrap();
        writer.create("residual", b"remaining");
        if mode == "strip" {
            writer.remote.deny_publications.store(8, Ordering::Relaxed);
        } else {
            writer.local.lock().unwrap().fault_control().arm(
                "sync.commit",
                "before_replace",
                1,
                granary_client::FaultAction::Fail,
            );
        }
        let result = Box::pin(writer.engine.drive_commit(
            &lane,
            &mut secure,
            &mut ImmediateDelay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ))
        .await;
        assert_eq!(
            (
                result
                    .as_ref()
                    .is_ok_and(|r| r.outcome == PublicationOutcome::Exhausted),
                result.is_err()
            ),
            (mode == "strip", mode != "strip"),
            "mode={mode}: {result:?}"
        );
    }
    let id = recorded(&writer).writer;
    let remote = writer.remote.clone();
    writer.crash().await;
    (id, remote)
}

#[tokio::test]
async fn settled_and_plain_dirty_journals_finish_without_archive_provenance() {
    let mut cases = 0;
    for mode in ["plain", "strip", "install"] {
        let fx = Fixture::new(None);
        let server = fx.start(1, roomy(), true, None).await;
        let (writer, remote) = Box::pin(journal_store(&fx, server.addr, mode)).await;
        let events = RecoveryEvents::default();
        let _guard = events.guard();
        let result = command(
            &fx,
            server.addr,
            remote.clone(),
            fx.dir.join("journal-store"),
            writer,
            None,
        )
        .await;
        assert_eq!(
            (
                result,
                head_file(&fx, server.addr, "a").await,
                head_file(&fx, server.addr, "residual").await,
                phase(&fx, server.addr, "journal-store"),
                live_rows(&fx, server.addr).await,
                remote.publication_sends.lock().unwrap().len(),
                events
                    .text()
                    .contains("\"event\":\"recover.journal_finished\"")
            ),
            (
                Ok(()),
                Some(b"acknowledged".to_vec()),
                Some(b"remaining".to_vec()),
                Phase::Released,
                0,
                match mode {
                    "plain" => 1,
                    "strip" => 9,
                    _ => 2,
                },
                true
            ),
            "mode={mode}, cases={}, {}",
            cases + 1,
            events.text()
        );
        server.stop().await;
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[tokio::test]
async fn completed_settlement_and_install_do_not_hide_unfinished_remainder() {
    let mut cases = 0;
    for mode in ["strip", "install"] {
        let fx = Fixture::new(None);
        let server = fx.start(1, roomy(), true, None).await;
        let (writer, remote) = Box::pin(journal_store(&fx, server.addr, mode)).await;
        remote.recovery_faults.arm(
            "sync.commit",
            "before_submit",
            1,
            granary_client::FaultAction::Fail,
        );
        let events = RecoveryEvents::default();
        let _guard = events.guard();
        let result = command(
            &fx,
            server.addr,
            remote.clone(),
            fx.dir.join("journal-store"),
            writer,
            None,
        )
        .await;
        let text = events.text();
        assert_eq!(
            (
                result.is_err(),
                remote.recovery_faults.sync_fired().len(),
                live_rows(&fx, server.addr).await,
                phase(&fx, server.addr, "journal-store") == Phase::Released,
                text.contains("\"event\":\"recover.fence_settled\""),
                text.contains("\"event\":\"recover.journal_blocked\""),
                text.contains("\"event\":\"recover.journal_finished\"")
            ),
            (true, 1, 1, false, true, true, false),
            "mode={mode}, cases={}, {result:?}, {text}",
            cases + 1
        );
        let restored = command(
            &fx,
            server.addr,
            remote,
            fx.dir.join("journal-store"),
            writer,
            None,
        )
        .await;
        assert_eq!(
            (
                restored,
                head_file(&fx, server.addr, "residual").await,
                live_rows(&fx, server.addr).await
            ),
            (Ok(()), Some(b"remaining".to_vec()), 0),
            "mode={mode}"
        );
        server.stop().await;
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[tokio::test]
async fn same_head_conflict_refuses_without_release_or_finished_event() {
    let mut cases = 0;
    for conflict in [true, false] {
        let fx = Fixture::new(None);
        let server = fx.start(1, roomy(), true, None).await;
        let (writer, remote) = Box::pin(journal_store(&fx, server.addr, "plain")).await;
        let http = fx.client(server.addr, 0);
        let foreign = prepared(
            &fx,
            &http,
            &[(if conflict { "a" } else { "other" }, b"foreign")],
            [77; 16],
        )
        .await;
        land(&fx, server.addr, &http, foreign.clone(), "foreign").await;
        for _ in 0..if conflict { 2 } else { 1 } {
            let events = RecoveryEvents::default();
            let _guard = events.guard();
            let result = command(
                &fx,
                server.addr,
                remote.clone(),
                fx.dir.join("journal-store"),
                writer,
                None,
            )
            .await;
            let text = events.text();
            assert_eq!(
                (
                    result.err(),
                    live_rows(&fx, server.addr).await,
                    text.contains("\"event\":\"recover.conflict\""),
                    text.contains("\"event\":\"recover.journal_finished\"")
                ),
                (
                    conflict.then(|| "intent refused: RecoveryConflict".to_owned()),
                    usize::from(conflict),
                    conflict,
                    !conflict
                ),
                "conflict={conflict}, cases={}, {text}",
                cases + 1
            );
            if conflict {
                assert_eq!(head(&fx, server.addr).await, foreign);
            }
            cases += 1;
        }
        server.stop().await;
    }
    assert_eq!(cases, 3);
}

#[tokio::test]
async fn recovery_cli_and_event_contract_match_observed_completion() {
    let fx = Fixture::new(None);
    let server = fx.start(1, roomy(), true, None).await;
    let (writer, remote) = Box::pin(journal_store(&fx, server.addr, "plain")).await;
    remote.recovery_faults.arm(
        "recover.postcondition",
        "publication",
        1,
        granary_client::FaultAction::Fail,
    );
    let events = RecoveryEvents::default();
    let _guard = events.guard();
    let mut cases = 0;
    for blocked in [true, false] {
        let result = command(
            &fx,
            server.addr,
            remote.clone(),
            fx.dir.join("journal-store"),
            writer,
            None,
        )
        .await;
        let text = events.text();
        assert_eq!(
            (
                result.err(),
                live_rows(&fx, server.addr).await,
                phase(&fx, server.addr, "journal-store") == Phase::Released,
                text.contains("\"reason\":\"publication\""),
                text.contains("\"event\":\"recover.journal_finished\"")
            ),
            (
                blocked.then(|| "intent refused: RecoveryJournalBlocked".to_owned()),
                usize::from(blocked),
                !blocked,
                true,
                !blocked
            ),
            "blocked={blocked}, cases={}, {text}",
            cases + 1
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
    server.stop().await;
}

#[tokio::test]
async fn normalization_and_release_crash_cuts_rederive_completion() {
    let mut cases = 0;
    for cut in ["before", "prepared", "confirmed", "lost-answer"] {
        let fx = Fixture::new(None);
        let server = fx.start(1, roomy(), true, None).await;
        let (writer, remote) = Box::pin(journal_store(&fx, server.addr, "install")).await;
        if cut == "lost-answer" {
            remote.lose_release.store(true, Ordering::Relaxed);
        } else {
            remote.recovery_faults.arm(
                "recover.release",
                cut,
                1,
                granary_client::FaultAction::Crash,
            );
        }
        let events = RecoveryEvents::default();
        let _guard = events.guard();
        let result = command(
            &fx,
            server.addr,
            remote.clone(),
            fx.dir.join("journal-store"),
            writer,
            None,
        )
        .await;
        assert_eq!(
            (
                result.is_err(),
                remote.recovery_faults.fired().len(),
                events.text().contains("recover.journal_finished")
            ),
            (
                cut != "lost-answer",
                usize::from(cut != "lost-answer"),
                cut == "lost-answer"
            ),
            "cut={cut}, cases={}, {result:?}: {}",
            cases + 1,
            events.text()
        );
        let sends = remote.publication_sends.lock().unwrap().len();
        let result = command(
            &fx,
            server.addr,
            remote.clone(),
            fx.dir.join("journal-store"),
            writer,
            None,
        )
        .await;
        assert_eq!(
            (
                result,
                phase(&fx, server.addr, "journal-store"),
                live_rows(&fx, server.addr).await,
                head_file(&fx, server.addr, "a").await,
                head_file(&fx, server.addr, "residual").await,
                remote.publication_sends.lock().unwrap().len()
            ),
            (
                Ok(()),
                Phase::Released,
                0,
                Some(b"acknowledged".to_vec()),
                Some(b"remaining".to_vec()),
                sends
            ),
            "cut={cut}"
        );
        let releases = remote
            .recovery_sends
            .lock()
            .unwrap()
            .iter()
            .filter(|bytes| intent::decode_release(bytes).is_ok())
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            releases.len(),
            if cut == "lost-answer" { 2 } else { 1 },
            "cut={cut}: {releases:?}"
        );
        assert!(
            releases.windows(2).all(|pair| pair.first() == pair.get(1)),
            "lost release did not replay exact bytes: {releases:?}"
        );
        server.stop().await;
        cases += 1;
    }
    assert_eq!(cases, 4);
}
