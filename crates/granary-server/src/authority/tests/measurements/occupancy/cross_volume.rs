// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::super::super::*;
use super::super::{Capture, output, rows::runtime_thread, stopwatch};
use super::{Instant, enrollment, identity, maximal_root};
use crate::authority::intent::persistence::Persistence;
use crate::authority::intent::{self, Principal as IntentPrincipal, Snapshot};
use crate::authority::{IntentOperation, IntentStore};
use granary_core::intent::encode_register;
use std::fmt::Write as _;
use tokio::sync::mpsc;

const SAMPLE_FLOOR: usize = 100;

struct CommitProbe {
    inner: Arc<dyn Persistence>,
    times: mpsc::UnboundedSender<u128>,
    origin: Instant,
}

impl Persistence for CommitProbe {
    fn load(
        &self,
        volume: &VolumeName,
        epoch: Option<Epoch>,
        keys: &TrustedKeys,
    ) -> std::io::Result<Option<Snapshot>> {
        self.inner.load(volume, epoch, keys)
    }
    fn load_for_rebind(&self, volume: &VolumeName) -> std::io::Result<Option<Snapshot>> {
        self.inner.load_for_rebind(volume)
    }
    fn ready(&self, volume: &VolumeName) -> Result<(), LogIoError> {
        self.inner.ready(volume)
    }
    fn commit(&self, snapshot: &Snapshot) -> Result<(), LogIoError> {
        self.times.send(self.origin.elapsed().as_nanos()).unwrap();
        let result = self.inner.commit(snapshot);
        self.times.send(self.origin.elapsed().as_nanos()).unwrap();
        result
    }
}

fn ceiling(volume: &VolumeName, root: &[u8], keys: &TrustedKeys) -> Snapshot {
    let mut holder = IntentPrincipal::default();
    let now = FixedClock.now();
    let change = |holder: &mut IntentPrincipal, operation, body: Vec<u8>| {
        let transition = intent::transition(Some(holder), operation, &body, volume, keys, now);
        *holder = transition.next.unwrap();
    };
    for writer in 1..=64_u8 {
        let acquire = intent::tests::acquire(writer, 3, u64::from(writer - 1));
        change(&mut holder, IntentOperation::Ownership, acquire);
        let (operation, body) = if writer <= 48 {
            (
                IntentOperation::Release,
                intent::tests::release(&holder, writer, 2),
            )
        } else {
            let body = encode_register(&[writer; 16], u64::from(writer), &[3; 16], 1, root);
            (IntentOperation::Register, body.unwrap())
        };
        change(&mut holder, operation, body);
    }
    let mut principals: BTreeMap<_, _> = enrollment(0, 16_384, 0)
        .principals()
        .map(|(id, _, _)| (id, IntentPrincipal::default()))
        .collect();
    for principal in principals.values_mut().take(16) {
        principal.clone_from(&holder);
    }
    Snapshot {
        volume: volume.clone(),
        epoch: Epoch::from_bytes([WORLD_EPOCH; 16]),
        principals,
    }
}

async fn quiet(handle: &AuthorityHandle, volume: &VolumeName, origin: Instant) -> [u128; 3] {
    let inbox = &handle.inner.inboxes[volume];
    let mut request = std::pin::pin!(handle.intent_roots(volume));
    let mut queued = 0;
    let start = origin.elapsed().as_nanos();
    // This caller is the only source of work for the quiet inbox.
    let roots = std::future::poll_fn(|cx| {
        let result = request.as_mut().poll(cx);
        if queued == 0 && inbox.capacity() < inbox.max_capacity() {
            queued = origin.elapsed().as_nanos();
        }
        result
    })
    .await;
    let end = origin.elapsed().as_nanos();
    assert!(roots.unwrap().is_empty(), "quiet volume has live roots");
    [start, queued, end]
}

async fn observe(count: usize) -> Vec<[u128; 10]> {
    use super::super::super::intents::{recording, recording_log, scratch};
    let dir = scratch();
    let (log, store) = recording_log(recording(&dir));
    let [busy, idle] = [a(), b()];
    let (root, keys) = maximal_root(&busy, 2);
    log.write_marker(&encode_marker(&RunMarker::Clean))
        .await
        .unwrap();
    log.initialise(&encode_envelope(&envelope(&busy, WORLD_EPOCH)))
        .await
        .unwrap();
    store.io.commit(&ceiling(&busy, &root, &keys)).unwrap();
    let origin = stopwatch();
    let (times, mut commits) = mpsc::unbounded_channel();
    let probe = CommitProbe {
        inner: store.io.clone(),
        times,
        origin,
    };
    let occupied =
        VolumeConfig::new(busy.clone(), keys.clone()).with_intents(Arc::new(IntentStore {
            io: Arc::new(probe),
        }));
    let quiet_volume = VolumeConfig::new(idle.clone(), keys).with_intents(store);
    let parts = AuthorityParts {
        admission: crate::Admission::chain_fixture(),
        log,
        store: Sim::new().node(0, Faults::none()),
        clock: FixedClock,
        rng: rng(1),
        secure_random: secure(1),
        pause: YieldPause,
    };
    let (handle, driver) = start(parts, boot(1), vec![occupied, quiet_volume])
        .await
        .unwrap();
    let capture = Capture::authority_log_wait(32);
    let driver = runtime_thread(driver.run(), tracing::Dispatch::new(capture.clone()));
    handle.initialise(&idle).await.unwrap();
    assert_eq!(handle.intent_roots(&busy).await.unwrap().len(), 256);
    capture.take();
    let mut samples = Vec::with_capacity(count);
    for generation in 2..=u64::try_from(count + 16).unwrap() + 1 {
        let body = encode_register(&[49; 16], 49, &[3; 16], generation, &root).unwrap();
        let [bs, _, be] = quiet(&handle, &idle, origin).await;
        let (writer, volume) = (handle.clone(), busy.clone());
        #[expect(
            clippy::disallowed_methods,
            reason = "the independent caller submits while observing the server commit"
        )]
        let commit = tokio::spawn(async move {
            writer
                .intent(&volume, identity(0).0, IntentOperation::Register, body)
                .await
        });
        let cs = tokio::time::timeout(Duration::from_secs(5), commits.recv())
            .await
            .expect("commit start missing")
            .unwrap();
        let [rs, queued, re] = quiet(&handle, &idle, origin).await;
        assert_eq!(commit.await.unwrap().status().as_u16(), 200);
        let ce = commits.try_recv().expect("commit end missing");
        let (gate, lost) = capture.take();
        assert_eq!((gate.len(), lost), (1, 0), "authority_log_wait sample loss");
        let overlaps = cs < rs && rs <= queued && queued < ce && ce <= re;
        if let Some(wait) = (re - rs).checked_sub(be - bs).filter(|_| overlaps) {
            let gate = (gate[0].end - gate[0].start).as_nanos();
            samples.push([bs, be, cs, ce, rs, queued, re, ce - cs, wait, gate]);
            if samples.len() == count {
                break;
            }
        }
    }
    assert_eq!(samples.len(), count, "cross-volume overlap sample floor");
    handle.stop().await;
    assert_eq!(driver.join().unwrap(), RunEnd::Stopped);
    std::fs::remove_dir_all(dir).unwrap();
    samples
}

#[tokio::test]
#[ignore = "cross-volume timing runs only in the authority venue"]
async fn authority_measurement_cross_volume_driver_stall() {
    let columns = "baseline_start_ns\tbaseline_end_ns\tcommit_start_ns\tcommit_end_ns\trequest_start_ns\trequest_queued_ns\trequest_end_ns\tcommit_ns\twait_ns\tauthority_log_wait_ns\n";
    let mut tsv = String::from(columns);
    for sample in observe(SAMPLE_FLOOR).await {
        writeln!(tsv, "{}", sample.map(|value| value.to_string()).join("\t")).unwrap();
    }
    output::write_tsv("cross_volume", &tsv);
}

#[tokio::test]
async fn authority_measurement_cross_volume_wait_is_attributed() {
    let samples = observe(3).await;
    let attributed = samples
        .iter()
        .any(|&[bs, be, _, ce, _, queued, re, commit, wait, _]| {
            queued < ce && ce <= re && (be - bs) * 4 < commit && wait * 4 >= commit * 3
        });
    assert!(attributed, "quiet wait attribution: {samples:?}");
}
