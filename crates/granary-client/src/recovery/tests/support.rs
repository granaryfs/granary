// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    AuthorityError, PublishRequest, StatusResponse, validate_publish_answer,
    validate_status_observation,
};
use granary_core::{
    authlog::Epoch,
    authority_answer::{self, Head, Position, PublishAnswer, Receipt, VolumeStatus},
    binstore::BinStore,
    clock::Clock,
    grainsource::{GrainSource, GrainSourceError},
    manifest, retained_submission,
    rootstore::{HintRead, HintToken, RefusalKind, RootStore, RootStoreError, filter_above},
    secure_random::{EntropyUnavailable, SecureRandom},
};
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

type SendTuple = (u64, [u8; 16], Vec<u8>, Vec<u8>);
#[derive(Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent scripted fault switches in a test double"
)]
pub(crate) struct Remote {
    pub(crate) roots: BTreeMap<u64, Vec<u8>>,
    pub(super) meta: BTreeMap<GrainId, Vec<u8>>,
    pub(super) bins: BTreeMap<[u8; 32], Vec<u8>>,
    pub(super) plans: VecDeque<Plan>,
    pub(crate) sends: Vec<SendTuple>,
    pub(super) attempts: Vec<u64>,
    pub(crate) probes: usize,
    pub(crate) status_calls: usize,
    pub(crate) max_seq_calls: usize,
    pub(super) fail_max_seq: bool,
    pub(crate) head_error: Option<RootStoreError>,
    pub(super) meta_reads: usize,
    pub(super) range_reads: usize,
    pub(crate) bin_uploads: usize,
    pub(crate) meta_uploads: usize,
    pub(super) fail_probe: bool,
    pub(super) fail_probe_at: Option<usize>,
    pub(super) over_cap_probe_at: Option<usize>,
    pub(super) oversized_probe: bool,
    pub(super) status: Option<StatusResponse>,
    pub(super) meta_corrupt: bool,
    pub(super) range_short: bool,
    pub(super) range_corrupt: bool,
    pub(super) land_on_upload: Option<(u64, Vec<u8>)>,
    pub(super) roots_on_probe: Vec<(u64, Vec<u8>)>,
    pub(super) roots_on_send: Vec<(u64, Vec<u8>)>,
    pub(super) range_wrong_hash: bool,
    pub(super) range_overdeclared: bool,
}
pub(super) enum Plan {
    Reply(PublishResponse),
    Wire(PublishAnswer),
    Land,
    StaleContest,
    LostContest,
    LostContestAndLose,
    StaleContestAndLose,
    LostReply,
    Invalid,
}
#[derive(Clone, Default)]
pub(crate) struct Transport {
    pub(crate) remote: Arc<Mutex<Remote>>,
    pub(super) durable: Arc<Mutex<Option<Submission>>>,
}
pub(super) struct Journal {
    pub(super) durable: Arc<Mutex<Option<Submission>>>,
    pub(super) objects: BTreeMap<GrainId, Vec<u8>>,
    pub(super) fail_at: Option<usize>,
    pub(super) cuts: usize,
    pub(super) poisoned: bool,
    pub(super) reads: Mutex<BTreeMap<GrainId, usize>>,
    pub(super) read_fault: Option<(GrainId, ReadFault)>,
    pub(super) recovered: Option<crate::RecoveredObjects>,
}
pub(super) enum ReadFault {
    WrongOk,
    Backend,
}
impl Journal {
    pub(super) fn new(durable: Arc<Mutex<Option<Submission>>>) -> Self {
        Self {
            durable,
            objects: BTreeMap::new(),
            fail_at: None,
            cuts: 0,
            poisoned: false,
            reads: Mutex::new(BTreeMap::new()),
            read_fault: None,
            recovered: None,
        }
    }
    pub(super) fn put(&mut self, bytes: Vec<u8>) -> GrainId {
        let id = GrainId::of(&bytes);
        self.objects.insert(id, bytes);
        id
    }
    pub(super) fn tree(&mut self) -> GrainId {
        let body = b"frozen grain".to_vec();
        let id = self.put(body.clone());
        let bytes = manifest::encode_dir_leaf(&[manifest::DirEntry {
            name: manifest::Name::new(b"file".to_vec()).unwrap(),
            kind: manifest::EntryKind::File {
                exec: false,
                size: body.len() as u64,
                grains: manifest::FileGrains::Inline(vec![manifest::GrainRef {
                    id,
                    unpacked_len: u32::try_from(body.len()).unwrap(),
                }]),
            },
        }])
        .unwrap();
        self.put(bytes)
    }
    fn persist(&mut self, r: &Submission) -> Result<(), crate::PublicationStoreError> {
        self.cuts += 1;
        if self.poisoned || self.fail_at == Some(self.cuts) {
            self.poisoned = true;
            return Err(crate::PublicationStoreError {
                path: "journal".into(),
                kind: crate::PublicationStoreErrorKind::Refused,
                reason: "injected sync failure".into(),
            });
        }
        retained_submission::validate(r).unwrap();
        *self.durable.lock().unwrap() = Some(r.clone());
        Ok(())
    }
}
impl GrainSource for Journal {
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        *self.reads.lock().unwrap().entry(*id).or_default() += 1;
        if let Some((fault_id, fault)) = &self.read_fault
            && id == fault_id
        {
            return match fault {
                ReadFault::WrongOk => Ok(vec![0; 12]),
                ReadFault::Backend => {
                    Err(GrainSourceError::Backend("injected read failure".into()))
                }
            };
        }
        let bytes = self.objects.get(id).ok_or(GrainSourceError::Missing(*id))?;
        if GrainId::of(bytes) != *id {
            return Err(GrainSourceError::Corrupt(*id));
        }
        Ok(bytes.clone())
    }
    fn has(&self, id: &GrainId) -> bool {
        self.objects.contains_key(id)
    }
}
impl PublicationJournal for Journal {
    fn load(
        &mut self,
        s: &Scope,
        v: &VolumeName,
    ) -> Result<Option<Submission>, crate::PublicationStoreError> {
        let Some(mut r) = self.durable.lock().unwrap().clone() else {
            return Ok(None);
        };
        if r.scope != *s || r.volume != *v {
            return Err(crate::PublicationStoreError {
                path: "journal".into(),
                kind: crate::PublicationStoreErrorKind::Refused,
                reason: "foreign scope".into(),
            });
        }
        r.generation += 1;
        self.persist(&r)?;
        Ok(Some(r))
    }
    fn begin(&mut self, r: &Submission) -> Result<(), crate::PublicationStoreError> {
        assert!(
            self.durable
                .lock()
                .unwrap()
                .as_ref()
                .is_none_or(Submission::is_complete)
        );
        self.persist(r)
    }
    async fn replace(
        &mut self,
        g: u64,
        r: &Submission,
    ) -> Result<(), crate::PublicationStoreError> {
        assert_eq!(self.durable.lock().unwrap().as_ref().unwrap().generation, g);
        self.persist(r)
    }
    fn recovered(&mut self) -> Option<&mut crate::RecoveredObjects> {
        self.recovered.as_mut()
    }
    fn put_recovered(
        &mut self,
        id: &GrainId,
        bytes: &[u8],
    ) -> Result<(), crate::PublicationStoreError> {
        self.objects.insert(*id, bytes.to_vec());
        Ok(())
    }
}
impl RootStore for Transport {
    async fn put_root(&self, _v: &str, _n: u64, _b: Vec<u8>) -> Result<(), RootStoreError> {
        panic!("served publication must not use direct root PUT")
    }
    async fn get_root(&self, _v: &str, _n: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        panic!("all root reads must use the retry-free probe")
    }
    async fn read_hint(
        &self,
        _v: &str,
        _t: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        Ok(HintRead::Missing)
    }
    async fn write_hint(&self, _v: &str, _n: u64) -> Result<(), RootStoreError> {
        panic!("coordinator does not write hints")
    }
    async fn max_seq(&self, _v: &str) -> Result<Option<u64>, RootStoreError> {
        let mut r = self.remote.lock().unwrap();
        r.max_seq_calls += 1;
        if let Some(error) = &r.head_error {
            return Err(error.clone());
        }
        if r.fail_max_seq {
            return Err(RootStoreError::Backend("injected head read failure".into()));
        }
        Ok(r.roots.keys().copied().max())
    }

    async fn max_seq_above(&self, v: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(v).await?, floor))
    }
}
impl BinStore for Transport {
    async fn put_bin(&self, delay: &[u8; 32], b: Vec<u8>) -> Result<bool, RootStoreError> {
        let mut r = self.remote.lock().unwrap();
        r.bin_uploads += 1;
        Ok(r.bins.insert(*delay, b).is_none())
    }
    async fn put_meta(&self, _v: &str, id: &GrainId, b: Vec<u8>) -> Result<bool, RootStoreError> {
        let mut remote = self.remote.lock().unwrap();
        remote.meta_uploads += 1;
        if let Some((seq, bytes)) = remote.land_on_upload.take() {
            remote.roots.entry(seq).or_insert(bytes);
        }
        Ok(remote.meta.insert(*id, b).is_none())
    }
    async fn get_meta(&self, _v: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        let mut r = self.remote.lock().unwrap();
        r.meta_reads += 1;
        if r.meta_corrupt {
            return Ok(vec![0]);
        }
        r.meta.get(id).cloned().ok_or(RootStoreError::NotFound)
    }
    async fn get_bin_range(
        &self,
        digest: &[u8; 32],
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        let mut r = self.remote.lock().unwrap();
        r.range_reads += 1;
        let b = r.bins.get(digest).ok_or(RootStoreError::NotFound)?;
        let mut out = b
            .get(usize::try_from(offset).unwrap()..usize::try_from(offset).unwrap() + len as usize)
            .unwrap()
            .to_vec();
        if r.range_short {
            out.pop();
        }
        if r.range_corrupt {
            out.fill(0);
        }
        if r.range_overdeclared {
            out.get_mut(5..9)
                .unwrap()
                .copy_from_slice(&13_u32.to_be_bytes());
        }
        if r.range_wrong_hash {
            let mut decoded = granary_store::codec::GrainCodec::new()
                .unwrap()
                .decompress_frame(&out)
                .unwrap();
            *decoded.first_mut().unwrap() ^= 128;
            let foreign = granary_store::codec::GrainCodec::new()
                .unwrap()
                .compress_grain(&decoded)
                .unwrap();
            assert_eq!(foreign.len(), out.len());
            return Ok(foreign);
        }
        Ok(out)
    }
}
impl AuthorityTransport for Transport {
    #[expect(
        clippy::too_many_lines,
        reason = "the scripted transport keeps every response and injected store action visible"
    )]
    async fn publish_once(&self, req: &PublishRequest) -> Result<PublishResponse, AuthorityError> {
        let durable = self
            .durable
            .lock()
            .unwrap()
            .clone()
            .expect("POST before durable begin");
        let Phase::AwaitingAnswer { candidate, attempt } = durable.phase else {
            panic!("send before durable attempt")
        };
        let c = durable
            .candidates
            .iter()
            .find(|c| c.number == candidate)
            .unwrap();
        assert_eq!(c.evidence.started, attempt);
        assert!(attempt > c.evidence.last_answered_attempt);
        assert_eq!(c.root.as_slice(), req.candidate().bytes().as_ref());
        assert_eq!(c.request.epoch, req.epoch().to_bytes());
        assert_eq!(c.request.operation.as_slice(), req.operation());
        let mut r = self.remote.lock().unwrap();
        r.attempts.push(attempt);
        r.sends.push((
            req.candidate().seq(),
            req.epoch().to_bytes(),
            req.operation().to_vec(),
            req.candidate().bytes().to_vec(),
        ));
        for (seq, bytes) in std::mem::take(&mut r.roots_on_send) {
            r.roots.insert(seq, bytes);
        }
        let plan = r
            .plans
            .pop_front()
            .unwrap_or(Plan::Reply(PublishResponse::RateLimited));
        let wire = match plan {
            Plan::Reply(reply) => return Ok(reply),
            Plan::Wire(wire) => wire,
            Plan::LostReply => return Err(AuthorityError::Elapsed),
            Plan::Invalid => return validate_publish_answer(req, 200, None, b"invalid"),
            contest @ (Plan::StaleContest
            | Plan::LostContest
            | Plan::LostContestAndLose
            | Plan::StaleContestAndLose) => {
                let mut doc = root::decode_root(req.candidate().bytes()).unwrap();
                doc.writer_uuid = [99; 16];
                let bytes = sign_doc(doc, &SigningKey::from_seed(&[9; 32]).unwrap());
                let occupant = GrainId::of(&bytes);
                r.roots.entry(req.candidate().seq()).or_insert(bytes);
                let reply = if matches!(contest, Plan::LostContest | Plan::LostContestAndLose) {
                    PublishAnswer::Lost {
                        position: Position {
                            epoch: req.epoch(),
                            entry_seq: 91,
                        },
                        candidate_id: req.candidate().id(),
                        occupant,
                        head: None,
                    }
                } else {
                    PublishAnswer::StaleBase(Head::new(Some((req.candidate().seq(), occupant))))
                };
                if matches!(
                    contest,
                    Plan::LostContestAndLose | Plan::StaleContestAndLose
                ) {
                    r.plans.push_front(Plan::Wire(reply));
                    return Err(AuthorityError::Elapsed);
                }
                reply
            }
            Plan::Land => {
                r.roots
                    .entry(req.candidate().seq())
                    .or_insert(req.candidate().bytes().to_vec());
                PublishAnswer::Landed {
                    receipt: Receipt {
                        position: Position {
                            epoch: req.epoch(),
                            entry_seq: 91,
                        },
                        root_seq: req.candidate().seq(),
                        stored_id: req.candidate().id(),
                    },
                    head: None,
                }
            }
        };
        let status = match wire {
            PublishAnswer::Landed { .. } | PublishAnswer::Lost { .. } => 200,
            PublishAnswer::Accepted { .. } | PublishAnswer::Open { .. } => 202,
            _ => 409,
        };
        let token = match wire {
            PublishAnswer::StaleBase(_) => Some("stale-base"),
            PublishAnswer::OperationBound(_) => Some("operation-bound"),
            PublishAnswer::NotDecided { .. } => Some("not-decided"),
            PublishAnswer::EpochMismatch { .. } => Some("epoch-mismatch"),
            PublishAnswer::VolumeDamaged => Some("volume-damaged"),
            _ => None,
        };
        validate_publish_answer(req, status, token, &authority_answer::encode(wire).unwrap())
    }
    async fn status_once(&self, _v: &str) -> Result<StatusResponse, AuthorityError> {
        let mut r = self.remote.lock().unwrap();
        r.status_calls += 1;
        if let Some(s) = r.status {
            return Ok(s);
        }
        validate_status_observation(
            &authority_answer::encode_status(VolumeStatus {
                epoch: Epoch::from_bytes([1; 16]),
                head: Some(Head::new(Some((10, GrainId::of(b"untrusted status"))))),
                open: None,
            })
            .unwrap(),
        )
    }
    async fn probe_root_once(&self, _v: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        if let Some(record) = self.durable.lock().unwrap().as_ref() {
            assert!(
                record.current.is_some() || record.is_complete(),
                "new epoch identity must survive the probe phase"
            );
            assert!(
                !matches!(record.phase, Phase::Ready),
                "catalogue read without a durable probe or answered-attempt marker"
            );
            if let Phase::ProbeStarted(probe) = record.phase {
                assert!(
                    record
                        .candidates
                        .iter()
                        .any(|candidate| candidate.seq == probe.seq),
                    "durable probe marker must name a catalogue slot"
                );
            }
        }
        let mut r = self.remote.lock().unwrap();
        r.probes += 1;
        for (seq, bytes) in std::mem::take(&mut r.roots_on_probe) {
            r.roots.insert(seq, bytes);
        }
        if r.fail_probe || r.fail_probe_at == Some(r.probes) {
            return Err(RootStoreError::Backend("injected probe failure".into()));
        }
        if r.over_cap_probe_at == Some(r.probes) {
            return Err(RootStoreError::RefusedResponse {
                reason: "injected over-cap root".into(),
                kind: RefusalKind::OverCap,
            });
        }
        if r.oversized_probe {
            return Ok(Some(vec![0; 65537]));
        }
        Ok(r.roots.get(&seq).cloned())
    }
}
pub(super) struct FixedClock(pub(super) i64);
impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            secs: self.0,
            nanos: 0,
        }
    }
}
pub(super) struct Entropy {
    pub(super) next: u8,
    pub(super) fail: bool,
}
impl Default for Entropy {
    fn default() -> Self {
        Self {
            next: 1,
            fail: false,
        }
    }
}
impl SecureRandom for Entropy {
    fn fill(&mut self, b: &mut [u8]) -> Result<(), EntropyUnavailable> {
        if self.fail {
            b.fill(99);
            return Err(EntropyUnavailable);
        }
        for (i, v) in b.iter_mut().enumerate() {
            *v = self.next.wrapping_add(u8::try_from(i).unwrap());
        }
        self.next = self.next.wrapping_add(32);
        Ok(())
    }
}
#[derive(Default)]
pub(super) struct Delay {
    pub(super) waits: Vec<Duration>,
}
impl RecoveryDelay for Delay {
    fn jitter(&mut self, _ceiling: Duration) -> Duration {
        Duration::from_mins(1)
    }
    fn wait(&mut self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.waits.push(duration);
        Box::pin(async {})
    }
}
pub(super) fn parts<'a>(
    transport: &'a Transport,
    journal: &'a mut Journal,
    key: &'a SigningKey,
    keys: &'a granary_store::crypto::TrustedKeys,
    entropy: &'a mut Entropy,
    c: &'a FixedClock,
    delay: &'a mut Delay,
) -> RecoveryParts<'a, Transport, Journal> {
    RecoveryParts {
        transport,
        journal,
        publisher_keys: keys,
        signer: key,
        secure: entropy,
        clock: c,
        delay,
    }
}
pub(super) fn setup() -> (
    Transport,
    Journal,
    SigningKey,
    granary_store::crypto::TrustedKeys,
    Entropy,
    Delay,
) {
    let transport = Transport::default();
    let journal = Journal::new(transport.durable.clone());
    let key = SigningKey::from_seed(&[9; 32]).unwrap();
    let keys = granary_store::crypto::TrustedKeys::new([*key.public_key()]).unwrap();
    (
        transport,
        journal,
        key,
        keys,
        Entropy::default(),
        Delay::default(),
    )
}
pub(super) fn handle(r: &Submission) -> PublicationHandle {
    PublicationHandle {
        scope: r.scope.clone(),
        volume: r.volume.clone(),
        publication_id: r.publication_id,
    }
}
pub(super) fn mismatch(epoch: u8) -> Plan {
    Plan::Wire(PublishAnswer::EpochMismatch {
        epoch: Epoch::from_bytes([epoch; 16]),
        head: None,
    })
}
