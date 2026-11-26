// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::authlog`.
//! Out-of-line: `granary-core`'s non-test artifact has workspace
//! consumers, so the module's own tests move out of the parent file
//! (coding-standards rule 18).

use super::codec::{self, decode_mark, decode_record};
use super::record::{TAG_DECISION, TAG_RESERVED_05};
use super::*;
use crate::hash::GrainId;
use crate::root::{
    self, ED25519_SIG_LEN, KEY_ID_LEN, ROOT_SIG_SLOT_LEN, ROOT_V1_MAX_ENCODABLE, RootDoc, RootSig,
    VolumeName,
};
use crate::sheaf::Timestamp;

// ============================================================ fixtures

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(out, "{b:02x}").unwrap_or_else(|e| panic!("{e}"));
    }
    out
}

fn test_volume() -> VolumeName {
    VolumeName::new("vol-a".to_owned()).unwrap_or_else(|e| panic!("{e}"))
}

fn other_volume() -> VolumeName {
    VolumeName::new("vol-b".to_owned()).unwrap_or_else(|e| panic!("{e}"))
}

/// A volume name at [`root::VOLUME_NAME_MAX`] — the tail-bound tests'
/// largest-decision fixture needs a candidate root whose OWN volume
/// field is at its cap too, since a decision's candidate must name the
/// envelope's volume.
fn max_len_volume() -> VolumeName {
    VolumeName::new("a".repeat(root::VOLUME_NAME_MAX)).unwrap_or_else(|e| panic!("{e}"))
}

fn test_epoch() -> Epoch {
    Epoch::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
}

fn other_epoch() -> Epoch {
    Epoch::from_bytes([0xEE; 16])
}

fn test_envelope() -> Envelope {
    Envelope::new(test_volume(), test_epoch())
}

/// A real, decodable root for `volume` at `seq`/`parent` — small (no
/// profiled-volume fields exist in v1), deterministic. `seq`/`parent`
/// must already satisfy the root format's own cross-rule (parent absent
/// iff `seq == 1`); callers that need a structurally-invalid seq/parent
/// combination build bytes manually instead (`encode_root` itself
/// refuses it).
fn sample_root(volume: &VolumeName, seq: u64, parent: Option<GrainId>) -> Vec<u8> {
    sample_root_variant(volume, seq, parent, b"manifest")
}

/// [`sample_root`] with a caller-chosen manifest-root seed, so two
/// calls at the SAME `(volume, seq, parent)` can still produce
/// genuinely distinct root bytes/ids where a test needs "a different
/// candidate" rather than "the same one twice".
fn sample_root_variant(
    volume: &VolumeName,
    seq: u64,
    parent: Option<GrainId>,
    manifest_seed: &[u8],
) -> Vec<u8> {
    let doc = RootDoc {
        volume: volume.clone(),
        seq,
        parent,
        writer_uuid: [0xAB; 16],
        epoch: 7,
        timestamp: Timestamp {
            secs: 1_700_000_000,
            nanos: 0,
        },
        chunker_spec: "test-chunker".to_owned(),
        manifest_root: GrainId::of(manifest_seed),
        binmap_index: GrainId::of(b"binmap"),
        sheaf_head: GrainId::of(b"sheaf"),
        sigs: vec![RootSig {
            key_id: [0x01; KEY_ID_LEN],
            sig: [0x02; ED25519_SIG_LEN],
        }],
    };
    root::encode_root(&doc).unwrap_or_else(|e| panic!("{e}"))
}

fn identity_of(candidate_id: GrainId) -> SubmissionIdentity {
    SubmissionIdentity::new(
        Tenant::new(vec![0x11]).unwrap_or_else(|e| panic!("{e}")),
        Principal::new(vec![0x22, 0x22]).unwrap_or_else(|e| panic!("{e}")),
        Operation::new(vec![0x33]).unwrap_or_else(|e| panic!("{e}")),
        candidate_id,
    )
}

fn other_identity(candidate_id: GrainId) -> SubmissionIdentity {
    SubmissionIdentity::new(
        Tenant::new(vec![0x44, 0x44]).unwrap_or_else(|e| panic!("{e}")),
        Principal::new(vec![0x55]).unwrap_or_else(|e| panic!("{e}")),
        Operation::new(vec![0x66, 0x66, 0x66]).unwrap_or_else(|e| panic!("{e}")),
        candidate_id,
    )
}

/// A decision + its candidate root bytes, for `envelope`'s volume, at
/// `root_seq` 1 (no base).
fn standard_decision(envelope: &Envelope, seq: u64) -> (Record, Vec<u8>) {
    let candidate_bytes = sample_root(envelope.volume(), 1, None);
    let candidate_id = GrainId::of(&candidate_bytes);
    let body = RecordBody::Decision {
        identity: identity_of(candidate_id),
        root_seq: 1,
        base: None,
        decided_at: Timestamp {
            secs: 1_700_000_001,
            nanos: 500_000_000,
        },
        candidate: RootBytes::new(candidate_bytes.clone()).unwrap_or_else(|e| panic!("{e}")),
    };
    (
        Record::new(seq, body).unwrap_or_else(|e| panic!("{e}")),
        candidate_bytes,
    )
}

fn standard_attestation(seq: u64, candidate_bytes: &[u8]) -> Record {
    let candidate_id = GrainId::of(candidate_bytes);
    let body = RecordBody::Attestation {
        identity: identity_of(candidate_id),
        stored_id: candidate_id,
        final_root: RootBytes::new(candidate_bytes.to_vec()).unwrap_or_else(|e| panic!("{e}")),
    };
    Record::new(seq, body).unwrap_or_else(|e| panic!("{e}"))
}

fn standard_landed(seq: u64, candidate_bytes: &[u8]) -> Record {
    let candidate_id = GrainId::of(candidate_bytes);
    Record::new(
        seq,
        RecordBody::Landed {
            identity: identity_of(candidate_id),
        },
    )
    .unwrap_or_else(|e| panic!("{e}"))
}

fn standard_lost(seq: u64, candidate_bytes: &[u8], occupant_id: GrainId) -> Record {
    let candidate_id = GrainId::of(candidate_bytes);
    Record::new(
        seq,
        RecordBody::Lost {
            identity: identity_of(candidate_id),
            occupant_id,
        },
    )
    .unwrap_or_else(|e| panic!("{e}"))
}

fn append_pair(out: &mut Vec<u8>, envelope: &Envelope, record: &Record) {
    let append = encode_append(envelope, record).unwrap_or_else(|e| panic!("{e}"));
    out.extend_from_slice(append.record());
    out.extend_from_slice(append.mark());
}

/// A clean, fully closed one-entry log: decision, attestation, landed —
/// all at seq 1.
fn clean_log() -> (Envelope, Vec<u8>) {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let (decision, candidate) = standard_decision(&envelope, 1);
    append_pair(&mut out, &envelope, &decision);
    append_pair(&mut out, &envelope, &standard_attestation(1, &candidate));
    append_pair(&mut out, &envelope, &standard_landed(1, &candidate));
    (envelope, out)
}

/// Re-sign `bytes` (a record's wire bytes) in place: recompute its
fn hex_digit_test(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

fn push_hex_test(out: &mut Vec<u8>, raw: &[u8]) {
    for b in raw {
        out.push(hex_digit_test(b >> 4));
        out.push(hex_digit_test(b & 0x0F));
    }
}

fn manual_hex16(out: &mut Vec<u8>, raw: &[u8]) {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "test fixtures never exceed a few thousand bytes"
    )]
    let hex_len = (raw.len() * 2) as u16;
    out.extend_from_slice(&hex_len.to_be_bytes());
    push_hex_test(out, raw);
}

fn manual_hex32(out: &mut Vec<u8>, raw: &[u8]) {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "test fixtures never exceed a few hundred thousand bytes"
    )]
    let hex_len = (raw.len() * 2) as u32;
    out.extend_from_slice(&hex_len.to_be_bytes());
    push_hex_test(out, raw);
}

/// A hex32 field whose LENGTH FIELD lies about being hex: it declares
/// `raw.len()` (not `2 * raw.len()`) and writes `raw` verbatim,
/// bypassing the hex rule entirely. Test-only — this is the "planted
/// mark, raw variant" mutation proof's own helper, never something a
/// conforming encoder could produce.
fn manual_raw32_bypassing_hex(out: &mut Vec<u8>, raw: &[u8]) {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "test fixtures never exceed a few hundred thousand bytes"
    )]
    let len = raw.len() as u32;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(raw);
}

fn manual_identity(
    tenant: &[u8],
    principal: &[u8],
    operation: &[u8],
    candidate_id: GrainId,
) -> Vec<u8> {
    let mut out = Vec::new();
    manual_hex16(&mut out, tenant);
    manual_hex16(&mut out, principal);
    manual_hex16(&mut out, operation);
    out.extend_from_slice(&candidate_id.to_bytes());
    out
}

fn good_identity_bytes(candidate_id: GrainId) -> Vec<u8> {
    manual_identity(&[0x11], &[0x22, 0x22], &[0x33], candidate_id)
}

/// Assemble one record's wire bytes + mark from a raw tag and body,
/// bypassing `RecordBody`/`encode_append` entirely — the workhorse for
/// every deliberately-malformed fixture below.
fn manual_record(envelope: &Envelope, seq: u64, tag: u8, body: &[u8]) -> (Vec<u8>, [u8; MARK_LEN]) {
    let mut out = Vec::new();
    out.push(tag);
    out.extend_from_slice(&envelope.version().to_be_bytes());
    out.extend_from_slice(&envelope.epoch().to_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    #[expect(
        clippy::cast_possible_truncation,
        reason = "test fixtures never exceed a few hundred thousand bytes"
    )]
    let body_len = body.len() as u32;
    out.extend_from_slice(&body_len.to_be_bytes());
    out.extend_from_slice(body);
    let check = blake3::derive_key(RECORD_CONTEXT, &out);
    out.extend_from_slice(&check);
    let mark = codec::build_mark(envelope.epoch(), seq, tag, check);
    (out, mark)
}

fn manual_decision_body(
    identity: Vec<u8>,
    root_seq: u64,
    base: Option<GrainId>,
    ts: Timestamp,
    candidate_raw: &[u8],
) -> Vec<u8> {
    let mut out = identity;
    out.extend_from_slice(&root_seq.to_be_bytes());
    match base {
        None => out.push(0x00),
        Some(id) => {
            out.push(0x01);
            out.extend_from_slice(&id.to_bytes());
        }
    }
    out.extend_from_slice(&ts.secs.to_be_bytes());
    out.extend_from_slice(&ts.nanos.to_be_bytes());
    manual_hex32(&mut out, candidate_raw);
    out
}

// ---------------------------------------------------- golden vectors
//
// Committed hex fixtures (format-object discipline, as `cacheindex`
// does): a drift here is a FORMAT EVENT, never a refactor side effect.
// Captured from this module's own encoder against the fixed inputs
// above (`test_envelope`, `standard_decision`/`standard_attestation`/
// `standard_landed`/`standard_lost`), then pinned. The reserved-tag
// record below is the one golden that is a REJECT vector.

const ENVELOPE_GOLDEN_HEX: &str = "47524e414c4f47000001004205766f6c2d610102030405060708090a0b0c0d0e0f102be34a384aa8568c5511aa77228495\
83678ca06c628c0838f3bc66ff520d3551";

const MARK_GOLDEN_HEX: &str = "47524e434f4d49540102030405060708090a0b0c0d0e0f10000000000000000101d25271f07b3216571ea37d98c7afa041\
9d164b7b01108375c66ec044ade56824033b216c9afc3f9775d5bc1d1c29eea17cc5aa79aed5a9279ca113aebf3735ae";

const DECISION_GOLDEN_HEX: &str = "0100010102030405060708090a0b0c0d0e0f1000000000000000010000026c00023131000432323232000233330177f453\
64de7ed97e3502101650d0da3fcc2d027c6332a20c71deeb24723cc486000000000000000100000000006553f1011dcd65\
00000002243437353234313465343135323539303030393031303537363666366332643631303030303030303030303030\
30303031303061626162616261626162616261626162616261626162616261626162616261623030303030303030303030\
30303030373030303030303030363535336631303030303030303030303063373436353733373432643633363837353665\
36623635373230313064313937353231643961343837363035373664613163383764666438323861363064333937656131\
65313666393261356237633434623466343036306365313030303130626333306338356436373866306635646363643931\
65313438643339656136303138313265663034633764643939306363333030636264356361636130323530313730313762\
30623865343462336430633537353338363932643137653436326137323932303433623963623633353837333462343732\
66336237373735366634303130313031303130313031303130313031303130313031303130313031303130313031303130\
31303130313031303130313031303130313031303130313031303130313030343030323032303230323032303230323032\
30323032303230323032303230323032303230323032303230323032303230323032303230323032303230323032303230\
32303230323032303230323032303230323032303230323032303230323032303230323032303230323032303230323032\
3032303230323032303230323032d25271f07b3216571ea37d98c7afa0419d164b7b01108375c66ec044ade56824";

const ATTESTATION_GOLDEN_HEX: &str = "0200010102030405060708090a0b0c0d0e0f1000000000000000010000027800023131000432323232000233330177f453\
64de7ed97e3502101650d0da3fcc2d027c6332a20c71deeb24723cc4860177f45364de7ed97e3502101650d0da3fcc2d02\
7c6332a20c71deeb24723cc486000002243437353234313465343135323539303030393031303537363666366332643631\
30303030303030303030303030303031303061626162616261626162616261626162616261626162616261626162616261\
62303030303030303030303030303030373030303030303030363535336631303030303030303030303063373436353733\
37343264363336383735366536623635373230313064313937353231643961343837363035373664613163383764666438\
32386136306433393765613165313666393261356237633434623466343036306365313030303130626333306338356436\
37386630663564636364393165313438643339656136303138313265663034633764643939306363333030636264356361\
63613032353031373031376230623865343462336430633537353338363932643137653436326137323932303433623963\
62363335383733346234373266336237373735366634303130313031303130313031303130313031303130313031303130\
31303130313031303130313031303130313031303130313031303130313031303130313031303130313030343030323032\
30323032303230323032303230323032303230323032303230323032303230323032303230323032303230323032303230\
32303230323032303230323032303230323032303230323032303230323032303230323032303230323032303230323032\
3032303230323032303230323032303230323032303230323032829049a8017f3535183f1c83f0b0c67b86f074eceb7280\
77ebcc358038767ffc";

const LANDED_GOLDEN_HEX: &str = "0300010102030405060708090a0b0c0d0e0f1000000000000000010000002f00023131000432323232000233330177f453\
64de7ed97e3502101650d0da3fcc2d027c6332a20c71deeb24723cc48698eb8872f15b051a47f86f74794db419eecfb235\
b3429cde6e3568bbf5b288bf";

const LOST_GOLDEN_HEX: &str = "0400010102030405060708090a0b0c0d0e0f1000000000000000010000005000023131000432323232000233330177f453\
64de7ed97e3502101650d0da3fcc2d027c6332a20c71deeb24723cc486018de1b2afaa714a5e7097f63b8e3edf581c68c2\
5f9ef8d1d2ff91337ad578049d70de7e3ae11909be4ec0c9377fa38aaaac4c6de4b1f731620a199693d85c34aa";

/// A committed record under the reserved tag `0x05`
/// ([`crate::testkit::authlog_reserved_tag_pair`]'s record, for
/// [`test_envelope`], seq 1 and [`standard_decision`]'s candidate id):
/// a reject vector. v1 never writes the tag, so a log holding it refuses.
const RESERVED_TAG_05_RECORD_HEX: &str = "0500010102030405060708090a0b0c0d0e0f1000000000000000010000005a00023131000432323232000233330177f453\
64de7ed97e3502101650d0da3fcc2d027c6332a20c71deeb24723cc486010100000000000000050135f1ea002bfb00c125\
884e650f864046b687e0a48a6edc1a591c459f8c341da50c75d6f4298e7fef74a5ed74d9e5883f887805f5d795cf533ce1\
3160feadebad";

/// The clean, fully closed one-entry log ([`clean_log`]) — the "whole
/// file" golden ([`cacheindex`](crate::cacheindex)'s own
/// `JOURNAL_GOLDEN_HEX` precedent for a pinned multi-piece file).
const CLEAN_LOG_GOLDEN_HEX: &str = "47524e414c4f47000001004205766f6c2d610102030405060708090a0b0c0d0e0f102be34a384aa8568c5511aa77228495\
83678ca06c628c0838f3bc66ff520d35510100010102030405060708090a0b0c0d0e0f1000000000000000010000026c00\
023131000432323232000233330177f45364de7ed97e3502101650d0da3fcc2d027c6332a20c71deeb24723cc486000000\
000000000100000000006553f1011dcd650000000224343735323431346534313532353930303039303130353736366636\
63326436313030303030303030303030303030303130306162616261626162616261626162616261626162616261626162\
61626162616230303030303030303030303030303037303030303030303036353533663130303030303030303030306337\
34363537333734326436333638373536653662363537323031306431393735323164396134383736303537366461316338\
37646664383238613630643339376561316531366639326135623763343462346634303630636531303030313062633330\
63383564363738663066356463636439316531343864333965613630313831326566303463376464393930636333303063\
62643563616361303235303137303137623062386534346233643063353735333836393264313765343632613732393230\
34336239636236333538373334623437326633623737373536663430313031303130313031303130313031303130313031\
30313031303130313031303130313031303130313031303130313031303130313031303130313031303130313031303034\
30303230323032303230323032303230323032303230323032303230323032303230323032303230323032303230323032\
30323032303230323032303230323032303230323032303230323032303230323032303230323032303230323032303230\
32303230323032303230323032303230323032303230323032303230323032d25271f07b3216571ea37d98c7afa0419d16\
4b7b01108375c66ec044ade5682447524e434f4d49540102030405060708090a0b0c0d0e0f10000000000000000101d252\
71f07b3216571ea37d98c7afa0419d164b7b01108375c66ec044ade56824033b216c9afc3f9775d5bc1d1c29eea17cc5aa\
79aed5a9279ca113aebf3735ae0200010102030405060708090a0b0c0d0e0f100000000000000001000002780002313100\
0432323232000233330177f45364de7ed97e3502101650d0da3fcc2d027c6332a20c71deeb24723cc4860177f45364de7e\
d97e3502101650d0da3fcc2d027c6332a20c71deeb24723cc4860000022434373532343134653431353235393030303930\
31303537363666366332643631303030303030303030303030303030313030616261626162616261626162616261626162\
61626162616261626162616261623030303030303030303030303030303730303030303030303635353366313030303030\
30303030303063373436353733373432643633363837353665366236353732303130643139373532316439613438373630\
35373664613163383764666438323861363064333937656131653136663932613562376334346234663430363063653130\
30303130626333306338356436373866306635646363643931653134386433396561363031383132656630346337646439\
39306363333030636264356361636130323530313730313762306238653434623364306335373533383639326431376534\
36326137323932303433623963623633353837333462343732663362373737353666343031303130313031303130313031\
30313031303130313031303130313031303130313031303130313031303130313031303130313031303130313031303130\
31303130313030343030323032303230323032303230323032303230323032303230323032303230323032303230323032\
30323032303230323032303230323032303230323032303230323032303230323032303230323032303230323032303230\
323032303230323032303230323032303230323032303230323032303230323032303230323032829049a8017f3535183f\
1c83f0b0c67b86f074eceb728077ebcc358038767ffc47524e434f4d49540102030405060708090a0b0c0d0e0f10000000\
000000000102829049a8017f3535183f1c83f0b0c67b86f074eceb728077ebcc358038767ffca22f322f65cc7f118684d8\
74037a782faa12088bcda42be880d8bf1c8426b7780300010102030405060708090a0b0c0d0e0f10000000000000000100\
00002f00023131000432323232000233330177f45364de7ed97e3502101650d0da3fcc2d027c6332a20c71deeb24723cc4\
8698eb8872f15b051a47f86f74794db419eecfb235b3429cde6e3568bbf5b288bf47524e434f4d49540102030405060708\
090a0b0c0d0e0f1000000000000000010398eb8872f15b051a47f86f74794db419eecfb235b3429cde6e3568bbf5b288bf\
998099aee3f9b1fccfeb69894cf36212f07ce825d480497202057f5658ddb2df";

#[test]
fn envelope_golden_vector_is_pinned() {
    let envelope = test_envelope();
    let bytes = encode_envelope(&envelope).as_bytes().to_vec();
    assert_eq!(hex_encode(&bytes), ENVELOPE_GOLDEN_HEX);
    match classify(&bytes, envelope.volume()) {
        Ok(Classified::Log {
            envelope: decoded,
            records,
            committed_len,
            tail_len,
        }) => {
            assert_eq!(decoded, envelope, "an envelope alone decodes back exactly");
            assert_eq!(records, Vec::new());
            assert_eq!(committed_len, bytes.len());
            assert_eq!(tail_len, 0);
        }
        other => panic!("an envelope alone is a valid, empty log: {other:?}"),
    }
}

#[test]
fn mark_golden_vector_is_pinned() {
    let envelope = test_envelope();
    let (decision, _) = standard_decision(&envelope, 1);
    let append = encode_append(&envelope, &decision).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(hex_encode(append.mark()), MARK_GOLDEN_HEX);

    let decoded = decode_mark(append.mark()).unwrap_or_else(|| panic!("golden mark must decode"));
    assert_eq!(decoded.epoch, envelope.epoch());
    assert_eq!(decoded.seq, decision.seq());
    assert_eq!(decoded.tag, decision.body().tag());
    let record_bytes = append.record();
    let record_check: [u8; 32] = record_bytes
        .get(record_bytes.len() - 32..)
        .and_then(|s| s.try_into().ok())
        .unwrap_or_else(|| panic!("record must carry a 32-byte check"));
    assert_eq!(decoded.record_check, record_check);
}

#[test]
fn decision_record_golden_vector_is_pinned() {
    let envelope = test_envelope();
    let (decision, _) = standard_decision(&envelope, 1);
    let append = encode_append(&envelope, &decision).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(hex_encode(append.record()), DECISION_GOLDEN_HEX);
    let decoded = decode_record(append.record(), envelope.volume())
        .unwrap_or_else(|| panic!("golden decision record must decode"));
    assert_eq!(decoded.record, decision);
    assert_eq!(decoded.consumed, append.record().len());
}

#[test]
fn attestation_record_golden_vector_is_pinned() {
    let envelope = test_envelope();
    let (_, candidate) = standard_decision(&envelope, 1);
    let attestation = standard_attestation(1, &candidate);
    let append = encode_append(&envelope, &attestation).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(hex_encode(append.record()), ATTESTATION_GOLDEN_HEX);
    let decoded = decode_record(append.record(), envelope.volume())
        .unwrap_or_else(|| panic!("golden attestation record must decode"));
    assert_eq!(decoded.record, attestation);
}

#[test]
fn landed_record_golden_vector_is_pinned() {
    let envelope = test_envelope();
    let (_, candidate) = standard_decision(&envelope, 1);
    let landed = standard_landed(1, &candidate);
    let append = encode_append(&envelope, &landed).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(hex_encode(append.record()), LANDED_GOLDEN_HEX);
    let decoded = decode_record(append.record(), envelope.volume())
        .unwrap_or_else(|| panic!("golden landed record must decode"));
    assert_eq!(decoded.record, landed);
}

#[test]
fn lost_record_golden_vector_is_pinned() {
    let envelope = test_envelope();
    let (_, candidate) = standard_decision(&envelope, 1);
    let lost = standard_lost(1, &candidate, GrainId::of(b"occupant"));
    let append = encode_append(&envelope, &lost).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(hex_encode(append.record()), LOST_GOLDEN_HEX);
    let decoded = decode_record(append.record(), envelope.volume())
        .unwrap_or_else(|| panic!("golden lost record must decode"));
    assert_eq!(decoded.record, lost);
}

/// The reserved-tag reject vector: the test kit builds exactly the
/// pinned bytes, the body decoder refuses the tag by name, and a golden
/// log holding the pair refuses at classification, alone or after a
/// closed entry, as damage to committed history at the pair's offset.
#[test]
fn a_committed_pair_under_the_reserved_tag_0x05_refuses() {
    let envelope = test_envelope();
    let (_, candidate) = standard_decision(&envelope, 1);
    let candidate_id = GrainId::of(&candidate);
    let pair = crate::testkit::authlog_reserved_tag_pair(&envelope, 1, candidate_id);
    let (record_bytes, mark) = pair.split_at(pair.len() - MARK_LEN);
    assert_eq!(hex_encode(record_bytes), RESERVED_TAG_05_RECORD_HEX);
    assert!(decode_mark(mark).is_some(), "the mark is valid");
    assert!(
        decode_record(record_bytes, envelope.volume()).is_none(),
        "no v1 record decodes under the reserved tag"
    );
    let body = &record_bytes[RECORD_FIXED_LEN - 32..record_bytes.len() - 32];
    assert_eq!(
        codec::decode_record_body(TAG_RESERVED_05, body, envelope.volume()),
        Err(codec::RecordFieldReason::ReservedTag)
    );

    let mut alone = encode_envelope(&envelope).as_bytes().to_vec();
    let env_len = alone.len();
    alone.extend_from_slice(&pair);
    assert_eq!(
        classify(&alone, envelope.volume()),
        Err(LogError {
            offset: env_len,
            reason: LogErrorReason::DamagedCommittedHistory,
        })
    );

    let (_, mut after_entry) = clean_log();
    let at = after_entry.len();
    after_entry.extend_from_slice(&crate::testkit::authlog_reserved_tag_pair(
        &envelope,
        2,
        GrainId::of(b"another candidate"),
    ));
    assert_eq!(
        classify(&after_entry, envelope.volume()),
        Err(LogError {
            offset: at,
            reason: LogErrorReason::DamagedCommittedHistory,
        })
    );
}

#[test]
fn clean_log_golden_vector_is_pinned_and_classifies_as_a_closed_entry() {
    let (envelope, bytes) = clean_log();
    assert_eq!(hex_encode(&bytes), CLEAN_LOG_GOLDEN_HEX);
    let (_, candidate) = standard_decision(&envelope, 1);
    match classify(&bytes, envelope.volume()) {
        Ok(Classified::Log {
            envelope: decoded,
            records,
            committed_len,
            tail_len,
        }) => {
            assert_eq!(decoded, envelope);
            assert_eq!(
                records,
                vec![
                    standard_decision(&envelope, 1).0,
                    standard_attestation(1, &candidate),
                    standard_landed(1, &candidate),
                ]
            );
            assert_eq!(committed_len, bytes.len());
            assert_eq!(tail_len, 0);
        }
        other => panic!("a clean, closed log must classify as Log with no tail: {other:?}"),
    }
}

// ================================================================
// Classification branches — one whole file per verdict
// ================================================================

#[test]
fn torn_record_is_discarded_as_a_tail() {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let (decision, candidate) = standard_decision(&envelope, 1);
    append_pair(&mut out, &envelope, &decision);
    let committed_len = out.len();
    let attestation = standard_attestation(1, &candidate);
    let attestation_append =
        encode_append(&envelope, &attestation).unwrap_or_else(|e| panic!("{e}"));
    out.extend_from_slice(attestation_append.record().get(..20).unwrap_or_default());
    let tail_len = out.len() - committed_len;
    match classify(&out, envelope.volume()) {
        Ok(Classified::Log {
            records,
            committed_len: cl,
            tail_len: tl,
            ..
        }) => {
            assert_eq!(records, vec![decision]);
            assert_eq!(cl, committed_len);
            assert_eq!(tl, tail_len);
        }
        other => panic!("a torn record must be discarded as a tail: {other:?}"),
    }
}

#[test]
fn record_with_a_torn_mark_is_discarded_as_a_tail() {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let (decision, candidate) = standard_decision(&envelope, 1);
    append_pair(&mut out, &envelope, &decision);
    let committed_len = out.len();
    let attestation = standard_attestation(1, &candidate);
    let attestation_append =
        encode_append(&envelope, &attestation).unwrap_or_else(|e| panic!("{e}"));
    out.extend_from_slice(attestation_append.record());
    out.extend_from_slice(attestation_append.mark().get(..40).unwrap_or_default());
    match classify(&out, envelope.volume()) {
        Ok(Classified::Log {
            records,
            committed_len: cl,
            tail_len: tl,
            ..
        }) => {
            assert_eq!(records, vec![decision]);
            assert_eq!(cl, committed_len);
            assert_eq!(tl, out.len() - committed_len);
        }
        other => panic!("a record with a torn mark must be discarded: {other:?}"),
    }
}

#[test]
fn record_with_an_absent_mark_is_discarded_as_a_tail() {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let (decision, candidate) = standard_decision(&envelope, 1);
    append_pair(&mut out, &envelope, &decision);
    let committed_len = out.len();
    let attestation = standard_attestation(1, &candidate);
    let attestation_append =
        encode_append(&envelope, &attestation).unwrap_or_else(|e| panic!("{e}"));
    out.extend_from_slice(attestation_append.record());
    match classify(&out, envelope.volume()) {
        Ok(Classified::Log {
            records,
            committed_len: cl,
            tail_len: tl,
            ..
        }) => {
            assert_eq!(records, vec![decision]);
            assert_eq!(cl, committed_len);
            assert_eq!(tl, out.len() - committed_len);
        }
        other => panic!("a record with no mark at all must be discarded: {other:?}"),
    }
}

#[test]
fn a_zero_filled_hole_in_the_last_record_is_discarded() {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let (decision, _) = standard_decision(&envelope, 1);
    append_pair(&mut out, &envelope, &decision);
    let committed_len = out.len();
    // A pre-allocated-but-never-written hole: the crash model's own
    // shape for "the file was extended before the write landed".
    out.extend_from_slice(&[0u8; 150]);
    match classify(&out, envelope.volume()) {
        Ok(Classified::Log {
            records,
            committed_len: cl,
            tail_len: tl,
            ..
        }) => {
            assert_eq!(records, vec![decision]);
            assert_eq!(cl, committed_len);
            assert_eq!(tl, 150);
        }
        other => panic!("a zero-filled hole must be discarded: {other:?}"),
    }
}

#[test]
fn damage_to_a_middle_committed_record_refuses() {
    let (envelope, mut bytes) = clean_log();
    let env_len = encode_envelope(&envelope).as_bytes().len();
    let (decision, _) = standard_decision(&envelope, 1);
    let decision_append = encode_append(&envelope, &decision).unwrap_or_else(|e| panic!("{e}"));
    let attestation_start = env_len + decision_append.record().len() + MARK_LEN;
    // One body byte inside the attestation (the "middle" record: landed
    // still follows with its own intact mark), flipped WITHOUT
    // recomputing its check.
    let flip_at = attestation_start + (RECORD_FIXED_LEN - 32) + 4;
    if let Some(b) = bytes.get_mut(flip_at) {
        *b ^= 0xFF;
    }
    assert_eq!(
        classify(&bytes, envelope.volume()),
        Err(LogError {
            offset: attestation_start,
            reason: LogErrorReason::DamagedCommittedHistory,
        })
    );
}

#[test]
fn a_corrupted_length_field_running_past_later_marks_refuses() {
    let (envelope, mut bytes) = clean_log();
    let env_len = encode_envelope(&envelope).as_bytes().len();
    let (decision, _) = standard_decision(&envelope, 1);
    let decision_append = encode_append(&envelope, &decision).unwrap_or_else(|e| panic!("{e}"));
    let attestation_start = env_len + decision_append.record().len() + MARK_LEN;
    // body_len sits right after tag+version+epoch+seq.
    let len_field_start = attestation_start + 1 + 2 + EPOCH_LEN + 8;
    let true_len = bytes
        .get(len_field_start..len_field_start + 4)
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map_or_else(
            || panic!("body_len field must be present"),
            u32::from_be_bytes,
        );
    let corrupted = true_len + 40; // runs past this record's true end
    if let Some(slot) = bytes.get_mut(len_field_start..len_field_start + 4) {
        slot.copy_from_slice(&corrupted.to_be_bytes());
    }
    // Lengths inside the tail are never used for the mark search, so
    // the corrupted length cannot hide mark 2 or mark 3 from it.
    assert_eq!(
        classify(&bytes, envelope.volume()),
        Err(LogError {
            offset: attestation_start,
            reason: LogErrorReason::DamagedCommittedHistory,
        })
    );
}

#[test]
fn another_epochs_record_with_an_intact_mark_refuses() {
    let envelope = test_envelope();
    let wrong_envelope = Envelope::new(test_volume(), other_epoch());
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let (decision, _) = standard_decision(&envelope, 1);
    append_pair(&mut out, &envelope, &decision);
    let damaged_start = out.len();
    let (_, wrong_candidate) = standard_decision(&wrong_envelope, 1);
    let landed_wrong_epoch = standard_landed(1, &wrong_candidate);
    append_pair(&mut out, &wrong_envelope, &landed_wrong_epoch);
    assert_eq!(
        classify(&out, envelope.volume()),
        Err(LogError {
            offset: damaged_start,
            reason: LogErrorReason::DamagedCommittedHistory,
        })
    );
}

#[test]
fn another_epochs_record_with_no_mark_is_discarded() {
    let envelope = test_envelope();
    let wrong_envelope = Envelope::new(test_volume(), other_epoch());
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let (decision, _) = standard_decision(&envelope, 1);
    append_pair(&mut out, &envelope, &decision);
    let committed_len = out.len();
    let (_, wrong_candidate) = standard_decision(&wrong_envelope, 1);
    let landed_wrong_epoch = standard_landed(1, &wrong_candidate);
    let landed_append =
        encode_append(&wrong_envelope, &landed_wrong_epoch).unwrap_or_else(|e| panic!("{e}"));
    out.extend_from_slice(landed_append.record());
    match classify(&out, envelope.volume()) {
        Ok(Classified::Log {
            committed_len: cl,
            tail_len: tl,
            ..
        }) => {
            assert_eq!(cl, committed_len);
            assert_eq!(tl, out.len() - committed_len);
        }
        other => panic!("a record from another epoch with no mark must be discarded: {other:?}"),
    }
}

#[test]
fn unknown_version_refuses() {
    let envelope = test_envelope();
    let mut bytes = encode_envelope(&envelope).as_bytes().to_vec();
    if let Some(slot) = bytes.get_mut(8..10) {
        slot.copy_from_slice(&2u16.to_be_bytes());
    }
    let len = bytes.len();
    let check = blake3::derive_key(ENVELOPE_CONTEXT, bytes.get(..len - 32).unwrap_or_default());
    if let Some(slot) = bytes.get_mut(len - 32..) {
        slot.copy_from_slice(&check);
    }
    assert_eq!(
        classify(&bytes, envelope.volume()),
        Err(LogError {
            offset: 0,
            reason: LogErrorReason::UnknownVersion { version: 2 },
        })
    );
}

#[test]
fn envelope_with_a_malformed_v1_body_refuses() {
    let envelope = test_envelope();
    let mut bytes = encode_envelope(&envelope).as_bytes().to_vec();
    if let Some(b) = bytes.get_mut(12) {
        *b = 0; // an empty volume_name: not a legal DNS-1123 label
    }
    let len = bytes.len();
    let check = blake3::derive_key(ENVELOPE_CONTEXT, bytes.get(..len - 32).unwrap_or_default());
    if let Some(slot) = bytes.get_mut(len - 32..) {
        slot.copy_from_slice(&check);
    }
    assert_eq!(
        classify(&bytes, envelope.volume()),
        Err(LogError {
            offset: 0,
            reason: LogErrorReason::EnvelopeMalformed,
        })
    );
}

#[test]
fn envelope_for_another_volume_refuses() {
    let envelope = test_envelope();
    let bytes = encode_envelope(&envelope).as_bytes().to_vec();
    assert_eq!(
        classify(&bytes, &other_volume()),
        Err(LogError {
            offset: 0,
            reason: LogErrorReason::WrongVolume,
        })
    );
}

#[test]
fn empty_file_is_no_envelope() {
    assert_eq!(classify(&[], &test_volume()), Ok(Classified::NoEnvelope));
}

#[test]
fn a_torn_envelope_is_no_envelope() {
    let envelope = test_envelope();
    let bytes = encode_envelope(&envelope).as_bytes().to_vec();
    let torn = bytes.get(..30).unwrap_or_default();
    assert_eq!(
        classify(torn, envelope.volume()),
        Ok(Classified::NoEnvelope)
    );
}

#[test]
fn a_garbage_envelope_with_no_mark_is_no_envelope() {
    let garbage = vec![0xAAu8; 50];
    assert_eq!(
        classify(&garbage, &test_volume()),
        Ok(Classified::NoEnvelope)
    );
}

#[test]
fn a_garbage_envelope_followed_by_a_valid_pair_refuses() {
    let envelope = test_envelope();
    let mut out = vec![0xAAu8; 20];
    let (decision, _) = standard_decision(&envelope, 1);
    append_pair(&mut out, &envelope, &decision);
    assert_eq!(
        classify(&out, envelope.volume()),
        Err(LogError {
            offset: 0,
            reason: LogErrorReason::DamagedCommittedHistory,
        })
    );
}

#[test]
fn the_accepted_residual_is_discarded() {
    let (envelope, mut bytes) = clean_log();
    // Destroy exactly the LAST record's (landed's) mark and nothing
    // after it -- indistinguishable from an interrupted append.
    let flip_at = bytes.len() - 1;
    if let Some(b) = bytes.get_mut(flip_at) {
        *b ^= 0xFF;
    }
    let (decision, candidate) = standard_decision(&envelope, 1);
    let attestation = standard_attestation(1, &candidate);
    match classify(&bytes, envelope.volume()) {
        Ok(Classified::Log {
            records,
            committed_len,
            tail_len,
            ..
        }) => {
            assert_eq!(records, vec![decision, attestation]);
            assert!(tail_len > 0);
            assert_eq!(committed_len + tail_len, bytes.len());
        }
        other => {
            panic!(
                "destroying only the LAST record's mark must discard it, never refuse: {other:?}"
            )
        }
    }
}

// ================================================================
// The tail bound used during recovery.
// A mark-free tail is held to what one interrupted append can
// leave — the legal next record plus a
// mark, or RECORD_V1_MAX.
// ================================================================

/// The largest record a v1 decision can ever encode: every identity
/// field at its cap and a maximal [`ROOT_V1_MAX_ENCODABLE`]-byte v1
/// root as the candidate. Returns the envelope it must be classified
/// against (its own 63-byte volume name, matching the candidate root's
/// `volume` field) and the record itself, at `seq`.
fn largest_legal_decision(seq: u64) -> (Envelope, Record) {
    let volume = max_len_volume();
    let parent = GrainId::of(b"parent");
    let root_doc = RootDoc {
        volume: volume.clone(),
        // seq 2 so `parent` is PRESENT -- the larger of the decision's
        // two `base` encodings.
        seq: 2,
        parent: Some(parent),
        writer_uuid: [0xAB; 16],
        epoch: u64::MAX,
        timestamp: Timestamp {
            secs: i64::MAX,
            nanos: 999_999_999,
        },
        chunker_spec: "c".repeat(root::CHUNKER_SPEC_MAX),
        manifest_root: GrainId::of(b"manifest"),
        binmap_index: GrainId::of(b"binmap"),
        sheaf_head: GrainId::of(b"sheaf"),
        sigs: vec![
            RootSig {
                key_id: [0x01; KEY_ID_LEN],
                sig: [0x11; ED25519_SIG_LEN],
            },
            RootSig {
                key_id: [0x02; KEY_ID_LEN],
                sig: [0x22; ED25519_SIG_LEN],
            },
        ],
    };
    let candidate_bytes = root::encode_root(&root_doc).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        candidate_bytes.len(),
        ROOT_V1_MAX_ENCODABLE,
        "the fixture root must itself be the golden vector for ROOT_V1_MAX_ENCODABLE"
    );
    let candidate_id = GrainId::of(&candidate_bytes);

    let identity = SubmissionIdentity::new(
        Tenant::new(vec![0xAA; TENANT_MAX]).unwrap_or_else(|e| panic!("{e}")),
        Principal::new(vec![0xBB; PRINCIPAL_MAX]).unwrap_or_else(|e| panic!("{e}")),
        Operation::new(vec![0xCC; OPERATION_MAX]).unwrap_or_else(|e| panic!("{e}")),
        candidate_id,
    );
    let body = RecordBody::Decision {
        identity,
        root_seq: 2,
        base: Some(parent),
        decided_at: Timestamp {
            secs: i64::MAX,
            nanos: 999_999_999,
        },
        candidate: RootBytes::new(candidate_bytes).unwrap_or_else(|e| panic!("{e}")),
    };
    let record = Record::new(seq, body).unwrap_or_else(|e| panic!("{e}"));
    let envelope = Envelope::new(volume, test_epoch());
    (envelope, record)
}

#[test]
fn mark_free_tail_of_exactly_record_v1_max_is_discarded() {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let committed_len = out.len();
    out.extend(std::iter::repeat_n(0x5Au8, RECORD_V1_MAX));
    match classify(&out, envelope.volume()) {
        Ok(Classified::Log {
            records,
            committed_len: cl,
            tail_len: tl,
            ..
        }) => {
            assert!(records.is_empty());
            assert_eq!(cl, committed_len);
            assert_eq!(tl, RECORD_V1_MAX);
        }
        other => {
            panic!("a mark-free tail of exactly RECORD_V1_MAX bytes must be discarded: {other:?}")
        }
    }
}

#[test]
fn mark_free_tail_of_record_v1_max_plus_one_refuses() {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let committed_len = out.len();
    out.extend(std::iter::repeat_n(0x5Au8, RECORD_V1_MAX + 1));
    assert_eq!(
        classify(&out, envelope.volume()),
        Err(LogError {
            offset: committed_len,
            reason: LogErrorReason::DamagedCommittedHistory,
        })
    );
}

#[test]
fn largest_legal_next_decision_encodes_at_exactly_record_v1_max() {
    let (envelope, record) = largest_legal_decision(1);
    let append = encode_append(&envelope, &record).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(append.record().len(), RECORD_V1_MAX);
}

#[test]
fn largest_legal_next_decision_followed_by_a_broken_mark_is_discarded() {
    let (envelope, record) = largest_legal_decision(1);
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let committed_len = out.len();
    let append = encode_append(&envelope, &record).unwrap_or_else(|e| panic!("{e}"));
    out.extend_from_slice(append.record());
    // Exactly MARK_LEN bytes, none of which forms a valid mark.
    out.extend(std::iter::repeat_n(0x5Au8, MARK_LEN));
    match classify(&out, envelope.volume()) {
        Ok(Classified::Log {
            records,
            committed_len: cl,
            tail_len: tl,
            ..
        }) => {
            assert!(records.is_empty());
            assert_eq!(cl, committed_len);
            assert_eq!(tl, out.len() - committed_len);
        }
        other => panic!(
            "the largest legal next record followed by exactly MARK_LEN broken-mark bytes must \
             be discarded: {other:?}"
        ),
    }
}

#[test]
fn largest_legal_next_decision_followed_by_one_byte_too_many_refuses() {
    let (envelope, record) = largest_legal_decision(1);
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let committed_len = out.len();
    let append = encode_append(&envelope, &record).unwrap_or_else(|e| panic!("{e}"));
    out.extend_from_slice(append.record());
    // MARK_LEN + 1 bytes: one more than the largest legal record's own
    // bound (record length + MARK_LEN) admits.
    out.extend(std::iter::repeat_n(0x5Au8, MARK_LEN + 1));
    assert_eq!(
        classify(&out, envelope.volume()),
        Err(LogError {
            offset: committed_len,
            reason: LogErrorReason::DamagedCommittedHistory,
        })
    );
}

#[test]
fn a_shrunk_body_len_header_is_discarded_within_the_record_v1_max_bound() {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let committed_len = out.len();
    let (decision, _) = standard_decision(&envelope, 1);
    let append = encode_append(&envelope, &decision).unwrap_or_else(|e| panic!("{e}"));
    let mut record_bytes = append.record().to_vec();
    // body_len sits right after tag(1) + version(2) + epoch(16) + seq(8)
    // = 27.
    let len_field_start = 1 + 2 + EPOCH_LEN + 8;
    let true_len = record_bytes
        .get(len_field_start..len_field_start + 4)
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map_or_else(
            || panic!("body_len field must be present"),
            u32::from_be_bytes,
        );
    // Shrunk by more than MARK_LEN, so a bound that trusted this header
    // (its claimed length plus a mark) would fall below the bytes
    // actually written and refuse an honest crash.
    let cut = u32::try_from(MARK_LEN + 1).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        true_len > cut,
        "the fixture's body must be longer than a mark"
    );
    let shrunk = true_len - cut;
    if let Some(slot) = record_bytes.get_mut(len_field_start..len_field_start + 4) {
        slot.copy_from_slice(&shrunk.to_be_bytes());
    }
    // No mark: the tail is exactly this record's own (real, un-shrunk)
    // length, an honest crash mid-write.
    out.extend_from_slice(&record_bytes);
    let tail_len = out.len() - committed_len;
    assert!(tail_len <= RECORD_V1_MAX);
    match classify(&out, envelope.volume()) {
        Ok(Classified::Log {
            records,
            committed_len: cl,
            tail_len: tl,
            ..
        }) => {
            assert!(records.is_empty());
            assert_eq!(cl, committed_len);
            assert_eq!(tl, tail_len);
        }
        other => panic!(
            "a header claiming a shorter body than was actually written must be discarded while \
             the tail fits RECORD_V1_MAX: {other:?}"
        ),
    }
}

#[test]
fn three_committed_pairs_with_all_marks_zeroed_and_first_record_intact_refuses() {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let committed_len = out.len();
    let (decision, candidate) = standard_decision(&envelope, 1);
    let attestation = standard_attestation(1, &candidate);
    let landed = standard_landed(1, &candidate);
    for record in [&decision, &attestation, &landed] {
        let append = encode_append(&envelope, record).unwrap_or_else(|e| panic!("{e}"));
        out.extend_from_slice(append.record());
        out.extend_from_slice(&[0u8; MARK_LEN]);
    }
    assert_eq!(
        classify(&out, envelope.volume()),
        Err(LogError {
            offset: committed_len,
            reason: LogErrorReason::DamagedCommittedHistory,
        })
    );
}

#[test]
fn three_committed_pairs_with_marks_zeroed_and_first_record_also_damaged_is_discarded() {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let committed_len = out.len();
    let (decision, candidate) = standard_decision(&envelope, 1);
    let attestation = standard_attestation(1, &candidate);
    let landed = standard_landed(1, &candidate);
    let decision_start = out.len();
    for record in [&decision, &attestation, &landed] {
        let append = encode_append(&envelope, record).unwrap_or_else(|e| panic!("{e}"));
        out.extend_from_slice(append.record());
        out.extend_from_slice(&[0u8; MARK_LEN]);
    }
    // Flip the decision record's own tag byte: its check no longer
    // holds, so it no longer decodes as a complete record at all -- the
    // tail falls to the RECORD_V1_MAX bound rather than the legal-next
    // one. All three damaged pairs together still fit inside
    // RECORD_V1_MAX, which is what makes this the pinned residual.
    if let Some(b) = out.get_mut(decision_start) {
        *b ^= 0xFF;
    }
    let tail_len = out.len() - committed_len;
    assert!(tail_len <= RECORD_V1_MAX);
    match classify(&out, envelope.volume()) {
        Ok(Classified::Log {
            records,
            committed_len: cl,
            tail_len: tl,
            ..
        }) => {
            assert!(records.is_empty());
            assert_eq!(cl, committed_len);
            assert_eq!(tl, tail_len);
        }
        other => panic!(
            "damage to the first of several zeroed-mark records, within RECORD_V1_MAX, must be \
             discarded (the pinned residual): {other:?}"
        ),
    }
}

#[test]
fn a_check_valid_record_of_this_epoch_that_is_not_the_legal_next_record_refuses() {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let committed_len = out.len();
    // seq 5 with no entry open and highest_seq 0: not the legal next
    // position (grammar rule 1 wants seq 1).
    let (decision, _) = standard_decision(&envelope, 5);
    let append = encode_append(&envelope, &decision).unwrap_or_else(|e| panic!("{e}"));
    out.extend_from_slice(append.record());
    assert_eq!(
        classify(&out, envelope.volume()),
        Err(LogError {
            offset: committed_len,
            reason: LogErrorReason::DamagedCommittedHistory,
        })
    );
}

// ================================================================
// Round trips: hand-built values across every field's boundaries
// Deterministic boundary regressions complement the generated round trips
// in granary-conformance; proptest stays outside core's pure closure.
// ================================================================

#[track_caller]
fn assert_round_trips(envelope: &Envelope, cases: &[Record]) {
    for record in cases {
        let append = encode_append(envelope, record).unwrap_or_else(|e| panic!("{record:?}: {e}"));
        let decoded = decode_record(append.record(), envelope.volume())
            .unwrap_or_else(|| panic!("{record:?}: must decode back"));
        assert_eq!(&decoded.record, record);
        assert_eq!(decoded.consumed, append.record().len());
        assert_eq!(decoded.version, envelope.version());
        assert_eq!(decoded.epoch, envelope.epoch());
    }
}

#[test]
fn decision_records_round_trip_across_field_boundaries() {
    let envelope = test_envelope();
    let mut cases: Vec<Record> = Vec::new();

    for (root_seq, base) in [
        (1u64, None),
        (2, Some(GrainId::of(b"parent-a"))),
        (18_446_744_073_709_551_613, Some(GrainId::of(b"parent-b"))),
    ] {
        let sample_candidate = sample_root(envelope.volume(), root_seq, base);
        let sample_id = GrainId::of(&sample_candidate);
        for (tenant_len, principal_len, operation_len) in [
            (1usize, 1usize, 1usize),
            (TENANT_MAX, PRINCIPAL_MAX, OPERATION_MAX),
        ] {
            let identity = SubmissionIdentity::new(
                Tenant::new(vec![0x7A; tenant_len]).unwrap_or_else(|e| panic!("{e}")),
                Principal::new(vec![0x7B; principal_len]).unwrap_or_else(|e| panic!("{e}")),
                Operation::new(vec![0x7C; operation_len]).unwrap_or_else(|e| panic!("{e}")),
                sample_id,
            );
            for decided_at in [
                Timestamp {
                    secs: i64::MIN,
                    nanos: 0,
                },
                Timestamp {
                    secs: i64::MAX,
                    nanos: 999_999_999,
                },
            ] {
                let body = RecordBody::Decision {
                    identity: identity.clone(),
                    root_seq,
                    base,
                    decided_at,
                    candidate: RootBytes::new(sample_candidate.clone())
                        .unwrap_or_else(|e| panic!("{e}")),
                };
                cases.push(Record::new(1, body).unwrap_or_else(|e| panic!("{e}")));
            }
        }
    }

    assert_round_trips(&envelope, &cases);
}

#[test]
fn other_record_kinds_round_trip_across_field_boundaries() {
    let envelope = test_envelope();
    let (_, candidate) = standard_decision(&envelope, 1);
    let candidate_id = GrainId::of(&candidate);
    let mut cases: Vec<Record> = Vec::new();

    // Attestation: `final_root` carries no root-decodability rule, so
    // this is the one place the true ROOT_BYTES_MAX-byte ceiling is
    // reachable.
    for len in [1usize, ROOT_BYTES_MAX] {
        let final_bytes = vec![0x5Cu8; len];
        let stored_id = GrainId::of(&final_bytes);
        let body = RecordBody::Attestation {
            identity: identity_of(stored_id),
            stored_id,
            final_root: RootBytes::new(final_bytes).unwrap_or_else(|e| panic!("{e}")),
        };
        cases.push(Record::new(1, body).unwrap_or_else(|e| panic!("{e}")));
    }

    cases.push(
        Record::new(
            1,
            RecordBody::Landed {
                identity: identity_of(candidate_id),
            },
        )
        .unwrap_or_else(|e| panic!("{e}")),
    );
    cases.push(
        Record::new(
            1,
            RecordBody::Lost {
                identity: identity_of(candidate_id),
                occupant_id: GrainId::of(b"occupant"),
            },
        )
        .unwrap_or_else(|e| panic!("{e}")),
    );

    assert_round_trips(&envelope, &cases);
}

// ================================================================
// Non-canonical rejects — each funnels through DamagedCommittedHistory
// once wrapped in a self-consistent mark (the format doesn't
// distinguish WHY a candidate record was bad, only whether a mark
// commits it).
// ================================================================

#[track_caller]
fn assert_bad_record_refuses(tag: u8, body: &[u8]) {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let env_len = out.len();
    let (record_bytes, mark) = manual_record(&envelope, 1, tag, body);
    out.extend_from_slice(&record_bytes);
    out.extend_from_slice(&mark);
    assert_eq!(
        classify(&out, envelope.volume()),
        Err(LogError {
            offset: env_len,
            reason: LogErrorReason::DamagedCommittedHistory,
        })
    );
}

#[test]
fn uppercase_hex_is_refused() {
    let candidate = sample_root(&test_volume(), 1, None);
    let candidate_id = GrainId::of(&candidate);
    let mut identity = Vec::new();
    manual_hex16(&mut identity, &[0xAB]); // "ab" -- a hex char that has an uppercase form
    manual_hex16(&mut identity, &[0x22, 0x22]);
    manual_hex16(&mut identity, &[0x33]);
    identity.extend_from_slice(&candidate_id.to_bytes());
    if let Some(b) = identity.get_mut(2) {
        assert_eq!(*b, b'a', "offset 2 must be tenant's first hex char");
        *b = b'A';
    }
    let body = manual_decision_body(
        identity,
        1,
        None,
        Timestamp { secs: 1, nanos: 0 },
        &candidate,
    );
    assert_bad_record_refuses(TAG_DECISION, &body);
}

#[test]
fn odd_hex_length_is_refused() {
    let candidate = sample_root(&test_volume(), 1, None);
    let candidate_id = GrainId::of(&candidate);
    let mut identity = good_identity_bytes(candidate_id);
    if let Some(slot) = identity.get_mut(0..2) {
        slot.copy_from_slice(&1u16.to_be_bytes());
    }
    let body = manual_decision_body(
        identity,
        1,
        None,
        Timestamp { secs: 1, nanos: 0 },
        &candidate,
    );
    assert_bad_record_refuses(TAG_DECISION, &body);
}

#[test]
fn a_hex_length_of_zero_is_refused() {
    let candidate = sample_root(&test_volume(), 1, None);
    let candidate_id = GrainId::of(&candidate);
    let mut identity = good_identity_bytes(candidate_id);
    if let Some(slot) = identity.get_mut(0..2) {
        slot.copy_from_slice(&0u16.to_be_bytes());
    }
    let body = manual_decision_body(
        identity,
        1,
        None,
        Timestamp { secs: 1, nanos: 0 },
        &candidate,
    );
    assert_bad_record_refuses(TAG_DECISION, &body);
}

#[test]
fn decision_base_presence_byte_0x02_is_refused() {
    let candidate = sample_root(&test_volume(), 2, Some(GrainId::of(b"parent")));
    let candidate_id = GrainId::of(&candidate);
    let mut body = good_identity_bytes(candidate_id);
    body.extend_from_slice(&2u64.to_be_bytes());
    body.push(0x02);
    body.extend_from_slice(&1i64.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes());
    manual_hex32(&mut body, &candidate);
    assert_bad_record_refuses(TAG_DECISION, &body);
}

#[test]
fn root_seq_zero_is_refused() {
    let candidate = sample_root(&test_volume(), 1, None);
    let candidate_id = GrainId::of(&candidate);
    let body = manual_decision_body(
        good_identity_bytes(candidate_id),
        0,
        None,
        Timestamp { secs: 1, nanos: 0 },
        &candidate,
    );
    assert_bad_record_refuses(TAG_DECISION, &body);
}

#[test]
fn root_seq_u64_max_is_refused() {
    let candidate = sample_root(&test_volume(), 1, None);
    let candidate_id = GrainId::of(&candidate);
    let body = manual_decision_body(
        good_identity_bytes(candidate_id),
        u64::MAX,
        None,
        Timestamp { secs: 1, nanos: 0 },
        &candidate,
    );
    assert_bad_record_refuses(TAG_DECISION, &body);
}

#[test]
fn base_present_at_root_seq_one_is_refused() {
    let candidate = sample_root(&test_volume(), 1, None);
    let candidate_id = GrainId::of(&candidate);
    let body = manual_decision_body(
        good_identity_bytes(candidate_id),
        1,
        Some(GrainId::of(b"unexpected-base")),
        Timestamp { secs: 1, nanos: 0 },
        &candidate,
    );
    assert_bad_record_refuses(TAG_DECISION, &body);
}

#[test]
fn base_absent_at_root_seq_two_is_refused() {
    // The decision's OWN root_seq/base cross-rule is checked before the
    // candidate is ever decoded as a root, so the candidate need not be
    // a structurally valid one here (a real root with `seq=2, parent:
    // None` would refuse construction itself, at `encode_root`).
    let candidate = b"never inspected: the cross-rule refuses first".to_vec();
    let candidate_id = GrainId::of(&candidate);
    let body = manual_decision_body(
        good_identity_bytes(candidate_id),
        2,
        None,
        Timestamp { secs: 1, nanos: 0 },
        &candidate,
    );
    assert_bad_record_refuses(TAG_DECISION, &body);
}

#[test]
fn nanos_at_one_billion_is_refused() {
    let candidate = sample_root(&test_volume(), 1, None);
    let candidate_id = GrainId::of(&candidate);
    let body = manual_decision_body(
        good_identity_bytes(candidate_id),
        1,
        None,
        Timestamp {
            secs: 1,
            nanos: 1_000_000_000,
        },
        &candidate,
    );
    assert_bad_record_refuses(TAG_DECISION, &body);
}

#[test]
fn candidate_id_not_the_candidates_hash_is_refused() {
    let candidate = sample_root(&test_volume(), 1, None);
    let wrong_id = GrainId::of(b"not the candidate");
    let body = manual_decision_body(
        good_identity_bytes(wrong_id),
        1,
        None,
        Timestamp { secs: 1, nanos: 0 },
        &candidate,
    );
    assert_bad_record_refuses(TAG_DECISION, &body);
}

#[test]
fn trailing_body_bytes_are_refused() {
    let candidate = sample_root(&test_volume(), 1, None);
    let candidate_id = GrainId::of(&candidate);
    let mut body = manual_decision_body(
        good_identity_bytes(candidate_id),
        1,
        None,
        Timestamp { secs: 1, nanos: 0 },
        &candidate,
    );
    body.push(0xFF);
    assert_bad_record_refuses(TAG_DECISION, &body);
}

#[test]
fn an_unknown_tag_with_a_valid_check_and_mark_is_refused() {
    let candidate = sample_root(&test_volume(), 1, None);
    let candidate_id = GrainId::of(&candidate);
    let body = good_identity_bytes(candidate_id);
    assert_bad_record_refuses(0xFE, &body);
}

#[test]
fn tenant_one_byte_over_its_cap_is_refused() {
    let candidate = sample_root(&test_volume(), 1, None);
    let candidate_id = GrainId::of(&candidate);
    let mut identity = Vec::new();
    manual_hex16(&mut identity, &vec![0xAAu8; TENANT_MAX + 1]);
    manual_hex16(&mut identity, &[0x22]);
    manual_hex16(&mut identity, &[0x33]);
    identity.extend_from_slice(&candidate_id.to_bytes());
    let body = manual_decision_body(
        identity,
        1,
        None,
        Timestamp { secs: 1, nanos: 0 },
        &candidate,
    );
    assert_bad_record_refuses(TAG_DECISION, &body);
}

#[test]
fn principal_one_byte_over_its_cap_is_refused() {
    let candidate = sample_root(&test_volume(), 1, None);
    let candidate_id = GrainId::of(&candidate);
    let mut identity = Vec::new();
    manual_hex16(&mut identity, &[0x11]);
    manual_hex16(&mut identity, &vec![0xBBu8; PRINCIPAL_MAX + 1]);
    manual_hex16(&mut identity, &[0x33]);
    identity.extend_from_slice(&candidate_id.to_bytes());
    let body = manual_decision_body(
        identity,
        1,
        None,
        Timestamp { secs: 1, nanos: 0 },
        &candidate,
    );
    assert_bad_record_refuses(TAG_DECISION, &body);
}

#[test]
fn operation_one_byte_over_its_cap_is_refused() {
    let candidate = sample_root(&test_volume(), 1, None);
    let candidate_id = GrainId::of(&candidate);
    let mut identity = Vec::new();
    manual_hex16(&mut identity, &[0x11]);
    manual_hex16(&mut identity, &[0x22]);
    manual_hex16(&mut identity, &vec![0xCCu8; OPERATION_MAX + 1]);
    identity.extend_from_slice(&candidate_id.to_bytes());
    let body = manual_decision_body(
        identity,
        1,
        None,
        Timestamp { secs: 1, nanos: 0 },
        &candidate,
    );
    assert_bad_record_refuses(TAG_DECISION, &body);
}

// ================================================================
// Cross-field (format doc "Field rules" and grammar rule 5)
// ================================================================

#[test]
fn attestation_final_differing_from_decisions_candidate_refuses() {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let (decision, candidate) = standard_decision(&envelope, 1);
    append_pair(&mut out, &envelope, &decision);
    let attestation_start = out.len();
    // `final_root` carries no root-decodability rule (unlike a
    // decision's `candidate`), so arbitrary distinct bytes suffice here.
    let other_final = b"a different final payload than the decision's candidate".to_vec();
    assert_ne!(other_final, candidate, "the fixture must actually differ");
    let stored_id = GrainId::of(&other_final);
    let attestation = Record::new(
        1,
        RecordBody::Attestation {
            identity: identity_of(GrainId::of(&candidate)),
            stored_id,
            final_root: RootBytes::new(other_final).unwrap_or_else(|e| panic!("{e}")),
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    append_pair(&mut out, &envelope, &attestation);
    assert_eq!(
        classify(&out, envelope.volume()),
        Err(LogError {
            offset: attestation_start,
            reason: LogErrorReason::Grammar(GrammarRule::Rule5IdentityMismatch),
        })
    );
}

#[test]
fn candidate_that_does_not_decode_as_a_root_is_refused() {
    let garbage = b"not a root at all, just plain bytes".to_vec();
    let candidate_id = GrainId::of(&garbage);
    let body = manual_decision_body(
        good_identity_bytes(candidate_id),
        1,
        None,
        Timestamp { secs: 1, nanos: 0 },
        &garbage,
    );
    assert_bad_record_refuses(TAG_DECISION, &body);
}

#[test]
fn candidate_naming_another_volume_is_refused() {
    let candidate = sample_root(&other_volume(), 1, None);
    let candidate_id = GrainId::of(&candidate);
    let body = manual_decision_body(
        good_identity_bytes(candidate_id),
        1,
        None,
        Timestamp { secs: 1, nanos: 0 },
        &candidate,
    );
    assert_bad_record_refuses(TAG_DECISION, &body);
}

#[test]
fn candidate_naming_another_seq_than_root_seq_is_refused() {
    let candidate = sample_root(&test_volume(), 5, Some(GrainId::of(b"parent")));
    let candidate_id = GrainId::of(&candidate);
    let body = manual_decision_body(
        good_identity_bytes(candidate_id),
        2,
        Some(GrainId::of(b"parent")),
        Timestamp { secs: 1, nanos: 0 },
        &candidate,
    );
    assert_bad_record_refuses(TAG_DECISION, &body);
}

#[test]
fn candidate_naming_a_parent_other_than_base_is_refused() {
    let candidate = sample_root(&test_volume(), 2, Some(GrainId::of(b"real-parent")));
    let candidate_id = GrainId::of(&candidate);
    let body = manual_decision_body(
        good_identity_bytes(candidate_id),
        2,
        Some(GrainId::of(b"claimed-parent")),
        Timestamp { secs: 1, nanos: 0 },
        &candidate,
    );
    assert_bad_record_refuses(TAG_DECISION, &body);
}

// ================================================================
// Grammar: one failing log per rule 1-7
// ================================================================

#[test]
fn grammar_rule_1_sequence_position() {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let env_len = out.len();
    let (decision, _) = standard_decision(&envelope, 2); // must be 1
    append_pair(&mut out, &envelope, &decision);
    assert_eq!(
        classify(&out, envelope.volume()),
        Err(LogError {
            offset: env_len,
            reason: LogErrorReason::Grammar(GrammarRule::Rule1SequencePosition),
        })
    );
}

#[test]
fn grammar_rule_2_concurrent_entry() {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let (decision1, _) = standard_decision(&envelope, 1);
    append_pair(&mut out, &envelope, &decision1);
    let second_start = out.len();
    let candidate2 = sample_root(envelope.volume(), 1, None);
    let decision2 = Record::new(
        2,
        RecordBody::Decision {
            identity: other_identity(GrainId::of(&candidate2)),
            root_seq: 1,
            base: None,
            decided_at: Timestamp { secs: 2, nanos: 0 },
            candidate: RootBytes::new(candidate2).unwrap_or_else(|e| panic!("{e}")),
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    append_pair(&mut out, &envelope, &decision2);
    assert_eq!(
        classify(&out, envelope.volume()),
        Err(LogError {
            offset: second_start,
            reason: LogErrorReason::Grammar(GrammarRule::Rule2ConcurrentEntry),
        })
    );
}

#[test]
fn grammar_rule_3_attestation_preconditions() {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let env_len = out.len();
    let (_, candidate) = standard_decision(&envelope, 1);
    let attestation = standard_attestation(1, &candidate);
    append_pair(&mut out, &envelope, &attestation);
    assert_eq!(
        classify(&out, envelope.volume()),
        Err(LogError {
            offset: env_len,
            reason: LogErrorReason::Grammar(GrammarRule::Rule3AttestationPreconditions),
        })
    );
}

#[test]
fn grammar_rule_4_outcome_preconditions() {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let (decision, candidate) = standard_decision(&envelope, 1);
    append_pair(&mut out, &envelope, &decision);
    let landed_start = out.len();
    let landed = standard_landed(1, &candidate);
    append_pair(&mut out, &envelope, &landed);
    assert_eq!(
        classify(&out, envelope.volume()),
        Err(LogError {
            offset: landed_start,
            reason: LogErrorReason::Grammar(GrammarRule::Rule4OutcomePreconditions),
        })
    );
}

#[test]
fn grammar_rule_5_identity_mismatch() {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let (decision, candidate) = standard_decision(&envelope, 1);
    append_pair(&mut out, &envelope, &decision);
    let attestation_start = out.len();
    let candidate_id = GrainId::of(&candidate);
    let attestation = Record::new(
        1,
        RecordBody::Attestation {
            identity: other_identity(candidate_id),
            stored_id: candidate_id,
            final_root: RootBytes::new(candidate.clone()).unwrap_or_else(|e| panic!("{e}")),
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    append_pair(&mut out, &envelope, &attestation);
    assert_eq!(
        classify(&out, envelope.volume()),
        Err(LogError {
            offset: attestation_start,
            reason: LogErrorReason::Grammar(GrammarRule::Rule5IdentityMismatch),
        })
    );
}

/// A `Lost` outcome whose `occupant_id` is the entry's own stored id (in
/// v1, the decision's candidate id): a correct writer classifies a read
/// that finds its own bytes as landed, never lost (spec §4.2), so this
/// is a grammar violation — rule 5's third clause — not a legal outcome.
#[test]
fn grammar_rule_5_lost_naming_its_own_stored_id() {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let (decision, candidate) = standard_decision(&envelope, 1);
    append_pair(&mut out, &envelope, &decision);
    append_pair(&mut out, &envelope, &standard_attestation(1, &candidate));
    let lost_start = out.len();
    let lost = standard_lost(1, &candidate, GrainId::of(&candidate));
    append_pair(&mut out, &envelope, &lost);
    assert_eq!(
        classify(&out, envelope.volume()),
        Err(LogError {
            offset: lost_start,
            reason: LogErrorReason::Grammar(GrammarRule::Rule5IdentityMismatch),
        })
    );
}

#[test]
fn grammar_rule_6_landed_operation_replay() {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let (decision1, candidate1) = standard_decision(&envelope, 1);
    append_pair(&mut out, &envelope, &decision1);
    append_pair(&mut out, &envelope, &standard_attestation(1, &candidate1));
    append_pair(&mut out, &envelope, &standard_landed(1, &candidate1));
    let second_decision_start = out.len();
    let candidate2 = sample_root_variant(envelope.volume(), 1, None, b"a-different-manifest");
    assert_ne!(candidate1, candidate2);
    let decision2 = Record::new(
        2,
        RecordBody::Decision {
            identity: identity_of(GrainId::of(&candidate2)), // same tenant/principal/operation
            root_seq: 1,
            base: None,
            decided_at: Timestamp { secs: 3, nanos: 0 },
            candidate: RootBytes::new(candidate2).unwrap_or_else(|e| panic!("{e}")),
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    append_pair(&mut out, &envelope, &decision2);
    assert_eq!(
        classify(&out, envelope.volume()),
        Err(LogError {
            offset: second_decision_start,
            reason: LogErrorReason::Grammar(GrammarRule::Rule6LandedOperationReplay),
        })
    );
}

#[test]
fn grammar_rule_7_duplicate_answer() {
    let envelope = test_envelope();
    let mut out = encode_envelope(&envelope).as_bytes().to_vec();
    let (decision1, candidate1) = standard_decision(&envelope, 1);
    append_pair(&mut out, &envelope, &decision1);
    append_pair(&mut out, &envelope, &standard_attestation(1, &candidate1));
    // Closed via LOST, not landed: landed_operations stays empty, so
    // only rule 7's answered-identity set can be what refuses the
    // replay below (rule 6 is checked first and must not fire here).
    append_pair(
        &mut out,
        &envelope,
        &standard_lost(1, &candidate1, GrainId::of(b"occupant")),
    );
    let second_decision_start = out.len();
    // `standard_decision` always builds the SAME candidate/identity --
    // exactly the identity replay rule 7 refuses.
    let (decision2, _) = standard_decision(&envelope, 2);
    append_pair(&mut out, &envelope, &decision2);
    assert_eq!(
        classify(&out, envelope.volume()),
        Err(LogError {
            offset: second_decision_start,
            reason: LogErrorReason::Grammar(GrammarRule::Rule7DuplicateAnswer),
        })
    );
}

// ================================================================
// The planted-mark test: the hex rule's own mutation proof
// ================================================================

/// A root whose SECOND signature slot's bytes, read directly (never
/// hex-encoded), hold a complete, self-consistent 97-byte mark.
/// The log's hex encoding keeps those bytes distinct from a commit
/// mark. A root's signature section sits outside its signed prefix.
/// The fields `alg` and
/// `sig_len` are FIXED by `encode_root` at v1's only legal values
/// (0x01, 64), and those two fixed bytes are exactly where the mark's
/// own `tag` byte and the first two bytes of `record_check` land — so
/// only [`RootSig::key_id`]/[`RootSig::sig`] need to be chosen at all.
///
/// Returns the encoded root and the mark's byte offset within it.
fn root_with_planted_mark(
    volume: &VolumeName,
    mark_epoch: [u8; EPOCH_LEN],
    mark_seq: u64,
) -> (Vec<u8>, usize) {
    let mut key_id = [0u8; KEY_ID_LEN];
    {
        let (magic_dst, rest) = key_id.split_at_mut(8);
        magic_dst.copy_from_slice(&MARK_MAGIC);
        let (epoch_dst, seq_dst) = rest.split_at_mut(EPOCH_LEN);
        epoch_dst.copy_from_slice(&mark_epoch);
        seq_dst.copy_from_slice(&mark_seq.to_be_bytes());
    }
    let filler: [u8; 30] = core::array::from_fn(|i| {
        #[expect(clippy::cast_possible_truncation, reason = "i < 30")]
        {
            i as u8
        }
    });
    // The mark's 65-byte preimage: key_id(32) + alg(1, forced 0x01) +
    // record_check(32, whose first 2 bytes are FORCED to 0x00,0x40 by
    // the slot's fixed sig_len).
    let mut preimage = [0u8; 65];
    {
        let (a, rest) = preimage.split_at_mut(KEY_ID_LEN);
        a.copy_from_slice(&key_id);
        let (b, c) = rest.split_at_mut(1);
        b.copy_from_slice(&[0x01]);
        let (record_check_head, record_check_tail) = c.split_at_mut(2);
        record_check_head.copy_from_slice(&64u16.to_be_bytes());
        record_check_tail.copy_from_slice(&filler);
    }
    let mark_check = blake3::derive_key(MARK_CONTEXT, &preimage);

    let mut sig = [0u8; ED25519_SIG_LEN];
    {
        let (head, rest) = sig.split_at_mut(30);
        head.copy_from_slice(&filler);
        let (check_slot, free) = rest.split_at_mut(32);
        check_slot.copy_from_slice(&mark_check);
        free.copy_from_slice(&[0xCC, 0xDD]);
    }

    let doc = RootDoc {
        volume: volume.clone(),
        seq: 1,
        parent: None,
        writer_uuid: [0xAB; 16],
        epoch: 7,
        timestamp: Timestamp {
            secs: 1_700_000_000,
            nanos: 0,
        },
        chunker_spec: "test-chunker".to_owned(),
        manifest_root: GrainId::of(b"manifest"),
        binmap_index: GrainId::of(b"binmap"),
        sheaf_head: GrainId::of(b"sheaf"),
        sigs: vec![
            RootSig {
                key_id: [0x09; KEY_ID_LEN],
                sig: [0x0A; ED25519_SIG_LEN],
            },
            RootSig { key_id, sig },
        ],
    };
    let signing_prefix_len = root::signing_prefix_of(&doc)
        .unwrap_or_else(|e| panic!("{e}"))
        .len();
    // sig_count(1) + the first (untouched) slot(ROOT_SIG_SLOT_LEN)
    // precede the planted second slot, which the mark starts at.
    let mark_offset = signing_prefix_len + 1 + ROOT_SIG_SLOT_LEN;
    let bytes = root::encode_root(&doc).unwrap_or_else(|e| panic!("{e}"));
    (bytes, mark_offset)
}

#[test]
fn planted_mark_inside_a_hex_encoded_candidate_never_causes_a_refusal() {
    let envelope = test_envelope();
    let (planted_root, mark_offset) =
        root_with_planted_mark(envelope.volume(), [0x01; EPOCH_LEN], 42);
    // The premise: the plant really is a complete, valid mark when read
    // directly off the raw root bytes.
    let raw_mark = planted_root
        .get(mark_offset..mark_offset + MARK_LEN)
        .unwrap_or_else(|| panic!("planted mark must be in bounds"));
    assert!(
        decode_mark(raw_mark).is_some(),
        "the planted bytes must be a genuinely valid mark"
    );

    let candidate_id = GrainId::of(&planted_root);
    let decision = Record::new(
        1,
        RecordBody::Decision {
            identity: identity_of(candidate_id),
            root_seq: 1,
            base: None,
            decided_at: Timestamp { secs: 1, nanos: 0 },
            candidate: RootBytes::new(planted_root).unwrap_or_else(|e| panic!("{e}")),
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let mut whole = encode_envelope(&envelope).as_bytes().to_vec();
    let env_len = whole.len();
    append_pair(&mut whole, &envelope, &decision);

    // Every cut strictly inside the record+mark region: hex-encoded on
    // the wire, the planted mark's raw bytes never appear literally, so
    // every one of these is an ordinary interrupted append.
    for cut in env_len..whole.len() {
        match classify(whole.get(..cut).unwrap_or_default(), envelope.volume()) {
            Ok(Classified::Log { .. }) => {}
            other => panic!(
                "cut at {cut} (record region [{env_len}, {})) must discard, never refuse: {other:?}",
                whole.len()
            ),
        }
    }
}

#[test]
fn planted_mark_in_a_raw_non_hex_candidate_is_the_guards_mutation_proof() {
    let envelope = test_envelope();
    let (planted_root, mark_offset) =
        root_with_planted_mark(envelope.volume(), [0x02; EPOCH_LEN], 7);
    let raw_mark = planted_root
        .get(mark_offset..mark_offset + MARK_LEN)
        .unwrap_or_else(|| panic!("planted mark must be in bounds"));
    assert!(decode_mark(raw_mark).is_some());

    // A decision body whose "candidate" field bypasses the hex rule and
    // stores the root's bytes RAW — a shape no conforming encoder ever
    // produces, built only to show what the hex rule prevents.
    let candidate_id = GrainId::of(&planted_root);
    let mut body = good_identity_bytes(candidate_id);
    body.extend_from_slice(&1u64.to_be_bytes()); // root_seq
    body.push(0x00); // base absent
    body.extend_from_slice(&1i64.to_be_bytes()); // decided_at.secs
    body.extend_from_slice(&0u32.to_be_bytes()); // decided_at.nanos
    let candidate_field_start = body.len();
    manual_raw32_bypassing_hex(&mut body, &planted_root);
    let candidate_text_start = candidate_field_start + 4;

    let envelope_bytes = encode_envelope(&envelope).as_bytes().to_vec();
    let env_len = envelope_bytes.len();
    let (record_bytes, mark) = manual_record(&envelope, 1, TAG_DECISION, &body);
    let mut whole = envelope_bytes;
    whole.extend_from_slice(&record_bytes);
    whole.extend_from_slice(&mark);

    let header_len = RECORD_FIXED_LEN - 32; // tag+version+epoch+seq+body_len
    let planted_mark_end_in_file =
        env_len + header_len + candidate_text_start + mark_offset + MARK_LEN;

    // One byte short of the plant: this "record" was never going to be
    // accepted anyway (it fails hex decoding regardless of any cut), so
    // the only question is whether the bytes handed to the tail scan
    // happen to contain a valid mark -- and one byte short, they do not.
    match classify(
        whole
            .get(..planted_mark_end_in_file - 1)
            .unwrap_or_default(),
        envelope.volume(),
    ) {
        Ok(Classified::Log { .. }) => {}
        other => panic!("one byte short of the plant must not find it: {other:?}"),
    }

    // At and past the plant's end, the tail scan finds it: refused,
    // never discarded. WITHOUT the hex rule, bytes a submitter chooses
    // freely can defeat commit-evidence discovery this way.
    for cut in [planted_mark_end_in_file, whole.len()] {
        assert_eq!(
            classify(whole.get(..cut).unwrap_or_default(), envelope.volume()),
            Err(LogError {
                offset: env_len,
                reason: LogErrorReason::DamagedCommittedHistory,
            }),
            "cut at {cut} must find the planted mark and refuse"
        );
    }
}

// ================================================================
// The wire magics are never hex
// ================================================================

#[test]
fn magics_are_never_hex() {
    let is_lower_hex = |b: u8| matches!(b, b'0'..=b'9' | b'a'..=b'f');
    for &b in ENVELOPE_MAGIC.iter().chain(MARK_MAGIC.iter()) {
        assert!(
            !is_lower_hex(b),
            "magic byte {b:#04x} is inside the lowercase-hex alphabet"
        );
    }
}

/// The fuzz corpus's body seeds decode and re-encode exactly under the
/// probe's volume, so the probe's direct body check is not vacuous: a
/// seed set that decoded to nothing would leave the body decoder
/// fuzzed only through bytes that never carry valid checks.
#[test]
fn the_fuzz_body_seeds_decode_and_re_encode_exactly() {
    let seeds: [&[u8]; 4] = [
        include_bytes!("../../tests/vectors/authlog/seed-body-tag01"),
        include_bytes!("../../tests/vectors/authlog/seed-body-tag02"),
        include_bytes!("../../tests/vectors/authlog/seed-body-tag03"),
        include_bytes!("../../tests/vectors/authlog/seed-body-tag04"),
    ];
    for (i, seed) in seeds.iter().enumerate() {
        let Some((&tag, body)) = seed.split_first() else {
            panic!("seed {i} is empty");
        };
        let decoded = codec::decode_record_body(tag, body, &test_volume())
            .unwrap_or_else(|e| panic!("seed {i} (tag {tag:#04x}) must decode: {e:?}"));
        assert_eq!(decoded.tag(), tag, "seed {i} decodes to its own tag");
        let mut re = Vec::new();
        codec::encode_record_body(&mut re, &decoded, &test_volume())
            .unwrap_or_else(|e| panic!("seed {i} must re-encode: {e}"));
        assert_eq!(re, body, "seed {i} re-encodes to its own bytes");
    }
}

/// The corpus seeds laid out under the reserved tag `0x05` stay in the
/// corpus as reject seeds: the body seed refuses by its tag, and the
/// record seed decodes as no record and classifies as refused.
#[test]
fn the_fuzz_reserved_tag_seeds_refuse() {
    let body_seed: &[u8] = include_bytes!("../../tests/vectors/authlog/seed-body-tag05");
    let Some((&tag, body)) = body_seed.split_first() else {
        panic!("the body seed is empty");
    };
    assert_eq!(tag, TAG_RESERVED_05);
    assert_eq!(
        codec::decode_record_body(tag, body, &test_volume()),
        Err(codec::RecordFieldReason::ReservedTag)
    );

    let record_seed: &[u8] = include_bytes!("../../tests/vectors/authlog/seed-refusal-record");
    assert_eq!(record_seed.first(), Some(&TAG_RESERVED_05));
    assert!(decode_record(record_seed, &test_volume()).is_none());
    assert!(classify(record_seed, &test_volume()).is_err());
}

// A different version is foreign bytes even when its v1 body decodes and
// its sequence would be illegal in this prefix. An epoch-only tail check
// would incorrectly refuse this interrupted append.
#[test]
fn foreign_version_tail_uses_generic_bound() {
    let envelope = test_envelope();
    let (decision, _) = standard_decision(&envelope, 2);
    let append = encode_append(&envelope, &decision).unwrap();
    let mut tail = append.record().to_vec();
    tail[1..3].copy_from_slice(&2_u16.to_be_bytes());
    let covered = tail.len() - 32;
    let check = blake3::derive_key(RECORD_CONTEXT, &tail[..covered]);
    tail[covered..].copy_from_slice(&check);
    assert_eq!(
        decode_record(&tail, envelope.volume()).map(|decoded| (
            decoded.version,
            decoded.epoch,
            decoded.record.seq()
        )),
        Some((2, envelope.epoch(), 2)),
        "checksum-valid v1-decodable foreign record premise"
    );
    assert_eq!(
        (tail.len() <= 4642, tail.windows(8).any(|w| w == MARK_MAGIC)),
        (true, false),
        "mark-free generic-bound premise, actual tail length {}",
        tail.len()
    );
    let mut bytes = encode_envelope(&envelope).as_bytes().to_vec();
    let committed_len = bytes.len();
    bytes.extend_from_slice(&tail);
    assert_eq!(
        bytes,
        include_bytes!("../../tests/vectors/authlog/foreign-version-tail.bin")
    );
    match classify(&bytes, envelope.volume()) {
        Ok(Classified::Log {
            records,
            committed_len: actual,
            tail_len,
            ..
        }) => assert_eq!(
            (records, actual, tail_len),
            (vec![], committed_len, tail.len())
        ),
        result => panic!("foreign version within generic bound must be discarded: {result:?}"),
    }
    tail.resize(4643, 0);
    bytes.truncate(committed_len);
    bytes.extend_from_slice(&tail);
    assert_eq!(
        classify(&bytes, envelope.volume()),
        Err(LogError {
            offset: committed_len,
            reason: LogErrorReason::DamagedCommittedHistory,
        })
    );
}

fn decision_sequence_vector(root_seq: u64) -> (Envelope, Record, Vec<u8>, Vec<u8>) {
    let envelope = test_envelope();
    let base = Some(GrainId::of(b"sequence boundary base"));
    let candidate = sample_root(envelope.volume(), root_seq, base);
    let identity = identity_of(GrainId::of(&candidate));
    let decided_at = Timestamp {
        secs: 123,
        nanos: 456,
    };
    let body = manual_decision_body(
        good_identity_bytes(identity.candidate_id()),
        root_seq,
        base,
        decided_at,
        &candidate,
    );
    let (bytes, _) = manual_record(&envelope, 1, TAG_DECISION, &body);
    let (covered, check) = bytes.split_last_chunk::<32>().unwrap();
    assert_eq!(
        *check,
        blake3::derive_key(RECORD_CONTEXT, covered),
        "checksum-valid boundary {root_seq}"
    );
    let record = Record::new(
        1,
        RecordBody::Decision {
            identity,
            root_seq,
            base,
            decided_at,
            candidate: RootBytes::new(candidate).unwrap(),
        },
    )
    .unwrap();
    (envelope, record, body, bytes)
}

#[test]
fn decision_sequence_encode_boundary() {
    assert_eq!(
        crate::authority_answer::LAST_CANDIDATE_SEQ,
        18_446_744_073_709_551_613
    );
    for seq in [18_446_744_073_709_551_613, 18_446_744_073_709_551_614] {
        let (envelope, record, _, bytes) = decision_sequence_vector(seq);
        if seq == 18_446_744_073_709_551_613 {
            assert_eq!(encode_append(&envelope, &record).unwrap().record(), bytes);
        } else {
            assert!(
                matches!(
                    encode_append(&envelope, &record),
                    Err(EncodeRecordError::RootSeqOutOfRange {
                        root_seq: 18_446_744_073_709_551_614
                    })
                ),
                "encode must reject impossible candidate sequence"
            );
        }
    }
}

#[test]
fn decision_sequence_decode_boundary() {
    for seq in [18_446_744_073_709_551_613, 18_446_744_073_709_551_614] {
        let (envelope, record, body, bytes) = decision_sequence_vector(seq);
        if seq == 18_446_744_073_709_551_613 {
            assert_eq!(
                decode_record(&bytes, envelope.volume()).unwrap().record,
                record
            );
        } else {
            assert_eq!(
                codec::decode_record_body(TAG_DECISION, &body, envelope.volume()),
                Err(codec::RecordFieldReason::RootSeqOutOfRange)
            );
            assert!(decode_record(&bytes, envelope.volume()).is_none());
        }
    }
}
