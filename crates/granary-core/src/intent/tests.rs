// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::hash::HashAlgorithm;
use crate::root::{
    ED25519_SIG_LEN, KEY_ID_LEN, RootDoc, RootSig, Timestamp, WRITER_UUID_LEN, encode_root,
};

mod epoch;
mod judge;

const VOLUME: &str = "granary-test";
const OTHER_VOLUME: &str = "other-volume";
const HIGH: u64 = 0x8000_0000_0000_0001;

fn vol(name: &str) -> VolumeName {
    VolumeName::new(name.to_owned()).unwrap()
}

/// A real, decodable root v1 for `volume`; `seed` makes distinct bytes.
/// Signatures are synthetic: core holds no cryptography, and the
/// caller-supplied step is what a test varies.
fn root_for(volume: &str, seed: u8) -> Vec<u8> {
    encode_root(&RootDoc {
        volume: vol(volume),
        seq: 1,
        parent: None,
        writer_uuid: [seed; WRITER_UUID_LEN],
        epoch: 1,
        timestamp: Timestamp {
            secs: 1_760_000_000,
            nanos: 0,
        },
        chunker_spec: crate::thresh::CHUNKER_SPEC.to_string(),
        manifest_root: GrainId::of(&[seed, 1]),
        binmap_index: GrainId::of(&[seed, 2]),
        sheaf_head: GrainId::of(&[seed, 3]),
        sigs: vec![RootSig {
            key_id: [seed; KEY_ID_LEN],
            sig: [seed ^ 0x5a; ED25519_SIG_LEN],
        }],
    })
    .unwrap()
}

fn root(seed: u8) -> Vec<u8> {
    root_for(VOLUME, seed)
}

fn writer(n: u8) -> [u8; WRITER_LEN] {
    [n; WRITER_LEN]
}

fn inst(n: u8) -> [u8; INSTANCE_LEN] {
    [n; INSTANCE_LEN]
}

/// The instance token of the process under test.
const I: u8 = 0xB1;

fn accept(_: &RootDoc, _: &[u8]) -> bool {
    true
}

fn refuse(_: &RootDoc, _: &[u8]) -> bool {
    false
}

fn id(n: u8) -> GrainId {
    GrainId::from_parts(HashAlgorithm::Blake3, [n; 32])
}

fn live(writer: [u8; WRITER_LEN], generation: u64, root_id: GrainId) -> Receipt {
    Receipt {
        epoch: 1,
        writer,
        instance: inst(I),
        generation,
        state: ReceiptState::Live {
            prepared_root_id: root_id,
        },
    }
}

fn gone(writer: [u8; WRITER_LEN], generation: u64) -> Receipt {
    Receipt {
        epoch: 1,
        writer,
        instance: inst(I),
        generation,
        state: ReceiptState::Released,
    }
}

fn readback_of(volume: &str, writers: &[u8]) -> Vec<u8> {
    let roots: Vec<Vec<u8>> = writers.iter().map(|w| root_for(volume, *w)).collect();
    let rows: Vec<ReadbackRow<'_>> = writers
        .iter()
        .zip(&roots)
        .zip(1u64..)
        .map(|((w, r), generation)| ReadbackRow {
            epoch: 1,
            writer: writer(*w),
            generation,
            root: r,
        })
        .collect();
    encode_readback(u64::MAX, &rows).unwrap()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Register,
    Release,
    Receipt,
    Readback,
    Ownership,
    Grant,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Release => "release",
            Self::Receipt => "receipt",
            Self::Readback => "readback",
            Self::Ownership => "ownership",
            Self::Grant => "grant",
        }
    }
}

/// Decode `bytes` as `kind` for the test volume; the signature step accepts
/// unless `reject_signature`. The name of the refusal, or `None` if accepted.
fn refusal(kind: Kind, bytes: &[u8], volume: &str, reject_signature: bool) -> Option<&'static str> {
    let volume = vol(volume);
    let verify = |d: &RootDoc, p: &[u8]| {
        if reject_signature {
            refuse(d, p)
        } else {
            accept(d, p)
        }
    };
    match kind {
        Kind::Register => decode_register(bytes, &volume, verify).err(),
        Kind::Release => decode_release(bytes).err(),
        Kind::Receipt => decode_receipt(bytes).err(),
        Kind::Readback => decode_readback(bytes, &volume, verify).err(),
        Kind::Ownership => decode_ownership(bytes).err(),
        Kind::Grant => decode_grant(bytes).err(),
    }
    .map(|e| e.name())
}

/// The committed accepted bodies, built independently of the codec's encoder
/// where the layout is short enough to transcribe by hand.
#[expect(
    clippy::too_many_lines,
    reason = "flat table of six carrier golden vectors"
)]
fn goldens() -> Vec<(&'static str, Kind, Vec<u8>)> {
    let r1 = root(1);
    let mut register = b"GRNINTRG\x00\x01".to_vec();
    register.extend_from_slice(&writer(0xA1));
    register.extend_from_slice(&1u64.to_be_bytes());
    register.extend_from_slice(&inst(I));
    register.extend_from_slice(&1u64.to_be_bytes());
    register.extend_from_slice(&r1);
    let mut register_high = b"GRNINTRG\x00\x01".to_vec();
    register_high.extend_from_slice(&writer(0xA1));
    register_high.extend_from_slice(&HIGH.to_be_bytes());
    register_high.extend_from_slice(&inst(I));
    register_high.extend_from_slice(&HIGH.to_be_bytes());
    register_high.extend_from_slice(&r1);
    let mut release = b"GRNINTRL\x00\x01".to_vec();
    release.extend_from_slice(&writer(0xA1));
    release.extend_from_slice(&1u64.to_be_bytes());
    release.extend_from_slice(&inst(I));
    release.extend_from_slice(&7u64.to_be_bytes());
    let mut release_high = b"GRNINTRL\x00\x01".to_vec();
    release_high.extend_from_slice(&writer(0xA1));
    release_high.extend_from_slice(&1u64.to_be_bytes());
    release_high.extend_from_slice(&inst(I));
    release_high.extend_from_slice(&HIGH.to_be_bytes());
    let mut receipt_live = b"GRNINTRC\x00\x01\x01".to_vec();
    receipt_live.extend_from_slice(&writer(0xA1));
    receipt_live.extend_from_slice(&1u64.to_be_bytes());
    receipt_live.extend_from_slice(&inst(I));
    receipt_live.extend_from_slice(&HIGH.to_be_bytes());
    receipt_live.extend_from_slice(&id(0x22).to_bytes());
    let mut receipt_released = b"GRNINTRC\x00\x01\x02".to_vec();
    receipt_released.extend_from_slice(&writer(0xA1));
    receipt_released.extend_from_slice(&1u64.to_be_bytes());
    receipt_released.extend_from_slice(&inst(I));
    receipt_released.extend_from_slice(&7u64.to_be_bytes());
    let acquire = Ownership {
        writer: writer(0xA1),
        instance: inst(I),
        mode: OwnershipMode::Acquire {
            observed_cursor: HIGH,
        },
    };
    let takeover = |state| Ownership {
        writer: writer(0xA1),
        instance: inst(I),
        mode: OwnershipMode::Takeover {
            expected_epoch: HIGH,
            generation: if state == ReceiptState::Released {
                0
            } else {
                HIGH
            },
            state,
            recovery_ack: true,
        },
    };
    let grant = |req: Ownership| Grant {
        request_id: GrainId::of(&encode_ownership(req).unwrap()),
        receipt: Receipt {
            writer: req.writer,
            instance: req.instance,
            epoch: HIGH + 1,
            generation: match req.mode {
                OwnershipMode::Acquire { .. } => 0,
                OwnershipMode::Takeover { generation, .. } => generation,
            },
            state: match req.mode {
                OwnershipMode::Acquire { .. } => ReceiptState::Released,
                OwnershipMode::Takeover { state, .. } => state,
            },
        },
    };
    let live = takeover(ReceiptState::Live {
        prepared_root_id: id(9),
    });
    vec![
        (
            "ownership-acquire",
            Kind::Ownership,
            encode_ownership(acquire).unwrap(),
        ),
        (
            "ownership-takeover-released",
            Kind::Ownership,
            encode_ownership(takeover(ReceiptState::Released)).unwrap(),
        ),
        (
            "ownership-takeover-live",
            Kind::Ownership,
            encode_ownership(live).unwrap(),
        ),
        (
            "grant-released",
            Kind::Grant,
            encode_grant(grant(acquire)).unwrap(),
        ),
        (
            "grant-live",
            Kind::Grant,
            encode_grant(grant(live)).unwrap(),
        ),
        (
            "receipt-released-zero",
            Kind::Receipt,
            encode_receipt(gone(writer(1), 0)).unwrap(),
        ),
        ("register", Kind::Register, register),
        ("register-high-generation", Kind::Register, register_high),
        ("release", Kind::Release, release),
        ("release-high-generation", Kind::Release, release_high),
        ("receipt-live", Kind::Receipt, receipt_live),
        ("receipt-released", Kind::Receipt, receipt_released),
        ("readback-empty", Kind::Readback, readback_header(0)),
        ("readback-one", Kind::Readback, readback_of(VOLUME, &[3])),
        ("readback-high-epoch", Kind::Readback, {
            let mut b = readback_of(VOLUME, &[3]);
            b[36..44].copy_from_slice(&HIGH.to_be_bytes());
            b
        }),
        (
            "readback-three",
            Kind::Readback,
            readback_of(VOLUME, &[2, 5, 9]),
        ),
    ]
}

/// A header-only readback claiming `count` rows.
fn readback_header(count: u16) -> Vec<u8> {
    let mut out = b"GRNINTRB\x00\x01".to_vec();
    out.extend_from_slice(&u64::MAX.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    out
}

/// One readback row written by hand, so a reject can break one field of it.
fn raw_row(writer_byte: u8, generation: u64, root_len: u32, root: &[u8]) -> Vec<u8> {
    let mut out = writer(writer_byte).to_vec();
    out.extend_from_slice(&1u64.to_be_bytes());
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(&root_len.to_be_bytes());
    out.extend_from_slice(root);
    out
}

fn with_header(count: u16, rows: &[Vec<u8>]) -> Vec<u8> {
    let mut out = readback_header(count);
    for row in rows {
        out.extend_from_slice(row);
    }
    out
}

fn envelope(magic: [u8; 8], version: u16, writer_byte: u8, generation: u64) -> Vec<u8> {
    let mut out = magic.to_vec();
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&writer(writer_byte));
    out.extend_from_slice(&1u64.to_be_bytes());
    out.extend_from_slice(&inst(I));
    out.extend_from_slice(&generation.to_be_bytes());
    out
}

/// Every reject vector: `(file, kind, bytes)`. The refusal a file must give is
/// the longest `Error` name its file name starts with after `reject-<kind>-`.
#[expect(clippy::too_many_lines, reason = "a flat table of reject vectors")]
fn rejects() -> Vec<(String, Kind, Vec<u8>)> {
    use Kind::{Readback, Receipt, Register, Release};
    let r1 = root(1);
    let r2 = root(2);
    let mut v: Vec<(String, Kind, Vec<u8>)> = Vec::new();
    let mut add = |name: &str, kind: Kind, bytes: Vec<u8>| {
        v.push((format!("reject-{}-{name}", kind.label()), kind, bytes));
    };

    // registration
    let reg = |generation: u64, tail: &[u8]| {
        let mut b = envelope(REGISTER_MAGIC, 1, 0xA1, generation);
        b.extend_from_slice(tail);
        b
    };
    let mut over = reg(1, &r1);
    over.resize(REGISTER_MAX_BYTES + 1, 0);
    add("over-bound", Register, over);
    add("short-input", Register, REGISTER_MAGIC[..7].to_vec());
    add(
        "bad-magic-release",
        Register,
        envelope(RELEASE_MAGIC, 1, 0xA1, 1),
    );
    add("unknown-version-0", Register, {
        let mut b = reg(1, &r1);
        b[8..10].copy_from_slice(&0u16.to_be_bytes());
        b
    });
    add("unknown-version-2", Register, {
        let mut b = reg(1, &r1);
        b[8..10].copy_from_slice(&2u16.to_be_bytes());
        b
    });
    add("truncated-instance", Register, reg(1, &[])[..30].to_vec());
    add("truncated-generation", Register, reg(1, &[])[..46].to_vec());
    add("generation-zero", Register, reg(0, &r1));
    add("generation-max", Register, reg(u64::MAX, &r1));
    add("root-empty", Register, reg(1, &[]));
    add("root-invalid-trailing", Register, {
        let mut tail = r1.clone();
        tail.push(0);
        reg(1, &tail)
    });
    add("root-invalid-garbage", Register, reg(1, b"not a root"));
    add(
        "root-wrong-volume",
        Register,
        reg(1, &root_for(OTHER_VOLUME, 1)),
    );
    add("root-bad-signature", Register, reg(1, &r1));

    // release
    let rel = |generation: u64| envelope(RELEASE_MAGIC, 1, 0xA1, generation);
    let mut over = rel(1);
    over.push(0);
    add("over-bound", Release, over);
    add("short-input", Release, RELEASE_MAGIC[..7].to_vec());
    add(
        "bad-magic-receipt",
        Release,
        envelope(RECEIPT_MAGIC, 1, 0xA1, 1),
    );
    add(
        "unknown-version-0",
        Release,
        envelope(RELEASE_MAGIC, 0, 0xA1, 1),
    );
    add(
        "unknown-version-2",
        Release,
        envelope(RELEASE_MAGIC, 2, 0xA1, 1),
    );
    add("truncated-instance", Release, rel(1)[..30].to_vec());
    add("truncated-generation", Release, rel(1)[..49].to_vec());
    add("generation-zero", Release, rel(0));
    add("generation-max", Release, rel(u64::MAX));

    // receipt
    let rec = |state: u8, generation: u64, tail: &[u8]| {
        let mut b = RECEIPT_MAGIC.to_vec();
        b.extend_from_slice(&1u16.to_be_bytes());
        b.push(state);
        b.extend_from_slice(&writer(0xA1));
        b.extend_from_slice(&1u64.to_be_bytes());
        b.extend_from_slice(&inst(I));
        b.extend_from_slice(&generation.to_be_bytes());
        b.extend_from_slice(tail);
        b
    };
    let tail = id(0x22).to_bytes();
    let mut over = rec(1, 7, &tail);
    over.push(0);
    add("over-bound", Receipt, over);
    add("short-input", Receipt, RECEIPT_MAGIC[..7].to_vec());
    add("bad-magic-readback", Receipt, readback_header(0));
    add("unknown-version-0", Receipt, {
        let mut b = rec(1, 7, &tail);
        b[8..10].copy_from_slice(&0u16.to_be_bytes());
        b
    });
    add("unknown-version-2", Receipt, {
        let mut b = rec(1, 7, &tail);
        b[8..10].copy_from_slice(&2u16.to_be_bytes());
        b
    });
    add(
        "truncated-root-id",
        Receipt,
        rec(1, 7, &tail)[..83].to_vec(),
    );
    add("truncated-instance", Receipt, rec(2, 7, &[])[..30].to_vec());
    add(
        "truncated-state",
        Receipt,
        RECEIPT_MAGIC.iter().chain(&[0, 1]).copied().collect(),
    );
    add("bad-state-0", Receipt, rec(0, 7, &tail));
    add("bad-state-3", Receipt, rec(3, 7, &tail));
    add("bad-snapshot-generation", Receipt, rec(1, 0, &tail));
    add(
        "bad-snapshot-generation-max",
        Receipt,
        rec(2, u64::MAX, &[]),
    );
    add("bad-grain-id-tag-0", Receipt, {
        let mut t = tail;
        t[0] = 0;
        rec(1, 7, &t)
    });
    add("bad-grain-id-tag-unregistered", Receipt, {
        let mut t = tail;
        t[0] = 0x7f;
        rec(1, 7, &t)
    });
    add(
        "trailing-bytes-released-with-root-id",
        Receipt,
        rec(2, 7, &tail),
    );
    add("trailing-bytes-released-plus-one", Receipt, rec(2, 7, &[0]));

    // readback
    let row = |w: u8, root: &[u8]| raw_row(w, 1, u32::try_from(root.len()).unwrap(), root);
    let one = with_header(1, &[row(3, &r1)]);
    add("short-input", Readback, READBACK_MAGIC[..7].to_vec());
    add(
        "bad-magic-register",
        Readback,
        envelope(REGISTER_MAGIC, 1, 0xA1, 1),
    );
    add("unknown-version-0", Readback, {
        let mut b = one.clone();
        b[8..10].copy_from_slice(&0u16.to_be_bytes());
        b
    });
    add("unknown-version-2", Readback, {
        let mut b = one.clone();
        b[8..10].copy_from_slice(&2u16.to_be_bytes());
        b
    });
    add(
        "truncated-count",
        Readback,
        READBACK_MAGIC.iter().chain(&[0, 1, 0]).copied().collect(),
    );
    add("truncated-mid-row", Readback, one[..one.len() - 1].to_vec());
    add("count-over-ceiling", Readback, readback_header(17));
    add("count-mismatch-no-rows", Readback, readback_header(1));
    add(
        "count-mismatch-two-of-three",
        Readback,
        with_header(3, &[row(1, &r1), row(2, &r2)]),
    );
    add(
        "rows-unsorted",
        Readback,
        with_header(2, &[row(5, &r1), row(2, &r2)]),
    );
    add(
        "rows-duplicate",
        Readback,
        with_header(2, &[row(5, &r1), row(5, &r2)]),
    );
    add(
        "generation-zero",
        Readback,
        with_header(1, &[raw_row(3, 0, u32::try_from(r1.len()).unwrap(), &r1)]),
    );
    add(
        "generation-max",
        Readback,
        with_header(
            1,
            &[raw_row(3, u64::MAX, u32::try_from(r1.len()).unwrap(), &r1)],
        ),
    );
    add(
        "root-empty",
        Readback,
        with_header(1, &[raw_row(3, 1, 0, &[])]),
    );
    add(
        "root-too-long",
        Readback,
        with_header(1, &[raw_row(3, 1, 65_537, &[])]),
    );
    add(
        "root-invalid-garbage",
        Readback,
        with_header(1, &[row(3, b"not a root")]),
    );
    add("root-invalid-trailing", Readback, {
        let mut root = r1.clone();
        root.push(0);
        with_header(1, &[row(3, &root)])
    });
    add(
        "root-wrong-volume",
        Readback,
        with_header(1, &[row(3, &root_for(OTHER_VOLUME, 1))]),
    );
    add("root-bad-signature", Readback, one.clone());
    add("trailing-bytes", Readback, {
        let mut b = one;
        b.push(0);
        b
    });
    add("trailing-bytes-empty", Readback, {
        let mut b = readback_header(0);
        b.push(0);
        b
    });
    // New guard fixtures, each with a valid golden as its positive control.
    let acquire = encode_ownership(Ownership {
        writer: writer(1),
        instance: inst(I),
        mode: OwnershipMode::Acquire { observed_cursor: 0 },
    })
    .unwrap();
    add("bad-ownership-mode", Kind::Ownership, {
        let mut b = acquire;
        b[10] = 3;
        b
    });
    let takeover = encode_ownership(Ownership {
        writer: writer(1),
        instance: inst(I),
        mode: OwnershipMode::Takeover {
            expected_epoch: 1,
            generation: 0,
            state: ReceiptState::Released,
            recovery_ack: true,
        },
    })
    .unwrap();
    add("bad-recovery-ack", Kind::Ownership, {
        let mut b = takeover.clone();
        *b.last_mut().unwrap() = 2;
        b
    });
    add("epoch-zero", Kind::Ownership, {
        let mut b = takeover;
        b[43..51].fill(0);
        b
    });
    add("epoch-past-cursor", Readback, {
        let mut b = readback_of(VOLUME, &[1]);
        b[10..18].fill(0);
        b
    });
    v
}

fn vectors_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// The refusal a reject file must give, from its name.
fn expected_refusal(file: &str) -> &'static str {
    let rest = file
        .strip_prefix("reject-")
        .and_then(|r| r.split_once('-'))
        .map(|(_, rest)| rest)
        .unwrap();
    ALL_REFUSALS
        .iter()
        .copied()
        .find(|name| rest.starts_with(name))
        .unwrap_or_else(|| panic!("{file} names no refusal"))
}

const ALL_REFUSALS: [&str; 24] = [
    "over-bound",
    "short-input",
    "bad-magic",
    "unknown-version",
    "truncated",
    "trailing-bytes",
    "generation-zero",
    "generation-max",
    "epoch-zero",
    "epoch-past-cursor",
    "bad-ownership-mode",
    "bad-recovery-ack",
    "bad-snapshot-generation",
    "bad-state",
    "bad-grain-id-tag",
    "root-invalid",
    "root-too-long",
    "root-empty",
    "count-over-ceiling",
    "count-mismatch",
    "rows-unsorted",
    "rows-duplicate",
    "root-wrong-volume",
    "root-bad-signature",
];

/// Regenerates the committed vectors and the fuzz corpus seeds from the
/// definitions above. Run by hand after a deliberate format change.
#[test]
#[ignore = "rewrites the committed vectors"]
fn write_vectors() {
    let dir = vectors_dir();
    let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/intent_decode");
    for sub in ["intent", "intent-rejects"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    std::fs::create_dir_all(&corpus).unwrap();
    let seed = |bytes: &[u8]| {
        let name = GrainId::of(bytes).to_string().replace("blake3:", "");
        std::fs::write(corpus.join(&name[..40]), bytes).unwrap();
    };
    for (name, _, bytes) in goldens() {
        std::fs::write(dir.join(format!("intent/{name}.bin")), &bytes).unwrap();
        std::fs::write(
            dir.join(format!("intent/{name}.hash")),
            format!("{}\n", GrainId::of(&bytes)),
        )
        .unwrap();
        seed(&bytes);
    }
    for (name, _, bytes) in rejects() {
        if bytes.len() <= 1 << 16 {
            std::fs::write(dir.join(format!("intent-rejects/{name}")), &bytes).unwrap();
            seed(&bytes);
        }
    }
}

#[test]
fn constants_are_pinned() {
    assert_eq!(REGISTER_MAGIC, *b"GRNINTRG");
    assert_eq!(RELEASE_MAGIC, *b"GRNINTRL");
    assert_eq!(RECEIPT_MAGIC, *b"GRNINTRC");
    assert_eq!(READBACK_MAGIC, *b"GRNINTRB");
    assert_eq!(OWNERSHIP_MAGIC, *b"GRNINTOW");
    assert_eq!(GRANT_MAGIC, *b"GRNINTGR");
    assert_eq!(ACQUIRE_BYTES, 51);
    assert_eq!(TAKEOVER_RELEASED_BYTES, 61);
    assert_eq!(OWNERSHIP_MAX_BYTES, 94);
    assert_eq!(GRANT_RELEASED_BYTES, 92);
    assert_eq!(GRANT_MAX_BYTES, 125);
    assert_eq!(
        MEDIA_OWNERSHIP,
        "application/vnd.granary.intent-ownership.v1"
    );
    assert_eq!(MEDIA_GRANT, "application/vnd.granary.intent-grant.v1");
    assert_eq!(VERSION, 1);
    assert_eq!(MEDIA_REGISTER, "application/vnd.granary.intent-register.v1");
    assert_eq!(MEDIA_RELEASE, "application/vnd.granary.intent-release.v1");
    assert_eq!(MEDIA_RECEIPT, "application/vnd.granary.intent-receipt.v1");
    assert_eq!(MEDIA_READBACK, "application/vnd.granary.intent-readback.v1");
    assert_eq!(WRITER_LEN, 16);
    assert_eq!(INSTANCE_LEN, 16);
    assert_eq!(ROOT_CAP, 65_536);
    assert_eq!(ENVELOPE_LEN, 58);
    assert_eq!(REGISTER_MAX_BYTES, 65_594);
    assert_eq!(RELEASE_BYTES, 58);
    assert_eq!(RECEIPT_RELEASED_BYTES, 59);
    assert_eq!(RECEIPT_LIVE_BYTES, 92);
    assert_eq!(RECEIPT_MAX_BYTES, 92);
    assert_eq!(MAX_LIVE_ROWS, 16);
    assert_eq!(MAX_TOTAL_ROWS, 64);
    assert_eq!(MAX_ROOT_BYTES, 1_048_576);
    assert_eq!(READBACK_HEADER_LEN, 20);
    assert_eq!(READBACK_ROW_OVERHEAD, 36);
    assert_eq!(READBACK_MAX_BYTES, 1_049_172);
    assert_eq!(RETRANSMIT_HORIZON_SECS, 86_400);
}

/// A maximal v1 root is far under the cap the bounds are derived from.
#[test]
fn the_ceilings_derive_from_the_root_cap_not_the_maximal_root() {
    assert_eq!(
        MAX_ROOT_BYTES as u64,
        MAX_LIVE_ROWS as u64 * root::ROOT_MAX_BYTES
    );
    const { assert!(root::ROOT_V1_MAX_ENCODABLE < ROOT_CAP / MAX_LIVE_ROWS) };
    const { assert!(MAX_LIVE_ROWS <= MAX_TOTAL_ROWS) };
}

/// A released row is kept for the longer of the grace and the horizon, and
/// for no other reason: there is no floor.
#[test]
fn a_released_row_is_kept_for_the_longer_of_grace_and_horizon() {
    assert_eq!(released_row_retention_secs(0), 86_400);
    assert_eq!(released_row_retention_secs(86_399), 86_400);
    assert_eq!(released_row_retention_secs(RETRANSMIT_HORIZON_SECS), 86_400);
    assert_eq!(released_row_retention_secs(86_401), 86_401);
    assert_eq!(released_row_retention_secs(7 * 86_400), 7 * 86_400);
    assert_eq!(released_row_retention_secs(30 * 86_400), 30 * 86_400);
    assert_eq!(released_row_retention_secs(u64::MAX), u64::MAX);
}

#[test]
fn goldens_match_the_committed_vectors_and_round_trip() {
    let goldens = goldens();
    assert!(goldens.len() >= 9);
    let dir = vectors_dir().join("intent");
    for (name, kind, bytes) in &goldens {
        let committed = std::fs::read(dir.join(format!("{name}.bin"))).unwrap();
        assert_eq!(&committed, bytes, "{name}: committed bytes");
        let hash = std::fs::read_to_string(dir.join(format!("{name}.hash"))).unwrap();
        assert_eq!(GrainId::of(bytes).to_string(), hash.trim(), "{name}: hash");
        assert_eq!(
            refusal(*kind, bytes, VOLUME, false),
            None,
            "{name}: accepts"
        );
        let again = match kind {
            Kind::Register => {
                let r = decode_register(bytes, &vol(VOLUME), accept).unwrap();
                encode_register(&r.writer, r.epoch, &r.instance, r.generation, r.root).unwrap()
            }
            Kind::Ownership => encode_ownership(decode_ownership(bytes).unwrap()).unwrap(),
            Kind::Grant => encode_grant(decode_grant(bytes).unwrap()).unwrap(),
            Kind::Release => encode_release(decode_release(bytes).unwrap()).unwrap(),
            Kind::Receipt => encode_receipt(decode_receipt(bytes).unwrap()).unwrap(),
            Kind::Readback => {
                let r = decode_readback(bytes, &vol(VOLUME), accept).unwrap();
                encode_readback(r.cursor, &r.rows).unwrap()
            }
        };
        assert_eq!(&again, bytes, "{name}: canonical re-encode");
        for n in 0..bytes.len() {
            assert!(
                refusal(*kind, &bytes[..n], VOLUME, false).is_some(),
                "{name}: prefix of {n} bytes accepted"
            );
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(
            refusal(*kind, &longer, VOLUME, false).is_some(),
            "{name}: one trailing byte accepted"
        );
    }
}

/// The wrong implementation reads the generation signed or little-endian.
#[test]
fn a_generation_with_the_high_bit_set_reads_big_endian_unsigned() {
    let goldens = goldens();
    let get = |name: &str| goldens.iter().find(|g| g.0 == name).unwrap().2.clone();
    let register = get("register-high-generation");
    assert_eq!(register[50..58], [0x80, 0, 0, 0, 0, 0, 0, 1]);
    let r = decode_register(&register, &vol(VOLUME), accept).unwrap();
    assert_eq!(r.generation, HIGH);
    assert!(r.generation > 1);
    let release = decode_release(&get("release-high-generation")).unwrap();
    assert_eq!(release.generation, HIGH);
    let receipt = decode_receipt(&get("receipt-live")).unwrap();
    assert_eq!(receipt.generation, HIGH);
    assert_eq!(
        receipt.state,
        ReceiptState::Live {
            prepared_root_id: id(0x22)
        }
    );
}

#[test]
fn reject_vectors_match_their_names_and_the_definitions() {
    let dir = vectors_dir().join("intent-rejects");
    let mut cases = 0;
    let mut seen = std::collections::BTreeSet::new();
    for (file, kind, bytes) in rejects() {
        let name = expected_refusal(&file);
        seen.insert(name);
        let reject_signature = name == "root-bad-signature";
        let got = refusal(kind, &bytes, VOLUME, reject_signature);
        assert_eq!(got, Some(name), "{file}");
        if bytes.len() <= 1 << 16 {
            let committed = std::fs::read(dir.join(&file)).unwrap();
            assert_eq!(committed, bytes, "{file}: committed bytes");
        }
        // Positive controls: the two refusals the caller drives accept once
        // the volume or the signature step agrees.
        if reject_signature {
            assert_eq!(
                refusal(kind, &bytes, VOLUME, false),
                None,
                "{file}: control"
            );
        }
        if name == "root-wrong-volume" {
            assert_eq!(
                refusal(kind, &bytes, OTHER_VOLUME, false),
                None,
                "{file}: control"
            );
        }
        cases += 1;
    }
    assert!(cases >= 50, "only {cases} reject vectors");
    for name in ALL_REFUSALS {
        assert!(seen.contains(name), "no reject vector for {name}");
    }
    let files = std::fs::read_dir(&dir).unwrap().count();
    assert_eq!(
        files,
        rejects().iter().filter(|r| r.2.len() <= 1 << 16).count()
    );
}

#[test]
fn error_names_are_unique_and_listed() {
    let errors = [
        Error::OverBound,
        Error::ShortInput,
        Error::BadMagic,
        Error::UnknownVersion(0),
        Error::Truncated,
        Error::TrailingBytes,
        Error::GenerationZero,
        Error::GenerationMax,
        Error::EpochZero,
        Error::EpochPastCursor,
        Error::BadOwnershipMode(0),
        Error::BadRecoveryAck(2),
        Error::BadSnapshotGeneration,
        Error::BadState(0),
        Error::BadGrainIdTag,
        Error::RootInvalid(DecodeError::Truncated),
        Error::RootTooLong,
        Error::RootEmpty,
        Error::CountOverCeiling,
        Error::CountMismatch,
        Error::RowsUnsorted,
        Error::RowsDuplicate,
        Error::RootWrongVolume,
        Error::RootBadSignature,
    ];
    let names: Vec<&str> = errors.iter().map(Error::name).collect();
    assert_eq!(names, ALL_REFUSALS);
}

/// The body bound is applied to the counted bytes and before any parse; the
/// boundary is exact.
#[test]
fn body_bounds_are_exact_and_checked_first() {
    // A register body at the maximum is past the bound check (it then fails as
    // an invalid root); one byte more is over it.
    let at = |len: usize| {
        let mut b = envelope(REGISTER_MAGIC, 1, 1, 1);
        b.resize(len, 0);
        b
    };
    assert_eq!(
        refusal(Kind::Register, &at(REGISTER_MAX_BYTES), VOLUME, false),
        Some("root-invalid")
    );
    assert_eq!(
        refusal(Kind::Register, &at(REGISTER_MAX_BYTES + 1), VOLUME, false),
        Some("over-bound")
    );
    // Over the bound wins over a bad magic: nothing else is looked at.
    assert_eq!(
        refusal(
            Kind::Register,
            &vec![0xFF; REGISTER_MAX_BYTES + 1],
            VOLUME,
            false
        ),
        Some("over-bound")
    );
    // Receipt and release are exact sizes.
    let mut rel = envelope(RELEASE_MAGIC, 1, 1, 1);
    assert_eq!(refusal(Kind::Release, &rel, VOLUME, false), None);
    rel.push(0);
    assert_eq!(
        refusal(Kind::Release, &rel, VOLUME, false),
        Some("over-bound")
    );
    // A readback at the maximum passes the bound; one more byte is over it.
    let readback = |len: usize| {
        let mut b = readback_header(0);
        b.resize(len, 0);
        b
    };
    assert_eq!(
        refusal(Kind::Readback, &readback(READBACK_MAX_BYTES), VOLUME, false),
        Some("trailing-bytes")
    );
    assert_eq!(
        refusal(
            Kind::Readback,
            &readback(READBACK_MAX_BYTES + 1),
            VOLUME,
            false
        ),
        Some("over-bound")
    );
}

/// The live-row ceiling: 16 rows decode, 17 refuse before any row is read.
#[test]
fn the_live_row_ceiling_is_16() {
    let writers: Vec<u8> = (1..=16).collect();
    let body = readback_of(VOLUME, &writers);
    let r = decode_readback(&body, &vol(VOLUME), accept).unwrap();
    assert_eq!(r.rows.len(), 16);
    assert!(body.len() <= READBACK_MAX_BYTES);
    assert_eq!(
        refusal(Kind::Readback, &readback_header(17), VOLUME, false),
        Some("count-over-ceiling")
    );
    let rows: Vec<ReadbackRow<'_>> = (0..17)
        .map(|n| ReadbackRow {
            epoch: 1,
            writer: writer(n + 1),
            generation: 1,
            root: &[],
        })
        .collect();
    assert_eq!(
        encode_readback(u64::MAX, &rows),
        Err(Error::CountOverCeiling)
    );
}

/// The caller's step is called once per row, with the signed prefix of the
/// received bytes, and only after the whole body parsed.
#[test]
fn the_signature_step_gets_the_received_signed_prefix_once_per_row() {
    let body = readback_of(VOLUME, &[2, 5, 9]);
    let mut seen: Vec<(u8, usize)> = Vec::new();
    let r = decode_readback(&body, &vol(VOLUME), |doc, prefix| {
        seen.push((doc.writer_uuid[0], prefix.len()));
        true
    })
    .unwrap();
    assert_eq!(seen.len(), 3);
    for (row, (w, len)) in r.rows.iter().zip(&seen) {
        let expect = root::signed_prefix(row.root).unwrap().len();
        assert_eq!((row.writer[0], expect), (*w, *len));
        assert!(*len < row.root.len());
    }
    // The prefix is a subslice of the received bytes: its pointer lies inside.
    let mut inside = false;
    decode_readback(&body, &vol(VOLUME), |_, prefix| {
        let start = body.as_ptr() as usize;
        let at = prefix.as_ptr() as usize;
        inside = at >= start && at + prefix.len() <= start + body.len();
        true
    })
    .unwrap();
    assert!(inside);

    // Structure is judged before any signature is asked for.
    let mut calls = 0;
    let wrong = {
        let a = root(1);
        let b = root_for(OTHER_VOLUME, 2);
        with_header(
            2,
            &[
                raw_row(1, 1, u32::try_from(a.len()).unwrap(), &a),
                raw_row(2, 1, u32::try_from(b.len()).unwrap(), &b),
            ],
        )
    };
    let got = decode_readback(&wrong, &vol(VOLUME), |_, _| {
        calls += 1;
        true
    });
    assert_eq!(got, Err(Error::RootWrongVolume));
    assert_eq!(calls, 0, "a signature was checked before the body parsed");

    // One refused row fails the whole body, and it is the first refused row.
    let mut order = Vec::new();
    let got = decode_readback(&body, &vol(VOLUME), |doc, _| {
        order.push(doc.writer_uuid[0]);
        doc.writer_uuid[0] != 5
    });
    assert_eq!(got, Err(Error::RootBadSignature));
    assert_eq!(order, [2, 5]);
}

#[test]
fn register_signature_step_is_called_with_the_received_prefix() {
    let r = root(1);
    let body = encode_register(&writer(1), 1, &inst(I), 1, &r).unwrap();
    let mut got = None;
    decode_register(&body, &vol(VOLUME), |doc, prefix| {
        got = Some((doc.volume.as_str().to_owned(), prefix.to_vec()));
        true
    })
    .unwrap();
    let (volume, prefix) = got.unwrap();
    assert_eq!(volume, VOLUME);
    assert_eq!(prefix, root::signed_prefix(&r).unwrap());
    assert_eq!(
        decode_register(&body, &vol(VOLUME), refuse),
        Err(Error::RootBadSignature)
    );
}

/// The prepared root id is the id of the exact received bytes.
#[test]
fn the_prepared_root_id_is_the_id_of_the_received_bytes() {
    let r = root(1);
    let body = encode_register(&writer(1), 1, &inst(I), 3, &r).unwrap();
    let decoded = decode_register(&body, &vol(VOLUME), accept).unwrap();
    assert_eq!(decoded.root, r.as_slice());
    assert_eq!(decoded.root_id(), GrainId::of(&r));
    let rb = readback_of(VOLUME, &[4]);
    let rows = decode_readback(&rb, &vol(VOLUME), accept).unwrap();
    assert_eq!(rows.rows[0].root_id(), GrainId::of(&root(4)));
}

#[test]
fn row_order_has_one_name_per_input() {
    let (a, b) = (root(1), root(2));
    let row = |w: u8, r: &[u8]| raw_row(w, 1, u32::try_from(r.len()).unwrap(), r);
    for (rows, name) in [
        (vec![row(2, &a), row(2, &b)], "rows-duplicate"),
        (vec![row(3, &a), row(2, &b)], "rows-unsorted"),
        (vec![row(2, &a), row(3, &b)], ""),
    ] {
        let got = refusal(Kind::Readback, &with_header(2, &rows), VOLUME, false);
        assert_eq!(got, (!name.is_empty()).then_some(name));
    }
    // Ordering is memcmp over the writer bytes, so the first differing byte decides.
    let low = {
        let mut w = [0u8; WRITER_LEN];
        w[15] = 0xFF;
        w
    };
    let high = {
        let mut w = [0u8; WRITER_LEN];
        w[0] = 1;
        w
    };
    let rows = [
        ReadbackRow {
            epoch: 1,
            writer: low,
            generation: 1,
            root: &a,
        },
        ReadbackRow {
            epoch: 1,
            writer: high,
            generation: 1,
            root: &b,
        },
    ];
    assert!(encode_readback(u64::MAX, &rows).is_ok());
    let rows = [rows[1], rows[0]];
    assert_eq!(encode_readback(u64::MAX, &rows), Err(Error::RowsUnsorted));
}

/// Every encoder refuses what its decoder refuses without a request.
#[test]
fn encoders_refuse_what_decoders_reject() {
    let r = root(1);
    assert_eq!(
        encode_register(&writer(1), 1, &inst(I), 0, &r),
        Err(Error::GenerationZero)
    );
    assert_eq!(
        encode_register(&writer(1), 1, &inst(I), u64::MAX, &r),
        Err(Error::GenerationMax)
    );
    assert_eq!(
        encode_register(&writer(1), 1, &inst(I), 1, &[]),
        Err(Error::RootEmpty)
    );
    assert!(matches!(
        encode_register(&writer(1), 1, &inst(I), 1, b"nope"),
        Err(Error::RootInvalid(_))
    ));
    let mut trailing = r.clone();
    trailing.push(0);
    assert!(matches!(
        encode_register(&writer(1), 1, &inst(I), 1, &trailing),
        Err(Error::RootInvalid(_))
    ));
    assert_eq!(
        encode_register(&writer(1), 1, &inst(I), 1, &vec![0; ROOT_CAP + 1]),
        Err(Error::RootTooLong)
    );
    assert_eq!(
        encode_release(Release {
            epoch: 1,
            writer: writer(1),
            instance: inst(I),
            generation: 0
        }),
        Err(Error::GenerationZero)
    );
    assert_eq!(
        encode_release(Release {
            epoch: 1,
            writer: writer(1),
            instance: inst(I),
            generation: u64::MAX
        }),
        Err(Error::GenerationMax)
    );
    assert_eq!(
        encode_receipt(live(writer(1), 0, id(1))),
        Err(Error::BadSnapshotGeneration)
    );
    assert_eq!(
        encode_receipt(live(writer(1), u64::MAX, id(1))),
        Err(Error::BadSnapshotGeneration)
    );
    let row = |generation: u64, root: &'static [u8]| ReadbackRow {
        epoch: 1,
        writer: writer(1),
        generation,
        root,
    };
    assert_eq!(
        encode_readback(u64::MAX, &[row(0, &[])]),
        Err(Error::GenerationZero)
    );
    assert_eq!(
        encode_readback(u64::MAX, &[row(u64::MAX, &[])]),
        Err(Error::GenerationMax)
    );
    assert_eq!(
        encode_readback(u64::MAX, &[row(1, &[])]),
        Err(Error::RootEmpty)
    );
    let dup = [
        ReadbackRow {
            epoch: 1,
            writer: writer(1),
            generation: 1,
            root: &r,
        },
        ReadbackRow {
            epoch: 1,
            writer: writer(1),
            generation: 2,
            root: &r,
        },
    ];
    assert_eq!(encode_readback(u64::MAX, &dup), Err(Error::RowsDuplicate));
}

#[test]
fn the_empty_readback_is_twenty_bytes_and_a_success() {
    let body = encode_readback(u64::MAX, &[]).unwrap();
    assert_eq!(body.len(), READBACK_HEADER_LEN);
    let got = decode_readback(&body, &vol(VOLUME), refuse).unwrap();
    assert!(got.rows.is_empty());
}

/// A receipt's state decides whether a root id follows.
#[test]
fn the_receipt_state_and_the_root_id_travel_together() {
    let live_bytes = encode_receipt(live(writer(1), 5, id(9))).unwrap();
    let released_bytes = encode_receipt(gone(writer(1), 5)).unwrap();
    assert_eq!(live_bytes.len(), RECEIPT_LIVE_BYTES);
    assert_eq!(released_bytes.len(), RECEIPT_RELEASED_BYTES);
    assert_eq!(
        decode_receipt(&live_bytes).unwrap(),
        live(writer(1), 5, id(9))
    );
    assert_eq!(decode_receipt(&released_bytes).unwrap(), gone(writer(1), 5));
    // Flip the state byte: the id is then missing, or unexpected.
    let mut as_released = live_bytes.clone();
    as_released[10] = 0x02;
    assert_eq!(decode_receipt(&as_released), Err(Error::TrailingBytes));
    let mut as_live = released_bytes;
    as_live[10] = 0x01;
    assert_eq!(decode_receipt(&as_live), Err(Error::Truncated));
}

#[test]
fn every_body_refuses_every_other_bodys_magic() {
    let goldens = goldens();
    for (name_a, kind_a, bytes_a) in &goldens {
        for (name_b, kind_b, _) in &goldens {
            if kind_a == kind_b {
                continue;
            }
            // Present `a`'s bytes to `b`'s decoder: the bound comes first, then the magic.
            let max = match kind_b {
                Kind::Register => REGISTER_MAX_BYTES,
                Kind::Release => RELEASE_BYTES,
                Kind::Receipt => RECEIPT_MAX_BYTES,
                Kind::Readback => READBACK_MAX_BYTES,
                Kind::Ownership => OWNERSHIP_MAX_BYTES,
                Kind::Grant => GRANT_MAX_BYTES,
            };
            let want = if bytes_a.len() > max {
                "over-bound"
            } else {
                "bad-magic"
            };
            assert_eq!(
                refusal(*kind_b, bytes_a, VOLUME, false),
                Some(want),
                "{name_a} accepted by the {name_b} decoder"
            );
        }
    }
}

/// The instance token sits after the writer in every body that carries it,
/// and a decoder returns exactly those 16 bytes: the wrong implementation
/// drops the field, reads it from the writer's bytes, or reorders the two.
#[test]
fn the_epoch_then_instance_follow_the_writer_in_each_body() {
    let r = root(1);
    let (w, i) = (writer(0xA1), inst(0xC3));

    let reg = encode_register(&w, 1, &i, 9, &r).unwrap();
    assert_eq!(reg[10..26], w);
    assert_eq!(reg[34..50], i);
    assert_eq!(reg[50..58], 9u64.to_be_bytes());
    let got = decode_register(&reg, &vol(VOLUME), accept).unwrap();
    assert_eq!((got.writer, got.instance, got.generation), (w, i, 9));

    let rel = encode_release(Release {
        epoch: 1,
        writer: w,
        instance: i,
        generation: 9,
    })
    .unwrap();
    assert_eq!(rel[10..26], w);
    assert_eq!(rel[34..50], i);
    assert_eq!(rel[50..58], 9u64.to_be_bytes());
    let got = decode_release(&rel).unwrap();
    assert_eq!((got.writer, got.instance, got.generation), (w, i, 9));

    for state in [
        ReceiptState::Live {
            prepared_root_id: id(7),
        },
        ReceiptState::Released,
    ] {
        let receipt = Receipt {
            epoch: 1,
            writer: w,
            instance: i,
            generation: 9,
            state,
        };
        let bytes = encode_receipt(receipt).unwrap();
        assert_eq!(bytes[11..27], w);
        assert_eq!(bytes[35..51], i);
        assert_eq!(bytes[51..59], 9u64.to_be_bytes());
        assert_eq!(decode_receipt(&bytes), Ok(receipt));
    }
}

/// Two tokens differing in one byte are two identities: a row is one writer
/// under one instance.
#[test]
fn bodies_that_differ_only_in_the_instance_token_differ() {
    let r = root(1);
    let one = encode_register(&writer(1), 1, &inst(1), 1, &r).unwrap();
    let mut other = inst(1);
    other[15] ^= 1;
    let two = encode_register(&writer(1), 1, &other, 1, &r).unwrap();
    assert_ne!(one, two);
    assert_eq!(
        decode_register(&two, &vol(VOLUME), accept)
            .unwrap()
            .instance,
        other
    );
}

/// The signed prefix a decoder derives is the one the root format defines,
/// for one and for two signature slots.
#[test]
fn the_signed_prefix_is_the_one_the_root_format_defines() {
    let two_sigs = |seed: u8| {
        encode_root(&RootDoc {
            volume: vol(VOLUME),
            seq: 1,
            parent: None,
            writer_uuid: [seed; WRITER_UUID_LEN],
            epoch: 1,
            timestamp: Timestamp {
                secs: 1_760_000_000,
                nanos: 0,
            },
            chunker_spec: crate::thresh::CHUNKER_SPEC.to_string(),
            manifest_root: GrainId::of(&[seed, 1]),
            binmap_index: GrainId::of(&[seed, 2]),
            sheaf_head: GrainId::of(&[seed, 3]),
            sigs: vec![
                RootSig {
                    key_id: [1; KEY_ID_LEN],
                    sig: [2; ED25519_SIG_LEN],
                },
                RootSig {
                    key_id: [3; KEY_ID_LEN],
                    sig: [4; ED25519_SIG_LEN],
                },
            ],
        })
        .unwrap()
    };
    for r in [root(1), two_sigs(2)] {
        let sigs = root::decode_root(&r).unwrap().sigs.len();
        let body = encode_register(&writer(1), 1, &inst(I), 1, &r).unwrap();
        let mut got = None;
        decode_register(&body, &vol(VOLUME), |_, prefix| {
            got = Some(prefix.to_vec());
            true
        })
        .unwrap();
        assert_eq!(
            got.as_deref(),
            Some(root::signed_prefix(&r).unwrap()),
            "{sigs} signature slots"
        );
        assert_eq!(r.len() - got.unwrap().len(), 1 + sigs * SIG_SLOT_LEN);
    }
}
