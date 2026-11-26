// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Bounded canonical ownership snapshots.

use crate::encoding::Cursor;
use crate::hash::GrainId;
use crate::intent::{self, Receipt, ReceiptState, Reply, Verdict};
use crate::retained_submission::Scope;
use crate::root::VolumeName;

pub const MAX_BYTES: usize = 16_777_216;
pub const REPLACEMENT_RESERVE: u64 = 33_554_432;
pub const MAX_PENDING: usize = 128;
pub const CONTEXT_MAX: usize = 4096;
pub const CHECK_CONTEXT: &str = "granary overlay ownership v1";
/// Upper bound on the layout, including maximum fields of all reserved slots.
pub const MAX_LAYOUT_BYTES: usize = 12
    + 4
    + 8192
    + 4
    + 255
    + 1
    + 8 * 32
    + 4
    + 63
    + 32
    + 8
    + 1
    + 24
    + 4
    + 94
    + 4
    + 125
    + 2 * (4 + 92 + 4 + 65536)
    + 8
    + 4
    + 16384
    + 1
    + 4
    + 92
    + 2
    + 128 * (42 + 65594 + 4096 + 125)
    + (42 + 94 + 4096 + 125)
    + (42 + 58 + 4096 + 125)
    + 32;
const _: () = assert!(MAX_LAYOUT_BYTES < MAX_BYTES);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub &'static str);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ownership refused: {}", self.0)
    }
}
impl std::error::Error for Error {}
fn require(ok: bool, reason: &'static str) -> Result<(), Error> {
    if ok { Ok(()) } else { Err(Error(reason)) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    Unowned,
    Handshake,
    OwnedStart,
    Serving,
    Releasing,
    Released,
    Fenced,
}
impl Phase {
    /// # Errors
    /// Refuses an edge outside the exhaustive relation or unacknowledged recovery.
    pub fn transition(self, next: Self, acknowledged: bool) -> Result<(), Error> {
        use Phase::{Fenced, Handshake, OwnedStart, Released, Releasing, Serving, Unowned};
        require(
            self == next
                || matches!(
                    (self, next),
                    (
                        Unowned | OwnedStart | Serving | Releasing | Released,
                        Handshake
                    ) | (Handshake, OwnedStart | Unowned)
                        | (OwnedStart, Serving)
                        | (Serving, Releasing)
                        | (Releasing, Released)
                        | (
                            Unowned | Handshake | OwnedStart | Serving | Releasing | Released,
                            Fenced
                        )
                )
                || (self == Fenced && next == Handshake && acknowledged),
            "phase transition",
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Operation {
    Ownership = 1,
    Register = 2,
    Release = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub operation: Operation,
    pub body: Vec<u8>,
    pub context: Vec<u8>,
    pub first: u64,
    pub expires: u64,
    pub eligible: u64,
    pub attempts: u32,
    pub terminal: bool,
    /// The request's own final answer was observed, rather than only covered by G.
    pub answered: bool,
    pub answer: Vec<u8>,
}
impl Pending {
    /// # Errors
    /// Malformed retained request bytes.
    pub fn generation(&self) -> Result<u64, Error> {
        match self.operation {
            Operation::Ownership => Ok(0),
            Operation::Register => Ok(register(&self.body)?.generation),
            Operation::Release => Ok(intent::decode_release(&self.body)
                .map_err(|_| Error("release"))?
                .generation),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carrier {
    pub scope: Scope,
    pub volume: VolumeName,
    pub writer: [u8; 16],
    pub instance: [u8; 16],
    pub revision: u64,
    pub phase: Phase,
    pub cursor: u64,
    pub allocated: u64,
    pub sent: u64,
    pub handshake: Vec<u8>,
    pub grant: Vec<u8>,
    pub current: Vec<u8>,
    pub root: Vec<u8>,
    pub selected: Vec<u8>,
    pub selected_root: Vec<u8>,
    pub selected_cursor: u64,
    pub consent: Vec<u8>,
    pub fence: u8,
    pub fence_evidence: Vec<u8>,
    pub pending: Vec<Pending>,
}

fn register(bytes: &[u8]) -> Result<intent::Registration<'_>, Error> {
    // Signature verification belongs to the client; strict bytes/volume decoding
    // still happens here. The embedded root determines its own bound volume.
    let root = bytes.get(intent::ENVELOPE_LEN..).ok_or(Error("register"))?;
    let doc = crate::root::decode_root(root).map_err(|_| Error("prepared root"))?;
    intent::decode_register(bytes, &doc.volume, |_, _| true).map_err(|_| Error("register"))
}
fn snapshot(bytes: &[u8], root: &[u8], c: &Carrier) -> Result<Option<Receipt>, Error> {
    if bytes.is_empty() {
        require(root.is_empty(), "root without snapshot")?;
        return Ok(None);
    }
    let receipt = intent::decode_receipt(bytes).map_err(|_| Error("snapshot"))?;
    require(receipt.writer == c.writer, "snapshot writer")?;
    match receipt.state {
        ReceiptState::Released => require(root.is_empty(), "released root")?,
        ReceiptState::Live { prepared_root_id } => {
            require(
                root.len() <= 65536 && GrainId::of(root) == prepared_root_id,
                "snapshot root id",
            )?;
            let doc = crate::root::decode_root(root).map_err(|_| Error("snapshot root"))?;
            require(doc.volume == c.volume, "snapshot volume")?;
        }
    }
    Ok(Some(receipt))
}
impl Carrier {
    /// # Errors
    /// Invalid binding, bounds, evidence, request identity or ordering.
    pub fn validate(&self) -> Result<(), Error> {
        self.scope.digest().map_err(|_| Error("scope"))?;
        require(
            self.sent <= self.allocated && self.allocated < u64::MAX,
            "high water",
        )?;
        require(
            self.consent.len() <= 16384 && self.fence <= 2,
            "consent/fence",
        )?;
        require(
            self.handshake.len() <= 94 && self.grant.len() <= 125,
            "grant cap",
        )?;
        require(
            self.handshake.is_empty() == self.grant.is_empty(),
            "grant pair",
        )?;
        if !self.grant.is_empty() {
            let verdict = intent::judge_ownership(
                &self.handshake,
                &Reply {
                    status: 200,
                    token: None,
                    media_type: Some(intent::MEDIA_GRANT),
                    body: &self.grant,
                },
            )
            .map_err(|_| Error("handshake"))?;
            require(
                matches!(verdict, Verdict::Accepted(g) if g.receipt.writer == self.writer),
                "grant binding",
            )?;
        }
        let current = snapshot(&self.current, &self.root, self)?;
        let selected = snapshot(&self.selected, &self.selected_root, self)?;
        if matches!(
            self.phase,
            Phase::OwnedStart | Phase::Serving | Phase::Releasing | Phase::Released
        ) {
            require(
                !self.grant.is_empty() && current.is_some(),
                "owned evidence",
            )?;
            let granted = intent::decode_grant(&self.grant)
                .map_err(|_| Error("grant"))?
                .receipt;
            require(
                current.is_some_and(|r| {
                    r.epoch == granted.epoch
                        && r.instance == granted.instance
                        && r.generation >= granted.generation
                }),
                "current ownership",
            )?;
        }
        if self.phase == Phase::Fenced {
            require(self.fence != 0, "fence missing")?;
        }
        require(
            self.fence == 0 || self.phase == Phase::Fenced || self.phase == Phase::Handshake,
            "sticky fence",
        )?;
        if self.fence == 1 {
            let proof =
                intent::decode_receipt(&self.fence_evidence).map_err(|_| Error("fence receipt"))?;
            require(
                proof.writer == self.writer
                    && current.or(selected).is_some_and(|r| proof.epoch > r.epoch),
                "fence displacement",
            )?;
        } else {
            require(self.fence_evidence.is_empty(), "fence evidence")?;
        }
        self.validate_pending()
    }

    fn validate_pending(&self) -> Result<(), Error> {
        require(self.pending.len() <= MAX_PENDING + 2, "pending count")?;
        let mut previous = None;
        let mut counts = [0usize; 3];
        for p in &self.pending {
            require(
                p.context.len() <= CONTEXT_MAX && p.answer.len() <= 125,
                "pending context",
            )?;
            require(
                !p.answered || (p.terminal && p.attempts != 0),
                "answer lifecycle",
            )?;
            require(
                p.first <= p.eligible && p.eligible <= p.expires,
                "retry interval",
            )?;
            let g = p.generation()?;
            let key = (p.operation, g);
            require(previous.is_none_or(|old| old < key), "pending order")?;
            previous = Some(key);
            let (count, writer) = match p.operation {
                Operation::Ownership => (
                    &mut counts[0],
                    intent::decode_ownership(&p.body)
                        .map_err(|_| Error("ownership request"))?
                        .writer,
                ),
                Operation::Register => {
                    let r = register(&p.body)?;
                    let doc =
                        crate::root::decode_root(r.root).map_err(|_| Error("prepared root"))?;
                    require(
                        doc.volume == self.volume && doc.writer_uuid == self.writer,
                        "prepared binding",
                    )?;
                    (&mut counts[1], r.writer)
                }
                Operation::Release => (
                    &mut counts[2],
                    intent::decode_release(&p.body)
                        .map_err(|_| Error("release"))?
                        .writer,
                ),
            };
            *count += 1;
            require(
                writer == self.writer && g <= self.sent,
                "pending writer/high water",
            )?;
            if p.operation == Operation::Ownership {
                let request =
                    intent::decode_ownership(&p.body).map_err(|_| Error("ownership request"))?;
                if let intent::OwnershipMode::Takeover {
                    expected_epoch,
                    generation,
                    state,
                    recovery_ack,
                } = request.mode
                {
                    let selected = snapshot(&self.selected, &self.selected_root, self)?
                        .ok_or(Error("takeover selection"))?;
                    require(
                        (selected.epoch, selected.generation, selected.state)
                            == (expected_epoch, generation, state),
                        "takeover selection",
                    )?;
                    require(
                        !recovery_ack || self.consent == recovery_consent(self, &p.body)?,
                        "takeover consent",
                    )?;
                    require(
                        self.fence == 0
                            || recovery_ack
                            || (self.phase == Phase::Fenced
                                && p.terminal
                                && !p.answered
                                && p.attempts != 0),
                        "fenced takeover consent",
                    )?;
                }
            }
        }
        require(
            counts[0] <= 1 && counts[1] <= MAX_PENDING && counts[2] <= 1,
            "pending slots",
        )
    }
}

/// Exact canonical recovery acknowledgement binding, without credentials or text.
/// # Errors
/// An invalid scope or field length.
pub fn recovery_consent(c: &Carrier, takeover: &[u8]) -> Result<Vec<u8>, Error> {
    c.scope.digest().map_err(|_| Error("scope"))?;
    let mut out = b"GRNOVACK".to_vec();
    put(&mut out, &c.scope.authority_base)?;
    put(&mut out, &c.scope.credential_context)?;
    out.push(u8::try_from(c.scope.pins.len()).map_err(|_| Error("pins"))?);
    for pin in &c.scope.pins {
        out.extend_from_slice(pin);
    }
    put(&mut out, c.volume.as_str().as_bytes())?;
    out.extend_from_slice(&c.writer);
    put(&mut out, &c.selected)?;
    put(&mut out, takeover)?;
    Ok(out)
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| Error("length"))?
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
    Ok(())
}
fn blob<'a>(c: &mut Cursor<'a>, cap: usize) -> Result<&'a [u8], Error> {
    let n =
        usize::try_from(c.u32().map_err(|_| Error("truncated"))?).map_err(|_| Error("length"))?;
    require(n <= cap, "section cap")?;
    c.take(n).map_err(|_| Error("truncated"))
}
fn array<const N: usize>(c: &mut Cursor<'_>) -> Result<[u8; N], Error> {
    c.take(N)
        .map_err(|_| Error("truncated"))?
        .try_into()
        .map_err(|_| Error("truncated"))
}
fn tick(c: &mut Cursor<'_>) -> Result<u64, Error> {
    c.u64().map_err(|_| Error("truncated"))
}
fn byte(c: &mut Cursor<'_>) -> Result<u8, Error> {
    c.u8().map_err(|_| Error("truncated"))
}

/// # Errors
/// Invalid value relations or a file exceeding its whole-file budget.
pub fn encode(c: &Carrier) -> Result<Vec<u8>, Error> {
    c.validate()?;
    let mut out = b"GRNOVOWN\0\x01\0\0".to_vec();
    put(&mut out, &c.scope.authority_base)?;
    put(&mut out, &c.scope.credential_context)?;
    out.push(u8::try_from(c.scope.pins.len()).map_err(|_| Error("pins"))?);
    for pin in &c.scope.pins {
        out.extend_from_slice(pin);
    }
    put(&mut out, c.volume.as_str().as_bytes())?;
    out.extend_from_slice(&c.writer);
    out.extend_from_slice(&c.instance);
    out.extend_from_slice(&c.revision.to_be_bytes());
    out.push(c.phase as u8);
    for n in [c.cursor, c.allocated, c.sent] {
        out.extend_from_slice(&n.to_be_bytes());
    }
    for b in [
        &c.handshake,
        &c.grant,
        &c.current,
        &c.root,
        &c.selected,
        &c.selected_root,
    ] {
        put(&mut out, b)?;
    }
    out.extend_from_slice(&c.selected_cursor.to_be_bytes());
    put(&mut out, &c.consent)?;
    out.push(c.fence);
    put(&mut out, &c.fence_evidence)?;
    out.extend_from_slice(
        &u16::try_from(c.pending.len())
            .map_err(|_| Error("pending count"))?
            .to_be_bytes(),
    );
    for p in &c.pending {
        out.push(p.operation as u8);
        put(&mut out, &p.body)?;
        put(&mut out, &p.context)?;
        for n in [p.first, p.expires, p.eligible] {
            out.extend_from_slice(&n.to_be_bytes());
        }
        out.extend_from_slice(&p.attempts.to_be_bytes());
        out.push(u8::from(p.terminal) | (u8::from(p.answered) << 1));
        put(&mut out, &p.answer)?;
    }
    require(out.len() <= MAX_BYTES - 32, "file cap")?;
    let check = blake3::derive_key(CHECK_CONTEXT, &out);
    out.extend_from_slice(&check);
    Ok(out)
}

/// # Errors
/// Oversize, truncated, unsupported, noncanonical or internally inconsistent bytes.
pub fn decode(bytes: &[u8]) -> Result<Carrier, Error> {
    require(bytes.len() <= MAX_BYTES, "file cap")?;
    let end = bytes.len().checked_sub(32).ok_or(Error("truncated"))?;
    let payload = bytes.get(..end).ok_or(Error("truncated"))?;
    require(
        bytes.get(end..) == Some(blake3::derive_key(CHECK_CONTEXT, payload).as_slice()),
        "check",
    )?;
    let mut c = Cursor::new(payload);
    require(array::<8>(&mut c)? == *b"GRNOVOWN", "magic")?;
    require(c.u16().map_err(|_| Error("truncated"))? == 1, "version")?;
    require(c.u16().map_err(|_| Error("truncated"))? == 0, "flags")?;
    let authority_base = blob(&mut c, 8192)?.to_vec();
    let credential_context = blob(&mut c, 255)?.to_vec();
    let count = byte(&mut c)?;
    require(count <= 8, "pins")?;
    let mut pins = Vec::new();
    for _ in 0..count {
        pins.push(array(&mut c)?);
    }
    let volume = VolumeName::from_bytes(blob(&mut c, 63)?).map_err(|_| Error("volume"))?;
    let writer = array(&mut c)?;
    let instance = array(&mut c)?;
    let revision = tick(&mut c)?;
    let phase = match byte(&mut c)? {
        0 => Phase::Unowned,
        1 => Phase::Handshake,
        2 => Phase::OwnedStart,
        3 => Phase::Serving,
        4 => Phase::Releasing,
        5 => Phase::Released,
        6 => Phase::Fenced,
        _ => return Err(Error("phase")),
    };
    let cursor = tick(&mut c)?;
    let allocated = tick(&mut c)?;
    let sent = tick(&mut c)?;
    let handshake = blob(&mut c, 94)?.to_vec();
    let grant = blob(&mut c, 125)?.to_vec();
    let current = blob(&mut c, 92)?.to_vec();
    let root = blob(&mut c, 65536)?.to_vec();
    let selected = blob(&mut c, 92)?.to_vec();
    let selected_root = blob(&mut c, 65536)?.to_vec();
    let selected_cursor = tick(&mut c)?;
    let consent = blob(&mut c, 16384)?.to_vec();
    let fence = byte(&mut c)?;
    let fence_evidence = blob(&mut c, 92)?.to_vec();
    let pending = decode_pending(&mut c)?;
    c.finish().map_err(|_| Error("trailing"))?;
    let value = Carrier {
        scope: Scope {
            authority_base,
            pins,
            credential_context,
        },
        volume,
        writer,
        instance,
        revision,
        phase,
        cursor,
        allocated,
        sent,
        handshake,
        grant,
        current,
        root,
        selected,
        selected_root,
        selected_cursor,
        consent,
        fence,
        fence_evidence,
        pending,
    };
    value.validate()?;
    Ok(value)
}

#[cfg(test)]
mod tests;

fn decode_pending(c: &mut Cursor<'_>) -> Result<Vec<Pending>, Error> {
    let count = c.u16().map_err(|_| Error("truncated"))?;
    require(usize::from(count) <= MAX_PENDING + 2, "pending count")?;
    let mut pending = Vec::new();
    for _ in 0..count {
        let operation = match byte(c)? {
            1 => Operation::Ownership,
            2 => Operation::Register,
            3 => Operation::Release,
            _ => return Err(Error("operation")),
        };
        let cap = match operation {
            Operation::Ownership => 94,
            Operation::Register => 65594,
            Operation::Release => 58,
        };
        let body = blob(c, cap)?.to_vec();
        let context = blob(c, CONTEXT_MAX)?.to_vec();
        let first = tick(c)?;
        let expires = tick(c)?;
        let eligible = tick(c)?;
        let attempts = c.u32().map_err(|_| Error("truncated"))?;
        let flags = byte(c)?;
        require(flags <= 3, "terminal")?;
        let terminal = flags & 1 != 0;
        let answered = flags & 2 != 0;
        let answer = blob(c, 125)?.to_vec();
        pending.push(Pending {
            operation,
            body,
            context,
            first,
            expires,
            eligible,
            attempts,
            terminal,
            answered,
            answer,
        });
    }
    Ok(pending)
}
