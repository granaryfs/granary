// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Streaming, bounded snapshot framing and complete-state validation.

use super::{Principal, Row, Snapshot};
use granary_core::authlog::Epoch;
use granary_core::enrollment::PrincipalId;
use granary_core::hash::GrainId;
use granary_core::intent::{self as wire, Receipt, ReceiptState};
use granary_core::root::VolumeName;
use granary_core::sheaf::Timestamp;
use granary_store::crypto::{TrustedKeys, check_signatures};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::sync::Arc;

const MAGIC: &[u8; 8] = b"GRNINSTO";
const END: &[u8; 8] = b"GRNINEND";
const ROW_MAX: usize = 65_728;
const ENVELOPE_DOMAIN: &[u8] = b"granary intent-store envelope v1";
const FRAME_DOMAIN: &[u8] = b"granary intent-store frame v1";
const FOOTER_DOMAIN: &[u8] = b"granary intent-store footer v1";
fn bad(rule: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, rule)
}
fn check(domain: &[u8], bytes: &[u8]) -> GrainId {
    let mut input = Vec::with_capacity(domain.len().saturating_add(bytes.len()));
    input.extend_from_slice(domain);
    input.extend_from_slice(bytes);
    GrainId::of(&input)
}
fn number(n: usize) -> io::Result<u64> {
    u64::try_from(n).map_err(|_| bad("length-over"))
}

#[cfg(test)]
pub(crate) fn encode(snapshot: &Snapshot, out: impl Write) -> io::Result<()> {
    validate(snapshot)?;
    encode_frames(snapshot, out)
}

#[cfg(test)]
fn validate(snapshot: &Snapshot) -> io::Result<()> {
    for principal in snapshot.principals.values() {
        validate_principal(principal, &snapshot.volume)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) static PRINCIPAL_VALIDATIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Validate just the proposed principal; other blocks were validated on load.
pub(crate) fn validate_principal(principal: &Principal, volume: &VolumeName) -> io::Result<()> {
    #[cfg(test)]
    PRINCIPAL_VALIDATIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if principal.rows.len() > wire::MAX_TOTAL_ROWS {
        return Err(bad("count-over"));
    }
    let mut epochs = BTreeSet::new();
    let mut live = 0_usize;
    let mut root_bytes = 0_usize;
    for (writer, row) in &principal.rows {
        let r = row.receipt;
        if r.writer != *writer {
            return Err(bad("writer-order"));
        }
        if r.epoch > principal.h || !epochs.insert(r.epoch) {
            return Err(bad("epoch-cursor"));
        }
        if !row.changed.is_valid() {
            return Err(bad("timestamp-nanos"));
        }
        wire::encode_receipt(r).map_err(|_| bad("receipt-invalid"))?;
        if row.root.is_empty() {
            if r.state != ReceiptState::Released {
                return Err(bad("root-shape"));
            }
        } else {
            if r.state
                != (ReceiptState::Live {
                    prepared_root_id: GrainId::of(&row.root),
                })
            {
                return Err(bad("root-shape"));
            }
            let bytes =
                wire::encode_register(writer, r.epoch, &r.instance, r.generation, &row.root)
                    .map_err(|_| bad("root-invalid"))?;
            wire::decode_register(&bytes, volume, |_, _| true).map_err(|_| bad("root-invalid"))?;
            live += 1;
        }
        root_bytes = root_bytes
            .checked_add(row.root.len())
            .ok_or(bad("root-over"))?;
        if live > wire::MAX_LIVE_ROWS || root_bytes > wire::MAX_ROOT_BYTES {
            return Err(bad("quota-over"));
        }
        let g = row.grant.receipt;
        wire::encode_grant(row.grant).map_err(|_| bad("grant-invalid"))?;
        if g.writer != r.writer
            || g.epoch != r.epoch
            || g.instance != r.instance
            || g.generation > r.generation
        {
            return Err(bad("grant-current"));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn encode_unchecked(snapshot: &Snapshot, out: impl Write) -> io::Result<()> {
    encode_frames(snapshot, out)
}

pub(crate) fn encode_frames(snapshot: &Snapshot, mut out: impl Write) -> io::Result<()> {
    let mut envelope = Vec::new();
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(&1_u16.to_be_bytes());
    envelope.extend_from_slice(&0_u16.to_be_bytes());
    let volume = snapshot.volume.as_str().as_bytes();
    envelope.push(u8::try_from(volume.len()).map_err(|_| bad("volume-length"))?);
    envelope.extend_from_slice(volume);
    envelope.extend_from_slice(&snapshot.epoch.to_bytes());
    envelope.extend_from_slice(&number(snapshot.principals.len())?.to_be_bytes());
    let rows = snapshot.principals.values().try_fold(0_u64, |n, p| {
        n.checked_add(number(p.rows.len())?)
            .ok_or(bad("count-over"))
    })?;
    envelope.extend_from_slice(&rows.to_be_bytes());
    let initial = check(ENVELOPE_DOMAIN, &envelope);
    envelope.extend_from_slice(&initial.to_bytes());
    out.write_all(&envelope)?;
    let mut length = number(envelope.len())?;
    let mut chain = initial;
    let mut frames = 0_u64;
    for (id, principal) in &snapshot.principals {
        let mut block = Vec::new();
        block.extend_from_slice(id.as_bytes());
        block.extend_from_slice(&principal.h.to_be_bytes());
        let count = u16::try_from(principal.rows.len()).map_err(|_| bad("count-over"))?;
        block.extend_from_slice(&count.to_be_bytes());
        frame(&mut out, 1, &block, &mut chain, &mut length)?;
        frames = frames.checked_add(1).ok_or(bad("count-over"))?;
        for row in principal.rows.values() {
            let mut payload = Vec::with_capacity(row.root.len() + 192);
            payload.extend_from_slice(&row.receipt.writer);
            payload.extend_from_slice(&row.receipt.epoch.to_be_bytes());
            payload.extend_from_slice(&row.receipt.instance);
            payload.extend_from_slice(&row.receipt.generation.to_be_bytes());
            payload.push(if row.root.is_empty() { 2 } else { 1 });
            payload.extend_from_slice(&row.changed.secs.to_be_bytes());
            payload.extend_from_slice(&row.changed.nanos.to_be_bytes());
            payload.extend_from_slice(
                &u32::try_from(row.root.len())
                    .map_err(|_| bad("root-over"))?
                    .to_be_bytes(),
            );
            payload.extend_from_slice(&row.root);
            let grant = wire::encode_grant(row.grant).map_err(|_| bad("grant-invalid"))?;
            payload.extend_from_slice(
                &u16::try_from(grant.len())
                    .map_err(|_| bad("grant-over"))?
                    .to_be_bytes(),
            );
            payload.extend_from_slice(&grant);
            frame(&mut out, 2, &payload, &mut chain, &mut length)?;
            frames = frames.checked_add(1).ok_or(bad("count-over"))?;
        }
    }
    let mut footer = Vec::new();
    footer.extend_from_slice(END);
    footer.extend_from_slice(&frames.to_be_bytes());
    footer.extend_from_slice(
        &length
            .checked_add(90)
            .ok_or(bad("length-over"))?
            .to_be_bytes(),
    );
    footer.extend_from_slice(&chain.to_bytes());
    let mut checked = initial.to_bytes().to_vec();
    checked.extend_from_slice(&footer);
    footer.extend_from_slice(&check(FOOTER_DOMAIN, &checked).to_bytes());
    out.write_all(&footer)
}
fn frame(
    out: &mut impl Write,
    tag: u8,
    payload: &[u8],
    chain: &mut GrainId,
    length: &mut u64,
) -> io::Result<()> {
    if payload.len() > ROW_MAX {
        return Err(bad("frame-over"));
    }
    let mut bytes = Vec::with_capacity(payload.len() + 38);
    bytes.extend_from_slice(
        &u32::try_from(payload.len())
            .map_err(|_| bad("frame-over"))?
            .to_be_bytes(),
    );
    bytes.push(tag);
    bytes.extend_from_slice(payload);
    let mut input = Vec::with_capacity(33 + bytes.len());
    input.extend_from_slice(&chain.to_bytes());
    input.extend_from_slice(&bytes);
    *chain = check(FRAME_DOMAIN, &input);
    bytes.extend_from_slice(&chain.to_bytes());
    *length = length
        .checked_add(number(bytes.len())?)
        .ok_or(bad("length-over"))?;
    out.write_all(&bytes)
}
struct Reader<R> {
    input: R,
    length: u64,
}
impl<R: Read> Reader<R> {
    fn take(&mut self, n: usize) -> io::Result<Vec<u8>> {
        if n > ROW_MAX {
            return Err(bad("frame-over"));
        }
        let mut bytes = vec![0; n];
        self.input.read_exact(&mut bytes)?;
        self.length = self
            .length
            .checked_add(number(n)?)
            .ok_or(bad("length-over"))?;
        Ok(bytes)
    }
    fn frame(&mut self, tag: u8, chain: &mut GrainId) -> io::Result<Vec<u8>> {
        let header = self.take(5)?;
        let mut c = Fields(&header);
        let len = usize::try_from(c.u32()?).map_err(|_| bad("frame-over"))?;
        if c.u8()? != tag {
            return Err(bad("frame-tag"));
        }
        if (tag == 1 && len != 26) || len > ROW_MAX {
            return Err(bad("frame-over"));
        }
        let payload = self.take(len)?;
        let mut checked = chain.to_bytes().to_vec();
        checked.extend_from_slice(&header);
        checked.extend_from_slice(&payload);
        let expected = check(FRAME_DOMAIN, &checked);
        if self.take(33)? != expected.to_bytes() {
            return Err(bad("frame-check"));
        }
        *chain = expected;
        Ok(payload)
    }
}
struct Fields<'a>(&'a [u8]);
impl<'a> Fields<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let value = self.0.get(..n).ok_or(bad("truncated"))?;
        self.0 = self.0.get(n..).ok_or(bad("truncated"))?;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| bad("truncated"))
    }
    fn u8(&mut self) -> io::Result<u8> {
        Ok(u8::from_be_bytes(self.array()?))
    }
    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn end(self) -> io::Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(bad("trailing-bytes"))
        }
    }
}

pub(crate) fn decode(
    input: impl Read,
    volume: &VolumeName,
    epoch: Option<Epoch>,
    keys: &TrustedKeys,
) -> io::Result<Snapshot> {
    decode_inner(input, volume, epoch, Some(keys))
}

pub(crate) fn decode_for_rebind(input: impl Read, volume: &VolumeName) -> io::Result<Snapshot> {
    decode_inner(input, volume, None, None)
}

#[expect(
    clippy::too_many_lines,
    reason = "Streaming framing and complete-state validation stay in consumption order"
)]
fn decode_inner(
    input: impl Read,
    volume: &VolumeName,
    epoch: Option<Epoch>,
    keys: Option<&TrustedKeys>,
) -> io::Result<Snapshot> {
    let mut input = Reader { input, length: 0 };
    let mut envelope = input.take(13)?;
    let mut prefix = Fields(&envelope);
    if prefix.take(8)? != MAGIC || prefix.u16()? != 1 || prefix.u16()? != 0 {
        return Err(bad("envelope"));
    }
    let volume_len = usize::from(prefix.u8()?);
    if !(1..=63).contains(&volume_len) {
        return Err(bad("volume-length"));
    }
    let rest = input.take(volume_len.checked_add(32).ok_or(bad("length-over"))?)?;
    let mut fields = Fields(&rest);
    if fields.take(volume_len)? != volume.as_str().as_bytes() {
        return Err(bad("volume-mismatch"));
    }
    let bound = Epoch::from_bytes(fields.array()?);
    if epoch.is_some_and(|e| e != bound) {
        return Err(bad("epoch-mismatch"));
    }
    let principal_count = fields.u64()?;
    let row_count = fields.u64()?;
    envelope.extend_from_slice(&rest);
    let initial = check(ENVELOPE_DOMAIN, &envelope);
    if input.take(33)? != initial.to_bytes() {
        return Err(bad("envelope-check"));
    }
    let mut chain = initial;
    let mut snapshot = Snapshot {
        volume: volume.clone(),
        epoch: bound,
        principals: BTreeMap::new(),
    };
    let mut rows = 0_u64;
    let mut frames = 0_u64;
    let mut previous = None;
    // Counts drive reads only; allocation follows verified, consumed frames.
    for _ in 0..principal_count {
        let payload = input.frame(1, &mut chain)?;
        frames = frames.checked_add(1).ok_or(bad("count-over"))?;
        let mut c = Fields(&payload);
        let id = PrincipalId::from_bytes(c.array()?);
        if previous.is_some_and(|p| p >= id) {
            return Err(bad("principal-order"));
        }
        previous = Some(id);
        let h = c.u64()?;
        let count = usize::from(c.u16()?);
        if count > wire::MAX_TOTAL_ROWS {
            return Err(bad("count-over"));
        }
        c.end()?;
        let mut principal = Principal {
            h,
            rows: BTreeMap::new(),
        };
        let mut epochs = BTreeSet::new();
        let mut previous_writer = None;
        let mut live = 0_usize;
        let mut root_bytes = 0_usize;
        for _ in 0..count {
            let payload = input.frame(2, &mut chain)?;
            frames = frames.checked_add(1).ok_or(bad("count-over"))?;
            rows = rows.checked_add(1).ok_or(bad("count-over"))?;
            let row = decode_row(&payload, volume, keys)?;
            let rec = row.receipt;
            if rec.epoch > h || !epochs.insert(rec.epoch) {
                return Err(bad("epoch-cursor"));
            }
            if previous_writer.is_some_and(|w| w >= rec.writer) {
                return Err(bad("writer-order"));
            }
            previous_writer = Some(rec.writer);
            if !row.root.is_empty() {
                live += 1;
            }
            root_bytes = root_bytes
                .checked_add(row.root.len())
                .ok_or(bad("root-over"))?;
            if live > wire::MAX_LIVE_ROWS || root_bytes > wire::MAX_ROOT_BYTES {
                return Err(bad("quota-over"));
            }
            principal.rows.insert(rec.writer, row);
        }
        snapshot.principals.insert(id, principal);
    }
    if rows != row_count {
        return Err(bad("count-mismatch"));
    }
    let footer = input.take(90)?;
    let mut c = Fields(&footer);
    if c.take(8)? != END
        || c.u64()? != frames
        || c.u64()? != input.length
        || c.take(33)? != chain.to_bytes()
    {
        return Err(bad("footer"));
    }
    let mut checked = initial.to_bytes().to_vec();
    checked.extend_from_slice(footer.get(..57).ok_or(bad("truncated"))?);
    if c.take(33)? != check(FOOTER_DOMAIN, &checked).to_bytes() {
        return Err(bad("footer-check"));
    }
    let mut trailing = [0];
    if input.input.read(&mut trailing)? != 0 {
        return Err(bad("trailing-bytes"));
    }
    Ok(snapshot)
}
fn decode_row(payload: &[u8], volume: &VolumeName, keys: Option<&TrustedKeys>) -> io::Result<Row> {
    let mut c = Fields(payload);
    let writer = c.array()?;
    let epoch = c.u64()?;
    let instance = c.array()?;
    let generation = c.u64()?;
    let state = c.u8()?;
    let changed = Timestamp {
        secs: i64::from_be_bytes(c.array()?),
        nanos: c.u32()?,
    };
    if !changed.is_valid() {
        return Err(bad("timestamp-nanos"));
    }
    let root_len = usize::try_from(c.u32()?).map_err(|_| bad("root-over"))?;
    if root_len > 65_536 || !matches!((state, root_len), (1, 1..=65_536) | (2, 0)) {
        return Err(bad("root-shape"));
    }
    let root = c.take(root_len)?;
    let receipt = Receipt {
        writer,
        epoch,
        instance,
        generation,
        state: if state == 1 {
            ReceiptState::Live {
                prepared_root_id: GrainId::of(root),
            }
        } else {
            ReceiptState::Released
        },
    };
    wire::encode_receipt(receipt).map_err(|_| bad("receipt-invalid"))?;
    if !root.is_empty() {
        let register = wire::encode_register(&writer, epoch, &instance, generation, root)
            .map_err(|_| bad("root-invalid"))?;
        wire::decode_register(&register, volume, |doc, signed| {
            keys.is_none_or(|keys| check_signatures(doc, signed, keys).is_ok())
        })
        .map_err(|_| bad("root-invalid"))?;
    }
    let grant_len = usize::from(c.u16()?);
    if grant_len > wire::GRANT_MAX_BYTES {
        return Err(bad("grant-over"));
    }
    let bytes = c.take(grant_len)?;
    let grant = wire::decode_grant(bytes).map_err(|_| bad("grant-invalid"))?;
    if wire::encode_grant(grant).map_err(|_| bad("grant-invalid"))? != bytes {
        return Err(bad("grant-canonical"));
    }
    if grant.receipt.writer != writer
        || grant.receipt.epoch != epoch
        || grant.receipt.instance != instance
        || grant.receipt.generation > generation
    {
        return Err(bad("grant-current"));
    }
    c.end()?;
    Ok(Row {
        receipt,
        root: Arc::from(root),
        grant,
        changed,
    })
}
