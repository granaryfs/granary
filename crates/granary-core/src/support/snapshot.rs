// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Complete cached domains, with grant labels removed before encoding.
use super::types::{
    CaptureCounters, EnrollmentSnapshot, ReaderCounters, RefusalReason, RefusalSnapshot,
    SnapshotCounters, SnapshotState, SupportCapture, TerminalState, UnavailableReason, VolumeView,
};
use super::{Result, SNAPSHOT_KIND, SNAPSHOT_MAX, SupportError, Tape, open, require, seal};
use crate::{
    debug_grant::{DebugGrant, GrantAction, GrantFields, GrantScope, Incarnation, Owner, Reason},
    enrollment::{CREDENTIALS_MAX, PRINCIPALS_MAX, PrincipalId},
    root::VolumeName,
    sheaf::Timestamp,
};
use std::collections::BTreeMap;

/// Structural grant fields only; operator labels cannot inhabit this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportGrantRecord {
    pub incarnation: Incarnation,
    pub file_revision: u64,
    pub grant_generation: u64,
    pub action: GrantAction,
    pub issuer_uid: u32,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub scope: GrantScope,
    pub line_ceiling: u64,
    pub byte_ceiling: u64,
}
/// Cached grant metadata, fixed codes and every reader/capture counter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportGrant {
    pub incarnation: Incarnation,
    pub state: &'static str,
    pub reason: Option<&'static str>,
    pub future_issued_lead_secs: Option<u64>,
    pub observed: Option<SupportGrantRecord>,
    pub accepted: Option<SupportGrantRecord>,
    pub effective: Option<SupportCapture>,
    pub slot: Option<u64>,
    pub capture_revision: u64,
    pub high_revision: u64,
    pub high_generation: u64,
    pub retired_generation: u64,
    pub reader_counters: ReaderCounters,
    pub capture_counters: CaptureCounters,
}
/// Disk-sampled state: each volume is coherent; domains and counters are
/// sampled separately, and process totals need not equal retained row totals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportSnapshot {
    pub incarnation: Incarnation,
    pub sampled_at: Timestamp,
    pub volumes: BTreeMap<VolumeName, VolumeView>,
    pub terminal: Option<TerminalState>,
    pub enrollment: EnrollmentSnapshot,
    pub refusals: RefusalSnapshot,
    pub grant: Option<SupportGrant>,
}
impl SupportSnapshot {
    /// Encode canonical bounded bytes, checking every field.
    /// # Errors
    /// Refuses fields outside the documented v1 accept set.
    pub fn encode(&self) -> Result<Vec<u8>> {
        seal(SNAPSHOT_KIND, SNAPSHOT_MAX, |t| {
            snapshot_fields(t, Some(self))?;
            Ok(())
        })
    }
    /// Verify the exact received bytes before bounded field decoding.
    /// # Errors
    /// Refuses damaged checks, unsupported tags, disorder, bounds and trailing data.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut t = open(bytes, SNAPSHOT_KIND, SNAPSHOT_MAX)?;
        let value = snapshot_fields(&mut t, None)?;
        t.end()?;
        Ok(value)
    }
}
const REFUSAL_DATA_MAX: usize =
    PRINCIPALS_MAX * (16 + 2 + REASONS.len() * 10) + 2 + REASONS.len() * 10 + 4;
const _: () = assert!(REFUSAL_DATA_MAX == 4_882_718);
const _: () =
    assert!(REFUSAL_DATA_MAX + 50 + 16 + 12 + 1 + 2 + 64 * 187 + 1 + 89 + 756 < SNAPSHOT_MAX);

const ZERO_TIME: Timestamp = Timestamp { secs: 0, nanos: 0 };
fn incarnation(t: &mut Tape<'_>, s: Option<Incarnation>) -> Result<Incarnation> {
    Ok(Incarnation::from_bytes(
        t.fixed(s.map_or([0; 16], |s| *s.as_bytes()))?,
    ))
}
fn number_option(t: &mut Tape<'_>, s: Option<&u64>) -> Result<Option<u64>> {
    t.option(s, |t, s| t.u64(s.copied().unwrap_or(0)))
}
fn snapshot_fields(t: &mut Tape<'_>, s: Option<&SupportSnapshot>) -> Result<SupportSnapshot> {
    let incarnation = incarnation(t, s.map(|s| s.incarnation))?;
    let sampled_at = t.time(s.map_or(ZERO_TIME, |s| s.sampled_at))?;
    require(t.u8(1)? == 1, "sampling semantics")?;
    let count = t.count(s.map_or(0, |s| s.volumes.len()), 64, false)?;
    require(count != 0, "volume count")?;
    let mut seeds = s.into_iter().flat_map(|s| s.volumes.iter());
    let mut volumes = BTreeMap::new();
    for _ in 0..count {
        let seed = seeds.next();
        let name = t.name(seed.map(|(n, _)| n))?;
        require(
            volumes
                .last_key_value()
                .is_none_or(|(last, _)| last < &name),
            "volume order",
        )?;
        let view = if t.boolean(seed.is_some_and(|(_, v)| !matches!(v, VolumeView::NoLog)))? {
            let status = seed.and_then(|(_, v)| v.status());
            let encoded = status
                .copied()
                .map(crate::authority_answer::encode_status)
                .transpose()
                .map_err(|_| SupportError("volume view"))?;
            let len = t.count(encoded.as_ref().map_or(0, Vec::len), 120, false)?;
            let mut bytes = Vec::with_capacity(len);
            for i in 0..len {
                bytes.push(
                    t.u8(encoded
                        .as_ref()
                        .and_then(|b| b.get(i))
                        .copied()
                        .unwrap_or(0))?,
                );
            }
            let v = crate::authority_answer::decode_status(&bytes)
                .map_err(|_| SupportError("volume view"))?;
            VolumeView::Log(v)
        } else {
            VolumeView::NoLog
        };
        volumes.insert(name, view);
    }
    let terminal = match t.u8(s.and_then(|s| s.terminal).map_or(0, |v| match v {
        TerminalState::Fenced => 1,
        TerminalState::Stopped => 2,
    }))? {
        0 => None,
        1 => Some(TerminalState::Fenced),
        2 => Some(TerminalState::Stopped),
        _ => return Err(SupportError("terminal tag")),
    };
    let enrollment = enrollment(t, s.map(|s| &s.enrollment))?;
    let totals = reasons(t, s.map(|s| &s.refusals.totals))?;
    let count = t.count(
        s.map_or(0, |s| s.refusals.principals.len()),
        PRINCIPALS_MAX,
        true,
    )?;
    let mut seeds = s.into_iter().flat_map(|s| s.refusals.principals.iter());
    let mut principals = BTreeMap::new();
    for _ in 0..count {
        let seed = seeds.next();
        let id = PrincipalId::from_bytes(t.fixed(seed.map_or([0; 16], |(id, _)| *id.as_bytes()))?);
        require(
            principals
                .last_key_value()
                .is_none_or(|(last, _)| last < &id),
            "principal order",
        )?;
        principals.insert(id, reasons(t, seed.map(|(_, r)| r))?);
    }
    let grant = t.option(s.and_then(|s| s.grant.as_ref()), grant)?;
    require(
        grant.as_ref().is_none_or(|g| g.incarnation == incarnation),
        "snapshot grant incarnation",
    )?;
    Ok(SupportSnapshot {
        incarnation,
        sampled_at,
        volumes,
        terminal,
        enrollment,
        refusals: RefusalSnapshot { totals, principals },
        grant,
    })
}
pub(super) const UNAVAILABLE: [UnavailableReason; 7] = [
    UnavailableReason::Missing,
    UnavailableReason::Unreadable,
    UnavailableReason::Unprotected,
    UnavailableReason::Oversize,
    UnavailableReason::Corrupt,
    UnavailableReason::Directory,
    UnavailableReason::Stalled,
];
fn enrollment(t: &mut Tape<'_>, s: Option<&EnrollmentSnapshot>) -> Result<EnrollmentSnapshot> {
    let state_tag = s.map_or(0, |s| match s.state {
        SnapshotState::Ok { .. } => 0,
        SnapshotState::Unavailable(r) => {
            u8::try_from(UNAVAILABLE.iter().position(|&v| v == r).unwrap_or(7))
                .unwrap_or(7)
                .saturating_add(1)
        }
    });
    let state = match t.u8(state_tag)? {
        0 => {
            let (p, c) = s.map_or((0, 0), |s| match s.state {
                SnapshotState::Ok {
                    principals,
                    credentials,
                } => (principals, credentials),
                SnapshotState::Unavailable(_) => (0, 0),
            });
            let p = t.count(p, PRINCIPALS_MAX, true)?;
            let c = t.count(c, CREDENTIALS_MAX, true)?;
            require(p != 0 || c == 0, "enrollment inventory")?;
            SnapshotState::Ok {
                principals: p,
                credentials: c,
            }
        }
        tag => SnapshotState::Unavailable(
            *UNAVAILABLE
                .get(usize::from(tag.saturating_sub(1)))
                .ok_or(SupportError("enrollment state"))?,
        ),
    };
    let sequence = t.u64(s.map_or(0, |s| s.sequence))?;
    let c = s.map_or(SnapshotCounters::default(), |s| s.counters);
    let counters = SnapshotCounters {
        missing: t.u64(c.missing)?,
        unreadable: t.u64(c.unreadable)?,
        unprotected: t.u64(c.unprotected)?,
        oversize: t.u64(c.oversize)?,
        corrupt: t.u64(c.corrupt)?,
        directory: t.u64(c.directory)?,
        stalled: t.u64(c.stalled)?,
        reloads: t.u64(c.reloads)?,
        reload_failures: t.u64(c.reload_failures)?,
    };
    Ok(EnrollmentSnapshot {
        state,
        sequence,
        counters,
    })
}
pub(super) const REASONS: [RefusalReason; 28] = [
    RefusalReason::NotFound,
    RefusalReason::UnknownTarget,
    RefusalReason::AlreadyExists,
    RefusalReason::AddressMismatch,
    RefusalReason::VerifyFailed,
    RefusalReason::LayoutInvalid,
    RefusalReason::BadRange,
    RefusalReason::ExtentTooWide,
    RefusalReason::BadRequest,
    RefusalReason::MethodNotAllowed,
    RefusalReason::TooLarge,
    RefusalReason::Internal,
    RefusalReason::Unavailable,
    RefusalReason::NoPrincipal,
    RefusalReason::NotEnrolled,
    RefusalReason::RateLimited,
    RefusalReason::AuthorityManaged,
    RefusalReason::InvalidCandidate,
    RefusalReason::NoLog,
    RefusalReason::UnknownVolume,
    RefusalReason::StaleBase,
    RefusalReason::OperationBound,
    RefusalReason::NotDecided,
    RefusalReason::EpochMismatch,
    RefusalReason::VolumeDamaged,
    RefusalReason::Fenced,
    RefusalReason::Stopped,
    RefusalReason::EnrollmentUnavailable,
];
fn reasons(
    t: &mut Tape<'_>,
    s: Option<&BTreeMap<RefusalReason, u64>>,
) -> Result<BTreeMap<RefusalReason, u64>> {
    let mut seeds = Vec::new();
    if let Some(s) = s {
        for (&reason, &count) in s {
            let tag = REASONS
                .iter()
                .position(|&r| r == reason)
                .ok_or(SupportError("refusal reason"))?;
            seeds.push((
                u16::try_from(tag)
                    .map_err(|_| SupportError("refusal reason"))?
                    .saturating_add(1),
                count,
            ));
        }
    }
    seeds.sort_unstable_by_key(|&(tag, _)| tag);
    let count = t.count(seeds.len(), 28, false)?;
    let mut previous = 0;
    let mut result = BTreeMap::new();
    for i in 0..count {
        let seed = seeds.get(i).copied().unwrap_or((0, 0));
        let tag = t.u16(seed.0)?;
        let reason = *REASONS
            .get(usize::from(tag.saturating_sub(1)))
            .filter(|_| tag != 0)
            .ok_or(SupportError("refusal reason"))?;
        require(tag > previous, "refusal reason order")?;
        previous = tag;
        result.insert(reason, t.u64(seed.1)?);
    }
    Ok(result)
}
fn scope(t: &mut Tape<'_>, s: Option<&GrantScope>) -> Result<GrantScope> {
    let tag = t.u8(s.map_or(0, |s| match s {
        GrantScope::Principal(_) => 1,
        GrantScope::Volume(_) => 2,
        GrantScope::Conjunction { .. } => 3,
    }))?;
    require((1..=3).contains(&tag), "grant scope")?;
    let principal = if tag == 2 {
        None
    } else {
        Some(PrincipalId::from_bytes(t.fixed(s.map_or(
            [0; 16],
            |s| match s {
                GrantScope::Principal(p) | GrantScope::Conjunction { principal: p, .. } => {
                    *p.as_bytes()
                }
                GrantScope::Volume(_) => [0; 16],
            },
        ))?))
    };
    let volume = if tag == 1 {
        None
    } else {
        Some(t.name(s.and_then(|s| match s {
            GrantScope::Volume(v) | GrantScope::Conjunction { volume: v, .. } => Some(v),
            GrantScope::Principal(_) => None,
        }))?)
    };
    match (principal, volume) {
        (Some(p), None) => Ok(GrantScope::Principal(p)),
        (None, Some(v)) => Ok(GrantScope::Volume(v)),
        (Some(principal), Some(volume)) => Ok(GrantScope::Conjunction { principal, volume }),
        _ => Err(SupportError("grant scope")),
    }
}
fn record(t: &mut Tape<'_>, s: Option<&SupportGrantRecord>) -> Result<SupportGrantRecord> {
    let incarnation = incarnation(t, s.map(|s| s.incarnation))?;
    let file_revision = t.u64(s.map_or(0, |s| s.file_revision))?;
    let grant_generation = t.u64(s.map_or(0, |s| s.grant_generation))?;
    let action = match t.u8(s.map_or(0, |s| match s.action {
        GrantAction::Issue => 1,
        GrantAction::Narrow => 2,
        GrantAction::Revoke => 3,
    }))? {
        1 => GrantAction::Issue,
        2 => GrantAction::Narrow,
        3 => GrantAction::Revoke,
        _ => return Err(SupportError("grant action")),
    };
    let issuer_uid = t.u32(s.map_or(0, |s| s.issuer_uid))?;
    let issued_at = t.time(s.map_or(ZERO_TIME, |s| s.issued_at))?;
    let expires_at = t.time(s.map_or(ZERO_TIME, |s| s.expires_at))?;
    let scope = scope(t, s.map(|s| &s.scope))?;
    let line_ceiling = t.u64(s.map_or(0, |s| s.line_ceiling))?;
    let byte_ceiling = t.u64(s.map_or(0, |s| s.byte_ceiling))?;
    // Reuse the existing validated structural contract with constant labels;
    // no operator label enters this projection or its bytes.
    let fields = GrantFields {
        incarnation,
        file_revision,
        grant_generation,
        action,
        issuer_uid,
        issued_at,
        expires_at,
        scope: scope.clone(),
        line_ceiling,
        byte_ceiling,
        owner: Owner::from_bytes(b"support").map_err(|_| SupportError("grant structure"))?,
        reason: Reason::from_bytes(b"support").map_err(|_| SupportError("grant structure"))?,
    };
    DebugGrant::new(fields).map_err(|_| SupportError("grant structure"))?;
    Ok(SupportGrantRecord {
        incarnation,
        file_revision,
        grant_generation,
        action,
        issuer_uid,
        issued_at,
        expires_at,
        scope,
        line_ceiling,
        byte_ceiling,
    })
}
pub(super) const STATES: [&str; 3] = ["unread", "applied", "disabled"];
pub(super) const GRANT_REASONS: [&str; 26] = [
    "missing",
    "unreadable",
    "stalled",
    "unprotected",
    "oversize",
    "corrupt",
    "directory",
    "stale-incarnation",
    "future-issued",
    "already-expired",
    "rollback",
    "equal-revision-different-bytes",
    "widening",
    "retired-generation",
    "revoked",
    "unsupported-clock-profile",
    "clock-source-failure",
    "clock-overflow",
    "unsupported-contextual-ceiling",
    "unsupported-host-ceiling",
    "unsupported-instrumentation",
    "unsupported-producer",
    "unsupported-capture-clock",
    "capture-refused",
    "slot-overflow",
    "expired",
];
fn code(
    t: &mut Tape<'_>,
    seed: Option<&str>,
    registry: &'static [&'static str],
) -> Result<&'static str> {
    let tag = seed
        .map(|s| {
            registry
                .iter()
                .position(|&r| r == s)
                .ok_or(SupportError("grant code"))
        })
        .transpose()?
        .map_or(Ok(0), |i| {
            u16::try_from(i.saturating_add(1)).map_err(|_| SupportError("grant code"))
        })?;
    let tag = t.u16(tag)?;
    registry
        .get(usize::from(tag.saturating_sub(1)))
        .copied()
        .filter(|_| tag != 0)
        .ok_or(SupportError("grant code"))
}
fn effective(t: &mut Tape<'_>, s: Option<&SupportCapture>) -> Result<SupportCapture> {
    let slot = t.u64(s.map_or(0, |s| s.slot))?;
    let scope = scope(t, s.map(|s| &s.scope))?;
    require(t.u8(1)? == 1 && t.u8(1)? == 1, "capture kind or level")?;
    let remaining_lines = t.u64(s.map_or(0, |s| s.remaining_lines))?;
    let remaining_bytes = t.u64(s.map_or(0, |s| s.remaining_bytes))?;
    require(
        remaining_lines <= 1024 && remaining_bytes <= 1_048_576,
        "capture budget",
    )?;
    let deadline = t.option(s.and_then(|s| s.deadline.as_ref()), |t, s| {
        t.time(s.copied().unwrap_or(ZERO_TIME))
    })?;
    let lease = number_option(t, s.and_then(|s| s.lease.as_ref()))?;
    Ok(SupportCapture {
        slot,
        scope,
        remaining_lines,
        remaining_bytes,
        deadline,
        lease,
    })
}
fn grant(t: &mut Tape<'_>, s: Option<&SupportGrant>) -> Result<SupportGrant> {
    let incarnation = incarnation(t, s.map(|s| s.incarnation))?;
    let state = code(t, s.map(|s| s.state), &STATES)?;
    let reason = t.option(s.and_then(|s| s.reason.as_ref()), |t, s| {
        code(t, s.copied(), &GRANT_REASONS)
    })?;
    let future_issued_lead_secs =
        number_option(t, s.and_then(|s| s.future_issued_lead_secs.as_ref()))?;
    let observed = t.option(s.and_then(|s| s.observed.as_ref()), record)?;
    let accepted = t.option(s.and_then(|s| s.accepted.as_ref()), record)?;
    let effective = t.option(s.and_then(|s| s.effective.as_ref()), effective)?;
    let slot = t.option(s.and_then(|s| s.slot.as_ref()), |t, s| {
        t.u64(s.copied().unwrap_or(0))
    })?;
    let capture_revision = t.u64(s.map_or(0, |s| s.capture_revision))?;
    let high_revision = t.u64(s.map_or(0, |s| s.high_revision))?;
    let high_generation = t.u64(s.map_or(0, |s| s.high_generation))?;
    let retired_generation = t.u64(s.map_or(0, |s| s.retired_generation))?;
    let c = s.map_or(ReaderCounters::default(), |s| s.reader_counters);
    let reader_counters = ReaderCounters {
        refreshes: t.u64(c.refreshes)?,
        reloads: t.u64(c.reloads)?,
        refusals: t.u64(c.refusals)?,
        unreadable: t.u64(c.unreadable)?,
        stalled: t.u64(c.stalled)?,
        applications: t.u64(c.applications)?,
        retirements: t.u64(c.retirements)?,
    };
    let c = s.map_or(CaptureCounters::default(), |s| s.capture_counters);
    let capture_counters = CaptureCounters {
        admitted: t.u64(c.admitted)?,
        budget_suppressed: t.u64(c.budget_suppressed)?,
        suppressed: t.u64(c.suppressed)?,
        expiry_suppressed: t.u64(c.expiry_suppressed)?,
        expired: t.u64(c.expired)?,
        contention: t.u64(c.contention)?,
        malformed: t.u64(c.malformed)?,
        oversize: t.u64(c.oversize)?,
        queued: t.u64(c.queued)?,
        sink_drops: t.u64(c.sink_drops)?,
    };
    Ok(SupportGrant {
        incarnation,
        state,
        reason,
        future_issued_lead_secs,
        observed,
        accepted,
        effective,
        slot,
        capture_revision,
        high_revision,
        high_generation,
        retired_generation,
        reader_counters,
        capture_counters,
    })
}
