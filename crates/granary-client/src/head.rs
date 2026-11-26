// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Hint-first head discovery with revalidation, forward probing, `max_seq`
//! fallback and a per-volume freshness floor. `granary_core::clock::Clock`'s own
//! doc names this module as the seam's first production consumer of
//! `now()`: the hint TTL is the first thing in this workspace that reads a
//! clock for anything other than minting a timestamp field.
//!
//! **Two senses of "anchor" meet in this module and stay distinct.**
//! [`crate::resolve::RootVerifier`] holds the signing-key TRUST anchor (the
//! key a root's signature must come from), decided once at configuration
//! time. The cache's anchor is a different thing entirely: a per-volume,
//! per-cache-dir FRESHNESS floor, read and raised through
//! [`crate::cache::Cache`]'s [`crate::cache::HeadAnchor`]/
//! [`crate::cache::PersistedHint`], and its type is named `HeadAnchor` for
//! exactly that reason. A resolve
//! consults BOTH in the same few lines (the verifier decides who to
//! trust; the floor decides how stale a trusted answer may be), which is
//! why the naming collision would have been worse than usual.
//!
//! **Discovery order (normative):**
//!
//! 1. Read the anchor floor — cheap, local, no wire call. Reading it
//!    early and APPLYING it early are different things: the
//!    floor is never itself a search step or a head candidate, only a
//!    refusal gate on whatever candidate the steps below land on.
//! 2. If the persisted hint is fresh (age under the jittered TTL) and
//!    at or above the floor (in steady state the two are EQUAL — the
//!    hint and the floor are written together, from the same accepted
//!    head), answer with it directly — zero wire calls. A hint
//!    STRICTLY BELOW the floor is IGNORED, not refused: an
//!    ordinary crash-window staleness (an explicit `resolve_at` having
//!    raised the floor without touching the hint), not evidence of a
//!    rollback, so it falls through to the slower path instead of a
//!    hard refusal.
//! 3. Otherwise revalidate over the wire (`RootStore::read_hint`, `If-
//!    None-Match` when a token is cached) and forward-probe
//!    (`get_root(hint.checked_add(1))`, capped) from whatever hint that
//!    produces.
//! 4. With no hint at all (never persisted, and the wire answered
//!    `Missing`), fall back to one `max_seq` call — the expensive
//!    question, kept rare by the hint existing in the first place.
//!
//! The floor then applies ONCE, to whatever candidate step 2, 3 or 4
//! landed on: below it is [`crate::resolve::ResolveError::StaleHead`],
//! naming both seqs; at or above it, the candidate stands.
//!
//! **Step 2's zero-wire shortcut is why the transport-down degraded trigger
//! lives in `resolve.rs`, not here.** While the persisted hint is
//! fresh, this module answers a head candidate WITHOUT ever touching the wire
//! — so a transport that has gone down is invisible to discovery itself; the
//! first thing that can notice is whichever wire call `resolve.rs` makes
//! next on that candidate's behalf (typically its own `get_root`). The
//! degraded fallback therefore wraps the WHOLE head-resolve
//! (`resolve_head_verified`), not merely a call into this module — see
//! `resolve.rs`'s own module doc, "Degraded reads".
//!
//! **Single-flight.** Concurrent head questions for one volume inside
//! one process coalesce onto one wire poll, through
//! `std::sync::Mutex<BTreeMap<String, tokio::sync::watch::Receiver<..>>>`
//! keyed by volume (`HashMap` is banned at this crate's lib root). The
//! lock scope NEVER crosses an `await`: [`HeadContext::join_or_lead`]
//! takes the lock, decides leader-or-follower and returns, all
//! synchronously: a leader awaits the real work OUTSIDE the lock, and a
//! follower awaits the watch channel's `changed()` OUTSIDE the lock too.
//!
//! **The jitter figure is a labelled, chosen SIMPLIFICATION**:
//! `±20%` jitter over a fixed 60s TTL, re-drawn from the
//! [`granary_core::rng::Rng`] seam EACH poll cycle (never cached across
//! one), chosen over probabilistic early expiration (`XFetch` — Vattani,
//! Chierichetti, Lowenstein, "Optimal Probabilistic Cache Stampede
//! Prevention", PVLDB 8(8):886-897, 2015). Revisit only with
//! fleet-scale evidence.
//!
//! **The forward-probe walk is CAPPED** at [`FORWARD_PROBE_MAX`]
//! consecutive probes. Uncapped, a hostile origin that answers `Some`
//! to every seq it is asked commands an unbounded walk, each probe up to
//! `ROOT_MAX_BYTES` — a `DoS` a reader has no reason to be exposed to
//! when one `max_seq` call already answers the same question. Past the
//! cap, that one call answers instead.
//!
//! **Purity.** Everything here lives in `granary-client`; `granary-core`
//! gains only the doc-sentence pointer above. Both determinism seams
//! this module consumes ([`granary_core::clock::Clock`],
//! [`granary_core::rng::Rng`]) are taken from the caller — this module
//! never constructs a `ProcessRng` or reads the wall clock itself, so a
//! sim-driven caller can hand it its own deterministic implementations.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use tokio::sync::watch;

use granary_core::clock::Clock;
use granary_core::rng::Rng;
use granary_core::root::VolumeName;
use granary_core::rootstore::{HintRead, HintToken, RootStore, RootStoreError, is_reserved_seq};
use granary_core::sheaf::Timestamp;

use crate::cache::{Cache, PersistedHint};
use crate::resolve::ResolveError;

/// Hint-poll TTL, integer millis: `48_000 + rng.below(24_000)` spans
/// `[48s, 72s)`, ±20% around the 60s default. Integer throughout
/// — no float, no cast lint.
const JITTER_BASE_MS: u64 = 48_000;
const JITTER_SPAN_MS: u64 = 24_000;

/// Forward-probe cap: consecutive `get_root` calls before one
/// `max_seq` call answers instead. See the module doc's `DoS` rationale.
const FORWARD_PROBE_MAX: u32 = 32;

/// The discovery context: the `Clock` and `Rng` seams a resolve's
/// head-discovery needs (never constructed internally — see the module
/// doc's purity section) plus the single-flight coalescing map.
///
/// **One `HeadContext` is bound to ONE `(RootStore, cache dir)` pairing;
/// never share one across two stores or two cache dirs.** The
/// single-flight map is keyed by volume NAME alone, so a context shared
/// across two stores would coalesce a same-named volume's discovery
/// across them — a follower would receive the leader's seq and `ETag`
/// from the OTHER store. The rollback half of that hazard is
/// already closed (the floor is applied per-caller in `discover_head`,
/// and a candidate the store cannot resolve triggers a bounded `max_seq`
/// retry), so what remains is token/seq HYGIENE for a configuration no
/// shipped caller uses — every current caller (`main.rs`, the sim, the
/// tests) builds a fresh context per resolve. Keying the map by store
/// identity, or owning it inside a per-store client object, is still
/// the deferred fix for cross-store coalescing;
/// until then this pairing constraint is the contract.
pub struct HeadContext {
    clock: Box<dyn Clock>,
    rng: Mutex<Box<dyn Rng + Send>>,
    inflight: Mutex<BTreeMap<String, watch::Receiver<Share>>>,
}

/// One volume's single-flight slot: `None` while the leader's work is
/// still running, `Some` once it has published a result every follower
/// clones out.
type Share = Option<Result<Discovered, DiscoveryError>>;

impl std::fmt::Debug for HeadContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeadContext").finish_non_exhaustive()
    }
}

impl HeadContext {
    /// Build a discovery context from the caller's own `Clock`/`Rng`
    /// implementations — the CLI hands it `WallClock`/`ProcessRng` at
    /// the edge, the sim hands it its own seeded implementations, tests
    /// hand it pinned/seeded ones. Never call `ProcessRng::new()` or
    /// read the wall clock inside library code on this module's behalf.
    #[must_use]
    pub fn new(clock: Box<dyn Clock>, rng: Box<dyn Rng + Send>) -> Self {
        Self {
            clock,
            rng: Mutex::new(rng),
            inflight: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn now(&self) -> Timestamp {
        self.clock.now()
    }

    /// Re-drawn EACH poll cycle — never cached across one, which is what
    /// keeps a restarted fleet from phase-locking to its restart storm
    /// (a once-per-process offset would not).
    fn jitter_ttl_ms(&self) -> u64 {
        let mut rng = self.rng.lock().unwrap_or_else(PoisonError::into_inner);
        JITTER_BASE_MS + rng.below(JITTER_SPAN_MS)
    }

    /// Decide, SYNCHRONOUSLY and under one lock scope, whether this call
    /// joins an in-flight poll for `volume` or becomes its leader. The
    /// lock is taken, inspected, possibly inserted into, and dropped —
    /// never held across an `await`.
    fn join_or_lead(&self, volume: &str) -> Role {
        let mut map = self.inflight.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(rx) = map.get(volume) {
            Role::Follower(rx.clone())
        } else {
            let (tx, rx) = watch::channel(None);
            map.insert(volume.to_owned(), rx);
            Role::Leader(tx)
        }
    }

    /// The leader's own cleanup, once its work has finished — also one
    /// short, synchronous lock scope.
    fn clear_inflight(&self, volume: &str) {
        let mut map = self.inflight.lock().unwrap_or_else(PoisonError::into_inner);
        map.remove(volume);
    }
}

enum Role {
    Follower(watch::Receiver<Share>),
    Leader(watch::Sender<Share>),
}

/// Clears one volume's single-flight slot when dropped. The leader arm
/// holds one so the slot is cleared even when the leader FUTURE is
/// dropped mid-await (caller cancellation): a leaked entry would
/// otherwise hand every later caller for that volume a follower's view
/// of a channel whose sender is gone — a typed error forever, wedging
/// the volume's discovery for the life of the process. On the normal
/// path it is dropped explicitly AFTER the send, preserving the
/// publish-before-clear window rationale in [`discover_head`].
struct ClearInflightOnDrop<'a> {
    ctx: &'a HeadContext,
    volume: &'a str,
}

impl Drop for ClearInflightOnDrop<'_> {
    fn drop(&mut self) {
        self.ctx.clear_inflight(self.volume);
    }
}

/// What discovery landed on: the accepted head seq, the wire hint
/// confirmation it last saw (`None` on the zero-wire fresh path, where
/// nothing was confirmed this call), and whether the seq itself was
/// HINT-DERIVED — see [`Discovered::hint_derived`].
#[derive(Debug, Clone)]
pub(crate) struct Discovered {
    pub(crate) seq: u64,
    /// The wire hint `ETag` this call last saw, paired with the
    /// WIRE-confirmation instant it was read at — captured INSIDE
    /// discovery, at the `read_hint` 304/200 itself, never a later
    /// reading taken after the resolve that follows discovery has
    /// completed. `None` on the zero-wire fresh path.
    pub(crate) wire_confirmation: Option<WireConfirmation>,
    /// Whether `seq` was derived from a HINT (the fresh zero-wire
    /// shortcut, a `Current`/`NotModified` wire answer, or a
    /// forward-probe walked from one of those) rather than
    /// authoritatively from [`RootStore::max_seq`] alone. A hint can
    /// name a seq the store has no root for (a fresh persisted hint
    /// after a store rollback, a `Current`/`NotModified` seq the store
    /// no longer backs, or a forward-probe base past the real roots);
    /// `resolve_head_verified` uses this flag to decide whether a
    /// `NoHead` resolve of the candidate is worth ONE bounded retry via
    /// [`discover_head_forced_max_seq`] rather than a final answer.
    pub(crate) hint_derived: bool,
}

/// The wire hint token + the instant it was confirmed at — see
/// [`Discovered::wire_confirmation`].
#[derive(Debug, Clone)]
pub(crate) struct WireConfirmation {
    pub(crate) token: HintToken,
    pub(crate) stamp_secs: i64,
}

/// Discovery's own error shape — small and `Clone` so the single-flight
/// channel can hand every follower an owned copy. Converted to
/// [`ResolveError`] at [`discover_head`]'s return, never leaked past it.
/// The `StaleHead` refusal is NOT a member here: it is applied
/// per-CALLER, after coalescing, in [`discover_head`] itself — never
/// baked into the one shared answer every caller for a volume clones (a
/// follower must be gated against ITS OWN cache dir's floor, which can
/// differ from the leader's).
#[derive(Debug, Clone)]
enum DiscoveryError {
    NoHead,
    Remote(RootStoreError),
}

impl From<DiscoveryError> for ResolveError {
    fn from(e: DiscoveryError) -> Self {
        match e {
            DiscoveryError::NoHead => Self::NoHead,
            DiscoveryError::Remote(e) => Self::Remote(e),
        }
    }
}

/// This caller's own freshness floor for `volume`, read once — shared by
/// [`discover_head`] (applied per-caller, after coalescing) and
/// [`discover_head_forced_max_seq`] (the bounded backstop below).
/// Read-only: never requires a mutable borrow of `cache`, so it can be
/// read BEFORE `cache` is (possibly) moved into the leader's uncoalesced
/// call.
fn read_floor(cache: Option<&Cache>, volume: &str) -> Option<u64> {
    let vol = VolumeName::new(volume.to_owned()).ok()?;
    cache?.read_anchor(&vol).map(|a| a.seq)
}

/// Refuse `seq` if it sits below `floor` — a freshness check applied to
/// a candidate that discovery has already decided on (never itself a
/// search step).
fn refuse_below_floor(seq: u64, floor: Option<u64>) -> Result<(), ResolveError> {
    if let Some(f) = floor
        && seq < f
    {
        return Err(ResolveError::StaleHead {
            candidate: seq,
            anchor: f,
        });
    }
    Ok(())
}

/// Discover `volume`'s head — the single-flight-coalesced entry point
/// `resolve_head`/`resolve_head_verified` call. See the module doc for
/// the discovery order and the single-flight mechanism.
pub(crate) async fn discover_head<R: RootStore>(
    ctx: &HeadContext,
    remote: &R,
    volume: &str,
    cache: Option<&mut Cache>,
) -> Result<Discovered, ResolveError> {
    // THIS CALLER's own floor, read once, BEFORE either branch below
    // runs — read-only, so it needs no mutable borrow and can be taken
    // before `cache` is (possibly) moved into the leader's uncoalesced
    // call. Applied AFTER coalescing, to whatever candidate comes back,
    // for BOTH the leader and follower arms: a follower cloning the
    // leader's answer must be gated against ITS OWN cache dir's floor,
    // which can differ from the leader's — the leader's own internal
    // shortcut gate (inside `discover_head_uncoalesced`, scoped to the
    // zero-wire fresh-hint check alone) is not a substitute for this.
    let caller_floor = read_floor(cache.as_deref(), volume);

    let discovered = match ctx.join_or_lead(volume) {
        Role::Follower(mut rx) => loop {
            if let Some(result) = rx.borrow_and_update().clone() {
                break result.map_err(ResolveError::from);
            }
            if rx.changed().await.is_err() {
                // The leader's sender was dropped without ever sending —
                // unreachable in practice (the leader below always sends
                // before returning, even on its own error path), typed
                // rather than panicked on, per this crate's rule against
                // panicking on anything reachable from a stored object
                // (the leader's own failure IS reachable from remote
                // state).
                break Err(ResolveError::Remote(RootStoreError::Backend(
                    "single-flight leader dropped before publishing a result".to_owned(),
                )));
            }
        },
        Role::Leader(tx) => {
            // Cleared on EVERY exit from this arm — including this
            // future being dropped mid-await (caller cancellation),
            // which would otherwise leak the map entry and wedge every
            // later call for this volume onto a dead channel.
            let clear = ClearInflightOnDrop { ctx, volume };
            // Last use of `cache` in this function, so a plain move —
            // no reborrow needed (matches `resolve_at_verified`'s own
            // "last use" idiom).
            let result = discover_head_uncoalesced(ctx, remote, volume, cache).await;
            // Publish BEFORE clearing the slot: a caller that arrives in
            // the narrow window between this line and the next sees the
            // map entry still present, joins as a follower, and reads
            // the already-published answer straight off the channel —
            // no redundant wire call. Clearing first would instead make
            // that caller a spurious second leader.
            let _ = tx.send(Some(result.clone()));
            drop(clear);
            result.map_err(ResolveError::from)
        }
    }?;

    refuse_below_floor(discovered.seq, caller_floor)?;
    Ok(discovered)
}

/// A bounded backstop, called from `resolve_head_verified` AT MOST
/// ONCE per resolve, only when a HINT-DERIVED candidate
/// ([`Discovered::hint_derived`]) failed to resolve with
/// [`ResolveError::NoHead`]: re-run discovery with the hint path
/// disabled entirely, consulting [`RootStore::max_seq`] directly. A
/// max_seq-derived candidate that STILL yields `NoHead` is a genuinely
/// empty volume, not a wedge.
///
/// Deliberately bypasses the single-flight coalescing map: this is a
/// rare recovery path taken by one caller after ITS OWN failed resolve,
/// never the ordinary poll every caller for a volume shares, so it needs
/// no leader/follower choreography — a concurrent second caller hitting
/// this path at the same time simply makes its own bounded `max_seq`
/// call too, paying the same one-call cost as the ordinary no-hint fallback.
pub(crate) async fn discover_head_forced_max_seq<R: RootStore>(
    remote: &R,
    volume: &str,
    cache: Option<&mut Cache>,
) -> Result<Discovered, ResolveError> {
    let floor = read_floor(cache.as_deref(), volume);
    let candidate = remote
        .max_seq(volume)
        .await
        .map_err(ResolveError::Remote)?
        .ok_or(ResolveError::NoHead)?;
    refuse_below_floor(candidate, floor)?;
    Ok(Discovered {
        seq: candidate,
        wire_confirmation: None,
        hint_derived: false,
    })
}

async fn discover_head_uncoalesced<R: RootStore>(
    ctx: &HeadContext,
    remote: &R,
    volume: &str,
    cache: Option<&mut Cache>,
) -> Result<Discovered, DiscoveryError> {
    let vol = VolumeName::new(volume.to_owned()).ok();
    let anchor = match (&vol, cache) {
        (Some(v), Some(c)) => c.read_anchor(v),
        _ => None,
    };
    let floor = anchor.as_ref().map(|a| a.seq);

    // Step 2: the fresh-hint, zero-wire shortcut. `hint.seq >= floor`
    // (not a STRICT `>`): in steady state the persisted hint's seq
    // EQUALS the floor by construction (`PersistedHint`'s own doc — the
    // two are written together, from the same accepted head), so a
    // strict `>` would defeat the shortcut on every ordinary call, not
    // only a stale one. Only a hint STRICTLY BELOW the floor (an
    // explicit `resolve_at` having raised the floor past the last hint
    // write, without touching the hint — the one write site that
    // doesn't) is IGNORED, not refused: that
    // case falls through to the slower path instead of trusting the
    // hint OR hard-refusing it, so forward-probing can walk past it to
    // the true current head.
    if let Some(hint) = anchor.as_ref().and_then(|a| a.hint.as_ref())
        && is_fresh(hint, ctx)
        && floor.is_none_or(|f| hint.seq >= f)
    {
        return Ok(Discovered {
            seq: hint.seq,
            wire_confirmation: None,
            hint_derived: true, // an unconfirmed local hint, never wire-checked this call
        });
    }

    // Step 2 (else) / 3 / 4: revalidate over the wire, or read for the
    // first time, then forward-probe or fall back to max_seq.
    let cached_token = anchor
        .as_ref()
        .and_then(|a| a.hint.as_ref())
        .map(|h| HintToken(h.token.clone()));
    // The hint route is ADVISORY — a transport/status error
    // on it must degrade to the `max_seq` fallback exactly like
    // `HintRead::Missing`, never abort a discovery `max_seq` alone would
    // answer. Only a `max_seq` failure below is fatal.
    let hint_read = remote.read_hint(volume, cached_token.as_ref()).await.ok();
    // Captured HERE, at the wire confirmation itself (a 304 or a 200) —
    // never a later reading taken after the resolve that follows
    // discovery has completed. `None` when there was no wire read at all
    // (the error-degraded path above, or `HintRead::Missing` below).
    let wire_now = hint_read.is_some().then(|| ctx.now());

    let (probe_from, wire_confirmation) = match hint_read {
        None | Some(HintRead::Missing) => (None, None),
        Some(HintRead::NotModified) => {
            let seq = anchor.as_ref().and_then(|a| a.hint.as_ref()).map(|h| h.seq);
            let confirmation = match (cached_token, wire_now) {
                (Some(token), Some(now)) => Some(WireConfirmation {
                    token,
                    stamp_secs: now.secs,
                }),
                _ => None,
            };
            (seq, confirmation)
        }
        Some(HintRead::Current { seq, token }) => {
            let confirmation = wire_now.map(|now| WireConfirmation {
                token,
                stamp_secs: now.secs,
            });
            (Some(seq), confirmation)
        }
    };

    // The provenance flag: HINT-DERIVED whenever the candidate came
    // through the hint path at all (a `Current`/`NotModified` seq, or a
    // forward-probe walked from one) — never only from a SUCCESSFUL
    // forward-probe, because the vulnerable case (`forward_probe_or_
    // fallback` accepting `hint_seq` itself as `last_seen` without ever
    // confirming it via `get_root`) lives inside that walk too. `false`
    // only for the direct, no-hint-at-all `max_seq` path below.
    let hint_derived = probe_from.is_some();

    let candidate = match probe_from {
        Some(hint_seq) => forward_probe_or_fallback(remote, volume, hint_seq).await?,
        None => remote
            .max_seq(volume)
            .await
            .map_err(DiscoveryError::Remote)?
            .ok_or(DiscoveryError::NoHead)?,
    };

    // The freshness-floor refusal is NOT applied here — see `discover_head`,
    // which applies it per-caller, after coalescing.

    Ok(Discovered {
        seq: candidate,
        wire_confirmation,
        hint_derived,
    })
}

/// `get_root(hint.checked_add(1))`, walked forward until a `404`
/// (`Ok(None)`) names the head, capped at [`FORWARD_PROBE_MAX`]
/// consecutive probes. `checked_add` is total on
/// `hint_seq == u64::MAX`: a reader built to the
/// unchecked `hint + 1` would panic under overflow-checks or wrap to
/// the never-valid seq 0, on exactly the accept case
/// `RootStore::read_hint`'s own module docs name as pinned.
///
/// **The walk's stopping rule assumes publish is strictly CONTIGUOUS
/// (`max+1`).** The first `get_root` that answers `None` is
/// treated as the head boundary, which is correct only because a
/// publish never skips a seq — under that assumption, once `hint_seq +
/// k` exists and `hint_seq + k + 1` does not, nothing published later
/// can occupy a lower seq either. If a hint names a seq the store has NO
/// root for at all (a stale local hint after a store rollback, or a
/// wire-confirmed seq the store no longer backs), this walk's OWN
/// `get_root(hint_seq + 1)` check never confirms `hint_seq` itself —
/// only probes PAST it — so a store with nothing at `hint_seq + 1`
/// makes this function return `hint_seq` UNCONFIRMED. A bounded
/// `max_seq` retry in `resolve_head_verified` (triggered by
/// [`Discovered::hint_derived`]) is the backstop for exactly that case:
/// it re-runs discovery with the hint path disabled when the returned
/// candidate then fails to resolve at all.
async fn forward_probe_or_fallback<R: RootStore>(
    remote: &R,
    volume: &str,
    hint_seq: u64,
) -> Result<u64, DiscoveryError> {
    let mut last_seen = hint_seq;
    let mut confirmed = false;
    let mut steps: u32 = 0;
    let mut probe = hint_seq.checked_add(1);
    // Walk forward while there is a next seq to probe, it is a LEGAL
    // (non-reserved) seq, and we are under the cap. Stopping BEFORE the
    // reserved seq `u64::MAX` is deliberate (it is forbidden as a
    // head): a hostile store answering `Some` there must never become
    // `last_seen` and displace the highest LEGAL confirmed seq below it —
    // the walk would otherwise discard a confirmed `u64::MAX - 1` for a
    // lagging/lying `max_seq`, serving an older head over a newer one it
    // had just confirmed.
    while let Some(p) = probe {
        if is_reserved_seq(p) || steps >= FORWARD_PROBE_MAX {
            break;
        }
        steps += 1;
        match remote
            .get_root(volume, p)
            .await
            .map_err(DiscoveryError::Remote)?
        {
            Some(_) => {
                last_seen = p;
                confirmed = true;
                probe = p.checked_add(1);
            }
            None => return Ok(last_seen),
        }
    }
    // No `None` boundary was found: the walk ran out of legal seqs (the
    // reserved boundary), hit the cap, or exhausted `u64`. `last_seen` is
    // a WALK-CONFIRMED legal seq iff `confirmed`; otherwise it is still
    // the unconfirmed `hint_seq`, which F1's bounded retry backstops.
    let max_answer = remote
        .max_seq(volume)
        .await
        .map_err(DiscoveryError::Remote)?;
    match (confirmed, max_answer) {
        // A confirmed legal seq is a valid FLOOR for the answer: a
        // `max_seq` that lags or lies below it must never win.
        (true, Some(m)) => Ok(m.max(last_seen)),
        (true, None) => Ok(last_seen),
        // Nothing confirmed — the hint was never validated by this walk;
        // trust `max_seq` (or `NoHead`), and let the resolve's F1 retry
        // catch a still-unresolvable candidate.
        (false, Some(m)) => Ok(m),
        (false, None) => Err(DiscoveryError::NoHead),
    }
}

/// Whether a persisted hint is still inside its jittered TTL. A FUTURE
/// stamp (`now < stamp`) is STALE, never infinitely fresh —
/// `age_secs` negative or unrepresentable as `u64` both refuse.
fn is_fresh(hint: &PersistedHint, ctx: &HeadContext) -> bool {
    let now = ctx.now();
    let age_secs = now.secs.saturating_sub(hint.stamp_secs);
    let Ok(age_secs) = u64::try_from(age_secs) else {
        return false;
    };
    let ttl_ms = ctx.jitter_ttl_ms();
    age_secs.saturating_mul(1000) < ttl_ms
}

#[cfg(test)]
mod tests;
