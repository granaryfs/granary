// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Structure: walk the manifest's nodes into residency, one bounded
//! round at a time, and speculate ahead of the walk without letting
//! speculation displace what the walk actually asked for.
//!
//! **What breaks when this module is wrong:** the walk asks for the
//! same node twice and pays twice; a round reports done while a node
//! is still absent; or the prefetch pool evicts a node the walk is
//! about to need — a hint that was supposed to save a fetch causing
//! one. The pool's cap, the provenance that decides which entries are
//! evictable, and the demotion that outlives the round that made it
//! are all one subject: **what the walk is allowed to hold on
//! speculation**.
//!
//! It owns the round loop ([`fetch_tree_structure`]), the per-round
//! log, the hint pass and its provenance ([`hints_with_provenance`],
//! [`hints_for_round`], [`demote_pooled_provenance`]) and the prefetch
//! pool ([`prefetch_structure_nodes`], [`POOL_CAP_BYTES`]). It does
//! NOT own the chain check, the reachability check or the emission
//! walk that consumes what it fetched — those are the parent's and its
//! siblings'.
//!
//! Out-of-line, a child one flat
//! level under `resolve/`, beside
//! `emission` and `budget`.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use granary_core::binmap::ShardEntry;
use granary_core::binstore::BinStore;
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::manifest::{self, MANIFEST_NODE_MAX_BYTES, Step, TreeStats, ValidateError};
use granary_core::rootstore::RootStoreError;

use crate::cache::Cache;
use crate::fetcher::{FetchError, Fetcher, Want};

// The CLOSED REACH SET for this child's parent dependencies, imported BY
// NAME so the list is short and an unused one is `unused_imports`.
// `MetadataBudget` is defined in the sibling `budget` module and is
// imported here through the parent's `pub(crate) use` re-export of
// it, so every name on the set is spelled `super::`.
use super::{MetadataBudget, ResolveError, map_fetch_err};

/// Test-only visit accounting for `fetch_tree_structure`'s VALIDATION
/// closure (never the hint closure): how many times the walk asked
/// for any id, and how many times for the root. The cursor asks it
/// at most
/// twice when the root's OWN WALK completes within one round — its
/// B-tree AND the spill trees its leaves name, because `walk_dir`
/// calls `validate_file_grains` inside that same walk, so a `Need`
/// raised in a leaf's spill tree also leaves the cursor
/// `Entering(root)`. A one-node root with inline files, which is what
/// the chain fixtures these rows build, satisfies it; so does one
/// whose missing nodes all pool in the first pass. A `Need` raised
/// inside a directory's own B-tree leaves the cursor `Entering` that
/// directory, so a root that takes several rounds to become resident
/// is re-asked once per round — 74 times on the measured 787-node
/// directory, whose every round stops inside the root's own walk.
#[cfg(test)]
#[derive(Default, Debug)]
pub(crate) struct VisitCounter {
    pub(crate) root_visits: u64,
    pub(crate) total_visits: u64,
}

/// The round loop's instrument: cumulative counters and ONE `INFO`
/// event per round, so the measurement reads the OBSERVED round
/// count out of the daemon's stderr instead of restating a figure,
/// and the same event carries the per-round hint and admission
/// counts. Emitted AFTER promotion and BEFORE dispatch, so a round
/// that REACHES dispatch is on the record with the counters as they
/// stood BEFORE that round's dispatch — a terminal round fetches
/// nothing, so on `done` those totals are complete, while a `need`
/// round's own need, hints and admits are added after this line. A
/// `ValidateError` outcome DOES get its `outcome=error` line,
/// because this call precedes dispatch on all three arms. What has
/// no terminal line is a resolve that dies OUTSIDE the emit:
/// promotion `?`s on a budget refusal BEFORE this call, and
/// `fetch_one_need` `?`s AFTER this round's `need` line. A round-timing harness
/// reading the last line per resolve must therefore treat a trailing
/// `need` as "failed or still running", never as success. The field
/// names are what the round-timing harness matches; renaming
/// one requires a matching harness change. So does the LEVEL. This is `INFO`
/// deliberately: the round-timing harness reads a production daemon's stderr at
/// `gran`'s default level, takes its first timestamp from the FIRST
/// of these lines to derive per-round wall time, and its own
/// self-test fixture is written with `INFO` in the line. Demoting it
/// to `debug!` would break all three, and running the daemon at
/// debug to see it again would perturb the wall time the round-timing harness
/// exists to measure. Keep this event at `INFO` so the harness can
/// read it at the default level without changing the measured workload.
#[derive(Debug, Default)]
struct RoundLog {
    round: u64,
    needs: u64,
    hints: u64,
    admits: u64,
}

impl RoundLog {
    fn emit(&self, outcome: &Result<Step, ValidateError>, pool_len: usize, pool_used: u64) {
        let outcome = match outcome {
            Ok(Step::Done(_)) => crate::observe::WalkOutcome::Done,
            Ok(Step::Need(_)) => crate::observe::WalkOutcome::Need,
            Err(_) => crate::observe::WalkOutcome::Error,
        };
        // The structure-walk instrument keeps its INFO level, resolve target,
        // field names and text prefix for acquisition counters.
        crate::observe::OperatorDiagnostic::structure_walk(
            self.round,
            outcome,
            self.needs,
            self.hints,
            self.admits,
            (pool_len) as u64,
            pool_used,
        )
        .emit();
    }
}

/// Fetch every manifest STRUCTURE node the walk visits, through
/// `fetcher`, and validate the whole tree exactly as strictly as
/// `validate_dir_tree` always has (the bounded walk, its
/// grain-list leaf budget, the sheaf cross-check — none of this moves).
///
/// **The round-loop shape, and why.** `granary-core` stays pure (no I/O)
/// so the walk's `fetch` closure is, and must stay, SYNCHRONOUS — the
/// bounded walk's own machinery (`DEPTH_MAX`, the leaf budget) cannot
/// be reimplemented here without reopening exactly the cost attack that
/// machinery closes. So this drives a [`manifest::TreeCursor`]
/// in rounds. Each round: (1) `resume` the walk over what is
/// resident so far — the charged `nodes` map and the speculative `pool`;
/// (2) PROMOTE every pool node the walk just asked for into `nodes`, in
/// the walk's own ask order and with the same admission a need fetch
/// pays, BEFORE the resume's outcome is dispatched on any arm — so a
/// budget refusal pre-empts a validation error found later in the same
/// resume, and a `Done` never leaves a consumed pool node outside
/// `nodes`, which `check_reachable_grains` reads; (3) dispatch: `Done`
/// returns, an error is [`ResolveError::Tree`], and a [`Step::Need`]
/// names the ONE node the walk cannot continue without, fetched on the
/// need path (`fetch_one_need`) and charged at the node ceiling plus the
/// per-node overhead; (4) the cursor's hint pass
/// (`prefetch_hints`) names what the walk will ask for next, and
/// `prefetch_structure_nodes` fetches what fits into the pool —
/// speculative bytes that are NEVER charged to `budget`, bounded by
/// `POOL_CAP_BYTES` on their own, and dropped (never an error) when a
/// hint cannot be served. The cursor resumes where it stopped instead of
/// replaying from the root, so the walk's asks are linear in the nodes —
/// 2n on a one-child chain, where replaying from the root on every miss
/// would ask n(n+3)/2 (`fetch_tree_structure_asks_linearly_not_triangularly`).
///
/// The closure handed to `resume` is MONOTONE per id:
/// nothing leaves `nodes`, and a pool node only ever moves
/// INTO `nodes` — eviction takes never-asked queued roots only. The
/// closure handed to `prefetch_hints` records ONE thing, which POOLED
/// ids the pass reached, and returns exactly the bytes it would have
/// returned without the record — so the emission is unchanged and only
/// [`demote_pooled_provenance`] sees the difference. `visited` is
/// every id the walk asked for; on `Ok` it equals `nodes.keys()`.
///
/// A missing id the binmap does not map at all is not a fetch target —
/// it is [`ResolveError::Tree`], exactly as an eagerly-fetched walk
/// would report it.
pub(super) async fn fetch_tree_structure<R: BinStore>(
    fetcher: &mut Fetcher<'_, R>,
    mut cache: Option<&mut Cache>,
    entries: &BTreeMap<GrainId, ShardEntry>,
    bins: &[[u8; DIGEST_LEN]],
    root: &GrainId,
    budget: &mut MetadataBudget,
    #[cfg(test)] visits: Option<&mut VisitCounter>,
) -> Result<(BTreeMap<GrainId, Vec<u8>>, TreeStats, BTreeSet<GrainId>), ResolveError> {
    let mut nodes: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    // Speculative: prefetched by the hint pass, NEVER charged to the
    // budget, promoted into `nodes` only when the walk asks.
    let mut pool: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    let mut pool_used: u64 = 0;
    // Insertion order of the pool, and each entry's ADMISSION provenance
    // — which is IMMUTABLE once written. Eviction takes the oldest entry
    // that `is_eviction_victim` still accepts: admitted as a queued root
    // AND not since demoted by `demoted` below. Entering-directory hints
    // are never victims at all.
    let mut pool_order: VecDeque<(GrainId, bool)> = VecDeque::new(); // (id, is_queued_root)
    let mut hint_tried: BTreeSet<GrainId> = BTreeSet::new();
    // Pooled ids some hint pass has REACHED through the directory being
    // entered. Monotone for the life of a pool entry — see
    // `demote_pooled_provenance` for why it must not be per-round — and
    // pruned at promotion, which is the only way a demoted id can leave
    // the pool, so `demoted` is a subset of `pool`'s keys throughout.
    let mut demoted: BTreeSet<GrainId> = BTreeSet::new();
    let visited: RefCell<BTreeSet<GrainId>> = RefCell::new(BTreeSet::new());
    // The walk's asks THIS resume, in the order made, first occurrence
    // only: the one-shot's demand order, and the ONLY order promotion
    // iterates. `visited` is a set in hash order and must not be used
    // for it.
    let asked: RefCell<Vec<GrainId>> = RefCell::new(Vec::new());
    let asked_set: RefCell<BTreeSet<GrainId>> = RefCell::new(BTreeSet::new());
    #[cfg(test)]
    let visits = RefCell::new(visits);
    let mut cursor = manifest::TreeCursor::new(*root);
    let mut log = RoundLog::default();
    loop {
        log.round = log.round.saturating_add(1);
        // 1. Resume — NOT `?`: promotion runs before the outcome is
        //    dispatched, on every arm.
        let outcome = cursor.resume(&|id| {
            visited.borrow_mut().insert(*id);
            if asked_set.borrow_mut().insert(*id) {
                asked.borrow_mut().push(*id);
            }
            #[cfg(test)]
            if let Some(v) = visits.borrow_mut().as_deref_mut() {
                v.total_visits += 1;
                if id == root {
                    v.root_visits += 1;
                }
            }
            nodes.get(id).or_else(|| pool.get(id)).cloned()
        });
        // 2. Promote, in ask order, with today's exact admission —
        //    `retained` before each charge is the one-shot's prefix sum.
        //    A refusal surfaces HERE, before the outcome; a `Done` whose
        //    pool nodes were never promoted would hide them from
        //    `check_reachable_grains` (a wrong accept), and an `Err`
        //    dispatched first would let a later fault pre-empt an
        //    earlier budget refusal.
        let this_round: Vec<GrainId> = std::mem::take(&mut *asked.borrow_mut());
        asked_set.borrow_mut().clear();
        for id in this_round {
            if nodes.contains_key(&id) || !pool.contains_key(&id) {
                continue;
            }
            let node_ceiling = MANIFEST_NODE_MAX_BYTES;
            budget.charge_before_structure_node(u64::from(node_ceiling))?;
            let bytes = pool.remove(&id).unwrap_or_default();
            pool_used = pool_used.saturating_sub(bytes.len() as u64);
            pool_order.retain(|(p, _)| *p != id);
            // Keeps `demoted` a subset of `pool`'s keys instead of
            // letting it grow with the resolve. It has NO BEHAVIOURAL
            // consequence: `is_eviction_victim` is only asked about
            // entries still in `pool_order`, and a promoted id is both
            // removed from it above and blocked from re-admission
            // forever by `nodes.contains_key`, so a stale entry here can
            // never be consulted. IT IS PINNED ANYWAY, though by no
            // assertion about eviction: the row that catches it is an
            // eviction row, but what fires is the subset assertion, not
            // any eviction expectation. This line WAS a recorded
            // EQUIVALENT MUTANT — deleting it passed every row
            // in the file, executed. The exit gate then added
            // `demoted_is_pool_subset` below, whose `debug_assert!`
            // asserts exactly the invariant this line maintains, and
            // deleting the line now panics
            // `a_pooled_root_the_hint_pass_reached_is_not_evicted` at
            // that assertion (executed at the exit gate). So the mutant
            // is KILLED, and the register's "no row can see it" is
            // history rather than a current fact. The CHECK is
            // `debug_assertions`-only; the BOUND is not. In release no
            // row observes the deletion — equivalent in the register's
            // sense there, which in this project means unobserved by any
            // row — but the mutant is not INERT: without this line
            // `demoted` grows with the whole resolve instead of staying
            // bounded by the live pool, which is exactly what the module
            // header at the top of this file states as a memory bound.
            demoted.remove(&id);
            budget.fold_structure_node(bytes.len());
            debug_assert!(nodes.get(&id).is_none_or(|old| *old == bytes));
            nodes.insert(id, bytes);
        }
        // 2b. The instrument: this round, its outcome, and the counters as
        //     they stand BEFORE its dispatch — so the terminal round's
        //     line carries complete totals. A `need` round adds its own
        //     need, hints and admits afterward; `done` adds none, and an
        //     error reaching dispatch is logged before it returns.
        //     `RoundLog` documents exits outside this emit and why the
        //     level stays INFO: the round-timing harness reads default-level stderr,
        //     derives timing from these lines, and pins INFO in its fixtures.
        log.emit(&outcome, pool.len(), pool_used);
        // 3. Dispatch.
        let id = match outcome {
            Ok(Step::Done(stats)) => return Ok((nodes, stats, visited.into_inner())),
            Err(source) => {
                return Err(ResolveError::Tree {
                    root: *root,
                    source,
                });
            }
            Ok(Step::Need(id)) => id,
        };
        // A Need means the closure just answered None from BOTH maps;
        // nothing inserts between the resume and here.
        debug_assert!(!pool.contains_key(&id));
        if nodes.contains_key(&id) {
            // An unstable fetch: the walk asked for something resident
            // and did not get it. Today's guard, kept.
            return Err(ResolveError::Tree {
                root: *root,
                source: ValidateError::MissingObject { id },
            });
        }
        let bytes = fetch_one_need(
            fetcher,
            cache.as_deref_mut(),
            entries,
            bins,
            budget,
            root,
            id,
        )
        .await?;
        nodes.insert(id, bytes);
        log.needs = log.needs.saturating_add(1);
        // 4. THE HINTS, the provenance the pool's eviction rule reads,
        //    and what this round's hint pass REACHED in the pool.
        //    Provenance travels with each id: `false` = reachable through
        //    the entering directory (may evict queued roots), `true` = a
        //    queued root (never evicts). What the pass reached is folded
        //    into `demoted`, which OUTLIVES the round — a per-round set
        //    is unsound, see `demote_pooled_provenance` — and is read by
        //    `is_eviction_victim` inside `prefetch_structure_nodes`,
        //    where the eviction decision is actually made. The fold runs
        //    before that call and the order is normative.
        let (hints, reached) = hints_for_round(&cursor, &nodes, &pool);
        // THE SCOPE IS RESOLVE-WIDE, AND NOTHING PINS IT AT THIS
        // LINE. Do NOT clear `demoted` HERE, before the fold. A
        // per-round scope was designed, reviewed and RETIRED: the
        // hint pass is budgeted by `HINT_WORK_MAX`, so a publisher
        // can exhaust it before the pass re-reaches an
        // already-pooled node the walk still needs, and that node
        // then loses protection for exactly the round in which it is
        // taken as the oldest victim and banned. BOTH DIRECTIONS
        // WERE MEASURED, at an exit gate, and they DIFFER, which
        // is why this comment is here and not one line down:
        // `demoted.clear()` on THIS line — before the fold, the
        // per-round scope — leaves ALL 839 granary-client rows
        // GREEN, while the same clear placed AFTER the fold dies at
        // `a_pooled_root_the_hint_pass_reached_is_not_evicted`,
        // because clearing after the fold empties the set before
        // both readers and is simply the demotion removed. A clear
        // INSIDE `demote_pooled_provenance` dies at
        // `a_demotion_outlives_the_round_that_made_it` — but that
        // row drives `PoolState` directly and never enters this
        // loop, so it cannot see this line either. Register row 253
        // carries the missing end-to-end row and its discharge test.
        demote_pooled_provenance(&mut demoted, reached);
        debug_assert!(demoted_is_pool_subset(&demoted, &pool));
        log.hints = log.hints.saturating_add(hints.len() as u64);
        let admitted = prefetch_structure_nodes(
            fetcher,
            cache.as_deref_mut(),
            entries,
            bins,
            &mut nodes,
            &mut pool,
            &mut pool_used,
            &mut pool_order,
            &mut hint_tried,
            hints,
            &demoted,
        )
        .await;
        log.admits = log.admits.saturating_add(admitted as u64);
    }
}

/// Each hint id paired with its ADMISSION provenance: `false` = reachable
/// through the entering directory — never a victim, and the only kind of
/// candidate that may CAUSE an eviction; `true` = a queued root, which is the
/// only kind of entry eviction may take.
///
/// **`true` here is NECESSARY for eviction, not sufficient**, and the
/// difference is load-bearing. The victim search is
/// `position(|entry| is_eviction_victim(entry, demoted))`, not a raw filter on
/// this flag: a queued root that a hint pass has REACHED through the directory
/// being entered is demoted and may not be taken. Refactoring either the victim
/// search or the `evictable` sufficiency sum back to `|(_, root)| *root` is a
/// silent regression of that, which is what
/// `the_sufficiency_test_reads_the_demoted_provenance` and
/// `a_pooled_root_the_hint_pass_reached_is_not_evicted` exist to catch.
///
/// The two vectors are disjoint but the dedup is
/// ONE-DIRECTIONAL, so `queued_roots` is a SUBSET of the worklist's queued
/// roots — "in `entering`" must not be read as "not a queued root" (the
/// register row on `Hints` provenance).
///
/// Hoisted out of the round loop rather than written inline for the same
/// reason `fetch_one_need` was: inline, its six lines put
/// `fetch_tree_structure` at 101/100 `clippy::too_many_lines`, and an
/// `#[expect]` on this consensus-adjacent function is not justified here.
/// It is the mechanical half of the loop and moves without touching
/// the cap site or the promotion order.
fn hints_with_provenance(hints: manifest::Hints) -> Vec<(GrainId, bool)> {
    hints
        .entering
        .into_iter()
        .map(|id| (id, false))
        .chain(hints.queued_roots.into_iter().map(|id| (id, true)))
        .collect()
}

/// One round's hint pass, from the cursor to the paired provenance the
/// pool's admission reads — hoisted out of the round loop for the same
/// reason [`hints_with_provenance`] and [`fetch_one_need`] were: inline,
/// its lines put `fetch_tree_structure` at 105/100
/// `clippy::too_many_lines`, and an `#[expect]` on that function is not
/// justified here.
///
/// The closure records exactly one thing: which POOLED ids the pass
/// REACHED. A pooled id the hint walk fetched is reachable through the
/// directory being entered — an entering dependency — and no emission
/// can ever say so, because both walkers push to `entering` only in the
/// arm where the closure answered `None`, so a pooled node can never
/// appear THERE. **Nor can a REACHED one appear under `queued_roots` in
/// the same pass** — `missing_in_dir_tree` inserts an id into the shared
/// `seen` set BEFORE it fetches, and the frames loop drops a worklist
/// child already in `seen`. What CAN appear there is a different pooled
/// id, one this pass never reached: the frames loop does not
/// residency-check, so it lists such an id as the queued root it was
/// admitted as. The record changes no returned byte, so what the pass
/// emits is unchanged.
///
/// This function does NOT demote. It returns what the pass reached and
/// the caller folds that into the resolve's `demoted` set, immediately,
/// before running `prefetch_structure_nodes` on the hints — and that
/// ORDER is normative, because the eviction this demotion exists to stop
/// happens inside that call. The fold is a separate statement rather
/// than a step of this function so that the set it feeds can outlive the
/// round; see `demote_pooled_provenance` for why it must.
fn hints_for_round(
    cursor: &manifest::TreeCursor,
    nodes: &BTreeMap<GrainId, Vec<u8>>,
    pool: &BTreeMap<GrainId, Vec<u8>>,
) -> (Vec<(GrainId, bool)>, BTreeSet<GrainId>) {
    let reached: RefCell<BTreeSet<GrainId>> = RefCell::new(BTreeSet::new());
    let hints = cursor.prefetch_hints(
        &|id| {
            if let Some(bytes) = nodes.get(id) {
                return Some(bytes.clone());
            }
            let bytes = pool.get(id)?;
            reached.borrow_mut().insert(*id);
            Some(bytes.clone())
        },
        manifest::PREFETCH_HINT_MAX,
    );
    (hints_with_provenance(hints), reached.into_inner())
}

/// Fold what THIS round's hint pass reached in the pool into the
/// resolve's demoted set. An entry admitted as a QUEUED ROOT that any
/// hint pass has reached through the directory being entered is a
/// dependency of the walk in progress and must stop being an eviction
/// victim; `is_eviction_victim` is where that is read.
///
/// Why the caller must supply `reached` rather than this reading it off
/// `Hints`: an id resident in the pool is answered by the hint closure,
/// so neither walker can emit it under `entering` (both push there only
/// in their `fetch` returned-`None` arm), and a REACHED one cannot be
/// emitted under `queued_roots` either, because the walker puts it in
/// the shared `seen` set before fetching and the frames loop drops what
/// is already there. A pooled id this pass did NOT reach can still be
/// listed under `queued_roots`, which is the role it was admitted as and
/// so is no evidence of a change — that is the pair
/// `hints_for_round_demotes_only_the_pooled_ids_the_pass_reached`
/// asserts, on two DIFFERENT ids. "The hint closure served it from the
/// pool" is the only evidence there is.
///
/// **A FOLD, not a scan, and the difference is the whole point.** An
/// alternative, mutating the flag in `pool_order`, costs one full
/// O(pool ENTRIES) pass per round whose `reached` is non-empty. Entry
/// count is uncapped (`POOL_CAP_BYTES` caps BYTES), and on a round with
/// neither a promotion nor capacity pressure that pass would be the ONLY
/// P-scaled work in the loop. Folding the reached set instead costs
/// `O(reached · log demoted)` with `reached`
/// bounded by `HINT_WORK_MAX`, and the two readers pay one set lookup
/// per candidate victim inside walks they were already making.
///
/// **MONOTONE for the life of the pool entry, and per-round is NOT
/// sufficient.** The tempting argument is
/// that the cursor re-walks the entering directory every round it is
/// stopped inside, so a node the walk still needs is reached again every
/// round and the current round's set would do. **The hint pass is
/// BUDGETED.** `HINT_WORK_MAX` bounds it, repeated children are charged
/// before the dedup, and a spill is not memoised until it validates — so
/// a publisher can build a directory whose hint pass spends its whole
/// budget before it reaches an already-pooled node the walk still needs.
/// Under a per-round set that node loses protection for exactly that
/// round, is taken as the oldest victim, and is BANNED in `hint_tried`,
/// costing a need-path round trip for bytes the pool was holding. The
/// set therefore only ever grows while an entry is pooled.
///
/// It is pruned at PROMOTION, which is the only way a demoted id can
/// leave the pool: a demoted entry is never a victim, so eviction cannot
/// take it. That keeps `demoted` a subset of `pool`'s keys rather than
/// growing with the resolve.
///
/// What this does NOT do, in the usual case: it does not reduce the
/// number of fetches a resolve makes. When another queued root is
/// available as a victim the eviction simply takes that one instead, and
/// the gain is that the node evicted is one the walk needs LATER or
/// never rather than one it needs in the round after next.
///
/// "Usual" is necessary because the count can decrease on failure.
/// For example, if the walk needs the
/// protected node `P` and then FAILS, while the replacement victim `Q`
/// is never reached at all, the demotion saves `P`'s refetch and `Q`'s
/// is never spent — one fetch fewer, not the same number. The claim is
/// therefore about the common shape, not a bound.
fn demote_pooled_provenance(demoted: &mut BTreeSet<GrainId>, reached: BTreeSet<GrainId>) {
    demoted.extend(reached);
}

/// `demoted` is a subset of the pool's keys — the invariant the module's
/// RAM bound and the promotion prune's no-oracle argument both rest on,
/// asserted rather than only argued.
///
/// It holds because the only thing that ADDS is the fold, over ids
/// `hints_for_round` obtained from `pool`; the only thing that REMOVES an
/// id from the pool while it could still be demoted is promotion, which
/// prunes both together; and eviction cannot take a demoted entry because
/// [`is_eviction_victim`] refuses it. A second pool-removal path added
/// later — an error-path clear, a size trim, a re-admission that bypasses
/// the `nodes` check — would break it silently, and the module's stated
/// RAM bound would become false with every row still green.
///
/// A free function rather than an inline `debug_assert!` body because
/// five lines of assertion put `fetch_tree_structure` at 101/100
/// `clippy::too_many_lines`, and an `#[expect]` on that function is not
/// justified here — the same reason [`hints_for_round`] and
/// [`hints_with_provenance`] are hoisted. `debug_assert!` expands through
/// `if cfg!(debug_assertions)`, so this stays compiled (and non-dead) in
/// release while costing nothing there. Under `debug_assertions` it IS a
/// per-round `O(|demoted| · log |pool|)` walk — the P-scaled cost register
/// row 251 exists for — paid only in debug and test builds.
fn demoted_is_pool_subset(demoted: &BTreeSet<GrainId>, pool: &BTreeMap<GrainId, Vec<u8>>) -> bool {
    demoted.iter().all(|id| pool.contains_key(id))
}

/// Is this pooled entry still something eviction may TAKE? It must have
/// been admitted as a QUEUED ROOT and not have been demoted.
///
/// **Both readers of the stored provenance must go through here.** The
/// victim search decides WHICH entry is taken; the `evictable` sum
/// decides WHETHER taking any is sufficient, and eviction is
/// ALL-OR-NOTHING precisely because a victim is banned as well as
/// removed. A sum that counted bytes held by demoted entries would
/// over-state what can be freed, so the loop would enter, evict and BAN
/// every entry it actually may take, still not fit, and defer — the
/// pool spent for an admission that could never happen. A mutant that
/// applied the demotion to the victim search alone SURVIVED every row in
/// this file until `the_sufficiency_test_reads_the_demoted_provenance`
/// was written for it.
fn is_eviction_victim(entry: &(GrainId, bool), demoted: &BTreeSet<GrainId>) -> bool {
    let (id, admitted_as_queued_root) = entry;
    *admitted_as_queued_root && !demoted.contains(id)
}

/// THE NEED, ALONE — today's single-want path, byte for byte except the
/// structure-node charge, including per-node overhead. Hoisted out of the round loop so
/// `fetch_tree_structure` stays under `clippy::too_many_lines` (125/100
/// with it inline); the loop keeps its four numbered steps, in order.
async fn fetch_one_need<R: BinStore>(
    fetcher: &mut Fetcher<'_, R>,
    cache: Option<&mut Cache>,
    entries: &BTreeMap<GrainId, ShardEntry>,
    bins: &[[u8; DIGEST_LEN]],
    budget: &mut MetadataBudget,
    root: &GrainId,
    id: GrainId,
) -> Result<Vec<u8>, ResolveError> {
    let Some(entry) = entries.get(&id).copied() else {
        // The binmap never mapped this node at all — a genuine tree
        // defect, not a fetch-pump target.
        return Err(ResolveError::Tree {
            root: *root,
            source: ValidateError::MissingObject { id },
        });
    };
    // ONE binding feeds both the budget charge and the want's
    // declaration below: charge < declare would let the fetcher hold
    // bytes the budget never reserved, charge > declare would refuse
    // legal volumes near the budget edge earlier than the guard
    // requires — a single name makes the divergence unwritable.
    let node_ceiling = MANIFEST_NODE_MAX_BYTES;
    budget.charge_before_structure_node(u64::from(node_ceiling))?;
    let digest = *bins
        .get(entry.bin_ordinal as usize)
        .ok_or(ResolveError::BadOrdinal {
            id,
            ordinal: entry.bin_ordinal,
        })?;
    let want = Want::BinRange {
        id,
        digest,
        offset: entry.offset,
        comp_len: entry.comp_len,
        // No manifest field declares a structure node's own
        // decompressed size (unlike a content grain's
        // `GrainRef.unpacked_len`) — `MANIFEST_NODE_MAX_BYTES` is the
        // widest any LEGAL structure node ever encodes to, and the same
        // worst case the metadata budget check just above already
        // charges this fetch at.
        unpacked_len: node_ceiling,
    };
    let mut result = fetcher
        .fetch(cache, [want])
        .await
        .map_err(|e| map_fetch_err("manifest node", id, e))?;
    let bytes = result
        .remove(&id)
        .unwrap_or(Err(FetchError::Remote(RootStoreError::NotFound)))
        .map_err(|e| map_fetch_err("manifest node", id, e))?;
    // The WIRE path already refused anything wider than the
    // declaration inside the fetcher, and so does the CACHE path.
    // Re-checked here, where both delivery paths converge, so the
    // refusal never depends on which path the bytes arrived by and
    // the budget never folds more than the charge above reserved.
    if bytes.len() > node_ceiling as usize {
        return Err(ResolveError::OverDeclared {
            id,
            declared: node_ceiling,
            got: bytes.len(),
        });
    }
    budget.fold_structure_node(bytes.len());
    Ok(bytes)
}

/// Speculative pool cap: pool-resident actual bytes plus in-flight
/// worst-case declarations. Equal to the fetcher's own in-flight bound,
/// so a chunk at an empty pool is at most the ~10 max-declared wants the
/// fetcher's byte gate admits anyway.
const POOL_CAP_BYTES: u64 = 64 * 1024 * 1024;

/// Fetch a hint chunk into the speculative pool. NEVER an error: a hint
/// that cannot be mapped, whose ordinal is bad, whose fetch fails or
/// whose bytes exceed the declaration is dropped and remembered in
/// `hint_tried` (one speculative attempt per id per resolve); when the
/// walk needs it, the need path fetches it and ITS failure surfaces, in
/// walk order. A hint deferred for CAPACITY was never attempted and is
/// not remembered.
///
/// **Eviction, in full, because this is the function that performs it.**
/// A victim must be a never-asked entry whose ADMISSION provenance is
/// QUEUED ROOT *and* which `demoted` does not contain — that pair is
/// `is_eviction_victim`, and BOTH readers here go through it: the
/// `evictable` sufficiency sum and the victim search. `true` alone is
/// NOT the rule; a queued root some hint pass has reached through the
/// directory being entered is a dependency of the walk in progress and
/// may not be taken. Filtering either reader on the raw flag is a silent
/// regression, which is why `the_sufficiency_test_reads_the_demoted_provenance`
/// and `a_pooled_root_the_hint_pass_reached_is_not_evicted` exist.
/// Victims go oldest first, and only to admit entering-directory hints
/// (the ids the pass lists BEFORE the worklist's roots —
/// `prefetch_hints`'s own order); entering-directory hints never evict
/// each other. Returns how many candidates this pass admitted to the
/// pool — the instrument's `admits`.
#[expect(
    clippy::too_many_arguments,
    reason = "the round loop's state, threaded once"
)]
async fn prefetch_structure_nodes<R: BinStore>(
    fetcher: &mut Fetcher<'_, R>,
    cache: Option<&mut Cache>,
    entries: &BTreeMap<GrainId, ShardEntry>,
    bins: &[[u8; DIGEST_LEN]],
    nodes: &mut BTreeMap<GrainId, Vec<u8>>,
    pool: &mut BTreeMap<GrainId, Vec<u8>>,
    pool_used: &mut u64,
    pool_order: &mut VecDeque<(GrainId, bool)>,
    hint_tried: &mut BTreeSet<GrainId>,
    hints: Vec<(GrainId, bool)>,
    demoted: &BTreeSet<GrainId>,
) -> usize {
    let node_ceiling = MANIFEST_NODE_MAX_BYTES;
    let worst = u64::from(node_ceiling);
    let mut seen: BTreeSet<GrainId> = BTreeSet::new();
    let mut chunk: Vec<(Want, GrainId, bool)> = Vec::new();
    let mut chunk_worst: u64 = 0;
    let mut admitted: usize = 0;
    for (id, is_queued_root) in hints {
        if !seen.insert(id)
            || nodes.contains_key(&id)
            || pool.contains_key(&id)
            || hint_tried.contains(&id)
        {
            continue;
        }
        let Some(entry) = entries.get(&id).copied() else {
            hint_tried.insert(id);
            continue;
        };
        let Some(digest) = bins.get(entry.bin_ordinal as usize).copied() else {
            hint_tried.insert(id);
            continue;
        };
        // Capacity. FIRST: a candidate that would not fit even
        // against an EMPTY pool never evicts anything. The chunk's
        // own worst-case reservations (`chunk_worst`) are not
        // pool-resident bytes and no eviction can reduce them, so
        // without this the eleventh entering-directory candidate of
        // a full chunk walks the whole `pool_order`, evicts every
        // queued root in it that is still a victim — and that
        // is the never-demoted ones, not simply every `true` entry
        // — marks each one `hint_tried`, and then defers anyway,
        // having emptied the pool of what it could take and banned
        // that from speculation for the rest of the resolve.
        if chunk_worst.saturating_add(worst) > POOL_CAP_BYTES {
            break; // deferred: no eviction can make room for this chunk
        }
        // THEN: evict never-asked queued roots for an ENTERING-DIRECTORY
        // hint; otherwise defer (not remembered). Eviction is
        // ALL-OR-NOTHING against the need: a victim leaves the pool AND
        // is banned in `hint_tried` for the rest of the resolve, so it
        // is only ever spent when the eligible victims are ENOUGH to
        // admit this candidate. "Eligible" is `is_eviction_victim`, not
        // the raw flag: a queued root SOME hint pass has
        // reached is not a victim at all — any pass, not only this
        // round's, because `demoted` is monotone for the life of a pool
        // entry. Without the sufficiency test the loop drains every
        // queued root it MAY take, re-checks, and defers anyway — the
        // pool emptied of those and their contents banned for an
        // admission that could never happen. The guard above does not
        // cover this: it refuses only a chunk too big for an EMPTY pool,
        // and here the chunk fits while the VICTIMS are insufficient.
        let need = pool_used.saturating_add(chunk_worst).saturating_add(worst);
        let evictable: u64 = if need > POOL_CAP_BYTES && !is_queued_root {
            pool_order
                .iter()
                .filter(|slot| is_eviction_victim(slot, demoted))
                .filter_map(|(vid, _)| pool.get(vid).map(|b| b.len() as u64))
                .sum()
        } else {
            0
        };
        while need.saturating_sub(evictable) <= POOL_CAP_BYTES
            && pool_used.saturating_add(chunk_worst).saturating_add(worst) > POOL_CAP_BYTES
        {
            // UNREACHABLE since the sufficiency test above: a queued-root
            // candidate gets `evictable = 0`, so the first clause is false
            // whenever the second is true. Kept as defence in depth — it is
            // what makes "a queued root never evicts" true by reading, not
            // by an argument about the clause above it.
            if is_queued_root {
                break;
            }
            let Some(pos) = pool_order
                .iter()
                .position(|slot| is_eviction_victim(slot, demoted))
            else {
                break;
            };
            let Some((victim, _)) = pool_order.remove(pos) else {
                break;
            };
            if let Some(evicted) = pool.remove(&victim) {
                *pool_used = pool_used.saturating_sub(evicted.len() as u64);
            }
            // REMEMBERED. Without this the next round's hint pass lists
            // the same queued root again (worklist entries are not
            // residency-checked), finds it in neither `nodes`, `pool`
            // nor `hint_tried`, and fetches it SPECULATIVELY a second
            // time — so "every id is fetched speculatively at most once"
            // would not hold, and a `bin_call_count == 2` could be two
            // speculative fetches rather than one speculative and one
            // need. The victim is marked attempted; the walk will fetch
            // it on the need path when
            // it enters it.
            hint_tried.insert(victim);
        }
        if pool_used.saturating_add(chunk_worst).saturating_add(worst) > POOL_CAP_BYTES {
            break; // deferred: the rest of this pass waits for the next
        }
        chunk_worst = chunk_worst.saturating_add(worst);
        chunk.push((
            Want::BinRange {
                id,
                digest,
                offset: entry.offset,
                comp_len: entry.comp_len,
                unpacked_len: node_ceiling,
            },
            id,
            is_queued_root,
        ));
    }
    if chunk.is_empty() {
        return 0;
    }
    let wants: Vec<Want> = chunk.iter().map(|(w, _, _)| w.clone()).collect();
    let Ok(mut results) = fetcher.fetch(cache, wants).await else {
        // Unreachable for an infallible want iterator; nothing was
        // inserted, nothing to release.
        return 0;
    };
    for (_, id, is_queued_root) in chunk {
        match results.remove(&id) {
            Some(Ok(bytes)) if bytes.len() <= node_ceiling as usize => {
                *pool_used = pool_used.saturating_add(bytes.len() as u64);
                pool_order.push_back((id, is_queued_root));
                pool.insert(id, bytes);
                admitted = admitted.saturating_add(1);
            }
            _ => {
                hint_tried.insert(id);
            }
        }
    }
    admitted
}

#[cfg(test)]
mod tests;
