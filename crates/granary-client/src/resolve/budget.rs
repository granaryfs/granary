// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The metadata budget: one running charge for one resolve, and the
//! admission decisions that read it.
//!
//! **What breaks when this module is wrong:** a resolve retains more
//! metadata than the ceiling admits and the process grows without a
//! refusal — or the opposite, a legal volume is refused because the
//! charge double-counts. The accounting is deliberately centralised
//! here rather than re-derived at each call site: `entries_len` is
//! tracked, not recomputed, because a caller picking its own figure
//! per call lets admission checks disagree about the retained entry count.
//!
//! It owns the three modelled costs ([`METADATA_BUDGET_BYTES`],
//! [`ENTRY_COST_BYTES`], [`NODE_COST_BYTES`]) and the
//! running state that charges against them. It does NOT own the walks
//! that spend the budget, nor the transport helper that reports a
//! fetch failure: `map_fetch_err` begins immediately after this block
//! and is the parent's.
//!
//! Out-of-line, a child one flat
//! level under `resolve/`, beside
//! `emission` and `structure`.

use granary_core::manifest::MANIFEST_NODE_MAX_BYTES;
use granary_store::bounds::META_MAX_BYTES;

use super::ResolveError;

/// A budget accounting three terms — `retained_bytes`, the entries map's
/// modelled cost (`entries.len() * ENTRY_COST_BYTES`) and the structure
/// nodes' modelled overhead (`retained_nodes * NODE_COST_BYTES`) — as
/// the running metadata charge: the entry MAP itself is priced,
/// not only the shard bytes that filled it, and each retained
/// structure node adds its modelled overhead beyond its bytes.
/// `ENTRY_COST_BYTES` is a stated MODEL of one entry's true cost (id +
/// `ShardEntry` + `BTreeMap` overhead, rounded up). It is a ceiling,
/// deliberately, and not a measurement of any particular entry.
pub(crate) const METADATA_BUDGET_BYTES: u64 = 256 * 1024 * 1024;

/// See [`METADATA_BUDGET_BYTES`].
pub(crate) const ENTRY_COST_BYTES: u64 = 128;

/// A MODEL of what the walk retains per manifest structure node
/// BEYOND its bytes: the cursor's directory frame (112 bytes
/// measured), its `todo` allocation (132), a memo entry (48) and the
/// node map's own overhead (~95), rounded up to a power of two like
/// `ENTRY_COST_BYTES`. Charged in the pre-admission
/// predicate so the prospective node cannot cross the budget and
/// return `Done` unchecked. It is a POLICY constant, not an RSS
/// guarantee. The acceptance boundary it sets decides what is
/// admitted, and it is the owner's to move.
/// Adrian Ana ruled 512 on 2026-09-05.
pub(crate) const NODE_COST_BYTES: u64 = 512;

const _: () = assert!(
    META_MAX_BYTES <= METADATA_BUDGET_BYTES,
    "a lone meta fetch must always admit against its own budget — charging \
     more than the whole budget for one fetch would refuse every resolve"
);

// The structure-node twin of the witness above: the tree pump charges
// each node fetch at `MANIFEST_NODE_MAX_BYTES` PLUS that node's
// modelled overhead, and a lone structure fetch must equally
// always admit. The `NODE_COST_BYTES` term is what
// `charge_before_structure_node` actually adds, so the witness carries
// it too — without it this would assert a property the charge site
// does not have.
const _: () = assert!(
    MANIFEST_NODE_MAX_BYTES as u64 + NODE_COST_BYTES <= METADATA_BUDGET_BYTES,
    "a lone structure-node fetch must always admit against its own budget"
);

/// The running metadata charge for ONE resolve — `retained_bytes`
/// (shard/index/table/sheaf/manifest-node bytes ACTUALLY fetched so
/// far) plus the current entries map's MODELLED cost plus the manifest
/// structure nodes held so far at THEIR modelled cost — `retained_nodes`
/// times [`NODE_COST_BYTES`]. ONE total,
/// [`retained_total`](Self::retained_total), and both admission
/// predicates read it. `entries_len` is
/// tracked HERE, not re-derived from `entries.len()` at each call site:
/// every metadata fetch this resolve retains threads the SAME budget
/// through [`charge_before_fetch`](Self::charge_before_fetch) and [`fold`](Self::fold), and
/// [`bump_entries`](Self::bump_entries) is the ONLY other way the
/// figure changes — a caller picking its own `entries_len` per call is
/// a way for admission checks to use different totals, and centralising the
/// state here removes the class rather than re-auditing each call site
/// for it. `retained_nodes` moves only through
/// [`fold_structure_node`](Self::fold_structure_node), for the same
/// reason.
#[derive(Debug, Default)]
pub(crate) struct MetadataBudget {
    // `pub(super)`, not private, and NOT widened by reflex: these fields are
    // private today and still reach every descendant of `resolve`, because
    // privacy is hierarchical and `MetadataBudget` is DEFINED in `resolve`.
    // Moving it into `resolve::budget` would narrow that to this module's own
    // descendants and give `E0451` at five struct-literal sites in two sibling
    // test modules — three of them the `structure` child's, which belong to
    // structure by subject and must not be dragged here to satisfy a privacy
    // edge. `pub(super)` restores exactly the reach they had and no more.
    pub(super) retained_bytes: u64,
    pub(super) entries_len: usize,
    pub(super) retained_nodes: usize,
}

impl MetadataBudget {
    /// Refuse BEFORE the wire call if this fetch, even at its
    /// WORST-CASE size, would cross [`METADATA_BUDGET_BYTES`] — the
    /// pessimistic admission gate that lets `MetadataBudgetExceeded`
    /// arrive before the crossing object's own fetch counter ever moves.
    /// Pessimistic because no format field declares an object's size
    /// ahead of fetching it; charging the worst case here costs only
    /// THIS resolve's own window, rather than reserving a shared
    /// server budget that other callers also need.
    pub(super) fn charge_before_fetch(&self, worst_case: u64) -> Result<(), ResolveError> {
        let attempted = self.retained_total().saturating_add(worst_case);
        if attempted > METADATA_BUDGET_BYTES {
            return Err(ResolveError::MetadataBudgetExceeded { attempted });
        }
        Ok(())
    }

    /// Fold a fetch's ACTUAL bytes into `retained_bytes`, once it has
    /// answered — the running total the NEXT [`charge_before_fetch`](Self::charge_before_fetch)
    /// call checks.
    pub(super) fn fold(&mut self, actual_bytes: usize) {
        self.retained_bytes = self
            .retained_bytes
            .saturating_add(u64::try_from(actual_bytes).unwrap_or(u64::MAX));
    }

    /// Everything this budget currently counts as RETAINED: the bytes
    /// already folded, the binmap entries at their modelled cost, and
    /// the manifest structure nodes at theirs. ONE function,
    /// because both admission predicates must agree on what "retained"
    /// means. Computing it twice could let `charge_before_fetch` ignore
    /// `retained_nodes` and admit a meta fetch after the structure walk
    /// against a smaller total than the walk itself used. This shared
    /// definition prevents that mismatch.
    fn retained_total(&self) -> u64 {
        let entries_cost = u64::try_from(self.entries_len)
            .unwrap_or(u64::MAX)
            .saturating_mul(ENTRY_COST_BYTES);
        let nodes_cost = u64::try_from(self.retained_nodes)
            .unwrap_or(u64::MAX)
            .saturating_mul(NODE_COST_BYTES);
        self.retained_bytes
            .saturating_add(entries_cost)
            .saturating_add(nodes_cost)
    }

    /// [`charge_before_fetch`](Self::charge_before_fetch) for a manifest
    /// STRUCTURE node — the same worst-case admission, plus the modelled
    /// per-node overhead of THIS one on top of everything already
    /// retained. General metadata fetches do not pay the
    /// prospective node's overhead; they do pay for the nodes already
    /// held, through [`retained_total`](Self::retained_total).
    pub(super) fn charge_before_structure_node(&self, worst_case: u64) -> Result<(), ResolveError> {
        let attempted = self
            .retained_total()
            .saturating_add(NODE_COST_BYTES)
            .saturating_add(worst_case);
        if attempted > METADATA_BUDGET_BYTES {
            return Err(ResolveError::MetadataBudgetExceeded { attempted });
        }
        Ok(())
    }

    /// [`fold`](Self::fold) for a structure node: its actual bytes, and
    /// one more retained node.
    pub(super) fn fold_structure_node(&mut self, actual_bytes: usize) {
        self.fold(actual_bytes);
        self.retained_nodes = self.retained_nodes.saturating_add(1);
    }

    /// Count `n` MORE entries into the running charge — the binmap
    /// shard loop's own growth, called once per decoded shard,
    /// immediately after its entries land in the map. The only place
    /// `entries_len` ever changes.
    ///
    /// Between this call and the next [`charge_before_fetch`](Self::charge_before_fetch),
    /// the retained total can sit at most one shard's modelled entry
    /// cost above [`METADATA_BUDGET_BYTES`] — this shard's own entries
    /// already landed in the map before its cost was ever checked
    /// against the ceiling — and that next check is exactly where the
    /// crossing shard is refused.
    pub(super) fn bump_entries(&mut self, n: usize) {
        self.entries_len = self.entries_len.saturating_add(n);
    }
}

#[cfg(test)]
mod tests;
