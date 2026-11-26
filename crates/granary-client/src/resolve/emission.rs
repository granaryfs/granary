// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Emission: route a resolved target to the walk that serves it and
//! stream its grains in manifest order.
//!
//! **What breaks when this module is wrong:** a reader is handed bytes
//! that are not the file — the wrong grains, the right grains in the
//! wrong order, or a duplicated grain counted once — or the walk
//! materialises a per-position vector and the read path's residency
//! bound stops holding. Refusal is the other half of the same subject:
//! a target that names a directory, a path that leaves its entering
//! directory, a repeated leaf whose spans exceed what the budget
//! admits, all refuse BEFORE any position is walked.
//!
//! It owns the two walks (`ResolveTarget::Path` through
//! [`lookup_in_dir`], `ResolveTarget::WholeTree` through
//! [`walk_all_files`]), the edge-derived span facts the residency
//! bound is computed from ([`grain_span_facts`],
//! [`duplicate_span_peak`]), and the streaming emit itself
//! ([`emit_file`]). It does NOT own the structure walk that fetched
//! the manifest ([`super::fetch_tree_structure`]), the budget that
//! charged for it, the verifier, or `ResolveError` — an error enum
//! REPORTS failure domains and is not one, so it stays with the
//! parent.
//!
//! Out-of-line, and a child — children sit one flat
//! level under `resolve/`, the parent keeps its path
//! and its name, and `lib.rs` is untouched because
//! the parent re-exports what it always exported.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use granary_core::binmap::ShardEntry;
use granary_core::binstore::BinStore;
use granary_core::encoding::{self, ObjectType};
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::manifest::{
    self, DEPTH_MAX, EntryKind, FileGrains, GrainRef, Name, ValidateError,
};
use granary_core::rootstore::RootStoreError;

use crate::cache::Cache;
use crate::fetcher::{FETCH_INFLIGHT_BYTES, Fetcher, Want};

// The CLOSED REACH SET for this child's parent dependencies is the import
// below, listed BY NAME so that it is short, visible in one place, and an
// unused one is `unused_imports`. The child -> parent direction is not
// bounded by the compiler — an inline `super::helper()` needs no `use`
// at all — so this list is a review aid that only works if nothing
// bypasses it. A parent name absent from this list is a finding.
use super::{EmitSink, ResolveError, ResolveTarget, decode_err, map_fetch_err};

/// Route `target` to the walk that serves it, over the manifest
/// STRUCTURE already fetched by [`super::fetch_tree_structure`]. `entries`/
/// `bins` resolve a grain reference to a [`Want::BinRange`]; `fetcher`/
/// `cache` are the SAME seam and window the metadata phase used, so
/// content fetches inherit whatever caution a shed already taught the
/// window.
///
/// **`degraded`**: forwarded unchanged to every [`emit_file`] call
/// this routes to — see that function's own doc for the residency
/// pre-flight it runs when it is `Some`. The structure nodes emitted
/// directly below (the `WholeTree` arm) need no such check THEMSELVES:
/// `nodes` only ever holds bytes [`super::fetch_tree_structure`]
/// already fetched SUCCESSFULLY, before `check_chain` or emission ever
/// ran, so there is no partial-node state this function could observe.
///
/// **Rule (d) for `WholeTree`, specifically.** `WholeTree` emits every
/// structure node BEFORE the first [`emit_file`] call, so per-file
/// pre-flights alone cannot keep the sink clean: a later file's missing
/// grain would surface only after every structure node, and possibly
/// several earlier files, had already reached the sink. So the
/// `WholeTree` arm runs ONE additional pre-flight, over every file's
/// position streams combined (from the same [`walk_all_files`]
/// enumeration it emits), before its first `sink` call at all — see that arm's own
/// comment. `Path` needs no such whole-set step: it names exactly one
/// file and emits nothing before [`emit_file`]'s own per-file
/// pre-flight runs, so that one check already keeps rule (d) true
/// there.
#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the emission walk needs the binmap's routing tables and both \
              seams alongside the tree and the caller's own target/sink/degraded marker; \
              WholeTree's fail-before-emit residency pass stays beside its emission order"
)]
pub(super) async fn emit_target<R: BinStore>(
    fetcher: &mut Fetcher<'_, R>,
    mut cache: Option<&mut Cache>,
    entries: &BTreeMap<GrainId, ShardEntry>,
    bins: &[[u8; DIGEST_LEN]],
    manifest_root: &GrainId,
    nodes: &BTreeMap<GrainId, Vec<u8>>,
    target: ResolveTarget<'_>,
    sink: &mut EmitSink<'_>,
    degraded: Option<&RootStoreError>,
) -> Result<(), ResolveError> {
    match target {
        ResolveTarget::Path(path) => {
            let Some((file_name, dirs)) = path.split_last() else {
                return Err(ResolveError::NoSuchTarget {
                    message: "the path names no file".to_owned(),
                });
            };
            let mut dir = *manifest_root;
            for component in dirs {
                match lookup_in_dir(nodes, manifest_root, &dir, component)?.0 {
                    EntryKind::Dir { child } => dir = child,
                    EntryKind::File { .. } => {
                        return Err(refuse_kind(component, "file", ", not a directory"));
                    }
                    EntryKind::Symlink { .. } => {
                        return Err(refuse_kind(
                            component,
                            "symlink",
                            ", and this walk does not follow one — name the target directly",
                        ));
                    }
                    EntryKind::Fifo => return Err(refuse_kind(component, "fifo", "")),
                    EntryKind::Socket => return Err(refuse_kind(component, "socket", "")),
                }
            }
            match lookup_in_dir(nodes, manifest_root, &dir, file_name)? {
                (EntryKind::File { grains, .. }, containing_dir_leaf) => {
                    emit_file(
                        fetcher,
                        cache.as_deref_mut(),
                        entries,
                        bins,
                        nodes,
                        manifest_root,
                        &grains,
                        containing_dir_leaf,
                        sink,
                        degraded,
                    )
                    .await
                }
                (EntryKind::Dir { .. }, _) => Err(refuse_kind(
                    file_name,
                    "directory",
                    ", and only a file's bytes can be streamed",
                )),
                (EntryKind::Symlink { .. }, _) => Err(refuse_kind(
                    file_name,
                    "symlink",
                    ", and this walk does not follow one — name the target directly",
                )),
                (EntryKind::Fifo, _) => Err(refuse_kind(
                    file_name,
                    "fifo",
                    ", which has no bytes to stream",
                )),
                (EntryKind::Socket, _) => Err(refuse_kind(
                    file_name,
                    "socket",
                    ", which has no bytes to stream",
                )),
            }
        }
        ResolveTarget::WholeTree => {
            // The walk is hoisted ABOVE the structure-node emission on
            // EVERY path, not just the degraded one: a walk error
            // `?`-surfaces before the first `sink` call rather than after
            // the nodes were delivered. Deliberate — a walk error then
            // delivers nothing to the sink, on every path. It does not
            // make the whole resolve fail-before-emit: an error raised
            // later, while emitting a file, can follow bytes the sink
            // has already received.
            let all_files = walk_all_files(nodes, manifest_root, WHOLE_TREE_PATH_BUDGET)?;
            // Preserve the walk's fail-before-emit property without
            // retaining any file's positions: every file's unique-node
            // facts are derived before the first sink call. `emit_file`
            // derives them again when that file is reached, keeping
            // WholeTree's live span state to one file at a time. The
            // degraded path retains only their unique ids for its
            // whole-set residency check.
            let mut resident_ids = VecDeque::new();
            let mut resident_seen = BTreeSet::new();
            for file in &all_files {
                let facts = grain_span_facts(nodes, manifest_root, &file.grains)?;
                if degraded.is_some() {
                    for id in grain_ids_in_first_position_order(&facts, manifest_root)? {
                        if resident_seen.insert(id) {
                            resident_ids.push_back(id);
                        }
                    }
                }
            }
            // Rule (d), the WHOLE-SET pre-flight this arm's own doc
            // above explains: `emit_file`'s per-file pre-flight cannot
            // by itself keep the sink clean here, because structure
            // nodes (and any earlier file) are emitted before a LATER
            // file's own miss would ever surface. Every file's want set
            // combined, checked once, before the first `sink` call —
            // never per file, never after a structure node has gone
            // out. `resident_ids` is the union of the already-derived
            // per-unique facts, so this step never walks or retains a
            // positional sequence.
            if let Some(source) = degraded {
                residency_preflight(cache.as_deref_mut(), resident_ids, source)?;
            }
            // Every structure node the walk fetched, handed to the sink
            // as-is — the closest equivalent to a whole-tree object
            // map.
            for (id, bytes) in nodes {
                sink(*id, bytes).map_err(|message| ResolveError::Sink { message })?;
            }
            for file in all_files {
                emit_file(
                    fetcher,
                    cache.as_deref_mut(),
                    entries,
                    bins,
                    nodes,
                    manifest_root,
                    &file.grains,
                    file.containing_dir_leaf,
                    sink,
                    degraded,
                )
                .await?;
            }
            Ok(())
        }
    }
}

/// Render a path-component name for an operator message. Names are
/// arbitrary bytes, including non-UTF-8; `{:?}` quotes and escapes
/// control characters so a hostile name is rendered as visible text
/// rather than executed by the terminal that prints it.
pub(super) fn show(name: &Name) -> String {
    format!("{:?}", String::from_utf8_lossy(name.as_bytes()))
}

/// A `Path` target naming something that is not usable the way it was
/// named — a non-directory partway down the path, or a non-file at the
/// end of it. ONE construction for both positions (`emit_target`'s two
/// match arms): `kind_word` names what it actually is, `detail` is the
/// (possibly empty) reason-specific tail, so both positions share one
/// message format while their tails may differ.
fn refuse_kind(name: &Name, kind_word: &str, detail: &str) -> ResolveError {
    ResolveError::NoSuchTarget {
        message: format!("{} is a {kind_word}{detail}", show(name)),
    }
}

/// A manifest structure node's bytes, from the ALREADY-FETCHED,
/// already-validated map [`super::fetch_tree_structure`] built. Absent here
/// after a successful whole-tree validation means this walk and
/// resolve's walk disagree about what is reachable — a state
/// unreachable by construction, refused here as a missing object
/// rather than assumed away. `root` names the walk this node is
/// being read FOR (a manifest directory root, or a file's grain-list
/// root), for [`ResolveError::Tree`]'s own field.
fn node<'a>(
    nodes: &'a BTreeMap<GrainId, Vec<u8>>,
    root: &GrainId,
    id: &GrainId,
) -> Result<&'a [u8], ResolveError> {
    nodes.get(id).map(Vec::as_slice).ok_or(ResolveError::Tree {
        root: *root,
        source: ValidateError::MissingObject { id: *id },
    })
}

/// Find `name` in the directory whose B-tree is rooted at `dir`, over
/// the verified structure map. A SECOND `DEPTH_MAX` bound, deliberately,
/// on a tree the fetch-pump already walked once: that walk bounds its
/// own descent, so on any input that got this far the bound is already
/// satisfied — this is an argument about ANOTHER function's behaviour,
/// made at the one place where being wrong means an unbounded loop.
///
/// Routing is by separator, and a lying separator cannot produce the
/// wrong file: the target lives under the LAST child whose `first_key`
/// does not exceed it, and the leaf scan matches on the name EXACTLY, so
/// the outcome is a spurious "no entry named", never another file's
/// bytes (resolve's own walk already refused a tampered `first_key` via
/// `ValidateError::SeparatorMismatch`/`CrossNodeOrder`).
///
/// **"No entry named" is the caller's own mistake** (`NoSuchTarget`) —
/// the name genuinely is not there. A depth violation or a wrong-typed
/// node hit DURING the search is not: the same tree already validated
/// completely under [`DEPTH_MAX`] and its own node types
/// (`fetch_tree_structure`), so either one means this SECOND, INDEPENDENT
/// walk disagrees with that proof — an internal inconsistency
/// (`ResolveError::Tree`), never something the caller's path could have
/// avoided.
fn lookup_in_dir(
    nodes: &BTreeMap<GrainId, Vec<u8>>,
    root: &GrainId,
    dir: &GrainId,
    name: &Name,
) -> Result<(EntryKind, GrainId), ResolveError> {
    let mut current = *dir;
    for _ in 0..DEPTH_MAX {
        let bytes = node(nodes, root, &current)?;
        let (ty, cursor) = encoding::open_envelope(bytes).map_err(decode_err("manifest node"))?;
        match ty {
            ObjectType::DirLeaf => {
                let entries = manifest::decode_dir_leaf(cursor).map_err(decode_err("dir leaf"))?;
                return entries
                    .into_iter()
                    .find(|e| e.name == *name)
                    .map(|e| (e.kind, current))
                    .ok_or_else(|| ResolveError::NoSuchTarget {
                        message: format!("no entry named {}", show(name)),
                    });
            }
            ObjectType::DirInterior => {
                let children =
                    manifest::decode_dir_interior(cursor).map_err(decode_err("dir interior"))?;
                let child = children
                    .iter()
                    .rev()
                    .find(|ch| ch.first_key <= *name)
                    .ok_or_else(|| ResolveError::NoSuchTarget {
                        message: format!("no entry named {}", show(name)),
                    })?;
                current = child.child;
            }
            ObjectType::GrainListLeaf
            | ObjectType::GrainListIndex
            | ObjectType::Bin
            | ObjectType::BinmapIndex
            | ObjectType::BinTable
            | ObjectType::BinmapShard
            | ObjectType::Root
            | ObjectType::Sheaf => {
                return Err(ResolveError::Tree {
                    root: *root,
                    source: ValidateError::WrongObjectType { id: current },
                });
            }
        }
    }
    Err(ResolveError::Tree {
        root: *root,
        source: ValidateError::DepthExceeded,
    })
}

/// One unit of the explicit depth-first grain-list walk. `Node` keeps
/// only an as-yet-unvisited stored edge; `Ref` keeps one decoded leaf
/// entry until the caller asks for it.
enum GrainWalkItem {
    Node {
        id: GrainId,
        depth: u32,
    },
    Ref {
        grain: GrainRef,
        declaring_node: GrainId,
    },
}

enum GrainPositionState<'a> {
    Inline {
        refs: std::slice::Iter<'a, GrainRef>,
        declaring_node: GrainId,
    },
    Spill {
        pending: VecDeque<GrainWalkItem>,
    },
}

/// A file's grain refs in FILE order, each paired with the manifest node
/// that declared it. The iterator retains only the decoded entries and
/// unvisited stored edges along its explicit DFS worklist, never one
/// tuple per expanded position. Repeated DAG edges are intentionally
/// walked repeatedly: emission time is positional, while residency is
/// bounded by the stored representation.
struct GrainPositions<'a> {
    nodes: &'a BTreeMap<GrainId, Vec<u8>>,
    root: GrainId,
    state: GrainPositionState<'a>,
    declared_count: u32,
    yielded: u32,
    finished: bool,
}

fn grain_positions<'a>(
    nodes: &'a BTreeMap<GrainId, Vec<u8>>,
    root: &GrainId,
    grains: &'a FileGrains,
    containing_dir_leaf: GrainId,
) -> GrainPositions<'a> {
    let state = match grains {
        FileGrains::Inline(refs) => GrainPositionState::Inline {
            refs: refs.iter(),
            declaring_node: containing_dir_leaf,
        },
        FileGrains::Spill {
            root: spill_root, ..
        } => GrainPositionState::Spill {
            pending: VecDeque::from([GrainWalkItem::Node {
                id: *spill_root,
                depth: 1,
            }]),
        },
    };
    GrainPositions {
        nodes,
        root: *root,
        state,
        declared_count: grains.grain_count(),
        yielded: 0,
        finished: false,
    }
}

impl GrainPositions<'_> {
    fn next_position(&mut self) -> Result<Option<(GrainRef, GrainId)>, ResolveError> {
        match &mut self.state {
            GrainPositionState::Inline {
                refs,
                declaring_node,
            } => Ok(refs.next().map(|grain| (*grain, *declaring_node))),
            GrainPositionState::Spill { pending } => loop {
                let Some(item) = pending.pop_back() else {
                    return Ok(None);
                };
                match item {
                    GrainWalkItem::Ref {
                        grain,
                        declaring_node,
                    } => return Ok(Some((grain, declaring_node))),
                    GrainWalkItem::Node { id, depth } => {
                        if depth > DEPTH_MAX {
                            return Err(ResolveError::Tree {
                                root: self.root,
                                source: ValidateError::DepthExceeded,
                            });
                        }
                        let bytes = node(self.nodes, &self.root, &id)?;
                        let (ty, cursor) = encoding::open_envelope(bytes)
                            .map_err(decode_err("grain-list node"))?;
                        match ty {
                            ObjectType::GrainListLeaf => {
                                let refs = manifest::decode_grain_list_leaf(cursor)
                                    .map_err(decode_err("grain-list leaf"))?;
                                for grain in refs.into_iter().rev() {
                                    pending.push_back(GrainWalkItem::Ref {
                                        grain,
                                        declaring_node: id,
                                    });
                                }
                            }
                            ObjectType::GrainListIndex => {
                                let children = manifest::decode_grain_list_index(cursor)
                                    .map_err(decode_err("grain-list index"))?;
                                let next_depth =
                                    depth.checked_add(1).ok_or(ResolveError::Tree {
                                        root: self.root,
                                        source: ValidateError::DepthExceeded,
                                    })?;
                                for child in children.into_iter().rev() {
                                    pending.push_back(GrainWalkItem::Node {
                                        id: child.child,
                                        depth: next_depth,
                                    });
                                }
                            }
                            ObjectType::DirLeaf
                            | ObjectType::DirInterior
                            | ObjectType::Bin
                            | ObjectType::BinmapIndex
                            | ObjectType::BinTable
                            | ObjectType::BinmapShard
                            | ObjectType::Root
                            | ObjectType::Sheaf => {
                                return Err(ResolveError::Tree {
                                    root: self.root,
                                    source: ValidateError::WrongObjectType { id },
                                });
                            }
                        }
                    }
                }
            },
        }
    }
}

impl Iterator for GrainPositions<'_> {
    type Item = Result<(GrainRef, GrainId), ResolveError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        match self.next_position() {
            Ok(Some(position)) => {
                let Some(yielded) = self.yielded.checked_add(1) else {
                    self.finished = true;
                    return Some(Err(ResolveError::Tree {
                        root: self.root,
                        source: ValidateError::CountMismatch,
                    }));
                };
                if yielded > self.declared_count {
                    self.finished = true;
                    return Some(Err(ResolveError::Tree {
                        root: self.root,
                        source: ValidateError::CountMismatch,
                    }));
                }
                self.yielded = yielded;
                Some(Ok(position))
            }
            Ok(None) => {
                self.finished = true;
                (self.yielded != self.declared_count).then_some(Err(ResolveError::Tree {
                    root: self.root,
                    source: ValidateError::CountMismatch,
                }))
            }
            Err(error) => {
                self.finished = true;
                Some(Err(error))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub(super) struct GrainSpan {
    first: u32,
    last: u32,
    max_len: u32,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct NodeReach {
    incoming_left: u32,
    first_start: u32,
    last_start: u32,
}

pub(super) fn grain_span_facts(
    nodes: &BTreeMap<GrainId, Vec<u8>>,
    manifest_root: &GrainId,
    grains: &FileGrains,
) -> Result<BTreeMap<GrainId, GrainSpan>, ResolveError> {
    match grains {
        FileGrains::Inline(refs) => {
            let mut facts = BTreeMap::new();
            for (position, r) in refs.iter().enumerate() {
                let position = u32::try_from(position).map_err(|_| ResolveError::Tree {
                    root: *manifest_root,
                    source: ValidateError::CountMismatch,
                })?;
                merge_grain_span(&mut facts, *r, position, position);
            }
            Ok(facts)
        }
        FileGrains::Spill { grain_count, root } => {
            grain_list_span_facts(nodes, manifest_root, root, *grain_count)
        }
    }
}

fn merge_grain_span(
    facts: &mut BTreeMap<GrainId, GrainSpan>,
    grain: GrainRef,
    first: u32,
    last: u32,
) {
    facts
        .entry(grain.id)
        .and_modify(|span| {
            span.first = span.first.min(first);
            span.last = span.last.max(last);
            span.max_len = span.max_len.max(grain.unpacked_len);
        })
        .or_insert(GrainSpan {
            first,
            last,
            max_len: grain.unpacked_len,
        });
}

#[expect(
    clippy::too_many_lines,
    reason = "the two edge-record passes share one compact node memo; splitting either pass would obscure that both count and merge every stored edge"
)]
fn grain_list_span_facts(
    nodes: &BTreeMap<GrainId, Vec<u8>>,
    manifest_root: &GrainId,
    spill_root: &GrainId,
    declared_count: u32,
) -> Result<BTreeMap<GrainId, GrainSpan>, ResolveError> {
    let tree_error = |source| ResolveError::Tree {
        root: *manifest_root,
        source,
    };

    // Discovery counts stored incoming edge records. Repeated child ids
    // are separate edges and each one contributes to `incoming_left`.
    let mut memo = BTreeMap::new();
    memo.insert(
        *spill_root,
        NodeReach {
            incoming_left: 0,
            first_start: 0,
            last_start: 0,
        },
    );
    let mut queue = VecDeque::from([*spill_root]);
    let mut root_count = None;
    while let Some(id) = queue.pop_front() {
        let bytes = node(nodes, manifest_root, &id)?;
        let (ty, cursor) = encoding::open_envelope(bytes)
            .map_err(|source| tree_error(ValidateError::Decode(source)))?;
        match ty {
            ObjectType::GrainListLeaf => {
                if id == *spill_root {
                    let mut cursor = cursor;
                    root_count = Some(
                        cursor
                            .u32()
                            .map_err(|source| tree_error(ValidateError::Decode(source)))?,
                    );
                }
            }
            ObjectType::GrainListIndex => {
                let children = manifest::decode_grain_list_index(cursor)
                    .map_err(|source| tree_error(ValidateError::Decode(source)))?;
                if id == *spill_root {
                    root_count = children
                        .last()
                        .map(|child| {
                            u32::try_from(child.cum_ref_count)
                                .map_err(|_| tree_error(ValidateError::CumulativeMismatch))
                        })
                        .transpose()?;
                }
                for child in children {
                    if let Some(reach) = memo.get_mut(&child.child) {
                        reach.incoming_left = reach
                            .incoming_left
                            .checked_add(1)
                            .ok_or_else(|| tree_error(ValidateError::CumulativeMismatch))?;
                    } else {
                        memo.insert(
                            child.child,
                            NodeReach {
                                incoming_left: 1,
                                first_start: u32::MAX,
                                last_start: 0,
                            },
                        );
                        queue.push_back(child.child);
                    }
                }
            }
            ObjectType::DirLeaf
            | ObjectType::DirInterior
            | ObjectType::Bin
            | ObjectType::BinmapIndex
            | ObjectType::BinTable
            | ObjectType::BinmapShard
            | ObjectType::Root
            | ObjectType::Sheaf => {
                return Err(tree_error(ValidateError::WrongObjectType { id }));
            }
        }
    }
    if root_count != Some(declared_count) {
        return Err(tree_error(ValidateError::CountMismatch));
    }
    if memo
        .get(spill_root)
        .is_none_or(|reach| reach.incoming_left != 0)
    {
        return Err(tree_error(ValidateError::CumulativeMismatch));
    }

    // Kahn propagation releases a node only after every stored incoming
    // edge has merged its minimum and maximum absolute subtree start.
    queue.push_back(*spill_root);
    let mut facts = BTreeMap::new();
    let mut processed = 0_usize;
    while let Some(id) = queue.pop_front() {
        let reach = memo
            .get(&id)
            .copied()
            .ok_or_else(|| tree_error(ValidateError::CumulativeMismatch))?;
        processed = processed
            .checked_add(1)
            .ok_or_else(|| tree_error(ValidateError::CumulativeMismatch))?;

        let bytes = node(nodes, manifest_root, &id)?;
        let (ty, cursor) = encoding::open_envelope(bytes)
            .map_err(|source| tree_error(ValidateError::Decode(source)))?;
        match ty {
            ObjectType::GrainListLeaf => {
                let refs = manifest::decode_grain_list_leaf(cursor)
                    .map_err(|source| tree_error(ValidateError::Decode(source)))?;
                for (local_index, grain) in refs.into_iter().enumerate() {
                    let local_index = u32::try_from(local_index)
                        .map_err(|_| tree_error(ValidateError::CumulativeMismatch))?;
                    let first = reach
                        .first_start
                        .checked_add(local_index)
                        .ok_or_else(|| tree_error(ValidateError::CumulativeMismatch))?;
                    let last = reach
                        .last_start
                        .checked_add(local_index)
                        .ok_or_else(|| tree_error(ValidateError::CumulativeMismatch))?;
                    // Constraint: `check_fill_canonical`'s uniform leaf height and
                    // this walk's FIFO release make validated inputs arrive here in
                    // nondecreasing positional order. `merge_grain_span` deliberately
                    // remains order-independent, so a traversal-order change cannot
                    // silently corrupt its extrema.
                    merge_grain_span(&mut facts, grain, first, last);
                }
            }
            ObjectType::GrainListIndex => {
                let children = manifest::decode_grain_list_index(cursor)
                    .map_err(|source| tree_error(ValidateError::Decode(source)))?;
                let mut local_start = 0_u32;
                for child in children {
                    let first = reach
                        .first_start
                        .checked_add(local_start)
                        .ok_or_else(|| tree_error(ValidateError::CumulativeMismatch))?;
                    let last = reach
                        .last_start
                        .checked_add(local_start)
                        .ok_or_else(|| tree_error(ValidateError::CumulativeMismatch))?;
                    let child_reach = memo
                        .get_mut(&child.child)
                        .ok_or_else(|| tree_error(ValidateError::CumulativeMismatch))?;
                    child_reach.first_start = child_reach.first_start.min(first);
                    child_reach.last_start = child_reach.last_start.max(last);
                    child_reach.incoming_left = child_reach
                        .incoming_left
                        .checked_sub(1)
                        .ok_or_else(|| tree_error(ValidateError::CumulativeMismatch))?;
                    if child_reach.incoming_left == 0 {
                        queue.push_back(child.child);
                    }
                    local_start = u32::try_from(child.cum_ref_count)
                        .map_err(|_| tree_error(ValidateError::CumulativeMismatch))?;
                }
            }
            ObjectType::DirLeaf
            | ObjectType::DirInterior
            | ObjectType::Bin
            | ObjectType::BinmapIndex
            | ObjectType::BinTable
            | ObjectType::BinmapShard
            | ObjectType::Root
            | ObjectType::Sheaf => {
                return Err(tree_error(ValidateError::WrongObjectType { id }));
            }
        }
    }
    if processed != memo.len() {
        return Err(tree_error(ValidateError::CumulativeMismatch));
    }
    Ok(facts)
}

/// Every expanded file path in manifest-walk order, as a fixed-shape
/// emission descriptor — the whole-tree target's enumeration. The
/// returned vector remains necessary because `WholeTree` must finish the
/// directory walk before its first sink call. It is O(expanded file
/// paths), never O(spilled grain positions); an inline descriptor owns
/// at most [`granary_core::manifest::FILE_INLINE_MAX_REFS`] refs already
/// stored in its directory entry. Directory-DAG path expansion itself
/// is bounded by [`WHOLE_TREE_PATH_BUDGET`], charged below over every
/// expanded action.
///
/// **The depth budget resets at each directory's own B-tree root, and
/// is charged only WITHIN one directory — never across directory
/// NESTING.** `validate_dir_tree`'s own rule 4 (`tree.rs`'s
/// `validate_one_dir`, called fresh for every directory the nesting
/// worklist visits) draws exactly this line: a directory's internal
/// fill nodes (`DirInterior` descending to more `DirInterior`/`DirLeaf`
/// nodes of the SAME directory) are bounded by [`DEPTH_MAX`], but
/// entering a CHILD directory (`EntryKind::Dir`) starts that child's
/// own B-tree walk at depth 1 again, uncapped in how many directories
/// may nest — "a walker charging nested subdirectories against a
/// single budget would reject manifests this format accepts" is
/// `tree.rs`'s own words for the shape this walk mirrors.
///
/// **Directory NESTING is an explicit stack, not native recursion —
/// mirroring `tree.rs`'s own `validate_dir_tree`/`validate_one_dir`
/// split exactly.** A fresh depth budget per directory removes the
/// BOUND on nesting depth (the paragraph above); removing the bound
/// while nesting still recursed on the native call stack would only
/// trade one refusal for a different crash — a manifest a validator
/// accepts (nesting is uncapped by contract) reaching a native `fatal
/// runtime error: stack overflow` here, a panic reachable from
/// untrusted input. `collect_dir_actions` keeps the ONE recursion this
/// walk still needs — a directory's own B-tree fill, `DirInterior`
/// descending to more `DirInterior`/`DirLeaf` nodes of the SAME
/// directory — bounded to [`DEPTH_MAX`] frames, same as `tree.rs`'s own
/// `walk_dir`. Crossing into a CHILD directory never recurses: it
/// pushes a new frame — that child's own action list, built fresh at
/// depth 1 — onto a heap-allocated `stack`, and the outer loop below
/// drains frames depth-first by construction (a `Descend` always pushes
/// before the current frame's remaining actions are touched again),
/// so manifest order comes out identical to a recursive walk's without
/// the native stack ever growing past this function's own frame.
fn walk_all_files(
    nodes: &BTreeMap<GrainId, Vec<u8>>,
    root: &GrainId,
    budget: usize,
) -> Result<Vec<FileEmission>, ResolveError> {
    let mut out = Vec::new();
    // ONE counter over every EXPANDED ACTION — a directory descent and a
    // file emission alike, charged before the action is taken. Metering
    // EMISSIONS alone leaves the exponential half of the shape
    // unbounded: a DAG whose directory entries all name one EMPTY child
    // expands `fanout ^ depth` directory paths while `out.len()` stays
    // at 0, so the refusal never fires and the walk runs to exhaustion.
    // Descents are the work; emissions are a subset of it.
    let mut expanded: usize = 0;
    let mut stack: Vec<Vec<DirAction>> = vec![reversed_dir_actions(nodes, root, root)?];
    while let Some(frame) = stack.last_mut() {
        let Some(action) = frame.pop() else {
            stack.pop();
            continue;
        };
        if expanded >= budget {
            return Err(ResolveError::PathBudgetExceeded {
                attempted: expanded.saturating_add(1),
                budget,
            });
        }
        expanded = expanded.saturating_add(1);
        match action {
            DirAction::EmitFile(file) => out.push(file),
            DirAction::Descend(child) => {
                stack.push(reversed_dir_actions(nodes, root, &child)?);
            }
        }
    }
    Ok(out)
}

/// The most EXPANDED ACTIONS — directory descents and file
/// emissions together — a `WholeTree` resolve will take before
/// refusing. Distinct from every byte and object
/// budget: a directory DAG is linear in OBJECTS and exponential in
/// PATHS, and `walk_all_files` allocates per path. The unit is the
/// ACTION, not the emitted file: a DAG whose entries all name one
/// EMPTY child expands exponentially many directory paths and emits
/// nothing at all, so a bound on emissions alone bounds nothing.
///
/// **This bounds the action COUNT; it does NOT bound retained BYTES,
/// and at the ceiling the two are 65x apart.** A `FileEmission` is 80
/// bytes flat (`size_of`, this target), so 2^20 of them are 83,886,080
/// B ≈ 80 MiB of descriptors — but its `grains` field is an INLINE vec
/// that OWNS its refs, up to
/// [`granary_core::manifest::FILE_INLINE_MAX_REFS`] = 128 of them at 40
/// bytes each. The worst legal emission is therefore 5,200 B and 2^20
/// of those are 5,452,595,200 B ≈ 5.08 GiB, all resident before the
/// first sink call — the walk finishes before emission begins. The
/// amplification is this budget's own subject turned on the bytes: in
/// a DAG that shares subtrees, one directory entry is decoded once per
/// PATH, so its refs are COPIED once per path too.
///
/// **That 5.08 GiB is the DOMINANT term, not the whole ceiling.** The
/// walk's pending frame `stack` retains one built action list per
/// directory on the current DFS path as well, alive until that
/// directory's last action is popped — bounded, because content
/// addressing makes the manifest graph acyclic and no path can revisit
/// a node, but not zero and not counted above. Add it before sizing
/// anything from this number.
///
/// **The value and the charge unit stay as they are, deliberately.**
/// Charging inline refs would admit only 2^20 / 128 = 8,192 maximally
/// fragmented files, and lowering the constant by the 65x the byte
/// arithmetic is off would refuse a legitimate repository of a few
/// thousand files — a control added against one exhaustion opening
/// another. The BENIGN headroom says which risk is the real one, and
/// a measured volume (about 105,000 entries and 3,013 structure nodes)
/// resolves in roughly 108,000 actions, about a tenth of this ceiling
/// (`gran cat` uses `Path` and never walks the tree at all).
///
/// **A benign-consumer headroom figure is not a bound on adversarial
/// input, and nothing here should be read as one.** The in-tree
/// adversarial rows deliberately reach this ceiling THROUGH the entry
/// point, not merely by calling the walk directly. And the byte axis
/// is worse than the action axis: an ~8 KB manifest — a deep binary
/// DAG whose every level names one shared child, bottoming out in a
/// leaf that holds a single 128-inline-ref file — is ADMITTED under
/// this budget and retains on the order of a GIGABYTE while doing it.
/// Size a whole-tree consumer from the byte ceiling above, never from
/// the 108,000.
///
/// **Residual, owned by whoever ships a whole-volume consumer.**
/// Memoising the decoded directory leaf by id — so emissions share one
/// copy of a directory's refs instead of copying them per path — is
/// the root fix, and it is where to start if this ceiling ever binds.
/// It does NOT restore the ~80 MiB envelope, though: the memo itself
/// retains the decoded bytes of every distinct directory leaf reached,
/// so the honest claim is ~80 MiB PLUS the memo — bounded by the
/// tree's OBJECT count rather than its PATH count, which is the whole
/// point, but not free. A ref-count charge is the weaker alternative,
/// and it would have to count INLINE refs ONLY: a spilled file's
/// `grain_count` retains no vec here, so charging it would refuse
/// legitimate huge files for bytes this walk never holds.
// `pub(super)`, which is the truth in one word. It carried `pub(crate)`
// across the emission cut with visibility preserved — a `pub(crate)`
// item stays `pub(crate)` through a pure move, where a reviewer could not
// tell a tightening from the move — and the narrowing was registered as a
// one-line follow-up then. This is that follow-up.
//
// What `pub(crate)` bought and is now given up: `mod emission` is PRIVATE,
// so no path outside `resolve` can name this constant directly at either
// spelling. The difference is a re-export — `pub(crate) use
// emission::WHOLE_TREE_PATH_BUDGET` in `resolve.rs` compiles against a
// `pub(crate)` item and is refused against a `pub(super)` one (`E0364`).
// No such re-export exists and nothing outside `resolve.rs` and its tests
// consumes the constant anywhere in the workspace, so what is given up is
// the OPTION of widening without touching this line. Mutation-proved in
// both directions: narrowing further to private fails `E0603`.
pub(super) const WHOLE_TREE_PATH_BUDGET: usize = 1 << 20;

struct FileEmission {
    grains: FileGrains,
    containing_dir_leaf: GrainId,
}

/// One entry `collect_dir_actions` found, in the order it found it —
/// either a file ready to emit or another directory's own B-tree root
/// still to visit.
enum DirAction {
    EmitFile(FileEmission),
    Descend(GrainId),
}

/// [`collect_dir_actions`] over `dir`, REVERSED — ready for
/// [`walk_all_files`]'s own `Vec::pop`, which removes from the back, so
/// popping a reversed list yields entries in their ORIGINAL (forward,
/// manifest) order. The same trick `tree.rs`'s `validate_one_dir` uses
/// on `walk.todo`, for the same reason.
fn reversed_dir_actions(
    nodes: &BTreeMap<GrainId, Vec<u8>>,
    root: &GrainId,
    dir: &GrainId,
) -> Result<Vec<DirAction>, ResolveError> {
    let mut actions = Vec::new();
    collect_dir_actions(nodes, root, dir, 1, &mut actions)?;
    actions.reverse();
    Ok(actions)
}

/// One directory's own B-tree — the recursion `tree.rs`'s `walk_dir`
/// also keeps, bounded to [`DEPTH_MAX`] frames, since it is fill WITHIN
/// one directory, never nesting ACROSS directories. Appends this
/// directory's own files and named children to `out`, in manifest
/// order; a `DirInterior` node's children are visited left to right, so
/// a directory spanning more than one `DirLeaf` still appends in
/// canonical order overall.
fn collect_dir_actions(
    nodes: &BTreeMap<GrainId, Vec<u8>>,
    root: &GrainId,
    dir: &GrainId,
    depth: u32,
    out: &mut Vec<DirAction>,
) -> Result<(), ResolveError> {
    if depth > DEPTH_MAX {
        return Err(ResolveError::Tree {
            root: *root,
            source: ValidateError::DepthExceeded,
        });
    }
    let bytes = node(nodes, root, dir)?;
    let (ty, cursor) = encoding::open_envelope(bytes).map_err(decode_err("manifest node"))?;
    match ty {
        ObjectType::DirLeaf => {
            for entry in manifest::decode_dir_leaf(cursor).map_err(decode_err("dir leaf"))? {
                match entry.kind {
                    EntryKind::Dir { child } => out.push(DirAction::Descend(child)),
                    EntryKind::File { grains, .. } => {
                        out.push(DirAction::EmitFile(FileEmission {
                            grains,
                            containing_dir_leaf: *dir,
                        }));
                    }
                    EntryKind::Symlink { .. } | EntryKind::Fifo | EntryKind::Socket => {}
                }
            }
            Ok(())
        }
        ObjectType::DirInterior => {
            // Still THIS directory's own B-tree fill — the SAME budget
            // continues.
            for ch in manifest::decode_dir_interior(cursor).map_err(decode_err("dir interior"))? {
                collect_dir_actions(nodes, root, &ch.child, depth + 1, out)?;
            }
            Ok(())
        }
        ObjectType::GrainListLeaf
        | ObjectType::GrainListIndex
        | ObjectType::Bin
        | ObjectType::BinmapIndex
        | ObjectType::BinTable
        | ObjectType::BinmapShard
        | ObjectType::Root
        | ObjectType::Sheaf => Err(ResolveError::Tree {
            root: *root,
            source: ValidateError::WrongObjectType { id: *dir },
        }),
    }
}

/// The peak concurrent duplicate-holdback the edge-derived `facts`
/// force, computed from declared lengths ALONE — no wire call, no cache
/// read, no `entries`/`bins` lookup.
///
/// **What forces retention.** An id referenced at more than one
/// position stays resident (and, once charged, stays charged) from its
/// FIRST drained position to its LAST — `emit_file`'s own doc explains
/// why eviction waits for the last occurrence. That is a SPAN over
/// positions, `[first, last]` inclusive; a single-occurrence id has a
/// zero-width span and forces nothing (it drains and evicts together,
/// at the one position that needs it). Sweeping the derived events,
/// the running sum of declared `unpacked_len` over every span covering
/// the current position is the retention the FILE's OWN STRUCTURE
/// demands at that point, independent of how its wants happen to
/// complete — the admission window can only ever DELAY when a want's
/// bytes arrive, never shrink what a duplicate's own span requires
/// resident once they have.
///
/// **The sweep.** Each multi-occurrence fact contributes two events:
/// `+max_len` at `first`, and `-max_len` at the position after `last`.
/// Events sharing a position combine before the running peak reads them.
///
/// **Why the caller refuses rather than schedules around it.** If
/// this peak exceeds the whole in-flight budget, no admission ORDER
/// can avoid it — the retention is forced by which positions the file
/// itself names for that id, not by which want happens to complete
/// first. `emit_file` refuses such a file up front, with the exact
/// peak named. The recorded alternative — re-sourcing a duplicate's
/// bytes from the cache at its LATER positions instead of holding the
/// first fetch resident — is real and better, but belongs to the
/// daemon: it needs a cache to always be present, which resolve's own
/// contract does not require (`cache` is `Option`).
pub(super) fn duplicate_span_peak(facts: &BTreeMap<GrainId, GrainSpan>) -> u64 {
    // Sweep events keyed by position, so several spans starting or
    // ending at the same position combine before the sweep reads them.
    // i128 headroom: even every ref in a maximal spill file at
    // GRAIN_UNPACKED_MAX apiece cannot approach it, so the running
    // total below cannot saturate on legal facts.
    let mut events: BTreeMap<u64, i128> = BTreeMap::new();
    for span in facts.values() {
        if span.first == span.last {
            continue; // single occurrence — zero-width span, forces nothing
        }
        let len = i128::from(span.max_len);
        let after_last = u64::from(span.last).saturating_add(1);
        let start = events.entry(u64::from(span.first)).or_insert(0);
        *start = start.saturating_add(len);
        let end = events.entry(after_last).or_insert(0);
        *end = end.saturating_sub(len);
    }

    let mut running: i128 = 0;
    let mut peak: u64 = 0;
    for delta in events.values() {
        running = running.saturating_add(*delta);
        // Never negative: every decrement's position is strictly past
        // the matching increment's, by construction above.
        let Ok(current) = u64::try_from(running) else {
            return u64::MAX;
        };
        peak = peak.max(current);
    }
    peak
}

/// The unique ids in the order their first positions occur. Span facts
/// are keyed by id for the peak sweep; degraded residency historically
/// reported the first missing id in FILE order, so this edge-derived
/// inverse preserves that diagnostic without expanding positions.
fn grain_ids_in_first_position_order(
    facts: &BTreeMap<GrainId, GrainSpan>,
    manifest_root: &GrainId,
) -> Result<VecDeque<GrainId>, ResolveError> {
    let mut by_first = BTreeMap::new();
    for (id, span) in facts {
        if by_first.insert(span.first, *id).is_some() {
            return Err(ResolveError::Tree {
                root: *manifest_root,
                source: ValidateError::CumulativeMismatch,
            });
        }
    }
    Ok(by_first.into_values().collect())
}

/// Never-silently-partial, made TRUE by a hash-verified
/// residency check over the caller's complete unique-id set, run
/// BEFORE the first `sink` call whenever the read is degraded. Reuses
/// [`Cache::get`] — the crate's own audited, hash-verifying read path
/// — rather than a new cache API or a `stat`: a STAT-ONLY check would
/// pass a corrupt object (a hash mismatch is a MISS on `Cache::get`,
/// never on a size check) and the pre-flight would then wave a file
/// through that the real fetch, moments later, evicts as corrupt —
/// truncating it exactly the way this check exists to prevent.
///
/// **Two call sites, one per emission shape.** [`emit_file`] calls this
/// over its OWN span-fact keys, once per file, right before that file's
/// first byte would reach the sink — sufficient for
/// [`ResolveTarget::Path`], which emits nothing earlier.
/// [`emit_target`]'s `WholeTree` arm ALSO calls this, once, over the
/// union of every file's span-fact keys, before its first structure node
/// reaches the sink — see that arm's own doc for why a per-file check
/// alone is not enough there. Both inputs are already unique, so a grain
/// named by two different files in one `WholeTree` resolve is still only
/// checked once by the whole-set call, and once more by whichever
/// per-file call reaches it.
///
/// Each distinct id is checked once per CALL, not once per position: a
/// duplicate's positions all need the SAME bytes, so a second check
/// within one call would only pay the cost again for no new
/// information.
///
/// **Cost, stated plainly.** On a `Path` target, every grain a file
/// needs is read and hashed TWICE on the degraded path — once by
/// `emit_file`'s pre-flight, once by the real fetch immediately after
/// (page-cache-warm on the second pass). On a `WholeTree` target it is
/// hashed a THIRD time: once by the whole-set pre-flight, once again by
/// the per-file pre-flight the same grain's file still runs, once by
/// the real fetch. The degraded path is the exceptional one to begin
/// with, and rule (d) is worth that cost.
///
/// **Residual, stated and NOT claimed closed.** A concurrent eviction
/// between this check and the real fetch — a competing writer's own
/// quota eviction racing this read — can still truncate the file: this
/// pre-flight proves residency at ONE instant, not for the whole
/// function's duration. Cache objects are content-addressed and `0444`,
/// so a grain can VANISH under that race but can never
/// CHANGE — which is what keeps this a race between two reads of an
/// immutable object's presence, never a correctness hole a hash check
/// could have caught.
fn residency_preflight(
    mut cache: Option<&mut Cache>,
    ids: impl IntoIterator<Item = GrainId>,
    source: &RootStoreError,
) -> Result<(), ResolveError> {
    for id in ids {
        let hit = cache.as_deref_mut().is_some_and(|c| c.get(&id).is_some());
        if !hit {
            return Err(ResolveError::Degraded {
                missing: format!("content grain {id}"),
                source: source.clone(),
            });
        }
    }
    Ok(())
}

fn want_for_position(
    r: GrainRef,
    declaring_node: GrainId,
    entries: &BTreeMap<GrainId, ShardEntry>,
    bins: &[[u8; DIGEST_LEN]],
    span_facts: &BTreeMap<GrainId, GrainSpan>,
    manifest_root: &GrainId,
) -> Result<Want, ResolveError> {
    // Unreachable after `check_reachable_grains`, retained as typed
    // refusals because every lookup is ultimately selected by stored
    // data. This runs for every position before fetch admission dedups
    // ids, preserving the position-specific declaring-node diagnostic.
    let entry = entries.get(&r.id).ok_or(ResolveError::UnmappedGrain {
        id: r.id,
        node: declaring_node,
    })?;
    let ordinal = usize::try_from(entry.bin_ordinal).map_err(|_| ResolveError::BadOrdinal {
        id: r.id,
        ordinal: entry.bin_ordinal,
    })?;
    let digest = *bins.get(ordinal).ok_or(ResolveError::BadOrdinal {
        id: r.id,
        ordinal: entry.bin_ordinal,
    })?;
    let max_len = span_facts
        .get(&r.id)
        .ok_or(ResolveError::Tree {
            root: *manifest_root,
            source: ValidateError::CumulativeMismatch,
        })?
        .max_len;
    Ok(Want::BinRange {
        id: r.id,
        digest,
        offset: entry.offset,
        comp_len: entry.comp_len,
        unpacked_len: max_len,
    })
}

/// Stream one file's content grains, in FILE order, through `fetcher`
/// and to `sink` — the per-file reassembly the module doc's holdback
/// argument covers.
///
/// **Positional truth.** Every check here reads ONE streamed position's
/// own `unpacked_len` and declaring node — never an id-keyed map that
/// collapses every reference to one grain down to a single remembered
/// declaration. Two positions naming
/// the SAME grain with CONFLICTING declared lengths are two SEPARATE
/// checks, each against the SAME fetched bytes: a duplicate only one of
/// them agrees with is caught at whichever position disagrees, not
/// silently passed because an earlier (or later) declaration for the
/// same id happened to match.
///
/// **Out-of-order completion cannot reorder emission.** Both positional
/// iterators are in FILE order: the first streams `Want`s into
/// `fetch_streaming`, whose admission dedups ids while retaining their
/// first-position order, and the second drives the drain below;
/// that drain advances the position cursor forward only while the NEXT
/// position's bytes are already resident, buffering anything that
/// arrives early. FIFO admission means the earliest position not yet
/// emitted is always the front of the admission queue — the front never
/// waits behind something later — so a full holdback always has its one
/// missing (gap) grain in flight, never stuck behind an already-admitted
/// later one: the budget can delay this function, never deadlock it
/// (the error-mode paragraph below is the one exception, and it is a
/// deliberate exit, not a wedge).
///
/// **`held` evicts, and a want's charge releases at the SAME moment,
/// not before.** The edge-derived facts name each id's exact LAST
/// position; the entry leaves `held` when the drain reaches that
/// position, and THAT eviction — never an earlier occurrence's own
/// drain — is what removes the id
/// from `charged_unreleased` and releases its converted bytes, if it
/// was ever charged. A grain referenced once is retained, charged, and
/// released together at the one position that needs it; a grain
/// referenced N times stays resident AND stays charged across all N
/// positions, releasing only once its Nth (last) position has drained
/// — the charge lives exactly as long as the bytes do, never freed
/// while a later duplicate still needs them resident. A cache hit IS
/// charged at its verified `bytes.len()` (`fetch_streaming` passes
/// `charged: true`) and therefore enters `charged_unreleased`; its final
/// eviction releases that charge exactly like a wire completion's. Treating
/// a hit as free here would strand its charge and eventually wedge admission.
///
/// **Length is checked here, per position, against ITS OWN
/// declaration** — `check_reachable_grains`'s length half, moved to
/// where the bytes actually are (the module's doc explains the scope).
/// Emission STOPS at the first mismatch: a position already emitted
/// before it is a proven-correct prefix, never rewound; no position
/// after it is emitted.
///
/// **Error mode.** The moment `first_err` is set — a failed want, a
/// length mismatch, or a sink refusal — this function stops holding
/// ANYTHING back: every id still in `charged_unreleased` at that instant
/// is released in the SAME step (its buffered bytes are never going to
/// be emitted now, so there is nothing left to hold them for), `held`
/// and `charged_unreleased` are both cleared, and every completion still
/// to arrive afterward releases IMMEDIATELY too (its own converted
/// bytes if charged, nothing if not) instead of being buffered and
/// checked — nothing is sunk and nothing is drained positionally once
/// in this mode. Without this, a held-back completion arriving AFTER
/// the first error would buffer (return `0`) forever: the drain loop
/// that would normally release it never runs again (it stopped at the
/// gap the error left), so its charge would stay reserved for good —
/// enough of those and admission closes with nothing left in flight to
/// ever complete and free it, which is a permanent hang, not merely a
/// delay. `fetch_streaming` itself already releases a FAILING want's own
/// charge unconditionally (that method's own doc), so the only gap this
/// function has to close is the one for wants that succeed AFTER the
/// first error.
///
/// **`degraded`**: when `Some`, a hash-verified RESIDENCY PRE-FLIGHT
/// runs before the peak gate and want iterator — see
/// [`residency_preflight`]'s own doc for why this, and only this, is
/// what makes rule (d) (never silently partial) true on a degraded
/// path. Emission is streaming and positional (this doc, above):
/// without the pre-flight, a file with position 0 cached and a LATER
/// position evicted would emit position 0's bytes to the sink and
/// only THEN fail — a truncated file, not a clean refusal.
#[expect(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    reason = "one streaming positional drain (want mapping, eviction-at-last, the \
              charge-once release loop, and error mode) shares one closure's captured state \
              and the validated manifest inputs"
)]
async fn emit_file<R: BinStore>(
    fetcher: &mut Fetcher<'_, R>,
    mut cache: Option<&mut Cache>,
    entries: &BTreeMap<GrainId, ShardEntry>,
    bins: &[[u8; DIGEST_LEN]],
    nodes: &BTreeMap<GrainId, Vec<u8>>,
    manifest_root: &GrainId,
    grains: &FileGrains,
    containing_dir_leaf: GrainId,
    sink: &mut EmitSink<'_>,
    degraded: Option<&RootStoreError>,
) -> Result<(), ResolveError> {
    let span_facts = grain_span_facts(nodes, manifest_root, grains)?;

    if let Some(source) = degraded {
        let resident_ids = grain_ids_in_first_position_order(&span_facts, manifest_root)?;
        residency_preflight(cache.as_deref_mut(), resident_ids, source)?;
    }

    // STATIC DUPLICATE-SPAN PRE-BOUND — before any wire call or cache
    // read, before `entries`/`bins` are even consulted: see
    // `duplicate_span_peak`'s own doc for the sweep and why this is the
    // one shape release-at-eviction cannot admit-and-drain within the
    // budget, whatever order its wants complete in.
    let peak = duplicate_span_peak(&span_facts);
    if peak > FETCH_INFLIGHT_BYTES {
        return Err(ResolveError::DuplicateSpanExceedsBudget {
            need: peak,
            budget: FETCH_INFLIGHT_BYTES,
        });
    }

    // Mapping remains positional so the first impossible mapping error
    // retains its declaring-node diagnostic. `fetch_streaming` consumes
    // this fallible iterator completely before cache or wire admission,
    // retaining only one queued want per unique id.
    let wants =
        grain_positions(nodes, manifest_root, grains, containing_dir_leaf).map(|position| {
            let (r, declaring_node) = position?;
            want_for_position(r, declaring_node, entries, bins, &span_facts, manifest_root)
        });

    let mut held: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    let mut charged_unreleased: BTreeSet<GrainId> = BTreeSet::new();
    let mut positions = grain_positions(nodes, manifest_root, grains, containing_dir_leaf);
    let mut pending_position: Option<(GrainRef, GrainId)> = None;
    let mut next_pos: usize = 0;
    let mut first_err: Option<ResolveError> = None;

    fetcher
        .fetch_streaming(cache, wants, |id, result, charged| {
            // ERROR MODE: release immediately, buffer nothing, sink
            // nothing, touch no positional state — see this function's
            // own doc's "Error mode" paragraph for why this closes the
            // permanent-hang gap.
            if first_err.is_some() {
                return match (&result, charged) {
                    (Ok(bytes), true) => bytes.len() as u64,
                    _ => 0,
                };
            }

            match result {
                Err(e) => {
                    first_err = Some(map_fetch_err("object", id, e));
                    // Flush: everything this closure was ALREADY holding
                    // back is never going to drain now.
                    // `fetch_streaming` releases THIS want's own
                    // (failed, unconverted) charge on its own — this
                    // return is the EXTRA, on top of that.
                    let flush: u64 = charged_unreleased
                        .iter()
                        .filter_map(|held_id| held.get(held_id).map(|b| b.len() as u64))
                        .fold(0, u64::saturating_add);
                    held.clear();
                    charged_unreleased.clear();
                    flush
                }
                Ok(bytes) => {
                    if charged {
                        charged_unreleased.insert(id);
                    }
                    held.insert(id, bytes);

                    // Drain the in-order prefix as far as it now
                    // reaches — a gap (the next position's bytes not
                    // yet resident) stops the drain without touching
                    // anything after it, which is the no-reorder
                    // property: nothing later ever emits before
                    // something earlier that has not arrived.
                    let mut released: u64 = 0;
                    loop {
                        let position = if let Some(position) = pending_position.take() {
                            Some(Ok(position))
                        } else {
                            positions.next()
                        };
                        let (r, declaring_node) = match position {
                            Some(Ok(position)) => position,
                            Some(Err(error)) => {
                                first_err = Some(error);
                                break;
                            }
                            None => break,
                        };
                        let want_id = r.id;
                        let Some(bytes) = held.get(&want_id) else {
                            pending_position = Some((r, declaring_node));
                            break;
                        };
                        let declared_len = if let Ok(len) = usize::try_from(r.unpacked_len) {
                            len
                        } else {
                            first_err = Some(ResolveError::Tree {
                                root: *manifest_root,
                                source: ValidateError::CountMismatch,
                            });
                            0
                        };
                        if first_err.is_none() && bytes.len() == declared_len {
                            if let Err(message) = sink(want_id, bytes) {
                                first_err = Some(ResolveError::Sink { message });
                            }
                        } else if first_err.is_none() {
                            first_err = Some(ResolveError::GrainLenMismatch {
                                id: want_id,
                                node: declaring_node,
                                want: r.unpacked_len,
                                got: bytes.len(),
                            });
                        }
                        let at_last = if let Some(span) = span_facts.get(&want_id) {
                            match usize::try_from(span.last) {
                                Ok(last) if last >= next_pos => last == next_pos,
                                Ok(_) | Err(_) => {
                                    if first_err.is_none() {
                                        first_err = Some(ResolveError::Tree {
                                            root: *manifest_root,
                                            source: ValidateError::CumulativeMismatch,
                                        });
                                    }
                                    false
                                }
                            }
                        } else {
                            if first_err.is_none() {
                                first_err = Some(ResolveError::Tree {
                                    root: *manifest_root,
                                    source: ValidateError::CumulativeMismatch,
                                });
                            }
                            false
                        };
                        if let Some(advanced) = next_pos.checked_add(1) {
                            next_pos = advanced;
                        } else if first_err.is_none() {
                            first_err = Some(ResolveError::Tree {
                                root: *manifest_root,
                                source: ValidateError::CountMismatch,
                            });
                        }
                        // EVICTION AND RELEASE, TOGETHER — `bytes`
                        // (borrowed from `held` above) is not read again
                        // past this point, so the mutable borrow below is
                        // sound. The charge lives exactly as long as the
                        // bytes do: a duplicate reference stays resident
                        // AND stays charged across every occurrence
                        // before its last, and only the LAST occurrence's
                        // own drain both frees `held`'s entry and, if it
                        // was ever charged, releases it — never at the
                        // first occurrence, while later duplicates still
                        // need the bytes resident.
                        if at_last
                            && let Some(evicted) = held.remove(&want_id)
                            && charged_unreleased.remove(&want_id)
                        {
                            released = released.saturating_add(evicted.len() as u64);
                        }
                        if first_err.is_some() {
                            // THIS position's own check just set
                            // first_err (a mismatch or a sink refusal)
                            // — transition to error mode now: flush
                            // everything else still held, since none of
                            // it will ever drain.
                            let flush: u64 = charged_unreleased
                                .iter()
                                .filter_map(|held_id| held.get(held_id).map(|b| b.len() as u64))
                                .fold(0, u64::saturating_add);
                            held.clear();
                            charged_unreleased.clear();
                            released = released.saturating_add(flush);
                            break;
                        }
                    }
                    released
                }
            }
        })
        .await?;

    if let Some(e) = first_err {
        return Err(e);
    }
    // Every position must have drained — `fetch_streaming` completing
    // with every want answered and none erroring guarantees it (each
    // completion's drain loop stops only at a gap, and there is no gap
    // left once every id has arrived). The file's TOTAL declared size
    // and grain count are not re-checked here: `fetch_tree_structure`'s
    // walk already ran `validate_file_grains` over this file's declared
    // lengths before emission began, so a per-grain length match here,
    // for every position, already implies the sums it proved.
    // Unreachable in practice; typed rather than asserted, on this
    // crate's rule against panicking on anything reachable from a
    // stored object.
    let positions = usize::try_from(grains.grain_count()).map_err(|_| ResolveError::Tree {
        root: *manifest_root,
        source: ValidateError::CountMismatch,
    })?;
    if next_pos != positions {
        return Err(ResolveError::IncompleteDrain {
            positions,
            drained: next_pos,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
