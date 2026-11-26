#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# The structural scanner behind the root-shape gate in
# scripts/check-vfs-root-shape.sh.
# Reuses scripts/fsguard-scan.py's comment/string stripper, attribute/brace
# matching and top-comma splitter — imported by file path via `importlib`,
# the same technique scripts/vfs-purity-scan.py already uses, never copied.
#
# THE GATE IS AN ALLOW-LIST, NOT A DENY-LIST. A
# deny-list enumerates known-bad shapes and is defeated by the shape
# nobody enumerated; an allow-list enumerates known-GOOD shapes and fails
# CLOSED on everything else, including a route nobody thought of yet.
# `granary-vfs/src/lib.rs`'s crate scope may contain, and ONLY contain:
#
#   - attributes (inner `#![...]` / outer `#[...]`) and doc comments —
#     doc comments are already invisible: the comment/string stripper
#     blanks them before this scanner ever sees the text
#   - a non-`pub` `extern crate` item (`extern crate alloc;`) — a `pub
#     extern crate` promotes a whole crate name to the root and is refused
#   - a non-`pub` `mod` declaration or inline definition (`mod foo;` /
#     `mod foo { ... }`, including `pub(crate)`/`pub(super)` visibility,
#     neither of which crosses the crate boundary) — a genuinely `pub mod`
#     replaces curation with wholesale exposure and is refused. An inline
#     module's whole body is skipped as one block, WHATEVER IS INSIDE
#     IT: it is private, so nothing inside it is part of the root's
#     public surface as far as a NAME resolves, and this scanner does
#     not try to understand what is in it (this is what keeps
#     `#[cfg(test)] mod <name> { ... }`'s own fns, `use` imports and
#     assertions green without a single special case).
#     **NOT CAUGHT: an `impl` block inside such a body still widens an
#     EXISTING type's real public surface — `impl` blocks are not scoped by
#     their enclosing module's visibility. Deciding whether the `Self` type is
#     externally reachable needs compiler name resolution, which a text
#     scanner does not have; a dedicated check for exactly this was shipped
#     and then CUT, refuted by execution in BOTH directions — an attributed
#     `impl` slipped past it, and a legitimate private test-double `impl` was
#     refused alongside a real violation.**
#   - a non-`pub` `use` (private, `pub(crate)`, `pub(super)`, `pub(in
#     ...)`) — none of these create an externally-visible re-export
#   - a `pub use` whose target is a NAMED LEAF: `pub use path::Name;`,
#     `pub use path::Name as Alias;`, or a (possibly nested) brace list
#     of named leaves. An ungrouped path must contain `::`; a grouped
#     leaf may be a bare identifier. Glob and `self` leaves are refused,
#     including `path::*`, `path::{*}`, `path::self`, and `path::{self}`.
#     PLUS the first-segment foreign-root check below: the
#     path's first segment (after stripping one leading `crate::`/
#     `self::` anchor) must be one of this crate's own modules declared
#     at the root — never a foreign crate. **NOT CAUGHT: With `snapshot`
#     declared at the root, `crate::snapshot`, `self::snapshot`,
#     `crate::{snapshot}`, `{snapshot}`, and `snapshot::sibling` pass as
#     `pub use` bodies. The scanner checks leaf spelling without resolving
#     whether it names a module or another item.**
#
# Everything else — every item DEFINITION at crate scope (`const`,
# `static`, `struct`, `enum`, `union`, `trait`, `type`, `fn`, `impl`, an
# `extern "C" { ... }` foreign block, `macro_rules!`), any bare macro
# INVOCATION (`some_macro! { ... }`), and a `pub mod`/`pub extern crate`
# — is simply not on the list, and is refused by naming the line. There
# is no separate "unclassifiable macro invocation" bucket: with a
# deny-list, an unrecognised construct is a genuine "I don't know" that
# has to refuse uncertainly (exit 2); with an allow-list, "not on the
# list" already IS a confident, complete answer (exit 1, the same as any
# other refusal). Exit 2 is reserved for this scanner being unable to
# read or parse the input at all (see `--could-not-run` conditions in
# each command's own docstring below) — never for a construct it merely
# does not recognise.
#
# WHAT THE FIRST-SEGMENT CHECK AND THE NAMED-LEAF CHECK CLOSE BEYOND THE
# BASE NAMED-LEAF SHAPE, AND WHAT THEY DELIBERATELY LEAVE TO OTHER MECHANISMS:
#   - THE GLOB ROUTE IS CLOSED HERE, BY THIS SCANNER'S OWN NAMED-LEAF
#     CHECK — the deliberate, primary mechanism, not an incidental side
#     effect of requiring a named-leaf shape. A workspace clippy config
#     (`warn-on-all-wildcard-imports = true`) is kept as defence-in-depth,
#     but it is NOT sufficient on its own: EXECUTED, `mod extra;` plus
#     `pub use extra::*;` at a crate root produces ZERO
#     `wildcard_imports` warnings — clippy skips the lint whenever
#     `names_imported_by_glob_use` is empty (the case for a `pub use`
#     re-export glob, since nothing NAMES the imported items at the
#     glob site) and defers to `unused_imports`, which never fires on a
#     re-export either. This scanner's named-leaf check is the closer.
#   - BARE UNGROUPED PATHS AND `self` LEAVES ARE REFUSED —
#     `pub use snapshot;` lacks the `::` required by
#     `classify_pub_use_top`'s no-brace branch. `snapshot::{self}` and
#     `snapshot::self` have a forbidden `self` leaf. With `snapshot`
#     declared at the root, `crate::snapshot`, `self::snapshot`,
#     `crate::{snapshot}`, `{snapshot}`, and `snapshot::sibling` pass.
#     Named leaves are not resolved as modules or other items.
#   - A FOREIGN-CRATE ROOT (`pub use granary_core::manifest;`, or any
#     path whose first segment — after stripping one leading `crate::`/
#     `self::` anchor, if present — is not one of this crate's own
#     modules declared at the root) is refused by the first-segment
#     foreign-root check: the
#     engine root re-exports only its own items. This check is KEPT —
#     it is a first-segment test against the crate's OWN root-level
#     `mod` declarations (derived from the same `lib.rs` text this
#     scanner already reads, no separate file walk), not a
#     leaf-classification test, and is not implicated by the cut above.
#     GENERALIZED through `_foreign_root_reason`:
#     `_foreign_root_reason` runs at every unchecked path root; it is
#     propagated into a nested group only when no real first segment has
#     already been checked. It runs uniformly at every path root that can reach the crate's root
#     surface, INCLUDING one reached through a bare `crate::`/`self::`
#     anchor before a brace group (`pub use crate::{alloc::boxed::Box};`)
#     and one carried by an entry that is itself a leading nested brace
#     group with no prefix (`pub use {{attr::Attr}, handle::HandleKind};`).
#     Checked once per root; an already-checked prefix is never re-applied
#     to its own nested sub-paths (`snapshot::{inner::Thing}` stays green).
#   - `#[macro_export]` is a SEPARATE arm (`--macro-export`, below), not
#     part of the allow-list walk: a `#[macro_export] macro_rules!` in a
#     CHILD module lands in the crate root's namespace with zero lines
#     changed in `lib.rs`, so the allow-list walk (which only ever reads
#     `lib.rs`) cannot see it at all. **This arm is an explicitly
#     LITERAL-SOURCE defence, not a semantic closer.** It matches the
#     attribute's own TEXT, so it fails in both directions: a macro built to
#     EXPAND into `#[macro_export]` through an indirection like
#     `#[$attr] macro_rules! …; plant!(macro_export);` passes both this scan
#     and `cargo clippy` undetected, and — the opposite error — a dormant
#     macro TEMPLATE that merely CONTAINS the literal `macro_export` inside a
#     `macro_rules!` body it never expands is reported as though it had
#     exported something.
#
# WHAT THIS SCANNER IS, STATED PLAINLY:
# the literal-source limitations in this header bound what this scanner claims.
# The compiler-dependent arms stay cut because this scanner cannot resolve
# their questions, and the retained arms have the limitations below. It is a
# LITERAL-SOURCE shape scanner over `lib.rs`'s
# crate scope, not complete public-surface enforcement, and it does not
# resist a determined bypass. At least two classes named here (not a closed
# register; these are the literal-source limitations stated in this header), neither
# fixed, because closing either needs information this scanner
# structurally does not have:
#   - A `#[cfg(any())] mod core;` declaration still enters the module
#     inventory this scanner derives from `lib.rs`'s own text (cfg state
#     is not evaluated), so `pub use core::fmt::Debug;` then passes as
#     though `core` were one of this crate's own modules — closing this
#     needs the crate's cfg state, which a text scanner does not have.
#   - This scanner counts `pub use` STATEMENTS ("N allowed pub use
#     line(s)"), not resolved public NAMES: `pub use attr::{};`,
#     `pub use {};`, and `pub use attr::Attr as _;` each name zero real
#     public identifiers but are still counted as one allowed line —
#     inflating the reported count without widening the actual public
#     surface. A correct fix needs a name count threaded through
#     `_classify_use_tree_list`'s whole recursion (and a second counter
#     kept apart from `scan_root_shape`'s own zero-`pub-use`-lines
#     could-not-run floor, which currently reads "zero attempts" as
#     "could not walk this as a crate root" — conflating the two would
#     make a legitimate all-`_`-aliased root read as unreadable); priced
#     and declined as more than this counting inaccuracy is worth.
#
# `_collect_root_module_names` walks depth zero only: it skips an inline
# `mod { ... }` body as one block, so a nested decoy such as
# `mod sneaky { mod core {} }` cannot enter the module inventory.
# A `#[cfg(any())] mod core;` declared directly at crate scope still enters
# that inventory because the scanner does not evaluate cfg state.
#
# Two commands, each ONE process (never piped through `head`/`xargs`, for
# the same reason fsguard-scan.py's own header gives: a batched or
# truncated capture can print more than one structured line, or none,
# into a caller's `$(...)`):
#
#   vfs-root-shape-scan.py --root-shape <path-to-lib.rs>
#       Walks <path>'s crate scope (depth 0, on comment/string-stripped
#       text) left to right. Prints `PUBUSE-COUNT <n>` for the number of
#       ALLOWED `pub use` statements found (the caller's floor: a root
#       with zero of them could not have been walked as the crate's real
#       root), then one `REFUSE <line>: <reason> :: <original source
#       line>` per construct not on the allow-list. Exit 0 whether or not
#       any REFUSE line was printed — the caller decides pass/fail, same
#       division of labour as vfs-purity-scan.py's `--attr`/`--closure`.
#       Exit 2 — COULD NOT RUN, never read as clean — if <path> cannot be
#       read as UTF-8, or the walk finds an attribute/brace/`pub use`
#       whose matching delimiter this scanner cannot locate (a malformed
#       or truncated file: rustc would refuse it too, and refusing to
#       guess is the only sound response to source this scanner cannot
#       parse).
#
#   vfs-root-shape-scan.py --macro-export < NUL-separated paths
#       Reads file paths from stdin (`find crates/granary-vfs/src -name
#       '*.rs' -print0 | vfs-root-shape-scan.py --macro-export`) and
#       prints `MACRO-EXPORT <path>:<line>: <original source line>` for
#       every `#[macro_export]` attribute found anywhere under
#       `crates/granary-vfs/src/` — not just in `lib.rs`, because THIS is
#       the one route that adds a root-namespace item with no `lib.rs`
#       diff at all. Matched structurally inside an attribute's own
#       brackets (so a `#[cfg_attr(cond, macro_export)]` counts, and a
#       decoy in a comment or a string does not); a plain, non-exported
#       `macro_rules!` beside it is not matched and must stay green.
#       Exit 0 normally; exit 2 if any input file cannot be read.
#
import importlib.util
import os
import re
import sys

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_FSGUARD_PATH = os.path.join(_SCRIPT_DIR, "fsguard-scan.py")


def _load_fsguard_scan():
    spec = importlib.util.spec_from_file_location("fsguard_scan_lib", _FSGUARD_PATH)
    if spec is None or spec.loader is None:
        print(f"ERROR could not load {_FSGUARD_PATH} as a module", file=sys.stderr)
        sys.exit(2)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as e:  # noqa: BLE001 — any failure here is a refusal
        print(f"ERROR could not import {_FSGUARD_PATH}: {e}", file=sys.stderr)
        sys.exit(2)
    return mod


fsguard = _load_fsguard_scan()

WS = fsguard.WS
IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
IDENT_RE = re.compile(IDENT)

# `pub`, `pub(crate)`, `pub(super)`, `pub(self)`, `pub(in a::b)` — every
# visibility spelling that is NOT full, crate-crossing `pub`. Captured as
# one group so the caller can tell "matched, text == 'pub'" (full public)
# apart from "matched, text starts 'pub('" (restricted) and "did not
# match at all" (private) — the THREE-way distinction a naive `pub\s+`
# matcher collapses to two, silently treating `pub(crate)` as absent.
PUB_RE = rf"pub{WS}*(?:\({WS}*[^)]*\){WS}*)?"

WS_RUN_RE = re.compile(rf"{WS}*")
EXTERN_CRATE_HEAD_RE = re.compile(
    rf"(?P<pub>{PUB_RE})?extern{WS}+crate{WS}+{IDENT}"
    rf"(?:{WS}+as{WS}+{IDENT})?{WS}*;"
)
MOD_HEAD_RE2 = re.compile(rf"(?P<pub>{PUB_RE})?mod{WS}+(?P<name>{IDENT}){WS}*")
USE_HEAD_RE = re.compile(rf"(?P<pub>{PUB_RE})?use\b")

# Normalize the `WS` class ONCE, at the source, before
# any regex or split below ever runs — not at each comparison site.
#
# Python's bare `.strip()` does not remove U+200E/U+200F. A mark
# after `pub` would make `pub_text.strip() == "pub"` false, treating
# a public declaration as private. Visibility checks and alias text
# need normalization as well as path segments and leaves.
#
# Source-wide normalization covers those inputs; per-site checks leave
# a gap whenever a comparison is omitted. Blanking every `WS`-class character
# except plain spaces and newlines after blanking comments and strings means
# no comparison site downstream — known today, or added tomorrow — can miss the class,
# because no such character survives for it to miss. This is a
# single-character substitution (one `WS`-class character in, one
# ASCII space out), so it preserves `clean`'s exact length and every
# newline stays in place: every line number and column this scanner
# reports off `clean` stays correct. `_norm_segment` (below) is KEPT —
# it still does the right thing on an ordinary run of spaces or tabs,
# and remains at the three path-segment comparison sites — but
# this pre-pass makes its `WS`-class role dead code: not
# load-bearing, and not a live second line of defence
# either.
# MUTATION-
# PROVED: reverting all three `_norm_segment` call sites to a bare
# `.strip()` at once leaves `--self-test` AND the real gate at rc=0 —
# this pre-pass makes those three sites' own normalization dead code,
# not merely redundant on some inputs, because nothing downstream of
# this function can still see a WS-class mark for `_norm_segment` to
# strip. The three `_norm_segment` calls are dead behind
# `_normalize_ws_class`; see `_is_full_pub`'s own docstring below for the ONE
# site that has no such belt at all.
#
# Arm B bypasses this normalization and is mark-robust
# only accidentally through Python `\b`. In detail, this pre-pass runs
# inside `scan_root_shape` ONLY. `scan_macro_export` (arm B, below)
# builds its OWN `clean` from `strip_comments_and_strings` directly and
# never calls `_normalize_ws_class` — a WS-class mark reaching arm B's
# `MACRO_EXPORT_RE = re.compile(r"\bmacro_export\b")` is untouched by
# anything this paragraph describes. Arm B stays mark-robust today only
# because Python's own `\b` treats U+200E/U+200F as non-word characters
# — an accident of `\b`'s semantics, not a designed invariant this
# scanner enforces.
_WS_CHAR_RE = re.compile(WS)


def _normalize_ws_class(clean):
    """Replace every character `WS` matches, except a plain ASCII space
    or a newline, with a plain ASCII space — one character in, one
    character out, so `clean` keeps its exact length and every newline
    stays exactly where it was; every position, line number and column
    computed on the result afterward stays correct. Applied ONCE, right
    after `strip_comments_and_strings`, to the whole text this scanner
    then walks — see the comment above `_WS_CHAR_RE` for why
    this replaces per-site normalization rather than adding to it."""
    return _WS_CHAR_RE.sub(lambda m: m.group(0) if m.group(0) in (" ", "\n") else " ", clean)


# The first-segment foreign-root check's crate-owned ROOT-LEVEL MODULE NAMES, used
# ONLY for the first-segment foreign-crate check below. Derived
# from `_collect_root_module_names`'s OWN depth-0 walk —
# see that function's docstring — never a whole-file regex.
# A cfg-disabled root module can still spoof the module inventory because
# cfg is not evaluated; a nested decoy module cannot, because
# `_collect_root_module_names` walks depth zero only.


def _collect_root_module_names(clean):
    """The first-segment foreign-root check's module-names set: every `mod <name>` head
    this scanner's OWN depth-0 walk passes over, on the SAME
    comment/string-stripped, `WS`-normalized text `scan_root_shape`
    then walks for real — never a second, independent regex pass over
    the whole file. Mirrors `scan_root_shape`'s own loop exactly
    (attributes skipped, `extern crate`/`mod`/`use` heads recognised,
    everything else skipped via `fsguard.item_extent`) but only ever
    RECORDS a `mod` head's name; it does not classify visibility or
    build any refusal, because `scan_root_shape`'s own walk — called
    right after this one, on the same text — does that and will raise
    the identical could-not-run diagnostic if the two ever disagree on
    where a construct ends.

    A cfg-disabled root module can still spoof the module inventory because cfg
    is not evaluated; a nested decoy module cannot, because
    `_collect_root_module_names` walks depth zero only. A `mod` declared inside
    an inline `mod { ... }` body is never
    visited at all: this walk skips such a body as ONE block, the same
    way `scan_root_shape` does, so the inventory this function returns
    is DEPTH-0 ONLY, so a nested decoy module cannot enter it (see the comment
    above this function).

    Returns `None` if the text cannot be walked (an attribute or an
    inline `mod` body's brace could not be matched) — `scan_root_shape`
    performs the identical walk immediately afterward and will hit the
    same construct at the same position, raising its own could-not-run
    diagnostic there; this function does not need a second one, and a
    caller must never treat `None` here as "no modules" (an empty set)."""
    n = len(clean)
    pos = 0
    names = set()
    while pos < n:
        skipped = _skip_ws_and_attrs(clean, pos)
        if skipped is None:
            return None
        pos = skipped
        if pos >= n:
            break
        m = EXTERN_CRATE_HEAD_RE.match(clean, pos)
        if m:
            pos = m.end()
            continue
        m = MOD_HEAD_RE2.match(clean, pos)
        if m:
            names.add(m.group("name"))
            after = _skip_ws_and_attrs(clean, m.end())
            if after is None or after >= n:
                return None
            ch = clean[after]
            if ch == ";":
                pos = after + 1
            elif ch == "{":
                close = fsguard.find_matching(clean, after, "{", "}")
                if close is None:
                    return None
                pos = close + 1
            else:
                return None
            continue
        m = USE_HEAD_RE.match(clean, pos)
        if m:
            semi = clean.find(";", m.end())
            if semi == -1:
                return None
            pos = semi + 1
            continue
        _, end, _, _ = fsguard.item_extent(clean, pos)
        pos = max(end, pos) + 1
    return names


# Path-segment comparisons use this file's `WS` class, which includes
# U+200E/U+200F (LEFT-TO-RIGHT MARK / RIGHT-TO-LEFT MARK); Python's
# built-in `str.strip()` does not remove those marks. Examples:
# `pub use attr‎::Attr;` and `pub use attr::‎Attr;`.
# `_normalize_ws_class` blanks those marks in the source before any
# path-segment comparison runs, so this helper's mark handling is redundant
# on that path. It also strips ordinary spaces and tabs.
_SEGMENT_TRIM_RE = re.compile(rf"^{WS}+|{WS}+$")


def _norm_segment(s):
    """Strip a run of this file's `WS` class — never Python's
    `str.strip()` — from both ends of one path segment or leaf-side
    string. See the comment above `_SEGMENT_TRIM_RE` for why: a bare
    `.strip()` on a segment compared against `module_names` (or against
    a leaf's own shape) leaves U+200E/U+200F attached, and a segment
    that still carries one of those never equals the clean name in
    this crate's module inventory — refusing valid Rust, exactly the
    false-refusal failure mode this allow-list exists to prevent."""
    return _SEGMENT_TRIM_RE.sub("", s)


def _is_full_pub(pub_text):
    """True only for a bare `pub` — never for `pub(crate)` and friends,
    and never for no match at all (private). The exact three-way split
    every arm below needs: full pub is the ONLY visibility a `mod`/
    `extern crate` promotes across the crate boundary, and the ONLY one
    a `pub use` needs its named-leaf shape checked for.

    Deliberately still a bare `.strip()`, not `_norm_segment`:
    `scan_root_shape` normalizes the whole `WS` class out of `clean`
    before this function ever sees `pub_text`, so a per-call normalize
    here would be redundant on every input that can actually reach it —
    see `_normalize_ws_class`'s own comment for why this is the
    structural fix rather than one more site added to the enumeration.

    **NOTE:** `_is_full_pub` has no fallback if the normalization
    pre-pass is bypassed; this is the inverse of the three `_norm_segment` call
    sites' own asymmetry.** Those three
    keep a redundant `_norm_segment` call that the pre-pass has made
    dead code (MUTATION-PROVED — see `_normalize_ws_class`'s comment),
    but a redundant call that still does the right thing on its own if
    the pre-pass is ever bypassed. This function has NO such fallback —
    it is the ONE call site every downstream visibility decision in
    this whole scanner depends on, and it is also the ONE call site with
    zero belt-and-braces of its own. A future entry point that builds
    `clean` without routing it through `_normalize_ws_class` first would
    silently reopen the pub-keyword WS-class fail-open at exactly this, the highest-value
    arm — while the three lower-value `_norm_segment` sites would keep
    working correctly regardless, purely by accident of their own
    now-dead code still being present."""
    return pub_text is not None and pub_text.strip() == "pub"


def _first_own_segment(path):
    """For the first-segment foreign-root check, the first path segment whose crate-of-origin
    matters, after (1) truncating at the first `{` — a raw `pub use`
    entry or prefix may be handed here directly, whether it is a bare
    path (`alloc::boxed::Box`), a path immediately followed by a
    nested brace group (`attr::{Attr, NodeKind}`), a bare brace group
    with no prefix of its own (`{attr::Attr}`), a glob
    (`alloc::boxed::*`), or a leaf carrying ` as Alias` (unaffected,
    since an alias identifier never contains `::` or `{`) — and (2)
    stripping ONE leading `crate::`/`self::` anchor if present, since
    those two are always the current crate, never foreign, and carry
    no information of their own about WHICH crate a path belongs to.

    Returns None in two distinct situations a caller must tell apart
    itself (see `_foreign_root_reason`'s callers below): a bare
    `crate`/`self` anchor with nothing further (`crate::` truncated
    from `crate::{...}`) or an entry that opens directly on `{` with
    no path text ahead of it (`{attr::Attr}`, truncated to the empty
    string) — the first-segment foreign-root check has NOTHING CHECKED YET at either shape, and
    the check must be handed down into whatever comes next rather than
    treated as already having run. `_foreign_root_reason` runs at every unchecked
    path root; it is propagated into a nested group only when no real first
    segment has already been checked.

    Truncating at the first brace keeps the literal `{attr` in a leading
    nested group from being treated as a first segment.

    A segment is stripped of surrounding whitespace before it is compared
    or returned. Splitting `"attr :: Attr"` on `"::"` leaves spaces attached
    to the pieces; trimming lets the first segment match `attr` in
    `module_names`. The separator remains the literal `"::"`.

    Python's bare `.strip()` does not remove U+200E/U+200F, including
    the LEFT-TO-RIGHT MARK between `attr` and `::` in `pub use attr‎::Attr;`.
    `_norm_segment` uses this file's `WS` class, which covers those marks."""
    brace = path.find("{")
    if brace != -1:
        path = path[:brace]
    segments = [_norm_segment(s) for s in path.split("::")]
    segments = [s for s in segments if s]
    if not segments:
        return None
    if segments[0] in ("crate", "self"):
        return segments[1] if len(segments) > 1 else None
    return segments[0]


def _foreign_root_reason(path_text, module_names):
    """The first-segment foreign-root check for a `pub use` path root.

    `path_text` is handed straight to `_first_own_segment`, which does
    all the real work (anchor-stripping, brace-truncation): this
    function only decides what a `first is not None and first not in
    module_names` result MEANS, and builds the refusal message.
    Returns a reason string, or None — meaning either "nothing to check at this level"
    (a bare anchor exhausted, or an entry opening directly on `{`) or
    "checked, and it is one of this crate's own modules." Callers that
    need to tell those two None cases apart — to decide whether the
    check must be handed DOWN into a nested recursion instead of being
    dropped — call `_first_own_segment` directly on the same text and
    test it for None themselves; see `classify_pub_use_top` and
    `_classify_use_tree_list` below for exactly where and why: the
    correct rule is "skip a level's check only where the check ACTUALLY
    RAN there" (`_first_own_segment` returned a real segment), never
    "skip it because a shared prefix merely LOOKS present" — those two
    differ exactly in the bare-anchor case (`crate::{...}`,
    `self::{...}`)."""
    first = _first_own_segment(path_text)
    if first is not None and first not in module_names:
        return (
            f"a pub use rooted at `{first}` — not one of this crate's own "
            "declared modules; a foreign-crate (or otherwise unscoped) path is "
            "not on the root-shape allow-list"
        )
    return None


def _leaf_ok(segment_text):
    """One un-braced, top-comma-split entry of a `pub use` tree (e.g.
    'Attr', 'Attr as PublicAttr', 'self', '*', 'sub::Name',
    'sub::Name as X'). Returns None if it names exactly one item,
    possibly aliased; otherwise a reason string for refusal.

    Deliberately does NOT check whether the leaf's own final segment is
    itself a module name. Only bare `pub use snapshot;` is syntactically
    refused; `crate::snapshot`, `self::snapshot`, `crate::{snapshot}`, and
    nested-module spellings pass because module-versus-item classification
    requires compiler namespace resolution. `mod read; pub use read::read;`
    is valid Rust because the module and function occupy different namespaces."""
    text = segment_text.strip()
    if not text:
        return "an empty pub use entry"
    alias = None
    m = re.search(rf"{WS}+as{WS}+", text)
    if m:
        alias = text[m.end() :].strip()
        text = text[: m.start()].strip()
    # `_norm_segment` trims the final path segment using this file's `WS` class.
    last = _norm_segment(text.split("::")[-1])
    if last == "*":
        return "a glob re-export (`*`)"
    if last == "self":
        return "a `self` re-export (surfaces the whole module under its own name)"
    if not IDENT_RE.fullmatch(last):
        return f"an unrecognised pub use leaf shape: {segment_text!r}"
    if alias is not None and not IDENT_RE.fullmatch(alias):
        return f"an unrecognised alias in pub use: {segment_text!r}"
    return None


def _classify_use_tree_list(tree_text, module_names=None):
    """The content of a `{...}` brace group (nested groups included):
    every top-level, comma-split entry must itself be a named leaf or a
    nested brace group of named leaves. None if every entry is legit;
    otherwise the first reason string found — `_split_top_commas` is
    fsguard-scan.py's own helper (banned_prefix_rename_re's neighbour),
    reused rather than re-derived, since nesting depth is unbounded and
    a regex cannot count braces.

    `module_names` is non-None exactly when the first-segment foreign-root
    check has NOT yet run for entries at this level — the PREFIX-LESS
    call site in `classify_pub_use_top` (`pub use {granary_core::manifest,
    attr::Attr};`, where each entry carries its own path root and there
    is no shared prefix for the check to have run on), and a bare
    `crate::`/`self::` anchor exhausted one level up
    (`pub use crate::{alloc::boxed::Box};` — the bare-anchor propagation hazard). Each entry here gets
    checked on its OWN first segment via `_foreign_root_reason`, via
    `_first_own_segment`'s own brace-truncation — never on the entry's
    raw, un-truncated text, which is what let a leading nested group
    (`{attr::Attr}`) leak its literal `{attr` through as a garbage
    "first segment" before brace truncation (the leading-nested-group brace-truncation hazard).

    Whether `module_names` is handed DOWN into a nested group's own
    recursion is decided per entry, by whether THIS level's check
    actually ran for it — `_first_own_segment(part) is None` — never by
    whether a shared prefix merely looks present. It ran (and passed;
    a failure already returned) whenever the entry's own first segment
    resolves to something real, in which case propagating further
    would FALSE-POSITIVE on a nested sub-path under an
    already-validated prefix: in `pub use snapshot::{inner::Thing}`
    the leaf's own first segment is `inner`, a SUBmodule of `snapshot`,
    correctly absent from the crate's ROOT-level module set — decision
    1 already checked `snapshot`, and re-checking `inner` there would
    refuse valid Rust (the over-propagated-check hazard). It did NOT run when the entry itself opens
    directly on `{` (`{attr::Attr}`, the leading-nested-group brace-truncation hazard) or is itself a bare exhausted
    anchor (`crate::{attr::Attr}` as one entry of an outer prefix-less
    group) — there `_first_own_segment` returns None because there was
    nothing to check, not because it already passed, and the check
    must be handed down into that entry's own nested group instead."""
    for raw in fsguard._split_top_commas(tree_text):
        part = raw.strip()
        if not part:
            continue
        # `_split_top_commas` supplies each top-level entry; its first brace
        # opens the nested group, if any.
        brace = part.find("{")
        brace = brace if brace != -1 else None
        if brace is not None:
            if module_names is not None:
                reason = _foreign_root_reason(part, module_names)
                if reason is not None:
                    return reason
            next_module_names = (
                module_names if module_names is not None and _first_own_segment(part) is None else None
            )
            close = fsguard.find_matching(part, brace, "{", "}")
            if close is None:
                return f"an unterminated brace group in pub use: {part!r}"
            reason = _classify_use_tree_list(part[brace + 1 : close], next_module_names)
            if reason is not None:
                return reason
            continue
        # No nested group: the leaf's OWN shape governs first (the leaf-shape
        # diagnostic-ordering hazard) — a glob, `self`, or malformed leaf/alias
        # fires its own diagnostic; the first-segment foreign-root check's
        # message is reported only once the entry is otherwise a
        # well-formed named leaf, so it never shadows a diagnostic
        # several controls in this file assert by name (`control
        # glob-not-clippy`'s glob, `control self-reexport`'s self).
        reason = _leaf_ok(part)
        if reason is not None:
            return reason
        if module_names is not None:
            reason = _foreign_root_reason(part, module_names)
            if reason is not None:
                return reason
    return None


def classify_pub_use_top(body, module_names):
    """`body` is the full text between `use` and the terminating `;` of
    a `pub use` statement — e.g. `'snapshot::{A, B}'`,
    `'snapshot::Attr as PublicAttr'`, `'snapshot'`, `'{attr::Attr,
    handle::HandleKind}'`. None if this is an allowed named-leaf-only
    `pub use`; otherwise a reason string. `module_names` is the first-segment
    foreign-root check's set of the crate's own ROOT-LEVEL module names, used
    ONLY for the first-segment foreign-crate check: a `pub use` rooted
    outside the crate's own modules is refused."""
    text = body.strip()
    if not text:
        return "an empty pub use statement"
    # `body` is one whole `pub use` statement's text, so its first `{`
    # opens the top-level brace list, if any.
    brace = text.find("{")
    brace = brace if brace != -1 else None
    if brace is not None:
        prefix = text[:brace]
        close = fsguard.find_matching(text, brace, "{", "}")
        if close is None:
            return f"an unterminated brace group in pub use: {text!r}"
        # A group with no shared prefix passes `module_names` down so each
        # entry gets the first-segment foreign-root check.
        # A real prefix such as `snapshot` is checked here; its sub-paths
        # need no root-level check. A bare `crate::`/`self::` anchor has no
        # segment to check, so its nested entries still need `module_names`.
        if "::" in prefix:
            reason = _foreign_root_reason(prefix, module_names)
            if reason is not None:
                return reason
            next_module_names = module_names if _first_own_segment(prefix) is None else None
            return _classify_use_tree_list(text[brace + 1 : close], next_module_names)
        return _classify_use_tree_list(text[brace + 1 : close], module_names)
    # No brace anywhere: a single path, optionally `as Alias`. The
    # leaf's own shape (glob / self / malformed) is checked, and only
    # THEN the first-segment foreign-root check: the leaf-shape
    # diagnostic-ordering hazard requires each leaf check to run ahead of its
    # foreign-crate check, so a malformed or disallowed leaf shape
    # gets its own distinctive diagnostic rather than being reported as
    # a foreign root.
    path = text
    alias = None
    m = re.search(rf"{WS}+as{WS}+", path)
    if m:
        alias = path[m.end() :].strip()
        path = path[: m.start()].strip()
    if "::" not in path:
        return (
            "a whole-module re-export with no `::` — this re-exports the entire "
            "module under its own name, not a named item of it"
        )
    # `_norm_segment` trims the final path segment using this file's `WS` class.
    last = _norm_segment(path.split("::")[-1])
    if last == "*":
        return "a glob re-export (`*`)"
    if last == "self":
        return "a `self` re-export (surfaces the whole module under its own name)"
    if not IDENT_RE.fullmatch(last):
        return f"an unrecognised pub use path shape: {text!r}"
    if alias is not None and not IDENT_RE.fullmatch(alias):
        return f"an unrecognised alias in pub use: {text!r}"
    return _foreign_root_reason(path, module_names)


def _skip_ws_and_attrs(clean, pos):
    """Advance past whitespace and stacked attributes (`#[...]`/
    `#![...]`), which license the item or module that follows and carry
    no surface information of their own. Returns the new position, or
    None if an attribute's own `[`...`]` cannot be matched (malformed or
    truncated source — a could-not-run condition, not a refusal)."""
    n = len(clean)
    while pos < n:
        m = WS_RUN_RE.match(clean, pos)
        if m and m.end() > pos:
            pos = m.end()
            continue
        attr_m = fsguard.ATTR_OPEN_RE.match(clean, pos)
        if attr_m:
            close = fsguard.find_matching(clean, attr_m.end() - 1, "[", "]")
            if close is None:
                return None
            pos = close + 1
            continue
        break
    return pos


def scan_root_shape(path):
    """Returns (pubuse_count, refusals, error). `refusals` is a list of
    (line_no, reason, original_source_line). `error` is None on success
    (whether or not any refusal was found) or a one-line diagnostic —
    the caller must treat a non-None error as COULD NOT RUN, never as a
    clean pass."""
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read()
    except UnicodeDecodeError as e:
        return 0, [], f"{path}: not valid UTF-8 ({e}) — refused, not skipped"
    except OSError as e:
        return 0, [], f"{path}: could not read ({e})"

    clean = fsguard.RAW_IDENT_RE.sub(
        "  ", fsguard.strip_comments_and_strings(fsguard.blank_shebang(raw))
    )
    # Blank the `WS` class to plain spaces ONCE, here,
    # before any regex or split below ever runs — see
    # `_normalize_ws_class`'s own comment for why this replaces per-site
    # normalization instead of adding to it. A single-character
    # substitution, so every position downstream still lands on the
    # same line and column as it would against the un-normalized text.
    clean = _normalize_ws_class(clean)
    # The first-segment foreign-root check's module-names set, for that
    # foreign-crate check only — derived from THIS SAME cleaned text, no
    # separate file read. Only bare `pub use snapshot;` is syntactically
    # refused; `crate::snapshot`, `self::snapshot`, `crate::{snapshot}`, and
    # nested-module spellings pass because module-versus-item classification
    # requires compiler namespace resolution. The deleted final-segment
    # inventory and the depth-zero `_collect_root_module_names` replacement are
    # different mechanisms. Derived
    # from `_collect_root_module_names`'s
    # own depth-0 walk, not a whole-file regex — see that function's
    # docstring for why this closes the nested-decoy route. A `None`
    # result (the walk hit something it could not parse) falls back to
    # an empty set here: `scan_root_shape`'s own walk below performs the
    # identical walk over the same text and will hit the same construct
    # at the same position, raising the real could-not-run diagnostic —
    # this fallback only ever feeds a result that gets discarded once
    # that happens, never a silently-wrong module inventory.
    module_names = _collect_root_module_names(clean)
    if module_names is None:
        module_names = set()
    # CORRECTED: `raw.splitlines()` also breaks on
    # U+000B/U+000C/U+0085/U+2028/U+2029 — characters `line_of`
    # below does NOT count, since it counts only `\n` in `clean`. Those
    # exact characters are rustc whitespace, and
    # `_normalize_ws_class` makes them refusable (e.g. `pub<FF>mod`
    # reaches a refusal). With `raw.splitlines()`, a refusal on such a
    # line named the WRONG line number and quoted a truncated or empty
    # source line. `\n`-only splitting agrees with `line_of`'s own `\n`-only
    # counting — which is also what rustc's own line numbering uses.
    raw_lines = raw.split("\n")
    n = len(clean)
    pos = 0
    pubuse_count = 0
    refusals = []

    def line_of(p):
        return clean.count("\n", 0, p) + 1

    def orig_line(line_no):
        return raw_lines[line_no - 1].strip() if 0 <= line_no - 1 < len(raw_lines) else ""

    while pos < n:
        skipped = _skip_ws_and_attrs(clean, pos)
        if skipped is None:
            line_no = line_of(pos)
            return (
                pubuse_count,
                refusals,
                f"{path}:{line_no}: an attribute's `[`...`]` could not be matched — "
                "malformed or truncated source",
            )
        pos = skipped
        if pos >= n:
            break

        m = EXTERN_CRATE_HEAD_RE.match(clean, pos)
        if m:
            line_no = line_of(pos)
            if _is_full_pub(m.group("pub")):
                refusals.append(
                    (
                        line_no,
                        "`pub extern crate` — not on the allow-list; it promotes a whole "
                        "crate name to the root",
                        orig_line(line_no),
                    )
                )
            pos = m.end()
            continue

        m = MOD_HEAD_RE2.match(clean, pos)
        if m:
            line_no = line_of(pos)
            after = _skip_ws_and_attrs(clean, m.end())
            if after is None or after >= n:
                return (
                    pubuse_count,
                    refusals,
                    f"{path}:{line_no}: a `mod` head is not followed by `;` or `{{` — "
                    "malformed or truncated source",
                )
            ch = clean[after]
            if ch == ";":
                end = after + 1
            elif ch == "{":
                close = fsguard.find_matching(clean, after, "{", "}")
                if close is None:
                    return (
                        pubuse_count,
                        refusals,
                        f"{path}:{line_no}: an inline `mod {{ ... }}` body could not be "
                        "matched — malformed or truncated source",
                    )
                end = close + 1
                # An inline mod's body is skipped as ONE opaque block —
                # it is private, so nothing inside it is part of the
                # root's public surface as far as name resolution goes.
                # NOT CAUGHT: an `impl` inside such a body still widens an
                # EXISTING type's real public surface, because `impl` blocks
                # are not scoped by their enclosing module's visibility.
                # Deciding whether the `Self` type is externally reachable
                # needs compiler name resolution, which a text scanner does
                # not have. A dedicated check for exactly this was shipped and
                # then CUT, refuted by execution in BOTH directions: an
                # attributed `impl` slipped past it, and a legitimate private
                # test-double `impl` was refused alongside a real violation.
            else:
                return (
                    pubuse_count,
                    refusals,
                    f"{path}:{line_no}: a `mod` head is not followed by `;` or `{{` — "
                    "malformed or truncated source",
                )
            if _is_full_pub(m.group("pub")):
                refusals.append(
                    (
                        line_no,
                        "`pub mod` — not on the allow-list; this crate's whole public "
                        "surface is a curated `pub use` list, and promoting a module "
                        "replaces curation with wholesale exposure",
                        orig_line(line_no),
                    )
                )
            # Non-pub, and no `impl` found inside: allowed, and the rest
            # of an inline body is skipped as one block without
            # inspecting what else is inside it — it is private, so
            # nothing else there is part of the root's public surface.
            pos = end
            continue

        m = USE_HEAD_RE.match(clean, pos)
        if m:
            line_no = line_of(pos)
            semi = clean.find(";", m.end())
            # UNBOUNDED find — deliberately not fsguard.use_statements's
            # own `text.find(";", start, start + 2000)`. That 2000-char
            # cap exists to keep an unrelated caller's scan from going
            # quadratic on a file with an unterminated `use`; here it
            # would silently DROP any `pub use` whose brace list runs
            # past 2000 characters (a plausible shape once the root
            # carries a dozen or more named imports across a wrapped
            # multi-line list), reading a real statement as though it
            # did not exist. `pub use` occurrences are sparse — a linear
            # scan per occurrence is not the quadratic case that cap
            # guards against — so this scans to the actual terminator,
            # however far away it is.
            if semi == -1:
                return (
                    pubuse_count,
                    refusals,
                    f"{path}:{line_no}: an unterminated `use` (no `;` found) — malformed "
                    "or truncated source",
                )
            body = clean[m.end() : semi]
            if _is_full_pub(m.group("pub")):
                reason = classify_pub_use_top(body, module_names)
                if reason is None:
                    pubuse_count += 1
                else:
                    refusals.append((line_no, f"pub use — {reason}", orig_line(line_no)))
            # else: a private/pub(crate)/pub(super)/pub(in ...) use —
            # never creates an externally-visible re-export, allowed
            # unconditionally.
            pos = semi + 1
            continue

        # FALLBACK: not on the allow-list. fsguard.item_extent finds
        # where THIS construct ends regardless of what it turns out to
        # be (a body item like `fn`/`struct`/`impl`/`macro_rules!`, a
        # statement like `const`/`static`/`type`, or a bare macro
        # invocation like `some_macro! { ... }`, which item_extent's
        # STATEMENT_RESUME_RE safety net ends at its own closing brace
        # rather than running on to the next real `;`) — reused so this
        # scanner does not need its own second copy of that extent
        # logic just to keep walking past what it refuses.
        line_no = line_of(pos)
        _, end, _, _ = fsguard.item_extent(clean, pos)
        refusals.append(
            (
                line_no,
                "not on the allow-list — this crate's crate root may contain only "
                "attributes; a non-pub `extern crate`/`mod`/`use`; and a `pub use` of "
                "named leaves (the root-shape allow-list)",
                orig_line(line_no),
            )
        )
        pos = max(end, pos) + 1

    return pubuse_count, refusals, None


MACRO_EXPORT_RE = re.compile(r"\bmacro_export\b")


def scan_macro_export(path):
    """Returns (hits, error) — `hits` a list of (line_no, original
    source line) for every attribute anywhere in `path` whose body names
    `macro_export` (a direct `#[macro_export]`, or nested inside a
    `#[cfg_attr(cond, macro_export)]`). `error` is None on success."""
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read()
    except UnicodeDecodeError as e:
        return [], f"{path}: not valid UTF-8 ({e}) — refused, not skipped"
    except OSError as e:
        return [], f"{path}: could not read ({e})"

    clean = fsguard.RAW_IDENT_RE.sub(
        "  ", fsguard.strip_comments_and_strings(fsguard.blank_shebang(raw))
    )
    raw_lines = raw.splitlines()
    hits = []
    for attr_m in fsguard.ATTR_OPEN_RE.finditer(clean):
        open_bracket = attr_m.end() - 1
        close_bracket = fsguard.find_matching(clean, open_bracket, "[", "]")
        if close_bracket is None:
            return hits, f"{path}: an attribute's `[`...`]` could not be matched"
        body = clean[open_bracket + 1 : close_bracket]
        if MACRO_EXPORT_RE.search(body):
            line_no = clean.count("\n", 0, attr_m.start()) + 1
            orig = raw_lines[line_no - 1].strip() if 0 <= line_no - 1 < len(raw_lines) else ""
            hits.append((line_no, orig))
    return hits, None


def main() -> None:
    argv = sys.argv[1:]
    if "--root-shape" in argv:
        i = argv.index("--root-shape")
        if i + 1 >= len(argv):
            print("ERROR --root-shape needs a path", file=sys.stderr)
            sys.exit(2)
        path = argv[i + 1]
        pubuse_count, refusals, error = scan_root_shape(path)
        if error is not None:
            print(f"ERROR {error}", file=sys.stderr)
            sys.exit(2)
        print(f"PUBUSE-COUNT {pubuse_count}")
        for line_no, reason, orig in refusals:
            print(f"REFUSE {line_no}: {reason} :: {orig}")
        return
    if "--macro-export" in argv:
        paths = [p for p in sys.stdin.buffer.read().split(b"\0") if p]
        for raw_path in paths:
            try:
                path = raw_path.decode("utf-8")
            except UnicodeDecodeError as e:
                print(
                    f"ERROR {raw_path!r}: the FILE NAME is not valid UTF-8 ({e}) — refused, "
                    "not skipped.",
                    file=sys.stderr,
                )
                sys.exit(2)
            hits, error = scan_macro_export(path)
            if error is not None:
                print(f"ERROR {error}", file=sys.stderr)
                sys.exit(2)
            for line_no, orig in hits:
                print(f"MACRO-EXPORT {path}:{line_no}: {orig}")
        return
    print(
        "ERROR usage: vfs-root-shape-scan.py --root-shape <path> | "
        "--macro-export < NUL-separated paths",
        file=sys.stderr,
    )
    sys.exit(2)


if __name__ == "__main__":
    main()
