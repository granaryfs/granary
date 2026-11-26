#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""The RESOLVED-GRAPH licence-boundary gate: what `check-licence-boundary.sh`
cannot see because it reads source TEXT, this reads what cargo actually
RESOLVED and what rustc actually COMPILED.

granary-server is AGPL-3.0-or-later; every other crate in this workspace is
Apache-2.0. `check-licence-boundary.sh` enforces the boundary by scanning
committed text for the server's name and for paths
into its directory, and its own header names what a content scan cannot
reach: an escape inside a string literal, a name split across `concat!`
pieces, a nested inline-mod path, a `tests/` file pulled into `src/` by
`#[path]`, a symlink, and a TOML spelling of the server's name that a
comment-strip or a rename defeats. Every one of those still has to resolve to
real bytes on disk before rustc will compile it, so reading the RESOLVED
dependency graph and the COMPILED dep-info closes them independently of how
the source spells the reference.

TWO checks, independent and both required, over DIFFERENT feature sets:

  CHECK A (`cargo metadata --all-features`'s resolve graph). No workspace
  member other than the server may REACH the server -- not only by a direct
  edge, but TRANSITIVELY, walking the whole resolve graph (member and
  non-member nodes alike, every dependency kind, any `cfg`) from each
  non-server member. A rename (`srv = { package = "granary-server", ... }`)
  still resolves to the server's package id, so the manifest's local name is
  irrelevant; and a member that reaches the server only through an
  intermediate crate -- one excluded from the workspace, or simply a path
  dependency sitting outside it -- is still a boundary crossing, because
  that intermediate crate still compiles the server's code into whatever
  depends on it. `--all-features` is used HERE and only here: `cargo
  metadata` only RESOLVES, it builds nothing, so it is safe to ask it about
  every feature at once, including `granary-net`'s and `granary-store`'s
  `fips` (which would need cmake/go/perl to actually BUILD). An optional
  dependency gated behind a feature that is off by default is invisible to
  a bare `cargo metadata` call -- MEASURED: a member's resolve node lists
  `"deps": []` for an `optional = true` path dependency on the server
  without `--all-features`, and the real edge only appears with it -- so
  omitting the flag would make this check blind to exactly the boundary
  crossing a feature flag can hide.

  CHECK B (what rustc actually compiled, every feature EXCEPT fips-gated
  ones). Examines every LOCAL PATH package's compiled ARTIFACTS -- a
  package whose `source` is `null` in `cargo metadata` (equivalently, whose
  id starts `path+file://`) -- member or not, except the server. Cargo
  builds a local path crate that is a dependency of a member even when that
  crate is excluded from the workspace (sitting outside its root, or
  otherwise not in `members`), and check A's manifest-edge view cannot see
  a source-level `include!`/`#[path]` bypass planted INSIDE such a crate,
  since a reference of that kind makes no dependency edge for a graph walk
  to see at all -- only compiling it and reading its own dep-info does.
  Every examined artifact's dep-info is checked for a source path that
  resolves (`os.path.realpath`, compared case-insensitively -- see below)
  inside the server's directory: the mechanism that closes an
  `include!`/`#[path]` bypass leaving no manifest edge, a spelling no text
  scanner reaches (an escaped literal, a name split across `concat!`
  pieces), and a symlink -- the dep-info lists the path AS WRITTEN, and
  only `realpath` reveals where a symlink actually reads from.

  Check B activates every workspace member's OWN declared feature except
  `default` itself, PROVIDED cargo's own resolver -- asked directly,
  never predicted by a hand-rolled walk over the feature tables -- shows
  that turning it on does not activate a feature literally named `fips`
  anywhere in the resolve graph. Each candidate `pkgname/feat` is probed
  in ISOLATION first (`cargo metadata --features pkgname/feat`, on top of
  default features, matching exactly what the eventual build does),
  excluded the moment ANY node in that resolve reports `fips` in its OWN
  `resolve.nodes[].features` list -- cargo's account of what THIS
  selection actually activated, not a prediction of one, so a rename, a
  second version of one crate, a hyphenated dependency name, or a
  dependency's own `[lib] name` override never needs separate handling:
  cargo resolves all of that itself before this gate ever reads the
  result (see `compute_feature_flags`). The surviving candidates are then
  re-checked TOGETHER in one combined `cargo metadata --features
  <survivors>` call, because two features that are each individually safe
  can jointly activate `fips` through feature unification -- if THAT
  activates `fips` anywhere, the gate REFUSES outright rather than
  guessing which survivor to blame. This set is COMPUTED from real
  `cargo metadata` calls on every run -- never a hard-coded name, and
  never a name this gate has to know the shape of -- passed as `--features
  pkg/feat,...`, and both the surviving set and every EXCLUDED candidate
  are printed. `fips` itself, and anything shown to reach it, is excluded
  because activating it would need cmake/go/perl to actually BUILD
  (`granary-net`'s and `granary-store`'s own `fips` features), unlike
  anything else this gate would otherwise compile; this is check B's one
  remaining coverage gap, stated plainly: an `include!`/`#[path]` bypass,
  or a `[[bin]]`/`[[test]]` gated by `required-features`, reachable ONLY
  behind a `fips`-implying feature is not compiled here and is not
  detected. Every OTHER feature-gated route, and every target whose
  `required-features` the computed set satisfies, IS compiled and
  examined -- check A's resolve-graph walk does NOT stand in for this: a
  source-level reference makes no manifest edge for it to see regardless of
  which features are active.

  Reading only the CURRENT run's artifacts is the point of check B, not a
  detail of it: a stale `.d` file left in a restored `target/` directory
  names whatever it was compiled against LAST time, and CI restores
  `target/` from a cache between runs. This gate never globs the deps
  directory -- it derives each dep-info path from the `compiler-artifact`
  messages `cargo build --message-format=json` emits for THIS build, so a
  stale file with no current artifact pointing at it is never read. Check B
  also refuses (rather than silently under-covering) if any non-server
  WORKSPACE MEMBER (not every local path package -- an unused path
  dependency legitimately need not be built) produced NO
  `compiler-artifact` message at all, and if any line of `cargo build`'s
  JSON-lines output fails to parse as JSON -- either is a sign this gate
  examined less than it believes it did, which is worse than examining
  nothing, because it looks the same as a clean run.

DEP-INFO DERIVATION, verified against real `cargo build --message-format=json`
output on this machine (cargo/rustc 1.97.1) rather than assumed from
documentation. An artifact's `filenames` entries that sit in a `deps/`
directory carry a hash that uniquely identifies the compiled unit, and the
dep-info file for that exact unit sits beside it in the SAME directory, named
by dropping a leading `lib` from the stem (when the stem has one) and
swapping the extension for `.d`: `deps/libfoo-<hash>.rmeta` and
`deps/foo-<hash>` (no extension -- an executable) both name
`deps/foo-<hash>.d`. A filename OUTSIDE `deps/` (the hash-less top-level copy
cargo also writes for a lib's or a bin's primary artifact, such as
`target/debug/libfoo.rlib` or `target/debug/foo`) keeps its `lib` prefix when
swapping the extension instead: `target/debug/libfoo.d`. Some artifacts (a
`[[bin]]` target's normal build, when the crate also carries `#[test]`s,
observed on this machine) list ONLY that hash-less top-level filename, with
no `deps/`-directory sibling in `filenames` at all.

A build script's `custom-build` artifact is a THIRD shape, verified
separately: its filename (`target/.../build/<pkg>-<hash>/build-script-build`)
carries no hash of its own at all -- the hash sits only on its ENCLOSING
directory's name -- and its paired dep-info is `build_script_build-<hash>.d`
in that same directory, with every `-` in the build target's own name turned
into `_`. This is the ONLY candidate ever tried for this shape: a bare,
hash-less `build-script-build.d` beside it was NEVER OBSERVED on this
machine for a real build, so there is no generic fallback -- if the exact,
hash-qualified name is absent, this gate refuses (exit 2) rather than
falling back to a same-named file it cannot verify is CURRENT. A fallback
that is tried only after the exact name still creates a risk the exact-first
ordering does not remove: if the exact file is ever missing for any reason
(a cargo change, a race, a corrupted `target/`) while an unrelated or stale
generic-named file happens to sit in that directory, reading it would be a
SILENTLY WRONG recovery -- possibly reporting a real violation as clean by
reading the wrong file's content instead of refusing outright.

CASE-INSENSITIVE CONTAINMENT. `os.path.realpath` resolves symlinks and `.`/
`..` components, but it does NOT canonicalise case -- MEASURED on this
machine (APFS, case-insensitive by default): `realpath` of a path spelled
`crates/Granary-Server/...` that is reachable only because the filesystem
folds case returns that path UNCHANGED, still spelled with the capital
letters, even though it opens the same file as `crates/granary-server/...`.
Comparing those two strings byte-for-byte therefore MISSES the crossing.
Containment here is decided on `.casefold()` of both sides instead. On a
genuinely case-SENSITIVE filesystem (most Linux filesystems) this can only
ever make the check MORE conservative -- two distinctly-cased directories
that happen to casefold equal would be treated as one -- never less: it
fails CLOSED rather than open, which is the direction a licence gate should
err in, and such a collision is not a shape this workspace has.

COVERAGE LIMITS, STATED RATHER THAN IMPLIED:

  * The four fuzz crates (`crates/*/fuzz`) are each their own cargo
    workspace and do not appear in the root workspace's `cargo metadata` at
    all, under any feature flag -- this gate does not see them, and neither
    does the metadata call it runs at the root.
  * Check B examines only the targets `--all-targets` builds FOR THE HOST. A
    `cfg`-gated `include!` reachable only under a different target (a
    cross-compiled `#[cfg(target_os = "linux")]` module, built on a
    non-Linux host, for example) produces no artifact here and so sits
    outside check B's dep-info scan on that host, WHATEVER the active
    feature set -- check A's resolve-graph walk covers a MANIFEST edge
    under any target, but not a source-level `include!` gated the same way,
    which stays a check B concern only.
  * A feature literally named `fips`, or one CARGO's own resolver shows
    activates it, is deliberately never activated for check B's build
    (see above) -- an `include!`/`#[path]` bypass, or a
    `required-features`-gated target, reachable only behind such a
    feature is not compiled and not detected. This is the one
    feature-shaped gap left standing once every OTHER feature is covered.
  * Check B builds exactly TWO feature configurations -- default, and
    every non-fips feature ON at once -- NOT a powerset of every subset of
    features. Source gated by a MIXED predicate needing two non-default
    features in a particular combination, such as
    `cfg(all(feature = "x", not(feature = "y")))`, is compiled by NEITHER
    build (the feature build turns both `x` and `y` on, so `not(feature =
    "y")` is false there too) and is not examined by either. This is
    deliberate: the two configurations catch a single feature toggled
    either way, not every combination two or more can form together.
  * A proc-macro that reads a file at expansion time without declaring it to
    rustc (an ad-hoc `std::fs::read` in the macro body, no `include!` or
    `include_str!`) leaves no dep-info entry at all -- there is nothing for
    check B to read.
  * A build script (or a proc-macro) that COPIES a server source file into
    `$OUT_DIR` and has the crate `include!` the COPY is outside what
    dep-info path-checking can see: the dep-info names the path UNDER
    `OUT_DIR` (a generated file inside `target/`), not the original file it
    was copied from, so the containment check here never sees the server's
    directory at all for that route. Nothing in this gate detects a copy
    made this way.
  * `--features pkg/feat` addresses WORKSPACE MEMBERS; a non-member local
    path package's own features are not separately activated here (the
    examined set is broader than the activated one) -- such a package
    inherits only whatever features its dependents' activations happen to
    turn on for it through normal feature unification.
  * The case-INSENSITIVE containment comparison's `--self-test` COVERAGE
    exists ONLY on a case-insensitive filesystem (APFS's default, exFAT,
    NTFS): on a case-sensitive one (most Linux filesystems, including this
    project's own CI runners) the differently-cased fixture path does not
    exist on disk at all, `cargo build` fails outright, and the row that
    would exercise `.casefold()` SKIPS rather than passing or failing. That
    self-test row therefore proves nothing about that comparison on a
    case-sensitive CI run; the containment code itself still runs there
    (case-folding a same-case path is a no-op), only the DEDICATED proof of
    the fold is what goes unexercised.

CHECK C (`cargo metadata --all-features`'s resolve graph, NORMAL and
BUILD edges). The simulator's crate, `granary-sim`, holds a SEEDED implementation
of the cryptographic-randomness seam (`granary_core::secure_random`): its
streams are fixed by a replay seed, which is what a simulator needs and
exactly what a production identity or epoch must never be. So
`granary-sim` must appear in no production binary's dependency graph,
whether linked or run at build time. From each production root --
`granary-cli` (the `gran` binary) and the server -- the check walks the
resolve graph TRANSITIVELY over normal and build edges (an edge counts
when any of its `dep_kinds` has kind `null` or `"build"`), so it covers
both binaries, every library they link, and every build script any of
those runs, through any intermediate crate, member or not. A build edge
counts because a build script's output (generated source, constants)
lands in the binary. Only a dev-dependency (how the server's and the
client's tests use the simulator) is not followed. `--all-features` makes an optional
normal dependency behind a feature visible, as in check A. Check A's
reachability helper collapses every dependency kind into one edge set, so
check C walks its own adjacency without dev edges; a resolve node whose edges
carry no `dep_kinds` (a cargo too old to report them) refuses the gate
rather than guessing a kind. A missing root or a missing `granary-sim`
member refuses the gate (exit 2): a check that cannot find its subject is
blind, not clean.

This gate does not replace `check-licence-boundary.sh`; it closes the
specific gaps that script's own header names. Run `--self-test` first,
always: it builds throwaway cargo workspaces offline and proves every
refusal above fires red before a green run against this repository's own
workspace is trusted.

EXIT: 0 clean (prints the packages/artifacts/dependency-paths counts it
examined), 1 a boundary violation (each named: the offending package/target
and the dependency edge or the source path), 2 THE GATE COULD NOT RUN (a
cargo command failed, its subject was not found, or it would be judging an
empty population).
"""
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import typing
from collections import deque

SERVER_NAME = "granary-server"
SERVER_REL_MANIFEST = os.path.join("crates", "granary-server", "Cargo.toml")
SERVER_REL_DIR = os.path.join("crates", "granary-server")
# Check C's subject and its roots, each identified by name AND manifest path.
SIM_NAME = "granary-sim"
SIM_REL_MANIFEST = os.path.join("crates", "granary-sim", "Cargo.toml")
PRODUCTION_ROOTS = (
    ("granary-cli", os.path.join("crates", "granary-cli", "Cargo.toml")),
    (SERVER_NAME, SERVER_REL_MANIFEST),
)


class DepInfoError(Exception):
    """A `.d` file that does not parse as the Makefile-syntax rustc writes --
    distinct from `OSError` (the file could not be READ at all)."""


class _SkipRow(Exception):
    """Raised by a self-test row's fixture builder when the row's premise
    cannot hold on THIS machine (a filesystem property, most often) -- the
    row is reported skipped, with the reason printed, rather than silently
    counted as a pass or bluntly counted as a failure."""


def run(cmd, cwd, env=None, timeout=1800):
    """A cargo/subprocess call that never raises: a `cargo` binary missing from
    PATH, or a hung process, is a gate that could not run, not a traceback."""
    try:
        return subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True,
                               text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(cmd, 127, "", str(e))


def cargo_metadata(root, all_features=False, features=None):
    """(metadata dict, None) on success, (None, reason) on any failure -- a
    failure to run `cargo metadata` is never treated as an empty, clean
    graph. `features`, given as a list of `"pkgname/feat"` strings, becomes
    ONE comma-joined `--features` argument -- mutually exclusive with
    `all_features` (cargo itself refuses both at once); `all_features`
    wins if a caller ever passed both, though nothing in this gate does."""
    cmd = ["cargo", "metadata", "--format-version", "1", "--locked"]
    if all_features:
        cmd.append("--all-features")
    elif features:
        cmd += ["--features", ",".join(features)]
    proc = run(cmd, root)
    if proc.returncode != 0:
        return None, (f"`{' '.join(cmd)}` exited "
                       f"{proc.returncode}:\n{proc.stderr.strip()[-4000:]}")
    try:
        return json.loads(proc.stdout), None
    except json.JSONDecodeError as e:
        return None, f"cargo metadata's stdout did not parse as JSON: {e}"


def find_member(meta, root, name, rel_manifest):
    """The workspace member `name`, identified by name AND manifest path --
    not by name alone, so a differently-placed crate that merely shares the
    name cannot stand in for the real subject."""
    want = os.path.realpath(os.path.join(root, rel_manifest))
    members = set(meta.get("workspace_members", []))
    for p in meta.get("packages", []):
        if p.get("id") not in members:
            continue
        if p.get("name") != name:
            continue
        if os.path.realpath(p.get("manifest_path", "")) == want:
            return p
    return None


def find_server(meta, root):
    """The server package (`find_member`)."""
    return find_member(meta, root, SERVER_NAME, SERVER_REL_MANIFEST)


class CheckAResult(typing.NamedTuple):
    ok: bool
    reason: str
    violations: list


def _resolve_adjacency(meta):
    """id -> [neighbour ids], over EVERY node cargo's resolve graph carries
    (workspace members and ordinary dependency packages alike), collapsing
    every dependency kind into one edge set -- reachability, not any one
    kind of edge, is what check A decides on."""
    nodes = {n["id"]: n for n in meta.get("resolve", {}).get("nodes", [])}
    adjacency = {}
    for nid, node in nodes.items():
        deps = node.get("deps")
        if deps is None:
            # Cargo older than 1.44 lacks the `deps` field; `dependencies` is
            # the bare id list every such cargo still provides. Unreachable
            # at this workspace's pinned toolchain -- kept so a missing
            # field degrades rather than silently drops every edge.
            deps = [{"pkg": pid} for pid in node.get("dependencies", [])]
        adjacency[nid] = [d.get("pkg") for d in deps if d.get("pkg")]
    return nodes, adjacency


def _bfs_path(adjacency, start, target):
    """BFS from `start` over `adjacency`; returns the list of ids from start
    to target INCLUSIVE if reachable, else None. Walks the WHOLE graph --
    member and non-member nodes alike -- because a non-member path
    dependency (excluded from the workspace, or simply outside it) can sit
    between a member and the server with no direct edge for a shallower
    check to see."""
    if start == target:
        return [start]
    seen = {start}
    parent = {}
    q = deque([start])
    while q:
        cur = q.popleft()
        for nxt in adjacency.get(cur, []):
            if nxt in seen:
                continue
            seen.add(nxt)
            parent[nxt] = cur
            if nxt == target:
                path = [target]
                while path[-1] != start:
                    path.append(parent[path[-1]])
                path.reverse()
                return path
            q.append(nxt)
    return None


def check_a(meta, server_id, other_ids, id_to_name):
    """Every OTHER workspace member, checked for TRANSITIVE reachability of
    the server anywhere in the resolve graph -- not only its own direct
    deps. `other_ids` is a set; a member absent from the graph's own nodes
    is a refusal (a gate that cannot see its own subject is blind, not
    clean), not a silently skipped member.

    Iterated in SORTED order, not the set's own: a Python set's iteration
    order for `str` members depends on `PYTHONHASHSEED` (hash
    randomisation, on by default), so iterating `other_ids` directly would
    make two violations' printed ORDER a coin flip across otherwise
    IDENTICAL runs -- non-determinism this gate's own diagnostic must not
    have, whatever the interpreter's hash seed happens to be."""
    nodes, adjacency = _resolve_adjacency(meta)
    violations = []
    for mid in sorted(other_ids):
        if mid not in nodes:
            return CheckAResult(False,
                f"{id_to_name.get(mid, mid)} is a workspace member but has "
                f"no resolve node in cargo metadata's graph", [])
        path = _bfs_path(adjacency, mid, server_id)
        if path is not None:
            violations.append(
                f"{' -> '.join(id_to_name.get(p, p) for p in path)} "
                f"(check A: transitive reachability, cargo metadata "
                f"--all-features resolve graph)")
    return CheckAResult(True, "", violations)


# The dependency kinds check C follows: `null` (normal) and `"build"`.
_SHIPPED_KINDS = (None, "build")


def _shipped_adjacency(meta):
    """(id -> [neighbour ids] over NORMAL and BUILD edges, None) -- an edge
    counts when any of its `dep_kinds` entries has kind `null` or
    `"build"`; a dev-only edge does not -- or (None, reason) when an edge
    carries no `dep_kinds` at all, since its kind cannot then be told and
    guessing either way would be wrong."""
    adjacency = {}
    for node in meta.get("resolve", {}).get("nodes", []):
        out = []
        for dep in node.get("deps") or []:
            kinds = dep.get("dep_kinds")
            if not kinds:
                return None, (f"resolve node {node.get('id')!r} has an edge "
                              f"to {dep.get('pkg')!r} with no dep_kinds, so "
                              f"its kind cannot be told")
            if any(k.get("kind") in _SHIPPED_KINDS for k in kinds) and dep.get("pkg"):
                out.append(dep["pkg"])
        adjacency[node.get("id")] = out
    return adjacency, None


def check_c(meta, root, id_to_name):
    """No production root reaches `granary-sim` over normal or build edges
    (the header's CHECK C). Roots and subject are found by name and manifest
    path; any of them missing refuses."""
    sim = find_member(meta, root, SIM_NAME, SIM_REL_MANIFEST)
    if sim is None:
        return CheckAResult(False,
            f"check C: no workspace member named {SIM_NAME!r} with manifest "
            f"{SIM_REL_MANIFEST} was found", [])
    adjacency, reason = _shipped_adjacency(meta)
    if adjacency is None:
        return CheckAResult(False, f"check C: {reason}", [])
    violations = []
    for name, rel in PRODUCTION_ROOTS:
        pkg = find_member(meta, root, name, rel)
        if pkg is None:
            return CheckAResult(False,
                f"check C: no workspace member named {name!r} with manifest "
                f"{rel} was found", [])
        if pkg["id"] not in adjacency:
            return CheckAResult(False,
                f"check C: {name} has no resolve node in cargo metadata's "
                f"graph", [])
        path = _bfs_path(adjacency, pkg["id"], sim["id"])
        if path is not None:
            violations.append(
                f"{' -> '.join(id_to_name.get(p, p) for p in path)} "
                f"(check C: {SIM_NAME}, the seeded randomness, reachable over "
                f"normal or build dependency edges from a production root, "
                f"cargo metadata --all-features resolve graph)")
    return CheckAResult(True, "", violations)


_BUILD_DIR_HASH = re.compile(r"^(.*)-([0-9a-f]{8,32})$")

# Extensions a LIBRARY-shaped crate-type output can carry -- `.rlib`/
# `.rmeta` observed directly on this machine; `.a`/`.so`/`.dylib` for a
# staticlib/cdylib/dylib crate type (Unix); `.dll`/`.lib` included for the
# same reason on a platform this gate does not run on. Anything else
# (notably NO extension at all, a bin/test/bench executable on this
# platform) is never a `lib`-prefixed output, whatever letters its own
# name happens to start with.
_LIB_EXTENSIONS = {".rlib", ".rmeta", ".a", ".so", ".dylib", ".dll", ".lib"}


def dep_info_candidates(filenames):
    """Candidate dep-info paths for one `compiler-artifact` message's
    `filenames`. The `custom-build` shape gets EXACTLY ONE candidate -- its
    hash-qualified name, with NO generic `build-script-build.d` fallback
    (deliberately, with no generic name tried at all: a bare, hash-less
    name beside it is never observed on this machine for a real build, so
    it names nothing this gate can trust to be CURRENT -- reading it if
    the exact file were ever absent would be a silently-wrong recovery,
    mistaking a stale or planted file for THIS build's real dep-info.
    Absent means refuse (exit 2), not guess.) Then the `deps/`-directory
    and hash-less top-level shapes for
    every other filename. See the header for the derivation and where each
    was verified."""
    seen, out = set(), []

    def add(c):
        if c not in seen:
            seen.add(c)
            out.append(c)

    # The `custom-build` shape. `target/.../build/<pkg>-<hash>/<name>`
    # carries no hash of its own; the dep-info's hash comes from the
    # ENCLOSING directory. Every filename handled here is EXCLUDED from the
    # generic loop below: that loop's own rule (swap the extension for
    # `.d`, keep the name otherwise) would independently re-derive the
    # exact same hash-less `build-script-build.d` this shape must NOT use
    # as a fallback -- MEASURED: without this exclusion, a custom-build
    # filename with no extension at all falls straight through the generic
    # rule unchanged, silently producing the same hash-less
    # `build-script-build.d` name this shape must never use as a fallback.
    custom_build_files = set()
    for f in filenames:
        d = os.path.dirname(f)
        if os.path.basename(os.path.dirname(d)) == "build":
            m = _BUILD_DIR_HASH.match(os.path.basename(d))
            if m:
                custom_build_files.add(f)
                stem = os.path.basename(f).replace("-", "_")
                add(os.path.join(d, f"{stem}-{m.group(2)}.d"))

    ordered = sorted(filenames,
                      key=lambda f: os.path.basename(os.path.dirname(f)) != "deps")
    for f in ordered:
        if f in custom_build_files:
            continue
        d = os.path.dirname(f)
        stem, ext = os.path.splitext(os.path.basename(f))
        # The `lib` prefix is stripped ONLY for an actual library-shaped
        # output (rlib/rmeta, and the linkable forms a cdylib/dylib/
        # staticlib can produce) -- NEVER by the STEM merely starting with
        # the letters "lib", which any bin/test/bench target can do purely
        # by being named that way. An integration test file
        # `tests/library_api.rs` compiles to the bare executable
        # `deps/library_api-<hash>` (NO extension, no real `lib` prefix at
        # all): stripping unconditionally on a `deps/`-directory stem
        # starting with "lib" would mangle it into `deps/rary_api-<hash>.d`
        # -- a name nothing ever writes, refusing the whole gate on a
        # clean workspace. Gating on the OUTPUT'S OWN EXTENSION rather than on
        # its name closes this: a bin/test/bench executable has NO
        # extension on this platform (or `.exe`, on one this gate never
        # runs on), neither of which is a library extension, so its stem
        # is never touched regardless of what letters it starts with.
        if (os.path.basename(d) == "deps" and stem.startswith("lib")
                and ext in _LIB_EXTENSIONS):
            stem = stem[3:]
        add(os.path.join(d, stem + ".d"))
    return out


def _find_unescaped_colon(line):
    """The index of the first `:` not immediately preceded by a backslash, or
    None. Dep-info is Makefile syntax: `target: dep dep ...`, and this is the
    separator between the two. No path in this repository's own tree may
    hold a `:` at all (a rule `check-licence-boundary.sh` enforces on itself
    for the same parsing reason), so an escaped colon inside a real path is
    not a case this needs to defend against."""
    i, n = 0, len(line)
    while i < n:
        if line[i] == "\\" and i + 1 < n:
            i += 2
            continue
        if line[i] == ":":
            return i
        i += 1
    return None


def _tokenize_makefile_deps(s):
    """Space-separated dep-info tokens, undoing exactly what rustc's own
    dep-info writer escapes and nothing more. VERIFIED on this machine
    (cargo/rustc 1.97.1): a crate whose module path names a file containing
    a literal `#`, a literal space and a literal backslash (via `#[path]`,
    read back from the real `.d` file with `od -c`) showed rustc escapes
    ONLY the embedded SPACE -- as a backslash immediately before it
    (`\\ `). A literal `#` and a literal `\\` in the same path are both
    written back RAW, with no escaping at all: `x#hash y.rs` became
    `x#hash\\ y.rs` (the `#` untouched, only the space escaped), and
    `back\\slash.rs` became `back\\slash.rs` byte-for-byte (the backslash
    untouched). Unescaping a bare `\\#` or `\\\\` here would therefore
    silently DROP a real backslash byte that never meant anything -- rustc
    has no such escape to undo, so this tokenizer must not invent one."""
    tokens, cur, i, n = [], [], 0, len(s)
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n and s[i + 1] == " ":
            cur.append(" ")
            i += 2
            continue
        if c.isspace():
            if cur:
                tokens.append("".join(cur))
                cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    if cur:
        tokens.append("".join(cur))
    return tokens


def parse_dep_info(path):
    """Every dependency path a dep-info file names, across all its stanzas,
    de-duplicated. A `.d` file carries one `target: dep dep ...` stanza per
    output file the unit produces (the `.rlib`, the `.rmeta`, a phony
    self-rule for the source with no deps), and they all name the same
    dependency set -- counting a source file once per stanza would inflate
    "dependency paths resolved" without finding anything new. `# env-dep:`
    lines (and any other comment) are not paths and are skipped outright.

    NOT `.strip()`ped: a dependency path can legitimately END in an escaped
    literal space (`\\ `), and `str.strip()` does not know that a trailing
    backslash-space pair is an ESCAPE rather than incidental whitespace -- it
    removes the space regardless, corrupting the last token on a line.
    `text.split("\\n")` has already removed the newline itself, and Python's
    own universal-newline text reading upstream of that has already turned
    any `\\r\\n` into a bare `\\n`, so there is no trailing newline left to
    strip in the first place.

    Refuses (raises `DepInfoError`) on a non-blank, non-comment line with no
    `:` separator -- not valid dep-info -- and on parsing to ZERO dependency
    paths overall: rustc always lists at least the compiled unit's own crate
    root among its dependencies, so an empty result means this was not
    really rustc's dep-info, or this parser broke, either way nothing was
    verified."""
    text = pathlib.Path(path).read_text(encoding="utf-8", errors="surrogateescape")
    # Backslash-newline is a Makefile continuation: join it into one logical
    # line before splitting, so a dependency list wrapped across lines is
    # read whole rather than truncated at the first line break.
    text = text.replace("\\\r\n", " ").replace("\\\n", " ")
    out, seen = [], set()
    for i, line in enumerate(text.split("\n"), 1):
        if not line or line.startswith("#"):
            continue
        idx = _find_unescaped_colon(line)
        if idx is None:
            raise DepInfoError(
                f"{path}: line {i} has content but no ':' separator -- not "
                f"valid Makefile-syntax dep-info: {line!r}")
        for tok in _tokenize_makefile_deps(line[idx + 1:]):
            if tok not in seen:
                seen.add(tok)
                out.append(tok)
    if not out:
        raise DepInfoError(
            f"{path}: parsed ZERO dependency paths -- rustc always lists at "
            f"least the crate root among a unit's dependencies")
    return out


class BuildPassResult(typing.NamedTuple):
    ok: bool
    reason: str
    violations: list
    packages_examined: int
    artifacts_examined: int
    deps_resolved: int


class CheckBResult(typing.NamedTuple):
    ok: bool
    reason: str
    violations: list
    default_pass: BuildPassResult
    feature_pass: BuildPassResult


def _process_build_output(lines, server_id, local_path_ids, member_ids,
                           id_to_name, root, check_completeness=True):
    """The core of check B for ONE build's output, taking cargo's raw
    JSON-lines stdout as an iterable of strings rather than running cargo
    itself -- what makes a workspace member producing NO artifact, and a
    stray non-JSON line, testable with a synthetic line list and no real
    `cargo build`.

    `local_path_ids`: every LOCAL PATH package's id (source is `None`) other
    than the server -- member or not -- whose artifacts are EXAMINED.
    `member_ids`: workspace members other than the server, the (smaller,
    always-should-be-built) set whose ABSENCE from the build is a refusal
    when `check_completeness` is true; a non-member local path dependency
    that legitimately never gets built is not held to that same bar, and
    NEITHER is a `required-features`-gated member target that legitimately
    exists only under the OTHER build (`check_completeness=False` is what
    the feature-flags pass uses -- see `check_b`).

    The returned `BuildPassResult.violations` is a list of `(package,
    target, path, message)` TUPLES, sorted, not plain message strings --
    `path` here is the OFFENDING SOURCE path the dep-info line resolved
    to, not the dep-info file's own path (see the inline note where the
    tuple is built). `check_b` needs the three fields again when it
    combines THIS pass with the other one; sorting each pass separately
    does not sort their concatenation, and de-duplicating needs the
    structured, offending-path-keyed form too."""
    server_dir = os.path.realpath(os.path.join(root, SERVER_REL_DIR))
    server_dir_cf = server_dir.casefold()
    violations = []
    packages_seen = set()
    artifacts_examined = 0
    deps_resolved = 0
    dep_info_owner = {}  # realpath(path).casefold() -> (pkg_id, target_name)
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            return BuildPassResult(False,
                f"a line of `cargo build --message-format=json`'s output "
                f"did not parse as JSON -- check B verifies nothing a build "
                f"did not produce, and a line it cannot read is not a line "
                f"it can silently skip ({e}): {line[:500]!r}", [], 0, 0, 0)
        if msg.get("reason") != "compiler-artifact":
            continue
        pkg_id = msg.get("package_id")
        if pkg_id == server_id or pkg_id not in local_path_ids:
            continue
        filenames = msg.get("filenames") or []
        target_name = (msg.get("target") or {}).get("name")
        is_custom_build = (msg.get("target") or {}).get("kind") == ["custom-build"]
        dep_info = None
        candidates = dep_info_candidates(filenames)
        for cand in candidates:
            if os.path.isfile(cand):
                dep_info = cand
                break
        if dep_info is None:
            # For a `custom-build` artifact there is exactly ONE candidate
            # (the exact, hash-qualified name -- no generic fallback; see
            # `dep_info_candidates`), so this is never a silently-wrong
            # recovery: absent means the gate cannot see what that build
            # script compiled, and refuses rather than guessing.
            extra = (" (custom-build: no generic fallback is tried -- see "
                     "dep_info_candidates)") if is_custom_build else ""
            return BuildPassResult(False,
                f"no dep-info file found for {id_to_name.get(pkg_id, pkg_id)}"
                f"'s target {target_name!r}{extra} -- tried: "
                f"{candidates or filenames}", [], 0, 0, 0)
        # Keyed by `realpath().casefold()`, not the raw candidate string --
        # the SAME fail-closed reasoning as containment below: two
        # differently-spelled paths (a symlink, or two case-spellings on a
        # case-insensitive filesystem) can name the identical on-disk file,
        # and comparing the raw strings would miss that collision entirely.
        dep_info_key = os.path.realpath(dep_info).casefold()
        prior = dep_info_owner.get(dep_info_key)
        if prior is not None and prior != (pkg_id, target_name):
            prior_pkg, prior_target = prior
            return BuildPassResult(False,
                f"dep-info path collision: {dep_info} resolves for BOTH "
                f"{id_to_name.get(pkg_id, pkg_id)} target {target_name!r} "
                f"AND {id_to_name.get(prior_pkg, prior_pkg)} target "
                f"{prior_target!r} -- cargo's own 'output filename "
                f"collision' hazard (see check_b); a dep-info file shared "
                f"between two units cannot be trusted to describe either "
                f"one", [], 0, 0, 0)
        dep_info_owner[dep_info_key] = (pkg_id, target_name)
        try:
            dep_paths = parse_dep_info(dep_info)
        except (OSError, DepInfoError) as e:
            return BuildPassResult(False, f"could not read {dep_info}: {e}",
                                    [], 0, 0, 0)
        packages_seen.add(pkg_id)
        artifacts_examined += 1
        for dep in dep_paths:
            dep_abs = dep if os.path.isabs(dep) else os.path.join(root, dep)
            real = os.path.realpath(dep_abs)
            deps_resolved += 1
            real_cf = real.casefold()
            if real_cf == server_dir_cf or real_cf.startswith(server_dir_cf + os.sep):
                dep_info_relpath = os.path.relpath(dep_info, root)
                real_relpath = os.path.relpath(real, root)
                pkg_display = id_to_name.get(pkg_id, pkg_id)
                # The tuple's third field is the OFFENDING SERVER-SIDE
                # SOURCE path (`real`, the realpath the dep-info line
                # resolves to), not the dep-info path -- `check_b`'s
                # combining step needs to recognise the SAME violation
                # when it shows up in both the default and the feature
                # build's output, and the dep-info path is a HASH-
                # QUALIFIED build-directory name (`deps/<pkg>-<hash>.d`)
                # that differs between the two builds even when the
                # offending source file is identical (a different Cargo
                # fingerprint per feature set); the offending source path
                # itself does not.
                violations.append((
                    pkg_display, str(target_name), real_relpath,
                    f"{pkg_display} target {target_name!r}: dep-info "
                    f"{dep_info_relpath} names {dep!r}, which resolves to "
                    f"{real} -- inside {SERVER_REL_DIR}/ (check B: rustc's "
                    f"dep-info)"))
    # Sorted by (package, target, the offending source path) -- NOT the
    # order artifacts happened to be discovered in, which tracks cargo's
    # own build-parallelism scheduling and can vary between two otherwise-
    # identical invocations of the exact same build (a DIFFERENT source of
    # nondeterminism than check A's Python-`set` one, closed the same way:
    # report in a fixed order regardless of the order the underlying data
    # arrived in). Kept as STRUCTURED `(package, target, path, message)`
    # tuples here, not flattened to plain message strings -- `check_b`
    # needs the same three fields again when it combines this pass with
    # the OTHER one, both to sort their concatenation (which sorting each
    # pass separately does not do) and to recognise a violation that
    # shows up in both passes (see `_combine_violations`).
    violations.sort(key=lambda v: v[:3])
    if check_completeness:
        missing = sorted(member_ids - packages_seen)
        if missing:
            return BuildPassResult(False,
                "the following workspace member(s) produced NO compiler-artifact "
                "under `cargo build --workspace --all-targets` -- check B "
                "verified nothing about them: " +
                ", ".join(id_to_name.get(m, m) for m in missing), [], 0, 0, 0)
    if artifacts_examined == 0:
        return BuildPassResult(False,
            "zero non-server artifacts were examined by check B -- a check "
            "that verified nothing must not report green", [], 0, 0, 0)
    return BuildPassResult(True, "", violations, len(packages_seen),
                            artifacts_examined, deps_resolved)


def _fips_node_ids(meta):
    """The set of resolve node ids that report a feature literally named
    `fips` in their OWN `resolve.nodes[].features` list -- CARGO's account
    of what a given `--features` selection actually activated for THAT
    package, never a prediction this gate reconstructs from the feature
    tables by hand. VERIFIED on this workspace: `cargo metadata --locked
    --features granary-net/fips` reports `"fips"` in the `features` list
    of the `granary-net`, `rustls`, `aws-lc-rs` and `aws-lc-fips-sys`
    nodes; a metadata call under this gate's own COMPUTED (surviving)
    feature set shows `"fips"` on none of them.

    Returns the SET of ids, not a bool, because a candidate is judged
    against a BASELINE (see `compute_feature_flags`): activating a
    feature is only a problem if it ADDS a node to this set relative to
    plain `cargo metadata` with no extra features, not merely if the set
    is non-empty. A workspace whose DEFAULT build already has `fips`
    active on some node (a mandatory, unconditional dependency on a
    crate whose own `default` includes `fips`, say) would otherwise
    attribute that PRE-EXISTING activation to every candidate probed on
    top of it, excluding every one of them regardless of what each
    candidate itself does -- the feature-pass build would silently
    degenerate into a second default build, indistinguishable from one,
    while the gate kept reporting green."""
    return {node["id"] for node in meta.get("resolve", {}).get("nodes", [])
            if "fips" in (node.get("features") or [])}


class FeatureFlagsResult(typing.NamedTuple):
    ok: bool
    reason: str
    flags: list
    excluded: list


def compute_feature_flags(root, meta_all, member_ids, id_to_name):
    """Every workspace member's own declared feature (server included), as
    `"pkgname/feat"`, EXCEPT `default` itself -- KEPT only if CARGO's own
    resolver, asked directly against the real workspace at `root`, shows
    that turning it on does not activate a feature literally named `fips`
    anywhere in the graph.

    This asks CARGO directly rather than hand-rolling a walk over the
    feature tables: matching a manifest `dep:name`/`name/feat` requirement
    to a resolved package id, following renames, disambiguating two
    versions of one crate by version requirement, and tracking
    `default-features = false` by hand are all CARGO's own job already,
    and a hand-rolled walk patched one shape at a time (a rename, a
    hyphenated name, a `[lib]` override, a version range, a git source)
    opens a new edge for every shape it does not cover rather than
    closing the class -- re-implementing a dependency resolver one shape
    at a time does not converge. Asking cargo directly removes the class
    instead of chasing another instance of it: renames, two versions of
    one crate, hyphenated names, a custom `[lib] name`, and a git or
    registry source are all things CARGO resolves as a matter of course,
    and this gate does not need to know any of those shapes exist.

    A BASELINE is taken first -- plain `cargo metadata --locked`, no
    extra features at all -- and its own `_fips_node_ids` is what every
    later probe is compared AGAINST, never an absolute "is fips active
    anywhere" test: a workspace whose default build already has `fips`
    active on some node must not have that pre-existing activation
    attributed to every candidate probed on top of it (see
    `_fips_node_ids`'s own docstring for why an absolute test degenerates
    the whole feature-pass build silently).

    TWO rounds after the baseline, because a feature can reach `fips`
    alone or only in COMBINATION with another (feature unification does
    not decompose one candidate at a time):

    1. Every candidate `pkgname/feat` is tried ALONE, on top of default
       features -- matching exactly what check B's own feature-pass build
       later does: `cargo metadata --locked --features pkgname/feat`.
       Excluded the moment that probe's `_fips_node_ids` contains an id
       NOT in the baseline -- a node the candidate itself newly activated.
    2. The SURVIVING candidates are re-checked TOGETHER, in one combined
       `cargo metadata --locked --features <survivors>` call, against the
       SAME baseline. If THAT probe adds a node the baseline did not have,
       the gate REFUSES (`ok=False`) rather than guessing which survivor
       to blame and silently dropping it.

    `excluded` reports every round-1 exclusion, so the caller can print
    plainly what was left out and why -- never a silent narrowing. Every
    entry in `excluded` is, by this construction, a candidate that ADDED a
    fips-active node relative to the baseline -- there is no other place
    this function appends to it -- so a caller that only ever sees
    additions here does not need a separate check that a returned
    `ok=True` result's exclusions were all justified this way."""
    meta_baseline, err = cargo_metadata(root)
    if err:
        return FeatureFlagsResult(
            False, "could not probe the default-features baseline with "
                   f"cargo metadata: {err}", [], [])
    baseline_fips = _fips_node_ids(meta_baseline)

    features_by_pkg = {p["id"]: (p.get("features") or {})
                        for p in meta_all.get("packages", [])}
    candidates = set()
    for pid in member_ids:
        pkg_name = id_to_name.get(pid, pid)
        for fname in features_by_pkg.get(pid, {}):
            if fname == "default":
                continue
            candidates.add(f"{pkg_name}/{fname}")

    survivors = []
    excluded = []
    for cand in sorted(candidates):
        meta_cand, err = cargo_metadata(root, features=[cand])
        if err:
            return FeatureFlagsResult(
                False, f"could not probe candidate feature {cand!r} with "
                       f"cargo metadata: {err}", [], [])
        added = _fips_node_ids(meta_cand) - baseline_fips
        if added:
            excluded.append(f"{cand} (cargo shows it newly activates fips "
                             f"on {len(added)} node(s) beyond the default "
                             f"build's own baseline)")
        else:
            survivors.append(cand)

    if survivors:
        meta_combined, err = cargo_metadata(root, features=survivors)
        if err:
            return FeatureFlagsResult(
                False, "could not probe the combined surviving feature "
                       f"set with cargo metadata: {err}", [], [])
        if _fips_node_ids(meta_combined) - baseline_fips:
            return FeatureFlagsResult(
                False,
                "the surviving feature set activates fips TOGETHER (beyond "
                "the default build's own baseline) even though no single "
                "one of them does alone -- refusing rather than guessing "
                "which to drop: " + ", ".join(sorted(survivors)), [], [])

    return FeatureFlagsResult(True, "", sorted(survivors), sorted(excluded))


def _run_build_pass(root, extra_args, server_id, local_path_ids, member_ids,
                     id_to_name, check_completeness):
    """One `cargo build --message-format=json` invocation, turned into a
    `BuildPassResult`."""
    cmd = ["cargo", "build", "--workspace", "--all-targets", "--locked",
           *extra_args, "--message-format=json"]
    proc = run(cmd, root)
    if proc.returncode != 0:
        return BuildPassResult(False,
            f"`{' '.join(cmd)}` exited {proc.returncode} -- check B "
            f"verifies nothing a build did not produce:\n"
            f"{proc.stderr.strip()[-4000:]}", [], 0, 0, 0)
    # `cargo`'s own "output filename collision" warning (two units writing
    # the SAME hash-less top-level output -- VERIFIED: it is cargo's plain
    # stderr TEXT, never part of the `--message-format=json` stream on
    # stdout) means the build's result is order-dependent: whichever unit
    # linked last is the one `target/debug/<name>` actually holds. This
    # gate does not trust which one that was.
    if "output filename collision" in proc.stderr:
        return BuildPassResult(False,
            "cargo reported an output filename collision -- the build's "
            "result is order-dependent, and this gate does not trust which "
            "unit's output survived:\n" + proc.stderr.strip()[-4000:],
            [], 0, 0, 0)
    return _process_build_output(proc.stdout.splitlines(), server_id,
                                  local_path_ids, member_ids, id_to_name,
                                  root, check_completeness)


def _combine_violations(default_violations, feature_violations, root=None):
    """The COMBINED (default pass + feature pass) violation list, de-
    duplicated and sorted by (package, target, the offending source path)
    -- NOT each pass sorted separately and then concatenated, which is not
    the same thing: two already-sorted lists appended end to end is not
    itself sorted (a default-pass violation for "b" and a feature-pass
    violation for "a" must print "a" before "b", the OPPOSITE of
    concatenation order).

    De-duplicated on (package, target, the offending path CASEFOLDED) --
    and DELIBERATELY NOT on the full 4-tuple (which a plain `dict.fromkeys`
    over the whole list would give): the 4th field, the MESSAGE, embeds
    the dep-info file's own path, and that path is derived from a HASH-
    QUALIFIED build-directory name that differs between the default and
    feature builds even when they found the identical offending source
    file (a different Cargo fingerprint per feature set) -- keying on the
    full tuple would never actually collapse the SAME violation reported
    by both passes, only two byte-identical ones. The offending path is
    keyed by FILE IDENTITY (`st_dev`, `st_ino` of the file under `root`),
    not by its spelling: two spellings that differ only in case name one
    file on a case-insensitive filesystem and collapse, while two distinct
    files on a case-sensitive one stay two. A path that cannot be stat'ed,
    or a call with no `root`, falls back to the raw spelling.

    Sorted on the FULL 4-tuple FIRST, THEN grouped for de-duplication,
    keeping the FIRST entry each (package, target, casefolded path) group
    produces in that sorted order -- not the reverse (group first, keep
    whichever list's entry arrived first in the concatenation). Sorting
    everything before grouping makes the result depend only on the
    CONTENT of the two input lists, never on which list a caller happened
    to pass as `default_violations` versus `feature_violations`: the SAME
    multiset of tuples, fed in EITHER argument order, sorts into the exact
    same sequence before de-duplication ever looks at it, so the kept
    message is always the one that compares smallest, regardless of which
    pass reported it or which argument position it arrived in. Returns the
    final flat list of MESSAGE strings `CheckBResult.violations` reports;
    the inputs are lists of `(package, target, path, message)` tuples."""
    def identity(path):
        if root is not None:
            try:
                st = os.stat(os.path.join(root, path))
                return ("inode", st.st_dev, st.st_ino)
            except OSError:
                pass
        return ("path", path)

    combined = {}
    for v in sorted(default_violations + feature_violations):
        key = (v[0], v[1], identity(v[2]))
        if key not in combined:
            combined[key] = v
    ordered = sorted(combined.values(), key=lambda v: v[:3])
    return [v[3] for v in ordered]


def check_b(root, server_id, local_path_ids, member_ids, id_to_name, feature_flags):
    """TWO builds, unioned. A single build with every non-fips feature ON
    is blind to source
    compiled only when a feature is OFF -- `#[cfg(not(feature = "x"))]`
    branches exist in this very workspace (`conformance-breakage`'s own
    release wall is one) -- because activating every feature at once makes
    every such branch's condition false everywhere at once. So check B
    also runs the DEFAULT-features build, and takes the union of both
    builds' examined artifacts and violations.

    Completeness (every workspace member produced at least one artifact)
    is enforced on the DEFAULT build only: `--all-targets` under the
    computed feature set can legitimately produce MORE targets (a
    `required-features`-gated one) than under defaults, but never fewer,
    so the default build is the floor every member must clear, and the
    feature build's own member coverage is not separately demanded.

    When `feature_flags` is empty there is nothing the second build could
    compile that the first does not already -- skipped, not run as a
    wasteful duplicate of the exact same invocation."""
    default_pass = _run_build_pass(root, [], server_id, local_path_ids,
                                    member_ids, id_to_name,
                                    check_completeness=True)
    if not default_pass.ok:
        return CheckBResult(False, default_pass.reason, [], default_pass,
                             default_pass)
    if not feature_flags:
        return CheckBResult(True, "", _combine_violations(default_pass.violations, [], root),
                             default_pass, default_pass)
    feature_pass = _run_build_pass(
        root, ["--features", ",".join(feature_flags)], server_id,
        local_path_ids, member_ids, id_to_name, check_completeness=False)
    if not feature_pass.ok:
        return CheckBResult(False, feature_pass.reason, [], default_pass,
                             feature_pass)
    violations = _combine_violations(default_pass.violations, feature_pass.violations, root)
    return CheckBResult(True, "", violations, default_pass, feature_pass)


def run_gate(root):
    """The whole gate against workspace root `root`. Returns an exit code."""
    meta, err = cargo_metadata(root)
    if err:
        print(f"THE LICENCE-RESOLVED GATE COULD NOT RUN -- {err}", file=sys.stderr)
        return 2
    server = find_server(meta, root)
    if server is None:
        print("THE LICENCE-RESOLVED GATE COULD NOT RUN -- no workspace member "
              f"named {SERVER_NAME!r} with manifest {SERVER_REL_MANIFEST} was "
              "found. A gate that cannot find its subject is blind, not "
              "clean.", file=sys.stderr)
        return 2
    server_id = server["id"]
    id_to_name = {p["id"]: p["name"] for p in meta.get("packages", [])}
    others = {m for m in meta.get("workspace_members", []) if m != server_id}
    if not others:
        print(f"THE LICENCE-RESOLVED GATE COULD NOT RUN -- {SERVER_NAME} is "
              "the only workspace member; there is no OTHER member for this "
              "gate to check.", file=sys.stderr)
        return 2

    meta_all, err_all = cargo_metadata(root, all_features=True)
    if err_all:
        print("THE LICENCE-RESOLVED GATE COULD NOT RUN -- check A's "
              f"`--all-features` cargo metadata call failed: {err_all}",
              file=sys.stderr)
        return 2
    id_to_name_all = dict(id_to_name)
    id_to_name_all.update({p["id"]: p["name"] for p in meta_all.get("packages", [])})

    a = check_a(meta_all, server_id, others, id_to_name_all)
    if not a.ok:
        print(f"THE LICENCE-RESOLVED GATE COULD NOT RUN -- {a.reason}",
              file=sys.stderr)
        return 2
    c = check_c(meta_all, root, id_to_name_all)
    if not c.ok:
        print(f"THE LICENCE-RESOLVED GATE COULD NOT RUN -- {c.reason}",
              file=sys.stderr)
        return 2

    # Every OTHER member feature (never fips-gated) is activated, computed
    # rather than named -- see the header and compute_feature_flags. The
    # SERVER's own non-fips features are included too: its own artifacts
    # stay exempt from containment below, but a server feature can still
    # enable a feature on a non-member local helper that compiles server
    # source, and that edge would never get built (so never examined) if
    # only the OTHER members' features were considered.
    ff = compute_feature_flags(root, meta_all, others | {server_id}, id_to_name_all)
    if not ff.ok:
        print(f"THE LICENCE-RESOLVED GATE COULD NOT RUN -- {ff.reason}",
              file=sys.stderr)
        return 2
    feature_flags = ff.flags
    print(f"licence-resolved: check B feature set (every member feature, "
          f"server included, except fips-gated ones): "
          f"{feature_flags or '(none)'}")
    # Reported on EVERY run, not only a failing one -- a silent narrowing
    # of the feature set is exactly what this gate's own coverage limits
    # must not be.
    if ff.excluded:
        print("licence-resolved: excluded from check B's feature set "
              "(cargo metadata shows each ADDS fips beyond the default "
              "build's own baseline):")
        for reason in ff.excluded:
            print(f"  {reason}")
    # An EMPTY surviving set with candidates that WERE excluded is not the
    # same thing as "this workspace declares no non-default feature at
    # all" (the `(none)` line above covers that case too, indistinguishably
    # by itself) -- every candidate reaching fips is a real possible
    # outcome, but it collapses check B's feature-pass build into a
    # near-duplicate of the default build, and a run that only prints
    # `(none)` looks identical to the harmless "no features exist" case.
    # Stated PROMINENTLY here rather than left for a reader to infer from
    # counting the two lists above.
    if not feature_flags and ff.excluded:
        print("licence-resolved: ALL candidate features were excluded -- "
              "check B's feature-pass build activates NOTHING beyond "
              "default, and covers no more than the default build already "
              "does. This is a possible, not a silent, outcome: exit stays "
              "0 because every exclusion above is one cargo itself showed "
              "ADDS fips beyond the baseline, never a guess.")

    # Check B examines every LOCAL PATH package (source is `None`, id
    # starts `path+file://`), member or not, except the server -- cargo
    # builds a path dependency excluded from the workspace too, and check
    # A's manifest-edge view cannot see a source-level bypass planted
    # inside one. Derived from `meta_all` (`--all-features`), NOT the
    # default-features `meta`: check B's own build activates `feature_flags`
    # (every non-fips feature), and an OPTIONAL local path dependency that
    # only exists once some feature is on would be compiled by that build
    # but invisible to a default-features-only package list -- examined
    # nothing, looking the same as clean. `meta_all`'s package set is a
    # sound superset of whatever `feature_flags` actually activates: cargo's
    # feature resolution is MONOTONIC (turning MORE features on can only
    # ADD packages/edges to the graph, never remove one that a narrower
    # selection already had), and `--all-features` turns on every feature
    # everywhere, including ones `feature_flags` excludes (fips) or that no
    # member's own manifest names at all -- so it can only ever see AT LEAST
    # as much of the local-path universe as the real build does.
    local_path_ids = {p["id"] for p in meta_all.get("packages", [])
                       if p.get("source") is None
                       and p.get("id", "").startswith("path+file://")} - {server_id}

    b = check_b(root, server_id, local_path_ids, others, id_to_name_all, feature_flags)
    if not b.ok:
        print(f"THE LICENCE-RESOLVED GATE COULD NOT RUN -- {b.reason}",
              file=sys.stderr)
        return 2

    violations = a.violations + b.violations + c.violations
    if violations:
        print(f"licence-resolved: {len(violations)} violation(s):", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        if c.violations:
            print(f"\n  {SIM_NAME} holds the seeded cryptographic-randomness "
                  "stream, fixed by a replay seed; a production binary that "
                  "links it or generates code from it at build time could "
                  "mint repeatable identities or epochs. For a "
                  "[dependencies] edge used only by tests, move it to "
                  "[dev-dependencies]; for a [build-dependencies] edge, the "
                  "build script must not use the simulator at all -- drop "
                  "the edge, and move what the script needs into a crate "
                  "that is not the simulator.", file=sys.stderr)
        if a.violations or b.violations:
            print(f"\n  {SERVER_NAME} is AGPL-3.0-or-later and every other "
                  "crate is Apache-2.0. A resolved dependency edge (direct or "
                  "transitive), or a compiled source path, crossing that "
                  "boundary makes the consumer's distribution terms the "
                  "server's. Move what is needed into an Apache crate as a "
                  "pure primitive instead; the server's own logic never "
                  "migrates outward.", file=sys.stderr)
        return 1

    feature_pass_line = ("skipped (identical to the default build -- no "
                          "non-fips feature to activate)" if not feature_flags
                          else f"{b.feature_pass.packages_examined} local path "
                               f"package(s), {b.feature_pass.artifacts_examined} "
                               f"artifact(s), resolved "
                               f"{b.feature_pass.deps_resolved} dependency "
                               f"path(s)")
    roots = ", ".join(name for name, _ in PRODUCTION_ROOTS)
    print(f"licence-resolved: {len(others)} other workspace member(s) "
          f"checked (check A, transitive, --all-features: zero paths onto "
          f"{SERVER_NAME}); check C: zero normal- or build-edge paths from {roots} "
          f"onto {SIM_NAME}; check B default-features build examined "
          f"{b.default_pass.packages_examined} local path package(s), "
          f"{b.default_pass.artifacts_examined} artifact(s), resolved "
          f"{b.default_pass.deps_resolved} dependency path(s); check B "
          f"{len(feature_flags)}-non-fips-feature build ({feature_pass_line}) "
          f"-- ALL GREEN")
    return 0


# ============================================================ --self-test ==
# Every subprocess row builds a throwaway two-member cargo workspace
# (granary-server plus a member named `a`), offline -- both are path-only
# packages with no registry dependency at all, so nothing here ever touches
# the network. Some items (a workspace member missing its own resolve node;
# an invalid JSON line; a member cargo would refuse to build at all) have no
# REAL fixture that can produce them -- those are proven with direct calls
# on synthetic input instead, the same way check-bench-results-
# classification.py and check-citations.py test their own refusals.

def _write(path, content):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _cargo(args, cwd, env):
    return subprocess.run(["cargo", *args], cwd=str(cwd), env=env,
                           capture_output=True, text=True, timeout=600)


def _base_fixture(root, with_server=True, with_member=True):
    _write(root / "Cargo.toml",
           '[workspace]\nresolver = "3"\nmembers = ["crates/*"]\n')
    if with_server:
        _write(root / "crates/granary-server/Cargo.toml",
               '[package]\nname = "granary-server"\nversion = "0.0.0"\n'
               'edition = "2021"\n')
        _write(root / "crates/granary-server/src/lib.rs",
               'pub fn hello() -> u32 { 1 }\n')
    if with_member:
        _write(root / "crates/a/Cargo.toml",
               '[package]\nname = "a"\nversion = "0.0.0"\nedition = "2021"\n')
        _write(root / "crates/a/src/lib.rs", 'pub fn hi() -> u32 { 2 }\n')
        # Check C's subject and its other root, shaped as in the real
        # workspace: the cli takes the simulator as a DEV-dependency only,
        # so every clean row is also check C's positive control for an
        # edge kind it must not follow.
        _write(root / "crates/granary-sim/Cargo.toml",
               '[package]\nname = "granary-sim"\nversion = "0.0.0"\n'
               'edition = "2021"\n')
        _write(root / "crates/granary-sim/src/lib.rs",
               'pub fn seeded() -> u32 { 3 }\n')
        _write(root / "crates/granary-cli/Cargo.toml",
               '[package]\nname = "granary-cli"\nversion = "0.0.0"\n'
               'edition = "2021"\n\n[dev-dependencies]\n'
               'granary-sim = { path = "../granary-sim" }\n')
        _write(root / "crates/granary-cli/src/lib.rs",
               'pub fn gran() -> u32 { 4 }\n')


def _env_for(fixture):
    env = dict(os.environ)
    env["CARGO_TARGET_DIR"] = str(fixture / "target")
    env["CARGO_NET_OFFLINE"] = "true"
    return env


def _lock(root, env):
    r = _cargo(["generate-lockfile", "--offline"], root, env)
    if r.returncode != 0:
        raise RuntimeError(f"fixture setup: generate-lockfile failed: {r.stderr}")


def _invoke(root, env):
    return subprocess.run([sys.executable, os.path.abspath(__file__)], cwd=str(root),
                           env=env, capture_output=True, text=True, timeout=900)


def _fs_is_case_insensitive(directory):
    """True if `directory`'s filesystem treats differently-cased names as the
    SAME entry (APFS's default, exFAT, NTFS) -- false on a case-sensitive one
    (ext4, most Linux filesystems). Detected empirically rather than assumed
    from the platform, because APFS CAN be formatted case-sensitive."""
    probe = pathlib.Path(directory) / ".case-probe-XyZ"
    probe.write_text("x")
    try:
        return (pathlib.Path(directory) / ".CASE-PROBE-XyZ").exists()
    finally:
        probe.unlink(missing_ok=True)


def _find_compiler_artifact(stdout, pkg_substr, kind):
    """The first `compiler-artifact` message in `stdout` (cargo's captured
    JSON-lines) whose package id contains `pkg_substr` and whose target kind
    equals `kind`, or None."""
    for line in stdout.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") != "compiler-artifact":
            continue
        if pkg_substr not in msg.get("package_id", ""):
            continue
        if (msg.get("target") or {}).get("kind") != kind:
            continue
        return msg
    return None


# ---- rows 1-12: the canonical crossings and refusals, with their positive controls (1, 9, 11)

def _row_clean(root, env):
    _base_fixture(root)
    _lock(root, env)


def _row_dep(kind):
    def build(root, env):
        _base_fixture(root)
        _write(root / "crates/a/Cargo.toml",
               (root / "crates/a/Cargo.toml").read_text() +
               f'\n[{kind}]\ngranary-server = {{ path = "../granary-server" }}\n')
        if kind == "build-dependencies":
            _write(root / "crates/a/build.rs", "fn main() {}\n")
        _lock(root, env)
    return build


def _row_renamed_dep(root, env):
    _base_fixture(root)
    _write(root / "crates/a/Cargo.toml",
           (root / "crates/a/Cargo.toml").read_text() +
           '\n[dev-dependencies]\n'
           'srv = { package = "granary-server", path = "../granary-server" }\n')
    _lock(root, env)


def _row_concat_include(root, env):
    _base_fixture(root)
    _write(root / "crates/granary-server/src/x.rs", "pub const X: u32 = 9;\n")
    _write(root / "crates/a/src/lib.rs",
           (root / "crates/a/src/lib.rs").read_text() +
           'include!(concat!("../../granary-", "server/src/x.rs"));\n')
    _lock(root, env)


def _row_path_attr(root, env):
    _base_fixture(root)
    _write(root / "crates/granary-server/src/x.rs", "pub const X: u32 = 9;\n")
    _write(root / "crates/a/src/lib.rs",
           (root / "crates/a/src/lib.rs").read_text() +
           '#[path = "../../granary-server/src/x.rs"]\nmod x;\n')
    _lock(root, env)


def _row_symlink(root, env):
    _base_fixture(root)
    _write(root / "crates/granary-server/src/x.rs", "pub const X: u32 = 9;\n")
    link = root / "crates/a/src/linked.rs"
    link.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(os.path.join("..", "..", "granary-server", "src", "x.rs"), link)
    _write(root / "crates/a/src/lib.rs",
           (root / "crates/a/src/lib.rs").read_text() + "mod linked;\n")
    _lock(root, env)


def _row_escaped_include_str(root, env):
    _base_fixture(root)
    _write(root / "crates/granary-server/src/data.txt", "secret\n")
    _write(root / "crates/a/src/lib.rs",
           (root / "crates/a/src/lib.rs").read_text() +
           r'pub const G: &str = include_str!("../../\x67ranary-server/src/data.txt");'
           "\n")
    _lock(root, env)


def _row_server_self_include(root, env):
    _base_fixture(root)
    _write(root / "crates/granary-server/src/other.rs", "pub const OTHER: u32 = 1;\n")
    _write(root / "crates/granary-server/src/lib.rs",
           (root / "crates/granary-server/src/lib.rs").read_text() +
           'include!("other.rs");\n')
    _lock(root, env)


def _row_no_server(root, env):
    _base_fixture(root, with_server=False, with_member=True)
    _lock(root, env)


def _row_server_only(root, env):
    _base_fixture(root, with_server=True, with_member=False)
    _lock(root, env)


def _row_stale_dep_info(root, env):
    _base_fixture(root)
    _lock(root, env)
    r = _cargo(["build", "--workspace", "--all-targets", "--locked"], root, env)
    if r.returncode != 0:
        raise RuntimeError(f"fixture setup: initial build failed: {r.stderr}")
    deps_dir = pathlib.Path(env["CARGO_TARGET_DIR"]) / "debug" / "deps"
    bogus = deps_dir / "bogus-deadbeefdeadbeef.d"
    server_lib = root / "crates/granary-server/src/lib.rs"
    _write(bogus, f"{deps_dir / 'bogus-deadbeefdeadbeef'}: {server_lib}\n")


def _row_cargo_failure(root, env):
    _base_fixture(root)
    _lock(root, env)
    _write(root / "crates/a/Cargo.toml", '[package\nname = "a"\n')


# ---- additional rows: each covers one construction a real fixture can make

def _row_optional_feature_dep(root, env):
    """An optional dependency edge that only shows up once every feature is on."""
    _base_fixture(root)
    _write(root / "crates/a/Cargo.toml",
           (root / "crates/a/Cargo.toml").read_text() +
           '\n[dependencies]\n'
           'granary-server = { path = "../granary-server", optional = true }\n'
           '\n[features]\n'
           'extra = ["dep:granary-server"]\n')
    _lock(root, env)


def _row_transitive_reachability(root, env):
    """Member -> non-member path crate (excluded from the workspace by
    simply sitting outside its root) -> server."""
    _base_fixture(root)
    helper_dir = root.parent / f"{root.name}-helper"
    server_dir = root / "crates/granary-server"
    rel_to_server = os.path.relpath(server_dir, helper_dir)
    _write(helper_dir / "Cargo.toml",
           '[package]\nname = "helper"\nversion = "0.0.0"\nedition = "2021"\n\n'
           '[dependencies]\n'
           f'granary-server = {{ path = {json.dumps(rel_to_server)} }}\n')
    _write(helper_dir / "src/lib.rs",
           "pub fn h() -> u32 { granary_server::hello() }\n")
    a_dir = root / "crates/a"
    rel_to_helper = os.path.relpath(helper_dir, a_dir)
    a_manifest = a_dir / "Cargo.toml"
    _write(a_manifest, a_manifest.read_text() +
           f'\n[dependencies]\nhelper = {{ path = {json.dumps(rel_to_helper)} }}\n')
    _write(a_dir / "src/lib.rs",
           (a_dir / "src/lib.rs").read_text() +
           "pub fn use_helper() -> u32 { helper::h() }\n")
    _lock(root, env)


def _row_stale_generic_custom_build(root, env):
    """A stale, INNOCENT generic-named custom-build dep-info sitting BESIDE
    the real, hash-qualified one changes nothing: `dep_info_candidates`
    never generates the generic name as a candidate at ALL (see the
    header), so it is not merely outranked by the exact one -- it is never
    looked at. This row guards that: were the generic candidate ever
    reintroduced ahead of the exact one, THIS row would flip red; the
    `missing-custom-build-dep-info` direct unit check below covers the
    other direction -- the exact file ABSENT with only the generic one
    present, which a real `cargo build` cannot be made to reproduce
    reliably (cargo regenerates a deleted output on its very next
    invocation, even with unchanged inputs -- MEASURED), so that direction
    is proven with a synthetic `compiler-artifact` message instead."""
    _base_fixture(root)
    _write(root / "crates/granary-server/src/x.rs", "pub const X: u32 = 9;\n")
    # build.rs sits directly under crates/a/ (not crates/a/src/, like lib.rs
    # does), so it is only ONE directory above crates/ -- "../granary-server",
    # not "../../granary-server".
    _write(root / "crates/a/build.rs",
           'include!("../granary-server/src/x.rs");\nfn main() {}\n')
    _lock(root, env)
    r = _cargo(["build", "--workspace", "--all-targets", "--locked",
                "--message-format=json"], root, env)
    if r.returncode != 0:
        raise RuntimeError(f"fixture setup: initial build failed: {r.stderr}")
    msg = _find_compiler_artifact(r.stdout, "/crates/a#", ["custom-build"])
    if msg is None:
        raise RuntimeError("fixture setup: no custom-build artifact for `a`")
    filenames = msg.get("filenames") or []
    if not filenames:
        raise RuntimeError("fixture setup: custom-build artifact has no filenames")
    build_dir = os.path.dirname(filenames[0])
    bogus = pathlib.Path(build_dir) / "build-script-build.d"
    innocent_source = root / "crates/a/build.rs"
    bogus.write_text(f"{build_dir}/build-script-build: {innocent_source}\n")


def _case_sensitive_skip_reason():
    """The `_SkipRow` message for `_row_case_insensitive_include` on a
    case-sensitive filesystem, factored out so its CONTENT (not just its
    firing) is directly checkable regardless of the host's own
    case-sensitivity -- see the `case-insensitive-skip-wording` unit
    check."""
    return (
        "SKIPPED, NOT PASSED: this filesystem is case-sensitive (most "
        "Linux filesystems, including CI's runners), so a "
        "differently-cased path into the server does not exist on disk "
        "at all and `cargo build` would fail outright rather than "
        "exercising case-insensitive containment. This row's COVERAGE "
        "of the `.casefold()` containment comparison EXISTS ONLY ON A "
        "CASE-INSENSITIVE FILESYSTEM (APFS's default, exFAT, NTFS) -- "
        "on a case-sensitive one it proves nothing about that code "
        "path, every run, not just this one; see the header's coverage "
        "limits.")


def _row_case_insensitive_include(root, env):
    """A differently-cased spelling of the server's directory, reachable
    only because the filesystem folds case."""
    if not _fs_is_case_insensitive(root):
        raise _SkipRow(_case_sensitive_skip_reason())
    _base_fixture(root)
    _write(root / "crates/granary-server/src/x.rs", "pub const X: u32 = 9;\n")
    _write(root / "crates/a/src/lib.rs",
           (root / "crates/a/src/lib.rs").read_text() +
           'include!(concat!("../../Granary-", "Server/src/x.rs"));\n')
    _lock(root, env)


def _row_trailing_space_dep_info(root, env):
    """A dependency path ending in a literal, escaped trailing space.
    PLANTED into a real, already-built dep-info file rather than
    built end to end: on this toolchain (cargo/rustc 1.97.1) a crate
    containing a source file whose name ends in a space cannot be built at
    all -- MEASURED separately -- cargo's OWN dep-info reader fails to
    round-trip the phony self-rule such a file gets, exiting 101 with
    'malformed dep-info format, trailing \\\\', independent of this gate.
    A no-op rebuild of an ALREADY-built, unrelated fixture does not
    re-parse this file's content at all (MEASURED: appending this exact
    line and rebuilding succeeds), which is what makes planting it usable
    here."""
    _base_fixture(root)
    _lock(root, env)
    r = _cargo(["build", "--workspace", "--all-targets", "--locked",
                "--message-format=json"], root, env)
    if r.returncode != 0:
        raise RuntimeError(f"fixture setup: initial build failed: {r.stderr}")
    msg = _find_compiler_artifact(r.stdout, "/crates/a#", ["lib"])
    if msg is None:
        raise RuntimeError("fixture setup: no lib artifact for `a`")
    dep_info_path = None
    for cand in dep_info_candidates(msg.get("filenames") or []):
        if os.path.isfile(cand):
            dep_info_path = cand
            break
    if dep_info_path is None:
        raise RuntimeError("fixture setup: could not locate member a's lib dep-info")
    extra_target = os.path.join(root, "crates", "granary-server", "src", "trail.rs ")
    escaped = extra_target[:-1] + "\\" + extra_target[-1]
    with open(dep_info_path, "a", encoding="utf-8") as fh:
        fh.write(f"{dep_info_path}: {escaped}\n")


def _check_trailing_space_message(proc):
    """The exit code alone cannot distinguish correct parsing here: the
    corruption `.strip()` causes is confined to the dependency's OWN
    trailing character (a literal space becomes a stray backslash), and the
    surrounding directory components are untouched either way -- so
    containment-by-prefix fires and the exit code is 1 whether or not the
    trailing space survives intact. What differs is the reported PATH:
    correct when it survives (`repr()` of a string ending in a plain space
    shows it unescaped, right before the closing quote: `...trail.rs '`),
    mangled when `.strip()` corrupts it (ending in a backslash `repr()`
    DOES escape: `...trail.rs\\\\'`)."""
    combined = proc.stdout + proc.stderr
    if "trail.rs '" not in combined:
        return ("the reported violation does not show the dependency's real "
                "trailing-space filename intact (expected \"trail.rs '\" "
                "verbatim); tail:\n" + combined[-1000:])
    return None


def _row_excluded_path_crate_includes_server(root, env):
    """A LOCAL PATH crate that is a dependency of a member, but is not
    itself a workspace member (sitting outside the workspace root),
    includes a server file directly -- with NO dependency edge on the
    server declared ANYWHERE, so check A's graph walk sees nothing at all.
    Only examining this crate's own compiled artifact (check B, widened to
    every local path package) catches it."""
    _base_fixture(root)
    _write(root / "crates/granary-server/src/x.rs", "pub const X: u32 = 9;\n")
    helper_dir = root.parent / f"{root.name}-helper2"
    rel_to_x = os.path.relpath(root / "crates/granary-server/src/x.rs",
                                helper_dir / "src")
    _write(helper_dir / "Cargo.toml",
           '[package]\nname = "helper2"\nversion = "0.0.0"\nedition = "2021"\n')
    _write(helper_dir / "src/lib.rs",
           f'include!({json.dumps(rel_to_x)});\n'
           'pub fn h() -> u32 { X }\n')
    a_dir = root / "crates/a"
    rel_to_helper = os.path.relpath(helper_dir, a_dir)
    a_manifest = a_dir / "Cargo.toml"
    _write(a_manifest, a_manifest.read_text() +
           f'\n[dependencies]\nhelper2 = {{ path = {json.dumps(rel_to_helper)} }}\n')
    _write(a_dir / "src/lib.rs",
           (a_dir / "src/lib.rs").read_text() +
           "pub fn use_helper2() -> u32 { helper2::h() }\n")
    _lock(root, env)


def _row_feature_gated_include(root, env):
    """An `include!` compiled only behind a non-default feature that member
    `a` itself declares -- `compute_feature_flags` must pick it up (nothing
    here is special-cased for this fixture) and activate it, or the gated
    module is never compiled and check B never sees it."""
    _base_fixture(root)
    _write(root / "crates/granary-server/src/x.rs", "pub const X: u32 = 9;\n")
    _write(root / "crates/a/Cargo.toml",
           (root / "crates/a/Cargo.toml").read_text() + '\n[features]\nextra = []\n')
    _write(root / "crates/a/src/lib.rs",
           (root / "crates/a/src/lib.rs").read_text() +
           '#[cfg(feature = "extra")]\n'
           'mod gated {\n'
           '    include!("../../granary-server/src/x.rs");\n'
           '}\n')
    _lock(root, env)


def _row_required_features_gated_bin(root, env):
    """A `[[bin]]` target gated by `required-features`: with that feature
    OFF, `--all-targets` silently skips the target -- no artifact, nothing
    for check B to examine. `compute_feature_flags` picking up the member's
    own feature is what makes the target buildable at all."""
    _base_fixture(root)
    _write(root / "crates/granary-server/src/x.rs", "pub const X: u32 = 9;\n")
    _write(root / "crates/a/Cargo.toml",
           (root / "crates/a/Cargo.toml").read_text() +
           '\n[features]\nreqf = []\n'
           '\n[[bin]]\nname = "gated"\npath = "src/bin/gated.rs"\n'
           'required-features = ["reqf"]\n')
    _write(root / "crates/a/src/bin/gated.rs",
           'include!("../../../granary-server/src/x.rs");\n'
           'fn main() { let _ = X; }\n')
    _lock(root, env)


def _row_optional_local_path_dep_via_feature(root, env):
    """An OPTIONAL local path dependency `helper3`, pulled into the graph
    only when member `a`'s own non-default feature `extra` is active.
    VERIFIED separately: under bare `cargo metadata` (default features,
    no `--all-features`), `helper3` is ABSENT from `packages` entirely --
    not merely unreached by an edge, the whole package never resolves --
    and only `--all-features` metadata sees it. Since
    `compute_feature_flags` activates `a/extra`, the real build compiles
    `helper3` regardless; deriving the examined set from anything narrower
    than `--all-features` metadata would miss it."""
    _base_fixture(root)
    _write(root / "crates/granary-server/src/x.rs", "pub const X: u32 = 9;\n")
    helper_dir = root.parent / f"{root.name}-helper3"
    rel_to_x = os.path.relpath(root / "crates/granary-server/src/x.rs",
                                helper_dir / "src")
    _write(helper_dir / "Cargo.toml",
           '[package]\nname = "helper3"\nversion = "0.0.0"\nedition = "2021"\n')
    _write(helper_dir / "src/lib.rs",
           f'include!({json.dumps(rel_to_x)});\n'
           'pub fn h() -> u32 { X }\n')
    a_dir = root / "crates/a"
    rel_to_helper = os.path.relpath(helper_dir, a_dir)
    a_manifest = a_dir / "Cargo.toml"
    _write(a_manifest, a_manifest.read_text() +
           f'\n[dependencies]\nhelper3 = {{ path = {json.dumps(rel_to_helper)}, '
           'optional = true }\n'
           '\n[features]\nextra = ["dep:helper3"]\n')
    _write(a_dir / "src/lib.rs",
           (a_dir / "src/lib.rs").read_text() +
           '#[cfg(feature = "extra")]\n'
           'pub fn use_helper3() -> u32 { helper3::h() }\n')
    _lock(root, env)


def _row_server_feature_enables_helper(root, env):
    """A feature declared on the SERVER ITSELF (`x`) enables a feature
    (`helper4/y`) on a non-member local helper crate whose gated code
    `include!`s a server file. The server's own artifact stays exempt from
    containment, but its feature must still be ACTIVATED --
    `compute_feature_flags` including the server, not only the other
    members, is what makes `helper4`'s gated module compile at all."""
    _base_fixture(root)
    _write(root / "crates/granary-server/src/x.rs", "pub const X: u32 = 9;\n")
    helper_dir = root.parent / f"{root.name}-helper4"
    rel_to_x = os.path.relpath(root / "crates/granary-server/src/x.rs",
                                helper_dir / "src")
    _write(helper_dir / "Cargo.toml",
           '[package]\nname = "helper4"\nversion = "0.0.0"\nedition = "2021"\n\n'
           '[features]\ny = []\n')
    _write(helper_dir / "src/lib.rs",
           '#[cfg(feature = "y")]\n'
           'mod gated {\n'
           f'    include!({json.dumps(rel_to_x)});\n'
           '}\n'
           'pub fn h() -> u32 { 1 }\n')
    server_dir = root / "crates/granary-server"
    rel_to_helper = os.path.relpath(helper_dir, server_dir)
    server_manifest = server_dir / "Cargo.toml"
    _write(server_manifest, server_manifest.read_text() +
           f'\n[dependencies]\nhelper4 = {{ path = {json.dumps(rel_to_helper)} }}\n'
           '\n[features]\nx = ["helper4/y"]\n')
    _write(server_dir / "src/lib.rs",
           (server_dir / "src/lib.rs").read_text() +
           '#[cfg(feature = "x")]\n'
           'pub fn use_helper4() -> u32 { helper4::h() }\n')
    _lock(root, env)


def _row_special_char_symlink(root, env):
    """A member module reached through a SYMLINK whose own name contains
    characters rustc's dep-info writer leaves UNESCAPED (a literal `#` and
    a literal backslash -- verified separately, see
    `_tokenize_makefile_deps`). Unescaping them as if rustc had escaped
    them would corrupt the recorded path into one that names a DIFFERENT,
    nonexistent file rather than the real symlink, so `os.path.realpath`
    could not follow it back into the server's directory -- a silent false
    negative, not merely a cosmetic one."""
    _base_fixture(root)
    _write(root / "crates/granary-server/src/target.rs", "pub const T: u32 = 1;\n")
    link_name = "linked\\#.rs"
    link = root / "crates/a/src" / link_name
    link.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(os.path.join("..", "..", "granary-server", "src", "target.rs"), link)
    _write(root / "crates/a/src/lib.rs",
           (root / "crates/a/src/lib.rs").read_text() +
           '#[path = r"linked\\#.rs"]\n'
           'mod linked;\n')
    _lock(root, env)


def _row_cfg_not_feature_include(root, env):
    """An `include!` compiled only when member `a`'s OWN non-default
    feature `extra` is OFF (`#[cfg(not(feature = "extra"))]`).
    `compute_feature_flags` activates `a/extra` for the FEATURE build, so
    that build alone never compiles this branch -- only the DEFAULT-features
    build (activating nothing) does. A single-build check B (whichever
    features it chose) is blind to whichever of the two directions it did
    not run; running both is what catches this regardless of which way the
    gate's own computed feature set happens to point."""
    _base_fixture(root)
    _write(root / "crates/granary-server/src/x.rs", "pub const X: u32 = 9;\n")
    _write(root / "crates/a/Cargo.toml",
           (root / "crates/a/Cargo.toml").read_text() + '\n[features]\nextra = []\n')
    _write(root / "crates/a/src/lib.rs",
           (root / "crates/a/src/lib.rs").read_text() +
           '#[cfg(not(feature = "extra"))]\n'
           'mod gated {\n'
           '    include!("../../granary-server/src/x.rs");\n'
           '}\n')
    _lock(root, env)


def _row_test_file_named_library(root, env):
    """A CLEAN workspace whose only unusual feature is an integration test
    file named `tests/library_api.rs` -- the compiled test binary is the
    bare executable `deps/library_api-<hash>` (no extension, no real `lib`
    PREFIX at all, only a name that happens to start with those letters).
    Stripping "lib" unconditionally from any `deps/`-directory stem
    starting with it would mangle this into `deps/rary_api-<hash>.d`, a
    name nothing ever writes, and would refuse an otherwise clean
    workspace."""
    _base_fixture(root)
    _write(root / "crates/a/tests/library_api.rs",
           "#[test]\nfn it_works() {\n    assert!(true);\n}\n")
    _lock(root, env)


# ---- rows 26-34: check C, the simulator kept out of production graphs

def _append(path, text):
    _write(path, pathlib.Path(path).read_text() + text)


def _row_sim_normal_dep_of(crate):
    def build(root, env):
        _base_fixture(root)
        _append(root / f"crates/{crate}/Cargo.toml",
                '\n[dependencies]\ngranary-sim = { path = "../granary-sim" }\n')
        _lock(root, env)
    return build


def _row_sim_transitive(root, env):
    """cli -> a -> granary-sim, every edge normal."""
    _base_fixture(root)
    _append(root / "crates/granary-cli/Cargo.toml",
            '\n[dependencies]\na = { path = "../a" }\n')
    _append(root / "crates/a/Cargo.toml",
            '\n[dependencies]\ngranary-sim = { path = "../granary-sim" }\n')
    _lock(root, env)


def _row_sim_optional_feature(root, env):
    """An optional normal edge, on only behind a cli feature."""
    _base_fixture(root)
    _append(root / "crates/granary-cli/Cargo.toml",
            '\n[features]\nsim = ["dep:granary-sim"]\n\n[dependencies]\n'
            'granary-sim = { path = "../granary-sim", optional = true }\n')
    _lock(root, env)


def _row_sim_dev_dep_of_a_dependency(root, env):
    """cli -> a (normal), a -> granary-sim (dev only): not reached."""
    _base_fixture(root)
    _append(root / "crates/granary-cli/Cargo.toml",
            '\n[dependencies]\na = { path = "../a" }\n')
    _append(root / "crates/a/Cargo.toml",
            '\n[dev-dependencies]\ngranary-sim = { path = "../granary-sim" }\n')
    _lock(root, env)


def _row_without(crate):
    def build(root, env):
        _base_fixture(root)
        if crate == "granary-sim":
            # The cli's dev edge onto it goes with it.
            _write(root / "crates/granary-cli/Cargo.toml",
                   '[package]\nname = "granary-cli"\nversion = "0.0.0"\n'
                   'edition = "2021"\n')
        shutil.rmtree(root / f"crates/{crate}")
        _lock(root, env)
    return build


def _row_sim_build_dep_of_cli(root, env):
    """cli -> granary-sim as a [build-dependencies] edge, with a build.rs."""
    _base_fixture(root)
    _append(root / "crates/granary-cli/Cargo.toml",
            '\n[build-dependencies]\ngranary-sim = { path = "../granary-sim" }\n')
    _write(root / "crates/granary-cli/build.rs", "fn main() {}\n")
    _lock(root, env)


def _row_sim_build_dep_of_a_dependency(root, env):
    """cli -> a (normal), a -> granary-sim (build): run building the cli."""
    _base_fixture(root)
    _append(root / "crates/granary-cli/Cargo.toml",
            '\n[dependencies]\na = { path = "../a" }\n')
    _append(root / "crates/a/Cargo.toml",
            '\n[build-dependencies]\ngranary-sim = { path = "../granary-sim" }\n')
    _write(root / "crates/a/build.rs", "fn main() {}\n")
    _lock(root, env)


def _check_c_refusal(name):
    """The checker for a row whose gate must refuse because check C cannot
    find `name`: its own refusal text, not any exit-2 diagnostic."""
    want = f"check C: no workspace member named {name!r}"

    def check(proc):
        if want not in proc.stderr:
            return f"no {want!r} in stderr: {proc.stderr!r}"
        return None
    return check


def _check_c_message(proc):
    if "check C:" not in proc.stderr or "granary-sim" not in proc.stderr:
        return f"no check C violation naming granary-sim in stderr: {proc.stderr!r}"
    return None


ROWS = [
    ("1  clean workspace passes, and the success line reports nonzero counts",
     _row_clean, 0, None),
    ("2  a path [dependencies] on the server is refused (check A)",
     _row_dep("dependencies"), 1, None),
    ("3a the same as [dev-dependencies] is refused",
     _row_dep("dev-dependencies"), 1, None),
    ("3b the same as [build-dependencies] is refused",
     _row_dep("build-dependencies"), 1, None),
    ("4  a dependency declared under a RENAMED key is refused",
     _row_renamed_dep, 1, None),
    ("5  include!(concat!(\"granary-\", \"server/...\")) is refused (check B)",
     _row_concat_include, 1, None),
    ("6  #[path = \"../../granary-server/...\"] mod x; is refused",
     _row_path_attr, 1, None),
    ("7  a member source file that is a SYMLINK into the server is refused",
     _row_symlink, 1, None),
    ("8  include_str! of a server file via an escaped string literal is refused",
     _row_escaped_include_str, 1, None),
    ("9  the server including its OWN files passes (exempt from check B)",
     _row_server_self_include, 0, None),
    ("10a no server package in the workspace refuses the gate",
     _row_no_server, 2, None),
    ("10b a workspace whose only member is the server refuses the gate",
     _row_server_only, 2, None),
    ("11 a planted STALE .d file naming a server path is ignored",
     _row_stale_dep_info, 0, None),
    ("12 cargo itself failing (bad TOML) refuses the gate",
     _row_cargo_failure, 2, None),
    ("13 an optional dependency behind an off-by-default feature is refused "
     "only with --all-features",
     _row_optional_feature_dep, 1, None),
    ("14 TRANSITIVE reachability through a non-member path crate is refused",
     _row_transitive_reachability, 1, None),
    ("15 a stale generic custom-build .d must not shadow the exact one",
     _row_stale_generic_custom_build, 1, None),
    ("16 a case-INSENSITIVE spelling of the server's directory is refused",
     _row_case_insensitive_include, 1, None),
    ("17 a trailing-space dependency path survives tokenizing intact",
     _row_trailing_space_dep_info, 1, _check_trailing_space_message),
    ("18 an excluded (non-member) local path crate that includes a server "
     "file, with no dependency edge anywhere, is refused",
     _row_excluded_path_crate_includes_server, 1, None),
    ("19 an include! behind a non-default feature is refused",
     _row_feature_gated_include, 1, None),
    ("20 a [[bin]] gated by required-features that includes a server file "
     "is refused",
     _row_required_features_gated_bin, 1, None),
    ("21 an OPTIONAL local path dep pulled in only by a non-default "
     "feature is examined",
     _row_optional_local_path_dep_via_feature, 1, None),
    ("22 a SERVER feature enabling a non-member helper's feature is "
     "activated (server itself stays exempt)",
     _row_server_feature_enables_helper, 1, None),
    ("23 a symlink named with a literal '#' and backslash survives "
     "tokenizing intact",
     _row_special_char_symlink, 1, None),
    ("24 an include! compiled only when a member's own feature is OFF "
     "(#[cfg(not(feature))]) is refused by the default-features build",
     _row_cfg_not_feature_include, 1, None),
    ("25 an integration test file named tests/library_api.rs passes on a "
     "clean workspace",
     _row_test_file_named_library, 0, None),
    ("26 granary-sim as a normal [dependencies] of granary-cli is refused "
     "(check C)",
     _row_sim_normal_dep_of("granary-cli"), 1, _check_c_message),
    ("27 granary-sim as a normal [dependencies] of the server is refused",
     _row_sim_normal_dep_of("granary-server"), 1, _check_c_message),
    ("28 granary-sim reached TRANSITIVELY over normal edges (cli -> a -> sim) "
     "is refused",
     _row_sim_transitive, 1, _check_c_message),
    ("29 granary-sim as an OPTIONAL normal dependency behind a cli feature is "
     "refused (--all-features)",
     _row_sim_optional_feature, 1, _check_c_message),
    ("30 a dependency's own dev-dependency on granary-sim is not followed "
     "(cli -> a normal, a -> sim dev) and passes",
     _row_sim_dev_dep_of_a_dependency, 0, None),
    ("31 no granary-sim member refuses the gate",
     _row_without("granary-sim"), 2, _check_c_refusal("granary-sim")),
    ("32 no granary-cli member refuses the gate",
     _row_without("granary-cli"), 2, _check_c_refusal("granary-cli")),
    ("33 granary-sim as a [build-dependencies] of granary-cli is refused",
     _row_sim_build_dep_of_cli, 1, _check_c_message),
    ("34 granary-sim as a build-dependency of a crate the cli links is "
     "refused (cli -> a normal, a -> sim build)",
     _row_sim_build_dep_of_a_dependency, 1, _check_c_message),
]


def _generic_diagnostics_problem(proc, want):
    """An exit code that merely MATCHES `want` is not proof of a controlled
    refusal: an uncaught Python exception also exits 1 (CPython's default
    for a top-level exception), which is indistinguishable from a genuine
    violation by exit code alone -- and if it happened to strike inside the
    exit-2 refusal path, or even the exit-0 success path, it would exit
    with whatever CPython gives an uncaught exception, not necessarily the
    same code either, but the point stands for every want: a crash must
    never be read as a legitimate outcome. Every row is checked for the
    diagnostic ITS OWN exit code promises, and for the absence of a
    traceback, regardless of whether the row also carries its own
    `extra_check`."""
    combined = proc.stdout + proc.stderr
    if "Traceback (most recent call last):" in combined:
        return ("the process printed a Python traceback -- an uncaught "
                "exception, not a controlled refusal")
    if want == 1 and "violation(s):" not in proc.stderr:
        return "exit 1 but no 'violation(s):' diagnostic in stderr"
    if want == 2 and "COULD NOT RUN" not in proc.stderr:
        return "exit 2 but no 'COULD NOT RUN' diagnostic in stderr"
    if want == 0 and "ALL GREEN" not in proc.stdout:
        return "exit 0 but no 'ALL GREEN' in stdout"
    return None


def self_test():
    # Declared at the top, not only where it is reassigned, because a
    # name this function already CALLS earlier (a plain global read) and
    # later ASSIGNS (to install and restore a stub -- see
    # combined-round-catches-joint-fips) must be `global` for the WHOLE
    # function; Python treats the two as contradictory otherwise.
    global cargo_metadata
    tmproot = tempfile.mkdtemp(prefix="check-licence-resolved-selftest-")
    rc = 0
    row1_stdout = None
    try:
        for i, row in enumerate(ROWS):
            name, builder, want = row[0], row[1], row[2]
            extra_check = row[3] if len(row) > 3 else None
            fixture = pathlib.Path(tmproot) / f"r{i}"
            fixture.mkdir(parents=True)
            env = _env_for(fixture)
            try:
                builder(fixture, env)
            except _SkipRow as e:
                print(f"  [skip] {name}: {e}")
                continue
            except Exception as e:  # noqa: BLE001 -- a fixture that cannot
                # build is reported as its own failure, not a crash of the
                # whole self-test.
                print(f"  [FAIL] {name}: fixture setup raised {e!r}")
                rc = 2
                continue
            proc = _invoke(fixture, env)
            if proc.returncode != want:
                print(f"  [FAIL] {name}: wanted exit {want}, got "
                      f"{proc.returncode}\n         stdout: "
                      f"{proc.stdout.strip()[-2000:]}\n         stderr: "
                      f"{proc.stderr.strip()[-2000:]}")
                rc = 2
                continue
            generic_problem = _generic_diagnostics_problem(proc, want)
            if generic_problem is not None:
                print(f"  [FAIL] {name}: exit code ok ({proc.returncode}) "
                      f"but: {generic_problem}\n         stdout: "
                      f"{proc.stdout.strip()[-2000:]}\n         stderr: "
                      f"{proc.stderr.strip()[-2000:]}")
                rc = 2
                continue
            if extra_check is not None:
                problem = extra_check(proc)
                if problem is not None:
                    print(f"  [FAIL] {name}: exit code ok ({proc.returncode}) "
                          f"but: {problem}")
                    rc = 2
                    continue
            print(f"  [ok ] {name} (exit {proc.returncode})")
            if i == 0:
                row1_stdout = proc.stdout

        if row1_stdout is not None:
            nums = re.findall(r"(\d+) artifact\(s\)", row1_stdout)
            resolved = re.findall(r"resolved (\d+) dependency", row1_stdout)
            if not nums or int(nums[0]) == 0 or not resolved or int(resolved[0]) == 0:
                print(f"  [FAIL] row 1's success line does not report nonzero "
                      f"coverage counts: {row1_stdout.strip()!r}")
                rc = 2
            else:
                print(f"  [ok ] row 1's success line reports nonzero coverage "
                      f"({nums[0]} artifact(s), {resolved[0]} dependency "
                      f"path(s))")
        elif rc == 0:
            print("  [FAIL] row 1 never produced stdout to check coverage "
                  "reporting against")
            rc = 2

        # ---- direct unit checks: a construction no real `cargo` invocation
        # can produce (a workspace member cargo itself refuses to build with
        # no resolve node reachable at all; an internal invariant of a
        # well-formed dep-info) is tested by calling the functions directly
        # with synthetic input, the same way check-bench-results-
        # classification.py and check-citations.py test their own refusals
        # against synthetic data rather than only through a real run.
        print("-- direct unit checks (no `cargo` invocation) --")

        # missing-node: a workspace member with no resolve node at all.
        synthetic_meta = {
            "packages": [{"id": "srv", "name": "granary-server"},
                         {"id": "m1", "name": "a"}],
            "resolve": {"nodes": [{"id": "srv", "deps": []}]},  # "m1" absent
        }
        a_result = check_a(synthetic_meta, "srv", {"m1"},
                            {"srv": "granary-server", "m1": "a"})
        if a_result.ok:
            print("  [FAIL] missing-node: check_a did not refuse a workspace "
                  "member with no resolve node")
            rc = 2
        else:
            print("  [ok ] missing-node: check_a refuses a workspace member with "
                  "no resolve node")

        # untyped-edge: check C refuses an edge whose kind it cannot tell,
        # follows normal and build edges, and skips a dev-only one.
        untyped = {"resolve": {"nodes": [
            {"id": "cli", "deps": [{"pkg": "sim"}]},
            {"id": "sim", "deps": []}]}}
        typed = {"resolve": {"nodes": [
            {"id": "cli", "deps": [
                {"pkg": "a", "dep_kinds": [{"kind": None, "target": None}]},
                {"pkg": "sim", "dep_kinds": [{"kind": "dev", "target": None}]},
                {"pkg": "gen", "dep_kinds": [{"kind": "build", "target": None}]}]},
            {"id": "gen", "deps": []},
            {"id": "a", "deps": [
                {"pkg": "sim", "dep_kinds": [{"kind": "dev", "target": None},
                                             {"kind": None, "target": None}]}]},
            {"id": "sim", "deps": []}]}}
        untyped_adj, untyped_reason = _shipped_adjacency(untyped)
        typed_adj, _ = _shipped_adjacency(typed)
        if untyped_adj is not None or not untyped_reason:
            print("  [FAIL] untyped-edge: _shipped_adjacency accepted an edge "
                  "with no dep_kinds")
            rc = 2
        elif typed_adj != {"cli": ["a", "gen"], "a": ["sim"], "gen": [],
                           "sim": []}:
            print(f"  [FAIL] untyped-edge: the shipped-edge adjacency is wrong: "
                  f"{typed_adj!r}")
            rc = 2
        else:
            print("  [ok ] untyped-edge: check C refuses an edge of unknown "
                  "kind, follows an edge that is normal or build under any "
                  "of its kinds, and skips a dev-only one")

        # A REAL, findable dep-info for a synthetic member "m1", shared by
        # bad-json-line and member-with-no-artifact below, so each test
        # isolates its OWN failure mode rather than tripping the
        # pre-existing "zero artifacts examined" catch-all by coincidence.
        unit_dir = pathlib.Path(tmproot) / "unit-4"
        deps_dir = unit_dir / "deps"
        deps_dir.mkdir(parents=True)
        fake_artifact = deps_dir / "libm1-aaaa1111.rmeta"
        fake_artifact.write_text("x")
        fake_dep_info = deps_dir / "m1-aaaa1111.d"
        fake_dep_info.write_text(f"{fake_dep_info}: src/lib.rs\n")
        fake_msg = json.dumps({"reason": "compiler-artifact", "package_id": "m1",
                                "target": {"name": "m1", "kind": ["lib"]},
                                "filenames": [str(fake_artifact)]})

        # bad-json-line: an invalid JSON line ALONGSIDE an otherwise-complete,
        # valid message. A lone bad line with nothing else would still be
        # caught by the pre-existing "zero artifacts examined" catch-all
        # regardless of whether the per-line JSON check fires at all, so
        # that construction cannot tell the two apart -- pairing the bad
        # line with a message that would OTHERWISE let every member
        # succeed is what isolates the per-line validation: read strictly,
        # this refuses on the first line; skipping a bad line instead lets
        # the rest of the (valid) processing complete and reports green.
        b_bad_json = _process_build_output(
            ["not json at all", fake_msg], "srv", {"m1"}, {"m1"},
            {"srv": "granary-server", "m1": "a"}, unit_dir)
        if b_bad_json.ok:
            print("  [FAIL] bad-json-line: _process_build_output did not refuse "
                  "an invalid JSON line sitting alongside an otherwise-"
                  "complete, valid build")
            rc = 2
        else:
            print("  [ok ] bad-json-line: _process_build_output refuses an "
                  "invalid JSON line even when every member would "
                  "otherwise be complete")

        # member-with-no-artifact: a workspace member that produced no compiler-artifact --
        # isolated from the same catch-all by giving ONE other member (m1)
        # the SAME real, findable dep-info so artifacts_examined is
        # nonzero, leaving the missing member's absence as the only
        # possible cause of a refusal.
        #
        # THE NAME IS DELIBERATELY DISTINCTIVE, and the assertion checks it
        # in the EXACT delimited context the diagnostic prints it in
        # (`"... verified nothing about them: " + name`) -- a single
        # letter like "b" is a substring of ordinary boilerplate words in
        # the same sentence ("cargo **b**uild", "check **B**"), so a check
        # of the form `"b" in reason` passes whether or not the missing
        # member is actually NAMED at all -- a one-letter id would let
        # such an assertion succeed by coincidence rather than by
        # verifying the name landed in the diagnostic. A one-letter id is
        # used for the id itself
        # (irrelevant to what gets checked) but its NAME is not.
        b_missing = _process_build_output(
            [fake_msg], "srv", {"m1", "m2"}, {"m1", "m2"},
            {"srv": "granary-server", "m1": "a", "m2": "quokka-member"}, unit_dir)
        expected = "about them: quokka-member"
        if b_missing.ok or expected not in b_missing.reason:
            print(f"  [FAIL] member-with-no-artifact: expected {expected!r} in "
                  f"the refusal, got ok={b_missing.ok} reason="
                  f"{b_missing.reason!r}")
            rc = 2
        elif expected in b_bad_json.reason:
            # THE CONTROL FOR THE CONTROL: an UNRELATED refusal (the bad
            # JSON line above, which names no member at all) must NOT
            # satisfy the same check -- if it did, the check would be
            # trivially satisfiable by any refusal's boilerplate and would
            # prove nothing about naming the RIGHT member.
            print(f"  [FAIL] member-with-no-artifact: {expected!r} also "
                  f"appears in an UNRELATED refusal (bad-json-line) -- the "
                  f"check does not discriminate")
            rc = 2
        else:
            print("  [ok ] member-with-no-artifact: _process_build_output names "
                  "the missing member exactly, in its delimited context, and "
                  "an unrelated refusal does not satisfy the same check")

        # colon-less-line: a non-comment, non-blank line with no ':' separator.
        # ISOLATED from the zero-deps guard below: a fixture with ONLY a
        # colon-less line and nothing else would still raise DepInfoError
        # if the colon-less check were disabled entirely -- `out` would
        # stay empty and the SEPARATE "parsed ZERO dependency paths" guard
        # would fire instead, so this row would report a pass whether or
        # not the colon-less rejection itself does anything. One VALID
        # dependency line is added so `out` is non-empty if the colon-less
        # line is (wrongly) skipped rather than rejected -- only then does
        # this check exercise the colon-less rejection specifically.
        bad_dep_info = pathlib.Path(tmproot) / "bad.d"
        bad_dep_info.write_text(
            "target: valid/dep.rs\nthis line has no colon at all\n")
        try:
            parse_dep_info(str(bad_dep_info))
            print("  [FAIL] colon-less-line: parse_dep_info did not refuse a "
                  "colon-less line (a valid line alongside it means the "
                  "zero-deps guard cannot be masking this)")
            rc = 2
        except DepInfoError:
            print("  [ok ] colon-less-line: parse_dep_info refuses a colon-less "
                  "line even when a valid line elsewhere would otherwise let "
                  "it return successfully")

        # zero-deps: a dep-info that parses to ZERO dependency paths.
        empty_dep_info = pathlib.Path(tmproot) / "empty.d"
        empty_dep_info.write_text("# just a comment\n\n")
        try:
            parse_dep_info(str(empty_dep_info))
            print("  [FAIL] zero-deps: parse_dep_info did not refuse a "
                  "dep-info with zero dependency paths")
            rc = 2
        except DepInfoError:
            print("  [ok ] zero-deps: parse_dep_info refuses zero dependency "
                  "paths")

        # The four checks below exercise `compute_feature_flags` against
        # REAL, small, OFFLINE cargo workspaces (built the same way the
        # subprocess ROWS above build theirs) rather than synthetic
        # metadata dicts: the mechanism runs actual `cargo metadata`
        # subprocesses and asks CARGO whether a candidate reaches `fips`,
        # and there is no hand-rolled graph walk for synthetic input to
        # exercise instead. Each fixture calls `cargo_metadata` and
        # `compute_feature_flags` directly (no need to spawn a whole
        # second gate-script subprocess) against a fixture built with the
        # same `_write`/`_lock` helpers the rows use.

        def _ff_ids(meta_all):
            return {p["name"]: p["id"] for p in meta_all.get("packages", [])}

        # dep-default-reaches-fips: `secure = ["dep:crypto"]` turns
        # `crypto` on with its OWN default features active (Cargo's
        # ordinary semantics: turning a dependency on turns its defaults
        # on with it, unless the edge says otherwise) -- `crypto`'s
        # `default = ["fips"]` means enabling `secure` activates `fips`
        # transitively, with NO hand-written closure walk deciding that:
        # `cargo metadata --features a/secure` is asked directly, and its
        # own resolve reports `fips` activated on `crypto`'s node.
        #
        # `crypto` sits OUTSIDE the fixture's workspace root (a SIBLING
        # directory, like the two-version fixture below), not merely
        # excluded from `members` -- VERIFIED this matters: a path crate
        # that IS a workspace member (matched by this fixture's own
        # `crates/*` glob) gets its OWN default features activated simply
        # by being one of the workspace's default members, REGARDLESS of
        # what any depending edge's `default-features` setting says, since
        # a bare `cargo metadata` (no `-p` filter) resolves every default
        # member as its own root. An ordinary dependency has no such
        # self-activation; only what an edge actually requests reaches it
        # -- the shape every REAL fips-gated dependency in this workspace
        # (`aws-lc-rs`, `rustls`) actually has, being external crates, not
        # workspace members.
        ff1_dir = pathlib.Path(tmproot) / "ff-dep-default"
        ff1_ext = pathlib.Path(tmproot) / "ff-dep-default-external"
        try:
            _base_fixture(ff1_dir)
            ff1_env = _env_for(ff1_dir)
            _write(ff1_ext / "crypto/Cargo.toml",
                   '[package]\nname = "crypto"\nversion = "0.0.0"\n'
                   'edition = "2021"\n\n'
                   '[features]\ndefault = ["fips"]\nfips = []\n')
            _write(ff1_ext / "crypto/src/lib.rs", "pub fn c() -> u32 { 0 }\n")
            _write(ff1_dir / "crates/a/Cargo.toml",
                   (ff1_dir / "crates/a/Cargo.toml").read_text() +
                   '\n[features]\nsecure = ["dep:crypto"]\n\n'
                   '[dependencies]\n'
                   f'crypto = {{ path = {str(ff1_ext / "crypto")!r}, '
                   f'optional = true }}\n')
            _lock(ff1_dir, ff1_env)
            meta1, err1 = cargo_metadata(ff1_dir, all_features=True)
            if err1:
                raise RuntimeError(f"cargo metadata failed: {err1}")
            ids1 = _ff_ids(meta1)
            ff1 = compute_feature_flags(ff1_dir, meta1, {ids1["a"]},
                                         {v: k for k, v in ids1.items()})
        except Exception as e:  # noqa: BLE001
            print(f"  [FAIL] dep-default-reaches-fips: fixture/probe raised {e!r}")
            rc = 2
        else:
            if not ff1.ok:
                print(f"  [FAIL] dep-default-reaches-fips: compute_feature_flags "
                      f"refused unexpectedly: {ff1.reason}")
                rc = 2
            elif "a/secure" in ff1.flags:
                print(f"  [FAIL] dep-default-reaches-fips: 'a/secure' turns on "
                      f"crypto's default features (which reach fips) and "
                      f"should be EXCLUDED; got {ff1.flags}")
                rc = 2
            elif not any("a/secure" in x for x in ff1.excluded):
                print(f"  [FAIL] dep-default-reaches-fips: 'a/secure' was "
                      f"excluded but not REPORTED in `excluded`: {ff1.excluded}")
                rc = 2
            else:
                # Also proves the exclusion is REPORTED, not just computed,
                # end to end: the WHOLE gate, run for real against this
                # same fixture, must print the exclusion on its OWN
                # successful (exit 0) run, not just return it from the
                # internal function.
                real_proc = _invoke(ff1_dir, ff1_env)
                if real_proc.returncode != 0:
                    print(f"  [FAIL] dep-default-reaches-fips: the real gate "
                          f"exited {real_proc.returncode}, expected 0: "
                          f"{real_proc.stdout}{real_proc.stderr}")
                    rc = 2
                elif "a/secure" not in real_proc.stdout or \
                        "excluded" not in real_proc.stdout.lower():
                    print(f"  [FAIL] dep-default-reaches-fips: the real gate's "
                          f"stdout does not plainly report the exclusion: "
                          f"{real_proc.stdout!r}")
                    rc = 2
                else:
                    print("  [ok ] dep-default-reaches-fips: a feature that "
                          "turns on a dependency's default features (which "
                          "reach fips) is excluded, and cargo's own resolve "
                          "-- not a hand walk -- is what says so; the real "
                          "gate reports the exclusion on a clean run")

        # dep-no-default-features-included: the SAME shape (crypto again
        # OUTSIDE the workspace root, for the same reason as above), but
        # the manifest edge sets `default-features = false` -- `crypto`'s
        # `default` (and so its `fips`) is never activated merely by
        # turning `dep:crypto` on, so `secure` reaches nothing and must be
        # INCLUDED.
        ff2_dir = pathlib.Path(tmproot) / "ff-dep-no-default"
        ff2_ext = pathlib.Path(tmproot) / "ff-dep-no-default-external"
        try:
            _base_fixture(ff2_dir)
            ff2_env = _env_for(ff2_dir)
            _write(ff2_ext / "crypto/Cargo.toml",
                   '[package]\nname = "crypto"\nversion = "0.0.0"\n'
                   'edition = "2021"\n\n'
                   '[features]\ndefault = ["fips"]\nfips = []\n')
            _write(ff2_ext / "crypto/src/lib.rs", "pub fn c() -> u32 { 0 }\n")
            _write(ff2_dir / "crates/a/Cargo.toml",
                   (ff2_dir / "crates/a/Cargo.toml").read_text() +
                   '\n[features]\nsecure = ["dep:crypto"]\n\n'
                   '[dependencies]\n'
                   f'crypto = {{ path = {str(ff2_ext / "crypto")!r}, '
                   f'optional = true, default-features = false }}\n')
            _lock(ff2_dir, ff2_env)
            meta2, err2 = cargo_metadata(ff2_dir, all_features=True)
            if err2:
                raise RuntimeError(f"cargo metadata failed: {err2}")
            ids2 = _ff_ids(meta2)
            ff2 = compute_feature_flags(ff2_dir, meta2, {ids2["a"]},
                                         {v: k for k, v in ids2.items()})
        except Exception as e:  # noqa: BLE001
            print(f"  [FAIL] dep-no-default-features-included: fixture/probe "
                  f"raised {e!r}")
            rc = 2
        else:
            if not ff2.ok:
                print(f"  [FAIL] dep-no-default-features-included: "
                      f"compute_feature_flags refused unexpectedly: "
                      f"{ff2.reason}")
                rc = 2
            elif "a/secure" not in ff2.flags:
                print(f"  [FAIL] dep-no-default-features-included: "
                      f"default-features=false means dep:crypto never "
                      f"activates crypto's default (or its fips), so "
                      f"'a/secure' should be INCLUDED; got {ff2.flags}, "
                      f"excluded {ff2.excluded}")
                rc = 2
            else:
                print("  [ok ] dep-no-default-features-included: with "
                      "default-features=false on the edge, turning on the "
                      "dependency alone never reaches its fips-gated "
                      "default, so the feature is included")

        # renamed-second-version-excluded: Cargo allows depending on TWO
        # versions of ONE crate at once when at least one is renamed --
        # tested against a REAL two-version graph by putting both `foo`
        # crates OUTSIDE the workspace root (a SIBLING directory): two
        # same-named PATH crates INSIDE one workspace's own directory tree
        # refuse to resolve at all ("two packages named `foo` in this
        # workspace", VERIFIED), but two same-named path crates that
        # merely sit outside the workspace root and are reached only as
        # dependencies resolve exactly like two registry versions would,
        # fully offline. `secure` reaches `fips` ONLY through the RENAMED
        # `foo_v1` (resolving to v1's `enables_fips`); `foo_v2` (the
        # unrelated v2, plain) is present only to make the correlation
        # non-trivial. Cargo resolves the alias itself -- this gate never
        # sees "foo_v1" as anything but a `--features` STRING it handed to
        # cargo, so it does not need to know two versions are involved at
        # all.
        ff3_dir = pathlib.Path(tmproot) / "ff-two-versions"
        ff3_ext = pathlib.Path(tmproot) / "ff-two-versions-external"
        try:
            _base_fixture(ff3_dir)
            ff3_env = _env_for(ff3_dir)
            _write(ff3_ext / "foo1/Cargo.toml",
                   '[package]\nname = "foo"\nversion = "1.0.0"\n'
                   'edition = "2021"\n\n'
                   '[features]\nenables_fips = ["fips"]\nfips = []\n')
            _write(ff3_ext / "foo1/src/lib.rs", "pub fn f1() -> u32 { 1 }\n")
            _write(ff3_ext / "foo2/Cargo.toml",
                   '[package]\nname = "foo"\nversion = "2.0.0"\n'
                   'edition = "2021"\n')
            _write(ff3_ext / "foo2/src/lib.rs", "pub fn f2() -> u32 { 2 }\n")
            _write(ff3_dir / "crates/a/Cargo.toml",
                   (ff3_dir / "crates/a/Cargo.toml").read_text() +
                   '\n[features]\nsecure = ["foo_v1/enables_fips"]\n\n'
                   '[dependencies]\n'
                   f'foo_v1 = {{ path = {str(ff3_ext / "foo1")!r}, package = "foo" }}\n'
                   f'foo_v2 = {{ path = {str(ff3_ext / "foo2")!r}, package = "foo" }}\n')
            _lock(ff3_dir, ff3_env)
            meta3, err3 = cargo_metadata(ff3_dir, all_features=True)
            if err3:
                raise RuntimeError(f"cargo metadata failed: {err3}")
            ids3 = _ff_ids(meta3)
            ff3 = compute_feature_flags(ff3_dir, meta3, {ids3["a"]},
                                         {v: k for k, v in ids3.items()})
        except Exception as e:  # noqa: BLE001
            print(f"  [FAIL] renamed-second-version-excluded: fixture/probe "
                  f"raised {e!r}")
            rc = 2
        else:
            if not ff3.ok:
                print(f"  [FAIL] renamed-second-version-excluded: "
                      f"compute_feature_flags refused unexpectedly: "
                      f"{ff3.reason}")
                rc = 2
            elif "a/secure" in ff3.flags:
                print(f"  [FAIL] renamed-second-version-excluded: 'a/secure' "
                      f"reaches fips only via the RENAMED foo_v1 (v1's "
                      f"enables_fips); should be EXCLUDED; got {ff3.flags}")
                rc = 2
            else:
                print("  [ok ] renamed-second-version-excluded: with two "
                      "versions of one crate present, one renamed, cargo's "
                      "own resolution of the rename -- not this gate's -- "
                      "picks the right one to exclude on")

        # hyphenated-name-custom-lib-name-handled: the WORKSPACE MEMBER's
        # own name is hyphenated (`my-member`, used verbatim in the
        # `--features` string this gate constructs), and the dependency it
        # reaches fips through has BOTH a hyphenated crate name
        # (`crypto-core`) and a `[lib] name` override completely unrelated
        # to it (`cryptocorelib`) -- VERIFIED elsewhere in this workspace
        # that a `[lib]` override can make resolve's OWN extern-crate name
        # arbitrary (`md-5` exposes lib `md5`). None of that needs
        # handling here: exclusion is decided by inspecting
        # `resolve.nodes[].features`, which is keyed by PACKAGE id, never
        # by a lib target name, so a `[lib]` override never enters into
        # this gate's own logic at all.
        #
        # `crypto-core` sits OUTSIDE the workspace root, same as
        # `dep-default-reaches-fips` above and for the SAME reason: a path
        # crate that is itself a workspace member activates its own
        # default features regardless of any depending edge, which would
        # make `fips` show up in this fixture's resolve whether or not
        # `secure` reached it at all -- a real demonstration needs the
        # dependency edge to be what actually turns `fips` on.
        ff4_dir = pathlib.Path(tmproot) / "ff-hyphen-libname"
        ff4_ext = pathlib.Path(tmproot) / "ff-hyphen-libname-external"
        try:
            _base_fixture(ff4_dir, with_member=False)
            ff4_env = _env_for(ff4_dir)
            _write(ff4_ext / "crypto-core/Cargo.toml",
                   '[package]\nname = "crypto-core"\nversion = "0.0.0"\n'
                   'edition = "2021"\n\n'
                   '[lib]\nname = "cryptocorelib"\n\n'
                   '[features]\ndefault = ["fips"]\nfips = []\n')
            _write(ff4_ext / "crypto-core/src/lib.rs", "pub fn c() -> u32 { 0 }\n")
            _write(ff4_dir / "crates/my-member/Cargo.toml",
                   '[package]\nname = "my-member"\nversion = "0.0.0"\n'
                   'edition = "2021"\n\n'
                   '[features]\nsecure = ["dep:crypto-core"]\n\n'
                   '[dependencies]\n'
                   f'crypto-core = {{ path = {str(ff4_ext / "crypto-core")!r}, '
                   f'optional = true }}\n')
            _write(ff4_dir / "crates/my-member/src/lib.rs", "pub fn hi() -> u32 { 2 }\n")
            _lock(ff4_dir, ff4_env)
            meta4, err4 = cargo_metadata(ff4_dir, all_features=True)
            if err4:
                raise RuntimeError(f"cargo metadata failed: {err4}")
            ids4 = _ff_ids(meta4)
            ff4 = compute_feature_flags(ff4_dir, meta4, {ids4["my-member"]},
                                         {v: k for k, v in ids4.items()})
        except Exception as e:  # noqa: BLE001
            print(f"  [FAIL] hyphenated-name-custom-lib-name-handled: "
                  f"fixture/probe raised {e!r}")
            rc = 2
        else:
            if not ff4.ok:
                print(f"  [FAIL] hyphenated-name-custom-lib-name-handled: "
                      f"compute_feature_flags refused unexpectedly: "
                      f"{ff4.reason}")
                rc = 2
            elif "my-member/secure" in ff4.flags:
                print(f"  [FAIL] hyphenated-name-custom-lib-name-handled: "
                      f"'my-member/secure' reaches fips through crypto-core's "
                      f"default and should be EXCLUDED; got {ff4.flags}")
                rc = 2
            else:
                print("  [ok ] hyphenated-name-custom-lib-name-handled: a "
                      "hyphenated member name and a dependency with a custom "
                      "[lib] name are both handled by cargo's own "
                      "resolution, with no special-casing in this gate")

        # baseline-fips-safe-feature-survives: member `a` has a MANDATORY
        # (non-optional, always present) dependency on `crypto`, whose OWN
        # `default = ["fips"]` means `crypto`'s node already reports
        # `fips` active under PLAIN `cargo metadata`, no extra features at
        # all -- a baseline that has nothing to do with any candidate.
        # `a` also declares an empty, genuinely no-op feature `safe = []`.
        # Without the baseline diff, probing `a/safe` would see the SAME
        # pre-existing `crypto` fips node and wrongly exclude `safe`
        # (MUTANT: drop the baseline -> `safe` is excluded -> this check
        # goes red). `a` ALSO declares `unsafe_feat = ["dep:crypto2"]`,
        # an OPTIONAL dependency on a SEPARATE crate with the same
        # `default = ["fips"]` shape -- crypto2 is invisible under the
        # baseline (optional, off by default), so turning `unsafe_feat`
        # on genuinely ADDS a new fips-active node, and must still be
        # excluded: the baseline diff must not become a blanket pass.
        ff5_dir = pathlib.Path(tmproot) / "ff-baseline-fips"
        ff5_ext = pathlib.Path(tmproot) / "ff-baseline-fips-external"
        try:
            _base_fixture(ff5_dir)
            ff5_env = _env_for(ff5_dir)
            _write(ff5_ext / "crypto/Cargo.toml",
                   '[package]\nname = "crypto"\nversion = "0.0.0"\n'
                   'edition = "2021"\n\n'
                   '[features]\ndefault = ["fips"]\nfips = []\n')
            _write(ff5_ext / "crypto/src/lib.rs", "pub fn c() -> u32 { 0 }\n")
            _write(ff5_ext / "crypto2/Cargo.toml",
                   '[package]\nname = "crypto2"\nversion = "0.0.0"\n'
                   'edition = "2021"\n\n'
                   '[features]\ndefault = ["fips"]\nfips = []\n')
            _write(ff5_ext / "crypto2/src/lib.rs", "pub fn c2() -> u32 { 0 }\n")
            _write(ff5_dir / "crates/a/Cargo.toml",
                   (ff5_dir / "crates/a/Cargo.toml").read_text() +
                   '\n[features]\nsafe = []\nunsafe_feat = ["dep:crypto2"]\n\n'
                   '[dependencies]\n'
                   f'crypto = {{ path = {str(ff5_ext / "crypto")!r} }}\n'
                   f'crypto2 = {{ path = {str(ff5_ext / "crypto2")!r}, '
                   f'optional = true }}\n')
            _lock(ff5_dir, ff5_env)
            meta5, err5 = cargo_metadata(ff5_dir, all_features=True)
            if err5:
                raise RuntimeError(f"cargo metadata failed: {err5}")
            ids5 = _ff_ids(meta5)
            ff5 = compute_feature_flags(ff5_dir, meta5, {ids5["a"]},
                                         {v: k for k, v in ids5.items()})
        except Exception as e:  # noqa: BLE001
            print(f"  [FAIL] baseline-fips-safe-feature-survives: "
                  f"fixture/probe raised {e!r}")
            rc = 2
        else:
            if not ff5.ok:
                print(f"  [FAIL] baseline-fips-safe-feature-survives: "
                      f"compute_feature_flags refused unexpectedly: "
                      f"{ff5.reason}")
                rc = 2
            elif "a/safe" not in ff5.flags:
                print(f"  [FAIL] baseline-fips-safe-feature-survives: "
                      f"'a/safe' does nothing at all and must SURVIVE "
                      f"despite crypto's baseline-active fips; got "
                      f"flags={ff5.flags}, excluded={ff5.excluded}")
                rc = 2
            elif "a/unsafe_feat" in ff5.flags:
                print(f"  [FAIL] baseline-fips-safe-feature-survives: "
                      f"'a/unsafe_feat' adds a NEW fips-active node "
                      f"(crypto2) beyond the baseline and should still be "
                      f"EXCLUDED; got flags={ff5.flags}")
                rc = 2
            else:
                print("  [ok ] baseline-fips-safe-feature-survives: a "
                      "workspace whose DEFAULT build already has fips "
                      "active on some node still lets a genuinely safe "
                      "feature survive, while a feature that ADDS a new "
                      "fips-active node is still excluded")

        # combined-round-catches-joint-fips: round 2 (the COMBINED probe)
        # must still catch two candidates that are each individually SAFE
        # but jointly activate fips. A genuine "safe alone, unsafe
        # together" graph is not constructible from plain OFFLINE path
        # dependencies -- Cargo's own feature activation, and a package's
        # default-features setting, are each a monotonic UNION across
        # every edge that reaches them: two independently-insufficient
        # contributions (an edge that requests nothing extra, unified with
        # another edge that ALSO requests nothing extra) can only unify to
        # "still insufficient", never synthesize a NEW activation neither
        # side named -- that would need registry semver-range unification
        # picking a DIFFERENT resolved version only when both requirements
        # are simultaneously in force, which a fixed-version path
        # dependency cannot fabricate offline. Proven instead the way this
        # file already tests a shape no real `cargo` invocation can
        # produce (`missing-node`, `bad-json-line`, ...): a STUB stands in
        # for `cargo_metadata`, reporting each candidate SAFE alone and
        # UNSAFE only when probed together, confirming
        # `compute_feature_flags` still refuses rather than reporting the
        # individually-clean set as complete.
        real_cargo_metadata = cargo_metadata

        def _joint_fips_stub(root, all_features=False, features=None):
            feats = tuple(sorted(features or []))
            if feats == ():
                # The BASELINE call `compute_feature_flags` makes first --
                # an empty, fips-free default resolve, so "added relative
                # to baseline" reduces to "fips present at all" for this
                # stub's other two branches below.
                return {"resolve": {"nodes": [
                    {"id": "a", "features": []}]}}, None
            if feats in (("a/x",), ("a/y",)):
                return {"resolve": {"nodes": [
                    {"id": "a", "features": list(feats)}]}}, None
            if feats == ("a/x", "a/y"):
                return {"resolve": {"nodes": [
                    {"id": "a", "features": ["x", "y", "fips"]}]}}, None
            return real_cargo_metadata(root, all_features=all_features,
                                        features=features)

        cargo_metadata = _joint_fips_stub
        try:
            joint_meta_all = {"packages": [
                {"id": "a", "name": "a", "features": {"x": [], "y": []}}]}
            ff_joint = compute_feature_flags(
                pathlib.Path(tmproot) / "unused-joint-root", joint_meta_all,
                {"a"}, {"a": "a"})
        finally:
            cargo_metadata = real_cargo_metadata

        if ff_joint.ok:
            print(f"  [FAIL] combined-round-catches-joint-fips: two "
                  f"candidates each safe ALONE but unsafe TOGETHER should "
                  f"refuse (ok=False); got ok=True, flags={ff_joint.flags}")
            rc = 2
        elif "a/x" not in ff_joint.reason or "a/y" not in ff_joint.reason:
            print(f"  [FAIL] combined-round-catches-joint-fips: refused, "
                  f"but the reason does not name both surviving candidates "
                  f"that jointly triggered it: {ff_joint.reason!r}")
            rc = 2
        else:
            print("  [ok ] combined-round-catches-joint-fips: two "
                  "candidates each safe alone are still caught when the "
                  "COMBINED probe shows them jointly activating fips")

        # missing-custom-build-dep-info: the exact, hash-qualified dep-info
        # for a `custom-build` artifact is ABSENT, and only an INNOCENT
        # generic-named `build-script-build.d` sits beside it -- a real
        # `cargo build` cannot be made to reproduce this reliably (it
        # regenerates a deleted output on its very next invocation, even
        # with unchanged inputs -- MEASURED separately), so it is proven
        # with a synthetic `compiler-artifact` message instead. A fallback
        # would read the innocent file and report this artifact CLEAN,
        # hiding whatever the missing exact file actually recorded; without
        # one, `dep_info_candidates` yields no existing candidate at all
        # and `_process_build_output` must refuse rather than guess.
        cb_dir = pathlib.Path(tmproot) / "custom-build-missing"
        build_subdir = cb_dir / "target/debug/build/a-deadbeefdeadbeef"
        build_subdir.mkdir(parents=True)
        (build_subdir / "build-script-build.d").write_text(
            f"{build_subdir / 'build-script-build'}: {cb_dir / 'crates/a/build.rs'}\n")
        cb_msg = json.dumps({
            "reason": "compiler-artifact", "package_id": "m1",
            "target": {"name": "build-script-build", "kind": ["custom-build"]},
            "filenames": [str(build_subdir / "build-script-build")],
        })
        cb_result = _process_build_output(
            [cb_msg], "srv", {"m1"}, {"m1"}, {"srv": "granary-server", "m1": "a"},
            cb_dir)
        if cb_result.ok:
            print("  [FAIL] missing-custom-build-dep-info: "
                  "_process_build_output did not refuse when the exact "
                  "dep-info is absent and only an innocent generic-named "
                  "file exists")
            rc = 2
        else:
            print("  [ok ] missing-custom-build-dep-info: "
                  "_process_build_output refuses rather than falling back "
                  "to an innocent generic-named file")

        # dep-info-path-collision: two DIFFERENT compiler-artifact messages
        # (different package ids) resolving to the SAME dep-info path must
        # refuse -- reading one file as if it described two distinct units
        # is exactly the "output filename collision" hazard cargo itself
        # warns about (see `_run_build_pass`'s stderr scan for the real,
        # cargo-reported half of this); this proves the SAME protection
        # exists at the level this gate can construct without a real
        # collision.
        coll_dir = pathlib.Path(tmproot) / "dep-info-collision"
        coll_deps = coll_dir / "deps"
        coll_deps.mkdir(parents=True)
        shared_artifact = coll_deps / "libshared-aaaa1111.rmeta"
        shared_artifact.write_text("x")
        shared_dep_info = coll_deps / "shared-aaaa1111.d"
        shared_dep_info.write_text(f"{shared_dep_info}: src/lib.rs\n")
        coll_msg_a = json.dumps({"reason": "compiler-artifact", "package_id": "m1",
                                  "target": {"name": "shared", "kind": ["lib"]},
                                  "filenames": [str(shared_artifact)]})
        coll_msg_b = json.dumps({"reason": "compiler-artifact", "package_id": "m2",
                                  "target": {"name": "shared", "kind": ["lib"]},
                                  "filenames": [str(shared_artifact)]})
        coll_result = _process_build_output(
            [coll_msg_a, coll_msg_b], "srv", {"m1", "m2"}, {"m1", "m2"},
            {"srv": "granary-server", "m1": "a", "m2": "b"}, coll_dir)
        if coll_result.ok or "collision" not in coll_result.reason:
            print(f"  [FAIL] dep-info-path-collision: expected a refusal "
                  f"mentioning 'collision', got ok={coll_result.ok} reason="
                  f"{coll_result.reason!r}")
            rc = 2
        else:
            print("  [ok ] dep-info-path-collision: two different artifacts "
                  "resolving to the same dep-info path refuses rather than "
                  "reading one file as if it described both")

        # dep-info-path-collision-case: the SAME collision, but the two
        # artifacts' filenames spell the real file's path with DIFFERENT
        # CASE -- only detectable by keying on `realpath().casefold()`, not
        # the raw string. Meaningful only on a case-insensitive filesystem
        # (the differently-cased candidate must actually resolve to the
        # real file for `os.path.isfile` to treat it as present at all);
        # skipped, not silently passed, elsewhere.
        if not _fs_is_case_insensitive(pathlib.Path(tmproot)):
            print("  [skip] dep-info-path-collision-case: " +
                  _case_sensitive_skip_reason())
        else:
            # "deps" itself must stay lower-case in BOTH filenames: that
            # directory NAME match is its own case-sensitive string
            # comparison (deciding whether to strip a `lib` prefix at
            # all), unrelated to the containment/collision comparisons
            # under test here. Case is varied only in the part AFTER the
            # stripped `lib` prefix, which is where a real collision's two
            # spellings would actually differ.
            coll2_dir = pathlib.Path(tmproot) / "dep-info-collision-case"
            coll2_deps = coll2_dir / "deps"
            coll2_deps.mkdir(parents=True)
            shared2_artifact = coll2_deps / "libShared-bbbb2222.rmeta"
            shared2_artifact.write_text("x")
            shared2_dep_info = coll2_deps / "Shared-bbbb2222.d"
            shared2_dep_info.write_text(f"{shared2_dep_info}: src/lib.rs\n")
            # Message A spells the real (mixed-case) path; message B spells
            # the SAME file with its post-`lib` stem in a DIFFERENT case,
            # reachable only because the filesystem folds it -- the derived
            # candidate `deps/SHARED-bbbb2222.d` is a differently-cased
            # spelling of the same real `deps/Shared-bbbb2222.d`.
            coll2_msg_a = json.dumps({
                "reason": "compiler-artifact", "package_id": "m1",
                "target": {"name": "shared", "kind": ["lib"]},
                "filenames": [str(shared2_artifact)]})
            coll2_msg_b = json.dumps({
                "reason": "compiler-artifact", "package_id": "m2",
                "target": {"name": "shared", "kind": ["lib"]},
                "filenames": [str(coll2_deps / "libSHARED-bbbb2222.rmeta")]})
            coll2_result = _process_build_output(
                [coll2_msg_a, coll2_msg_b], "srv", {"m1", "m2"}, {"m1", "m2"},
                {"srv": "granary-server", "m1": "a", "m2": "b"}, coll2_dir)
            if coll2_result.ok or "collision" not in coll2_result.reason:
                print(f"  [FAIL] dep-info-path-collision-case: expected a "
                      f"refusal mentioning 'collision', got "
                      f"ok={coll2_result.ok} reason={coll2_result.reason!r}")
                rc = 2
            else:
                print("  [ok ] dep-info-path-collision-case: two "
                      "differently-CASED spellings of the same dep-info "
                      "path still refuse as a collision")

        # case-insensitive-skip-wording: the skip reason a case-sensitive
        # filesystem gets must say PLAINLY that the row's coverage exists
        # only on a case-insensitive one, and must not read as a pass.
        # Checked directly (not by forcing the host case-sensitive, which
        # this machine is not) so the wording is proven regardless of which
        # filesystem actually runs this suite.
        skip_reason = _case_sensitive_skip_reason()
        required_phrases = ["SKIPPED, NOT PASSED",
                             "CASE-INSENSITIVE FILESYSTEM",
                             "coverage limits"]
        missing_phrases = [p for p in required_phrases
                            if p.lower() not in skip_reason.lower()]
        if missing_phrases:
            print(f"  [FAIL] case-insensitive-skip-wording: missing "
                  f"{missing_phrases} from the skip reason: {skip_reason!r}")
            rc = 2
        else:
            print("  [ok ] case-insensitive-skip-wording: the skip reason "
                  "states plainly that coverage exists only on a "
                  "case-insensitive filesystem and points at the header")

        # mixed-predicate-coverage-limit: the header must say PLAINLY that
        # check B's two feature configurations (default, every non-fips
        # feature on) do not cover a MIXED predicate needing two
        # non-default features together -- checked by reading the module's
        # OWN docstring, not a copy, so the two cannot drift apart.
        header = __doc__ or ""
        required_mp_phrases = ["cfg(all(feature", "TWO feature configurations",
                                "not examined by either"]
        missing_mp = [p for p in required_mp_phrases
                      if p.lower() not in header.lower()]
        if missing_mp:
            print(f"  [FAIL] mixed-predicate-coverage-limit: the module "
                  f"docstring is missing {missing_mp}")
            rc = 2
        else:
            print("  [ok ] mixed-predicate-coverage-limit: the header states "
                  "plainly that a mixed two-feature predicate is examined by "
                  "neither build")

        # check-a-violations-sorted: `check_a` is exercised directly with
        # EIGHT synthetic ids fed as a `list` ALREADY in reverse-sorted
        # order, not a `set`, which sidesteps hash randomisation entirely
        # rather than merely outrunning it. A comparison of `set`
        # iteration order across two `PYTHONHASHSEED` subprocess runs
        # would not be RELIABLE proof here: with only two members, an
        # unsorted `set` has exactly two possible orders, so two ARBITRARY
        # seeds agree by pure chance about half the time, and
        # `PYTHONHASHSEED` only fixes the hash seed at interpreter
        # STARTUP, so such a comparison could only run across separate
        # subprocesses, never the process already running `--self-test`.
        #
        # EIGHT ids fed as a list already in reverse-sorted order avoids
        # all of that. `sorted()` turns the input into a-through-h; a
        # mutant that reverts to bare iteration walks the list in the
        # exact order it was handed, h-through-a, which is the list's own
        # literal order and never hash-derived. That makes the mutant's
        # wrong order reproduce identically on every interpreter and every
        # hash seed -- caught on every run, not just half of them -- while
        # still calling the real function under test rather than a copy.
        order_ids = list("abcdefgh")
        order_meta = {
            "resolve": {"nodes":
                [{"id": "srv", "deps": []}] +
                [{"id": mid, "deps": [{"pkg": "srv"}]} for mid in order_ids]},
        }
        order_id_to_name = {mid: mid for mid in order_ids}
        order_id_to_name["srv"] = "srv"
        order_result = check_a(order_meta, "srv", list(reversed(order_ids)),
                                order_id_to_name)
        order_actual = [v.split(" -> ", 1)[0] for v in order_result.violations]
        if not order_result.ok:
            print(f"  [FAIL] check-a-violations-sorted: expected ok=True, "
                  f"got {order_result.reason!r}")
            rc = 2
        elif len(order_result.violations) != len(order_ids):
            print(f"  [FAIL] check-a-violations-sorted: expected "
                  f"{len(order_ids)} violations, got "
                  f"{len(order_result.violations)}")
            rc = 2
        elif order_actual != order_ids:
            print(f"  [FAIL] check-a-violations-sorted: eight ids fed in "
                  f"reverse-sorted order printed as {order_actual}, not "
                  f"the sorted order {order_ids}")
            rc = 2
        else:
            print("  [ok ] check-a-violations-sorted: eight ids fed to "
                  "check_a as a list in reverse-sorted order print in "
                  "SORTED order -- a property of the list's own order, "
                  "not of the current process's hash seed")

        # check-b-violations-sorted: the SAME structural proof for check
        # B's own violation order, which tracks the order artifacts were
        # DISCOVERED in cargo's JSON output (build-parallelism scheduling)
        # -- a different nondeterminism source than check A's `set`, so it
        # gets its own direct, mechanism-targeted proof: synthetic
        # compiler-artifact messages fed to `_process_build_output` in
        # REVERSE (package "z" before "a"), with
        # BOTH resolving to a real containment violation. The returned
        # violations list must come back in (package, target, path) order
        # regardless of the INPUT order, proving the sort itself rather
        # than relying on any particular build happening to discover
        # artifacts in a convenient order.
        sortv_dir = pathlib.Path(tmproot) / "checkb-violations-sorted"
        sortv_server = sortv_dir / "crates" / "granary-server"
        (sortv_server / "src").mkdir(parents=True)
        # The directory must be named EXACTLY "deps" (not "deps-a"/"deps-z")
        # for dep_info_candidates' own `lib`-prefix stripping to apply at
        # all -- that check compares the directory's basename to "deps"
        # literally, so each artifact's "deps" lives under its OWN distinct
        # parent to avoid the two artifacts colliding on disk.
        sortv_dep_dir_a = sortv_dir / "pkg-a" / "deps"
        sortv_dep_dir_a.mkdir(parents=True)
        sortv_dep_dir_z = sortv_dir / "pkg-z" / "deps"
        sortv_dep_dir_z.mkdir(parents=True)
        sortv_artifact_a = sortv_dep_dir_a / "liba-aaaa0001.rmeta"
        sortv_artifact_a.write_text("x")
        (sortv_dep_dir_a / "a-aaaa0001.d").write_text(
            f"{sortv_dep_dir_a / 'a-aaaa0001'}: {sortv_server / 'src' / 'x.rs'}\n")
        sortv_artifact_z = sortv_dep_dir_z / "libz-zzzz0001.rmeta"
        sortv_artifact_z.write_text("x")
        (sortv_dep_dir_z / "z-zzzz0001.d").write_text(
            f"{sortv_dep_dir_z / 'z-zzzz0001'}: {sortv_server / 'src' / 'x.rs'}\n")
        sortv_msg_z = json.dumps({"reason": "compiler-artifact", "package_id": "zid",
                                   "target": {"name": "z", "kind": ["lib"]},
                                   "filenames": [str(sortv_artifact_z)]})
        sortv_msg_a = json.dumps({"reason": "compiler-artifact", "package_id": "aid",
                                   "target": {"name": "a", "kind": ["lib"]},
                                   "filenames": [str(sortv_artifact_a)]})
        sortv_result = _process_build_output(
            [sortv_msg_z, sortv_msg_a],  # fed in REVERSE order
            "srv", {"aid", "zid"}, {"aid", "zid"},
            {"srv": "granary-server", "aid": "a", "zid": "z"}, sortv_dir)
        if not sortv_result.ok:
            print(f"  [FAIL] check-b-violations-sorted: expected ok=True "
                  f"with two violations, got ok=False reason="
                  f"{sortv_result.reason!r}")
            rc = 2
        elif len(sortv_result.violations) != 2:
            print(f"  [FAIL] check-b-violations-sorted: expected 2 "
                  f"violations, got {len(sortv_result.violations)}: "
                  f"{sortv_result.violations}")
            rc = 2
        elif sortv_result.violations[0][0] != "a" or \
                sortv_result.violations[1][0] != "z":
            print(f"  [FAIL] check-b-violations-sorted: violations fed in "
                  f"REVERSE (z, a) order came back "
                  f"{[v[0] for v in sortv_result.violations]}, "
                  f"expected sorted (a, z)")
            rc = 2
        else:
            print("  [ok ] check-b-violations-sorted: two violations fed in "
                  "REVERSE order are returned SORTED by (package, target, "
                  "path)")

        # combined-violations-sorted: `check_b`'s COMBINING step (default
        # pass + feature pass) must sort the UNION, not each pass
        # separately and then concatenate them. The default pass reports
        # "b", the feature pass reports "a" -- concatenation order would
        # print "b" then "a"; the correct combined order is "a" then "b".
        # A third package "dup" appears in BOTH passes (compiled under
        # both builds) and must be reported ONCE, sorted on its own
        # merits -- "dup" sorts AFTER "b" ('d' > 'b'), so the fully sorted
        # order is a, b, dup, not the order in which the two passes happen
        # to list their entries.
        cv_b = ("b", "lib", "path/b", "b target 'lib': message-b")
        cv_a = ("a", "lib", "path/a", "a target 'lib': message-a")
        cv_dup = ("dup", "lib", "path/dup", "dup target 'lib': message-dup")
        combined_msgs = _combine_violations([cv_b, cv_dup], [cv_a, cv_dup])
        if combined_msgs != ["a target 'lib': message-a",
                              "b target 'lib': message-b",
                              "dup target 'lib': message-dup"]:
            print(f"  [FAIL] combined-violations-sorted: default reports "
                  f"'b', feature reports 'a' (plus a violation shared by "
                  f"both, 'dup') -- expected [a, b, dup] deduplicated and "
                  f"sorted, got {combined_msgs}")
            rc = 2
        else:
            print("  [ok ] combined-violations-sorted: default-pass 'b' and "
                  "feature-pass 'a' combine into SORTED (a, b, dup) order, "
                  "and a violation shared by both passes is reported once")

        # combined-violations-dedup-different-dep-info: the SAME (package,
        # target, offending source path), reported once by EACH build, but
        # with DIFFERENT dep-info-derived text in the message (a different
        # hash-qualified `deps/dup-<hash>.d` cited by each, exactly what
        # two real builds under different feature sets produce for the
        # identical offending source file) must still collapse to ONE
        # entry. `cv_dup` above (identical in both passes, including the
        # message) would ALSO dedupe under a naive full-tuple equality --
        # this is the construction that isolates the ACTUAL bug: keying
        # on the full 4-tuple never collapses two occurrences whose
        # MESSAGE text differs, even when the first three fields (the
        # real identity of the violation) agree. The kept message is the
        # one that sorts smallest across the FULL tuple -- here, the
        # "aaaa1111" hash before "bbbb2222" -- not "whichever pass" it
        # came from.
        cv_dup_default = ("dup", "lib", "crates/granary-server/src/x.rs",
                           "dup target 'lib': dep-info deps/dup-aaaa1111.d "
                           "names '../granary-server/src/x.rs', which "
                           "resolves to crates/granary-server/src/x.rs -- "
                           "inside crates/granary-server/ (check B: rustc's "
                           "dep-info)")
        cv_dup_feature = ("dup", "lib", "crates/granary-server/src/x.rs",
                           "dup target 'lib': dep-info deps/dup-bbbb2222.d "
                           "names '../granary-server/src/x.rs', which "
                           "resolves to crates/granary-server/src/x.rs -- "
                           "inside crates/granary-server/ (check B: rustc's "
                           "dep-info)")
        dedup_msgs = _combine_violations([cv_dup_default], [cv_dup_feature])
        if dedup_msgs != [cv_dup_default[3]]:
            print(f"  [FAIL] combined-violations-dedup-different-dep-info: "
                  f"the SAME (package, target, offending path), reported "
                  f"by both builds through two DIFFERENT dep-info-hash "
                  f"messages, must collapse to ONE entry (the one that "
                  f"sorts smallest) -- got {dedup_msgs}")
            rc = 2
        else:
            print("  [ok ] combined-violations-dedup-different-dep-info: "
                  "the same violation, reported by both builds through "
                  "different hash-qualified dep-info paths in its message, "
                  "de-duplicates on (package, target, offending source "
                  "path) rather than surviving as two")

        # combined-violations-identity-order-independent: the dedup key is
        # FILE IDENTITY. Two case-variant spellings of ONE real file collapse
        # on a case-insensitive filesystem and stay two on a case-sensitive
        # one (where the second spelling names no file); two DISTINCT real
        # files always stay two. Fed in both argument orders, the result is
        # identical, because the full tuple is sorted before grouping.
        cf = pathlib.Path(tmproot) / "cf"
        cf.mkdir(parents=True, exist_ok=True)
        (cf / "x.rs").write_text("x")
        (cf / "y.rs").write_text("y")
        folds = _fs_is_case_insensitive(cf)
        cv_case_upper = ("dup", "lib", "cf/X.rs", "dup target 'lib': via deps/dup-aaaa1111.d")
        cv_case_lower = ("dup", "lib", "cf/x.rs", "dup target 'lib': via deps/dup-bbbb2222.d")
        cv_other = ("dup", "lib", "cf/y.rs", "dup target 'lib': via deps/dup-cccc3333.d")
        order_ab = _combine_violations([cv_case_upper], [cv_case_lower, cv_other], tmproot)
        order_ba = _combine_violations([cv_case_lower, cv_other], [cv_case_upper], tmproot)
        want = 2 if folds else 3
        if order_ab != order_ba or len(order_ab) != want:
            print(f"  [FAIL] combined-violations-identity-order-independent: "
                  f"expected {want} entries (case-insensitive fs: {folds}), "
                  f"identical in both argument orders -- got {order_ab!r} vs "
                  f"{order_ba!r}")
            rc = 2
        else:
            print("  [ok ] combined-violations-identity-order-independent: "
                  f"{want} entries on this filesystem (case-insensitive: "
                  f"{folds}); distinct files never merge, and argument order "
                  "does not change the result")
    finally:
        shutil.rmtree(tmproot, ignore_errors=True)
    print("check-licence-resolved --self-test: "
          f"{'ALL OK' if rc == 0 else 'FAILED'}")
    return rc


def main(argv):
    known = {"--self-test"}
    unknown = [a for a in argv if a not in known]
    if unknown or len(argv) > 1:
        print(f"usage: {os.path.basename(__file__)} [--self-test]",
              file=sys.stderr)
        return 2
    if argv == ["--self-test"]:
        return self_test()
    root = pathlib.Path.cwd()
    if not (root / "Cargo.toml").is_file():
        print(f"THE LICENCE-RESOLVED GATE COULD NOT RUN -- {root} has no "
              "Cargo.toml; run this from the workspace root.", file=sys.stderr)
        return 2
    return run_gate(root)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
