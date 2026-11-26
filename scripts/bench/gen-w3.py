#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""W3: a deterministic append-only corpus — the counter-case where fixed
blocks work fine. Synthetic and labelled as such; the mechanism (appends
preserve alignment) is the exhibit, and synthetic makes it reproducible
with no download. Pure ASCII, seeded xorshift64, no wall clock.

    --build DIR {1|2}    write one version tree, print "DIR <digest>"
    --digest DIR         print the corpus digest
    --verify DIR {1|2}   digest DIR and REQUIRE the value pinned in
                         bench/datasets/w3.pin — HEAD's bytes of it, so
                         the pin must be committed and the working copy
                         must match (build-w2.sh's PINS_BLOB anchor)
    --self-test          the append-only property, the digest's field
                         coverage and every guard's refusal, on tiny
                         trees this generator builds

Every guard refuses BY NAME — `REFUSING (<name>): …` on stderr, exit 1 —
and `--self-test` asserts those names, so a guard cannot be softened
without a red self-test.
"""

if not __debug__:  # pragma: no cover
    raise SystemExit(
        "REFUSED: this script's checks are assert statements and -O / "
        "PYTHONOPTIMIZE disables them. Run it without -O.")


import hashlib
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile

FILES = 24

# granary's minimum grain, from crates/granary-core/src/thresh.rs:23. It is
# the one constant this generator cannot import — this file is Python and the
# source of truth is Rust — so the duplication is tripwired instead:
# crates/granary-bench/tests/gen_w3_constants.rs reads THIS literal and fails
# if it ever disagrees with granary_core::thresh::MIN_GRAIN.
MIN_GRAIN = 128 * 1024

# The coarsest `min` on the pre-registered sweep grid: SWEEP_AVGS tops out at
# 2 MiB and the grid's tuple policy is min = avg/2 (crates/granary-bench/
# src/tuple.rs). A file below THIS is single-grain at the top of the grid even
# though it clears MIN_GRAIN, which is exactly what the shipped late-*.log did
# — 1.85x MIN_GRAIN but 0.93x this, below the floor at the very grid point the
# sweep reports. Tripwired by the same test as MIN_GRAIN.
SWEEP_COARSEST_MIN = 1024 * 1024

# Sizes matter: at 54 bytes/line, 4000 lines is 216,000 B, which is
# single-grain at the sweep grid's three coarsest points — the mins there are
# 256 KiB, 512 KiB and 1 MiB (at avgs 512 KiB, 1 MiB and 2 MiB), all above
# 216,000 — so CDC, fixed and whole-file would be identical by construction
# at those points and the counter-case would be vacuous at exactly the coarse
# end it most needs to test.
# Use 80_000 lines, about 4.3 MB per file.
# The assertions below, rather than this comment, guarantee the size:
# every generated file must be at least 4x MIN_GRAIN AND 2x the grid's
# coarsest min so the counter-case remains multi-grain across the grid.
# The shipped minimum and the sweep's coarsest minimum are separate bounds.
# The shipped minimum is 128 KiB, which a 216,000-byte file already exceeds;
# exceeding that minimum alone therefore does not establish the grid requirement.
# The grid's coarsest minimum is 1 MiB.
# Its binding size assertion requires at least twice that value,
# i.e. 2,097,152 B, independently of the assertion against MIN_GRAIN.
LINE_BYTES = 54          # asserted against the formatter below, not assumed
V1_LINES = 80_000        # lines per file in version 1 (4,320,000 B)
V2_APPEND = 24_000       # lines appended in version 2 (+1,296,000 B)
V2_NEW_FILES = 2         # files that appear only in version 2
# The new files were an unnamed `18_000` literal sitting outside the reasoning
# block above: 972,000 B, which clears MIN_GRAIN but NOT the grid's coarsest
# min. Sized at V1_LINES they clear every assertion the other files clear.
# [controller decision]
V2_NEW_LINES = V1_LINES

SVC_SEED_BASE = 0xA5A5A5A5
LATE_SEED_BASE = 0xBEEF0000

LOGS = "logs"
SVC_NAME = re.compile(r"\Asvc-[0-9]{2}\.log\Z")
LATE_NAME = re.compile(r"\Alate-[0-9]{2}\.log\Z")

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
PIN_REL = "bench/datasets/w3.pin"  # HEAD-relative, forward slashes
PIN_PATH = REPO_ROOT / pathlib.PurePosixPath(PIN_REL)
PIN_VERSIONS = ("v1", "v2")
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")

# Domain separator for the corpus digest. Bump it only as a deliberate
# re-pinning event — every committed pin is a digest under THIS tag.
DIGEST_DOMAIN = b"granary-w3-corpus-digest-v1\n"


class Refusal(Exception):
    """A named refusal. `main` prints it and exits 1; the self-test asserts
    the name, so no guard can be quietly softened into a warning."""

    def __init__(self, name, message):
        super().__init__(f"REFUSING ({name}): {message}")
        self.name = name
        self.message = message


def _line(i, v):
    return f"{i:08d} {v:016x} event=append svc=granary-w3\n"


# --- Tripwires on the pre-registered constants. ---------------------------
# The file carried no assertion at all: V1_LINES could be edited to 4_000,
# leaving the eight-line comment above explaining why 4000 is wrong sitting
# word-for-word in place, and nothing in the repo failed while every arm at
# every grid point from 512 KiB up became
# 100.000% novel.
_MAX_INDEX = max(V1_LINES + V2_APPEND, V2_NEW_LINES) - 1
assert LINE_BYTES == len(_line(0, 0).encode("ascii")), (
    f"LINE_BYTES {LINE_BYTES} != the formatter's {len(_line(0, 0))}"
)
assert LINE_BYTES == len(_line(_MAX_INDEX, (1 << 64) - 1).encode("ascii")), (
    f"line width is not constant at index {_MAX_INDEX} — the counters overflowed "
    f"their field, so the sizes asserted below are wrong"
)
V1_FILE_BYTES = V1_LINES * LINE_BYTES
V2_FILE_BYTES = (V1_LINES + V2_APPEND) * LINE_BYTES
NEW_FILE_BYTES = V2_NEW_LINES * LINE_BYTES
for _label, _size in (
    ("v1 svc-*.log", V1_FILE_BYTES),
    ("v2 svc-*.log", V2_FILE_BYTES),
    ("v2 late-*.log", NEW_FILE_BYTES),
):
    assert _size >= 4 * MIN_GRAIN, (
        f"{_label} is {_size} B = {_size / MIN_GRAIN:.2f}x MIN_GRAIN ({MIN_GRAIN} B); "
        f"W3 requires >= 4x, or the counter-case is vacuous at the shipped tuple "
        f"(files below a grain-size floor cannot distinguish chunking from whole-file storage)"
    )
    assert _size >= 2 * SWEEP_COARSEST_MIN, (
        f"{_label} is {_size} B = {_size / SWEEP_COARSEST_MIN:.2f}x the sweep grid's "
        f"coarsest min ({SWEEP_COARSEST_MIN} B); W3 requires >= 2x, or the file is "
        f"single-grain at the top of the grid"
    )
assert all(SVC_SEED_BASE + i != 0 for i in range(FILES)), "an svc-* seed is zero"
assert all(LATE_SEED_BASE + j != 0 for j in range(V2_NEW_FILES)), "a late-* seed is zero"
assert FILES > 0 and V2_NEW_FILES > 0, "FILES and V2_NEW_FILES must be positive"


def xorshift64(seed):
    # `state = seed or <constant>` silently substituted a constant for seed 0,
    # so a caller that lost its seed still got plausible-looking bytes. 0 is a
    # fixed point of xorshift; refuse it.
    assert seed != 0, "xorshift64: the seed must be non-zero (0 is a fixed point)"
    state = seed
    while True:
        state ^= (state << 13) & 0xFFFFFFFFFFFFFFFF
        state ^= state >> 7
        state ^= (state << 17) & 0xFFFFFFFFFFFFFFFF
        yield state


def lines(seed, count):
    gen = xorshift64(seed)
    out = []
    for i in range(count):
        v = next(gen)
        out.append(_line(i, v))
    return "".join(out).encode("ascii")


def looks_like_w3_tree(root):
    """True if `root` is empty or holds ONLY `logs/` with only `svc-NN.log` /
    `late-NN.log` regular files — i.e. a tree this generator wrote."""
    try:
        entries = sorted(os.listdir(root))
        if not entries:
            return True
        if entries != [LOGS]:
            return False
        logs = root / LOGS
        if logs.is_symlink() or not logs.is_dir():
            return False
        for name in sorted(os.listdir(logs)):
            p = logs / name
            if p.is_symlink() or not p.is_file():
                return False
            if not (SVC_NAME.match(name) or LATE_NAME.match(name)):
                return False
    except OSError:
        # Unreadable is not recognisable, and unrecognisable means refuse.
        return False
    return True


def build(root, version, v1_lines=V1_LINES, append=V2_APPEND, new_lines=V2_NEW_LINES):
    """Write one version tree at `root`, replacing an existing w3 tree.

    Nothing destructive may be safe only by virtue of being pointed at the
    right path (build-w2.sh:46-47). The target must be absent, empty, or
    already a w3 tree, and its basename must be the version being written.
    """
    if version not in (1, 2):
        raise Refusal(
            "build-version",
            f"version must be 1 or 2, got {version!r} — every other value silently "
            f"built version 1, so a 'v3' directory would hold a byte-identical "
            f"copy of v1 and pair at 0% novel for every arm",
        )
    root = pathlib.Path(root)
    if root.name not in PIN_VERSIONS:
        raise Refusal(
            "build-target-basename",
            f"{root} — the target's basename must be 'v1' or 'v2', not {root.name!r}; "
            f"this directory is about to be DELETED and rewritten",
        )
    if root.name != f"v{version}":
        raise Refusal(
            "build-target-version-mismatch",
            f"{root} names version {root.name} but version {version} was requested",
        )
    if root.is_symlink():
        raise Refusal(
            "build-target-occupied",
            f"{root} is a symlink; refusing to delete through it",
        )
    if root.exists():
        if not root.is_dir():
            raise Refusal("build-target-occupied", f"{root} is not a directory")
        if not looks_like_w3_tree(root):
            raise Refusal(
                "build-target-occupied",
                f"{root} is neither empty nor a w3 tree (only {LOGS}/ holding "
                f"svc-NN.log and late-NN.log regular files) — refusing to delete it",
            )
        shutil.rmtree(root)
    n = v1_lines + (append if version == 2 else 0)
    for i in range(FILES):
        p = root / LOGS / f"svc-{i:02d}.log"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(lines(SVC_SEED_BASE + i, n))
    if version == 2:
        for j in range(V2_NEW_FILES):
            p = root / LOGS / f"late-{j:02d}.log"
            p.write_bytes(lines(LATE_SEED_BASE + j, new_lines))


# --- The corpus digest. ---------------------------------------------------
# It hashes exactly the fields crates/granary-bench/src/corpus.rs records —
# lstat type, exec bit, file length and content, symlink target bytes, empty
# directories — in corpus.rs's own order: per-directory memcmp sort, depth first.
# A digest restricted to `p.is_file()` over `rglob` is insufficient:
# it follows symlinks, excludes empty directories and does not bind the exec bit.
# Replacing a file by a symlink to identical content must change the digest;
# that replacement also removes the file's bytes from the sweep's file_bytes.
# The digest must also distinguish an added empty directory, a dangling
# symlink, a symlink to a directory, and an unsupported entry such as a fifo.
# corpus.rs refuses the whole load for a fifo, so a pin must not conceal it.
# Encode fields at fixed width or with length prefixes:
# unseparated `path || sha256(content)` does not delimit the fields.
# The pin must cover the tree shape and metadata, as well as file contents.


def _u64(n):
    return n.to_bytes(8, "big")


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.digest()


def _emit(h, tag, components):
    h.update(tag)
    h.update(_u64(len(components)))
    for c in components:
        h.update(_u64(len(c)))
        h.update(c)


def _walk(dirpath, components, h, stats):
    """Hash one directory's entries; returns whether it had any."""
    try:
        names = sorted(os.listdir(dirpath))
    except OSError as e:
        raise Refusal("digest-io", f"{os.fsdecode(dirpath)}: {e}") from e
    for name in names:
        path = os.path.join(dirpath, name)
        try:
            st = os.lstat(path)
        except OSError as e:
            raise Refusal("digest-io", f"{os.fsdecode(path)}: {e}") from e
        components.append(name)
        if stat.S_ISDIR(st.st_mode):
            if not _walk(path, components, h, stats):
                _emit(h, b"D", components)
                stats["empty_dirs"] += 1
                stats["nodes"] += 1
        elif stat.S_ISREG(st.st_mode):
            _emit(h, b"F", components)
            h.update(b"\x01" if st.st_mode & 0o111 else b"\x00")
            h.update(_u64(st.st_size))
            h.update(_sha256_file(path))
            stats["files"] += 1
            stats["file_bytes"] += st.st_size
            stats["nodes"] += 1
        elif stat.S_ISLNK(st.st_mode):
            try:
                target = os.readlink(path)
            except OSError as e:
                raise Refusal("digest-io", f"{os.fsdecode(path)}: {e}") from e
            _emit(h, b"L", components)
            h.update(_u64(len(target)))
            h.update(target)
            stats["symlinks"] += 1
            stats["nodes"] += 1
        else:
            # corpus.rs refuses these outright rather than skipping them; a
            # digest that skipped one would pin a tree the harness cannot load.
            raise Refusal(
                "digest-unsupported-type",
                f"{os.fsdecode(path)}: not a file, directory or symlink — "
                f"corpus.rs refuses this tree",
            )
        components.pop()
    return bool(names)


def digest_and_stats(root):
    root_b = os.fsencode(root)
    if not os.path.isdir(root_b):
        raise Refusal(
            "digest-root-not-a-directory",
            f"{os.fsdecode(root_b)!r} is not a directory — the shipped digest "
            f"returned sha256('') with exit 0 for a missing path, a regular file "
            f"and the empty string (which digested the CWD)",
        )
    h = hashlib.sha256()
    h.update(DIGEST_DOMAIN)
    stats = {"nodes": 0, "files": 0, "file_bytes": 0, "symlinks": 0, "empty_dirs": 0}
    _walk(root_b, [], h, stats)
    if stats["files"] == 0:
        raise Refusal(
            "digest-root-no-files",
            f"{os.fsdecode(root_b)} holds no regular files — an empty or "
            f"half-deleted corpus must not digest happily",
        )
    h.update(_u64(stats["nodes"]))
    return h.hexdigest(), stats


def digest(root):
    return digest_and_stats(root)[0]


def parse_pin_text(text, source):
    """The ONE parser of w3.pin records: CR stripped, trimmed, blanks and
    comments (indented ones included) dropped. Exactly one `v1` and one `v2`
    record, each a 64-hex digest. `source` names where the bytes came from
    (a path, or `HEAD:…`), for the refusal messages."""
    path = source
    pins = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.replace("\r", "").strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 2:
            raise Refusal(
                "verify-pin-record",
                f"{path}:{lineno}: a data record is '<version> <64-hex>', got {line!r}",
            )
        version, want = fields[0].lower(), fields[1].lower()
        if version not in PIN_VERSIONS:
            raise Refusal(
                "verify-pin-record",
                f"{path}:{lineno}: unknown version {fields[0]!r}, expected one of "
                f"{', '.join(PIN_VERSIONS)}",
            )
        if not HEX64.match(want):
            raise Refusal(
                "verify-pin-record",
                f"{path}:{lineno}: {fields[1]!r} is not a 64-character hex digest",
            )
        if version in pins:
            raise Refusal(
                "verify-pin-record", f"{path}:{lineno}: {version} is pinned twice"
            )
        pins[version] = want
    missing = [v for v in PIN_VERSIONS if v not in pins]
    if missing:
        raise Refusal(
            "verify-pin-record", f"{path}: no pin for {', '.join(missing)}"
        )
    return pins


def parse_pins(path):
    """Parse a pin FILE — the working-tree reader, used by the self-test's
    parser cases. --verify does not go through here: it consumes HEAD's bytes
    via anchored_pins, never a working file."""
    try:
        # UTF-8: the comment block is prose and uses em dashes. The data
        # fields are restricted to version names and hex by parse_pin_text.
        text = pathlib.Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise Refusal("verify-pin-missing", f"{path}: {e}") from e
    except UnicodeDecodeError as e:
        raise Refusal("verify-pin-record", f"{path}: not valid UTF-8: {e}") from e
    return parse_pin_text(text, path)


def _git_env():
    """The environment every git child gets: all `GIT_*` scrubbed.
    Used by the anchor and the self-test's scratch-repo plumbing so a
    caller-set GIT_DIR cannot redirect those operations to another repository."""
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def _git(repo_root, *args):
    """Run git against `repo_root`; refuse BY NAME if git itself cannot run.
    A missing git must fail CLOSED — a purity gate once failed open on
    exactly this shape.

    Every `GIT_*` variable is SCRUBBED from the child's environment:
    `GIT_DIR=/attacker/.git GIT_WORK_TREE=<repo_root>` redirects object
    reads to a stranger's HEAD while `rev-parse --show-toplevel` still
    reports the expected path — so every check below would pass while
    `cat-file` consumed the attacker's pin. This was reproduced
    in the self-test before the scrub.
    `-C` sets only the starting directory; it does not clear the
    environment. A hostile `$HOME/.gitconfig` is not closed by this. That
    remains residual hostile-environment risk: code inside the script cannot
    prove that the running script itself is the committed copy."""
    env = _git_env()
    try:
        # --no-replace-objects: a refs/replace/<HEAD-oid> entry transparently
        # substitutes another commit's tree under an UNCHANGED commit id, so
        # `cat-file HEAD:<pin>` would serve replacement bytes nobody
        # committed while every id check passes. The scrub above cannot
        # close this (it is repo state, not environment) — and it in fact
        # re-enables replacement by dropping GIT_NO_REPLACE_OBJECTS, so the
        # flag is load-bearing. Replacement under an unchanged commit id
        # was reproduced in the self-test.
        return subprocess.run(
            ["git", "--no-replace-objects", "-C", os.fspath(repo_root), *args],
            capture_output=True,
            check=False,
            env=env,
        )
    except OSError as e:
        raise Refusal(
            "verify-pin-unanchored",
            f"git could not run ({e}) — without it there is no HEAD to anchor "
            f"the pin to, and an unanchored pin is not a pin",
        ) from e


def anchored_pins(repo_root=REPO_ROOT, rel=PIN_REL):
    """Parse the pin from HEAD'S BYTES, refusing unless the working copy is
    byte-identical — build-w2.sh's PINS_BLOB anchor, minus the temp file:
    the blob is parsed from MEMORY, so
    between the guard and the read there is no pathname for a hostile TMPDIR
    to swap (the recorded residual fetch-w1.sh and build-w2.sh both carry).

    A pin is only a pin if it is COMMITTED: the digest in this file decides
    whether a measurement run trusts a multi-GB corpus, so an uncommitted
    edit redefines the dataset with nothing to review it. `git diff` says
    nothing about an untracked file, so the path must exist in HEAD first,
    then the working copy must match it — same mechanism and wording as
    build-w2.sh and fetch-w1.sh's verify_key."""
    root = pathlib.Path(repo_root)
    working = root / pathlib.PurePosixPath(rel)
    r = _git(root, "rev-parse", "--show-toplevel")
    if r.returncode != 0:
        raise Refusal(
            "verify-pin-unanchored",
            f"{root} is not inside a git work tree "
            f"({r.stderr.decode(errors='replace').strip() or 'git rev-parse failed'}) "
            f"— there is no HEAD to hold the approved pin bytes",
        )
    toplevel = os.path.realpath(r.stdout.decode(errors="replace").strip())
    if toplevel != os.path.realpath(root):
        # git walked UP and found some OTHER repository enclosing this tree
        # (an exported copy sitting under an unrelated checkout). HEAD there
        # is not this project's HEAD; consuming it would anchor the pin to a
        # stranger's history.
        raise Refusal(
            "verify-pin-unanchored",
            f"the enclosing git work tree is {toplevel}, not {root} — "
            f"HEAD:{rel} would be read from the wrong repository",
        )
    if _git(root, "cat-file", "-e", f"HEAD:{rel}").returncode != 0:
        raise Refusal(
            "verify-pin-uncommitted",
            f"{rel} is not committed at HEAD — commit the pin before relying "
            f"on it (an uncommitted pin redefines the dataset with nothing "
            f"to review it)",
        )
    r = _git(root, "cat-file", "blob", f"HEAD:{rel}")
    if r.returncode != 0:
        raise Refusal(
            "verify-pin-unanchored",
            f"could not read HEAD:{rel} "
            f"({r.stderr.decode(errors='replace').strip()}) — there are no "
            f"approved bytes to consume",
        )
    blob = r.stdout
    try:
        working_bytes = working.read_bytes()
    except OSError as e:
        raise Refusal("verify-pin-missing", f"{working}: {e}") from e
    if working_bytes != blob:
        raise Refusal(
            "verify-pin-differs-from-head",
            f"{working} differs from HEAD:{rel} — commit the pin before "
            f"relying on it",
        )
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError as e:
        raise Refusal(
            "verify-pin-record", f"HEAD:{rel}: not valid UTF-8: {e}"
        ) from e
    return parse_pin_text(text, f"HEAD:{rel}")


def verify(root, version):
    """Digest `root` and REQUIRE the pinned value.

    build() rmtrees and then writes file by file with no temp-then-rename and
    no completion marker, so a partial tree is the natural interrupted state —
    and a sweep over a half-written corpus exits 0 and writes a complete
    result record with every novel fraction roughly doubled. Only a call to
    this before measuring rules that out.
    """
    if version not in (1, 2):
        raise Refusal("verify-version", f"version must be 1 or 2, got {version!r}")
    want = anchored_pins()[f"v{version}"]
    got = digest(root)
    if got != want:
        raise Refusal(
            "verify-digest-mismatch",
            f"{root} is NOT the pinned v{version} corpus\n"
            f"    pinned (HEAD:{PIN_REL}): {want}\n"
            f"    measured:                {got}",
        )
    return got


# --- Self-test. -----------------------------------------------------------
# W3's whole caption is "appends preserve alignment, so fixed blocks work
# fine", and nothing in the repo checked that the generator does that: a
# mutant rewriting one byte at offset 3 of each svc-*.log in v2 took fixed-4M
# from 26.377% to 100.000% novel and produced a structurally
# indistinguishable result record.

ST_V1_LINES = 8
ST_APPEND = 3
ST_NEW_LINES = 5


def _st_case(state, label, ok, detail=""):
    state["cases"] += 1
    if ok:
        print(f"  ok: {label}")
    else:
        state["fails"] += 1
        suffix = f" — {detail}" if detail else ""
        print(f"SELF-TEST FAIL: {label}{suffix}", file=sys.stderr)


def _st_refuses(state, label, argv, name):
    """The CLI must exit 1 with this named refusal. Run out-of-process so a
    guard that exits cannot end the self-test."""
    r = subprocess.run(
        [sys.executable, os.path.abspath(__file__), *argv],
        capture_output=True,
        text=True,
        check=False,
    )
    ok = r.returncode == 1 and f"REFUSING ({name})" in r.stderr
    _st_case(
        state,
        f"{label} → REFUSING ({name})",
        ok,
        f"rc={r.returncode} stderr={r.stderr.strip()[:160]!r}",
    )


def _st_raises(state, label, fn, name):
    try:
        fn()
    except Refusal as e:
        _st_case(state, f"{label} → REFUSING ({e.name})", e.name == name, f"wanted {name}")
        return
    _st_case(state, f"{label} → REFUSING ({name})", False, "no refusal raised")


def _st_mutation(state, label, root, mutate, undo):
    """A mutation the digest MUST see, and whose undo must restore it."""
    base = digest(root)
    mutate()
    moved = digest(root) != base
    undo()
    restored = digest(root) == base
    _st_case(
        state,
        f"digest sees: {label}",
        moved and restored,
        f"moved={moved} restored_after_undo={restored}",
    )


def _selftest_append_only(state, tmp):
    v1 = pathlib.Path(tmp, "a", "v1")
    v2 = pathlib.Path(tmp, "a", "v2")
    build(v1, 1, ST_V1_LINES, ST_APPEND, ST_NEW_LINES)
    build(v2, 2, ST_V1_LINES, ST_APPEND, ST_NEW_LINES)
    prefix_ok = True
    for i in range(FILES):
        name = f"svc-{i:02d}.log"
        a = (v1 / LOGS / name).read_bytes()
        b = (v2 / LOGS / name).read_bytes()
        if not (b[: len(a)] == a and len(b) > len(a)):
            prefix_ok = False
            _st_case(
                state,
                f"{name}: v1 is a strict byte prefix of v2",
                False,
                f"len v1={len(a)} len v2={len(b)} prefix_match={b[: len(a)] == a}",
            )
    if prefix_ok:
        _st_case(
            state,
            f"all {FILES} svc-*.log: v1 is a strict byte PREFIX of v2 (the exhibit)",
            True,
        )
    for j in range(V2_NEW_FILES):
        name = f"late-{j:02d}.log"
        _st_case(
            state,
            f"{name}: present in v2, absent from v1",
            (v2 / LOGS / name).is_file() and not (v1 / LOGS / name).exists(),
        )
    svc = {f"svc-{i:02d}.log" for i in range(FILES)}
    late = {f"late-{j:02d}.log" for j in range(V2_NEW_FILES)}
    _st_case(
        state,
        "v1 holds exactly the svc-* files",
        set(os.listdir(v1 / LOGS)) == svc,
        f"{sorted(os.listdir(v1 / LOGS))}",
    )
    _st_case(
        state,
        "v2 holds exactly the svc-* files plus late-*",
        set(os.listdir(v2 / LOGS)) == svc | late,
        f"{sorted(os.listdir(v2 / LOGS))}",
    )
    v1b = pathlib.Path(tmp, "b", "v1")
    build(v1b, 1, ST_V1_LINES, ST_APPEND, ST_NEW_LINES)
    _st_case(
        state,
        "two builds at two different paths have one digest",
        digest(v1) == digest(v1b),
    )
    before = digest(v1b)
    build(v1b, 1, ST_V1_LINES, ST_APPEND, ST_NEW_LINES)
    _st_case(
        state,
        "rebuilding over an existing w3 tree is allowed and reproduces it",
        digest(v1b) == before,
    )
    return v1b


def _selftest_digest_fields(state, tmp, tree):
    f = tree / LOGS / "svc-00.log"
    original = f.read_bytes()
    _st_mutation(
        state,
        "a one-byte in-place flip at offset 3 (the append-only mutant's shape)",
        tree,
        lambda: f.write_bytes(original[:3] + bytes([original[3] ^ 0x01]) + original[4:]),
        lambda: f.write_bytes(original),
    )
    _st_mutation(
        state,
        "a one-byte append",
        tree,
        lambda: f.write_bytes(original + b"x"),
        lambda: f.write_bytes(original),
    )
    _st_mutation(
        state,
        "an exec bit (corpus.rs records File{exec})",
        tree,
        lambda: f.chmod(0o755),
        lambda: f.chmod(0o644),
    )
    _st_mutation(
        state,
        "an added empty directory (corpus.rs records EmptyDir)",
        tree,
        lambda: (tree / LOGS / "hollow").mkdir(),
        lambda: (tree / LOGS / "hollow").rmdir(),
    )
    dangling = tree / LOGS / "dangling"
    _st_mutation(
        state,
        "an added dangling symlink",
        tree,
        lambda: dangling.symlink_to("nowhere"),
        dangling.unlink,
    )
    # Target sensitivity needs two different targets under ONE name, so it is
    # a comparison rather than a mutate/undo pair.
    dangling.symlink_to("nowhere")
    one = digest(tree)
    dangling.unlink()
    dangling.symlink_to("elsewhere")
    _st_case(
        state,
        "digest sees: a symlink target changed under an unchanged name",
        digest(tree) != one,
    )
    dangling.unlink()
    other = tree / "sibling"
    _st_mutation(
        state,
        "a symlink to a DIRECTORY (is_file() is false for it)",
        tree,
        lambda: (other.mkdir(), (tree / LOGS / "dirlink").symlink_to("../sibling"))[0],
        lambda: ((tree / LOGS / "dirlink").unlink(), other.rmdir())[0],
    )
    # A regular file replaced by a symlink to IDENTICAL content: the shipped
    # digest followed the link and saw no change at all, while corpus.rs drops
    # the file's bytes from file_bytes and records a Symlink node instead.
    fx = pathlib.Path(tmp, "fx")
    (fx / LOGS).mkdir(parents=True)
    (fx / LOGS / "a.log").write_bytes(b"alpha\n")
    (fx / LOGS / "b.log").write_bytes(b"alpha\n")
    fx_b = fx / LOGS / "b.log"
    _st_mutation(
        state,
        "a regular file replaced by a symlink to IDENTICAL content",
        fx,
        lambda: (fx_b.unlink(), fx_b.symlink_to("a.log"))[0],
        lambda: (fx_b.unlink(), fx_b.write_bytes(b"alpha\n"))[0],
    )
    fifo = fx / LOGS / "pipe"
    os.mkfifo(fifo)
    _st_raises(
        state,
        "a fifo in the tree (corpus.rs refuses the whole load)",
        lambda: digest(fx),
        "digest-unsupported-type",
    )
    fifo.unlink()


def _selftest_guards(state, tmp):
    occupied = pathlib.Path(tmp, "occupied", "v1")
    occupied.mkdir(parents=True)
    (occupied / "someone-elses-data").write_bytes(b"precious\n")
    cache = pathlib.Path(tmp, "cache-root")
    cache.mkdir()
    (cache / "w1").mkdir()
    empty = pathlib.Path(tmp, "empty")
    empty.mkdir()
    plain = pathlib.Path(tmp, "plain-file")
    plain.write_bytes(b"x")
    good = pathlib.Path(tmp, "a", "v1")

    _st_refuses(state, "--build over a cache ROOT", ["--build", str(cache), "1"],
                "build-target-basename")
    _st_refuses(state, "--build over an occupied v1", ["--build", str(occupied), "1"],
                "build-target-occupied")
    _st_refuses(state, "--build v1 with version 2", ["--build", str(good), "2"],
                "build-target-version-mismatch")
    for n in ("3", "0", "-1", "99"):
        _st_refuses(state, f"--build … {n}", ["--build", str(pathlib.Path(tmp, "z", "v1")), n],
                    "build-version")
    _st_refuses(state, "--build … notanumber",
                ["--build", str(pathlib.Path(tmp, "z", "v1")), "notanumber"],
                "build-version")
    _st_refuses(state, "--digest a missing path", ["--digest", str(tmp / "nope")],
                "digest-root-not-a-directory")
    _st_refuses(state, "--digest a regular file", ["--digest", str(plain)],
                "digest-root-not-a-directory")
    _st_refuses(state, "--digest ''", ["--digest", ""], "digest-root-not-a-directory")
    _st_refuses(state, "--digest an empty directory", ["--digest", str(empty)],
                "digest-root-no-files")
    _st_refuses(state, "--verify a tree that is not the pinned corpus",
                ["--verify", str(good), "1"], "verify-digest-mismatch")
    _st_refuses(state, "--verify … 3", ["--verify", str(good), "3"], "verify-version")


def _selftest_anchor(state, tmp):
    """Every anchor refusal demonstrated by name in a scratch repo, plus the
    pass case. The build-w2 TOCTOU (guard passes, tampered bytes consumed) is
    structurally impossible here — HEAD's blob is parsed from memory, there
    is no second read — so what these cases prove is the guard itself: the
    working copy can never be consumed, matching or not."""
    scratch = pathlib.Path(tmp, "anchor-repo")
    pin = scratch / pathlib.PurePosixPath(PIN_REL)
    good = f"v1 {'a' * 64}\nv2 {'b' * 64}\n"

    def g(*args):
        r = subprocess.run(
            ["git", "-C", str(scratch), *args],
            capture_output=True,
            text=True,
            env=_git_env(),
        )
        assert r.returncode == 0, f"scratch git {args}: {r.stderr}"

    pin.parent.mkdir(parents=True)
    g("init", "-q")  # g() scrubs GIT_*, so init cannot land elsewhere
    pin.write_text(good, encoding="ascii")
    _st_raises(
        state,
        "anchor: a pin present in the tree but not in HEAD",
        lambda: anchored_pins(scratch),
        "verify-pin-uncommitted",
    )
    g("add", PIN_REL)
    _st_raises(
        state,
        "anchor: a pin staged but never committed",
        lambda: anchored_pins(scratch),
        "verify-pin-uncommitted",
    )
    g("-c", "user.name=w3", "-c", "user.email=w3@selftest", "commit", "-qm", "pin")
    parsed = anchored_pins(scratch)
    _st_case(
        state,
        "anchor: a committed, matching pin parses — from HEAD's bytes",
        parsed == {"v1": "a" * 64, "v2": "b" * 64},
        f"{parsed}",
    )
    pin.write_text(f"v1 {'d' * 64}\nv2 {'b' * 64}\n", encoding="ascii")
    _st_raises(
        state,
        "anchor: a working copy edited after the commit",
        lambda: anchored_pins(scratch),
        "verify-pin-differs-from-head",
    )
    pin.write_text(good, encoding="ascii")
    pin.unlink()
    _st_raises(
        state,
        "anchor: a working copy deleted while HEAD still holds the pin",
        lambda: anchored_pins(scratch),
        "verify-pin-missing",
    )
    pin.write_text(good, encoding="ascii")
    # Not a repo at all — and immune to whatever repository might enclose the
    # system temp dir, because the toplevel check refuses a stranger's HEAD.
    plain = pathlib.Path(tmp, "anchor-plain")
    ppin = plain / pathlib.PurePosixPath(PIN_REL)
    ppin.parent.mkdir(parents=True)
    ppin.write_text(good, encoding="ascii")
    _st_raises(
        state,
        "anchor: no git work tree at the root fails CLOSED",
        lambda: anchored_pins(plain),
        "verify-pin-unanchored",
    )
    # Toplevel mismatch, DETERMINISTICALLY: a subdirectory of the scratch
    # repo is inside a work tree (so `rev-parse` succeeds), but its
    # toplevel is the scratch root, not the subdirectory — the branch the
    # plain-dir case above cannot pin down, since there both roads refuse
    # under one name.
    nested = scratch / "nested-root"
    npin = nested / pathlib.PurePosixPath(PIN_REL)
    npin.parent.mkdir(parents=True)
    npin.write_text(good, encoding="ascii")
    _st_raises(
        state,
        "anchor: an ENCLOSING repository's HEAD is refused (toplevel mismatch)",
        lambda: anchored_pins(nested),
        "verify-pin-unanchored",
    )
    # The GIT_DIR/GIT_WORK_TREE attack, reproduced: an attacker repository
    # whose HEAD commits a MALICIOUS pin, the victim's working copy made to
    # match it, and the environment pointing git at the attacker's object
    # store while naming the victim as the work tree. Before the _git env
    # scrub this PASSED and returned the attacker's digests; it must refuse
    # as a tamper, because the victim's REAL HEAD
    # does not match.
    evil = pathlib.Path(tmp, "anchor-attacker")
    epin = evil / pathlib.PurePosixPath(PIN_REL)
    epin.parent.mkdir(parents=True)
    subprocess.run(
        ["git", "-C", str(evil), "init", "-q"], check=True, env=_git_env()
    )
    malicious = f"v1 {'e' * 64}\nv2 {'f' * 64}\n"
    epin.write_text(malicious, encoding="ascii")
    subprocess.run(
        ["git", "-C", str(evil), "add", PIN_REL], check=True, env=_git_env()
    )
    subprocess.run(
        ["git", "-C", str(evil), "-c", "user.name=x", "-c", "user.email=x@x",
         "commit", "-qm", "evil pin"],
        check=True,
        env=_git_env(),
    )
    pin.write_text(malicious, encoding="ascii")  # victim working copy tampered
    saved = {k: os.environ.get(k) for k in ("GIT_DIR", "GIT_WORK_TREE")}
    os.environ["GIT_DIR"] = str(evil / ".git")
    os.environ["GIT_WORK_TREE"] = str(scratch)
    try:
        _st_raises(
            state,
            "anchor: GIT_DIR/GIT_WORK_TREE cannot swap in a stranger's HEAD",
            lambda: anchored_pins(scratch),
            "verify-pin-differs-from-head",
        )
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    pin.write_text(good, encoding="ascii")
    # A replace ref: refs/replace/<HEAD-oid> pointing at a commit whose tree
    # holds the malicious pin. HEAD's commit id never moves, yet without
    # --no-replace-objects `cat-file HEAD:<pin>` serves the REPLACEMENT's
    # bytes — so a tampered working copy matches "HEAD" and verify passes on
    # digests nobody committed. The env scrub cannot close this (repo state,
    # not environment).
    def g_out(*args):
        r = subprocess.run(
            ["git", "-C", str(scratch), *args],
            capture_output=True,
            text=True,
            env=_git_env(),
        )
        assert r.returncode == 0, f"scratch git {args}: {r.stderr}"
        return r.stdout.strip()

    good_head = g_out("rev-parse", "HEAD")
    pin.write_text(malicious, encoding="ascii")
    g("add", PIN_REL)
    g("-c", "user.name=x", "-c", "user.email=x@x", "commit", "-qm", "evil")
    evil_head = g_out("rev-parse", "HEAD")
    g("reset", "-q", "--hard", good_head)
    g("replace", good_head, evil_head)
    pin.write_text(malicious, encoding="ascii")  # matches the REPLACEMENT tree
    try:
        _st_raises(
            state,
            "anchor: a refs/replace substitution cannot impersonate HEAD",
            lambda: anchored_pins(scratch),
            "verify-pin-differs-from-head",
        )
    finally:
        g("replace", "-d", good_head)
        pin.write_text(good, encoding="ascii")
    # The REAL repo's committed pin, through the exact path --verify consumes.
    real = anchored_pins()
    _st_case(
        state,
        f"anchor: the committed {PIN_PATH.name} parses via HEAD:{PIN_REL}",
        sorted(real) == list(PIN_VERSIONS),
        f"{sorted(real)}",
    )


def _selftest_pins(state, tmp):
    pins = parse_pins(PIN_PATH)
    _st_case(
        state,
        f"the committed {PIN_PATH.name} parses to exactly {len(PIN_VERSIONS)} records",
        sorted(pins) == list(PIN_VERSIONS),
        f"{sorted(pins)}",
    )
    good = (
        "# comment\n"
        "   # an INDENTED comment is a comment\n"
        "\n"
        f"v1 {'a' * 64}\r\n"
        f"V2 {'B' * 64}\n"
    )
    p = pathlib.Path(tmp, "pins")
    p.write_text(good, encoding="ascii")
    parsed = parse_pins(p)
    _st_case(
        state,
        "pin parser: comments, indented comments, blanks, CRLF and case",
        parsed == {"v1": "a" * 64, "v2": "b" * 64},
        f"{parsed}",
    )
    _st_raises(state, "pin file missing",
               lambda: parse_pins(pathlib.Path(tmp, "no-such-pin")), "verify-pin-missing")
    cases = [
        ("one field", f"v1 {'a' * 64}\nv2\n"),
        ("three fields", f"v1 {'a' * 64} extra\nv2 {'b' * 64}\n"),
        ("unknown version", f"v3 {'a' * 64}\nv2 {'b' * 64}\n"),
        ("63-hex digest", f"v1 {'a' * 63}\nv2 {'b' * 64}\n"),
        ("non-hex digest", f"v1 {'g' * 64}\nv2 {'b' * 64}\n"),
        ("v1 pinned twice", f"v1 {'a' * 64}\nv1 {'b' * 64}\nv2 {'b' * 64}\n"),
        ("v2 absent", f"v1 {'a' * 64}\n"),
        ("no records at all", "# nothing here\n"),
    ]
    for label, text in cases:
        p.write_text(text, encoding="ascii")
        _st_raises(state, f"pin parser: {label}", lambda: parse_pins(p), "verify-pin-record")


def self_test():
    state = {"cases": 0, "fails": 0}
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="granary-w3-selftest-"))
    try:
        tree = _selftest_append_only(state, tmp)
        _selftest_digest_fields(state, tmp, tree)
        _selftest_guards(state, tmp)
        _selftest_pins(state, tmp)
        _selftest_anchor(state, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if state["fails"]:
        print(f"SELF-TEST FAIL: {state['fails']} of {state['cases']} case(s) failed",
              file=sys.stderr)
        sys.exit(1)
    print(f"self-test: ok ({state['cases']} cases)")


def _version_arg(raw, name):
    try:
        return int(raw)
    except ValueError as e:
        raise Refusal(name, f"version must be 1 or 2, got {raw!r}") from e


USAGE = (
    "usage: gen-w3.py --build DIR {1|2} | --digest DIR | --verify DIR {1|2} | --self-test"
)


def main(argv):
    try:
        if len(argv) == 2 and argv[1] == "--self-test":
            self_test()
        elif len(argv) == 3 and argv[1] == "--digest":
            print(digest(argv[2]))
        elif len(argv) == 4 and argv[1] == "--build":
            build(argv[2], _version_arg(argv[3], "build-version"))
            print(f"{argv[2]} {digest(argv[2])}")
        elif len(argv) == 4 and argv[1] == "--verify":
            version = _version_arg(argv[3], "verify-version")
            got = verify(argv[2], version)
            print(f"{argv[2]} v{version}: matches {PIN_PATH} ({got})")
        else:
            print(USAGE, file=sys.stderr)
            return 2
    except Refusal as e:
        print(str(e), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
