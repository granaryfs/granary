#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
# UWASL dedup-bench cross-check, MODIFIED:
# - dedup.exe only (measure-variance has an ASan-proven stack overflow
# at >=18 KiB chunks; the python analysis script crashes on real dedup)
# - DIRECT set difference over hash.out, not the subtraction workaround
# - compare REALIZED distributions, never configured targets
# It validates our IMPLEMENTATION of FastCDC. It is the same lab as the
# calibration paper, so it validates neither the methodology nor the
# targets.
#
# WHAT THIS SCRIPT WRITES IS NOT A HARNESS RECORD. `--out` produces a JSON
# provenance record for an EXTERNAL tool: it carries no `ControlsPassed`
# token and never passes `report::write_record`'s gate (report.rs:4, "A
# result without its metadata does not exist"). It says so in its own
# `not_a_harness_record` field rather than imitating one.
set -euo pipefail
cd "$(dirname "$0")/../.."
DATA="${GRANARY_BENCH_DATA:-$HOME/.cache/granary-bench}"
SRC="$DATA/tools/dedup-bench"
PIN="bench/datasets/dedup-bench.pin"
# CITATIONS INTO THE REPO BELOW — dedup-bench, not granary — are written in prose, never as
# path + colon + line. granary has a root README.md of its own, so that form resolves to
# GRANARY's file and reads as a checked local citation. This binds upstream references ONLY:
# this file's citations into
# granary — the two in the header notes below — are correct, gate-checked, and must stay
# spelled as they are.
# Still spelled as path + colon + line, and surviving only because their extensions are outside
# the gate's set: the Makefile, .hpp and .cpp references below. They are upstream too — if those
# extensions are ever admitted, they are the sites to convert.
# (The two granary citations are named above without being spelled. A comment ABOUT the census
# that adds two duplicate citations TO the census is the same class it is warning about.)
REPO="https://github.com/UWASL/dedup-bench"
TAG="Stable"

# The three make-variable overrides are part of the recorded build
# configuration. Determine them on this machine, pass them here, and RECORD
# THEM in this comment before committing. Zero source edits are allowed;
# if a source edit seems necessary, STOP.
# RECORDED (authoritative copy lives in the pin,
# which is what this script actually reads; this comment is the required
# in-script record). All three are Apple Silicon Homebrew path fixes:
#   INCLUDE_PATH_OPENSSL=/opt/homebrew/opt/openssl@3/include
#   LD_FLAGS=-Wl,-L/opt/homebrew/opt/openssl@3/lib,-L/opt/homebrew/lib,-lcrypto,-lxxhash
#   EXTRA_COMPILER_FLAGS=-I/opt/homebrew/include
# dedup/build/Makefile:15 and :23 hardcode the Intel prefix /usr/local/opt,
# -lxxhash has no -L at all, and xxhash_hashing.hpp:16 includes "xxhash.h"
# with no include variable for it (Makefile:53's ${EXTRA_COMPILER_FLAGS} is
# the only hook). LD_FLAGS uses clang's -Wl, comma form because the pin
# validator below accepts only whitespace-free VAR=value tokens; it is the
# same two -L paths and the same two libraries.
MAKE_OVERRIDES=(${DEDUP_BENCH_MAKE_OVERRIDES:-})
# The build CONFIGURATION is part of what is pinned: a pin that fixes the
# source but lets the flags float does not describe the artifact that gets
# executed.
#
# ASSIGNED BY load_pin, OUT OF HEAD'S BLOB — see there. It is unavailable
# until the committed pin has been checked, so no WORKING-TREE value can be
# consumed before its provenance is established.
PINNED_OVERRIDES=""

# The chunker configuration IS part of the cross-check's definition, so it
# is a committed, pinned artifact — not an argument someone types, and NOT
# overridable by the environment: an env escape hatch would let the
# self-test and the real run both pass against an arbitrary config, which
# is exactly the control
# the pin exists to provide.
#
# MODE is the one exception to "not an argument someone types", and only
# because it chooses BETWEEN two hardcoded, committed, digest-pinned
# config paths rather than accepting either one as text: `legacy` (the
# default, unchanged behaviour — every existing invocation of this script
# keeps working verbatim) reads the original frozen config, `128k` reads the
# newer config at granary's current shipped tuple. Consumed here,
# before any function below is defined, so it can only ever be a plain
# `case`/`shift` — no `refuse` call is reachable yet, and none is needed:
# an unrecognised token here is simply left in place and falls through to
# the ordinary `--self-test`/`--older` parsing far below, which refuses it
# by the existing "unknown argument" path.
MODE="legacy"
case "${1:-}" in
  legacy | 128k) MODE="$1"; shift ;;
esac
case "$MODE" in
  legacy) CFG="bench/datasets/dedup-bench.config" ;;
  128k) CFG="bench/datasets/dedup-bench-128k.config" ;;
esac
# The pin-field suffix for this mode. `legacy` reads the ORIGINAL field
# names (`config_sha256`, `selftest_mean_lo`, `selftest_mean_hi`) exactly
# as defined — never renamed, never touched — and `128k` reads a
# second, purely-additive set the same load_pin/pin_field machinery
# already provides. The pin covers the build
# configuration too; this extends that same coverage to a second chunker
# configuration without touching the first.
case "$MODE" in
  legacy) PIN_SUFFIX="" ;;
  128k) PIN_SUFFIX="_128k" ;;
esac

# The self-test corpus is DETERMINISTIC (SHAKE-256 of a fixed seed
# string),
# not /dev/urandom, because one of its controls is a pinned realized-mean
# window and a fresh random corpus every run would make that window either
# meaningless or enormous. Changing either constant moves the realized mean
# and therefore fails the window — which is the intent.
SELFTEST_BYTES=134217728
SELFTEST_SEED_X="granary-t13-selftest-x"
SELFTEST_SEED_Y="granary-t13-selftest-y"

refuse() { printf 'REFUSING: %s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*" >&2; }

# "a pin that a human has ALREADY APPROVED" (see the comment above EXPECTED)
# is only true of a pin that is COMMITTED. Both the pin and the config are
# read from the WORKING TREE, so an uncommitted edit silently redefines what
# was approved — the commit to build, the make_overrides, the config digest,
# the self-test window — and the script then clones, compiles and EXECUTES
# it. `git diff` says nothing about an UNTRACKED file, so require the path to
# exist in HEAD FIRST, then require the working copy to match it. Same
# mechanism, same wording as fetch-w1.sh's verify_key.
# fetch-w1.sh and build-w2.sh carry the same check.
#
# COMPARE THE BYTES, NEVER THE STATUS. `git diff --quiet HEAD -- <path>`,
# `git status --porcelain` and every other porcelain answer is computed
# THROUGH THE INDEX, and `git update-index --assume-unchanged` (or
# --skip-worktree) tells git to presume the working file already matches its
# index entry — so an edited pin reads as CLEAN and the script goes on to
# consume the editor's `commit`, `make_overrides` and `config_sha256`
# believing HEAD approved them. With assume-unchanged set and the pin's
# commit id replaced, `git diff --quiet` can say clean and `git status
# --porcelain` can print nothing while the changed id remains readable. The
# index has no say in the comparison below: the working copy is compared
# with HEAD's blob directly.
assert_committed() { # <path> — the working copy must be BYTE-IDENTICAL to HEAD's
  git cat-file -e "HEAD:$1" 2>/dev/null ||
    refuse "$1 is not committed — commit it before relying on it"
  [ -f "$1" ] && [ -r "$1" ] ||
    refuse "$1 is in HEAD but is not a readable file in the working tree"
  git cat-file blob "HEAD:$1" 2>/dev/null | cmp -s - "$1" ||
    refuse "$1 differs from HEAD — commit it before relying on it"
}

# PARSE HEAD'S BLOB, NOT THE WORKING TREE. assert_committed proves the two are
# identical — but proving it and then parsing the OTHER copy is an ORDERING
# argument, and an ordering can be the wrong way round: extracting `commit` and
# `make_overrides` at file scope with the check running later, inside setup(),
# leaves a window. Narrowing that window is not closing it, and these are the fields
# whose entire purpose is that a human approved them. So read them out of
# `git cat-file blob HEAD:<path>` — the trusted source assert_committed already
# compares against — and "the bytes I acted on came from HEAD" is true BY
# CONSTRUCTION: it survives a reordering, a race between the check and the
# parse, and any future edit that moves either one. Demonstrated by defeating
# the byte comparison outright: the working-tree `commit` and `make_overrides`
# still never reach `make`, `git reset --hard` or any other command.
# The working-tree comparison STAYS: an operator who edits a pin and expects it
# to take effect must be refused loudly rather than silently
# ignored.
PIN_BLOB=""
CFG_BLOB=""

load_pin() {
  if ! git cat-file -e "HEAD:$PIN" 2>/dev/null; then
    # Not in HEAD. Either a genuine FIRST RUN — no pin anywhere, and setup()
    # then writes a stub and exits 2 without building — or a pin that exists
    # and has not been approved yet, which must never be read.
    if [ -e "$PIN" ]; then
      refuse "$PIN exists but is NOT COMMITTED — a pin records an approval only once it is in HEAD. Commit it (or delete it deliberately) before relying on it."
    fi
    return 0
  fi
  assert_committed "$PIN"
  PIN_BLOB="$(git cat-file blob "HEAD:$PIN")"
  EXPECTED="$(printf '%s\n' "$PIN_BLOB" | awk '/^commit /{print $2; exit}')"
  PINNED_OVERRIDES="$(printf '%s\n' "$PIN_BLOB" \
    | awk '/^make_overrides /{sub(/^make_overrides[ ]*/,""); print; exit}')"
}

# `field NAME` -> the rest of that pin line in HEAD'S blob, empty if absent.
pin_field() {
  [ -n "$PIN_BLOB" ] ||
    refuse "internal error: pin_field $1 called before load_pin read HEAD's $PIN"
  printf '%s\n' "$PIN_BLOB" | awk -v k="$1" '$1==k {sub(/^[^ \t]+[ \t]*/,""); print; exit}'
}

sha256_of() {
  python3 - "$1" <<'PY'
import hashlib, sys
h = hashlib.sha256()
with open(sys.argv[1], "rb") as fh:
    for block in iter(lambda: fh.read(1 << 20), b""):
        h.update(block)
print(h.hexdigest())
PY
}

# One walker, two modes, matching TWO different corpus definitions on
# purpose — that difference is the finding, not a detail.
#
# granary_*  regular files only, symlinks NEVER followed. This is what
# corpus.rs records (`symlink_metadata`; test
# `symlinks_are_recorded_not_followed`), so it is the file
# set our own numbers come from.
# dedup_*    what dedup.exe will actually chunk: it walks with
# recursive_directory_iterator (which does NOT descend into
# symlinked directories), skips anything `is_directory()`
# says is a directory (so a symlinked DIRECTORY contributes
# nothing), and opens everything else through ifstream —
# which FOLLOWS file symlinks and chunks the target.
#
# On the PostgreSQL two-commit corpus that difference is live: 4 symlinks per version directory carrying
# 598,808 B, ~2% of the tree, inside the 10% agreement band and therefore
# invisible to it. Both totals are reported for every tree.
#
# It REFUSES rather than skips — an unreadable file, a broken symlink, a
# fifo/socket/device — for the same reason corpus.rs does
# (corpus.rs:7-11):
# a silently skipped file is a silently wrong number. dedup.exe skips them
# with a stderr line and exits 0.
walker() {
  python3 - "$@" <<'PY'
import os, stat, sys

mode, root, min_grain = sys.argv[1], sys.argv[2], int(sys.argv[3])
farm = sys.argv[4] if len(sys.argv) > 4 else None

granary_files = granary_bytes = 0
symlinks = symlinks_to_dir = symlink_bytes = 0
dedup_files = dedup_bytes = 0
cdc_files = cdc_bytes = 0

def die(msg):
    sys.stderr.write("REFUSING: %s\n" % msg)
    raise SystemExit(1)

if not os.path.isdir(root):
    die("not a directory: %s" % root)

stack = [root]
while stack:
    d = stack.pop()
    try:
        entries = sorted(os.scandir(d), key=lambda e: e.name)
    except OSError as e:
        die("unreadable directory %s: %s" % (d, e))
    for e in entries:
        p = e.path
        st = os.lstat(p)
        if stat.S_ISDIR(st.st_mode):
            stack.append(p)
            continue
        if stat.S_ISLNK(st.st_mode):
            symlinks += 1
            try:
                tst = os.stat(p)
            except OSError as err:
                die("broken symlink %s: %s" % (p, err))
            if stat.S_ISDIR(tst.st_mode):
                # dedup.exe skips it AND does not descend into it, so
                # everything underneath is unmeasured. Disclosed, not
                # absorbed: the count is reported for every tree.
                symlinks_to_dir += 1
                continue
            if not stat.S_ISREG(tst.st_mode):
                die("symlink to a non-regular file: %s" % p)
            symlink_bytes += tst.st_size
            dedup_files += 1
            dedup_bytes += tst.st_size
            continue
        if not stat.S_ISREG(st.st_mode):
            die("not a regular file, symlink or directory: %s" % p)
        if not os.access(p, os.R_OK):
            die("unreadable file: %s" % p)
        granary_files += 1
        granary_bytes += st.st_size
        dedup_files += 1
        dedup_bytes += st.st_size
        if st.st_size >= min_grain:
            cdc_files += 1
            cdc_bytes += st.st_size
            if farm is not None:
                os.symlink(os.path.realpath(p), os.path.join(farm, "%08d.bin" % cdc_files))

if mode == "facts":
    print(" ".join(str(n) for n in (
        granary_files, granary_bytes, symlinks, symlinks_to_dir, symlink_bytes,
        dedup_files, dedup_bytes, cdc_files, cdc_bytes)))
elif mode == "farm":
    print("%d %d" % (cdc_files, cdc_bytes))
else:
    die("unknown walker mode %s" % mode)
PY
}

# A git TAG IS MUTABLE. Cloning it and then recording whatever it resolved
# to is trust-on-first-use AFTER the code has already been built and run —
# the pin protects nothing. So: resolve the sha with ls-remote (no code
# fetched, nothing executed), require it to equal a pin that a human has
# already approved, and only then clone and build.
# The approved commit is checked before any external code is fetched or run.
#
# ASSIGNED BY load_pin, OUT OF HEAD'S BLOB — see there. The approved
# commit id is not put into the shell's variables until its provenance
# is established, so a working-tree value is never consumed before the
# committed source has been checked.
EXPECTED=""

# Ask for the PEELED ref first and fall back to the lightweight one.
# Querying both at once and taking head -1 can return the annotated tag
# OBJECT rather than the commit it points at, which would then fail the
# rev-parse check below even though the tag never moved.
# The peeled annotated-tag ref must take precedence over its tag object.
resolve_remote_sha() {
  local sha
  sha="$(git ls-remote "$REPO" "refs/tags/$TAG^{}" | cut -f1)"
  [ -n "$sha" ] || sha="$(git ls-remote "$REPO" "refs/tags/$TAG" | cut -f1)"
  printf '%s\n' "$sha"
}

# Called before the fetch AND before each destructive operation, not once
# at the top: `fetch` contacts whatever remote the pre-existing clone
# names, and `reset --hard` + `clean -xdff` delete whatever is there.
# The frozen script checked identity on ONE of the two destructive paths
# and never before the fetch; the FIRST-RUN path (pin present, `commit`
# line absent — a truncated pin, or a checkout predating the pin) ran all
# three with no identity check at all and deleted a foreign clone's
# untracked files.
assert_src_identity() {
  [ -e "$SRC" ] || return 0
  [ -d "$SRC/.git" ] || refuse "$SRC exists and is not a git clone — refusing to touch it"
  local got
  got="$(git -C "$SRC" remote get-url origin 2>/dev/null || true)"
  [ "$got" = "$REPO" ] || {
    note "  origin: ${got:-<none>}"
    note "  wanted: $REPO"
    refuse "$SRC does not point at the pinned repository"
  }
}

# make_overrides reaches `make` as build-time variables, and make will
# happily accept SHELL=, CC= or LDFLAGS= — SHELL= alone executes an
# arbitrary script 54 times as the recipe shell while the build still
# succeeds and the self-test still prints ok (demonstrated by review).
# `commit` is anchored to the remote by the TAG-MOVED check; make_overrides
# is anchored to NOTHING, so it is the one approval-gated field an edit can
# change without tripping any other check. Hence a NAME allowlist as well
# as a value charset, and a refusal on duplicates.
# The allowlist covers variable names as well as values; syntax checks for
# quotes, globs and a missing `=` are not sufficient.
validate_overrides() {
  local tok name value shape seen=""
  # noglob: the word split below is deliberately unquoted, and without
  # this a value containing a glob character would be expanded against
  # the working directory BEFORE any of the checks could see it.
  set -f
  for tok in $1; do
    case "$tok" in
      *=*) ;;
      *) set +f; refuse "make_overrides token is not VAR=value: $tok" ;;
    esac
    name="${tok%%=*}"
    value="${tok#*=}"
    case "$name" in
      INCLUDE_PATH_OPENSSL | LD_FLAGS | EXTRA_COMPILER_FLAGS) ;;
      *)
        set +f
        refuse "make_overrides variable is not on the allowlist (INCLUDE_PATH_OPENSSL, LD_FLAGS, EXTRA_COMPILER_FLAGS): $name"
        ;;
    esac
    [ -n "$value" ] || { set +f; refuse "make_overrides value is empty: $tok"; }
    case "$value" in
      *[!A-Za-z0-9_,./@+=:-]*)
        set +f
        refuse "make_overrides value has a character outside [A-Za-z0-9_,./@+=:-]: $tok"
        ;;
    esac
    # A CHARSET IS NOT A SHAPE. The charset above excludes every shell
    # metacharacter — shell injection really is closed — but it ACCEPTS
    # `-B/tmp/x`, `-fplugin=/tmp/x.dylib` and `@/tmp/argfile`, and all three
    # make the compiler driver load and execute code of the writer's
    # choosing: `-B` adds a program search prefix, so the driver runs
    # `<dir>/ld` and `<dir>/as`; `-fplugin=` loads a plugin in-process; `@file`
    # reads whitespace-separated arguments from a file, which defeats the
    # single-token restriction the pin's own notes rest on. Each of the three
    # allowlisted variables has exactly ONE legitimate form, so match the
    # FORM. The shapes below admit every value in the committed pin and
    # nothing else.
    shape=""
    case "$name" in
      INCLUDE_PATH_OPENSSL) shape='^/[A-Za-z0-9_./@+-]+$' ;;
      EXTRA_COMPILER_FLAGS) shape='^-I/[A-Za-z0-9_./@+-]+$' ;;
      LD_FLAGS)             shape='^-Wl(,-L/[A-Za-z0-9_./@+-]+|,-l[A-Za-z0-9_.+-]+)+$' ;;
    esac
    # Fail CLOSED: a name added to the allowlist above without a shape here
    # would otherwise match the empty regex, which matches everything — the
    # allowlist would silently go back to being a charset check.
    [ -n "$shape" ] || {
      set +f
      refuse "make_overrides $name is allowlisted but has no value-shape rule — add one before allowlisting it"
    }
    [[ "$value" =~ $shape ]] || {
      set +f
      refuse "make_overrides $name does not have this variable's one legitimate form ($shape): $tok"
    }
    case " $seen " in
      *" $name "*) set +f; refuse "make_overrides names $name twice" ;;
    esac
    seen="$seen $name"
  done
  set +f
}

# The config is READ FROM THE WORKING TREE at every use, so nothing but a
# digest ties the numbers to the approved configuration. Every mutation
# below left BOTH set-identity controls green while moving the published
# realized mean from -59% to +375%: buffer_size 8 MiB -> 1 MiB, min == max
# (FastCDC degenerates to whole-file and "disjoint trees give ALL novel"
# is satisfied by a single chunk), avg -> 4 KiB, normalization 1 -> 3.
# The controls are set-identity properties that hold for ANY deterministic
# content-defined chunker at any parameters, so they are structurally
# blind to this file.
# Same rule as pin_field: the VALUES come out of HEAD's blob, so no ordering
# argument is needed for them. The config FILE is still what dedup.exe is
# handed — it needs a path, and the record names that path — and it is tied to
# HEAD by assert_committed plus the pin's config_sha256, re-checked by
# assert_config immediately before every dedup.exe invocation.
cfg_num() {
  [ -n "$CFG_BLOB" ] ||
    refuse "internal error: cfg_num $1 called before assert_config read HEAD's $CFG"
  printf '%s\n' "$CFG_BLOB" | awk -F= -v k="$1" '$1==k {gsub(/[ \t\r]/,"",$2); print $2; exit}'
}
assert_config() {
  [ -f "$CFG" ] || refuse "missing pinned config for mode $MODE: restore the committed file at $CFG"
  # The digest below proves the config matches the PIN; it says nothing about
  # whether either was approved. Both are working-tree files, and a co-edit of
  # config + config_sha256 keeps the digest green — which is exactly the
  # mutation the pin's own calibration notes describe. Only HEAD anchors them.
  assert_committed "$CFG"
  CFG_BLOB="$(git cat-file blob "HEAD:$CFG")"
  local want got
  want="$(pin_field "config_sha256$PIN_SUFFIX")"
  [ -n "$want" ] || refuse "the pin records no config_sha256$PIN_SUFFIX — the configuration is unpinned (mode $MODE)"
  got="$(sha256_of "$CFG")"
  [ "$got" = "$want" ] || {
    note "  pinned: $want"
    note "  actual: $got"
    refuse "CONFIG NOT AS PINNED: $CFG has been edited since the pin was approved"
  }
  local buf min avg max algo out
  buf="$(cfg_num buffer_size)"
  min="$(cfg_num fastcdc_min_block_size)"
  avg="$(cfg_num fastcdc_avg_block_size)"
  max="$(cfg_num fastcdc_max_block_size)"
  algo="$(cfg_num chunking_algo)"
  out="$(cfg_num output_file)"
  [ "$algo" = "fastcdc" ] || refuse "config chunking_algo is '$algo', not fastcdc"
  [ "$out" = "hash.out" ] || refuse "config output_file is '$out'; this script reads hash.out"
  # chunking_common.cpp's chunk_stream caps a chunk at the stream buffer,
  # so a buffer below the max block size silently truncates every large
  # chunk at the buffer boundary. The config file states this as a MUST
  # and nothing enforced it.
  [ "$buf" -ge "$max" ] ||
    refuse "config buffer_size ($buf) < fastcdc_max_block_size ($max): every large chunk would be truncated at the buffer boundary"
  # min == max makes FastCDC degenerate to whole-file chunking, which both
  # set-identity controls accept with a single chunk.
  [ "$min" -lt "$max" ] || refuse "config fastcdc_min_block_size ($min) >= fastcdc_max_block_size ($max): FastCDC would degenerate to whole-file"
  [ "$min" -le "$avg" ] && [ "$avg" -le "$max" ] ||
    refuse "config block sizes are not ordered min <= avg <= max ($min, $avg, $max)"
}

setup() {
  local remote
  # BEFORE the network, and before anything is cloned, built or executed: a
  # pin only records an approval if it is committed, so load_pin checks that
  # FIRST and only then parses HEAD's blob for `commit` and `make_overrides`.
  # It leaves both empty on the documented FIRST-RUN path — no pin in HEAD and
  # none in the working tree — and the branch below then writes a stub and
  # exits 2 without building anything.
  load_pin
  remote="$(resolve_remote_sha)"
  [ -n "$remote" ] || refuse "could not resolve $TAG at $REPO"
  if [ -z "$EXPECTED" ]; then
    # NEVER overwrite an existing pin. The frozen script wrote a 4-line
    # stub over a 35-line human-approved pin — every override and the
    # whole supply-chain approval record — and exited 2, which reads as
    # ordinary first-run behaviour. A pin that exists but records no
    # commit is a damaged pin, not a first run.
    # Reaching here with the file present means load_pin found it in HEAD,
    # byte-identical to the working copy, and HEAD's own bytes carry no
    # `commit` line: an APPROVED but damaged pin. (An UNCOMMITTED pin never
    # gets this far — load_pin refuses it by name.)
    if [ -e "$PIN" ]; then
      refuse "$PIN is committed but records no 'commit' line. Refusing to overwrite it; restore it from git or delete it deliberately."
    fi
    assert_src_identity
    { echo "# UWASL dedup-bench, pinned. $REPO"
      echo "tag $TAG"
      echo "commit $remote"
      echo "make_overrides <unset>   # <-- RECORD the overrides here, then commit"
      echo "config_sha256 <unset>    # <-- sha256 of bench/datasets/dedup-bench.config"
      echo "selftest_mean_lo <unset> # <-- realized-mean window for the self-test corpus"
      echo "selftest_mean_hi <unset>"
    } > "$PIN"
    # Clone (but do NOT build) so the overrides can be determined from the
    # real Makefile before anything is approved. Cloning fetches code; it
    # does not execute it. Doing this now keeps the task to TWO gated
    # commits instead of three; no external code is built before approval.
    if [ ! -d "$SRC/.git" ]; then
      mkdir -p "$(dirname "$SRC")"
      git clone "$REPO" "$SRC"
    fi
    assert_src_identity
    git -C "$SRC" fetch --tags origin
    assert_src_identity
    git -C "$SRC" reset -q --hard "$remote"
    assert_src_identity
    git -C "$SRC" clean -xdffq
    note "FIRST RUN: wrote $PIN with commit $remote, and checked the tree out"
    note "at $SRC WITHOUT building it. Review the commit, determine the make"
    note "overrides from its Makefile, write them into the pin's"
    note "make_overrides line, record the config sha256 and the self-test"
    note "mean window, commit the pin, then re-run."
    exit 2
  fi
  if [ "$remote" != "$EXPECTED" ]; then
    note "TAG MOVED: $TAG now resolves to $remote, pin says $EXPECTED."
    refuse "the pinned commit no longer matches the tag. STOP and ask the controller."
  fi
  case "$PINNED_OVERRIDES" in
    "" | "<unset>" | "<none recorded>")
      note "The pin does not record make_overrides. Determine them on this"
      note "machine, write them into $PIN, commit, and re-run."
      exit 2
      ;;
  esac
  # The PIN is the source of truth; the env var exists only so a first
  # build can be tried before the pin records it. Unset means "use the
  # pinned line", which is what every later run wants — an ordinary run
  # must not have to re-supply it. An unset environment override therefore
  # means "use the pinned value", not "reject the invocation".
  if [ -n "${DEDUP_BENCH_MAKE_OVERRIDES:-}" ] \
    && [ "$DEDUP_BENCH_MAKE_OVERRIDES" != "$PINNED_OVERRIDES" ]; then
    note "BUILD CONFIG NOT AS PINNED:"
    note "  pinned: $PINNED_OVERRIDES"
    note "  given:  $DEDUP_BENCH_MAKE_OVERRIDES"
    refuse "the pin covers the build configuration too"
  fi
  validate_overrides "$PINNED_OVERRIDES"
  set -f
  MAKE_OVERRIDES=($PINNED_OVERRIDES)
  set +f
  assert_config
  assert_src_identity
  if [ ! -d "$SRC/.git" ]; then
    mkdir -p "$(dirname "$SRC")"
    git clone "$REPO" "$SRC"
  fi
  assert_src_identity
  git -C "$SRC" fetch --tags origin
  # HEAD alone is not enough: a pre-existing clone can sit at the pinned
  # commit with modified tracked files or untracked build inputs, and make
  # would then build content nobody approved. Force the worktree to the
  # pinned tree and prove it is clean before any build begins.
  assert_src_identity
  git -C "$SRC" reset -q --hard "$EXPECTED"
  assert_src_identity
  git -C "$SRC" clean -xdffq
  [ "$(git -C "$SRC" rev-parse HEAD)" = "$EXPECTED" ] ||
    refuse "checkout did not land on the pinned commit"
  [ -z "$(git -C "$SRC" status --porcelain)" ] ||
    refuse "worktree is dirty after reset/clean — refusing to build"
  # bash 3.2 (the /bin/bash macOS ships) treats an empty array under set -u
  # as unbound, so expand it defensively.
  # The repo is NOT flat: there is no root Makefile. The canonical build is
  # `make` run in build/ (lines 92-94 of THAT repo's README, and its
  # .github/workflows/makefile.yml, at the pinned commit above), and
  # dedup/build/Makefile links dedup.exe then
  # copies it to ../../build/dedup.exe. These are the two build paths used
  # below.
  (cd "$SRC/build" && make ${MAKE_OVERRIDES[@]+"${MAKE_OVERRIDES[@]}"} >/dev/null)
  [ -x "$SRC/build/dedup.exe" ] || refuse "dedup.exe not built"
}

abspath() { (cd "$(dirname "$1")" > /dev/null && printf '%s/%s\n' "$PWD" "$(basename "$1")"); }

# hashes_of DIR CONFIG OUTFILE -> OUTFILE gets one chunk hash per line.
# Sets RUN_CHUNKS, RUN_BYTES, RUN_MEAN and the WALK_* facts for DIR.
#
# dedup.exe writes hash.out into its WORKING directory, so we run it in a
# scratch dir — which means both arguments must be absolutised FIRST.
# Relative paths would be resolved inside the scratch working directory, so
# both arguments are made absolute before dedup.exe is launched there.
hashes_of() {
  local dir cfg out work lines sumsz
  # EXISTENCE FIRST, then absolutise. abspath cds into the PARENT directory,
  # so when the parent is missing the `cd` fails, the command substitution
  # fails with it, and errexit kills the script right here — a bare
  # `cd: no such file or directory` and exit 1, with the named refusal below
  # never reached. A missing LEAF took the guard and exited 3, so the two
  # spellings of "that corpus is not there" did not look alike
  # when executed with a missing parent and a missing leaf.
  [ -e "$1" ] || refuse "no such corpus: $1"
  [ -f "$2" ] || refuse "no such config: $2"
  dir="$(abspath "$1")"
  cfg="$(abspath "$2")"
  out="$3"
  assert_config
  walk_facts "$dir"
  work="$(mktemp -d)"
  # ARGUMENT ORDER: `dedup.exe <corpus-dir> <config-file>`, confirmed by
  # the self-test, which is the first thing that ever runs it.
  (cd "$work" && "$SRC/build/dedup.exe" "$dir" "$cfg" > stdout.txt 2> stderr.txt) ||
    { rm -rf "$work"; refuse "dedup.exe failed on $dir"; }
  # dedup.exe SKIPS what it cannot open — "Failed to open X for reading",
  # stderr, exit 0 — and measures the rest. An unreadable file in the OLD
  # tree turned an identical pair into 4/6 novel chunks with no signal
  # anywhere. Refuse on any diagnostic instead of relying on a `cat` in an
  # unrelated pipeline to trip pipefail.
  if [ -s "$work/stderr.txt" ]; then
    note "dedup.exe wrote to stderr while chunking $dir:"
    sed 's/^/  /' "$work/stderr.txt" >&2
    rm -rf "$work"
    refuse "dedup.exe skipped at least one entry; the measurement would cover part of the tree"
  fi
  [ -s "$work/hash.out" ] || { rm -rf "$work"; refuse "dedup.exe produced no hash.out for $dir"; }
  RUN_CHUNKS="$(awk -F': ' '/^Total number of chunks: /{print $2; exit}' "$work/stdout.txt")"
  RUN_BYTES="$(awk -F': ' '/^Total bytes chunked: /{print $2; exit}' "$work/stdout.txt")"
  [ -n "$RUN_CHUNKS" ] && [ -n "$RUN_BYTES" ] ||
    { rm -rf "$work"; refuse "dedup.exe printed no chunk/byte totals for $dir"; }
  # COVERAGE. `[ -s hash.out ]` and `total > 0` are satisfied by ONE
  # chunk,
  # and a per-chunk mean is structurally incapable of detecting truncation:
  # a tree measured at 10% of its size passed every guard the frozen script
  # had. These three equalities are the check, and dedup.exe already prints
  # the two numbers they need — the frozen script threw them away with
  # `>/dev/null`. They also close `out_file.close()` being unchecked
  # (driver.cpp:101), where a full disk truncates hash.out and exits 0.
  lines="$(wc -l < "$work/hash.out" | tr -d ' ')"
  [ "$RUN_CHUNKS" = "$lines" ] ||
    { rm -rf "$work"; refuse "dedup.exe counted $RUN_CHUNKS chunks but hash.out holds $lines lines (truncated output)"; }
  # hash.out is `<hexhash>,<size>` (chunking_common.cpp:62), so the sizes
  # are on the floor too: they must sum to the byte total.
  sumsz="$(awk -F, '{s+=$2} END{printf "%d\n", s}' "$work/hash.out")"
  [ "$RUN_BYTES" = "$sumsz" ] ||
    { rm -rf "$work"; refuse "dedup.exe chunked $RUN_BYTES bytes but hash.out's sizes sum to $sumsz"; }
  [ "$RUN_BYTES" = "$WALK_DEDUP_BYTES" ] ||
    { rm -rf "$work"; refuse "dedup.exe chunked $RUN_BYTES bytes; an independent walk of $dir says it should have chunked $WALK_DEDUP_BYTES"; }
  # FIELD 1 OF A COMMA-DELIMITED LINE. The frozen script's `awk '{print
  # $1}'` split on whitespace, so it took the WHOLE `hash,size` line while
  # its comment claimed it was taking the hash — the protection it
  # described was never in force.
  awk -F, '{print $1}' "$work/hash.out" > "$out"
  RUN_MEAN=0
  [ "$RUN_CHUNKS" -gt 0 ] && RUN_MEAN=$((RUN_BYTES / RUN_CHUNKS))
  # BOTH statistics, because ours are reported both ways too and a
  # comparison must be like for like: `realized_mean_span` is
  # raw-to-raw,
  # `realized_mean_grain` is unique-to-unique. hash.out's second field is
  # the chunk size, so the unique-side numbers are already on the floor.
  sort -u "$work/hash.out" > "$work/uniq"
  RUN_UNIQUE_CHUNKS="$(wc -l < "$work/uniq" | tr -d ' ')"
  RUN_UNIQUE_BYTES="$(awk -F, '{s+=$2} END{printf "%d\n", s}' "$work/uniq")"
  RUN_MEAN_UNIQUE=0
  [ "$RUN_UNIQUE_CHUNKS" -gt 0 ] && RUN_MEAN_UNIQUE=$((RUN_UNIQUE_BYTES / RUN_UNIQUE_CHUNKS))
  rm -rf "$work"
}

# walk_facts DIR -> WALK_* for DIR, and the stamp cross-check.
walk_facts() {
  local dir facts stamp base sfiles sbytes ssyms
  dir="$1"
  facts="$(walker facts "$dir" "$MIN_GRAIN")" || exit 1
  read -r WALK_FILES WALK_BYTES WALK_SYMLINKS WALK_SYMLINK_DIRS WALK_SYMLINK_BYTES \
    WALK_DEDUP_FILES WALK_DEDUP_BYTES WALK_CDC_FILES WALK_CDC_BYTES <<< "$facts"
  # A pinned corpus carries a stamp written by its own fetch/build script.
  # Checking the walk against it is the one coverage check that is
  # independent of both this script and dedup.exe.
  base="$(basename "$dir")"
  stamp="$(dirname "$dir")/.stamp-$base"
  WALK_STAMP="none"
  WALK_CORPUS_SHA="none"
  if [ -f "$stamp" ]; then
    WALK_STAMP="$stamp"
    WALK_CORPUS_SHA="$(awk '/^sha256 /{print $2; exit}' "$stamp")"
    sfiles="$(awk '/^files /{print $2; exit}' "$stamp")"
    sbytes="$(awk '/^bytes /{print $2; exit}' "$stamp")"
    [ -n "$sbytes" ] || sbytes="$(awk '/^file_bytes /{print $2; exit}' "$stamp")"
    ssyms="$(awk '/^symlinks /{print $2; exit}' "$stamp")"
    [ -z "$sfiles" ] || [ "$sfiles" = "$WALK_FILES" ] ||
      refuse "$dir holds $WALK_FILES files, its stamp says $sfiles — the tree is not the pinned corpus"
    [ -z "$sbytes" ] || [ "$sbytes" = "$WALK_BYTES" ] ||
      refuse "$dir holds $WALK_BYTES file bytes, its stamp says $sbytes — the tree is not the pinned corpus"
    [ -z "$ssyms" ] || [ "$ssyms" = "$WALK_SYMLINKS" ] ||
      refuse "$dir holds $WALK_SYMLINKS symlinks, its stamp says $ssyms"
  else
    note "note: no stamp beside $dir — corpus identity is unverified for this tree"
  fi
}

# cdc_split DIR -> CDC_CHUNKS, CDC_MEAN over the files >= MIN_GRAIN only.
#
# WHY: on the Rust 1.97.0 toolchain corpus, 65,592 of 65,789 files (99.70%) are below MIN_GRAIN
# and
# become ONE whole-file chunk each, so 98.6% of all chunks never touch the
# chunker and any correct implementation produces them identically by
# construction. The whole-tree realized mean tracks the corpus's mean FILE
# size, not the cutter's behaviour. The CDC-relevant subset is 197 files and
# 72.4% of the bytes, and that is where the two implementations can actually
# disagree. The whole-tree numbers stay — they are just not the validation.
#
# The farm is symlinks to the selected files: dedup.exe follows file
# symlinks, so it chunks exactly the same bytes, and the selection is
# granary's own file set (regular files only, symlinks excluded), so this
# comparison is symlink-clean on both sides by construction.
cdc_split() {
  local dir farm counted out
  dir="$1"
  CDC_FILES=0
  CDC_BYTES=0
  CDC_CHUNKS=0
  CDC_MEAN=0
  CDC_UNIQUE_CHUNKS=0
  CDC_MEAN_UNIQUE=0
  farm="$(mktemp -d)"
  counted="$(walker farm "$dir" "$MIN_GRAIN" "$farm")" || { rm -rf "$farm"; exit 1; }
  read -r CDC_FILES CDC_BYTES <<< "$counted"
  if [ "$CDC_FILES" -gt 0 ]; then
    out="$(mktemp)"
    hashes_of "$farm" "$CFG" "$out"
    CDC_CHUNKS="$RUN_CHUNKS"
    CDC_MEAN="$RUN_MEAN"
    CDC_UNIQUE_CHUNKS="$RUN_UNIQUE_CHUNKS"
    CDC_MEAN_UNIQUE="$RUN_MEAN_UNIQUE"
    rm -f "$out"
  fi
  rm -rf "$farm"
}

# crosscheck OLD NEW [expect]
#   expect: "zero" | "all" | "report" (default). The self-test's controls are
#   ASSERTIONS — a control that only prints
#   is not a control.
crosscheck() {
  local old="$1" new="$2" expect="${3:-report}"
  local a b braw novel total raw_total
  a="$(mktemp)"; b="$(mktemp)"; braw="$(mktemp)"
  hashes_of "$old" "$CFG" "$braw"
  sort -u "$braw" > "$a"
  OLD_FILES="$WALK_FILES"; OLD_BYTES="$WALK_BYTES"; OLD_SYMLINKS="$WALK_SYMLINKS"
  OLD_SYMLINK_DIRS="$WALK_SYMLINK_DIRS"; OLD_SYMLINK_BYTES="$WALK_SYMLINK_BYTES"
  OLD_DEDUP_BYTES="$WALK_DEDUP_BYTES"; OLD_CHUNKS="$RUN_CHUNKS"
  OLD_STAMP="$WALK_STAMP"; OLD_CORPUS_SHA="$WALK_CORPUS_SHA"
  # RAW first, then unique: the two counts answer different questions and
  # conflating them corrupts the realized mean: a mean computed over UNIQUE
  # chunks is not a chunk-size distribution. The numerator and denominator
  # below therefore use every emitted chunk.
  hashes_of "$new" "$CFG" "$braw"
  sort -u "$braw" > "$b"
  novel="$(comm -13 "$a" "$b" | wc -l | tr -d ' ')"  # unique, in NEW not in OLD
  total="$(wc -l < "$b" | tr -d ' ')"                # unique chunks in NEW
  raw_total="$RUN_CHUNKS"                            # every chunk emitted
  rm -f "$a" "$b" "$braw"
  NEW_FILES="$WALK_FILES"; NEW_BYTES="$WALK_BYTES"; NEW_SYMLINKS="$WALK_SYMLINKS"
  NEW_SYMLINK_DIRS="$WALK_SYMLINK_DIRS"; NEW_SYMLINK_BYTES="$WALK_SYMLINK_BYTES"
  NEW_DEDUP_BYTES="$WALK_DEDUP_BYTES"; NEW_CDC_FILES="$WALK_CDC_FILES"
  NEW_CDC_BYTES="$WALK_CDC_BYTES"
  NEW_STAMP="$WALK_STAMP"; NEW_CORPUS_SHA="$WALK_CORPUS_SHA"
  # Realized MEAN CHUNK SIZE = bytes dedup.exe actually chunked / every
  # chunk it emitted. Both numbers come from dedup.exe's own totals, so
  # they cannot disagree about what was in the tree: the frozen script
  # divided a `find -type f` byte count (symlinks excluded) by a chunk
  # count that INCLUDED the symlinked content, and reported exactly half
  # the true mean on a tree with one symlink.
  NOVEL_UNIQUE="$novel"; UNIQUE_CHUNKS="$total"; RAW_CHUNKS="$raw_total"
  REALIZED_MEAN="$RUN_MEAN"
  REALIZED_MEAN_UNIQUE="$RUN_MEAN_UNIQUE"
  # Two independent counts of the same thing: `total` counts distinct
  # HASHES, `RUN_UNIQUE_CHUNKS` counts distinct `hash,size` lines. They can
  # only differ if one hash carried two different sizes.
  [ "$total" = "$RUN_UNIQUE_CHUNKS" ] ||
    refuse "$total distinct hashes but $RUN_UNIQUE_CHUNKS distinct hash,size lines — one hash carried two sizes"
  echo "dedup-bench: novel_unique=$novel unique_chunks=$total raw_chunks=$raw_total realized_mean=$REALIZED_MEAN realized_mean_unique=$REALIZED_MEAN_UNIQUE expect=$expect"
  echo "dedup-bench: newer tree: granary_files=$NEW_FILES granary_bytes=$NEW_BYTES symlinks=$NEW_SYMLINKS (to_dir=$NEW_SYMLINK_DIRS) symlink_bytes=$NEW_SYMLINK_BYTES dedup_bytes=$NEW_DEDUP_BYTES"
  [ "$total" -gt 0 ] || refuse "zero chunks — dedup.exe produced nothing"
  case "$expect" in
    zero) [ "$novel" -eq 0 ] || refuse "identical trees gave $novel novel chunks" ;;
    all) [ "$novel" -eq "$total" ] || refuse "disjoint trees gave $novel/$total novel" ;;
    report) ;;
    *) refuse "unknown expectation $expect" ;;
  esac
}

# --- the provenance record (NOT a harness record) ----------------------
rec_put() { printf '%s\t%s\n' "$1" "$2" >> "$REC"; }
rec_write() {
  python3 - "$REC" "$1" <<'PY'
import json, os, sys
src, out = sys.argv[1], sys.argv[2]
record = {}
for line in open(src):
    line = line.rstrip("\n")
    if not line:
        continue
    key, _, value = line.partition("\t")
    listy = key.endswith("[]")
    if listy:
        key = key[:-2]
    if value.lstrip("-").isdigit():
        value = int(value)
    parts = key.split(".")
    node = record
    for p in parts[:-1]:
        node = node.setdefault(p, {})
    if listy:
        node.setdefault(parts[-1], []).append(value)
    else:
        node[parts[-1]] = value
d = os.path.dirname(out)
if d:
    os.makedirs(d, exist_ok=True)
with open(out, "w") as fh:
    json.dump(record, fh, indent=2)
    fh.write("\n")
print("cross-check record written to %s" % out)
PY
}

provenance() {
  local exe line p
  exe="$SRC/build/dedup.exe"
  rec_put kind external-cross-check
  rec_put mode "$MODE"
  rec_put not_a_harness_record "This is NOT a granary-bench result record: no ControlsPassed token, never passed report::write_record's gate. It is the provenance of an EXTERNAL tool run."
  rec_put tool "UWASL dedup-bench dedup.exe"
  rec_put validates "our implementation of FastCDC — same lab as the calibration paper, so neither the methodology nor the targets"
  rec_put dedup_bench.repo "$REPO"
  rec_put dedup_bench.tag "$TAG"
  rec_put dedup_bench.commit "$EXPECTED"
  rec_put dedup_bench.make_overrides "$PINNED_OVERRIDES"
  rec_put dedup_bench.pin "$PIN"
  rec_put dedup_bench.pin_sha256 "$(sha256_of "$PIN")"
  rec_put dedup_bench.exe_sha256 "$(sha256_of "$exe")"
  rec_put config.path "$CFG"
  rec_put config.sha256 "$(sha256_of "$CFG")"
  for p in chunking_algo hashing_algo buffer_size fastcdc_min_block_size \
    fastcdc_avg_block_size fastcdc_max_block_size fastcdc_normalization_level \
    fastcdc_disable_normalization simd_mode; do
    rec_put "config.$p" "$(cfg_num "$p")"
  done
  rec_put granary.git_sha "$(git rev-parse HEAD)"
  rec_put granary.worktree_dirty "$([ -n "$(git status --porcelain)" ] && echo yes || echo no)"
  # The floor the EXTERNAL tool cuts at comes from the pinned config.
  # It holds the external tool's floor, and granary never runs inside this
  # script, so the key is `comparison.floor_bytes`, outside the granary
  # namespace. Comparability requires the matching granary-bench record's
  # `cdc_relevant.min_grain_bytes` to EQUAL this
  # recorded external-tool
  # value (see the compare_with.* keys) — recorded from the config, so
  # the record states what was actually run either way.
  rec_put comparison.floor_bytes "$MIN_GRAIN"
  rec_put machine.cpu "$(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m)"
  rec_put machine.os "$(uname -s) $(sw_vers -productVersion 2>/dev/null || uname -r)"
  rec_put toolchain.cxx "$(c++ --version 2>/dev/null | head -1)"
  rec_put toolchain.make "$(make --version 2>/dev/null | head -1)"
  # hashing_algo=xxhash128 means the chunk identities come from a FLOATING
  # Homebrew libxxhash, and -lcrypto from a floating openssl@3. Record what
  # the binary actually loads, with digests: the dylib path alone does not
  # identify the code.
  # `NR>1`: otool's first line is the binary's own path.
  while read -r p; do
    [ -n "$p" ] || continue
    if [ -f "$p" ]; then
      rec_put "toolchain.linked[]" "$p sha256=$(sha256_of "$p")"
    else
      rec_put "toolchain.linked[]" "$p (not a file on disk; dyld shared cache)"
    fi
  done <<< "$(otool -L "$exe" 2>/dev/null | awk 'NR>1 {print $1}' || true)"
}

MIN_GRAIN=0

setup
# MIN_GRAIN is the chunker's own configured minimum block size, taken from
# the pinned config rather than re-literalled here: a file below it cannot
# be cut and becomes one whole-file chunk in either implementation.
MIN_GRAIN="$(cfg_num fastcdc_min_block_size)"

case "${1:-}" in
  --self-test)
    # No positional config: the self-test uses the pinned $CFG, so the
    # documented `--self-test` invocation works as written without a
    # positional config argument.
    T="$(mktemp -d)"
    trap 'rm -rf "$T"' EXIT
    mkdir -p "$T/x" "$T/y"
    python3 - "$T/x/a.bin" "$SELFTEST_SEED_X" "$SELFTEST_BYTES" <<'PY'
import hashlib, sys
open(sys.argv[1], "wb").write(hashlib.shake_256(sys.argv[2].encode()).digest(int(sys.argv[3])))
PY
    python3 - "$T/y/a.bin" "$SELFTEST_SEED_Y" "$SELFTEST_BYTES" <<'PY'
import hashlib, sys
open(sys.argv[1], "wb").write(hashlib.shake_256(sys.argv[2].encode()).digest(int(sys.argv[3])))
PY
    echo "== identical trees: novel must be 0"
    crosscheck "$T/x" "$T/x" zero
    MEAN_X="$REALIZED_MEAN"
    echo "== disjoint trees: novel must equal total"
    crosscheck "$T/x" "$T/y" all
    MEAN_Y="$REALIZED_MEAN"
    # THE PARAMETER-SENSITIVE CONTROL. The two above are set-identity
    # properties: they hold for ANY deterministic content-defined chunker
    # at ANY parameters, so they cannot see the configuration at all.
    # This
    # one can — the corpus is fixed, so the realized mean is a function of
    # the chunker and its parameters and nothing else.
    LO="$(pin_field "selftest_mean_lo$PIN_SUFFIX")"
    HI="$(pin_field "selftest_mean_hi$PIN_SUFFIX")"
    case "$LO$HI" in
      "" | *"<unset>"*) refuse "the pin records no self-test realized-mean window for mode $MODE (selftest_mean_lo$PIN_SUFFIX/selftest_mean_hi$PIN_SUFFIX)" ;;
    esac
    echo "== realized mean must land in the pinned window [$LO, $HI]"
    for m in "$MEAN_X" "$MEAN_Y"; do
      [ "$m" -ge "$LO" ] && [ "$m" -le "$HI" ] ||
        refuse "self-test realized mean $m is outside the pinned window [$LO, $HI] — the chunker or its configuration is not the pinned one"
    done
    echo "self-test realized means: x=$MEAN_X y=$MEAN_Y"
    # Recording an executable hash without checking it gates nothing:
    # the self-test and the measurement run must
    # have used byte-identical external executables, or the run is
    # invalid. Nothing here compares the two — that comparison happens
    # OUTSIDE this process, across two separate invocations — but both
    # must print the hash so it CAN be compared, and this is the only
    # place the self-test path had a `dedup.exe` built and never said so.
    echo "dedup-bench: exe_sha256=$(sha256_of "$SRC/build/dedup.exe")"
    echo "dedup-bench self-test (mode $MODE): ok"
    exit 0
    ;;
esac

# EXPLICIT --older/--newer. Positionally, `... v2 v1` ran happily and put
# the realized mean 3.9% from the correct value — inside the 10%
# agreement
# band, so a reversal could not be seen in the published number.
OLDER=""; NEWER=""; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --older) OLDER="${2:-}"; shift 2 ;;
    --newer) NEWER="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    *) refuse "unknown argument '$1' (usage: $0 --older DIR --newer DIR --out FILE, or --self-test)" ;;
  esac
done
if [ -z "$OLDER" ] || [ -z "$NEWER" ] || [ -z "$OUT" ]; then
  note "usage: $0 --older DIR --newer DIR --out FILE      (or --self-test)"
  note "the pin is already approved; this run needs the two corpora and a"
  note "path for the provenance record"
  exit 2
fi

REC="$(mktemp)"
trap 'rm -f "$REC"' EXIT
crosscheck "$OLDER" "$NEWER"
cdc_split "$NEWER"
CDC_PCT=0
[ "$NEW_BYTES" -gt 0 ] && CDC_PCT=$((NEW_CDC_BYTES * 100 / NEW_BYTES))
echo "dedup-bench: CDC-relevant (files >= $MIN_GRAIN B): files=$NEW_CDC_FILES bytes=$NEW_CDC_BYTES (${CDC_PCT}% of tree) chunks=$CDC_CHUNKS realized_mean=$CDC_MEAN unique_chunks=$CDC_UNIQUE_CHUNKS realized_mean_unique=$CDC_MEAN_UNIQUE"

provenance
rec_put older.path "$OLDER"
rec_put older.stamp "$OLD_STAMP"
rec_put older.corpus_sha256 "$OLD_CORPUS_SHA"
rec_put older.granary_files "$OLD_FILES"
rec_put older.granary_bytes "$OLD_BYTES"
rec_put older.symlinks "$OLD_SYMLINKS"
rec_put older.symlinks_to_dir "$OLD_SYMLINK_DIRS"
rec_put older.symlink_target_bytes "$OLD_SYMLINK_BYTES"
rec_put older.dedup_visible_bytes "$OLD_DEDUP_BYTES"
rec_put older.raw_chunks "$OLD_CHUNKS"
rec_put newer.path "$NEWER"
rec_put newer.stamp "$NEW_STAMP"
rec_put newer.corpus_sha256 "$NEW_CORPUS_SHA"
rec_put newer.granary_files "$NEW_FILES"
rec_put newer.granary_bytes "$NEW_BYTES"
rec_put newer.symlinks "$NEW_SYMLINKS"
rec_put newer.symlinks_to_dir "$NEW_SYMLINK_DIRS"
rec_put newer.symlink_target_bytes "$NEW_SYMLINK_BYTES"
rec_put newer.dedup_visible_bytes "$NEW_DEDUP_BYTES"
rec_put whole_tree.novel_unique_chunks "$NOVEL_UNIQUE"
rec_put whole_tree.unique_chunks "$UNIQUE_CHUNKS"
rec_put whole_tree.raw_chunks "$RAW_CHUNKS"
rec_put whole_tree.bytes_chunked "$NEW_DEDUP_BYTES"
rec_put whole_tree.realized_mean_raw "$REALIZED_MEAN"
rec_put whole_tree.realized_mean_unique "$REALIZED_MEAN_UNIQUE"
rec_put whole_tree.caveat "Dominated by files below the chunker's minimum block size, which become one whole-file chunk each in ANY implementation. Not the validation; see cdc_relevant."
rec_put cdc_relevant.min_grain_bytes "$MIN_GRAIN"
rec_put cdc_relevant.files "$NEW_CDC_FILES"
rec_put cdc_relevant.bytes "$NEW_CDC_BYTES"
rec_put cdc_relevant.raw_chunks "$CDC_CHUNKS"
rec_put cdc_relevant.realized_mean_raw "$CDC_MEAN"
rec_put cdc_relevant.unique_chunks "$CDC_UNIQUE_CHUNKS"
rec_put cdc_relevant.realized_mean_unique "$CDC_MEAN_UNIQUE"
rec_put compare_with.raw_to_raw "granary-bench record field realized_mean_span on the matching arm"
rec_put compare_with.unique_to_unique "granary-bench record field realized_mean_grain on the matching arm"
rec_put compare_with.band "within 10%, else report the cross-check as inconclusive on this axis"
rec_write "$OUT"
