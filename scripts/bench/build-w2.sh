#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
# W2: build PostgreSQL at two commits with a PROVEN zero-byte noise floor.
# The recipe is load-bearing; every part of it has been independently
# rechecked. Do not "simplify" it.
#
# Modes:
#   (none)                     build the noise floor and both dataset trees
#   --prove-noise-floor-fails  the blocking negative control
#   --print-pins               validate w2.pins and echo "OLD NEW" (the ONE
#                              validated pin source; consumers never re-parse
#                              the file themselves)
set -euo pipefail
cd "$(dirname "$0")/../.."

DATA="${GRANARY_BENCH_DATA:-$HOME/.cache/granary-bench}"
PINS="bench/datasets/w2.pins"
SRC="$DATA/w2/src"              # ONE source+build dir, reused: the absolute
PREFIX="/opt/granary-w2"        # path and prefix must be identical per commit
REPO="https://git.postgresql.org/git/postgresql.git"
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"

# Configure flags ARE part of the dataset definition (recorded in metadata,
# and in the per-tree stamp — see stamp_apply).
CONFIGURE_FLAGS=(--prefix="$PREFIX" --without-icu --without-readline
                 --without-zlib --without-libxml)

# Floor on an installed tree. A separate build measured 1,633 regular files /
# 28.2 MiB, and this run measures 1,633 / 29,577,637 B. These are FLOORS, not
# equalities: the point is to refuse a truncated, half-installed or
# hand-substituted tree, not to re-pin the dataset (the stamp does that
# exactly).
MIN_TREE_FILES=1500
MIN_TREE_BYTES=25000000

usage_error() {
  echo "$1" >&2
  echo "usage: $0 [--prove-noise-floor-fails | --print-pins]" >&2
  exit 2
}

# ---------------------------------------------------------------------------
# The pins, parsed and validated AT PARSE TIME.
#
# An empty OLD makes `rm -rf "$DATA/w2/$OLD"` target the whole w2 namespace.
# Nothing destructive may depend on the call order of a function for its safety.
# ---------------------------------------------------------------------------

# Data records, one per line: CR stripped (a CRLF editor must not make the id
# `<40 hex>\r`, which would then be a directory name), trimmed, lowercased,
# comments and blanks dropped. An INDENTED comment is a comment — a bare
# `!/^#/` rule would read one as data. This is the ONLY reader of the file.
#
# The file is a REQUIRED argument, exactly as in fetch-w1.sh's pin_records: a
# working-tree default is the mechanism by which "verify one copy, read
# another" keeps coming back. Every caller passes $PINS_BLOB — HEAD's bytes,
# never the working copy.
pin_records() { # <file>
  awk '{ sub(/\r$/, ""); sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, "") }
       $0 != "" && $0 !~ /^#/ { print tolower($0) }' "$1"
}

validate_id() { # <label> <value>
  case "$2" in
    "") echo "REFUSING: $PINS: the $1 commit id is empty" >&2; exit 1 ;;
    *[!0-9a-f]*)
      echo "REFUSING: $PINS: the $1 record '$2' is not a lowercase 40-hex commit id" >&2
      exit 1 ;;
  esac
  [ ${#2} -eq 40 ] || {
    echo "REFUSING: $PINS must carry FULL 40-hex commit ids, not prefixes —" >&2
    echo "  the $1 record is ${#2} characters: '$2'" >&2
    exit 1; }
}

[ -f "$PINS" ] && [ -r "$PINS" ] || {
  echo "REFUSING: $PINS is missing or unreadable — there are no pins to build" >&2
  exit 1; }
# A pin is only a pin if it is COMMITTED. The two ids in this file decide
# what gets cloned, compiled and installed, and which trees
# `rm -rf "$DATA/w2/$OLD"` deletes — so an uncommitted edit redefines the
# dataset with nothing to review it. `git diff` says nothing
# about an UNTRACKED file, so require the path to exist in HEAD FIRST, then
# require the working copy to match it. Same mechanism, same wording as
# fetch-w1.sh's verify_key.
#
# COMPARE THE BYTES, NEVER THE STATUS. `git diff --quiet HEAD -- <path>` is
# computed THROUGH THE INDEX, and `git update-index --assume-unchanged` (or
# --skip-worktree) tells git to presume the working file already matches its
# index entry — so an edited pins file can read as CLEAN.
# The index has no say in the comparison below.
git cat-file -e "HEAD:$PINS" 2>/dev/null || {
  echo "REFUSING: $PINS is not committed — commit the pin before relying on it" >&2
  exit 1; }
git cat-file blob "HEAD:$PINS" 2>/dev/null | cmp -s - "$PINS" || {
  echo "REFUSING: $PINS differs from HEAD — commit the pin before relying on it" >&2
  exit 1; }
# AND THEN CONSUME HEAD'S BYTES, NOT THE WORKING COPY THE GUARD JUST
# COMPARED. Re-opening the working tree after the comparison can consume
# bytes that arrived behind a passed guard. Every pin consumer below reads
# the blob of HEAD's bytes. Re-opening that blob's temp path by pathname
# remains a residual risk; nothing inside this script proves that the
# script itself is the committed one.
PINS_BLOB="$(mktemp)" || exit 1
trap 'rm -f "$PINS_BLOB"' EXIT
git cat-file blob "HEAD:$PINS" > "$PINS_BLOB" || {
  echo "REFUSING: could not read HEAD:$PINS — there are no approved bytes to consume" >&2
  exit 1; }
pin_count="$(pin_records "$PINS_BLOB" | wc -l | tr -d ' ')"
[ "$pin_count" -eq 2 ] || {
  echo "REFUSING: $PINS must hold EXACTLY 2 data records (one 40-hex commit id" >&2
  echo "  per line, older first); found $pin_count." >&2
  echo "  Extra records or both ids on one line do not define the required pair." >&2
  exit 1; }
OLD="$(pin_records "$PINS_BLOB" | sed -n 1p)"
NEW="$(pin_records "$PINS_BLOB" | sed -n 2p)"
validate_id OLD "$OLD"
validate_id NEW "$NEW"
[ "$OLD" != "$NEW" ] || {
  echo "REFUSING: $PINS names the SAME commit twice ($OLD)." >&2
  echo "  W2 is a two-version dataset; a pair with no delta is not one." >&2
  exit 1; }

# ---------------------------------------------------------------------------
# The tree walker. ONE python program, two modes, so `describe` and `compare`
# can never drift apart.
#
# It mirrors crates/granary-bench/src/corpus.rs::walk — the walker that
# produces W2's numbers. Exec bits, symlink targets, empty directories,
# dangling symlinks, and directory-versus-symlink distinctions all affect
# manifest nodes and must be compared, not only regular-file contents.
#
# Correspondence to corpus::walk, node for node:
#   File{exec,len}      -> ("file", exec-bit, size, sha256-of-contents)
#   Symlink{target}     -> ("symlink", raw target bytes, never followed)
#   EmptyDir            -> ("emptydir")
#   memcmp-sorted names -> sorted(os.listdir(<bytes>))
#   symlink_metadata    -> os.lstat
#   Unsupported refusal -> an error exit, never a "difference"
# The content hash is the ONE addition: corpus::walk records {exec,len} and
# leaves contents to the chunker, but two files of equal length and different
# contents are exactly what W2 exists to measure. corpus::walk's format-level
# refusals (Name/SymlinkTarget validation) are NOT mirrored: they are the
# loader's contract with the manifest format, not a property of a comparison.
#
# COUNT DEFINITION, stated so it cannot be confused with another count:
#   files       = regular files only
#   symlinks    = symlinks, never followed
#   empty_dirs  = directories with no entries
#   nodes       = files + symlinks + empty_dirs  (the manifest-node count)
#   file_bytes  = sum of regular-file sizes (apparent bytes; never `du`)
#
# Exit status is a three-way, and callers depend on it:
#   0  the two trees are identical
#   1  the two trees GENUINELY differ
#   2  an ERROR — nothing was judged
# ---------------------------------------------------------------------------
walker() {
  python3 - "$@" <<'PY'
import hashlib, os, stat, sys

def die(msg):
    sys.stderr.write("REFUSING: %s\n" % msg)
    raise SystemExit(2)

def hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def check_root(root):
    d = os.fsdecode(root)
    if not os.path.exists(root):
        die("%s does not exist — there is no installed tree here to compare" % d)
    if not os.path.isdir(root):
        die("%s is not a directory" % d)
    if not os.listdir(root):
        die("%s is EMPTY — an empty tree is not evidence of anything" % d)

def walk(root):
    nodes = {}
    c = {"files": 0, "symlinks": 0, "empty_dirs": 0, "file_bytes": 0}

    def rec(d, prefix):
        try:
            names = sorted(os.listdir(d))          # bytes names: memcmp order
        except OSError as e:
            die("%s: %s" % (os.fsdecode(d), e))
        for raw in names:
            p = os.path.join(d, raw)
            rel = raw if not prefix else prefix + b"/" + raw
            try:
                st = os.lstat(p)                   # NEVER follows symlinks
            except OSError as e:
                die("%s: %s" % (os.fsdecode(p), e))
            m = st.st_mode
            if stat.S_ISDIR(m):
                if not rec(p, rel):
                    nodes[rel] = ("emptydir",)
                    c["empty_dirs"] += 1
            elif stat.S_ISREG(m):
                try:
                    digest = hash_file(p)
                except OSError as e:
                    die("%s: %s" % (os.fsdecode(p), e))
                nodes[rel] = ("file", 1 if m & 0o111 else 0, st.st_size, digest)
                c["files"] += 1
                c["file_bytes"] += st.st_size
            elif stat.S_ISLNK(m):
                try:
                    nodes[rel] = ("symlink", os.readlink(p))
                except OSError as e:
                    die("%s: %s" % (os.fsdecode(p), e))
                c["symlinks"] += 1
            else:
                die("%s: unsupported file type — corpus::walk REFUSES these "
                    "rather than skipping them, so this tree is not measurable"
                    % os.fsdecode(p))
        return bool(names)

    rec(root, b"")
    return nodes, c

def digest_of(nodes):
    h = hashlib.sha256()
    for rel in sorted(nodes):
        n = nodes[rel]
        h.update(rel + b"\0" + n[0].encode() + b"\0")
        if n[0] == "file":
            h.update(("%d %d %s" % (n[1], n[2], n[3])).encode())
        elif n[0] == "symlink":
            h.update(n[1])
        h.update(b"\n")
    return h.hexdigest()

def facts(nodes, c):
    return ("nodes=%d files=%d symlinks=%d empty_dirs=%d file_bytes=%d sha256=%s"
            % (len(nodes), c["files"], c["symlinks"], c["empty_dirs"],
               c["file_bytes"], digest_of(nodes)))

def kind_of(n):
    return n[0]

def positional_byte_mismatches(pa, pb):
    """Byte POSITIONS holding different values, plus the length delta.

    This is NOT novel bytes and NOT an edit distance: a 16-byte insertion
    shifts every following byte and scores the whole tail. Measured here: the
    W2 pair's 144-byte change to bin/postgres scores 2,540,334 — about
    17,600x the real delta, and in the same order as a plausible CDC result.
    It is printed as a diagnostic only, and is labelled at every site so
    that no reader can mistake it for the measured delta.
    """
    with open(pa, "rb") as f:
        x = f.read()
    with open(pb, "rb") as f:
        y = f.read()
    return sum(1 for u, v in zip(x, y) if u != v) + abs(len(x) - len(y))

def main(argv):
    if len(argv) == 3 and argv[1] == "describe":
        root = os.fsencode(argv[2])
        check_root(root)
        nodes, c = walk(root)
        print(facts(nodes, c))
        return 0
    if len(argv) == 4 and argv[1] == "compare":
        a, b = os.fsencode(argv[2]), os.fsencode(argv[3])
        check_root(a)
        check_root(b)
        na, ca = walk(a)
        nb, cb = walk(b)
        print("  tree A: %s" % facts(na, ca))
        print("  tree B: %s" % facts(nb, cb))
        only_a = sorted(set(na) - set(nb))
        only_b = sorted(set(nb) - set(na))
        modified = 0
        positional = 0
        for rel in sorted(set(na) & set(nb)):
            x, y = na[rel], nb[rel]
            if x == y:
                continue
            modified += 1
            why = []
            if kind_of(x) != kind_of(y):
                why.append("kind %s -> %s" % (kind_of(x), kind_of(y)))
            elif kind_of(x) == "file":
                if x[1] != y[1]:
                    why.append("exec %d -> %d" % (x[1], y[1]))
                if x[2] != y[2]:
                    why.append("size %d -> %d" % (x[2], y[2]))
                if x[3] != y[3]:
                    n = positional_byte_mismatches(os.path.join(a, rel),
                                                   os.path.join(b, rel))
                    positional += n
                    why.append("content, positional_byte_mismatches=%d "
                               "(positional, NOT novel bytes)" % n)
            elif kind_of(x) == "symlink":
                why.append("symlink target %s -> %s"
                           % (os.fsdecode(x[1]), os.fsdecode(y[1])))
            print("  differs: %s (%s)" % (os.fsdecode(rel), ", ".join(why)))
        for rel in only_a:
            print("  only in tree A: %s (%s)" % (os.fsdecode(rel), kind_of(na[rel])))
        for rel in only_b:
            print("  only in tree B: %s (%s)" % (os.fsdecode(rel), kind_of(nb[rel])))
        only_one = len(only_a) + len(only_b)
        print("SUMMARY modified=%d only_one_tree=%d positional_byte_mismatches=%d"
              % (modified, only_one, positional))
        print("  (positional_byte_mismatches is a POSITIONAL MISMATCH COUNT over "
              "the modified regular files. It is NOT novel bytes, NOT an edit "
              "distance, and must never be published as either.)")
        print("VERDICT: %s" % ("identical" if (modified == 0 and only_one == 0)
                               else "differs"))
        return 0 if (modified == 0 and only_one == 0) else 1
    sys.stderr.write("REFUSING: walker usage: describe ROOT | compare A B\n")
    return 2

try:
    raise SystemExit(main(sys.argv))
except SystemExit:
    raise
except BaseException as e:                  # never a "difference", always an error
    sys.stderr.write("REFUSING: the tree walker failed: %r\n" % (e,))
    raise SystemExit(2)
PY
}

command -v python3 >/dev/null 2>&1 || {
  echo "REFUSING: python3 is not on PATH — the tree comparator cannot run, and" >&2
  echo "  a comparator that cannot run is not a measurement" >&2
  exit 1; }

CMP_OUT=""
# compare_trees A B — 0 identical, 1 genuinely differ, >=2 ERROR. Sets CMP_OUT.
#
# The status is three-way AND cross-checked against the VERDICT line.
# A missing tree, an absent python3 or a comparator error must never count
# as evidence that the build path perturbs the output.
compare_trees() {
  local rc=0
  CMP_OUT="$(walker compare "$1" "$2")" || rc=$?
  [ -z "$CMP_OUT" ] || printf '%s\n' "$CMP_OUT"
  case "$CMP_OUT" in
    *"VERDICT: identical"*)
      [ "$rc" -eq 0 ] || {
        echo "REFUSING: comparator said identical but exited $rc" >&2; return 2; }
      return 0 ;;
    *"VERDICT: differs"*)
      [ "$rc" -eq 1 ] || {
        echo "REFUSING: comparator said differs but exited $rc" >&2; return 2; }
      return 1 ;;
    *)
      echo "REFUSING: the tree comparator produced no VERDICT line (exit $rc)." >&2
      echo "  That is an ERROR, not a result — nothing has been compared." >&2
      return 2 ;;
  esac
}

cmp_field() { # <key> — a field of the last comparison's SUMMARY line
  printf '%s\n' "$CMP_OUT" \
    | awk -v k="$1" '$1=="SUMMARY"{for(i=2;i<=NF;i++){split($i,kv,"=");
        if(kv[1]==k){print kv[2]; exit}}}'
}

fact() { # <facts-line> <key>
  printf '%s\n' "$1" | tr ' ' '\n' | awk -F= -v k="$2" '$1==k{print $2; exit}'
}

describe_tree() { # <root> -> the facts line on stdout
  local out rc=0
  out="$(walker describe "$1")" || rc=$?
  case "$out" in
    nodes=*) ;;
    *) echo "REFUSING: cannot describe the tree at $1 (walker exit $rc)" >&2
       exit 1 ;;
  esac
  [ "$rc" -eq 0 ] || {
    echo "REFUSING: the walker exited $rc describing $1" >&2; exit 1; }
  printf '%s\n' "$out"
}

assert_tree_floor() { # <label> <root> <facts>
  local files bytes
  files="$(fact "$3" files)"
  bytes="$(fact "$3" file_bytes)"
  { [ "$files" -ge "$MIN_TREE_FILES" ] && [ "$bytes" -ge "$MIN_TREE_BYTES" ]; } || {
    echo "REFUSING: the installed tree for $1 is implausibly small" >&2
    echo "  $2" >&2
    echo "  measured files=$files file_bytes=$bytes" >&2
    echo "  floor    files>=$MIN_TREE_FILES file_bytes>=$MIN_TREE_BYTES" >&2
    echo "  (the reference run installed 1,633 files / 28.2 MiB with these flags)" >&2
    exit 1; }
}

# ---------------------------------------------------------------------------
# Per-dataset-tree provenance stamps.
#
# The run consumes these trees BY PATH and does not rebuild them, so without a
# stamp a hand-run `./configure --with-icu && make install DESTDIR=…`
# substitutes a different dataset while the record still reports the pinned
# flags. The stamp lives OUTSIDE the tree it describes — at
# $DATA/w2/.stamp-<commit>, matching fetch-w1.sh's $DATA/w1/.stamp-<ver>
# — because a file inside the corpus changes the very counts being
# measured.
# ---------------------------------------------------------------------------
stamp_path() { echo "$DATA/w2/.stamp-$1"; }

stamp_facts() { # <stamp> -> the facts line recorded in it
  awk '$1=="nodes"||$1=="files"||$1=="symlinks"||$1=="empty_dirs"||
       $1=="file_bytes"||$1=="sha256" {printf "%s=%s ", $1, $2}
       END {print ""}' "$1" | sed -e 's/[[:space:]]*$//'
}

stamp_mismatch() { # <commit> <root> <stamp> <recorded> <measured> <why>
  echo "REFUSING: the W2 stamp for $1 does not describe the tree at $2" >&2
  echo "  $6" >&2
  echo "  stamp    $4 ($3)" >&2
  echo "  measured $5" >&2
  echo "  configure flags in the stamp: $(awk '$1=="configure"{sub(/^configure /,""); print}' "$3")" >&2
  echo "  configure flags in this script: ${CONFIGURE_FLAGS[*]}" >&2
  echo "remove $2 and $3 to rebuild this dataset tree from the pinned commit" >&2
  exit 1
}

stamp_verify_existing() { # <commit> — before anything destroys the tree
  local stamp root recorded measured
  stamp="$(stamp_path "$1")"
  root="$DATA/w2/$1"
  { [ -f "$stamp" ] && [ -d "$root" ]; } || return 0
  recorded="$(stamp_facts "$stamp")"
  measured="$(describe_tree "$root")"
  [ "$recorded" = "$measured" ] || stamp_mismatch "$1" "$root" "$stamp" \
    "$recorded" "$measured" \
    "the tree on disk was changed after it was stamped — it is NOT the dataset the stamp names"
  echo "stamp ok (pre-build): $root still matches $stamp"
}

stamp_apply() { # <commit> <root> <facts>
  local stamp recorded
  stamp="$(stamp_path "$1")"
  if [ -f "$stamp" ]; then
    recorded="$(stamp_facts "$stamp")"
    [ "$recorded" = "$3" ] || stamp_mismatch "$1" "$2" "$stamp" \
      "$recorded" "$3" \
      "this build did not reproduce the stamped tree — the recipe or the source changed"
    grep -qx "commit $1" "$stamp" || stamp_mismatch "$1" "$2" "$stamp" \
      "$recorded" "$3" "the stamp names a different commit"
    grep -qx "configure ${CONFIGURE_FLAGS[*]}" "$stamp" || stamp_mismatch "$1" "$2" "$stamp" \
      "$recorded" "$3" "the configure flags changed, so this is a DIFFERENT dataset"
    echo "stamp ok: $2 matches $stamp"
    return 0
  fi
  { echo "w2-stamp 1"
    echo "commit $1"
    echo "repo $REPO"
    echo "prefix $PREFIX"
    echo "zero_ar_date 1"
    echo "configure ${CONFIGURE_FLAGS[*]}"
    printf '%s\n' "$3" | tr ' ' '\n' | sed -e 's/=/ /'
  } > "$stamp"
  echo "stamped $1 -> $stamp"
}

fetch_src() {
  if [ ! -d "$SRC/.git" ]; then
    mkdir -p "$(dirname "$SRC")"
    git clone "$REPO" "$SRC"
  fi
  # A clone whose origin is not $REPO is a different codebase wearing the
  # right path.
  local origin
  origin="$(git -C "$SRC" remote get-url origin 2>/dev/null || true)"
  [ "$origin" = "$REPO" ] || {
    echo "REFUSING: $SRC does not point at the pinned repository" >&2
    echo "  origin: ${origin:-<none>}" >&2
    echo "  wanted: $REPO" >&2
    exit 1; }
  git -C "$SRC" fetch --all --tags
  for c in "$OLD" "$NEW"; do
    [ "$(git -C "$SRC" rev-parse --verify "${c}^{commit}" 2>/dev/null)" = "$c" ] || {
      echo "pinned commit $c is not present in the clone as that exact object" >&2; exit 1; }
  done
  # Direction is part of the dataset definition: the ancestry check below
  # enforces older-to-newer order.
  git -C "$SRC" merge-base --is-ancestor "$OLD" "$NEW" || {
    echo "REFUSING: $PINS is not in older-to-newer order — $OLD is not an" >&2
    echo "  ancestor of $NEW. W2's delta is directional." >&2
    exit 1; }
}

# prepare_source <commit> — put $SRC at exactly that commit, or refuse BY NAME.
prepare_source() {
  local commit="$1" v gitdir flagged tracked intree
  # reset --hard, not checkout: `clean` removes only untracked files, and
  # `checkout` does not restore modified tracked files when the worktree is
  # already at that commit — a pre-existing dirty clone would compile
  # unpinned source and quietly invalidate both the noise floor and the
  # pin.
  # A dirty pre-existing clone must never supply build input.
  git -C "$SRC" reset -q --hard "$commit"
  git -C "$SRC" clean -xdffq
  [ "$(git -C "$SRC" rev-parse HEAD)" = "$commit" ] || {
    echo "REFUSING: worktree is not at $commit" >&2; exit 1; }
  [ -z "$(git -C "$SRC" status --porcelain)" ] || {
    echo "REFUSING: worktree dirty after reset/clean" >&2; exit 1; }
  # The guards above see only the worktree. State that lives in .git/ corrupts
  # the build while leaving `status --porcelain` EMPTY, and the noise floor
  # CANNOT catch it: both floor builds use the same $SRC, so corruption common
  # to both yields a floor of exactly 0 and the gate conceals it. Demonstrated
  # with sparse-checkout left on (.c files 1286 -> 223), autocrlf
  # (1190 CR bytes into cash.c), and a .git/info/attributes clean/smudge pair
  # injecting text into every .c.
  v="$(git -C "$SRC" config --get core.sparseCheckout || true)"
  case "$v" in
    ""|false|0|no|off) ;;
    *) echo "REFUSING: sparse checkout is enabled in $SRC (core.sparseCheckout=$v)" >&2
       echo "  a sparsely checked-out worktree builds a DIFFERENT program and" >&2
       echo "  leaves 'git status --porcelain' empty while it does" >&2
       exit 1 ;;
  esac
  v="$(git -C "$SRC" config --get core.autocrlf || true)"
  case "$v" in
    ""|false|0|no|off) ;;
    *) echo "REFUSING: core.autocrlf=$v in $SRC — line endings are rewritten on" >&2
       echo "  checkout, so the compiled source is not the pinned source" >&2
       exit 1 ;;
  esac
  if git -C "$SRC" config --get-regexp '^filter\.' >/dev/null 2>&1; then
    echo "REFUSING: $SRC configures a content filter:" >&2
    git -C "$SRC" config --get-regexp '^filter\.' >&2
    echo "  clean/smudge filters rewrite files on checkout and hide it from" >&2
    echo "  'git status'" >&2
    exit 1
  fi
  gitdir="$(git -C "$SRC" rev-parse --absolute-git-dir)"
  [ ! -e "$gitdir/info/attributes" ] || {
    echo "REFUSING: $gitdir/info/attributes exists — an untracked attributes" >&2
    echo "  file can bind a filter to every source file invisibly" >&2
    exit 1; }
  # Every index entry must be plain-cached ("H"). `S` is skip-worktree and a
  # lowercase tag is assume-unchanged; both tell git to ignore the worktree
  # for that path, so the file can be MISSING with `status --porcelain` empty.
  # A deleted skip-worktree file still has an index entry, so matching
  # ls-files/ls-tree counts alone cannot detect it. Sparse checkout also
  # sets skip-worktree on the files it omits.
  flagged="$(git -C "$SRC" ls-files -v | grep -cv '^H ' || true)"
  [ "$flagged" = 0 ] || {
    echo "REFUSING: $flagged index entr(y|ies) in $SRC are marked skip-worktree" >&2
    echo "  or assume-unchanged, so git ignores the worktree for them and a" >&2
    echo "  missing or edited file never reaches 'git status':" >&2
    git -C "$SRC" ls-files -v | grep -v '^H ' | head -20 >&2
    exit 1; }
  tracked="$(git -C "$SRC" ls-files | wc -l | tr -d ' ')"
  intree="$(git -C "$SRC" ls-tree -r "$commit" | wc -l | tr -d ' ')"
  [ "$tracked" = "$intree" ] || {
    echo "REFUSING: $SRC has $tracked file(s) in the index but commit $commit" >&2
    echo "  has $intree — the worktree is not the whole commit" >&2
    exit 1; }
}

# build <commit> <destdir> [zero_ar_date] — also sets BUILD_FACTS to the facts
# line for the tree it just installed, so a caller stamps EXACTLY what was
# built rather than re-walking and hoping nothing moved in between.
BUILD_FACTS=""
build() {
  local commit="$1" destdir="$2" zero="${3:-1}" facts
  rm -rf "$destdir"
  prepare_source "$commit"
  ( cd "$SRC"
    if [ "$zero" = 1 ]; then export ZERO_AR_DATE=1; else unset ZERO_AR_DATE; fi
    ./configure "${CONFIGURE_FLAGS[@]}" >/dev/null
    make -s -j"$JOBS" >/dev/null
    make -s install DESTDIR="$destdir" >/dev/null )
  facts="$(describe_tree "$destdir")"
  assert_tree_floor "$commit" "$destdir" "$facts"
  BUILD_FACTS="$facts"
  echo "built $commit -> $destdir (ZERO_AR_DATE=${zero})"
  echo "  $facts"
}

case "${1:-}" in
  --print-pins)
    # The ONE validated pin source. Consumers read this instead of
    # re-parsing w2.pins with an unvalidated awk.
    # Covers every parse-time check (readable file, exactly two records, full
    # 40-hex, OLD != NEW). The older-to-newer ancestry check needs the clone,
    # so it stays in fetch_src and is not part of this mode.
    [ $# -eq 1 ] || usage_error "unexpected extra argument(s) after $1: ${*:2}"
    echo "$OLD $NEW"
    exit 0 ;;
  --prove-noise-floor-fails)
    [ $# -eq 1 ] || usage_error "unexpected extra argument(s) after $1: ${*:2}"
    fetch_src
    build "$OLD" "$DATA/w2/noisefloor-a" 1
    # BLOCKING control: a different absolute build path MUST perturb the
    # output (PostgreSQL embeds CONFIGURE_ARGS verbatim — the same fact
    # that forbids -ffile-prefix-map here).
    # A valid negative control must change only the absolute source/build path.
    # Vary ONLY the source/build directory. PREFIX must stay constant:
    # `make install DESTDIR=…` lays the tree out under $DESTDIR/$PREFIX, so
    # changing PREFIX would give the two trees DISJOINT relative paths, the
    # comparison would have nothing in common to compare, and the control
    # would "pass" without ever comparing a byte. The source/build directory
    # must be the only varied path, while PREFIX remains constant.
    SRC_MAIN="$SRC"
    SRC="${SRC}-altpath"
    fetch_src
    build "$OLD" "$DATA/w2/noisefloor-altpath" 1
    SRC="$SRC_MAIN"
    echo "== NEGATIVE TEST (blocking): same commit, different absolute path"
    rc=0
    compare_trees "$DATA/w2/noisefloor-a" "$DATA/w2/noisefloor-altpath" || rc=$?
    case "$rc" in
      0) echo "NEGATIVE TEST FAILED: a different build path changed nothing." >&2
         echo "The noise floor is not being measured here. STOP." >&2
         exit 1 ;;
      1) ;;
      *) echo "NEGATIVE TEST INCONCLUSIVE: the comparator ERRORED (exit $rc)." >&2
         echo "An error is not evidence that the build path perturbs anything." >&2
         echo "STOP." >&2
         exit 1 ;;
    esac
    # Require a modified entry: entries present only in one tree do not
    # establish build-path sensitivity.
    mod="$(cmp_field modified)"
    case "$mod" in
      ''|*[!0-9]*)
        echo "NEGATIVE TEST INCONCLUSIVE: no parsable SUMMARY line. STOP." >&2
        exit 1 ;;
    esac
    [ "$mod" -ge 1 ] || {
      echo "NEGATIVE TEST FAILED: the two trees differ ONLY by entries present" >&2
      echo "in one tree (modified=0). That is a missing or incomplete install," >&2
      echo "not build-path sensitivity. STOP." >&2
      exit 1; }
    echo "negative test: ok — the build path DOES perturb the output"
    echo "  ($mod modified entr(y|ies); positional_byte_mismatches=$(cmp_field positional_byte_mismatches), positional, NOT novel bytes)"
    # INFORMATIONAL, never blocking: modern ar may already be deterministic.
    build "$OLD" "$DATA/w2/noisefloor-noflag" 0
    echo "== INFORMATIONAL: same commit, ZERO_AR_DATE dropped"
    rc=0
    compare_trees "$DATA/w2/noisefloor-a" "$DATA/w2/noisefloor-noflag" || rc=$?
    case "$rc" in
      0) echo "note: dropping ZERO_AR_DATE changed nothing on this toolchain" ;;
      1) echo "note: dropping ZERO_AR_DATE perturbs the build on this toolchain" ;;
      *) echo "note: INCONCLUSIVE — the comparator errored (exit $rc)" ;;
    esac
    exit 0 ;;
  "")
    [ $# -eq 0 ] || usage_error "unexpected argument(s): $*" ;;
  *) usage_error "unknown mode: $1" ;;
esac

fetch_src
# Before anything is destroyed: if a dataset tree is already here and carries
# a stamp, it must still be the tree that stamp describes.
stamp_verify_existing "$OLD"
stamp_verify_existing "$NEW"

echo "== noise floor: build $OLD twice"
build "$OLD" "$DATA/w2/noisefloor-a" 1
build "$OLD" "$DATA/w2/noisefloor-b" 1
rc=0
compare_trees "$DATA/w2/noisefloor-a" "$DATA/w2/noisefloor-b" || rc=$?
case "$rc" in
  0) ;;
  1) echo "NOISE FLOOR IS NOT ZERO — W2 measurements are not admissible. STOP." >&2
     exit 1 ;;
  *) echo "NOISE FLOOR NOT MEASURED: the comparator errored (exit $rc). An error" >&2
     echo "is not a zero. STOP." >&2
     exit 1 ;;
esac
echo "noise floor: 0 differing nodes, 0 differing bytes"

echo "== dataset builds"
# $OLD is BUILT, never copied, to preserve the hardlink layout.
# Result metadata records tree size as apparent bytes, never `du`.
build "$OLD" "$DATA/w2/$OLD" 1
stamp_apply "$OLD" "$DATA/w2/$OLD" "$BUILD_FACTS"
build "$NEW" "$DATA/w2/$NEW" 1
stamp_apply "$NEW" "$DATA/w2/$NEW" "$BUILD_FACTS"

# The dataset must HAVE a delta.
echo "== dataset delta (an assertion, not a decoration)"
rc=0
compare_trees "$DATA/w2/$OLD" "$DATA/w2/$NEW" || rc=$?
case "$rc" in
  1) ;;
  0) echo "REFUSING: the two dataset trees are IDENTICAL. W2 is the byte-shift" >&2
     echo "exhibit; a pair with no delta is not a dataset. STOP." >&2
     exit 1 ;;
  *) echo "REFUSING: the dataset delta was not measured (comparator exit $rc)." >&2
     exit 1 ;;
esac
echo "w2 ready: $DATA/w2/$OLD -> $DATA/w2/$NEW"
