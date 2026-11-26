#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
# Reference line: what an ideal `zstd --patch-from` binary delta achieves on
# the same version pair. It is NOT a contestant, and this number never enters
# cost::choose.
#
# WHAT THIS SCRIPT WRITES IS NOT A HARNESS RECORD. It carries no
# `ControlsPassed` token and never passes `report::write_record`'s gate
# (report.rs:4, "A result without its metadata does not exist"). It says
# so
# in its own `not_a_harness_record` field rather than imitating one, and it
# carries the provenance a reader would otherwise have to take on trust.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# gnu-tar: macOS bsdtar rejects --sort and --mtime.
TAR="$(command -v gtar || command -v gnutar || true)"
[ -n "$TAR" ] || { echo "gnu-tar required (brew install gnu-tar)" >&2; exit 1; }
tar_of() {
  "$TAR" --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    -cf "$2" -C "$1" .
}

# The record builder is the only place a record
# is written. It enforces the no-clobber rule: a
# FAILURE never overwrites an existing successful
# record, but lands beside it as $OUT.failed. A
# failed attempt must preserve the successful
# result and remain distinguishable from success.
write_record() {
  python3 - "$@" <<'PY'
import json, os, stat, sys

w, out, status, stage, older, newer, zstdver, tarver, sha, dirty, cpu, osdesc = sys.argv[1:13]

# A compression that never ran leaves no file, and a record that cannot be
# written is the failure mode this whole function exists to prevent. An
# absent size is reported as null, not as a traceback, and the FIRST
# compression is covered by the same rule.
def size(name):
    p = os.path.join(w, name)
    return os.path.getsize(p) if os.path.exists(p) else None

mismatches = []

# Every key a stamp is allowed to carry, and what this script does with it.
# The two writers are fetch-w1.sh's `w1-stamp` (w1-stamp/version/sha256/files/
# bytes) and build-w2.sh's `w2-stamp` (w2-stamp/commit/repo/prefix/
# zero_ar_date/configure/nodes/files/symlinks/empty_dirs/file_bytes/sha256) —
# both match the actual stamp formats those scripts write. gen-w3.py writes no stamp.
#
# COUNT_KEYS names compared dimensions; NONCOUNT_KEYS
# explicitly names metadata that carries no
# count. Any other key is fatal because silently
# skipping it could omit a dimension the stamp
# expects checked. File, byte and symlink counts
# alone cannot detect a change consisting only
# of empty directories. The walk also counts
# non-root empty directories and defines nodes
# as files plus symlinks plus empty directories.
# Those dimensions are compared when present
# in the stamp, and every key must belong
# to one of the declared categories.
NONCOUNT_KEYS = frozenset((
    "w1-stamp", "w2-stamp",          # format tag
    "version", "commit", "repo", "prefix", "configure", "zero_ar_date",
    "sha256",                        # the recorded digest, copied not compared
))


def facts(root):
    files = nbytes = symlinks = empty_dirs = 0
    stack = [(root, 0)]
    while stack:
        d, depth = stack.pop()
        entries = sorted(os.scandir(d), key=lambda e: e.name)
        if not entries:
            # The ROOT is not a node of itself; a caller-level guard already
            # refuses a tree with no files. Matches build-w2.sh's rec().
            if depth:
                empty_dirs += 1
            continue
        for e in entries:
            st = os.lstat(e.path)
            if stat.S_ISDIR(st.st_mode):
                stack.append((e.path, depth + 1))
            elif stat.S_ISLNK(st.st_mode):
                symlinks += 1
            elif stat.S_ISREG(st.st_mode):
                files += 1
                nbytes += st.st_size
    stamp = os.path.join(os.path.dirname(os.path.abspath(root)),
                         ".stamp-" + os.path.basename(os.path.abspath(root)))
    # ONE ordered table: dimension -> the stamp spellings that carry it -> the
    # value this walk measured. `bytes` is fetch-w1.sh's spelling, `file_bytes` is build-w2.sh's.
    dims = (("files",      ("files",),              files),
            ("bytes",      ("bytes", "file_bytes"), nbytes),
            ("symlinks",   ("symlinks",),           symlinks),
            ("empty_dirs", ("empty_dirs",),         empty_dirs),
            ("nodes",      ("nodes",),              files + symlinks + empty_dirs))
    count_keys = frozenset(k for _, keys, _ in dims for k in keys)
    out_ = {"path": root, "granary_files": files, "granary_bytes": nbytes,
            "symlinks": symlinks, "empty_dirs": empty_dirs,
            "nodes": files + symlinks + empty_dirs}
    # The stamp's sha256 is COPIED into the record,
    # not recomputed over this tree: it identifies
    # the fetch/build artefact. The stamp alone
    # cannot establish that the supplied directory
    # matches it. This function compares the
    # stamp's file, byte and symlink counts with
    # its independent walk, as dedup-bench-crosscheck.sh's
    # walk_facts does. The record states what
    # the digest identifies and which dimensions
    # were compared. A mismatch is fatal to
    # the RUN, but the record is written
    # first so the evidence remains on disk.
    if not os.path.exists(stamp):
        out_.update(stamp="none", corpus_sha256="none",
                    corpus_sha256_is="no stamp beside this tree; corpus "
                                     "identity is UNVERIFIED",
                    stamp_dimensions_compared=[],
                    stamp_dimensions_skipped=[d for d, _, _ in dims],
                    stamp_fields_unrecognised=[],
                    stamp_lines_not_understood=[],
                    stamp_cross_check="no stamp")
        return out_
    # A line this parser cannot account for is REPORTED.
    # A one-token line has no value, and a repeated key is
    # ambiguous; neither may disappear silently. Both are
    # recorded as malformed input and are fatal below.
    fields, not_understood = {}, []
    for lineno, line in enumerate(open(stamp), 1):
        parts = line.split()
        if not parts:
            continue
        if len(parts) < 2:
            not_understood.append("line %d: %r has no value" % (lineno, line.strip()[:60]))
        elif parts[0] in fields:
            not_understood.append("line %d: %r appears more than once" % (lineno, parts[0]))
        else:
            fields[parts[0]] = parts[1]
    # A dimension the stamp does not carry is a
    # dimension NOTHING COMPARED, and the record has
    # to say which ones those were. Skipping an absent
    # key cannot establish that its count matched:
    # that would infer a pass from absence rather than
    # evidence. The comparison records skipped
    # dimensions separately from compared dimensions,
    # and requires file and byte counts. `bytes` is
    # fetch-w1.sh's spelling of the byte dimension;
    # `file_bytes` is build-w2.sh's. An absent symlink
    # count must remain disclosed as unverified.
    #
    # Present-but-UNKNOWN fields also require a refusal:
    # silently treating an unknown key as absent
    # could skip a countable dimension. The table
    # above is checked for TOTALITY against the fields
    # the stamp holds — see COUNT/NONCOUNT above.
    unrecognised = sorted(k for k in fields
                          if k not in count_keys and k not in NONCOUNT_KEYS)
    compared, skipped, disagree = [], [], []
    for dim, keys, got in dims:
        present = [k for k in keys if k in fields]
        if not present:
            skipped.append(dim)
            continue
        compared.append(dim)
        for k in present:
            if fields[k] != str(got):
                disagree.append("%s: stamp says %s, the tree holds %d"
                                % (k, fields[k], got))
    # The floor. Both stamp formats that exist carry a file count and a byte
    # count, so a stamp missing either is not a stamp this script understands —
    # and its sha256 is about to be copied into the record AS THE CORPUS
    # IDENTITY. A stamp too thin to check anything against establishes no
    # identity at all, so it is fatal exactly as a disagreement is: the record
    # is written, then the run refuses. (A tree with NO stamp is a different
    # case, handled above: it claims no identity, so it is allowed to proceed
    # saying so.) `symlinks` is deliberately NOT required because stamps from
    # fetch-w1.sh do not carry it; its absence downgrades the verdict to
    # PARTIAL and is named in the record.
    required = ("files", "bytes")
    absent_required = [d for d in required if d in skipped]
    unrec_msg = ""
    if unrecognised or not_understood:
        unrec_msg = ("UNRECOGNISED: this stamp holds %s; an unknown key may be "
                     "a countable dimension that NOTHING compared, so it is not "
                     "treated as absent. Add it to the dimension table (to be "
                     "compared) or to NONCOUNT_KEYS (to declare it carries no "
                     "count), then re-run"
                     % "; ".join(
                         ([("field(s) this script does not know: "
                            + ", ".join(unrecognised))] if unrecognised else [])
                         + ([("line(s) it could not parse: "
                              + ", ".join(not_understood))] if not_understood else [])))
    if disagree:
        verdict = "MISMATCH: " + "; ".join(disagree)
    elif unrec_msg:
        verdict = unrec_msg
    elif absent_required:
        verdict = ("UNVERIFIED: the stamp carries no %s field, so the required "
                   "%s could not be compared at all; its sha256 names a corpus "
                   "nothing has checked this tree against"
                   % ("/".join(absent_required),
                      "dimension" if len(absent_required) == 1 else "dimensions"))
    elif skipped:
        verdict = ("PARTIAL: compared %s against an independent walk of this "
                   "tree; SKIPPED %s — absent from the stamp, therefore "
                   "UNVERIFIED here" % (", ".join(compared), ", ".join(skipped)))
    else:
        verdict = ("ok: compared %s against an independent walk of this tree"
                   % ", ".join(compared))
    out_.update(
        stamp=stamp,
        corpus_sha256=fields.get("sha256", "none"),
        corpus_sha256_is="the value RECORDED IN THE STAMP, copied verbatim; "
                         "NOT a digest recomputed over the measured tree",
        stamp_dimensions_compared=compared,
        stamp_dimensions_skipped=skipped,
        stamp_fields_unrecognised=unrecognised,
        stamp_lines_not_understood=not_understood,
        stamp_cross_check=verdict)
    # Each fatal condition reports ITSELF. The `elif` chain above picks one
    # headline verdict; it must not decide which failures get recorded.
    if disagree:
        mismatches.append("%s: %s" % (root, "; ".join(disagree)))
    if unrec_msg:
        mismatches.append("%s: %s" % (root, unrec_msg))
    if absent_required:
        mismatches.append("%s: the stamp carries no %s field, so the required "
                          "dimension(s) could not be compared at all"
                          % (root, "/".join(absent_required)))
    return out_

record = {
    "kind": "reference-line",
    "not_a_harness_record": "This is NOT a granary-bench result record: no "
                            "ControlsPassed token, never passed "
                            "report::write_record's gate. It is an external "
                            "reference line with its own provenance.",
    "tool": "zstd --patch-from",
    "note": "NOT a contestant; ideal-delta reference for interpreting the curve",
    "status": status,
    "zstd_cli_version": zstdver.strip(),
    "tar_version": tarver.strip(),
    "granary": {"git_sha": sha, "worktree_dirty": dirty},
    "machine": {"cpu": cpu, "os": osdesc},
    "older": facts(older),
    "newer": facts(newer),
    "old_tar_bytes": size("old.tar"),
    "new_tar_bytes": size("new.tar"),
    "new_tar_zstd19_bytes": size("new.tar.zst"),
}
if status == "ok":
    record["patch_from_bytes"] = size("patch.zst")
else:
    record["failed_stage"] = stage
    errp = os.path.join(w, "err")
    record["reason"] = (open(errp).read().strip()[:500]
                        if os.path.exists(errp) else "(no stderr captured)")

# THE PERSISTED RECORD MUST DESCRIBE ITS FAILURE.
# Compression can succeed while the corpus stamp
# fails validation. Recording only compression's
# outcome would leave `status: "ok"` on a run
# refused by the stamp check. On mismatch, set
# the record's status to `failed` and add
# `stamp_refusal`, while retaining the measurement
# fields as evidence of the compression that ran.
# Consumers reading the file then see the failure
# without relying on the process exit status.
if mismatches:
    record["status"] = "failed"
    record["stamp_refusal"] = "; ".join(mismatches)[:1000]
    record.setdefault("failed_stage", "stamp-cross-check")
    record.setdefault("reason", "the corpus stamp does not describe the tree "
                                "that was measured, or is too thin to check "
                                "it; see stamp_refusal and stamp_cross_check")

d = os.path.dirname(out)
if d:
    os.makedirs(d, exist_ok=True)
# A failure must never destroy a good measurement. If one is already
# there, the failure lands beside it. Keyed off the RECORD's status, not
# the argument: a stamp-refused run is a failure too, and it must not
# overwrite a good record either.
if record["status"] != "ok" and os.path.exists(out):
    try:
        prior = json.load(open(out))
    except (OSError, ValueError):
        prior = {}
    if prior.get("status") == "ok":
        out = out + ".failed"
        sys.stderr.write("a successful record already exists; the failure "
                         "record goes to %s instead\n" % out)
# Use a context manager to close the results file when
# writing finishes. The JSON record and its trailing
# newline are written through the same handle; leaving
# its lifetime implicit would make closure depend on
# the interpreter's handling of that temporary object.
with open(out, "w") as fh:
    json.dump(record, fh, indent=2)
    fh.write("\n")
print(json.dumps(record, indent=2))
if mismatches:
    sys.stderr.write("REFUSING: a corpus stamp does not describe the tree that "
                     "was measured, or is too thin to check it:\n")
    for m in mismatches:
        sys.stderr.write("  " + m + "\n")
    raise SystemExit(3)
PY
}

# write_record exits 3 when a tree's stamp does not describe the tree that was
# actually measured. The record has already been written at that point — the
# evidence belongs on disk — but the RUN fails, because a reference line
# attributed to a corpus it did not measure is worse than no reference line.
record() {
  local rc=0
  write_record "$@" || rc=$?
  case "$rc" in
    0) return 0 ;;
    3) echo "the record was written, then REFUSED — read its stamp_cross_check" >&2
       return 1 ;;
    *) echo "write_record itself failed (exit $rc)" >&2; return "$rc" ;;
  esac
}

# reference_line OLD NEW OUT -> writes the record; returns 1 if the
# reference line could not be produced.
reference_line() {
  local old="$1" new="$2" out="$3" w rc stage
  local sha dirty
  [ -d "$old" ] || { echo "no such directory: $old" >&2; exit 1; }
  [ -d "$new" ] || { echo "no such directory: $new" >&2; exit 1; }
  # Two empty directories give `status: ok`, patch 24 B against a 61 B
  # standalone compression — a 39% ratio the identical-tree control would
  # reject outright. A reference line over nothing is an operator error,
  # not a measurement.
  [ -n "$(find "$old" -type f -print -quit)" ] || { echo "no files under $old — refusing to publish a reference line over an empty tree" >&2; exit 1; }
  [ -n "$(find "$new" -type f -print -quit)" ] || { echo "no files under $new — refusing to publish a reference line over an empty tree" >&2; exit 1; }

  mkdir -p "$(dirname "$out")" # a standalone run must not fail AFTER the
                               # expensive compression.
  w="$(mktemp -d)"
  tar_of "$old" "$w/old.tar"
  tar_of "$new" "$w/new.tar"

  sha="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  dirty="$([ -n "$(git -C "$ROOT" status --porcelain 2>/dev/null)" ] && echo yes || echo no)"

  # --patch-from needs a window covering the
  # whole dictionary; --long=31 is 2 GiB and
  # costs real RAM. A compression failure must
  # be caught so the script can write a FAILURE
  # RECORD before returning nonzero. The
  # input is never shrunk to make a number
  # appear, and a `set -e` caller must not
  # read a failed reference line as success.
  # BOTH compressions use the failure-record
  # path. The standalone -19 of new.tar supplies
  # the denominator and can fail on the same
  # large input through memory or disk exhaustion.
  # A bare command under `set -e` could terminate
  # the shell before recording that failure;
  # both statuses are captured explicitly.
  rc=0; stage=standalone-zstd19
  zstd -q -19 "$w/new.tar" -o "$w/new.tar.zst" 2> "$w/err" || rc=$?
  if [ "$rc" -eq 0 ]; then
    stage=patch-from
    zstd -q --long=31 --patch-from="$w/old.tar" -19 "$w/new.tar" -o "$w/patch.zst" 2> "$w/err" || rc=$?
  fi
  if [ "$rc" -ne 0 ]; then
    record "$w" "$out" failed "$stage" "$old" "$new" "$(zstd --version)" "$("$TAR" --version | head -1)" \
      "$sha" "$dirty" "$(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m)" \
      "$(uname -s) $(sw_vers -productVersion 2>/dev/null || uname -r)" || true
    echo "$stage FAILED; failure record written for $out" >&2
    rm -rf "$w"
    return 1
  fi
  rc=0
  record "$w" "$out" ok none "$old" "$new" "$(zstd --version)" "$("$TAR" --version | head -1)" \
    "$sha" "$dirty" "$(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m)" \
    "$(uname -s) $(sw_vers -productVersion 2>/dev/null || uname -r)" || rc=$?
  rm -rf "$w"
  return "$rc"
}

# The controls are COMMITTED and re-runnable. A one-off heredoc entered at an
# interactive shell would run only at authoring time and could never detect a
# later regression.
if [ "${1:-}" = "--self-test" ]; then
  P="$(mktemp -d)"
  trap 'rm -rf "$P"' EXIT
  mkdir -p "$P/a" "$P/b" "$P/c"
  # Deterministic, so the two numbers below are reproducible rather than
  # a fresh sample every run.
  python3 - "$P/a/f.bin" "$P/c/f.bin" <<'PY'
import hashlib, sys
open(sys.argv[1], "wb").write(hashlib.shake_256(b"granary-patchfrom-a").digest(2000000))
open(sys.argv[2], "wb").write(hashlib.shake_256(b"granary-patchfrom-c").digest(2000000))
PY
  cp "$P/a/f.bin" "$P/b/f.bin" # identical tree
  reference_line "$P/a" "$P/b" "$P/same.json" > /dev/null
  reference_line "$P/a" "$P/c" "$P/diff.json" > /dev/null
  python3 - "$P/same.json" "$P/diff.json" <<'PY'
import json, sys
same = json.load(open(sys.argv[1]))
diff = json.load(open(sys.argv[2]))
for r, name in ((same, "identical"), (diff, "disjoint")):
    assert r["status"] == "ok", "%s: %s" % (name, r)
ratio = same["patch_from_bytes"] / same["new_tar_zstd19_bytes"]
assert ratio < 0.01, "identical trees: patch is %.4f%% of standalone, want <1%%" % (ratio * 100)
factor = diff["patch_from_bytes"] / max(same["patch_from_bytes"], 1)
assert factor >= 100, "disjoint/identical patch factor %.1f, want >=100" % factor
print("patch-from controls: ok (identical %.4f%%, factor %.0fx)" % (ratio * 100, factor))
PY
  exit 0
fi

OLD="${1:?usage: $0 OLD_DIR NEW_DIR OUT_JSON   (or --self-test)}"
NEW="${2:?}"
OUT="${3:?}"
reference_line "$OLD" "$NEW" "$OUT"
