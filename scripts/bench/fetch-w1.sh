#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
# W1: fetch + verify + unpack successive Rust stable toolchain releases.
# Datasets live OUTSIDE the repo: $GRANARY_BENCH_DATA (default
# ~/.cache/granary-bench). NEVER ~/.rustup — an installed toolchain tree
# differs from a pristine tarball in both directions.
#
# Modes:
#   (none)           fetch, verify and unpack every pinned release
#   --self-test      the sha256 verifier, against independent golden vectors
#   --self-test-key  the gpg status parser, against recorded status blobs
#   --verify-key     re-run the release-key check against the pinned fingerprint
#   --print-pins     validate w1.pins and echo the pinned versions, ascending,
#                    on one line (the ONE validated pin source; consumers never
#                    re-parse the file themselves)
set -euo pipefail
cd "$(dirname "$0")/../.."

DATA="${GRANARY_BENCH_DATA:-$HOME/.cache/granary-bench}"
PINS="bench/datasets/w1.pins"
BASE="https://static.rust-lang.org/dist"

# The corpus-root definition, pinned in CODE. Without this nothing compares
# the tree that gets measured against the tree the pilot measured, so a drifted
# corpus root produces a wrong benchmark number with a clean exit code and
# silently voids the comparison.
# Prints "<files> <bytes>"; returns 1 for a version with no entry, which is
# reported as UNPINNED rather than silently accepted.
# The counts below measure regular files and their total bytes under the
# unpacked toolchain root. The 1.96.0 and 1.97.0 measurements were taken
# in the 2026-08-10 pilot and the 1.95.0 measurement on 2026-08-11.
#
# ONE TABLE, rows "<version> <files> <bytes>", ascending. It is both the
# corpus-root definition and the list of versions W1 pins, so --print-pins
# takes the record count, the version expected at each position, and the print
# order from here instead of re-literalling any of them. Adding a version is
# one row — and --print-pins then refuses the pins file until it agrees, which
# is the intent: a consumer reading a fixed number of versions must be updated
# in the same breath.
EXPECTED_COUNTS=(
  "1.95.0 52175 1758260155"
  "1.96.0 52228 1767403201"
  "1.97.0 65789 1849207377"
)
# A string EQUALITY on the first field, never a `case "$row" in "$1 "*)` prefix
# glob: the glob form answered `expected_counts "1.95.0 52175"` with 1.95.0's
# counts, where the case statement it replaced returned 1. Unreachable from the
# fetch loop (a `read` field holds no space) but a real divergence, and it is
# the counts of a DIFFERENT dataset that a divergence here hands back.
expected_counts() {
  local row
  for row in "${EXPECTED_COUNTS[@]}"; do
    [ "${row%% *}" = "$1" ] || continue
    printf '%s\n' "${row#* }"
    return 0
  done
  return 1
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# Both sides of every checksum comparison go through this. A pin that is
# byte-perfect but UPPERCASE, or that picked up a CR from a CRLF editor, is
# correct: the shipped version compared it raw, declared a mismatch and
# deleted a 200 MB tarball — and in the CRLF case printed the two hashes so
# that the CR returned the cursor to column 0 and the second line overwrote
# the first, making them look identical. INNER whitespace is deliberately NOT
# stripped: a malformed multi-field pin must fail the
# 64-hex check below rather than be glued into something that
# passes it.
normalize_hex() {
  printf '%s' "$1" | tr -d '\r' | tr 'A-F' 'a-f' \
    | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

# The ONE definition of "this string is a sha256 pin": normalize, then require
# 64 lowercase hex. Echoes the NORMALIZED value, so a caller stores and
# compares exactly what passed the check. <context> and <suffix> reproduce each
# call site's wording verbatim — the wording is per-site, the CHECK is not, and
# three copies of a check are three chances for one of them to drift.
normalized_pin() { # <context> <suffix> <raw> -> the normalized pin on stdout
  local want
  want="$(normalize_hex "$3")"
  case "$want" in
    "") echo "MALFORMED PIN $1: empty sha256$2" >&2; return 1 ;;
    *[!0-9a-f]*)
      echo "MALFORMED PIN $1: '$want' is not lowercase hex$2" >&2; return 1 ;;
  esac
  [ ${#want} -eq 64 ] || {
    echo "MALFORMED PIN $1: sha256 must be 64 hex chars, got ${#want}$2" >&2
    return 1; }
  printf '%s\n' "$want"
}

# The ONE place a checksum is compared. Exit codes are distinct on purpose:
#   0  match
#   1  MISMATCH — the file is not what the pin names
#   2  MALFORMED PIN — the pin is not a sha256 at all, so the file has not
#      been judged; callers must never route this into a destructive path.
verify_sha256() {
  local file="$1" want="$2" got
  want="$(normalized_pin "for $file" "" "$want")" || return 2
  got="$(normalize_hex "$(sha256_of "$file")")"
  if [ "$got" != "$want" ]; then
    echo "CHECKSUM MISMATCH for $file" >&2
    echo "  want $want" >&2
    echo "  got  $got" >&2
    return 1
  fi
  echo "ok $(basename "$file") $got"
}

# The ONE place a `gpg --status-fd` blob becomes a primary-key fingerprint.
# Extracted from verify_key so --self-test-key exercises THIS code and not a
# copy of it.
#
# Both checks are FIELD-ANCHORED, which is the entire point. The shipped
# version matched `*GOODSIG*` as a substring and `/VALIDSIG/` as an unanchored
# regex, so gpg's GOODSIG line — emitted FIRST, and carrying the key's uid
# VERBATIM — was parsed as if it were a VALIDSIG line. A substituted bundle of
# [real pinned key, rogue key] whose rogue uid ENDS IN "VALIDSIG <pinned-40-hex>",
# with every manifest signed by the rogue key, then yielded primary=<pinned>
# and passed every guard. A real rogue key reproduced the attack;
# its status blob is a fixture of --self-test-key, where the parse must
# name the ROGUE primary so that verify_key's pin comparison refuses it.
#
# Prints "<signing-fpr> <primary-fpr>" on stdout; prints a NAMED refusal on
# stderr and returns 1 otherwise. The signing key is RECORDED, never enforced:
# a rotated signing subkey under the same primary is a normal, valid release,
# so callers enforce the PRIMARY, which is the last field.
# Callers enforce the primary-key fingerprint and permit subkey rotation.
key_verdict() {
  local status="$1" label="$2" keys primary n
  printf '%s\n' "$status" | grep -q '^\[GNUPG:\] GOODSIG ' || {
    echo "no GOODSIG line for $label" >&2; return 1; }
  # A real VALIDSIG record is "[GNUPG:] VALIDSIG" plus ten fields, the last of
  # which is the primary-key fingerprint — verified on GnuPG 2.5.19. NF==12
  # both anchors the record and ASSERTS the layout $NF depends on, so a future
  # gpg that appends a field fires the refusal below instead of silently
  # comparing the wrong field if the status layout ever changes.
  keys="$(printf '%s\n' "$status" \
    | awk '$1=="[GNUPG:]" && $2=="VALIDSIG" && NF==12 {print $3, $NF}')"
  n="$(printf '%s\n' "$keys" | grep -c . || true)"
  case "$n" in
    1) ;;
    0) echo "no well-formed VALIDSIG line for $label" >&2; return 1 ;;
    *) echo "expected exactly one VALIDSIG line for $label, found $n" >&2; return 1 ;;
  esac
  primary="$(printf '%s\n' "$keys" | awk '{print $2; exit}')"
  case "$primary" in
    *[!0-9A-Fa-f]*|"")
      echo "VALIDSIG last field is not a fingerprint for $label: $primary" >&2
      return 1 ;;
  esac
  [ ${#primary} -eq 40 ] || {
    echo "VALIDSIG last field is ${#primary} chars for $label, want 40 hex" >&2
    return 1; }
  printf '%s\n' "$keys"
}

# One fixture assertion. Bumps the caller's failure counter rather than
# exiting, so one run reports every failing case.
st_case() {
  local label="$1" file="$2" want="$3" expect="$4" rc=0
  verify_sha256 "$file" "$want" >/dev/null 2>&1 || rc=$?
  case "$expect" in
    accept) [ "$rc" -eq 0 ] || {
      echo "SELF-TEST FAIL: $label — expected accept, got rc=$rc" >&2
      ST_FAILS=$((ST_FAILS + 1)); return 0; } ;;
    reject) [ "$rc" -ne 0 ] || {
      echo "SELF-TEST FAIL: $label — expected reject, got rc=0" >&2
      ST_FAILS=$((ST_FAILS + 1)); return 0; } ;;
  esac
  echo "  ok: $label ($expect)"
}

self_test() {
  # EXIT, not RETURN: every failure path here is `exit 1`, and a RETURN trap
  # does not fire on exit — the shipped version leaked its temp dir, and the
  # fixture inside it, on exactly the paths that matter.
  # The path is a GLOBAL because an EXIT trap
  # runs after this function's locals are gone, and `set -u` would then abort
  # in the trap itself.
  ST_TMP="$(mktemp -d)"
  trap 'rm -rf "$ST_TMP"' EXIT
  local tmp="$ST_TMP"
  local ST_FAILS=0
  # GOLDEN VECTORS, computed with python3 hashlib — an implementation
  # INDEPENDENT of sha256_of. The shipped self-test took its expected value
  # from the function under test, so a verifier that hashed wrongly but
  # consistently passed.
  local A=d359d2724f56ae8d65d1fcc8215be494f5f0f9a3c250b39f2cee0d1746027ce9   # sha256("granary w1 self test\n")
  local BIG=de74164511e63e5055d43fa652a342d8c2ad14b2a6bdb76367bfc982fba04dd7 # sha256("g" x 1048577)
  local NIL=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 # sha256("")
  printf 'granary w1 self test\n' > "$tmp/a"
  printf 'granary w1 self tesT\n' > "$tmp/corrupt"   # one byte changed
  : > "$tmp/empty"
  # A >1 MiB fixture, because every size-dependent bypass is invisible against
  # a 21-byte file and the real inputs are 200 MB tarballs.
  head -c 1048577 /dev/zero | tr '\0' 'g' > "$tmp/big"
  [ "$(wc -c < "$tmp/big" | tr -d ' ')" -eq 1048577 ] || {
    echo "SELF-TEST FAIL: the >1 MiB fixture is not 1048577 bytes" >&2; exit 1; }

  local upper cr trunc_tail trunc_head flip_first flip_last transposed toolong nonhex
  upper="$(printf '%s' "$A" | tr 'a-f' 'A-F')"
  cr="$(printf '%s\r' "$A")"
  trunc_tail="${A%?}"          # 63 chars, last dropped
  trunc_head="${A#?}"          # 63 chars, first dropped
  flip_last="${A%?}0"          # differs from the golden value ONLY in the last char
  flip_first="0${A#?}"         # differs from the golden value ONLY in the first char
  # A PERMUTATION of the golden value (its first two characters swapped), so a
  # verifier that compares sorted characters accepts it.
  transposed=3d59d2724f56ae8d65d1fcc8215be494f5f0f9a3c250b39f2cee0d1746027ce9
  toolong="${A}0"
  nonhex="${A%?}g"
  local d
  for d in "$flip_first" "$flip_last" "$transposed" "$trunc_head" "$trunc_tail" \
           "$toolong" "$nonhex"; do
    [ "$d" != "$A" ] || {
      echo "SELF-TEST FAIL: a derived fixture collapsed onto the golden value" >&2
      exit 1; }
  done
  [ "$(printf '%s' "$transposed" | fold -w1 | sort | tr -d '\n')" \
    = "$(printf '%s' "$A" | fold -w1 | sort | tr -d '\n')" ] || {
    echo "SELF-TEST FAIL: the transposed fixture is not a permutation of the golden value" >&2
    exit 1; }

  st_case "golden vector accepted"                          "$tmp/a"       "$A"          accept
  st_case "one-byte corruption rejected"                    "$tmp/corrupt" "$A"          reject
  st_case "uppercase pin accepted"                          "$tmp/a"       "$upper"      accept
  st_case "pin with a trailing CR accepted"                 "$tmp/a"       "$cr"         accept
  st_case "empty want rejected"                             "$tmp/a"       ""            reject
  st_case "tail-truncated want rejected"                    "$tmp/a"       "$trunc_tail" reject
  st_case "head-truncated want rejected"                    "$tmp/a"       "$trunc_head" reject
  st_case "over-long want rejected"                         "$tmp/a"       "$toolong"    reject
  st_case "non-hex want rejected"                           "$tmp/a"       "$nonhex"     reject
  st_case "want differing only in the LAST char rejected"   "$tmp/a"       "$flip_last"  reject
  st_case "want differing only in the FIRST char rejected"  "$tmp/a"       "$flip_first" reject
  st_case "permuted want rejected"                          "$tmp/a"       "$transposed" reject
  st_case ">1 MiB file, golden vector accepted"             "$tmp/big"     "$BIG"        accept
  st_case ">1 MiB file, wrong want rejected"                "$tmp/big"     "$A"          reject
  st_case "0-byte file, golden vector accepted"             "$tmp/empty"   "$NIL"        accept
  st_case "0-byte file, wrong want rejected"                "$tmp/empty"   "$A"          reject

  [ "$ST_FAILS" -eq 0 ] || {
    echo "SELF-TEST FAIL: $ST_FAILS case(s) failed" >&2; exit 1; }
  echo "self-test: ok (16 verify_sha256 cases against independent golden vectors)"
}

# Recorded `gpg --status-fd 1 --verify` output, all captured on this machine on
# 2026-08-11, GnuPG 2.5.19. Provenance per blob:
#   real-primary    the genuine Rust release-key signature over
#                   channel-rust-1.97.0.toml (signing key == primary).
#   good-subkey     a locally generated key signing with a ROTATED SIGNING
#                   SUBKEY, so VALIDSIG's $3 != $NF. This one MUST be
#                   accepted — the primary key stays pinned.
#   uid-injection   a locally generated rogue key whose uid ENDS IN
#                   "VALIDSIG <the pinned fingerprint>"; the signature is the
#                   rogue key's. The shipped parse returned the PINNED
#                   fingerprint for this blob.
#   badsig          a real signature over a tampered payload.
#   goodsig-in-uid  a rogue key whose uid ends in "GOODSIG <hex>", over a
#                   tampered payload: only a BADSIG verdict, but a substring
#                   match for GOODSIG.
#   two-validsig    one payload signed by two different keys.
#   no-validsig     the real 1.97.0 blob with its VALIDSIG line deleted.
key_blob() {
  case "$1" in
    real-primary) cat <<'BLOB'
[GNUPG:] NEWSIG
[GNUPG:] KEY_CONSIDERED 108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE 0
[GNUPG:] SIG_ID 4Bc8HisxgKNNI46hir8gNtLWkfc 2026-07-09 1783598755
[GNUPG:] GOODSIG 85AB96E6FA1BE5FE Rust Language (Tag and Release Signing Key) <rust-key@rust-lang.org>
[GNUPG:] VALIDSIG 108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE 2026-07-09 1783598755 0 4 0 1 10 00 108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE
[GNUPG:] TRUST_UNDEFINED 0 pgp
BLOB
      ;;
    good-subkey) cat <<'BLOB'
[GNUPG:] NEWSIG
[GNUPG:] KEY_CONSIDERED 0CC4CA9EB99922DBD75AFF189BF40B868724A1EE 0
[GNUPG:] SIG_ID VDsZEiOoInF3mRkZ10lL2s3xyCA 2026-08-11 1786467432
[GNUPG:] GOODSIG 8916A9E1C9F66C45 Subkey Signer Test
[GNUPG:] VALIDSIG 56E2F1973E11E192BE4171B28916A9E1C9F66C45 2026-08-11 1786467432 0 4 0 22 10 00 0CC4CA9EB99922DBD75AFF189BF40B868724A1EE
[GNUPG:] KEY_CONSIDERED 0CC4CA9EB99922DBD75AFF189BF40B868724A1EE 0
[GNUPG:] TRUST_ULTIMATE 0 pgp
BLOB
      ;;
    uid-injection) cat <<'BLOB'
[GNUPG:] NEWSIG
[GNUPG:] KEY_CONSIDERED 4EA398E635300B7677031297B76109A82E59F956 0
[GNUPG:] SIG_ID DykGryUwCtOO8abvOsz7yuywmg4 2026-08-11 1786467361
[GNUPG:] GOODSIG B76109A82E59F956 Rogue Rust Release VALIDSIG 108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE
[GNUPG:] VALIDSIG 4EA398E635300B7677031297B76109A82E59F956 2026-08-11 1786467361 0 4 0 22 10 00 4EA398E635300B7677031297B76109A82E59F956
[GNUPG:] TRUST_ULTIMATE 0 pgp
BLOB
      ;;
    badsig) cat <<'BLOB'
[GNUPG:] NEWSIG
[GNUPG:] KEY_CONSIDERED 0CC4CA9EB99922DBD75AFF189BF40B868724A1EE 0
[GNUPG:] BADSIG 8916A9E1C9F66C45 Subkey Signer Test
[GNUPG:] FAILURE gpg-exit 33554433
BLOB
      ;;
    goodsig-in-uid) cat <<'BLOB'
[GNUPG:] NEWSIG
[GNUPG:] KEY_CONSIDERED C6A290E0D1DFBE3BB32A215E152C4F19AA96E8A0 0
[GNUPG:] BADSIG 152C4F19AA96E8A0 Rogue Uid GOODSIG deadbeefdeadbeef
[GNUPG:] FAILURE gpg-exit 33554433
BLOB
      ;;
    two-validsig) cat <<'BLOB'
[GNUPG:] NEWSIG
[GNUPG:] KEY_CONSIDERED 0CC4CA9EB99922DBD75AFF189BF40B868724A1EE 0
[GNUPG:] SIG_ID VDsZEiOoInF3mRkZ10lL2s3xyCA 2026-08-11 1786467432
[GNUPG:] GOODSIG 8916A9E1C9F66C45 Subkey Signer Test
[GNUPG:] VALIDSIG 56E2F1973E11E192BE4171B28916A9E1C9F66C45 2026-08-11 1786467432 0 4 0 22 10 00 0CC4CA9EB99922DBD75AFF189BF40B868724A1EE
[GNUPG:] KEY_CONSIDERED 0CC4CA9EB99922DBD75AFF189BF40B868724A1EE 0
[GNUPG:] TRUST_ULTIMATE 0 pgp
[GNUPG:] NEWSIG
[GNUPG:] KEY_CONSIDERED C6A290E0D1DFBE3BB32A215E152C4F19AA96E8A0 0
[GNUPG:] SIG_ID FpAu0VDx0YMEx1C4WezVgqGU5zM 2026-08-11 1786467432
[GNUPG:] GOODSIG 152C4F19AA96E8A0 Rogue Uid GOODSIG deadbeefdeadbeef
[GNUPG:] VALIDSIG C6A290E0D1DFBE3BB32A215E152C4F19AA96E8A0 2026-08-11 1786467432 0 4 0 22 10 00 C6A290E0D1DFBE3BB32A215E152C4F19AA96E8A0
[GNUPG:] TRUST_ULTIMATE 0 pgp
BLOB
      ;;
    no-validsig) cat <<'BLOB'
[GNUPG:] NEWSIG
[GNUPG:] KEY_CONSIDERED 108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE 0
[GNUPG:] SIG_ID 4Bc8HisxgKNNI46hir8gNtLWkfc 2026-07-09 1783598755
[GNUPG:] GOODSIG 85AB96E6FA1BE5FE Rust Language (Tag and Release Signing Key) <rust-key@rust-lang.org>
[GNUPG:] TRUST_UNDEFINED 0 pgp
BLOB
      ;;
    *) echo "no such blob: $1" >&2; return 1 ;;
  esac
}

# One key-parser assertion. $3 is the "<signing> <primary>" pair the parse must
# report (accept cases); $4, when given, is a primary the parse must NEVER
# report.
sk_case() {
  local label="$1" expect="$2" want="${3:-}" forbidden="${4:-}" out rc=0
  out="$(key_verdict "$(key_blob "$label")" "$label" 2>&1)" || rc=$?
  case "$expect" in
    accept)
      if [ "$rc" -ne 0 ]; then
        echo "SELF-TEST FAIL: $label — expected accept, refused with: $out" >&2
        SK_FAILS=$((SK_FAILS + 1)); return 0
      fi
      if [ "$out" != "$want" ]; then
        echo "SELF-TEST FAIL: $label — keys are '$out', want '$want'" >&2
        SK_FAILS=$((SK_FAILS + 1)); return 0
      fi ;;
    refuse)
      if [ "$rc" -eq 0 ]; then
        echo "SELF-TEST FAIL: $label — expected refusal, accepted primary '$out'" >&2
        SK_FAILS=$((SK_FAILS + 1)); return 0
      fi
      if [ -z "$out" ]; then
        echo "SELF-TEST FAIL: $label — refused without naming a reason" >&2
        SK_FAILS=$((SK_FAILS + 1)); return 0
      fi ;;
  esac
  if [ -n "$forbidden" ] && [ "${out##* }" = "$forbidden" ]; then
    echo "SELF-TEST FAIL: $label — the parse reported the forbidden primary '$forbidden'" >&2
    SK_FAILS=$((SK_FAILS + 1)); return 0
  fi
  if [ "$expect" = refuse ]; then echo "  ok: $label (refused: $out)"
  else echo "  ok: $label (accepted, KEYS $out)"; fi
}

# The negative test for verify_key's PARSER: these feed key_verdict — the
# real parser, not a copy — recorded gpg status blobs and assert the
# verdict on each. verify_key's other refusals are not exercised here.
# No second parser is involved.
self_test_key() {
  local SK_FAILS=0
  local PINNED=108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE
  sk_case real-primary   accept "$PINNED $PINNED"
  # The signing key here is 56E2F197…, the primary 0CC4CA9E…: a rotated
  # signing subkey must stay VALID and must report the PRIMARY last.
  sk_case good-subkey    accept \
    "56E2F1973E11E192BE4171B28916A9E1C9F66C45 0CC4CA9EB99922DBD75AFF189BF40B868724A1EE"
  sk_case badsig         refuse
  sk_case goodsig-in-uid refuse
  sk_case no-validsig    refuse
  sk_case two-validsig   refuse
  # The parse must name the ROGUE primary and never the
  # fingerprint injected through the uid — verify_key's "$primary" != "$pinned"
  # comparison then refuses the bundle.
  sk_case uid-injection  accept \
    "4EA398E635300B7677031297B76109A82E59F956 4EA398E635300B7677031297B76109A82E59F956" \
    "$PINNED"
  [ "$SK_FAILS" -eq 0 ] || {
    echo "SELF-TEST FAIL: $SK_FAILS key-parser case(s) failed" >&2; exit 1; }
  echo "self-test-key: ok (7 recorded gpg status blobs, including the uid-injection bundle)"
}

# The ONE definition of "this file is the bytes HEAD holds". Returns 0 only
# then; prints a NAMED reason and returns 1 otherwise.
#
# COMPARE THE BYTES, NEVER THE STATUS. `git diff --quiet HEAD -- <path>` is
# computed THROUGH THE INDEX, and `git update-index --assume-unchanged` (or
# --skip-worktree) tells git to presume the working file already matches its
# index entry — so an edited pins file reads as CLEAN. With assume-unchanged
# set and the `rust_release_key_fpr` line deleted, a status-based guard can
# pass while the script reads the altered file. The index has no say in the
# comparison below.
# The committed blob and working file are compared byte-for-byte below.
#
# `git diff` also says nothing about an UNTRACKED file, so require the path to
# EXIST in HEAD first, then require the working copy to match it.
#
# Two callers, ONE definition, so both verify_key and --print-pins require
# the same git anchoring before treating the pin source as validated.
assert_committed() { # <path> — the working copy must be BYTE-IDENTICAL to HEAD's
  if ! git rev-parse --verify -q HEAD >/dev/null 2>&1; then
    # Named separately, and LOUDLY: outside a git repo (or on an unborn HEAD)
    # there is no approval to anchor to, and "not committed" would be a
    # misleading way to say so.
    echo "$PWD is not a git repository with a commit (or HEAD is unborn)," >&2
    echo "so $1 cannot be anchored to an approved commit here" >&2
    return 1
  fi
  if ! git cat-file -e "HEAD:$1" 2>/dev/null; then
    echo "$1 is not committed — commit the pin before relying on it" >&2
    return 1
  fi
  if ! { [ -f "$1" ] && [ -r "$1" ]; }; then
    echo "$1 is in HEAD but is not a readable file in the working tree" >&2
    return 1
  fi
  if ! git cat-file blob "HEAD:$1" 2>/dev/null | cmp -s - "$1"; then
    echo "$1 differs from HEAD — commit the pin before relying on it" >&2
    return 1
  fi
}

# Data records: the lines that are neither blank nor comments, with the CR of a
# CRLF editor stripped and the line trimmed. An INDENTED comment is a comment,
# and a CRLF blank line is a blank line. This is the ONE record filter:
# count_pin_records and
# --print-pins are both defined on it, so they cannot disagree about what a
# record is.
#
# The file is a REQUIRED argument, with no default. A default to the
# working-tree $PINS is the mechanism by which "verify one copy, read
# another" comes back: a caller that forgets to pass HEAD's blob silently
# gets the unapproved bytes and looks exactly like a caller that did not —
# which is precisely the mistake a default makes easy.
#
# With no default a forgotten argument FAILS CLOSED, which is not the same as
# aborting and is worth stating exactly. `set -u` writes "$1: unbound
# variable" to stderr, but the read runs in a subshell (a pipeline here, a
# process substitution in --print-pins) and `|| true` below discards its
# status, so what the caller receives is an EMPTY record set. Every caller
# turns that into a named refusal: the count sites refuse with "must hold
# EXACTLY 3" and "carries ZERO data records", the read site with "3 record(s)
# counted but 0 read".
# Empty-and-refused, never "silently the unapproved
# bytes".
pin_records() { # <file>
  awk '{ sub(/\r$/, ""); sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, "") }
       $0 != "" && $0 !~ /^#/ { print }' "$1"
}

# Counted up front so a silently dropped record is a refusal rather than a
# smaller corpus. `|| true` (as with the grep this replaced): an unreadable
# file must reach the caller's named refusal, not abort inside a substitution.
count_pin_records() { # <file>
  pin_records "$1" | wc -l | tr -d ' ' || true
}

# THE APPROVED BYTES, and the ONE place they are obtained. assert_committed
# proves the working copy EQUALS HEAD's blob; anchor_pins then hands every
# consumer HEAD's blob, so "what I checked is what I read" holds by
# construction rather than by the check and the read staying adjacent.
# Re-reading the working copy after a successful comparison is sound only
# while nothing can change it in between — and the file this guards is
# exactly the file an attacker, or a hurried operator with
# `git update-index --assume-unchanged`, is editing.
#
# --print-pins had this shape before three sibling sites did:
# verify_key extracted the PINNED FINGERPRINT from the working copy it
# had just compared, and both record loops read the working copy too. Fixing
# an instance is not fixing the class, so the anchoring is one function every
# verified path calls, and the working-tree default above is
# gone. Every verified path therefore consumes the same anchored bytes.
#
# A file, not a variable, because counting the records and reading them are
# two passes and only identical bytes make the counted-vs-read assertions
# mean anything. NEVER cached: every call re-runs the comparison, so a second
# caller cannot inherit a first caller's verdict.
PINS_BLOB=""
anchor_pins() { # -> $PINS_BLOB holds HEAD's $PINS; 1, named, if it is unapproved
  assert_committed "$PINS" || return 1
  if [ -z "$PINS_BLOB" ]; then
    PINS_BLOB="$(mktemp)" || return 1
    trap 'rm -f "$PINS_BLOB"' EXIT
  fi
  # Checked explicitly: this function is called in `||` context, where bash
  # switches errexit OFF for the whole body — an unchecked redirect would
  # leave a truncated blob behind and return whatever ran last.
  git cat-file blob "HEAD:$PINS" > "$PINS_BLOB" || {
    echo "could not read HEAD:$PINS — refusing" >&2; return 1; }
}

# ---------------------------------------------------------------------------
# --print-pins: the ONE validated source of W1's pinned versions.
#
# A consumer must not re-parse this file for itself with
#   read -r V0 V1 V2 <<<"$(awk '!/^#/ && NF {print $1}' w1.pins | tr '\n' ' ')"
# — a SECOND parser of a file this script already validates, and an
# unvalidated one. Measured on scratch copies of the real file: an INDENTED
# comment line gave V0='#' and glued V2='1.96.0 1.97.0'; a blank line in a CRLF
# file did the same, with V0 a lone '\r' (invisible in a terminal, and a real
# directory-name byte); and a file one record short left V2 EMPTY, expanding
# "$DATA/w1/$V2" to "$DATA/w1/" — the whole 6 GB corpus directory as a single
# "version" path. The w2 half had the identical exposure, closed the
# same way in build-w2.sh's own parser.
#
# This mode covers every check that needs nothing but the file: it is readable,
# it holds exactly the records the corpus definition pins, in that (ascending)
# order, and each carries the four fields the fetch loop reads with a
# well-formed sha256 pin. The release-key checks are NOT part of it — verify_key
# fetches the key over the network; run --verify-key for those.
#
# ANCHORED TO HEAD, AND UNCONDITIONALLY SO. This mode validates HEAD's blob,
# not the WORKING TREE: an uncommitted edit — or one masked by
# `git update-index --assume-unchanged`, which every status-based guard
# reads as clean — must not be certified by the one mode whose whole job is
# to be the trustworthy pin source. (The printed VERSIONS are pinned separately,
# by the
# expected_counts table in this file, and an edit that changes a version field
# or drops a record is refused below; what an unanchored run would certify is the
# rest of the record — the sha256 the fetch path then enforces, the dist date,
# the target.)
#
# NO OPT-OUT, deliberately, and no silent fallback:
#   - the fetch path already hard-requires git (verify_key anchors $PINS the
#     same way before a single byte is downloaded), so a non-git checkout
#     cannot use this script for its actual purpose. A --print-pins that kept
#     working there would be a mode that succeeds where the script does not.
#   - an opt-out flag is one an operator in a hurry, or a copied command line,
#     will carry — and the consumer reads stdout, so the consequence is silent
#     by construction. That is the exact defect class this battery has been
#     chasing.
#   - "I am deliberately editing the pins file" is precisely when the versions
#     must NOT be printed as approved. Commit the edit (staging is not enough
#     — the comparison is against HEAD); the commit IS the approval.
# Outside a git repo, or on an unborn HEAD, assert_committed says so by name
# and nothing is printed.
# ---------------------------------------------------------------------------
print_pins() {
  local total="${#EXPECTED_COUNTS[@]}" n i=0 expect out=""
  local version date target want extra
  [ -f "$PINS" ] && [ -r "$PINS" ] || {
    echo "REFUSING: $PINS is missing or unreadable — there are no pins to print" >&2
    exit 1; }
  # Every check below reads HEAD'S BYTES, not the working copy anchor_pins just
  # compared them to: "what I validated is what was approved" is then true by
  # construction, and survives any later reordering of these two steps.
  anchor_pins || {
    echo "REFUSING: --print-pins is the ONE VALIDATED source of W1's pinned" >&2
    echo "  versions, and validating bytes nobody approved is not validation." >&2
    echo "  Nothing has been printed." >&2
    exit 1; }
  n="$(count_pin_records "$PINS_BLOB")"
  [ "$n" -eq "$total" ] || {
    echo "REFUSING: $PINS must hold EXACTLY $total data record(s) — one per" >&2
    echo "  version the corpus definition pins (expected_counts) — and holds $n." >&2
    echo "  A consumer reads this line into a fixed set of variables, so a short" >&2
    echo "  file leaves one EMPTY (a bare \$DATA/w1/ path) and a long one glues" >&2
    echo "  the tail into the last." >&2
    exit 1; }
  # Process substitution, NOT a pipe: a pipe would run the loop in a subshell
  # and throw away both the counter and the line being built.
  while read -r version date target want extra; do
    i=$((i + 1))
    [ "$i" -le "$total" ] || {
      echo "REFUSING: $PINS holds more records than the $total just counted —" >&2
      echo "  two reads of the file disagreed, which is the defect this mode" >&2
      echo "  exists to remove" >&2
      exit 1; }
    expect="${EXPECTED_COUNTS[$((i - 1))]%% *}"
    [ -z "$extra" ] || {
      echo "REFUSING: $PINS record $i has MORE than the four fields the fetch" >&2
      echo "  loop reads (<version> <date> <target> <sha256>); trailing: '$extra'" >&2
      exit 1; }
    { [ -n "$version" ] && [ -n "$date" ] && [ -n "$target" ] && [ -n "$want" ]; } || {
      echo "REFUSING: $PINS record $i has FEWER than the four fields the fetch" >&2
      echo "  loop reads (<version> <date> <target> <sha256>): '$version $date $target $want'" >&2
      exit 1; }
    [ "$version" = "$expect" ] || {
      echo "REFUSING: $PINS record $i names version '$version', but the corpus" >&2
      echo "  definition pins '$expect' in that position (expected_counts)." >&2
      echo "  --print-pins prints the definition's ascending order; it does not" >&2
      echo "  reorder the file, and it never names a version whose corpus root" >&2
      echo "  is UNPINNED." >&2
      exit 1; }
    normalized_pin "in $PINS for $version" " — refusing, nothing printed" "$want" \
      >/dev/null || exit 1
    out="${out:+$out }$version"
  done < <(pin_records "$PINS_BLOB")
  # The same shape as the fetch loop's own tail guard: counting the records and
  # reading them are two passes, and only an assertion makes them one answer.
  [ "$i" -eq "$total" ] || {
    echo "REFUSING: $PINS: $n record(s) counted but $i read — refusing" >&2
    exit 1; }
  printf '%s\n' "$out"
}

# Re-run the release-key check against the fingerprint pinned in w1.pins.
# This is what makes "later runs check a committed constant, not a fetch"
# TRUE rather than a procedure someone remembers: every later run compares
# every manifest's signing primary against the committed fingerprint.
verify_key() {
  # The "committed constant" claim is only true if the pin is COMMITTED.
  # Verifying a working-tree value nobody reviewed is not the guarantee this
  # script advertises: an unapproved pins file would supply any fingerprint it
  # liked, and this function would then enforce the EDITOR's fingerprint and
  # the EDITOR's sha256 lines against every tarball it fetches.
  # `anchor_pins` carries the complete committed-byte check and is the sole
  # definition used here.
  anchor_pins || return 1
  # HEAD'S BYTES for both extractions below, not the working copy
  # `anchor_pins` just compared them to. This is the
  # pinned-fingerprint read: its value authenticates every fetched
  # tarball. Both loops in this file likewise consume the approved blob
  # rather than the working copy, so the bytes checked are the bytes
  # used.
  local hits pinned
  hits="$(grep -c '^# rust_release_key_fpr ' "$PINS_BLOB" || true)"
  if [ "$hits" != "1" ]; then
    echo "$PINS must carry EXACTLY ONE rust_release_key_fpr line (found $hits)" >&2
    echo "settle the release-key anchor decision first (A or B), and remove" >&2
    echo "any placeholder line" >&2
    return 1
  fi
  pinned="$(awk '/^# rust_release_key_fpr /{print $3; exit}' "$PINS_BLOB")"
  case "$pinned" in
    *[!0-9A-Fa-f]*|"") echo "pinned fingerprint is not hex: $pinned" >&2; return 1 ;;
  esac
  # A truncated fingerprint is not a fingerprint; require all 40 hex characters.
  [ ${#pinned} -eq 40 ] || {
    echo "pinned fingerprint must be 40 hex chars, got ${#pinned}" >&2; return 1; }
  # A pins file with no data records verifies NOTHING, and printing
  # "release key: ok" for it would be a vacuous pass with
  # exit 0.
  local records seen=0 version=""
  records="$(count_pin_records "$PINS_BLOB")"
  [ "$records" -ge 1 ] || {
    echo "$PINS carries ZERO data records — there is nothing to verify and a" >&2
    echo "pass would be vacuous; refusing" >&2; return 1; }
  command -v gpg >/dev/null 2>&1 || { echo "gpg not found" >&2; return 1; }
  local work; work="$(mktemp -d)"
  # `local -x`: the shipped form exported GNUPGHOME without scoping it, so the
  # process carried a GNUPGHOME pointing at a DELETED directory long after
  # verify_key returned.
  local -x GNUPGHOME="$work/gnupg"
  mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
  # Bounded: these run BEFORE anything is authenticated, so cap size and time
  # rather than trusting the far end. --max-filesize aborts on a DECLARED
  # over-size and, on curl < 8.4.0, is ignored entirely when the size is not
  # known before transfer — which is why --max-time is here too and is the
  # bound that always holds. Record the curl version in the run report.
  # The byte bound is version-dependent;
  # the time bound is not.
  local CURL="curl -fsLO --max-filesize 8000000 --max-time 120"
  ( cd "$work" && { $CURL "https://static.rust-lang.org/rust-key.gpg.ascii" \
                 || $CURL "https://static.rust-lang.org/rust-key.gpg.asc"; } \
                 && gpg --quiet --import rust-key.gpg.as* ) || {
    echo "could not fetch/import the release key" >&2; rm -rf "$work"; return 1; }
  local got
  got="$(gpg --with-colons --fingerprint | awk -F: '/^fpr:/{print $10; exit}')"
  if [ "$got" != "$pinned" ]; then
    echo "KEY FINGERPRINT MISMATCH: pinned $pinned, fetched $got" >&2
    rm -rf "$work"; return 1
  fi
  local first="" status keys primary
  # `|| [ -n "$version" ]`: a pins file whose last line has no trailing
  # newline made `read` return 1 with the fields ALREADY assigned, so the plain
  # loop dropped its last record silently — one editor keystroke away from
  # verifying two of three pins and still printing
  # "ok".
  while read -r version _date _target _want || [ -n "$version" ]; do
    case "$version" in ""|"#"*) continue ;; esac
    seen=$((seen + 1))
    ( cd "$work" && $CURL "$BASE/channel-rust-${version}.toml" \
                 && $CURL "$BASE/channel-rust-${version}.toml.asc" ) || {
      echo "could not fetch the channel manifest for $version" >&2; rm -rf "$work"; return 1; }
    # One verification, captured to a variable. `grep -q` inside a
    # pipeline under `set -o pipefail` can fail on SIGPIPE when the reader
    # exits early; capturing first removes the question, and verifying once
    # instead of twice avoids repeating the same cryptographic operation.
    status="$(gpg --status-fd 1 --verify "$work/channel-rust-${version}.toml.asc" \
              "$work/channel-rust-${version}.toml" 2>/dev/null || true)"
    keys="$(key_verdict "$status" "$version")" || { rm -rf "$work"; return 1; }
    primary="${keys##* }"
    # The signing key must be THE PINNED KEY, not merely the same key across
    # the manifests: a substituted bundle containing the pinned public key
    # PLUS a rogue signing key would satisfy both the first-fingerprint check
    # and the all-agree check while every signature came from the rogue key.
    # Therefore each manifest's primary key is compared directly with the pin.
    if [ "$primary" != "$pinned" ]; then
      echo "signature for $version is from primary key $primary, pinned is $pinned" >&2
      rm -rf "$work"; return 1
    fi
    # Enforce the PRIMARY only. A rotated signing subkey under the same
    # primary is a normal, valid release; demanding the whole pair match
    # would reject valid signing-subkey rotation under the pinned primary.
    if [ -z "$first" ]; then first="$primary"; fi
    if [ "$primary" != "$first" ]; then
      echo "PRIMARY KEY CHANGED between versions: $first vs $primary at $version" >&2
      rm -rf "$work"; return 1
    fi
    echo "ok signature $version KEYS $keys"
  done < "$PINS_BLOB"
  rm -rf "$work"
  [ "$seen" -eq "$records" ] || {
    echo "$PINS has $records data record(s) but the loop verified $seen — refusing" >&2
    return 1; }
  echo "release key: ok (pinned $pinned, $seen of $records pinned record(s) verified)"
}

# device:inode, the only identity that survives a macOS firmlink.
inode_id() { stat -f '%d:%i' "$1" 2>/dev/null || stat -c '%d:%i' "$1" 2>/dev/null || true; }

# Canonicalise a path that may not exist yet: resolve the deepest EXISTING
# ancestor with `cd -P` (which resolves symlinks) and re-append the rest.
canon_path() {
  local p="$1" tail="" base parent out
  while [ ! -d "$p" ]; do
    base="$(basename "$p")"; parent="$(dirname "$p")"
    tail="/$base$tail"
    [ "$parent" != "$p" ] || break
    p="$parent"
  done
  if [ -d "$p" ]; then p="$(cd "$p" && pwd -P)"; fi
  if [ "$p" = "/" ]; then p=""; fi
  out="$p$tail"
  [ -n "$out" ] || out="/"
  printf '%s\n' "$out"
}

# NEVER ~/.rustup. The shipped guard was a literal prefix match on "$HOME/.rustup",
# which four equivalent paths walked straight past: "$HOME/./.rustup/x",
# "$HOME//.rustup/x", the macOS firmlink "/System/Volumes/Data$HOME/.rustup/x",
# and a symlink into it.
refuse_if_inside_rustup() {
  local data="$1" rustup="$HOME/.rustup" data_c rustup_c rid probe pid
  data_c="$(canon_path "$data")"
  rustup_c="$(canon_path "$rustup")"
  case "$data_c" in
    "$rustup_c"|"$rustup_c"/*)
      echo "REFUSING: \$GRANARY_BENCH_DATA is inside ~/.rustup ($data -> $data_c)" >&2
      return 1 ;;
  esac
  # String canonicalisation cannot see through a firmlink: on macOS
  # /System/Volumes/Data/Users/… IS /Users/…, and `pwd -P` does not rewrite it.
  # device:inode does — both report the same pair. So compare identities of
  # every existing ancestor as well.
  [ -d "$rustup" ] || return 0
  rid="$(inode_id "$rustup")"
  [ -n "$rid" ] || return 0
  probe="$data_c"
  while : ; do
    if [ -e "$probe" ]; then
      pid="$(inode_id "$probe")"
      if [ -n "$pid" ] && [ "$pid" = "$rid" ]; then
        echo "REFUSING: \$GRANARY_BENCH_DATA is inside ~/.rustup ($probe is ~/.rustup)" >&2
        return 1
      fi
    fi
    case "$probe" in /|"") break ;; esac
    probe="$(dirname "$probe")"
  done
  return 0
}

usage_error() {
  echo "$1" >&2
  echo "usage: $0 [--self-test | --self-test-key | --verify-key | --print-pins]" >&2
  exit 2
}

# Extra arguments are refused: accepted and ignored, `--verify-key --whatever`
# would look like it had done something with --whatever.
case "${1:-}" in
  --self-test)
    [ $# -eq 1 ] || usage_error "unexpected extra argument(s) after $1: ${*:2}"
    self_test; exit 0 ;;
  --self-test-key)
    [ $# -eq 1 ] || usage_error "unexpected extra argument(s) after $1: ${*:2}"
    self_test_key; exit 0 ;;
  --verify-key)
    [ $# -eq 1 ] || usage_error "unexpected extra argument(s) after $1: ${*:2}"
    if verify_key; then exit 0; else exit 1; fi ;;
  --print-pins)
    [ $# -eq 1 ] || usage_error "unexpected extra argument(s) after $1: ${*:2}"
    print_pins; exit 0 ;;
  "")
    [ $# -eq 0 ] || usage_error "unexpected argument(s): $*" ;;
  *)
    usage_error "unknown mode: $1" ;;
esac

refuse_if_inside_rustup "$DATA" || exit 1

# Every fetch enforces the pinned key, not just the first one.
verify_key || { echo "release-key check failed — refusing to fetch" >&2; exit 1; }

# Anchored HERE, and not inherited from verify_key: the source this loop reads
# must not depend on some other function having anchored first, or on the two
# staying in this order. anchor_pins re-runs the comparison, so this costs one
# cheap `git cat-file`.
anchor_pins || { echo "REFUSING: $PINS is not anchored to HEAD — nothing fetched" >&2; exit 1; }
records="$(count_pin_records "$PINS_BLOB")"
[ "$records" -ge 1 ] || {
  echo "REFUSING: $PINS carries ZERO data records — there would be no corpus" >&2
  exit 1; }
seen=0
version=""
mkdir -p "$DATA/w1/dist"
while read -r version date target want || [ -n "$version" ]; do
  case "$version" in ''|'#'*) continue ;; esac
  seen=$((seen + 1))
  # Validate the pin BEFORE anything destructive can see it: the shipped code
  # routed a malformed or merely uppercase pin straight into `rm -f` on a
  # 200 MB tarball.
  want="$(normalized_pin "in $PINS for $version" " — refusing, nothing deleted" "$want")" \
    || exit 1
  tarball="rust-${version}-${target}.tar.xz"
  url="$BASE/${date}/${tarball}"
  dest="$DATA/w1/dist/$tarball"
  downloaded=0
  if [ ! -f "$dest" ]; then
    echo "fetching $url"
    curl --fail --location --silent --show-error --output "$dest.part" "$url"
    mv "$dest.part" "$dest"
    downloaded=1
  fi
  if ! verify_sha256 "$dest" "$want"; then
    if [ "$downloaded" = 1 ]; then
      rm -f "$dest"
      echo "removed the download THIS RUN made; re-run to retry" >&2
    else
      echo "$dest was already here and does not match its pin — NOT deleting it" >&2
      echo "inspect it, then remove it by hand if you want a fresh download" >&2
    fi
    exit 1
  fi
  root="$DATA/w1/$version"
  # The stamp lives OUTSIDE $root on purpose: $root IS the measured corpus, so
  # a file inside it would change the very file count and byte total this run
  # measures and the pilot comparison depends on.
  stamp="$DATA/w1/.stamp-$version"
  exp="$(expected_counts "$version")" || {
    echo "REFUSING: no expected-count entry for $version — the corpus definition" >&2
    echo "is UNPINNED for this version. Add one to expected_counts(), with its" >&2
    echo "provenance, before measuring it" >&2
    exit 1; }
  exp_files="${exp%% *}"; exp_bytes="${exp##* }"
  fresh=0
  if [ ! -d "$root" ]; then
    echo "unpacking $tarball"
    rm -rf "$root.part"; mkdir -p "$root.part"
    tar -xf "$dest" -C "$root.part"
    # The tarball must hold exactly ONE top-level entry, and it must be a
    # directory: that IS the corpus root. Counting only directories let a stray
    # top-level FILE be dropped silently while $root was still created — and
    # the next run then reported the incomplete tree as verified with
    # exit 0.
    entries="$(find "$root.part" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')"
    if [ "$entries" != "1" ]; then
      echo "REFUSING: $tarball unpacked to $entries top-level entries, want exactly 1" >&2
      rm -rf "$root.part"; exit 1
    fi
    inner="$(find "$root.part" -mindepth 1 -maxdepth 1 -type d)"
    if [ -z "$inner" ]; then
      echo "REFUSING: $tarball's single top-level entry is not a directory" >&2
      rm -rf "$root.part"; exit 1
    fi
    # The move happens only AFTER both checks, so a refusal never leaves a
    # $root behind for a later run to report as verified corpus.
    mv "$inner" "$root"
    rmdir "$root.part"
    fresh=1
  fi
  files="$(find "$root" -type f | wc -l | tr -d ' ')"
  bytes="$(find "$root" -type f -exec cat {} + | wc -c | tr -d ' ')"
  if [ "$files" != "$exp_files" ] || [ "$bytes" != "$exp_bytes" ]; then
    echo "REFUSING: corpus definition drift for $version" >&2
    echo "  expected files=$exp_files bytes=$exp_bytes (expected_counts, see its provenance)" >&2
    echo "  measured files=$files bytes=$bytes" >&2
    echo "Investigate the count mismatch before using this tree for W1 benchmark comparisons." >&2
    exit 1
  fi
  # Tie the tree that gets MEASURED to the tarball that got VERIFIED. Without
  # this, `[ ! -d "$root" ]` skipped the unpack for ANY pre-existing or
  # partially unpacked tree and reported it under an `ok <tarball> <sha>` line
  # it had no causal link to.
  if [ -f "$stamp" ]; then
    s_sha="$(awk '$1=="sha256"{print $2; exit}' "$stamp")"
    s_files="$(awk '$1=="files"{print $2; exit}' "$stamp")"
    s_bytes="$(awk '$1=="bytes"{print $2; exit}' "$stamp")"
    if [ "$s_sha" != "$want" ] || [ "$s_files" != "$files" ] || [ "$s_bytes" != "$bytes" ]; then
      echo "REFUSING: the unpack stamp for $version does not describe this tree" >&2
      echo "  stamp    sha256=$s_sha files=$s_files bytes=$s_bytes ($stamp)" >&2
      echo "  measured sha256=$want files=$files bytes=$bytes" >&2
      echo "remove $root and $stamp to re-unpack from the verified tarball" >&2
      exit 1
    fi
  else
    # Migration: the corpus may already be unpacked from before stamps existed.
    # Back-fill rather than force a re-download — but ONLY here, past the
    # expected-count check above, so the tree we vouch for is one that matched
    # the pinned definition exactly.
    { echo "w1-stamp 1"
      echo "version $version"
      echo "sha256 $want"
      echo "files $files"
      echo "bytes $bytes"; } > "$stamp"
    if [ "$fresh" = 1 ]; then echo "stamped $version (fresh unpack of $tarball)"
    else echo "stamped $version (back-filled: the existing tree matches the pinned counts exactly)"; fi
  fi
  echo "w1 $version: root=$root files=$files bytes=$bytes"
done < "$PINS_BLOB"
[ "$seen" -eq "$records" ] || {
  echo "REFUSING: $PINS has $records data record(s) but the loop processed $seen" >&2
  exit 1; }
echo "w1: $seen of $records pinned record(s) processed"
