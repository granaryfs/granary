#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# The CI FUSE lane's mount-table helper: list, check, or reap the mounts a job
# owns, keyed on WHERE they are (a directory prefix the job owns) and on WHAT
# they are (source `gran`, fstype `fuse` or `fuse.*` — a granary mount on
# either mount route), never on a name alone.
#
#   ci-mounts.sh list  (--under DIR | --gran)...   NUL-separated targets,
#                                                     deepest first
#   ci-mounts.sh check (--under DIR | --gran)...   exit 1 if any such mount
#                                                     exists (each is printed);
#                                                     exit 0 with a witness line
#   ci-mounts.sh reap  (--under DIR | --gran)...   root only: lazy-unmount
#                                                     each (deepest first), abort
#                                                     its FUSE connection, then
#                                                     verify none remain (exit 1
#                                                     if one does)
#   ci-mounts.sh --self-test [--under DIR]         root only, Linux only:
#                                                     every refusal fires and the
#                                                     reap works on planted mounts
#
# Exit 2 everywhere means "could not decide": the mount table could not be
# read, the caller is not root for `reap`, or the arguments are malformed. A
# gate that cannot read what it gates on must refuse, never report clean.
#
# Why a directory prefix and not only the source name: the suite this lane
# runs as root creates mounts of its own — bind mounts of scratch
# directories, and one FUSE mount whose source is deliberately not `gran` —
# and a job cancelled mid-suite leaves them behind. Everything that job
# creates lives under one per-run directory, so "every mount below that
# directory" is the reap domain, and the source-name selector is the belt
# over it for a granary mount that ended up anywhere else.
#
# Why findmnt's RAW format and `printf %b`: raw output escapes every byte a
# path can carry that would break field splitting (space, tab, newline,
# backslash) as `\xNN`, and `printf %b` undoes exactly that escaping. The
# suite has a fixture whose mountpoint carries a space; a word-split
# `$(findmnt ...)` would hand `umount` the literal `\x20` and fail to reap it.
#
# Why the connection abort is scoped: `/sys/fs/fuse/connections/<N>/abort`
# ends every waiter on FUSE connection N, and N is the minor number of the
# mount's anonymous device (mountinfo's `0:N`). Aborting EVERY connection on
# the host would also end whatever unrelated FUSE filesystem the machine
# happens to have; aborting only the connections of the mounts being reaped
# cannot. The connection directories are root-only (mode 0500), so this must
# run as root — a glob expanded by an unprivileged shell silently matches
# nothing.
set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd -P)/$(basename "$0")"

# Prints the header's usage block: every comment line from the one that starts
# with the script's own name down to the first blank comment line after it.
# Deriving the range from the text means an edit to the header above cannot
# silently truncate or extend what this prints, which a hard-coded line range
# did — and the header has already grown twice.
usage() {
  awk '
    /^#   ci-mounts\.sh/ { on = 1 }
    on && /^#[[:space:]]*$/ { exit }
    on { sub(/^# ?/, ""); print }
  ' "$SELF" >&2
}

die() {
  echo "ci-mounts: $*" >&2
  exit 2
}

# Parse the selector flags shared by list/check/reap. Sets UNDER (an absolute
# directory, no trailing slash, or empty) and GRAN (0/1). At least one
# selector is required: a selector-less call would mean "every mount on the
# host", which is never what a job owns.
UNDER=""
GRAN=0
parse_selectors() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --under)
        [ "$#" -ge 2 ] || die "--under needs a directory"
        [ -n "$2" ] || die "--under must be non-empty"
        case "$2" in
          /) die "--under / would select every mount on the host" ;;
          /*) ;;
          *) die "--under must be an absolute path: $2" ;;
        esac
        case "$2" in
          */) die "--under must not end in a slash: $2" ;;
          */../*|*/..|*/./*|*/.) die "--under must be a plain path without . or .. components: $2" ;;
        esac
        # Selection compares findmnt's ESCAPED target against this prefix, so a
        # prefix carrying any byte findmnt would escape could never match its
        # own mounts. The escaped set is not four characters: findmnt escapes
        # every whitespace byte, every control byte and the backslash, so the
        # refusal is written as those CLASSES rather than as a list — a `\r`
        # or a `\v` in a prefix is the same silent no-match as a space, and
        # this is the fail-open the header says the tool refuses.
        case "$2" in
          *[[:space:]]*|*[[:cntrl:]]*|*'\'*) die "--under must not contain whitespace, a control byte or a backslash (findmnt escapes them, so such a prefix can never match its own mounts): $2" ;;
          *//*) die "--under must not contain a doubled slash (it is compared against the kernel's own canonical targets, which never carry one): $2" ;;
        esac
        # REFUSED rather than overwritten: a silent overwrite means every
        # prefix but the last goes unchecked, which is the fail-open shape.
        # One domain per invocation; call the tool twice for two.
        [ -z "$UNDER" ] || die "--under may be given only once (a second would silently replace the first): $UNDER then $2"
        UNDER="$2"
        shift 2
        ;;
      --gran)
        GRAN=1
        shift
        ;;
      *) die "unknown argument: $1" ;;
    esac
  done
  [ -n "$UNDER" ] || [ "$GRAN" -eq 1 ] || die "a selector is required: --under DIR and/or --gran"
  # The prefix is compared against findmnt's targets, which the kernel stores
  # CANONICALISED — so a prefix reaching its directory through a symlink can
  # never match its own mounts, and the caller would read a clean witness over
  # a leak. Resolve the deepest existing ancestor and require the literal
  # prefix to equal what the kernel would have recorded. The reap also
  # DELETES under this prefix, so a symlinked component can redirect
  # writes as well as hide mounts from the prefix check.
  if [ -n "$UNDER" ]; then
    local probe rest resolved
    probe="$UNDER"
    rest=""
    # `! -d` alone would walk PAST a symlink pointing at a file, treating an
    # existing entry as a missing component and reconstructing a path that
    # never gets compared to what it really resolves to.
    while [ ! -d "$probe" ] && [ ! -L "$probe" ] && [ "$probe" != "/" ]; do
      rest="/$(basename "$probe")$rest"
      probe="$(dirname "$probe")"
    done
    resolved="$(cd "$probe" 2>/dev/null && pwd -P)" \
      || die "--under's existing ancestor cannot be resolved: $probe"
    # `pwd -P` of the ROOT is "/", and the suffix already carries its own
    # leading slash, so rejoining them naively yields "//x" and refuses a
    # perfectly ordinary prefix. Measured, not reasoned.
    [ "$resolved" != "/" ] || resolved=""
    [ ! -L "$probe" ] \
      || die "--under passes through the symlink $probe: it is compared against the kernel's canonical mount targets, and this tool DELETES under this prefix"
    [ "${resolved}${rest}" = "$UNDER" ] \
      || die "--under resolves to ${resolved}${rest}, not the literal $UNDER: a symlinked component can never match the kernel's canonical mount targets, and this tool DELETES under this prefix"
  fi
}

# Emit the selected mounts, deepest target first, one record per line:
#   <escaped target> <source> <fstype> <maj:min>
# "Deepest first" is a sort on the escaped target's byte length, descending.
# That is not path depth, and it does not need to be: the property the reap
# needs is that a mount is unmounted before the mount it sits INSIDE, and a
# path below another is always strictly longer than it. Unrelated mounts may
# come out in any order.
# Refuses (exit 2) when the table cannot be read or reads empty — a real
# mount table always has at least the root row, so an empty read is a failed
# read wearing the shape of "nothing mounted".
selected_rows() {
  local table rc malformed
  set +e
  table="$(findmnt -rn -o TARGET,SOURCE,FSTYPE,MAJ:MIN 2>&1)"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    echo "ci-mounts: could not read the mount table (findmnt rc=$rc): $table" >&2
    return 2
  fi
  if [ -z "$table" ]; then
    echo "ci-mounts: the mount table read empty; refusing to treat that as clean" >&2
    return 2
  fi
  # Selection happens on the ESCAPED target, which is safe because the
  # prefix itself is a plain path (no byte findmnt would escape), so a
  # prefix match on the escaped form is a prefix match on the real path.
  # A row that does not parse into exactly four fields is REFUSED, never
  # dropped: findmnt renders an absent source as `-`, but a row this selector
  # cannot read is a row it cannot judge, and silently skipping it is the
  # fail-open the whole tool exists to avoid.
  local malformed
  malformed="$(printf '%s\n' "$table" | awk 'NF != 4 { print }')"
  if [ -n "$malformed" ]; then
    echo "ci-mounts: the mount table has row(s) this selector cannot read (want 4 fields); refusing rather than skipping them:" >&2
    printf '%s\n' "$malformed" | sed 's/^/  /' >&2
    return 2
  fi
  printf '%s\n' "$table" | awk -v under="$UNDER" -v gran="$GRAN" '
    NF == 4 {
      sel = 0
      if (under != "" && ($1 == under || index($1, under "/") == 1)) sel = 1
      # EXACTLY gran. Looser prefixes matched unrelated sources such as
      # gran[backup], gran[/backup, and gran[/sub]suffix, so the source
      # predicate is exactly gran and subtree renders are not supported.
      # A false match can detach an unrelated filesystem, which is far worse
      # than the case being covered. Nothing in the suite currently binds the
      # granary mount, only scratch directories. A bind of a granary subtree
      # UNDER the lane own directory is still caught by the --under domain;
      # one placed elsewhere is a recorded residual, not something this
      # predicate should guess at.
      # The exact comparison below enforces that boundary.
      if (gran == 1 && $2 == "gran" && ($3 == "fuse" || index($3, "fuse.") == 1)) sel = 1
      if (sel) print length($1) "\t" $0
    }' | sort -t "$(printf '\t')" -k1,1nr | cut -f2-
}

describe_selection() {
  local parts=""
  [ -n "$UNDER" ] && parts="under $UNDER"
  if [ "$GRAN" -eq 1 ]; then
    [ -n "$parts" ] && parts="$parts, or "
    parts="${parts}source gran with fstype fuse/fuse.*"
  fi
  printf '%s' "$parts"
}

# The four call sites below all need the same thing: the selected rows, or a
# refusal. Written once so a change to how an unreadable table is surfaced
# cannot be applied to three of them and forgotten in the fourth.
ROWS=""
require_rows() {
  local status
  set +e
  ROWS="$(selected_rows)"
  status=$?
  set -e
  [ "$status" -eq 0 ] || exit 2
}

cmd_list() {
  parse_selectors "$@"
  local rows target
  require_rows
  rows="$ROWS"
  [ -n "$rows" ] || return 0
  while IFS= read -r row; do
    # The same sentinel the reap uses: command substitution strips trailing
    # newlines, which would silently shorten a target whose last byte is one.
    target="$(printf '%bx' "${row%% *}")"
    target="${target%x}"
    printf '%s\0' "$target"
  done <<< "$rows"
}

cmd_check() {
  parse_selectors "$@"
  local rows
  require_rows
  rows="$ROWS"
  if [ -n "$rows" ]; then
    echo "ci-mounts: mount(s) present ($(describe_selection)):" >&2
    printf '%s\n' "$rows" | sed 's/^/  /' >&2
    exit 1
  fi
  echo "ci-mounts: no mount $(describe_selection)"
}

cmd_reap() {
  parse_selectors "$@"
  [ "$(id -u)" -eq 0 ] || die "reap must run as root (unmounting and aborting FUSE connections need it)"
  local rows row escaped target source fstype majmin minor reaped=0
  local -a row_lines
  require_rows
  rows="$ROWS"
  # The count is the number of rows this reap will ACT on, taken once from the
  # list itself rather than accumulated in the loop: a future per-row skip
  # cannot then desync the printed number from what was selected.
  if [ -n "$rows" ]; then
    # Counted in the shell, with no external command: this function runs from
    # a teardown whose PATH the caller controls, and the count must not be one
    # more thing that can fail there.
    mapfile -t row_lines <<< "$rows"
    reaped="${#row_lines[@]}"
  fi
  if [ -n "$rows" ]; then
    while IFS= read -r row; do
      # `read`, never `set -- $row`: the latter is subject to pathname
      # expansion, so a target or source carrying `*` or `?` would expand
      # against the filesystem and shift the fstype and device fields.
      IFS=' ' read -r escaped source fstype majmin <<< "$row"
      target="$(printf '%bx' "$escaped")"
      target="${target%x}"
      echo "ci-mounts: reaping $target ($source $fstype $majmin)"
      # The abort comes FIRST, before the lazy detach. `umount` stats its
      # target before detaching, and a stat of a FUSE root whose attribute
      # cache has expired is a request to the daemon — against a daemon that
      # is alive but WEDGED (not dead: that answers ENOTCONN at once) the
      # unmount can block, and the abort that would unstick it is the very
      # thing waiting behind it. Aborting a connection about to be detached
      # costs nothing.
      case "$fstype" in
        fuse|fuse.*)
          minor="${majmin#*:}"
          # Guarded, and the guard is the point: the connection directory can
          # disappear between the test and the write (the kernel removes it
          # when a detached mount loses its last user), and an unguarded
          # redirection failing under errexit would end the reap mid-loop —
          # leaving every later mount untouched AND skipping the verifying
          # re-list that is this function's actual proof.
          if [ ! -d /sys/fs/fuse/connections ]; then
            # Distinct from "already gone": with no fusectl mounted there is
            # no abort to reach at all, and a process blocked inside a request
            # to a wedged daemon stays blocked. Saying "no connection left"
            # here would be a success-shaped no-op.
            echo "ci-mounts: /sys/fs/fuse/connections is not mounted, so connection $minor for $target could not be aborted" >&2
          elif [ -e "/sys/fs/fuse/connections/$minor/abort" ]; then
            if echo 1 > "/sys/fs/fuse/connections/$minor/abort" 2>/dev/null; then
              echo "ci-mounts: aborted fuse connection $minor for $target"
            else
              echo "ci-mounts: fuse connection $minor went away before it could be aborted" >&2
            fi
          else
            echo "ci-mounts: no fuse connection $minor left to abort for $target"
          fi
          ;;
      esac
      if ! umount -l -- "$target"; then
        echo "ci-mounts: umount -l failed for $target" >&2
      fi
    done <<< "$rows"
  fi
  require_rows
  rows="$ROWS"
  if [ -n "$rows" ]; then
    echo "ci-mounts: mount(s) still present after the reap ($(describe_selection)):" >&2
    printf '%s\n' "$rows" | sed 's/^/  /' >&2
    exit 1
  fi
  echo "ci-mounts: reaped $reaped mount(s) (attempts; the re-list above is the verification); none remain $(describe_selection)"
}

# ---------------------------------------------------------------------------
# --self-test: every refusal fires, and the reap works on planted mounts —
# including a nested one under a mountpoint whose path carries a space, an
# impostor with source `gran` on a non-FUSE fstype (must NOT match --gran),
# and an outsider above the prefix (must SURVIVE a --under reap).
# ---------------------------------------------------------------------------
CHECKS=0
# The self-test's one capture idiom. Every assertion below needs the same four
# clauses — errexit off, stdout AND stderr captured, the status kept, errexit
# back on — and a copy that drops one silently changes what is captured or ends
# the run at the next non-zero status. Written once, called as `try <cmd...>`,
# leaving `out` and `rc` set.
out=""
rc=0
try() {
  set +e
  out="$("$@" 2>&1)"
  rc=$?
  set -e
}
pass() { CHECKS=$((CHECKS + 1)); echo "ok $CHECKS - $1"; }
fail() { CHECKS=$((CHECKS + 1)); echo "not ok $CHECKS - $1" >&2; echo "ci-mounts self-test: FAIL" >&2; exit 1; }

SELFTEST_ROOT=""
SELFTEST_EXEC=""
selftest_cleanup() {
  set +e
  [ -z "$SELFTEST_EXEC" ] || rm -rf -- "$SELFTEST_EXEC"
  if [ -n "$SELFTEST_ROOT" ]; then
    # Best effort, deepest first, so a failed check never leaves a mount
    # behind for the caller's own gate to trip over.
    # This unwind uses the tool's OWN selection rather than a second copy of
    # the prefix predicate and the deepest-first sort: a change to what "under"
    # means must not leave the self-test cleaning a different set of paths than
    # the command it is testing.
    while IFS= read -r -d '' t; do umount -l -- "$t" 2>/dev/null; done < <("$SELF" list --under "$SELFTEST_ROOT" 2>/dev/null)
    while IFS= read -r -d '' t; do umount -l -- "$t" 2>/dev/null; done < <("$SELF" list --under "$SELFTEST_ROOT.outside" 2>/dev/null)
    rm -rf -- "$SELFTEST_ROOT" "$SELFTEST_ROOT.outside"
  fi
}

cmd_self_test() {
  local root="" rc out stubbin granbin liarbin n t outside
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --under)
        [ "$#" -ge 2 ] || die "--under needs a directory"
        root="$2"
        shift 2
        ;;
      *) die "unknown argument: $1" ;;
    esac
  done
  [ "$(uname -s)" = Linux ] || die "--self-test needs Linux (it plants real mounts)"
  [ "$(id -u)" -eq 0 ] || die "--self-test must run as root (it plants real mounts)"
  command -v findmnt >/dev/null 2>&1 || die "--self-test needs findmnt"
  [ -n "$root" ] || root="/run/gran-ci/selftest-$$"
  case "$root" in
    /*) ;;
    *) die "--under must be absolute: $root" ;;
  esac
  { [ ! -e "$root" ] && [ ! -L "$root" ]; } || die "--self-test scratch already exists: $root"
  # The cleanup below REMOVES the sibling `.outside` path too (it is the
  # control proving a reap scoped to the prefix spares what sits beside it),
  # so refuse to run when something already lives there rather than mounting
  # over a stranger's directory and then deleting it.
  # `-e` alone is FALSE for a dangling symlink, whose directory entry exists
  # all the same — and the cleanup would remove it.
  { [ ! -e "$root.outside" ] && [ ! -L "$root.outside" ]; } \
    || die "--self-test would create and then remove $root.outside, which already exists"
  mkdir -p "$root"
  SELFTEST_ROOT="$root"
  # The stubs and the non-root copy below must be EXECUTABLE, and the mount
  # scratch above may sit on a filesystem mounted noexec (/run is, on Ubuntu:
  # a stub there fails with EACCES, rc 126, which reads like a failed findmnt
  # and passes the wrong check). They live in an ordinary temp dir instead.
  SELFTEST_EXEC="$(mktemp -d "${TMPDIR:-/tmp}/ci-mounts-selftest.XXXXXX")"
  trap selftest_cleanup EXIT

  # --- argument refusals ---------------------------------------------------
  try "$SELF" check
  [ "$rc" -eq 2 ] && [[ "$out" == *"a selector is required"* ]] \
    && pass "check with no selector refuses (exit 2)" || fail "check with no selector: rc=$rc out=$out"
  try "$SELF" check --under relative/dir
  [ "$rc" -eq 2 ] && [[ "$out" == *"must be an absolute path"* ]] \
    && pass "a relative --under refuses (exit 2)" || fail "relative --under: rc=$rc out=$out"
  try "$SELF" check --under /
  [ "$rc" -eq 2 ] && pass "--under / refuses (exit 2)" || fail "--under /: rc=$rc out=$out"
  try "$SELF" check --under "$root/"
  [ "$rc" -eq 2 ] && [[ "$out" == *"must not end in a slash"* ]] \
    && pass "a trailing slash refuses (exit 2)" || fail "trailing slash: rc=$rc out=$out"
  try "$SELF" check --under "$root/../x"
  [ "$rc" -eq 2 ] && pass "a .. component refuses (exit 2)" || fail ".. component: rc=$rc out=$out"
  try "$SELF" bogus --under "$root"
  [ "$rc" -eq 2 ] && pass "an unknown subcommand refuses (exit 2)" || fail "unknown subcommand: rc=$rc out=$out"
  try "$SELF" check --under "$root/with space"
  [ "$rc" -eq 2 ] && [[ "$out" == *"must not contain whitespace"* ]] \
    && pass "a prefix carrying a space refuses (exit 2)" || fail "escapable prefix: rc=$rc out=$out"
  # A byte the four-character list missed: findmnt escapes every control byte,
  # so a carriage return is the same silent no-match as a space.
  try "$SELF" check --under "$root/with"$'\r'"cr"
  [ "$rc" -eq 2 ] && [[ "$out" == *"must not contain whitespace"* ]] \
    && pass "a prefix carrying a control byte refuses (exit 2)" || fail "control-byte prefix: rc=$rc out=$out"
  ln -s "$root" "$SELFTEST_EXEC/link-to-root"
  try "$SELF" check --under "$SELFTEST_EXEC/link-to-root"
  # Either refusal is correct: the walk now stops AT the symlink and names it,
  # where before it resolved past and compared the reconstructed path.
  [ "$rc" -eq 2 ] && [[ "$out" == *"symlink"* || "$out" == *"can never match"* ]] \
    && pass "a --under reaching its directory through a symlink refuses (exit 2)" \
    || fail "symlinked prefix: rc=$rc out=$out"
  try "$SELF" check --under "$root" --under "$root"
  [ "$rc" -eq 2 ] && [[ "$out" == *"only once"* ]] \
    && pass "a second --under refuses rather than silently replacing the first" \
    || fail "repeated --under: rc=$rc out=$out"
  # A prefix whose deepest existing ancestor is the ROOT: a rejoin that
  # doubles the slash yields "//x" and refuses an ordinary path.
  try "$SELF" check --under "/nonexistent-under-root-$$"
  [ "$rc" -eq 0 ] && pass "a prefix directly under / is accepted (the root rejoin does not double its slash)" \
    || fail "root-ancestor prefix: rc=$rc out=$out"
  # A symlink to a FILE in the path: `! -d` alone walked past it as though the
  # component did not exist.
  : > "$SELFTEST_EXEC/afile"
  ln -s "$SELFTEST_EXEC/afile" "$SELFTEST_EXEC/link-to-file"
  try "$SELF" check --under "$SELFTEST_EXEC/link-to-file/below"
  [ "$rc" -eq 2 ] && pass "a --under passing through a symlink to a file refuses (exit 2)" \
    || fail "symlink-to-file prefix: rc=$rc out=$out"
  try "$SELF" check --under "/run//gran-ci"
  [ "$rc" -eq 2 ] && [[ "$out" == *"doubled slash"* ]] \
    && pass "a prefix carrying a doubled slash refuses (exit 2)" || fail "doubled-slash prefix: rc=$rc out=$out"

  # --- the unreadable-table refusal: a PATH whose findmnt fails ---------------
  stubbin="$SELFTEST_EXEC/stubbin"
  mkdir -p "$stubbin"
  for tool in bash env awk sort cut sed id umount uname printf cat basename dirname; do
    if command -v "$tool" >/dev/null 2>&1; then ln -s "$(command -v "$tool")" "$stubbin/$tool"; fi
  done
  printf '#!/bin/sh\necho "findmnt: simulated failure" >&2\nexit 1\n' > "$stubbin/findmnt"
  chmod +x "$stubbin/findmnt"
  try env PATH="$stubbin" "$SELF" check --under "$root"
  # The stub's OWN message is asserted, not merely a non-zero status: an
  # unexecutable stub (no +x, no /bin/sh) also fails, and a control that
  # accepts any failure certifies itself rather than the refusal.
  [ "$rc" -eq 2 ] && [[ "$out" == *"could not read the mount table"* ]] && [[ "$out" == *"simulated failure"* ]] \
    && pass "an unreadable mount table refuses (exit 2), never reports clean" \
    || fail "unreadable table: rc=$rc out=$out"
  printf '#!/bin/sh\nexit 0\n' > "$stubbin/findmnt"
  try env PATH="$stubbin" "$SELF" check --under "$root"
  [ "$rc" -eq 2 ] && [[ "$out" == *"read empty"* ]] \
    && pass "an empty mount table refuses (exit 2), never reports clean" \
    || fail "empty table: rc=$rc out=$out"

  # --- POSITIVE controls driven by a findmnt stub -------------------------------
  # The `--gran` arm had only a negative control (an impostor that must NOT
  # match), so a selector wired to always-false passed the whole self-test while
  # a leaked granary mount outside the prefix survived every reap. A stub that
  # emits one synthetic row is enough to prove the arm SELECTS, with no FUSE
  # daemon anywhere near it. The same stub proves the malformed-row refusal,
  # which likewise had no control: breaking it left the suite green while a row
  # the selector cannot read was silently skipped.
  granbin="$SELFTEST_EXEC/granbin"
  mkdir -p "$granbin"
  for tool in bash env awk sort cut sed id umount uname printf cat basename dirname; do
    if command -v "$tool" >/dev/null 2>&1; then ln -s "$(command -v "$tool")" "$granbin/$tool"; fi
  done
  printf '#!/bin/sh\nprintf "%%s\\n" "/somewhere/else gran fuse 0:99"\n' > "$granbin/findmnt"
  chmod +x "$granbin/findmnt"
  try env PATH="$granbin" "$SELF" check --gran
  [ "$rc" -eq 1 ] && [[ "$out" == *"/somewhere/else gran fuse 0:99"* ]] \
    && pass "--gran SELECTS a gran/fuse row anywhere on the host (the arm's positive control)" \
    || fail "gran positive control: rc=$rc out=$out"
  printf '#!/bin/sh\nprintf "%%s\\n" "/somewhere/else gran fuse.gran 0:99"\n' > "$granbin/findmnt"
  try env PATH="$granbin" "$SELF" check --gran
  [ "$rc" -eq 1 ] && pass "--gran selects the unprivileged route's fuse.gran too" \
    || fail "gran fuse.gran control: rc=$rc out=$out"
  # Each subtree spelling below is pinned as a NON-match: the predicate
  # is an exact source match and must never reach for a filesystem whose
  # name merely resembles ours.
  for impostor in 'gran[backup]' 'gran[/sub]' 'gran[/backup' 'gran[/sub]suffix' 'grand' 'gran2'; do
    printf '#!/bin/sh\nprintf "%%s\\n" "/somewhere/else %s fuse 0:99"\n' "$impostor" > "$granbin/findmnt"
    try env PATH="$granbin" "$SELF" check --gran
    [ "$rc" -eq 0 ] || fail "--gran must NOT select source $impostor: rc=$rc out=$out"
  done
  pass "--gran selects the source gran and nothing that merely resembles it (6 shapes)"
  printf '#!/bin/sh\nprintf "%%s\\n" "/somewhere/else gran"\n' > "$granbin/findmnt"
  try env PATH="$granbin" "$SELF" check --gran
  [ "$rc" -eq 2 ] && [[ "$out" == *"cannot read"* ]] \
    && pass "a mount-table row that does not parse is REFUSED (exit 2), never skipped" \
    || fail "malformed-row control: rc=$rc out=$out"

  # --- the non-root refusal for reap ------------------------------------------
  # A copy in the executable temp dir: the repository checkout may sit below
  # a directory an unprivileged user cannot traverse, and a permission error
  # on the way to the script would be mistaken for the refusal under test.
  cp -- "$SELF" "$SELFTEST_EXEC/copy.sh"
  chmod 755 "$SELFTEST_EXEC" "$SELFTEST_EXEC/copy.sh"
  if command -v runuser >/dev/null 2>&1; then
    try runuser -u nobody -- "$SELFTEST_EXEC/copy.sh" reap --under "$root"
  elif command -v setpriv >/dev/null 2>&1; then
    try setpriv --reuid=65534 --regid=65534 --clear-groups -- "$SELFTEST_EXEC/copy.sh" reap --under "$root"
  else
    # A control that cannot run is a failed control, not a passed one.
    fail "neither runuser nor setpriv is available, so the non-root reap refusal cannot be exercised"
  fi
  [ "$rc" -eq 2 ] && [[ "$out" == *"must run as root"* ]] \
    && pass "reap as a non-root user refuses (exit 2)" || fail "non-root reap: rc=$rc out=$out"

  # --- the clean case prints a witness ------------------------------------------
  try "$SELF" check --under "$root"
  [ "$rc" -eq 0 ] && [[ "$out" == "ci-mounts: no mount under $root" ]] \
    && pass "a clean prefix passes with its witness line" || fail "clean prefix: rc=$rc out=$out"

  # --- plant: tmpfs, a bind under a path with a space, a tmpfs nested under the
  #     bind (the bind path carries a space and a backslash), an impostor (source
  #     gran, fstype tmpfs), and an outsider above the prefix ------------------
  outside="$root.outside"
  mkdir -p "$root/a" "$root/b/c d\\e" "$root/imp" "$root/star*dir" "$root/starXdir" "$outside"
  # Private propagation on the two mounts that get something mounted INSIDE
  # them: on a host whose root mount is shared (Ubuntu's is), the tmpfs
  # mounted under the bind would otherwise propagate to the bind's source
  # and the count below would depend on the host's propagation setup.
  mount -t tmpfs tmpfs "$root/a"
  mount --make-private "$root/a"
  mkdir -p "$root/a/deep"
  mount --bind "$root/a" "$root/b/c d\\e"
  mount --make-private "$root/b/c d\\e"
  mount -t tmpfs tmpfs "$root/b/c d\\e/deep"
  mount -t tmpfs gran "$root/imp"
  # A mountpoint whose name is a glob, beside a sibling the glob matches: an
  # unquoted word split would expand it and shift the fstype/device fields.
  mount -t tmpfs tmpfs "$root/star*dir"
  mount -t tmpfs tmpfs "$outside"

  try "$SELF" check --under "$root"
  n="$(printf '%s\n' "$out" | grep -c '^  ' || true)"
  [ "$rc" -eq 1 ] && [ "$n" -eq 5 ] \
    && pass "check --under sees all five planted mounts (exit 1)" || fail "check sees planted: rc=$rc n=$n out=$out"
  try "$SELF" check --gran
  [ "$rc" -eq 0 ] && pass "an impostor with source gran on tmpfs does NOT match --gran" \
    || fail "impostor matched --gran: rc=$rc out=$out"

  n=0; t=""
  while IFS= read -r -d '' t; do
    n=$((n + 1))
    [ "$n" -eq 1 ] && [ "$t" = "$root/b/c d\\e/deep" ] \
      && pass "list returns the deepest mount first, its space and backslash unescaped" \
      || { [ "$n" -ne 1 ] || fail "list order/unescape: first=[$t]"; }
  done < <("$SELF" list --under "$root")
  [ "$n" -eq 5 ] && pass "list returns five NUL-separated targets" || fail "list count: $n"

  # A lying umount: exits 0 and unmounts nothing. The post-reap re-list is the
  # only thing that can see through it, so the reap must FAIL here (exit 1)
  # and the mounts must still be present afterwards.
  liarbin="$SELFTEST_EXEC/liarbin"
  mkdir -p "$liarbin"
  for tool in bash env awk sort cut sed id findmnt uname printf cat basename dirname; do
    if command -v "$tool" >/dev/null 2>&1; then ln -s "$(command -v "$tool")" "$liarbin/$tool"; fi
  done
  printf '#!/bin/sh\nexit 0\n' > "$liarbin/umount"
  chmod +x "$liarbin/umount"
  try env PATH="$liarbin" "$SELF" reap --under "$root"
  # The lie must be a LIE: a umount that failed loudly reaches the same
  # re-list and the same exit 1, so this also requires that no row reported a
  # umount failure. Without it the control passes on a stub that never ran.
  [ "$rc" -eq 1 ] && [[ "$out" == *"still present after the reap"* ]] && [[ "$out" != *"umount -l failed for"* ]] \
    && pass "a reap whose umount lies (exit 0, nothing unmounted) is refused by the re-list (exit 1)" \
    || fail "lying umount: rc=$rc out=$out"
  try "$SELF" check --under "$root"
  [ "$rc" -eq 1 ] && pass "the planted mounts are still present after the lying reap" || fail "post-liar check: rc=$rc out=$out"
  try "$SELF" reap --under "$root"
  [ "$rc" -eq 0 ] && [[ "$out" == *"reaped 5 mount(s)"*"none remain under $root"* ]] \
    && [[ "$out" == *"reaping $root/star*dir (tmpfs tmpfs "* ]] \
    && pass "reap --under unmounts all five, deepest first, the glob-named one with its fields intact, and verifies" \
    || fail "reap: rc=$rc out=$out"
  try "$SELF" check --under "$root"
  [ "$rc" -eq 0 ] && pass "check --under is clean after the reap" || fail "post-reap check: rc=$rc out=$out"
  if findmnt -rn "$outside" >/dev/null 2>&1; then
    pass "the outsider above the prefix SURVIVED the --under reap"
  else
    fail "the outsider was reaped"
  fi
  umount -l -- "$outside"
  try "$SELF" reap --under "$root"
  [ "$rc" -eq 0 ] && [[ "$out" == *"reaped 0 mount(s)"* ]] \
    && pass "reap on a clean prefix is a witnessed no-op" || fail "clean reap: rc=$rc out=$out"

  echo "ci-mounts self-test: PASS ($CHECKS checks)"
}

case "${1:-}" in
  list) shift; cmd_list "$@" ;;
  check) shift; cmd_check "$@" ;;
  reap) shift; cmd_reap "$@" ;;
  --self-test) shift; cmd_self_test "$@" ;;
  -h|--help) usage; exit 0 ;;
  *) usage; exit 2 ;;
esac
