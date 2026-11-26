#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# The propagation harness. Three parts: the two
# INSTRUMENTS, the RUN that uses them, the two CLOCKS, and the ARTIFACT.
#
#   * THE SUBTREE WALKER — ONE function, used TWICE: for the EXPECTED digest
#     on the publisher's source tree and for the OBSERVED digest read back
#     through each client's mount. One function because absolute and relative
#     forms never produce the same digest, so two implementations would agree
#     only by luck.
#   * THE MEASURED SERVER'S LIFECYCLE — start (the stack's store environment,
#     the stack's TLS cert/key, `GRANARY_LISTEN=127.0.0.1:0`, the three
#     `GRANARY_WIRE_*` values), readiness, the SIGTERM of the STACK's server
#     under an identity check, and a stop that uses THIS harness's own waiter.
#
#   * THE RUN — the corpus presets, the delta (every TENTH regular file of the
#     changed subtree, from a second seed), and the ELEVEN-PROCESS run: per
#     client a warm-up mount at `--seq n`, a warm-up-verify on the now-warm
#     cache, then the byte workload at `--seq n+1` on that same cache-dir, with
#     the three clients CONCURRENT against one shared measured server.
#
#   * THE CLOCKS AND THE ARTIFACT (clock A, a CACHELESS `gran cat` polled at
#     1 s; clock B, a FRESH `gran mount` on a NEW cache directory per attempt),
#     both stopping on ONE predicate — the sentinel's CONTENT HASH, never "the
#     read succeeded" — the `--node-samples` contract, the remaining negative
#     rows, and THE ARTIFACT ASSEMBLER: one JSON object in the required
#     shape, carrying no verdict, no ratio and no total the verb can compute.
# The header must describe the corpus, delta and orchestration alongside
# the instruments: it said "ONLY THE INSTRUMENTS" and listed those parts
# as absent while the run section already implemented them. A stale
# scope description misstates what this harness actually runs.
#
# WHAT IT IS BUILT ON, AND WHAT IT MUST NOT TOUCH. `scripts/stack.sh`
# stands up MinIO, the pinned TLS, a `granary-server` and the initial
# publication; this harness consumes that and MODIFIES NONE OF IT. It cannot
# even SOURCE it — `stack.sh` dispatches on `$1` at load — so the two
# predicates this file needs from it (`pid_is_alive`'s zombie handling and
# `classify_owned_pid`'s identity check) are reimplemented here, with the
# original's line numbers cited at each site.
#
# THE VENUE IS LINUX, and the tool checks say which half needs what: the
# WALKER needs `sha256sum`, GNU `find`, `xargs`, `sort`, `tr` and `wc`
# (`require_tools`), and the SELF-TEST additionally needs `ps`, `fusermount3`,
# `mountpoint`, `mkfifo` and the rest (`require_self_test_tools`). There is no
# macOS fallback on purpose: a walker whose digest depends on which hashing
# tool happened to be installed is not one digest, and one digest computed the
# same way on both sides is the whole point of the instrument.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
STACK_SCRIPT="$REPO_ROOT/scripts/stack.sh"
GEN_TREE="$REPO_ROOT/scripts/gen-tree.py"

# `stack.sh` hardcodes `target/debug/` (`:12-13`) and is not ours to
# change; the measurement runs RELEASE binaries. Both profiles are built on
# both venues, so the two coexist rather than one overwriting the other. This
# selects the profile for the processes THIS script starts.
PROFILE="${GRANARY_BUILD_PROFILE:-release}"

# `terminate_pid`'s waiter is `wait_for_death "$pid" 100` — 100 x 0.1 s = 10 s
# (`stack.sh:172`) — and `SHUTDOWN_DEADLINE` is also 10 s
# (`granary-net/src/accept.rs:87`). A drain that finishes near the deadline
# would have its snapshot write racing that SIGKILL, and the SIGKILL wins by
# leaving no file, so the run is refused and cluster time is burnt for nothing.
# THE MEASURED SERVER IS THEREFORE NEVER STOPPED WITH `terminate_pid`: it is
# stopped here, with this bound — the deadline, plus the write, plus margin.
# The minimum wait is 30 s; this is 45.
MEASURED_STOP_WAIT_SECONDS=45

# The snapshot refusal fragment is emitted by
# `write_wire_snapshot_if_requested` and
# `cmd_publish_with_credentials` in granary-cli, and by
# the server snapshot writer in `crates/granary-server/src/serve.rs`.
# A snapshot write refusal does not necessarily change
# the verb's exit status: the client helper reports
# the auxiliary write failure after the operation has
# run. An exit status of zero therefore cannot establish
# that the requested snapshot exists. The harness
# checks this diagnostic as well as the snapshot file
# when deciding whether the measurement is usable.
WIRE_REFUSAL_FRAGMENT='wire-snapshot not written'

# `stack.sh`'s own 10 s terminator, named
# so N6 can scan THIS FILE for it. ASSEMBLED
# FROM TWO PIECES to avoid matching the
# scanner's own diagnostic; scripts/check-fail-open.py
# assembles patterns for the same reason.
# Other mentions of the helper live
# in whole-line comments, allowing
# N6 to check any code-line mention.
UNSAFE_WAITER_TOKEN="terminate""_pid"

usage() {
  echo "usage: $0 walk DIR            # prints '<64-hex digest> <regular-file count>'" >&2
  echo "       $0 instrument-self-test [--workdir DIR] [--profile debug|release] [--keep]" >&2
  echo "       $0 propagation-run [--workdir DIR] [--preset selftest|m10] [--volume NAME]" >&2
  echo "                          [--profile debug|release] [--negatives|--no-negatives] [--keep]" >&2
  echo "                          [--artifact FILE --node-samples FILE --venue-node NAME" >&2
  echo "                           --venue-guest NAME [--git-sha 40HEX]]" >&2
  echo "         The eleven measured processes, their snapshots, the timeline and the" >&2
  echo "         two clocks. --workdir names a PARENT; the run creates its own directory" >&2
  echo "         inside it and keeps it, because the snapshots are the output." >&2
  echo "         --git-sha is recorded by EVERY run (with the venue's arch, kernel and" >&2
  echo "         OS) because assemble-artifact reads the run's record rather than" >&2
  echo "         re-deriving it later; a run without one cannot be assembled." >&2
  echo "         --artifact assembles the JSON run artifact and REQUIRES --node-samples," >&2
  echo "         --venue-node and --venue-guest; it also forces the negative rows on," >&2
  echo "         because every one of them is a REQUIRED observation of the artifact." >&2
  echo "       $0 assemble-artifact --run-dir DIR --artifact FILE --node-samples FILE" >&2
  echo "                            --venue-node NAME --venue-guest NAME [--git-sha 40HEX]" >&2
  echo "         The same assembly, run later against a KEPT run directory — which is" >&2
  echo "         what the measurement venue needs, because m10-node-sample.sh writes its" >&2
  echo "         file on the DRIVER and it cannot reach the guest until the run is over." >&2
  echo "         The architecture, kernel, OS and harness sha come from the RUN's own" >&2
  echo "         venue.tsv, never from this machine; --git-sha here is an ASSERTION and" >&2
  echo "         a disagreement with the recorded value is refused." >&2
}

die() {
  echo "m10-propagate: $*" >&2
  exit 1
}

note() {
  echo "m10-propagate: $*" >&2
}

require_tools() {
  local tool
  for tool in cat find grep mktemp rm sha256sum sort tr wc xargs; do
    command -v "$tool" > /dev/null 2>&1 \
      || die "required tool is missing (the walker needs it): $tool"
  done
}

require_self_test_tools() {
  local tool
  for tool in awk chmod cmp cp date fusermount3 id kill ln mkdir mkfifo mountpoint od ps python3 sed seq sleep; do
    command -v "$tool" > /dev/null 2>&1 \
      || die "required tool is missing (the self-test needs it): $tool"
  done
}

# ROOT IS REFUSED, and the reason is that two rows would otherwise report a
# PASS having demonstrated nothing. W6 (a listed file the walker cannot read)
# and N2 (a stderr capture the refusal scan cannot read) both build their
# controls with `chmod 000`, and root bypasses a permission bit — so as uid 0
# both controls succeed at reading, both refusals fail to fire, and the rows
# go red for a reason that looks like a harness bug. Both venues run as an
# unprivileged user today; this makes that assumption enforced rather than
# ambient.
require_unprivileged() {
  local uid
  uid="$(id -u)"
  case "$uid" in
    ''|*[!0-9]*) die "could not read the effective uid (got [$uid])" ;;
  esac
  [ "$uid" -ne 0 ] \
    || die "REFUSED: this harness must not run as root. Rows W6 and N2 prove their refusals with chmod 000 controls and root bypasses a permission bit, so as uid 0 they would report a result they had not established."
}

# ---------------------------------------------------------------- liveness
#
# A LOCAL COPY of `stack.sh:25-74`.
#
# The liveness check probes the pid with
# `kill -0` and then reads its process state.
# A failed probe or an empty state means the
# pid is not alive for this waiter. A state
# beginning with `Z` also returns false: a
# zombie can still have a pid while no longer
# running. The state check is separate from
# `wait`, which is responsible for obtaining
# a child's exit status. It does not require
# this shell to be the process's parent.
#
# The zombie arm supports polling a pid whose
# parent has not reaped it. It is not evidence
# that an ordinary background child remains a
# zombie until an explicit `wait`: the predicate
# reads the state available when it polls.
pid_is_alive() {
  local pid="$1" stat
  kill -0 "$pid" 2>/dev/null || return 1
  if stat="$(ps -o stat= -p "$pid" 2>/dev/null)"; then
    # `set -f` first: this expansion is deliberately unquoted so the shell
    # splits the field, and without it a glob character in the state string
    # would be expanded against the current directory instead of parsed.
    set -f
    # shellcheck disable=SC2086
    set -- $stat
    set +f
    stat="${1:-}"
    [ -n "$stat" ] || return 1
    case "$stat" in
      Z*) return 1 ;;
      *) return 0 ;;
    esac
  fi
  # `ps` FAILED, which does not by itself mean the observer is restricted:
  # `kill -0` above can succeed while the process is mid-exit and `ps` can
  # then fail a moment later simply because it has finished. Re-ask `kill -0`
  # NOW to tell the two apart — the same race, and the same remedy, as
  # `stack.sh:43-53`.
  kill -0 "$pid" 2>/dev/null || return 1
  return 0
}

# `stack.sh:124-144`, the `ps` arm only. The lsof fallback there exists for
# restricted environments; both measurement venues run ordinary procps, and a weaker
# identity (the executable path, with no start-time discriminator) is worse
# than a named refusal for a check whose whole job is to refuse.
process_identity() {
  local pid="$1" identity
  if identity="$(ps -o lstart= -o command= -p "$pid" 2>/dev/null)" \
      && [ -n "$identity" ]; then
    printf 'ps:%s\n' "$identity"
    return 0
  fi
  return 1
}

# Poll for death, in 0.1 s ticks. Returns 0 iff the pid is gone.
wait_for_death() {
  local pid="$1" ticks="$2" waited=0
  while pid_is_alive "$pid" && [ "$waited" -lt "$ticks" ]; do
    sleep 0.1
    waited=$((waited + 1))
  done
  ! pid_is_alive "$pid"
}

# ------------------------------------------------------------- THE WALKER
#
# ONE function, used twice: the EXPECTED digest over the publisher's
# SOURCE tree before publication, and the OBSERVED digest read back
# through a client's mount. Use this same relative-path command form —
#
#   cd <subtree> && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
#
# over the RELATIVE form, with the sorted listing hashed alongside the
# contents. Absolute and relative forms never produce the same digest, which
# is why one function does both sides rather than two functions agreeing by
# construction.
#
# THE PIPELINE IS SPLIT AT THE sort/xargs BOUNDARY, and that is a
# strengthening rather than a deviation: the sorted listing is materialised
# once and then used BOTH as the thing hashed and as `xargs`'s input, so the
# listing this digest commits to is provably the same listing the content pass
# read. Run as one pipeline, the listing would have to be recomputed by a
# second `find`, and a tree that changed between the two would produce a
# digest over a listing nothing hashed.
#
# IT REFUSES ANY ENTRY THAT IS NEITHER A REGULAR FILE NOR A DIRECTORY. `-type
# f` SILENTLY SKIPS symlinks, sockets, fifos and devices, so a corpus that
# grew a symlink would produce a digest that agreed on both sides while
# ignoring it — an agreement about nothing. The `m10` preset generates no
# symlinks (`gen-tree.py --symlinks 0`); the narrowing is enforced here
# instead of being left as a silent property of the fixture.
#
# IT ALSO REFUSES AN EMPTY SUBTREE, and the reason is MEASURED rather than
# reasoned. GNU xargs 4.8.0 runs its command ONCE WITH NO ARGUMENTS on empty
# input, and `sha256sum` with no operand reads STDIN. Both outcomes were
# executed on the aarch64 guest, 2026-09-09:
#
#   find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum < /dev/zero
#       -> rc 124 under `timeout 5`: it HANGS, reading whatever stdin it
#          inherited, which in a harness is the harness's own stdin.
#   printf '' | xargs -0 sha256sum
#       -> rc 0, printing
#          e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  -
#          — the digest of the EMPTY STRING, a confident wrong answer.
#
# So `xargs -0 sha256sum` on an empty subtree either hangs or silently
# digests something that is not the subtree, and which of the two you get
# depends on the caller's stdin. And on the merits: an observed empty digest
# equalling an expected empty digest is a vacuous agreement, which is the shape
# this harness exists to refuse. The refusal comes BEFORE the xargs line, so
# neither outcome is reachable.
#
# PRINTS ONE LINE: `<64-hex digest> <regular-file count>`. Two fields rather
# than a side-effect variable because every caller reaches this through a
# COMMAND SUBSTITUTION, which is a subshell — a variable set in here would be
# discarded on the way out, and the caller would read a stale 0 while believing
# it had the count for the walk it just made. That is a silent wrong number, so
# the value travels on stdout with the digest it belongs to.
subtree_digest() {
  local dir="$1" label="$2"
  local tmp offenders listing contents stream rc digest_line digest count

  [ -n "$dir" ] || die "$label: the walker was given an empty path"
  [ -d "$dir" ] || die "$label: the walker's subtree root is not a directory: $dir"
  # The ROOT itself: `cd` through a symlink would make every relative path
  # below it name a tree the caller did not ask for, and the digest would be
  # of that other tree with nothing to say so.
  [ ! -L "$dir" ] || die "$label: the walker's subtree root is a symbolic link: $dir"

  tmp="$(mktemp -d "${TMPDIR:-/tmp}/m10-walk.XXXXXX")" \
    || die "$label: could not create a scratch directory for the walk"
  offenders="$tmp/offenders"
  listing="$tmp/listing"
  contents="$tmp/contents"
  stream="$tmp/stream"

  # (1) THE ENTRY-KIND REFUSAL, before anything is hashed.
  set +e
  ( cd "$dir" && find . ! -type f ! -type d -print ) > "$offenders" 2> "$tmp/kind.err"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    cat "$tmp/kind.err" >&2
    rm -rf "$tmp"
    die "$label: the walker's entry-kind pass failed under $dir (find exited $rc)"
  fi
  if [ -s "$offenders" ]; then
    note "$label: entries under $dir that are neither a regular file nor a directory:"
    cat "$offenders" >&2
    rm -rf "$tmp"
    die "$label: the walker REFUSES this subtree — \`-type f\` would silently skip those entries, so the digest would agree while ignoring them"
  fi

  # (2) THE SORTED RELATIVE LISTING. `LC_ALL=C` because a locale-dependent
  # collation would make the digest depend on the environment the walk ran in,
  # and the two sides of the comparison run in different processes.
  set +e
  ( cd "$dir" && find . -type f -print0 | LC_ALL=C sort -z ) > "$listing" 2> "$tmp/list.err"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    cat "$tmp/list.err" >&2
    rm -rf "$tmp"
    die "$label: the walker's listing pass failed under $dir (pipeline exited $rc)"
  fi
  if [ ! -s "$listing" ]; then
    rm -rf "$tmp"
    die "$label: no regular file under $dir — the walker refuses an empty subtree rather than reporting a digest over nothing"
  fi

  set +e
  count="$(tr -cd '\0' < "$listing" | wc -c)"
  rc=$?
  set -e
  count="${count//[[:space:]]/}"
  case "$count" in
    ''|*[!0-9]*)
      rm -rf "$tmp"
      die "$label: could not count the walked files (rc=$rc, got [$count])"
      ;;
  esac
  [ "$count" -gt 0 ] \
    || { rm -rf "$tmp"; die "$label: the listing is non-empty but holds zero NUL-terminated names under $dir"; }

  # (3) THE CONTENTS, over exactly the listing hashed in (4).
  #
  # THE RELATIVE FORM ALSO CLOSES THE `-`-AS-STDIN CASE, which is worth
  # knowing before anyone "simplifies" this to absolute paths. GNU
  # `sha256sum` reads the operand `-` as STANDARD INPUT, so a regular file
  # named exactly `-` would be reported with the digest of whatever stdin the
  # harness inherited — and the hashed-equals-listed guard below would still
  # pass, because a line was printed. `find .` run from INSIDE the subtree
  # emits `./-`, never a bare `-`, so `sha256sum` treats it as a path.
  # MEASURED on the cluster guest 2026-09-09: `./-` hashed to the digest of
  # the FILE's contents, not of stdin. The relative form is mandated for an
  # unrelated reason — expected and observed digests must be computed
  # identically — and this is the second thing it buys.
  set +e
  ( cd "$dir" && xargs -0 sha256sum < "$listing" ) > "$contents" 2> "$tmp/sha.err"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    cat "$tmp/sha.err" >&2
    rm -rf "$tmp"
    die "$label: the walker's content pass failed under $dir (xargs/sha256sum exited $rc)"
  fi

  # (3a) AS MANY HASHES AS THERE WERE NAMES. `sha256sum` prints one line per
  # operand (a name containing a newline is ESCAPED onto one line, not split
  # across two), so this equality is exact. It is here because the digest
  # comparison alone cannot catch a SYSTEMATIC under-read: if both sides hash
  # the same 5 of 10 files, the two digests agree and the agreement is about
  # nothing — and the EXPECTED digest is computed before the publish, with
  # nothing to compare it against at all.
  local hashed
  set +e
  hashed="$(wc -l < "$contents")"
  rc=$?
  set -e
  hashed="${hashed//[[:space:]]/}"
  case "$hashed" in
    ''|*[!0-9]*)
      rm -rf "$tmp"
      die "$label: could not count the hashed files (rc=$rc, got [$hashed])"
      ;;
  esac
  if [ "$hashed" -ne "$count" ]; then
    rm -rf "$tmp"
    die "$label: the walker LISTED $count regular files under $dir but HASHED $hashed of them; a digest over a subset proves nothing about the tree"
  fi

  # (4) ONE digest over BOTH, with a version tag and labelled sections.
  #
  # THE LABELS DESCRIBE THE STREAM STRUCTURE. The
  # digest input contains a version tag, the
  # `listing` label and listing bytes, then the
  # `contents` label and content-hash bytes. Both
  # inputs are copied into one stream before
  # `sha256sum` runs. The final digest therefore
  # covers the listing and the content hashes
  # together; hashing either input alone would
  # leave the other part outside the tree identity.
  {
    printf 'm10-subtree-digest v1\n'
    printf 'listing\n'
    cat "$listing"
    printf '\ncontents\n'
    cat "$contents"
  } > "$stream"

  set +e
  digest_line="$(sha256sum "$stream")"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ] || [ -z "$digest_line" ]; then
    rm -rf "$tmp"
    die "$label: sha256sum failed over the walk stream (rc=$rc)"
  fi
  digest="${digest_line%% *}"
  rm -rf "$tmp"
  case "$digest" in
    ''|*[!0-9a-f]*) die "$label: sha256sum produced a non-hex digest: [$digest]" ;;
  esac
  [ "${#digest}" -eq 64 ] \
    || die "$label: sha256sum produced a ${#digest}-character digest, want 64: [$digest]"

  printf '%s %s\n' "$digest" "$count"
}

# The two fields of one `subtree_digest` line, so no caller re-splits it by
# hand and gets the order wrong.
walk_field_digest() { printf '%s' "${1%% *}"; }
walk_field_count()  { printf '%s' "${1##* }"; }

# ------------------------------------------------------------- THE FLOORS
#
# Each of these is a HARD failure of the run. They are functions rather than
# inline tests because the same three have to run after every measured process
# and a copy per call site is how one of them quietly stops running.

# PRESENCE, NEVER EXIT CODE. Exit 0 does not establish that
# a snapshot was written: a pre-existing destination and an unwritable parent
# directory both leave `rc=0` and no file.
assert_snapshot_present() {
  local path="$1" role="$2"
  [ -n "$path" ] || die "$role: the harness has no snapshot path for this role"
  [ -e "$path" ] \
    || die "$role: NO SNAPSHOT FILE at $path. Exit code 0 does not establish that a snapshot was written; the run is refused."
  [ -f "$path" ] \
    || die "$role: the snapshot path $path exists but is not a regular file"
  [ -s "$path" ] \
    || die "$role: the snapshot file $path is empty"
}

# The exact stderr fragment, treated as a hard failure of the run EVEN AT
# EXIT 0 — because that is precisely when it appears.
#
# `grep`'s three outcomes are kept apart on purpose. Exit 1 is "no match" and
# is the only clean one; exit 0 is the refusal; anything else means grep did
# not read the file, and a scanner that could not read its input has not
# cleared it. Collapsing 2 into 1 is the fail-open shape this repo has shipped
# before.
assert_no_snapshot_refusal() {
  local stderr_file="$1" role="$2" rc hits
  [ -n "$stderr_file" ] || die "$role: the harness has no stderr capture for this role"
  [ -f "$stderr_file" ] \
    || die "$role: the stderr capture $stderr_file is missing; the snapshot-refusal scan cannot be run, so the run is refused"
  hits="$(mktemp "${TMPDIR:-/tmp}/m10-refusal.XXXXXX")" \
    || die "$role: could not create a scratch file for the snapshot-refusal scan"
  set +e
  grep -a -F -n -- "$WIRE_REFUSAL_FRAGMENT" "$stderr_file" > "$hits" 2> "$hits.err"
  rc=$?
  set -e
  case "$rc" in
    0)
      note "$role: the measured process reported that it wrote NO snapshot:"
      cat "$hits" >&2
      rm -f "$hits" "$hits.err"
      die "$role: '$WIRE_REFUSAL_FRAGMENT' on a measured process's stderr is a hard failure of the run, whatever its exit code"
      ;;
    1)
      rm -f "$hits" "$hits.err"
      ;;
    *)
      cat "$hits.err" >&2
      rm -f "$hits" "$hits.err"
      die "$role: could not scan $stderr_file for '$WIRE_REFUSAL_FRAGMENT' (grep exited $rc); a scan that did not run has cleared nothing"
      ;;
  esac
}

assert_exit_code() {
  local got="$1" want="$2" label="$3"
  [ "$got" = "$want" ] \
    || die "$label: exited $got, want $want"
}

# The stale-`GRAN_ENDPOINT` trap. `stack.sh start` prints `GRAN_ENDPOINT=`
# for the server IT started (`:546`); a harness that `eval`s that output has
# the UNMEASURED endpoint in its environment. This harness captures it as
# STACK_ENDPOINT, never exports GRAN_ENDPOINT, passes `--endpoint` explicitly
# on every measured command line, and asserts here that the two differ.
assert_distinct_endpoints() {
  local stack="$1" measured="$2"
  [ -n "$stack" ] || die "the stack endpoint is empty"
  [ -n "$measured" ] || die "the measured endpoint is empty"
  [ "$stack" != "$measured" ] \
    || die "the stack endpoint and the measured endpoint are the same ($measured); every measured byte would be attributed to the wrong server lifetime"
}

# Run ONE measured process and apply all three floors to it, in the order that
# names the real cause first: a process that exits 0 having written nothing
# should be diagnosed as "it said so on stderr", not as "the file is missing".
MEASURED_RUN_RC=""
run_measured() {
  local role="$1" snapshot="$2" stdout_file="$3" stderr_file="$4" want_rc="$5"
  shift 5
  local rc
  set +e
  "$@" > "$stdout_file" 2> "$stderr_file"
  rc=$?
  set -e
  MEASURED_RUN_RC="$rc"
  # ALSO to a file. Every negative row runs this through a subshell (a `die`
  # in the current shell would end the self-test rather than fail one row), and
  # a variable set inside that subshell is gone by the time the row reads it —
  # the row would then judge a STALE rc and could pass without the process it
  # names ever having run.
  printf '%s\n' "$rc" > "$stderr_file.rc"
  assert_no_snapshot_refusal "$stderr_file" "$role"
  assert_exit_code "$rc" "$want_rc" "$role"
  assert_snapshot_present "$snapshot" "$role"
}

# --------------------------------------------- THE MEASURED SERVER
#
# A SECOND process, and this is FORCED rather than chosen. `stack.sh`
# starts its server with environment only and no argument beyond the binary
# (`:456-466`); that start path is not parameterised, so the stack's server
# can never carry a snapshot path, a run id or a role, and a server given none
# of the three writes nothing. And its lifetime is wrong anyway: `stack.sh
# start` publishes the whole initial tree through its own server before it
# returns (`:505-507`), so that server's request-body total already contains
# the initial upload, and there is no reset API by design.
MEASURED_PID=""
MEASURED_LOG=""
MEASURED_ADDR=""
MEASURED_ENDPOINT=""
MEASURED_SNAPSHOT=""
MEASURED_EXIT=""

start_measured_server() {
  local stack_state="$1" harness_state="$2" run_id="$3" snapshot="$4"
  local server_bin minio_port cert key log addr rc

  server_bin="$REPO_ROOT/target/$PROFILE/granary-server"
  [ -x "$server_bin" ] \
    || die "granary-server is not executable; build the $PROFILE profile first: $server_bin"
  [ -d "$stack_state" ] || die "the stack state directory does not exist: $stack_state"
  [ -d "$harness_state" ] || die "the harness state directory does not exist: $harness_state"
  [ -n "$run_id" ] || die "the measured server was given an empty run id"
  [ -n "$snapshot" ] || die "the measured server was given an empty snapshot path"
  [ ! -e "$snapshot" ] \
    || die "the measured server's snapshot destination already exists: $snapshot — the writer refuses a pre-existing destination at exit 0, so this would be a silent non-write"

  [ -f "$stack_state/minio.port" ] \
    || die "the stack did not write $stack_state/minio.port"
  minio_port="$(sed -n '1p' "$stack_state/minio.port")"
  case "$minio_port" in
    ''|*[!0-9]*) die "the stack's MinIO port is not numeric: [$minio_port]" ;;
  esac

  # The SAME certificate and key files the stack generated, so the `GRAN_PIN`
  # the stack printed stays valid against this second server. A fresh
  # certificate here would change the SPKI pin and every measured client would
  # be refused by its own pin check — which is a correct refusal, and a
  # confusing way to discover a harness bug.
  cert="$stack_state/tls/cert.pem"
  key="$stack_state/tls/key.pem"
  [ -f "$cert" ] || die "the stack's TLS certificate is missing: $cert"
  [ -f "$key" ] || die "the stack's TLS key is missing: $key"

  log="$harness_state/measured-server.log"
  : > "$log"

  # THE HARNESS NEVER WRITES ITS OWN SERVER'S PID INTO
  # `$stack_state/server.pid` OR `server.identity`. `stack.sh stop` refuses
  # to signal a live pid whose identity does not match the persisted one
  # (`classify_owned_pid`, `:566-576`) and `die`s inside `stop_stack` when it
  # does — and MinIO is then never stopped. The measured server's pid file
  # lives here, in the harness's own state directory.
  GRANARY_STORE="s3:" \
  GRANARY_STORE_BUCKET="granary-test" \
  GRANARY_STORE_ENDPOINT="http://127.0.0.1:${minio_port}" \
  GRANARY_STORE_REGION="us-east-1" \
  AWS_ACCESS_KEY_ID="granary-test" \
  AWS_SECRET_ACCESS_KEY="granary-test-secret" \
  GRANARY_LISTEN="127.0.0.1:0" \
  GRANARY_TLS_CERT="$cert" \
  GRANARY_TLS_KEY="$key" \
  GRANARY_WIRE_SNAPSHOT="$snapshot" \
  GRANARY_WIRE_RUN_ID="$run_id" \
  GRANARY_WIRE_ROLE="server" \
    "$server_bin" > "$log" 2>&1 &
  MEASURED_PID=$!
  MEASURED_LOG="$log"
  MEASURED_SNAPSHOT="$snapshot"
  MEASURED_EXIT=""
  printf '%s\n' "$MEASURED_PID" > "$harness_state/measured-server.pid"

  # The readiness line, read the way `stack.sh:479-497` reads it: a fresh
  # log and the spawned pid bind the line to THIS invocation, the server picks
  # its own ephemeral port, and the poll has a hard ceiling.
  addr=""
  for _ in $(seq 1 100); do
    if ! pid_is_alive "$MEASURED_PID"; then
      set +e
      wait "$MEASURED_PID"
      rc=$?
      set -e
      note "the measured granary-server exited ($rc) before becoming ready; log:"
      cat "$log" >&2
      MEASURED_PID=""
      die "the measured server never became ready"
    fi
    addr="$(sed -n 's/.*"addr":"\([^"]*\)".*/\1/p' "$log" 2>/dev/null)"
    [ -n "$addr" ] && break
    sleep 0.1
  done
  if [ -z "$addr" ]; then
    note "the measured granary-server never printed a readiness line within the bound; log:"
    cat "$log" >&2
    die "the measured server never printed a readiness address"
  fi
  case "$addr" in
    *$'\n'*) die "the measured granary-server printed more than one readiness address" ;;
  esac
  MEASURED_ADDR="$addr"
  MEASURED_ENDPOINT="https://$addr"
  printf '%s\n' "$addr" > "$harness_state/measured-server.addr"
}

# SIGTERM the STACK's server, with the identity check `classify_owned_pid`
# performs (`stack.sh:555-578`), so the UNMEASURED server cannot receive
# traffic by accident. A process pointed at the stale endpoint is then refused
# a connection and exits non-zero, which converts a silent misroute into a
# hard failure.
#
# It is SIGTERM plus this harness's own waiter, and NOT `terminate_pid`:
# nothing here may write to the stack's state, and `stack.sh stop` must
# later find a DEAD pid so it takes the `rm -f`-then-MinIO arm — the only arm
# that works for a server the harness already killed.
terminate_stack_server() {
  local stack_state="$1"
  local pid_file="$stack_state/server.pid"
  local identity_file="$stack_state/server.identity"
  local pid expected current rc

  [ -f "$pid_file" ] || die "the stack did not write $pid_file"
  pid="$(sed -n '1p' "$pid_file")"
  case "$pid" in
    ''|*[!0-9]*) die "the stack's server pid file is invalid: [$pid]" ;;
  esac
  if ! pid_is_alive "$pid"; then
    note "the stack's granary-server (pid $pid) was already dead"
    return 0
  fi
  [ -f "$identity_file" ] \
    || die "the stack's granary-server pid $pid is alive but its identity file is missing; refusing to signal it"
  expected="$(< "$identity_file")"
  [ -n "$expected" ] || die "the stack's granary-server identity file is empty: $identity_file"
  set +e
  current="$(process_identity "$pid")"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ] || [ "$current" != "$expected" ]; then
    die "the stack's granary-server pid $pid does not match its persisted identity; refusing to signal it"
  fi

  if ! kill -TERM "$pid" 2>/dev/null; then
    if pid_is_alive "$pid"; then
      die "could not SIGTERM the stack's granary-server pid $pid, and it is still alive"
    fi
  fi
  wait_for_death "$pid" 300 \
    || die "the stack's granary-server pid $pid was still alive 30 s after SIGTERM"
  note "the stack's granary-server (pid $pid) is down; its endpoint is now stale by construction"
}

# The measured server's own stop. The caller has ALREADY waited for every
# measured client and the publisher to exit, so the drain has nothing to drain
# and completes at once; this then SIGTERMs and waits
# MEASURED_STOP_WAIT_SECONDS before any SIGKILL.
#
# Exit 0 is `EXIT_DRAINED` (`granary-server/src/serve.rs:45`). Exit 3 is
# `EXIT_DEADLINE_EXPIRED` (`:61`) and means a connection was still resident —
# a resident connection is a measured process that did not exit, so the run is
# refused with the log saying which.
stop_measured_server() {
  local pid="$MEASURED_PID" ticks rc
  [ -n "$pid" ] || die "stop_measured_server was called with no measured server running"
  ticks=$((MEASURED_STOP_WAIT_SECONDS * 10))

  if ! kill -TERM "$pid" 2>/dev/null; then
    if pid_is_alive "$pid"; then
      die "could not SIGTERM the measured granary-server pid $pid, and it is still alive"
    fi
  fi
  if ! wait_for_death "$pid" "$ticks"; then
    note "the measured granary-server pid $pid did not exit within ${MEASURED_STOP_WAIT_SECONDS}s of SIGTERM; escalating to SIGKILL. Its snapshot is lost with it."
    kill -KILL "$pid" 2>/dev/null || note "SIGKILL to pid $pid failed"
    wait_for_death "$pid" 100 \
      || die "the measured granary-server pid $pid survived SIGTERM and SIGKILL"
    set +e
    wait "$pid"
    set -e
    MEASURED_PID=""
    die "the measured granary-server ignored SIGTERM for ${MEASURED_STOP_WAIT_SECONDS}s; the run is refused"
  fi
  set +e
  wait "$pid"
  rc=$?
  set -e
  MEASURED_PID=""
  MEASURED_EXIT="$rc"

  case "$rc" in
    0) ;;
    3)
      note "the measured granary-server exited 3 (EXIT_DEADLINE_EXPIRED): a connection was still resident at the drain deadline, which means a measured process had not exited. Log:"
      cat "$MEASURED_LOG" >&2
      die "the measured server did not drain; the run is refused"
      ;;
    *)
      note "the measured granary-server exited $rc; log:"
      cat "$MEASURED_LOG" >&2
      die "the measured server exited $rc, want 0 (EXIT_DRAINED); the run is refused"
      ;;
  esac

  assert_no_snapshot_refusal "$MEASURED_LOG" "server"
  assert_snapshot_present "$MEASURED_SNAPSHOT" "server"
}

# ------------------------------------------------------------- self-test
#
# Instrument self-test: every instrument-level control, each shown to FIRE. A
# harness control whose failure was never demonstrated does not exist, and a
# shell harness has no compiler to make that claim for it.
#
# KNOWN GAP, RECORDED HERE BECAUSE IT IS NOT THIS FILE'S TO CLOSE: this
# self-test is wired into NO LANE. The CI workflows
# and `scripts/linux-container.sh` all run without it, so the rows below fire only
# when a human runs them on a Linux venue. That matters most for the rows that
# pin a string the Rust side also emits — `WIRE_REFUSAL_FRAGMENT` above is
# asserted from both sides, so the SYSTEM does pin it, but a Rust-side
# rename lands green in `cargo nextest` and is caught only here. Wiring it
# into a lane is a decision above this file.

SELF_TEST_FAILURES=0
SELF_TEST_ROWS=0
# `INSTRUMENT` for the instrument section's rows, `RUN` for the propagation run's.
# One counter pair either way: a row is a row.
ROW_PREFIX="INSTRUMENT"
row_pass() {
  SELF_TEST_ROWS=$((SELF_TEST_ROWS + 1))
  echo "$ROW_PREFIX $1: PASS — $2"
}
row_fail() {
  SELF_TEST_ROWS=$((SELF_TEST_ROWS + 1))
  SELF_TEST_FAILURES=$((SELF_TEST_FAILURES + 1))
  echo "$ROW_PREFIX $1: FAIL — $2"
}

# ------------------------- THE ROW'S VERDICT *IS* THE OBSERVATION'S VERDICT
#
# ONE VERDICT, COMPUTED ONCE AND PERSISTED. The
# no-cache observation requires the byte separation
# and the content digest checked by NEG1. The
# no-publish observation requires the exit
# statuses, cap verdicts and actual poll or mount
# attempts checked by NEG3. Recomputing either
# outcome from fewer conditions could persist
# a pass after the row failed. A later verifier
# sees the persisted observation, so that record
# must preserve the row's decision rather
# than an independently simplified predicate.
#
# Each row registers its verdict under the observation
# name. The file writer reads this table, and
# OBS1 reads the written file back to compare
# names and outcomes. It requires each registered
# name exactly once and rejects unregistered
# names, so the stored observations can be checked
# against the decisions made during the run.
OBS_REGISTERED=""
OBS_VALUE=""
obs_set() {
  local name="$1" verdict="$2" var
  case "$name" in
    ''|*[!a-z0-9_]*)
      die "obs_set: [$name] is not an observation name (lowercase letters, digits and underscore)" ;;
  esac
  case "$verdict" in
    pass|fail) ;;
    *) die "obs_set($name): the verdict is [$verdict] and an observation is pass or fail" ;;
  esac
  var="OBS_VERDICT_$name"
  [ -z "${!var:-}" ] \
    || die "obs_set($name): already registered as [${!var}]. A row registers its verdict once; a second registration means two predicates are competing for one observation, which is the drift this table exists to stop"
  printf -v "$var" '%s' "$verdict"
  OBS_REGISTERED="$OBS_REGISTERED$name"$'\n'
}

obs_has() {
  local var="OBS_VERDICT_$1"
  [ -n "${!var:-}" ]
}

# SETS `OBS_VALUE` RATHER THAN PRINTING, and that is load-bearing rather than
# a style choice: `die` inside a command substitution exits the SUBSHELL, so a
# `$(obs_get x)` that refused would hand the caller an empty string and carry
# on. Every reader of this table therefore calls it as a statement.
obs_get() {
  local var="OBS_VERDICT_$1"
  OBS_VALUE="${!var:-}"
  [ -n "$OBS_VALUE" ] \
    || die "the observation '$1' is being written with no registered row verdict; every observation's outcome comes from the row that validated it, so inventing a separate value here could weaken that claim"
}

# ROW AND OBSERVATION IN ONE CALL. `verdict` is computed ONCE by the caller
# and becomes both the row's outcome and the persisted observation's, so the
# two cannot disagree. `-` as the observation name is a row with no persisted
# twin.
row_outcome() {
  local row="$1" obs="$2" verdict="$3" pass_message="$4" fail_message="$5"
  [ "$obs" = "-" ] || obs_set "$obs" "$verdict"
  case "$verdict" in
    pass) row_pass "$row" "$pass_message" ;;
    fail) row_fail "$row" "$fail_message" ;;
    *) die "row_outcome($row): the verdict is [$verdict] and a row passes or fails" ;;
  esac
}

# ------------------------------------- A REJECTED RUN LEAVES NO RECORD
#
# A run with failed rows must not leave a complete-looking
# artifact. A verifier reading only the artifact
# cannot recover every harness check from the JSON.
# The row ledger preserves the harness's own acceptance
# decision, and the artifact gate checks it before
# publication. A nonzero process exit after writing
# the artifact would be insufficient: the file
# would still be available to a later consumer.
#
# The ledger travels in the run directory as well as in this process, because
# `assemble-artifact` runs LATER and in a FRESH process: its own counters
# start at zero and know nothing about the run whose records it is reading.
RUN_STATUS_ROWS=""
RUN_STATUS_FAILURES=""

write_run_status() {
  local file="$1" rows="$2" failures="$3"
  {
    printf 'rows\t%s\n' "$rows"
    printf 'failures\t%s\n' "$failures"
  } > "$file" || die "could not write the run's row ledger to $file"
}

read_run_status() {
  local file="$1"
  [ -f "$file" ] \
    || die "$file is missing: this run directory carries no record of its OWN row ledger, so an assembly cannot tell a run the harness ACCEPTED from one it REJECTED. A run directory written by a harness that predates this record is refused rather than assumed clean"
  RUN_STATUS_ROWS="$(awk -F '\t' '$1 == "rows" { print $2; exit }' "$file")"
  RUN_STATUS_FAILURES="$(awk -F '\t' '$1 == "failures" { print $2; exit }' "$file")"
  case "$RUN_STATUS_ROWS" in
    ''|*[!0-9]*) die "$file has no numeric 'rows' field: [$RUN_STATUS_ROWS]" ;;
  esac
  case "$RUN_STATUS_FAILURES" in
    ''|*[!0-9]*) die "$file has no numeric 'failures' field: [$RUN_STATUS_FAILURES]" ;;
  esac
}

# THE GATE. It `die`s, and the message says NO ARTIFACT IS WRITTEN in those
# words, because the run's stdout is where an operator finds out that a rejected
# run produced nothing. Row ASM27 fires it on a synthetic ledger, in both
# directions, with a clean ledger as its positive control.
artifact_ledger_gate() {
  local run_failures="$1" run_rows="$2" live_failures="$3" live_rows="$4" where="$5"
  case "$run_failures$run_rows$live_failures$live_rows" in
    ''|*[!0-9]*)
      die "the artifact ledger gate was given a ledger that is not numeric: run [$run_failures]/[$run_rows], $where [$live_failures]/[$live_rows]" ;;
  esac
  if [ "$run_failures" -ne 0 ] || [ "$live_failures" -ne 0 ]; then
    die "REFUSED, AND NO ARTIFACT IS WRITTEN: $run_failures of $run_rows rows FAILED in the run itself and $live_failures of $live_rows in $where. A rejected run gets no record — an artifact is a complete-looking document to a verifier that reads only the FILE, and a check that is not represented in the JSON is one such a verifier cannot repeat"
  fi
}

# ------------------------------ THE VENUE BLOCK, CAPTURED AT *RUN* TIME
#
# `assemble-artifact` exists precisely to assemble LATER — the node-CPU
# samples are written on the DRIVER and cannot reach the guest until the run
# is over — so reading the architecture, the kernel, the OS and the repository
# HEAD at ASSEMBLY time attributes the measurement to a machine and a commit
# that may never have run it. A guest upgraded or a checkout advanced between
# the run and the assembly, and the artifact said otherwise. So the run writes
# these four facts into its own directory when it takes them, and every
# assembly READS them; an assembly whose run directory carries no venue record
# is REFUSED rather than re-derived. Rows ASM13 and ASM14 are the pair: the
# record's absence refuses, and a SYNTHETIC record is carried through to the
# artifact verbatim, which is what proves the values are read rather than
# taken again from `uname`.
write_venue_record() {
  local file="$1" git_sha="$2" arch kernel os_name
  arch="$(uname -m)" || die "could not read the machine architecture"
  kernel="$(uname -r)" || die "could not read the kernel release"
  os_name=""
  if [ -r /etc/os-release ]; then
    os_name="$(sed -n 's/^PRETTY_NAME="\(.*\)"$/\1/p' /etc/os-release | sed -n '1p')"
  fi
  [ -n "$os_name" ] || os_name="$(uname -s)"
  [ -n "$arch" ] && [ -n "$kernel" ] && [ -n "$os_name" ] \
    || die "the venue record would carry an empty field: arch=[$arch] kernel=[$kernel] os=[$os_name]"
  {
    printf 'arch\t%s\n' "$arch"
    printf 'kernel\t%s\n' "$kernel"
    printf 'os\t%s\n' "$os_name"
    printf 'git_sha\t%s\n' "$git_sha"
  } > "$file" || die "could not write the venue record to $file"
}

# Run a command that MUST FAIL, capturing its output. Sets EXPECT_RC and
# leaves the combined output in EXPECT_OUT.
EXPECT_RC=""
EXPECT_OUT=""
# A SUBSHELL, and it is load-bearing: every function under test refuses by
# calling `die`, which is `exit 1`. Run in the current shell, the first firing
# control would end the self-test at the row that proved it works — reported as
# a crash rather than as a pass.
expect_failure() {
  local out="$1"
  shift
  set +e
  ( "$@" ) > "$out" 2>&1
  EXPECT_RC=$?
  set -e
  EXPECT_OUT="$out"
}

# The rc a subshelled `run_measured` recorded for the process it ran.
measured_run_rc_from() {
  local stderr_file="$1"
  [ -f "$stderr_file.rc" ] || { printf 'no-rc-file'; return 0; }
  sed -n '1p' "$stderr_file.rc"
}

SELF_TEST_WORKDIR=""
SELF_TEST_WORKDIR_OWNED=0
SELF_TEST_KEEP=0
STACK_STATE=""
MOUNT_DAEMON_PID=""
MOUNT_POINT=""
# Every mountpoint the run has attached, newline-separated, so the exit trap
# can detach ALL of them. `MOUNT_POINT` above holds one, which was enough for
# the instrument section's single mount and is not enough for eleven processes.
RUN_MOUNTPOINTS=""

# THE EXIT TRAP REMOVES ONLY A DIRECTORY THIS PROCESS CREATED.
#
# A caller-supplied `--workdir` is a PARENT for a
# uniquely named subdirectory created by `mktemp -d`.
# Removing the supplied parent itself could erase
# files this run did not create. Cleanup receives
# both the owned subdirectory and its ownership
# flag; a directory without that flag is left
# intact. Repository paths and shared roots
# are also refused by `remove_owned_workdir`.
#
# The ownership flag is a PARAMETER rather than a global read, so the refusal
# has an oracle: row W7 calls this function directly on a directory it did not
# create and proves the contents survive.
remove_owned_workdir() {
  local dir="$1" owned="$2"
  [ -n "$dir" ] || return 0
  [ -d "$dir" ] || return 0
  if [ "$owned" != "1" ]; then
    echo "m10-propagate: NOT removing $dir: this process did not create it, and a recursive delete of a directory the caller supplied is not this harness's to make" >&2
    return 0
  fi
  case "$dir" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
      echo "m10-propagate: NOT removing $dir: it is inside the repository" >&2
      return 0
      ;;
    /|/tmp|/var/tmp|"${HOME:-/nonexistent}")
      echo "m10-propagate: NOT removing $dir: it is a shared root, not a run directory" >&2
      return 0
      ;;
  esac
  rm -rf "$dir"
}

# Stop the stack and RELEASE the exit trap's claim on it ONLY if the stop
# actually succeeded.
#
# Clearing `STACK_STATE` after a failed stop
# would tell the exit trap that nothing remains
# to stop. `stop_stack` clears the registration
# only on success; a nonzero status keeps
# it available for another cleanup attempt.
STACK_STOP_RC=""
stop_stack() {
  local out="$1" err="$2" rc
  [ -n "$STACK_STATE" ] || die "stop_stack was called with no stack registered"
  set +e
  "$STACK_SCRIPT" stop --state-dir "$STACK_STATE" > "$out" 2> "$err"
  rc=$?
  set -e
  STACK_STOP_RC="$rc"
  if [ "$rc" -eq 0 ]; then
    STACK_STATE=""
  else
    note "stack.sh stop exited $rc; KEEPING the stack registered so the exit trap tries again — clearing it here would leak a live MinIO into every later run"
  fi
}

self_test_cleanup() {
  local rc=$?
  set +e
  # THE DETACH TURNS ON THE MOUNTPOINT'S STATE, NOT
  # THE DAEMON'S LIVENESS. A daemon can exit while
  # its kernel mount remains attached. Cleanup checks
  # registered mountpoints independently of the
  # daemon pid, then handles surviving processes.
  local mnt
  while IFS= read -r mnt; do
    [ -n "$mnt" ] || continue
    if mountpoint -q "$mnt" 2>/dev/null; then
      echo "m10-propagate: cleanup: $mnt is still attached; detaching" >&2
      fusermount3 -u -z "$mnt" 2>/dev/null
    fi
  done <<< "$RUN_MOUNTPOINTS"
  if [ -n "$MOUNT_DAEMON_PID" ] && pid_is_alive "$MOUNT_DAEMON_PID"; then
    echo "m10-propagate: cleanup: a mount daemon (pid $MOUNT_DAEMON_PID) survived; SIGTERM" >&2
    kill -TERM "$MOUNT_DAEMON_PID" 2>/dev/null
    wait_for_death "$MOUNT_DAEMON_PID" 100
  fi
  if [ -n "$MEASURED_PID" ] && pid_is_alive "$MEASURED_PID"; then
    echo "m10-propagate: cleanup: the measured server (pid $MEASURED_PID) survived; SIGTERM" >&2
    kill -TERM "$MEASURED_PID" 2>/dev/null
    wait_for_death "$MEASURED_PID" 300
    kill -KILL "$MEASURED_PID" 2>/dev/null
  fi
  if [ -n "$STACK_STATE" ] && [ -d "$STACK_STATE" ]; then
    echo "m10-propagate: cleanup: stopping the stack at $STACK_STATE" >&2
    "$STACK_SCRIPT" stop --state-dir "$STACK_STATE" >&2
    local stop_rc=$?
    if [ "$stop_rc" -ne 0 ]; then
      # SAID, not swallowed. This runs on the EXIT trap, so it must not change
      # the script's status — but a teardown that failed and printed nothing is
      # how a leaked MinIO becomes the next run's mystery.
      echo "m10-propagate: cleanup: stack.sh stop exited $stop_rc; processes may have leaked from $STACK_STATE" >&2
    fi
  fi
  if [ "$SELF_TEST_KEEP" -eq 0 ]; then
    remove_owned_workdir "$SELF_TEST_WORKDIR" "$SELF_TEST_WORKDIR_OWNED"
  elif [ -n "$SELF_TEST_WORKDIR" ]; then
    echo "m10-propagate: cleanup: keeping $SELF_TEST_WORKDIR" >&2
  fi
  exit "$rc"
}

instrument_self_test() {
  local workdir="" profile_input=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --workdir)
        [ "$#" -ge 2 ] || { usage; exit 1; }
        workdir="$2"; shift 2 ;;
      --profile)
        [ "$#" -ge 2 ] || { usage; exit 1; }
        profile_input="$2"; shift 2 ;;
      --keep)
        SELF_TEST_KEEP=1; shift ;;
      *) usage; exit 1 ;;
    esac
  done
  case "$profile_input" in
    '') ;;
    debug|release) PROFILE="$profile_input" ;;
    *) die "--profile must be debug or release, got: $profile_input" ;;
  esac

  require_tools
  require_self_test_tools
  require_unprivileged
  [ -f "$GEN_TREE" ] || die "the promoted tree generator is missing: $GEN_TREE"
  [ -x "$STACK_SCRIPT" ] || die "stack.sh is not executable: $STACK_SCRIPT"

  local gran="$REPO_ROOT/target/$PROFILE/gran"
  [ -x "$gran" ] || die "gran is not executable; build the $PROFILE profile first: $gran"

  # A caller-supplied `--workdir` is a PARENT, never the run directory
  # itself: this run creates its own uniquely-named subdirectory inside it and
  # the exit trap removes only that. `mktemp -d` is what makes the claim
  # honest — it CREATES the name it returns and fails rather than adopting one
  # that exists, so "this process created it" is a fact and not an assumption.
  local created
  if [ -n "$workdir" ]; then
    mkdir -p "$workdir" \
      || die "could not create the workdir parent: $workdir"
    created="$(mktemp -d "$workdir/m10-propagate.XXXXXX")" \
      || die "could not create a fresh run directory under $workdir"
  else
    created="$(mktemp -d "${TMPDIR:-/tmp}/m10-propagate.XXXXXX")" \
      || die "could not create a run directory under ${TMPDIR:-/tmp}"
  fi
  SELF_TEST_WORKDIR="$(cd "$created" && pwd -P)"
  SELF_TEST_WORKDIR_OWNED=1
  case "$SELF_TEST_WORKDIR" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
      remove_owned_workdir "$SELF_TEST_WORKDIR" "$SELF_TEST_WORKDIR_OWNED"
      die "the self-test workdir must not be inside the repository: $SELF_TEST_WORKDIR"
      ;;
  esac
  trap self_test_cleanup EXIT

  local W="$SELF_TEST_WORKDIR"
  local SRC="$W/src" H="$W/harness" MNT="$W/mnt" OUT="$W/out"
  STACK_STATE="$W/stack"
  mkdir -p "$SRC" "$H" "$MNT" "$OUT"
  MOUNT_POINT="$MNT"
  # Registered BEFORE anything attaches to it, so the exit trap detaches it on
  # the mountpoint's own state rather than on a daemon's liveness.
  RUN_MOUNTPOINTS="$RUN_MOUNTPOINTS$MNT"$'\n'

  # `od -N4` reads exactly four bytes and exits, so `tr` never SIGPIPEs its
  # producer. The obvious spelling — `tr -cd 'a-f0-9' < /dev/urandom | dd
  # count=8` — makes `tr` take SIGPIPE, and under `set -o pipefail` the
  # substitution's status is then 141, so `set -e` aborts the run at the line
  # that mints the run id.
  local run_id stamp rand_hex
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  rand_hex="$(od -An -N4 -v -tx1 /dev/urandom | tr -d ' \n')"
  [ "${#rand_hex}" -eq 8 ] || die "could not mint 8 hex characters for the run id (got [$rand_hex])"
  run_id="m10-selftest-$stamp-$rand_hex"
  # The writers refuse an empty run id and the verb refuses it again; the
  # harness aborts here, before any process starts, so an unset variable can
  # never reach five files as five equal empties.
  [ -n "$run_id" ] || die "the run id is empty"
  echo "m10-propagate: instrument self-test"
  echo "  workdir : $W"
  echo "  profile : $PROFILE"
  echo "  run id  : $run_id"
  echo

  # ---------------------------------------------------------------- corpus
  python3 "$GEN_TREE" "$SRC" --seed 1 --dirs 12 --files 120 --symlinks 0 > "$OUT/gen-tree.log"
  cat "$OUT/gen-tree.log"
  local subtree="m10-subtree"
  mkdir -p "$SRC/$subtree/a" "$SRC/$subtree/b"
  local i
  for i in 0 1 2 3 4; do
    printf 'm10 subtree a file %s\n' "$i" > "$SRC/$subtree/a/f$i.txt"
    printf 'm10 subtree b file %s\n' "$i" > "$SRC/$subtree/b/f$i.txt"
  done
  printf 'm10 instrument self-test sentinel\n' > "$SRC/sentinel.txt"

  # ---------------------------------------------------- W1: walker stability
  local d1 d2
  d1="$(subtree_digest "$SRC/$subtree" "expected(v_n subtree), run 1")"
  d2="$(subtree_digest "$SRC/$subtree" "expected(v_n subtree), run 2")"
  if [ "$d1" = "$d2" ]; then
    row_pass W1 "the walker is stable across two runs over the same tree ($d1)"
  else
    row_fail W1 "the walker returned two digests for one unchanged tree: [$d1] vs [$d2]"
  fi

  # ------------------------------------------- W2: a one-byte change is seen
  local before after
  before="$(subtree_digest "$SRC/$subtree" "one-byte control, before")"
  # ONE BYTE, and the SAME LENGTH. A longer replacement would also change the
  # file's size, so a walker that hashed only sizes would still look like it
  # discriminated. This one differs from the original in exactly one byte.
  printf 'm10 subtree a file Z\n' > "$SRC/$subtree/a/f0.txt"
  after="$(subtree_digest "$SRC/$subtree" "one-byte control, after")"
  printf 'm10 subtree a file %s\n' 0 > "$SRC/$subtree/a/f0.txt"
  local restored
  restored="$(subtree_digest "$SRC/$subtree" "one-byte control, restored")"
  if [ "$before" != "$after" ] && [ "$before" = "$restored" ]; then
    row_pass W2 "a one-byte change moves the digest ($before -> $after) and the revert restores it"
  else
    row_fail W2 "before=$before after=$after restored=$restored — the walker did not discriminate, or the revert did not restore"
  fi

  # ------------------------------------ W3/W4: non-regular entries are refused
  ln -s a/f0.txt "$SRC/$subtree/a-link"
  expect_failure "$OUT/w3.log" subtree_digest "$SRC/$subtree" "symlink control"
  rm -f "$SRC/$subtree/a-link"
  if [ "$EXPECT_RC" -ne 0 ] && grep -a -F -q -- 'neither a regular file nor a directory' "$EXPECT_OUT"; then
    row_pass W3 "the walker REFUSES a symlink (rc=$EXPECT_RC)"
  else
    row_fail W3 "a symlink did not stop the walker (rc=$EXPECT_RC); output in $EXPECT_OUT"
  fi

  mkfifo "$SRC/$subtree/a-fifo"
  expect_failure "$OUT/w4.log" subtree_digest "$SRC/$subtree" "fifo control"
  rm -f "$SRC/$subtree/a-fifo"
  if [ "$EXPECT_RC" -ne 0 ] && grep -a -F -q -- 'neither a regular file nor a directory' "$EXPECT_OUT"; then
    row_pass W4 "the walker REFUSES a fifo (rc=$EXPECT_RC)"
  else
    row_fail W4 "a fifo did not stop the walker (rc=$EXPECT_RC); output in $EXPECT_OUT"
  fi

  # ----------------------------------------- W5: an empty subtree is refused
  mkdir -p "$W/empty-subtree"
  expect_failure "$OUT/w5.log" subtree_digest "$W/empty-subtree" "empty control"
  if [ "$EXPECT_RC" -ne 0 ] && grep -a -F -q -- 'refuses an empty subtree' "$EXPECT_OUT"; then
    row_pass W5 "the walker REFUSES an empty subtree instead of hanging in xargs (rc=$EXPECT_RC)"
  else
    row_fail W5 "an empty subtree did not stop the walker (rc=$EXPECT_RC); output in $EXPECT_OUT"
  fi

  # -------------------- W6: a listed file it cannot READ is a refusal
  # The dangerous shape is not "the walk failed" — it is a walk that hashes the
  # readable remainder and reports a confident digest of a tree it only partly
  # read.
  chmod 000 "$SRC/$subtree/b/f0.txt"
  expect_failure "$OUT/w6.log" subtree_digest "$SRC/$subtree" "unreadable-file control"
  chmod 644 "$SRC/$subtree/b/f0.txt"
  if [ "$EXPECT_RC" -ne 0 ] && grep -a -F -q -- 'content pass failed' "$EXPECT_OUT"; then
    row_pass W6 "the walker REFUSES a subtree holding a file it listed but cannot read, instead of digesting the readable remainder (rc=$EXPECT_RC)"
  else
    row_fail W6 "an unreadable file did not stop the walker (rc=$EXPECT_RC); output in $EXPECT_OUT"
  fi

  # ------------------------- N1: assert_distinct_endpoints refuses equality
  expect_failure "$OUT/n1.log" assert_distinct_endpoints "https://127.0.0.1:1" "https://127.0.0.1:1"
  if [ "$EXPECT_RC" -ne 0 ] && grep -a -F -q -- 'are the same' "$EXPECT_OUT"; then
    row_pass N1 "assert_distinct_endpoints REFUSES two equal endpoints (rc=$EXPECT_RC)"
  else
    row_fail N1 "two equal endpoints did not stop the harness (rc=$EXPECT_RC); output in $EXPECT_OUT"
  fi

  # ---------- N2: the snapshot-refusal scan refuses a file it CANNOT READ
  # grep exits 2 when it could not read its input, and a scanner that collapses
  # 2 into 1 ("no match") reports a clean stderr it never looked at.
  local unreadable="$OUT/unreadable.err"
  printf 'no refusal here\n' > "$unreadable"
  chmod 000 "$unreadable"
  expect_failure "$OUT/n2.log" assert_no_snapshot_refusal "$unreadable" "client-1"
  chmod 644 "$unreadable"
  if [ "$EXPECT_RC" -ne 0 ] && grep -a -F -q -- 'a scan that did not run has cleared nothing' "$EXPECT_OUT"; then
    row_pass N2 "the snapshot-refusal scan REFUSES a stderr file it cannot read, instead of reading grep's 2 as 'no match' (rc=$EXPECT_RC)"
  else
    row_fail N2 "an unreadable stderr file did not stop the scan (rc=$EXPECT_RC); output in $EXPECT_OUT"
  fi

  # ------------------- N3: the presence floor refuses an EMPTY snapshot file
  : > "$OUT/empty-snapshot.json"
  expect_failure "$OUT/n3.log" assert_snapshot_present "$OUT/empty-snapshot.json" "client-2"
  if [ "$EXPECT_RC" -ne 0 ] && grep -a -F -q -- 'is empty' "$EXPECT_OUT"; then
    row_pass N3 "the presence floor REFUSES a zero-byte snapshot file (rc=$EXPECT_RC)"
  else
    row_fail N3 "a zero-byte snapshot file passed the presence floor (rc=$EXPECT_RC); output in $EXPECT_OUT"
  fi

  # ---- N5/N6: the two facts the measured server's stop turns on, asserted
  # DIRECTLY, because a behavioural proof of them is not constructible in this
  # fixture and an implied proof is worse than a named one.
  #
  # No behavioural row here can see MEASURED_STOP_WAIT_SECONDS: a 0 would
  # pass every one of them. The reason is not that the bound
  # does not matter — it is that this fixture's drain has nothing resident, so
  # the server is already a zombie by the time the first `ps` returns and the
  # waiter never has to wait. In the real run three concurrent clients make the
  # drain take real time, and a 0-second waiter would SIGKILL a server that was
  # mid-write. So the bound is asserted as a NUMBER against the two numbers it
  # has to beat: `terminate_pid`'s 10 s (`stack.sh:172`), which is also
  # `SHUTDOWN_DEADLINE` (`granary-net/src/accept.rs:87`), and the required
  # 30 s floor.
  if [ "$MEASURED_STOP_WAIT_SECONDS" -ge 30 ] && [ "$MEASURED_STOP_WAIT_SECONDS" -gt 10 ]; then
    row_pass N5 "the measured server's own waiter is ${MEASURED_STOP_WAIT_SECONDS}s — at or above the 30 s survival floor and above the 10 s that is both ${UNSAFE_WAITER_TOKEN}'s bound and SHUTDOWN_DEADLINE"
  else
    row_fail N5 "the measured server's waiter is ${MEASURED_STOP_WAIT_SECONDS}s; the survival floor is 30 s, and anything at or below 10 s races the snapshot write against SIGKILL"
  fi

  # And that the 10 s helper is never CALLED or DEFINED here. It exists
  # because the obvious way for a successor to shorten this file is to copy
  # `stack.sh`'s helper in, and that helper races the snapshot
  # write against SIGKILL.
  #
  # ANY MENTION ON A CODE LINE, not merely a mention in FIRST-COMMAND
  # POSITION.
  #
  # Matching every line containing the token would
  # include a failure message quoting it.
  # Restricting the match to first-command position
  # would miss `function <token> { ...; }` and
  # `if <token> "$pid"; then`, which put keywords
  # before the definition or call. The oracle
  # must exclude its own diagnostic text without
  # narrowing away those code-line uses.
  #
  # The resolution is not a cleverer regex. It is to stop the scanner's own
  # source from carrying the token: `UNSAFE_WAITER_TOKEN` is assembled from two
  # pieces at the top of this file, every other mention lives in a whole-line
  # comment, and the question this row asks is therefore the BROAD one — does
  # the token appear anywhere on a line that is not a comment? A whole-line
  # comment is skipped; nothing else is. It still would not see a token
  # spelled through a variable, which is the same limit every source scanner
  # has; the threat model is a successor reaching for the familiar helper, not
  # one evading this check.
  awk -v token="$UNSAFE_WAITER_TOKEN" '
       { probe = $0
         sub(/^[[:space:]]+/, "", probe)
         if (substr(probe, 1, 1) == "#") next
         if (index($0, token) > 0) { print FILENAME ":" FNR ": " $0 }
       }' "$0" > "$OUT/n6.txt"
  if [ ! -s "$OUT/n6.txt" ]; then
    row_pass N6 "the stack 10 s terminator appears in this harness only in whole-line comments; the measured server is never stopped with the waiter that equals SHUTDOWN_DEADLINE"
  else
    row_fail N6 "the stack 10 s terminator is named on a code line: $(cat "$OUT/n6.txt")"
  fi

  # ------ N7: `wait_into_rc` REFUSES A SUBSHELL CALL
  #
  # A numeric status cannot establish that `wait` ran
  # in the shell that spawned the child. In a command
  # substitution, the assignment disappears with the
  # subshell and the parent retains its previous value.
  # This row checks execution context: `expect_failure`
  # invokes the function in a subshell and requires
  # a refusal naming SUBSHELL. Its positive control
  # invokes the same function in the main shell
  # and requires the child's exit status of 7, so
  # a function that always refuses cannot pass.
  local n7_pid n7_rc n7_sub_pid n7_sub_rc n7_named
  ( exit 7 ) &
  n7_pid=$!
  wait_into_rc "$n7_pid"
  n7_rc="$WAITED_RC"
  sleep 5 &
  n7_sub_pid=$!
  expect_failure "$OUT/n7.log" wait_into_rc "$n7_sub_pid"
  n7_sub_rc="$EXPECT_RC"
  set +e
  grep -a -F -q -- 'SUBSHELL' "$OUT/n7.log"
  n7_named=$?
  kill "$n7_sub_pid" 2> /dev/null
  wait "$n7_sub_pid"
  set -e
  if [ "$n7_rc" = "7" ] && [ "$n7_sub_rc" -ne 0 ] && [ "$n7_named" -eq 0 ]; then
    row_pass N7 "wait_into_rc returns a child's REAL status in the shell that spawned it (pid $n7_pid exited $n7_rc) and REFUSES to run in a subshell by name (rc=$n7_sub_rc) — the subshell call is refused before waiting"
  else
    row_fail N7 "main-shell status=[$n7_rc] want 7, subshell rc=$n7_sub_rc, the refusal names the subshell: $n7_named; see $OUT/n7.log"
  fi

  # ------------- W7: the exit trap's delete refuses a directory it does not own
  # The trap `rm -rf`'d
  # whatever `--workdir` named, whether or not this run had created it. The
  # guard is only worth having if it is shown to refuse, so this calls the
  # decision directly on a directory with a file already in it.
  local guard_dir="$W/not-ours"
  local guard_file="$guard_dir/precious.txt"
  mkdir -p "$guard_dir"
  printf 'a file the caller already had\n' > "$guard_file"
  remove_owned_workdir "$guard_dir" 0 > "$OUT/w7.log" 2>&1
  if [ -d "$guard_dir" ] && [ -f "$guard_file" ] \
      && grep -a -F -q -- 'did not create it' "$OUT/w7.log"; then
    row_pass W7 "the workdir removal REFUSES a directory this process did not create, and $guard_file survived it"
  else
    row_fail W7 "an unowned directory was removed, or the refusal did not print: dir=$([ -d "$guard_dir" ] && echo present || echo GONE) file=$([ -f "$guard_file" ] && echo present || echo GONE); see $OUT/w7.log"
  fi

  # ---------- W8: the digest must not depend on the CALLER'S LOCALE
  # `LC_ALL=C` was untested: both walks in a row run in one process under one
  # locale, so nothing ever saw collation. The fixture is chosen so C and
  # en_US.UTF-8 sort it DIFFERENTLY, and the row's own control asserts that
  # first — on a venue without the locale the two orders agree and the row
  # fails CLOSED rather than reporting a locale independence it never tested.
  mkdir -p "$W/locale-tree"
  printf 'one\n' > "$W/locale-tree/B.txt"
  printf 'two\n' > "$W/locale-tree/_c.txt"
  printf 'three\n' > "$W/locale-tree/a.txt"
  local order_c order_u digest_c digest_u
  order_c="$(printf 'B.txt\0_c.txt\0a.txt\0' | LC_ALL=C sort -z | tr '\0' ' ')"
  order_u="$(printf 'B.txt\0_c.txt\0a.txt\0' | LC_ALL=en_US.UTF-8 sort -z | tr '\0' ' ')"
  digest_c="$(LC_ALL=C subtree_digest "$W/locale-tree" "locale control (C)")"
  digest_u="$(LC_ALL=en_US.UTF-8 subtree_digest "$W/locale-tree" "locale control (en_US.UTF-8)")"
  if [ "$order_c" = "$order_u" ]; then
    row_fail W8 "the row's own control did not fire: en_US.UTF-8 collates [$order_u] exactly as C does, so this venue cannot demonstrate locale independence and the row refuses to claim it"
  elif [ "$digest_c" = "$digest_u" ]; then
    row_pass W8 "ONE digest under LC_ALL=C and under en_US.UTF-8, although sort collates the fixture differently ([$order_c] vs [$order_u]) — the two sides of the comparison run in different processes and must not depend on the environment either was launched in"
  else
    row_fail W8 "the digest depends on the caller's locale: C=$digest_c en_US.UTF-8=$digest_u"
  fi

  # ---------- W9: a name with whitespace is ONE entry, not two
  # Equivalent for the `m10` preset, whose names are `dNNNNNN/fNNNNN.dat`, and a
  # real gap in the INSTRUMENT's contract: the walker is a general function
  # and a successor will point it at a tree that was not generated.
  mkdir -p "$W/space-tree/d"
  printf 'x\n' > "$W/space-tree/d/f 1.txt"
  printf 'y\n' > "$W/space-tree/d/f2.txt"
  local space_line space_rc
  set +e
  space_line="$(subtree_digest "$W/space-tree" "whitespace control" 2> "$OUT/w9.err")"
  space_rc=$?
  set -e
  if [ "$space_rc" -eq 0 ] && [ "$(walk_field_count "$space_line")" = "2" ]; then
    row_pass W9 "a file named 'f 1.txt' is listed and hashed as ONE entry (count 2), so the NUL-delimited pipeline is doing the work its comments claim"
  else
    row_fail W9 "a whitespace name broke the walker (rc=$space_rc, line=[$space_line]); see $OUT/w9.err"
  fi

  # ---------- N5b: the stop's bound, BEHAVIOURALLY
  # N5 asserts the CONSTANT's value, but this mutation passed it:
  # hardcoding `ticks=100` inside the stop while leaving
  # MEASURED_STOP_WAIT_SECONDS=45 in place keeps N5 green while the measured
  # server is SIGKILLed after 10 s — the exact race the constant exists to
  # avoid. This row measures what the stop actually WAITS, against a stand-in
  # that ignores SIGTERM. It costs about 45 s, which is most of this suite's
  # runtime, and it subsumes N5's "at least 30 s" half.
  #
  # IT OBSERVES WHEN THE KILL LANDED, NOT HOW LONG THE FUNCTION TOOK. Measuring
  # only `stop_measured_server`'s total duration is fail-open. Here is the
  # regression that walks past it: a stop that SIGKILLs
  # IMMEDIATELY and then sleeps 30 s before printing the refusal satisfies every
  # condition a duration-only row checks — non-zero exit, the expected text, an
  # elapsed time above the floor — while having reintroduced the exact
  # snapshot-write race the bound exists to prevent. So a WATCHER polls the
  # stand-in and records the moment it actually died; the stand-in ignores
  # SIGTERM (`trap "" TERM` survives `exec`), so its death IS the SIGKILL and
  # the delay from t0 to that moment is what the 30 s survival floor is about.
  local standin n5b_t0 n5b_t1 n5b_elapsed n5b_t0_ms n5b_death_ms n5b_kill_delay_ms
  local n5b_death_file n5b_watcher
  bash -c 'trap "" TERM; exec sleep 300' &
  standin=$!
  sleep 0.2
  pid_is_alive "$standin" || die "the N5b stand-in did not start"
  MEASURED_PID="$standin"
  MEASURED_LOG="$OUT/n5b.standin.log"
  MEASURED_SNAPSHOT="$OUT/n5b.absent.json"
  : > "$MEASURED_LOG"
  n5b_death_file="$OUT/n5b.death.ms"
  : > "$n5b_death_file"
  n5b_t0="$(date +%s)"
  n5b_t0_ms="$(date -u +%s%3N)"
  (
    n5b_ticks=0
    while pid_is_alive "$standin" && [ "$n5b_ticks" -lt 1200 ]; do
      sleep 0.1
      n5b_ticks=$((n5b_ticks + 1))
    done
    if pid_is_alive "$standin"; then
      printf 'never\n' > "$n5b_death_file"
    else
      date -u +%s%3N > "$n5b_death_file"
    fi
  ) &
  n5b_watcher=$!
  expect_failure "$OUT/n5b.log" stop_measured_server
  n5b_t1="$(date +%s)"
  set +e
  wait "$n5b_watcher"
  set -e
  n5b_death_ms="$(sed -n '1p' "$n5b_death_file")"
  case "$n5b_death_ms" in
    ''|*[!0-9]*) n5b_kill_delay_ms=-1 ;;
    *) n5b_kill_delay_ms=$((n5b_death_ms - n5b_t0_ms)) ;;
  esac
  # `stop_measured_server` runs inside expect_failure's SUBSHELL, so the
  # globals it clears there are gone with it; the parent's copies are cleared
  # here or the exit trap would chase a pid this row already reaped.
  MEASURED_PID=""
  MEASURED_LOG=""
  MEASURED_SNAPSHOT=""
  n5b_elapsed=$((n5b_t1 - n5b_t0))
  if ! kill -KILL "$standin" 2>/dev/null; then
    if pid_is_alive "$standin"; then
      die "N5b could not SIGKILL its stand-in pid $standin, and it is still alive"
    fi
  fi
  set +e
  wait "$standin" 2>/dev/null
  set -e
  if [ "$EXPECT_RC" -ne 0 ] \
      && grep -a -F -q -- 'ignored SIGTERM for' "$EXPECT_OUT" \
      && [ "$n5b_kill_delay_ms" -ge 30000 ] \
      && [ "$n5b_elapsed" -ge 30 ]; then
    row_pass N5b "a process that ignores SIGTERM SURVIVED ${n5b_kill_delay_ms} ms — observed by a watcher polling the stand-in, so this is when the SIGKILL landed and not merely how long the stop took (${n5b_elapsed}s) — which is at or above the 30 s survival floor and well above the 10 s that is SHUTDOWN_DEADLINE; the run is then refused (rc=$EXPECT_RC)"
  else
    row_fail N5b "the stand-in DIED ${n5b_kill_delay_ms} ms after the stop began, with the stop itself taking ${n5b_elapsed}s (rc=$EXPECT_RC). The floor is 30 s of SURVIVAL: a stop that kills at once and then waits before refusing satisfies the elapsed time and the refusal text while racing the snapshot write against SIGKILL exactly as before. Output in $EXPECT_OUT"
  fi

  # ------------------------------------------- the EXPECTED digest, pinned
  local expected_line expected_subtree expected_files
  expected_line="$(subtree_digest "$SRC/$subtree" "expected(subtree) on the publisher's source tree")"
  expected_subtree="$(walk_field_digest "$expected_line")"
  expected_files="$(walk_field_count "$expected_line")"
  [ "$expected_files" -ge 1 ] || die "the expected walk covered $expected_files files"
  echo "  expected subtree digest: $expected_subtree ($expected_files files)"

  # -------------------------------------------------------------- the stack
  local stack_out="$OUT/stack-start.log" stack_rc
  set +e
  "$STACK_SCRIPT" start --source-dir "$SRC" --volume m10-selftest \
    --state-dir "$STACK_STATE" > "$stack_out" 2> "$OUT/stack-start.err"
  stack_rc=$?
  set -e
  if [ "$stack_rc" -ne 0 ]; then
    cat "$OUT/stack-start.err" >&2
    die "stack.sh start failed (rc=$stack_rc)"
  fi

  # The four contract lines, read as DATA. `GRAN_ENDPOINT` is captured as
  # STACK_ENDPOINT and never exported: exporting it would put the UNMEASURED
  # endpoint into every child's environment.
  local STACK_ENDPOINT GRAN_PIN GRAN_ROOT_KEY GRAN_VOLUME line key value
  STACK_ENDPOINT=""; GRAN_PIN=""; GRAN_ROOT_KEY=""; GRAN_VOLUME=""
  while IFS= read -r line; do
    key="${line%%=*}"
    value="${line#*=}"
    # `stack.sh` prints these with `printf %q`, so the value is a shell
    # word; `eval` on the VALUE alone, into a named variable, keeps the
    # quoting contract without ever letting the line choose the variable.
    case "$key" in
      GRAN_ENDPOINT) eval "STACK_ENDPOINT=$value" ;;
      GRAN_PIN) eval "GRAN_PIN=$value" ;;
      GRAN_ROOT_KEY) eval "GRAN_ROOT_KEY=$value" ;;
      GRAN_VOLUME) eval "GRAN_VOLUME=$value" ;;
      *) die "stack.sh printed an unexpected contract line: $line" ;;
    esac
  done < "$stack_out"
  [ -n "$STACK_ENDPOINT" ] || die "stack.sh printed no GRAN_ENDPOINT"
  [ -n "$GRAN_PIN" ] || die "stack.sh printed no GRAN_PIN"
  [ -n "$GRAN_ROOT_KEY" ] || die "stack.sh printed no GRAN_ROOT_KEY"
  [ "$GRAN_VOLUME" = "m10-selftest" ] \
    || die "stack.sh published volume [$GRAN_VOLUME], want m10-selftest"
  case "$STACK_ENDPOINT" in
    https://*) ;;
    *) die "the stack endpoint is not an https URL: [$STACK_ENDPOINT]" ;;
  esac
  case "$GRAN_PIN" in
    sha256/*) ;;
    *) die "the stack pin is not an SPKI pin: [$GRAN_PIN]" ;;
  esac
  case "$GRAN_ROOT_KEY" in
    ed25519:*) ;;
    *) die "the stack root key is not an ed25519 key: [$GRAN_ROOT_KEY]" ;;
  esac

  # ------------------------------------------- S1: the measured server starts
  start_measured_server "$STACK_STATE" "$H" "$run_id" "$H/server.json"
  assert_distinct_endpoints "$STACK_ENDPOINT" "$MEASURED_ENDPOINT"
  row_pass S1 "the measured server is ready at $MEASURED_ENDPOINT (stack was $STACK_ENDPOINT), pid $MEASURED_PID"

  # ------- N4: the identity check refuses to signal a pid it cannot vouch for
  # `classify_owned_pid` (`stack.sh:566-576`) exists so a stale or recycled
  # pid naming an unrelated same-user process is never signalled. The copy of
  # that check in this harness has to be shown to refuse, or it is decoration.
  local stack_pid
  stack_pid="$(sed -n '1p' "$STACK_STATE/server.pid")"
  cp "$STACK_STATE/server.identity" "$W/server.identity.bak"
  printf 'ps:not the process this harness started\n' > "$STACK_STATE/server.identity"
  expect_failure "$OUT/n4.log" terminate_stack_server "$STACK_STATE"
  cp "$W/server.identity.bak" "$STACK_STATE/server.identity"
  cmp "$W/server.identity.bak" "$STACK_STATE/server.identity" \
    || die "the self-test could not restore the stack's identity file"
  if [ "$EXPECT_RC" -ne 0 ] \
      && grep -a -F -q -- 'does not match its persisted identity' "$EXPECT_OUT" \
      && pid_is_alive "$stack_pid"; then
    row_pass N4 "a mismatched identity file REFUSES the signal and the stack's server (pid $stack_pid) is STILL ALIVE (rc=$EXPECT_RC)"
  else
    row_fail N4 "the identity check did not refuse (rc=$EXPECT_RC), or pid $stack_pid died anyway; output in $EXPECT_OUT"
  fi

  # ---------- N4b: SAME command, DIFFERENT start time — the recycled pid
  # N4's fixture is total garbage, so ANY comparison refuses it; the
  # discriminator `classify_owned_pid` actually exists for — `ps -o lstart`,
  # which separates a live pid from a DIFFERENT process that has since been
  # given the same number — was never exercised. This perturbs only the year
  # in a REAL identity, and asserts the perturbation landed before drawing any
  # conclusion from the refusal.
  cp "$STACK_STATE/server.identity" "$W/server.identity.bak2"
  sed -E 's/ [0-9]{4} \// 1999 \//' "$W/server.identity.bak2" > "$STACK_STATE/server.identity"
  if cmp -s "$W/server.identity.bak2" "$STACK_STATE/server.identity"; then
    die "N4b could not perturb the identity's start time; the row would otherwise 'prove' a refusal against an unmodified file"
  fi
  expect_failure "$OUT/n4b.log" terminate_stack_server "$STACK_STATE"
  cp "$W/server.identity.bak2" "$STACK_STATE/server.identity"
  cmp "$W/server.identity.bak2" "$STACK_STATE/server.identity" \
    || die "the self-test could not restore the stack's identity file (N4b)"
  if [ "$EXPECT_RC" -ne 0 ] \
      && grep -a -F -q -- 'does not match its persisted identity' "$EXPECT_OUT" \
      && pid_is_alive "$stack_pid"; then
    row_pass N4b "an identity with the SAME command and a DIFFERENT start time REFUSES the signal and pid $stack_pid is still alive (rc=$EXPECT_RC) — the recycled-pid case, which a garbage fixture cannot test"
  else
    row_fail N4b "a same-command identity with a different start time was signalled (rc=$EXPECT_RC), or pid $stack_pid died; output in $EXPECT_OUT"
  fi

  # --------------------------------- S2: the stack's server is SIGTERMed
  terminate_stack_server "$STACK_STATE"
  if pid_is_alive "$stack_pid"; then
    row_fail S2 "the stack's granary-server pid $stack_pid is still alive after terminate_stack_server"
  else
    row_pass S2 "the stack's granary-server (pid $stack_pid) is down, identity-checked before the signal"
  fi

  # ------------------------------------- S3: a stale endpoint is a hard failure
  # CACHELESS on purpose: with `--root-key` AND a cache holding a resolvable
  # head, `gran cat` is DESIGNED to degrade to the cache instead of failing
  # (CAT_HELP), which would turn this control green for the wrong reason.
  #
  # AND IT ASSERTS THE CONNECTION REFUSAL SPECIFICALLY, not merely a non-zero
  # exit. "The client failed" is satisfied by a mistyped flag, a pin
  # mismatch, a verification error — any of which would pass this row while
  # proving nothing about whether the terminated endpoint still serves. The
  # text is the transport's own (`Connection refused (os error 111)`), which
  # is the one outcome that can only come from nothing listening there.
  local stale_rc
  set +e
  "$gran" cat "$GRAN_VOLUME" sentinel.txt \
    --endpoint "$STACK_ENDPOINT" --pin "$GRAN_PIN" --root-key "$GRAN_ROOT_KEY" \
    > "$OUT/stale.out" 2> "$OUT/stale.err"
  stale_rc=$?
  set -e
  set +e
  grep -a -F -q -- 'Connection refused' "$OUT/stale.err"
  local stale_refused_rc=$?
  set -e
  if [ "$stale_rc" -ne 0 ] && [ "$stale_refused_rc" -eq 0 ]; then
    row_pass S3 "a client pointed at the terminated stack endpoint exits $stale_rc with a CONNECTION REFUSED on its stderr; the misroute is a hard failure, and not merely some other failure"
  else
    row_fail S3 "stale-endpoint client rc=$stale_rc, 'Connection refused' grep rc=$stale_refused_rc; a non-zero exit for an unrelated reason does not establish that the terminated endpoint stopped serving. stderr in $OUT/stale.err"
  fi

  # ------------------- S4: expected == observed through a mount (the positive control)
  local cache="$W/cache-client-1"
  mkdir -p "$cache"
  local mount_log="$OUT/mount.err" mount_snapshot="$H/client-1.json"
  "$gran" mount "$GRAN_VOLUME" "$MNT" \
    --endpoint "$MEASURED_ENDPOINT" --pin "$GRAN_PIN" --root-key "$GRAN_ROOT_KEY" \
    --cache-dir "$cache" --foreground \
    --wire-snapshot "$mount_snapshot" --wire-run-id "$run_id" --wire-role "client-1" \
    > "$OUT/mount.out" 2> "$mount_log" &
  MOUNT_DAEMON_PID=$!

  local ready=0 attempt=0
  while [ "$attempt" -lt 200 ]; do
    sleep 0.1
    attempt=$((attempt + 1))
    if ! pid_is_alive "$MOUNT_DAEMON_PID"; then
      cat "$mount_log" >&2
      die "the mount daemon exited before the mount became ready"
    fi
    if mountpoint -q "$MNT" 2>/dev/null; then
      ready=1
      break
    fi
  done
  [ "$ready" -eq 1 ] || { cat "$mount_log" >&2; die "the mount did not become ready within 20 s"; }

  local observed_line observed observed_files
  observed_line="$(subtree_digest "$MNT/$subtree" "observed(subtree) through the mount")"
  observed="$(walk_field_digest "$observed_line")"
  observed_files="$(walk_field_count "$observed_line")"

  local umount_rc
  set +e
  "$gran" umount "$MNT" > "$OUT/umount.out" 2> "$OUT/umount.err"
  umount_rc=$?
  set -e
  wait_for_death "$MOUNT_DAEMON_PID" 300 \
    || die "the mount daemon pid $MOUNT_DAEMON_PID survived 30 s after gran umount"
  local mount_rc
  set +e
  wait "$MOUNT_DAEMON_PID"
  mount_rc=$?
  set -e
  MOUNT_DAEMON_PID=""

  if [ "$expected_subtree" = "$observed" ] && [ "$expected_files" = "$observed_files" ]; then
    row_pass S4 "expected == observed through the mount: $observed ($observed_files files); gran umount rc=$umount_rc, mount rc=$mount_rc"
  else
    row_fail S4 "expected $expected_subtree ($expected_files files) != observed $observed ($observed_files files)"
  fi
  assert_no_snapshot_refusal "$mount_log" "client-1"
  assert_exit_code "$mount_rc" 0 "client-1 (gran mount)"
  # ASSERTED, not merely printed in the row above. `gran umount` detaches the
  # kernel mount and then VERIFIES it is gone; a non-zero exit means it did
  # not, and a row that reports that number without acting on it leaves the
  # next mount to discover it.
  assert_exit_code "$umount_rc" 0 "client-1 (gran umount)"
  assert_snapshot_present "$mount_snapshot" "client-1"

  # ---- S4b: and the comparison CAN disagree. An equality that has never been
  # shown to fail is not evidence; this is the STALE-CONTENT shape in
  # miniature — the source moves on, nothing is republished, and the digest
  # taken through the mount must stop matching.
  printf 'm10 subtree a file 0 (moved on, never published)\n' > "$SRC/$subtree/a/f0.txt"
  local moved_line moved_digest
  moved_line="$(subtree_digest "$SRC/$subtree" "expected(subtree) after an unpublished source change")"
  moved_digest="$(walk_field_digest "$moved_line")"
  printf 'm10 subtree a file %s\n' 0 > "$SRC/$subtree/a/f0.txt"
  local restored_line restored_digest
  restored_line="$(subtree_digest "$SRC/$subtree" "expected(subtree) after the restore")"
  restored_digest="$(walk_field_digest "$restored_line")"
  if [ "$moved_digest" != "$observed" ] && [ "$restored_digest" = "$expected_subtree" ]; then
    row_pass S4b "the expected-vs-observed comparison DISAGREES when the source moves on unpublished ($moved_digest != $observed), and the restore returns it to $restored_digest"
  else
    row_fail S4b "moved=$moved_digest observed=$observed restored=$restored_digest expected=$expected_subtree — the comparison did not discriminate, or the restore failed"
  fi

  # ----------- S5: `wire-snapshot not written` at exit 0 — a PRE-EXISTING dest
  local pre="$H/pre-existing.json"
  printf 'not a snapshot\n' > "$pre"
  expect_failure "$OUT/s5.log" run_measured "warmup-1" "$pre" "$OUT/s5.out" "$OUT/s5.err" 0 \
    "$gran" cat "$GRAN_VOLUME" sentinel.txt \
      --endpoint "$MEASURED_ENDPOINT" --pin "$GRAN_PIN" --root-key "$GRAN_ROOT_KEY" \
      --wire-snapshot "$pre" --wire-run-id "$run_id" --wire-role "warmup-1"
  local s5_process_rc
  s5_process_rc="$(measured_run_rc_from "$OUT/s5.err")"
  if [ "$s5_process_rc" = "0" ] && [ "$EXPECT_RC" -ne 0 ] \
      && grep -a -F -q -- 'hard failure of the run' "$EXPECT_OUT"; then
    row_pass S5 "a PRE-EXISTING destination leaves the process at rc=0 and no snapshot of its own, and the harness REFUSES it (harness rc=$EXPECT_RC)"
  else
    row_fail S5 "process rc=$s5_process_rc, harness rc=$EXPECT_RC — the refusal did not fire as expected; see $EXPECT_OUT and $OUT/s5.err"
  fi

  # ----------- S6: `wire-snapshot not written` at exit 0 — a MISSING PARENT
  local nodir="$H/no-such-directory/warmup-2.json"
  expect_failure "$OUT/s6.log" run_measured "warmup-2" "$nodir" "$OUT/s6.out" "$OUT/s6.err" 0 \
    "$gran" cat "$GRAN_VOLUME" sentinel.txt \
      --endpoint "$MEASURED_ENDPOINT" --pin "$GRAN_PIN" --root-key "$GRAN_ROOT_KEY" \
      --wire-snapshot "$nodir" --wire-run-id "$run_id" --wire-role "warmup-2"
  local s6_process_rc
  s6_process_rc="$(measured_run_rc_from "$OUT/s6.err")"
  if [ "$s6_process_rc" = "0" ] && [ "$EXPECT_RC" -ne 0 ] \
      && grep -a -F -q -- 'hard failure of the run' "$EXPECT_OUT"; then
    row_pass S6 "a destination whose PARENT DIRECTORY does not exist leaves the process at rc=0 and no snapshot, and the harness REFUSES it (harness rc=$EXPECT_RC)"
  else
    row_fail S6 "process rc=$s6_process_rc, harness rc=$EXPECT_RC — the refusal did not fire as expected; see $EXPECT_OUT and $OUT/s6.err"
  fi

  # ---------- S5c: exit NON-ZERO, snapshot PRESENT,
  # no fragment. The fixture writes a snapshot and
  # exits 7 without a diagnostic fragment. File
  # presence alone cannot reject it, and the stderr
  # scan has no fragment to match. The row requires
  # a refusal naming the unexpected exit status,
  # establishing that the exit-code check
  # applies independently of snapshot presence.
  local s5c="$H/s5c.json"
  expect_failure "$OUT/s5c.log" run_measured "warmup-3" "$s5c" "$OUT/s5c.out" "$OUT/s5c.err" 0 \
    sh -c 'printf "{}\n" > "$1"; exit 7' _ "$s5c"
  local s5c_rc
  s5c_rc="$(measured_run_rc_from "$OUT/s5c.err")"
  if [ "$s5c_rc" = "7" ] && [ -s "$s5c" ] && [ "$EXPECT_RC" -ne 0 ] \
      && grep -a -F -q -- 'exited 7, want 0' "$EXPECT_OUT"; then
    row_pass S5c "a measured process that exits 7 having WRITTEN its snapshot is refused by the exit-code floor (harness rc=$EXPECT_RC)"
  else
    row_fail S5c "process rc=$s5c_rc, snapshot present=$([ -s "$s5c" ] && echo yes || echo no), harness rc=$EXPECT_RC; see $EXPECT_OUT"
  fi

  # ---------- S6b: exit 0, NO fragment, NO file — the PRESENCE floor alone
  # S5 and S6 both carry `wire-snapshot not written` on stderr, and the
  # refusal scan fires before the presence floor is reached; every other row
  # that exercises presence calls it DIRECTLY. So nothing established that
  # `run_measured`'s own presence floor decides anything. This is a real
  # `gran cat` with the `--wire-snapshot` trio simply absent from the command
  # line — the shape a mis-edited harness produces — and only presence catches
  # it.
  local s6b="$H/s6b.json"
  expect_failure "$OUT/s6b.log" run_measured "warmup-verify-1" "$s6b" "$OUT/s6b.out" "$OUT/s6b.err" 0 \
    "$gran" cat "$GRAN_VOLUME" sentinel.txt \
      --endpoint "$MEASURED_ENDPOINT" --pin "$GRAN_PIN" --root-key "$GRAN_ROOT_KEY"
  local s6b_rc
  s6b_rc="$(measured_run_rc_from "$OUT/s6b.err")"
  if [ "$s6b_rc" = "0" ] && [ ! -e "$s6b" ] && [ "$EXPECT_RC" -ne 0 ] \
      && grep -a -F -q -- 'NO SNAPSHOT FILE' "$EXPECT_OUT"; then
    row_pass S6b "a measured command line WITHOUT --wire-snapshot exits 0 with a CLEAN stderr and no file, and run_measured's presence floor is the only thing that refuses it (harness rc=$EXPECT_RC)"
  else
    row_fail S6b "process rc=$s6b_rc, file exists=$([ -e "$s6b" ] && echo yes || echo no), harness rc=$EXPECT_RC; see $EXPECT_OUT"
  fi

  # ------------------ S7: the measured server drains, exits 0, writes a snapshot
  stop_measured_server
  local drained_pid_snapshot="$MEASURED_SNAPSHOT"
  set +e
  grep -a -F -q -- '"drain_outcome": "drained"' "$drained_pid_snapshot"
  local drained_rc=$?
  set -e
  if [ "$MEASURED_EXIT" = "0" ] && [ "$drained_rc" -eq 0 ]; then
    row_pass S7 "the measured server exited 0 (EXIT_DRAINED); the drain_outcome check beside it is TAUTOLOGICAL today (a hardcoded literal written only on the Drained arm) and the EXIT CODE is what discriminates"
  else
    row_fail S7 "measured server exit=$MEASURED_EXIT, drain_outcome grep rc=$drained_rc over $drained_pid_snapshot"
  fi

  # ------------- S8: SIGKILL before the rename => no snapshot => refusal
  local kill_snapshot="$H/server-killed.json"
  start_measured_server "$STACK_STATE" "$H" "$run_id" "$kill_snapshot"
  local killed_pid="$MEASURED_PID"
  kill -KILL "$killed_pid" 2>/dev/null || die "could not SIGKILL the measured server pid $killed_pid"
  wait_for_death "$killed_pid" 300 || die "the SIGKILLed measured server pid $killed_pid is still alive"
  set +e
  wait "$killed_pid"
  local killed_rc=$?
  set -e
  MEASURED_PID=""
  expect_failure "$OUT/s8.log" assert_snapshot_present "$kill_snapshot" "server"
  if [ ! -e "$kill_snapshot" ] && [ "$EXPECT_RC" -ne 0 ]; then
    row_pass S8 "a SIGKILL before the rename leaves NO snapshot file (server wait status $killed_rc) and the presence floor REFUSES the run (rc=$EXPECT_RC)"
  else
    row_fail S8 "kill_snapshot exists=$([ -e "$kill_snapshot" ] && echo yes || echo no), harness rc=$EXPECT_RC"
  fi

  # --- S9b: a FAILED stop keeps the exit trap's claim on the stack
  # A failed `stop` must leave `STACK_STATE`
  # registered for cleanup. The fixture
  # temporarily replaces the real stack registration
  # and restores it immediately after the
  # call, before checking the retained value.
  #
  # THE FIXTURE IS A REGULAR FILE. `scripts/stack.sh`
  # returns success for a nonexistent state
  # directory because the stack is already stopped.
  # A path that exists but is not a directory
  # reaches the directory check and fails,
  # providing the nonzero status this row needs.
  #
  # WHAT THIS ROW PROVES: `stop_stack` keeps the
  # registration when `stop` exits nonzero. The
  # regular-file fixture tests that decision.
  # It does not construct a running MinIO process
  # that refuses to stop, so it does not
  # establish the behavior of that teardown path.
  local real_stack_state="$STACK_STATE"
  printf 'not a state directory\n' > "$W/never-a-stack"
  STACK_STATE="$W/never-a-stack"
  stop_stack "$OUT/s9b.out" "$OUT/s9b.err"
  local kept_state="$STACK_STATE"
  STACK_STATE="$real_stack_state"
  if [ "$STACK_STOP_RC" != "0" ] && [ "$kept_state" = "$W/never-a-stack" ]; then
    row_pass S9b "a stop that exited $STACK_STOP_RC KEEPS the stack registered for the exit trap to retry, instead of reporting nothing left to stop"
  else
    row_fail S9b "stop rc=$STACK_STOP_RC left STACK_STATE=[$kept_state]; a failed teardown that clears the registration leaks a live MinIO into the next run"
  fi

  # ------------------------- S9: stack.sh stop takes the dead-server arm
  stop_stack "$OUT/stack-stop.out" "$OUT/stack-stop.err"
  local stop_rc="$STACK_STOP_RC"
  set +e
  grep -a -F -q -- 'stopped state' "$OUT/stack-stop.err"
  local stopped_rc=$?
  set -e
  if [ "$stop_rc" -eq 0 ] && [ "$stopped_rc" -eq 0 ]; then
    row_pass S9 "stack.sh stop took the dead-server arm cleanly after the harness killed its server (rc=$stop_rc)"
  else
    row_fail S9 "stack.sh stop rc=$stop_rc, 'stopped state' grep rc=$stopped_rc; see $OUT/stack-stop.err"
  fi

  echo
  echo "m10-propagate: $SELF_TEST_ROWS rows, $SELF_TEST_FAILURES failed"
  if [ "$SELF_TEST_FAILURES" -ne 0 ]; then
    die "the instrument self-test FAILED"
  fi
  echo "m10-propagate: instrument self-test PASSED"
}


# =============================================================== THE RUN
#
# THE RUN. The section above built the instruments; this builds the measurement
# they instrument: the corpus, the delta, and the ELEVEN measured processes
# that produce eleven snapshots and a timeline.
#
# This phase leaves raw inputs for assembly: snapshot
# files emitted by the measured processes, a
# tab-separated timeline, and a tab-separated corpus
# record. The assembler consumes these records.
# Keeping the run inputs permits assembly in a separate
# invocation, using the records captured by the run
# instead of the machine state at assembly time.

# The 2 GiB MEASUREMENT preset, measured on the Tier 2 guest on 2026-09-09:
# apparent (sum of st_size over regular
# files) 2,185,904,223 B = 2.036 GiB, 100,000 files, 4,000 directories.
# `d000001` is the changed subtree (6,003 files, 131,444,247 B, 6.0 % of
# the tree). `--symlinks 0` is NOT a parameter here: the walker refuses any
# entry that is neither a regular file nor a directory, so a preset that
# grew symlinks would be refused rather than silently half-walked.
PRESET_M10_SEED=10
PRESET_M10_DIRS=4000
PRESET_M10_FILES=100000
PRESET_M10_MEDIAN=13312
PRESET_M10_MAX_DEPTH=8
PRESET_M10_SUBTREE=d000001

# The SELF-TEST preset. The 2 GiB preset is for the measurement run; this
# one exists so a harness bug is found on a small corpus rather than after
# an hour of cluster time. Measured on the Tier 2 guest on 2026-09-09 with these
# exact parameters: apparent 65,143,063 B = 62.1 MiB (the >= 8 MiB
# corpus floor, cleared by 7.8x), 3,000 files, 120 directories; `d000001`
# holds 235 files and 4,844,834 B, so the one-in-ten delta rewrites 24
# files and the structure cost (~95 B/file x 235 ~ 22 KB) stays a few per
# cent of the novel total — the same regime the 2 GiB preset sits in, which
# is the property that makes a self-test on it meaningful.
PRESET_SELFTEST_SEED=10
PRESET_SELFTEST_DIRS=120
PRESET_SELFTEST_FILES=3000
PRESET_SELFTEST_MEDIAN=13312
PRESET_SELFTEST_MAX_DEPTH=8
PRESET_SELFTEST_SUBTREE=d000001

# THE DELTA REWRITES EVERY TENTH REGULAR FILE of the changed subtree in
# LC_ALL=C sorted order, with fresh content from a SECOND seed. The stride
# is fixed by the separation required between a working cache and no cache: let the
# changed subtree hold S bytes and the delta rewrite a fraction f, so
# novel = f*S. A perfect-cache client downloads f*S + structure; a no-cache
# client downloads S. Each client's download must be <= 3*novel, so a NO-CACHE client
# is caught only while f < 1/3, and a perfect-cache client passes with
# margin only while f >= structure/(2*S). f = 0.1 gives 1.05 against 10.0 —
# a 9.6x separation between a working cache and no cache, the outcomes the bound must distinguish.
# "Every SECOND file" was ruled first and REFUTED: at f = 0.5 a client with
# no cache at all downloads 2.0x novel and PASSES.
DELTA_STRIDE=10
# The second seed is 20,
# not the corpus seed (10), so no rewritten file
# can accidentally receive the content it already had.
DELTA_SEED=20

# The corpus floor, and the reason it is a floor: the cold/warm
# inequality `100 x warmup-verify <= warmup` holds while the corpus is
# large enough that the warm read's FIXED cost (root and hint reads — 318 B
# measured) is negligible. A harness run on a smaller tree is REFUSED with
# this number named, rather than silently reporting a bound that has
# stopped discriminating.
CORPUS_MIN_APPARENT_BYTES=8388608

# Bounds for the run's own waiters. The mount readiness bound is generous
# because the measurement mounts against a 2 GiB volume on a shared server
# with two siblings doing the same thing at the same moment. The umount bound
# is RAISED to the same 60 s for the same reason — three concurrent unmounts of
# a 2 GiB volume are not the instrument self-test's single small one.
# Both constants below are 600 ticks = 60 s. Halving either value to
# the instrument self-test's bound would not cover the three concurrent
# 2 GiB operations described above, so readiness and unmount use the
# same raised duration.
# The constants immediately below encode that duration.
MOUNT_READY_TICKS=600
MOUNT_UMOUNT_TICKS=600

# ------------------------------------------------------------- THE CLOCKS
#
# TWO INSTRUMENTS, ONE PREDICATE. Clock A is a CACHELESS `gran cat` polled at
# 1 s; clock B is a FRESH `gran mount` on a NEW cache directory per attempt.
# Both stop on the SAME thing: the SENTINEL'S CONTENT HASH equalling the
# `v_(n+1)` value computed on the publisher's source tree before the publish.
# NEVER "the read succeeded" — a client serving the OLD content returns bytes
# and exits 0, and that green vacuum is the trap this harness exists to
# refuse. One predicate across two instruments is also what makes the two
# numbers comparable.
CLOCK_A_POLL_SECONDS=1

# The caps are NOT the verdict thresholds and must not be confused with
# them. The thresholds are 30 s for clock A and 60 s for clock B, and
# THE VERB decides whether a number clears them — this harness computes no
# verdict. These are the bounds past which the harness stops waiting and
# reports a FAILED clock, which is a refusal of the run rather than a small
# number. They sit well above the registered thresholds on purpose: a clock
# that reports 91 s must reach the verb as 91 s, fail the clock thresholds, and not be
# truncated here into an unfalsifiable "timed out".
CLOCK_A_CAP_SECONDS=120
CLOCK_B_CAP_SECONDS=180

# The NO-PUBLISH negative's cap. It runs BEFORE the publish, so the content it
# hunts does not exist and no cap can produce it; the only thing the length
# buys is polls, and eight seconds is eight polls of clock A and at least one
# full mount/read/umount cycle of clock B.
CLOCK_NEGATIVE_CAP_SECONDS=8

# `head.rs:106-107`: the persisted hint's poll TTL is `48_000 + rng.below(24_000)`
# ms, i.e. `[48 s, 72 s)`. Under 48 s a reused cache-dir is GUARANTEED not to
# re-poll, which is the premise the reused-cache-dir demonstration rests on —
# and the demonstration MEASURES that premise instead of assuming it, because a
# probe taken after the window has reopened would see the new content and the
# row would report a failure of granary rather than an unmet premise of its own.
HINT_TRUSTED_SECONDS=48

# ---------------------------------------------------------- THE ARTIFACT
ARTIFACT_VERSION=1

# The count gate's DENSITY FLOOR and the sample spacing bound. The count
# floor is `floor(duration / NODE_SAMPLE_DENSITY_PERIOD_SECONDS)` over the RUN
# WINDOW, and no two consecutive samples covering that window may be more
# than `NODE_SAMPLE_MAX_GAP_SECONDS` apart: a series CLUSTERED at the two
# boundaries satisfies first, last and count while leaving the middle of the
# run — where a competing workload would show — unsampled.
#
# THIS IS NOT THE SAMPLER'S OWN INTERVAL. `scripts/m10-node-sample.sh` writes
# a reading every 10 s (its own `sleep 10`, unrelated to this constant) and
# that stays 10 s — a verifier enforcing 10 s would have REFUSED a good run
# whose largest observed gap was 11.0 s. A count floor of
# `floor(duration / 10)` re-imposed that same 10 s as an average from the
# other side: the committed run cleared it by ONE sample (14 against 13
# required), and a run at a uniform 11.0 s cadence — a spacing this sampler
# has already produced — yields 12 and would be REFUSED while passing the
# 15 s spacing bound. 12 s sits strictly above the largest gap observed so
# far and strictly below the 15 s hole bound, and it is scale-free: an 11 s
# run clears it at any window length, where `floor(duration / 10) - 1` would
# silently re-impose the sampler's 10 s interval as the window grows.
NODE_SAMPLE_DENSITY_PERIOD_SECONDS=12
NODE_SAMPLE_MAX_GAP_SECONDS=15

# Read ONE scalar field out of a snapshot, by dotted path, REFUSING every
# way it could be absent. A sed/grep field extractor was the obvious
# spelling and it is fail-open twice over: a missing field yields the empty
# string, and an empty string compared numerically is a syntax error whose
# rc a caller may or may not be reading. This refuses a file that is not
# JSON, a path that is not present, a null, and a non-scalar — each with
# the file and the path named.
SNAPSHOT_FIELD_PY="$(cat <<'PY'
import json
import sys

path_arg = sys.argv[1]
field = sys.argv[2]
try:
    with open(path_arg, "rb") as handle:
        doc = json.load(handle)
except Exception as error:  # noqa: BLE001 - any failure to read is a refusal
    sys.stderr.write("REFUSED: %s is not readable JSON: %s\n" % (path_arg, error))
    raise SystemExit(9)
cur = doc
for segment in field.split("."):
    if not isinstance(cur, dict) or segment not in cur:
        sys.stderr.write("REFUSED: %s has no field %s\n" % (path_arg, field))
        raise SystemExit(9)
    cur = cur[segment]
if cur is None:
    sys.stderr.write("REFUSED: %s field %s is null\n" % (path_arg, field))
    raise SystemExit(9)
if isinstance(cur, bool):
    sys.stdout.write("true\n" if cur else "false\n")
elif isinstance(cur, int):
    sys.stdout.write("%d\n" % cur)
elif isinstance(cur, str):
    if cur == "":
        sys.stderr.write("REFUSED: %s field %s is the empty string\n" % (path_arg, field))
        raise SystemExit(9)
    sys.stdout.write("%s\n" % cur)
else:
    sys.stderr.write("REFUSED: %s field %s is not a scalar\n" % (path_arg, field))
    raise SystemExit(9)
PY
)"

# THE DELTA. Every TENTH regular file of the changed subtree, in LC_ALL=C
# sorted order (the walker's own order — byte order over the RELATIVE form,
# so the two agree by construction rather than by luck), rewritten with
# fresh pseudorandom content derived from the second seed and the file's own
# relative path. Prints `<files rewritten> <bytes rewritten> <files seen>`.
#
# THE SIZE IS PRESERVED, deliberately. `changed_subtree_bytes` is recorded
# at v_n and the delta fraction is recomputed from it later, so a delta that
# also changed the subtree's total would make the recorded denominator
# describe a tree that no longer exists.
#
# IT REFUSES a rewrite that produced the SAME bytes. gen-tree writes at
# least one byte per file, and a one-byte file redrawn from 256 values
# collides one time in 256 — a file that "changed" to its own content
# contributes no novel bytes and would quietly shrink f. Redrawn with a
# salt, up to eight times, then refused.
#
# IT REFUSES a non-regular entry the same way the walker does, including a
# symlinked DIRECTORY, which `os.walk` reports under `dirnames` and which a
# check over files alone would never see.
#
# IT ALSO WRITES THE PICKED LIST, `<relative path>\t<old sha256>\t<new sha256>`
# per rewritten file, and THAT IS WHERE THE SENTINEL COMES FROM. The two clocks
# need one file whose content differs between `v_n` and `v_(n+1)` and whose two
# hashes are both known; the delta is the only code that ever holds both, since
# `v_n`'s bytes are gone the moment they are overwritten. Deriving the sentinel
# instead from "the first file the walker's sort visits" would be a SECOND
# implementation of this function's ordering, agreeing with it by luck; the
# harness re-hashes the new content off the source tree as a cross-check, so
# the one number that cannot be re-derived (the OLD hash) is the only one taken
# on trust.
DELTA_PY="$(cat <<'PY'
import hashlib
import os
import random
import stat
import sys

root = sys.argv[1]
seed = int(sys.argv[2])
stride = int(sys.argv[3])
picked_out = sys.argv[4]

names = []
for dirpath, dirnames, filenames in os.walk(root):
    for entry in dirnames:
        st = os.lstat(os.path.join(dirpath, entry))
        if not stat.S_ISDIR(st.st_mode):
            sys.stderr.write(
                "REFUSED: %s is listed as a directory but is not one\n"
                % os.path.join(dirpath, entry))
            raise SystemExit(9)
    for entry in filenames:
        full = os.path.join(dirpath, entry)
        st = os.lstat(full)
        if not stat.S_ISREG(st.st_mode):
            sys.stderr.write(
                "REFUSED: %s is neither a regular file nor a directory\n" % full)
            raise SystemExit(9)
        names.append(os.path.relpath(full, root))

names.sort(key=lambda name: name.encode("utf-8", "surrogateescape"))
picked = [name for index, name in enumerate(names) if index % stride == 0]
if not picked:
    sys.stderr.write(
        "REFUSED: a stride of %d over %d regular files would rewrite NOTHING; "
        "a delta that changes no byte makes the whole measurement vacuous\n"
        % (stride, len(names)))
    raise SystemExit(9)

written = 0
rows = []
for rel in picked:
    full = os.path.join(root, rel)
    with open(full, "rb") as handle:
        old = handle.read()
    fresh = None
    for salt in range(8):
        digest = hashlib.sha256(
            b"m10-delta\x00%d\x00%d\x00" % (seed, salt)
            + rel.encode("utf-8", "surrogateescape")).digest()
        candidate = random.Random(int.from_bytes(digest, "big")).randbytes(len(old))
        if candidate != old:
            fresh = candidate
            break
    if fresh is None:
        sys.stderr.write(
            "REFUSED: eight draws for %s all reproduced its existing content\n" % rel)
        raise SystemExit(9)
    with open(full, "wb") as handle:
        handle.write(fresh)
    written += len(fresh)
    if "\t" in rel or "\n" in rel:
        sys.stderr.write(
            "REFUSED: %s carries a tab or a newline and the picked list is "
            "tab-separated one row per file\n" % rel)
        raise SystemExit(9)
    rows.append("%s\t%s\t%s" % (rel,
                                hashlib.sha256(old).hexdigest(),
                                hashlib.sha256(fresh).hexdigest()))

with open(picked_out, "w", encoding="utf-8") as handle:
    handle.write("\n".join(rows) + "\n")

sys.stdout.write("%d %d %d\n" % (len(picked), written, len(names)))
PY
)"

# The generator's default size cap, passed EXPLICITLY and validated here.
#
# INHERITED DEFECT, guarded at the call site rather than fixed at its home:
# `scripts/gen-tree.py`'s `lognormal_size` draws `n = max(1,
# int(v))` and resamples until `n < cap_bytes`, so any cap at or below 1 can
# never be satisfied and the loop spins forever — AFTER `main` has already
# created the destination directory. `main`'s own validation checks
# only the UPPER bound (the 16 MiB C2 no-spill precondition) and
# never the lower one. The generator was promoted byte-for-byte,
# with that defect retained, so the refusal lives here:
# this harness never passes a cap no draw can satisfy. Promotion inherits
# defects, and this is the first one this tree has found.
CORPUS_SIZE_CAP=1048576

# ----------------------------------------------------------- the corpus
#
# Use the preset parameters defined below. `--symlinks 0` is not a
# choice a caller gets: the walker covers regular files and directories,
# and `-type f` would SILENTLY SKIP a symlink, so a preset that
# grew one would produce expected and observed digests that agreed while
# ignoring it.
CORPUS_SEED=""
CORPUS_DIRS=""
CORPUS_FILES=""
CORPUS_MEDIAN=""
CORPUS_MAX_DEPTH=""
CORPUS_SUBTREE=""

select_preset() {
  local name="$1"
  case "$name" in
    m10)
      CORPUS_SEED="$PRESET_M10_SEED"
      CORPUS_DIRS="$PRESET_M10_DIRS"
      CORPUS_FILES="$PRESET_M10_FILES"
      CORPUS_MEDIAN="$PRESET_M10_MEDIAN"
      CORPUS_MAX_DEPTH="$PRESET_M10_MAX_DEPTH"
      CORPUS_SUBTREE="$PRESET_M10_SUBTREE"
      ;;
    selftest)
      CORPUS_SEED="$PRESET_SELFTEST_SEED"
      CORPUS_DIRS="$PRESET_SELFTEST_DIRS"
      CORPUS_FILES="$PRESET_SELFTEST_FILES"
      CORPUS_MEDIAN="$PRESET_SELFTEST_MEDIAN"
      CORPUS_MAX_DEPTH="$PRESET_SELFTEST_MAX_DEPTH"
      CORPUS_SUBTREE="$PRESET_SELFTEST_SUBTREE"
      ;;
    *) die "--preset must be m10 or selftest, got: $name" ;;
  esac
}

generate_corpus() {
  local dest="$1" log="$2" rc

  # The inherited-defect guard, and the generator's own upper bound restated
  # so a cap outside the band is refused BEFORE the destination exists rather
  # than by an infinite loop after it.
  case "$CORPUS_SIZE_CAP" in
    ''|*[!0-9]*) die "the corpus size cap is not numeric: [$CORPUS_SIZE_CAP]" ;;
  esac
  [ "$CORPUS_SIZE_CAP" -ge 2 ] \
    || die "the corpus size cap is $CORPUS_SIZE_CAP; gen-tree.py draws at least one byte per file and resamples until the draw is STRICTLY BELOW the cap, so any cap at or below 1 spins forever after creating the destination (gen-tree.py's lognormal_size resample loop; its main() validates only the upper bound)"
  [ "$CORPUS_SIZE_CAP" -lt 16777216 ] \
    || die "the corpus size cap is $CORPUS_SIZE_CAP; gen-tree.py refuses 16777216 or more (the C2 no-spill precondition, gen-tree.py main()'s size-cap refusal)"
  case "$CORPUS_MEDIAN" in
    ''|*[!0-9]*) die "the corpus median size is not numeric: [$CORPUS_MEDIAN]" ;;
  esac
  [ "$CORPUS_MEDIAN" -ge 1 ] \
    || die "the corpus median size must be at least 1 byte, got $CORPUS_MEDIAN"
  [ "$CORPUS_MEDIAN" -lt "$CORPUS_SIZE_CAP" ] \
    || die "the corpus median size $CORPUS_MEDIAN is not below the cap $CORPUS_SIZE_CAP; the generator would resample most draws away and the corpus would not have the shape its parameters name"

  set +e
  python3 "$GEN_TREE" "$dest" \
    --seed "$CORPUS_SEED" --dirs "$CORPUS_DIRS" --files "$CORPUS_FILES" \
    --symlinks 0 --size-median-bytes "$CORPUS_MEDIAN" \
    --size-cap-bytes "$CORPUS_SIZE_CAP" --max-depth "$CORPUS_MAX_DEPTH" \
    > "$log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    cat "$log" >&2
    die "gen-tree.py failed (rc=$rc)"
  fi
  cat "$log"
}

# Sum of `st_size` over REGULAR FILES, computed by this harness
# rather than read off `du` (allocated blocks, measured 10 % higher) or off
# `gen-tree.py`'s printed `bytes=` (an INTENDED count, and its own docstring
# says it is not a substitute for a tool-derived one).
#
# IT IS CROSS-CHECKED AGAINST THE WALKER'S OWN COUNT. This is a SECOND `find`
# pass over the same tree, and a sum over a different set of files than the
# digest committed to would be a number about nothing — so the caller passes
# the count `subtree_digest` returned and a disagreement refuses.
apparent_bytes() {
  local dir="$1" label="$2" expect="$3"
  local tmp rc total counted

  [ -d "$dir" ] || die "$label: not a directory: $dir"
  case "$expect" in
    ''|*[!0-9]*) die "$label: the walker's file count is not numeric: [$expect]" ;;
  esac
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/m10-apparent.XXXXXX")" \
    || die "$label: could not create a scratch directory for the size pass"
  set +e
  ( cd "$dir" && find . -type f -printf '%s\n' ) > "$tmp/sizes" 2> "$tmp/err"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    cat "$tmp/err" >&2
    rm -rf "$tmp"
    die "$label: the size pass failed under $dir (find exited $rc)"
  fi
  counted="$(wc -l < "$tmp/sizes")"
  counted="${counted//[[:space:]]/}"
  case "$counted" in
    ''|*[!0-9]*) rm -rf "$tmp"; die "$label: could not count the sized files (got [$counted])" ;;
  esac
  if [ "$counted" -ne "$expect" ]; then
    rm -rf "$tmp"
    die "$label: the size pass saw $counted regular files under $dir but the walker hashed $expect; the two passes disagree about what the tree is"
  fi
  total="$(awk '{ s += $1 } END { printf "%d\n", s }' "$tmp/sizes")"
  rm -rf "$tmp"
  total="${total//[[:space:]]/}"
  case "$total" in
    ''|*[!0-9]*) die "$label: the size pass produced a non-numeric total: [$total]" ;;
  esac
  [ "$total" -gt 0 ] || die "$label: the apparent size under $dir is zero"
  printf '%s\n' "$total"
}

generate_delta() {
  local subtree="$1" out="$2" picked="$3" rc line

  [ -d "$subtree" ] || die "the delta's changed subtree is not a directory: $subtree"
  [ -n "$picked" ] || die "the delta generator was given no path for the picked list"
  [ ! -e "$picked" ] \
    || die "the delta's picked-list destination already exists: $picked"
  set +e
  python3 -c "$DELTA_PY" "$subtree" "$DELTA_SEED" "$DELTA_STRIDE" "$picked" \
    > "$out" 2> "$out.err"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    cat "$out.err" >&2
    die "the delta generator failed under $subtree (rc=$rc)"
  fi
  line="$(sed -n '1p' "$out")"
  [ -n "$line" ] || die "the delta generator printed nothing"
  [ -s "$picked" ] \
    || die "the delta generator wrote no picked list at $picked; the sentinel the two clocks poll comes from that list and there is no second source for it"
  printf '%s\n' "$line"
}

# ------------------------------ THE SENTINEL MUST RESOLVE INSIDE THE SUBTREE
#
# The sentinel must identify content inside the changed
# subtree. A spelling that begins with the subtree name
# is insufficient: `..` can escape it, and a symlink
# can resolve outside it without a `..` component.
# Hashing the same escaped file again would only confirm
# that file's contents, not its membership in the
# workload. The harness checks absolute paths and parent
# components before resolving the target, then requires
# the resolved path to equal the subtree root or begin
# with that root and a path separator. This makes
# containment a harness requirement rather than
# leaving it to whichever consumer reads the sentinel.
#
# THREE REFUSALS, AND THE THIRD IS THE ONE A SPELLING RULE CANNOT GIVE YOU.
# An absolute path and a `..` component are refused by spelling. Resolution is
# refused separately, because a SYMLINK inside the subtree leaves it with no
# `..` anywhere in the name — and `gran mount` will follow one exactly as the
# kernel does. Row C2 fires all three, with an ordinary name as its positive
# control.
assert_sentinel_contained() {
  local subtree="$1" rel="$2" label="${3:-the sentinel}"
  local rc
  [ -n "$rel" ] || die "$label: the path is empty"
  case "$rel" in
    /*) die "$label: [$rel] is an ABSOLUTE path; the clocks poll a path RELATIVE to the changed subtree and an absolute one names a file the byte workload never reads" ;;
  esac
  case "/$rel/" in
    */../*) die "$label: [$rel] carries a '..' component. It is inside the subtree by spelling and outside it by resolution: gran cat refuses such a name by its own rule and a FUSE mount NORMALISES it, so the two instruments would measure different files" ;;
  esac
  set +e
  python3 - "$subtree" "$rel" >&2 <<'PY'
import os
import sys

root = os.path.realpath(sys.argv[1])
target = os.path.realpath(os.path.join(sys.argv[1], sys.argv[2]))
if not (target == root or target.startswith(root + os.sep)):
    sys.stderr.write("REFUSED: %s resolves to %s, which is OUTSIDE %s. A "
                     "symlink inside the subtree leaves it with no '..' "
                     "anywhere in the name, and gran mount follows one exactly "
                     "as the kernel does.\n" % (sys.argv[2], target, root))
    raise SystemExit(9)
if not os.path.isfile(target) or os.path.islink(os.path.join(sys.argv[1], sys.argv[2])):
    sys.stderr.write("REFUSED: %s is not a regular file at %s (or the name "
                     "itself is a symlink)\n" % (sys.argv[2], target))
    raise SystemExit(8)
PY
  rc=$?
  set -e
  [ "$rc" -eq 0 ] \
    || die "$label: [$rel] does not resolve to a regular file INSIDE $subtree (rc=$rc)"
}

# The digest of everything OUTSIDE the changed subtree, as a MANIFEST of
# (relative path, size, mtime) rather than of content — and the difference is
# a cost decision, stated: the measurement corpus is hundreds of megabytes and
# a content digest of its complement, taken twice, would add two full reads to
# every run for a property that mtime already settles. A delta rewrites bytes
# in place, so any file it touched outside the subtree moves its mtime; a file
# it created or removed changes the listing. Row C3 proves the manifest MOVES
# for a file created outside the subtree and returns to its original value
# when that file is removed, so it is not a constant.
complement_manifest() {
  local root="$1" subtree="$2" out="$3"
  find "$root" -path "$subtree" -prune -o -type f -printf '%P\t%s\t%T@\n' \
    | LC_ALL=C sort > "$out" \
    || die "could not take the complement manifest of $root outside $subtree"
  [ -s "$out" ] \
    || die "the complement manifest of $root outside $subtree is EMPTY; a manifest with no rows cannot detect a change and would pass every comparison"
}

# --------------------------------------------------- WHERE `n` COMES FROM
#
# The stack prints `GRAN_ENDPOINT`/`GRAN_PIN`/`GRAN_ROOT_KEY`/`GRAN_VOLUME`
# on success (`stack.sh:546-549`) and NOT the seq, so the harness reads it
# from the stack's own publish log by MATCHING `published <volume> seq <n>
# epoch <e>` (`granary-cli`'s `report_publish`) — BY PATTERN, NEVER BY
# LINE POSITION. Position is not stable: `gran publish` prints a three-line
# key block ONLY when the seed is first generated (`stack.sh:527-528`), so
# a positional parse reads the key line on a first run and the right line on
# every later one. Measured on a 320 MB tree on the Tier 2 guest on 2026-09-09:
# `generated publishing key: …` / `  seed  …` / `  pub   …` /
# `published rate seq 1 epoch 1` — the line wanted is FOUR.
#
# THE MATCH IS STRUCTURAL, not a regex over the volume name: `awk` compares
# whole fields, so a volume name carrying a regex metacharacter cannot widen
# or narrow the match.
#
# AND THIS IS A SHELL PARSE OF A TOOL'S STDOUT, which this harness refuses
# for `novel_bytes`. The difference is not taste: `novel_bytes` is refused
# because NOTHING re-derives it — the shell's claim would be the only witness
# and Rust would seal it. `n` is admissible because the artifact makes it
# CHECKABLE: `warmup-k.pinned_seq + 1 == publisher.publish.seq` and
# `client-k.pinned_seq == publisher.publish.seq` are both recomputed from
# snapshots Rust wrote from `margs.seq` (`granary-cli`'s `attach`, where
# `MountWireSnapshot` is built), so a misparsed `n`
# cannot reach a verdict — it fails the run. The test for "may the shell
# parse this?" is whether the artifact lets Rust refute the parse.
parse_stack_seq() {
  local log="$1" volume="$2"
  local tmp rc matched seq

  [ -f "$log" ] \
    || die "the stack did not write $log; the harness has no source for n"
  [ -n "$volume" ] || die "parse_stack_seq was given an empty volume name"
  tmp="$(mktemp "${TMPDIR:-/tmp}/m10-seq.XXXXXX")" \
    || die "could not create a scratch file for the seq parse"
  set +e
  awk -v vol="$volume" \
    '(NF == 6 || (NF == 7 && $7 == "route=server-seam")) && $1 == "published" && $2 == vol && $3 == "seq" && $5 == "epoch" { print $4 }' \
    "$log" > "$tmp" 2> "$tmp.err"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    cat "$tmp.err" >&2
    rm -f "$tmp" "$tmp.err"
    die "could not scan $log for the published-seq line (awk exited $rc); a scan that did not run has established nothing"
  fi
  matched="$(wc -l < "$tmp")"
  matched="${matched//[[:space:]]/}"
  case "$matched" in
    ''|*[!0-9]*) rm -f "$tmp" "$tmp.err"; die "could not count the matching lines in $log (got [$matched])" ;;
  esac
  if [ "$matched" -ne 1 ]; then
    rm -f "$tmp" "$tmp.err"
    die "expected EXACTLY ONE 'published $volume seq <n> epoch <e>' line in $log, found $matched; the seq is matched by pattern and a source that is ambiguous or absent is refused rather than guessed at"
  fi
  seq="$(sed -n '1p' "$tmp")"
  rm -f "$tmp" "$tmp.err"
  case "$seq" in
    ''|*[!0-9]*) die "the published-seq line in $log carries a non-numeric seq: [$seq]" ;;
  esac
  printf '%s\n' "$seq"
}

# ------------------------------------------------ reading a snapshot back
snapshot_field() {
  local file="$1" field="$2" label="$3" out rc
  [ -f "$file" ] || die "$label: no snapshot file at $file"
  set +e
  out="$(python3 -c "$SNAPSHOT_FIELD_PY" "$file" "$field" 2>&1)"
  rc=$?
  set -e
  [ "$rc" -eq 0 ] \
    || die "$label: could not read '$field' from $file (rc=$rc): $out"
  [ -n "$out" ] || die "$label: '$field' in $file read back empty"
  printf '%s' "$out"
}

# THE UPPER BOUND ON EVERY SNAPSHOT INTEGER, enforced where the values ENTER
# rather than at each of the dozen places they are multiplied and summed.
#
# Snapshot counters enter shell arithmetic after parsing. A
# digit-only check is insufficient: a large decimal value
# can exceed the range of the arithmetic used for products
# and sums. `snapshot_u64` bounds each value before those
# computations, including the client-byte comparisons and the
# multi-client sum. A wrapped total could appear smaller than
# the server total and satisfy an upper bound for the wrong
# reason. The shared input bound prevents callers from
# treating an arbitrarily long digit string as a usable
# counter; checking each value on entry also avoids depending
# on every later arithmetic site to repeat the validation.
#
# 2^53 IS THE BOUND, and it is chosen rather than convenient. It is 9 PB — far
# above any byte count these runs can produce. It is far below 2^63/3 and below
# 2^63/(10 x 100), so no product or sum this harness forms can wrap beneath it.
# And it is exactly representable as an IEEE double, so a successor who moves
# one of these comparisons into `awk`, `python` or a JSON consumer inherits a
# number that survives the move rather than one that silently stops being
# integral.
SNAPSHOT_U64_MAX=9007199254740992
snapshot_u64() {
  local file="$1" field="$2" label="$3" value trimmed
  value="$(snapshot_field "$file" "$field" "$label")"
  case "$value" in
    ''|*[!0-9]*) die "$label: '$field' in $file is not a non-negative integer: [$value]" ;;
  esac
  # THE DIGIT COUNT IS CHECKED BEFORE THE COMPARISON, and the order is
  # load-bearing. The comparison below is bash arithmetic, and bash reads a
  # decimal literal through `strtoimax`, which SATURATES at 2^63-1 — so a
  # 20-digit field would be compared as 9223372036854775807, caught only by an
  # accident of a saturation this code does not control. 2^53 has 16 digits, so
  # a longer one is above the bound by construction and is refused before any
  # arithmetic touches it.
  trimmed="${value#"${value%%[!0]*}"}"
  [ -n "$trimmed" ] || trimmed=0
  if [ "${#trimmed}" -gt 16 ] || [ "$trimmed" -ge "$SNAPSHOT_U64_MAX" ]; then
    die "$label: '$field' in $file is $value, at or above the $SNAPSHOT_U64_MAX (2^53) bound this harness accepts. Bash arithmetic is 64-bit signed, so every product and sum these rows compute over it would wrap silently and the upper-bound comparisons would report a PASS; an over-large counter is REFUSED rather than compared."
  fi
  printf '%s' "$value"
}

# --------------------------------------------------------- THE TIMELINE
#
# Harness wall clock, UTC, MILLISECOND resolution and a FIXED WIDTH.
#
# The width is the point: every stamp this harness writes is exactly
# `YYYY-MM-DDTHH:MM:SS.mmmZ`, so lexicographic order IS chronological order
# and the ordering assertions below need no date arithmetic. Seconds were the
# obvious choice and are not enough — the delta of a small corpus is
# generated and published inside one second, so a second-resolution timeline
# cannot show that the warm-ups ended before the publish started even when
# they did. Whatever produces the node-CPU samples must use this same
# spelling, or a consumer comparing the two has to parse rather than compare.
TIMELINE_FILE=""
timeline_mark() {
  local field="$1" now
  [ -n "$TIMELINE_FILE" ] || die "timeline_mark was called before the timeline file was set"
  now="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
  # `?` checks width without requiring digits.
  # The explicit `[0-9]` fields check the
  # timestamp's numeric spelling as well as
  # punctuation before it is written to the timeline.
  case "$now" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z) ;;
    *) die "the harness clock produced a stamp this harness cannot order: [$now]" ;;
  esac
  printf '%s\t%s\n' "$field" "$now" >> "$TIMELINE_FILE"
  printf '%s' "$now"
}

timeline_get() {
  local field="$1" tmp matched value
  [ -f "$TIMELINE_FILE" ] || die "the timeline file is missing: $TIMELINE_FILE"
  tmp="$(mktemp "${TMPDIR:-/tmp}/m10-timeline.XXXXXX")" \
    || die "could not create a scratch file for the timeline read"
  awk -F '\t' -v want="$field" 'NF == 2 && $1 == want { print $2 }' \
    "$TIMELINE_FILE" > "$tmp"
  matched="$(wc -l < "$tmp")"
  matched="${matched//[[:space:]]/}"
  if [ "$matched" != "1" ]; then
    rm -f "$tmp"
    die "the timeline holds $matched entries for '$field', want exactly 1"
  fi
  value="$(sed -n '1p' "$tmp")"
  rm -f "$tmp"
  printf '%s' "$value"
}

# THE TIMELINE CHAIN IS STRICT; PHASE MEMBERSHIP
# ALLOWS EQUALITY. Adjacent timeline events need
# strictly increasing timestamps to establish their
# order. An observation timestamp can legitimately
# equal a phase boundary, so `stamp_not_after` admits
# equality. These are separate predicates for separate
# questions: one orders consecutive events, the
# other tests whether an observation falls within a
# phase. The assembler also rejects equal consecutive
# timeline timestamps. Keep the strict ordering
# check separate from the inclusive boundary
# predicate instead of using one comparison for both.
assert_strictly_before() {
  local earlier="$1" later="$2" what="$3"
  [[ "$earlier" < "$later" ]] \
    || die "the timeline is not strictly increasing: $what ($earlier does not precede $later)"
}

# The same comparison as a PREDICATE, for the rows that report every violation
# in one pass instead of dying at the first.
stamp_not_after() {
  [[ "$1" < "$2" || "$1" == "$2" ]]
}

# ---------------------------------------- A CLOCK THE HARNESS DOES NOT STAMP
#
# `timeline_mark` records when the HARNESS CALLED IT, which is a fact about the
# harness and not about the event it names. A mark moved to the wrong side of
# the work it brackets records a false ordering and every ordering assertion
# still passes, because they all read the same marks.
#
# The eleven snapshot FILES carry a second clock: kernel modification times,
# written by the MEASURED PROCESSES as they exit, from the same
# `CLOCK_REALTIME` the harness's `date` reads — and `write`-then-`rename`
# preserves them, so the stamp is the moment the content was written and not
# the moment it was published. Measured on this venue: 8-19 ms before each
# `.rc`, and the file timestamp granularity is 10 ms (a coarse jiffy clock),
# which TRUNCATES an mtime downwards — the safe direction for every
# `mtime <= mark` bound and a 10 ms tax on every `mark <= mtime` one, all of
# which carry more than 100 ms.
#
# WHAT THIS IS AND IS NOT: it is a CROSS-CHECK between two clocks, not a proof
# that the events happened. Nothing here can establish that the processes named
# are the processes that ran; that stays in the artifact's OBSERVED partition,
# read back by the verb and never derived by it.
file_stamp() {
  local path="$1" label="$2" out
  [ -e "$path" ] || die "$label: no file at $path to read a modification time from"
  out="$(date -u -r "$path" +%Y-%m-%dT%H:%M:%S.%3NZ 2>/dev/null)" \
    || die "$label: could not read the modification time of $path"
  case "$out" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z) ;;
    *) die "$label: the modification time of $path is not a stamp this harness can order: [$out]" ;;
  esac
  printf '%s' "$out"
}

# The same mtime as milliseconds since the epoch, for the rows that report a
# MARGIN rather than an ordering. Two spellings of one clock, so nothing has to
# parse the other.
file_stamp_ms() {
  local path="$1" label="$2" out
  [ -e "$path" ] || die "$label: no file at $path to read a modification time from"
  out="$(date -u -r "$path" +%s%3N 2>/dev/null)" \
    || die "$label: could not read the modification time of $path"
  case "$out" in
    ''|*[!0-9]*) die "$label: the modification time of $path is not numeric: [$out]" ;;
  esac
  [ "${#out}" -le 16 ] \
    || die "$label: the modification time of $path has ${#out} digits; the harness will not do arithmetic on it"
  printf '%s' "$out"
}

# ------------------------------------------------ THE MOUNT/WALK UNIT
#
# ONE measured mount process, its walk, its unmount and its three floors —
# the shape all NINE of the per-client processes share. It exists as one
# function because the alternative is three near-copies, and a copy per call
# site is how one of the floors quietly stops running.
#
# IT MUST RUN IN A SUBSHELL, and it checks that it is. It installs its own
# EXIT trap so a walk that refuses does not leave a live FUSE mount behind,
# and a trap installed in the MAIN shell would replace the run's own cleanup.
#
# CLEANUP CHECKS THE DAEMON AS WELL AS THE MOUNTPOINT.
# A mount process can still be alive without an
# attached mount when the readiness deadline expires.
# A sweep of attached mountpoints alone cannot find
# that process, and a surviving process could attach
# after the sweep. Lazy detachment can also leave
# a daemon alive. The unit tracks its pid
# independently: after attempting detachment, cleanup
# checks liveness, sends SIGTERM, and escalates
# to SIGKILL if the wait expires. It then waits
# for the tracked child and clears the saved pid.
#
# THE ORDER IS DETACH-THEN-TERMINATE. A daemon whose mount is detached exits on
# its own, so the polite path is tried first and the signal is what remains.
UNIT_MNT=""
UNIT_DAEMON_PID=""
unit_detach() {
  if [ -n "${UNIT_MNT:-}" ] && mountpoint -q "$UNIT_MNT" 2>/dev/null; then
    echo "m10-propagate: unit cleanup: $UNIT_MNT is still attached; detaching" >&2
    if ! fusermount3 -u -z "$UNIT_MNT" 2>/dev/null; then
      echo "m10-propagate: unit cleanup: could not detach $UNIT_MNT" >&2
    fi
  fi
  if [ -n "${UNIT_DAEMON_PID:-}" ] && pid_is_alive "$UNIT_DAEMON_PID"; then
    echo "m10-propagate: unit cleanup: the mount daemon (pid $UNIT_DAEMON_PID) is still alive; SIGTERM" >&2
    kill -TERM "$UNIT_DAEMON_PID" 2>/dev/null
    if ! wait_for_death "$UNIT_DAEMON_PID" 100; then
      echo "m10-propagate: unit cleanup: pid $UNIT_DAEMON_PID ignored SIGTERM for 10 s; SIGKILL" >&2
      kill -KILL "$UNIT_DAEMON_PID" 2>/dev/null
      wait_for_death "$UNIT_DAEMON_PID" 100 \
        || echo "m10-propagate: unit cleanup: pid $UNIT_DAEMON_PID survived SIGKILL" >&2
    fi
    set +e
    wait "$UNIT_DAEMON_PID" 2>/dev/null
    set -e
  fi
  UNIT_DAEMON_PID=""
  return 0
}

# mount_walk_unit ROLE RUN_ID MNT CACHE SEQ SNAPSHOT WALK_REL OUTDIR PREFIX
#
# WALK_REL empty walks the WHOLE tree; otherwise it walks that path under the
# mount. Writes `<prefix>.digest` (`<64 hex> <count>`) and `<prefix>.rc`.
mount_walk_unit() {
  local role="$1" run_id="$2" mnt="$3" cache="$4" seq="$5"
  local snapshot="$6" walk_rel="$7" outdir="$8" prefix="$9"
  local stdout_file stderr_file daemon_pid ready attempt walk_dir line rc umount_rc

  [ "${BASHPID:-$$}" != "$$" ] \
    || die "$role: mount_walk_unit must run in a subshell; in the main shell its EXIT trap would replace the run's own cleanup"

  stdout_file="$outdir/$prefix.mount.out"
  stderr_file="$outdir/$prefix.mount.err"
  UNIT_MNT="$mnt"
  trap unit_detach EXIT

  # THE MOUNTS USE `--root-key` WITH THE STACK'S `GRAN_ROOT_KEY`,
  # not `--trust-server`. Both work; only one is the production posture, and a
  # measurement taken under a trust mode nobody ships is a measurement of
  # something else.
  "$RUN_GRAN" mount "$RUN_VOLUME" "$mnt" \
    --endpoint "$MEASURED_ENDPOINT" --pin "$RUN_PIN" --root-key "$RUN_ROOT_KEY" \
    --cache-dir "$cache" --foreground --seq "$seq" \
    --wire-snapshot "$snapshot" --wire-run-id "$run_id" --wire-role "$role" \
    > "$stdout_file" 2> "$stderr_file" &
  daemon_pid=$!
  # THE TRAP'S HANDLE ON IT, set before the first line that can `die`. And the
  # pid goes to a FILE as well, because the unit is a subshell: a row in the
  # run that has to establish "no daemon survived" cannot otherwise name the
  # process it is talking about.
  UNIT_DAEMON_PID="$daemon_pid"
  printf '%s\n' "$daemon_pid" > "$outdir/$prefix.daemon.pid"

  ready=0
  attempt=0
  while [ "$attempt" -lt "$MOUNT_READY_TICKS" ]; do
    sleep 0.1
    attempt=$((attempt + 1))
    if ! pid_is_alive "$daemon_pid"; then
      cat "$stderr_file" >&2
      die "$role: the mount daemon exited before the mount became ready"
    fi
    if mountpoint -q "$mnt" 2>/dev/null; then
      ready=1
      break
    fi
  done
  if [ "$ready" -ne 1 ]; then
    cat "$stderr_file" >&2
    die "$role: the mount did not become ready within $((MOUNT_READY_TICKS / 10)) s"
  fi

  if [ -n "$walk_rel" ]; then
    walk_dir="$mnt/$walk_rel"
  else
    walk_dir="$mnt"
  fi
  line="$(subtree_digest "$walk_dir" "$role observed")"
  printf '%s\n' "$line" > "$outdir/$prefix.digest"

  set +e
  "$RUN_GRAN" umount "$mnt" > "$outdir/$prefix.umount.out" 2> "$outdir/$prefix.umount.err"
  umount_rc=$?
  set -e
  wait_for_death "$daemon_pid" "$MOUNT_UMOUNT_TICKS" \
    || die "$role: the mount daemon pid $daemon_pid survived $((MOUNT_UMOUNT_TICKS / 10)) s after gran umount (umount rc=$umount_rc)"
  set +e
  wait "$daemon_pid"
  rc=$?
  set -e
  printf '%s\n' "$rc" > "$outdir/$prefix.rc"
  UNIT_MNT=""
  # Reaped above; clearing it stops the EXIT trap chasing a pid this unit has
  # already waited on.
  UNIT_DAEMON_PID=""

  # THE THREE FLOORS, in the order that names the real cause first. A mount
  # exits 0 for clean and 3 for "unmounted, but the cache could not be closed
  # cleanly" (`granary-cli`'s `attach::MOUNT_HELP`); this harness requires 0 and not 3.
  assert_no_snapshot_refusal "$stderr_file" "$role"
  assert_exit_code "$rc" 0 "$role (gran mount)"
  assert_snapshot_present "$snapshot" "$role"
  assert_exit_code "$umount_rc" 0 "$role (gran umount)"
}

# Spawn one unit. The MOUNTPOINT IS REGISTERED BY THE PARENT, before the child
# exists: the child is a subshell, so anything it records about itself is
# discarded on the way out, and the exit trap that has to detach the mount
# runs in the parent.
#
# THE PID COMES BACK IN A GLOBAL, NOT ON STDOUT, and that is not a style
# choice. A caller writing `pid="$(spawn_mount_walk ...)"` runs this whole
# function inside a COMMAND SUBSTITUTION — itself a subshell — so the mount
# registration above would be discarded, and the background job would be a
# child of that subshell rather than of the run. The run's `wait` would then
# refuse the pid as "not a child of this shell" and the unit would be orphaned
# to init with its mount still attached. This shape makes the mistake
# unavailable.
SPAWNED_PID=""
spawn_mount_walk() {
  local mnt="$3"
  RUN_MOUNTPOINTS="$RUN_MOUNTPOINTS$mnt"$'\n'
  ( mount_walk_unit "$@" ) &
  SPAWNED_PID=$!
}

join_units() {
  local label="$1"
  shift
  local pid rc failed=0
  for pid in "$@"; do
    set +e
    wait "$pid"
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
      note "$label: a measured process (pid $pid) failed with rc=$rc"
      failed=1
    fi
  done
  [ "$failed" -eq 0 ] || die "$label: at least one measured process failed; the run is refused"
}

require_run_tools() {
  # THE WALKER'S LIST IS INCLUDED BY CALLING IT, never by being copied here.
  # Every digest the run takes comes from `subtree_digest`, so the run needs
  # `sha256sum`, GNU `find`, `xargs`, `sort`, `tr` and `wc` exactly as the
  # walker does — and a list that repeated those names would be a second list
  # to keep in step. This check omitted `sha256sum`; the
  # `propagation_run` caller already called `require_tools` immediately
  # before it, masking the omission. Calling only this function must also
  # check the walker's requirements, so it calls `require_tools` itself.
  require_tools
  local tool
  for tool in awk cmp cp date env fusermount3 id kill ln ls mkdir mountpoint mv od python3 sed seq sleep uname; do
    command -v "$tool" > /dev/null 2>&1 \
      || die "required tool is missing (the run needs it): $tool"
  done
}

# ------------------------------------------------------ THE TWO CLOCKS
#
# Both measure from ONE t0 — the moment the publisher process exited — and
# both stop on ONE predicate: the SENTINEL'S CONTENT HASH equal to the
# `v_(n+1)` value the delta computed on the publisher's SOURCE tree before the
# publish. Neither stops on "the read succeeded", and that is the whole design:
# a client serving the OLD content returns bytes, exits 0 and would give a
# small, wrong number to a clock whose predicate was success.
#
# THE CLOCKS RUN CONCURRENTLY WITH THE BYTE WORKLOADS, and that is forced
# rather than chosen. Both are stopwatches started at the publisher's exit; run
# after the workloads they would measure the workloads' duration and report a
# propagation latency of tens of seconds that has nothing to do with
# propagation. The poll's byte cost
# IS the load the instrument puts on the server DURING the byte phase.
#
# THEY CANNOT INFLATE THE PUBLISHER FLOORS. Every client read carries an EMPTY
# request body (`http_store.rs:818`, `:845`, `:1325`); only the publisher's PUT
# carries one (`:802`). So `server.request_bytes` and `requests_with_body` —
# the two numbers that bound the publisher's upload — are untouched by anything
# either clock does. The server's response-side counter is demoted and is never
# excluded from the three-times-novel upload/download bounds; its one use (E7's cross-crate bound) bounds in the
# direction the clocks move it, which is why that row states its direction.

# The harness's own millisecond clock, validated the way `timeline_mark`
# validates its stamp. A clock that reports a duration derived from an
# unparsed string is a number with no units.
now_ms() {
  local out
  out="$(date -u +%s%3N)" \
    || die "the harness clock could not produce a millisecond stamp"
  case "$out" in
    ''|*[!0-9]*) die "the harness clock produced a non-numeric millisecond stamp: [$out]" ;;
  esac
  [ "${#out}" -le 16 ] \
    || die "the harness clock produced a ${#out}-digit millisecond stamp; the harness will not do arithmetic on it"
  printf '%s' "$out"
}

# `sha256sum` over ONE file, with every way it could not be a digest refused.
# The two clocks compare this against a value computed by a different process
# on a different tree, so a truncated, empty or error-shaped answer must stop
# the run rather than become a mismatch that reads as "the content is stale".
sha256_of_file() {
  local path="$1" label="$2" line digest rc
  [ -e "$path" ] || die "$label: no file at $path to hash"
  [ -f "$path" ] || die "$label: $path is not a regular file"
  set +e
  line="$(sha256sum "$path" 2>/dev/null)"
  rc=$?
  set -e
  [ "$rc" -eq 0 ] && [ -n "$line" ] \
    || die "$label: sha256sum failed over $path (rc=$rc)"
  digest="${line%% *}"
  case "$digest" in
    ''|*[!0-9a-f]*) die "$label: sha256sum produced a non-hex digest over $path: [$digest]" ;;
  esac
  [ "${#digest}" -eq 64 ] \
    || die "$label: sha256sum produced a ${#digest}-character digest over $path, want 64"
  printf '%s' "$digest"
}

# ONE mount, ONE sentinel read, ONE unmount — the body both clock B and the
# reused-cache-dir demonstration share, so the two cannot drift apart in what
# "reading the sentinel through a mount" means.
#
# NO `--seq`. Clock B measures DISCOVERY: pinning the seq would hand the client
# the answer the clock exists to time. The BYTE WORKLOAD pins
# to measure bytes for the changed subtree,
# a different quantity from discovery latency.
#
# NO `--wire-snapshot`: the eleven roles are all spoken for and a clock is not
# one of them.
#
# Sets MOUNT_READ_HASH (the sentinel's content hash as this mount served it)
# and MOUNT_READ_MS (the millisecond the read completed, taken BEFORE the
# unmount — the clock stops when the content is in hand, not when the
# filesystem has been taken down).
MOUNT_READ_HASH=""
MOUNT_READ_MS=""
mount_read_sentinel() {
  local mnt="$1" cache="$2" sentinel="$3" outdir="$4" prefix="$5" label="$6"
  local daemon_pid ready attempt rc umount_rc

  [ "${BASHPID:-$$}" != "$$" ] \
    || die "$label: mount_read_sentinel must run in a subshell; in the main shell its mount would outlive the failure that abandoned it"
  [ -d "$mnt" ] || die "$label: the mountpoint is not a directory: $mnt"
  [ ! -e "$cache" ] || [ -d "$cache" ] \
    || die "$label: the cache path exists and is not a directory: $cache"
  mkdir -p "$cache" || die "$label: could not create the cache directory $cache"

  UNIT_MNT="$mnt"
  "$RUN_GRAN" mount "$RUN_VOLUME" "$mnt" \
    --endpoint "$MEASURED_ENDPOINT" --pin "$RUN_PIN" --root-key "$RUN_ROOT_KEY" \
    --cache-dir "$cache" --foreground \
    > "$outdir/$prefix.mount.out" 2> "$outdir/$prefix.mount.err" &
  daemon_pid=$!
  UNIT_DAEMON_PID="$daemon_pid"

  ready=0
  attempt=0
  while [ "$attempt" -lt "$MOUNT_READY_TICKS" ]; do
    sleep 0.1
    attempt=$((attempt + 1))
    if ! pid_is_alive "$daemon_pid"; then
      cat "$outdir/$prefix.mount.err" >&2
      die "$label: the mount daemon exited before the mount became ready"
    fi
    if mountpoint -q "$mnt" 2>/dev/null; then
      ready=1
      break
    fi
  done
  if [ "$ready" -ne 1 ]; then
    cat "$outdir/$prefix.mount.err" >&2
    die "$label: the mount did not become ready within $((MOUNT_READY_TICKS / 10)) s"
  fi

  # THE ORDER OF THESE TWO LINES DEFINES THE
  # CLOCK'S ENDPOINT. Clock B measures until the
  # sentinel content has been read through the
  # mount. `sha256_of_file` completes before
  # `now_ms` records the time. Taking the timestamp
  # before the read would instead stop at the
  # point where the mount is ready for that read,
  # excluding the read itself. A positive duration
  # alone does not establish which ordering
  # produced it. The timestamp and the content
  # hash therefore have distinct roles: the
  # hash identifies the bytes obtained, while
  # the following timestamp records when that
  # operation has completed. Preserve that
  # sequence when changing this block; a duration
  # check cannot substitute for reading the
  # content before recording the endpoint.
  MOUNT_READ_HASH="$(sha256_of_file "$mnt/$sentinel" "$label (the sentinel through the mount)")"
  MOUNT_READ_MS="$(now_ms)"

  set +e
  "$RUN_GRAN" umount "$mnt" > "$outdir/$prefix.umount.out" 2> "$outdir/$prefix.umount.err"
  umount_rc=$?
  set -e
  wait_for_death "$daemon_pid" "$MOUNT_UMOUNT_TICKS" \
    || die "$label: the mount daemon pid $daemon_pid survived $((MOUNT_UMOUNT_TICKS / 10)) s after gran umount (umount rc=$umount_rc)"
  set +e
  wait "$daemon_pid"
  rc=$?
  set -e
  UNIT_MNT=""
  UNIT_DAEMON_PID=""
  # A mount exits 0 for clean and 3 for "unmounted, but the cache could not be
  # closed cleanly" (`granary-cli`'s `attach::MOUNT_HELP`). A clock reading a number
  # off a mount that could not close its own cache is reading a number about an
  # unknown state, so 3 is refused here exactly as `mount_walk_unit` refuses it for the
  # measured mounts.
  assert_exit_code "$rc" 0 "$label (gran mount)"
  assert_exit_code "$umount_rc" 0 "$label (gran umount)"
}

# ------------------------------------------------------------------ CLOCK A
#
# A CACHELESS `gran cat` (its `--cache-dir` is OPTIONAL — absent is the
# cacheless form, `granary-cli`'s `CAT_HELP`), polled at 1 s from the
# publisher's exit until the sentinel's bytes hash to the `v_(n+1)` value.
#
# CACHELESS IS LOAD-BEARING, not a simplification. With `--root-key` and a
# cache holding a resolvable head, `gran cat` is DESIGNED to be served the
# cached tree rather than fail — so a clock with a cache-dir could stop on
# content that never crossed the wire, which is the same green vacuum the
# content-identity predicate exists to refuse, arriving through the other door.
#
# EACH POLL WRITES A WIRE SNAPSHOT, despite the initial requirement
# that clock processes write none.
# The reason for that requirement was the fixed role vocabulary:
# `ROLE_VOCABULARY` holds eleven names and none is spare. The
# artifact must also carry `clock_a_poll_bytes`, a MEASURED byte
# cost, for which the client's own frame-level counter is the only
# instrument in existence — the reported "202,988 bytes to read a
# 10,419-byte file" was taken with it. The two requirements cannot both be met
# literally, so the fixed role vocabulary is preserved as follows:
#   * NO TWELFTH ROLE IS INVENTED. The poll reuses `client-<k>`, which the
#     writer accepts, under a DIFFERENT run id (`<run id>-clock`) — exactly the
#     convention this harness already uses for its negative rows.
#   * THE ELEVEN ARE UNTOUCHED. Poll snapshots are written under the run's
#     `clocks/` directory and never under `$H`, which E11 asserts holds exactly
#     eleven entries and nothing else, and which the assembler reads by eleven
#     fixed names.
#   * THE CLOCKS ENTER NO MEASURED TOTAL. `clock_a_poll_bytes` is recorded as
#     what it is — the load the instrument put on the server — and contributes
#     to neither clock latency nor the three-times-novel upload/download bounds.
# The alternative was to multiply a poll count by a constant measured
# elsewhere and record the product as though it had been measured, which is the
# same substitution of a prediction for a measurement.
clock_a_unit() {
  local client="$1" sentinel="$2" want="$3" t0_ms="$4" cap="$5"
  local outdir="$6" prefix="$7" snapdir="$8" run_id="$9"
  local polls=0 bytes=0 rc got now deadline snap out err poll_bytes label

  [ "${BASHPID:-$$}" != "$$" ] \
    || die "clock A must run in a subshell; the run spawns it beside the byte workloads"
  case "$t0_ms" in ''|*[!0-9]*) die "clock A (client $client): t0 is not a millisecond stamp: [$t0_ms]" ;; esac
  [ "${#want}" -eq 64 ] || die "clock A (client $client): the expected sentinel hash is not 64 hex: [$want]"
  mkdir -p "$snapdir" || die "clock A (client $client): could not create $snapdir"
  deadline=$((t0_ms + cap * 1000))

  while :; do
    polls=$((polls + 1))
    label="clock A (client $client, poll $polls)"
    snap="$snapdir/$prefix-poll-$polls.json"
    out="$outdir/$prefix-poll-$polls.out"
    err="$outdir/$prefix-poll-$polls.err"
    set +e
    "$RUN_GRAN" cat "$RUN_VOLUME" "$sentinel" \
      --endpoint "$MEASURED_ENDPOINT" --pin "$RUN_PIN" --root-key "$RUN_ROOT_KEY" \
      --wire-snapshot "$snap" --wire-run-id "$run_id" --wire-role "client-$client" \
      > "$out" 2> "$err"
    rc=$?
    set -e
    # A poll that FAILED is not "the content has not arrived yet": a cacheless
    # read against a healthy server succeeds and returns the OLD bytes until
    # the new ones are there. Treating a failure as a not-yet would let a
    # misrouted or refused clock spin its whole cap and then report a
    # timeout, which reads as slow propagation.
    assert_no_snapshot_refusal "$err" "$label"
    assert_exit_code "$rc" 0 "$label (gran cat $sentinel)"
    assert_snapshot_present "$snap" "$label"
    poll_bytes=""
    poll_bytes="$(snapshot_u64 "$snap" "response_bytes" "$label")" \
      || die "$label: could not read the poll's own response_bytes"
    bytes=$((bytes + poll_bytes))
    got="$(sha256_of_file "$out" "$label")"
    now="$(now_ms)"
    if [ "$got" = "$want" ]; then
      printf '%s\t%s\t%s\t%s\n' \
        "$(awk -v a="$now" -v b="$t0_ms" 'BEGIN { printf "%.3f", (a - b) / 1000 }')" \
        "$polls" "$bytes" 0 > "$outdir/$prefix.result"
      return 0
    fi
    if [ "$now" -ge "$deadline" ]; then
      printf '%s\t%s\t%s\t%s\n' \
        "$(awk -v a="$now" -v b="$t0_ms" 'BEGIN { printf "%.3f", (a - b) / 1000 }')" \
        "$polls" "$bytes" 1 > "$outdir/$prefix.result"
      note "clock A (client $client): after $polls polls and ${cap}s the sentinel $sentinel still hashes to $got; the expected v_(n+1) sentinel is $want"
      return 1
    fi
    sleep "$CLOCK_A_POLL_SECONDS"
  done
}

# ------------------------------------------------------------------ CLOCK B
#
# A FRESH `gran mount` per attempt, and A NEW CACHE DIRECTORY PER MOUNT. The
# cached-head hazard described above for `gran cat` applies here too:
# `gran mount` REQUIRES `--cache-dir`, its open path is hint-first, and the
# persisted hint is blind for `[48 s, 72 s)` (`head.rs:106-107`). A harness
# that reused one cache-dir between rounds would false-fail clock B — or
# false-PASS it, if the predicate were ever weakened from content identity to
# "the mount attached". The row that demonstrates this is `reused_cache_dir`.
clock_b_unit() {
  local client="$1" sentinel="$2" want="$3" t0_ms="$4" cap="$5"
  local mnt="$6" cachebase="$7" outdir="$8" prefix="$9"
  local attempts=0 now deadline cache

  [ "${BASHPID:-$$}" != "$$" ] \
    || die "clock B must run in a subshell; it installs its own EXIT trap and a trap in the main shell would replace the run's own cleanup"
  case "$t0_ms" in ''|*[!0-9]*) die "clock B (client $client): t0 is not a millisecond stamp: [$t0_ms]" ;; esac
  [ "${#want}" -eq 64 ] || die "clock B (client $client): the expected sentinel hash is not 64 hex: [$want]"
  trap unit_detach EXIT
  deadline=$((t0_ms + cap * 1000))

  while :; do
    attempts=$((attempts + 1))
    cache="$cachebase-$attempts"
    [ ! -e "$cache" ] \
      || die "clock B (client $client): the cache directory $cache already exists; each clock-B mount gets a NEW one and reusing one is the trap this instrument is built around"
    mount_read_sentinel "$mnt" "$cache" "$sentinel" "$outdir" "$prefix-$attempts" \
      "clock B (client $client, attempt $attempts)"
    now="$MOUNT_READ_MS"
    # The cache-dir of the LAST attempt and the moment it finished, so the
    # reused-cache-dir row can name the directory whose hint it is about and
    # MEASURE how old that hint is instead of assuming.
    printf '%s\n' "$cache" > "$outdir/$prefix.lastcache"
    printf '%s\n' "$now" > "$outdir/$prefix.lastcache.ms"
    if [ "$MOUNT_READ_HASH" = "$want" ]; then
      printf '%s\t%s\t%s\n' \
        "$(awk -v a="$now" -v b="$t0_ms" 'BEGIN { printf "%.3f", (a - b) / 1000 }')" \
        "$attempts" 0 > "$outdir/$prefix.result"
      return 0
    fi
    if [ "$now" -ge "$deadline" ]; then
      printf '%s\t%s\t%s\n' \
        "$(awk -v a="$now" -v b="$t0_ms" 'BEGIN { printf "%.3f", (a - b) / 1000 }')" \
        "$attempts" 1 > "$outdir/$prefix.result"
      note "clock B (client $client): after $attempts fresh mounts and ${cap}s the sentinel $sentinel still hashes to $MOUNT_READ_HASH; the expected v_(n+1) sentinel is $want"
      return 1
    fi
    sleep "$CLOCK_A_POLL_SECONDS"
  done
}

# ONE mount on a cache-dir the caller names — the reused-cache-dir
# demonstration's body. It reports what it saw and judges nothing; the row
# that spawned it owns the verdict.
sentinel_probe_unit() {
  local mnt="$1" cache="$2" sentinel="$3" outdir="$4" prefix="$5"
  [ "${BASHPID:-$$}" != "$$" ] \
    || die "the sentinel probe must run in a subshell"
  trap unit_detach EXIT
  mount_read_sentinel "$mnt" "$cache" "$sentinel" "$outdir" "$prefix" "sentinel probe ($prefix)"
  printf '%s\n' "$MOUNT_READ_HASH" > "$outdir/$prefix.hash"
  printf '%s\n' "$MOUNT_READ_MS" > "$outdir/$prefix.ms"
}

# The three spawners. Each REGISTERS ITS MOUNTPOINT IN THE PARENT before the
# child exists, for the reason `spawn_mount_walk` gives: the child is a
# subshell and anything it records about itself is discarded on the way out,
# while the exit trap that has to detach the mount runs in the parent.
spawn_clock_a() {
  ( clock_a_unit "$@" ) &
  SPAWNED_PID=$!
}

spawn_clock_b() {
  local mnt="$6"
  RUN_MOUNTPOINTS="$RUN_MOUNTPOINTS$mnt"$'\n'
  ( clock_b_unit "$@" ) &
  SPAWNED_PID=$!
}

spawn_sentinel_probe() {
  local mnt="$1"
  RUN_MOUNTPOINTS="$RUN_MOUNTPOINTS$mnt"$'\n'
  ( sentinel_probe_unit "$@" ) &
  SPAWNED_PID=$!
}

# `wait` for ONE pid and KEEP its status instead of dying on it. `join_units`
# is right for a measured process, whose failure is a failure of the run; a
# clock's and a NEGATIVE row's status is the row's own evidence and something
# has to read it.
#
# THE STATUS COMES BACK IN A GLOBAL, NOT
# ON STDOUT. Command substitution runs in
# a subshell, which cannot wait for its
# parent's children. A substitution also
# discards the status assignment when that
# subshell exits, leaving the caller's
# previous value untouched. `wait_into_rc`
# must run in the shell that spawned the
# pid; it stores the wait status in
# WAITED_RC for the caller to read there.
# The subshell check refuses before the
# wait so a command substitution cannot
# silently turn a failed wait into
# evidence about a still-running process.
#
# A STATUS-VALUE CHECK CANNOT DETECT THE SUBSHELL
# CALL. `wait` assigns a numeric status even when
# it cannot wait for the pid. Inside a command
# substitution, the assignment disappears with
# the subshell while the parent retains its
# previous value. Check the execution context
# before waiting: `BASH_SUBSHELL` counts subshell
# nesting, including command substitution, and
# `wait_into_rc` refuses a nonzero value. Row
# N7 exercises the subshell refusal and uses
# a main-shell call as its positive control.
WAITED_RC=""
wait_into_rc() {
  local pid="$1"
  [ -n "$pid" ] || die "wait_into_rc was given no pid"
  [ "${BASH_SUBSHELL:-0}" -eq 0 ] \
    || die "wait_into_rc was called from a SUBSHELL (BASH_SUBSHELL=${BASH_SUBSHELL:-0}), which is what a command substitution is. bash answers -1 WITHOUT WAITING when \`wait\` is called from a subshell for a pid the subshell did not spawn, and the status this function assigns would die with the subshell while the caller read a stale value. Call it in the shell that spawned the pid and read \$WAITED_RC there."
  set +e
  wait "$pid"
  WAITED_RC=$?
  set -e
}

# One tab-separated field of a clock's result line, refusing every way it could
# be absent. A clock that produced no result file is a clock that did not run,
# and an empty field reaching the artifact as a duration is a number with no
# event behind it.
clock_result_field() {
  local file="$1" index="$2" label="$3" value
  [ -f "$file" ] || die "$label: no clock result at $file; the clock did not run"
  value="$(awk -F '\t' -v i="$index" 'NR == 1 { print $i }' "$file")"
  [ -n "$value" ] || die "$label: field $index of $file is empty"
  printf '%s' "$value"
}

# ------------------------------------------------- THE ARTIFACT ASSEMBLER
#
# ONE JSON object, in the artifact schema, assembled LAST from records
# this run already wrote: the eleven snapshots VERBATIM, the timeline, the
# corpus record, the two clocks per client, the per-client observations and the
# harness observations. It carries NO VERDICT, NO RATIO and NO TOTAL THE VERB
# COULD COMPUTE — `corpus.apparent_bytes_v_n` is an input and the ratio is
# the verb's output — and the six RESERVED keys are refused wherever they
# appear, so the shell cannot hand Rust a conclusion to seal.
#
# IT IS PYTHON, and for the same reason `snapshot_field` is: a shell assembler
# would have to quote JSON by hand, and a mis-escaped byte in a digest or a
# path is a document that parses into something other than what was measured.
#
# IT VALIDATES WHAT IT EMITS. Every check below is a REFUSAL of the run, not a
# warning: an artifact that reaches the verb malformed costs a whole re-run,
# and the whole point of assembling last is that the harness knows here what it
# will never know again.
ARTIFACT_PY="$(cat <<'PY'
import json
import math
import os
import re
import sys
from datetime import datetime, timezone

(run_dir, snap_dir, out_path, samples_path, venue_node, venue_guest,
 arch, kernel, os_name, git_sha, artifact_version, sample_period,
 max_gap) = sys.argv[1:14]

artifact_version = int(artifact_version)
sample_period = int(sample_period)
max_gap = float(max_gap)

STAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")

# The six RESERVED keys, refused wherever they appear — including inside a
# snapshot, which is why the scan is recursive. None of the eleven writers
# emits any of them (`granary-client/src/wire_snapshot.rs`,
# `granary-server/src/wire_snapshot.rs`), so this cannot fire on an honest run.
RESERVED = ("p1_verdict", "p2_verdict", "digest", "run_artifact_digest",
            "metadata", "controls")

TOP_KEYS = ["artifact_version", "run_id", "harness", "venue", "node_cpu_samples",
            "corpus", "timeline", "clocks", "snapshots", "observations",
            "per_client"]

SNAPSHOT_NAMES = ["server", "publisher", "client-1", "client-2", "client-3",
                  "warmup-1", "warmup-2", "warmup-3",
                  "warmup-verify-1", "warmup-verify-2", "warmup-verify-3"]

TIMELINE_KEYS = ["warmups_ended", "delta_generated", "publish_started",
                 "publish_ended", "workloads_started", "workloads_ended",
                 "server_stopped"]

# The required MINIMUM, not a ceiling: further observations are permitted and
# every one of them carries the label, so a harness cannot smuggle in an
# unlabelled claim by inventing a name.
REQUIRED_OBSERVATIONS = [
    "no_publish", "stale_content", "wrong_server", "no_snapshot",
    "empty_run_id", "three_processes", "server_killed_before_snapshot",
    "expected_digests_computed_before_publish", "warmup_cache_dirs_were_empty",
    "no_cache_client_fails_p2",
]


def refuse(message):
    sys.stderr.write("REFUSED: %s\n" % message)
    raise SystemExit(9)


def read_tsv_rows(path, want_fields, label):
    if not os.path.isfile(path):
        refuse("%s is missing at %s" % (label, path))
    rows = []
    with open(path, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            line = line.rstrip("\n")
            if line == "":
                refuse("%s line %d is blank" % (label, number))
            fields = line.split("\t")
            if len(fields) != want_fields:
                refuse("%s line %d has %d tab-separated fields, want %d: %r"
                       % (label, number, len(fields), want_fields, line))
            rows.append(fields)
    if not rows:
        refuse("%s at %s is empty" % (label, path))
    return rows


def stamp_to_epoch(text, label):
    if not STAMP.match(text):
        refuse("%s is not a YYYY-MM-DDTHH:MM:SS.mmmZ stamp: %r" % (label, text))
    parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ")
    return parsed.replace(tzinfo=timezone.utc).timestamp()


def as_int(text, label, minimum=0):
    if not re.match(r"^(0|[1-9][0-9]*)$", text):
        refuse("%s is not a non-negative decimal integer: %r" % (label, text))
    value = int(text)
    if value < minimum:
        refuse("%s is %d, below %d" % (label, value, minimum))
    return value


def as_float(text, label, minimum=None, maximum=None):
    try:
        value = float(text)
    except ValueError:
        refuse("%s is not a number: %r" % (label, text))
    if not math.isfinite(value):
        refuse("%s is not finite: %r" % (label, text))
    if minimum is not None and value < minimum:
        refuse("%s is %r, below %r" % (label, value, minimum))
    if maximum is not None and value > maximum:
        refuse("%s is %r, above %r" % (label, value, maximum))
    return value


def as_hex64(text, label):
    if not HEX64.match(text):
        refuse("%s is not a 64-character lowercase hex digest: %r" % (label, text))
    return text


# ---------------------------------------------------------------- corpus
corpus_rows = read_tsv_rows(os.path.join(run_dir, "corpus.tsv"), 2, "corpus.tsv")
corpus_raw = {}
for key, value in corpus_rows:
    if key in corpus_raw:
        refuse("corpus.tsv names %s twice" % key)
    corpus_raw[key] = value
for key in ("run_id", "apparent_bytes_v_n", "changed_subtree",
            "changed_subtree_bytes", "expected_v_n_tree_digest",
            "expected_v_n1_subtree_digest", "walker"):
    if key not in corpus_raw:
        refuse("corpus.tsv has no %s" % key)

run_id = corpus_raw["run_id"]
if run_id == "":
    refuse("the run id is empty; eleven files stamped from an unset variable "
           "satisfy equality just as well as eleven stamped from a real one")

corpus = {
    "apparent_bytes_v_n": as_int(corpus_raw["apparent_bytes_v_n"],
                                 "corpus.apparent_bytes_v_n"),
    "changed_subtree": corpus_raw["changed_subtree"],
    "changed_subtree_bytes": as_int(corpus_raw["changed_subtree_bytes"],
                                    "corpus.changed_subtree_bytes"),
    "expected_v_n_tree_digest": as_hex64(corpus_raw["expected_v_n_tree_digest"],
                                         "corpus.expected_v_n_tree_digest"),
    "expected_v_n1_subtree_digest": as_hex64(
        corpus_raw["expected_v_n1_subtree_digest"],
        "corpus.expected_v_n1_subtree_digest"),
    "walker": corpus_raw["walker"],
}
if corpus["changed_subtree"] == "" or corpus["walker"] == "":
    refuse("corpus.changed_subtree and corpus.walker must be non-empty")

# -------------------------------------------------------------- timeline
timeline_rows = read_tsv_rows(os.path.join(run_dir, "timeline.tsv"), 2,
                              "timeline.tsv")
timeline_raw = {}
for key, value in timeline_rows:
    if key in timeline_raw:
        refuse("timeline.tsv names %s twice" % key)
    timeline_raw[key] = value
extra = sorted(set(timeline_raw) - set(TIMELINE_KEYS))
if extra:
    refuse("timeline.tsv carries stamps the schema does not list: %s"
           % ", ".join(extra))
timeline = {}
previous_name = None
previous_epoch = None
for key in TIMELINE_KEYS:
    if key not in timeline_raw:
        refuse("timeline.tsv has no %s" % key)
    epoch = stamp_to_epoch(timeline_raw[key], "timeline.%s" % key)
    # Require strictly increasing timestamps in
    # timeline order. Equal timestamps cannot
    # establish that the second event follows the
    # first, even if both parse successfully.
    # Compare each parsed epoch with the preceding
    # one and refuse both equality and reversal.
    # This checks the event chain; inclusive
    # comparisons used for phase membership answer
    # a different question and cannot replace it.
    if previous_epoch is not None and epoch <= previous_epoch:
        refuse("the timeline is not strictly increasing: %s (%s) does not follow %s (%s)"
               % (key, timeline_raw[key], previous_name,
                  timeline_raw[previous_name]))
    previous_name, previous_epoch = key, epoch
    timeline[key] = timeline_raw[key]

window_start = stamp_to_epoch(timeline[TIMELINE_KEYS[0]], "the run window's start")
window_end = stamp_to_epoch(timeline[TIMELINE_KEYS[-1]], "the run window's end")
duration = window_end - window_start
if duration < 0:
    refuse("the run window is negative: %r to %r"
           % (timeline[TIMELINE_KEYS[0]], timeline[TIMELINE_KEYS[-1]]))

# --------------------------------------------------- the node CPU samples
#
# THE ARTIFACT CARRIES THE LIST AND NOTHING DERIVED FROM IT. The verb computes
# the mean and the maximum, over the samples INSIDE the run window only —
# which is why the timestamped list travels and a mean does not. Padding
# outside the window is the normal case (a sampler started early and stopped
# late) and it must not dilute a statistic; an honest sampler left running for
# hours around a short run is enough to pull a 60 % mean under 40 %.
if not os.path.isfile(samples_path):
    refuse("the node-CPU samples file is missing at %s. A missing measurement "
           "of the measurement is not a pass" % samples_path)
samples = []
with open(samples_path, "r", encoding="utf-8") as handle:
    for number, line in enumerate(handle, 1):
        line = line.rstrip("\n")
        if line == "":
            continue
        fields = line.split("\t")
        if len(fields) != 2:
            refuse("the node-CPU samples file line %d is not '<UTC stamp>\\t<percent>': %r"
                   % (number, line))
        epoch = stamp_to_epoch(fields[0], "node-CPU sample %d's timestamp" % number)
        percent = as_float(fields[1], "node-CPU sample %d's percentage" % number,
                           minimum=0.0, maximum=100.0)
        samples.append((epoch, fields[0], percent))
if not samples:
    refuse("the node-CPU samples file at %s holds no samples" % samples_path)
for index in range(1, len(samples)):
    if samples[index][0] <= samples[index - 1][0]:
        refuse("the node-CPU samples are not strictly increasing: %s follows %s"
               % (samples[index][1], samples[index - 1][1]))
if samples[0][0] >= window_start:
    refuse("the first node-CPU sample (%s) does not precede the run's first "
           "timeline stamp (%s); the run is not covered"
           % (samples[0][1], timeline[TIMELINE_KEYS[0]]))
if samples[-1][0] <= window_end:
    refuse("the last node-CPU sample (%s) does not follow the run's last "
           "timeline stamp (%s); the run is not covered"
           % (samples[-1][1], timeline[TIMELINE_KEYS[-1]]))

in_window = [s for s in samples if window_start <= s[0] <= window_end]
want = int(duration // sample_period)
if len(in_window) < want:
    refuse("the node-CPU samples hold %d readings inside the run window and "
           "the window is %.3f s, so at least %d are required"
           % (len(in_window), duration, want))

# THE SPACING IS CHECKED OVER THE COVERING SET — every sample from the last one
# at or before the window's start through the first one at or after its end.
# Consecutive pairs INSIDE the window alone would leave the two boundary
# crossings unchecked, and clustering at the boundaries is exactly the shape
# this bound exists to catch.
lower = max(i for i, s in enumerate(samples) if s[0] <= window_start)
upper = min(i for i, s in enumerate(samples) if s[0] >= window_end)
for index in range(lower + 1, upper + 1):
    gap = samples[index][0] - samples[index - 1][0]
    if gap > max_gap:
        refuse("the node-CPU samples leave a %.3f s gap between %s and %s, "
               "above the %.3f s bound; samples CLUSTERED at the two "
               "boundaries satisfy first, last and count while the middle of "
               "the run — where a competing workload would show — is unsampled"
               % (gap, samples[index - 1][1], samples[index][1], max_gap))

node_cpu_samples = [{"t": s[1], "cpu": s[2]} for s in samples]

# ---------------------------------------------------------------- clocks
clock_rows = read_tsv_rows(os.path.join(run_dir, "clocks.tsv"), 5, "clocks.tsv")
if len(clock_rows) != 3:
    refuse("clocks.tsv holds %d rows, want 3 (one per client)" % len(clock_rows))
clocks = []
for index, fields in enumerate(clock_rows, 1):
    client = as_int(fields[0], "clocks.tsv row %d's client" % index, minimum=1)
    if client != index:
        refuse("clocks.tsv row %d names client %d" % (index, client))
    clocks.append({
        "client": client,
        # MINIMUM 0.001, not 0.0. `as_float`'s bound is `value < minimum`,
        # so `minimum=0.0` let a literal `0.0` seconds through — and
        # the verb (`wallclock::CLOCK_SECONDS_FLOOR`) renders this field
        # at THREE decimal digits, so anything below one whole render
        # unit prints as `0.000 s`, the exact line the floor exists to
        # refuse, indistinguishable from a poll that never happened. Same
        # bound, both implementations, so a run cannot pass here and be
        # refused there or vice versa.
        "clock_a_seconds": as_float(fields[1], "clock_a_seconds (client %d)" % client,
                                    minimum=0.001),
        "clock_a_polls": as_int(fields[2], "clock_a_polls (client %d)" % client,
                                minimum=1),
        # MINIMUM ONE, not zero. A CACHELESS `gran cat` cannot cost zero
        # bytes — it has no cache to be served from — so a zero here is a
        # counter that was never accumulated rather than a poll that was
        # free, and a mutation that stopped accumulating it
        # left a `0` in the artifact that nothing questioned.
        "clock_a_poll_bytes": as_int(fields[3],
                                     "clock_a_poll_bytes (client %d)" % client,
                                     minimum=1),
        # MINIMUM 0.001, for the identical reason `clock_a_seconds` above
        # carries one: the verb floors both fields at the same
        # `CLOCK_SECONDS_FLOOR`, and `minimum=0.0` here would accept a
        # `clock_b_seconds` the other implementation refuses.
        "clock_b_seconds": as_float(fields[4], "clock_b_seconds (client %d)" % client,
                                    minimum=0.001),
    })

# ------------------------------------------------------------- snapshots
#
# ELEVEN, VERBATIM as their writers emitted them. The directory is counted as
# well as read by name: a `for name in ...` loop reports what its list says and
# is blind both to a twelfth file and — without this — to one that has been
# removed after the run wrote it.
if not os.path.isdir(snap_dir):
    refuse("the snapshot directory is missing at %s" % snap_dir)
present = sorted(os.listdir(snap_dir))
if len(present) != 11:
    refuse("the snapshot directory %s holds %d entries, want exactly 11: %s"
           % (snap_dir, len(present), ", ".join(present)))
snapshots = {}
for name in SNAPSHOT_NAMES:
    path = os.path.join(snap_dir, "%s.json" % name)
    if not os.path.isfile(path):
        refuse("NO SNAPSHOT FILE for role %s at %s; the artifact requires all "
               "eleven and exit code 0 does not establish that one was written"
               % (name, path))
    try:
        with open(path, "rb") as handle:
            document = json.load(handle)
    except Exception as error:  # noqa: BLE001 - any failure to read is a refusal
        refuse("%s is not readable JSON: %s" % (path, error))
    if not isinstance(document, dict):
        refuse("%s is not a JSON object" % path)
    if document.get("run_id") != run_id:
        refuse("%s carries run_id %r and the run's id is %r"
               % (path, document.get("run_id"), run_id))
    if document.get("role") != name:
        refuse("%s carries role %r, want %r" % (path, document.get("role"), name))
    snapshots[name] = document

# ----------------------------------------------------------- observations
#
# EVERY entry carries `"kind": "observation"`, and the label travels as DATA
# from `observations.tsv` rather than being stamped on here — a label the
# assembler adds unconditionally is a label no fixture can remove, and a check
# that cannot fire is not a check.
observation_rows = read_tsv_rows(os.path.join(run_dir, "observations.tsv"), 4,
                                 "observations.tsv")
observations = []
seen = set()
for index, (kind, name, outcome, detail) in enumerate(observation_rows, 1):
    if kind != "observation":
        refuse("observations.tsv row %d is labelled %r and every observation "
               "must carry kind=observation; an unlabelled claim sitting beside "
               "a recomputed number is the false independent-validation "
               "guarantee this partition exists to refuse" % (index, kind))
    if name == "":
        refuse("observations.tsv row %d has an empty name" % index)
    if name in seen:
        refuse("observations.tsv names %s twice" % name)
    seen.add(name)
    if outcome not in ("pass", "fail"):
        refuse("observations.tsv row %d (%s) has outcome %r, want pass or fail"
               % (index, name, outcome))
    observations.append({"kind": "observation", "name": name,
                         "outcome": outcome, "detail": detail})
missing = [name for name in REQUIRED_OBSERVATIONS if name not in seen]
if missing:
    refuse("the artifact is missing required observation(s): %s. A missing or "
           "unlabelled required name is a REFUSAL — these are the harness "
           "controls the verb cannot derive" % ", ".join(missing))

# ------------------------------------------------------------- per client
per_client_rows = read_tsv_rows(os.path.join(run_dir, "per-client.tsv"), 12,
                                "per-client.tsv")
if len(per_client_rows) != 3:
    refuse("per-client.tsv holds %d rows, want 3" % len(per_client_rows))
per_client = []
for index, fields in enumerate(per_client_rows, 1):
    client = as_int(fields[0], "per-client.tsv row %d's client" % index, minimum=1)
    if client != index:
        refuse("per-client.tsv row %d names client %d" % (index, client))
    if fields[9] == "":
        refuse("per-client.tsv row %d has an empty endpoint_given" % index)
    per_client.append({
        "client": client,
        "observed_subtree_digest": as_hex64(fields[1],
                                            "client %d observed_subtree_digest" % client),
        "warmup_observed_tree_digest": as_hex64(
            fields[2], "client %d warmup_observed_tree_digest" % client),
        "warmup_verify_observed_tree_digest": as_hex64(
            fields[3], "client %d warmup_verify_observed_tree_digest" % client),
        "exit_codes": {
            "warmup": as_int(fields[4], "client %d warmup exit code" % client),
            "warmup_verify": as_int(fields[5],
                                    "client %d warmup_verify exit code" % client),
            "workload": as_int(fields[6], "client %d workload exit code" % client),
            "clock_a": as_int(fields[7], "client %d clock_a exit code" % client),
            "clock_b": as_int(fields[8], "client %d clock_b exit code" % client),
        },
        "endpoint_given": fields[9],
        "seq_given": {
            "warmup": as_int(fields[10], "client %d warmup seq" % client),
            "workload": as_int(fields[11], "client %d workload seq" % client),
        },
    })

# ------------------------------------------------------------ the harness
if not HEX40.match(git_sha):
    refuse("the harness git sha is not 40 lowercase hex characters: %r" % git_sha)

# THE TIER LABEL IS DERIVED FROM THE KERNEL, NEVER TYPED. Benchmark round 2
# runs on Tier 1 and Tier 2 separately, so the artifact must identify which
# tier supplied the measurement.
#
# 6.12 is the kernel floor for this measurement:
# Tier 1 here means a current-kernel VM.
# The O_PATH/fget_raw relaxation lands exactly at 6.12 (the spec's Support tiers),
# which is longterm and ships in RHEL 10.
# The label says nothing about DELIVERY:
# the spec's Tier-1 delivery row is "passthrough enabled", which this run
# excludes, and the run's report states that the measured binary uses
# neither passthrough nor io_uring.
#
# An unreadable kernel REFUSES rather than defaulting. A tier label that
# guesses is worse than no label, because it is indistinguishable from one
# that was measured.
TIER1_MIN_KERNEL = (6, 12)

def support_tier_of(kernel_release):
    matched = re.match(r"^(\d+)\.(\d+)\.", kernel_release)
    if not matched:
        refuse("cannot read a major.minor kernel version from %r, so the "
               "support tier cannot be derived; it is never guessed"
               % kernel_release)
    version = (int(matched.group(1)), int(matched.group(2)))
    return "tier-1" if version >= TIER1_MIN_KERNEL else "tier-2"

artifact = {
    "artifact_version": artifact_version,
    "run_id": run_id,
    "harness": {"script": "scripts/m10-propagate.sh", "git_sha": git_sha},
    "venue": {"node": venue_node, "guest": venue_guest, "arch": arch,
              "kernel": kernel, "os": os_name, "transport": "tcp",
              "support_tier": support_tier_of(kernel)},
    "node_cpu_samples": node_cpu_samples,
    "corpus": corpus,
    "timeline": timeline,
    "clocks": clocks,
    "snapshots": snapshots,
    "observations": observations,
    "per_client": per_client,
}

for key in ("node", "guest", "arch", "kernel", "os"):
    if artifact["venue"][key] == "":
        refuse("venue.%s is empty" % key)

if list(artifact.keys()) != TOP_KEYS:
    refuse("the artifact's top-level keys are %s, want exactly %s"
           % (list(artifact.keys()), TOP_KEYS))


def scan(node, path):
    """Refuse a reserved key anywhere, and any negative or non-finite number.

    NO FIELD IN THIS SCHEMA IS LEGITIMATELY NEGATIVE — every one is a
    duration, a byte count, a count, an exit code, a seq or a percentage — so
    the range constraint is enforced as a property of the whole document
    rather than as a list of fields a successor has to remember to extend. A
    literal verifier that accepted a negative duration or a negative
    percentage would compute a passing clock-threshold verdict and a passing
    load check out of impossible inputs.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if key in RESERVED:
                refuse("the RESERVED key %r appears at %s; the artifact carries "
                       "no verdict and no digest of itself, so the shell cannot "
                       "hand Rust a conclusion to seal" % (key, path or "the root"))
            scan(value, "%s.%s" % (path, key) if path else key)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            scan(value, "%s[%d]" % (path, index))
    elif isinstance(node, bool):
        return
    elif isinstance(node, (int, float)):
        if isinstance(node, float) and not math.isfinite(node):
            refuse("%s is not a finite number: %r" % (path, node))
        if node < 0:
            refuse("%s is %r; every numeric field in this artifact is a "
                   "duration, a count, a byte total, an exit code, a seq or a "
                   "percentage, and none of them can be negative" % (path, node))


scan(artifact, "")

# AN EXCLUSIVE CREATE, not `exists()` then `open(..., "w")`. Two defects in
# the pair it replaces, and only one of them needs concurrency:
#   * TOCTOU. Two assemblies racing for the same absent path both saw False
#     and both reported success; the second silently overwrote the first.
#   * A DANGLING SYMLINK. `os.path.exists` FOLLOWS the link and reports False
#     for one whose target is missing, so the `open(..., "w")` then wrote the
#     artifact THROUGH the link, to a path the operator never named. O_EXCL
#     fails with EEXIST on a symlink whether or not its target exists, which
#     is the behaviour wanted: the destination is a name this run is claiming,
#     not a name it is willing to follow. Row ASM26 fires on both.
try:
    handle_fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
except FileExistsError:
    refuse("the artifact destination already exists: %s (the exclusive create "
           "refused it; a symlink counts as existing whether or not its target "
           "does)" % out_path)
except OSError as error:
    refuse("could not create the artifact at %s: %s" % (out_path, error))
with os.fdopen(handle_fd, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(artifact, indent=2, sort_keys=False))
    handle.write("\n")
sys.stdout.write("%s\n" % out_path)
PY
)"

# Assemble ONE artifact. It NEVER `die`s: the negative rows below assemble
# deliberately-broken copies and their evidence is the refusal, so the verdict
# belongs to the caller. Sets ASSEMBLE_RC and ASSEMBLE_LOG.
ASSEMBLE_RC=""
ASSEMBLE_LOG=""
assemble_artifact() {
  local run_dir="$1" snap_dir="$2" out="$3" samples="$4" node="$5" guest="$6"
  local log="$7"
  local venue_file="$run_dir/venue.tsv" arch kernel os_name git_sha rc

  ASSEMBLE_LOG="$log"
  # THE VENUE COMES OFF THE RUN'S OWN RECORD, never from `uname` here. Every
  # refusal in this function writes the log and sets a non-zero rc rather than
  # dying, because the negative rows below assemble deliberately-broken copies
  # and the verdict belongs to the caller.
  if [ ! -f "$venue_file" ]; then
    printf 'REFUSED: %s holds no venue.tsv, so this assembly has no record of the machine and the commit that took the measurement. The venue block is captured at RUN time precisely because an assembly runs later, on a guest that may have been upgraded and a checkout that may have advanced; it is refused rather than re-derived here.\n' \
      "$run_dir" > "$log"
    ASSEMBLE_RC=9
    return 0
  fi
  arch="$(awk -F '\t' '$1 == "arch" { print $2; exit }' "$venue_file")"
  kernel="$(awk -F '\t' '$1 == "kernel" { print $2; exit }' "$venue_file")"
  os_name="$(awk -F '\t' '$1 == "os" { print $2; exit }' "$venue_file")"
  git_sha="$(awk -F '\t' '$1 == "git_sha" { print $2; exit }' "$venue_file")"
  if [ -z "$arch" ] || [ -z "$kernel" ] || [ -z "$os_name" ] || [ -z "$git_sha" ]; then
    printf 'REFUSED: %s is incomplete: arch=[%s] kernel=[%s] os=[%s] git_sha=[%s]. All four are captured at RUN time and an assembly that cannot read one of them attributes the measurement to a venue it cannot name.\n' \
      "$venue_file" "$arch" "$kernel" "$os_name" "$git_sha" > "$log"
    ASSEMBLE_RC=9
    return 0
  fi

  set +e
  python3 -c "$ARTIFACT_PY" "$run_dir" "$snap_dir" "$out" "$samples" \
    "$node" "$guest" "$arch" "$kernel" "$os_name" "$git_sha" \
    "$ARTIFACT_VERSION" "$NODE_SAMPLE_DENSITY_PERIOD_SECONDS" "$NODE_SAMPLE_MAX_GAP_SECONDS" \
    > "$log" 2>&1
  rc=$?
  set -e
  ASSEMBLE_RC="$rc"
}

# The samples file's LAST reading must FOLLOW the run's last timeline stamp,
# and a sampler writing every 10 s has not necessarily written one by the time
# the run reaches assembly. Without this wait the coverage check would fail on
# a perfectly good run, at the end of a measurement that cost an hour — the
# expensive kind of false red. Bounded, and a refusal when the bound expires:
# a sampler that has STOPPED is a real failure of coverage and must not be
# waited out forever.
wait_for_sample_coverage() {
  local samples="$1" want_after="$2" bound="$3" waited=0 last
  [ -n "$want_after" ] || die "the sample-coverage wait was given no stamp to cover"
  while [ "$waited" -lt "$bound" ]; do
    if [ -f "$samples" ]; then
      last="$(awk -F '\t' 'NF == 2 { line = $1 } END { print line }' "$samples")"
      if [ -n "$last" ] && ! stamp_not_after "$last" "$want_after"; then
        note "the node-CPU samples now reach $last, past the run's last timeline stamp $want_after"
        return 0
      fi
    fi
    sleep 1
    waited=$((waited + 1))
  done
  die "the node-CPU samples at $samples never reached past the run's last timeline stamp $want_after within ${bound}s; a sampler that stopped before the run did leaves the end of the run unmeasured, and a missing measurement of the measurement is not a pass"
}


# ---------------------------------------- THE ASSEMBLER'S OWN NEGATIVE ROWS
#
# Every refusal the assembler owns is shown to FIRE, on COPIES of the very
# records the real artifact is made of — so a row that passes is a row about
# THIS run's data, not about a fixture built to match the check.

# The pristine fixture: this run's own records, plus the ONE row the real
# record cannot carry yet. `no_snapshot`'s outcome is decided by the row that
# consumes this fixture, so the fixture carries a provisional value and the
# real `observations.tsv` gets the true one afterwards. Without it every
# fixture would be refused for a MISSING REQUIRED NAME and each row would pass
# for a reason that has nothing to do with the defect it injected.
build_assembly_fixture() {
  local dest="$1" from="$2" snaps="$3" samples="$4"
  [ ! -e "$dest" ] || die "the assembly fixture destination already exists: $dest"
  mkdir -p "$dest" || die "could not create the assembly fixture at $dest"
  cp "$from/corpus.tsv" "$from/timeline.tsv" "$from/clocks.tsv" \
     "$from/per-client.tsv" "$from/observations.tsv" "$from/venue.tsv" "$dest/" \
    || die "could not copy the run's records into the assembly fixture"
  cp -R "$snaps" "$dest/snapshots" \
    || die "could not copy the eleven snapshots into the assembly fixture"
  cp "$samples" "$dest/samples.tsv" \
    || die "could not copy the node-CPU samples into the assembly fixture"
  # ANY EXISTING `no_snapshot` ROW IS REMOVED FIRST. A run directory that has
  # ALREADY been assembled once carries the real row, and appending the
  # provisional one beside it makes a fixture the assembler refuses as a
  # DUPLICATE NAME — a correct refusal, for a defect nobody injected, which
  # would turn every structural row below into a pass or a fail about the wrong
  # thing. MEASURED: the second assembly of a kept run directory went red on
  # exactly this, with four rows reporting refusals they had not caused.
  local fixture_rc
  set +e
  grep -a -v -- "	no_snapshot	" "$dest/observations.tsv" > "$dest/observations.trimmed"
  fixture_rc=$?
  set -e
  [ "$fixture_rc" -le 1 ] \
    || die "could not build the fixture's observation list (grep exited $fixture_rc)"
  mv "$dest/observations.trimmed" "$dest/observations.tsv"
  printf 'observation\tno_snapshot\tpass\tprovisional inside a fixture that exists to be broken; the REAL record carries the outcome of the row that consumes it\n' \
    >> "$dest/observations.tsv"
}

asm_fixture_from() {
  local src="$1" dest="$2"
  [ ! -e "$dest" ] || die "the assembly fixture destination already exists: $dest"
  cp -a "$src" "$dest" || die "could not copy the assembly fixture $src to $dest"
  rm -f "$dest/out.json" "$dest/assemble.log"
}

# ONE refusal row. It asserts THREE things and not one: a non-zero status, the
# refusal's OWN TEXT, and that no artifact was written. An assembler that
# refused everything would satisfy "it refused" on every row here; naming the
# fragment is what makes a row about the defect it injected.
assembler_refuses() {
  local row="$1" dir="$2" samples="$3" fragment="$4" what="$5"
  local node="$6" guest="$7"
  local out="$dir/out.json" found
  rm -f "$out"
  assemble_artifact "$dir" "$dir/snapshots" "$out" "$samples" \
    "$node" "$guest" "$dir/assemble.log"
  set +e
  grep -a -F -q -- "$fragment" "$dir/assemble.log"
  found=$?
  set -e
  if [ "$ASSEMBLE_RC" -ne 0 ] && [ "$found" -eq 0 ] && [ ! -e "$out" ]; then
    row_pass "$row" "$what — the assembler REFUSES it (rc=$ASSEMBLE_RC): $(sed -n '1p' "$dir/assemble.log")"
  else
    row_fail "$row" "$what — rc=$ASSEMBLE_RC, the refusal text $([ "$found" -eq 0 ] && echo names || echo 'does NOT name') [$fragment], and the artifact was $([ -e "$out" ] && echo WRITTEN || echo 'not written'); see $dir/assemble.log"
  fi
}

# A SYNTHETIC 120 s WINDOW FOR THE SAMPLE ROWS. A short
# self-test window cannot exercise the same count and
# spacing failures as a longer measurement: a count
# floor can round down to zero, and a window shorter
# than the permitted gap cannot contain an excessive
# internal gap. The stretched timeline gives these
# fixtures room to construct sparse samples, boundary-crossing
# gaps and insufficient coverage. The sample variants
# share the stretched window so their differences come
# from the samples. The fixture retains this run's
# snapshots, corpus and clock records while supplying
# timestamps long enough for the sampling checks.
STRETCH_BASE_EPOCH=1800000000
STRETCH_WINDOW_SECONDS=120

stamp_at() {
  local epoch="$1" out
  out="$(date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null)" \
    || die "could not render the fixture stamp for epoch $epoch"
  case "$out" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z) ;;
    *) die "the fixture stamp for epoch $epoch is not orderable: [$out]" ;;
  esac
  printf '%s' "$out"
}

stretched_timeline() {
  local file="$1" t="$STRETCH_BASE_EPOCH"
  {
    printf 'warmups_ended\t%s\n' "$(stamp_at "$t")"
    printf 'delta_generated\t%s\n' "$(stamp_at $((t + 1)))"
    printf 'publish_started\t%s\n' "$(stamp_at $((t + 2)))"
    printf 'publish_ended\t%s\n' "$(stamp_at $((t + 3)))"
    printf 'workloads_started\t%s\n' "$(stamp_at $((t + 4)))"
    printf 'workloads_ended\t%s\n' "$(stamp_at $((t + 100)))"
    printf 'server_stopped\t%s\n' "$(stamp_at $((t + STRETCH_WINDOW_SECONDS)))"
  } > "$file"
}

# The sample series for that window, in seven shapes. `good` is the honest one
# and every other is one property away from it, so each row below names exactly
# which property it removed.
stretched_samples() {
  local file="$1" mode="$2" t="$STRETCH_BASE_EPOCH" i pct
  : > "$file"
  case "$mode" in
    thin)
      # Five readings inside a 120 s window, where floor(120/12) = 10 are
      # required. The COUNT bound is what this one is about.
      for i in -10 0 30 60 90 120 130; do
        printf '%s\t%s\n' "$(stamp_at $((t + i)))" '12.5' >> "$file"
      done
      ;;
    padded)
      # NINE readings INSIDE the window and eight outside it. The count floor
      # is floor(120/12) = 10 and it is a floor on the readings inside; a
      # degenerate that counted the UNCLIPPED list saw seventeen and passed,
      # while the middle of the run held nine. Spacing is 15 s throughout, so
      # the 15 s bound has nothing to say and the COUNT is what this fixture
      # is about.
      for i in -70 -60 -50 -40 -30 -20 -10 0 15 30 45 60 75 90 105 120 130; do
        printf '%s\t%s\n' "$(stamp_at $((t + i)))" '12.5' >> "$file"
      done
      ;;
    boundary)
      # TWELVE in-window readings — comfortably above the count floor of
      # TEN — and a 105 s hole that CROSSES the window's start: the sample
      # before it is 100 s early and the first in-window reading is at +5.
      # Spacing checked between in-window samples ALONE never sees the
      # crossing, which is why this file's spacing bound runs over the
      # COVERING set.
      for i in -100 5 15 25 35 45 55 65 75 85 95 105 115 125; do
        printf '%s\t%s\n' "$(stamp_at $((t + i)))" '12.5' >> "$file"
      done
      ;;
    shortfall)
      # NINE in-window readings against a floor
      # of TEN — one short. The `thin` fixture
      # has five, so rejecting it alone cannot
      # distinguish floors from six through ten.
      # This fixture pins the one-below boundary.
      #
      # The `shortfall` and `padded` fixtures both contain
      # nine readings inside the window. They exercise different
      # input shapes: `padded` adds samples outside the window
      # to challenge a count that includes those samples,
      # while `shortfall` carries only the surrounding boundary
      # samples and the nine in-window readings. A floor
      # lowered to nine would admit both. Their overlapping
      # counts are intentional: one tests clipping before
      # counting, and the other tests the count threshold
      # itself. The offsets below place the in-window readings
      # at 15-second intervals through the end of the 120-second
      # window; the samples before and after it provide
      # coverage without increasing the in-window count.
      for i in -10 0 15 30 45 60 75 90 105 120 130; do
        printf '%s\t%s\n' "$(stamp_at $((t + i)))" '12.5' >> "$file"
      done
      ;;
    cluster)
      # CLUSTERED at the two boundaries and PADDED with hours of idle outside
      # the window: fourteen in-window readings (above the count floor), a
      # first that precedes and a last that follows — and 108 s in the middle
      # of the run, where a competing workload would show, unsampled.
      printf '%s\t%s\n' "$(stamp_at $((t - 7200)))" '3.0' >> "$file"
      printf '%s\t%s\n' "$(stamp_at $((t - 5)))" '3.0' >> "$file"
      for i in 0 1 2 3 4 5 6 114 115 116 117 118 119 120; do
        printf '%s\t%s\n' "$(stamp_at $((t + i)))" '12.5' >> "$file"
      done
      printf '%s\t%s\n' "$(stamp_at $((t + 125)))" '3.0' >> "$file"
      printf '%s\t%s\n' "$(stamp_at $((t + 7200)))" '3.0' >> "$file"
      ;;
    *)
      for i in $(seq -10 10 130); do
        if [ "$mode" = "gap" ] && [ "$i" -eq 60 ]; then
          continue
        fi
        if [ "$mode" = "late" ] && [ "$i" -eq -10 ]; then
          continue
        fi
        pct='12.5'
        if [ "$mode" = "percent" ] && [ "$i" -eq 50 ]; then
          pct='100.5'
        fi
        printf '%s\t%s\n' "$(stamp_at $((t + i)))" "$pct" >> "$file"
        if [ "$mode" = "repeat" ] && [ "$i" -eq 60 ]; then
          printf '%s\t%s\n' "$(stamp_at $((t + i)))" "$pct" >> "$file"
        fi
      done
      ;;
  esac
  [ -s "$file" ] || die "the $mode sample fixture is empty"
}

# ONE PHASE, TWO CALLERS. `propagation-run --artifact` runs it at the end of a
# run, and the `assemble-artifact` verb runs it later against a KEPT run
# directory — which is not a convenience. `scripts/m10-node-sample.sh` samples
# the node FROM THE DRIVER (the guest cannot reach its own hypervisor) and
# writes its file THERE, so on the measurement venue the samples do not exist on
# the guest until the sampler has stopped and the file has been copied across.
# A phase that could only run inside the run would make the artifact
# unobtainable on the only venue that matters.
#
# IT TAKES NO GIT SHA AND NO VENUE FACTS. Both come off `$run_dir/venue.tsv`,
# written when the run took them; see `write_venue_record`.
#
# ITS FIXTURES LIVE IN A FRESH DIRECTORY EACH TIME, so a second assembly of the
# same run directory neither collides with the first nor silently reuses it.
#
# This phase also runs under `assemble-artifact`,
# outside `propagation_run`. Its paths must come
# from its own parameters and locals. Referring
# to a caller's local variable in a failure
# diagnostic can abort that separate invocation under
# `set -u` instead of reporting the failed row.
artifact_phase() {
  local run_dir="$1" snap_dir="$2" neg_dir="$3" artifact_out="$4"
  local node_samples="$5" venue_node="$6" venue_guest="$7"
  local last_stamp="$8"
  local ASMROOT
  mkdir -p "$neg_dir" || die "could not create the assembly fixture parent $neg_dir"
  ASMROOT="$(mktemp -d "$neg_dir/asm.XXXXXX")" \
    || die "could not create a fixture directory under $neg_dir"

  # ======================= THE RUN'S OWN LEDGER, BEFORE ANYTHING IS ASSEMBLED
  #
  # A REJECTED RUN GETS NO RECORD, and the cheapest place to say so is here,
  # before an hour of fixtures. `SELF_TEST_FAILURES` alone is not enough: this
  # phase also runs from `assemble-artifact`, in a fresh process whose counters
  # start at zero and know nothing about the run whose records it is reading.
  # Both are consulted.
  read_run_status "$run_dir/run-status.tsv"
  artifact_ledger_gate "$RUN_STATUS_FAILURES" "$RUN_STATUS_ROWS" \
    "$SELF_TEST_FAILURES" "$SELF_TEST_ROWS" "this phase before it began"

  # =============================================== THE ARTIFACT AND ITS ROWS
  #
  # The artifact is assembled LAST and the harness computes no verdict. Before
  # the real one is written, every refusal the assembler owns is shown to FIRE
  # on copies of the very records the real artifact is made of, and the
  # PRISTINE copy is assembled GREEN first — so a row that fires is firing on
  # its mutation and not on the copy.
  # THE SAMPLER MAY NOT HAVE WRITTEN ITS
  # LAST READING YET. Wait before building
  # the fixture, not just before real assembly:
  # copying an incomplete sample file would
  # give the fixture a series that stops
  # short of the run window. A structural
  # negative would then refuse for missing
  # coverage rather than for its injected
  # mutation. The coverage wait is bounded,
  # since a sampler that stops before
  # covering the run is itself a failure.
  wait_for_sample_coverage "$node_samples" "$last_stamp" 60

  local ASM="$ASMROOT/asm" no_snapshot_outcome="fail" no_snapshot_rc=""
  build_assembly_fixture "$ASM" "$run_dir" "$snap_dir" "$node_samples"

  assemble_artifact "$ASM" "$ASM/snapshots" "$ASM/out.json" "$ASM/samples.tsv" \
    "$venue_node" "$venue_guest" "$ASM/assemble.log"
  if [ "$ASSEMBLE_RC" -eq 0 ] && [ -s "$ASM/out.json" ]; then
    row_pass ASM0 "the PRISTINE assembly fixture — this run's own eleven snapshots, timeline, corpus, clocks, per-client rows and observations — assembles into a valid artifact, so every refusal below fires on its mutation and not on the copy"
  else
    row_fail ASM0 "the pristine fixture did NOT assemble (rc=$ASSEMBLE_RC); every refusal row below would then be reporting on a broken copy. See $ASM/assemble.log"
  fi

  asm_fixture_from "$ASM" "$ASMROOT/asm-reserved"
  python3 - "$ASMROOT/asm-reserved/snapshots/client-1.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    document = json.load(handle)
document["digest"] = "sha256:" + "0" * 64
with open(path, "w", encoding="utf-8") as handle:
    json.dump(document, handle, indent=2)
PY
  assembler_refuses ASM1 "$ASMROOT/asm-reserved" "$ASMROOT/asm-reserved/samples.tsv" \
    'RESERVED key' "a snapshot carrying the reserved key 'digest'" \
    "$venue_node" "$venue_guest"

  asm_fixture_from "$ASM" "$ASMROOT/asm-unlabelled"
  sed -i "1s/^observation\\t/note\\t/" "$ASMROOT/asm-unlabelled/observations.tsv"
  assembler_refuses ASM2 "$ASMROOT/asm-unlabelled" "$ASMROOT/asm-unlabelled/samples.tsv" \
    'kind=observation' "an observation whose LABEL has been removed" \
    "$venue_node" "$venue_guest"

  asm_fixture_from "$ASM" "$ASMROOT/asm-missing-name"
  local trimmed_rc
  set +e
  grep -a -v -- "	stale_content	" "$ASMROOT/asm-missing-name/observations.tsv" \
    > "$ASMROOT/asm-missing-name/observations.trimmed"
  trimmed_rc=$?
  set -e
  [ "$trimmed_rc" -le 1 ] \
    || die "could not build the missing-name fixture (grep exited $trimmed_rc)"
  mv "$ASMROOT/asm-missing-name/observations.trimmed" \
     "$ASMROOT/asm-missing-name/observations.tsv"
  assembler_refuses ASM3 "$ASMROOT/asm-missing-name" "$ASMROOT/asm-missing-name/samples.tsv" \
    'missing required observation' "a REQUIRED observation name deleted" \
    "$venue_node" "$venue_guest"

  asm_fixture_from "$ASM" "$ASMROOT/asm-no-snapshot"
  rm -f "$ASMROOT/asm-no-snapshot/snapshots/warmup-2.json"
  assembler_refuses ASM4 "$ASMROOT/asm-no-snapshot" "$ASMROOT/asm-no-snapshot/samples.tsv" \
    'want exactly 11' "one of the ELEVEN snapshots deleted before assembly" \
    "$venue_node" "$venue_guest"
  no_snapshot_rc="$ASSEMBLE_RC"
  if [ "$no_snapshot_rc" -ne 0 ] && [ ! -e "$ASMROOT/asm-no-snapshot/out.json" ]; then
    no_snapshot_outcome="pass"
  fi

  asm_fixture_from "$ASM" "$ASMROOT/asm-no-samples"
  assembler_refuses ASM5 "$ASMROOT/asm-no-samples" "$ASMROOT/asm-no-samples/absent.tsv" \
    'samples file is missing' "a --node-samples file that does not exist" \
    "$venue_node" "$venue_guest"

  asm_fixture_from "$ASM" "$ASMROOT/asm-window"
  stretched_timeline "$ASMROOT/asm-window/timeline.tsv"
  stretched_samples "$ASMROOT/asm-window/samples.tsv" good
  rm -f "$ASMROOT/asm-window/out.json"
  assemble_artifact "$ASMROOT/asm-window" "$ASMROOT/asm-window/snapshots" \
    "$ASMROOT/asm-window/out.json" "$ASMROOT/asm-window/samples.tsv" \
    "$venue_node" "$venue_guest" "$ASMROOT/asm-window/assemble.log"
  if [ "$ASSEMBLE_RC" -eq 0 ] && [ -s "$ASMROOT/asm-window/out.json" ]; then
    row_pass ASM6 "the stretched-window fixture (a synthetic 120 s run window, samples every 10 s from 10 s before it to 10 s after) assembles GREEN — the positive control the sample refusals below are measured against, and the only fixture on which a 15 s spacing bound and a floor(duration/12) count bound have anything to say"
  else
    row_fail ASM6 "the stretched-window fixture did not assemble (rc=$ASSEMBLE_RC); the sample rows below would be firing on the fixture rather than on their mutations. See $ASMROOT/asm-window/assemble.log"
  fi

  asm_fixture_from "$ASMROOT/asm-window" "$ASMROOT/asm-gap"
  stretched_samples "$ASMROOT/asm-gap/samples.tsv" gap
  assembler_refuses ASM7 "$ASMROOT/asm-gap" "$ASMROOT/asm-gap/samples.tsv" \
    's gap between' "a single 20 s hole in an otherwise complete 10 s series" \
    "$venue_node" "$venue_guest"

  asm_fixture_from "$ASMROOT/asm-window" "$ASMROOT/asm-cluster"
  stretched_samples "$ASMROOT/asm-cluster/samples.tsv" cluster
  assembler_refuses ASM8 "$ASMROOT/asm-cluster" "$ASMROOT/asm-cluster/samples.tsv" \
    'is unsampled' "samples CLUSTERED at the two boundaries, padded with hours of idle outside the window" \
    "$venue_node" "$venue_guest"

  asm_fixture_from "$ASMROOT/asm-window" "$ASMROOT/asm-thin"
  stretched_samples "$ASMROOT/asm-thin/samples.tsv" thin
  assembler_refuses ASM9 "$ASMROOT/asm-thin" "$ASMROOT/asm-thin/samples.tsv" \
    'are required' "fewer readings inside the window than floor(duration / 12)" \
    "$venue_node" "$venue_guest"

  asm_fixture_from "$ASMROOT/asm-window" "$ASMROOT/asm-order"
  stretched_samples "$ASMROOT/asm-order/samples.tsv" repeat
  assembler_refuses ASM10 "$ASMROOT/asm-order" "$ASMROOT/asm-order/samples.tsv" \
    'not strictly increasing' "a repeated sample timestamp" \
    "$venue_node" "$venue_guest"

  asm_fixture_from "$ASMROOT/asm-window" "$ASMROOT/asm-late"
  stretched_samples "$ASMROOT/asm-late/samples.tsv" late
  assembler_refuses ASM11 "$ASMROOT/asm-late" "$ASMROOT/asm-late/samples.tsv" \
    'does not precede' "a series whose first reading does not precede the run" \
    "$venue_node" "$venue_guest"

  asm_fixture_from "$ASMROOT/asm-window" "$ASMROOT/asm-percent"
  stretched_samples "$ASMROOT/asm-percent/samples.tsv" percent
  assembler_refuses ASM12 "$ASMROOT/asm-percent" "$ASMROOT/asm-percent/samples.tsv" \
    'above 100' "a CPU percentage outside [0, 100]" \
    "$venue_node" "$venue_guest"

  # ------------------------ ASM13/ASM14: THE VENUE BLOCK IS *READ*, NOT TAKEN
  #
  # The two controls cover both directions. ASM13 proves the record's ABSENCE is a
  # refusal — a run directory with no venue record cannot say which machine or
  # which commit produced it, and an assembly that filled the gap from its own
  # `uname` would attribute the measurement to the machine it happened to be
  # running on. ASM14 is the half that cannot be faked by a refusal: a
  # SYNTHETIC venue record travels through to the artifact VERBATIM, and the
  # values are ones no `uname` on any venue returns. An assembler that still
  # re-derived them would emit this guest's real architecture and kernel and
  # the row would go red.
  asm_fixture_from "$ASM" "$ASMROOT/asm-no-venue"
  rm -f "$ASMROOT/asm-no-venue/venue.tsv"
  assembler_refuses ASM13 "$ASMROOT/asm-no-venue" "$ASMROOT/asm-no-venue/samples.tsv" \
    'holds no venue.tsv' "a run directory carrying NO venue record" \
    "$venue_node" "$venue_guest"

  # The synthetic kernel is now version-SHAPED, because the tier label is
  # derived from it and an unparseable kernel is refused (ASM29). It is
  # still a value no `uname -r` on any venue returns, which is all ASM14
  # needs: 99.99 is not a kernel that exists.
  local synth_arch='m10-synthetic-arch' synth_kernel='99.99.0-m10-synthetic-kernel'
  local synth_os='m10-synthetic-os'
  local synth_sha='0123456789abcdef0123456789abcdef01234567'
  local live_arch live_kernel venue_read_rc
  live_arch="$(uname -m)"
  live_kernel="$(uname -r)"
  asm_fixture_from "$ASM" "$ASMROOT/asm-venue-synth"
  {
    printf 'arch\t%s\n' "$synth_arch"
    printf 'kernel\t%s\n' "$synth_kernel"
    printf 'os\t%s\n' "$synth_os"
    printf 'git_sha\t%s\n' "$synth_sha"
  } > "$ASMROOT/asm-venue-synth/venue.tsv"
  rm -f "$ASMROOT/asm-venue-synth/out.json"
  assemble_artifact "$ASMROOT/asm-venue-synth" "$ASMROOT/asm-venue-synth/snapshots" \
    "$ASMROOT/asm-venue-synth/out.json" "$ASMROOT/asm-venue-synth/samples.tsv" \
    "$venue_node" "$venue_guest" "$ASMROOT/asm-venue-synth/assemble.log"
  venue_read_rc=1
  if [ "$ASSEMBLE_RC" -eq 0 ] && [ -s "$ASMROOT/asm-venue-synth/out.json" ]; then
    set +e
    python3 - "$ASMROOT/asm-venue-synth/out.json" \
      "$synth_arch" "$synth_kernel" "$synth_os" "$synth_sha" \
      "$live_arch" "$live_kernel" > "$ASMROOT/asm-venue-synth/check.log" 2>&1 <<'PY'
import json
import sys

(path, want_arch, want_kernel, want_os, want_sha,
 live_arch, live_kernel) = sys.argv[1:8]
with open(path, "r", encoding="utf-8") as handle:
    artifact = json.load(handle)
venue = artifact["venue"]
got = (venue["arch"], venue["kernel"], venue["os"], artifact["harness"]["git_sha"])
want = (want_arch, want_kernel, want_os, want_sha)
print("artifact venue/sha: %r" % (got,))
print("the run record said: %r" % (want,))
print("this machine says  : %r" % ((live_arch, live_kernel),))
if want_arch == live_arch or want_kernel == live_kernel:
    print("REFUSED: the synthetic values coincide with the live ones, so this "
          "row could not tell a read from a re-derivation")
    raise SystemExit(2)
if got != want:
    print("REFUSED: the artifact does not carry the run's recorded venue")
    raise SystemExit(1)
print("OK: the artifact carries the RUN's venue record, not this machine's")
PY
    venue_read_rc=$?
    set -e
  fi
  if [ "$venue_read_rc" -eq 0 ]; then
    row_pass ASM14 "a SYNTHETIC venue record in the run directory ($synth_arch / $synth_kernel / $synth_os, sha $synth_sha) reaches the artifact VERBATIM while this machine is $live_arch / $live_kernel — so the venue block and the harness sha are READ from the run's own record and not taken from the machine that happens to be assembling"
  else
    row_fail ASM14 "the artifact did not carry the run's recorded venue (assembler rc=$ASSEMBLE_RC, check rc=$venue_read_rc); see $ASMROOT/asm-venue-synth/check.log and $ASMROOT/asm-venue-synth/assemble.log"
  fi

  # ------------------- ASM29-ASM32: THE TIER LABEL IS DERIVED, AND BOTH WAYS
  #
  # These rows assert the `support_tier` MAPPING in both directions and at the
  # boundary, plus the refusal, because a label that can only ever say one
  # thing is not a label.
  #
  # The boundary matters more than the two easy cases: 6.11 and 6.12 differ
  # by one minor version and land on opposite sides, which is the only place
  # an off-by-one in the comparison shows up.
  tier_label_row() {   # <row-id> <kernel> <expected-tier> <why>
    local row="$1" kern="$2" want="$3" why="$4" dir="$ASMROOT/asm-tier-$1" got rc
    asm_fixture_from "$ASM" "$dir"
    {
      printf 'arch\t%s\n' 'x86_64'
      printf 'kernel\t%s\n' "$kern"
      printf 'os\t%s\n' 'm10-synthetic-os'
      printf 'git_sha\t%s\n' '0123456789abcdef0123456789abcdef01234567'
    } > "$dir/venue.tsv"
    rm -f "$dir/out.json"
    assemble_artifact "$dir" "$dir/snapshots" "$dir/out.json" "$dir/samples.tsv" \
      "$venue_node" "$venue_guest" "$dir/assemble.log"
    if [ "$ASSEMBLE_RC" -ne 0 ] || [ ! -s "$dir/out.json" ]; then
      row_fail "$row" "the assembler did not produce an artifact for kernel $kern (rc=$ASSEMBLE_RC); see $dir/assemble.log"
      return
    fi
    set +e
    got="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["venue"]["support_tier"])' "$dir/out.json" 2>&1)"
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
      row_fail "$row" "could not read support_tier out of $dir/out.json: $got"
    elif [ "$got" = "$want" ]; then
      row_pass "$row" "kernel $kern is labelled $got — $why"
    else
      row_fail "$row" "kernel $kern was labelled $got, want $want — $why"
    fi
  }

  tier_label_row ASM30 '5.14.0-687.36.1.el9_8.x86_64' tier-2 \
    "the Tier 2 guest kernel used for the M10 measurement"
  tier_label_row ASM31 '6.12.0-211.47.1.el10_2.x86_64' tier-1 \
    "the Tier 1 guest kernel: AlmaLinux 10.2 is RHEL-10-class and ships 6.12, the minimum kernel line for Tier 1 in this measurement"
  tier_label_row ASM32 '6.11.99-synthetic.x86_64' tier-2 \
    "ONE MINOR VERSION BELOW the line still reads tier-2; this is where an off-by-one would show"

  # The refusal. An unreadable kernel must never fall back to a tier, because
  # a guessed label is indistinguishable from a measured one.
  asm_fixture_from "$ASM" "$ASMROOT/asm-tier-unparseable"
  {
    printf 'arch\t%s\n' 'x86_64'
    printf 'kernel\t%s\n' 'not-a-kernel-version'
    printf 'os\t%s\n' 'm10-synthetic-os'
    printf 'git_sha\t%s\n' '0123456789abcdef0123456789abcdef01234567'
  } > "$ASMROOT/asm-tier-unparseable/venue.tsv"
  assembler_refuses ASM29 "$ASMROOT/asm-tier-unparseable" \
    "$ASMROOT/asm-tier-unparseable/samples.tsv" \
    'the support tier cannot be derived' \
    "a venue record whose kernel carries no major.minor version" \
    "$venue_node" "$venue_guest"

  # ------------------- ASM15/ASM16: A SNAPSHOT'S IDENTITY, READ BY THE ASSEMBLER
  #
  # Both checks exist in the assembler and NEITHER had a row: degenerates that
  # deleted them survived the whole suite. ASM15 SWAPS two snapshot files, so
  # each is a valid snapshot carrying its own role under the wrong name — the
  # shape a mis-wired harness produces, and one that a per-file schema check
  # cannot see. ASM16 substitutes a snapshot whose RUN ID belongs to the
  # negative rows' `<run id>-neg`: eleven files stamped from the wrong run
  # satisfy every count and every role.
  asm_fixture_from "$ASM" "$ASMROOT/asm-role-swap"
  mv "$ASMROOT/asm-role-swap/snapshots/client-2.json" "$ASMROOT/asm-role-swap/snapshots/.swap"
  mv "$ASMROOT/asm-role-swap/snapshots/client-3.json" "$ASMROOT/asm-role-swap/snapshots/client-2.json"
  mv "$ASMROOT/asm-role-swap/snapshots/.swap" "$ASMROOT/asm-role-swap/snapshots/client-3.json"
  assembler_refuses ASM15 "$ASMROOT/asm-role-swap" "$ASMROOT/asm-role-swap/samples.tsv" \
    'carries role' "two snapshot FILES swapped, each still carrying its own role" \
    "$venue_node" "$venue_guest"

  asm_fixture_from "$ASM" "$ASMROOT/asm-run-id"
  python3 - "$ASMROOT/asm-run-id/snapshots/client-1.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    document = json.load(handle)
document["run_id"] = "%s-neg" % document["run_id"]
with open(path, "w", encoding="utf-8") as handle:
    json.dump(document, handle, indent=2)
PY
  assembler_refuses ASM16 "$ASMROOT/asm-run-id" "$ASMROOT/asm-run-id/samples.tsv" \
    'carries run_id' "a snapshot stamped with the NEGATIVE rows' run id" \
    "$venue_node" "$venue_guest"

  # ------------- ASM17/ASM18: THE RECURSIVE RANGE AND RESERVED-KEY SCANS
  #
  # Both scans are correct and NEITHER had a row. ASM17 puts a NEGATIVE
  # number where every field in the schema is a duration, a count, a byte
  # total, an exit code, a seq or a percentage. ASM18 hides a reserved key
  # inside a LIST, which is the arm a degenerate removed and survived: the
  # existing ASM1 finds a reserved key at the top level of a snapshot dict and
  # says nothing about recursion through lists.
  asm_fixture_from "$ASM" "$ASMROOT/asm-negative"
  python3 - "$ASMROOT/asm-negative/snapshots/client-2.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    document = json.load(handle)
document["response_bytes"] = -1
with open(path, "w", encoding="utf-8") as handle:
    json.dump(document, handle, indent=2)
PY
  assembler_refuses ASM17 "$ASMROOT/asm-negative" "$ASMROOT/asm-negative/samples.tsv" \
    'can be negative' "a snapshot reporting NEGATIVE response bytes" \
    "$venue_node" "$venue_guest"

  asm_fixture_from "$ASM" "$ASMROOT/asm-list-reserved"
  python3 - "$ASMROOT/asm-list-reserved/snapshots/client-2.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    document = json.load(handle)
document["aside"] = [{"digest": "sha256:" + "0" * 64}]
with open(path, "w", encoding="utf-8") as handle:
    json.dump(document, handle, indent=2)
PY
  assembler_refuses ASM18 "$ASMROOT/asm-list-reserved" "$ASMROOT/asm-list-reserved/samples.tsv" \
    'RESERVED key' "a reserved key hidden inside a LIST inside a snapshot" \
    "$venue_node" "$venue_guest"

  # ------------------- ASM19/ASM20: THE DIRECTORY COUNT, AND THE MISSING NAME
  #
  # ASM4 above deletes a file and the COUNT refuses it, which leaves two arms
  # unexercised. ASM19 adds a TWELFTH file: a count written `< 11` instead of
  # `!= 11` passes that and the artifact would be assembled from a directory
  # holding something nobody can account for. ASM20 RENAMES one of the eleven,
  # so the count is right and the NAME is missing — the only fixture that
  # reaches the assembler's per-role presence check at all.
  asm_fixture_from "$ASM" "$ASMROOT/asm-twelfth"
  cp "$ASMROOT/asm-twelfth/snapshots/client-1.json" \
     "$ASMROOT/asm-twelfth/snapshots/twelfth.json" \
    || die "could not build the twelfth-snapshot fixture"
  assembler_refuses ASM19 "$ASMROOT/asm-twelfth" "$ASMROOT/asm-twelfth/samples.tsv" \
    'want exactly 11' "a TWELFTH file in the snapshot directory" \
    "$venue_node" "$venue_guest"

  asm_fixture_from "$ASM" "$ASMROOT/asm-renamed"
  mv "$ASMROOT/asm-renamed/snapshots/warmup-2.json" \
     "$ASMROOT/asm-renamed/snapshots/warmup-2.json.bak" \
    || die "could not build the renamed-snapshot fixture"
  assembler_refuses ASM20 "$ASMROOT/asm-renamed" "$ASMROOT/asm-renamed/samples.tsv" \
    'NO SNAPSHOT FILE for role' "one of the eleven RENAMED, so the count is right and the NAME is gone" \
    "$venue_node" "$venue_guest"

  # ------------------------- ASM21: AN OBSERVATION OUTCOME OUTSIDE THE VOCABULARY
  #
  # `pass` or `fail`, and nothing else. A third spelling reaching the artifact
  # is a claim a verifier has to interpret, and interpretation is where a
  # `maybe` becomes a `pass`.
  asm_fixture_from "$ASM" "$ASMROOT/asm-outcome"
  sed -i 's/^observation\twarmup_cache_dirs_were_empty\tpass\t/observation\twarmup_cache_dirs_were_empty\tmaybe\t/' \
    "$ASMROOT/asm-outcome/observations.tsv"
  assembler_refuses ASM21 "$ASMROOT/asm-outcome" "$ASMROOT/asm-outcome/samples.tsv" \
    'want pass or fail' "an observation whose outcome is neither pass nor fail" \
    "$venue_node" "$venue_guest"

  # ------------------- ASM22/ASM23/ASM24: THE SAMPLE WINDOW, THREE MORE SIDES
  #
  # Mutations covering these three shapes passed the existing checks.
  # ASM22 pads OUTSIDE the window so a count taken over the unclipped list
  # passes while the run itself is thinly sampled. ASM23 puts the hole across
  # the window's START, which spacing checked between in-window samples alone
  # never sees. ASM24 is ONE reading below the floor, because the existing
  # `thin` fixture holds five against a floor of ten — any floor from 6 to
  # 10 passes it, so the floor's VALUE was untested.
  #
  # ASM22 uses `padded` to require counting only the
  # nine readings inside the window. ASM23 uses
  # `boundary` to require spacing checks across the
  # start boundary, even with enough in-window readings.
  # ASM24 uses `shortfall` to pin the count one below
  # the floor. Sharing an in-window count between
  # `padded` and `shortfall` does not make their
  # inputs identical: the former also supplies outside
  # padding that an unclipped count could admit.
  asm_fixture_from "$ASMROOT/asm-window" "$ASMROOT/asm-padded"
  stretched_samples "$ASMROOT/asm-padded/samples.tsv" padded
  assembler_refuses ASM22 "$ASMROOT/asm-padded" "$ASMROOT/asm-padded/samples.tsv" \
    'are required' "nine readings INSIDE the window and eight outside it" \
    "$venue_node" "$venue_guest"

  asm_fixture_from "$ASMROOT/asm-window" "$ASMROOT/asm-boundary"
  stretched_samples "$ASMROOT/asm-boundary/samples.tsv" boundary
  assembler_refuses ASM23 "$ASMROOT/asm-boundary" "$ASMROOT/asm-boundary/samples.tsv" \
    's gap between' "a 105 s hole that CROSSES the window's start, with twelve in-window readings behind it" \
    "$venue_node" "$venue_guest"

  asm_fixture_from "$ASMROOT/asm-window" "$ASMROOT/asm-shortfall"
  stretched_samples "$ASMROOT/asm-shortfall/samples.tsv" shortfall
  assembler_refuses ASM24 "$ASMROOT/asm-shortfall" "$ASMROOT/asm-shortfall/samples.tsv" \
    'are required' "NINE in-window readings against a floor of ten — the floor's value, not merely its existence" \
    "$venue_node" "$venue_guest"

  # --------------------------- ASM28: THE STRICT TIMELINE HAS A NEGATIVE ROW
  #
  # ASM28 checks equal adjacent TIMELINE
  # timestamps. ASM10 repeats a node-CPU
  # sample timestamp, so it cannot establish
  # this separate timeline rule. Copy the
  # complete stretched-window fixture and
  # change its timeline, then require the
  # ordering refusal. Equal adjacent timestamps
  # do not order their events; an assembler
  # that rejects only reversal would admit
  # them. The control id remains distinct
  # from ASM26 and ASM27, whose
  # exclusive-create and ledger checks appear
  # below and use row_pass/row_fail
  # directly rather than assembler_refuses.
  asm_fixture_from "$ASMROOT/asm-window" "$ASMROOT/asm-equal-stamps"
  python3 - "$ASMROOT/asm-equal-stamps/timeline.tsv" <<'EQPY'
import sys
path = sys.argv[1]
rows = [l.rstrip("\n").split("\t") for l in open(path) if l.strip()]
by = {r[0]: r[1] for r in rows if len(r) == 2}
# `publish_ended` is set equal to `publish_started`: adjacent, and the pair the
# verb's own row (`two_equal_timeline_stamps_are_refused`) uses.
by["publish_ended"] = by["publish_started"]
with open(path, "w") as fh:
    for r in rows:
        if len(r) == 2:
            fh.write("%s\t%s\n" % (r[0], by[r[0]]))
        else:
            fh.write("\t".join(r) + "\n")
EQPY
  assembler_refuses ASM28 "$ASMROOT/asm-equal-stamps" "$ASMROOT/asm-equal-stamps/samples.tsv" \
    'not strictly increasing' "two EQUAL adjacent timeline stamps" \
    "$venue_node" "$venue_guest"

  # --------------------------- ASM25: "VERBATIM" HAS AN ORACLE
  #
  # The artifact's contract is that the eleven snapshots travel VERBATIM as
  # their writers emitted them — but nothing
  # read the embedded copies back. An assembler that dropped `format_version`
  # from all eleven and `publish.manifest_root` from the publisher's survived
  # every other row here. This compares each embedded document against the file
  # it came from, by value and to full depth.
  #
  # IT RUNS ON THE PRISTINE FIXTURE, whose snapshots are this run's own eleven
  # copied whole, and NOT on the real artifact — because the real artifact is
  # written after the ledger gate below, and a row that could only fail after
  # the file existed would be the very defect that gate closes. The real
  # artifact is checked too, immediately after it is written, by the same
  # script; that check removes the artifact rather than reporting a row.
  local roundtrip_rc=1
  if [ -s "$ASM/out.json" ]; then
    set +e
    python3 - "$ASM/out.json" "$ASM/snapshots" > "$ASMROOT/roundtrip.log" 2>&1 <<'PY'
import json
import os
import sys

artifact_path, snap_dir = sys.argv[1:3]
with open(artifact_path, "r", encoding="utf-8") as handle:
    artifact = json.load(handle)
embedded = artifact["snapshots"]
if len(embedded) != 11:
    print("REFUSED: the artifact embeds %d snapshots, want 11" % len(embedded))
    raise SystemExit(2)
bad = []
for name in sorted(embedded):
    with open(os.path.join(snap_dir, "%s.json" % name), "r", encoding="utf-8") as handle:
        on_disk = json.load(handle)
    if on_disk != embedded[name]:
        bad.append("%s: only-on-disk=%s only-in-artifact=%s"
                   % (name,
                      sorted(set(on_disk) - set(embedded[name])),
                      sorted(set(embedded[name]) - set(on_disk))))
print("compared %d embedded snapshots against their files; %d differ"
      % (len(embedded), len(bad)))
for line in bad:
    print(line)
raise SystemExit(1 if bad else 0)
PY
    roundtrip_rc=$?
    set -e
  fi
  if [ "$roundtrip_rc" -eq 0 ]; then
    row_pass ASM25 "all ELEVEN embedded snapshots are equal, by value and to full depth, to the files they were read from — 'verbatim' is asserted rather than intended, and an assembler that dropped a field from every one of them would be caught here. See $ASMROOT/roundtrip.log"
  else
    row_fail ASM25 "an embedded snapshot differs from the file it came from (rc=$roundtrip_rc); see $ASMROOT/roundtrip.log"
  fi

  # ---------------------- ASM26: THE DESTINATION IS CLAIMED, NOT TESTED THEN TAKEN
  #
  # Testing `exists()` and then opening for writing
  # leaves a race between the check and the write.
  # A dangling symlink also defeats an existence
  # check that follows its target: the target is
  # absent, but opening for writing can create it
  # through the link. These controls require refusal
  # for both an occupied regular file and a dangling
  # symlink, unchanged contents in the occupied
  # file, and no creation of the link target.
  local excl_dir="$ASMROOT/asm-exclusive"
  asm_fixture_from "$ASM" "$excl_dir"
  local excl_file="$excl_dir/occupied.json" excl_link="$excl_dir/dangling.json"
  local excl_target="$excl_dir/never-named.json"
  printf 'this is not an artifact\n' > "$excl_file"
  ln -s "$excl_target" "$excl_link" \
    || die "could not build the dangling-symlink fixture at $excl_link"
  assemble_artifact "$excl_dir" "$excl_dir/snapshots" "$excl_file" \
    "$excl_dir/samples.tsv" "$venue_node" "$venue_guest" "$excl_dir/excl-file.log"
  local excl_file_rc="$ASSEMBLE_RC"
  assemble_artifact "$excl_dir" "$excl_dir/snapshots" "$excl_link" \
    "$excl_dir/samples.tsv" "$venue_node" "$venue_guest" "$excl_dir/excl-link.log"
  local excl_link_rc="$ASSEMBLE_RC"
  local excl_file_named excl_link_named excl_kept
  set +e
  grep -a -F -q -- 'already exists' "$excl_dir/excl-file.log"
  excl_file_named=$?
  grep -a -F -q -- 'already exists' "$excl_dir/excl-link.log"
  excl_link_named=$?
  set -e
  excl_kept="$(sed -n '1p' "$excl_file")"
  if [ "$excl_file_rc" -ne 0 ] && [ "$excl_link_rc" -ne 0 ] \
      && [ "$excl_file_named" -eq 0 ] && [ "$excl_link_named" -eq 0 ] \
      && [ "$excl_kept" = "this is not an artifact" ] \
      && [ ! -e "$excl_target" ]; then
    row_pass ASM26 "the artifact destination is claimed with an EXCLUSIVE create: an existing regular file is refused (rc=$excl_file_rc) with its contents untouched, and a DANGLING SYMLINK is refused too (rc=$excl_link_rc) rather than followed — nothing was written to $excl_target"
  else
    row_fail ASM26 "the exclusive create did not hold: file rc=$excl_file_rc (names the refusal: $excl_file_named), link rc=$excl_link_rc (names it: $excl_link_named), the occupied file now reads [$excl_kept], and the symlink target is $([ -e "$excl_target" ] && echo WRITTEN || echo absent). See $excl_dir/excl-file.log and $excl_dir/excl-link.log"
  fi

  # ------------------------ ASM27: THE LEDGER GATE, FIRED IN BOTH DIRECTIONS
  #
  # The gate that stands between a rejected run and a complete-looking
  # artifact. It is shown to refuse a run whose OWN rows failed, to refuse one
  # whose ASSEMBLY rows failed, and — the positive control, without which
  # "it refuses" is satisfied by a gate that refuses everything — to PASS a
  # clean ledger.
  local gate_run_rc gate_live_rc gate_clean_rc gate_run_named gate_live_named
  expect_failure "$ASMROOT/gate-run.log" \
    artifact_ledger_gate 1 40 0 13 "a synthetic ledger"
  gate_run_rc="$EXPECT_RC"
  expect_failure "$ASMROOT/gate-live.log" \
    artifact_ledger_gate 0 40 1 13 "a synthetic ledger"
  gate_live_rc="$EXPECT_RC"
  set +e
  ( artifact_ledger_gate 0 40 0 13 "a synthetic ledger" ) \
    > "$ASMROOT/gate-clean.log" 2>&1
  gate_clean_rc=$?
  grep -a -F -q -- 'NO ARTIFACT IS WRITTEN' "$ASMROOT/gate-run.log"
  gate_run_named=$?
  grep -a -F -q -- 'NO ARTIFACT IS WRITTEN' "$ASMROOT/gate-live.log"
  gate_live_named=$?
  set -e
  if [ "$gate_run_rc" -ne 0 ] && [ "$gate_live_rc" -ne 0 ] \
      && [ "$gate_run_named" -eq 0 ] && [ "$gate_live_named" -eq 0 ] \
      && [ "$gate_clean_rc" -eq 0 ]; then
    row_pass ASM27 "the artifact ledger gate REFUSES a ledger with a failed RUN row (rc=$gate_run_rc) and one with a failed ASSEMBLY row (rc=$gate_live_rc), both saying NO ARTIFACT IS WRITTEN in those words, and PASSES a clean ledger (rc=$gate_clean_rc) — so the run below reaches the assembler only with every row green"
  else
    row_fail ASM27 "the ledger gate did not behave: failed-run rc=$gate_run_rc (names the refusal: $gate_run_named), failed-assembly rc=$gate_live_rc (names it: $gate_live_named), clean rc=$gate_clean_rc. See $ASMROOT/gate-run.log, $ASMROOT/gate-live.log and $ASMROOT/gate-clean.log"
  fi

  # THE ROW'S OUTCOME BECOMES THE OBSERVATION, appended now that it is known.
  # `no_snapshot` is a REQUIRED name and its outcome is decided by ASM4 —
  # which is why the fixtures above carry a provisional value for it and the
  # real record does not get one until here.
  # REPLACED, NOT APPENDED. This phase can be run a second time against the
  # same kept run directory — that is the whole point of it being separable —
  # and a second append would leave TWO `no_snapshot` rows, which the assembler
  # refuses as a duplicate name. The refusal would be correct and the cause
  # invisible, so the row is removed before it is written.
  local obs_rc
  set +e
  grep -a -v -- "	no_snapshot	" "$run_dir/observations.tsv" > "$run_dir/observations.next"
  obs_rc=$?
  set -e
  [ "$obs_rc" -le 1 ] \
    || die "could not rewrite $run_dir/observations.tsv (grep exited $obs_rc)"
  mv "$run_dir/observations.next" "$run_dir/observations.tsv"
  printf 'observation\tno_snapshot\t%s\tone of the eleven snapshots was deleted from a copy of this run and the assembler refused it (rc=%s)\n' \
    "$no_snapshot_outcome" "$no_snapshot_rc" >> "$run_dir/observations.tsv"

  # ================================ THE GATE, AND ONLY THEN THE REAL ARTIFACT
  #
  # Every row above has now run. If any of them failed — or if the run itself
  # failed, which the record read at the top of this function is what makes
  # visible to a LATER assembly — nothing is written and the reason is said
  # out loud. This is the gate's whole point: without it the artifact
  # would be written before anyone looked.
  artifact_ledger_gate "$RUN_STATUS_FAILURES" "$RUN_STATUS_ROWS" \
    "$SELF_TEST_FAILURES" "$SELF_TEST_ROWS" "the assembly's own rows"

  assemble_artifact "$run_dir" "$snap_dir" "$artifact_out" "$node_samples" \
    "$venue_node" "$venue_guest" "$run_dir/assemble.log"
  if [ "$ASSEMBLE_RC" -ne 0 ]; then
    cat "$run_dir/assemble.log" >&2
    die "the artifact assembler REFUSED this run's own records (rc=$ASSEMBLE_RC); see $run_dir/assemble.log"
  fi
  [ -s "$artifact_out" ] \
    || die "the assembler reported success and wrote no artifact at $artifact_out"

  # THE SAME ROUND-TRIP, ON THE REAL ARTIFACT. ASM25 proves the check works;
  # this applies it to the document that leaves the venue. A failure REMOVES
  # the artifact — a file that reached disk and then failed its own contract is
  # exactly the complete-looking record the gate above exists to prevent.
  local real_roundtrip_rc
  set +e
  python3 - "$artifact_out" "$snap_dir" > "$run_dir/roundtrip.log" 2>&1 <<'PY'
import json
import os
import sys

artifact_path, snap_dir = sys.argv[1:3]
with open(artifact_path, "r", encoding="utf-8") as handle:
    artifact = json.load(handle)
embedded = artifact["snapshots"]
if len(embedded) != 11:
    print("REFUSED: the artifact embeds %d snapshots, want 11" % len(embedded))
    raise SystemExit(2)
bad = []
for name in sorted(embedded):
    with open(os.path.join(snap_dir, "%s.json" % name), "r", encoding="utf-8") as handle:
        on_disk = json.load(handle)
    if on_disk != embedded[name]:
        bad.append("%s: only-on-disk=%s only-in-artifact=%s"
                   % (name,
                      sorted(set(on_disk) - set(embedded[name])),
                      sorted(set(embedded[name]) - set(on_disk))))
print("compared %d embedded snapshots against their files; %d differ"
      % (len(embedded), len(bad)))
for line in bad:
    print(line)
raise SystemExit(1 if bad else 0)
PY
  real_roundtrip_rc=$?
  set -e
  if [ "$real_roundtrip_rc" -ne 0 ]; then
    cat "$run_dir/roundtrip.log" >&2
    rm -f "$artifact_out"
    die "the assembled artifact does not carry the eleven snapshots verbatim (rc=$real_roundtrip_rc); the artifact has been REMOVED — see $run_dir/roundtrip.log"
  fi

  echo
  echo "m10-propagate: artifact $artifact_out"
  echo "m10-propagate: artifact sha256 $(sha256_of_file "$artifact_out" "the artifact")"

}

# --------------------------------------------------------------- THE RUN
RUN_GRAN=""
RUN_VOLUME=""
RUN_PIN=""
RUN_ROOT_KEY=""
RUN_ID=""

propagation_run() {
  local workdir="" profile_input="" preset="selftest" volume="m10-propagation"
  local negatives="" negatives_explicit=0 keep_input=0
  local artifact_out="" node_samples="" venue_node="" venue_guest="" git_sha=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --workdir)  [ "$#" -ge 2 ] || { usage; exit 1; }; workdir="$2"; shift 2 ;;
      --profile)  [ "$#" -ge 2 ] || { usage; exit 1; }; profile_input="$2"; shift 2 ;;
      --preset)   [ "$#" -ge 2 ] || { usage; exit 1; }; preset="$2"; shift 2 ;;
      --volume)   [ "$#" -ge 2 ] || { usage; exit 1; }; volume="$2"; shift 2 ;;
      --artifact) [ "$#" -ge 2 ] || { usage; exit 1; }; artifact_out="$2"; shift 2 ;;
      --node-samples) [ "$#" -ge 2 ] || { usage; exit 1; }; node_samples="$2"; shift 2 ;;
      --venue-node)   [ "$#" -ge 2 ] || { usage; exit 1; }; venue_node="$2"; shift 2 ;;
      --venue-guest)  [ "$#" -ge 2 ] || { usage; exit 1; }; venue_guest="$2"; shift 2 ;;
      --git-sha)  [ "$#" -ge 2 ] || { usage; exit 1; }; git_sha="$2"; shift 2 ;;
      --negatives)    negatives=1; negatives_explicit=1; shift ;;
      --no-negatives) negatives=0; negatives_explicit=1; shift ;;
      --keep)     keep_input=1; shift ;;
      *) usage; exit 1 ;;
    esac
  done
  case "$profile_input" in
    '') ;;
    debug|release) PROFILE="$profile_input" ;;
    *) die "--profile must be debug or release, got: $profile_input" ;;
  esac
  select_preset "$preset"
  # THE SHA IS RESOLVED FOR EVERY RUN, not only for one that assembles now.
  # `assemble-artifact` reads the run's OWN record rather than re-deriving,
  # so a run that recorded no sha cannot be assembled later — and the place to
  # find that out is here, in the first seconds, not after an hour.
  if [ -z "$git_sha" ]; then
    set +e
    git_sha="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null)"
    set -e
  fi
  if [ -z "$negatives" ]; then
    # These are the SELF-TEST's negative rows. They put extra
    # load on the measured server, so they are on for the self-test preset
    # and off for the measurement unless a caller asks.
    #
    # BUT `no_cache_client_fails_p2` IS A REQUIRED OBSERVATION NAME, and the
    # artifact contract says a missing required name is a REFUSAL -- so gating
    # it on the self-test preset meant the MEASUREMENT run, the only one whose
    # artifact is ever ingested, was the one run that never emitted it. The
    # whole cluster run would have been refused by the verb after the
    # fact. The required row must therefore run in the measurement
    # preset as well as the self-test preset.
    # (The row itself runs in the no-cache step further down, ungated.)
    # So the no-cache row is NOT one of the optional negatives: it runs in
    # EVERY preset. `stale_content` stays optional, because it is a self-test
    # demonstration rather than a required artifact observation.
    case "$preset" in
      selftest) negatives=1 ;;
      *) negatives=0 ;;
    esac
  fi
  # AN ARTIFACT REQUIRES THE NEGATIVE OBSERVATIONS.
  # The m10 preset defaults to negatives off, but
  # an artifact without their required observation
  # names is incomplete. Requesting an artifact
  # therefore enables negatives unless the caller
  # explicitly requested `--no-negatives`, in which
  # case the incompatible request is refused.
  if [ -n "$artifact_out" ] && [ "$negatives" -ne 1 ]; then
    if [ "$negatives_explicit" = "1" ]; then
      die "--no-negatives and --artifact are incompatible: seven of the artifact's REQUIRED observation names are the negative rows, and an artifact missing one is refused by the verb that reads it"
    fi
    note "--artifact is set, so the negative rows are ON: seven of the artifact's required observation names are those rows"
    negatives=1
  fi
  # THE FORCING ABOVE ONLY FIRES WHEN `--artifact` IS
  # PASSED. A run saved for later assembly does not request
  # the artifact at run time, so it needs an explicit
  # decision about negatives too. With the m10 default of
  # negatives off, such a run lacks required observation
  # rows and cannot supply an artifact. The check below
  # refuses an implicit choice: the operator must request
  # negatives for an artifact-producing run or explicitly
  # select `--no-negatives` for a run without them.
  #
  # The refusal leaves the run choice explicit:
  # negative rows add load to the measured server,
  # so enabling them requires an operator decision.
  if [ "$preset" = "m10" ] && [ "$negatives" -ne 1 ] && [ "$negatives_explicit" != "1" ]; then
    die "an m10-preset run with the negative rows OFF cannot produce a valid artifact: seven of the artifact's REQUIRED observation names ARE those rows, and the assemble-later flow (no --artifact on the run) does not turn them on. Pass --negatives for a run an artifact will be assembled from, or --no-negatives to state deliberately that this run is not one."
  fi
  [ "$keep_input" -eq 0 ] || SELF_TEST_KEEP=1

  # EVERYTHING CHECKABLE IS CHECKED HERE, before a stack is started:
  # anything the harness checks it checks EARLY, to refuse a doomed run
  # before cluster time is spent.
  require_tools
  require_self_test_tools
  require_run_tools
  require_unprivileged
  [ -f "$GEN_TREE" ] || die "the promoted tree generator is missing: $GEN_TREE"
  [ -x "$STACK_SCRIPT" ] || die "stack.sh is not executable: $STACK_SCRIPT"
  RUN_GRAN="$REPO_ROOT/target/$PROFILE/gran"
  [ -x "$RUN_GRAN" ] || die "gran is not executable; build the $PROFILE profile first: $RUN_GRAN"
  [ -x "$REPO_ROOT/target/$PROFILE/granary-server" ] \
    || die "granary-server is not executable; build the $PROFILE profile first"
  RUN_VOLUME="$volume"
  [ -n "$RUN_VOLUME" ] || die "the run was given an empty volume name"

  # THE ARTIFACT'S OWN PRECONDITIONS, CHECKED HERE — before a stack is
  # started. Every one of them is knowable now, and
  # anything the harness checks it checks EARLY, to refuse a doomed run before
  # cluster time is spent. A run that produced eleven snapshots and then
  # discovered it had no venue name is an hour thrown away.
  if [ -n "$artifact_out" ]; then
    case "$artifact_out" in
      /*) ;;
      *) die "--artifact must be an absolute path, got: $artifact_out" ;;
    esac
    case "$artifact_out" in
      "$REPO_ROOT"|"$REPO_ROOT"/*)
        die "--artifact points inside the repository ($artifact_out); the artifact and the log stay OUTSIDE it, so a failed or rejected run leaves nothing behind to be mistaken for a result" ;;
    esac
    [ ! -e "$artifact_out" ] \
      || die "the artifact destination already exists: $artifact_out"
    [ -d "$(dirname "$artifact_out")" ] \
      || die "the artifact destination's parent directory does not exist: $(dirname "$artifact_out")"
    [ -n "$node_samples" ] \
      || die "--artifact requires --node-samples: the harness CANNOT sample the node itself (guest to host is filtered by the PVE firewall), and a run that cannot produce the samples is rejected — a missing measurement of the measurement is not a pass"
    [ -f "$node_samples" ] \
      || die "the node-CPU samples file does not exist: $node_samples"
    [ -n "$venue_node" ] || die "--artifact requires --venue-node"
    [ -n "$venue_guest" ] || die "--artifact requires --venue-guest"
    case "$git_sha" in
      *[!0-9a-f]*|'') die "the harness git sha is not 40 lowercase hex characters: [$git_sha]. Neither venue carries git, so pass --git-sha <40 hex> read from the machine the tree was shipped from" ;;
    esac
    [ "${#git_sha}" -eq 40 ] \
      || die "the harness git sha is ${#git_sha} characters, want 40: [$git_sha]"
  else
    [ -z "$node_samples" ] && [ -z "$venue_node" ] && [ -z "$venue_guest" ] \
      || die "--node-samples, --venue-node and --venue-guest describe an ARTIFACT and there is nothing to put them in without --artifact"
  fi

  local created
  if [ -n "$workdir" ]; then
    mkdir -p "$workdir" || die "could not create the workdir parent: $workdir"
    created="$(mktemp -d "$workdir/m10-run.XXXXXX")" \
      || die "could not create a fresh run directory under $workdir"
  else
    created="$(mktemp -d "${TMPDIR:-/tmp}/m10-run.XXXXXX")" \
      || die "could not create a run directory under ${TMPDIR:-/tmp}"
  fi
  SELF_TEST_WORKDIR="$(cd "$created" && pwd -P)"
  SELF_TEST_WORKDIR_OWNED=1
  case "$SELF_TEST_WORKDIR" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
      remove_owned_workdir "$SELF_TEST_WORKDIR" "$SELF_TEST_WORKDIR_OWNED"
      die "the run directory must not be inside the repository: $SELF_TEST_WORKDIR"
      ;;
  esac
  trap self_test_cleanup EXIT

  local W="$SELF_TEST_WORKDIR"
  # `$H` HOLDS THE ELEVEN SNAPSHOTS AND NOTHING ELSE. The measured server's
  # pid file, readiness address and multi-megabyte log go to `$HARNESS_STATE`
  # instead: a directory a later phase will assemble from must not also be
  # where the run drops its own bookkeeping.
  local SRC="$W/src" H="$W/snapshots" OUT="$W/logs" NEG="$W/negatives"
  local HARNESS_STATE="$W/harness"
  STACK_STATE="$W/stack"
  mkdir -p "$SRC" "$H" "$OUT" "$NEG" "$HARNESS_STATE"
  # THE VENUE AND THE HARNESS SHA, RECORDED NOW — on the machine that is about
  # to take the measurement, not on whichever machine assembles it later. Every
  # assembly reads this file; see `write_venue_record`.
  write_venue_record "$W/venue.tsv" "$git_sha"
  if [ -z "$git_sha" ]; then
    note "this run records NO harness git sha (no --git-sha and no git on this venue), so \`assemble-artifact --run-dir $W\` will REFUSE it. Pass --git-sha <40 hex> to the RUN if this run's records are meant to become an artifact."
  fi
  TIMELINE_FILE="$W/timeline.tsv"
  : > "$TIMELINE_FILE"

  # THE RUN ID IS MINTED ONCE, HERE, and the run aborts before any process
  # starts if it is empty. Five files stamped from an unset `$RUN_ID` satisfy
  # equality just as well as five stamped from a real one.
  local stamp rand_hex
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  rand_hex="$(od -An -N4 -v -tx1 /dev/urandom | tr -d ' \n')"
  [ "${#rand_hex}" -eq 8 ] || die "could not mint 8 hex characters for the run id (got [$rand_hex])"
  RUN_ID="m10-$stamp-$rand_hex"
  [ -n "$RUN_ID" ] || die "the run id is empty"
  # The negative rows' OWN run id, minted with the real one and never equal to
  # it. Their roles must come from the closed vocabulary (the writers refuse
  # anything else), so the run id is the ONLY thing keeping a snapshot written
  # by a deliberately-broken process out of the eleven — and the same
  # separation carries the clock processes' poll snapshots, which reuse a
  # client role for the same reason.
  local neg_run_id="$RUN_ID-neg"
  local clock_run_id="$RUN_ID-clock"

  echo "m10-propagate: propagation run"
  echo "  workdir  : $W"
  echo "  profile  : $PROFILE"
  echo "  preset   : $preset"
  echo "  volume   : $RUN_VOLUME"
  echo "  run id   : $RUN_ID"
  echo "  negatives: $negatives"
  echo

  # ----------------------------- THE SEQ PARSE, PROVEN BEFORE ANYTHING RUNS
  #
  # A pure-function control, and it runs FIRST because it costs nothing and
  # the run cannot recover from a misparsed n. The three fixtures are the
  # three outcomes the parse has to tell apart: the MEASURED shape (the
  # three-line key block `gran publish` prints only on a first run, so the
  # wanted line is FOUR — the reason a positional parse is refused), a log
  # with no matching line at all, and a log with two.
  local seq_fixture="$OUT/seq-fixture.log" parsed
  {
    printf 'generated publishing key: /tmp/state/publish.key\n'
    printf '  seed  0000000000000000000000000000000000000000000000000000000000000000\n'
    printf '  pub   1111111111111111111111111111111111111111111111111111111111111111\n'
    printf 'published %s seq 41 epoch 1 route=server-seam\n' "$RUN_VOLUME"
    printf 'manifest-root blake3:2222222222222222222222222222222222222222222222222222222222222222\n'
  } > "$seq_fixture"
  parsed="$(parse_stack_seq "$seq_fixture" "$RUN_VOLUME")"
  if [ "$parsed" = "41" ]; then
    row_pass Q1 "the seq parse reads 41 from the line at POSITION FOUR, behind the three-line key block gran publish prints only on a first run — matched by pattern, so the position does not matter"
  else
    row_fail Q1 "the seq parse read [$parsed] from $seq_fixture, want 41"
  fi

  local seq_none="$OUT/seq-none.log"
  {
    printf 'generated publishing key: /tmp/state/publish.key\n'
    printf 'published %s-other seq 41 epoch 1\n' "$RUN_VOLUME"
    printf 'published %s seq 41\n' "$RUN_VOLUME"
  } > "$seq_none"
  expect_failure "$OUT/q2.log" parse_stack_seq "$seq_none" "$RUN_VOLUME"
  if [ "$EXPECT_RC" -ne 0 ] && grep -a -F -q -- 'found 0' "$EXPECT_OUT"; then
    row_pass Q2 "the seq parse REFUSES a log with NO matching line — a different volume and a truncated line are both non-matches, not near-misses (rc=$EXPECT_RC)"
  else
    row_fail Q2 "a log with no published-seq line did not stop the parse (rc=$EXPECT_RC); see $EXPECT_OUT"
  fi

  local seq_two="$OUT/seq-two.log"
  {
    printf 'published %s seq 41 epoch 1\n' "$RUN_VOLUME"
    printf 'published %s seq 42 epoch 2\n' "$RUN_VOLUME"
  } > "$seq_two"
  expect_failure "$OUT/q3.log" parse_stack_seq "$seq_two" "$RUN_VOLUME"
  if [ "$EXPECT_RC" -ne 0 ] && grep -a -F -q -- 'found 2' "$EXPECT_OUT"; then
    row_pass Q3 "the seq parse REFUSES a log with TWO matching lines instead of taking one of them (rc=$EXPECT_RC)"
  else
    row_fail Q3 "a log with two published-seq lines did not stop the parse (rc=$EXPECT_RC); see $EXPECT_OUT"
  fi

  # ------------------- THE SNAPSHOT INTEGER BOUND, PROVEN BEFORE ANYTHING RUNS
  #
  # A pure-function control on `snapshot_u64`, in the pre-flight block for the
  # same reason as the seq parse: it costs nothing, and without it every row
  # below that multiplies or sums a snapshot integer is fail-open at scale.
  #
  # THREE FIXTURES, because a refusal on its own is satisfied by a function that
  # refuses everything: `2^53 - 1` must be read back INTACT, `2^53` exactly must
  # be refused, and `1.4e18` — the value from the worked case where E7's
  # ten-term sum wraps to a negative and reports PASS — must be refused by digit
  # count, before bash arithmetic can saturate it into range. Both refusals must
  # NAME THE FIELD: a message that does not is unactionable in a file carrying a
  # dozen counters.
  local bound_fixture="$OUT/bound-fixture.json" bound_ok=1 bound_got
  printf '{ "ok": 9007199254740991, "at_bound": 9007199254740992, "huge": 1400000000000000000 }\n' \
    > "$bound_fixture"
  bound_got="$(snapshot_u64 "$bound_fixture" "ok" "bound fixture")"
  if [ "$bound_got" != "9007199254740991" ]; then
    note "Q4: the in-range value read back as [$bound_got], want 9007199254740991"
    bound_ok=0
  fi
  # BOTH FRAGMENTS, because "a refusal naming the field" is also what
  # `snapshot_field` emits for a field that is ABSENT — so a fixture with a
  # typo would satisfy a one-fragment check while the bound never fired.
  expect_failure "$OUT/q4-at-bound.log" snapshot_u64 "$bound_fixture" "at_bound" "bound fixture"
  if [ "$EXPECT_RC" -eq 0 ] \
      || ! grep -a -F -q -- "'at_bound'" "$EXPECT_OUT" \
      || ! grep -a -F -q -- 'at or above the' "$EXPECT_OUT"; then
    note "Q4: 2^53 exactly was accepted, or the refusal did not name the field (rc=$EXPECT_RC); see $EXPECT_OUT"
    bound_ok=0
  fi
  expect_failure "$OUT/q4-huge.log" snapshot_u64 "$bound_fixture" "huge" "bound fixture"
  if [ "$EXPECT_RC" -eq 0 ] \
      || ! grep -a -F -q -- "'huge'" "$EXPECT_OUT" \
      || ! grep -a -F -q -- 'at or above the' "$EXPECT_OUT"; then
    note "Q4: a 19-digit counter was accepted, or the refusal did not name the field (rc=$EXPECT_RC); see $EXPECT_OUT"
    bound_ok=0
  fi
  if [ "$bound_ok" -eq 1 ]; then
    row_pass Q4 "snapshot integers are bounded at $SNAPSHOT_U64_MAX (2^53) where they ENTER: 2^53-1 reads back intact, 2^53 exactly is REFUSED, and 1.4e18 is refused by digit count before strtoimax can saturate it — and both refusals name the field. Bash arithmetic is 64-bit signed, so without this every product and sum these rows compute wraps in the direction that makes an upper bound PASS"
  else
    row_fail Q4 "the snapshot integer bound did not hold; a counter large enough to wrap bash's signed arithmetic would reach 3 x novel_bytes, 100 x verify_bytes and E7's ten-term sum, each of which then reports a PASS it has not established"
  fi

  # THE PRE-FLIGHT ROWS MUST ABORT, NOT MERELY COUNT.
  #
  # `row_fail` increments a counter and returns; that is right for the rows
  # AFTER the run, whose whole point is to report every failure in one pass.
  # It is WRONG here. These three rows must refuse early:
  # anything the harness checks it checks EARLY, to refuse a doomed run
  # before cluster time is spent — and a counter lets corpus generation, a
  # MinIO start, a server start and a 2 GiB publish all proceed behind a seq
  # parser that has already been shown broken. So a failed pre-flight row
  # ends the run here, before any stack is started: the check below dies
  # on a non-zero failure count
  # instead of letting the run continue.
  if [ "$SELF_TEST_FAILURES" -ne 0 ]; then
    die "$SELF_TEST_FAILURES pre-flight row(s) FAILED before any stack was started; refusing to spend a run behind a broken seq parse — see the rows above"
  fi

  # ------------------------------------------------------------ the corpus
  generate_corpus "$SRC" "$OUT/gen-tree.log"
  local subtree_path="$SRC/$CORPUS_SUBTREE"
  [ -d "$subtree_path" ] \
    || die "the preset names $CORPUS_SUBTREE as the changed subtree and the generated corpus has no such directory under $SRC"

  # ---- THE EXPECTED DIGESTS AND SIZES, on the publisher's SOURCE tree
  local v_n_line v_n_digest v_n_files apparent
  v_n_line="$(subtree_digest "$SRC" "expected(v_n whole tree)")"
  v_n_digest="$(walk_field_digest "$v_n_line")"
  v_n_files="$(walk_field_count "$v_n_line")"
  apparent="$(apparent_bytes "$SRC" "corpus apparent(v_n)" "$v_n_files")"
  [ "$apparent" -ge "$CORPUS_MIN_APPARENT_BYTES" ] \
    || die "the corpus is $apparent B apparent and the corpus floor is $CORPUS_MIN_APPARENT_BYTES B (8 MiB): below it the warm read's fixed cost stops being negligible and the 100x cold/warm bound stops discriminating, so the run is REFUSED rather than reporting a bound that no longer means anything"

  # ------------------ C1: THE WHOLE-TREE WALK REALLY WALKED THE WHOLE TREE
  #
  # `gen-tree.py` emits EXACTLY `--files` regular files, so the walker's count
  # is checkable against the PRESET rather than only against itself. Without
  # this row a harness whose "whole tree" expectation had been narrowed to the
  # changed subtree — the expected `v_n` digest taken on `$subtree_path` and the
  # warm-ups walking the same path — agrees with itself everywhere later: E4's
  # digests match because BOTH sides moved, and E6's cold/warm ratio is
  # scale-free. On the selftest preset the corpus floor catches it by accident
  # (the subtree is 4.8 MB against an 8 MiB floor); on the m10 preset the
  # subtree is 131 MB and NOTHING catches it. An accident that holds for one
  # preset is not a control.
  #
  # AND IT ABORTS rather than only counting, for the reason the pre-flight block
  # gives: a doomed 2 GiB run costs an hour of cluster time.
  if [ "$v_n_files" = "$CORPUS_FILES" ]; then
    row_pass C1 "the expected v_n walk covered $v_n_files regular files, exactly the $CORPUS_FILES the preset asked gen-tree.py for — so the whole-tree side of every later digest is the WHOLE tree"
  else
    row_fail C1 "the expected v_n walk covered $v_n_files regular files and the preset generated $CORPUS_FILES; a whole-tree expectation narrowed to a subtree agrees with a warm-up narrowed the same way, and every later digest row passes over it"
  fi
  if [ "$SELF_TEST_FAILURES" -ne 0 ]; then
    die "$SELF_TEST_FAILURES row(s) FAILED on the corpus, before any stack was started; refusing to spend a run on a corpus that is not the one the preset names — see the rows above"
  fi

  # ONE REAL PATH out of the corpus, for the stale-endpoint probe below. It is
  # read from a FILE rather than out of a `find | sort | sed 1p` pipeline: under
  # `set -o pipefail` an early-exiting reader SIGPIPEs its producer and the
  # substitution fails for a reason that has nothing to do with the corpus.
  ( cd "$SRC" && find . -type f -print ) | LC_ALL=C sort > "$OUT/corpus-files.txt"
  local probe_rel
  probe_rel="$(sed -n '1p' "$OUT/corpus-files.txt")"
  probe_rel="${probe_rel#./}"
  case "$probe_rel" in
    ''|*[!A-Za-z0-9._/-]*)
      die "the corpus's first path is not a plain name this harness will hand to a command line: [$probe_rel]" ;;
  esac

  local sub_n_line sub_n_digest sub_n_files changed_subtree_bytes
  sub_n_line="$(subtree_digest "$subtree_path" "expected(v_n changed subtree)")"
  sub_n_digest="$(walk_field_digest "$sub_n_line")"
  sub_n_files="$(walk_field_count "$sub_n_line")"
  changed_subtree_bytes="$(apparent_bytes "$subtree_path" "changed subtree bytes(v_n)" "$sub_n_files")"

  echo "  corpus   : $apparent B apparent over $v_n_files regular files"
  echo "  subtree  : $CORPUS_SUBTREE — $changed_subtree_bytes B over $sub_n_files regular files"
  echo "  v_n tree digest    : $v_n_digest"
  echo "  v_n subtree digest : $sub_n_digest"
  echo

  # -------------------------------------------------------------- the stack
  local stack_out="$OUT/stack-start.log" stack_rc
  set +e
  "$STACK_SCRIPT" start --source-dir "$SRC" --volume "$RUN_VOLUME" \
    --state-dir "$STACK_STATE" > "$stack_out" 2> "$OUT/stack-start.err"
  stack_rc=$?
  set -e
  if [ "$stack_rc" -ne 0 ]; then
    cat "$OUT/stack-start.err" >&2
    die "stack.sh start failed (rc=$stack_rc)"
  fi

  # The four contract lines, read as DATA. `GRAN_ENDPOINT` is captured as
  # STACK_ENDPOINT and NEVER exported: exporting it would put the UNMEASURED
  # endpoint into every child's environment, and every measured command line
  # carries `--endpoint "$MEASURED_ENDPOINT"` explicitly instead.
  local STACK_ENDPOINT line key value
  STACK_ENDPOINT=""; RUN_PIN=""; RUN_ROOT_KEY=""
  local stack_volume=""
  while IFS= read -r line; do
    key="${line%%=*}"
    value="${line#*=}"
    case "$key" in
      GRAN_ENDPOINT) eval "STACK_ENDPOINT=$value" ;;
      GRAN_PIN) eval "RUN_PIN=$value" ;;
      GRAN_ROOT_KEY) eval "RUN_ROOT_KEY=$value" ;;
      GRAN_VOLUME) eval "stack_volume=$value" ;;
      *) die "stack.sh printed an unexpected contract line: $line" ;;
    esac
  done < "$stack_out"
  [ -n "$STACK_ENDPOINT" ] || die "stack.sh printed no GRAN_ENDPOINT"
  [ -n "$RUN_PIN" ] || die "stack.sh printed no GRAN_PIN"
  [ -n "$RUN_ROOT_KEY" ] || die "stack.sh printed no GRAN_ROOT_KEY"
  [ "$stack_volume" = "$RUN_VOLUME" ] \
    || die "stack.sh published volume [$stack_volume], want $RUN_VOLUME"

  # ---------------------------------------------------------- WHERE `n` IS
  local seq_n seq_next
  seq_n="$(parse_stack_seq "$STACK_STATE/publish.log" "$RUN_VOLUME")"
  seq_next=$((seq_n + 1))
  echo "  seq      : n=$seq_n (from $STACK_STATE/publish.log, by pattern), workload at n+1=$seq_next"

  # ------------------------------------------------ the MEASURED server
  start_measured_server "$STACK_STATE" "$HARNESS_STATE" "$RUN_ID" "$H/server.json"
  assert_distinct_endpoints "$STACK_ENDPOINT" "$MEASURED_ENDPOINT"
  echo "  measured : $MEASURED_ENDPOINT (stack was $STACK_ENDPOINT), pid $MEASURED_PID"
  terminate_stack_server "$STACK_STATE"

  # ------------------- R1: the stack's server really IS down
  #
  # `terminate_stack_server` is what makes the stale endpoint stale, and NOTHING
  # IN THIS RUN NOTICED IF IT WAS NEVER CALLED. That matters more here than a
  # missing call usually does: the stack's server is the only other listener
  # holding the SAME certificate and therefore the same pin, so a measured
  # process that reached it would be refused by nothing — no pin check, no
  # endpoint check on the way out, and the measured request total would simply
  # be short. The endpoint residual is discharged by this termination and by no
  # other check in the run. The S3 fixture above is transplanted here, where the
  # run that matters is.
  #
  # CACHELESS on purpose: with `--root-key` and a cache holding a resolvable
  # head, `gran cat` is DESIGNED to degrade to the cache rather than fail
  # (CAT_HELP), which would turn this control green for the wrong reason. And
  # the CONNECTION REFUSAL is asserted specifically, not merely a non-zero exit:
  # "the client failed" is satisfied by a mistyped flag, a pin mismatch or a
  # missing path, none of which says anything about whether the terminated
  # endpoint still serves. The path is a real file of the published `v_n` tree,
  # so with a live server the probe would SUCCEED — which is what makes the
  # refusal evidence rather than a coincidence.
  local stale_rc stale_refused_rc
  set +e
  "$RUN_GRAN" cat "$RUN_VOLUME" "$probe_rel" \
    --endpoint "$STACK_ENDPOINT" --pin "$RUN_PIN" --root-key "$RUN_ROOT_KEY" \
    > "$OUT/stale.out" 2> "$OUT/stale.err"
  stale_rc=$?
  grep -a -F -q -- 'Connection refused' "$OUT/stale.err"
  stale_refused_rc=$?
  set -e
  if [ "$stale_rc" -ne 0 ] && [ "$stale_refused_rc" -eq 0 ]; then
    row_pass R1 "a cacheless gran cat of $probe_rel against the stack endpoint $STACK_ENDPOINT exits $stale_rc with a CONNECTION REFUSED on its stderr — the second listener that shares this run's certificate and pin is really gone, and the endpoint residual is discharged by a number rather than by having called the function"
  else
    row_fail R1 "stale-endpoint probe rc=$stale_rc, 'Connection refused' grep rc=$stale_refused_rc. The stack's server shares the measured server's certificate and pin, so a measured process that reached it would be refused by nothing; stderr in $OUT/stale.err"
  fi
  echo

  # ------------------------------------------------- the nine client processes
  #
  # THREE PROCESSES PER CLIENT ON ONE CACHE-DIR, because the client's counters are
  # LIFETIME-SCOPED: a warm-up and a workload inside one process would report
  # the warm-up's bytes inside the workload's total. Across k they run
  # CONCURRENTLY against ONE shared server, which is the measured fan-out
  # shape; within k they are strictly ordered, because warmup-verify has
  # to read a cache warmup-k has finished filling.
  local k cache_dir mnt_dir warmup_caches_checked=0
  local -a unit_pids
  for k in 1 2 3; do
    cache_dir="$W/cache-$k"
    mnt_dir="$W/mnt-$k"
    mkdir -p "$cache_dir" "$mnt_dir"
    # The warm-up's cache-dir MUST be empty: a cache carrying anything at all
    # makes `warmup-k.response_bytes` a number about an unknown starting
    # state, and the cold/warm ratio below rests on the cold side being cold.
    if [ -n "$(ls -A "$cache_dir" 2>/dev/null)" ]; then
      die "client $k: the cache directory $cache_dir is not empty; a warm-up on a dirty cache measures nothing"
    fi
    warmup_caches_checked=$((warmup_caches_checked + 1))
  done
  # THE OBSERVATION IS REGISTERED WHERE THE FACT IS ESTABLISHED, not written as
  # a literal in the observations block three hundred lines below. It is
  # fail-CLOSED — a dirty cache-dir `die`s above and no observation file is
  # ever written — but a `pass` that comes from control flow rather than from a
  # named check can conceal whether every required check ran, so the count
  # is asserted and the registration is here.
  [ "$warmup_caches_checked" -eq 3 ] \
    || die "the warm-up cache-dir check ran $warmup_caches_checked times, want 3"
  obs_set warmup_cache_dirs_were_empty pass

  unit_pids=()
  for k in 1 2 3; do
    spawn_mount_walk "warmup-$k" "$RUN_ID" "$W/mnt-$k" "$W/cache-$k" \
      "$seq_n" "$H/warmup-$k.json" "" "$OUT" "warmup-$k"
    unit_pids+=("$SPAWNED_PID")
  done
  join_units "the warm-ups" "${unit_pids[@]}"

  unit_pids=()
  for k in 1 2 3; do
    spawn_mount_walk "warmup-verify-$k" "$RUN_ID" "$W/mnt-$k" "$W/cache-$k" \
      "$seq_n" "$H/warmup-verify-$k.json" "" "$OUT" "warmup-verify-$k"
    unit_pids+=("$SPAWNED_PID")
  done
  join_units "the warm-up verifications" "${unit_pids[@]}"

  # BOTH warm-ups have ended. Everything after this line happens against
  # chunks that did not exist while those caches were being filled, which is
  # what "NOT any v_(n+1) chunk" means.
  local t_warmups_ended
  t_warmups_ended="$(timeline_mark warmups_ended)"

  # ------------------------------------------------------------- the delta
  #
  # THE COMPLEMENT IS RECORDED FIRST. Nothing checked that the delta touched
  # ONLY the changed subtree; a mutation demonstrated the gap when it
  # rewrote a file outside the subtree and named that file as the sentinel.
  # Everything downstream then agreed with itself, because every check was
  # about the subtree.
  complement_manifest "$SRC" "$subtree_path" "$OUT/complement.before"
  local delta_line delta_files delta_bytes delta_seen
  delta_line="$(generate_delta "$subtree_path" "$OUT/delta.out" "$OUT/delta.picked")"
  delta_files="$(printf '%s' "$delta_line" | awk '{ print $1 }')"
  delta_bytes="$(printf '%s' "$delta_line" | awk '{ print $2 }')"
  delta_seen="$(printf '%s' "$delta_line" | awk '{ print $3 }')"
  [ "$delta_seen" = "$sub_n_files" ] \
    || die "the delta walked $delta_seen regular files under $CORPUS_SUBTREE and the harness's walker hashed $sub_n_files; the two disagree about what the changed subtree is"
  # ---------------- C3: THE DELTA TOUCHED THE CHANGED SUBTREE AND NOTHING ELSE
  #
  # The comparison, and then a POSITIVE CONTROL, because a manifest that never
  # moves passes this row for free. A scratch file is created outside the
  # subtree, the manifest is taken again and must DIFFER, the file is removed,
  # and the manifest must return to the original — which also proves the tree
  # is exactly as it was before this row ran, seconds before it is published.
  complement_manifest "$SRC" "$subtree_path" "$OUT/complement.after"
  local complement_same=1 complement_moved=0 complement_restored=0
  cmp -s "$OUT/complement.before" "$OUT/complement.after" || complement_same=0
  local complement_probe="$SRC/.m10-complement-probe"
  [ ! -e "$complement_probe" ] \
    || die "the complement control's scratch path already exists: $complement_probe"
  printf 'a file the delta did not write\n' > "$complement_probe"
  complement_manifest "$SRC" "$subtree_path" "$OUT/complement.probe"
  cmp -s "$OUT/complement.after" "$OUT/complement.probe" || complement_moved=1
  rm -f "$complement_probe"
  complement_manifest "$SRC" "$subtree_path" "$OUT/complement.restored"
  cmp -s "$OUT/complement.after" "$OUT/complement.restored" && complement_restored=1
  if [ "$complement_same" -eq 1 ] && [ "$complement_moved" -eq 1 ] \
      && [ "$complement_restored" -eq 1 ]; then
    row_pass C3 "the delta moved NOTHING outside $CORPUS_SUBTREE: the (path, size, mtime) manifest of the rest of $SRC is byte-identical across the delta, and the same manifest DOES move for one scratch file created outside the subtree and returns when it is removed — so the comparison is a check and not a constant"
  else
    row_fail C3 "the complement of $CORPUS_SUBTREE changed across the delta (identical=$complement_same), or the control could not move it (moved=$complement_moved restored=$complement_restored); compare $OUT/complement.before and $OUT/complement.after"
  fi

  local t_delta_generated
  t_delta_generated="$(timeline_mark delta_generated)"

  # THE EXPECTED v_(n+1) DIGEST, computed on the publisher's SOURCE tree
  # BEFORE the publish. This is the content-identity predicate the byte
  # workload is judged against: without it a client serving the OLD
  # content passes every floor with roughly zero novel bytes, so those
  # floors alone do not establish that the changed subtree arrived.
  local sub_n1_line sub_n1_digest sub_n1_files
  sub_n1_line="$(subtree_digest "$subtree_path" "expected(v_(n+1) changed subtree)")"
  sub_n1_digest="$(walk_field_digest "$sub_n1_line")"
  sub_n1_files="$(walk_field_count "$sub_n1_line")"
  [ "$sub_n1_files" = "$sub_n_files" ] \
    || die "the delta changed the changed subtree's FILE COUNT from $sub_n_files to $sub_n1_files; the recorded changed_subtree_bytes would then describe a tree that no longer exists"
  [ "$sub_n1_digest" != "$sub_n_digest" ] \
    || die "the delta rewrote $delta_files files and the changed subtree's digest did not move; a delta that changes no byte makes the whole measurement vacuous"
  # BOTH EXPECTED DIGESTS NOW EXIST, and `gran publish` has not run — which is
  # the whole content of this observation, so it is registered HERE, at the
  # only point in the run where the claim is true by position rather than by
  # assertion.
  obs_set expected_digests_computed_before_publish pass
  echo "  delta    : $delta_files of $delta_seen files rewritten, $delta_bytes B; v_(n+1) subtree digest $sub_n1_digest"

  # ------------------------------------------------------------ THE SENTINEL
  #
  # ONE file, taken from the delta's own picked list — so it is a file whose
  # content DEMONSTRABLY differs between v_n and v_(n+1), and both its hashes
  # are known. The two clocks poll it and stop when its bytes hash to the
  # v_(n+1) value: content identity, never "the read succeeded".
  #
  # THE NEW HASH IS RE-DERIVED FROM THE SOURCE TREE and compared against the
  # delta's claim. The delta is the only code that can report the OLD hash (the
  # bytes are gone once they are overwritten) and that one number is taken on
  # trust; every other number it reports about the sentinel is checked against
  # the file it says it wrote.
  local sentinel_line sentinel_rel sentinel_old sentinel_new sentinel_check
  sentinel_line="$(sed -n '1p' "$OUT/delta.picked")"
  [ -n "$sentinel_line" ] || die "the delta's picked list is empty; there is no sentinel for the clocks to poll"
  sentinel_rel="$(printf '%s' "$sentinel_line" | awk -F '\t' '{ print $1 }')"
  sentinel_old="$(printf '%s' "$sentinel_line" | awk -F '\t' '{ print $2 }')"
  sentinel_new="$(printf '%s' "$sentinel_line" | awk -F '\t' '{ print $3 }')"
  sentinel_rel="${sentinel_rel#./}"
  case "$sentinel_rel" in
    ''|*[!A-Za-z0-9._/-]*)
      die "the sentinel's path is not a plain name this harness will hand to a command line: [$sentinel_rel]" ;;
  esac
  # THE PATTERN ABOVE ADMITS `.` AND `/`, SO IT ADMITS `..`. Containment is a
  # separate question from spelling and is asked separately; see
  # `assert_sentinel_contained`.
  assert_sentinel_contained "$subtree_path" "$sentinel_rel" "the sentinel"

  # ---------------- C2: THE CONTAINMENT REFUSAL, FIRED ON ALL THREE OF ITS ARMS
  #
  # On a throwaway fixture rather than on the corpus, because two of the three
  # probes need a file that does not belong in the tree about to be published.
  # The ordinary name is the positive control: a guard that refused everything
  # would satisfy "it refused" three times over and say nothing.
  local contain_dir="$NEG/containment"
  mkdir -p "$contain_dir/inside/sub" "$contain_dir/outside"
  printf 'outside\n' > "$contain_dir/outside/f.dat"
  printf 'inside\n' > "$contain_dir/inside/sub/g.dat"
  ln -s ../../outside/f.dat "$contain_dir/inside/escape.dat" \
    || die "could not build the containment control's symlink"
  local contain_ok_rc contain_dotdot_rc contain_abs_rc contain_link_rc
  set +e
  ( assert_sentinel_contained "$contain_dir/inside" "sub/g.dat" "C2 ordinary" ) \
    > "$NEG/c2-ordinary.log" 2>&1
  contain_ok_rc=$?
  set -e
  expect_failure "$NEG/c2-dotdot.log" \
    assert_sentinel_contained "$contain_dir/inside" "sub/../../outside/f.dat" "C2 dot-dot"
  contain_dotdot_rc="$EXPECT_RC"
  expect_failure "$NEG/c2-absolute.log" \
    assert_sentinel_contained "$contain_dir/inside" "/etc/hostname" "C2 absolute"
  contain_abs_rc="$EXPECT_RC"
  expect_failure "$NEG/c2-symlink.log" \
    assert_sentinel_contained "$contain_dir/inside" "escape.dat" "C2 symlink"
  contain_link_rc="$EXPECT_RC"
  if [ "$contain_ok_rc" -eq 0 ] && [ "$contain_dotdot_rc" -ne 0 ] \
      && [ "$contain_abs_rc" -ne 0 ] && [ "$contain_link_rc" -ne 0 ]; then
    row_pass C2 "the sentinel's containment check ACCEPTS an ordinary name (rc=$contain_ok_rc) and refuses all three escapes: a '..' component (rc=$contain_dotdot_rc), an absolute path (rc=$contain_abs_rc) and a SYMLINK that leaves the subtree with no '..' anywhere in the name (rc=$contain_link_rc). The symlink arm is the one a spelling rule cannot give you, and the escape it closes was measured: gran cat refuses '..' by its own rule while a FUSE mount normalises it, so the two instruments read different files"
  else
    row_fail C2 "the containment check did not separate the cases: ordinary rc=$contain_ok_rc, dot-dot rc=$contain_dotdot_rc, absolute rc=$contain_abs_rc, symlink rc=$contain_link_rc; see $NEG/c2-*.log"
  fi
  case "$sentinel_old$sentinel_new" in
    *[!0-9a-f]*) die "the delta reported non-hex sentinel hashes: old=[$sentinel_old] new=[$sentinel_new]" ;;
  esac
  [ "${#sentinel_old}" -eq 64 ] && [ "${#sentinel_new}" -eq 64 ] \
    || die "the delta reported sentinel hashes of ${#sentinel_old} and ${#sentinel_new} characters, want 64 each"
  [ "$sentinel_old" != "$sentinel_new" ] \
    || die "the sentinel $sentinel_rel hashes the same before and after the delta; a clock polling it could never distinguish v_n from v_(n+1) and would stop on the first read"
  sentinel_check="$(sha256_of_file "$subtree_path/$sentinel_rel" "the sentinel on the source tree")"
  [ "$sentinel_check" = "$sentinel_new" ] \
    || die "the delta says it wrote $sentinel_new into $sentinel_rel and the source tree holds $sentinel_check; the clocks would hunt content nobody published"
  local sentinel_path="$CORPUS_SUBTREE/$sentinel_rel"
  echo "  sentinel : $sentinel_path — v_n $sentinel_old, v_(n+1) $sentinel_new"

  # ------------------------- THE NO-PUBLISH NEGATIVE, RUN BEFORE THE PUBLISH
  #
  # "With the publish deliberately not performed, the harness must FAIL both
  # clocks rather than report a small number. A demo that cannot fail is not a
  # gate." Constructed LITERALLY: at this instant the delta exists on the
  # publisher's source tree and `gran publish` has not run, so the v_(n+1)
  # sentinel the clocks hunt is not in the store. Same server, same instruments,
  # same expected hash as the real clocks a moment later — the ONLY difference
  # is whether the publish has happened, which is what makes the pair a
  # before/after control rather than two unrelated tests.
  #
  # THE CAP IS SHORT because no cap can produce content that does not exist;
  # the length only buys polls.
  local nopublish_a_rc="" nopublish_b_rc="" nopublish_t0 nopublish_cache=""
  local nopublish_hint_ms=""
  if [ "$negatives" -eq 1 ]; then
    mkdir -p "$NEG/mnt-nopub" "$NEG/clocks"
    nopublish_t0="$(now_ms)"
    spawn_clock_a 1 "$sentinel_path" "$sentinel_new" "$nopublish_t0" \
      "$CLOCK_NEGATIVE_CAP_SECONDS" "$NEG" "nopub-a" "$NEG/clocks" "$neg_run_id"
    local nopub_a_pid="$SPAWNED_PID"
    spawn_clock_b 1 "$sentinel_path" "$sentinel_new" "$nopublish_t0" \
      "$CLOCK_NEGATIVE_CAP_SECONDS" "$NEG/mnt-nopub" "$NEG/cache-nopub" "$NEG" "nopub-b"
    local nopub_b_pid="$SPAWNED_PID"
    wait_into_rc "$nopub_a_pid"
    nopublish_a_rc="$WAITED_RC"
    wait_into_rc "$nopub_b_pid"
    nopublish_b_rc="$WAITED_RC"
    if [ -f "$NEG/nopub-b.lastcache" ]; then
      nopublish_cache="$(sed -n '1p' "$NEG/nopub-b.lastcache")"
      nopublish_hint_ms="$(sed -n '1p' "$NEG/nopub-b.lastcache.ms")"
    fi
    # A NON-ZERO EXIT IS NOT ENOUGH, and this is the fail-open the row would
    # otherwise have. Every floor inside a clock — a refused connection, a
    # missing poll snapshot, a mount that never attached — also exits non-zero,
    # so "both clocks failed" is satisfied by a clock that never polled at all
    # and the row would report a control it had not demonstrated. What it must
    # establish is that the clocks RAN, READ CONTENT and REJECTED it: each
    # wrote its result line, each recorded at least one poll or attempt, and
    # each ended on its CAP rather than on a floor.
    local nopub_a_polls="" nopub_a_verdict="" nopub_b_tries="" nopub_b_verdict=""
    if [ -f "$NEG/nopub-a.result" ] && [ -f "$NEG/nopub-b.result" ]; then
      nopub_a_polls="$(clock_result_field "$NEG/nopub-a.result" 2 "the no-publish clock A")"
      nopub_a_verdict="$(clock_result_field "$NEG/nopub-a.result" 4 "the no-publish clock A")"
      nopub_b_tries="$(clock_result_field "$NEG/nopub-b.result" 2 "the no-publish clock B")"
      nopub_b_verdict="$(clock_result_field "$NEG/nopub-b.result" 3 "the no-publish clock B")"
    fi
    # ONE VERDICT, REGISTERED. Nonzero exits alone can
    # reflect failures before either clock reads. Require
    # the cap verdicts and positive poll or attempt
    # counts as well, then persist the same result.
    local neg3_verdict="fail"
    if [ "$nopublish_a_rc" != "0" ] && [ "$nopublish_b_rc" != "0" ] \
        && [ "$nopub_a_verdict" = "1" ] && [ "$nopub_b_verdict" = "1" ] \
        && [ "${nopub_a_polls:-0}" -ge 1 ] && [ "${nopub_b_tries:-0}" -ge 1 ]; then
      neg3_verdict="pass"
    fi
    if [ "$neg3_verdict" = "pass" ]; then
      row_pass NEG3 "with the publish DELIBERATELY NOT PERFORMED, BOTH clocks FAIL against the same v_(n+1) sentinel hash $sentinel_new they will meet a moment from now: clock A read the sentinel $nopub_a_polls times and clock B mounted $nopub_b_tries times, and each ran out its ${CLOCK_NEGATIVE_CAP_SECONDS}s cap rather than dying (rc $nopublish_a_rc and $nopublish_b_rc). They report NO number rather than a small one"
    else
      row_fail NEG3 "clock A rc=$nopublish_a_rc (polls=[$nopub_a_polls] cap-verdict=[$nopub_a_verdict]), clock B rc=$nopublish_b_rc (attempts=[$nopub_b_tries] cap-verdict=[$nopub_b_verdict]) before any publish. Either a clock produced a number for content nobody published, or one failed without ever reading — and a control that fired for the wrong reason has demonstrated nothing"
    fi
    obs_set no_publish "$neg3_verdict"
  fi

  # ------------------------------------------------------------ the publish
  #
  # THE PINNED SERVER ROUTE, never `--direct-s3`: that flag routes around
  # granary-server entirely (`main.rs:2403-2428`), leaves the measured
  # request total at zero, and prints `wire-snapshot not written: --direct-s3
  # has no wire-byte counter` while writing no snapshot at all — a second,
  # independent enforcement of the route assertion, and one this harness's
  # own refusal scan would catch.
  #
  # HOME is bound to the stack's state directory the way `stack.sh:505`
  # binds it: the seed validator walks to HOME, and the key seed lives there.
  local t_publish_started t_publish_ended
  t_publish_started="$(timeline_mark publish_started)"
  run_measured "publisher" "$H/publisher.json" "$OUT/publish.out" "$OUT/publish.err" 0 \
    env "HOME=$STACK_STATE" "$RUN_GRAN" publish \
      "$STACK_STATE/store" "$SRC" "$RUN_VOLUME" \
      --publish-mode legacy-server \
      --endpoint "$MEASURED_ENDPOINT" --pin "$RUN_PIN" \
      --key-seed "$STACK_STATE/publish.key" \
      --wire-snapshot "$H/publisher.json" --wire-run-id "$RUN_ID" --wire-role "publisher"
  # T0 FOR BOTH CLOCKS, taken at the publisher's EXIT and before the timeline
  # mark beside it, so nothing between the two can be charged to propagation.
  # The two spellings are of ONE moment: `timeline_mark` writes the ordered
  # stamp the verb reads, `now_ms` gives the clocks arithmetic they can do.
  local clock_t0_ms
  clock_t0_ms="$(now_ms)"
  t_publish_ended="$(timeline_mark publish_ended)"

  local published_seq
  published_seq="$(snapshot_u64 "$H/publisher.json" "publish.seq" "publisher")"
  [ "$published_seq" = "$seq_next" ] \
    || die "the publisher's snapshot says seq $published_seq and the harness parsed n=$seq_n from the stack's publish log, so it expected $seq_next; a misparsed n is refused rather than measured around"

  # ---------------------------------------------------------- the workloads
  #
  # Each client reads the full CONTENT of the changed subtree exactly once,
  # pinned to n+1, on the cache-dir its own warm-up filled. THREE CONCURRENT
  # CLIENTS AGAINST ONE SHARED SERVER — the measured fan-out property,
  # not a bigger byte budget.
  #
  # AND THE TWO CLOCKS RUN BESIDE THEM, from the publisher's exit. That is
  # forced, not a scheduling convenience: both are stopwatches started at t0,
  # and a clock run AFTER the workloads would measure the workloads. The
  # poll's byte cost is the load the
  # instrument puts on the server DURING the byte phase — and the two clocks
  # cannot disturb the byte accounting, because every client read carries an
  # empty request body and each workload counts its own bytes in its own
  # process.
  local t_workloads_started t_workloads_ended
  local -a clock_a_pids clock_b_pids
  mkdir -p "$W/clocks"
  t_workloads_started="$(timeline_mark workloads_started)"
  unit_pids=()
  clock_a_pids=()
  clock_b_pids=()
  for k in 1 2 3; do
    spawn_mount_walk "client-$k" "$RUN_ID" "$W/mnt-$k" "$W/cache-$k" \
      "$seq_next" "$H/client-$k.json" "$CORPUS_SUBTREE" "$OUT" "client-$k"
    unit_pids+=("$SPAWNED_PID")
  done
  for k in 1 2 3; do
    mkdir -p "$W/mnt-clockb-$k"
    spawn_clock_a "$k" "$sentinel_path" "$sentinel_new" "$clock_t0_ms" \
      "$CLOCK_A_CAP_SECONDS" "$OUT" "clock-a-$k" "$W/clocks" "$clock_run_id"
    clock_a_pids+=("$SPAWNED_PID")
    spawn_clock_b "$k" "$sentinel_path" "$sentinel_new" "$clock_t0_ms" \
      "$CLOCK_B_CAP_SECONDS" "$W/mnt-clockb-$k" "$W/cache-clockb-$k" "$OUT" "clock-b-$k"
    clock_b_pids+=("$SPAWNED_PID")
  done
  join_units "the byte workloads" "${unit_pids[@]}"
  # THE CLOCKS ARE JOINED WITH THEIR OWN STATUSES KEPT, not with `join_units`.
  # A failed clock is a refusal of the run — but the per-client observations
  # record its exit code, and `join_units` dies before anything can read one.
  local -a clock_a_rcs clock_b_rcs
  clock_a_rcs=()
  clock_b_rcs=()
  for k in 0 1 2; do
    wait_into_rc "${clock_a_pids[$k]}"
    clock_a_rcs+=("$WAITED_RC")
    wait_into_rc "${clock_b_pids[$k]}"
    clock_b_rcs+=("$WAITED_RC")
  done
  t_workloads_ended="$(timeline_mark workloads_ended)"

  # ------------------------------------------------------- K1: THE TWO CLOCKS
  #
  # The positive control for the whole instrument: on a REAL republish both
  # clocks produce a number for every client. Their thresholds are NOT checked
  # here — the registered limits are 30 s and 60 s, and the verb applies
  # those clock-A and clock-B thresholds because the harness records no verdict.
  local clock_ok=1 clock_detail="" ca_s ca_p ca_b cb_s
  for k in 1 2 3; do
    if [ "${clock_a_rcs[$((k - 1))]}" != "0" ]; then
      note "clock A (client $k) exited ${clock_a_rcs[$((k - 1))]}: it never saw the v_(n+1) sentinel within ${CLOCK_A_CAP_SECONDS}s"
      clock_ok=0
    fi
    if [ "${clock_b_rcs[$((k - 1))]}" != "0" ]; then
      note "clock B (client $k) exited ${clock_b_rcs[$((k - 1))]}: it never saw the v_(n+1) sentinel within ${CLOCK_B_CAP_SECONDS}s"
      clock_ok=0
    fi
    ca_s="$(clock_result_field "$OUT/clock-a-$k.result" 1 "clock A (client $k)")"
    ca_p="$(clock_result_field "$OUT/clock-a-$k.result" 2 "clock A (client $k)")"
    ca_b="$(clock_result_field "$OUT/clock-a-$k.result" 3 "clock A (client $k)")"
    cb_s="$(clock_result_field "$OUT/clock-b-$k.result" 1 "clock B (client $k)")"
    # A LOWER BOUND ON THE POLL COST, because there was none. Clock A is
    # CACHELESS by construction — it has no cache to be served from — so a
    # zero here is a counter that was never accumulated, not a poll that was
    # free. A mutation stopped accumulating it and left a `0`
    # in the artifact that every row and the assembler both accepted; the
    # assembler now refuses it too (`clock_a_poll_bytes`, minimum 1).
    case "$ca_b" in
      ''|*[!0-9]*) note "clock A (client $k) reported a poll cost that is not a count: [$ca_b]"; clock_ok=0 ;;
      *) [ "$ca_b" -ge 1 ] || { note "clock A (client $k) polled $ca_p times and reports $ca_b bytes; a cacheless gran cat cannot cost zero"; clock_ok=0; } ;;
    esac
    clock_detail="$clock_detail k=$k A=${ca_s}s/${ca_p} polls/${ca_b} B B=${cb_s}s;"
  done
  local k1_verdict="fail"
  [ "$clock_ok" -eq 1 ] && k1_verdict="pass"
  # `clock_a_poll_cost` is the observation that CARRIES `$clock_detail`, and
  # its outcome is K1's rather than a hardcoded `pass`: the detail is a
  # measurement of the clocks, and a clock that never met its predicate has
  # not measured anything for the artifact to carry as a cost.
  row_outcome K1 clock_a_poll_cost "$k1_verdict" \
    "both clocks produced a number for every client on a real republish:$clock_detail each stopped on the sentinel's CONTENT HASH $sentinel_new, and the poll cost is recorded rather than hidden because it is load the instrument put on the server during the byte phase" \
    "at least one clock never met the content-identity predicate within its cap, or a clock-A poll cost came back at zero bytes; a clock with no number is a refusal of the run, not a large one.$clock_detail"

  # ------------- K2: THE PREDICATE IS EQUALITY, NOT "THE CONTENT CHANGED"
  #
  # K1 above and NEG3 before the publish are both satisfied by a clock that
  # stops on "it is no longer v_n" — weakening both predicates
  # exactly that way left BOTH rows green. That weaker rule stops on a
  # corrupted or partial read, which is a number for content nobody published,
  # arriving through the door the content-identity predicate was built to shut.
  #
  # SO: AFTER the publish, with the real v_(n+1) sitting in the store and the
  # real clocks already stopped on it, one clock A and one clock B are given a
  # hash that is NEITHER version. Both must run out their cap. A clock whose
  # predicate were "changed away from v_n" would stop on the first read here,
  # because the content HAS changed.
  local k2_want="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  local k2_t0 k2_a_pid k2_b_pid k2_a_rc k2_b_rc k2_a_verdict="" k2_b_verdict=""
  mkdir -p "$NEG/mnt-k2" "$NEG/clocks"
  k2_t0="$(now_ms)"
  spawn_clock_a 1 "$sentinel_path" "$k2_want" "$k2_t0" \
    "$CLOCK_NEGATIVE_CAP_SECONDS" "$NEG" "k2-a" "$NEG/clocks" "$neg_run_id"
  k2_a_pid="$SPAWNED_PID"
  spawn_clock_b 1 "$sentinel_path" "$k2_want" "$k2_t0" \
    "$CLOCK_NEGATIVE_CAP_SECONDS" "$NEG/mnt-k2" "$NEG/cache-k2" "$NEG" "k2-b"
  k2_b_pid="$SPAWNED_PID"
  wait_into_rc "$k2_a_pid"
  k2_a_rc="$WAITED_RC"
  wait_into_rc "$k2_b_pid"
  k2_b_rc="$WAITED_RC"
  if [ -f "$NEG/k2-a.result" ]; then
    k2_a_verdict="$(clock_result_field "$NEG/k2-a.result" 4 "the K2 clock A")"
  fi
  if [ -f "$NEG/k2-b.result" ]; then
    k2_b_verdict="$(clock_result_field "$NEG/k2-b.result" 3 "the K2 clock B")"
  fi
  if [ "$k2_a_rc" != "0" ] && [ "$k2_b_rc" != "0" ] \
      && [ "$k2_a_verdict" = "1" ] && [ "$k2_b_verdict" = "1" ]; then
    row_pass K2 "AFTER the publish, both clocks given a hash that is NEITHER the v_n sentinel nor the v_(n+1) one ran out their ${CLOCK_NEGATIVE_CAP_SECONDS}s cap (A rc=$k2_a_rc, B rc=$k2_b_rc, both ending on the cap rather than on a floor) — the stopping rule is EQUALITY with the hash the clock was given, not 'the content has changed', which is the weakening that survives K1 and NEG3 together"
  else
    row_fail K2 "a clock STOPPED on content that is not the hash it was given, or failed without reaching its cap: A rc=$k2_a_rc verdict=[$k2_a_verdict], B rc=$k2_b_rc verdict=[$k2_b_verdict]. A predicate that is anything other than equality with the expected hash will stop on a corrupted or partial read"

  fi

  # ------------------------------------------------- the negative rows
  #
  # THE SELF-TEST's negative rows, run while the measured server is still up
  # because both need to fetch. They carry a DIFFERENT run id — `<run
  # id>-neg` — and write into a directory of their own, so a snapshot from a
  # deliberately-broken client can never be mistaken for one of the eleven by
  # anything that later assembles them. Their roles come from the closed
  # vocabulary because the writers refuse anything else; the run id is what
  # keeps them apart.
  local nocache_digest="" stale_digest="" nocache_bytes=""
  local neg_pids
  mkdir -p "$W/cache-nocache" "$W/mnt-nocache"

  # A NO-CACHE CLIENT MUST EXCEED THREE TIMES THE NOVEL-BYTE TOTAL. This is the
  # delta's discriminating power: without it, f is a number in a table and
  # nothing shows the measurement can tell a working cache from a broken
  # one. Same seq, same content, same walk — only the cache is cold.
  #
  # THIS RUNS IN EVERY PRESET, unlike the optional negatives below, because
  # `no_cache_client_fails_p2` is a REQUIRED observation name and a missing
  # required name is an artifact REFUSAL. Gating it on the self-test meant the
  # measurement run was the one run that never emitted it.
  spawn_mount_walk "client-1" "$neg_run_id" "$W/mnt-nocache" \
    "$W/cache-nocache" "$seq_next" "$NEG/nocache.json" "$CORPUS_SUBTREE" "$NEG" "nocache"
  neg_pids="$SPAWNED_PID"
  join_units "the no-cache negative" "$neg_pids"
  nocache_digest="$(walk_field_digest "$(sed -n '1p' "$NEG/nocache.digest")")"
  nocache_bytes="$(snapshot_u64 "$NEG/nocache.json" "response_bytes" "no-cache negative")"

  # -------------- R2: a mount that never attaches leaves NO daemon behind
  #
  # A live daemon without an attached mount is
  # invisible to a mountpoint-only cleanup sweep.
  # It could survive the subshell and attach
  # after cleanup, over a directory the run is
  # about to remove. This row constructs an alive
  # process that never attaches, sets a one-second
  # readiness bound, and checks that the unit's
  # failure path terminates the process.
  #
  # ITS POSITIVE CONTROL IS IN THE FAILURE TEXT, and it is needed: "the pid is
  # dead" is trivially true of a daemon that never started. The unit dies with a
  # DIFFERENT message when the process exits early ("exited before the mount
  # became ready") than when the deadline expires ("did not become ready
  # within"), and only the second establishes that the process was ALIVE at the
  # deadline — which is the premise the row is about.
  #
  # THE DAEMON IS A STAND-IN, making the row
  # deterministic. A real mount can attach before
  # a short readiness deadline and defeat the
  # negative's premise. This row tests cleanup
  # of the spawned process, so it spawns a process
  # that stays alive and never attaches. It
  # places no load on the measured server and
  # requires no mount behavior from the stack.
  local saved_ready_ticks="$MOUNT_READY_TICKS" saved_gran="$RUN_GRAN"
  local leak_pid leak_ok=1
  mkdir -p "$W/cache-leak" "$W/mnt-leak"
  {
    printf '#!/usr/bin/env bash\n'
    printf '# A stand-in for the mount daemon: alive, and it never attaches.\n'
    printf 'exec sleep 300\n'
  } > "$NEG/never-mounts"
  chmod +x "$NEG/never-mounts"
  RUN_MOUNTPOINTS="$RUN_MOUNTPOINTS$W/mnt-leak"$'\n'
  RUN_GRAN="$NEG/never-mounts"
  MOUNT_READY_TICKS=10
  expect_failure "$NEG/leak.log" mount_walk_unit "client-1" "$neg_run_id" \
    "$W/mnt-leak" "$W/cache-leak" "$seq_next" "$NEG/leak.json" \
    "$CORPUS_SUBTREE" "$NEG" "leak"
  MOUNT_READY_TICKS="$saved_ready_ticks"
  RUN_GRAN="$saved_gran"
  if [ "$EXPECT_RC" -eq 0 ] || ! grep -a -F -q -- 'did not become ready within' "$EXPECT_OUT"; then
    note "R2: the unit did not fail at the READINESS DEADLINE (rc=$EXPECT_RC), so the row has not established that a daemon was alive to leak; see $EXPECT_OUT"
    leak_ok=0
  fi
  leak_pid=""
  # An `if`, NOT `[ -f X ] && leak_pid=...`: that spelling is a standalone
  # compound whose status is the test's, so a missing pid file would end the run
  # under `set -e` at exactly the point the diagnostic below exists to report.
  if [ -f "$NEG/leak.daemon.pid" ]; then
    leak_pid="$(sed -n '1p' "$NEG/leak.daemon.pid")"
  fi
  case "$leak_pid" in
    ''|*[!0-9]*)
      note "R2: the unit recorded no mount-daemon pid [$leak_pid]; the row cannot name the process it is about"
      leak_ok=0
      ;;
    *)
      if pid_is_alive "$leak_pid"; then
        note "R2: the mount daemon (pid $leak_pid) SURVIVED the unit's cleanup and can still attach $W/mnt-leak"
        leak_ok=0
        kill -KILL "$leak_pid" 2>/dev/null
        wait_for_death "$leak_pid" 100 || note "R2: pid $leak_pid survived SIGKILL"
      fi
      ;;
  esac
  if mountpoint -q "$W/mnt-leak" 2>/dev/null; then
    note "R2: $W/mnt-leak is still attached after the unit's cleanup"
    leak_ok=0
    fusermount3 -u -z "$W/mnt-leak" 2>/dev/null
  fi
  if [ "$leak_ok" -eq 1 ]; then
    row_pass R2 "a unit whose daemon could not attach within its readiness bound left NOTHING behind: pid $leak_pid is gone and $W/mnt-leak is unattached, and the unit failed at the DEADLINE rather than by the daemon exiting — so there was a live process for the cleanup to have to kill, and it killed it"
  else
    row_fail R2 "the unit's cleanup did not account for its mount daemon; a surviving daemon can attach a mountpoint after the cleanup that was supposed to remove it, over a directory the run then deletes. See $EXPECT_OUT"
  fi

  if [ "$negatives" -eq 1 ]; then
    mkdir -p "$W/cache-stale" "$W/mnt-stale"

    # STALE CONTENT. A client pinned to n instead of n+1 reads the OLD tree,
    # exits 0, returns bytes and would pass every other floor here — which is
    # exactly the fail-open the content-identity predicate exists to close.
    # The row proves the predicate SEES it.
    spawn_mount_walk "client-1" "$neg_run_id" "$W/mnt-stale" \
      "$W/cache-stale" "$seq_n" "$NEG/stale.json" "$CORPUS_SUBTREE" "$NEG" "stale"
    neg_pids="$SPAWNED_PID"
    join_units "the stale-content negative" "$neg_pids"
    stale_digest="$(walk_field_digest "$(sed -n '1p' "$NEG/stale.digest")")"

    # ---------- M1: WHAT A REUSED CLOCK-B CACHE-DIR ACTUALLY SERVES
    #
    # A MEASUREMENT ROW, NOT A CONTROL: the
    # prediction did not survive being executed. A clock-B mount
    # that reused a cache-dir was predicted to false-fail, because `gran mount`'s
    # open path is hint-first and the persisted hint is blind for `[48 s, 72 s)`
    # (`head.rs:106-107`), so this row probes for that false-fail.
    # RUN on this venue, with the reused directory's hint 3 s old — well inside
    # the blind window — THE REUSED CACHE-DIR SERVED THE NEW CONTENT.
    #
    # The mechanism, read back off the directory afterwards: a `gran mount`
    # that lives a second or two writes only the MOUNT-PRIVATE FLOOR
    # `anchors/<volume>.mount` (`Cache::raise_mount_anchor` in `cache.rs`,
    # whose own doc says "Unlike [`Self::raise_anchor`] there is no hint to
    # update"), and NOT the persisted hint at `anchors/<volume>`. With no
    # hint there is no fresh-hint zero-wire shortcut to take
    # (`head.rs:415-436`), so discovery goes to the wire and finds n+1; and
    # the floor that IS written has max semantics, so it can only stop a
    # reader going BACKWARDS.
    #
    # WHAT THIS ROW THEREFORE DOES: it runs the probe, it refuses anything that
    # is neither known version, and it RECORDS WHICH — so the artifact carries
    # the measurement rather than the prediction. The fresh-cache-dir-per-mount
    # rule stays implemented: it costs nothing, and
    # a hazard that this configuration does not reproduce is not a hazard that
    # has been shown not to exist.
    if [ "$preset" = "selftest" ] && [ -n "$nopublish_cache" ] \
        && [ -n "$nopublish_hint_ms" ]; then
      local reuse_pid reuse_hash reuse_ms reuse_age reuse_hint="absent"
      if [ -e "$nopublish_cache/anchors/$RUN_VOLUME" ]; then
        reuse_hint="present"
      fi
      mkdir -p "$NEG/mnt-reuse"
      spawn_sentinel_probe "$NEG/mnt-reuse" "$nopublish_cache" "$sentinel_path" \
        "$NEG" "reuse"
      reuse_pid="$SPAWNED_PID"
      join_units "the reused-cache-dir measurement" "$reuse_pid"
      reuse_hash="$(sed -n '1p' "$NEG/reuse.hash")"
      reuse_ms="$(sed -n '1p' "$NEG/reuse.ms")"
      reuse_age=$(((reuse_ms - nopublish_hint_ms) / 1000))
      # THE PREMISE GATE IS KEPT, and the reason is worth stating because it
      # makes this row's pass/fail depend on how fast the machine is: the
      # ${HINT_TRUSTED_SECONDS}s span covers the no-publish clock B, three
      # warm-ups and verifies, the byte workloads and the stale-content
      # negative, so a slow venue can run the reused directory's hint out of
      # the blind window and the row goes red having measured nothing. It is
      # kept anyway. It runs ONLY under the selftest preset, so the
      # measurement run does not carry the exposure at all; `reused_cache_dir`
      # is not a required artifact observation; and the alternative — recording
      # `pass` for a probe whose premise did not hold — is exactly the
      # weaker-claim defect the observation table above exists to stop. A red
      # here costs a re-run and says why; a green would cost a false record.
      local m1_verdict="fail" m1_message=""
      if [ "$reuse_age" -ge "$HINT_TRUSTED_SECONDS" ]; then
        m1_message="the reused cache-dir was last written ${reuse_age}s ago and the hint blind window is ${HINT_TRUSTED_SECONDS}s, so this row's own PREMISE is not established on this run and it refuses to report a result either way"
      elif [ "$reuse_hash" = "$sentinel_old" ]; then
        m1_verdict="pass"
        m1_message="a clock-B mount on a REUSED cache-dir ($nopublish_cache, last written ${reuse_age}s ago, persisted hint $reuse_hint) is served the OLD sentinel $sentinel_old — reused cache state can make the new-content check fail, so each measured clock-B mount must get a new cache directory"
      elif [ "$reuse_hash" = "$sentinel_new" ]; then
        m1_verdict="pass"
        m1_message="a clock-B mount on a REUSED cache-dir ($nopublish_cache, last written ${reuse_age}s ago, INSIDE the ${HINT_TRUSTED_SECONDS}s blind window, persisted hint $reuse_hint) was served the NEW sentinel $sentinel_new. This run does not demonstrate stale content from cache reuse: the short-lived mount writes only the mount-private FLOOR anchors/$RUN_VOLUME.mount and no persisted hint at anchors/$RUN_VOLUME, so there is no fresh-hint shortcut to take and discovery goes to the wire. Each measured clock-B mount must still get a fresh cache directory; this row records the observed content and does not require the reused directory to serve stale content"
      else
        m1_message="the reused cache-dir served [$reuse_hash], which is NEITHER the v_n sentinel $sentinel_old nor the v_(n+1) sentinel $sentinel_new; the probe read content this run cannot account for"
      fi
      # Persist the premise check together with the
      # hash result: a known hash cannot establish
      # this row if the hint window has expired.
      row_outcome M1 reused_cache_dir "$m1_verdict" "$m1_message" "$m1_message"
    fi

    # ---------------------- NEG5: THE PUBLISHER ON THE WRONG SERVER
    #
    # The stack's server is down and its endpoint is stale by construction, so
    # a publisher pointed at it must be REFUSED — a non-zero exit and no
    # snapshot. It is worth a row because the failure it guards against is
    # SILENT in the other direction: a publisher on the wrong server leaves the
    # measured request total at zero, and zero passes every upper bound.
    # THE CONNECTION REFUSAL IS ASSERTED, not merely a non-zero exit. "The
    # publisher failed" is satisfied by a mistyped flag, a missing key seed or
    # a pin mismatch, none of which says anything about whether the terminated
    # endpoint still serves — and this row's whole claim is about the endpoint.
    # Same discipline as R1, and for the same reason.
    local wrong_rc wrong_refused_rc wrong_snapshot="$NEG/wrongserver.json"
    set +e
    env "HOME=$STACK_STATE" "$RUN_GRAN" publish \
      "$STACK_STATE/store" "$SRC" "$RUN_VOLUME" \
      --publish-mode legacy-server \
      --endpoint "$STACK_ENDPOINT" --pin "$RUN_PIN" \
      --key-seed "$STACK_STATE/publish.key" \
      --wire-snapshot "$wrong_snapshot" --wire-run-id "$neg_run_id" \
      --wire-role "publisher" \
      > "$NEG/wrongserver.out" 2> "$NEG/wrongserver.err"
    wrong_rc=$?
    grep -a -F -q -- 'Connection refused' "$NEG/wrongserver.err"
    wrong_refused_rc=$?
    set -e
    local neg5_verdict="fail"
    if [ "$wrong_rc" -ne 0 ] && [ "$wrong_refused_rc" -eq 0 ] \
        && [ ! -e "$wrong_snapshot" ]; then
      neg5_verdict="pass"
    fi
    row_outcome NEG5 wrong_server "$neg5_verdict" \
      "a publisher pointed at the TERMINATED stack endpoint $STACK_ENDPOINT is refused: exit $wrong_rc with a CONNECTION REFUSED on its stderr, and NO snapshot at $wrong_snapshot. A misroute is a hard failure and not a quiet zero — and the refusal is the endpoint's, not some other failure of the same command" \
      "the wrong-server publisher exited $wrong_rc, the 'Connection refused' grep exited $wrong_refused_rc, and its snapshot is $([ -e "$wrong_snapshot" ] && echo present || echo absent); a non-zero exit for an unrelated reason does not establish that the terminated endpoint stopped serving. See $NEG/wrongserver.err"

    # ---------------------------- NEG6: AN EMPTY RUN ID, REFUSED BY THE WRITER
    #
    # Eleven files stamped from an unset `$RUN_ID` satisfy every equality check
    # in this harness. The writer refuses an empty id
    # (`wire_snapshot_trio_is_valid`), and the row proves it does so with a
    # NON-ZERO EXIT AND NO FILE rather than by writing a file the harness would
    # then have to notice was wrong.
    # THE WRITER'S OWN WORDS ARE ASSERTED. `gran cat` exits non-zero for every
    # malformed command line, so "it exited 2" would be satisfied by a typo in
    # any other flag and the row would report a refusal it had not caused. The
    # fragment is the exact sentence the trio validator emits for this case.
    local emptyid_rc emptyid_named_rc emptyid_snapshot="$NEG/emptyid.json"
    set +e
    "$RUN_GRAN" cat "$RUN_VOLUME" "$sentinel_path" \
      --endpoint "$MEASURED_ENDPOINT" --pin "$RUN_PIN" --root-key "$RUN_ROOT_KEY" \
      --wire-snapshot "$emptyid_snapshot" --wire-run-id "" --wire-role "client-1" \
      > "$NEG/emptyid.out" 2> "$NEG/emptyid.err"
    emptyid_rc=$?
    grep -a -F -q -- 'the wire-snapshot run id is empty' "$NEG/emptyid.err"
    emptyid_named_rc=$?
    set -e
    local neg6_verdict="fail"
    if [ "$emptyid_rc" -ne 0 ] && [ "$emptyid_named_rc" -eq 0 ] \
        && [ ! -e "$emptyid_snapshot" ]; then
      neg6_verdict="pass"
    fi
    row_outcome NEG6 empty_run_id "$neg6_verdict" \
      "a measured process given --wire-run-id \"\" is refused by the WRITER, in its own words — 'the wire-snapshot run id is empty' — with exit $emptyid_rc and no file at $emptyid_snapshot. Eleven files stamped from an unset variable satisfy every equality check in this harness, so the refusal has to happen before the file exists" \
      "the empty-run-id process exited $emptyid_rc, the writer's own refusal text grep exited $emptyid_named_rc, and its snapshot is $([ -e "$emptyid_snapshot" ] && echo present || echo absent); see $NEG/emptyid.err"
  fi

  # ------------------------------------------------------- the teardown
  #
  # The measured server is stopped by THIS harness, with its own waiter, only
  # after every measured client and the publisher have EXITED — so the drain
  # has nothing to drain and completes at once. `terminate_pid` is never used
  # on it: its 10 s bound IS `SHUTDOWN_DEADLINE`, and a drain finishing near
  # the deadline would have its snapshot write racing a SIGKILL that wins by
  # leaving no file.
  stop_measured_server

  # ------ NEG7: A SERVER SIGKILLED BEFORE ITS RENAME LEAVES NO SNAPSHOT
  #
  # `terminate_pid`'s waiter is 10 s and `SHUTDOWN_DEADLINE` is 10 s
  # (`stack.sh:172`, `granary-net/src/accept.rs:87`), so a drain finishing
  # near the deadline has its snapshot write RACING a SIGKILL that wins by
  # leaving no file. This row proves the DIRECTION of that trap — no file, and
  # a refusal — by CONSTRUCTING it with a SIGKILL rather than by trying to win
  # a race, which is why it is deterministic and why it says nothing about how
  # often the race is lost.
  #
  # A THROWAWAY SECOND SERVER, started after the measured one has exited and
  # while MinIO is still up. The measured server's globals are SAVED AND
  # RESTORED around it: `MEASURED_ENDPOINT` is read by the endpoint floor
  # below, and a row that quietly reassigned it would make that floor compare
  # the ten client snapshots against an address no measured process ever used.
  local killed_ok=1
  if [ "$negatives" -eq 1 ]; then
    local saved_pid="$MEASURED_PID" saved_log="$MEASURED_LOG" saved_addr="$MEASURED_ADDR"
    local saved_endpoint="$MEASURED_ENDPOINT" saved_snapshot="$MEASURED_SNAPSHOT"
    local saved_exit="$MEASURED_EXIT"
    local kill_snapshot="$NEG/killed-server.json" kill_pid kill_wait_rc
    mkdir -p "$NEG/killserver"
    start_measured_server "$STACK_STATE" "$NEG/killserver" "$neg_run_id" "$kill_snapshot"
    kill_pid="$MEASURED_PID"
    # THE KILL'S OWN FAILURE FAILS THE ROW. If the
    # server exits before the signal, a dead pid and an
    # absent snapshot do not establish that SIGKILL
    # created the condition. The verdict includes
    # `kill_rc` as well as the snapshot refusal. A failed
    # signal therefore cannot produce a passing record
    # merely because the process is already dead. NEG8
    # provides the contrasting clean-exit control.
    local kill_rc
    set +e
    kill -KILL "$kill_pid" 2> "$NEG/killserver.kill.err"
    kill_rc=$?
    set -e
    [ "$kill_rc" -eq 0 ] || note "NEG7: SIGKILL to pid $kill_pid exited $kill_rc: $(sed -n '1p' "$NEG/killserver.kill.err")"
    wait_for_death "$kill_pid" 300 \
      || die "NEG7: the throwaway granary-server pid $kill_pid survived SIGKILL"
    set +e
    wait "$kill_pid"
    kill_wait_rc=$?
    set -e
    MEASURED_PID=""
    expect_failure "$NEG/neg7.log" assert_snapshot_present "$kill_snapshot" "killed server"
    local neg7_verdict="pass"
    if [ -e "$kill_snapshot" ] || [ "$EXPECT_RC" -eq 0 ] || [ "$kill_rc" -ne 0 ]; then
      neg7_verdict="fail"
      killed_ok=0
    fi
    row_outcome NEG7 server_killed_before_snapshot "$neg7_verdict" \
      "a granary-server SIGKILLed before its rename (the kill itself exited $kill_rc, wait status $kill_wait_rc) leaves NO snapshot file, and the presence floor REFUSES the run (rc=$EXPECT_RC) — the direction of the stack 10 s terminator trap, constructed rather than raced (the helper is named in this file's comments only, which is what row N6 enforces)" \
      "the SIGKILL to pid $kill_pid exited $kill_rc, the killed server left $([ -e "$kill_snapshot" ] && echo a snapshot || echo no snapshot) and the presence floor returned $EXPECT_RC; a run whose server died before its rename must be REFUSED, and a row that did not construct the condition it names has demonstrated nothing"

    # ---------- NEG8: THE KILL-FAILURE DETECTOR ABOVE IS SHOWN TO FIRE
    #
    # NEG7's whole claim rests on `kill` reporting failure when there is
    # nothing to signal. That is asserted here rather than assumed: a child
    # that has exited AND been reaped is a pid the kernel no longer knows, and
    # `kill` must refuse it. Its positive control is in the same row — a
    # LIVE child of this shell is signalled successfully by the same builtin,
    # so "kill always fails here" cannot pass this row either.
    local dead_pid live_pid dead_kill_rc live_kill_rc
    ( exit 0 ) &
    dead_pid=$!
    set +e
    wait "$dead_pid"
    sleep 0.2
    kill -KILL "$dead_pid" 2> "$NEG/neg8-dead.err"
    dead_kill_rc=$?
    set -e
    sleep 30 &
    live_pid=$!
    set +e
    kill -KILL "$live_pid" 2> "$NEG/neg8-live.err"
    live_kill_rc=$?
    wait "$live_pid"
    set -e
    if [ "$dead_kill_rc" -ne 0 ] && [ "$live_kill_rc" -eq 0 ]; then
      row_pass NEG8 "SIGKILL to a REAPED pid ($dead_pid) fails (rc=$dead_kill_rc: $(sed -n '1p' "$NEG/neg8-dead.err")) while SIGKILL to a LIVE child ($live_pid) succeeds (rc=$live_kill_rc) — so NEG7's kill status really does separate a constructed kill from a server that had already exited, and it is not a status that is always zero or always non-zero on this venue"
    else
      row_fail NEG8 "kill to a reaped pid exited $dead_kill_rc and kill to a live child exited $live_kill_rc; on this venue \`kill\`'s status cannot tell NEG7 whether its SIGKILL constructed the condition it reports"
    fi
    MEASURED_PID="$saved_pid"; MEASURED_LOG="$saved_log"; MEASURED_ADDR="$saved_addr"
    MEASURED_ENDPOINT="$saved_endpoint"; MEASURED_SNAPSHOT="$saved_snapshot"
    MEASURED_EXIT="$saved_exit"
  fi

  local t_server_stopped
  t_server_stopped="$(timeline_mark server_stopped)"
  stop_stack "$OUT/stack-stop.out" "$OUT/stack-stop.err"
  [ "$STACK_STOP_RC" = "0" ] \
    || die "stack.sh stop exited $STACK_STOP_RC; see $OUT/stack-stop.err"
  echo

  # =================================================== THE FLOORS AND THE ROWS
  local listen_addr server_endpoint
  listen_addr="$(snapshot_field "$H/server.json" "listen_addr" "server")"
  server_endpoint="https://$listen_addr"

  check_snapshot_identity "$H/server.json" "server" "granary-server"
  check_snapshot_identity "$H/publisher.json" "publisher" "granary-client"
  for k in 1 2 3; do
    check_snapshot_identity "$H/warmup-$k.json" "warmup-$k" "granary-client"
    check_snapshot_identity "$H/warmup-verify-$k.json" "warmup-verify-$k" "granary-client"
    check_snapshot_identity "$H/client-$k.json" "client-$k" "granary-client"
  done

  # ELEVEN FILES, ELEVEN ROLES, ONE RUN ID. The identity check above already
  # pins each file's role to the name the harness asked for; this counts the
  # files and the distinct roles so "eleven" is asserted rather than implied
  # by a loop that ran the number of times it was written to run.
  local roles_file="$OUT/roles.txt"
  : > "$roles_file"
  local snap
  for snap in server publisher client-1 client-2 client-3 \
              warmup-1 warmup-2 warmup-3 \
              warmup-verify-1 warmup-verify-2 warmup-verify-3; do
    assert_snapshot_present "$H/$snap.json" "$snap"
    snapshot_field "$H/$snap.json" "role" "$snap" >> "$roles_file"
    printf '\n' >> "$roles_file"
  done
  local distinct_roles
  distinct_roles="$(sort -u "$roles_file" | wc -l)"
  distinct_roles="${distinct_roles//[[:space:]]/}"
  if [ "$distinct_roles" = "11" ]; then
    row_pass E1 "eleven snapshot files carry ELEVEN DISTINCT ROLES and the one run id $RUN_ID"
  else
    row_fail E1 "the eleven snapshots carry $distinct_roles distinct roles, want 11; see $roles_file"
  fi

  # ------------------------------------------- E11: ELEVEN FILES, AND NO TWELFTH
  #
  # E1 above counts the DISTINCT ROLES of eleven files it names one by one, so
  # it is blind to a twelfth: a `for snap in ...` loop over a written-out list
  # reports what the list says, and NOTHING in this harness globs `$H` — 38
  # fixed-name reads and not one wildcard. A stray snapshot in the directory a
  # later phase assembles from must be refused. This row checks the file count,
  # because the writers emit no pid and no timestamp
  # and the three client snapshots are byte-identical apart from `role`.
  #
  # BOTH the `.json` count and the TOTAL entry count are asserted, because the
  # comment on `$H` says it holds the eleven snapshots and nothing else, and a
  # twelfth file under another name would be equally unwelcome to a phase that
  # assembles the directory. `find` rather than `ls "$H"/*.json`: an unmatched
  # glob would arrive as a literal path and make the count 1.
  local json_count entry_count
  [ -d "$H" ] || die "the snapshot directory is missing: $H"
  json_count="$(find "$H" -mindepth 1 -maxdepth 1 -type f -name '*.json' -print | wc -l)"
  entry_count="$(find "$H" -mindepth 1 -maxdepth 1 -print | wc -l)"
  json_count="${json_count//[[:space:]]/}"
  entry_count="${entry_count//[[:space:]]/}"
  case "$json_count$entry_count" in
    ''|*[!0-9]*) die "could not count the files in $H (json=[$json_count] entries=[$entry_count])" ;;
  esac
  local e11_verdict="fail"
  if [ "$json_count" = "11" ] && [ "$entry_count" = "11" ]; then
    e11_verdict="pass"
  fi
  row_outcome E11 three_processes "$e11_verdict" \
    "$H holds EXACTLY eleven entries and all eleven are .json — no twelfth snapshot, and nothing else, in the directory a later phase assembles from" \
    "$H holds $entry_count entries of which $json_count are .json, want 11 and 11; the eleven-role check above enumerates a fixed list and cannot see a twelfth file"

  # ------------------------------------------------------- the endpoint floor
  local endpoint_ok=1 got_endpoint
  for snap in publisher client-1 client-2 client-3 \
              warmup-1 warmup-2 warmup-3 \
              warmup-verify-1 warmup-verify-2 warmup-verify-3; do
    got_endpoint="$(snapshot_field "$H/$snap.json" "endpoint" "$snap")"
    if [ "$got_endpoint" != "$server_endpoint" ] || [ "$got_endpoint" != "$MEASURED_ENDPOINT" ]; then
      note "$snap: endpoint [$got_endpoint], want [$server_endpoint] (the measured server's own listen_addr)"
      endpoint_ok=0
    fi
  done
  if [ "$endpoint_ok" -eq 1 ]; then
    row_pass E2 "all ten client-kind snapshots name the measured server's endpoint $server_endpoint, which is https:// + the server snapshot's own listen_addr"
  else
    row_fail E2 "at least one measured process ran against a server other than the measured one; a publisher on the wrong server leaves the measured request total at zero and would PASS every upper bound"
  fi

  # ------------------------------------------------------------- the seq floor
  local seq_ok=1 pinned
  for k in 1 2 3; do
    pinned="$(snapshot_u64 "$H/warmup-$k.json" "pinned_seq" "warmup-$k")"
    [ "$((pinned + 1))" = "$published_seq" ] \
      || { note "warmup-$k: pinned_seq $pinned, and pinned_seq + 1 must equal the publisher's $published_seq"; seq_ok=0; }
    pinned="$(snapshot_u64 "$H/warmup-verify-$k.json" "pinned_seq" "warmup-verify-$k")"
    [ "$((pinned + 1))" = "$published_seq" ] \
      || { note "warmup-verify-$k: pinned_seq $pinned, and pinned_seq + 1 must equal the publisher's $published_seq"; seq_ok=0; }
    pinned="$(snapshot_u64 "$H/client-$k.json" "pinned_seq" "client-$k")"
    [ "$pinned" = "$published_seq" ] \
      || { note "client-$k: pinned_seq $pinned, want the publisher's $published_seq"; seq_ok=0; }
  done
  if [ "$seq_ok" -eq 1 ]; then
    row_pass E3 "every warm-up's pinned_seq + 1 and every workload's pinned_seq equal the publisher's publish.seq $published_seq — all read back from snapshots Rust wrote from margs.seq, which is what makes the shell's parse of n refutable"
  else
    row_fail E3 "the pinned seqs do not agree with the publisher's publish.seq $published_seq"
  fi

  # ------------------------------------------------------- the digest floors
  local digest_ok=1 observed
  for k in 1 2 3; do
    observed="$(walk_field_digest "$(sed -n '1p' "$OUT/warmup-$k.digest")")"
    [ "$observed" = "$v_n_digest" ] \
      || { note "warmup-$k: whole-tree digest $observed, want the expected v_n digest $v_n_digest"; digest_ok=0; }
    observed="$(walk_field_digest "$(sed -n '1p' "$OUT/warmup-verify-$k.digest")")"
    [ "$observed" = "$v_n_digest" ] \
      || { note "warmup-verify-$k: whole-tree digest $observed, want the expected v_n digest $v_n_digest"; digest_ok=0; }
    observed="$(walk_field_digest "$(sed -n '1p' "$OUT/client-$k.digest")")"
    [ "$observed" = "$sub_n1_digest" ] \
      || { note "client-$k: changed-subtree digest $observed, want the expected v_(n+1) digest $sub_n1_digest"; digest_ok=0; }
  done
  if [ "$digest_ok" -eq 1 ]; then
    row_pass E4 "every warm-up read v_n whole and every workload read v_(n+1) over the changed subtree; the content-identity predicate is the digest, never 'the read succeeded'"
  else
    row_fail E4 "at least one measured process read content that is not what its phase requires"
  fi

  # ---------------------------------------------------- the non-zero floors
  local server_request_bytes server_with_body server_produced novel_bytes bin_bytes c1_bytes
  server_request_bytes="$(snapshot_u64 "$H/server.json" "request_bytes" "server")"
  server_with_body="$(snapshot_u64 "$H/server.json" "requests_with_body" "server")"
  server_produced="$(snapshot_u64 "$H/server.json" "response_bytes_produced" "server")"
  novel_bytes="$(snapshot_u64 "$H/publisher.json" "publish.novel_bytes" "publisher")"
  bin_bytes="$(snapshot_u64 "$H/publisher.json" "publish.bin_bytes_uploaded" "publisher")"
  # Read `c1_bytes` outside the optional-negatives
  # block. The final observations use the value
  # in every preset, including a run with
  # `--no-negatives`. Assigning it only when
  # negatives run would leave the final write with
  # an unset variable under `set -u`, after the
  # measurement processes have already completed.
  c1_bytes="$(snapshot_u64 "$H/client-1.json" "response_bytes" "client-1")"
  local drain
  # TAUTOLOGICAL TODAY, AND KEPT ANYWAY -- said plainly because reporting it as
  # discriminating evidence would be false. `drain_outcome` is a hardcoded
  # literal (`granary-server/src/wire_snapshot.rs:219`) and the snapshot is
  # written only on the `Drained` arm (`serve.rs:228-231`), so a server that
  # wrote a snapshot at all wrote this value. The EXIT CODE beside it is what
  # actually discriminates. This stays because it costs one line and it is the
  # only thing that would notice a future writer emitting the field on another
  # arm -- but it is not evidence that the drain completed.
  drain="$(snapshot_field "$H/server.json" "drain_outcome" "server")"
  [ "$drain" = "drained" ] || die "the server's snapshot says drain_outcome=[$drain], want drained"

  local nonzero_ok=1
  [ "$server_request_bytes" -gt 0 ] || { note "server.request_bytes is zero"; nonzero_ok=0; }
  [ "$server_with_body" -gt 0 ] || { note "server.requests_with_body is zero"; nonzero_ok=0; }
  [ "$novel_bytes" -gt 0 ] || { note "publisher.publish.novel_bytes is zero"; nonzero_ok=0; }
  local warm_bytes verify_bytes client_bytes client_sum=0
  for k in 1 2 3; do
    warm_bytes="$(snapshot_u64 "$H/warmup-$k.json" "response_bytes" "warmup-$k")"
    [ "$warm_bytes" -gt 0 ] || { note "warmup-$k.response_bytes is zero"; nonzero_ok=0; }
    client_bytes="$(snapshot_u64 "$H/client-$k.json" "response_bytes" "client-$k")"
    [ "$client_bytes" -gt 0 ] || { note "client-$k.response_bytes is zero"; nonzero_ok=0; }
  done
  if [ "$nonzero_ok" -eq 1 ]; then
    row_pass E5 "the five non-zero floors hold: server.request_bytes=$server_request_bytes, requests_with_body=$server_with_body, publish.novel_bytes=$novel_bytes, and every warmup-k and client-k response_bytes above zero"
  else
    row_fail E5 "a measured quantity is zero; an upper bound alone is fail-open on every kind of undercount, which is why these floors exist"
  fi

  # -------------------------------------------------- the UNDER-download floor
  #
  # THE DIRECTION NOTHING ELSE LOOKED AT. Every other byte check here is an
  # UPPER bound or a `> 0` floor, so a client that transferred almost nothing
  # passes the lot: a client was constructed with a cache that ALREADY held
  # `v_(n+1)` and downloaded 363 B against a 426,595 B delta. It
  # satisfied the nonzero floor (`> 0`) and the client `<= 3x novel` bound (at
  # 0.0008x), the cross-crate sum (which bounds the other way) and the timeline
  # (which was honest — the workloads really did run inside their window).
  # Over-download fails the client `<= 3x novel` bound; under-download reached
  # nothing at all.
  #
  # IT IS COMPRESSION-FREE, unlike the `apparent_bytes` floor it
  # replaces. A client reading the changed subtree must receive at least the
  # compressed bins the publisher uploaded for it — the SAME zstd bins over the
  # SAME wire — so no property of the corpus's compressibility is being
  # smuggled in as a coverage control. Measured margin on this venue:
  # 580,178 B received against 426,595 B uploaded, and the 153,583 B difference
  # is the structure cost the `f.S + structure` arithmetic above predicts. The
  # constructed degenerate fails it by 1175x.
  #
  # THE FLOOR'S OWN DENOMINATOR IS FLOORED HERE — AND ONLY AT ZERO. `x >= 0`
  # is satisfied by every x, so a publisher snapshot carrying
  # `bin_bytes_uploaded: 0` would make this row report a PASS about nothing,
  # and THAT is the vacuity this guard closes: zero, and only zero.
  #
  # What this does NOT close, said plainly: a PASS about a client that
  # received ONE byte. At `bin_bytes_uploaded == 1` the loop below degrades
  # to `client-k >= 1`, which the E-series nonzero floor on each client's
  # `response_bytes` already guarantees elsewhere in this run, so the guard
  # adds nothing at 1 that was not already true. A meaningful lower bound
  # above zero would have to tie `bin_bytes_uploaded` to some OTHER quantity
  # fixed in advance; no such tie exists today, and inventing a
  # numeric floor here would invent a bound
  # decided by this guard alone.
  #
  # `bin_bytes_uploaded` is NOT one of the five nonzero floors, which
  # `wallclock.rs`'s `check_floors` enumerates by name. The guard sits inside the row
  # that depends on it rather than widening that list.
  # The corresponding artifact check is
  # `check_under_download` in `crates/granary-bench/src/wallclock.rs`;
  # both checks require a positive uploaded-bin
  # count before comparing client bytes.
  local under_ok=1 under_bytes
  if [ "$bin_bytes" -le 0 ]; then
    note "publisher.publish.bin_bytes_uploaded is $bin_bytes; a floor of zero is satisfied by every client and this row would report a PASS about nothing"
    under_ok=0
  fi
  for k in 1 2 3; do
    under_bytes="$(snapshot_u64 "$H/client-$k.json" "response_bytes" "client-$k")"
    [ "$under_bytes" -ge "$bin_bytes" ] \
      || { note "client-$k: response_bytes $under_bytes is BELOW the publisher's bin_bytes_uploaded $bin_bytes; a client that received less than the bins uploaded for the delta cannot have read the delta from the wire"; under_ok=0; }
  done
  if [ "$under_ok" -eq 1 ]; then
    row_pass E10 "every client received at least the publisher's bin_bytes_uploaded ($bin_bytes B) — client-1 $c1_bytes B — so the UNDER-download direction has a number: a client whose cache already held v_(n+1) transfers almost nothing and passes every upper bound and every > 0 floor"
  else
    row_fail E10 "at least one client's response_bytes is below the publisher's bin_bytes_uploaded $bin_bytes; that client did not fetch the delta over the wire, and nothing else in this run would have said so"
  fi

  # ------------------------------------------- the cold/warm separation
  local coldwarm_ok=1 coldwarm_detail=""
  for k in 1 2 3; do
    warm_bytes="$(snapshot_u64 "$H/warmup-$k.json" "response_bytes" "warmup-$k")"
    verify_bytes="$(snapshot_u64 "$H/warmup-verify-$k.json" "response_bytes" "warmup-verify-$k")"
    [ $((100 * verify_bytes)) -le "$warm_bytes" ] \
      || { note "client $k: 100 x warm-up-verify ($verify_bytes) = $((100 * verify_bytes)) exceeds the cold warm-up's $warm_bytes"; coldwarm_ok=0; }
    coldwarm_detail="$coldwarm_detail k=$k cold=$warm_bytes warm=$verify_bytes;"
  done
  if [ "$coldwarm_ok" -eq 1 ]; then
    row_pass E6 "the cold/warm baseline separates — 100 x warmup-verify <= warmup for every client:$coldwarm_detail this compares the instrument against ITSELF rather than against a compression ratio"
  else
    row_fail E6 "the cold/warm inequality failed; the cache is not serving v_n from disk, or the cold side was not cold"
  fi

  # ------------------------------- the cross-crate response-byte cross-check
  client_sum=0
  for snap in publisher client-1 client-2 client-3 \
              warmup-1 warmup-2 warmup-3 \
              warmup-verify-1 warmup-verify-2 warmup-verify-3; do
    client_bytes="$(snapshot_u64 "$H/$snap.json" "response_bytes" "$snap")"
    client_sum=$((client_sum + client_bytes))
  done
  if [ "$client_sum" -le "$server_produced" ]; then
    row_pass E7 "the sum of the ten client-kind response_bytes ($client_sum) is within the server's own response_bytes_produced ($server_produced) — a SECOND implementation of the same count, in the other crate under the other licence. It BOUNDS IN ONE DIRECTION ONLY: it catches an over-count and gross mis-wiring, and it does NOT catch an under-count"
  else
    row_fail E7 "the clients report $client_sum response bytes and the server produced $server_produced; the two counters disagree in the direction that means something is mis-wired"
  fi

  # ------------------------------------------------- the delta fraction band
  #
  # RECORDED so a later phase can recompute it; the band is asserted here in
  # INTEGER arithmetic so no float rounding decides a gate. Below 0.01 the
  # fixed structure cost eats the client `<= 3x novel` budget; at or above 1/3
  # a client that reused NOTHING still satisfies that upper bound.
  local f_text
  f_text="$(awk -v n="$novel_bytes" -v s="$changed_subtree_bytes" 'BEGIN { printf "%.4f", n / s }')"
  if [ $((100 * novel_bytes)) -ge "$changed_subtree_bytes" ] \
      && [ $((100 * novel_bytes)) -le $((30 * changed_subtree_bytes)) ]; then
    row_pass E8 "the delta fraction f = novel_bytes/changed_subtree_bytes = $novel_bytes/$changed_subtree_bytes = $f_text, inside [0.01, 0.30]"
  else
    row_fail E8 "the delta fraction f = $f_text is outside [0.01, 0.30]; outside that band the measurement stops discriminating and a pass would not be interpretable"
  fi

  # -------------------------------------------------------- the timeline
  # THE CHAIN IS ADJACENT PAIRS ONLY. A `warmups_ended < publish_started` check
  # sat here and COULD NOT FIRE: the two lines above establish
  # `warmups_ended < delta_generated < publish_started`, which implies it
  # transitively now that the comparisons are strict. A gate that cannot fail is
  # a defect by this harness's own policy, and it is worse than useless in a
  # list of named gates -- a reader counts it as protection. Removed
  # for that reason.
  assert_strictly_before "$t_warmups_ended" "$t_delta_generated" "the warm-ups must end before the delta is generated"
  assert_strictly_before "$t_delta_generated" "$t_publish_started" "the delta must be generated before the publish starts"
  assert_strictly_before "$t_publish_started" "$t_publish_ended" "the publish must start before it ends"
  assert_strictly_before "$t_publish_ended" "$t_workloads_started" "the publish must end before the workloads start"
  assert_strictly_before "$t_workloads_started" "$t_workloads_ended" "the workloads must start before they end"
  assert_strictly_before "$t_workloads_ended" "$t_server_stopped" "the workloads must end before the server stops"
  # AND THE FILE HOLDS WHAT THE HARNESS BELIEVES. The assertions above run on
  # values held in memory; a later phase reads the FILE, so a timeline that
  # was written wrong (a duplicated field, a lost append) would be ordered
  # here and wrong there. `timeline_get` refuses anything but exactly one
  # entry per field.
  local field expected_stamp file_stamp
  for field in warmups_ended delta_generated publish_started publish_ended \
               workloads_started workloads_ended server_stopped; do
    case "$field" in
      warmups_ended)     expected_stamp="$t_warmups_ended" ;;
      delta_generated)   expected_stamp="$t_delta_generated" ;;
      publish_started)   expected_stamp="$t_publish_started" ;;
      publish_ended)     expected_stamp="$t_publish_ended" ;;
      workloads_started) expected_stamp="$t_workloads_started" ;;
      workloads_ended)   expected_stamp="$t_workloads_ended" ;;
      server_stopped)    expected_stamp="$t_server_stopped" ;;
    esac
    file_stamp="$(timeline_get "$field")"
    [ "$file_stamp" = "$expected_stamp" ] \
      || die "the timeline file says $field=[$file_stamp] and the run recorded [$expected_stamp]"
  done
  row_pass E9 "the timeline orders warmups_ended=$t_warmups_ended <= delta_generated=$t_delta_generated <= publish_started=$t_publish_started <= publish_ended=$t_publish_ended <= workloads_started=$t_workloads_started <= workloads_ended=$t_workloads_ended <= server_stopped=$t_server_stopped"

  # ------------- E12: THE TIMELINE AGAINST A CLOCK THE HARNESS DOES NOT STAMP
  #
  # E9 orders seven marks against each other, and every one of them records when
  # the HARNESS CALLED `timeline_mark` — so a mark placed on the wrong side of
  # the work it brackets records a false ordering that E9 confirms. The eleven
  # snapshot files carry a second clock (see `file_stamp`): kernel mtimes
  # written by the MEASURED PROCESSES as they exit, from the same
  # `CLOCK_REALTIME`.
  #
  # THIS IS A CROSS-CHECK BETWEEN TWO CLOCKS, NOT A PROOF THAT THE EVENTS
  # HAPPENED. It cannot establish that the processes named are the processes
  # that ran, or that a stamp corresponds to the event it names; those stay in
  # the artifact's OBSERVED partition, which the verb reads back and never derives.
  # What it does close is a mark moved far enough to be a lie about the run.
  local bracket_ok=1 bs
  for k in 1 2 3; do
    bs="$(file_stamp "$H/warmup-verify-$k.json" "warmup-verify-$k")"
    stamp_not_after "$bs" "$t_warmups_ended" \
      || { note "warmup-verify-$k.json was written at $bs, AFTER the warmups_ended mark $t_warmups_ended"; bracket_ok=0; }
  done
  bs="$(file_stamp "$H/publisher.json" "publisher")"
  stamp_not_after "$t_publish_started" "$bs" \
    || { note "publisher.json was written at $bs, BEFORE the publish_started mark $t_publish_started"; bracket_ok=0; }
  stamp_not_after "$bs" "$t_publish_ended" \
    || { note "publisher.json was written at $bs, AFTER the publish_ended mark $t_publish_ended"; bracket_ok=0; }
  for k in 1 2 3; do
    bs="$(file_stamp "$H/client-$k.json" "client-$k")"
    stamp_not_after "$t_workloads_started" "$bs" \
      || { note "client-$k.json was written at $bs, BEFORE the workloads_started mark $t_workloads_started"; bracket_ok=0; }
    stamp_not_after "$bs" "$t_workloads_ended" \
      || { note "client-$k.json was written at $bs, AFTER the workloads_ended mark $t_workloads_ended"; bracket_ok=0; }
  done
  bs="$(file_stamp "$H/server.json" "server")"
  stamp_not_after "$t_workloads_ended" "$bs" \
    || { note "server.json was written at $bs, BEFORE the workloads_ended mark $t_workloads_ended"; bracket_ok=0; }
  stamp_not_after "$bs" "$t_server_stopped" \
    || { note "server.json was written at $bs, AFTER the server_stopped mark $t_server_stopped"; bracket_ok=0; }
  if [ "$bracket_ok" -eq 1 ]; then
    row_pass E12 "the snapshot files' kernel mtimes sit inside the marks that bracket them — warmup-verify-k before warmups_ended, publisher inside [publish_started, publish_ended], client-k inside [workloads_started, workloads_ended], server inside [workloads_ended, server_stopped]. A CROSS-CHECK against a clock this harness does not stamp, not a proof that the events happened"
  else
    row_fail E12 "at least one snapshot was written outside the timeline marks that bracket it; a mark records when the harness CALLED it, so a mark on the wrong side of its work is an ordering E9 cannot see"
  fi

  # ---------------- E13: THE THREE CLIENTS REALLY RAN CONCURRENTLY
  #
  # `N = 3 concurrent clients against one shared server` is the fan-out property
  # the run claims to measure, and without this row NOTHING TESTS IT: a harness that
  # spawned and joined one client at a time produces the same eleven snapshots,
  # the same digests and the same byte totals, and every row above passes. The
  # snapshots carry no timestamps and the server no concurrency counter.
  #
  # THE TWO FILE MTIMES ARE THE INSTRUMENT. `<prefix>.mount.out` is created by
  # the redirect at the moment the unit starts its `gran mount` and is never
  # written again (`gran mount --foreground` prints nothing to stdout; the row
  # asserts the file is empty, so a future writer to stdout is diagnosed here
  # rather than as a mystery). `<prefix>.rc` is written after the daemon has
  # been waited on. So `max_k start < min_k end` says some client was still
  # running when the last one started — which is what concurrency is. Pristine
  # margins on this venue: 5,480 ms for the warm-ups, 350 ms for the
  # verifications, 180 ms for the client phase.
  local conc_ok=1 phase kk start_max end_min st en conc_detail=""
  for phase in warmup warmup-verify client; do
    start_max=""
    end_min=""
    for kk in 1 2 3; do
      if [ -s "$OUT/$phase-$kk.mount.out" ]; then
        note "$phase-$kk: its mount stdout capture is NOT empty, so its mtime is no longer the moment the unit started"
        conc_ok=0
      fi
      st="$(file_stamp_ms "$OUT/$phase-$kk.mount.out" "$phase-$kk start")"
      en="$(file_stamp_ms "$OUT/$phase-$kk.rc" "$phase-$kk end")"
      if [ -z "$start_max" ] || [ "$st" -gt "$start_max" ]; then start_max="$st"; fi
      if [ -z "$end_min" ] || [ "$en" -lt "$end_min" ]; then end_min="$en"; fi
    done
    if [ "$start_max" -lt "$end_min" ]; then
      conc_detail="$conc_detail $phase=+$((end_min - start_max))ms;"
    else
      note "$phase: the last of the three started at $start_max ms and the first had already finished at $end_min ms; the three ran SEQUENTIALLY"
      conc_ok=0
    fi
  done
  if [ "$conc_ok" -eq 1 ]; then
    row_pass E13 "in each phase the LAST of the three units started before the FIRST of them finished, so the three clients overlapped against the one shared server:$conc_detail the pre-registered N=3 concurrency is a measurement rather than a description"
  else
    row_fail E13 "at least one phase did not overlap; three clients run one after another produce the same snapshots, the same digests and the same totals as three run together, and every other row here passes over the difference"
  fi

  # ------------------------------------------------ the negative rows' verdicts
  if [ "$negatives" -eq 1 ]; then
    # `c1_bytes` is read with the other snapshot totals above, in every preset.
    local ratio_client ratio_nocache
    ratio_client="$(awk -v b="$c1_bytes" -v n="$novel_bytes" 'BEGIN { printf "%.3f", b / n }')"
    ratio_nocache="$(awk -v b="$nocache_bytes" -v n="$novel_bytes" 'BEGIN { printf "%.3f", b / n }')"
    # THE SEPARATION, not the byte-bound verdict — the harness writes no verdict,
    # and the verb recomputes the publisher and each-client `<= 3x novel` bounds. What this row asserts is the property
    # the delta was sized for: a client whose cache did nothing lands OUTSIDE
    # the 3x limit while a client whose cache worked lands inside it. Without
    # this row, f is a number in a table.
    # The verdict is computed once and registered with all
    # three conditions: the no-cache byte excess, the
    # warmed-client byte bound, and the expected no-cache
    # digest. Byte separation alone would admit a client that
    # downloads enough bytes but returns the wrong content.
    local neg1_verdict="fail"
    if [ "$nocache_bytes" -gt $((3 * novel_bytes)) ] \
        && [ "$c1_bytes" -le $((3 * novel_bytes)) ] \
        && [ "$nocache_digest" = "$sub_n1_digest" ]; then
      neg1_verdict="pass"
    fi
    row_outcome NEG1 no_cache_client_fails_p2 "$neg1_verdict" \
      "a NO-CACHE client downloads $nocache_bytes B against novel $novel_bytes B = ${ratio_nocache}x, PAST the 3x limit, while the warmed client-1 downloads $c1_bytes B = ${ratio_client}x — and both read the same v_(n+1) content, so the separation is the cache and nothing else" \
      "no-cache ${ratio_nocache}x, warmed ${ratio_client}x, no-cache digest $nocache_digest vs expected $sub_n1_digest — the delta did not separate a working cache from a cold one, so f is a number in a table"

    # The stale digest must be nonempty as well as
    # different from the expected digest; inequality
    # alone would also admit an empty result.
    local neg2_verdict="fail"
    if [ -n "$stale_digest" ] && [ "$stale_digest" != "$sub_n1_digest" ]; then
      neg2_verdict="pass"
    fi
    row_outcome NEG2 stale_content "$neg2_verdict" \
      "a client pinned to n instead of n+1 reads $stale_digest, which is NOT the expected v_(n+1) digest $sub_n1_digest — so the content-identity predicate REFUSES a client serving the old content with exit 0, non-zero bytes and the right role" \
      "a client pinned to the OLD seq produced digest [$stale_digest] and the content-identity predicate did not separate it from the expected $sub_n1_digest"
  fi

  # ------------------------------------------------------- the raw records
  #
  # RAW, and no conclusion among them. A later phase assembles the artifact
  # from these plus the eleven snapshots; nothing here is a ratio, a verdict
  # or a total that a verifier could compute for itself.
  {
    printf 'preset\t%s\n' "$preset"
    printf 'apparent_bytes_v_n\t%s\n' "$apparent"
    printf 'v_n_regular_files\t%s\n' "$v_n_files"
    printf 'changed_subtree\t%s\n' "$CORPUS_SUBTREE"
    printf 'changed_subtree_bytes\t%s\n' "$changed_subtree_bytes"
    printf 'changed_subtree_regular_files\t%s\n' "$sub_n_files"
    printf 'expected_v_n_tree_digest\t%s\n' "$v_n_digest"
    printf 'expected_v_n_subtree_digest\t%s\n' "$sub_n_digest"
    printf 'expected_v_n1_subtree_digest\t%s\n' "$sub_n1_digest"
    printf 'delta_stride\t%s\n' "$DELTA_STRIDE"
    printf 'delta_seed\t%s\n' "$DELTA_SEED"
    printf 'delta_files_rewritten\t%s\n' "$delta_files"
    printf 'delta_bytes_rewritten\t%s\n' "$delta_bytes"
    printf 'seq_n\t%s\n' "$seq_n"
    printf 'seq_workload\t%s\n' "$published_seq"
    printf 'run_id\t%s\n' "$RUN_ID"
    printf 'measured_endpoint\t%s\n' "$MEASURED_ENDPOINT"
    printf 'stack_endpoint\t%s\n' "$STACK_ENDPOINT"
    printf 'bin_bytes_uploaded\t%s\n' "$bin_bytes"
    printf 'sentinel\t%s\n' "$sentinel_path"
    printf 'sentinel_v_n_sha256\t%s\n' "$sentinel_old"
    printf 'sentinel_v_n1_sha256\t%s\n' "$sentinel_new"
    printf 'walker\t%s\n' 'cd <dir> && find . ! -type f ! -type d -print (refused if non-empty); find . -type f -print0 | LC_ALL=C sort -z > listing; xargs -0 sha256sum < listing > contents; sha256sum over "m10-subtree-digest v1\nlisting\n<listing>\ncontents\n<contents>"'
  } > "$W/corpus.tsv"

  # THE TWO CLOCKS, one row per client. RAW: two durations, a poll count and a
  # poll byte cost. No ratio, no threshold, no verdict — the
  # thresholds are 30 s and 60 s and the verb is what compares against them.
  : > "$W/clocks.tsv"
  for k in 1 2 3; do
    printf '%s\t%s\t%s\t%s\t%s\n' "$k" \
      "$(clock_result_field "$OUT/clock-a-$k.result" 1 "clock A (client $k)")" \
      "$(clock_result_field "$OUT/clock-a-$k.result" 2 "clock A (client $k)")" \
      "$(clock_result_field "$OUT/clock-a-$k.result" 3 "clock A (client $k)")" \
      "$(clock_result_field "$OUT/clock-b-$k.result" 1 "clock B (client $k)")" \
      >> "$W/clocks.tsv"
  done

  # THE PER-CLIENT OBSERVATIONS. The three digests each client actually read,
  # the five exit codes, the endpoint it was GIVEN and the two seqs it was
  # given — the inputs beside the outputs, so a reader can see what each
  # process was asked for as well as what it returned.
  : > "$W/per-client.tsv"
  for k in 1 2 3; do
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$k" \
      "$(walk_field_digest "$(sed -n '1p' "$OUT/client-$k.digest")")" \
      "$(walk_field_digest "$(sed -n '1p' "$OUT/warmup-$k.digest")")" \
      "$(walk_field_digest "$(sed -n '1p' "$OUT/warmup-verify-$k.digest")")" \
      "$(sed -n '1p' "$OUT/warmup-$k.rc")" \
      "$(sed -n '1p' "$OUT/warmup-verify-$k.rc")" \
      "$(sed -n '1p' "$OUT/client-$k.rc")" \
      "${clock_a_rcs[$((k - 1))]}" \
      "${clock_b_rcs[$((k - 1))]}" \
      "$MEASURED_ENDPOINT" "$seq_n" "$published_seq" \
      >> "$W/per-client.tsv"
  done

  # THE HARNESS OBSERVATIONS, each carrying its LABEL as data. The label is the
  # first field rather than something the assembler stamps on: a label added
  # unconditionally is a label no fixture can remove, and a check that cannot
  # fire is not a check.
  #
  # EVERY OUTCOME BELOW COMES FROM THE ROW LEDGER.
  # Recomputing a predicate here could weaken the claim
  # already checked by a row, such as omitting its content
  # check or its clock-poll requirement. Detail strings
  # describe the observation, while `obs_get` supplies
  # the recorded outcome. The final file must carry the
  # same verdict as the row rather than a second judgment
  # based on a subset of its conditions. OBS1 reads
  # the file back to compare it with the ledger.
  obs_get expected_digests_computed_before_publish; local v_digests="$OBS_VALUE"
  obs_get warmup_cache_dirs_were_empty;             local v_caches="$OBS_VALUE"
  obs_get no_cache_client_fails_p2;                 local v_nocache="$OBS_VALUE"
  obs_get three_processes;                          local v_three="$OBS_VALUE"
  obs_get clock_a_poll_cost;                        local v_clockcost="$OBS_VALUE"
  local v_stale="" v_nopub="" v_wrong="" v_emptyid="" v_killed="" v_reuse=""
  if [ "$negatives" -eq 1 ]; then
    obs_get stale_content;                 v_stale="$OBS_VALUE"
    obs_get no_publish;                   v_nopub="$OBS_VALUE"
    obs_get wrong_server;                 v_wrong="$OBS_VALUE"
    obs_get empty_run_id;                 v_emptyid="$OBS_VALUE"
    obs_get server_killed_before_snapshot; v_killed="$OBS_VALUE"
    if obs_has reused_cache_dir; then
      obs_get reused_cache_dir; v_reuse="$OBS_VALUE"
    fi
  fi
  {
    printf 'observation\texpected_digests_computed_before_publish\t%s\tthe v_n whole-tree digest %s and the v_(n+1) changed-subtree digest %s were both taken on the publisher SOURCE tree, the second after the delta and before gran publish ran\n' \
      "$v_digests" "$v_n_digest" "$sub_n1_digest"
    printf 'observation\twarmup_cache_dirs_were_empty\t%s\teach of the three cache-dirs was created by this run and refused if it held any entry before its warm-up\n' \
      "$v_caches"
    printf 'observation\tno_cache_client_fails_p2\t%s\tno-cache %s B reading digest %s, warmed client-1 %s B, novel %s B, expected v_(n+1) subtree digest %s\n' \
      "$v_nocache" "$nocache_bytes" "$nocache_digest" "$c1_bytes" "$novel_bytes" "$sub_n1_digest"
    printf 'observation\tthree_processes\t%s\tthe snapshot directory holds %s entries of which %s are .json, want 11 and 11; the writers emit no pid and no timestamp, so the count is what is buildable here and the role-copy case stays open\n' \
      "$v_three" "$entry_count" "$json_count"
    printf 'observation\tclock_a_poll_cost\t%s\t%s\n' "$v_clockcost" "$clock_detail"
    if [ "$negatives" -eq 1 ]; then
      printf 'observation\tstale_content\t%s\tobserved %s against expected %s\n' \
        "$v_stale" "$stale_digest" "$sub_n1_digest"
      printf 'observation\tno_publish\t%s\tbefore the publish, clock A exited %s after %s polls with cap verdict %s and clock B exited %s after %s mounts with cap verdict %s, against the same v_(n+1) sentinel hash both met after it\n' \
        "$v_nopub" "$nopublish_a_rc" "${nopub_a_polls:-none}" "${nopub_a_verdict:-none}" \
        "$nopublish_b_rc" "${nopub_b_tries:-none}" "${nopub_b_verdict:-none}"
      printf 'observation\twrong_server\t%s\ta publisher pointed at the terminated stack endpoint exited %s with a connection refusal on its stderr (grep rc %s) and wrote %s snapshot\n' \
        "$v_wrong" "$wrong_rc" "$wrong_refused_rc" "$([ -e "$wrong_snapshot" ] && echo a || echo no)"
      printf 'observation\tempty_run_id\t%s\ta measured process given an empty --wire-run-id exited %s naming the writer refusal (grep rc %s) and wrote %s file\n' \
        "$v_emptyid" "$emptyid_rc" "$emptyid_named_rc" "$([ -e "$emptyid_snapshot" ] && echo a || echo no)"
      printf 'observation\tserver_killed_before_snapshot\t%s\ta granary-server SIGKILLed before its rename left no snapshot and the presence floor refused the run\n' \
        "$v_killed"
      if [ -n "$v_reuse" ]; then
        printf 'observation\treused_cache_dir\t%s\ta clock-B mount on a REUSED cache-dir read %s; the v_n sentinel is %s and the published v_(n+1) sentinel is %s\n' \
          "$v_reuse" "$(sed -n '1p' "$NEG/reuse.hash")" "$sentinel_old" "$sentinel_new"
      fi
    fi
  } > "$W/observations.tsv"

  # ---------------- OBS1: THE OBSERVATION FILE, READ BACK AGAINST THE LEDGER
  #
  # The oracle for the whole table above, and it is not decoration: the defect
  # it closes is a persisted outcome that disagrees with the row that judged
  # it, and the only way to see that is to read the FILE. Two directions, both
  # required. Every name a row registered must appear EXACTLY ONCE in the file
  # with the registered outcome — so a printf that hardcodes `pass`, or that
  # recomputes a predicate, goes red here. And every name IN the file must have
  # been registered — so a successor who adds an observation with an inline
  # verdict cannot slip it in beside these.
  #
  # `no_snapshot` is deliberately absent from both sides: it is decided by ASM4
  # inside the artifact phase and appended to this file afterwards, which is
  # why this row runs before that phase.
  local obs_name obs_written obs_lines obs_bad="" obs_stray="" obs_checked=0
  while IFS= read -r obs_name; do
    [ -n "$obs_name" ] || continue
    obs_checked=$((obs_checked + 1))
    obs_lines="$(awk -F '\t' -v n="$obs_name" '$2 == n { c++ } END { print c + 0 }' "$W/observations.tsv")"
    obs_written="$(awk -F '\t' -v n="$obs_name" '$2 == n { print $3; exit }' "$W/observations.tsv")"
    obs_get "$obs_name"
    if [ "$obs_lines" != "1" ] || [ "$obs_written" != "$OBS_VALUE" ]; then
      obs_bad="$obs_bad $obs_name(lines=$obs_lines file=[$obs_written] row=[$OBS_VALUE])"
    fi
  done <<< "$OBS_REGISTERED"
  while IFS= read -r obs_name; do
    [ -n "$obs_name" ] || continue
    if ! obs_has "$obs_name"; then
      obs_stray="$obs_stray $obs_name"
    fi
  done <<< "$(awk -F '\t' '{ print $2 }' "$W/observations.tsv")"
  if [ "$obs_checked" -ge 1 ] && [ -z "$obs_bad" ] && [ -z "$obs_stray" ]; then
    row_pass OBS1 "all $obs_checked persisted observations carry the outcome of the ROW that judged them, each exactly once, and no observation in $W/observations.tsv was written without one — the artifact cannot record a claim weaker than the check the harness actually ran"
  else
    row_fail OBS1 "the observation file disagrees with the row ledger: checked=$obs_checked mismatched=[$obs_bad] unregistered=[$obs_stray]. A persisted outcome that its row would not have granted is a check that has silently stopped existing"
  fi

  # THE RUN'S OWN LEDGER, WRITTEN BEFORE ANY ASSEMBLY. `assemble-artifact` runs
  # later and in a fresh process whose counters start at zero, so without this
  # record it could not tell a run the harness ACCEPTED from one it REJECTED —
  # and it would assemble a complete-looking artifact for the second.
  write_run_status "$W/run-status.tsv" "$SELF_TEST_ROWS" "$SELF_TEST_FAILURES"

  if [ -n "$artifact_out" ]; then
    artifact_phase "$W" "$H" "$NEG" "$artifact_out" "$node_samples" \
      "$venue_node" "$venue_guest" "$t_server_stopped"
  fi

  echo
  echo "m10-propagate: $SELF_TEST_ROWS rows, $SELF_TEST_FAILURES failed"
  echo "m10-propagate: eleven snapshots in $H"
  echo "m10-propagate: timeline in $TIMELINE_FILE, corpus record in $W/corpus.tsv"
  echo "m10-propagate: clocks in $W/clocks.tsv, per-client rows in $W/per-client.tsv, observations in $W/observations.tsv"
  if [ "$SELF_TEST_FAILURES" -ne 0 ]; then
    die "the propagation run FAILED"
  fi
  echo "m10-propagate: propagation run PASSED"
}

# ------------------------------------------------- THE STANDALONE ASSEMBLY
#
# The same phase, run later against a KEPT run directory. It exists because
# `scripts/m10-node-sample.sh` samples the node FROM THE DRIVER and writes its
# file there: on the measurement venue the samples cannot be on the guest until
# the sampler has stopped and the file has been copied across, which is after
# the run has ended. `propagation-run --artifact` stays the one-shot path for a
# venue where the samples are already local — the self-test guest — and this is
# the path the cluster run takes.
assemble_artifact_verb() {
  local run_dir="" artifact_out="" node_samples="" venue_node="" venue_guest=""
  local git_sha=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --run-dir)      [ "$#" -ge 2 ] || { usage; exit 1; }; run_dir="$2"; shift 2 ;;
      --artifact)     [ "$#" -ge 2 ] || { usage; exit 1; }; artifact_out="$2"; shift 2 ;;
      --node-samples) [ "$#" -ge 2 ] || { usage; exit 1; }; node_samples="$2"; shift 2 ;;
      --venue-node)   [ "$#" -ge 2 ] || { usage; exit 1; }; venue_node="$2"; shift 2 ;;
      --venue-guest)  [ "$#" -ge 2 ] || { usage; exit 1; }; venue_guest="$2"; shift 2 ;;
      --git-sha)      [ "$#" -ge 2 ] || { usage; exit 1; }; git_sha="$2"; shift 2 ;;
      *) usage; exit 1 ;;
    esac
  done

  require_tools
  require_unprivileged
  local tool
  for tool in awk cp date ln mkdir mktemp mv python3 sed uname; do
    command -v "$tool" > /dev/null 2>&1 \
      || die "required tool is missing (the assembly needs it): $tool"
  done

  [ -n "$run_dir" ] || die "assemble-artifact requires --run-dir"
  [ -d "$run_dir" ] || die "the run directory does not exist: $run_dir"
  [ -d "$run_dir/snapshots" ] \
    || die "$run_dir holds no snapshots/ directory; it is not a propagation-run directory"
  [ -f "$run_dir/timeline.tsv" ] \
    || die "$run_dir holds no timeline.tsv; it is not a propagation-run directory"
  [ -n "$artifact_out" ] || die "assemble-artifact requires --artifact"
  case "$artifact_out" in
    /*) ;;
    *) die "--artifact must be an absolute path, got: $artifact_out" ;;
  esac
  case "$artifact_out" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
      die "--artifact points inside the repository ($artifact_out); the artifact and the log stay OUTSIDE it" ;;
  esac
  [ ! -e "$artifact_out" ] || die "the artifact destination already exists: $artifact_out"
  [ -n "$node_samples" ] || die "assemble-artifact requires --node-samples"
  [ -f "$node_samples" ] || die "the node-CPU samples file does not exist: $node_samples"
  [ -n "$venue_node" ] || die "assemble-artifact requires --venue-node"
  [ -n "$venue_guest" ] || die "assemble-artifact requires --venue-guest"

  # THE HARNESS SHA AND VENUE COME FROM THE RUN'S RECORD.
  # Assembly can happen later, after a checkout advances
  # or a guest is upgraded. Reading `git rev-parse HEAD`
  # or `uname` at assembly time could attribute the
  # measurement to code or a kernel that did not run
  # it. The recorded venue is required, and an optional
  # `--git-sha` acts as an assertion: it must equal
  # the recorded value. A disagreement is refused
  # instead of choosing which identity to publish.
  local venue_file="$run_dir/venue.tsv" recorded_sha
  [ -f "$venue_file" ] \
    || die "$run_dir holds no venue.tsv, so it carries no record of the machine and the commit that took the measurement. It is refused rather than re-derived here: a guest upgraded or a checkout advanced between the run and this assembly would otherwise be recorded as the venue of the measurement"
  recorded_sha="$(awk -F '\t' '$1 == "git_sha" { print $2; exit }' "$venue_file")"
  case "$recorded_sha" in
    *[!0-9a-f]*|'') die "the git sha recorded by the run is not 40 lowercase hex characters: [$recorded_sha] in $venue_file. Neither venue carries git, so pass --git-sha <40 hex> to the RUN, where the tree it describes is the tree that is executing" ;;
  esac
  [ "${#recorded_sha}" -eq 40 ] \
    || die "the git sha recorded by the run is ${#recorded_sha} characters, want 40: [$recorded_sha]"
  if [ -n "$git_sha" ] && [ "$git_sha" != "$recorded_sha" ]; then
    die "--git-sha is [$git_sha] and the run recorded [$recorded_sha]. One of the two is a belief about this run rather than a fact of it, and choosing between them here is how a measurement acquires the provenance of the machine that assembled it"
  fi
  git_sha="$recorded_sha"

  # The run's LAST timeline stamp, read from the run's own record — the same
  # value `propagation-run` passes, and the one the coverage rule is about.
  TIMELINE_FILE="$run_dir/timeline.tsv"
  local last_stamp
  last_stamp="$(timeline_get server_stopped)"

  echo "m10-propagate: assembling the artifact for $run_dir"
  echo "m10-propagate: the run recorded harness sha $git_sha and venue $(awk -F '\t' '$1 == "arch" || $1 == "kernel" || $1 == "os" { printf "%s ", $2 }' "$venue_file")"
  artifact_phase "$run_dir" "$run_dir/snapshots" "$run_dir/assembly" \
    "$artifact_out" "$node_samples" "$venue_node" "$venue_guest" \
    "$last_stamp"

  echo
  echo "m10-propagate: $SELF_TEST_ROWS rows, $SELF_TEST_FAILURES failed"
  if [ "$SELF_TEST_FAILURES" -ne 0 ]; then
    die "the artifact assembly FAILED"
  fi
  echo "m10-propagate: artifact assembly PASSED"
}

# Identity, writer kind and the poison flag for ONE snapshot. A function
# rather than eleven copies: a copy per call site is how one of these quietly
# stops running.
check_snapshot_identity() {
  local file="$1" role="$2" want_kind="$3" got
  got="$(snapshot_field "$file" "run_id" "$role")"
  [ "$got" = "$RUN_ID" ] \
    || die "$role: snapshot run_id [$got], want [$RUN_ID]; five files stamped from an unset variable satisfy equality just as well as five stamped from a real id"
  got="$(snapshot_field "$file" "role" "$role")"
  [ "$got" = "$role" ] || die "$role: snapshot role [$got], want [$role]"
  got="$(snapshot_field "$file" "writer_kind" "$role")"
  [ "$got" = "$want_kind" ] || die "$role: writer_kind [$got], want [$want_kind]"
  got="$(snapshot_field "$file" "poisoned" "$role")"
  [ "$got" = "false" ] \
    || die "$role: the snapshot is POISONED; its counter overflowed or was never sealed, so every number in it is unusable"
}

case "${1:-}" in
  walk)
    shift
    [ "$#" -eq 1 ] || { usage; exit 1; }
    require_tools
    subtree_digest "$1" "walk $1"
    ;;
  instrument-self-test)
    shift
    instrument_self_test "$@"
    ;;
  assemble-artifact)
    shift
    ROW_PREFIX="ASSEMBLE"
    assemble_artifact_verb "$@"
    ;;
  propagation-run)
    shift
    ROW_PREFIX="RUN"
    # The eleven snapshots and the timeline ARE this verb's output, so the run
    # directory is kept unless a caller explicitly asks otherwise.
    SELF_TEST_KEEP=1
    propagation_run "$@"
    ;;
  *) usage; exit 1 ;;
esac
