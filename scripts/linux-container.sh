#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# The Linux repro harness. granary's FUSE client crate
# (crates/granary-fuse) and the cfg(target_os = "linux") parts of
# crates/granary-client can only be BUILT and RUN on Linux, and this Mac
# cannot do either directly. The loop this script closes:
#
#   BUILD in a rootless podman container (native aarch64 Linux, matching
#   rust-toolchain.toml's channel exactly) -> land the artifacts on a
#   directory shared with the podman VM over virtiofs -> RUN them either in a
#   second container (the two privilege lanes below) or in the BARE VM
#   itself (the process-per-test root-gated tests a container's own root
#   user would corrupt).
#
# Subcommands: build, test, mount, conform, clean, --self-test (also
# `self-test`).
#
# THREE LANES, each defined by the PRECONDITION IT GUARANTEES -- never by a
# list of test names, because a name
# resolves to whatever nextest's filter matches today and a rename or a new
# test silently changes what a name-list gate actually covers:
#   container-root    -- container, --device /dev/fuse --cap-add SYS_ADMIN,
#                         the VM's fusectl bound at /sys/fs/fuse/connections,
#                         uid 0. require_root() cannot defer, and the
#                         connection-abort witnesses find their control
#                         filesystem, so every root-gated granary-fuse test
#                         necessarily executes.
#   container-nonroot -- container, --user <uid>:<gid>, no grants, uid != 0.
#                         The `owner_uid == 0` guards in granary-client's
#                         mount.rs cannot fire, so those fixtures necessarily
#                         execute. It leaves the gran binary's daemon_linux_
#                         rows to the bare VM, the one selection that runs
#                         them as root.
#   bare VM            -- podman machine ssh, a nextest ARCHIVE, sudo. Real
#                         mount namespace (a leaked mount is visible there,
#                         which it is NOT from inside a container whose own
#                         mount namespace is torn down on exit), and
#                         process-per-test isolation, which containment
#                         alone does not give (see the S8 note below).
#                         With pre-existing gran mounts, mount warns and
#                         continues; unit refuses before running its checks.
#                         Unit also refuses pre-existing gran-mount@* units
#                         or a runtime gran-mount@.service template.
#
# MEASURED FACTS this script depends on (all executed 2026-09-01 on this
# machine; re-run anything you depend on rather than trusting this comment
# forever):
#  - cargo-nextest HIDES a passing test's output unless run with
#    --success-output=final: without it, 8 granary-fuse tests that verified
#    nothing print a green "168 passed, 0 skipped" with ZERO "NOT EXECUTED"
#    markers in the log. The flag is load-bearing; S6/S7 in --self-test pin
#    it, including the contrast that the flag changes the marker count but
#    not nextest's own reported summary.
#  - Running granary-fuse's root-gated tests in a NON-root container, or
#    granary-client's uid-0-gated tests in a ROOT container, is a fail-open:
#    nextest reports a clean pass having verified nothing. S6 and S10 in
#    --self-test are the positive controls for those two gates.
#  - The bare VM has no cargo. Running the compiled test BINARY there
#    directly is ALSO a fail-open: unmount.rs's fusermount fallback tests
#    call setuid(65534) irreversibly (the file's own comment says they rely
#    on process-per-test isolation), so the first one poisons every later
#    root-gated test in the SAME process (measured: 18 passed, 0 failed, 6
#    "NOT EXECUTED" once --nocapture reveals the tests' own output -- same
#    capture-by-default trap as the nextest flag above). This script runs
#    a nextest ARCHIVE extracted and run with process-per-test isolation. S8
#    in --self-test pins the contrast.
#  - virtiofs SQUASHES ownership on the shared path: a file written by one
#    privilege lane appears owned by the other's uid, and both can write, so
#    container-root and container-nonroot can share ONE target dir.
#  - virtiofs does not support FIFOs. granary-client's seed fixtures root
#    their scratch dir at $HOME and one calls mkfifo, so the nonroot lane
#    needs a real HOME on a non-virtiofs filesystem (a container-local dir),
#    chmod 700 (validate_seed_ancestor refuses a group-writable HOME too).
#  - `gran` has no `--version` flag (a hand-rolled arg parser, no clap): it
#    prints its usage banner and exits 2 for ANY unrecognized invocation,
#    --version included. `mount`'s ELF/loader acceptance check therefore
#    accepts "exit 2 with the usage banner present" as proof the binary
#    RAN, rather than requiring exit 0 -- a genuine loader failure (wrong
#    ISA, a missing shared library) would print no such banner at all. See
#    the `mount` subcommand.
#
# SHELL DISCIPLINE, binding: every gate captures `rc=$?` on its own line,
# never through a pipe (`cmd | tail || true` binds `||` to the pipeline's
# exit status, which is `tail`'s, not `cmd`'s). No `pgrep -f`/`ps | grep`
# process probes -- they can match their own argv; leak detection here reads
# the mount table (/proc/self/mountinfo, or a before/after diff of it in the
# VM) instead. `--self-test` never accepts a bare nonzero exit as proof a
# guard fired -- it greps for that guard's OWN diagnostic string, and every
# negative case is paired with a positive proving the same code path is not
# vacuously always-refuse.
#
# REQUIRES bash >= 4. This is a PARSE-time requirement, not a runtime one --
# no version check inside this file can help, because the failure happens
# before any of this file's own code ever executes. Measured 2026-09-01:
# stock macOS /bin/bash 3.2.57 mis-parses a heredoc nested inside a `$( ... )`
# command substitution and reads the heredoc BODY as live code; this script
# uses that idiom four times (the BUILD/ROOT/NONROOT/SELFTEST_PROBE lane
# scripts below, each captured via `"$(cat <<'INNER' ... INNER)"`) and is the
# only script in `scripts/` that does. Symptom: `syntax error near unexpected
# token '('`, rc nonzero, under 3.2.57; rc=0 (silently fine) under 5.3.15+.
# The reported LINE is not the root cause's own location -- it is wherever
# 3.2's confused parser happens to trip on the first stray `(` after
# mis-reading the FIRST heredoc's body as code, so it drifts with every
# unrelated edit to this file; `bash -n scripts/linux-container.sh` under
# `/bin/bash` reproduces it fresh if you need the current line. Run this
# with a bash from Homebrew or similar (`bash --version`), never with
# `/bin/bash` on an unmodified Mac. Do not "fix" this with a runtime guard.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO_ROOT="$(pwd -P)"

die() {
  echo "linux-container: $*" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Configuration, all overridable by environment.
# ---------------------------------------------------------------------------
GRANARY_LINUX_TARGET_DIR="${GRANARY_LINUX_TARGET_DIR:-$REPO_ROOT/../granary-target-linux}"
GRANARY_LINUX_IMAGE="${GRANARY_LINUX_IMAGE:-localhost/linux-container:latest}"
GRANARY_LINUX_MEMORY="${GRANARY_LINUX_MEMORY:-8g}"
# The container-root lane's podman grant flags are FIXED in production.
# --self-test needs to drive the REAL `cmd_test`/`run_root_container`
# codepaths with one grant deliberately withheld (S4/S5/S19), or the lane
# forced non-root despite full grants (S11), without reimplementing
# The probes need controlled changes to the production
# grants, not arbitrary podman options supplied through
# the environment. An option string could include
# `--entrypoint /bin/true`, making the container exit
# successfully without running its preflight or tests.
# Such an exit would say nothing about whether the
# required privilege was available. Map the test choice
# to flags inside the script so the probe cannot replace
# the command whose refusal it intends to observe.
#
# Use a CLOSED ENUM (`root_lane_grants` below maps it to flags
# internally): only `none|no-cap|no-device|no-fusectl|nonroot` are accepted, anything
# else refused BY NAME. An arbitrary podman flag must never be reachable
# from the environment. Not documented in `usage` alongside the three
# knobs above -- this is a --self-test-only poison switch, not a
# production behaviour toggle.
GRANARY_SELFTEST_ROOT_LANE_POISON="${GRANARY_SELFTEST_ROOT_LANE_POISON:-none}"

CONTAINERFILE="$REPO_ROOT/scripts/linux-container.Containerfile"
STAMP_NAME=".linux-container-harness"
# A container-local (never virtiofs) HOME, chmod 700 -- measured fact above
# (fifo_pub_sidecar_is_refused_promptly needs a real filesystem for mkfifo;
# validate_seed_ancestor separately refuses a group-writable HOME).
CONTAINER_HOME="/tmp/linux-container-home"
# .github/workflows/ci.yml's cargo-nextest pin -- grep that file for
# `cargo-nextest@` to reconfirm rather than trusting this literal forever.
WANT_NEXTEST="0.9.143"
# rust-toolchain.toml's channel, read from the file itself so this can never
# drift from what the repo actually pins. `grep -m1 '^channel'` is anchored
# to column 1 and would go silently empty against an indented `channel =`
# under a reformatted `[toolchain]` table -- fails CLOSED today (an empty
# WANT_CHANNEL can never equal a real rustc version, so BUILD-PREFLIGHT
# still refuses), but with a confusing "does not EXACTLY match channel """
# message. Die here, naming the actual cause, rather than downstream with
# that riddle.
# Keep extraction failures available for the explicit
# empty-value refusal rather than allowing the assignment
# to terminate under errexit. Normalize single and double
# quotes before extracting the channel. The first extracted
# line is retained without a short-circuiting reader, then
# checked before it becomes the expected toolchain value.
WANT_CHANNEL="$(tr "'" '\"' < "$REPO_ROOT/rust-toolchain.toml" 2>/dev/null | sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' || true)"
WANT_CHANNEL="${WANT_CHANNEL%%$'\n'*}"   # first line, without a short-circuit reader
[ -n "$WANT_CHANNEL" ] || die "SETUP: refused -- could not parse a channel out of '$REPO_ROOT/rust-toolchain.toml' (grep -m1 '^channel' found nothing at column 1). If the file was reformatted with an indented key, update this grep to match."
# Validate the extracted channel's shape as well
# as requiring a nonempty value. The case below
# rejects whitespace and equals signs, keeping
# assignment syntax or multiword text from becoming
# an expected channel. This is a separate check
# after the sed extraction and first-line selection.
case "$WANT_CHANNEL" in
  *[[:space:]]* | *=*)
    die "SETUP: refused -- the channel extracted from '$REPO_ROOT/rust-toolchain.toml' ('$WANT_CHANNEL') contains whitespace or '=', which no real channel value does. The extractor's sed emits an unmatched line unchanged rather than failing; refusing a pass-through here rather than trusting it."
    ;;
esac

# root_lane_grants: maps GRANARY_SELFTEST_ROOT_LANE_POISON to the podman grant flags
# run_root_container passes, refusing any value outside the closed set BY
# NAME before a single podman flag is ever built from it. `none` is full
# production grants; the others exist only for --self-test probes
# (S4 drops the cap, S5 drops the device, S19 drops the control filesystem,
# S11 forces non-root despite full grants).
#
# With the argument `root` (run_root_container only) the flags also bind the
# VM's fusectl (FUSECTL_BIND), unless the poison is no-fusectl; conform and
# demo never use it.
# The control filesystem is the VM's own fusectl, bound in: the podman
# machine is rootless, and fusectl cannot be mounted inside a user namespace
# (mount -t fusectl fails with EPERM there). Its connection directories are
# global, and one the container's root creates is owned by that root, so a
# witness can write its own connection's abort file (measured 2026-11-01).
FUSECTL_BIND="-v /sys/fs/fuse/connections:/sys/fs/fuse/connections"
root_lane_grants() {
  local bind=""
  [ "${1:-}" != root ] || bind=" $FUSECTL_BIND"
  case "$GRANARY_SELFTEST_ROOT_LANE_POISON" in
    none) printf '%s' "--device /dev/fuse --cap-add SYS_ADMIN$bind" ;;
    no-cap) printf '%s' "--device /dev/fuse$bind" ;;
    no-device) printf '%s' "--cap-add SYS_ADMIN$bind" ;;
    no-fusectl) printf '%s' "--device /dev/fuse --cap-add SYS_ADMIN" ;;
    nonroot) printf '%s' "--device /dev/fuse --cap-add SYS_ADMIN$bind --user 1000:1000" ;;
    *)
      die "ROOT-LANE-POISON: refused -- GRANARY_SELFTEST_ROOT_LANE_POISON=\"$GRANARY_SELFTEST_ROOT_LANE_POISON\" is not one of the closed set none|no-cap|no-device|no-fusectl|nonroot. Arbitrary podman flags must never be reachable from the environment."
      ;;
  esac
}

[ -n "${HOME:-}" ] || die "FORBIDDEN-ROOT setup: refused -- \$HOME is unset; the forbidden-directory guards below cannot be evaluated without it."

# CLEANUP_DIR + cleanup_dir: a single shared EXIT-trap slot for cmd_mount
# and cmd_self_test's scratch workdirs (main() runs exactly one subcommand
# per invocation, so the two never collide). Deliberately a plain
# (non-`local`) variable: an EXIT trap can fire AFTER the function that set
# it has already returned (the ordinary end-of-script path through main()),
# at which point a `local` variable is out of scope and `set -u` refuses to
# read it -- a global slot is always in scope. And deliberately `trap
# cleanup_dir EXIT` (a function, referencing the variable through normal
# quoted expansion) rather than `trap "rm -rf '$dir'" EXIT`: that builds
# the trap action as a STRING with the path spliced in via simple
# single-quoting, which a path containing its own single quote would break
# out of. A function call registered as the trap action is never
# re-parsed from interpolated text at all.
CLEANUP_DIR=""
cleanup_dir() {
  if [ -n "$CLEANUP_DIR" ]; then
    rm -rf -- "$CLEANUP_DIR"
  fi
}
trap cleanup_dir EXIT

usage() {
  cat <<USAGE
usage: $0 <build|test|publish-restart|mount|conform|demo|unit|clean|--self-test>

  build        container-nonroot: builds the gran binary and the
               granary-fuse and granary-cli daemon archives onto \$GRANARY_LINUX_TARGET_DIR
               (shared with the VM over virtiofs).
  test         both container lanes: container-root (granary-fuse) and
               container-nonroot (granary-client + its Linux clippy/doc).
               The gran binary's daemon_linux_ rows run under mount.
  mount        the bare VM (podman machine ssh): runs the container-built
               gran binary there, then the FUSE and daemon archives under sudo
               with process-per-test isolation, then checks the VM's own
               mount table for a leak.
               Warns and continues when a gran mount already exists on the VM.
               Also runs the blocked-stderr battery; set
               GRANARY_STDERR_CONTROLS=1 to build and run scratch-copy mutants.
  conform      builds and freshly stages the four conformance binaries in a
               container-nonroot lane, then runs scripts/conformance.sh in
               a fixed container-root lane.
  demo         reuses conform's build and staging, then runs
               scripts/demo.sh (a smoke mount, read back, teardown) in a
               container-root lane, requiring every witness checked by check_demo_log_witnesses
               by name, then runs scripts/demo-self-check.sh (the
               negatives) in a second container-root lane, requiring
               DEMO-SELF-CHECK: PASS and each N<k> PASS.
  unit         the systemd unit check (packaging/gran-mount@.service):
               reuses conform's build and staging, starts the stack in a
               container on the VM's OWN network (--network host) so the
               bare VM can reach it, asserting that BEFORE installing anything,
               installs the staged gran on the VM and runs
               scripts/unit-check.sh there under sudo, requires every
               UNIT witness in the log by name, tears the stack down, and
               runs the VM leak gate (a mountinfo before/after diff AND
               'systemctl list-units --all gran-mount@*' both empty).
               Refuses when a gran mount already exists on the VM.
               Also refuses pre-existing gran-mount@* units or a runtime template.
  publish-restart  runs scripts/publish-restart.sh in the nonroot Linux container,
               on the supported authority venue, including persistent backend control,
               dispatch-loss provenance, exclusion, rendezvous and exact coverage.
  clean        removes the named artefacts 'build'/'test'/'conform'/'demo'/'unit'
               write under \$GRANARY_LINUX_TARGET_DIR (requires the stamp file the
               harness writes to be present first), then removes the now-empty
               directory with a non-recursive rmdir -- a directory that
               has gained a TOP-LEVEL foreign entry fails that rmdir and is
               left alone, by construction. Content placed INSIDE a
               marker-validated recursive tree (debug/, release/, armed/,
               conform-bin/) is not individually protected.
  --self-test  plants failure conditions across the target-dir guards, the
               container preflights, the marker gates and -- directly --
               the production subcommands (cmd_test, cmd_mount, cmd_conform,
               cmd_demo, cmd_unit)
               themselves,
               and confirms this script refuses each one, paired with a
               positive proving the refusal is not vacuous. No case count is
               named here deliberately (this repo has been bitten by a
               hardcoded count going stale); read the case table the run
               itself prints. (also accepted as the subcommand 'self-test')

Environment (all overridable):
  GRANARY_LINUX_TARGET_DIR   default: \$repo/../granary-target-linux
  GRANARY_LINUX_IMAGE        default: localhost/linux-container:latest
  GRANARY_LINUX_MEMORY       default: 8g
USAGE
}

# ---------------------------------------------------------------------------
# canon_path: resolve symlinks WITHOUT requiring the path to exist.
#
# This machine's readlink -f (BSD) refuses a path whose final component does
# not exist, but the guards below must be able to refuse a target dir
# BEFORE `build` has ever created it (first run, or a --self-test case that
# plants a nonexistent path). Walks up to the nearest existing ancestor,
# canonicalizes THAT (resolving any symlink in it), and reattaches the
# nonexistent (therefore symlink-free) suffix untouched.
#
# `-e` is false for a dangling symlink,
# but `-L` still recognises the link
# itself. The direct-resolution branch
# therefore accepts either an existing
# target or a symlink. Only a path with no
# node takes the walk-up branch. Otherwise
# a dangling link could be compared using
# its unresolved spelling rather than
# the destination returned by readlink.
#
# Normalise the joined ancestor and suffix
# before comparing paths. A nonexistent suffix
# can contain `.` or `..`, so its literal
# spelling need not match the directory consumers
# reach. The existing ancestor is resolved
# first, then os.path.normpath normalises the
# joined path. If that result exists, it is
# resolved again. This keeps a spelling such
# as a missing component followed by `..` from
# bypassing the canonical target comparison.
canon_path() {
  local p="$1" dir suffix="" next
  if [ -e "$p" ] || [ -L "$p" ]; then
    readlink -f "$p"
    return 0
  fi
  dir="$p"
  while [ ! -e "$dir" ] && [ ! -L "$dir" ]; do
    suffix="$(basename "$dir")/$suffix"
    next="$(dirname "$dir")"
    if [ "$next" = "$dir" ]; then
      break
    fi
    dir="$next"
  done
  suffix="${suffix%/}"
  if ! dir="$(readlink -f "$dir")" || [ -z "$dir" ]; then
    die "SETUP: refused -- could not canonicalise '$p' (readlink -f failed on its nearest existing ancestor; a symlink loop does this). An unresolvable path must never be joined to its suffix and returned as if it had resolved."
  fi
  if [ -n "$suffix" ]; then
    # Normalise the JOINED path (not just the suffix) lexically: this is
    # safe specifically because $dir is already the output of `readlink -f`
    # (symlink-free by construction), so a `..` in the nonexistent suffix
    # can never misinterpret a symlink on the way back up through it -- and
    # it additionally collapses a suffix whose `..` count walks back above
    # $dir itself, which normalising the suffix ALONE would not.
    local joined
    joined="$(python3 -c 'import os,sys; print(os.path.normpath(sys.argv[1]))' "$dir/$suffix")"
    # A `..` in the suffix can CANCEL the nonexistent component and land back on
    # a path that exists -- and on a case-insensitive volume that may be another
    # SPELLING of an existing directory. Returning the lexical answer there let
    # `$REPO/.missing/../TARGET` pass G1 and stamp the real `target/`. So: if the
    # normalised result exists, resolve it for real; only a still-nonexistent
    # result is returned lexically.
    if [ -e "$joined" ] || [ -L "$joined" ]; then
      readlink -f "$joined"
    else
      printf '%s\n' "$joined"
    fi
  else
    printf '%s\n' "$dir"
  fi
}

# ---------------------------------------------------------------------------
# Guards. Each refuses with its own distinct, greppable message and exit 1.
# ---------------------------------------------------------------------------

# The destructive-removal hazard needs a
# bound on what cleanup can delete, as well
# as checks on the supplied path. Stamp
# validation, emptiness checks and path
# canonicalisation each have edge cases; a
# mistake in one must not grant permission to
# remove the caller's entire directory.
# `clean_target` limits removal to named entries
# inside a target that passes the checks.
#
# `clean_target` does not remove the caller-named
# directory itself. It removes exactly the named
# artefacts `build`/`test` write, then removes the (by then hopefully
# empty) directory with a single NON-RECURSIVE `rmdir`. A TOP-LEVEL entry
# the harness did not write -- a foreign file, a directory it never
# created -- fails that `rmdir` and is left alone, BY CONSTRUCTION: that is
# a kernel guarantee, not a script check, and does not depend on the stamp,
# the emptiness probe or the forbidden-roots list being correct to be the
# reason a mistaken target dir survives. TOP-LEVEL ONLY, stated narrowly on
# purpose: `debug/` is cargo's own build tree, too large to
# enumerate, and is removed recursively once claimed as cargo's own (see
# `clean_target`'s marker check) -- content placed INSIDE it is not.
#
# `guard_forbidden_roots` and the stamp (via `claim_target_dir`) are KEPT
# below -- they are cheap and still catch an obvious mistake early, with a
# clearer message than "rmdir: Directory not empty" -- but neither is the
# LAST line of defence any more. (A controller proposal to instead hardcode
# `clean`'s path and drop these guards entirely was REFUTED: `claim_target_dir`
# is also called from `build`/`test`/`--self-test`, so the defective checks
# would have stayed live on the WRITE path with one less consumer; a fixed
# NAME is not a proof of ownership either.)
guard_forbidden_roots() {
  local canon="$1" home_canon
  if [ "$canon" = "/" ]; then
    die "FORBIDDEN-ROOT: refused -- '$canon' is the filesystem root. The harness may only ever use a directory it created; refusing before anything -- mkdir, stamp or clean -- touches '/'."
  fi
  home_canon="$(canon_path "$HOME")"
  if [ "$canon" = "$home_canon" ]; then
    die "FORBIDDEN-ROOT: refused -- '$canon' IS \$HOME ('$home_canon'). The harness may only ever use a directory it created; refusing before anything -- mkdir, stamp or clean -- touches your home directory."
  fi
  if [ "$canon" = "$REPO_ROOT" ]; then
    die "FORBIDDEN-ROOT: refused -- '$canon' IS the repo root ('$REPO_ROOT'). The harness may only ever use a directory it created; refusing before anything -- mkdir, stamp or clean -- touches the repo."
  fi
  case "$REPO_ROOT" in
    "$canon"/*)
      die "FORBIDDEN-ROOT: refused -- '$canon' is an ANCESTOR of the repo root (the repo root '$REPO_ROOT' lies inside it). The harness may only ever use a directory it created; refusing before anything -- mkdir, stamp or clean -- touches anything above the repo."
      ;;
  esac
}

# claim_target_dir: the ownership rule enforced here, run before the FIRST
# write into the target dir on every path that writes one (`build`'s
# artifact drop and --self-test's prerequisite build; `test` also calls it
# before creating its logs/ subdirectory). Idempotent: safe to call on an
# already-claimed (stamped) directory every time.
claim_target_dir() {
  local canon="$1" probe probe_err probe_rc errtxt
  guard_forbidden_roots "$canon"
  # The stamp is tested with -L and -f, never a bare -e. `-e` FOLLOWS a
  # symlink, so a `.linux-container-harness` pointing anywhere -- at the repo's own
  # Cargo.toml, say -- would make a POPULATED directory look already claimed,
  # and the build lane's `: > "$STAMP"` then truncates the LINK TARGET rather
  # than the link. Demonstrated: a victim file went from content to zero
  # bytes exactly that way. A stamp that is not a regular file is refused.
  if [ -L "$canon/$STAMP_NAME" ]; then
    die "CLAIM: refused -- '$canon/$STAMP_NAME' is a SYMLINK. The stamp must be a regular file: writing through a symlinked stamp truncates whatever it points at, and trusting one would let a populated directory pass this ownership check."
  fi
  if [ -f "$canon/$STAMP_NAME" ]; then
    return 0
  fi
  if [ -e "$canon/$STAMP_NAME" ]; then
    die "CLAIM: refused -- '$canon/$STAMP_NAME' exists but is not a regular file. The stamp must be a regular file the harness itself wrote."
  fi
  if [ ! -e "$canon" ]; then
    mkdir -p "$canon"
    # Re-canonicalise now that the path EXISTS: canon_path's walk-up branch
    # reattaches a nonexistent suffix with the caller's own case, and on a
    # case-insensitive volume that is a DIFFERENT SPELLING of the same inode.
    # With the repo's target/ absent, G1 compared spellings and passed. The
    # direct branch normalises, so re-running the guard here fires.
    canon="$(canon_path "$canon")"
    # Probe the guards in a subshell first: they `die`, and a refusal must not
    # leave the directory this function just created lying around. If the probe
    # refuses, remove it and then call the guard FOR REAL so its own message is
    # what the operator sees.
    if ! ( guard_g1_not_repo_target "$canon"; guard_forbidden_roots "$canon" ) >/dev/null 2>&1; then
      rmdir "$canon" 2>/dev/null || true
      guard_g1_not_repo_target "$canon"
      guard_forbidden_roots "$canon"
    fi
    : >"$canon/$STAMP_NAME"
    echo "linux-container: claimed a fresh target dir '$canon' (did not exist -- created, stamped)."
    return 0
  fi
  # Emptiness probe via `find ... >file`, never `[ -z "$(ls -A ... 2>/dev/null)" ]`.
  # Two bugs in that one line: `2>/dev/null` swallowed find/ls's OWN
  # error, so an UNREADABLE populated directory (mode 0300 -- write+execute
  # is enough to CREATE the stamp file, but not enough to READ the
  # directory's entries) read as empty and got claimed anyway; and command
  # substitution strips ALL trailing newlines, so a directory whose only
  # entry is a filename that is itself just a newline character also read
  # as empty (`ls -A`'s one line of output is nothing but newlines).
  # Redirecting to a FILE and testing its SIZE (`-s`, not its content)
  # sidesteps the second bug entirely -- byte count is never fooled by
  # trailing-newline stripping the way a captured string is -- and find's
  # own exit status is captured explicitly on its own line, so the first
  # bug becomes a distinguishable refusal instead of a silent misread.
  probe="$(mktemp "${TMPDIR:-/tmp}/target-claim-probe.XXXXXX")"
  probe_err="$(mktemp "${TMPDIR:-/tmp}/target-claim-probe-err.XXXXXX")"
  # `if cmd; then...else rc=$?; fi`, not `set +e; cmd; rc=$?; set -e`
  # (S11 lesson, run_root_container): this function is called from
  # --self-test under the CALLER's own `set +e` (run_captured), and
  # restoring `set -e` here would turn errexit back on for the REST of
  # this function too -- if the stamp write below then failed under a
  # restored `set -e`, it would escape via `exit`, skipping this
  # function's own `return 0`, rather than reporting back through the
  # caller's intended `$?` capture.
  if find "$canon" -mindepth 1 -maxdepth 1 -print -quit >"$probe" 2>"$probe_err"; then
    probe_rc=0
  else
    probe_rc=$?
  fi
  if [ "$probe_rc" -ne 0 ]; then
    errtxt="$(cat "$probe_err")"
    rm -f "$probe" "$probe_err"
    die "CLAIM: refused -- could not determine whether '$canon' is empty (find rc=$probe_rc): $errtxt. An unreadable directory must never be scored as empty."
  fi
  if [ ! -s "$probe" ]; then
    rm -f "$probe" "$probe_err"
    : >"$canon/$STAMP_NAME"
    echo "linux-container: claimed an existing EMPTY target dir '$canon' (stamped)."
    return 0
  fi
  rm -f "$probe" "$probe_err"
  die "CLAIM: refused -- '$canon' exists, is not empty, and does not carry the stamp file '$STAMP_NAME'. The harness may only ever use a directory it created: a populated directory can never acquire the stamp, so it could never later be safely aimed at by 'clean'. Point GRANARY_LINUX_TARGET_DIR at a directory that does not exist yet, is empty, or already carries the stamp."
}

# G1 -- never share the macOS target/ with a Linux build: host build
# scripts and proc-macros collide, and cargo's lock misbehaves over
# virtiofs. Resolved through symlinks on BOTH sides (canon_path already
# resolved $1; this resolves the repo's target/ too) so a symlinked alias
# is refused as well as a literal one.
guard_g1_not_repo_target() {
  local target_canon="$1" repo_target_canon
  repo_target_canon="$(canon_path "$REPO_ROOT/target")"
  case "$target_canon" in
    "$repo_target_canon" | "$repo_target_canon"/*)
      die "G1: refused -- GRANARY_LINUX_TARGET_DIR resolves to '$target_canon', which IS or is INSIDE the repo's own target/ ('$repo_target_canon'). Never share the macOS target/ with a Linux build: host build scripts and proc-macros collide, and cargo's lock misbehaves over virtiofs."
      ;;
  esac
}

# G2 -- the target dir must lie under a virtiofs-shared prefix, or the
# built binary is unreachable from the VM that has to run it and the loop
# never closes. Measured 2026-09-01: /Users, /private and /var/folders are
# the four virtiofs mounts inside this podman machine (the fourth,
# /etc/containers, is podman's own config and never a build target).
guard_g2_virtiofs_visible() {
  local target_canon="$1"
  case "$target_canon" in
    /Users | /Users/* | /private | /private/* | /var/folders | /var/folders/*) ;;
    *)
      die "G2: refused -- GRANARY_LINUX_TARGET_DIR resolves to '$target_canon', which is not under a virtiofs-shared prefix (/Users, /private, /var/folders). The podman VM cannot see it, so the container-built binary would be unreachable from 'mount' and the loop would not close."
      ;;
  esac
}

# G1 + G2 together, on the resolved path. Prints the canonical path on
# stdout for the caller to capture; everything else goes to stderr via die.
# Refuse a target path the harness cannot transport FAITHFULLY. Command
# substitution strips trailing newlines, so a component ending in one silently
# becomes a different path downstream -- a build could then overwrite another
# stamped target, or clean remove it. Control characters have the same class of
# problem, and the remote-shell allowlist already refuses them for the VM leg.
# Refusing once at the boundary is cheaper and safer than making every transport
# newline-correct.
assert_transportable_path() {
  local label="$1" val="$2"
  case "$val" in
    *[[:cntrl:]]*)
      die "SETUP: refused -- $label contains a control character or newline. Such a path cannot be carried faithfully through command substitution (trailing newlines are stripped), so the harness would silently act on a DIFFERENT path than the one named."
      ;;
  esac
}

guards_target_dir() {
  local raw="${1:-$GRANARY_LINUX_TARGET_DIR}" canon
  assert_transportable_path "the target directory" "$raw"
  canon="$(canon_path "$raw")"
  guard_forbidden_roots "$canon"
  guard_g1_not_repo_target "$canon"
  guard_g2_virtiofs_visible "$canon"
  printf '%s\n' "$canon"
}

# G3 -- the podman machine must be running. This script never starts,
# stops or reconfigures it (task instructions); it only refuses to proceed
# without one already up.
guard_g3_machine_running() {
  local out
  set +e
  out="$(podman machine list --format '{{.Name}}\t{{.Running}}' 2>&1)"
  local rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    die "G3: refused -- 'podman machine list' failed (rc=$rc): $out"
  fi
  if ! printf '%s\n' "$out" | awk -F'\t' '$2=="true"{found=1} END{exit !found}'; then
    die "G3: refused -- no podman machine is 'Running: true' ($out). Start one with 'podman machine start' first; this script never starts, stops or reconfigures it."
  fi
}

# G4 -- the image must exist; build it from the Containerfile if not.
ensure_image() {
  if podman image exists "$GRANARY_LINUX_IMAGE"; then
    return 0
  fi
  echo "linux-container: G4 -- image '$GRANARY_LINUX_IMAGE' not found; building from $CONTAINERFILE" >&2
  podman build -t "$GRANARY_LINUX_IMAGE" -f "$CONTAINERFILE" "$REPO_ROOT"
}

# ---------------------------------------------------------------------------
# count_marker: prints the count of the FIXED STRING $2 in file $1 via
# `grep -Fc`, and returns grep's OWN exit status unchanged: 0 (matched,
# n>0), 1 (no match, n=='0' -- a genuinely benign, expected outcome), or >1
# (grep itself failed: the log is unreadable or missing, or some other
# error). Uses an `if` construct rather than `set +e`/`set -e` around the
# substitution, which is safe to call regardless of the ambient errexit
# state (an `if` condition never triggers errexit) -- unlike toggling
# `set -e` back on inside a function that might then `return` nonzero (see
# check_markers's own comment on that specific hazard).
#
# Read the grep status as well as its
# count. Status 1 means no matches and can
# be paired with the printed zero; a larger
# status means the count could not be
# established. A missing or unreadable
# log may provide no stdout at all.
# Replacing that empty output with zero
# would confuse a failed query with a clean
# log. `count_marker` prints what grep
# returned and returns its status so
# callers can distinguish those outcomes
# without relying on a defaulted number.
# ---------------------------------------------------------------------------
count_marker() {
  local log="$1" pat="$2" n rc
  if n="$(grep -Fc -- "$pat" "$log")"; then
    rc=0
  else
    rc=$?
  fi
  printf '%s\n' "$n"
  return "$rc"
}

# ---------------------------------------------------------------------------
# The skip-marker gate. A lane's log must contain zero occurrences of
# "NOT EXECUTED" (a require_root-gated granary-fuse test deferred) and zero
# of "running as uid 0" (a granary-client owner_uid==0 guard fired instead
# of the fixture it guards). Prints its own diagnostic and returns 1 --
# callers decide whether that aborts the whole script (production lanes,
# via `|| exit 1`) or is scored as a --self-test case.
# ---------------------------------------------------------------------------
check_markers() {
  # Deliberately does NOT toggle the global `set -e` state anywhere in this
  # function: it is called as a bare statement from check_markers_case
  # under the CALLER's own `set +e`, and re-enabling errexit in here before
  # `return 1` would trigger the shell to abort on the return itself,
  # before the caller ever reaches its own `rc=$?` line. Every command
  # below that might legitimately fail (count_marker included) is therefore
  # either tested by `if`/a plain status capture with NO intervening
  # `set -e`, matching this function's documented contract that it always
  # runs with errexit already off (both call sites guarantee this: cmd_test
  # calls it before `|| exit 1`, itself an errexit-exempt context per
  # POSIX/bash's rules for compound commands whose failure is tested; and
  # check_markers_case wraps it in an explicit `set +e`/`set -e` pair).
  local log="$1" lane="$2" n0 n1 n2 rc0 rc1 rc2
  # Independent of the GRANARY_SELFTEST_ROOT_LANE_POISON closed enum (see S2-no-summary
  # below): a lane whose log contains no nextest summary line AT ALL must
  # REFUSE, not score as "0 markers". A free-form podman option string
  # once made a container exit 0 having run nothing at all
  # (`--entrypoint /bin/true`); the ENUM closes that specific injection
  # off, but an empty/truncated log is a failure for other reasons too (a
  # crashed podman invocation, a killed process),
  # and "0 occurrences of NOT EXECUTED" is vacuously true of an EMPTY log --
  # this must never be indistinguishable from a genuinely clean pass.
  n0="$(count_marker "$log" 'tests run:')"
  rc0=$?
  if [ "$rc0" -gt 1 ]; then
    echo "MARKER-GATE($lane): refused -- could not count nextest summary lines in $log (count_marker/grep rc=$rc0); an unreadable or missing log must never be scored as if it were clean." >&2
    return 1
  fi
  if [ "$n0" -eq 0 ]; then
    echo "MARKER-GATE($lane): refused -- $log contains no nextest summary line ('tests run:') at all. A lane whose log has no summary must never be scored as '0 markers' clean -- something prevented nextest from completing (or from ever running)." >&2
    return 1
  fi
  n1="$(count_marker "$log" 'NOT EXECUTED')"
  rc1=$?
  n2="$(count_marker "$log" 'running as uid 0')"
  rc2=$?
  if [ "$rc1" -gt 1 ]; then
    echo "MARKER-GATE($lane): refused -- could not count 'NOT EXECUTED' occurrences in $log (count_marker/grep rc=$rc1); an unreadable or missing log must never be scored as if it were clean." >&2
    return 1
  fi
  if [ "$rc2" -gt 1 ]; then
    echo "MARKER-GATE($lane): refused -- could not count 'running as uid 0' occurrences in $log (count_marker/grep rc=$rc2); an unreadable or missing log must never be scored as if it were clean." >&2
    return 1
  fi
  if [ "$n1" -gt 0 ]; then
    echo "MARKER-GATE($lane): refused -- $n1 occurrence(s) of 'NOT EXECUTED' in $log (a root/uid-gated test deferred instead of executing):" >&2
    grep -Fn 'NOT EXECUTED' "$log" >&2
    return 1
  fi
  if [ "$n2" -gt 0 ]; then
    echo "MARKER-GATE($lane): refused -- $n2 occurrence(s) of 'running as uid 0' in $log (a uid==0 guard fired instead of the fixture it guards executing):" >&2
    grep -Fn 'running as uid 0' "$log" >&2
    return 1
  fi
  echo "MARKER-GATE($lane): OK -- 0 'NOT EXECUTED', 0 'running as uid 0' in $log"
  return 0
}

# Report gran mounts in a raw /proc/self/mountinfo snapshot, mountpoint first
# (tab-separated from the original row). Optional fields precede the "-".
# Match unit-check's findmnt SOURCE==gran cleanup predicate: for any fstype,
# mountinfo source must be gran and root must be /; other roots are displayed
# by findmnt as gran[/sub] and do not match that cleanup predicate.
# A pre-existing mount would otherwise surface only at unit-check's exit
# cleanup, after a full run. Mount's before/after leak diff already excludes
# these rows, so that lane only warns.
foreign_gran_mount_rows() {
  awk '{
    for (i=7; i<=NF; i++) {
      if ($i == "-") {
        if ($(i+2) == "gran" && $4 == "/")
          print $5 "\t" $0
        break
      }
    }
  }' "$1"
}

# Diagnose only: an active mount and an orphan look identical in this table.
preexisting_gran_mount_message() {
  local before="$1" rows mnt row fstype unmount remote_mnt command_mnt commands=""
  # Leave empty/missing snapshots to the existing capture and leak checks.
  [ -s "$before" ] || return 0
  rows="$(foreign_gran_mount_rows "$before")" || return 1
  [ -n "$rows" ] || return 0
  while IFS=$'\t' read -r mnt row; do
    fstype="$(printf '%s\n' "$row" | awk '{for(i=7;i<=NF;i++) if($i=="-"){print $(i+1); exit}}')" || return 1
    case "$fstype" in
      fuse | fuse.*) unmount='fusermount3 -u' ;;
      *) unmount='umount' ;;
    esac
    # Decode exactly three octal digits per mountinfo escape: %b otherwise
    # consumes a following digit too. Then quote for both host and remote shells.
    mnt="$(printf '%s' "$mnt" | sed 's/\\\([0-7]\{3\}\)/\\0\1/g')" || return 1
    printf -v mnt '%b' "$mnt"
    printf -v remote_mnt '%q' "$mnt"
    printf -v command_mnt '%q' "$remote_mnt"
    commands+=$'\n'"  podman machine ssh -- sudo $unmount $command_mnt"
  done <<<"$rows"
  printf '%s\n' "mount row(s) with SOURCE=gran already exist on the VM:
$rows
These rows existed before THIS run started, possibly left by an earlier run of this lane or by a hand-run gran mount. No mounts or processes have been touched.
SOURCE=gran is only a label; a non-FUSE row may be an unrelated filesystem. Check what it is and whether it is in active use before removing it.
Removal commands:$commands
Find the owning gran mount process with:
  podman machine ssh -- ps -eo pid,etimes,args | grep '[g]ran mount'"
}

refuse_foreign_gran_mounts() {
  local before="$1" units="${2:-}" units_rc="${3:-0}" runtime="${4:-absent}" runtime_rc="${5:-0}"
  local message mount_message runtime_message
  # Combine all pre-existing state in one refusal, with unit-stop advice first.
  message="$(preexisting_gran_units_message "$units" "$units_rc")"
  if ! mount_message="$(preexisting_gran_mount_message "$before")"; then
    mount_message='could not inspect the VM mount-table snapshot taken before THIS run started.'
  elif [ -n "$mount_message" ]; then
    mount_message+=$'\n'"These rows would fail this lane's exit cleanup."
  fi
  runtime_message="$(preexisting_gran_runtime_message "$runtime" "$runtime_rc")"
  if [ -n "$mount_message" ]; then
    [ -z "$message" ] || message+=$'\n'
    message+="$mount_message"
  fi
  if [ -n "$runtime_message" ]; then
    [ -z "$message" ] || message+=$'\n'
    message+="$runtime_message"
  fi
  [ -n "$message" ] || return 0
  die "unit: refused -- $message
This run refuses before starting the stack and the unit check."
}

warn_foreign_gran_mounts() {
  local message
  if ! message="$(preexisting_gran_mount_message "$1")"; then
    printf '%s\n' 'linux-container: mount: WARNING -- the pre-existing-mount check could not run because inspecting the snapshot failed; continuing.' >&2
    return 0
  fi
  [ -n "$message" ] || return 0
  printf 'linux-container: mount: WARNING -- %s\n' "$message
The before/after leak diff does not count these pre-existing rows; continuing." >&2
  return 0
}

# Pure diagnostics over captured query text/status. Any listed unit would
# fail exit cleanup, even with no mount row; never stop/reset it here.
preexisting_gran_units_message() {
  local units="$1" query_rc="$2" unit rest remote_unit command_unit commands=""
  if [ "$query_rc" -ne 0 ]; then
    printf '%s\n' "could not query gran-mount@* units on the VM (podman machine ssh rc=$query_rc); a failed query must never be scored as 'no units found'.
Captured query output:
$units"
    return 0
  fi
  [ -n "$units" ] || return 0
  while read -r unit rest; do
    [ -n "$unit" ] || continue
    printf -v remote_unit '%q' "$unit"
    printf -v command_unit '%q' "$remote_unit"
    commands+=$'\n'"  podman machine ssh -- sudo systemctl stop $command_unit; podman machine ssh -- sudo systemctl reset-failed $command_unit 2>/dev/null"
  done <<<"$units"
  printf '%s\n' "gran-mount@* unit(s) already listed on the VM:
$units
These units existed before THIS run started and would fail this lane's exit cleanup. No units have been touched.
After checking whether each unit is in active use, stop it first; stopping the unit also unmounts its mount. Then clear its failed state (a not-loaded unit is harmless):$commands"
}

preexisting_gran_runtime_message() {
  local state="$1" query_rc="$2"
  if [ "$query_rc" -ne 0 ] || { [ "$state" != present ] && [ "$state" != absent ]; }; then
    printf '%s\n' "could not check /run/systemd/system/gran-mount@.service on the VM (podman machine ssh rc=$query_rc).
Captured query output:
$state"
  elif [ "$state" = present ]; then
    printf '%s\n' '/run/systemd/system/gran-mount@.service already exists and this harness did not just create it. Refusing to overwrite a pre-existing runtime unit. No runtime unit has been touched.
After checking whether it is in active use, remove it and reload systemd with:
  podman machine ssh -- sudo rm /run/systemd/system/gran-mount@.service && podman machine ssh -- sudo systemctl daemon-reload'
  fi
}

# ---------------------------------------------------------------------------
# `mount_leak_check` compares bare-VM mount-table
# snapshots. Its file arguments let the
# self-test exercise the same implementation
# with synthetic snapshots, while cmd_mount
# supplies captures from the real run.
#
# Report every new mount-table row as a leak.
# Restricting the difference to FUSE rows
# would miss a leaked bind mount or another
# filesystem type. The diagnostic may label
# FUSE rows, but that label does not determine
# which rows count. The before/after
# comparison supplies the baseline for this
# harness run; the synthetic controls
# include non-FUSE rows so the check cannot
# silently narrow its scope to FUSE only.
# ---------------------------------------------------------------------------
mount_leak_check() {
  local before="$1" after="$2" new_rows_file row fstype rc
  # An empty `before` is not "no baseline rows", it is a FAILED capture: a
  # real mountinfo snapshot always has at least a root row. Running
  # `awk 'NR==FNR{seen[k]=1;next} !(k in seen)' <empty-before> <after>`
  # prints NOTHING no matter what `after` contains, because when `before`
  # has zero records, `after`'s own first record is ALSO the very first
  # record awk has read overall -- so NR==FNR holds for it too, and awk
  # populates `seen` from `after` instead of diffing against it. This must
  # be refused, never scored as "no new rows".
  if [ ! -s "$before" ]; then
    echo "MOUNT-LEAK(bare-vm): refused -- '$before' (the VM's mount-table snapshot taken BEFORE 'mount' ran) is empty or missing. A real snapshot always has at least one row; an empty 'before' makes the awk diff below silently treat 'after' as its own baseline, always reporting no leak regardless of what actually happened. This must be treated as a failed capture, never as evidence of no leak." >&2
    return 1
  fi
  # With zero records in 'after' there is nothing for the awk diff to
  # report as new, so a failed AFTER capture reads as "no leak" too.
  if [ ! -s "$after" ]; then
    echo "MOUNT-LEAK(bare-vm): refused -- '$after' (the VM's mount-table snapshot taken AFTER 'mount' ran) is empty or missing. A real snapshot always has at least one row; an empty 'after' makes the awk diff below silently report zero new rows regardless of what actually happened. This must be treated as a failed capture, never as evidence of no leak." >&2
    return 1
  fi
  new_rows_file="$(mktemp "${TMPDIR:-/tmp}/mount-leak-rows.XXXXXX")"
  set +e
  # THE VOLATILE TOKEN IS STRIPPED, not the whole field. `nr_inodes=` is
  # the only part of the super-options that churns for an UNCHANGED mount: `shmem_show_options` prints `,nr_inodes=N` only when a
  # tmpfs's frozen `max_inodes` differs from a default the kernel recomputes
  # live from `totalram_pages()`, so on a virtio-balloon guest the same
  # tmpfs row gains or loses that token when guest RAM moves.
  # DROPPING THE WHOLE SUPER-OPTIONS FIELD INSTEAD WOULD LOSE COVERAGE, even
  # though field 1, the mount ID, is unique among live
  # mounts. Mount
  # IDs are RECYCLED after unmount, and `before`/`after` are two different
  # instants. A baseline mount can be replaced by one reusing the ID
  # at the same mountpoint and differing only in super-options.
  # Stripping only `nr_inodes=` retains those other differences.
  awk '{ orig=$0; tmp=$NF; gsub(/(^|,)nr_inodes=[0-9]+/, "", tmp); $NF=tmp; k=$0; $0=orig } NR==FNR{seen[k]=1; next} !(k in seen)' "$before" "$after" >"$new_rows_file"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    rm -f "$new_rows_file"
    echo "MOUNT-LEAK(bare-vm): refused -- the before/after mount-table diff itself failed (awk rc=$rc, '$after' unreadable or missing); this must be treated as 'could not verify', never as 'no leak'." >&2
    return 1
  fi
  if [ ! -s "$new_rows_file" ]; then
    rm -f "$new_rows_file"
    echo "MOUNT-LEAK(bare-vm): OK -- no new row(s) in the VM's mount table"
    return 0
  fi
  echo "MOUNT-LEAK(bare-vm): refused -- new row(s) appeared in the VM's mount table after 'mount' (every new row counts, not only fstype fuse* ones -- a lazy-unmount fallback test can leave a non-fuse bind mount just as leaked; fuse rows are marked [FUSE] below for triage):" >&2
  while IFS= read -r row; do
    [ -n "$row" ] || continue
    fstype="$(printf '%s\n' "$row" | awk '{for(i=1;i<=NF;i++) if ($i=="-"){print $(i+1); exit}}')"
    case "$fstype" in
      fuse*) echo "  [FUSE]  $row" >&2 ;;
      *) echo "  [other] $row" >&2 ;;
    esac
  done <"$new_rows_file"
  rm -f "$new_rows_file"
  return 1
}

# ---------------------------------------------------------------------------
# unit_leak_check: the unit's own leak gate is TWO
# checks, not one -- mount_leak_check's existing before/after mountinfo
# diff, PLUS a check that no gran-mount@* unit is still LOADED on the VM
# (a unit can be 'failed' with no mount row at all, which mount_leak_check
# alone would score clean). Extracted into its own function so --self-test
# can drive it DIRECTLY with a planted loaded unit (a real, if throwaway,
# systemd-run transient named gran-mount@<x>.service -- it does not need to
# come from this repo's own template to match the 'gran-mount@*' glob),
# exactly as mount_leak_check itself is already driven directly by S12.
# vm_gran_mount_units runs over podman machine ssh, matching every other
# VM-side query in this file.
# ---------------------------------------------------------------------------
vm_gran_mount_units() {
  podman machine ssh -- "sudo systemctl list-units --all --no-legend --plain 'gran-mount@*'"
}

vm_gran_runtime_unit() {
  podman machine ssh -- "sudo sh -c 'if [ -e /run/systemd/system/gran-mount@.service ]; then echo present; else echo absent; fi'"
}

unit_leak_check() {
  local before="$1" after="$2" units_after units_query_rc mount_rc=0 units_rc=0
  # The mount-table half refuses missing or
  # empty captures and failed comparisons.
  # Propagate that result independently of
  # the unit-list query; either half failing
  # must prevent a clean leak verdict.
  mount_leak_check "$before" "$after" || mount_rc=1
  # `vm_gran_mount_units` runs `podman machine ssh -- systemctl
  # list-units ...`; its errors (an ssh blip, a sudo failure, a D-Bus
  # error) go to STDERR while stdout comes back EMPTY, and a bare
  # `set +e; x="$(cmd)"; set -e` with no rc check reads that identically to
  # a genuine "no units left" -- a failed query must never be scored
  # "clean". Capture and consult the rc explicitly.
  # `if cmd; then …; else rc=$?; fi` preserves the caller's errexit state.
  # --self-test calls these functions under the CALLER's `set +e`
  # (run_captured), so an unconditional `set -e` here turns the next
  # nonzero command into an `exit` that escapes the intended `$?` capture.
  if units_after="$(vm_gran_mount_units)"; then
    units_query_rc=0
  else
    units_query_rc=$?
  fi
  if [ "$units_query_rc" -ne 0 ]; then
    echo "UNIT-LEAK(bare-vm): refused -- could not query gran-mount@* units on the VM (podman machine ssh rc=$units_query_rc); a failed query must never be scored as 'no units found'." >&2
    units_rc=1
  elif [ -n "$units_after" ]; then
    echo "UNIT-LEAK(bare-vm): refused -- gran-mount@* unit(s) still listed on the VM after the check:" >&2
    printf '%s\n' "$units_after" >&2
    units_rc=1
  else
    echo "UNIT-LEAK(bare-vm): OK -- no gran-mount@* unit listed on the VM"
  fi
  [ "$mount_rc" -eq 0 ] && [ "$units_rc" -eq 0 ]
}

# ---------------------------------------------------------------------------
# clean_target: the shared implementation behind `clean` and its --self-test
# cases. Never `rm -rf`s the caller-named directory -- see the block
# comment above guard_forbidden_roots for why. Removes exactly
# the named artefacts `build`/`test`/`conform` write (the FUSE and daemon archives,
# the staged cargo-nextest binary, the stamp, the three named logs, the
# debug/ subtree, and cargo's own droppings). conform-bin/ and armed/ are
# removed recursively only after their own ownership markers are validated.
# It then
# removes the directory itself with a single NON-RECURSIVE `rmdir` -- which
# refuses (ENOTEMPTY) if anything else is still there, by construction. That
# guarantee is TOP-LEVEL ONLY -- see the block comment above
# guard_forbidden_roots, and the marker check below debug/'s own recursive
# removal, for why.
# ---------------------------------------------------------------------------
clean_target() {
  local dir="$1" canon
  # clean_target does NOT route through guards_target_dir (it never needed G2),
  # so the transportability check has to be repeated here or `clean` is the one
  # destructive command that skips it. A trailing newline otherwise resolves to
  # the no-newline SIBLING and this function then recursively removes that other
  # tree's debug/, doc/ and tmp/.
  assert_transportable_path "the target directory" "$dir"
  canon="$(canon_path "$dir")"
  # Belt and braces: guards_target_dir already runs this same check
  # on every OTHER command, but clean_target does not route through
  # guards_target_dir (it never required G2), so it is repeated here
  # explicitly rather than relying on a shared call path staying wired up.
  guard_forbidden_roots "$canon"
  guard_g1_not_repo_target "$canon"
  # The stamp is an early ownership check before
  # named files are removed. The final `rmdir`
  # also refuses a nonempty directory, but that
  # does not justify beginning deletion in
  # a directory this harness never claimed.
  if [ -L "$canon/$STAMP_NAME" ]; then
    die "CLEAN: refused -- '$canon/$STAMP_NAME' is a SYMLINK, not a regular file. A symlinked stamp is not proof the harness created this directory: it can point at any existing file, so trusting one would authorise deleting a directory that was never ours."
  fi
  if [ ! -f "$canon/$STAMP_NAME" ]; then
    die "CLEAN: refused -- '$canon' does not contain the stamp file '$STAMP_NAME'. The harness may only ever act on a directory it claimed."
  fi
  # The cleanup list includes `.rustdoc_fingerprint.json`,
  # `doc/` and `tmp/` as well as build outputs.
  # A build, test and documentation run can
  # leave those entries at the target root.
  # If the toolchain adds entries, compare
  # the list with what remains after cleanup
  # before expanding the removal set.
  # Checked BEFORE any removal below (the `rm -f` two lines down would
  # otherwise erase CACHEDIR.TAG, the very marker this reads): a cargo
  # target dir carries CACHEDIR.TAG at its root and/or debug/.fingerprint/,
  # neither of which a user creates by hand. Absent both, refuse rather than
  # recursively remove a directory merely because it is named `debug`.
  # -f/-d plus an explicit -L refusal, never -e: `-e` follows symlinks and
  # accepts any object type, so a symlinked CACHEDIR.TAG or a plain FILE named
  # `debug/.fingerprint` satisfied a check documented as "cargo's own directory".
  if [ -L "$canon/debug" ]; then
    die "CLEAN: refused -- '$canon/debug' is a SYMLINK; recursively removing through it would delete whatever it points at."
  fi
  if [ -d "$canon/debug" ] \
     && { [ -L "$canon/CACHEDIR.TAG" ] || [ ! -f "$canon/CACHEDIR.TAG" ]; } \
     && { [ -L "$canon/debug/.fingerprint" ] || [ ! -d "$canon/debug/.fingerprint" ]; }; then
    die "CLEAN: refused -- '$canon/debug' exists but carries neither cargo's CACHEDIR.TAG (at '$canon') nor a debug/.fingerprint/ directory, so it cannot be confirmed as cargo's own output. Refusing to recursively remove it rather than risk deleting a directory that merely happens to be named 'debug'."
  fi
  # Validate release/ with the same cargo markers as debug/ above.
  # `cargo build --release` can reuse this $CARGO_TARGET_DIR and create
  # a release/ profile directory here.
  # Clean must handle that cargo output too, so the remaining profile
  # directory does not defeat the final rmdir.
  if [ -L "$canon/release" ]; then
    die "CLEAN: refused -- '$canon/release' is a SYMLINK; recursively removing through it would delete whatever it points at."
  fi
  if [ -d "$canon/release" ] \
     && { [ -L "$canon/CACHEDIR.TAG" ] || [ ! -f "$canon/CACHEDIR.TAG" ]; } \
     && { [ -L "$canon/release/.fingerprint" ] || [ ! -d "$canon/release/.fingerprint" ]; }; then
    die "CLEAN: refused -- '$canon/release' exists but carries neither cargo's CACHEDIR.TAG (at '$canon') nor a release/.fingerprint/ directory, so it cannot be confirmed as cargo's own output. Refusing to recursively remove it rather than risk deleting a directory that merely happens to be named 'release'."
  fi
  # logs/ holds exactly the files this harness writes, so it is removed by
  # NAME and then `rmdir`-ed: anything else a reader put beside a log survives
  # and stops the removal, the same by-construction rule as the target dir
  # itself. debug/, release/, doc/ and tmp/ are cargo's and are removed
  # recursively -- that asymmetry is deliberate and is why the message below
  # says what is and is not protected.
  if [ -L "$canon/logs" ]; then
    die "CLEAN: refused -- '$canon/logs' is a SYMLINK. Removing the named log files through it would delete them from wherever it points, outside this target dir, before the protective rmdir could stop anything."
  fi
  for _lg in "$canon/logs/test-root.log" "$canon/logs/test-nonroot.log" "$canon/logs/conform.log" "$canon/logs/demo.log" "$canon/logs/demo-self-check.log" "$canon/logs/unit.log" "$canon/logs/unit-stack.log"; do
    if [ -L "$_lg" ]; then
      die "CLEAN: refused -- '$_lg' is a SYMLINK; removing it by name would follow it out of this target dir."
    fi
  done
  rm -f -- "$canon/logs/test-root.log" "$canon/logs/test-nonroot.log" "$canon/logs/conform.log" "$canon/logs/demo.log" "$canon/logs/demo-self-check.log" "$canon/logs/unit.log" "$canon/logs/unit-stack.log"
  rmdir -- "$canon/logs" 2>/dev/null || true
  # cmd_unit's own stack contract file and ready marker (unit-stack.env,
  # unit-stack.ready) are plain single-shot files this harness writes at
  # the top of every run -- its tiny source tree and the stack
  # state it drives live under a container-LOCAL /tmp instead (never
  # under this target dir; see cmd_unit's own comment), so there is
  # nothing recursive to clean up for either of those.
  if [ -L "$canon/unit-stack.env" ] || [ -L "$canon/unit-stack.ready" ]; then
    die "CLEAN: refused -- '$canon/unit-stack.env' or '$canon/unit-stack.ready' is a SYMLINK."
  fi
  rm -f -- "$canon/unit-stack.env" "$canon/unit-stack.ready"
  # These are recursive cargo/staging trees, but neither is trusted merely
  # because it has the expected top-level name. armed/ must carry cargo's own
  # target marker; conform-bin/ must have the regular, named sidecar written
  # when the staging directory is freshly recreated. The sidecar stays OUTSIDE
  # conform-bin/ so that directory contains exactly the four staged binaries.
  # A dangling symlink is visible to -L even though -e would miss it, so every
  # object-type check names both.
  if [ -L "$canon/armed" ]; then
    die "CLEAN: refused -- '$canon/armed' is a SYMLINK; recursively removing through it would delete whatever it points at."
  fi
  if [ -e "$canon/armed" ]; then
    [ -d "$canon/armed" ] \
      || die "CLEAN: refused -- '$canon/armed' exists but is not a directory."
    if { [ -L "$canon/armed/CACHEDIR.TAG" ] || [ ! -f "$canon/armed/CACHEDIR.TAG" ]; } \
       && { [ -L "$canon/armed/debug/.fingerprint" ] || [ ! -d "$canon/armed/debug/.fingerprint" ]; }; then
      die "CLEAN: refused -- '$canon/armed' carries neither cargo's regular CACHEDIR.TAG nor a real debug/.fingerprint/ directory, so it cannot be confirmed as the conform lane's separate cargo target."
    fi
    rm -rf -- "$canon/armed"
  fi
  if [ -L "$canon/conform-bin" ]; then
    die "CLEAN: refused -- '$canon/conform-bin' is a SYMLINK; recursively removing through it would delete whatever it points at."
  fi
  if [ -L "$canon/$STAMP_NAME.conform-bin" ]; then
    die "CLEAN: refused -- '$canon/$STAMP_NAME.conform-bin' is a SYMLINK, not conform-bin/'s regular ownership sidecar."
  fi
  if [ -e "$canon/conform-bin" ]; then
    [ -d "$canon/conform-bin" ] \
      || die "CLEAN: refused -- '$canon/conform-bin' exists but is not a directory."
    if [ ! -f "$canon/$STAMP_NAME.conform-bin" ]; then
      die "CLEAN: refused -- '$canon/conform-bin' does not have the harness's regular '$STAMP_NAME.conform-bin' ownership sidecar, so it cannot be confirmed as conform's owned staging directory."
    fi
    rm -rf -- "$canon/conform-bin"
  fi
  if [ -e "$canon/$STAMP_NAME.conform-bin" ]; then
    [ -f "$canon/$STAMP_NAME.conform-bin" ] \
      || die "CLEAN: refused -- '$canon/$STAMP_NAME.conform-bin' exists but is not a regular ownership sidecar."
    rm -f -- "$canon/$STAMP_NAME.conform-bin"
  fi
  rm -f -- "$canon/fuse-tests.tar.zst" "$canon/daemon-tests.tar.zst" "$canon/cargo-nextest" "$canon/$STAMP_NAME" "$canon/.rustc_info.json" "$canon/.rustdoc_fingerprint.json" "$canon/CACHEDIR.TAG"
  rm -rf -- "$canon/debug" "$canon/release" "$canon/doc" "$canon/tmp"
  if ! rmdir -- "$canon" 2>/dev/null; then
    die "CLEAN: STOPPED (not refused -- the harness's own artefacts above were already removed) -- '$canon' is not empty after removing the harness's own artefacts (fuse-tests.tar.zst, daemon-tests.tar.zst, cargo-nextest, the stamp file, the named files in logs/, marked conform-bin/, marked armed/, debug/, release/, doc/, tmp/, .rustc_info.json, .rustdoc_fingerprint.json, CACHEDIR.TAG); a directory that has gained other content fails 'rmdir' by construction. This only ever catches TOP-LEVEL foreign entries -- content placed INSIDE the marker-validated recursive subtrees is not individually protected. Remove the extra content yourself if you are sure, or point GRANARY_LINUX_TARGET_DIR elsewhere."
  fi
  echo "linux-container: clean -- removed $canon"
}

# ===========================================================================
# Container-side scripts. Each is captured from a QUOTED heredoc (no host-
# side expansion at all -- the container's own bash parses it for the first
# time when `bash -c "$SCRIPT"` runs), and reads its inputs from environment
# variables the caller sets with `-e` on `podman run`. This is what lets the
# same literal script serve both a real production lane and a --self-test
# case built on the same podman invocation with different flags.
# ===========================================================================

BUILD_LANE_SCRIPT="$(cat <<'INNER'
set -uo pipefail
UID_NOW="$(id -u)"
if [ "$UID_NOW" -eq 0 ]; then
  echo "BUILD-PREFLIGHT: refused -- id -u is 0 inside the container; build runs container-nonroot so the produced binary and archive are never silently built as root." >&2
  exit 9
fi
RUSTC_V="$(rustc -V)"
RUSTC_VER="$(printf '%s\n' "$RUSTC_V" | awk 'NR==1{print $2; exit}')"
if [ "$RUSTC_VER" != "$LANE_WANT_CHANNEL" ]; then
  echo "BUILD-PREFLIGHT: refused -- container rustc is \"$RUSTC_V\" (parsed version \"$RUSTC_VER\"), which does not EXACTLY match channel \"$LANE_WANT_CHANNEL\" from rust-toolchain.toml." >&2
  exit 9
fi
NEXTEST_V="$(cargo nextest --version)"
# cargo-nextest --version prints MULTIPLE lines (release/commit-hash/commit-date/
# host after the first) -- only the FIRST line's second field is the version.
NEXTEST_VER="$(printf '%s\n' "$NEXTEST_V" | awk 'NR==1{print $2; exit}')"
if [ "$NEXTEST_VER" != "$LANE_WANT_NEXTEST" ]; then
  echo "BUILD-PREFLIGHT: refused -- container cargo-nextest is \"$NEXTEST_V\" (parsed version \"$NEXTEST_VER\"), which does not EXACTLY match the CI-pinned $LANE_WANT_NEXTEST." >&2
  exit 9
fi
echo "BUILD-PREFLIGHT: OK (uid=$UID_NOW, rustc=$RUSTC_VER, nextest=$NEXTEST_VER) -- --self-test asserts this line is present in a real build's log; its absence means this preflight was silently deleted. (Deliberately UNDEFAULTED: under this INNER script's own \`set -uo pipefail\`, deleting the preflight ALSO deletes these variables' only assignments, so a partial deletion that left this line behind would crash loudly here rather than silently print a placeholder.)"
# These three run before the first `set -e` below, so they are checked
# EXPLICITLY rather than left to errexit: a failed `cd` in particular would
# otherwise leave cargo running against whatever directory the container
# started in, which fails later and confusingly instead of here and clearly.
mkdir -p "$HOME" || { echo "LANE: refused -- could not create HOME '$HOME'." >&2; exit 9; }
chmod 700 "$HOME" || { echo "LANE: refused -- could not chmod 700 HOME '$HOME'." >&2; exit 9; }
cd "$LANE_REPO" || { echo "LANE: refused -- could not cd to the repo '$LANE_REPO' inside the container; the bind mount is missing or unreadable." >&2; exit 9; }
set +e
cargo build -p granary-cli --bin gran
BUILD_RC=$?
set -e
if [ "$BUILD_RC" -ne 0 ]; then
  exit "$BUILD_RC"
fi
set +e
cargo nextest archive -p granary-fuse --archive-file "$CARGO_TARGET_DIR/fuse-tests.tar.zst"
ARCHIVE_RC=$?
set -e
if [ "$ARCHIVE_RC" -ne 0 ]; then
  exit "$ARCHIVE_RC"
fi
set +e
cargo nextest archive -p granary-cli --bin gran --features overlay-fault-tests --archive-file "$CARGO_TARGET_DIR/daemon-tests.tar.zst"
DAEMON_ARCHIVE_RC=$?
set -e
if [ "$DAEMON_ARCHIVE_RC" -ne 0 ]; then
  exit "$DAEMON_ARCHIVE_RC"
fi
set +e
if [ -L "$CARGO_TARGET_DIR/cargo-nextest" ]; then
  echo "BUILD: refused -- '$CARGO_TARGET_DIR/cargo-nextest' is a symlink; copying through it would overwrite its target and then mark that executable." >&2
  exit 9
fi
cp "$(command -v cargo-nextest)" "$CARGO_TARGET_DIR/cargo-nextest"
CP_RC=$?
set -e
if [ "$CP_RC" -ne 0 ]; then
  exit "$CP_RC"
fi
set +e
chmod +x "$CARGO_TARGET_DIR/cargo-nextest"
CHMOD_RC=$?
set -e
if [ "$CHMOD_RC" -ne 0 ]; then
  exit "$CHMOD_RC"
fi
# Refuse rather than write THROUGH a symlink: `: >` follows one and would
# truncate its target. The host-side claim check refuses a symlinked stamp
# too; this is that same rule at the only site that WRITES it.
if [ -L "$CARGO_TARGET_DIR/$LANE_STAMP_NAME" ]; then
  echo "BUILD: refused -- the stamp path is a symlink; refusing to truncate its target." >&2
  exit 9
fi
: > "$CARGO_TARGET_DIR/$LANE_STAMP_NAME"
exit 0
INNER
)"

CONFORM_BUILD_LANE_SCRIPT="$(cat <<'INNER'
set -uo pipefail
UID_NOW="$(id -u)"
if [ "$UID_NOW" -eq 0 ]; then
  echo "CONFORM-BUILD-PREFLIGHT: refused -- id -u is 0 inside the container; conform compilation and staging must run container-nonroot." >&2
  exit 9
fi
mkdir -p "$HOME" || { echo "LANE: refused -- could not create HOME '$HOME'." >&2; exit 9; }
chmod 700 "$HOME" || { echo "LANE: refused -- could not chmod 700 HOME '$HOME'." >&2; exit 9; }
cd "$LANE_REPO" || { echo "LANE: refused -- could not cd to the repo '$LANE_REPO' inside the container; the bind mount is missing or unreadable." >&2; exit 9; }

# The armed target persists between runs. Refuse a pre-existing tree unless
# cargo itself marked it; otherwise the conform lane would write into a
# caller-owned directory and clean would later mistake that name for ours.
ARMED_TARGET="$CARGO_TARGET_DIR/armed"
if [ -L "$ARMED_TARGET" ]; then
  echo "CONFORM-BUILD: refused -- '$ARMED_TARGET' is a symlink." >&2
  exit 9
fi
if [ -e "$ARMED_TARGET" ]; then
  if [ ! -d "$ARMED_TARGET" ]; then
    echo "CONFORM-BUILD: refused -- '$ARMED_TARGET' exists but is not a directory." >&2
    exit 9
  fi
  if { [ -L "$ARMED_TARGET/CACHEDIR.TAG" ] || [ ! -f "$ARMED_TARGET/CACHEDIR.TAG" ]; } \
     && { [ -L "$ARMED_TARGET/debug/.fingerprint" ] || [ ! -d "$ARMED_TARGET/debug/.fingerprint" ]; }; then
    echo "CONFORM-BUILD: refused -- '$ARMED_TARGET' is not marked as cargo's own target directory." >&2
    exit 9
  fi
fi

set -e
cargo build -p granary-cli --bin gran
cargo build -p granary-server --bin granary-server
cargo build -p granary-conformance --bin granconf
# This MUST be a separate target dir: a feature-on build would overwrite the
# feature-OFF debug/gran above. Feature unification is not the reason.
cargo build -p granary-cli --bin gran --features conformance-breakage \
  --target-dir "$ARMED_TARGET"

# A successful build does not make stale staging into current evidence. Empty
# the fixed directory only after all four builds succeeded, accepting an old
# directory only when its own regular harness sidecar proves we created it.
STAGE="$CARGO_TARGET_DIR/conform-bin"
STAGE_MARKER="$CARGO_TARGET_DIR/$LANE_STAMP_NAME.conform-bin"
if [ -L "$STAGE" ]; then
  echo "CONFORM-BUILD: refused -- '$STAGE' is a symlink." >&2
  exit 9
fi
if [ -L "$STAGE_MARKER" ]; then
  echo "CONFORM-BUILD: refused -- '$STAGE_MARKER' is a symlink, not a regular ownership sidecar." >&2
  exit 9
fi
if [ -e "$STAGE" ]; then
  if [ ! -d "$STAGE" ]; then
    echo "CONFORM-BUILD: refused -- '$STAGE' exists but is not a directory." >&2
    exit 9
  fi
  if [ ! -f "$STAGE_MARKER" ]; then
    echo "CONFORM-BUILD: refused -- '$STAGE' lacks its regular '$STAGE_MARKER' ownership sidecar." >&2
    exit 9
  fi
  rm -rf -- "$STAGE"
elif [ -e "$STAGE_MARKER" ] && [ ! -f "$STAGE_MARKER" ]; then
  echo "CONFORM-BUILD: refused -- '$STAGE_MARKER' exists but is not a regular ownership sidecar." >&2
  exit 9
fi
mkdir "$STAGE"
: > "$STAGE_MARKER"
cp -- "$CARGO_TARGET_DIR/debug/gran" "$STAGE/gran"
cp -- "$ARMED_TARGET/debug/gran" "$STAGE/gran-armed"
cp -- "$CARGO_TARGET_DIR/debug/granary-server" "$STAGE/granary-server"
cp -- "$CARGO_TARGET_DIR/debug/granconf" "$STAGE/granconf"
for BIN in gran gran-armed granary-server granconf; do
  [ -x "$STAGE/$BIN" ] \
    || { echo "CONFORM-BUILD: refused -- staged '$STAGE/$BIN' is not executable." >&2; exit 9; }
done
echo "CONFORM-BUILD: OK -- freshly staged gran, gran-armed, granary-server, granconf"
exit 0
INNER
)"

ROOT_LANE_SCRIPT="$(cat <<'INNER'
set -uo pipefail
UID_NOW="$(id -u)"
if [ "$UID_NOW" -ne 0 ]; then
  echo "ROOT-PREFLIGHT: refused -- id -u is $UID_NOW inside the container, not 0. The container-root lane needs uid 0 so require_root() cannot defer any root-gated granary-fuse test." >&2
  exit 9
fi
if [ ! -c /dev/fuse ]; then
  echo "ROOT-PREFLIGHT: refused -- /dev/fuse is not present as a character device inside the container. Pass --device /dev/fuse." >&2
  exit 9
fi
CAPEFF="$(awk '/^CapEff:/{print $2}' /proc/self/status)"
CAPVAL=$((16#$CAPEFF))
if [ $(( (CAPVAL >> 21) & 1 )) -eq 0 ]; then
  echo "ROOT-PREFLIGHT: refused -- CapEff ($CAPEFF) does not have CAP_SYS_ADMIN (bit 21) set. Pass --cap-add SYS_ADMIN." >&2
  exit 9
fi
# The connection-abort witnesses test only that the directory exists, and an
# unbound container still has sysfs's empty one; check the mount's type.
FUSECTL_TYPE="$(awk '$5 == "/sys/fs/fuse/connections" { for (i = 7; i <= NF; i++) if ($i == "-") { t = $(i + 1); break } } END { print t }' /proc/self/mountinfo)"
if [ "$FUSECTL_TYPE" != fusectl ]; then
  echo "ROOT-PREFLIGHT: refused -- /sys/fs/fuse/connections is not a fusectl mount inside the container (type '${FUSECTL_TYPE:-none}'), so the connection-abort witnesses would defer. Bind the VM's: -v /sys/fs/fuse/connections:/sys/fs/fuse/connections." >&2
  exit 9
fi
# These three run before the first `set -e` below, so they are checked
# EXPLICITLY rather than left to errexit: a failed `cd` in particular would
# otherwise leave cargo running against whatever directory the container
# started in, which fails later and confusingly instead of here and clearly.
mkdir -p "$HOME" || { echo "LANE: refused -- could not create HOME '$HOME'." >&2; exit 9; }
chmod 700 "$HOME" || { echo "LANE: refused -- could not chmod 700 HOME '$HOME'." >&2; exit 9; }
cd "$LANE_REPO" || { echo "LANE: refused -- could not cd to the repo '$LANE_REPO' inside the container; the bind mount is missing or unreadable." >&2; exit 9; }
# Snapshot BEFORE running the suite, diff AFTER -- the same before/after
# shape as the host-side mount_leak_check, replacing a
# single-point "is any fuse* row still present" check that missed
# non-fuse leaks entirely: mnt_detach_lazily_unmounts_a_busy_bind_mount (in
# the very suite this lane runs) leaves an ext4 BIND mount behind on a
# lazy-detach path, which a fuse*-only filter cannot see. Every new row
# counts as a leak now, not only fstype fuse* ones; the filter below only
# decides which rows get the [FUSE] label for triage.
MOUNT_BEFORE="$(mktemp)"
if ! cat /proc/self/mountinfo >"$MOUNT_BEFORE"; then
  echo "MOUNT-LEAK: refused -- reading /proc/self/mountinfo FAILED when captured at the start of the container-root lane. A partial capture is nonempty, so the emptiness check below cannot see it: treat a failed read as 'could not verify', never as 'no leak'." >&2
  exit 11
fi
if [ ! -s "$MOUNT_BEFORE" ]; then
  echo "MOUNT-LEAK: refused -- /proc/self/mountinfo was empty when captured at the start of the container-root lane; this must be treated as 'could not verify', never as 'no leak'." >&2
  exit 11
fi
set +e
cargo nextest run -p granary-fuse --success-output=final --no-fail-fast
NEXTEST_RC=$?
set -e
MOUNT_AFTER="$(mktemp)"
if ! cat /proc/self/mountinfo >"$MOUNT_AFTER"; then
  echo "MOUNT-LEAK: refused -- reading /proc/self/mountinfo FAILED when captured at the end of the container-root lane. A partial capture is nonempty, so the emptiness check below cannot see it: treat a failed read as 'could not verify', never as 'no leak'." >&2
  exit 11
fi
if [ ! -s "$MOUNT_AFTER" ]; then
  echo "MOUNT-LEAK: refused -- /proc/self/mountinfo was empty when captured at the end of the container-root lane; this must be treated as 'could not verify', never as 'no leak' (a nonempty BEFORE followed by an empty AFTER makes the awk diff below report zero new rows regardless of what actually happened)." >&2
  exit 11
fi
MOUNT_DIFF="$(mktemp)"
set +e
# Keyed on every field with the nr_inodes=<n> token stripped from the last
# -- see mount_leak_check's own comment: that token is volatile for an
# UNCHANGED tmpfs under ballooning, and an exact whole-line diff reports it
# as a phantom leak.
awk '{ orig=$0; tmp=$NF; gsub(/(^|,)nr_inodes=[0-9]+/, "", tmp); $NF=tmp; k=$0; $0=orig } NR==FNR{seen[k]=1; next} !(k in seen)' "$MOUNT_BEFORE" "$MOUNT_AFTER" >"$MOUNT_DIFF"
AWK_RC=$?
set -e
if [ "$AWK_RC" -ne 0 ]; then
  echo "MOUNT-LEAK: refused -- the in-container mountinfo before/after diff itself failed (awk rc=$AWK_RC); this must be treated as 'could not verify', never as 'no leak'." >&2
  exit 11
fi
if [ -s "$MOUNT_DIFF" ]; then
  echo "MOUNT-LEAK: new row(s) appeared in this container's /proc/self/mountinfo during the container-root lane (every new row counts, not only fstype fuse* ones -- a lazy-unmount fallback test can leave a non-fuse bind mount just as leaked; fuse rows are marked [FUSE] below):" >&2
  while IFS= read -r ROW; do
    [ -n "$ROW" ] || continue
    FSTYPE="$(printf '%s\n' "$ROW" | awk '{for(i=1;i<=NF;i++) if ($i=="-"){print $(i+1); exit}}')"
    case "$FSTYPE" in
      fuse*) echo "  [FUSE]  $ROW" >&2 ;;
      *) echo "  [other] $ROW" >&2 ;;
    esac
  done <"$MOUNT_DIFF"
  exit 10
fi
exit "$NEXTEST_RC"
INNER
)"

CONFORM_LANE_SCRIPT="$(cat <<'INNER'
set -uo pipefail
cd "$LANE_REPO" || { echo "LANE: refused -- could not cd to the repo '$LANE_REPO' inside the container; the bind mount is missing or unreadable." >&2; exit 9; }
exec scripts/conformance.sh
INNER
)"

DEMO_LANE_SCRIPT="$(cat <<'INNER'
set -uo pipefail
cd "$LANE_REPO" || { echo "LANE: refused -- could not cd to the repo '$LANE_REPO' inside the container; the bind mount is missing or unreadable." >&2; exit 9; }
exec scripts/demo.sh
INNER
)"

DEMO_SELFCHECK_LANE_SCRIPT="$(cat <<'INNER'
set -uo pipefail
cd "$LANE_REPO" || { echo "LANE: refused -- could not cd to the repo '$LANE_REPO' inside the container; the bind mount is missing or unreadable." >&2; exit 9; }
exec scripts/demo-self-check.sh
INNER
)"

# The stack, on the container's OWN network
# (--network host, set by the caller's podman invocation) so the bare VM
# can reach it. Runs container-nonroot (no mount happens in this
# container; that happens on the bare VM, outside). Stays alive after
# stack.sh start returns (`exec sleep infinity`) -- the moment this
# script's own PID 1 exits, podman tears down the container's pid
# namespace and kills every process in it, MinIO and granary-server
# included, so the stack has to be kept alive deliberately rather than by
# the script simply finishing.
UNIT_STACK_LANE_SCRIPT="$(cat <<'INNER'
set -uo pipefail
UID_NOW="$(id -u)"
if [ "$UID_NOW" -eq 0 ]; then
  echo "UNIT-STACK-PREFLIGHT: refused -- id -u is 0 inside the container; the stack lane runs container-nonroot (the mount itself happens on the bare VM, not in here)." >&2
  exit 9
fi
mkdir -p "$HOME" || { echo "LANE: refused -- could not create HOME '$HOME'." >&2; exit 9; }
chmod 700 "$HOME" || { echo "LANE: refused -- could not chmod 700 HOME '$HOME'." >&2; exit 9; }
cd "$LANE_REPO" || { echo "LANE: refused -- could not cd to the repo '$LANE_REPO' inside the container; the bind mount is missing or unreadable." >&2; exit 9; }
# The source tree is written HERE, inside this container, immediately
# before the harvest that walks it -- never on the host side first.
# Measured: writing it on the host (across the virtiofs boundary this
# container ALSO crosses to reach the same path) raced gran publish's own
# torn-read guard, which refused with "changed during harvest
# (identity/type/size/mtime moved between stat and read)" even ~1s after
# the host-side write completed -- a virtiofs metadata-consistency quirk,
# not an actual concurrent writer. Writing and harvesting from the SAME
# filesystem view removes the cross-boundary race entirely.
mkdir -p "$LANE_UNIT_SRC/bin" || { echo "LANE: refused -- could not create '$LANE_UNIT_SRC/bin'." >&2; exit 9; }
# this script runs under `set -uo pipefail`, deliberately never
# `set -e` (the stack.sh start step below needs its own $? captured
# explicitly, which blanket errexit would short-circuit before the RC
# check ever ran) -- but that means every command in between needs its
# OWN explicit guard, matching the three above, or a failure here falls
# through silently into stack.sh start with a missing/partial source
# tree.
printf '%s' "$LANE_UNIT_SENTINEL" >"$LANE_UNIT_SRC/sentinel.txt" \
  || { echo "LANE: refused -- could not write '$LANE_UNIT_SRC/sentinel.txt'." >&2; exit 9; }
{
  printf '#!/bin/sh\n'
  printf 'printf '\''UNIT-EXEC %%s\\n'\'' "$0"\n'
} >"$LANE_UNIT_SRC/bin/hello.sh" \
  || { echo "LANE: refused -- could not write '$LANE_UNIT_SRC/bin/hello.sh'." >&2; exit 9; }
chmod 0755 "$LANE_UNIT_SRC/bin/hello.sh" \
  || { echo "LANE: refused -- could not chmod '$LANE_UNIT_SRC/bin/hello.sh'." >&2; exit 9; }
scripts/stack.sh start --source-dir "$LANE_UNIT_SRC" --volume "$LANE_UNIT_VOLUME" --state-dir "$LANE_UNIT_STATE" \
  >"$LANE_UNIT_ENV_OUT" 2>"$LANE_UNIT_LOG_OUT"
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "UNIT-STACK: refused -- stack.sh start failed (rc=$RC); its log:" >&2
  cat "$LANE_UNIT_LOG_OUT" >&2
  exit "$RC"
fi
: > "$LANE_UNIT_READY"
echo "UNIT-STACK: ready" >&2
exec sleep infinity
INNER
)"

NONROOT_LANE_SCRIPT="$(cat <<'INNER'
set -uo pipefail
UID_NOW="$(id -u)"
if [ "$UID_NOW" -eq 0 ]; then
  echo "NONROOT-PREFLIGHT: refused -- id -u is 0 inside the container. The container-nonroot lane needs uid != 0 so granary-client's owner_uid==0 guards in mount.rs cannot fire." >&2
  exit 9
fi
# These three run before the first `set -e` below, so they are checked
# EXPLICITLY rather than left to errexit: a failed `cd` in particular would
# otherwise leave cargo running against whatever directory the container
# started in, which fails later and confusingly instead of here and clearly.
mkdir -p "$HOME" || { echo "LANE: refused -- could not create HOME '$HOME'." >&2; exit 9; }
chmod 700 "$HOME" || { echo "LANE: refused -- could not chmod 700 HOME '$HOME'." >&2; exit 9; }
cd "$LANE_REPO" || { echo "LANE: refused -- could not cd to the repo '$LANE_REPO' inside the container; the bind mount is missing or unreadable." >&2; exit 9; }
set +e
# The gran binary's daemon_linux_ rows need root and a real mount: mount runs
# them under sudo from daemon-tests.tar.zst (--bin gran, test(daemon_linux_)),
# as CI's fuse job does. Here they would only defer, so this lane takes the
# exact complement of that selection. A root-gated row anywhere else still
# runs here, and still trips the marker gate if it defers.
cargo nextest run -p granary-client -p granary-cli --success-output=final --no-fail-fast \
  -E 'not (binary_id(granary-cli::bin/gran) & test(daemon_linux_))'
NEXTEST_RC=$?
set -e
if [ "$NEXTEST_RC" -ne 0 ]; then
  exit "$NEXTEST_RC"
fi
echo "NONROOT-CLIPPY: running CARGO_BUILD_WARNINGS=deny cargo clippy -p granary-client -p granary-cli --all-targets (features=none)"
set +e
CARGO_BUILD_WARNINGS=deny cargo clippy -p granary-client -p granary-cli --all-targets
CLIENT_OFF_CLIPPY_RC=$?
set -e
if [ "$CLIENT_OFF_CLIPPY_RC" -ne 0 ]; then
  exit "$CLIENT_OFF_CLIPPY_RC"
fi
echo "NONROOT-CLIPPY: OK (rc=$CLIENT_OFF_CLIPPY_RC, package=granary-client+granary-cli, features=none)"

# This feature list is the ONLY Linux clippy invocation that reaches the
# arming site in the cfg(target_os = "linux") run_fuse_daemon body — which
# lives in granary-cli (src/attach.rs), along with the
# `conformance-breakage` feature itself. granary-client does not DECLARE
# that feature (its src/ uses the name zero times), so
# this invocation naming granary-client would fail outright rather than
# silently cover less. Keep the feature list in one
# array consumed by both cargo and the sentinel: deleting its contents either
# makes cargo's argument set feature-OFF or makes the indexed sentinel expansion
# fail under `set -u`, and S13 requires the interpolated feature name exactly.
CLIENT_ON_FEATURE_ARGS=(--features conformance-breakage)
echo "NONROOT-CLIPPY: running CARGO_BUILD_WARNINGS=deny cargo clippy -p granary-cli --all-targets ${CLIENT_ON_FEATURE_ARGS[*]}"
set +e
CARGO_BUILD_WARNINGS=deny cargo clippy -p granary-cli --all-targets "${CLIENT_ON_FEATURE_ARGS[@]}"
CLIENT_ON_CLIPPY_RC=$?
set -e
if [ "$CLIENT_ON_CLIPPY_RC" -ne 0 ]; then
  exit "$CLIENT_ON_CLIPPY_RC"
fi
echo "NONROOT-CLIPPY: OK (rc=$CLIENT_ON_CLIPPY_RC, package=granary-cli, features=${CLIENT_ON_FEATURE_ARGS[1]})"

FUSE_ON_FEATURE_ARGS=(--features conformance-breakage)
echo "NONROOT-CLIPPY: running CARGO_BUILD_WARNINGS=deny cargo clippy -p granary-fuse --all-targets ${FUSE_ON_FEATURE_ARGS[*]}"
set +e
CARGO_BUILD_WARNINGS=deny cargo clippy -p granary-fuse --all-targets "${FUSE_ON_FEATURE_ARGS[@]}"
FUSE_ON_CLIPPY_RC=$?
set -e
if [ "$FUSE_ON_CLIPPY_RC" -ne 0 ]; then
  exit "$FUSE_ON_CLIPPY_RC"
fi
echo "NONROOT-CLIPPY: OK (rc=$FUSE_ON_CLIPPY_RC, package=granary-fuse, features=${FUSE_ON_FEATURE_ARGS[1]})"
echo "NONROOT-DOC: running RUSTDOCFLAGS=\"-D warnings\" cargo doc -p granary-client -p granary-cli --no-deps"
set +e
RUSTDOCFLAGS="-D warnings" cargo doc -p granary-client -p granary-cli --no-deps
DOC_RC=$?
set -e
if [ "$DOC_RC" -ne 0 ]; then
  exit "$DOC_RC"
fi
echo "NONROOT-DOC: OK (rc=$DOC_RC) -- this is the discharge for the register row on granary-client's Linux-gated rustdoc coverage; --self-test's S13 fails if this line is ever absent."
exit 0
INNER
)"

# A generic probe used only by --self-test, for scenarios that do not
# correspond to any production lane (e.g. running granary-fuse as
# non-root, which production never does -- S6/S7 exist to prove what WOULD
# happen if it did). Reads LANE_PKG / LANE_FILTER / LANE_FINAL_FLAG from the
# environment; LANE_FILTER empty means "no -E filter, run everything".
# LANE_FINAL_FLAG is a SCRIPT-SET literal (run_selftest_probe's own $4, always
# "" or "--success-output=final"), never externally controlled, so
# the unquoted `${LANE_FINAL_FLAG:-}` splice could only select
# one of those two script-defined values.
# Quoted via an array below regardless.
SELFTEST_PROBE_SCRIPT="$(cat <<'INNER'
set -uo pipefail
# These three run before the first `set -e` below, so they are checked
# EXPLICITLY rather than left to errexit: a failed `cd` in particular would
# otherwise leave cargo running against whatever directory the container
# started in, which fails later and confusingly instead of here and clearly.
mkdir -p "$HOME" || { echo "LANE: refused -- could not create HOME '$HOME'." >&2; exit 9; }
chmod 700 "$HOME" || { echo "LANE: refused -- could not chmod 700 HOME '$HOME'." >&2; exit 9; }
cd "$LANE_REPO" || { echo "LANE: refused -- could not cd to the repo '$LANE_REPO' inside the container; the bind mount is missing or unreadable." >&2; exit 9; }
id -u
FINAL_FLAG_ARGS=()
if [ -n "${LANE_FINAL_FLAG:-}" ]; then
  FINAL_FLAG_ARGS=("$LANE_FINAL_FLAG")
fi
set +e
if [ -n "${LANE_FILTER:-}" ]; then
  cargo nextest run -p "$LANE_PKG" "${FINAL_FLAG_ARGS[@]}" --no-fail-fast -E "$LANE_FILTER"
else
  cargo nextest run -p "$LANE_PKG" "${FINAL_FLAG_ARGS[@]}" --no-fail-fast
fi
rc=$?
set -e
exit "$rc"
INNER
)"

# ---------------------------------------------------------------------------
# podman run wrappers. None redirect their own output -- callers capture
# via `> log 2>&1; rc=$?` (production) or via run_captured (--self-test),
# per the shell-discipline rule against piping a gate's result.
# ---------------------------------------------------------------------------

# $2/$3: the expected rustc channel / nextest version, defaulting to the
# real ones read at startup (WANT_CHANNEL/WANT_NEXTEST). Overridable ONLY so
# --self-test can prove BUILD-PREFLIGHT's version checks actually refuse a
# mismatch; production callers (cmd_build, cmd_self_test's own prerequisite
# build) always take the defaults.
run_build_container() {
  local target="$1" want_channel="${2:-$WANT_CHANNEL}" want_nextest="${3:-$WANT_NEXTEST}"
  podman run --rm --entrypoint "" \
    --user "$(id -u):$(id -g)" \
    --memory "$GRANARY_LINUX_MEMORY" \
    -v "$REPO_ROOT:$REPO_ROOT" \
    -v "$target:$target" \
    -e CARGO_TARGET_DIR="$target" \
    -e HOME="$CONTAINER_HOME" \
    -e LANE_REPO="$REPO_ROOT" \
    -e LANE_WANT_CHANNEL="$want_channel" \
    -e LANE_WANT_NEXTEST="$want_nextest" \
    -e LANE_STAMP_NAME="$STAMP_NAME" \
    -w "$REPO_ROOT" \
    "$GRANARY_LINUX_IMAGE" bash -c "$BUILD_LANE_SCRIPT"
}

run_conform_build_container() {
  local target="$1"
  podman run --rm --entrypoint "" \
    --user "$(id -u):$(id -g)" \
    --memory "$GRANARY_LINUX_MEMORY" \
    -v "$REPO_ROOT:$REPO_ROOT" \
    -v "$target:$target" \
    -e CARGO_TARGET_DIR="$target" \
    -e HOME="$CONTAINER_HOME" \
    -e LANE_REPO="$REPO_ROOT" \
    -e LANE_STAMP_NAME="$STAMP_NAME" \
    -w "$REPO_ROOT" \
    "$GRANARY_LINUX_IMAGE" bash -c "$CONFORM_BUILD_LANE_SCRIPT"
}

# $1: GRANARY_SELFTEST_ROOT_LANE_POISON value (none|no-cap|no-device|no-fusectl|nonroot) -- mapped to
# podman grant flags by root_lane_grants, which refuses anything outside
# that closed set by name before a single flag is built from it. Every
# caller passes a literal from that set (production always "none"; the
# others are --self-test-only probes for S4/S5/S11/S19), so the word
# splitting below is never fed anything other than this file's own fixed,
# space-only, glob-free flag strings.
# Identical to run_build_container except that it does NOT pass --user, so the
# container runs as its own root. Used ONLY by --self-test's S-BUILD-UID case,
# to drive the build lane's `id -u` refusal into firing. Production never calls
# it: the build lane must always run non-root.
run_build_container_as_root() {
  local target="$1"
  podman run --rm --entrypoint "" \
    --memory "$GRANARY_LINUX_MEMORY" \
    -v "$REPO_ROOT:$REPO_ROOT" \
    -v "$target:$target" \
    -e CARGO_TARGET_DIR="$target" \
    -e HOME="$CONTAINER_HOME" \
    -e LANE_REPO="$REPO_ROOT" \
    -e LANE_WANT_CHANNEL="$WANT_CHANNEL" \
    -e LANE_WANT_NEXTEST="$WANT_NEXTEST" \
    -e LANE_STAMP_NAME="$STAMP_NAME" \
    -w "$REPO_ROOT" \
    "$GRANARY_LINUX_IMAGE" bash -c "$BUILD_LANE_SCRIPT"
}

run_root_container() {
  local poison="$1" target="$2" grants rc
  # root_lane_grants calls `die` (which `exit`s) on an invalid poison value
  # -- but a command substitution always forks its OWN subshell, so that
  # `exit` only ever terminates THAT subshell, never propagates through
  # this assignment via errexit. The die message is already on stderr by
  # now; check the substitution's rc explicitly and stop here rather than
  # fall through to `podman run` with an empty (unprivileged) grants
  # string.
  #
  # Uses the SAME `if cmd; then ... else rc=$?; fi` idiom count_marker
  # documents, deliberately NOT `set +e; cmd; rc=$?; set -e`: this
  # function's every caller invokes it under its OWN `set +e` (to capture
  # `podman run`'s own exit code, e.g. cmd_test's ROOT-PREFLIGHT refusal,
  # a normal nonzero outcome it wants back via `$?`, not an errexit
  # escape) -- measured, this is not a hypothetical: `set -e` here
  # unconditionally turns errexit back ON globally, and the very next
  # command run is `podman run`, whose expected-nonzero exit then fired
  # errexit immediately, terminating the whole process via `exit 9` before
  # ever returning control to the caller's `rc=$?` line at all (S11 caught
  # this: cmd_test's own die() and its "container-root lane failed"
  # message never printed, because cmd_test's body never got control back).
  if grants="$(GRANARY_SELFTEST_ROOT_LANE_POISON="$poison" root_lane_grants root)"; then
    rc=0
  else
    rc=$?
  fi
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi
  # shellcheck disable=SC2086
  podman run --rm --entrypoint "" $grants \
    --memory "$GRANARY_LINUX_MEMORY" \
    -v "$REPO_ROOT:$REPO_ROOT" \
    -v "$target:$target" \
    -e CARGO_TARGET_DIR="$target" \
    -e HOME="$CONTAINER_HOME" \
    -e LANE_REPO="$REPO_ROOT" \
    -w "$REPO_ROOT" \
    "$GRANARY_LINUX_IMAGE" bash -c "$ROOT_LANE_SCRIPT"
}

run_conform_container() {
  local target="$1" grants rc
  # Production conform is never poisonable: the fixed literal requests both
  # grants, and conformance.sh independently verifies uid, /dev/fuse,
  # CAP_SYS_ADMIN and glibc inside the container before doing work. Preserve
  # run_root_container's if/else capture idiom; turning errexit on inside this
  # wrapper would terminate cmd_conform before its own rc capture could run.
  if grants="$(GRANARY_SELFTEST_ROOT_LANE_POISON="none" root_lane_grants)"; then
    rc=0
  else
    rc=$?
  fi
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi
  # shellcheck disable=SC2086
  podman run --rm --entrypoint "" $grants \
    --memory "$GRANARY_LINUX_MEMORY" \
    -v "$REPO_ROOT:$REPO_ROOT" \
    -v "$target/conform-bin:$REPO_ROOT/target/debug" \
    -e HOME="$CONTAINER_HOME" \
    -e LANE_REPO="$REPO_ROOT" \
    -w "$REPO_ROOT" \
    "$GRANARY_LINUX_IMAGE" bash -c "$CONFORM_LANE_SCRIPT"
}

# Reuses conform's staged binaries (gran, granary-server both land at
# target/debug via the same bind mount trick) -- the demo build lane IS
# conform's build lane.
run_demo_container() {
  local target="$1" grants rc
  if grants="$(GRANARY_SELFTEST_ROOT_LANE_POISON="none" root_lane_grants)"; then
    rc=0
  else
    rc=$?
  fi
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi
  # shellcheck disable=SC2086
  podman run --rm --entrypoint "" $grants \
    --memory "$GRANARY_LINUX_MEMORY" \
    -v "$REPO_ROOT:$REPO_ROOT" \
    -v "$target/conform-bin:$REPO_ROOT/target/debug" \
    -e HOME="$CONTAINER_HOME" \
    -e LANE_REPO="$REPO_ROOT" \
    -w "$REPO_ROOT" \
    "$GRANARY_LINUX_IMAGE" bash -c "$DEMO_LANE_SCRIPT"
}

# A SEPARATE container-root lane from run_demo_container: the demo's
# own negatives are proved against the shipped script inside a fresh
# container, never inside the same process that ran the positive.
run_demo_selfcheck_container() {
  local target="$1" grants rc
  if grants="$(GRANARY_SELFTEST_ROOT_LANE_POISON="none" root_lane_grants)"; then
    rc=0
  else
    rc=$?
  fi
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi
  # shellcheck disable=SC2086
  podman run --rm --entrypoint "" $grants \
    --memory "$GRANARY_LINUX_MEMORY" \
    -v "$REPO_ROOT:$REPO_ROOT" \
    -v "$target/conform-bin:$REPO_ROOT/target/debug" \
    -e HOME="$CONTAINER_HOME" \
    -e LANE_REPO="$REPO_ROOT" \
    -w "$REPO_ROOT" \
    "$GRANARY_LINUX_IMAGE" bash -c "$DEMO_SELFCHECK_LANE_SCRIPT"
}

# The stack container, detached (-d) so it stays
# alive after stack.sh start returns, and --network host so the bare VM
# (podman machine ssh) can reach whatever port granary-server/MinIO bind to
# at 127.0.0.1 inside it -- without this the container gets its own,
# separate network and the VM's bare shell could never reach the endpoint
# at all. --rm so `podman stop` alone is enough teardown (auto-removes).
# Prints the container id on stdout; the caller polls for the ready marker
# file (host-visible under $target, virtiofs-shared) rather than parsing
# any container output.
run_unit_stack_container() {
  local target="$1" src="$2" state="$3" volume="$4" env_out="$5" log_out="$6" ready="$7" sentinel="$8"
  podman run --rm -d --network host --entrypoint "" \
    --user "$(id -u):$(id -g)" \
    --memory "$GRANARY_LINUX_MEMORY" \
    -v "$REPO_ROOT:$REPO_ROOT" \
    -v "$target:$target" \
    -v "$target/conform-bin:$REPO_ROOT/target/debug" \
    -e HOME="$CONTAINER_HOME" \
    -e LANE_REPO="$REPO_ROOT" \
    -e LANE_UNIT_SRC="$src" \
    -e LANE_UNIT_STATE="$state" \
    -e LANE_UNIT_VOLUME="$volume" \
    -e LANE_UNIT_ENV_OUT="$env_out" \
    -e LANE_UNIT_LOG_OUT="$log_out" \
    -e LANE_UNIT_READY="$ready" \
    -e LANE_UNIT_SENTINEL="$sentinel" \
    -w "$REPO_ROOT" \
    "$GRANARY_LINUX_IMAGE" bash -c "$UNIT_STACK_LANE_SCRIPT"
}

run_nonroot_container() {
  local target="$1"
  podman run --rm --entrypoint "" \
    --user "$(id -u):$(id -g)" \
    --memory "$GRANARY_LINUX_MEMORY" \
    -v "$REPO_ROOT:$REPO_ROOT" \
    -v "$target:$target" \
    -e CARGO_TARGET_DIR="$target" \
    -e HOME="$CONTAINER_HOME" \
    -e LANE_REPO="$REPO_ROOT" \
    -w "$REPO_ROOT" \
    "$GRANARY_LINUX_IMAGE" bash -c "$NONROOT_LANE_SCRIPT"
}

# $1: "root" or "nonroot"; $2: package; $3: nextest filterset (may be
# empty); $4: "--success-output=final" or empty; $5: target dir.
run_selftest_probe() {
  local uid_mode="$1" pkg="$2" filter="$3" final_flag="$4" target="$5"
  local user_flag=()
  if [ "$uid_mode" = "nonroot" ]; then
    user_flag=(--user "$(id -u):$(id -g)")
  fi
  podman run --rm --entrypoint "" "${user_flag[@]}" \
    --memory "$GRANARY_LINUX_MEMORY" \
    -v "$REPO_ROOT:$REPO_ROOT" \
    -v "$target:$target" \
    -e CARGO_TARGET_DIR="$target" \
    -e HOME="$CONTAINER_HOME" \
    -e LANE_REPO="$REPO_ROOT" \
    -e LANE_PKG="$pkg" \
    -e LANE_FILTER="$filter" \
    -e LANE_FINAL_FLAG="$final_flag" \
    -w "$REPO_ROOT" \
    "$GRANARY_LINUX_IMAGE" bash -c "$SELFTEST_PROBE_SCRIPT"
}

# ---------------------------------------------------------------------------
# Host-path shell injection into the remote command string.
# `podman machine ssh -- "T='$target' ... bash -s" <<heredoc` was safe in
# the HEREDOC BODY (a quoted here-doc the remote bash parses fresh, so
# awk's $-fields etc. reach it untouched) but NOT in the ENV-ASSIGNMENT
# PREFIX: that line is built by simple single-quote wrapping on the HOST
# side, which a value containing its OWN single quote breaks out of. A
# target containing `; echo usage:\ gran; #` was observed to make
# cmd_mount's ELF gate see its expected banner and PASS WITHOUT gran
# ever executing. `assert_safe_for_remote_shell` refuses (an allowlist, not
# a denylist of "dangerous" characters -- a denylist is always incomplete)
# BEFORE any remote command string referencing the value is ever built, at
# every function that builds one.
# ---------------------------------------------------------------------------
assert_safe_for_remote_shell() {
  local label="$1" val="$2"
  case "$val" in
    *[!A-Za-z0-9_./-]*)
      die "REMOTE-SHELL-SAFETY: refused -- $label ('$val') contains a character outside [A-Za-z0-9_./-]. This value is interpolated into a remote 'podman machine ssh' command string; refusing here (an allowlist, not an escaping trick) rather than risk a quote, semicolon or other metacharacter reaching the remote shell unescaped."
      ;;
  esac
}

# ---------------------------------------------------------------------------
# The bare-VM side (mount, and --self-test's S8). Values known on the host
# (paths) are substituted into the REMOTE COMMAND STRING (which the host
# shell expands normally) ONLY after `assert_safe_for_remote_shell` has
# passed; the SCRIPT BODY piped over stdin is a quoted heredoc, so awk's
# $-fields and every other special character inside it reach the remote
# bash untouched, with $REPO/$T/$EX read back from the environment the
# remote command string set.
# ---------------------------------------------------------------------------

vm_mountinfo() {
  podman machine ssh -- 'cat /proc/self/mountinfo'
}

vm_run_gran_version() {
  local target="$1"
  assert_safe_for_remote_shell "target dir" "$target"
  podman machine ssh -- "T='$target' bash -s" <<'EOF'
set -uo pipefail
"$T/debug/gran" --version
EOF
}

# The bare-VM lane runs the full archived
# suite. Selecting only an unmount-module
# name pattern could omit a root-gated
# test added elsewhere, even though
# this is the lane with host mount-namespace
# visibility. The archive invocation
# below has no test-name filter.
# Coverage is selected by the venue
# and its preconditions rather than
# a list of test names, matching
# the container-root lane's scope.
# The separate CLI archive selects the real daemon rows and refuses an
# empty selection; its mount leaks and skip markers share the same gates.
vm_run_archive() {
  local target="$1" extract="$2"
  assert_safe_for_remote_shell "target dir" "$target"
  assert_safe_for_remote_shell "extract dir" "$extract"
  assert_safe_for_remote_shell "repo root" "$REPO_ROOT"
  podman machine ssh -- "T='$target' EX='$extract' REPO='$REPO_ROOT' bash -s" <<'EOF'
set -uo pipefail
cd "$REPO"
sudo "$T/cargo-nextest" nextest run --archive-file "$T/fuse-tests.tar.zst" --extract-to "$EX" --success-output=final --no-fail-fast
FUSE_RC=$?
mkdir "$EX/daemon" || { echo "linux-container: could not create the daemon archive's extract dir '$EX/daemon'" >&2; exit 9; }
sudo "$T/cargo-nextest" nextest run --archive-file "$T/daemon-tests.tar.zst" --extract-to "$EX/daemon" --profile ci --success-output=final --no-fail-fast --no-tests=fail -E 'test(daemon_linux_)'
DAEMON_RC=$?
if [ "$FUSE_RC" -ne 0 ]; then exit "$FUSE_RC"; fi
exit "$DAEMON_RC"
EOF
}

vm_run_direct_binary() {
  local extract="$1"
  assert_safe_for_remote_shell "extract dir" "$extract"
  podman machine ssh -- "EX='$extract' bash -s" <<'EOF'
set -uo pipefail
BIN="$(find "$EX" -type f -perm -u+x -name 'granary_fuse-*' | head -1)"
if [ -z "$BIN" ]; then
  echo "S8: could not locate the extracted granary_fuse test binary under $EX" >&2
  exit 9
fi
sudo "$BIN" --test-threads=1 --nocapture unmount::tests::
EOF
}

# `vm_mktemp_dir` creates a fresh extraction
# directory on the VM. Concurrent runs
# need separate directories so cleanup
# cannot remove another run's extracted
# files. The argument is a host-side
# literal used as the template prefix.
vm_mktemp_dir() {
  local prefix="$1"
  podman machine ssh -- "mktemp -d /tmp/${prefix}.XXXXXX"
}

vm_remove_extract_dir() {
  local extract="$1"
  assert_safe_for_remote_shell "extract dir" "$extract"
  podman machine ssh -- "sudo rm -rf '$extract'"
}

# vm_run_unit_check: runs scripts/unit-check.sh (a checked-in file,
# virtiofs-visible on the VM at the SAME absolute path as on this host) on
# the bare VM under sudo. The endpoint/pin/root-key/volume never cross this
# boundary as values -- only PATHS do (env_file, gran_bin), which satisfy
# assert_safe_for_remote_shell's [A-Za-z0-9_./-] allowlist; a stack endpoint
# URL ('https://127.0.0.1:PORT') does not (':' is outside that set), so the
# check script itself parses the endpoint back out of env_file rather than
# ever taking it as a remote-shell argument. sentinel is generated by this
# script (see cmd_unit) from the same safe charset.
vm_run_unit_check() {
  local repo="$1" env_file="$2" gran_bin="$3" sentinel="$4"
  assert_safe_for_remote_shell "repo root" "$repo"
  assert_safe_for_remote_shell "env file" "$env_file"
  assert_safe_for_remote_shell "gran binary" "$gran_bin"
  assert_safe_for_remote_shell "sentinel" "$sentinel"
  podman machine ssh -- "REPO='$repo' ENVF='$env_file' GRANBIN='$gran_bin' SENT='$sentinel' bash -s" <<'EOF'
set -uo pipefail
cd "$REPO"
sudo "$REPO/scripts/unit-check.sh" "$ENVF" "$GRANBIN" "$SENT"
EOF
}

# vm_curl_stack_endpoint: the precondition -- the stack endpoint must
# be reachable from the VM's OWN bare shell BEFORE anything is installed
# there. Reads GRAN_ENDPOINT back out of env_file itself (a safe PATH)
# rather than ever passing the URL (which contains ':', outside the
# remote-shell allowlist) across the boundary.
vm_curl_stack_endpoint() {
  local env_file="$1"
  assert_safe_for_remote_shell "env file" "$env_file"
  podman machine ssh -- "ENVF='$env_file' bash -s" <<'EOF'
set -uo pipefail
E="$(sed -n 's/^GRAN_ENDPOINT=//p' "$ENVF" | head -1)"
if [ -z "$E" ]; then
  echo "vm_curl_stack_endpoint: no GRAN_ENDPOINT line in $ENVF" >&2
  exit 9
fi
curl -sk --max-time 5 -o /dev/null -w '%{http_code}\n' "$E"
EOF
}

# ===========================================================================
# Subcommands
# ===========================================================================

cmd_build() {
  local target log rc f
  target="$(guards_target_dir)"
  guard_g3_machine_running
  ensure_image
  claim_target_dir "$target"
  log="$(mktemp "${TMPDIR:-/tmp}/linux-container-build.XXXXXX")"
  echo "linux-container: build -- image=$GRANARY_LINUX_IMAGE target=$target"
  set +e
  run_build_container "$target" >"$log" 2>&1
  rc=$?
  set -e
  cat "$log"
  if [ "$rc" -ne 0 ]; then
    rm -f "$log"
    die "build failed (rc=$rc); see output above."
  fi
  # A container exit status alone is not proof BUILD_LANE_SCRIPT ever ran:
  # a GRANARY_LINUX_IMAGE naming an image whose own ENTRYPOINT
  # ignores its arguments and exits 0 makes `podman run` report success
  # having never invoked the build. --self-test's S-BUILD-PREFLIGHT checks
  # this same sentinel only against ITS OWN build call -- never this,
  # the production path. Verify it, and the promised artefacts, here too.
  if ! grep -qF 'BUILD-PREFLIGHT: OK' "$log"; then
    rm -f "$log"
    die "build: refused -- the container exited 0 but printed no BUILD-PREFLIGHT: OK sentinel in its output. An image that ignores its arguments and exits 0 without ever running the build script looks identical by exit status alone; check GRANARY_LINUX_IMAGE names the harness's own image."
  fi
  rm -f "$log"
  for f in "$target/fuse-tests.tar.zst" "$target/daemon-tests.tar.zst" "$target/cargo-nextest" "$target/$STAMP_NAME"; do
    [ -e "$f" ] || die "build: refused -- the container exited 0 and printed the BUILD-PREFLIGHT sentinel, but the promised artefact '$f' is missing. The build did not actually complete."
  done
  [ -x "$target/cargo-nextest" ] || die "build: refused -- '$target/cargo-nextest' exists but is not executable; the build did not actually complete."
  echo "linux-container: build OK -- $target/fuse-tests.tar.zst, $target/daemon-tests.tar.zst, $target/cargo-nextest, $target/$STAMP_NAME written."
}

cmd_conform() {
  local target build_log conform_log rc f sentinel
  local -a required_sentinels=(
    'PREFLIGHT: PASS'
    'STATIC-CONTROLS: PASS'
    'CONTRACT: PASS'
    'ABSOLUTE-PREFLIGHT: PASS'
    'EXPECT-REFUSAL-LEDGER: PASS'
    'ABSOLUTE: PASS'
    'ROUND-LEDGER: PASS'
    'CONFORMANCE: PASS'
    'ROUND truncate-read content PASS'
    'ROUND omit-entry presence PASS'
    'ROUND exec-everywhere exec PASS'
    'ROUND follow-symlink kind PASS'
    'ROUND misreport-size size PASS'
    'ROUND mangle-symlink-target target PASS'
    'ROUND dirent-type-lie dtype PASS'
    # The group sentinels above prove the oracle REACHED each stage. They do
    # NOT prove every control inside a stage ran: deleting one static control
    # outright still leaves 'STATIC-CONTROLS: PASS' printed, which was
    # measured -- a probe removed the whole two-class leg and the suite stayed
    # green. Each individual control therefore names its own verdict line here,
    # deliberately brittle: a reworded control has to be re-listed, and that is
    # the price of a deleted control being visible.
    'VERIFY: name-byte-0xff FAIL: no name contains byte 0xff'
    'gran mount: unknown flag --breakage'
    'CONTRACT: REFUSED line-count'
    'CONTRACT: REFUSED name-order'
    'CONTRACT: REFUSED assignment-shape'
    'ID-MAP-REDS: PASS'
    # Require each positive control's own witness. A control
    # whose successful execution prints nothing cannot
    # be distinguished here from a deleted call merely
    # by checking that the other sentinels are present.
    'VENUE-TRIPWIRE: PASS'
    'VERIFY-SOURCE: PASS'
    'EMPTY-DUMP: PASS'
    'CONFORM: PASS --expect content'
    'CONTRACT: REFUSED value-charset'
    'CONFORM: FAIL --expect presence: zero rows of class presence (expected at least one)'
    'CONFORM: FAIL --expect kind: zero rows of class kind (expected at least one)'
    'CONFORM: FAIL --expect size: zero rows of class size (expected at least one)'
    'CONFORM: FAIL --expect exec: zero rows of class exec (expected at least one)'
    'CONFORM: FAIL --expect content: zero rows of class content (expected at least one)'
    'CONFORM: FAIL --expect target: zero rows of class target (expected at least one)'
    'CONFORM: FAIL --expect dtype: zero rows of class dtype (expected at least one)'
    'CONFORM: FAIL --expect content: a row of class size diverged too — --expect content requires ONLY content divergences'
    'CONFORM: FAIL --expect presence: zero rows compared EQUAL — a dead or empty mount must not pass this way'
    'ABSOLUTE: FAIL uid'
    'ABSOLUTE: FAIL gid'
    'ABSOLUTE: FAIL dir-mode'
    'ABSOLUTE: FAIL file-mode'
    'ABSOLUTE: FAIL symlink-mode'
    'ABSOLUTE: FAIL timestamps'
    'ABSOLUTE: FAIL row-count'
    'ABSOLUTE: REFUSED exec-path-cardinality'
  )

  target="$(guards_target_dir)"
  guard_g3_machine_running
  ensure_image
  claim_target_dir "$target"

  echo "linux-container: conform -- lane container-nonroot (build and fresh staging)"
  build_log="$(mktemp "${TMPDIR:-/tmp}/linux-container-conform-build.XXXXXX")"
  set +e
  run_conform_build_container "$target" >"$build_log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    cat "$build_log" >&2
    rm -f "$build_log"
    die "conform build lane failed (rc=$rc); see output above."
  fi
  if ! grep -qxF 'CONFORM-BUILD: OK -- freshly staged gran, gran-armed, granary-server, granconf' "$build_log"; then
    cat "$build_log" >&2
    rm -f "$build_log"
    die "conform: refused -- the build container exited 0 without its completion sentinel. Persistent staged files are not proof that this run built and copied them."
  fi
  for f in gran gran-armed granary-server granconf; do
    if [ ! -x "$target/conform-bin/$f" ]; then
      rm -f "$build_log"
      die "conform: refused -- the build lane printed its completion sentinel but '$target/conform-bin/$f' is missing or not executable."
    fi
  done
  if [ -L "$target/$STAMP_NAME.conform-bin" ] \
     || [ ! -f "$target/$STAMP_NAME.conform-bin" ]; then
    rm -f "$build_log"
    die "conform: refused -- the freshly staged directory lacks its regular '$STAMP_NAME.conform-bin' ownership sidecar."
  fi
  rm -f "$build_log"
  echo "linux-container: conform -- fresh staging OK"

  if [ -L "$target/logs" ]; then
    die "conform: refused -- '$target/logs' is a SYMLINK. Shell redirection follows one, so conform.log would truncate a file wherever it points."
  fi
  mkdir -p "$target/logs"
  conform_log="$target/logs/conform.log"
  if [ -L "$conform_log" ]; then
    die "conform: refused -- '$conform_log' is a SYMLINK; redirecting into it would truncate its target rather than the log."
  fi

  echo "linux-container: conform -- lane container-root (scripts/conformance.sh)"
  set +e
  run_conform_container "$target" >"$conform_log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    cat "$conform_log" >&2
    die "conform lane failed (rc=$rc); see above ($conform_log)."
  fi

  # Exit 0 alone is not proof that the oracle ran. Require every fixed verdict
  # the landed, executed oracle emits; the one row-count-bearing baseline is
  # deliberately prefix-matched because its N is generated by the corpus.
  for sentinel in "${required_sentinels[@]}"; do
    if ! grep -qxF "$sentinel" "$conform_log"; then
      die "conform: refused -- the container exited 0 but '$conform_log' lacks the required oracle sentinel: $sentinel"
    fi
  done
  # The guard is a NAMED function beside check_demo_log_witnesses and
  # check_demo_selfcheck_log_witnesses, not an inline `if`, so --self-test's
  # S16-baseline case can drive THIS branch rather than re-derive the pattern.
  # A control that re-derived it would prove nothing about the code that runs.
  check_conform_baseline_verdict "$conform_log" || die "$(check_conform_baseline_verdict_msg "$conform_log")"
  echo "CONFORM-GATE: OK -- every enumerated oracle sentinel is present in $conform_log"
  echo "linux-container: conform OK"
}

# ---------------------------------------------------------------------------
# Keep the demo and self-check witness sets in functions callable directly,
# as well as from cmd_demo. The --self-test S18-witness case must drive
# the SAME demo witness-check function against a COPY of a real demo.log
# with one required witness deleted.
# This perturbation must use the production codepath's output, never a
# synthetic log built from scratch or a second expensive container run
# merely to prove that the check function refuses by name.
# ---------------------------------------------------------------------------
# check_conform_baseline_verdict <log> -- 0 if the log carries the baseline
# verdict as a WHOLE LINE, 1 otherwise. Each of the three things it refuses was
# executed against the real logs/conform.log rather than argued:
#
#   * a hyphen-prefixed verdict -> refused.
#   A substring search for `CONFORM: identical, `
#   would accept it, even though the
#   prefix makes it a different
#   line from the required verdict;
#   * conformance.sh's OWN `die` text, which embeds this verdict inside
#     `...: expected exactly one verdict line: CONFORM: identical, N rows` and
#     is printed EXACTLY WHEN THE VERDICT IS MISSING -> refused. A merely
#     boundary-anchored form ACCEPTS that line, which
#     is a fail-open: the guard is satisfied by the
#     message announcing the failure it exists to
#     catch. The verdict must occupy the whole line;
#     matching a verdict embedded in refusal text
#     cannot establish that the comparison passed.
#   * the real verdict line, at column 1 of logs/conform.log -> accepted, and
#     it is the only line that matches.
#
# The prefix control changes the surrounding text
# while retaining the verdict substring. This
# distinguishes a whole-line predicate from a
# substring search; the embedded-diagnostic control
# makes the same distinction with a refusal message.
check_conform_baseline_verdict() {
  grep -qE '^CONFORM: identical, [0-9]+ rows$' "$1"
}

# The refusal text, kept beside the predicate so the two cannot drift.
check_conform_baseline_verdict_msg() {
  echo "conform: refused -- the container exited 0 but '$1' carries no whole line reading exactly 'CONFORM: identical, <N> rows'. Neither a hyphen-prefixed spelling nor this verdict quoted inside another message satisfies it, and both exclusions are deliberate."
}

check_demo_log_witnesses() {
  local log="$1" sentinel
  local -a required_demo_sentinels=(
    'DEMO-PREFLIGHT: PASS'
    'DEMO-VENUE-TRIPWIRE: PASS'
    'DEMO-CONTRACT: PASS'
    'DEMO-MOUNTED: gran fuse'
    'DEMO-OPTIONS: PASS'
    'DEMO grep: PASS'
    'DEMO exec: PASS'
    'DEMO-UNMOUNTED: PASS'
    'DEMO-STACK-STOPPED: PASS'
    'MOUNT-OK'
  )
  for sentinel in "${required_demo_sentinels[@]}"; do
    if ! grep -qxF "$sentinel" "$log"; then
      echo "demo: refused -- '$log' lacks the required witness: $sentinel" >&2
      return 1
    fi
  done
  # du's numbers are generated, so this one is a SHAPE match rather than a
  # whole-line match -- but ANCHORED and pinned to the exact shape, never a
  # bare unanchored substring: an unanchored 'DEMO du: PASS ' is
  # satisfied by a line like 'ERROR: DEMO du: PASS skipped', which is
  # not a pass at all.
  if ! grep -qE '^DEMO du: PASS [0-9]+ bytes in [0-9]+ files$' "$log"; then
    echo "demo: refused -- '$log' lacks a line matching the required shape: ^DEMO du: PASS <digits> bytes in <digits> files\$" >&2
    return 1
  fi
  echo "demo: witnesses OK -- every required demo sentinel present in $log"
}

check_demo_selfcheck_log_witnesses() {
  local log="$1" sentinel
  local -a required_selfcheck_sentinels=(
    'DEMO-SELF-CHECK: N1 PASS'
    'DEMO-SELF-CHECK: N2 PASS'
    'DEMO-SELF-CHECK: N3 PASS'
    'DEMO-SELF-CHECK: PASS'
  )
  for sentinel in "${required_selfcheck_sentinels[@]}"; do
    if ! grep -qxF "$sentinel" "$log"; then
      echo "demo: refused -- '$log' lacks the required self-check witness: $sentinel" >&2
      return 1
    fi
  done
  echo "demo: self-check witnesses OK -- every case sentinel present in $log"
}

cmd_demo() {
  local target build_log demo_log selfcheck_log rc f

  target="$(guards_target_dir)"
  guard_g3_machine_running
  ensure_image
  claim_target_dir "$target"

  echo "linux-container: demo -- lane container-nonroot (build and fresh staging, reused from conform)"
  build_log="$(mktemp "${TMPDIR:-/tmp}/linux-container-demo-build.XXXXXX")"
  set +e
  run_conform_build_container "$target" >"$build_log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    cat "$build_log" >&2
    rm -f "$build_log"
    die "demo build lane failed (rc=$rc); see output above."
  fi
  if ! grep -qxF 'CONFORM-BUILD: OK -- freshly staged gran, gran-armed, granary-server, granconf' "$build_log"; then
    cat "$build_log" >&2
    rm -f "$build_log"
    die "demo: refused -- the build container exited 0 without its completion sentinel. Persistent staged files are not proof that this run built and copied them."
  fi
  for f in gran granary-server; do
    if [ ! -x "$target/conform-bin/$f" ]; then
      rm -f "$build_log"
      die "demo: refused -- the build lane printed its completion sentinel but '$target/conform-bin/$f' is missing or not executable."
    fi
  done
  rm -f "$build_log"
  echo "linux-container: demo -- fresh staging OK"

  if [ -L "$target/logs" ]; then
    die "demo: refused -- '$target/logs' is a SYMLINK. Shell redirection follows one, so the demo logs would truncate files wherever it points."
  fi
  mkdir -p "$target/logs"
  demo_log="$target/logs/demo.log"
  selfcheck_log="$target/logs/demo-self-check.log"
  for f in "$demo_log" "$selfcheck_log"; do
    if [ -L "$f" ]; then
      die "demo: refused -- '$f' is a SYMLINK; redirecting into it would truncate its target rather than the log."
    fi
  done

  echo "linux-container: demo -- lane container-root (scripts/demo.sh)"
  set +e
  run_demo_container "$target" >"$demo_log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    cat "$demo_log" >&2
    die "demo lane failed (rc=$rc); see above ($demo_log)."
  fi
  check_demo_log_witnesses "$demo_log" \
    || die "demo: refused -- the container exited 0 but check_demo_log_witnesses failed for $demo_log"
  echo "linux-container: demo -- positive lane OK, every required demo witness present"

  echo "linux-container: demo -- lane container-root (scripts/demo-self-check.sh)"
  set +e
  run_demo_selfcheck_container "$target" >"$selfcheck_log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    cat "$selfcheck_log" >&2
    die "demo self-check lane failed (rc=$rc); see above ($selfcheck_log)."
  fi
  check_demo_selfcheck_log_witnesses "$selfcheck_log" \
    || die "demo: refused -- the self-check container exited 0 but its witness check failed for $selfcheck_log"

  echo "DEMO-GATE: OK -- every enumerated demo and self-check witness is present"
  echo "linux-container: demo OK"
}

# ---------------------------------------------------------------------------
# check_unit_log_witnesses requires the check's witnesses
# BY NAME. rc=0 from the remote 'sudo scripts/unit-check.sh'
# is NEVER trusted alone: a check that skipped its negatives
# could still exit 0. Every UNIT: <case> PASS witness plus
# the final gate line is required, AND (separately,
# below) each namespace negative's own literal FAIL line.
# ---------------------------------------------------------------------------
check_unit_log_witnesses() {
  local log="$1" sentinel fail_line_count
  local -a required_unit_sentinels=(
    'UNIT-CHECK: PASS'
    'UNIT: visible-outside PASS'
    'UNIT: stop PASS'
    'UNIT: allow-other PASS'
    'UNIT: namespace-negative-privatemounts PASS'
    'UNIT: namespace-negative-protectsystem PASS'
    'UNIT: capability-negative PASS'
    'UNIT: trust-downgrade-negative PASS'
    'UNIT: missing-env-negative PASS'
    'UNIT: hostile-instance-negative PASS'
    'UNIT: forbidden-directive-lint PASS'
    'UNIT: static-pins PASS'
    'UNIT: hostname-endpoint PASS'
  )
  for sentinel in "${required_unit_sentinels[@]}"; do
    if ! grep -qxF -- "$sentinel" "$log"; then
      echo "unit: refused -- '$log' lacks the required witness: $sentinel" >&2
      return 1
    fi
  done
  # Case 12 needs a witness too. Require
  # either the full SELinux-label PASS line
  # for an enforcing host or a SKIPPED line
  # naming its reason for a host where that
  # check cannot run. Without this
  # requirement, the case could disappear
  # while all other sentinels remained
  # present. The skip reason makes reduced
  # coverage visible in the captured log.
  # Both branches need an ENDING boundary (`$`), or the gate accepts a
  # truncated or decorated line. The SKIPPED branch must
  # additionally carry a NON-EMPTY reason and close its parenthesis: a skip
  # naming no reason is a silent skip wearing a witness's clothes.
  # PASS is a bare summary line; its label appears
  # on the separate `selinux-label-positive` witness.
  # Require a reason in the SKIPPED branch without
  # imposing that parenthesized form on PASS.
  if ! grep -qE '^UNIT: selinux-label (PASS|SKIPPED \([^)]+\))$' "$log"; then
    echo "unit: refused -- '$log' lacks the required case-12 witness: neither a 'UNIT: selinux-label PASS ...' line nor a 'UNIT: selinux-label SKIPPED (<reason>)' line is present" >&2
    return 1
  fi
  # Case 4's TWO namespace negatives each print this literal line as
  # evidence the perturbation actually fired; a
  # dispatcher that only checked rc==0 could not tell a check that never
  # reached its negatives from one that ran and passed them.
  fail_line_count="$(grep -cxF -- 'UNIT: FAIL mount invisible outside the unit' "$log" || true)"
  if [ "${fail_line_count:-0}" -lt 2 ]; then
    echo "unit: refused -- '$log' contains ${fail_line_count:-0} occurrence(s) of 'UNIT: FAIL mount invisible outside the unit', want at least 2 (one per namespace negative)" >&2
    return 1
  fi
  echo "unit: witnesses OK -- every required sentinel present, $fail_line_count namespace-negative FAIL line(s), in $log"
}

cmd_unit() {
  local target build_log rc f
  local unit_src unit_state env_out log_out ready_marker check_log
  local run_id sentinel volume_name container_id
  local before after leak_rc units_before units_query_rc units_log runtime_log runtime_state runtime_rc

  target="$(guards_target_dir)"
  guard_g3_machine_running
  ensure_image
  claim_target_dir "$target"

  CLEANUP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/linux-container-unit.XXXXXX")"
  echo "linux-container: unit -- querying pre-existing gran-mount@* units"
  units_log="$CLEANUP_DIR/units-before.txt"
  if vm_gran_mount_units >"$units_log" 2>&1; then
    units_query_rc=0
  else
    units_query_rc=$?
  fi
  units_before="$(cat "$units_log")"

  echo "linux-container: unit -- recording the VM mount table before"
  before="$CLEANUP_DIR/mountinfo-before.txt"
  set +e
  vm_mountinfo >"$before" 2>&1
  rc=$?
  set -e
  [ "$rc" -eq 0 ] || { cat "$before" >&2; die "unit: refused -- could not read the VM mount table before (podman machine ssh rc=$rc)."; }
  runtime_log="$CLEANUP_DIR/runtime-unit-before.txt"
  if vm_gran_runtime_unit >"$runtime_log" 2>&1; then
    runtime_rc=0
  else
    runtime_rc=$?
  fi
  runtime_state="$(cat "$runtime_log")"
  refuse_foreign_gran_mounts "$before" "$units_before" "$units_query_rc" "$runtime_state" "$runtime_rc"

  echo "linux-container: unit -- lane container-nonroot (build and fresh staging, reused from conform)"
  build_log="$(mktemp "${TMPDIR:-/tmp}/linux-container-unit-build.XXXXXX")"
  set +e
  run_conform_build_container "$target" >"$build_log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    cat "$build_log" >&2
    rm -f "$build_log"
    die "unit build lane failed (rc=$rc); see output above."
  fi
  if ! grep -qxF 'CONFORM-BUILD: OK -- freshly staged gran, gran-armed, granary-server, granconf' "$build_log"; then
    cat "$build_log" >&2
    rm -f "$build_log"
    die "unit: refused -- the build container exited 0 without its completion sentinel. Persistent staged files are not proof that this run built and copied them."
  fi
  for f in gran granary-server; do
    if [ ! -x "$target/conform-bin/$f" ]; then
      rm -f "$build_log"
      die "unit: refused -- the build lane printed its completion sentinel but '$target/conform-bin/$f' is missing or not executable."
    fi
  done
  rm -f "$build_log"
  echo "linux-container: unit -- fresh staging OK"

  if [ -L "$target/logs" ]; then
    die "unit: refused -- '$target/logs' is a SYMLINK. Shell redirection follows one, so the unit logs would truncate files wherever it points."
  fi
  mkdir -p "$target/logs"

  # The expected sentinel comes from OUTSIDE
  # the mount: its value is generated here
  # and passed as the check's third argument.
  # The stack container writes its CONTENT
  # (UNIT_STACK_LANE_SCRIPT) under a CONTAINER-LOCAL path, never under
  # $target: measured, writing (or even just reading) it under $target --
  # which G2 requires to be virtiofs-shared -- raced gran publish's own
  # harvest_file torn-read guard (pre-lstat vs post-read fstat mtime/size
  # comparison) even when the SAME container wrote it moments earlier and
  # never touched it again; a genuine virtiofs attribute-cache
  # consistency artefact, not a real second writer. demo.sh already
  # avoids this by keeping its own source tree under a container-local
  # /tmp, never under the virtiofs-shared target dir -- the same placement for the same
  # reason. Nothing outside the container ever needs to read this
  # directory's CONTENT again (the sentinel VALUE is generated here and
  # passed through directly), so a fixed container-internal path is
  # sufficient; the stack STATE (its own TLS certs, MinIO data
  # dir, local publish staging store) gets the identical treatment for
  # the same reason.
  unit_src="/tmp/unit-check-src"
  unit_state="/tmp/unit-check-stack-state"
  run_id="$(date +%s)-$$"
  run_id="${run_id//[!A-Za-z0-9]/-}"
  sentinel="unit-check-sentinel.${run_id}"

  env_out="$target/unit-stack.env"
  log_out="$target/logs/unit-stack.log"
  ready_marker="$target/unit-stack.ready"
  if [ -L "$env_out" ] || [ -L "$log_out" ] || [ -L "$ready_marker" ]; then
    die "unit: refused -- one of $env_out/$log_out/$ready_marker is a SYMLINK."
  fi
  rm -f -- "$env_out" "$log_out" "$ready_marker"

  # The instance IS the volume. A fresh, run-unique, DNS-1123-shaped
  # name avoids colliding with any leftover from a prior aborted run.
  volume_name="unit${run_id//[!0-9]/}"
  volume_name="${volume_name:0:32}"

  echo "linux-container: unit -- starting the stack in a container on the VM's own network (--network host), volume=$volume_name"
  set +e
  container_id="$(run_unit_stack_container "$target" "$unit_src" "$unit_state" "$volume_name" "$env_out" "$log_out" "$ready_marker" "$sentinel")"
  rc=$?
  set -e
  [ "$rc" -eq 0 ] && [ -n "$container_id" ] \
    || die "unit: refused -- could not start the stack container (rc=$rc)"

  local waited=0 ready=0
  while [ "$waited" -lt 300 ]; do
    if [ -f "$ready_marker" ]; then
      ready=1
      break
    fi
    if ! podman container exists "$container_id" 2>/dev/null; then
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done
  if [ "$ready" -ne 1 ]; then
    echo "linux-container: unit -- the stack container did not become ready within ${waited}s" >&2
    [ -f "$log_out" ] && cat "$log_out" >&2
    podman logs "$container_id" >&2 2>&1 || true
    podman stop -t 5 "$container_id" >/dev/null 2>&1 || true
    die "unit: refused -- stack container readiness bound exceeded"
  fi
  echo "linux-container: unit -- stack container ready ($container_id), waited ${waited}s"
  # this is the SAME virtiofs boundary the source-tree comment above
  # (in UNIT_STACK_LANE_SCRIPT) already documents a torn-read/attribute-
  # cache artefact on -- a Mac-host stat of a file the container just wrote
  # can observe stale cached metadata for a brief window even after the
  # write has genuinely completed. That measured artefact was on a full
  # content READ with a pre/post attribute comparison (gran publish's
  # harvest_file guard); this is a bare `-s` SIZE check, so the exposure
  # here is narrower -- worst case a spurious "empty" read of a file that
  # is, underneath, already complete (fail CLOSED, not a silent accept of
  # wrong data), and even a genuinely truncated read would still be caught
  # downstream by unit-check.sh's own four-line contract validator
  # before any value is trusted. Closing it anyway, defensively and
  # cheaply, with the same bounded-poll idiom the ready-marker check above
  # already uses for the identical class of staleness, rather than a
  # single-shot stat immediately after the marker's own poll succeeds.
  local env_ready=0 env_waited=0
  while [ "$env_waited" -lt 10 ]; do
    if [ -s "$env_out" ]; then
      env_ready=1
      break
    fi
    sleep 0.5
    env_waited=$((env_waited + 1))
  done
  [ "$env_ready" -eq 1 ] \
    || { podman stop -t 5 "$container_id" >/dev/null 2>&1 || true; die "unit: refused -- $env_out is still empty after the stack reported ready (waited an additional ${env_waited}x0.5s)"; }

  # The endpoint MUST be reachable from the VM's own bare shell BEFORE
  # anything is installed there. --network host is what makes this
  # possible at all; naming the failure here (rather than a confusing
  # downstream systemd error) is the point of checking it explicitly.
  echo "linux-container: unit -- asserting the stack endpoint is reachable from the VM's own shell, before installing anything"
  local curl_log curl_rc
  curl_log="$(mktemp "${TMPDIR:-/tmp}/linux-container-unit-curl.XXXXXX")"
  set +e
  vm_curl_stack_endpoint "$env_out" >"$curl_log" 2>&1
  curl_rc=$?
  set -e
  if [ "$curl_rc" -ne 0 ]; then
    cat "$curl_log" >&2
    rm -f "$curl_log"
    podman stop -t 5 "$container_id" >/dev/null 2>&1 || true
    die "unit: refused -- the stack endpoint is not reachable from the VM's own shell (curl rc=$curl_rc; see the log above). --network host is required for this; check the podman machine's own networking."
  fi
  echo "linux-container: unit -- endpoint reachable from the VM shell (http status $(cat "$curl_log"))"
  rm -f "$curl_log"

  echo "linux-container: unit -- installing the staged gran on the VM and running scripts/unit-check.sh there under sudo"
  check_log="$target/logs/unit.log"
  if [ -L "$check_log" ]; then
    podman stop -t 5 "$container_id" >/dev/null 2>&1 || true
    die "unit: refused -- '$check_log' is a SYMLINK."
  fi
  set +e
  vm_run_unit_check "$REPO_ROOT" "$env_out" "$target/conform-bin/gran" "$sentinel" >"$check_log" 2>&1
  rc=$?
  set -e
  cat "$check_log"

  echo "linux-container: unit -- stopping the stack container"
  podman stop -t 5 "$container_id" >/dev/null 2>&1 \
    || echo "linux-container: unit -- WARNING: podman stop failed for $container_id" >&2

  if [ "$rc" -ne 0 ]; then
    die "unit: refused -- scripts/unit-check.sh failed on the VM (rc=$rc); see $check_log above."
  fi
  check_unit_log_witnesses "$check_log" \
    || die "unit: refused -- the check exited 0 but the witness check failed for $check_log"
  echo "UNIT-GATE: OK -- every enumerated unit-check witness is present, both namespace negatives fired"

  echo "linux-container: unit -- recording the VM mount table after, and the VM leak gate"
  after="$CLEANUP_DIR/mountinfo-after.txt"
  set +e
  vm_mountinfo >"$after" 2>&1
  rc=$?
  set -e
  [ "$rc" -eq 0 ] || { cat "$after" >&2; die "unit: refused -- could not read the VM mount table after (podman machine ssh rc=$rc)."; }

  leak_rc=0
  unit_leak_check "$before" "$after" || leak_rc=1
  [ "$leak_rc" -eq 0 ] \
    || die "unit: refused -- the VM leak gate failed (see UNIT-LEAK/MOUNT-LEAK output above); a real systemd host's own state must never be left dirty by this check."
  echo "linux-container: unit -- no leaked mount and no gran-mount@* unit left on the VM"

  echo "linux-container: unit OK"
}

cmd_publish_restart() {
  local target
  target="$(guards_target_dir)"
  guard_g3_machine_running
  ensure_image
  claim_target_dir "$target"
  GRANARY_AUTHORITY_TARGET_DIR="$target" scripts/authority-venue.sh --publish-restart
}

cmd_test() {
  local target root_log nonroot_log rc
  target="$(guards_target_dir)"
  guard_g3_machine_running
  ensure_image
  claim_target_dir "$target"
  if [ -L "$target/logs" ]; then
    die "test: refused -- '$target/logs' is a SYMLINK. Shell redirection follows one, so the lane logs would truncate files wherever it points."
  fi
  mkdir -p "$target/logs"
  root_log="$target/logs/test-root.log"
  nonroot_log="$target/logs/test-nonroot.log"
  for _lg in "$root_log" "$nonroot_log"; do
    if [ -L "$_lg" ]; then
      die "test: refused -- '$_lg' is a SYMLINK; redirecting into it would truncate its target rather than the log."
    fi
  done

  echo "linux-container: test -- lane container-root (granary-fuse)"
  set +e
  run_root_container "$GRANARY_SELFTEST_ROOT_LANE_POISON" "$target" >"$root_log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    cat "$root_log" >&2
    die "container-root lane failed (rc=$rc); see above ($root_log)."
  fi
  check_markers "$root_log" "container-root" || exit 1
  echo "linux-container: container-root lane OK"

  echo "linux-container: test -- lane container-nonroot (granary-client, clippy, doc)"
  set +e
  run_nonroot_container "$target" >"$nonroot_log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    cat "$nonroot_log" >&2
    die "container-nonroot lane failed (rc=$rc); see above ($nonroot_log)."
  fi
  check_markers "$nonroot_log" "container-nonroot" || exit 1
  echo "linux-container: container-nonroot lane OK"

  echo "linux-container: test -- ALL LANES OK"
}

# Reuse the existing nonroot build/staging and stack lanes. Only the supporting
# services run in a container; every gran under test runs under sudo on the VM.
run_stderr_battery() (
  set -e
  target="$1"
  mode=fixed
  case "${GRANARY_STDERR_CONTROLS:-0}" in
    0) ;;
    1) mode=controls ;;
    *) die 'GRANARY_STDERR_CONTROLS must be 0 or 1' ;;
  esac
  ensure_image
  claim_target_dir "$target"
  [ ! -L "$target/tmp" ] || die 'stderr: target/tmp must not be a symlink'
  mkdir -p "$target/tmp"
  work="$(mktemp -d "$target/tmp/blocked-stderr.XXXXXX")"
  echo "linux-container: stderr -- build evidence in $work"
  if run_conform_build_container "$target" >"$work/build.log" 2>&1; then
    :
  else
    rc=$?
    cat "$work/build.log" >&2
    exit "$rc"
  fi
  grep -qxF 'CONFORM-BUILD: OK -- freshly staged gran, gran-armed, granary-server, granconf' "$work/build.log" \
    || { cat "$work/build.log" >&2; die 'stderr: fresh build witness missing'; }
  controls=""
  if [ "$mode" = controls ]; then
    controls="$work/controls"
    podman run --rm --entrypoint "" --user "$(id -u):$(id -g)" \
      --memory "$GRANARY_LINUX_MEMORY" \
      -v "$REPO_ROOT:$REPO_ROOT" -v "$target:$target" \
      -e HOME="$CONTAINER_HOME" -e CARGO_TARGET_DIR="$target/armed" \
      -w "$REPO_ROOT" "$GRANARY_LINUX_IMAGE" \
      bash scripts/blocked-stderr-controls.sh "$controls"
  fi
  _STDERR_CONTAINER=""
  cleanup_stderr_stack() {
    [ -z "$_STDERR_CONTAINER" ] || podman stop -t 5 "$_STDERR_CONTAINER" >/dev/null 2>&1 || true
  }
  trap cleanup_stderr_stack EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  sentinel="stderr-sentinel-$(basename "$work")"
  _STDERR_CONTAINER="$(run_unit_stack_container "$target" /tmp/stderr-src /tmp/stderr-stack \
    stderr-probe "$work/stack.env" "$work/stack.log" "$work/ready" "$sentinel")"
  [ -n "$_STDERR_CONTAINER" ] || die 'stderr: no stack container id'
  waited=0
  until [ -s "$work/stack.env" ] && [ -f "$work/ready" ]; do
    if [ "$waited" -ge 300 ] || ! podman container exists "$_STDERR_CONTAINER"; then
      cat "$work/stack.log" >&2 || true
      die 'stderr: stack did not become ready within 300s'
    fi
    sleep 1
    waited=$((waited + 1))
  done
  vm_work="$(vm_mktemp_dir blocked-stderr)"
  for path in "$target" "$REPO_ROOT" "$work" "$vm_work" "$sentinel"; do
    assert_safe_for_remote_shell 'stderr argument' "$path"
  done
  [ -z "$controls" ] || assert_safe_for_remote_shell 'stderr controls' "$controls"
  echo "linux-container: stderr -- evidence in $work and VM $vm_work/run"
  podman machine ssh -- "T='$target' REPO='$REPO_ROOT' WORK='$work' VM_WORK='$vm_work' SENTINEL='$sentinel' CONTROLS='$controls' bash -s" <<'EOF'
set -euo pipefail
args=(run "$T/conform-bin/gran-armed" "$WORK/stack.env" "$SENTINEL" "$VM_WORK/run")
[ -z "$CONTROLS" ] || args+=("$CONTROLS")
sudo bash "$REPO/scripts/blocked-stderr.sh" "${args[@]}"
EOF
)

cmd_mount() {
  local target f before after version_log extract archive_log rc version_rc archive_rc
  local markers_rc leak_rc stderr_rc stderr_log stderr_mode
  target="$(guards_target_dir)"
  guard_g3_machine_running

  for f in "$target/cargo-nextest" "$target/fuse-tests.tar.zst" "$target/daemon-tests.tar.zst" "$target/debug/gran"; do
    [ -e "$f" ] || die "mount: refused -- '$f' is missing. Run '$0 build' first."
  done

  CLEANUP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/linux-container-mount.XXXXXX")"

  echo "linux-container: mount -- recording the VM mount table before"
  before="$CLEANUP_DIR/mountinfo-before.txt"
  set +e
  vm_mountinfo >"$before" 2>&1
  rc=$?
  set -e
  [ "$rc" -eq 0 ] || { cat "$before" >&2; die "mount: refused -- could not read the VM mount table before (podman machine ssh rc=$rc)."; }
  warn_foreign_gran_mounts "$before"

  echo "linux-container: mount -- running the container-built gran as the unprivileged core user (ELF/loader acceptance proof)"
  version_log="$CLEANUP_DIR/gran-version.log"
  set +e
  vm_run_gran_version "$target" >"$version_log" 2>&1
  version_rc=$?
  set -e
  # gran has no --version flag (see the script header) -- it prints its own
  # usage banner and exits 2 for any unrecognized invocation. The proof this
  # step exists for is that the ELF LOADS AND RUNS on Fedora CoreOS, not
  # that it recognizes this flag: a genuine loader failure (wrong ISA, a
  # missing shared library) would print no such banner at all, so the
  # banner's presence -- not the exit code -- is the acceptance proof.
  if ! grep -q 'usage: gran' "$version_log"; then
    cat "$version_log" >&2
    die "mount: refused -- 'gran --version' produced no output resembling gran's own usage banner (rc=$version_rc). The ELF/loader acceptance proof failed: the Debian-built binary may not run on Fedora CoreOS."
  fi
  echo "linux-container: gran executed on the bare VM (rc=$version_rc, usage banner present) -- ELF/loader acceptance proof OK"

  set +e
  extract="$(vm_mktemp_dir "linux-container-mount-extract")"
  rc=$?
  set -e
  [ "$rc" -eq 0 ] && [ -n "$extract" ] || die "mount: refused -- could not create a per-run extraction dir on the VM (rc=$rc)."

  echo "linux-container: mount -- running the FUSE and daemon archives under sudo in the bare VM, process-per-test"
  archive_log="$CLEANUP_DIR/archive.log"
  set +e
  vm_run_archive "$target" "$extract" >"$archive_log" 2>&1
  archive_rc=$?
  set -e
  vm_remove_extract_dir "$extract" >/dev/null 2>&1 || true
  # Do NOT `die` here on a nonzero archive_rc: a test that
  # mounts something and then panics or times out -- exactly what the leak
  # gate below exists to catch -- IS a nonzero archive_rc, so returning
  # early would skip the AFTER snapshot and the leak gate entirely. Record
  # the outcome and fall through; report both failures together below.
  markers_rc=0
  if [ "$archive_rc" -ne 0 ]; then
    cat "$archive_log" >&2
    echo "linux-container: mount -- the archive run in the bare VM failed (rc=$archive_rc); see above. Still recording the AFTER mount table and running the leak gate below." >&2
  else
    check_markers "$archive_log" "bare-vm-archive" || markers_rc=1
    if [ "$markers_rc" -eq 0 ]; then
      echo "linux-container: bare-VM archive lane OK"
    fi
  fi

  echo "linux-container: mount -- blocked-stderr battery on the bare VM"
  stderr_log="$CLEANUP_DIR/stderr.log"
  set +e
  run_stderr_battery "$target" >"$stderr_log" 2>&1
  stderr_rc=$?
  set -e
  cat "$stderr_log"
  stderr_mode=fixed
  [ "${GRANARY_STDERR_CONTROLS:-0}" != 1 ] || stderr_mode=controls
  if [ "$stderr_rc" -eq 0 ]; then
    bash "$REPO_ROOT/scripts/blocked-stderr.sh" --check-log "$stderr_log" "$stderr_mode" || stderr_rc=1
    if [ "$stderr_rc" -eq 0 ]; then
      echo 'STDERR-GATE(bare-vm): OK -- every required witness present'
    fi
  fi

  echo "linux-container: mount -- recording the VM mount table after"
  after="$CLEANUP_DIR/mountinfo-after.txt"
  set +e
  vm_mountinfo >"$after" 2>&1
  rc=$?
  set -e
  [ "$rc" -eq 0 ] || { cat "$after" >&2; die "mount: refused -- could not read the VM mount table after (podman machine ssh rc=$rc); the archive run itself had already $([ "$archive_rc" -eq 0 ] && echo "succeeded" || echo "failed with rc=$archive_rc")."; }

  leak_rc=0
  mount_leak_check "$before" "$after" || leak_rc=1

  if [ "$archive_rc" -ne 0 ] || [ "$markers_rc" -ne 0 ] || [ "$stderr_rc" -ne 0 ] || [ "$leak_rc" -ne 0 ]; then
    die "mount: refused -- archive_rc=$archive_rc markers_rc=$markers_rc stderr_rc=$stderr_rc leak_rc=$leak_rc (see the specific failures reported above); the archive, stderr and mount-table leak outcomes are always checked together."
  fi
  echo "linux-container: mount -- no leaked mount in the VM's own mount table"
  echo "linux-container: mount OK"
}

cmd_clean() {
  clean_target "$GRANARY_LINUX_TARGET_DIR"
}

# ===========================================================================
# --self-test
# ===========================================================================

SELFTEST_FAIL=0
declare -a SELFTEST_TABLE=()

record_case() {
  SELFTEST_TABLE+=("$1|$2|$3")
}

# Runs "$@" in a SUBSHELL (so a die()/exit inside it terminates only the
# probe, never the whole --self-test run), capturing combined output to a
# fresh temp file. Sets SC_RC and SC_LOG for the caller.
run_captured() {
  SC_LOG="$(mktemp "${TMPDIR:-/tmp}/linux-container-selftest.XXXXXX")"
  set +e
  ("$@") >"$SC_LOG" 2>&1
  SC_RC=$?
  set -e
}

# A gate must FAIL for the right reason: any nonzero exit is NOT accepted as
# proof (a missing image or a typo would then "prove" the guard) -- the
# case's OWN diagnostic string must be present too. Every pattern
# passed to this function must be a FULL, DISTINCTIVE sentence fragment from
# the guard's own die message -- never a bare word/path that could also
# appear in ordinary command output.
expect_refusal() {
  local id="$1" desc="$2" pat="$3"
  shift 3
  run_captured "$@"
  if [ "$SC_RC" -ne 0 ] && grep -qF -- "$pat" "$SC_LOG"; then
    echo "[$id] REFUSED as expected -- $desc"
    grep -F -- "$pat" "$SC_LOG" | sed 's/^/    > /'
    record_case "$id" "REFUSED (expected)" "$desc"
  else
    echo "[$id] DID NOT REFUSE AS EXPECTED -- $desc (rc=$SC_RC, wanted rc!=0 with a message containing: $pat)"
    sed 's/^/    > /' "$SC_LOG"
    record_case "$id" "FAILED" "$desc"
    SELFTEST_FAIL=1
  fi
  rm -f "$SC_LOG"
}

expect_pass() {
  local id="$1" desc="$2"
  shift 2
  run_captured "$@"
  if [ "$SC_RC" -eq 0 ]; then
    echo "[$id] PASSED as expected (positive control) -- $desc"
    record_case "$id" "PASSED (expected)" "$desc"
  else
    echo "[$id] DID NOT PASS -- $desc (rc=$SC_RC)"
    sed 's/^/    > /' "$SC_LOG"
    record_case "$id" "FAILED" "$desc"
    SELFTEST_FAIL=1
  fi
  rm -f "$SC_LOG"
}

# Compare output as well as status: success alone cannot prove a pure filter
# reported the mountpoint, or stayed silent for an unrelated filesystem.
check_foreign_gran_rows() {
  local snapshot="$1" expected="$2" actual
  actual="$(foreign_gran_mount_rows "$snapshot")" || return 1
  if [ "$actual" != "$expected" ]; then
    printf 'foreign_gran_mount_rows: expected <%s>, got <%s>\n' "$expected" "$actual" >&2
    return 1
  fi
}

# Exercise the production refusal/warning, including the escape decoder and
# both levels of shell quoting. A nonzero status alone is not a witness.
check_preexisting_gran_diagnostic() {
  local handler="$1" snapshot="$2" want_rc="$3" prefix="$4" rc failed=0
  local encoded="$5" expected_command="$6" expected_path="$7" command arg decoded reason
  local out="$CLEANUP_DIR/preexisting-gran.out" err="$CLEANUP_DIR/preexisting-gran.err"
  case "$handler" in
    refuse_foreign_gran_mounts) reason='This run refuses before starting the stack and the unit check.' ;;
    warn_foreign_gran_mounts) reason='The before/after leak diff does not count these pre-existing rows; continuing.' ;;
  esac
  if ("$handler" "$snapshot") >"$out" 2>"$err"; then
    rc=0
  else
    rc=$?
  fi
  if [ "$rc" -ne "$want_rc" ] || [ -s "$out" ] ||
    ! grep -qxF -- "$prefix mount row(s) with SOURCE=gran already exist on the VM:" "$err" ||
    ! grep -qxF -- "$reason" "$err" ||
    ! grep -qF -- 'SOURCE=gran is only a label; a non-FUSE row may be an unrelated filesystem. Check what it is' "$err" ||
    ! grep -qF -- "$encoded" "$err" ||
    ! grep -qxF -- "$expected_command" "$err"; then
    failed=1
  else
    command="$(grep '^  podman machine ssh -- sudo ' "$err")"
    arg="${command#  podman machine ssh -- sudo }"
    arg="${arg#fusermount3 -u }"
    arg="${arg#umount }"
    # Parse only the argument from these synthetic fixtures through both
    # shells. Never evaluate the removal command or call podman.
    if ! decoded="$(
      eval "set -- $arg"
      [ "$#" -eq 1 ] || exit 1
      eval "set -- $1"
      [ "$#" -eq 1 ] || exit 1
      printf '%s' "$1"
    )" || [ "$decoded" != "$expected_path" ]; then
      failed=1
    fi
  fi
  if [ "$failed" -ne 0 ]; then
    printf 'pre-existing gran diagnostic: rc=%s, expected %s; stdout/stderr follow\n' "$rc" "$want_rc" >&2
    cat "$out" "$err" >&2
  fi
  rm -f "$out" "$err"
  return "$failed"
}

check_preexisting_inspection_failure() (
  local handler="$1" snapshot="$2" want_rc="$3" pattern="$4" failed=0
  # Poison just the pure inspection, within this subshell; no VM query runs.
  foreign_gran_mount_rows() { return 9; }
  run_captured "$handler" "$snapshot"
  if [ "$SC_RC" -ne "$want_rc" ] || ! grep -qF -- "$pattern" "$SC_LOG"; then
    cat "$SC_LOG" >&2
    failed=1
  fi
  rm -f "$SC_LOG"
  return "$failed"
)

# Assert one refusal and all diagnostic fragments in order. This also pins
# unit-stop advice ahead of mount-removal advice in the combined case.
check_preexisting_unit_state() {
  local before="$1" units="$2" units_rc="$3" runtime="$4" runtime_rc="$5"
  local remaining pattern failed=0 refusals
  shift 5
  run_captured refuse_foreign_gran_mounts "$before" "$units" "$units_rc" "$runtime" "$runtime_rc"
  remaining="$(cat "$SC_LOG")"
  refusals="$(grep -cF 'linux-container: unit: refused --' "$SC_LOG" || true)"
  [ "$SC_RC" -eq 1 ] && [ "$refusals" -eq 1 ] || failed=1
  for pattern in "$@"; do
    if [[ "$remaining" == *"$pattern"* ]]; then
      remaining="${remaining#*"$pattern"}"
    else
      failed=1
    fi
  done
  if [ "$failed" -ne 0 ]; then
    printf 'unit preflight: expected one refusal with all fragments in order (rc=%s)\n' "$SC_RC" >&2
    cat "$SC_LOG" >&2
  fi
  rm -f "$SC_LOG"
  return "$failed"
}

selftest_foreign_gran_mount_rows() {
  local snapshot="$CLEANUP_DIR/foreign-gran-before.txt" first second
  first='199 50 0:99 / /mnt/foreign-one rw,relatime shared:1 - fuse.gran /dev/fuse rw,user_id=0'
  second='200 50 0:100 / /mnt/foreign-two rw - fuse.gran gran rw,user_id=0'
  printf '%s\n' "$first" "$second" >"$snapshot"
  expect_pass S12-foreign-gran "reports only source gran, excluding fuse.gran with source /dev/fuse" \
    check_foreign_gran_rows "$snapshot" $'/mnt/foreign-two\t'"$second"

  first='201 50 0:101 / /mnt/foreign-source rw - fuse gran rw,user_id=0'
  second='202 50 0:102 / /mnt/foreign-subtype rw shared:1 master:2 - fuse.other gran rw,user_id=0'
  printf '%s\n' "$first" "$second" >"$snapshot"
  expect_pass S12-foreign-source "reports other fuse rows whose source is gran" \
    check_foreign_gran_rows "$snapshot" $'/mnt/foreign-source\t'"$first"$'\n/mnt/foreign-subtype\t'"$second"

  printf '%s\n' '213 50 0:112 /sub /mnt/subtree rw - fuse.gran gran rw' >"$snapshot"
  expect_pass S12-foreign-subroot "source gran with root /sub is findmnt SOURCE gran[/sub], so reports nothing" \
    check_foreign_gran_rows "$snapshot" ""

  first='206 50 0:105 / /mnt/gran-data rw - tmpfs gran rw'
  printf '%s\n' "$first" >"$snapshot"
  expect_pass S12-foreign-tmpfs "reports source gran even on tmpfs, matching unit-check exit cleanup" \
    check_foreign_gran_rows "$snapshot" $'/mnt/gran-data\t'"$first"
  expect_pass S12-preexisting-tmpfs-advice "a non-FUSE row gets umount advice and the source-label explanation" \
    check_preexisting_gran_diagnostic refuse_foreign_gran_mounts "$snapshot" 1 'linux-container: unit: refused --' \
    '/mnt/gran-data' '  podman machine ssh -- sudo umount /mnt/gran-data' '/mnt/gran-data'

  printf '%s\n' \
    '99 50 0:1 / / rw,relatime shared:1 - ext4 /dev/root rw' \
    '203 50 0:103 / /mnt/share rw - virtiofs hostshare rw' \
    '204 50 0:104 / /mnt/ssh rw - fuse.sshfs user@host:/ rw' \
    '207 50 0:106 / /mnt/block rw - fuseblk /dev/sdb rw' \
    '208 50 0:107 / /sys/fs/fuse/connections rw - fusectl fusectl rw' >"$snapshot"
  expect_pass S12-foreign-ordinary "ordinary rows, including virtiofs, fuse.sshfs, fuseblk and fusectl with other sources, report nothing" \
    check_foreign_gran_rows "$snapshot" ""
  expect_pass S12-preexisting-unit-clean "unit does not refuse a clean snapshot" \
    refuse_foreign_gran_mounts "$snapshot"

  printf '%s\n' \
    '205 50 0:1 /gran /var/lib/gran/mnt rw shared:1 - ext4 /dev/root rw' >"$snapshot"
  expect_pass S12-foreign-nonfuse "gran only in a path, with another source and non-fuse fstype, reports nothing" \
    check_foreign_gran_rows "$snapshot" ""

  printf '%s\n' '209 50 0:108 / /mnt/gran\0402 rw - fuse.gran gran rw' >"$snapshot"
  expect_pass S12-preexisting-unit-refusal "unit refuses, naming the escaped mountpoint and the correctly quoted removal command" \
    check_preexisting_gran_diagnostic refuse_foreign_gran_mounts "$snapshot" 1 'linux-container: unit: refused --' \
    '/mnt/gran\0402' '  podman machine ssh -- sudo fusermount3 -u /mnt/gran\\\ 2' '/mnt/gran 2'
  expect_pass S12-preexisting-mount-warning "mount warns on stderr with the same mountpoint and command, and succeeds" \
    check_preexisting_gran_diagnostic warn_foreign_gran_mounts "$snapshot" 0 'linux-container: mount: WARNING --' \
    '/mnt/gran\0402' '  podman machine ssh -- sudo fusermount3 -u /mnt/gran\\\ 2' '/mnt/gran 2'

  printf '%s\n' '210 50 0:109 / /mnt/gran\1342 rw - fuse gran rw' >"$snapshot"
  expect_pass S12-preexisting-backslash "backslash escape followed by a digit has the exact removal command and decodes to the original path" \
    check_preexisting_gran_diagnostic refuse_foreign_gran_mounts "$snapshot" 1 'linux-container: unit: refused --' \
    '/mnt/gran\1342' '  podman machine ssh -- sudo fusermount3 -u /mnt/gran\\\\2' '/mnt/gran\2'

  printf '%s\n' '211 50 0:110 / /mnt/gran\0112 rw - fuse.gran gran rw' >"$snapshot"
  expect_pass S12-preexisting-tab "tab escape followed by a digit has the exact removal command and decodes to the original path" \
    check_preexisting_gran_diagnostic refuse_foreign_gran_mounts "$snapshot" 1 'linux-container: unit: refused --' \
    '/mnt/gran\0112' "  podman machine ssh -- sudo fusermount3 -u \\$\\'/mnt/gran\\\\t2\\'" $'/mnt/gran\t2'

  printf '%s\n' "212 50 0:111 / /mnt/gran'2 rw - fuse.gran gran rw" >"$snapshot"
  expect_pass S12-preexisting-quote "single quote has the exact removal command and decodes to the original path" \
    check_preexisting_gran_diagnostic refuse_foreign_gran_mounts "$snapshot" 1 'linux-container: unit: refused --' \
    "/mnt/gran'2" "  podman machine ssh -- sudo fusermount3 -u /mnt/gran\\\\\\'2" "/mnt/gran'2"

  expect_pass S12-preexisting-mount-inspection-failed "mount warns and succeeds when snapshot inspection fails" \
    check_preexisting_inspection_failure warn_foreign_gran_mounts "$snapshot" 0 \
    'linux-container: mount: WARNING -- the pre-existing-mount check could not run because inspecting the snapshot failed; continuing.'
  expect_pass S12-preexisting-unit-inspection-failed "unit refuses when snapshot inspection fails" \
    check_preexisting_inspection_failure refuse_foreign_gran_mounts "$snapshot" 1 \
    'unit: refused -- could not inspect the VM mount-table snapshot taken before THIS run started.'

  printf '%s\n' '99 50 0:1 / / rw - ext4 /dev/root rw' >"$snapshot"
  expect_pass S12-preexisting-units-listed "listed unit refuses with its name and stop/reset-failed advice" \
    check_preexisting_unit_state "$snapshot" 'gran-mount@fixture.service loaded failed failed Fixture mount' 0 absent 0 \
    'gran-mount@fixture.service loaded failed failed Fixture mount' \
    'stopping the unit also unmounts its mount' \
    'podman machine ssh -- sudo systemctl stop gran-mount@fixture.service; podman machine ssh -- sudo systemctl reset-failed gran-mount@fixture.service 2>/dev/null' \
    'This run refuses before starting the stack and the unit check.'
  expect_pass S12-preexisting-units-empty "successful empty unit query passes" \
    refuse_foreign_gran_mounts "$snapshot" '' 0 absent 0
  expect_pass S12-preexisting-units-query-failed "failed unit query refuses and includes its captured stderr" \
    check_preexisting_unit_state "$snapshot" 'ssh: fixture connection failure' 9 absent 0 \
    "unit: refused -- could not query gran-mount@* units on the VM (podman machine ssh rc=9); a failed query must never be scored as 'no units found'." \
    'Captured query output:' 'ssh: fixture connection failure'

  expect_pass S12-preexisting-runtime-present "pre-existing runtime template refuses with remove/reload advice" \
    check_preexisting_unit_state "$snapshot" '' 0 present 0 \
    '/run/systemd/system/gran-mount@.service already exists and this harness did not just create it. Refusing to overwrite a pre-existing runtime unit.' \
    'podman machine ssh -- sudo rm /run/systemd/system/gran-mount@.service && podman machine ssh -- sudo systemctl daemon-reload' \
    'This run refuses before starting the stack and the unit check.'
  expect_pass S12-preexisting-runtime-absent "absent runtime template and clean unit/mount snapshots pass" \
    refuse_foreign_gran_mounts "$snapshot" '' 0 absent 0
  expect_pass S12-preexisting-runtime-query-failed "failed runtime-template query refuses with captured error" \
    check_preexisting_unit_state "$snapshot" '' 0 'sudo: fixture failure' 9 \
    'could not check /run/systemd/system/gran-mount@.service on the VM (podman machine ssh rc=9).' \
    'sudo: fixture failure'

  printf '%s\n' '214 50 0:113 / /mnt/combined rw - fuse.gran gran rw' >"$snapshot"
  expect_pass S12-preexisting-combined "one refusal names the unit, mount and runtime template, with stop advice first" \
    check_preexisting_unit_state "$snapshot" 'gran-mount@fixture.service loaded active running Fixture mount' 0 present 0 \
    'gran-mount@fixture.service loaded active running Fixture mount' \
    'stopping the unit also unmounts its mount' \
    'podman machine ssh -- sudo systemctl stop gran-mount@fixture.service; podman machine ssh -- sudo systemctl reset-failed gran-mount@fixture.service 2>/dev/null' \
    '/mnt/combined' 'podman machine ssh -- sudo fusermount3 -u /mnt/combined' \
    '/run/systemd/system/gran-mount@.service already exists' \
    'This run refuses before starting the stack and the unit check.'
}

# check_markers wrapper scored as a --self-test case: $5 is 1 to expect a
# refusal, 0 to expect a pass. Reuses check_markers's own diagnostic output
# (already printed by the call itself) rather than duplicating it.
#
# An OPTIONAL $6, the PRODUCING run's own exit status. Only checked
# when want_refuse=0: that is the "expect a clean pass, 0 markers" half,
# where a producer that crashed outright (a podman error, not a genuine
# clean nextest run) is INDISTINGUISHABLE from a real clean pass by marker
# count alone -- an error log also contains zero occurrences of the marker
# text. Measured: MARKER-GATE(S10-client-nonroot): OK against a log that
# was actually a podman error. (The want_refuse=1 half needs no such check:
# a crashed producer there already fails the case correctly, since check_markers
# would then ALSO refuse -- via count_marker's rc>1 path -- for the wrong
# reason, which still correctly registers as "did not behave as expected"
# once the two rc's disagree in the way this comment's sibling logic checks.)
# Pass a literal `skip` (or omit $6) to skip the producer-rc check.
#
# An OPTIONAL $7, a distinctive fragment of check_markers's OWN diagnostic
# text (only meaningful when want_refuse=1). check_markers
# normalises EVERY refusal path -- a genuine marker found, AND an
# unreadable/missing log (count_marker's rc>1 path) -- to the SAME rc=1, so
# a want_refuse=1 case that only checked "rc != 0" would score a case as
# "behaved as expected" even when the log path was simply wrong and no
# marker was ever actually counted. $7 pins the case to the SPECIFIC
# documented reason it claims to demonstrate, exactly like expect_refusal's
# own pattern argument.
check_markers_case() {
  local id="$1" desc="$2" log="$3" lane="$4" want_refuse="$5" producer_rc="${6:-skip}" expect_pat="${7:-}"
  local rc cm_log matched=1
  if [ "$want_refuse" -eq 0 ] && [ "$producer_rc" != "skip" ] && [ "$producer_rc" -ne 0 ]; then
    echo "[$id] DID NOT BEHAVE AS EXPECTED -- $desc (the PRODUCING run itself failed with rc=$producer_rc; 0 markers is not evidence of a clean pass when the run that would have produced them never completed)"
    SELFTEST_FAIL=1
    record_case "$id" "FAILED" "$desc"
    return
  fi
  cm_log="$(mktemp "${TMPDIR:-/tmp}/marker-case-output.XXXXXX")"
  set +e
  check_markers "$log" "$lane" >"$cm_log" 2>&1
  rc=$?
  set -e
  cat "$cm_log"
  if [ "$want_refuse" -eq 1 ]; then
    if [ "$rc" -ne 0 ] && { [ -z "$expect_pat" ] || grep -qF -- "$expect_pat" "$cm_log"; }; then
      matched=0
    fi
  else
    [ "$rc" -eq 0 ] && matched=0
  fi
  rm -f "$cm_log"
  if [ "$matched" -eq 0 ]; then
    echo "[$id] behaved as expected -- $desc"
    record_case "$id" "OK" "$desc"
  else
    echo "[$id] DID NOT BEHAVE AS EXPECTED (rc=$rc, want_refuse=$want_refuse) -- $desc"
    SELFTEST_FAIL=1
    record_case "$id" "FAILED" "$desc"
  fi
}

# Probe the REAL production subcommands
# through poisoned arguments and
# environment values. Testing helpers
# alone cannot establish that cmd_test,
# cmd_mount and cmd_conform invoke
# their marker, identity and leak
# checks. These wrappers call the
# production commands so a missing
# guard at their call sites can change
# the observed result. They do not
# rewrite the script under test.
selftest_root_lane_forced_nonroot() {
  local target="$1"
  GRANARY_SELFTEST_ROOT_LANE_POISON="nonroot" GRANARY_LINUX_TARGET_DIR="$target" cmd_test
}

selftest_mount_with_target() {
  local target="$1"
  GRANARY_LINUX_TARGET_DIR="$target" cmd_mount
}

cmd_self_test() {
  local target n_with n_without rc_fuse_nonroot_final rc_fuse_nonroot_noflag
  local rc_count_with rc_count_without rc_count_s8_archive rc_count_s8_direct
  local n_s8_archive n_s8_direct
  target="$(guards_target_dir)"
  guard_g3_machine_running
  ensure_image
  claim_target_dir "$target"
  CLEANUP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/linux-container-selftest.XXXXXX")"

  echo "== --self-test: building fresh artifacts (S8 needs a current archive) =="
  local build_log="$CLEANUP_DIR/build.log" build_rc
  set +e
  run_build_container "$target" >"$build_log" 2>&1
  build_rc=$?
  set -e
  if [ "$build_rc" -ne 0 ]; then
    cat "$build_log" >&2
    die "--self-test: the prerequisite build failed (rc=$build_rc); every case below depends on it. See above."
  fi
  echo "== --self-test: prerequisite build OK =="

  # ---- S-BUILD-PREFLIGHT: the same reasoning applied to `build` itself -----
  # A genuine build (correct uid, correct image) satisfies BUILD_LANE_SCRIPT's
  # uid/version preflight regardless of whether the preflight CODE is even
  # present -- the checks are airtight given how run_build_container invokes
  # the container, so a poisoned-argument case can never observe their
  # absence (same reasoning as S13-markers/S14 for cmd_test/cmd_mount). Only
  # a sentinel proving the preflight's OWN "OK" line was actually printed
  # can catch it being silently deleted.
  if grep -qF 'BUILD-PREFLIGHT: OK' "$build_log"; then
    echo "[S-BUILD-PREFLIGHT] the prerequisite build's uid+version preflight ran and printed its OK sentinel"
    record_case S-BUILD-PREFLIGHT "OK" "BUILD-PREFLIGHT OK sentinel present in the real build's log"
  else
    echo "[S-BUILD-PREFLIGHT] DID NOT FIND the BUILD-PREFLIGHT OK sentinel in $build_log -- build's uid/version preflight is missing or did not complete"
    SELFTEST_FAIL=1
    record_case S-BUILD-PREFLIGHT "FAILED" "BUILD-PREFLIGHT OK sentinel missing from the real build's log"
  fi

  # ---- S-BUILD-PREFLIGHT-negative: run_build_container's optional
  # want_channel override drives the REAL preflight with a deliberately
  # wrong expected channel; production (cmd_build, the prerequisite build
  # above) never passes this argument.
  expect_refusal S-BUILD-PREFLIGHT-negative "BUILD-PREFLIGHT refuses when the expected rustc channel does not match" \
    "does not EXACTLY match channel" \
    run_build_container "$target" "0.0.0-bogus-channel-selftest"

  # The preflight checks TWO things. Exercise the nextest-version argument
  # too, with the channel left at its real value.
  expect_refusal S-BUILD-PREFLIGHT-negative-nextest "BUILD-PREFLIGHT refuses when the expected cargo-nextest version does not match" \
    "does not EXACTLY match the CI-pinned" \
    run_build_container "$target" "$WANT_CHANNEL" "0.0.0-bogus-nextest-selftest"

  # ---- guard_forbidden_roots -- each named refusal, own case, own
  # sentence, and each is safe to call DIRECTLY (never through clean_target
  # or claim_target_dir) precisely because the refusal fires before either
  # of THOSE functions would ever reach a mkdir/stamp/rm -rf.
  expect_refusal S-ROOT-HOME 'guard_forbidden_roots refuses $HOME by name' \
    "IS \$HOME (" \
    guard_forbidden_roots "$HOME"
  expect_refusal S-ROOT-REPO "guard_forbidden_roots refuses the repo root by name" \
    "IS the repo root (" \
    guard_forbidden_roots "$REPO_ROOT"
  expect_refusal S-ROOT-ANCESTOR "guard_forbidden_roots refuses an ANCESTOR of the repo root by name" \
    "is an ANCESTOR of the repo root (" \
    guard_forbidden_roots "$(canon_path "$(dirname "$REPO_ROOT")")"
  expect_refusal S-ROOT-SLASH "guard_forbidden_roots refuses '/' by name" \
    "is the filesystem root." \
    guard_forbidden_roots "/"
  expect_pass S-ROOT-positive "guard_forbidden_roots does not vacuously refuse a normal target dir" \
    guard_forbidden_roots "$target"

  # ---- claim_target_dir -- the create/empty/stamped ownership rule.
  local claim_pop
  claim_pop="$(mktemp -d "${TMPDIR:-/tmp}/linux-container-selftest-claim.XXXXXX")"
  : >"$claim_pop/unrelated-file"
  expect_refusal S-CLAIM "claim_target_dir refuses a POPULATED directory with no stamp" \
    "exists, is not empty, and does not carry the stamp file" \
    claim_target_dir "$claim_pop"
  rm -rf "$claim_pop"

  local claim_fresh_parent claim_fresh
  claim_fresh_parent="$(mktemp -d "${TMPDIR:-/tmp}/linux-container-selftest-claim.XXXXXX")"
  claim_fresh="$claim_fresh_parent/does-not-exist-yet"
  expect_pass S-CLAIM-positive-fresh "claim_target_dir accepts and stamps a NONEXISTENT directory" \
    claim_target_dir "$claim_fresh"
  if [ ! -e "$claim_fresh/$STAMP_NAME" ]; then
    echo "[S-CLAIM-positive-fresh] claimed successfully but the stamp file is missing afterward" >&2
    SELFTEST_FAIL=1
  fi

  local claim_empty
  claim_empty="$(mktemp -d "${TMPDIR:-/tmp}/linux-container-selftest-claim.XXXXXX")"
  expect_pass S-CLAIM-positive-empty "claim_target_dir accepts and stamps an EXISTING EMPTY directory" \
    claim_target_dir "$claim_empty"
  if [ ! -e "$claim_empty/$STAMP_NAME" ]; then
    echo "[S-CLAIM-positive-empty] claimed successfully but the stamp file is missing afterward" >&2
    SELFTEST_FAIL=1
  fi
  expect_pass S-CLAIM-positive-stamped "claim_target_dir is idempotent on an ALREADY-stamped directory" \
    claim_target_dir "$claim_empty"
  rm -rf "$claim_fresh_parent" "$claim_empty"

  # ---- S1, S2, S3: the target-dir guards, plus the coverage gaps below ------
  # (each guard's own equality half, inside half, and walk-up-branch
  # correctness, not the same "$target" positive worn four times) and
  # (The S2 symlink now lives under $CLEANUP_DIR, already trap-cleaned.)
  expect_refusal S1 "target dir = the repo's own target/ (exact equality)" \
    "which IS or is INSIDE the repo's own target/" \
    guards_target_dir "$REPO_ROOT/target"
  expect_pass S1-positive "guards_target_dir reaches a normal target dir (not vacuously refusing everything)" \
    guards_target_dir "$target"

  # Probe G1's INSIDE half separately from exact
  # equality: a child path must be refused too.
  expect_refusal S1b "target dir is a path INSIDE the repo's own target/ (not equal to it)" \
    "which IS or is INSIDE the repo's own target/" \
    guards_target_dir "$REPO_ROOT/target/some-subdir"

  local s2_link="$CLEANUP_DIR/.linux-container-selftest-symlink"
  ln -sfn "$REPO_ROOT/target" "$s2_link"
  expect_refusal S2 "target dir is a symlink resolving to the repo's target/" \
    "which IS or is INSIDE the repo's own target/" \
    guards_target_dir "$s2_link"
  expect_pass S2-positive "guards_target_dir reaches a normal target dir (not vacuously refusing everything)" \
    guards_target_dir "$target"

  # canon_path's walk-up branch must handle a
  # NONEXISTENT path reached THROUGH the symlink
  # above: it must walk up, resolve the symlink,
  # and reattach the nonexistent suffix, landing
  # inside the repo's target/, so G1's INSIDE half
  # must refuse it. A walk-up replaced with a literal
  # path would leave the unresolved suffix at the
  # symlink spelling, which does not textually
  # match the repo target pattern. This case checks
  # that the guard refuses the resolved path.
  expect_refusal S2b "a NONEXISTENT path reached through the S2 symlink resolves via canon_path's walk-up and is refused by G1's INSIDE half" \
    "which IS or is INSIDE the repo's own target/" \
    guards_target_dir "$s2_link/deeper/deeper2"
  rm -f "$s2_link"

  expect_refusal S3 "target dir outside the virtiofs prefixes" \
    "which is not under a virtiofs-shared prefix (/Users, /private, /var/folders)" \
    guards_target_dir "/opt/linux-container-selftest-outside"
  expect_pass S3-positive "guards_target_dir reaches a normal target dir (not vacuously refusing everything)" \
    guards_target_dir "$target"

  # G2's refuse-set was pinned by exactly one sample (/opt/...).
  expect_refusal S3b "target dir outside the virtiofs prefixes -- a SECOND, distinct sample" \
    "which is not under a virtiofs-shared prefix (/Users, /private, /var/folders)" \
    guards_target_dir "/home/linux-container-selftest-outside-b"

  # "a nonexistent target dir that must be ACCEPTED and correctly
  # canonicalised" -- checks the EXACT returned value, not just accept/
  # refuse, so a walk-up that reattached the suffix wrongly (or a gutted
  # walk-up that returned something else entirely) would be caught here too.
  local walkpos_parent walkpos_probe walkpos_expected walkpos_got walkpos_rc
  walkpos_parent="$(mktemp -d "${TMPDIR:-/tmp}/linux-container-selftest-walkpos.XXXXXX")"
  walkpos_probe="$walkpos_parent/sub1/sub2"
  # $walkpos_parent itself may not be fully canonical (on macOS, $TMPDIR
  # resolves through a /var -> /private/var symlink), and guards_target_dir
  # always returns the FULLY resolved form -- so the expected value must be
  # computed through the same readlink -f, not the raw mktemp output.
  walkpos_expected="$(readlink -f "$walkpos_parent")/sub1/sub2"
  set +e
  walkpos_got="$(guards_target_dir "$walkpos_probe" 2>&1)"
  walkpos_rc=$?
  set -e
  if [ "$walkpos_rc" -eq 0 ] && [ "$walkpos_got" = "$walkpos_expected" ]; then
    echo "[S-WALKPOS] guards_target_dir ACCEPTS a target dir that does not exist yet, and canonicalises it EXACTLY -- got '$walkpos_got'"
    record_case S-WALKPOS "OK" "nonexistent target accepted + correctly canonicalised"
  else
    echo "[S-WALKPOS] DID NOT BEHAVE AS EXPECTED -- rc=$walkpos_rc got='$walkpos_got' want='$walkpos_expected'"
    SELFTEST_FAIL=1
    record_case S-WALKPOS "FAILED" "nonexistent target accept+canonicalise (got=$walkpos_got want=$walkpos_expected)"
  fi
  rmdir "$walkpos_parent" 2>/dev/null || true

  # ---- S2-negative: GRANARY_SELFTEST_ROOT_LANE_POISON refuses an unknown value, BY NAME,
  # before a single podman flag is built from it (the closed-enum
  # replacement for the free-form grants string it superseded).
  expect_refusal S2-poison-unknown "run_root_container refuses a GRANARY_SELFTEST_ROOT_LANE_POISON value outside the closed set" \
    "is not one of the closed set none|no-cap|no-device|no-fusectl|nonroot" \
    run_root_container "bogus-value" "$target"

  # ---- Shared setup for S4/S5/S6/S19: one real container-root, full-grants run
  echo "== --self-test: running the container-root lane with full grants (shared positive for S4/S5/S6/S19) =="
  local log_root_full="$CLEANUP_DIR/root-full.log" rc_root_full
  set +e
  run_root_container "none" "$target" >"$log_root_full" 2>&1
  rc_root_full=$?
  set -e

  # ---- S4, S5: the container-root preflight, one grant dropped at a time.
  # Full sentence fragments, not bare "CAP_SYS_ADMIN"/"/dev/fuse".
  expect_refusal S4 "container-root lane launched WITHOUT --cap-add SYS_ADMIN (GRANARY_SELFTEST_ROOT_LANE_POISON=no-cap)" \
    "does not have CAP_SYS_ADMIN (bit 21) set" \
    run_root_container "no-cap" "$target"
  expect_refusal S5 "container-root lane launched WITHOUT --device /dev/fuse (GRANARY_SELFTEST_ROOT_LANE_POISON=no-device)" \
    "ROOT-PREFLIGHT: refused -- /dev/fuse is not present as a character device" \
    run_root_container "no-device" "$target"
  expect_refusal S19 "container-root lane launched WITHOUT the VM's fusectl bound in (GRANARY_SELFTEST_ROOT_LANE_POISON=no-fusectl)" \
    "ROOT-PREFLIGHT: refused -- /sys/fs/fuse/connections is not a fusectl mount inside the container" \
    run_root_container "no-fusectl" "$target"

  if [ "$rc_root_full" -eq 0 ] && ! grep -q 'ROOT-PREFLIGHT: refused' "$log_root_full"; then
    echo "[S4/S5/S19-positive] PASSED as expected -- the full grants together reach past preflight and the full granary-fuse run succeeds (rc=$rc_root_full)"
    record_case "S4/S5/S19-positive" "PASSED (expected)" "the full grants together reach past preflight"
  else
    echo "[S4/S5/S19-positive] DID NOT PASS -- rc=$rc_root_full"
    sed 's/^/    > /' "$log_root_full"
    SELFTEST_FAIL=1
    record_case "S4/S5/S19-positive" "FAILED" "the full grants together reach past preflight"
  fi

  # ---- S6, S7: the granary-fuse marker gate, non-root, with/without the flag
  echo "== --self-test: running granary-fuse NON-ROOT, with and without --success-output=final (S6/S7) =="
  local log_fuse_nonroot_final="$CLEANUP_DIR/fuse-nonroot-final.log"
  set +e
  run_selftest_probe nonroot granary-fuse "" "--success-output=final" "$target" >"$log_fuse_nonroot_final" 2>&1
  rc_fuse_nonroot_final=$?
  set -e
  local log_fuse_nonroot_noflag="$CLEANUP_DIR/fuse-nonroot-noflag.log"
  set +e
  run_selftest_probe nonroot granary-fuse "" "" "$target" >"$log_fuse_nonroot_noflag" 2>&1
  rc_fuse_nonroot_noflag=$?
  set -e

  check_markers_case S6 "granary-fuse run in a NON-ROOT container, through the marker gate, refuses on the NOT EXECUTED markers even though nextest itself exited 0 with a green 'passed, 0 skipped' summary" \
    "$log_fuse_nonroot_final" "S6-fuse-nonroot" 1 skip "occurrence(s) of 'NOT EXECUTED' in"
  # Require the producing run's own status, not
  # only zero NOT EXECUTED markers. A crashed
  # producer can leave a log with no such
  # markers without having completed the checks.
  check_markers_case S6-positive "the SAME marker gate against the container-root both-grants run passes with 0 markers" \
    "$log_root_full" "S6-positive-root-fuse" 0 "$rc_root_full"

  # ---- S2 (empty-log hole), a negative control: a lane log that contains
  # no nextest summary line at all (e.g. a poisoned entrypoint that exits 0
  # having run nothing) must REFUSE, never score as "0 markers" clean.
  local s2_nolog="$CLEANUP_DIR/s2-empty-summary.log"
  printf 'this log has some text but no nextest summary line in it\n' >"$s2_nolog"
  expect_refusal S2-no-summary "check_markers refuses a log with no nextest summary line at all" \
    "contains no nextest summary line ('tests run:') at all" \
    check_markers "$s2_nolog" "S2-no-summary-lane"

  # count_marker's OWN rc (grep's rc, distinct from the PRODUCING run's rc
  # checked above) must be checked at all four of these contrast
  # sites: leaving it unchecked lets an unreadable or missing log
  # silently read as "0 markers", hiding the difference between a
  # failed count and a successful count of zero.
  set +e
  n_with="$(count_marker "$log_fuse_nonroot_final" 'NOT EXECUTED')"
  rc_count_with=$?
  set -e
  set +e
  n_without="$(count_marker "$log_fuse_nonroot_noflag" 'NOT EXECUTED')"
  rc_count_without=$?
  set -e
  # n_without's PRODUCING run's rc is now part of the contrast --
  # measured: [S7] THE CONTRAST holds ... without it: 0 markers, where the
  # no-flag log was actually a podman error, not a genuine clean nextest
  # run. A producer crash must not be able to satisfy "0 markers" vacuously.
  # rc_fuse_nonroot_final (the WITH-flag run's own rc) is now also checked --
  # it was captured but never tested, so a crashed with-flag producer could
  # spuriously satisfy "n_with > 0" from garbage output.
  if [ "$rc_count_with" -gt 1 ] || [ "$rc_count_without" -gt 1 ]; then
    echo "[S7] THE CONTRAST DID NOT HOLD -- count_marker itself failed (with-flag count_marker rc=$rc_count_with, without-flag count_marker rc=$rc_count_without); an unreadable/missing log must never be scored as a marker count."
    SELFTEST_FAIL=1
    record_case S7 "FAILED" "count_marker rc with=$rc_count_with without=$rc_count_without"
  elif [ "${n_with:-0}" -gt 0 ] && [ "${n_without:-0}" -eq 0 ] && [ "$rc_fuse_nonroot_final" -eq 0 ] && [ "$rc_fuse_nonroot_noflag" -eq 0 ]; then
    echo "[S7] THE CONTRAST holds -- with --success-output=final: $n_with 'NOT EXECUTED' markers; without it: $n_without markers (rc with=$rc_fuse_nonroot_final rc without=$rc_fuse_nonroot_noflag, both runs report the same green nextest summary). The flag is load-bearing."
    record_case S7 "OK" "the --success-output=final contrast holds ($n_with vs $n_without)"
  else
    echo "[S7] THE CONTRAST DID NOT HOLD -- with-flag=$n_with without-flag=$n_without (rc with=$rc_fuse_nonroot_final rc without=$rc_fuse_nonroot_noflag) (expected >0 and ==0 with both producer rc==0)"
    SELFTEST_FAIL=1
    record_case S7 "FAILED" "the --success-output=final contrast ($n_with vs $n_without, rc with=$rc_fuse_nonroot_final rc without=$rc_fuse_nonroot_noflag)"
  fi

  # ---- S8: the bare-VM process-per-test contrast ---------------------------
  # The direct-binary half is PARASITIC on the archive half (it
  # locates the binary the archive run just extracted into $extract) -- the
  # two vm_run_* calls below are deliberately ORDERED, archive before
  # direct, and must stay that way; run direct alone and it errors (fails
  # CLOSED, so this is documentation debt rather than a fail-open).
  echo "== --self-test: S8, the bare-VM archive vs. direct-binary contrast =="
  local extract rc
  set +e
  extract="$(vm_mktemp_dir "linux-container-selftest-extract")"
  rc=$?
  set -e
  { [ "$rc" -eq 0 ] && [ -n "$extract" ]; } || die "--self-test: could not create a per-run VM extraction dir for S8 (rc=$rc)."
  local log_s8_archive="$CLEANUP_DIR/s8-archive.log" rc_s8_archive
  set +e
  vm_run_archive "$target" "$extract" >"$log_s8_archive" 2>&1
  rc_s8_archive=$?
  set -e
  local log_s8_direct="$CLEANUP_DIR/s8-direct.log" rc_s8_direct
  set +e
  vm_run_direct_binary "$extract" >"$log_s8_direct" 2>&1
  rc_s8_direct=$?
  set -e
  vm_remove_extract_dir "$extract" >/dev/null 2>&1 || true

  # count_marker's OWN rc, unchecked at this site before (S6's remaining
  # half, same reasoning as S7 above): an unreadable/missing log must never
  # silently read as "0 markers".
  set +e
  n_s8_archive="$(count_marker "$log_s8_archive" 'NOT EXECUTED')"
  rc_count_s8_archive=$?
  set -e
  set +e
  n_s8_direct="$(count_marker "$log_s8_direct" 'NOT EXECUTED')"
  rc_count_s8_direct=$?
  set -e
  if [ "$rc_count_s8_archive" -gt 1 ] || [ "$rc_count_s8_direct" -gt 1 ]; then
    echo "[S8] THE CONTRAST DID NOT HOLD -- count_marker itself failed (archive count_marker rc=$rc_count_s8_archive, direct count_marker rc=$rc_count_s8_direct)"
    SELFTEST_FAIL=1
    record_case S8 "FAILED" "count_marker rc archive=$rc_count_s8_archive direct=$rc_count_s8_direct"
  elif [ "$rc_s8_archive" -eq 0 ] && [ "${n_s8_archive:-0}" -eq 0 ] && [ "$rc_s8_direct" -eq 0 ] && [ "${n_s8_direct:-0}" -ge 1 ]; then
    echo "[S8] THE CONTRAST holds -- archive run (process-per-test): rc=$rc_s8_archive, $n_s8_archive markers; direct single-process binary run: rc=$rc_s8_direct, $n_s8_direct markers (an irreversible setuid in an earlier test poisoned every later root-gated one in the same process)."
    record_case S8 "OK" "archive=$n_s8_archive markers, direct=$n_s8_direct markers"
  else
    echo "[S8] THE CONTRAST DID NOT HOLD -- archive rc=$rc_s8_archive markers=$n_s8_archive; direct rc=$rc_s8_direct markers=$n_s8_direct"
    sed 's/^/    > /' "$log_s8_archive" "$log_s8_direct"
    SELFTEST_FAIL=1
    record_case S8 "FAILED" "archive=$n_s8_archive/$rc_s8_archive direct=$n_s8_direct/$rc_s8_direct"
  fi

  # ---- S9: clean's stamp-file guard ----------------------------------------
  local s9_dir
  s9_dir="$(mktemp -d "${TMPDIR:-/tmp}/linux-container-selftest-clean.XXXXXX")"
  expect_refusal S9 "clean against a directory with no stamp file" \
    "does not contain the stamp file '$STAMP_NAME'" \
    clean_target "$s9_dir"
  rm -rf "$s9_dir"

  # A populated unstamped directory distinguishes
  # the stamp check from a mere emptiness
  # check. The empty directory in S9 is refused
  # by either condition, so that control
  # alone cannot establish the ownership
  # requirement. Create a separate scratch
  # directory containing an unrelated file,
  # leave the stamp absent, and require the
  # stamp diagnostic from `clean_target`.
  local s9_populated
  s9_populated="$(mktemp -d "${TMPDIR:-/tmp}/linux-container-selftest-clean.XXXXXX")"
  : >"$s9_populated/some-unrelated-file"
  expect_refusal S9-populated-unstamped "clean against a POPULATED directory that still lacks the stamp file (distinguishes the stamp check from a mere emptiness check)" \
    "does not contain the stamp file '$STAMP_NAME'" \
    clean_target "$s9_populated"
  rm -rf "$s9_populated"

  local s9_dir2
  s9_dir2="$(mktemp -d "${TMPDIR:-/tmp}/linux-container-selftest-clean.XXXXXX")"
  : >"$s9_dir2/$STAMP_NAME"
  expect_pass S9-positive "clean removes a directory that DOES carry the stamp file" \
    clean_target "$s9_dir2"
  if [ -e "$s9_dir2" ]; then
    echo "[S9-positive] the directory still exists after clean_target claimed success" >&2
    SELFTEST_FAIL=1
  fi

  # ---- S1-clean-foreign: the mandated new negative control for S1 -- a
  # STAMPED target dir that has gained a foreign file must still be refused:
  # named-artefact deletion never touches unrecognised content, so the
  # directory is not empty afterward, and the final non-recursive `rmdir`
  # refuses BY CONSTRUCTION (a kernel guarantee, not a script check). The
  # refusal message must name the path.
  local s1_foreign s1_foreign_canon
  s1_foreign="$(mktemp -d "${TMPDIR:-/tmp}/linux-container-selftest-clean.XXXXXX")"
  s1_foreign_canon="$(canon_path "$s1_foreign")"
  : >"$s1_foreign/$STAMP_NAME"
  : >"$s1_foreign/some-foreign-file-clean-must-not-touch"
  expect_refusal S1-clean-foreign "clean refuses (at rmdir) a STAMPED target dir that has gained a foreign file it does not recognise" \
    "'$s1_foreign_canon' is not empty after removing the harness's own artefacts" \
    clean_target "$s1_foreign"
  if [ -e "$s1_foreign/some-foreign-file-clean-must-not-touch" ]; then
    echo "[S1-clean-foreign] the foreign file survived, as expected -- clean_target only ever touches its own named artefacts"
  else
    echo "[S1-clean-foreign] the foreign file is GONE -- clean_target touched content it must never touch" >&2
    SELFTEST_FAIL=1
  fi
  rm -rf "$s1_foreign"

  # ---- S-CLEAN-MARKER: the cargo-marker guard's own negative control.
  # `clean_target` recursively removes debug/ ONLY after confirming it is a real
  # cargo target dir (CACHEDIR.TAG at the root, or debug/.fingerprint/). That
  # guard protects a RECURSIVE DELETE. Plant a stamped dir whose debug/
  # carries NEITHER marker and require the refusal, then prove the contents survived.
  local s_marker
  s_marker="$(mktemp -d "${TMPDIR:-/tmp}/linux-container-selftest-marker.XXXXXX")"
  : >"$s_marker/$STAMP_NAME"
  mkdir -p "$s_marker/debug"
  : >"$s_marker/debug/not-cargos-output.txt"
  expect_refusal S-CLEAN-MARKER "clean refuses to recurse into a debug/ that carries neither CACHEDIR.TAG nor debug/.fingerprint/ (it cannot be confirmed as cargo's own output)" \
    "carries neither cargo's CACHEDIR.TAG" \
    clean_target "$s_marker"
  if [ -e "$s_marker/debug/not-cargos-output.txt" ]; then
    echo "[S-CLEAN-MARKER] the unrecognised debug/ content survived, as expected"
  else
    echo "[S-CLEAN-MARKER] the unrecognised debug/ content was DELETED -- the marker guard did not protect it" >&2
    SELFTEST_FAIL=1
  fi
  rm -rf "$s_marker"

  # Paired positive: the SAME function, on a dir whose debug/ DOES carry the
  # marker, removes it and succeeds -- so the refusal above is the guard
  # firing, not clean_target refusing everything.
  local s_marker_ok
  s_marker_ok="$(mktemp -d "${TMPDIR:-/tmp}/linux-container-selftest-marker.XXXXXX")"
  : >"$s_marker_ok/$STAMP_NAME"
  : >"$s_marker_ok/CACHEDIR.TAG"
  mkdir -p "$s_marker_ok/debug"
  : >"$s_marker_ok/debug/cargo-output.bin"
  expect_pass S-CLEAN-MARKER-positive "clean DOES remove a debug/ that carries cargo's CACHEDIR.TAG" \
    clean_target "$s_marker_ok"
  if [ -e "$s_marker_ok" ]; then
    echo "[S-CLEAN-MARKER-positive] the directory still exists after clean_target reported success" >&2
    SELFTEST_FAIL=1
  fi
  rm -rf "$s_marker_ok"

  # ---- S-BUILD-UID: the build lane's own uid refusal, demonstrated.
  # BUILD_LANE_SCRIPT refuses `id -u` == 0 so an artefact is never silently
  # built as root. Run the REAL build wrapper as container root and
  # require its own sentence.
  local s_builduid_log="$CLEANUP_DIR/build-as-root.log"
  set +e
  run_build_container_as_root "$target" >"$s_builduid_log" 2>&1
  local s_builduid_rc=$?
  set -e
  if [ "$s_builduid_rc" -ne 0 ] && grep -qF 'BUILD-PREFLIGHT: refused' "$s_builduid_log"; then
    echo "[S-BUILD-UID] REFUSED as expected -- the build lane refuses to run as container root"
    grep -F 'BUILD-PREFLIGHT: refused' "$s_builduid_log" | sed 's/^/    > /'
    record_case S-BUILD-UID "REFUSED (expected)" "the build lane refuses uid 0"
  else
    echo "[S-BUILD-UID] DID NOT REFUSE (rc=$s_builduid_rc) -- the build lane's uid guard did not fire as root"
    sed 's/^/    > /' "$s_builduid_log"
    record_case S-BUILD-UID "FAILED" "the build lane refuses uid 0"
    SELFTEST_FAIL=1
  fi

  # ---- S10: the client marker gate against a ROOT container ---------------
  echo "== --self-test: S10, the client marker gate against root vs non-root =="
  local log_client_root="$CLEANUP_DIR/client-root-cf.log"
  set +e
  run_selftest_probe root granary-client "test(close_failure)" "--success-output=final" "$target" >"$log_client_root" 2>&1
  set -e
  local log_client_nonroot="$CLEANUP_DIR/client-nonroot-cf.log" rc_client_nonroot
  set +e
  run_selftest_probe nonroot granary-client "test(close_failure)" "--success-output=final" "$target" >"$log_client_nonroot" 2>&1
  rc_client_nonroot=$?
  set -e

  check_markers_case S10 "the client suite's close_failure fixtures, run in a ROOT container, refuse on 'running as uid 0' markers even though nextest reports a green pass" \
    "$log_client_root" "S10-client-root" 1 skip "occurrence(s) of 'running as uid 0' in"
  # Same producer-rc requirement as S6-positive.
  check_markers_case S10-positive "the SAME gate against the non-root lane passes with 0 markers" \
    "$log_client_nonroot" "S10-client-nonroot" 0 "$rc_client_nonroot"

  # ---- S11 -- the REAL cmd_test, root lane forced NON-ROOT ----------
  # Poisoned via GRANARY_SELFTEST_ROOT_LANE_POISON=nonroot (arguments/environment, never
  # by rewriting the script), which maps to a FULL grant set plus --user:
  # the container has --device /dev/fuse AND --cap-add SYS_ADMIN, so this is
  # specifically proving the uid check itself, not a missing grant (that is
  # S4/S5's job).
  echo "== --self-test: S11, the REAL cmd_test with the container-root lane forced non-root =="
  expect_refusal S11 "cmd_test's container-root lane forced NON-ROOT despite full device+cap grants" \
    "inside the container, not 0. The container-root lane needs uid 0 so require_root() cannot defer" \
    selftest_root_lane_forced_nonroot "$target"

  # ---- S12 -- the REAL cmd_mount and mount_leak_check -----
  selftest_foreign_gran_mount_rows
  echo "== --self-test: S12, mount_leak_check (the leak gate's positive control) and cmd_mount with a gran that cannot execute =="
  local s12_before="$CLEANUP_DIR/s12-before.txt" s12_after_clean="$CLEANUP_DIR/s12-after-clean.txt"
  local s12_after_fuse="$CLEANUP_DIR/s12-after-fuse.txt" s12_after_bind="$CLEANUP_DIR/s12-after-bind.txt"
  local s12_before_superopts_base="$CLEANUP_DIR/s12-before-superopts.txt"
  printf '99 50 0:1 / / rw,relatime shared:1 - ext4 /dev/root rw\n' >"$s12_before"
  cp "$s12_before" "$s12_after_clean"
  {
    cat "$s12_before"
    printf '199 50 0:99 / /run/gran-ci/x rw,relatime shared:1 - fuse.gran /dev/fuse rw,user_id=0\n'
  } >"$s12_after_fuse"
  {
    cat "$s12_before"
    printf '299 50 0:1 /var/lib/x /mnt/bindtarget rw,relatime shared:1 - ext4 /dev/root rw\n'
  } >"$s12_after_bind"

  expect_refusal S12-leak-fuse "mount_leak_check fed a synthetic 'after' table with a planted FUSE row the 'before' lacks" \
    "MOUNT-LEAK(bare-vm): refused -- new row(s) appeared in the VM's mount table" \
    mount_leak_check "$s12_before" "$s12_after_fuse"
  expect_refusal S12-leak-nonfuse "mount_leak_check ALSO refuses a planted NON-fuse (ext4 bind) row -- the widened detector" \
    "MOUNT-LEAK(bare-vm): refused -- new row(s) appeared in the VM's mount table" \
    mount_leak_check "$s12_before" "$s12_after_bind"
  expect_pass S12-leak-positive "mount_leak_check passes on an identical before/after table (no planted row)" \
    mount_leak_check "$s12_before" "$s12_after_clean"

  # An UNCHANGED tmpfs mount whose trailing super-options field gains
  # `nr_inodes=` must pass: only that volatile token differs between
  # these snapshots.
  local s12_after_superopts="$CLEANUP_DIR/s12-after-superopts.txt"
  printf '99 50 0:1 / / rw,relatime shared:1 - ext4 /dev/root rw\n46 28 0:45 / /run/gran-ci/x rw,relatime shared:21 - tmpfs tmpfs rw,size=1048576k,mode=755,inode64\n' >"$s12_before_superopts_base"
  printf '99 50 0:1 / / rw,relatime shared:1 - ext4 /dev/root rw\n46 28 0:45 / /run/gran-ci/x rw,relatime shared:21 - tmpfs tmpfs rw,size=1048576k,nr_inodes=943884,mode=755,inode64\n' >"$s12_after_superopts"
  expect_pass S12-leak-superopts "mount_leak_check does NOT report a leak when an unchanged tmpfs row only gains its volatile nr_inodes super-option" \
    mount_leak_check "$s12_before_superopts_base" "$s12_after_superopts"
  # The same pair with a REAL leak appended must still refuse.
  local s12_after_superopts_leak="$CLEANUP_DIR/s12-after-superopts-leak.txt"
  {
    cat "$s12_after_superopts"
    printf '199 50 0:99 / /run/gran-ci/x/mnt rw,relatime shared:1 - fuse.gran /dev/fuse rw,user_id=0\n'
  } >"$s12_after_superopts_leak"
  expect_refusal S12-leak-superopts-still-fires "mount_leak_check STILL refuses a planted FUSE row when the same table also carries the benign super-options churn" \
    "MOUNT-LEAK(bare-vm): refused -- new row(s) appeared in the VM's mount table" \
    mount_leak_check "$s12_before_superopts_base" "$s12_after_superopts_leak"

  # Dropping the whole super-options field would hide a replacement mount
  # reusing the baseline mount ID and mountpoint but differing in those
  # options. This pair differs only in super-options: stripping nr_inodes
  # preserves the difference between errors=continue and errors=remount-ro.
  local s12_before_recycle="$CLEANUP_DIR/s12-before-recycle.txt"
  local s12_after_recycle="$CLEANUP_DIR/s12-after-recycle.txt"
  printf '99 50 0:1 / / rw,relatime shared:1 - ext4 /dev/root rw\n46 28 8:1 /src /mnt/x rw,relatime shared:21 - ext4 /dev/sda1 rw,errors=continue\n' >"$s12_before_recycle"
  printf '99 50 0:1 / / rw,relatime shared:1 - ext4 /dev/root rw\n46 28 8:1 /src /mnt/x rw,relatime shared:21 - ext4 /dev/sda1 rw,errors=remount-ro\n' >"$s12_after_recycle"
  expect_refusal S12-leak-recycled-id "mount_leak_check refuses a row that REUSES a baseline mount id at the same mountpoint and differs only in its super-options -- the case a whole-field key could not see, because mount ids are recycled across the two snapshots" \
    "MOUNT-LEAK(bare-vm): refused -- new row(s) appeared in the VM's mount table" \
    mount_leak_check "$s12_before_recycle" "$s12_after_recycle"

  # ---- S4: mount_leak_check's own fail-open guards, as negative
  # controls: a missing snapshot, and an EMPTY 'before' (the NR==FNR trick
  # that silently treats 'after' as its own baseline).
  # A MISSING 'after' file is caught by the AFTER-nonempty check below
  # (a nonexistent path is not
  # `-s`), before the awk step is ever
  # reached, so the pattern names the check that fires -- the
  # AFTER-specific wording, distinct from S12-leak-empty-before's
  # BEFORE-specific one two cases down.
  expect_refusal S12-leak-missing "mount_leak_check refuses when the 'after' snapshot file is missing" \
    "taken AFTER 'mount' ran) is empty or missing" \
    mount_leak_check "$s12_before" "$CLEANUP_DIR/s12-does-not-exist.txt"
  local s12_before_empty
  s12_before_empty="$CLEANUP_DIR/s12-before-empty.txt"
  : >"$s12_before_empty"
  expect_refusal S12-leak-empty-before "mount_leak_check refuses when 'before' is empty, even though 'after' contains a genuine leak the empty-before bug would otherwise hide" \
    "is empty or missing" \
    mount_leak_check "$s12_before_empty" "$s12_after_fuse"

  local s12b_target
  s12b_target="$(mktemp -d "${TMPDIR:-/tmp}/linux-container-selftest-s12b.XXXXXX")"
  mkdir -p "$s12b_target/debug"
  : >"$s12b_target/cargo-nextest"
  chmod +x "$s12b_target/cargo-nextest"
  : >"$s12b_target/fuse-tests.tar.zst"
  : >"$s12b_target/daemon-tests.tar.zst"
  printf 'not an ELF -- a plain text file standing in for a broken build\n' >"$s12b_target/debug/gran"
  chmod 644 "$s12b_target/debug/gran"
  expect_refusal S12-gran-exec "the REAL cmd_mount with a debug/gran that CANNOT EXECUTE (no +x bit)" \
    "mount: refused -- 'gran --version' produced no output resembling gran's own usage banner" \
    selftest_mount_with_target "$s12b_target"
  rm -rf "$s12b_target"

  # ---- S13 -- the REAL cmd_test end to end, unpoisoned -------------
  # Also doubles as an overall smoke test of both production lanes, and is
  # the case that fails if the container-nonroot lane's cargo clippy or
  # cargo doc step is ever silently deleted: that lane discharges the
  # register row on granary-client's Linux-gated clippy/doc coverage, and
  # nothing else in --self-test pinned it before this case existed. It is
  # ALSO the only thing that can catch cmd_test's OWN check_markers calls
  # being deleted: with the uid preflight airtight, a correctly
  # privileged lane genuinely never has markers to find, so a poisoned-input
  # case can never observe that gate's absence -- only a sentinel proving the
  # gate's OWN "MARKER-GATE(...): OK" line was actually printed can.
  #
  # NOTE: cmd_test redirects each container's stdout/stderr into a LOG FILE
  # ($target/logs/test-{root,nonroot}.log) and only `cat`s it to stderr on
  # FAILURE -- on a successful run, the container's own output (including
  # the NONROOT-CLIPPY/NONROOT-DOC sentinels) never reaches cmd_test's OWN
  # stdout/stderr, so it is not in $SC_LOG. Read the log file cmd_test itself
  # just wrote instead. check_markers's "MARKER-GATE(...): OK" lines, by
  # contrast, ARE printed directly by cmd_test (not redirected), so those
  # two are read from $SC_LOG as usual.
  echo "== --self-test: S13, the REAL cmd_test end to end (unpoisoned) -- proves clippy AND doc actually ran =="
  run_captured cmd_test
  if [ "$SC_RC" -eq 0 ]; then
    echo "[S13-cmd_test] cmd_test PASSED end-to-end (rc=0)"
    record_case "S13-cmd_test" "PASSED (expected)" "the real cmd_test subcommand succeeds unpoisoned"
  else
    echo "[S13-cmd_test] cmd_test FAILED (rc=$SC_RC) -- S13's assertions below depend on this having succeeded"
    sed 's/^/    > /' "$SC_LOG"
    SELFTEST_FAIL=1
    record_case "S13-cmd_test" "FAILED" "the real cmd_test subcommand (unpoisoned)"
  fi
  if grep -qF 'MARKER-GATE(container-root): OK' "$SC_LOG" && grep -qF 'MARKER-GATE(container-nonroot): OK' "$SC_LOG"; then
    echo "[S13-markers] cmd_test's OWN check_markers calls for BOTH lanes ran and printed their OK sentinel"
    record_case S13-markers "OK" "MARKER-GATE OK sentinels present for both lanes in the real cmd_test run"
  else
    echo "[S13-markers] DID NOT FIND both MARKER-GATE OK sentinels in cmd_test's output -- one of cmd_test's own check_markers calls is missing"
    SELFTEST_FAIL=1
    record_case S13-markers "FAILED" "MARKER-GATE OK sentinels missing from the real cmd_test run"
  fi
  local cmd_test_rc="$SC_RC"
  rm -f "$SC_LOG"
  # $nonroot_container_log is a PERSISTENT file cmd_test overwrites (`>`,
  # not `>>`) every time it reaches the nonroot lane -- but if THIS run of
  # cmd_test died before ever reaching that lane (e.g. the root lane itself
  # started failing), the file is untouched and would still hold a STALE
  # sentinel from an earlier, unrelated successful run, which would read as
  # a false OK here even though S13-cmd_test above already correctly failed.
  # Gate on cmd_test's own rc so a stale file can never masquerade as this
  # run's evidence.
  local nonroot_container_log="$target/logs/test-nonroot.log"
  if [ "$cmd_test_rc" -eq 0 ] \
     && [ -e "$nonroot_container_log" ] \
     && grep -qxF 'NONROOT-CLIPPY: OK (rc=0, package=granary-client+granary-cli, features=none)' "$nonroot_container_log" \
     && grep -qxF 'NONROOT-CLIPPY: OK (rc=0, package=granary-cli, features=conformance-breakage)' "$nonroot_container_log" \
     && grep -qxF 'NONROOT-CLIPPY: OK (rc=0, package=granary-fuse, features=conformance-breakage)' "$nonroot_container_log" \
     && grep -qF 'NONROOT-DOC: OK' "$nonroot_container_log"; then
    echo "[S13] the container-nonroot lane's three exact package+feature clippy steps AND doc step all ran and succeeded (their OK sentinels are present in $nonroot_container_log)"
    record_case S13 "OK" "three exact clippy package+feature sentinels + doc sentinel present in the real cmd_test run's own log"
  else
    echo "[S13] DID NOT FIND all three exact clippy package+feature OK sentinels plus the doc OK sentinel in $nonroot_container_log (cmd_test_rc=$cmd_test_rc) -- a Linux clippy feature set or the doc step is missing or did not complete"
    SELFTEST_FAIL=1
    record_case S13 "FAILED" "exact clippy package+feature/doc sentinels missing from the real cmd_test run's own log (rc=$cmd_test_rc)"
  fi

  # ---- S14 -- the REAL cmd_mount end to end, unpoisoned -----
  # Symmetric to S13: catches cmd_mount's OWN check_markers call (group D2b)
  # and mount_leak_check call (group D2c) being deleted -- same reasoning as
  # S13's note above, a clean run genuinely has 0 markers and 0 leaked rows
  # either way, so only the gates' own "OK" sentinels prove they ran at all.
  # Reuses the artifacts the prerequisite build already produced in $target.
  echo "== --self-test: S14, the REAL cmd_mount end to end (unpoisoned) -- proves the marker gate AND the leak check actually ran =="
  run_captured cmd_mount
  if [ "$SC_RC" -eq 0 ]; then
    echo "[S14-cmd_mount] cmd_mount PASSED end-to-end (rc=0)"
    record_case "S14-cmd_mount" "PASSED (expected)" "the real cmd_mount subcommand succeeds unpoisoned"
  else
    echo "[S14-cmd_mount] cmd_mount FAILED (rc=$SC_RC) -- S14's sentinel assertions below depend on this having succeeded"
    sed 's/^/    > /' "$SC_LOG"
    SELFTEST_FAIL=1
    record_case "S14-cmd_mount" "FAILED" "the real cmd_mount subcommand (unpoisoned)"
  fi
  if grep -qF 'MARKER-GATE(bare-vm-archive): OK' "$SC_LOG" && grep -qF 'MOUNT-LEAK(bare-vm): OK' "$SC_LOG" \
     && grep -qF 'STDERR-GATE(bare-vm): OK' "$SC_LOG"; then
    echo "[S14] cmd_mount's archive, stderr and mount-leak gates all printed their OK sentinels"
    record_case S14 "OK" "archive, stderr and mount-leak sentinels present in the real cmd_mount run"
  else
    echo "[S14] DID NOT FIND every OK sentinel in cmd_mount's output"
    SELFTEST_FAIL=1
    record_case S14 "FAILED" "archive, stderr or mount-leak sentinel missing from the real cmd_mount run"
  fi
  rm -f "$SC_LOG"

  # ---- S15 -- conform's argv boundary ---------------------------------
  expect_pass stderr-witnesses 'every required stderr witness refuses deletion and duplication' \
    bash "$REPO_ROOT/scripts/blocked-stderr.sh" --self-test-witnesses
  # Poison main itself, not cmd_conform: the defect is dispatch silently
  # ignoring argv[2..], so a helper-only test could never observe it.
  expect_refusal S15 "the conform subcommand refuses a trailing argument instead of silently ignoring it" \
    "conform: refused -- this subcommand takes no arguments" \
    main conform unexpected-trailing-argument

  # ---- S16 -- the REAL cmd_conform end to end, unpoisoned ------------
  # This is intentionally expensive: it performs four builds, eight mount
  # lifecycles (baseline plus seven breakages), the stack lifecycle, and every
  # pure-text control in conformance.sh. A clean run genuinely has nothing
  # to find whether cmd_conform's sentinel gate exists or not, so require the
  # gate's OWN OK line as proof the production gate actually ran.
  echo "== --self-test: S16, the REAL cmd_conform end to end (unpoisoned; expensive) -- proves cmd_conform's own oracle-sentinel gate ran =="
  run_captured cmd_conform
  if [ "$SC_RC" -eq 0 ] && grep -qF 'CONFORM-GATE: OK' "$SC_LOG"; then
    echo "[S16] cmd_conform passed end-to-end and printed its OWN CONFORM-GATE OK sentinel"
    record_case S16 "OK" "the real cmd_conform succeeded and its own sentinel gate printed OK"
  else
    echo "[S16] cmd_conform DID NOT prove its own sentinel gate ran (rc=$SC_RC)"
    sed 's/^/    > /' "$SC_LOG"
    SELFTEST_FAIL=1
    record_case S16 "FAILED" "the real cmd_conform or its own sentinel gate failed"
  fi

  # ---- S16-baseline: the conform verdict guard's NEGATIVE controls --------
  # S16 above proves cmd_conform PASSES; it cannot show that the
  # baseline-verdict guard refuses. These controls drive
  # check_conform_baseline_verdict itself against the real log and mutants.
  local cbv_real="$target/logs/conform.log"
  if [ -s "$cbv_real" ]; then
    local cbv_ok=1 cbv_mut
    # POSITIVE: the real, unmodified log must be ACCEPTED, or the three
    # refusals below prove only that this predicate refuses everything.
    if ! check_conform_baseline_verdict "$cbv_real"; then
      echo "[S16-baseline] the real '$cbv_real' was REFUSED by check_conform_baseline_verdict; the negative controls below would be vacuous" >&2
      cbv_ok=0
    fi
    # PERTURBATION-LANDED: the real log must contain exactly one such line, or
    # a deletion-based mutant is not a deletion.
    if [ "$(grep -cE '^CONFORM: identical, [0-9]+ rows$' "$cbv_real")" -ne 1 ]; then
      echo "[S16-baseline] '$cbv_real' does not carry exactly one whole-line baseline verdict; the mutants below would not be perturbations" >&2
      cbv_ok=0
    fi
    if [ "$cbv_ok" -eq 1 ]; then
      cbv_mut="$(mktemp "${TMPDIR:-/tmp}/linux-container-selftest-cbv.XXXXXX")"
      local cbv_bad=0
      # MUTANT 1 -- a hyphen-prefixed spelling. A substring guard
      # accepts it without establishing the required whole-line verdict.
      sed -E 's/^(CONFORM: identical, [0-9]+ rows)$/STALE-\1/' "$cbv_real" >"$cbv_mut"
      if ! grep -qE '^STALE-CONFORM: identical, [0-9]+ rows$' "$cbv_mut"; then
        echo "[S16-baseline] mutant 1 DID NOT LAND: no hyphen-prefixed verdict was produced" >&2
        cbv_bad=1
      elif check_conform_baseline_verdict "$cbv_mut"; then
        echo "[S16-baseline] the guard ACCEPTED a hyphen-prefixed verdict -- a substring match does not establish the required whole line" >&2
        cbv_bad=1
      fi
      # MUTANT 2 -- the verdict only as conformance.sh's own die
      # text, which that script prints EXACTLY WHEN THE VERDICT
      # IS MISSING. Accepting this is a fail-open: the guard is
      # satisfied by the message announcing its own failure.
      sed -E 's/^(CONFORM: identical, [0-9]+ rows)$/conformance: baseline comparison: expected exactly one verdict line: \1/' "$cbv_real" >"$cbv_mut"
      if ! grep -q 'expected exactly one verdict line: CONFORM: identical' "$cbv_mut"; then
        echo "[S16-baseline] mutant 2 DID NOT LAND: no embedded verdict was produced" >&2
        cbv_bad=1
      elif check_conform_baseline_verdict "$cbv_mut"; then
        echo "[S16-baseline] the guard ACCEPTED the verdict embedded in conformance.sh's own die text -- a FAIL-OPEN: that line is printed precisely when the verdict is absent" >&2
        cbv_bad=1
      fi
      # MUTANT 3 -- the verdict deleted outright.
      grep -vE '^CONFORM: identical, [0-9]+ rows$' "$cbv_real" >"$cbv_mut"
      if [ "$(wc -l <"$cbv_mut")" -ne "$(( $(wc -l <"$cbv_real") - 1 ))" ]; then
        echo "[S16-baseline] mutant 3 DID NOT LAND: the deletion removed other than exactly one line" >&2
        cbv_bad=1
      elif check_conform_baseline_verdict "$cbv_mut"; then
        echo "[S16-baseline] the guard ACCEPTED a log with the baseline verdict deleted" >&2
        cbv_bad=1
      fi
      rm -f "$cbv_mut"
      if [ "$cbv_bad" -eq 0 ]; then
        record_case S16-baseline "REFUSED (expected)" "check_conform_baseline_verdict accepts the real conform.log and refuses all three mutants of it: a hyphen-prefixed spelling, the verdict embedded in conformance.sh's own die text (the fail-open), and the verdict deleted"
      else
        SELFTEST_FAIL=1
        record_case S16-baseline "FAILED" "the baseline-verdict guard did not refuse a mutant it must refuse"
      fi
    else
      SELFTEST_FAIL=1
      record_case S16-baseline "FAILED" "the real conform.log could not serve as the control corpus"
    fi
  else
    echo "[S16-baseline] SKIPPED -- $cbv_real is missing or empty (S16 above did not produce it)" >&2
    SELFTEST_FAIL=1
    record_case S16-baseline "FAILED" "the real cmd_conform log was missing or empty; the perturbation case could not run"
  fi
  rm -f "$SC_LOG"

  # ---- S17 -- demo's argv boundary ------------------------------------
  # Same reasoning as S15 for conform: poison main itself, not cmd_demo --
  # the defect is dispatch silently ignoring argv[2..].
  expect_refusal S17 "the demo subcommand refuses a trailing argument instead of silently ignoring it" \
    "demo: refused -- this subcommand takes no arguments" \
    main demo unexpected-trailing-argument

  # ---- S18 -- the REAL cmd_demo end to end, unpoisoned; then ONE
  # perturbation on its own log against the extracted witness-check function.
  # This drives the PRODUCTION codepath -- the real container-root
  # mount, read-through, teardown, AND the real self-check container -- not
  # a synthetic log built from scratch; the same reasoning as S16.
  echo "== --self-test: S18, the REAL cmd_demo end to end (unpoisoned; expensive) -- proves cmd_demo's own witness gates ran =="
  run_captured cmd_demo
  if [ "$SC_RC" -eq 0 ] && grep -qF 'DEMO-GATE: OK' "$SC_LOG"; then
    echo "[S18] cmd_demo passed end-to-end and printed its OWN DEMO-GATE OK sentinel"
    record_case S18 "OK" "the real cmd_demo succeeded and its own sentinel gate printed OK"
  else
    echo "[S18] cmd_demo DID NOT prove its own sentinel gate ran (rc=$SC_RC)"
    sed 's/^/    > /' "$SC_LOG"
    SELFTEST_FAIL=1
    record_case S18 "FAILED" "the real cmd_demo or its own sentinel gate failed"
  fi
  rm -f "$SC_LOG"

  # Required perturbation: a COPY of the demo.log S18 just produced,
  # with ONE required demo witness deleted, must make check_demo_log_witnesses
  # (the same function cmd_demo itself calls) refuse BY NAME. Never a synthetic
  # log assembled from scratch -- that would test the check function
  # against a fixture nobody shipped, not against the production codepath's
  # own output.
  local demo_real_log="$target/logs/demo.log"
  if [ -s "$demo_real_log" ]; then
    local demo_mutant
    demo_mutant="$(mktemp "${TMPDIR:-/tmp}/linux-container-selftest-demo.XXXXXX")"
    grep -vxF 'DEMO-OPTIONS: PASS' "$demo_real_log" >"$demo_mutant"
    # PROVE THE MUTATION LANDED. If the real log did not contain the witness
    # -- S18 failed, or the line was reworded -- `grep -vxF` removes NOTHING,
    # the "mutant" is byte-identical to the original, and the checker refuses
    # it anyway because the witness is genuinely absent. The control would
    # then pass having proved only that a log missing a witness is refused,
    # never that a DELETION is detected. Require exactly one line fewer.
    if [ "$(wc -l <"$demo_mutant")" -ne "$(( $(wc -l <"$demo_real_log") - 1 ))" ]; then
      echo "[S18-witness] the perturbation DID NOT LAND: '$demo_real_log' did not contain exactly one 'DEMO-OPTIONS: PASS' line, so the mutant is not a deletion" >&2
      SELFTEST_FAIL=1
      record_case S18-witness "FAILED" "the perturbation did not land; the control would have passed without testing a deletion"
      rm -f "$demo_mutant"
      demo_mutant=""
    fi
    [ -z "$demo_mutant" ] || expect_refusal S18-witness "check_demo_log_witnesses refuses a COPY of the real demo.log with one required demo witness deleted, BY NAME" \
      "lacks the required witness: DEMO-OPTIONS: PASS" \
      check_demo_log_witnesses "$demo_mutant"
    rm -f "$demo_mutant"
  else
    echo "[S18-witness] SKIPPED -- $demo_real_log is missing or empty (S18 above did not produce it)" >&2
    SELFTEST_FAIL=1
    record_case S18-witness "FAILED" "the real cmd_demo log was missing or empty; the perturbation case could not run"
  fi

  # A COPY of the REAL demo-self-check.log S18 just produced, with ONE
  # required witness deleted, must make check_demo_selfcheck_log_witnesses
  # refuse BY NAME.
  local selfcheck_real_log="$target/logs/demo-self-check.log"
  if [ -s "$selfcheck_real_log" ]; then
    local selfcheck_mutant
    selfcheck_mutant="$(mktemp "${TMPDIR:-/tmp}/linux-container-selftest-selfcheck.XXXXXX")"
    grep -vxF 'DEMO-SELF-CHECK: N1 PASS' "$selfcheck_real_log" >"$selfcheck_mutant"
    # Require exactly one deleted witness line, as in S18-witness above.
    if [ "$(wc -l <"$selfcheck_mutant")" -ne "$(( $(wc -l <"$selfcheck_real_log") - 1 ))" ]; then
      echo "[S18-selfcheck-witness] the perturbation DID NOT LAND: '$selfcheck_real_log' did not contain exactly one 'DEMO-SELF-CHECK: N1 PASS' line, so the mutant is not a deletion" >&2
      SELFTEST_FAIL=1
      record_case S18-selfcheck-witness "FAILED" "the perturbation did not land; the control would have passed without testing a deletion"
      rm -f "$selfcheck_mutant"
      selfcheck_mutant=""
    fi
    [ -z "$selfcheck_mutant" ] || expect_refusal S18-selfcheck-witness "check_demo_selfcheck_log_witnesses refuses a COPY of the real demo-self-check.log with one witness deleted, BY NAME" \
      "lacks the required self-check witness: DEMO-SELF-CHECK: N1 PASS" \
      check_demo_selfcheck_log_witnesses "$selfcheck_mutant"
    rm -f "$selfcheck_mutant"
  else
    echo "[S18-selfcheck-witness] SKIPPED -- $selfcheck_real_log is missing or empty (S18 above did not produce it)" >&2
    SELFTEST_FAIL=1
    record_case S18-selfcheck-witness "FAILED" "the real demo-self-check log was missing or empty; the perturbation case could not run"
  fi

  # ---- S-UNIT-LEAK-FN -- the --self-test requirement that a
  # planted loaded gran-mount@* unit must make the leak gate go red.
  # NAMED -FN and says so here because of WHAT this drives --
  # unit_leak_check() DIRECTLY, never cmd_unit. A full cmd_unit run would
  # build the client binary in a container, boot a whole stack
  # container on the VM's own network, and drive the twelve-case
  # scripts/unit-check.sh remotely under sudo -- the same multi-minute
  # cost `./scripts/linux-container.sh unit` already pays as the systemd unit's own
  # decisive verification path (run separately, not duplicated here).
  # Paying that cost a second time on every --self-test run, for a
  # leak-gate probe that only needs a throwaway planted unit, is not worth
  # it -- but that means a green run HERE is proof only of unit_leak_check()
  # in isolation, never that cmd_unit's own call chain (the stack-
  # reachability check, the install-and-run-under-sudo step, the witness
  # gate) actually REACHES unit_leak_check at all. `./scripts/linux-container.sh
  # unit` itself is that proof.
  # Matches S12's mount_leak_check probes: a real, if throwaway,
  # `systemd-run --unit=gran-mount@loaded-probe.service` transient unit is
  # planted on the bare VM (it need not come from this repo's own template
  # to match the 'gran-mount@*' glob systemctl list-units filters on), and
  # the gate must refuse, NAMING it -- never a bare nonzero rc. A positive
  # control (identical before/after, no planted unit) proves the gate is
  # not vacuously always red.
  echo "== --self-test: S-UNIT-LEAK-FN, unit_leak_check() DIRECTLY (not cmd_unit -- see comment above) with a planted loaded gran-mount@* unit =="
  local ul_before ul_after plant_rc
  ul_before="$CLEANUP_DIR/unit-leak-before.txt"
  ul_after="$CLEANUP_DIR/unit-leak-after.txt"
  set +e
  vm_mountinfo >"$ul_before" 2>&1
  set -e
  set +e
  podman machine ssh -- 'sudo systemd-run --unit=gran-mount@loaded-probe.service --no-block /usr/bin/sleep 120' >"$CLEANUP_DIR/unit-leak-plant.log" 2>&1
  plant_rc=$?
  set -e
  if [ "$plant_rc" -ne 0 ]; then
    echo "[S-UNIT-LEAK-FN] SKIPPED -- could not plant the probe unit via systemd-run (rc=$plant_rc):" >&2
    sed 's/^/    > /' "$CLEANUP_DIR/unit-leak-plant.log" >&2
    SELFTEST_FAIL=1
    record_case S-UNIT-LEAK-FN "FAILED" "could not plant the gran-mount@loaded-probe.service probe unit on the VM"
  else
    sleep 1
    set +e
    vm_mountinfo >"$ul_after" 2>&1
    set -e
    expect_refusal S-UNIT-LEAK-FN "unit_leak_check() directly refuses with a planted loaded gran-mount@* unit still listed on the VM, naming it (not a cmd_unit run -- see comment above)" \
      "gran-mount@loaded-probe.service" \
      unit_leak_check "$ul_before" "$ul_after"
    podman machine ssh -- 'sudo systemctl stop gran-mount@loaded-probe.service; sudo systemctl reset-failed gran-mount@loaded-probe.service' >/dev/null 2>&1 || true
    expect_pass S-UNIT-LEAK-FN-positive "unit_leak_check() does not vacuously refuse -- identical before/after and no planted unit passes" \
      unit_leak_check "$ul_before" "$ul_before"
  fi

  # ---- Summary ---------------------------------------------------------
  echo ""
  echo "== --self-test summary =="
  printf '%-20s %-22s %s\n' "CASE" "OUTCOME" "DESCRIPTION"
  local row id outcome desc
  for row in "${SELFTEST_TABLE[@]}"; do
    IFS='|' read -r id outcome desc <<<"$row"
    printf '%-20s %-22s %s\n' "$id" "$outcome" "$desc"
  done

  if [ "$SELFTEST_FAIL" -ne 0 ]; then
    echo ""
    echo "linux-container --self-test: FAILED -- one or more cases did not behave as expected." >&2
    exit 1
  fi
  echo ""
  echo "linux-container --self-test: ALL CASES BEHAVED AS EXPECTED"
}

# ===========================================================================
main() {
  local cmd="${1:-}"
  # EVERY subcommand refuses trailing argv, not only conform. `main` examined $1
  # alone, so `linux-container.sh clean --dry-run` silently performed a REAL clean --
  # a discarded argument that reads as a safety flag is the worst shape for this
  # to take, and `clean` is the destructive one.
  case "$cmd" in
    build | test | mount | clean | conform | demo | unit | publish-restart)
      [ "$#" -eq 1 ] \
        || die "$cmd: refused -- this subcommand takes no arguments; trailing argv elements must not be ignored."
      ;;
  esac
  case "$cmd" in
    build) cmd_build ;;
    test) cmd_test ;;
    publish-restart) cmd_publish_restart ;;
    mount) cmd_mount ;;
    conform) cmd_conform ;;
    demo) cmd_demo ;;
    unit) cmd_unit ;;
    clean) cmd_clean ;;
    --self-test | self-test) cmd_self_test ;;
    -h | --help) usage ;;
    *)
      usage >&2
      die "unknown or missing subcommand: '${cmd}'"
      ;;
  esac
}

# Guarded so this file can be `source`d (e.g. to unit-probe a single guard
# function such as canon_path or guard_forbidden_roots in isolation) without
# also invoking a subcommand. DETECTS sourcing rather than trusting an
# environment variable to claim it: a source-only switch was observed
# to bypass the script entirely, with `main` simply never called
# (the third hook added for testability in this file that turned out to be a
# hole in the property being tested). Run directly, bash sets $0 to the same
# path as ${BASH_SOURCE[0]}; sourced, $0 stays the SOURCING shell's own name
# while ${BASH_SOURCE[0]} still names this file -- they differ iff sourced.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  main "$@"
fi
