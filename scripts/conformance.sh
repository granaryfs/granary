#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# docs/dev-environment.md says "Do not containerise the mount you are
# PROVING". This content-equivalence oracle deliberately departs from that
# rule: mount-table proof belongs to separate mount and mechanism checks, the bare
# VM cannot run the shasum-dependent MinIO harness, and the compared
# read/attr/readdir properties are independent of mount propagation. This
# script therefore does not claim to prove host mount-table behaviour.
#
# The dtype fixture needs glibc >= 2.37: older glibc releases discard the
# zero-inode dirent before the observer can record its deliberately false
# d_type. All generated, cached, mounted, and stack state must remain on the
# checked container-local overlayfs tree; the repository's fuse filesystem
# cannot represent the byte-0xff source name.
set -euo pipefail

export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
STACK="$REPO_ROOT/scripts/stack.sh"
GRAN="$REPO_ROOT/target/debug/gran"
GRAN_ARMED="$REPO_ROOT/target/debug/gran-armed"
GRANARY_SERVER="$REPO_ROOT/target/debug/granary-server"
GRANCONF="$REPO_ROOT/target/debug/granconf"

UID_SENTINEL=54321
GID_SENTINEL=12345
CAPTURE_RC=0
CURRENT_DAEMON_PID=""
CURRENT_DAEMON_LABEL=""
CURRENT_MOUNT_LOG=""
MOUNTPOINT_STATE=""
GRAN_ENDPOINT=""
GRAN_PIN=""
GRAN_ROOT_KEY=""
GRAN_VOLUME=""

die() {
  echo "conformance: $*" >&2
  exit 1
}

capture_all() {
  local output="$1"
  shift
  set +e
  "$@" >"$output" 2>&1
  CAPTURE_RC=$?
  set -e
}

capture_split() {
  local output="$1" error="$2"
  shift 2
  set +e
  "$@" >"$output" 2>"$error"
  CAPTURE_RC=$?
  set -e
}

line_count() {
  awk 'END { print NR + 0 }' "$1"
}

require_exact_line() {
  local file="$1" expected="$2" label="$3" count
  local failure_log="${4:-}"
  if ! count="$(awk -v expected="$expected" '$0 == expected { n++ } END { print n + 0 }' "$file")"; then
    [ -z "$failure_log" ] || cat "$failure_log" >&2
    die "$label: could not inspect the verdict output"
  fi
  [ "$count" -eq 1 ] \
    || { [ -z "$failure_log" ] || cat "$failure_log" >&2;
         die "$label: expected exactly one verdict line: $expected"; }
}

require_refusal_line() {
  local file="$1" expected="$2" rc="$3" label="$4"
  require_exact_line "$file" "$expected" "$label"
  [ "$rc" -ne 0 ] \
    || die "$label: printed its refusal verdict but returned success"
}

require_success_line() {
  local file="$1" expected="$2" rc="$3" label="$4"
  require_exact_line "$file" "$expected" "$label"
  [ "$rc" -eq 0 ] \
    || die "$label: printed its success verdict but returned rc=$rc"
}

print_contract_names() {
  printf '%s\n' \
    GRAN_ENDPOINT \
    GRAN_PIN \
    GRAN_ROOT_KEY \
    GRAN_VOLUME
}

# The verdict and status are both functions only of the supplied text.
#
# It establishes the SHAPE, the NAMES in order, and a VALUE CHARSET that needs no
# shell quoting -- which is what lets the caller assign the four variables
# directly rather than eval the text.
#
# Evaluating the contract as shell code would couple
# this caller's safety to quoting in the producer. The
# validator instead checks assignment shape and allowed
# value characters before direct assignment. A producer
# formatting change must not turn its output into
# commands executed by this privileged caller.
validate_contract() {
  local text_value="$1" line diff_rc
  local -a lines names

  mapfile -t lines < <(printf '%s\n' "$text_value")
  if [ "${#lines[@]}" -ne 4 ]; then
    printf '%s\n' 'CONTRACT: REFUSED line-count'
    return 1
  fi
  for line in "${lines[@]}"; do
    if [[ ! "$line" =~ ^GRAN_(ENDPOINT|PIN|ROOT_KEY|VOLUME)=.+$ ]]; then
      printf '%s\n' 'CONTRACT: REFUSED assignment-shape'
      return 1
    fi
    # The VALUE is constrained too, to a charset carrying no shell meaning:
    # base64 for the pin, hex for the key, host:port for the endpoint. This is
    # what lets the caller assign directly instead of eval-ing the text. A value
    # that would ever need quoting is REFUSED here, never silently evaluated.
    if [[ ! "${line#*=}" =~ ^[][A-Za-z0-9._:/+=@%,-]+$ ]]; then
      printf '%s\n' 'CONTRACT: REFUSED value-charset'
      return 1
    fi
    names+=("${line%%=*}")
  done
  if diff -u <(print_contract_names) <(printf '%s\n' "${names[@]}") >/dev/null 2>&1; then
    diff_rc=0
  else
    diff_rc=$?
  fi
  case "$diff_rc" in
    0) ;;
    1)
      printf '%s\n' 'CONTRACT: REFUSED name-order'
      return 1
      ;;
    *)
      printf '%s\n' 'CONTRACT: REFUSED validator-error'
      return 2
      ;;
  esac
  printf '%s\n' 'CONTRACT: PASS'
}

run_contract_case() {
  local input="$1" expected="$2" polarity="$3" label="$4" verdict rc
  set +e
  verdict="$(validate_contract "$input")"
  rc=$?
  set -e
  printf '%s\n' "$verdict"
  [ "$verdict" = "$expected" ] \
    || die "$label: got contract verdict $(printf '%q' "$verdict"), want $expected"
  case "$polarity" in
    pass)
      [ "$rc" -eq 0 ] || die "$label: PASS verdict returned rc=$rc"
      ;;
    refuse)
      [ "$rc" -ne 0 ] || die "$label: refusal verdict returned success"
      ;;
    *) die "$label: internal contract-test polarity is invalid: $polarity" ;;
  esac
}

require_planned_descendant() {
  local parent="$1" candidate="$2" label="$3"
  case "$candidate" in
    "$parent"/*) ;;
    *) die "$label is not planned below the checked work directory: $candidate" ;;
  esac
}

require_existing_descendant() {
  local parent="$1" candidate="$2" label="$3" parent_abs candidate_abs
  [ -d "$candidate" ] || die "$label is not an existing directory: $candidate"
  parent_abs="$(cd "$parent" && pwd -P)"
  candidate_abs="$(cd "$candidate" && pwd -P)"
  case "$candidate_abs" in
    "$parent_abs"/*) ;;
    *) die "$label resolves outside the checked work directory: $candidate_abs" ;;
  esac
}

preflight() {
  local uid_now capeff capval glibc_raw glibc_name glibc_version extra
  local glibc_major glibc_minor work_type repo_type repo_now tool

  [ "$#" -eq 0 ] || die "this script takes no command-line arguments"
  for tool in awk cat diff find getconf grep id mkdir mktemp mountpoint pwd sleep stat timeout umount; do
    command -v "$tool" >/dev/null 2>&1 \
      || die "preflight refused: required tool is missing: $tool"
  done
  uid_now="$(id -u)"
  [ "$uid_now" -eq 0 ] \
    || die "preflight refused: id -u is $uid_now inside the container, not 0"
  [ -c /dev/fuse ] \
    || die "preflight refused: /dev/fuse is not a character device"

  if ! capeff="$(awk '/^CapEff:/ { print $2 }' /proc/self/status)"; then
    die "preflight refused: could not read CapEff from /proc/self/status"
  fi
  case "$capeff" in
    ''|*[!0-9A-Fa-f]*) die "preflight refused: invalid CapEff value: $capeff" ;;
  esac
  capval=$((16#$capeff))
  [ $(((capval >> 21) & 1)) -eq 1 ] \
    || die "preflight refused: CapEff $capeff lacks CAP_SYS_ADMIN bit 21"

  if ! glibc_raw="$(getconf GNU_LIBC_VERSION)"; then
    die "preflight refused: getconf GNU_LIBC_VERSION failed"
  fi
  read -r glibc_name glibc_version extra <<<"$glibc_raw"
  if [ "$glibc_name" != glibc ] || [ -n "${extra:-}" ]; then
    die "preflight refused: unexpected GNU_LIBC_VERSION output: $glibc_raw"
  fi
  if [[ ! "$glibc_version" =~ ^([0-9]+)\.([0-9]+)(\.[0-9]+)?$ ]]; then
    die "preflight refused: glibc version is not numeric: $glibc_version"
  fi
  glibc_major=$((10#${BASH_REMATCH[1]}))
  glibc_minor=$((10#${BASH_REMATCH[2]}))
  if [ "$glibc_major" -lt 2 ] \
      || { [ "$glibc_major" -eq 2 ] && [ "$glibc_minor" -lt 37 ]; }; then
    die "preflight refused: glibc $glibc_version is older than required 2.37"
  fi

  [ -x "$STACK" ] || die "preflight refused: stack driver is not executable: $STACK"
  [ -x "$GRAN" ] || die "preflight refused: baseline gran is not executable: $GRAN"
  [ -x "$GRAN_ARMED" ] || die "preflight refused: armed gran is not executable: $GRAN_ARMED"
  [ -x "$GRANARY_SERVER" ] \
    || die "preflight refused: granary-server is not executable: $GRANARY_SERVER"
  [ -x "$GRANCONF" ] || die "preflight refused: granconf is not executable: $GRANCONF"

  repo_now="$(pwd -P)"
  [ "$repo_now" = "$REPO_ROOT" ] \
    || die "preflight refused: cwd is $repo_now, want repository root $REPO_ROOT"
  work_type="$(stat -f -c %T -- "$WORK")"
  repo_type="$(stat -f -c %T -- "$REPO_ROOT")"
  [ "$work_type" = overlayfs ] \
    || die "preflight refused: work filesystem is $work_type, want exactly overlayfs"
  [ "$repo_type" = fuse ] \
    || die "preflight refused: repository filesystem is $repo_type, want exactly fuse"

  require_planned_descendant "$WORK" "$SOURCE_DIR" "source directory"
  require_planned_descendant "$WORK" "$CACHE_DIR" "cache directory"
  require_planned_descendant "$WORK" "$MOUNTPOINT" "mountpoint"
  require_planned_descendant "$WORK" "$STACK_STATE" "stack state"
  printf '%s\n' 'PREFLIGHT: PASS'
}

print_verify_passes() {
  printf '%s\n' \
    'VERIFY: name-len-1 PASS' \
    'VERIFY: name-len-255 PASS' \
    'VERIFY: case-fold-siblings PASS' \
    'VERIFY: depth-100 PASS' \
    'VERIFY: wide-dir PASS' \
    'VERIFY: empty-file PASS' \
    'VERIFY: grain-boundary-sizes PASS' \
    'VERIFY: exec-and-nonexec PASS' \
    'VERIFY: symlink-absolute PASS' \
    'VERIFY: symlink-dotdot PASS' \
    'VERIFY: symlink-dangling PASS' \
    'VERIFY: symlink-to-dir PASS' \
    'VERIFY: symlink-to-sibling-file PASS' \
    'VERIFY: dup-subtrees PASS' \
    'VERIFY: name-byte-0xff PASS' \
    'VERIFY: name-literal-backslash-x2f PASS'
}

print_verify_byte_red() {
  printf '%s\n' \
    'VERIFY: name-len-1 PASS' \
    'VERIFY: name-len-255 PASS' \
    'VERIFY: case-fold-siblings PASS' \
    'VERIFY: depth-100 PASS' \
    'VERIFY: wide-dir PASS' \
    'VERIFY: empty-file PASS' \
    'VERIFY: grain-boundary-sizes PASS' \
    'VERIFY: exec-and-nonexec PASS' \
    'VERIFY: symlink-absolute PASS' \
    'VERIFY: symlink-dotdot PASS' \
    'VERIFY: symlink-dangling PASS' \
    'VERIFY: symlink-to-dir PASS' \
    'VERIFY: symlink-to-sibling-file PASS' \
    'VERIFY: dup-subtrees PASS' \
    'VERIFY: name-byte-0xff FAIL: no name contains byte 0xff' \
    'VERIFY: name-literal-backslash-x2f PASS'
}

# Both failure paths below exit 41 on purpose. awk runs END even after an
# in-rule exit, and the END exit status REPLACES the in-rule one, so two codes
# would collapse into this one regardless and read as a diagnosis nobody made.
# The caller turns either into a named message rather than a bare status.
make_mutant() {
  local mode="$1" output="$2"
  awk -F '\t' -v OFS='\t' -v mode="$mode" \
    -v zeros='0000000000000000000000000000000000000000000000000000000000000000' \
    -v ones='1111111111111111111111111111111111111111111111111111111111111111' '
      $2 == "file" {
        files++
        if (files == 1) {
          $6 = ($6 == zeros ? ones : zeros)
        }
        if (files == 2 && mode == "two") {
          if ($4 !~ /^[0-9]+$/) {
            bad_size = 1
            exit 41
          }
          $4 = $4 + 1
        }
      }
      { print }
      END {
        if (files < 2 || bad_size) {
          exit 41
        }
      }
    ' "$SOURCE_DUMP" >"$output" \
    || die "make_mutant $mode: the source dump has fewer than two file rows, or a non-numeric size field"
}

# The last row of a captured TSV, with one field perturbed by APPENDING a digit
# as a STRING. Not arithmetic: awk reformats a numeric result through OFMT, and
# `%.6g` turns a timestamp like 1788344889.9541246310 into 1.78834e+09, which the
# checker then rejects as malformed rather than as the mismatch this red is for.
# Appending keeps the field matching the numeric regex and still differs.
# Every absolute
# red above perturbs a GLOBAL EXPECTATION, so each fires on row 1 alone and none
# of them can tell a checker that walks every row from one that stops after the
# first. Perturbing the OBSERVATION in the LAST row is what pins the far end.
mutate_last_row_field() {
  local input="$1" output="$2" field="$3" rows="$4" changed
  awk -F '\t' -v OFS='\t' -v target="$rows" -v field="$field" \
    'NR == target { $field = $field "1" } { print }' "$input" >"$output"
  changed="$(count_different_rows "$input" "$output")" \
    || die "mutate_last_row_field: could not compare the mutated capture"
  [ "$changed" -eq 1 ] \
    || die "mutate_last_row_field: changed $changed rows, want exactly 1"
}

count_different_rows() {
  local left="$1" right="$2"
  awk '
    NR == FNR { left[FNR] = $0; left_count = FNR; next }
    {
      right_count = FNR
      if (!(FNR in left) || left[FNR] != $0) {
        different++
      }
    }
    END {
      if (left_count != right_count) {
        exit 2
      }
      print different + 0
    }
  ' "$left" "$right"
}

print_expect_refusal_ledger() {
  printf '%s\n' \
    'CONFORM: FAIL --expect content: zero rows of class content (expected at least one)' \
    'CONFORM: FAIL --expect presence: zero rows of class presence (expected at least one)' \
    'CONFORM: FAIL --expect exec: zero rows of class exec (expected at least one)' \
    'CONFORM: FAIL --expect kind: zero rows of class kind (expected at least one)' \
    'CONFORM: FAIL --expect size: zero rows of class size (expected at least one)' \
    'CONFORM: FAIL --expect target: zero rows of class target (expected at least one)' \
    'CONFORM: FAIL --expect dtype: zero rows of class dtype (expected at least one)'
}

probe_mountpoint() {
  local path="$1" rc
  if mountpoint -q "$path"; then
    MOUNTPOINT_STATE=mounted
    return 0
  else
    rc=$?
  fi
  case "$rc" in
    32)
      MOUNTPOINT_STATE=unmounted
      return 0
      ;;
    *)
      MOUNTPOINT_STATE=error
      echo "conformance: mountpoint probe failed for $path with rc=$rc" >&2
      return 1
      ;;
  esac
}

require_unmounted() {
  local label="$1"
  probe_mountpoint "$MOUNTPOINT" \
    || die "$label: mountpoint invocation failed"
  [ "$MOUNTPOINT_STATE" = unmounted ] \
    || die "$label: mountpoint was already mounted before launch"
}

banner_line_count() {
  awk 'index($0, "BREAKAGE ACTIVE: ") == 1 { n++ } END { print n + 0 }' "$1"
}

# The sink worker can deliver the banner after the kernel mount is visible.
# Use the same 100 attempts at 0.1s as mount readiness; the caller still owns
# the exact-count and exact-string assertions, including after this bound.
wait_for_armed_banner() {
  local file="$1" attempts=0 banner_count
  while [ "$attempts" -lt 100 ]; do
    banner_count="$(banner_line_count "$file")" || return 1
    [ "$banner_count" -eq 1 ] && break
    sleep 0.1 || return 1
    attempts=$((attempts + 1))
  done
  printf '%s\n' "$banner_count"
}

# File fixtures exercise the real reader. A subshell-local sleep substitutes
# delayed delivery and records the wait budget without spending wall time.
run_banner_poll_case() (
  local label="$1" initial="$2" delayed="$3" expected_count="$4" expected_waits="$5"
  local file="$WORK/banner-poll.log" waits_file="$WORK/banner-poll.waits"
  local count waits
  printf '%s' "$initial" >"$file"
  printf '%s\n' 0 >"$waits_file"
  sleep() {
    [ "$#" -eq 1 ] && [ "$1" = 0.1 ] \
      || die "$label: banner polling interval changed"
    read -r waits <"$waits_file"
    waits=$((waits + 1))
    [ "$waits" -le 100 ] || die "$label: banner polling exceeded its bound"
    printf '%s\n' "$waits" >"$waits_file"
    if [ "$waits" -eq 2 ]; then
      printf '%s' "$delayed" >>"$file"
    fi
  }
  count="$(wait_for_armed_banner "$file")" || die "$label: banner reader failed"
  read -r waits <"$waits_file"
  [ "$count" -eq "$expected_count" ] \
    || die "$label: got banner count $count, want $expected_count"
  [ "$waits" -eq "$expected_waits" ] \
    || die "$label: got $waits polling waits, want $expected_waits"
  printf 'BANNER-POLL: %s PASS\n' "$label"
)

run_banner_poll_checks() {
  local banner='BREAKAGE ACTIVE: follow-symlink
'
  run_banner_poll_case immediate "$banner" '' 1 0
  run_banner_poll_case delayed '' "$banner" 1 2
  run_banner_poll_case absent '' '' 0 100
  run_banner_poll_case duplicate "$banner$banner" '' 2 100
}

# All eight mounts go through this function. The banner is inspected only
# after the kernel mount and its owning daemon are simultaneously observable.
launch_mount() {
  local binary="$1" breakage="$2" label="$3" attempts=0 ready=0
  local daemon_rc banner_count expected_banner
  local -a args

  require_unmounted "$label"
  [ -z "$CURRENT_DAEMON_PID" ] \
    || die "$label: another mount daemon is still owned: $CURRENT_DAEMON_PID"
  CURRENT_MOUNT_LOG="$WORK/mount-$label.log"
  : >"$CURRENT_MOUNT_LOG"

  args=(mount)
  if [ -n "$breakage" ]; then
    # The feature-off refusal depends on this value-taking flag being the first
    # token after `mount`; keep the live armed invocations in the same shape.
    args+=(--breakage "$breakage")
  fi
  args+=(
    "$GRAN_VOLUME" "$MOUNTPOINT"
    --endpoint "$GRAN_ENDPOINT"
    --pin "$GRAN_PIN"
    --root-key "$GRAN_ROOT_KEY"
    --cache-dir "$CACHE_DIR"
    --uid "$UID_SENTINEL"
    --gid "$GID_SENTINEL"
    --foreground
  )

  "$binary" "${args[@]}" >"$CURRENT_MOUNT_LOG" 2>&1 &
  CURRENT_DAEMON_PID=$!
  CURRENT_DAEMON_LABEL="$label"

  while [ "$attempts" -lt 100 ]; do
    probe_mountpoint "$MOUNTPOINT" \
      || { cat "$CURRENT_MOUNT_LOG" >&2; die "$label: readiness mountpoint probe failed"; }
    if kill -0 "$CURRENT_DAEMON_PID" 2>/dev/null; then
      if [ "$MOUNTPOINT_STATE" = mounted ]; then
        ready=1
        break
      fi
    else
      set +e
      wait "$CURRENT_DAEMON_PID"
      daemon_rc=$?
      set -e
      CURRENT_DAEMON_PID=""
      cat "$CURRENT_MOUNT_LOG" >&2
      die "$label: daemon exited with rc=$daemon_rc before the mount became ready"
    fi
    sleep 0.1
    attempts=$((attempts + 1))
  done
  [ "$ready" -eq 1 ] \
    || { cat "$CURRENT_MOUNT_LOG" >&2; die "$label: mount did not become ready within 10s"; }

  if [ -n "$breakage" ]; then
    if ! banner_count="$(wait_for_armed_banner "$CURRENT_MOUNT_LOG")"; then
      cat "$CURRENT_MOUNT_LOG" >&2
      die "$label: could not inspect the mount banner log"
    fi
    expected_banner="BREAKAGE ACTIVE: $breakage"
    [ "$banner_count" -eq 1 ] \
      || { cat "$CURRENT_MOUNT_LOG" >&2; die "$label: expected exactly one armed banner, found $banner_count"; }
    require_exact_line "$CURRENT_MOUNT_LOG" "$expected_banner" "$label armed banner" "$CURRENT_MOUNT_LOG"
    awk -v expected="$expected_banner" '$0 == expected { print }' "$CURRENT_MOUNT_LOG"
  else
    if ! banner_count="$(banner_line_count "$CURRENT_MOUNT_LOG")"; then
      die "$label: could not inspect the mount banner log"
    fi
    [ "$banner_count" -eq 0 ] \
      || die "$label: feature-off mount printed an armed banner"
  fi
}

lazy_unmount_after_failure() {
  local label="$1"
  if ! probe_mountpoint "$MOUNTPOINT"; then
    echo "conformance: $label: cannot classify mountpoint for forced cleanup" >&2
    return 1
  fi
  if [ "$MOUNTPOINT_STATE" = mounted ]; then
    echo "conformance: $label: forcing lazy unmount after a loud teardown failure" >&2
    if ! umount -l "$MOUNTPOINT"; then
      echo "conformance: $label: lazy unmount failed" >&2
      return 1
    fi
  fi
  if ! probe_mountpoint "$MOUNTPOINT"; then
    return 1
  fi
  [ "$MOUNTPOINT_STATE" = unmounted ]
}

stop_current_mount() {
  local label="$1" pid="$CURRENT_DAEMON_PID" attempts=0 wait_rc failure=0

  [ -n "$pid" ] || { echo "conformance: $label: no current daemon to stop" >&2; return 1; }
  if kill -0 "$pid" 2>/dev/null; then
    if ! kill -TERM "$pid" 2>/dev/null; then
      echo "conformance: $label: could not send SIGTERM to daemon $pid" >&2
      failure=1
    fi
  else
    echo "conformance: $label: daemon $pid exited before coordinated teardown" >&2
    failure=1
  fi

  while kill -0 "$pid" 2>/dev/null && [ "$attempts" -lt 100 ]; do
    if ! sleep 0.1; then
      echo "conformance: $label: shutdown polling sleep failed" >&2
      failure=1
      break
    fi
    attempts=$((attempts + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    echo "conformance: $label: daemon $pid ignored SIGTERM for 10s" >&2
    failure=1
    lazy_unmount_after_failure "$label" || failure=1
    kill -KILL "$pid" 2>/dev/null || true
    attempts=0
    while kill -0 "$pid" 2>/dev/null && [ "$attempts" -lt 50 ]; do
      if ! sleep 0.1; then
        echo "conformance: $label: SIGKILL polling sleep failed" >&2
        failure=1
        break
      fi
      attempts=$((attempts + 1))
    done
  fi

  if kill -0 "$pid" 2>/dev/null; then
    echo "conformance: $label: daemon $pid survived SIGTERM and SIGKILL" >&2
    failure=1
  else
    if wait "$pid"; then
      wait_rc=0
    else
      wait_rc=$?
    fi
    CURRENT_DAEMON_PID=""
    CURRENT_DAEMON_LABEL=""
    if [ "$wait_rc" -ne 0 ]; then
      echo "conformance: $label: daemon exited uncleanly with rc=$wait_rc" >&2
      failure=1
    fi
  fi

  if ! probe_mountpoint "$MOUNTPOINT"; then
    failure=1
  elif [ "$MOUNTPOINT_STATE" = mounted ]; then
    echo "conformance: $label: mount survived daemon teardown" >&2
    failure=1
    lazy_unmount_after_failure "$label" || failure=1
  fi
  return "$failure"
}

# A daemon can mount successfully and then wedge
# while a dump reads through FUSE. Bound that
# operation with `timeout` as well as bounding
# readiness loops; status 124 receives its own diagnostic
# so a blocked dump has an attributable failure.
MOUNT_IO_TIMEOUT=300

dump_tree() {
  local root="$1" output="$2" label="$3" rc
  # A SEPARATE statement: `local` is a builtin, so bash expands every word
  # of it BEFORE running it -- deriving this from $output inside the same
  # `local` reads the name while it is still unset, which `set -u` refuses.
  local error="$output.stderr"
  capture_split "$output" "$error" timeout "$MOUNT_IO_TIMEOUT" "$GRANCONF" dump "$root"
  rc=$CAPTURE_RC
  if [ "$rc" -eq 124 ]; then
    die "$label: granconf dump exceeded ${MOUNT_IO_TIMEOUT}s -- the mount is wedged, not merely slow"
  fi
  if [ "$rc" -ne 0 ]; then
    cat "$error" >&2
    die "$label: granconf dump failed with rc=$rc"
  fi
  if [ -s "$error" ]; then
    cat "$error" >&2
    die "$label: granconf dump wrote an unexpected diagnostic"
  fi
}

check_id_map() {
  local map_file="$1" wanted="$2"
  awk -v wanted="$wanted" '
    NF != 3 || $1 !~ /^[0-9]+$/ || $2 !~ /^[0-9]+$/ || $3 !~ /^[0-9]+$/ || $3 == 0 {
      malformed = 1
      next
    }
    wanted >= $1 && wanted - $1 < $3 { found = 1 }
    END {
      if (NR == 0 || malformed) {
        print "malformed"
        exit 2
      }
      if (found) {
        print "mapped"
        exit 0
      }
      print "unmapped"
      exit 1
    }
  ' "$map_file"
}

# check_id_map is the same pure-function-over-text shape as validate_contract,
# and validate_contract gets five synthetic reds while this got none -- a probe
# that made check_id_map print "mapped" and return 0 unconditionally survived the
# whole suite. Its reds are cheap because its input is a file.
run_id_map_case() {
  local label="$1" wanted="$2" expected="$3" expected_rc="$4" body="$5"
  local file="$WORK/id-map-case.txt" verdict rc
  printf '%s' "$body" >"$file"
  set +e
  verdict="$(check_id_map "$file" "$wanted")"
  rc=$?
  set -e
  [ "$verdict" = "$expected" ] \
    || die "$label: got id-map verdict $(printf '%q' "$verdict"), want $expected"
  [ "$rc" -eq "$expected_rc" ] \
    || die "$label: id-map verdict $expected returned rc=$rc, want $expected_rc"
}

require_sentinel_mappings() {
  local uid_verdict gid_verdict uid_rc gid_rc
  # The reds run every time, before the real read, so a check_id_map degraded to
  # a constant cannot reach the real assertion below.
  run_id_map_case "id-map mapped red"    54321 mapped    0 '0 502 1
1 100000 1000000
'
  run_id_map_case "id-map unmapped red"  54321 unmapped  1 '0 502 1
1 100000 100
'
  run_id_map_case "id-map malformed red" 54321 malformed 2 'not a mapping line
'
  run_id_map_case "id-map empty red"     54321 malformed 2 ''
  run_id_map_case "id-map zero-length-range red" 54321 malformed 2 '1 100000 0
'
  # A witness line, for the same reason every other control here prints one: a
  # control that emits nothing on success leaves the log unable to show it ran.
  printf '%s\n' 'ID-MAP-REDS: PASS'
  set +e
  uid_verdict="$(check_id_map /proc/self/uid_map "$UID_SENTINEL")"
  uid_rc=$?
  gid_verdict="$(check_id_map /proc/self/gid_map "$GID_SENTINEL")"
  gid_rc=$?
  set -e
  if [ "$uid_verdict" != mapped ] || [ "$uid_rc" -ne 0 ]; then
    die "absolute preflight refused: uid $UID_SENTINEL is $uid_verdict in /proc/self/uid_map"
  fi
  if [ "$gid_verdict" != mapped ] || [ "$gid_rc" -ne 0 ]; then
    die "absolute preflight refused: gid $GID_SENTINEL is $gid_verdict in /proc/self/gid_map"
  fi
  printf '%s\n' 'ABSOLUTE-PREFLIGHT: PASS'
}

# This checker reads only the captured TSV. Its timestamp expectation is one
# byte string shared by every row, taken from row 1.
#
# This arm gets NO expectation parameter. Every
# other arm takes its expectation from outside, so
# swapping it yields a red the checker can only
# pass by reading the data. Timestamps have no
# external expectation to swap: the expectation IS
# the observation. A red keyed on a branch selector
# would certify the branch alone. The reds perturb
# the DATA in the LAST row, one field at a time.
check_absolute_text() {
  local file="$1" expected_count="$2" expected_uid="$3" expected_gid="$4"
  local expected_dir_mode="$5" expected_file_mode="$6" expected_exec_mode="$7"
  local expected_symlink_mode="$8" expected_exec_path="$9"
  awk -F '\t' \
    -v expected_count="$expected_count" \
    -v expected_uid="$expected_uid" \
    -v expected_gid="$expected_gid" \
    -v expected_dir_mode="$expected_dir_mode" \
    -v expected_file_mode="$expected_file_mode" \
    -v expected_exec_mode="$expected_exec_mode" \
    -v expected_symlink_mode="$expected_symlink_mode" \
    -v expected_exec_path="$expected_exec_path" '
      {
        rows++
        if (NF != 8) {
          malformed = 1
          next
        }
        if ($1 != expected_uid) bad_uid = 1
        if ($2 != expected_gid) bad_gid = 1
        if ($4 == "d") {
          directories++
          if ($3 != expected_dir_mode) bad_dir_mode = 1
        } else if ($4 == "f") {
          files++
          wanted_mode = expected_file_mode
          if ($8 == expected_exec_path) {
            exec_paths++
            wanted_mode = expected_exec_mode
          }
          if ($3 != wanted_mode) bad_file_mode = 1
        } else if ($4 == "l") {
          symlinks++
          if ($3 != expected_symlink_mode) bad_symlink_mode = 1
        } else {
          malformed = 1
        }
        if ($5 !~ /^-?[0-9]+(\.[0-9]+)?$/ ||
            $6 !~ /^-?[0-9]+(\.[0-9]+)?$/ ||
            $7 !~ /^-?[0-9]+(\.[0-9]+)?$/) {
          malformed = 1
          next
        }
        if (!have_timestamp) {
          common_timestamp = $5
          have_timestamp = 1
        }
        # Concatenating "" forces a STRING comparison. The three stamps must
        # be BYTE-identical, and awk would otherwise compare two
        # strnum fields NUMERICALLY -- which silently accepts 1788.10 against
        # 1788.1, and accepts any difference below double precision. The
        # comparison now proves the property the clause states.
        if ($5 "" != common_timestamp "" || $6 "" != common_timestamp "" ||
            $7 "" != common_timestamp "") {
          bad_timestamps = 1
        }
      }
      END {
        if (malformed || !have_timestamp || directories == 0 || files == 0 || symlinks == 0) {
          print "ABSOLUTE: REFUSED malformed-or-incomplete-tsv"
          exit 2
        }
        if (exec_paths != 1) {
          print "ABSOLUTE: REFUSED exec-path-cardinality"
          exit 2
        }
        if (rows != expected_count) {
          print "ABSOLUTE: FAIL row-count"
          exit 1
        }
        if (bad_uid) {
          print "ABSOLUTE: FAIL uid"
          exit 1
        }
        if (bad_gid) {
          print "ABSOLUTE: FAIL gid"
          exit 1
        }
        if (bad_dir_mode) {
          print "ABSOLUTE: FAIL dir-mode"
          exit 1
        }
        if (bad_file_mode) {
          print "ABSOLUTE: FAIL file-mode"
          exit 1
        }
        if (bad_symlink_mode) {
          print "ABSOLUTE: FAIL symlink-mode"
          exit 1
        }
        if (bad_timestamps) {
          print "ABSOLUTE: FAIL timestamps"
          exit 1
        }
        print "ABSOLUTE: PASS"
      }
    ' "$file"
}

run_absolute_case() {
  local expected="$1" polarity="$2" label="$3"
  shift 3
  local verdict rc
  set +e
  verdict="$(check_absolute_text "$@")"
  rc=$?
  set -e
  printf '%s\n' "$verdict"
  [ "$verdict" = "$expected" ] \
    || die "$label: got absolute verdict $(printf '%q' "$verdict"), want $expected"
  case "$polarity" in
    pass) [ "$rc" -eq 0 ] || die "$label: PASS verdict returned rc=$rc" ;;
    refuse) [ "$rc" -ne 0 ] || die "$label: refusal verdict returned success" ;;
    *) die "$label: internal absolute-test polarity is invalid: $polarity" ;;
  esac
}

print_round_ledger() {
  printf '%s\n' \
    'ROUND truncate-read content PASS' \
    'ROUND omit-entry presence PASS' \
    'ROUND exec-everywhere exec PASS' \
    'ROUND follow-symlink kind PASS' \
    'ROUND misreport-size size PASS' \
    'ROUND mangle-symlink-target target PASS' \
    'ROUND dirent-type-lie dtype PASS'
}

teardown_on_exit() {
  local failure=0 pid attempts wait_rc stack_rc
  set +e

  if [ -n "$CURRENT_DAEMON_PID" ]; then
    pid="$CURRENT_DAEMON_PID"
    if kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || failure=1
    fi
    attempts=0
    while kill -0 "$pid" 2>/dev/null && [ "$attempts" -lt 100 ]; do
      sleep 0.1
      attempts=$((attempts + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
      echo "conformance: EXIT teardown: $CURRENT_DAEMON_LABEL daemon $pid ignored SIGTERM" >&2
      failure=1
      lazy_unmount_after_failure "EXIT teardown" || failure=1
      kill -KILL "$pid" 2>/dev/null || true
      attempts=0
      while kill -0 "$pid" 2>/dev/null && [ "$attempts" -lt 50 ]; do
        sleep 0.1
        attempts=$((attempts + 1))
      done
    fi
    if kill -0 "$pid" 2>/dev/null; then
      echo "conformance: EXIT teardown: daemon $pid survived SIGKILL" >&2
      failure=1
    else
      wait "$pid"
      wait_rc=$?
      CURRENT_DAEMON_PID=""
      if [ "$wait_rc" -ne 0 ]; then
        echo "conformance: EXIT teardown: daemon exited with rc=$wait_rc" >&2
        failure=1
      fi
    fi
  fi

  "$STACK" stop --state-dir "$STACK_STATE"
  stack_rc=$?
  if [ "$stack_rc" -ne 0 ]; then
    echo "conformance: EXIT teardown: stack stop failed with rc=$stack_rc" >&2
    failure=1
  fi

  if ! probe_mountpoint "$MOUNTPOINT"; then
    failure=1
  elif [ "$MOUNTPOINT_STATE" = mounted ]; then
    echo "conformance: EXIT teardown: mount survived the final assertion" >&2
    failure=1
    lazy_unmount_after_failure "EXIT teardown" || failure=1
  fi
  return "$failure"
}

emit_final() {
  if ! diff -u <(print_round_ledger) "$ROUND_LEDGER" >&2; then
    echo "conformance: ordered round ledger did not match the frozen table" >&2
    return 1
  fi
  cat "$ROUND_LEDGER" || return 1
  printf '%s\n' 'ROUND-LEDGER: PASS'
  printf '%s\n' 'CONFORMANCE: PASS'
}

command -v mktemp >/dev/null 2>&1 \
  || die "preflight refused: required tool is missing: mktemp"
WORK="$(mktemp -d /tmp/conformance.XXXXXX)"
SOURCE_DIR="$WORK/src"
CACHE_DIR="$WORK/cache"
MOUNTPOINT="$WORK/mount"
STACK_STATE="$WORK/stack"
EMPTY_DIR="$WORK/empty-dir"
SOURCE_DUMP="$WORK/source.dump"
EMPTY_DUMP="$WORK/empty.dump"
EXPECT_LEDGER="$WORK/expect-refusals.ledger"
ROUND_LEDGER="$WORK/rounds.ledger"
ABSOLUTE_TSV="$WORK/absolute.tsv"

preflight "$@"
grep -q 'shasum -a 256' scripts/minio-harness.sh \
  || die 'the venue premise dissolved: minio-harness.sh no longer digests with shasum -a 256; re-decide the venue'
printf '%s\n' 'VENUE-TRIPWIRE: PASS'
run_banner_poll_checks

mkdir -m 700 "$CACHE_DIR" "$MOUNTPOINT" "$STACK_STATE" "$EMPTY_DIR"
require_existing_descendant "$WORK" "$CACHE_DIR" "cache directory"
require_existing_descendant "$WORK" "$MOUNTPOINT" "mountpoint"
require_existing_descendant "$WORK" "$STACK_STATE" "stack state"

capture_all "$WORK/gendir.log" "$GRANCONF" gendir --out "$SOURCE_DIR" --seed 13
gendir_rc=$CAPTURE_RC
cat "$WORK/gendir.log"
[ "$gendir_rc" -eq 0 ] || die "granconf gendir failed with rc=$gendir_rc"
require_existing_descendant "$WORK" "$SOURCE_DIR" "source directory"

dump_tree "$SOURCE_DIR" "$SOURCE_DUMP" "source"
if ! SOURCE_ROWS="$(line_count "$SOURCE_DUMP")"; then
  die "could not count source dump rows"
fi
[ "$SOURCE_ROWS" -gt 0 ] || die "source dump is empty"

if ! SOURCE_EXEC_REL="$(awk -F '\t' '
    $2 == "file" && $5 == "x" { count++; path = $1 }
    END { if (count != 1) exit 1; print path }
  ' "$SOURCE_DUMP")"; then
  die "source dump does not contain exactly one executable file row"
fi
if [[ ! "$SOURCE_EXEC_REL" =~ ^[-A-Za-z0-9._/+~]+$ ]]; then
  die "source executable path is not directly representable for the absolute checker: $SOURCE_EXEC_REL"
fi
SOURCE_EXEC_MOUNT_PATH="$MOUNTPOINT/$SOURCE_EXEC_REL"

capture_all "$WORK/verify-source.log" "$GRANCONF" verify-cases "$SOURCE_DUMP"
verify_source_rc=$CAPTURE_RC
cat "$WORK/verify-source.log"
[ "$verify_source_rc" -eq 0 ] \
  || die "unmodified source verify-cases returned rc=$verify_source_rc"
diff -u <(print_verify_passes) "$WORK/verify-source.log" >/dev/null \
  || die "unmodified source did not produce the frozen 16-case PASS list"
printf '%s\n' 'VERIFY-SOURCE: PASS'

dump_tree "$EMPTY_DIR" "$WORK/empty-dir.dump" "empty-directory"
[ ! -s "$WORK/empty-dir.dump" ] \
  || die "granconf dump emitted a row for an empty directory"
# The property the dead-mount control silently rests on: were there a root row,
# a dead mount would emit exactly one, it would compare EQUAL, and --expect
# presence would PASS -- the control proving the opposite of its claim.
printf '%s\n' 'EMPTY-DUMP: PASS'

make_mutant one "$WORK/mutant-content.dump"
make_mutant two "$WORK/mutant-content-size.dump"
if ! one_diff_rows="$(count_different_rows "$SOURCE_DUMP" "$WORK/mutant-content.dump")"; then
  die "could not compare source and one-class mutant row-for-row"
fi
if ! two_diff_rows="$(count_different_rows "$SOURCE_DUMP" "$WORK/mutant-content-size.dump")"; then
  die "could not compare source and two-class mutant row-for-row"
fi
[ "$one_diff_rows" -eq 1 ] \
  || die "one-class mutant differs on $one_diff_rows rows, want exactly 1"
[ "$two_diff_rows" -eq 2 ] \
  || die "two-class mutant differs on $two_diff_rows rows, want exactly 2"

: >"$EXPECT_LEDGER"
for class in content presence exec kind size target dtype; do
  expected="CONFORM: FAIL --expect $class: zero rows of class $class (expected at least one)"
  capture_all "$WORK/expect-zero-$class.log" \
    "$GRANCONF" compare "$SOURCE_DUMP" "$SOURCE_DUMP" --expect "$class"
  control_rc=$CAPTURE_RC
  cat "$WORK/expect-zero-$class.log"
  require_refusal_line "$WORK/expect-zero-$class.log" "$expected" "$control_rc" \
    "identical-dump --expect $class control"
  awk -v expected="$expected" '$0 == expected { print }' \
    "$WORK/expect-zero-$class.log" >>"$EXPECT_LEDGER"
done
diff -u <(print_expect_refusal_ledger) "$EXPECT_LEDGER" >/dev/null \
  || die "ordered per-class refusal ledger did not match the frozen table"
printf '%s\n' 'EXPECT-REFUSAL-LEDGER: PASS'

capture_all "$WORK/expect-two-class.log" \
  "$GRANCONF" compare "$SOURCE_DUMP" "$WORK/mutant-content-size.dump" --expect content
two_class_rc=$CAPTURE_RC
cat "$WORK/expect-two-class.log"
require_refusal_line "$WORK/expect-two-class.log" \
  'CONFORM: FAIL --expect content: a row of class size diverged too — --expect content requires ONLY content divergences' \
  "$two_class_rc" "two-class content mutant control"

capture_all "$WORK/expect-one-class.log" \
  "$GRANCONF" compare "$SOURCE_DUMP" "$WORK/mutant-content.dump" --expect content
one_class_rc=$CAPTURE_RC
cat "$WORK/expect-one-class.log"
require_success_line "$WORK/expect-one-class.log" \
  'CONFORM: PASS --expect content' "$one_class_rc" \
  "one-class content mutant control"

: >"$EMPTY_DUMP"
capture_all "$WORK/expect-dead-mount.log" \
  "$GRANCONF" compare "$SOURCE_DUMP" "$EMPTY_DUMP" --expect presence
dead_mount_rc=$CAPTURE_RC
cat "$WORK/expect-dead-mount.log"
require_refusal_line "$WORK/expect-dead-mount.log" \
  'CONFORM: FAIL --expect presence: zero rows compared EQUAL — a dead or empty mount must not pass this way' \
  "$dead_mount_rc" "dead-mount expect control"

set +e
grep -vF '\xff' "$SOURCE_DUMP" >"$WORK/source-without-ff.dump"
grep_rc=$?
set -e
[ "$grep_rc" -eq 0 ] || die "grep -vF could not construct the byte-0xff verify red"
if ! no_ff_rows="$(line_count "$WORK/source-without-ff.dump")"; then
  die "could not count the byte-0xff verify red"
fi
[ $((SOURCE_ROWS - no_ff_rows)) -eq 1 ] \
  || die "byte-0xff verify red removed $((SOURCE_ROWS - no_ff_rows)) rows, want exactly 1"
capture_all "$WORK/verify-without-ff.log" \
  "$GRANCONF" verify-cases "$WORK/source-without-ff.dump"
verify_red_rc=$CAPTURE_RC
cat "$WORK/verify-without-ff.log"
require_refusal_line "$WORK/verify-without-ff.log" \
  'VERIFY: name-byte-0xff FAIL: no name contains byte 0xff' \
  "$verify_red_rc" "byte-0xff verify control"
diff -u <(print_verify_byte_red) "$WORK/verify-without-ff.log" >/dev/null \
  || die "byte-0xff verify red did not fail only the frozen named case"

capture_all "$WORK/baseline-breakage-refusal.log" \
  "$GRAN" mount --breakage exec-everywhere
baseline_refusal_rc=$CAPTURE_RC
cat "$WORK/baseline-breakage-refusal.log"
require_refusal_line "$WORK/baseline-breakage-refusal.log" \
  'gran mount: unknown flag --breakage' "$baseline_refusal_rc" \
  "feature-off gran breakage control"
[ "$baseline_refusal_rc" -eq 2 ] \
  || die "feature-off gran printed the exact refusal but returned rc=$baseline_refusal_rc, want 2"

run_contract_case \
  $'GRAN_ENDPOINT=a\nGRAN_PIN=b\nGRAN_ROOT_KEY=c\nGRAN_VOLUME=d\nGRAN_VOLUME=e' \
  'CONTRACT: REFUSED line-count' refuse "five-line contract red"
run_contract_case \
  $'GRAN_ENDPOINT=a\nGRAN_PIN=b\nGRAN_ROOT_KEY=c\nGRAN_ROOT_KEY=d' \
  'CONTRACT: REFUSED name-order' refuse "duplicate-name contract red"
run_contract_case \
  $'GRAN_ENDPOINT=a\nGRAN_PIN=b\nGRAN_ROOT_KEY=c\nGRAN_VOLUME=' \
  'CONTRACT: REFUSED assignment-shape' refuse "blank-value contract red"
run_contract_case \
  $'GRAN_ENDPOINT=a\nGRAN_PIN=b\nnot-an-assignment\nGRAN_VOLUME=d' \
  'CONTRACT: REFUSED assignment-shape' refuse "non-assignment contract red"
run_contract_case \
  $'GRAN_ENDPOINT=a\nGRAN_ROOT_KEY=c\nGRAN_PIN=b\nGRAN_VOLUME=d' \
  'CONTRACT: REFUSED name-order' refuse "reordered-name contract red"
run_contract_case \
  $'GRAN_ENDPOINT=a\nGRAN_PIN=b\nGRAN_ROOT_KEY=c\nGRAN_VOLUME=d$(touch /tmp/contract-should-never-exist)' \
  'CONTRACT: REFUSED value-charset' refuse "value-charset contract red"
[ ! -e /tmp/contract-should-never-exist ] \
  || die "the value-charset red's payload EXECUTED -- the contract text is still being evaluated somewhere"
printf '%s\n' 'STATIC-CONTROLS: PASS'

# The trap is armed BEFORE `start`, not after it. teardown_on_exit is safe to run
# against a stack that never came up (it stops what exists and reports), and the
# window between a successful start and a later trap installation is a window in
# which a failure leaks MinIO and the server -- observed once, as
# "MinIO pid 124 is still alive after stop returned".
trap 'rc=$?; teardown_on_exit; s=$?; if [ "$rc" -eq 0 ] && [ "$s" -eq 0 ]; then emit_final; s=$?; fi; trap - EXIT; exit $(( rc != 0 ? rc : s ))' EXIT
stack_contract="$("$STACK" start --source-dir "$SOURCE_DIR" --volume conform --state-dir "$STACK_STATE")"
set +e
real_contract_verdict="$(validate_contract "$stack_contract")"
real_contract_rc=$?
set -e
if [ "$real_contract_verdict" != 'CONTRACT: PASS' ] || [ "$real_contract_rc" -ne 0 ]; then
  printf '%s\n' "$real_contract_verdict"
  # No explicit stop here any more: the EXIT trap above already owns the stack
  # from before it was started, and stopping it twice reports a spurious failure.
  die "real stack contract was refused"
fi

printf '%s\n' "$real_contract_verdict"

GRAN_ENDPOINT=""
GRAN_PIN=""
GRAN_ROOT_KEY=""
GRAN_VOLUME=""
# Direct assignment, no eval. validate_contract has already pinned that there
# are exactly four lines carrying exactly these names in this order, with values
# in a charset that has no shell meaning.
mapfile -t CONTRACT_LINES < <(printf '%s\n' "$stack_contract")
GRAN_ENDPOINT="${CONTRACT_LINES[0]#*=}"
GRAN_PIN="${CONTRACT_LINES[1]#*=}"
GRAN_ROOT_KEY="${CONTRACT_LINES[2]#*=}"
GRAN_VOLUME="${CONTRACT_LINES[3]#*=}"
[ -n "$GRAN_ENDPOINT" ] || die "validated GRAN_ENDPOINT evaluated empty"
[ -n "$GRAN_PIN" ] || die "validated GRAN_PIN evaluated empty"
[ -n "$GRAN_ROOT_KEY" ] || die "validated GRAN_ROOT_KEY evaluated empty"
[ -n "$GRAN_VOLUME" ] || die "validated GRAN_VOLUME evaluated empty"
[ "$GRAN_VOLUME" = conform ] \
  || die "validated GRAN_VOLUME is $GRAN_VOLUME, want conform"

require_sentinel_mappings
launch_mount "$GRAN" "" baseline

dump_tree "$MOUNTPOINT" "$WORK/mount-baseline.dump" "baseline mount"
capture_all "$WORK/compare-baseline.log" \
  "$GRANCONF" compare "$SOURCE_DUMP" "$WORK/mount-baseline.dump"
baseline_compare_rc=$CAPTURE_RC
cat "$WORK/compare-baseline.log"
require_success_line "$WORK/compare-baseline.log" \
  "CONFORM: identical, $SOURCE_ROWS rows" "$baseline_compare_rc" \
  "baseline comparison"

set +e
timeout "$MOUNT_IO_TIMEOUT" find "$MOUNTPOINT" -mindepth 1 \
  -printf '%U\t%G\t%m\t%y\t%A@\t%T@\t%C@\t%p\n' >"$ABSOLUTE_TSV"
find_rc=$?
set -e
[ "$find_rc" -ne 124 ] \
  || die "absolute metadata find exceeded ${MOUNT_IO_TIMEOUT}s -- the mount is wedged"
[ "$find_rc" -eq 0 ] \
  || die "absolute metadata find failed with rc=$find_rc before its row count was read"

run_absolute_case 'ABSOLUTE: FAIL uid' refuse "absolute uid red" \
  "$ABSOLUTE_TSV" "$SOURCE_ROWS" "$GID_SENTINEL" "$GID_SENTINEL" \
  555 444 555 777 "$SOURCE_EXEC_MOUNT_PATH"
run_absolute_case 'ABSOLUTE: FAIL gid' refuse "absolute gid red" \
  "$ABSOLUTE_TSV" "$SOURCE_ROWS" "$UID_SENTINEL" "$UID_SENTINEL" \
  555 444 555 777 "$SOURCE_EXEC_MOUNT_PATH"
run_absolute_case 'ABSOLUTE: FAIL dir-mode' refuse "absolute dir-mode red" \
  "$ABSOLUTE_TSV" "$SOURCE_ROWS" "$UID_SENTINEL" "$GID_SENTINEL" \
  755 444 555 777 "$SOURCE_EXEC_MOUNT_PATH"
run_absolute_case 'ABSOLUTE: FAIL file-mode' refuse "absolute file-mode red" \
  "$ABSOLUTE_TSV" "$SOURCE_ROWS" "$UID_SENTINEL" "$GID_SENTINEL" \
  555 555 555 777 "$SOURCE_EXEC_MOUNT_PATH"
run_absolute_case 'ABSOLUTE: FAIL symlink-mode' refuse "absolute symlink-mode red" \
  "$ABSOLUTE_TSV" "$SOURCE_ROWS" "$UID_SENTINEL" "$GID_SENTINEL" \
  555 444 555 755 "$SOURCE_EXEC_MOUNT_PATH"
# One red per timestamp field, each perturbing the OBSERVATION in the LAST row.
# Three separate cases because a checker comparing only two of the three fields
# passes any single one of them, and the last row because a checker that stops
# after row 1 passes a red aimed at row 1.
for ts_field in 5 6 7; do
  mutate_last_row_field "$ABSOLUTE_TSV" "$WORK/absolute-ts-$ts_field.tsv" \
    "$ts_field" "$SOURCE_ROWS"
  run_absolute_case 'ABSOLUTE: FAIL timestamps' refuse \
    "absolute timestamp red (last row, field $ts_field)" \
    "$WORK/absolute-ts-$ts_field.tsv" "$SOURCE_ROWS" "$UID_SENTINEL" "$GID_SENTINEL" \
    555 444 555 777 "$SOURCE_EXEC_MOUNT_PATH"
done
# The row-count comparison is the clause's own guard against a vacuous pass over
# a single row, and it was the one arm with no red of its own: deleting it left
# every other red and the real pass printing their exact verdicts.
# The cardinality guard had no red either, and it is what pins the capture's
# PROVENANCE -- reading the source tree instead of the mount trips it. Pointing
# it at a path no row carries drives exec_paths to 0. It needs the whole walk,
# so it cannot be satisfied by a checker that stops early.
run_absolute_case 'ABSOLUTE: REFUSED exec-path-cardinality' refuse \
  "absolute exec-path-cardinality red" \
  "$ABSOLUTE_TSV" "$SOURCE_ROWS" "$UID_SENTINEL" "$GID_SENTINEL" \
  555 444 555 777 "/no/row/carries/this/path"
run_absolute_case 'ABSOLUTE: FAIL row-count' refuse "absolute row-count red" \
  "$ABSOLUTE_TSV" "$(( SOURCE_ROWS + 1 ))" "$UID_SENTINEL" "$GID_SENTINEL" \
  555 444 555 777 "$SOURCE_EXEC_MOUNT_PATH"
# An OBSERVATION red rather than an expectation red: the last row's uid is bumped
# in a copy of the capture, so this fires only if the checker actually reads it.
mutate_last_row_field "$ABSOLUTE_TSV" "$WORK/absolute-lastrow-uid.tsv" 1 "$SOURCE_ROWS"
run_absolute_case 'ABSOLUTE: FAIL uid' refuse "absolute last-row uid observation red" \
  "$WORK/absolute-lastrow-uid.tsv" "$SOURCE_ROWS" "$UID_SENTINEL" "$GID_SENTINEL" \
  555 444 555 777 "$SOURCE_EXEC_MOUNT_PATH"
run_absolute_case 'ABSOLUTE: PASS' pass "absolute real pass" \
  "$ABSOLUTE_TSV" "$SOURCE_ROWS" "$UID_SENTINEL" "$GID_SENTINEL" \
  555 444 555 777 "$SOURCE_EXEC_MOUNT_PATH"
printf '%s\n' 'ABSOLUTE-CONTROLS: PASS'

set +e
stop_current_mount baseline
baseline_stop_rc=$?
set -e
[ "$baseline_stop_rc" -eq 0 ] || die "baseline mount teardown failed"

: >"$ROUND_LEDGER"
while read -r breakage class; do
  launch_mount "$GRAN_ARMED" "$breakage" "$breakage"
  dump_tree "$MOUNTPOINT" "$WORK/mount-$breakage.dump" "$breakage mount"
  capture_all "$WORK/compare-$breakage.log" \
    "$GRANCONF" compare "$SOURCE_DUMP" "$WORK/mount-$breakage.dump" --expect "$class"
  round_compare_rc=$CAPTURE_RC
  cat "$WORK/compare-$breakage.log"
  require_success_line "$WORK/compare-$breakage.log" \
    "CONFORM: PASS --expect $class" "$round_compare_rc" \
    "$breakage --expect $class round"
  set +e
  stop_current_mount "$breakage"
  round_stop_rc=$?
  set -e
  [ "$round_stop_rc" -eq 0 ] || die "$breakage mount teardown failed"
  printf 'ROUND %s %s PASS\n' "$breakage" "$class" >>"$ROUND_LEDGER"
done <<'ROUNDS'
truncate-read content
omit-entry presence
exec-everywhere exec
follow-symlink kind
misreport-size size
mangle-symlink-target target
dirent-type-lie dtype
ROUNDS

exit 0
