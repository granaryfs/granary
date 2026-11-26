#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0

# Shared local/CI lane: armed tests plus source, symbol and release-wall controls.
set -euo pipefail
cd "$(dirname "$0")/.."
# One build job by default, for shared local machines; a general
# CARGO_BUILD_JOBS in the caller's environment does not raise it. CI sets
# GRANARY_OVERLAY_JOBS for its runners.
export CARGO_BUILD_JOBS="${GRANARY_OVERLAY_JOBS:-1}" CARGO_BUILD_WARNINGS=deny
python3 scripts/check-overlay-fault-exclusion.py --self-test
cargo clippy --locked -p granary-client --all-targets --features overlay-fault-tests
cargo clippy --locked -p granary-cli --all-targets --features overlay-fault-tests
cargo clippy --locked -p granary-sim --all-targets --features overlay-fault-tests
cargo clippy --locked -p granary-server --all-targets --features overlay-fault-tests
listing=$(cargo nextest list --locked -p granary-client --features overlay-fault-tests -E 'test(overlay_store::)')
for test_name in crash_and_failure_matrix_has_fired_seams_and_disarmed_controls replacement_crash_matrix_keeps_old_or_complete_new_journal sweep_and_tail_cut_crash_matrix_restarts_idempotently establishment_crash_matrix_never_promotes_temporary_state stage_creation_shrink_and_rollback_crash_matrix; do
  case "$listing" in
    *"overlay_store::tests::$test_name"*) ;;
    *) echo "OVERLAY-FAULT REFUSED: missing armed matrix $test_name" >&2; exit 1 ;;
  esac
done
# Linux-only discard rows must exist before the full client run.
if [[ "$(uname -s)" == Linux ]]; then
  discard_suite='overlay_discard::tests::linux::'
  discard_filter="test($discard_suite)"
  discard_prefix="${discard_suite}discard_refuses_"
  require_discard_rows() {
    local mode=$1 listing row
    shift
    listing=$(cargo nextest list --locked -p granary-client --lib --features overlay-fault-tests --run-ignored "$mode" -E "$discard_filter")
    for row in "$@"; do
      if ! grep -Fxq "granary-client ${discard_prefix}$row" <<<"$listing"; then
        echo "OVERLAY-FAULT REFUSED: missing Linux discard row $row ($mode)" >&2
        exit 1
      fi
    done
    if [[ "$mode" == ignored-only && $(grep -c "^granary-client $discard_suite" <<<"$listing") != "$#" ]]; then
      echo "OVERLAY-FAULT REFUSED: unexpected ignored Linux discard rows" >&2
      exit 1
    fi
  }
  require_discard_rows default empty_destination_race nonempty_destination_race dangling_destination_race foreign_mode granting_posix_acl unpaired_hard_link
  privileged_rows=(foreign_owner mount_crossing)
  require_discard_rows ignored-only "${privileged_rows[@]}"
  if [[ "${GRANARY_REQUIRE_DISCARD_CUSTODY:-}" == 1 ]]; then
    # Only the two privileged fixture rows run as root, with private mounts.
    client_tests=$(cargo nextest list --locked -p granary-client --lib --features overlay-fault-tests --list-type binaries-only --message-format json |
      python3 -c 'import json, sys; print(json.load(sys.stdin)["rust-binaries"]["granary-client"]["binary-path"])')
    privileged_tests=("${privileged_rows[@]/#/$discard_prefix}")
    results=$(sudo --non-interactive unshare --mount --propagation private -- "$client_tests" --ignored --exact --format pretty "${privileged_tests[@]}") || {
      status=$?
      printf '%s\n' "$results" >&2
      exit "$status"
    }
    printf '%s\n' "$results"
    if [[ $(grep -Ec '^test .* \.\.\. ' <<<"$results") != "${#privileged_tests[@]}" ]]; then
      echo "OVERLAY-FAULT REFUSED: expected exactly two privileged discard test results" >&2
      exit 1
    fi
    for test_name in "${privileged_tests[@]}"; do
      if ! grep -Fxq "test $test_name ... ok" <<<"$results"; then
        echo "OVERLAY-FAULT REFUSED: privileged discard test did not pass $test_name" >&2
        exit 1
      fi
    done
  fi
fi
# On macOS the client's durable syncs are F_FULLFSYNC, a full-device flush
# whose latency grows with every process flushing beside it (measured on an
# Apple SSD: 7 ms alone, 14 ms at 4 processes, 27 ms at 16; plain fsync stays
# under 0.1 ms). At one test per core, wall-clock-bounded rows then miss their
# bounds or the ci profile's hard kill: the client suite's rows, and the sim's
# fsync_waits_for_inflight_commit (60 s kill, 9.5 s on Linux CI). At 4 threads
# both suites pass. Linux keeps nextest's default; each subshell keeps the cap
# to its own run, and a caller's smaller positive count stands.
macos_thread_cap() {
  if [ "$(uname -s)" = Darwin ]; then
    case "${NEXTEST_TEST_THREADS:-}" in
      [1-3]) ;;
      *) export NEXTEST_TEST_THREADS=4 ;;
    esac
  fi
}
(
  macos_thread_cap
  cargo nextest run --profile ci --locked -p granary-client --features overlay-fault-tests
)
cargo nextest run --profile ci --locked --no-tests fail -p granary-server --lib --features overlay-fault-tests -E 'test(integration_)'
(
  macos_thread_cap
  cargo nextest run --profile ci --locked -p granary-sim --features overlay-fault-tests --test sync_engine
)
cargo build --release --locked -p granary-client --lib
python3 scripts/check-overlay-fault-exclusion.py target/release/libgranary_client.rlib
cargo build --locked -p granary-client --lib --features overlay-fault-tests
set +e
armed_log=$(python3 scripts/check-overlay-fault-exclusion.py target/debug/libgranary_client.rlib 2>&1)
armed_rc=$?
set -e
if [ "$armed_rc" -ne 1 ]; then
  echo "OVERLAY-FAULT REFUSED: armed artifact did not return exclusion status 1" >&2
  exit 1
fi
case "$armed_log" in
  *'OVERLAY-FAULT REFUSED: arming API present;'*) ;;
  *) echo "$armed_log" >&2; exit 1 ;;
esac
set +e
wall_log=$(cargo build --release --locked -p granary-client --features overlay-fault-tests 2>&1)
wall_rc=$?
set -e
if [ "$wall_rc" -eq 0 ]; then
  echo "OVERLAY-FAULT REFUSED: feature-on release build succeeded" >&2
  exit 1
fi
case "$wall_log" in
  *'overlay-fault-tests must not compile into a release artifact'*) ;;
  *) echo "$wall_log" >&2; exit 1 ;;
esac
echo "OVERLAY-FAULT PASS: armed matrices, shipping symbols and release wall"
