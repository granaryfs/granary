#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
if [[ "$#" -ne 0 ]]; then
  echo 'usage: scripts/publish-restart.sh (from the repository root)' >&2
  exit 2
fi
# Real authority evidence requires supported Linux storage; the controlled-peer
# restart suite also runs natively before provisioning the Linux venue.
restart_platform="$(uname -s)"
if [[ "$restart_platform" == Linux ]]; then
  python3 scripts/check-publish-restart.py venue
fi
restart_target_dir="${CARGO_TARGET_DIR:-target}"
if [[ "$restart_target_dir" != /* ]]; then
  restart_target_dir="$PWD/$restart_target_dir"
fi
export CARGO_TARGET_DIR="$restart_target_dir"
if [[ "$restart_platform" == Linux ]]; then
  scripts/minio-harness.sh ensure
  GRANARY_COMPOSITION_MINIO="$PWD/$(scripts/minio-harness.sh path)"
  export GRANARY_COMPOSITION_MINIO
fi
python3 scripts/check-publish-restart.py self-test
python3 scripts/check-publish-restart.py graph
python3 scripts/check-publish-restart.py walls
export GRANARY_SHIPPING_GRAN="$CARGO_TARGET_DIR/publish-restart-shipping/release/gran"
export GRANARY_SHIPPING_SERVER="$CARGO_TARGET_DIR/publish-restart-shipping/release/granary-server"
CARGO_BUILD_WARNINGS=deny cargo clippy --locked -p granary-cli -p granary-client -p granary-server --all-targets \
  --features granary-cli/publish-restart-tests,granary-server/publish-restart-tests,granary-server/crash-points
cargo build --locked -p granary-cli --bin gran --features publish-restart-tests --target-dir "$CARGO_TARGET_DIR/publish-restart-armed"
python3 scripts/check-publish-restart.py armed-control "$CARGO_TARGET_DIR/publish-restart-armed/debug/gran"
cargo build --locked -p granary-server --bin granary-server --features crash-points
python3 scripts/check-publish-restart.py armed-control "$CARGO_TARGET_DIR/debug/granary-server"
# Fresh reports cannot be inherited from a previous successful run.
reports=$(mktemp -d "$CARGO_TARGET_DIR/publish-restart-report.XXXXXX")
trap 'rm -rf "$reports"' EXIT
cargo nextest list --locked -p granary-client --lib --features publish-restart-tests \
  --message-format json > "$reports/client-selection.json"
python3 scripts/check-publish-restart.py client-selection "$reports/client-selection.json"
rm "$reports/client-selection.json"
cargo nextest run --locked -p granary-client --lib --features publish-restart-tests \
  --profile ci --success-output=final
cargo nextest list --locked -p granary-cli --bin gran --features publish-restart-tests \
  -E 'test(publication::) | test(publication_report::)' \
  --message-format json > "$reports/cli-selection.json"
python3 scripts/check-publish-restart.py cli-selection "$reports/cli-selection.json"
rm "$reports/cli-selection.json"
# Winner repair and the terminal writer have socket-free guard controls too.
cargo nextest run --locked -p granary-cli --bin gran --features publish-restart-tests \
  -E 'test(publication::) | test(publication_report::)' \
  --profile ci --success-output=final
export GRANARY_RESTART_GRAN="$CARGO_TARGET_DIR/publish-restart-armed/debug/gran"
export GRANARY_RESTART_REPORT_DIR="$reports"
GRANARY_RESTART_RUN="$(python3 -c 'import uuid; print(uuid.uuid4())')"
export GRANARY_RESTART_RUN
printf 'EVIDENCE revision=%s date=%s os=%s kernel=%s run=%s\n' "$(git rev-parse HEAD)" "$(date -u +%FT%TZ)" "$(uname -s)" "$(uname -r)" "$GRANARY_RESTART_RUN"
cargo nextest list --locked -p granary-server --features publish-restart-tests,crash-points \
  --test publish_restart --message-format json > "$reports/selection.json"
python3 scripts/check-publish-restart.py selection "$reports/selection.json"
rm "$reports/selection.json"
cargo nextest run --locked -p granary-server --features publish-restart-tests,crash-points \
  --test publish_restart --profile ci --success-output=final
python3 scripts/check-publish-restart.py coverage "$reports"
# Reuse the existing second-publisher wedge proof against the ordinary gran.
cargo nextest list --locked -p granary-server --features crash-points \
  --test authority_host -E 'test(=shipping_local_abandonment_does_not_release_a_wedged_authority)' \
  --message-format json > "$reports/authority-selection.json"
python3 scripts/check-publish-restart.py authority-selection "$reports/authority-selection.json"
rm "$reports/authority-selection.json"
cargo nextest run --locked -p granary-server --features crash-points \
  --test authority_host -E 'test(=shipping_local_abandonment_does_not_release_a_wedged_authority)' \
  --profile ci --success-output=final
if [[ "$restart_platform" != Linux ]]; then
  scripts/authority-venue.sh --publish-restart
fi
