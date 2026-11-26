#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# Sample the measurement NODE's CPU for the duration of a propagation
# run, and write the file `m10-propagate.sh --node-samples` consumes.
#
# Run the sampler from the benchmark driver. The driver
# reaches the workload guest and its host over SSH. It
# starts the workload in the guest and opens a separate
# connection to the host for CPU samples. A firewall that
# blocks direct access from the guest to its host leaves
# both driver connections available.
#
#
# This samples the NODE's CPU rather than the guest's because the contention
# the re-run rule guards against is other VMs on the same host, which is exactly
# what is invisible from inside a guest.
#
#   m10-node-sample.sh <ssh-destination> <seconds> <out-file> [ssh-opts...]
#
# Writes one `<UTC>\t<percent>` line every 10 s. The stamp is the interval's
# END, because a /proc/stat sample summarises the interval PRECEDING it and
# which end the stamp names decides whether boundary load is counted in or out.
#
# The harness REFUSES the file unless it brackets the run, holds at least
# floor(duration/10) samples, has strictly increasing stamps and no gap over
# 15 s -- so start this BEFORE the run and stop it AFTER.
set -euo pipefail

DEST="${1:-}"; SECONDS_TOTAL="${2:-}"; OUT="${3:-}"
shift 3 2>/dev/null || { echo "usage: m10-node-sample.sh <ssh-dest> <seconds> <out-file> [ssh-opts...]" >&2; exit 2; }
[ -n "$DEST" ] && [ -n "$SECONDS_TOTAL" ] && [ -n "$OUT" ] \
  || { echo "usage: m10-node-sample.sh <ssh-dest> <seconds> <out-file> [ssh-opts...]" >&2; exit 2; }
case "$SECONDS_TOTAL" in ''|*[!0-9]*) echo "m10-node-sample: seconds must be a positive integer" >&2; exit 2 ;; esac
# NORMALISED TO BASE TEN BEFORE ANY ARITHMETIC, and this is not tidiness.
# `test -ge` parses in base ten and `$(( ))` parses a LEADING ZERO AS OCTAL, so
# `020` passed the floor below as twenty and then computed `020 / 10` as ONE:
# the sampler stopped after 10 s, wrote one line, and reported success against
# its own wrong arithmetic. The one `10#` here fixes both the floor's units and
# the round count, because everything downstream reads this variable.
SECONDS_TOTAL=$((10#$SECONDS_TOTAL))
[ "$SECONDS_TOTAL" -ge 10 ] || { echo "m10-node-sample: seconds must be at least 10" >&2; exit 2; }

# REACHABILITY FIRST, and named as reachability. The same fail-open the venue
# provisioner had: without this, a connection failure looks like a fact about
# the node.
PROBE="$(ssh -o BatchMode=yes -o ConnectTimeout=15 "$@" "$DEST" 'echo m10-node-reachable' 2>&1 || true)"
case "$PROBE" in
  *m10-node-reachable*) ;;
  *) echo "m10-node-sample: refused -- could not reach $DEST. This says nothing about its load; fix the connection. ssh said: $PROBE" >&2; exit 1 ;;
esac

ROUNDS=$(( SECONDS_TOTAL / 10 ))
echo "m10-node-sample: sampling $DEST every 10s for ${SECONDS_TOTAL}s ($ROUNDS samples) -> $OUT" >&2

# ONE ssh session for the whole run, not one per sample: a per-sample connection
# would put its own handshake cost on the node being measured, and a dropped
# connection mid-run would leave a gap the harness then refuses.
ssh -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=30 "$@" "$DEST" "
  for _ in \$(seq 1 $ROUNDS); do
    read -r _ u n s idle io irq soft st _ < /proc/stat
    t1=\$((u+n+s+idle+io+irq+soft+st)); i1=\$idle
    sleep 10
    read -r _ u n s idle io irq soft st _ < /proc/stat
    t2=\$((u+n+s+idle+io+irq+soft+st)); i2=\$idle
    dt=\$((t2-t1)); di=\$((i2-i1))
    if [ \"\$dt\" -gt 0 ]; then
      awk -v dt=\"\$dt\" -v di=\"\$di\" 'BEGIN{printf \"%s\t%.1f\n\", strftime(\"%Y-%m-%dT%H:%M:%S.000Z\", systime(), 1), 100*(dt-di)/dt}'
    else
      echo \"m10-node-sample: /proc/stat did not advance; refusing to invent a sample\" >&2
      exit 1
    fi
  done
" > "$OUT"

LINES="$(wc -l < "$OUT" | tr -d ' ')"
[ "$LINES" -eq "$ROUNDS" ] \
  || { echo "m10-node-sample: wrote $LINES samples, wanted $ROUNDS -- the harness will refuse this file, so it is refused here where the cause is visible" >&2; exit 1; }
echo "m10-node-sample: $LINES samples -> $OUT" >&2
