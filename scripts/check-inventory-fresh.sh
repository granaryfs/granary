#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# Regenerate the dependency inventory and fail if the committed copy was
# stale. Called by .github/workflows/ci.yml (purity job).
#
# The exit-code discipline below distinguishes a clean inventory from a
# `git status` invocation that could not run.
#
# EXIT: 0 fresh, 1 stale, 2 THE CHECK COULD NOT RUN.
set -euo pipefail
cd "$(dirname "$0")/.."

./scripts/dep-inventory.sh

# `test -z "$(git status …)"` is the fail-open shape: a git that cannot run
# hands back an empty string, which reads as "nothing stale" and passes.
# The exit code is the only thing that tells the two apart.
rc=0
dirty=$(git status --porcelain supply-chain/) || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "THE INVENTORY CHECK COULD NOT RUN — it verified NOTHING." >&2
  echo "  \`git status --porcelain supply-chain/\` exited $rc." >&2
  exit 2
fi
if [ -n "$dirty" ]; then
  # `supply-chain/`, not one filename: dep-inventory.sh writes inventory.txt
  # (the shipped graph) AND inventory-fuzz.txt (the four nested fuzz
  # workspaces). Naming only the first sent a reader looking at the wrong
  # file when the second was the one untracked, and an UNTRACKED regenerated
  # file reads as "stale" here, which is the shape that would otherwise be
  # committed without its contents.
  echo "supply-chain/ is stale or carries an untracked file — commit what was regenerated:" >&2
  echo "$dirty" >&2
  exit 1
fi
