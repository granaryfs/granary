# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# Shared by scripts/check-vfs-purity.sh and scripts/check-vfs-deps.sh
# because both scripts extract the workspace's edition and
# rust-version and build an otherwise IDENTICAL scratch single-member
# workspace manifest pair for their self-test fixtures — a
# granary-vfs-shaped package depending on the real granary-core by
# absolute path, wrapped in its own `[workspace]`. That text had drifted
# into two copies with nothing to notice a future edit landing in only
# one of them — the same drift risk that
# `check_tree_flags_match_core` tripwire exists to catch for a
# DIFFERENT pair of constants (check-core-purity.sh's own `cargo tree`
# flags). Rather than add a second tripwire for a second duplication,
# this factors the shared text into one place so there is nothing left
# to drift.
#
# SOURCED, not executed: no shebang, and it must never itself `set -e`
# or `cd` — either would apply to whichever caller sources it, silently
# changing that script's own error-handling mid-file.

# vfs_ws_edition_and_rust_version — reads the workspace root Cargo.toml
# and sets WS_EDITION / WS_RUST_VERSION in the CALLER's scope (no
# `local` here, deliberately — bash function scoping means an
# unqualified assignment inside a sourced function is visible to
# whatever sources it, the mirror of how a caller's `local` stays
# invisible to a function it calls). Refuses — exit 2, the house idiom
# for an input this scanner cannot read — if either comes back empty,
# rather than handing a caller a scratch fixture built from a blank
# edition or rust-version.
vfs_ws_edition_and_rust_version() {
  WS_EDITION="$(sed -n 's/^edition = "\(.*\)"/\1/p' Cargo.toml | head -1)"
  WS_RUST_VERSION="$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
  if [[ -z "$WS_EDITION" || -z "$WS_RUST_VERSION" ]]; then
    echo "vfs-scratch-fixture: could not read edition/rust-version from the workspace Cargo.toml — refused, never treated as clean" >&2
    exit 2
  fi
}

# vfs_workspace_lints_toml — prints the real workspace root Cargo.toml's
# own `[workspace.lints.*]` tables VERBATIM, read fresh
# on every call rather than duplicated by hand into this file — a
# hand-typed second copy would itself be exactly the drift risk this
# whole file exists to close for the manifest text around it. Requires
# cwd to be the repo root (every caller of this file already `cd`s
# there). Refuses — prints nothing on stdout, exit 2 — if no
# `[workspace.lints` section is found at all, rather than silently
# handing back an empty (and so unlicensed) table.
#
# Collects EVERY `[workspace.lints*]` section wherever it appears in the
# file, not merely the first contiguous run: a
# `[profile.*]` or other table interleaved between
# `[workspace.lints.rust]` and `[workspace.lints.clippy]` must not end
# the scan at the first non-lints header: that silently copies only a
# PARTIAL lint set while still exiting 0 — fixtures would then compile
# under a strictly weaker lint configuration than the tracked crate, the
# exact defect this function's own header says it closes. Asserts the number
# of `[workspace.lints...]` headers copied equals the number present in
# the source, so a partial copy refuses (exit 2) instead of passing.
vfs_workspace_lints_toml() {
  python3 - <<'PYEOF'
import sys

lines = open("Cargo.toml", encoding="utf-8").readlines()
total_headers = sum(1 for line in lines if line.startswith("[workspace.lints"))
if total_headers == 0:
    print("could not find a [workspace.lints...] section in the workspace Cargo.toml", file=sys.stderr)
    sys.exit(2)

out = []
copied_headers = 0
in_section = False
for line in lines:
    if line.startswith("[workspace.lints"):
        in_section = True
        copied_headers += 1
    elif line.startswith("["):
        in_section = False
    if in_section:
        out.append(line)

if copied_headers != total_headers:
    print(
        f"copied {copied_headers} of {total_headers} [workspace.lints...] sections from the "
        "workspace Cargo.toml — a partial copy would compile fixtures under a weaker lint set "
        "than the tracked crate",
        file=sys.stderr,
    )
    sys.exit(2)
sys.stdout.write("".join(out))
PYEOF
}

# vfs_write_scratch_manifests <root> — writes <root>/Cargo.toml (the
# wrapping single-member `[workspace]`, carrying a VERBATIM copy of the
# real workspace's own `[workspace.lints.*]` tables) and
# <root>/vfscopy/Cargo.toml (a granary-vfs-shaped package depending on
# the real granary-core by absolute path, with `[lints] workspace =
# true`). Requires WS_EDITION/WS_RUST_VERSION already set (call
# vfs_ws_edition_and_rust_version first) and `<root>/vfscopy/` to
# already exist.
#
# `[lints] workspace = true` on the PACKAGE makes a
# fixture compile under the SAME lint configuration as the tracked
# crate — without it, the `bite-absent` control's "the IDENTICAL source
# compiles at rc=0" claim was true only of a crate the workspace
# `[lints]` table does not govern. `workspace = true` needs somewhere to
# inherit FROM, which is why the wrapping `[workspace]` manifest carries
# its own `[workspace.lints.*]` copy — a scratch workspace with no such
# table makes `cargo` refuse every fixture with "workspace.lints was not
# defined" before this gate's own logic ever runs.
#
# `[dependencies]` is deliberately the LAST section in the PACKAGE
# manifest, not `[lints]`: several self-test controls in both callers
# `>>`-append a bare `name = { path = "..." }` line (a second
# dependency, a feature-gated one, …) straight onto the end of the file
# with no section header of its own — TOML attributes a header-less
# line to whichever table was declared last, so `[dependencies]` must
# stay last or those appends would silently land inside `[lints]`
# instead.
vfs_write_scratch_manifests() {
  local root="$1" lints_toml
  lints_toml="$(vfs_workspace_lints_toml)" || {
    echo "vfs-scratch-fixture: could not extract the workspace's [workspace.lints] table — refused, never treated as clean" >&2
    exit 2
  }
  cat > "$root/Cargo.toml" <<EOF
[workspace]
members = ["vfscopy"]
resolver = "3"

$lints_toml
EOF
  cat > "$root/vfscopy/Cargo.toml" <<EOF
[package]
name = "granary-vfs"
version = "0.0.1"
edition = "$WS_EDITION"
rust-version = "$WS_RUST_VERSION"
license = "Apache-2.0"
publish = false

[lints]
workspace = true

[dependencies]
granary-core = { path = "$(pwd)/crates/granary-core" }
EOF
}
