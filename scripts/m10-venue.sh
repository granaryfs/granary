#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# Prepare a RHEL 9-class benchmark guest for scripts/m10-propagate.sh.
# Build Granary on the guest with the pinned Rust toolchain. The standard
# Linux container builds against glibc 2.41, and the guest uses glibc 2.34.
# The guest build links against the glibc version available at runtime.
#
#   scripts/m10-venue.sh provision [ssh-opts...] <ssh-destination>
#   scripts/m10-venue.sh check     [ssh-opts...] <ssh-destination>
#
#     --from-head   ship the tree at HEAD instead of the working tree. Use
#                   this for a MEASUREMENT run: the shipped bytes are then a
#                   commit, and the digest printed below pins them. The
#                   archive is gzipped with `-n` so the same commit yields
#                   the same digest.
#     --remote-dir  where the source lands (default: granary, under $HOME)
#
# Pass ssh options before the destination. For example, use `-J` for a
# jump host or `-i` for an identity file.
#
#   scripts/m10-venue.sh provision -J jump.example.org build@runner.example.org
#
# WHAT IT REFUSES, because a provisioner that cannot fail is not a gate:
#   * a non-dnf guest (named refusal, not a silent skip -- the package set
#     below is RHEL-family and this script does not pretend otherwise);
#   * a guest whose installed rustc is not rust-toolchain.toml's channel. NOTE,
#     stated rather than claimed: this one is DEFENCE IN DEPTH and is not
#     reachable as the code stands, because rustup installs the channel by name
#     and `rustc +<channel> -V` cannot then report a different one. It is kept
#     because the failure it guards is silent at the BUILD, not here. Its
#     refusal has never fired and this comment says so instead of letting a
#     reader count it as an exercised gate;
#   * a binary that does not EXECUTE on the guest. `+x` is a mode bit; a
#     wrong-architecture file keeps it and fails at exec(2). Both probes
#     demand a diagnostic only that binary emits, the same way
#     stack.sh:344-382 does.
#
# Refusal checks recorded on 2026-09-09:
#   * unreachable venue -- EXERCISED. `provision ... nobody@10.255.255.1` →
#     rc 1, "could not reach the venue over ssh ... This says NOTHING about
#     the guest". This check exists BECAUSE its absence was a fail-open: the
#     dnf probe alone reported "the venue has no dnf" when the real cause was
#     a mangled ssh option.
#   * wrong-architecture binary -- EXERCISED. A macOS Mach-O `gran` planted at
#     target/release/gran on an aarch64 guest → rc 1, "did not print gran's
#     usage banner: ... cannot execute binary file: Exec format error".
#   * no dnf -- NOT EXERCISED, and said here rather than left to be assumed.
#     No reachable RHEL-family-less venue was available to point it at; Fedora
#     CoreOS, the obvious candidate, ships dnf and instead failed at the
#     install (`bootc ... read-only`, rc 1 -- fail-closed, with dnf's own
#     message, which is the better diagnostic anyway). Treat this refusal as
#     unproven until something has run it.
set -euo pipefail
cd "$(dirname "$0")/.."

# Install strace for manual FUSE diagnostics. The harness measures file
# availability and leaves strace to the operator. Counting FUSE operations
# would require decoding opcodes because one read can carry a batch of replies.
PACKAGES="fuse3 gcc perl-Digest-SHA strace"
REMOTE_DIR="granary"
FROM_HEAD=0
MODE="${1:-}"
shift || true

case "$MODE" in
  provision|check) ;;
  *) echo "usage: m10-venue.sh provision|check [--from-head] [--remote-dir D] [ssh-opts] <dest>" >&2; exit 2 ;;
esac

SSH_ARGS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --from-head) FROM_HEAD=1; shift ;;
    --remote-dir) [ "$#" -ge 2 ] || { echo "m10-venue: --remote-dir needs a value" >&2; exit 2; }
                  REMOTE_DIR="$2"; shift 2 ;;
    *) SSH_ARGS+=("$1"); shift ;;
  esac
done
[ "${#SSH_ARGS[@]}" -ge 1 ] || { echo "m10-venue: no ssh destination given" >&2; exit 2; }

# The channel is READ, never retyped: a second copy of a pinned version is a
# second thing to drift.
CHANNEL="$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' rust-toolchain.toml)"
[ -n "$CHANNEL" ] || { echo "m10-venue: could not read the channel from rust-toolchain.toml" >&2; exit 1; }

on_venue() { ssh -o BatchMode=yes -o ConnectTimeout=20 "${SSH_ARGS[@]}" "$@"; }

banner() { echo "== m10-venue: $*"; }

banner "target $(printf '%s ' "${SSH_ARGS[@]}")-- channel $CHANNEL"

# REACHABILITY FIRST, and it is separate from every fact about the venue.
# The dnf probe below, run alone, can report "the venue has no dnf" when the
# real cause is ssh failing -- a mangled ssh option or a transient connection
# failure: `command -v dnf` inherits ssh's non-zero status, and the connection
# failure reads as a settled fact about the guest. So the first
# thing asked of a venue is a sentinel only a working shell can echo, and a
# failure here is named as a failure to REACH.
PROBE="$(on_venue 'echo m10-venue-reachable' 2>&1 || true)"
case "$PROBE" in
  *m10-venue-reachable*) ;;
  *) echo "m10-venue: refused -- could not reach the venue over ssh. This says NOTHING about the guest; fix the connection first. ssh said: $PROBE" >&2
     exit 1 ;;
esac

if ! on_venue 'command -v dnf >/dev/null 2>&1'; then
  echo "m10-venue: refused -- the venue is reachable but has no dnf. The package set ($PACKAGES) is RHEL-family; port it deliberately rather than letting this script half-run." >&2
  exit 1
fi

if [ "$MODE" = "check" ]; then
  PROBE="$(on_venue 'echo m10-venue-reachable' 2>&1 || true)"
  case "$PROBE" in
    *m10-venue-reachable*) ;;
    *) echo "m10-venue: refused -- could not reach the venue over ssh. ssh said: $PROBE" >&2; exit 1 ;;
  esac
  on_venue "cd '$REMOTE_DIR' 2>/dev/null || { echo 'm10-venue: no source at ~/$REMOTE_DIR'; exit 1; }
    echo \"arch \$(uname -m)  \$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release)\"
    echo \"glibc \$(ldd --version | sed -n '1s/.*) //p')\"
    for b in target/release/gran target/release/granary-server target/debug/gran target/debug/granary-server; do
      if [ -x \"\$b\" ]; then echo \"present \$b (\$(stat -c %s \"\$b\") bytes)\"; else echo \"MISSING \$b\"; fi
    done"
  exit 0
fi

banner "packages"
on_venue "sudo dnf install -y -q $PACKAGES >/dev/null" 
# ONE `command -v` PER TOOL, because `command -v a b c` exits 0 when ANY of the
# names resolves -- verified in bash: `command -v gcc nosuchtool` returns 0. The
# single-call form could not fail unless EVERY tool was missing, so the check
# that was supposed to prove `strace` had arrived would have passed with it
# absent.
on_venue 'rc=0; for t in gcc fusermount3 shasum strace; do command -v "$t" >/dev/null 2>&1 || { echo "MISSING $t"; rc=1; }; done; exit $rc' \
  || { echo "m10-venue: refused -- a required tool is still absent after the install (named above)" >&2; exit 1; }

banner "toolchain $CHANNEL"
on_venue "set -e
  if [ ! -x \"\$HOME/.cargo/bin/rustup\" ]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh
    sh /tmp/rustup-init.sh -y --no-modify-path --default-toolchain none >/dev/null
  fi
  \"\$HOME/.cargo/bin/rustup\" toolchain install '$CHANNEL' --profile minimal >/dev/null 2>&1"
GOT="$(on_venue "\"\$HOME/.cargo/bin/rustc\" +$CHANNEL -V")"
case "$GOT" in
  "rustc $CHANNEL "*) banner "toolchain ok: $GOT" ;;
  *) echo "m10-venue: refused -- the venue reports '$GOT', which is not rust-toolchain.toml's $CHANNEL" >&2; exit 1 ;;
esac

banner "source"
TARBALL="$(mktemp -t m10-venue-src)"
trap 'rm -f "$TARBALL"' EXIT
if [ "$FROM_HEAD" -eq 1 ]; then
  SOURCE_LABEL="HEAD $(git rev-parse HEAD)"
  # `gzip -n`, not `gzip`: gzip stamps the CURRENT TIME into its header, so
  # without it two provisionings of the SAME commit print DIFFERENT digests
  # and the "the digest pins them" claim in this file's header is false --
  # a reader comparing two venues provisioned seconds apart would conclude
  # different content shipped. Measured 2026-09-11: `gzip -1` twice, two
  # seconds apart, differs; `gzip -n1` is byte-identical. The digest is a
  # LABEL (nothing compares it on the guest), so this makes the label
  # honest rather than adding a gate.
  git archive --format=tar HEAD | gzip -n1 > "$TARBALL"
else
  SOURCE_LABEL="WORKING TREE (tracked files; NOT a commit)"
  git ls-files -z | COPYFILE_DISABLE=1 tar cf - --no-xattrs --null -T - | gzip -n1 > "$TARBALL"
fi
DIGEST="$(shasum -a 256 "$TARBALL" | cut -d' ' -f1)"
banner "shipping $SOURCE_LABEL"
banner "tarball sha256 $DIGEST"
on_venue "rm -rf '$REMOTE_DIR' && mkdir -p '$REMOTE_DIR'" 
on_venue "tar xzf - -C '$REMOTE_DIR'" < "$TARBALL"

banner "build (release and debug are SEPARATE invocations)"
# `cargo build -p a --bin x -p b` applies --bin to the whole invocation and
# silently builds only x: a provisioning run built that way produced `gran`
# and no `granary-server`, with rc=0.
on_venue "cd '$REMOTE_DIR' && export PATH=\"\$HOME/.cargo/bin:\$PATH\" &&
  cargo build --release -p granary-cli --bin gran >/dev/null 2>&1 &&
  cargo build --release -p granary-server --bin granary-server >/dev/null 2>&1 &&
  cargo build -p granary-cli --bin gran >/dev/null 2>&1 &&
  cargo build -p granary-server --bin granary-server >/dev/null 2>&1"

banner "execution probes"
on_venue "cd '$REMOTE_DIR'
  for p in release debug; do
    out=\"\$(./target/\$p/gran --version 2>&1 || true)\"
    case \"\$out\" in *'usage: gran '*) ;; *) echo \"m10-venue: refused -- target/\$p/gran did not print gran's usage banner: \$out\" >&2; exit 1 ;; esac
    out=\"\$(env -u GRANARY_LISTEN GRANARY_STORE=probe GRANARY_STORE_BUCKET=probe GRANARY_STORE_ENDPOINT=probe GRANARY_STORE_REGION=probe AWS_ACCESS_KEY_ID=probe AWS_SECRET_ACCESS_KEY=probe GRANARY_TLS_CERT=probe GRANARY_TLS_KEY=probe ./target/\$p/granary-server 2>&1 || true)\"
    case \"\$out\" in *'startup failed: GRANARY_LISTEN:'*) ;; *) echo \"m10-venue: refused -- target/\$p/granary-server did not print its GRANARY_LISTEN startup refusal: \$out\" >&2; exit 1 ;; esac
  done"

banner "minio"
on_venue "cd '$REMOTE_DIR' && ./scripts/minio-harness.sh ensure 2>&1 | tail -1"

banner "PROVISIONED  source=$SOURCE_LABEL  sha256=$DIGEST"
