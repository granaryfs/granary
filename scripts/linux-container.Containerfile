# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# Builds and runs granary's Linux-only code (crates/granary-fuse, and the
# cfg(target_os = "linux") paths in crates/granary-client) for
# scripts/linux-container.sh. See that script's header for the loop this closes and
# docs/dev-environment.md's "The Linux loop" for the operator-facing version.

# Matches rust-toolchain.toml's channel exactly (measured 2026-09-01:
# docker.io/library/rust:1.97.1 is Debian trixie, glibc 2.41, and `rustc -V`
# names the same 1.97.1 channel this repo pins) — so a container build uses
# the identical toolchain CI and the macOS host use, never a silently
# different one.
FROM docker.io/library/rust:1.97.1

# fuse3: ships /usr/bin/fusermount3 (setuid root), which granary-fuse's mount
#   path and its unmount fallback tests (crates/granary-fuse/src/unmount.rs)
#   need. Measured: no libfuse dev headers are required — the `fuser` crate
#   talks to /dev/fuse directly and only shells out to the fusermount3
#   binary, so `fuse3` alone (no `libfuse3-dev`) is sufficient.
# ca-certificates: TLS roots, needed both for the nextest download below and
#   for any cargo registry fetch during `build`/`test`.
# curl: fetches the cargo-nextest release archive below.
# strace: the authority log adapter's syscall trace on ext4
#   (scripts/authority-venue.sh); the podman VM has none.
# iproute2: the Q3 venue creates its isolated veth and applies netem with ip/tc.
# iputils-ping: the Q3 venue calibrates each configured RTT from the client netns.
# ethtool: the Q3 venue disables and records veth segmentation offloads.
# e2fsprogs: mkfs.ext4 formats the Q3 recovery pair's replacement loop image.
# --no-install-recommends + the apt-lists cleanup: keep the image small;
#   nothing here needs apt's recommended extras.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        fuse3 \
        ca-certificates \
        curl \
        e2fsprogs \
        ethtool \
        iproute2 \
        iputils-ping \
        strace \
    && rm -rf /var/lib/apt/lists/*

# cargo-nextest 0.9.143, pinned to the exact version
# .github/workflows/ci.yml installs (grep that file for `cargo-nextest@` to
# reconfirm) — a drifted local nextest is exactly the kind of local-vs-CI
# divergence docs/dev-environment.md warns against. `linux-arm` because the
# podman machine backing this image is native aarch64 (Apple Silicon host,
# no emulation).
#
# `curl ... | tar zxf -` records TAR's exit status, not curl's — a
# truncated transfer (network drop mid-download) can still let tar report
# success on whatever partial bytes it got. Download to a file and check
# curl's own status first, then extract, so a truncated transfer fails the
# build instead of silently shipping a corrupt or partial nextest binary.
#
# No checksum or signature was verified here before, and the binary this
# downloads is then run in the privileged container-root lane (and, copied
# onto the shared target dir, through `sudo` in the bare VM too) — CI's own
# `taiki-e/install-action` verifies this download, so this build must too.
# SHA256 measured directly 2026-09-01 (downloaded twice, byte-identical
# both times) against https://get.nexte.st/0.9.143/linux-arm, which 302s to
# https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-0.9.143/cargo-nextest-0.9.143-aarch64-unknown-linux-gnu.tar.gz
# -- get.nexte.st ships no published .sha256/.sha512 sidecar to check this
# against, so this pin IS the checksum's source of truth; re-measure with
# `curl -LsSf https://get.nexte.st/<version>/linux-arm | sha256sum` before
# ever bumping the version above.
RUN curl -LsSf -o /tmp/cargo-nextest.tar.gz https://get.nexte.st/0.9.143/linux-arm \
    && echo "2a64b3566a92508550a7ab29c3e8db25472ca37730ecb4d22100b6aa440c2a68  /tmp/cargo-nextest.tar.gz" | sha256sum -c - \
    && tar zxf /tmp/cargo-nextest.tar.gz -C /usr/local/cargo/bin \
    && rm -f /tmp/cargo-nextest.tar.gz

# rust-toolchain.toml's channel is already the base image's default (measured
# 2026-09-01: both name 1.97.1), but the base image ships only
# rustc/cargo/rust-std — not the rustfmt/clippy/rust-src components the
# toolchain file also requests. Left unbaked, rustup silently fetches those
# three from the network on the FIRST cargo invocation inside every single
# `podman run --rm` (measured: every invocation, because RUSTUP_HOME lives in
# the container's own ephemeral filesystem, never on the shared target dir).
# Installing them here, once, at image-build time removes that repeated
# network dependency from every build/test/self-test run.
RUN rustup component add rustfmt clippy rust-src
