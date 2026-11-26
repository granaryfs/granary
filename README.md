<!-- SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Granary

Granary is a distributed filesystem for software distribution. It uses a global
namespace and content-addressed storage. A publish makes a complete version of
a tree available atomically. Clients can mount a version through FUSE on Linux.

Granary takes inspiration from AFS.

**Status:** Pre-release. Build from source to try it. The command line, on-disk
formats and wire protocol may change.

## Layout

| crate | what it does | licence |
|---|---|---|
| `granary-core` | pure logic — formats, chunking, protocol types. No I/O, no tokio, no clocks | Apache-2.0 |
| `granary-vfs` | the portable manifest-reading engine: snapshot indexing, grain reads, attribute construction (`no_std`) | Apache-2.0 |
| `granary-cli` | the `gran` command-line binary — a thin shell over `granary-client` | Apache-2.0 |
| `granary-client` | the client library: publish, harvest, resolve, cache, mount sessions | Apache-2.0 |
| `granary-fuse` | the FUSE shim (Linux) | Apache-2.0 |
| `granary-net` | HTTP transport plumbing and TLS configuration for both sides | Apache-2.0 |
| `granary-store` | object-store adapters — bins and the root CAS | Apache-2.0 |
| `granary-server` | verify-ingest, serve, CAS | **AGPL-3.0-or-later** |
| `granary-bench`, `granary-conformance`, `granary-sim` | the dedup benchmark harness, the differential oracle for the FUSE reader, and the deterministic simulator | Apache-2.0 |

The server is AGPL-3.0-or-later. The client and shared crates are Apache-2.0.
Each file's SPDX identifier states its licence. See
[LICENSING.md](LICENSING.md) and the
[licensing rationale](docs/licensing-rationale.md).

## Try the CLI

Install Rust with rustup. The checkout selects the pinned toolchain.

```sh
cargo run --locked -p granary-cli -- thresh README.md
```

The command prints the content identifier and length of each chunk in the file.
It runs locally without a server.

The mount needs Linux with access to `/dev/fuse`. For unprivileged mounts,
install the FUSE mount helper (`fusermount3` on systems with the `fuse3` package).
The Linux build uses the pure-Rust FUSE backend and needs no libfuse C library. See
[development setup](docs/dev-environment.md),
[operating a mount](docs/operating-a-mount.md), and the
[documentation index](docs/README.md).

## Contributing

Run the [local checks](CONTRIBUTING.md#run-the-local-checks) to test a change.
The [contributor guide](CONTRIBUTING.md) covers pull requests, review and sign-offs.
To use the [issue forms](.github/ISSUE_TEMPLATE), open **Issues** in this
repository and select **New issue**. Open a design proposal before changing an
on-disk format or the wire protocol so we can discuss compatibility. Read the
[dependency policy](docs/dependency-policy.md) before adding a dependency.
Report vulnerabilities through the [security policy](SECURITY.md).
