# Licensing

Granary is split-licensed. Which licence applies depends on which component you
are using.

| Component | Licence | File |
|---|---|---|
| `granary-core` and all client crates | Apache-2.0 | [LICENSE-APACHE](LICENSE-APACHE) |
| `granary-cli` (the `gran` binary) and `granary-client` (the client library) | Apache-2.0 | [LICENSE-APACHE](LICENSE-APACHE) |
| `granary-server` | AGPL-3.0-or-later | [LICENSE-AGPL](LICENSE-AGPL) |

Every source file carries an SPDX identifier. That identifier is authoritative
for the file; this table is a summary.

The root contains the [Apache-2.0](LICENSE-APACHE) and [AGPL-3.0](LICENSE-AGPL)
texts. `LICENSES/` holds SPDX-named copies for `reuse lint`. Crates that
carry their own `LICENSE` keep a regular copy so packaging can include it
from the crate directory.

## What this means in practice

**If you mount a Granary filesystem**, the client components are covered by
Apache-2.0. For redistribution, see section 4 of [LICENSE-APACHE](LICENSE-APACHE).

**If you build software against `granary-core`**, the library is available
under Apache-2.0.

**If you convey `granary-server`**, see sections 4 through 6 of
[LICENSE-AGPL](LICENSE-AGPL). Section 13 covers offering the corresponding
source to remote users of a modified server.

## Why split

The client should reach as many people as possible; the server should not be
strip-mineable. Those are different goals and they want different licences.

This is the model MongoDB used for years — AGPL server, Apache-2.0 drivers — and
it produced very large adoption while keeping the server protected.

The reasoning, with evidence, is in
[docs/licensing-rationale.md](docs/licensing-rationale.md).

## Commercial licensing

Not currently offered. If AGPL is an obstacle for a use case you think is
legitimate, open an issue and describe it — that is useful signal regardless of
whether a commercial licence ever exists.

## Contributing

Contributions are accepted under the Developer Certificate of Origin. See
[CONTRIBUTING.md](CONTRIBUTING.md). There is no CLA and no copyright assignment.

## Trademark

"Granary" as a name and mark is reserved separately from the copyright in the
code, in the same way Rust, Linux and Kubernetes reserve theirs. The licences
above grant no trademark rights.
