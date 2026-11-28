# Contributing to Granary

## Find or propose work

Open a bug report for a problem you can reproduce. Open a design proposal to
discuss changes to public behavior, on-disk formats, or the wire protocol.
Comment on an existing issue before starting so others can see who is working
on it.

## Run the local checks

Install Rust with rustup, with `rustfmt` and `clippy` for the toolchain pinned
in [rust-toolchain.toml](rust-toolchain.toml). Install `cargo-nextest` as well.
From the repository root or a workspace member, run:

```sh
cargo run --quiet --locked --package xtask -- check
```

This checks workspace formatting and Clippy lints, then runs the portable
`granary-core` and `granary-vfs` test suites. From the root,
`./scripts/check-local.sh` remains a no-argument shortcut for this check.
For the same formatting and lint checks followed by workspace tests and
documentation tests, run:

```sh
cargo run --quiet --locked --package xtask -- check-full
```

Use absolute directories in `PATH` for Cargo tools and wrappers. If `PATH`
contains a relative directory, the runner uses the absolute Cargo executable
provided by `cargo run` for its child checks, so a `PATH` wrapper may only
handle the initial command.

Use the [Linux mount test instructions](docs/dev-environment.md) for FUSE
coverage when a change affects mounting.

Cache and mount tests create fixtures under the system temporary directory. If
space is tight on Linux or macOS, set `TMPDIR` to a writable local directory
with room for the fixtures. For tests that use the real free-space check,
leave room for each cache write plus the reserve: 5% of filesystem capacity
(rounded down to bytes), with a 1 GiB minimum only on filesystems larger than
1 GiB.

## Open a pull request

Keep the PR focused on one change. Write a short title and use the description
to explain what changed, why, and how you verified it. The title and description
form the draft message for the squash commit.

Check the PR's **Checks** tab after opening it. GitHub may ask the maintainer
to approve the first workflow run from a fork.

Address any blocking review findings before the PR lands. Changes to product
behavior, safety guarantees, or the checks that govern merging require
independent review and explicit maintainer approval.

The maintainer runs the checked squash command once the required reviews cover
the change and CI passes for the current PR head and base. The command verifies
the evidence and final message before merging, then checks the landed commit.

### Choose a change class

Use the class that describes the strongest guarantee your change affects.

| Class | Use for |
| --- | --- |
| E | Editorial changes that leave the stated claims the same. |
| I | Internal changes or ordinary tests that preserve the public contract. |
| P | Changes to public behavior, a documented contract, or contributor policy. |
| S | Changes to a safety guarantee or to the checks that authorize it. |
| R | Irreversible maintainer actions, such as publishing a release. |

End the PR description with one block of trailers. Put the change class in
`Class:`, followed by the AI credits and the applicable human sign-offs.
The maintainer reviews the class and credits before merging.

This sample PR description records how a test for existing behavior was verified.

```text
Exercise the existing refusal for an empty journal. Added a fixture
for the empty input and ran the granary-core suite.

Class: I
Assisted-by: none
Signed-off-by: Jamie Example <jamie@example.com>
```

## Sign your commits

Contributions are accepted under the **Developer Certificate of Origin**. There
is no CLA and no copyright assignment — you keep the copyright in your work.

Sign off each commit:

```
git commit -s
```

which appends:

```
Signed-off-by: Your Name <your.email@example.com>
```

By signing off you certify the DCO below. Use your real name; pseudonyms and
anonymous contributions cannot be accepted.

The squash commit preserves the required human sign-offs verbatim. Add your own
sign-off and keep any existing sign-offs that apply to work you carry forward.

## AI assistance and review

You are responsible for the change you submit. Read and understand it.
Disclose material AI assistance in the `Assisted-by:` trailer. Use
`Assisted-by: none` if there was no material assistance. Use
`AI-Reviewed-by:` only for a review that covers the change as it lands.

Maintainers may send relevant material from public PRs to external model
providers for review. Follow the [security policy](SECURITY.md) to report a
vulnerability privately.

## Which licence your contribution lands under

Inbound equals outbound. A contribution to `granary-server` is AGPL-3.0-or-later;
a contribution to `granary-core` or a client crate is Apache-2.0. See
[LICENSING.md](LICENSING.md).

**There is no relicensing reservation.** A DCO does not grant the maintainer the
right to relicense your contribution, and none is claimed. If the project's
licence ever needs to change, contributors will be asked.

## Developer Certificate of Origin 1.1

```
By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

Full text: <https://developercertificate.org/>

## Source file headers

Every source file starts with an SPDX identifier:

```rust
// SPDX-License-Identifier: Apache-2.0
```

or, in `granary-server`:

```rust
// SPDX-License-Identifier: AGPL-3.0-or-later
```

The identifier is authoritative for that file.

If you add or adapt third-party code, fixtures, or assets, identify the upstream
source and version or revision in the PR. State which material you used and the
terms that cover it. Preserve the required notices in the repository.
