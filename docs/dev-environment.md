# Development environment

The portable Rust crates and deterministic simulation tests run natively on
macOS. Use Linux for a real FUSE mount. On Apple Silicon, the
[optional Podman VM](#the-vm-loop) runs the Linux checks.

For mount-table checks, do not containerise the mount you are proving. The
harness runs `mount` directly in the VM to inspect its mount table and
`test` in containers to detect leaked FUSE mounts in an isolated namespace.

## Linux benchmark hosts

Keep a physical Linux host for benchmarks. Compare results from Linux 6.12 or
later (the Tier 1 benchmark baseline) with results from an older kernel such
as the one shipped with RHEL 8 or 9 (Tier 2). Record the date, tier, kernel version and
architecture for each run and include them with published wall-clock
results. State which read path the measured binary used. The current
implementation serves reads through the userspace daemon and uses neither
passthrough nor FUSE-over-io_uring.

## Apple Silicon development tools

The checkout selects the Rust toolchain. The [contributor guide](../CONTRIBUTING.md)
lists the tools for the local checks. The following commands also install tools
for linting, fuzzing, profiling and testing:

```
xcode-select --install            # cc for aws-lc-rs/zstd/blake3
brew install gh cmake zizmor cargo-shear shellcheck uv
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup component add rust-src
rustup target add aarch64-unknown-linux-gnu   # OPTIONAL/manual: only for manual
                                              # VM cross-checks; not in
                                              # rust-toolchain.toml — CI owns
                                              # cross-target coverage (arm64 VM,
                                              # NOT x86_64)
rustup toolchain install nightly && rustup +nightly component add miri rust-src
cargo install --locked cargo-binstall
cargo binstall cargo-nextest      # has attestations: gh attestation verify on upgrades
cargo install --locked cargo-deny cargo-fuzz samply   # unattested: build from source
# (binstall --secure is a deprecated no-op — do not rely on it)
samply setup                      # self-sign; SIP blocks profiling otherwise
uv tool install reuse
```

### VS Code

The checkout includes [rust-analyzer settings](../.vscode/settings.json)
for Apple Silicon. Check-on-save runs Clippy for the native macOS target.
A separate Cargo target directory keeps editor checks from waiting on
terminal builds. On a different host, select its native target in the editor.

### The VM loop

For the optional Linux loop on Apple Silicon, install Podman and Bash 4 or later.
Run these commands from the checkout. Use a checkout under `/Users` whose
absolute path contains only letters, digits, dots, slashes, underscores and
hyphens. The harness also uses a sibling directory, `granary-target-linux`.
The VM must see both paths at the same absolute locations on a writable
virtiofs share.

```sh
brew install podman bash
export PATH="$(brew --prefix)/bin:$PATH"
podman machine list
```

If you need a new default machine, initialize it with Podman's supplied
image. Share the checkout's parent so the sibling build directory is visible.
This example gives the VM 10 GiB for the harness's default 8 GiB container
limit. For an existing default machine, skip initialization and start it
only if stopped.

```sh
parent=$(dirname "$(pwd -P)")
podman machine init --memory 10240 --volume "$parent:$parent"
podman machine start
```

Before a mount run, check the rootless connection with
`podman info --format '{{.Host.Security.Rootless}}'` (it should print
`true`). Use `podman machine ssh` to open a guest shell. Check that
`uname -m` reports `aarch64`, `/dev/fuse` is a character device,
`fusermount3` is setuid root and `/sys/fs/fuse/connections` is mounted
as `fusectl`. From the guest, open the checkout's `Cargo.toml` at its
host path and check that its parent share is writable. Podman's
`podman-machine-init(1)` manual describes the volume and memory options.

**Never share one `target/` between macOS and
the VM** — host-side build scripts and proc-macros collide and Cargo's
lock misbehaves over virtiofs; if the repo is mounted, set
`CARGO_TARGET_DIR` inside the VM (the scripted loop instead uses a
distinct, shared-but-not-`target/` directory — see below). macOS
`ulimit -n` defaults to 256 — raise it before FD-heavy test runs. APFS is
case-insensitive; the Linux VM is the real case-collision detector (and
a determinism fixture exists for exactly that class).

### The Linux loop

`scripts/linux-container.sh` is the scripted form of the loop above: it builds
granary's Linux-only code (`crates/granary-fuse`, and the
`cfg(target_os = "linux")` parts of `crates/granary-client` and
`crates/granary-cli`) in a rootless
podman container on the machine described above, and runs it either in a
second container or in the bare VM, depending on what a given check
actually needs.

**The eight commands listed below take no trailing arguments.** A `main` that examined `$1`
alone would run `linux-container.sh clean --dry-run` as a REAL clean —
a discarded argument that reads as a safety flag is the worst shape for
this, and `clean` is the destructive one. There is no `--dry-run`.

**Requires bash >= 4** — run it with a Homebrew bash or similar, never with
stock macOS `/bin/bash` (3.2.57). This is a PARSE-time failure, not a
runtime one: 3.2 mis-parses a heredoc nested inside a `$( … )` command
substitution, which the script's four container-side lane scripts all use;
no in-script version check can catch it, because the failure happens
before any of the script's own code runs. Measured symptom: a bare
`syntax error near unexpected token '('`, rc nonzero, under 3.2.57;
silently fine under 5.3.15+.

Run `scripts/linux-container.sh --help` for the full usage.

- `build` — container, non-root: builds the `gran` binary and the
  granary-fuse and CLI daemon nextest archives onto the shared target directory.
- `test` — two container lanes. container-root (`--device /dev/fuse
  --cap-add SYS_ADMIN`, uid 0) for granary-fuse — the only way every
  `require_root()`-gated test is guaranteed to execute rather than
  silently defer. container-non-root (no grants, uid != 0) for
  granary-client and granary-cli plus their Linux-only clippy and rustdoc
  lanes — the only way their `owner_uid == 0` guards are guaranteed not to
  fire and skip the fixtures they guard.
- `mount` — the bare VM (`podman machine ssh`): runs the container-built
  `gran` binary there (the actual proof a Debian-built ELF runs on Fedora
  CoreOS — glibc version arithmetic alone is not that proof), then the
  FUSE and CLI daemon archives under `sudo` with process-per-test isolation. The
  bare VM has no cargo, and running the compiled test binary directly in
  one process is a fail-open: an irreversible `setuid()` in one
  fusermount-fallback test poisons every later root-gated test in that
  same process.
- The `mount` lane also runs `scripts/blocked-stderr.sh` on the bare VM under
  `sudo`. A fresh container build stages the feature-gated probe executable;
  the supporting stack runs in a nonroot container on the VM's host network.
  The battery verifies mount/read progress, typed refusal, panic termination,
  and clean shutdown after a failed wire-snapshot write against a full pipe
  whose reader never reads. A separate draining pipe must deliver the snapshot
  diagnostic. Probe markers use independent files, so blocked output cannot
  hide which path ran. CI's `fuse` job runs the same fixed battery.

  Run the fixed battery with:

  ```sh
  scripts/linux-container.sh build
  scripts/linux-container.sh mount
  ```

  Run the fixed battery followed by all four controls with:

  ```sh
  GRANARY_STDERR_CONTROLS=1 scripts/linux-container.sh mount
  ```

  The controls apply `scripts/blocked-stderr-controls/*.patch` to separate
  scratch source copies and build them in the nonroot container. The checkout
  is never patched. Each mutant must reach its named checkpoint and remain
  alive past its bound. The banner control must remain unmounted; the shutdown
  control must first mount, read the sentinel, unmount, and reach the failed
  snapshot write. Bounds are 20 seconds for mount startup, 5 seconds for the
  sentinel read, 5 seconds from launch for refusal/panic, and 5 seconds after
  unmount for shutdown. Each control observes the full corresponding interval
  after its checkpoint. Logs name the shared build directory and VM evidence
  directory; failed runs retain them for inspection.
- `conform` — the differential conformance oracle, in two lanes.
  container-non-root builds four binaries — `gran` (feature-off),
  `gran-armed` (built `--features conformance-breakage` through a SEPARATE
  `--target-dir`, because a feature build overwrites `debug/gran`),
  `granary-server` and `granconf` — then EMPTIES a staging directory and
  copies exactly those four into it. container-root
  (`--device /dev/fuse --cap-add SYS_ADMIN`) bind-mounts that staging
  directory over `target/debug` and runs `scripts/conformance.sh`,
  which stands the stack up and mounts the volume eight times: one honest
  baseline plus one per deliberate breakage.
  **The staging directory is emptied and re-copied every run on purpose.**
  The shared target directory PERSISTS, so an executable file being present
  proves a file exists, not that this run built it.
  The conformance check compares file contents, attributes and directory
  entries. Those comparisons can run in a container. Use `mount` to check
  the VM's mount table. The MinIO harness also needs `shasum -a 256`,
  which the bare Fedora CoreOS VM lacks. The script flags changes to that
  dependency so the choice of test host can be revisited.
- `demo` — runs the mount, read and teardown smoke test and its self-check
  in containers.
- `unit` — tests the packaged systemd unit on the VM with a container-hosted
  server. It refuses an existing Granary mount, mount unit or runtime unit template.
- `publish-restart` — runs the [publication restart checks](#publication-process-restart-checks)
  on the supported Linux filesystem.
- `clean` — removes the harness's named build artefacts (requires a regular,
  non-symlink stamp file to be present first;
  the two recursive trees `conform` adds, `armed/` and `conform-bin/`, each
  need their own ownership marker before they are removed), then
  removes the now-empty directory with a non-recursive `rmdir` — never a
  recursive removal of the caller-named directory itself. **What that
  protects, precisely:** a directory that has gained an unrecognised
  **top-level** entry fails the `rmdir` and is left alone, by construction
  (a kernel guarantee, not a script check), and `logs/` is emptied by
  naming its two files rather than recursively. **What it does not
  protect:** `debug/`, `release/`, `doc/` and `tmp/` are removed
  recursively, including files you put there. Before deleting `debug/` or
  `release/`, the harness checks for a Cargo marker in the target directory
  (`CACHEDIR.TAG`) or a `.fingerprint/` directory under that build profile.
- `--self-test` — plants failure conditions (a target dir aliasing the
  repo's own `target/`, a dropped container grant, a suite run under the
  wrong privilege, and so on) and confirms the script refuses each one,
  each paired with a positive proving the refusal is not vacuous.

**Why the target directory is a sibling of the repo, on one line:** it has
to sit on the SAME virtiofs-shared path the container and the VM can both
see, and it must never be the repo's own `target/` — sharing that one with
a Linux build corrupts it exactly the way "never share one `target/`
between macOS and the VM" above already warns against.
`GRANARY_LINUX_TARGET_DIR` defaults to `../granary-target-linux`, a sibling of
the repo; the script refuses to run against any resolved path that is, or
lives inside, the repo's own `target/`, or that resolves outside the
virtiofs-shared prefixes (`/Users`, `/private`, `/var/folders`) — both
refusals are demonstrated by `--self-test`.

### Commit signing

To sign commits in this checkout with an SSH key (Git 2.34 or later),
set the path to your public signing key:

```sh
git config --local gpg.format ssh
git config --local user.signingkey ~/.ssh/id_ed25519.pub
git config --local commit.gpgsign true
```

## Git identity

Configure the name and email Git records for commits in this checkout.
Choose the address you want to appear in the public history.

```
git config --local user.name "Your Name"
git config --local user.email "you@example.org"
```

Follow the [contribution guide](../CONTRIBUTING.md) when signing off commits and
opening a pull request.

## Publication process restart checks

Run `scripts/publish-restart.sh` from the repository root on supported Linux
storage with TCP and Unix-domain loopback sockets. On macOS it first runs the
native controlled-peer restart suite, including selection and cut coverage;
only the Linux-only composition scenarios are excluded from that required set.
It then runs `scripts/authority-venue.sh --publish-restart`, which mounts
journaled ext4 at `/tmp` in the Linux container.
`scripts/linux-container.sh publish-restart` uses this same supported venue.
If Git reports dubious ownership in the rootless Podman container, set the
user namespace for this invocation so the container sees the checkout under
your user ID.

```sh
PODMAN_USERNS=keep-id scripts/authority-venue.sh --publish-restart
```

CI's required `publish-restart` job runs the script directly and refuses
unsupported or unreadable storage.
The venue check inspects the resolved fixture directory: `TMPDIR` when set,
otherwise `/tmp`, and records that directory in its evidence.

Build and report directories are under `CARGO_TARGET_DIR` (default `target`);
the container lane sets its claimed Linux target directory. The MinIO binary
uses the shared repository cache at `target/minio`, independent of that setting.
The instrumented executable is `publish-restart-armed/debug/gran` under that
directory, built with the default-off `publish-restart-tests` feature. The
shipping client and server are built in `publish-restart-shipping/release`.
The server test feature selects only tests; no dev-dependency enables client
instrumentation. The shipping graph excludes client/CLI restart instrumentation
and server crash points, including workspace dev edges. Each release wall is
checked independently, and both shipping artifacts are inspected for markers;
armed client/server artifacts must fail that inspection. Feature resolution is
profile-independent; artifact inspection also covers release builds with debug
assertions enabled that bypass the walls.

The controlled peer's restart rows retain complete canonical records and exact
request/response transcripts. It can run on macOS and Linux. The composed rows
use real TLS enrollment, GrainService, FileLog and the authority host, with a
parent-owned persistent MinIO process and a signed HTTP delay proxy. Every
matching root PUT is captured completely and identified by volume, seq, body ID
and occurrence. Explicit releases observe MinIO's actual create-only result;
issuer disconnect cannot discard a pending request. Backend reads/listing and
committed log records independently establish occupancy and authorization.

The dispatch-loss schedule holds a committed Accepted reply before the final
fence check/send. The gateway bounds authority replies at 250 ms, below the
client's 45-second transport base, and store dispatch at 5 s. The hold remains
armed through all eight sends and coordinator backoff, until Pending exit 3.
Each response must be a real 503 unavailable. Durable no-write evidence remains
zero. Release permits the attested PUT to land. A fresh invocation completes
from owned occupancy with zero POSTs. The normal unheld reply and
competing/detached PUT controls run beside it.

The replay schedules interrupt the client at its dispatch-after cut, after a
normal committed Accepted response and before local answer accounting. A clean
stop explicitly settles the issuer's attempt with a terminal backend refusal
while retaining its signed capture; restart under the same boot reissues the
original bytes and seq. A SIGKILL of the gateway/host instead requires an
unchanged-state same-boot refusal, then recovery with a changed boot ID through
the seam, labeled a modeled reboot. Both surviving PUTs are released and their
conditional results counted separately from the single root creation. A fresh
client completes with only its root probe and hint repair, sending zero POSTs.

The archive schedule releases an authorised old PUT after actual local CLI
abandonment. The abandoned/may-land report sends no requests, and ordinary
publish and archived-ID recovery both refuse without changing the archive or
sending a POST. The binary control transfers a normally initialised empty log
to the shipping server, forwards the enrolled fixture identity through a TLS
request tap, and checks one publication and landing through its real gateway.
The tap records the complete preparation, publication, probe and hint order;
it never constructs an authority answer. A shipping CLI invocation also checks
the human winner report without another POST. These real-host rows require supported Linux storage; macOS-only
controlled-peer evidence is not a supported authority venue pass.

Ordinary rendezvous/child-exit waits are bounded at ten seconds; the dispatch-loss
invocation has a 35-second bound. The client's control-reply wait has a
30-second backstop. Missing rendezvous or timeout is a fixture failure, never
semantic guard evidence. Reports bind test/binary identity and scenario stages
to a fresh run identity; stale, duplicate, ignored, wrong-binary and incomplete
evidence refuses. Process restart checks and persistence models do not claim
physical power-loss evidence. Socket-denied venues report compiled/listed rows
and unexecuted subprocess coverage separately.
