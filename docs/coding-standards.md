# Coding standards

**Rule numbers are append-only and are never renumbered.** They are cited from
source — `#![expect(clippy::expect_used, reason = "test code (standards rule
3)")]` and similar — so a renumbering silently re-points every citation at a
different rule. New rules take the next free number wherever they belong by
strength, which is why the MUST list is not contiguous. Same reason CWE, RFC
and ADR identifiers are append-only.

## MUST

1. Workspace-root `[workspace.lints]`; every crate sets
   `lints.workspace = true`. Lint suppressions use
   `#[expect(lint, reason = "…")]`, never bare `#[allow]` — `expect` warns
   when the suppression goes stale. Enforced by the compiler where a crate
   denies `clippy::allow_attributes` (`granary-client` and `granary-cli` do);
   the other crates rely on review until the workspace table carries it.
2. `unsafe_code = "forbid"` in every crate except explicitly named
   FFI-bearing crates (`granary-fuse`), which will run at `deny` once FFI
   lands with:
   `unsafe_op_in_unsafe_fn` deny, `clippy::undocumented_unsafe_blocks`
   deny, and a `// SAFETY:` comment on every block naming the invariant
   it upholds. `granary-client` already carries this shape:
   its own in-crate copy of the workspace lint table sets
   `unsafe_code = "deny"`, scoped to exactly six named
   `#[expect(unsafe_code, reason = "…")]` sites (the client cache's
   `statfs`/`statvfs` free-space seam and its macOS plain-`fsync` call,
   the macOS extended-ACL probe, and Linux/macOS native no-replace
   archive renames). `scripts/check-unsafe-sites.sh` pins this inventory.
   A scheduled nightly-toolchain CI lane will run
   `cargo miri nextest run` scoped to any crate containing `unsafe` —
   the lane is created with the first unsafe crate. Implementing a filesystem
   does not itself require `unsafe`: a full read-only
   `fuser::Filesystem` implementation was compiled successfully
   under `#![forbid(unsafe_code)]` — `fuser`'s API is safe and a dependency's
   `unsafe` is not governed by our lint — so granary-fuse keeps `forbid`,
   `scripts/check-unsafe-sites.sh` needs no widening, and this lane has nothing
   to scope to yet. It is created by whichever crate first writes `unsafe`
   itself. `gran umount` reaches `umount2(2)` through the safe
   `nix::mount::umount2` wrapper. Local control peer credentials use tokio's
   safe Unix-stream adapter, with no new unsafe exemption. The miri lane
   remains scheduled and scoped to crates with their own unsafe code; it
   covers Rust code and cannot inspect dependency-internal FFI.
3. **No `unwrap`/`expect`/`panic!`/slice-indexing in code reachable from
   untrusted input.** `clippy::unwrap_used`, `clippy::expect_used`,
   `clippy::indexing_slicing` denied in library code (allowed in tests).
   Every parser/decoder has a fuzz target; a reachable panic is a bug.
4. `overflow-checks = true` in the release profile (cargo's default is
   off), and checked or saturating arithmetic on every offset or length
   derived from untrusted input. A filesystem doing offset math on untrusted
   input does not get to wrap. `clippy::arithmetic_side_effects` is **not**
   enabled anywhere today, so this rule is enforced by review and tests, not
   by the compiler.
5. Errors: `granary-core` hand-rolls error enums with manual `Display`
   (no proc-macro deps in core — dependency policy); other library crates
   may use thiserror; `anyhow` only in binaries. All public error types
   are `Error + Send + Sync + 'static`; Display messages are lowercase,
   concise, no trailing period (API Guidelines C-GOOD-ERR).
6. CI denies warnings via `CARGO_BUILD_WARNINGS=deny` on the clippy/build
   lanes (`build.warnings`, stable since Rust 1.97 — verified to cover
   clippy warnings and, unlike `RUSTFLAGS="-D warnings"`, it does not
   invalidate the build cache). Not in checked-in `.cargo/config.toml`
   (hostile to local mid-refactor builds); source never contains
   `#![deny(warnings)]` (the documented anti-pattern — it breaks builds
   on future rustc).
7. Async: any `async fn` usable in `select!` documents
   `# Cancellation safety`. Never `read_exact`/`write_all`/`Mutex::lock`/
   `Semaphore::acquire` in a `select!` arm (tokio documents these as not
   cancel-safe). No blocking syscalls or sustained CPU work in async
   context — `spawn_blocking` for short work, a dedicated thread for
   long-lived work. Cleanup is an explicit `async fn shutdown()`; `Drop`
   never needs to await (AsyncDrop is still nightly-only).
8. Determinism seams: no `Instant::now`/`SystemTime::now` outside the
   `Clock` seam, no direct `rand`/hasher seeding outside the `Rng` seam —
   enforced by clippy `disallowed-methods`.
9. `package.rust-version` declared; MSRV bumps are minor releases (cargo
   semver reference). `cargo deny check` gates merge.
   The pinned toolchain (`rust-toolchain.toml`) moves only in a PR of its
   own, which reads the platform-support notes of every release it crosses.
   Check the minimum kernel and glibc requirements for supported targets.
   A static musl binary still depends on the kernel: for example, RHEL 7
   runs Linux 3.10. Tests on newer kernels cannot establish compatibility
   with that host. A bump that raises the support floor requires the owner's
   approval.
10. SPDX header in every source file (CONTRIBUTING.md); Apache-2.0
    everywhere except `granary-server` (AGPL-3.0-or-later). Server logic
    never migrates into Apache crates.

16. **A check reports PASS only from observed evidence of the successful
    outcome — never from the absence of a detected failure, and never from a
    count or a status that stands in for the thing itself.** Corollaries, each
    earned by a shipped defect:
    - **A check that cannot fail is not a check.** Under `set -e`, errexit
      exempts every command of an `&&`/`||` list except the last, so
      `lint -q && echo ok` can never fail the script — it printed ALL GREEN
      over a failing lint for five tasks. (CWE-253, *Incorrect Check of
      Function Return Value*: the status **is** checked; it is the wrong
      status.)
    - **A pass over an empty or unparsed domain is vacuous, not verified.** A
      summariser counted findings only from results that parsed, then printed
      "no blocker or major — freeze" when *every* result failed to parse.
      Assert the domain is non-empty and complete *by identity*, not by
      cardinality: `len(results) == expected` let `part1 + part3` pass as
      "2 of 2". (*Vacuity* is a term of art from temporal-logic model
      checking — Beer et al. 1997; Kupferman & Vardi 1999 — where ~20% of
      passing specifications pass vacuously. Borrowed here by structural
      analogy, not native usage.)
    - **An absent input is not a matching input.** A stamp cross-check treated
      a field missing from the stamp as agreement.
    - **Verify the bytes you will use, not a proxy for them.** `git diff
      --quiet HEAD -- <path>` is defeated by `assume-unchanged`; read
      `git cat-file blob HEAD:<path>` instead. And verify then use *the same
      copy* — checking one file and reading another is CWE-367 (TOCTOU) even
      with no attacker and no race.
    - **A claimed guarantee must name the code that enforces it, or admit in
      the same breath that it is prose.**

    The governing principle is Saltzer & Schroeder's **fail-safe defaults**
    ("base access decisions on permission rather than exclusion", CACM 17(7),
    1975) — stated there for access control, extended here to verification
    logic; that extension is ours, not theirs. Where a real instance needs a
    precise citation, give it its own CWE (252/253/345/367 as it fits) rather
    than one label: these defects span several subtrees, and CWE-703 is marked
    DISCOURAGED for mapping. Deliberately **not** called "positive validation"
    — OWASP ASVS already uses that phrase for allow-list input validation.

    Reviewing for this is different from reviewing for correctness: review
    lanes check whether a guard **exists**, so ask instead **what input makes
    it pass without verifying
    anything**.

17. **granary-client's source-input closure** (the fsguard sibling-site
    gate, `scripts/check-fsguard-sites.sh`): no `macro_rules!`, no
    `#[path]`, no `include!`/`include_str!`/`include_bytes!` under any name
    that reaches source, no symlinked source root, and the crate's direct
    dependency and target-path sets are pinned — so the filesystem ban
    (`crates/granary-client/clippy.toml`) sees every token it must license,
    and every licensed call site carries one `#[expect(clippy::disallowed_methods,
    reason = "…")]` with a reason a reviewer can check. A new filesystem
    call is an audit change: the gate's site count moves on purpose.

18. **Structure follows ownership, not size.** A module holds one subject: the
    invariant its items implement. An item belongs to the subject whose
    invariant it enforces, not to whichever caller uses it most. A file is split
    where two subjects meet at a seam that runs one way, never at a line count;
    a crate is extracted only where a real boundary exists — a different
    dependency set, licence, purity rule or set of consumers. Name modules and
    items for what they do, never for when or in which task they were written.
    A module's unit tests live out of line at `<module>/tests.rs` when its
    crate's non-test artifact has consumers (another crate depends on it, or it
    has its own binary or `tests/` directory), and inline otherwise; integration
    tests live under `tests/`. A file under `crates/*/src` over 3,000 lines
    carries a written disposition that `scripts/check-file-dispositions.sh`
    checks. No speculative abstraction: a trait or generic earns its place with
    a second implementation or a test double that needs it.

19. **Comments and docs describe the code as it is now.** A comment states
    what the code cannot say for itself: intent, an invariant, a non-obvious
    mechanism, a limitation, or the reason a plausible alternative was not
    taken. It does not narrate how the code came to be.
    - **Keep:** the reason for a choice; protocol, RFC, CVE or spec references
      that resolve in this repository or upstream (RFC 9113 §6.9); a
      reproducible example; a stated limitation ("does not see renames across
      mounts").
    - **Do not narrate the code's development in shipping source**: how it
      used to behave, which review, task, milestone or session produced it,
      who or what suggested it, or a decision number a reader of the published
      tree cannot resolve. Say the rule the decision settled instead. The test
      is the sentence's meaning, not its words: "the previous protocol
      version" describing a real compatibility path is fine.
    - **A stated guarantee is true, and a reader can see why.** Where it is not
      obvious from the code, say what carries it — a type that cannot hold the
      bad state, a mechanism, a gate or a test. Where nothing enforces it, say
      so. This is not a call for a citation beside every sentence.
    - **Cite code by item name, not line number.** Line numbers go stale with
      the next edit above them.
    - **A change that falsifies a comment fixes the comment in the same
      change.** Search for the old claim, not only the lines you edited.
    - Public items follow the Rust API Guidelines' documentation chapter:
      `# Errors`, `# Panics` and `# Safety` sections where they apply, and
      intra-doc links (`cargo doc` with `-D warnings` is a CI gate).

    Provenance — who wrote a change, which reviews ran, what they found — goes
    in the commit message and the change's review record, where it is kept.
    Keeping it out of source is about where it belongs, not about hiding it.

20. **New code reuses what exists and reads like its neighbours.** Before
    writing a helper, find the item that already does the job and call it; a
    second copy of a step drifts from the first, and the copy is where a
    later fix is missed. Where the existing item is private, widen it only as
    far as the new caller needs. New code follows the module around it: its
    naming, error and refusal style, fault points, lock and transaction
    order, doc-comment style and test layout. A deliberate departure is named
    with its reason in the change's description (an implementer names it in
    its report, and the controller carries it there). Someone other than the
    author checks this (the `rust-review` skill's consistency pass), because
    an author's own check misses it.

## SHOULD

11. `clippy::pedantic = { level = "warn", priority = -1 }` with
    cherry-picked `expect`s; never blanket-enable `restriction` or
    `nursery` (clippy's own guidance).
12. rustc lints raised: `missing_debug_implementations`,
    `unreachable_pub`, `elided_lifetimes_in_paths`; `missing_docs` on
    published crates.
13. Structured concurrency: `JoinSet` + `CancellationToken` over bare
    `tokio::spawn`; every external I/O call wrapped in
    `tokio::time::timeout`.
14. For keys and other secrets, use `zeroize` with pre-reserved
    capacity and `subtle::ConstantTimeEq` for comparisons — noting both
    crates' documented limits (no register clearing; debug builds
    branch).
15. Tests: proptest for every encoder/decoder (round-trip + no-panic
    properties), insta snapshots for on-disk-format bytes and error
    messages, doc-tests as the public API examples, `#[track_caller]` on
    assertion helpers, no `#[should_panic]` — assert `Err` variants.

## Corpus notes (why these and not more)

The Safety-Critical Rust Coding Guidelines (Rust Foundation consortium)
are v0.1 with 600+ open issues — mined, not adopted. ANSSI's guide is
still marked unstable and skips async entirely. MISRA-Rust does not
exist. When the consortium's guidelines mature, revisit; until then the
API Guidelines + clippy + the rules above are the enforceable set.
