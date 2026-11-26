# Dependency policy

Why this exists: dependencies are the supply chain. crates.io shipped at
least five documented malicious-crate incidents in 2025–26 (faster_log,
evm-units, finch-rust/sha-rust families, plus a maintainer-phishing
campaign — see the rust-lang blog), and the delivery vector in every case
was "someone depended on it." The build-time surface is the sharp end:
`build.rs` and proc-macros execute arbitrary code on every contributor and
CI machine at *compile* time.

The reference cases this policy copies: **sudo-rs** (reduced 135 transitive
dependencies to 3, with published reasoning) and **ntpd-rs** ("only add a
new dependency if absolutely necessary"). ripgrep's parser choice (lexopt +
bespoke flag table) is the same ethos applied to CLI parsing.

## The rules

1. **Prefer std or ~200 lines of our own code** over any dependency whose
   whole value is convenience. Adopt a dependency only where hand-rolling
   is genuinely worse: cryptography, compression, protocol state machines,
   kernel interfaces, and specified formats with nontrivial parsers (TOML).
2. **Budget the transitive closure, not the direct dependency.** Anything
   adding more than ~5 new crates needs to replace more code than it adds
   (the sudo-rs test). `default-features = false` is the default posture.
3. **Build-time execution is the real threat.** Every new `build.rs` and
   every new proc-macro crate requires written justification in the commit
   that adds it. CI diffs the output of `scripts/dep-inventory.sh` against
   `supply-chain/` (dev edges per rule 6; all features so the fips tree is
   covered); unreviewed additions fail the build.
4. **Maintenance floor** for any new dependency. It has two halves and
   they work differently, as specified below.

   **4a. Mechanical, and a HARD floor.** A release within 24 months, no
   open RUSTSEC advisory, a licence on the deny.toml allow list
   (Apache-2.0/MIT baseline; ISC/BSD/Zlib-class accepted case-by-case —
   the accepted heavyweights already carry ISC, BSD and OpenSSL licences,
   so deny.toml is the authoritative set, not this sentence).
   Exact-version pins, `Cargo.lock` committed, cargo-deny licence +
   advisory gates (already in CI), cargo-vet audit trail once there are
   contributors. Failing any of these needs a written exception naming
   which criterion failed and why it is accepted anyway.

   **4b. Ownership is a RECORDED FINDING, not a test.** The adopting
   commit records **the crate's crates.io owner record verbatim, its
   governance document if one exists, and one sentence on what happens to
   the project if the named owners stop.** There is no threshold to pass.

   > **Ownership cannot be reduced to an owner-count threshold.** The
   > requirement "more than one maintainer or a named institutional owner"
   > has no registry field that mechanizes it. `criterion` carries a
   > crates.io `owner_team` pointing at a GitHub org whose own profile
   > reads *"Dead / no longer active"* with zero repos; `object_store` —
   > Apache Software Foundation, the strongest institutional signal in
   > this tree — carries **no team at all**; and `rust-lang-owner` and
   > `wasmtime-publish` are institutional ownership recorded as a single
   > *user*. Every candidate signal (repo-under-an-org, `owner_team`,
   > org-domain-verified) produces both false positives and false
   > negatives. Worse, **any line strict enough to exclude a
   > single-maintainer crate also excludes `blake3`, `fastcdc` and
   > `zstd`** — 3 of 12 direct dependencies, and the three most
   > load-bearing formats in the project (37% of the 268-package closure
   > fails at closure scope).
   >
   > The xz-utils backdoor (CVE-2024-3094) is the reason not to replace
   > it with a stricter count: the attacker's entire strategy was
   > *becoming the second maintainer* of a single-maintainer project, so
   > post-2022 xz would have **scored better** on a headcount rule while
   > being actively compromised. Headcount is adversarially gameable;
   > naming who is actually responsible is not.
   >
   > A recorded finding asks **who**, not **how many** — and it is what
   > the "Applied decisions" section below was already doing in practice.
5. **Re-justify annually.** A dependency that has become removable — the
   feature landed in std, or usage shrank to one call site — gets removed.
6. **Dev-dependencies are not exempt.** The build-time threat (rule 3)
   executes identically for bench/test/dev deps on every contributor and
   CI machine. Same rules, same written justification for build.rs and
   proc-macros in their trees; their only concession is that they never
   enter shipped artifacts or the purity-gated core graph.

## Ownership findings (rule 4b)

Backfilled 2026-08-15 with the rule-4b amendment, because the three
crates below shipped before the rule existed and are exactly the ones a
threshold would have excluded. Owner records retrieved from
`crates.io/api/v1/crates/<name>/owners` on 2026-08-15.

- **`blake3`** — sole crates.io owner `oconnor663` (user; no team).
  Repo `github.com/BLAKE3-team/BLAKE3`, an org, but that is not itself
  evidence (see rule 4b). Latest `1.8.6`, 2026-08-05, when evaluated — well inside 4a (pinned `=1.8.7`, released 2026-08-20, since 2026-09-29).
  Jack O'Connor is a **co-author of the BLAKE3 specification** and the
  repo is the reference implementation, so ownership and authorship
  are the same party; the org carries the other three designers. *If
  the named owner stops:* the algorithm is specified and frozen and the
  C/Rust reference code is Apache/CC0 — granary pins `=1.8.7` and could
  vendor the implementation. **The identity risk is not maintenance,
  it is that a compromise of one account reaches the grain-identity
  hash**, which is why the pin is exact and every upgrade re-opens the
  review.

- **`fastcdc`** — sole crates.io owner `nlfiedler` (user; no team).
  Repo `github.com/nlfiedler/fastcdc-rs`, a personal namespace. Latest
  `4.0.1`, 2026-04-26 — inside 4a. No governance document. *If the named
  owner stops:* the chunker is a **pinned format contract** — granary
  depends on the exact chunking behaviour, not on ongoing development,
  so an unmaintained crate at the pinned version is the *expected*
  steady state rather than a hazard. A fork is viable: the algorithm is
  published (FastCDC, Xia et al.) and the crate is small. **This is the
  thinnest ownership story of the three**, and it is accepted because the
  dependency is frozen by design.

- **`zstd`** — sole crates.io owner `gyscos` (user; no team). Repo
  `github.com/gyscos/zstd-rs`, a personal namespace. Pinned `=0.14.3`,
  2026-10-16, well inside 4a (at the 2026-08-15 backfill the latest was
  `0.13.3`, 2025-02-20, the closest of the three to the 24-month floor).
  Re-checked 2026-10-26 at the `0.14.3` bump: owner record unchanged
  (`gyscos`, user, no team; every 0.14/8.x/2.1 release published by that
  account). Bindings over upstream `zstd`, which
  is Meta-maintained; the binding layer is the single-owner part.
  *If the named owner stops:* the C library is unaffected and other
  bindings exist, but a stall would eventually strand security fixes in
  the C tree behind an unmaintained binding. **Re-check this one at the
  annual rule-5 pass**: a single owner and a release gap of 18 months
  before 0.14.0 make it the entry to watch, though it is not close to 4a
  today.

None of the three fails rule 4a. All three would have failed the deleted
maintainer threshold, which is the point.

### Pre-recorded for the transport promotion (Adrian, 2026-08-15)

Recorded ahead of use so the adopting task cites rather than re-derives,
with dependency promotions folded into the adopting task.

**Adopted 2026-08-16 by the accept-loop task**, which is the first code
to use them: `tokio-rustls =0.26.4`, `hyper =1.11.0`,
`hyper-util =0.1.20` (all three regular dependencies of `granary-net`)
and `http-body-util =0.1.5` (dev-only there; the handler task promotes
it when it needs it). The measured `Cargo.lock` delta is **one new
package, `httpdate`**, with no version bump anywhere else —
`tokio-rustls`, `hyper`, `hyper-util` and `http-body-util` were all
already in the lock transitively via `object_store → reqwest`. `http`
passes cleanly and needs no finding (`carllerche` + `seanmonstar`); it
is not a direct dependency in any case, since `hyper` re-exports the
types granary names.

**Dated as of the 2026-08-16 adoption; `hyper` has since moved.** The
`hyper 1.11.0` named here was that day's pin. The `hyper 1.11.1` entry
below records the 2026-09-29 patch bump; this paragraph's own facts
(the `httpdate` lock delta, `http`'s ownership) are unaffected and are
left as adopted.

- **`tokio-rustls 0.26.4`** — crates.io owners `quininer` and `djc`
  (Dirkjan Ochtman); two users, no team, verified 2026-08-16. The repo
  sits under the `rustls` GitHub org, which is a real signal about who
  is nearby, but **it carries no governance document of its own** — no
  `docs/` directory, no `CONTRIBUTING`, no `SECURITY.md`, where
  `rustls/rustls` has all three. The org tells you where the code lives,
  not who is on the hook for this crate. Passes 4a comfortably: released
  2025-09-26, ~11 months. Licence `MIT OR Apache-2.0`.
  *If the named owners stop:* this is a thin adapter — an
  `AsyncRead`/`AsyncWrite` shim over `rustls`'s own state machine, which
  we already depend on directly and which is the part that would carry
  a security fix. The realistic exposure is a lag in tracking a `rustls`
  major, not an unfixed vulnerability. Mitigations are the exact pin and
  the rule-5 annual re-justification.

  **`rustls` bumped `=0.23.43` → `=0.23.45`, 2026-09-15 (rule-4a re-check
  at bump time).** Forced, not elective: **RUSTSEC-2026-0285** —
  TLS 1.3 handshake messages accepted across encryption-level boundaries,
  where a handshake message packed into the same record as a key-changing
  message (a plaintext `EncryptedExtensions` beside `ServerHello`) was
  accepted instead of being refused with `unexpected_message` per RFC 8446
  §5.1. The transcript stays authenticated, so this is not a handshake
  forgery; the effect is that a peer can send in plaintext what should have
  been encrypted. Functionally the same bug as Go's CVE-2025-61730. The
  advisory names `>=0.23.45` and rule 4a's "no open RUSTSEC advisory" is a
  HARD floor, so the pin moved rather than an exception being written.
  **Lock delta measured at the bump: `rustls` 0.23.43 → 0.23.45 and its
  transitive `rustls-webpki` 0.103.13 → 0.103.15 — two version lines, two
  checksums, and 324 packages before AND after, so ZERO new packages.**
  `cargo deny check` goes from `advisories FAILED` to
  `advisories ok, bans ok, licenses ok, sources ok`; licences unchanged.
  The entry above predicted this exposure shape — *a lag in tracking a
  `rustls` fix* — and it arrived as a patch-level one, which the exact pin
  turned into a deliberate edit rather than a silent float.

  **`rustls` bumped `=0.23.45` → `=0.23.46`, 2026-10-14 (rule-4a re-check
  at bump time).** Forced again: **RUSTSEC-2026-0346, -0347, -0348 and
  -0349**, published together, cover `rustls` 0.23.45 — Brotli certificate
  decompression that can allocate up to 1 GiB before the certificate is
  authenticated, an unauthenticated `ServerHello` that can downgrade later
  connections to classical key exchange, and two Encrypted Client Hello
  issues. All four name `>=0.23.46`. **Lock delta measured at the bump:
  `rustls` 0.23.45 → 0.23.46 only, one version line and one checksum in
  each of the workspace lock and the client-fuzz lock, and 325 packages
  before AND after, so ZERO new packages.** `cargo deny check` goes from
  `advisories FAILED` to `advisories ok, bans ok, licenses ok, sources ok`;
  licences unchanged; the supply-chain inventories are regenerated.

- **`hyper 1.11.0`** (evaluated; pinned `=1.11.1` since 2026-09-29, see the note below) — crates.io owners `seanmonstar` (user) **and the
  `github:hyperium:core` team**, verified 2026-08-16: the one crate in
  this promotion where ownership is recorded institutionally rather than
  personally. `docs/GOVERNANCE.md` and `docs/MAINTAINERS.md` exist in
  its repo. Passes 4a: released 2026-07-20. Licence MIT.
  *If the named owner stops:* the core team is the named continuity,
  which is exactly what rule 4b asks for and what the two entries below
  lack.

  **`hyper` bumped `=1.11.0` → `=1.11.1`, 2026-09-29 (rule-4a re-check
  at bump time).** Version `1.11.1` released
  2026-08-28, same owners as above, licence unchanged, no open advisory
  at either version. Batched in the same commit as `rcgen =0.14.10` and
  `blake3 =1.8.7`; `h2` was proposed for the same bump (`=0.4.19`) but
  reverted after `/code-review` found it changes h2's small-DATA-frame
  budget default (now half the connection window, floor 25,600) in a
  way the client's 64 MiB window turns into roughly 130k one-byte
  frames instead of the ~100 that 0.4.18's fixed 25,600-byte default
  allows — so `h2` stays `=0.4.18` here, re-opening that
  review separately rather than folding it into a patch-bump commit.
  Verified `hyper 1.11.1` accepts `h2 =0.4.18` (`cargo update -p h2
  --precise 0.4.18` resolved cleanly against the pinned `hyper
  =1.11.1`).

- **`reqwest 0.13.4`** (direct edge from `granary-store`'s `backend` feature,
  2026-09-27) — sole
  crates.io owner `seanmonstar` (user; no team), verified 2026-09-27. Passes
  4a: released 2026-05-25, MIT OR Apache-2.0, `cargo deny` clean. Already in
  the lock at this version through `object_store`; the edge adds zero packages
  and no build-time code, and names only the features `object_store` enables
  (`rustls`, `http2`). It exists so every S3 store granary builds, the client's
  `--direct-s3` route and the server's store, uses a client that follows no
  redirects (`granary_store::http_client`). *If the named owner stops:*
  the exposure is `object_store`'s, which this edge does not change; the
  alternative is a hyper-util `HttpService`, rejected for now as more code and
  a second TLS trust configuration.
- **`hyper-util 0.1.20`** and **`http-body-util 0.1.5`** — sole
  crates.io owner `seanmonstar` (user; no team) for both, verified
  2026-08-15. Repos sit under `hyperium`, but `hyper` itself
  carries a `github:hyperium:core` team and these two do not, so
  the org tells you nothing here. **`hyper`'s `docs/GOVERNANCE.md`
  and `docs/MAINTAINERS.md` do not extend to these repos, which
  have no `docs/` directory at all**; `MAINTAINERS.md` names
  exactly one person at the admin tier regardless. Both pass 4a.
  *If the named owner stops:* granary already compiles several
  `seanmonstar`-solo crates today via `reqwest`'s tree, so this
  changes the direct-dependency count, not the exposure. Mitigations
  are the exact pin and the rule-5 annual re-justification. **Rule
  1 alternative, considered and left open for the transport task:**
  `hyper-util` is wanted for `TokioIo` and the `auto` h1/h2 builder
  — adapters, not a protocol state machine, which is the shape rule
  1 exists to reject. Keeping `hyper` alone and writing ~100 lines
  in `granary-net` (which already owns the accept loop) would drop
  this finding entirely. **That alternative was declined (Adrian,
  and taken up by the accept-loop task 2026-08-16):** the accept
  loop uses more of the crate than the ~100-line estimate covered —
  the sealed `GracefulConnection` implementations that turn a pinned h1/h2
  connection into the protocol's graceful close, plus `TokioTimer`,
  without which hyper's header-read timeout panics rather than
  arms. Granary owns the small receiver-counted `watch` drain so it can
  trigger graceful rotation before the hard connection lifetime; it does not
  reimplement hyper's protocol shutdown state machines.

- **`rustls-pki-types 1.15.1`** — regular dependency of
  `granary-server` (the binary reads PEM TLS material through
  `PemObject`; `std` feature). In the lock since rustls arrived; the
  direct edge is what makes this finding owed (rule 6's logic, on a
  regular edge). crates.io owners, verbatim (API, 2026-08-18): team
  `github:rustls:publishers` and user `djc` — an ORG TEAM plus a named
  maintainer, repo under `rustls/pki-types`, governed by the same
  rustls project whose core crates this workspace already pins, so the
  ownership story is the rustls entry's. Passes 4a;
  no open advisory; licences MIT/Apache-2.0.
  *If the named owners stop:* rustls itself stops with them — this
  crate adds no marginal exposure beyond the TLS stack it types for;
  the exact pin and rule-5 re-justification are the mitigations.

- **`h2 0.4.18`** — dev-dependency of `granary-server` (the loopback
  battery's HTTP/2 client: it can send `:path` values and duplicate
  field lines hyper's client refuses to construct), and ALSO a
  REGULAR dependency of `granary-client` since the retry landed:
  `retry.rs`'s seam-retry classifier downcasts a transport failure's
  `source()` chain to `h2::Error` to identify a `REFUSED_STREAM`
  reset (RFC 9113 §8.7's non-processing guarantee) and a remote
  GOAWAY, which needs the type in a non-dev position. In the lock
  since the transport task via hyper; the direct edge is what makes
  this finding owed (rule 6: dev-dependencies are not exempt). **The
  prior rule-4b note here said "Sole crates.io owner `seanmonstar`",
  and that is WRONG** — the second instance of exactly the error
  the `hyper-rustls` entry below already records, so it is corrected
  the same way and for the same reason: a 4b finding is a finding
  about the REGISTRY, not about which GitHub org a reader recognises.
  crates.io owners, verbatim (API, 2026-08-23, re-checked at the
  0.4.18 bump): users `carllerche` (Carl Lerche), `seanmonstar`
  (Sean McArthur) and `olix0r` (Oliver Gould) — three individual
  owners, no team. Repo under `hyperium` with no governance documents
  of its own. The bus factor is therefore BETTER than the entry
  claimed, not worse; the correction is recorded because the doc's
  value is that its facts were checked, and an unchecked one that
  happens to err on the safe side is still unchecked. **Bumped
  (rule-4a re-check at bump time):** `0.4.18` released 2026-08-20;
  RUSTSEC-2026-0258 (unbounded empty DATA frames) was fixed BY
  0.4.16 and stays fixed; the other three advisories against `h2`
  (`RUSTSEC-2023-0034`, `RUSTSEC-2024-0003`, `RUSTSEC-2024-0332`)
  are all patched at versions below 0.4.16 — nothing newer is
  open. Licence unchanged, MIT. Lock delta measured at the bump:
  h2's own version and checksum lines only, ZERO new packages.
  *If the owners stop:* the pin and rule-5 re-justification are
  the mitigations. The dependency is regular, not test-only
  (see below), so a lapse blocks `gran`/the daemon, not just
  the loopback battery. **Landed (checklisted ahead of time
  at the bump):** h2 is a **regular** dependency of
  `granary-client` — the retry classifier's
  `REFUSED_STREAM`/GOAWAY handling downcasts to
  `h2::Error` to identify the failure reason, which needs the
  type in a non-dev position. The manifest edge landed in the
  SAME commit as its first consumer
  (`retry.rs`).
  **`data_frame_budget` evaluated
  at this bump:** the knob lives on h2's own client AND server
  builders — verified at source in 0.4.18 (`client.rs:1169`,
  `server.rs:1063`; 0.4.18's changelog adds it to both). The
  client half matters precisely here: granary-client becomes an
  h2 consumer through this edge and is the side that RECEIVES
  DATA frames, so a reader asking "is there a client-side budget
  knob?" is owed the answer that there is one. The conclusion is
  the same on both
  sides — hyper-util owns both builders, the server's through
  `hyper_util::server::conn::auto` and the client's through
  `hyper_util::client::legacy::Client::builder`, and exposes no
  passthrough on either, so neither side can set it and neither needs
  to. This closes a hazard raised by a
  source reading of h2 0.4.16's small-DATA-frame limiter — reasoned to
  trip on ~100 indeterminate-length PUTs — and which execution REFUTED:
  a measurement of 150 such requests against the shipped envelope found
  no GOAWAY,
  150/150 clean.
  **Evidence currency, stated because that run predates the pin it is
  now cited for:** it executed against h2 0.4.16, and 0.4.17 changed
  this exact limiter (small-DATA-frame accounting now skips END_STREAM
  frames, plus a budget release on buffer clear). Both changes are
  strictly MORE permissive, so a clean run on the stricter 0.4.16 is
  a conservative lower bound for 0.4.18 and the refutation stands —
  but the link was unstated, and only reading the 0.4.17 source closed
  it.

- **`tracing 0.1.44`** — recorded alongside the h2 bump above, whose brief names
  THREE dependency events and this was the third; the record was
  missing and the next task was being told to cite it. Already a DIRECT dependency
  of `granary-net` and `granary-server` at this same workspace pin, so
  `granary-client`'s edge (landing with the retry's
  `tracing::debug!` as its first consumer) adds NO crate, NO lock
  package and NO new ownership exposure — it is a new CONSUMER of an
  already-adopted pin. That is why the record is cheap, not why it was
  optional. crates.io owners, verbatim (API, 2026-08-23): users
  `carllerche` and `hawkw`, plus the team
  `github:tokio-rs:publish-tracing` — team-owned under `tokio-rs`, a
  materially better ownership shape than the single-maintainer entries
  above. Rule 4a: no open advisory at this version; licence MIT.
  *If the owners stop:* the pin is the mitigation and the exposure is
  diagnostics only — a lapse costs `RUST_LOG` output, never a data path.

- **`hyper-rustls 0.27.9`** — regular dependency of `granary-client`
  (the HTTPS connector the through-the-server publish path builds,
  `http1` + `http2` features only). **The initial rule-4b ownership claim was
  "sole-owner `seanmonstar`", and that is WRONG** — recorded here
  because a finding is a finding about the registry, not about which
  GitHub org a reader assumed. crates.io owners, verbatim (API,
  2026-08-20): users `ctz` (Joe Birr-Pixton) and `djc` (Dirkjan
  Ochtman), plus the team `github:rustls:publishers`. The repo is
  `github.com/rustls/hyper-rustls` — the **rustls** org, not `hyperium`
  — so the ownership story is the `rustls-pki-types` entry's above
  and not the `hyper-util` entry's: an org team plus two named
  maintainers, under the same project whose core crates this workspace
  already pins. Passes 4a comfortably: `0.27.9` released 2026-04-14,
  ~4 months; no open advisory; licence `Apache-2.0 OR ISC OR MIT`,
  all three already on deny.toml's allow list, so no new exception.
  Rule 2: **ZERO new lock packages** — `Cargo.lock` holds 310 packages
  before and after, and hyper-rustls was already resolved at exactly
  `0.27.9` via `object_store → reqwest`; the only lock movement
  is granary-client's own edge list. Rule 3: `build = false`, no
  proc-macro anywhere in its own manifest. *If the named owners stop:*
  rustls itself stops with them, and this crate adds no marginal
  exposure beyond the TLS stack it wires into hyper. Mitigations are
  the exact pin and the rule-5 annual re-justification. **Rule 1,
  considered and declined.** The crate's value is not convenience:
  `HttpsConnector` is what binds the negotiated ALPN token to
  hyper-util's h1/h2 selection (`Connected::negotiated_h2`),
  and a hand-rolled `Service<Uri>` that got that wrong would
  silently serve HTTP/1.1 over an `h2`-negotiated connection — the
  defective-connector case the test asserting the served HTTP version
  on both ALPN legs exists to catch. That is protocol state, not a
  helper.

- **`httpdate 1.0.3` — FAILS RULE 4a, and this is its written
  exception.** Latest release **2023-08-13, ~36 months old** against 4a's
  24-month floor. Sole owner `pyfisch` (user; no team), personal
  namespace, no RUSTSEC advisory, repo not archived.
  **The failing criterion is RECENCY — the mechanical one — not
  ownership**, and rule 2 offers no escape: its text is "budget the
  transitive **closure**, not the direct dependency", so arriving
  transitively via hyper's `server` feature does not exempt it.
  *Accepted anyway* because it is an HTTP-date formatter whose input
  format is frozen by RFC 9110 — a crate with nothing left to do is the
  expected steady state for it, and enabling hyper's `server` feature is
  what pulls it in. **Say plainly what this costs: the 24-month floor
  becomes advisory for this crate.** If that trade is unwanted, the
  alternative is a hand-rolled IMF-fixdate formatter, which is genuinely
  inside rule 1's ~200 lines.

- **`libc 0.2.189`** — regular dependency of `granary-client` for
  the client cache's `FreeSpace` seam (`statfs` on macOS, `statvfs`
  on Linux — kernel interfaces, rule 1's canonical never-hand-roll
  category) and the macOS plain-`fsync` call the cache requires (std's
  `File::sync_all`/`sync_data` both issue `fcntl(F_FULLFSYNC)` on
  Apple targets, which the cache must not use). crates.io owners,
  verbatim (API, 2026-08-23): a single user, `rust-lang-owner` —
  institutional ownership recorded as one account, the exact shape
  the rule-4b amendment above discusses by name (the removed headcount
  threshold would have scored this WORSE than a personal-namespace
  crate while it is in fact the Rust project's own). Rule 4a: `0.2.189`
  released 2026-08-03 (~3 weeks old at this check, comfortably inside
  the 24-month floor); no open RUSTSEC advisory at the pin; licence
  `MIT OR Apache-2.0`, both already on deny.toml's allow list. Rule 2:
  **ZERO new lock packages** — `libc =0.2.189` has been in `Cargo.lock`
  throughout via `cpufeatures → libc` (the approved transitive edge
  under `blake3`); this is the crate's first DIRECT edge, changing only
  `granary-client`'s own dependency list, not the package set. Rule 3:
  libc's `build.rs` (a `rustc`-version cfg probe, no codegen) is already
  on `deny.toml`'s `allow-build-scripts` list and already recorded in
  `supply-chain/inventory.txt` — the new direct edge adds no build-time
  execution that was not already in the graph. *If the named owner
  stops:* `libc` is the Rust project's own crate — its continuity is the
  Rust project's, not one maintainer's personal availability — and the
  mitigations are the exact pin and the rule-5 annual re-justification,
  same as every other entry here.

### The FUSE mount dependency event (fuser, nix)

Landed in one commit: `cargo-shear` fails a `[workspace.dependencies]`
entry no member consumes, and `cargo deny check` goes red the moment
`fuser`'s manifest line lands, so the manifest edit, the four
`deny.toml` `allow-build-scripts` entries, the regenerated inventory and
the first consumers (`options.rs`, `unmount.rs`) are one commit or the
tree is red between them (R13's probe, with a baseline control).
Checklist run and owners retrieved 2026-08-30.

- **`fuser 0.18.0`** — regular dependency of `granary-fuse` (the
  read-only FUSE mount). Rule 1: a kernel/wire-protocol interface —
  the canonical never-hand-roll case; FUSE's request/reply ABI is not
  something to reimplement. Rule 2: measured lock delta at adoption is
  **+13 packages across the whole closure** (`cfg_aliases`, `fuser`,
  `memoffset`, `nix`, `num_enum`, `num_enum_derive`, `proc-macro-crate`,
  `ref-cast`, `ref-cast-impl`, `toml_datetime`, `toml_edit`,
  `toml_parser`, `winnow`), 0 removed.
  Rule 4a: `0.18.0` released 2026-07-22 (~5 weeks old at this check);
  licence MIT; `cargo deny check advisories` clean at this pin. crates.io
  owners, verbatim (API, 2026-08-30): sole user `cberner` (Christopher
  Berner; no team) — the crate's own maintainer, and also libfuse's
  Rust-binding author of record. Rule 3: `fuser`'s own `build.rs`, read
  at `~/.cargo/registry/src/index.crates.io-*/fuser-0.18.0/build.rs`:
  under the `macos-no-mount` feature this workspace pins (on every
  platform, not target-gated), it emits ONLY
  `cargo::rustc-cfg=fuser_mount_impl="macos-no-mount"` on macOS, or
  `"pure-rust"` on Linux without the `libfuse` feature — no pkg-config
  probe runs, no C compiles, no code is generated, in the configuration
  this workspace actually ships. (The same file's other branches —
  libfuse2/libfuse3 detection via `pkg_config` — exist in the source but
  are unreachable under this feature set.)
  *If the named owner stops:* `fuser` is the FUSE crate this ecosystem
  has converged on, wrapping a stable kernel ABI rather than an evolving
  one; a fork is viable if not urgent. Mitigations are the exact pin and
  the rule-5 annual re-justification.

- **`nix 0.31.3`** — already in the closure via `fuser` (which enables
  the `mount` feature itself); this is `granary-fuse`'s own DIRECT edge,
  costing ZERO new packages and ZERO new features, for the Linux-only
  `nix::mount::umount2` call in `unmount.rs` — the SAFE syscall
  wrapper that is why `unsafe_code = "forbid"` stays on in `granary-fuse`
  (probed: `nix`'s own Apple mount module has no `umount2` or
  `MntFlags::MNT_DETACH`, which is why the call site is
  `#[cfg(target_os = "linux")]`). crates.io owners, verbatim (API,
  2026-08-30): user `carllerche` (Carl Lerche) plus the team
  `github:nix-rust:nix-maintainers` — an org team AND a named
  individual, a stronger shape than `fuser`'s single-maintainer entry.
  Rule 4a: `0.31.3` released 2026-05-11; licence MIT; no open advisory at
  this pin. Rule 3: `nix`'s `build.rs` (same registry path pattern,
  `nix-0.31.3/build.rs`) runs the `cfg_aliases!` macro (a
  compile-time-only cfg-emission helper) plus two
  `cargo:rustc-check-cfg` lines — no codegen, no C.
  *If the named owners stop:* the crate is the de facto standard `*nix`
  syscall binding, with an org-backed maintainer team; continuity risk
  is low. Mitigations are the exact pin and rule-5.
  **`granary-server`'s direct edge** (same pin, `features = ["fs",
  "user"]`): the enrollment directory's descriptor walk and the
  enrollment verbs' file mechanics (`protected_dir`, `enrollment`) need
  the `*at` family (`openat`, `fstatat`, `renameat`, `unlinkat`),
  `fstatfs`, `flock`, `fchown` and `geteuid`, which std lacks and which
  through `libc` would need `unsafe`, forbidden in that crate. ZERO new
  packages and ZERO new features: `fuser` already enables `fs` and
  `user` in the workspace graph, so this is a direct edge from a crate
  that did not have one, not a new node. The manifest line's comment in
  `crates/granary-server/Cargo.toml` carries the same reasoning.

**`log` — NOT a direct edge, and no granary-owned `log::Log` bridge.** Neither a
direct `log 0.4.33` edge nor a `granary-fuse` module installing a
`log::Log` that forwards into `tracing` exists. The premise for one —
"granary is a `tracing` workspace with no bridge, so every fuser
diagnostic — including 'Reply not sent' — is silently discarded" — is
**false**, verified link by link in the
pinned crates: `tracing-subscriber 0.3.23`'s `default` features include
`tracing-log`; the workspace pin does not set `default-features = false`
on it; `tracing-subscriber`'s `try_init()` installs a
`tracing_log::LogTracer` into the global `log` slot as part of that
default; every `gran` entry point, including the `mount.gran` argv[0]
dispatch, passes through `granary-cli/src/main.rs`'s `main()`, whose
`.init()` runs before any `granary-fuse` code; and "Reply not sent" is a
`warn!`, which passes the default INFO filter and is printed today. A
bridge installed from `granary-fuse`, which runs only after `main()`'s
`.init()`, could therefore never install in the shipped binary (the slot
is always already owned), and installing one before `.init()` instead
would make `.init()`'s `LogTracer` install fail and `gran` panic at
startup. The one real argument for such a module — that a future edit
could disable `tracing-log` and go unnoticed — lives as a gate in this
repository's pre-push battery rather than as a module, under the name
`tracing-log wiring`.

**`ref-cast`'s build script — the fourth that `deny.toml` allows for
the `fuser` closure — is NOT cfg-emission-only, and the `deny.toml`
entry says so.**
`ref-cast 1.0.27`'s `build.rs` (read at
`~/.cargo/registry/src/index.crates.io-*/ref-cast-1.0.27/build.rs`) is
**not** cfg-emission-only, which is why its `deny.toml` comment
differs from its three siblings'. It ALSO writes a generated file,
`$OUT_DIR/private.rs`,
containing a fixed template —

```rust
#[doc(hidden)]
pub mod __private<PATCH> {
    #[doc(hidden)]
    pub use crate::private::*;
}
```

— with `<PATCH>` substituted from the crate's OWN
`CARGO_PKG_VERSION_PATCH` (not any externally- or attacker-reachable
input), which `src/lib.rs:185` then `include!`s into the crate. This is
`dtolnay`'s standard version-namespacing idiom for avoiding proc-macro
ABI collisions across multiple versions of the same crate in one
dependency graph, and the practical exposure is close to nil — the
generated content is a fixed string with a numeral substituted from the
crate's own manifest, never from untrusted or network-sourced input.

The [build-script allowlist](../deny.toml) records that three of the four
scripts in this group only probe their build environment or set configuration.
The `ref-cast` exception is accepted at the exact version in that list.
Its build script substitutes only the crate's own version numeral into a
fixed template. External input cannot affect the generated file. Bumping the
pin reopens the review.

## Applied decisions

- **Rule 4a exception: `chrono` and `humantime` are unmaintained
  (2026-11-17).**
  - **The criterion that failed:** rule 4a's "no open RUSTSEC
    advisory". The advisories are RUSTSEC-2026-0543 (`chrono`, all
    versions) and RUSTSEC-2026-0542 (`humantime`, flagged by its
    advisory because `chrono` is unmaintained). Both are
    *unmaintained* notices, not vulnerabilities.
  - **Why it is accepted anyway:**
    - Both arrive only as non-optional dependencies of
      `object_store`, at the pinned `=0.14.1` and at the latest 0.14.2
      (2026-09-15, checked against the crates.io dependency API).
      Granary calls neither crate directly.
    - Moving the pin does not escape them, and `object_store` is the
      storage seam, pinned on purpose. Replacing it would be a
      superseding decision, not a dependency tweak.
    - An unmaintained notice changes no code that runs today.
  - **How the gate records it:** `deny.toml` ignores exactly these two
    IDs, each with a reason that points here.
  - **Exit condition.** End the exception when an `object_store`
    release drops both crates or makes them optional, or when either
    advisory is upgraded beyond unmaintained. Re-check at every
    `object_store` bump and at the annual rule-5 pass.

- **rustls/tracing/tracing-subscriber adoption** (recorded here
  2026-08-09): rustls for TLS, its default provider being aws-lc-rs
  with a documented FIPS mode; tracing and tracing-subscriber for
  `EnvFilter` plus `fmt` output, with JSON output in the server.
- **CLI parsing.** `gran` parses arguments in its own command handlers and
  provides the usage text. Neither `lexopt` nor `clap` is a direct CLI dependency.
- **Server configuration.** The server reads named environment variables.
  See [Operating the server](operating-the-server.md) for the supported
  settings. Adoption of a TOML configuration parser is deferred. Revisit
  it at the second server deployment or when a store configuration first
  needs structured values such as a per-bucket table or a list of records,
  whichever comes first. Repeat the rule 2 measurement with the current
  toolchain, including the dependency tree, build scripts, procedural macros
  and RustSec advisory history.
- **`granary-core` holds the hard line**: no proc-macro dependencies, no
  build.rs dependencies, no tokio, no I/O. Hand-rolled error enums with
  manual `Display` (no thiserror in core); derive-free serde only where
  the wire needs it; every hashed object uses canonical hand-written
  encoding. One named, version-pinned exception: blake3 — the settled
  grain-identity hash; its build-script exception in deny.core.toml is
  pinned `=1.8.7` so every upgrade re-opens the review.
- **blake3 dependency exception under rule 6.** Version 1.8.7 uses
  `arrayvec`, `cfg-if` and `constant_time_eq` at runtime, plus
  `cpufeatures` on x86. Its C build also pulls in `cc` and that
  crate's build tool dependencies. The resolved tree exceeds the
  five-crate guideline. Use `cargo tree --locked -p blake3` to see
  the exact versions on your target. The licence exception lists in
  `deny.toml` and `deny.core.toml` cover the resolved tree.
  Justification under rules 1–2: consensus crypto is the canonical
  never-hand-roll dependency; no buildscript-free implementation
  exists (full crates.io scan 2026-08-09); the official crate is the
  BLAKE3-team-audited reference with SIMD. Mitigations: exact pin,
  version-pinned gate exception (bump = deliberate two-edit event with
  a build.rs skim), golden-hash vectors diffed across the 3-platform CI
  matrix per merge, zero RUSTSEC history.
- **Bench/test heavyweights: criterion and proptest, adopted as
  dev-dependencies with eyes open** (rule-6 memo).
  Measured trees: criterion ~58 crates including serde_derive +
  zerocopy-derive proc-macros and cc; proptest ~29. Justification under
  rules 1–2: statistical benchmarking (the K4 number's credibility) and
  shrinking-based property testing are both far beyond 200 lines to
  hand-roll credibly, and both are dev-only — never in shipped artifacts,
  never in the purity-gated core graph. Mitigations: exact pins, dev-dep
  trees included in the build.rs/proc-macro inventory diff, annual
  re-justification. divan was considered and rejected (dormant since
  2025-04); quickcheck rejected on shrinking model, not maintenance (it
  revived Feb 2026).
- **alloca in the criterion dev tree (rule 3, 2026-08-09)**: compiles
  a small C shim via cc at build time — the sharpest of the nine
  dev-tree build-script allows in deny.toml; version-pinned `=0.4.0`
  there so any bump re-opens review; dev-only, never in shipped
  artifacts (the purity gate and dep-inventory diff are the tripwires
  if it ever migrates).
- **serde_derive in the binaries' trees (rule 3, 2026-08-09)**:
  json-structured daemon logs justify tracing-subscriber's `json` feature;
  serde_derive rides in as its proc-macro — dev-machine/CI build-time
  only, never in granary-core, whose gates prove it.
- **Accepted heavyweights, eyes open** (they *are* the product): quinn
  (~731 K transitive SLoC), aws-lc-rs (~2 M SLoC of C/asm behind a cc
  build), zstd (C build), blake3 (cc + assembly everywhere: hand-written asm on
  x86-64, vendored NEON C on aarch64 — its `pure` feature keeps Rust
  SIMD intrinsics only on x86; on aarch64 it drops NEON entirely, 1.87×
  slower measured on the M4, and removes neither build.rs nor cc from
  the graph), tokio, fuser,
  object_store.
  These are the dependencies that pass rule 1 because hand-rolling them
  would be strictly worse — including for security.
- **zstd adopted (rule-1 format/compression exception; 2026-08-10)**:
  `zstd =0.13.3` / `zstd-safe 7.2.4` / `zstd-sys 2.0.16+zstd.1.5.7`, vendoring
  zstd C 1.5.7 — **3** new lock packages, `default-features = false` plus
  `zdict_builder`. Justification: the storage format uses per-grain zstd
  frames, and the bench metric is post-compression bytes, so the number
  must come from the code production will run. The crate, not the CLI:
  CLI/crate byte-identity breaks above ~393 KiB and the CLI's answer depends
  on threading mode. Rule-3 mitigations: two
  version-pinned `allow-build-scripts` entries (`zstd-sys` compiles the
  vendored C via `cc`; `zstd-safe` is a cfg probe), so any bump re-opens the
  build.rs review; no bindgen on this path. Licence at adoption `MIT`
  (zstd) and `MIT/Apache-2.0` (zstd-safe, zstd-sys); all three are
  `BSD-3-Clause` from 0.14.0 / 7.3.0 / 2.1.0 on — `cargo deny check`
  licences pass with no new exception either way. Its
  `bans` check does NOT pass with zero new entries; the two entries above
  are required.
  **Bumped 2026-10-26** to `zstd =0.14.3` / `zstd-safe 8.2.0` /
  `zstd-sys 2.1.2+zstd.1.5.7` for RUSTSEC-2026-0391/0398/0403/0410: same
  three lock packages, no new build-time crate. The licence changed to
  `BSD-3-Clause` (upstream zstd's own), which is on deny.toml's allow list.
  *Grain frames are byte-identical:* the vendored `zstd/lib` C tree is
  byte-identical between 2.0.16 and 2.1.2 (`diff -r`; 2.1.2 only adds the
  unused `build/` cmake tree and `libzstd.pc.in`); granary-store's
  `frame_golden` (`zstd_frame_golden_vectors`, whose compressible case
  runs the entropy coders) passes against the committed `frame_v1.txt`
  locally and in CI; and 52 grains (1 B to 8 MiB; random, text-like,
  zero, periodic) through one reused level-3 `bulk::Compressor` wrote
  identical output under 0.13.3 and 0.14.3 (sha256 `7eba3ab3348f0110c8a118722bb89e423a4c46f8d67fc7d95f9f0c809c52cae5`
  for both).
  *Build-script review (rule 3), 2.0.16 → 2.1.2,* for the resolved
  feature set `std, zdict_builder` (no bindgen, cmake, seekable, legacy,
  zstdmt, debug, pkg-config, vendored) and an environment that sets no
  `ZSTD_SYS_*` variable:
  - **cmake backend:** new, behind the `cmake` feature and the optional
    `cmake` build-dependency; neither resolves, so the cc path
    (`compile_zstd`) runs as before.
  - **pkg-config:** now taken only when `pkg-config` is on *and*
    `vendored` is off, or `ZSTD_SYS_USE_PKG_CONFIG` is set; neither
    holds, so the vendored C is compiled as before.
  - **asm:** `huf_decompress_amd64.S` is now added only on x86_64 (and not
    Windows or `no_asm`); elsewhere `ZSTD_DISABLE_ASM` is defined. On
    x86_64 Linux the build is unchanged. On aarch64 the old build
    assembled the file to an empty object, and the new define only forces
    `ZSTD_ENABLE_ASM_X86_64_BMI2` to 0, which `portability_macros.h`
    already gave it off x86_64 — no code change.
  - **visibility:** `-fvisibility=hidden` stays on unless
    `ZSTD_SYS_NO_HIDE_SYMBOLS` is set (new opt-out, also skipped on an
    MSVC target); granary sets it nowhere, so libzstd symbols stay hidden
    as before. `XXH_PRIVATE_API` and the empty `*_VISIBILITY` defines are
    unchanged.
  - **DEBUGLEVEL:** set to 5 only under the `debug` feature (off), so
    zstd's release default (0) holds, as before.
  - **seekable:** new code is all under the `seekable` feature (off);
    nothing in `contrib/seekable_format` is compiled.
  - **wasm shim:** the build-script half applies only to wasm32-unknown /
    wasi targets and `src/wasm_shim.rs` is `cfg(target_arch = "wasm32")`;
    no granary target reaches either.
  - **bindgen:** only an added derive callback, behind `bindgen` (off).
  zstd-safe 8.2.0's build.rs is byte-identical to 7.2.4's: it forces the
  `std` cfg on wasm32/hermit and does nothing else.

## Development tools that run but do not ship

The rules above govern crates that enter `Cargo.lock` — reachable by
`cargo`, hence by rule 3's build-time-execution threat and rule 4's
maintenance floor. A CI/local-gates tool invoked as its own binary is a
different shape: it never appears in a manifest or a lock file, never
links into a shipped artifact, and its licence obligation is "runs on
the build machine," not "ships with the product" — so a copyleft licence
that would be disqualifying on the `cargo deny` allow-list is not a
concern here. Pinned by VERSION (a git-sha pin, the norm for a GitHub
Action, does not apply to a tool a pinned action *installs*).

- **shellcheck 0.11.0** (`scripts/check-shellcheck.sh`), licence
  GPL-3.0-or-later. Installed in CI from `taiki-e/install-action`'s
  supported-tools list at the pinned version; installed locally with
  `brew install shellcheck` (dev-environment.md's checklist). It reads
  and reports on shell scripts and is never linked into or distributed
  with any granary binary.
- **reuse** (`reuse lint`, this repository's own licence-header gate) is
  already in this same class and carries the same GPL-3.0-or-later
  licence as shellcheck — installed via `uv tool install reuse`
  (dev-environment.md), invoked as its own binary, never a dependency of
  anything shipped.
- **pjdfstest (C suite), commit
  `85a8aea9e685999ef0540392fd80535f873d7ff7`** — BSD-2-Clause
  (`COPYING` and `pjdfstest.c` in [upstream](https://github.com/pjd/pjdfstest)).
  Installed by `scripts/posix-tools.sh`: clone from upstream, detach at that
  commit, `autoreconf -ifs`, `./configure`, `make -j2 pjdfstest`. The explicit
  commit pin is used for this source-built conformance suite, as requested by
  its bring-up contract; upstream's configure version is only `0.1`, not a
  unique source pin. `scripts/posix.Containerfile` installs the build/runtime
  prerequisites and builds into `/opt/posix`. Invoked as separate test
  processes against a disposable writable mount, never linked or shipped.
- **xfstests v2025.08.04, commit
  `3d57f543ae0c149eb460574dcfb8d688aeadbfff`** — GPL-2.0-only for the
  selected tests, with GPL-2.0-or-later common helpers (see upstream
  `LICENSES/GPL-2.0` and per-file notices).
  [Upstream release](https://kernel.googlesource.com/pub/scm/fs/xfs/xfstests-dev/+/refs/tags/v2025.08.04).
  Installed by `scripts/posix-tools.sh`: clone the kernel.org repository,
  detach at that release's commit, `make -j2`; prerequisites are installed
  in `scripts/posix.Containerfile`. Invoked through its own `check` executable
  as a development conformance tool, never linked or shipped. A pin update
  requires rechecking the selection, result grammar and triage identities.
- **zizmor** (workflow security linting) and **cargo-deny**/**cargo-shear**
  (the licence/advisory gate and the unused-dependency gate rule 3
  already names) are the same class under more permissive licences —
  MIT, and MIT OR Apache-2.0 respectively — so they were never a licence
  question; they are named here only so this section does not read as
  though shellcheck were the sole tool of this kind in the CI pipeline.
