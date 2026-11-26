<!-- SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Client publication configuration

`gran publish` uses authority publication for served volumes on pinned server
routes. The default `--publish-mode auto` runs the recovery coordinator. A
server without authority endpoints requires explicit
`--publish-mode legacy-server`. An unserved fallback identifies its route and
exact checked status evidence on stderr and its success record.
In `auto`, fallback requires both preflight and coordinator bootstrap to answer
`404 unknown-volume` on a fresh publication before any POST. An observed
preflight followed by bootstrap `unknown-volume` refuses without a root PUT.

| Option | Checked value and precedence |
|---|---|
| `--client-cert FILE` | Nonempty native filesystem path; every occurrence is checked; last wins. |
| `--client-key FILE` | Nonempty native filesystem path; every occurrence is checked; last wins. |
| `--credential-context NAME` | Exact UTF-8 ASCII `[A-Za-z0-9._-]{1,255}`; every occurrence is checked; last wins. |
| `--publisher-key KEY` | Exactly `ed25519:` followed by 64 lowercase hex digits; nonzero; occurrences accumulate. |

New options refuse missing and flag-shaped values. Existing options retain their
value-consumption rules. Unknown publish options use a fixed diagnostic without
rendering the option or its value. Credentials, context and publisher trust come
only from explicit flags. There is no credential discovery or configuration-file
layer. Repeated `--pin` values accumulate and replace the entire `GRANARY_TLS_PINS`
fallback. An absent pin option permits that fallback; an empty or blank fallback
refuses. The transport verifier's eight-input-entry cap applies before deduplication.

Certificate and key must be supplied together. Each new option is server-only and
refuses `--direct-s3`. Context without a pair and a pair without context are valid
configuration. Missing/invalid new values, half pairs, and static direct-S3 conflicts
are usage refusals (exit 2). Publisher trust omitting the loaded signing public key,
endpoint userinfo, and publisher keys on a selected direct seam are local configuration
refusals (exit 1). Credential file, custody, size, PEM and correspondence failures are
also local refusals (exit 1).

The certificate file is public. The key is loaded once through a custody-checked
regular-file descriptor: effective-UID ownership, restrictive permissions, exactly
one link, and no granting macOS ACL. Identity is captured from that descriptor
before reading its bounded PEM content. A failed configured load never becomes an
anonymous client. Diagnostics use fixed certificate-file, key-file/custody,
certificate-content, key-content, and key/certificate-mismatch messages; neither
Display, Debug nor source chains render PEM labels, provider text or private bytes.

A credential-aware server route constructs one `HttpStore` with the checked
credential installed before its pool is created. Construction sends no request and
reads no bucket credentials. Callers use that same store for status, probes, reads,
uploads, authority requests and hint writes. Reloading a credential constructs a
fresh store and pool. Direct-S3 refuses a supplied client credential before builder
or environment access; the server route refuses a bucket.

Publisher signing trust is separate from TLS server pins, client certificates and
enrollment digests. Its default is the current signing key alone. Explicit keys
replace that default and must contain the exact signing public key; construction
never appends it implicitly. Overlapping old/new publisher keys and duplicates are
supported. Explicit publisher trust requires authority publication, including when
it contains only the current signer. Direct-S3 and selected direct server seams
cannot consume it. The loaded TLS key is never the root signer.

A checked status answer other than `unknown-target` identifies an authority-configured
server, including `unknown-volume`, `no-log`, service failures and `internal`.
Transport, TLS and malformed-peer failures supply no classification. Authority write
admission must require the pair for every such server write, and context for authority
publication; these status-dependent refusals are local configuration errors (exit 1).
The classification alone grants no write or fallback permission.

Context is an operator declaration of principal continuity, never a transmitted
principal or a verified enrollment claim. Reusing a context with a credential enrolled
to another principal resumes bookkeeping under that declaration; the authority's
authorization fails closed. Names are never inferred from a credential, trimmed or
case-folded. Scope keeps the exact validated endpoint bytes (1–8192 bytes), exact
context bytes, and a nonempty validated pin set sorted by raw bytes and deduplicated.
Endpoint spelling or context changes select a different directory digest. Pin changes
preserve that digest but still refuse full-scope loading; there is no automatic
migration or pin update. Configure pin overlap before retaining a publication.

Protected harvest takes the signing-seed identity and the TLS-key identity. Every
matching opened file, including a nested hard link created after loading, refuses the
whole harvest before reading its grains or making publication writes. Descriptor closure and
path replacement do not change the captured identity. Ordinary and singular harvest,
prepare and publish APIs remain compatibility wrappers.
The TLS-key path must also be outside the store and cache roots, whose `txn/`
sweeps would otherwise unlink it. These checks apply to retained recovery too.

Endpoint guards apply to all client consumers, including `gran cat` and `gran mount`:
userinfo in the authority is forbidden, even empty userinfo; `@` in the path remains
valid. Malformed endpoints and userinfo errors do not render rejected URL bytes.
Direct-S3 applies the same userinfo guard while retaining HTTP/HTTPS support.


Before fresh harvest, the source and configured TLS key parent are resolved
separately. A source containing that parent, including through symlink aliases,
refuses. Resolution errors refuse. This check repeats at the harvest boundary;
it protects a replacement key renamed to the configured pathname. Resume and
abandonment do not inspect the source.

## Routing and retained selection

`--publish-mode auto|authority|legacy-server` defaults to `auto`. Explicit modes
conflict with `--direct-s3`. An observed authority status selects the coordinator
in auto/authority and refuses legacy-server. `unknown-volume` permits a server
seam in legacy-server; auto permits it only when both preflight and the
coordinator's bootstrap return that exact token on a fresh publication before
any publication POST. `unknown-target`
requires explicit legacy-server. `no-log` always refuses: initialise the log.
Other checked refusals stop, 503 is Pending, and internal or malformed responses
are BackendError. TLS, connection and deadline failures before submission are
local failures. Stop answers need no credential pair just to report the refusal.
A configured server seam requires the pair; authority publication also requires
context. Every direct seam refuses explicit publisher trust, even singleton self
trust. There is no fallback from retained recovery or a publication answer.

Selection happens under the original Store's exclusive lock before routing or
source work. An ordinary invocation resumes the exact live record; a Complete
record repeats reporting and advisory repair without another POST. Retained
state requires the original store, exact endpoint spelling, context and pins.
Source absence or changes do not imply a new publication. Use `-` for the unused
source operand on resume or abandonment. Direct routes also check live state
across all scopes and refuse every incomplete publication.

`--recover ID` must name the exact live publication; it authorizes another read
cycle after an interrupted/unresolved probe or loaded rebase. An ordinary rerun
uses Continue and does not grant that authorization. IDs are exactly 32 lowercase
hexadecimal digits, including the all-zero value. `--new`, `--recover` and
`--abandon` are mutually exclusive.

An ordinary archive-only invocation, or recovery of an archived/missing ID,
refuses with exit 4 and an explicit-new remedy. `--new` acknowledges that archived
work may still land and identical content can become another committed version.
It refuses any incomplete live record. It can replace Complete. The explicit-new
journal adapter applies this acknowledgement to the coordinator's internal load
as well as initial selection; it does not relax custody or scope checks.

## Recovery and local abandonment

Capacity-exhausted Unresolved and persistently open Pending both retain candidates.
Use the same original store and scope flags:

```sh
gran publish /absolute/store - vol --endpoint https://server --pin sha256/... \
  --key-seed /private/seed --client-cert /private/cert --client-key /private/key \
  --credential-context writer --recover 07070707070707070707070707070707

gran publish /absolute/store - vol --endpoint https://server --pin sha256/... \
  --credential-context writer --abandon 07070707070707070707070707070707 \
  --acknowledge-may-land
```

Abandonment requires endpoint, pins, context, volume, ID and the separate
`--acknowledge-may-land` flag. It loads no signer or credential files and creates
no runtime or transport. It rejects direct-S3, cache and wire-output options.
It accepts changed pins, reports their difference, and preserves all candidates
in the store-provided archive. Complete cannot be abandoned. Archive retries are
idempotent. Recovery stops locally; publication may still land. Abandonment is
not cancellation and does not unblock the volume: a wedged volume remains
unavailable to every publisher until out-of-band repair.

## Results, JSON and exit codes

These exit meanings apply to **gran publish alone**; other verbs keep their own
contracts (mount uses exit 3 for cache-close failure). Publish parse failures use
exit 2; operators relying on exit 1 for parse failures must update their scripts.

| Exit | Outcome |
|---|---|
| 0 | Landed, or successful local Abandoned action |
| 1 | Local configuration, custody, preparation, persistence or output failure |
| 2 | Usage error |
| 3 | Pending: bounded work stopped |
| 4 | Refused: named refusal or incompatible retained selection |
| 5 | Unresolved: explicit recovery, capacity, missing-content or direct uncertainty |
| 6 | BackendError: unusable peer response, a failed remote store call (on either route) or remote verification evidence |

Authority success prints `published <volume> seq=<seq> id=<root-id>
publication=<publication-id> route=authority evidence=<receipt|chain>`.
Direct success retains `published <volume> seq <seq> epoch <root-epoch>` and
summary lines; server-seam success appends `route=server-seam`. Non-landed
results and advisories go to stderr. “submission retained” requires known live
record evidence. Fresh Pending says “no submission started” and recommends
rerunning the invocation, without inventing an ID. Persistence failure reports
the known locator and uncertain durability. Coordinator uncertainty is preserved;
it is not inferred again from the latest answer.

Standalone `--json` in option position emits one final newline-terminated object
on stdout for every route and for local/usage failures. A flag value spelled
`--json` does not enable JSON. No human prefix is printed on stdout. Output
failure exits 1, reports any known landing or archival on stderr, and cannot
promise an object on stdout.

Schema v1 always includes these fields; unavailable values are explicit nulls:

| Fields | Contract |
|---|---|
| `schema_version`, `action` | 1; `publish` or `abandon` |
| `route`, `volume`, `publication_id` | authority, server-seam, direct-s3, local or null; selected names/ID or null |
| `outcome`, `exit_code`, `uncertain`, `retention` | typed outcome; code above; unchanged publication uncertainty; none/live/archive/unknown |
| `routing_evidence`, `response` | checked `{status,token,kind}` or null; registered tokens only |
| `diagnostic`, `next_action` | sanitized diagnostic; `{action,publication_id}` remedy or null |
| `completion` | `{seq,id,manifest_root,root_epoch,evidence,receipt}` or null; receipt is genuine `{epoch,position}` or null |
| `archive`, `pin_difference` | store-provided locator; `{retained,configured}` public pin bytes as hex or null |
| `cache`, `hint` | `{result,reason}` with written/skipped/failed/not-configured/not-attempted results |
| `metrics` | invocation response bytes; direct publication counters or null historical publication costs |

Receipt epoch/position belong to the authority log. Root epoch and manifest are
decoded from the actual winning root and remain null if decoding fails. Exact
root/answer bytes, private material and raw provider diagnostics are never output.

## Completion and advisory repair

Only Landed Completion supplies authority output, root-cache bytes, anchor and
hint sequence. A historical winner can differ from the latest candidate. The
winner is checked under publisher trust, and separately under the cache origin's
single signing key before root admission and floor advancement. An old-key
winner excluded by that origin skips both cache operations; its sequence still
drives the independent hint write through the same configured transport. Higher
cache floors and persisted hints are preserved. Advisory failure leaves Landed
at exit 0; a later Complete redisplay repeats repair without POST. Abandoned and
non-landed outcomes perform no completion repair.

Wire snapshots use winner sequence/manifest. Authority publication counters are
null because retained submissions do not preserve historical costs. Direct
counters remain numeric. The snapshot now writes an explicit `publish: null`
where no publish block is available, including non-publish invocations; this is
a deliberate schema change from omission. Retained-submission v1 bytes, cache
markers and authority request/answer formats are unchanged.
