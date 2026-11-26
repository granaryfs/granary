<!-- SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Operating the granary server

Run `granary-server` without arguments to serve. For local administration use
[`enrollment`](operating-enrollment.md) to manage client credentials,
[`debug-grant`](operating-debug-grants.md) to manage diagnostic grants,
[`support-export`](operating-support-export.md) to collect a support archive,
or [`initialise` and `unfence`](operating-the-authority-lifecycle.md) to
manage the authority log. Unknown commands exit with a usage error.

The server reads named environment variables at startup. Restart it to apply
configuration changes.

Exit codes: **0** drained cleanly · **1** serving failed · **2** startup refused
(nothing was served; every refusal, including a host refusal, carries
`startup failed: <reason>` on stderr naming what is at fault; the write waits
at most 250 ms, so a wedged stderr, or a machine too loaded to run the writer
within that, loses the line but not the exit code) · **3** the drain or authority-stop deadline expired · **4** the publication
authority fenced. An observed fence takes precedence over deadline expiry and clean drain.

## The boot variables

| variable | required | what it holds |
|---|---|---|
| `GRANARY_LISTEN` | yes | `host:port` to bind; port `0` picks one, and the readiness line reports the bound address |
| `GRANARY_TLS_CERT` | yes | PEM file holding the certificate chain |
| `GRANARY_TLS_KEY` | yes | PEM file holding the private key |
| `GRANARY_STORE` | yes | `memory:` (nothing durable) or `s3:` |
| `GRANARY_STORE_BUCKET` | with `s3:` | the bucket, which must already exist: the server never creates it |
| `GRANARY_STORE_ENDPOINT` | with `s3:` | the endpoint URL; its scheme (`http://` or `https://`, any case) decides plaintext |
| `GRANARY_STORE_REGION` | with `s3:` | the region |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` | no | store credentials; absent, the store's own provider chain is used. No other `AWS_*` variable is read |
| `RUST_LOG` | no | log filter; `info` by default. Logs are JSON lines on stderr |

`GRANARY_WIRE_SNAPSHOT`, `GRANARY_WIRE_RUN_ID` and `GRANARY_WIRE_ROLE` are test
harness instrumentation, all three or none outside authority mode; setting any
of them in authority mode refuses startup because wire snapshots are not
available there. A deployment sets none of them.

## Request logging

Baseline request spans record `wire_request_id`, bounded to at most 64 ASCII
letters, digits, dots, underscores or hyphens; malformed values are omitted, and
the field is never a counter key. The value comes from the client's
`Granary-Request-Id` header, is not authenticated, and can collide with another
client's id, so it joins logs but proves nothing about who sent them.

## Scoped diagnostic capture

The host installs one immutable `RUST_LOG` ceiling above all observers. Its
in-process `CaptureHandle` starts empty and supports only authenticated-write
admission at DEBUG. The shipped binary has no operator activation path and never
calls `replace`; the seam remains empty. A later authorized grant requires
`RUST_LOG=info,granary_server::scoped_capture=debug` and a restart as a precondition.
That setting alone activates nothing. Default INFO and a more-specific INFO/OFF
directive refuse scoped activation. Span/field directives retain their
baseline behavior but make scoped activation unsupported. The host layer returns
`None` for its maximum-level hint; changing entries never changes cached level
hints or requires rebuilding callsite interest. Compile-time exclusion of DEBUG
or absence of the producer also makes activation unsupported.

Entries select exact typed principal or volume event fields, with at most 64
entries. Reads do not resolve principals and are outside this producer. The
event uses the resolved enrollment principal and the admitted operation's volume
and closed operation name. Its JSON line adds DEBUG level, fixed target/event,
slot and revision. It contains no URI, headers, certificate digest, tenant,
token, body, keys, error detail or inherited span fields. The host owns the
baseline JSON/CLOSE fmt layer, forwards its lifecycle callbacks and excludes
this event from generic fmt; every accepted capture has one bounded line.

Replacement validates the whole set under a private write guard and checks the
expected typed revision. New slot IDs increase monotonically. Replacement refuses
newly introduced IDs at or below the highest retired ID; live retained IDs remain
valid below that watermark. Retained budgets become the minimum of current and
requested allowances, including when scope changes.
Replacement emits no audit event. Authorization and grant ownership belong to
the caller; this seam defines no grant file, command, expiry or persistence.

Each slot allows at most 1,024 lines and 1 MiB, reserving one line and 1,024
bytes per matching attempt without refund after queue loss. The lowest-ID
matching slot with available budget pays for the single record. Encoded lines
are capped at 896 bytes and use the existing 1,024-slot lossy queue and writer
thread. Extra queued DEBUG bytes therefore stay below 1 MiB; baseline output
has no byte bound. DEBUG receives no loss annotation and its drops are counted
only by capture. The sink reports baseline loss on the next baseline line. There
is no output priority or delivery guarantee.

Capture uses `try_read` and `try_send`, with no destination I/O, await or wait
for queue space on the request path. Captures share read guards through the final
current-scope check, atomic reservation of both budgets, bounded encoding and
enqueue. They do not exclude one another; lock contention is against replacement,
which takes the write guard. Once replacement returns, no old scope can enqueue,
although previously queued lines can drain. A poisoned write guard disables
capture until restart. Scope snapshots are coherent; each slot's budget and each counter
are sampled separately. Saturating counters expose admission, budget suppression, contention, malformed fields,
oversize records, queued DEBUG lines and DEBUG sink drops. Queued means local
queue acceptance, not destination delivery. With no entries the producer checks
one atomic flag and constructs no diagnostic fields or output buffer. Baseline
events retain their callbacks and incur one fixed metadata-routing branch.

## The publication authority

**Authority activation is Linux-only. Its formats are frozen v1 (2026-10-06).**
A complete authority configuration activates the authority in a default build.
Startup reads the real kernel boot ID before any state-changing work. There is
no fallback boot identity on other platforms.
Partial or malformed configurations refuse before ordinary serving setup.

Use the local `initialise` and `unfence` commands described in
[Operating the authority lifecycle](operating-the-authority-lifecycle.md) for
provisioning and fenced-marker recovery. Initialise uses the startup marker
table, makes running durable before changing the log, and writes clean on success
or an unfenced refusal. A successfully initialised fresh directory therefore
admits a server start; uncertain publishing I/O requires reboot and unfence.
The client retained-submission journal is a pre-release format. Its records
are disposable until the format is frozen.

Every configured volume finishes classification and recovery before the listener
binds or emits `listening`. A missing log remains `no-log`; startup never
initialises it. The engine and synchronous log operations run on a dedicated
thread. On the first shutdown cause, HTTP drain and engine stop share one
budget: `granary-net`'s `SHUTDOWN_DEADLINE` (ten seconds). The accept loop has the
same deadline; later causes do not restart the host budget. Every cause cancels
writes before forwarding transport shutdown. The process exits with the host's
code without joining the engine or destroying the runtime.

The held state and enrollment directories must have distinct `(st_dev, st_ino)`
identities. Equality refuses before engine startup, naming both configuration
variables, including when different accepted paths name the same directory.
Distinct parent/child directories and directories on one filesystem are allowed.
The filesystem acknowledgement waives only filesystem-type refusals, never
protection, exclusive ownership, directory separation or Linux boot identity.
A missing enrollment directory refuses; a missing or invalid enrollment file
allows startup with unavailable write-principal lookups.

| variable | required | what it holds |
|---|---|---|
| `GRANARY_AUTHORITY` | — | the predicate: exactly `single-process`. Absent, the server hosts no authority; any other value refuses |
| `GRANARY_AUTHORITY_STATE_DIR` | yes | absolute path of the authority's state directory, which must already exist, owned by the server's uid with no group or other access (`0700` or stricter): the server never creates it, and one server at a time holds it |
| `GRANARY_AUTHORITY_ENROLLMENT_DIR` | yes | absolute path of the enrollment directory |
| `GRANARY_AUTHORITY_CLIENT_CA` | yes | absolute path of the PEM file of the CA that client certificates chain to |
| `GRANARY_AUTHORITY_VOLUMES` | yes | the served volumes: a comma-separated list of 1 to 64 distinct volume names; spaces around a name are ignored |
| `GRANARY_AUTHORITY_VOLUME_<NAME>_PUBLISHER_KEYS` | one per listed volume | that volume's publisher keys: a comma-separated list of 1 to 8 distinct `ed25519:<64 lowercase hex>` keys |
| `GRANARY_AUTHORITY_CONTROLS` | no | complete tuple: publish submission refill, publish submission burst, byte refill, byte burst, in-flight cap; default `46,5,33554432,268435456,4` |
| `GRANARY_AUTHORITY_ACCEPT_UNSUPPORTED_FILESYSTEM` | no | `true` lifts the filesystem-type refusals on the authority's directories; `false` or absent leaves them in force |

**All or nothing.** With the predicate, every required variable must be set and
non-empty, and a configuration missing any refuses to start, naming each
required variable as set or unset. Without the predicate, every fixed variable
above must be unset, and one that is set refuses to start, naming it.

**`<NAME>` is the volume name uppercased, with `-` written `_`.** Volume
`my-vol-2` reads `GRANARY_AUTHORITY_VOLUME_MY_VOL_2_PUBLISHER_KEYS`. A volume
name holds only `a-z`, `0-9` and `-`, so no two volumes share a variable. A
per-volume variable for a volume that is not listed is never read, with or
without the predicate: the list is the inventory, and a key for an unlisted
volume configures nothing. A reserved volume name (one starting `gran-` or
`xn--`) may be listed; the reservation governs creating a volume, not serving
one.

**Every value is bounded.** No value may exceed 8 KiB. The three path variables
may hold any bytes; every other variable must be UTF-8, and one that is not
refuses naming it. A misspelled variable name is not detected as a misspelling:
it is simply absent, and since every fixed name but the filesystem acknowledgement and controls is
required, the absence refuses.

### Publishing through the client

The default pinned `gran publish` route uses the publication recovery coordinator
for served volumes. Supply the enrolled certificate/key pair, exact credential
context, TLS pins and signing seed. A server without authority endpoints needs
explicit `--publish-mode legacy-server`; unserved fallback prints its exact 404
evidence and `route=server-seam`. Served root PUTs remain refused, even if status
or inventory changes between preflight and publication. Publication's retained
state, recovery, local abandonment, JSON and verb-specific exit codes are defined
in [client publication configuration](client-publication-configuration.md).
Abandonment stops one client's recovery and cannot repair an authority wedge.
In `auto`, a fresh publication can use the seam only when both preflight and
coordinator bootstrap answer `404 unknown-volume` before any POST. An observed
preflight followed by bootstrap `unknown-volume` refuses without a root PUT.

### Client certificates

In authority mode, a client may present a certificate, and a
write needs one whose key is enrolled. The server checks a presented
certificate's chain to the CA in `GRANARY_AUTHORITY_CLIENT_CA`, its validity
at the server's clock, the extended key usage of every certificate in the
chain (where present it must include `clientAuth`, so an intermediate restricted
to other uses refuses every leaf beneath it), and the client's proof that it
holds the key. A certificate
that fails any of these refuses the connection; none is ever served as
anonymous. **The server does not examine the KeyUsage extension:** a leaf your
CA marks without `digitalSignature`, or an intermediate marked without
`keyCertSign`, is accepted if it chains. Issue client certificates with
KeyUsage `digitalSignature` and extended key usage `clientAuth`. The
enrollment set, not the certificate's extensions, decides who may write.

### A systemd unit

Keep the variables in one file the unit reads with `EnvironmentFile=`. The
`GRANARY_AUTHORITY*` lines show the authority configuration's shape. The
environment alone activates an authority: scrub inherited
`GRANARY_AUTHORITY*` variables from unit files and environments that should
not run one.

```ini
# /etc/granary/server.env
GRANARY_LISTEN=0.0.0.0:8443
GRANARY_TLS_CERT=/etc/granary/tls/chain.pem
GRANARY_TLS_KEY=/etc/granary/tls/key.pem
GRANARY_STORE=s3:
GRANARY_STORE_BUCKET=granary
GRANARY_STORE_ENDPOINT=https://s3.example.net
GRANARY_STORE_REGION=us-east-1

GRANARY_AUTHORITY=single-process
GRANARY_AUTHORITY_STATE_DIR=/var/lib/granary/authority
GRANARY_AUTHORITY_ENROLLMENT_DIR=/etc/granary/enrollment
GRANARY_AUTHORITY_CLIENT_CA=/etc/granary/client-ca.pem
GRANARY_AUTHORITY_VOLUMES=software,my-vol-2
GRANARY_AUTHORITY_VOLUME_SOFTWARE_PUBLISHER_KEYS=ed25519:<64 hex>
GRANARY_AUTHORITY_VOLUME_MY_VOL_2_PUBLISHER_KEYS=ed25519:<64 hex>,ed25519:<64 hex>
```

```ini
# /etc/systemd/system/granary-server.service (excerpt)
[Service]
EnvironmentFile=/etc/granary/server.env
ExecStart=/usr/local/bin/granary-server
RestartPreventExitStatus=4
```

Publisher keys are public keys, not secrets. The store credentials are secrets:
keep them out of this file, or give the file mode `0600`.
