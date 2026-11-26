# Why Granary is licensed the way it is

The operational summary is in
[LICENSING.md](../LICENSING.md); this is the reasoning, so that it survives.

## The constraint

The goal was never maximum adoption at any cost. It was: **Granary should be open
source, and nobody should be able to take it, close it, and sell it.**

That constraint rules out MIT and Apache-2.0 for the whole project immediately.
Both permit exactly that — taking the code, building a proprietary product,
selling it, publishing nothing. Apache-2.0 additionally requires preserving the
copyright notice. That is the entire obligation.

## Why not GPLv2

No network clause. Someone can run a modified Granary as a managed service and
share nothing. That is the specific free-ride worth blocking.

OpenAFS is relicensing *to* GPLv2, but their driver is Linux kernel symbol
visibility — the kernel increasingly restricts symbols to GPLv2 code, making it
"increasingly impractical for OpenAFS to support modern Linux versions." Granary
is a FUSE project and never needs those symbols. Different problem, different
answer.

## Why the split rather than AGPL everywhere

AGPL carries real adoption cost. **Google bans it outright** — their published
policy is that AGPL, OSL and SSPL code "cannot be used in google3 under any
circumstances, and only very rarely on workstations," because Google's core
products *are* network services and an accidental dependency would be
catastrophic. They describe it as "an aggressively-broad ban… to doubly-ensure."
Many enterprises copy that policy, and blanket bans match on the licence string
rather than on how the software would actually be used.

But the risk profile differs completely by component:

- **The client is mounted, not linked.** An enterprise running an unmodified
  client triggers nothing in AGPL §13. Yet a blanket ban would still block it,
  costing adoption for zero protective benefit.
- **The server is the strip-mine target.** That is where AGPL earns its keep.

So: Apache-2.0 for core and client, AGPL-3.0-or-later for the server. This is the
model MongoDB ran for years — AGPL server, Apache-2.0 drivers — which produced
very large adoption while keeping the server protected.

## Why AGPL is survivable where it applies

AGPL is OSI-approved and FSF-endorsed. It is genuinely open source, unlike
BUSL/SSPL/FSL, which matters when a public build log is half the project.

Evidence it works commercially:

- **Grafana** relicensed Grafana, Loki and Tempo to AGPLv3 in 2021 explicitly to
  stop strip-mining, then raised $220M. Deeply enterprise-adopted.
- **MinIO** is fully AGPLv3 and sells commercial exceptions as copyright holder,
  with enterprise pricing starting around $96k/year for 400 TB.
- **Redis returned to AGPLv3 in May 2025** after concluding SSPL "failed to be
  accepted by the community."
- **MongoDB's** AGPL adoption grew large enough that it pushed organisations to
  evaluate and eventually accept AGPL projects. Bans are not always permanent.

## The direction of travel matters

Released versions stay under their original licence forever. That makes
relicensing a one-way door, and only one direction is safe.

**AGPL → Apache later is safe.** The only forkable artifact is the AGPL version,
which is more restrictive than the new Apache release. Nobody forks to get
something worse. Fork risk is effectively zero.

**Apache → AGPL later is not protection at all**, and there is a definitive worked
example. Elasticsearch was Apache-2.0. AWS ran it as a managed service. Elastic
switched to SSPL in 2021 to stop that. **AWS forked Elasticsearch 7.10.2 — the
last Apache release — into OpenSearch, reaching 496 contributors and over 100
million downloads in its first year**, forcing a mass exodus. Elastic escalated by
breaking client-library compatibility, which drove more exodus. By late 2024
Elastic had added AGPL back.

Per former AWS VP Adrian Cockcroft, the root cause was that AWS wanted to
contribute security features and Elastic wanted to keep security as an enterprise
feature, rejecting the approaches.

The lesson is not "AWS is hostile." It is that **starting permissive and
tightening later does not work.** The attempt cost Elastic its community position
and handed a competitor a fork with more downloads than the original.

## DCO, not a CLA — for now

A **DCO does not authorise relicensing.** Inbound equals outbound; contributors
keep their copyright. A **CLA does** permit relicensing, which is why commercial
open-source projects use them — and why the community distrusts them.
**MongoDB used exactly those CLA rights in 2019 to move to a non-open-source
licence.**

The resolution is timing. As a solo author the project holds 100% of the
copyright and can relicense unilaterally today, so a CLA buys nothing right now
while costing goodwill immediately. Use a DCO until outside contributions become a
material fraction of the tree, then revisit.

Note the consequence honestly: once there are substantial outside contributions
under DCO, relicensing requires asking those contributors. Mozilla treated 95%
author coverage as sufficient in practice, so this is tractable but not free.

## Review trigger

Revisit in 12 months, or sooner if AGPL is demonstrably costing adoption on the
*server* side specifically. The relicensing door opens in the safe direction, so
this is a low-risk commitment rather than a permanent one.

What would change the decision:

- Evidence that server-side AGPL is blocking real deployments that would
  otherwise happen, at a rate that outweighs the strip-mining risk.
- Outside contributions becoming material, which makes any future change harder
  and argues for settling the question sooner.
- A commercial strategy emerging, which would make the CLA question live again.
