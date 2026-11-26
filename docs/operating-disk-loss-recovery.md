<!-- SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Operating disk-loss recovery

`gran recover` recovers a writer after its process or local store was lost, or
finishes work retained in a store that a writable mount can no longer start.
It is an offline operation: stop every process using the store and volume first.
Keep the signing seed and client credential outside the store. Losing both the
store and the signing seed is not recoverable.

Recovery can publish the selected prepared root, merge it onto a newer head,
settle an interrupted publication, finish retained journal work, and release the
writer row. It never accepts new user writes or silently resolves a namespace
conflict. Preserve the entire store after any refusal.

## Command and flags

The logging flags precede the command. This form records full conflict paths in
JSON while using the existing credential and publisher trust:

```sh
gran --log-format json --log-paths full recover "$STORE" "$VOLUME" \
  --writer "$WRITER" --key-seed "$KEY_SEED" \
  --endpoint "$ENDPOINT" --pin "$TLS_PIN" \
  --client-cert "$CLIENT_CERT" --client-key "$CLIENT_KEY" \
  --credential-context "$CREDENTIAL_CONTEXT" \
  --publisher-key "$PUBLISHER_KEY"
```

`$WRITER` is exactly 32 lowercase hexadecimal digits. The seed must be the
existing private signing file for the configured publisher key. `--client-cert`
and `--client-key` are a pair. `--pin` may be repeated; if it is omitted,
`GRANARY_TLS_PINS` must provide a nonempty valid pin set. `--publisher-key` may
be repeated to extend publisher trust.

The optional flags are:

| flag | use |
|---|---|
| `--construction-workspace-mib N` | Local construction budget, 1024 through 16384 MiB; default 1024. Supply the same policy again on a retry. |
| `--overlay-cap-bytes N` | Runtime overlay cap in bytes, at least 44,938,292; default 134,217,728. It is not persisted, so supply it again on a retry. |
| `--acknowledge-takeover "$WRITER"` | Consent to take over the exact authority row selected by `--writer`. The values must match. Without consent, recovery reports the selected epoch, generation, root and parent sequence and changes no local state. Inspect those public identifiers before retrying with consent. |
| `--acknowledge-resend "$PUBLICATION_ID"` | Permit one exact resend of the named live publication after `RecoveryUnresolved` or `missing-reference`. Archived evidence is ineligible. Any existing fence still requires settlement. |

The top-level `gran --help` output contains the shipped recovery synopsis.
`gran recover --help` is not a subcommand help form in this release; it is an
unknown recovery option and exits 2.

## Exit codes and completion

| command ending | exit | meaning |
|---|---:|---|
| `NothingOwed` | 0 | The store owes no recovery action. For an `Unowned` carrier, readback also found no Live row for this writer. A Released row can still exist. No completion line is printed. |
| `JournalFinished` | 0 | All admitted journal work is durable, the journal is clean, retained obligations are absent, and release is durably confirmed. Start the writable mount with this store. |
| Any recovery refusal or runtime error | 1 | Recovery did not complete. Preserve the store and use the refusal table below. A settlement action may already be durable. |
| Invalid syntax, missing required flags, invalid flag values, or `--help` | 2 | Correct the invocation. No recovery run starts. |

`recover.fence_settled` reports a durable settlement or landing-install action;
it is not overall success. An invocation may emit it and still exit 1. Only exit
0 with `JournalFinished` and `recover.journal_finished` proves journal completion
and writer release. `recover.journal_blocked` gives one of `replay`,
`publication`, `obligations`, `namespace`, `limit`, `release`, or
`selected-root-not-proved-published`.

A successful `JournalFinished` reports the saved `invalid-reference` or
`publish-work-limit` token when recovery settles that refusal. It also reports
settled refusal tokens from archived mount publications for the journal base
that recovery started with. That report is read after completion is durable. If
the archived publications cannot be listed or an archived publication for that
base cannot be read, recovery still exits 0. It prints
`gran recover: archived publication refusal report unavailable: <reason>` after
any refusal-token lines and before the `JournalFinished:` line. An empty report
proves there were no archived refusals only when the unavailable line is not
printed.

## What each store shape does

The first matching row wins. Recovery locks the store before inspecting or
changing it.

| store shape | result |
|---|---|
| The store path is absent | Without matching takeover consent, read the authority selection and stop without creating the path. With consent, create the store, persist the selected row and consent, then take it over and classify its prepared root. |
| `Unowned`, fence zero, no nonterminal request, nothing owed locally | After retained settlement, check the authenticated cursor against retained evidence. A Live row for this writer is the selection for reporting or acknowledged takeover. Without one, return `NothingOwed`. |
| No owned carrier, beside a landed commit not yet refreshed | Report `RecoveryLandedUnowned`. Matching renewed takeover consent reselects the live row before any landing repair. |
| No owned carrier, all other shapes | Report `IntentSelectedWriterMissing`. Nothing is published or released. |
| Landed commit, refresh or local install still owed | Authenticate the retained record and exact stored landing, replay or register the refresh, install the landing, then finish any suffix. Missing evidence refuses; a residual collision takes the B5 path below. |
| One open boundary with its complete retained record | Record its verified landing, finish the landing, then finish the remaining journal. |
| One open boundary with an incomplete live record | Probe only candidates that may have been written. A verified landing is finished; proved non-landing is archived and stripped; an unresolved result remains fenced unless an exact resend is acknowledged. |
| Open boundary with no matching retained record | An unfenced unsubmitted boundary is reconciled. A fenced boundary, multiple boundaries, or an unsettled foreign record refuses `SyncCommitRecoveryRequired`. |
| Open boundary with archived evidence | Probe read-only. A proved non-landing can be stripped; unresolved or landed archived evidence keeps the store unchanged and takes its specific refusal. Never resend from an archive. |
| No boundary, incomplete retained publication | Resume its exact retained publication. A non-landing ending refuses; a landing continues into journal finishing. |
| Dirty journal without a boundary | Replay and finish it once within the shared 30-second recovery deadline. The selected prepared root must be proved published before recovery can register over it or release it. |
| Clean journal and a live selected prepared root | Compare that root with the verified published chain. Equal, descendant or equal-manifest subsumption publishes nothing; an unchanged parent publishes exactly; disjoint changes merge against the prepared root's own parent; stale ancestry, corruption or a same-path change refuses. |
| Published or installed root with only release owed | Replay or send the retained release. Success requires the durable released receipt. |
| Clean journal and no live row | Return `NothingOwed`. |

An empty readback for this writer only establishes that there is no Live
selection. A hidden Released row can cause `IntentSelectionChanged` on mount
until eviction. A lost Release reply followed by eviction still fences when
the exact Release is answered absent. A store already fenced by an earlier
absence answer needs explicit recovery. With no Live selection, it has no
in-place repair; use the [fenced-store exit](#fenced-store-with-no-live-row).

## Refusal table

A refusal emitted by `gran recover` exits 1. A listed identifier that stops
writable startup makes `gran mount` exit 1 before attachment. A fenced shutdown
of an already attached mount is the separate mount exit 5.

| refusal identifier | operator-facing meaning | remedy |
|---|---|---|
| `RecoveryManagedPaths` | The signing seed or TLS private key nests with the store. | Move the private material and store to separate protected paths, then retry. |
| `RecoverySigningKeyRefused` | The existing seed failed custody/content checks or did not yield the engine key. | Restore the exact protected seed and sidecar. A different key cannot recover this writer. |
| `WritableIntentUnavailable`, `WritableAuthorityUnavailable` | Authority readback or intent service is unavailable. | Restore authenticated service/connectivity, then retry the same store. Remote effects may already exist. |
| `WritableIntentDiscoveryInvalid`, `WritableDiscoveryInvalid`, `IntentReadbackRefused`, `IntentReadbackScope`, `IntentPreparedRoot` | Readback, scope or prepared-root evidence is malformed, unverified or inconsistent. The authenticated cursor may be below the store's retained continuity floor. | Preserve the store and investigate authority data and publisher trust. If an authority was reinitialised below the floor, wait for its cursor to reach the floor or use a new store with a new writer identity. |
| `IntentScope`, `IntentSelection`, `IntentSelectionBinding`, `IntentTakeover` | Scope encoding, selection, acknowledgement or takeover bytes do not bind to the requested writer. | Correct the volume, endpoint/pins, credential context and exact writer acknowledgement; inspect the reported selection first. |
| `IntentSelectedWriterMissing` | Recovery needed a Live selection or owned carrier and found none. A fenced store with no Live selection has no in-place repair. | Preserve the store and inspect the authority row. Do not substitute another writer identity or automatically take over. When the store is fenced and the authority holds no row for its writer, use the [fenced-store exit](#fenced-store-with-no-live-row). |
| `IntentSelectionChanged` | The selected row changed, was superseded or disappeared during takeover, or Acquire found an existing row, possibly a hidden Released row. | Read back again and inspect the new selection. Renew takeover consent only for the exact intended row. If a hidden Released row blocks Acquire, wait for eviction. |
| `RecoveryLandedUnowned` | A commit landed, but this store lost ownership before refreshing that landing. | Stop displaced and displacing processes, preserve the store, inspect the selection, then use renewed exact takeover consent. |
| `IntentAdoptionBesideEvidence`, `IntentCeilingBelowEvidence`, `IntentOwnershipPending`, `IntentOwnershipUnresolved`, `IntentSelectionAlreadyStarted` | Local ownership evidence makes a new adoption unsafe, or an exact retained ownership operation is still owed. | Preserve the carrier and replay/restore its matching evidence. Do not delete ownership files or start a fresh adoption in this store. |
| `IntentFreshInstanceRequired` | A prepared release became unconfirmable and this instance may not own the row again. | Preserve the overlay. Restore service for exact retained replay if still possible; otherwise there is no in-place repair. |
| `IntentEntropyUnavailable`, `IntentDeadlineOverflow`, `IntentEpochExhausted`, `IntentGenerationExhausted` | Required identity, deadline, epoch or generation state cannot be represented safely. | Preserve the store. Restore entropy for the first case; the overflow/exhaustion cases require inspection, not a same-state retry. |
| `WritableRecoveryRequired` | Writable startup found retained recovery work or a visible row for this writer before Acquire. | Stop startup and run `gran recover` on this exact store. If explicit recovery returns the same underlying evidence error, use that row instead of retrying startup. |
| `SyncCommitRecoveryRequired` | An open boundary has no single matching retained record, is fenced without one, or has foreign/unsettled evidence. | Preserve journal, staging and retained records; inspect or restore the matching retained evidence. Do not resend or strip it manually. |
| `RecoveryPublicationMissing`, `RecoveryPublicationUnresolved`, `SyncCommitUnresolved` | A publication owed by the store is absent or still lacks a safe landing/non-landing conclusion. | Restore matching retained evidence or authenticated service. |
| `SyncCommitIdentity`, `SyncCommitLandingBinding`, `RecoveryLandedEvidenceMissing`, `RecoveryManifest`, `SyncBase`, `SyncCommitManifest`, `SyncGraphPoisoned` | Retained publication, landing, base, manifest or in-memory graph evidence does not match the journal-bound work. | Preserve the store and restore the exact matching evidence. Treat authentication or graph disagreement as damage; never manufacture replacement evidence. |
| `RecoveryStale` | The verified published chain no longer reaches the prepared root's parent. | Keep the volume read-only and investigate reinitialised or divergent history. Do not publish this selection onto that chain. |
| `RecoveryRemoteIntegrity: <detail>` | Authenticated remote history is missing, contradictory or fails ancestry/content verification. | Keep the volume read-only. The authority/storage administrator must establish a trustworthy chain before any continuation. |
| `RecoveryConflict` | A verified merge or landing install found a path changed incompatibly by local and published work. | Preserve the store; use the conflict event and the B5 procedure below when it is a landed residual collision. Otherwise change the files or head through a separately supported resolution before retrying. |
| `RecoveryArchivedLanded` | A publication archived with operator acknowledgement is now verified as landed at the event's sequence. | Stop all volume users, preserve the old store unchanged, and use the archived-store exit below. Do not recover or resend from it. |
| `RecoveryArchivedUnresolved` | Archived evidence still cannot be classified; its event sequence is not claimed published. | Preserve the old store and use an independently verified published sequence for read access or the fresh-store exit. Never resend the archive. |
| `RecoveryUnresolved` | A live publication may have written, but probing found no conclusion. | Inspect its publication ID. If one more exact send is intended, retry once with `--acknowledge-resend "$PUBLICATION_ID"`; the fence remains until later evidence settles it. |
| `missing-reference` | The authority refused the retained candidate because it could not find a reference. Recovery reports the publication ID and keeps the exact candidate. | Repair the missing objects, then explicitly acknowledge one exact resend using that ID. |
| `invalid-reference`, `publish-work-limit` | The authority refused the candidate. A work-limit refusal is against the observed head. | Inspect the references or publication work. Recovery archives only with proof of non-landing. |
| `RecoveryResendCandidate` | The acknowledged publication has no eligible exact active candidate at the unresolved sequence. | Preserve the store and inspect the retained publication; do not choose a different candidate. |
| `RecoveryResendUnanswered`, `RecoveryResendNoWrite`, `RecoveryResendPending`, `RecoveryResendInvalidAnswer` | The one acknowledged resend completed its transport attempt but did not settle the publication. | Inspect its retained answer and fence. Do not immediately resend again. |
| `OverlayCapacityExhausted`, `SyncCommitExhausted`, `SyncDeadline`, `SyncWorkspaceExhausted` | The overlay cap, attempt arithmetic, the shared 30-second bound, or the configured construction budget stopped recovery. | For overlay capacity, retry with a justified larger `--overlay-cap-bytes` value; for workspace, increase `--construction-workspace-mib`. For transient slowness, restore service before retrying. Exhaustion requires inspection. |
| `RecoveryJournalBlocked` | Admitted work remains after replay, publication, obligation, namespace, limit or release checks. | Preserve the store and inspect `recover.journal_blocked.reason`. Change that precondition before retrying; a same-state mount is not a repair. |
| `WritableCacheCloseFailed`, `WritableFinishLeaked` | Writable-start finishing closed its cache badly or left its engine holding the store. | Check cache storage and retry startup for the cache case. Retry once and report the engine-leak defect for the latter; keep the store. |
| `IntentFenced (ESTALE)` (writable start) | Startup reached a B5 landing collision while its authority ownership/commit is fenced. | Preserve the store. Use explicit recovery to obtain the full-path conflict event; startup does not resolve the collision. |

The residual evidence refusals below are also part of the start/recovery closure.
They all keep the store and exit 1:

| refusal identifier | meaning and remedy |
|---|---|
| `RecoveryResidualCaptureMissing`, `RecoveryResidualCaptureChanged`, `RecoveryResidualCaptureUnknown`, `RecoveryResidualCaptureSignature`, `RecoveryResidualExecChanged`, `RecoveryResidualLandingChanged`, `RecoveryResidualSourceMissing`, `RecoveryResidualSourceChanged`, `RecoveryResidualClosure` | The sealed capture, landing or source is absent, changed, unauthenticated or cannot reconstruct the required namespace. Restore the exact authenticated evidence; do not edit the journal or staging. |
| `RecoveryResidualInventoryCheck`, `RecoveryResidualInventoryCount` | The complete collision inventory does not match its authenticated check or count. Preserve all files and investigate the inventory/evidence pair. |
| `RecoveryResidualPayloadHeader`, `RecoveryResidualPayloadLength` | A staging file's header or physical length does not match its recorded payload. Restore the matching staging file; never trim or substitute it. |
| `RecoveryResidualUnavailable` | Required local or remote residual content is unavailable. Restore storage/service and retry the same store. |
| `RecoveryResidualWorkspace` | Bounded residual validation lacks workspace. Free space outside retained recovery files; do not remove retained files. |
| `RecoveryResidualReadOnly` | A read-only preflight path was asked to mutate or fetch through a forbidden route. Preserve the store and report the defect. |
| `RecoveryResidualValidatedAwaitingExecution` | A previously recorded terminal disposition validated, but this release has no executor for it. Preserve the sealed store for a later supported executor. |
| `RecoveryResidualUnrepresentable` | The residual is outside the supported file-payload shape. Preserve every byte; there is no automatic disposition in this release. |

The shared writable-start finisher can also surface any identifier in the
source-checked sync-engine catalogue. These are exit 1 at startup. The specific
rows above take precedence; the following groups complete that catalogue:

| identifiers | operator-facing meaning and remedy |
|---|---|
| `IntentAcquire`, `IntentAttemptNotStarted`, `IntentAttemptsExhausted`, `IntentBackendDisagreement`, `IntentBound`, `IntentCapExhausted`, `IntentCapOverflow`, `IntentCaptureCompletionStale`, `IntentCaptureProvenanceUnavailable`, `IntentCaptureRecoveryBinding`, `IntentCaptureRecoveryFailed`, `IntentCaptureRegistrationRefused`, `IntentCarrierBinding`, `IntentCarrierCap`, `IntentCarrierChanged`, `IntentClockInvalid`, `IntentCompletionBinding`, `IntentCompletionOwner`, `IntentControlChanged`, `IntentCoveringRootUnknown`, `IntentCursorChanged`, `IntentDrainPending`, `IntentExpiredRegisterUnresolved`, `IntentFenceReceipt`, `IntentForeignControl`, `IntentGrant`, `IntentLandedReplayInvalid`, `IntentNotImplemented`, `IntentOverQuota`, `IntentOwnershipRequest`, `IntentPendingReconciliation`, `IntentPendingSignature`, `IntentPersistencePoisoned`, `IntentPipelineFull`, `IntentPreparedSignature`, `IntentPreparedWriter`, `IntentReceipt`, `IntentRegister`, `IntentRelease`, `IntentReleaseGenerationZero`, `IntentReplacementReserve`, `IntentReplayPending`, `IntentRequestNotRetained`, `IntentRequestRetired`, `IntentRetryDeadline`, `IntentRetryNotEligible`, `IntentRevisionExhausted`, `IntentSnapshotMissing`, `IntentStagingChanged`, `IntentStartupAttemptsExhausted`, `IntentSyncPayloadBinding`, `IntentTerminalRefusal`, `IntentTokenDisplaced`, `IntentUnknownVolume`, `IntentUnmergedChanged`, `IntentUnmergedUnclassified`, `IntentVerdictMismatch`, `OverlayCapacityExhausted` | The authority carrier, a retained request, capture, receipt, grant or its capacity/retry bound prevented safe startup. Preserve the store. Restore service for retry/deadline failures, correct quota/capacity for quota or cap failures, and otherwise inspect or restore the exact retained authority evidence before retrying. A cursor/token displacement requires a fresh readback, not an automatic takeover. |
| `SyncBaseBinding`, `SyncBaseOverflow`, `SyncBasePoisoned`, `SyncCallerBinding`, `SyncCallerNotRetained`, `SyncCancelled`, `SyncCommitAlreadyRetained`, `SyncCommitBinmap`, `SyncCommitBootstrap`, `SyncCommitCandidateBinding`, `SyncCommitCapture`, `SyncCommitCheckpoint`, `SyncCommitConstructionPending`, `SyncCommitContainment`, `SyncCommitContext`, `SyncCommitDrainPending`, `SyncCommitInFlight`, `SyncCommitInitialRecord`, `SyncCommitLandingIdentity`, `SyncCommitLaneRequired`, `SyncCommitNamespace`, `SyncCommitNotRetained`, `SyncCommitReadback`, `SyncCommitRebaseManifest`, `SyncCommitRebaseUnavailable`, `SyncCommitRecord`, `SyncCommitRefresh`, `SyncCommitScope`, `SyncCommitSignature`, `SyncCompletionBinding`, `SyncContentDeadlineRequired`, `SyncDeadlineOverflow`, `SyncDirectoryTarget`, `SyncEngineAlreadyAttached`, `SyncFaultSupervisorLost`, `SyncFileIndex`, `SyncGraphOverflow`, `SyncInjectedFault`, `SyncLeaseExhausted`, `SyncLeaseMissing`, `SyncLocalTransactionLost`, `SyncMaterializationLost`, `SyncMediatorPoisoned`, `SyncOwnerBinding`, `SyncPreparedBase`, `SyncPreparedRoot`, `SyncProjectedBinding`, `SyncRange`, `SyncRechunkContent`, `SyncRecoveryRequired`, `SyncSelectionUnrepresentable`, `SyncStatePoisoned`, `SyncSupervisorLost`, `SyncWaiterConsumed` | The retained sync lane, authenticated graph, base, candidate, local transaction or supervisor could not be resumed safely. Preserve journal, staging and retained submission. Restore authenticated reads for unavailable/readback failures; otherwise inspect the named evidence or report an injected/internal/supervisor defect. Do not delete the lane or fabricate a completion. |
| `ViewAdapterLost`, `ViewHeadRefused`, `ViewHookBound`, `ViewHookUnbound`, `ViewPending`, `ViewRootEquivocation`, `ViewRootMismatch`, `ViewRootNotAccepted`, `ViewRootUnavailable`, `ViewRootUnpublished`, `ViewTimeUnrepresentable`, `ViewUnattendedUnsupported`, `ViewUnservable` | The temporary authenticated view required to finish the store was unavailable, inconsistent or could not be installed unattended. Restore service for `Unavailable`/`Pending`; investigate publisher trust, root history and local evidence for mismatch, equivocation or refusal; report adapter/hook defects. Keep the store. |
| `Store binding` | The opened store does not match the store bound to the finishing engine. Preserve both paths and retry only with the exact original store. |

The catalogue also contains the following exact local-evidence refusal strings.
Each exits 1 at startup. They mean the named journal, staging, namespace,
capture, projection or retained-evidence invariant failed. Preserve the whole
store, do not edit or delete the named evidence, and restore the exact matching
files if a known-good copy exists; otherwise report the identifier for repair.

| refusal identifiers |
|---|
| `adoption journal not clean`, `base read missing`, `base read type`, `base root/sequence mismatch`, `bind base content`, `bind name missing`, `bind type or stage conflict`, `boundary capture context`, `boundary cursor mapping`, `capture buffer range`, `capture context`, `capture dirty version`, `capture exhaustion`, `capture extent mismatch`, `capture extent overflow`, `capture extent range`, `capture file index`, `capture partition`, `capture range context`, `capture stage`, `capture verified range`, `capture version changed`, `capture version missing`, `capture was not flushed`, `carried journal header`, `carried journal scan`, `checkpoint mark missing`, `checkpoint stage missing`, `clean file content`, `clean file identity`, `clean selection`, `close stage`, `close without handle`, `commit graph overflow`, `commit prefix binding`, `commit prefix replay`, `commit prefix scan`, `commit stage missing`, `complete tree payload`, `complete tree selection` |
| `completion boundary`, `copy-up content missing`, `copy-up missing`, `create destination exists`, `damaged mark evidence`, `data encode`, `data value rule`, `delete name missing`, `delete type/stage/nonempty refused`, `detached stage has no handle`, `dirty interval overflow`, `duplicate base entry`, `duplicate unmerged payload`, `durable landing/refresh required`, `durable projection identity/boundary`, `empty path`, `engine graph underflow`, `entry vanished`, `equal mark conflict`, `extent overflow`, `extent size`, `final journal missing`, `final source changed`, `foreign scope`, `foreign staging name`, `foreign unmerged name`, `foreign volume entry`, `foreign volume`, `fragment length`, `fragment supersession`, `graph effect encoding`, `graph extent encoding`, `handle exhaustion`, `immutable object size bound`, `incarnation exhaustion`, `initial journal header`, `initial journal scan`, `initial journal writer`, `inode exhausted` |
| `inode exhaustion`, `invalid base entry`, `journal fenced`, `journal input budget`, `journal input changed or exceeded budget`, `journal missing beside staging`, `journal missing beside unmerged`, `journal missing`, `journal value rule`, `landing boundary missing`, `landing refers to absorbed boundary`, `landing scan`, `live extent bounds`, `live extent mismatch`, `live repair anchor`, `live repair bounds`, `mark above ceiling`, `mark block`, `mark encode`, `mark generation conflict`, `missing unanchored staging`, `move cycle or identity`, `move entry missing`, `move prefix`, `move source missing`, `name missing`, `named stage missing`, `namespace count overflow`, `namespace record kind`, `normalization header`, `normalization image`, `normalization scan`, `normalization writer`, `not extent`, `open stage`, `open unstaged/missing file`, `orphan capture has no prepared-root name`, `overlay root`, `parent is not a directory`, `partial write range` |
| `path bounds`, `platform buffer bound`, `projected prefix binding`, `projected prefix scan`, `projected residual unsupported`, `projected selection unnamed`, `projection base missing`, `projection empty path`, `projection file lacks durable payload`, `projection parent count`, `projection parent identity`, `projection parent missing`, `projection source identity`, `provenance empty path`, `provenance identity mapping`, `provenance journal scan`, `provenance parent missing`, `provenance replay namespace`, `provenance source missing`, `read offset`, `read requires staged routing`, `rebind empty path`, `rebind parent`, `receipt ceiling`, `receipt writer/ceiling`, `record encode`, `recovery commit scan`, `refetched extent mismatch`, `rejection attempt evidence`, `rejection boundary binding`, `rejection boundary missing`, `rejection fenced`, `rejection final scan`, `rejection header`, `rejection scan`, `rejection source`, `rejection torn source`, `rejection writer`, `repair header`, `repair range` |
| `repair stage`, `repaired journal changed`, `repaired journal rescan`, `replace destination missing`, `replace destination refused`, `replacement completion scan`, `replacement cursor map`, `replacement encode`, `replacement fenced source`, `replacement final counters`, `replacement final rescan`, `replacement final writer`, `replacement header`, `replacement pending prefix boundary`, `replacement prefix scan`, `replacement prefix value`, `replacement retained scan`, `replacement source scan`, `replacement source`, `replacement temporary already exists`, `replacement temporary missing`, `replacement torn source`, `replacement unexpected control`, `replacement value rule`, `replacement writer`, `replay ceiling`, `replay would discard held stage`, `residual reconciliation changed`, `residual scan`, `retained orphan has no landed Location`, `retirement header`, `retirement mark range`, `retirement stage`, `retirement still held`, `scope`, `second scope for volume`, `selected consent missing`, `selected ownership`, `selected receipt`, `selected writer binding` |
| `setattr name missing`, `setattr type refused`, `short capture extent`, `short capture read`, `shrink identity`, `short live extent beyond anchor`, `short live extent without anchor`, `short staged read`, `stage encode`, `stage header`, `stage id`, `stage identity binding`, `stage missing`, `stage name missing`, `stage selection`, `stage vanished`, `staging binding`, `staging header encode`, `staging header`, `stale replacement plan`, `sync boundary context`, `sync boundary was not flushed`, `sync directory identity`, `sync file identity`, `sync graph missing`, `sync graph underflow`, `sync projection admission`, `sync stage missing`, `synced mark beyond journal`, `through cursor mapping`, `truncate fold`, `truncate size`, `unmerged capacity`, `unmerged current disposition evidence`, `unmerged custody deadline`, `unmerged custody`, `unmerged installed binding`, `unmerged installed stage id`, `unmerged inventory binding`, `unmerged listing binding`, `unmerged listing missing` |
| `unmerged listing`, `unmerged pair pending retirement`, `unmerged payload binding`, `unmerged payload check`, `unmerged payload header`, `unmerged payload length`, `unmerged payload missing`, `unmerged temporary mismatch`, `unmerged temporary missing final`, `unmerged unresolved disposition`, `unnamed synced staging evidence`, `unprovable short staging header`, `verified source range length`, `write bounds`, `write extent bound`, `writer ceiling or identity`, `writer ceiling rollback/exhaustion`, `writer changed`, `writer decode`, `writer encode`, `writer entropy unavailable`, `writer length changed or exceeded bound`, `writer missing beside evidence`, `writer missing`, `writer volume`, `writer volume/identity`, `zero bound` |

## Retiring a refused overlay

Same-store `gran recover` replays the same journal and can hit the same
refusal. Stop users of the store and volume, and preserve the original store.
On a fresh store, inspect the selection without consent by running
`gran recover "$FRESH" "$VOLUME" --writer "$W"` with the original signing and
authority options. Retry with `--acknowledge-takeover "$W"` for the intended
row and verify the recovered head. Keep the original store for extraction,
discard and reconciliation. Discard alone publishes nothing.

Complete any wanted extraction before retiring the overlay. On the actual
store to retire, run `gran overlay discard --plan --store-dir "$STORE"
--scope "$S" --volume "$V"`, then use the printed S, V, W and I for
`gran overlay discard` with `--writer "$W" --journal-incarnation "$I"
--acknowledge-unsynced-loss --acknowledge-may-land`. Retry a durability or
output failure with the same tuple. Keep the complete store, including
`publications/`. Discard refuses a healthy, unclaimed overlay. Pending and
archived overlays remain fenced and can be retried with the same tuple.

Run `gran overlay reconcile` with the same tuple and the authority options
in the mount guide. Read a verified landing at its reported sequence
through a separate read cache.
[Mount guide](operating-a-mount.md#preserving-overlay-recovery-evidence)

Exit 0 with no rows settles the archive's late-publication risk.
If `OverlayArchiveUnresolved` is reported, keep the late-publication
acknowledgement in force, use an independently verified published sequence
for reads and rerun when missing authority evidence becomes available.
For a local refusal, resolve the local evidence problem first.
`OverlayArchiveRemoteIntegrity` calls for administrator investigation before
writable continuation. Continue from a separate fresh store and cache, with
a new writer and its own grant, at the verified current head.
See [preserving overlay recovery evidence](operating-a-mount.md#preserving-overlay-recovery-evidence)
for the discard and reconciliation commands.

## Fenced store with no Live row

A store is fenced and the authority holds no row for its writer, for
example when:

- the store still owes local work, such as journal entries nobody
  published, while its row is Released (a row with no registered root),
  and the authority evicts that row after released-row retention;
- a Release reply was lost, the row was evicted, and the replayed Release
  was answered absent.

On a maintenance pass, the authority evicts a Released row once
max(grace, 24 hours) has passed since its last change. After that, writable
start refuses `IntentFenced (ESTALE)`, and both `gran recover` forms, with
and without `--acknowledge-takeover`, refuse `IntentSelectedWriterMissing`
on every later run. Each refusal keeps the journal and staging. The store
has no in-place way back: it may not acquire again while fenced, and no row
is left to take over.

This refusal prints no B5 inventory, so the B5 extraction below does not
apply. No command in this release maps this store's unpublished files to
their paths. If the local work matters, keep a complete copy of the store
(`cp -a -- "$STORE" "$OLD_STORE"`) before anything else; discard also keeps
every byte, in the archive.

To return the volume to writable service:

1. Stop every process using the volume and preserve the store.
2. Retire the overlay as [above](#retiring-a-refused-overlay): the plan
   reports `live` for this store, and the acknowledged discard archives it.
   Ordinary paths then refuse the store with `OverlayArchived`.
3. Reconcile with the same tuple. When the archived journal holds no
   commit boundary, as in both examples above, reconciliation settles the
   archive locally, without contacting the authority, if the preserved
   publication records show that nothing can still land: exit 0 with no
   rows. Any row or refusal is
   handled as [above](#retiring-a-refused-overlay).
4. Start writable service from a separate fresh store and cache with the
   fresh-store command in [B5](#b5-landed-residual-collision) step 4. It
   acquires a new writer at the verified current head. The old store's
   unpublished work is not in it.

## B5: landed residual collision

B5 means a commit has landed as root L, while a later local staging file names a
path whose content in L changed. Both `gran recover` and writable startup refuse
by default. Recovery reports `RecoveryConflict` and exit 1; startup reports
`IntentFenced (ESTALE)` and exit 1. Each refused attempt appends exactly one
landed-refresh journal record and advances retained generation barriers. It does
not change any staging byte, publish anything, emit a finished event, or lose
data. Repeated unchanged attempts only grow that bookkeeping.

Use this manual exit:

1. Stop all volume users. Choose an absent `$OLD_STORE` outside `$STORE` and
   preserve the complete store there before recovery:

   ```sh
   cp -a -- "$STORE" "$OLD_STORE"
   ```

   Keep `$STORE` as the untouched preservation copy; run recovery and extraction
   against the same `$OLD_STORE` working tree. Each refused attempt appends one
   landed-refresh record and advances its generation barrier, but changes no
   staging byte. Choose an absent `$STAGE_LIST`, capture only the inventory
   stdout, request paths, and confirm exit 1 plus `RecoveryConflict` on stderr:

   ```sh
   umask 077
   gran --log-paths full recover "$OLD_STORE" "$VOLUME" ... >"$STAGE_LIST"
   ```

   If stderr also reports `RecoveryConflictInventoryOutput`, recovery could
   not confirm complete inventory output. Treat the capture as incomplete and
   preserve the working store. Only use an inventory that passes the checks
   below after a run without this output refusal.

2. The list starts with `B5-scope`; its value is `$SCOPE_DIGEST`. A
   default-redacted list still extracts every payload but uses `<file>` instead
   of named paths. Choose an absent `$RECOVERY_DIR`, then run this complete fenced block:

   ```sh
   (
     umask 077
     mkdir -- "$RECOVERY_DIR" || exit 1
     ROWS=0 SCOPES=0 TRAILERS=0 SCOPE_DIGEST= TRAILER_COUNT=
     while IFS="$(printf '\t')" read -r TAG VALUE STAGE_ID SIZE EXTRA; do
       case "$TAG" in
         B5-scope) [ "$ROWS:$SCOPES:$TRAILERS" = 0:0:0 ] && [ -n "$VALUE" ] &&
           [ -z "$STAGE_ID$SIZE$EXTRA" ] && [ "${#VALUE}" -eq 64 ] || exit 1
           case "$VALUE" in *[!0-9a-f]*) exit 1 ;; esac
           SCOPES=1; SCOPE_DIGEST=$VALUE ;;
         B5-stage) [ "$SCOPES:$TRAILERS" = 1:0 ] && [ -n "$VALUE" ] &&
           [ "${#STAGE_ID}" -eq 16 ] && [ -n "$SIZE" ] && [ -z "$EXTRA" ] || exit 1
           case "$STAGE_ID" in *[!0-9a-f]*) exit 1 ;; esac
           case "$SIZE" in *[!0-9]*) exit 1 ;; esac
           OUT="$RECOVERY_DIR/$STAGE_ID"
           dd if="$OLD_STORE/overlay/$SCOPE_DIGEST/$VOLUME/staging/$STAGE_ID" \
             of="$OUT" bs=160 skip=1 || exit 1
           [ "$(wc -c <"$OUT")" -eq "$SIZE" ] || exit 1; ROWS=$((ROWS + 1)) ;;
         B5-stages) [ "$SCOPES:$TRAILERS" = 1:0 ] && [ -n "$VALUE" ] &&
           [ -z "$STAGE_ID$SIZE$EXTRA" ] || exit 1
           case "$VALUE" in *[!0-9]*) exit 1 ;; esac
           TRAILERS=1; TRAILER_COUNT=$VALUE ;;
         *) exit 1 ;;
       esac
     done <"$STAGE_LIST"
     [ "$SCOPES:$TRAILERS" = 1:1 ] && [ "$ROWS" -eq "$TRAILER_COUNT" ] || exit 1
   )
   ```

3. A missing newline, row, or final trailer refuses. The first 160 bytes are the
   common staging header; each output thereafter is exactly the local file bytes.
   Keep the TSV as the path/id map. This is deliberately a superset: some
   recovered files may equal published content. Only after every row and count
   passes, use the existing fresh-store exit; never reuse `$OLD_STORE`.

4. If writable service may proceed without the old unpublished changes, choose
   absent, separate `$FRESH_STORE` and `$FRESH_CACHE` paths and run:

   ```sh
   gran mount "$VOLUME" "$MOUNTPOINT" --writable \
     --endpoint "$ENDPOINT" --pin "$TLS_PIN" --root-key "$PUBLISHER_KEY" \
     --key-seed "$KEY_SEED" --store-dir "$FRESH_STORE" \
     --client-cert "$CLIENT_CERT" --client-key "$CLIENT_KEY" \
     --credential-context "$CREDENTIAL_CONTEXT" \
     --cache-dir "$FRESH_CACHE" --foreground
   ```

   This acquires a fresh writer; it does not take over the old row. Retry a
   cursor race with the same fresh store. If admission or row quota still
   refuses, preserve the old store and use authenticated `gran cat` reads until
   the condition clears. Published data is available in the fresh mount, but
   the preserved local residual is not.

## Archived-store exit

For `RecoveryArchivedLanded` or `RecoveryArchivedUnresolved`, stop all processes
using the volume and preserve `$OLD_STORE` unchanged. Read a known published
file into a separate cache:

```sh
gran cat "$VOLUME" "$PUBLISHED_PATH" --seq "$PUBLISHED_SEQ" \
  --root-key "$PUBLISHER_KEY" --endpoint "$ENDPOINT" --pin "$TLS_PIN" \
  --cache-dir "$READ_CACHE"
```

Use the event's sequence for `RecoveryArchivedLanded`. For
`RecoveryArchivedUnresolved`, use an independently known and verified published
sequence. If writable service can proceed without the old residual, use the
fresh-store command above. Never reuse `$OLD_STORE`, `$FRESH_STORE`,
`$FRESH_CACHE` or `$READ_CACHE` for one another.
