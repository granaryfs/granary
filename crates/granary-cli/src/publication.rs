// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Publication selection under one Store lock, checked routing, and winner repair.

use crate::{
    CacheOnDrop, DEFAULT_CACHE_QUOTA_BYTES, PublishArgs, WallClock,
    admission::{ProcessCredentials, set_id_refusal},
    cache_origin,
    keys::load_or_create_key_with_identity,
    path_separation::{
        refuse_cache_dir_nesting, refuse_key_seed_nesting, refuse_managed_paths, refuse_nesting,
        refuse_store_as_source, refuse_tls_key_directory,
    },
    publication_report::{
        Advisory, Identification, InvocationReport, Outcome, Retention, Route, Winner,
    },
    publish_config::PublishConfiguration,
    writer_identity,
};
use granary_client::{
    AuthorityConfiguration, AuthorityError, AuthorityTransport, Cache, ClientTotals, FileIdentity,
    HintUpdate, MayLandAcknowledgement, Policy, PublicationHandle, PublicationJournal,
    PublicationOutcome, PublicationResult, PublicationStore, PublicationStoreError,
    PublicationStoreErrorKind, PublishError, PublishFields, PublishRoute, RecoveryBackoff,
    RecoveryError, RecoveryIntent, RecoveryParts, RouteError, StatusRefusal, StatusResponse, Store,
    begin_publication, bootstrap_publication, commit, harvest_excluding_files,
    open_publish_route_with_client_credential, prepare_excluding_files, resume_publication,
    write_client_snapshot,
};
use granary_core::{
    binstore::BinStore,
    clock::Clock as _,
    grainsource::{GrainSource, GrainSourceError},
    hash::GrainId,
    retained_submission::{Completion, Scope, Submission},
    root::VolumeName,
    rootstore::{RootStore, RootStoreError},
};
use granary_net::secure_random::OsSecureRandom;
use granary_store::crypto::{SigningKey, TrustedKeys, check_head};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublishMode {
    #[default]
    Auto,
    Authority,
    LegacyServer,
}
impl PublishMode {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "auto" => Ok(Self::Auto),
            "authority" => Ok(Self::Authority),
            "legacy-server" => Ok(Self::LegacyServer),
            _ => Err("--publish-mode needs auto, authority or legacy-server".into()),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Selection {
    Ordinary,
    New,
    Recover([u8; 16]),
    Abandon([u8; 16]),
}
pub(crate) fn parse_id(value: &str) -> Result<[u8; 16], String> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("publication ID must contain exactly 32 lowercase hexadecimal digits".into());
    }
    let mut id = [0; 16];
    for (slot, pair) in id.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let digit = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        };
        if let [a, b] = pair {
            *slot = digit(*a) * 16 + digit(*b);
        }
    }
    Ok(id)
}
fn acknowledgement(selection: Selection) -> Option<MayLandAcknowledgement> {
    (selection == Selection::New).then_some(MayLandAcknowledgement::Acknowledged)
}

/// Only explicit-new begin changes the coordinator's internal load semantics.
/// Begin/replace and the source surface remain the guarded Store operations.
struct NewJournal<'a, 's> {
    store: &'a mut PublicationStore<'s>,
    scope: &'a Scope,
    volume: &'a VolumeName,
}
impl GrainSource for NewJournal<'_, '_> {
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        self.store.get(id)
    }
    fn has(&self, id: &GrainId) -> bool {
        self.store.has(id)
    }
}
impl PublicationJournal for NewJournal<'_, '_> {
    fn load(
        &mut self,
        scope: &Scope,
        volume: &VolumeName,
    ) -> Result<Option<Submission>, PublicationStoreError> {
        if scope != self.scope || volume != self.volume {
            return Err(PublicationStoreError {
                path: std::path::PathBuf::new(),
                reason: "explicit new scope mismatch".into(),
                kind: PublicationStoreErrorKind::Selection,
            });
        }
        self.store
            .load_for_new(scope, volume, MayLandAcknowledgement::Acknowledged)
    }
    fn begin(&mut self, record: &Submission) -> Result<(), PublicationStoreError> {
        self.store.begin(record)
    }
    async fn replace(
        &mut self,
        generation: u64,
        record: &Submission,
    ) -> Result<(), PublicationStoreError> {
        self.store.replace(generation, record)
    }
}

fn selected_store_error(report: &mut InvocationReport, error: &PublicationStoreError) {
    match error.kind {
        PublicationStoreErrorKind::Abandoned | PublicationStoreErrorKind::MissingPublication => {
            report.fail(
                Outcome::Refused,
                "abandoned or missing publication; explicit new acknowledgement required",
            );
            report.retention = Retention::Archive;
            report.archive = Some(error.path.clone());
            report.remedy("--new (archived publication may still land)");
        }
        PublicationStoreErrorKind::Selection => {
            report.fail(Outcome::Refused, "retained publication prevents the requested selection; use the original store and exact scope");
            report.retention = Retention::Unknown;
            report.uncertain = true;
            report.archive = Some(error.path.clone());
        }
        PublicationStoreErrorKind::Refused
        | PublicationStoreErrorKind::Corrupt
        | PublicationStoreErrorKind::RemoteIntegrity
        | PublicationStoreErrorKind::Conflict
        | PublicationStoreErrorKind::Fenced
        | PublicationStoreErrorKind::Unavailable
        | PublicationStoreErrorKind::Io => {
            report.fail(
                Outcome::LocalError,
                "publication storage validation or persistence failed",
            );
            report.retention = Retention::Unknown;
            report.uncertain = true;
            report.archive = Some(error.path.clone());
        }
    }
}
fn scope(args: &PublishArgs) -> Result<Option<Scope>, String> {
    args.configuration
        .context
        .as_ref()
        .map(|context| {
            granary_client::publication_config::publication_scope(
                &args.endpoint,
                args.tls_pins.as_deref().unwrap_or(&[]),
                context,
            )
            .map_err(|e| e.to_string())
        })
        .transpose()
}
fn select(
    args: &PublishArgs,
    store: &mut Store,
    euid: u32,
    scope: Option<&Scope>,
    report: &mut InvocationReport,
) -> Result<Option<Submission>, ()> {
    let mut journal = store
        .publications(euid)
        .map_err(|e| selected_store_error(report, &e))?;
    let retained = if let Some(scope) = scope {
        let result = if args.selection == Selection::New {
            journal.load_for_new(scope, &args.volume, MayLandAcknowledgement::Acknowledged)
        } else {
            journal.load(scope, &args.volume)
        };
        result.map_err(|e| selected_store_error(report, &e))?
    } else {
        journal
            .select_direct(&args.volume, acknowledgement(args.selection))
            .map_err(|e| selected_store_error(report, &e))?;
        None
    };
    if let Some(record) = &retained {
        if args.selection == Selection::New && !record.is_complete() {
            report.publication_id = Some(record.publication_id);
            report.retention = Retention::Live;
            report.uncertain = record
                .candidates
                .iter()
                .any(|c| !c.evidence.never_decided());
            report.fail(
                Outcome::Refused,
                "--new refuses an incomplete live publication",
            );
            report.remedy("resume the same publication");
            return Err(());
        }
        if args.direct_s3 || args.mode == PublishMode::LegacyServer {
            report.fail(
                Outcome::Refused,
                "retained publication requires authority recovery",
            );
            report.publication_id = Some(record.publication_id);
            report.retention = Retention::Live;
            return Err(());
        }
    }
    if let Selection::Recover(id) = args.selection
        && retained.as_ref().is_none_or(|r| r.publication_id != id)
    {
        report.publication_id = Some(id);
        report.fail(
            Outcome::Refused,
            "no matching live publication; archived IDs cannot be resumed",
        );
        report.retention = Retention::Archive;
        report.remedy("--new (archived publication may still land)");
        return Err(());
    }
    Ok(retained)
}

#[expect(
    clippy::too_many_lines,
    reason = "selection, local abandonment and transport construction form one ordered admission sequence"
)]
pub(crate) fn invoke(args: &PublishArgs, credentials: &ProcessCredentials) -> InvocationReport {
    let mut report = InvocationReport::new(Some(args.volume.clone()));
    report.action = if matches!(args.selection, Selection::Abandon(_)) {
        "abandon"
    } else {
        "publish"
    };
    if let Some(error) = set_id_refusal(credentials) {
        report.fail(Outcome::LocalError, error);
        return report;
    }
    let scope = match scope(args) {
        Ok(s) => s,
        Err(e) => {
            report.fail(Outcome::LocalError, e);
            return report;
        }
    };
    if !matches!(args.selection, Selection::Abandon(_)) {
        let checks = managed_path_checks(args).and_then(|()| {
            // Only an established Store can hold retained recovery state.
            // A fresh/mistargeted root must pass source separation before
            // Store::open creates even its lock or structural directories.
            if granary_client::is_store_marker(&args.store_dir.join(granary_client::MARKER_NAME)) {
                Ok(())
            } else {
                fresh_source_checks(args)
            }
        });
        if let Err(error) = checks {
            report.fail(Outcome::LocalError, error);
            return report;
        }
    }
    let mut store = match Store::open(&args.store_dir) {
        Ok(store) => store,
        Err(error) => {
            report.fail(
                Outcome::LocalError,
                match &error {
                    granary_client::StoreError::Incompatible { .. } => {
                        "incompatible store marker; use a store compatible with this build".into()
                    }
                    _ => error.to_string(),
                },
            );
            return report;
        }
    };
    // Abandonment bypasses ordinary selection, signer and credential loading,
    // runtime construction, transport, cache and source work.
    if let Selection::Abandon(id) = args.selection {
        report.route = Some(Route::Local);
        report.publication_id = Some(id);
        let Some(scope) = scope else {
            report.fail(
                Outcome::LocalError,
                "abandonment requires credential context",
            );
            return report;
        };
        let result = store.publications(credentials.euid).and_then(|mut j| {
            j.abandon(
                &scope,
                &args.volume,
                id,
                MayLandAcknowledgement::Acknowledged,
            )
        });
        match result {
            Ok(done) => {
                #[cfg(feature = "publish-restart-tests")]
                {
                    report.restart_record = Some(done.archive.submission.clone());
                }
                report.outcome = Outcome::Abandoned;
                report.retention = Retention::Archive;
                report.uncertain = done.archive.uncertain;
                report.archive = Some(done.archive.path);
                report.pin_difference = done.pin_difference;
            }
            Err(e) => selected_store_error(&mut report, &e),
        }
        return report;
    }
    let Ok(retained) = select(
        args,
        &mut store,
        credentials.euid,
        scope.as_ref(),
        &mut report,
    ) else {
        return report;
    };
    if args.selection == Selection::New {
        report.previous_completion_id = retained.as_ref().map(|r| r.publication_id);
        warn_new();
    }
    let resuming = retained.is_some() && args.selection != Selection::New;
    if resuming && let Some(record) = &retained {
        report.publication_id = Some(record.publication_id);
        report.retention = Retention::Live;
        report.uncertain = record
            .candidates
            .iter()
            .any(|c| !c.evidence.never_decided());
    }
    let credential = match args.configuration.load(credentials.euid) {
        Ok(c) => c,
        Err(e) => {
            report.fail(Outcome::LocalError, e.to_string());
            return report;
        }
    };
    let tls_identity = credential
        .as_ref()
        .map(granary_client::ClientCredential::key_file_identity);
    let route = match open_publish_route_with_client_credential(
        &args.endpoint,
        args.tls_pins.clone(),
        args.direct_s3,
        args.bucket.as_deref(),
        credential,
        &|name| std::env::var(name).ok(),
    ) {
        Ok(route) => route,
        Err(error) => {
            report.fail(Outcome::LocalError, route_diagnostic(&error));
            return report;
        }
    };
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        report.fail(Outcome::LocalError, "runtime could not be created");
        return report;
    };
    let status = if !resuming && let PublishRoute::Server(remote) = &route {
        match runtime.block_on(remote.status_once(args.volume.as_str())) {
            Ok(status) => {
                report.routing_evidence = Some(Identification::status(&status));
                if preflight(args.mode, &status) == Preflight::Stop {
                    stopped_status(&mut report, &status);
                    return report;
                }
                Some(status)
            }
            Err(error) => {
                authority_error(&mut report, &error);
                return report;
            }
        }
    } else {
        None
    };
    if !resuming && let Err(error) = fresh_source_checks(args) {
        report.fail(Outcome::LocalError, error);
        return report;
    }
    let key = match load_or_create_key_with_identity(&args.key_seed, credentials, args.json) {
        Ok(key) => key,
        Err(error) => {
            report.fail(Outcome::LocalError, error);
            return report;
        }
    };
    let protected = PublishConfiguration::protected_files(key.seed_identity, tls_identity);
    let mut cache = CacheOnDrop(None);
    match &route {
        PublishRoute::Server(remote) => {
            runtime.block_on(server(
                args,
                credentials.euid,
                remote.as_ref(),
                &mut store,
                &key.key,
                &protected,
                scope,
                retained,
                status,
                &mut cache,
                &mut report,
            ));
            report.response_bytes = remote.wire_bytes().total();
            snapshot(args, &report, remote.wire_bytes().total());
        }
        PublishRoute::DirectS3(remote) => {
            report.route = Some(Route::DirectS3);
            runtime.block_on(direct(
                args,
                credentials.euid,
                remote.as_ref(),
                &mut store,
                &key.key,
                &protected,
                &mut cache,
                &mut report,
            ));
            if args.wire.is_some() {
                let _ = std::io::Write::write_all(
                    &mut std::io::stderr(),
                    b"wire-snapshot not written: --direct-s3 has no wire-byte counter\n",
                );
            }
        }
    }
    report
}
fn fresh_source_checks(args: &PublishArgs) -> Result<(), String> {
    refuse_store_as_source(&args.source)?;
    refuse_nesting(&args.source, &args.store_dir)?;
    refuse_cache_dir_nesting(args.cache_dir.as_deref(), &args.source, &args.store_dir)?;
    refuse_key_seed_nesting(
        &args.key_seed,
        &args.source,
        &args.store_dir,
        args.cache_dir.as_deref(),
    )?;
    refuse_tls_key_directory(&args.source, args.configuration.key.as_deref())
}
fn managed_path_checks(args: &PublishArgs) -> Result<(), String> {
    refuse_managed_paths(
        &args.key_seed,
        args.configuration.key.as_deref(),
        &args.store_dir,
        args.cache_dir.as_deref(),
    )
}
fn route_diagnostic(error: &RouteError) -> String {
    match error {
        // Provider errors may include endpoint or credential values. Preserve
        // only the known configuration name from a missing-variable refusal.
        RouteError::Store(message) => match message.as_str() {
            "Generic S3 error: Missing AccessKeyId" => {
                "object store: missing AWS_ACCESS_KEY_ID".into()
            }
            "Generic S3 error: Missing SecretAccessKey" => {
                "object store: missing AWS_SECRET_ACCESS_KEY".into()
            }
            _ => "object store configuration is invalid".into(),
        },
        _ => error.to_string(),
    }
}

fn open_cache(
    args: &PublishArgs,
    signer: &SigningKey,
    cache: &mut CacheOnDrop,
    report: &mut InvocationReport,
) -> Result<(), ()> {
    if cache.0.is_some() {
        return Ok(());
    }
    if let Some(dir) = &args.cache_dir {
        report.cache = Advisory::new("not-attempted", None);
        cache.0 = Some(
            Cache::open(
                dir,
                DEFAULT_CACHE_QUOTA_BYTES,
                &cache_origin(
                    &args.endpoint,
                    args.tls_pins.as_deref().unwrap_or(&[]),
                    Some(signer.public_key()),
                ),
            )
            .map_err(|error| {
                report.fail(Outcome::LocalError, match &error {
                    granary_client::CacheError::Incompatible { .. } => "incompatible cache marker or origin; use a cache compatible with this route".into(),
                    granary_client::CacheError::Io { .. } => error.to_string(),
                });
            })?,
        );
    }
    Ok(())
}
#[derive(Debug, PartialEq, Eq)]
enum Preflight {
    Coordinator,
    Seam,
    Stop,
}
fn preflight(mode: PublishMode, status: &StatusResponse) -> Preflight {
    match (mode, status) {
        (PublishMode::Auto | PublishMode::Authority, StatusResponse::Observed(_))
        | (PublishMode::Auto, StatusResponse::Refused(StatusRefusal::UnknownVolume)) => {
            Preflight::Coordinator
        }
        (
            PublishMode::LegacyServer,
            StatusResponse::Refused(StatusRefusal::UnknownVolume | StatusRefusal::UnknownTarget),
        ) => Preflight::Seam,
        _ => Preflight::Stop,
    }
}
fn write_admission(
    args: &PublishArgs,
    configured: bool,
    authority: bool,
) -> Result<(), &'static str> {
    if configured && args.configuration.certificate.is_none() {
        return Err("authority-configured writes require --client-cert and --client-key");
    }
    if authority && args.configuration.context.is_none() {
        return Err("authority publication requires --credential-context");
    }
    Ok(())
}
fn stopped_status(report: &mut InvocationReport, status: &StatusResponse) {
    report.routing_evidence = Some(Identification::status(status));
    match status {
        StatusResponse::ServiceUnavailable(_) => {
            report.fail(
                Outcome::Pending,
                "authority unavailable; no submission started",
            );
            report.remedy("re-run the invocation");
        }
        StatusResponse::Internal => report.fail(
            Outcome::BackendError,
            "authority returned internal failure; no submission started",
        ),
        StatusResponse::Refused(StatusRefusal::UnknownTarget) => {
            report.fail(Outcome::Refused, "authority endpoint is unknown; verify endpoint or explicitly choose --publish-mode legacy-server");
            report.remedy("verify endpoint or choose --publish-mode legacy-server");
        }
        StatusResponse::Refused(StatusRefusal::NoLog) => {
            report.fail(
                Outcome::Refused,
                "served volume requires authority initialisation",
            );
            report.remedy("initialise the authority log");
        }
        _ => {
            report.fail(
                Outcome::Refused,
                "checked status refuses the selected publication route",
            );
            report.remedy("verify mode, volume and authority configuration");
        }
    }
}
fn authority_error(report: &mut InvocationReport, error: &AuthorityError) {
    match error {
        AuthorityError::Backend(_) => report.fail(
            Outcome::BackendError,
            "authority peer response failed validation",
        ),
        AuthorityError::Elapsed => report.fail(
            Outcome::LocalError,
            "authority call deadline elapsed before submission",
        ),
        AuthorityError::Transport(_) => report.fail(
            Outcome::LocalError,
            "authority TLS or connection failed before submission",
        ),
        AuthorityError::Request(_) => report.fail(
            Outcome::LocalError,
            "authority request configuration is invalid",
        ),
    }
}
fn apply_result(report: &mut InvocationReport, result: PublicationResult) {
    #[cfg(feature = "publish-restart-tests")]
    {
        report.restart_record.clone_from(&result.restart_record);
    }
    report.publication_id = Some(result.handle.publication_id);
    report.retention = Retention::Live;
    report.uncertain = result.uncertain;
    report.response = result.response.as_ref().map(Identification::response);
    report.diagnostic = result.diagnostic.map(|message| match message.as_str() {
        "candidate capacity exhausted" | "probe unresolved" | "probe interrupted; explicit recovery required"
        | "probe unresolved; explicit recovery required" | "loaded rebase; explicit recovery required"
        | "unresolved retired candidate is not at target" | "stale retry release was not proven"
        | "open entry under foreign occupancy: possible wedge, repaired out of band" => message,
        _ => "publication work stopped; inspect checked response and explicitly recover retained content".into(),
    });
    report.outcome = match result.outcome {
        PublicationOutcome::Landed(done) => {
            report.completion = Some(Winner::authority(&done));
            Outcome::Landed
        }
        PublicationOutcome::Pending => Outcome::Pending,
        PublicationOutcome::Refused => Outcome::Refused,
        PublicationOutcome::Unresolved | PublicationOutcome::Exhausted => Outcome::Unresolved,
        PublicationOutcome::BackendError => Outcome::BackendError,
    };
    if report.outcome != Outcome::Landed {
        report.remedy("continue or explicitly recover the retained publication; abandonment stops local recovery but cannot repair a wedged volume");
    }
}
fn recovery_error(report: &mut InvocationReport, error: &RecoveryError) {
    match error {
        RecoveryError::Bootstrap(s) => stopped_status(report, s),
        RecoveryError::Authority(e) => authority_error(report, e),
        RecoveryError::Journal(e) => {
            selected_store_error(report, e);
            report.retention = Retention::Unknown;
            report.uncertain = true;
        }
        RecoveryError::Preparation(e) => direct_error(report, e, false),
        RecoveryError::RemoteIntegrity(rule) => report.fail(
            Outcome::BackendError,
            format!("remote publication history failed verification: {rule}"),
        ),
        RecoveryError::Remote(_) => report.fail(
            Outcome::BackendError,
            "remote verification evidence is unusable",
        ),
        RecoveryError::Record(e) => report.fail(
            Outcome::LocalError,
            format!(
                "publication could not be prepared or persisted: {}",
                record_kind(e)
            ),
        ),
        RecoveryError::Entropy(_) => report.fail(
            Outcome::LocalError,
            "publication could not be prepared or persisted: no cryptographic randomness was available",
        ),
        RecoveryError::Invalid(rule) => report.fail(
            Outcome::LocalError,
            format!("publication could not be prepared or persisted: invalid state: {rule}"),
        ),
        RecoveryError::Refused(rule) => report.fail(Outcome::Refused, *rule),
    }
}
/// A retained-record failure, rendered without the decode detail: every
/// other arm's own text is a fixed phrase or a static rule.
fn record_kind(error: &granary_core::retained_submission::Error) -> String {
    use granary_core::retained_submission::Error;
    match error {
        Error::Decode(_) => "retained submission could not be decoded".into(),
        other => other.to_string(),
    }
}
/// A remote-store failure named by kind only. The backend's own text can
/// carry an endpoint, a key or server-supplied bytes, so it is never
/// rendered. A call that carries a status names the call and the number;
/// every other variant is its [`RootStoreError::kind`] label, except the
/// free-text `Backend`, which stays the fixed phrase "backend error".
///
/// The server keeps the labels it logs and this diagnostic reuses them, so
/// one vocabulary names a store failure on both sides.
fn remote_kind(error: &RootStoreError) -> String {
    match error {
        RootStoreError::Unavailable { operation, status }
        | RootStoreError::UnexpectedStatus {
            operation, status, ..
        } => format!("{operation}: status {status}"),
        RootStoreError::Elapsed { operation, after } => {
            format!("{operation}: no answer within {}s", after.as_secs())
        }
        RootStoreError::Backend(_) => "backend error".into(),
        other => other.kind().into(),
    }
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one authority dispatch carries the selected record, owned lock, protected identities and checked report"
)]
async fn server<T: AuthorityTransport>(
    args: &PublishArgs,
    euid: u32,
    remote: &T,
    store: &mut Store,
    signer: &SigningKey,
    protected: &[FileIdentity],
    scope: Option<Scope>,
    retained: Option<Submission>,
    status: Option<StatusResponse>,
    cache: &mut CacheOnDrop,
    report: &mut InvocationReport,
) {
    let resuming = retained.is_some() && args.selection != Selection::New;
    let mut preflight_unknown_volume = false;
    if !resuming {
        let status = match status {
            Some(s) => s,
            None => match remote.status_once(args.volume.as_str()).await {
                Ok(s) => s,
                Err(e) => {
                    authority_error(report, &e);
                    return;
                }
            },
        };
        report.routing_evidence = Some(Identification::status(&status));
        preflight_unknown_volume = matches!(
            status,
            StatusResponse::Refused(StatusRefusal::UnknownVolume)
        );
        match preflight(args.mode, &status) {
            Preflight::Stop => {
                stopped_status(report, &status);
                return;
            }
            Preflight::Seam => {
                if let Err(error) = write_admission(
                    args,
                    status.authority_configuration() == AuthorityConfiguration::Configured,
                    false,
                ) {
                    report.fail(Outcome::LocalError, error);
                    return;
                }
                seam(
                    args, euid, remote, store, signer, protected, cache, report, &status,
                )
                .await;
                return;
            }
            Preflight::Coordinator => {}
        }
    }
    if let Err(error) = write_admission(args, true, false) {
        report.fail(Outcome::LocalError, error);
        return;
    }
    if scope.is_none() {
        if args.mode == PublishMode::Auto {
            match bootstrap_publication(remote, &args.volume).await {
                Err(RecoveryError::Bootstrap(status))
                    if bootstrap_seam(args.mode, resuming, preflight_unknown_volume, &status) =>
                {
                    seam(
                        args, euid, remote, store, signer, protected, cache, report, &status,
                    )
                    .await;
                }
                Err(error) => recovery_error(report, &error),
                Ok(_) => report.fail(
                    Outcome::LocalError,
                    "authority publication requires --credential-context",
                ),
            }
        } else {
            report.fail(
                Outcome::LocalError,
                "authority publication requires --credential-context",
            );
        }
        return;
    }
    if let Err(error) = write_admission(args, true, true) {
        report.fail(Outcome::LocalError, error);
        return;
    }
    let trust = match args.configuration.publishers.build(*signer.public_key()) {
        Ok(t) => t,
        Err(e) => {
            report.fail(Outcome::LocalError, e.to_string());
            return;
        }
    };
    if open_cache(args, signer, cache, report).is_err() {
        return;
    }
    report.route = Some(Route::Authority);
    let mut secure = OsSecureRandom::new();
    let mut delay = RecoveryBackoff {
        rng: granary_core::rng::ProcessRng::new(),
    };
    let result = if let Some(record) = retained.filter(|_| resuming) {
        let handle = PublicationHandle {
            scope: record.scope,
            volume: record.volume,
            publication_id: record.publication_id,
        };
        let mut journal = match store.publications(euid) {
            Ok(j) => j,
            Err(e) => {
                selected_store_error(report, &e);
                return;
            }
        };
        resume_publication(
            RecoveryParts {
                transport: remote,
                journal: &mut journal,
                publisher_keys: &trust,
                signer,
                secure: &mut secure,
                clock: &WallClock,
                delay: &mut delay,
            },
            &handle,
            if matches!(args.selection, Selection::Recover(_)) {
                RecoveryIntent::ExplicitRecovery
            } else {
                RecoveryIntent::Continue
            },
        )
        .await
    } else {
        if let Err(error) = fresh_source_checks(args) {
            report.fail(Outcome::LocalError, error);
            return;
        }
        let manifest = match harvest_excluding_files(&args.source, store, protected) {
            Ok((manifest, _)) => manifest,
            Err(error) => {
                direct_error(report, &PublishError::Harvest(error), false);
                return;
            }
        };
        let Some(scope) = scope else {
            report.fail(
                Outcome::LocalError,
                "authority publication requires --credential-context",
            );
            return;
        };
        let mut journal = match store.publications(euid) {
            Ok(j) => j,
            Err(e) => {
                selected_store_error(report, &e);
                return;
            }
        };
        if args.selection == Selection::New {
            let mut journal = NewJournal {
                store: &mut journal,
                scope: &scope,
                volume: &args.volume,
            };
            begin_publication(
                RecoveryParts {
                    transport: remote,
                    journal: &mut journal,
                    publisher_keys: &trust,
                    signer,
                    secure: &mut secure,
                    clock: &WallClock,
                    delay: &mut delay,
                },
                scope.clone(),
                args.volume.clone(),
                manifest,
                Policy::default(),
            )
            .await
        } else {
            begin_publication(
                RecoveryParts {
                    transport: remote,
                    journal: &mut journal,
                    publisher_keys: &trust,
                    signer,
                    secure: &mut secure,
                    clock: &WallClock,
                    delay: &mut delay,
                },
                scope,
                args.volume.clone(),
                manifest,
                Policy::default(),
            )
            .await
        }
    };
    match result {
        Err(RecoveryError::Bootstrap(status))
            if bootstrap_seam(args.mode, resuming, preflight_unknown_volume, &status) =>
        {
            if let Err(error) = write_admission(
                args,
                status.authority_configuration() == AuthorityConfiguration::Configured,
                false,
            ) {
                report.fail(Outcome::LocalError, error);
                return;
            }
            seam(
                args, euid, remote, store, signer, protected, cache, report, &status,
            )
            .await;
        }
        Ok(result) => {
            let completion = if let PublicationOutcome::Landed(done) = &result.outcome {
                Some(done.clone())
            } else {
                None
            };
            apply_result(report, result);
            if let Some(done) = completion {
                repair(
                    remote,
                    cache.0.as_mut(),
                    &args.volume,
                    signer,
                    &trust,
                    &done,
                    report,
                )
                .await;
            }
        }
        Err(error) => recovery_error(report, &error),
    }
}
fn bootstrap_seam(
    mode: PublishMode,
    resuming: bool,
    preflight_unknown_volume: bool,
    status: &StatusResponse,
) -> bool {
    mode == PublishMode::Auto
        && !resuming
        && preflight_unknown_volume
        && matches!(
            status,
            StatusResponse::Refused(StatusRefusal::UnknownVolume)
        )
}
fn warn_new() {
    let _ = std::io::Write::write_all(&mut std::io::stderr(), b"gran publish: explicit new publication: archived publication may still land; identical content can become another committed version\n");
}
#[expect(
    clippy::too_many_arguments,
    reason = "seam admission uses the same selected store and configured transport"
)]
async fn seam<T: RootStore + BinStore>(
    args: &PublishArgs,
    euid: u32,
    remote: &T,
    store: &mut Store,
    signer: &SigningKey,
    protected: &[FileIdentity],
    cache: &mut CacheOnDrop,
    report: &mut InvocationReport,
    status: &StatusResponse,
) {
    if let Err(e) = args.configuration.publishers.require_authority() {
        report.fail(Outcome::LocalError, e.to_string());
        return;
    }
    report.routing_evidence = Some(Identification::status(status));
    report.route = Some(Route::ServerSeam);
    let (code, token) = status.identification();
    let _ = std::io::Write::write_fmt(
        &mut std::io::stderr(),
        format_args!(
            "route=server-seam status={code} token={} reason=checked unserved or explicitly selected legacy endpoint\n",
            token.unwrap_or("none")
        ),
    );
    if open_cache(args, signer, cache, report).is_err() {
        return;
    }
    direct(args, euid, remote, store, signer, protected, cache, report).await;
}
#[expect(
    clippy::too_many_arguments,
    reason = "direct publication preserves exact prepared bytes under the selected Store lock"
)]
async fn direct<T: RootStore + BinStore>(
    args: &PublishArgs,
    euid: u32,
    remote: &T,
    store: &mut Store,
    signer: &SigningKey,
    protected: &[FileIdentity],
    cache: &mut CacheOnDrop,
    report: &mut InvocationReport,
) {
    let mut journal = match store.publications(euid) {
        Ok(journal) => journal,
        Err(error) => {
            selected_store_error(report, &error);
            return;
        }
    };
    if let Err(e) = journal.select_direct(&args.volume, acknowledgement(args.selection)) {
        selected_store_error(report, &e);
        return;
    }
    if let Err(error) = fresh_source_checks(args) {
        report.fail(Outcome::LocalError, error);
        return;
    }
    let Ok(identity) = writer_identity(&mut OsSecureRandom::new()) else {
        report.fail(Outcome::LocalError, "writer entropy unavailable");
        return;
    };
    let prepared = match prepare_excluding_files(
        remote,
        journal.content_store(),
        &args.source,
        protected,
        &args.volume,
        signer,
        &identity,
        WallClock.now(),
        Policy::default(),
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            direct_error(report, &e, false);
            return;
        }
    };
    let root = prepared.root_bytes.clone();
    match commit(remote, prepared).await {
        Ok(summary) => {
            report.outcome = Outcome::Landed;
            report.retention = Retention::None;
            report.uncertain = false;
            report.completion = Some(Winner {
                seq: summary.seq,
                id: GrainId::of(&root),
                manifest_root: Some(summary.manifest_root),
                root_epoch: Some(summary.epoch),
                evidence: "direct",
                receipt: None,
            });
            cache_winner(cache.0.as_mut(), &args.volume, summary.seq, &root, report);
            report.hint = if summary.hint_written {
                Advisory::new("written", None)
            } else {
                Advisory::new("failed", Some("readers forward-probe"))
            };
            report.summary = Some(summary);
        }
        Err(error) => direct_error(report, &error, true),
    }
    // Keep the publication borrow live until commit and its reporting finish.
    let _ = journal.content_store();
}
fn direct_error(report: &mut InvocationReport, error: &PublishError, commit_started: bool) {
    // Every variant is classified here and no arm is a wildcard: a new
    // `PublishError` variant must choose its outcome and its text.
    let (outcome, text): (Outcome, String) = match error {
        PublishError::LostRace { .. } => (
            Outcome::Refused,
            "publication lost the race: another writer holds the attempted seq; nothing was committed, re-run to resolve the verified head".into(),
        ),
        PublishError::Unresolved { put_error } => (
            Outcome::Unresolved,
            format!(
                "publication outcome unknown: the put failed ({}) and the settling probe found nothing at the attempted seq; it may have landed, inspect verified remote state",
                remote_kind(put_error)
            ),
        ),
        PublishError::ProbeUnresolved {
            put_error,
            probe_error,
        } => (
            Outcome::Unresolved,
            format!(
                "publication outcome unknown: the put failed ({}) and the settling probe failed ({}); it may have landed, inspect verified remote state",
                remote_kind(put_error),
                remote_kind(probe_error)
            ),
        ),
        PublishError::Remote(e) => (
            Outcome::BackendError,
            format!(
                "publication failed at a remote store call ({}); inspect verified remote state before retrying",
                remote_kind(e)
            ),
        ),
        PublishError::Decode { what, .. } => remote_state(&format!("{what} failed to decode")),
        PublishError::MissingRoot { .. } => remote_state("a listed root is missing"),
        PublishError::MissingMeta { .. } => remote_state("a metadata object is missing"),
        PublishError::VolumeMismatch { .. } => remote_state("the head root names another volume"),
        PublishError::SeqMismatch { .. } => remote_state("a root's seq differs from its key"),
        PublishError::UnknownSigner { .. } => {
            remote_state("the head root carries no signature by this key")
        }
        PublishError::BadSignature { .. } => remote_state("a root signature failed verification"),
        PublishError::CorruptMeta { .. } => {
            remote_state("a metadata object does not hash to its id")
        }
        PublishError::NotAManifestNode { .. } => {
            remote_state("an object is not a manifest node")
        }
        PublishError::Harvest(granary_client::HarvestError::Store(
            granary_client::StoreError::Incompatible { .. },
        )) => (
            Outcome::LocalError,
            "harvest: incompatible store marker".into(),
        ),
        PublishError::Source(GrainSourceError::Backend(_)) => (
            Outcome::LocalError,
            "publication failed reading the local store (backend error)".into(),
        ),
        PublishError::Harvest(_)
        | PublishError::Source(GrainSourceError::Missing(_) | GrainSourceError::Corrupt(_))
        | PublishError::Codec(_)
        | PublishError::EncodeBin(_)
        | PublishError::EncodeBinmap(_)
        | PublishError::EncodeSheaf(_)
        | PublishError::EncodeRoot(_)
        | PublishError::MissingObject { .. }
        | PublishError::RootTooLarge { .. }
        | PublishError::FrameTooLong { .. }
        | PublishError::CounterOverflow { .. } => (Outcome::LocalError, error.to_string()),
        PublishError::BadPlan => (
            Outcome::LocalError,
            "publication failed: internal bin plan does not cover its frames".into(),
        ),
        PublishError::BinmapConstruction => (
            Outcome::LocalError,
            "publication failed: internal binmap construction integrity failure".into(),
        ),
        PublishError::ReservedVolumeName { .. } => (
            Outcome::LocalError,
            "publication refused: the volume does not exist and its name is reserved; nothing was uploaded, but the source tree was already harvested into the local store".into(),
        ),
    };
    report.fail(outcome, text);
    report.uncertain |= commit_started
        && matches!(
            error,
            PublishError::Unresolved { .. } | PublishError::ProbeUnresolved { .. }
        );
    if report.uncertain {
        report.remedy("read the head back or re-run the direct route to converge");
    }
}
/// A remote-integrity failure: the remote state read back is not what a
/// verified chain holds. Named by a fixed phrase, never by peer bytes.
fn remote_state(what: &str) -> (Outcome, String) {
    (
        Outcome::BackendError,
        format!(
            "publication failed verifying remote state: {what}; inspect verified remote state before retrying"
        ),
    )
}
fn cache_winner(
    cache: Option<&mut Cache>,
    volume: &VolumeName,
    seq: u64,
    root: &[u8],
    report: &mut InvocationReport,
) {
    if let Some(cache) = cache {
        if cache.is_read_only_degraded() {
            report.cache = Advisory::new(
                "skipped",
                Some("cache lock is held; warm the cache after the lock is released"),
            );
        } else {
            #[cfg(feature = "publish-restart-tests")]
            report.restart_point("cache-repair", "before");
            cache.put_root_bytes(volume, seq, root);
            cache.raise_anchor(volume, Some(seq), HintUpdate::Unchanged);
            report.cache = if cache.get_root_bytes(volume, seq).as_deref() == Some(root)
                && cache.read_anchor(volume).is_some_and(|a| a.seq >= seq)
            {
                Advisory::new("written", None)
            } else {
                Advisory::new(
                    "failed",
                    Some("root or anchor admission failed; repeat completion to repair"),
                )
            };
            #[cfg(feature = "publish-restart-tests")]
            report.restart_point("cache-repair", "after");
        }
    }
}
async fn repair<T: RootStore>(
    remote: &T,
    cache: Option<&mut Cache>,
    volume: &VolumeName,
    signer: &SigningKey,
    trust: &TrustedKeys,
    done: &Completion,
    report: &mut InvocationReport,
) {
    // Completion's owned binding is checked independently of the cache origin.
    if GrainId::of(&done.root) != done.id
        || check_head(&done.root, volume.as_str(), done.seq, trust).is_err()
    {
        report.cache = Advisory::new("skipped", Some("winner binding could not be verified"));
        report.hint = Advisory::new(
            "not-attempted",
            Some("winner binding could not be verified"),
        );
        return;
    }
    let origin = TrustedKeys::new([*signer.public_key()]);
    if origin
        .as_ref()
        .is_ok_and(|keys| check_head(&done.root, volume.as_str(), done.seq, keys).is_ok())
    {
        cache_winner(cache, volume, done.seq, &done.root, report);
    } else if cache.is_some() {
        report.cache = Advisory::new(
            "skipped",
            Some("winner is excluded by the cache root-key origin"),
        );
    }
    #[cfg(feature = "publish-restart-tests")]
    report.restart_point("hint-repair", "before");
    let hint_result = remote.write_hint(volume.as_str(), done.seq).await;
    #[cfg(feature = "publish-restart-tests")]
    report.restart_point("hint-repair", "after");
    report.hint = if hint_result.is_ok() {
        Advisory::new("written", None)
    } else {
        Advisory::new(
            "failed",
            Some("readers forward-probe; repeat completion to repair"),
        )
    };
}
fn snapshot(args: &PublishArgs, report: &InvocationReport, response_bytes: Option<u64>) {
    let Some(wire) = &args.wire else {
        return;
    };
    let publish = report.completion.as_ref().map(|winner| PublishFields {
        seq: winner.seq,
        novel_objects: report.summary.map(|s| s.novel_objects),
        novel_bytes: report.summary.map(|s| s.novel_bytes),
        bins_uploaded: report.summary.map(|s| s.bins_uploaded),
        bin_bytes_uploaded: report.summary.map(|s| s.bin_bytes_uploaded),
        manifest_root: winner.manifest_root.map(|id| id.to_string()),
    });
    if write_client_snapshot(
        &wire.path,
        &wire.run_id,
        &wire.role,
        &ClientTotals {
            response_bytes,
            endpoint: Some(args.endpoint.clone()),
            pinned_seq: None,
            publish,
        },
    )
    .is_err()
    {
        let _ = std::io::Write::write_all(
            &mut std::io::stderr(),
            b"wire-snapshot not written (advisory)\n",
        );
    }
}

#[cfg(test)]
mod tests;
