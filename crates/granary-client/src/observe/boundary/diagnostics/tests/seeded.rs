// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::observe::boundary::path_class;
use crate::observe::boundary::*;
use crate::observe::tests::Fixed;
use std::ffi::OsStr;
use std::path::Path;

use super::scan;

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "exhaustive format/policy/event/field/surface sweep with nonempty paired controls"
)]
fn every_event_seeded_secret_sweep_checks_projections_outputs_history_and_metrics() {
    let path = Path::new(scan::ORDINARY[0]);
    let name = OsStr::new(scan::ORDINARY[2]);
    let mut prior_bundle = None;
    let metrics = crate::ClientMetrics::new(&mut Fixed(&[42; 16]));
    metrics.record_retry(RetryReason::Conflict);
    let baseline_metrics = metrics.snapshot().unwrap().render_prometheus().unwrap();
    for format in [LogFormat::Json, LogFormat::Text] {
        for policy in [LogPaths::Redacted, LogPaths::Full] {
            let output = Capture::default();
            let history = BundleHistory::default();
            let subscriber = closed_subscriber_with_paths(
                format,
                EnvFilter::new("trace"),
                output.clone(),
                policy,
                history.clone(),
            );
            let mut projections = Vec::new();
            let mut events: Vec<_> = fixtures::diagnostics()
                .into_iter()
                .map(|event| ClientEvent {
                    payload: Payload::Diagnostic(event.inner),
                })
                .collect();
            events.extend(fixtures::events());
            if !cfg!(feature = "overlay-fault-tests") {
                events.push(ClientEvent::overlay_fault(
                    OverlayFaultPoint::StageWrite,
                    FaultPhase::Before,
                    2,
                    9,
                ));
                events.push(ClientEvent::sync_fault(
                    SyncFaultPoint::Capture,
                    SyncFaultPhase::After,
                    2,
                    SyncObjectKind::None,
                ));
            }
            let faults: &[(&str, &[&str])] = if cfg!(feature = "overlay-fault-tests") {
                &[]
            } else {
                &[
                    (
                        "overlay.fault",
                        &["event", "point", "phase", "occurrence", "record_index"],
                    ),
                    (
                        "sync.fault",
                        &["event", "point", "phase", "occurrence", "object_kind"],
                    ),
                ]
            };
            let inventory: Vec<_> = fixtures::INVENTORY
                .iter()
                .chain(fixtures::EVENT_INVENTORY)
                .copied()
                .chain(faults.iter().copied())
                .collect();
            assert_eq!(
                events.len(),
                inventory.len(),
                "nonempty independent inventory"
            );
            let mut registered: Vec<_> = crate::observe::boundary::SITES
                .iter()
                .filter(|meta| meta.is_event())
                .chain(crate::observe::boundary::diagnostics::SITES)
                .map(|meta| {
                    (
                        meta.name(),
                        meta.fields()
                            .iter()
                            .map(|field| field.name())
                            .collect::<Vec<_>>(),
                    )
                })
                .collect();
            let mut expected: Vec<_> = inventory
                .iter()
                .map(|(name, fields)| (*name, fields.to_vec()))
                .collect();
            registered.sort();
            expected.sort();
            // The inventory exercises multiple typed value variants for some
            // sites. Collapse only the retry diagnostic's second value
            // variant when comparing it with that site's single registered
            // callsite; other same-name callsites retain their multiplicity,
            // and the emitted events and independent inventory remain paired.
            let mut retry_site_seen = false;
            expected.retain(|(name, _fields)| {
                if *name != "client.seam.attempt.failed.retrying.once" {
                    return true;
                }
                let keep = !retry_site_seen;
                retry_site_seen = true;
                keep
            });
            assert_eq!(
                (registered == expected, registered.len()),
                (true, 150),
                "registered identity/field inventory must be exactly and completely exercised: registered={registered:?}, expected={expected:?}"
            );
            // The bundle's log member names exactly these events, and the
            // records the layer writes without a registered site.
            let mut core_events: Vec<_> = granary_core::support::bundle_record_events().collect();
            let mut known: Vec<_> = registered
                .iter()
                .map(|(name, _)| *name)
                .chain(["log.line", "log.sink_loss", "log.record_refused"])
                .collect();
            core_events.sort_unstable();
            known.sort_unstable();
            // One event can register a site per level.
            known.dedup();
            assert!(
                core_events == known,
                "core's event list drifted from the registered sites"
            );
            tracing::subscriber::with_default(subscriber, || {
                let id = CorrelationId::draw(&mut Fixed(&[42; 8])).unwrap();
                let span = closed_operation_span(OperationKind::Commit, &id);
                let _entered = span.enter();
                span.record("kind", "rebase");
                for (event, (identity, expected)) in events.iter().zip(&inventory) {
                    let (meta, fields) = event.fields();
                    assert!(
                        meta.name() == *identity,
                        "independent event identity mismatch"
                    );
                    let actual: Vec<_> = meta.fields().iter().map(|field| field.name()).collect();
                    assert!(actual == *expected, "independent event field set mismatch");
                    let mut slots = Vec::new();
                    for field in *expected {
                        if let Some(class) = path_class(meta, field) {
                            slots.push(if class == "<name>" {
                                PathSlot::Name(field, LogName::entry(name))
                            } else {
                                PathSlot::Path(
                                    field,
                                    match class {
                                        "<file>" => LogPath::file(path),
                                        "<directory>" => LogPath::directory(path),
                                        "<cache-root>" => LogPath::cache_root(path),
                                        _ => panic!("unexpected ordinary path role"),
                                    },
                                )
                            });
                        }
                    }
                    let projected = project_slots(meta, &fields, &slots, policy);
                    projections.push(encode(meta, &projected, &[], format));
                    let (log, bundle) = event.project();
                    projections.push(std::str::from_utf8(log.as_bytes()).unwrap().to_owned());
                    projections.push(bundle.as_str().to_owned());
                    event.emit_paths(&slots);
                }
                // Untrusted strings cannot become event payloads: exercise the real
                // adapter and foreign boundary, including inherited span updates.
                for secret in scan::SECRETS {
                    span.record("kind", *secret);
                    tracing::warn!(target: "dependency", token = *secret, error = *secret);
                }
            });
            assert_eq!(
                scan::scan(&projections, scan::SECRETS),
                Ok(()),
                "seeded prequeue secret absence"
            );
            if policy == LogPaths::Redacted {
                assert_eq!(
                    scan::scan(&projections, scan::ORDINARY),
                    Ok(()),
                    "seeded default full-path and basename absence"
                );
            }
            let lines = output.lines();
            // Per secret: one refused span update. The dependency callsite inside the
            // loop is one callsite, refused once however often it fires.
            let refusals = scan::SECRETS.len() + 1;
            assert_eq!(
                lines.len(),
                events.len() + refusals,
                "every event and both refusal premises must emit"
            );
            assert!(
                lines
                    .iter()
                    .take(events.len())
                    .all(|line| line.contains("cor-2a2a2a2a2a2a2a2a")),
                "entered operation and approved update required"
            );
            assert!(
                lines
                    .iter()
                    .take(events.len())
                    .all(|line| !line.contains("log.record_refused")),
                "legitimate events must pass"
            );
            for (line, (identity, expected)) in lines.iter().zip(&inventory) {
                assert!(
                    fixtures::has_identity(line, identity),
                    "emitted independent identity missing"
                );
                if format == LogFormat::Json {
                    let mut keys = crate::observe::tests::top_level_keys(line);
                    let mut required: Vec<_> =
                        expected.iter().map(|field| (*field).to_owned()).collect();
                    required.extend(["level", "target", "spans"].map(str::to_owned));
                    keys.sort();
                    required.sort();
                    assert!(
                        keys == required,
                        "emitted exact independent field set changed"
                    );
                    let mut core: Vec<_> = granary_core::support::bundle_record_keys(identity)
                        .into_iter()
                        .flatten()
                        .map(str::to_owned)
                        .collect();
                    core.sort();
                    // An event whose levels carry different fields: core
                    // holds every field any of them carries.
                    let several = inventory
                        .iter()
                        .filter(|(name, _)| name == identity)
                        .any(|(_, fields)| fields != expected);
                    assert!(
                        if several {
                            required.iter().all(|key| core.contains(key))
                        } else {
                            core == required
                        },
                        "core's key set drifted from the emitted keys of {identity}"
                    );
                } else {
                    for field in *expected {
                        if *identity != "client.structure.walk"
                            || !matches!(*field, "event" | "message")
                        {
                            assert!(
                                line.contains(&format!("{field}=")),
                                "emitted text field missing"
                            );
                        }
                    }
                }
            }
            let records: Vec<_> = history
                .snapshot()
                .records()
                .iter()
                .map(|record| String::from_utf8(record.as_bytes().to_vec()).unwrap())
                .collect();
            let bundled = events
                .iter()
                .filter(|event| crate::observe::boundary::bundle_admits(event.meta()))
                .count();
            assert!(
                bundled > 0 && bundled < events.len(),
                "the fixed bundle level policy must admit some events and not all"
            );
            assert_eq!(
                records.len(),
                bundled + refusals,
                "every admitted event/refusal must reach typed history"
            );
            // The records the client keeps are the member's input: the whole
            // history must pass the codec's grammar and key sets, not only
            // match its key names.
            let member = granary_core::support::BundleLogs {
                lost: history.snapshot().lost(),
                records: records.clone(),
            };
            assert!(!member.records.is_empty(), "history held no records");
            let bytes = member
                .encode()
                .unwrap_or_else(|e| panic!("history does not encode as the logs member: {e}"));
            assert_eq!(
                granary_core::support::BundleLogs::decode(&bytes),
                Ok(member),
                "the logs member must decode to the history it was built from"
            );
            assert_eq!(
                scan::scan(&lines, scan::SECRETS),
                Ok(()),
                "seeded telemetry secret absence"
            );
            assert_eq!(
                scan::scan(&records, scan::SECRETS),
                Ok(()),
                "seeded bundle secret absence"
            );
            assert_eq!(
                scan::scan(&records, scan::ORDINARY),
                Ok(()),
                "seeded bundle path absence"
            );
            if policy == LogPaths::Redacted {
                assert_eq!(
                    scan::scan(&projections, scan::ORDINARY),
                    Ok(()),
                    "seeded default full-path and basename absence"
                );
                assert_eq!(
                    scan::scan(&lines, scan::ORDINARY),
                    Ok(()),
                    "seeded default output path absence"
                );
                assert!(
                    lines.iter().any(|line| line.contains("<name>"))
                        && lines.iter().any(|line| line.contains("<cache-root>")),
                    "path/name classes required"
                );
            } else {
                let joined = lines.join("\n");
                assert!(
                    joined.contains(scan::ORDINARY[0]) && joined.contains(scan::ORDINARY[2]),
                    "full eligible slots must disclose supplied spellings"
                );
                for ((line, event), (_, expected)) in lines.iter().zip(&events).zip(&inventory) {
                    let meta = event.fields().0;
                    if !expected
                        .iter()
                        .any(|field| path_class(meta, field).is_some())
                    {
                        assert_eq!(
                            scan::scan(std::slice::from_ref(line), scan::ORDINARY),
                            Ok(()),
                            "full path appeared outside eligible schema"
                        );
                    }
                }
            }
            if let Some(prior) = &prior_bundle {
                assert!(prior == &records, "bundle policy independence changed");
            }
            prior_bundle = Some(records);
            assert!(
                baseline_metrics == metrics.snapshot().unwrap().render_prometheus().unwrap(),
                "metrics inherited path policy"
            );
            assert_eq!(
                scan::scan(std::slice::from_ref(&baseline_metrics), scan::SECRETS),
                Ok(()),
                "metrics secret absence"
            );
        }
    }
}
