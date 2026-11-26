// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Preallocated span storage; callbacks never format or write output.

use super::stopwatch;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

#[derive(Debug, Clone)]
pub(super) struct Sample {
    pub name: &'static str,
    pub phase: &'static str,
    pub slot: u64,
    pub start: Instant,
    pub end: Instant,
}
#[derive(Debug)]
struct Live {
    id: u64,
    refs: usize,
    sample: Sample,
}
#[derive(Debug, Clone)]
pub(super) struct Capture {
    buffer: Arc<Mutex<Vec<Sample>>>,
    live: Arc<Vec<Mutex<Option<Live>>>>,
    next: Arc<AtomicU64>,
    lost: Arc<AtomicUsize>,
    only: Option<&'static str>,
}
impl Capture {
    pub(super) fn new(capacity: usize) -> Self {
        Self::with_filter(capacity, None)
    }
    pub(super) fn authority_log_wait(capacity: usize) -> Self {
        Self::with_filter(capacity, Some("authority_log_wait"))
    }
    fn with_filter(capacity: usize, only: Option<&'static str>) -> Self {
        Self {
            buffer: Arc::new(Mutex::new(Vec::with_capacity(capacity))),
            live: Arc::new((0..1024).map(|_| Mutex::new(None)).collect()),
            next: Arc::new(AtomicU64::new(1)),
            lost: Arc::new(AtomicUsize::new(0)),
            only,
        }
    }
    pub(super) fn take(&self) -> (Vec<Sample>, usize) {
        let mut buffer = self
            .buffer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let samples = buffer.drain(..).collect();
        (samples, self.lost.swap(0, Ordering::Relaxed))
    }
    fn update(&self, id: &Id, change: impl FnOnce(&mut Live) -> bool) -> bool {
        let slot = usize::try_from(id.into_u64() % 1024).unwrap_or(0);
        let Some(slot) = self.live.get(slot) else {
            return false;
        };
        let mut slot = slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(live) = slot.as_mut().filter(|live| live.id == id.into_u64()) else {
            return false;
        };
        if !change(live) {
            return false;
        }
        let sample = live.sample.clone();
        *slot = None;
        drop(slot);
        // Measurement spans finish on the driver; live-span creation on the
        // client uses a separate slot lock. Export waits for both producers.
        let mut buffer = self
            .buffer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if buffer.len() < buffer.capacity() {
            buffer.push(sample);
        } else {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
        true
    }
}
#[derive(Default)]
struct Fields {
    phase: &'static str,
    slot: u64,
}
impl Visit for Fields {
    fn record_debug(&mut self, _: &Field, _: &dyn std::fmt::Debug) {}
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "slot" {
            self.slot = value;
        }
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "phase" {
            self.phase = match value {
                "resolve_head" => "resolve_head",
                "classify_seq" => "classify_seq",
                _ => "unknown",
            };
        }
    }
}
impl Subscriber for Capture {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }
    fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
        Some(tracing::metadata::LevelFilter::TRACE)
    }
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        if let Some(only) = self.only {
            return metadata.name() == only;
        }
        matches!(
            metadata.name(),
            "authority_queue"
                | "authority_validation"
                | "authority_chain"
                | "authority_log_wait"
                | "authority_worker_poll"
        )
    }
    fn new_span(&self, attrs: &Attributes<'_>) -> Id {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let mut fields = Fields::default();
        attrs.record(&mut fields);
        let slot = usize::try_from(id % 1024).unwrap_or(0);
        if let Some(slot) = self.live.get(slot) {
            let mut target = slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if target.is_none() {
                // Exclude field visitation and lock acquisition from duration.
                // Remaining tracing overhead still belongs to the observation.
                let at = stopwatch();
                *target = Some(Live {
                    id,
                    refs: 1,
                    sample: Sample {
                        name: attrs.metadata().name(),
                        phase: fields.phase,
                        slot: fields.slot,
                        start: at,
                        end: at,
                    },
                });
            } else {
                self.lost.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
        Id::from_u64(id)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, _: &Event<'_>) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
    fn clone_span(&self, id: &Id) -> Id {
        self.update(id, |live| {
            live.refs += 1;
            false
        });
        id.clone()
    }
    fn try_close(&self, id: Id) -> bool {
        let end = stopwatch();
        self.update(&id, |live| {
            live.refs -= 1;
            if live.refs == 0 {
                live.sample.end = end;
                true
            } else {
                false
            }
        })
    }
}

#[test]
fn authority_measurement_span_lifecycle_survives_snapshot_contention() {
    let capture = Capture::new(8);
    let dispatch = tracing::Dispatch::new(capture.clone());
    let (ready, reached) = std::sync::mpsc::channel();
    let (resume, resumed) = std::sync::mpsc::channel();
    let snapshot = capture.buffer.lock().unwrap();
    let producer = std::thread::spawn(move || {
        tracing::dispatcher::with_default(&dispatch, || {
            let span = tracing::trace_span!("authority_chain", phase = "resolve_head");
            drop(span.clone());
            ready.send(()).unwrap();
            resumed
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            drop(span);
        });
    });
    reached
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    drop(snapshot);
    resume.send(()).unwrap();
    producer.join().unwrap();
    let (samples, lost) = capture.take();
    assert_eq!(
        (samples.len(), lost),
        (1, 0),
        "snapshot contention must not discard span creation or references"
    );
    assert_eq!(
        samples.first().map(|s| (s.name, s.phase)),
        Some(("authority_chain", "resolve_head"))
    );
}
