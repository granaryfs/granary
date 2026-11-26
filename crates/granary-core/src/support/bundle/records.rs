// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The recent-logs member's record check: one JSON object line, scanned for
//! the restricted grammar the client's records already satisfy, and held to
//! the closed key set of the event it names.
use crate::support::{Result, SupportError, require};

/// Most top-level keys a record may carry before it is refused outright.
const KEYS_MAX: usize = 32;
/// The keys of one operation span inside a record's `spans` array.
const SPAN_KEYS: &[&str] = &["name", "op", "kind"];
/// Keys every tracing-encoded record carries or may carry besides its fields.
const TRACED_KEYS: &[&str] = &["level", "target", "event", "spans"];
/// Records the client writes outside the tracing encoder, with their exact keys.
const FIXED_EVENTS: &[(&str, &[&str])] = &[
    ("log.record_refused", &["level", "event", "reason"]),
    ("log.line", &["event", "message", "path", "class"]),
    (
        "log.sink_loss",
        &["event", "telemetry_dropped", "protected_lost", "local_lost"],
    ),
];
/// Every tracing-encoded event with its fields other than `event`. A record
/// carries those and `TRACED_KEYS`.
const TRACED_EVENTS: &[(&str, &[&str])] = &[
    ("op.conflict", &["path", "class"]),
    ("overlay.discard_refused", &["reason"]),
    ("overlay.reconcile_refused", &["reason"]),
    ("recover.signing_key_refused", &[]),
    (
        "overlay.recovery",
        &[
            "outcome",
            "files",
            "bytes",
            "record_index",
            "cap",
            "commit_requested",
            "owed",
            "stage_reserve",
            "projected_reserve",
            "ownership_reserve",
            "completion_reserve",
            "writer_reserve",
            "journal_reserve",
            "rolled_back_stages",
            "rolled_back_bytes",
        ],
    ),
    (
        "overlay.stage_rolled_back",
        &[
            "rollback_seq",
            "stage_id",
            "old_size",
            "restored_size",
            "discarded_bytes",
            "path",
        ],
    ),
    (
        "overlay.refused",
        &["class", "record_index", "files", "bytes"],
    ),
    ("overlay.sweep", &["files", "bytes"]),
    (
        "overlay.fault",
        &["point", "phase", "occurrence", "record_index"],
    ),
    (
        "sync.fault",
        &["point", "phase", "occurrence", "object_kind"],
    ),
    ("op.begin", &["kind"]),
    ("op.end", &["kind", "outcome"]),
    ("op.retry", &["kind", "attempt", "reason"]),
    ("op.failed", &["kind", "class"]),
    ("metrics.export_failed", &["class"]),
    ("overlay.failures_dropped", &["dropped"]),
    ("commit.contention", &["commits", "conflicts"]),
    ("commit.backoff", &["cause", "outcome", "attempts"]),
    ("sync.workspace_exhausted", &["reason", "needed", "limit"]),
    (
        "overlay.cap_exhausted",
        &["reason", "cap", "charged", "reserved", "captured", "needed"],
    ),
    ("commit.stopped", &["cause"]),
    ("recover.nothing", &[]),
    ("recover.subsumed", &["relation", "seq"]),
    ("recover.stale", &[]),
    ("recover.landed", &["seq"]),
    ("recover.archived_landed", &["seq"]),
    ("recover.rebased", &["chain_len"]),
    ("recover.conflict", &["path"]),
    ("recover.selection_changed", &["token"]),
    ("recover.landed_unowned", &[]),
    ("recover.fence_settled", &["how"]),
    ("recover.journal_finished", &["base_seq"]),
    ("recover.journal_blocked", &["reason"]),
    ("recover.unresolved", &["seq"]),
    ("recover.resent", &["seq"]),
    ("op.publish_bound", &["publish_operation"]),
    ("log.config", &["format", "destination"]),
    ("log.filter_rejected", &["source", "reason", "detail"]),
    ("mount.view", &["cause", "outcome", "seq"]),
    // Every field any of the event's levels carries: a record holds the
    // ones its own level does.
    (
        "mount.unmount",
        &[
            "trigger",
            "outcome",
            "seq",
            "cause",
            "files",
            "bytes",
            "operations",
            "elapsed_ms",
        ],
    ),
    (
        "client.cache.journal.is.broken.after.a.failed.reopen.mid",
        &["message"],
    ),
    (
        "client.cache.journal.flush.failed.records.stay.buffered",
        &["message", "error"],
    ),
    (
        "client.cache.compaction.failed.journal.left.uncompacted",
        &["message", "error"],
    ),
    (
        "client.cache.journal.buffer.exceeded.its.cap.under.sustained.free",
        &["message", "dropped_records", "dropped_bytes"],
    ),
    (
        "client.cache.journal.flush.refused.by.the.free.space.watermark",
        &["message"],
    ),
    (
        "client.cache.compaction.refused.by.the.free.space.watermark.snapshot",
        &["message"],
    ),
    (
        "client.cache.compaction.refused.by.the.free.space.watermark.before",
        &["message"],
    ),
    (
        "client.cache.eviction.found.nothing.left.to.evict.the.insert",
        &["message", "total_bytes", "quota"],
    ),
    (
        "client.cache.insert.the.object.path.has.no.fanout.parent",
        &["message", "id"],
    ),
    (
        "client.cache.insert.refused.the.object.fanout.is.not.a",
        &["message", "id", "error"],
    ),
    (
        "client.cache.insert.declined.a.directory.occupies.the.object.path",
        &["message", "id", "path"],
    ),
    (
        "client.cache.insert.a.foreign.entry.sits.at.the.object",
        &["message", "id", "path"],
    ),
    (
        "client.cache.insert.failed.to.inspect.the.object.path",
        &["message", "id", "error"],
    ),
    (
        "client.cache.insert.refused.object.is.larger.than.the.whole",
        &["message", "id", "len", "quota"],
    ),
    (
        "client.cache.insert.failed.to.stage.the.object.nothing.was",
        &["message", "id", "error"],
    ),
    (
        "client.cache.insert.refused.by.the.free.space.watermark",
        &["message", "id", "len"],
    ),
    (
        "client.cache.insert.failed.to.create.its.fanout.directory",
        &["message", "id", "error"],
    ),
    (
        "client.cache.insert.failed.to.write.the.object",
        &["message", "id", "error"],
    ),
    (
        "client.cache.insert.object.too.large.to.index.the.file",
        &["message", "id", "len"],
    ),
    (
        "client.cache.root.write.skipped.the.root.path.has.no",
        &["message", "volume", "seq"],
    ),
    (
        "client.cache.root.write.skipped.the.volume.directory.is.not",
        &["message", "volume", "seq", "error"],
    ),
    (
        "client.cache.root.write.skipped.a.directory.occupies.the.destination",
        &["message", "volume", "seq", "path"],
    ),
    (
        "client.cache.root.write.a.foreign.entry.sits.at.the",
        &["message", "volume", "seq", "path"],
    ),
    (
        "client.cache.root.write.skipped.the.destination.could.not.be",
        &["message", "volume", "seq", "error"],
    ),
    (
        "client.cache.root.write.refused.by.the.free.space.watermark",
        &["message", "volume", "seq", "len"],
    ),
    (
        "client.cache.root.write.failed.to.create.its.volume.directory",
        &["message", "volume", "error"],
    ),
    (
        "client.cache.root.write.failed",
        &["message", "volume", "seq", "error"],
    ),
    (
        "client.anchor.floor.candidate.is.an.absent.class.seq.refusing",
        &["message", "volume", "candidate"],
    ),
    (
        "client.hint.token.is.empty.an.etag.less.backend.retaining",
        &["message", "volume"],
    ),
    (
        "client.hint.is.unpersistable.token.bytes.length.stamp.sign.or",
        &["message", "volume"],
    ),
    (
        "client.cache.anchor.write.failed.to.create.its.directory",
        &["message", "volume", "error"],
    ),
    (
        "client.cache.anchor.write.failed",
        &["message", "volume", "error"],
    ),
    (
        "client.mount.anchor.floor.candidate.is.an.absent.class.seq",
        &["message", "volume", "candidate"],
    ),
    (
        "client.cache.root.eviction.skipped.the.root.path.has.no",
        &["message", "volume", "seq"],
    ),
    (
        "client.cache.root.eviction.skipped.the.volume.directory.is.not",
        &["message", "volume", "seq", "error"],
    ),
    (
        "client.cache.root.eviction.failed.to.remove.the.file",
        &["message", "volume", "seq", "error"],
    ),
    (
        "client.cache.guard.present.at.open.the.previous.writer.did",
        &["message", "root"],
    ),
    (
        "client.cache.lock.held.by.another.process.opening.read.only",
        &["message", "root"],
    ),
    (
        "client.cache.read.refused.the.object.fanout.is.not.a",
        &["message", "id", "error"],
    ),
    (
        "client.cache.object.failed.hash.verification.unlinking.and.evicting",
        &["message", "id"],
    ),
    (
        "client.cache.object.exceeds.the.size.bound.treating.it.as",
        &["message", "id", "len"],
    ),
    (
        "client.cached.root.exceeds.the.size.bound.treating.it.as",
        &["message", "volume", "seq", "len"],
    ),
    (
        "client.cache.maintain.journal.flush.failed.skipping.compaction.this.cycle",
        &["message", "error"],
    ),
    (
        "client.cache.maintain.compaction.failed",
        &["message", "error"],
    ),
    (
        "client.set.in.the.environment.and.ignored.the.direct.s3",
        &["message", "variable"],
    ),
    (
        "client.wire.snapshot.publish.the.temp.file.could.not.be",
        &["message", "from", "to", "error"],
    ),
    (
        "client.a.cache.dir.is.present.but.a.transport.down",
        &["message", "volume"],
    ),
    (
        "client.the.transport.gave.no.answer.falling.back.to.the",
        &["message", "volume", "seq", "age"],
    ),
    (
        "client.store.an.object.path.has.no.fanout.parent.reporting",
        &["message", "path"],
    ),
    (
        "client.store.an.object.fanout.is.not.a.real.directory",
        &["message", "fanout", "error"],
    ),
    (
        "client.store.an.object.leaf.is.not.a.regular.file",
        &["message", "path"],
    ),
    (
        "client.store.an.object.leaf.could.not.be.classified.reporting",
        &["message", "path", "error"],
    ),
    (
        "client.store.put.the.object.fanout.is.not.a.real",
        &["message", "fanout", "error"],
    ),
    (
        "client.store.put.an.object.leaf.is.not.a.regular",
        &["message", "path"],
    ),
    (
        "client.store.get.the.object.fanout.is.not.a.real",
        &["message", "fanout", "error"],
    ),
    (
        "client.store.established.open.txn.is.not.a.real.directory",
        &["message", "path"],
    ),
    (
        "client.store.established.open.an.orphaned.txn.entry.could.not",
        &["message", "path", "error"],
    ),
    (
        "client.store.established.open.swept.orphaned.txn.staging.files",
        &["message", "swept", "skipped"],
    ),
    (
        "client.seam.attempt.failed.retrying.once",
        &["message", "seam", "class", "error"],
    ),
    (
        "client.writable.shutdown.coordination.failed",
        &["message", "coordination", "cache_closed"],
    ),
    (
        "client.mount.session.shutdown.closing.the.cache.failed.the.crash",
        &["message", "root", "error"],
    ),
    (
        "client.mount.teardown.read.path.counters.for.the.read.phase",
        &[
            "message",
            "via",
            "inflight_high_water",
            "window",
            "origin_requests",
            "origin_sheds",
            "origin_requests_total",
            "wants_bin",
            "wants_meta",
            "wants_total",
            "cache_hits",
            "cache_misses",
        ],
    ),
    (
        "client.mount.session.drop.closing.the.cache.failed.the.crash",
        &["message", "root", "error"],
    ),
    (
        "client.cache.anchor.file.exceeds.the.size.bound.treating.it",
        &["message", "volume", "len"],
    ),
    (
        "client.cache.anchor.file.failed.strict.parse.treating.it.as",
        &["message", "volume"],
    ),
    (
        "client.mount.anchor.file.carries.a.hint.line.which.its",
        &["message", "volume"],
    ),
    (
        "client.refusing.to.unlink.an.object.path.that.has.no",
        &["message", "path", "context"],
    ),
    (
        "client.refusing.to.unlink.an.object.through.a.foreign.fanout",
        &["message", "fanout", "context"],
    ),
    (
        "client.refusing.to.unlink.an.object.under.a.fanout.that",
        &["message", "fanout", "error", "context"],
    ),
    (
        "client.an.object.leaf.could.not.be.unlinked.it.stays",
        &["message", "path", "error", "context"],
    ),
    (
        "client.cold.rebuild.walk.skipping.a.non.digest.file.name",
        &["message", "name"],
    ),
    (
        "client.cold.rebuild.walk.skipping.a.file.whose.name.does",
        &["message", "name", "dir"],
    ),
    (
        "client.cold.rebuild.walk.skipping.an.entry.whose.metadata.could",
        &["message", "path", "error"],
    ),
    (
        "client.cold.rebuild.walk.skipping.a.non.regular.file.entry",
        &["message", "path"],
    ),
    (
        "client.cold.rebuild.walk.skipping.an.oversized.foreign.file",
        &["message", "path", "len"],
    ),
    (
        "client.cold.rebuild.walk.skipping.a.size.that.cannot.fit",
        &["message", "path", "len"],
    ),
    (
        "client.cold.rebuild.walk.skipping.a.non.fanout.entry.under",
        &["message", "name"],
    ),
    (
        "client.cold.rebuild.walk.skipping.a.fanout.entry.whose.type",
        &["message", "path", "error"],
    ),
    (
        "client.cold.rebuild.walk.skipping.a.non.directory.entry.under",
        &["message", "path"],
    ),
    (
        "client.cold.rebuild.walk.the.adoption.cap.was.reached.the",
        &["message", "dropped", "adoption_cap"],
    ),
    (
        "client.cold.rebuild.walk.snapshot.rewrite.and.journal.reset.refused",
        &["message"],
    ),
    (
        "client.cache.index.file.exceeds.the.size.bound.treating.it",
        &["message", "path", "len", "what"],
    ),
    (
        "client.cache.index.file.grew.past.the.size.bound.between",
        &["message", "path", "len", "what"],
    ),
    (
        "client.cache.snapshot.present.with.no.journal.a.creation.crash",
        &["message", "root"],
    ),
    (
        "client.cache.writer.open.an.orphaned.txn.entry.could.not",
        &["message", "path", "error"],
    ),
    (
        "client.cache.writer.open.swept.orphaned.txn.staging.files",
        &["message", "swept", "skipped"],
    ),
    (
        "client.structure.walk",
        &[
            "message",
            "round",
            "outcome",
            "needs",
            "hints",
            "admits",
            "pool_len",
            "pool_used",
        ],
    ),
    (
        "client.gran.mount.unmount.failed.falling.back.to.a.lazy",
        &["message", "error"],
    ),
    (
        "client.gran.mount.the.mount.was.lazily.detached.mnt.detach",
        &["message"],
    ),
    (
        "client.gran.mount.both.the.plain.unmount.and.the.mnt",
        &["message", "unmount_error", "detach_error"],
    ),
    (
        "client.gran.mount.a.signal.readiness.report.never.arrived.before",
        &["message"],
    ),
    (
        "client.gran.mount.a.cached.root.and.the.wire.root",
        &["message", "volume", "finding"],
    ),
    (
        "client.gran.mount.could.not.build.a.runtime.for.sigint",
        &["message"],
    ),
    (
        "client.gran.mount.could.not.register.a.sigint.handler.this",
        &["message", "error"],
    ),
    (
        "client.gran.mount.the.sigint.stream.ended.without.delivering.a",
        &["message"],
    ),
    (
        "client.gran.mount.could.not.build.a.runtime.for.sigterm",
        &["message"],
    ),
    (
        "client.gran.mount.could.not.register.a.sigterm.handler.this",
        &["message"],
    ),
    (
        "client.gran.mount.detach.target.unavailable.lazy.detach.cannot.be",
        &["message", "error"],
    ),
    (
        "client.gran.mount.received.signal.unmounting",
        &["message", "signal"],
    ),
    (
        "client.gran.mount.the.fuse.session.ended.with.an.error",
        &["message", "error"],
    ),
    (
        "client.gran.mount.the.fuse.session.did.not.end.after.its.unmount",
        &["message", "listed", "connection"],
    ),
    (
        "client.gran.mount.the.fuse.session.thread.panicked",
        &["message"],
    ),
    (
        "client.gran.mount.could.not.capture.the.mount.identity",
        &["message", "error"],
    ),
    (
        "client.gran.mount.the.fuse.session.ended.econnaborted.racing.its.unmount",
        &["message"],
    ),
    (
        "client.sync.registration.timing.sample.unavailable",
        &["message"],
    ),
];

/// Every event name a record may carry.
pub fn bundle_record_events() -> impl Iterator<Item = &'static str> {
    TRACED_EVENTS
        .iter()
        .chain(FIXED_EVENTS)
        .map(|(name, _)| *name)
}

/// The complete closed set of top-level keys a record of this event may
/// carry, or `None` for a name no record uses.
#[must_use]
pub fn bundle_record_keys(event: &str) -> Option<impl Iterator<Item = &'static str> + Clone> {
    let (shared, own) =
        if let Some((_, keys)) = FIXED_EVENTS.iter().find(|(name, _)| *name == event) {
            (&[][..], *keys)
        } else {
            let (_, fields) = TRACED_EVENTS.iter().find(|(name, _)| *name == event)?;
            (TRACED_KEYS, *fields)
        };
    Some(shared.iter().chain(own).copied())
}

/// Whether every key is in `allowed` and none repeats.
fn distinct_keys_in(keys: &[&str], allowed: &(impl Iterator<Item = &'static str> + Clone)) -> bool {
    keys.iter().enumerate().all(|(i, key)| {
        allowed.clone().any(|name| name == *key) && !keys.iter().skip(i + 1).any(|k| k == key)
    })
}

fn syntax() -> SupportError {
    SupportError("log record syntax")
}

fn take(rest: &mut &str, prefix: &str) -> bool {
    rest.strip_prefix(prefix).is_some_and(|tail| {
        *rest = tail;
        true
    })
}

/// A quoted string, returned as written between its quotes. Only the escapes
/// the client's encoder produces are admitted: `\"`, `\\` and `\u` with four
/// lowercase hex digits naming a control character.
fn string<'a>(rest: &mut &'a str) -> Result<&'a str> {
    let body = rest.strip_prefix('"').ok_or_else(syntax)?;
    let mut chars = body.char_indices();
    while let Some((at, ch)) = chars.next() {
        match ch {
            '"' => {
                let (text, tail) = body.split_at_checked(at).ok_or_else(syntax)?;
                *rest = tail.strip_prefix('"').ok_or_else(syntax)?;
                return Ok(text);
            }
            '\\' => match chars.next() {
                Some((_, '"' | '\\')) => {}
                Some((_, 'u')) => {
                    let mut code = 0_u32;
                    for _ in 0..4 {
                        let digit = match chars.next() {
                            Some((_, hex @ ('0'..='9' | 'a'..='f'))) => hex.to_digit(16),
                            _ => None,
                        };
                        code = code * 16 + digit.ok_or_else(syntax)?;
                    }
                    require(
                        char::from_u32(code).is_some_and(char::is_control),
                        "log record syntax",
                    )?;
                }
                _ => return Err(syntax()),
            },
            _ => {}
        }
    }
    Err(syntax())
}

/// A string, a canonical unsigned decimal (a value that fits a u64) or a boolean.
fn scalar<'a>(rest: &mut &'a str) -> Result<&'a str> {
    match rest.chars().next() {
        Some('"') => string(rest),
        Some('0'..='9') => {
            let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
            let (number, tail) = rest.split_at_checked(digits).ok_or_else(syntax)?;
            require(
                number.parse::<u64>().is_ok() && (digits == 1 || !number.starts_with('0')),
                "log record syntax",
            )?;
            *rest = tail;
            Ok(number)
        }
        _ => {
            require(
                take(rest, "true") || take(rest, "false"),
                "log record syntax",
            )?;
            Ok("")
        }
    }
}

/// One flat object. The record's own object may carry the `spans` array, whose
/// elements are flat objects of their own.
fn object<'a>(
    rest: &mut &'a str,
    outer: bool,
    keys: &mut Vec<&'a str>,
    event: &mut Option<&'a str>,
) -> Result<()> {
    require(take(rest, "{"), "log record syntax")?;
    loop {
        let key = string(rest)?;
        require(take(rest, ":"), "log record syntax")?;
        require(keys.len() < KEYS_MAX, "log record key")?;
        keys.push(key);
        if outer && key == "spans" {
            spans(rest)?;
        } else {
            let value = scalar(rest)?;
            if outer && key == "event" {
                require(event.replace(value).is_none(), "log record event")?;
            }
        }
        if !take(rest, ",") {
            return require(take(rest, "}"), "log record syntax");
        }
    }
}

fn spans(rest: &mut &str) -> Result<()> {
    require(take(rest, "["), "log record syntax")?;
    loop {
        let mut keys = Vec::new();
        object(rest, false, &mut keys, &mut None)?;
        require(
            distinct_keys_in(&keys, &SPAN_KEYS.iter().copied()),
            "log record key",
        )?;
        if !take(rest, ",") {
            return require(take(rest, "]"), "log record syntax");
        }
    }
}

/// Check one complete record, newline included: framing, control characters,
/// the grammar, a known event and that event's key set.
pub(super) fn check(record: &str) -> Result<()> {
    let mut rest = record
        .strip_suffix('\n')
        .filter(|body| body.starts_with('{') && body.ends_with('}'))
        .ok_or(SupportError("log record framing"))?;
    require(!rest.chars().any(char::is_control), "log record control")?;
    let (mut keys, mut event) = (Vec::new(), None);
    object(&mut rest, true, &mut keys, &mut event)?;
    require(rest.is_empty(), "log record syntax")?;
    let allowed = event
        .and_then(bundle_record_keys)
        .ok_or(SupportError("log record event"))?;
    require(distinct_keys_in(&keys, &allowed), "log record key")
}
