// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::observe::RecoverEvent;
use crate::{BackoffCause, BackoffOutcome, CommitStopCause, MetricsFailureClass};

#[expect(
    clippy::too_many_lines,
    reason = "exhaustive typed constructor fixtures"
)]
pub(super) fn diagnostics() -> Vec<OperatorDiagnostic> {
    vec![
        OperatorDiagnostic::cache_journal_is_broken_after_a_failed_reopen_mid(),
        OperatorDiagnostic::cache_journal_flush_failed_records_stay_buffered(FailureClass::Io),
        OperatorDiagnostic::cache_compaction_failed_journal_left_uncompacted(FailureClass::Io),
        OperatorDiagnostic::cache_journal_buffer_exceeded_its_cap_under_sustained_free(7, 7),
        OperatorDiagnostic::cache_journal_flush_refused_by_the_free_space_watermark(),
        OperatorDiagnostic::cache_compaction_refused_by_the_free_space_watermark_snapshot(),
        OperatorDiagnostic::cache_compaction_refused_by_the_free_space_watermark_before(),
        OperatorDiagnostic::cache_eviction_found_nothing_left_to_evict_the_insert(7, 7),
        OperatorDiagnostic::cache_insert_the_object_path_has_no_fanout_parent(),
        OperatorDiagnostic::cache_insert_refused_the_object_fanout_is_not_a(FailureClass::Io),
        OperatorDiagnostic::cache_insert_declined_a_directory_occupies_the_object_path(),
        OperatorDiagnostic::cache_insert_a_foreign_entry_sits_at_the_object(),
        OperatorDiagnostic::cache_insert_failed_to_inspect_the_object_path(FailureClass::Io),
        OperatorDiagnostic::cache_insert_refused_object_is_larger_than_the_whole(7, 7),
        OperatorDiagnostic::cache_insert_failed_to_stage_the_object_nothing_was(FailureClass::Io),
        OperatorDiagnostic::cache_insert_refused_by_the_free_space_watermark(7),
        OperatorDiagnostic::cache_insert_failed_to_create_its_fanout_directory(FailureClass::Io),
        OperatorDiagnostic::cache_insert_failed_to_write_the_object(FailureClass::Io),
        OperatorDiagnostic::cache_insert_object_too_large_to_index_the_file(7),
        OperatorDiagnostic::cache_root_write_skipped_the_root_path_has_no(7),
        OperatorDiagnostic::cache_root_write_skipped_the_volume_directory_is_not(
            7,
            FailureClass::Io,
        ),
        OperatorDiagnostic::cache_root_write_skipped_a_directory_occupies_the_destination(7),
        OperatorDiagnostic::cache_root_write_a_foreign_entry_sits_at_the(7),
        OperatorDiagnostic::cache_root_write_skipped_the_destination_could_not_be(
            7,
            FailureClass::Io,
        ),
        OperatorDiagnostic::cache_root_write_refused_by_the_free_space_watermark(7, 7),
        OperatorDiagnostic::cache_root_write_failed_to_create_its_volume_directory(
            FailureClass::Io,
        ),
        OperatorDiagnostic::cache_root_write_failed(7, FailureClass::Io),
        OperatorDiagnostic::anchor_floor_candidate_is_an_absent_class_seq_refusing(7),
        OperatorDiagnostic::hint_token_is_empty_an_etag_less_backend_retaining(),
        OperatorDiagnostic::hint_is_unpersistable_token_bytes_length_stamp_sign_or(),
        OperatorDiagnostic::cache_anchor_write_failed_to_create_its_directory(FailureClass::Io),
        OperatorDiagnostic::cache_anchor_write_failed(FailureClass::Io),
        OperatorDiagnostic::mount_anchor_floor_candidate_is_an_absent_class_seq(7),
        OperatorDiagnostic::cache_root_eviction_skipped_the_root_path_has_no(7),
        OperatorDiagnostic::cache_root_eviction_skipped_the_volume_directory_is_not(
            7,
            FailureClass::Io,
        ),
        OperatorDiagnostic::cache_root_eviction_failed_to_remove_the_file(7, FailureClass::Io),
        OperatorDiagnostic::cache_guard_present_at_open_the_previous_writer_did(),
        OperatorDiagnostic::cache_lock_held_by_another_process_opening_read_only(),
        OperatorDiagnostic::cache_read_refused_the_object_fanout_is_not_a(FailureClass::Io),
        OperatorDiagnostic::cache_object_failed_hash_verification_unlinking_and_evicting(),
        OperatorDiagnostic::cache_object_exceeds_the_size_bound_treating_it_as(7),
        OperatorDiagnostic::cached_root_exceeds_the_size_bound_treating_it_as(7, 7),
        OperatorDiagnostic::cache_maintain_journal_flush_failed_skipping_compaction_this_cycle(
            FailureClass::Io,
        ),
        OperatorDiagnostic::cache_maintain_compaction_failed(FailureClass::Io),
        OperatorDiagnostic::set_in_the_environment_and_ignored_the_direct_s3(
            ProxyVariableName::HttpsUpper,
        ),
        OperatorDiagnostic::wire_snapshot_publish_the_temp_file_could_not_be(FailureClass::Io),
        OperatorDiagnostic::a_cache_dir_is_present_but_a_transport_down(),
        OperatorDiagnostic::the_transport_gave_no_answer_falling_back_to_the(7, Age::Seconds(12)),
        OperatorDiagnostic::store_an_object_path_has_no_fanout_parent_reporting(),
        OperatorDiagnostic::store_an_object_fanout_is_not_a_real_directory(FailureClass::Io),
        OperatorDiagnostic::store_an_object_leaf_is_not_a_regular_file(),
        OperatorDiagnostic::store_an_object_leaf_could_not_be_classified_reporting(
            FailureClass::Io,
        ),
        OperatorDiagnostic::store_put_the_object_fanout_is_not_a_real(FailureClass::Io),
        OperatorDiagnostic::store_put_an_object_leaf_is_not_a_regular(),
        OperatorDiagnostic::store_get_the_object_fanout_is_not_a_real(FailureClass::Io),
        OperatorDiagnostic::store_established_open_txn_is_not_a_real_directory(),
        OperatorDiagnostic::store_established_open_an_orphaned_txn_entry_could_not(
            FailureClass::Io,
        ),
        OperatorDiagnostic::store_established_open_swept_orphaned_txn_staging_files(7, 7),
        OperatorDiagnostic::seam_attempt_failed_retrying_once(
            HttpSeam::PutMeta,
            WireRetryClass::Unsent,
            FailureClass::Io,
        ),
        OperatorDiagnostic::seam_attempt_failed_retrying_once(
            HttpSeam::GetMeta,
            WireRetryClass::ConnectionFailed,
            FailureClass::Unavailable,
        ),
        OperatorDiagnostic::writable_shutdown_coordination_failed(FailureClass::Io, true),
        OperatorDiagnostic::mount_session_shutdown_closing_the_cache_failed_the_crash(
            FailureClass::Io,
        ),
        OperatorDiagnostic::mount_teardown_read_path_counters_for_the_read_phase(
            TeardownCause::Shutdown,
            7,
            7,
            7,
            7,
            7,
            7,
            7,
            7,
            7,
            7,
        ),
        OperatorDiagnostic::mount_session_drop_closing_the_cache_failed_the_crash(FailureClass::Io),
        OperatorDiagnostic::cache_anchor_file_exceeds_the_size_bound_treating_it(7),
        OperatorDiagnostic::cache_anchor_file_failed_strict_parse_treating_it_as(),
        OperatorDiagnostic::mount_anchor_file_carries_a_hint_line_which_its(),
        OperatorDiagnostic::refusing_to_unlink_an_object_path_that_has_no(CacheAction::Evict),
        OperatorDiagnostic::refusing_to_unlink_an_object_through_a_foreign_fanout(
            CacheAction::Evict,
        ),
        OperatorDiagnostic::refusing_to_unlink_an_object_under_a_fanout_that(
            FailureClass::Io,
            CacheAction::Evict,
        ),
        OperatorDiagnostic::an_object_leaf_could_not_be_unlinked_it_stays(
            FailureClass::Io,
            CacheAction::Evict,
        ),
        OperatorDiagnostic::cold_rebuild_walk_skipping_a_non_digest_file_name(),
        OperatorDiagnostic::cold_rebuild_walk_skipping_a_file_whose_name_does(),
        OperatorDiagnostic::cold_rebuild_walk_skipping_an_entry_whose_metadata_could(
            FailureClass::Io,
        ),
        OperatorDiagnostic::cold_rebuild_walk_skipping_a_non_regular_file_entry(),
        OperatorDiagnostic::cold_rebuild_walk_skipping_an_oversized_foreign_file(7),
        OperatorDiagnostic::cold_rebuild_walk_skipping_a_size_that_cannot_fit(7),
        OperatorDiagnostic::cold_rebuild_walk_skipping_a_non_fanout_entry_under(),
        OperatorDiagnostic::cold_rebuild_walk_skipping_a_fanout_entry_whose_type(FailureClass::Io),
        OperatorDiagnostic::cold_rebuild_walk_skipping_a_non_directory_entry_under(),
        OperatorDiagnostic::cold_rebuild_walk_the_adoption_cap_was_reached_the(7, 7),
        OperatorDiagnostic::cold_rebuild_walk_snapshot_rewrite_and_journal_reset_refused(),
        OperatorDiagnostic::cache_index_file_exceeds_the_size_bound_treating_it(
            7,
            IndexFileKind::Journal,
        ),
        OperatorDiagnostic::cache_index_file_grew_past_the_size_bound_between(
            7,
            IndexFileKind::Journal,
        ),
        OperatorDiagnostic::cache_snapshot_present_with_no_journal_a_creation_crash(),
        OperatorDiagnostic::cache_writer_open_an_orphaned_txn_entry_could_not(FailureClass::Io),
        OperatorDiagnostic::cache_writer_open_swept_orphaned_txn_staging_files(7, 7),
        OperatorDiagnostic::structure_walk(7, WalkOutcome::Need, 7, 7, 7, 7, 7),
        OperatorDiagnostic::gran_mount_unmount_failed_falling_back_to_a_lazy(FailureClass::Io),
        OperatorDiagnostic::gran_mount_the_mount_was_lazily_detached_mnt_detach(),
        OperatorDiagnostic::gran_mount_both_the_plain_unmount_and_the_mnt(
            FailureClass::Io,
            FailureClass::Io,
        ),
        OperatorDiagnostic::gran_mount_a_signal_readiness_report_never_arrived_before(),
        OperatorDiagnostic::gran_mount_a_cached_root_and_the_wire_root(),
        OperatorDiagnostic::gran_mount_could_not_build_a_runtime_for_sigint(),
        OperatorDiagnostic::gran_mount_could_not_register_a_sigint_handler_this(FailureClass::Io),
        OperatorDiagnostic::gran_mount_the_sigint_stream_ended_without_delivering_a(),
        OperatorDiagnostic::gran_mount_could_not_build_a_runtime_for_sigterm(),
        OperatorDiagnostic::gran_mount_could_not_register_a_sigterm_handler_this(),
        OperatorDiagnostic::gran_mount_detach_target_unavailable_lazy_detach_cannot_be(
            FailureClass::Refused,
        ),
        OperatorDiagnostic::gran_mount_received_signal_unmounting(SignalKind::Terminate),
        OperatorDiagnostic::gran_mount_the_fuse_session_ended_with_an_error(FailureClass::Io),
        OperatorDiagnostic::gran_mount_the_fuse_session_did_not_end_after_its_unmount(
            crate::MountListing::Gone,
            crate::FuseConnection::Alive,
        ),
        OperatorDiagnostic::gran_mount_the_fuse_session_thread_panicked(),
        OperatorDiagnostic::gran_mount_could_not_capture_the_mount_identity(FailureClass::Corrupt),
        OperatorDiagnostic::gran_mount_the_fuse_session_ended_econnaborted_racing_its_unmount(),
        OperatorDiagnostic::sync_registration_timing_sample_unavailable(),
    ]
}

pub(super) const INVENTORY: &[(&str, &[&str])] = &[
    (
        "client.cache.journal.is.broken.after.a.failed.reopen.mid",
        &["event", "message"],
    ),
    (
        "client.cache.journal.flush.failed.records.stay.buffered",
        &["event", "message", "error"],
    ),
    (
        "client.cache.compaction.failed.journal.left.uncompacted",
        &["event", "message", "error"],
    ),
    (
        "client.cache.journal.buffer.exceeded.its.cap.under.sustained.free",
        &["event", "message", "dropped_records", "dropped_bytes"],
    ),
    (
        "client.cache.journal.flush.refused.by.the.free.space.watermark",
        &["event", "message"],
    ),
    (
        "client.cache.compaction.refused.by.the.free.space.watermark.snapshot",
        &["event", "message"],
    ),
    (
        "client.cache.compaction.refused.by.the.free.space.watermark.before",
        &["event", "message"],
    ),
    (
        "client.cache.eviction.found.nothing.left.to.evict.the.insert",
        &["event", "message", "total_bytes", "quota"],
    ),
    (
        "client.cache.insert.the.object.path.has.no.fanout.parent",
        &["event", "message", "id"],
    ),
    (
        "client.cache.insert.refused.the.object.fanout.is.not.a",
        &["event", "message", "id", "error"],
    ),
    (
        "client.cache.insert.declined.a.directory.occupies.the.object.path",
        &["event", "message", "id", "path"],
    ),
    (
        "client.cache.insert.a.foreign.entry.sits.at.the.object",
        &["event", "message", "id", "path"],
    ),
    (
        "client.cache.insert.failed.to.inspect.the.object.path",
        &["event", "message", "id", "error"],
    ),
    (
        "client.cache.insert.refused.object.is.larger.than.the.whole",
        &["event", "message", "id", "len", "quota"],
    ),
    (
        "client.cache.insert.failed.to.stage.the.object.nothing.was",
        &["event", "message", "id", "error"],
    ),
    (
        "client.cache.insert.refused.by.the.free.space.watermark",
        &["event", "message", "id", "len"],
    ),
    (
        "client.cache.insert.failed.to.create.its.fanout.directory",
        &["event", "message", "id", "error"],
    ),
    (
        "client.cache.insert.failed.to.write.the.object",
        &["event", "message", "id", "error"],
    ),
    (
        "client.cache.insert.object.too.large.to.index.the.file",
        &["event", "message", "id", "len"],
    ),
    (
        "client.cache.root.write.skipped.the.root.path.has.no",
        &["event", "message", "volume", "seq"],
    ),
    (
        "client.cache.root.write.skipped.the.volume.directory.is.not",
        &["event", "message", "volume", "seq", "error"],
    ),
    (
        "client.cache.root.write.skipped.a.directory.occupies.the.destination",
        &["event", "message", "volume", "seq", "path"],
    ),
    (
        "client.cache.root.write.a.foreign.entry.sits.at.the",
        &["event", "message", "volume", "seq", "path"],
    ),
    (
        "client.cache.root.write.skipped.the.destination.could.not.be",
        &["event", "message", "volume", "seq", "error"],
    ),
    (
        "client.cache.root.write.refused.by.the.free.space.watermark",
        &["event", "message", "volume", "seq", "len"],
    ),
    (
        "client.cache.root.write.failed.to.create.its.volume.directory",
        &["event", "message", "volume", "error"],
    ),
    (
        "client.cache.root.write.failed",
        &["event", "message", "volume", "seq", "error"],
    ),
    (
        "client.anchor.floor.candidate.is.an.absent.class.seq.refusing",
        &["event", "message", "volume", "candidate"],
    ),
    (
        "client.hint.token.is.empty.an.etag.less.backend.retaining",
        &["event", "message", "volume"],
    ),
    (
        "client.hint.is.unpersistable.token.bytes.length.stamp.sign.or",
        &["event", "message", "volume"],
    ),
    (
        "client.cache.anchor.write.failed.to.create.its.directory",
        &["event", "message", "volume", "error"],
    ),
    (
        "client.cache.anchor.write.failed",
        &["event", "message", "volume", "error"],
    ),
    (
        "client.mount.anchor.floor.candidate.is.an.absent.class.seq",
        &["event", "message", "volume", "candidate"],
    ),
    (
        "client.cache.root.eviction.skipped.the.root.path.has.no",
        &["event", "message", "volume", "seq"],
    ),
    (
        "client.cache.root.eviction.skipped.the.volume.directory.is.not",
        &["event", "message", "volume", "seq", "error"],
    ),
    (
        "client.cache.root.eviction.failed.to.remove.the.file",
        &["event", "message", "volume", "seq", "error"],
    ),
    (
        "client.cache.guard.present.at.open.the.previous.writer.did",
        &["event", "message", "root"],
    ),
    (
        "client.cache.lock.held.by.another.process.opening.read.only",
        &["event", "message", "root"],
    ),
    (
        "client.cache.read.refused.the.object.fanout.is.not.a",
        &["event", "message", "id", "error"],
    ),
    (
        "client.cache.object.failed.hash.verification.unlinking.and.evicting",
        &["event", "message", "id"],
    ),
    (
        "client.cache.object.exceeds.the.size.bound.treating.it.as",
        &["event", "message", "id", "len"],
    ),
    (
        "client.cached.root.exceeds.the.size.bound.treating.it.as",
        &["event", "message", "volume", "seq", "len"],
    ),
    (
        "client.cache.maintain.journal.flush.failed.skipping.compaction.this.cycle",
        &["event", "message", "error"],
    ),
    (
        "client.cache.maintain.compaction.failed",
        &["event", "message", "error"],
    ),
    (
        "client.set.in.the.environment.and.ignored.the.direct.s3",
        &["event", "message", "variable"],
    ),
    (
        "client.wire.snapshot.publish.the.temp.file.could.not.be",
        &["event", "message", "from", "to", "error"],
    ),
    (
        "client.a.cache.dir.is.present.but.a.transport.down",
        &["event", "message", "volume"],
    ),
    (
        "client.the.transport.gave.no.answer.falling.back.to.the",
        &["event", "message", "volume", "seq", "age"],
    ),
    (
        "client.store.an.object.path.has.no.fanout.parent.reporting",
        &["event", "message", "path"],
    ),
    (
        "client.store.an.object.fanout.is.not.a.real.directory",
        &["event", "message", "fanout", "error"],
    ),
    (
        "client.store.an.object.leaf.is.not.a.regular.file",
        &["event", "message", "path"],
    ),
    (
        "client.store.an.object.leaf.could.not.be.classified.reporting",
        &["event", "message", "path", "error"],
    ),
    (
        "client.store.put.the.object.fanout.is.not.a.real",
        &["event", "message", "fanout", "error"],
    ),
    (
        "client.store.put.an.object.leaf.is.not.a.regular",
        &["event", "message", "path"],
    ),
    (
        "client.store.get.the.object.fanout.is.not.a.real",
        &["event", "message", "fanout", "error"],
    ),
    (
        "client.store.established.open.txn.is.not.a.real.directory",
        &["event", "message", "path"],
    ),
    (
        "client.store.established.open.an.orphaned.txn.entry.could.not",
        &["event", "message", "path", "error"],
    ),
    (
        "client.store.established.open.swept.orphaned.txn.staging.files",
        &["event", "message", "swept", "skipped"],
    ),
    (
        "client.seam.attempt.failed.retrying.once",
        &["event", "message", "seam", "class", "error"],
    ),
    (
        "client.seam.attempt.failed.retrying.once",
        &["event", "message", "seam", "class", "error"],
    ),
    (
        "client.writable.shutdown.coordination.failed",
        &["event", "message", "coordination", "cache_closed"],
    ),
    (
        "client.mount.session.shutdown.closing.the.cache.failed.the.crash",
        &["event", "message", "root", "error"],
    ),
    (
        "client.mount.teardown.read.path.counters.for.the.read.phase",
        &[
            "event",
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
        &["event", "message", "root", "error"],
    ),
    (
        "client.cache.anchor.file.exceeds.the.size.bound.treating.it",
        &["event", "message", "volume", "len"],
    ),
    (
        "client.cache.anchor.file.failed.strict.parse.treating.it.as",
        &["event", "message", "volume"],
    ),
    (
        "client.mount.anchor.file.carries.a.hint.line.which.its",
        &["event", "message", "volume"],
    ),
    (
        "client.refusing.to.unlink.an.object.path.that.has.no",
        &["event", "message", "path", "context"],
    ),
    (
        "client.refusing.to.unlink.an.object.through.a.foreign.fanout",
        &["event", "message", "fanout", "context"],
    ),
    (
        "client.refusing.to.unlink.an.object.under.a.fanout.that",
        &["event", "message", "fanout", "error", "context"],
    ),
    (
        "client.an.object.leaf.could.not.be.unlinked.it.stays",
        &["event", "message", "path", "error", "context"],
    ),
    (
        "client.cold.rebuild.walk.skipping.a.non.digest.file.name",
        &["event", "message", "name"],
    ),
    (
        "client.cold.rebuild.walk.skipping.a.file.whose.name.does",
        &["event", "message", "name", "dir"],
    ),
    (
        "client.cold.rebuild.walk.skipping.an.entry.whose.metadata.could",
        &["event", "message", "path", "error"],
    ),
    (
        "client.cold.rebuild.walk.skipping.a.non.regular.file.entry",
        &["event", "message", "path"],
    ),
    (
        "client.cold.rebuild.walk.skipping.an.oversized.foreign.file",
        &["event", "message", "path", "len"],
    ),
    (
        "client.cold.rebuild.walk.skipping.a.size.that.cannot.fit",
        &["event", "message", "path", "len"],
    ),
    (
        "client.cold.rebuild.walk.skipping.a.non.fanout.entry.under",
        &["event", "message", "name"],
    ),
    (
        "client.cold.rebuild.walk.skipping.a.fanout.entry.whose.type",
        &["event", "message", "path", "error"],
    ),
    (
        "client.cold.rebuild.walk.skipping.a.non.directory.entry.under",
        &["event", "message", "path"],
    ),
    (
        "client.cold.rebuild.walk.the.adoption.cap.was.reached.the",
        &["event", "message", "dropped", "adoption_cap"],
    ),
    (
        "client.cold.rebuild.walk.snapshot.rewrite.and.journal.reset.refused",
        &["event", "message"],
    ),
    (
        "client.cache.index.file.exceeds.the.size.bound.treating.it",
        &["event", "message", "path", "len", "what"],
    ),
    (
        "client.cache.index.file.grew.past.the.size.bound.between",
        &["event", "message", "path", "len", "what"],
    ),
    (
        "client.cache.snapshot.present.with.no.journal.a.creation.crash",
        &["event", "message", "root"],
    ),
    (
        "client.cache.writer.open.an.orphaned.txn.entry.could.not",
        &["event", "message", "path", "error"],
    ),
    (
        "client.cache.writer.open.swept.orphaned.txn.staging.files",
        &["event", "message", "swept", "skipped"],
    ),
    (
        "client.structure.walk",
        &[
            "event",
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
        &["event", "message", "error"],
    ),
    (
        "client.gran.mount.the.mount.was.lazily.detached.mnt.detach",
        &["event", "message"],
    ),
    (
        "client.gran.mount.both.the.plain.unmount.and.the.mnt",
        &["event", "message", "unmount_error", "detach_error"],
    ),
    (
        "client.gran.mount.a.signal.readiness.report.never.arrived.before",
        &["event", "message"],
    ),
    (
        "client.gran.mount.a.cached.root.and.the.wire.root",
        &["event", "message", "volume", "finding"],
    ),
    (
        "client.gran.mount.could.not.build.a.runtime.for.sigint",
        &["event", "message"],
    ),
    (
        "client.gran.mount.could.not.register.a.sigint.handler.this",
        &["event", "message", "error"],
    ),
    (
        "client.gran.mount.the.sigint.stream.ended.without.delivering.a",
        &["event", "message"],
    ),
    (
        "client.gran.mount.could.not.build.a.runtime.for.sigterm",
        &["event", "message"],
    ),
    (
        "client.gran.mount.could.not.register.a.sigterm.handler.this",
        &["event", "message"],
    ),
    (
        "client.gran.mount.detach.target.unavailable.lazy.detach.cannot.be",
        &["event", "message", "error"],
    ),
    (
        "client.gran.mount.received.signal.unmounting",
        &["event", "message", "signal"],
    ),
    (
        "client.gran.mount.the.fuse.session.ended.with.an.error",
        &["event", "message", "error"],
    ),
    (
        "client.gran.mount.the.fuse.session.did.not.end.after.its.unmount",
        &["event", "message", "listed", "connection"],
    ),
    (
        "client.gran.mount.the.fuse.session.thread.panicked",
        &["event", "message"],
    ),
    (
        "client.gran.mount.could.not.capture.the.mount.identity",
        &["event", "message", "error"],
    ),
    (
        "client.gran.mount.the.fuse.session.ended.econnaborted.racing.its.unmount",
        &["event", "message"],
    ),
    (
        "client.sync.registration.timing.sample.unavailable",
        &["event", "message"],
    ),
];

pub(super) fn events() -> Vec<ClientEvent> {
    vec![
        ClientEvent::commit_contention(4, 1),
        ClientEvent::commit_backoff(BackoffCause::Outage, BackoffOutcome::Entered),
        ClientEvent::commit_backoff(
            BackoffCause::Stall,
            BackoffOutcome::Recovered { attempts: 3 },
        ),
        ClientEvent::workspace_exhausted(1_073_741_825, 1_073_741_824),
        ClientEvent::overlay_cap_exhausted(134_217_728, 96_624_009, 33_814_682, 34_180, 98_685_463),
        ClientEvent::commit_stopped(CommitStopCause::Fenced),
        ClientEvent::recover(RecoverEvent::JournalFinished(7)),
        ClientEvent::recover(RecoverEvent::JournalBlocked("release")),
        ClientEvent::recover(RecoverEvent::Nothing),
        ClientEvent::recovery_signing_key_refused(),
        ClientEvent::recover(RecoverEvent::Subsumed(crate::SubsumedRelation::Equal, 9)),
        ClientEvent::recover(RecoverEvent::Stale),
        ClientEvent::recover(RecoverEvent::Landed(9)),
        ClientEvent::recover(RecoverEvent::ArchivedLanded(9)),
        ClientEvent::recover(RecoverEvent::Rebased(2)),
        ClientEvent::recover(RecoverEvent::Conflict),
        ClientEvent::recover(RecoverEvent::SelectionChanged("none")),
        ClientEvent::recover(RecoverEvent::LandedUnowned),
        ClientEvent::recover(RecoverEvent::FenceSettled("released")),
        ClientEvent::recover(RecoverEvent::Unresolved(2)),
        ClientEvent::recover(RecoverEvent::Resent(2)),
        ClientEvent::conflict_detail(),
        ClientEvent::overlay_recovery(
            RecoveryClass::Repaired,
            7,
            800,
            9,
            4096,
            true,
            crate::OverlayOwed {
                owed: 512,
                stages: 2048,
                projected: 256,
                ownership: 1024,
                completion: 1732,
                writer: 64,
                journal: 117,
            },
            [2, 12],
        ),
        ClientEvent::stage_rolled_back(9, 2, 10, 8, 6, true),
        ClientEvent::stage_rolled_back(10, 3, 6, 0, 6, false),
        ClientEvent::overlay_refused(FailureClass::Corrupt, 9, 7, 800),
        ClientEvent::overlay_discard_refused(crate::OverlayRefusal::ForeignCustody),
        ClientEvent::overlay_reconcile_refused(crate::OverlayRefusal::Unresolved),
        ClientEvent::overlay_sweep(7, 800),
        ClientEvent::overlay_failures_dropped(3),
        #[cfg(feature = "overlay-fault-tests")]
        ClientEvent::overlay_fault(OverlayFaultPoint::StageWrite, FaultPhase::Before, 2, 9),
        #[cfg(feature = "overlay-fault-tests")]
        ClientEvent::sync_fault(
            SyncFaultPoint::Capture,
            SyncFaultPhase::After,
            2,
            SyncObjectKind::None,
        ),
        ClientEvent::op_begin(OperationKind::Commit),
        ClientEvent::op_end(OperationKind::Commit, Outcome::Ok),
        ClientEvent::op_retry(OperationKind::Rebase, 3, RetryReason::Conflict),
        ClientEvent::op_failed(OperationKind::Fsync, FailureClass::Io),
        ClientEvent::metrics_export_failed(MetricsFailureClass::Internal),
        ClientEvent::publish_bound(PublishOperationId::draw(&mut SeedRandom, 8).unwrap()),
        ClientEvent::log_config(LogFormat::Json, LogDestination::File),
        ClientEvent::log_filter_rejected(
            FilterSource::RustLog,
            FilterRejection::Malformed,
            FilterDetail::Malformed,
        ),
        ClientEvent::mount_view(crate::ViewCause::Landed, crate::ViewOutcome::Installed, 9),
        ClientEvent::mount_view(crate::ViewCause::Landed, crate::ViewOutcome::Refused, 9),
        ClientEvent::mount_unmounted(
            crate::UnmountTrigger::SessionEnd,
            crate::UnmountOutcome::Committed,
            9,
            12,
        ),
        ClientEvent::mount_unmount_left(
            crate::UnmountTrigger::SessionEnd,
            crate::UnmountOutcome::Incomplete,
            crate::UnmountCause::Deadline,
            Some([1, 2, 3]),
            12,
        ),
        ClientEvent::mount_unmount_left(
            crate::UnmountTrigger::Start,
            crate::UnmountOutcome::Incomplete,
            crate::UnmountCause::Internal,
            None,
            12,
        ),
    ]
}

pub(super) struct SeedRandom;
impl granary_core::secure_random::SecureRandom for SeedRandom {
    fn fill(
        &mut self,
        bytes: &mut [u8],
    ) -> Result<(), granary_core::secure_random::EntropyUnavailable> {
        bytes.fill(42);
        Ok(())
    }
}

pub(super) const EVENT_INVENTORY: &[(&str, &[&str])] = &[
    ("commit.contention", &["event", "commits", "conflicts"]),
    ("commit.backoff", &["event", "cause", "outcome"]),
    ("commit.backoff", &["event", "cause", "outcome", "attempts"]),
    (
        "sync.workspace_exhausted",
        &["event", "reason", "needed", "limit"],
    ),
    (
        "overlay.cap_exhausted",
        &[
            "event", "reason", "cap", "charged", "reserved", "captured", "needed",
        ],
    ),
    ("commit.stopped", &["event", "cause"]),
    ("recover.journal_finished", &["event", "base_seq"]),
    ("recover.journal_blocked", &["event", "reason"]),
    ("recover.nothing", &["event"]),
    ("recover.signing_key_refused", &["event"]),
    ("recover.subsumed", &["event", "relation", "seq"]),
    ("recover.stale", &["event"]),
    ("recover.landed", &["event", "seq"]),
    ("recover.archived_landed", &["event", "seq"]),
    ("recover.rebased", &["event", "chain_len"]),
    ("recover.conflict", &["event", "path"]),
    ("recover.selection_changed", &["event", "token"]),
    ("recover.landed_unowned", &["event"]),
    ("recover.fence_settled", &["event", "how"]),
    ("recover.unresolved", &["event", "seq"]),
    ("recover.resent", &["event", "seq"]),
    ("op.conflict", &["event", "path", "class"]),
    (
        "overlay.recovery",
        &[
            "event",
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
            "event",
            "rollback_seq",
            "stage_id",
            "old_size",
            "restored_size",
            "discarded_bytes",
            "path",
        ],
    ),
    (
        "overlay.stage_rolled_back",
        &[
            "event",
            "rollback_seq",
            "stage_id",
            "old_size",
            "restored_size",
            "discarded_bytes",
        ],
    ),
    (
        "overlay.refused",
        &["event", "class", "record_index", "files", "bytes"],
    ),
    ("overlay.discard_refused", &["event", "reason"]),
    ("overlay.reconcile_refused", &["event", "reason"]),
    ("overlay.sweep", &["event", "files", "bytes"]),
    ("overlay.failures_dropped", &["event", "dropped"]),
    #[cfg(feature = "overlay-fault-tests")]
    (
        "overlay.fault",
        &["event", "point", "phase", "occurrence", "record_index"],
    ),
    #[cfg(feature = "overlay-fault-tests")]
    (
        "sync.fault",
        &["event", "point", "phase", "occurrence", "object_kind"],
    ),
    ("op.begin", &["event", "kind"]),
    ("op.end", &["event", "kind", "outcome"]),
    ("op.retry", &["event", "kind", "attempt", "reason"]),
    ("op.failed", &["event", "kind", "class"]),
    ("metrics.export_failed", &["event", "class"]),
    ("op.publish_bound", &["event", "publish_operation"]),
    ("log.config", &["event", "format", "destination"]),
    (
        "log.filter_rejected",
        &["event", "source", "reason", "detail"],
    ),
    ("mount.view", &["event", "cause", "outcome", "seq"]),
    ("mount.view", &["event", "cause", "outcome", "seq"]),
    (
        "mount.unmount",
        &["event", "trigger", "outcome", "seq", "elapsed_ms"],
    ),
    (
        "mount.unmount",
        &[
            "event",
            "trigger",
            "outcome",
            "cause",
            "files",
            "bytes",
            "operations",
            "elapsed_ms",
        ],
    ),
    (
        "mount.unmount",
        &["event", "trigger", "outcome", "cause", "elapsed_ms"],
    ),
];

pub(super) fn has_identity(record: &str, name: &str) -> bool {
    record.contains(name)
        || (name == "client.structure.walk"
            && record.contains("granary_client::resolve: structure walk"))
}
