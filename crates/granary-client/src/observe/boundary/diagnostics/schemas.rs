// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Registered schemas and exact scalar domains.

use super::{
    DefaultCallsite, FailureClass, FieldSet, FuseConnection, Identifier, Level, Metadata,
    MountListing, SESSION_DID_NOT_END_MESSAGE,
};
use crate::observe::MOUNT_SESSION_DID_NOT_END;
static CACHE_JOURNAL_IS_BROKEN_AFTER_A_FAILED_REOPEN_MID_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_JOURNAL_IS_BROKEN_AFTER_A_FAILED_REOPEN_MID_META);
pub(super) static CACHE_JOURNAL_IS_BROKEN_AFTER_A_FAILED_REOPEN_MID_META: Metadata<'static> =
    Metadata::new(
        "client.cache.journal.is.broken.after.a.failed.reopen.mid",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message"],
            Identifier(&CACHE_JOURNAL_IS_BROKEN_AFTER_A_FAILED_REOPEN_MID_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_JOURNAL_FLUSH_FAILED_RECORDS_STAY_BUFFERED_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_JOURNAL_FLUSH_FAILED_RECORDS_STAY_BUFFERED_META);
pub(super) static CACHE_JOURNAL_FLUSH_FAILED_RECORDS_STAY_BUFFERED_META: Metadata<'static> =
    Metadata::new(
        "client.cache.journal.flush.failed.records.stay.buffered",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "error"],
            Identifier(&CACHE_JOURNAL_FLUSH_FAILED_RECORDS_STAY_BUFFERED_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_COMPACTION_FAILED_JOURNAL_LEFT_UNCOMPACTED_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_COMPACTION_FAILED_JOURNAL_LEFT_UNCOMPACTED_META);
pub(super) static CACHE_COMPACTION_FAILED_JOURNAL_LEFT_UNCOMPACTED_META: Metadata<'static> =
    Metadata::new(
        "client.cache.compaction.failed.journal.left.uncompacted",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "error"],
            Identifier(&CACHE_COMPACTION_FAILED_JOURNAL_LEFT_UNCOMPACTED_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_JOURNAL_BUFFER_EXCEEDED_ITS_CAP_UNDER_SUSTAINED_FREE_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_JOURNAL_BUFFER_EXCEEDED_ITS_CAP_UNDER_SUSTAINED_FREE_META);
pub(super) static CACHE_JOURNAL_BUFFER_EXCEEDED_ITS_CAP_UNDER_SUSTAINED_FREE_META: Metadata<
    'static,
> = Metadata::new(
    "client.cache.journal.buffer.exceeded.its.cap.under.sustained.free",
    "granary_client::event",
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message", "dropped_records", "dropped_bytes"],
        Identifier(&CACHE_JOURNAL_BUFFER_EXCEEDED_ITS_CAP_UNDER_SUSTAINED_FREE_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static CACHE_JOURNAL_FLUSH_REFUSED_BY_THE_FREE_SPACE_WATERMARK_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_JOURNAL_FLUSH_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META);
pub(super) static CACHE_JOURNAL_FLUSH_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META: Metadata<'static> =
    Metadata::new(
        "client.cache.journal.flush.refused.by.the.free.space.watermark",
        "granary_client::event",
        Level::DEBUG,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message"],
            Identifier(&CACHE_JOURNAL_FLUSH_REFUSED_BY_THE_FREE_SPACE_WATERMARK_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_COMPACTION_REFUSED_BY_THE_FREE_SPACE_WATERMARK_SNAPSHOT_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_COMPACTION_REFUSED_BY_THE_FREE_SPACE_WATERMARK_SNAPSHOT_META);
pub(super) static CACHE_COMPACTION_REFUSED_BY_THE_FREE_SPACE_WATERMARK_SNAPSHOT_META: Metadata<
    'static,
> = Metadata::new(
    "client.cache.compaction.refused.by.the.free.space.watermark.snapshot",
    "granary_client::event",
    Level::DEBUG,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message"],
        Identifier(&CACHE_COMPACTION_REFUSED_BY_THE_FREE_SPACE_WATERMARK_SNAPSHOT_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static CACHE_COMPACTION_REFUSED_BY_THE_FREE_SPACE_WATERMARK_BEFORE_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_COMPACTION_REFUSED_BY_THE_FREE_SPACE_WATERMARK_BEFORE_META);
pub(super) static CACHE_COMPACTION_REFUSED_BY_THE_FREE_SPACE_WATERMARK_BEFORE_META: Metadata<
    'static,
> = Metadata::new(
    "client.cache.compaction.refused.by.the.free.space.watermark.before",
    "granary_client::event",
    Level::DEBUG,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message"],
        Identifier(&CACHE_COMPACTION_REFUSED_BY_THE_FREE_SPACE_WATERMARK_BEFORE_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static CACHE_EVICTION_FOUND_NOTHING_LEFT_TO_EVICT_THE_INSERT_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_EVICTION_FOUND_NOTHING_LEFT_TO_EVICT_THE_INSERT_META);
pub(super) static CACHE_EVICTION_FOUND_NOTHING_LEFT_TO_EVICT_THE_INSERT_META: Metadata<'static> =
    Metadata::new(
        "client.cache.eviction.found.nothing.left.to.evict.the.insert",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "total_bytes", "quota"],
            Identifier(&CACHE_EVICTION_FOUND_NOTHING_LEFT_TO_EVICT_THE_INSERT_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_INSERT_THE_OBJECT_PATH_HAS_NO_FANOUT_PARENT_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_INSERT_THE_OBJECT_PATH_HAS_NO_FANOUT_PARENT_META);
pub(super) static CACHE_INSERT_THE_OBJECT_PATH_HAS_NO_FANOUT_PARENT_META: Metadata<'static> =
    Metadata::new(
        "client.cache.insert.the.object.path.has.no.fanout.parent",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "id"],
            Identifier(&CACHE_INSERT_THE_OBJECT_PATH_HAS_NO_FANOUT_PARENT_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_INSERT_REFUSED_THE_OBJECT_FANOUT_IS_NOT_A_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_INSERT_REFUSED_THE_OBJECT_FANOUT_IS_NOT_A_META);
pub(super) static CACHE_INSERT_REFUSED_THE_OBJECT_FANOUT_IS_NOT_A_META: Metadata<'static> =
    Metadata::new(
        "client.cache.insert.refused.the.object.fanout.is.not.a",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "id", "error"],
            Identifier(&CACHE_INSERT_REFUSED_THE_OBJECT_FANOUT_IS_NOT_A_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_INSERT_DECLINED_A_DIRECTORY_OCCUPIES_THE_OBJECT_PATH_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_INSERT_DECLINED_A_DIRECTORY_OCCUPIES_THE_OBJECT_PATH_META);
pub(super) static CACHE_INSERT_DECLINED_A_DIRECTORY_OCCUPIES_THE_OBJECT_PATH_META: Metadata<
    'static,
> = Metadata::new(
    "client.cache.insert.declined.a.directory.occupies.the.object.path",
    "granary_client::event",
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message", "id", "path"],
        Identifier(&CACHE_INSERT_DECLINED_A_DIRECTORY_OCCUPIES_THE_OBJECT_PATH_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static CACHE_INSERT_A_FOREIGN_ENTRY_SITS_AT_THE_OBJECT_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_INSERT_A_FOREIGN_ENTRY_SITS_AT_THE_OBJECT_META);
pub(super) static CACHE_INSERT_A_FOREIGN_ENTRY_SITS_AT_THE_OBJECT_META: Metadata<'static> =
    Metadata::new(
        "client.cache.insert.a.foreign.entry.sits.at.the.object",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "id", "path"],
            Identifier(&CACHE_INSERT_A_FOREIGN_ENTRY_SITS_AT_THE_OBJECT_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_INSERT_FAILED_TO_INSPECT_THE_OBJECT_PATH_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_INSERT_FAILED_TO_INSPECT_THE_OBJECT_PATH_META);
pub(super) static CACHE_INSERT_FAILED_TO_INSPECT_THE_OBJECT_PATH_META: Metadata<'static> =
    Metadata::new(
        "client.cache.insert.failed.to.inspect.the.object.path",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "id", "error"],
            Identifier(&CACHE_INSERT_FAILED_TO_INSPECT_THE_OBJECT_PATH_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_INSERT_REFUSED_OBJECT_IS_LARGER_THAN_THE_WHOLE_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_INSERT_REFUSED_OBJECT_IS_LARGER_THAN_THE_WHOLE_META);
pub(super) static CACHE_INSERT_REFUSED_OBJECT_IS_LARGER_THAN_THE_WHOLE_META: Metadata<'static> =
    Metadata::new(
        "client.cache.insert.refused.object.is.larger.than.the.whole",
        "granary_client::event",
        Level::DEBUG,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "id", "len", "quota"],
            Identifier(&CACHE_INSERT_REFUSED_OBJECT_IS_LARGER_THAN_THE_WHOLE_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_INSERT_FAILED_TO_STAGE_THE_OBJECT_NOTHING_WAS_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_INSERT_FAILED_TO_STAGE_THE_OBJECT_NOTHING_WAS_META);
pub(super) static CACHE_INSERT_FAILED_TO_STAGE_THE_OBJECT_NOTHING_WAS_META: Metadata<'static> =
    Metadata::new(
        "client.cache.insert.failed.to.stage.the.object.nothing.was",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "id", "error"],
            Identifier(&CACHE_INSERT_FAILED_TO_STAGE_THE_OBJECT_NOTHING_WAS_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_INSERT_REFUSED_BY_THE_FREE_SPACE_WATERMARK_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_INSERT_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META);
pub(super) static CACHE_INSERT_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META: Metadata<'static> =
    Metadata::new(
        "client.cache.insert.refused.by.the.free.space.watermark",
        "granary_client::event",
        Level::DEBUG,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "id", "len"],
            Identifier(&CACHE_INSERT_REFUSED_BY_THE_FREE_SPACE_WATERMARK_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_INSERT_FAILED_TO_CREATE_ITS_FANOUT_DIRECTORY_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_INSERT_FAILED_TO_CREATE_ITS_FANOUT_DIRECTORY_META);
pub(super) static CACHE_INSERT_FAILED_TO_CREATE_ITS_FANOUT_DIRECTORY_META: Metadata<'static> =
    Metadata::new(
        "client.cache.insert.failed.to.create.its.fanout.directory",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "id", "error"],
            Identifier(&CACHE_INSERT_FAILED_TO_CREATE_ITS_FANOUT_DIRECTORY_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_INSERT_FAILED_TO_WRITE_THE_OBJECT_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_INSERT_FAILED_TO_WRITE_THE_OBJECT_META);
pub(super) static CACHE_INSERT_FAILED_TO_WRITE_THE_OBJECT_META: Metadata<'static> = Metadata::new(
    "client.cache.insert.failed.to.write.the.object",
    "granary_client::event",
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message", "id", "error"],
        Identifier(&CACHE_INSERT_FAILED_TO_WRITE_THE_OBJECT_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static CACHE_INSERT_OBJECT_TOO_LARGE_TO_INDEX_THE_FILE_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_INSERT_OBJECT_TOO_LARGE_TO_INDEX_THE_FILE_META);
pub(super) static CACHE_INSERT_OBJECT_TOO_LARGE_TO_INDEX_THE_FILE_META: Metadata<'static> =
    Metadata::new(
        "client.cache.insert.object.too.large.to.index.the.file",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "id", "len"],
            Identifier(&CACHE_INSERT_OBJECT_TOO_LARGE_TO_INDEX_THE_FILE_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_ROOT_WRITE_SKIPPED_THE_ROOT_PATH_HAS_NO_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_ROOT_WRITE_SKIPPED_THE_ROOT_PATH_HAS_NO_META);
pub(super) static CACHE_ROOT_WRITE_SKIPPED_THE_ROOT_PATH_HAS_NO_META: Metadata<'static> =
    Metadata::new(
        "client.cache.root.write.skipped.the.root.path.has.no",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume", "seq"],
            Identifier(&CACHE_ROOT_WRITE_SKIPPED_THE_ROOT_PATH_HAS_NO_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_ROOT_WRITE_SKIPPED_THE_VOLUME_DIRECTORY_IS_NOT_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_ROOT_WRITE_SKIPPED_THE_VOLUME_DIRECTORY_IS_NOT_META);
pub(super) static CACHE_ROOT_WRITE_SKIPPED_THE_VOLUME_DIRECTORY_IS_NOT_META: Metadata<'static> =
    Metadata::new(
        "client.cache.root.write.skipped.the.volume.directory.is.not",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume", "seq", "error"],
            Identifier(&CACHE_ROOT_WRITE_SKIPPED_THE_VOLUME_DIRECTORY_IS_NOT_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_ROOT_WRITE_SKIPPED_A_DIRECTORY_OCCUPIES_THE_DESTINATION_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_ROOT_WRITE_SKIPPED_A_DIRECTORY_OCCUPIES_THE_DESTINATION_META);
pub(super) static CACHE_ROOT_WRITE_SKIPPED_A_DIRECTORY_OCCUPIES_THE_DESTINATION_META: Metadata<
    'static,
> = Metadata::new(
    "client.cache.root.write.skipped.a.directory.occupies.the.destination",
    "granary_client::event",
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message", "volume", "seq", "path"],
        Identifier(&CACHE_ROOT_WRITE_SKIPPED_A_DIRECTORY_OCCUPIES_THE_DESTINATION_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static CACHE_ROOT_WRITE_A_FOREIGN_ENTRY_SITS_AT_THE_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_ROOT_WRITE_A_FOREIGN_ENTRY_SITS_AT_THE_META);
pub(super) static CACHE_ROOT_WRITE_A_FOREIGN_ENTRY_SITS_AT_THE_META: Metadata<'static> =
    Metadata::new(
        "client.cache.root.write.a.foreign.entry.sits.at.the",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume", "seq", "path"],
            Identifier(&CACHE_ROOT_WRITE_A_FOREIGN_ENTRY_SITS_AT_THE_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_ROOT_WRITE_SKIPPED_THE_DESTINATION_COULD_NOT_BE_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_ROOT_WRITE_SKIPPED_THE_DESTINATION_COULD_NOT_BE_META);
pub(super) static CACHE_ROOT_WRITE_SKIPPED_THE_DESTINATION_COULD_NOT_BE_META: Metadata<'static> =
    Metadata::new(
        "client.cache.root.write.skipped.the.destination.could.not.be",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume", "seq", "error"],
            Identifier(&CACHE_ROOT_WRITE_SKIPPED_THE_DESTINATION_COULD_NOT_BE_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_ROOT_WRITE_REFUSED_BY_THE_FREE_SPACE_WATERMARK_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_ROOT_WRITE_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META);
pub(super) static CACHE_ROOT_WRITE_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META: Metadata<'static> =
    Metadata::new(
        "client.cache.root.write.refused.by.the.free.space.watermark",
        "granary_client::event",
        Level::DEBUG,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume", "seq", "len"],
            Identifier(&CACHE_ROOT_WRITE_REFUSED_BY_THE_FREE_SPACE_WATERMARK_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_ROOT_WRITE_FAILED_TO_CREATE_ITS_VOLUME_DIRECTORY_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_ROOT_WRITE_FAILED_TO_CREATE_ITS_VOLUME_DIRECTORY_META);
pub(super) static CACHE_ROOT_WRITE_FAILED_TO_CREATE_ITS_VOLUME_DIRECTORY_META: Metadata<'static> =
    Metadata::new(
        "client.cache.root.write.failed.to.create.its.volume.directory",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume", "error"],
            Identifier(&CACHE_ROOT_WRITE_FAILED_TO_CREATE_ITS_VOLUME_DIRECTORY_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_ROOT_WRITE_FAILED_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_ROOT_WRITE_FAILED_META);
pub(super) static CACHE_ROOT_WRITE_FAILED_META: Metadata<'static> = Metadata::new(
    "client.cache.root.write.failed",
    "granary_client::event",
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message", "volume", "seq", "error"],
        Identifier(&CACHE_ROOT_WRITE_FAILED_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static ANCHOR_FLOOR_CANDIDATE_IS_AN_ABSENT_CLASS_SEQ_REFUSING_SITE: DefaultCallsite =
    DefaultCallsite::new(&ANCHOR_FLOOR_CANDIDATE_IS_AN_ABSENT_CLASS_SEQ_REFUSING_META);
pub(super) static ANCHOR_FLOOR_CANDIDATE_IS_AN_ABSENT_CLASS_SEQ_REFUSING_META: Metadata<'static> =
    Metadata::new(
        "client.anchor.floor.candidate.is.an.absent.class.seq.refusing",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume", "candidate"],
            Identifier(&ANCHOR_FLOOR_CANDIDATE_IS_AN_ABSENT_CLASS_SEQ_REFUSING_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static HINT_TOKEN_IS_EMPTY_AN_ETAG_LESS_BACKEND_RETAINING_SITE: DefaultCallsite =
    DefaultCallsite::new(&HINT_TOKEN_IS_EMPTY_AN_ETAG_LESS_BACKEND_RETAINING_META);
pub(super) static HINT_TOKEN_IS_EMPTY_AN_ETAG_LESS_BACKEND_RETAINING_META: Metadata<'static> =
    Metadata::new(
        "client.hint.token.is.empty.an.etag.less.backend.retaining",
        "granary_client::event",
        Level::DEBUG,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume"],
            Identifier(&HINT_TOKEN_IS_EMPTY_AN_ETAG_LESS_BACKEND_RETAINING_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static HINT_IS_UNPERSISTABLE_TOKEN_BYTES_LENGTH_STAMP_SIGN_OR_SITE: DefaultCallsite =
    DefaultCallsite::new(&HINT_IS_UNPERSISTABLE_TOKEN_BYTES_LENGTH_STAMP_SIGN_OR_META);
pub(super) static HINT_IS_UNPERSISTABLE_TOKEN_BYTES_LENGTH_STAMP_SIGN_OR_META: Metadata<'static> =
    Metadata::new(
        "client.hint.is.unpersistable.token.bytes.length.stamp.sign.or",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume"],
            Identifier(&HINT_IS_UNPERSISTABLE_TOKEN_BYTES_LENGTH_STAMP_SIGN_OR_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_ANCHOR_WRITE_FAILED_TO_CREATE_ITS_DIRECTORY_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_ANCHOR_WRITE_FAILED_TO_CREATE_ITS_DIRECTORY_META);
pub(super) static CACHE_ANCHOR_WRITE_FAILED_TO_CREATE_ITS_DIRECTORY_META: Metadata<'static> =
    Metadata::new(
        "client.cache.anchor.write.failed.to.create.its.directory",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume", "error"],
            Identifier(&CACHE_ANCHOR_WRITE_FAILED_TO_CREATE_ITS_DIRECTORY_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_ANCHOR_WRITE_FAILED_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_ANCHOR_WRITE_FAILED_META);
pub(super) static CACHE_ANCHOR_WRITE_FAILED_META: Metadata<'static> = Metadata::new(
    "client.cache.anchor.write.failed",
    "granary_client::event",
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message", "volume", "error"],
        Identifier(&CACHE_ANCHOR_WRITE_FAILED_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static MOUNT_ANCHOR_FLOOR_CANDIDATE_IS_AN_ABSENT_CLASS_SEQ_SITE: DefaultCallsite =
    DefaultCallsite::new(&MOUNT_ANCHOR_FLOOR_CANDIDATE_IS_AN_ABSENT_CLASS_SEQ_META);
pub(super) static MOUNT_ANCHOR_FLOOR_CANDIDATE_IS_AN_ABSENT_CLASS_SEQ_META: Metadata<'static> =
    Metadata::new(
        "client.mount.anchor.floor.candidate.is.an.absent.class.seq",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume", "candidate"],
            Identifier(&MOUNT_ANCHOR_FLOOR_CANDIDATE_IS_AN_ABSENT_CLASS_SEQ_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_ROOT_EVICTION_SKIPPED_THE_ROOT_PATH_HAS_NO_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_ROOT_EVICTION_SKIPPED_THE_ROOT_PATH_HAS_NO_META);
pub(super) static CACHE_ROOT_EVICTION_SKIPPED_THE_ROOT_PATH_HAS_NO_META: Metadata<'static> =
    Metadata::new(
        "client.cache.root.eviction.skipped.the.root.path.has.no",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume", "seq"],
            Identifier(&CACHE_ROOT_EVICTION_SKIPPED_THE_ROOT_PATH_HAS_NO_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_ROOT_EVICTION_SKIPPED_THE_VOLUME_DIRECTORY_IS_NOT_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_ROOT_EVICTION_SKIPPED_THE_VOLUME_DIRECTORY_IS_NOT_META);
pub(super) static CACHE_ROOT_EVICTION_SKIPPED_THE_VOLUME_DIRECTORY_IS_NOT_META: Metadata<'static> =
    Metadata::new(
        "client.cache.root.eviction.skipped.the.volume.directory.is.not",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume", "seq", "error"],
            Identifier(&CACHE_ROOT_EVICTION_SKIPPED_THE_VOLUME_DIRECTORY_IS_NOT_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_ROOT_EVICTION_FAILED_TO_REMOVE_THE_FILE_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_ROOT_EVICTION_FAILED_TO_REMOVE_THE_FILE_META);
pub(super) static CACHE_ROOT_EVICTION_FAILED_TO_REMOVE_THE_FILE_META: Metadata<'static> =
    Metadata::new(
        "client.cache.root.eviction.failed.to.remove.the.file",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume", "seq", "error"],
            Identifier(&CACHE_ROOT_EVICTION_FAILED_TO_REMOVE_THE_FILE_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_GUARD_PRESENT_AT_OPEN_THE_PREVIOUS_WRITER_DID_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_GUARD_PRESENT_AT_OPEN_THE_PREVIOUS_WRITER_DID_META);
pub(super) static CACHE_GUARD_PRESENT_AT_OPEN_THE_PREVIOUS_WRITER_DID_META: Metadata<'static> =
    Metadata::new(
        "client.cache.guard.present.at.open.the.previous.writer.did",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "root"],
            Identifier(&CACHE_GUARD_PRESENT_AT_OPEN_THE_PREVIOUS_WRITER_DID_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_LOCK_HELD_BY_ANOTHER_PROCESS_OPENING_READ_ONLY_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_LOCK_HELD_BY_ANOTHER_PROCESS_OPENING_READ_ONLY_META);
pub(super) static CACHE_LOCK_HELD_BY_ANOTHER_PROCESS_OPENING_READ_ONLY_META: Metadata<'static> =
    Metadata::new(
        "client.cache.lock.held.by.another.process.opening.read.only",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "root"],
            Identifier(&CACHE_LOCK_HELD_BY_ANOTHER_PROCESS_OPENING_READ_ONLY_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_READ_REFUSED_THE_OBJECT_FANOUT_IS_NOT_A_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_READ_REFUSED_THE_OBJECT_FANOUT_IS_NOT_A_META);
pub(super) static CACHE_READ_REFUSED_THE_OBJECT_FANOUT_IS_NOT_A_META: Metadata<'static> =
    Metadata::new(
        "client.cache.read.refused.the.object.fanout.is.not.a",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "id", "error"],
            Identifier(&CACHE_READ_REFUSED_THE_OBJECT_FANOUT_IS_NOT_A_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_OBJECT_FAILED_HASH_VERIFICATION_UNLINKING_AND_EVICTING_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_OBJECT_FAILED_HASH_VERIFICATION_UNLINKING_AND_EVICTING_META);
pub(super) static CACHE_OBJECT_FAILED_HASH_VERIFICATION_UNLINKING_AND_EVICTING_META: Metadata<
    'static,
> = Metadata::new(
    "client.cache.object.failed.hash.verification.unlinking.and.evicting",
    "granary_client::event",
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message", "id"],
        Identifier(&CACHE_OBJECT_FAILED_HASH_VERIFICATION_UNLINKING_AND_EVICTING_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static CACHE_OBJECT_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_AS_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_OBJECT_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_AS_META);
pub(super) static CACHE_OBJECT_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_AS_META: Metadata<'static> =
    Metadata::new(
        "client.cache.object.exceeds.the.size.bound.treating.it.as",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "id", "len"],
            Identifier(&CACHE_OBJECT_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_AS_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHED_ROOT_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_AS_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHED_ROOT_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_AS_META);
pub(super) static CACHED_ROOT_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_AS_META: Metadata<'static> =
    Metadata::new(
        "client.cached.root.exceeds.the.size.bound.treating.it.as",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume", "seq", "len"],
            Identifier(&CACHED_ROOT_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_AS_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_MAINTAIN_JOURNAL_FLUSH_FAILED_SKIPPING_COMPACTION_THIS_CYCLE_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_MAINTAIN_JOURNAL_FLUSH_FAILED_SKIPPING_COMPACTION_THIS_CYCLE_META);
pub(super) static CACHE_MAINTAIN_JOURNAL_FLUSH_FAILED_SKIPPING_COMPACTION_THIS_CYCLE_META:
    Metadata<'static> = Metadata::new(
    "client.cache.maintain.journal.flush.failed.skipping.compaction.this.cycle",
    "granary_client::event",
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message", "error"],
        Identifier(&CACHE_MAINTAIN_JOURNAL_FLUSH_FAILED_SKIPPING_COMPACTION_THIS_CYCLE_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static CACHE_MAINTAIN_COMPACTION_FAILED_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_MAINTAIN_COMPACTION_FAILED_META);
pub(super) static CACHE_MAINTAIN_COMPACTION_FAILED_META: Metadata<'static> = Metadata::new(
    "client.cache.maintain.compaction.failed",
    "granary_client::event",
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message", "error"],
        Identifier(&CACHE_MAINTAIN_COMPACTION_FAILED_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static SET_IN_THE_ENVIRONMENT_AND_IGNORED_THE_DIRECT_S3_SITE: DefaultCallsite =
    DefaultCallsite::new(&SET_IN_THE_ENVIRONMENT_AND_IGNORED_THE_DIRECT_S3_META);
pub(super) static SET_IN_THE_ENVIRONMENT_AND_IGNORED_THE_DIRECT_S3_META: Metadata<'static> =
    Metadata::new(
        "client.set.in.the.environment.and.ignored.the.direct.s3",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "variable"],
            Identifier(&SET_IN_THE_ENVIRONMENT_AND_IGNORED_THE_DIRECT_S3_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static WIRE_SNAPSHOT_PUBLISH_THE_TEMP_FILE_COULD_NOT_BE_SITE: DefaultCallsite =
    DefaultCallsite::new(&WIRE_SNAPSHOT_PUBLISH_THE_TEMP_FILE_COULD_NOT_BE_META);
pub(super) static WIRE_SNAPSHOT_PUBLISH_THE_TEMP_FILE_COULD_NOT_BE_META: Metadata<'static> =
    Metadata::new(
        "client.wire.snapshot.publish.the.temp.file.could.not.be",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "from", "to", "error"],
            Identifier(&WIRE_SNAPSHOT_PUBLISH_THE_TEMP_FILE_COULD_NOT_BE_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static A_CACHE_DIR_IS_PRESENT_BUT_A_TRANSPORT_DOWN_SITE: DefaultCallsite =
    DefaultCallsite::new(&A_CACHE_DIR_IS_PRESENT_BUT_A_TRANSPORT_DOWN_META);
pub(super) static A_CACHE_DIR_IS_PRESENT_BUT_A_TRANSPORT_DOWN_META: Metadata<'static> =
    Metadata::new(
        "client.a.cache.dir.is.present.but.a.transport.down",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume"],
            Identifier(&A_CACHE_DIR_IS_PRESENT_BUT_A_TRANSPORT_DOWN_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static THE_TRANSPORT_GAVE_NO_ANSWER_FALLING_BACK_TO_THE_SITE: DefaultCallsite =
    DefaultCallsite::new(&THE_TRANSPORT_GAVE_NO_ANSWER_FALLING_BACK_TO_THE_META);
pub(super) static THE_TRANSPORT_GAVE_NO_ANSWER_FALLING_BACK_TO_THE_META: Metadata<'static> =
    Metadata::new(
        "client.the.transport.gave.no.answer.falling.back.to.the",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume", "seq", "age"],
            Identifier(&THE_TRANSPORT_GAVE_NO_ANSWER_FALLING_BACK_TO_THE_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static STORE_AN_OBJECT_PATH_HAS_NO_FANOUT_PARENT_REPORTING_SITE: DefaultCallsite =
    DefaultCallsite::new(&STORE_AN_OBJECT_PATH_HAS_NO_FANOUT_PARENT_REPORTING_META);
pub(super) static STORE_AN_OBJECT_PATH_HAS_NO_FANOUT_PARENT_REPORTING_META: Metadata<'static> =
    Metadata::new(
        "client.store.an.object.path.has.no.fanout.parent.reporting",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "path"],
            Identifier(&STORE_AN_OBJECT_PATH_HAS_NO_FANOUT_PARENT_REPORTING_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static STORE_AN_OBJECT_FANOUT_IS_NOT_A_REAL_DIRECTORY_SITE: DefaultCallsite =
    DefaultCallsite::new(&STORE_AN_OBJECT_FANOUT_IS_NOT_A_REAL_DIRECTORY_META);
pub(super) static STORE_AN_OBJECT_FANOUT_IS_NOT_A_REAL_DIRECTORY_META: Metadata<'static> =
    Metadata::new(
        "client.store.an.object.fanout.is.not.a.real.directory",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "fanout", "error"],
            Identifier(&STORE_AN_OBJECT_FANOUT_IS_NOT_A_REAL_DIRECTORY_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static STORE_AN_OBJECT_LEAF_IS_NOT_A_REGULAR_FILE_SITE: DefaultCallsite =
    DefaultCallsite::new(&STORE_AN_OBJECT_LEAF_IS_NOT_A_REGULAR_FILE_META);
pub(super) static STORE_AN_OBJECT_LEAF_IS_NOT_A_REGULAR_FILE_META: Metadata<'static> =
    Metadata::new(
        "client.store.an.object.leaf.is.not.a.regular.file",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "path"],
            Identifier(&STORE_AN_OBJECT_LEAF_IS_NOT_A_REGULAR_FILE_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static STORE_AN_OBJECT_LEAF_COULD_NOT_BE_CLASSIFIED_REPORTING_SITE: DefaultCallsite =
    DefaultCallsite::new(&STORE_AN_OBJECT_LEAF_COULD_NOT_BE_CLASSIFIED_REPORTING_META);
pub(super) static STORE_AN_OBJECT_LEAF_COULD_NOT_BE_CLASSIFIED_REPORTING_META: Metadata<'static> =
    Metadata::new(
        "client.store.an.object.leaf.could.not.be.classified.reporting",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "path", "error"],
            Identifier(&STORE_AN_OBJECT_LEAF_COULD_NOT_BE_CLASSIFIED_REPORTING_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static STORE_PUT_THE_OBJECT_FANOUT_IS_NOT_A_REAL_SITE: DefaultCallsite =
    DefaultCallsite::new(&STORE_PUT_THE_OBJECT_FANOUT_IS_NOT_A_REAL_META);
pub(super) static STORE_PUT_THE_OBJECT_FANOUT_IS_NOT_A_REAL_META: Metadata<'static> = Metadata::new(
    "client.store.put.the.object.fanout.is.not.a.real",
    "granary_client::event",
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message", "fanout", "error"],
        Identifier(&STORE_PUT_THE_OBJECT_FANOUT_IS_NOT_A_REAL_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static STORE_PUT_AN_OBJECT_LEAF_IS_NOT_A_REGULAR_SITE: DefaultCallsite =
    DefaultCallsite::new(&STORE_PUT_AN_OBJECT_LEAF_IS_NOT_A_REGULAR_META);
pub(super) static STORE_PUT_AN_OBJECT_LEAF_IS_NOT_A_REGULAR_META: Metadata<'static> = Metadata::new(
    "client.store.put.an.object.leaf.is.not.a.regular",
    "granary_client::event",
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message", "path"],
        Identifier(&STORE_PUT_AN_OBJECT_LEAF_IS_NOT_A_REGULAR_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static STORE_GET_THE_OBJECT_FANOUT_IS_NOT_A_REAL_SITE: DefaultCallsite =
    DefaultCallsite::new(&STORE_GET_THE_OBJECT_FANOUT_IS_NOT_A_REAL_META);
pub(super) static STORE_GET_THE_OBJECT_FANOUT_IS_NOT_A_REAL_META: Metadata<'static> = Metadata::new(
    "client.store.get.the.object.fanout.is.not.a.real",
    "granary_client::event",
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message", "fanout", "error"],
        Identifier(&STORE_GET_THE_OBJECT_FANOUT_IS_NOT_A_REAL_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static STORE_ESTABLISHED_OPEN_TXN_IS_NOT_A_REAL_DIRECTORY_SITE: DefaultCallsite =
    DefaultCallsite::new(&STORE_ESTABLISHED_OPEN_TXN_IS_NOT_A_REAL_DIRECTORY_META);
pub(super) static STORE_ESTABLISHED_OPEN_TXN_IS_NOT_A_REAL_DIRECTORY_META: Metadata<'static> =
    Metadata::new(
        "client.store.established.open.txn.is.not.a.real.directory",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "path"],
            Identifier(&STORE_ESTABLISHED_OPEN_TXN_IS_NOT_A_REAL_DIRECTORY_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static STORE_ESTABLISHED_OPEN_AN_ORPHANED_TXN_ENTRY_COULD_NOT_SITE: DefaultCallsite =
    DefaultCallsite::new(&STORE_ESTABLISHED_OPEN_AN_ORPHANED_TXN_ENTRY_COULD_NOT_META);
pub(super) static STORE_ESTABLISHED_OPEN_AN_ORPHANED_TXN_ENTRY_COULD_NOT_META: Metadata<'static> =
    Metadata::new(
        "client.store.established.open.an.orphaned.txn.entry.could.not",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "path", "error"],
            Identifier(&STORE_ESTABLISHED_OPEN_AN_ORPHANED_TXN_ENTRY_COULD_NOT_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static STORE_ESTABLISHED_OPEN_SWEPT_ORPHANED_TXN_STAGING_FILES_SITE: DefaultCallsite =
    DefaultCallsite::new(&STORE_ESTABLISHED_OPEN_SWEPT_ORPHANED_TXN_STAGING_FILES_META);
pub(super) static STORE_ESTABLISHED_OPEN_SWEPT_ORPHANED_TXN_STAGING_FILES_META: Metadata<'static> =
    Metadata::new(
        "client.store.established.open.swept.orphaned.txn.staging.files",
        "granary_client::event",
        Level::DEBUG,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "swept", "skipped"],
            Identifier(&STORE_ESTABLISHED_OPEN_SWEPT_ORPHANED_TXN_STAGING_FILES_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static SEAM_ATTEMPT_FAILED_RETRYING_ONCE_SITE: DefaultCallsite =
    DefaultCallsite::new(&SEAM_ATTEMPT_FAILED_RETRYING_ONCE_META);
pub(super) static SEAM_ATTEMPT_FAILED_RETRYING_ONCE_META: Metadata<'static> = Metadata::new(
    "client.seam.attempt.failed.retrying.once",
    "granary_client::event",
    Level::DEBUG,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message", "seam", "class", "error"],
        Identifier(&SEAM_ATTEMPT_FAILED_RETRYING_ONCE_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static WRITABLE_SHUTDOWN_COORDINATION_FAILED_SITE: DefaultCallsite =
    DefaultCallsite::new(&WRITABLE_SHUTDOWN_COORDINATION_FAILED_META);
pub(super) static WRITABLE_SHUTDOWN_COORDINATION_FAILED_META: Metadata<'static> = Metadata::new(
    "client.writable.shutdown.coordination.failed",
    "granary_client::event",
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message", "coordination", "cache_closed"],
        Identifier(&WRITABLE_SHUTDOWN_COORDINATION_FAILED_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static MOUNT_SESSION_SHUTDOWN_CLOSING_THE_CACHE_FAILED_THE_CRASH_SITE: DefaultCallsite =
    DefaultCallsite::new(&MOUNT_SESSION_SHUTDOWN_CLOSING_THE_CACHE_FAILED_THE_CRASH_META);
pub(super) static MOUNT_SESSION_SHUTDOWN_CLOSING_THE_CACHE_FAILED_THE_CRASH_META: Metadata<
    'static,
> = Metadata::new(
    "client.mount.session.shutdown.closing.the.cache.failed.the.crash",
    "granary_client::event",
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message", "root", "error"],
        Identifier(&MOUNT_SESSION_SHUTDOWN_CLOSING_THE_CACHE_FAILED_THE_CRASH_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static MOUNT_TEARDOWN_READ_PATH_COUNTERS_FOR_THE_READ_PHASE_SITE: DefaultCallsite =
    DefaultCallsite::new(&MOUNT_TEARDOWN_READ_PATH_COUNTERS_FOR_THE_READ_PHASE_META);
pub(super) static MOUNT_TEARDOWN_READ_PATH_COUNTERS_FOR_THE_READ_PHASE_META: Metadata<'static> =
    Metadata::new(
        "client.mount.teardown.read.path.counters.for.the.read.phase",
        "granary_client::event",
        Level::INFO,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
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
            Identifier(&MOUNT_TEARDOWN_READ_PATH_COUNTERS_FOR_THE_READ_PHASE_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static MOUNT_SESSION_DROP_CLOSING_THE_CACHE_FAILED_THE_CRASH_SITE: DefaultCallsite =
    DefaultCallsite::new(&MOUNT_SESSION_DROP_CLOSING_THE_CACHE_FAILED_THE_CRASH_META);
pub(super) static MOUNT_SESSION_DROP_CLOSING_THE_CACHE_FAILED_THE_CRASH_META: Metadata<'static> =
    Metadata::new(
        "client.mount.session.drop.closing.the.cache.failed.the.crash",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "root", "error"],
            Identifier(&MOUNT_SESSION_DROP_CLOSING_THE_CACHE_FAILED_THE_CRASH_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_ANCHOR_FILE_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_ANCHOR_FILE_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_META);
pub(super) static CACHE_ANCHOR_FILE_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_META: Metadata<'static> =
    Metadata::new(
        "client.cache.anchor.file.exceeds.the.size.bound.treating.it",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume", "len"],
            Identifier(&CACHE_ANCHOR_FILE_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_ANCHOR_FILE_FAILED_STRICT_PARSE_TREATING_IT_AS_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_ANCHOR_FILE_FAILED_STRICT_PARSE_TREATING_IT_AS_META);
pub(super) static CACHE_ANCHOR_FILE_FAILED_STRICT_PARSE_TREATING_IT_AS_META: Metadata<'static> =
    Metadata::new(
        "client.cache.anchor.file.failed.strict.parse.treating.it.as",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume"],
            Identifier(&CACHE_ANCHOR_FILE_FAILED_STRICT_PARSE_TREATING_IT_AS_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static MOUNT_ANCHOR_FILE_CARRIES_A_HINT_LINE_WHICH_ITS_SITE: DefaultCallsite =
    DefaultCallsite::new(&MOUNT_ANCHOR_FILE_CARRIES_A_HINT_LINE_WHICH_ITS_META);
pub(super) static MOUNT_ANCHOR_FILE_CARRIES_A_HINT_LINE_WHICH_ITS_META: Metadata<'static> =
    Metadata::new(
        "client.mount.anchor.file.carries.a.hint.line.which.its",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume"],
            Identifier(&MOUNT_ANCHOR_FILE_CARRIES_A_HINT_LINE_WHICH_ITS_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static REFUSING_TO_UNLINK_AN_OBJECT_PATH_THAT_HAS_NO_SITE: DefaultCallsite =
    DefaultCallsite::new(&REFUSING_TO_UNLINK_AN_OBJECT_PATH_THAT_HAS_NO_META);
pub(super) static REFUSING_TO_UNLINK_AN_OBJECT_PATH_THAT_HAS_NO_META: Metadata<'static> =
    Metadata::new(
        "client.refusing.to.unlink.an.object.path.that.has.no",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "path", "context"],
            Identifier(&REFUSING_TO_UNLINK_AN_OBJECT_PATH_THAT_HAS_NO_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static REFUSING_TO_UNLINK_AN_OBJECT_THROUGH_A_FOREIGN_FANOUT_SITE: DefaultCallsite =
    DefaultCallsite::new(&REFUSING_TO_UNLINK_AN_OBJECT_THROUGH_A_FOREIGN_FANOUT_META);
pub(super) static REFUSING_TO_UNLINK_AN_OBJECT_THROUGH_A_FOREIGN_FANOUT_META: Metadata<'static> =
    Metadata::new(
        "client.refusing.to.unlink.an.object.through.a.foreign.fanout",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "fanout", "context"],
            Identifier(&REFUSING_TO_UNLINK_AN_OBJECT_THROUGH_A_FOREIGN_FANOUT_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static REFUSING_TO_UNLINK_AN_OBJECT_UNDER_A_FANOUT_THAT_SITE: DefaultCallsite =
    DefaultCallsite::new(&REFUSING_TO_UNLINK_AN_OBJECT_UNDER_A_FANOUT_THAT_META);
pub(super) static REFUSING_TO_UNLINK_AN_OBJECT_UNDER_A_FANOUT_THAT_META: Metadata<'static> =
    Metadata::new(
        "client.refusing.to.unlink.an.object.under.a.fanout.that",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "fanout", "error", "context"],
            Identifier(&REFUSING_TO_UNLINK_AN_OBJECT_UNDER_A_FANOUT_THAT_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static AN_OBJECT_LEAF_COULD_NOT_BE_UNLINKED_IT_STAYS_SITE: DefaultCallsite =
    DefaultCallsite::new(&AN_OBJECT_LEAF_COULD_NOT_BE_UNLINKED_IT_STAYS_META);
pub(super) static AN_OBJECT_LEAF_COULD_NOT_BE_UNLINKED_IT_STAYS_META: Metadata<'static> =
    Metadata::new(
        "client.an.object.leaf.could.not.be.unlinked.it.stays",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "path", "error", "context"],
            Identifier(&AN_OBJECT_LEAF_COULD_NOT_BE_UNLINKED_IT_STAYS_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static COLD_REBUILD_WALK_SKIPPING_A_NON_DIGEST_FILE_NAME_SITE: DefaultCallsite =
    DefaultCallsite::new(&COLD_REBUILD_WALK_SKIPPING_A_NON_DIGEST_FILE_NAME_META);
pub(super) static COLD_REBUILD_WALK_SKIPPING_A_NON_DIGEST_FILE_NAME_META: Metadata<'static> =
    Metadata::new(
        "client.cold.rebuild.walk.skipping.a.non.digest.file.name",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "name"],
            Identifier(&COLD_REBUILD_WALK_SKIPPING_A_NON_DIGEST_FILE_NAME_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static COLD_REBUILD_WALK_SKIPPING_A_FILE_WHOSE_NAME_DOES_SITE: DefaultCallsite =
    DefaultCallsite::new(&COLD_REBUILD_WALK_SKIPPING_A_FILE_WHOSE_NAME_DOES_META);
pub(super) static COLD_REBUILD_WALK_SKIPPING_A_FILE_WHOSE_NAME_DOES_META: Metadata<'static> =
    Metadata::new(
        "client.cold.rebuild.walk.skipping.a.file.whose.name.does",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "name", "dir"],
            Identifier(&COLD_REBUILD_WALK_SKIPPING_A_FILE_WHOSE_NAME_DOES_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
pub(super) static COLD_REBUILD_WALK_SKIPPING_AN_ENTRY_WHOSE_METADATA_COULD_SITE: DefaultCallsite =
    DefaultCallsite::new(&COLD_REBUILD_WALK_SKIPPING_AN_ENTRY_WHOSE_METADATA_COULD_META);
pub(super) static COLD_REBUILD_WALK_SKIPPING_AN_ENTRY_WHOSE_METADATA_COULD_META: Metadata<'static> =
    Metadata::new(
        "client.cold.rebuild.walk.skipping.an.entry.whose.metadata.could",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "path", "error"],
            Identifier(&COLD_REBUILD_WALK_SKIPPING_AN_ENTRY_WHOSE_METADATA_COULD_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static COLD_REBUILD_WALK_SKIPPING_A_NON_REGULAR_FILE_ENTRY_SITE: DefaultCallsite =
    DefaultCallsite::new(&COLD_REBUILD_WALK_SKIPPING_A_NON_REGULAR_FILE_ENTRY_META);
pub(super) static COLD_REBUILD_WALK_SKIPPING_A_NON_REGULAR_FILE_ENTRY_META: Metadata<'static> =
    Metadata::new(
        "client.cold.rebuild.walk.skipping.a.non.regular.file.entry",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "path"],
            Identifier(&COLD_REBUILD_WALK_SKIPPING_A_NON_REGULAR_FILE_ENTRY_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static COLD_REBUILD_WALK_SKIPPING_AN_OVERSIZED_FOREIGN_FILE_SITE: DefaultCallsite =
    DefaultCallsite::new(&COLD_REBUILD_WALK_SKIPPING_AN_OVERSIZED_FOREIGN_FILE_META);
pub(super) static COLD_REBUILD_WALK_SKIPPING_AN_OVERSIZED_FOREIGN_FILE_META: Metadata<'static> =
    Metadata::new(
        "client.cold.rebuild.walk.skipping.an.oversized.foreign.file",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "path", "len"],
            Identifier(&COLD_REBUILD_WALK_SKIPPING_AN_OVERSIZED_FOREIGN_FILE_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static COLD_REBUILD_WALK_SKIPPING_A_SIZE_THAT_CANNOT_FIT_SITE: DefaultCallsite =
    DefaultCallsite::new(&COLD_REBUILD_WALK_SKIPPING_A_SIZE_THAT_CANNOT_FIT_META);
pub(super) static COLD_REBUILD_WALK_SKIPPING_A_SIZE_THAT_CANNOT_FIT_META: Metadata<'static> =
    Metadata::new(
        "client.cold.rebuild.walk.skipping.a.size.that.cannot.fit",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "path", "len"],
            Identifier(&COLD_REBUILD_WALK_SKIPPING_A_SIZE_THAT_CANNOT_FIT_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static COLD_REBUILD_WALK_SKIPPING_A_NON_FANOUT_ENTRY_UNDER_SITE: DefaultCallsite =
    DefaultCallsite::new(&COLD_REBUILD_WALK_SKIPPING_A_NON_FANOUT_ENTRY_UNDER_META);
pub(super) static COLD_REBUILD_WALK_SKIPPING_A_NON_FANOUT_ENTRY_UNDER_META: Metadata<'static> =
    Metadata::new(
        "client.cold.rebuild.walk.skipping.a.non.fanout.entry.under",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "name"],
            Identifier(&COLD_REBUILD_WALK_SKIPPING_A_NON_FANOUT_ENTRY_UNDER_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static COLD_REBUILD_WALK_SKIPPING_A_FANOUT_ENTRY_WHOSE_TYPE_SITE: DefaultCallsite =
    DefaultCallsite::new(&COLD_REBUILD_WALK_SKIPPING_A_FANOUT_ENTRY_WHOSE_TYPE_META);
pub(super) static COLD_REBUILD_WALK_SKIPPING_A_FANOUT_ENTRY_WHOSE_TYPE_META: Metadata<'static> =
    Metadata::new(
        "client.cold.rebuild.walk.skipping.a.fanout.entry.whose.type",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "path", "error"],
            Identifier(&COLD_REBUILD_WALK_SKIPPING_A_FANOUT_ENTRY_WHOSE_TYPE_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static COLD_REBUILD_WALK_SKIPPING_A_NON_DIRECTORY_ENTRY_UNDER_SITE: DefaultCallsite =
    DefaultCallsite::new(&COLD_REBUILD_WALK_SKIPPING_A_NON_DIRECTORY_ENTRY_UNDER_META);
pub(super) static COLD_REBUILD_WALK_SKIPPING_A_NON_DIRECTORY_ENTRY_UNDER_META: Metadata<'static> =
    Metadata::new(
        "client.cold.rebuild.walk.skipping.a.non.directory.entry.under",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "path"],
            Identifier(&COLD_REBUILD_WALK_SKIPPING_A_NON_DIRECTORY_ENTRY_UNDER_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static COLD_REBUILD_WALK_THE_ADOPTION_CAP_WAS_REACHED_THE_SITE: DefaultCallsite =
    DefaultCallsite::new(&COLD_REBUILD_WALK_THE_ADOPTION_CAP_WAS_REACHED_THE_META);
pub(super) static COLD_REBUILD_WALK_THE_ADOPTION_CAP_WAS_REACHED_THE_META: Metadata<'static> =
    Metadata::new(
        "client.cold.rebuild.walk.the.adoption.cap.was.reached.the",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "dropped", "adoption_cap"],
            Identifier(&COLD_REBUILD_WALK_THE_ADOPTION_CAP_WAS_REACHED_THE_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static COLD_REBUILD_WALK_SNAPSHOT_REWRITE_AND_JOURNAL_RESET_REFUSED_SITE: DefaultCallsite =
    DefaultCallsite::new(&COLD_REBUILD_WALK_SNAPSHOT_REWRITE_AND_JOURNAL_RESET_REFUSED_META);
pub(super) static COLD_REBUILD_WALK_SNAPSHOT_REWRITE_AND_JOURNAL_RESET_REFUSED_META: Metadata<
    'static,
> = Metadata::new(
    "client.cold.rebuild.walk.snapshot.rewrite.and.journal.reset.refused",
    "granary_client::event",
    Level::DEBUG,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message"],
        Identifier(&COLD_REBUILD_WALK_SNAPSHOT_REWRITE_AND_JOURNAL_RESET_REFUSED_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static CACHE_INDEX_FILE_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_INDEX_FILE_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_META);
pub(super) static CACHE_INDEX_FILE_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_META: Metadata<'static> =
    Metadata::new(
        "client.cache.index.file.exceeds.the.size.bound.treating.it",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "path", "len", "what"],
            Identifier(&CACHE_INDEX_FILE_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_INDEX_FILE_GREW_PAST_THE_SIZE_BOUND_BETWEEN_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_INDEX_FILE_GREW_PAST_THE_SIZE_BOUND_BETWEEN_META);
pub(super) static CACHE_INDEX_FILE_GREW_PAST_THE_SIZE_BOUND_BETWEEN_META: Metadata<'static> =
    Metadata::new(
        "client.cache.index.file.grew.past.the.size.bound.between",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "path", "len", "what"],
            Identifier(&CACHE_INDEX_FILE_GREW_PAST_THE_SIZE_BOUND_BETWEEN_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_SNAPSHOT_PRESENT_WITH_NO_JOURNAL_A_CREATION_CRASH_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_SNAPSHOT_PRESENT_WITH_NO_JOURNAL_A_CREATION_CRASH_META);
pub(super) static CACHE_SNAPSHOT_PRESENT_WITH_NO_JOURNAL_A_CREATION_CRASH_META: Metadata<'static> =
    Metadata::new(
        "client.cache.snapshot.present.with.no.journal.a.creation.crash",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "root"],
            Identifier(&CACHE_SNAPSHOT_PRESENT_WITH_NO_JOURNAL_A_CREATION_CRASH_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_WRITER_OPEN_AN_ORPHANED_TXN_ENTRY_COULD_NOT_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_WRITER_OPEN_AN_ORPHANED_TXN_ENTRY_COULD_NOT_META);
pub(super) static CACHE_WRITER_OPEN_AN_ORPHANED_TXN_ENTRY_COULD_NOT_META: Metadata<'static> =
    Metadata::new(
        "client.cache.writer.open.an.orphaned.txn.entry.could.not",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "path", "error"],
            Identifier(&CACHE_WRITER_OPEN_AN_ORPHANED_TXN_ENTRY_COULD_NOT_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static CACHE_WRITER_OPEN_SWEPT_ORPHANED_TXN_STAGING_FILES_SITE: DefaultCallsite =
    DefaultCallsite::new(&CACHE_WRITER_OPEN_SWEPT_ORPHANED_TXN_STAGING_FILES_META);
pub(super) static CACHE_WRITER_OPEN_SWEPT_ORPHANED_TXN_STAGING_FILES_META: Metadata<'static> =
    Metadata::new(
        "client.cache.writer.open.swept.orphaned.txn.staging.files",
        "granary_client::event",
        Level::DEBUG,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "swept", "skipped"],
            Identifier(&CACHE_WRITER_OPEN_SWEPT_ORPHANED_TXN_STAGING_FILES_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static STRUCTURE_WALK_SITE: DefaultCallsite = DefaultCallsite::new(&STRUCTURE_WALK_META);
pub(super) static STRUCTURE_WALK_META: Metadata<'static> = Metadata::new(
    "client.structure.walk",
    "granary_client::resolve",
    Level::INFO,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
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
        Identifier(&STRUCTURE_WALK_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static GRAN_MOUNT_UNMOUNT_FAILED_FALLING_BACK_TO_A_LAZY_SITE: DefaultCallsite =
    DefaultCallsite::new(&GRAN_MOUNT_UNMOUNT_FAILED_FALLING_BACK_TO_A_LAZY_META);
pub(super) static GRAN_MOUNT_UNMOUNT_FAILED_FALLING_BACK_TO_A_LAZY_META: Metadata<'static> =
    Metadata::new(
        "client.gran.mount.unmount.failed.falling.back.to.a.lazy",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "error"],
            Identifier(&GRAN_MOUNT_UNMOUNT_FAILED_FALLING_BACK_TO_A_LAZY_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static GRAN_MOUNT_THE_MOUNT_WAS_LAZILY_DETACHED_MNT_DETACH_SITE: DefaultCallsite =
    DefaultCallsite::new(&GRAN_MOUNT_THE_MOUNT_WAS_LAZILY_DETACHED_MNT_DETACH_META);
pub(super) static GRAN_MOUNT_THE_MOUNT_WAS_LAZILY_DETACHED_MNT_DETACH_META: Metadata<'static> =
    Metadata::new(
        "client.gran.mount.the.mount.was.lazily.detached.mnt.detach",
        "granary_client::event",
        Level::INFO,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message"],
            Identifier(&GRAN_MOUNT_THE_MOUNT_WAS_LAZILY_DETACHED_MNT_DETACH_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static GRAN_MOUNT_BOTH_THE_PLAIN_UNMOUNT_AND_THE_MNT_SITE: DefaultCallsite =
    DefaultCallsite::new(&GRAN_MOUNT_BOTH_THE_PLAIN_UNMOUNT_AND_THE_MNT_META);
pub(super) static GRAN_MOUNT_BOTH_THE_PLAIN_UNMOUNT_AND_THE_MNT_META: Metadata<'static> =
    Metadata::new(
        "client.gran.mount.both.the.plain.unmount.and.the.mnt",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "unmount_error", "detach_error"],
            Identifier(&GRAN_MOUNT_BOTH_THE_PLAIN_UNMOUNT_AND_THE_MNT_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static GRAN_MOUNT_A_SIGNAL_READINESS_REPORT_NEVER_ARRIVED_BEFORE_SITE: DefaultCallsite =
    DefaultCallsite::new(&GRAN_MOUNT_A_SIGNAL_READINESS_REPORT_NEVER_ARRIVED_BEFORE_META);
pub(super) static GRAN_MOUNT_A_SIGNAL_READINESS_REPORT_NEVER_ARRIVED_BEFORE_META: Metadata<
    'static,
> = Metadata::new(
    "client.gran.mount.a.signal.readiness.report.never.arrived.before",
    "granary_client::event",
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message"],
        Identifier(&GRAN_MOUNT_A_SIGNAL_READINESS_REPORT_NEVER_ARRIVED_BEFORE_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static GRAN_MOUNT_A_CACHED_ROOT_AND_THE_WIRE_ROOT_SITE: DefaultCallsite =
    DefaultCallsite::new(&GRAN_MOUNT_A_CACHED_ROOT_AND_THE_WIRE_ROOT_META);
pub(super) static GRAN_MOUNT_A_CACHED_ROOT_AND_THE_WIRE_ROOT_META: Metadata<'static> =
    Metadata::new(
        "client.gran.mount.a.cached.root.and.the.wire.root",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "volume", "finding"],
            Identifier(&GRAN_MOUNT_A_CACHED_ROOT_AND_THE_WIRE_ROOT_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static GRAN_MOUNT_COULD_NOT_BUILD_A_RUNTIME_FOR_SIGINT_SITE: DefaultCallsite =
    DefaultCallsite::new(&GRAN_MOUNT_COULD_NOT_BUILD_A_RUNTIME_FOR_SIGINT_META);
pub(super) static GRAN_MOUNT_COULD_NOT_BUILD_A_RUNTIME_FOR_SIGINT_META: Metadata<'static> =
    Metadata::new(
        "client.gran.mount.could.not.build.a.runtime.for.sigint",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message"],
            Identifier(&GRAN_MOUNT_COULD_NOT_BUILD_A_RUNTIME_FOR_SIGINT_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static GRAN_MOUNT_COULD_NOT_REGISTER_A_SIGINT_HANDLER_THIS_SITE: DefaultCallsite =
    DefaultCallsite::new(&GRAN_MOUNT_COULD_NOT_REGISTER_A_SIGINT_HANDLER_THIS_META);
pub(super) static GRAN_MOUNT_COULD_NOT_REGISTER_A_SIGINT_HANDLER_THIS_META: Metadata<'static> =
    Metadata::new(
        "client.gran.mount.could.not.register.a.sigint.handler.this",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "error"],
            Identifier(&GRAN_MOUNT_COULD_NOT_REGISTER_A_SIGINT_HANDLER_THIS_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static GRAN_MOUNT_THE_SIGINT_STREAM_ENDED_WITHOUT_DELIVERING_A_SITE: DefaultCallsite =
    DefaultCallsite::new(&GRAN_MOUNT_THE_SIGINT_STREAM_ENDED_WITHOUT_DELIVERING_A_META);
pub(super) static GRAN_MOUNT_THE_SIGINT_STREAM_ENDED_WITHOUT_DELIVERING_A_META: Metadata<'static> =
    Metadata::new(
        "client.gran.mount.the.sigint.stream.ended.without.delivering.a",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message"],
            Identifier(&GRAN_MOUNT_THE_SIGINT_STREAM_ENDED_WITHOUT_DELIVERING_A_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static GRAN_MOUNT_COULD_NOT_BUILD_A_RUNTIME_FOR_SIGTERM_SITE: DefaultCallsite =
    DefaultCallsite::new(&GRAN_MOUNT_COULD_NOT_BUILD_A_RUNTIME_FOR_SIGTERM_META);
pub(super) static GRAN_MOUNT_COULD_NOT_BUILD_A_RUNTIME_FOR_SIGTERM_META: Metadata<'static> =
    Metadata::new(
        "client.gran.mount.could.not.build.a.runtime.for.sigterm",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message"],
            Identifier(&GRAN_MOUNT_COULD_NOT_BUILD_A_RUNTIME_FOR_SIGTERM_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static GRAN_MOUNT_COULD_NOT_REGISTER_A_SIGTERM_HANDLER_THIS_SITE: DefaultCallsite =
    DefaultCallsite::new(&GRAN_MOUNT_COULD_NOT_REGISTER_A_SIGTERM_HANDLER_THIS_META);
pub(super) static GRAN_MOUNT_COULD_NOT_REGISTER_A_SIGTERM_HANDLER_THIS_META: Metadata<'static> =
    Metadata::new(
        "client.gran.mount.could.not.register.a.sigterm.handler.this",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message"],
            Identifier(&GRAN_MOUNT_COULD_NOT_REGISTER_A_SIGTERM_HANDLER_THIS_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static GRAN_MOUNT_DETACH_TARGET_UNAVAILABLE_LAZY_DETACH_CANNOT_BE_SITE: DefaultCallsite =
    DefaultCallsite::new(&GRAN_MOUNT_DETACH_TARGET_UNAVAILABLE_LAZY_DETACH_CANNOT_BE_META);
pub(super) static GRAN_MOUNT_DETACH_TARGET_UNAVAILABLE_LAZY_DETACH_CANNOT_BE_META: Metadata<
    'static,
> = Metadata::new(
    "client.gran.mount.detach.target.unavailable.lazy.detach.cannot.be",
    "granary_client::event",
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message", "error"],
        Identifier(&GRAN_MOUNT_DETACH_TARGET_UNAVAILABLE_LAZY_DETACH_CANNOT_BE_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static GRAN_MOUNT_RECEIVED_SIGNAL_UNMOUNTING_SITE: DefaultCallsite =
    DefaultCallsite::new(&GRAN_MOUNT_RECEIVED_SIGNAL_UNMOUNTING_META);
pub(super) static GRAN_MOUNT_RECEIVED_SIGNAL_UNMOUNTING_META: Metadata<'static> = Metadata::new(
    "client.gran.mount.received.signal.unmounting",
    "granary_client::event",
    Level::INFO,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message", "signal"],
        Identifier(&GRAN_MOUNT_RECEIVED_SIGNAL_UNMOUNTING_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static GRAN_MOUNT_THE_FUSE_SESSION_ENDED_WITH_AN_ERROR_SITE: DefaultCallsite =
    DefaultCallsite::new(&GRAN_MOUNT_THE_FUSE_SESSION_ENDED_WITH_AN_ERROR_META);
pub(super) static GRAN_MOUNT_THE_FUSE_SESSION_ENDED_WITH_AN_ERROR_META: Metadata<'static> =
    Metadata::new(
        "client.gran.mount.the.fuse.session.ended.with.an.error",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "error"],
            Identifier(&GRAN_MOUNT_THE_FUSE_SESSION_ENDED_WITH_AN_ERROR_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static GRAN_MOUNT_THE_FUSE_SESSION_DID_NOT_END_AFTER_ITS_UNMOUNT_SITE: DefaultCallsite =
    DefaultCallsite::new(&GRAN_MOUNT_THE_FUSE_SESSION_DID_NOT_END_AFTER_ITS_UNMOUNT_META);
pub(super) static GRAN_MOUNT_THE_FUSE_SESSION_DID_NOT_END_AFTER_ITS_UNMOUNT_META: Metadata<
    'static,
> = Metadata::new(
    MOUNT_SESSION_DID_NOT_END,
    "granary_client::event",
    Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message", "listed", "connection"],
        Identifier(&GRAN_MOUNT_THE_FUSE_SESSION_DID_NOT_END_AFTER_ITS_UNMOUNT_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static GRAN_MOUNT_THE_FUSE_SESSION_THREAD_PANICKED_SITE: DefaultCallsite =
    DefaultCallsite::new(&GRAN_MOUNT_THE_FUSE_SESSION_THREAD_PANICKED_META);
pub(super) static GRAN_MOUNT_THE_FUSE_SESSION_THREAD_PANICKED_META: Metadata<'static> =
    Metadata::new(
        "client.gran.mount.the.fuse.session.thread.panicked",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message"],
            Identifier(&GRAN_MOUNT_THE_FUSE_SESSION_THREAD_PANICKED_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static GRAN_MOUNT_COULD_NOT_CAPTURE_THE_MOUNT_IDENTITY_SITE: DefaultCallsite =
    DefaultCallsite::new(&GRAN_MOUNT_COULD_NOT_CAPTURE_THE_MOUNT_IDENTITY_META);
pub(super) static GRAN_MOUNT_COULD_NOT_CAPTURE_THE_MOUNT_IDENTITY_META: Metadata<'static> =
    Metadata::new(
        "client.gran.mount.could.not.capture.the.mount.identity",
        "granary_client::event",
        Level::WARN,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message", "error"],
            Identifier(&GRAN_MOUNT_COULD_NOT_CAPTURE_THE_MOUNT_IDENTITY_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
static GRAN_MOUNT_THE_FUSE_SESSION_ENDED_ECONNABORTED_RACING_ITS_UNMOUNT_SITE: DefaultCallsite =
    DefaultCallsite::new(&GRAN_MOUNT_THE_FUSE_SESSION_ENDED_ECONNABORTED_RACING_ITS_UNMOUNT_META);
pub(super) static GRAN_MOUNT_THE_FUSE_SESSION_ENDED_ECONNABORTED_RACING_ITS_UNMOUNT_META: Metadata<
    'static,
> = Metadata::new(
    "client.gran.mount.the.fuse.session.ended.econnaborted.racing.its.unmount",
    "granary_client::event",
    Level::DEBUG,
    Some(file!()),
    Some(line!()),
    Some(module_path!()),
    FieldSet::new(
        &["event", "message"],
        Identifier(&GRAN_MOUNT_THE_FUSE_SESSION_ENDED_ECONNABORTED_RACING_ITS_UNMOUNT_SITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static SYNC_REGISTRATION_TIMING_SAMPLE_UNAVAILABLE_SITE: DefaultCallsite =
    DefaultCallsite::new(&SYNC_REGISTRATION_TIMING_SAMPLE_UNAVAILABLE_META);
pub(super) static SYNC_REGISTRATION_TIMING_SAMPLE_UNAVAILABLE_META: Metadata<'static> =
    Metadata::new(
        "client.sync.registration.timing.sample.unavailable",
        "granary_client::event",
        Level::DEBUG,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(
            &["event", "message"],
            Identifier(&SYNC_REGISTRATION_TIMING_SAMPLE_UNAVAILABLE_SITE),
        ),
        tracing::metadata::Kind::EVENT,
    );
pub(in crate::observe::boundary) static SITES: &[&Metadata<'static>] = &[
    &CACHE_JOURNAL_IS_BROKEN_AFTER_A_FAILED_REOPEN_MID_META,
    &CACHE_JOURNAL_FLUSH_FAILED_RECORDS_STAY_BUFFERED_META,
    &CACHE_COMPACTION_FAILED_JOURNAL_LEFT_UNCOMPACTED_META,
    &CACHE_JOURNAL_BUFFER_EXCEEDED_ITS_CAP_UNDER_SUSTAINED_FREE_META,
    &CACHE_JOURNAL_FLUSH_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META,
    &CACHE_COMPACTION_REFUSED_BY_THE_FREE_SPACE_WATERMARK_SNAPSHOT_META,
    &CACHE_COMPACTION_REFUSED_BY_THE_FREE_SPACE_WATERMARK_BEFORE_META,
    &CACHE_EVICTION_FOUND_NOTHING_LEFT_TO_EVICT_THE_INSERT_META,
    &CACHE_INSERT_THE_OBJECT_PATH_HAS_NO_FANOUT_PARENT_META,
    &CACHE_INSERT_REFUSED_THE_OBJECT_FANOUT_IS_NOT_A_META,
    &CACHE_INSERT_DECLINED_A_DIRECTORY_OCCUPIES_THE_OBJECT_PATH_META,
    &CACHE_INSERT_A_FOREIGN_ENTRY_SITS_AT_THE_OBJECT_META,
    &CACHE_INSERT_FAILED_TO_INSPECT_THE_OBJECT_PATH_META,
    &CACHE_INSERT_REFUSED_OBJECT_IS_LARGER_THAN_THE_WHOLE_META,
    &CACHE_INSERT_FAILED_TO_STAGE_THE_OBJECT_NOTHING_WAS_META,
    &CACHE_INSERT_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META,
    &CACHE_INSERT_FAILED_TO_CREATE_ITS_FANOUT_DIRECTORY_META,
    &CACHE_INSERT_FAILED_TO_WRITE_THE_OBJECT_META,
    &CACHE_INSERT_OBJECT_TOO_LARGE_TO_INDEX_THE_FILE_META,
    &CACHE_ROOT_WRITE_SKIPPED_THE_ROOT_PATH_HAS_NO_META,
    &CACHE_ROOT_WRITE_SKIPPED_THE_VOLUME_DIRECTORY_IS_NOT_META,
    &CACHE_ROOT_WRITE_SKIPPED_A_DIRECTORY_OCCUPIES_THE_DESTINATION_META,
    &CACHE_ROOT_WRITE_A_FOREIGN_ENTRY_SITS_AT_THE_META,
    &CACHE_ROOT_WRITE_SKIPPED_THE_DESTINATION_COULD_NOT_BE_META,
    &CACHE_ROOT_WRITE_REFUSED_BY_THE_FREE_SPACE_WATERMARK_META,
    &CACHE_ROOT_WRITE_FAILED_TO_CREATE_ITS_VOLUME_DIRECTORY_META,
    &CACHE_ROOT_WRITE_FAILED_META,
    &ANCHOR_FLOOR_CANDIDATE_IS_AN_ABSENT_CLASS_SEQ_REFUSING_META,
    &HINT_TOKEN_IS_EMPTY_AN_ETAG_LESS_BACKEND_RETAINING_META,
    &HINT_IS_UNPERSISTABLE_TOKEN_BYTES_LENGTH_STAMP_SIGN_OR_META,
    &CACHE_ANCHOR_WRITE_FAILED_TO_CREATE_ITS_DIRECTORY_META,
    &CACHE_ANCHOR_WRITE_FAILED_META,
    &MOUNT_ANCHOR_FLOOR_CANDIDATE_IS_AN_ABSENT_CLASS_SEQ_META,
    &CACHE_ROOT_EVICTION_SKIPPED_THE_ROOT_PATH_HAS_NO_META,
    &CACHE_ROOT_EVICTION_SKIPPED_THE_VOLUME_DIRECTORY_IS_NOT_META,
    &CACHE_ROOT_EVICTION_FAILED_TO_REMOVE_THE_FILE_META,
    &CACHE_GUARD_PRESENT_AT_OPEN_THE_PREVIOUS_WRITER_DID_META,
    &CACHE_LOCK_HELD_BY_ANOTHER_PROCESS_OPENING_READ_ONLY_META,
    &CACHE_READ_REFUSED_THE_OBJECT_FANOUT_IS_NOT_A_META,
    &CACHE_OBJECT_FAILED_HASH_VERIFICATION_UNLINKING_AND_EVICTING_META,
    &CACHE_OBJECT_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_AS_META,
    &CACHED_ROOT_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_AS_META,
    &CACHE_MAINTAIN_JOURNAL_FLUSH_FAILED_SKIPPING_COMPACTION_THIS_CYCLE_META,
    &CACHE_MAINTAIN_COMPACTION_FAILED_META,
    &SET_IN_THE_ENVIRONMENT_AND_IGNORED_THE_DIRECT_S3_META,
    &WIRE_SNAPSHOT_PUBLISH_THE_TEMP_FILE_COULD_NOT_BE_META,
    &A_CACHE_DIR_IS_PRESENT_BUT_A_TRANSPORT_DOWN_META,
    &THE_TRANSPORT_GAVE_NO_ANSWER_FALLING_BACK_TO_THE_META,
    &STORE_AN_OBJECT_PATH_HAS_NO_FANOUT_PARENT_REPORTING_META,
    &STORE_AN_OBJECT_FANOUT_IS_NOT_A_REAL_DIRECTORY_META,
    &STORE_AN_OBJECT_LEAF_IS_NOT_A_REGULAR_FILE_META,
    &STORE_AN_OBJECT_LEAF_COULD_NOT_BE_CLASSIFIED_REPORTING_META,
    &STORE_PUT_THE_OBJECT_FANOUT_IS_NOT_A_REAL_META,
    &STORE_PUT_AN_OBJECT_LEAF_IS_NOT_A_REGULAR_META,
    &STORE_GET_THE_OBJECT_FANOUT_IS_NOT_A_REAL_META,
    &STORE_ESTABLISHED_OPEN_TXN_IS_NOT_A_REAL_DIRECTORY_META,
    &STORE_ESTABLISHED_OPEN_AN_ORPHANED_TXN_ENTRY_COULD_NOT_META,
    &STORE_ESTABLISHED_OPEN_SWEPT_ORPHANED_TXN_STAGING_FILES_META,
    &SEAM_ATTEMPT_FAILED_RETRYING_ONCE_META,
    &WRITABLE_SHUTDOWN_COORDINATION_FAILED_META,
    &MOUNT_SESSION_SHUTDOWN_CLOSING_THE_CACHE_FAILED_THE_CRASH_META,
    &MOUNT_TEARDOWN_READ_PATH_COUNTERS_FOR_THE_READ_PHASE_META,
    &MOUNT_SESSION_DROP_CLOSING_THE_CACHE_FAILED_THE_CRASH_META,
    &CACHE_ANCHOR_FILE_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_META,
    &CACHE_ANCHOR_FILE_FAILED_STRICT_PARSE_TREATING_IT_AS_META,
    &MOUNT_ANCHOR_FILE_CARRIES_A_HINT_LINE_WHICH_ITS_META,
    &REFUSING_TO_UNLINK_AN_OBJECT_PATH_THAT_HAS_NO_META,
    &REFUSING_TO_UNLINK_AN_OBJECT_THROUGH_A_FOREIGN_FANOUT_META,
    &REFUSING_TO_UNLINK_AN_OBJECT_UNDER_A_FANOUT_THAT_META,
    &AN_OBJECT_LEAF_COULD_NOT_BE_UNLINKED_IT_STAYS_META,
    &COLD_REBUILD_WALK_SKIPPING_A_NON_DIGEST_FILE_NAME_META,
    &COLD_REBUILD_WALK_SKIPPING_A_FILE_WHOSE_NAME_DOES_META,
    &COLD_REBUILD_WALK_SKIPPING_AN_ENTRY_WHOSE_METADATA_COULD_META,
    &COLD_REBUILD_WALK_SKIPPING_A_NON_REGULAR_FILE_ENTRY_META,
    &COLD_REBUILD_WALK_SKIPPING_AN_OVERSIZED_FOREIGN_FILE_META,
    &COLD_REBUILD_WALK_SKIPPING_A_SIZE_THAT_CANNOT_FIT_META,
    &COLD_REBUILD_WALK_SKIPPING_A_NON_FANOUT_ENTRY_UNDER_META,
    &COLD_REBUILD_WALK_SKIPPING_A_FANOUT_ENTRY_WHOSE_TYPE_META,
    &COLD_REBUILD_WALK_SKIPPING_A_NON_DIRECTORY_ENTRY_UNDER_META,
    &COLD_REBUILD_WALK_THE_ADOPTION_CAP_WAS_REACHED_THE_META,
    &COLD_REBUILD_WALK_SNAPSHOT_REWRITE_AND_JOURNAL_RESET_REFUSED_META,
    &CACHE_INDEX_FILE_EXCEEDS_THE_SIZE_BOUND_TREATING_IT_META,
    &CACHE_INDEX_FILE_GREW_PAST_THE_SIZE_BOUND_BETWEEN_META,
    &CACHE_SNAPSHOT_PRESENT_WITH_NO_JOURNAL_A_CREATION_CRASH_META,
    &CACHE_WRITER_OPEN_AN_ORPHANED_TXN_ENTRY_COULD_NOT_META,
    &CACHE_WRITER_OPEN_SWEPT_ORPHANED_TXN_STAGING_FILES_META,
    &STRUCTURE_WALK_META,
    &GRAN_MOUNT_UNMOUNT_FAILED_FALLING_BACK_TO_A_LAZY_META,
    &GRAN_MOUNT_THE_MOUNT_WAS_LAZILY_DETACHED_MNT_DETACH_META,
    &GRAN_MOUNT_BOTH_THE_PLAIN_UNMOUNT_AND_THE_MNT_META,
    &GRAN_MOUNT_A_SIGNAL_READINESS_REPORT_NEVER_ARRIVED_BEFORE_META,
    &GRAN_MOUNT_A_CACHED_ROOT_AND_THE_WIRE_ROOT_META,
    &GRAN_MOUNT_COULD_NOT_BUILD_A_RUNTIME_FOR_SIGINT_META,
    &GRAN_MOUNT_COULD_NOT_REGISTER_A_SIGINT_HANDLER_THIS_META,
    &GRAN_MOUNT_THE_SIGINT_STREAM_ENDED_WITHOUT_DELIVERING_A_META,
    &GRAN_MOUNT_COULD_NOT_BUILD_A_RUNTIME_FOR_SIGTERM_META,
    &GRAN_MOUNT_COULD_NOT_REGISTER_A_SIGTERM_HANDLER_THIS_META,
    &GRAN_MOUNT_DETACH_TARGET_UNAVAILABLE_LAZY_DETACH_CANNOT_BE_META,
    &GRAN_MOUNT_RECEIVED_SIGNAL_UNMOUNTING_META,
    &GRAN_MOUNT_THE_FUSE_SESSION_ENDED_WITH_AN_ERROR_META,
    &GRAN_MOUNT_THE_FUSE_SESSION_DID_NOT_END_AFTER_ITS_UNMOUNT_META,
    &GRAN_MOUNT_THE_FUSE_SESSION_THREAD_PANICKED_META,
    &GRAN_MOUNT_COULD_NOT_CAPTURE_THE_MOUNT_IDENTITY_META,
    &GRAN_MOUNT_THE_FUSE_SESSION_ENDED_ECONNABORTED_RACING_ITS_UNMOUNT_META,
    &SYNC_REGISTRATION_TIMING_SAMPLE_UNAVAILABLE_META,
];
pub(in crate::observe::boundary) fn numeric(name: &str) -> bool {
    matches!(
        name,
        "admits"
            | "adoption_cap"
            | "cache_hits"
            | "cache_misses"
            | "candidate"
            | "dropped"
            | "dropped_bytes"
            | "dropped_records"
            | "hints"
            | "inflight_high_water"
            | "len"
            | "needs"
            | "origin_requests"
            | "origin_requests_total"
            | "origin_sheds"
            | "pool_len"
            | "pool_used"
            | "quota"
            | "round"
            | "seq"
            | "skipped"
            | "swept"
            | "total_bytes"
            | "wants_bin"
            | "wants_meta"
            | "wants_total"
            | "window"
    )
}
#[expect(
    clippy::too_many_lines,
    reason = "exhaustive schema domains enumerate every admitted diagnostic scalar"
)]
pub(in crate::observe::boundary) fn domain(
    meta: &Metadata<'_>,
    name: &str,
    text: &str,
) -> Option<bool> {
    Some(match meta.name() {
        "client.cache.journal.is.broken.after.a.failed.reopen.mid" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache journal is broken after a failed reopen mid-session; refusing to record further journal entries into the orphaned file. The in-memory index stays correct for this session and the objects on disk stay hash-verifiable; the next Cache::open will rebuild the index from the snapshot and lose journal records written since the failure."
            }
            _ => false,
        },
        "client.cache.journal.flush.failed.records.stay.buffered" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache journal flush failed; records stay buffered",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.cache.compaction.failed.journal.left.uncompacted" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache compaction failed; journal left uncompacted",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.cache.journal.buffer.exceeded.its.cap.under.sustained.free" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache journal buffer exceeded its cap under sustained free-space refusal; dropping buffered records. The OBJECTS on disk stay correct and hash-verifiable; the INDEX now under-counts them, and nothing repairs that automatically — ordinary reads do not adopt a healthy unindexed object, and `gran verify` reports the divergence without fixing it. A cold rebuild (or removing the cache directory) is what resolves it."
            }
            _ => false,
        },
        "client.cache.journal.flush.refused.by.the.free.space.watermark" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache journal flush refused by the free-space watermark; records stay buffered"
            }
            _ => false,
        },
        "client.cache.compaction.refused.by.the.free.space.watermark.snapshot" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache compaction refused by the free-space watermark; snapshot left stale"
            }
            _ => false,
        },
        "client.cache.compaction.refused.by.the.free.space.watermark.before" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache compaction refused by the free-space watermark before truncating the journal; the snapshot already advanced, so the next open safely replays a stale-but-idempotent journal"
            }
            _ => false,
        },
        "client.cache.eviction.found.nothing.left.to.evict.the.insert" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache eviction found nothing left to evict; the insert that needed the room is declined rather than writing over quota"
            }
            _ => false,
        },
        "client.cache.insert.the.object.path.has.no.fanout.parent" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache insert: the object path has no fanout parent",
            "id" => text == "<object>",
            _ => false,
        },
        "client.cache.insert.refused.the.object.fanout.is.not.a" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache insert refused: the object fanout is not a real directory",
            "id" => text == "<object>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.cache.insert.declined.a.directory.occupies.the.object.path" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache insert declined: a DIRECTORY occupies the object path, which no write can replace; nothing is evicted and nothing is written"
            }
            "id" => text == "<object>",
            "path" => text == "<file>",
            _ => false,
        },
        "client.cache.insert.a.foreign.entry.sits.at.the.object" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache insert: a foreign entry sits at the object path; if this write goes through, the atomic rename replaces that NAME (never what it points at) — the size, eviction and watermark gates below can still decline it"
            }
            "id" => text == "<object>",
            "path" => text == "<file>",
            _ => false,
        },
        "client.cache.insert.failed.to.inspect.the.object.path" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache insert failed to inspect the object path",
            "id" => text == "<object>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.cache.insert.refused.object.is.larger.than.the.whole" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache insert refused: object is larger than the whole quota",
            "id" => text == "<object>",
            _ => false,
        },
        "client.cache.insert.failed.to.stage.the.object.nothing.was" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache insert failed to stage the object; nothing was evicted, and any staged bytes were removed or left under txn/ for the next sweep"
            }
            "id" => text == "<object>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.cache.insert.refused.by.the.free.space.watermark" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache insert refused by the free-space watermark",
            "id" => text == "<object>",
            _ => false,
        },
        "client.cache.insert.failed.to.create.its.fanout.directory" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache insert failed to create its fanout directory",
            "id" => text == "<object>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.cache.insert.failed.to.write.the.object" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache insert failed to write the object",
            "id" => text == "<object>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.cache.insert.object.too.large.to.index.the.file" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache insert: object too large to index; the file is cached but stays UNINDEXED (the single-object crash window's own shape; gran verify REPORTS it, and nothing re-indexes it short of a cold rebuild)"
            }
            "id" => text == "<object>",
            _ => false,
        },
        "client.cache.root.write.skipped.the.root.path.has.no" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache root write skipped: the root path has no volume parent",
            "volume" => text == "<volume>",
            _ => false,
        },
        "client.cache.root.write.skipped.the.volume.directory.is.not" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache root write skipped: the volume directory is not a real directory, so nothing below it describes this cache"
            }
            "volume" => text == "<volume>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.cache.root.write.skipped.a.directory.occupies.the.destination" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache root write skipped: a DIRECTORY occupies the destination, which no write can replace"
            }
            "volume" => text == "<volume>",
            "path" => text == "<file>",
            _ => false,
        },
        "client.cache.root.write.a.foreign.entry.sits.at.the" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache root write: a foreign entry sits at the destination; if this write goes through, the atomic rename replaces that NAME (never what it points at) — the free-space watermark below can still decline it"
            }
            "volume" => text == "<volume>",
            "path" => text == "<file>",
            _ => false,
        },
        "client.cache.root.write.skipped.the.destination.could.not.be" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache root write skipped: the destination could not be classified, so put-if-absent cannot know whether a root is already there"
            }
            "volume" => text == "<volume>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.cache.root.write.refused.by.the.free.space.watermark" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache root write refused by the free-space watermark",
            "volume" => text == "<volume>",
            _ => false,
        },
        "client.cache.root.write.failed.to.create.its.volume.directory" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache root write failed to create its volume directory",
            "volume" => text == "<volume>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.cache.root.write.failed" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache root write failed",
            "volume" => text == "<volume>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.anchor.floor.candidate.is.an.absent.class.seq.refusing" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "anchor floor candidate is an absent-class seq; refusing to persist it"
            }
            "volume" => text == "<volume>",
            _ => false,
        },
        "client.hint.token.is.empty.an.etag.less.backend.retaining" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "hint token is empty (an ETag-less backend); retaining the prior persisted hint — expected, not a warning"
            }
            "volume" => text == "<volume>",
            _ => false,
        },
        "client.hint.is.unpersistable.token.bytes.length.stamp.sign.or" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "hint is unpersistable (token bytes/length, stamp sign, or absent-class seq); retaining the prior persisted hint instead — the floor still writes"
            }
            "volume" => text == "<volume>",
            _ => false,
        },
        "client.cache.anchor.write.failed.to.create.its.directory" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache anchor write failed to create its directory",
            "volume" => text == "<volume>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.cache.anchor.write.failed" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache anchor write failed",
            "volume" => text == "<volume>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.mount.anchor.floor.candidate.is.an.absent.class.seq" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "mount anchor floor candidate is an absent-class seq; refusing to persist it"
            }
            "volume" => text == "<volume>",
            _ => false,
        },
        "client.cache.root.eviction.skipped.the.root.path.has.no" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache root eviction skipped: the root path has no volume parent",
            "volume" => text == "<volume>",
            _ => false,
        },
        "client.cache.root.eviction.skipped.the.volume.directory.is.not" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache root eviction skipped: the volume directory is not a real directory"
            }
            "volume" => text == "<volume>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.cache.root.eviction.failed.to.remove.the.file" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache root eviction failed to remove the file",
            "volume" => text == "<volume>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.cache.guard.present.at.open.the.previous.writer.did" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache guard present at open: the previous writer did not close cleanly; replaying the journal to reconcile"
            }
            "root" => text == "<cache-root>",
            _ => false,
        },
        "client.cache.lock.held.by.another.process.opening.read.only" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache lock held by another process; opening read-only degraded",
            "root" => text == "<cache-root>",
            _ => false,
        },
        "client.cache.read.refused.the.object.fanout.is.not.a" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache read refused: the object fanout is not a real directory, so nothing below it belongs to this cache"
            }
            "id" => text == "<object>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.cache.object.failed.hash.verification.unlinking.and.evicting" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache object failed hash verification; unlinking and evicting",
            "id" => text == "<object>",
            _ => false,
        },
        "client.cache.object.exceeds.the.size.bound.treating.it.as" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache object exceeds the size bound; treating it as a miss and unlinking"
            }
            "id" => text == "<object>",
            _ => false,
        },
        "client.cached.root.exceeds.the.size.bound.treating.it.as" => match name {
            "event" => text == meta.name(),
            "message" => text == "cached root exceeds the size bound; treating it as a miss",
            "volume" => text == "<volume>",
            _ => false,
        },
        "client.cache.maintain.journal.flush.failed.skipping.compaction.this.cycle" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache maintain: journal flush failed; skipping compaction this cycle"
            }
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.cache.maintain.compaction.failed" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache maintain: compaction failed",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.set.in.the.environment.and.ignored.the.direct.s3" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "set in the environment and ignored: the direct-S3 route connects directly"
            }
            "variable" => matches!(
                text,
                "HTTP_PROXY"
                    | "HTTPS_PROXY"
                    | "ALL_PROXY"
                    | "NO_PROXY"
                    | "http_proxy"
                    | "https_proxy"
                    | "all_proxy"
                    | "no_proxy"
                    | "other"
            ),
            _ => false,
        },
        "client.wire.snapshot.publish.the.temp.file.could.not.be" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "wire-snapshot publish: the temp file could not be removed after a successful hard_link — the destination is published and correct; the temp name is a leftover, not a failure"
            }
            "from" | "to" => text == "<file>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.a.cache.dir.is.present.but.a.transport.down" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "a cache dir is present, but a transport-down degraded serve requires the volume's root key to verify what it returns; this reader holds none, so the transport failure is returned unchanged"
            }
            "volume" => text == "<volume>",
            _ => false,
        },
        "client.the.transport.gave.no.answer.falling.back.to.the" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "the transport gave no answer; falling back to the cache's last verified head for this volume (possibly stale) — the read fails closed if the cache cannot fully satisfy it"
            }
            "volume" => text == "<volume>",
            "age" => text == "unknown",
            _ => false,
        },
        "client.store.an.object.path.has.no.fanout.parent.reporting" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "store: an object path has no fanout parent; reporting the object absent"
            }
            "path" => text == "<file>",
            _ => false,
        },
        "client.store.an.object.fanout.is.not.a.real.directory" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "store: an object fanout is not a real directory; reporting the object absent"
            }
            "fanout" => text == "<directory>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.store.an.object.leaf.is.not.a.regular.file" => match name {
            "event" => text == meta.name(),
            "message" => text == "store: an object leaf is not a regular file; reporting it absent",
            "path" => text == "<file>",
            _ => false,
        },
        "client.store.an.object.leaf.could.not.be.classified.reporting" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "store: an object leaf could not be classified; reporting it absent"
            }
            "path" => text == "<file>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.store.put.the.object.fanout.is.not.a.real" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "store put: the object fanout is not a real directory; refusing rather than writing or classifying through it"
            }
            "fanout" => text == "<directory>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.store.put.an.object.leaf.is.not.a.regular" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "store put: an object leaf is not a regular file; refusing rather than renaming over it"
            }
            "path" => text == "<file>",
            _ => false,
        },
        "client.store.get.the.object.fanout.is.not.a.real" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "store get: the object fanout is not a real directory; refusing rather than reading through it"
            }
            "fanout" => text == "<directory>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.store.established.open.txn.is.not.a.real.directory" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "store established open: txn/ is not a real directory (symlink or other); refusing the open rather than sweeping through it"
            }
            "path" => text == "<directory>",
            _ => false,
        },
        "client.store.established.open.an.orphaned.txn.entry.could.not" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "store established open: an orphaned txn/ entry could not be removed; skipping it — the staging NAME it occupies stays wedged for the pid that would use it"
            }
            "path" => text == "<directory>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.store.established.open.swept.orphaned.txn.staging.files" => match name {
            "event" => text == meta.name(),
            "message" => text == "store established open: swept orphaned txn/ staging files",
            _ => false,
        },
        "client.seam.attempt.failed.retrying.once" => match name {
            "event" => text == meta.name(),
            "message" => text == "seam attempt failed; retrying once",
            "seam" => matches!(
                text,
                "put_meta"
                    | "get_meta"
                    | "put_bin"
                    | "get_bin"
                    | "get_bin_range"
                    | "put_root"
                    | "get_root"
                    | "max_seq"
                    | "read_hint"
                    | "write_hint"
                    | "probe_root"
                    | "other"
            ),
            "class" => matches!(
                text,
                "unsent" | "stream_refused" | "connection_failed" | "not_retryable"
            ),
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.writable.shutdown.coordination.failed" => match name {
            "event" => text == meta.name(),
            "message" => text == "WritableShutdownCoordinationFailed",
            "coordination" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.mount.session.shutdown.closing.the.cache.failed.the.crash" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "mount session shutdown: closing the cache failed; the crash guard may remain"
            }
            "root" => text == "<cache-root>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.mount.teardown.read.path.counters.for.the.read.phase" => match name {
            "event" => text == meta.name(),
            "message" => text == "mount teardown: read-path counters for the read phase",
            "via" => matches!(text, "shutdown" | "drop"),
            _ => false,
        },
        "client.mount.session.drop.closing.the.cache.failed.the.crash" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "mount session drop: closing the cache failed; the crash guard may remain"
            }
            "root" => text == "<cache-root>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.cache.anchor.file.exceeds.the.size.bound.treating.it" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache anchor file exceeds the size bound; treating it as absent",
            "volume" => text == "<volume>",
            _ => false,
        },
        "client.cache.anchor.file.failed.strict.parse.treating.it.as" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache anchor file failed strict parse; treating it as absent",
            "volume" => text == "<volume>",
            _ => false,
        },
        "client.mount.anchor.file.carries.a.hint.line.which.its" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "mount anchor file carries a hint line, which its grammar forbids; treating it as absent"
            }
            "volume" => text == "<volume>",
            _ => false,
        },
        "client.refusing.to.unlink.an.object.path.that.has.no" => match name {
            "event" => text == meta.name(),
            "message" => text == "refusing to unlink an object path that has no fanout parent",
            "path" => text == "<file>",
            "context" => matches!(
                text,
                "cache evict" | "cache get: hash mismatch" | "cache evict oversized" | "other"
            ),
            _ => false,
        },
        "client.refusing.to.unlink.an.object.through.a.foreign.fanout" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "refusing to unlink an object through a foreign fanout directory; nothing on disk is touched"
            }
            "fanout" => text == "<directory>",
            "context" => matches!(
                text,
                "cache evict" | "cache get: hash mismatch" | "cache evict oversized" | "other"
            ),
            _ => false,
        },
        "client.refusing.to.unlink.an.object.under.a.fanout.that" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "refusing to unlink an object under a fanout that could not be classified; nothing on disk is touched and the object is still there"
            }
            "fanout" => text == "<directory>",
            "error" => FailureClass::parse(text).is_some(),
            "context" => matches!(
                text,
                "cache evict" | "cache get: hash mismatch" | "cache evict oversized" | "other"
            ),
            _ => false,
        },
        "client.an.object.leaf.could.not.be.unlinked.it.stays" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "an object leaf could not be unlinked; it stays on disk as an unindexed residue, and this cache's accounting under-counts it until a cold rebuild re-adopts it or an operator removes it"
            }
            "path" => text == "<file>",
            "error" => FailureClass::parse(text).is_some(),
            "context" => matches!(
                text,
                "cache evict" | "cache get: hash mismatch" | "cache evict oversized" | "other"
            ),
            _ => false,
        },
        "client.cold.rebuild.walk.skipping.a.non.digest.file.name" => match name {
            "event" => text == meta.name(),
            "message" => text == "cold rebuild walk: skipping a non-digest file name",
            "name" => text == "<name>",
            _ => false,
        },
        "client.cold.rebuild.walk.skipping.a.file.whose.name.does" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cold rebuild walk: skipping a file whose name does not match its fanout directory"
            }
            "name" | "dir" => text == "<name>",
            _ => false,
        },
        "client.cold.rebuild.walk.skipping.an.entry.whose.metadata.could" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cold rebuild walk: skipping an entry whose metadata could not be read"
            }
            "path" => text == "<file>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.cold.rebuild.walk.skipping.a.non.regular.file.entry" => match name {
            "event" => text == meta.name(),
            "message" => text == "cold rebuild walk: skipping a non-regular-file entry",
            "path" => text == "<file>",
            _ => false,
        },
        "client.cold.rebuild.walk.skipping.an.oversized.foreign.file" => match name {
            "event" => text == meta.name(),
            "message" => text == "cold rebuild walk: skipping an oversized foreign file",
            "path" => text == "<file>",
            _ => false,
        },
        "client.cold.rebuild.walk.skipping.a.size.that.cannot.fit" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cold rebuild walk: skipping a size that cannot fit the index format"
            }
            "path" => text == "<file>",
            _ => false,
        },
        "client.cold.rebuild.walk.skipping.a.non.fanout.entry.under" => match name {
            "event" => text == meta.name(),
            "message" => text == "cold rebuild walk: skipping a non-fanout entry under objects/",
            "name" => text == "<name>",
            _ => false,
        },
        "client.cold.rebuild.walk.skipping.a.fanout.entry.whose.type" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cold rebuild walk: skipping a fanout entry whose type could not be read"
            }
            "path" => text == "<file>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.cold.rebuild.walk.skipping.a.non.directory.entry.under" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cold rebuild walk: skipping a non-directory entry under objects/ (a symlink to one included)"
            }
            "path" => text == "<file>",
            _ => false,
        },
        "client.cold.rebuild.walk.the.adoption.cap.was.reached.the" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cold rebuild walk: the adoption cap was reached; the dropped entries' files stay on disk and stay hash-verifiable by path, and a get() for one still HITS — but it is not re-indexed by that read (touch_id no-ops for an untracked id and insert() returns early because the file exists), so it stays outside quota and LRU accounting. gran verify reports it as `adopted`; nothing repairs it short of raising the cap or removing the cache directory."
            }
            _ => false,
        },
        "client.cold.rebuild.walk.snapshot.rewrite.and.journal.reset.refused" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cold rebuild walk: snapshot rewrite and journal reset refused together by the free-space watermark; neither was touched and the next open will simply walk again"
            }
            _ => false,
        },
        "client.cache.index.file.exceeds.the.size.bound.treating.it" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache index file exceeds the size bound; treating it as untrustworthy"
            }
            "path" => text == "<file>",
            "what" => matches!(text, "snapshot" | "journal" | "other"),
            _ => false,
        },
        "client.cache.index.file.grew.past.the.size.bound.between" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache index file grew past the size bound between the stat and the read; treating it as untrustworthy"
            }
            "path" => text == "<file>",
            "what" => matches!(text, "snapshot" | "journal" | "other"),
            _ => false,
        },
        "client.cache.snapshot.present.with.no.journal.a.creation.crash" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache snapshot present with no journal: a creation-crash window from the last compaction; recreating an empty journal"
            }
            "root" => text == "<cache-root>",
            _ => false,
        },
        "client.cache.writer.open.an.orphaned.txn.entry.could.not" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "cache writer open: an orphaned txn/ entry could not be removed; skipping it — the staging NAME it occupies stays wedged for the pid that would use it"
            }
            "path" => text == "<directory>",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.cache.writer.open.swept.orphaned.txn.staging.files" => match name {
            "event" => text == meta.name(),
            "message" => text == "cache writer open: swept orphaned txn/ staging files",
            _ => false,
        },
        "client.structure.walk" => match name {
            "event" => text == meta.name(),
            "message" => text == "structure walk",
            "outcome" => matches!(text, "done" | "need" | "error"),
            _ => false,
        },
        "client.gran.mount.unmount.failed.falling.back.to.a.lazy" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "gran mount: unmount failed; falling back to a lazy detach — the session thread is presumed wedged (still blocked reading /dev/fuse, since unmounting is what would have let it return) and will NOT be joined — joining a wedged thread is exactly what would hang this coordinator forever"
            }
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.gran.mount.the.mount.was.lazily.detached.mnt.detach" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "gran mount: the mount was lazily detached (MNT_DETACH) after the plain unmount was refused; the FUSE connection itself may still outlive this process until every already-open file on it is closed"
            }
            _ => false,
        },
        "client.gran.mount.both.the.plain.unmount.and.the.mnt" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "gran mount: both the plain unmount and the MNT_DETACH fallback failed; the mount is likely still attached"
            }
            "unmount_error" | "detach_error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.gran.mount.a.signal.readiness.report.never.arrived.before" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "gran mount: a signal-readiness report never arrived before Session::new (the producer thread ended before reporting, most likely a panic); proceeding without waiting for the other one"
            }
            _ => false,
        },
        "client.gran.mount.a.cached.root.and.the.wire.root" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "gran mount: a cached root and the wire root disagreed at open; served the wire root"
            }
            "volume" => text == "<volume>",
            "finding" => text == "<equivocation>",
            _ => false,
        },
        "client.gran.mount.could.not.build.a.runtime.for.sigint" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "gran mount: could not build a runtime for SIGINT handling; this daemon is now deaf to SIGINT (SIGTERM and an external `gran umount` are still live)"
            }
            _ => false,
        },
        "client.gran.mount.could.not.register.a.sigint.handler.this" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "gran mount: could not register a SIGINT handler; this daemon is now deaf to SIGINT (SIGTERM and an external `gran umount` are still live)"
            }
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.gran.mount.the.sigint.stream.ended.without.delivering.a" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "gran mount: the SIGINT stream ended without delivering a signal; this daemon is now deaf to SIGINT (SIGTERM and an external `gran umount` are still live)"
            }
            _ => false,
        },
        "client.gran.mount.could.not.build.a.runtime.for.sigterm" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "gran mount: could not build a runtime for SIGTERM handling; this daemon is now deaf to SIGTERM — under systemd this means TimeoutStopSec then SIGKILL, which skips destroy/Cache::close entirely"
            }
            _ => false,
        },
        "client.gran.mount.could.not.register.a.sigterm.handler.this" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "gran mount: could not register a SIGTERM handler; this daemon is now deaf to SIGTERM — under systemd this means TimeoutStopSec then SIGKILL, which skips destroy/Cache::close entirely"
            }
            _ => false,
        },
        "client.gran.mount.detach.target.unavailable.lazy.detach.cannot.be" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "gran mount: detach target unavailable; lazy detach cannot be attempted"
            }
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.gran.mount.received.signal.unmounting" => match name {
            "event" => text == meta.name(),
            "message" => text == "gran mount: received signal, unmounting",
            "signal" => matches!(text, "SIGINT" | "SIGTERM" | "other"),
            _ => false,
        },
        "client.gran.mount.the.fuse.session.ended.with.an.error" => match name {
            "event" => text == meta.name(),
            "message" => text == "gran mount: the FUSE session ended with an error",
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        MOUNT_SESSION_DID_NOT_END => match name {
            "event" => text == meta.name(),
            "message" => text == SESSION_DID_NOT_END_MESSAGE,
            "listed" => MountListing::ALL
                .iter()
                .any(|member| member.as_str() == text),
            "connection" => FuseConnection::ALL
                .iter()
                .any(|member| member.as_str() == text),
            _ => false,
        },
        "client.gran.mount.the.fuse.session.thread.panicked" => match name {
            "event" => text == meta.name(),
            "message" => text == "gran mount: the FUSE session thread panicked",
            _ => false,
        },
        "client.gran.mount.could.not.capture.the.mount.identity" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "gran mount: could not capture the mount identity; a session end that races its unmount will report a failure"
            }
            "error" => FailureClass::parse(text).is_some(),
            _ => false,
        },
        "client.gran.mount.the.fuse.session.ended.econnaborted.racing.its.unmount" => match name {
            "event" => text == meta.name(),
            "message" => {
                text == "gran mount: the FUSE session ended ECONNABORTED racing its unmount and the mount is gone; a clean end"
            }
            _ => false,
        },
        "client.sync.registration.timing.sample.unavailable" => match name {
            "event" => text == meta.name(),
            "message" => text == "registration timing sample unavailable",
            _ => false,
        },
        _ => return None,
    })
}

/// Ordinary slots come only from the closed schema inventory.
pub(in crate::observe::boundary) fn path_class(
    meta: &Metadata<'_>,
    field: &str,
) -> Option<&'static str> {
    match (meta.name(), field) {
        (
            "client.cache.insert.declined.a.directory.occupies.the.object.path"
            | "client.cache.insert.a.foreign.entry.sits.at.the.object"
            | "client.cache.root.write.skipped.a.directory.occupies.the.destination"
            | "client.cache.root.write.a.foreign.entry.sits.at.the"
            | "client.store.an.object.path.has.no.fanout.parent.reporting"
            | "client.store.an.object.leaf.is.not.a.regular.file"
            | "client.store.an.object.leaf.could.not.be.classified.reporting"
            | "client.store.put.an.object.leaf.is.not.a.regular"
            | "client.refusing.to.unlink.an.object.path.that.has.no"
            | "client.an.object.leaf.could.not.be.unlinked.it.stays"
            | "client.cold.rebuild.walk.skipping.an.entry.whose.metadata.could"
            | "client.cold.rebuild.walk.skipping.a.non.regular.file.entry"
            | "client.cold.rebuild.walk.skipping.an.oversized.foreign.file"
            | "client.cold.rebuild.walk.skipping.a.size.that.cannot.fit"
            | "client.cold.rebuild.walk.skipping.a.fanout.entry.whose.type"
            | "client.cold.rebuild.walk.skipping.a.non.directory.entry.under"
            | "client.cache.index.file.exceeds.the.size.bound.treating.it"
            | "client.cache.index.file.grew.past.the.size.bound.between",
            "path",
        )
        | ("client.wire.snapshot.publish.the.temp.file.could.not.be", "from" | "to") => {
            Some("<file>")
        }
        (
            "client.cache.guard.present.at.open.the.previous.writer.did"
            | "client.cache.lock.held.by.another.process.opening.read.only"
            | "client.mount.session.shutdown.closing.the.cache.failed.the.crash"
            | "client.mount.session.drop.closing.the.cache.failed.the.crash"
            | "client.cache.snapshot.present.with.no.journal.a.creation.crash",
            "root",
        ) => Some("<cache-root>"),
        (
            "client.store.an.object.fanout.is.not.a.real.directory"
            | "client.store.put.the.object.fanout.is.not.a.real"
            | "client.store.get.the.object.fanout.is.not.a.real"
            | "client.refusing.to.unlink.an.object.through.a.foreign.fanout"
            | "client.refusing.to.unlink.an.object.under.a.fanout.that",
            "fanout",
        )
        | (
            "client.store.established.open.txn.is.not.a.real.directory"
            | "client.store.established.open.an.orphaned.txn.entry.could.not"
            | "client.cache.writer.open.an.orphaned.txn.entry.could.not",
            "path",
        ) => Some("<directory>"),
        (
            "client.cold.rebuild.walk.skipping.a.non.digest.file.name"
            | "client.cold.rebuild.walk.skipping.a.non.fanout.entry.under",
            "name",
        )
        | ("client.cold.rebuild.walk.skipping.a.file.whose.name.does", "name" | "dir") => {
            Some("<name>")
        }
        _ => None,
    }
}
