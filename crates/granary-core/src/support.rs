// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Bounded, canonical support formats. Checksums detect corruption; source
//! protection and the selection of exported fields belong to the caller.
//! The version-one export, snapshot and configuration formats are frozen; the
//! support bundle is version one and unfrozen.
pub(crate) mod bundle;
pub use bundle::{
    BUNDLE_ARCHIVE_DERIVED_MAX, BUNDLE_ARCHIVE_MAX, BUNDLE_MANIFEST_DERIVED_MAX,
    BUNDLE_MANIFEST_ENTRIES_MAX, BUNDLE_MANIFEST_MAX, BUNDLE_MEMBERS_MAX, BundleArchive,
    BundleEntry, BundleEntryStatus, BundleKind, BundleManifest, BundleRefusal,
    members::{
        BUNDLE_CACHE_MAX, BUNDLE_CONFIGURATION_MAX, BUNDLE_FAILURES_ENTRIES_MAX,
        BUNDLE_FAILURES_MAX, BUNDLE_LOG_BYTES_MAX, BUNDLE_LOG_RECORD_MAX, BUNDLE_LOG_RECORDS_MAX,
        BUNDLE_LOGS_MAX, BUNDLE_METRICS_MAX, BUNDLE_METRICS_SCHEMA, BUNDLE_OPERATION_KINDS,
        BUNDLE_OVERLAY_MAX, BUNDLE_VERSION_MAX, BundleCache, BundleConfiguration, BundleFailure,
        BundleFailures, BundleHistogram, BundleLogs, BundleMetrics, BundleOverlay, BundleVersion,
    },
    records::{bundle_record_events, bundle_record_keys},
};
mod export;
pub use export::{
    ARCHIVE_MAX, AgeStatus, EntryStatus, ExportEntry, ExportRefusal, LOG_METADATA_MAX,
    MANIFEST_DERIVED_MAX, MANIFEST_ENTRIES_MAX, MANIFEST_MAX, SCAN_NAMES_MAX, SnapshotAge,
    SourceKind, SupportArchive, SupportLogMetadata, SupportManifest,
};
mod snapshot;
#[cfg(test)]
mod tests;
mod types;
use crate::{debug_grant::Incarnation, hash::GrainId, root::VolumeName, sheaf::Timestamp};
pub use snapshot::{SupportGrant, SupportGrantRecord, SupportSnapshot};
use std::collections::BTreeMap;
pub use types::{
    AuthorityProfile, CaptureCounters, EnrollmentSnapshot, ReaderCounters, RefusalReason,
    RefusalSnapshot, SnapshotCounters, SnapshotState, SupportCapture, SupportControls,
    TerminalState, UnavailableReason, VolumeView,
};

/// Full encoded snapshot cap: 8 MiB.
pub const SNAPSHOT_MAX: usize = 8 * 1024 * 1024;
/// Full encoded configuration cap: 32 KiB.
pub const CONFIGURATION_MAX: usize = 32 * 1024;
const SNAPSHOT_KIND: u16 = 0x0201;
const CONFIGURATION_KIND: u16 = 0x0202;
pub(crate) const HEADER_LEN: usize = 8 + 2 + 2 + 4;
pub(crate) const PROFILE_LEN: usize = 2;
pub(crate) const CHECK_LEN: usize = 32;
pub(crate) const TRAILER_LEN: usize = PROFILE_LEN + CHECK_LEN;
pub(crate) const OVERHEAD: usize = HEADER_LEN + TRAILER_LEN;

/// A fixed refusal with no attacker-derived text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupportError(pub &'static str);
impl std::fmt::Display for SupportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for SupportError {}
type Result<T> = std::result::Result<T, SupportError>;
fn require(ok: bool, reason: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(SupportError(reason))
    }
}

/// Owned allowlist retained before configuration and store owners move.
/// No path, key, endpoint, proxy, logging filter or erased store is retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportConfiguration {
    pub incarnation: Incarnation,
    pub authority_profile: AuthorityProfile,
    pub volumes: BTreeMap<VolumeName, u8>,
    pub accept_unsupported_filesystem: bool,
    pub controls: SupportControls,
    pub listen_port: u16,
    /// Authority composition always enables TLS and requires client auth.
    pub tls_enabled: bool,
    pub client_auth_required: bool,
    pub worker_threads: u64,
    pub shutdown_budget_ms: u64,
    pub dispatch_deadline_ms: Option<u64>,
    /// Declared limits for the network store, even when the selected store is memory.
    pub network_dispatch_limit_ms: u64,
    pub network_client_timeout_ms: u64,
}
impl SupportConfiguration {
    /// Canonical encoding with a full-width exact-byte checksum.
    /// # Errors
    /// Refuses any field outside the documented v1 accept set.
    pub fn encode(&self) -> Result<Vec<u8>> {
        seal(CONFIGURATION_KIND, CONFIGURATION_MAX, |t| {
            configuration_fields(t, Some(self))?;
            Ok(())
        })
    }
    /// Bounded verification and decoding; never hashes a re-encoding.
    /// # Errors
    /// Refuses invalid envelopes, checksums, bounds and noncanonical fields.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut t = open(bytes, CONFIGURATION_KIND, CONFIGURATION_MAX)?;
        let value = configuration_fields(&mut t, None)?;
        t.end()?;
        Ok(value)
    }
}
// A single handwritten field walk serves both directions, so validation and
// field order cannot diverge. Decode borrows the verified body; each allocation
// is preceded by a count/name bound and a check that the bytes fit.
struct Tape<'a> {
    input: Option<&'a [u8]>,
    output: Vec<u8>,
}
impl Tape<'_> {
    fn fixed<const N: usize>(&mut self, seed: [u8; N]) -> Result<[u8; N]> {
        if let Some(input) = self.input {
            let (field, rest) = input
                .split_at_checked(N)
                .ok_or(SupportError("truncated support field"))?;
            self.input = Some(rest);
            field
                .try_into()
                .map_err(|_| SupportError("truncated support field"))
        } else {
            self.output.extend_from_slice(&seed);
            Ok(seed)
        }
    }
    fn u8(&mut self, seed: u8) -> Result<u8> {
        Ok(u8::from_be_bytes(self.fixed(seed.to_be_bytes())?))
    }
    fn u16(&mut self, seed: u16) -> Result<u16> {
        Ok(u16::from_be_bytes(self.fixed(seed.to_be_bytes())?))
    }
    fn u32(&mut self, seed: u32) -> Result<u32> {
        Ok(u32::from_be_bytes(self.fixed(seed.to_be_bytes())?))
    }
    fn u64(&mut self, seed: u64) -> Result<u64> {
        Ok(u64::from_be_bytes(self.fixed(seed.to_be_bytes())?))
    }
    fn time(&mut self, seed: Timestamp) -> Result<Timestamp> {
        let value = Timestamp {
            secs: i64::from_be_bytes(self.fixed(seed.secs.to_be_bytes())?),
            nanos: self.u32(seed.nanos)?,
        };
        require(value.is_valid(), "timestamp nanoseconds")?;
        Ok(value)
    }
    fn boolean(&mut self, seed: bool) -> Result<bool> {
        match self.u8(u8::from(seed))? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(SupportError("boolean tag")),
        }
    }
    fn option<T>(
        &mut self,
        seed: Option<&T>,
        field: impl FnOnce(&mut Self, Option<&T>) -> Result<T>,
    ) -> Result<Option<T>> {
        if self.boolean(seed.is_some())? {
            field(self, seed).map(Some)
        } else {
            Ok(None)
        }
    }
    fn name(&mut self, seed: Option<&VolumeName>) -> Result<VolumeName> {
        let len = self.u8(seed.map_or(0, VolumeName::wire_len))?;
        require((1..=63).contains(&len), "volume name length")?;
        let bytes = if let Some(input) = self.input {
            let (bytes, rest) = input
                .split_at_checked(usize::from(len))
                .ok_or(SupportError("truncated support field"))?;
            self.input = Some(rest);
            bytes
        } else {
            let bytes = seed.ok_or(SupportError("volume name"))?.as_str().as_bytes();
            self.output.extend_from_slice(bytes);
            bytes
        };
        VolumeName::from_bytes(bytes).map_err(|_| SupportError("volume name"))
    }
    fn count(&mut self, seed: usize, cap: usize, wide: bool) -> Result<usize> {
        require(seed <= cap, "support count bound")?;
        let n = u32::try_from(seed).map_err(|_| SupportError("support count bound"))?;
        let n = if wide {
            self.u32(n)?
        } else {
            u32::from(self.u16(u16::try_from(n).map_err(|_| SupportError("support count bound"))?)?)
        };
        let n = usize::try_from(n).map_err(|_| SupportError("support count bound"))?;
        require(n <= cap, "support count bound")?;
        Ok(n)
    }
    fn blob(&mut self, seed: &[u8], length: usize, cap: usize) -> Result<Vec<u8>> {
        require(length <= cap, "support size bound")?;
        if let Some(input) = self.input {
            let (bytes, rest) = input
                .split_at_checked(length)
                .ok_or(SupportError("truncated support field"))?;
            self.input = Some(rest);
            Ok(bytes.to_vec())
        } else {
            require(seed.len() == length, "support body length")?;
            self.output.extend_from_slice(seed);
            Ok(seed.to_vec())
        }
    }
    fn export_name(&mut self, seed: &[u8]) -> Result<Vec<u8>> {
        let len =
            self.u8(u8::try_from(seed.len()).map_err(|_| SupportError("export name length"))?)?;
        require((1..=96).contains(&len), "export name length")?;
        let bytes = self.blob(seed, usize::from(len), 96)?;
        require(
            !bytes.contains(&0)
                && !bytes.contains(&b'/')
                && ![b".".as_slice(), b"..", b".gran"].contains(&bytes.as_slice()),
            "export name",
        )?;
        Ok(bytes)
    }
    fn end(&self) -> Result<()> {
        require(
            self.input.is_none_or(<[u8]>::is_empty),
            "trailing support bytes",
        )
    }
}
fn seal(
    kind: u16,
    cap: usize,
    fields: impl FnOnce(&mut Tape<'_>) -> Result<()>,
) -> Result<Vec<u8>> {
    let mut tape = Tape {
        input: None,
        output: Vec::new(),
    };
    fields(&mut tape)?;
    require(
        tape.output.len() <= cap.saturating_sub(OVERHEAD),
        "support size bound",
    )?;
    let len = u32::try_from(tape.output.len()).map_err(|_| SupportError("support size bound"))?;
    let mut bytes = b"GRANARY\0".to_vec();
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend(tape.output);
    bytes.extend_from_slice(&[1, 1]);
    let check = GrainId::of(&bytes);
    bytes.extend_from_slice(check.digest());
    Ok(bytes)
}
fn open(bytes: &[u8], kind: u16, cap: usize) -> Result<Tape<'_>> {
    require(
        (OVERHEAD..=cap).contains(&bytes.len()),
        "support size bound",
    )?;
    let (prefix, check) = bytes
        .split_at_checked(bytes.len().saturating_sub(CHECK_LEN))
        .ok_or(SupportError("support size bound"))?;
    require(GrainId::of(prefix).digest() == check, "support checksum")?;
    let mut t = Tape {
        input: Some(prefix),
        output: Vec::new(),
    };
    require(t.fixed([0; 8])? == *b"GRANARY\0", "support magic")?;
    require(t.u16(0)? == kind, "support object kind")?;
    require(t.u16(0)? == 1, "support version")?;
    let len = usize::try_from(t.u32(0)?).map_err(|_| SupportError("support size bound"))?;
    require(len <= cap.saturating_sub(OVERHEAD), "support size bound")?;
    let input = t.input.ok_or(SupportError("truncated support field"))?;
    let (body, tags) = input
        .split_at_checked(len)
        .ok_or(SupportError("support body length"))?;
    require(tags == [1, 1], "support checksum profile")?;
    Ok(Tape {
        input: Some(body),
        output: Vec::new(),
    })
}
fn configuration_fields(
    t: &mut Tape<'_>,
    s: Option<&SupportConfiguration>,
) -> Result<SupportConfiguration> {
    let incarnation =
        Incarnation::from_bytes(t.fixed(s.map_or([0; 16], |s| *s.incarnation.as_bytes()))?);
    require(t.u8(s.map_or(0, |_| 1))? == 1, "authority profile")?;
    let count = t.count(s.map_or(0, |s| s.volumes.len()), 64, false)?;
    require(count != 0, "volume count")?;
    let mut seeds = s.into_iter().flat_map(|s| s.volumes.iter());
    let mut volumes = BTreeMap::new();
    for _ in 0..count {
        let seed = seeds.next();
        let name = t.name(seed.map(|(v, _)| v))?;
        require(
            volumes
                .last_key_value()
                .is_none_or(|(last, _)| last < &name),
            "volume order",
        )?;
        let keys = t.u8(seed.map_or(0, |(_, k)| *k))?;
        require((1..=8).contains(&keys), "publisher key count")?;
        volumes.insert(name, keys);
    }
    let accept_unsupported_filesystem =
        t.boolean(s.is_some_and(|s| s.accept_unsupported_filesystem))?;
    let (submission_rate, submission_burst, byte_rate, byte_burst, cap) =
        s.map_or((0, 0, 0, 0, 0), |s| s.controls.tuple());
    let values = [
        t.u64(submission_rate)?,
        t.u64(submission_burst)?,
        t.u64(byte_rate)?,
        t.u64(byte_burst)?,
        t.u64(cap)?,
    ];
    let controls = SupportControls(values);
    controls.validate()?;
    let listen_port = t.u16(s.map_or(0, |s| s.listen_port))?;
    require(listen_port != 0, "listen port")?;
    let tls_enabled = t.boolean(s.is_some_and(|s| s.tls_enabled))?;
    let client_auth_required = t.boolean(s.is_some_and(|s| s.client_auth_required))?;
    require(tls_enabled && client_auth_required, "authority tls policy")?;
    let worker_threads = t.u64(s.map_or(0, |s| s.worker_threads))?;
    require(worker_threads != 0, "worker count")?;
    let shutdown_budget_ms = t.u64(s.map_or(0, |s| s.shutdown_budget_ms))?;
    require(shutdown_budget_ms != 0, "shutdown budget")?;
    let dispatch_deadline_ms =
        t.option(s.and_then(|s| s.dispatch_deadline_ms.as_ref()), |t, s| {
            let n = t.u64(s.copied().unwrap_or(0))?;
            require(n != 0, "dispatch deadline")?;
            Ok(n)
        })?;
    let network_dispatch_limit_ms = t.u64(s.map_or(0, |s| s.network_dispatch_limit_ms))?;
    let network_client_timeout_ms = t.u64(s.map_or(0, |s| s.network_client_timeout_ms))?;
    require(
        network_dispatch_limit_ms == 30_000 && network_client_timeout_ms == 60_000,
        "declared network limits",
    )?;
    Ok(SupportConfiguration {
        incarnation,
        authority_profile: AuthorityProfile::SingleProcess,
        volumes,
        accept_unsupported_filesystem,
        controls,
        listen_port,
        tls_enabled,
        client_auth_required,
        worker_threads,
        shutdown_budget_ms,
        dispatch_deadline_ms,
        network_dispatch_limit_ms,
        network_client_timeout_ms,
    })
}
