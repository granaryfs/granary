// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::path::{Path, PathBuf};

use super::{WATERMARK_MIN_BYTES, WATERMARK_PERCENT_DIVISOR};

/// The free-space determinism seam (the `Clock`/`Rng` shape, applied to
/// a kernel interface `granary-core`'s purity gate forbids): production
/// code queries the real filesystem, tests inject a fixed reading.
/// Consulted before every write under the cache root — object inserts,
/// root writes, journal flushes, snapshot compaction — refusing each write
/// that fails the free-space check, with no small-write exemption. **The
/// one exception is the anchor write** (`WriterState::raise_anchor`).
///
/// **`: Send`** — a `Cache` must be storable in a `fuser::Filesystem`,
/// which is `Send + Sync + 'static`; `WriterState` holds a `Box<dyn
/// FreeSpace>`, so without this supertrait `Cache` is `!Send` and
/// cannot be held behind the mount's mutex. Adding a supertrait to a
/// `pub` trait is a semver break for any external implementor —
/// `FreeSpace` and `Cache::open_with_free_space` are both public
/// — but nothing outside this WORKSPACE
/// implements it today.
pub trait FreeSpace: Send {
    /// # Errors
    /// An I/O failure querying the filesystem the cache root lives on.
    fn free_space(&self) -> io::Result<FreeSpaceInfo>;
}

/// One free-space reading. Both fields are the filesystem's own
/// counts — never the cache's internal accounting of what it believes
/// it has written (cvmfs#2948's own bug was reading the wrong
/// field, not reading a stale source, but the two are related traps).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreeSpaceInfo {
    pub free_bytes: u64,
    pub capacity_bytes: u64,
}

/// The production [`FreeSpace`]: queries the filesystem the cache root
/// lives on, per platform (a single cross-platform formula is
/// false on macOS).
#[derive(Debug)]
pub(super) struct SystemFreeSpace {
    root: PathBuf,
}

impl SystemFreeSpace {
    /// Constructed through here rather than by struct literal so `root`
    /// stays private to this module: the parent needs exactly one
    /// capability over this type — make one — and a `pub(super)` field
    /// would also hand it read and write access to the path a durability
    /// query is answered about.
    pub(super) const fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

impl FreeSpace for SystemFreeSpace {
    fn free_space(&self) -> io::Result<FreeSpaceInfo> {
        platform_free_space(&self.root)
    }
}

#[cfg(target_os = "linux")]
#[expect(
    unsafe_code,
    reason = "statvfs is a kernel interface with no safe std wrapper; the crate's own \
              lint table (Cargo.toml addendum) narrows unsafe_code to deny specifically \
              so this FFI call can compile"
)]
fn platform_free_space(root: &Path) -> io::Result<FreeSpaceInfo> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let c_path = CString::new(root.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `c_path` is a valid NUL-terminated C string alive for the
    // duration of this call, and `stat` is a correctly-sized,
    // appropriately-aligned buffer for `statvfs` to populate; the call
    // does not retain either pointer past its return.
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `statvfs` returned 0 (success), so POSIX guarantees `stat`
    // is now fully initialized.
    let stat = unsafe { stat.assume_init() };
    // gnu-64: `f_bavail`/`f_blocks`/`f_frsize` are already `u64`
    // (`fsblkcnt_t`/`c_ulong`) — no widening cast here, deliberately:
    // one would trip `clippy::useless_conversion` on this platform even
    // though the identical-looking macOS formula below needs one (the
    // field widths differ per platform, not just per name).
    // NEVER `f_bsize` (the optimal-transfer hint, cvmfs#2948's own bug);
    // `f_frsize` is the fundamental block size these counts are in.
    Ok(FreeSpaceInfo {
        free_bytes: stat.f_bavail.saturating_mul(stat.f_frsize),
        capacity_bytes: stat.f_blocks.saturating_mul(stat.f_frsize),
    })
}

#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "statfs is a kernel interface with no safe std wrapper; the crate's own \
              lint table (Cargo.toml addendum) narrows unsafe_code to deny specifically \
              so this FFI call can compile"
)]
fn platform_free_space(root: &Path) -> io::Result<FreeSpaceInfo> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let c_path = CString::new(root.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `c_path` is a valid NUL-terminated C string alive for the
    // duration of this call, and `stat` is a correctly-sized,
    // appropriately-aligned buffer for `statfs` to populate; the call
    // does not retain either pointer past its return.
    let rc = unsafe { libc::statfs(c_path.as_ptr(), stat.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `statfs` returned 0 (success), so the buffer is now fully
    // initialized.
    let stat = unsafe { stat.assume_init() };
    // Apple's `statfs`: `f_bavail`/`f_blocks` are already `u64`; `f_bsize`
    // is `u32` and needs the widening `u64::from` below. NEVER
    // `f_iosize` (the optimal-transfer hint on Apple's `statfs`).
    let block = u64::from(stat.f_bsize);
    Ok(FreeSpaceInfo {
        free_bytes: stat.f_bavail.saturating_mul(block),
        capacity_bytes: stat.f_blocks.saturating_mul(block),
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("granary-client's cache module supports only linux and macos");

/// `max(1 GiB, 5% of capacity)` — ongoing, not init-only
/// (cvmfs#3832's warn-once-at-init is the rejected precedent). When the
/// filesystem's whole capacity is at or below the fixed floor, the floor
/// cannot be satisfied and is clamped down to the capacity-relative 5%
/// reserve; otherwise every write on that volume would be refused forever.
pub(super) fn watermark_bytes(capacity_bytes: u64) -> u64 {
    let capacity_relative = capacity_bytes / WATERMARK_PERCENT_DIVISOR;
    if capacity_bytes <= WATERMARK_MIN_BYTES {
        capacity_relative
    } else {
        capacity_relative.max(WATERMARK_MIN_BYTES)
    }
}

/// Whether a write of `additional_len` bytes may proceed: refuses when
/// `free - additional_len < watermark`, computed without underflow via
/// `free < watermark + additional_len`. A free-space QUERY failure
/// itself refuses too (fail-safe default): a cache that cannot tell
/// how much room is left must not assume there is enough.
pub(super) fn free_space_precheck(free_space: &dyn FreeSpace, additional_len: u64) -> bool {
    let Ok(info) = free_space.free_space() else {
        return false;
    };
    let watermark = watermark_bytes(info.capacity_bytes);
    info.free_bytes >= watermark.saturating_add(additional_len)
}

#[cfg(test)]
mod tests;
