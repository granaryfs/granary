// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Test work accounts distinguish query planning from provisional storage work.

use std::cell::Cell;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QueryWork {
    pub namespace_copies: usize,
    pub primary_visits: usize,
    pub entry_copies: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StorageWork {
    pub namespace_clones: usize,
    pub entry_copies: usize,
    pub primary_rows: usize,
    pub inverse_rows: usize,
    pub parent_buckets: usize,
    pub parent_memberships: usize,
    pub parent_counts: usize,
    pub path_bytes: usize,
    pub primary_visits: usize,
}

std::thread_local! {
    static STORAGE: Cell<bool> = const { Cell::new(false) };
    static QUERY_WORK: Cell<QueryWork> = Cell::new(QueryWork::default());
    static STORAGE_WORK: Cell<StorageWork> = Cell::new(StorageWork::default());
}

pub(super) struct StorageScope(bool);
impl StorageScope {
    pub(super) fn enter() -> Self {
        Self(STORAGE.replace(true))
    }
}
impl Drop for StorageScope {
    fn drop(&mut self) {
        STORAGE.set(self.0);
    }
}

pub(super) fn entry_copy() {
    if STORAGE.get() {
        STORAGE_WORK.with(|cell| {
            let mut work = cell.get();
            work.entry_copies += 1;
            cell.set(work);
        });
    } else {
        QUERY_WORK.with(|cell| {
            let mut work = cell.get();
            work.entry_copies += 1;
            cell.set(work);
        });
    }
}

pub(super) fn primary_visits(rows: usize) {
    if STORAGE.get() {
        STORAGE_WORK.with(|cell| {
            let mut work = cell.get();
            work.primary_visits += rows;
            cell.set(work);
        });
    } else {
        QUERY_WORK.with(|cell| {
            let mut work = cell.get();
            work.primary_visits += rows;
            cell.set(work);
        });
    }
}

pub(super) fn namespace_copy() {
    QUERY_WORK.with(|cell| {
        let mut work = cell.get();
        work.namespace_copies += 1;
        cell.set(work);
    });
}

pub(super) fn namespace_clone(
    primary: usize,
    inverse: usize,
    buckets: usize,
    memberships: usize,
    path_bytes: usize,
) {
    STORAGE_WORK.with(|cell| {
        let mut work = cell.get();
        work.namespace_clones += 1;
        work.primary_rows += primary;
        work.inverse_rows += inverse;
        work.parent_buckets += buckets;
        work.parent_memberships += memberships;
        work.parent_counts += buckets;
        work.path_bytes += path_bytes;
        cell.set(work);
    });
}

impl QueryWork {
    pub(crate) fn since(self, before: Self) -> Self {
        Self {
            namespace_copies: self.namespace_copies - before.namespace_copies,
            primary_visits: self.primary_visits - before.primary_visits,
            entry_copies: self.entry_copies - before.entry_copies,
        }
    }
}

impl StorageWork {
    fn since(self, before: Self) -> Self {
        Self {
            namespace_clones: self.namespace_clones - before.namespace_clones,
            entry_copies: self.entry_copies - before.entry_copies,
            primary_rows: self.primary_rows - before.primary_rows,
            inverse_rows: self.inverse_rows - before.inverse_rows,
            parent_buckets: self.parent_buckets - before.parent_buckets,
            parent_memberships: self.parent_memberships - before.parent_memberships,
            parent_counts: self.parent_counts - before.parent_counts,
            path_bytes: self.path_bytes - before.path_bytes,
            primary_visits: self.primary_visits - before.primary_visits,
        }
    }
}

pub(crate) fn query_snapshot() -> QueryWork {
    QUERY_WORK.get()
}

pub(crate) fn measure<T>(action: impl FnOnce() -> T) -> (T, QueryWork, StorageWork) {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            super::state::EXHAUSTIVE_QUERY_CHECKS.set(self.0);
        }
    }
    let _restore = Restore(super::state::EXHAUSTIVE_QUERY_CHECKS.replace(false));
    let before = (QUERY_WORK.get(), STORAGE_WORK.get());
    let answer = action();
    (
        answer,
        QUERY_WORK.get().since(before.0),
        STORAGE_WORK.get().since(before.1),
    )
}

/// Iteration is measured at each yielded primary row, including borrowed scans.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct PrimaryEntries(std::collections::BTreeMap<Vec<super::Name>, super::OverlayEntry>);

impl std::ops::Deref for PrimaryEntries {
    type Target = std::collections::BTreeMap<Vec<super::Name>, super::OverlayEntry>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for PrimaryEntries {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PrimaryEntries {
    pub(crate) fn iter(
        &self,
    ) -> PrimaryRows<std::collections::btree_map::Iter<'_, Vec<super::Name>, super::OverlayEntry>>
    {
        PrimaryRows(self.0.iter())
    }
    pub(crate) fn keys(
        &self,
    ) -> PrimaryRows<std::collections::btree_map::Keys<'_, Vec<super::Name>, super::OverlayEntry>>
    {
        PrimaryRows(self.0.keys())
    }
    pub(crate) fn values(
        &self,
    ) -> PrimaryRows<std::collections::btree_map::Values<'_, Vec<super::Name>, super::OverlayEntry>>
    {
        PrimaryRows(self.0.values())
    }
    pub(crate) fn values_mut(
        &mut self,
    ) -> PrimaryRows<
        std::collections::btree_map::ValuesMut<'_, Vec<super::Name>, super::OverlayEntry>,
    > {
        PrimaryRows(self.0.values_mut())
    }
    pub(crate) fn into_values(
        self,
    ) -> PrimaryRows<std::collections::btree_map::IntoValues<Vec<super::Name>, super::OverlayEntry>>
    {
        PrimaryRows(self.0.into_values())
    }
    pub(crate) fn iter_mut(
        &mut self,
    ) -> PrimaryRows<std::collections::btree_map::IterMut<'_, Vec<super::Name>, super::OverlayEntry>>
    {
        PrimaryRows(self.0.iter_mut())
    }
    pub(crate) fn range<T: Ord + ?Sized, R: std::ops::RangeBounds<T>>(
        &self,
        range: R,
    ) -> PrimaryRows<std::collections::btree_map::Range<'_, Vec<super::Name>, super::OverlayEntry>>
    where
        Vec<super::Name>: std::borrow::Borrow<T>,
    {
        PrimaryRows(self.0.range(range))
    }
    /// Accounting's own byte summation is instrumentation overhead, not query work.
    pub(crate) fn unmeasured(
        &self,
    ) -> &std::collections::BTreeMap<Vec<super::Name>, super::OverlayEntry> {
        &self.0
    }
}

#[derive(Debug)]
pub(crate) struct PrimaryRows<I>(I);

fn visited<T>(row: Option<T>) -> Option<T> {
    if row.is_some() {
        primary_visits(1);
        super::state::QUERY_PRIMARY_VISITS.set(super::state::QUERY_PRIMARY_VISITS.get() + 1);
    }
    row
}
impl<I: Iterator> Iterator for PrimaryRows<I> {
    type Item = I::Item;
    fn next(&mut self) -> Option<Self::Item> {
        visited(self.0.next())
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}
impl<I: DoubleEndedIterator> DoubleEndedIterator for PrimaryRows<I> {
    fn next_back(&mut self) -> Option<Self::Item> {
        visited(self.0.next_back())
    }
}
impl<I: ExactSizeIterator> ExactSizeIterator for PrimaryRows<I> {}

impl<'a> IntoIterator for &'a PrimaryEntries {
    type Item = (&'a Vec<super::Name>, &'a super::OverlayEntry);
    type IntoIter =
        PrimaryRows<std::collections::btree_map::Iter<'a, Vec<super::Name>, super::OverlayEntry>>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
impl IntoIterator for PrimaryEntries {
    type Item = (Vec<super::Name>, super::OverlayEntry);
    type IntoIter =
        PrimaryRows<std::collections::btree_map::IntoIter<Vec<super::Name>, super::OverlayEntry>>;
    fn into_iter(self) -> Self::IntoIter {
        PrimaryRows(self.0.into_iter())
    }
}

impl<'a> IntoIterator for &'a mut PrimaryEntries {
    type Item = (&'a Vec<super::Name>, &'a mut super::OverlayEntry);
    type IntoIter = PrimaryRows<
        std::collections::btree_map::IterMut<'a, Vec<super::Name>, super::OverlayEntry>,
    >;
    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}
