// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production object reads and complete, metered root listings.

use std::future::{Future, poll_fn};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use std::time::Duration;

use granary_core::clock::Clock;
use granary_core::root::VolumeName;
use granary_core::rootstore::{RefusalKind, RootStoreError, format_hint_body};
use granary_store::backend::{GranaryStore, listed_root_seq};
use object_store::aws::AmazonS3;
use object_store::list::{PaginatedListOptions, PaginatedListResult, PaginatedListStore};
use object_store::memory::InMemory;
use object_store::path::Path;
use object_store::{ObjectMeta, ObjectStore};

use super::proofs::Proofs;
use super::{
    PublicationValidator, Result, ValidationAttempt, ValidationError, ValidationLimits,
    ValidationObject, ValidationRead, ValidationReadError,
};

mod connector;

pub(crate) use connector::BoundedListingConnector;
use connector::{PageCap, PageSize};

// 1,000 S3 keys of up to 1 KiB, allowing XML escaping and metadata.
const PAGE_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Store and shared work limits for every volume in one authority.
#[derive(Debug, Clone)]
pub struct Admission {
    pub(super) backend: Backend,
    validator: PublicationValidator,
    #[cfg(test)]
    pub(in crate::authority) intake_gate: Option<Arc<super::intake::Gate>>,
    #[cfg(test)]
    pub(in crate::authority) bin_gate: Option<Arc<BinGate>>,
}

impl Admission {
    /// Use the same in-process storage as the root store and HTTP upload routes.
    #[must_use]
    pub fn memory(store: Arc<InMemory>) -> Self {
        Self::over(Backend::Memory(store))
    }

    /// Withhold new decisions when the admission store is unavailable.
    #[must_use]
    pub fn unavailable() -> Self {
        Self::over(Backend::Unavailable)
    }

    pub(crate) fn s3(single_attempt: AmazonS3) -> Self {
        Self::over(Backend::S3(single_attempt))
    }

    #[cfg(test)]
    pub(crate) fn chain_fixture() -> Self {
        Self::over(Backend::ChainFixture)
    }

    fn over(backend: Backend) -> Self {
        Self {
            backend,
            validator: PublicationValidator::default(),
            #[cfg(test)]
            intake_gate: None,
            #[cfg(test)]
            bin_gate: None,
        }
    }

    /// Set the shared work limits and the number of simultaneous attempts.
    #[must_use]
    pub fn with_limits(mut self, limits: ValidationLimits, concurrent: u16) -> Self {
        self.validator = PublicationValidator::new(limits, concurrent);
        self
    }

    pub(super) async fn begin_intake(
        &self,
        clock: Arc<dyn Clock>,
    ) -> Result<Option<ValidationAttempt>> {
        match self.backend {
            Backend::Unavailable => Err(ValidationError::Unavailable),
            #[cfg(test)]
            Backend::ChainFixture => Ok(None),
            _ => self.validator.begin_intake(clock).await.map(Some),
        }
    }

    pub(in crate::authority) fn fresh(mut self) -> Self {
        self.validator = self.validator.fresh();
        self
    }

    pub(in crate::authority) fn proofs(&self) -> &Proofs {
        self.validator.proofs()
    }

    #[cfg(test)]
    pub(in crate::authority) fn limit_proofs(&mut self, bytes: usize) {
        self.validator.limit_proofs(bytes);
    }

    pub(in crate::authority) async fn acquire(
        &self,
        attempt: &mut ValidationAttempt,
    ) -> Result<bool> {
        self.validator.acquire(attempt).await
    }

    pub(in crate::authority) fn preflight(
        &self,
        clock: Arc<dyn Clock>,
    ) -> Result<Option<ValidationAttempt>> {
        match self.backend {
            Backend::Unavailable => Err(ValidationError::Unavailable),
            #[cfg(test)]
            Backend::ChainFixture => Ok(None),
            _ => Ok(Some(self.validator.preflight(clock))),
        }
    }
}

#[cfg(test)]
#[derive(Debug)]
pub(in crate::authority) struct BinGate {
    pub digest: [u8; 32],
    pub entered: tokio::sync::Semaphore,
    pub release: tokio::sync::Semaphore,
}

#[derive(Debug, Clone)]
pub(super) enum Backend {
    S3(AmazonS3),
    Memory(Arc<InMemory>),
    Unavailable,
    #[cfg(test)]
    ChainFixture,
}

impl ValidationRead for Admission {
    async fn read(
        &self,
        object: ValidationObject<'_>,
        cap: u64,
    ) -> std::result::Result<Vec<u8>, ValidationReadError> {
        if matches!(object, ValidationObject::BinRange(_, _, len) if u64::from(len) > cap) {
            return Err(ValidationReadError::OverCap);
        }
        #[cfg(test)]
        if let (Some(gate), ValidationObject::Bin(digest)) = (&self.bin_gate, object)
            && gate.digest == digest
        {
            gate.entered.add_permits(1);
            gate.release.acquire().await.unwrap().forget();
        }
        let bytes = match &self.backend {
            Backend::S3(store) => fetch(GranaryStore::new(store.clone()), object, cap).await,
            Backend::Memory(store) => fetch(GranaryStore::new(store.clone()), object, cap).await,
            Backend::Unavailable => return Err(ValidationReadError::Unavailable),
            #[cfg(test)]
            Backend::ChainFixture => return Err(ValidationReadError::Unavailable),
        };
        if matches!(object, ValidationObject::Bin(_)) {
            crash_point!(ValidationBinRead);
        }
        bytes.map_err(|error| match error {
            RootStoreError::NotFound => ValidationReadError::Missing,
            RootStoreError::RefusedResponse {
                kind: RefusalKind::OverCap | RefusalKind::Extent,
                ..
            } => ValidationReadError::OverCap,
            _ => ValidationReadError::Unavailable,
        })
    }
}

async fn fetch(
    store: GranaryStore<impl ObjectStore>,
    object: ValidationObject<'_>,
    cap: u64,
) -> std::result::Result<Vec<u8>, RootStoreError> {
    match object {
        ValidationObject::Root(volume, seq) => {
            store.get_root_bounded(volume.as_str(), seq, cap).await
        }
        ValidationObject::Meta(volume, id) => {
            store.get_meta_bounded(volume.as_str(), &id, cap).await
        }
        ValidationObject::Bin(digest) => store.get_bin_bounded(&digest, cap).await,
        ValidationObject::BinRange(digest, offset, len) => {
            store.get_bin_range(&digest, offset, len).await
        }
    }
}

/// A rule-6 listing has no usable maximum until the listing ends.
pub(crate) async fn max_seq(
    source: &Admission,
    attempt: &mut ValidationAttempt,
    volume: &VolumeName,
    floor: Option<u64>,
) -> Result<Option<u64>> {
    let prefix = Path::from(format!("root/{}", volume.as_str()));
    let offset = floor.map(|seq| format!("{prefix}/{}", format_hint_body(seq)));
    let mut head = None;
    match &source.backend {
        Backend::S3(store) => {
            let raw_prefix = format!("{prefix}/");
            scan_pages(attempt, &prefix, floor, offset, |options| {
                store.list_paginated(Some(&raw_prefix), options)
            })
            .await
        }
        Backend::Memory(store) => {
            attempt.prepare_page(0).await?;
            attempt.list_page()?;
            let mut stream = match offset {
                Some(offset) => store.list_with_offset(Some(&prefix), &Path::from(offset)),
                None => store.list(Some(&prefix)),
            };
            loop {
                attempt.prepare_entry().await?;
                let Some(meta) = attempt
                    .request(poll_fn(|cx| stream.as_mut().poll_next(cx)))
                    .await?
                else {
                    break;
                };
                attempt.steps(1)?;
                consider(
                    &prefix,
                    floor,
                    &mut head,
                    &meta.map_err(|_| ValidationError::Unavailable)?,
                );
            }
            Ok(head)
        }
        Backend::Unavailable => Err(ValidationError::Unavailable),
        #[cfg(test)]
        Backend::ChainFixture => Err(ValidationError::Unavailable),
    }
}

async fn scan_pages<F>(
    attempt: &mut ValidationAttempt,
    prefix: &Path,
    floor: Option<u64>,
    offset: Option<String>,
    mut list: impl FnMut(PaginatedListOptions) -> F,
) -> Result<Option<u64>>
where
    F: Future<Output = object_store::Result<PaginatedListResult>>,
{
    let mut head = None;
    let mut page_token = None;
    loop {
        let mut backoff = Duration::from_millis(50);
        let PaginatedListResult {
            result,
            page_token: next,
        } = loop {
            match read_page(attempt, offset.clone(), page_token.clone(), &mut list).await {
                Err(error) if attempt.retry(error, &mut backoff).await => {}
                result => break result?,
            }
        };
        for meta in &result.objects {
            consider(prefix, floor, &mut head, meta);
        }
        if next.is_none() {
            return Ok(head);
        }
        page_token = next;
    }
}

async fn read_page<F>(
    attempt: &mut ValidationAttempt,
    offset: Option<String>,
    page_token: Option<String>,
    list: &mut impl FnMut(PaginatedListOptions) -> F,
) -> Result<PaginatedListResult>
where
    F: Future<Output = object_store::Result<PaginatedListResult>>,
{
    attempt.prepare_page(PAGE_MAX_BYTES).await?;
    let max_keys = attempt.list_page()?;
    let cap = attempt.reserve_bytes(PAGE_MAX_BYTES)?;
    let exceeded = Arc::new(AtomicBool::new(false));
    let mut options = PaginatedListOptions {
        offset,
        max_keys: Some(max_keys),
        page_token,
        ..PaginatedListOptions::default()
    };
    options.extensions.insert(PageCap {
        bytes: usize::try_from(cap).map_err(|_| ValidationError::WorkLimit)?,
        exceeded: exceeded.clone(),
    });
    let page = attempt.request(list(options)).await;
    if exceeded.load(Ordering::Relaxed) {
        return Err(ValidationError::WorkLimit);
    }
    let page = page?.map_err(|_| ValidationError::Unavailable)?;
    let result = &page.result;
    let PageSize(bytes) = result
        .extensions
        .get::<PageSize>()
        .copied()
        .ok_or(ValidationError::Unavailable)?;
    attempt.refund_bytes(cap.checked_sub(bytes).ok_or(ValidationError::WorkLimit)?);
    if result.objects.len() > max_keys || !result.common_prefixes.is_empty() {
        return Err(ValidationError::Unavailable);
    }
    attempt.steps(result.objects.len() as u64)?;
    Ok(page)
}

fn consider(prefix: &Path, floor: Option<u64>, head: &mut Option<u64>, item: &ObjectMeta) {
    if let Some(seq) = listed_root_seq(prefix, &item.location)
        && floor.is_none_or(|floor| seq > floor)
    {
        *head = (*head).max(Some(seq));
    }
}

#[cfg(test)]
pub(in crate::authority) mod tests;
