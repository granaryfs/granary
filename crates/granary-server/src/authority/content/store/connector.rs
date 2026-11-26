// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Limit S3 listing XML before the SDK buffers and parses it.

use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use granary_store::http_client::NoRedirectConnector;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::Body;
use object_store::ClientOptions;
use object_store::client::{
    HttpClient, HttpConnector, HttpError, HttpErrorKind, HttpRequest, HttpResponse, HttpService,
};

#[derive(Debug, Clone)]
pub(super) struct PageCap {
    pub(super) bytes: usize,
    pub(super) exceeded: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PageSize(pub(super) u64);

#[derive(Debug)]
pub(crate) struct BoundedListingConnector;

impl HttpConnector for BoundedListingConnector {
    fn connect(&self, options: &ClientOptions) -> object_store::Result<HttpClient> {
        let inner = NoRedirectConnector.connect(options)?;
        Ok(HttpClient::new(BoundedListing(inner)))
    }
}

#[derive(Debug)]
pub(super) struct BoundedListing(pub(super) HttpClient);

impl HttpService for BoundedListing {
    fn call<'a, 'future>(
        &'a self,
        request: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, HttpError>> + Send + 'future>>
    where
        'a: 'future,
        Self: 'future,
    {
        Box::pin(async move {
            let cap = request.extensions().get::<PageCap>().cloned();
            let response = self.0.execute(request).await?;
            let Some(cap) = cap else {
                return Ok(response);
            };
            let (mut parts, body) = response.into_parts();
            let too_large = || {
                cap.exceeded.store(true, Ordering::Relaxed);
                HttpError::new(
                    HttpErrorKind::Decode,
                    std::io::Error::other("listing exceeds its byte allowance"),
                )
            };
            if body.size_hint().lower() > cap.bytes as u64 {
                return Err(too_large());
            }
            let bytes = Limited::new(body, cap.bytes)
                .collect()
                .await
                .map_err(|error| {
                    if error.is::<LengthLimitError>() {
                        too_large()
                    } else {
                        HttpError::new_boxed(HttpErrorKind::Decode, error)
                    }
                })?
                .to_bytes();
            parts.extensions.insert(PageSize(bytes.len() as u64));
            Ok(HttpResponse::from_parts(parts, bytes.into()))
        })
    }
}
