// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::future::ready;

use granary_core::sheaf::Timestamp;
use hyper::http::Extensions;
use object_store::{ListResult, ObjectStoreExt};

use super::*;

struct Fixed;
impl Clock for Fixed {
    fn now(&self) -> Timestamp {
        Timestamp { secs: 1, nanos: 0 }
    }
}

#[tokio::test]
async fn a_partial_listing_never_supplies_a_maximum() {
    for (reads, intake) in [(1, false), (2, false), (1, true)] {
        let validator = PublicationValidator::new(
            ValidationLimits {
                reads,
                ..ValidationLimits::default()
            },
            1,
        );
        let mut attempt = if intake {
            validator.begin_intake(Arc::new(Fixed)).await.unwrap()
        } else {
            validator.begin(Arc::new(Fixed)).await.unwrap()
        };
        let prefix = Path::from("root/vol-a");
        let store = InMemory::new();
        let key = Path::from("source");
        store.put(&key, "fixture".into()).await.unwrap();
        let template = store.head(&key).await.unwrap();
        let mut calls = 0;
        let listed = scan_pages(
            &mut attempt,
            &prefix,
            Some(1),
            Some(format!("{prefix}/{:020}", 1)),
            |opts| {
                calls += 1;
                assert_eq!(
                    opts.page_token.as_deref(),
                    if calls == 1 { None } else { Some("next") }
                );
                assert_eq!(opts.max_keys, Some(1_000));
                let seq = calls + 1;
                let mut extensions = Extensions::new();
                extensions.insert(PageSize(128));
                ready(Ok(PaginatedListResult {
                    result: ListResult {
                        common_prefixes: vec![],
                        objects: vec![ObjectMeta {
                            location: Path::from(format!("{prefix}/{seq:020}")),
                            ..template.clone()
                        }],
                        extensions,
                    },
                    page_token: (calls == 1).then(|| "next".to_owned()),
                }))
            },
        )
        .await;
        if reads == 1 && !intake {
            assert_eq!(calls, 1);
            assert_eq!(listed, Err(ValidationError::WorkLimit));
        } else {
            assert_eq!(calls, 2);
            assert_eq!(listed, Ok(Some(3)));
        }
    }
}

#[tokio::test]
async fn s3_pages_pass_through_the_bounded_connector() {
    use connector::BoundedListing;
    use object_store::ClientOptions;
    use object_store::aws::AmazonS3Builder;
    use object_store::client::{
        HttpClient, HttpConnector, HttpError, HttpRequest, HttpResponse, HttpService,
    };
    use std::pin::Pin;

    #[derive(Debug, Clone, Copy)]
    struct S3Page;
    impl HttpConnector for S3Page {
        fn connect(&self, _: &ClientOptions) -> object_store::Result<HttpClient> {
            Ok(HttpClient::new(BoundedListing(HttpClient::new(*self))))
        }
    }
    impl HttpService for S3Page {
        fn call<'a, 'future>(
            &'a self,
            request: HttpRequest,
        ) -> Pin<
            Box<dyn Future<Output = std::result::Result<HttpResponse, HttpError>> + Send + 'future>,
        >
        where
            'a: 'future,
            Self: 'future,
        {
            assert!(request.extensions().get::<PageCap>().is_some());
            assert!(request.uri().query().unwrap().contains("max-keys=1000"));
            Box::pin(ready(Ok(HttpResponse::new(
                hyper::body::Bytes::from_static(
                    b"<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>",
                )
                .into(),
            ))))
        }
    }
    let store = AmazonS3Builder::new()
        .with_bucket_name("fixture")
        .with_region("us-east-1")
        .with_access_key_id("fixture")
        .with_secret_access_key("fixture")
        .with_http_connector(S3Page)
        .build()
        .unwrap();
    let source = Admission::s3(store);
    let volume = VolumeName::new("vol-a".to_owned()).unwrap();
    for (bytes, expected) in [(16, Err(ValidationError::WorkLimit)), (128, Ok(None))] {
        let admission = source.clone().with_limits(
            ValidationLimits {
                bytes,
                ..ValidationLimits::default()
            },
            1,
        );
        let mut attempt = admission.preflight(Arc::new(Fixed)).unwrap().unwrap();
        assert_eq!(
            max_seq(&source, &mut attempt, &volume, None).await,
            expected
        );
    }
}

pub(in crate::authority) fn s3_fixture(
    service: impl object_store::client::HttpService + Clone,
) -> Admission {
    use connector::BoundedListing;
    use object_store::RetryConfig;
    use object_store::aws::AmazonS3Builder;
    use object_store::client::{HttpClient, HttpConnector, HttpService};

    #[derive(Debug, Clone)]
    struct Connector<S>(S);
    impl<S: Clone + HttpService> HttpConnector for Connector<S> {
        fn connect(&self, _: &object_store::ClientOptions) -> object_store::Result<HttpClient> {
            Ok(HttpClient::new(BoundedListing(HttpClient::new(
                self.0.clone(),
            ))))
        }
    }

    Admission::s3(
        AmazonS3Builder::new()
            .with_bucket_name("fixture")
            .with_region("us-east-1")
            .with_access_key_id("fixture")
            .with_secret_access_key("fixture")
            .with_virtual_hosted_style_request(true)
            .with_retry(RetryConfig {
                max_retries: 0,
                ..RetryConfig::default()
            })
            .with_http_connector(Connector(service))
            .build()
            .unwrap(),
    )
}
