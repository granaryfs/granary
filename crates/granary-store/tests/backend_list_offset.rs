// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "backend")]
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "the scripted endpoint's setup and request checks fail the test on error"
)]

//! Bounded root listings through the S3 client's `ListObjectsV2` decoder.

use granary_core::rootstore::{RootStore, RootStoreError};
use granary_store::backend::GranaryStore;
use granary_store::http_client::NoRedirectConnector;
use object_store::aws::AmazonS3Builder;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

const VOLUME: &str = "vol-list";

async fn request_line(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") && head.len() < 64 * 1024 {
        head.push(stream.read_u8().await.unwrap());
    }
    assert!(head.ends_with(b"\r\n\r\n"), "unterminated request head");
    String::from_utf8(head)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_owned()
}

fn list_response(request_line: &str, pages: &[&[&str]]) -> String {
    let mut parts = request_line.split_whitespace();
    assert_eq!(parts.next(), Some("GET"));
    let target = parts.next().unwrap();
    let url = reqwest::Url::parse(&format!("http://localhost{target}")).unwrap();
    assert_eq!(url.path(), "/granary-test");
    let query: BTreeMap<_, _> = url.query_pairs().collect();
    assert_eq!(query.get("list-type").map(AsRef::as_ref), Some("2"));
    let prefix = format!("root/{VOLUME}/");
    assert_eq!(
        query.get("prefix").map(AsRef::as_ref),
        Some(prefix.as_str())
    );
    let start_after = query.get("start-after").map(AsRef::as_ref);
    let page = query
        .get("continuation-token")
        .map_or(0, |token| token.parse::<usize>().unwrap());
    let keys = pages.get(page).unwrap();
    let next = page + 1;
    let truncated = next < pages.len();
    let mut xml = format!("<ListBucketResult><IsTruncated>{truncated}</IsTruncated>");
    // Use raw keys here. The S3 client owns normalization and validation.
    for &key in *keys {
        if key.starts_with(&prefix) && start_after.is_none_or(|offset| key > offset) {
            write!(
                xml,
                "<Contents><Key>{key}</Key><Size>1</Size>\
                 <LastModified>2026-01-01T00:00:00Z</LastModified><ETag>e</ETag></Contents>"
            )
            .unwrap();
        }
    }
    if truncated {
        write!(xml, "<NextContinuationToken>{next}</NextContinuationToken>").unwrap();
    }
    xml.push_str("</ListBucketResult>");
    xml
}

async fn scripted_listing(
    pages: &[&[&str]],
    floor: Option<u64>,
) -> Result<Option<u64>, RootStoreError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind scripted S3 endpoint");
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let client = AmazonS3Builder::new()
        .with_http_connector(NoRedirectConnector)
        .with_endpoint(endpoint)
        .with_allow_http(true)
        .with_virtual_hosted_style_request(false)
        .with_region("us-east-1")
        .with_bucket_name("granary-test")
        .with_skip_signature(true)
        .build()
        .unwrap();
    let store = GranaryStore::new(client);
    let mut serve = pin!(async {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let line = request_line(&mut stream).await;
            let body = list_response(&line, pages);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    let mut list = pin!(async {
        match floor {
            Some(floor) => store.max_seq_above(VOLUME, floor).await,
            None => store.max_seq(VOLUME).await,
        }
    });
    // Drive both ends of the exchange on one runtime. A listing that
    // stops early still returns its result to the test assertion.
    tokio::time::timeout(
        Duration::from_secs(10),
        poll_fn(|cx| {
            let _ = serve.as_mut().poll(cx);
            list.as_mut().poll(cx)
        }),
    )
    .await
    .expect("scripted S3 listing timed out")
}

#[tokio::test]
async fn max_seq_above_omits_only_malformed_keys_below_the_offset() {
    let pages: &[&[&str]] = &[&[
        "root/vol-list/00000000000000000004/../junk",
        "root/vol-list/00000000000000000009",
    ]];
    for floor in [None, Some(3)] {
        let result = scripted_listing(pages, floor).await;
        assert!(
            matches!(&result, Err(RootStoreError::Backend(reason)) if reason.contains("..")),
            "floor {floor:?}: {result:?}"
        );
    }
    assert_eq!(scripted_listing(pages, Some(5)).await, Ok(Some(9)));
}

#[tokio::test]
async fn max_seq_above_rejects_the_floor_key_with_a_trailing_slash() {
    let pages: &[&[&str]] = &[&["root/vol-list/00000000000000000010/"]];
    assert_eq!(scripted_listing(pages, None).await, Ok(Some(10)));
    assert_eq!(scripted_listing(pages, Some(10)).await, Ok(None));
}

#[tokio::test]
async fn max_seq_above_reaches_the_second_page() {
    let pages: &[&[&str]] = &[
        &[
            "root/vol-list/00000000000000000003",
            "root/vol-list/00000000000000000008",
        ],
        &["root/vol-list/00000000000000000013"],
    ];
    assert_eq!(scripted_listing(pages, Some(3)).await, Ok(Some(13)));
}
