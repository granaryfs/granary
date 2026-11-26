// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Run the unchanged seam suites through in-process HTTP requests.
use super::*;
use granary_core::binstore::BinStore;
use granary_core::rootstore::{filter_above, parse_hint_body};
use hyper::{HeaderMap, Request};

pub(super) struct Client(pub(super) crate::GrainService<Store>);
fn volume(v: &str) -> Result<(), RootStoreError> {
    VolumeName::from_bytes(v.as_bytes())
        .map(|_| ())
        .map_err(|e| RootStoreError::InvalidVolume {
            reason: e.to_string(),
        })
}
impl Client {
    async fn call(&self, r: Request<Full<Bytes>>) -> (u16, HeaderMap, Vec<u8>) {
        let response = self.0.request_for_test(r).await;
        let (parts, body) = response.into_parts();
        (
            parts.status.as_u16(),
            parts.headers,
            body.collect().await.unwrap().to_bytes().to_vec(),
        )
    }
    async fn put(&self, path: &str, b: Vec<u8>) -> Result<bool, RootStoreError> {
        let (status, _, _) = self
            .call(request("PUT", path, Full::new(Bytes::from(b))))
            .await;
        match status {
            201 => Ok(true),
            200 | 204 => Ok(false),
            409 => Err(RootStoreError::AlreadyExists),
            _ => Err(RootStoreError::Backend(format!("status {status}"))),
        }
    }
    async fn get(&self, path: &str) -> Result<Option<Vec<u8>>, RootStoreError> {
        let (status, _, b) = self
            .call(request("GET", path, Full::new(Bytes::new())))
            .await;
        match status {
            200 => Ok(Some(b)),
            404 => Ok(None),
            _ => Err(RootStoreError::Backend(format!("status {status}"))),
        }
    }
}
impl RootStore for Client {
    async fn put_root(&self, v: &str, n: u64, b: Vec<u8>) -> Result<(), RootStoreError> {
        volume(v)?;
        self.put(&format!("/volume/{v}/root/{n:020}"), b)
            .await
            .map(|_| ())
    }
    async fn get_root(&self, v: &str, n: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        volume(v)?;
        self.get(&format!("/volume/{v}/root/{n:020}")).await
    }
    async fn max_seq(&self, v: &str) -> Result<Option<u64>, RootStoreError> {
        volume(v)?;
        Ok(self
            .get(&format!("/volume/{v}/max-seq"))
            .await?
            .map(|b| parse_hint_body(std::str::from_utf8(&b).unwrap()).unwrap()))
    }
    async fn max_seq_above(&self, v: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(v).await?, floor))
    }
    async fn write_hint(&self, v: &str, n: u64) -> Result<(), RootStoreError> {
        volume(v)?;
        self.put(
            &format!("/volume/{v}/hint"),
            format!("{n:020}").into_bytes(),
        )
        .await
        .map(|_| ())
    }
    async fn read_hint(&self, v: &str, t: Option<&HintToken>) -> Result<HintRead, RootStoreError> {
        volume(v)?;
        let mut req = request("GET", &format!("/volume/{v}/hint"), Full::new(Bytes::new()));
        if let Some(t) = t {
            req.headers_mut()
                .insert("if-none-match", t.0.parse().unwrap());
        }
        let (status, headers, b) = self.call(req).await;
        match status {
            404 => Ok(HintRead::Missing),
            304 => Ok(HintRead::NotModified),
            200 => Ok(HintRead::Current {
                seq: parse_hint_body(std::str::from_utf8(&b).unwrap()).unwrap(),
                token: HintToken(headers["etag"].to_str().unwrap().to_owned()),
            }),
            _ => Err(RootStoreError::Backend(format!("status {status}"))),
        }
    }
}
impl BinStore for Client {
    async fn put_meta(&self, v: &str, id: &GrainId, b: Vec<u8>) -> Result<bool, RootStoreError> {
        volume(v)?;
        self.put(&format!("/volume/{v}/meta/{id}"), b).await
    }
    async fn get_meta(&self, v: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        volume(v)?;
        self.get(&format!("/volume/{v}/meta/{id}"))
            .await?
            .ok_or(RootStoreError::NotFound)
    }
    async fn put_bin(&self, d: &[u8; 32], b: Vec<u8>) -> Result<bool, RootStoreError> {
        self.put(
            &format!(
                "/bin/{}",
                hex(GrainId::from_parts(
                    granary_core::hash::HashAlgorithm::Blake3,
                    *d
                ))
            ),
            b,
        )
        .await
    }
    async fn get_bin_range(&self, d: &[u8; 32], o: u64, n: u32) -> Result<Vec<u8>, RootStoreError> {
        let end = o
            .checked_add(u64::from(n))
            .ok_or(RootStoreError::RangeOverflow)?;
        if n == 0 {
            return Err(RootStoreError::Backend("empty range".into()));
        }
        let mut req = request(
            "GET",
            &format!(
                "/bin/{}",
                hex(GrainId::from_parts(
                    granary_core::hash::HashAlgorithm::Blake3,
                    *d
                ))
            ),
            Full::new(Bytes::new()),
        );
        req.headers_mut()
            .insert("range", format!("bytes={o}-{}", end - 1).parse().unwrap());
        let (status, _, b) = self.call(req).await;
        match status {
            206 => Ok(b),
            404 => Err(RootStoreError::NotFound),
            _ => Err(RootStoreError::Backend(format!("status {status}"))),
        }
    }
}

#[tokio::test]
async fn phase1_shared_conformance_unchanged() {
    for authority in [false, true] {
        for stray in [false, true] {
            let logs = if stray {
                vec![
                    vol("vol-conf"),
                    vol("root-conf-cas"),
                    vol("root-conf-max"),
                    vol("root-conf-hint"),
                ]
            } else {
                vec![]
            };
            let (fx, driver) = Fx::new(false, &logs, &[]).await;
            let mut run = spawn_driver(driver);
            let service = if authority {
                fx.service.clone()
            } else {
                crate::GrainService::for_test(
                    Arc::new(fx.store.clone()),
                    "",
                    crate::VerifyPolicy::seam_only(),
                    Some(crate::admission::DECLARED_MAX_EXTENT),
                    crate::adapter::WRITE_BODY_BUDGET_BYTES,
                    crate::adapter::READ_BODY_BUDGET_BYTES,
                    crate::adapter::VERIFY_PERMIT_MAX_WAIT,
                    None,
                )
            };
            let client = Client(service);
            granary_core::testkit::rootstore_conformance(&client).await;
            granary_core::testkit::binstore_conformance(&client).await;
            fx.handle.stop().await;
            run.join_next().await.unwrap().unwrap();
        }
    }
}
