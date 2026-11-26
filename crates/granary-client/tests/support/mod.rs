// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;

pub(super) fn base_url(addr: SocketAddr) -> String {
    format!("https://{addr}")
}
