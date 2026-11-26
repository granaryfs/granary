// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared wire shapes tested for `granary-request-id` conformance (§13.2 item 24).

/// The wire shapes tested for `granary-request-id` conformance (§13.2 item 24).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RequestIdShape {
    Single(&'static [u8]),
    Repeated(&'static [u8], &'static [u8]),
    Owned(Vec<u8>),
}

impl RequestIdShape {
    pub(crate) fn as_wire_fields(&self) -> Vec<(&'static str, &[u8])> {
        match self {
            Self::Single(bytes) => vec![("granary-request-id", *bytes)],
            Self::Repeated(first, second) => {
                vec![
                    ("granary-request-id", *first),
                    ("granary-request-id", *second),
                ]
            }
            Self::Owned(bytes) => vec![("granary-request-id", bytes.as_slice())],
        }
    }

    /// If this shape conforms to §9.1 grammar (1 to 64 ASCII alphanumeric or `.` `_` `-`),
    /// returns the parsed string value; otherwise returns `None`.
    pub(crate) fn conforming_value(&self) -> Option<&str> {
        let bytes = match self {
            Self::Single(b) => *b,
            Self::Owned(b) => b.as_slice(),
            Self::Repeated(..) => return None,
        };
        if (1..=64).contains(&bytes.len())
            && bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            std::str::from_utf8(bytes).ok()
        } else {
            None
        }
    }

    pub(crate) fn is_conforming(&self) -> bool {
        self.conforming_value().is_some()
    }

    pub(crate) fn apply_headers(&self, headers: &mut hyper::HeaderMap) {
        for (name, value) in self.as_wire_fields() {
            let name = hyper::header::HeaderName::from_static(name);
            let value = hyper::header::HeaderValue::from_bytes(value).unwrap();
            headers.append(name, value);
        }
    }

    pub(crate) fn to_headers(&self) -> hyper::HeaderMap {
        let mut map = hyper::HeaderMap::new();
        self.apply_headers(&mut map);
        map
    }
}

/// Classify whether a given shape conforms to the §9.1 grammar.
pub(crate) fn is_conforming_request_id_shape(shape: &RequestIdShape) -> bool {
    shape.is_conforming()
}

pub(crate) fn request_id_shapes() -> [RequestIdShape; 11] {
    let valid_sixty_four = vec![b'a'; 64];
    let malformed_sixty_five = vec![b'a'; 65];
    [
        RequestIdShape::Single(b"a"),
        RequestIdShape::Owned(valid_sixty_four),
        RequestIdShape::Single(b"A_1.z-9"),
        RequestIdShape::Single(b""),
        RequestIdShape::Owned(malformed_sixty_five),
        RequestIdShape::Single(b"a b"),
        RequestIdShape::Single(b"a/b"),
        RequestIdShape::Single(b"a,b"),
        RequestIdShape::Single(b"a\x80"),
        RequestIdShape::Repeated(b"a", b"a"),
        RequestIdShape::Repeated(b"a", b"b"),
    ]
}
