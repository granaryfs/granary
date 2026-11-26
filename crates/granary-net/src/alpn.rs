// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The ALPN admission predicate.
//!
//! Phase 1 speaks HTTP semantics over TCP with `http/1.1` as the mandatory
//! baseline and `h2` as the offer, so the admitted set is
//! *both* tokens. The predicate is a set-membership test against
//! [`GRANARY_ALPN`], never a comparison against one expected token: a
//! singular comparison drops whichever of the two it was not, breaking
//! either the mandatory baseline or the h2 offer depending on which way it
//! is written.
//!
//! **The set is not a parameter, and that is the point.** A caller that
//! chose the allowed set could wire this predicate with `{h2}` alone and
//! still satisfy every isolated predicate test while silently dropping
//! conforming `http/1.1` clients. A gate whose allowed set the caller picks
//! is not a gate.
//!
//! **A non-empty server ALPN list is not itself a gate.** A client that
//! omits the ALPN extension entirely completes the handshake and negotiates
//! nothing; RFC 7301's fatal alert fires only when a client *offers* ALPN
//! and nothing overlaps. `None` is therefore a live input here, and it is
//! dropped.
//!
//! **Admission and binding are two questions, and both are answered here.**
//! [`admits`] says whether the connection may proceed at all; [`serves`] says
//! which protocol it is then served with. Splitting them and answering both
//! from one `match` is what keeps the connection from being served a protocol
//! its peer did not negotiate — a version-sniffing connection builder decides
//! that from the first bytes on the wire instead, which serves real HTTP/2 to
//! a peer that negotiated `http/1.1` (RFC 7301 §3.2) and serves anything at
//! all to a peer that negotiated nothing.
//!
//! [`GRANARY_ALPN`] is what the server OFFERS and [`serves`] is what the
//! accept path will BIND, so the two must agree or the server offers a token
//! it then refuses. A token added to the constant without a `serves` arm is
//! exactly that drift, and the suite asserts against it.

/// The HTTP/2 ALPN token (RFC 7540 §3.1).
pub const ALPN_H2: &[u8] = b"h2";

/// The HTTP/1.1 ALPN token (RFC 7301 §6, IANA registry).
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Every application protocol granary admits, and the only ones.
pub const GRANARY_ALPN: [&[u8]; 2] = [ALPN_H2, ALPN_HTTP11];

/// The HTTP version an admitted connection is served with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// HTTP/1.1, negotiated as [`ALPN_HTTP11`].
    Http1,
    /// HTTP/2, negotiated as [`ALPN_H2`].
    Http2,
}

/// Bind a negotiated ALPN protocol to the HTTP version it may be served with.
///
/// `None` in means nothing was negotiated — the state a client that omits the
/// extension reaches while still completing the handshake — and `None` out
/// means the connection is not admitted. Every token this returns `Some` for
/// is a member of [`GRANARY_ALPN`], and every member must appear here: the
/// offered set and the servable set are the same set, checked by test.
#[must_use]
pub fn serves(negotiated: Option<&[u8]>) -> Option<Protocol> {
    match negotiated {
        Some(ALPN_H2) => Some(Protocol::Http2),
        Some(ALPN_HTTP11) => Some(Protocol::Http1),
        Some(_) | None => None,
    }
}

/// Admit a connection whose negotiated ALPN protocol is `negotiated`.
///
/// `None` — nothing negotiated, which a client that omits the extension
/// reaches while completing the handshake — is dropped. `Some(p)` is
/// admitted exactly when `p` is a member of [`GRANARY_ALPN`].
///
/// Defined as "[`serves`] has an answer", so admission cannot outgrow
/// binding: a token this admitted but nothing could serve would be a
/// connection accepted into a protocol chosen by something other than the
/// negotiation.
#[must_use]
pub fn admits(negotiated: Option<&[u8]>) -> bool {
    serves(negotiated).is_some()
}
