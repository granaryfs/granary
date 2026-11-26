// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The TLS client credential: a certificate chain and the private key it
//! certifies, read from PEM under a strict profile and checked to
//! correspond.
//!
//! **Every byte of both files is placed, and every field of the key's top
//! level.** A PEM reader that skips what it does not recognise would accept
//! a file holding a second key, a stray block or a pasted fragment, and load
//! whatever it did recognise; an operator who meant something else by the
//! file would never hear of it. So the files are split into blocks here,
//! every line placed, and only then is each block decoded (by
//! `rustls-pki-types`). The key block is then held, here, to one PKCS#8
//! structure (RFC 5958's `OneAsymmetricKey`) at its top level: version,
//! algorithm, key, an optional public key, no attributes, nothing else and
//! nothing after. Granary checks this because the provider's own reader
//! does not promise it in every build.
//!
//! **What is inside those fields is the provider's to judge, and it does
//! not promise to read every byte of them.** That is a named limit, not a
//! hole: the key file is the operator's own and custody-checked, and bytes
//! the provider skips never enter the loaded key, whose public half must
//! equal the end-entity certificate's (below).
//!
//! The certificate file holds one or more `CERTIFICATE` blocks, the end
//! entity first, at most [`CERTIFICATE_CHAIN_MAX`]; every one must decode as
//! an X.509 certificate, the intermediates too. The key file holds exactly
//! one unencrypted PKCS#8 `PRIVATE KEY` block. Only whitespace (blank lines,
//! spaces, tabs; LF or CRLF line ends) may surround the blocks, and each
//! file is at most [`CREDENTIAL_FILE_MAX`] bytes. Everything else refuses,
//! naming what it found: an encrypted key, a PKCS#1 (`RSA PRIVATE KEY`) or
//! SEC1 (`EC PRIVATE KEY`) key, a second key, a key in the certificate file
//! or a certificate in the key file, a block of any other label, malformed
//! base64, a key block that is not one PKCS#8 structure at its top level or
//! carries attributes, a key the provider refuses, and any other text.
//!
//! **The key must be the end entity's.** The key is loaded through the
//! workspace's provider, and its public key is compared with the end-entity
//! certificate's (`CertifiedKey::keys_match`). The comparison is required to
//! succeed: rustls's own `CertifiedKey::from_der` lets a key whose public half
//! it cannot derive through as "unknown", which this does not.
//!
//! Nothing here judges the chain: the server verifies it against its CA in
//! the handshake. Reading the files from disk, with the key file's custody
//! checks, is the client crate's.

use std::sync::Arc;

use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::ParsedCertificate;
use rustls::sign::CertifiedKey;

/// The most bytes either credential file may hold.
pub const CREDENTIAL_FILE_MAX: usize = 64 * 1024;

/// The most certificates the certificate file may hold, end entity
/// included.
pub const CERTIFICATE_CHAIN_MAX: usize = 8;

/// A certificate chain and the private key its end entity certifies,
/// checked to correspond.
///
/// The only constructor is [`Self::from_pem`], so a value of this type has
/// passed the strict profile and the correspondence check.
#[derive(Clone)]
pub struct ClientCertifiedKey {
    certified: Arc<CertifiedKey>,
}

impl std::fmt::Debug for ClientCertifiedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCertifiedKey")
            .field("certificates", &self.certified.cert.len())
            .finish_non_exhaustive()
    }
}

/// Why a credential file's content was refused. Blocks and lines are
/// numbered from one.
pub enum PemRefusal {
    /// The file holds more than [`CREDENTIAL_FILE_MAX`] bytes.
    TooLarge,
    /// The file holds no block.
    Empty,
    /// A line outside every block is not whitespace.
    Text {
        /// The line.
        line: usize,
    },
    /// A `-----` boundary line is malformed, has no block to end, or ends
    /// a block of another label.
    Boundary {
        /// The line.
        line: usize,
    },
    /// The block begun on `line` has no end line.
    Unterminated {
        /// The block's begin line.
        line: usize,
    },
    /// A block's body is not base64.
    Base64 {
        /// The block.
        block: usize,
    },
    /// A block whose label this profile does not know.
    UnknownBlock {
        /// The block.
        block: usize,
        /// Its label, as written.
        label: String,
    },
    /// An `ENCRYPTED PRIVATE KEY`: keys are stored unencrypted, under the
    /// key file's custody.
    EncryptedKey {
        /// The block.
        block: usize,
    },
    /// A PKCS#1 `RSA PRIVATE KEY`: the key must be PKCS#8.
    Pkcs1Key {
        /// The block.
        block: usize,
    },
    /// A SEC1 `EC PRIVATE KEY`: the key must be PKCS#8.
    Sec1Key {
        /// The block.
        block: usize,
    },
    /// A key after the first in the key file.
    SecondKey {
        /// The block.
        block: usize,
    },
    /// A key block whose bytes are not exactly one PKCS#8 structure at its
    /// top level: bytes after its outer `SEQUENCE` or after its last field,
    /// a field out of order, a length that does not fit, or an attributes field.
    KeyNotOneStructure {
        /// The block.
        block: usize,
    },
    /// A private key in the certificate file.
    KeyInCertificateFile {
        /// The block.
        block: usize,
    },
    /// A certificate in the key file.
    CertificateInKeyFile {
        /// The block.
        block: usize,
    },
    /// More than [`CERTIFICATE_CHAIN_MAX`] certificates.
    TooManyCertificates,
    /// A `CERTIFICATE` block whose DER is not an X.509 certificate.
    Certificate {
        /// The block.
        block: usize,
        /// rustls's parse refusal.
        error: rustls::Error,
    },
    /// The `PRIVATE KEY` block's DER is not a key the provider can load.
    Key(rustls::Error),
}

impl std::fmt::Display for PemRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => write!(f, "larger than {CREDENTIAL_FILE_MAX} bytes"),
            Self::Empty => f.write_str("no PEM block"),
            Self::Text { line } => write!(f, "line {line}: text outside a PEM block"),
            Self::Boundary { line } => {
                write!(f, "line {line}: a malformed or unmatched PEM boundary line")
            }
            Self::Unterminated { line } => {
                write!(f, "line {line}: a PEM block with no end line")
            }
            Self::Base64 { block } => write!(f, "block {block}: malformed base64"),
            Self::UnknownBlock { block, .. } => {
                write!(f, "block {block}: an unknown PEM block")
            }
            Self::EncryptedKey { block } => write!(
                f,
                "block {block}: an encrypted private key; the key must be unencrypted PKCS#8"
            ),
            Self::Pkcs1Key { block } => write!(
                f,
                "block {block}: an RSA PRIVATE KEY (PKCS#1); the key must be PKCS#8 (PRIVATE KEY)"
            ),
            Self::Sec1Key { block } => write!(
                f,
                "block {block}: an EC PRIVATE KEY (SEC1); the key must be PKCS#8 (PRIVATE KEY)"
            ),
            Self::SecondKey { block } => write!(
                f,
                "block {block}: a second private key; the file holds exactly one"
            ),
            Self::KeyNotOneStructure { block } => {
                write!(
                    f,
                    "block {block}: the key is not exactly one PKCS#8 structure or has an attributes field"
                )
            }
            Self::KeyInCertificateFile { block } => {
                write!(f, "block {block}: a private key in the certificate file")
            }
            Self::CertificateInKeyFile { block } => {
                write!(f, "block {block}: a certificate in the key file")
            }
            Self::TooManyCertificates => {
                write!(f, "more than {CERTIFICATE_CHAIN_MAX} certificates")
            }
            Self::Certificate { block, .. } => {
                write!(f, "block {block}: not an X.509 certificate")
            }
            Self::Key(_) => f.write_str("not a usable PKCS#8 private key"),
        }
    }
}

impl std::fmt::Debug for PemRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for PemRefusal {}

/// Why a client credential was refused.
pub enum CredentialError {
    /// The certificate file's content.
    Certificate(PemRefusal),
    /// The key file's content.
    Key(PemRefusal),
    /// The key is not the end-entity certificate's, or its correspondence
    /// cannot be established.
    Mismatch(rustls::Error),
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Certificate(refusal) => write!(f, "certificate file: {refusal}"),
            Self::Key(refusal) => write!(f, "key file: {refusal}"),
            Self::Mismatch(_) => {
                f.write_str("the key does not correspond to the end-entity certificate")
            }
        }
    }
}

impl std::fmt::Debug for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for CredentialError {}

impl ClientCertifiedKey {
    /// The credential in `certificate_pem` (the certificate file's bytes)
    /// and `key_pem` (the key file's), under the module's profile.
    ///
    /// # Errors
    ///
    /// [`CredentialError::Certificate`] or [`CredentialError::Key`] naming
    /// what the profile refused in that file, and
    /// [`CredentialError::Mismatch`] when the key is not the end entity's.
    pub fn from_pem(certificate_pem: &[u8], key_pem: &[u8]) -> Result<Self, CredentialError> {
        let chain = certificate_chain(certificate_pem).map_err(CredentialError::Certificate)?;
        let key = private_key(key_pem).map_err(CredentialError::Key)?;
        let provider = crate::crypto_provider();
        let signing_key = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(key))
            .map_err(|error| CredentialError::Key(PemRefusal::Key(error)))?;
        let certified = CertifiedKey::new(chain, signing_key);
        certified.keys_match().map_err(CredentialError::Mismatch)?;
        Ok(Self {
            certified: Arc::new(certified),
        })
    }

    /// The certificate chain, the end entity first.
    #[must_use]
    pub fn certificate_chain(&self) -> &[CertificateDer<'static>] {
        &self.certified.cert
    }

    /// The chain and key, as rustls's client certificate resolver serves
    /// them.
    pub(crate) fn certified_key(&self) -> Arc<CertifiedKey> {
        Arc::clone(&self.certified)
    }
}

/// One PEM block, as written: its label and its body lines.
struct Block<'a> {
    label: &'a [u8],
    body: Vec<&'a [u8]>,
}

const BEGIN: &[u8] = b"-----BEGIN ";
const END: &[u8] = b"-----END ";
const DASHES: &[u8] = b"-----";

/// The blocks of `input`, every line placed: whitespace outside a block, a
/// begin line, a body line, or the end line matching its begin line.
fn blocks(input: &[u8]) -> Result<Vec<Block<'_>>, PemRefusal> {
    if input.len() > CREDENTIAL_FILE_MAX {
        return Err(PemRefusal::TooLarge);
    }
    let mut found = Vec::new();
    // The open block, and the line it began on.
    let mut open: Option<(Block<'_>, usize)> = None;
    for (index, raw) in input.split(|byte| *byte == b'\n').enumerate() {
        let number = index + 1;
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        match open.take() {
            None => {
                if line.iter().all(|byte| matches!(byte, b' ' | b'\t')) {
                    continue;
                }
                if !line.starts_with(DASHES) {
                    return Err(PemRefusal::Text { line: number });
                }
                let label = begin_label(line).ok_or(PemRefusal::Boundary { line: number })?;
                open = Some((
                    Block {
                        label,
                        body: Vec::new(),
                    },
                    number,
                ));
            }
            Some((mut block, began)) => {
                if line.starts_with(DASHES) {
                    if end_label(line) != Some(block.label) {
                        return Err(PemRefusal::Boundary { line: number });
                    }
                    found.push(block);
                } else {
                    block.body.push(line);
                    open = Some((block, began));
                }
            }
        }
    }
    if let Some((_, began)) = open {
        return Err(PemRefusal::Unterminated { line: began });
    }
    if found.is_empty() {
        return Err(PemRefusal::Empty);
    }
    Ok(found)
}

/// The label of a `-----BEGIN <label>-----` line, if `line` is exactly one.
fn begin_label(line: &[u8]) -> Option<&[u8]> {
    boundary_label(line, BEGIN)
}

/// The label of a `-----END <label>-----` line, if `line` is exactly one.
fn end_label(line: &[u8]) -> Option<&[u8]> {
    boundary_label(line, END)
}

/// The label between `prefix` and the closing dashes. A label is printable
/// ASCII with no `-`, neither starting nor ending with a space
/// (RFC 7468 §3, narrowed).
fn boundary_label<'a>(line: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let label = line.strip_prefix(prefix)?.strip_suffix(DASHES)?;
    let printable = label
        .iter()
        .all(|byte| (b' '..=b'~').contains(byte) && *byte != b'-');
    let trimmed = label.first() != Some(&b' ') && label.last() != Some(&b' ');
    (!label.is_empty() && printable && trimmed).then_some(label)
}

/// The block re-rendered with LF line ends, for `rustls-pki-types` to
/// decode, after every body line was checked to be base64 alone.
fn normalised(block: &Block<'_>, number: usize) -> Result<Vec<u8>, PemRefusal> {
    let base64 = |line: &&[u8]| {
        !line.is_empty()
            && line
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    };
    if block.body.is_empty() || !block.body.iter().all(base64) {
        return Err(PemRefusal::Base64 { block: number });
    }
    let mut out = Vec::new();
    out.extend_from_slice(BEGIN);
    out.extend_from_slice(block.label);
    out.extend_from_slice(DASHES);
    out.push(b'\n');
    for line in &block.body {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.extend_from_slice(END);
    out.extend_from_slice(block.label);
    out.extend_from_slice(DASHES);
    out.push(b'\n');
    Ok(out)
}

/// What a block's label is, for this profile.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Certificate,
    Pkcs8Key,
    EncryptedKey,
    Pkcs1Key,
    Sec1Key,
    Unknown,
}

impl Kind {
    fn of(label: &[u8]) -> Self {
        match label {
            b"CERTIFICATE" => Self::Certificate,
            b"PRIVATE KEY" => Self::Pkcs8Key,
            b"ENCRYPTED PRIVATE KEY" => Self::EncryptedKey,
            b"RSA PRIVATE KEY" => Self::Pkcs1Key,
            b"EC PRIVATE KEY" => Self::Sec1Key,
            _ => Self::Unknown,
        }
    }
}

/// The longest label a refusal repeats.
const LABEL_SHOWN_MAX: usize = 64;

fn unknown(block: usize, label: &[u8]) -> PemRefusal {
    let shown = label.get(..LABEL_SHOWN_MAX).unwrap_or(label);
    PemRefusal::UnknownBlock {
        block,
        label: String::from_utf8_lossy(shown).into_owned(),
    }
}

/// The certificate file's chain: every block a `CERTIFICATE` that parses.
fn certificate_chain(input: &[u8]) -> Result<Vec<CertificateDer<'static>>, PemRefusal> {
    let mut chain = Vec::new();
    for (index, block) in blocks(input)?.iter().enumerate() {
        let number = index + 1;
        match Kind::of(block.label) {
            Kind::Certificate => {}
            Kind::Pkcs8Key | Kind::EncryptedKey | Kind::Pkcs1Key | Kind::Sec1Key => {
                return Err(PemRefusal::KeyInCertificateFile { block: number });
            }
            Kind::Unknown => return Err(unknown(number, block.label)),
        }
        if chain.len() == CERTIFICATE_CHAIN_MAX {
            return Err(PemRefusal::TooManyCertificates);
        }
        let pem = normalised(block, number)?;
        let der = CertificateDer::from_pem_slice(&pem)
            .map_err(|_| PemRefusal::Base64 { block: number })?;
        ParsedCertificate::try_from(&der).map_err(|error| PemRefusal::Certificate {
            block: number,
            error,
        })?;
        chain.push(der);
    }
    Ok(chain)
}

/// One DER element at the front of `input`: its tag, its contents, and
/// what follows it. `None` unless the tag is one byte and the length is
/// definite, in its shortest form, and fits in what follows.
fn element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        // Long form: one to four length bytes, no leading zero, and a
        // length the short form could not have carried.
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let (bytes, rest) = rest.split_at(count);
        if bytes.first() == Some(&0) {
            return None;
        }
        let len = bytes
            .iter()
            .fold(0usize, |len, &byte| (len << 8) | usize::from(byte));
        if len < 0x80 {
            return None;
        }
        (len, rest)
    };
    if rest.len() < len {
        return None;
    }
    let (contents, after) = rest.split_at(len);
    Some((tag, contents, after))
}

/// Whether `der` is exactly one PKCS#8 structure (RFC 5958's
/// `OneAsymmetricKey`) at its top level: a `SEQUENCE` holding, in order,
/// the version `INTEGER`, the algorithm `SEQUENCE`, the key `OCTET STRING`,
/// then at most the `[1]` public key, no attributes, and nothing after
/// either level. The fields' contents are the provider's to judge; it
/// does not promise to read every byte of them.
fn is_one_pkcs8(der: &[u8]) -> bool {
    let Some((0x30, mut body, [])) = element(der) else {
        return false;
    };
    for want in [0x02, 0x30, 0x04] {
        match element(body) {
            Some((tag, _, rest)) if tag == want => body = rest,
            _ => return false,
        }
    }
    if let Some((0x81, _, rest)) = element(body) {
        body = rest;
    }
    body.is_empty()
}

/// The key file's key: exactly one block, an unencrypted PKCS#8 key.
fn private_key(input: &[u8]) -> Result<PrivatePkcs8KeyDer<'static>, PemRefusal> {
    let mut key = None;
    for (index, block) in blocks(input)?.iter().enumerate() {
        let number = index + 1;
        let kind = Kind::of(block.label);
        if key.is_some() && kind != Kind::Certificate && kind != Kind::Unknown {
            return Err(PemRefusal::SecondKey { block: number });
        }
        match kind {
            Kind::Pkcs8Key => {}
            Kind::EncryptedKey => return Err(PemRefusal::EncryptedKey { block: number }),
            Kind::Pkcs1Key => return Err(PemRefusal::Pkcs1Key { block: number }),
            Kind::Sec1Key => return Err(PemRefusal::Sec1Key { block: number }),
            Kind::Certificate => {
                return Err(PemRefusal::CertificateInKeyFile { block: number });
            }
            Kind::Unknown => return Err(unknown(number, block.label)),
        }
        let pem = normalised(block, number)?;
        let der = PrivatePkcs8KeyDer::from_pem_slice(&pem)
            .map_err(|_| PemRefusal::Base64 { block: number })?;
        // The provider does not promise to exhaust the top level in
        // every build, so its shape and bounds are checked here.
        if !is_one_pkcs8(der.secret_pkcs8_der()) {
            return Err(PemRefusal::KeyNotOneStructure { block: number });
        }
        key = Some(der);
    }
    key.ok_or(PemRefusal::Empty)
}
