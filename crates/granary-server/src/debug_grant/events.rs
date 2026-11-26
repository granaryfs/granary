// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded transition records, copied under the coordinator guard and emitted
//! after releasing it through the complete host dispatch. Repeated verdicts do
//! not become repeated lifecycle events; skipped revisions are not reconstructed.

use super::reader::{ReaderSnapshot, ReaderState, Reason};
use crate::diagnostics::{CaptureHandle, CaptureRevision, CaptureSlot};
use granary_core::debug_grant::{DebugGrant, GrantAction};
use std::sync::Arc;

pub(super) struct Transition {
    event: &'static str,
    reason: Option<&'static str>,
    incarnation: granary_core::debug_grant::Incarnation,
    grant: Option<Arc<DebugGrant>>,
    effective_scope: Option<granary_core::debug_grant::GrantScope>,
    slot: Option<CaptureSlot>,
    capture_revision: CaptureRevision,
}

impl Transition {
    pub(super) fn between(before: &ReaderSnapshot, after: &ReaderSnapshot) -> Option<Self> {
        if before.state == after.state && before.observed == after.observed {
            return None;
        }
        let (event, reason) = match after.state {
            ReaderState::Unread => return None,
            ReaderState::Applied => (
                match after.observed.as_ref()?.fields().action {
                    GrantAction::Issue => "debug_grant_issue",
                    GrantAction::Narrow => "debug_grant_narrow",
                    GrantAction::Revoke => "debug_grant_revoke",
                },
                None,
            ),
            ReaderState::Disabled(Reason::Revoked) => ("debug_grant_revoke", None),
            ReaderState::Disabled(Reason::StaleIncarnation) => {
                ("debug_grant_stale", Some("stale-incarnation"))
            }
            ReaderState::Disabled(reason) => ("debug_grant_refuse", Some(reason.as_str())),
        };
        Some(Self {
            event,
            reason,
            incarnation: after.incarnation,
            grant: after.observed.clone().or_else(|| after.accepted.clone()),
            effective_scope: match after.state {
                ReaderState::Applied => after.observed.as_ref().map(|g| g.fields().scope.clone()),
                _ => None,
            },
            slot: after.slot,
            capture_revision: after.capture_revision,
        })
    }

    pub(super) fn emit(self, capture: &CaptureHandle) {
        if let Some(dispatch) = capture.dispatch() {
            tracing::dispatcher::with_default(&dispatch, || {
                let fields = self.grant.as_ref().map(|grant| grant.fields());
                tracing::info!(
                    event = self.event, phase = "applied", stage = "reader",
                    outcome = if self.reason.is_some() { "refused" } else { "applied" },
                    refusal_code = self.reason,
                    incarnation = %IncarnationText(self.incarnation),
                    file_revision = fields.map(|f| f.file_revision),
                    generation = fields.map(|f| f.grant_generation),
                    capture_revision = self.capture_revision.0,
                    slot = self.slot.map(|s| s.0),
                    capture_level = "DEBUG", kind = "AuthenticatedRequest",
                    scope = ?fields.map(|f| &f.scope),
                    effective_scope = ?self.effective_scope,
                    expires_secs = fields.map(|f| f.expires_at.secs),
                    expires_nanos = fields.map(|f| f.expires_at.nanos),
                    line_ceiling = fields.map(|f| f.line_ceiling),
                    byte_ceiling = fields.map(|f| f.byte_ceiling),
                    owner = fields.and_then(|f| std::str::from_utf8(f.owner.as_bytes()).ok()),
                    reason = fields.and_then(|f| std::str::from_utf8(f.reason.as_bytes()).ok()),
                    issuer_uid = fields.map(|f| f.issuer_uid),
                    "debug grant transition"
                );
            });
        }
    }
}

pub(crate) struct IncarnationText(pub(crate) granary_core::debug_grant::Incarnation);
impl std::fmt::Display for IncarnationText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("incarnation:")?;
        for byte in self.0.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
