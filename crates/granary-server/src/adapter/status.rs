// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Status selects a synchronous observation, then uses the shared response
//! memory budget and bounded content drain. No principal or read permit applies.

use super::{
    AuthorityHandle, Body, Bounds, Bytes, Full, Outcome, Response, VolumeName, drain_to_budget,
    render, render_charged,
};
use crate::authority::{TerminalState, VolumeView};
use crate::wire::StatusRefusal;

fn terminal(handle: &AuthorityHandle) -> Option<Outcome> {
    handle.terminal_state().map(|state| {
        Outcome::status_refused(match state {
            TerminalState::Fenced => StatusRefusal::Fenced,
            TerminalState::Stopped => StatusRefusal::Stopped,
        })
    })
}

fn select(handle: &AuthorityHandle, volume: &VolumeName) -> Outcome {
    if let Some(outcome) = terminal(handle) {
        return outcome;
    }
    match handle.volume_view(volume) {
        None => Outcome::status_refused(StatusRefusal::UnknownVolume),
        Some(VolumeView::NoLog) => Outcome::status_refused(StatusRefusal::NoLog),
        Some(view) => view
            .status()
            .and_then(|status| granary_core::authority_answer::encode_status(status).ok())
            .map_or_else(
                || Outcome::status_refused(StatusRefusal::Internal),
                Outcome::volume_status,
            ),
    }
}

pub(super) async fn answer<B>(
    handle: &AuthorityHandle,
    volume: &VolumeName,
    body: B,
    bounds: &Bounds<'_>,
) -> Response<Full<Bytes>>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let outcome = select(handle, volume);
    let resident = u64::try_from(outcome.body_capacity()).unwrap_or(u64::MAX);
    let (outcome, charge) = if let Some(charge) = bounds.read_budget.take(resident) {
        (outcome, Some(charge))
    } else {
        // Discard the uncharged allocation before awaiting request content.
        drop(outcome);
        (Outcome::status_refused(StatusRefusal::Unavailable), None)
    };
    let drain = drain_to_budget(body, bounds.budget).await;
    if let Some(terminal) = terminal(handle) {
        drop(outcome);
        drop(charge);
        return render(terminal, drain);
    }
    render_charged(outcome, drain, charge)
}
