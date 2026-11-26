// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn novel_grain_staging_uses_the_configured_workspace() {
    let mut cases = 0;
    for (bound, expected) in [(11, Some("SyncWorkspaceExhausted")), (12, None)] {
        let (transport, mut journal, key, keys, ..) = setup();
        let tree = journal.tree();
        let id = GrainId::of(b"frozen grain");
        let prepared = crate::publish::prepare_from_state(
            &transport,
            &journal,
            tree,
            crate::HarvestStats::default(),
            &record().volume,
            &key,
            &granary_core::identity::WriterIdentity::from_bytes([7; 16]),
            Timestamp { secs: 1, nanos: 0 },
            crate::Policy::default(),
            crate::publish::RemoteState::empty(),
        )
        .await
        .unwrap();
        let state = crate::publish::state_from_head(
            &transport,
            &record().volume,
            1,
            &prepared.root_bytes,
            &keys,
        )
        .await
        .unwrap();
        journal.recovered = Some(RecoveredObjects::default());
        assert!(
            state.known.contains_key(&id),
            "prepared grain {id} is unmapped: {:?}",
            state.known
        );
        let result = super::preparation::stage_novel(
            &transport,
            &mut journal,
            &state,
            &BTreeMap::new(),
            &BTreeMap::from([(id, 12)]),
            bound,
        )
        .await
        .err()
        .map(|error| {
            (
                error.to_string(),
                crate::sync::failure_class(&crate::CoordinationError::Recovery(error)),
            )
        });
        assert_eq!(
            (
                result.as_ref().map(|(text, _)| text.as_str()),
                result.as_ref().map(|(_, class)| *class),
                journal
                    .recovered
                    .as_ref()
                    .unwrap()
                    .verified
                    .contains_key(&id)
            ),
            (
                expected,
                expected.map(|_| crate::FailureClass::Refused),
                expected.is_none()
            ),
            "bound={bound}, result={result:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}
