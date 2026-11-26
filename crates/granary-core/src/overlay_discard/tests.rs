// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn v1_selection_and_text_vectors() {
    let volume = VolumeName::from_bytes(b"vol").unwrap();
    let writer = [2; 16];
    let id = incarnation(
        b"/store",
        &[1; 32],
        &volume,
        &writer,
        &[(
            b"journal".to_vec(),
            Some((3, *crate::hash::GrainId::of(b"abc").digest())),
        )],
        &[],
    )
    .unwrap();
    assert_eq!(
        hex(&id),
        "63d0bf4e1f91ac1badce38f18d6b6ab01c1a9cb310a5ff1e214eeab6391634b9"
    );
    let row = Row {
        scope: [1; 32],
        name: DiscardName {
            volume,
            writer,
            incarnation: id,
        },
        bytes: 3,
        outcome: Outcome::Live(1),
    };
    for intent in [false, true] {
        let leaf = row.name.leaf(intent);
        assert_eq!(
            DiscardName::parse(leaf.as_bytes()),
            Ok(Some((row.name.clone(), intent)))
        );
        assert!(DiscardName::parse(leaf.replace("v1", "v2").as_bytes()).is_err());
    }
    let text = row.to_string();
    assert_eq!(Row::parse(text.as_bytes()), Ok(row));
    assert!(Row::parse(text.trim_end().as_bytes()).is_err());
    assert!(Row::parse(text.replace("\t3\t", "\t03\t").as_bytes()).is_err());
}
