// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RequestClass {
    Publication,
    Preparation,
    Recovery,
    Hint,
}

type RequestTrace = ((usize, usize, usize, usize), Vec<(RequestClass, String)>);

/// The first decision and its attestation share entry position 1.
pub(super) fn open_log_positions(records: &[granary_core::authlog::Record]) -> bool {
    use granary_core::authlog::RecordBody;
    matches!(records, [decision, attestation]
        if (decision.seq(), attestation.seq()) == (1, 1)
            && matches!(decision.body(), RecordBody::Decision { .. })
            && matches!(attestation.body(), RecordBody::Attestation { .. }))
}

/// Counts and exact method/path order share one oracle; no request is discarded.
pub(super) fn request_trace(responses: &str) -> Result<RequestTrace, String> {
    let mut counts = (0, 0, 0, 0);
    let mut order = Vec::new();
    for line in responses.lines() {
        let (method, rest) = line
            .split_once(' ')
            .ok_or_else(|| format!("malformed gateway request: {line}"))?;
        let (path, _) = rest
            .split_once(' ')
            .ok_or_else(|| format!("malformed gateway request: {line}"))?;
        let class = match (method, path) {
            ("POST", "/volume/alpha/publish") => RequestClass::Publication,
            ("GET", "/volume/alpha/status" | "/volume/alpha/max-seq") => RequestClass::Preparation,
            ("PUT", path)
                if path.strip_prefix("/bin/").is_some_and(|id| {
                    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
                }) || path
                    .strip_prefix("/volume/alpha/meta/")
                    .is_some_and(|id| id.parse::<granary_core::hash::GrainId>().is_ok()) =>
            {
                RequestClass::Preparation
            }
            ("GET", path)
                if path.strip_prefix("/volume/alpha/root/").is_some_and(|seq| {
                    seq.len() == 20
                        && seq.bytes().all(|b| b.is_ascii_digit())
                        && seq.parse::<u64>().is_ok_and(|seq| seq != 0)
                }) =>
            {
                RequestClass::Recovery
            }
            ("PUT", "/volume/alpha/hint") => RequestClass::Hint,
            _ => return Err(format!("unclassified gateway request: {line}")),
        };
        match class {
            RequestClass::Publication => counts.0 += 1,
            RequestClass::Preparation => counts.1 += 1,
            RequestClass::Recovery => counts.2 += 1,
            RequestClass::Hint => counts.3 += 1,
        }
        order.push((class, format!("{method} {path}")));
    }
    Ok((counts, order))
}

pub(super) fn provenance(committed: bool, notes: &str) -> bool {
    committed
        && notes.lines().any(|l| l == "REACHED HostReply 1")
        && !notes.lines().any(|l| l == "RELEASED HostReply")
        && notes
            .lines()
            .filter(|l| *l == "GATEWAY post-dispatch unavailable")
            .count()
            == 8
}

pub(super) fn trace_and_occupancy(
    notes: &str,
    responses: &str,
    exact: &str,
    expected_replies: &[&str],
    roots: &[(u64, Vec<u8>)],
    seq: u64,
    bytes: &[u8],
) -> bool {
    post_transcripts_and_occupancy(
        notes,
        responses,
        &vec![exact; expected_replies.len()],
        expected_replies,
        roots,
        seq,
        bytes,
    )
}

pub(super) fn post_transcripts_and_occupancy(
    notes: &str,
    responses: &str,
    expected_posts: &[&str],
    expected_replies: &[&str],
    roots: &[(u64, Vec<u8>)],
    seq: u64,
    bytes: &[u8],
) -> bool {
    !expected_posts.is_empty()
        && expected_posts.iter().all(|post| !post.is_empty())
        && !expected_replies.is_empty()
        && notes
            .lines()
            .filter(|l| l.starts_with("POST "))
            .collect::<Vec<_>>()
            == expected_posts
        && responses
            .lines()
            .filter(|l| l.starts_with("POST "))
            .collect::<Vec<_>>()
            == expected_replies
        && roots == [(seq, bytes.to_vec())]
}

fn request_class_controls() {
    use RequestClass::{Hint, Preparation, Publication, Recovery};
    let probe = "GET /volume/alpha/root/00000000000000000001 404 - \n";
    let post = "POST /volume/alpha/publish 503 unavailable \n";
    let pending = format!("GET /volume/alpha/status 200 - ab\n{probe}{post}");
    let expected = Ok((
        (1, 1, 1, 0),
        vec![
            (Preparation, "GET /volume/alpha/status".into()),
            (
                Recovery,
                "GET /volume/alpha/root/00000000000000000001".into(),
            ),
            (Publication, "POST /volume/alpha/publish".into()),
        ],
    ));
    assert_eq!(request_trace(&pending), expected);
    assert!(
        request_trace(&(pending.clone() + "GET /unclassified 200 - \n")).is_err(),
        "unclassified gateway request accepted"
    );
    assert_ne!(
        request_trace(&pending.replace(&format!("{probe}{post}"), &format!("{post}{probe}"))),
        expected,
        "probe reordered after POST accepted"
    );
    assert_eq!(
        request_trace(&format!("{probe}PUT /volume/alpha/hint 204 - \n")),
        Ok((
            (0, 0, 1, 1),
            vec![
                (
                    Recovery,
                    "GET /volume/alpha/root/00000000000000000001".into()
                ),
                (Hint, "PUT /volume/alpha/hint".into())
            ]
        ))
    );
}

fn candidate_post_controls() {
    let replies = [
        "POST /volume/alpha/publish 202 - a",
        "POST /volume/alpha/publish 202 - b",
    ];
    assert!(
        post_transcripts_and_occupancy(
            "POST alpha e0 op0 a\nPOST alpha e1 op1 b\n",
            &replies.join("\n"),
            &["POST alpha e0 op0 a", "POST alpha e1 op1 b"],
            &replies,
            &[(1, b"a".to_vec())],
            1,
            b"a"
        ),
        "distinct candidate POST transcript rejected"
    );
    for notes in [
        "POST alpha e0 op0 a\nPOST alpha e0 op0 a\n",
        "POST alpha e1 op1 b\nPOST alpha e0 op0 a\n",
        "POST alpha e0 reused a\nPOST alpha e1 op1 b\n",
    ] {
        assert!(
            !post_transcripts_and_occupancy(
                notes,
                &replies.join("\n"),
                &["POST alpha e0 op0 a", "POST alpha e1 op1 b"],
                &replies,
                &[(1, b"a".to_vec())],
                1,
                b"a"
            ),
            "altered candidate POST transcript accepted: {notes}"
        );
    }
}

#[test]
fn provenance_and_occupancy_controls() {
    #[cfg(feature = "crash-points")]
    super::epochs::operation_failure_controls();
    candidate_post_controls();
    open_log_position_controls();
    request_class_controls();
    let reached = "REACHED HostReply 1\n";
    let gateway = "GATEWAY post-dispatch unavailable\n".repeat(8);
    assert!(provenance(true, &(reached.to_owned() + &gateway)));
    assert!(
        !provenance(false, &(reached.to_owned() + &gateway)),
        "pre-dispatch refusal supplied no committed decision"
    );
    assert!(
        !provenance(true, &gateway),
        "unheld reply used as dispatch-loss evidence"
    );
    assert!(!provenance(
        true,
        &(reached.to_owned() + &gateway + "RELEASED HostReply\n")
    ));
    let exact = "POST alpha epoch operation owned";
    let posts = (exact.to_owned() + "\n").repeat(8);
    let replies = "POST /volume/alpha/publish 503 unavailable \n".repeat(8);
    let roots = vec![(1, b"owned".to_vec())];
    let check = |p: &str, r: &[(u64, Vec<u8>)]| {
        trace_and_occupancy(
            p,
            &replies,
            exact,
            &["POST /volume/alpha/publish 503 unavailable "; 8],
            r,
            1,
            b"owned",
        )
    };
    assert!(check(&posts, &roots));
    assert!(trace_and_occupancy(
        "POST alpha epoch operation owned\n",
        "POST /volume/alpha/publish 202 - accepted\n",
        exact,
        &["POST /volume/alpha/publish 202 - accepted"],
        &roots,
        1,
        b"owned"
    ));
    assert!(
        !trace_and_occupancy("", "", exact, &[], &roots, 1, b"owned"),
        "empty POST domain verified no publication"
    );
    for bad in [
        posts.clone() + exact,
        posts.replace("epoch", "other"),
        posts.replace("operation", "other"),
    ] {
        assert!(!check(&bad, &roots), "altered or extra POST accepted");
    }
    assert!(
        !check(&posts, &[(1, b"foreign".to_vec())]),
        "foreign occupancy called owned"
    );
    assert!(
        !check(
            &posts,
            &[(1, b"owned".to_vec()), (2, b"successor".to_vec())]
        ),
        "successor root accepted"
    );
    assert!(!trace_and_occupancy(
        &posts,
        &replies.replace("503 unavailable", "0 transport-error"),
        exact,
        &["POST /volume/alpha/publish 503 unavailable "; 8],
        &roots,
        1,
        b"owned"
    ));
    super::support::observe("oracle::provenance_and_occupancy_controls", &[]);
}

fn open_log_position_controls() {
    use granary_core::authlog::{
        Grammar, Operation, Principal, Record, RecordBody, RootBytes, SubmissionIdentity, Tenant,
    };
    let retained = granary_core::retained_submission::decode(include_bytes!(
        "../../../granary-core/tests/vectors/retained-submission/ready.bin"
    ))
    .unwrap();
    let bytes = retained.frozen.initial_root;
    let root = granary_core::root::decode_root(&bytes).unwrap();
    let id = granary_core::hash::GrainId::of(&bytes);
    let identity = SubmissionIdentity::new(
        Tenant::new(vec![1]).unwrap(),
        Principal::new(vec![2]).unwrap(),
        Operation::new(vec![3]).unwrap(),
        id,
    );
    let decision = Record::new(
        1,
        RecordBody::Decision {
            identity: identity.clone(),
            root_seq: root.seq,
            base: root.parent,
            decided_at: root.timestamp,
            candidate: RootBytes::new(bytes.clone()).unwrap(),
        },
    )
    .unwrap();
    let attestation = Record::new(
        1,
        RecordBody::Attestation {
            identity,
            stored_id: id,
            final_root: RootBytes::new(bytes).unwrap(),
        },
    )
    .unwrap();
    let records = [decision.clone(), attestation.clone()];
    let mut grammar = Grammar::new();
    for record in &records {
        grammar.apply(record).unwrap();
    }
    assert!(
        open_log_positions(&records),
        "legal decision/attestation share entry 1: {records:?}"
    );
    for (reason, bad) in [
        ("second decision", vec![decision.clone(), decision.clone()]),
        ("missing attestation", vec![decision.clone()]),
        (
            "extra decision",
            vec![decision.clone(), attestation.clone(), decision.clone()],
        ),
        (
            "reordered attestation",
            vec![attestation.clone(), decision.clone()],
        ),
        (
            "wrong attestation position",
            vec![
                decision,
                Record::new(2, attestation.body().clone()).unwrap(),
            ],
        ),
    ] {
        assert!(
            !open_log_positions(&bad),
            "{reason} accepted as the sole open entry: {bad:?}"
        );
    }
}
