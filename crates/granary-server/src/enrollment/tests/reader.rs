// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The reader: three outcomes and every unavailable reason, the reload
//! keyed on the full identity (a mode change its times do not show included), a replaced directory, the blocking pool and
//! its deadline, transient failures retried, and a lookup never answered
//! by a refresh that began before it.

use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use granary_core::enrollment::encode_set;

use super::super::reader::{Lookup, ReaderOn, ReaderStartError, SnapshotState};
use super::super::verbs::{mint_on, revoke_on};
use super::super::{SET_NAME, UnavailableReason};
use super::{Door, Fx, OPTS, block_on, digest, fifo, id, one, open_rw, tenant};
use crate::protected_dir::NixOps;
use crate::protected_dir::tests::{Call, Pause, Phase, Recorder, chmod, is_root};

/// A setup step for one case of a table.
type Setup<'a> = &'a dyn Fn(&Fx);
fn enrolled(p: u8, t: &str) -> Lookup {
    Lookup::Enrolled {
        principal: id(p),
        tenant: tenant(t),
    }
}

fn unavailable(reason: UnavailableReason) -> Lookup {
    Lookup::Unavailable(reason)
}

/// A runtime on its own thread, running `lookups` in order and sending
/// each answer.
fn lookups_on_thread(
    reader: &ReaderOn<Recorder>,
    digests: Vec<u8>,
) -> (mpsc::Receiver<Lookup>, std::thread::JoinHandle<()>) {
    let reader = reader.clone();
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        for d in digests {
            let _sent = tx.send(rt.block_on(reader.lookup(&digest(d))));
        }
    });
    (rx, handle)
}

#[test]
fn a_missing_file_starts_and_every_lookup_is_unavailable_missing() {
    let fx = Fx::new("rd-missing");
    let reader = fx.reader(Recorder::new());
    let snap = reader.snapshot();
    assert_eq!(
        snap.state,
        SnapshotState::Unavailable(UnavailableReason::Missing)
    );
    assert_eq!(snap.sequence, 1, "the constructor's refresh is the first");
    for _ in 0..2 {
        assert_eq!(
            block_on(reader.lookup(&digest(1))),
            unavailable(UnavailableReason::Missing)
        );
    }
    let snap = reader.snapshot();
    assert_eq!(snap.counters.missing, 2);
    assert_eq!(snap.counters.reload_failures, 3);
    assert_eq!(snap.sequence, 3);
}

#[test]
fn each_unreadable_set_is_unavailable_and_never_absent() {
    let put_corrupt = |fx: &Fx| {
        let mut bytes = encode_set(&one(1, "acme", 1)).as_bytes().to_vec();
        if let Some(last) = bytes.last_mut() {
            *last ^= 1;
        }
        fx.put_bytes(&bytes);
    };
    let put_oversize = |fx: &Fx| {
        fx.put(&one(1, "acme", 1));
        open_rw(&fx.set_path())
            .set_len(u64::try_from(granary_core::enrollment::ENCODED_MAX).unwrap() + 1)
            .unwrap();
    };
    let put_writable = |fx: &Fx| {
        fx.put(&one(1, "acme", 1));
        chmod(&fx.set_path(), 0o602);
    };
    let put_fifo = |fx: &Fx| fifo(&fx.set_path());
    let put_link = |fx: &Fx| {
        let elsewhere = fx.base.join("real");
        std::fs::write(&elsewhere, encode_set(&one(1, "acme", 1)).as_bytes()).unwrap();
        chmod(&elsewhere, 0o600);
        std::os::unix::fs::symlink(&elsewhere, fx.set_path()).unwrap();
    };
    let cases: [(&str, Setup<'_>, UnavailableReason); 5] = [
        ("corrupt", &put_corrupt, UnavailableReason::Corrupt),
        ("oversize", &put_oversize, UnavailableReason::Oversize),
        (
            "other-writable",
            &put_writable,
            UnavailableReason::Unprotected,
        ),
        ("a fifo", &put_fifo, UnavailableReason::Unprotected),
        ("a symbolic link", &put_link, UnavailableReason::Unprotected),
    ];
    for (what, setup, reason) in cases {
        let fx = Fx::new("rd-bad");
        setup(&fx);
        let reader = fx.reader(Recorder::new());
        assert_eq!(
            reader.snapshot().state,
            SnapshotState::Unavailable(reason),
            "{what}"
        );
        assert_eq!(
            block_on(reader.lookup(&digest(1))),
            unavailable(reason),
            "{what}"
        );
        assert_eq!(
            block_on(reader.lookup(&digest(9))),
            unavailable(reason),
            "{what}"
        );
        let counters = reader.snapshot().counters;
        let counted = match reason {
            UnavailableReason::Corrupt => counters.corrupt,
            UnavailableReason::Oversize => counters.oversize,
            _ => counters.unprotected,
        };
        assert_eq!(counted, 2, "{what}");
    }
}

#[test]
fn a_corrupt_file_is_decoded_once_per_identity() {
    let fx = Fx::new("rd-corrupt-once");
    fx.put_bytes(b"GRNENROL and then nothing that checks");
    let rec = Recorder::new();
    let reader = fx.reader(rec.clone());
    rec.clear_calls();
    for _ in 0..3 {
        assert_eq!(
            block_on(reader.lookup(&digest(1))),
            unavailable(UnavailableReason::Corrupt)
        );
    }
    assert!(
        !rec.calls()
            .iter()
            .any(|c| matches!(c, Call::OpenReadAt(_) | Call::ReadAt)),
        "an unchanged identity answers from the held verdict"
    );
}

#[test]
fn a_set_renamed_over_the_name_is_seen_by_the_next_lookup() {
    let fx = Fx::new("rd-rename");
    fx.put(&one(1, "acme", 1));
    let reader = fx.reader(Recorder::new());
    assert_eq!(block_on(reader.lookup(&digest(1))), enrolled(1, "acme"));
    fx.put(&one(1, "acme", 2));
    assert_eq!(block_on(reader.lookup(&digest(1))), Lookup::Absent);
    assert_eq!(block_on(reader.lookup(&digest(2))), enrolled(1, "acme"));
}

#[test]
fn a_rename_between_the_open_and_the_read_answers_the_opened_set() {
    let fx = Fx::new("rd-midrename");
    let rec = Recorder::new();
    let reader = fx.reader(rec.clone());
    fx.put(&one(1, "acme", 1));
    let fired = AtomicBool::new(false);
    let base = fx.base.clone();
    let name = fx.set_path();
    rec.set_hook(move |call, phase| {
        if *call == Call::OpenReadAt(SET_NAME.to_owned())
            && phase == Phase::After
            && !fired.swap(true, Ordering::SeqCst)
        {
            let next = base.join("next");
            std::fs::write(&next, encode_set(&one(1, "acme", 2)).as_bytes()).unwrap();
            chmod(&next, 0o600);
            std::fs::rename(&next, &name).unwrap();
        }
        Ok(())
    });
    // Renamed just after the open: the judgement and the read both run on
    // the opened descriptor, so the answer is the old set, whole.
    assert_eq!(block_on(reader.lookup(&digest(1))), enrolled(1, "acme"));
    // The next lookup sees the new name.
    assert_eq!(block_on(reader.lookup(&digest(1))), Lookup::Absent);
    assert_eq!(block_on(reader.lookup(&digest(2))), enrolled(1, "acme"));
}

/// Two sets of the same size: one credential each under one principal.
fn same_size_pair() -> (Vec<u8>, Vec<u8>) {
    let a = encode_set(&one(1, "acme", 1)).as_bytes().to_vec();
    let b = encode_set(&one(1, "acme", 2)).as_bytes().to_vec();
    assert_eq!(a.len(), b.len());
    (a, b)
}

#[test]
fn a_same_size_same_mtime_set_renamed_over_the_name_is_seen() {
    let fx = Fx::new("rd-samesize");
    let (a, b) = same_size_pair();
    fx.put_bytes(&a);
    let reader = fx.reader(Recorder::new());
    assert_eq!(block_on(reader.lookup(&digest(1))), enrolled(1, "acme"));
    let mtime = std::fs::metadata(fx.set_path())
        .unwrap()
        .modified()
        .unwrap();
    let next = fx.base.join("next");
    std::fs::write(&next, &b).unwrap();
    chmod(&next, 0o600);
    std::fs::File::options()
        .write(true)
        .open(&next)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    std::fs::rename(&next, fx.set_path()).unwrap();
    assert_eq!(
        std::fs::metadata(fx.set_path())
            .unwrap()
            .modified()
            .unwrap(),
        mtime
    );
    assert_eq!(block_on(reader.lookup(&digest(1))), Lookup::Absent);
}

#[test]
fn a_change_time_alone_is_seen() {
    let fx = Fx::new("rd-ctime");
    let (a, b) = same_size_pair();
    fx.put_bytes(&a);
    let rec = Recorder::with_frozen_times();
    let reader = fx.reader(rec.clone());
    assert_eq!(block_on(reader.lookup(&digest(1))), enrolled(1, "acme"));
    let reloads = reader.snapshot().counters.reloads;

    open_rw(&fx.set_path()).write_all(&b).unwrap();
    rec.set_ctime_skew(1);

    assert_eq!(block_on(reader.lookup(&digest(1))), Lookup::Absent);
    assert_eq!(block_on(reader.lookup(&digest(2))), enrolled(1, "acme"));
    assert_eq!(reader.snapshot().counters.reloads, reloads + 1);
}

/// Pins the in-place rewrite limit documented by [`crate::enrollment::Identity`]:
/// changed bytes with the same identity keep the held verdict.
#[test]
fn an_identity_equal_in_place_rewrite_keeps_the_held_verdict() {
    let fx = Fx::new("rd-inplace");
    let (a, b) = same_size_pair();
    fx.put_bytes(&a);
    let reader = fx.reader(Recorder::with_frozen_times());
    assert_eq!(block_on(reader.lookup(&digest(1))), enrolled(1, "acme"));
    let reloads = reader.snapshot().counters.reloads;

    open_rw(&fx.set_path()).write_all(&b).unwrap();

    assert_eq!(block_on(reader.lookup(&digest(1))), enrolled(1, "acme"));
    assert_eq!(block_on(reader.lookup(&digest(2))), Lookup::Absent);
    assert_eq!(reader.snapshot().counters.reloads, reloads);
}

/// A mode change the file's times do not show (two changes inside one tick
/// of a coarse filesystem clock) is still seen: an unprotected verdict is a
/// verdict about the mode, so the mode and owner are part of the identity
/// a verdict is kept against.
#[test]
fn a_mode_change_with_the_same_times_is_seen() {
    let fx = Fx::new("rd-mode");
    fx.put(&one(1, "acme", 1));
    let reader = fx.reader(Recorder::with_frozen_times());
    assert_eq!(block_on(reader.lookup(&digest(1))), enrolled(1, "acme"));
    chmod(&fx.set_path(), 0o602);
    assert_eq!(
        block_on(reader.lookup(&digest(1))),
        unavailable(UnavailableReason::Unprotected)
    );
    chmod(&fx.set_path(), 0o600);
    assert_eq!(block_on(reader.lookup(&digest(1))), enrolled(1, "acme"));
}

#[test]
fn a_replaced_directory_is_unavailable_until_restart() {
    let fx = Fx::new("rd-dir");
    let ops = NixOps;
    mint_on(
        &ops,
        &fx.dir,
        OPTS,
        &tenant("acme"),
        digest(1),
        &mut Door::of(&[1]),
    )
    .unwrap();
    let reader = fx.reader(Recorder::new());
    assert_eq!(block_on(reader.lookup(&digest(1))), enrolled(1, "acme"));

    let aside = fx.base.join("aside");
    std::fs::rename(&fx.dir, &aside).unwrap();
    std::fs::create_dir(&fx.dir).unwrap();
    chmod(&fx.dir, 0o700);
    // The operator revokes in the replacement; the old set still holds it.
    mint_on(
        &ops,
        &fx.dir,
        OPTS,
        &tenant("acme"),
        digest(1),
        &mut Door::of(&[2]),
    )
    .unwrap();
    revoke_on(&ops, &fx.dir, OPTS, digest(1)).unwrap();
    assert_eq!(
        block_on(reader.lookup(&digest(1))),
        unavailable(UnavailableReason::Directory)
    );

    // Even with the original put back, until the server restarts.
    std::fs::rename(&fx.dir, fx.base.join("second")).unwrap();
    std::fs::rename(&aside, &fx.dir).unwrap();
    assert_eq!(
        block_on(reader.lookup(&digest(1))),
        unavailable(UnavailableReason::Directory)
    );
    assert_eq!(reader.snapshot().counters.directory, 2);
    // A restart (a new reader) reads the restored directory.
    let restarted = fx.reader(Recorder::new());
    assert_eq!(block_on(restarted.lookup(&digest(1))), enrolled(1, "acme"));
}

#[test]
fn a_failed_stat_of_the_path_is_unavailable_once_and_never_latched() {
    let fx = Fx::new("rd-dir-stat");
    fx.put(&one(1, "acme", 1));
    let rec = Recorder::new();
    let reader = fx.reader(rec.clone());
    let fired = AtomicBool::new(false);
    rec.set_hook(move |call, phase| {
        if *call == Call::StatPath && phase == Phase::Before && !fired.swap(true, Ordering::SeqCst)
        {
            return Err(std::io::Error::other("injected stat failure"));
        }
        Ok(())
    });
    assert_eq!(
        block_on(reader.lookup(&digest(1))),
        unavailable(UnavailableReason::Directory)
    );
    // The same directory answers again: an error is not a mismatch.
    assert_eq!(block_on(reader.lookup(&digest(1))), enrolled(1, "acme"));
}

#[test]
fn a_stalled_refresh_answers_stalled_within_the_bound_and_is_never_duplicated() {
    let fx = Fx::new("rd-stall");
    fx.put(&one(1, "acme", 1));
    let rec = Recorder::new();
    let reader = ReaderOn::open(rec.clone(), &fx.dir, true, Duration::from_millis(300)).unwrap();
    let pause = Arc::new(Pause::default());
    let hook_pause = Arc::clone(&pause);
    let fired = AtomicBool::new(false);
    rec.set_hook(move |call, phase| {
        if *call == Call::StatPath && phase == Phase::Before && !fired.swap(true, Ordering::SeqCst)
        {
            hook_pause.arrive_and_wait();
        }
        Ok(())
    });
    rec.clear_calls();
    let (answers, worker) = lookups_on_thread(&reader, vec![1, 1]);
    assert!(
        pause.wait_arrived(Duration::from_secs(5)),
        "the refresh reached its stat"
    );
    // Status reads while the filesystem is stalled.
    let snap = reader.snapshot();
    assert_eq!(
        snap.state,
        SnapshotState::Ok {
            principals: 1,
            credentials: 1
        }
    );
    let first = answers.recv_timeout(Duration::from_secs(3));
    let second = answers.recv_timeout(Duration::from_secs(3));
    // Read while the first refresh is still stalled: a lookup that started
    // its own refresh would have replaced the flight, and no join counted.
    let joins = reader.joins_in_flight();
    pause.release();
    worker.join().unwrap();
    assert_eq!(
        first.expect("a lookup returned while the refresh was stalled"),
        unavailable(UnavailableReason::Stalled)
    );
    assert_eq!(second.unwrap(), unavailable(UnavailableReason::Stalled));
    assert_eq!(
        joins,
        Some(1),
        "the second lookup joined the stalled refresh, never started a second"
    );
    assert_eq!(reader.snapshot().counters.stalled, 2);
    // The released refresh completed; the next lookup answers.
    assert_eq!(block_on(reader.lookup(&digest(1))), enrolled(1, "acme"));
}

#[test]
fn an_io_failure_is_retried_not_cached_and_drops_the_held_set() {
    let fx = Fx::new("rd-transient");
    let rec = Recorder::new();
    let reader = fx.reader(rec.clone());
    fx.put(&one(1, "acme", 1));
    let fired = AtomicBool::new(false);
    rec.set_hook(move |call, phase| {
        if *call == Call::ReadAt && phase == Phase::Before && !fired.swap(true, Ordering::SeqCst) {
            return Err(std::io::Error::other("injected read failure"));
        }
        Ok(())
    });
    assert_eq!(
        block_on(reader.lookup(&digest(1))),
        unavailable(UnavailableReason::Unreadable)
    );
    assert_eq!(block_on(reader.lookup(&digest(1))), enrolled(1, "acme"));

    // A failure after a good set drops it: no earlier binding answers.
    fx.put(&one(1, "acme", 3));
    let fired = AtomicBool::new(false);
    rec.set_hook(move |call, phase| {
        if *call == Call::ReadAt && phase == Phase::Before && !fired.swap(true, Ordering::SeqCst) {
            return Err(std::io::Error::other("injected read failure"));
        }
        Ok(())
    });
    assert_eq!(
        block_on(reader.lookup(&digest(1))),
        unavailable(UnavailableReason::Unreadable)
    );
    assert_eq!(block_on(reader.lookup(&digest(1))), Lookup::Absent);
    let counters = reader.snapshot().counters;
    assert_eq!((counters.unreadable, counters.reloads), (2, 2));
}

/// Pause the refresh after its observation of the name; run `between`
/// while it is paused; start lookup L; release; L's answer.
fn lookup_after_a_paused_refresh(fx: &Fx, between: impl FnOnce()) -> (Lookup, Lookup) {
    let rec = Recorder::new();
    let reader = fx.reader(rec.clone());
    let pause = Arc::new(Pause::default());
    let hook_pause = Arc::clone(&pause);
    let fired = AtomicBool::new(false);
    rec.set_hook(move |call, phase| {
        if *call == Call::StatAt(SET_NAME.to_owned())
            && phase == Phase::After
            && !fired.swap(true, Ordering::SeqCst)
        {
            hook_pause.arrive_and_wait();
        }
        Ok(())
    });
    let (first, first_worker) = lookups_on_thread(&reader, vec![1]);
    assert!(
        pause.wait_arrived(Duration::from_secs(5)),
        "the refresh observed the old set"
    );
    between();
    let (late, late_worker) = lookups_on_thread(&reader, vec![1]);
    // L has joined the paused refresh before it is released.
    let (tick_tx, tick) = mpsc::channel::<()>();
    let mut joined = false;
    for _ in 0..5000 {
        if reader.joins_in_flight().is_some_and(|n| n >= 1) {
            joined = true;
            break;
        }
        let _ = tick.recv_timeout(Duration::from_millis(1));
    }
    drop(tick_tx);
    pause.release();
    assert!(joined, "the late lookup reached the refresh in flight");
    let out = (
        first.recv_timeout(Duration::from_secs(5)).unwrap(),
        late.recv_timeout(Duration::from_secs(5)).unwrap(),
    );
    first_worker.join().unwrap();
    late_worker.join().unwrap();
    out
}

#[test]
fn a_lookup_never_takes_a_refresh_that_began_before_it() {
    let fx = Fx::new("rd-order");
    let ops = NixOps;
    mint_on(
        &ops,
        &fx.dir,
        OPTS,
        &tenant("acme"),
        digest(1),
        &mut Door::of(&[1]),
    )
    .unwrap();
    let (first, late) = lookup_after_a_paused_refresh(&fx, || {
        revoke_on(&ops, &fx.dir, OPTS, digest(1)).unwrap();
    });
    assert_eq!(
        first,
        enrolled(1, "acme"),
        "the refresh that began before the revoke"
    );
    assert_eq!(late, Lookup::Absent, "a lookup after the revoke returned");
}

#[test]
fn a_lookup_never_takes_a_refresh_that_began_before_a_directory_replacement() {
    let fx = Fx::new("rd-order-dir");
    let ops = NixOps;
    mint_on(
        &ops,
        &fx.dir,
        OPTS,
        &tenant("acme"),
        digest(1),
        &mut Door::of(&[1]),
    )
    .unwrap();
    let (first, late) = lookup_after_a_paused_refresh(&fx, || {
        std::fs::rename(&fx.dir, fx.base.join("aside")).unwrap();
        std::fs::create_dir(&fx.dir).unwrap();
        chmod(&fx.dir, 0o700);
    });
    assert_eq!(first, enrolled(1, "acme"));
    assert_eq!(late, unavailable(UnavailableReason::Directory));
}

#[test]
fn an_unsearchable_directory_refuses_startup() {
    if is_root() {
        // Root searches any directory; the arm needs a plain uid.
        return;
    }
    let fx = Fx::new("rd-search");
    chmod(&fx.dir, 0o400);
    let result = ReaderOn::open(Recorder::new(), &fx.dir, true, Duration::from_secs(1));
    chmod(&fx.dir, 0o700);
    assert!(
        matches!(result, Err(ReaderStartError::NotSearchable { .. })),
        "{result:?}"
    );
}

#[test]
fn an_unprotected_directory_refuses_startup() {
    let fx = Fx::new("rd-unprotected");
    chmod(&fx.dir, 0o770);
    assert!(matches!(
        ReaderOn::open(Recorder::new(), &fx.dir, true, Duration::from_secs(1)),
        Err(ReaderStartError::Directory(_))
    ));
}

#[test]
fn the_snapshot_carries_the_counts_the_sequence_and_the_reloads() {
    let fx = Fx::new("rd-snap");
    let mut set = one(1, "acme", 1);
    set.attach(id(1), digest(2)).unwrap();
    set.mint(id(2), tenant("beta"), digest(3)).unwrap();
    fx.put(&set);
    let reader = fx.reader(Recorder::new());
    let snap = reader.snapshot();
    assert_eq!(
        snap.state,
        SnapshotState::Ok {
            principals: 2,
            credentials: 3
        }
    );
    assert_eq!((snap.sequence, snap.counters.reloads), (1, 1));
    assert_eq!(block_on(reader.lookup(&digest(3))), enrolled(2, "beta"));
    let snap = reader.snapshot();
    assert_eq!(
        (snap.sequence, snap.counters.reloads),
        (2, 1),
        "an unchanged file is not reloaded"
    );
    std::fs::remove_file(fx.set_path()).unwrap();
    assert_eq!(
        block_on(reader.lookup(&digest(3))),
        unavailable(UnavailableReason::Missing)
    );
    assert_eq!(
        reader.snapshot().state,
        SnapshotState::Unavailable(UnavailableReason::Missing)
    );
}

#[test]
fn a_set_file_of_another_owner_is_unprotected_as_root() {
    if !is_root() {
        return;
    }
    let fx = Fx::new("rd-owner");
    fx.put(&one(1, "acme", 1));
    nix::unistd::chown(&fx.set_path(), Some(nix::unistd::Uid::from_raw(4242)), None).unwrap();
    let reader = fx.reader(Recorder::new());
    assert_eq!(
        block_on(reader.lookup(&digest(1))),
        unavailable(UnavailableReason::Unprotected)
    );
}
