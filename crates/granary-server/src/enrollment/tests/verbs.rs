// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The verbs: the round trip, every refusal with the file unchanged, the
//! bounds, the door, the write's order, the lock, and the credential's
//! two spellings.

use std::os::unix::fs::FileTypeExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use granary_core::enrollment::{
    CREDENTIALS_MAX, ClientSpkiDigest, EnrollmentSet, MintError, PRINCIPALS_MAX, PrincipalState,
    SetChangeError, WrittenFormError, decode_set,
};

use super::super::UnavailableReason;
use super::super::reader::Lookup;
use super::super::verbs::{
    CredentialError, ListReport, VerbError, VerbRefusal, attach_on, list_on, mint_on,
    resolve_credential, retire_on, revoke_on,
};
use super::{Door, Fx, OPTS, PartialDoor, block_on, digest, fifo, id, ino, one, temp, tenant};
use crate::protected_dir::NixOps;
use crate::protected_dir::tests::{Call, Pause, Phase, Recorder, chmod, is_root};

/// A setup step for one case of a table.
type Setup<'a> = &'a dyn Fn(&Fx);
#[track_caller]
fn refusal(result: Result<impl std::fmt::Debug, VerbError>) -> VerbRefusal {
    match result {
        Err(VerbError::Refused(r)) => r,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[track_caller]
fn change_refusal(result: Result<impl std::fmt::Debug, VerbError>) -> SetChangeError {
    match refusal(result) {
        VerbRefusal::Change(e) => e,
        other => panic!("expected a set refusal, got {other}"),
    }
}

#[test]
fn the_verbs_round_trip_and_each_lookup_sees_the_last_change() {
    let fx = Fx::new("enr-round");
    let ops = NixOps;
    let reader = fx.reader(Recorder::new());
    assert_eq!(
        block_on(reader.lookup(&digest(1))),
        Lookup::Unavailable(UnavailableReason::Missing)
    );

    let (p, d) = mint_on(
        &ops,
        &fx.dir,
        OPTS,
        &tenant("acme"),
        digest(1),
        &mut Door::of(&[7]),
    )
    .unwrap();
    assert_eq!((p, d), (id(7), digest(1)));
    assert_eq!(
        block_on(reader.lookup(&digest(1))),
        Lookup::Enrolled {
            principal: id(7),
            tenant: tenant("acme")
        }
    );

    attach_on(&ops, &fx.dir, OPTS, id(7), digest(2)).unwrap();
    assert!(matches!(
        block_on(reader.lookup(&digest(2))),
        Lookup::Enrolled { .. }
    ));

    // Rotation: attach the new, revoke the old.
    assert_eq!(
        revoke_on(&ops, &fx.dir, OPTS, digest(1)).unwrap(),
        (id(7), digest(1))
    );
    assert_eq!(block_on(reader.lookup(&digest(1))), Lookup::Absent);
    revoke_on(&ops, &fx.dir, OPTS, digest(2)).unwrap();
    assert_eq!(retire_on(&ops, &fx.dir, OPTS, id(7)).unwrap(), id(7));

    match list_on(&ops, &fx.dir, OPTS).unwrap() {
        ListReport::Ok(set) => {
            let principals: Vec<_> = set.principals().map(|(i, s, _)| (i, s)).collect();
            assert_eq!(principals, vec![(id(7), PrincipalState::Retired)]);
            assert_eq!(set.credential_count(), 0);
        }
        other @ ListReport::Unavailable { .. } => panic!("{other:?}"),
    }
    assert_eq!(block_on(reader.lookup(&digest(2))), Lookup::Absent);
}

#[test]
fn only_mint_accepts_a_missing_file_and_nothing_is_created_by_the_others() {
    let fx = Fx::new("enr-missing");
    let ops = NixOps;
    assert!(matches!(
        refusal(attach_on(&ops, &fx.dir, OPTS, id(1), digest(1))),
        VerbRefusal::NoSet
    ));
    assert!(matches!(
        refusal(revoke_on(&ops, &fx.dir, OPTS, digest(1))),
        VerbRefusal::NoSet
    ));
    assert!(matches!(
        refusal(retire_on(&ops, &fx.dir, OPTS, id(1))),
        VerbRefusal::NoSet
    ));
    assert_eq!(fx.bytes(), None);
    match list_on(&ops, &fx.dir, OPTS).unwrap() {
        ListReport::Unavailable { reason, .. } => assert_eq!(reason, UnavailableReason::Missing),
        other @ ListReport::Ok(_) => panic!("{other:?}"),
    }
}

#[test]
fn each_set_refusal_leaves_the_file_unchanged() {
    let fx = Fx::new("enr-refuse");
    let ops = NixOps;
    let mut set = one(1, "acme", 1);
    set.mint(id(2), tenant("beta"), digest(2)).unwrap();
    set.revoke(&digest(2)).unwrap();
    set.retire(&id(2)).unwrap();
    fx.put(&set);
    let before = fx.bytes();

    let cases: Vec<(&str, SetChangeError)> = vec![
        (
            "mint an enrolled credential",
            change_refusal(mint_on(
                &ops,
                &fx.dir,
                OPTS,
                &tenant("x"),
                digest(1),
                &mut Door::of(&[9]),
            )),
        ),
        (
            "attach to an absent principal",
            change_refusal(attach_on(&ops, &fx.dir, OPTS, id(3), digest(3))),
        ),
        (
            "attach to a retired principal",
            change_refusal(attach_on(&ops, &fx.dir, OPTS, id(2), digest(3))),
        ),
        (
            "attach an enrolled credential",
            change_refusal(attach_on(&ops, &fx.dir, OPTS, id(1), digest(1))),
        ),
        (
            "revoke an unenrolled credential",
            change_refusal(revoke_on(&ops, &fx.dir, OPTS, digest(3))),
        ),
        (
            "retire an absent principal",
            change_refusal(retire_on(&ops, &fx.dir, OPTS, id(3))),
        ),
        (
            "retire a retired principal",
            change_refusal(retire_on(&ops, &fx.dir, OPTS, id(2))),
        ),
        (
            "retire a principal holding a credential",
            change_refusal(retire_on(&ops, &fx.dir, OPTS, id(1))),
        ),
    ];
    let want = [
        SetChangeError::CredentialEnrolled,
        SetChangeError::PrincipalAbsent,
        SetChangeError::PrincipalRetired,
        SetChangeError::CredentialEnrolled,
        SetChangeError::CredentialNotEnrolled,
        SetChangeError::PrincipalAbsent,
        SetChangeError::PrincipalRetired,
        SetChangeError::PrincipalHoldsCredentials,
    ];
    for ((what, got), want) in cases.into_iter().zip(want) {
        assert_eq!(got, want, "{what}");
    }
    assert_eq!(fx.bytes(), before);
}

#[test]
fn a_corrupt_oversize_or_unprotected_set_is_refused_and_left_alone() {
    let ops = NixOps;
    let corrupt = |fx: &Fx| {
        let mut bytes = granary_core::enrollment::encode_set(&one(1, "acme", 1))
            .as_bytes()
            .to_vec();
        if let Some(b) = bytes.get_mut(20) {
            *b ^= 1;
        }
        fx.put_bytes(&bytes);
    };
    let oversize = |fx: &Fx| {
        fx.put(&one(1, "acme", 1));
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(fx.set_path())
            .unwrap();
        f.set_len(u64::try_from(granary_core::enrollment::ENCODED_MAX).unwrap() + 1)
            .unwrap();
    };
    let writable = |fx: &Fx| {
        fx.put(&one(1, "acme", 1));
        chmod(&fx.set_path(), 0o620);
    };
    let pipe = |fx: &Fx| fifo(&fx.set_path());
    let cases: [(&str, Setup<'_>, UnavailableReason); 4] = [
        ("corrupt", &corrupt, UnavailableReason::Corrupt),
        ("oversize", &oversize, UnavailableReason::Oversize),
        ("group-writable", &writable, UnavailableReason::Unprotected),
        ("a fifo", &pipe, UnavailableReason::Unprotected),
    ];
    for (what, setup, reason) in cases {
        let fx = Fx::new("enr-bad");
        setup(&fx);
        let before = std::fs::symlink_metadata(fx.set_path()).unwrap();
        let bytes = if before.file_type().is_file() {
            fx.bytes()
        } else {
            None
        };
        for result in [
            mint_on(
                &ops,
                &fx.dir,
                OPTS,
                &tenant("x"),
                digest(9),
                &mut Door::of(&[9]),
            )
            .map(|_| ()),
            attach_on(&ops, &fx.dir, OPTS, id(1), digest(9)).map(|_| ()),
            revoke_on(&ops, &fx.dir, OPTS, digest(1)).map(|_| ()),
            retire_on(&ops, &fx.dir, OPTS, id(1)).map(|_| ()),
        ] {
            let r = refusal(result);
            let ok = matches!(
                (&r, reason),
                (VerbRefusal::Corrupt(_), UnavailableReason::Corrupt)
                    | (VerbRefusal::Oversize { .. }, UnavailableReason::Oversize)
                    | (VerbRefusal::Unprotected(_), UnavailableReason::Unprotected)
            );
            assert!(ok, "{what}: {r}");
        }
        let after = std::fs::symlink_metadata(fx.set_path()).unwrap();
        assert_eq!(
            (before.ino(), before.len()),
            (after.ino(), after.len()),
            "{what}"
        );
        if before.file_type().is_file() {
            assert_eq!(fx.bytes(), bytes, "{what}");
        }
        match list_on(&ops, &fx.dir, OPTS).unwrap() {
            ListReport::Unavailable { reason: got, .. } => assert_eq!(got, reason, "{what}"),
            other @ ListReport::Ok(_) => panic!("{what}: {other:?}"),
        }
    }
}

#[test]
fn the_bounds_refuse_mint_and_attach_with_the_file_unchanged() {
    let ops = NixOps;
    // The credential bound with one principal.
    let fx = Fx::new("enr-cbound");
    let mut set = one(1, "acme", 0);
    for n in 1..CREDENTIALS_MAX {
        let mut d = [0_u8; 32];
        d[..8].copy_from_slice(&u64::try_from(n).unwrap().to_be_bytes());
        set.attach(id(1), ClientSpkiDigest::from_bytes(d)).unwrap();
    }
    fx.put(&set);
    let before = fx.bytes();
    assert_eq!(
        change_refusal(mint_on(
            &ops,
            &fx.dir,
            OPTS,
            &tenant("x"),
            digest(0xEE),
            &mut Door::of(&[9])
        )),
        SetChangeError::CredentialBoundReached
    );
    assert_eq!(
        change_refusal(attach_on(&ops, &fx.dir, OPTS, id(1), digest(0xEE))),
        SetChangeError::CredentialBoundReached
    );
    assert_eq!(fx.bytes(), before);

    // The principal bound.
    let fx = Fx::new("enr-pbound");
    let mut set = EnrollmentSet::empty();
    for n in 0..PRINCIPALS_MAX {
        let mut p = [0_u8; 16];
        p[..8].copy_from_slice(&u64::try_from(n).unwrap().to_be_bytes());
        let mut d = [0_u8; 32];
        d[..8].copy_from_slice(&u64::try_from(n).unwrap().to_be_bytes());
        set.mint(
            granary_core::enrollment::PrincipalId::from_bytes(p),
            tenant("t"),
            ClientSpkiDigest::from_bytes(d),
        )
        .unwrap();
    }
    fx.put(&set);
    let before = fx.bytes();
    assert_eq!(
        change_refusal(mint_on(
            &ops,
            &fx.dir,
            OPTS,
            &tenant("x"),
            digest(0xEE),
            &mut Door::of(&[0xFF])
        )),
        SetChangeError::PrincipalBoundReached
    );
    assert_eq!(fx.bytes(), before);
}

#[test]
fn an_entropy_failure_refuses_mint_with_the_file_unchanged() {
    let fx = Fx::new("enr-entropy");
    let ops = NixOps;
    assert!(matches!(
        refusal(mint_on(
            &ops,
            &fx.dir,
            OPTS,
            &tenant("x"),
            digest(1),
            &mut PartialDoor
        )),
        VerbRefusal::Mint(MintError::Entropy)
    ));
    assert_eq!(fx.bytes(), None);
    fx.put(&one(1, "acme", 1));
    let before = fx.bytes();
    assert!(matches!(
        refusal(mint_on(
            &ops,
            &fx.dir,
            OPTS,
            &tenant("x"),
            digest(2),
            &mut PartialDoor
        )),
        VerbRefusal::Mint(MintError::Entropy)
    ));
    assert_eq!(fx.bytes(), before);
}

#[test]
fn a_minted_id_is_all_sixteen_bytes_from_the_door() {
    let ops = NixOps;
    let a = Fx::new("enr-door-a");
    let b = Fx::new("enr-door-b");
    let (pa, _) = mint_on(
        &ops,
        &a.dir,
        OPTS,
        &tenant("x"),
        digest(1),
        &mut Door::of(&[0x11]),
    )
    .unwrap();
    let (pb, _) = mint_on(
        &ops,
        &b.dir,
        OPTS,
        &tenant("x"),
        digest(1),
        &mut Door::of(&[0x22]),
    )
    .unwrap();
    assert_eq!((pa, pb), (id(0x11), id(0x22)));
}

#[test]
fn a_retired_id_drawn_again_is_redrawn() {
    let fx = Fx::new("enr-redraw");
    let ops = NixOps;
    mint_on(
        &ops,
        &fx.dir,
        OPTS,
        &tenant("x"),
        digest(1),
        &mut Door::of(&[5]),
    )
    .unwrap();
    revoke_on(&ops, &fx.dir, OPTS, digest(1)).unwrap();
    retire_on(&ops, &fx.dir, OPTS, id(5)).unwrap();
    let (p, _) = mint_on(
        &ops,
        &fx.dir,
        OPTS,
        &tenant("x"),
        digest(2),
        &mut Door::of(&[5, 6]),
    )
    .unwrap();
    assert_eq!(p, id(6));
}

/// The calls from the temporary's creation on.
fn from_create(calls: &[Call]) -> Vec<Call> {
    let at = calls
        .iter()
        .position(|c| *c == Call::CreateExclAt(temp()))
        .expect("the temporary was created");
    calls[at..]
        .iter()
        // Ownership and mode are set before writing; this assertion isolates
        // the durability order.
        .filter(|c| !matches!(c, Call::WriteAt | Call::Fchown { .. } | Call::Fchmod { .. }))
        .cloned()
        .collect()
}

#[test]
fn the_write_is_temp_synced_renamed_then_the_directory_synced_then_the_return() {
    let fx = Fx::new("enr-order");
    let rec = Recorder::new();
    mint_on(
        &rec,
        &fx.dir,
        OPTS,
        &tenant("x"),
        digest(1),
        &mut Door::of(&[1]),
    )
    .unwrap();
    let calls = rec.calls();
    assert!(calls.contains(&Call::WriteAt), "the bytes were written");
    let tail = from_create(&calls);
    // The temporary synced is the inode now at the name.
    let set_ino = ino(&fx.set_path());
    assert_eq!(
        tail,
        vec![
            Call::CreateExclAt(temp()),
            Call::Fstat,
            Call::SyncFile { ino: set_ino },
            Call::RenameAt(temp(), super::super::SET_NAME.to_owned()),
            Call::SyncDir { ino: ino(&fx.dir) },
            // The file was missing: the parent too.
            Call::SyncDir { ino: ino(&fx.base) },
        ],
        "bootstrap: temp, file sync, rename, directory sync, parent sync, and nothing after"
    );

    rec.clear_calls();
    revoke_on(&rec, &fx.dir, OPTS, digest(1)).unwrap();
    let tail = from_create(&rec.calls());
    let set_ino = ino(&fx.set_path());
    assert_eq!(
        tail,
        vec![
            Call::CreateExclAt(temp()),
            Call::Fstat,
            Call::SyncFile { ino: set_ino },
            Call::RenameAt(temp(), super::super::SET_NAME.to_owned()),
            Call::SyncDir { ino: ino(&fx.dir) },
        ],
        "a present file: no parent sync, nothing after the directory sync"
    );
}

#[test]
fn a_failed_directory_sync_is_an_io_failure_never_success() {
    let fx = Fx::new("enr-syncfail");
    fx.put(&one(1, "acme", 1));
    let rec = Recorder::new();
    rec.set_hook(|call, phase| match (call, phase) {
        (Call::SyncDir { .. }, Phase::Before) => Err(std::io::Error::other("injected")),
        _ => Ok(()),
    });
    match revoke_on(&rec, &fx.dir, OPTS, digest(1)) {
        Err(VerbError::Io { during, .. }) => assert!(during.contains("syncing"), "{during}"),
        other => panic!("{other:?}"),
    }
}

/// The lock is the directory itself: taken on the walked descriptor
/// before the set is read, and held until after the directory sync.
#[test]
fn the_lock_is_on_the_directory_from_before_the_read_until_after_the_directory_sync() {
    let fx = Fx::new("enr-lockorder");
    fx.put(&one(1, "acme", 1));
    let dir_ino = ino(&fx.dir);
    let rec = Recorder::new();
    let probe_dir = fx.dir.clone();
    // A second open of the directory, tried without waiting: refused while
    // the verb holds the lock.
    let try_lock = move || {
        nix::fcntl::Flock::lock(
            std::fs::File::open(&probe_dir).unwrap(),
            nix::fcntl::FlockArg::LockExclusiveNonblock,
        )
        .is_ok()
    };
    let probe = try_lock.clone();
    let held_at_sync = Arc::new(std::sync::Mutex::new(None));
    let seen = Arc::clone(&held_at_sync);
    rec.set_hook(move |call, phase| {
        if *call == (Call::SyncDir { ino: dir_ino }) && phase == Phase::After {
            *seen.lock().unwrap() = Some(!probe());
        }
        Ok(())
    });
    revoke_on(&rec, &fx.dir, OPTS, digest(1)).unwrap();
    let calls = rec.calls();
    let at = |want: &Call| calls.iter().position(|c| c == want);
    let lock = at(&Call::Lock { ino: dir_ino }).expect("the directory was locked");
    let read = at(&Call::OpenReadAt(super::super::SET_NAME.to_owned())).expect("the set was read");
    assert!(lock < read, "locked before the read: {calls:?}");
    assert_eq!(
        calls
            .iter()
            .filter(|c| matches!(c, Call::Lock { .. }))
            .count(),
        1,
        "one lock, and only on the directory"
    );
    assert_eq!(
        *held_at_sync.lock().unwrap(),
        Some(true),
        "the lock was still held after the directory sync"
    );
    assert!(try_lock(), "the lock was released when the verb returned");
    assert!(!fx.dir.join("LOCK").exists(), "no lock file is created");
}

/// A file named `LOCK` left by an earlier build is neither opened nor
/// judged, whatever it is.
#[test]
fn a_leftover_lock_file_is_ignored() {
    let fx = Fx::new("enr-oldlock");
    fx.put(&one(1, "acme", 1));
    let old = fx.dir.join("LOCK");
    fifo(&old);
    let rec = Recorder::new();
    let dir = fx.dir.clone();
    let (tx, rx) = mpsc::channel();
    let ops = rec.clone();
    std::thread::spawn(move || {
        let _sent = tx.send(attach_on(&ops, &dir, OPTS, id(1), digest(2)).map(|_| ()));
    });
    rx.recv_timeout(Duration::from_secs(5))
        .expect("the verb blocked on a FIFO at LOCK")
        .unwrap();
    assert!(
        !rec.calls()
            .iter()
            .any(|c| format!("{c:?}").contains("LOCK")),
        "LOCK was consulted"
    );
    assert!(
        std::fs::symlink_metadata(&old)
            .unwrap()
            .file_type()
            .is_fifo()
    );
    assert!(
        decode_set(&fx.bytes().unwrap())
            .unwrap()
            .lookup(&digest(2))
            .is_some()
    );
}

#[test]
fn list_takes_no_lock_creates_nothing_and_reads_a_read_only_directory() {
    let fx = Fx::new("enr-listro");
    let rec = Recorder::new();
    match list_on(&rec, &fx.dir, OPTS).unwrap() {
        ListReport::Unavailable { reason, .. } => assert_eq!(reason, UnavailableReason::Missing),
        other @ ListReport::Ok(_) => panic!("{other:?}"),
    }
    assert!(
        std::fs::read_dir(&fx.dir).unwrap().next().is_none(),
        "list created nothing"
    );
    assert!(
        !rec.calls().iter().any(|c| matches!(c, Call::Lock { .. })),
        "list took the lock"
    );
    if is_root() {
        // Root writes into any directory; the read-only arm needs a plain uid.
        return;
    }
    fx.put(&one(1, "acme", 1));
    chmod(&fx.dir, 0o500);
    let listed = list_on(&NixOps, &fx.dir, OPTS);
    chmod(&fx.dir, 0o700);
    match listed.unwrap() {
        ListReport::Ok(set) => assert!(set.lookup(&digest(1)).is_some()),
        other @ ListReport::Unavailable { .. } => panic!("{other:?}"),
    }
}

#[test]
fn two_verbs_racing_both_survive_under_the_lock() {
    let fx = Fx::new("enr-race");
    fx.put(&one(1, "acme", 1));
    // A pauses inside the lock, before it writes; B starts and must wait.
    let a_ops = Recorder::new();
    let a_pause = Arc::new(Pause::default());
    let a_hook = Arc::clone(&a_pause);
    a_ops.set_hook(move |call, phase| {
        if *call == Call::CreateExclAt(temp()) && phase == Phase::Before {
            a_hook.arrive_and_wait();
        }
        Ok(())
    });
    let b_ops = Recorder::new();
    let b_locking = Arc::new(Pause::default());
    let b_hook = Arc::clone(&b_locking);
    let b_once = AtomicBool::new(false);
    b_ops.set_hook(move |call, phase| {
        if matches!(call, Call::Lock { .. })
            && phase == Phase::Before
            && !b_once.swap(true, Ordering::SeqCst)
        {
            // Arrival only: B goes on into the lock call at once.
            b_hook.release();
            b_hook.arrive_and_wait();
        }
        Ok(())
    });
    let dir = fx.dir.clone();
    let a = std::thread::spawn(move || attach_on(&a_ops, &dir, OPTS, id(1), digest(2)).map(|_| ()));
    assert!(
        a_pause.wait_arrived(Duration::from_secs(5)),
        "A reached its write"
    );
    let dir = fx.dir.clone();
    let (b_tx, b_rx) = mpsc::channel();
    let b = std::thread::spawn(move || {
        let _sent = b_tx.send(attach_on(&b_ops, &dir, OPTS, id(1), digest(3)).map(|_| ()));
    });
    assert!(
        b_locking.wait_arrived(Duration::from_secs(5)),
        "B reached the lock"
    );
    // With the lock, B cannot finish while A holds it.
    let early = b_rx.recv_timeout(Duration::from_millis(500));
    a_pause.release();
    a.join().unwrap().unwrap();
    let b_result = early
        .or_else(|_| b_rx.recv_timeout(Duration::from_secs(5)))
        .unwrap();
    b.join().unwrap();
    b_result.unwrap();
    let set = decode_set(&fx.bytes().unwrap()).unwrap();
    for n in [1, 2, 3] {
        assert!(set.lookup(&digest(n)).is_some(), "credential {n} survived");
    }
}

#[test]
fn a_leftover_temporary_is_removed_under_the_lock() {
    let fx = Fx::new("enr-leftover");
    fx.put(&one(1, "acme", 1));
    std::fs::write(fx.dir.join(temp()), b"a crashed verb's bytes").unwrap();
    attach_on(&NixOps, &fx.dir, OPTS, id(1), digest(2)).unwrap();
    assert!(!fx.dir.join(temp()).exists());
    assert!(
        decode_set(&fx.bytes().unwrap())
            .unwrap()
            .lookup(&digest(2))
            .is_some()
    );
}

#[test]
fn a_root_run_verb_leaves_files_owned_by_the_directory_owner_as_root() {
    if !is_root() {
        return;
    }
    let fx = Fx::new("enr-root");
    nix::unistd::chown(
        &fx.dir,
        Some(nix::unistd::Uid::from_raw(4242)),
        Some(nix::unistd::Gid::from_raw(4343)),
    )
    .unwrap();
    mint_on(
        &NixOps,
        &fx.dir,
        OPTS,
        &tenant("x"),
        digest(1),
        &mut Door::of(&[1]),
    )
    .unwrap();
    let meta = std::fs::metadata(fx.set_path()).unwrap();
    assert_eq!((meta.uid(), meta.gid()), (4242, 4343));
    assert_eq!(meta.mode() & 0o777, 0o600);
    let names: Vec<_> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, vec![super::super::SET_NAME], "no file but the set");
    // The server, running as the owner, reads it: judged with the owner's
    // uid, the file passes the file rule.
    let ops = Recorder::with_euid(4242);
    let reader =
        super::super::reader::ReaderOn::open(ops, &fx.dir, true, Duration::from_secs(5)).unwrap();
    assert!(matches!(
        block_on(reader.lookup(&digest(1))),
        Lookup::Enrolled { .. }
    ));
}

// ------------------------------------------------------------ credentials

#[test]
fn a_credential_is_a_written_digest_or_a_certificate_and_never_a_pasted_key() {
    let d = digest(0xAB);
    assert_eq!(resolve_credential(d.to_string().as_ref()).unwrap(), d);
    for (pasted, want) in [
        (
            "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            WrittenFormError::TlsServerPin,
        ),
        ("ed25519:00", WrittenFormError::RootSigningKey),
        ("keyid:00", WrittenFormError::KeyLocator),
    ] {
        match resolve_credential(pasted.as_ref()) {
            Err(CredentialError::Written(e)) => assert_eq!(e, want, "{pasted}"),
            other => panic!("{pasted}: {other:?}"),
        }
    }
    let upper = d.to_string().replace("ab", "AB");
    assert!(matches!(
        resolve_credential(upper.as_ref()),
        Err(CredentialError::Written(WrittenFormError::NotLowercaseHex))
    ));
    assert!(matches!(
        resolve_credential("/nonexistent/granary/cert.pem".as_ref()),
        Err(CredentialError::Certificate { .. })
    ));
}

/// The fixed Ed25519 key's seed, and its PKCS#8 v1 wrapping.
const SEED: [u8; 32] = [7; 32];
const PKCS8_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
/// The DER `SubjectPublicKeyInfo` prefix of an Ed25519 key.
const SPKI_ED25519_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
/// The digest of the fixed key's SPKI, pinned.
const CERT_DIGEST_GOLDEN: &str =
    "clientspki-v1:93e79526c1e0df8466604401028d644a19aa86d46319fc1cc6a1a083e0d6c7c5";

#[test]
fn a_certificate_digest_is_the_spki_digest_of_its_key_golden() {
    let mut pkcs8 = PKCS8_ED25519_PREFIX.to_vec();
    pkcs8.extend_from_slice(&SEED);
    let key = rcgen::KeyPair::try_from(pkcs8.as_slice()).unwrap();
    let mut spki = SPKI_ED25519_PREFIX.to_vec();
    spki.extend_from_slice(key.public_key_raw());
    let cert = rcgen::CertificateParams::new(vec!["client.test".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let fx = Fx::new("enr-cert");
    let path = fx.base.join("client.pem");
    // A key block before the certificate: the first CERTIFICATE block is
    // the one read.
    std::fs::write(&path, format!("{}{}", key.serialize_pem(), cert.pem())).unwrap();
    let got = resolve_credential(path.as_os_str()).unwrap();
    assert_eq!(
        got,
        ClientSpkiDigest::from_spki_der(&spki),
        "the complete DER SPKI is digested"
    );
    assert_eq!(got.to_string(), CERT_DIGEST_GOLDEN);
}

#[test]
fn enrollment_temporary_mode_is_0600_despite_create_mask() {
    for mode in [
        nix::sys::stat::Mode::empty(),
        nix::sys::stat::Mode::from_bits_truncate(0o777),
    ] {
        let fx = Fx::new("enr-create-mode");
        let ops = Recorder::with_create_mode(mode);
        mint_on(
            &ops,
            &fx.dir,
            OPTS,
            &tenant("acme"),
            digest(1),
            &mut Door::of(&[7]),
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(fx.set_path()).unwrap().mode() & 0o777,
            0o600,
            "enrollment publication also fixes temporary permissions"
        );
        assert_eq!(decode_set(&fx.bytes().unwrap()).unwrap(), one(7, "acme", 1));
    }
}
