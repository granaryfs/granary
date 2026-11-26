// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::MountError;

#[test]
fn callback_domains_and_errno_classes_are_closed() {
    assert_eq!(Callback::ALL.len(), 40);
    let names = Callback::ALL
        .iter()
        .map(|callback| callback.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(names.len(), 40);
    for callback in Callback::ALL {
        assert_eq!(Callback::parse(callback.as_str()), Some(*callback));
    }
    for callback in [
        Callback::Getxattr,
        Callback::Listxattr,
        Callback::Releasedir,
        Callback::Getlk,
        Callback::Bmap,
        Callback::Ioctl,
        Callback::Poll,
        Callback::Lseek,
        Callback::Getxtimes,
    ] {
        assert!(callback.reports_overlay_operation());
    }
    assert_eq!(Callback::parse("secret-shaped/caller-path"), None);
    for (error, expected) in [
        (fuser::Errno::EINTR, CallbackOutcome::Cancelled),
        (fuser::Errno::EROFS, CallbackOutcome::Refused),
        (fuser::Errno::ENOSYS, CallbackOutcome::Refused),
        (fuser::Errno::ENOTSUP, CallbackOutcome::Refused),
        (
            fuser::Errno::ENOSPC,
            CallbackOutcome::Failed(MountError::NoSpace),
        ),
        (
            fuser::Errno::ESTALE,
            CallbackOutcome::Failed(MountError::Stale),
        ),
        (
            fuser::Errno::EDQUOT,
            CallbackOutcome::Failed(MountError::Quota),
        ),
        (
            fuser::Errno::EAGAIN,
            CallbackOutcome::Failed(MountError::PlanningExhausted),
        ),
        (fuser::Errno::EIO, CallbackOutcome::Failed(MountError::Io)),
    ] {
        assert_eq!(CallbackOutcome::from_errno(Some(error)), expected);
    }
    assert_eq!(CallbackOutcome::from_errno(None), CallbackOutcome::Ok);
    for (error, expected) in [
        (MountError::NoSpace, fuser::Errno::ENOSPC),
        (MountError::Access, fuser::Errno::EACCES),
        (MountError::Quota, fuser::Errno::EDQUOT),
        (MountError::Stale, fuser::Errno::ESTALE),
        (MountError::PlanningExhausted, fuser::Errno::EAGAIN),
        (MountError::Corrupt, fuser::Errno::EIO),
        (MountError::Unavailable, fuser::Errno::EIO),
        (MountError::Io, fuser::Errno::EIO),
        (MountError::Closing, fuser::Errno::EROFS),
    ] {
        assert_eq!(error.errno(), expected);
    }
}
