// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::filesystem::ReplyError;
use crate::{Callback, CallbackOutcome, MountError};

fn action(
    fs: &GranaryFs<MutableBackend>,
    callback: Callback,
    ino: INodeNo,
    file: fuser::FileHandle,
    directory: fuser::FileHandle,
    sink: &mut LiveSink,
) -> Result<(), ReplyError> {
    match callback {
        Callback::Lookup => fs.lookup_entry(INodeNo::ROOT, b"file").map(|_| ()),
        Callback::Getattr => fs.getattr_attr(ino).map(|_| ()),
        Callback::Readdir => fs.directory_entries_handle(1, directory, 0, sink),
        Callback::Readdirplus => fs.directory_entries_plus_handle(1, directory, 0, sink),
        Callback::Read => fs
            .read_handle_bytes(ino, file, 0, 1)
            .map(|bytes| assert_eq!(bytes, b"Z")),
        actual => panic!("unexpected query callback: {actual:?}"),
    }
}

fn terminal(callback: Callback, site: &'static str, cause: MountError) {
    let mut fs = bound_adapter();
    let observer = Arc::new(Replies::default());
    fs.observer = Some(observer.clone());
    let (attr, file) = fs
        .create_overlay(
            INodeNo::ROOT,
            b"file",
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(2)),
        )
        .unwrap();
    let ino = INodeNo(attr.ino);
    let file = file.unwrap();
    fs.write_overlay(ino, file, 0, b"x").unwrap();
    let directory = fs.opendir_handle(INodeNo::ROOT).unwrap();
    let mut valid_sink = LiveSink::default();
    let valid = fs.completed(
        callback,
        action(&fs, callback, ino, file, directory, &mut valid_sink),
    );
    assert_eq!(
        (valid, observer.0.lock().unwrap().clone()),
        (Ok(()), vec![(callback, CallbackOutcome::Ok)])
    );
    if matches!(callback, Callback::Readdir | Callback::Readdirplus) {
        assert_eq!(
            valid_sink.plain.len() + valid_sink.plus.len(),
            3,
            "nonempty dots/file listing control"
        );
    }
    observer.0.lock().unwrap().clear();
    fs.write_inner(|inner| {
        inner.backend.failure = Some((site, cause));
        Ok(())
    })
    .unwrap();
    let mut sink = LiveSink::default();
    let result = fs.completed(
        callback,
        action(&fs, callback, ino, file, directory, &mut sink),
    );
    let completions = observer.0.lock().unwrap().clone();
    let failures = fs
        .write_inner(|inner| Ok(inner.backend.failures_seen))
        .unwrap();
    assert_eq!(
        (
            result,
            completions,
            failures,
            sink.plain.len() + sink.plus.len()
        ),
        (
            Err(fuser::Errno::EIO),
            vec![(callback, CallbackOutcome::Failed(cause))],
            1,
            0
        ),
        "one terminal failure, one reached fault, no successful listing offer: callback={callback:?}, site={site}"
    );
    eprintln!(
        "callback={callback:?}; fault={cause:?}; terminal=(EIO, Failed({cause:?}), 1); reached faults=1; successful replies=0"
    );
}

#[test]
fn indexed_lookup_fault_has_one_typed_terminal() {
    terminal(Callback::Lookup, "overlay_lookup", MountError::Io);
}

#[test]
fn indexed_getattr_fault_has_one_typed_terminal() {
    terminal(Callback::Getattr, "overlay_path", MountError::Io);
}

#[test]
fn indexed_readdir_fault_has_one_typed_terminal_and_no_rows() {
    terminal(Callback::Readdir, "overlay_children", MountError::Io);
}

#[test]
fn indexed_readdirplus_fault_has_one_typed_terminal_and_no_rows() {
    terminal(Callback::Readdirplus, "overlay_children", MountError::Io);
}

#[test]
fn indexed_read_fault_has_one_typed_terminal() {
    terminal(Callback::Read, "overlay_object", MountError::Io);
}

#[test]
fn unavailable_read_has_one_typed_terminal() {
    terminal(Callback::Read, "read_object", MountError::Unavailable);
}

#[test]
fn corrupt_read_has_one_typed_terminal() {
    terminal(Callback::Read, "read_object", MountError::Corrupt);
}
