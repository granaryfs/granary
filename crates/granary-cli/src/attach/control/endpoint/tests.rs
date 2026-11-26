// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use super::*;

#[test]
fn control_directory_binding_is_rechecked() {
    let scratch = crate::tests::ScratchDir::new();
    let owner = crate::admission::process_credentials().euid;
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o700)).unwrap();
    let directory = Directory {
        fd: open_directory(&scratch.0).unwrap(),
        original: scratch.0.clone(),
        owner,
    };
    directory.recheck().unwrap();
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        directory.recheck().unwrap_err().to_string(),
        "refusing: control runtime directory requires its owner and mode 0700"
    );
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o700)).unwrap();
    let displaced = scratch.0.with_extension("displaced");
    fs::rename(&scratch.0, &displaced).unwrap();
    let displaced = crate::tests::ScratchDir(displaced);
    fs::create_dir(&scratch.0).unwrap();
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        directory.recheck().unwrap_err().to_string(),
        "refusing: control runtime directory binding changed"
    );
    drop(displaced);
}

#[cfg(target_os = "linux")]
#[test]
fn daemon_linux_support_arms_from_a_prepared_endpoint_without_reopening_its_runtime_path() {
    use super::super::support::{PreparedSupport, Producer, Support};

    let scratch = crate::tests::ScratchDir::new();
    let owner = crate::admission::process_credentials().euid;
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = scratch.0.join("prepared-support.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    // As the production bind does: tokio adopts only a nonblocking listener.
    listener.set_nonblocking(true).unwrap();
    let meta = fs::symlink_metadata(&socket).unwrap();
    let lock_path = scratch.0.join("prepared-support.lock");
    fs::write(&lock_path, b"").unwrap();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path)
        .unwrap();
    let endpoint = Endpoint {
        directory: Directory {
            fd: open_directory(&scratch.0).unwrap(),
            original: scratch.0.join("covered-after-preparation"),
            owner,
        },
        name: "prepared-support.sock".to_owned(),
        inode: (meta.dev(), meta.ino()),
        listener: Some(listener),
        _lock: lock,
    };
    // The endpoint's runtime path does not exist, as when a forced mount covers
    // it: arming succeeds only if it never reopens or walks that path.
    assert!(!scratch.0.join("covered-after-preparation").exists());
    let support =
        Support::start(owner, PreparedSupport(endpoint), Producer::unavailable()).unwrap();
    drop(support);
}

#[cfg(target_os = "linux")]
fn runtime_fixture() -> crate::tests::ScratchDir {
    #[expect(
        clippy::disallowed_methods,
        reason = "process id distinguishes this fixture's exclusively owned short runtime directory from other test processes; it reaches no protocol or hashed value"
    )]
    let pid = std::process::id();
    let path = PathBuf::from(format!("/run/gc{pid}"));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    crate::tests::ScratchDir(path)
}

#[test]
fn control_custody_and_stale_endpoint() {
    let scratch = crate::tests::ScratchDir::new();
    let owner = crate::admission::process_credentials().euid;
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o700)).unwrap();
    let directory = open_directory(&scratch.0).unwrap();
    assert!(private(&directory, owner).is_ok());
    let wrong_owner = u32::from(owner == 0);
    assert_eq!(
        private(&directory, wrong_owner).unwrap_err().to_string(),
        "refusing: control runtime directory requires its owner and mode 0700"
    );
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        private(&directory, owner).unwrap_err().to_string(),
        "refusing: control runtime directory requires its owner and mode 0700"
    );
    let path = scratch.0.join("mount.lock");
    fs::write(&path, b"sentinel").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let open = || {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .unwrap()
    };
    assert_eq!(
        private(&open(), owner).unwrap_err().to_string(),
        "refusing: control runtime directory requires its owner and mode 0700"
    );
    let lock = claim_lock(open(), owner).unwrap();
    assert_eq!(
        claim_lock(open(), owner).unwrap_err().to_string(),
        "refusing: control endpoint is locked by another daemon"
    );
    drop(lock);
    assert_eq!(
        claim_lock(open(), wrong_owner).unwrap_err().to_string(),
        "refusing: control lock requires a sole regular owner-owned mode 0600 file"
    );
    fs::hard_link(&path, scratch.0.join("hard-link")).unwrap();
    assert_eq!(
        claim_lock(open(), owner).unwrap_err().to_string(),
        "refusing: control lock requires a sole regular owner-owned mode 0600 file"
    );
    assert_eq!(fs::read(&path).unwrap(), b"sentinel");
    assert!(private(&directory, owner).is_err());
    fs::remove_file(scratch.0.join("hard-link")).unwrap();
    let link = scratch.0.join("symlink-lock");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert_eq!(
        open_lock(&link, owner).unwrap_err().raw_os_error(),
        Some(libc::ELOOP)
    );
    let fifo = scratch.0.join("fifo-lock");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    fs::set_permissions(&fifo, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        open_lock(&fifo, owner).unwrap_err().to_string(),
        "refusing: control lock requires a sole regular owner-owned mode 0600 file"
    );
    let fresh = scratch.0.join("fresh.lock");
    let lock = open_lock(&fresh, owner).unwrap();
    assert_eq!(lock.metadata().unwrap().mode() & 0o7777, 0o600);
    assert_eq!(
        open_lock(&fresh, owner).unwrap_err().to_string(),
        "refusing: control endpoint is locked by another daemon"
    );
    drop(lock);
    fs::set_permissions(&fresh, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        open_lock(&fresh, owner).unwrap_err().to_string(),
        "refusing: control lock requires a sole regular owner-owned mode 0600 file"
    );
}

#[test]
fn control_endpoint_path_policy() {
    let name = socket_name((1, 2), Path::new("/mnt"));
    let support = support_socket_name((1, 2), Path::new("/mnt"));
    assert_eq!(name.len(), 69);
    assert_eq!(
        directory_name(0).join(&name).as_os_str().as_bytes().len(),
        89
    );
    assert_eq!(
        name,
        "0ac9975aca866be10aefc2b0abe1b00fab550b77bbc3f72c906f262391d34437.sock"
    );
    assert_eq!(support.len(), 69);
    assert_eq!(
        support,
        "0ac9975aca866be10aefc2b0abe1b00fab550b77bbc3f72c906f2623.support.sock"
    );
    assert_ne!(name, support, "support must never reuse the control socket");
    assert_eq!(
        directory_name(u32::MAX)
            .join(&support)
            .as_os_str()
            .as_bytes()
            .len(),
        105
    );
    assert_eq!(directory_name(0), Path::new("/run/granary-umount"));
    assert_eq!(
        directory_name(u32::MAX),
        Path::new("/run/user/4294967295/granary-umount")
    );
    let advertised = directory_name(u32::MAX).join(&name);
    assert_eq!(advertised.as_os_str().as_bytes().len(), 105);
    assert!(pathname(&advertised).is_ok());
    assert!(pathname(Path::new(&"a".repeat(107))).is_ok());
    assert_eq!(
        pathname(Path::new(&"a".repeat(108)))
            .unwrap_err()
            .to_string(),
        "refusing: control socket pathname exceeds Linux limit or contains NUL"
    );
    assert_ne!(
        socket_name((1, 2), Path::new("/mnt")),
        socket_name((1, 3), Path::new("/mnt"))
    );
    assert_ne!(
        socket_name((1, 2), Path::new(std::ffi::OsStr::from_bytes(b"/m\xff"))),
        socket_name((1, 2), Path::new("/m\u{fffd}"))
    );
}

#[cfg(target_os = "linux")]
#[test]
fn daemon_linux_control_custody_and_stale_endpoint() {
    if crate::admission::process_credentials().euid != 0 {
        eprintln!("NOT EXECUTED: control runtime filesystem fixture requires root");
        return;
    }
    let scratch = runtime_fixture();
    let directory = || Directory::open_under(&scratch.0, 0, true).unwrap();
    let target = Path::new("/fixture-mount");
    let name = socket_name((1, 2), target);
    let original = directory().original;
    let endpoint = Endpoint::bind_in(directory(), 0, (1, 2), target).unwrap();
    assert_eq!(
        Endpoint::bind_in(directory(), 0, (1, 2), target)
            .err()
            .unwrap()
            .to_string(),
        "refusing: control endpoint is locked by another daemon"
    );
    drop(endpoint);
    let stale = UnixListener::bind(original.join(&name)).unwrap();
    drop(stale);
    let mut endpoint = Endpoint::bind_in(directory(), 0, (1, 2), target).unwrap();
    let listener = endpoint.take_listener().unwrap();
    let (path, meta) = endpoint.directory.connect_path(&name, 0).unwrap();
    assert!(endpoint.directory.connection_absent(
        &name,
        &meta,
        &io::Error::from(io::ErrorKind::ConnectionRefused)
    ));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(
        endpoint
            .directory
            .recheck_socket(&name, &meta)
            .unwrap_err()
            .to_string(),
        "refusing: control endpoint requires an owner-owned mode 0600 socket"
    );
    assert!(!endpoint.directory.connection_absent(
        &name,
        &meta,
        &io::Error::from(io::ErrorKind::ConnectionRefused)
    ));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let client = std::os::unix::net::UnixStream::connect(path).unwrap();
    let (_server, _) = listener.accept().unwrap();
    drop(client);
    let old = original.join("old-socket");
    fs::rename(original.join(&name), &old).unwrap();
    let replacement = UnixListener::bind(original.join(&name)).unwrap();
    let replaced = fs::symlink_metadata(original.join(&name)).unwrap();
    drop(listener);
    drop(endpoint);
    assert_eq!(
        fs::symlink_metadata(original.join(&name)).unwrap().ino(),
        replaced.ino()
    );
    drop(replacement);
    fs::remove_file(original.join(&name)).unwrap();
    fs::write(original.join(&name), b"impostor").unwrap();
    assert_eq!(
        Endpoint::bind_in(directory(), 0, (1, 2), target)
            .err()
            .unwrap()
            .to_string(),
        "refusing: stale endpoint is not a same-owner socket"
    );
    assert_eq!(fs::read(original.join(&name)).unwrap(), b"impostor");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn daemon_linux_control_runtime_directory_loss() {
    use super::super::{
        service,
        tests::hello,
        transport::{Reader, Writer},
    };
    use granary_client::{SyncRuntime as _, TokioSyncRuntime};
    use granary_core::mount_control::{Message, ResultKind};
    if crate::admission::process_credentials().euid != 0 {
        eprintln!("NOT EXECUTED: control runtime directory loss fixture requires root");
        return;
    }
    let scratch = runtime_fixture();
    let directory = Directory::open_under(&scratch.0, 0, true).unwrap();
    let original = directory.original.clone();
    let mut endpoint =
        Endpoint::bind_in(directory, 0, (1, 2), Path::new("/fixture-mount")).unwrap();
    let listener = tokio::net::UnixListener::from_std(endpoint.take_listener().unwrap()).unwrap();
    let (publish, state) = tokio::sync::watch::channel(service::State::Serving(hello()));
    let (send, receive) = std::sync::mpsc::channel();
    let task = TokioSyncRuntime
        .spawn(async move { service::serve(&listener, state, send, 0, &TokioSyncRuntime).await });
    let (path, _) = endpoint.directory.connect_path(&endpoint.name, 0).unwrap();
    let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
    let mut reader = Reader::default();
    assert_eq!(
        reader.read(&mut stream).await.unwrap(),
        Message::Hello(hello())
    );
    Writer::new(&Message::Stop {
        instance: hello().instance,
        key: hello().key,
    })
    .unwrap()
    .write(&mut stream)
    .await
    .unwrap();
    assert_eq!(
        reader.read(&mut stream).await.unwrap(),
        Message::Accepted(hello().instance)
    );
    assert_eq!(
        receive.try_recv(),
        Ok(super::super::super::Exit::ControlUmount)
    );
    let displaced = scratch.0.join("displaced");
    fs::rename(&original, &displaced).unwrap();
    fs::create_dir(&original).unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
    let discovery = Directory::open_under(&scratch.0, 0, false).unwrap();
    assert_eq!(
        discovery
            .connect_path(&endpoint.name, 0)
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
    let replacement = UnixListener::bind(original.join(&endpoint.name)).unwrap();
    fs::set_permissions(
        original.join(&endpoint.name),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let inode = fs::symlink_metadata(original.join(&endpoint.name))
        .unwrap()
        .ino();
    assert_eq!(
        endpoint.directory.recheck().unwrap_err().to_string(),
        "refusing: control runtime directory binding changed"
    );
    let message = Message::Final {
        instance: hello().instance,
        result: ResultKind::RuntimeFailure,
        report: None,
    };
    publish.send_replace(service::State::Final {
        message: message.clone(),
        published_at: TokioSyncRuntime.now(),
    });
    assert_eq!(reader.read(&mut stream).await.unwrap(), message);
    assert!(matches!(task.await, Ok(Ok(()))));
    let name = endpoint.name.clone();
    drop(endpoint);
    assert_eq!(
        fs::symlink_metadata(original.join(name)).unwrap().ino(),
        inode
    );
    drop(replacement);
}

#[cfg(target_os = "linux")]
fn peer_child(mode: &str, path: &Path, uid: u32) -> crate::tests::OwnedChild {
    use std::os::unix::process::CommandExt as _;
    crate::tests::OwnedChild(
        crate::tests::test_command()
            .args([
                "--exact",
                "attach::control::endpoint::tests::control_linux_peer_child",
                "--nocapture",
            ])
            .env("GRANARY_CONTROL_PEER_MODE", mode)
            .env("GRANARY_CONTROL_PEER_PATH", path)
            .uid(uid)
            .gid(uid)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    )
}

#[cfg(target_os = "linux")]
#[test]
fn control_linux_peer_child() {
    use std::io::Read as _;
    let Some(mode) = std::env::var_os("GRANARY_CONTROL_PEER_MODE") else {
        return;
    };
    let path = PathBuf::from(std::env::var_os("GRANARY_CONTROL_PEER_PATH").unwrap());
    if mode == "denied" {
        assert_eq!(
            std::os::unix::net::UnixStream::connect(path)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    } else if mode == "rejected" {
        let mut stream = std::os::unix::net::UnixStream::connect(path).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut byte = [0];
        assert_eq!(
            stream.read(&mut byte).unwrap(),
            0,
            "foreign peer received protocol bytes before refusal"
        );
    } else if mode == "server" {
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        println!("READY");
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut byte = [0];
        assert_eq!(
            stream.read(&mut byte).unwrap(),
            0,
            "client sent Stop to a mismatched server uid"
        );
    } else {
        assert_eq!(mode, "owner");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            use granary_client::{SyncRuntime as _, TokioSyncRuntime};
            let stream = tokio::net::UnixStream::connect(path).await.unwrap();
            let outcome = super::super::client::exchange(
                stream,
                super::super::tests::hello().key,
                0,
                0,
                TokioSyncRuntime.now() + std::time::Duration::from_secs(2),
                &TokioSyncRuntime,
                &|_| {},
            )
            .await
            .unwrap();
            assert_eq!(outcome, super::super::super::MountOutcome::RuntimeFailure);
        });
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn daemon_linux_support_endpoint_lifecycle_and_peer_credentials() {
    use super::super::support::{Producer, Support, answer};
    use granary_client::TokioSyncRuntime;
    use granary_core::support_trigger as wire;
    use std::os::unix::net::UnixStream as StdUnixStream;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    if crate::admission::process_credentials().euid != 0 {
        eprintln!("NOT EXECUTED: support endpoint fixture requires root");
        return;
    }
    let target = Path::new("/fixture-support");
    let namespace = super::super::super::mount_table::mount_namespace().unwrap();
    let name = support_socket_name(namespace, target);
    let directory = directory_name(0);
    let path = directory.join(&name);
    let lock = directory.join(name.replace(".sock", ".lock"));

    let producer = Producer::unavailable();
    let support =
        Support::start(0, Support::prepare(0, target).unwrap(), producer.clone()).unwrap();
    assert_eq!(
        (
            name.ends_with(".support.sock"),
            fs::symlink_metadata(&path).unwrap().mode() & 0o7777,
            fs::metadata(&lock).unwrap().mode() & 0o7777,
            lock.file_name()
                .unwrap()
                .as_bytes()
                .ends_with(b".support.lock")
        ),
        (true, 0o600, 0o600, true)
    );
    let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    stream.write_all(&wire::request()).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).await.unwrap();
    let mut body = vec![0; wire::header_frame_length(prefix).unwrap()];
    stream.read_exact(&mut body).await.unwrap();
    assert_eq!(
        wire::decode_header(&body).unwrap(),
        wire::Header::Unavailable
    );
    let mut trailing = [0];
    assert_eq!(stream.read(&mut trailing).await.unwrap(), 0);

    let (server, _client) = StdUnixStream::pair().unwrap();
    server.set_nonblocking(true).unwrap();
    let server = tokio::net::UnixStream::from_std(server).unwrap();
    assert_eq!(
        answer(server, 1, 1, &producer, &TokioSyncRuntime)
            .await
            .unwrap_err()
            .to_string(),
        "refusing: support peer uid mismatch or unavailable"
    );

    drop(support);
    assert_eq!(
        fs::symlink_metadata(&path).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    drop(Support::start(0, Support::prepare(0, target).unwrap(), producer).unwrap());
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one peer-credential matrix over a live socket"
)]
async fn daemon_linux_control_linux_peer_credentials() {
    use super::super::{client, service, tests::hello};
    use granary_client::{SyncRuntime as _, TokioSyncRuntime};
    use granary_core::mount_control::{Message, ResultKind};
    if crate::admission::process_credentials().euid != 0 {
        eprintln!("NOT EXECUTED: kernel peer credential fixture requires root");
        return;
    }
    let scratch = runtime_fixture();
    let directory = Directory::open_under(&scratch.0, 0, true).unwrap();
    let endpoint = Endpoint::bind_in(directory, 0, (1, 2), Path::new("/fixture-peer")).unwrap();
    let protected = endpoint.directory.original.join(&endpoint.name);
    let mut denied = peer_child("denied", &protected, 65534);
    assert!(
        TokioSyncRuntime
            .blocking(move || denied.wait().success())
            .await
            .unwrap()
    );

    let public = scratch.0.join("public.sock");
    let listener = tokio::net::UnixListener::bind(&public).unwrap();
    fs::set_permissions(&public, fs::Permissions::from_mode(0o666)).unwrap();
    let (publish, state) = tokio::sync::watch::channel(service::State::Serving(hello()));
    let (send, receive) = std::sync::mpsc::channel();
    let task = TokioSyncRuntime
        .spawn(async move { service::serve(&listener, state, send, 0, &TokioSyncRuntime).await });
    let mut rejected = peer_child("rejected", &public, 65534);
    assert!(
        TokioSyncRuntime
            .blocking(move || rejected.wait().success())
            .await
            .unwrap()
    );
    assert_eq!(
        receive.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    );
    let mut owner = peer_child("owner", &public, 0);
    let request = TokioSyncRuntime
        .blocking(move || receive.recv_timeout(std::time::Duration::from_secs(2)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request, super::super::super::Exit::ControlUmount);
    publish.send_replace(service::State::Final {
        message: Message::Final {
            instance: hello().instance,
            result: ResultKind::RuntimeFailure,
            report: None,
        },
        published_at: TokioSyncRuntime.now(),
    });
    assert!(
        TokioSyncRuntime
            .blocking(move || owner.wait().success())
            .await
            .unwrap()
    );
    assert!(matches!(task.await, Ok(Ok(()))));

    let foreign = scratch.0.join("foreign");
    fs::create_dir(&foreign).unwrap();
    std::os::unix::fs::chown(&foreign, Some(65534), Some(65534)).unwrap();
    let path = foreign.join("server.sock");
    let mut server = peer_child("server", &path, 65534);
    let stdout = server.0.stdout.take().unwrap();
    let ready = TokioSyncRuntime.blocking(move || {
        use std::io::BufRead as _;
        let mut reader = std::io::BufReader::new(stdout);
        for _ in 0..32 {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
            if line.ends_with("READY\n") {
                return Some(reader);
            }
        }
        None
    });
    let _stdout = TokioSyncRuntime
        .timeout_at(
            TokioSyncRuntime.now() + std::time::Duration::from_secs(2),
            ready,
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let stream = tokio::net::UnixStream::connect(path).await.unwrap();
    let actual = client::exchange(
        stream,
        hello().key,
        0,
        0,
        TokioSyncRuntime.now() + std::time::Duration::from_secs(2),
        &TokioSyncRuntime,
        &|_| {},
    )
    .await;
    assert_eq!(
        actual.unwrap_err().to_string(),
        "refusing: control server peer uid mismatch or unavailable"
    );
    assert!(
        TokioSyncRuntime
            .blocking(move || server.wait().success())
            .await
            .unwrap()
    );
}
