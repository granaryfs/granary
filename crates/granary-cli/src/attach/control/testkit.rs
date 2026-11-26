// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

//! Scripted readiness for the same framing and service poll loop.

use super::transport::{Listener, Stream};
use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
pub(super) struct Script {
    pub input: VecDeque<u8>,
    pub output: Vec<u8>,
    pub eof: bool,
    pub blocked: bool,
    pub peer: Option<u32>,
    pub wake: Option<Waker>,
    pub closed: bool,
    pub on_read: Option<Box<dyn FnOnce() + Send>>,
}
pub(super) struct ScriptedStream(pub Arc<Mutex<Script>>);
impl ScriptedStream {
    pub(super) fn new(input: Vec<u8>) -> (Self, Arc<Mutex<Script>>) {
        let script = Arc::new(Mutex::new(Script {
            input: input.into(),
            peer: Some(0),
            ..Script::default()
        }));
        (Self(script.clone()), script)
    }
}
impl Stream for ScriptedStream {
    fn peer_uid(&self) -> io::Result<u32> {
        self.0
            .lock()
            .unwrap()
            .peer
            .ok_or_else(|| io::Error::other("credential query failed"))
    }
}
impl Drop for ScriptedStream {
    fn drop(&mut self) {
        self.0.lock().unwrap().closed = true;
    }
}
impl AsyncRead for ScriptedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        read: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut script = self.0.lock().unwrap();
        if script.input.is_empty() && !script.eof {
            script.wake = Some(cx.waker().clone());
            return Poll::Pending;
        }
        while read.remaining() > 0 {
            let Some(byte) = script.input.pop_front() else {
                break;
            };
            read.put_slice(&[byte]);
        }
        let on_read = if script.input.is_empty() {
            script.on_read.take()
        } else {
            None
        };
        drop(script);
        if let Some(on_read) = on_read {
            on_read();
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for ScriptedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut script = self.0.lock().unwrap();
        if script.blocked {
            script.wake = Some(cx.waker().clone());
            return Poll::Pending;
        }
        script.output.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
pub(super) struct ScriptedListener {
    pub streams: Mutex<VecDeque<ScriptedStream>>,
}
impl Listener for ScriptedListener {
    type Stream = ScriptedStream;
    fn poll_accept(&self, _: &mut Context<'_>) -> Poll<io::Result<ScriptedStream>> {
        self.streams
            .lock()
            .unwrap()
            .pop_front()
            .map_or(Poll::Pending, |stream| Poll::Ready(Ok(stream)))
    }
}

pub(super) fn frame(message: &granary_core::mount_control::Message) -> Vec<u8> {
    let body = granary_core::mount_control::encode(message).unwrap();
    [
        u32::try_from(body.len()).unwrap().to_be_bytes().as_slice(),
        body.as_slice(),
    ]
    .concat()
}
