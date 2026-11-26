// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Incremental bounded framing; cancellation closes the stream at the caller.

use granary_core::mount_control::{self as wire, Message};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{UnixListener, UnixStream},
};

pub(super) fn malformed(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

pub(super) trait Stream: AsyncRead + AsyncWrite + Unpin + Send {
    fn peer_uid(&self) -> io::Result<u32>;
}
impl Stream for UnixStream {
    fn peer_uid(&self) -> io::Result<u32> {
        self.peer_cred().map(|peer| peer.uid())
    }
}
pub(super) trait Listener {
    type Stream: Stream;
    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<Self::Stream>>;
}
impl Listener for UnixListener {
    type Stream = UnixStream;
    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<UnixStream>> {
        UnixListener::poll_accept(self, cx).map(|result| result.map(|(stream, _)| stream))
    }
}

fn allocate_body(prefix: [u8; 4], allocate: impl FnOnce(usize) -> Vec<u8>) -> io::Result<Vec<u8>> {
    let length = wire::frame_length(prefix).map_err(malformed)?;
    Ok(allocate(length))
}

#[derive(Default)]
pub(super) struct Reader {
    prefix: [u8; 4],
    prefix_offset: usize,
    body: Vec<u8>,
    body_offset: usize,
}
impl Reader {
    pub(super) fn poll<S: Stream>(
        &mut self,
        stream: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Message>> {
        // At most one prefix read and one body read per poll. The caller's
        // turn budget bounds aggregate work across resident connections.
        if self.prefix_offset < 4 {
            let Some(rest) = self.prefix.get_mut(self.prefix_offset..) else {
                return Poll::Ready(Err(malformed("invalid frame offset")));
            };
            let mut read = ReadBuf::new(rest);
            match Pin::new(&mut *stream).poll_read(cx, &mut read) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if read.filled().is_empty() => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated control frame prefix",
                    )));
                }
                Poll::Ready(Ok(())) => self.prefix_offset += read.filled().len(),
            }
            if self.prefix_offset != 4 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.body = match allocate_body(self.prefix, |length| vec![0; length]) {
                Ok(body) => body,
                Err(error) => return Poll::Ready(Err(error)),
            };
        }
        let Some(rest) = self.body.get_mut(self.body_offset..) else {
            return Poll::Ready(Err(malformed("invalid frame offset")));
        };
        let mut read = ReadBuf::new(rest);
        match Pin::new(stream).poll_read(cx, &mut read) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) if read.filled().is_empty() => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated control frame body",
                )));
            }
            Poll::Ready(Ok(())) => self.body_offset += read.filled().len(),
        }
        if self.body_offset < self.body.len() {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let result = wire::decode(&self.body).map_err(malformed);
        *self = Self::default();
        Poll::Ready(result)
    }

    /// # Cancellation safety
    /// Dropping this future loses partial framing state only when the caller
    /// closes its stream. It never cancels an already admitted stop.
    pub(super) async fn read<S: Stream>(&mut self, stream: &mut S) -> io::Result<Message> {
        std::future::poll_fn(|cx| self.poll(stream, cx)).await
    }
}

#[cfg(test)]
mod tests;

pub(super) struct Writer {
    bytes: Vec<u8>,
    offset: usize,
}
impl Writer {
    pub(super) fn new(message: &Message) -> io::Result<Self> {
        let body = wire::encode(message).map_err(malformed)?;
        let length = u32::try_from(body.len()).map_err(malformed)?;
        let mut bytes = length.to_be_bytes().to_vec();
        bytes.extend_from_slice(&body);
        Ok(Self { bytes, offset: 0 })
    }
    pub(super) fn poll<S: Stream>(
        &mut self,
        stream: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset == self.bytes.len() {
            return Poll::Ready(Ok(()));
        }
        let Some(rest) = self.bytes.get(self.offset..) else {
            return Poll::Ready(Err(malformed("invalid frame offset")));
        };
        match Pin::new(stream).poll_write(cx, rest) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(0)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "control frame write returned zero",
            ))),
            Poll::Ready(Ok(count)) => {
                self.offset += count;
                if self.offset == self.bytes.len() {
                    Poll::Ready(Ok(()))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }
    }
    /// # Cancellation safety
    /// The caller closes its stream on cancellation; any admitted shutdown
    /// continues. A partial Stop is never retried on another connection.
    pub(super) async fn write<S: Stream>(&mut self, stream: &mut S) -> io::Result<()> {
        std::future::poll_fn(|cx| self.poll(stream, cx)).await
    }
}
