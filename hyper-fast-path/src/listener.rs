//! A [`TcpListener`] wrapper that picks the fast path's dynamic table updates
//! out of the byte stream.
//!
//! When the fast path answers an HTTP/2 request in the kernel, the server never
//! sees that request, and so never sees the entries it added to the client's
//! HPACK dynamic table. The fast path therefore prepends the entries it added
//! behind the server's back to the next message it does forward, as a frame of
//! the unassigned type [`DT_SYNC_FRAME_TYPE`] (see `server.bpf.c`).
//!
//! [`BeeperStream`] takes those frames back out of the stream before the
//! server's HTTP/2 codec ever sees them and hands them to whoever holds the
//! matching [`SyncHandle`], which is where the connection loop picks them up to
//! prime its decoder. Everything else is passed through untouched, so to the
//! codec above it the stream looks like an ordinary connection.
//!
//! Frames of type [`FC_SYNC_FRAME_TYPE`] ride along the same way and are
//! reported through a [`FlowHandle`]. They carry the number of bytes the fast
//! path answered with, which the server has to take out of the send window its
//! own codec believes it still has, see [`FlowHandle::take`].
//!
//! This mirrors the shape of `tokio_rustls`: the listener yields a stream that
//! wraps the socket and quietly handles a protocol of its own underneath the
//! one the caller speaks.

use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    task::{Context, Poll, ready},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, warn};

/// The frame type the fast path prepends its dynamic table changes under. Must
/// stay in sync with `DT_SYNC_FRAME_TYPE` in `server.bpf.c`.
const DT_SYNC_FRAME_TYPE: u8 = 0xFB;

/// The frame type the fast path reports the bytes it answered with under. Must
/// stay in sync with `FC_SYNC_FRAME_TYPE` in `server.bpf.c`.
const FC_SYNC_FRAME_TYPE: u8 = 0xFA;

/// The size of a flow control frame's body: one 32 bit count of bytes.
const FC_SYNC_BODY_LEN: usize = 4;

/// The HTTP/2 connection preface a client opens with, see section 3.5 of RFC
/// 7540. Scanning only starts once it has been seen, so an HTTP/1.1 connection
/// is passed through untouched.
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The fixed size of an HTTP/2 frame header.
const FRAME_HEADER_LEN: usize = 9;

/// The largest sync frame that is accepted. The fast path builds these itself
/// and keeps them far below this, so anything larger means the stream is not
/// carrying what we think it is.
const MAX_SYNC_FRAME: usize = 64 * 1024;

/// How many bytes are read from the socket in one go.
const READ_CHUNK: usize = 16 * 1024;

/// The dynamic table updates the fast path has sent on a connection, in the
/// order it applied them.
///
/// [`BeeperStream`] fills this in as it comes across sync frames; the
/// connection loop drains it and replays the blocks into its HPACK decoder.
#[derive(Clone, Default)]
pub struct SyncHandle {
    blocks: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl SyncHandle {
    /// Removes and returns the blocks received so far, oldest first.
    ///
    /// Each one is a raw HPACK block of literal header fields with incremental
    /// indexing, i.e. exactly the representation that makes a decoder add them
    /// to its dynamic table.
    ///
    /// The stream stops handing out bytes once it has read an update and only
    /// resumes when it has been taken, so a reader that does not drain this
    /// makes no further progress. That is what keeps the codec from decoding
    /// the very request the update belongs to before the update is applied.
    pub fn take(&self) -> Vec<Vec<u8>> {
        let mut blocks = self.blocks.lock().expect("sync handle poisoned");
        blocks.drain(..).collect()
    }

    /// Returns whether any update is waiting to be applied.
    fn is_pending(&self) -> bool {
        !self.blocks.lock().expect("sync handle poisoned").is_empty()
    }

    fn push(&self, block: Vec<u8>) {
        let mut blocks = self.blocks.lock().expect("sync handle poisoned");
        blocks.push_back(block);
    }
}

/// The bytes the fast path has answered with on a connection that the server's
/// own codec has not been told about yet.
///
/// Those bytes were written straight onto the socket, so the client's
/// connection level flow control window has already paid for them while `h2`
/// still counts them as its to spend. The connection loop drains this and hands
/// it to [`h2::server::Connection::consume_send_capacity`], which is what puts
/// the two back in step.
#[derive(Clone, Default)]
pub struct FlowHandle {
    sent: Arc<AtomicU32>,
}

impl FlowHandle {
    /// Removes and returns the bytes reported so far.
    pub fn take(&self) -> u32 {
        self.sent.swap(0, Ordering::Relaxed)
    }

    fn add(&self, sent: u32) {
        self.sent.fetch_add(sent, Ordering::Relaxed);
    }
}

/// The protocol a connection turned out to speak.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Http1,
    Http2,
}

/// Where the scanner is in the stream it is walking.
enum State {
    /// Matching the connection preface. Anything that diverges from it is not
    /// HTTP/2, and the scanner falls back to passing everything through.
    Preface { matched: usize },

    /// Collecting the nine bytes of a frame header.
    Header {
        buf: [u8; FRAME_HEADER_LEN],
        got: usize,
    },

    /// Passing on the payload of a frame that is none of our business.
    Payload { remaining: usize },

    /// Collecting the payload of a sync frame, which is taken out of the
    /// stream rather than passed on.
    Sync { block: Vec<u8>, remaining: usize },

    /// Collecting the payload of a flow control frame, which is taken out of
    /// the stream the same way.
    Flow {
        buf: [u8; FC_SYNC_BODY_LEN],
        got: usize,
    },

    /// Not HTTP/2, or no longer able to follow the framing: everything from
    /// here on is passed through untouched.
    Blind,
}

/// Walks a client's byte stream, separating the fast path's sync frames from
/// everything the HTTP/2 codec above is meant to see.
struct Scanner {
    state: State,

    /// Bytes that have been scanned and are waiting to be handed to the reader.
    out: VecDeque<u8>,

    /// Bytes that have arrived but must not be scanned yet, because an update
    /// ahead of them has not been applied. See [`Scanner::scan`].
    hold: VecDeque<u8>,

    sync: SyncHandle,
    flow: FlowHandle,
}

impl Scanner {
    fn new(sync: SyncHandle, flow: FlowHandle) -> Self {
        Self {
            state: State::Preface { matched: 0 },
            out: VecDeque::new(),
            hold: VecDeque::new(),
            sync,
            flow,
        }
    }

    /// Walks `input`, appending everything that is not one of the fast path's
    /// own frames to `out` and handing the ones it finds to the [`SyncHandle`]
    /// or the [`FlowHandle`] they belong to.
    ///
    /// Scanning stops at an update and the rest of `input` is held back, so
    /// that the request the update belongs to cannot reach the codec before
    /// the update has been applied to its dynamic table. It resumes once the
    /// update has been taken off the handle.
    fn scan(&mut self, input: &[u8]) {
        if self.sync.is_pending() {
            self.hold.extend(input.iter().copied());
            return;
        }

        let mut rest = input;

        while !rest.is_empty() {
            match &mut self.state {
                State::Blind => {
                    self.out.extend(rest.iter().copied());
                    return;
                }

                State::Preface { matched } => {
                    let n = (PREFACE.len() - *matched).min(rest.len());

                    if rest[..n] != PREFACE[*matched..*matched + n] {
                        // not an HTTP/2 connection, so there is no framing to
                        // follow and nothing to filter
                        debug!("no HTTP/2 preface, passing the connection through");

                        self.out.extend(rest.iter().copied());
                        self.state = State::Blind;
                        return;
                    }

                    self.out.extend(rest[..n].iter().copied());
                    *matched += n;
                    rest = &rest[n..];

                    if *matched == PREFACE.len() {
                        self.state = State::header();
                    }
                }

                State::Header { buf, got } => {
                    let n = (FRAME_HEADER_LEN - *got).min(rest.len());
                    buf[*got..*got + n].copy_from_slice(&rest[..n]);
                    *got += n;
                    rest = &rest[n..];

                    if *got < FRAME_HEADER_LEN {
                        return;
                    }

                    let len = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;
                    let kind = buf[3];

                    if kind == FC_SYNC_FRAME_TYPE {
                        if len != FC_SYNC_BODY_LEN {
                            warn!(
                                "flow control frame of {len}B is not the expected \
                                 {FC_SYNC_BODY_LEN}B, passing the connection through"
                            );
                            self.state = State::Blind;
                        } else {
                            self.state = State::Flow {
                                buf: [0; FC_SYNC_BODY_LEN],
                                got: 0,
                            };
                        }
                    } else if kind != DT_SYNC_FRAME_TYPE {
                        let hdr = *buf;
                        self.out.extend(hdr.iter().copied());
                        self.state = State::Payload { remaining: len };
                    } else if len > MAX_SYNC_FRAME {
                        warn!(
                            "dynamic table sync frame of {len}B is implausibly large, \
                             passing the connection through"
                        );
                        self.state = State::Blind;
                    } else {
                        // the header is dropped along with the payload, the
                        // codec above must not see either
                        self.state = State::Sync {
                            block: Vec::with_capacity(len),
                            remaining: len,
                        };
                    }
                }

                State::Payload { remaining } => {
                    let n = (*remaining).min(rest.len());
                    self.out.extend(rest[..n].iter().copied());
                    *remaining -= n;
                    rest = &rest[n..];

                    if *remaining == 0 {
                        self.state = State::header();
                    }
                }

                State::Flow { buf, got } => {
                    let n = (FC_SYNC_BODY_LEN - *got).min(rest.len());
                    buf[*got..*got + n].copy_from_slice(&rest[..n]);
                    *got += n;
                    rest = &rest[n..];

                    if *got == FC_SYNC_BODY_LEN {
                        let sent = u32::from_be_bytes(*buf);
                        debug!("received a report of {sent}B served out of band");

                        self.flow.add(sent);
                        self.state = State::header();
                    }
                }

                State::Sync { block, remaining } => {
                    let n = (*remaining).min(rest.len());
                    block.extend_from_slice(&rest[..n]);
                    *remaining -= n;
                    rest = &rest[n..];

                    if *remaining == 0 {
                        let block = std::mem::take(block);
                        debug!("received a {}B dynamic table update", block.len());

                        self.sync.push(block);
                        self.state = State::header();

                        // everything behind the update has to wait for it to
                        // be applied
                        self.hold.extend(rest.iter().copied());
                        return;
                    }
                }
            }
        }
    }
}

impl State {
    fn header() -> Self {
        Self::Header {
            buf: [0; FRAME_HEADER_LEN],
            got: 0,
        }
    }
}

/// A [`TcpStream`] with the fast path's dynamic table updates filtered out of
/// its read side. The write side is passed straight through.
pub struct BeeperStream {
    inner: TcpStream,
    scanner: Scanner,
}

impl BeeperStream {
    /// Returns the handle the dynamic table updates seen on this connection are
    /// reported through.
    pub fn sync_handle(&self) -> SyncHandle {
        self.scanner.sync.clone()
    }

    /// Returns the handle the bytes the fast path answered with on this
    /// connection are reported through.
    pub fn flow_handle(&self) -> FlowHandle {
        self.scanner.flow.clone()
    }

    /// Reads until the protocol the client speaks is known.
    ///
    /// The bytes this consumes are the ones the scanner needs to recognise the
    /// preface; they are kept and handed to the codec afterwards, so this can
    /// be called before serving the connection without losing anything.
    pub async fn protocol(&mut self) -> io::Result<Protocol> {
        loop {
            match self.scanner.state {
                State::Preface { .. } => {}
                State::Blind => return Ok(Protocol::Http1),
                _ => return Ok(Protocol::Http2),
            }

            let mut chunk = [0; READ_CHUNK];
            let n = {
                use tokio::io::AsyncReadExt;
                self.inner.read(&mut chunk).await?
            };

            if n == 0 {
                // the connection ended before it said anything, so it does not
                // matter which of the two it would have been
                return Ok(Protocol::Http1);
            }

            self.scanner.scan(&chunk[..n]);
        }
    }

    /// Moves as much of the scanned output as fits into `buf`.
    fn drain_into(&mut self, buf: &mut ReadBuf<'_>) {
        let out = &mut self.scanner.out;
        let n = out.len().min(buf.remaining());
        let (head, tail) = out.as_slices();

        let from_head = n.min(head.len());
        buf.put_slice(&head[..from_head]);
        buf.put_slice(&tail[..n - from_head]);

        out.drain(..n);
    }
}

impl AsyncRead for BeeperStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        loop {
            if !me.scanner.out.is_empty() {
                me.drain_into(buf);
                return Poll::Ready(Ok(()));
            }

            if me.scanner.sync.is_pending() {
                // an update is waiting to be applied, and nothing behind it may
                // be handed out until it has been. the reader of this stream is
                // the one that applies it (see `serve` in `h2serve.rs`), and it
                // drains the handle before every poll, so waking the task right
                // back up is what lets it get there.
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            if !me.scanner.hold.is_empty() {
                let held: Vec<u8> = me.scanner.hold.drain(..).collect();
                me.scanner.scan(&held);
                continue;
            }

            let mut chunk = [0; READ_CHUNK];
            let mut read = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut me.inner).poll_read(cx, &mut read))?;

            let n = read.filled().len();
            if n == 0 {
                // EOF, which is reported by leaving `buf` untouched
                return Poll::Ready(Ok(()));
            }

            // a chunk that held nothing but a sync frame leaves the scanner's
            // output empty, and returning here would look like EOF to the
            // caller, so keep reading until there is something to pass on
            me.scanner.scan(&chunk[..n]);
        }
    }
}

impl AsyncWrite for BeeperStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A [`TcpListener`] whose connections filter out the fast path's dynamic table
/// updates, see [`BeeperStream`].
pub struct BeeperListener {
    inner: TcpListener,
}

impl BeeperListener {
    /// Wraps `inner` so that every connection accepted from it is scanned for
    /// dynamic table updates.
    pub fn new(inner: TcpListener) -> Self {
        Self { inner }
    }

    /// Accepts a connection, see [`TcpListener::accept`].
    pub async fn accept(&self) -> io::Result<(BeeperStream, SocketAddr)> {
        let (stream, addr) = self.inner.accept().await?;

        stream.set_nodelay(true)?;

        let stream = BeeperStream {
            inner: stream,
            scanner: Scanner::new(SyncHandle::default(), FlowHandle::default()),
        };

        Ok((stream, addr))
    }

    /// Returns the address the listener is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Renders an HTTP/2 frame of type `kind` around `payload`.
    fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
        f.push(kind);
        f.push(0);
        f.extend_from_slice(&0u32.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// Feeds `chunks` through a scanner and returns what it passed on and what
    /// it took out.
    ///
    /// Updates are taken off the handle as they appear, which is what the
    /// connection loop does after applying them and what lets the scanner carry
    /// on past the barrier.
    fn scan(chunks: &[&[u8]]) -> (Vec<u8>, Vec<Vec<u8>>) {
        let sync = SyncHandle::default();
        let mut scanner = Scanner::new(sync.clone(), FlowHandle::default());
        let mut blocks = Vec::new();

        for chunk in chunks {
            scanner.scan(chunk);

            while sync.is_pending() {
                blocks.extend(sync.take());

                let held: Vec<u8> = scanner.hold.drain(..).collect();
                scanner.scan(&held);
            }
        }

        (scanner.out.into_iter().collect(), blocks)
    }

    #[test]
    fn passes_a_stream_without_sync_frames_through_untouched() {
        let mut input = PREFACE.to_vec();
        input.extend_from_slice(&frame(0x04, b"settings"));
        input.extend_from_slice(&frame(0x01, b"headers"));

        let (out, blocks) = scan(&[&input]);

        assert_eq!(out, input);
        assert!(blocks.is_empty());
    }

    #[test]
    fn takes_a_sync_frame_out_of_the_stream() {
        let mut input = PREFACE.to_vec();
        input.extend_from_slice(&frame(DT_SYNC_FRAME_TYPE, b"the-update"));
        input.extend_from_slice(&frame(0x01, b"headers"));

        let mut expected = PREFACE.to_vec();
        expected.extend_from_slice(&frame(0x01, b"headers"));

        let (out, blocks) = scan(&[&input]);

        assert_eq!(out, expected);
        assert_eq!(blocks, vec![b"the-update".to_vec()]);
    }

    #[test]
    fn finds_a_sync_frame_split_across_reads() {
        let mut input = PREFACE.to_vec();
        input.extend_from_slice(&frame(DT_SYNC_FRAME_TYPE, b"the-update"));
        input.extend_from_slice(&frame(0x01, b"headers"));

        let mut expected = PREFACE.to_vec();
        expected.extend_from_slice(&frame(0x01, b"headers"));

        // one byte at a time is the worst case the scanner has to survive
        let chunks: Vec<&[u8]> = input.chunks(1).collect();
        let (out, blocks) = scan(&chunks);

        assert_eq!(out, expected);
        assert_eq!(blocks, vec![b"the-update".to_vec()]);
    }

    #[test]
    fn keeps_several_sync_frames_in_order() {
        let mut input = PREFACE.to_vec();
        input.extend_from_slice(&frame(DT_SYNC_FRAME_TYPE, b"first"));
        input.extend_from_slice(&frame(0x01, b"headers"));
        input.extend_from_slice(&frame(DT_SYNC_FRAME_TYPE, b"second"));

        let (_, blocks) = scan(&[&input]);

        assert_eq!(blocks, vec![b"first".to_vec(), b"second".to_vec()]);
    }

    #[test]
    fn keeps_an_empty_sync_frame_out_of_the_stream() {
        let mut input = PREFACE.to_vec();
        input.extend_from_slice(&frame(DT_SYNC_FRAME_TYPE, b""));
        input.extend_from_slice(&frame(0x01, b"headers"));

        let mut expected = PREFACE.to_vec();
        expected.extend_from_slice(&frame(0x01, b"headers"));

        let (out, blocks) = scan(&[&input]);

        assert_eq!(out, expected);
        assert_eq!(blocks, vec![Vec::<u8>::new()]);
    }

    /// Feeds `chunks` through a scanner and returns what it passed on and the
    /// bytes it was told the fast path answered with.
    fn scan_flow(chunks: &[&[u8]]) -> (Vec<u8>, u32) {
        let flow = FlowHandle::default();
        let mut scanner = Scanner::new(SyncHandle::default(), flow.clone());

        for chunk in chunks {
            scanner.scan(chunk);
        }

        (scanner.out.into_iter().collect(), flow.take())
    }

    #[test]
    fn takes_a_flow_control_frame_out_of_the_stream() {
        let mut input = PREFACE.to_vec();
        input.extend_from_slice(&frame(FC_SYNC_FRAME_TYPE, &4096u32.to_be_bytes()));
        input.extend_from_slice(&frame(0x01, b"headers"));

        let mut expected = PREFACE.to_vec();
        expected.extend_from_slice(&frame(0x01, b"headers"));

        let (out, sent) = scan_flow(&[&input]);

        assert_eq!(out, expected);
        assert_eq!(sent, 4096);
    }

    #[test]
    fn finds_a_flow_control_frame_split_across_reads() {
        let mut input = PREFACE.to_vec();
        input.extend_from_slice(&frame(FC_SYNC_FRAME_TYPE, &4096u32.to_be_bytes()));
        input.extend_from_slice(&frame(0x01, b"headers"));

        let mut expected = PREFACE.to_vec();
        expected.extend_from_slice(&frame(0x01, b"headers"));

        let chunks: Vec<&[u8]> = input.chunks(1).collect();
        let (out, sent) = scan_flow(&chunks);

        assert_eq!(out, expected);
        assert_eq!(sent, 4096);
    }

    #[test]
    fn adds_up_the_flow_control_frames_of_a_connection() {
        let mut input = PREFACE.to_vec();
        input.extend_from_slice(&frame(FC_SYNC_FRAME_TYPE, &4096u32.to_be_bytes()));
        input.extend_from_slice(&frame(0x01, b"headers"));
        input.extend_from_slice(&frame(FC_SYNC_FRAME_TYPE, &128u32.to_be_bytes()));

        let (_, sent) = scan_flow(&[&input]);

        assert_eq!(sent, 4224);
    }

    #[test]
    fn ignores_a_malformed_flow_control_frame() {
        let mut input = PREFACE.to_vec();
        input.extend_from_slice(&frame(FC_SYNC_FRAME_TYPE, b"not-a-count"));
        input.extend_from_slice(&frame(0x01, b"headers"));

        let (out, sent) = scan_flow(&[&input]);

        // the framing cannot be trusted from here on, so scanning gives up and
        // nothing else is taken out of the stream
        assert!(out.ends_with(&frame(0x01, b"headers")));
        assert_eq!(sent, 0);
    }

    #[test]
    fn leaves_a_non_http2_connection_alone() {
        let input = b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n";

        let (out, blocks) = scan(&[input]);

        assert_eq!(out, input);
        assert!(blocks.is_empty());
    }

    #[tokio::test]
    async fn reads_through_a_socket_with_the_sync_frame_removed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let listener = BeeperListener::new(listener);

        let mut input = PREFACE.to_vec();
        input.extend_from_slice(&frame(DT_SYNC_FRAME_TYPE, b"the-update"));
        input.extend_from_slice(&frame(0x01, b"headers"));

        let mut expected = PREFACE.to_vec();
        expected.extend_from_slice(&frame(0x01, b"headers"));

        let sent = input.clone();
        tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.expect("connect");
            client.write_all(&sent).await.expect("write");
            client.shutdown().await.expect("shutdown");
        });

        let (mut stream, _) = listener.accept().await.expect("accept");
        let sync = stream.sync_handle();

        // the stream stops handing out bytes at an update until it has been
        // taken, so a reader that never drains would stall here; this stands in
        // for the connection loop doing it between requests
        let taken = Arc::new(Mutex::new(Vec::new()));
        let drain = {
            let sync = sync.clone();
            let taken = taken.clone();
            tokio::spawn(async move {
                loop {
                    taken.lock().unwrap().extend(sync.take());
                    tokio::task::yield_now().await;
                }
            })
        };

        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.expect("read");

        drain.abort();
        taken.lock().unwrap().extend(sync.take());

        assert_eq!(got, expected);
        assert_eq!(*taken.lock().unwrap(), vec![b"the-update".to_vec()]);
    }
}
