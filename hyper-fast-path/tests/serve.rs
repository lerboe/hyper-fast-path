//! Tests the server's connection loop end to end, without the fast path.
//!
//! Everything here goes over a real socket into [`server::serve`], so it
//! covers the listener wrapper, the protocol split and the dynamic table
//! handover together. The one thing it does not need is eBPF: the fast path's
//! sync frame is written onto the wire by the test itself.

use axum::{Router, routing::get};
use beeper_axum::{listener::BeeperListener, server};
use httlib_huffman as huffman;
use http::HeaderValue;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Must stay in sync with `DT_SYNC_FRAME_TYPE` in `server.bpf.c`.
const DT_SYNC_FRAME_TYPE: u8 = 0xFB;

const TEST_HEADER: &str = "x-beeper";
const TEST_VALUE: &str = "in-the-hive";

const FIRST_DYNAMIC_INDEX: u8 = 62;

fn huffman_encode(val: &str) -> Vec<u8> {
    let mut out = Vec::new();
    huffman::encode(val.as_bytes(), &mut out).expect("huffman encode");
    out
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    f.push(kind);
    f.push(flags);
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// How a string was put on the wire. HPACK lets a peer choose per string, and
/// the fast path copies whichever form it stored.
#[derive(Clone, Copy)]
enum Coding {
    Huffman,
    Raw,
}

/// Renders a string with its length prefix, the top bit saying whether what
/// follows is Huffman coded.
fn sync_str(s: &str, coding: Coding) -> Vec<u8> {
    let (bytes, flag) = match coding {
        Coding::Huffman => (huffman_encode(s), 0x80u8),
        Coding::Raw => (s.as_bytes().to_vec(), 0x00),
    };

    let mut out = vec![flag | bytes.len() as u8];
    out.extend_from_slice(&bytes);

    out
}

/// Renders a sync block the way `render_dt_sync` in `server.bpf.c` does: every
/// entry as a literal with incremental indexing, oldest first.
fn sync_block(entries: &[(&str, &str, Coding)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value, coding) in entries {
        out.push(0x40);
        out.extend_from_slice(&sync_str(name, Coding::Huffman));
        out.extend_from_slice(&sync_str(value, *coding));
    }

    out
}

/// Starts the server on an ephemeral port and returns the address it listens
/// on. The application echoes back the header the handover is about, so that a
/// response says whether the index resolved.
async fn start() -> SocketAddr {
    let app = Router::new()
        .route("/hello", get(|| async { "hello" }))
        .route(
            "/echo",
            get(|headers: axum::http::HeaderMap| async move {
                headers
                    .get(TEST_HEADER)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("<missing>")
                    .to_string()
            }),
        );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(server::serve(BeeperListener::new(listener), app));

    addr
}

/// Sends an HTTP/2 request whose header block is `block`, optionally preceded
/// by the fast path's sync frame carrying `update`, and returns the response
/// body.
async fn request_h2(addr: SocketAddr, block: Vec<u8>, update: Option<Vec<u8>>) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).await.expect("connect");

    stream.write_all(PREFACE).await.expect("preface");
    stream
        .write_all(&frame(0x04, 0, 0, &[]))
        .await
        .expect("settings");

    // the fast path prepends the update to the very message that carries the
    // request it belongs to, so both go out together
    let mut msg = Vec::new();
    if let Some(update) = update {
        msg.extend_from_slice(&frame(DT_SYNC_FRAME_TYPE, 0, 0, &update));
    }
    msg.extend_from_slice(&frame(0x01, 0x05, 1, &block));

    stream.write_all(&msg).await.expect("request");
    stream.flush().await.expect("flush");

    let mut got = Vec::new();
    // the server closes the stream once it has answered; reading to the end
    // keeps this from depending on how the response is split into frames
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut got),
    )
    .await;

    got
}

/// Builds a header block for `path`, referring to the handed over entry by its
/// dynamic table index when `indexed` is set.
fn request_block(path: &str, indexed: bool) -> Vec<u8> {
    // :method: GET and :scheme: http come straight out of the static table
    let mut block = vec![0x82, 0x86];

    block.push(0x04);
    block.push(path.len() as u8);
    block.extend_from_slice(path.as_bytes());

    block.push(0x01);
    block.push(b"beeper.test".len() as u8);
    block.extend_from_slice(b"beeper.test");

    if indexed {
        block.push(0x80 | FIRST_DYNAMIC_INDEX);
    }

    block
}

/// Returns whether `haystack` carries `needle`, which is how the response body
/// is found in the raw frames read back.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn serves_http1() {
    let addr = start().await;

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(b"GET /hello HTTP/1.1\r\nHost: beeper.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("request");

    let mut got = Vec::new();
    stream.read_to_end(&mut got).await.expect("read");

    let got = String::from_utf8_lossy(&got);
    assert!(
        got.starts_with("HTTP/1.1 200"),
        "unexpected response: {got}"
    );
    assert!(got.ends_with("hello"), "unexpected response: {got}");
}

#[tokio::test]
async fn serves_http2() {
    let addr = start().await;

    let got = request_h2(addr, request_block("/hello", false), None).await;

    assert!(
        contains(&got, b"hello"),
        "the response did not carry the body: {got:?}"
    );
}

#[tokio::test]
async fn applies_a_dynamic_table_update_before_the_request_that_needs_it() {
    let addr = start().await;

    // the client indexed this on a request the fast path answered, so the
    // server only learns about it from the update
    let update = sync_block(&[(TEST_HEADER, TEST_VALUE, Coding::Huffman)]);
    let got = request_h2(addr, request_block("/echo", true), Some(update)).await;

    assert!(
        contains(&got, TEST_VALUE.as_bytes()),
        "the indexed header did not reach the application: {got:?}"
    );
}

#[tokio::test]
async fn applies_an_update_whose_value_was_not_huffman_coded() {
    let addr = start().await;

    // curl spells `accept: */*` out rather than Huffman coding it and indexes
    // it, so a handover that assumes Huffman fails on an ordinary request
    let update = sync_block(&[
        ("accept", "*/*", Coding::Raw),
        (TEST_HEADER, TEST_VALUE, Coding::Huffman),
    ]);
    let got = request_h2(addr, request_block("/echo", true), Some(update)).await;

    assert!(
        contains(&got, TEST_VALUE.as_bytes()),
        "the handover failed on a value that was not Huffman coded: {got:?}"
    );
}

#[tokio::test]
async fn a_request_needing_an_update_that_never_came_does_not_reach_the_application() {
    let addr = start().await;

    // the same request without the update, which the server cannot decode
    let got = request_h2(addr, request_block("/echo", true), None).await;

    assert!(
        !contains(&got, TEST_VALUE.as_bytes()),
        "the header resolved without the update, \
         so this test no longer proves anything: {got:?}"
    );
}

#[tokio::test]
async fn passes_an_ordinary_request_through_untouched() {
    let addr = start().await;

    // no update on this connection at all, so the header the application sees
    // is the one that is missing
    let got = request_h2(addr, request_block("/echo", false), None).await;

    assert!(
        contains(&got, b"<missing>"),
        "the application did not run: {got:?}"
    );
    assert!(
        !contains(&got, HeaderValue::from_static(TEST_VALUE).as_bytes()),
        "a header appeared that was never sent: {got:?}"
    );
}
