//! Tests that a server which never saw a request can still resolve the HPACK
//! indices that request left behind in its client's dynamic table.
//!
//! This is the user space half of the fast path's dynamic table handover, and
//! it runs without any eBPF. The client is written at the byte level so that it
//! can do the one thing a real client library will not: refer to a dynamic
//! table entry that it added on a request the server never received, which is
//! exactly what a client does after the fast path answered one in the kernel.

use h2::server;
use http::{HeaderName, HeaderValue};
use httlib_huffman as huffman;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const TEST_HEADER: HeaderName = HeaderName::from_static("x-beeper");
const TEST_VALUE: &str = "in-the-hive";

/// The first index of the dynamic table, the static one taking up everything
/// below it.
const FIRST_DYNAMIC_INDEX: u8 = 62;

fn huffman_encode(val: &str) -> Vec<u8> {
    let mut out = Vec::new();
    huffman::encode(val.as_bytes(), &mut out).expect("huffman encode");
    out
}

/// Renders an HTTP/2 frame.
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
/// the fast path copies whichever form it stored, so both have to be covered.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Coding {
    Huffman,
    Raw,
}

/// Renders a string with its length prefix, the top bit saying whether what
/// follows is Huffman coded.
fn sync_str(s: &str, coding: Coding) -> Vec<u8> {
    let (bytes, flag) = match coding {
        Coding::Huffman => (huffman_encode(s), 0x80),
        Coding::Raw => (s.as_bytes().to_vec(), 0x00),
    };

    let mut out = vec![flag | bytes.len() as u8];
    out.extend_from_slice(&bytes);

    out
}

/// Renders a header as the fast path does: a literal header field with
/// incremental indexing and a new name.
///
/// Must stay in sync with `render_dt_sync` in `server.bpf.c`.
fn sync_entry(name: &str, value: &str, coding: Coding) -> Vec<u8> {
    let mut out = vec![0x40];
    out.extend_from_slice(&sync_str(name, Coding::Huffman));
    out.extend_from_slice(&sync_str(value, coding));

    out
}

/// Renders a whole sync block the way the fast path does: every entry replayed
/// oldest first. Emptying the table beforehand is the reader's job, see
/// `Decoder::prime`.
///
/// Must stay in sync with `render_dt_sync` in `server.bpf.c`.
fn sync_block(entries: &[(&str, &str, Coding)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value, coding) in entries {
        out.extend_from_slice(&sync_entry(name, value, *coding));
    }

    out
}

/// Builds the header block of a request that refers to the entry the server
/// missed by its dynamic table index.
///
/// Everything else is taken from the static table, so the block stands on its
/// own: `:method: GET` is index 2 and `:scheme: http` index 6, while `:path`
/// and `:authority` are spelled out against their static names.
fn request_block() -> Vec<u8> {
    let mut block = vec![0x82, 0x86];

    // :path, whose name is static index 4
    block.push(0x04);
    block.push(b"/two".len() as u8);
    block.extend_from_slice(b"/two");

    // :authority, whose name is static index 1
    block.push(0x01);
    block.push(b"beeper.test".len() as u8);
    block.extend_from_slice(b"beeper.test");

    // and the entry that only exists because of a request the server never saw
    block.push(0x80 | FIRST_DYNAMIC_INDEX);

    block
}

/// Runs a server that applies `updates` to its dynamic table and then reports
/// the headers of the first request it receives.
async fn serve_once(
    listener: TcpListener,
    updates: Vec<Vec<u8>>,
) -> anyhow::Result<http::HeaderMap> {
    let (stream, _) = listener.accept().await?;
    let mut conn = server::handshake(stream).await?;

    for block in &updates {
        conn.prime_dynamic_table(block)?;
    }

    let (req, mut respond) = conn
        .accept()
        .await
        .ok_or_else(|| anyhow::anyhow!("the connection carried no request"))??;

    let headers = req.headers().clone();
    respond.send_response(http::Response::new(()), true)?;

    Ok(headers)
}

/// Opens a connection and sends a single request carrying `block`.
async fn send_request(addr: SocketAddr, block: Vec<u8>) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect(addr).await?;

    stream.write_all(PREFACE).await?;
    stream.write_all(&frame(0x04, 0, 0, &[])).await?;
    // END_STREAM | END_HEADERS, the request has no body
    stream.write_all(&frame(0x01, 0x05, 1, &block)).await?;
    stream.flush().await?;

    let mut sink = [0; 1024];
    let _ = stream.read(&mut sink).await;

    Ok(())
}

#[tokio::test]
async fn a_primed_table_resolves_an_index_the_server_never_saw() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // the entry is handed over the way the fast path would have sent it
    let update = sync_block(&[(TEST_HEADER.as_str(), TEST_VALUE, Coding::Huffman)]);
    let server = tokio::spawn(serve_once(listener, vec![update]));

    send_request(addr, request_block()).await.expect("client");

    let headers = server.await.expect("join").expect("serve");

    assert_eq!(
        headers.get(&TEST_HEADER),
        Some(&HeaderValue::from_static(TEST_VALUE)),
        "the header the client sent as a dynamic table index did not resolve"
    );
    assert_eq!(headers.get(http::header::HOST), None);
}

#[tokio::test]
async fn a_value_that_was_not_huffman_coded_survives_the_handover() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // curl sends `accept: */*` spelled out rather than Huffman coded, because
    // Huffman does not make it any shorter, and indexes it. Copying it back out
    // with the H bit set regardless is what made the handover fail with
    // "unable to maintain the header compression context": the decoder tried to
    // read `*/*` as Huffman.
    let update = sync_block(&[("accept", "*/*", Coding::Raw)]);
    let server = tokio::spawn(serve_once(listener, vec![update]));

    send_request(addr, request_block()).await.expect("client");

    let headers = server.await.expect("join").expect("serve");

    assert_eq!(
        headers.get(http::header::ACCEPT),
        Some(&HeaderValue::from_static("*/*")),
        "a value that was not Huffman coded did not survive the handover"
    );
}

#[tokio::test]
async fn a_mix_of_coded_and_spelled_out_entries_survives_the_handover() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // a real request carries both kinds, so the H bit has to be tracked per
    // string rather than assumed for the block
    let update = sync_block(&[
        ("accept", "*/*", Coding::Raw),
        (TEST_HEADER.as_str(), TEST_VALUE, Coding::Huffman),
    ]);
    let server = tokio::spawn(serve_once(listener, vec![update]));

    send_request(addr, request_block()).await.expect("client");

    let headers = server.await.expect("join").expect("serve");

    // the request indexes the most recent entry, which is the Huffman one
    assert_eq!(
        headers.get(&TEST_HEADER),
        Some(&HeaderValue::from_static(TEST_VALUE))
    );
}

#[tokio::test]
async fn a_resync_replaces_a_table_that_holds_evicted_entries() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // the server is first told about entries the client has since evicted, and
    // then handed the table as it actually stands. only the second block may
    // survive: if the first were still in the table the entries would sit at
    // the wrong indices, which is the drift a full resync exists to undo.
    let stale = sync_block(&[
        ("x-gone", "evicted", Coding::Huffman),
        ("x-also-gone", "evicted", Coding::Huffman),
    ]);
    let fresh = sync_block(&[(TEST_HEADER.as_str(), TEST_VALUE, Coding::Huffman)]);
    let server = tokio::spawn(serve_once(listener, vec![stale, fresh]));

    send_request(addr, request_block()).await.expect("client");

    let headers = server.await.expect("join").expect("serve");

    assert_eq!(
        headers.get(&TEST_HEADER),
        Some(&HeaderValue::from_static(TEST_VALUE)),
        "the index resolved against a table the resync should have emptied"
    );
}

#[tokio::test]
async fn an_unprimed_table_cannot_resolve_the_index() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // the same request without the handover, which is the bug it exists to fix
    let server = tokio::spawn(serve_once(listener, Vec::new()));

    let _ = send_request(addr, request_block()).await;

    let result = server.await.expect("join");

    match result {
        Err(_) => {
            // the index pointed past the end of the table, so the connection
            // failed with a compression error, as HPACK requires
        }
        Ok(headers) => panic!(
            "the request decoded without the handover ({:?}), \
             so this test no longer proves anything",
            headers
        ),
    }
}
