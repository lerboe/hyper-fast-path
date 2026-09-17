#![allow(unused_imports)]
use crate::dummies::{DummyMaps, DummyPool, find_dynamic_table_info};
use anyhow::{Context, Result, bail};
use beeper::{h1, h2};
use httlib_huffman as huffman;
use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
    mem::MaybeUninit,
    net::{SocketAddr, ToSocketAddrs},
    os::{
        fd::{AsFd, AsRawFd, IntoRawFd},
        unix::fs::OpenOptionsExt,
    },
    path::{Path, PathBuf},
};
use tracing::{Level, debug, info};
use xbpf::libbpf::{
    self as libbpf_rs, Link, MapCore, MapFlags, MapHandle,
    skel::{OpenSkel, Skel, SkelBuilder},
};

xbpf::include_bpf!("fast_path");

fn huffman_encode(val: &str) -> Vec<u8> {
    let mut res = Vec::new();
    huffman::encode(val.as_bytes(), &mut res).unwrap();
    res
}

// Must stay in sync with the corresponding `#define`s in fastpath.bpf.c.
const MAX_ROUTES: usize = 16;
const MAX_ROUTE_PATH: usize = 64;
const CHUNK: usize = 32768;
const MAX_CHUNKS: usize = 14;
const MAX_ROUTE_BODY: usize = MAX_CHUNKS * CHUNK;
const MAX_SID_OFFS: usize = 32;
/// The smallest `SETTINGS_MAX_FRAME_SIZE` a peer may announce, and so the
/// largest DATA frame that is safe to send without having seen its settings.
const MAX_FRAME_SIZE: usize = 16384;

const MAX_DUMMIES: usize = 16384;

const ARENA_BASE: usize = 1 << 44;
const PAGE_SIZE: usize = 4096;

/// The number of connections the fast path runs on at once unless told
/// otherwise, see [`FastPath::attach`].
pub const DEFAULT_DUMMIES: usize = 1024;

/// The eBPF fast path of a server.
///
/// It parses the requests arriving on the server's sockets with an HTTP/1.1
/// parser and answers the ones whose path it has a pre-rendered response for
/// straight from the kernel. Everything else is passed on to the user space
/// server. The fast path stays attached until this value is dropped.
pub struct FastPath<'obj> {
    #[allow(dead_code)]
    dummies: DummyPool,
    #[allow(dead_code)]
    skel: FastPathSkel<'obj>,
    #[allow(dead_code)]
    sockops: Link,
    #[allow(dead_code)]
    h1: h1::AttachedParser,
    #[allow(dead_code)]
    h2: h2::AttachedParser,
}

unsafe impl<'obj> Send for FastPath<'obj> {}

unsafe impl<'obj> Sync for FastPath<'obj> {}

/// The HTTP/2 rendering of a response, along with the offsets of the stream ids
/// in its frame headers and the one it is placed at in the arena.
struct H2Response {
    body: Vec<u8>,
    off: usize,
    sid_offs: Vec<u32>,
    data_len: usize,
}

/// A response rendered for every protocol the fast path can answer it on, ready
/// to be loaded into the eBPF program.
struct PreparedRoute {
    keys: [Vec<u8>; 2],
    body: Vec<u8>,
    body_off: usize,
    h2: Option<H2Response>,
}

/// Returns the value of the `Content-Type` header to serve `file` with, based
/// on its extension.
fn content_type(file: &Path) -> &'static str {
    match file.extension().and_then(|ext| ext.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript",
        Some("css") => "text/css",
        Some("json") => "application/json",
        _ => "application/octet-stream",
    }
}

/// Renders the full HTTP/1.1 response (status line, headers and body) that
/// the fast path will serve verbatim whenever `path` is requested.
fn render_response(file: &Path) -> Result<Vec<u8>> {
    let body = std::fs::read(file)
        .with_context(|| format!("failed to read fastpath asset {}", file.display()))?;

    let mut resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len(),
        content_type(file),
    )
    .into_bytes();
    resp.extend_from_slice(&body);

    Ok(resp)
}

/// Encodes a header as an HPACK literal without indexing, taking the name from
/// the static table. Not indexing keeps the client's dynamic table untouched,
/// which it has to be: the server never sees this response, so its own encoder
/// would not know about the entry.
fn hpack_literal(name_idx: u8, value: &str) -> Vec<u8> {
    let mut out = vec![0x0F, name_idx - 15];
    out.push(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
    out
}

fn h2_frame(kind: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(9 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    frame.push(kind);
    frame.push(flags);
    // the stream id is only known once a request comes in, the fast path
    // patches it into the frame header before serving
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Renders the same response as [`render_response`] as an HTTP/2 HEADERS frame
/// followed by as many DATA frames as the body needs. Every frame carries a
/// zeroed stream id; the returned offsets point at the spots the fast path has
/// to patch it into.
///
/// The body's length is returned alongside them: it is the part of the response
/// that is flow controlled, and so what the fast path has to have room for in
/// the client's windows before it may answer with it.
fn render_h2_response(file: &Path) -> Result<(Vec<u8>, Vec<u32>, usize)> {
    let body = std::fs::read(file)
        .with_context(|| format!("failed to read fastpath asset {}", file.display()))?;

    // :status: 200 is a static table entry of its own, so it can be referenced
    // as an indexed field
    let mut hdrs = vec![0x88];
    hdrs.extend_from_slice(&hpack_literal(28, &body.len().to_string()));
    hdrs.extend_from_slice(&hpack_literal(31, content_type(file)));

    let mut resp = h2_frame(0x01, 0x04, &hdrs); // HEADERS, END_HEADERS

    // the stream id sits at offset 5 of a frame header
    let mut sid_offs = vec![5];

    // an empty body still needs a frame of its own to carry END_STREAM, which
    // is what `chunks` on its own would leave out
    let empty: &[u8] = &[];
    let chunks: Vec<&[u8]> = match body.is_empty() {
        true => vec![empty],
        false => body.chunks(MAX_FRAME_SIZE).collect(),
    };

    for (i, chunk) in chunks.iter().enumerate() {
        let flags = match i + 1 == chunks.len() {
            true => 0x01, // END_STREAM
            false => 0x00,
        };

        sid_offs.push(resp.len() as u32 + 5);
        resp.extend_from_slice(&h2_frame(0x00, flags, chunk));
    }

    Ok((resp, sid_offs, body.len()))
}

impl<'obj> FastPath<'obj> {
    /// Attaches the server's fast path.
    ///
    /// `routes` maps request paths (e.g. `/index.html`) to files on disk. The
    /// contents of those files are pre-rendered into full HTTP responses and
    /// loaded into the eBPF program's `.bss` section, so that requests for a
    /// matching path can be served directly from the fast path without ever
    /// reaching userspace.
    ///
    /// `dummies` is the number of connections the fast path runs on at once,
    /// each of which takes up a loopback connection of its own. Connections
    /// beyond that are served by userspace alone.
    pub fn attach<A: ToSocketAddrs>(
        address: A,
        open_obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
        routes: HashMap<String, PathBuf>,
        dummies: usize,
    ) -> Result<Self> {
        if dummies == 0 || dummies > MAX_DUMMIES {
            bail!("the fast path runs on 1 to {MAX_DUMMIES} connections, {dummies} requested");
        }

        if routes.len() > MAX_ROUTES {
            bail!(
                "too many fastpath routes: {} configured, at most {MAX_ROUTES} supported",
                routes.len()
            );
        }

        // a route is reachable under its plain text path as well as under the
        // huffman encoded one h2 puts on the wire
        let mut prepared = Vec::with_capacity(routes.len());
        let mut arena_len = 0;
        for (path, file) in routes.iter() {
            let keys = [path.as_bytes().to_vec(), huffman_encode(path)];
            if keys.iter().any(|key| key.len() > MAX_ROUTE_PATH) {
                bail!("fastpath route path `{path}` is longer than {MAX_ROUTE_PATH} bytes");
            }

            // a response too large to pre-render is left to the server rather
            // than refused: a path the fast path does not know is one it passes
            // on, which is exactly what should happen to it
            let body = render_response(file)?;
            if body.len() > MAX_ROUTE_BODY {
                let len = body.len();
                info!("Not serving `{path}` from the fast path, {len}B exceeds {MAX_ROUTE_BODY}B");
                continue;
            }

            let body_off = arena_len;
            arena_len += body.len();

            // the HTTP/2 rendering carries a frame header every
            // `MAX_FRAME_SIZE` bytes, so it can outgrow the HTTP/1.1 one by
            // enough to no longer fit
            let (h2_body, sid_offs, data_len) = render_h2_response(file)?;
            let fits = h2_body.len() <= MAX_ROUTE_BODY && sid_offs.len() <= MAX_SID_OFFS;
            let h2 = match fits {
                false => {
                    let len = h2_body.len();
                    info!(
                        "Only serving `{path}` over HTTP/1.1, its {len}B HTTP/2 rendering does not fit"
                    );
                    None
                }
                true => {
                    let off = arena_len;
                    arena_len += h2_body.len();

                    Some(H2Response {
                        body: h2_body,
                        off,
                        sid_offs,
                        data_len,
                    })
                }
            };

            debug!("Serving `{path}` from the fast path");
            prepared.push(PreparedRoute {
                keys,
                body,
                body_off,
                h2,
            });
        }

        let address = address
            .to_socket_addrs()?
            .next()
            .expect("Failed to parse address");

        let skel_builder = FastPathSkelBuilder::default();
        let mut open_skel = skel_builder.open(open_obj)?;
        if tracing::event_enabled!(Level::TRACE) {
            open_skel.progs.msg_verdict.set_log_level(1);
            open_skel.progs.skb_verdict.set_log_level(1);
        }

        let ip4 = match address {
            SocketAddr::V4(addr) => Ok(u32::from_ne_bytes(addr.ip().octets())),
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                "Unsupported address family",
            )),
        }?;

        open_skel.maps.rodata_data.as_mut().unwrap().ip4 = ip4;
        open_skel.maps.rodata_data.as_mut().unwrap().port = address.port() as u32;

        // the bodies go into the arena once it exists, all that is loaded here
        // is where each of them will be found
        let bss = open_skel.maps.bss_data.as_mut().unwrap();
        for (i, PreparedRoute { body, body_off, h2, .. }) in prepared.iter().enumerate() {
            let route = &mut bss.routes[i];
            route.body_off = *body_off as u32;
            route.body_len = body.len() as u32;

            let Some(H2Response { body, off, sid_offs, data_len }) = h2 else {
                continue;
            };
            route.h2_body_off = *off as u32;
            route.h2_body_len = body.len() as u32;
            route.h2_sid_offs[..sid_offs.len()].copy_from_slice(sid_offs);
            route.h2_sid_count = sid_offs.len() as u32;
            route.h2_data_len = *data_len as u32;
        }

        // an arena is sized in pages, and only the ones the responses reach are
        // ever backed by memory
        let pages = arena_len.div_ceil(PAGE_SIZE).max(1);
        open_skel.maps.arena.set_max_entries(pages as u32)?;

        let maps = &mut open_skel.maps;
        for map in [
            &mut maps.dummy_map,
            &mut maps.free_dummies,
            &mut maps.conn_dummy,
            &mut maps.dummy_idx,
            &mut maps.dummy_owners,
        ] {
            map.set_max_entries(dummies as u32)?;
        }

        let skel = open_skel.load()?;
        xbpf::tracing::try_init(skel.object())?;

        // libbpf maps the arena where the program's `map_extra` asked for it,
        // so a route's offset addresses the same bytes on both sides
        let arena =
            unsafe { std::slice::from_raw_parts_mut(ARENA_BASE as *mut u8, pages * PAGE_SIZE) };
        for PreparedRoute { body, body_off, h2, .. } in prepared.iter() {
            arena[*body_off..*body_off + body.len()].copy_from_slice(body);

            let Some(H2Response { body, off, .. }) = h2 else {
                continue;
            };
            arena[*off..*off + body.len()].copy_from_slice(body);
        }

        debug!("Loaded {arena_len}B of responses into a {pages} page arena");

        // the route index is a hash map, so it can only be populated once the
        // program is loaded and the map created
        for (i, PreparedRoute { keys, .. }) in prepared.iter().enumerate() {
            for key in keys {
                let mut padded = [0; MAX_ROUTE_PATH];
                padded[..key.len()].copy_from_slice(key);

                skel.maps
                    .route_idx
                    .update(&padded, &[i as u8], MapFlags::ANY)
                    .with_context(|| format!("failed to index fastpath route {i}"))?;
            }
        }
        let sock_map_fd = skel.maps.sock_map.as_fd().as_raw_fd();
        let dummy_map_fd = skel.maps.dummy_map.as_fd().as_raw_fd();
        let prog_fd = skel.progs.msg_verdict.as_fd().as_raw_fd();

        let h1 = h1::Parser::new()
            .match_h2_preface()
            .capture_hdr(&beeper::header::PATH)
            .capture_hdr(&http::header::CONTENT_LENGTH)
            .replace_parse_msg("parse_h1")
            .replace_extract("extract_h1_match")
            .replace_matched("matched_h1")
            .attach(prog_fd)?;

        let h2 = h2::Parser::new()
            .capture_hdr(&beeper::header::PATH)?
            .capture_hdr(&http::header::CONTENT_LENGTH)?
            .replace_parse_msg("parse_h2")
            .replace_extract("extract_h2_match")
            .replace_get_dynamic_table_entry("get_dt_entry")
            .attach(prog_fd)?;

        let cgroup_fd = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open("/sys/fs/cgroup")?
            .into_raw_fd();

        // a socket only picks up the programs attached to the map by the time it
        // is added, so they have to be in place before any socket is
        skel.progs.msg_verdict.attach_sockmap(dummy_map_fd)?;
        skel.progs.skb_verdict.attach_sockmap(sock_map_fd)?;

        let maps = DummyMaps {
            dummy_map: MapHandle::try_from(&skel.maps.dummy_map)?,
            dummy_idx: MapHandle::try_from(&skel.maps.dummy_idx)?,
            free_dummies: MapHandle::try_from(&skel.maps.free_dummies)?,
            released_dummies: MapHandle::try_from(&skel.maps.released_dummies)?,
            dynamic_table_info: find_dynamic_table_info(skel.progs.msg_verdict.as_fd())?,
        };
        let dummies = DummyPool::new(dummies, maps)?;

        let sockops = skel.progs.monitor_sockets.attach_cgroup(cgroup_fd)?;

        debug!("Server fast path attached");

        Ok(Self {
            dummies,
            sockops,
            skel,
            h1,
            h2,
        })
    }
}
